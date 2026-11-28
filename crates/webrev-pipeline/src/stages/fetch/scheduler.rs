//! The crawl frontier: what the fetch stage pops next.
//!
//! Two strategies, both deterministic. `Bfs` is a `VecDeque` behind the same
//! interface the pre-existing crawler used (`push_back`/`pop_front`), kept
//! byte-for-byte as a regression baseline. `BestFirst` is a `BinaryHeap`
//! ordered on signals already available at discovery time — depth (shallower
//! first) and resource kind (scripts/source maps before plain links, since
//! they tend to reveal more endpoints per fetch than a navigation page) —
//! with discovery order as the final tie-break so that, within the same
//! depth and kind, candidates are still served oldest-first rather than
//! starved indefinitely. There is no learned/adaptive scoring here: see
//! `docs/asgc-plan.md` for why that is deliberately out of scope for now.

use std::cmp::Reverse;
use std::collections::{BinaryHeap, VecDeque};
use webrev_core::CrawlerStrategy;

/// What a crawl candidate was discovered as. Only affects `BestFirst`
/// ordering; `Bfs` ignores it entirely, matching prior behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ResourceHint {
    /// `<script src>`, a manifest/service-worker reference, or a recovered
    /// source map: content, not navigation.
    Script,
    /// An `<a href>` link: may or may not lead anywhere useful.
    Link,
}

/// A queued, not-yet-fetched URL.
#[derive(Debug, Clone)]
pub(super) struct Candidate {
    pub url: String,
    pub depth: usize,
}

/// Total ordering used by `BestFirst`. Declaration order is comparison
/// order: shallower depth wins first, then scripts over links, then older
/// discovery order (lower `seq`) — so `#[derive(Ord)]` alone expresses the
/// whole priority rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct Score {
    depth_rev: Reverse<usize>,
    is_script: u8,
    seq_rev: Reverse<u64>,
}

pub(super) struct HeapEntry {
    candidate: Candidate,
    score: Score,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}
impl Eq for HeapEntry {}
impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.score.cmp(&other.score)
    }
}

/// The crawl frontier. Each pushed candidate carries the sequence number it
/// was discovered at, so `BestFirst` can still break ties by discovery
/// order without a separate fairness module.
pub(super) enum Frontier {
    Bfs(VecDeque<Candidate>),
    BestFirst(BinaryHeap<HeapEntry>),
}

impl Frontier {
    pub fn new(strategy: CrawlerStrategy) -> Self {
        match strategy {
            CrawlerStrategy::Bfs => Self::Bfs(VecDeque::new()),
            CrawlerStrategy::BestFirst => Self::BestFirst(BinaryHeap::new()),
        }
    }

    /// Seed the frontier with the mission's seeds, in order, at depth 0.
    /// Each seed gets its own sequence number so `BestFirst` still breaks
    /// ties between seeds by their listed order, not arbitrarily.
    pub fn seed(strategy: CrawlerStrategy, seeds: impl IntoIterator<Item = String>) -> Self {
        let mut frontier = Self::new(strategy);
        for (seq, url) in seeds.into_iter().enumerate() {
            frontier.push(Candidate { url, depth: 0 }, ResourceHint::Link, seq as u64);
        }
        frontier
    }

    /// Push a candidate discovered at `seq` (a monotonically increasing
    /// discovery counter the caller owns — see `fetch/mod.rs`).
    pub fn push(&mut self, candidate: Candidate, hint: ResourceHint, seq: u64) {
        match self {
            Self::Bfs(queue) => queue.push_back(candidate),
            Self::BestFirst(heap) => {
                let score = Score {
                    depth_rev: Reverse(candidate.depth),
                    is_script: u8::from(hint == ResourceHint::Script),
                    seq_rev: Reverse(seq),
                };
                heap.push(HeapEntry { candidate, score });
            }
        }
    }

    pub fn pop(&mut self) -> Option<Candidate> {
        match self {
            Self::Bfs(queue) => queue.pop_front(),
            Self::BestFirst(heap) => heap.pop().map(|entry| entry.candidate),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(url: &str, depth: usize) -> Candidate {
        Candidate {
            url: url.to_owned(),
            depth,
        }
    }

    #[test]
    fn bfs_is_strict_fifo_regardless_of_hint() {
        let mut f = Frontier::new(CrawlerStrategy::Bfs);
        f.push(cand("a", 0), ResourceHint::Link, 0);
        f.push(cand("b", 0), ResourceHint::Script, 1);
        f.push(cand("c", 5), ResourceHint::Script, 2);
        let order: Vec<_> = std::iter::from_fn(|| f.pop()).map(|c| c.url).collect();
        assert_eq!(order, ["a", "b", "c"]);
    }

    #[test]
    fn best_first_prefers_shallower_depth() {
        let mut f = Frontier::new(CrawlerStrategy::BestFirst);
        f.push(cand("deep", 3), ResourceHint::Script, 0);
        f.push(cand("shallow", 0), ResourceHint::Link, 1);
        assert_eq!(f.pop().unwrap().url, "shallow");
        assert_eq!(f.pop().unwrap().url, "deep");
    }

    #[test]
    fn best_first_prefers_scripts_over_links_at_same_depth() {
        let mut f = Frontier::new(CrawlerStrategy::BestFirst);
        f.push(cand("link", 1), ResourceHint::Link, 0);
        f.push(cand("script", 1), ResourceHint::Script, 1);
        assert_eq!(f.pop().unwrap().url, "script");
        assert_eq!(f.pop().unwrap().url, "link");
    }

    #[test]
    fn best_first_breaks_ties_by_discovery_order_oldest_first() {
        let mut f = Frontier::new(CrawlerStrategy::BestFirst);
        f.push(cand("first", 0), ResourceHint::Link, 0);
        f.push(cand("second", 0), ResourceHint::Link, 1);
        f.push(cand("third", 0), ResourceHint::Link, 2);
        let order: Vec<_> = std::iter::from_fn(|| f.pop()).map(|c| c.url).collect();
        assert_eq!(order, ["first", "second", "third"]);
    }

    #[test]
    fn best_first_never_starves_an_old_deep_candidate_behind_endless_shallow_scripts() {
        // Fairness check: a candidate's age (seq) only ever breaks ties
        // within the same (depth, hint) — it cannot promote a deep
        // candidate over a shallower one. This is intentional: depth order
        // is the crawler's actual budget-bounding signal (`max_depth`), so
        // "fairness" here means determinism within a tier, not starvation
        // avoidance across tiers.
        let mut f = Frontier::new(CrawlerStrategy::BestFirst);
        f.push(cand("old-deep", 2), ResourceHint::Script, 0);
        for i in 1..20u64 {
            f.push(cand("new-shallow", 0), ResourceHint::Script, i);
        }
        // All 19 shallow candidates drain before the single deep one.
        for _ in 0..19 {
            assert_eq!(f.pop().unwrap().url, "new-shallow");
        }
        assert_eq!(f.pop().unwrap().url, "old-deep");
    }
}
