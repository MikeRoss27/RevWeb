# Memory audit: in-process accumulation over a scan's lifetime (2026-10-20)

## Constraint this audit respects

`docs/security.md` documents a deliberate choice: sessions exist only in
memory, with no disk-backed history, and reports are exported explicitly by
the application (CLI write, or the TUI's `r` key). This is an opsec decision,
not an oversight — scan data (including live credentials and secret
plaintext) must not touch disk unexpectedly. This audit does not question
that design. The question it answers is narrower: **within that one in-memory
session, which collections grow as the scan processes more pages/requests,
and which of those growths are (a) already bounded by an explicit cap,
(b) unbounded in principle but an accepted, inherent cost of the design, or
(c) a genuine gap — unbounded growth that is not an inherent cost and could
realistically be capped without losing evidence or changing behavior.**

Method: static reading of the pipeline, storage, browser and extractor
crates (no workspace build — the shared machine was near memory exhaustion
from concurrent `cargo` jobs run by other agents this session, so this audit
stayed read-only).

## Precedent: the project's existing bounded-buffer convention

Several places already draw an explicit line rather than accumulating
without limit:

- `crates/webrev-browser/src/dynamic.rs`: `MAX_WS_FRAMES` (50),
  `MAX_CLICKS_PER_PASS` (10), `MAX_WS_PAYLOAD_CHARS` (500),
  `MAX_REFUSED_INTERACTIONS`, each applied with a `len() < CAP` check inside
  the collector that would otherwise grow per CDP event.
- `crates/webrev-extract/src/extractors/metadata/domsinks/modules.rs`:
  `MAX_MODULES` (128), `MAX_MODULE_BYTES` (512 KiB), `MAX_TOTAL_BYTES`
  (8 MiB), `MAX_LINK_PASSES` (8). The module cap is applied in
  `retain_module_input` *before* a module is even added to the pipeline's
  retained-inputs `Vec`, i.e. the cap precedes the per-file extraction, not
  just the cross-file linking pass.
- `docs/security.md`'s active-scanning section: a shared request budget
  (`--max-active-requests`, default 200), per-category attempt caps (15),
  query-position caps (4), and a decoded-body cap (512 KiB).

This is the yardstick the rest of this audit uses: where an equivalent cap
exists, growth is bounded (a); where none exists but the growth is itself
what the feature is for and stays proportional to a single document/response
rather than to total scan size, it's accepted cost (b); where growth tracks
scan size with no cap and nothing in the design requires that, it's a gap (c).

## Area-by-area findings

### 1. `webrev-core::model` — `Finding`, `Endpoint`, `Scope` (bounded / gap, see 6)

`Finding` and `Endpoint` themselves are plain structs with no internal
collections that grow on their own; the growth happens in how they are
*merged* (see Finding 6 below, which is the one genuine gap this audit
found). `Scope`'s `include`/`exclude` lists are operator-supplied and sized
by the mission configuration, not by scan progress — bounded (a).

### 2. `webrev-storage` — `InMemoryStorage` (bounded, by design)

`crates/webrev-storage/src/backends/memory.rs` holds `findings`, `endpoints`
and `secrets` per `SessionId` in `BTreeMap`s inside a single `Mutex<State>`.
Both `insert_finding` and `insert_endpoint` look up an index
(`finding_indexes` / `endpoint_indexes`, keyed by `Finding::dedup_key()` and
`(url, method)` respectively) before deciding whether to push a new row or
merge into an existing one — so a given endpoint or finding observed on every
page of a crawl occupies one slot, not one per observation. This is the
correct bounded pattern (a), modulo the one gap in `Finding::merge_from`
itself (Finding 6).

`cleanup_session` exists and is unit-tested
(`crates/webrev-storage/src/backends/memory.rs`, the
`round_trips_findings_and_cleans_up` test) but is never called from any
binary: `grep -rn cleanup_session crates/` finds only the trait, its impl,
and that one test. This is not a leak in practice, though: every CLI command
(`static_scan.rs`, `scan.rs`, `active_scan.rs`, `dynamic_scan.rs`, `bola.rs`)
and the TUI (`webrev-tui/src/main.rs`, `runtime/mod.rs`) constructs exactly
one `Mission` and one `InMemoryStorage` per process and exits (or, for the
TUI, keeps that single session for the process's lifetime) — matching
`docs/security.md`'s "all sessions stay in memory until the process exits."
There is currently no code path that creates a second session inside one
still-running process, so the dead `cleanup_session` call has no live target
to orphan. Accepted (b), with a note: if a future feature ever runs multiple
missions inside one long-lived process (e.g. a TUI "new scan" action that
keeps the old mission's data around), `cleanup_session` would need to
actually be wired in at that point — it already exists and is tested, so
that would be a one-line call, not new code.

### 3. `webrev-pipeline` — crawl frontier, fetch stage, channels (bounded)

`crates/webrev-pipeline/src/stages/fetch/mod.rs` runs a breadth-first crawl
bounded by `ctx.opsec.max_pages` (loop condition `while processed < max_pages`)
and `ctx.opsec.max_depth` (links beyond `max_depth` are never captured,
line ~172). The `visited: BTreeSet<String>` and `queue: VecDeque<(String,
usize)>` grow with distinct URLs discovered, but discovery only happens from
pages that were actually fetched, and fetching stops at `max_pages`; `queue`
cannot outlive the crawl by more than one wave's worth of over-discovery
before the loop exits. Each fetched body (`fetch_with_retry`,
`crates/webrev-pipeline/src/stages/fetch/request.rs`) is read fully into
memory (`resp.text()` / `resp.bytes()`) and handed downstream as one
`PipelineItem::Content`, then **dropped by the fetch stage** — it is not
retained across pages. The only thing the fetch stage itself still holds
across the whole crawl is `visited`/`queue` (short strings), bounded by
`max_pages`.

The inter-stage channels (`crates/webrev-pipeline/src/engine.rs`,
`CHANNEL_CAPACITY = 1024`) bound how many in-flight `Content`/`Finding`
items can be buffered between a slow stage and a fast one — a real,
if implicit, memory cap: at most 1024 unconsumed page bodies queued at once,
not the whole crawl's worth.

One thing to flag as a related, secondary observation rather than a
scan-size growth issue: `fetch_with_retry` has no response-size cap — a
single pathologically large response is read to completion with no limit
analogous to active scanning's "decoded bodies capped at 512 KiB"
(`docs/security.md`). This is a single-request memory risk, not a
scan-size accumulation, so it is out of this audit's main scope, but worth
noting since the project already has the pattern (active probes) for the
equivalent problem on the fetch path and hasn't applied it there.

The static-extract stage (`crates/webrev-pipeline/src/stages/static_extract.rs`)
accumulates one cross-page collection, `modules: Vec<ExtractInput>`, fed via
`DomSinkExtractor::retain_module_input` — this is exactly the capped path
described in area 6 above (`MAX_MODULES` / `MAX_TOTAL_BYTES`), so it is
bounded (a) even though it lives for the whole stage, not per-page.

### 4. `webrev-browser` — `BrowserPool` and per-page capture (bounded, with one gap)

`crates/webrev-browser/src/pool.rs`: `BrowserPool::new(max)` bounds live
Chromium instances with a `Semaphore`; `acquire_with_scope` blocks until a
permit is free. `PooledBrowser::drop` returns a reusable browser to the
`idle: Vec` or, if marked non-reusable, closes it (`close_entry`) and drops
the OS process. `run_dynamic_with_report`
(`crates/webrev-browser/src/dynamic.rs`) opens one `Page` per dynamic seed
(`browser.new_page("about:blank")`, line ~225) and explicitly closes it with
`page.close()` at the end (line ~582) regardless of success — pages do not
accumulate. The dwell loop's per-pass collectors are explicitly capped
(`MAX_WS_FRAMES`, `MAX_CLICKS_PER_PASS`, `MAX_WS_PAYLOAD_CHARS`,
`MAX_REFUSED_INTERACTIONS`), each checked with `len() < CAP` before pushing.

**Gap found here:** the CDP network-request collector feeding `Har` has no
such cap. `crates/webrev-browser/src/dynamic.rs`, lines 307–329:

```rust
let har = Arc::new(Mutex::new(Har::new()));
let mut requests = page.event_listener::<EventRequestWillBeSent>().await...;
let collector = tokio::spawn(async move {
    while let Some(event) = requests.next().await {
        ...
        if let Ok(mut har) = har_capture.lock() {
            har.push(HarEntry { method: req.method.clone(), url: req.url.clone(), headers });
        }
    }
});
```

`Har::push` (`crates/webrev-browser/src/har.rs`) appends unconditionally.
Every `HarEntry` clones the full request header map (`BTreeMap<String,
String>`). This runs for the whole `--duration` dwell window on one page, and
is only deduplicated afterwards, when converting to `Finding`s
(`dynamic.rs` lines 507–524, via `har.endpoints()` and a `seen: BTreeSet<(String,
Method)>`). So a chatty page — long-polling, analytics beacons, telemetry —
during a long `--duration` dwell accumulates one full `HarEntry` (with
headers) per request event, not capped, before the dedup pass runs. This
sits right next to three sibling collectors in the same function that *are*
capped, which makes the omission look like an oversight rather than an
intentional choice: there's no comment explaining why HAR capture is
exempt from the convention the surrounding code visibly follows.

Scale: for a single page polled every ~100ms over a one-hour `--duration`,
that's on the order of 36,000 `HarEntry` values; at a rough estimate of a few
hundred bytes to a few KB each (method + URL + header map), this is more
likely tens of MB than GB for one page — not catastrophic, but unbounded and
inconsistent with its neighbors.

### 5. `webrev-extract` — secrets, DOM taint, modules (bounded / accepted cost)

- `SecretExtractor::extract` (`crates/webrev-extract/src/extractors/secrets/mod.rs`)
  uses a `seen: BTreeSet<String>` of fingerprints that is local to one call —
  built fresh per file and dropped when `extract` returns. It dedupes within
  one file's matches, not across the whole session (cross-session dedup
  happens one layer up, in storage, keyed by `Finding::dedup_key()`). There
  is no explicit cap on the input body size for this extractor specifically —
  regex scanning cost (time and transient capture-group memory) is
  proportional to one file's size, not to total scan size. This is accepted
  cost (b): a single minified bundle can be large, but that is a property of
  the target, not of how many pages have been crawled, and the pipeline
  processes and drops one `Content` item at a time (area 3).
- `TaintVisitor` (`crates/webrev-extract/src/extractors/metadata/domsinks/taint.rs`)
  is constructed fresh per file (`TaintVisitor::new()` in both
  `analyze_standalone` and once per module in `extract_modules`), so its
  `scopes`, `handler_spans`, `traces` etc. are per-file working state, not
  retained for the session. Accepted cost (b).
- `DomSinkExtractor`'s module cap (`MAX_MODULES` / `MAX_MODULE_BYTES` /
  `MAX_TOTAL_BYTES` / `MAX_LINK_PASSES`, `modules.rs`) is the strongest
  precedent in the codebase for this audit's yardstick — bounded (a), see
  area 3 above for where it is fed.
- The external-corpus cache (`benchmarks/external-corpus/v1/cache/`) is a
  benchmark-time, not scan-time, artifact and is out of scope for this audit
  beyond this one-line mention.

### 6. `webrev-core::model::finding::Finding::merge_from` — genuine gap

**This is the one finding in this audit that does not fit "bounded" or
"accepted cost."**

`crates/webrev-core/src/model/finding.rs`, `Finding::merge_from` (around
lines 251–262):

```rust
pub fn merge_from(&mut self, other: Self) {
    for provenance in other.provenances.into_iter().chain([other.provenance]) {
        if !self.provenances.contains(&provenance) {
            self.provenances.push(provenance);
        }
    }
    ...
}
```

This is called from `InMemoryStorage::insert_finding`
(`crates/webrev-storage/src/backends/memory.rs`) whenever a new `Finding`
shares a `dedup_key()` with one already stored, which is exactly the
intended, correct behavior for *tracking additional evidence locations* for
one logical finding. The gap is that `self.provenances` has no cap: it grows
by one distinct `Provenance { source, location }` for every differently-located
occurrence, for the lifetime of the session, with no equivalent of
`MAX_WS_FRAMES` / `MAX_MODULES` / the active-scan request budget.

For `FindingKind::Endpoint`, `dedup_key()` is `"{kind}|{value}"` — the
endpoint's method+path, **not** the referencing page's URL
(`crates/webrev-core/src/model/finding.rs`, `dedup_key`, lines ~378). That
means every static reference to the same endpoint (e.g. a shared API client
call baked into a bundle that's served identically, or re-emitted with a
per-page `provenance.location`, from many distinct pages) merges into *one*
`Finding`, but each distinct referencing location still grows
`provenances` by one entry. The same shape of growth applies to any other
`FindingKind` whose `dedup_key()` folds multiple distinct locations into one
key (`Secret`, `Technology`, `Config`, `Parameter`, …) wherever the same
value/token legitimately appears at many distinct locations across a large
site. `additional_evidence` (a `Vec<ProbeEvidence>`, same file, lines
281–294) has the identical pattern for active-probe evidence, but that path
is self-limiting in practice because active scanning already has a hard,
documented request budget (`--max-active-requests`, default 200,
`docs/security.md`) — so this audit treats `additional_evidence` as low-risk
and `provenances` as the concrete gap, since nothing caps how many distinct
pages can statically reference the same endpoint/value on a large crawl.

How bad this could get: on a crawl of, say, 10,000 pages that all load the
same shared JS bundle calling a handful of common API endpoints (a very
ordinary SPA/CMS shape, not a pathological case), each of those common
`Endpoint`-kind `Finding`s could accumulate up to ~10,000 `Provenance`
entries (an enum discriminant plus a `String` location each — tens of bytes
to ~100 bytes per entry once the `Vec`'s growth overhead is included). For a
handful of such shared endpoints this is a few MB, not GB; it is a real,
unbounded-with-scan-size growth with no cap today, not a crisis, but it is
the one place in this codebase where the established bounded-buffer
convention visibly stops.

Minimal fix (not applied — this is a read-only audit): cap `provenances` the
same way `dynamic.rs` caps `ws_frames`/`refused_interactions` — a
`MAX_PROVENANCES_PER_FINDING` constant (something in the same order as
`MAX_WS_FRAMES`'s 50, enough to show "this is genuinely everywhere" without
keeping every occurrence) checked before the `self.provenances.push(...)` in
`merge_from`, dropping additional locations once the cap is hit without
changing `dedup_key()`/merge semantics otherwise. This would not lose the
finding or its confidence/evidence fields, only trim how many *redundant
location strings* for the same already-proven fact are retained.

### 7. `webrev-report` — building and rendering `SessionReport` (accepted cost)

`crates/webrev-cli/src/commands/mod.rs::write_session_report` calls
`storage.findings_by_session` / `endpoints_by_session` (which clone the
stored `Vec`s out of the `Mutex`), then `SessionReport::build` (another
holding structure), then `report.export_json(redact)` — which, for
`--redact`, calls `self.redacted()` (`crates/webrev-report/src/redact.rs`),
cloning the whole report again before rendering. `render_jsonl`
(`crates/webrev-report/src/format.rs`, lines 167–176) builds one `String` in
memory line-by-line rather than streaming to the output writer directly, and
the CLI then does `std::fs::write(path, ...)`, buffering the whole rendered
string again before the single write syscall. So at report time there are
several live copies of (bounded) data: stored findings, the cloned
`SessionReport`, optionally the redacted clone, and the rendered `String`.

This is accepted cost (b), not a gap: materializing the full findings/endpoints
set in memory at once is close to unavoidable for the JSON/CSV/OpenAPI/DOT
formats (several of them need the whole set for summary counters, graph
edges, or cross-referencing), and every upstream collection that feeds this
is itself bounded or deduplicated (areas 2–6). JSONL is the one format where
streaming directly to the output writer (instead of building one `String`
then writing it) is a straightforward, low-risk improvement that is not
currently done — worth a mention as a nice-to-have, not as a fix this audit
is asking for, since it only reduces a redundant-copy multiplier on data
that's already bounded, rather than removing an unbounded growth.

## Summary

| Area | Verdict |
|---|---|
| `webrev-core::model` (`Finding`/`Endpoint`/`Scope`) | bounded, except `Finding::merge_from` (see below) |
| `webrev-storage::InMemoryStorage` | bounded — merge-on-dedup-key, one session per process by design |
| `webrev-pipeline` crawl frontier / fetch stage | bounded by `--max-pages`/`--max-depth`; channels cap in-flight buffering |
| `webrev-browser::BrowserPool` | bounded — semaphore-capped, pages closed promptly |
| `webrev-browser::dynamic` per-pass collectors | bounded, **except** the HAR request collector (gap) |
| `webrev-extract` secrets / DOM taint | accepted cost — per-file working state, not session-wide |
| `webrev-extract` DOM-sinks module linking | bounded — `MAX_MODULES`/`MAX_MODULE_BYTES`/`MAX_TOTAL_BYTES` |
| `webrev-report` building/rendering `SessionReport` | accepted cost — bounded inputs, several in-memory copies at export time |
| `Finding::merge_from` provenance accumulation | **genuine gap** |

Two genuine gaps were found, both small in absolute terms but real:

## Prioritized follow-up items

1. **Done (2026-10-22).** Cap `Finding::provenances` growth in `merge_from`:
   `MAX_PROVENANCES_PER_FINDING` (50), checked before
   `self.provenances.push(provenance)` in
   `crates/webrev-core/src/model/finding.rs::Finding::merge_from`, mirroring
   the `len() < CAP` guard already used for `MAX_WS_FRAMES` in
   `crates/webrev-browser/src/dynamic.rs`.

2. **Done (2026-10-22).** Cap the dynamic-capture HAR collector:
   `MAX_HAR_ENTRIES` (2000) added to the CDP `EventRequestWillBeSent`
   collector in `run_dynamic_with_report`
   (`crates/webrev-browser/src/dynamic.rs`), checked at the call site before
   `Har::push`, the same way its three sibling collectors in the same
   function already were.

3. **(Still optional, lower priority) Stream JSONL export instead of
   buffering a full `String`.** Description: `render_jsonl`
   (`crates/webrev-report/src/format.rs`, lines 167–176) could write each
   serialized finding line directly to the output writer (file handle or
   stdout) instead of accumulating the whole report into one `String` first.
   This does not fix an unbounded growth — the underlying findings set is
   already bounded by items 1–2 and the rest of this audit — it only removes
   one redundant in-memory copy at export time, specifically for the one
   format (JSONL) where streaming is a natural fit.

4. **Done (2026-10-22).** Cap the fetch stage's per-response body size:
   `fetch_with_retry` (`crates/webrev-pipeline/src/stages/fetch/request.rs`)
   now reads the body in chunks via `read_bounded`, truncating at
   `OpsecConfig::max_body_bytes` (default 20 MiB, `--max-body-bytes`) instead
   of reading to completion — the crawl-side counterpart to active
   scanning's documented 512 KiB decoded-body cap (`docs/security.md`), kept
   separately configurable since a crawled page can legitimately be far
   larger than a probe response. A truncated text body is decoded from its
   first `max_body_bytes` bytes as UTF-8 with lossy replacement, identical to
   `Response::text()`'s own fallback whenever the response declares no
   explicit non-UTF-8 charset (the common case for the HTML/JS this scanner
   extracts from); a response with an explicit non-UTF-8 charset header that
   gets truncated mid-multi-byte-sequence may show extra replacement
   characters near the cut, a narrow, documented trade-off rather than
   reimplementing charset-aware decoding for a bounded read.
