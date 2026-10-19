# External DOM XSS validation corpus (v1)

Purpose: measure Webrev's static DOM XSS detector on code and labels that Webrev's
maintainers did not write, and report what that does and does not show. It
complements `benchmarks/static-corpus/` (maintainer-authored regression data) and
`benchmarks/external-candidates/swipe-v1/` (30 SWIPE fixtures, maintainer-adjudicated).

**No third-party code is committed.** `sources.json` pins every input (git commit
SHAs, npm versions, a CSV hash); `manifest.json` records the SHA-256 and size of every
file. `scripts/external_corpus.py fetch` downloads the files into
`cache/` (git-ignored, or `$WEBREV_EXTERNAL_CORPUS`) and fails if any byte differs.
`results.json` (per case) and `summary.json` (per source) are this repository's own
output.

```sh
python3 scripts/external_corpus.py fetch
cargo test --release -p webrev-extract --test external_corpus_domxss -- --ignored --nocapture
python3 scripts/external_corpus.py report
```

## Sources, label provenance and limits

| Source | Cases | Label | Where the label comes from | Main limit |
| --- | ---: | --- | --- | --- |
| `ghsa` | 15 pairs (30 cases) | `positive` = files at the parent of the fix commit; `fixed` = same files at the fix commit | A GitHub Security Advisory (reviewed, npm/pip/composer/go/maven/rubygems, CWE-79) that says DOM-based XSS or names a browser-controlled source, plus its fix commit | The advisory names a vulnerability, not a file. The changed files are a proxy. `fixed` is **not** a negative: only the advisory's flow is fixed. Each pair is tagged `browser` (URL, postMessage, cookie... source modeled by Webrev) or `other` (stored data, file names, API responses: not a browser-controlled source in Webrev's model) from the advisory text, by the maintainer who built the corpus |
| `sak3y` | 250 (124 positive, 126 negative) | dataset `label` column with a written source, sink and justification per row | [sak3y/ML-XSS-Detector](https://github.com/sak3y/ML-XSS-Detector) `data/dataset_labelled.csv`, pinned | One labeller, no agreement measured, 17 of 18 task categories prompt-generated. No license declared: fetched, never redistributed. Snippets are function definitions, often never called |
| `pwnfunction` | 14 positive | `positive` | The vulnerable page of each [XSS Game](https://github.com/PwnFunction/xss.pwnfunction.com) warm-up/challenge, which ships a working exploit | Game puzzles. 11 of 14 pass the input through a filter or sanitizer the exploit must bypass (`filtered`, computed before any run) |
| `domdig` | 8 positive, 1 ambiguous | `positive` / `ambiguous` | Test pages of the [domdig](https://github.com/fcavallarin/domdig) DOM XSS scanner (GPL-3.0, fetched only) | Written to exercise that scanner. The postMessage frame checks `event.origin`, so it was set to `ambiguous` before any detector run. Pages call a helper in a companion `common.js` |
| `npm` | 28 `background` | none | Popular library distribution files pinned by npm version and registry integrity | **Nobody labelled these.** They are not claimed safe. They give a rate of flows reported per file on real, large code, to be read case by case |

Labels are not human-reviewed by anyone independent of this repository. The only
reviews are the original authors' (advisories, dataset labeller, game and scanner
authors) and the one-time tagging described above. No label was changed after the
detector ran on it.

## What is not in here, and why

- DomXssMicro: no public download was found (the paper is on ResearchGate). The IBM
  benchmarks cited by the Gelato paper were not found either.
- JS-VulBench: behind an IEEE DataPort subscription.
- JsVul: already triaged in `benchmarks/external-audit/2026-10-16/`; its CWE-79
  pairs are mostly stored/config flows, not browser-source DOM XSS, so they would
  be false negatives by construction. The GHSA pairs here replace that route.
- Google Firing Range templates and the Kanaoka multi-file derivatives: already
  measured in `benchmarks/external-domxss/`; they are positive-only and correlated.
- CMU DOM XSS dataset: token features only, no source text.

## Evaluation protocol (fixed before the first run)

- Unit of evaluation: a case. A case is detected if any of its files yields a
  `DOM XSS:` finding from `ExtractorRegistry::with_defaults()` run per file, in a
  release build. Cross-file flows between a case's files are not linked in this
  runner, which understates recall on multi-file cases.
- Metrics are reported per source, never pooled across sources: TP, FP, FN, TN,
  precision, recall, FPR with Wilson 95 % intervals. `fixed`, `background` and
  `ambiguous` cases are never counted as negatives.
- The detector, its sources/sinks and its heuristics are not tuned on this corpus.
