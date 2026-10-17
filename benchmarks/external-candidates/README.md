# External corpus candidates (2026)

This directory records selected, version-pinned external material that can be
used to extend Webrev's detector diagnostics. It is not a single accuracy
benchmark: sources have different labels, scopes, licenses and execution
requirements.

| Source | Acquired data | Relevant coverage | License / status | Limits |
| --- | --- | --- | --- | --- |
| [SWIPE artifact](https://doi.org/10.5281/zenodo.15883603) | 30 selected HTML cases plus companion JS; source ZIP is 1,894,433,749 bytes | Browser DOM-XSS source-to-sink | MIT; selected fixtures in `swipe-v1/` | Manually reviewed, correlated examples, not a real-world snapshot |
| [Google Firing Range](https://github.com/google/firing-range/tree/4f991a6418b07a66cd63006f4a2bec27c84b72f4) | Pinned source archive in `snapshots/` | Synthetic XSS source/sink combinations | Apache-2.0; archived legacy App Engine project | No Webrev scoring yet; needs legacy runtime. Inspected 2026-10-17: its DOM templates (`tests/dom/data`) are all vulnerable by design; the only "sanitize" case HTML-escapes before `eval`, which does not make it safe. It provides no usable negatives |
| [Security Defect Corpus](https://github.com/RusDavies/security-defect-corpus/tree/84dd9c822eea735448353a01afe5e7e0df6549c4) | Pinned source archive in `snapshots/` | JS/TS/Node reachability, server XSS, redirect, SSRF and secret cases | MIT; 84 cases / 23 ecosystems per its validator | Small maintainer-authored fixtures; much is server-side |
| [SecBench.js](https://github.com/cristianstaicu/SecBench.js) | Reviewed, not acquired | Node package security | No clear repository license detected; excluded | 600 vulnerable package cases; server-side, execution risk and reuse terms unclear |
| [X.js](https://arxiv.org/abs/2610.18585) | Paper reviewed; dataset not found | Node.js source/sink and exploit traces | Dataset availability not established | Node-only classes; not browser extraction |
| [Snyk VulnBench](https://github.com/snyk-labs/snyk-vulnbench) | Candidate reviewed, not acquired | Small deterministic JavaScript apps | Reuse terms need review | Agentic code-fixing repeatability, not independent scanner ground truth |

## SWIPE pilot result

Run with:

```sh
cargo test -p webrev-extract --test swipe_domxss_external -- --nocapture
```

The current worktree executed 30 cases: TP=14, FP=0, FN=2, TN=13, with one
inconclusive case excluded from binary metrics. On the 16 reviewed positives
and 13 reviewed negatives this is 100% precision, 87.5% recall, 0% FPR and
12.5% FNR. The preceding run was TP=13, FP=1, FN=3, TN=12. These rates apply
only to this small, manually reviewed selection; they are not independent
ground truth or general performance claims.

Current misses: `swipe-simpleDOMXSS1-index` (cross-file helper/dataflow) and
`swipe-testFields3-index` (object-field aliasing). The previous false positive
`swipe-testStrSearch-index` was resolved by treating `search()`'s numeric
result as untainted; the `onclick` miss was resolved by recognizing dynamic
event-handler sinks. The iframe case remains inconclusive and is not treated
as a negative. Case rationale and provenance are in `swipe-v1/cases.jsonl`;
measured output is in `swipe-v1/results.json`.

## Safety and provenance

The SWIPE paper describes 44,480 collected URLs and 194 pages classified as
vulnerable. These are third-party sites, not authorized scan targets. Webrev
was not run against those URLs. The artifact contains test code and analysis
infrastructure, not a frozen local copy of all those websites. Only selected
fixture byte ranges were fetched and hashed.

The archives are pinned snapshots for offline inspection. Do not install their
dependencies or run legacy testbeds against the network for detector
benchmarking. Keep any lab execution local and explicitly scoped. SHA-256
manifests cover all acquired files.
