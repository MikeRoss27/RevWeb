# SWIPE DOM XSS candidate fixtures

This is a selective, byte-preserving extraction from the [SWIPE artifact, DOI
10.5281/zenodo.15883603](https://doi.org/10.5281/zenodo.15883603), whose project
license is MIT. `inventory.json` records the artifact's SHA-256-independent
publisher MD5, original byte size, exact upstream paths, per-file SHA-256, and
retrieval method. `LICENSE` is the license included in the artifact.

The source ZIP is 1,894,433,749 bytes compressed and contains about 7.8 GB of
expanded files, chiefly vendored dependencies and virtual environments. It was
not downloaded wholesale. Thirty-two small HTML/JavaScript test files were
selected by HTTP byte ranges from `SWIPE/tests/`; dependency shims were omitted.
The 30-page manifest has 16 manually reviewed source-to-sink positives, 13
negative controls, and one inconclusive iframe navigation case. Each row cites
its exact upstream file and records its rationale. `simpleDOMXSS1` references
its companion `script1.js`, preserving the cross-file challenge. Labels here
are our source-level adjudication of the published fixture code; they are not
claims that all cases were dynamically replayed or that the source project
published a per-file confusion matrix.

The SWIPE paper reports an independently collected real-world set of 44,480
URLs and 194 pages with DOM-XSS; its tested conditions report 83 confirmed
flows from the interaction fuzzer and 72 from passive analysis on the core set.
Those public URLs are not included as scan targets in this repository. They are
live third-party systems, mutable, and require explicit scope/authorization;
Webrev has not been run against them. The released artifact is the analysis
infrastructure plus a Tranco seed list and selected lab fixtures, not a
reproducible local snapshot of the 44,480 sites or all 194 vulnerable pages.

This candidate only evaluates DOM-XSS source/sink extraction. It says nothing
about endpoint precision, HTTP parameter extraction, secret detection, or
active SSRF validation. The fixtures are correlated and mostly synthetic; use
them as an external regression layer, not as the sole estimate of general
accuracy. The matching test is `cargo test -p webrev-extract --test
swipe_domxss_external -- --nocapture`.

The initial worktree run reported TP=13, FP=1, FN=3, TN=12 and one inconclusive
case. After correcting numeric string-method results and adding event-handler
sinks, the current run reports TP=14, FP=0, FN=2, TN=13 and one inconclusive
case (excluded from binary metrics). Remaining misses are the inter-file helper
flow and object-field aliasing. See sibling `results.json` and the
external-candidates README for counts, rates and interpretation.

## Regression contract

The runner now fails if any of the 14 previously detected positive cases stops
producing a DOM-flow signal, or if any of the 13 reviewed negative cases starts
producing one. Checks are per case: a newly detected positive cannot compensate
for another positive becoming undetected. The two recorded positive misses may
improve without failing the test. The inconclusive case is counted separately
and has no binary expectation. This gate preserves measured behavior; passing it
does not establish the Step 5 accuracy target.

The manifest includes the previously unreferenced `simpleDOMXSS2methods/hero.js`
companion (an untainted greeting class); upstream source bytes and labels are
unchanged. The manifest must retain 30 unique case IDs, its 16/13/1 label counts, and exact
coverage of the inventory's 32 source files. Paths and source byte lengths are
checked by the Rust runner. Run `sha256sum -c SHA256SUMS` from this directory to
check the source hashes and metadata, too. Neither check executes fixture code
or fetches dependencies.

Scoring is at case level: any emitted `DOM XSS:` flow counts as detected. It
does not match a specific source/sink pair or replay an exploit in a browser.
Consequently these counts describe candidate extraction behavior, not confirmed
exploitable findings. The pinned `results.json` records the historical
2026-10-17 run; new extractor work must retain its own run evidence and update
the result documentation when the measured outcomes change.

The hardened gate was executed on 2026-10-17 with a Linux target directory:

```sh
CARGO_TARGET_DIR=/home/na/.cache/webrev-validation-target \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
cargo test -p webrev-extract --test swipe_domxss_external -- --nocapture
```

Result: one test passed, zero failed; TP=14, FP=0, FN=2, TN=13 and one
inconclusive case. All 32 inventoried sources are now exercised, including
`hero.js`. This runner continues to extract each file separately; the new
ES-module linking API is evaluated by the separate multi-file diagnostic and
does not resolve SWIPE's classic-script helper miss. The companion inclusion
changes input completeness without changing these measured counts.
