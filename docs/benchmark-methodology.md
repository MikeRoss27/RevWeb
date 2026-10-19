# Benchmark plan for Webrev reliability

## Recommendation

Do not use XBOW Validation Benchmarks as Webrev's primary precision/recall
benchmark. XBOW is a set of 104 end-to-end, Jeopardy-style CTF objectives for
web offensive tools. Its repository now labels the set outdated and saturated
as of mid-2026. A task-solving score does not provide ground truth for Webrev's
individual extractors (API routes, HTTP parameters, secrets, or DOM source-to-
sink flows), nor does it measure false-positive rates per detector.

Use three complementary layers instead:

1. **Primary detector corpus (offline, checked into this repository):**
   labeled HTML/JavaScript samples, each with expected detector, evidence
   location, and rationale. Include positive, negative, and ambiguous cases
   for endpoints, HTTP parameters, secrets, DOM taint and sanitization, plus
   SSRF response controls. Split development and held-out validation by
   originating project/template, not by individual snippets, to reduce
   leakage. Keep the held-out labels unavailable to tuning changes.
2. **Active/browser lab (local only):** deterministic fixtures for redirects,
   scope refusal, DNS/CIDR behavior, budgets, browser subresources, and probes.
   OWASP VulnerableApp is a candidate for an additional full DAST pass: the
   project describes deterministic scanner scenarios, a ground-truth
   comparator, and cases including XSS, SSRF, open redirect, and IDOR. Map
   only its scenarios to behaviors Webrev actually exercises; do not interpret
   its aggregate score as extractor precision.
3. **External code corpus (candidate):** review a license-compatible,
   manually checked subset of [JsVul](https://arxiv.org/abs/2609.38012), a
   recent function-level JavaScript/TypeScript vulnerable/fixed dataset. Its
   paper describes heuristic labeling and a mix of client/server ecosystems;
   verify actual records, licensing and frontend relevance before including
   cases. Never treat its labels as ground truth without review.
4. **External sanity sets:** XBOW or OWASP Benchmark may be used as secondary
   smoke/compatibility suites with an explicit mapping and limitations.
   OWASP Benchmark has expected per-case true/false labels, but its official
   suite is Java/Python servlet/application code, so it is not a direct test of
   Webrev's client-side JavaScript extraction.

## Measurement protocol

- Freeze corpus version, Webrev commit, configuration, budgets, and runtime
  environment for each before/after comparison.
- Run the same labeled cases through both revisions and count at the
  case-detector level: TP, FP, FN, TN, precision, recall, FPR, and FNR.
- Keep detector-specific metrics separate. Do not pool static extraction,
  browser observations, and active probe outcomes into one accuracy number.
- Report untested, inconclusive, refused, and errored cases separately from
  negative results. Do not count coverage gaps as true negatives.
- Publish corpus size, sources, license, split method, exclusions, and known
  limitations with the numbers. Preserve individual mismatches as regression
  cases after review.
- Measure p95 runtime, peak RSS, and stability separately on identical
  hardware and fixed concurrency; keep lab app startup outside scan time and
  record both values.

### Local performance microbenchmark (2026-10-16)

The deterministic static-crawl harness and raw measurements are archived in
`benchmarks/performance/2026-10-16/`. It runs 20 paired release scans against
the same 40-page, eight-bundle loopback fixture. Compared with clean `HEAD`
`61b843d`, the dirty worktree measured p95 +13.57% and maximum process RSS
+0.76%, within the proposed +20% and +25% limits. Every run succeeded and
reported the same 265 findings within its revision. See the archive README for
the environment, command, raw runs and limitations. Since the candidate was a
dirty worktree with broad source and manifest changes, the result is a combined
revision comparison and cannot isolate the cost of individual detectors. It
is a small local microbenchmark, not a production performance guarantee.

### Expanded SPA-like performance profile

A second deterministic loopback fixture is archived under
`benchmarks/performance/2026-10-16/spa-site/`. It has 120 routes, eleven
JavaScript bundles (three shared and eight section chunks), CSS, SVG, forms and
internal navigation. On 20 runs per revision, the clean `61b843d` baseline had
p95 29.987 ms and max RSS 20,024 KiB; the dirty worktree had p95 183.435 ms
(+511.72%) and max RSS 22,588 KiB (+12.80%). All runs succeeded and each
revision had a stable finding count (574 vs 755). The p95 limit fails. The
fixture serves identical bytes to both binaries (SHA-256 recorded in
`results.json`) but intentionally repeats endpoint-like patterns and remains
synthetic; the dirty worktree comparison cannot attribute the slowdown to an
individual detector. The paired candidate rerun is archived under
`benchmarks/performance/2026-10-17/spa-site-final/`: p95 32.352 → 39.817 ms
(+23.07%), max RSS 22,976 → 22,976 KiB (+0.00%), 574 → 760 findings, 40/40
valid scans. RSS meets its limit, but p95 exceeds the 20% threshold. Cargo
rewrote the baseline lockfile during its build to match the baseline workspace
manifests. Its post-build hash equals clean `HEAD`; a lockfile diff shows only
local workspace dependency-edge changes, with no registry package version or
checksum changes. External dependency version drift is therefore not evident.
The comparison still includes different source and workspace dependency edges,
so it does not isolate the contribution of the DOM prefilter or storage
indexes. The source-only follow-up is archived under
`benchmarks/performance/2026-10-17/spa-site-source-only/`. It copies candidate
workspace manifests and lockfile onto the baseline Rust source and uses
`cargo build --locked` for both builds. The four lock hashes match; p95 is
32.142 → 37.859 ms (+17.79%) and max RSS 24,392 → 24,392 KiB (+0.00%). That
source-only profile meets the proposed limits. It still has 574 versus 760
findings and is synthetic, so it does not isolate a detector or predict every
site. The full end-to-end profile remains above the p95 threshold.

## Benchmark-source review (2026-10-16)

- [XBOW Validation Benchmarks](https://github.com/xbow-engineering/validation-benchmarks):
  useful for broad, end-to-end challenge coverage, but CTF/task-oriented and
  marked outdated/saturated by its maintainers. Not the primary accuracy set.
- [OWASP VulnerableApp](https://owasp.github.io/www-project-vulnerableapp/):
  better fit for deterministic end-to-end scanner scenarios and ground-truth
  comparison; treat it as an active lab, subject to exact case mapping and
  version pinning.
- [OWASP Benchmark](https://owasp.org/projects/benchmark): strong per-case
  labels and score tooling, but its Java/Python server-side focus does not
  directly represent Webrev's static JavaScript/HTML detectors.
- [JsVul paper and dataset description](https://arxiv.org/abs/2609.38012): a
  promising JavaScript/TypeScript candidate with vulnerable/fixed pairs, but
  code-level labels, ecosystem mix, licensing and case-level ground truth need
  validation for Webrev's browser-facing extraction task.

### JsVul artifact check

The paper's dataset link resolves to the live [Zenodo record 18195839](https://zenodo.org/records/18195839),
which declares CC-BY-4.0. A stale record number, 18195838, returns HTTP 410.
The downloadable `js_vul.zip` is about 9.7 MB compressed and about 68 MB
unpacked. Its test split contains 1,726 records (203 positive and 1,523
negative according to the supplied `label` field); these are dataset counts,
not Webrev detection results. Records include JavaScript and TypeScript from
134 projects, and the label is tied to vulnerable/fixed code pairs. The paper
describes heuristic collection/labeling, so each candidate must still be
reviewed for frontend relevance, expected Webrev behavior, paired-record
consistency, and the original source project's license before inclusion.
No JsVul code or labels have been copied into the repository or counted in a
benchmark. The live artifact is a candidate for a reviewed subset, not a
ready-made ground-truth corpus. A separate read-only review of
`js_vul_pairs_only.zip` found 2,684 paired function records; its test split has
316 records and the CWE-79 slice has 28 vulnerable/fixed pairs. These remain
function-level, heuristic-labeled and not DOM-specific. License files were
checked at both revisions for all 28 pairs; six custom/unidentified terms
remain unresolved, so no excerpts were redistributed. The review did not run
Webrev against these samples; see `benchmarks/external-audit/2026-10-16/`.

### VulnerableApp exploratory run and mapping

At the pinned checkout, the lab has its own scanner benchmark interface:
`/scanner/dast` serves URL/type ground truth, and `/scanner/benchmark` compares
submitted findings by normalized URL plus type, CWE, or WASC ID (and optionally
HTTP method). This makes a reproducible DAST comparison possible without
guessing labels. Webrev's report still needs an explicit adapter from a
finding's evidence and detector to VulnerableApp's canonical types; only
findings with a technically supported type mapping should be submitted.
Unmapped observations must be listed separately, not sent as guessed
vulnerability findings. The lab's `unmatchedItems` and `missedItems` should
both be retained with the run.

The first adapter is `scripts/vulnerableapp_adapter.py`. It maps only
Webrev's `open_redirect` evidence when the recorded 3xx `Location`, resolved
against the probe URL, points to the exact randomized `.invalid` host and
nonce path. This accepts absolute and protocol-relative locations as well as
authority-prefix bypasses while rejecting reflected markers on a same-origin
path. It removes host, query, and fragment from the submitted target, uses VulnerableApp's canonical
`OPEN_REDIRECT_3XX_STATUS_CODE` type, and writes skipped findings to a review
sidecar. It refuses to emit a payload unless the report records an executed
`open_redirect` coverage check, preventing an untested scan from becoming an
empty finding list (and apparent false negatives). Refused and unselected
counts stay visible in the sidecar because the comparator may otherwise grade
unrun cases as misses. Example:

```sh
python3 scripts/vulnerableapp_adapter.py webrev-report.json \
  --output vulnerableapp-input.json
```

The current adapter does not make a benchmark score by itself. The operator
must also map which ground-truth URLs Webrev actually exercised and preserve
VulnerableApp's comparator response. It currently maps only open redirects;
SSRF leads, reflected markup, and anonymous-access similarities are excluded
because Webrev does not claim proof of SSRF, script execution, or IDOR for
those signals.

The first pinned lab slice was executed on 2026-10-16 and is archived under
`benchmarks/vulnerableapp/2026-10-16/open-redirect/`. The selected cases were
all nine vulnerable open-redirect levels, two labeled secure levels, and one
additional unlabeled secure control. A paired rerun used the same 12 routes,
lab revision, concurrency, delay and 160-request cap. The baseline used 146
requests and found levels 1, 9 and 10 (TP=3, FN=6, FP=0, TN=1, one refused).
The revised probe added protocol-relative, authority-prefix, tab-prefixed and
backslash URL forms, within the same 160-request cap. The batch found levels 1
through 6 except level 7, plus levels 9 and 10 (TP=8, FN=1, FP=0); level 11
was HTTP-refused. Because the batch exhausted its budget before level 12, a
separate one-route active scan tested that labeled secure control (25 requests,
one negative result), giving TN=1. Precision is 100% (8/8), recall 88.9% (8/9),
FPR 0% (0/1), and FNR 11.1% (1/9). The unlabeled level 8 control is excluded.
Chromium 154 URL parsing was also checked offline: the level 3/4 challenge's
documented `/%09/host` form stays same-origin, while a tab-prefixed `//host`
resolves externally; the level 5 `\/host` form resolves externally; level 7's
app-prefixed backslash remains same-origin. The full comparator returned 8
detected, 160 missed, 0 unmatched of 168 expected rows (4.7619% coverage),
including 159 out-of-slice types and the level 7 miss. This paired result is a
small single-lab measurement, not a production accuracy estimate. The archive's
`baseline/` directory preserves the original report, mapping and checksums.

Candidate mapping is intentionally narrow: Webrev's active vulnerability and
IDOR findings can be mapped only where their recorded evidence demonstrates
the corresponding case, such as open redirect with an injected URL in
`Location`, SSRF with server-side fetch evidence, or an access-control case
with a cross-identity comparison. Mere endpoint discovery, response
difference, or reflection is not a match. VulnerableApp also includes many
Java/server-side classes outside Webrev's intended client-side static
detectors; those are unsupported cases and must not be counted as true
negatives for the JS/HTML detector corpus.

On 2026-10-16, Webrev was run against OWASP VulnerableApp at pinned source
commit `8003daf8e13044802fdeb4b665f0c9cc6d09096b`. Docker Compose used the
project's `without_llm` stack with an internal-only network and loopback-only
published ports; the scan targeted the facade's private container IP from the
host. The run used Chromium 154, static plus browser discovery, a 10-page cap,
depth 1, concurrency 1, a 20-request active budget, and a 2-second active
duration. It completed with 43 static and 17 browser findings (60 total),
including 17 browser-observed endpoints. It reported no vulnerability or
secret candidates.

This was a bounded exploratory integration check, **not a benchmark result**:
the run covered only the application entry point, did not map the lab's
individual ground-truth scenarios, and did not execute active vulnerability
probes. Therefore no precision, recall, or coverage score can be derived. The
compose stack and volumes were removed after the run. The JSON report remains
in `/tmp/webrev-vapp-report.json` on the operator machine and is not a
repository artifact. For a reproducible benchmark, pin image digests as well
as the source revision, map each selected scenario to a Webrev detector, and
retain the expected outcomes and scan configuration with the run.

The current 16-unique-input synthetic corpus remains a development regression
suite; it is not an independent or sufficiently representative validation
benchmark. On 2026-10-16, the executable suite reported TP=2, FP=0, FN=0, TN=2
for each of five detector checks (AST endpoints, regex endpoint fallback, HTTP
parameters, secrets, and DOM flows). Those perfect small-sample results only
show that the current hand-authored controls pass; they are not estimates of
production precision or recall and do not satisfy the benchmark acceptance
criteria.

### Original static corpus v1

To replace the hard-coded sample list with traceable inputs, an original
hand-authored corpus and metric runner were added at
`benchmarks/static-corpus/v1/`. It contains 50 case-detector entries (40 unique
source snippets because AST and regex endpoint detectors are evaluated against
the same endpoint inputs). Five detector checks each have 4 positives, 4
negatives and 2 ambiguous cases; binary metrics exclude ambiguous cases. Dev
and validation splits use distinct template families for each detector.
Inputs are new minimal fixtures under this repository's MIT license; no
third-party source or labels are copied. The corpus records a fixture URI,
rationale and expected signal for each case.

This is a repeatable controlled regression set, **not independently curated or
representative validation**. All examples and labels were authored/reviewed by
the maintainers, the validation labels are visible, and no independent
real-project sample has yet been reviewed. JsVul remains excluded because
dataset-level CC-BY-4.0 metadata does not establish licensing for every
upstream project record, while its labels do not directly describe browser
source-to-sink behavior. VulnerableApp remains a separate DAST result and is
not pooled into static metrics.

Executed on 2026-10-17 (`rustc 1.98.1`, worktree based on `61b843d`) with
`cargo test -p webrev-extract --test static_corpus -- --nocapture`:

| Detector | TP | FP | FN | TN | Ambiguous | Precision | Recall | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AST endpoints | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |
| Regex endpoints | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |
| HTTP parameters | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |
| Secrets | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |
| DOM source-to-sink | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |

The regex endpoint false positive had been a `fetch()` string inside a comment;
its false negative had been a literal WebSocket URL emitted as a config
candidate rather than an Endpoint. Comment masking and explicit WebSocket
extraction now remove these mismatches in the current corpus. The runner passes
as a metric calculation/structure test and does not gate on accuracy. With only
four positive and four negative examples per detector, this set cannot validate
the Step 5 thresholds. It also does not measure active SSRF: that detector needs
separately controlled HTTP evidence.

### OWASP Juice Shop browser compatibility probe

A four-positive probe from OWASP Juice Shop v19.0.0 (MIT, pinned upstream
commit `36870cbbdfe7864698e1adf644c7bf772f67ebb7`) is archived in
`benchmarks/juice-shop/v19.0.0/`. The source and official challenge evidence
support a frontend API request with query parameter `q` and a DOM XSS challenge
flow from a query parameter through Angular `bypassSecurityTrustHtml` to an
`[innerHTML]` template binding. After generic Angular `HttpClient` support,
Webrev detects the endpoint with both endpoint extractors and extracts query
parameter `q`. It still misses DOM taint because source and sink span a
TypeScript component and an Angular template. The set has no reliable
negatives or secrets, so precision and false-positive rates are not
measurable. It is an external compatibility probe, not an accuracy benchmark.

The broader external-source audit, including corpus schemas, pinned versions,
license and exclusion reasons, is recorded in
`benchmarks/external-audit/2026-10-16/README.md`. None of the reviewed sources
currently provides an adequate general static detector benchmark for Webrev.

### Multi-file DOM XSS positive corpus

The Apache-2.0 [`kanaoka-laboratory/multifile-domxss-dataset` repository at
pinned commit `28f06b4b331c6192477c8987deee3cfaf08eaf57`](https://github.com/kanaoka-laboratory/multifile-domxss-dataset/tree/28f06b4b331c6192477c8987deee3cfaf08eaf57)
provides 342 positive project cases derived from Firing Range: 69 source/sink
combinations arranged across five ES-module splitting methods. The 342
folders represent only 69 correlated templates, and the dataset contains no
negative cases. It is appropriate as an external multi-file coverage diagnostic,
not as an intra-file recall, precision or overall accuracy benchmark. The paper reports the
multi-file evaluation set and its 342 cases ([ICISSP 2025 paper](https://www.scitepress.org/PublishedPapers/2025/131093/)).

Webrev's pinned copy and runner are in
`benchmarks/external-domxss/multifile-v1/`. We preserve each JavaScript file
boundary and score only an exact source→sink evidence match after mapping
upstream category IDs to Webrev source/sink categories. For example, source ID
15 maps by category to Webrev's `event.data`, not by literal label equality. Of
the 342 positive variants, 122 fit the current modeled source/sink categories
(25 unique pairs). The runner finds **0/122 exact cross-file matches** in that subset. It analyzes
each JavaScript module independently, while each case places its source and sink
in separate modules. This measures multi-file propagation coverage of the
current extraction pipeline, not intra-file detector recall. It emits raw
DOM-flow signals on 12 cases, but none matches the case's annotated source and
sink. No negatives means precision and FPR are unavailable. Out-of-scope cases
are not treated as safe.

### Additional external corpus candidate check

On 2026-10-16, the public [`RusDavies/security-defect-corpus`](https://github.com/RusDavies/security-defect-corpus)
was inspected at commit `84dd9c822eea735448353a01afe5e7e0df6549c4`. Its root
MIT license allows reuse with attribution, and the project provides explicit
reachable/unreachable pairs and machine-readable ground truth. It is a
maintainer-authored controlled fixture suite, however, not a collection of
independently adjudicated real-world reports. Its JavaScript XSS and redirect
cases are server-side Express-style handlers, while Webrev's static detector
corpus targets browser-facing HTML/JavaScript extraction; its WebSocket beacon
pair is adjacent but measures code reachability and unauthorized behavior,
which Webrev does not currently claim to prove. Therefore the candidate was
not copied or scored, and cannot replace the missing independent detector
validation corpus. The audit inspected the source, labels, license, and the
corpus's own benchmark-contamination guidance.

### 2026 external candidate acquisition and SWIPE diagnostic

SWIPE is the closest newly reviewed source for browser DOM-XSS: its paper
reports 44,480 collected URLs and 194 pages classified as vulnerable, while
the released artifact is analysis code and selected local fixtures rather
than a frozen snapshot of those live pages. Only 30 local cases were selected
from its MIT artifact; 32 HTML/JavaScript source files are preserved byte for
byte with hashes under `benchmarks/external-candidates/swipe-v1/`. No public
SWIPE URLs were scanned. See the [paper](https://users.ece.cmu.edu/~lbauer/papers/2026/ndss2026-dom-xss.pdf)
and [artifact](https://doi.org/10.5281/zenodo.15883603).

The first run of `cargo test -p webrev-extract --test swipe_domxss_external -- --nocapture`
reported 30 cases: TP=13, FP=1, FN=3, TN=12, and one inconclusive case. Two
targeted changes were then measured against the same fixtures: `search()` and
other numeric/boolean string methods no longer propagate string taint, and
dynamic event-handler sinks (`setAttribute('onclick', …)` and `element.onclick`)
are recognized. The rerun reports TP=14, FP=0, FN=2, TN=13, with one
inconclusive case. On the 16 manually reviewed positives and 13 negatives this
is precision 100%, recall 87.5%, FPR 0%, and FNR 12.5%.
The labels were adjudicated from fixture source and rationale by maintainers;
the publication does not supply these per-file labels. Treat these as a
small external-fixture diagnostic, not independent accuracy evidence. The
initial false positive flowed through `String.search()` to `document.write`
even though the retained value is numeric. The initial `onclick` miss is now
detected; remaining misses are a cross-file helper flow and object-field alias
propagation. The iframe navigation case is inconclusive and excluded from
binary rates.
Raw output and per-case provenance are preserved in `swipe-v1/results.json`
and `cases.jsonl`.

Two pinned source archives were also acquired for offline follow-up:
[Google Firing Range](https://github.com/google/firing-range/tree/4f991a6418b07a66cd63006f4a2bec27c84b72f4)
is an Apache-2.0 synthetic XSS scanner testbed with source/sink combinations,
but its archived App Engine runtime is legacy and it has not been scored by
Webrev. [Security Defect Corpus](https://github.com/RusDavies/security-defect-corpus/tree/84dd9c822eea735448353a01afe5e7e0df6549c4)
is MIT licensed; its own validator confirms 84 cases across 23 ecosystems.
Selected JS/TS/Node cases include server-side SSRF, redirect, XSS and secret
examples, but the suite is small and largely outside browser extraction.
Both archive hashes and pins are recorded in
`benchmarks/external-candidates/snapshots/SHA256SUMS`.

Other 2026 candidates were evaluated but not acquired for scoring. SecBench.js
has 600 vulnerable Node/npm package cases but is server-side and its reuse
license was unclear; X.js describes Node-only source/sink cases and no released
dataset was located; Snyk VulnBench targets repeatable agentic code-fixing,
not independent scanner accuracy. The decision and limitations are tracked in
`benchmarks/external-candidates/README.md`. No third-party dependencies were
installed or executed.

### Paired static-corpus baseline (2026-10-16)

The same v1 case file was run on current Webrev and on clean baseline commit
`61b843daf845946060abae026b43349170ff177b`. For the baseline run, the Rust
metric runner and the unmodified `cases.jsonl` were copied into a detached
worktree; no detector code or fixture was changed. Counts below combine the
dev and validation splits, excluding ambiguous labels (4 positives and 4
negatives per detector).

| Detector | Baseline TP/FP/FN/TN | Current TP/FP/FN/TN | Baseline precision / recall | Current precision / recall |
| --- | --- | --- | --- | --- |
| AST endpoints | 4/2/0/2 | 4/0/0/4 | 66.7% / 100% | 100% / 100% |
| Regex endpoints | 4/2/0/2 | 4/0/0/4 | 66.7% / 100% | 100% / 100% |
| HTTP parameters | 4/2/0/2 | 4/0/0/4 | 66.7% / 100% | 100% / 100% |
| Secrets | 4/2/0/2 | 4/0/0/4 | 66.7% / 100% | 100% / 100% |
| DOM source-to-sink | 4/0/0/4 | 4/0/0/4 | 100% / 100% | 100% / 100% |

Reproduce the baseline by checking out the pinned commit in a detached worktree,
copying the current `crates/webrev-extract/tests/static_corpus.rs` and
`benchmarks/static-corpus/v1/cases.jsonl` into their corresponding paths, then
running `cargo test -p webrev-extract --test static_corpus -- --nocapture`.
Run the same command in the current checkout for the candidate. This is a
paired regression comparison, not an independent accuracy estimate: the
small corpus and visible labels were authored by Webrev maintainers. The regex
endpoint detector removes two baseline false positives and now has no binary
mismatch in these eight labeled cases; this small set does not establish
general accuracy.

### Explicit module linking follow-up (2026-10-17)

The pinned multi-file corpus is now evaluated with separate ASTs linked through
explicit ES-module value imports, using one session per case. Exact matches
increase from **0/122 to 26/122**, covering 13/25 unique modeled source/sink
pairs. Type01 has 13/25 matches, type02 13/22; types03–05 remain at 0/25 each.
The matcher and source/sink category subset are unchanged. The runner guards
26 matches as a regression count; this is not an accuracy threshold.

`benchmarks/external-domxss/multifile-v1/results.json` retains the independent-file
baseline; `linked-results.json` and `linked-run.log` record the executed follow-up.
The additional 44/342 cases with any raw DOM-flow signal must not be counted as
44 annotated exact matches. All labels remain positive, synthetic and correlated;
precision and FPR cannot be computed from this corpus.

The implementation summarizes straight-line value-export initialization and
named function exports with short, synchronous, straight-line bodies (later
addition; the archived `multifile-v1` JSON files predate it and were not
regenerated). Namespace imports (`ns.name`), `export {..} from` and `export * from`
re-exports, and top-level local functions taking parameters were added later and
are covered by unit tests only; the archived corpora and their counts were not
re-run against them. Classic (non-module) scripts across files, closures, computed
namespace members, `export * as ns from` and general interprocedural flows remain
unsupported. The pipeline links modules already collected without fetching
additional imports. Candidates remain `Suspicious` with `Medium` confidence,
source/sink provenance and no claim of runtime execution. Analysis is bounded to
128 modules, 512 KiB/module, 8 MiB total and eight linking passes. Negative unit
controls cover sanitizer, overwrites, numeric results, shadowed parameters/catch,
default-export snapshots, blocks, duplicate URLs and unresolved imports; these
controls improve regression protection but are not independent accuracy evidence.

SWIPE remains a per-file diagnostic because its remaining cross-file helper uses
classic scripts. Its result stays TP14/FP0/FN2/TN13 with one inconclusive case.
The runner now asserts results per case, verifies the full 32-file inventory and
exercises the previously omitted companion `hero.js`; CI runs it and checks its
hashes. No upstream source or label was changed.

### External corpus v1 and the two taint-rule fixes it found (2026-10-19)

`benchmarks/external-corpus/v1/` is a second, larger external validation
corpus: 331 cases across five sources whose labels come from a party
independent of this repository — 15 GitHub Security Advisory DOM XSS CVEs
(paired with their fix commit), the `sak3y/ML-XSS-Detector` dataset, the
`pwnfunction` XSS Game challenges, the `domdig` scanner's own test pages, and
28 unlabelled npm distribution files for a background rate. See
`benchmarks/external-corpus/v1/README.md` for the full protocol, pinning and
label provenance of every source.

The first run (detector at `6b33d8d`) had precision 100% wherever measurable
but recall 0% on the GHSA CVEs, 0% on pwnfunction, 20% on sak3y, 25% on
domdig — a sharp contrast with the SWIPE result above. Reading the missed
cases found two taint-flow rules missing from
`crates/webrev-extract/src/extractors/metadata/domsinks/taint.rs`, not
obscure edge cases: `new URL(tainted)` / `new URLSearchParams(tainted)` were
never classified as a taint source at all, so the dominant pwnfunction/sak3y
idiom `new URL(location).searchParams.get(...)` was invisible to the
analysis; and `classify()` only handled `+` among binary operators, so the
equally common `param || "default"` / `param ?? "default"` fallback idiom
broke the taint chain. Both were added, each with a dedicated positive and
negative unit test (`domsinks_tests.rs`).

Rerun: pwnfunction 0% → 57% recall (8/14), sak3y 20% → 52% (65/124), GHSA
0% → 6.7% (1/15 — most remaining GHSA cases are multi-file flows through
`postMessage`, outside this detector's intra-file scope), domdig unchanged
(25% — none of its cases use either idiom). Precision on sak3y dropped to
98.5%: `sak3y/snippet_179` manually HTML-entity-encodes (`&`, `<`, `>`)
before `innerHTML`, which is a real sanitizer the detector does not
recognize (today only `DOMPurify.sanitize` breaks taint). Recognizing manual
entity-encoding as a sanitizer is tracked as follow-up work, not fixed here.
Of the four pwnfunction cases still missed, three route through
`DOMPurify.sanitize` by design (the challenge is a sanitizer-bypass puzzle)
and one (`bourne`) is an object-key confusion bug, not a DOM XSS flow.

### Native paired performance measurement (2026-10-17)

The final integrated candidate in
`benchmarks/performance/2026-10-17/spa-site-optimized/` uses 30 seeded randomized
pairs on the same deterministic 120-route local fixture. P95 is
38.081 → 45.178 ms (+18.64%); maximum RSS is 20,748 → 22,136 KiB (+6.69%).
All 60 scans succeed; findings remain 574 baseline and 760 candidate. Both
proposed thresholds pass on this fixture. The candidate archive and per-source
hashes pin the dirty worktree used; external package versions, sources and
checksums are unchanged between revisions, while local dependency edges differ.

The canonical runner now delegates measurement to `scripts/measure_process.c`.
Direct Python `fork`/`wait4` and even `posix_spawn` can contaminate the child's
RSS high-water mark with inherited Python memory. A small native parent starts
the scanner and collects `wait4` RSS; a controlled memory-allocation probe is
archived. Earlier Python RSS numbers are historical and must not be interpreted
as isolated scanner memory. Build and native-launcher startup are excluded from
runtime; scanner process startup is included, equally for both revisions.

The native pre-regex run is retained under `spa-site-native-pre-regex/`:
p95 +21.43%, RSS +14.55%, 60/60 successful scans. A subsequent code change
removes two redundant optional Unicode receiver prefixes from unanchored
HttpClient regexes; capture-equivalence tests pass. Its isolated compilation
microbenchmark saves about 0.590 ms across the two patterns. The final paired
campaign above follows that change; background activity on this shared machine
prevents attributing the entire between-campaign delta to the regex change.
The biased Python-launcher run is separately marked diagnostic. No passing run
was obtained by repeating an unchanged candidate until it met the threshold.
