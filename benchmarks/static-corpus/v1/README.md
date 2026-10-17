# Webrev static detector corpus v1

This is a small, manually authored, deterministic fixture set for evaluating
the current JavaScript/HTML extractor behavior. Every source snippet was
written for this repository from scratch; no third-party source code or labels
are redistributed. The repository's top-level license applies to these new
fixtures.

This corpus is independent of the detector implementation at the *input*
level, but it is **not an independently curated validation benchmark**. The
same maintainers who reviewed the detectors authored and labeled it, it has
few cases, and cases do not represent real application distributions. It is
useful for repeatable regression measurements only. Do not use its scores as
production precision or recall estimates, or to claim Step 5 is validated.

## Layout and labels

`cases.jsonl` contains one JSON object per case with the raw snippet, target
detector, expected label, source family, split, rationale, and expected signal.
`dev` and `validation` use different template families for each detector; no
individual snippet is split across them. The validation labels are published
because this is a regression artifact, not a secret challenge set. Do not tune
against validation cases and then describe the result as held-out performance.

Labels:

- `positive`: the detector should emit its matching signal.
- `negative`: the detector should not emit that signal.
- `ambiguous`: reasonable behavior depends on runtime context, unsupported
  dataflow, or a product boundary. These cases are listed but excluded from
  binary metrics.

Detector predicates are deliberately narrow: AST/regex endpoint findings,
HTTP parameter findings, secret findings, and DOM-XSS flow findings. For DOM
XSS a static flow is a suspicious lead, not proof of exploitable impact.
SSRF is not represented here because the active probe requires an HTTP lab and
response evidence; its separate VulnerableApp run is not pooled with static
extractor metrics.

## Run

```sh
cargo test -p webrev-extract --test static_corpus -- --nocapture
```

The test prints TP, FP, FN, TN, precision, recall, FPR, and FNR per detector,
plus ambiguous counts. A zero denominator is printed as `n/a`; ambiguous cases
never count as true negatives. The test also validates unique IDs and required
annotation fields.

## Provenance and limits

All inputs are original minimal examples, dated 2026-10-16, and carry an
internal `fixture://` provenance identifier. They intentionally exercise
different syntax shapes (fetch/axios/XHR/WebSocket, forms/query strings,
credential shapes/HTML identifiers, direct and transformed DOM flows), but
they do not originate from distinct real projects. The `project_family` split
therefore prevents template overlap, not project-level dataset leakage in the
strong empirical sense. Labels are reviewed against the stated detector
predicate and source text; they are not exploitability labels.

The external candidates reviewed so far are not incorporated: JsVul's CC-BY-4.0
dataset-level record does not by itself establish rights for every upstream
project file, and its labels are code-pair heuristics rather than Webrev
browser-flow ground truth. OWASP Benchmark is mostly Java/Python server-side;
VulnerableApp is retained as a separate DAST lab. See
`docs/benchmark-methodology.md` for that review.

## Measured result

Executed 2026-10-16 from the working tree based on revision `61b843d`, with
`rustc 1.98.1 (48a229cea 2026-09-01)`:

```text
cargo test -p webrev-extract --test static_corpus -- --nocapture
```

The metric runner test passed and evaluated 50 case-detector entries (40
distinct snippets); each detector has four binary positives, four binary
negatives and two ambiguous cases, split evenly between dev and validation.
Aggregated results:

| Detector | TP | FP | FN | TN | Ambiguous | Precision | Recall | FPR | FNR |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| AST endpoints | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |
| Regex endpoints | 3 | 1 | 1 | 3 | 2 | 75% | 75% | 25% | 25% |
| HTTP parameters | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |
| Secrets | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |
| DOM source-to-sink | 4 | 0 | 0 | 4 | 2 | 100% | 100% | 0% | 0% |

The two regex endpoint mismatches are concrete: it reports an endpoint-looking
call inside a comment, and it treats a literal WebSocket URL as a config
candidate instead of an `Endpoint`. The latter is a recall miss for this
corpus's endpoint predicate; Webrev still emits a lower-confidence static URL
candidate. These cases are intentionally retained and are not counted as
ambiguous. Scores are based on only four positive and four negative examples
per detector, so even 100% values have almost no statistical precision.

The Rust test verifies corpus structure and computes results; it does not fail
when detector output differs from labels. This is deliberate so the benchmark
can report current mismatches without fabricating a passing accuracy gate.
Existing focused unit tests remain the regression gate. The v1 corpus is not
large or independent enough to validate Step 5.
