# External static credential-presence diagnostic

Pinned source: [Russ Davies, Security Defect Corpus](https://github.com/RusDavies/security-defect-corpus/tree/84dd9c822eea735448353a01afe5e7e0df6549c4),
commit `84dd9c822eea735448353a01afe5e7e0df6549c4`, MIT (see
`upstream/LICENSE`). Eight JavaScript/TypeScript files are preserved byte for
byte from the already archived snapshot. `acquire.py` rebuilds this selection
without network access; `provenance.json` identifies its archive hash.
No upstream program, dependency, service or URL is executed.

This covers the secret extractor's **static credential presence** predicate.
It does not evaluate DOM XSS, browser reachability, backdoor exploitability or
whether a credential is active. Server-side JS/TS is relevant to this text
extractor, but is not evidence for browser application generalization.

## Selection and label review

Selection was made before executing Webrev: the three JS/TS families in the
pinned ground truth with hardcoded authentication credentials (payment API key,
operator key, magic password). Each has reachable, unreachable and fixed
variants. The fixed TS-secret function duplicates the unreachable implementation
and is omitted; eight files remain across three strongly correlated families.
All original ground truth is retained at `upstream/ground_truth/cases.json`.

Webrev maintainers reviewed source and upstream ground truth to adjudicate
five positive and three negative **presence** labels in `cases.jsonl`.
These are not upstream binary reachability labels. In particular:

| Family | Reachable | Unreachable | Fixed | Evidence |
| --- | --- | --- | --- | --- |
| TS-SECRET-001 | positive | negative | omitted duplicate | Literal `apiKey` versus environment variable plus explicitly documented test placeholder. |
| NODE-BACKDOOR-OPKEY-001 | positive | positive | negative | Authentication key remains in retired code; fixed source removes it. |
| NODE-BACKDOOR-MAGIC-001 | positive | positive | negative | Password remains in retired code; fixed source removes it. |

The upstream `unreachable` operator/password variants must **not** be counted
as secret-negative controls merely because the vulnerable operation is
unreachable. Their literals are present in the input text. Conversely, an
environment-variable name or the documented placeholder is not a credential.
All values are controlled fixture values; a positive label does not mean a
real exposed secret or a Confirmed vulnerability.

Review is **not independent**. No person outside the Webrev implementation
team has adjudicated these labels. The evaluating agent had access to source,
ground truth, fixed fixtures and benchmark validity guidance before execution;
this is potentially contaminated development evidence, with no held-out claim. `label-review.json` explicitly preserves
that pending status. Before any independent-quality claim, a named reviewer
who did not implement the detector must inspect original source and ground
truth without seeing predictions, record the exact credential use or exclusion,
resolve disagreements, and then freeze labels with hashes before scoring.
A second automated agent is not an independent external reviewer.

## Reproduce

```sh
python3 benchmarks/external-secrets/sdc-v1/acquire.py
(cd benchmarks/external-secrets/sdc-v1 && sha256sum -c SHA256SUMS)
CARGO_TARGET_DIR=/home/na/.cache/webrev-validation-target \
CARGO_PROFILE_DEV_DEBUG=0 CARGO_PROFILE_TEST_DEBUG=0 \
WEBREV_SDC_SECRETS_REPORT="$PWD/benchmarks/external-secrets/sdc-v1/results.json" \
cargo test -p webrev-extract --test sdc_secrets_external -- --nocapture
```

The runner scores any `FindingKind::Secret` against the whole-file presence
label. It guards each negative and the initially detected payment-key positive;
new detections on known missed positives are allowed. It does not gate on an
aggregate accuracy threshold. Findings from different files cannot compensate
for a per-case regression.

Executed result (`results.json`, `run.log`): **TP=1, FP=0, FN=4, TN=3**.
Precision is 100%, recall 20%, FPR 0% and FNR 80% on these eight cases.
The payment API literal is detected; the short operator key and magic password
are missed in both reachable and retired variants. These misses expose limited
credential-shape coverage; the detector was not changed to fit this selection.

Read these as compatibility diagnostics only. Eight visible cases, three correlated toy
families, maintainer-remapped labels and no live-secret validation cannot
establish precision, recall or false-positive rates on real applications.
