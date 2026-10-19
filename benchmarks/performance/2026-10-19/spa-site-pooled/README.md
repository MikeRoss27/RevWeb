# Pooled SPA scan measurement, judged with a bootstrap interval

First measurement under the pooled criterion fixed in `goal.md` ("Définition de la
mesure, révisée le 2026-10-19") **before** it was run. Tool: `scripts/benchmark_pool.py`
(`benchmark_performance.py pool RESULTS.json...`), 2 000 two-level bootstrap draws,
seed 20261019.

Setup: baseline `61b843d` (binary SHA-256 `082e27b3...`, the same file hash as the
2026-10-18 baseline), current = `main` at `6b33d8d` (Rust sources identical to the commit
measured; binary `e299dbbe...`), both built once with `CARGO_BUILD_JOBS=2` and reused
(`--baseline-bin`, `--current-bin`). Profile `site`, 120 pages, 30 seeded pairs per
invocation, native `measure_process.c` launcher, `--max-load 4`, 16 logical CPUs.
Findings: 574 (baseline) and 760 (current); 0 failed scans in 720 runs.

Two batches of 6 invocations, seeds `2026101N` (batch A, planned) and `20261019NN`
(batch B, a replication run after batch A, see "What this does and does not show").

| scope | runs/rev | p95 base → current | Δ p95 (95% CI) | median time Δ (95% CI) | RSS median Δ | RSS max Δ | verdict |
|---|---:|---|---|---|---:|---:|---|
| batch A (01-06) | 180 | 30.8 → 35.8 ms | **+16.0%** (+12.3% .. **+20.5%**) | +18.1% (+16.2 .. +20.3) | +11.6% | +4.4% | **not demonstrated** |
| batch B (07-12) | 180 | 31.4 → 36.1 ms | +15.0% (+10.1% .. +18.8%) | +16.9% (+15.0 .. +18.8) | +11.4% | +5.3% | pass |
| all 12 | 360 | 31.1 → 35.8 ms | +15.2% (+12.2% .. +18.5%) | +17.4% (+16.1 .. +19.0) | +11.6% | +4.4% | pass |

Per-invocation single-30-run p95 change (the old criterion), in order:
A: 22.4, 13.9, 16.8, 13.2, 18.1, 17.3 %; B: 16.0, 16.7, 16.0, 7.3, 12.7, 20.3 %.
Over the +20% line: 1 of 6 in A (22.4%), 1 of 6 in B (20.3%), 2 of 12 overall. No baseline
RSS anomaly was flagged (the 14.4 MiB cold-baseline mode of 2026-10-18 did not recur).

## What this does and does not show

- RSS is comfortably inside the limit (max +4.4%, median +11.6%), and stable.
- The p95 point estimate is +15 to +16% in both batches, inside the limit. The upper
  bound of the 95% interval is +20.5% for the planned batch A: **above** the line by half
  a point, so the strict criterion (upper bound ≤ +20%) is **not met** by that batch.
- Batch B was run **after** seeing batch A's bound, as a replication; it passes (+18.8%),
  and so do the 12 together (+18.5%). A replication run only because the first result was
  disappointing is subject to optional stopping, so it is reported but the checkbox is
  **not** ticked on it. A pre-declared third batch, or accepting the 12-invocation pool as
  the pool of record, is a decision for the owner; the evidence is archived either way.
- Absolute times are about 2.5x shorter than on 2026-10-18 (baseline p95 31 ms vs 77 ms):
  the host is faster today, the ratios are consistent (+16 to +17% before, +15 to +16% now).

## Where the extra time goes (partial)

`stage-timing/extractors.txt`: a scratch harness timing every default extractor over the
same 251 inputs in both trees (not committed). Extraction goes from 10.15 to 11.38 ms
(+12.1%) per pass: `params` 0.30 → 0.89 ms (x3), `js-ast` +0.39 ms (and 100 more findings),
`js-regex` +0.38, `secret` +0.29, `html` +0.12, while `dom-sinks` is 0.68 ms faster.
That is about 1.2 ms of the ~4.7 ms wall-clock difference per scan; the remaining
~3.5 ms (crawl, storage and deduplication stages, report writing, startup of a 7.4% larger
binary: 22.0 → 23.7 MB) could not be attributed without a profiler (`perf` is not
installed here). Nothing was optimised in this change.

## Files

`invocationNN/results.json` (one per invocation, including per-run load), `pooled-01-06.json`,
`pooled-07-12.json`, `pooled-all-12.json` (outputs of the pooling tool), `stage-timing/`,
`SHA256SUMS`.
