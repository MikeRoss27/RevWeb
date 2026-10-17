# Local crawl runtime, RSS, and stability measurement

## Result

This is a reproducible microbenchmark, not a production workload. The scanner
ran a deterministic, loopback-only static crawl with 40 HTML pages and eight
JavaScript bundles. The same generated fixture, scope, budgets, release profile,
and machine were used for both binaries. Build time was excluded. The measured
process runtime includes CLI startup and report serialization.

| Revision | Runs | Median | p95 | Maximum RSS | Findings per run | Failed runs |
|---|---:|---:|---:|---:|---:|---:|
| `HEAD` `61b843d` | 20 | 19.068 ms | 22.130 ms | 19,536 KiB | 265 (all runs) | 0 |
| Dirty worktree | 20 | 22.833 ms | 25.134 ms | 19,684 KiB | 265 (all runs) | 0 |
| Change | — | — | **+13.57%** | **+0.76%** | no variation | — |

Both observed changes are within the proposed limits (p95 ≤20%, maximum RSS
≤25%). All 40 scans exited successfully, emitted parseable JSON reports, and
had the same finding count within each revision. This is evidence of stability
for these 40 runs and this fixture only; it does not establish stability for
long-duration or production scans.

## Reproduce

From the repository root, with Cargo, Rust, Python 3, and Git installed:

```sh
python3 scripts/benchmark_performance.py \
  --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --runs 20 --pages 40 --output /tmp/webrev-perf-rerun
```

The harness builds both release binaries, serves the generated fixture on
`127.0.0.1`, uses a seeded shuffle of a balanced run order, and records raw
per-run wall time and Linux `wait4` maximum RSS. The p95 uses nearest rank.
`results.json` contains the raw run records, parameters, environment and
aggregate calculations from the original run.

## Environment and limits

- Arch Linux x86_64, kernel 7.2.9, glibc 2.44.
- 13th Gen Intel Core i7-13620H, 16 logical CPUs.
- rustc 1.98.1, Cargo 1.98.1.
- Static-only command, `--max-pages 40 --max-depth 2 --max-concurrency 4`,
  zero delay, explicit `127.0.0.1` scope.
- The baseline is the clean Git `HEAD`; the candidate was a dirty worktree.
  Both were built with the same copied `Cargo.lock` and toolchain, but source,
  manifests, and features differ across many changes. Therefore this measures
  the combined revision delta and cannot attribute cost to any one detector.
- The local server is not included in scanner RSS. Runtime is dominated by a
  small local fixture and must not be projected to remote or browser scans.

The raw archive is `results.json`. The source harness is
[`scripts/benchmark_performance.py`](../../../scripts/benchmark_performance.py).
