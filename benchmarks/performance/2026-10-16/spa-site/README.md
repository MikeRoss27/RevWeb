# SPA-like local crawl performance measurement

## Result

This expands the earlier 40-page microbenchmark with a deterministic, loopback-only
multi-asset site. It is still a generated workload, not a captured production site
or an external lab application.

| Revision | Runs | Median | p95 | Maximum RSS | Findings per run | Failed runs |
|---|---:|---:|---:|---:|---:|---:|
| Baseline `61b843d` | 20 | 28.846 ms | 29.987 ms | 20,024 KiB | 574 | 0 |
| Dirty worktree | 20 | 179.377 ms | 183.435 ms | 22,588 KiB | 755 | 0 |
| Change | — | — | **+511.72%** | **+12.80%** | different detector outputs | — |

The p95 increase exceeds the proposed 20% limit. The RSS increase remains below
the proposed 25% limit. All 40 scans exited successfully, emitted parseable
reports, and produced one stable finding count per revision. This does not pass
the performance gate. The finding count differs because the worktree changes
detector behavior; it is not a performance equivalence assertion.

## Workload

- 120 generated HTML routes, organized into six sections with neighbor links.
- Eleven JS files (three shared bundles and eight section chunks), with repeated
  endpoint-bearing module declarations to exercise JavaScript extraction.
- One CSS file, twelve SVG assets, forms, inline scripts, and internal navigation.
- Static scan: scope `127.0.0.1`, max pages 120, max depth 2, concurrency 4,
  zero delay. No external network requests.
- 20 runs per revision in seeded shuffled order. Builds are excluded from run
  times; each scan's wall time includes process startup and report serialization.
- p95 uses nearest rank. RSS is per scanner process from Linux `wait4`.

## Reproduce

Run from the repository root with the archived `harness.py` (identical to the
measured harness):

```sh
python3 benchmarks/performance/2026-10-16/spa-site/harness.py \
  --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --runs 20 --pages 120 --profile site --output /tmp/webrev-perf-spa-rerun
```

The baseline build uses the current worktree's `Cargo.lock`, copied into its
detached checkout before both builds. The dirty worktree source inputs at
measurement time are identified by the SHA-256 digest in `results.json`; the
working tree itself was not committed or bundled in this archive. A rerun is
comparable only when those source inputs, Rust toolchain, hardware, and machine
load match. Builds used separate target directories. The harness starts a
temporary `127.0.0.1` HTTP server and removes its detached worktree afterward.

## Limits

This is a moderately sized synthetic SPA-like crawl. It exercises page fan-out,
shared and chunked JavaScript assets, and extraction volume, but lacks real-world
bundle diversity, compression, authentication, browser execution, and network
latency. It is stronger evidence than the tiny repeated-page microbenchmark but
does not establish production performance. The comparison covers the combined
dirty-worktree changes and cannot attribute the slowdown to one change.

`results.json` contains all 40 raw per-run timings, RSS values, exit codes,
finding counts, environment details, fixture digest, and source-input digest.
