# Paired SPA scan re-measurement on current main

Three independent runs of `scripts/benchmark_performance.py` on current code
(commit `6bdc3cc`; the Rust sources are identical to `00f58f0`, only docs
differ), against the same baseline `61b843d` and the same profile as the
2026-10-17 PASS: 30 seeded pairs per run, `--pages 120 --profile site`,
loopback fixture, native `measure_process.c` launcher. This supersedes the
2026-10-17 result for the code on `main`, which predates cross-module function
summaries, the wider secret regex, the egress proxy and the redaction guards.

| Run | Baseline p95 | Current p95 | p95 change | Baseline max RSS | Current max RSS | RSS change |
|---|---:|---:|---:|---:|---:|---:|
| 1 | 35.386 ms | 39.542 ms | +11.74% | 20,660 KiB | 22,012 KiB | +6.54% |
| 2 | 32.393 ms | 37.303 ms | +15.16% | 15,928 KiB | 23,116 KiB | +45.13% |
| 3 | 31.900 ms | 36.310 ms | +13.81% | 15,824 KiB | 22,356 KiB | +41.28% |

All 90 scans per revision succeeded; findings 574 (baseline) and 760 (current)
in every run.

Per-run RSS (KiB, from `raw_runs`):

| Run | Baseline min / median / max | Current min / median / max |
|---|---|---|
| 1 | 18,020 / 18,870 / 20,660 | 19,464 / 20,870 / 22,012 |
| 2 | 13,580 / 14,552 / 15,928 | 19,512 / 21,118 / 23,116 |
| 3 | 13,596 / 14,454 / 15,824 | 20,000 / 21,152 / 22,356 |

## Verdict

- Runtime threshold (p95 overhead <= 20%): **PASS** in all three runs
  (+11.74%, +15.16%, +13.81%).
- RSS threshold (<= 25%): **FAIL / not validated.** Runs 2 and 3 exceed it
  (+45.13%, +41.28%); only run 1 passes (+6.54%).

The current binary's RSS is stable across runs (median 20.9-21.2 MiB). The
baseline's RSS is not: its median is 18.9 MiB in run 1 and 14.5 MiB in runs 2
and 3, and the 2026-10-17 baseline was 20.7 MiB. Why the baseline moved is not
established, so the RSS comparison is unreliable and no PASS is claimed. Read
conservatively against the lowest baseline (runs 2-3), the current code uses
about 6.5 MiB more than the baseline on this fixture.

## Conditions

The host was not isolated; other user sessions were compiling throughout.
1-minute load average at the start of each run, taken after waiting for it to
drop below 4 (bounded wait), and immediately after: 3.74 -> 16.75 (run 2),
3.92 -> 14.56 (run 3); run 1 started at 4.96 -> 16.96 (no wait). The script
builds both revisions in release mode right before measuring, so the load at
measurement time includes those builds. `host-load-run*.txt` hold the raw
`uptime`/`free` snapshots. Changes between runs must not be attributed to code.

## Reproduction

```sh
python3 scripts/benchmark_performance.py \
  --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --runs 30 --pages 120 --profile site --output /tmp/webrev-remeasure
```

`results-run*.json` contain per-run observations, binary hashes and the
fixture hash recorded by the script.
