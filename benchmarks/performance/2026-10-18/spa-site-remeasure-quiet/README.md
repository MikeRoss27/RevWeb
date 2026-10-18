# Paired SPA scan re-measurement on a quiet host, with fixed binaries

Follow-up to `../spa-site-remeasure/`, whose baseline RSS moved between runs
(18.9, 14.5, 14.5 MiB; 20.7 MiB on 2026-10-17) for no established reason. Here
both binaries are built **once** and reused (`--baseline-bin`, `--current-bin`),
so every invocation measures the same two files. Code under test: `main` at
`b3f5e42` (includes the DOM XSS namespace/re-export/local-function work);
baseline `61b843d`; same profile as before (`--pages 120 --profile site`,
30 seeded pairs per invocation, loopback fixture, native `measure_process.c`
launcher). Each invocation uses a different `--seed`, i.e. a different run order.

Binary SHA-256 (identical in every file): baseline
`082e27b3...df05f`, current `42efbc31...78a115` (full hashes in the JSON).
Rebuilding the baseline into a fresh target directory produced the same hash
(`082e27b3...`), so the build is reproducible here and is **not** what moved the
baseline RSS.

## Results per invocation

`p95` is the nearest-rank p95 of 30 runs; RSS is the scanner's `ru_maxrss`.

| # | file | load 1 min at start | p95 base → cur (Δ) | median time Δ | RSS median base → cur (Δ) | RSS max Δ |
|---|---|---:|---|---:|---|---:|
| 1 | `…invocation01-anomalous-cold-baseline` | 2.0 (after builds) | 76.1 → 94.2 ms (+23.9%) | +16.3% | 14,426 → 21,400 KiB (**+48.3%**) | +44.8% |
| 2 | `…invocation02` | 1.5 | 77.6 → 88.4 ms (+13.9%) | +18.3% | 19,148 → 21,524 KiB (+12.4%) | +14.9% |
| 3 | `…invocation03` | 1.1 | 77.0 → 92.5 ms (+20.1%) | +18.0% | 19,100 → 21,882 KiB (+14.6%) | +10.7% |
| 4 | `…invocation04` | 1.0 | 77.8 → 91.5 ms (+17.6%) | +15.9% | 18,992 → 21,688 KiB (+14.2%) | +11.6% |
| 5 | `…invocation05` | 1.2 | 78.2 → 89.0 ms (+13.8%) | +14.7% | 19,108 → 21,620 KiB (+13.1%) | +15.5% |
| 6 | `…invocation06` | 1.1 | 79.4 → 87.3 ms (+9.9%) | +15.4% | 19,142 → 21,826 KiB (+14.0%) | +9.8% |
| 7 | `…invocation07` | 1.2 | 75.2 → 93.8 ms (+24.7%) | +17.0% | 19,192 → 21,640 KiB (+12.8%) | +13.1% |
| 8 | `…invocation08` | 1.2 | 79.8 → 89.7 ms (+12.4%) | +14.1% | 19,262 → 21,678 KiB (+12.5%) | +12.1% |
| 9 | `…invocation09-warmup` | 1.8 | 75.8 → 91.8 ms (+21.1%) | +18.8% | 19,148 → 21,670 KiB (+13.2%) | +13.7% |
| 10 | `…invocation10-warmup` | 1.8 | 77.0 → 87.3 ms (+13.4%) | +15.3% | 19,078 → 21,620 KiB (+13.3%) | +13.0% |
| 11 | `…invocation11-warmup` | 1.8 | 76.4 → 89.4 ms (+17.1%) | +13.7% | 19,178 → 21,630 KiB (+12.8%) | +14.4% |
| – | `…invocation12-14-post-build-load` | 8–11 | +16.4 / +22.0 / +10.7% | – | +13.4 / +13.8 / +12.6% | +12.4 / +9.4 / +13.0% |

Invocations 12-14 ran right after a 3-minute build, with the host load still
8-11, so they are **excluded** from the pooled figures (load above the 4 limit).
Invocation 1 is excluded as the cold-baseline anomaly described below.

Pooled over the 10 clean invocations (2-11; 300 pairs per revision, computed by
`pool.py`): p95 **77.2 → 90.2 ms (+16.8%)**, median time **+16.0%**, RSS median
**19,130 → 21,676 KiB (+13.3%)**, RSS max **20,328 → 22,580 KiB (+11.1%)**.
All scans succeeded in every file; findings 574 (baseline) and 760 (current).

## What was found about the baseline RSS

- Not the build: a second build of the same source gives a byte-identical
  binary, and the same file measured in two invocations gave 14.4 MiB (inv. 1)
  and 19.1 MiB (inv. 2-11).
- Not run order or host load: invocation 1 was stable at ~14.4 MiB across all
  30 baseline runs in a shuffled order at load ~2.0; invocations 12-14 at load
  8-11 gave 19.1 MiB. The current binary stays at 21.4-21.9 MiB throughout.
- It is a per-invocation level shift, tight within an invocation (±0.5 MiB).
  Invocation 1 was the first measurement after the two builds; the unmeasured
  warm-up added to the script afterwards (2 runs per binary) is consistent with
  it, but the low mode was seen once and **not reproduced**, so the cause
  (page-cache state of the freshly built binary, or transparent huge pages,
  which are set to `always` on this host) is a hypothesis, not a finding.
- The 2026-10-17 baseline (20.7 MiB) and invocations 2-14 (19.1 MiB) agree to
  within the usual differences between builds and hosts; the 14.4-14.5 MiB
  values (invocation 1, and runs 2-3 of the earlier archive) are the outliers.

## Verdict

- RSS (limit +25%): **passes in 10 of 10 clean invocations** (+12.4% to +14.6%
  median, +9.8% to +15.5% max) when the baseline is in its usual 19.1 MiB mode.
  One invocation (the first one after the builds) showed a 14.4 MiB baseline
  and +48%; it is unexplained and not reproduced.
- Runtime p95 (limit +20%): pooled **+16.8%** (n=300 pairs), but a single
  30-pair p95 is the 29th of 30 values and swings from +9.9% to +24.7% on the
  same binaries; **3 of 10 clean invocations exceed 20%** (+20.1, +24.7,
  +21.1%). The median shows a steady ~+16%.
- Overall: **not a reproducible PASS under the criterion as written** (single
  30-pair p95 ≤ 20%). The pooled estimate is inside both limits, with ~3 points
  of margin on runtime. The criterion box in `goal.md` stays unchecked.
- Absolute times are about twice those of 2026-10-17 (baseline p95 77 ms vs
  38 ms): this host runs slower now, so compare ratios, not milliseconds.

## Conditions

Host with other user sessions present; 1-minute load 1.0-1.8 at the start of
the clean invocations, `--max-load 2.5` used for invocations 1-2 (bounded
15-minute wait), 8-11 right after the builds for invocations 12-14.
`host-load-invocation01.txt` and `…02.txt` hold the `uptime`/`free` snapshots;
the per-row `loadavg_1m_after` is in every JSON. Peak RSS is per scanner
process; Python, the fixture server and the launcher are excluded.

## Reproduction

```sh
# build both once (same Cargo.lock for the baseline checkout), then:
python3 scripts/benchmark_performance.py --baseline-ref 61b843d \
  --baseline-bin <baseline webrev> --current-bin <current webrev> \
  --runs 30 --pages 120 --profile site --seed <n> --output <dir>
```

`drive.py` runs several seeds in a row; `pool.py` pools the per-run JSON files.
Both have the scratchpad paths of this session hard-coded. `SHA256SUMS` covers
every file here.
