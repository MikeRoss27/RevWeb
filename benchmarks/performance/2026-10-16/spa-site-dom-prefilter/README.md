# DOM taint prefilter performance rerun

This archive reruns the 120-route, 11-JavaScript-bundle, local SPA-like crawl
after adding a conservative source/sink hint gate before the DOM taint AST walk.
The previous SPA run remains in `../spa-site/` and was not modified.

## Measurement

| Revision | Runs | Median | p95 | Maximum RSS | Findings/run | Failed runs |
|---|---:|---:|---:|---:|---:|---:|
| Baseline `61b843d` | 20 | 28.938 ms | 31.520 ms | 21,972 KiB | 574 | 0 |
| Worktree with prefilter | 20 | 181.133 ms | 184.399 ms | 22,688 KiB | 755 | 0 |
| Change | — | — | **+485.03%** | **+3.26%** | — | — |

All 40 scans exited successfully and had stable finding counts per revision.
Compared with the preceding worktree measurement (183.435 ms p95, 22,588 KiB,
755 findings/run), this rerun measured 184.399 ms p95, 22,688 KiB, and the same
755 findings/run. That difference is within run-to-run noise; the prefilter did
not materially improve end-to-end runtime. The relative regression percentage
fell from 511.72% to 485.03% because this rerun's baseline was slower (31.520 ms
versus 29.987 ms), not because the candidate became faster. The performance
gate remains failed.

## What the filter does

The prefilter only skips the DOM taint AST walk when broad textual searches find
no possible taint source or sink. It does not skip regex sink leads, WebAssembly
references, or postMessage checks. Hints include location/document/window/self,
message handlers and `.data`, common DOM sinks, and a navigation-assignment
pattern. Case-insensitive searches can retain unnecessary parses; they are
designed to avoid dropping possible flows.

All JavaScript files in the generated fixture have no source-to-sink flow. The
gate therefore skips the DOM taint parse for those assets. Since total runtime
did not improve, this pass is not the dominant source of the observed slowdown
on this fixture. That is an inference from the end-to-end rerun; the benchmark
does not expose per-extractor timings. The AST endpoint extractor and other
changed extraction paths remain candidates for separate profiling.

## Fixture payload audit

`fixture-manifest.json` records file sizes and SHA-256 hashes. Its aggregate
fixture digest is identical to the preceding SPA run: both binaries are served
from the same generated fixture tree on one loopback server, so they receive
identical response bytes.

The fixture has 144 files / 242,610 bytes, including 11 JS files / 122,878
bytes. Their 1,191 lines are unique as exact text. The workload is structurally
repetitive by construction: three shared bundles each have 180 similarly
shaped endpoint-bearing declarations; eight section bundles each have 80
similar `fetch` declarations. It has no duplicated exact JS lines, but this
repeated template shape is synthetic and can amplify AST extraction cost.

## Reproduce

```sh
python3 benchmarks/performance/2026-10-16/spa-site-dom-prefilter/harness.py \
  --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --runs 20 --pages 120 --profile site --output /tmp/webrev-perf-spa-rerun
```

`results.json` contains raw per-run observations, environment, fixture digest,
and source-input digest. `harness.py` is the exact script used for this run; it
locates the workspace root from its own archive path. Builds use separate
targets and are excluded from scan wall times. The comparison is against a
dirty worktree as a whole, so it cannot attribute the combined regression to
one change.
