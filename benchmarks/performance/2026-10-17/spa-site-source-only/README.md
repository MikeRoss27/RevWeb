# Source-only paired SPA performance comparison

This follow-up holds the candidate Cargo workspace manifests and lockfile fixed
for both release builds. The baseline starts from Rust sources at clean commit
`61b843daf845946060abae026b43349170ff177b`; the candidate uses the frozen
source snapshot from `../spa-site-final/candidate-source.tar.gz`. The harness
copies only `Cargo.toml` files and `Cargo.lock` from that snapshot into the
baseline checkout, then requires both builds to pass `cargo build --locked`.
All four pre/post lock hashes match.

## Results

| Source tree | Runs | Median | p95 | Maximum RSS | Findings/run | Failures |
|---|---:|---:|---:|---:|---:|---:|
| Baseline Rust source | 20 | 29.809 ms | 32.142 ms | 24,392 KiB | 574 | 0 |
| Frozen candidate Rust source | 20 | 35.847 ms | 37.859 ms | 24,392 KiB | 760 | 0 |
| Change | — | +20.26% median | **+17.79% p95** | **0.00%** | — | — |

The source-only p95 and RSS are within the proposed limits of +20% and +25%.
All 40 scans succeeded; the finding count was stable within each source tree.
Each of the 20 randomized adjacent pairs had a slower candidate run; the
median paired runtime change was +22.16%. The report's acceptance metric is
the ratio of the two nearest-rank p95 values, which is +17.79% here.

For context, the separate end-to-end comparison in
[`../spa-site-final/README.md`](../spa-site-final/README.md) measured +23.07%
p95 with clean baseline manifests. That comparison combines source and local
workspace manifest changes. The source-only result holds those manifests and
external dependency versions constant. Neither synthetic local result predicts
all production workloads; the original end-to-end run still exceeds its gate.

## Reproduce

From the repository root:

```sh
python3 benchmarks/performance/2026-10-17/spa-site-source-only/harness.py \
  --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --candidate-source-archive benchmarks/performance/2026-10-17/spa-site-final/candidate-source.tar.gz \
  --runs 20 --pages 120 --profile site \
  --output /tmp/webrev-perf-source-only
```

The fixture is the same deterministic 120-route, 24-asset SPA-like loopback
fixture as the paired run; its file hashes are in `fixture-manifest.json`.
Build time is excluded from runtime. Scans use scope `127.0.0.1`, depth 2,
concurrency 4, and zero delay. Runs are grouped into pairs and the binary order
inside each pair is pseudo-randomized with a fixed seed. Raw observations,
lockfile hashes, toolchain and environment are in `results.json`.

The source-only baseline is intentionally synthetic: it compiles old Rust
sources under the candidate's current manifest/dependency configuration. It
isolates the source-tree change from manifest and lock changes, but does not
attribute runtime to any individual detector or module.
