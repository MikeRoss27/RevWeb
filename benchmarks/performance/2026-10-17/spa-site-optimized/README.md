# Paired SPA scan: optimized candidate

30 seeded shuffled pairs were executed against the same deterministic
120-route SPA-like fixture on loopback, with depth 2, concurrency 4,
maximum 120 pages and no delay. This does not imply every route was visited.
Builds were excluded; both scanner binaries were copied to a temporary
filesystem before execution. Project builds were stopped before measurements;
unrelated user processes were left running.

| Revision | Runs | Median | p95 | Maximum RSS | Findings/run | Failures |
|---|---:|---:|---:|---:|---:|---:|
| Baseline `61b843d` | 30 | 34.240 ms | 38.081 ms | 20,748 KiB | 574 | 0 |
| Frozen candidate | 30 | 39.677 ms | 45.178 ms | 22,136 KiB | 760 | 0 |
| Relative change | — | +15.88% | +18.64% | +6.69% | — | — |

Runtime threshold (<=20% p95 overhead): **PASS**.
RSS threshold (<=25%): **PASS**.
All 60 reports were valid with stable finding counts per revision. The candidate
retains 186 additional findings compared with the historical baseline. This is
an end-to-end revision comparison; it does not isolate any single optimization.

## Measurement and provenance

`measure.c` creates a small native parent that forks and execs the scanner,
then measures monotonic elapsed time and the scanner child's `wait4` peak RSS.
The interval includes scanner process startup and excludes launcher startup,
compilation, Python and the fixture server. A `/usr/bin/true` probe verifies
that the native parent contributes less than 8 MiB to the measured child.

The previous direct Python fork/spawn measurement inherited the Python heap
high-water mark: a controlled 64 MiB parent allocation made `true` appear to
use about 76 MiB. Native measurement instead reports about 1.5 MiB. Historical
Python-launcher RSS values therefore cannot establish scanner memory overhead.
The new native measurements supersede that RSS methodology.

`candidate-source.tar.gz` and `source-snapshot.json` contain the exact Rust
sources, crate manifests and lockfile used to build the candidate. The harness
rejects source changes during build/measurement. `results.json` records
per-run observations, binary hashes, launcher hash and lockfile hashes before
and after builds. `fixture-manifest.json` records every fixture file hash.
Baseline Cargo rewrites local workspace dependency edges; comparison of the
426 external package version/source/checksum tuples found no difference.

The fixture is synthetic and small. A passing observation on this host is
not a guarantee for every production workload. The host was not isolated;
changes between separately timed runs must not be attributed entirely to code.

## Reproduction

From the repository containing the candidate sources:

```sh
python3 benchmarks/performance/2026-10-17/spa-site-optimized/harness.py \
  --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --runs 30 --pages 120 --profile site --output /tmp/webrev-spa-site-optimized
```

Requires Rust/Cargo, Python, POSIX `wait4`, a C compiler and `/usr/bin/true`.
For build-cache reuse, add `--shared-target /absolute/path/to/cargo-target`.
The archived source snapshot must be restored in a separate checkout to
reproduce this exact candidate rather than a later working tree.

## Changes and regression checks

The resolver parses mission seeds once and reuses a bounded one-entry source
base cache, while preserving document-relative JavaScript and source-relative
HTML rules. URL normalization borrows its input path and recognizes UUIDs
without allocating a vector for every path segment.

Two HttpClient regexes no longer compile an optional Unicode receiver prefix.
The searches are unanchored, and only the method/URL suffix is captured, so
this preserves captured values, including Unicode and chained receivers.
Regression tests compare legacy and optimized captures across receiver names,
method names, quote styles and `myhttp`/`http2` boundaries; the JS test also
checks commented calls remain ignored. Workspace tests and strict Clippy were
rerun by the parent agent after the final source changes.

The standalone `regex-compile.rs` measures 100 alternating construction pairs
per pattern using the release regex library, excluding destruction:

| Pattern | Legacy mean | Optimized mean |
|---|---:|---:|
| `http_client` | 326.990 us | 66.356 us |
| `network_url` | 441.729 us | 111.968 us |

The combined construction saving is about 0.590 ms per scanner registry.
This microbenchmark measures regex construction, not end-to-end scan speed.
The preceding native run before this code change is retained at
[spa-site-native-pre-regex](../spa-site-native-pre-regex/README.md); its p95
overhead was +21.43% (FAIL). Different ambient load prevents clean attribution
of the full difference between those separate end-to-end runs.
`rss-launcher-probe.json` records the explicit inherited-RSS diagnostic.
