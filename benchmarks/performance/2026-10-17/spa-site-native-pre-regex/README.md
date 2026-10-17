# Paired SPA scan: native launcher before regex optimization

30 seeded shuffled pairs were executed against the same deterministic
120-route SPA-like fixture on loopback, with depth 2, concurrency 4,
maximum 120 pages and no delay. This does not imply every route was visited.
Builds were excluded; both scanner binaries were copied to a temporary
filesystem before execution. Project builds were stopped before measurements;
unrelated user processes were left running.

| Revision | Runs | Median | p95 | Maximum RSS | Findings/run | Failures |
|---|---:|---:|---:|---:|---:|---:|
| Baseline `61b843d` | 30 | 38.984 ms | 43.886 ms | 19,440 KiB | 574 | 0 |
| Frozen candidate | 30 | 48.278 ms | 53.289 ms | 22,268 KiB | 760 | 0 |
| Relative change | — | +23.84% | +21.43% | +14.55% | — | — |

Runtime threshold (<=20% p95 overhead): **FAIL**.
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
python3 benchmarks/performance/2026-10-17/spa-site-native-pre-regex/harness.py \
  --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --runs 30 --pages 120 --profile site --output /tmp/webrev-spa-site-native-pre-regex
```

Requires Rust/Cargo, Python, POSIX `wait4`, a C compiler and `/usr/bin/true`.
For build-cache reuse, add `--shared-target /absolute/path/to/cargo-target`.
The archived source snapshot must be restored in a separate checkout to
reproduce this exact candidate rather than a later working tree.

## Subsequent run

This candidate includes the resolver/normalization changes but precedes the
optional receiver-prefix regex optimization. Its threshold failure is retained,
not replaced or silently discarded. The later source change and native rerun
are recorded at [spa-site-optimized](../spa-site-optimized/README.md).

`diagnostic-posix-spawn-results.json` retains an earlier diagnostic run that
incorrectly attributed inherited Python RSS to the scanner. It is explicitly
invalid for RSS and does not validate the memory criterion. The subsequent
native launcher and code-change runs were required to correct the measurement
method and then evaluate a concrete code optimization.
