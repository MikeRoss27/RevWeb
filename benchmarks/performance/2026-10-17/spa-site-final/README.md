# Paired SPA scan: frozen candidate snapshot

This run was executed after extractor and storage changes were frozen. The
candidate source snapshot, `Cargo.lock`, deterministic fixture generator, raw
observations and source archive are included here. The candidate is the dirty
worktree captured in `candidate-source.tar.gz`; its Git base commit is recorded
in `source-snapshot.json`. The detached baseline starts from a copy of the candidate `Cargo.lock`. Cargo
may rewrite the lockfile when the baseline workspace manifests differ; the
initial and post-build hashes are recorded in `results.json`.

## Results

| Revision | Runs | Median | p95 | Maximum RSS | Findings/run | Failures |
|---|---:|---:|---:|---:|---:|---:|
| Baseline `61b843d` | 20 | 29.106 ms | 32.352 ms | 22,976 KiB | 574 | 0 |
| Frozen candidate | 20 | 35.290 ms | 39.817 ms | 22,976 KiB | 760 | 0 |
| Relative change | — | +21.25% median | +23.07% p95 | +0.00% | — | — |

All 40 local scans succeeded with a valid report. RSS meets the configured
limit (≤25%); p95 increase of 23.07% exceeds its ≤20% limit. Finding counts
differ because the candidate includes detector changes, so this is an
end-to-end scanner comparison, not an isolated storage-index microbenchmark.
The baseline started with a copy of the candidate lockfile, but Cargo rewrote
it during its build. Its post-build hash exactly matches the clean `HEAD`
lockfile (`2772e2b0…`); the candidate lock differs from `HEAD` only in local
workspace dependency edges. A direct diff shows no registry package version
or checksum changes, so external dependency version drift is not a likely
cause of this delta. The source and workspace dependency edges still differ,
so this remains an end-to-end comparison rather than a source-only attribution.

A [source-only follow-up](../spa-site-source-only/README.md) now holds the
candidate manifests and lockfile fixed for both builds, compiles both with
`--locked`, and replaces only the baseline Rust sources. It measures +17.79%
p95 and +0.00% RSS, within the proposed limits. This complements but does not
erase the +23.07% end-to-end p95 result.

The external multi-file corpus runner and its CI step were added after the
scanner source snapshot. They are integration-test and workflow changes; they
are not compiled into the `webrev` release binary measured here. The candidate
source archive therefore records the scanner source used for the run.

## Reproduction

```sh
python3 harness.py --baseline-ref 61b843daf845946060abae026b43349170ff177b \
  --runs 20 --pages 120 --profile site --output /tmp/webrev-perf-reproduce
```

The harness compiles both revisions in release mode. The baseline starts from a
copy of the candidate `Cargo.lock`; Cargo rewrites it to match the baseline
workspace manifests. Pre-build and post-build lockfile hashes are in
`results.json`. The post-build baseline lock matches clean `HEAD`; external
package versions and checksums are unchanged from the candidate lock. The
harness then serves a deterministic 120-route SPA-like
fixture over loopback. It runs 20 seeded shuffled baseline/current pairs, with
randomized order within each pair, using scope `127.0.0.1`, depth 2, concurrency
4, and no delay. Build time is excluded; scan time includes process
startup. The fixture is synthetic and does not establish performance on every
production site. Raw per-run values are in `results.json`.
