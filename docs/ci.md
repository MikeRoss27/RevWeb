# Continuous integration and release

All workflows live in `.github/workflows/`. Every third-party action is pinned
to a commit SHA (the version is in the trailing comment) and Dependabot keeps
them current. The Rust toolchain used for gating is pinned (`RUST_TOOLCHAIN`),
so a new stable release cannot break the build by adding lints; the `canary`
workflow tests floating stable, beta and the newest compatible dependencies.

## Run it locally

```sh
scripts/ci-local.sh          # same gates as CI, in the same order
scripts/ci-local.sh --quick  # skip the Chromium tests
```

`cargo-deny` runs if installed (`cargo install cargo-deny --locked`).

## Workflows

| Workflow | Trigger | What it does |
| --- | --- | --- |
| `ci.yml` | push to `main`, pull request, merge queue, release | `lint` (fmt, clippy `-D warnings`, rustdoc `-D warnings`, source size), `test` (Linux required; macOS and Windows informational), `msrv` (reads `rust-version`), `detection` (all pinned-corpus checksums and detector regression floors), `scripts` (Python), `browser` (Chromium, informational), `coverage` (cargo llvm-cov, informational, no threshold), and the `ci` gate |
| `security.yml` | PR touching Rust, manifests or workflows; weekly; push to `main` | `cargo-deny` (advisories, licenses, bans, sources). `dependency-review` and CodeQL (Rust, Python, Actions) run only when the repository is public |
| `canary.yml` | weekly | Stable and beta toolchains; newest compatible dependencies. Never a merge gate |
| `bundles.yml` | manual, or called by `release.yml` | Portable bundles for four targets, installer packaging, native install check |
| `release.yml` | tag `v*` | Tag must equal the workspace version, then CI, bundles, aggregated `SHA256SUMS`, build-provenance attestation (public repositories only) and a **draft** GitHub release |

## Branch protection (to configure by hand)

Require only the check named **`ci`**. It aggregates `lint`, `test`, `msrv`,
`detection` and `scripts`, so adding or renaming a job never changes the
protection rule. Suggested settings: require a pull request, require `ci` to be
up to date, dismiss stale approvals, disallow force pushes, and enable "delete
branch on merge". Branch protection is not available for private repositories
on a free plan; the checks still run and report.

`browser` is deliberately outside the gate until it has a track record on hosted
runners. Promote it by adding it to `needs` in the `ci` job.

## Cutting a release

1. Bump `version` in `[workspace.package]` and merge to `main`.
2. `git tag vX.Y.Z && git push origin vX.Y.Z`.
3. Review the draft release (notes, assets, `SHA256SUMS`) and publish it.

## What the detection job guarantees, and what it does not

It fails on any checksum mismatch in a pinned corpus and on any drop below the
recorded floors (for example 105/122 cross-file DOM XSS flows, zero false
positives on the maintainer-written negative set, SDC secrets TP=3 FP=0).
Those floors are regression guards on small, maintainer-reviewed and correlated
corpora. They are not accuracy claims; see `docs/benchmark-methodology.md`.

## Observed on hosted runners

The first runs of this pipeline (PR #5) found and fixed real problems that no
local run could show: archived benchmark reports ignored by `.gitignore` and
never committed, Windows line-ending conversion breaking pinned corpora, tests
binding `127.0.0.2` (absent on macOS), and fixture sockets inheriting
non-blocking mode on Windows. After those fixes one run was green on Linux,
macOS, Windows and the Chromium job. That is a single green run per platform,
not a track record: macOS, Windows and `browser` stay informational until they
have stayed green for a while.

Later pull requests (#8, #9, #10) also ran green on Linux, macOS, Windows and
the Chromium job, with the `ci` gate passing. Still a short history, so those
jobs remain outside the gate except Linux `test`.

## Measured coverage

First local measurement of `main` at `11beb2c` (`cargo llvm-cov --workspace`,
Chromium tests not run, 1 test failing under instrumentation, see below): line
coverage **86.57%** (12610 of 14567 lines).

| Crate | Lines covered | Lines | Coverage |
|---|---:|---:|---:|
| webrev-browser | 739 | 1342 | 55.07% |
| webrev-cli | 910 | 1189 | 76.53% |
| webrev-core | 1094 | 1177 | 92.95% |
| webrev-extract | 4281 | 4527 | 94.57% |
| webrev-pipeline | 3550 | 3920 | 90.56% |
| webrev-report | 1053 | 1117 | 94.27% |
| webrev-storage | 284 | 310 | 91.61% |
| webrev-tui | 699 | 985 | 70.96% |

Security-critical files are well covered by line: `sanitize.rs` 97.57%,
`egress_proxy.rs` 94.16%, `har.rs` 100%, `logging.rs` 94.74%, `transport.rs`
98.85%, and the `domsinks` modules 90.00% to 100%. Line coverage says the lines
ran, not that the assertions would catch a regression.

Least covered files of 50 lines or more: `commands/dynamic_scan.rs` 0%,
`stages/fetch/sourcemaps.rs` 0%, `webrev-browser/src/dynamic.rs` 4.09% and
`pool.rs` 11.00% (both need Chromium), `tui/runtime/input.rs` and
`controller.rs` about 32%. No test exercises `sourcemaps.rs` (0 of 87 lines).

`active::integration_tests::limits::cancellation_interrupts_an_inflight_response`
failed twice under instrumentation (it gives the scan 300 ms to react to a
cancel against an 800 ms response) and passes in the normal `test` job. The
coverage job uses `--ignore-run-fail` so that this does not discard the report.

## Known gaps

- Fuzzing and SBOM generation do not exist yet.
- Coverage is measured but not gated, and no threshold has been chosen. The
  `coverage` job runs `cargo llvm-cov --workspace --ignore-run-fail` and uploads
  `coverage.json` and `lcov.info`; the per-crate and per-file table goes to the
  job summary. It excludes the `#[ignore]` Chromium tests, so
  `webrev-browser/src/dynamic.rs` and `pool.rs` read as almost uncovered here
  even though the `browser` job exercises them.
- `release.yml` and `bundles.yml` have not been exercised (they need a tag or a
  manual dispatch); `release.yml` additionally skips attestations while the
  repository is private.
- CodeQL and dependency review stay off while the repository is private.
- `cargo-deny` allows duplicate crate versions with a warning only.
- The first `cargo-deny` run found four RUSTSEC advisories in `rustls 0.23.45`;
  the lockfile now pins 0.23.46.
