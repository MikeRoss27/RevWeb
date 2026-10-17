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
| `ci.yml` | push to `main`, pull request, merge queue, release | `lint` (fmt, clippy `-D warnings`, rustdoc `-D warnings`, source size), `test` (Linux required; macOS and Windows informational), `msrv` (reads `rust-version`), `detection` (all pinned-corpus checksums and detector regression floors), `scripts` (Python), `browser` (Chromium, informational), and the `ci` gate |
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

## Known gaps

- No code coverage, fuzzing or SBOM generation yet.
- `release.yml` and `bundles.yml` have not been exercised (they need a tag or a
  manual dispatch); `release.yml` additionally skips attestations while the
  repository is private.
- CodeQL and dependency review stay off while the repository is private.
- `cargo-deny` allows duplicate crate versions with a warning only.
- The first `cargo-deny` run found four RUSTSEC advisories in `rustls 0.23.45`;
  the lockfile now pins 0.23.46.
