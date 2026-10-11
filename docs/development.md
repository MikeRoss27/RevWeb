# Development

Use Rust 1.89 or newer. The native TLS provider needs a C compiler and CMake.
Windows x86/x64 assembly builds use NASM or supported prebuilt objects; the
browser pass needs a local Chromium/Chrome installation.

## Source organization

`src/lib.rs` defines each crate's public surface. `src/main.rs` parses arguments
and launches the application. Put implementation details in modules grouped by
responsibility:

```text
webrev-tui/src/
  app/                 state, tabs, filtering/navigation, event updates, tests
  ui/                  frame composition, chrome, panels, overlays, theme, tests
  runtime/             terminal/event loop, scan controller, input dispatch
  events.rs            key actions and UI events
  brand.rs             shared visual identity

webrev-extract/src/extractors/
  endpoints/           HTML/JS, GraphQL, SPA routes, source-map references
  metadata/            configuration, manifests, parameters
    tech/              detection engine, tests, signatures grouped by stack layer
  secrets/             scanner, credential patterns, heuristics, tests

webrev-pipeline/src/
  active/              orchestration, client, URL helpers, origin/injection/access checks
    transport.rs       scope, actual request budget, bounded bodies, cancellation
    expression.rs      arithmetic-only template evaluation and controls
    integration_tests/ positive/negative wire fixtures and operational limits
  stages/fetch/        crawler, HTTP/retries, discovery, source-map recovery, tests
```

Keep a file focused on one responsibility. Aim for 200–400 lines; the source-size
check fails above 600 lines, before files grow toward 1,000. A necessary exception
must name the file and explain its concrete reason in `scripts/check_source_size.py`.
Keep tests next to the module they exercise in `tests.rs` when they would obscure
the implementation. Keep existing public re-exports stable during internal moves.

## Dependencies

Direct dependency versions are centralized in the workspace `Cargo.toml` and
resolved in `Cargo.lock`. The October 2026 update includes reqwest 0.13.5,
rand 0.10.3/rand_distr 0.6.0, HMAC 0.13.0/SHA-2 0.11.0 and SWC 82.0.1.
Use the official crate documentation when upgrading across incompatible API
versions, then run the checks below.

Two transitive versions remain required by upstream crates:

- `crypto-common 0.1.7` requires `generic-array =0.14.7` through Chromium's
  WebSocket stack. Cargo rejects a standalone upgrade to 0.14.9.
- `pest 2.9.3` requires `psm =0.1.24` through ratatui's optional termwiz backend.
  Cargo rejects a standalone upgrade to 0.1.32.

## Checks

```bash
python scripts/check_source_size.py
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --all-targets --locked
cargo test --workspace --locked

# Real local template engine (Jinja2 available in the test environment)
python scripts/check_template_engine.py --binary target/debug/webrev.exe

# Real Chromium, loopback fixture only
cargo test -p webrev-cli --test ephemeral --locked \
  dynamic_scans_preserve_captured_tokens_without_database -- --ignored
```

The default tests require no external target. Sessions remain in memory and
detected secrets are visible by default; exports are written directly.

## Distribution

`install.ps1` and `install.sh` build both binaries once from a source checkout,
or install local `bin/` bundles without Cargo. `package.py` creates platform
archives and checksums. `check_bundle.py` installs the native archive in a
workspace-owned temporary directory with spaces, checks both executables and
hashes, then verifies that a corrupt source is rejected before either installed
binary changes. The bundle workflow runs that check on each native runner.

```sh
cargo build --release --locked -p webrev-cli -p webrev-tui
python scripts/package.py --target x86_64-pc-windows-msvc
python scripts/check_bundle.py --target x86_64-pc-windows-msvc
```

Use the appropriate native Rust target triple on Linux/macOS. The workflow
creates artifacts, with no release publication or repository writes.

Brand copy and outlined SVG generation are described in [branding.md](branding.md).
