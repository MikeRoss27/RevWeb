# webrev

```text
╭─╮
│◠│  webrev
╰─╯  web reconnaissance toolkit · authorized targets only
```

A web reconnaissance and analysis toolkit for **authorized** security testing — a
CLI + TUI that performs static and dynamic analysis of web applications: it
crawls in scope, extracts endpoints, parameters, routes, GraphQL operations,
source maps and secrets, fingerprints the tech/SaaS/DB stack, and (optionally)
drives a headless Chromium to capture live traffic.

> ⚠️ **Use only against targets you are explicitly authorized to test.** The scope
> is fail-closed and secrets are stored as non-reversible fingerprints, but you
> are responsible for staying within the bounds of your engagement. See
> [docs/security.md](docs/security.md).

## Highlights

- **Bounded concurrent crawler** — breadth-first, scope-restricted, with
  `--max-pages` / `--max-depth` / `--max-concurrency` budgets and request jitter.
- **Rich static extraction** — HTML (scripts/links/forms), JavaScript via regex
  **and** `swc` AST (`fetch`, `axios`, `XHR.open`, `WebSocket`), SPA routes,
  GraphQL operations, request parameters/JSON keys, and URL normalization
  (`/users/123` → `/users/{id}`).
- **Source-map recovery** — fetches and parses `.map` files to re-mine the
  original, un-minified source for hidden endpoints and secrets.
- **Secret detection** — known credential shapes plus Shannon-entropy heuristics;
  every secret is stored as a truncated HMAC fingerprint, never in plaintext.
- **Technology fingerprinting** — frameworks (Next.js, React, Vue, Angular, …),
  BaaS/DB (Supabase, Firebase, Hasura, Cognito, …), and backend servers
  (nginx, Express, Laravel, Rails, …) from body, URL, and response headers.
- **Dynamic analysis** — headless Chromium with injected `fetch`/XHR hooks, HAR
  capture, active SPA interaction (scroll + click) and WebSocket capture.
- **Authenticated scans** — cookies / headers / bearer token applied to both the
  HTTP client and the browser.
- **Live TUI** — four tabs (Endpoints / Findings / Logs / Status) streaming
  pipeline events, with live `/` filtering, internal/external endpoint tagging,
  and a JSON report export.
- **Pipeline-native** — seeds can be read from stdin
  (`subfinder -d x.com | httpx | webrev static`), and `report` emits `json`,
  `jsonl`, `urls` (pipe into ffuf/httpx/nuclei), or `csv`, with scope and
  confidence filters; data goes to stdout, chatter to stderr, and a closed pipe
  exits cleanly.

## Install / build

Requires a recent stable Rust toolchain (edition 2021, Rust ≥ 1.82). Dynamic
analysis additionally needs a local Chrome/Chromium.

```bash
cargo build --release          # binaries: target/release/webrev and webrev-tui
cargo test --workspace         # 50+ tests (browser tests are #[ignore])
cargo clippy --workspace --all-targets -- -D warnings
```

## Quick start

```bash
# Static analysis + crawl, then export a JSON report of the latest session
webrev static --seed https://app.example.com/ --max-depth 2 --max-pages 200
webrev report --output report.json

# Authenticated, behind a login, through an intercepting proxy
webrev static --seed https://app.example.com/ \
  --cookie "session=…" --header "X-Env: staging" --proxy http://127.0.0.1:8080

# Dynamic analysis (headless Chromium)
webrev dynamic --seed https://app.example.com/ --duration-secs 8

# Interactive TUI (auto-starts a static scan; s/d/r/Tab/q)
webrev tui --seed https://app.example.com/
```

Full command/flag reference and the TUI key map are in
[docs/usage.md](docs/usage.md).

## Documentation

| Doc | What it covers |
| --- | --- |
| [docs/usage.md](docs/usage.md) | Commands, flags, env vars, TUI keys, worked examples |
| [docs/architecture.md](docs/architecture.md) | Workspace layout, crate responsibilities, pipeline data flow |
| [docs/extractors.md](docs/extractors.md) | The extractor catalog, finding kinds, and how to add your own |
| [docs/security.md](docs/security.md) | Authorization, scope, secret handling, responsible use |

## Architecture at a glance

A Cargo workspace of focused crates (pure core → extraction → storage →
orchestration → I/O adapters → apps):

```text
webrev-core      domain model, errors, sanitize/opsec/auth, URL normalization
webrev-extract   pure, synchronous extractors + priority registry (zero I/O)
webrev-storage   Storage port + SQLite and in-memory backends
webrev-pipeline  tokio stage pipeline (fetch → static-extract → store)
webrev-browser   all chromiumoxide: profile, pool, hooks, HAR, dynamic run
webrev-report    JSON report + summary counters
webrev-cli       the `webrev` binary (clap subcommands)
webrev-tui       the `webrev-tui` binary + library (ratatui)
```

See [docs/architecture.md](docs/architecture.md) for the data flow and the
`PipelineItem` model.

## License

MIT. See individual crate manifests.
