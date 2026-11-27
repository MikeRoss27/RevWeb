# Changelog

All notable changes to webrev are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Reliability and
benchmark history lives in [docs/changelog-reliability.md](docs/changelog-reliability.md).

## [0.1.0] - Unreleased

First public release. Static, dynamic and active analysis of web applications,
with a CLI (`webrev`) and a terminal UI (`webrev-tui`).

### Analysis

- Static extraction of endpoints, secrets, technologies, embedded config,
  dynamic imports, webpack/Vite chunk manifests, service workers and
  GraphQL introspection signals.
- Dynamic capture through headless Chromium: live HTTP and WebSocket traffic.
- Active, opt-in probes: security headers, cookies, CORS, sensitive files,
  open redirects, reflected XSS and SQL error signals, IDOR-lite, a
  timing-based command-injection probe and an MCP tool-exposure check.
- GraphQL introspection recovers the live schema, not just the signal.
- `bola`: cross-account object-access comparison, keeping the response body
  and the A/B comparison as evidence.
- `ws-replay`: controlled replay and bounded mutation of captured WebSocket
  frames, with an optional cross-account comparison.
- DOM XSS taint follows namespace imports, re-exports and local functions;
  cross-file `postMessage` handlers are linked.

### Correlation and reporting

- Endpoint evidence tiers (`observed` > `static` > `inferred`), kept through
  merges and shown in reports and the TUI.
- `compare`: cross-target fingerprint correlation with explicit `weak`,
  `moderate` and `strong` tiers.
- Report formats: JSON, text, DOT, GraphML, `urls-exact` and `requests`.
- Reports are exported raw by default; `--redact` masks credentials in every
  format.

### CLI and TUI

- Grouped `--help` with per-command examples, and shell completions.
- Unified color policy: `--color`, `NO_COLOR`, `CLICOLOR` and a 256-color
  fallback.
- Live scan progress on stderr (`--progress`, `--quiet`), a width-aware triage
  summary with `--limit` / `--all`.
- Errors carry hints. Exit codes: 1 runtime, 2 usage, 3 `--fail-on` threshold.
- TUI: quit confirmation, progress line, toasts, empty states, overwrite-safe
  async export, redraw only on change.

### Fixed

- Relative URLs in finding text are masked like the `url` field under
  `--redact`, including short values.
- A malformed `--header` or `--cookie` is now a usage error (exit 2) instead
  of being dropped silently, which used to run the scan without credentials.
- The `ws-replay` command now shows the startup banner.
- Capped response-body size in the crawl fetch stage, the dynamic-capture HAR
  collector and `Finding::provenances` growth.
- A probe-evidence excerpt is no longer cut in the middle of a secret.
- `cargo doc -D warnings` is clean again (public docs no longer link to a
  private item).
- The active cancellation test no longer depends on wall-clock timing under
  load.

### Security

- Dependencies updated past RUSTSEC-2026-0592 (`url`), RUSTSEC-2026-0385
  (`ctutils`) and RUSTSEC-2026-0486 (`rustix`); `rustls-webpki` and
  `webpki-root-certs` moved off the emSign distrust advisories.

### Known limitations

- Only the Windows release bundle has been validated locally; the Linux and
  macOS bundles are built by `bundles.yml`, which has not run yet.
- No correlation on TLS certificates or error pages; no route-to-endpoint or
  endpoint-to-technology links in the relation graph (see
  [docs/roadmap.md](docs/roadmap.md)).
