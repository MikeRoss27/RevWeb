# Architecture

webrev is a Cargo workspace layered from a pure domain core outward to the I/O
adapters and the two binaries. Dependencies only point "inward": apps depend on
adapters, adapters depend on the core, and the core depends on nothing in the
workspace.

## Crates

| Crate | Role | Notable deps |
| --- | --- | --- |
| `webrev-core` | Pure domain: `Finding`, `Endpoint`, `Mission`/`Scope`/`SessionId`, `WebrevError`, `sanitize`, `opsec`, `auth`, URL `normalize`. No I/O, no async. | thiserror, serde |
| `webrev-extract` | Synchronous extractors + priority `ExtractorRegistry`. **Zero network/filesystem I/O.** | regex, lol_html, swc_core |
| `webrev-storage` | `Storage` port (async trait) + `SqliteStorage` and `InMemoryStorage` backends. | sqlx (runtime API), async-trait |
| `webrev-pipeline` | tokio stage pipeline wiring extraction + storage; the crawler lives in the fetch stage. | tokio, reqwest, futures |
| `webrev-browser` | All `chromiumoxide`: disposable profile, pool, JS hooks, HAR, dynamic run. | chromiumoxide, futures |
| `webrev-report` | JSON report document + summary counters. | serde, serde_json |
| `webrev-cli` | The `webrev` binary (clap subcommands). | clap, anyhow |
| `webrev-tui` | The `webrev-tui` binary + library (ratatui). | ratatui, crossterm |

Error handling: libraries return `webrev_core::Result` (thiserror); the two app
crates use `anyhow`. Clippy runs with `clippy::all` + `clippy::pedantic`; a few
noisy pedantic lints are allowed per-crate with a justifying comment.

## The pipeline

The pipeline is a linear chain of `Stage`s, each running in its own tokio task,
connected by bounded `mpsc` channels. Progress is published on a `broadcast`
channel the TUI subscribes to, and a `CancellationToken` stops everything
cleanly.

```text
seed ──▶ [fetch] ──▶ [static-extract] ──▶ [store] ──▶ (drained tail → summary)
             │                │                 │
         network          registry          dedup + Storage
         crawl +          (pure)             + events
         sourcemaps
```

### `PipelineItem`

The channel carries a polymorphic item rather than a bare `Finding`, because a
`Finding` cannot transport a fetched body to the (network-free) extraction
stage:

```rust
enum PipelineItem {
    Content { url, kind, body, headers }, // raw fetched content to extract
    Finding(Finding),                     // a produced finding, toward storage
}
```

- **fetch** (source stage) reads seeds from the mission, crawls breadth-first in
  waves of `max_concurrency` concurrent requests, emits each body as `Content`
  (with its response headers), discovers scripts + same-scope links (up to
  `max_depth`), and recovers source maps — all bounded by `max_pages`.
- **static-extract** turns each `Content` into `Finding`s via the registry and
  forwards any `Finding` it receives unchanged. No I/O.
- **store** deduplicates (`BTreeSet` on `kind + url`), persists via the
  `Storage` port, normalizes endpoints into routes for the endpoints table, and
  emits `Finding` / `SecretDetected` events.

### Events

`PipelineEvent` variants: `StageStarted`, `StageCompleted`, `Progress`,
`Finding`, `SecretDetected`, `Error`. The engine also tallies a
`PipelineSummary` (stages, items out, findings emitted, errors).

## Storage schema

SQLite tables (`migrations/0001_init.sql`, applied idempotently on connect):
`sessions`, `findings`, `endpoints`, `secrets`. The runtime `sqlx::query` API is
used (no compile-time schema, so no `DATABASE_URL` is needed to build). Secrets
are stored as fingerprints by default; the opt-in `--reveal-secrets` flag also
persists the plaintext in `findings.plaintext` (see [security.md](security.md)).

## Dynamic analysis (webrev-browser)

`run_dynamic` acquires a browser from a small `BrowserPool`, applies the
disposable `BrowserProfile` (temp user-data dir, anti-headless init script,
proxy, auth headers), injects the `fetch`/XHR hooks before navigation, drives an
active dwell (scroll + click), and returns endpoints from the hook log, CDP
network capture (HAR), and WebSocket events — all sanitized.
