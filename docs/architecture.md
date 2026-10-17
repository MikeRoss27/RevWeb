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
| `webrev-storage` | `Storage` port (async trait) + process-local `InMemoryStorage`. No disk I/O. | async-trait |
| `webrev-pipeline` | tokio stage pipeline wiring extraction + storage (crawler lives in the fetch stage); also the standalone `active` module (opt-in active-scan checks). | tokio, reqwest, futures |
| `webrev-browser` | All `chromiumoxide`: disposable profile, pool, JS hooks, HAR, dynamic run. | chromiumoxide, futures |
| `webrev-report` | JSON report document + summary counters. | serde, serde_json |
| `webrev-cli` | The `webrev` binary (clap subcommands). | clap, anyhow |
| `webrev-tui` | The `webrev-tui` binary + library (ratatui). | ratatui, crossterm |

Error handling: libraries return `webrev_core::Result` (thiserror); the two app
crates use `anyhow`. Clippy runs with `clippy::all` + `clippy::pedantic`; a few
noisy pedantic lints are allowed per-crate with a justifying comment.

The TUI separates state (`app/`), rendering (`ui/`) and terminal/scan execution
(`runtime/`). Extractors are grouped into endpoint discovery, metadata and secret
detection. The crawler and active probes keep orchestration separate from HTTP,
discovery, source-map recovery and individual checks. See
[development.md](development.md) for the module map and file-size rule.

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

## Session lifetime and reports

`InMemoryStorage` keeps sessions, findings and endpoints in process-local maps.
There is no database backend, migration or disk-backed session history. Detected
secret values are always attached to `Finding::plaintext`; fingerprints are used
for deduplication. CLI scans export their report before dropping the session.
The TUI exports on `r`. `webrev report` reads a full JSON report and converts or
filters it while preserving mission metadata.

## Dynamic analysis (webrev-browser)

`run_dynamic` acquires a browser from a small `BrowserPool`, applies the
disposable `BrowserProfile` (temp user-data dir, anti-headless init script,
proxy, auth headers), injects the `fetch`/XHR hooks before navigation, drives an
active dwell, and returns endpoints from the hook log, CDP network capture
(HAR), and WebSocket events, preserving original captured values.

The active dwell clicks one element at a time rather than firing all of them
at once: before each click it sets `window.__webrev_trigger` to a label
derived from the element (id/aria-label/text), so any call the hooks record
in the settle window right after is attributed to that click (`Finding`
`provenance.location` becomes `click: <label>`) — a before/after diff that
turns a flat endpoint list into "clicking Delete Account calls DELETE
/api/account".

`EventWebSocketFrameSent`/`EventWebSocketFrameReceived` are captured
alongside `EventWebSocketCreated` (bounded to `MAX_WS_FRAMES`, each payload
truncated to `MAX_WS_PAYLOAD_CHARS`) and emitted as `FindingKind::WebSocketFrame`,
tagged with direction + socket URL in `provenance.location`.
The WebSocket capture records these frames without replaying them. Frame replay
is not implemented; the operator can use the captured exchange in Burp or websocat.
This capture behavior is separate from the browser interactions and active probes.

## Active security testing

`active_targets` resolves findings to concrete, scoped URLs, keeping the query
strings and identifiers that normalized route exports remove. The active engine
checks headers, cookies, CORS, sensitive-file exposure and redirects, probes query
individual query positions for HTML reflection/SQL error signals, performs
differential arithmetic template checks, and compares authenticated and
unauthenticated responses for IDOR-lite signals. The CLI's `active` command,
`scan --active` and the TUI controller's `a` action share this engine. Results
return to the in-memory session and carry `Source::Active` for triage.

A shared active transport enforces scope, cancellation, decoded body size, jitter,
UA selection and one actual request budget across controls and checks. Evidence
uses explicit verdicts and response observations from `webrev-core::model::evidence`.
Every active run adds a typed `ScanCoverage` record to the in-memory findings;
report formats and TUI details retain it. Confirmed expression evaluation never
promotes itself to OS RCE. See [research review](active-research.md).

## Finding status, evidence and deduplication

Every finding now carries an evidentiary `status` (`observed`, `suspicious`,
`confirmed`, `inconclusive`) independent of confidence and qualitative
severity. `evidence_score` ranks verification strength; it is not a probability
and does not derive from CVSS. CVSS is not currently assessed. Active response
evidence stores request method/URL, response status, content type, size and a
bounded excerpt. Authorization header values are not stored in evidence.

Static extractors add stable detector identifiers. Storage merges contributing
detectors, provenances, confidence and evidence for repeated findings before
the store stage suppresses duplicate events. Endpoint keys retain the HTTP
method. Older JSON reports remain readable through serde defaults; old
findings deserialize as `observed`, since their original evidence state cannot
be reconstructed.

The static extractor registry labels recognized call sites as endpoints;
other endpoint-shaped JavaScript literals are low-confidence configuration
candidates. Parameter findings now come from page URLs, network-call literals,
HTML forms/links/actions and recognizable inline JSON bodies. Free-standing
JavaScript object keys are no longer request parameters.
