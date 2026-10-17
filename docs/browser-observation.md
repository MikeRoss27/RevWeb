# Browser observation controls

Browser-driven investigation keeps its historical default: Webrev scrolls and
clicks buttons / role-button elements and captures scoped application requests.
Those actions can change state, including with authenticated sessions.

For `dynamic` and `scan --dynamic`, opt into restricted observation:

```sh
webrev dynamic --seed http://127.0.0.1:8080/ --observation-only
webrev scan --seed http://127.0.0.1:8080/ --dynamic --observation-only
```

This option disables Webrev-driven scrolling and clicking and refuses HTTP
methods other than GET, HEAD and OPTIONS at browser request interception. It
does not establish non-destructivity: the page's own scripts still execute,
GET routes may change state, and WebSocket messages and other browser mechanisms
can change application state. The option controls the browser pass only; it does
not change separately selected active probes. The TUI rejects this option before
launch because its browser interaction policy is not configurable yet.

The Rust equivalent is
`BrowserProfile::with_interaction_policy(InteractionPolicy::ObserveOnly)`.
`run_dynamic` retains its existing signature. `run_dynamic_with_report` also
returns refused request intents and their reasons (`OutOfScope` or
`MethodRestricted`). Refused intents are excluded from browser endpoint findings,
even when page hooks or CDP observed them before interception refused them.

Both supported CLI paths persist one `ScanCoverage` finding per successful seed
capture. Its `value` contains JSON with the selected policy, exact refusal count,
up to 1024 refused intents (at most 1 MiB of original URL/method bytes), an omission indicator and limitations. This
coverage evidence is included in JSON and text reports. `complete` is always
false: a bounded browser dwell cannot establish complete application coverage.
Whole evidence records beyond either bound are omitted and counted; retained values are not truncated. No active-probe wire counter is inferred from browser request events. Original
URLs, methods, credential values and existing findings remain available for
triage; existing capture limits still apply.

Local validation uses a loopback page with a page-load POST, a DELETE button,
an allowed GET and a separate out-of-scope loopback resource. The tests require
locally installed Chromium and are ignored in normal environments:

```sh
cargo test -p webrev-browser --lib -- --ignored
cargo test -p webrev-cli --test ephemeral -- --include-ignored
```

The browser fixture verifies that default exploration sends the page's own
scripted POST but no longer clicks destructive-looking controls (see below),
while restricted observation sends neither and retains refusal evidence.
CLI tests cover both command paths, JSON/text coverage and original credential
values. These tests do not qualify final destinations behind proxies or prove
non-destructivity on arbitrary applications.

## Destructive controls in default exploration

`Explore` clicks at most 10 `button`/`[role=button]` elements per pass. Before each
click the driver reads the control's id, class, name, value, title, aria-label,
`onclick`, enclosing link and form action, and refuses it when a whole token matches
a state-changing word (delete, remove, logout/sign out, pay, checkout, purchase,
cancel, reset, unsubscribe, ...) or when it would submit a non-GET form. A control
that cannot be inspected is not clicked. Refusals are kept in the coverage evidence
(`refused_interactions`, `refused_interaction_count`; coverage stays
`complete: false`). The word list is a heuristic: a mislabelled control, a script
that mutates on load, or a handler reached by scrolling is not covered.

## Confirmed WebSocket egress gap

The additional diagnostic `diagnostic_websocket_scope_egress` was executed on
Chromium 154.0.8037.97 (Arch Linux) against loopback listeners only. The scoped
page at `127.0.0.1` attempted WebSocket upgrades both to its own host and to the
out-of-scope address `127.0.0.2`. The server recorded both HTTP Upgrade attempts:

```text
out_of_scope_handshake_received=true
interception_refusals=0
exported_out_of_scope_endpoints=0
```

The existing Fetch interception does **not** enforce the WebSocket scope boundary
on this browser. Filtering the resulting findings excludes the out-of-scope
endpoint from reports but does not prevent its handshake from reaching the
network. The fixture replies HTTP 200, so this diagnostic demonstrates an
unauthorized handshake attempt, not an established socket or exchanged frames.
The page-executed beacon and in-scope upgrade serve as controls. The diagnostic
is observational: a passing test process does not mean the scope boundary
passed. Its current result is **FAIL for WebSocket egress enforcement**.

The reproducible log is
`benchmarks/browser-scope/2026-10-17/websocket-diagnostic.log`. Run it with:

```sh
cargo test -p webrev-browser diagnostic_websocket_scope_egress -- --ignored --nocapture
```

A bounded correction should enforce the boundary in the browser/network layer
before every WebSocket handshake, including frames, workers and redirects. A
policy-enforcing egress proxy with browser proxy bypass disabled is one candidate;
newer CDP ordered `Network.setBlockedURLs` patterns are another candidate that
requires a real WebSocket canary before adoption. A JavaScript constructor wrapper
alone is insufficient because page code can obtain unwrapped constructors from
other realms or workers. No production fix is claimed by this diagnostic.

A second local spike, `diagnostic_websocket_cdp_block_patterns`, installed
`Network.setBlockedURLs` **before navigation** with blocking patterns
`ws://*:*/*` and `wss://*:*/*`. An HTTP rule blocked `/probe-executed` while
`/probe-control` reached the server, proving that the network guard was active.
Both WebSocket Upgrade attempts still reached the loopback listeners. The
candidate guard therefore **failed**, despite the CDP command succeeding.
The failing assertion and wire log are retained in
`benchmarks/browser-scope/2026-10-17/websocket-cdp-candidate-failed.log`.
The currently tested CDP URL block patterns are not a WebSocket scope fix.
