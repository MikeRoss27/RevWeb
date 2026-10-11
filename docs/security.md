# Security & responsible use

webrev is built for **authorized** security work: penetration tests with a
signed scope, bug-bounty programs within their rules, your own applications, and
lab/CTF targets. Using it against systems you do not have permission to test may
be illegal. You are responsible for staying within your authorization.

## Scope is fail-closed

Every request is checked against the mission `Scope` (host-suffix include/exclude
lists). An empty include list denies everything, and the crawler never follows a
link or fetches a script/source-map outside the allowed hosts. When no `--scope`
is given, it is derived from the seed hosts — so a single-seed scan stays on that
host and its subdomains unless you widen it explicitly.

Set `--exclude` to carve out sensitive subdomains (e.g. admin panels) that are
out of scope even though they share a parent domain.

## In-memory sessions and visible secrets

All sessions stay in memory until the process exits. There is no database or
automatic disk-backed history. CLI scans write their report directly; the TUI
writes a report when `r` is pressed. `scan --no-report` writes no report.

Detected secrets are always retained in `Finding::plaintext` and displayed in
the TUI and JSON/JSONL/CSV reports. No reveal option is required. A truncated
HMAC-SHA256 fingerprint (`fp:<16 hex>`) remains the deduplication key, generated
with a random per-run key that is never persisted.

Dynamic capture preserves original request URLs, headers and WebSocket payloads
instead of masking credential-looking substrings. Existing capture-size budgets
still apply. Reports contain the values needed to triage the findings.

## Operational controls

`OpsecConfig` bounds and shapes traffic so scans stay polite and within limits:

- **Request jitter** — delays are sampled from a normal distribution inside the
  `[delay-min-ms, delay-max-ms]` window, not a fixed rate.
- **Concurrency & budgets** — `--max-concurrency`, `--max-pages`, `--max-depth`
  cap load and breadth.
- **Egress policy** — route all traffic through an intercepting proxy with
  `--proxy`; `EgressPolicy::allow_direct = false` (fail-closed egress) refuses
  direct connections when no proxy is set.

## Authentication material

Cookies, headers, and bearer tokens you pass (`--cookie` / `--header` /
`--bearer`, or `WEBREV_BEARER`) are applied to both the HTTP client and the
headless browser. Treat these as sensitive: prefer environment variables over
shell history. Exported reports can contain authenticated findings and detected
credentials.

## Headless browser notes

The dynamic analyzer normalizes the most trivial headless-automation tells
(`navigator.webdriver`, language list, a WebGL vendor string) so legitimate,
authorized analysis is not blocked outright by basic bot checks. It does **not**
impersonate any specific user or target identity, and it uses a disposable,
per-run profile directory that is deleted afterwards. Dynamic investigation
scrolls and clicks buttons / role-button elements, records the requests they
trigger and attributes calls to those interactions. It does not click links.
Those interactions execute the target application's code and can trigger
authenticated or state-changing requests: this is browser-driven investigation.

## Active scanning (opt-in, abnormal traffic)

`webrev active`, `scan --active` and the TUI's `a` key launch active security
probes: injected characters in query parameters, a spoofed `Origin` header,
requests for sensitive paths (`.env`, `.git/HEAD`, …), and authenticated versus
unauthenticated access comparisons. Active probes are selected explicitly and
use the mission scope, authentication and `OpsecConfig` (jitter, egress policy).
Static analysis, browser interaction and active probing are distinct modes of
the same web security toolkit.

Probe behavior:

- **GET-shaped probe requests.** Endpoints known to be `POST`/`PUT`/`DELETE`/`PATCH`
  are skipped by the probe client. Browser interactions execute application
  behavior independently of this restriction.
- **Never follows an injected redirect.** The probe client disables redirect
  following outright, so an open-redirect check cannot itself send a request
  to the attacker-controlled-looking URL it injects.
- **Shared request budget** counts every active request, including controls and
  unsuccessful attempts (default 200; `--max-active-requests`). Per-category target
  attempts are capped at 15; query positions at four; decoded bodies at 512 KiB.
  Oversized/refused responses, errors, cancellations and reached limits are
  recorded in `ScanCoverage`, rather than interpreted as a clean scan.
- **Expression probes** perform two arithmetic evaluations and a payload-free
  control. They do not execute OS commands, write files or trigger callbacks.
  The resulting verdict establishes evaluation only.
- **IDOR-lite only runs on an authenticated mission** — it compares "with the
  mission's auth headers" against "with none of those headers," which is only meaningful once
  auth material is actually configured.

Findings land as `FindingKind::Vulnerability` or `FindingKind::Idor`, with
`Provenance::source == Source::Active` so they're always distinguishable from
static discoveries and browser-captured findings in a report. Each active run
also records `ScanCoverage`; structured evidence distinguishes observations,
signals and confirmed expression evaluation. See [proof boundaries](active-research.md).

## Reporting scope

A report includes the original mission metadata, scope, seeds, findings,
endpoints, summary counters and detected plaintext secrets. `webrev report`
preserves this metadata when converting or filtering an existing JSON report.
