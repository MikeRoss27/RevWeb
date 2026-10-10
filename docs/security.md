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

## Secrets are never stored in plaintext

Detected secrets are reduced to a truncated **HMAC-SHA256 fingerprint**
(`fp:<16 hex>`) using a key that is:

- generated randomly **per run**, and
- **never persisted** to disk or the database.

So the database and reports record *that* a secret was present and let you count
or correlate duplicates **within a run**, without ever retaining the credential
itself. Fingerprints are not comparable across runs (different key each time).

Captured HAR headers and URLs are passed through the `Sanitizer`, which redacts
sensitive headers (`Authorization`, `Cookie`, `Set-Cookie`, `X-API-Key`,
`Proxy-Authorization`) and scrubs secret-looking substrings before anything is
stored or displayed.

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
shell history, and remember the SQLite database may contain authenticated
responses' findings — store and dispose of it accordingly.

## Headless browser notes

The dynamic analyzer normalizes the most trivial headless-automation tells
(`navigator.webdriver`, language list, a WebGL vendor string) so legitimate,
authorized analysis is not blocked outright by basic bot checks. It does **not**
impersonate any specific user or target identity, and it uses a disposable,
per-run profile directory that is deleted afterwards. Active interaction is
limited to scrolling and clicking buttons (never links), to avoid navigating
away or triggering destructive actions.

## Reporting scope

A report reconstructs minimal mission metadata (scope and seeds are not
persisted in the current schema); its substance is the findings, endpoints, and
summary counters. Review a report before sharing it — while secrets are
fingerprinted, discovered endpoints and parameters can still be sensitive.
