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

### Revealing plaintext (opt-in, dangerous)

Triaging or reporting a real leak sometimes needs the actual value. Pass
`--reveal-secrets` (or set `WEBREV_REVEAL_SECRETS=1`) on `static` / `tui` to make
the secret extractor **also** keep each detected secret in plaintext. When it is
set:

- the plaintext is shown in the TUI (the `[secret]` log line and the finding
  detail overlay) **and persisted** to the `findings.plaintext` column, so it
  flows into exported JSON/JSONL reports;
- the fingerprint is still the finding's `value`, so dedup and counting are
  unchanged.

This deliberately drops the fingerprint-only guarantee above, so the database
and any report now contain live credentials. It is **off by default**; enable it
only for authorized work, and treat the resulting `webrev.db` and reports as
secret material (see *Authentication material* below). `dynamic` scans capture
network traffic rather than running the secret extractor, so the flag has no
effect there.

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

## Active scanning (opt-in, abnormal traffic)

`webrev active` and `scan --active` are the only paths that intentionally send
abnormal traffic rather than passively observing: injected characters in query
parameters, a spoofed `Origin` header, and probes for a short list of
well-known sensitive paths (`.env`, `.git/HEAD`, …). This is opt-in for a
reason, and it is still bound by the same scope and `OpsecConfig` (jitter,
egress policy) as every other request webrev sends.

Guardrails baked into the checks themselves:

- **Never mutates state.** Endpoints known to be `POST`/`PUT`/`DELETE`/`PATCH`
  are skipped entirely; only GET-shaped requests are issued.
- **Never follows an injected redirect.** The probe client disables redirect
  following outright, so an open-redirect check cannot itself send a request
  to the attacker-controlled-looking URL it injects.
- **Hard per-category budgets** (≤15 targets each for fuzzing, redirects, and
  IDOR-lite) bound the extra request volume regardless of how many endpoints
  recon discovered.
- **IDOR-lite only runs on an authenticated mission** — it compares "with the
  mission's auth" against "with none at all," which is only meaningful once
  auth material is actually configured.

Findings land as `FindingKind::Vulnerability` or `FindingKind::Idor`, with
`Provenance::source == Source::Active` so they're always distinguishable from
passively observed findings in a report.

## Reporting scope

A report reconstructs minimal mission metadata (scope and seeds are not
persisted in the current schema); its substance is the findings, endpoints, and
summary counters. Review a report before sharing it — while secrets are
fingerprinted, discovered endpoints and parameters can still be sensitive.
