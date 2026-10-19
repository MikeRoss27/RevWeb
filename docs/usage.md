# Usage

`webrev` has six subcommands: `scan`, `static`, `dynamic`, `active`, `tui`, and
`report`. `scan` is the one-shot convenience wrapper; the others are the
individual steps.

```text
webrev <COMMAND> [OPTIONS]
```

All scanning subcommands (`scan`, `static`, `dynamic`, `active`, `tui`) share
the same options below. `scan` adds a few of its own (see its section), and
`report` has its own, smaller set.

## Analysis and testing modes

- **Static**: fetch scoped resources, inspect HTML/JavaScript/source maps and
  recover APIs, parameters, routes, configuration, secrets and technologies.
- **Dynamic**: drive Chromium, interact with the application, attribute calls to
  clicks, and capture HTTP/HAR/WebSocket traffic. Application interactions can
  trigger authenticated requests and application state changes.
- **Active**: test the discovered surface with scoped security probes for access
  control, CORS, redirects, headers/cookies, exposed files and injection signals.

`scan` starts with static analysis. Select `--dynamic` / `--active` to combine the
modes, or use `s` / `d` / `a` in the TUI. The selected modes determine the traffic
sent to the target.

## Scan options (scan / static / dynamic / active / tui)

| Flag | Default | Description |
| --- | --- | --- |
| `--seed <URL>` | stdin | Seed URL to analyze. Repeatable. If omitted, seeds are read from stdin (one URL per line; `#` comments and blanks ignored). |
| `--stdin` | off | Also read seeds from stdin, merging them with any `--seed` values. |
| `--scope <HOST\|CIDR>` | seeds' hosts | In-scope host suffix, exact IP, or IP network. Repeatable. If omitted, derived from the seeds. |
| `--scope-file <PATH>` | — | JSON file with a non-empty `include` array and optional `exclude` array of host suffixes, IPs, or CIDRs. Lists combine with CLI values; exclusions win. |
| `--exclude <HOST\|CIDR>` | — | Out-of-scope host suffix, exact IP, or IP network. Repeatable. |
| `--name <NAME>` | `webrev-mission` | Mission name (env `WEBREV_NAME`). |
| `--proxy <URL>` | — | Egress proxy, e.g. `http://127.0.0.1:8080` (env `WEBREV_PROXY`). |
| `--header "<N: V>"` | — | Extra request header. Repeatable. |
| `--cookie "<n=v>"` | — | Cookie. Repeatable (collapsed into one `Cookie` header). |
| `--bearer <TOKEN>` | — | `Authorization: Bearer <token>` (env `WEBREV_BEARER`). |
| `--delay-min-ms <N>` | `150` | Lower bound of the inter-request delay window. |
| `--delay-max-ms <N>` | `600` | Upper bound of the inter-request delay window. |
| `--max-pages <N>` | `50` | Hard budget on resources fetched per crawl. |
| `--max-active-requests <N>` | `200` | Total active HTTP requests, including controls and unsuccessful attempts. |
| `--max-depth <N>` | `2` | Link-following depth from the seeds (0 = seeds only). |
| `--max-concurrency <N>` | `4` | Concurrent in-flight requests during the crawl. |
| `--duration-secs <N>` | `8` | Dynamic dwell time per seed (dynamic/tui only). |
| `--observation-only` | off | For `dynamic` and `scan --dynamic`: no driven scrolling/clicking; refuse methods other than GET/HEAD/OPTIONS. Page scripts still execute. Unsupported in TUI. |
| `--report <PATH>` | `webrev-report.json` | Direct report output for CLI scans; export path for the TUI `r` key. |
| `--redact` | off (`WEBREV_REPORT_REDACT=1`) | Mask credentials in the exported report. **By default the report is raw**: URLs, response excerpts, captured frames and finding text keep what was captured, because that is the proof of a finding. A raw report holds live credentials, so keep it private and add `--redact` before sharing it; writing one to a file prints a one-line warning. Detected secret plaintext is kept in both modes, and object identifiers (numbers, UUIDs, short hex ids) are never masked, so even a masked report must be treated as confidential. Logs, errors and the end-of-scan summary are masked whatever the mode. See [`security.md`](security.md). |

Scope matching is **host-suffix** based: `--scope example.com` matches
`example.com` and `api.example.com`. The scope is **fail-closed** — an empty
include list denies everything.

IP literals and CIDRs are also supported, for example `--scope 192.0.2.0/24`
or `--exclude 192.0.2.128/25`. Direct HTTP clients filter resolved addresses
against CIDR rules before connecting. A hostname explicitly included by domain
may use its DNS addresses unless an excluded IP/CIDR matches. Chromium can
enforce IP/CIDRs on literal-IP URLs, but cannot verify a hostname's resolved IP.
Dynamic hostname requests fail closed when IP or CIDR exclusions are present;
CIDR-only scope supports dynamic requests to literal IP URLs, while hostname
URLs require an explicit hostname entry too.

Example `scope.json`:

```json
{
  "include": ["example.com", "vendor.test"],
  "exclude": ["admin.example.com"]
}
```

Run with `webrev scan --seed https://app.example.com/ --scope-file scope.json`.
An explicitly supplied file with no allowed hosts is rejected; it never falls
back to the seed-derived scope.

All scans hold their session in memory. No database is created. Detected secrets
are retained and shown in plaintext by default, including JSON, JSONL, CSV and
the TUI. No reveal flag is required. The fingerprint remains a deduplication key.

## `report` options

| Flag | Default | Description |
| --- | --- | --- |
| `--input <PATH>` | `webrev-report.json` | Existing full JSON report to convert or filter. |
| `--output <PATH>` | stdout | Write the report to a file instead of printing it. |
| `--format <FMT>` | `json` | `json` (full document), `jsonl` (one finding per line), `urls` (stored route templates such as `/users/{id}`, one per line, no query string), `urls-exact` (the concrete URLs as discovered, real ids and query strings, one per line), `requests` (`METHOD URL` per line, same concrete URLs), `csv` (findings table), `text` (grouped human-readable triage), `openapi` (reconstructed OpenAPI 3.1 spec), `dot` (Graphviz graph), or `graphml` (GraphML graph). |
| `--scope <SEL>` | `all` | Restrict endpoint output: `all`, `internal` (in-scope target), or `external` (third-party). |
| `--min-confidence <LVL>` | `low` | Drop findings below `low` / `medium` / `high`. |
| `--min-severity <LVL>` | `info` | Drop findings below `info` / `low` / `medium` / `high` / `critical`. `jsonl`/`csv` are ranked by severity; `csv` leads with a `severity` column. |
| `--redact` | off (`WEBREV_REPORT_REDACT=1`) | Mask credentials in the converted output (every format). The input is converted as it is: a report that was already masked when it was written cannot be restored. Object identifiers are never masked, only credentials. |

Informational messages go to stderr and the data to stdout, so every format
pipes cleanly (a closed pipe such as `| head` exits without error).

## Subcommands

### `scan`

One-shot: runs the static pipeline, then (with `--dynamic`) a dynamic pass over
the same session, then writes a report. The fastest way to go from a seed to
findings without chaining `static` + `report` by hand.

Adds to the shared scan options:

| Flag | Default | Description |
| --- | --- | --- |
| `--dynamic` | off | Also run a dynamic (headless Chromium) pass after the static scan, in the same session. |
| `--active` | off | Also run a light active-scan pass (see below) over every endpoint the static/dynamic passes discovered, plus the seeds themselves. Sends abnormal traffic — authorized targets only. |
| `--format <FMT>` | `json` | Format of the end-of-scan report: `json`, `jsonl`, `urls`, `urls-exact`, `requests`, `csv`, `text`, `openapi`, `dot`, or `graphml`. |
| `--no-report` | off | Print the scan summary, then discard the in-memory session without writing a report. |

```bash
webrev scan --seed https://app.example.com/                 # static + report
webrev scan --seed https://app.example.com/ --dynamic       # + headless pass
webrev scan --seed https://app.example.com/ --active        # + active probing
webrev scan --seed https://app.example.com/ --no-report     # console summary only
subfinder -d example.com | httpx | webrev scan              # seeds on stdin
```

The session disappears when the process exits. JSON reports can be converted
later with `webrev report --input <PATH> --format <FMT>`. If you choose another
format during the scan, that export is the only saved artifact.

### `static`

Fetches the seeds and crawls same-scope links (and their scripts + source maps),
runs every extractor, deduplicates, and holds findings in memory. Prints a summary
and writes a full JSON report directly to `--report`.

```bash
webrev static --seed https://app.example.com/ --max-depth 2 --max-pages 200

# Compose with a recon pipeline — seeds come from stdin, one URL per line
subfinder -d example.com | httpx -silent | webrev static --scope example.com
```

### `dynamic`

Drives a headless Chromium per in-scope seed: injects `fetch`/XHR hooks, applies
auth, scrolls and clicks to exercise SPA behaviour, captures the resulting
requests and WebSocket endpoints, and exports a JSON report directly to
`--report`. Requires a local Chrome/Chromium.

```bash
webrev dynamic --seed https://app.example.com/ --duration-secs 10 --cookie "session=…"
```

Chromium is auto-detected on `PATH`. For a non-standard install (Flatpak/Snap,
custom path), set `CHROME=/path/to/chromium`. On Arch Linux, `pacman -S chromium`
is detected out of the box.

### `active`

> [!WARNING]
> Unlike every other subcommand, `active` sends abnormal, intentionally
> malformed traffic to the target (injected characters, a spoofed `Origin`,
> probes for well-known sensitive paths). It is opt-in for a reason —
> authorized targets only. The probe client issues GET-shaped requests, skips
> known `POST`/`PUT`/`DELETE`/`PATCH` endpoints, and does not follow injected redirects.

Runs a light, capped battery of active checks against the mission seeds
(standalone) or, via `scan --active`, every endpoint already discovered by the
static/dynamic passes plus the seeds. Each check is a handful of requests, not
a wordlist brute-forcer:

The standalone command exports its findings as JSON directly to `--report`.

| Check | What it does |
| --- | --- |
| Security headers | Flags missing `Content-Security-Policy`, `X-Content-Type-Options`, `X-Frame-Options`, and (on https) `Strict-Transport-Security`. |
| Cookie flags | Flags `Set-Cookie` entries missing `Secure` (https), `HttpOnly`, or `SameSite`. |
| CORS misconfiguration | Requires an arbitrary reflected Origin with `Access-Control-Allow-Credentials: true` on a successful response. Credentialless public reflection alone is not flagged. |
| Sensitive-file exposure | Compares a short path list against a nonexistent-path control and requires recognizable file content/magic, rather than a length difference alone. |
| Open redirect | For endpoints with a redirect-shaped parameter (`redirect`, `next`, `return`, `url`, …), swaps in a probe URL and checks whether the response blindly redirects there. |
| Parameter fuzzing | Mutates one query position at a time, preserving other raw pairs. Compares new SQL errors and literal HTML/XHTML reflection against a successful baseline; JSON is not classified as XSS. |
| IDOR-lite | Compares authenticated and anonymous id-shaped responses, omitting all mission headers and skipping recognized query credentials. Public resources can match; ownership is not established. |
| Template expressions | Two randomized arithmetic results plus a payload-free control verify expression evaluation in braces/dollar syntax. This does not prove OS command execution. |
| Path traversal / LFI | For file/path-shaped parameters, sends `../`-style and encoded payloads and content-verifies the response for `/etc/passwd` or `win.ini` signatures (not length alone). |
| CRLF / header injection | Injects an encoded `\r\n`-prefixed header into reflectable parameters and flags only when the response actually carries the injected header. |
| SSRF signal | For URL-valued parameters, substitutes a harmless unresolvable `.invalid` host — never internal/metadata addresses — and reports reflection or a behavior change as a low-confidence lead. Observational only. |
| Prototype pollution signal | Appends `__proto__[…]` / `constructor[prototype][…]` and flags a new 500 or reflected marker; a low-confidence lead for dynamic confirmation. |
| GraphQL introspection | For `graphql` endpoints, attempts an introspection query over GET and flags a `__schema`/`queryType` response. |
| Subdomain takeover | Fetches each origin root once and matches the body against known dangling-service signatures (GitHub Pages, S3 `NoSuchBucket`, Heroku, Fastly, Shopify, Surge, Read the Docs, Netlify). |

The active engine counts every HTTP attempt against a shared budget (default
200), including controls and unsuccessful requests. Each query/redirect/access
category also has 15 target attempts; at most four query positions are tested per
endpoint. Decoded bodies are limited to 512 KiB; oversized responses remain
inconclusive. Scope, jitter and cancellation apply to every request. A
`ScanCoverage` record exposes transport failures, HTTP refusals, scope
refusals, detector outcomes and reached limits. A refused scope target is not
reported as a negative test.
See [research review and proof boundaries](active-research.md).

```bash
webrev active --seed https://app.example.com/ --cookie "session=…"
webrev scan --seed https://app.example.com/ --active
```

### `tui`

Launches the interactive terminal UI and auto-starts a static scan. Keys:

| Key | Action |
| --- | --- |
| `Tab` / `→` | Next tab |
| `Shift-Tab` / `←` | Previous tab |
| `↑` / `k`, `↓` / `j` | Scroll the active list |
| `g` / `Home`, `G` / `End` | Jump to top / bottom (bottom re-enables follow) |
| `/` | Filter the active list (type to narrow, `Enter` apply, `Esc` clear) |
| `o` | Toggle severity ordering of the Endpoints/Findings list |
| `Enter` | Open/close the detail overlay for the selected endpoint/finding |
| `s` | Start a static scan |
| `d` | Start a dynamic scan |
| `a` | Run active checks over captured endpoints + seeds (authorized targets only) |
| `r` | Export the JSON report |
| `?` | Open/close the keyboard-help overlay |
| `q` / `Esc` | Close an open overlay, then quit |

Endpoints and Findings lead each row with a colored severity tag
(`CRIT`/`HIGH`/`MED`/`LOW`/`INFO`) and, for endpoints, an `int`/`ext` scope tag;
`o` reorders by severity. The focused Secrets, Vulns and Tech tabs share the same records and support
filtering, severity sorting and inspection. The Status tab shows scope counts,
IDOR/XSS/SQLi/SSTI counts and RCE as not tested. The latest active coverage appears
in Status. Details include structured probe observations, proof limits, severity,
confidence, full evidence and source; use arrows to scroll long details. Scans
run one at a time and the UI returns to ready when each task finishes.

### `report`

Converts or filters an existing full JSON report (summary counters, endpoints,
and all findings). Mission metadata and detected secret values are preserved.

```bash
webrev report --format text         # grouped human-readable triage
webrev report                       # reads webrev-report.json and prints JSON
webrev report --output report.json  # writes it to a file

# Feed just the in-scope endpoint URLs into another tool
webrev report --format urls-exact --scope internal | ffuf -u FUZZ -w -

# Only the high-confidence findings, as a spreadsheet
webrev report --format csv --min-confidence high --output findings.csv

# Reconstruct an OpenAPI 3.1 spec of the discovered surface (marked UNVERIFIED)
webrev report --format openapi --output api.json

# Export observed component, endpoint, and parameter relations
webrev report --format dot --output relations.dot
webrev report --format graphml --output relations.graphml

# Reports are raw by default. `urls` lists route templates (`/users/{id}`, no
# query string); `urls-exact` lists the concrete URLs as discovered, so a
# fuzzer or replay tool gets the real object ids and parameters
webrev scan --seed https://app.example.com/
webrev report --format urls-exact | ffuf -u FUZZ -w -
webrev report --format requests     # METHOD URL per line (UNKNOWN when the verb is not known)

# Share a report: mask credentials (a raw one holds live ones)
webrev report --input webrev-report.json --redact --output shareable.json

# Compare stack and API routes across separate target reports
webrev compare --input target-a.json --input target-b.json --output comparison.json
```

### Automated cross-account BOLA checks

Use two test accounts and objects you own. Put each account's authentication in
a JSON file such as `{"cookies":[["sid","ACCOUNT_SESSION"]]}` or
`{"bearer":"TOKEN"}`. The `bola` command opens each seed in the browser under
both accounts, pairs GET object URLs with the same route shape and different
identifiers, then compares A→A, B→B, B→A, and A→B. It does not guess IDs or
send write requests.

```bash
webrev bola --seed https://app.example.com/ --scope example.com \
  --a-auth account-a.json --b-auth account-b.json
```

If the account-specific scans have already been captured, Chromium is not
needed for the comparison:

```bash
webrev bola --a-report account-a-report.json --b-report account-b-report.json \
  --a-auth account-a.json --b-auth account-b.json --output bola.json
```

The output is a JSON report with a coverage record and any cross-account
signals. A matching response still needs an ownership and privacy check before
it is treated as a vulnerability.

## Environment variables

`WEBREV_NAME`, `WEBREV_PROXY`, and `WEBREV_BEARER` provide defaults
for the matching flags, so they can be set once per engagement.

## Standalone TUI binary

`webrev-tui` is also a thin binary with a reduced flag set
(`--seed`, `--scope`, `--name`, `--report`, `--proxy`). Prefer
`webrev tui …` for the full option set (auth, budgets).

## Reading results and piping a scan

All scan commands print a prioritized triage view to stdout and send progress to
stderr. Vulnerability and secret leads appear first, followed by technologies,
the top eight surface observations, and a coverage summary. The JSON report
retains every finding and its full evidence; `webrev report --format text` shows
the complete human-readable version. Secrets remain complete. Lead rows show
severity (priority), status, confidence, and a short evidence excerpt.
Technologies are signature matches; secret validity is not tested. XSS reflections, SQL errors, sensitive-file and
IDOR-lite observations require manual verification, independently of their
severity. Template arithmetic can confirm expression evaluation, while OS RCE is not
tested. A count of zero is not proof of coverage.

Use `--report -` on any CLI scan to send only the machine report to stdout (JSON
for standalone commands; `--format` selects it for `scan`). No file is created:

```sh
webrev scan --seed https://app.example.com/ --active --format jsonl --report - | jq .
webrev scan --seed https://app.example.com/ --format urls-exact --report - | httpx
webrev static --seed https://app.example.com/ --report - > findings.json
webrev scan --seed https://app.example.com/ --format text --report findings.txt
```

`NO_COLOR` disables CLI result styling; redirected output has no ANSI escapes.
Machine exports retain the original bytes; terminal views escape control
characters so fetched content cannot forge rows or terminal commands.
