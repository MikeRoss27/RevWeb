# Usage

`webrev` has five subcommands: `scan`, `static`, `dynamic`, `tui`, and `report`.
`scan` is the one-shot convenience wrapper; the others are the individual steps.

```text
webrev <COMMAND> [OPTIONS]
```

All scanning subcommands (`scan`, `static`, `dynamic`, `tui`) share the same
options below. `scan` adds a few of its own (see its section), and `report` has
its own, smaller set.

## Scan options (scan / static / dynamic / tui)

| Flag | Default | Description |
| --- | --- | --- |
| `--seed <URL>` | stdin | Seed URL to analyze. Repeatable. If omitted, seeds are read from stdin (one URL per line; `#` comments and blanks ignored). |
| `--stdin` | off | Also read seeds from stdin, merging them with any `--seed` values. |
| `--scope <HOST>` | seeds' hosts | In-scope host suffix. Repeatable. If omitted, derived from the seeds. |
| `--exclude <HOST>` | — | Out-of-scope host suffix. Repeatable. |
| `--name <NAME>` | `webrev-mission` | Mission name (env `WEBREV_NAME`). |
| `--db <PATH>` | `webrev.db` | SQLite database path (env `WEBREV_DB`). |
| `--proxy <URL>` | — | Egress proxy, e.g. `http://127.0.0.1:8080` (env `WEBREV_PROXY`). |
| `--header "<N: V>"` | — | Extra request header. Repeatable. |
| `--cookie "<n=v>"` | — | Cookie. Repeatable (collapsed into one `Cookie` header). |
| `--bearer <TOKEN>` | — | `Authorization: Bearer <token>` (env `WEBREV_BEARER`). |
| `--delay-min-ms <N>` | `150` | Lower bound of the inter-request delay window. |
| `--delay-max-ms <N>` | `600` | Upper bound of the inter-request delay window. |
| `--max-pages <N>` | `50` | Hard budget on resources fetched per crawl. |
| `--max-depth <N>` | `2` | Link-following depth from the seeds (0 = seeds only). |
| `--max-concurrency <N>` | `4` | Concurrent in-flight requests during the crawl. |
| `--duration-secs <N>` | `8` | Dynamic dwell time per seed (dynamic/tui only). |
| `--report <PATH>` | `webrev-report.json` | Report path used by `scan` and the TUI `r` key. |
| `--reveal-secrets` | off | Record and show detected secrets in **plaintext** instead of only a fingerprint (env `WEBREV_REVEAL_SECRETS`). Dangerous: writes live credentials to the DB and reports. See [security.md](security.md). No effect on `dynamic`. |

Scope matching is **host-suffix** based: `--scope example.com` matches
`example.com` and `api.example.com`. The scope is **fail-closed** — an empty
include list denies everything.

## `report` options

| Flag | Default | Description |
| --- | --- | --- |
| `--session <UUID>` | latest scan | Session to export. Defaults to the most recent one in the DB. |
| `--db <PATH>` | `webrev.db` | SQLite database path (env `WEBREV_DB`). |
| `--output <PATH>` | stdout | Write the report to a file instead of printing it. |
| `--format <FMT>` | `json` | `json` (full document), `jsonl` (one finding per line), `urls` (bare endpoint URLs, one per line), or `csv` (findings table). |
| `--scope <SEL>` | `all` | Restrict endpoint output: `all`, `internal` (in-scope target), or `external` (third-party). |
| `--min-confidence <LVL>` | `low` | Drop findings below `low` / `medium` / `high`. |
| `--min-severity <LVL>` | `info` | Drop findings below `info` / `low` / `medium` / `high` / `critical`. `jsonl`/`csv` are ranked by severity; `csv` leads with a `severity` column. |

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
| `--format <FMT>` | `json` | Format of the end-of-scan report: `json`, `jsonl`, `urls`, or `csv`. |
| `--no-report` | off | Just populate the database; skip writing the report. |

```bash
webrev scan --seed https://app.example.com/                 # static + report
webrev scan --seed https://app.example.com/ --dynamic       # + headless pass
subfinder -d example.com | httpx | webrev scan              # seeds on stdin
```

### `static`

Fetches the seeds and crawls same-scope links (and their scripts + source maps),
runs every extractor, deduplicates, and stores findings. Prints a summary and
the `report` command to run next.

```bash
webrev static --seed https://app.example.com/ --max-depth 2 --max-pages 200

# Compose with a recon pipeline — seeds come from stdin, one URL per line
subfinder -d example.com | httpx -silent | webrev static --scope example.com
```

### `dynamic`

Drives a headless Chromium per in-scope seed: injects `fetch`/XHR hooks, applies
auth, scrolls and clicks to exercise SPA behaviour, captures the resulting
requests and WebSocket endpoints, and stores them. Requires a local
Chrome/Chromium.

```bash
webrev dynamic --seed https://app.example.com/ --duration-secs 10 --cookie "session=…"
```

Chromium is auto-detected on `PATH`. For a non-standard install (Flatpak/Snap,
custom path), set `CHROME=/path/to/chromium`. On Arch Linux, `pacman -S chromium`
is detected out of the box.

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
| `r` | Export the JSON report |
| `?` | Open/close the keyboard-help overlay |
| `q` / `Esc` | Close an open overlay, then quit |

Endpoints and Findings lead each row with a colored severity tag
(`CRIT`/`HIGH`/`MED`/`LOW`/`INFO`) and, for endpoints, an `int`/`ext` scope tag;
`o` reorders by severity. The Status tab breaks endpoints down by scope.

### `report`

Exports a stored session as JSON (summary counters, endpoints, and all
findings). With no `--session`, it uses the most recent scan.

```bash
webrev report                       # prints the latest session as JSON
webrev report --output report.json  # writes it to a file

# Feed just the in-scope endpoint URLs into another tool
webrev report --format urls --scope internal | ffuf -u FUZZ -w -

# Only the high-confidence findings, as a spreadsheet
webrev report --format csv --min-confidence high --output findings.csv
```

## Environment variables

`WEBREV_DB`, `WEBREV_NAME`, `WEBREV_PROXY`, and `WEBREV_BEARER` provide defaults
for the matching flags, so they can be set once per engagement.

## Standalone TUI binary

`webrev-tui` is also a thin binary with a reduced flag set
(`--seed`, `--scope`, `--name`, `--db`, `--report`, `--proxy`). Prefer
`webrev tui …` for the full option set (auth, budgets).
