# Usage

`webrev` has four subcommands: `static`, `dynamic`, `tui`, and `report`.

```text
webrev <COMMAND> [OPTIONS]
```

All scanning subcommands (`static`, `dynamic`, `tui`) share the same options.
`report` has its own, smaller set.

## Scan options (static / dynamic / tui)

| Flag | Default | Description |
| --- | --- | --- |
| `--seed <URL>` | *(required)* | Seed URL to analyze. Repeatable. |
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
| `--report <PATH>` | `webrev-report.json` | Report path used by the TUI `r` key. |

Scope matching is **host-suffix** based: `--scope example.com` matches
`example.com` and `api.example.com`. The scope is **fail-closed** — an empty
include list denies everything.

## `report` options

| Flag | Default | Description |
| --- | --- | --- |
| `--session <UUID>` | latest scan | Session to export. Defaults to the most recent one in the DB. |
| `--db <PATH>` | `webrev.db` | SQLite database path (env `WEBREV_DB`). |
| `--output <PATH>` | stdout | Write the JSON report to a file instead of printing it. |

## Subcommands

### `static`

Fetches the seeds and crawls same-scope links (and their scripts + source maps),
runs every extractor, deduplicates, and stores findings. Prints a summary and
the `report` command to run next.

```bash
webrev static --seed https://app.example.com/ --max-depth 2 --max-pages 200
```

### `dynamic`

Drives a headless Chromium per in-scope seed: injects `fetch`/XHR hooks, applies
auth, scrolls and clicks to exercise SPA behaviour, captures the resulting
requests and WebSocket endpoints, and stores them. Requires a local
Chrome/Chromium.

```bash
webrev dynamic --seed https://app.example.com/ --duration-secs 10 --cookie "session=…"
```

### `tui`

Launches the interactive terminal UI and auto-starts a static scan. Keys:

| Key | Action |
| --- | --- |
| `Tab` / `→` | Next tab |
| `Shift-Tab` / `←` | Previous tab |
| `↑` / `k`, `↓` / `j` | Scroll the active list |
| `g` / `Home`, `G` / `End` | Jump to top / bottom (bottom re-enables follow) |
| `s` | Start a static scan |
| `d` | Start a dynamic scan |
| `r` | Export the JSON report |
| `q` / `Esc` | Quit |

### `report`

Exports a stored session as JSON (summary counters, endpoints, and all
findings). With no `--session`, it uses the most recent scan.

```bash
webrev report                      # prints the latest session as JSON
webrev report --output report.json # writes it to a file
```

## Environment variables

`WEBREV_DB`, `WEBREV_NAME`, `WEBREV_PROXY`, and `WEBREV_BEARER` provide defaults
for the matching flags, so they can be set once per engagement.

## Standalone TUI binary

`webrev-tui` is also a thin binary with a reduced flag set
(`--seed`, `--scope`, `--name`, `--db`, `--report`, `--proxy`). Prefer
`webrev tui …` for the full option set (auth, budgets).
