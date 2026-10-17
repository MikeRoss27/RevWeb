# Active assessment research review — 11 October 2026

## What the supplied site establishes

[Web Hack List, 2026 AI collection](https://webhacklist.com/?year=2026-ai#evidence)
is a research index with an investigation-board interface, not a scanner or a
validated exploit catalogue. Its downloaded collection declares 296 records,
version `c9de31bb3812b1be7a42`, and a coverage date of 9 October 2026. The collection
is explicitly preliminary, unranked, incomplete and AI-collected. Those records
are leads; their presence does not establish applicability to a scanned target.
The [maintained Markdown source](https://github.com/irsdl/webhacklist/blob/master/2026-ai.md)
also records withdrawn sources, inaccessible bodies and work first disclosed in
earlier years. Tag frequencies overlap and are not prevalence measurements.

## Sources checked and implementation decisions

| Primary research | Implication for webrev | Implemented / remaining |
| --- | --- | --- |
| [RCEKit](https://github.com/kabiri-labs/rcekit) distinguishes execution, evaluation, weaker signals, blocked probes and untested runs. | A reflected marker or database error cannot justify a confirmed RCE. Coverage must count failed requests and controls. | Structured verdicts and HTTP observations; actual shared request budget; coverage records including cancellation, refused/oversized responses, transport failures and limits. Shell execution, timing and callback verification remain outside the current engine. |
| [PortSwigger's SSTI methodology](https://portswigger.net/web-security/server-side-template-injection) uses calculated expressions to identify template evaluation, while noting context and engine differences. | Add an arithmetic-only assessment before attempting engine-specific exploitation. | `{{a*b}}` and `${a*b}` probes with random operands/nonces, two distinct results, the original baseline and a payload-free control. The verdict proves expression evaluation; engine identification, unintended access and OS execution remain unproven. |
| [Voorivex query-parser differentials](https://blog.voorivex.team/when-two-parsers-disagree-exploiting-query-string-differentials-for-xss) demonstrates differing interpretations of raw query strings. | Re-encoding every value or mutating duplicate names together can alter the test and lose attribution. | Exactly one query position changes; other raw pairs, duplicate keys and existing encoding remain intact. Empty positions are retained. This does not implement the article's browser-side bypass challenge or prove DOM XSS. |
| [Remote MCP authentication study](https://arxiv.org/abs/2605.22333) examines tool exposure and OAuth authorization boundaries. | Seeing an MCP URL or getting HTTP 200 is insufficient to establish access to a privileged tool. | Anonymous HTTP comparisons include an explicit public-resource limitation and skip recognized query credentials. MCP initialization, tool authorization and OAuth flows require a dedicated protocol module; generic HTTP checks cannot claim those properties. |
| [Supabase study](https://modernpentest.com/blog/yc-supabase-vulnerability-research) investigates anonymously accessible application data. | Technology detection and a client API key do not establish a row-level authorization flaw. | Existing Supabase detection remains discovery. Cross-user/tenant row access needs operator-provided identities and ownership expectations; current IDOR-lite remains a signal. |
| [YesWeHack cache-key research](https://www.yeswehack.com/lab/research-cache-key-injection) studies ambiguity in cache-key construction and layered caches. | Shared cache state can contaminate a result and affect other users. | Expression confirmation includes a payload-free control to reject matching cached output. There is no cache-key poisoning detector; isolated cache experiments and read-back proof need a separate module. |

These decisions are an engineering assessment of the sources, not a claim to
reproduce every listed exploit. The engine was implemented independently; it
does not download, execute or import exploit payloads from the archive.

## Current checks and proof boundaries

- SQL error findings identify the query position and newly introduced signature,
  compared to a successful baseline. A different signature already present in
  the baseline no longer suppresses the new one. SQL execution remains unproven.
- XSS signals require literal markup reflection in an HTML/XHTML response.
  JSON responses and escaped markup do not count. JavaScript execution and DOM
  context still require manual/browser verification.
- Sensitive-file findings require recognizable content: Git structures,
  environment assignments, PHP configuration source, ZIP or DS_Store magic.
  A different-length HTML error page is insufficient.
- CORS findings require arbitrary Origin reflection together with credential
  allowance on a successful response. Public credentialless reflection alone is
  not emitted as a vulnerability. Browser credential policy and data sensitivity
  still determine impact.
- IDOR-lite removes all mission headers in its anonymous request, skips recognized
  credential-bearing queries, compares bounded complete bodies, and records both
  responses. Public resources can legitimately match. There is no second-identity
  ownership test.
- Open redirects require the exact randomized injected URL in Location. Redirects
  are never followed by the active client.

## Operational limits and reporting

Every active HTTP request passes through one transport. Scope and HTTP scheme
checks precede connection; URL userinfo is rejected. Redirects and automatic
retries are disabled. One explicit retry on transport failure consumes
the same request budget and delay; the initial failure remains in coverage.
Each probe uses a separate connection, avoiding stale
pooled connections and connection-bound authentication leaking into anonymous
controls. Mission proxy selection is explicit. Authentication header syntax is
validated instead of silently dropping invalid material.

Defaults: 200 total requests, 512 KiB decoded response body, four query positions
per endpoint, and 15 target attempts per parameter-fuzz, expression, redirect and
anonymous-access category. Controls and unsuccessful requests consume the same
budget. Each request observes the mission delay/UA policy. Cancellation interrupts
HTTP waits and body reads. GET handlers can still cause application side effects.

Use `--max-active-requests N` in the CLI or either TUI entry point to change the
shared budget. Library callers can also set `OpsecConfig.active.max_parameters`
and `max_body_bytes`. Limits apply to active probing separately from crawl limits.

Each run stores a `ScanCoverage` finding in the in-memory session, including when
no weakness was found. JSON/JSONL/CSV preserve structured evidence and coverage;
text reports and TUI details expose the observations. The TUI Status view shows
the latest active coverage. A zero finding count does not establish absence of
vulnerabilities. Recorded refused responses conservatively make coverage
incomplete, including authentication refusals that may be expected.

## Validation scope

Wire-level loopback regressions cover positive and negative arithmetic cases,
HTML versus JSON reflection, individual parameter mutation, SQL baseline
calibration, sensitive-file controls, CORS policy, credential stripping, budgets,
body limits, scope/method boundaries and cancellation. Existing CLI/TUI tests
exercise the real entry points. Arithmetic fixtures validate detection logic;
an additional local Jinja2 run checks an actual template engine. These checks
do not establish coverage of third-party products or production CVEs.

Validated on Windows: 151 workspace tests passed; the separately enabled real
Chrome loopback test also passed (152 successful Cargo tests total). The external
browser smoke test remains ignored in the default suite, but its local-only
Chromium run is separately recorded in the reliability changelog. Strict workspace/all-target Clippy passed;
the largest Rust source has 488 lines. Debug and release CLI runs against real
Jinja2 each produced one expression finding for the vulnerable renderer and none
for the safe renderer. Both release binaries were installed and hash-matched;
the native bundle passed installation and corruption-before-replacement checks.
Linux/macOS execution and production-CVE reproduction were not performed here.
