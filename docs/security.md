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

For an explicit engagement boundary, pass every authorized domain with
repeatable `--scope` options or use `--scope-file scope.json`, for example
`webrev scan --seed https://app.example.com --scope example.com --scope api.vendor.test`.
Webrev treats DNS answers for an allowed hostname as routing that authorized
hostname and pins the first answer set per HTTP client. Redirects still need to
match the configured hostname scope. A proxy may resolve the destination
remotely, so its egress policy must enforce the same authorization boundary.
Scope files are JSON with `include` and optional `exclude` arrays. Entries may
be hostname suffixes, exact IP literals, or CIDR networks. Direct HTTP clients
filter resolved addresses through CIDR entries before connecting. For a domain
explicitly included by hostname, its DNS answers are treated as routes for that
authorized hostname unless an excluded IP/CIDR matches. Chromium cannot check a
hostname's resolved address before it connects; dynamic scans fail closed for
hostname requests if the scope contains IP/CIDR exclusions. CIDR-only scope
supports dynamic requests to literal IP URLs, while hostname URLs require a
hostname entry as well. When a proxy resolves target hostnames remotely, it
must enforce the same destination IP/CIDR rules; Webrev cannot inspect that
remote resolution.

Active coverage separates HTTP refusals (for example 401/403/429) from scope
refusals. A direct DNS lookup whose addresses all fall outside the configured
IP/CIDR scope is refused before connection and is not retried; it cannot count
as a negative security test. The aggregate `out_of_scope` count also includes
targets excluded before detector selection.

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
- **Destructive-looking URLs are refused.** Endpoints, BOLA candidates and
  crawled `<a href>` links whose path or query contains a whole-token
  state-changing word (logout, delete, remove, unsubscribe, pay, checkout,
  reset, ...) are never requested. Active scans and BOLA record them as a
  `destructive_url_guard` check (refused, not executed, inconclusive), so the
  coverage record is never complete. There is no override flag. This is a
  name heuristic: a GET handler with a harmless name can still mutate state.
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

## Exposition accidentelle des données sensibles

Le texte en clair des secrets détectés reste volontairement présent dans les
findings et les rapports (`Finding.plaintext`) : cette section ne le concerne
pas. Elle traite des fuites non voulues, hors rapport.

Corrigé :

- `AuthConfig` (en-têtes, cookies, bearer) n'a plus de `Debug` dérivé : `{:?}`
  n'affiche que les noms des en-têtes/cookies et `<redacted>` pour le bearer.
  La sérialisation JSON (fichiers de compte BOLA) est inchangée.
- `EgressPolicy` et `DnsPolicy` masquent le `user:pass@` et les paramètres de
  requête sensibles de l'URL du proxy / DoH dans `Debug`, donc aussi dans
  `OpsecConfig` et `MissionProfile`.
- `webrev_core::redact_url` masque userinfo et valeurs de paramètres
  `token/key/secret/pass/sig/session/...` (requête et fragment). Elle est
  utilisée pour les lignes `dynamic:` / `skip out-of-scope:` et l'erreur de
  seed BOLA invalide. Elle ne s'applique jamais aux findings ni aux rapports.

Non corrigé ou non vérifié (hors périmètre de cette passe) :

- `webrev-pipeline` : les erreurs `invalid proxy {proxy:?}` (`active/client.rs`,
  `stages/fetch/request.rs`), les erreurs reqwest `requesting {url}` /
  `reading {url}` (le texte reqwest contient l'URL complète) et
  `tracing::debug!(%url, ...)` (`active/transport.rs`) peuvent afficher
  userinfo ou jetons en requête sur stderr ; à passer par `redact_url`.
- `webrev-browser` : `HarEntry` dérive `Debug` et contient les en-têtes de
  requête (dont `Authorization`) ; il n'est pas écrit sur disque à ce jour.
  *(Corrigé le 2026-10-18, voir le suivi ci-dessous.)*
- Les extraits de preuve actifs (256 caractères) et les URL de seeds sont
  conservés tels quels dans le rapport ; une réponse qui renvoie un cookie ou un
  jeton dans son corps s'y retrouve. Les seeds avec userinfo/jeton figurent
  dans `mission.seeds` du rapport JSON.
- Le défaut de `RUST_LOG=debug`/`trace` des dépendances (reqwest, hyper,
  chromiumoxide) n'a pas été audité. *(Audit partiel le 2026-10-18 : reqwest
  seulement, voir le suivi ci-dessous.)*

### Suivi : journaux et erreurs du pipeline (2026-10-17)

Les messages `invalid proxy`, `requesting`, `reading` et le journal
`active probe request failed` passent maintenant par `redact_url` et utilisent
`reqwest::Error::without_url`, de sorte que userinfo et jetons de requête
n'apparaissent plus dans les erreurs ni dans `tracing`. Restent hors de portée :
le `Debug` de `HarEntry` (en-têtes `Authorization`, en mémoire uniquement), les
extraits de réponses de sondes actives stockés tels quels dans le rapport JSON,
et les journaux internes de reqwest/hyper/chromiumoxide sous `RUST_LOG=debug`.

### Suivi : `HarEntry`, extraits de sondes et journaux des dépendances (2026-10-18)

- `HarEntry` n'a plus de `Debug` dérivé : `{:?}` masque les valeurs des en-têtes
  sensibles (`Authorization`, `Cookie`, ...), les motifs de secrets et les
  paramètres sensibles de l'URL. Les données restent intactes en mémoire.
- `ProbeResponse::observation` passe l'extrait (avant la troncature à 256
  caractères) dans `Sanitizer::scrub` et l'URL dans `redact_url` avant stockage
  dans le rapport JSON. Seuls les motifs de secrets connus sont masqués ; un
  jeton de forme inconnue dans un corps de réponse subsiste.
- Audit de `RUST_LOG=debug` / `trace` des dépendances : lecture du code de
  reqwest 0.12.28 uniquement, **aucune exécution contre une fixture** (la
  machine manquait de mémoire pour compiler le binaire). Constats :
  - `debug` : `starting new connection: {dst:?}` (connect.rs) journalise l'URI
    complète, jetons de requête compris ; `proxy({proxy:?}) intercepts ...`
    journalise la configuration du proxy.
  - `trace` : le wrapper de connexion journalise les octets lus/écrits
    (`read:` / `write:`), donc les requêtes et en-têtes `Authorization` en clair.
  - hyper, hyper-util et chromiumoxide (qui expose les messages CDP) n'ont pas
    été lus.
  Le filtre par défaut est `info,chromiumoxide::handler=error` ; seul un
  `RUST_LOG` explicite active ces niveaux. Rien n'est corrigé côté code : il
  faudrait filtrer ces cibles, à décider. À ne pas activer avec de vrais
  identifiants.
