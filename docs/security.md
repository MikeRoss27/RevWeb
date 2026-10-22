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
in memory instead of masking credential-looking substrings. Existing
capture-size budgets still apply. Exported reports keep them: they are raw by
default, and `--redact` masks credentials when a report has to be shared (see
"Reporting scope").

## Operational controls

`OpsecConfig` bounds and shapes traffic so scans stay polite and within limits:

- **Request jitter** — delays are sampled from a normal distribution inside the
  `[delay-min-ms, delay-max-ms]` window, not a fixed rate.
- **Concurrency & budgets** — `--max-concurrency`, `--max-pages`, `--max-depth`
  cap load and breadth.
- **Crawl response body cap** — `--max-body-bytes` (default 20 MiB) truncates
  a per-page response read instead of buffering it to completion; a
  pathologically large or slow-drip response cannot grow the fetch stage's
  memory without bound. Separate from, and much larger than, active
  scanning's own 512 KiB decoded-body cap below, since a crawled page can
  legitimately be a multi-megabyte bundle.
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

- **GET-shaped probe requests, with two documented exceptions.** Endpoints
  known to be `POST`/`PUT`/`DELETE`/`PATCH` are skipped by the probe client.
  Browser interactions execute application behavior independently of this
  restriction. Both exceptions send only a compile-time-fixed, literal
  JSON body — via `ProbeClient::post_literal`/`post_literal_with_accept`,
  whose body parameter is typed `&'static str` so it can never carry a
  value built from a response, a URL, or any other runtime input — and the
  same scope check, request budget, retry-once policy, and redirect
  refusal apply as to every GET probe:
  - **GraphQL introspection** (`crates/webrev-pipeline/src/active/graphql.rs`):
    introspection is defined by the GraphQL specification as a read of
    schema metadata, so it cannot mutate application state regardless of
    HTTP verb. Sent over POST only when the standard `IntrospectionQuery`
    does not answer over GET.
  - **MCP tool-exposure check** (`crates/webrev-pipeline/src/active/mcp.rs`):
    an unauthenticated `initialize` + `tools/list` JSON-RPC handshake
    against endpoints whose path looks like an MCP server. Per the Model
    Context Protocol specification, both calls are capability negotiation
    and read-only enumeration — never `tools/call` (actually invoking a
    tool), which this check never attempts. Listing a tool does not
    establish that calling it would also succeed unauthenticated; full
    OAuth authorization-flow testing is out of scope for this check (see
    [proof boundaries](active-research.md)).
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
- **Timing-injection probes are the one documented exception, and are
  disabled unless explicitly requested.** `--allow-timing-probes`
  (`OpsecConfig.active.allow_timing_probes`, off by default) lets
  `active::timing` inject a `sleep`-shaped command separator and measure
  whether the response is delayed by roughly the injected amount — which, on
  a vulnerable target, means a real shell command actually ran. No file
  write, no callback: the only side effect, if the target is vulnerable, is
  the target process sleeping for a few seconds. A single slow response
  proves nothing (a slow endpoint, jitter, rate limiting can look
  identical), so each candidate is tested at two distinct injected delays,
  each measured net of a length-matched, non-executing control carrying the
  same number; both magnitudes must scale with what was injected before any
  finding is raised. Even confirmed on both magnitudes, this stays at
  `EvidenceVerdict::TimingCorrelated`, never `Confirmed`: timing is a side
  channel, not a deterministic proof, unlike expression evaluation's two
  independent arithmetic results.
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

**An exported report is raw by default.** It is the deliverable of a bug-bounty
run, and the proof of a finding lives in the captured values: the token in the
leaked URL, the `session_id` that travels in a query string, the `/reset/<token>`
path, the `Authorization` header of a captured request, the response excerpt of
a probe. Masking them by default would leave a report that proves nothing.
A raw report therefore holds live credentials: **treat it as confidential, and
do not hand it to a client, a ticket or a chat without `--redact`.** Every scan
that writes a raw report to a file ends with a one-line warning to that effect.

`--redact` (or `WEBREV_REPORT_REDACT=1`) masks credentials in every export
(JSON, JSONL, CSV, URLs, text, OpenAPI, DOT, GraphML; `--report -` included;
the TUI `r` key; `bola` results; `webrev report`) through
`SessionReport::redacted`: mission name and seeds, endpoint and finding URLs,
finding text, probe evidence and captured frames go through `redact_url` and
`Sanitizer::scrub`, JSON values leaf by leaf. A masked JSON report carries
`"redacted": true`. The detected plaintext of secret findings is kept either
way. Raw is what `webrev report --format urls-exact | ffuf` (the `urls` format lists route templates, not real values) and
`webrev bola --a-report/--b-report` need; both also accept a masked report,
minus the pairs whose captured URL held a credential.

What stays masked whatever the mode, because it is accidental exposure and not
a deliverable: logs (`RUST_LOG`, with `chromiumoxide::conn` and `tungstenite`
capped at `error` unless `WEBREV_LOG_UNSAFE=1`), error messages, `Debug`
renderings (`HarEntry`, `AuthConfig`, `OpsecConfig`), the `dynamic: <seed>`
line and the compact summary printed at the end of a scan.

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
  seed BOLA invalide. Elle ne s'applique ni aux findings ni aux rapports
  exportés par défaut ; avec `--redact`, l'export la réutilise (voir « Suivi :
  rapports bruts par défaut »).

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
- *(Révisé le 2026-10-19 : voir « Suivi : rapports bruts par défaut ».)*
  `ProbeResponse::observation` passait l'extrait (avant la troncature à 256
  caractères) dans `Sanitizer::scrub` et l'URL dans `redact_url` avant stockage
  dans le rapport JSON. Elle stocke maintenant l'extrait et l'URL bruts, et le
  masquage se fait à l'export avec `--redact`.
- Audit de `RUST_LOG=debug` / `trace` des dépendances : lecture du code de
  reqwest 0.12.28 uniquement, sans exécution. **Remplacé par l'audit exécuté du
  2026-10-18 ci-dessous**, qui corrige certains de ces constats. Constats de la
  lecture :
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

### Suivi : audit exécuté de `RUST_LOG` (2026-10-18)

Mesuré en lançant le binaire (`scan --dynamic --active`, Chromium système)
contre une fixture loopback qui exige des secrets factices : `--bearer`,
`--cookie`, `--header "X-Api-Key: …"`, jeton en paramètre de requête, `Set-Cookie`
et secrets dans le corps JSON. Trois niveaux : `info`, `debug`, `trace`.

Avant correctif (nombre de lignes de journal contenant le secret, `debug` /
`trace`) :

| Secret | `debug` | `trace` | Cible qui l'écrit |
|---|---:|---:|---|
| Bearer (`Authorization`) | 4 | 32 | `chromiumoxide::conn::raw_ws::parse_errors`, `chromiumoxide::conn`, `tungstenite::protocol` |
| En-tête `X-Api-Key` | 4 | 32 | idem |
| `Set-Cookie` de la réponse | 4 | 26 | idem |
| Cookie `--cookie` | 0 | 16 | `chromiumoxide::conn`, `tungstenite` |
| Jeton en requête (`token=`) | 0 | 8 | idem |

- chromiumoxide journalise les messages CDP bruts (`Network.*ExtraInfo`) dès
  `debug`, et tungstenite les trames WebSocket à `trace`. Ce sont eux qui fuient.
- reqwest et hyper (`hyper_util`, `reqwest::connect`, `reqwest::retry`) n'ont
  journalisé que l'hôte et le port à `debug`/`trace` : aucun secret sur 132 lignes
  `hyper_util` et 44 lignes `reqwest` à `trace`. La lecture de code précédente
  surestimait leur exposition (reqwest 0.12.28 n'écrit plus l'URI complète).
- Le corps de réponse n'apparaît dans aucun niveau (pas de canari de corps).

Correctif : `crates/webrev-cli/src/logging.rs`. Après le filtre de l'utilisateur
(`RUST_LOG`), les cibles `chromiumoxide::conn` et `tungstenite` sont ramenées à
`error`, et une directive explicite telle que `RUST_LOG=chromiumoxide::conn=trace`
ne les rouvre pas. `WEBREV_LOG_UNSAFE=1` lève ce plafond, pour déboguer avec des
identifiants jetables. Tests : `cargo test -p webrev-cli logging` (4 tests, dont
le plafond et la levée).

Après correctif, même fixture : **0 ligne** contenant le Bearer, le cookie,
`X-Api-Key`, `Set-Cookie` ou le jeton de requête à `info`, `debug` et `trace`.

Restes constatés :

- ~~`redact_url` masquait par nom de paramètre seulement (`tok` fuyait dans
  `dynamic: <seed>` à tous les niveaux).~~ *Corrigé (voir « Suivi : redaction par
  forme de valeur » ci-dessous).*
- Le rapport écrit sur stdout conserve les seeds et les URL d'endpoints
  découverts tels quels (`?tok=…`, `?token=…` dans l'URL d'un `fetch` trouvé dans
  le JavaScript de la cible), comme déjà documenté. *(Le résumé compact est
  masqué depuis le 2026-10-18 ; les rapports exportés le sont depuis le
  2026-10-19, voir « Suivi : rapports exportés ».)*
- ~~Un secret de corps de forme inconnue (`"session":"…"`) restait dans l'extrait
  de preuve.~~ *Corrigé pour les noms session/sid/auth/credential/passwd/pwd/jwt/
  bearer/cookie, voir ci-dessous.*
- Non audités : TUI (sa sortie n'est pas du journal stderr), proxy en amont.

### Suivi : redaction par forme de valeur (2026-10-18)

- `redact_url` masque aussi toute valeur de requête ou de fragment qui a la
  forme d'un secret, quel que soit le nom du paramètre : au moins 16 caractères
  de l'alphabet de jeton, au moins deux classes parmi minuscules, majuscules et
  chiffres, entropie de Shannon d'au moins 3,2 bits par caractère. Le seed
  `dynamic:` n'est journalisé qu'après ce masquage.
- `Sanitizer::scrub` masque `nom: valeur` / `"nom":"valeur"` pour les noms
  contenant `session`, `sid`, `auth`, `credential`, `passwd`, `pwd`, `jwt`,
  `bearer` ou `cookie`, **seulement si la valeur a cette même forme**.
  `"session_timeout":"30000000000000"` ou `session: connected-and-healthy`
  restent lisibles.
- *(Révisé le 2026-10-19, voir « Suivi : identifiants d'objets lisibles ».)*
  Un identifiant d'objet n'est pas un identifiant de connexion et n'est plus
  masqué par sa seule forme : UUID, ids numériques et ids hexadécimaux de
  32 chiffres au plus restent lisibles, comme les mots courants, horodatages
  et identifiants `snake_case` (tests positifs et négatifs dans
  `security/sanitize/url.rs`).
- Limites : un secret de moins de 16 caractères, ou d'une seule classe de
  caractères (par exemple 20 chiffres), n'est pas reconnu par la forme. Les
  segments de chemin (`/reset/<jeton>`) ne sont pas analysés. Les noms de clé
  hors de la liste ci-dessus ne sont couverts que par les motifs existants
  (`api_key`, `secret`, `token`, `password`). *(Réduit le 2026-10-18, voir
  « Suivi : trous de redaction et fuzzing ».)*

### Suivi : trous de redaction et fuzzing (2026-10-18)

Le premier run GitHub de `fuzz.yml` (39166754778) a fait échouer la cible
`redaction` : un JWT placé dans un **segment de chemin**
(`https://host.test/ht<JWT>…`) traversait `redact_url`, qui n'analysait que
l'userinfo, la requête et le fragment. L'entrée est dans
`fuzz/corpus/redaction/jwt-in-path-segment` et dans le test
`masks_a_secret_glued_to_padding`.

Code : `crates/webrev-core/src/security/sanitize.rs` et
`security/sanitize/url.rs`.

- **Segments de chemin** (et fragments sans `=`, routes SPA `#/reset/<jeton>`) :
  un segment est masqué en entier s'il contient un jeton connu (JWT, clés AWS
  `AKIA`/`ASIA`, Google `AIza`, GitHub `ghp_`…/`github_pat_`, GitLab `glpat-`,
  Slack `xox?-`, Stripe `sk_live_`/`rk_test_`…), s'il contient une fenêtre de
  16 caractères alphanumériques avec au moins 2 chiffres, 4 lettres et
  12 caractères distincts (un jeton collé à du texte ordinaire), ou s'il a la
  forme d'un secret **et** contient au moins 2 chiffres et 2 lettres. Restent
  lisibles : ids numériques, slugs, versions, dates, `getUserProfileData`,
  `app.3f2a1c.js`. *(Un UUID en segment était masqué à ce stade ; ce n'est plus
  le cas depuis le 2026-10-19, voir plus bas.)*
- **Paramètres de requête** : un nom de paramètre qui contient lui-même un
  secret, ou un paramètre nu (`?<jeton>`), masque toute la paire. Les valeurs
  passent aussi par les jetons connus et la fenêtre ci-dessus.
- **Noms de paramètre** ajoutés : `csrf`, `xsrf`, `saml`, `hmac`, `ticket` en
  sous-chaîne ; `code`, `otp`, `pin`, `mfa` en nom exact (`barcode`,
  `postcode`, `encode` restent lisibles).
- **Secrets courts sous un nom sans ambiguïté** (`Sanitizer::scrub`) :
  `password`, `passwd`, `passphrase`, `pwd`, `secret`, `api_key`,
  `access_token`, `refresh_token`, `id_token`, `auth_token`, `token`,
  `private_key`, `session_id`, `sessid`, `sid`, avec un préfixe quelconque
  (`db_password`, `X-Client-Secret`, `PHPSESSID`) : la valeur est masquée dès
  4 caractères, quelle que soit sa forme, sauf `true`, `false`, `null`, `none`,
  `undefined`. `password_policy: strict`, `passwordless`, `tokens: 42`,
  `token_count` restent lisibles.
- **Noms de clé hors liste** : le masquage par forme de valeur couvre aussi
  `csrf`, `xsrf`, `signature`, `hmac`, `saml`, `ticket`, `secret`, `token`,
  `key`, `pass` ; les jetons préfixés ci-dessus sont masqués partout dans le
  texte.
- **Vue compacte sur stdout** (`commands/output.rs`, résumé affiché après
  chaque scan) : le nom de mission, les URL des findings et les valeurs de
  surface d'attaque passent par `redact_url`.

Ce qui reste, et pourquoi le critère « preuves sensibles protégées » de
`goal.md` reste décoché :

- Le résumé compact affiche toujours le **texte clair des secrets détectés**
  (c'est l'objet du finding) ; il n'est pas masqué.
- ~~Les **rapports exportés** (fichier, ou `--report -` sur stdout, JSON/texte/
  OpenAPI) gardent seeds, endpoints et texte clair des secrets tels quels.~~
  *Corrigé le 2026-10-19 : voir « Suivi : rapports exportés » ci-dessous. Seul
  le texte clair des secrets détectés reste volontairement exporté.*
- ~~Les extraits de preuve hors sondes actives ne passent pas par `scrub`.~~
  *Corrigé à l'export le 2026-10-19.*
- Heuristiques : un secret de moins de 4 caractères sous un nom sensible, ou
  un secret court sous un nom quelconque sans motif connu, n'est pas reconnu.
  Les secrets dans le nom d'hôte ne sont pas analysés.
- TUI et proxy en amont : non audités.

### Suivi : rapports exportés (2026-10-19)

*(Le défaut a été inversé le 2026-10-19, voir « Suivi : rapports bruts par
défaut » : l'export est brut, et c'est `--redact` / `WEBREV_REPORT_REDACT=1` qui
active ce qui suit.)* Tous les formats d'export passent par
`SessionReport::redacted` (`crates/webrev-report/src/redact.rs`) avec
`--redact` : JSON, JSONL, CSV, URLs, texte, OpenAPI, DOT,
GraphML, `--report -`, la touche `r` de la TUI et le rapport de `bola`. Sont
masqués : nom de mission et seeds, URL des endpoints et des findings,
`provenance.location`, texte des findings (valeur, justification, trames
WebSocket capturées), extraits et URL des preuves de sondes. Une valeur qui est
elle-même du JSON est masquée feuille par feuille, donc reste parsable (les
`ScanCoverage` en sont) ; un JSON sans rien à masquer est conservé octet pour
octet. Un rapport masqué porte `"redacted": true`. La détection travaille sur
les findings d'origine : seule la copie exportée change, la suite de détection
n'est pas affectée. La vue compacte sur stdout garde son comportement.

Gardé volontairement en clair : `Finding.plaintext` d'un finding `Secret` (le
secret détecté est le livrable, voir la section sur les sessions) et son
empreinte `fp:…`. Un secret dans le rapport reste donc un choix d'export, pas un
accident ; si ce choix doit changer, c'est une décision de produit, pas un
correctif.

Conséquences à connaître :

- *(Corrigé le 2026-10-19.)* Cette première version masquait les UUID en
  chemin, ce qui rendait les résultats `bola` inutilisables (on ne voyait plus
  quel objet avait fuité) et faisait refuser les rapports masqués par
  `--a-report/--b-report`. Voir « Suivi : identifiants d'objets lisibles ».
- Avec `--redact`, `webrev report --format urls-exact | ffuf` reçoit `[REDACTED]` à
  la place des jetons ; les identifiants d'objets restent. Sans `--redact` (le
  défaut), `ffuf` reçoit les vraies valeurs.
- Deux endpoints qui ne diffèrent que par un segment masqué restent deux
  entrées (pas de déduplication, les compteurs du résumé restent justes).
- Convertir sans `--redact` un rapport déjà masqué ne restaure rien : il
  convertit seulement.

Ce qui reste (le critère « preuves sensibles protégées » de `goal.md` reste
donc décoché) :

- Secrets courts sous un nom de clé quelconque sans motif connu, et secrets
  dans le nom d'hôte : non reconnus.
- Les extraits de preuve hors sondes actives sont masqués à l'export, mais pas
  en mémoire ni dans la vue compacte.
- TUI (affichage à l'écran) et proxy en amont : non audités.

### Suivi : identifiants d'objets lisibles (2026-10-19)

**Problème.** Le masquage des rapports exportés (ci-dessus) cachait les UUID et
les ids opaques dans les chemins. Un résultat `bola` affiche l'objet atteint
(`/api/orders/<uuid>`) : masqué, il ne dit plus quel objet de quel compte a
fuité, donc il n'est plus exploitable. C'était une régression de la PR #21.

**Principe.** La redaction vise les *identifiants de connexion* (JWT, clés et
jetons à préfixe connu, `Authorization`, cookies, mots de passe, valeurs sous un
nom sensible, jetons de reset/invitation), pas les *identifiants d'objets*.
Code : `security/sanitize/names.rs`, `security/sanitize/url.rs`.

Ce qui n'est plus masqué par sa seule forme : un nombre, un UUID (avec ou sans
tirets, majuscules comprises), un id hexadécimal de 32 chiffres au plus (Mongo
`ObjectId`, condensat court), dans un segment de chemin, un fragment ou une
valeur de paramètre.

Ce qui reste masqué :

- tout jeton de forme connue (JWT, AWS, Google, GitHub, GitLab, Slack,
  Stripe), même dans un segment ordinaire ;
- la valeur d'un paramètre dont le **nom** désigne un identifiant de connexion,
  quelle que soit sa forme, y compris un UUID : `session_id=<uuid>`,
  `access_token`, `api_key`… La correspondance se fait **par mot** (`access`,
  `token`), plus par sous-chaîne : `author_id`, `passenger_id`, `design_id` ne
  sont plus pris pour des secrets ;
- le segment qui suit un segment annonçant un jeton (`/reset/<id>`,
  `/invite/`, `/verify/`, `/confirm/`, `/activate/`, `/magic/`, `/token/`,
  `/unsubscribe/`) s'il fait 8 caractères ou plus et contient un chiffre, même
  s'il a la forme d'un UUID ;
- les valeurs de forme secrète qui ne sont pas des identifiants : au moins
  16 caractères, deux classes de caractères, entropie d'au moins 3,2 bits. Un
  condensat de plus de 32 chiffres hexadécimaux (SHA-1, SHA-256) reste masqué ;
- sous un nom de clé sensible, `Sanitizer::scrub` masque un id comme avant
  (`"session":"<uuid>"`) ; sous un autre nom (`author_id=<uuid>`) il le garde.

**Résultat de `bola`.** Par défaut, il garde l'URL de l'objet atteint, les
quatre observations (rôles « A own object », « B reads A object »…, méthode,
URL avec l'identifiant, code de statut, empreinte SHA-256 du corps), le verdict
et la limite d'interprétation. Seuls les identifiants de connexion en sont
retirés. (Corps de réponse et comparaison A/B : voir « Preuve de `bola` » plus
bas.) `bola --a-report/--b-report` accepte maintenant un rapport masqué : les
identifiants d'objets y sont intacts. Une paire dont l'URL capturée portait un
identifiant de connexion (`?token=[REDACTED]`) ne peut pas être rejouée telle
quelle ; elle est écartée avec un message, et une capture sans `--redact` (le défaut)
la rétablit. Le marqueur `"redacted": true` est conservé.

**Compromis, à lire.** Les identifiants d'objets ne sont plus masqués, donc un
rapport peut contenir des identifiants sensibles (ids de comptes, de commandes,
de dossiers). **Un rapport exporté, même masqué, reste confidentiel.** Le
masquage retire les moyens de se connecter, pas la liste des objets touchés.
Limites de l'heuristique : un jeton de session hexadécimal de 32 chiffres au
plus sous un nom de paramètre ordinaire (`?s=<hex>`) n'est pas reconnu ; un
jeton de reset dans un chemin que rien n'annonce (`/r/<hex>`) non plus ; un
condensat de plus de 32 chiffres, comme un identifiant de commit Git dans
`/commit/<sha1>`, est masqué par excès.

### Suivi : rapports bruts par défaut (2026-10-19)

**Décision de produit.** Le masquage par défaut des rapports (PR #21 et #22)
cachait ce qu'un chasseur de bugs doit montrer pour signaler : le jeton exposé,
le `session_id` dans l'URL, le `/reset/<jeton>`, l'en-tête `Authorization`
capturé, l'extrait d'une réponse de sonde. Un rapport qui ne contient plus la
preuve ne prouve rien. L'export est donc **brut par défaut** ; `--redact`
(`WEBREV_REPORT_REDACT=1`) produit la version à partager.

Ce qui change :

- `--unredacted` / `WEBREV_REPORT_UNREDACTED` sont **supprimés** (l'option
  n'existait que depuis la PR #21 ; clap la rejette comme toute option retirée,
  ce qui évite qu'un script la croie encore utile). Remplacés par `--redact` /
  `WEBREV_REPORT_REDACT`, sur `scan`, `static`, `dynamic`, `active`, `tui`,
  `report` et `bola`. Défaut de bibliothèque : `RenderOptions::default().redact`
  vaut `false`.
- Les extraits et URL de preuve des sondes actives sont stockés **bruts** dans
  le rapport (troncature à 256 caractères conservée) ; `ProbeResponse::observation`
  ne masque plus au stockage. Le masquage se fait à l'export, avec `--redact`,
  sur l'extrait tronqué. *(Corrigé le 2026-10-20 : la coupe ne tombe plus au
  milieu d'un secret, voir « Suivi : secret coupé par la troncature de
  l'extrait de sonde » plus bas.)*
- Chaque scan qui écrit un rapport brut dans un fichier (`scan`, `static`,
  `dynamic`, `active`, `report --output`, `bola --output`) affiche une ligne
  d'avertissement sur stderr ; la TUI l'ajoute à son message de statut. Écrire
  sur stdout (`--report -`) n'ajoute rien : c'est un tube.
- `webrev bola --a-report/--b-report` accepte les deux sortes de rapports ; il
  écarte les paires dont l'URL capturée porte `[REDACTED]`, avec un message.

Ce qui **reste masqué dans tous les modes** (accident, pas livrable) : journaux
(`RUST_LOG`, plafonnement de `chromiumoxide::conn` et `tungstenite`,
`WEBREV_LOG_UNSAFE=1` pour lever), messages d'erreur, `Debug` (`HarEntry`,
`AuthConfig`, `OpsecConfig`), la ligne `dynamic: <seed>` et le résumé compact
affiché en fin de scan. `crates/webrev-cli/tests/report_redaction.rs` le vérifie
en lançant le binaire avec `RUST_LOG=debug` dans les deux modes (la ligne
`dynamic:` elle-même demande Chromium et n'est couverte que par les tests
unitaires de `redact_url`).

Modèle de menace, honnêtement : un rapport brut contient les identifiants
capturés pendant le scan, ceux de la cible et parfois les vôtres. Il se lit
comme un fichier de secrets : droits restreints, hors des dépôts de code, pas de
ticket, pas de pièce jointe sans `--redact`. `--redact` retire des moyens de se
connecter, pas la liste des objets touchés, et son heuristique a des trous (voir
les suivis précédents). Le texte en clair des secrets détectés reste exporté
dans les deux modes, car c'est l'objet du finding.

### Suivi : secret coupé par la troncature de l'extrait de sonde (2026-10-20)

**Constat.** Le trou documenté ci-dessus ("un secret coupé en deux par la
troncature ne garde que son début, que le masquage par forme ne reconnaît pas
toujours") était réel, confirmé par une reproduction avant correctif : avec un
JWT placé sous un nom de paramètre (`?v=`) qu'aucun motif nommé de `Sanitizer`
ne reconnaît (`session`, `token`, `key`… absents), seule la structure à trois
segments du JWT pouvait le faire reconnaître comme secret. Pour un `pad_len`
qui plaçait la coupe à 256 caractères (`ProbeResponse::observation`,
`active/transport.rs`) au milieu de ce JWT, 65 caractères de son en-tête et de
ses revendications (`"role":"admin"`, `"sub":"1234567890"`) restaient en clair
après `Sanitizer::scrub` : la forme à trois segments était rompue, et aucun
autre motif ne s'appliquait. Même mécanisme, même limite, pour l'extrait de
preuve `bola` (`active/bola_diff.rs::body_excerpt`, coupe à 4 KiO).

**Correctif.** `ProbeResponse::observation` et `body_excerpt` ne coupent plus
au milieu d'une suite de caractères de forme jeton (alphanumérique ASCII plus
`-_.~+/=%`, l'alphabet de tout secret reconnu par `Sanitizer`) : quand la coupe
naïve tomberait à l'intérieur d'une telle suite longue d'au moins 12 caractères
(en dessous, `Sanitizer` ne la reconnaîtrait pas non plus, coupée ou non) et
d'au plus 200 caractères pour l'extrait de sonde ou 256 pour `body_excerpt`,
elle recule au début de la suite : un secret est désormais toujours gardé en
entier ou absent, jamais tronqué en deux. Au-delà de cette borne — un extrait
dominé par un seul bloc opaque (image en base64, fichier minifié…), plus
probablement une donnée qu'un secret — la coupe naïve d'origine s'applique,
comme avant.

**Tests.** `active/transport.rs` :
`a_token_straddling_the_excerpt_limit_is_dropped_whole_not_split` (balaie les
longueurs de remplissage faisant tomber la coupe dans le JWT, vérifie qu'aucun
fragment de 12 caractères ou plus n'y survit après `scrub`) et
`a_short_ordinary_run_at_the_boundary_is_not_retreated` (un mot ordinaire de
sous la barre des 12 caractères ne déclenche aucun recul). Mêmes deux tests
dans `active/bola_diff.rs`, à l'échelle de `BODY_LIMIT`. Les tests existants
(coupe UTF-8 sûre, longue suite factice coupée au plafond) restent inchangés.

**Compromis.** Heuristique de forme, pas de détection de secrets : pas de
dépendance nouvelle vers les motifs de `webrev-extract`, juste l'alphabet déjà
implicite dans `Sanitizer` (`webrev-core`, déjà une dépendance du pipeline). En
dessous de 12 caractères inclus, un fragment trop court pour que `Sanitizer`
l'aurait reconnu de toute façon peut rester coupé — sans perte réelle. Une
suite ordinaire de 12 à 200/256 caractères pile à la frontière de coupe (un
identifiant inhabituellement long, par exemple) est elle aussi reculée par
excès de prudence, au prix de quelques caractères d'extrait.

### Suivi : test d'egress instable (2026-10-18)

`egress_proxy::tests::upstream_is_never_contacted_for_refused_or_unresolvable_destinations`
a échoué une fois en CI (attente de 3 s expirée dans `exchange`). **Non
reproduit en local.** Cause probable, déduite du code et non mesurée : le proxy
résolvait `hidden.invalid` avec le résolveur du système, dont la latence est
hors de notre contrôle, alors que le client de test n'attend que 3 s et que le
proxy en accorde 5 (`HANDSHAKE_TIMEOUT`). Le test dépendait donc du DNS de la
machine. Correctif : `destination` répond localement aux noms `.invalid`
(RFC 6761, ils ne se résolvent jamais) avec `NotFound`, donc 502, sans requête
DNS. Le test vérifie maintenant que la réponse arrive en moins d'une seconde,
et `is_invalid_name` a son propre test. Effet de bord voulu : le nom n'est plus
envoyé au résolveur.

## Preuve de `bola` : corps de réponse et comparaison A/B (2026-10-19)

Une observation de `bola` ne stockait qu'une empreinte `sha256=` du corps. Elle
prouvait que les deux comptes avaient reçu la même réponse, pas ce que la
réponse contenait, alors que le contenu de l'objet de l'autre compte est la
preuve d'un IDOR.

- Chaque observation garde maintenant `body` : les 4 premiers KiO de la réponse
  (`body_truncated` indique une troncature, `body_bytes` la taille totale). La
  coupe est UTF-8 sûre : un caractère multi-octet coupé par la limite est
  retiré, pas déformé. L'empreinte est conservée.
- `diff` (dans l'évidence) indique le sens de la fuite et, pour deux corps JSON,
  les champs qui distinguent l'objet de A de celui de B (valeurs différentes,
  champs présents d'un seul côté, nombre de champs identiques), 20 lignes au
  plus, valeurs coupées à 80 caractères.
- Brut par défaut, comme les autres preuves. `--redact` passe `body` et `diff`
  par la même redaction que les extraits (`Sanitizer::scrub`) : un identifiant
  d'objet reste lisible, une clé ou un jeton stocké dans l'objet est masqué.
- La détection ne change pas : le verdict repose toujours sur l'égalité exacte
  des octets de la réponse croisée et de celle du propriétaire.
- Les anciens rapports sans ces champs se chargent (`#[serde(default)]`), donc
  `bola --a-report/--b-report` fonctionne avec eux.

Compromis : un résultat `bola` brut contient désormais des données de l'autre
compte de test (e-mail, adresse, clés présentes dans l'objet). Il est
confidentiel ; `--redact` le rend partageable au prix des valeurs sensibles.
Limites : la comparaison porte sur le corps entier des deux réponses « own »,
mais seuls 4 KiO de chaque corps sont stockés, donc `body` peut être plus court
que ce qui a été comparé ; elle ne s'applique qu'aux corps JSON valides (les
autres n'ont que la ligne de sens) ; 2000 champs au plus sont comparés.
