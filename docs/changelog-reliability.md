# Changelog — reliability work

## 2026-10-19

- Added `--format urls-exact` and `--format requests` to `report` and `scan`.
  The stored endpoint rows are route templates (`/users/{id}`, no query
  string), so `urls` cannot feed a fuzzer or a replay. The new formats rebuild
  the concrete URLs from the `Endpoint` findings, resolved against their
  document as the store stage does, with real path ids and query strings.
  Template placeholders and fragments are skipped, output is de-duplicated and
  sorted, and `--scope` applies. `requests` prints `METHOD URL`, with
  `UNKNOWN` when the extractor could not tell the verb. `--redact` masks each
  URL with `redact_url`, which keeps object ids and hides credentials. `urls`
  and the other formats are unchanged. `EndpointResolver` moved from
  `webrev-pipeline` to `webrev-core` so the report crate can use it.

## 2026-10-15

- Added `FindingStatus`, detector identifiers, evidence score, explanation,
  merged provenance and additional evidence. Secret severity no longer rises
  solely because the extractor confidence is high.
- Added report counts for status and rendered detector, justification, active
  observations and per-check coverage outcomes.
- Store merges duplicate findings and keeps evidence; endpoint identity
  retains method.
- SSRF probing no longer treats status/body-size changes or reflection as a
  server-side fetch. Redirect-shaped parameters are left to open-redirect
  testing; DNS error output remains a suspicious lead only.
- JavaScript endpoint strings without a recognized network call are labeled
  as static URL candidates. Arbitrary object keys and string examples no
  longer become HTTP parameters.
- Secret scanning filters HTML identity/style attributes. DOM analysis records
  source, recognized transformation chain and sink; direct `DOMPurify.sanitize`
  flows are excluded from XSS leads.
- Crawl redirects and Chromium requests are gated by mission scope. Crawl waves
  respect the remaining page budget. Active coverage distinguishes executed,
  negative, not executed, not selected, refused, error and inconclusive counts.
- Added a reproducible static detector benchmark and a local out-of-scope
  redirect test.
- Active probes now reserve request-budget slots atomically before the delay
  await, preventing concurrent targets from overshooting `max_requests`. A
  local integration test exercises 30 targets with a budget of 3.
- Direct HTTP clients pin the first system DNS answer set per hostname for the
  lifetime of the client. Redirect destinations use the same resolver after
  the URL scope gate. Local tests verify stable `localhost` answers and a real
  HTTP connection through the active client.
- Added `--scope-file` for explicit JSON `include`/`exclude` hostname, IP, and
  CIDR lists. File and CLI entries combine, exclusions win, malformed entries are rejected,
  and an empty explicit allow list never falls back to seed hosts.
- Scope matching and direct DNS egress now support IPv4/IPv6 CIDR allow and
  deny rules. The resolver filters addresses before connecting; Chromium fails
  closed for hostname URLs when CIDR exclusions require an IP check it cannot
  perform before navigation.
- DNS answers rejected by the direct-client scope filter are now counted as
  scope refusals, are not retried, and cannot produce a negative test result.
  Text coverage output labels scope refusals separately from HTTP refusals.
- Replaced the browser smoke test's external example.com target with a local
  loopback fixture. It verifies an in-scope script and fetch and uses a second
  loopback address as a canary for blocked out-of-scope subresource traffic.
- Added a benchmark-source review and methodology. It selects an independently
  reviewed JS/HTML corpus for detector accuracy, OWASP VulnerableApp for a
  mapped local DAST pass, and excludes XBOW from primary scoring because its
  maintainers describe it as saturated and task/CTF-oriented.
- Ran an exploratory Webrev pass against OWASP VulnerableApp source commit
  `8003daf8e13044802fdeb4b665f0c9cc6d09096b` in an internal Docker network.
  The entrypoint-only static/browser run produced 60 findings, including 17
  browser-observed endpoints, and no vulnerability/secret candidates. It did
  not execute active vulnerability probes or map ground-truth scenarios, so it
  yields no precision/recall score. Compose containers, network, and volumes
  were removed after the run.
- Audited the JsVul artifact link: Zenodo record 18195839 is live and declares
  CC-BY-4.0; stale record 18195838 returns 410. Its test split has 1,726
  records (203 positive and 1,523 negative by supplied label), but heuristic
  labels and mixed client/server projects require case-by-case review. No
  external samples were copied into the repository.
- Completed source, diff, and license review for all 28 JsVul CWE-79 test pairs:
  13 DOM/client candidates, 3 ambiguous, 4 sanitizer/context, 5 server/non-DOM,
  and 3 doubtful/incomplete. Six pairs have custom or unidentified terms and
  remain unsuitable for redistribution. Webrev was not scored on this set.
- Executed `cargo test -p webrev-extract --test reliability_benchmark
  -- --nocapture`: all five small detector checks reported TP=2, FP=0, FN=0,
  TN=2. The fixtures are synthetic and development-only; these values are
  explicitly not treated as independent precision/recall measurements.
- Added `scripts/vulnerableapp_adapter.py` for the narrow, evidence-backed
  Webrev open-redirect to VulnerableApp type mapping. It strips host/query data,
  deduplicates identical cases, records unmapped findings in a sidecar, and
  refuses reports without executed open-redirect coverage. Seven Python unit
  tests pass. The previous exploratory report was correctly rejected because
  it contains no active open-redirect coverage.
- Ran a pinned OWASP VulnerableApp open-redirect slice (source commit
  `8003daf8e13044802fdeb4b665f0c9cc6d09096b`, image digests and report archived
  under `benchmarks/vulnerableapp/2026-10-16/open-redirect/`). Webrev used 146
  active requests of a 160-request budget, concurrency 1, 50 ms delay, and an
  internal Docker target. It attempted 12 routes and emitted 3 evidence-backed
  redirect findings. The category slice measured TP=3, FN=6, FP=0, TN=1, with
  one refused secure case excluded from TN: precision 100% (3/3), recall 33.3%
  (3/9), FPR 0% (0/1), FNR 66.7% (6/9). VulnerableApp's full comparator scored
  3/168 detected, 165 missed, 0 unmatched (1.7857% coverage); 159 missed rows
  are out-of-slice types, so that aggregate is not detector-only recall. This
  was the initial baseline; a same-case paired run is recorded immediately
  below.

- Refined open-redirect validation to try bounded absolute, protocol-relative,
  and authority-prefix destinations, and resolve each returned `Location`
  against the probed URL without following it. Added wire tests for levels 2/6
  patterns and a 302 reflected-marker negative control. Expanded the benchmark
  adapter to validate the resolved randomized `.invalid` host and path. In the
  paired VulnerableApp run (same 12 routes and 160-request cap), the check
  detected levels 1, 2, 6, 9 and 10: TP=5, FN=4, FP=0, TN=1, one secure HTTP
  refusal; precision 100% (5/5), recall 55.6%, FPR 0% (0/1), FNR 44.4%. The run
  used all 160 allowed requests versus 146 in baseline, while all 12 redirect
  checks executed. Levels 3, 4, 5 and 7 remain misses without an externally
  resolving `Location` proof. Original artifacts are kept in the archive's
  `baseline/` directory; full comparator score was 5/168, with 159 misses from
  untested types.
- Followed the four remaining open-redirect lab cases with offline Chromium
  URL-resolution checks. Added bounded tab-prefixed protocol-relative and
  backslash-separator probes; both require the exact randomized external host
  and nonce path after Rust URL resolution. Levels 3, 4 and 5 now have 3xx
  `Location` proofs; level 7's app-prefixed backslash resolves to the app host
  and remains a miss. The pinned 12-route batch reached 160 requests and ran
  11 open-redirect checks before the shared budget stopped it. It detected
  eight of nine labeled vulnerable cases (level 7 missed); level 11 was
  refused. A separate one-route active run tested secure level 12 (25 requests,
  negative), yielding TP=8, FN=1, FP=0, TN=1 and one refusal. The slice metrics
  are precision 100% (8/8), recall 88.9%, FPR 0% (0/1), FNR 11.1%; the full
  comparator scored 8/168 with 159 out-of-slice misses. Offline Chromium 154
  normalization and the supplemental control report are archived with the
  updated comparator artifacts.

Validation after this change: `CHROME=/usr/bin/chromium cargo test -p
webrev-browser dynamic_run_smoke -- --ignored --nocapture` passed against
Chromium 154.0.8037.97 and a loopback-only fixture. The standard workspace test
suite passed (264 passed, 2 ignored); formatting and diff checks passed. Strict
workspace Clippy passed; two findings in the fingerprint and graph modules
were corrected as part of validation.

### Compatibility

Older JSON reports deserialize using field defaults. Their status defaults to
`observed`; no evidence state can be inferred from old data. New Rust struct
fields on `Finding` and `ResponseObservation` require downstream struct-literal
initializers to supply the added fields or use constructors.

### Limitations

The benchmark corpus is synthetic and small; see
`docs/benchmark-methodology.md` for the independent validation plan. Dynamic
Chromium request interception has now been exercised against a loopback
fixture, but this does not cover every browser redirect or auth scenario.
Direct HTTP clients pin DNS responses and
enforce configured CIDR rules, but a proxy may resolve target names remotely;
its egress policy must enforce destination ranges. DOM taint remains
single-file and does not model custom sanitizers or interprocedural dataflow.
CVSS values are not calculated.

### Étape 5 — corpus et performance (2026-10-16)

#### Collecte externe complémentaire (2026-10-17)

- Acquis 30 cas locaux de l'artefact SWIPE MIT, totalisant 32 fichiers HTML/JS
  sélectionnés par requêtes byte-range; hashes par fichier et provenance sont
  conservés. Aucun des 44 480 sites mentionnés dans l'étude n'a été scanné.
- Exécuté `cargo test -p webrev-extract --test swipe_domxss_external
  -- --nocapture` : TP=13, FP=1, FN=3, TN=12, 1 inconclusif. Taux sur la
  sélection revue manuellement : précision 92,86 %, rappel 81,25 %, FPR
  7,69 %, FNR 18,75 %. Le FP passe par `search()` avant `document.write`;
  les misses couvrent flux inter-fichiers, sink `onclick` et alias de champs.
  Ce n'est pas un score indépendant ou représentatif.
- Ajouté des snapshots épinglés de Google Firing Range (Apache-2.0) et
  Security Defect Corpus (MIT), avec SHA-256. Les dépendances n'ont pas été
  installées ni exécutées; ces sources restent candidates non scorées.
- Documenté le tri SecBench.js, X.js et Snyk VulnBench, leurs limites de
  périmètre/licence et les motifs d'exclusion dans
  `benchmarks/external-candidates/README.md`.
- L'étape 5 reste non validée : le corpus SWIPE est petit et ses labels sont
  une adjudication mainteneur, les archives candidates ne sont pas encore
  scorées, le benchmark end-to-end dépasse le seuil p95 et la CI distante
  n'a pas été déclenchée.

#### Corrections motivées par les cas SWIPE (2026-10-17)

- Affiné la taint DOM XSS : les méthodes de chaîne qui ne retournent qu'un
  nombre ou booléen (`search`, `indexOf`, `charCodeAt`, `includes`, etc.) ne
  transmettent plus une taint de chaîne vers un sink HTML/code.
- Ajouté les sinks événementiels `setAttribute` pour des attributs `on*`
  reconnus et les affectations de propriétés comme `element.onclick`.
- Rejoué les 30 cas SWIPE : TP/FP/FN/TN passent de 13/1/3/12 à 14/0/2/13;
  le cas inconclusif reste exclu. Précision 100 %, rappel 87,5 %, FPR 0 %,
  FNR 12,5 % sur ce corpus pilote. Les deux misses restants sont le flux
  inter-fichier et l'alias d'objet.
- Tests unitaires ajoutés pour résultats non chaîne, sinks événementiels et
  attributs `setAttribute` non exécutables. La validation complète suit dans
  les résultats de tests de cette étape.

- Ajouté `benchmarks/static-corpus/v1/` et son runner data-driven : 50 cas
  annotés sur 40 snippets, avec splits dev/validation par familles. Mesures
  réelles : AST endpoints, paramètres HTTP, secrets et DOM source→sink sont à
  TP=4/FP=0/FN=0/TN=4 chacun; regex endpoints est à TP=3/FP=1/FN=1/TN=3.
  Les deux mismatches regex restent visibles dans les sorties. Le corpus est
  petit, mainteneur-authored et non indépendant; il ne ferme donc pas le gate
  de validité externe.
- Ajouté `benchmarks/performance/2026-10-16/` avec 40 mesures brutes : 20 runs
  par révision, p95 +13,57%, RSS max +0,76%, 40/40 succès et 265 findings par
  run. Seuils atteints sur la fixture loopback microbenchmark uniquement.
- La CI exécute désormais les corpus Rust synthétique et annoté, les tests
  Python et la vérification des archives DAST. Le workflow GitHub n'a pas été
  déclenché dans cette session; ses composants ont été testés localement.
- Les contrôles locaux finaux ont réussi : formatage, diff-check, contrôle de
  taille (avec exception explicitement documentée pour le module DOM AST),
  `cargo test --workspace`, Clippy strict all-features, 12 tests Python et
  SHA-256 des deux archives VulnerableApp. Les tests de navigateur dépendants
  de Chromium restent ignorés dans la suite standard.
- Décision : l'étape 5 reste EN COURS. Il manque un corpus indépendant de taille
  suffisante, des mesures sur workload représentatif et le run effectif du
  workflow CI distant. L'étape 6 n'est pas engagée tant que ce gate n'est pas
  validé.
- Audited an additional external MIT-licensed corpus candidate at pinned commit
  `84dd9c822eea735448353a01afe5e7e0df6549c4`. Its explicit labels and paired
  fixtures are useful for secure-code/reachability testing, but its JavaScript
  cases are mostly server-side or outside Webrev's claims. It was not copied
  or counted as validation evidence.

- Comparaison statique baseline/current sur les mêmes 50 cas mainteneur-authored:
  AST endpoints, paramètres HTTP et secrets passent chacun de
  TP=4/FP=2/FN=0/TN=2 à TP=4/FP=0/FN=0/TN=4; DOM reste à
  TP=4/FP=0/FN=0/TN=4. Regex endpoints passe de 4/2/0/2 à 3/1/1/3 : un FP
  en moins mais un FN nouveau. Ces deltas ne démontrent pas la généralisation.
- Ajouté un probe séparé OWASP Juice Shop v19.0.0 épinglé à son commit MIT.
  Quatre positifs documentés exposent quatre misses : Angular HttpClient
  endpoint/paramètre et flux DOM XSS réparti entre TypeScript/template. Aucun
  cas négatif fiable n'est disponible; précision/FPR ne sont pas mesurables.
- Le profil SPA-like élargi échoue au seuil p95 : +511,72% (29,987 →
  183,435 ms), RSS +12,80%, 40/40 scans réussis et cardinalité stable par
  révision. L'archive est conservée; une optimisation du préfiltre DOM AST est
  en validation.
- CI locale auditée: formatage, corpus Rust, probe Juice Shop, Python, hashes,
  build, workspace tests et Clippy all-features sont couverts. Le workflow
  GitHub n'a pas été exécuté; Python local est 3.14, CI épingle 3.12.
  L'étape 5 reste non validée.

### Mise à jour de validation (2026-10-17)

- Corrigé le détecteur regex endpoints : les appels WebSocket explicites sont
  classés comme endpoints et le contenu des commentaires est masqué avant
  extraction. Sur le corpus statique apparié, la regex passe de TP=4/FP=2/FN=0/TN=2
  sur la baseline à TP=4/FP=0/FN=0/TN=4 sur le candidat. Le corpus actuel donne
  ces mêmes résultats dans ses splits dev et validation.
- Ajouté le support générique des appels Angular `HttpClient` avec routes
  statiques ou suffixes statiques de templates interpolés, ainsi que les
  paramètres HTTP contenus dans ces URLs. Le probe Juice Shop passe de 0/4 à
  3/4 positifs détectés; le flux DOM XSS réparti entre TypeScript et template
  reste manqué.
- Audité et épinglé le corpus académique Apache-2.0 DOM XSS multi-fichiers
  (342 variantes positives, 69 paires source/sink, cinq découpages ES-module).
  Sur les 122 variantes aux catégories source/sink modélisées (25 paires),
  l’extraction indépendante des modules trouve 0 correspondance exacte
  inter-fichiers. Ce chiffre mesure la couverture de propagation multi-fichier,
  pas le rappel intra-fichier. Les 12 signaux DOM bruts ne correspondent pas
  aux labels des cas. Aucun négatif n'est fourni : précision/FPR restent
  non mesurables.
- Indexé la déduplication de findings et d'endpoints dans le stockage mémoire.
  Les vecteurs et leur ordre restent canoniques; les merges et le nettoyage de
  session sont couverts par les tests du crate.
- Rejoué le benchmark SPA 120 routes avec ordre apparié aléatoire : p95
  32,352 → 39,817 ms (+23,07%), RSS max 22 976 → 22 976 KiB (+0,00%),
  574 → 760 findings et 40/40 runs réussis. Le seuil RSS passe; le seuil p95
  de 20% échoue. Cargo a réécrit le lockfile baseline pour refléter ses
  manifestes de workspace; son hash post-build égale celui de `HEAD`. Le diff
  de lockfile ne contient que des arêtes de dépendances locales, sans changement
  de version ou checksum des paquets externes. La dérive de versions externes
  n'explique donc pas l'écart observé. Le code et les arêtes locales changent
  ensemble, donc cette mesure n'isole pas le coût de l'index mémoire. L'archive
  inclut le harness, les résultats bruts, les hashes et les sources. Un suivi
  source-only doit utiliser les manifestes et le lock candidat pour les deux
  builds et `--locked`.
- Benchmark source-only complémentaire : anciens fichiers Rust compilés avec
  les `Cargo.toml` et `Cargo.lock` candidats identiques, `cargo build --locked`
  sur les deux arbres. Les quatre hashes lock concordent; p95 32,142 → 37,859
  ms (+17,79%), RSS max 24 392 → 24 392 KiB (+0,00%), 40/40 scans réussis.
  Ce profil respecte les seuils source-only; le profil end-to-end reste à
  +23,07% p95 et dépasse donc encore le seuil global.
- Tests exécutés après changements : corpus statique et probe Juice Shop
  réussis comme tests diagnostiques; stockage 5/5; `cargo test --workspace`
  et Clippy all-targets/all-features passent. Les 12 tests Python, le
  formatage, le contrôle de taille et les checksums locaux passent. Les tests
  Python et le contrôle de taille ont aussi été exécutés sous Python 3.12.14
  via `uv`. GitHub Actions n'a pas été exécuté à distance.
- Revue protocole : le corpus DOM XSS mesure la couverture de propagation
  multi-fichier (0/122 correspondances exactes), pas le rappel intra-fichier;
  le matcher exige maintenant le sink annoté `innerHTML` et un test rejette
  `outerHTML`.
- Décision : étape 5 non validée faute d'un corpus externe représentatif avec
  positifs/négatifs revus indépendamment, d'exécution distante de GitHub Actions
  et parce que le benchmark p95 dépasse le seuil. Les gates locaux Python 3.12
  passent. L'étape 6 reste derrière ce gate.

### Reprise parallèle : modules DOM et coût des endpoints (2026-10-17)

- Ajout de `DomSinkExtractor::extract_modules`, branché à la fin de l'étape
  statique si le registre contient `dom-sinks`. Chaque fichier garde son AST;
  seules les relations d'import ES explicites entre modules déjà collectés
  transportent les valeurs exportées. Aucun téléchargement supplémentaire.
  Les candidats restent `Suspicious`, confiance `Medium`, avec provenance
  source et sink; aucune preuve d'exploitation n'est fabriquée.
- Travail borné : 128 modules, 512 KiB par module, 8 MiB retenus et huit passes.
  Le chemin sans imports évite l'analyse batch. Les exports de valeurs sont
  limités à l'initialisation rectiligne; fonctions exportées, imports namespace,
  réexports `from`, scripts classiques, inline HTML et propagation
  interprocédurale restent hors couverture inter-fichiers.
- Le probe externe multi-fichiers passe de 0 à **26/122** correspondances
  exactes, soit 13/25 paires : type01 13/25, type02 13/22 et types03–05 0/25
  chacun. Ce corpus positif et corrélé ne mesure toujours ni précision ni FPR.
  Les contrôles négatifs ajoutés couvrent notamment sanitizer, écrasement,
  résultat numérique, masquage de paramètres/catch, snapshots `export default`,
  blocs lexicaux, doublons URL, imports absents, cycles et sessions distinctes.
- La résolution des endpoints réutilise les seeds parsées et une seule base
  source en cache. La normalisation UUID n'alloue plus un vecteur par segment.
  Les règles de résolution HTML/JS et les seeds invalides restent couvertes.
- SWIPE vérifie désormais les résultats par cas, les labels et l'inventaire.
  Le companion `hero.js` présent dans les sources épinglées est ajouté au
  manifeste : les 32 fichiers sont exercés. Résultat inchangé : TP14, FP0, FN2,
  TN13, un inconclusif; les scripts classiques restent extraits séparément.
  La CI inclut ce probe et ses checksums.
- Validation locale exécutée : `cargo test --workspace` **299 réussis, aucun
  échec, deux ignorés**; `cargo clippy --workspace --all-targets --all-features
  -- -D warnings`, `cargo fmt --all -- --check`, contrôle de taille, 12 tests
  Python et checksums des trois corpus externes réussis. Après la dernière
  correction de style Clippy, les trois tests d'intégration pipeline passent.
  Les commandes Cargo utilisent `CARGO_TARGET_DIR=/home/na/.cache/webrev-validation-target`,
  `CARGO_PROFILE_DEV_DEBUG=0` et `CARGO_PROFILE_TEST_DEBUG=0`.
- La première tentative de tests sur le target NTFS a échoué par SIGSEGV avant
  les assertions; le binaire généré renvoyait ensuite `EINVAL` à `stat`/`file`.
  Le target neuf sur Btrfs a permis l'exécution réussie. Aucun contournement
  fonctionnel n'a été ajouté pour cet incident d'artefact.
- Les résultats précédents de performance restent historiques; le nouveau
  profil apparié de la version intégrée est archivé séparément sous
  `benchmarks/performance/2026-10-17/spa-site-optimized/`.
- Le profil intégré final passe les seuils : 30 paires, p95 38,081 → 45,178 ms
  (**+18,64%**, limite 20%), RSS max 20 748 → 22 136 KiB (**+6,69%**, limite
  25%), 574 → 760 findings, **60/60 scans réussis**. Le premier run natif valide
  dépassait encore p95 (+21,43%); il est conservé sous
  `spa-site-native-pre-regex/`. La nouvelle passe suit un changement réel :
  retrait de deux préfixes Unicode optionnels inutiles dans les regex
  HttpClient. Deux tests comparent les captures anciennes et nouvelles;
  le microbenchmark séparé mesure 0,590 ms économisée en compilation cumulée,
  sans attribuer à lui seul le delta de temps complet entre campagnes.
- Le harness Python pouvait contaminer `ru_maxrss` par sa mémoire héritée,
  même avec `posix_spawn`. Un petit lanceur C mesure maintenant le scanner
  depuis un parent natif; un probe contrôlé avec Python chargé de 64 MiB
  documente la correction. La commande canonique et l'archive utilisent le
  même lanceur, compilé avec `-Wall -Wextra -Werror`. Les anciens chiffres RSS
  ne sont pas des mesures isolées fiables du scanner. Le run final et celui
  précédant le changement regex utilisent tous deux la méthode native.
- Les 426 paquets externes gardent versions, sources et checksums identiques
  entre baseline et candidat; les arêtes locales du lock diffèrent. Les
  archives contiennent sources figées, générateur de fixture, lanceur, résultats
  bruts et hashes. La machine partagée et la fixture synthétique limitent
  l'interprétation. L'étape 5 reste ouverte pour le corpus représentatif avec
  négatifs et revue indépendante, et pour le workflow GitHub distant.

## Proxy d'egress du navigateur (2026-10-17)

- Chromium contourne l'interception Fetch pour les handshakes WebSocket : un
  `ws://` vers une IP loopback hors scope atteignait le serveur. Un proxy local
  (`egress_proxy.rs`) vérifie maintenant le scope et la résolution DNS avant
  toute connexion, pour HTTP, les upgrades WebSocket et CONNECT.
- Défaut corrigé : chromiumoxide préfixe lui-même `--`; les flags passés sous
  forme `"--proxy-server=..."` devenaient `----proxy-server=...` et étaient
  ignorés (idem `--lang` et `--disable-blink-features`). Ils passent en
  `(clé, valeur)`, et `--proxy-bypass-list=<-loopback>` retire le contournement
  implicite du loopback.
- Preuve : `websocket_scope_blocks_egress` (Chromium 154) ne reçoit plus
  `UPGRADE /ws-out-of-scope`; le refus `CONNECT 127.0.0.2:<port>` figure dans
  `refused_requests` (un CONNECT ne porte pas le chemin). Le trafic de fond de
  Chromium (Google) est aussi refusé et compté, borné par la troncature
  existante. 21/21 tests navigateur (dont les 5 `ignored`), 322 tests du
  workspace, Clippy strict et `git diff --check` OK.

## DOM XSS entre fichiers : branches, boucles, helpers (2026-10-17)

- Couverture exacte du corpus multi-fichiers épinglé (122 cas modélisés) :
  63 → **105/122**. Le plancher de non-régression du test passe à 105.
- Changements, tous dans l'analyse de résumés d'export (`domsinks/modules`) :
  `document.location.*` est replié sur `location.*`; un `if` de niveau module
  ou dans une fonction exportée n'invalide plus le résumé (fusion « peut-être
  contaminé » des deux branches, `return` précoce inclus); les boucles `for` /
  `while` sont parcourues une fois; les helpers de même module (déclarés au
  niveau module ou dans la fonction, un seul niveau) propagent leur retour;
  `obj.prop = v` n'est plus traité comme une réaffectation de `obj`
  (`window.name = …`). Une condition littérale (`if (false)`) écarte la branche
  morte. `let`/`const` dans une branche, `for…of`, `try`, `switch` retirent le
  résumé plutôt que de deviner.
- Les 17 cas restants ne sont pas de vrais flux inter-fichiers dans ce corpus :
  15 cas `event.data` (l'export référence une variable locale à la fonction ou
  la valeur retournée par le handler n'est jamais consommée) et 2 cas sans
  `main.js` qui lie source et sink (`type05/03-09`, `type05/11-15`).
- Limites : le corpus multi-fichiers est 100 % positif, donc il mesure le
  rappel et ne dit rien des faux positifs. Le seul contrôle de précision est
  SWIPE (TP=14 FP=0 FN=2 TN=13, inchangé) et la suite statique, qui n'ont pas
  de négatifs multi-fichiers. La fusion « peut-être contaminé » est volontairement
  sur-approximante (un écrasement conditionnel par une valeur sûre ne retire
  pas la contamination); les résultats restent `Suspicious`, jamais `Confirmed`.
  Corpus de taille réduite, variantes corrélées, revue non indépendante.

## Négatifs multi-fichiers DOM XSS (2026-10-17)

- Aucun dataset public multi-fichiers avec négatifs n'a été trouvé : le corpus
  kanaoka est 100 % positif et les templates DOM de Firing Range sont tous
  vulnérables par construction (son cas « sanitize » échappe le HTML avant un
  `eval`, ce qui ne protège pas).
- Ajout de `benchmarks/external-domxss/multifile-negatives-v1/` : 20 cas
  négatifs **écrits par les mainteneurs**, calqués sur les motifs négatifs de
  SWIPE (branche seule, résultat numérique, sortie constante, sanitizer) et sur
  les formes que les résumés d'export traitent (branches, code mort, boucles,
  helpers, paramètre ignoré, import masqué, `let` de branche).
- Résultat : 0 faux positif sur 20 (`domxss_multifile_negatives`). Contrôle de
  sensibilité : en rendant 7 cas vulnérables, le test en signale 6; le 7e
  (`show(payload)` via une fonction locale à paramètre) n'est pas suivi, c'est
  un manque de rappel connu, pas un faux positif.
- Limites : jeu non indépendant, petit, écrit par l'auteur des correctifs. Un
  zéro signifie que ces formes sont gérées, pas que la précision est mesurée.

## Secrets : comparaison d'identifiants codés en dur (2026-10-17)

- Le motif générique `password|secret|token|api_key|access_key = "valeur"`
  accepte maintenant aussi `:`, `==`, `===`, `!=`, `!==` avant le littéral
  (16 caractères ou plus, mêmes filtres de placeholder et de contexte). Cela
  couvre les portes dérobées `req.body.password === 'debug-open-sesame'`.
- Corpus SDC épinglé : TP=1 → 3, FP=0, FN=4 → 2, TN=3. Les deux manques
  restants (`NODE-BACKDOOR-OPKEY-001`, reachable et unreachable) comparent
  `req.headers[...]` à `OPERATOR_KEY = 'operator-maintenance-key'` : le nom ne
  contient aucun mot-clé de credential du motif. Ajouter `key` seul n'a pas
  été fait : `event.key`, `CACHE_KEY` et d'autres constantes d'UI deviendraient
  des faux positifs, pour gagner deux cas d'un même jeu de fixtures.
- Contrôles : 0 correspondance de la nouvelle forme sur 3 000 fichiers JS
  locaux (`/usr/lib/chromium`, `/usr/lib/node_modules`, dépôts locaux), suite
  statique et Juice Shop inchangées, tests négatifs unitaires ajoutés
  (variables, littéraux vides ou courts, `event.key`, placeholder).
- Limites : 8 cas, 3 familles, jouets écrits par les auteurs du corpus et
  remappés par les mainteneurs; ces chiffres ne mesurent pas la précision
  générale. Le détecteur reste de la présence statique, sans validation active.

## Proxy de sortie du navigateur : audit derrière un proxy amont (2026-10-17)

- Constat sur `egress_proxy.rs` : avec `opsec.egress.proxy`, Webrev résout le
  nom **localement**, filtre chaque adresse par `Scope::allows_resolved_ip`, puis
  envoie à l'amont `CONNECT <ip>:<port>` (jamais le nom). L'amont ne résout donc
  rien : la destination finale est l'IP validée par Webrev (test
  `upstream_connect_receives_ip_never_the_hostname`). Un nom que seul l'amont
  pourrait résoudre échoue en 502 sans contacter l'amont (test
  `upstream_is_never_contacted_for_refused_or_unresolvable_destinations`).
- Bogue corrigé : un hôte avec point final (`localhost.`) n'était pas reconnu par
  une exclusion de nom (`localhost`) quand le scope contient aussi un CIDR
  (le nom passait alors à la validation DNS puis était autorisé). Les hôtes sont
  maintenant canonisés avant le scope : point final retiré, littéral IPv6
  mappé IPv4 (`[::ffff:127.0.0.1]`) réécrit en IPv4, et adresses DNS
  canonisées. Les formes décimale, hexadécimale, octale et courte d'IPv4 sont
  déjà normalisées par le parseur d'URL.
- Tests ajoutés (écouteurs loopback uniquement) : formes d'IP exclues, casse et
  point final, userinfo et désaccord `Host`/URI/CONNECT, CONNECT IPv6, redirection
  non suivie (le saut suivant repasse par le scope), amont non contacté pour une
  destination refusée, refus amont traduit en 502.
- Résultat : `cargo test -p webrev-browser` 27 réussis, 6 ignorés; clippy
  `-D warnings` propre. Avec `--include-ignored` (Chromium), 32 réussis et 1
  échec hors périmètre du proxy : `dynamic::tests::explore_never_clicks_destructive_controls_and_records_refusals`
  (exploration dynamique), non investigué ici.
- Limites, non résolues : (1) la résolution DNS locale n'est pas faite via
  l'amont : elle fuit le nom vers le résolveur de la machine (opsec) et
  peut différer de la vue réseau de l'amont (DNS à horizon partagé, géo-DNS);
  le contrôle porte sur l'IP locale, pas sur ce que le nom désigne côté amont.
  (2) Aucune restriction de port. (3) L'amont lui-même n'est pas soumis au
  scope; il reçoit l'IP, mais sa politique propre (réseau interne accessible
  depuis l'amont) n'est pas vérifiée par Webrev. (4) Le proxy ne suit pas les
  redirections : leur contrôle repose sur le navigateur qui repasse par le
  proxy; non testé avec Chromium dans ce passage. (5) Les exclusions de nom ne
  couvrent que les noms écrits dans le scope : un autre nom résolvant vers une
  IP non exclue est autorisé si un CIDR l'inclut. (6) `Scope::allows` côté
  `webrev-core` ne normalise pas le point final; seul le proxy le fait.
  Ce passage ne qualifie pas l'étape 4 de `goal.md`.

## Non-destructivité par défaut (2026-10-17)

- Inventaire. Sondes actives et BOLA : uniquement `GET` (le client n'expose que
  `get`; test : toutes les requêtes d'un scan complet commencent par `GET `, aucune
  cible interne/métadonnées). Les endpoints `POST/PUT/PATCH/DELETE` sont déjà
  ignorés (`skipped_methods`). SSRF : hôte `.invalid` uniquement. Écart réel
  trouvé : un `GET` sur `/logout`, `/delete?id=3` ou `?action=unsubscribe` était
  fuzzé; le crawler statique suivait tout `<a href>`; le mode navigateur par
  défaut (`Explore`) cliquait « Delete account » (l'ancien test de fumée
  l'exigeait).
- Correctifs. `active/destructive.rs` : liste de mots entiers (chemin et
  paramètres, assets statiques exclus) appliquée aux cibles actives, aux
  candidats BOLA et aux liens du crawler. Refus enregistré dans la couverture
  (`destructive_url_guard` : refused, not_executed, inconclusive) donc jamais
  « complet ». Navigateur : chaque bouton est décrit avant le clic; mots
  destructifs ou soumission de formulaire non-GET refusés et listés
  (`refused_interactions`); contrôle non inspectable : pas de clic.
- Tests (boucle locale uniquement) : `active::integration_tests::safety` (4),
  `destructive::tests` (2), `crawler_never_enqueues_state_changing_links`,
  `policy::tests` (3), Chromium `explore_never_clicks_destructive_controls_and_records_refusals`
  et `dynamic_run_smoke` mis à jour. Aussi vérifié : échec de référence, 403/429,
  dépassement de taille, budget nul = couverture incomplète, jamais « sûr ».
- Limites. Heuristique par nom : un handler `GET` anodin qui modifie l'état,
  une requête émise par les scripts de la page au chargement, le défilement,
  WebSocket et les redirections côté serveur ne sont pas couverts; pas d'option
  pour lever le refus. Le crawler journalise (`tracing`) sans compteur de
  couverture. `--observation-only` reste le seul mode sans clic. Critères
  de goal.md non cochés.

## Refactor `domsinks`, masquage des identifiants, documentation (2026-10-18)

- `domsinks.rs` (1206 lignes) est découpé en `domsinks/{sources,sinks,ast,taint}.rs`
  et `taint/visit.rs`, sans changement de comportement; l'exception de
  `scripts/check_source_size.py` est retirée. `cargo test --workspace` : 350
  réussis (job `test (ubuntu-24.04)`), job `detection regression` vert.
- `HarEntry` : `Debug` manuel qui masque en-têtes sensibles, motifs de secrets
  et paramètres sensibles de l'URL. Extraits des sondes actives : `Sanitizer::scrub`
  puis troncature, URL via `redact_url`. Les jetons de forme inconnue dans un
  corps de réponse ne sont pas masqués.
- Audit `RUST_LOG=debug` : reqwest 0.12.28 lu seulement; hyper, hyper-util et
  chromiumoxide non lus, rien exécuté contre une fixture. Détails dans
  `docs/security.md`. *(Remplacé par l'audit exécuté plus bas.)*
- Limites DOM XSS inter-fichiers inchangées : imports namespace, réexports
  `export … from`, scripts classiques non-module, fermetures, fonction locale à
  paramètre. 105/122 repose sur ce changelog et le plancher du test; les JSON
  archivés de `multifile-v1` n'ont pas été régénérés (ils montrent 63/122).
- La mesure de performance de l'étape 5 n'a pas été refaite sur ce code.

## 2026-10-18 — limites DOM XSS levées (imports namespace, réexports, fonctions locales)

- Imports namespace : `import * as ns` expose `ns.nom` (valeur ou fonction
  résumée) ; `ns[x]`, un membre absent ou une liaison locale `ns` ne créent aucun
  flux.
- Réexports : `export {a as b} from` et `export * from` (sans `default`). Un nom
  fourni par deux `export *` différents est ambigu et écarté ; un export local de
  même nom masque le réexport. Le fichier « barrel » apparaît dans la provenance.
- Fonctions locales d'un fichier unique : un argument ou une valeur de retour
  tainted traverse un appel à une déclaration `function` de premier niveau
  (candidat `Medium`). Arguments sûrs, mauvais indice de paramètre, assainisseur
  dans la fonction, nom réaffecté ou masqué (paramètre, déclaration imbriquée) ne
  produisent rien.
- Inchangé : scripts classiques non-module inter-fichiers, fermetures (flèches,
  expressions de fonction, méthodes), `ns[x]`, `export * as ns from`.
- Vérifié localement : `cargo test -p webrev-extract` (137 tests unitaires et les
  corpus épinglés de détection, sans changement de résultat). Les chiffres
  105/122 ne sont pas recalculés : les JSON archivés n'ont pas été régénérés.

## 2026-10-18 — Audit exécuté de `RUST_LOG`

- Binaire lancé (`scan --dynamic --active`, Chromium système) contre une fixture
  loopback avec secrets factices, à `info`, `debug` et `trace`. Avant correctif,
  `chromiumoxide::conn` (dès `debug`) et `tungstenite` (`trace`) écrivaient
  Bearer, cookies, `X-Api-Key`, `Set-Cookie` et jetons de requête. reqwest et
  hyper n'écrivaient que l'hôte et le port.
- Correctif : `crates/webrev-cli/src/logging.rs` plafonne ces deux cibles à
  `error` après `RUST_LOG`; `WEBREV_LOG_UNSAFE=1` lève le plafond. Après
  correctif, 0 ligne de journal avec ces secrets aux trois niveaux.
- Reste : paramètres d'URL de nom inconnu (`tok=`) dans la ligne `dynamic: <seed>`
  et secrets de corps de forme inconnue (`"session":…`). Détails dans
  `docs/security.md`.
- Vérifié : `cargo test -p webrev-cli logging` (4 tests). Pas de
  `cargo test --workspace` local; la CI le fait.

## 2026-10-18 — remesure performance sur machine calme

- `scripts/benchmark_performance.py` : options `--baseline-bin`, `--current-bin`
  (binaires construits une fois, réutilisés), `--max-load`, `--seed`; deux runs
  d'échauffement non mesurés par binaire; médiane et min de RSS, SHA-256 des
  binaires et charge 1 min par run dans le JSON.
- Mesure de `main` b3f5e42 contre `61b843d` (120 pages, profil site) : 14
  invocations de 30 paires, archivées sous
  `benchmarks/performance/2026-10-18/spa-site-remeasure-quiet/`. Sur les 10
  invocations propres (300 paires) : p95 +16,8%, temps médian +16,0%, RSS
  médiane +13,3%, RSS max +11,1%.
- Un p95 isolé de 30 paires dépasse 20% dans 3 invocations sur 10 (jusqu'à
  +24,7%) : le critère tel qu'écrit n'est pas atteint de façon reproductible,
  la case de `goal.md` reste décochée.
- RSS de la base : binaire identique après rebuild; niveau de 19,1 MiB dans 13
  invocations sur 14, 14,4 MiB dans une (la première après les builds, +48% de
  RSS). Cause non établie (hypothèse : cache de pages ou THP), non reproduite.
- Les temps absolus sont environ deux fois ceux du 2026-10-17 : comparer des
  rapports.

## 2026-10-19 — rapports exportés bruts par défaut, `--redact` pour masquer

Décision de produit (chasseur de bugs) : le masquage par défaut des PR #21 et
#22 cachait la preuve des findings (jeton exposé, `session_id` d'une URL,
`/reset/<jeton>`, en-tête capturé, extrait de sonde). Les sections « masqués
par défaut » ci-dessous décrivent l'état avant ce changement.

- `--redact` / `WEBREV_REPORT_REDACT=1` remplacent `--unredacted` /
  `WEBREV_REPORT_UNREDACTED` (supprimés, rejetés par clap) sur `scan`,
  `static`, `dynamic`, `active`, `tui`, `report` et `bola`. L'export est brut
  par défaut dans tous les formats, y compris `--report -`, la touche `r` de la
  TUI, `report --format urls-exact | ffuf` (écrit `urls` à l'époque, qui liste en réalité des modèles de route) et le résultat de `bola`.
  `RenderOptions::default().redact` vaut `false`.
- `ProbeResponse::observation` stocke l'URL et l'extrait bruts (troncature à
  256 caractères conservée) ; `--redact` les masque à l'export.
- Écrire un rapport brut dans un fichier affiche une ligne d'avertissement
  (stderr ; message de statut dans la TUI).
- Toujours masqués, tous modes : journaux, erreurs, `Debug`, ligne
  `dynamic: <seed>`, résumé compact de fin de scan.
- Tests : `tests/report_redaction.rs` (brut par défaut dans les huit formats,
  `--redact` masque les huit formats, flag et variable d'environnement,
  `--unredacted` rejeté, conversion et `bola` avec les deux captures, une seule
  ligne d'avertissement, terminal/journaux/erreurs masqués dans les deux modes),
  `tests/bola_readable.rs` (IDOR lisible en brut et sous `--redact`, aucun
  jeton de compte écrit), `transport.rs` (extrait brut et tronqué),
  `redact.rs` (défaut brut). La cible de fuzz `report_redaction` fixe
  `redact: true`.
- Voir `docs/security.md`, « Suivi : rapports bruts par défaut ».

## 2026-10-19 — rapports exportés masqués par défaut (remplacé, voir ci-dessus)

- Tous les formats d'export (JSON, JSONL, CSV, URLs, texte, OpenAPI, DOT,
  GraphML, `--report -`, touche `r` de la TUI, rapport `bola`) passent par
  `SessionReport::redacted` : mission, seeds, URL, texte des findings, preuves
  de sondes et trames capturées sont masqués ; le JSON est masqué feuille par
  feuille et reste parsable. (`--unredacted` / `WEBREV_REPORT_UNREDACTED=1`
  gardaient le brut ; remplacés par `--redact`.) Un rapport masqué porte
  `"redacted": true` et `webrev bola --a-report/--b-report` le refuse (les
  identifiants d'objets ont disparu).
  *(Corrigé le jour même, voir la section suivante.)*
- Le texte clair des secrets détectés reste exporté (choix de produit
  inchangé). La détection n'est pas affectée : seule la copie exportée change.
- Tests : 9 unitaires (`redact.rs`, dont idempotence, JSON, prose, données
  ordinaires intactes, les huit formats), 1 `bola`, 3 de bout en bout
  (`tests/report_redaction.rs`, huit formats contre la fixture loopback).
  `ephemeral.rs` partage maintenant sa fixture via `tests/common/mod.rs`.
- Cible de fuzz `report_redaction`.
- Critère « preuves sensibles protégées » de `goal.md` toujours décoché.

## 2026-10-19 — identifiants d'objets lisibles dans les rapports masqués

- Régression de la PR #21 : les UUID et ids opaques en chemin étaient masqués,
  donc un résultat `bola` ne disait plus quel objet avait fuité. La redaction
  vise maintenant les identifiants de connexion, pas les identifiants d'objets.
- Plus masqués par leur seule forme : nombres, UUID (avec ou sans tirets), ids
  hexadécimaux de 32 chiffres au plus. Toujours masqués : jetons de forme
  connue, valeurs sous un nom de paramètre sensible (`session_id=<uuid>`), le
  segment qui suit `/reset/`, `/invite/`, `/verify/`, `/confirm/`…, les
  condensats de plus de 32 chiffres.
- Les noms sensibles se comparent par mot (`access_token`, `apiKey`) et non par
  sous-chaîne : `author_id`, `passenger_id`, `design_id` ne sont plus masqués.
- `bola --a-report/--b-report` accepte un rapport masqué ; une paire dont l'URL
  portait un identifiant de connexion est écartée avec un message.
- Tests : `sanitize/names.rs` (3), `sanitize/url.rs` (2 nouveaux, 1 adapté),
  de bout en bout `tests/bola_readable.rs` (IDOR détectée, objet lisible, aucun
  jeton ; objets protégés sans signal).
- Compromis : un rapport peut contenir des identifiants sensibles ; il reste
  confidentiel même masqué. Voir `docs/security.md`.

## 2026-10-19 — preuve de `bola` : corps de réponse et comparaison A/B

- Constat : une observation de `bola` ne gardait qu'une empreinte `sha256=` du
  corps, donc le rapport ne montrait pas ce que le compte A avait lu de l'objet
  de B.
- `ResponseObservation` gagne `body` (4 KiO au plus, UTF-8 sûr) et
  `body_truncated` ; `ProbeEvidence` gagne `diff` (sens de la fuite, champs
  JSON qui diffèrent entre les deux objets). Ils sont omis du JSON quand ils
  sont vides et ont une valeur par défaut au chargement : les anciens rapports
  et les autres sondes sont inchangés.
- Brut par défaut ; `--redact` masque les identifiants de connexion dans `body`
  et `diff` en gardant les identifiants d'objets. La logique de détection et le
  verdict `Idor` ne changent pas.
- Tests : `active/bola_diff.rs` (8 : troncature, UTF-8 coupé, UTF-8 invalide,
  comparaison, tableaux imbriqués, plafond de lignes), intégration `bola`
  (corps des deux lectures croisées, diff), `redact.rs` (corps et diff masqués
  sans perdre l'objet), de bout en bout `tests/bola_readable.rs` (corps lisible
  en brut, clé de l'objet masquée sous `--redact`, cas protégé sans signal).
- Cible de fuzz `report_redaction` : `body` et `diff` portent aussi le canari.

## 2026-10-19 — critère de performance poolé, avec intervalle de confiance

- Un p95 de 30 exécutions est la 29e valeur sur 30 : sur les mêmes binaires il
  varie de +9,9 % à +24,7 % d'une invocation à l'autre. Les seuils (p95 ≤ +20 %,
  RSS max ≤ +25 %) ne changent pas ; leur estimation passe sur un pool d'au moins
  3 invocations propres et 90 exécutions par révision, avec un intervalle de
  confiance bootstrap à deux niveaux, et la borne haute doit être sous 20 %
  (plus strict que le critère d'origine). Définition écrite dans `goal.md`
  avant la mesure.
- `scripts/benchmark_pool.py` (aussi `benchmark_performance.py pool RESULTS.json…`) :
  pool, bootstrap à graine fixe, exclusion des invocations chargées ou en échec
  (listées), signalement des bases anormales, verdict `pass` / `fail` /
  `not_demonstrated` / `insufficient`. 12 tests Python dans
  `scripts/test_benchmark_pool.py`. Sur l'archive du 2026-10-18 il redonne
  exactement +16,8 % (p95 poolé) et +11,1 % (RSS max).
- Mesure sur `main` 6b33d8d : lot prévu de 6 invocations, p95 +16,0 % (IC +12,3 %
  à +20,5 %) → non démontré ; réplication de 6 lancée ensuite +15,0 % (haut
  +18,8 %) ; 12 ensemble +15,2 % (haut +18,5 %) ; RSS max +4,4 %. Case non
  cochée (voir `goal.md`). Attribution partielle : l'extraction passe de 10,15 à
  11,38 ms par passe (`params` ×3, `js-ast`, `js-regex`, `secret` plus lents,
  `dom-sinks` plus rapide), soit environ 1,2 ms des ~4,7 ms d'écart.
  `benchmarks/performance/2026-10-19/spa-site-pooled/`.
