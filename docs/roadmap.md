# Roadmap — aller plus loin dans le reverse engineering

Suivi des pistes pour pousser webrev au-delà de l'extraction actuelle. Cocher
au fur et à mesure. Chaque item renvoie au(x) fichier(s) concerné(s).

## 1. Extraction statique — ✅ fait (2026-10-11)

- [x] **Constantes de config embarquées** — nouvel extracteur AST `config`
      qui détecte les objets/`const` dont la clé ressemble à un flag/réglage
      (`featureFlag`, `DEBUG_MODE`, `apiVersion`, `tenantId`, …) liée à un
      littéral (string/bool/num). Nouveau `FindingKind::Config`.
      `crates/webrev-extract/src/extractors/metadata/config.rs`
- [x] **Imports dynamiques** — `JsAstExtractor` reporte désormais le
      spécificateur de chaque `import("…")` comme finding `script`, même s'il
      ne ressemble pas à une URL (ex. `import("./AdminPanel")`).
      `crates/webrev-extract/src/extractors/endpoints/js_ast.rs`
- [x] **Graphe de chunks webpack/Vite** (version light) — nouvel extracteur
      `manifest` (JSON) qui marche récursivement sur `asset-manifest.json`
      (webpack, forme plate) et `manifest.json` (Vite, forme imbriquée
      entry→{file,imports,css}) et ressort chaque chemin de chunk/asset, y
      compris ceux jamais liés depuis une page HTML.
      `crates/webrev-extract/src/extractors/metadata/manifest.rs`
- [x] **Service workers & manifest.json** — le fetch stage suit désormais
      `<link rel="manifest">` et `navigator.serviceWorker.register(...)`
      (jusque-là ignorés : ni `<script src>` ni `<a href>`), et l'extracteur
      `manifest` en tire `start_url`/`scope`/`id` comme findings `config`.
      `crates/webrev-pipeline/src/stages/fetch/mod.rs`
- [x] **Introspection GraphQL — détection** — `graphql` signale désormais
      quand le client embarque une `IntrospectionQuery`/`__schema`, ce qui
      indique qu'une sonde manuelle sur `/graphql` vaut le coup.
      **Non fait : l'introspection automatique réelle** (requête HTTP live)
      est hors de portée d'un extracteur pur (contrat `Extractor`: pas d'I/O) ;
      il faudrait un nouveau stage pipeline, comme `fetch.rs`. Reste ouvert si
      utile plus tard.
      `crates/webrev-extract/src/extractors/endpoints/graphql.rs`

Nouveau au passage : `ContentKind::Json` et `Source::Manifest` (core),
conservés dans les findings et les exports. Tests ajoutés pour
chaque extracteur ; `cargo test --workspace` et `cargo clippy --workspace
--all-targets` passent sans warning.

## 2. Analyse dynamique (navigateur) — ✅ fait (2026-10-11)

- [x] **Attribution clic → endpoint** (version réaliste du "diffing d'état") —
      plutôt qu'un diff DOM/store générique (infaisable sans connaître le
      state manager de la page), le driver clique désormais un élément à la
      fois et pose `window.__webrev_trigger` juste avant le clic ; tout appel
      hook enregistré dans la fenêtre de settle qui suit est attribué à cet
      élément (`provenance.location = "click: <label>"`). Borné à
      `MAX_CLICKS_PER_PASS` par passe pour rester borné dans le temps.
      `crates/webrev-browser/src/hooks.rs`, `crates/webrev-browser/src/dynamic.rs`
- [x] **Capture des frames WebSocket** — `EventWebSocketFrameSent`/
      `EventWebSocketFrameReceived` sont désormais capturées (en plus de
      `EventWebSocketCreated`), bornées (`MAX_WS_FRAMES`,
      `MAX_WS_PAYLOAD_CHARS`), conservées avec leurs valeurs d'origine et ressorties comme nouveau
      `FindingKind::WebSocketFrame` (tag direction + URL du socket).
      **Non fait : replay / mutation des frames** — la capture conserve les
      échanges pour l'analyse, mais leur réémission n'est pas implémentée.
      C'est une piste de tests actifs à concevoir avec les contrôles de scope,
      d'authentification et de trafic du projet. Les payloads peuvent déjà être
      rejoués avec Burp ou websocat.
      `crates/webrev-browser/src/dynamic.rs`
- [x] **Adaptation anti-WAF/anti-rate-limit** — en fait plus pertinent côté
      crawler HTTP (`webrev-pipeline`) que navigateur : `fetch_with_retry`
      détecte 429/503, honore `Retry-After` (plafonné à 30s), et le crawl
      réduit sa concurrence (÷2 par strike, jusqu'à ÷8) et étire le délai
      inter-vague (jusqu'à ×16) après des vagues consécutives rate-limitées,
      au lieu d'un jitter fixe.
      `crates/webrev-pipeline/src/stages/fetch/mod.rs`, `crates/webrev-pipeline/src/stages/mod.rs`

Nouveau au passage : `FindingKind::WebSocketFrame` (core, slug `ws_frame`,
`Severity::Low`), conservé dans la session en mémoire. Tests
unitaires ajoutés (backoff, retry-after, dynamic imports…) ; `cargo test
--workspace` et `cargo clippy --workspace --all-targets` passent sans
warning. Le test `dynamic_run_smoke` (ignoré par défaut, nécessite Chromium)
a été lancé en live contre un vrai Chrome local avec succès.

## 3. Tests de sécurité actifs — implémentés

- [x] Headers de sécurité, attributs des cookies, CORS, fichiers sensibles
      accessibles et redirections ouvertes.
- [x] Signaux XSS par réflexion et SQLi par erreurs de base de données.
- [x] Signal IDOR / contrôle d'accès par comparaison avec et sans authentification.
- [x] Probes sur les URL concrètes découvertes, avec leurs paramètres et identifiants.
- [x] Triage CLI/TUI, secrets complets, stack détectée, confiance et preuves.
      Lancement par `active`, `scan --active` ou la touche `a` du TUI.
      `crates/webrev-pipeline/src/active/`, `crates/webrev-report/src/text.rs`,
      `crates/webrev-tui/src/runtime/active.rs`

Les signaux XSS/SQLi/IDOR demandent une validation manuelle. Aucune vérification
RCE n'est implémentée. Les fonctions futures restent suivies séparément des
capacités déjà présentes.

## 4. Corrélation / intelligence

- [ ] **Graphe de relations endpoint ↔ composant ↔ paramètres observés** —
      export vers un format exploitable (DOT/GraphML/Neo4j) en plus du
      JSON/CSV actuel.
      `crates/webrev-report/src/*`, `crates/webrev-storage/src/*`
- [x] **Score de confiance par endpoint** (2026-10-20) — `EndpointConfidence`
      (`inferred` < `static` < `observed`) distingue "vu en trafic live" >
      "vu en JS statique/HTML/manifest" > "deviné par normalisation de
      pattern/template". `Endpoint::merge_from` conserve la meilleure preuve
      (et sa source) quand plusieurs findings normalisent vers la même route,
      quel que soit l'ordre d'écriture — une route déjà `observed` n'est
      jamais rétrogradée par un hit statique ou inféré arrivant ensuite.
      Persisté par endpoint dans `webrev-storage`, compté dans
      `Summary::endpoints_by_evidence_tier`, exposé dans le rapport JSON
      (`Endpoint::confidence`), la ligne "Endpoint evidence" du résumé CLI,
      l'export GraphML/DOT et l'onglet Endpoints du TUI.
      `crates/webrev-core/src/model/endpoint.rs`, `crates/webrev-core/src/model/normalize.rs`,
      `crates/webrev-storage/src/backends/memory.rs`, `crates/webrev-report/src/summary.rs`,
      `crates/webrev-cli/src/commands/output.rs`, `crates/webrev-tui/src/app/updates.rs`
- [ ] **Fingerprint cross-cibles** — comparer la stack/API de plusieurs
      domaines scannés pour repérer la réutilisation d'infra dans un même
      engagement multi-cibles.
      `crates/webrev-extract/src/extractors/metadata/tech/signatures/`, `crates/webrev-storage/src/*`

## Notes

- Priorité suggérée : commencer par **1** (statique, gain rapide, peu de
  risque opsec) avant **2** (dynamique, plus coûteux) puis **3**
  (corrélation, dépend des deux premiers).
- Garder le scope fail-closed, les sessions en mémoire et les secrets visibles pour toute
  nouvelle fonctionnalité (voir `docs/security.md`).
