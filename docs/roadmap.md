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
- [x] **Introspection GraphQL — détection (statique)** — `graphql` signale
      quand le client embarque une `IntrospectionQuery`/`__schema`, ce qui
      indique qu'une sonde manuelle sur `/graphql` vaut le coup.
      `crates/webrev-extract/src/extractors/endpoints/graphql.rs`
- [x] **Introspection GraphQL — automatique réelle (2026-10-20)** — plutôt
      qu'un nouveau stage pipeline, la sonde vit dans `active/graphql.rs`
      (`webrev-pipeline`), au même niveau que les autres checks actifs :
      c'est là que vivent déjà le scope fail-closed, le budget de requêtes,
      le retry et la redaction, qu'un stage séparé aurait dû réimporter.
      `is_graphql_endpoint` repère les endpoints `/graphql` (détectés
      statiquement ou observés) et `check_graphql_introspection` tente,
      pour chacun, la requête standard `IntrospectionQuery` du spec
      GraphQL : d'abord en GET (comme le signal existant), puis en POST
      uniquement si le GET ne répond pas avec un schéma. Le schéma recouvré
      (types, champs de `Query`/`Mutation`/`Subscription`) devient un
      nouveau `FindingKind::GraphQlSchema`, avec l'URL interrogée en
      provenance et la liste des noms en JSON dans `value` (masqué comme
      tout le reste par `--redact`, via le chemin JSON générique de
      `redact.rs`). Introspection = lecture de métadonnées de schéma, jamais
      une mutation ; c'est la seule dérogation documentée à la politique
      « sondes GET uniquement » (`docs/security.md`, « Probe behavior ») :
      `ProbeClient::post_literal` n'accepte qu'un `&'static str`, donc
      seule une constante du code source — jamais une valeur construite à
      l'exécution — peut partir en POST. Échec, timeout, hors scope ou
      introspection désactivée côté serveur : aucun finding, compté comme
      `graphql_introspection` négatif/non exécuté dans `ScanCoverage`,
      jamais un faux verdict. **Limites documentées** : seuls les noms de
      types/champs sont recouvrés (pas les arguments, interfaces,
      directives ni les raisons de dépréciation) pour borner la taille de
      la réponse ; pas de contournement des protections anti-introspection
      non standard (désactivation partielle par champ, GraphQL par lots/
      `multipart`, alias-based bypass) — hors périmètre d'une sonde GET/POST
      simple. Tests unitaires : schéma recouvré avec succès, JSON sans
      `__schema` reconnaissable, introspection désactivée (réponse
      `errors`), corps non-JSON, statut HTTP en échec ; intégration via le
      budget/scope déjà testés sur `active/mod.rs`.
      `crates/webrev-pipeline/src/active/graphql.rs`,
      `crates/webrev-pipeline/src/active/transport.rs`

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

- [x] **Graphe de relations endpoint ↔ composant ↔ paramètres observés** —
      `SessionReport` expose `render_dot`/`render_graphml` (`ReportFormat::Dot`,
      `ReportFormat::GraphMl`, CLI `--format dot|graphml`). Le graphe relie
      uniquement ce qui est réellement observable dans les findings actuels :
      endpoint → paramètre (`has_parameter`, depuis la query string de
      l'endpoint stocké ou d'un finding `endpoint`/`parameter` qui matche
      sans ambiguïté un endpoint par méthode+URL), composant (fichier/script
      source, via `provenance.location`) → endpoint (`reveals`) et composant →
      paramètre (`mentions_parameter`), plus endpoint → paramètre
      (`probed_parameter`) quand une sonde active (`Idor`/`Vulnerability`)
      porte un nom de paramètre. **Non fait** : aucun lien route client ↔
      endpoint (le modèle actuel n'a pas de finding "route" relié
      explicitement ou implicitement à une URL d'API — ce serait une
      corrélation inventée) ni endpoint ↔ technologie : les findings
      `Technology` portent bien une provenance (fichier/URL où la stack a été
      détectée), mais ce n'est pas câblé dans `relation_graph` — relier un
      composant qui "reveals" un
      endpoint au même composant qui "uses" une techno donnerait une
      transitivité endpoint→techno trop indirecte pour être présentée comme
      une relation observée plutôt que déduite ; laissé pour une itération
      future plutôt que fait à moitié. Pas d'intégration Neo4j live (hors scope,
      différente classe de fonctionnalité) ; DOT/GraphML suffisent comme
      "format exploitable" au sens de la roadmap. La redaction (`--redact`)
      s'applique au graphe comme aux autres formats (labels masqués via le
      même `SessionReport::redacted()`). Tests unitaires couvrant les
      relations attendues, l'absence de relations non prouvées, l'échappement
      DOT/XML et le déterminisme de sortie.
      `crates/webrev-report/src/graph.rs`, `crates/webrev-report/src/format.rs`,
      `crates/webrev-cli/src/cli.rs`
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
