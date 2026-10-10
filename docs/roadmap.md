# Roadmap — aller plus loin dans le reverse engineering

Suivi des pistes pour pousser webrev au-delà de l'extraction actuelle. Cocher
au fur et à mesure. Chaque item renvoie au(x) fichier(s) concerné(s).

## 1. Extraction statique — ✅ fait (2026-10-11)

- [x] **Constantes de config embarquées** — nouvel extracteur AST `config`
      qui détecte les objets/`const` dont la clé ressemble à un flag/réglage
      (`featureFlag`, `DEBUG_MODE`, `apiVersion`, `tenantId`, …) liée à un
      littéral (string/bool/num). Nouveau `FindingKind::Config`.
      `crates/webrev-extract/src/extractors/config.rs`
- [x] **Imports dynamiques** — `JsAstExtractor` reporte désormais le
      spécificateur de chaque `import("…")` comme finding `script`, même s'il
      ne ressemble pas à une URL (ex. `import("./AdminPanel")`).
      `crates/webrev-extract/src/extractors/js_ast.rs`
- [x] **Graphe de chunks webpack/Vite** (version light) — nouvel extracteur
      `manifest` (JSON) qui marche récursivement sur `asset-manifest.json`
      (webpack, forme plate) et `manifest.json` (Vite, forme imbriquée
      entry→{file,imports,css}) et ressort chaque chemin de chunk/asset, y
      compris ceux jamais liés depuis une page HTML.
      `crates/webrev-extract/src/extractors/manifest.rs`
- [x] **Service workers & manifest.json** — le fetch stage suit désormais
      `<link rel="manifest">` et `navigator.serviceWorker.register(...)`
      (jusque-là ignorés : ni `<script src>` ni `<a href>`), et l'extracteur
      `manifest` en tire `start_url`/`scope`/`id` comme findings `config`.
      `crates/webrev-pipeline/src/stages/fetch.rs`
- [x] **Introspection GraphQL — détection** — `graphql` signale désormais
      quand le client embarque une `IntrospectionQuery`/`__schema`, ce qui
      indique qu'une sonde manuelle sur `/graphql` vaut le coup.
      **Non fait : l'introspection automatique réelle** (requête HTTP live)
      est hors de portée d'un extracteur pur (contrat `Extractor`: pas d'I/O) ;
      il faudrait un nouveau stage pipeline, comme `fetch.rs`. Reste ouvert si
      utile plus tard.
      `crates/webrev-extract/src/extractors/graphql.rs`

Nouveau au passage : `ContentKind::Json` et `Source::Manifest` (core), table
`parse_kind`/`parse_source` à jour dans `webrev-storage`. Tests ajoutés pour
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
      `MAX_WS_PAYLOAD_CHARS`), sanitizées et ressorties comme nouveau
      `FindingKind::WebSocketFrame` (tag direction + URL du socket).
      **Non fait : la rejouabilité elle-même** — renvoyer/muter une frame
      changerait webrev d'un outil d'observation passive à un outil actif
      d'exploitation, hors de son identité de recon ; le payload capturé
      donne à l'opérateur ce qu'il faut pour rejouer avec son propre outil
      (Burp, websocat, …).
      `crates/webrev-browser/src/dynamic.rs`
- [x] **Adaptation anti-WAF/anti-rate-limit** — en fait plus pertinent côté
      crawler HTTP (`webrev-pipeline`) que navigateur : `fetch_with_retry`
      détecte 429/503, honore `Retry-After` (plafonné à 30s), et le crawl
      réduit sa concurrence (÷2 par strike, jusqu'à ÷8) et étire le délai
      inter-vague (jusqu'à ×16) après des vagues consécutives rate-limitées,
      au lieu d'un jitter fixe.
      `crates/webrev-pipeline/src/stages/fetch.rs`, `crates/webrev-pipeline/src/stages/mod.rs`

Nouveau au passage : `FindingKind::WebSocketFrame` (core, slug `ws_frame`,
`Severity::Low`), table `parse_kind` à jour dans `webrev-storage`. Tests
unitaires ajoutés (backoff, retry-after, dynamic imports…) ; `cargo test
--workspace` et `cargo clippy --workspace --all-targets` passent sans
warning. Le test `dynamic_run_smoke` (ignoré par défaut, nécessite Chromium)
a été lancé en live contre un vrai Chrome local avec succès.

## 3. Corrélation / intelligence

- [ ] **Graphe de relations endpoint ↔ composant ↔ paramètres observés** —
      export vers un format exploitable (DOT/GraphML/Neo4j) en plus du
      JSON/CSV actuel.
      `crates/webrev-report/src/*`, `crates/webrev-storage/src/*`
- [ ] **Score de confiance par endpoint** — distinguer "vu en trafic live" >
      "vu en JS statique" > "deviné par normalisation de pattern".
      `crates/webrev-core/src/model/endpoint.rs`, `crates/webrev-core/src/model/normalize.rs`
- [ ] **Fingerprint cross-cibles** — comparer la stack/API de plusieurs
      domaines scannés pour repérer la réutilisation d'infra dans un même
      engagement multi-cibles.
      `crates/webrev-extract/src/extractors/tech.rs`, `crates/webrev-storage/src/*`

## Notes

- Priorité suggérée : commencer par **1** (statique, gain rapide, peu de
  risque opsec) avant **2** (dynamique, plus coûteux) puis **3**
  (corrélation, dépend des deux premiers).
- Garder le principe fail-closed / secrets non-réversibles pour toute
  nouvelle fonctionnalité (voir `docs/security.md`).
