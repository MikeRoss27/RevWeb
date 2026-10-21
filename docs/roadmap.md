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
      **Replay / mutation des frames — fait (2026-10-20), portée réduite.**
      Nouveau test actif `crates/webrev-pipeline/src/active/ws_replay.rs`
      (`run_ws_replay_scan`, nouveau `FindingKind::WebSocketReplay`), sur le
      même patron que `bola.rs`/`bola_diff.rs` : même rigueur de preuve
      (diff de réponse, jamais un simple « accepté »), mêmes garde-fous
      (scope fail-closed, non-destructif par défaut, budget borné, résultat
      classé exécuté/refusé/inconclusif/erreur). Deux capacités :
      - **Replay verbatim** — rejoue une frame `sent` capturée telle quelle et
        capture les réponses reçues dans la fenêtre qui suit, comme preuve de
        reproductibilité (`FindingKind::WebSocketReplay`, statut `Observed` —
        jamais un verdict de vulnérabilité en soi).
      - **Mutation IDOR-style** — avec un second profil de compte
        (`--b-auth`), rejoue la même frame (éventuellement après une
        substitution littérale `find`/`replace` dans son payload, ex. un id
        d'objet) sous les deux comptes ; une réponse non vide et
        byte-identique sous les deux déclenche un `FindingKind::Idor` avec
        diff de champs (réutilise `bola_diff::comparison`), jamais sur un
        simple statut ou une URL acceptée.
      Garde-fous : scope vérifié deux fois comme les sondes HTTP (host via
      `Scope::allows`, puis chaque adresse DNS résolue via
      `Scope::allows_resolved_ip` avant `TcpStream::connect`, puisque ce
      module ouvre sa propre socket et ne passe pas par le résolveur épinglé
      de `reqwest` dans `crate::dns`) ; une frame dont la capture a été
      tronquée (`MAX_WS_PAYLOAD_CHARS`) est refusée, jamais rejouée à moitié ;
      une frame dont le payload (après mutation) contient un verbe d'action
      destructeur (`destructive::payload_keyword`, même liste que
      `destructive_keyword` pour les URL) ou un champ JSON à nom « montant »
      (`amount`, `balance`, `price`, `total`, `quantity`, `sum`, `credit`,
      `debit`, `payment`) avec une valeur numérique est refusée avant tout
      envoi. Budget : `MAX_WS_REPLAY_FRAMES` (10) connexions live par run,
      plafonné en plus par `max_requests`. Un proxy configuré fait échouer le
      scan explicitement (`ws_replay` ouvre sa propre connexion TCP, pas de
      support `HTTP CONNECT`) plutôt que de s'y substituer silencieusement.
      CLI : `webrev ws-replay` (`--report`/`--seed`, `--auth`, `--b-auth`,
      `--mutate-find`/`--mutate-replace`), sur le même patron que `webrev
      bola` — une commande dédiée, pas branchée sur `scan --active`/la touche
      `a` du TUI, pour la même raison que `bola` : ce test a besoin d'un
      second profil de compte explicite que le flux `active` générique n'a
      pas.
      **Limites honnêtes, non masquées :** (1) l'injection de payloads
      XSS/SQLi dans un champ de frame n'est **pas implémentée** — une frame
      WebSocket n'a pas de canal d'erreur SQL ni de DOM observable depuis un
      client brut comme une réponse HTTP ; `WsMutation` fait une substitution
      littérale générique, sans interprétation de ce qui revient. (2) la
      capture ne distingue pas les frames binaires des frames texte (CDP ne
      remonte qu'un `payload_data` déjà en chaîne) : tout est rejoué comme
      frame `Message::Text`, donc une frame binaire d'origine serait rejouée
      sous sa forme texte/base64 captée, pas reconstruite en binaire. (3)
      l'appariement requête→réponse capturé par `webrev-browser` n'est pas
      réutilisé pour établir la preuve de replay : la réponse comparée est
      toujours celle obtenue en direct après le renvoi, jamais la réponse
      originale observée pendant la capture (qui n'est pas fiablement
      associable à sa frame `sent`). (4) le signal cross-account peut être un
      faux positif documenté (message public/broadcast, écho non
      authentifié) — la justification jointe au finding le dit explicitement,
      comme pour `bola`. Tests unitaires : replay réussi avec preuve,
      frame refusée (destructive, hors scope, tronquée), budget dépassé,
      mutation qui change la réponse (pas de signal) vs qui ne change rien
      (signal), proxy configuré refusé. `cargo fmt`, `cargo clippy
      --workspace --all-targets -- -D warnings` et `cargo test --workspace`
      passent sans warning (voir `docs/changelog-reliability.md`).
      `crates/webrev-pipeline/src/active/ws_replay.rs`,
      `crates/webrev-cli/src/commands/ws_replay.rs`,
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
