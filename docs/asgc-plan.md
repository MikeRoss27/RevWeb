# WebRev ASGC — plan de développement (scope réaliste)

Ce document reprend l'idée reçue en brainstorm (« Adaptive State Graph
Crawler ») et la recadre sur l'état réel du dépôt, pas sur des suppositions.
Le plan d'origine décrivait correctement les dépendances déjà présentes
(`tokio`, `reqwest`, `chromiumoxide`, `swc_core`, `lol_html`, `sha2`/`hmac`,
`ratatui`, `clap`) et les 8 crates du workspace, mais sous-estimait à quel
point le projet est déjà avancé : tests actifs (BOLA, SSRF, CRLF, takeover,
replay WebSocket, introspection GraphQL), scope fail-closed vérifié à chaque
requête, statuts de preuve (`observed`/`suspicious`/`confirmed`/
`inconclusive`), limites honnêtes documentées pour chaque fonctionnalité
(voir `docs/roadmap.md`, `docs/architecture.md`, `docs/active-research.md`).

**Principe directeur : on fait évoluer une discipline de preuve existante,
pas une démo d'algorithmes.** Toute nouvelle capacité doit respecter les
mêmes règles que le reste du projet — sinon elle ne rentre pas, même si elle
est algorithmiquement intéressante.

## 1. Principes non négociables (inchangés)

| Principe | Exigence |
| --- | --- |
| Langage / archi | Rust natif, workspace Cargo existant, pas de nouvelle crate sans besoin démontré |
| Runtime | Tokio |
| Stockage | Sessions en mémoire, pas de DB, pas de persistance implicite |
| Scope | Fail-closed, vérifié avant **chaque** opération réseau (y compris après redirection, y compris côté navigateur) |
| Preuve | Jamais de verdict de vulnérabilité sans évidence reproductible (diff de réponse, pas un simple statut accepté) |
| Budgets | Bornés en requêtes, mémoire, concurrence, profondeur ; un algorithme peut *répartir* un budget, jamais l'*augmenter* |
| Navigateur | Pas d'action destructrice par défaut (déjà imposé par `webrev-pipeline/src/active/destructive.rs`) |
| Secrets | Masqués par défaut, jamais dans les logs |
| LLM / scanners externes | Aucun requis |

## 2. Méthode : baseline avant tout changement

Avant d'écrire une ligne du nouveau scheduler, on mesure le BFS actuel
(`webrev-pipeline/src/stages/fetch/`) sur des applications locales
synthétiques :

- ressources uniques découvertes, requêtes totales, taux de doublons ;
- temps d'exécution, mémoire pic ;
- comportement à l'annulation ;
- violations de scope (doit être 0) ;
- couverture par rapport à une vérité terrain connue (fixture locale).

Ce baseline est le seul juge de ce qui vaut la peine d'être construit
ensuite. On ne remplace pas une implémentation qui marche sur la base d'une
intuition algorithmique non mesurée — c'est la règle déjà en vigueur dans ce
projet (voir `docs/roadmap.md`, qui documente systématiquement limites et
tests pour chaque feature).

## 3. Ce qu'on construit maintenant (P0)

### 3.1 Frontière de priorité (scheduler)

Remplacer progressivement le parcours BFS par vagues par une frontière
`BinaryHeap` priorisée, **sans dépendance externe** et sans toucher à
`PipelineItem`/`Stage` :

```
webrev-pipeline/src/stages/fetch/
├── mod.rs
├── discovery.rs
├── request.rs
├── sourcemaps.rs
└── scheduler/          (nouveau)
    ├── frontier.rs      candidat + score, BinaryHeap
    ├── priority.rs      fonction de score
    ├── fairness.rs      anti-starvation (ancienneté)
    └── metrics.rs       instrumentation testable
```

Stratégies disponibles dès le départ : `bfs` (défaut actuel, conservé comme
baseline de régression) et `best-first` (priorité déterministe). Le feedback
adaptatif (Phase 8 de l'ancien plan) n'est **pas** dans ce lot — voir §5.

Critère d'acceptation : sous n'importe quelle stratégie, le scope, les
budgets, l'annulation et la concurrence par origine restent respectés à
l'identique. Un test de régression compare `bfs` avant/après refactor pour
garantir zéro changement de comportement sur la stratégie historique.

### 3.2 Graphe de connaissance applicative (bornes incluses dès le départ)

**Fait (premier incrément) :** plutôt que de faire naître un second graphe
typé en parallèle du graphe de relations déjà exporté par `webrev-report`
(`docs/roadmap.md`, §4), on l'a étendu en place, dans
`crates/webrev-report/src/graph.rs` :

- Nouveau nœud `resource` (cible d'un `FindingKind::Script`/`Link`/
  `SourceMap`), en plus de `endpoint`/`parameter`/`component` existants.
- Nouvelles relations `loads` (page → script), `links_to` (page → page),
  `maps_to` (script → source map) — dérivées des findings déjà collectés
  par `html.rs`/`sourcemaps.rs`, sans nouvelle passe de découverte ni
  nouveau stage pipeline. C'est une lecture directe de la provenance que
  webrev enregistre déjà, pas un second système.
- Bornes `MAX_GRAPH_NODES`/`MAX_GRAPH_EDGES` (5 000 / 20 000) : au-delà, le
  graphe est marqué `truncated` plutôt que de grossir sans limite, visible
  dans le DOT (`// truncated: true`) et le GraphML
  (`<data key="truncated">true</data>`).
- Limite honnête documentée : une référence relative sans `/` initial
  (`contact`, `app.js`) n'est jamais résolue par cette couche — elle n'a
  pas la logique de résolution d'URL du crawler, et re-deviner une
  résolution serait fabriquer une relation non prouvée. Pas d'arête créée
  pour ces cas, plutôt qu'une arête vers une URL inventée.

**Fait (deuxième incrément) :**
- Le nœud `component` porte maintenant un `kind` classifié par extension
  (`document`/`script`/`stylesheet`/`sourcemap`) au lieu d'un `"component"`
  générique — purement cosmétique, aucune clé ni arête existante ne change.
- Nouveau nœud `framework` + relation `detected_on`, à partir des findings
  `FindingKind::Technology` déjà collectés (`tech/mod.rs`) : lien direct
  composant → techno, **sans** chaînage vers un endpoint que le même
  composant révèle aussi — cette transitivité avait déjà été explicitement
  écartée (`docs/roadmap.md`, §4, "Non fait") et ce choix est respecté ici.

**Pas fait (reporté)** : les nœuds `Document`/`NetworkObservation`/
`Finding` comme types *distincts* dans le modèle de données (aujourd'hui
`component` reste une seule structure de nœud, seul son `kind` varie), les
relations `Imports`/`References`/`ObservedDuring`/`Contains`/`ProducedBy`
(`NetworkObservation` notamment: les findings `WebSocketFrame` n'ont pas
d'association connue à la page qui a ouvert le socket — l'ajouter serait
deviner une relation, pas la lire), et surtout
une structure *construite pendant le crawl* plutôt que *dérivée au moment
du rapport*. Le graphe reste un calcul sur `SessionReport` (findings +
endpoints déjà stockés), pas une structure vivante dans
`webrev-storage` — cohérent avec "sessions en mémoire", mais ça veut dire
qu'aucun consommateur temps réel (TUI "Graph tab" du plan d'origine) ne
peut encore s'y brancher pendant un scan en cours. À reprendre seulement si
un besoin concret apparaît (ex. la TUI veut vraiment un onglet Graph live).

## 4. Ce qu'on reporte et pourquoi (P1/P2)

| Capacité | Statut | Raison |
| --- | --- | --- |
| Adaptateurs frameworks (Next.js, React, Nuxt…) | P1, premier incrément fait (Next.js) | Valeur réelle mais indépendant de l'ASGC ; se branche sur `webrev-extract` sans dépendre du scheduler |
| Browser Engine 2.0 (DOM/accessibility/state fingerprint) | P1, premier incrément fait (couverture des clics) | `webrev-browser` existe déjà et fonctionne (clic→endpoint, frames WS) ; à étendre, pas à réécrire |
| Protocol Intelligence (gRPC-Web, WebTransport…) | P2 | Valeur incertaine sans cas d'usage concret observé sur une cible réelle |
| Secret Intelligence refonte (`engine.rs`, `confidence.rs`...) | P2 | Le module actuel (`webrev-extract/src/extractors/secrets/`) fonctionne ; à faire évoluer seulement si le baseline montre des faux positifs/négatifs mesurés |

### 4.1 Adaptateur Next.js (`webrev-extract/src/extractors/endpoints/nextjs.rs`)

**Fait** : un nouvel extracteur (`nextjs`, priorité 51, juste sous `graphql`)
lit uniquement des données que Next.js produit lui-même — jamais de
devinette :
- `__NEXT_DATA__` (présent sur toute page server-rendue) → la route
  courante (`page`, JSON strict) et le `buildId`.
- `self.__BUILD_MANIFEST` / `self.__SSG_MANIFEST` (dans `_buildManifest.js`
  / `_ssgManifest.js`, que Next.js lie en `<script src>` direct depuis le
  `<head>` — donc déjà découvert et récupéré par le crawler existant, sans
  changement de pipeline) → la liste **complète** des pages connues du
  build, qu'elles soient ou non liées depuis une page visitée. C'est la
  vraie valeur ajoutée par rapport à `SpaRouteExtractor` (générique, regex
  `path:`/`<Route>`, ne voit que ce qui est référencé dans le JS atteint).

Le corps de `__BUILD_MANIFEST` est un littéral JS (pas du JSON strict : clés
non quotées comme `sortedPages` mélangées aux chemins quotés) — on ne le
parse donc pas en bloc, seulement la forme `"<path>": [` de chaque entrée de
page de premier niveau. Une forme de manifeste non reconnue (futur format
Next.js) ne produit simplement aucun finding ; rien n'est inventé.

**Pas fait (reporté)** : React / Nuxt / autres frameworks (aucun n'expose un
équivalent aussi direct et structuré que `__BUILD_MANIFEST` — Nuxt a
`__NUXT__` mais pour l'état hydraté, pas une liste de routes ; nécessiterait
son propre adaptateur dédié, pas une généralisation du code Next.js). Pas de
fetch proactif du build manifest quand il n'est pas déjà lié en `<script
src>` (changerait le comportement du crawler, hors scope de cet incrément).

### 4.2 Browser Engine — couverture des clics (`webrev-browser/src/dynamic.rs`)

**Bug trouvé et corrigé** : la passe d'interaction active sélectionnait
toujours `document.querySelectorAll('button, [role=button]')[0..10]` —
mêmes index à chaque passe. Sur une page avec plus de
`MAX_CLICKS_PER_PASS` (10) contrôles, les 10 premiers étaient re-cliqués à
chaque passe pendant toute la durée du dwell, et tout contrôle au-delà de
l'index 10 n'était **jamais** atteint. Un contrôle refusé (politique de
sécurité) à un index bas bloquait aussi silencieusement tout le budget de
clics de chaque passe suivante.

**Fait** : chaque élément examiné (cliqué ou refusé) est marqué
`data-webrev-seen` sur l'élément DOM lui-même, et le sélecteur
(`INTERACTIVE_SELECTOR`) l'exclut ensuite — donc chaque passe avance sur des
éléments neufs au lieu de revenir aux mêmes. `describe_script` (en lecture)
et le clic/marquage (en écriture, qui modifie la `NodeList` live) sont
désynchronisés exprès via `window.__webrev_pending` : décrire puis marquer
par le même appel aurait décalé les index vivants entre les deux appels
`evaluate()`.

Vérifié avec un vrai Chromium (pas seulement compilé) : nouveau test
`active_interaction_covers_every_control_across_passes_without_repeats`
(12 boutons, `MAX_CLICKS_PER_PASS` = 10) — chaque bouton est appelé
**exactement une fois** sur tout le dwell. Les 3 tests réels existants
(`dynamic_run_smoke`, `observation_only_refuses_page_post_and_does_not_click`,
`explore_never_clicks_destructive_controls_and_records_refusals`,
`websocket_scope_blocks_egress`, `diagnostic_websocket_cdp_block_patterns`)
passent toujours sans modification de leur assertion.

**Pas fait (reporté)** : accessibility tree (rôles ARIA au-delà de
`[role=button]`), fingerprint d'état de page (détecter qu'une route SPA a
changé sans rechargement complet pour éviter de re-scanner un DOM
identique), et élargissement du sélecteur à d'autres contrôles interactifs
(`<select>`, `[onclick]` générique) — chacun change le rayon d'action réel
du moteur (donc le risque de sécurité) et doit être une décision séparée,
pas un effet de bord du correctif de couverture.

### 4.3 Browser Engine — `input[type=submit|button|reset]` (`webrev-browser/src/dynamic.rs`)

**Fait** : `INTERACTIVE_SELECTOR` couvre maintenant aussi les contrôles
natifs `<input type=submit|button|reset>` — très courants dans du HTML
simple à la place de `<button>`, et jusqu'ici totalement invisibles au
moteur actif. La logique de classification "ce contrôle soumet-il un
formulaire non-GET" a été corrigée au passage : elle testait `el.tagName
!== 'BUTTON'` (vrai pour tout `<input>`, donc tout input dans un formulaire
aurait été classé "soumet", y compris `type=button`/`type=reset` qui ne
soumettent jamais) ; elle compare maintenant le `type` effectif de l'élément
(`submit` par défaut pour `<button>`, `button` par défaut pour `<input>`) à
`'submit'`, correct pour les deux balises.

Toujours pas de sélecteur `[onclick]` générique (cf. §4.2 — décision
séparée).

Vérifié avec un vrai Chromium : nouveau test
`native_input_controls_are_clicked_or_refused_like_buttons` — un
`input[type=button]` hors formulaire est cliqué (preuve qu'il est
désormais atteint), un `input[type=submit]` dans un formulaire POST est
refusé et jamais cliqué (donc jamais soumis), et apparaît dans
`refused_interactions`. Les 6 autres tests réels existants, dont celui du
§4.2, passent toujours sans changement d'assertion.

## 5. Ce qu'on rejette ou qu'on bloque derrière une mesure (important)

### 5.1 Fingerprinting multicouche (SimHash/MinHash/LSH) — **rejeté tant que non justifié**

Le dépôt a déjà une dédup fonctionnelle par SHA-256
(`webrev-storage/src/fingerprint.rs`). Rien dans le projet n'indique
aujourd'hui que la dédup « presque identique » soit un problème mesuré.
Ajouter trois couches de similarité par anticipation va à l'encontre de la
règle du projet : pas d'abstraction sans besoin démontré. **Condition de
déblocage** : le baseline (§2) montre un volume significatif de quasi-doublons
non capturés par SHA-256+normalisation d'URL. Sans ce chiffre, cette phase
reste fermée.

### 5.2 Bandit adaptatif (UCB1) pour l'allocation moteur — **rejeté en l'état, risque de sécurité, pas seulement de perf**

Un bandit qui alloue le budget entre HTTP/statique/navigateur/secrets sur la
base d'une récompense « nouvelles observations utiles / coût » peut
sous-prioriser silencieusement la détection de secrets ou les sondes actives
parce qu'elles « rapportent moins » à court terme sur une cible donnée — ce
n'est plus une optimisation, c'est une régression de couverture de sécurité
déguisée. L'ancien plan disait déjà « l'algorithme ne doit jamais augmenter
les limites de sécurité » ; ça ne suffit pas. **Si cette phase est un jour
reprise**, elle doit respecter un invariant testé, pas seulement documenté :
chaque moteur de détection a un budget plancher non négociable que le bandit
ne peut jamais descendre, vérifié par un test d'intégration dédié.

### 5.3 Planning 12 semaines jusqu'à v1.0 — **remplacé par une cadence par revue**

Le dépôt fait déjà ~37 000 lignes avec une suite de tests actifs
conséquente. Tenter tout le roadmap d'un coup avec des agents de code est
justement le scénario que l'ancien plan voulait éviter (« un agent risquerait
de réécrire des composants fonctionnels »). On remplace les jalons par
version (v0.2.0 → v1.0.0 en 12 semaines) par une cadence par étape validée :
scheduler → revue humaine → graphe → revue humaine → etc. Pas de date fixe.

## 6. Prompt de lancement (agent de code), version resserrée

```
Mission : faire évoluer le crawler BFS de WebRev vers une frontière de
priorité déterministe, sans rien casser.

Contraintes non négociables : voir §1 de ce document. Ne pas toucher
PipelineItem/Stage. Ne pas introduire de dépendance externe pour la
frontière (BinaryHeap de la std suffit). Ne pas implémenter les phases du
§5 sans qu'on en discute d'abord.

Étape 1 — Audit (lecture seule) : lire webrev-pipeline/src/stages/fetch/,
discovery.rs, request.rs, sourcemaps.rs, stage.rs, engine.rs. Identifier
précisément où s'insère la frontière sans changer la forme de PipelineItem.
Produire un plan de migration avec chemins de fichiers exacts. Ne rien
modifier.

Étape 2 — Baseline : mesurer le BFS actuel sur une fixture locale
synthétique (ressources uniques, doublons, temps, mémoire, violations de
scope). Rendre ce baseline reproductible (script ou test).

Étape 3 — Scheduler : implémenter scheduler/{frontier,priority,fairness,
metrics}.rs sous webrev-pipeline/src/stages/fetch/. Stratégies bfs (baseline
de régression, comportement identique à l'existant) et best-first
uniquement. Tests : régression bfs avant/après, respect scope/budget/
concurrence sous best-first, fairness anti-starvation.

Arrêt obligatoire après l'étape 3 pour revue humaine. Ne pas enchaîner sur
le graphe de connaissance ni sur une autre phase sans accord explicite.

Standards : cargo fmt, cargo clippy --workspace --all-targets --all-features
-- -D warnings, cargo test --workspace --all-features après chaque étape.
```

## 7. Checklist réduite

**Fondations**
- [ ] Baseline BFS mesuré et reproductible
- [ ] Config TOML (si besoin réel identifié pendant l'audit — pas par
      anticipation)

**Scheduler (P0)**
- [ ] Frontière `BinaryHeap` + stratégies `bfs`/`best-first`
- [ ] Budgets partagés inchangés sous les deux stratégies
- [ ] Fairness anti-starvation testée
- [ ] Revue humaine avant de continuer

**Graphe (P0, après revue du scheduler)**
- [x] Nœuds/arêtes typés, bornés dès le premier commit (`resource` +
      `loads`/`links_to`/`maps_to`, bornes `MAX_GRAPH_NODES`/
      `MAX_GRAPH_EDGES`, marqueur `truncated`)
- [x] Export compatible avec `webrev-report` DOT/GraphML existant (étendu en
      place, pas un second système)
- [ ] Nœuds `Document`/`Framework`/`NetworkObservation` distincts, relations
      `Imports`/`References`/`ObservedDuring`/`Contains`/`ProducedBy`
- [ ] Structure vivante pendant le crawl (actuellement dérivée au rendu du
      rapport) — à ne reprendre que si un consommateur temps réel concret
      (ex. TUI) en a besoin

**Différé (P1/P2, non lancé sans décision explicite)**
- [ ] Adaptateurs frameworks
- [ ] Browser Engine 2.0 (extension, pas réécriture)
- [ ] Protocol Intelligence
- [ ] Refonte Secret Intelligence

**Rejeté / bloqué derrière une mesure**
- [ ] Fingerprinting SimHash/MinHash/LSH — nécessite un chiffre du baseline
- [ ] Bandit UCB1 — nécessite un invariant de plancher de sécurité testé
      avant toute implémentation
