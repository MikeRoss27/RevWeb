# Audit de fiabilité Webrev — 2026-10-15

Les causes recensées ci-dessous décrivent l'état initial avant les correctifs.
Les validations et limites actuelles sont ajoutées dans les sections de suivi.

## Pipeline et responsabilités

`webrev-cli` construit `Mission` et `OpsecConfig`; `webrev-pipeline` exécute
`fetch → static_extract → store` sur des canaux bornés. `fetch` collecte HTML,
JS, manifestes, WASM et source maps. `webrev-extract` exécute 17 extracteurs
purs, y compris sur les scripts inline. `store` déduplique, persiste dans
`webrev-storage` (mémoire) et crée la table des endpoints normalisés.
`webrev-browser` observe les appels navigateur et WebSocket. Le moteur `active`
envoie des GET optionnels via `ProbeClient`; `webrev-report`, CLI et TUI
présentent les findings. `webrev-core` définit modèle, scope et preuves.

## Matrice des détecteurs existants

La précision est **non mesurée** avant corpus labellisé; les niveaux ci-dessous
décrivent le mécanisme, pas un taux de précision.

| Détecteur | Signal / source | Limite de validation | Couverture |
| --- | --- | --- | --- |
| `js-ast` | appels fetch, axios, XHR, WebSocket; toutes chaînes URL | chaînes arbitraires confondues avec réseau | JS analysable |
| `html` | liens, formulaires, scripts | présence seulement | HTML |
| `js-regex` | appels et chaînes URL par regex | commentaires, chaînes et contexte mélangés | JS même malformé |
| `secret` | signatures et entropie | identifiants HTML/CSS, variables opaques | HTML, JS |
| `sourcemap` | commentaire `sourceMappingURL` | référence ≠ carte accessible | JS |
| `tech` | signatures framework/service | signature ≠ version ou configuration | HTML, JS, headers |
| `graphql` | opérations GraphQL statiques | opération ≠ endpoint accessible | JS |
| `routes` | chemins de route SPA | route client ≠ API | JS |
| `params` | query, champs HTML, clés objet | clé interne ≠ paramètre HTTP | HTML, JS |
| `config` | constantes et options | présence ≠ exposition sensible | JS |
| `manifest` | manifeste web et chunks | chemin statique ≠ requête | JSON |
| `buckets` | URL stockage | URL ≠ bucket accessible | HTML, JS |
| `jwt` | forme JWT | forme ≠ jeton valide | HTML, JS |
| `dom-sinks` | taint AST + sink regex | sanitizers absents; sink seul encore affiché | JS analysable + repli regex |
| `csp` | politique CSP | présence ≠ efficacité | HTML, headers |
| `ghost` | indices de routes/config | heuristique sans confirmation réseau | JS |
| `wasm` | imports, exports, chaînes URL | chaînes ≠ appels réseau | WASM |
| actifs | headers, cookies, CORS, fichiers, redirect, injection, expression, IDOR, traversal, CRLF, SSRF, pollution, GraphQL, takeover | signaux différentiels parfois non spécifiques | cibles GET sélectionnées, budget global |

## Causes racines et lacunes

- SSRF (`active/ssrf.rs`) : tout changement de statut ou de longueur produit un
  finding, même pour `redirect_uri`/`service`. Le test ne démontre aucun fetch
  serveur. `EvidenceVerdict::Signal` limite l'affirmation, mais le libellé
  « possible SSRF sink » reste trompeur.
- Secrets (`secrets/mod.rs`) : le passage entropie accepte tout littéral entre
  guillemets assez opaque, sans distinguer `id`, `class`, attributs CSS ou
  contexte d'affectation. Une signature de forme ne prouve pas sa validité.
- DOM XSS (`domsinks.rs`) : le flux source→sink existe déjà, mais aucune
  sanitation n'est modélisée; un repli regex émet un lead pour `innerHTML`
  sans source. La catégorie `Config` masque la nature de l'observation.
- Endpoints (`js_ast.rs`, `js_regex.rs`) : `visit_str` et les regex URL absolues
  relèvent toute chaîne, y compris documentation ou contenu de page. La table
  normalisée ne distingue pas route candidate et appel effectivement observé.
- Paramètres (`params.rs`) : toute clé d'objet JS quotée est une entrée de
  wordlist, même sans passage par fetch/XHR/formulaire.
- Déduplication (`stages/store.rs`) : première clé gagnante; les autres sources,
  méthodes et preuves sont abandonnées. La clé endpoint ignore la méthode.
- Couverture (`ActiveCoverage`) : compte tentatives et quelques erreurs, mais
  pas chaque résultat prévu/exécuté/refusé/ignoré par détecteur. Le reporting
  statique et dynamique ne différencie pas absence, non-test et négatif.
- Scope (`stages/fetch/request.rs`) : `Policy::limited(5)` peut suivre hors
  scope une redirection depuis une URL autorisée, avec headers d'auth par
  défaut. Le scope est contrôlé à l'enqueue, pas à chaque saut HTTP. La
  résolution DNS et les connexions navigateur demandent aussi une revue.

## Plan priorisé

| Priorité | Travail et dépendances | Fichiers majeurs | Risque |
| --- | --- | --- | --- |
| P0 | Bloquer les redirections crawl hors scope; rendre SSRF purement inconclusif sans preuve de fetch; établir états et preuves distincts de la sévérité | `fetch/request.rs`, `active/ssrf.rs`, `core/model/*`, `report/*` | compatibilité JSON, pertes de cibles après redirection |
| P0 | Préserver sources et preuves lors de la déduplication | `stages/store.rs`, `storage/*`, `core/model/finding.rs` | ordre des événements et tables endpoint |
| P1 | Restreindre secrets par contexte; taint DOM avec sanitizers; séparer chaînes JS des appels réseau; paramètres liés à un transport | `extractors/{secrets,endpoints,metadata}/*` | rappel sur JS minifié |
| P1 | États par test, budget et refus explicites dans la couverture; tests lab locaux | `active/*`, `core/model/evidence.rs`, `report/*` | taille rapport et bruit |
| P2 | Corpus indépendant, comparaison avant/après, CI, p95 et mémoire sur machine identique | `tests/*`, `.github/*`, `docs/*` | représentativité et environnement de mesure |

## Baseline

Commandes initiales exécutées avant tout changement du code produit, avec
`CARGO_TARGET_DIR=/home/na/.cache/webrev-target CARGO_INCREMENTAL=0
CARGO_PROFILE_DEV_DEBUG=0` pour éviter le volume du dépôt saturé :

- `cargo test --workspace --quiet` : **FAIL**, 1 test navigateur réussi,
  `profile::tests::config_builds_and_init_script_patches_webdriver` échoue
  (`profile.to_config().is_ok()`), 1 test ignoré; exécution interrompue par
  Cargo à ce crate. Une première tentative sur le volume du dépôt avait
  échoué pendant la compilation (`No space left on device`), sans test.
- `cargo test --workspace --exclude webrev-browser --quiet` : **PASS**, 216
  tests réussis, 1 ignoré, 0 échec dans les sept autres crates.

Le premier lancement de la suite sur le commit initial a échoué dans un test navigateur
qui exigeait Chrome, absent de l'environnement. Le test a été corrigé pour accepter
le diagnostic explicite d'exécutable manquant; la suite complète passe ensuite sur
la version modifiée. Un corpus de développement
minimal, `crates/webrev-extract/tests/reliability_benchmark.rs`, compare le
commit `61b843d` (worktree temporaire) et la version modifiée avec les mêmes
16 cas synthétiques (20 résultats car les deux extracteurs d'endpoints sont
mesurés). Commande :
`cargo test -p webrev-extract --test reliability_benchmark -- --nocapture`.

| Mesure | Avant (précision, rappel, FPR, FNR, FP) | Après (précision, rappel, FPR, FNR, FP) |
| --- | --- | --- |
| Endpoints AST | 0.667, 1.000, 0.500, 0, 1 | 1.000, 1.000, 0, 0, 0 |
| Endpoints regex | 1.000, 1.000, 0, 0, 0 | 1.000, 1.000, 0, 0, 0 |
| Paramètres HTTP | 0.500, 1.000, 1.000, 0, 2 | 1.000, 1.000, 0, 0, 0 |
| Secrets | 0.667, 1.000, 0.500, 0, 1 | 1.000, 1.000, 0, 0, 0 |
| Flux DOM XSS | 1.000, 1.000, 0, 0, 0 | 1.000, 1.000, 0, 0, 0 |

Le corpus est petit, construit pour développement et non indépendant. Les
résultats **ne valident pas** le seuil de précision de 95 %, le rappel global
ni les performances. Les cas SSRF sont vérifiés séparément par tests locaux :
une simple réflexion n'émet aucun finding SSRF; un texte de résolution DNS
reste un signal suspect, non une confirmation, et ne prouve pas qu'un appel
DNS serveur a eu lieu.
Temps p95, mémoire maximale et stabilité longue durée n'ont pas été mesurés;
aucune conclusion de performance avant/après n'est disponible.

### Budgets et résolution DNS

Une revue de l'étape 4 a trouvé une course : plusieurs cibles pouvaient lire le
même compteur avant l'incrément, puis toutes envoyer une requête. Chaque sonde
réserve maintenant atomiquement un créneau avant l'attente réseau. Le test
d'intégration `concurrent_targets_cannot_overshoot_shared_request_budget`
exerce 30 cibles avec un budget de 3 et vérifie le compteur et le serveur local.
Les clients HTTP directs utilisent aussi un résolveur qui conserve le premier
jeu d'adresses système obtenu pour chaque nom pendant la durée du client; les
redirections passent par ce résolveur après le contrôle URL du scope. Des tests
locaux vérifient la stabilité de `localhost` et la connexion via le client actif.

La validation actuelle ne classe pas les adresses comme publiques ou privées :
la résolution d'un hostname explicitement inclus est autorisée pour ce nom,
tandis que les règles IP/CIDR configurées filtrent les destinations directes.
Avec un proxy HTTP, la destination est généralement résolue par le proxy et
Webrev ne peut pas vérifier son IP finale; le proxy doit appliquer sa propre
politique de destination. Le DNS-over-HTTPS de `DnsPolicy` n'est pas implémenté
dans le pipeline actuel.
