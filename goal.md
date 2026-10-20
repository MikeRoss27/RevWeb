# WEBREV — Critères d'acceptation (Definition of Done)

Tu dois respecter les critères suivants pour considérer chaque étape comme terminée. Une fonctionnalité implémentée n'est pas nécessairement une fonctionnalité validée.

## Étape 1 — Audit architectural

**Critères d'acceptation :**
- [ ] Tous les détecteurs existants sont identifiés et documentés.
- [ ] Le pipeline complet, de la collecte au reporting, est cartographié.
- [ ] Chaque catégorie de faux positifs observés dispose d'une analyse de cause racine.
- [ ] Les lacunes de couverture et de validation sont identifiées.
- [ ] Une baseline reproductible est établie avant toute modification.
- [ ] Le plan P0/P1/P2 précise les dépendances, risques et fichiers concernés.

**Validation :** rapport d'audit vérifiable, baseline enregistrée et plan fondé sur le code réel.

## Étape 2 — Classification et preuves

**Critères d'acceptation :**
- [ ] Chaque finding possède un état explicite : `Observed`, `Suspicious`, `Confirmed` ou `Inconclusive`.
- [ ] Aucun finding ne devient `Confirmed` sans preuve reproductible correspondant à la vulnérabilité annoncée.
- [ ] Le niveau de confiance est indépendant de la sévérité.
- [ ] Les findings équivalents sont dédupliqués sans perte de preuves ni de provenance.
- [ ] Chaque finding conserve son détecteur, sa source, ses observations et sa justification.
- [ ] Les changements d'état sont testés automatiquement.

**Validation :** tests unitaires réussis et aucun finding confirmé artificiellement dans le corpus de référence.

## Étape 3 — Fiabilité des détecteurs

**Critères d'acceptation :**
- [ ] SSRF : une différence de statut HTTP ou une URL acceptée ne suffisent jamais à confirmer une SSRF.
- [ ] Secrets : les identifiants HTML, CSS et variables JavaScript ordinaires ne sont plus classés comme credentials.
- [ ] DOM XSS : les sources, transformations, mécanismes de sanitization et sinks sont analysés avant classification.
- [ ] Endpoints : les routes réseau observées sont distinguées des chaînes extraites statiquement.
- [ ] Paramètres : les variables JavaScript ne sont pas automatiquement considérées comme paramètres HTTP.
- [ ] Chaque détecteur possède des tests positifs, négatifs et de cas limites.
- [ ] Aucun détecteur existant n'est supprimé ou désactivé pour améliorer artificiellement les métriques.

**Objectifs de qualité sur un corpus labellisé indépendant :**
- Précision des findings `Confirmed` ≥ 95 %.
- Rappel global au moins égal à la baseline.
- Aucune régression connue sur les cas High/Critical de référence.
- Réduction mesurable des faux positifs.
- Aucun cas du corpus de régression ne doit échouer.

Ces objectifs sont des seuils de validation proposés, pas des performances actuellement démontrées. La taille et la représentativité du corpus doivent être documentées. Si elles sont insuffisantes, le résultat reste non validé.

## Étape 4 — Couverture et sécurité

**Critères d'acceptation :**
- [ ] Aucune requête n'est envoyée volontairement hors du scope configuré.
- [ ] Les redirections, résolutions DNS et destinations finales sont contrôlées.
- [ ] Les budgets de requêtes et limites de concurrence sont respectés.
- [ ] Les tests potentiellement destructifs sont interdits par défaut.
- [ ] Chaque test possède un résultat : exécuté, non exécuté, refusé, inconclusif ou erreur.
- [ ] Une couverture incomplète ne produit jamais un verdict « sécurisé ».
- [ ] Les User-Agent et autres exigences des programmes sont configurables.
- [ ] Les preuves sensibles sont protégées dans les journaux, erreurs et `Debug`, et les rapports sont masquables à l'export sur demande (`--redact`).

**Validation :** tests d'intégration sur environnement local contrôlé, dont tentatives simulées de sortie du scope et dépassement de budget, sans requêtes non autorisées.

**Suivi de validation (2026-10-16) :** le smoke test Chromium a été exécuté
avec `/usr/bin/chromium` sur une fixture loopback : la navigation, le script
et le `fetch` autorisés ont été observés, tandis que la ressource sur une IP
loopback distincte a été bloquée par le scope. Le test de navigateur reste
marqué `ignored` dans les tests ordinaires pour les CI sans Chromium; la
commande explicite et son résultat sont consignés dans `docs/changelog-reliability.md`.
La politique IP/CIDR d'un proxy qui résout les noms reste à la charge du proxy.
**État de l'étape 4 : PARTIEL.** La navigation locale et le blocage de
sous-ressources hors scope ont une preuve d'intégration Chromium. La validation
de la destination finale derrière proxy, la non-destructivité des interactions
dynamiques et la protection des secrets/preuves affichés restent à qualifier;
les critères correspondants ne sont pas déclarés satisfaits.

**Suivi (2026-10-18) :** audit exécuté de `RUST_LOG` contre une fixture avec
secrets factices : `chromiumoxide::conn` et `tungstenite` fuitaient Bearer,
cookies et en-têtes à `debug`/`trace`; ces cibles sont plafonnées à `error`
(`crates/webrev-cli/src/logging.rs`), 0 fuite mesurée aux trois niveaux ensuite.
Le critère « preuves sensibles protégées » reste décoché : paramètres d'URL de
nom inconnu et secrets de corps de forme inconnue subsistent (voir
`docs/security.md`).
**Suivi (2026-10-18, fuzzing) :** le run GitHub 39166754778 de `fuzz.yml` a
trouvé un JWT non masqué dans un segment de chemin. `redact_url` analyse
maintenant les segments, les noms de paramètres et les jetons préfixés connus,
`scrub` masque les valeurs courtes sous un nom sans ambiguïté, et le résumé
compact sur stdout passe par `redact_url`. Le critère reste décoché : le
résumé affiche le texte clair des secrets détectés, les rapports exportés ne
sont pas masqués, et les heuristiques ne couvrent pas les secrets courts sous
un nom quelconque (voir `docs/security.md`).
**Suivi (2026-10-19, rapports exportés) :** tous les formats d'export
savent masquer les identifiants (`SessionReport::redacted`) ; corrigé le jour
même : les identifiants d'objets ne sont plus masqués et `bola` accepte un
rapport masqué (voir `docs/security.md`, « Suivi : identifiants d'objets
lisibles »). Le texte clair des secrets détectés reste exporté volontairement.
**Décision de produit (2026-10-19, rapports bruts) :** l'export est **brut par
défaut**, car un chasseur de bugs a besoin des valeurs capturées pour prouver et
signaler ; `--redact` / `WEBREV_REPORT_REDACT=1` masque pour partager
(`--unredacted` est supprimé), et un rapport brut écrit dans un fichier affiche
un avertissement. Restent masqués dans tous les modes : journaux, erreurs,
`Debug`, ligne `dynamic: <seed>` et résumé compact de fin de scan. Le critère
a été reformulé en conséquence ; voir `docs/security.md`, « Suivi : rapports
bruts par défaut ». **Il reste décoché** : journaux, erreurs, `Debug` et
`--redact` sont couverts par des tests, mais les heuristiques de `--redact` ont
des trous documentés (secrets courts sous un nom de clé quelconque, secrets
dans le nom d'hôte), et l'affichage de la TUI à l'écran et le proxy en amont ne
sont pas audités. Le critère reste décoché : secrets courts sous un nom de clé
quelconque, secrets dans le nom d'hôte, affichage de la TUI et proxy en amont
restent non traités (voir `docs/security.md`, « Suivi : rapports exportés »).
**Suivi (2026-10-20, quatre trous sur cinq fermés) :** secrets courts sous un
nom de clé quelconque — `SecretExtractor::scan_body`, passe 1c
(`crates/webrev-extract/src/extractors/secrets/mod.rs`) : une valeur
assignée (`:`/`=` simple, pas `==`/`===`) à une clé sans ambiguïté
(`password`, `sid`, `bearer`, …) est signalée même trop courte pour
l'entropie, sauf littéral booléen/`null` ou placeholder. Secrets dans le nom
d'hôte — `scan_hostname` fait tourner les mêmes motifs connus sur
`Url::host_str()`, plus un repli entropie limité à des labels de 20 à 63
caractères (évite les hash de build/CDN courts). Affichage de la TUI à
l'écran — `skip_out_of_scope_message`/`dynamic_error_message`
(`crates/webrev-tui/src/runtime/controller.rs`) passent désormais par
`redact_url`, comme l'équivalent CLI. Proxy en amont — audit effectué sur
deux chemins distincts : `egress_proxy::parse_upstream`
(`crates/webrev-browser/`, proxy du navigateur dynamique) rejetait déjà une
URL avec identifiants embarqués mais sans aucun test (deux tests ajoutés) ;
le flag `--proxy` du scan statique (chemin reqwest séparé, CLI) a été
exercé pour la première fois avec un vrai identifiant sous `RUST_LOG=trace`
(`crates/webrev-cli/tests/proxy_redaction.rs`) — ni stdout/stderr ni le
rapport écrit ne contiennent le mot de passe en clair ou l'en-tête
`Proxy-Authorization` encodé en base64. Reste décoché, hors périmètre de ce
correctif : un secret coupé par la troncature à 256 caractères d'un extrait
de sonde (`webrev-pipeline/src/active/bola_diff.rs::body_excerpt`) — un
problème distinct (troncature d'une preuve active, pas détection de
secret) qui demande sa propre analyse.
**Suivi (2026-10-20, cinquième et dernier trou fermé) :** ce trou était réel,
pas théorique — confirmé par une reproduction avant correctif. Un JWT placé
sous un nom de paramètre que `Sanitizer` ne reconnaît par aucun motif nommé
(`?v=<jwt>`, ni « token », ni « key », ni « session »…) n'est reconnu comme
secret que par sa structure à trois segments ; coupé en deux par la
troncature à 256 caractères de `ProbeResponse::observation`
(`active/transport.rs`), 65 caractères de son en-tête et de ses revendications
en clair (`"role":"admin"`, `"sub":"1234567890"`) survivaient à
`Sanitizer::scrub`, donc à `--redact`. Même mécanisme pour l'extrait de preuve
`bola` (`active/bola_diff.rs::body_excerpt`, coupe à 4 KiO). **Corrigé** : la
coupe recule désormais au début de toute suite de caractères de forme jeton
(12 à 200/256 caractères selon la limite) plutôt que de la traverser, donc un
secret est gardé entier ou absent, jamais tronqué en deux ; au-delà de cette
borne (un extrait dominé par un seul bloc opaque, plus probablement une donnée
qu'un secret), la coupe naïve d'origine s'applique comme avant. Détails,
reproduction et compromis dans `docs/security.md`, « Suivi : secret coupé par
la troncature de l'extrait de sonde ». **Les cinq trous identifiés sont
désormais fermés.** Le critère « preuves sensibles protégées » peut être
considéré comme satisfait pour les heuristiques `--redact` connues à ce jour ;
voir `docs/security.md` pour le détail de chaque correctif et les limites
restantes non encore identifiées.

## Étape 5 — Benchmarks et non-régression

**Décision corpus :** XBOW ne sera pas utilisé comme benchmark de précision
principal; il mesure des objectifs CTF de bout en bout et son dépôt signale
que la suite est saturée. Voir `docs/benchmark-methodology.md` pour le plan
retenu : corpus JavaScript/HTML indépendant et labellisé pour les détecteurs,
complété par des tests locaux et OWASP VulnerableApp pour le DAST.
**Suivi (2026-10-16) :** vérification exploratoire de VulnerableApp au commit
`8003daf8e13044802fdeb4b665f0c9cc6d09096b` terminée dans un réseau Docker
interne : 43 findings statiques et 17 findings navigateur (60 au total), dont
17 endpoints observés; aucun candidat vulnérabilité/secret. Le scan n'a visité
que l'entrée de l'application et n'a pas exécuté de probes actives ni comparé
les scénarios au ground truth. Ce résultat ne constitue donc pas une mesure de
précision/rappel. L'archive JsVul et ses labels ont été inspectés : le split
test contient 1 726 enregistrements (203 positifs, 1 523 négatifs selon son
champ `label`), mais reste non validé et non incorporé. Détails et limites dans
`docs/benchmark-methodology.md`.

**Collecte externe (2026-10-17) :** sélection byte-preserving de 30 cas SWIPE
DOM XSS (32 fichiers HTML/JS), deux archives MIT/Apache-2.0 épinglées (Firing
Range et Security Defect Corpus), inventaire et SHA-256 ajoutés sous
`benchmarks/external-candidates/`. Le premier run SWIPE (TP=13, FP=1, FN=3,
TN=12, 1 inconclusif) a motivé deux corrections : les résultats numériques de
`search()` ne propagent plus la taint de chaîne, et les sinks événementiels
dynamiques sont reconnus. Le rerun donne TP=14, FP=0, FN=2, TN=13 et
1 inconclusif : précision 100 %, rappel 87,5 %, FPR 0 %, FNR 12,5 % sur cette
sélection revue manuellement. Restent deux misses : flux inter-fichier et
alias de champs. Ce résultat est un diagnostic petit, mainteneur-revu et non
indépendant. Aucune URL réelle du corpus SWIPE n'a été scannée. Détails dans
`docs/benchmark-methodology.md`.

**Corpus externe v1 (2026-10-19) :** `benchmarks/external-corpus/v1/` ajoute
331 cas sur cinq sources dont les labels viennent d'un tiers indépendant de ce
dépôt (15 CVE GitHub Security Advisory DOM XSS avec leur commit de correction,
le dataset `sak3y/ML-XSS-Detector`, les challenges `pwnfunction`, les pages de
test du scanner `domdig`, et 28 fichiers npm non labellisés). Aucun code tiers
n'est commité : `sources.json` épingle chaque entrée par SHA de commit ou
version npm, `manifest.json` enregistre le SHA-256 de chaque fichier,
`scripts/external_corpus.py fetch` télécharge dans un cache ignoré par git et
échoue si un octet diffère. Premier run sur le détecteur au commit `6b33d8d` :
précision 100 % partout où elle est mesurable (0 faux positif), mais rappel
**0 % sur les 15 CVE GHSA et 0 % sur les 14 challenges pwnfunction**, 20 %
sur sak3y (124 positifs), 25 % sur domdig. Ce résultat contredisait la lecture
optimiste du run SWIPE ci-dessus (rappel 87,5 %, corpus maintenu par ce
dépôt) : le détecteur généralisait mal dès qu'il voyait du code DOM XSS qu'il
n'avait pas été ajusté sur. Limites du protocole (à ne pas lisser) : l'unité
d'évaluation est un fichier, pas un flux inter-fichiers (les CVE avec flux
coupé entre fichiers comptent comme ratées par construction) ; `sak3y` n'a
qu'un seul labelleur, sans mesure d'accord ; les métriques ne sont jamais
regroupées entre sources. Détails et protocole figé avant le run dans
`benchmarks/external-corpus/v1/README.md`.

**Correction (2026-10-19, règles de taint manquantes) :** l'investigation des
cas ratés a trouvé deux règles de flux absentes du traqueur de taint
(`crates/webrev-extract/src/extractors/metadata/domsinks/taint.rs`), pas des
cas limites obscurs : `new URL(tainted)` / `new URLSearchParams(tainted)`
n'étaient jamais classés comme source (donc `new URL(location).searchParams
.get(...)`, l'idiome dominant des cas pwnfunction/sak3y, échappait entièrement
à l'analyse), et `classify()` ne traitait que `+` parmi les opérateurs
binaires, pas `||`/`??`/`&&` (donc l'idiome `param || "défaut"`, omniprésent
dans le corpus, cassait la taint). Les deux ont été ajoutées avec des tests
positifs/négatifs dédiés. Rerun : pwnfunction 0 % → 57 % de rappel (8/14),
sak3y 20 % → 52 % (65/124), GHSA 0 % → 6,7 % (1/15, la plupart des cas
restants sont multi-fichiers via `postMessage`, hors de la portée intra-
fichier documentée plus haut), domdig inchangé (25 %, aucun de ses cas
n'utilise ces idiomes). Un faux positif est apparu sur `sak3y/snippet_179`
(précision 100 % → 98,5 % sur cette source) : un encodage d'entités HTML
manuel (`.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')`)
avant `innerHTML`, que le détecteur ne reconnaît pas comme un assainissement
— seul `DOMPurify.sanitize` casse la taint aujourd'hui. Reconnaître
l'encodage d'entités manuel comme un assainisseur reste à faire. Les 4
autres cas pwnfunction encore ratés passent tous par `DOMPurify.sanitize`
(bypass volontaire du CTF) sauf un (`bourne`), qui est une confusion de clé
d'objet, pas une injection DOM. Détails dans
`benchmarks/external-corpus/v1/README.md` et les résultats rejoués.

**Correction (2026-10-19, encodage d'entités manuel reconnu comme
assainisseur) :** le faux positif `sak3y/snippet_179` ci-dessus est corrigé.
`classify_call()` reconnaît désormais une chaîne de `.replace(pattern,
entité)` (littéral d'un caractère ou regex `/…/g` d'un caractère) comme
cassant la taint, mais seulement quand la chaîne couvre à la fois `<` → `&lt;`
et `>` → `&gt;` — les deux caractères qui permettent réellement l'injection de
balises ; `&`/`"`/`'` seuls sont reconnus comme des liens de la chaîne mais
n'en suffisent pas à casser la taint. Un seul `.replace()` isolé, sans rapport
avec un échappement HTML, continue de propager la taint (règle générique de
préservation des méthodes de chaîne, inchangée). Le repli regex
(`sanitizer_wraps_sink` dans `domsinks.rs`) a dû être étendu en miroir : sans
ça, une instruction que la passe AST juge déjà assainie (donc sans trace)
déclenchait encore le lead « unverified source » de bas niveau, en
contradiction avec son propre verdict — même logique que le cas
`DOMPurify.sanitize` déjà présent. Trois tests ajoutés dans
`domsinks_tests.rs` : la chaîne complète (`sak3y/snippet_179`) ne produit plus
de lead ; une chaîne partielle (seul `&` échappé) continue de tracer ; un
`.replace()` isolé et sans rapport continue de tracer. Rerun du corpus externe
v1 : précision sur `sak3y` 98,5 % → 100 % (0 FP), rappel sak3y inchangé à
52 % (65/124) puisque ce cas était déjà un vrai négatif pour la taint, pas un
cas raté différemment. Aucune régression observée sur les autres sources
(`ghsa`, `pwnfunction`, `domdig`, `npm`) ni sur la suite statique/synthétique.
Portée volontairement restreinte : seules les paires littérales reconnues
(un caractère, correspondance exacte à l'entité canonique) comptent ; une
regex multi-caractères (`/[&<>]/g`), une fonction de remplacement, ou un
encodage via une bibliothèque autre que `DOMPurify` restent non reconnus et
sont un faux positif potentiel documenté, pas corrigé ici.

**Correction (2026-10-20, liaison inter-fichiers pour `postMessage`,
rappel GHSA inchangé) :** la majorité des cas GHSA ratés avaient été
attribués par hypothèse à des flux `postMessage` inter-fichiers hors de la
portée intra-fichier existante. `modules.rs` (nouveau sous-module
`handlers.rs`) lie maintenant `window.addEventListener('message',
imported)` / `addEventListener('message', imported)` à travers les
fichiers quand `imported` est un identifiant importé (nommé ou par défaut,
un seul saut, pas via un barrel de ré-export) d'une déclaration `function`
de premier niveau d'un autre module : le premier paramètre de cette
déclaration est semé comme `event.data` et son corps analysé exactement
comme un handler `message` du même fichier. Six tests dédiés
(`tests_handlers.rs`) confirment le cas lié et les limites volontaires
(membre de namespace, registre calculé, barrel de ré-export, handler
d'expression plutôt que de déclaration — tous non liés). **Rappel GHSA
inchangé : 6,7 % (1/15).** Lecture des 14 cas GHSA toujours ratés dans le
cache local du corpus (`benchmarks/external-corpus/v1/cache/ghsa/`) :
l'hypothèse ne tient pas. Les CVE réels enregistrent et distribuent les
messages `postMessage` via des méthodes d'objet et des tables de dispatch
par type de message (`api.source.postMessage(...)`, un gestionnaire
affecté dynamiquement à `api.xxxHandler`), pas via une simple fonction
`function` de premier niveau importée puis passée directement à
`addEventListener`. Ce motif plus riche (fermetures, méthodes, dispatch
par type) reste explicitement hors de portée (voir
`docs/extractors.md`). La fonctionnalité livrée ici est correcte et
testée sur son périmètre déclaré ; elle ne corrige simplement pas la
cause réelle des misses GHSA de ce corpus. Aucune régression sur les
autres sources (`sak3y`, `pwnfunction`, `domdig`, `npm`).

La suite synthétique existante a été exécutée : cinq checks, chacun TP=2,
FP=0, FN=0, TN=2. Elle reste une suite de régression, pas une estimation de
qualité.

Le corpus statique `benchmarks/static-corpus/v1/` comprend 50 cas annotés (40
snippets distincts), cinq détecteurs, des cas positifs/négatifs/ambigus et des
splits dev/validation séparés par famille. Résultats actuels exécutés : AST endpoints, regex endpoints, paramètres HTTP,
secrets et DOM source→sink ont chacun TP=4, FP=0, FN=0, TN=4. Les exemples et
labels sont écrits par les mainteneurs, très petits et visibles; ce corpus
n'est ni indépendant ni représentatif et ne valide pas les seuils de précision
ou rappel. La suite des métriques expose ces limites sans les masquer.

Pour le détecteur de redirections, l'adaptateur et le benchmark VulnerableApp
sont archivés sous `benchmarks/vulnerableapp/2026-10-16/open-redirect/`. Avec
les mêmes 12 routes et le plafond de 160 requêtes, le run trouve 8/9 cas
vulnérables (TP=8, FN=1), sans FP. Le niveau sécurisé 12 testé séparément donne
un seul TN; le niveau 11 a été refusé. Ces résultats (précision 100%, rappel
88,9%, FPR 0%, FNR 11,1%) sont limités à ce petit lab. Le comparateur complet
rapporte 8/168 correspondances, dont 159 cas hors tranche et le miss du niveau
7; il ne faut pas interpréter ces 159 cas comme des TN.

Une comparaison statique avant/après a aussi été exécutée sur les mêmes 50
cas, avec baseline propre `61b843daf845946060abae026b43349170ff177b` et le même
runner. AST endpoints, paramètres HTTP et secrets passent chacun de
TP=4/FP=2/FN=0/TN=2 à TP=4/FP=0/FN=0/TN=4; DOM reste à TP=4/FP=0/FN=0/TN=4.
La regex endpoints passait de TP=4/FP=2/FN=0/TN=2 à TP=3/FP=1/FN=1/TN=3.
Après correction des WebSocket et des commentaires, le corpus actuel donne
TP=4/FP=0/FN=0/TN=4. Ces deltas mesurent les fixtures maintainer-authored
uniquement et ne remplacent pas une validation externe.

Le premier benchmark apparié, archivé dans `benchmarks/performance/2026-10-16/`,
mesure sur une petite fixture 40 pages un p95 de 22,130 ms → 25,134 ms
(+13,57%) et une RSS max de 19 536 → 19 684 KiB (+0,76%). Un profil SPA
synthétique élargi, archivé dans `benchmarks/performance/2026-10-16/spa-site/`,
comprend 120 routes, 11 bundles JS, CSS, SVG, formulaires et navigation. Sur
20 scans par révision, une première mesure avait un p95 de 183,435 ms
(+511,72%). Le benchmark SPA 120 routes est archivé sous
`benchmarks/performance/2026-10-17/spa-site-final/` : p95 32,352 → 39,817 ms
(+23,07%), RSS max 22 976 → 22 976 KiB (+0,00%), 574 → 760 findings,
40/40 scans réussis. Le seuil RSS passe, mais le seuil p95 de 20% échoue.
Cargo a réécrit le lockfile baseline pour refléter ses manifestes; son hash
post-build égale celui de `HEAD`. Le diff de lockfile ne montre que les arêtes
de dépendances locales : aucune version ni checksum de paquet externe ne
change. La dérive de versions externes n'explique pas le delta observé. La
comparaison mêle encore code et arêtes locales, donc n'attribue pas le coût à
l'index mémoire; la fixture reste synthétique.

Un probe externe OWASP Juice Shop v19.0.0 (MIT, commit épinglé) est archivé
sous `benchmarks/juice-shop/v19.0.0/`. Après ajout de reconnaissance générique
des appels Angular HttpClient, trois positifs sur quatre sont détectés; le flux
DOM XSS Angular composant→template reste manqué. Sans négatifs, ce probe ne
mesure ni précision ni FPR. Il documente la compatibilité, pas une validation
générale. Un corpus académique positif multi-fichiers DOM XSS est également
audité et exécuté sous `benchmarks/external-domxss/multifile-v1/` : sur les 122
cas dont les catégories source/sink sont modélisées, aucune correspondance
exacte inter-fichiers n’est détectée (0/122). Chaque module est extrait
séparément : ce diagnostic mesure la couverture de propagation entre fichiers,
pas le rappel intra-fichier. Ses 342 variantes dérivent de 69 cas et il ne
contient aucun négatif.
L'audit des candidats externes est consigné sous
`benchmarks/external-audit/2026-10-16/`; aucun candidat n'est assez large et
équilibré pour valider la précision générale. Le suivi JsVul v1 repère 28 paires
CWE-79 test (fonction vulnérable/corrigée), mais les labels sont dérivés des
correctifs et CWE-79 n'isole pas le DOM XSS. La revue source/diff/licence les
classe en 13 candidats DOM/client, 3 ambigus, 4 sanitizer/contexte, 5 serveur/
hors DOM et 3 labels douteux/flux incomplets. Les licences sont MIT/Apache pour
17 paires, GPL/LGPL pour 5 et custom/non identifiées pour 6. Aucun code n'a été
intégré ou évalué; le corpus reste trop petit et hétérogène pour valider l'étape
5. Voir le tableau par paire dans `benchmarks/external-audit/2026-10-16/README.md`.

La CI inclut les corpus Rust (dont le probe diagnostique Juice Shop), tests
Python, hashes, formatage, build, Clippy et tests workspace. Les équivalents
locaux sont passés, dont les tests Python sous Python 3.12.14 via `uv`; le
workflow GitHub distant a depuis été exécuté et est vert (voir « Mise à jour
2026-10-18 » ci-dessous). Le contrôle de taille de source
n'a plus d'exception : `domsinks.rs` a été découpé en modules (PR #10).

**État de l'étape 5 : EN COURS — non validée.** *Mise à jour 2026-10-19 :* première
mesure selon le critère poolé (voir « Définition de la mesure », étape 5) sur `main`
`6b33d8d`, 6 invocations propres de 30 paires (180 par révision) : p95 **+16,0 %**,
IC à 95 % **+12,3 % à +20,5 %** → borne haute au-dessus de 20 % : **non démontré**.
RSS max +4,4 %, médiane +11,6 % (conforme). Une réplication de 6 invocations, lancée
*après* ce premier résultat, donne +15,0 % (IC +10,1 % à +18,8 %) et les 12 ensemble
+15,2 % (IC +12,2 % à +18,5 %), donc conformes ; comme la réplication a été décidée
après avoir vu le premier lot, la case n'est pas cochée sur cette base (arrêt
optionnel) : à vous de dire si le pool de 12 fait foi ou s'il faut un troisième lot
déclaré à l'avance. Détail, par extracteur et fichiers :
`benchmarks/performance/2026-10-19/spa-site-pooled/`. Mesure du 2026-10-18 :
la remesure sur machine calme du
2026-10-18 (`main` b3f5e42, binaires fixes, 10 invocations propres de 30 paires,
voir « Remesure performance sur machine calme » plus bas) donne, poolé sur 300
paires, un p95 de +16,8% (limite +20%) et une RSS de +13,3% en médiane / +11,1%
au max (limite +25%). Mais un p95 isolé de 30 paires dépasse 20% dans 3
invocations sur 10 (+20,1 / +24,7 / +21,1%) et une invocation a montré une base
anormalement basse (+48% de RSS, non reproduite, cause non établie) : le critère
tel qu'écrit n'est pas atteint de façon reproductible et reste non coché. La
remesure précédente (3 runs avec rebuilds, base instable) est conservée plus bas.
Les profils antérieurs ci-dessus,
dont le PASS du 2026-10-17 (p95 +18,64%, RSS +6,69%), sont historiques. Le corpus
statique ne montre plus de régression regex. La couverture externe DOM XSS
inter-fichiers atteint 105/122 sur les catégories compatibles (26/122 était un jalon
historique, voir la mise à jour du 2026-10-18); Juice Shop reste
à 3/4 positifs.
Les jeux externes sont positifs seulement ou trop étroits; un corpus négatif
et des labels indépendamment revus manquent. Python 3.12.14 et les équivalents
locaux CI sont vérifiés; le workflow GitHub distant a été exécuté (vert, voir
« Mise à jour 2026-10-18 »).
Les preuves actuelles ne démontrent donc pas la généralisation.

**Reprise parallèle (2026-10-17, suivi le plus récent) :** la propagation de
valeurs entre imports ES explicites est implémentée et branchée au pipeline
statique pour les modules déjà collectés. Sur le même corpus externe, la
couverture exacte passe de 0 à **26/122**, soit 13/25 paires source/sink
(type01 13/25, type02 13/22, types03–05 0/25 chacun). Les candidats restent
`Suspicious`, confiance `Medium`, avec provenance source et sink. Les fonctions
exportées, imports namespace, réexports `from`, scripts classiques et flux
interprocéduraux restent hors couverture inter-fichiers; l'initialisation des
exports doit être rectiligne. Bornes : 128 modules, 512 KiB/module, 8 MiB au total,
huit passes. Aucun fetch supplémentaire. Résultats et log sous
`benchmarks/external-domxss/multifile-v1/linked-results.json` et `linked-run.log`;
le résultat 0/122 précédent est conservé comme baseline.

Le résolveur d'endpoints réutilise les seeds et une base source en cache borné;
la normalisation UUID évite une allocation par segment. SWIPE conserve
TP14/FP0/FN2/TN13 et un inconclusif; ses 32 fichiers sont désormais exercés,
les résultats sont protégés par des assertions par cas et la CI vérifie les
hashes. Validation exécutée sur target neuf Btrfs : **299 tests workspace
réussis, zéro échec, deux ignorés**, Clippy strict, formatage, taille source,
12 tests Python et checksums externes réussis. Après la dernière correction
de style, les trois tests d'intégration pipeline passent également. La première
tentative sur le target NTFS a échoué sur un artefact inaccessible (`EINVAL`)
avant les assertions; aucun verdict fonctionnel n'en est déduit. Les limites
de corpus et l'absence de workflow GitHub distant demeurent. Le benchmark de
la version intégrée est consigné séparément sous
`benchmarks/performance/2026-10-17/spa-site-optimized/`; les chiffres de
performance précédents restent des mesures historiques.

**Mise à jour 2026-10-18 (état de `main` à 6cfd10f, merge de la PR #5) :**
- Couverture exacte du corpus externe multi-fichiers : **105/122** (et non
  26/122, qui est un jalon historique). Source : `docs/changelog-reliability.md`
  (« DOM XSS entre fichiers : branches, boucles, helpers », 63 → 105/122) et
  plancher de non-régression du test à 105. Les JSON archivés sous
  `benchmarks/external-domxss/multifile-v1/` (`function-results.json`: 63/122)
  n'ont pas été régénérés pour 105 : le chiffre repose sur le changelog et le
  test, pas sur ces fichiers. Ce corpus reste positif seulement.
- Tests : **350 réussis, 0 échec, 8 ignorés** sur le job `test (ubuntu-24.04)`
  du run CI 39073647553 (commit 6cfd10f). Le chiffre 299 est historique.
- CI distante : exécutée et verte sur `main`, run CI 39073647553 et run
  Security 39073647540 (jobs : test ubuntu/macOS/Windows, lint, msrv, python
  scripts, browser integration chromium, detection regression, gate `ci`).
- `bundles.yml` déclenché à la main sur `main` : run 39096637766, vert sur les
  quatre cibles (x86_64-pc-windows-msvc, x86_64-unknown-linux-gnu,
  x86_64-apple-darwin, aarch64-apple-darwin), avec build, packaging, vérification
  d'installation native et envoi des artefacts. Non vérifié : le chemin tag/release
  (`release.yml`) qui appelle ce workflow.

**Remesure performance (2026-10-18, code de `main` 6bdc3cc, sources Rust
identiques à 00f58f0) : p95 PASS, RSS FAIL / non validée.** Trois runs de 30
paires (`scripts/benchmark_performance.py`, base `61b843d`, 120 pages, profil
site), archivés sous `benchmarks/performance/2026-10-18/spa-site-remeasure/` :

| Run | p95 base → actuel | Δ p95 | RSS max base → actuel | Δ RSS |
|---|---|---:|---|---:|
| 1 | 35,386 → 39,542 ms | +11,74% | 20 660 → 22 012 KiB | +6,54% |
| 2 | 32,393 → 37,303 ms | +15,16% | 15 928 → 23 116 KiB | +45,13% |
| 3 | 31,900 → 36,310 ms | +13,81% | 15 824 → 22 356 KiB | +41,28% |

La RSS du code actuel est stable (médiane 20,9-21,2 MiB), celle de la base ne
l'est pas (médiane 18,9 MiB au run 1, 14,5 MiB aux runs 2 et 3, 20,7 MiB le
2026-10-17) et la cause n'est pas établie : la comparaison RSS n'est donc pas
fiable et aucun PASS n'est revendiqué. Machine non isolée (charge 1 min de 3,7
à 5 avant chaque run, 14-17 juste après; les builds du script précèdent la
mesure). Le PASS ci-dessous date d'avant ces changements.

**Remesure performance sur machine calme (2026-10-18, `main` b3f5e42) : RSS
conforme, p95 conforme en poolé mais pas de façon reproductible → non validé.**
Les deux binaires sont construits une seule fois et réutilisés (`--baseline-bin`,
`--current-bin`; un second build de la base donne un binaire identique, SHA-256
`082e27b3…`). 14 invocations de 30 paires (seeds différents, base `61b843d`,
120 pages, profil site), archivées sous
`benchmarks/performance/2026-10-18/spa-site-remeasure-quiet/` (README, JSON,
`SHA256SUMS`). Charge 1 min de 1,0 à 1,8 au départ des invocations propres.

| Mesure (invocations propres 2-11, 300 paires par révision) | Base | Actuel | Δ | Limite |
|---|---:|---:|---:|---:|
| p95 poolé | 77,2 ms | 90,2 ms | +16,8% | +20% |
| temps médian | 72,6 ms | 84,2 ms | +16,0% | – |
| RSS médiane | 19 130 KiB | 21 676 KiB | +13,3% | – |
| RSS max | 20 328 KiB | 22 580 KiB | +11,1% | +25% |

- RSS : de +9,8% à +15,5% (max) dans 10 invocations sur 10 quand la base est dans
  son mode habituel (19,1 MiB). Une invocation (la première après les builds) a
  mesuré une base à 14,4 MiB, soit +48%; non reproduite sur les 13 suivantes. Pas
  la cause : le build (binaire identique), l'ordre des runs, la charge (19,1 MiB
  aussi à charge 8-11). Hypothèse non démontrée : état du cache de pages ou THP
  (`always` sur cet hôte). Un échauffement non mesuré (2 runs par binaire) a été
  ajouté au script.
- p95 : un p95 de 30 paires est la 29e valeur sur 30 et varie de +9,9% à +24,7%
  sur les mêmes binaires; 3 invocations sur 10 dépassent 20% (+20,1 / +24,7 /
  +21,1%). Le médian est stable à environ +16%.
- Les temps absolus sont environ deux fois ceux du 2026-10-17 (p95 base 77 ms
  contre 38 ms) : comparer les rapports, pas les millisecondes.

**Résultat performance intégré du 2026-10-17 : PASS (historique).** Avec 30 paires et un lanceur C
qui isole la mémoire du scanner de celle du harness Python, p95
38,081 → 45,178 ms (**+18,64%**), RSS max 20 748 → 22 136 KiB (**+6,69%**),
574 → 760 findings et **60/60 scans réussis**. Le run natif précédent
(+21,43% p95, +14,55% RSS) est conservé sous `spa-site-native-pre-regex/`.
Deux préfixes Unicode optionnels inutiles ont ensuite été supprimés des regex
HttpClient : les captures sont vérifiées équivalentes et la compilation des
deux regex économise environ 0,590 ms dans un microbenchmark distinct. Ce coût
isolé ne permet pas d'attribuer tout l'écart entre les runs end-to-end au code,
car la machine héberge d'autres processus. Le lanceur historique Python
pouvait inclure sa RSS héritée; ses chiffres mémoire ne doivent pas être pris
comme une mesure isolée du scanner. La commande canonique utilise désormais
`scripts/measure_process.c`. Les versions et checksums des 426 paquets externes
sont identiques entre baseline et candidat; seules les arêtes locales du lock
diffèrent. Les deux seuils passent sur cette fixture synthétique, sans garantie
de généralisation à tous les sites.

**Critères d'acceptation :**
- [x] Comparaisons appariées statiques, DAST et performance exécutées sur fixtures/configurations/budgets identiques; la qualité générale reste à valider.
- [x] Les métriques TP/FP/FN/TN, précision, rappel, FPR et FNR sont calculées et vérifiées sur les corpus/lab exécutés.
- [x] Le corpus statique distingue les splits dev et validation par famille (sans prétention d’indépendance).
- [x] Équivalents locaux CI passés : formatage, taille source, 12 tests Python, checksums, tests workspace, Clippy strict.
- [x] Workflow GitHub distant exécuté et vert sur `main` (run CI 39073647553, commit 6cfd10f); équivalents locaux exécutés avec Python 3.12.14 via `uv`.
- [x] Tests workspace et corpus relancés après les changements actuels; aucun échec observé.
- [ ] Profil SPA, critère poolé (révisé le 2026-10-19) sur `main` 6b33d8d : lot prévu de 6 invocations (180 paires/révision) p95 +16,0 % mais IC 95 % haut +20,5 % → non démontré ; réplication de 6 (décidée après coup) +15,0 % (haut +18,8 %), 12 ensemble +15,2 % (haut +18,5 %), RSS max +4,4 %. Case non cochée tant que le pool de référence n'est pas tranché (voir « État de l'étape 5 »). Mesure précédente, critère d'origine (b3f5e42, machine calme, binaires fixes, 300 paires) : p95 poolé +16,8% (≤20%) mais >20% dans 3 invocations sur 10 de 30 paires; RSS +9,8 à +15,5% (≤25%) dans 10 invocations sur 10, avec une invocation à base anormalement basse (+48%) non reproduite, cause non établie. Non reproductible au sens du critère écrit, donc non coché. Le PASS du 2026-10-17 (p95 +18,64%, RSS +6,69%, 60/60 scans réussis) précède ces changements. Pour mémoire, le lockfile baseline est réécrit pour ses arêtes locales, sans changement de version/source/checksum des paquets externes.
- [ ] Corpus externe représentatif avec positifs et négatifs, labels examinés indépendamment.

**Objectifs de performance :**
- Surcoût de temps d'exécution p95 ≤ 20 %.
- Augmentation de mémoire maximale ≤ 25 %.
- Aucun crash ou comportement non déterministe identifié dans les tests de stabilité.

**Définition de la mesure (révisée le 2026-10-19, fixée AVANT la mesure qui
l'applique).** Les seuils ne changent pas (p95 ≤ +20 %, RSS max ≤ +25 %). Ce qui
change est la façon de les estimer. *Raison :* le texte d'origine appliquait le
seuil à un p95 calculé sur 30 exécutions, soit la 29e valeur sur 30. Sur les
mêmes binaires, ce nombre varie de +9,9 % à +24,7 % d'une invocation à l'autre
(remesure du 2026-10-18, 10 invocations) : il mesure le bruit, pas le code. Le
critère est donc exprimé sur un pool, avec son incertitude :

- *Pool :* au moins 3 invocations propres et au moins 90 exécutions par révision,
  mêmes binaires fixes (`--baseline-bin` / `--current-bin`), baseline `61b843d`,
  profil `site` de 120 pages. Une invocation est « propre » si la charge 1 min
  était sous 4 pendant toute sa durée ; les autres sont exclues et listées.
- *p95 :* p95 au rang le plus proche calculé sur le pool entier, avec un
  intervalle de confiance bootstrap à 95 % à deux niveaux (ré-échantillonnage des
  invocations, puis des exécutions dans chacune ; 2 000 tirages, graine fixe
  20261019) sur le rapport p95 actuel / p95 baseline.
- *Verdict PASS :* l'estimation ponctuelle ET la **borne haute** de l'IC à 95 % du
  p95 sont ≤ +20 %. *Justification de la borne haute :* l'objectif est de
  démontrer l'absence de régression au-delà de 20 %, pas seulement de ne pas
  l'observer ; une estimation à +17 % avec une borne haute à +26 % n'exclut pas
  une régression de 26 %. C'est plus strict que le critère d'origine, assumé.
  Si l'estimation passe mais pas la borne haute : *non démontré* (case non cochée),
  avec les chiffres.
- *RSS :* RSS max du pool ≤ +25 % ; la médiane de RSS et son IC sont rapportés.
  Une invocation dont la base s'écarte de plus de 15 % de la médiane des autres
  est signalée comme anormale (sans être retirée silencieusement : elle est
  listée et son effet sur le pool est donné).
- *Temps médian :* rapporté avec son IC, à titre indicatif (pas de seuil).

L'ancienne formulation (p95 de 30 exécutions ≤ +20 %) reste citée comme
historique dans les résultats ci-dessous, et chaque mesure est rapportée selon
les deux définitions.

Toute exception doit être chiffrée, justifiée et signalée avant validation.

## Étape 6 — Livraison finale

**Critères d'acceptation :**
- [ ] `cargo fmt --check` réussit.
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` réussit, ou les exceptions préexistantes sont explicitement documentées.
- [ ] `cargo test --workspace` réussit.
- [ ] Les tests d'intégration et de régression sont réussis.
- [ ] Les APIs et configurations existantes restent compatibles ou disposent d'une migration documentée.
- [ ] Les modifications sont documentées.
- [ ] Les benchmarks avant/après sont fournis.
- [ ] Les limitations restantes sont listées.
- [ ] Aucun résultat de test, benchmark ou preuve n'est inventé.

## Règles de validation obligatoires

À la fin de chaque étape, produire :

1. **Résumé** des modifications.
2. **Fichiers modifiés** et justification.
3. **Critères d'acceptation** avec statut PASS / FAIL / BLOCKED.
4. **Tests exécutés** avec commandes et résultats réels.
5. **Métriques avant/après**, lorsque pertinentes.
6. **Risques et limitations** restant à traiter.

**Gate de progression :** une étape n'est considérée comme terminée que lorsque ses critères obligatoires sont satisfaits. En cas d'échec, corrige et reteste avant de la déclarer validée. Les tâches indépendantes peuvent progresser, mais les critères bloquants doivent être résolus avant la livraison finale.

## Definition of Done globale

Webrev sera considéré comme amélioré avec succès uniquement si :

- Les faux positifs diminuent de manière quantifiable sur un corpus représentatif.
- La capacité à détecter les vulnérabilités réelles est conservée ou améliorée.
- Chaque vulnérabilité confirmée dispose d'une preuve suffisante et reproductible.
- La couverture réelle est mesurée et honnêtement présentée.
- Les protections de scope et de trafic sont validées.
- Les performances restent dans les seuils acceptés.
- Les fonctionnalités existantes ne présentent aucune régression critique.
- Tous les tests et livrables obligatoires sont vérifiés.

**Principe fondamental : précision ≠ couverture ≠ confiance ≠ sévérité. Ces quatre dimensions doivent rester distinctes dans le moteur et dans les rapports.**
