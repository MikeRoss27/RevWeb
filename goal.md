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
- [ ] Les preuves sensibles sont protégées contre une exposition accidentelle.

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

**État de l'étape 5 : EN COURS — non validée.** La remesure sur machine calme du
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
- [ ] Profil SPA sur le code actuel de `main` (b3f5e42, machine calme, binaires fixes, 300 paires) : p95 poolé +16,8% (≤20%) mais >20% dans 3 invocations sur 10 de 30 paires; RSS +9,8 à +15,5% (≤25%) dans 10 invocations sur 10, avec une invocation à base anormalement basse (+48%) non reproduite, cause non établie. Non reproductible au sens du critère écrit, donc non coché. Le PASS du 2026-10-17 (p95 +18,64%, RSS +6,69%, 60/60 scans réussis) précède ces changements. Pour mémoire, le lockfile baseline est réécrit pour ses arêtes locales, sans changement de version/source/checksum des paquets externes.
- [ ] Corpus externe représentatif avec positifs et négatifs, labels examinés indépendamment.

**Objectifs de performance :**
- Surcoût de temps d'exécution p95 ≤ 20 %.
- Augmentation de mémoire maximale ≤ 25 %.
- Aucun crash ou comportement non déterministe identifié dans les tests de stabilité.

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
