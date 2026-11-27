# Revue de préparation à la première publication — webrev v0.1.0

État du projet au 2026-11-27. Version : `0.1.0` (`Cargo.toml` + binaires —
`webrev --version` = `webrev-tui --version` = 0.1.0).

## Verdict global

**Prêt côté code, publication en attente.** Tous les blocages techniques
trouvés lors de la revue sont levés sur la branche `feat/ui-color-policy`
(local, non poussée). Reste la publication elle-même (push, fusion dans
`main`, tag) et la validation des workflows de release, qui ne se testent
qu'avec un tag.

---

## 1. Blocages levés

| Point | Résolution |
|---|---|
| `cargo doc -D warnings` rouge (`session.rs:75`, lien vers `TOAST_TTL` privé) | Lien remplacé par du texte; la commande passe. |
| Advisories cargo-deny (`url`, `ctutils`, `rustix`) | `cargo update` → `url 2.5.9`, `ctutils 0.4.8`, `rustix 1.1.6`; `cargo deny check` vert, `ignore = []` inchangé. |
| Test flaky `cancellation_interrupts_an_inflight_response` | Cause : le test enveloppait tout le scan (création du client, connexion, envoi) dans un timeout de 300 ms. Le fixture attend maintenant un signal du test; garde-fou de 30 s. Code produit inchangé. 100 exécutions sur 100 sous charge. |
| Split `ws_replay` non commité | Commité (`ws_replay/frames.rs` + `ws_replay/tests.rs`). |
| `--redact` laissait un token dans `value` pour les URLs relatives | `value` passe par la même logique que `url`, y compris pour les valeurs courtes. Test ajouté. |
| `--header` / `--cookie` mal formés ignorés en silence | Erreur d'usage (exit 2) avec un hint; la valeur n'est pas répétée dans le message. |
| Banner absent pour `ws-replay` | Ajouté. |
| `docs/usage.md` sans section `ws-replay` | Section ajoutée. Le compte « ten subcommands » était déjà exact. |
| Badge README sans macOS | Corrigé. |
| `.claude/` non ignoré | Ajouté à `.gitignore`. |
| Pas de `CHANGELOG.md` | Créé à la racine. |

Vérifié sur la branche fusionnée : `cargo fmt --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`,
`cargo deny check` et `cargo test --workspace --locked` passent.

---

## 2. Reste à faire

### 2.1 Smoke test de release

- `cargo build --release --locked -p webrev-cli -p webrev-tui`
- `scripts/package.py --target <triple>` puis `scripts/check_bundle.py`
  sur la plateforme locale.

### 2.2 Workflows jamais exécutés

- `.github/workflows/release.yml` : tag `v*` → CI + bundles + draft GitHub
  release + SHA256SUMS + attestations (si le dépôt est public).
- `.github/workflows/bundles.yml` : 4 cibles (`x86_64-pc-windows-msvc`,
  `x86_64-unknown-linux-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin`).
  `docs/installation.md` signale que seul le bundle Windows local a été
  validé; à mettre à jour seulement après une validation réelle.
- `release.yml` vérifie que le tag est égal à `v` + la version du workspace.

### 2.3 Publication

- Pousser `feat/ui-color-policy`, la fusionner dans `main`, puis
  `git tag v0.1.0 && git push --tags`.
- Le `main` local est en retard sur `origin/main` (3 commits : #37, #38,
  #39); `feat/ui-color-policy` les contient déjà.

### 2.4 À vérifier plus tard (non bloquant)

- MSRV `1.89` (`Cargo.toml`, `scripts/install.*`, `docs/development.md`) :
  non testée localement (toolchains disponibles : stable, nightly).
- `docs/development.md` ne mentionne pas le split de `ws_replay/`.

---

## 3. Références rapides

- Changelog : `CHANGELOG.md`.
- Test de cancellation : `crates/webrev-pipeline/src/active/integration_tests/limits.rs`.
- Redaction : `crates/webrev-report/src/redact.rs`,
  `crates/webrev-core/src/security/sanitize/url.rs`.
- Erreurs d'usage : `crates/webrev-cli/src/commands/mod.rs` (`parse_pairs`).
- Bundles : `scripts/package.py`, `scripts/check_bundle.py`,
  `.github/workflows/bundles.yml`.
