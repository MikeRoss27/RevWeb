#!/usr/bin/env bash
# Run the same gates as .github/workflows/ci.yml, in the same order.
# Usage: scripts/ci-local.sh [--quick]   (--quick skips the Chromium tests)
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n==> %s\n' "$*"; }

step "source size";  python3 scripts/check_source_size.py
step "fmt";          cargo fmt --all -- --check
step "clippy";       cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
step "rustdoc";      RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
step "tests";        cargo test --workspace --locked

step "pinned corpus checksums"
find benchmarks -name SHA256SUMS | sort | while IFS= read -r sums; do
  (cd "$(dirname "$sums")" && sha256sum -c SHA256SUMS >/dev/null) && echo "ok  $sums"
done

step "python scripts"
python3 -m compileall -q scripts
python3 -m unittest discover -s scripts -p 'test_*.py'

if command -v cargo-deny >/dev/null 2>&1; then
  step "cargo-deny";  cargo deny check
else
  echo "skip cargo-deny (cargo install cargo-deny --locked)"
fi

if [[ "${1:-}" != "--quick" ]] && { command -v chromium >/dev/null 2>&1 || [[ -n "${CHROME:-}" ]]; }; then
  step "chromium integration"; cargo test --locked -p webrev-browser -- --include-ignored
else
  echo "skip chromium tests"
fi
printf '\nall gates passed\n'
