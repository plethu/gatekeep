#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  check-project-gates.sh [repo-root]

Runs Gatekeep's canonical local project gates:
  1. Rust/TOML formatting, spelling and dependency ownership
  2. cargo clippy --workspace --all-targets --all-features -- -D warnings
  3. production-only arithmetic and Result panic restrictions
  4. cargo deny advisory, ban, license, and source checks
  5. cargo test --workspace --all-features
  6. strict documentation
  7. isolated consumer features and documentation-site links
  8. standalone source-integration checks when GATEKEEP_RELATION_CONSUMER=1
EOF
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" || "${1:-}" == "help" ]]; then
  usage
  exit 0
fi

input_root="${1:-}"
if [[ -n "$input_root" ]]; then
  if ! repo_root="$(git -C "$input_root" rev-parse --show-toplevel 2>/dev/null)"; then
    echo "repo root is not a git checkout: $input_root" >&2
    exit 2
  fi
else
  if ! repo_root="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    echo "unable to resolve git repo root from current directory" >&2
    exit 2
  fi
fi

for tool in cargo taplo typos cargo-machete; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is unavailable; run 'mise install' and invoke through 'mise exec --'" >&2
    exit 2
  fi
done

echo "== TOML, spelling and dependency checks =="
(
  cd "$repo_root"
  taplo fmt --check
  typos
  # The documentation harness includes Markdown snippets outside Rust's module tree.
  # Its two dependencies are exercised by the mandatory doctest lane below.
  cargo machete crates examples
)

echo "== cargo fmt --all --check =="
(
  cd "$repo_root"
  cargo fmt --all --check
)

echo
echo "== cargo clippy =="
(
  cd "$repo_root"
  cargo clippy --workspace --all-targets --all-features -- -D warnings
)

echo
echo "== production Clippy restrictions =="
(
  cd "$repo_root"
  cargo clippy --workspace --lib --bins --all-features -- -D warnings -D clippy::arithmetic_side_effects -D clippy::panic_in_result_fn -D unreachable_pub
)

echo
echo "== cargo deny supply-chain checks =="
(
  cd "$repo_root"
  if command -v cargo-deny >/dev/null 2>&1; then
    cargo deny --all-features check advisories bans licenses sources
  elif command -v mise >/dev/null 2>&1; then
    mise exec -- cargo-deny --all-features check advisories bans licenses sources
  else
    echo "cargo-deny is unavailable; run 'mise install'" >&2
    exit 2
  fi
)

echo
echo "== cargo test =="
(
  cd "$repo_root"
  cargo test --workspace --all-features
)

echo
echo "== strict documentation =="
(
  cd "$repo_root"
  RUSTDOCFLAGS="${RUSTDOCFLAGS:+$RUSTDOCFLAGS }-D warnings" cargo doc --workspace --all-features --no-deps
)

echo
if [[ "${GATEKEEP_RELATION_CONSUMER:-0}" == "1" ]]; then
  "$repo_root/scripts/check-relation-consumer.sh"
else
  echo "Standalone relation consumer source integration skipped; set GATEKEEP_RELATION_CONSUMER=1 with matching sibling sources (see CONTRIBUTING.md)."
fi

echo "== isolated consumer features =="
python3 "$repo_root/scripts/check-consumers.py"
echo "== documentation site and links =="
python3 "$repo_root/scripts/build-docs.py"
python3 "$repo_root/scripts/check-doc-links.py"
echo "Gatekeep project gates passed."
