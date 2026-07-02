#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'EOF'
Usage:
  check-project-gates.sh [repo-root]

Runs Gatekeep's canonical local project gates:
  1. cargo fmt --all --check
  2. cargo clippy --workspace --all-targets --all-features -- -D warnings
  3. cargo test --workspace --all-features
  4. pnpm install --frozen-lockfile
  5. pnpm docs:verify
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

export PNPM_STORE_DIR="${PNPM_STORE_DIR:-$repo_root/.pnpm-store}"
export NPM_CONFIG_STORE_DIR="${NPM_CONFIG_STORE_DIR:-$PNPM_STORE_DIR}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$repo_root/.cache/xdg/data}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$repo_root/.cache/xdg/state}"

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
echo "== cargo test =="
(
  cd "$repo_root"
  cargo test --workspace --all-features
)

echo
echo "== docs install =="
(
  cd "$repo_root"
  pnpm install --frozen-lockfile
)

echo
echo "== docs verify =="
(
  cd "$repo_root"
  pnpm docs:verify
)

echo
echo "Gatekeep project gates passed."
