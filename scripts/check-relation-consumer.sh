#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: check-relation-consumer.sh [--live]

Checks the standalone relation transaction consumer using sibling Keepsake and
Dovecote sources. --live additionally runs its PostgreSQL regression test;
DATABASE_URL must name a dedicated disposable database. Its value is not printed.
HELP
}

live=0
case "${1:-}" in
  "") ;;
  --live) live=1 ;;
  --help|-h) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac
if (( $# > 1 )); then
  usage >&2
  exit 2
fi
if [[ "$live" == "1" && -z "${DATABASE_URL:-}" ]]; then
  echo "DATABASE_URL must name a dedicated disposable PostgreSQL database for --live" >&2
  exit 2
fi

repo_root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
manifest="$repo_root/examples/relation-lifecycle/Cargo.toml"
for source in "$repo_root/../keepsake-rs/crates/keepsake-sqlx/Cargo.toml" "$repo_root/../carrier/crates/dovecote/Cargo.toml"; do
  if [[ ! -f "$source" ]]; then
    echo "matching sibling Keepsake and Dovecote sources are required; see CONTRIBUTING.md" >&2
    exit 2
  fi
done
for tool in cargo cargo-deny; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "$tool is unavailable; run 'mise install' then invoke this check through 'mise exec --'" >&2
    exit 2
  fi
done

cd "$repo_root"
echo "== relation consumer format =="
cargo fmt --manifest-path "$manifest" --check
echo "== relation consumer strict Clippy =="
cargo clippy --manifest-path "$manifest" --locked --all-targets -- -D warnings
echo "== relation consumer test compilation =="
cargo test --manifest-path "$manifest" --locked --no-run
echo "== relation consumer supply chain =="
cargo deny --manifest-path "$manifest" --config "$repo_root/deny.toml" --all-features check advisories bans licenses sources
if [[ "$live" == "1" ]]; then
  echo "== relation consumer PostgreSQL regression =="
  cargo test --manifest-path "$manifest" --locked -- --ignored --test-threads=1
fi
echo "Relation consumer checks passed."
