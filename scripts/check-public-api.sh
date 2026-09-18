#!/usr/bin/env bash
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
mode="${1:-minor}"
case "$mode" in
  minor|patch|major) ;;
  *) echo 'usage: check-public-api.sh [minor|patch|major]' >&2; exit 2 ;;
esac
if ! command -v cargo-semver-checks >/dev/null 2>&1; then
  echo "cargo-semver-checks is unavailable; run 'mise install' and invoke through 'mise exec --'" >&2
  exit 2
fi
# Major mode is an explicit release decision, not an automatic response to a failure.
while read -r package baseline; do
  for features in --default-features --only-explicit-features --all-features; do
    extra=()
    if [[ "$package" == "gatekeep-sqlx" && "$features" == "--only-explicit-features" ]]; then
      # SQLx requires a backend; exercise SQLite without the default PostgreSQL feature.
      extra=(--features sqlite)
    fi
    cargo semver-checks check-release --package "$package" \
      --baseline-version "$baseline" --release-type "$mode" "$features" "${extra[@]}"
  done
done <<'BASELINES'
gatekeep 4.0.1
gatekeep-axum 4.0.0
gatekeep-fluent 4.0.0
gatekeep-keepsake 5.0.0
gatekeep-sqlx 4.0.1
BASELINES
