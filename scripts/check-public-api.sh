#!/usr/bin/env bash
set -euo pipefail
mode="${1:-minor}"
case "$mode" in
  minor|patch|major) ;;
  *) echo 'usage: check-public-api.sh [minor|patch|major]' >&2; exit 2 ;;
esac
# Major mode is an explicit release decision, not an automatic response to a failure.
while read -r package baseline; do
  cargo semver-checks check-release --package "$package" --baseline-version "$baseline" --release-type "$mode" --default-features
done <<'BASELINES'
gatekeep 4.0.1
gatekeep-axum 4.0.0
gatekeep-fluent 4.0.0
gatekeep-keepsake 5.0.0
gatekeep-sqlx 4.0.1
BASELINES
