#!/usr/bin/env bash
set -euo pipefail

# Checks out the Keepsake and Dovecote revisions pinned in .github/workflows/ci.yml
# beside this repository, as examples/relation-lifecycle expects. Reads the pins
# from ci.yml so they stay in one place. Existing sibling directories are left
# untouched unless they are links this script created earlier.

repo_root="$(git -C "$(dirname "${BASH_SOURCE[0]}")" rev-parse --show-toplevel)"
ci="$repo_root/.github/workflows/ci.yml"
parent="$(dirname "$repo_root")"
store="$repo_root/.siblings"

pin() {
  local value
  value="$(sed -nE "s/^[[:space:]]*$1:[[:space:]]*([0-9a-f]{40})[[:space:]]*$/\1/p" "$ci")"
  if [[ ! "$value" =~ ^[0-9a-f]{40}$ ]]; then
    echo "could not read a full commit SHA for $1 from $ci" >&2
    exit 2
  fi
  printf '%s' "$value"
}

checkout() {
  local repository="$1" revision="$2" name="$3"
  local target="$parent/$name"
  if [[ -e "$target" && ! -L "$target" ]]; then
    echo "$target already exists; leaving it in place" >&2
    return
  fi
  rm -rf "$store/$name"
  git init -q "$store/$name"
  git -C "$store/$name" fetch -q --depth 1 "https://github.com/$repository" "$revision"
  git -C "$store/$name" checkout -q --detach FETCH_HEAD
  ln -sfn "$store/$name" "$target"
  echo "$name -> $repository@$revision"
}

mkdir -p "$store"
grep -qxF '/.siblings/' "$repo_root/.git/info/exclude" 2>/dev/null \
  || echo '/.siblings/' >> "$repo_root/.git/info/exclude"

checkout plethu/keepsake "$(pin keepsake_ref)" keepsake-rs
checkout plethu/dovecote "$(pin carrier_ref)" carrier
