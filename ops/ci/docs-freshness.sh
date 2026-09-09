#!/usr/bin/env bash
# Fail closed when a reviewed public document drifts too far from its exact
# ancestor or when a declared source path disappears or becomes a symlink.
set -euo pipefail

reason() {
  printf '[ci] DOC_FRESHNESS_INVALID: %s\n' "$1" >&2
  exit 1
}

script_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
root="$script_root"
if (($# > 0)); then
  if (($# != 2)) || [[ "$1" != "--fixture-root" ]] || [[ "${BULLET_DOC_FRESHNESS_SELF_TEST:-}" != "1" ]]; then
    reason "arguments are reserved for the hostile self-test"
  fi
  [[ "$2" = /* ]] || reason "fixture root must be absolute"
  [[ -d "$2" && ! -L "$2" ]] || reason "fixture root must be a non-symlink directory"
  root="$(cd "$2" && pwd -P)"
fi

[[ -d "$root/.git" && ! -L "$root/.git" ]] || reason "root is not a canonical primary checkout"
toplevel="$(git -C "$root" rev-parse --show-toplevel 2>/dev/null)" || reason "root is not a Git checkout"
[[ "$toplevel" == "$root" ]] || reason "root does not equal the Git toplevel"

documents=(README.md docs/architecture.md docs/cli.md docs/egress-isolation.md)
marker_pattern='^<!-- bullet-doc-review:v1 subject=([0-9a-f]{40}) max_distance=([0-9]{1,3}) paths=([A-Za-z0-9_./,-]+) -->$'

ordinary_path() {
  local relative="$1"
  [[ "$relative" != /* && "$relative" != *//* ]] || return 1
  local cursor="$root"
  local segment
  local -a segments=()
  IFS='/' read -r -a segments <<<"$relative"
  ((${#segments[@]} > 0)) || return 1
  for segment in "${segments[@]}"; do
    [[ -n "$segment" && "$segment" != "." && "$segment" != ".." ]] || return 1
    cursor="$cursor/$segment"
    [[ ! -L "$cursor" ]] || return 1
  done
  [[ -f "$cursor" ]]
}

for document in "${documents[@]}"; do
  ordinary_path "$document" || reason "$document is missing, non-regular, or symlinked"
  mapfile -t markers < <(grep '^<!-- bullet-doc-review:' "$root/$document" || true)
  ((${#markers[@]} == 1)) || reason "$document must contain exactly one review marker"
  marker="${markers[0]}"
  [[ "$marker" =~ $marker_pattern ]] || reason "$document has a malformed review marker"
  subject="${BASH_REMATCH[1]}"
  max_distance="${BASH_REMATCH[2]}"
  paths_csv="${BASH_REMATCH[3]}"
  ((10#$max_distance >= 1 && 10#$max_distance <= 25)) || reason "$document has an unsafe review window"

  git -C "$root" cat-file -e "${subject}^{commit}" 2>/dev/null || reason "$document names an unknown review subject"
  git -C "$root" merge-base --is-ancestor "$subject" HEAD 2>/dev/null || reason "$document review subject is not an ancestor"
  distance="$(git -C "$root" rev-list --count "${subject}..HEAD")" || reason "$document review distance is unreadable"
  [[ "$distance" =~ ^[0-9]+$ ]] || reason "$document review distance is malformed"
  ((10#$distance <= 10#$max_distance)) || reason "$document is $distance commits past its review subject"

  declare -A seen_paths=()
  IFS=',' read -r -a paths <<<"$paths_csv"
  ((${#paths[@]} > 0)) || reason "$document has no reviewed source paths"
  for path in "${paths[@]}"; do
    [[ -z "${seen_paths[$path]+x}" ]] || reason "$document repeats reviewed source path $path"
    seen_paths[$path]=1
    ordinary_path "$path" || reason "$document source path $path is missing, unsafe, or symlinked"
    git -C "$root" cat-file -e "${subject}:${path}" 2>/dev/null || reason "$document source path $path did not exist at its review subject"
    tree_entry="$(git -C "$root" ls-tree "$subject" -- "$path")" || reason "$document source path $path has no review tree entry"
    read -r tree_mode tree_type _ <<<"$tree_entry"
    [[ "$tree_type" == "blob" && ( "$tree_mode" == "100644" || "$tree_mode" == "100755" ) ]] || reason "$document source path $path was not an ordinary file at its review subject"
  done
  unset seen_paths
done

printf '[ci] docs freshness passed (%s documents)\n' "${#documents[@]}"
