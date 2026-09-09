#!/usr/bin/env bash
# Fail on broken or escaping repository-relative Markdown links without a
# second language runtime in the proof lane.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool realpath || exit 1
require_tool rg || exit 1

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

percent_decode() {
  local remaining="$1"
  local decoded=''
  local byte
  local hex
  while [[ "$remaining" =~ ^([^%]*)%([0-9A-Fa-f]{2})(.*)$ ]]; do
    decoded+="${BASH_REMATCH[1]}"
    hex="${BASH_REMATCH[2]}"
    case "${hex^^}" in
      00|0[1-9A-F]|1[0-9A-F]|7F)
        return 1
        ;;
    esac
    printf -v byte '%b' "\\x$hex"
    decoded+="$byte"
    remaining="${BASH_REMATCH[3]}"
  done
  decoded+="$remaining"
  printf '%s' "$decoded"
}

mapfile -t markdown_files < <(
  rg --files -g '*.md' \
    | awk 'index($0, "/") == 0 || $0 ~ /^(docs|ops|agent)\//' \
    | sort -u
)
[[ "${#markdown_files[@]}" -gt 0 ]] \
  || { refuse MARKDOWN_INVENTORY_EMPTY "no Markdown files found"; exit 1; }

failures=()
link_pattern='(.*)!?\[[^]]*\]\(([^)]*)\)(.*)'
for source in "${markdown_files[@]}"; do
  source_dir="${source%/*}"
  [[ "$source_dir" != "$source" ]] || source_dir='.'
  line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    line_number=$((line_number + 1))
    remaining="$line"
    # The prefix is greedy, so this processes links right-to-left without
    # interpreting Markdown text as a shell pattern.
    while [[ "$remaining" =~ $link_pattern ]]; do
      raw="$(trim "${BASH_REMATCH[2]}")"
      remaining="${BASH_REMATCH[1]}"
      if [[ "$raw" == \<*\>* ]]; then
        target="${raw#<}"
        target="${target%%>*}"
      else
        target="${raw%%[[:space:]]*}"
      fi
      [[ -n "$target" && "$target" != \#* ]] || continue
      lower="${target,,}"
      case "$lower" in
        http://*|https://*|mailto:*|tel:*|data:*) continue ;;
      esac

      path_text="${target%%[#?]*}"
      [[ -n "$path_text" ]] || continue
      if ! path_text="$(percent_decode "$path_text")"; then
        failures+=("$source:$line_number: link contains an encoded control byte: $target")
        continue
      fi
      if [[ "$path_text" == /* ]]; then
        candidate="$REPO_ROOT/${path_text#/}"
      else
        candidate="$source_dir/$path_text"
      fi
      resolved="$(realpath -m -- "$candidate")"
      case "$resolved" in
        "$REPO_ROOT"|"$REPO_ROOT"/*) ;;
        *)
          failures+=("$source:$line_number: link escapes repository: $target")
          continue
          ;;
      esac
      [[ -e "$resolved" ]] \
        || failures+=("$source:$line_number: missing link target: $target")
    done
  done <"$source"
done

if [[ "${#failures[@]}" -gt 0 ]]; then
  printf '%s\n' "${failures[@]}" >&2
  exit 1
fi
log "docs links passed (${#markdown_files[@]} Markdown files)"
