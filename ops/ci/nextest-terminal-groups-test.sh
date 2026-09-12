#!/usr/bin/env bash
# Sourced only by nextest-groups-test.sh after its exact timeout validation.
# shellcheck disable=SC2154 # caller owns frozen filter, scratch dir and functions

terminal_filter_line="filter = '$terminal_filter'"
terminal_group_line="$terminal_group = { max-threads = 1 }"
terminal_group_override="test-group = '$terminal_group'"
for replacement in "filter = 'all()'" \
  "filter = 'binary_id(=bullet::operator_tui)'" \
  "filter = '$terminal_filter | binary_id(=bullet::coding_operator)'"; do
  rewrite_exact_line "$terminal_filter_line" "$replacement" "$test_root/terminal-filter.toml"
  reject_hostile_config "$test_root/terminal-filter.toml" 'changed terminal filter accepted'
done
for replacement in 'threads-required = 1' 'threads-required = 3' 'threads-required = 5'; do
  rewrite_exact_line 'threads-required = 4' "$replacement" "$test_root/terminal-weight.toml"
  reject_hostile_config "$test_root/terminal-weight.toml" 'changed terminal resource weight accepted'
done
for removed in "$terminal_filter_line" "$terminal_group_line" "$terminal_group_override" 'threads-required = 4'; do
  remove_exact_line "$removed" "$test_root/terminal-missing.toml"
  reject_hostile_config "$test_root/terminal-missing.toml" 'missing terminal resource entry accepted'
done
rewrite_exact_line "$terminal_group_line" "$terminal_group = { max-threads = 2 }" "$test_root/terminal-parallel.toml"
reject_hostile_config "$test_root/terminal-parallel.toml" 'parallel terminal group accepted'
rewrite_exact_line "$terminal_group_override" "$terminal_group_override"$'\n'"$receipt_timeout" "$test_root/terminal-timeout.toml"
reject_hostile_config "$test_root/terminal-timeout.toml" 'terminal timeout relaxation accepted'
cp .config/nextest.toml "$test_root/terminal-duplicate.toml"
printf '\n%s\n%s\n%s\n%s\n' '[[profile.fast.overrides]]' "$terminal_filter_line" \
  "$terminal_group_override" 'threads-required = 4' >>"$test_root/terminal-duplicate.toml"
reject_hostile_config "$test_root/terminal-duplicate.toml" 'duplicate terminal override accepted'

# Actual nextest expansion must contain every identity in precisely these three
# binary targets. No new fixed count or test-execution credit is invented here.
cargo nextest list --locked --workspace "${NEXTEST_FEATURES[@]}" --run-ignored all \
  --message-format json -E "$terminal_filter" >"$test_root/terminal-inventory.json"
jq -r '."rust-suites" | to_entries[] | .key as $binary | .value.testcases | to_entries[] | select(.value["filter-match"].status == "matches") | "\($binary)::\(.key)"' \
  "$test_root/terminal-inventory.json" | sort -u >"$test_root/terminal-expected"
jq -r '."rust-suites" | to_entries[] | select(any(.value.testcases[]; .["filter-match"].status == "matches")) | .key' \
  "$test_root/terminal-inventory.json" | sort -u >"$test_root/terminal-binaries"
printf '%s\n' 'bullet::operator_terminal' 'bullet::operator_tui' 'bullet::operator_tui_startup' \
  >"$test_root/terminal-binaries-expected"
cmp -s "$test_root/terminal-binaries" "$test_root/terminal-binaries-expected" \
  || { refuse NEXTEST_TERMINAL_FILTER_DRIFT 'expected three nonempty terminal binaries'; exit 1; }
cargo nextest --color never show-config test-groups --locked --workspace "${NEXTEST_FEATURES[@]}" \
  --profile fast --groups "$terminal_group" --no-pager >"$test_root/terminal-show-config"
rg -Fxq "group: $terminal_group (max threads = 1)" "$test_root/terminal-show-config" \
  || { refuse NEXTEST_TERMINAL_GROUP_INVALID 'nextest did not apply max-threads=1'; exit 1; }
rg -Fq "* override for fast profile with filter '$terminal_filter':" "$test_root/terminal-show-config" \
  || { refuse NEXTEST_TERMINAL_OVERRIDE_MISSING 'nextest did not apply exact terminal override'; exit 1; }
awk '
  /^      [^[:space:]]/ { binary=$0; sub(/^ +/, "", binary); sub(/:$/, "", binary); next }
  /^          [^[:space:]]/ { test=$0; sub(/^ +/, "", test); print binary "::" test }
' "$test_root/terminal-show-config" | sort -u >"$test_root/terminal-actual"
cmp -s "$test_root/terminal-expected" "$test_root/terminal-actual" \
  || { refuse NEXTEST_TERMINAL_GROUP_EXPANSION_DRIFT 'group lost or added terminal identities'; exit 1; }
