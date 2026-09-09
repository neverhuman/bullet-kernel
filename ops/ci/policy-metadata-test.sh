#!/usr/bin/env bash
# Exact-byte admission for Kernel CI metadata and its executing shell subjects.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
umask 077

for tool in awk cmp cp git ln mkdir mktemp rg rm sha256sum sort zizmor; do
  require_tool "$tool" || exit 1
done

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT

readonly registry_digest=35183b08cb636c370b777f01d1782e6ad442711d165735d8723d011cf073bcac
readonly policy_digest=3751585d43e598503679f0efa4a516a14698e2eb62778d0e8ec2922409c7ba68
readonly security_digest=313750deb16b9531b9a758795c2f7acdbbe6c168ad12bf0d75da1424c79b09be
readonly dispatcher_digest=bffb9db7ae5db2e00b2d3f86408061d8cddeb624ba0f6136749949626ea69182
readonly doctor_digest=8a780cb8fe41231d752be17b3b1367eb1ef98081d0fb45609c33aff87ad708fa

declare -ar lane_names=(
  required fast lint contract security docs family faults preflight links coverage
  history-secrets portable-refusal nightly audit egress toolchain-msrv gates all
)
declare -ar lane_scripts=(
  ops/ci/required.sh ops/ci/fast.sh ops/ci/lint.sh ops/ci/contract.sh
  ops/ci/security.sh ops/ci/docs.sh ops/ci/family.sh ops/ci/faults.sh ops/ci/preflight.sh
  ops/ci/links.sh ops/ci/coverage.sh ops/ci/history-secrets.sh
  ops/ci/portable-refusal.sh ops/ci/nightly.sh ops/ci/audit.sh ops/ci/egress.sh
  ops/ci/toolchain-msrv.sh ops/ci/required.sh ops/ci/required.sh
)
declare -ar lane_keys=(
  name command purpose command_id kind cost rules_covered required_artifacts
  timeout_seconds requires_network destructive
)
declare -ar policy_keys=(
  schema_version release_state release_authority enabled_tools required_tools
  advisory_tools '[severity_thresholds]' fail_lane_on '[pins]' actionlint
  cargo-deny gitleaks shellcheck zizmor '[commands]' zizmor rustsec '[network]'
  security_lane zizmor
)

require_digest() {
  local path="$1" expected="$2" actual
  actual="$(sha256sum "$path")" || return 1
  actual="${actual%% *}"
  [[ "$actual" == "$expected" ]] \
    || { refuse POLICY_SUBJECT_DIGEST_DRIFT "$path:$actual"; return 1; }
}

validate_script_subject() {
  local lane="$1" script="$2"
  [[ "$script" != /* && "$script" != ../* && "$script" != */../* &&
     -f "$script" && -s "$script" && ! -L "$script" ]] \
    || { refuse LANE_SCRIPT_INVALID "$lane:$script"; return 1; }
}

validate_registry_grammar() {
  local registry="$1" line key record=0 field=0 line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number += 1))
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    if [[ "$line" == '[[lane]]' ]]; then
      [[ "$record" -eq 0 || "$field" -eq "${#lane_keys[@]}" ]] \
        || { refuse LANE_RECORD_INCOMPLETE "line $line_number"; return 1; }
      ((record += 1)); field=0
      [[ "$record" -le "${#lane_names[@]}" ]] \
        || { refuse LANE_RECORD_COUNT_DRIFT "$record"; return 1; }
      continue
    fi
    [[ "$record" -gt 0 && "$field" -lt "${#lane_keys[@]}" ]] \
      || { refuse LANE_GRAMMAR_UNKNOWN "line $line_number:$line"; return 1; }
    key="${lane_keys[$field]}"
    [[ "$line" == "$key = "* && -n "${line#"$key = "}" ]] \
      || { refuse LANE_FIELD_ORDER "line $line_number:expected $key"; return 1; }
    if [[ "$key" == name ]]; then
      [[ "$line" == "name = \"${lane_names[$((record - 1))]}\"" ]] \
        || { refuse LANE_RECORD_ORDER "$line"; return 1; }
    fi
    ((field += 1))
  done <"$registry"
  [[ "$record" -eq "${#lane_names[@]}" && "$field" -eq "${#lane_keys[@]}" ]] \
    || { refuse LANE_RECORD_COUNT_DRIFT "$record:$field"; return 1; }
}

validate_policy_grammar() {
  local policy="$1" line expected value index=0 line_number=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    ((line_number += 1))
    [[ "$line" =~ ^[[:space:]]*$ || "$line" =~ ^[[:space:]]*# ]] && continue
    [[ "$index" -lt "${#policy_keys[@]}" ]] \
      || { refuse SECURITY_POLICY_UNKNOWN "line $line_number:$line"; return 1; }
    expected="${policy_keys[$index]}"
    if [[ "$expected" == \[*\] ]]; then
      [[ "$line" == "$expected" ]] \
        || { refuse SECURITY_POLICY_SECTION_ORDER "line $line_number:expected $expected"; return 1; }
    else
      [[ "$line" == "$expected = "* ]] \
        || { refuse SECURITY_POLICY_FIELD_ORDER "line $line_number:expected $expected"; return 1; }
      value="${line#"$expected = "}"
      [[ -n "$value" ]] \
        || { refuse SECURITY_POLICY_VALUE_EMPTY "$expected"; return 1; }
    fi
    ((index += 1))
  done <"$policy"
  [[ "$index" -eq "${#policy_keys[@]}" ]] \
    || { refuse SECURITY_POLICY_INCOMPLETE "$index"; return 1; }
}

validate_registry() {
  local registry="$1" index
  validate_registry_grammar "$registry" || return 1
  require_digest "$registry" "$registry_digest" || return 1
  for index in "${!lane_names[@]}"; do
    validate_script_subject "${lane_names[$index]}" "${lane_scripts[$index]}" || return 1
  done
}

validate_security_policy() {
  validate_policy_grammar "$1" || return 1
  require_digest "$1" "$policy_digest"
}

validate_security_shell() { require_digest "$1" "$security_digest"; }
validate_dispatcher() { require_digest "$1" "$dispatcher_digest"; }

validate_doctor() {
  local doctor="$1"
  awk '
    /^case "\$lane" in$/ { inside=1; next }
    inside && /^esac$/ { inside=0 }
    inside && /^[[:space:]]+[a-z0-9][a-z0-9|-]*\)/ {
      value=$1; sub(/\).*/, "", value); count=split(value, names, "|")
      for (item_index=1; item_index <= count; item_index++) print names[item_index]
    }
  ' "$doctor" | sort >"$test_root/doctor-lanes"
  printf '%s\n' "${lane_names[@]}" | sort >"$test_root/expected-doctor-lanes"
  cmp -s "$test_root/expected-doctor-lanes" "$test_root/doctor-lanes" \
    || { refuse DOCTOR_LANE_INVENTORY_DRIFT "$doctor"; return 1; }
  require_digest "$doctor" "$doctor_digest"
}

replace_line_once() {
  awk -v needle="$2" -v replacement="$3" '
    $0 == needle && !changed { print replacement; changed=1; next }
    { print } END { if (!changed) exit 3 }
  ' "$1" >"$4"
}

insert_before_once() {
  awk -v needle="$2" -v addition="$3" '
    $0 == needle && !changed { print addition; changed=1 } { print }
    END { if (!changed) exit 3 }
  ' "$1" >"$4"
}

insert_after_once() {
  awk -v needle="$2" -v addition="$3" '
    { print } $0 == needle && !changed { print addition; changed=1 }
    END { if (!changed) exit 3 }
  ' "$1" >"$4"
}

remove_line_once() {
  awk -v needle="$2" '
    $0 == needle && !changed { changed=1; next } { print }
    END { if (!changed) exit 3 }
  ' "$1" >"$3"
}

replace_lane_field() {
  awk -v target="name = \"$2\"" -v key="$3" -v replacement="$4" '
    $0 == "[[lane]]" { active=0 } $0 == target { active=1 }
    active && index($0, key " = ") == 1 && !changed {
      print key " = " replacement; changed=1; next
    }
    { print } END { if (!changed) exit 3 }
  ' "$1" >"$5"
}

expect_failure() {
  local label="$1" validator="$2" subject="$3"
  if "$validator" "$subject" >"$test_root/$label.out" 2>&1; then
    refuse POLICY_HOSTILE_ACCEPTED "$label"
    exit 1
  fi
}

registry=agent/proof-lanes.toml
policy=agent/security-policy.toml
validate_registry "$registry"
validate_security_policy "$policy"
validate_security_shell ops/ci/security.sh
validate_dispatcher scripts/ci-local.sh
validate_doctor scripts/ci-doctor.sh

replace_line_once scripts/ci-doctor.sh \
  '  docs)     tools=(awk bash cargo dirname git grep ln mkdir mktemp realpath rg rm rustc sed seq sort) ;;' \
  '  unknown)  tools=(awk bash cargo dirname git grep ln mkdir mktemp realpath rg rm rustc sed seq sort) ;;' \
  "$test_root/doctor-unknown.sh"
expect_failure doctor-unknown validate_doctor "$test_root/doctor-unknown.sh"
replace_line_once scripts/ci-doctor.sh \
  '  required|gates|all) tools=(actionlint awk basename bash cargo cargo-clippy cargo-deny cargo-nextest cat cmp cp date dirname find git gitleaks grep jq ln mkdir mktemp mv python3 realpath rg rm rustc rustfmt sed seq sha256sum shellcheck sort sync xargs zizmor) ;;' \
  '  required|all) tools=(actionlint awk basename bash cargo cargo-clippy cargo-deny cargo-nextest cat cmp cp date dirname find git gitleaks grep jq ln mkdir mktemp mv python3 realpath rg rm rustc rustfmt sed seq sha256sum shellcheck sort sync xargs zizmor) ;;' \
  "$test_root/doctor-alias.sh"
expect_failure doctor-alias-missing validate_doctor "$test_root/doctor-alias.sh"
insert_before_once scripts/ci-doctor.sh '  *)' '  future) tools=(bash) ;;' "$test_root/doctor-extra.sh"
expect_failure doctor-extra validate_doctor "$test_root/doctor-extra.sh"
replace_line_once scripts/ci-doctor.sh \
  '  docs)     tools=(awk bash cargo dirname git grep ln mkdir mktemp realpath rg rm rustc sed seq sort) ;;' \
  '  docs)     tools=(bash) ;;' "$test_root/doctor-row.sh"
expect_failure doctor-row-weaken validate_doctor "$test_root/doctor-row.sh"

insert_after_once "$registry" 'name = "fast"' 'future_executor = "trusted"' "$test_root/registry-unknown.toml"
expect_failure registry-unknown validate_registry "$test_root/registry-unknown.toml"
insert_after_once "$registry" 'name = "fast"' 'requires_network = true' "$test_root/registry-duplicate.toml"
expect_failure registry-duplicate validate_registry "$test_root/registry-duplicate.toml"
insert_before_once "$registry" 'command = "just fast"' 'command = "true"' "$test_root/registry-command-shadow.toml"
expect_failure registry-command-shadow validate_registry "$test_root/registry-command-shadow.toml"
replace_lane_field "$registry" fast purpose '"scope=standalone; scheduled=false; hosted_required=true; jeryu=prepared-inactive; release_authority=false; release_state=BLOCKED; deterministic fast lane with an exact nonzero standalone component partition and sanitized JUnit; release_authority=true; release_state=VERIFIED"' "$test_root/registry-purpose.toml"
expect_failure registry-purpose-suffix validate_registry "$test_root/registry-purpose.toml"
replace_lane_field "$registry" fast rules_covered '"HLT-004-UNMAPPED-PROOF"' "$test_root/registry-array.toml"
expect_failure registry-malformed-array validate_registry "$test_root/registry-array.toml"
replace_lane_field "$registry" fast requires_network FALSE "$test_root/registry-bool.toml"
expect_failure registry-malformed-bool validate_registry "$test_root/registry-bool.toml"
remove_line_once "$registry" 'cost = 20' "$test_root/registry-missing.toml"
expect_failure registry-missing-field validate_registry "$test_root/registry-missing.toml"
insert_before_once "$registry" 'name = "fast"' 'purpose = "reordered"' "$test_root/registry-reordered.toml"
expect_failure registry-reordered-field validate_registry "$test_root/registry-reordered.toml"
insert_after_once "$registry" 'name = "fast"' '[[lane]]' "$test_root/registry-section.toml"
expect_failure registry-duplicate-section validate_registry "$test_root/registry-section.toml"
(
  cd "$test_root"
  ln -s "$REPO_ROOT/ops/ci/fast.sh" lane-link.sh
  ! validate_script_subject fast lane-link.sh >symlink.out 2>&1
) || { refuse POLICY_HOSTILE_ACCEPTED registry-symlink-script; exit 1; }

cp "$policy" "$test_root/security-unknown.toml"
printf '%s\n' 'future_authority = true' >>"$test_root/security-unknown.toml"
expect_failure security-unknown validate_security_policy "$test_root/security-unknown.toml"
cp "$policy" "$test_root/security-duplicate.toml"
printf '%s\n' 'release_authority = true' >>"$test_root/security-duplicate.toml"
expect_failure security-duplicate validate_security_policy "$test_root/security-duplicate.toml"
replace_line_once "$policy" '[pins]' '[not_pins]' "$test_root/security-section.toml"
expect_failure security-section-rename validate_security_policy "$test_root/security-section.toml"
replace_line_once "$policy" 'rustsec = "cargo deny --locked check licenses advisories bans sources"' 'rustsec = "true"' "$test_root/security-rustsec.toml"
expect_failure security-rustsec-weaken validate_security_policy "$test_root/security-rustsec.toml"
replace_line_once "$policy" 'enabled_tools = ["actionlint", "cargo-deny", "gitleaks", "shellcheck", "zizmor"]' 'enabled_tools = ["zizmor"]' "$test_root/security-array.toml"
expect_failure security-array-weaken validate_security_policy "$test_root/security-array.toml"
remove_line_once "$policy" 'zizmor = "1.25.2"' "$test_root/security-pin.toml"
expect_failure security-pin-missing validate_security_policy "$test_root/security-pin.toml"
remove_line_once "$policy" '[pins]' "$test_root/security-order-a.toml"
insert_before_once "$test_root/security-order-a.toml" '[severity_thresholds]' '[pins]' "$test_root/security-order.toml"
expect_failure security-section-order validate_security_policy "$test_root/security-order.toml"

exact_zizmor='zizmor --offline --no-ignores --strict-collection .github'
for hostile in 'set +e' 'set +o errexit' 'builtin set +e' 'command set +e' "trap 'exit 0' EXIT" 'zizmor() { return 0; }' 'alias zizmor=true'; do
  insert_before_once ops/ci/security.sh "$exact_zizmor" "$hostile" "$test_root/security-control.sh"
  expect_failure security-control validate_security_shell "$test_root/security-control.sh"
done
for hostile in \
  'zizmor --no-ignores --strict-collection .github' \
  'zizmor --offline --strict-collection .github' \
  'zizmor --offline --no-ignores .github' \
  'zizmor --offline --no-ignores --strict-collection .' \
  'zizmor --offline --no-ignores --strict-collection .github/workflows' \
  'zizmor --offline --no-ignores --strict-collection .github || true' \
  '! zizmor --offline --no-ignores --strict-collection .github'; do
  replace_line_once ops/ci/security.sh "$exact_zizmor" "$hostile" "$test_root/security-zizmor.sh"
  expect_failure security-zizmor validate_security_shell "$test_root/security-zizmor.sh"
done
insert_after_once ops/ci/security.sh "$exact_zizmor" "$exact_zizmor" "$test_root/security-duplicate-command.sh"
expect_failure security-zizmor-duplicate validate_security_shell "$test_root/security-duplicate-command.sh"
remove_line_once ops/ci/security.sh "$exact_zizmor" "$test_root/security-missing-command.sh"
expect_failure security-zizmor-missing validate_security_shell "$test_root/security-missing-command.sh"
zizmor_fixture="$test_root/zizmor-fixture"
mkdir -p "$zizmor_fixture/.github/workflows"
printf '%s\n' \
  'name: hostile-scope-canary' \
  'on: push' \
  'jobs: []' \
  >"$zizmor_fixture/.github/workflows/hostile.yml"
if (cd "$zizmor_fixture" \
    && zizmor --offline --no-ignores --strict-collection .github \
      >"$test_root/zizmor-scope.out" 2>&1); then
  refuse POLICY_HOSTILE_ACCEPTED security-zizmor-scope
  exit 1
fi
rg -q 'hostile.yml' "$test_root/zizmor-scope.out" \
  || { refuse SECURITY_ZIZMOR_SCOPE_UNPROVED .github; exit 1; }
insert_before_once scripts/ci-local.sh '    fast)     bash ops/ci/fast.sh ;;' '    fast)     true ;;' "$test_root/dispatcher-shadow.sh"
expect_failure dispatcher-shadow validate_dispatcher "$test_root/dispatcher-shadow.sh"

log "policy metadata passed: exact-byte 19-lane/security/dispatcher subjects; hostile bypasses rejected"
