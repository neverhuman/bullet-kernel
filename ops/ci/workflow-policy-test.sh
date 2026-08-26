#!/usr/bin/env bash
# Sourced hostile fixtures for the hosted-workflow contract.

workflow_test_root="$(mktemp -d)"
cleanup_workflow_tests() { rm -rf -- "$workflow_test_root"; }
trap cleanup_workflow_tests EXIT
cp .github/workflows/ci.yml "$workflow_test_root/ci.yml"
cp .github/workflows/scheduled.yml "$workflow_test_root/scheduled.yml"
mkdir "$workflow_test_root/workflows"
cp .github/workflows/ci.yml "$workflow_test_root/workflows/ci.yml"
cp .github/workflows/scheduled.yml "$workflow_test_root/workflows/scheduled.yml"

assert_workflow_inventory_failure() {
  local label="$1" reason="${2-WORKFLOW_}" output code
  set +e
  output="$(validate_workflow_inventory "$workflow_test_root/workflows" 2>&1)"
  code=$?
  set -e
  [[ "$code" -ne 0 && "$output" == *"$reason"* ]] \
    || { refuse WORKFLOW_FILE_HOSTILE_FAILED "$label reason=$reason code=$code output=$output"; exit 1; }
}

expect_workflow_inventory_failure() {
  local extension="$1" name="${2-exfil.$1}" hostile
  hostile="$workflow_test_root/workflows/$name"
  printf '%s\n' \
    'name: hostile broad upload' \
    'on: workflow_dispatch' \
    'permissions: { contents: read }' \
    'jobs:' \
    '  exfil:' \
    '    runs-on: ubuntu-24.04' \
    '    steps:' \
    '      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' \
    '        with: { name: exfil, path: . }' >"$hostile"
  assert_workflow_inventory_failure "$extension"
  rm -- "$hostile"
}

expect_workflow_inventory_failure yml
expect_workflow_inventory_failure yaml
expect_workflow_inventory_failure yml .exfil.yml
expect_workflow_inventory_failure yaml .exfil.yaml
ln -s ci.yml "$workflow_test_root/workflows/exfil.yml"
assert_workflow_inventory_failure symlink
rm -- "$workflow_test_root/workflows/exfil.yml"
mkdir "$workflow_test_root/workflows/exfil.yaml"
assert_workflow_inventory_failure directory
rmdir "$workflow_test_root/workflows/exfil.yaml"
rm -- "$workflow_test_root/workflows/ci.yml"
ln -s "$workflow_test_root/ci.yml" "$workflow_test_root/workflows/ci.yml"
assert_workflow_inventory_failure canonical-symlink WORKFLOW_ENTRY_INVALID
rm -- "$workflow_test_root/workflows/ci.yml"
cp "$workflow_test_root/ci.yml" "$workflow_test_root/workflows/ci.yml"
rm -- "$workflow_test_root/workflows/scheduled.yml"
mkdir "$workflow_test_root/workflows/scheduled.yml"
assert_workflow_inventory_failure canonical-directory WORKFLOW_ENTRY_INVALID
rmdir "$workflow_test_root/workflows/scheduled.yml"
cp "$workflow_test_root/scheduled.yml" "$workflow_test_root/workflows/scheduled.yml"

expect_required_workflow_failure() {
  local reason="$1" output code
  set +e
  output="$(validate_required_workflow "$workflow_test_root/ci.yml" 2>&1)"
  code=$?
  set -e
  [[ "$code" -ne 0 && "$output" == *"$reason"* ]] \
    || { refuse WORKFLOW_HOSTILE_FAILED "$reason code=$code output=$output"; exit 1; }
  cp .github/workflows/ci.yml "$workflow_test_root/ci.yml"
}

expect_required_context_failure() {
  local reason="$1" output code
  set +e
  output="$(validate_required_context "$workflow_test_root/ci.yml" 2>&1)"
  code=$?
  set -e
  [[ "$code" -ne 0 && "$output" == *"$reason"* ]] \
    || { refuse WORKFLOW_CONTEXT_HOSTILE_FAILED "$reason code=$code output=$output"; exit 1; }
  cp .github/workflows/ci.yml "$workflow_test_root/ci.yml"
}

expect_scheduled_failure() {
  local reason="$1" output code
  set +e
  output="$(validate_scheduled_uploads "$workflow_test_root/scheduled.yml" 2>&1)"
  code=$?
  set -e
  [[ "$code" -ne 0 && "$output" == *"$reason"* ]] \
    || { refuse SCHEDULED_HOSTILE_FAILED "$reason code=$code output=$output"; exit 1; }
  cp .github/workflows/scheduled.yml "$workflow_test_root/scheduled.yml"
}

append_hostile_job() {
  local workflow="$1" job="$2" path="${3-}"
  printf '\n  %s:\n    runs-on: ubuntu-24.04\n    steps:\n      - run: true\n' "$job" >>"$workflow"
  if [[ -n "$path" ]]; then
    printf '%s\n' \
      '      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02' \
      '        with:' \
      "          name: $job" \
      "          path: $path" >>"$workflow"
  fi
}

sed -i '0,/^          bash scripts\/ci-local\.sh lint$/{s//          true # bash scripts\/ci-local.sh lint/}' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_LANE_STEP_DRIFT
sed -i '0,/^        if: \${{ !cancelled() }}$/{s//        if: \${{ !cancelled() \&\& false }}/}' \
  "$workflow_test_root/ci.yml"
sed -i "0,/^          EXIT_CODE: .*|| '1' }}\$/{s/|| '1'/|| '0'/}" \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_LANE_STEP_DRIFT
sed -i "0,/^          EXIT_CODE: .*|| '1' }}\$/{s/|| '1'/|| '0'/}" \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_OBSERVATION_STEP_DRIFT
sed -i '/^      - id: lane$/a\        shell: sh -c '\''exit 0; # {0}'\''' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_EXECUTION_ENV_DRIFT
sed -i 's|^        run: bash scripts/ci-observation\.sh preflight|        run: true; bash scripts/ci-observation.sh preflight|' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_OBSERVATION_STEP_DRIFT
sed -i '/^      - name: Upload sanitized diagnostics$/,/^        uses:/{s/^        if: \${{ always() }}$/        if: \${{ !cancelled() }}/}' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_UPLOAD_STEP_DRIFT
sed -i '0,/^      - id: lane$/{s//      - run: true\n&/}' "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_STEP_INVENTORY_DRIFT
# The hostile payload must retain shell variables literally in generated YAML.
# shellcheck disable=SC2016
sed -i '/^  fast:$/a\    defaults:\n      run:\n        shell: bash -c '\''if [ -n "$EXIT_CODE" ]; then bash "$1"; else echo exit_code=0 >>"$GITHUB_OUTPUT"; fi'\'' _ {0}' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_EXECUTION_ENV_DRIFT
for hostile in '".ci-artifacts/"' './.ci-artifacts' '.ci-artifacts/**'; do
  sed -i "s|^          path: \.ci-artifacts/observations/preflight\.json\$|          path: $hostile|" \
    "$workflow_test_root/ci.yml"
  expect_required_workflow_failure HOSTED_UPLOAD_STEP_DRIFT
done
sed -i '/^            \.ci-artifacts\/junit\/fast\.xml$/a\            .ci-artifacts/**' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_UPLOAD_STEP_DRIFT
sed -i '/uses: actions\/upload-artifact@/,/^          name: kernel-preflight-/{s/^        with:$/        with: { path: .ci-artifacts\/** }/}' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_UPLOAD_STEP_DRIFT
sed -i '0,/^          path: \.ci-artifacts\/atomic\/observations$/{s//          path: .ci-artifacts\/atomic/}' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_DOWNLOAD_LAYOUT_DRIFT
sed -i '/^  preflight:$/a\    env:\n      BASH_ENV: .github/noop-lane.sh' \
  "$workflow_test_root/ci.yml"
expect_required_context_failure HOSTED_JOB_CONTEXT_DRIFT
sed -i '/^jobs:$/i\defaults:\n  run:\n    shell: bash -c '\''exit 0'\'' {0}' \
  "$workflow_test_root/ci.yml"
expect_required_context_failure HOSTED_WORKFLOW_CONTEXT_DRIFT
append_hostile_job "$workflow_test_root/ci.yml" extra-noop
expect_required_context_failure HOSTED_JOB_INVENTORY_DRIFT
append_hostile_job "$workflow_test_root/ci.yml" broad-upload '.ci-artifacts/**'
expect_required_workflow_failure HOSTED_ACTION_INVENTORY_DRIFT
sed -i '0,/^    steps:$/{s|^    steps:$|&\n      - uses : actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with: { name: broad-upload, path: .ci-artifacts/** }|}' \
  "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_ACTION_INVENTORY_DRIFT
sed -i '/^jobs:$/a\  # unbound workflow source is not admitted' "$workflow_test_root/ci.yml"
expect_required_workflow_failure HOSTED_REQUIRED_CONTEXT_DRIFT
append_hostile_job "$workflow_test_root/scheduled.yml" extra-noop
expect_scheduled_failure HOSTED_JOB_INVENTORY_DRIFT
append_hostile_job "$workflow_test_root/scheduled.yml" broad-upload '.ci-artifacts/**'
expect_scheduled_failure HOSTED_ACTION_INVENTORY_DRIFT
sed -i '0,/^    steps:$/{s|^    steps:$|&\n      - uses : actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with: { name: broad-upload, path: .ci-artifacts/** }|}' \
  "$workflow_test_root/scheduled.yml"
expect_scheduled_failure HOSTED_ACTION_INVENTORY_DRIFT
sed -i '0,/^    steps:$/{s|^    steps:$|&\n      - uses: "actions/upload-artifact\\u0040ea165f8d65b6e75b540449e92b4886f43607fa02"\n        with: { name: broad-upload, path: .ci-artifacts/** }|}' \
  "$workflow_test_root/scheduled.yml"
expect_scheduled_failure HOSTED_SCHEDULED_CONTEXT_DRIFT
# Hosted audit job: the lane must execute, observe, and be neutral only through
# the lane script's exact typed refusal.
sed -i '0,/^          bash scripts\/ci-local\.sh audit$/{s//          true # bash scripts\/ci-local.sh audit/}' \
  "$workflow_test_root/scheduled.yml"
expect_scheduled_failure HOSTED_AUDIT_LANE_STEP_DRIFT
sed -i '/^  audit:$/,$ s/^        if: \${{ !cancelled() }}$/        if: \${{ false }}/' \
  "$workflow_test_root/scheduled.yml"
expect_scheduled_failure HOSTED_AUDIT_LANE_STEP_DRIFT
sed -i 's|^        run: bash scripts/ci-observation\.sh audit |        run: true; bash scripts/ci-observation.sh audit |' \
  "$workflow_test_root/scheduled.yml"
expect_scheduled_failure HOSTED_AUDIT_OBSERVATION_DRIFT
sed -i '/^  audit:$/,$d' "$workflow_test_root/scheduled.yml"
expect_scheduled_failure HOSTED_ACTION_INVENTORY_DRIFT

expect_audit_source_failure() {
  local reason="$1" output code
  set +e
  output="$(validate_audit_neutral_source "$workflow_test_root/audit.sh" 2>&1)"
  code=$?
  set -e
  [[ "$code" -ne 0 && "$output" == *"$reason"* ]] \
    || { refuse AUDIT_SOURCE_HOSTILE_FAILED "$reason code=$code output=$output"; exit 1; }
  rm -f -- "$workflow_test_root/audit.sh"
  cp ops/ci/audit.sh "$workflow_test_root/audit.sh"
}
cp ops/ci/audit.sh "$workflow_test_root/audit.sh"
validate_audit_neutral_source "$workflow_test_root/audit.sh" || exit 1
sed -i '0,/^    exit 78$/{s//    exit 0/}' "$workflow_test_root/audit.sh"
expect_audit_source_failure HOSTED_AUDIT_NEUTRAL_DRIFT
sed -i '/^  refuse AUDITOR_MISSING /d' "$workflow_test_root/audit.sh"
expect_audit_source_failure HOSTED_AUDIT_NEUTRAL_DRIFT
sed -i '0,/^  exit 1$/{s//  exit 0/}' "$workflow_test_root/audit.sh"
expect_audit_source_failure HOSTED_AUDIT_NEUTRAL_DRIFT
# The hostile payload keeps the shell variable literal.
# shellcheck disable=SC2016
sed -i 's/^  if \[\[ "\${GITHUB_ACTIONS:-}" == true \]\]; then$/  if true; then/' "$workflow_test_root/audit.sh"
expect_audit_source_failure HOSTED_AUDIT_NEUTRAL_DRIFT
sed -i '/^jankurai audit \. /,/^  --json /d' "$workflow_test_root/audit.sh"
expect_audit_source_failure HOSTED_AUDIT_NEUTRAL_DRIFT
rm -- "$workflow_test_root/audit.sh"
ln -s "$REPO_ROOT/ops/ci/audit.sh" "$workflow_test_root/audit.sh"
expect_audit_source_failure HOSTED_AUDIT_NEUTRAL_DRIFT
