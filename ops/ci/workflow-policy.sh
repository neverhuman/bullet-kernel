#!/usr/bin/env bash
# Expected workflow blocks intentionally preserve shell and GitHub expressions literally.
# shellcheck disable=SC2016
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

validate_workflow_inventory() {
  local workflow_root="$1" required index
  local actual=() expected=("$workflow_root/ci.yml" "$workflow_root/scheduled.yml")
  [[ -d "$workflow_root" && ! -L "$workflow_root" ]] \
    || { refuse WORKFLOW_DIRECTORY_INVALID "$workflow_root"; return 1; }
  while IFS= read -r -d '' required; do
    actual+=("$required")
  done < <(find "$workflow_root" -mindepth 1 -maxdepth 1 -print0 | LC_ALL=C sort -z)
  [[ "${#actual[@]}" -eq "${#expected[@]}" ]] \
    || { refuse WORKFLOW_INVENTORY_DRIFT "${actual[*]}"; return 1; }
  for index in "${!expected[@]}"; do
    [[ "${actual[$index]}" == "${expected[$index]}" ]] \
      || { refuse WORKFLOW_INVENTORY_DRIFT "${actual[*]}"; return 1; }
  done
  for required in "${expected[@]}"; do
    [[ -f "$required" && ! -L "$required" ]] \
      || { refuse WORKFLOW_ENTRY_INVALID "$required"; return 1; }
  done
}

validate_workflow_inventory .github/workflows || exit 1
existing_workflows=(.github/workflows/ci.yml .github/workflows/scheduled.yml)

if rg -n 'pull_request_target|paths-ignore:|^[[:space:]]+paths:|ubuntu-latest|persist-credentials:[[:space:]]*true|Swatinem/rust-cache|actions/cache|continue-on-error:[[:space:]]*true|write-all|^[[:space:]]+[a-z-]+:[[:space:]]*write' \
  "${existing_workflows[@]}"; then
  refuse WORKFLOW_POLICY_VIOLATION "forbidden trigger, path filter, runner alias, credentials, or cache"
  exit 1
fi
while IFS= read -r use_line; do
  use_ref="${use_line#*uses: }"
  use_ref="${use_ref%% *}"
  if [[ ! "$use_ref" =~ @[0-9a-f]{40}$ ]]; then
    refuse ACTION_REF_NOT_IMMUTABLE "$use_line"
    exit 1
  fi
done < <(rg '^[[:space:]]*-[[:space:]]+uses:[[:space:]]+' "${existing_workflows[@]}")

literal_dollar='$'
required_patterns=(
  '^name: CI$'
  '^  pull_request:'
  '^  push:'
  '^  merge_group:'
  '^  contents: read$'
  'cancel-in-progress:.*github.event_name == .pull_request.'
  '^    name: required$'
  '^  required:$'
  '^    if:.*always\(\)'
  'needs: \[preflight, fast, lint, contract, security, docs\]'
  'uses: actions/download-artifact@[0-9a-f]{40}'
  'bash ops/ci/aggregate\.sh'
  "\"\\${literal_dollar}EXPECTED_COMMIT\""
  "\"\\${literal_dollar}PREFLIGHT_RESULT\""
  "\"\\${literal_dollar}DOCS_RESULT\""
)
for pattern in "${required_patterns[@]}"; do
  rg -q "$pattern" .github/workflows/ci.yml \
    || { refuse REQUIRED_WORKFLOW_CONTROL_MISSING "$pattern"; exit 1; }
done

[[ "$(rg -c '^name: CI$' .github/workflows/ci.yml)" -eq 1 &&
   "$(rg -c '^  required:$' .github/workflows/ci.yml)" -eq 1 &&
   "$(rg -c '^    name: required$' .github/workflows/ci.yml)" -eq 1 ]] \
  || { refuse PROTECTED_CONTEXT_DRIFT "workflow CI / job required must be unique"; exit 1; }

[[ "$(rg -c 'name: Write unsigned diagnostic observation' .github/workflows/ci.yml)" -eq 6 &&
   "$(rg -c 'name: Upload sanitized diagnostics' .github/workflows/ci.yml)" -eq 6 ]] \
  || { refuse ATOMIC_OBSERVATION_INVENTORY_DRIFT "six lanes must write and upload observations"; exit 1; }

# shellcheck source=ops/ci/workflow-contract.sh
source "$(dirname "${BASH_SOURCE[0]}")/workflow-contract.sh"
validate_required_ci .github/workflows/ci.yml || exit 1
validate_scheduled_uploads .github/workflows/scheduled.yml || exit 1

# shellcheck source=ops/ci/workflow-policy-test.sh
source "$(dirname "${BASH_SOURCE[0]}")/workflow-policy-test.sh"

checkout_count="$(rg -c 'uses: actions/checkout@' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
credential_count="$(rg -c 'persist-credentials: false' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
[[ "$checkout_count" -eq "$credential_count" ]] \
  || { refuse CHECKOUT_CREDENTIAL_POLICY "every checkout must disable persisted credentials"; exit 1; }

lane_step_count="$(rg -c '^[[:space:]]{6}- id: lane$' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
noncancelled_lane_count="$(rg -c '^[[:space:]]{8}if:.*!cancelled\(\)' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
[[ "$lane_step_count" -eq "$noncancelled_lane_count" && "$lane_step_count" -gt 0 ]] \
  || { refuse LANE_SETUP_FAILURE_POLICY "every lane command must run after setup failure unless cancelled"; exit 1; }

toml_job_block() {
  local job="$1"
  awk -v target="id = \"$job\"" '
    $0 == "[[job]]" { if (found) { exit }; block=$0 ORS; next }
    { block=block $0 ORS; if ($0 == target) { found=1 } }
    END { if (found) { printf "%s", block } }
  ' ci.toml
}

[[ "$(rg -c '^\[\[job\]\]$' ci.toml)" -eq 8 ]] \
  || { refuse JERYU_JOB_INVENTORY_DRIFT "ci.toml must contain eight prepared jobs"; exit 1; }
[[ "$(rg -c '^cache_mounts = \[\]$' ci.toml)" -eq 8 ]] \
  || { refuse JERYU_CACHE_POLICY_DRIFT "all prepared jobs must be cache-free"; exit 1; }
for job in activation preflight fast lint contract security docs required; do
  block="$(toml_job_block "$job")"
  [[ -n "$block" ]] || { refuse JERYU_JOB_MISSING "$job"; exit 1; }
  [[ "$block" == *'run = ["bash ops/ci/jeryu-activation-gate.sh"'* ]] \
    || { refuse JERYU_ACTIVATION_GATE_MISSING "$job"; exit 1; }
done
preflight_block="$(toml_job_block preflight)"
[[ "$preflight_block" == *'needs = ["activation"]'* &&
   "$preflight_block" == *'"bash scripts/ci-local.sh preflight"'* ]] \
  || { refuse JERYU_SOURCE_ADMISSION_INVALID "preflight"; exit 1; }
for lane in fast lint contract security docs; do
  block="$(toml_job_block "$lane")"
  [[ "$block" == *'needs = ["preflight"]'* &&
     "$block" == *"\"bash scripts/ci-local.sh $lane\""* ]] \
    || { refuse JERYU_COMMAND_DRIFT "$lane"; exit 1; }
done
required_block="$(toml_job_block required)"
[[ "$required_block" == *'needs = ["preflight", "fast", "lint", "contract", "security", "docs"]'* ]] \
  || { refuse JERYU_REQUIRED_CONVERGENCE_INVALID "required"; exit 1; }
if rg -n 'path = "\.\./|artifact_paths = \["\.ci-artifacts"\]' ci.toml; then
  refuse JERYU_POLICY_VIOLATION "sibling paths and broad artifact roots are forbidden"
  exit 1
fi

set +e
jeryu_refusal="$(bash ops/ci/jeryu-activation-gate.sh 2>&1)"
jeryu_code=$?
set -e
[[ "$jeryu_code" -eq 78 && "$jeryu_refusal" == *'JERYU_CI_NOT_RATIFIED'* ]] \
  || { refuse JERYU_ACTIVATION_REFUSAL_INVALID "code=$jeryu_code"; exit 1; }

log "workflow policy passed"
