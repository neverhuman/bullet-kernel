#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

workflow_files=(.github/workflows/*.yml .github/workflows/*.yaml)
existing_workflows=()
for workflow in "${workflow_files[@]}"; do
  [[ -f "$workflow" ]] && existing_workflows+=("$workflow")
done
[[ "${#existing_workflows[@]}" -gt 0 ]] \
  || { refuse WORKFLOW_INVENTORY_EMPTY "no workflow files found"; exit 1; }

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
  'pattern: kernel-\*-\$\{\{ github.run_id \}\}-\$\{\{ github.run_attempt \}\}'
  "observation=\"\.ci-artifacts/atomic/observations/\\\$lane\.json\""
  "\.commit_oid == \\\$commit"
  "\.outcomes == \[\{\"lane\": \\\$lane, \"status\": \"PASS\", \"exit_code\": 0\}\]"
  "sha256sum \"\\\$artifact\""
  'junit/contract\.xml'
  'observations/security\.json'
  'find \.ci-artifacts/atomic -type f'
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

checkout_count="$(rg -c 'uses: actions/checkout@' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
credential_count="$(rg -c 'persist-credentials: false' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
[[ "$checkout_count" -eq "$credential_count" ]] \
  || { refuse CHECKOUT_CREDENTIAL_POLICY "every checkout must disable persisted credentials"; exit 1; }

lane_step_count="$(rg -c '^[[:space:]]{6}- id: lane$' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
noncancelled_lane_count="$(rg -c '^[[:space:]]{8}if:.*!cancelled\(\)' "${existing_workflows[@]}" | awk -F: '{ total += $NF } END { print total + 0 }')"
[[ "$lane_step_count" -eq "$noncancelled_lane_count" && "$lane_step_count" -gt 0 ]] \
  || { refuse LANE_SETUP_FAILURE_POLICY "every lane command must run after setup failure unless cancelled"; exit 1; }

[[ "$(rg -c '^\[\[job\]\]$' ci.toml)" -eq 5 ]] \
  || { refuse JERYU_JOB_INVENTORY_DRIFT "ci.toml must contain exactly five atomic jobs"; exit 1; }
for lane in fast lint contract security docs; do
  rg -Fq "run = [\"bash scripts/ci-local.sh $lane\"]" ci.toml \
    || { refuse JERYU_COMMAND_DRIFT "$lane does not invoke its local lane script"; exit 1; }
done
if rg -n 'cache_mounts|path = "\.\./' ci.toml; then
  refuse JERYU_POLICY_VIOLATION "explicit caches and sibling path dependencies are forbidden"
  exit 1
fi

log "workflow policy passed"
