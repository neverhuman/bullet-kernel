#!/usr/bin/env bash
# Sourced hosted-workflow structure, subject, and archive contract.
# Expected blocks intentionally preserve shell and GitHub expressions literally.
# shellcheck disable=SC2016

literal_dollar='$'

workflow_job_block() {
  local workflow="$1" job="$2"
  awk -v target="  $job:" '
    /^  [a-z][a-z-]*:$/ {
      if (found) { exit }
      if ($0 == target) { found=1 }
    }
    found { print }
  ' "$workflow"
}

sha256_text() {
  printf '%s' "$1" | sha256sum | awk '{ print $1 }'
}

workflow_header() {
  awk '$0 == "jobs:" { exit } { print }' "$1"
}

workflow_job_ids() {
  awk '
    $0 == "jobs:" { in_jobs=1; next }
    in_jobs && /^[^ ]/ { exit }
    in_jobs && /^  [A-Za-z_][A-Za-z0-9_-]*:$/ {
      value=$0
      sub(/^  /, "", value)
      sub(/:$/, "", value)
      print value
    }
  ' "$1"
}

expect_job_inventory() {
  local workflow="$1" actual expected
  shift
  actual="$(workflow_job_ids "$workflow")"
  expected="$(printf '%s\n' "$@")"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_JOB_INVENTORY_DRIFT "$actual"; return 1; }
}

expect_global_action_count() {
  local workflow="$1" action="$2" expected="$3" actual needle="actions/$2@"
  actual="$(awk -v needle="$needle" '
    {
      line=$0
      while ((offset=index(line, needle)) > 0) {
        count++
        line=substr(line, offset + length(needle))
      }
    }
    END { print count + 0 }
  ' "$workflow")"
  [[ "$actual" -eq "$expected" ]] \
    || { refuse HOSTED_ACTION_INVENTORY_DRIFT "$action=$actual"; return 1; }
}

expected_context_digest() {
  case "$1" in
    header) printf '%s\n' 4c4f307636e38761db26d62f4dfa81ddd69c161d14c48a8e2fab25b741c729b0 ;;
    preflight) printf '%s\n' 27e9a021702b1f2f000d0bdff459e664ccc8cac7a746cf3d0e54c60dcfa2b225 ;;
    fast) printf '%s\n' 0059a0451f5e0d1bed388030dd997e9e9096d670d800f3669037676b67d5ffa0 ;;
    lint) printf '%s\n' 20a034924d4b9b1665d0bcd1d2825bc1cd57ffc70aeaa11da58fd356b4bec038 ;;
    contract) printf '%s\n' 7a3c15047e212633d56ee5787a74891ae4283ec58795c469ec429e40f5d9da70 ;;
    security) printf '%s\n' 15e5e5aceec8f0255af37993c8b7067e17e1f2d0089f8a230dd49416fb559914 ;;
    docs) printf '%s\n' d9cc1e81b45c3bef36efe7955142924c1eb6b3ac4b4fbf18f9018c72bed63c2a ;;
    required) printf '%s\n' b4dff6def32376ff8c26152c4026456995fa1b3e59298fecb2348456f8dfec9a ;;
    *) return 2 ;;
  esac
}

validate_required_context() {
  local workflow="$1" subject actual expected block
  actual="$(sha256_text "$(workflow_header "$workflow")")"
  expected="$(expected_context_digest header)"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_WORKFLOW_CONTEXT_DRIFT "$actual"; return 1; }
  expect_job_inventory "$workflow" preflight fast lint contract security docs required || return 1
  for subject in preflight fast lint contract security docs required; do
    block="$(workflow_job_block "$workflow" "$subject")"
    actual="$(sha256_text "$block")"
    expected="$(expected_context_digest "$subject")"
    [[ "$actual" == "$expected" ]] \
      || { refuse HOSTED_JOB_CONTEXT_DRIFT "$subject=$actual"; return 1; }
  done
}

upload_step_block() {
  awk '
    /^      - / {
      if (in_step && upload) { printf "%s", block }
      block=$0 ORS
      in_step=1
      upload=0
      next
    }
    in_step {
      block=block $0 ORS
      if ($0 ~ /^        uses: actions\/upload-artifact@[0-9a-f]{40}/) { upload=1 }
    }
    END { if (in_step && upload) { printf "%s", block } }
  ' <<<"$1"
}

workflow_step_block() {
  local job_block="$1" anchor="$2"
  awk -v target="$anchor" '
    $0 == target { found=1 }
    found {
      if (seen && /^      - /) { exit }
      print
      seen=1
    }
  ' <<<"$job_block"
}

expected_lane_step() {
  local lane="$1" name
  case "$lane" in
    preflight) name='Scan source and lockfiles before dependency installation' ;;
    fast) name='Standalone component partition' ;;
    lint) name='Rust and CI policy lint' ;;
    contract) name='Offline provider contracts and simulation' ;;
    security) name='Secrets, advisories, bans, licenses, sources, workflows' ;;
    docs) name='Contracts, rustdoc, and relative links' ;;
    *) return 2 ;;
  esac
  printf '%s\n' \
    '      - id: lane' \
    '        if: ${{ !cancelled() }}' \
    "        name: $name" \
    '        run: |' \
    '          set +e' \
    "          bash scripts/ci-local.sh $lane" \
    '          code=$?' \
    '          set -e' \
    '          printf '\''exit_code=%s\n'\'' "$code" >>"$GITHUB_OUTPUT"' \
    '          exit "$code"'
}

expected_observation_step() {
  local lane="$1"
  printf '%s\n' \
    '      - name: Write unsigned diagnostic observation' \
    '        if: ${{ always() }}' \
    '        env:' \
    "          EXIT_CODE: \${{ steps.lane.outputs.exit_code || '1' }}"
  if [[ "$lane" == fast || "$lane" == contract ]]; then
    printf '%s\n' \
      '        run: |' \
      '          artifacts=()' \
      "          [[ -f .ci-artifacts/junit/$lane.xml ]] && artifacts+=(.ci-artifacts/junit/$lane.xml)" \
      "          bash scripts/ci-observation.sh $lane \"\$EXIT_CODE\" 'bash scripts/ci-local.sh $lane' \"\${artifacts[@]}\""
  else
    printf '        run: bash scripts/ci-observation.sh %s "$EXIT_CODE" '\''bash scripts/ci-local.sh %s'\''\n' \
      "$lane" "$lane"
  fi
}

expected_upload_step() {
  local lane="$1"
  printf '%s\n' \
    '      - name: Upload sanitized diagnostics' \
    '        if: ${{ always() }}' \
    '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2' \
    '        with:'
  printf '          name: kernel-%s-${{ github.run_id }}-${{ github.run_attempt }}\n' "$lane"
  if [[ "$lane" == fast || "$lane" == contract ]]; then
    printf '%s\n' \
      '          path: |' \
      "            .ci-artifacts/observations/$lane.json" \
      "            .ci-artifacts/junit/$lane.xml"
  else
    printf '          path: .ci-artifacts/observations/%s.json\n' "$lane"
  fi
  printf '%s\n' \
    '          include-hidden-files: true' \
    '          if-no-files-found: error' \
    '          retention-days: 14'
}

expected_download_step() {
  local lane="$1" name destination
  case "$lane" in
    preflight) name='Download preflight observation'; destination='.ci-artifacts/atomic/observations' ;;
    fast) name='Download fast observation and JUnit'; destination='.ci-artifacts/atomic' ;;
    lint) name='Download lint observation'; destination='.ci-artifacts/atomic/observations' ;;
    contract) name='Download contract observation and JUnit'; destination='.ci-artifacts/atomic' ;;
    security) name='Download security observation'; destination='.ci-artifacts/atomic/observations' ;;
    docs) name='Download docs observation'; destination='.ci-artifacts/atomic/observations' ;;
    *) return 2 ;;
  esac
  printf '%s\n' \
    "      - name: $name" \
    '        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0' \
    '        with:'
  printf '          name: kernel-%s-${{ github.run_id }}-${{ github.run_attempt }}\n' "$lane"
  printf '          path: %s\n' "$destination"
}

expected_aggregate_step() {
  printf '%s\n' \
    '      - name: Reject failed, skipped, cancelled, missing, or malformed predecessors' \
    '        run: >-' \
    '          bash ops/ci/aggregate.sh .ci-artifacts/atomic "$EXPECTED_COMMIT"' \
    '          "$PREFLIGHT_RESULT" "$FAST_RESULT" "$LINT_RESULT"' \
    '          "$CONTRACT_RESULT" "$SECURITY_RESULT" "$DOCS_RESULT"'
}

workflow_environment() {
  awk '
    /^env:$/ { found=1 }
    found {
      if (seen && !/^  /) { exit }
      print
      seen=1
    }
  ' "$1"
}

job_environment() {
  awk '
    /^    env:$/ { found=1 }
    found {
      if (seen && /^    [^ ]/ && !/^    env:$/) { exit }
      print
      seen=1
    }
  ' <<<"$1"
}

upload_paths() {
  awk '
    /^          path:[[:space:]]*/ {
      value=$0
      sub(/^          path:[[:space:]]*/, "", value)
      if (value == "|") { multiline=1; next }
      print value
      exit
    }
    multiline && /^            / {
      value=$0
      sub(/^            /, "", value)
      print value
      next
    }
    multiline { exit }
  ' <<<"$1"
}

expect_upload_paths() {
  local workflow="$1" job="$2" expected="$3" block upload_step actual always_guard inline_guard guard_count
  block="$(workflow_job_block "$workflow" "$job")"
  [[ -n "$block" ]] || { refuse HOSTED_LANE_MISSING "$job"; return 1; }
  [[ "$(rg -c 'uses: actions/upload-artifact@' <<<"$block")" -eq 1 ]] \
    || { refuse HOSTED_UPLOAD_ACTION_DRIFT "$job"; return 1; }
  upload_step="$(upload_step_block "$block")"
  [[ -n "$upload_step" ]] || { refuse HOSTED_UPLOAD_STEP_MISSING "$job"; return 1; }
  always_guard="        if: ${literal_dollar}{{ always() }}"
  inline_guard="      - if: ${literal_dollar}{{ always() }}"
  guard_count="$(awk -v named="$always_guard" -v inline="$inline_guard" \
    '$0 == named || $0 == inline { count++ } END { print count + 0 }' <<<"$upload_step")"
  [[ "$guard_count" -eq 1 ]] \
    || { refuse HOSTED_UPLOAD_GUARD_DRIFT "$job"; return 1; }
  [[ "$(rg -c '^        with:' <<<"$upload_step")" -eq 1 &&
     "$(rg -Fxc '        with:' <<<"$upload_step")" -eq 1 ]] \
    || { refuse HOSTED_UPLOAD_WITH_DRIFT "$job"; return 1; }
  [[ "$(rg -c '^          path:' <<<"$upload_step")" -eq 1 ]] \
    || { refuse HOSTED_UPLOAD_PATH_FIELD_DRIFT "$job"; return 1; }
  actual="$(upload_paths "$upload_step")"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_UPLOAD_ALLOWLIST_MISMATCH "$job=$actual"; return 1; }
}

validate_required_workflow() {
  local workflow="$1" lane block actual expected required expected_steps anchor
  expect_global_action_count "$workflow" upload-artifact 6 || return 1
  expect_global_action_count "$workflow" download-artifact 6 || return 1
  expect_job_inventory "$workflow" preflight fast lint contract security docs required || return 1
  if rg -n '^[[:space:]]+(defaults|shell|container|services):|^[[:space:]]+(BASH_ENV|ENV|PATH):' "$workflow"; then
    refuse HOSTED_EXECUTION_ENV_DRIFT "$workflow"
    return 1
  fi
  expected="$(printf '%s\n' 'env:' '  CARGO_TERM_COLOR: always' '  RUSTUP_AUTO_INSTALL: "0"')"
  actual="$(workflow_environment "$workflow")"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_EXECUTION_ENV_DRIFT workflow; return 1; }
  for lane in preflight fast lint contract security docs; do
    block="$(workflow_job_block "$workflow" "$lane")"
    [[ -n "$block" ]] || { refuse HOSTED_LANE_MISSING "$lane"; return 1; }
    [[ "$(rg -Fxc '    runs-on: ubuntu-24.04' <<<"$block")" -eq 1 ]] \
      || { refuse HOSTED_RUNNER_DRIFT "$lane"; return 1; }
    [[ -z "$(job_environment "$block")" ]] \
      || { refuse HOSTED_EXECUTION_ENV_DRIFT "$lane"; return 1; }
    case "$lane" in
      preflight|docs) expected_steps=5 ;;
      fast|contract) expected_steps=6 ;;
      lint|security) expected_steps=7 ;;
    esac
    [[ "$(rg -c '^      - ' <<<"$block")" -eq "$expected_steps" ]] \
      || { refuse HOSTED_STEP_INVENTORY_DRIFT "$lane"; return 1; }
    if [[ "$lane" != preflight ]]; then
      [[ "$(rg -Fxc '    needs: preflight' <<<"$block")" -eq 1 ]] \
        || { refuse HOSTED_SOURCE_PREDECESSOR_DRIFT "$lane"; return 1; }
    fi
    anchor='      - id: lane'
    [[ "$(rg -Fxc "$anchor" <<<"$block")" -eq 1 ]] \
      || { refuse HOSTED_LANE_STEP_DRIFT "$lane"; return 1; }
    actual="$(workflow_step_block "$block" "$anchor")"
    expected="$(expected_lane_step "$lane")"
    [[ "$actual" == "$expected" ]] \
      || { refuse HOSTED_LANE_STEP_DRIFT "$lane"; return 1; }
    anchor='      - name: Write unsigned diagnostic observation'
    [[ "$(rg -Fxc "$anchor" <<<"$block")" -eq 1 ]] \
      || { refuse HOSTED_OBSERVATION_STEP_DRIFT "$lane"; return 1; }
    actual="$(workflow_step_block "$block" "$anchor")"
    expected="$(expected_observation_step "$lane")"
    [[ "$actual" == "$expected" ]] \
      || { refuse HOSTED_OBSERVATION_STEP_DRIFT "$lane"; return 1; }
    anchor='      - name: Upload sanitized diagnostics'
    [[ "$(rg -Fxc "$anchor" <<<"$block")" -eq 1 ]] \
      || { refuse HOSTED_UPLOAD_STEP_DRIFT "$lane"; return 1; }
    actual="$(workflow_step_block "$block" "$anchor")"
    expected="$(expected_upload_step "$lane")"
    [[ "$actual" == "$expected" ]] \
      || { refuse HOSTED_UPLOAD_STEP_DRIFT "$lane"; return 1; }
  done

  required="$(workflow_job_block "$workflow" required)"
  [[ "$(rg -Fxc '    runs-on: ubuntu-24.04' <<<"$required")" -eq 1 ]] \
    || { refuse HOSTED_RUNNER_DRIFT required; return 1; }
  [[ "$(rg -c '^      - ' <<<"$required")" -eq 8 &&
     "$(rg -Fxc '    if: ${{ always() }}' <<<"$required")" -eq 1 &&
     "$(rg -Fxc '    needs: [preflight, fast, lint, contract, security, docs]' <<<"$required")" -eq 1 ]] \
    || { refuse HOSTED_REQUIRED_JOB_DRIFT required; return 1; }
  expected="$(printf '%s\n' \
    '    env:' \
    '      EXPECTED_COMMIT: ${{ github.sha }}' \
    '      PREFLIGHT_RESULT: ${{ needs.preflight.result }}' \
    '      FAST_RESULT: ${{ needs.fast.result }}' \
    '      LINT_RESULT: ${{ needs.lint.result }}' \
    '      CONTRACT_RESULT: ${{ needs.contract.result }}' \
    '      SECURITY_RESULT: ${{ needs.security.result }}' \
    '      DOCS_RESULT: ${{ needs.docs.result }}')"
  actual="$(job_environment "$required")"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_RESULT_BINDING_DRIFT required; return 1; }
  for lane in preflight fast lint contract security docs; do
    case "$lane" in
      preflight) anchor='      - name: Download preflight observation' ;;
      fast) anchor='      - name: Download fast observation and JUnit' ;;
      lint) anchor='      - name: Download lint observation' ;;
      contract) anchor='      - name: Download contract observation and JUnit' ;;
      security) anchor='      - name: Download security observation' ;;
      docs) anchor='      - name: Download docs observation' ;;
    esac
    actual="$(workflow_step_block "$required" "$anchor")"
    expected="$(expected_download_step "$lane")"
    [[ "$actual" == "$expected" ]] \
      || { refuse HOSTED_DOWNLOAD_LAYOUT_DRIFT "$lane"; return 1; }
    [[ "$(rg -Fxc "      ${lane^^}_RESULT: \${{ needs.$lane.result }}" <<<"$required")" -eq 1 ]] \
      || { refuse HOSTED_RESULT_BINDING_DRIFT "$lane"; return 1; }
  done
  anchor='      - name: Reject failed, skipped, cancelled, missing, or malformed predecessors'
  actual="$(workflow_step_block "$required" "$anchor")"
  expected="$(expected_aggregate_step)"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_AGGREGATE_STEP_DRIFT required; return 1; }

  actual="$(for lane in preflight fast lint contract security docs; do
    block="$(workflow_job_block "$workflow" "$lane")"
    mapfile -t paths < <(upload_paths "$(workflow_step_block "$block" '      - name: Upload sanitized diagnostics')")
    if [[ "${#paths[@]}" -eq 1 ]]; then
      printf 'observations/%s\n' "${paths[0]##*/}"
    else
      for path in "${paths[@]}"; do printf '%s\n' "${path#.ci-artifacts/}"; done
    fi
  done | LC_ALL=C sort)"
  expected="$(printf '%s\n' junit/contract.xml junit/fast.xml \
    observations/contract.json observations/docs.json observations/fast.json \
    observations/lint.json observations/preflight.json observations/security.json | LC_ALL=C sort)"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_ARCHIVE_LAYOUT_DRIFT "$actual"; return 1; }
  actual="$(sha256sum "$workflow" | awk '{ print $1 }')"
  [[ "$actual" == 5e45f68e8a682b8f474ff73bfa0b35545af3a77f3a13534fa4f462c6e1e1451d ]] \
    || { refuse HOSTED_REQUIRED_CONTEXT_DRIFT "$actual"; return 1; }
}

expected_scheduled_audit_lane_step() {
  printf '%s\n' \
    '      - id: lane' \
    '        if: ${{ !cancelled() }}' \
    '        run: |' \
    '          set +e' \
    '          bash scripts/ci-local.sh audit' \
    '          code=$?' \
    '          set -e' \
    '          printf '\''exit_code=%s\n'\'' "$code" >>"$GITHUB_OUTPUT"' \
    '          exit "$code"'
}

validate_scheduled_audit_lane() {
  local workflow="$1" block actual expected anchor
  block="$(workflow_job_block "$workflow" audit)"
  [[ -n "$block" ]] || { refuse HOSTED_LANE_MISSING audit; return 1; }
  [[ "$(rg -Fxc '    runs-on: ubuntu-24.04' <<<"$block")" -eq 1 ]] \
    || { refuse HOSTED_RUNNER_DRIFT audit; return 1; }
  [[ "$(rg -Fxc '    needs: source-admission' <<<"$block")" -eq 1 ]] \
    || { refuse HOSTED_SOURCE_PREDECESSOR_DRIFT audit; return 1; }
  anchor='      - id: lane'
  [[ "$(rg -Fxc "$anchor" <<<"$block")" -eq 1 ]] \
    || { refuse HOSTED_AUDIT_LANE_STEP_DRIFT audit; return 1; }
  actual="$(workflow_step_block "$block" "$anchor")"
  expected="$(expected_scheduled_audit_lane_step)"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_AUDIT_LANE_STEP_DRIFT audit; return 1; }
  anchor='        run: bash scripts/ci-observation.sh audit "$EXIT_CODE" '\''bash scripts/ci-local.sh audit'\'''
  [[ "$(rg -Fxc "$anchor" <<<"$block")" -eq 1 ]] \
    || { refuse HOSTED_AUDIT_OBSERVATION_DRIFT audit; return 1; }
}

# The hosted audit job is neutral only through the lane script's exact typed
# refusal (78 AUDITOR_UNAVAILABLE_HOSTED); a script that exits green or untyped
# without the auditor, or never invokes it, is drift.
expected_audit_resolution() {
  printf '%s\n' \
    'if ! command -v jankurai >/dev/null 2>&1; then' \
    '  if [[ "${GITHUB_ACTIONS:-}" == true ]]; then' \
    '    log "neutral (78): AUDITOR_UNAVAILABLE_HOSTED: jankurai 1.6.11 is a machine-local build with no checksum-pinned hosted artifact; the audit did not run"' \
    '    exit 78' \
    '  fi' \
    '  refuse AUDITOR_MISSING "jankurai is not on PATH; the audit lane fails closed"' \
    '  exit 1' \
    'fi'
}

validate_audit_neutral_source() {
  local script="$1" actual expected
  [[ -f "$script" && ! -L "$script" ]] \
    || { refuse HOSTED_AUDIT_NEUTRAL_DRIFT "$script"; return 1; }
  actual="$(awk '
    $0 == "if ! command -v jankurai >/dev/null 2>&1; then" { found=1 }
    found { print }
    found && $0 == "fi" { exit }
  ' "$script")"
  expected="$(expected_audit_resolution)"
  [[ "$actual" == "$expected" ]] \
    || { refuse HOSTED_AUDIT_NEUTRAL_DRIFT "$script"; return 1; }
  [[ "$(rg -c '^jankurai audit \. ' "$script")" -eq 1 && "$(rg -Fxc '    exit 78' "$script")" -eq 1 ]] \
    || { refuse HOSTED_AUDIT_NEUTRAL_DRIFT "$script"; return 1; }
}

validate_scheduled_uploads() {
  local workflow="$1" audit_script="${2:-ops/ci/audit.sh}" actual
  expect_global_action_count "$workflow" upload-artifact 7 || return 1
  expect_job_inventory "$workflow" source-admission links advisories coverage history-secrets portable-refusal audit || return 1
  validate_scheduled_audit_lane "$workflow" || return 1
  validate_audit_neutral_source "$audit_script" || return 1
  expect_upload_paths "$workflow" source-admission '.ci-artifacts/observations/scheduled-preflight.json' || return 1
  expect_upload_paths "$workflow" links '.ci-artifacts/observations/links.json' || return 1
  expect_upload_paths "$workflow" advisories '.ci-artifacts/observations/scheduled-security.json' || return 1
  expect_upload_paths "$workflow" coverage $'.ci-artifacts/observations/coverage.json\n.ci-artifacts/coverage/summary.json' || return 1
  expect_upload_paths "$workflow" history-secrets '.ci-artifacts/observations/history-secrets.json' || return 1
  # GitHub expands this expression; the local policy compares the literal source.
  # shellcheck disable=SC2016
  expect_upload_paths "$workflow" portable-refusal '.ci-artifacts/observations/portable-${{ matrix.os }}.json' || return 1
  expect_upload_paths "$workflow" audit '.ci-artifacts/observations/audit.json' || return 1
  actual="$(sha256sum "$workflow" | awk '{ print $1 }')"
  [[ "$actual" == 844082771185883a16508ee80a8560b83187119d7f42a75a7b0bc00fe6683082 ]] \
    || { refuse HOSTED_SCHEDULED_CONTEXT_DRIFT "$actual"; return 1; }
}

validate_required_ci() {
  validate_required_context "$1" && validate_required_workflow "$1"
}
