#!/usr/bin/env bash
# Sourced after lib.sh. Historical bytes are private diagnostics, never admission.
retain_junit_reports() (
  local retention_profile="$1" retention_lane="$2" uid history archive="" path name identity digest
  local root_identity history_identity archive_identity after tool index
  local -a paths names
  for tool in mktemp mv sync; do require_tool "$tool" || return 1; done
  prepare_junit_store "$retention_profile" "$retention_lane" || return 1
  uid="$(id -u)" || return 1
  root_identity="$(junit_store_identity "$retention_profile")" || return 1
  paths=("$REPO_ROOT/target/nextest/$retention_profile/junit.xml" "$REPO_ROOT/.ci-artifacts/junit/$retention_lane.xml")
  names=(raw.xml published.xml)
  # Validate both subjects before moving either. Failed/empty reports are retained
  # too; no XML validation or outcome interpretation belongs in this operation.
  for path in "${paths[@]}"; do
    [[ -e "$path" || -L "$path" ]] || continue
    identity="$(junit_file_identity "$path")" || {
      refuse JUNIT_RETENTION_SUBJECT_INVALID 'previous report is not a regular file'; return 1;
    }
    [[ "$identity" =~ ^[^:]+:[^:]+:$uid:600:1:[0-9]+:regular(\ empty)?\ file$ ]] || {
      refuse JUNIT_RETENTION_SUBJECT_INVALID 'previous report ownership, links or mode is ambiguous'; return 1;
    }
  done
  for index in 0 1; do
    path="${paths[$index]}"; name="${names[$index]}"
    [[ -e "$path" || -L "$path" ]] || continue
    if [[ -z "$archive" ]]; then
      history="$REPO_ROOT/.ci-artifacts/junit/history"
      junit_prepare_directory "$history" "$uid" || return 1
      history_identity="$(stat -Lc '%d:%i:%u:%a:%F' -- "$history")" || return 1
      [[ "$history_identity" =~ ^[^:]+:[^:]+:$uid:700:directory$ ]] || {
        refuse JUNIT_RETENTION_STORE_INVALID 'history must be private'; return 1;
      }
      archive="$(umask 077; mktemp -d "$history/$retention_lane.XXXXXXXXXX")" || return 1
      archive_identity="$(stat -Lc '%d:%i:%u:%a:%F' -- "$archive")" || return 1
      printf '[ci] retaining prior %s reports: %s\n' "$retention_lane" "$archive" >&2
    fi
    identity="$(junit_file_identity "$path")" || return 1
    digest="$(sha256_file "$path")" || return 1
    [[ "$identity" =~ ^[^:]+:[^:]+:$uid:600:1:[0-9]+:regular(\ empty)?\ file$ \
      && "$(junit_store_identity "$retention_profile")" == "$root_identity" \
      && "$(stat -Lc '%d:%i:%u:%a:%F' -- "$history")" == "$history_identity" \
      && "$(stat -Lc '%d:%i:%u:%a:%F' -- "$archive")" == "$archive_identity" ]] || {
      refuse JUNIT_RETENTION_CUSTODY_CHANGED 'report or store changed'; return 1;
    }
    junit_destination_absent "$archive/$name" || return 1
    mv -T -- "$path" "$archive/$name" || {
      refuse JUNIT_RETENTION_FAILED 'archival move failed; retained partial archive must be reconciled'; return 1;
    }
    after="$(junit_file_identity "$archive/$name")" || return 1
    [[ "$after" == "$identity" && "$(sha256_file "$archive/$name")" == "$digest" ]] || {
      refuse JUNIT_RETENTION_CUSTODY_CHANGED 'archived report changed'; return 1;
    }
    (umask 077; printf '%s  %s\n' "$digest" "$name" >>"$archive/SHA256SUMS") || return 1
    sync -- "$archive/$name" "$archive/SHA256SUMS" "$archive" "$(dirname "$path")" || return 1
  done
  [[ "$(junit_store_identity "$retention_profile")" == "$root_identity" ]] || {
    refuse JUNIT_RETENTION_CUSTODY_CHANGED 'report store changed'; return 1;
  }
  for path in "${paths[@]}"; do junit_destination_absent "$path" || return 1; done
  if [[ -n "$archive" ]]; then sync -- "$history" || return 1; fi
)
