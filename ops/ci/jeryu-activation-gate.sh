#!/usr/bin/env bash
# Prepared Jeryu jobs stay inert until forge, runner, and protected-context
# authority are ratified and read back.
set -euo pipefail
printf '%s\n' \
  '{"schema_version":"bullet.ci-activation-refusal.v1","code":"JERYU_CI_NOT_RATIFIED","status":"BLOCKED","exit_code":78,"release_authority":false}' >&2
exit 78
