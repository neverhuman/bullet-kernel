#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
calls="$test_root/calls"
mkdir "$test_root/bin"
printf '%s\n' \
  '#!/bin/sh' \
  "printf '%s\\n' \"\$1\" >>\"\$CI_REQUIRED_CALLS\"" \
  >"$test_root/bin/bash"
chmod +x "$test_root/bin/bash"

CI_REQUIRED_CALLS="$calls" PATH="$test_root/bin:$PATH" /usr/bin/bash ops/ci/required.sh >/dev/null
printf '%s\n' \
  ops/ci/preflight.sh \
  ops/ci/fast.sh \
  ops/ci/lint.sh \
  ops/ci/contract.sh \
  ops/ci/security.sh \
  ops/ci/docs.sh \
  >"$test_root/expected"
if ! cmp -s "$test_root/expected" "$calls"; then
  diff -u "$test_root/expected" "$calls" >&2 || true
  refuse REQUIRED_ORDER_INVALID "required must run preflight once before every dependency-consuming lane"
  exit 1
fi

printf '%s\n' \
  '#!/bin/sh' \
  "printf '%s\\n' \"\$(umask)\" >\"\$CI_OBSERVED_UMASK\"" \
  >"$test_root/bin/bash"
chmod +x "$test_root/bin/bash"
umask_fixture="$test_root/umask-fixture"
mkdir -p "$umask_fixture/scripts" "$umask_fixture/.git"
cp -- scripts/ci-local.sh "$umask_fixture/scripts/ci-local.sh"
printf '%s\n' 'ref: refs/heads/fixture' >"$umask_fixture/.git/HEAD"
(
  cd "$umask_fixture"
  umask 0002
  CI_OBSERVED_UMASK="$test_root/umask" PATH="$test_root/bin:$PATH" \
    env -u CARGO_TARGET_DIR -u BULLET_CI_CARGO_TARGET_DIR \
    -u BULLET_CI_CARGO_TARGET_ID \
    /usr/bin/bash scripts/ci-local.sh fast >/dev/null
)
[[ "$(<"$test_root/umask")" == "0077" ]] \
  || { refuse SECURE_UMASK_INVALID "lane inherited $(<"$test_root/umask")"; exit 1; }
[[ ! -e "$umask_fixture/.git/bullet-ci.lock.d" ]] \
  || { refuse PROOF_CUSTODY_NOT_RELEASED "isolated umask fixture retained its proof lock"; exit 1; }

# A required dispatch creates one target identity and every dependency-consuming
# child revalidates that same subject. The ordinary default target is disjoint,
# and both private target and lock are absent after success.
required_fixture="$test_root/required-fixture"
mkdir -p "$required_fixture/.git" "$required_fixture/scripts" "$required_fixture/ops/ci" \
  "$required_fixture/target"
printf 'ref: refs/heads/fixture\n' >"$required_fixture/.git/HEAD"
printf 'ordinary\n' >"$required_fixture/target/sentinel"
cp -- scripts/ci-local.sh "$required_fixture/scripts/ci-local.sh"
cp -- ops/ci/required.sh ops/ci/lib.sh ops/ci/inventory.sh "$required_fixture/ops/ci/"
for lane in preflight fast lint contract security docs; do
  # The generated sublane must expand these expressions when it runs, not here.
  # shellcheck disable=SC2016
  printf '%s\n' \
    '#!/usr/bin/env bash' \
    'set -euo pipefail' \
    'source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"' \
    'verify_ci_cargo_target' \
    'printf "%s\t%s\t%s\t%s\n" "${BASH_SOURCE[0]##*/}" "$BULLET_CI_CARGO_TARGET_DIR" "$BULLET_CI_CARGO_TARGET_ID" "$(stat -Lc '\''%d:%i:%u:%a:%F'\'' -- "$CARGO_TARGET_DIR")" >>required-targets' \
    >"$required_fixture/ops/ci/$lane.sh"
  chmod 0700 "$required_fixture/ops/ci/$lane.sh"
done
(
  cd "$required_fixture"
  env -u CARGO_TARGET_DIR -u BULLET_CI_CARGO_TARGET_DIR \
    -u BULLET_CI_CARGO_TARGET_ID /usr/bin/bash scripts/ci-local.sh required >/dev/null
) 2>"$test_root/required-stderr"
if [[ -s "$test_root/required-stderr" ]]; then
  cat "$test_root/required-stderr" >&2
  refuse REQUIRED_TARGET_CLEANUP_DIAGNOSTIC 'successful finalization wrote stderr'
  exit 1
fi
cut -f1 "$required_fixture/required-targets" >"$test_root/required-lanes"
printf '%s\n' preflight.sh fast.sh lint.sh contract.sh security.sh docs.sh \
  >"$test_root/required-lanes.expected"
cmp -s "$test_root/required-lanes.expected" "$test_root/required-lanes" \
  || { refuse REQUIRED_TARGET_LANES_INVALID 'required sublane target observations drifted'; exit 1; }
[[ "$(cut -f2 "$required_fixture/required-targets" | sort -u | wc -l)" -eq 1 \
  && "$(cut -f3 "$required_fixture/required-targets" | sort -u | wc -l)" -eq 1 \
  && "$(cut -f4 "$required_fixture/required-targets" | sort -u | wc -l)" -eq 1 ]] \
  || { refuse REQUIRED_TARGET_IDENTITY_DRIFT 'required sublanes did not share one identity'; exit 1; }
required_target="$(cut -f2 "$required_fixture/required-targets" | head -n 1)"
required_identity="$(cut -f3 "$required_fixture/required-targets" | head -n 1)"
required_prefix="$required_fixture/.git/bullet-ci-target."
required_suffix="${required_target#"$required_prefix"}"
IFS=: read -r required_device required_inode required_owner required_mode required_kind \
  <<<"$required_identity"
required_quarantine="$required_fixture/.git/bullet-ci-target-quarantine.$required_device.$required_inode.$required_suffix"
[[ "$(cut -f4 "$required_fixture/required-targets" | head -n 1)" == "$required_identity" \
  && "$required_target" == "$required_prefix$required_suffix" \
  && "$required_suffix" =~ ^[A-Za-z0-9]{10}$ \
  && "$required_device" =~ ^[0-9]+$ && "$required_inode" =~ ^[0-9]+$ \
  && "$required_owner" =~ ^[0-9]+$ && "$required_mode" == 700 \
  && "$required_kind" == directory \
  && "$required_target" != / && "$required_target" != "${HOME:-/}" \
  && "$required_target" != "$required_fixture" \
  && "$required_target" != "$required_fixture/target" \
  && ! -e "$required_target" && ! -L "$required_target" \
  && -d "$required_quarantine" && ! -L "$required_quarantine" \
  && "$(stat -Lc '%d:%i:%u:%a:%F' -- "$required_quarantine")" \
    == "$required_device:$required_inode:$required_owner:0:directory" \
  && "$(<"$required_fixture/target/sentinel")" == ordinary \
  && ! -e "$required_fixture/.git/bullet-ci.lock.d" ]] \
  || { refuse REQUIRED_TARGET_CLEANUP_INVALID 'required target was broad, retained, or shared'; exit 1; }

[[ "$(rg -c '^setup: preflight$' Justfile)" -eq 1 ]] \
  || { refuse SETUP_PREFLIGHT_MISSING "Justfile setup must depend on preflight exactly once"; exit 1; }
rg -Fxq '    umask 077 && rustup component add rustfmt clippy' Justfile \
  || { refuse SETUP_UMASK_MISSING "Rustup setup must establish umask 077"; exit 1; }
rg -Fxq '    umask 077 && cargo fetch --locked' Justfile \
  || { refuse SETUP_FETCH_MISSING "locked dependency fetch must establish umask 077"; exit 1; }
rg -Fxq '    bash scripts/ci-local.sh preflight' Justfile \
  || { refuse PREFLIGHT_RECIPE_MISSING "Justfile preflight must delegate to the local preflight lane"; exit 1; }

printf '%s\n' '#!/bin/sh' 'exit 0' >"$test_root/bin/bash"
# The generated stub must expand these expressions when it runs, not here.
# shellcheck disable=SC2016
printf '%s\n' \
  '#!/bin/sh' \
  'printf "%s\t%s\n" "${0##*/}" "$(umask)" >>"$CI_SETUP_CALLS"' \
  >"$test_root/bin/rustup"
cp "$test_root/bin/rustup" "$test_root/bin/cargo"
chmod +x "$test_root/bin/bash" "$test_root/bin/rustup" "$test_root/bin/cargo"
mapfile -t setup_commands < <(awk '
  /^setup: preflight$/ { setup=1; next }
  setup && /^[^[:space:]].*:$/ { exit }
  setup && /^    / { sub(/^    /, ""); print }
' Justfile)
[[ "${#setup_commands[@]}" -eq 2 ]] \
  || { refuse SETUP_COMMAND_INVENTORY_INVALID "expected exactly Rustup and Cargo"; exit 1; }
(
  umask 0002
  export CI_SETUP_CALLS="$test_root/setup-calls" PATH="$test_root/bin:$PATH"
  /bin/sh -c "${setup_commands[0]}" >/dev/null
  /bin/sh -c "${setup_commands[1]}" >/dev/null
)
printf '%s\n' $'rustup\t0077' $'cargo\t0077' >"$test_root/setup-expected"
if ! cmp -s "$test_root/setup-expected" "$test_root/setup-calls"; then
  diff -u "$test_root/setup-expected" "$test_root/setup-calls" >&2 || true
  refuse SETUP_UMASK_INVALID "Rustup and Cargo must both execute under umask 077"
  exit 1
fi

log "required and setup source-admission ordering passed"
