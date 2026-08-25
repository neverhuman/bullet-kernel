#!/usr/bin/env bash
# Prove that hosted JUnit is structural only and fails closed on schema drift.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

require_tool rg || exit 1

test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
canary='AKIAIOSFODNN7EXAMPLE'

printf '%s\n' \
  '<?xml version="1.0" encoding="UTF-8"?>' \
  '<testsuites name="nextest-run" tests="1" failures="1" errors="0" timestamp="host" uuid="host">' \
  '  <testsuite name="suite" tests="1" failures="1" errors="0">' \
  '    <testcase name="fails" classname="suite" time="0.1" timestamp="host">' \
  "      <failure message=\"$canary\" type=\"assertion\">$canary</failure>" \
  "      <system-out>$canary</system-out>" \
  "      <system-err>$canary</system-err>" \
  '    </testcase>' \
  '  </testsuite>' \
  '</testsuites>' >"$test_root/raw.xml"

bash ops/ci/sanitize-junit.sh "$test_root/raw.xml" "$test_root/sanitized.xml"
if rg -q "$canary|system-out|system-err|timestamp=|uuid=|message=|type=" "$test_root/sanitized.xml"; then
  refuse JUNIT_REDACTION_FAILED "captured output or host metadata survived"
  exit 1
fi
rg -Fqx '<testsuites name="nextest-run" tests="1" failures="1" errors="0">' "$test_root/sanitized.xml" \
  || { refuse JUNIT_ROOT_GUARD_FAILED "sanitized root attributes drifted"; exit 1; }
[[ "$(rg -Fxc '            <failure>' "$test_root/sanitized.xml")" -eq 1 ]] \
  || { refuse JUNIT_FAILURE_GUARD_FAILED "structural failure element was not retained exactly once"; exit 1; }
bash ops/ci/sanitize-junit.sh "$test_root/sanitized.xml" "$test_root/resanitized.xml"
cmp -s "$test_root/sanitized.xml" "$test_root/resanitized.xml" \
  || { refuse JUNIT_IDEMPOTENCE_FAILED "sanitized output is not canonical"; exit 1; }

printf '%s\n' '<testsuites><credential>secret</credential></testsuites>' >"$test_root/unknown.xml"
if bash ops/ci/sanitize-junit.sh "$test_root/unknown.xml" "$test_root/rejected.xml" >/dev/null 2>&1; then
  refuse JUNIT_SCHEMA_GUARD_FAILED "unknown output-bearing element was accepted"
  exit 1
fi
printf 'prior-output\n' >"$test_root/rejected.xml"
if bash ops/ci/sanitize-junit.sh "$test_root/missing.xml" "$test_root/rejected.xml" >/dev/null 2>&1; then
  refuse JUNIT_MISSING_GUARD_FAILED "missing report was accepted"
  exit 1
fi
[[ "$(<"$test_root/rejected.xml")" == prior-output ]] \
  || { refuse JUNIT_ATOMIC_FAILURE_GUARD_FAILED "failed sanitation replaced prior output"; exit 1; }

printf '%s\n' '<!DOCTYPE testsuites [<!ENTITY leak SYSTEM "file:///etc/passwd">]><testsuites/>' \
  >"$test_root/doctype.xml"
if bash ops/ci/sanitize-junit.sh "$test_root/doctype.xml" "$test_root/rejected.xml" >/dev/null 2>&1; then
  refuse JUNIT_DECLARATION_GUARD_FAILED "DOCTYPE input was accepted"
  exit 1
fi

log "JUnit structural sanitizer and secret canary passed"
