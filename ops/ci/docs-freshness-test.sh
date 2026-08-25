#!/usr/bin/env bash
# Hostile tests for docs-freshness.sh. All mutation is confined to mktemp roots.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

scratch="$(mktemp -d)"
trap 'rm -rf -- "$scratch"' EXIT
case_number=0

make_fixture() {
  case_number=$((case_number + 1))
  fixture="$scratch/case-$case_number"
  mkdir -p "$fixture"
  git -C "$fixture" init -q --initial-branch=main
  git -C "$fixture" config user.name 'Bullet Docs Test'
  git -C "$fixture" config user.email 'docs-test@invalid.example'
  local path
  for path in \
    apps/bullet/src/main.rs apps/bullet-farmd/src/main.rs crates/runner/src/lib.rs \
    crates/verifier/src/lib.rs crates/domain/src/lib.rs crates/application/src/lib.rs \
    crates/adapters/src/lib.rs apps/bullet-farmd/src/api.rs apps/bullet/src/authority.rs \
    apps/bullet/src/provider.rs apps/bullet/src/maintenance.rs apps/bullet/src/contracts.rs \
    crates/harness-egress/src/lib.rs crates/harness-egress/src/sandbox.rs \
    crates/harness-core/src/admission/signed.rs; do
    mkdir -p "$fixture/$(dirname "$path")"
    printf 'reviewed source\n' >"$fixture/$path"
  done
  git -C "$fixture" add -- .
  git -C "$fixture" commit -q -m subject
  subject="$(git -C "$fixture" rev-parse HEAD)"
  mkdir -p "$fixture/docs"
  local marker="<!-- bullet-doc-review:v1 subject=$subject max_distance=25 paths=apps/bullet/src/main.rs -->"
  for path in README.md docs/architecture.md docs/cli.md docs/egress-isolation.md; do
    printf '# fixture\n\n%s\n' "$marker" >"$fixture/$path"
  done
  git -C "$fixture" add -- .
  git -C "$fixture" commit -q -m docs
}

run_fixture() {
  BULLET_DOC_FRESHNESS_SELF_TEST=1 bash "$REPO_ROOT/ops/ci/docs-freshness.sh" --fixture-root "$fixture"
}

must_refuse() {
  local name="$1"
  if run_fixture >/dev/null 2>&1; then
    printf '[ci] DOC_FRESHNESS_SELF_TEST_FAILED: %s was accepted\n' "$name" >&2
    exit 1
  fi
}

make_fixture
run_fixture >/dev/null

make_fixture
for _ in $(seq 1 25); do
  git -C "$fixture" commit -q --allow-empty -m drift
done
must_refuse stale-subject

make_fixture
sed -i "s/$subject/1111111111111111111111111111111111111111/" "$fixture/README.md"
must_refuse foreign-subject

make_fixture
sed -i 's#apps/bullet/src/main.rs#apps/bullet/src/missing.rs#' "$fixture/docs/cli.md"
must_refuse missing-source

make_fixture
sed -i 's#apps/bullet/src/main.rs#../escape#' "$fixture/docs/architecture.md"
must_refuse traversal-source

make_fixture
rm -- "$fixture/apps/bullet/src/main.rs"
ln -s /etc/passwd "$fixture/apps/bullet/src/main.rs"
must_refuse symlink-source

make_fixture
old_subject="$subject"
rm -- "$fixture/apps/bullet/src/main.rs"
ln -s /etc/passwd "$fixture/apps/bullet/src/main.rs"
git -C "$fixture" add -- apps/bullet/src/main.rs
git -C "$fixture" commit -q -m symlink-subject
subject="$(git -C "$fixture" rev-parse HEAD)"
sed -i "s/$old_subject/$subject/" "$fixture/README.md" "$fixture/docs/architecture.md" "$fixture/docs/cli.md" "$fixture/docs/egress-isolation.md"
rm -- "$fixture/apps/bullet/src/main.rs"
printf 'regular now, but not at review subject\n' >"$fixture/apps/bullet/src/main.rs"
git -C "$fixture" add -- .
git -C "$fixture" commit -q -m regular-head
must_refuse symlink-at-review-subject

make_fixture
duplicate_marker="$(grep '^<!-- bullet-doc-review:' "$fixture/README.md")"
printf '%s\n' "$duplicate_marker" >>"$fixture/README.md"
must_refuse duplicate-marker

printf '[ci] docs freshness hostile tests passed\n'
