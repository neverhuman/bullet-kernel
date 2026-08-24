# bullet-kernel Agent Instructions

Read `SPLIT.md` first. This repository is the Bullet Farm control plane.

Read `agent/JANKURAI_STANDARD.md` next.
Do not edit outside requested ownership. Run the mapped test lane before the
final response.

- Canonical local Jeryu slug: `root/bullet-kernel`.
- Do not add committed cross-repo `path = "../..."` dependencies.
- `crates/domain` has no I/O. Durable writes live in `crates/adapters` and `db/`.
- Run `bash scripts/ci-local.sh required` before handing off changes.
