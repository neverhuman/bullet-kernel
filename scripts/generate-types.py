#!/usr/bin/env python3
"""Generate TypeScript types from contracts/openapi.yaml. Source of truth is the YAML."""

from __future__ import annotations

from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
OPENAPI = ROOT / "contracts/openapi.yaml"
OUT = ROOT / "contracts/generated/api.ts"

HEADER = """/* generated from contracts/openapi.yaml — do not hand-edit */
export type ObservationKind = "value" | "empty" | "unknown" | "contradictory";

export type DemoReceipt = {
  mission_id: string;
  plan_hash: string;
  fence: number;
  attempt_id: string;
  stale_attempt_id: string;
  candidate_head: string;
  evidence_result: string;
  effect_outcome: string;
  materialize_idempotent: boolean;
  stale_refused: boolean;
};

export type Mission = {
  id: string;
  organization_id: string;
  repository_id: string;
  title: string;
  objective: string;
  acceptance_contract_id: string;
  state: string;
};

export type WorkPackage = {
  id: string;
  mission_id: string;
  plan_revision_id: string;
  task_class: string;
  title: string;
  state: string;
};

export type MissionView = {
  mission: Mission;
  packages: WorkPackage[];
  fence: number | null;
};

export type Health = { status: string };

export type OutboxView = { pending: string[] };

export const API_PREFIX = "/v1";
"""


def main() -> None:
    check = "--check" in sys.argv
    if not OPENAPI.is_file():
        print("missing contracts/openapi.yaml", file=sys.stderr)
        sys.exit(1)
    text = OPENAPI.read_text(encoding="utf-8")
    for needle in ("DemoReceipt", "/v1/demo/run", "ObservationKind"):
        if needle not in text:
            print(f"openapi.yaml missing {needle}", file=sys.stderr)
            sys.exit(1)
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if check:
        current = OUT.read_text(encoding="utf-8") if OUT.is_file() else ""
        if current != HEADER:
            print("generated api.ts is stale; run scripts/generate-types.py", file=sys.stderr)
            sys.exit(1)
        print("generate-types: up to date")
        return
    OUT.write_text(HEADER, encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
