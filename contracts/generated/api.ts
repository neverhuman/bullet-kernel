/* generated from contracts/openapi.yaml — do not hand-edit */
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
