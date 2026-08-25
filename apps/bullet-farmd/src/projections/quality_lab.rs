//! Spec section 25.14 Quality Lab: every evidence row with its stored labels
//! and the typed outcome derived from them. Anything outside the outcome
//! catalog projects as `UNKNOWN` and never satisfies a requirement.

use crate::api::{snapshot_response, SharedState};
use crate::errors::ApiError;
use axum::extract::State;
use axum::response::Response;
use bullet_application::store::ProjectionReader;
use bullet_application::LedgerError;
use bullet_domain::{Evidence, GateOutcome};
use serde::Serialize;

use super::{count_labels, LabelCount};

const OUTCOMES: [GateOutcome; 11] = [
    GateOutcome::Pass,
    GateOutcome::Fail,
    GateOutcome::Flaky,
    GateOutcome::InfraError,
    GateOutcome::Cancelled,
    GateOutcome::TimedOut,
    GateOutcome::NotRun,
    GateOutcome::Unsupported,
    GateOutcome::Unknown,
    GateOutcome::Superseded,
    GateOutcome::Invalidated,
];

#[derive(Serialize)]
pub(crate) struct EvidenceRow {
    id: String,
    candidate_id: String,
    tier: String,
    gate: String,
    /// Stored result label, verbatim.
    result: String,
    /// Typed outcome of the stored label; garbage is `UNKNOWN`.
    outcome: String,
    satisfies_requirement: bool,
}

/// Quality Lab projection body.
#[derive(Serialize)]
pub(crate) struct QualityLabView {
    evidence: Vec<EvidenceRow>,
    outcome_counts: Vec<LabelCount>,
}

fn evidence_row(evidence: Evidence) -> EvidenceRow {
    let outcome = evidence.outcome();
    EvidenceRow {
        id: evidence.id.to_string(),
        candidate_id: evidence.candidate_id.to_string(),
        tier: evidence.tier,
        gate: evidence.gate,
        result: evidence.result,
        outcome: outcome.as_str().to_string(),
        satisfies_requirement: outcome.satisfies_requirement(),
    }
}

pub(crate) fn build(evidence: Vec<Evidence>) -> QualityLabView {
    let rows: Vec<EvidenceRow> = evidence.into_iter().map(evidence_row).collect();
    let outcome_counts = count_labels(
        OUTCOMES.iter().map(|outcome| outcome.as_str()),
        rows.iter().map(|row| row.outcome.as_str()),
    );
    QualityLabView {
        evidence: rows,
        outcome_counts,
    }
}

pub(crate) fn read<L: ProjectionReader>(ledger: &L) -> Result<QualityLabView, LedgerError> {
    Ok(build(ledger.list_evidence()?))
}

pub(crate) async fn quality_lab(State(state): State<SharedState>) -> Result<Response, ApiError> {
    let ledger = state.ledger.lock().await;
    let (view, as_of_sequence) = ledger.read_snapshot(read)?;
    snapshot_response(view, as_of_sequence)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_domain::{CandidateId, EvidenceId};

    #[test]
    fn garbage_results_project_unknown_and_never_satisfy() {
        let row = Evidence {
            id: EvidenceId::from_seed("ql-1"),
            candidate_id: CandidateId::from_seed("ql-c"),
            tier: "E2".into(),
            gate: "tests".into(),
            result: "passed".into(),
        };
        let view = build(vec![row]);
        assert_eq!(view.evidence[0].outcome, "UNKNOWN");
        assert!(!view.evidence[0].satisfies_requirement);
        assert_eq!(view.outcome_counts.len(), 11);
        let unknown = view
            .outcome_counts
            .iter()
            .find(|row| row.label == "UNKNOWN")
            .expect("catalog row");
        assert_eq!(unknown.count, 1);
        let pass = view
            .outcome_counts
            .iter()
            .find(|row| row.label == "PASS")
            .expect("catalog row");
        assert_eq!(pass.count, 0);
    }
}
