//! Relationships that JSON Schema cannot express, shared with Portal validation.

use super::models::OperatorSnapshotView;
use std::collections::BTreeMap;

pub(super) fn validate(view: &OperatorSnapshotView) -> Result<(), String> {
    let audit = &view.audit;
    if audit.events.len() as u64 != audit.latest_sequence.min(audit.tail_window)
        || audit.events.last().map_or(audit.latest_sequence != 0, |e| {
            e.seq != audit.latest_sequence
        })
        || audit
            .events
            .windows(2)
            .any(|w| w[0].seq.checked_add(1) != Some(w[1].seq))
    {
        return Err("FARMD_AUDIT_INCOMPLETE".into());
    }
    let missions: BTreeMap<_, _> = view.missions.iter().map(|m| (&m.id, m)).collect();
    let graphs: BTreeMap<_, _> = view.graphs.iter().map(|g| (&g.mission.id, g)).collect();
    if missions.len() != view.missions.len()
        || graphs.len() != view.graphs.len()
        || missions.len() != graphs.len()
        || view.graphs.iter().any(|graph| {
            missions.get(&graph.mission.id).is_none_or(|mission| {
                serde_json::to_value(mission).ok() != serde_json::to_value(&graph.mission).ok()
                    || graph.packages.iter().any(|p| p.mission_id != mission.id)
            })
        })
    {
        return Err("FARMD_MISSION_GRAPH_INCOMPATIBLE".into());
    }
    if view
        .quality_lab
        .evidence
        .iter()
        .any(|e| e.satisfies_requirement != (e.outcome == "PASS"))
    {
        return Err("FARMD_EVIDENCE_CONTRADICTORY".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn empty() -> Value {
        json!({"missions":[],"graphs":[],"outbox":{"items":[]},"ready":null,
            "fleet":{"authority_time":"2026-09-10T00:00:00Z","leases":[],"ready_queue":[]},
            "sessions":{"attempts":[],"state_counts":[]},"context_lineage":{"capsules":[]},
            "merge_rail":{"candidates":[],"effects":[],"intents":[],"receipts":[],"intent_state_counts":[]},
            "quality_lab":{"evidence":[],"outcome_counts":[]},
            "audit":{"latest_sequence":0,"tail_window":64,"events":[]}})
    }
    fn validate_value(value: Value) -> Result<(), String> {
        validate(&serde_json::from_value(value).unwrap())
    }
    #[test]
    fn incomplete_audit_and_contradictory_evidence_are_refused() {
        assert!(validate_value(empty()).is_ok());
        let mut changed = empty();
        changed["audit"]["latest_sequence"] = json!(7);
        assert_eq!(
            validate_value(changed).unwrap_err(),
            "FARMD_AUDIT_INCOMPLETE"
        );
        let mut changed = empty();
        changed["quality_lab"]["evidence"] = json!([{"id":"e","candidate_id":"c","tier":"t","gate":"g","result":"r","outcome":"FAIL","satisfies_requirement":true}]);
        assert_eq!(
            validate_value(changed).unwrap_err(),
            "FARMD_EVIDENCE_CONTRADICTORY"
        );
        let mut changed = empty();
        changed["audit"] = json!({"latest_sequence":2,"tail_window":64,"events":[
            {"id":"x","seq":2,"at":"2026-09-10T00:00:00Z","kind":"test","body":"{}","stream_id":null,"correlation_id":null},
            {"id":"y","seq":2,"at":"2026-09-10T00:00:00Z","kind":"test","body":"{}","stream_id":null,"correlation_id":null}]});
        assert!(validate_value(changed).is_err());
    }
    #[test]
    fn duplicate_and_mismatched_mission_graphs_are_refused() {
        let mission = json!({"id":"m","organization_id":"o","repository_id":"r","title":"title","objective":"objective","acceptance_contract_id":"a","state":"draft"});
        let mut value = empty();
        value["missions"] = json!([mission]);
        assert!(validate_value(value.clone()).is_err());
        value["graphs"] = json!([{"mission":mission,"packages":[],"fence":null}]);
        assert!(validate_value(value.clone()).is_ok());
        let mut changed = value.clone();
        changed["missions"] = json!([mission, mission]);
        assert!(validate_value(changed).is_err());
        let mut changed = value.clone();
        changed["graphs"][0]["mission"]["title"] = json!("changed");
        assert!(validate_value(changed).is_err());
        value["graphs"][0]["packages"] = json!([{"id":"w","mission_id":"foreign","plan_revision_id":"p","task_class":"x","title":"work","state":"new"}]);
        assert!(validate_value(value).is_err());
    }
    #[test]
    fn snapshot_header_is_mandatory_and_matches_the_generated_body() {
        let body = json!({"data":empty(),"as_of_sequence":0,"observed_at":"2026-09-10T00:00:00Z","source":"bullet-kernel/sqlite-ledger"});
        for sequence in [None, Some(1)] {
            assert!(
                crate::client::snapshot_response(crate::coding::http::HttpResponse {
                    status: 200,
                    body: body.clone(),
                    set_cookie: None,
                    sequence
                })
                .is_err()
            );
        }
        assert!(
            crate::client::snapshot_response(crate::coding::http::HttpResponse {
                status: 200,
                body,
                set_cookie: None,
                sequence: Some(0)
            })
            .is_ok()
        );
    }
}
