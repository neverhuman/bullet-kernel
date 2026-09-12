use super::*;
#[test]
fn selection_tracks_subject_across_insert_reorder_and_removal() {
    let r = |id: &str| Row {
        id: id.into(),
        label: id.into(),
        human: String::new(),
        raw: String::new(),
    };
    let mut model = Model::default();
    model.replace_rows(vec![r("a"), r("b")]);
    model.step(1);
    model.replace_rows(vec![r("c"), r("b"), r("a")]);
    assert_eq!(model.selected_id.as_deref(), Some("b"));
    model.replace_rows(vec![r("a")]);
    assert_eq!(model.selected_id.as_deref(), Some("a"));
    model.replace_rows(vec![]);
    assert!(model.selected_id.is_none());
    operational_rows_follow_their_snapshot();
}

#[test]
fn connecting_status_is_text_first_and_never_verified() {
    let model = Model::default();
    let text = model.status_lines();
    assert!(text.contains("HOLD"));
    assert!(text.contains("LIVE 0"));
    assert!(text.contains("UNBOUND"));
    assert!(text.contains("HEAD_RUNTIME_BINDING_REQUIRED"));
    assert!(text.contains("STOP_UNIMPLEMENTED"));
    assert!(text.contains("CONNECTING"));
    assert!(text.contains("snapshot UNKNOWN"));
    assert!(!text.contains("VERIFIED"));
    assert!(model
        .selected_detail()
        .contains("Waiting for an authenticated snapshot"));
}

#[test]
fn palette_unknown_surfaces_do_not_change_the_view() {
    let mut model = Model {
        palette: true,
        palette_selection: View::ALL.len(),
        ..Model::default()
    };
    model.enter();
    assert!(!model.palette);
    assert!(model.view == View::Missions);
}

// Extends the existing selection regression with actual generated snapshot rows.
fn operational_rows_follow_their_snapshot() {
    let id = |prefix| format!("{prefix}_{}", "ab".repeat(32));
    let at = "2026-09-12T00:00:00Z";
    let snapshot: OperatorSnapshot = serde_json::from_value(serde_json::json!({
        "as_of_sequence":42,"observed_at":at,"source":"bullet-kernel/sqlite-ledger",
        "data":{"missions":[],"graphs":[],"ready":null,
            "outbox":{"items":[{"seq":37,"kind":"run_coding","payload":"{}",
                "phase":"pending","delivered_at":null,"acked_at":null}]},
            "fleet":{"authority_time":at,"leases":[{
                "variant_id":id("var"),"attempt_id":id("att"),"fence":7,
                "runner_id":id("run"),"runner_epoch":1,"heartbeat_at":at,
                "expires_at":at,"ttl_seconds":15,"liveness":"expired",
                "attempt_state":null,"work_package_id":null,"mission_id":null
            }],"ready_queue":[{"work_package_id":id("wp"),"enqueued_at":at}]},
            "sessions":{"attempts":[],"state_counts":[]},
            "context_lineage":{"capsules":[]},
            "merge_rail":{"candidates":[],"effects":[],"intents":[],"receipts":[],"intent_state_counts":[]},
            "quality_lab":{"evidence":[],"outcome_counts":[]},
            "audit":{"latest_sequence":42,"tail_window":64,"events":[]}}
    })).unwrap();
    let mut model = Model::default();
    model.update(Ok(snapshot.clone()));
    assert_eq!(
        model.live_count(),
        0,
        "expired lease must not count as live"
    );
    for (view, subject, label) in [
        (
            View::Outbox,
            "outbox:37".into(),
            "[pending] run_coding seq 37".into(),
        ),
        (View::Ready, id("wp"), format!("ready {}", id("wp"))),
        (
            View::Fleet,
            id("att"),
            format!("[expired] {} fence 7", id("att")),
        ),
    ] {
        model.view = view;
        model.rebuild();
        assert_eq!(model.rows.len(), 1);
        assert_eq!(model.selected_id.as_deref(), Some(subject.as_str()));
        assert_eq!(model.rows[0].label, label);
        assert!(model.selected_detail().contains(&subject));
        assert!(model.selected_detail().contains("as_of_sequence 42"));
        assert!(model.selected_detail().contains(at));
        let raw: serde_json::Value = serde_json::from_str(&model.rows[0].raw).unwrap();
        assert!(raw.is_object());
        let mut regressed = snapshot.clone();
        regressed.as_of_sequence = 41;
        model.update(Ok(regressed));
        assert!(model
            .error
            .as_deref()
            .unwrap()
            .contains("FARMD_SNAPSHOT_REGRESSED"));
        assert_eq!(model.selected_id.as_deref(), Some(subject.as_str()));
        assert!(model.selected_detail().contains("as_of_sequence 42"));
    }
    let mut empty = snapshot;
    empty.as_of_sequence = 43;
    empty.data.outbox.items.clear();
    empty.data.fleet.leases.clear();
    empty.data.fleet.ready_queue.clear();
    model.update(Ok(empty));
    for view in [View::Outbox, View::Ready, View::Fleet] {
        model.view = view;
        model.rebuild();
        assert!(model.rows.is_empty());
        assert!(model.selected_id.is_none());
        assert!(model
            .selected_detail()
            .contains("zero rows, not a green fleet"));
    }
}
