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
