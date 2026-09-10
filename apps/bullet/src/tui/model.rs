use crate::client::{models::OperatorSnapshot, terminal_text};
use serde::Serialize;

#[derive(Clone, Copy, Default, PartialEq)]
pub(super) enum View {
    #[default]
    Missions,
    Tasks,
    Attempts,
    Review,
    Events,
    Context,
}
impl View {
    pub(super) const ALL: [Self; 6] = [
        Self::Missions,
        Self::Tasks,
        Self::Attempts,
        Self::Review,
        Self::Events,
        Self::Context,
    ];
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Missions => "Mission Graph",
            Self::Tasks => "Tasks",
            Self::Attempts => "Session Supervisor",
            Self::Review => "Merge Rail",
            Self::Events => "Incidents and Audit",
            Self::Context => "Context Lineage",
        }
    }
}

/// Portal surfaces farmd does not project. Palette lists them; Enter does not invent a view.
pub(super) const UNKNOWN_SURFACES: [&str; 6] = [
    "Cognitive Router — no ledger subject",
    "Fusion Lab — no ledger subject",
    "Quota and Capacity — no ledger subject",
    "Struggle and Escalation — no ledger subject",
    "Behavior Center — no ledger subject",
    "Workspace and Git Hygiene — no ledger subject",
];

pub(super) fn palette_len() -> usize {
    View::ALL.len() + UNKNOWN_SURFACES.len()
}

pub(super) struct Row {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) human: String,
    pub(super) raw: String,
}
fn row(value: &impl Serialize, id: &str, label: String, human: String) -> Row {
    Row {
        id: id.into(),
        label: terminal_text(&label),
        human: human
            .lines()
            .map(terminal_text)
            .collect::<Vec<_>>()
            .join("\n"),
        raw: serde_json::to_string_pretty(value)
            .unwrap_or_else(|_| "ENCODING_UNAVAILABLE".into())
            .lines()
            .map(terminal_text)
            .collect::<Vec<_>>()
            .join("\n"),
    }
}

fn field_lines(pairs: &[(&str, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{key:<14} {value}"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Default)]
pub(super) struct Model {
    pub(super) snapshot: Option<OperatorSnapshot>,
    pub(super) error: Option<String>,
    pub(super) view: View,
    pub(super) rows: Vec<Row>,
    pub(super) selected_id: Option<String>,
    pub(super) mission: Option<String>,
    pub(super) task: Option<String>,
    pub(super) details_focus: bool,
    pub(super) scroll: u16,
    pub(super) palette: bool,
    pub(super) palette_selection: usize,
    pub(super) help: bool,
    pub(super) refresh_pending: bool,
    pub(super) raw_json: bool,
    pub(super) destination: String,
}

impl Model {
    pub(super) fn update(&mut self, result: Result<OperatorSnapshot, String>) {
        match result {
            Ok(snapshot)
                if self
                    .snapshot
                    .as_ref()
                    .is_some_and(|old| old.as_of_sequence > snapshot.as_of_sequence) =>
            {
                self.error = Some("FARMD_SNAPSHOT_REGRESSED: previous data retained".into())
            }
            Ok(snapshot) => {
                self.snapshot = Some(snapshot);
                self.error = None;
                self.rebuild();
            }
            Err(error) => self.error = Some(error),
        }
    }
    pub(super) fn selected(&self) -> Option<usize> {
        self.selected_id
            .as_ref()
            .and_then(|id| self.rows.iter().position(|r| &r.id == id))
    }
    pub(super) fn live_count(&self) -> usize {
        self.snapshot
            .as_ref()
            .map(|s| {
                s.data
                    .fleet
                    .leases
                    .iter()
                    .filter(|lease| lease.liveness == "live")
                    .count()
            })
            .unwrap_or(0)
    }
    pub(super) fn observation(&self) -> &'static str {
        if self.error.is_some() {
            "STALE"
        } else if self.snapshot.is_none() {
            "CONNECTING"
        } else {
            "OBSERVED"
        }
    }
    pub(super) fn status_lines(&self) -> String {
        let live = self.live_count();
        let destination = if self.destination.is_empty() {
            "destination UNBOUND"
        } else {
            self.destination.as_str()
        };
        let snapshot = self
            .snapshot
            .as_ref()
            .map(|s| format!("snapshot {} · {}", s.as_of_sequence, s.observed_at))
            .unwrap_or_else(|| "snapshot UNKNOWN".into());
        let pending = if self.refresh_pending {
            " · refresh pending"
        } else {
            ""
        };
        format!(
            "HOLD · LIVE {live} · UNBOUND · HEAD_RUNTIME_BINDING_REQUIRED · STOP_UNIMPLEMENTED · {}\n{destination} · {snapshot}{pending}",
            self.observation()
        )
    }
    pub(super) fn selected_detail(&self) -> &str {
        match self.selected() {
            Some(i) if self.raw_json => self.rows[i].raw.as_str(),
            Some(i) => self.rows[i].human.as_str(),
            None if self.snapshot.is_none() => {
                "Waiting for an authenticated snapshot. Ctrl+C detaches while connecting."
            }
            None => {
                "zero rows, not a green fleet. No work, approval, or provider completion is inferred."
            }
        }
    }
    fn rebuild(&mut self) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let as_of = snapshot.as_of_sequence.to_string();
        let observed = snapshot.observed_at.clone();
        let data = &snapshot.data;
        let rows = match self.view {
            View::Missions => data
                .missions
                .iter()
                .map(|v| {
                    row(
                        v,
                        &v.id,
                        format!("[{}] {}", v.state, v.title),
                        field_lines(&[
                            ("id", v.id.clone()),
                            ("state", v.state.clone()),
                            ("title", v.title.clone()),
                            ("objective", v.objective.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Tasks => data
                .graphs
                .iter()
                .filter(|g| self.mission.as_ref().is_none_or(|id| id == &g.mission.id))
                .flat_map(|g| &g.packages)
                .map(|v| {
                    row(
                        v,
                        &v.id,
                        format!("[{}] {}", v.state, v.title),
                        field_lines(&[
                            ("id", v.id.clone()),
                            ("state", v.state.clone()),
                            ("title", v.title.clone()),
                            ("mission_id", v.mission_id.clone()),
                            ("task_class", v.task_class.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Attempts => data
                .sessions
                .attempts
                .iter()
                .filter(|v| self.task.as_ref().is_none_or(|id| id == &v.work_package_id))
                .map(|v| {
                    row(
                        v,
                        &v.id,
                        format!("[{} / lease {}] {}", v.state, v.lease, v.id),
                        field_lines(&[
                            ("id", v.id.clone()),
                            ("state", v.state.clone()),
                            ("lease", v.lease.clone()),
                            ("work_package_id", v.work_package_id.clone()),
                            ("fence", v.fence.to_string()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Review => data
                .merge_rail
                .candidates
                .iter()
                .map(|v| {
                    row(
                        v,
                        &v.id,
                        format!("Candidate {}", v.id),
                        field_lines(&[
                            ("id", v.id.clone()),
                            ("attempt_id", v.attempt_id.clone()),
                            ("base_sha", v.base_sha.clone()),
                            ("head_sha", v.head_sha.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Events => data
                .audit
                .events
                .iter()
                .rev()
                .map(|v| {
                    row(
                        v,
                        &v.seq.to_string(),
                        format!("{} [{}] {}", v.seq, v.at, v.kind),
                        field_lines(&[
                            ("seq", v.seq.to_string()),
                            ("at", v.at.clone()),
                            ("kind", v.kind.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Context => data
                .context_lineage
                .capsules
                .iter()
                .map(|v| {
                    row(
                        v,
                        &v.id,
                        format!("revision {} · {}", v.revision, v.id),
                        field_lines(&[
                            ("id", v.id.clone()),
                            ("revision", v.revision.to_string()),
                            ("mission_id", v.mission_id.clone()),
                            ("work_package_id", v.work_package_id.clone()),
                            ("recorded_at", v.recorded_at.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
        };
        self.replace_rows(rows);
    }
    fn replace_rows(&mut self, rows: Vec<Row>) {
        self.rows = rows;
        if self.selected().is_none() {
            self.selected_id = self.rows.first().map(|v| v.id.clone());
            self.scroll = 0;
        }
    }
    pub(super) fn step(&mut self, delta: i32) {
        if self.palette {
            self.palette_selection =
                (self.palette_selection as i32 + delta).rem_euclid(palette_len() as i32) as usize;
        } else if self.details_focus {
            self.scroll = (i32::from(self.scroll) + delta).clamp(0, i32::from(u16::MAX)) as u16;
        } else if !self.rows.is_empty() {
            let i = (self.selected().unwrap_or(0) as i32 + delta).rem_euclid(self.rows.len() as i32)
                as usize;
            self.selected_id = Some(self.rows[i].id.clone());
            self.scroll = 0;
        }
    }
    pub(super) fn enter(&mut self) {
        if self.palette {
            if self.palette_selection < View::ALL.len() {
                self.view = View::ALL[self.palette_selection];
                self.mission = None;
                self.task = None;
            }
            self.palette = false;
        } else if self.selected_id.is_some() && self.view == View::Missions {
            self.mission = self.selected_id.take();
            self.view = View::Tasks;
        } else if self.selected_id.is_some() && self.view == View::Tasks {
            self.task = self.selected_id.take();
            self.view = View::Attempts;
        } else {
            self.details_focus = true;
        }
        self.scroll = 0;
        self.rebuild();
    }
    pub(super) fn back(&mut self) {
        if self.help {
            self.help = false;
        } else if self.palette {
            self.palette = false;
        } else if self.details_focus {
            self.details_focus = false;
        } else {
            self.view = match self.view {
                View::Attempts if self.task.is_some() => View::Tasks,
                _ => View::Missions,
            };
            self.task = None;
            self.rebuild();
        }
    }
    pub(super) fn reconnect(&mut self, id: &str) {
        for view in View::ALL {
            self.view = view;
            self.mission = None;
            self.task = None;
            self.rebuild();
            if self.rows.iter().any(|r| r.id == id) {
                self.selected_id = Some(id.into());
                return;
            }
        }
        self.view = View::Missions;
        self.rebuild();
        self.error = Some("RECONNECT_SUBJECT_ABSENT: subject is not in this snapshot".into());
    }
    pub(super) fn plain(&self) -> String {
        let mut lines = vec![
            "BULLET · Operating HOLD".into(),
            self.status_lines()
                .lines()
                .map(str::to_string)
                .collect::<Vec<_>>()
                .join("\n"),
            self.view.title().into(),
        ];
        if let Some(error) = &self.error {
            lines.push(format!("STALE / UNKNOWN: {}", terminal_text(error)));
        }
        lines.extend(self.rows.iter().map(|r| format!("{} {}", r.id, r.label)));
        if self.rows.is_empty() {
            lines.push("zero rows, not a green fleet; unavailable subjects remain unknown.".into());
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
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
}
