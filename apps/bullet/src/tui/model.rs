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
            Self::Missions => "Missions",
            Self::Tasks => "Tasks",
            Self::Attempts => "Attempts / sessions",
            Self::Review => "Candidates / review",
            Self::Events => "Recent audit events",
            Self::Context => "Context handoffs",
        }
    }
}

pub(super) struct Row {
    pub(super) id: String,
    pub(super) label: String,
    pub(super) detail: String,
}
fn row(value: &impl Serialize, id: &str, label: String) -> Row {
    Row {
        id: id.into(),
        label: terminal_text(&label),
        detail: serde_json::to_string_pretty(value)
            .unwrap_or_else(|_| "ENCODING_UNAVAILABLE".into())
            .lines()
            .map(terminal_text)
            .collect::<Vec<_>>()
            .join("\n"),
    }
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
    fn rebuild(&mut self) {
        let Some(snapshot) = &self.snapshot else {
            return;
        };
        let data = &snapshot.data;
        let rows = match self.view {
            View::Missions => data
                .missions
                .iter()
                .map(|v| row(v, &v.id, format!("[{}] {}", v.state, v.title)))
                .collect(),
            View::Tasks => data
                .graphs
                .iter()
                .filter(|g| self.mission.as_ref().is_none_or(|id| id == &g.mission.id))
                .flat_map(|g| &g.packages)
                .map(|v| row(v, &v.id, format!("[{}] {}", v.state, v.title)))
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
                    )
                })
                .collect(),
            View::Review => data
                .merge_rail
                .candidates
                .iter()
                .map(|v| row(v, &v.id, format!("Candidate {}", v.id)))
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
                    )
                })
                .collect(),
            View::Context => data
                .context_lineage
                .capsules
                .iter()
                .map(|v| row(v, &v.id, format!("revision {} · {}", v.revision, v.id)))
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
                (self.palette_selection as i32 + delta).rem_euclid(View::ALL.len() as i32) as usize;
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
            self.view = View::ALL[self.palette_selection];
            self.palette = false;
            self.mission = None;
            self.task = None;
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
        let mut lines = vec!["BULLET · Operating HOLD".into(), self.view.title().into()];
        if let Some(s) = &self.snapshot {
            lines.push(format!("snapshot {} · {}", s.as_of_sequence, s.observed_at));
        }
        if let Some(error) = &self.error {
            lines.push(format!("STALE / UNKNOWN: {}", terminal_text(error)));
        }
        lines.extend(self.rows.iter().map(|r| format!("{} {}", r.id, r.label)));
        if self.rows.is_empty() {
            lines.push("No rows in this view; unavailable subjects remain unknown.".into());
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
            detail: String::new(),
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
}
