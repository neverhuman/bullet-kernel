use crate::client::{models::OperatorSnapshot, terminal_text, CodingCommand};
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
    Outbox,
    Ready,
    Fleet,
    Submissions,
}
impl View {
    pub(super) const ALL: [Self; 10] = [
        Self::Missions,
        Self::Tasks,
        Self::Attempts,
        Self::Review,
        Self::Events,
        Self::Context,
        Self::Outbox,
        Self::Ready,
        Self::Fleet,
        Self::Submissions,
    ];
    pub(super) fn title(self) -> &'static str {
        match self {
            Self::Missions => "Mission Graph",
            Self::Tasks => "Tasks",
            Self::Attempts => "Session Supervisor",
            Self::Review => "Merge Rail",
            Self::Events => "Incidents and Audit",
            Self::Context => "Context Lineage",
            Self::Outbox => "Outbox",
            Self::Ready => "Ready queue",
            Self::Fleet => "Fleet",
            Self::Submissions => "Submissions",
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
/// Human rows shorten each 64-hex run to `abcd…wxyz`. Raw JSON keeps the exact id.
pub(super) fn abbreviate_ledger_hex(text: &str) -> String {
    map_ledger_hex(text, |hex| format!("{}…{}", &hex[..4], &hex[60..]))
}

/// Detach / reconnect still hide 64-hex runs from the printed command.
pub(super) fn redact_ledger_hex(text: &str) -> String {
    map_ledger_hex(text, |_| "<redacted>".into())
}

fn map_ledger_hex(text: &str, rewrite: impl Fn(&str) -> String) -> String {
    let mut out = String::with_capacity(text.len());
    let mut hex = String::new();
    let flush = |out: &mut String, hex: &mut String| {
        if hex.len() == 64 {
            out.push_str(&rewrite(hex));
        } else {
            out.push_str(hex);
        }
        hex.clear();
    };
    for c in text.chars() {
        if c.is_ascii_hexdigit() && (c.is_ascii_digit() || c.is_ascii_lowercase()) {
            hex.push(c);
        } else {
            flush(&mut out, &mut hex);
            out.push(c);
        }
    }
    flush(&mut out, &mut hex);
    out
}

fn row(value: &impl Serialize, id: &str, label: String, human: String) -> Row {
    Row {
        id: id.into(),
        label: terminal_text(&abbreviate_ledger_hex(&label)),
        human: abbreviate_ledger_hex(&human)
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
    pub(super) coding: Vec<CodingCommand>,
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
    pub(super) view_stack: Vec<View>,
    pub(super) coding_after: u64,
    pub(super) coding_next_after: Option<u64>,
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
    pub(super) fn set_coding(&mut self, commands: Vec<CodingCommand>, next_after: Option<u64>) {
        self.coding = commands;
        self.coding_next_after = next_after;
        if self.snapshot.is_some() {
            self.rebuild();
        }
    }
    pub(super) fn page_coding(&mut self, forward: bool) -> bool {
        if self.view != View::Submissions {
            return false;
        }
        if forward {
            let Some(next) = self.coding_next_after else {
                return false;
            };
            self.coding_after = next;
            true
        } else if self.coding_after > 0 {
            self.coding_after = 0;
            true
        } else {
            false
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
            "HOLD · LIVE {live} · UNBOUND · HEAD_RUNTIME_BINDING_REQUIRED · STOP_UNIMPLEMENTED · harness {} · {}\n{destination} · {snapshot}{pending}",
            crate::client::harness_outcome(),
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
            View::Missions => {
                let mut rows: Vec<Row> = data
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
                    .collect();
                if rows.is_empty() {
                    rows.extend(self.coding_rows(&as_of, &observed, "mission"));
                }
                rows
            }
            View::Tasks => {
                let mut rows: Vec<Row> = data
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
                    .collect();
                if rows.is_empty() {
                    rows.extend(self.coding_rows(&as_of, &observed, "task"));
                }
                rows
            }
            View::Attempts => {
                let mut rows: Vec<Row> = data
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
                    .collect();
                if rows.is_empty() {
                    rows.extend(self.coding_rows(&as_of, &observed, "attempt"));
                }
                rows
            }
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
            View::Outbox => data
                .outbox
                .items
                .iter()
                .map(|v| {
                    row(
                        v,
                        &v.seq.to_string(),
                        format!("[{}] {} seq {}", v.phase, v.kind, v.seq),
                        field_lines(&[
                            ("seq", v.seq.to_string()),
                            ("kind", v.kind.clone()),
                            ("phase", v.phase.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Ready => data
                .fleet
                .ready_queue
                .iter()
                .map(|v| {
                    row(
                        v,
                        &v.work_package_id,
                        format!("ready {}", v.work_package_id),
                        field_lines(&[
                            ("work_package_id", v.work_package_id.clone()),
                            ("enqueued_at", v.enqueued_at.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Fleet => data
                .fleet
                .leases
                .iter()
                .map(|v| {
                    row(
                        v,
                        &v.attempt_id,
                        format!("[{}] {} fence {}", v.liveness, v.attempt_id, v.fence),
                        field_lines(&[
                            ("attempt_id", v.attempt_id.clone()),
                            ("liveness", v.liveness.clone()),
                            ("fence", v.fence.to_string()),
                            ("runner_id", v.runner_id.clone()),
                            ("as_of_sequence", as_of.clone()),
                            ("observed_at", observed.clone()),
                        ]),
                    )
                })
                .collect(),
            View::Submissions => self.coding_rows(&as_of, &observed, "submission"),
        };
        self.replace_rows(rows);
    }
    fn coding_rows(&self, as_of: &str, observed: &str, surface: &str) -> Vec<Row> {
        self.coding
            .iter()
            .map(|command| {
                let label = match surface {
                    "attempt" => format!("[{} / lease UNBOUND] coding attempt", command.status),
                    _ => format!("[{}] coding {}", command.status, surface),
                };
                let mut pairs = vec![
                    ("kind", command.kind.clone()),
                    ("status", command.status.clone()),
                    ("surface", surface.into()),
                    ("as_of_sequence", as_of.into()),
                    ("observed_at", observed.into()),
                ];
                for blocker in &command.blockers {
                    pairs.push(("blocked", blocker.clone()));
                }
                row(command, &command.id, label, field_lines(&pairs))
            })
            .collect()
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
                self.push_view(View::ALL[self.palette_selection]);
                self.mission = None;
                self.task = None;
            }
            self.palette = false;
        } else if self.selected_id.is_some() && self.view == View::Missions {
            self.mission = self.selected_id.take();
            self.push_view(View::Tasks);
        } else if self.selected_id.is_some() && self.view == View::Tasks {
            self.task = self.selected_id.take();
            self.push_view(View::Attempts);
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
        } else if let Some(prev) = self.view_stack.pop() {
            self.view = prev;
            if self.view != View::Attempts {
                self.task = None;
            }
            if self.view != View::Tasks && self.view != View::Attempts {
                self.mission = None;
            }
            self.rebuild();
        } else {
            self.view = View::Missions;
            self.task = None;
            self.rebuild();
        }
    }
    fn push_view(&mut self, next: View) {
        if self.view != next {
            self.view_stack.push(self.view);
            self.view = next;
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
        lines.extend(
            self.rows
                .iter()
                .map(|r| format!("{} {}", abbreviate_ledger_hex(&r.id), r.label)),
        );
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
        assert!(text.contains("harness UNBOUND"));
        assert!(text.contains("CONNECTING"));
        assert!(text.contains("snapshot UNKNOWN"));
        assert!(!text.contains("VERIFIED"));
        assert!(model
            .selected_detail()
            .contains("Waiting for an authenticated snapshot"));
    }

    #[test]
    fn painted_surfaces_redact_sixty_four_hex() {
        let hex = "ab".repeat(32);
        let id = format!("cmd_{hex}");
        let short = format!("cmd_{}…{}", &hex[..4], &hex[60..]);
        let painted = row(
            &serde_json::json!({"id": id, "status": "PENDING"}),
            &id,
            format!("label {id}"),
            format!("human {id}"),
        );
        assert_eq!(painted.id, id);
        assert!(!painted.label.contains(&hex));
        assert!(!painted.human.contains(&hex));
        assert!(painted.label.contains(&short));
        assert!(painted.human.contains(&short));
        assert!(painted.raw.contains(&hex));
        assert!(!painted.raw.contains("<redacted>"));
        let mut model = Model::default();
        model.replace_rows(vec![painted]);
        let text = model.plain();
        assert!(!text.contains(&hex));
        assert!(text.contains(&short));
        assert_eq!(
            redact_ledger_hex("unobserved'subject"),
            "unobserved'subject"
        );
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
