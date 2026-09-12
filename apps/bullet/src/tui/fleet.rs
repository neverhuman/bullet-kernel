//! Operational rows from the same authenticated atomic operator snapshot.

use super::{field_lines, row, OperatorSnapshot, Row, View};

pub(super) fn rows(snapshot: &OperatorSnapshot, view: View) -> Vec<Row> {
    let sequence = snapshot.as_of_sequence.to_string();
    let observed = &snapshot.observed_at;
    match view {
        View::Outbox => snapshot
            .data
            .outbox
            .items
            .iter()
            .map(|item| {
                row(
                    item,
                    &format!("outbox:{}", item.seq),
                    format!("[{}] {} seq {}", item.phase, item.kind, item.seq),
                    field_lines(&[
                        ("reconnect", format!("outbox:{}", item.seq)),
                        ("seq", item.seq.to_string()),
                        ("kind", item.kind.clone()),
                        ("phase", item.phase.clone()),
                        ("as_of_sequence", sequence.clone()),
                        ("observed_at", observed.clone()),
                    ]),
                )
            })
            .collect(),
        View::Ready => snapshot
            .data
            .fleet
            .ready_queue
            .iter()
            .map(|item| {
                row(
                    item,
                    &item.work_package_id,
                    format!("ready {}", item.work_package_id),
                    field_lines(&[
                        ("work_package_id", item.work_package_id.clone()),
                        ("enqueued_at", item.enqueued_at.clone()),
                        ("as_of_sequence", sequence.clone()),
                        ("observed_at", observed.clone()),
                    ]),
                )
            })
            .collect(),
        View::Fleet => snapshot
            .data
            .fleet
            .leases
            .iter()
            .map(|item| {
                row(
                    item,
                    &item.attempt_id,
                    format!(
                        "[{}] {} fence {}",
                        item.liveness, item.attempt_id, item.fence
                    ),
                    field_lines(&[
                        ("attempt_id", item.attempt_id.clone()),
                        ("liveness", item.liveness.clone()),
                        ("fence", item.fence.to_string()),
                        ("runner_id", item.runner_id.clone()),
                        ("as_of_sequence", sequence.clone()),
                        ("observed_at", observed.clone()),
                    ]),
                )
            })
            .collect(),
        _ => unreachable!("only operational views use fleet rows"),
    }
}
