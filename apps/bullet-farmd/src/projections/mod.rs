//! Read-only spec section 25 projections. Each route performs exactly one
//! atomic ledger snapshot and returns the standard envelope. An empty set is
//! zero rows verified at a sequence, never a healthy default, and every
//! catalog label is counted so a zero is explicit rather than absent.

mod audit;
mod context_lineage;
mod fleet;
mod merge_rail;
mod quality_lab;
mod sessions;

pub(crate) use audit::audit;
pub(crate) use context_lineage::context_lineage;
pub(crate) use fleet::fleet;
pub(crate) use merge_rail::merge_rail;
pub(crate) use quality_lab::quality_lab;
pub(crate) use sessions::sessions;

use bullet_application::{Ledger, LedgerError};
use serde::Serialize;
use std::collections::BTreeMap;

/// Work package id to mission id across every materialized graph.
fn package_missions<L: Ledger>(ledger: &L) -> Result<BTreeMap<String, String>, LedgerError> {
    let mut out = BTreeMap::new();
    for mission in ledger.list_missions()? {
        let Some(graph) = ledger.get_graph(&mission.id)? else {
            continue;
        };
        for package in &graph.packages {
            out.insert(package.id.to_string(), graph.mission.id.to_string());
        }
    }
    Ok(out)
}

/// One catalog label with its row count.
#[derive(Debug, PartialEq, Eq, Serialize)]
pub(crate) struct LabelCount {
    label: String,
    count: u64,
}

/// Count `observed` labels against a complete catalog. Labels outside the
/// catalog are appended after it so nothing observed is silently dropped.
fn count_labels<'a>(
    catalog: impl IntoIterator<Item = &'a str>,
    observed: impl IntoIterator<Item = &'a str>,
) -> Vec<LabelCount> {
    let mut counts: BTreeMap<&str, u64> = BTreeMap::new();
    for label in observed {
        *counts.entry(label).or_insert(0) += 1;
    }
    let mut out: Vec<LabelCount> = catalog
        .into_iter()
        .map(|label| LabelCount {
            label: label.to_string(),
            count: counts.remove(label).unwrap_or(0),
        })
        .collect();
    out.extend(counts.into_iter().map(|(label, count)| LabelCount {
        label: label.to_string(),
        count,
    }));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_catalog_label_is_listed_and_foreign_labels_survive() {
        let counts = count_labels(["a", "b"], ["b", "b", "zzz"]);
        assert_eq!(
            counts,
            vec![
                LabelCount {
                    label: "a".into(),
                    count: 0
                },
                LabelCount {
                    label: "b".into(),
                    count: 2
                },
                LabelCount {
                    label: "zzz".into(),
                    count: 1
                },
            ]
        );
    }
}
