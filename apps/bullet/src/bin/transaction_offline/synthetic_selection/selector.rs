//! Identity-blinded deterministic selection for the synthetic component proof.

use bullet_domain::Digest;
use serde::{Deserialize, Serialize};

pub(super) const NONQUALITY_TIEBREAK_V1: &str = "NONQUALITY_TIEBREAK_V1";

const HANDLE_DOMAIN: &[u8] = b"bullet.synthetic-selection.blinded-handle.v1";
const UNBLINDING_DOMAIN: &[u8] = b"bullet.synthetic-selection.unblinding.v1";
const HANDLE_PREFIX: &str = "bvh_";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct BlindedCandidateView {
    pub(super) blinded_handle: String,
    pub(super) base_oid: String,
    pub(super) head_oid: String,
    pub(super) tree_oid: String,
    pub(super) patch_blake3: String,
    pub(super) gate_ids: Vec<String>,
    pub(super) component_gate_passed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SelectionDecision {
    pub(super) rubric: String,
    pub(super) selected_handle: String,
    pub(super) ordered_handles: [String; 2],
}

#[allow(clippy::too_many_arguments)]
pub(super) fn blinded_view(
    run_salt: &[u8; 32],
    hidden_subject: &str,
    base_oid: String,
    head_oid: String,
    tree_oid: String,
    patch_blake3: String,
    gate_ids: Vec<String>,
    component_gate_passed: bool,
) -> Result<BlindedCandidateView, String> {
    require_hidden_subject(hidden_subject)?;
    let mut view = BlindedCandidateView {
        blinded_handle: format!("{HANDLE_PREFIX}{}", "0".repeat(64)),
        base_oid,
        head_oid,
        tree_oid,
        patch_blake3,
        gate_ids,
        component_gate_passed,
    };
    validate_view(&view)?;
    let pass = [u8::from(view.component_gate_passed)];
    let gate_count = u64::try_from(view.gate_ids.len())
        .map_err(|_| "SYNTHETIC_SELECTOR_GATE_COUNT_INVALID".to_owned())?
        .to_le_bytes();
    let mut fields = vec![
        run_salt.as_slice(),
        hidden_subject.as_bytes(),
        view.base_oid.as_bytes(),
        view.head_oid.as_bytes(),
        view.tree_oid.as_bytes(),
        view.patch_blake3.as_bytes(),
        gate_count.as_slice(),
    ];
    fields.extend(view.gate_ids.iter().map(String::as_bytes));
    fields.push(&pass);
    view.blinded_handle = format!("{HANDLE_PREFIX}{}", framed_digest(HANDLE_DOMAIN, &fields));
    Ok(view)
}

pub(super) fn unblinding_digest(
    run_salt: &[u8; 32],
    blinded_handle: &str,
    hidden_subject: &str,
) -> Result<String, String> {
    require_prefixed_hex(blinded_handle, HANDLE_PREFIX, "blinded handle")?;
    require_hidden_subject(hidden_subject)?;
    Ok(framed_digest(
        UNBLINDING_DOMAIN,
        &[
            run_salt.as_slice(),
            blinded_handle.as_bytes(),
            hidden_subject.as_bytes(),
        ],
    ))
}

pub(super) fn select_exact_pair(
    views: [BlindedCandidateView; 2],
) -> Result<SelectionDecision, String> {
    for view in &views {
        validate_view(view)?;
    }
    if views[0].blinded_handle == views[1].blinded_handle {
        return Err("SYNTHETIC_SELECTOR_DUPLICATE_HANDLE".into());
    }
    if views[0].base_oid != views[1].base_oid {
        return Err("SYNTHETIC_SELECTOR_BASE_MISMATCH".into());
    }
    if views[0].gate_ids != views[1].gate_ids {
        return Err("SYNTHETIC_SELECTOR_GATE_MISMATCH".into());
    }
    if views.iter().any(|view| !view.component_gate_passed) {
        return Err("SYNTHETIC_SELECTOR_COMPONENT_PASS_REQUIRED".into());
    }
    let selected = views
        .iter()
        .min_by(|left, right| {
            (
                &left.tree_oid,
                &left.patch_blake3,
                &left.head_oid,
                &left.blinded_handle,
            )
                .cmp(&(
                    &right.tree_oid,
                    &right.patch_blake3,
                    &right.head_oid,
                    &right.blinded_handle,
                ))
        })
        .ok_or_else(|| "SYNTHETIC_SELECTOR_PAIR_REQUIRED".to_owned())?;
    let mut ordered_handles = [
        views[0].blinded_handle.clone(),
        views[1].blinded_handle.clone(),
    ];
    ordered_handles.sort();
    Ok(SelectionDecision {
        rubric: NONQUALITY_TIEBREAK_V1.into(),
        selected_handle: selected.blinded_handle.clone(),
        ordered_handles,
    })
}

fn validate_view(view: &BlindedCandidateView) -> Result<(), String> {
    require_prefixed_hex(&view.blinded_handle, HANDLE_PREFIX, "blinded handle")?;
    let base_algorithm = oid_algorithm(&view.base_oid, "base OID")?;
    if oid_algorithm(&view.head_oid, "head OID")? != base_algorithm
        || oid_algorithm(&view.tree_oid, "tree OID")? != base_algorithm
    {
        return Err("SYNTHETIC_SELECTOR_OID_ALGORITHM_MISMATCH".into());
    }
    require_lower_hex(&view.patch_blake3, 64, "patch BLAKE3")?;
    if view.gate_ids.is_empty()
        || view
            .gate_ids
            .iter()
            .any(|gate| require_prefixed_hex(gate, "gat_", "gate ID").is_err())
        || !view.gate_ids.windows(2).all(|pair| pair[0] < pair[1])
    {
        return Err("SYNTHETIC_SELECTOR_GATES_NONCANONICAL".into());
    }
    Ok(())
}

fn oid_algorithm<'a>(value: &'a str, label: &str) -> Result<&'a str, String> {
    let (algorithm, hex) = value
        .split_once(':')
        .ok_or_else(|| format!("SYNTHETIC_SELECTOR_{label}: missing algorithm tag"))?;
    let length = match algorithm {
        "sha1" => 40,
        "sha256" => 64,
        _ => return Err(format!("SYNTHETIC_SELECTOR_{label}: unsupported algorithm")),
    };
    require_lower_hex(hex, length, label)?;
    Ok(algorithm)
}

fn require_prefixed_hex(value: &str, prefix: &str, label: &str) -> Result<(), String> {
    let hex = value
        .strip_prefix(prefix)
        .ok_or_else(|| format!("SYNTHETIC_SELECTOR_{label}: wrong prefix"))?;
    require_lower_hex(hex, 64, label)
}

fn require_lower_hex(value: &str, length: usize, label: &str) -> Result<(), String> {
    if value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        Ok(())
    } else {
        Err(format!(
            "SYNTHETIC_SELECTOR_{label}: malformed lowercase hex"
        ))
    }
}

fn require_hidden_subject(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 4_096 {
        Err("SYNTHETIC_SELECTOR_HIDDEN_SUBJECT_INVALID".into())
    } else {
        Ok(())
    }
}

fn framed_digest(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut bytes = Vec::new();
    push_frame(&mut bytes, domain);
    for field in fields {
        push_frame(&mut bytes, field);
    }
    Digest::of(&bytes).to_hex()
}

fn push_frame(bytes: &mut Vec<u8>, value: &[u8]) {
    bytes.extend_from_slice(&(value.len() as u64).to_le_bytes());
    bytes.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SALT: [u8; 32] = [7; 32];

    fn oid(algorithm: &str, nibble: char) -> String {
        let length = if algorithm == "sha1" { 40 } else { 64 };
        format!("{algorithm}:{}", nibble.to_string().repeat(length))
    }

    fn view(subject: &str, tree: char, patch: char, head: char) -> BlindedCandidateView {
        blinded_view(
            &SALT,
            subject,
            oid("sha1", '1'),
            oid("sha1", head),
            oid("sha1", tree),
            patch.to_string().repeat(64),
            vec![format!("gat_{}", "8".repeat(64))],
            true,
        )
        .expect("valid blinded view")
    }

    #[test]
    fn least_content_tuple_wins_under_frozen_rubric() {
        let loser = view("hidden-a", '3', '1', '1');
        let winner = view("hidden-b", '2', 'f', 'f');
        let decision = select_exact_pair([loser.clone(), winner.clone()]).expect("select");
        assert_eq!(decision.rubric, NONQUALITY_TIEBREAK_V1);
        assert_eq!(decision.selected_handle, winner.blinded_handle);
        assert_eq!(decision.ordered_handles.len(), 2);
    }

    #[test]
    fn reverse_order_and_swapped_hidden_mapping_do_not_change_selection() {
        let first = view("hidden-a", '2', '2', '2');
        let second = view("hidden-b", '3', '1', '1');
        let forward = select_exact_pair([first.clone(), second.clone()]).expect("forward");
        let reverse = select_exact_pair([second.clone(), first.clone()]).expect("reverse");
        assert_eq!(forward, reverse);

        let original_mapping = [
            (&first.blinded_handle, "hidden-a"),
            (&second.blinded_handle, "hidden-b"),
        ];
        let swapped_mapping = [
            (&first.blinded_handle, "hidden-b"),
            (&second.blinded_handle, "hidden-a"),
        ];
        assert_ne!(original_mapping, swapped_mapping);
        assert_eq!(
            forward.selected_handle,
            select_exact_pair([first, second])
                .expect("mapping is invisible")
                .selected_handle
        );
    }

    #[test]
    fn handle_and_unblinding_bind_salt_subject_and_content_domains() {
        let first = view("hidden-a", '2', '2', '2');
        let second = blinded_view(
            &[8; 32],
            "hidden-a",
            first.base_oid.clone(),
            first.head_oid.clone(),
            first.tree_oid.clone(),
            first.patch_blake3.clone(),
            first.gate_ids.clone(),
            true,
        )
        .expect("different salt");
        let third = view("hidden-b", '2', '2', '2');
        assert_ne!(first.blinded_handle, second.blinded_handle);
        assert_ne!(first.blinded_handle, third.blinded_handle);
        let binding = unblinding_digest(&SALT, &first.blinded_handle, "hidden-a").expect("bind");
        let drift = unblinding_digest(&SALT, &first.blinded_handle, "hidden-b").expect("drift");
        assert_ne!(binding, drift);
        assert_ne!(
            binding,
            first.blinded_handle.trim_start_matches(HANDLE_PREFIX)
        );
    }

    #[test]
    fn duplicate_base_gate_pass_and_shape_drift_refuse() {
        let first = view("hidden-a", '2', '2', '2');
        let second = view("hidden-b", '3', '3', '3');
        let mut cases = Vec::new();

        let mut duplicate = second.clone();
        duplicate.blinded_handle.clone_from(&first.blinded_handle);
        cases.push([first.clone(), duplicate]);

        let mut base = second.clone();
        base.base_oid = oid("sha1", '9');
        cases.push([first.clone(), base]);

        let mut gates = second.clone();
        gates.gate_ids.push(format!("gat_{}", "9".repeat(64)));
        cases.push([first.clone(), gates]);

        let mut failed = second.clone();
        failed.component_gate_passed = false;
        cases.push([first.clone(), failed]);

        let mut malformed = second;
        malformed.patch_blake3 = "ABC".into();
        cases.push([first, malformed]);

        for pair in cases {
            assert!(select_exact_pair(pair).is_err());
        }
    }

    #[test]
    fn gates_are_nonempty_strictly_sorted_and_records_are_closed() {
        let first = view("hidden-a", '2', '2', '2');
        let mut empty = first.clone();
        empty.gate_ids.clear();
        assert!(select_exact_pair([empty, first.clone()]).is_err());

        let mut unsorted = first.clone();
        unsorted.gate_ids = vec![
            format!("gat_{}", "9".repeat(64)),
            format!("gat_{}", "8".repeat(64)),
        ];
        assert!(select_exact_pair([unsorted, first.clone()]).is_err());

        let mut value = serde_json::to_value(&first).expect("encode view");
        value["desired_winner"] = json!(true);
        assert!(serde_json::from_value::<BlindedCandidateView>(value).is_err());

        let decision =
            select_exact_pair([first, view("hidden-b", '3', '3', '3')]).expect("decision");
        let mut value = serde_json::to_value(decision).expect("encode decision");
        value["score"] = json!(1);
        assert!(serde_json::from_value::<SelectionDecision>(value).is_err());
    }
}
