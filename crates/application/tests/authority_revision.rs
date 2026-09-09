//! Normalized authority rows refuse invalid counters and digests.

use bullet_application::authority_revision::{
    AuthorityRevisionError, NormalizedAuthority, MAX_SQLITE_INTEGER,
};

#[test]
fn zero_authority_epoch_is_refused() {
    let error = NormalizedAuthority::new(1, 1, "a".repeat(64), 1, 1, 0, 0).expect_err("zero");
    assert_eq!(
        error,
        AuthorityRevisionError::Invalid("authority counters cannot be zero".into())
    );
    assert_eq!(error.reason_code(), "AUTHORITY_REVISION_INVALID");
    let too_large = NormalizedAuthority::new(MAX_SQLITE_INTEGER + 1, 1, "a".repeat(64), 1, 1, 1, 0)
        .expect_err("unsafe integer");
    assert_eq!(too_large.reason_code(), "AUTHORITY_REVISION_INVALID");
}

#[test]
fn valid_row_round_trips_only_through_strict_deserialization() {
    let row = NormalizedAuthority::new(2, 1, "b".repeat(64), 3, 1, 1, 0).expect("row");
    assert_eq!(row.graph_revision(), 2);
    assert_eq!(row.workspace_generation(), 1);
    assert_eq!(row.scope_digest(), "b".repeat(64));
    assert_eq!(row.policy_generation(), 3);
    assert_eq!(row.routing_generation(), 1);
    assert_eq!(row.authority_epoch(), 1);
    assert_eq!(row.freeze_generation(), 0);
    let encoded = serde_json::to_vec(&row).expect("encode");
    assert_eq!(
        serde_json::from_slice::<NormalizedAuthority>(&encoded).expect("decode"),
        row
    );

    let uppercase = format!(
        r#"{{"graph_revision":1,"workspace_generation":1,"scope_digest":"{}","policy_generation":1,"routing_generation":1,"authority_epoch":1,"freeze_generation":0}}"#,
        "A".repeat(64)
    );
    assert!(serde_json::from_str::<NormalizedAuthority>(&uppercase).is_err());
    let unknown = String::from_utf8(encoded)
        .expect("utf8")
        .replacen('{', "{\"unexpected\":1,", 1);
    assert!(serde_json::from_str::<NormalizedAuthority>(&unknown).is_err());
}
