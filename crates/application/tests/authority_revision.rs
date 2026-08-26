//! Normalized authority rows refuse zero epochs and never upsert.

use bullet_application::authority_revision::{AuthorityRevisionError, NormalizedAuthority};

#[test]
fn zero_authority_epoch_is_refused() {
    let error = NormalizedAuthority::new(1, 1, "a".repeat(64), 1, 1, 0, 0).expect_err("zero");
    assert_eq!(
        error,
        AuthorityRevisionError::Invalid("authority counters cannot be zero".into())
    );
    assert_eq!(error.reason_code(), "AUTHORITY_REVISION_INVALID");
}

#[test]
fn valid_row_uses_insert_then_update() {
    let row = NormalizedAuthority::new(2, 1, "b".repeat(64), 3, 1, 1, 0).expect("row");
    assert_eq!(row.authority_epoch, 1);
    assert!(!NormalizedAuthority::insert_sql().contains("OR REPLACE"));
    assert!(!NormalizedAuthority::update_sql().contains("OR REPLACE"));
    assert!(NormalizedAuthority::insert_sql().starts_with("INSERT INTO"));
    assert!(NormalizedAuthority::update_sql().starts_with("UPDATE"));
}
