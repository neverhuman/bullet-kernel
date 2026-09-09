use bullet_application::{
    prepare_authority_scope_admission, AuthorityScopeError, AUTHORITY_SCOPE_ENVELOPE_CLASS,
};
use bullet_domain::schema_bundle::ScopeGrantV1;
use bullet_harness_core::candidate_preparation_scope_paths_digest;
use bullet_harness_core::launch_grant::MAX_SAFE_INTEGER;

type GrantMutation = Box<dyn Fn(&mut ScopeGrantV1)>;

fn grant() -> ScopeGrantV1 {
    ScopeGrantV1 {
        schema_version: "v1alpha1".to_owned(),
        scope_grant_id: format!("sgr_{}", "a".repeat(64)),
        scope_revision: 1,
        normalized_paths: vec!["src/lib.rs".to_owned(), "tests/scope.rs".to_owned()],
        protected_resources: Vec::new(),
        envelope_class: AUTHORITY_SCOPE_ENVELOPE_CLASS.to_owned(),
    }
}

fn refused(value: &ScopeGrantV1) {
    let error =
        prepare_authority_scope_admission(value, 1, "scope-admission-one", "2026-08-27T12:00:00Z")
            .expect_err("hostile scope admitted");
    assert_eq!(error.reason_code(), "AUTHORITY_SCOPE_INVALID");
}

#[test]
fn exact_scope_derives_command_and_shared_ordered_digest() {
    let grant = grant();
    let prepared =
        prepare_authority_scope_admission(&grant, 7, "scope-admission-one", "2026-08-27T12:00:00Z")
            .expect("valid scope");
    assert_eq!(prepared.grant(), &grant);
    assert_eq!(prepared.expected_authority_epoch(), 7);
    assert_eq!(prepared.admitted_at(), "2026-08-27T12:00:00Z");
    assert_eq!(
        prepared.scope_paths_digest(),
        candidate_preparation_scope_paths_digest(&grant.normalized_paths).unwrap()
    );
    assert_eq!(
        prepared.command().id(),
        bullet_domain::CommandId::from_seed("scope-admission-one")
    );
    assert!(!prepared.grant_bytes().is_empty());
    let mut reversed = grant.normalized_paths.clone();
    reversed.reverse();
    assert_ne!(
        prepared.scope_paths_digest(),
        candidate_preparation_scope_paths_digest(&reversed).unwrap()
    );
}

#[test]
fn schema_identity_bounds_and_envelope_are_closed() {
    let base = grant();
    let mutations: Vec<GrantMutation> = vec![
        Box::new(|v| v.schema_version = "v2".into()),
        Box::new(|v| v.scope_grant_id = format!("sgr_{}", "A".repeat(64))),
        Box::new(|v| v.scope_revision = 0),
        Box::new(|v| v.scope_revision = 2),
        Box::new(|v| v.scope_revision = MAX_SAFE_INTEGER + 1),
        Box::new(|v| v.normalized_paths.clear()),
        Box::new(|v| v.normalized_paths = vec!["src/lib.rs".into(); 129]),
        Box::new(|v| v.protected_resources = vec!["source".into()]),
        Box::new(|v| v.envelope_class = "read-only-source".into()),
    ];
    for mutation in mutations {
        let mut value = base.clone();
        mutation(&mut value);
        refused(&value);
    }
    let unknown = serde_json::json!({
        "schema_version": "v1alpha1",
        "scope_grant_id": format!("sgr_{}", "a".repeat(64)),
        "scope_revision": 1,
        "normalized_paths": ["src/lib.rs"],
        "protected_resources": [],
        "envelope_class": AUTHORITY_SCOPE_ENVELOPE_CLASS,
        "legacy_scope_digest": "0".repeat(64),
    });
    assert!(serde_json::from_value::<ScopeGrantV1>(unknown).is_err());
}

#[test]
fn hostile_repository_paths_and_command_metadata_refuse() {
    for path in [
        "/etc/passwd",
        "src\\lib.rs",
        "src/./lib.rs",
        "src/../lib.rs",
        ".git/config",
        "src//lib.rs",
        "src/lib.rs/",
        "C:/source.rs",
        "src/name. ",
        "src/\u{0000}name",
        "cafe\u{0301}.rs",
    ] {
        let mut value = grant();
        value.normalized_paths = vec![path.to_owned()];
        refused(&value);
    }
    for paths in [
        vec!["src/lib.rs".to_owned(), "src/lib.rs".to_owned()],
        vec!["src/lib.rs".to_owned(), "SRC/LIB.RS".to_owned()],
    ] {
        let mut value = grant();
        value.normalized_paths = paths;
        refused(&value);
    }
    for (epoch, key, now) in [
        (0, "scope-admission", "2026-08-27T12:00:00Z"),
        (
            MAX_SAFE_INTEGER + 1,
            "scope-admission",
            "2026-08-27T12:00:00Z",
        ),
        (1, "", "2026-08-27T12:00:00Z"),
        (1, "scope\nadmission", "2026-08-27T12:00:00Z"),
        (1, "scope-admission", "2026-08-27T12:00:00+01:00"),
        (1, "scope-admission", "not-time"),
    ] {
        let error = prepare_authority_scope_admission(&grant(), epoch, key, now)
            .expect_err("hostile command admitted");
        assert!(matches!(error, AuthorityScopeError::Invalid(_)));
    }
}
