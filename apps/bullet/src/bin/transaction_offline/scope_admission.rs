use super::support::fail;
use bullet_adapters::SqliteLedger;
use bullet_application::{
    AuthorityScopeAdmission, AuthorityScopeStore, Ledger, AUTHORITY_SCOPE_ENVELOPE_CLASS,
};
use bullet_domain::{schema_bundle::ScopeGrantV1, Digest};

const SCOPE_IDEMPOTENCY_KEY: &str = "txn-offline-scope-v1";
const SCOPE_PATHS: [&str; 2] = ["src", "PONG.txt"];

pub(super) fn offline_scope_paths() -> Vec<String> {
    SCOPE_PATHS.iter().map(|path| (*path).to_owned()).collect()
}

pub(super) fn admit_offline_scope(
    ledger: &mut SqliteLedger,
    now: &str,
) -> Result<AuthorityScopeAdmission, String> {
    let current = ledger
        .current_authority()
        .map_err(|error| fail(format!("read initial authority scope: {error}")))?;
    let grant = ScopeGrantV1 {
        schema_version: "v1alpha1".into(),
        scope_grant_id: format!(
            "sgr_{}",
            Digest::of(b"bullet-transaction-offline-scope-v1").to_hex()
        ),
        scope_revision: 1,
        normalized_paths: offline_scope_paths(),
        protected_resources: Vec::new(),
        envelope_class: AUTHORITY_SCOPE_ENVELOPE_CLASS.into(),
    };
    ledger
        .admit_scope_grant(
            &grant,
            current.authority_epoch(),
            SCOPE_IDEMPOTENCY_KEY,
            now,
        )
        .map_err(|error| fail(format!("admit offline authority scope: {error}")))
}
