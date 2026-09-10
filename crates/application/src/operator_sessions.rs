//! Durable operator authentication port. Only nonsecret identities and digests
//! cross this boundary. Authentication does not authorize provider execution.

use crate::LedgerError;
use bullet_domain::Digest;
use std::fmt;

/// Startup authority registered once without extending a prior token lifetime.
pub struct BootstrapRegistration {
    /// Domain-separated digest of the bootstrap token.
    pub digest: Digest,
    /// Random server-proposed identity, used only if this ledger has no operator.
    pub proposed_operator_id: String,
    /// Exact configured browser origin.
    pub origin: String,
    /// Server-selected validity, bounded to ten minutes.
    pub lifetime_seconds: u32,
}

/// One exchange request; the store allocates timestamps and binds its operator.
pub struct SessionIssue {
    /// Exact registered bootstrap digest.
    pub bootstrap_digest: Digest,
    /// Random server-generated nonsecret session identity.
    pub session_id: String,
    /// Domain-separated bearer digest, never the bearer.
    pub bearer_digest: Digest,
    /// Domain-separated CSRF digest, never the CSRF token.
    pub csrf_digest: Digest,
    /// Exact configured origin bound to the bootstrap.
    pub origin: String,
    /// Server-selected validity, bounded to eight hours.
    pub lifetime_seconds: u32,
}

/// A currently valid session from durable store authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperatorSession {
    /// Public opaque session identity.
    pub session_id: String,
    /// Durable local operator identity, shared by that operator's clients.
    pub operator_id: String,
    /// Stored bearer digest for matching stream permits.
    pub bearer_digest: Digest,
    /// Stored CSRF digest for mutation authentication.
    pub csrf_digest: Digest,
    /// Store-owned Unix timestamp in seconds.
    pub issued_at: i64,
    /// Store-owned absolute Unix expiry in seconds.
    pub expires_at: i64,
}

/// Durable revocation acknowledgement; no credential material.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionRevocation {
    /// Revoked nonsecret session identity.
    pub session_id: String,
    /// Owning operator identity.
    pub operator_id: String,
    /// Store-owned Unix revocation time in seconds.
    pub revoked_at: i64,
}

/// Stable authentication refusal categories. Store details remain private.
#[derive(Debug)]
pub enum OperatorSessionError {
    /// Invalid server-generated identity, origin or lifetime.
    InvalidRequest,
    /// Bootstrap digest is absent or belongs to another origin/restore epoch.
    BootstrapInvalid,
    /// Bootstrap was already exchanged; it can never mint another session.
    BootstrapConsumed,
    /// Absolute bootstrap lifetime ended.
    BootstrapExpired,
    /// Session is absent, expired, revoked or bound to another origin/epoch.
    SessionInvalid,
    /// CSRF digest does not belong to the presented session.
    CsrfInvalid,
    /// Underlying ledger failure, which must not become an empty authority set.
    Store(LedgerError),
}

impl OperatorSessionError {
    /// Stable machine-readable reason; shared with the HTTP authentication edge.
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRequest => "AUTH_REQUEST_INVALID",
            Self::BootstrapInvalid => "BOOTSTRAP_INVALID",
            Self::BootstrapConsumed => "BOOTSTRAP_CONSUMED",
            Self::BootstrapExpired => "BOOTSTRAP_EXPIRED",
            Self::SessionInvalid => "SESSION_INVALID",
            Self::CsrfInvalid => "CSRF_INVALID",
            Self::Store(_) => "STORE_FAILURE",
        }
    }
}

impl fmt::Display for OperatorSessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason_code())
    }
}
impl std::error::Error for OperatorSessionError {}
impl From<LedgerError> for OperatorSessionError {
    fn from(error: LedgerError) -> Self {
        Self::Store(error)
    }
}

/// Durable authentication operations. Implementations use their own clock and
/// transactions; no in-memory cache may outlive a revocation or restore epoch.
pub trait OperatorSessionStore {
    /// Register startup authority without changing an existing token's deadline.
    /// # Errors
    /// Invalid registration, incompatible existing binding, or store failure.
    fn register_operator_bootstrap(
        &mut self,
        request: &BootstrapRegistration,
    ) -> Result<(), OperatorSessionError>;

    /// Consume one bootstrap exactly once and persist its session atomically.
    /// # Errors
    /// Invalid/expired/consumed authority, invalid session input or store failure.
    fn exchange_operator_bootstrap(
        &mut self,
        request: &SessionIssue,
    ) -> Result<OperatorSession, OperatorSessionError>;

    /// Read active authority from current durable truth, including revocation.
    /// # Errors
    /// Invalid/expired/revoked session or store failure.
    fn read_operator_session(
        &self,
        bearer: Digest,
        origin: &str,
    ) -> Result<OperatorSession, OperatorSessionError>;

    /// Revalidate the session and CSRF digest, then append one revocation.
    /// # Errors
    /// Invalid session, mismatched CSRF, or store failure.
    fn revoke_operator_session(
        &mut self,
        bearer: Digest,
        csrf: Digest,
        origin: &str,
    ) -> Result<SessionRevocation, OperatorSessionError>;
}
