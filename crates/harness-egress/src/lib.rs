//! Provider egress isolation for the Bullet Farm kernel.
//!
//! A provider CLI is launched inside a fresh user+network namespace whose
//! only route to the world is a `slirp4netns` uplink to a host-side,
//! allow-listing HTTP `CONNECT` proxy. Inside the namespace an nftables
//! ruleset (chain policy `drop`, counted `reject` rules) admits only loopback
//! and TCP to that single proxy port; DNS, the host's own services (Jeryu on
//! 127.0.0.1:8787), and every direct internet address are refused. Before any
//! child runs, curl probes executed inside the namespace must observe exactly
//! those refusals and the proxy's `403`/allow decisions, and the whole setup
//! is sealed into an [`EgressReceipt`] whose digests admission can bind to.
//!
//! No unsafe code: namespaces are driven through `unshare`, `nsenter`,
//! `slirp4netns`, `nft`, `curl`, `cat`, and `kill`, resolved once and
//! recorded in the receipt. This crate never depends on `harness-core`.

pub mod allowlist;
pub mod decisions;
pub mod error;
pub mod filesystem;
pub mod namespace;
pub mod probes;
pub mod proxy;
pub mod receipt;
pub mod request;
pub mod ruleset;
pub mod sandbox;
pub mod tools;
pub mod tunnel;

pub use allowlist::{AllowlistEntry, AllowlistMode, EgressPolicy, PROVIDERS};
pub use decisions::{Decision, DecisionLog, DecisionRecord};
pub use error::{EgressCode, EgressError};
pub use filesystem::{
    FilesystemCommandPlan, FilesystemFileV0, FilesystemRuntimeFileV0, FilesystemSandboxProfileV0,
    PreparedFilesystemSandbox,
};
pub use namespace::GATEWAY;
pub use probes::{Containment, ContainmentProbe, ProbeOutcome, ProbeRecord, JERYU_PORT};
pub use proxy::{Proxy, ProxyLimits};
pub use receipt::{EgressEvidence, EgressReceipt, SCHEMA_VERSION};
pub use request::ConnectTarget;
pub use sandbox::{EgressSandbox, PreparedSandbox, DECISIONS_FILE, RECEIPT_FILE};

/// Typed exit when filesystem containment cannot be proven (namespaces
/// unavailable). Never a silent pass.
pub const CONTAINMENT_UNAVAILABLE_EXIT: u8 = 78;
pub use tools::{ToolRecord, Tooling};
