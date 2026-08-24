//! Planned spec section 17 policy table. A row records desired policy; it
//! does not claim detector or gateway enforcement.

use bullet_domain::Enforcement;

/// One normative catalog row.
#[derive(Clone, Copy, Debug)]
pub struct CatalogRow {
    /// Stable identifier such as `GT001`.
    pub id: &'static str,
    /// Spec category.
    pub category: &'static str,
    /// Prohibited or monitored behavior.
    pub title: &'static str,
    /// Default enforcement.
    pub action: Enforcement,
}

/// Every §17 identifier. Order matches the spec table.
#[rustfmt::skip]
pub const SPEC_ROWS: &[CatalogRow] = &[
    row("FS001", "workspace", "Writes outside assigned workspace", Enforcement::Block),
    row("FS002", "workspace", "Creates a second repository copy inside the workspace", Enforcement::Pause),
    row("FS003", "workspace", "Creates ad hoc copy directories", Enforcement::Pause),
    row("FS004", "workspace", "Writes runtime/provider configuration into product repository", Enforcement::Quarantine),
    row("FS005", "workspace", "Leaves unclassified untracked files at Candidate preparation", Enforcement::Block),
    row("FS006", "workspace", "Uses system temp paths for durable work without checkpoint", Enforcement::Pause),
    row("FS007", "workspace", "Writes large binary or archive unexpectedly", Enforcement::Pause),
    row("FS008", "workspace", "Creates recursive directory copies or symlink cycles", Enforcement::Block),
    row("FS009", "workspace", "Changes file ownership or broad permissions", Enforcement::Block),
    row("FS010", "workspace", "Deletes repository files outside granted scope", Enforcement::Pause),
    row("GT001", "git", "Uses Git worktree for writable task", Enforcement::Block),
    row("GT002", "git", "Modifies .git internals directly", Enforcement::Block),
    row("GT003", "git", "Runs unauthorized destructive git command", Enforcement::Block),
    row("GT004", "git", "Force pushes or deletes remote refs", Enforcement::Block),
    row("GT005", "git", "Pushes directly from agent sandbox", Enforcement::Block),
    row("GT006", "git", "Changes remote URL or credential helper", Enforcement::Block),
    row("GT007", "git", "Adds provider hook or runtime files to Candidate", Enforcement::Quarantine),
    row("GT008", "git", "Leaves detached-head commits without preservation", Enforcement::Pause),
    row("GT009", "git", "Claims clean state using commits-ahead", Enforcement::Block),
    row("GT010", "git", "Rebases or merges target without coordinator", Enforcement::Block),
    row("SC001", "scope", "Writes outside granted Change Intent", Enforcement::Pause),
    row("SC002", "scope", "Requests repeated broad scope expansions", Enforcement::Pause),
    row("SC003", "scope", "Touches protected paths without risk upgrade", Enforcement::Block),
    row("SC004", "scope", "Modifies lockfiles without declared dependency intent", Enforcement::Pause),
    row("SC005", "scope", "Modifies generated files without generator evidence", Enforcement::Block),
    row("SC006", "scope", "Changes CI/security/auth files while low risk", Enforcement::Pause),
    row("TL001", "tools", "Runs sudo, su, package manager, or Docker socket", Enforcement::Block),
    row("TL002", "tools", "Downloads or executes unpinned binary", Enforcement::Block),
    row("TL003", "tools", "Uses curl | shell remote execution", Enforcement::Block),
    row("TL004", "tools", "Spawns unbounded background process", Enforcement::Terminate),
    row("TL005", "tools", "Starts unmanaged server or listener", Enforcement::Pause),
    row("TL006", "tools", "Repeats identical command beyond threshold", Enforcement::Pause),
    row("TL007", "tools", "Runs broad repository scan repeatedly", Enforcement::Pause),
    row("TL008", "tools", "Ignores timeout/cancellation", Enforcement::Terminate),
    row("TL009", "tools", "Attempts unsupported MCP/tool without grant", Enforcement::Block),
    row("TL010", "tools", "Uses shell to bypass typed operation", Enforcement::Block),
    row("NW001", "network", "Connects to undeclared host", Enforcement::Block),
    row("NW002", "network", "Attempts cloud metadata or local discovery", Enforcement::Block),
    row("NW003", "network", "Exfiltrates repository content", Enforcement::Quarantine),
    row("NW004", "network", "Runs a tunnel, proxy, reverse shell, or port-forward", Enforcement::Terminate),
    row("NW005", "network", "Uses personal SCM credential or SSH agent", Enforcement::Block),
    row("SE001", "secrets", "Reads secret outside explicit grant", Enforcement::Block),
    row("SE002", "secrets", "Writes secret or high-entropy credential to repository", Enforcement::Quarantine),
    row("SE003", "secrets", "Prints secret into model context or logs", Enforcement::Pause),
    row("SE004", "secrets", "Attempts to enumerate credential stores", Enforcement::Terminate),
    row("CD001", "code", "Deletes or weakens tests to make suite pass", Enforcement::Quarantine),
    row("CD002", "code", "Adds skip/ignore/only/focus markers without intent", Enforcement::Block),
    row("CD003", "code", "Swallows errors or broadens catch to hide failure", Enforcement::Pause),
    row("CD004", "code", "Returns hardcoded success in production path", Enforcement::Quarantine),
    row("CD005", "code", "Adds TODO/FIXME in acceptance-critical path", Enforcement::Block),
    row("CD006", "code", "Duplicates large code or vendors source", Enforcement::Pause),
    row("CD007", "code", "Introduces unnecessary dependency", Enforcement::Pause),
    row("CD008", "code", "Changes public API without compatibility evidence", Enforcement::Block),
    row("CD009", "code", "Changes schema without migration/rollback evidence", Enforcement::Block),
    row("CD010", "code", "Introduces nondeterministic test or sleep sync", Enforcement::Pause),
    row("TS001", "testing", "Claims test pass without captured command Evidence", Enforcement::Block),
    row("TS002", "testing", "Runs only a narrower test after broader surface change", Enforcement::Block),
    row("TS003", "testing", "Treats flaky/timed-out/infra-error as pass", Enforcement::Block),
    row("TS004", "testing", "Modifies expected output instead of fixing behavior", Enforcement::Pause),
    row("TS005", "testing", "Skips required browser/accessibility/security test", Enforcement::Block),
    row("CP001", "completion", "Emits done with dirty workspace", Enforcement::Block),
    row("CP002", "completion", "Emits done without exact Candidate", Enforcement::Block),
    row("CP003", "completion", "Emits done with uncovered acceptance requirement", Enforcement::Block),
    row("CP004", "completion", "Closes task while external effect is unknown", Enforcement::Block),
    row("CP005", "completion", "Reports workflow step audit without executing steps", Enforcement::Terminate),
    row("CP006", "completion", "Restarts onto a closed/already-integrated target", Enforcement::Block),
    row("CX001", "context", "Exceeds context transition threshold without checkpoint", Enforcement::Pause),
    row("CX002", "context", "Repeatedly compresses or hands off without progress", Enforcement::Pause),
    row("CX003", "context", "Drops unresolved decision from capsule", Enforcement::Block),
    row("CX004", "context", "Uses provider-native history as sole durable record", Enforcement::Block),
    row("AG001", "agent", "Repeatedly states confidence without evidence", Enforcement::Pause),
    row("AG002", "agent", "Fabricates source reference, test, or tool result", Enforcement::Terminate),
    row("AG003", "agent", "Ignores explicit interruption or cancellation", Enforcement::Terminate),
    row("AG004", "agent", "Oscillates between plans without new evidence", Enforcement::Pause),
    row("AG005", "agent", "Performs report-only activity instead of required steps", Enforcement::Terminate),
    row("AG006", "agent", "Attempts to lower risk or waive checks in prose", Enforcement::Pause),
    row("AG007", "agent", "Edits runtime status or audit files", Enforcement::Block),
    row("EF001", "effects", "Attempts direct GitHub/cloud/package/deploy mutation", Enforcement::Block),
    row("EF002", "effects", "Retries ambiguous external effect blindly", Enforcement::Block),
    row("EF003", "effects", "Uses stale fence for external mutation", Enforcement::Block),
    row("CL001", "cleanup", "Deletes workspace before verified preservation", Enforcement::Block),
    row("CL002", "cleanup", "Treats failed observation as empty/clean", Enforcement::Block),
    row("CL003", "cleanup", "Cleanup targets resources by shared task ID", Enforcement::Block),
    row("CL004", "cleanup", "Reuses name/path before tombstoned cleanup completes", Enforcement::Block),
];

const fn row(
    id: &'static str,
    category: &'static str,
    title: &'static str,
    action: Enforcement,
) -> CatalogRow {
    CatalogRow {
        id,
        category,
        title,
        action,
    }
}

/// Look up one row by identifier.
#[must_use]
pub fn row_by_id(id: &str) -> Option<&'static CatalogRow> {
    SPEC_ROWS.iter().find(|row| row.id == id)
}
