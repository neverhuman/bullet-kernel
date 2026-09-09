//! The prompt capsule: objective, scope, base SHA, admitted gates, and the
//! `PatchProposal` schema, plus structured feedback prompts for refusals and
//! gate results. Prompts are data; the deterministic gate decides.

use crate::gate::GateReport;

/// Immutable per-attempt prompt context.
#[derive(Clone, Debug)]
pub struct Capsule {
    /// Mission objective text.
    pub objective: String,
    /// Granted change-intent path prefixes.
    pub scope_prefixes: Vec<String>,
    /// Exact base commit of the private clone.
    pub base_sha: String,
    /// Attempt that the proposal must bind.
    pub producing_attempt_id: String,
    /// Current daemon-issued checkpoint identity.
    pub base_checkpoint_id: String,
    /// Current daemon-issued checkpoint digest.
    pub base_checkpoint_digest: String,
    /// Ordered gate identifiers admitted by policy.
    pub admitted_gate_ids: Vec<String>,
}

impl Capsule {
    fn scope_line(&self) -> String {
        self.scope_prefixes.join(", ")
    }

    fn binding_lines(&self) -> String {
        format!(
            "Producing attempt ID: {}\nBase checkpoint ID: {}\nBase checkpoint digest: {}",
            self.producing_attempt_id, self.base_checkpoint_id, self.base_checkpoint_digest
        )
    }

    pub(crate) fn advance_checkpoint(&mut self, id: String, digest: String) {
        self.base_checkpoint_id = id;
        self.base_checkpoint_digest = digest;
    }

    /// The first turn's prompt.
    #[must_use]
    pub fn initial_prompt(&self) -> String {
        format!(
            "You are executing one fenced Attempt for Bullet Farm.\n\
             Objective: {}\n\
             Base commit: {}\n\
             {}\n\
             Writable scope (path prefixes; anything else is refused before apply): {}\n\
             Admitted gate IDs (echo this exact ordered list in gate_ids): {:?}\n\
             The workspace is read-only for you; the kernel applies changes through its \
             own writer.\n\
             Respond with exactly one PatchProposal JSON object matching this schema. \
             Echo the exact Attempt/checkpoint/gate subjects. Every operation must carry \
             an absent or BLAKE3 preimage and a tagged write/delete mutation:\n{}",
            self.objective,
            self.base_sha,
            self.binding_lines(),
            self.scope_line(),
            self.admitted_gate_ids,
            bullet_harness_core::proposal::schema_source(),
        )
    }

    /// Feedback after a gate selection refusal. Nothing was applied.
    #[must_use]
    pub fn gate_selection_prompt(&self, detail: &str) -> String {
        format!(
            "GATE_SELECTION_REFUSED: {detail}\n\
             Nothing was applied; gate IDs are policy references, never commands.\n\
             Re-propose with exactly these admitted gate_ids in order: {:?}\n{}",
            self.admitted_gate_ids,
            self.binding_lines(),
        )
    }

    /// Feedback after a proposal binds the wrong immutable subject.
    #[must_use]
    pub fn binding_refusal_prompt(&self, detail: &str) -> String {
        format!(
            "PROPOSAL_BINDING_REFUSED: {detail}\nNothing was applied. Re-propose with these exact bindings:\n{}",
            self.binding_lines()
        )
    }

    /// Feedback after a typed scope refusal. Nothing was applied.
    #[must_use]
    pub fn scope_denied_prompt(&self, path: &str) -> String {
        format!(
            "SCOPE_DENIED: your previous proposal touched \"{path}\", which is outside \
             the granted scope. Nothing was applied; the workspace is unchanged.\n\
             Granted prefixes: {}\n\
             Re-propose a PatchProposal that only touches paths under the granted prefixes.\n{}",
            self.scope_line(),
            self.binding_lines(),
        )
    }

    /// Feedback after the daemon refused a delete whose target is not an
    /// existing regular file (typed `PATH_ABSENT`). Nothing was applied.
    #[must_use]
    pub fn path_absent_prompt(&self, detail: &str) -> String {
        format!(
            "PATH_ABSENT: {detail}\n\
             The whole proposal was refused; nothing was applied and the workspace is \
             unchanged. Delete targets must be files that exist in the workspace.\n\
             Re-propose a complete PatchProposal without that delete.\n{}",
            self.binding_lines(),
        )
    }

    /// Structured gate results fed back for a bounded repair round.
    #[must_use]
    pub fn gate_feedback_prompt(&self, report: &GateReport) -> String {
        format!(
            "GATE_RESULT: gate `{}` with fixed argv {:?} did not pass.\n\
             exit_code: {:?}\ntimed_out: {}\nstdout:\n{}\nstderr:\n{}\n\
             Your patch was applied, then the gate ran in the workspace. Fix the failure \
             and respond with a complete new PatchProposal bound to the new checkpoint:\n{}",
            report.gate_id,
            report.argv,
            report.exit_code,
            report.timed_out,
            report.stdout,
            report.stderr,
            self.binding_lines(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capsule() -> Capsule {
        Capsule {
            objective: "create PONG.txt".into(),
            scope_prefixes: vec!["PONG.txt".into()],
            base_sha: "a".repeat(40),
            producing_attempt_id: format!("atm_{}", "2".repeat(64)),
            base_checkpoint_id: format!("ckp_{}", "3".repeat(64)),
            base_checkpoint_digest: "4".repeat(64),
            admitted_gate_ids: vec![crate::gate::REPOSITORY_GATE_ID.into()],
        }
    }

    #[test]
    fn initial_prompt_carries_the_capsule_fields() {
        let prompt = capsule().initial_prompt();
        for needle in [
            "create PONG.txt",
            &"a".repeat(40),
            crate::gate::REPOSITORY_GATE_ID,
            &format!("atm_{}", "2".repeat(64)),
            &format!("ckp_{}", "3".repeat(64)),
            "PatchProposal",
            "intent_summary",
        ] {
            assert!(prompt.contains(needle), "missing {needle}");
        }
    }

    #[test]
    fn feedback_prompts_are_typed() {
        let c = capsule();
        assert!(c.scope_denied_prompt("x/y").contains("SCOPE_DENIED"));
        let absent = c.path_absent_prompt("no regular file to delete at: z");
        assert!(absent.contains("PATH_ABSENT"));
        assert!(absent.contains("z"));
        assert!(absent.contains("nothing was applied"));
        let report = GateReport {
            gate_id: crate::gate::REPOSITORY_GATE_ID.into(),
            argv: vec![
                "/usr/bin/grep".into(),
                "-qx".into(),
                "PONG".into(),
                "PONG.txt".into(),
            ],
            exit_code: Some(1),
            timed_out: false,
            stdout: String::new(),
            stderr: "missing".into(),
        };
        let prompt = c.gate_feedback_prompt(&report);
        assert!(prompt.contains("GATE_RESULT"));
        assert!(prompt.contains("missing"));
        let selection = c.gate_selection_prompt("unknown gate");
        assert!(selection.contains("GATE_SELECTION_REFUSED"));
        assert!(selection.contains(crate::gate::REPOSITORY_GATE_ID));
    }
}
