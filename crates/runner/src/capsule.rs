//! The prompt capsule: objective, scope, base SHA, gate command, and the
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
    /// Deterministic gate command the kernel runs after each apply.
    pub gate_command: String,
}

impl Capsule {
    fn scope_line(&self) -> String {
        self.scope_prefixes.join(", ")
    }

    /// The first turn's prompt.
    #[must_use]
    pub fn initial_prompt(&self) -> String {
        format!(
            "You are executing one fenced Attempt for Bullet Farm.\n\
             Objective: {}\n\
             Base commit: {}\n\
             Writable scope (path prefixes; anything else is refused before apply): {}\n\
             Gate command the kernel will run after applying your proposal: {}\n\
             The workspace is read-only for you; the kernel applies changes through its \
             own writer.\n\
             Respond with exactly one PatchProposal JSON object matching this schema \
             (full-file contents per created/modified path; op \"delete\" removes an \
             existing file and carries \"contents\": null):\n{}",
            self.objective,
            self.base_sha,
            self.scope_line(),
            self.gate_command,
            bullet_harness_core::proposal::schema_source(),
        )
    }

    /// Feedback after a typed scope refusal. Nothing was applied.
    #[must_use]
    pub fn scope_denied_prompt(&self, path: &str) -> String {
        format!(
            "SCOPE_DENIED: your previous proposal touched \"{path}\", which is outside \
             the granted scope. Nothing was applied; the workspace is unchanged.\n\
             Granted prefixes: {}\n\
             Re-propose a PatchProposal that only touches paths under the granted prefixes.",
            self.scope_line(),
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
             Re-propose a complete PatchProposal without that delete.",
        )
    }

    /// Structured gate results fed back for a bounded repair round.
    #[must_use]
    pub fn gate_feedback_prompt(&self, report: &GateReport) -> String {
        format!(
            "GATE_RESULT: command `{}` did not pass.\n\
             exit_code: {:?}\ntimed_out: {}\nstdout:\n{}\nstderr:\n{}\n\
             Your patch was applied, then the gate ran in the workspace. Fix the failure \
             and respond with a complete new PatchProposal (full file contents; the next \
             apply replaces whole files).",
            report.command, report.exit_code, report.timed_out, report.stdout, report.stderr,
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
            gate_command: "test -f PONG.txt".into(),
        }
    }

    #[test]
    fn initial_prompt_carries_the_capsule_fields() {
        let prompt = capsule().initial_prompt();
        for needle in [
            "create PONG.txt",
            &"a".repeat(40),
            "test -f PONG.txt",
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
            command: "test -f PONG.txt".into(),
            exit_code: Some(1),
            timed_out: false,
            stdout: String::new(),
            stderr: "missing".into(),
        };
        let prompt = c.gate_feedback_prompt(&report);
        assert!(prompt.contains("GATE_RESULT"));
        assert!(prompt.contains("missing"));
    }
}
