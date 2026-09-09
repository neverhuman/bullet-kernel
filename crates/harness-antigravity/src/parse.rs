//! Strict ingestion for the frozen one-shot Antigravity JSON result subset.

use crate::protocol::{
    exact_fields, protocol, AgyHeadlessBinding, AgyHeadlessOutcome, AgyHeadlessTranscript, Phase,
    MAX_OUTPUT_FRAME_BYTES,
};
use bullet_harness_core::{
    decode_strict_json, AgentEvent, AgentEventKind, HarnessError, NativeMeta, PatchProposal,
};
use serde_json::{json, Value};

impl AgyHeadlessTranscript {
    /// Consume the single-line JSON object emitted for one prepared turn.
    ///
    /// The admitted subset is deliberately just `{ "structured_output": ... }`.
    /// Native JSON fields outside that observed authorization-bearing field are
    /// not guessed. Any malformed, extra, repeated, or late result poisons the
    /// transcript permanently.
    ///
    /// # Errors
    ///
    /// Returns a typed protocol/proposal error and poisons this transcript.
    pub fn ingest_result_line(&mut self, line: &str) -> Result<Vec<AgentEvent>, HarnessError> {
        let result = self.ingest_result_line_inner(line);
        if result.is_err() {
            self.phase = Phase::Poisoned;
            self.outcome = None;
        }
        result
    }

    fn ingest_result_line_inner(&mut self, line: &str) -> Result<Vec<AgentEvent>, HarnessError> {
        if self.phase == Phase::Poisoned {
            return Err(protocol("transcript is poisoned"));
        }
        if self.phase != Phase::AwaitResult {
            return Err(protocol(
                "result is not expected before one argv is prepared",
            ));
        }
        if line.is_empty()
            || line.len() > MAX_OUTPUT_FRAME_BYTES
            || line.contains(['\n', '\r', '\0'])
        {
            return Err(protocol("invalid one-line JSON result boundary"));
        }
        let value: Value = decode_strict_json(line)
            .map_err(|error| protocol(format!("malformed JSON result: {error}")))?;
        let object = value
            .as_object()
            .ok_or_else(|| protocol("JSON result is not an object"))?;
        if !exact_fields(object, &["structured_output"]) {
            return Err(protocol(
                "JSON result is outside the exact structured_output subset",
            ));
        }
        let proposal = PatchProposal::from_value(&object["structured_output"])?;
        if proposal.gate_ids != self.admitted_gate_ids {
            return Err(protocol(
                "proposal gate_ids differ from exact ordered admission",
            ));
        }
        let binding = AgyHeadlessBinding {
            provider: crate::PROVIDER.to_string(),
            binary: crate::BINARY.to_string(),
            profile_id: self.profile_id.clone(),
            invocation_id: self.invocation_id.clone(),
            cwd: self.expected_cwd.clone(),
            runtime_version: self.expected_runtime_version.clone(),
            binary_sha256: self.expected_binary_sha256.clone(),
            prompt_digest: self.prompt_digest.clone(),
            gate_ids: self.admitted_gate_ids.clone(),
        };
        let outcome = AgyHeadlessOutcome {
            proposal: proposal.clone(),
            binding: binding.clone(),
        };
        self.outcome = Some(outcome);
        self.phase = Phase::Terminal;
        let event = self.normalizer.accept(
            AgentEventKind::TurnCompleted,
            json!({
                "proposal": proposal,
                "verified": false,
                "source": "agy_offline_contract",
                "binding": {
                    "provider": binding.provider,
                    "binary": binding.binary,
                    "profile_id": binding.profile_id,
                    "invocation_id": binding.invocation_id,
                    "cwd": binding.cwd,
                    "runtime_version": binding.runtime_version,
                    "binary_sha256": binding.binary_sha256,
                    "prompt_digest": binding.prompt_digest,
                    "gate_ids": binding.gate_ids,
                }
            }),
            &NativeMeta::none(),
        );
        Ok(vec![event])
    }
}
