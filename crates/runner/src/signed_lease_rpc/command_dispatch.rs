//! Peer-authenticated Runner client for durable public-command dispatch.

use super::SignedLeaseRpcClient;
use crate::error::RunnerError;
use bullet_application::{
    CommandDispatchClaim, CommandDispatchDisposition, CommandRecord, ComponentCommandCompletionV1,
};
use bullet_domain::CommandPhase;

impl SignedLeaseRpcClient {
    /// Claim the oldest supported public command for this Runner incarnation.
    pub async fn claim_command_dispatch(
        &self,
    ) -> Result<Option<CommandDispatchClaim>, RunnerError> {
        let value: serde_json::Value = self.call("command_claim", &serde_json::json!({})).await?;
        self.decode_owned_claim(value)
    }

    /// Read back this incarnation's durable open claim after response loss.
    pub async fn readback_command_dispatch(
        &self,
    ) -> Result<Option<CommandDispatchClaim>, RunnerError> {
        let value: serde_json::Value = self
            .call("command_readback", &serde_json::json!({}))
            .await?;
        self.decode_owned_claim(value)
    }

    /// Settle one exact retained component receipt. The Kernel can only
    /// persist the bounded bridge as `UNKNOWN`.
    pub async fn settle_component_command_dispatch(
        &self,
        claim_id: &str,
        completion: &ComponentCommandCompletionV1,
    ) -> Result<CommandRecord, RunnerError> {
        let value: serde_json::Value = self
            .call(
                "command_settle_component",
                &serde_json::json!({
                    "claim_id": claim_id,
                    "completion": completion,
                }),
            )
            .await?;
        let record: CommandRecord = serde_json::from_value(value)
            .map_err(|error| RunnerError::Protocol(error.to_string()))?;
        record
            .validate()
            .map_err(|error| RunnerError::Protocol(error.to_string()))?;
        if record.id != completion.command_id || record.phase != CommandPhase::Unknown {
            return Err(RunnerError::Protocol(
                "component settlement response is not the exact UNKNOWN command".into(),
            ));
        }
        Ok(record)
    }

    fn decode_owned_claim(
        &self,
        value: serde_json::Value,
    ) -> Result<Option<CommandDispatchClaim>, RunnerError> {
        let claim: Option<CommandDispatchClaim> = serde_json::from_value(value)
            .map_err(|error| RunnerError::Protocol(error.to_string()))?;
        let Some(claim) = claim else {
            return Ok(None);
        };
        claim
            .validate()
            .map_err(|error| RunnerError::Protocol(error.to_string()))?;
        if claim.runner_id != self.runner_id
            || claim.runner_epoch != self.runner_epoch
            || claim.disposition != CommandDispatchDisposition::Claimed
        {
            return Err(RunnerError::Protocol(
                "command claim does not belong to this Runner incarnation".into(),
            ));
        }
        Ok(Some(claim))
    }
}

#[cfg(test)]
mod tests;
