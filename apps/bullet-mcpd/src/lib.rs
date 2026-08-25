//! Read-only MCP adapter over existing Bullet Farm Kernel projections.
//!
//! This process is deliberately outside every authority boundary. It reads
//! fixed loopback farmd routes and exposes their exact sequence-bound JSON. It
//! has no command, lease, Git, provider, verification, or effect operation.

mod client;
pub mod transport;

pub use client::{ClientError, LoopbackFarmd, ProjectionRoute};

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{CallToolResult, Implementation, ServerCapabilities, ServerInfo};
use rmcp::{handler::server::wrapper::Parameters, tool, tool_handler, tool_router, ServerHandler};
use schemars::JsonSchema;
use serde::Deserialize;
use serde_json::{json, Value};

/// Read-only MCP server backed by one exact loopback farmd.
#[derive(Clone, Debug)]
pub struct BulletMcp {
    farmd: LoopbackFarmd,
    tool_router: ToolRouter<Self>,
}

/// Input for one exact mission projection.
#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct MissionInput {
    /// Full `mis_` identifier from the shared Kernel domain.
    pub mission_id: String,
}

#[tool_router(router = tool_router)]
impl BulletMcp {
    /// Construct the server without minting or accepting any credential.
    #[must_use]
    pub fn new(farmd: LoopbackFarmd) -> Self {
        Self {
            farmd,
            tool_router: Self::tool_router(),
        }
    }

    /// Read the mission-list snapshot with its durable sequence watermark.
    #[tool(
        name = "bullet_missions",
        annotations(
            title = "Bullet missions",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn missions(&self) -> CallToolResult {
        self.read(ProjectionRoute::Missions).await
    }

    /// Read one exact mission graph projection.
    #[tool(
        name = "bullet_mission",
        annotations(
            title = "Bullet mission",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn mission(&self, Parameters(input): Parameters<MissionInput>) -> CallToolResult {
        tool_result(self.farmd.read_mission(&input.mission_id).await)
    }

    /// Read the fleet and ready-queue snapshot.
    #[tool(
        name = "bullet_fleet",
        annotations(
            title = "Bullet fleet",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn fleet(&self) -> CallToolResult {
        self.read(ProjectionRoute::Fleet).await
    }

    /// Read the attempt/session supervisor snapshot.
    #[tool(
        name = "bullet_sessions",
        annotations(
            title = "Bullet sessions",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn sessions(&self) -> CallToolResult {
        self.read(ProjectionRoute::Sessions).await
    }

    /// Read immutable context lineage.
    #[tool(
        name = "bullet_context_lineage",
        annotations(
            title = "Bullet context lineage",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn context_lineage(&self) -> CallToolResult {
        self.read(ProjectionRoute::ContextLineage).await
    }

    /// Read Candidate and effect reconciliation state.
    #[tool(
        name = "bullet_merge_rail",
        annotations(
            title = "Bullet merge rail",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn merge_rail(&self) -> CallToolResult {
        self.read(ProjectionRoute::MergeRail).await
    }

    /// Read exact-subject Evidence state.
    #[tool(
        name = "bullet_quality_lab",
        annotations(
            title = "Bullet quality lab",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn quality_lab(&self) -> CallToolResult {
        self.read(ProjectionRoute::QualityLab).await
    }

    /// Read the bounded durable audit tail.
    #[tool(
        name = "bullet_audit",
        annotations(
            title = "Bullet audit",
            read_only_hint = true,
            destructive_hint = false,
            idempotent_hint = true,
            open_world_hint = false
        )
    )]
    async fn audit(&self) -> CallToolResult {
        self.read(ProjectionRoute::Audit).await
    }

    async fn read(&self, route: ProjectionRoute) -> CallToolResult {
        tool_result(self.farmd.read_projection(route).await)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for BulletMcp {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("bullet-mcpd", env!("CARGO_PKG_VERSION"))
                    .with_title("Bullet Farm read-only projections"),
            )
            .with_instructions(
                "Every tool is a read-only, sequence-bound Kernel projection. No tool submits commands, mints authority, writes Git, invokes a provider, verifies evidence, or dispatches effects.",
            )
    }
}

fn tool_result(result: Result<Value, ClientError>) -> CallToolResult {
    match result {
        Ok(snapshot) => CallToolResult::structured(snapshot),
        Err(error) => CallToolResult::structured_error(json!({
            "code": error_code(&error),
            "detail": error.to_string(),
            "repair": "Confirm bullet-farmd is running on the configured loopback endpoint and read a fresh projection. Never infer empty, PASS, VERIFIED, or command failure from this error."
        })),
    }
}

fn error_code(error: &ClientError) -> &'static str {
    match error {
        ClientError::InvalidInput(_) => "INVALID_INPUT",
        ClientError::InvalidEndpoint(_) => "INVALID_FARMD_ENDPOINT",
        ClientError::Unavailable(_) => "FARMD_UNAVAILABLE",
        ClientError::Refused { .. } => "FARMD_REFUSED",
        ClientError::InvalidResponse(_) => "INVALID_FARMD_RESPONSE",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_inventory_is_closed_and_read_only() {
        let server = BulletMcp::new(LoopbackFarmd::new("http://127.0.0.1:7420").unwrap());
        let tools = server.tool_router.list_all();
        let names: Vec<_> = tools.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(
            names,
            [
                "bullet_audit",
                "bullet_context_lineage",
                "bullet_fleet",
                "bullet_merge_rail",
                "bullet_mission",
                "bullet_missions",
                "bullet_quality_lab",
                "bullet_sessions",
            ]
        );
        for tool in tools {
            let annotations = tool.annotations.expect("explicit annotations");
            assert_eq!(annotations.read_only_hint, Some(true));
            assert_eq!(annotations.destructive_hint, Some(false));
            assert_eq!(annotations.idempotent_hint, Some(true));
            assert_eq!(annotations.open_world_hint, Some(false));
            for forbidden in [
                "command",
                "submit",
                "lease",
                "git",
                "provider",
                "verify",
                "effect",
                "authority",
            ] {
                assert!(!tool.name.contains(forbidden), "{}", tool.name);
            }
        }
    }
}
