//! Mock MCP tools for required CI. No host filesystem writes, no GitHub,
//! no search network. Each handler answers JSON-RPC 2.0 over a value.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

/// JSON-RPC request.
#[derive(Clone, Debug, Deserialize)]
pub struct RpcRequest {
    /// Method name.
    pub method: String,
    /// Params object.
    #[serde(default)]
    pub params: Value,
    /// Request id.
    pub id: Value,
}

/// JSON-RPC response.
#[derive(Clone, Debug, Serialize, PartialEq)]
pub struct RpcResponse {
    /// Protocol version.
    pub jsonrpc: String,
    /// Echoed id.
    pub id: Value,
    /// Result or error payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    /// Error object.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
}

/// Which mock server is answering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MockServer {
    /// Virtual filesystem.
    Fs,
    /// GitHub-shaped REST facts.
    Github,
    /// Search index.
    Search,
}

/// In-memory mock world.
#[derive(Clone, Debug, Default)]
pub struct MockWorld {
    /// Path -> contents.
    pub files: BTreeMap<String, String>,
    /// Repo -> default branch SHA.
    pub repos: BTreeMap<String, String>,
    /// Query -> hits.
    pub index: BTreeMap<String, Vec<String>>,
}

impl MockWorld {
    /// Seed the three mocks with deterministic fixtures.
    #[must_use]
    pub fn fixtures() -> Self {
        let mut world = Self::default();
        world.files.insert("PONG.txt".into(), "pong\n".into());
        world
            .repos
            .insert("root/bullet-kernel".into(), "abc123".into());
        world
            .index
            .insert("pong".into(), vec!["PONG.txt:1:pong".into()]);
        world
    }

    /// Dispatch one request to a named server.
    #[must_use]
    pub fn handle(&self, server: MockServer, request: &RpcRequest) -> RpcResponse {
        match (server, request.method.as_str()) {
            (MockServer::Fs, "fs/read") => {
                let path = request
                    .params
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match self.files.get(path) {
                    Some(body) => ok(&request.id, json!({ "path": path, "contents": body })),
                    None => err(&request.id, "FS_NOT_FOUND", path),
                }
            }
            (MockServer::Fs, "fs/list") => ok(
                &request.id,
                json!({ "entries": self.files.keys().cloned().collect::<Vec<_>>() }),
            ),
            (MockServer::Github, "github/repo") => {
                let name = request
                    .params
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                match self.repos.get(name) {
                    Some(sha) => ok(&request.id, json!({ "name": name, "sha": sha })),
                    None => err(&request.id, "GITHUB_NOT_FOUND", name),
                }
            }
            (MockServer::Search, "search/query") => {
                let q = request
                    .params
                    .get("q")
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let hits = self.index.get(q).cloned().unwrap_or_default();
                ok(&request.id, json!({ "q": q, "hits": hits }))
            }
            (_, method) => err(&request.id, "MCP_UNSUPPORTED", method),
        }
    }
}

fn ok(id: &Value, result: Value) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: Some(result),
        error: None,
    }
}

fn err(id: &Value, code: &str, detail: &str) -> RpcResponse {
    RpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: None,
        error: Some(json!({ "code": code, "detail": detail })),
    }
}

/// Parse one stdio line into a request.
///
/// # Errors
///
/// Returns the serde error when the line is not JSON-RPC.
pub fn parse_line(line: &str) -> Result<RpcRequest, serde_json::Error> {
    serde_json::from_str(line)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, params: Value) -> RpcRequest {
        RpcRequest {
            method: method.into(),
            params,
            id: json!(1),
        }
    }

    #[test]
    fn mocks_stay_offline() {
        let world = MockWorld::fixtures();
        let read = world.handle(
            MockServer::Fs,
            &req("fs/read", json!({ "path": "PONG.txt" })),
        );
        assert_eq!(read.result.unwrap()["contents"], "pong\n");
        let missing = world.handle(MockServer::Fs, &req("fs/read", json!({ "path": "secret" })));
        assert_eq!(missing.error.unwrap()["code"], "FS_NOT_FOUND");
        let repo = world.handle(
            MockServer::Github,
            &req("github/repo", json!({ "name": "root/bullet-kernel" })),
        );
        assert_eq!(repo.result.unwrap()["sha"], "abc123");
        let search = world.handle(
            MockServer::Search,
            &req("search/query", json!({ "q": "pong" })),
        );
        assert_eq!(search.result.unwrap()["hits"][0], "PONG.txt:1:pong");
        let bad = world.handle(MockServer::Search, &req("search/live", json!({})));
        assert_eq!(bad.error.unwrap()["code"], "MCP_UNSUPPORTED");
    }
}
