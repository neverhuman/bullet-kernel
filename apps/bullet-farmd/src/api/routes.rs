//! Static farmd route catalog and its documentation/OpenAPI projection proof.

use super::SharedState;
use axum::{
    routing::{any, get, post},
    Router,
};

macro_rules! core_route_catalog {
    ($emit:ident) => {
        $emit! {
            Get, "/health", super::meta::health, true, "liveness `{\"status\":\"ok\"}`";
            Get, "/openapi.yaml", super::meta::openapi, true, "the embedded contract bytes";
            Get, "/api/v1/missions", super::list_missions, true, "mission list snapshot";
            Get, "/api/v1/missions/{id}", super::get_mission, true, "one mission with its sequence watermark";
            Get, "/api/v1/demo", super::get_demo, true, "demo receipt re-derived from ledger rows";
            Post, "/api/v1/demo/run", super::removed_demo_mutation, true, "retired direct mutation; submit a `run_demo` command";
            Post, "/api/v1/auth/bootstrap", crate::auth::bootstrap, true, "one-time local-browser session bootstrap";
            Post, "/api/v1/commands", crate::commands::submit, true, "authenticated command submission records `PENDING`";
            Get, "/api/v1/commands/{id}", crate::commands::get, true, "command status";
            Post, "/internal/v1/commands/{id}/reconcile", crate::commands::reconcile, false, "worker-bearer reconciler, outside the public contract";
            Get, "/api/v1/outbox", super::outbox, true, "outbox snapshot";
            Get, "/api/v1/events", super::events, true, "SSE ledger events with bounded replay";
            Get, "/api/v1/ready", crate::leases::next_ready, true, "next ready work package with its sequence watermark";
            Get, "/api/v1/fleet", crate::projections::fleet, true, "fleet projection from one atomic ledger snapshot";
            Get, "/api/v1/sessions", crate::projections::sessions, true, "sessions projection from one atomic ledger snapshot";
            Get, "/api/v1/context-lineage", crate::projections::context_lineage, true, "context-lineage projection from one atomic ledger snapshot";
            Get, "/api/v1/merge-rail", crate::projections::merge_rail, true, "merge-rail projection from one atomic ledger snapshot";
            Get, "/api/v1/quality-lab", crate::projections::quality_lab, true, "quality-lab projection from one atomic ledger snapshot";
            Get, "/api/v1/audit", crate::projections::audit, true, "audit projection from one atomic ledger snapshot";
            Any, "/v1", super::retired_api_version, false, "retired operator API root; always `410 API_VERSION_RETIRED`";
            Any, "/v1/{*path}", super::retired_api_version, false, "retired operator API subtree; always `410 API_VERSION_RETIRED`";
        }
    };
}

macro_rules! mount_route_method {
    (Get, $handler:path) => {
        get($handler)
    };
    (Post, $handler:path) => {
        post($handler)
    };
    (Any, $handler:path) => {
        any($handler)
    };
}

macro_rules! mount_routes {
    ($( $kind:ident, $path:literal, $handler:path, $openapi:literal, $meaning:literal; )+) => {
        Router::new()$(.route($path, mount_route_method!($kind, $handler)))+
    };
}

pub(super) fn router() -> Router<SharedState> {
    core_route_catalog!(mount_routes)
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(super) enum RouteMethod {
    Get,
    Put,
    Post,
    Delete,
    Options,
    Head,
    Patch,
    Trace,
    Any,
}

#[cfg(test)]
impl RouteMethod {
    fn from_openapi(value: &str) -> Option<Self> {
        Some(match value {
            "get" => Self::Get,
            "put" => Self::Put,
            "post" => Self::Post,
            "delete" => Self::Delete,
            "options" => Self::Options,
            "head" => Self::Head,
            "patch" => Self::Patch,
            "trace" => Self::Trace,
            _ => return None,
        })
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Post => "POST",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
            Self::Head => "HEAD",
            Self::Patch => "PATCH",
            Self::Trace => "TRACE",
            Self::Any => "ANY",
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Debug)]
pub(super) struct RouteSpec {
    method: RouteMethod,
    path: &'static str,
    openapi: bool,
    meaning: &'static str,
}

#[cfg(test)]
impl RouteSpec {
    pub(super) const fn new(
        method: RouteMethod,
        path: &'static str,
        openapi: bool,
        meaning: &'static str,
    ) -> Self {
        Self {
            method,
            path,
            openapi,
            meaning,
        }
    }
}

#[cfg(test)]
macro_rules! declare_route_inventory {
    ($( $kind:ident, $path:literal, $handler:path, $openapi:literal, $meaning:literal; )+) => {
        const CORE_ROUTE_INVENTORY: &[RouteSpec] = &[
            $(RouteSpec::new(RouteMethod::$kind, $path, $openapi, $meaning)),+
        ];
    };
}

#[cfg(test)]
core_route_catalog!(declare_route_inventory);

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use std::fmt::Write as _;

    const START: &str = "<!-- bullet-farmd-route-table:v1:start -->";
    const END: &str = "<!-- bullet-farmd-route-table:v1:end -->";
    const README: &str = include_str!("../../../../README.md");
    const OPENAPI: &str = include_str!("../../../../contracts/openapi.yaml");

    fn inventory() -> Vec<RouteSpec> {
        CORE_ROUTE_INVENTORY
            .iter()
            .chain(super::super::portal::PORTAL_ROUTE_INVENTORY)
            .copied()
            .collect()
    }

    fn render(routes: &[RouteSpec]) -> String {
        let mut output = String::new();
        writeln!(output, "{START}").unwrap();
        writeln!(output, "| Method | Path | In `openapi.yaml` | Meaning |").unwrap();
        writeln!(output, "| --- | --- | --- | --- |").unwrap();
        for route in routes {
            writeln!(
                output,
                "| {} | `{}` | {} | {} |",
                route.method.label(),
                route.path,
                if route.openapi { "yes" } else { "no" },
                route.meaning,
            )
            .unwrap();
        }
        output.push_str(END);
        output
    }

    fn openapi_routes(source: &str) -> Result<BTreeSet<(RouteMethod, String)>, String> {
        // Deliberately narrow: the committed contract uses block YAML with one
        // top-level `paths`, two-space literal path keys, and four-space HTTP
        // method keys. Unknown keys at either level fail closed; the general
        // YAML/schema check remains `bullet contracts check`.
        let mut in_paths = false;
        let mut saw_paths = false;
        let mut current_path = None;
        let mut routes = BTreeSet::new();
        for (index, line) in source.lines().enumerate() {
            if line == "paths:" {
                if saw_paths {
                    return Err("OpenAPI contains duplicate paths mappings".into());
                }
                in_paths = true;
                saw_paths = true;
                continue;
            }
            if !in_paths {
                continue;
            }
            if !line.is_empty() && !line.starts_with(' ') {
                break;
            }
            let indentation = line.len() - line.trim_start().len();
            if indentation == 2 {
                let key = line.trim().strip_suffix(':').ok_or_else(|| {
                    format!("OpenAPI path key at line {} has no colon", index + 1)
                })?;
                if !key.starts_with('/') || key.contains(['\'', '"']) {
                    return Err(format!("unsupported OpenAPI path key {key}"));
                }
                current_path = Some(key.to_string());
            } else if indentation == 4 && !line.trim().is_empty() {
                let key = line.trim().strip_suffix(':').ok_or_else(|| {
                    format!("OpenAPI method key at line {} has no colon", index + 1)
                })?;
                let method = RouteMethod::from_openapi(key)
                    .ok_or_else(|| format!("unsupported OpenAPI method key {key}"))?;
                let path = current_path
                    .clone()
                    .ok_or_else(|| "OpenAPI method precedes its path".to_string())?;
                if !routes.insert((method, path)) {
                    return Err("OpenAPI contains a duplicate method/path".into());
                }
            }
        }
        if !saw_paths || routes.is_empty() {
            return Err("OpenAPI paths mapping is absent or empty".into());
        }
        Ok(routes)
    }

    fn expected_openapi(routes: &[RouteSpec]) -> Result<BTreeSet<(RouteMethod, String)>, String> {
        let mut all = BTreeSet::new();
        let mut expected = BTreeSet::new();
        for route in routes {
            if !all.insert((route.method, route.path)) {
                return Err(format!(
                    "duplicate catalog route {} {}",
                    route.method.label(),
                    route.path
                ));
            }
            if route.openapi {
                if route.method == RouteMethod::Any {
                    return Err(format!("ANY route {} cannot be public OpenAPI", route.path));
                }
                expected.insert((route.method, route.path.to_string()));
            }
        }
        Ok(expected)
    }

    fn compare_openapi(
        actual: &BTreeSet<(RouteMethod, String)>,
        routes: &[RouteSpec],
    ) -> Result<(), String> {
        if actual != &expected_openapi(routes)? {
            return Err("OpenAPI method/path set differs from catalog membership".into());
        }
        Ok(())
    }

    fn validate(readme: &str, openapi: &str, routes: &[RouteSpec]) -> Result<(), String> {
        let expected = render(routes);
        let starts = readme.match_indices(START).collect::<Vec<_>>();
        let ends = readme.match_indices(END).collect::<Vec<_>>();
        if starts.len() != 1 || ends.len() != 1 || starts[0].0 >= ends[0].0 {
            return Err("README route-table markers are missing, duplicated, or reordered".into());
        }
        let actual = &readme[starts[0].0..ends[0].0 + END.len()];
        if actual != expected {
            return Err("README route table differs from the static catalog projection".into());
        }
        compare_openapi(&openapi_routes(openapi)?, routes)
    }

    #[test]
    fn route_inventory_binds_router_readme_and_openapi() {
        let routes = inventory();
        validate(README, OPENAPI, &routes).expect("current route contract");

        let generated = render(&routes);
        let first_row = generated.lines().nth(3).expect("first route row");
        for hostile in [
            README.replace(&format!("{first_row}\n"), ""),
            README.replace(END, "| GET | `/hostile-extra` | no | hostile |\n<!-- bullet-farmd-route-table:v1:end -->"),
            README.replacen("| GET | `/health`", "| POST | `/health`", 1),
        ] {
            assert!(validate(&hostile, OPENAPI, &routes).is_err());
        }

        let actual = openapi_routes(OPENAPI).expect("parse current OpenAPI routes");
        let health = (RouteMethod::Get, "/health".to_string());
        let mut missing = actual.clone();
        assert!(missing.remove(&health));
        let mut extra = actual.clone();
        extra.insert((RouteMethod::Get, "/hostile-extra".into()));
        let mut wrong_method = actual;
        assert!(wrong_method.remove(&health));
        wrong_method.insert((RouteMethod::Post, "/health".into()));
        for hostile in [missing, extra, wrong_method] {
            assert!(
                compare_openapi(&hostile, &routes).is_err(),
                "hostile OpenAPI set was accepted"
            );
        }

        let mut method_mismatch = routes.clone();
        method_mismatch
            .iter_mut()
            .find(|route| route.path == "/health")
            .expect("health route")
            .method = RouteMethod::Post;
        assert!(validate(README, OPENAPI, &method_mismatch).is_err());

        let mut wrong_membership = routes.clone();
        let retired = wrong_membership
            .iter_mut()
            .find(|route| route.path == "/v1")
            .expect("retired route");
        retired.openapi = true;
        assert!(compare_openapi(
            &openapi_routes(OPENAPI).expect("parse current OpenAPI routes"),
            &wrong_membership
        )
        .is_err());
    }
}
