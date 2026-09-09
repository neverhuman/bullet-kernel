//! Optional same-origin serving of the embedded Portal bundle.
//!
//! Without the `embedded-portal` feature [`router`] is empty, [`health_field`]
//! is `None`, and farmd mounts exactly the API routes it always has. With the
//! feature, `build.rs` has already verified a `bullet-portal` `dist/` against
//! its own bundle manifest, so the bytes compiled in here are exactly the
//! bytes of a known bundle subject; they are served from the daemon's own
//! origin so `--portal-origin` may equal that origin. Serving the page changes
//! no authority: the bootstrap, session-cookie, CSRF, and exact-Origin rules
//! in `auth.rs` are untouched, and no static route reads or writes the ledger.

use crate::api::SharedState;
use axum::Router;
#[cfg(feature = "embedded-portal")]
use axum::{
    response::{IntoResponse, Response},
    routing::get,
};

#[cfg(any(feature = "embedded-portal", test))]
macro_rules! portal_route_catalog {
    ($emit:ident) => {
        $emit! {
            Get, "/", index, false, "embedded-portal entry point; absent without the feature";
            Get, "/index.html", index, false, "embedded-portal entry point alias; absent without the feature";
            Get, "/assets/{file}", asset, false, "content-hashed embedded-portal asset; absent without the feature";
        }
    };
}

#[cfg(feature = "embedded-portal")]
macro_rules! mount_portal_method {
    (Get, $handler:ident) => {
        get($handler)
    };
}

#[cfg(feature = "embedded-portal")]
macro_rules! mount_portal_routes {
    ($( $kind:ident, $path:literal, $handler:ident, $openapi:literal, $meaning:literal; )+) => {
        Router::new()$(.route($path, mount_portal_method!($kind, $handler)))+
    };
}

#[cfg(test)]
macro_rules! declare_portal_inventory {
    ($( $kind:ident, $path:literal, $handler:ident, $openapi:literal, $meaning:literal; )+) => {
        pub(super) const PORTAL_ROUTE_INVENTORY: &[super::routes::RouteSpec] = &[
            $(super::routes::RouteSpec::new(
                super::routes::RouteMethod::$kind,
                $path,
                $openapi,
                $meaning,
            )),+
        ];
    };
}

#[cfg(test)]
portal_route_catalog!(declare_portal_inventory);

/// Content-hashed asset lifetime; the file name changes when the bytes change.
#[cfg(feature = "embedded-portal")]
const ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";
/// The entry point is never cached: it names the current asset digests.
#[cfg(feature = "embedded-portal")]
const INDEX_CACHE_CONTROL: &str = "no-cache, no-store, must-revalidate";
/// The page may load only its own same-origin assets and API, may not be
/// framed, and may not rewrite its base URI. `script-src` must allow
/// `unsafe-eval` because the Portal compiles its JSON Schema validators (AJV)
/// in the browser; narrowing that needs precompiled validators in the Portal
/// build, not a policy the page cannot run under.
#[cfg(feature = "embedded-portal")]
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; \
     script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; \
     img-src 'self' data:; connect-src 'self'; \
     base-uri 'none'; object-src 'none'; frame-ancestors 'none'";

/// One verified file of the embedded bundle.
#[cfg(feature = "embedded-portal")]
pub(crate) struct EmbeddedFile {
    /// Bundle-relative path.
    path: &'static str,
    /// MIME type bound by the bundle manifest.
    mime: &'static str,
    /// Strong entity tag derived from the manifest digest.
    etag: &'static str,
    /// Verified bytes.
    body: &'static [u8],
}

#[cfg(feature = "embedded-portal")]
mod embedded {
    use super::EmbeddedFile;

    include!(concat!(env!("OUT_DIR"), "/portal_bundle.rs"));
}

/// Static routes for the embedded Portal; empty without the feature.
///
/// The returned router has no fallback, so merging it never displaces the
/// API's typed `NOT_FOUND` answer for unknown paths.
#[cfg(feature = "embedded-portal")]
pub(crate) fn router() -> Router<SharedState> {
    tracing::info!("{}", startup_line());
    portal_route_catalog!(mount_portal_routes)
}

/// Static routes for the embedded Portal; empty without the feature.
#[cfg(not(feature = "embedded-portal"))]
pub(crate) fn router() -> Router<SharedState> {
    tracing::info!("{}", startup_line());
    Router::new()
}

/// `/health` `portal` field: `None` when no bundle is compiled in.
#[cfg(feature = "embedded-portal")]
pub(crate) fn health_field() -> Option<&'static str> {
    Some(embedded::ROOT)
}

/// `/health` `portal` field: `None` when no bundle is compiled in.
#[cfg(not(feature = "embedded-portal"))]
pub(crate) fn health_field() -> Option<&'static str> {
    None
}

/// Startup line describing what this binary serves at `/`.
#[cfg(feature = "embedded-portal")]
pub(crate) fn startup_line() -> String {
    format!(
        "portal: embedded {} (bullet-portal commit {}, tree {})",
        embedded::ROOT,
        embedded::SOURCE_COMMIT,
        embedded::SOURCE_TREE
    )
}

/// Startup line describing what this binary serves at `/`.
#[cfg(not(feature = "embedded-portal"))]
pub(crate) fn startup_line() -> String {
    "portal: none".to_string()
}

#[cfg(feature = "embedded-portal")]
async fn index() -> Response {
    match find("index.html") {
        Some(file) => serve(file, INDEX_CACHE_CONTROL),
        None => crate::errors::ApiError::NotFound("Portal entry point".into()).into_response(),
    }
}

#[cfg(feature = "embedded-portal")]
async fn asset(axum::extract::Path(file): axum::extract::Path<String>) -> Response {
    let requested = format!("assets/{file}");
    match find(&requested) {
        Some(file) => serve(file, ASSET_CACHE_CONTROL),
        None => crate::errors::ApiError::NotFound("Portal asset".into()).into_response(),
    }
}

/// Exact-path lookup; no filesystem, traversal, or directory listing exists.
#[cfg(feature = "embedded-portal")]
fn find(path: &str) -> Option<&'static EmbeddedFile> {
    embedded::FILES.iter().find(|file| file.path == path)
}

#[cfg(feature = "embedded-portal")]
fn serve(file: &'static EmbeddedFile, cache_control: &'static str) -> Response {
    use axum::http::header;

    (
        [
            (header::CONTENT_TYPE, file.mime),
            (header::CACHE_CONTROL, cache_control),
            (header::ETAG, file.etag),
            (header::CONTENT_SECURITY_POLICY, CONTENT_SECURITY_POLICY),
            (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
            (header::REFERRER_POLICY, "no-referrer"),
        ],
        file.body,
    )
        .into_response()
}
