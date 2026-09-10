//! Bounded recovery of server-owned command identities after local cache loss.
use super::{operator_error, status_view, CommandStatus};
use crate::{api::SharedState, errors::ApiError};
use axum::{
    extract::{RawQuery, State},
    http::{header, HeaderMap, HeaderValue},
    response::Response,
};
use bullet_application::operator_commands::{OperatorCommandError, OperatorCommandStore};
use serde::Serialize;

#[derive(Serialize)]
struct CommandDiscoveryView {
    commands: Vec<CommandStatus>,
    next_after: Option<u64>,
}
pub(super) fn query(raw: Option<&str>) -> Result<(u64, u32), ApiError> {
    let bad = || operator_error(OperatorCommandError::InvalidRequest);
    let Some(raw) = raw.filter(|query| !query.is_empty()) else {
        return Ok((0, 50));
    };
    if raw.len() > 256 {
        return Err(bad());
    }
    let mut after = None;
    let mut limit = None;
    for pair in raw.split('&') {
        let (key, value) = pair.split_once('=').ok_or_else(bad)?;
        if value.is_empty()
            || !value.bytes().all(|byte| byte.is_ascii_digit())
            || (value.len() > 1 && value.starts_with('0'))
        {
            return Err(bad());
        }
        match key {
            "after" if after.is_none() => after = Some(value.parse::<u64>().map_err(|_| bad())?),
            "limit" if limit.is_none() => limit = Some(value.parse::<u32>().map_err(|_| bad())?),
            _ => return Err(bad()),
        }
    }
    let after = after.unwrap_or(0);
    let limit = limit.unwrap_or(50);
    if after > 9_007_199_254_740_991 || !(1..=100).contains(&limit) {
        return Err(bad());
    }
    Ok((after, limit))
}
pub(crate) async fn list(
    State(state): State<SharedState>,
    headers: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Result<Response, ApiError> {
    let operator = state
        .auth
        .lock()
        .await
        .authorize_session(&headers)?
        .operator_id;
    let (after, limit) = query(raw.as_deref())?;
    let page = state
        .ledger
        .lock()
        .await
        .list_operator_commands(&operator, after, limit)
        .map_err(operator_error)?;
    let commands = page
        .commands
        .into_iter()
        .map(status_view)
        .collect::<Result<Vec<_>, _>>()?;
    let mut response = crate::api::snapshot_response(
        CommandDiscoveryView {
            commands,
            next_after: page.next_after,
        },
        page.as_of_sequence,
    )?;
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn discovery_query_is_bounded_unambiguous_and_closed() {
        assert_eq!(
            query(None).unwrap_or_else(|_| panic!("default query")),
            (0, 50)
        );
        assert_eq!(
            query(Some("after=7&limit=2")).unwrap_or_else(|_| panic!("bounded query")),
            (7, 2)
        );
        for raw in [
            "after=01",
            "after=-1",
            "after=+1",
            "after=%31",
            "after=1&after=2",
            "limit=0",
            "limit=101",
            "limit=2&limit=3",
            "owner=someone",
            "after=9007199254740992",
            "after=1&",
            "limit=4294967296",
        ] {
            assert!(query(Some(raw)).is_err(), "{raw}");
        }
        assert!(query(Some(&"1".repeat(257))).is_err());
    }
}
