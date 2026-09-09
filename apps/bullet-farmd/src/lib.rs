//! Control-plane daemon library. The portal is a projection of this API.

pub mod api;
pub mod auth;
mod commands;
mod dispatch;
pub mod errors;
pub mod kernel_authority;
pub mod kernel_authority_rpc;
pub mod lease_transport_custody;
pub mod lease_transport_rpc;
pub mod leases;
mod projections;
pub mod reaper;
