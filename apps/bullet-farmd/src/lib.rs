//! Control-plane daemon library. The portal is a projection of this API.

pub mod api;
pub mod auth;
mod commands;
pub mod errors;
pub mod leases;
mod projections;
pub mod reaper;
