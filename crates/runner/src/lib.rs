//! Attempt runner loop: lease, private clone via bullet-gitd, provider session, scope check, apply, gate, candidate.
//!
//! Scaffold registered by lane L0 so parallel lanes never edit Cargo.toml concurrently.
