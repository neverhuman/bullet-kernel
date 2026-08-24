//! Simulator-only adapter selection for non-gating integration scaffolding.

use bullet_harness_core::HarnessAdapter;
use std::sync::Arc;

/// Resolve the only provider admitted by this scaffold.
#[must_use]
pub fn adapter_for(provider: &str) -> Option<Arc<dyn HarnessAdapter>> {
    (provider == "sim")
        .then(|| Arc::new(bullet_harness_sim::SimAdapter::new()) as Arc<dyn HarnessAdapter>)
}
