use super::canonical::hash_canonical;
use crate::error::HarnessError;

const SCOPE_PATHS_DOMAIN: &str = "candidate-preparation.scope-paths.v1alpha1";

/// Bind the ordered granted-scope list to one bullet-wire framed BLAKE3 digest.
pub fn candidate_preparation_scope_paths_digest(paths: &[String]) -> Result<String, HarnessError> {
    hash_canonical(SCOPE_PATHS_DOMAIN, &paths)
}
