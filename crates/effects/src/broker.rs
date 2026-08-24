//! Effect broker. Timeout is UNKNOWN. Replay uses the logical key.

use crate::forge::{EffectIntent, LocalBareForge};
use crate::phase::EffectPhase;

/// One brokered effect.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EffectRecord {
    /// Intent.
    pub intent: EffectIntent,
    /// Phase.
    pub phase: EffectPhase,
}

/// Drive one intent against `LocalBareForge`.
///
/// After a timeout the remote is read back. If the desired value is present,
/// the effect is adopted as verified. A retry never writes a second object
/// when the first write already landed.
///
/// # Errors
///
/// Returns a conflict when the precondition no longer matches and the desired
/// value is not already present.
pub fn dispatch(
    forge: &mut LocalBareForge,
    intent: EffectIntent,
) -> Result<EffectRecord, &'static str> {
    let remote = forge.read_back(&intent.target);
    if remote.value.as_deref() == Some(intent.desired.as_str()) {
        return Ok(EffectRecord {
            intent,
            phase: EffectPhase::Verified,
        });
    }
    match forge.push(&intent) {
        Ok(()) => Ok(EffectRecord {
            intent,
            phase: EffectPhase::Verified,
        }),
        Err("timeout") => {
            let remote = forge.read_back(&intent.target);
            if remote.value.as_deref() == Some(intent.desired.as_str()) {
                Ok(EffectRecord {
                    intent,
                    phase: EffectPhase::Verified,
                })
            } else {
                Ok(EffectRecord {
                    intent,
                    phase: EffectPhase::OutcomeUnknown,
                })
            }
        }
        Err(other) => Err(other),
    }
}

/// Reconcile an UNKNOWN receipt by read-back. Does not push again unless the
/// remote is still at the expected precondition.
///
/// # Errors
///
/// Returns a conflict when the remote is neither expected nor desired.
pub fn reconcile_unknown(
    forge: &mut LocalBareForge,
    record: EffectRecord,
) -> Result<EffectRecord, &'static str> {
    if record.phase != EffectPhase::OutcomeUnknown {
        return Ok(record);
    }
    let remote = forge.read_back(&record.intent.target);
    if remote.value.as_deref() == Some(record.intent.desired.as_str()) {
        return Ok(EffectRecord {
            phase: EffectPhase::Verified,
            ..record
        });
    }
    if remote.value.as_deref().unwrap_or("") == record.intent.expected {
        return dispatch(forge, record.intent);
    }
    Err("unknown cannot be assumed; remote is neither expected nor desired")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> EffectIntent {
        EffectIntent {
            logical_key: "github:push:demo".into(),
            target: "refs/heads/bullet/candidate/demo".into(),
            expected: String::new(),
            desired: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
        }
    }

    #[test]
    fn timeout_after_apply_adopts_via_read_back() {
        let mut forge = LocalBareForge::new();
        forge.timeout_next_push = true;
        let first = dispatch(&mut forge, intent()).expect("dispatch");
        assert_eq!(first.phase, EffectPhase::Verified);
        assert_eq!(forge.write_count, 1);
        let second = dispatch(&mut forge, intent()).expect("replay");
        assert_eq!(second.phase, EffectPhase::Verified);
        assert_eq!(forge.write_count, 1);
    }

    #[test]
    fn unknown_is_not_success_when_remote_absent() {
        let mut forge = LocalBareForge::new();
        let record = EffectRecord {
            intent: intent(),
            phase: EffectPhase::OutcomeUnknown,
        };
        let next = reconcile_unknown(&mut forge, record).expect("still expected");
        assert_eq!(next.phase, EffectPhase::Verified);
        assert_eq!(forge.write_count, 1);
    }

    #[test]
    fn timeout_without_apply_stays_unknown() {
        let forge = LocalBareForge::new();
        let phase = EffectPhase::Dispatching.after_timeout();
        assert_eq!(phase, EffectPhase::OutcomeUnknown);
        assert!(forge.get("refs/heads/bullet/candidate/demo").is_none());
        assert!(!phase.is_verified());
    }
}
