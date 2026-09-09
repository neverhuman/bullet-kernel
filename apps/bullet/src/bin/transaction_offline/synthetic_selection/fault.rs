//! Exact debug-only faults used to prove selection/receipt ordering.

const ENV: &str = "BULLET_SYNTHETIC_DOGFOOD_FAULT";
const AFTER_ACQUIRE: &str = "after-acquire";
const LANE_B_AFTER_ACQUIRE: &str = "lane-b-after-acquire";
const BEFORE_SELECTION: &str = "before-selection";
const BEFORE_RECEIPT: &str = "before-receipt";
const AFTER_RECEIPT: &str = "after-receipt";
const AFTER_DELIVERY_UNKNOWN: &str = "after-delivery-unknown";
const BEFORE_EFFECT_RECEIPT: &str = "before-effect-receipt";
const AFTER_EFFECT_RECEIPT: &str = "after-effect-receipt";
const EFFECT_GRANT_CHANGED: &str = "effect-grant-changed";
const EFFECT_GRANT_READBACK_ERROR: &str = "effect-grant-readback-error";

pub(super) fn preflight() -> Result<(), String> {
    match std::env::var_os(ENV) {
        None => Ok(()),
        Some(value)
            if [
                AFTER_ACQUIRE,
                LANE_B_AFTER_ACQUIRE,
                BEFORE_SELECTION,
                BEFORE_RECEIPT,
                AFTER_RECEIPT,
                AFTER_DELIVERY_UNKNOWN,
                BEFORE_EFFECT_RECEIPT,
                AFTER_EFFECT_RECEIPT,
                EFFECT_GRANT_CHANGED,
                EFFECT_GRANT_READBACK_ERROR,
            ]
            .iter()
            .any(|expected| value == *expected) =>
        {
            Ok(())
        }
        Some(_) => Err(super::fail(
            "SYNTHETIC_DOGFOOD_FAULT_INVALID: unsupported exact fault",
        )),
    }
}

pub(super) fn after_acquire() -> bool {
    std::env::var_os(ENV).is_some_and(|value| value == AFTER_ACQUIRE)
}

pub(super) fn lane_b_after_acquire(index: usize) -> bool {
    index == 1 && selected(LANE_B_AFTER_ACQUIRE)
}

pub(super) fn before_selection() -> bool {
    selected(BEFORE_SELECTION)
}

pub(super) fn before_receipt() -> bool {
    selected(BEFORE_RECEIPT)
}

pub(super) fn after_receipt() -> bool {
    selected(AFTER_RECEIPT)
}

pub(super) fn after_delivery_unknown() -> bool {
    selected(AFTER_DELIVERY_UNKNOWN)
}

pub(super) fn before_effect_receipt() -> bool {
    selected(BEFORE_EFFECT_RECEIPT)
}

pub(super) fn after_effect_receipt() -> bool {
    selected(AFTER_EFFECT_RECEIPT)
}

pub(super) fn effect_grant_changed() -> bool {
    selected(EFFECT_GRANT_CHANGED)
}

pub(super) fn effect_grant_readback_error() -> bool {
    selected(EFFECT_GRANT_READBACK_ERROR)
}

fn selected(expected: &str) -> bool {
    std::env::var_os(ENV).is_some_and(|value| value == expected)
}

#[cfg(test)]
mod tests {
    #[test]
    fn only_ten_exact_faults_exist() {
        assert_eq!(super::ENV, "BULLET_SYNTHETIC_DOGFOOD_FAULT");
        assert_eq!(super::AFTER_ACQUIRE, "after-acquire");
        assert_eq!(super::LANE_B_AFTER_ACQUIRE, "lane-b-after-acquire");
        assert_eq!(super::BEFORE_SELECTION, "before-selection");
        assert_eq!(super::BEFORE_RECEIPT, "before-receipt");
        assert_eq!(super::AFTER_RECEIPT, "after-receipt");
        assert_eq!(super::AFTER_DELIVERY_UNKNOWN, "after-delivery-unknown");
        assert_eq!(super::BEFORE_EFFECT_RECEIPT, "before-effect-receipt");
        assert_eq!(super::AFTER_EFFECT_RECEIPT, "after-effect-receipt");
        assert_eq!(super::EFFECT_GRANT_CHANGED, "effect-grant-changed");
        assert_eq!(
            super::EFFECT_GRANT_READBACK_ERROR,
            "effect-grant-readback-error"
        );
    }
}
