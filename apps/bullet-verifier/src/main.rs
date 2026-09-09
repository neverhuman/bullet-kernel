//! Product verifier boundary. Verification remains unavailable until the
//! Kernel can admit a signed intent and an independently owned verifier.

const REFUSAL: &str = concat!(
    r#"{"reason_code":"VERIFICATION_INTENT_ADMISSION_UNAVAILABLE","message":""#,
    "signed verification-intent admission and independent verifier custody are unavailable",
    r#"","evidence_emitted":false}"#,
);

fn main() {
    eprintln!("{REFUSAL}");
    std::process::exit(2);
}
