//! Configuration generations (spec §49.2, Gastown E10/R33): content-addressed
//! generation records and the activation ledger that refuses partial
//! activation, stale or duplicate acknowledgements, tampered digests, and
//! regression, binds an Attempt only to a fully acknowledged generation, and
//! offers abort as the only typed exit from a stuck activation.

use bullet_application::policy_snapshot::Component::{Effects, Kernel, Runner, Verifier};
use bullet_application::policy_snapshot::{
    AbortRecord, ActivationLedger, ActivationState, Component, ConfigurationGeneration,
    GenerationContent, GenerationError, RecordedGeneration, CONFIGURATION_GENERATION_DOMAIN,
    MAX_ACTIVATION_SUBJECT_BYTES,
};
use bullet_harness_core::launch_grant::{hash_canonical, MAX_SAFE_INTEGER};
use std::collections::BTreeSet;
use std::fmt::Debug;

const POLICY_DIGEST: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ROUTING_DIGEST: &str = "2222222222222222222222222222222222222222222222222222222222222222";
const OTHER_DIGEST: &str = "3333333333333333333333333333333333333333333333333333333333333333";
const CREATED_AT: u64 = 1_800_000_000_000;
const AT: u64 = CREATED_AT + 5_000;
const ACTIVATING: ActivationState = ActivationState::Activating;
const ACTIVE: ActivationState = ActivationState::Active;

type Outcome = Result<ActivationState, GenerationError>;
fn required() -> BTreeSet<Component> {
    Component::ALL.into_iter().collect()
}
fn content(generation: u64) -> GenerationContent {
    GenerationContent {
        generation,
        policy_digest: POLICY_DIGEST.to_string(),
        routing_digest: ROUTING_DIGEST.to_string(),
        activation_subject: "operator:alice".to_string(),
        created_at_unix_ms: CREATED_AT,
        required_components: required(),
    }
}
fn sealed(generation: u64) -> ConfigurationGeneration {
    ConfigurationGeneration::seal(content(generation)).unwrap()
}
fn row(generation: u64) -> RecordedGeneration {
    sealed(generation).recorded()
}
fn activate(
    ledger: &mut ActivationLedger,
    generation: &ConfigurationGeneration,
    at: u64,
) -> Outcome {
    ledger.activate(generation.recorded(), at)
}
fn ack(
    ledger: &mut ActivationLedger,
    component: Component,
    g: &ConfigurationGeneration,
) -> Outcome {
    ledger.acknowledge(component, g.number(), g.digest())
}

/// Activate `generation` and collect every required acknowledgement.
fn fully_active(ledger: &mut ActivationLedger, generation: u64) -> ConfigurationGeneration {
    let sealed = sealed(generation);
    let at = ledger.activated_at_unix_ms().map_or(AT, |at| at + 1);
    assert_eq!(activate(ledger, &sealed, at).unwrap(), ACTIVATING);
    for component in required() {
        ack(ledger, component, &sealed).unwrap();
    }
    assert_eq!(ledger.state(), Some(ACTIVE));
    sealed
}

fn admission(ledger: &ActivationLedger) -> Result<&ConfigurationGeneration, GenerationError> {
    ledger.generation_for_admission()
}

fn refusal<T: Debug>(result: Result<T, GenerationError>) -> GenerationError {
    result.expect_err("typed refusal")
}

fn refuses<T: Debug>(result: Result<T, GenerationError>, expected: &str) {
    assert_eq!(refusal(result).reason_code(), expected);
}

#[test]
fn a_sealed_generation_is_content_addressed_and_immutable() {
    let generation = sealed(7);
    let expected = hash_canonical(CONFIGURATION_GENERATION_DOMAIN, &content(7)).unwrap();
    assert_eq!(generation.digest(), expected);
    assert_eq!(generation.number(), 7);
    assert_eq!(generation.content(), &content(7));
    let binding = generation.binding();
    assert_eq!(binding.generation, 7);
    assert_eq!(binding.generation_digest, expected);
    assert_eq!(binding.policy_digest, POLICY_DIGEST);
    assert_eq!(binding.routing_digest, ROUTING_DIGEST);

    let reordered = GenerationContent {
        required_components: [Effects, Verifier, Runner, Kernel].into_iter().collect(),
        ..content(7)
    };
    assert_eq!(
        ConfigurationGeneration::seal(reordered).unwrap().digest(),
        expected,
        "component order never changes the address"
    );
    let mut changed = content(7);
    changed.routing_digest = OTHER_DIGEST.to_string();
    assert_ne!(
        ConfigurationGeneration::seal(changed).unwrap().digest(),
        expected
    );
    let mut later = content(7);
    later.created_at_unix_ms += 1;
    assert_ne!(
        ConfigurationGeneration::seal(later).unwrap().digest(),
        expected
    );
    let round_trip = ConfigurationGeneration::from_recorded(generation.recorded()).unwrap();
    assert_eq!(round_trip, generation);
}

#[test]
fn invalid_content_is_refused_before_it_is_addressed() {
    type Break = fn(&mut GenerationContent);
    let cases: [(&str, Break); 10] = [
        ("zero_generation", |c| c.generation = 0),
        ("unsafe_generation", |c| c.generation = MAX_SAFE_INTEGER + 1),
        ("short_policy_digest", |c| c.policy_digest.truncate(63)),
        ("upper_routing_digest", |c| {
            c.routing_digest = ROUTING_DIGEST.to_uppercase().replace('2', "A");
        }),
        ("empty_subject", |c| c.activation_subject.clear()),
        ("spaced_subject", |c| {
            c.activation_subject = "operator alice".to_string()
        }),
        ("long_subject", |c| {
            c.activation_subject = "a".repeat(MAX_ACTIVATION_SUBJECT_BYTES + 1);
        }),
        ("unsafe_instant", |c| {
            c.created_at_unix_ms = MAX_SAFE_INTEGER + 1
        }),
        ("no_components", |c| c.required_components.clear()),
        ("missing_effects", |c| {
            c.required_components.remove(&Effects);
        }),
    ];
    for (name, damage) in cases {
        let mut broken = content(1);
        damage(&mut broken);
        let error = ConfigurationGeneration::seal(broken).unwrap_err();
        assert_eq!(error.reason_code(), "GENERATION_CONTENT_INVALID", "{name}");
    }
    let longest = GenerationContent {
        activation_subject: "a".repeat(MAX_ACTIVATION_SUBJECT_BYTES),
        ..content(1)
    };
    ConfigurationGeneration::seal(longest).unwrap();
}

#[test]
fn a_row_whose_digest_disagrees_with_its_content_never_activates() {
    let mut ledger = ActivationLedger::default();
    let mut tampered = row(1);
    tampered.content.policy_digest = OTHER_DIGEST.to_string();
    let error = refusal(ledger.activate(tampered.clone(), AT));
    assert_eq!(error.reason_code(), "GENERATION_DIGEST_MISMATCH");
    assert!(error.to_string().contains(&tampered.digest), "{error}");
    assert_eq!(ledger.state(), None);
    assert_eq!(ledger.highest_generation(), 0);
    refuses(admission(&ledger), "NO_ACTIVE_GENERATION");
    let mut forged_digest = row(1);
    forged_digest.digest = OTHER_DIGEST.to_string();
    refuses(
        ConfigurationGeneration::from_recorded(forged_digest),
        "GENERATION_DIGEST_MISMATCH",
    );
    let mut invalid_content = row(1);
    invalid_content.content.generation = 0;
    refuses(
        ledger.activate(invalid_content, AT),
        "GENERATION_CONTENT_INVALID",
    );
    for at in [CREATED_AT - 1, MAX_SAFE_INTEGER + 1] {
        refuses(ledger.activate(row(1), at), "GENERATION_CONTENT_INVALID");
    }
    assert_eq!(ledger, ActivationLedger::default());
}

#[test]
fn partial_acknowledgement_never_admits_an_attempt() {
    let mut ledger = ActivationLedger::default();
    let one = sealed(1);
    assert_eq!(activate(&mut ledger, &one, AT).unwrap(), ACTIVATING);
    assert_eq!(ledger.activated_at_unix_ms(), Some(AT));
    assert_eq!(ledger.current(), Some(&one));
    assert_eq!(ledger.missing_components(), required());

    let refused = refusal(admission(&ledger));
    assert_eq!(refused.reason_code(), "GENERATION_ACTIVATING");
    assert!(
        refused
            .to_string()
            .contains("kernel,runner,verifier,effects"),
        "{refused}"
    );

    assert_eq!(ack(&mut ledger, Kernel, &one).unwrap(), ACTIVATING);
    assert_eq!(ack(&mut ledger, Runner, &one).unwrap(), ACTIVATING);
    let refused = refusal(admission(&ledger));
    assert_eq!(refused.reason_code(), "GENERATION_ACTIVATING");
    assert!(
        refused.to_string().contains("missing verifier"),
        "{refused}"
    );
    assert_eq!(ledger.state(), Some(ACTIVATING));
    assert_eq!(ledger.last_known_good(), None);

    assert_eq!(ack(&mut ledger, Verifier, &one).unwrap(), ACTIVATING);
    assert_eq!(ack(&mut ledger, Effects, &one).unwrap(), ACTIVE);
    let admitted = admission(&ledger).unwrap();
    assert_eq!(admitted, &one);
    assert_eq!(admitted.binding(), one.binding());
    assert!(ledger.missing_components().is_empty());
}

#[test]
fn duplicate_unknown_stale_and_premature_acknowledgements_are_typed_refusals() {
    let mut ledger = ActivationLedger::default();
    let one = sealed(1);
    refuses(ack(&mut ledger, Kernel, &one), "NO_ACTIVATION_PENDING");

    activate(&mut ledger, &one, AT).unwrap();
    ack(&mut ledger, Kernel, &one).unwrap();
    let duplicate = refusal(ack(&mut ledger, Kernel, &one));
    assert_eq!(duplicate.reason_code(), "DUPLICATE_ACKNOWLEDGEMENT");
    assert!(duplicate.to_string().contains("kernel"), "{duplicate}");
    assert_eq!(ack(&mut ledger, Effects, &one).unwrap(), ACTIVATING);

    let wrong_number = ledger.acknowledge(Runner, 2, one.digest());
    refuses(wrong_number, "ACKNOWLEDGEMENT_TARGET_MISMATCH");
    let wrong_digest = refusal(ledger.acknowledge(Runner, 1, OTHER_DIGEST));
    assert_eq!(
        wrong_digest.reason_code(),
        "ACKNOWLEDGEMENT_TARGET_MISMATCH"
    );
    assert!(
        wrong_digest.to_string().contains(one.digest()),
        "{wrong_digest}"
    );

    let mut expected = required();
    expected.remove(&Kernel);
    expected.remove(&Effects);
    assert_eq!(
        ledger.missing_components(),
        expected,
        "refusals never count as acknowledgement"
    );
    refuses(admission(&ledger), "GENERATION_ACTIVATING");
}

#[test]
fn an_active_generation_still_refuses_repeat_and_foreign_acknowledgements() {
    let mut ledger = ActivationLedger::default();
    let one = fully_active(&mut ledger, 1);
    refuses(ack(&mut ledger, Kernel, &one), "DUPLICATE_ACKNOWLEDGEMENT");
    refuses(ack(&mut ledger, Effects, &one), "DUPLICATE_ACKNOWLEDGEMENT");
    assert_eq!(ledger.state(), Some(ACTIVE));
    assert_eq!(admission(&ledger).unwrap(), &one);
}

#[test]
fn generations_never_go_backwards_or_repeat() {
    let mut ledger = ActivationLedger::default();
    let five = fully_active(&mut ledger, 5);
    assert_eq!(ledger.highest_generation(), 5);

    for older in [1, 4] {
        let error = refusal(ledger.activate(row(older), AT + 1));
        assert_eq!(
            error.reason_code(),
            "GENERATION_REGRESSION",
            "generation {older}"
        );
        assert!(error.to_string().contains("past generation 5"), "{error}");
    }
    let mut same_number_other_content = content(5);
    same_number_other_content.routing_digest = OTHER_DIGEST.to_string();
    let same = ConfigurationGeneration::seal(same_number_other_content).unwrap();
    assert_ne!(same.digest(), five.digest());
    refuses(
        activate(&mut ledger, &same, AT + 1),
        "GENERATION_REGRESSION",
    );
    assert_eq!(
        refusal(activate(&mut ledger, &five, AT + 1)).reason_code(),
        "GENERATION_REGRESSION",
        "re-activating the active generation is not an advance"
    );
    assert_eq!(admission(&ledger).unwrap(), &five);
    assert_eq!(ledger.last_known_good(), None);
    assert_eq!(ledger.highest_generation(), 5);
}

#[test]
fn activation_supersedes_the_active_generation_and_retains_last_known_good() {
    let mut ledger = ActivationLedger::default();
    let one = fully_active(&mut ledger, 1);
    let two = sealed(2);
    refuses(
        activate(&mut ledger, &two, AT - 1),
        "GENERATION_CONTENT_INVALID",
    );
    assert_eq!(admission(&ledger).unwrap(), &one);
    assert_eq!(activate(&mut ledger, &two, AT + 10).unwrap(), ACTIVATING);
    assert_eq!(ledger.last_known_good(), Some(&one));
    assert_eq!(ledger.current(), Some(&two));
    let refused = refusal(admission(&ledger));
    assert_eq!(
        refused.reason_code(),
        "GENERATION_ACTIVATING",
        "last-known-good is retained, never admitted silently"
    );
    assert!(refused.to_string().contains("generation 2"), "{refused}");

    let in_progress = refusal(ledger.activate(row(3), AT + 20));
    assert_eq!(in_progress.reason_code(), "ACTIVATION_IN_PROGRESS");
    assert!(
        in_progress.to_string().contains("generation 2"),
        "{in_progress}"
    );
    assert_eq!(ledger.highest_generation(), 2);
    assert_eq!(
        refusal(ack(&mut ledger, Kernel, &one)).reason_code(),
        "ACKNOWLEDGEMENT_TARGET_MISMATCH",
        "acknowledging the superseded generation is stale"
    );

    for component in required() {
        ack(&mut ledger, component, &two).unwrap();
    }
    assert_eq!(admission(&ledger).unwrap(), &two);
    assert_eq!(ledger.last_known_good(), Some(&one));
    let three = fully_active(&mut ledger, 3);
    assert_eq!(ledger.last_known_good(), Some(&two));
    assert_eq!(admission(&ledger).unwrap(), &three);
}

#[test]
fn the_ledger_round_trips_without_changing_admission() {
    let mut ledger = ActivationLedger::default();
    fully_active(&mut ledger, 1);
    let two = sealed(2);
    activate(&mut ledger, &two, AT + 1).unwrap();
    ack(&mut ledger, Kernel, &two).unwrap();
    let encoded = serde_json::to_vec(&ledger).unwrap();
    let decoded: ActivationLedger = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(decoded, ledger);
    refuses(admission(&decoded), "GENERATION_ACTIVATING");
    let mut missing = required();
    missing.remove(&Kernel);
    assert_eq!(decoded.missing_components(), missing);

    let mut aborted = decoded.clone();
    aborted.abort_activation("operator:bob", AT + 2).unwrap();
    let reencoded: ActivationLedger =
        serde_json::from_slice(&serde_json::to_vec(&aborted).unwrap()).unwrap();
    assert_eq!(reencoded, aborted);
    assert_eq!(reencoded.abort_history().len(), 1);
    assert_eq!(admission(&reencoded).unwrap().number(), 1);
}

#[test]
fn abort_during_partial_acknowledgement_restores_last_known_good_exactly() {
    let mut ledger = ActivationLedger::default();
    let one = fully_active(&mut ledger, 1);
    let two = sealed(2);
    activate(&mut ledger, &two, AT + 10).unwrap();
    ack(&mut ledger, Kernel, &two).unwrap();
    refuses(admission(&ledger), "GENERATION_ACTIVATING");

    let record = ledger.abort_activation("operator:bob", AT + 20).unwrap();
    let expected = AbortRecord {
        aborted_generation: 2,
        aborted_digest: two.digest().to_string(),
        acknowledged_components: [Kernel].into_iter().collect(),
        subject: "operator:bob".to_string(),
        aborted_at_unix_ms: AT + 20,
    };
    assert_eq!(record, expected);
    assert_eq!(ledger.abort_history(), std::slice::from_ref(&expected));
    assert_eq!(admission(&ledger).unwrap(), &one);
    assert_eq!(ledger.state(), Some(ACTIVE));
    assert_eq!(
        ledger.activated_at_unix_ms(),
        Some(AT),
        "the retained activation is restored, not re-marked"
    );
    assert!(ledger.missing_components().is_empty());
    assert_eq!(ledger.last_known_good(), None);
    assert_eq!(
        ledger.highest_generation(),
        2,
        "the aborted number stays used"
    );

    refuses(
        activate(&mut ledger, &two, AT + 30),
        "GENERATION_REGRESSION",
    );
    let mut same_number = content(2);
    same_number.routing_digest = OTHER_DIGEST.to_string();
    let same_number = ConfigurationGeneration::seal(same_number).unwrap();
    refuses(
        activate(&mut ledger, &same_number, AT + 30),
        "GENERATION_REGRESSION",
    );
    assert_eq!(
        refusal(ack(&mut ledger, Runner, &two)).reason_code(),
        "ACKNOWLEDGEMENT_TARGET_MISMATCH",
        "the aborted generation never collects late acknowledgements"
    );
    assert_eq!(admission(&ledger).unwrap(), &one);

    let three = fully_active(&mut ledger, 3);
    assert_eq!(admission(&ledger).unwrap(), &three);
    assert_eq!(ledger.last_known_good(), Some(&one));
    assert_eq!(
        ledger.abort_history(),
        std::slice::from_ref(&expected),
        "history is append-only and untouched by later activation"
    );
}

#[test]
fn abort_without_a_prior_active_generation_admits_nothing() {
    let mut ledger = ActivationLedger::default();
    let one = sealed(1);
    activate(&mut ledger, &one, AT).unwrap();
    let first = ledger.abort_activation("operator:bob", AT + 1).unwrap();
    assert_eq!(first.aborted_generation, 1);
    assert_eq!(first.aborted_digest, one.digest());
    assert!(first.acknowledged_components.is_empty());
    assert_eq!(
        refusal(admission(&ledger)).reason_code(),
        "NO_ACTIVE_GENERATION",
        "the aborted generation is never admitted"
    );
    assert_eq!(ledger.state(), None);
    assert_eq!(ledger.current(), None);
    assert_eq!(ledger.last_known_good(), None);
    assert_eq!(ledger.highest_generation(), 1);
    refuses(ledger.activate(row(1), AT + 2), "GENERATION_REGRESSION");
    assert_eq!(ledger.activate(row(2), AT + 2).unwrap(), ACTIVATING);
    assert_eq!(ledger.abort_history(), std::slice::from_ref(&first));
    let second = ledger.abort_activation("operator:carol", AT + 3).unwrap();
    assert_eq!(second.aborted_generation, 2);
    assert_eq!(ledger.abort_history(), &[first, second]);
    refuses(admission(&ledger), "NO_ACTIVE_GENERATION");
}

#[test]
fn abort_is_refused_unless_a_generation_is_activating() {
    let mut ledger = ActivationLedger::default();
    refuses(
        ledger.abort_activation("operator:bob", AT),
        "NO_ACTIVATION_PENDING",
    );

    let one = fully_active(&mut ledger, 1);
    let before = ledger.clone();
    assert_eq!(
        refusal(ledger.abort_activation("operator:bob", AT + 1)).reason_code(),
        "NO_ACTIVATION_PENDING",
        "an active generation is not aborted"
    );
    assert_eq!(ledger, before);
    assert!(ledger.abort_history().is_empty());
    assert_eq!(admission(&ledger).unwrap(), &one);

    ledger.activate(row(2), AT + 2).unwrap();
    let before = ledger.clone();
    for (subject, at) in [
        ("", AT + 3),
        ("operator bob", AT + 3),
        ("operator:bob", AT + 1),
        ("operator:bob", MAX_SAFE_INTEGER + 1),
    ] {
        assert_eq!(
            refusal(ledger.abort_activation(subject, at)).reason_code(),
            "GENERATION_CONTENT_INVALID",
            "{subject:?} at {at}"
        );
    }
    assert_eq!(ledger, before, "invalid abort requests change nothing");
    assert_eq!(ledger.state(), Some(ACTIVATING));
}
