//! Effect broker process. Timeouts become UNKNOWN, never success.

use bullet_effects_core::{dispatch, EffectIntent, EffectPhase, LocalBareForge};

fn main() {
    let mut forge = LocalBareForge::new();
    forge.timeout_next_push = true;
    let intent = EffectIntent {
        logical_key: "github:push:demo".into(),
        target: "refs/heads/bullet/candidate/demo".into(),
        expected: String::new(),
        desired: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
    };
    let first = dispatch(&mut forge, intent.clone()).expect("first");
    let second = dispatch(&mut forge, intent).expect("replay");
    println!(
        "bullet-effects: first={} replay={} writes={}",
        first.phase.as_str(),
        second.phase.as_str(),
        forge.write_count
    );
    if first.phase != EffectPhase::Verified
        || second.phase != EffectPhase::Verified
        || forge.write_count != 1
    {
        std::process::exit(1);
    }
}
