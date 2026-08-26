//! Binary round-trip: the broker demo runs a real bare-repo flow and
//! reports honest states.

use bullet_effects_core::{DurableJob, DurableQueue, EffectsError};
use std::fs;
use std::path::Path;
use std::process::Command;

fn write_private_fixture(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("write hostile queue fixture");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("make hostile queue fixture private");
    }
}

#[test]
fn broker_demo_commits_and_reconciles_honestly() {
    let out = Command::new(env!("CARGO_BIN_EXE_bullet-effects"))
        .output()
        .expect("run bullet-effects");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let summary: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("stdout is one JSON summary");
    assert_eq!(summary["first"], "COMMITTED");
    assert_eq!(summary["created"], true);
    assert_eq!(summary["replay_created"], false);
    assert_eq!(summary["read_back_matches"], true);
    assert_eq!(summary["after_lost_response"], "OUTCOME_UNKNOWN");
    assert_eq!(summary["reconcile"], "Retried(Committed)");
    assert_eq!(summary["lost_intent_settled"], "COMMITTED");

    let scratch = tempfile::tempdir().expect("queue root");
    let queue_root = scratch.path().join("queue");
    let queue = DurableQueue::open(&queue_root).expect("open queue");
    let job = DurableJob {
        id: "effect-demo-1".into(),
        provider: "local-bare".into(),
        logical_effect_key: "candidate-ref/demo".into(),
        target_ref: "refs/bullet/candidates/demo".into(),
        new_oid: "1".repeat(40),
        expected_old_oid: "0".repeat(40),
        state: "PENDING".into(),
    };
    assert!(queue.enqueue(&job).expect("enqueue"));
    assert!(!queue.enqueue(&job).expect("idempotent replay"));
    let mut conflicting = job.clone();
    conflicting.new_oid = "2".repeat(40);
    let conflict = queue.enqueue(&conflicting).expect_err("conflict refused");
    assert!(matches!(&conflict, EffectsError::DurableQueueInvalid(_)));
    assert_eq!(conflict.reason_code(), "DURABLE_QUEUE_INVALID");
    let pending = queue.take_pending().expect("take pending").expect("job");
    queue.mark_unknown(pending.clone()).expect("mark unknown");
    queue
        .mark_unknown(pending)
        .expect("idempotent unknown transition after restart boundary");
    drop(queue);
    let queue = DurableQueue::open(&queue_root).expect("reopen durable queue");
    let unknown = queue.take_unknown().expect("take unknown").expect("job");
    assert!(matches!(
        queue.mark_settled(unknown.clone(), "PASS"),
        Err(EffectsError::DurableQueueInvalid(_))
    ));

    let out = Command::new(env!("CARGO_BIN_EXE_bullet-effects"))
        .arg("serve")
        .arg(&queue_root)
        .output()
        .expect("serve durable queue");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let daemon: serde_json::Value = serde_json::from_slice(&out.stdout).expect("daemon summary");
    assert_eq!(daemon["processed_job_id"], job.id);
    assert_eq!(daemon["disposition"], "QUARANTINED");
    assert_eq!(daemon["live_forge_success"], false);
    assert!(queue.take_unknown().expect("unknown queue").is_none());
    let settled: DurableJob = serde_json::from_slice(
        &fs::read(queue_root.join("settled/effect-demo-1.json")).expect("settled record"),
    )
    .expect("decode settled record");
    assert_eq!(settled.state, "QUARANTINED");

    let empty = Command::new(env!("CARGO_BIN_EXE_bullet-effects"))
        .arg("serve")
        .arg(&queue_root)
        .output()
        .expect("serve empty queue");
    let empty_summary: serde_json::Value =
        serde_json::from_slice(&empty.stdout).expect("empty daemon summary");
    assert_eq!(empty_summary["processed_job_id"], serde_json::Value::Null);
    assert_eq!(empty_summary["disposition"], "NO_WORK");

    let extra_arg = Command::new(env!("CARGO_BIN_EXE_bullet-effects"))
        .args([
            "serve",
            queue_root.to_str().expect("UTF-8 queue path"),
            "extra",
        ])
        .output()
        .expect("run invalid serve invocation");
    assert!(!extra_arg.status.success());

    let unsafe_job = DurableJob {
        id: "../escape".into(),
        ..job.clone()
    };
    assert!(matches!(
        queue.enqueue(&unsafe_job),
        Err(EffectsError::DurableQueueInvalid(_))
    ));

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let outside = scratch.path().join("outside.json");
        fs::write(&outside, b"{}\n").expect("outside sentinel");
        symlink(&outside, queue_root.join("unknown/hostile.json")).expect("queue symlink");
        assert!(matches!(
            queue.take_unknown(),
            Err(EffectsError::DurableQueueInvalid(_))
        ));
        assert_eq!(fs::read(&outside).expect("outside unchanged"), b"{}\n");
    }

    let corrupt_root = scratch.path().join("corrupt-queue");
    let corrupt = DurableQueue::open(&corrupt_root).expect("open corrupt queue");
    write_private_fixture(&corrupt_root.join("unknown/corrupt.json"), b"{not-json}\n");
    assert!(matches!(
        corrupt.take_unknown(),
        Err(EffectsError::DurableQueueInvalid(_))
    ));

    let oversized_root = scratch.path().join("oversized-queue");
    let oversized = DurableQueue::open(&oversized_root).expect("open oversized queue");
    write_private_fixture(
        &oversized_root.join("unknown/oversized.json"),
        &vec![b'x'; 64 * 1024 + 1],
    );
    assert!(matches!(
        oversized.take_unknown(),
        Err(EffectsError::DurableQueueInvalid(_))
    ));

    let ambiguous_root = scratch.path().join("ambiguous-queue");
    let ambiguous = DurableQueue::open(&ambiguous_root).expect("open ambiguous queue");
    assert!(ambiguous.enqueue(&job).expect("enqueue ambiguous source"));
    let mut unknown_copy = job.clone();
    unknown_copy.state = "OUTCOME_UNKNOWN".into();
    write_private_fixture(
        &ambiguous_root.join("unknown/effect-demo-1.json"),
        &serde_json::to_vec(&unknown_copy).expect("encode ambiguous destination"),
    );
    assert!(matches!(
        ambiguous.take_pending(),
        Err(EffectsError::DurableQueueInvalid(_))
    ));
    assert!(ambiguous_root.join("pending/effect-demo-1.json").is_file());
}
