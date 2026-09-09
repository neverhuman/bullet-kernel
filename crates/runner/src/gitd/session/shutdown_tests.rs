//! Real owned child processes prove shutdown, independent of native providers.

use super::*;
use rustix::io::Errno;
use rustix::process::{kill_process, waitpid, Pid, Signal, WaitOptions};

fn daemon(response: &str) -> (GitdSession, Pid) {
    // Shell builtins only: after one response the child remains blocked on its
    // owned stdin. No grandchildren, environment configuration, or repository I/O.
    let mut child = Command::new("/bin/sh")
        .args([
            "-c",
            "IFS= read -r request || exit 91; printf '%s\\n' \"$1\"; IFS= read -r stop; exit 92",
            "bullet-gitd-shutdown-fixture",
            response,
        ])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn fake daemon");
    let pid = Pid::from_raw(child.id().expect("child pid") as i32).expect("positive pid");
    let stdin = child.stdin.take().expect("stdin");
    let stdout = BufReader::new(child.stdout.take().expect("stdout"));
    (
        GitdSession {
            _child: child,
            stdin,
            stdout,
            next_id: 0,
            token: json!({}),
        },
        pid,
    )
}

fn assert_reaped(session: &GitdSession, pid: Pid) {
    // Tokio has observed the exit AND the OS no longer has a waitable child.
    // Merely dropping a kill-on-drop handle cannot satisfy the first assertion.
    assert!(session._child.id().is_none());
    assert!(matches!(
        waitpid(Some(pid), WaitOptions::NOHANG),
        Err(Errno::CHILD)
    ));
}

#[tokio::test]
async fn owner_shutdown_reaps_successful_daemon() {
    let (mut session, pid) = daemon(r#"{"id":1,"ok":{"retained":true}}"#);
    let outcome = session.invoke("fixture", json!({})).await;
    assert!(session._child.try_wait().expect("child status").is_none());
    let retained = session.finish(outcome).await.expect("successful shutdown");
    assert_eq!(retained, json!({"retained": true}));
    assert_reaped(&session, pid);
}

#[tokio::test]
async fn owner_shutdown_reaps_refused_daemon() {
    for (response, reason) in [
        (
            r#"{"id":1,"err":{"code":"AUTHORITY_CONTRACT_UNAVAILABLE","message":"fixture refusal"}}"#,
            "AUTHORITY_CONTRACT_UNAVAILABLE",
        ),
        (
            r#"{"id":1,"err":{"code":"STALE_AUTHORITY","message":"fixture refusal"}}"#,
            "STALE_AUTHORITY",
        ),
        (r#"{"id":2,"ok":{}}"#, "PROTOCOL_ERROR"),
    ] {
        let (mut session, pid) = daemon(response);
        let outcome = session.invoke("fixture", json!({})).await;
        assert!(session._child.try_wait().expect("child status").is_none());
        let original = outcome.as_ref().expect_err("protocol refusal").to_string();
        let refused = session.finish(outcome).await.expect_err("retained refusal");
        assert_eq!(refused.reason_code(), reason);
        assert_eq!(refused.to_string(), original);
        assert_reaped(&session, pid);
    }
}

#[tokio::test]
async fn owner_shutdown_preserves_primary_when_wait_fails() {
    for failed_attempt in [false, true] {
        let (mut session, pid) = daemon(r#"{"id":1,"ok":{}}"#);
        session
            .invoke("fixture", json!({}))
            .await
            .expect("response");
        // Reap only this fixture-owned child outside Tokio to inject real ECHILD
        // into the owner's wait. No other process or process group is signalled.
        kill_process(pid, Signal::KILL).expect("kill owned fixture child");
        assert_eq!(
            waitpid(Some(pid), WaitOptions::empty()).unwrap().unwrap().0,
            pid
        );
        let outcome = if failed_attempt {
            Err(RunnerError::StaleAuthority(
                "original fixture refusal".into(),
            ))
        } else {
            Ok(())
        };
        let refused = session
            .finish(outcome)
            .await
            .expect_err("failed owner wait");
        if failed_attempt {
            assert_eq!(refused.reason_code(), "STALE_AUTHORITY");
            assert!(refused.is_stale());
            assert!(refused.is_frozen());
            assert!(refused.to_string().contains("original fixture refusal"));
            assert!(matches!(refused, RunnerError::Shutdown { .. }));
        } else {
            assert_eq!(refused.reason_code(), "IO_FAILED");
        }
        assert!(refused.to_string().contains("gitd wait"));
        assert!(matches!(
            waitpid(Some(pid), WaitOptions::NOHANG),
            Err(Errno::CHILD)
        ));
    }
}
