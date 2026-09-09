use super::*;
use std::os::unix::fs::PermissionsExt;

fn guard(script: &str) -> ProcessGuard {
    let child = Command::new("/bin/sh")
        .args(["-c", script])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .process_group(0)
        .spawn()
        .unwrap();
    ProcessGuard::new(child)
}

#[test]
fn nonzero_and_bounded_output_are_retained_without_green_paint() {
    enable_subreaper().unwrap();
    let output = guard("printf out; printf err >&2; exit 7")
        .wait_with_output(Duration::from_secs(2))
        .unwrap();
    assert_eq!(output.status.code(), Some(7));
    assert_eq!(output.stdout, b"out");
    assert_eq!(output.stderr, b"err");
}

#[test]
fn timeout_kills_and_reaps_the_whole_process_group() {
    enable_subreaper().unwrap();
    let error = guard("sleep 30 & wait")
        .wait_with_output(Duration::from_millis(30))
        .unwrap_err();
    assert_eq!(error.code(), "COMMAND_CHILD_TIMEOUT");
}

#[test]
fn output_cap_is_a_typed_refusal() {
    enable_subreaper().unwrap();
    let script = format!("head -c {} /dev/zero", OUTPUT_LIMIT + 1);
    let error = guard(&script)
        .wait_with_output(Duration::from_secs(2))
        .unwrap_err();
    assert_eq!(error.code(), "COMMAND_CHILD_OUTPUT_LIMIT");
}

#[test]
fn preexisting_child_data_or_artifacts_refuse_before_spawn() {
    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().canonicalize().unwrap();
    let receipt = root.join("COMPONENT_PROOF.receipt.json");
    std::fs::create_dir(root.join("data")).unwrap();
    assert_eq!(
        validate_child_roots(&root, &receipt).unwrap_err().code(),
        "COMMAND_CHILD_ROOT_INVALID"
    );
}

#[test]
fn dangling_child_root_symlink_is_not_treated_as_absent() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().unwrap();
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = temp.path().canonicalize().unwrap();
    let receipt = root.join("COMPONENT_PROOF.receipt.json");
    symlink(root.join("missing-outside"), root.join("artifacts")).unwrap();
    assert_eq!(
        validate_child_roots(&root, &receipt).unwrap_err().code(),
        "COMMAND_CHILD_ROOT_INVALID"
    );
}
