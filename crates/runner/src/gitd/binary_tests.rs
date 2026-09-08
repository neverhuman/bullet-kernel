    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn sha256(path: &Path) -> String {
        let mut file = File::open(path).expect("open fixture");
        sha256_reader(&mut file).expect("hash fixture")
    }

    async fn assert_refused_without_execution(
        result: Result<AdmittedGitdBinary, RunnerError>,
        marker: &Path,
        expected_code: &str,
    ) {
        match result {
            Err(error) => assert_eq!(error.reason_code(), expected_code),
            Ok(binary) => {
                let session = crate::gitd::GitdSession::spawn_with(
                    binary,
                    [marker.as_os_str()],
                    serde_json::json!({}),
                )
                .await;
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                if let Ok(mut session) = session {
                    let _ = session.kill().await;
                }
                assert!(!marker.exists(), "invalid daemon subject executed");
                panic!("invalid daemon subject was admitted");
            }
        }
        assert!(!marker.exists(), "refused daemon subject executed");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn invalid_subjects_never_execute_canary() {
        std::fs::create_dir_all("target").expect("target");
        let temp = tempfile::Builder::new()
            .prefix("gitd-admission.")
            .tempdir_in("target")
            .expect("tempdir");
        let executable = temp.path().join("gitd");
        std::fs::copy("/usr/bin/touch", &executable).expect("copy executable canary");
        let digest = sha256(&executable);
        let marker = temp.path().join("invalid-subject-ran");

        for result in [
            admit_configured("PATH_VAR", None, "DIGEST_VAR", None),
            admit_configured(
                "PATH_VAR",
                Some(OsString::new()),
                "DIGEST_VAR",
                Some(OsString::from(digest.clone())),
            ),
            admit_configured(
                "PATH_VAR",
                Some(executable.clone().into_os_string()),
                "DIGEST_VAR",
                None,
            ),
        ] {
            assert_refused_without_execution(result, &marker, "GITD_BINARY_UNPROVISIONED").await;
        }

        let relative = if executable.is_absolute() {
            executable
                .strip_prefix(std::env::current_dir().expect("cwd"))
                .expect("temp is beneath cwd")
                .to_path_buf()
        } else {
            executable.clone()
        };
        assert_refused_without_execution(
            admit_path(relative, digest.clone()),
            &marker,
            "GITD_BINARY_ADMISSION_REFUSED",
        )
        .await;

        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&executable, permissions).expect("permissions");
        assert_refused_without_execution(
            admit_path(executable.clone(), digest.clone()),
            &marker,
            "GITD_BINARY_ADMISSION_REFUSED",
        )
        .await;
        let mut permissions = std::fs::metadata(&executable)
            .expect("metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&executable, permissions).expect("permissions");

        let link = temp.path().join("gitd-link");
        symlink(&executable, &link).expect("symlink");
        for result in [
            admit_path(link, digest),
            admit_path(executable.clone(), "0".repeat(64)),
            admit_configured(
                "PATH_VAR",
                Some(executable.into_os_string()),
                "DIGEST_VAR",
                Some(OsString::from("A".repeat(64))),
            ),
        ] {
            assert_refused_without_execution(result, &marker, "GITD_BINARY_ADMISSION_REFUSED")
                .await;
        }

        let script = temp.path().join("gitd-script");
        std::fs::write(&script, b"#!/bin/sh\ntouch \"$1\"\n").expect("write script");
        let mut permissions = std::fs::metadata(&script)
            .expect("script metadata")
            .permissions();
        permissions.set_mode(0o700);
        std::fs::set_permissions(&script, permissions).expect("script permissions");
        let script_digest = sha256(&script);
        assert_refused_without_execution(
            admit_path(script, script_digest),
            &marker,
            "GITD_BINARY_ADMISSION_REFUSED",
        )
        .await;
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn sealed_image_survives_same_inode_overwrite() {
        let temp = tempfile::tempdir().expect("tempdir");
        let executable = temp.path().join("gitd");
        std::fs::copy("/usr/bin/touch", &executable).expect("copy touch");
        let digest = sha256(&executable);
        let admitted = admit_path(executable.clone(), digest).expect("admit touch inode");
        let before = std::fs::metadata(&executable).expect("before metadata");
        let mut replacement = vec![0_u8; usize::try_from(before.len()).expect("bounded length")];
        let false_bytes = std::fs::read("/bin/false").expect("read false");
        assert!(false_bytes.len() <= replacement.len());
        replacement[..false_bytes.len()].copy_from_slice(&false_bytes);
        std::fs::write(&executable, replacement).expect("overwrite same inode");
        let after = std::fs::metadata(&executable).expect("after metadata");
        assert_eq!(before.ino(), after.ino());
        assert_eq!(before.len(), after.len());
        assert_ne!(admitted.sha256(), sha256(&executable));

        let procfd = admitted.spawn_path().expect("sealed procfd");
        let write_attempt = std::fs::OpenOptions::new().write(true).open(&procfd);
        if let Ok(mut reopened) = write_attempt {
            assert!(
                reopened.write_all(b"x").is_err(),
                "sealed memfd was writable"
            );
        }
        let marker = temp.path().join("original-inode-ran");
        let mut session = crate::gitd::GitdSession::spawn_with(
            admitted,
            [marker.as_os_str()],
            serde_json::json!({}),
        )
        .await
        .expect("spawn sealed image");
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        assert!(marker.is_file(), "substituted pathname was executed");
        let _ = session.kill().await;
    }

    #[test]
    fn fixture_resolver_refuses_when_release_builds_disable_debug_authority() {
        let error = fixture_binary_for_build(false, None, None).unwrap_err();
        assert_eq!(error.reason_code(), "GITD_BINARY_ADMISSION_REFUSED");
    }
