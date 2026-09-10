use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

fn private_temp() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[test]
fn bootstrap_file_is_create_only_private_and_refuses_malformed_or_linked_input() {
    let temp = private_temp();
    let path = temp.path().join("bootstrap.token");
    provision(&path).unwrap();
    let token = read(&path).unwrap();
    assert!(token.starts_with("boot_"));
    assert_eq!(token.len(), 69);
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(provision(&path).is_err());
    assert_eq!(read(&path).unwrap(), token);
    for mode in [0o400, 0o640, 0o644, 0o1600] {
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        assert!(read(&path).is_err());
    }
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    for bytes in [
        b"".to_vec(),
        b"secret-malformed".to_vec(),
        vec![255],
        format!("{token}\nextra").into_bytes(),
        format!("{token}\r\n").into_bytes(),
        format!("{token}\n{token}").into_bytes(),
    ] {
        std::fs::write(&path, bytes).unwrap();
        let error = read(&path).unwrap_err();
        assert!(error.starts_with("BOOTSTRAP_"));
        assert!(!error.contains(&token));
        assert!(!error.contains("secret-malformed"));
    }
    std::fs::write(&path, format!("{token}\n")).unwrap();
    assert_eq!(read(&path).unwrap(), token);
    let link = temp.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(read(&link).is_err());
    assert!(provision(&link).is_err());
    let hard = temp.path().join("hard");
    std::fs::hard_link(&path, &hard).unwrap();
    assert!(read(&hard).is_err());
    assert!(read(&path).is_err());
    assert!(read(temp.path()).is_err());
    assert!(read(Path::new("relative.token")).is_err());
}

#[test]
fn bootstrap_parent_custody_rejects_symlinks_public_modes_and_displacement() {
    let temp = private_temp();
    let directory = temp.path().join("custody");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join("bootstrap.token");
    provision(&path).unwrap();
    let link = temp.path().join("linked-parent");
    symlink(&directory, &link).unwrap();
    assert!(read(&link.join("bootstrap.token")).is_err());
    assert!(provision(&link.join("new.token")).is_err());
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(read(&path).is_err());
    assert!(provision(&directory.join("new.token")).is_err());
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let (opened, _) = parent(&path).unwrap();
    std::fs::rename(&directory, temp.path().join("moved")).unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(same_parent(&path, &opened)
        .unwrap_err()
        .contains("DIRECTORY_CHANGED"));
    assert!(!directory.join("new.token").exists());
}
