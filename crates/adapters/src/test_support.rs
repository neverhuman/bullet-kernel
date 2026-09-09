//! Test-only filesystem fixtures that satisfy production admission invariants.

pub(crate) fn private_tempdir() -> tempfile::TempDir {
    let mut builder = tempfile::Builder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        builder.permissions(std::fs::Permissions::from_mode(0o700));
    }
    builder.tempdir().expect("private tempdir")
}

pub(crate) fn sqlite_fixture(path: &std::path::Path) -> rusqlite::Connection {
    if !path.exists() {
        let mut options = std::fs::OpenOptions::new();
        options.read(true).write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        drop(options.open(path).expect("create private SQLite fixture"));
    }
    rusqlite::Connection::open(path).expect("open SQLite fixture")
}
