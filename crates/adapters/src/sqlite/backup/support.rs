fn require_absent(path: &Path) -> Result<(), SqliteMaintenanceError> {
    match std::fs::symlink_metadata(path) {
        Ok(_) => Err(SqliteMaintenanceError::DestinationExists(
            path.to_path_buf(),
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(phase("OPEN", error)),
    }
}

fn require_unix() -> Result<(), SqliteMaintenanceError> {
    if cfg!(unix) {
        Ok(())
    } else {
        Err(SqliteMaintenanceError::UnsupportedPlatform)
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn schema_error(error: impl ToString) -> SqliteMaintenanceError {
    phase("VERIFY", error)
}

fn receipt_mismatch(detail: impl Into<String>) -> SqliteMaintenanceError {
    SqliteMaintenanceError::ReceiptMismatch(detail.into())
}

fn phase(phase: &'static str, detail: impl ToString) -> SqliteMaintenanceError {
    SqliteMaintenanceError::Operation {
        phase,
        detail: detail.to_string(),
    }
}

fn fail(
    selected: Option<FaultPoint>,
    point: FaultPoint,
    phase_name: &'static str,
) -> Result<(), SqliteMaintenanceError> {
    if selected == Some(point) {
        Err(phase(phase_name, "injected maintenance failure"))
    } else {
        Ok(())
    }
}
