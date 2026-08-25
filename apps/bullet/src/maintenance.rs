//! Thin offline CLI boundary for receipt-bound SQLite maintenance.

use bullet_adapters::{create_backup, restore_backup, BackupReceipt};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::Path;

const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

pub(super) fn backup(database: &Path, output: &Path, receipt_path: &Path) -> Result<(), String> {
    let receipt = create_backup(database, output).map_err(|error| error.to_string())?;
    let bytes = serde_json::to_vec_pretty(&receipt).map_err(|error| error.to_string())?;
    write_new_synced(receipt_path, &bytes)?;
    println!(
        "{}",
        String::from_utf8(bytes).map_err(|error| error.to_string())?
    );
    Ok(())
}

pub(super) fn restore(
    backup_path: &Path,
    receipt_path: &Path,
    destination: &Path,
) -> Result<(), String> {
    let bytes = read_regular_bounded(receipt_path)?;
    let receipt: BackupReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid backup receipt: {error}"))?;
    let restored =
        restore_backup(backup_path, &receipt, destination).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::to_string_pretty(&restored).map_err(|error| error.to_string())?
    );
    eprintln!(
        "bullet: restored database is quarantined; production authority admission is unavailable"
    );
    Ok(())
}

fn write_new_synced(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let mut output = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|error| format!("create receipt without replacement: {error}"))?;
    output
        .write_all(bytes)
        .and_then(|()| output.sync_all())
        .map_err(|error| format!("write and sync receipt: {error}"))?;
    let parent = path
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("sync receipt directory: {error}"))
}

#[cfg(unix)]
fn read_regular_bounded(path: &Path) -> Result<Vec<u8>, String> {
    use std::os::unix::fs::OpenOptionsExt;
    let input = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|error| format!("open receipt without following symlinks: {error}"))?;
    if !input
        .metadata()
        .map_err(|error| format!("inspect receipt: {error}"))?
        .is_file()
    {
        return Err("receipt is not a regular file".into());
    }
    let mut bytes = Vec::new();
    input
        .take(MAX_RECEIPT_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("read receipt: {error}"))?;
    if u64::try_from(bytes.len()).map_err(|error| error.to_string())? > MAX_RECEIPT_BYTES {
        return Err("receipt exceeds 16384 bytes".into());
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_regular_bounded(_path: &Path) -> Result<Vec<u8>, String> {
    Err("safe receipt admission is unsupported on this platform".into())
}
