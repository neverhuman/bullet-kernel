//! Cooperative serving custody on the admitted, retained main-file descriptor.
//!
//! This supports in-place maintenance exclusion on the ext filesystem family.
//! It does not serialize generation replacement or uncooperative SQLite clients.
//! SQLite's own connections use separate descriptors; their close must not
//! release this Linux flock. Guard retains the owning descriptor until close.

use super::store;
use bullet_application::LedgerError;
use rustix::fs::{flock, fstatfs, FlockOperation};
use std::fs::File;

#[cfg(test)]
pub(super) mod tests;

pub(super) fn acquire_shared(database: &File) -> Result<(), LedgerError> {
    #[cfg(test)]
    tests::before_shared(database);
    verify_filesystem(i128::from(fstatfs(database).map_err(store)?.f_type))?;
    match flock(database, FlockOperation::NonBlockingLockShared) {
        Ok(()) => Ok(()),
        Err(error) if error == rustix::io::Errno::WOULDBLOCK => Err(store(
            "SQLITE_CUSTODY_BUSY: admitted database has exclusive maintenance custody",
        )),
        Err(error) => Err(store(format!("SQLITE_CUSTODY_REFUSED: {error}"))),
    }
}

fn verify_filesystem(kind: i128) -> Result<(), LedgerError> {
    // ext2/ext3/ext4 share this magic. Remote, userspace and stacked filesystems
    // require separate implementation support because flock semantics differ.
    if kind != 0xef53 {
        return Err(store(format!(
            "SQLITE_CUSTODY_FILESYSTEM_UNSUPPORTED: filesystem {kind:#x}; serving custody supports the ext filesystem family"
        )));
    }
    Ok(())
}
