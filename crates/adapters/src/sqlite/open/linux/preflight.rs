//! Inspect a private snapshot before SQLite can recover or checkpoint source files.

use super::{admit_file, open_optional, parent, revalidate, sidecar_name, store, Guard};
use crate::sqlite::migrations;
use bullet_application::LedgerError;
use rusqlite::{Connection, OpenFlags};
use std::ffi::OsString;
use std::fs::{File, Metadata, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::time::{Duration, Instant};

const MAX_SNAPSHOT_BYTES: u64 = 1024 * 1024 * 1024;
const JOURNAL_MAGIC: [u8; 8] = [0xd9, 0xd5, 0x05, 0xf9, 0x20, 0xa1, 0x63, 0xd7];

#[derive(Debug)]
enum InspectionError {
    Changed,
    Ledger(LedgerError),
}

impl From<LedgerError> for InspectionError {
    fn from(error: LedgerError) -> Self {
        Self::Ledger(error)
    }
}

#[derive(PartialEq, Eq)]
struct Fingerprint {
    device: u64,
    inode: u64,
    bytes: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

impl From<Metadata> for Fingerprint {
    fn from(metadata: Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            bytes: metadata.len(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

struct Subject {
    name: OsString,
    file: File,
    fingerprint: Fingerprint,
}

pub(super) fn verify(guard: &Guard) -> Result<(), LedgerError> {
    let started = Instant::now();
    loop {
        match inspect_once(guard) {
            Ok(()) => return Ok(()),
            Err(InspectionError::Changed) if started.elapsed() < Duration::from_secs(5) => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(InspectionError::Changed) => return Err(store(
                "SQLITE_PREFLIGHT_SOURCE_CHANGED: stable database snapshot unavailable within 5 seconds"
            )),
            Err(InspectionError::Ledger(error)) => return Err(error),
        }
    }
}

fn inspect_once(guard: &Guard) -> Result<(), InspectionError> {
    if guard.created {
        return Ok(());
    }
    let subjects = subjects(guard)?;
    let staging = tempfile::Builder::new()
        .prefix("bullet-sqlite-preflight-")
        .permissions(Permissions::from_mode(0o700))
        .tempdir_in("/tmp")
        .map_err(store)?;
    let result = inspect(guard, &subjects, staging.path());
    let retained = staging.path().to_path_buf();
    if let Err(error) = staging.close() {
        return Err(store(format!(
            "SQLITE_PREFLIGHT_CLEANUP_FAILED: private snapshot retained at {}; {error}; inspection={result:?}",
            retained.display()
        )).into());
    }
    result
}

fn inspect(guard: &Guard, subjects: &[Subject], staging: &Path) -> Result<(), InspectionError> {
    let mut digests = Vec::new();
    for subject in subjects {
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(staging.join(&subject.name))
            .map_err(store)?;
        digests.push(read_subject(subject, Some(&mut output))?);
    }
    verify_sources(guard, subjects, &digests)?;
    validate_replay(staging, &guard.database_name)?;
    let result = (|| {
        let mut copy = Connection::open_with_flags(
            staging.join(&guard.database_name),
            OpenFlags::SQLITE_OPEN_READ_WRITE
                | OpenFlags::SQLITE_OPEN_NO_MUTEX
                | OpenFlags::SQLITE_OPEN_NOFOLLOW,
        )
        .map_err(store)?;
        let inspected = migrations::enable_foreign_keys(&copy)
            .and_then(|()| migrations::verify_or_initialize(&mut copy));
        copy.close().map_err(|(_, error)| {
            store(format!(
                "SQLITE_PREFLIGHT_CLOSE_FAILED: {error}; inspection={inspected:?}"
            ))
        })?;
        inspected
    })();
    // Copy-side WAL checkpoint or hot-journal rollback must never touch the source.
    verify_sources(guard, subjects, &digests)?;
    result.map_err(Into::into)
}

fn validate_replay(staging: &Path, name: &std::ffi::OsStr) -> Result<(), LedgerError> {
    let main = File::open(staging.join(name)).map_err(store)?;
    let mut page_size = 4096;
    if main.metadata().map_err(store)?.len() >= 100 {
        let mut header = [0_u8; 100];
        main.read_exact_at(&mut header, 0).map_err(store)?;
        if header[..16] == *b"SQLite format 3\0" {
            page_size = u32::from(u16::from_be_bytes([header[16], header[17]]));
            if page_size == 1 {
                page_size = 65536;
            }
            bound_pages(be32(&header[28..32]), page_size)?;
        }
    }
    if let Some(journal) = optional_file(&staging.join(sidecar_name(name, "-journal")))? {
        let size = journal.metadata().map_err(store)?.len();
        if size >= 16 {
            let mut footer = [0_u8; 16];
            journal
                .read_exact_at(&mut footer, size - 16)
                .map_err(store)?;
            let length = u64::from(be32(&footer[..4]));
            // SQLite can follow/delete this name outside the private copy. Conservatively
            // reject the footer format even if its checksum is corrupt; never resolve it.
            if footer[8..] == JOURNAL_MAGIC && length > 0 && length <= size - 16 {
                return Err(store("SQLITE_PREFLIGHT_SUPER_JOURNAL: attached transaction recovery requires supervised admission"));
            }
        }
        if size >= 28 {
            let mut header = [0_u8; 28];
            journal.read_exact_at(&mut header, 0).map_err(store)?;
            if header[..8] == JOURNAL_MAGIC {
                let journal_page = be32(&header[24..28]);
                bound_pages(
                    be32(&header[16..20]),
                    if journal_page == 0 {
                        page_size
                    } else {
                        journal_page
                    },
                )?;
            }
        }
    }
    if let Some(wal) = optional_file(&staging.join(sidecar_name(name, "-wal")))? {
        let size = wal.metadata().map_err(store)?.len();
        if size >= 32 {
            let mut header = [0_u8; 32];
            wal.read_exact_at(&mut header, 0).map_err(store)?;
            if matches!(be32(&header[..4]), 0x377f0682 | 0x377f0683) {
                let page_size = be32(&header[8..12]);
                bound_pages(0, page_size)?;
                let mut offset = 32;
                while offset + 24 <= size {
                    let mut frame = [0_u8; 24];
                    wal.read_exact_at(&mut frame, offset).map_err(store)?;
                    bound_pages(be32(&frame[..4]), page_size)?;
                    bound_pages(be32(&frame[4..8]), page_size)?;
                    offset += 24 + u64::from(page_size);
                }
            }
        }
    }
    Ok(())
}

fn optional_file(path: &Path) -> Result<Option<File>, LedgerError> {
    match File::open(path) {
        Ok(file) => Ok(Some(file)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(store(error)),
    }
}

fn bound_pages(pages: u32, page_size: u32) -> Result<(), LedgerError> {
    if !(512..=65536).contains(&page_size) || !page_size.is_power_of_two() {
        return Err(store(
            "SQLITE_PREFLIGHT_REPLAY_FORMAT: unrecognized page size",
        ));
    }
    if u64::from(pages) * u64::from(page_size) > MAX_SNAPSHOT_BYTES {
        return Err(store("SQLITE_PREFLIGHT_REPLAY_TOO_LARGE: recovered database exceeds the 1 GiB inspection limit"));
    }
    Ok(())
}

fn be32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes(bytes.try_into().expect("four-byte field"))
}

fn subjects(guard: &Guard) -> Result<Vec<Subject>, InspectionError> {
    revalidate(guard)?;
    let directory = parent(&guard.boundary);
    let mut names = vec![guard.database_name.clone()];
    // SHM contains live read marks, not ledger authority. Revalidation still admits
    // its descriptor/type; the private copy reconstructs its own WAL index.
    names.extend(
        ["-journal", "-wal"]
            .iter()
            .map(|suffix| sidecar_name(&guard.database_name, suffix)),
    );
    let mut subjects = Vec::new();
    let mut total = 0_u64;
    for name in names {
        if let Some(file) = open_optional(&directory.descriptor, &name).map_err(store)? {
            admit_file(
                &file,
                &directory.public_path.join(&name),
                guard.effective_uid,
                "preflight",
            )?;
            let fingerprint = Fingerprint::from(file.metadata().map_err(store)?);
            total = total.checked_add(fingerprint.bytes).ok_or_else(too_large)?;
            if total > MAX_SNAPSHOT_BYTES {
                return Err(too_large().into());
            }
            subjects.push(Subject {
                name,
                file,
                fingerprint,
            });
        }
    }
    if subjects.first().map(|subject| &subject.name) != Some(&guard.database_name) {
        return Err(changed());
    }
    Ok(subjects)
}

fn read_subject(
    subject: &Subject,
    mut output: Option<&mut File>,
) -> Result<blake3::Hash, InspectionError> {
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0;
    while offset < subject.fingerprint.bytes {
        let remaining = subject.fingerprint.bytes - offset;
        let length = usize::try_from(remaining.min(buffer.len() as u64)).map_err(store)?;
        let count = subject
            .file
            .read_at(&mut buffer[..length], offset)
            .map_err(store)?;
        if count == 0 {
            return Err(changed());
        }
        hasher.update(&buffer[..count]);
        if let Some(output) = output.as_mut() {
            output.write_all(&buffer[..count]).map_err(store)?;
        }
        offset += count as u64;
    }
    if subject
        .file
        .read_at(&mut buffer[..1], offset)
        .map_err(store)?
        != 0
        || Fingerprint::from(subject.file.metadata().map_err(store)?) != subject.fingerprint
    {
        return Err(changed());
    }
    Ok(hasher.finalize())
}

fn verify_sources(
    guard: &Guard,
    original: &[Subject],
    digests: &[blake3::Hash],
) -> Result<(), InspectionError> {
    let current = subjects(guard)?;
    if current.len() != original.len() {
        return Err(changed());
    }
    for ((current, original), digest) in current.iter().zip(original).zip(digests) {
        if current.name != original.name
            || current.fingerprint != original.fingerprint
            || read_subject(current, None)? != *digest
        {
            return Err(changed());
        }
    }
    revalidate(guard).map_err(Into::into)
}

fn changed() -> InspectionError {
    InspectionError::Changed
}

fn too_large() -> LedgerError {
    store("SQLITE_PREFLIGHT_TOO_LARGE: database and sidecars exceed the 1 GiB inspection limit")
}
