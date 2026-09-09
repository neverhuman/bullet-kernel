//! Retained descriptor authority for one admitted workspace generation store.

use super::protocol;
use crate::error::RunnerError;
use bullet_domain::AuthorityToken;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Workspace root opened before clone and retained across daemon responses.
pub(crate) struct WorkspaceRootGuard {
    root: File,
}

/// Exact generations directory retained after the initial clone.
pub(crate) struct WorkspaceGenerationGuard {
    generations: File,
}

impl WorkspaceRootGuard {
    pub(crate) fn open(path: &Path) -> Result<Self, RunnerError> {
        #[cfg(not(target_os = "linux"))]
        {
            let _ = path;
            return Err(protocol(
                "workspace mutation is unsupported without Linux openat2",
            ));
        }
        #[cfg(target_os = "linux")]
        {
            use rustix::fs::{openat2, Mode, OFlags, ResolveFlags, ABS};

            let resolve = ResolveFlags::NO_SYMLINKS.union(ResolveFlags::NO_MAGICLINKS);
            let descriptor = openat2(
                ABS,
                path,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
                resolve,
            )
            .map(File::from)
            .map_err(|error| protocol(format!("open admitted workspace root: {error}")))?;
            Ok(Self { root: descriptor })
        }
    }

    pub(crate) fn bind(
        self,
        authority: &AuthorityToken,
        generation: u64,
    ) -> Result<WorkspaceGenerationGuard, RunnerError> {
        let relative = PathBuf::from("work")
            .join(authority.attempt_id.as_str())
            .join("generations");
        let generations = open_beneath(&self.root, &relative, "workspace generations")?;
        let guard = WorkspaceGenerationGuard { generations };
        let _initial = guard.open_generation(generation)?;
        Ok(guard)
    }
}

impl WorkspaceGenerationGuard {
    pub(crate) fn open_generation(&self, generation: u64) -> Result<File, RunnerError> {
        let relative = PathBuf::from(format!("generation-{generation:020}")).join("repo");
        open_beneath(&self.generations, &relative, "active generation repository")
    }
}

fn open_beneath(parent: &File, relative: &Path, label: &str) -> Result<File, RunnerError> {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (parent, relative, label);
        Err(protocol(
            "workspace mutation is unsupported without Linux openat2",
        ))
    }
    #[cfg(target_os = "linux")]
    {
        use rustix::fs::{openat2, Mode, OFlags, ResolveFlags};

        let resolve = ResolveFlags::BENEATH
            .union(ResolveFlags::NO_SYMLINKS)
            .union(ResolveFlags::NO_MAGICLINKS);
        openat2(
            parent,
            relative,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )
        .map(File::from)
        .map_err(|error| protocol(format!("open {label}: {error}")))
    }
}
