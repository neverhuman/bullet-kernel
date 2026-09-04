//! Closed filesystem-containment profile for provider child processes.
//!
//! Preparation admits exact host objects and retains their file descriptors.
//! A command plan is produced only after those objects are revalidated. The
//! plan itself runs no provider and grants no dogfood admission.

mod validation;

use crate::error::{EgressCode, EgressError};
use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use validation::{OpenedDirectory, OpenedFile};

const PROVIDER_DESTINATION: &str = "/run/bullet/provider";
const SCHEMA_DESTINATION: &str = "/run/bullet/proposal-schema.json";
const CA_DESTINATION: &str = "/etc/ssl/certs/ca-certificates.crt";
const CREDENTIAL_DESTINATION: &str = "/run/bullet/credential";
/// Fixed child working directory: the sandbox binds the admitted clone here
/// and chdirs the provider into it, so transcript cwd pins must expect this
/// path rather than the host clone path.
pub const CLONE_DESTINATION: &str = "/workspace";
const SCRATCH_DESTINATION: &str = "/scratch";

/// An admitted ordinary file and its lowercase BLAKE3 content digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemFileV0 {
    path: PathBuf,
    blake3: String,
}

impl FilesystemFileV0 {
    /// Define an expected canonical host path and exact content digest.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>, blake3: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            blake3: blake3.into(),
        }
    }

    /// Expected canonical absolute host path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Expected lowercase BLAKE3 digest.
    #[must_use]
    pub fn blake3(&self) -> &str {
        &self.blake3
    }
}

/// One explicitly admitted runtime file and its fixed path inside the child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemRuntimeFileV0 {
    source: FilesystemFileV0,
    destination: PathBuf,
}

impl FilesystemRuntimeFileV0 {
    /// Bind `source` read-only at `destination` in the child.
    #[must_use]
    pub fn new(source: FilesystemFileV0, destination: impl Into<PathBuf>) -> Self {
        Self {
            source,
            destination: destination.into(),
        }
    }

    /// Admitted host file.
    #[must_use]
    pub const fn source(&self) -> &FilesystemFileV0 {
        &self.source
    }

    /// Fixed absolute child destination.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }
}

/// Versioned, closed filesystem inputs for one provider process.
///
/// V0 requires root custody for every static file and its ancestors. The
/// clone and scratch directories are exact, retained, owner-private FD mounts,
/// but their same-UID contents remain mutable by a peer process. That open
/// service-identity boundary prevents this component from admitting dogfood.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FilesystemSandboxProfileV0 {
    bubblewrap: FilesystemFileV0,
    provider: FilesystemFileV0,
    clone_directory: PathBuf,
    proposal_schema: FilesystemFileV0,
    ca_bundle: FilesystemFileV0,
    credential: Option<FilesystemFileV0>,
    prepared_home: Option<PathBuf>,
    runtime_files: Vec<FilesystemRuntimeFileV0>,
    scratch_directory: PathBuf,
    locale: String,
    provider_max_bytes: Option<u64>,
}

impl FilesystemSandboxProfileV0 {
    /// Construct the complete required profile. Validation happens in
    /// [`Self::prepare`]. No PATH lookup or implicit runtime mount exists.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        bubblewrap: FilesystemFileV0,
        provider: FilesystemFileV0,
        clone_directory: impl Into<PathBuf>,
        proposal_schema: FilesystemFileV0,
        ca_bundle: FilesystemFileV0,
        runtime_files: Vec<FilesystemRuntimeFileV0>,
        scratch_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            bubblewrap,
            provider,
            clone_directory: clone_directory.into(),
            proposal_schema,
            ca_bundle,
            credential: None,
            prepared_home: None,
            runtime_files,
            scratch_directory: scratch_directory.into(),
            locale: "C.UTF-8".to_string(),
            provider_max_bytes: None,
        }
    }

    /// Admit a provider entrypoint larger than the 64 MiB default, up to the
    /// exact bound an inspected runtime passport declares for it. The caller
    /// is responsible for having verified that passport; this profile still
    /// pins the entrypoint's content digest and root custody.
    #[must_use]
    pub fn with_provider_max_bytes(mut self, bytes: u64) -> Self {
        self.provider_max_bytes = Some(bytes);
        self
    }

    /// Bind an already-staged provider HOME (from `PreparedProviderHome`) as
    /// `/home/bullet`. The directory is writable so a token refresh can rewrite
    /// the copy; the host source is never mounted. Brokered credential files
    /// stay refused.
    #[must_use]
    pub fn with_prepared_home(mut self, home: impl Into<PathBuf>) -> Self {
        self.prepared_home = Some(home.into());
        self
    }

    /// Describe an optional broker-created credential file. V0 preparation
    /// refuses every credential path until sealed-FD broker custody exists;
    /// its contents are never copied into the environment or error details.
    #[must_use]
    pub fn with_brokered_credential(mut self, credential: FilesystemFileV0) -> Self {
        self.credential = Some(credential);
        self
    }

    /// Admit a locale environment setting. The environment is closed: only
    /// `LANG` and `LC_ALL`, both exactly `C.UTF-8`, are accepted.
    ///
    /// # Errors
    ///
    /// `EGRESS_FILESYSTEM_DENIED` for every other key or value.
    pub fn with_environment(mut self, key: &str, value: &str) -> Result<Self, EgressError> {
        if !matches!(key, "LANG" | "LC_ALL") || value != "C.UTF-8" {
            return Err(EgressError::new(
                EgressCode::FilesystemDenied,
                "environment entry is not allowlisted",
            ));
        }
        self.locale = value.to_string();
        Ok(self)
    }

    /// Open, validate, and retain every admitted object.
    ///
    /// # Errors
    ///
    /// `EGRESS_FILESYSTEM_DENIED` for an invalid profile, or
    /// `EGRESS_IO_FAILED` when a validated object cannot be read.
    pub fn prepare(self) -> Result<PreparedFilesystemSandbox, EgressError> {
        validation::prepare(self)
    }
}

/// Prepared filesystem subject. Open descriptors pin every mounted object.
/// This proves mount containment, not same-UID writer isolation or credential
/// custody; both remain prerequisites for an executable dogfood composition.
pub struct PreparedFilesystemSandbox {
    profile: FilesystemSandboxProfileV0,
    bubblewrap: OpenedFile,
    provider: OpenedFile,
    clone_directory: OpenedDirectory,
    proposal_schema: OpenedFile,
    ca_bundle: OpenedFile,
    credential: Option<OpenedFile>,
    prepared_home: Option<OpenedDirectory>,
    runtime_files: Vec<(PathBuf, OpenedFile)>,
    scratch_directory: OpenedDirectory,
    provider_argv0: OsString,
}

impl PreparedFilesystemSandbox {
    /// Original closed profile.
    #[must_use]
    pub const fn profile(&self) -> &FilesystemSandboxProfileV0 {
        &self.profile
    }

    /// Revalidate all identities and construct an inert, network-denied
    /// Bubblewrap plan. Only the crate-private composition with a proven
    /// [`crate::PreparedSandbox`] adds `--share-net` and proxy variables. The
    /// prepared subject must remain alive while the plan is used.
    ///
    /// # Errors
    ///
    /// `EGRESS_FILESYSTEM_CHANGED` if any retained or named object drifted.
    pub fn command_plan<'a>(
        &'a self,
        provider_args: &[&str],
    ) -> Result<FilesystemCommandPlan<'a>, EgressError> {
        self.command_plan_with_proxy(provider_args, None)
    }

    pub(crate) fn command_plan_with_proxy<'a>(
        &'a self,
        provider_args: &[&str],
        proxy_url: Option<&str>,
    ) -> Result<FilesystemCommandPlan<'a>, EgressError> {
        validation::revalidate(self)?;
        let mut arguments = base_arguments(proxy_url.is_some());
        add_runtime_directories(&mut arguments, &self.runtime_files);
        bind_fd(
            &mut arguments,
            "--ro-bind-fd",
            &self.bubblewrap,
            "/run/bullet/.bwrap-subject",
        );
        arguments.extend([OsString::from("--tmpfs"), OsString::from("/run/bullet")]);
        bind_fd(
            &mut arguments,
            "--ro-bind-fd",
            &self.clone_directory,
            CLONE_DESTINATION,
        );
        bind_fd(
            &mut arguments,
            "--ro-bind-fd",
            &self.provider,
            PROVIDER_DESTINATION,
        );
        bind_fd(
            &mut arguments,
            "--ro-bind-fd",
            &self.proposal_schema,
            SCHEMA_DESTINATION,
        );
        bind_fd(
            &mut arguments,
            "--ro-bind-fd",
            &self.ca_bundle,
            CA_DESTINATION,
        );
        if let Some(credential) = &self.credential {
            bind_fd(
                &mut arguments,
                "--ro-bind-fd",
                credential,
                CREDENTIAL_DESTINATION,
            );
        }
        for (destination, source) in &self.runtime_files {
            bind_fd(&mut arguments, "--ro-bind-fd", source, destination);
        }
        bind_fd(
            &mut arguments,
            "--bind-fd",
            &self.scratch_directory,
            SCRATCH_DESTINATION,
        );
        if let Some(home) = &self.prepared_home {
            bind_fd(&mut arguments, "--bind-fd", home, "/home/bullet");
        }
        seal_structural_directories(&mut arguments, &self.runtime_files);
        set_environment(&mut arguments, "HOME", "/home/bullet");
        set_environment(&mut arguments, "TMPDIR", "/tmp");
        set_environment(&mut arguments, "PATH", "/runtime/bin");
        set_environment(&mut arguments, "LANG", &self.profile.locale);
        set_environment(&mut arguments, "LC_ALL", &self.profile.locale);
        set_environment(&mut arguments, "SSL_CERT_FILE", CA_DESTINATION);
        if self.credential.is_some() {
            set_environment(
                &mut arguments,
                "BULLET_BROKERED_CREDENTIAL_FILE",
                CREDENTIAL_DESTINATION,
            );
        }
        if let Some(url) = proxy_url {
            for key in ["HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"] {
                set_environment(&mut arguments, key, url);
            }
            set_environment(&mut arguments, "NO_PROXY", "");
            set_environment(&mut arguments, "no_proxy", "");
        }
        arguments.extend([OsString::from("--argv0"), self.provider_argv0.clone()]);
        arguments.extend([OsString::from("--chdir"), OsString::from(CLONE_DESTINATION)]);
        arguments.extend([OsString::from("--"), OsString::from(PROVIDER_DESTINATION)]);
        arguments.extend(provider_args.iter().map(OsString::from));
        Ok(FilesystemCommandPlan {
            _prepared: self,
            program: self.bubblewrap.descriptor_path(),
            arguments,
        })
    }
}

/// Inert exact-program Bubblewrap invocation.
pub struct FilesystemCommandPlan<'a> {
    _prepared: &'a PreparedFilesystemSandbox,
    program: PathBuf,
    arguments: Vec<OsString>,
}

impl FilesystemCommandPlan<'_> {
    /// Exact retained Bubblewrap descriptor path; never a bare PATH program.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// Complete, closed Bubblewrap argument vector.
    #[must_use]
    pub fn arguments(&self) -> &[OsString] {
        &self.arguments
    }
}

fn base_arguments(share_network: bool) -> Vec<OsString> {
    let mut arguments: Vec<OsString> = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--dir",
        "/run",
        "--dir",
        "/run/bullet",
        "--dir",
        "/runtime",
        "--dir",
        "/etc",
        "--dir",
        "/etc/ssl",
        "--dir",
        "/etc/ssl/certs",
        "--tmpfs",
        "/tmp",
        "--tmpfs",
        "/home",
        "--dir",
        "/home/bullet",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    if share_network {
        arguments.insert(1, OsString::from("--share-net"));
    }
    arguments
}

fn add_runtime_directories(args: &mut Vec<OsString>, files: &[(PathBuf, OpenedFile)]) {
    let mut directories = BTreeSet::new();
    for (destination, _) in files {
        let mut parent = destination.parent();
        while let Some(path) = parent {
            if path == Path::new("/") {
                break;
            }
            directories.insert((path.components().count(), path.to_path_buf()));
            parent = path.parent();
        }
    }
    for (_, directory) in directories {
        args.push(OsString::from("--dir"));
        args.push(directory.into_os_string());
    }
}

fn seal_structural_directories(args: &mut Vec<OsString>, files: &[(PathBuf, OpenedFile)]) {
    let mut directories: BTreeSet<(usize, PathBuf)> = [
        "/",
        "/run",
        "/run/bullet",
        "/runtime",
        "/etc",
        "/etc/ssl",
        "/etc/ssl/certs",
        "/home",
    ]
    .into_iter()
    .map(PathBuf::from)
    .map(|path| (path.components().count(), path))
    .collect();
    for (destination, _) in files {
        for parent in destination.ancestors().skip(1) {
            if parent != Path::new("/") {
                directories.insert((parent.components().count(), parent.to_path_buf()));
            }
        }
    }
    for (_, directory) in directories.into_iter().rev() {
        args.extend([
            OsString::from("--chmod"),
            OsString::from("0555"),
            directory.into_os_string(),
        ]);
    }
}

trait BindSource {
    fn descriptor_number(&self) -> i32;
}

impl BindSource for OpenedFile {
    fn descriptor_number(&self) -> i32 {
        self.descriptor_number()
    }
}

impl BindSource for OpenedDirectory {
    fn descriptor_number(&self) -> i32 {
        self.descriptor_number()
    }
}

fn bind_fd(
    args: &mut Vec<OsString>,
    operation: &str,
    source: &impl BindSource,
    destination: impl AsRef<OsStr>,
) {
    args.push(OsString::from(operation));
    args.push(OsString::from(source.descriptor_number().to_string()));
    args.push(destination.as_ref().to_os_string());
}

fn set_environment(args: &mut Vec<OsString>, key: &str, value: &str) {
    args.extend([
        OsString::from("--setenv"),
        OsString::from(key),
        OsString::from(value),
    ]);
}

#[cfg(test)]
mod tests;
