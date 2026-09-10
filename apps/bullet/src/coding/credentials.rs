use super::args::ConnectionArgs;

#[cfg(unix)]
pub(super) struct Session {
    pub(super) credentials: crate::auth::store::Credentials,
    pub(super) directory: std::path::PathBuf,
}

#[cfg(unix)]
impl std::ops::Deref for Session {
    type Target = crate::auth::store::Credentials;
    fn deref(&self) -> &Self::Target {
        &self.credentials
    }
}

#[cfg(not(unix))]
pub(super) struct Session {
    pub(super) farmd: String,
    pub(super) origin: String,
    pub(super) cookie: String,
    pub(super) csrf: String,
}

impl ConnectionArgs {
    #[cfg(unix)]
    pub(super) fn load(self) -> Result<Session, String> {
        let path = crate::auth::state_dir(self.state_dir)?;
        let session = crate::auth::store::CredentialStore::open(&path)?
            .load()?
            .ok_or("AUTH_REQUIRED: run bullet auth login")?;
        if self
            .farmd
            .as_ref()
            .is_some_and(|address| address != &session.farmd)
        {
            return Err(
                "AUTH_DESTINATION_MISMATCH: use the state directory for this endpoint".into(),
            );
        }
        Ok(Session {
            credentials: session,
            directory: path,
        })
    }
    #[cfg(not(unix))]
    pub(super) fn load(self) -> Result<Session, String> {
        Err("AUTH_PRIVATE_STORE_UNSUPPORTED".into())
    }
}
