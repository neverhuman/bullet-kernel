//! Exact local check, protected integration, and read-back contract.

use crate::error::EffectsError;
use crate::forge::require_oid;
use crate::git_env::run_git;
use crate::integration::{
    Capability, CheckPublication, CheckReceipt, ForgeIntegration, IntegrationDescriptor,
    IntegrationReceipt, IntegrationSubject, IntegrationSubjectRequest, MergeGroupSubject,
    ProtectedIntegrationRequest, ProtectionState,
};
use crate::local::LocalBareForge;
use crate::local_state::LocalState;

const MAX_CHECK_NAME_BYTES: usize = 128;
const MAX_PROOF_ROOT_BYTES: usize = 256;

impl LocalBareForge {
    /// Persist immutable protection for one local target. Replaying the exact
    /// state is idempotent; rebinding the target to another proof root refuses.
    ///
    /// # Errors
    ///
    /// Typed target, proof-root, read-back, or durable-state refusal.
    pub fn protect_target(
        &mut self,
        target: &str,
        required_proof_root: &str,
    ) -> Result<ProtectionState, EffectsError> {
        self.require_target_ref(target)?;
        require_text(
            "required_proof_root",
            required_proof_root,
            MAX_PROOF_ROOT_BYTES,
        )?;
        if self.read_exact_ref(target)?.is_none() {
            return Err(EffectsError::ProtectionMismatch(format!(
                "target {target} is absent"
            )));
        }
        let state = ProtectionState {
            target: target.to_owned(),
            protected: true,
            required_proof_root: Some(required_proof_root.to_owned()),
        };
        if !self.state.put_protection(&state)? {
            return Err(EffectsError::ProtectionMismatch(format!(
                "target {target} protection is already bound differently"
            )));
        }
        Ok(state)
    }

    fn require_target_ref(&self, target: &str) -> Result<(), EffectsError> {
        let suffix = target.strip_prefix("refs/heads/").unwrap_or_default();
        if suffix.is_empty() || target.starts_with("refs/heads/bullet/candidate/") {
            return Err(EffectsError::RefDenied(format!(
                "{target} is not an integration target"
            )));
        }
        let (code, _out, error) = run_git(None, &["check-ref-format", target])?;
        if code != 0 {
            return Err(EffectsError::RefDenied(format!(
                "invalid integration target {target}: {error}"
            )));
        }
        Ok(())
    }

    fn require_commit(&self, oid: &str) -> Result<(), EffectsError> {
        require_oid("commit", oid)?;
        let object = format!("{oid}^{{commit}}");
        let (code, _out, error) = run_git(Some(&self.bare), &["cat-file", "-e", &object])?;
        if code != 0 {
            return Err(EffectsError::IntegrationSubjectMismatch(format!(
                "commit {oid} is absent from local forge: {error}"
            )));
        }
        Ok(())
    }

    fn read_exact_ref(&self, target: &str) -> Result<Option<String>, EffectsError> {
        self.require_target_ref(target)?;
        let (code, output, error) = run_git(
            Some(&self.bare),
            &["rev-parse", "--verify", "--quiet", target],
        )?;
        if code == 1 && output.is_empty() && error.is_empty() {
            return Ok(None);
        }
        if code != 0 {
            return Err(EffectsError::TargetReadbackUnavailable(format!(
                "read {target}: {error}"
            )));
        }
        if output.lines().count() != 1 {
            return Err(EffectsError::TargetReadbackUnavailable(format!(
                "read {target} returned a non-singleton value"
            )));
        }
        require_oid("target_oid", &output)?;
        Ok(Some(output))
    }

    fn validate_subject(&self, subject: &IntegrationSubject) -> Result<(), EffectsError> {
        self.require_commit(&subject.base)?;
        self.require_commit(&subject.head)?;
        self.require_target_ref(&subject.target)?;
        let expected = LocalState::subject_id(&subject.base, &subject.head, &subject.target);
        if subject.id != expected {
            return Err(EffectsError::IntegrationSubjectMismatch(format!(
                "subject id {} does not match exact tuple",
                subject.id
            )));
        }
        Ok(())
    }

    fn require_ancestry(&self, base: &str, head: &str) -> Result<(), EffectsError> {
        let (code, _out, error) = run_git(
            Some(&self.bare),
            &["merge-base", "--is-ancestor", base, head],
        )?;
        match code {
            0 => Ok(()),
            1 => Err(EffectsError::IntegrationSubjectMismatch(format!(
                "head {head} does not descend from base {base}"
            ))),
            _ => Err(EffectsError::GitFailed(format!(
                "merge-base {base} {head}: {error}"
            ))),
        }
    }

    fn require_check_request(&self, sha: &str, name: &str) -> Result<(), EffectsError> {
        require_oid("check_sha", sha)?;
        require_text("check_name", name, MAX_CHECK_NAME_BYTES)
    }
}

impl ForgeIntegration for LocalBareForge {
    fn integration_descriptor(&self) -> IntegrationDescriptor {
        IntegrationDescriptor {
            exact_oid_cas: Capability::Supported,
            protected_refs: Capability::SupportedWithLimitations(
                "immutable local control record; not an external forge ruleset",
            ),
            check_runs: Capability::SupportedWithLimitations(
                "exact local control record; not an external forge check run",
            ),
            merge_group: Capability::Unsupported,
            exact_oid_readback: Capability::Supported,
            third_party_credential: Capability::Unsupported,
        }
    }

    fn read_protection(&self, target: &str) -> Result<ProtectionState, EffectsError> {
        self.require_target_ref(target)?;
        Ok(self
            .state
            .read_protection(target)?
            .unwrap_or_else(|| ProtectionState {
                target: target.to_owned(),
                protected: false,
                required_proof_root: None,
            }))
    }

    fn publish_check(&mut self, req: &CheckPublication) -> Result<CheckReceipt, EffectsError> {
        self.require_check_request(&req.sha, &req.name)?;
        self.require_commit(&req.sha)?;
        require_text("proof_root", &req.proof_root, MAX_PROOF_ROOT_BYTES)?;
        let receipt = CheckReceipt {
            sha: req.sha.clone(),
            name: req.name.clone(),
            proof_root: req.proof_root.clone(),
        };
        if !self.state.put_check(&receipt)? {
            return Err(EffectsError::CheckSubjectMismatch(format!(
                "check ({}, {}) is already bound to another proof root",
                req.sha, req.name
            )));
        }
        Ok(receipt)
    }

    fn read_check(&self, sha: &str, name: &str) -> Result<Option<CheckReceipt>, EffectsError> {
        self.require_check_request(sha, name)?;
        let receipt = self.state.read_check(sha, name)?;
        if receipt
            .as_ref()
            .is_some_and(|value| value.sha != sha || value.name != name)
        {
            return Err(EffectsError::CheckSubjectMismatch(format!(
                "stored check differs from ({sha}, {name})"
            )));
        }
        Ok(receipt)
    }

    fn ensure_integration_subject(
        &mut self,
        req: &IntegrationSubjectRequest,
    ) -> Result<IntegrationSubject, EffectsError> {
        self.require_commit(&req.base)?;
        self.require_commit(&req.head)?;
        self.require_target_ref(&req.target)?;
        self.require_ancestry(&req.base, &req.head)?;
        let subject = IntegrationSubject {
            id: LocalState::subject_id(&req.base, &req.head, &req.target),
            base: req.base.clone(),
            head: req.head.clone(),
            target: req.target.clone(),
        };
        if let Some(existing) = self.state.read_subject(&subject.id)? {
            return if existing == subject {
                Ok(existing)
            } else {
                Err(EffectsError::IntegrationSubjectMismatch(format!(
                    "subject {} is rebound",
                    subject.id
                )))
            };
        }
        if self.read_exact_ref(&req.target)?.as_deref() != Some(req.base.as_str()) {
            return Err(EffectsError::IntegrationPreconditionFailed(format!(
                "target {} does not equal subject base {}",
                req.target, req.base
            )));
        }
        if !self.state.put_subject(&subject)? {
            return Err(EffectsError::IntegrationSubjectMismatch(format!(
                "subject {} raced with a different value",
                subject.id
            )));
        }
        Ok(subject)
    }

    fn integrate_protected(
        &mut self,
        req: &ProtectedIntegrationRequest,
    ) -> Result<IntegrationReceipt, EffectsError> {
        self.validate_subject(&req.subject)?;
        require_oid("expected_old_oid", &req.expected_old_oid)?;
        require_text("check_name", &req.check_name, MAX_CHECK_NAME_BYTES)?;
        require_text("proof_root", &req.proof_root, MAX_PROOF_ROOT_BYTES)?;
        if req.expected_old_oid != req.subject.base {
            return Err(EffectsError::IntegrationSubjectMismatch(
                "expected old OID differs from subject base".into(),
            ));
        }
        if self.state.read_subject(&req.subject.id)?.as_ref() != Some(&req.subject) {
            return Err(EffectsError::IntegrationSubjectMismatch(format!(
                "subject {} is absent or differs from durable state",
                req.subject.id
            )));
        }
        let protection = self.read_protection(&req.subject.target)?;
        if !protection.protected
            || protection.required_proof_root.as_deref() != Some(req.proof_root.as_str())
        {
            return Err(EffectsError::ProtectionMismatch(format!(
                "target {} does not require proof root {}",
                req.subject.target, req.proof_root
            )));
        }
        let check = self
            .read_check(&req.subject.head, &req.check_name)?
            .ok_or_else(|| {
                EffectsError::CheckSubjectMismatch(format!(
                    "check ({}, {}) is absent",
                    req.subject.head, req.check_name
                ))
            })?;
        if check.proof_root != req.proof_root {
            return Err(EffectsError::CheckSubjectMismatch(format!(
                "check proof root {} differs from required {}",
                check.proof_root, req.proof_root
            )));
        }
        let receipt = IntegrationReceipt {
            subject_id: req.subject.id.clone(),
            target: req.subject.target.clone(),
            previous_oid: req.expected_old_oid.clone(),
            integrated_oid: req.subject.head.clone(),
            check,
        };
        if let Some(existing) = self.state.read_integration(&req.subject.id)? {
            if existing != receipt
                || self.read_exact_ref(&req.subject.target)?.as_deref()
                    != Some(req.subject.head.as_str())
            {
                return Err(EffectsError::OrphanedRemote(format!(
                    "integration {} no longer matches target or receipt",
                    req.subject.id
                )));
            }
            return Ok(existing);
        }
        let observed = self.read_exact_ref(&req.subject.target)?;
        if observed.as_deref() != Some(req.expected_old_oid.as_str()) {
            let error = if observed.as_deref() == Some(req.subject.head.as_str()) {
                EffectsError::OrphanedRemote(format!(
                    "target {} moved without a durable receipt",
                    req.subject.target
                ))
            } else {
                EffectsError::IntegrationPreconditionFailed(format!(
                    "target {} expected {} observed {observed:?}",
                    req.subject.target, req.expected_old_oid
                ))
            };
            return Err(error);
        }
        let (code, _output, error) = run_git(
            Some(&self.bare),
            &[
                "update-ref",
                "--no-deref",
                &req.subject.target,
                &req.subject.head,
                &req.expected_old_oid,
            ],
        )?;
        if code != 0 {
            let observed = self.read_exact_ref(&req.subject.target)?;
            return Err(EffectsError::IntegrationPreconditionFailed(format!(
                "target {} compare-and-swap failed; observed {observed:?}: {error}",
                req.subject.target
            )));
        }
        if self.read_exact_ref(&req.subject.target)?.as_deref() != Some(req.subject.head.as_str()) {
            return Err(EffectsError::OrphanedRemote(format!(
                "target {} did not read back exact integrated head",
                req.subject.target
            )));
        }
        if !self.state.put_integration(&receipt)? {
            return Err(EffectsError::OrphanedRemote(format!(
                "integration {} receipt conflicts after target mutation",
                req.subject.id
            )));
        }
        Ok(receipt)
    }

    fn merge_group_subject(
        &self,
        _subject: &IntegrationSubject,
    ) -> Result<Option<MergeGroupSubject>, EffectsError> {
        Ok(None)
    }

    fn read_target(&self, target: &str) -> Result<Option<String>, EffectsError> {
        self.read_exact_ref(target)
    }
}

fn require_text(field: &str, value: &str, max_bytes: usize) -> Result<(), EffectsError> {
    if value.is_empty()
        || value.len() > max_bytes
        || value.chars().any(char::is_control)
        || value.trim() != value
    {
        return Err(EffectsError::CheckSubjectMismatch(format!(
            "{field} must be 1..={max_bytes} trimmed non-control bytes"
        )));
    }
    Ok(())
}
