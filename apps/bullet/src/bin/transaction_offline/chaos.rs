//! Debug-only boundary addressability for the offline component bridge.

use super::support::fail;
use std::os::unix::process::ExitStatusExt as _;
use std::process::Output;
use std::time::Duration;

pub(super) const ENV: &str = "BULLET_TRANSACTION_OFFLINE_CHAOS";
pub(super) const FAULT_CELL_ENV: &str = "BULLET_TRANSACTION_OFFLINE_FAULT_CELL";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Boundary {
    GrantPersistence,
    RunnerStartup,
    WorkspaceOpen,
    ProviderCompletion,
    PatchApply,
    Checkpoint,
    CandidatePreparation,
    VerifierHandoff,
    CandidateDelivery,
    CheckPublication,
    Integration,
    ObservationCleanup,
}

impl Boundary {
    #[cfg(debug_assertions)]
    const ALL: [Self; 12] = [
        Self::GrantPersistence,
        Self::RunnerStartup,
        Self::WorkspaceOpen,
        Self::ProviderCompletion,
        Self::PatchApply,
        Self::Checkpoint,
        Self::CandidatePreparation,
        Self::VerifierHandoff,
        Self::CandidateDelivery,
        Self::CheckPublication,
        Self::Integration,
        Self::ObservationCleanup,
    ];

    pub(super) const fn label(self) -> &'static str {
        match self {
            Self::GrantPersistence => "grant-persistence",
            Self::RunnerStartup => "runner-startup",
            Self::WorkspaceOpen => "workspace-open",
            Self::ProviderCompletion => "provider-completion",
            Self::PatchApply => "patch-apply",
            Self::Checkpoint => "checkpoint",
            Self::CandidatePreparation => "candidate-preparation",
            Self::VerifierHandoff => "verifier-handoff",
            Self::CandidateDelivery => "candidate-delivery",
            Self::CheckPublication => "check-publication",
            Self::Integration => "integration",
            Self::ObservationCleanup => "observation-cleanup",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(not(debug_assertions), allow(dead_code))]
pub(super) enum FaultMode {
    Death,
    Timeout,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct FaultCell {
    boundary: Boundary,
    mode: FaultMode,
}

impl FaultCell {
    #[cfg(debug_assertions)]
    const ALL: [Self; 4] = [
        Self::new(Boundary::RunnerStartup, FaultMode::Death),
        Self::new(Boundary::RunnerStartup, FaultMode::Timeout),
        Self::new(Boundary::VerifierHandoff, FaultMode::Death),
        Self::new(Boundary::VerifierHandoff, FaultMode::Timeout),
    ];

    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    const fn new(boundary: Boundary, mode: FaultMode) -> Self {
        Self { boundary, mode }
    }

    pub(super) const fn label(self) -> &'static str {
        match (self.boundary, self.mode) {
            (Boundary::RunnerStartup, FaultMode::Death) => "runner-startup:death",
            (Boundary::RunnerStartup, FaultMode::Timeout) => "runner-startup:timeout",
            (Boundary::VerifierHandoff, FaultMode::Death) => "verifier-handoff:death",
            (Boundary::VerifierHandoff, FaultMode::Timeout) => "verifier-handoff:timeout",
            _ => "inapplicable-fault-cell",
        }
    }

    pub(super) const fn mode_label(self) -> &'static str {
        match self.mode {
            FaultMode::Death => "death",
            FaultMode::Timeout => "timeout",
        }
    }

    pub(super) const fn signal(self) -> rustix::process::Signal {
        match self.mode {
            FaultMode::Death => rustix::process::Signal::KILL,
            FaultMode::Timeout => rustix::process::Signal::STOP,
        }
    }

    pub(super) const fn deadline(self) -> Duration {
        match self.mode {
            FaultMode::Death => Duration::from_secs(2),
            FaultMode::Timeout => Duration::from_millis(100),
        }
    }
}

pub(super) fn refuse_if_selected(boundary: Boundary) -> Result<(), String> {
    if selected_boundary()? == Some(boundary) {
        return Err(fail(format!(
            "CHAOS_BOUNDARY_INJECTED: {}; classification=COMPONENT_PROOF \
             signing_trust=UNSIGNED_FIXTURE transaction_gate_eligible=false \
             independent_evidence_eligible=false release_gate_eligible=false",
            boundary.label()
        )));
    }
    Ok(())
}

pub(super) fn admit_debug_selection() -> Result<(), String> {
    let boundary = selected_boundary()?;
    let fault = selected_fault_cell()?;
    if boundary.is_some() && fault.is_some() {
        return Err(fail(
            "CHAOS_SELECTION_CONFLICT: boundary addressability and process fault selectors are mutually exclusive",
        ));
    }
    Ok(())
}

pub(super) fn fault_for(boundary: Boundary) -> Result<Option<FaultCell>, String> {
    Ok(selected_fault_cell()?.filter(|cell| cell.boundary == boundary))
}

pub(super) fn validate_process_fault(
    cell: FaultCell,
    outcome: &std::io::Result<Output>,
) -> Result<String, String> {
    match (cell.mode, outcome) {
        (FaultMode::Death, Ok(output))
            if output.status.signal() == Some(rustix::process::Signal::KILL.as_raw()) => {}
        (FaultMode::Timeout, Err(error)) if error.kind() == std::io::ErrorKind::TimedOut => {}
        (_, Err(error)) => {
            return Err(fail(format!(
                "CHAOS_FAULT_CLEANUP_FAILED: cell={} error={error}",
                cell.label()
            )));
        }
        (_, Ok(output)) => {
            return Err(fail(format!(
                "CHAOS_FAULT_EXECUTION_INVALID: cell={} status={:?}",
                cell.label(),
                output.status.code()
            )));
        }
    }
    Ok(format!(
        "CHAOS_FAULT_INJECTED: boundary={} mode={}; classification=COMPONENT_PROOF \
         signing_trust=UNSIGNED_FIXTURE transaction_gate_eligible=false \
         independent_evidence_eligible=false release_gate_eligible=false",
        cell.boundary.label(),
        cell.mode_label()
    ))
}

fn selected_boundary() -> Result<Option<Boundary>, String> {
    let Some(raw) = std::env::var_os(ENV) else {
        return Ok(None);
    };
    #[cfg(not(debug_assertions))]
    {
        let _ = raw;
        Err(fail(
            "CHAOS_DEBUG_ONLY_REFUSED: boundary addressability is debug-component-only",
        ))
    }
    #[cfg(debug_assertions)]
    {
        let value = raw
            .into_string()
            .map_err(|_| fail("CHAOS_BOUNDARY_INVALID: label must be UTF-8"))?;
        let boundary = Boundary::ALL
            .into_iter()
            .find(|candidate| candidate.label() == value)
            .ok_or_else(|| {
                fail(format!(
                    "CHAOS_BOUNDARY_INVALID: expected exactly one of {}",
                    labels().join(",")
                ))
            })?;
        Ok(Some(boundary))
    }
}

fn selected_fault_cell() -> Result<Option<FaultCell>, String> {
    let Some(raw) = std::env::var_os(FAULT_CELL_ENV) else {
        return Ok(None);
    };
    #[cfg(not(debug_assertions))]
    {
        let _ = raw;
        Err(fail(
            "CHAOS_DEBUG_ONLY_REFUSED: boundary addressability is debug-component-only",
        ))
    }
    #[cfg(debug_assertions)]
    {
        let value = raw
            .into_string()
            .map_err(|_| fail("CHAOS_FAULT_CELL_INVALID: label must be UTF-8"))?;
        FaultCell::ALL
            .into_iter()
            .find(|candidate| candidate.label() == value)
            .map(Some)
            .ok_or_else(|| {
                fail(format!(
                    "CHAOS_FAULT_CELL_INVALID: expected exactly one of {}",
                    fault_cell_labels().join(",")
                ))
            })
    }
}

#[cfg(debug_assertions)]
fn labels() -> Vec<&'static str> {
    Boundary::ALL
        .into_iter()
        .map(Boundary::label)
        .collect::<Vec<_>>()
}

#[cfg(debug_assertions)]
fn fault_cell_labels() -> Vec<&'static str> {
    FaultCell::ALL
        .into_iter()
        .map(FaultCell::label)
        .collect::<Vec<_>>()
}
