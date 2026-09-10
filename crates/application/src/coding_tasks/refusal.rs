//! Finite task-admission refusals; callers never parse internal error text.

/// A valid task request conflicts with durable admission constraints.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum CodingTaskRefusal {
    /// The task deadline has already passed according to the store clock.
    DeadlineExpired,
    /// A dependency is absent, belongs to another owner or is not earlier work.
    DependencyNotAccepted,
    /// This revision has exhausted its accepted invocation-request count.
    InvocationLimit,
    /// Task intent arrived without an authenticated submitting operator.
    OperatorIngressRequired,
}

impl CodingTaskRefusal {
    /// Stable machine-readable refusal, independent of diagnostic formatting.
    #[must_use]
    pub const fn reason_code(self) -> &'static str {
        match self {
            Self::DeadlineExpired => "CODING_TASK_DEADLINE_EXPIRED",
            Self::DependencyNotAccepted => "CODING_DEPENDENCY_NOT_ACCEPTED",
            Self::InvocationLimit => "CODING_TASK_INVOCATION_LIMIT",
            Self::OperatorIngressRequired => "CODING_OPERATOR_INGRESS_REQUIRED",
        }
    }

    /// Concrete operator action; unchanged retries cannot repair fresh refusal.
    #[must_use]
    pub const fn repair(self) -> &'static str {
        match self {
            Self::DeadlineExpired => "Submit a reviewed task revision with a future deadline.",
            Self::DependencyNotAccepted => "Use earlier accepted task revisions from this operator's command history.",
            Self::InvocationLimit => "Recover an existing invocation, or submit a reviewed task revision with revised limits.",
            Self::OperatorIngressRequired => "Authenticate and submit task intent through POST /api/v1/commands.",
        }
    }
}

impl std::fmt::Display for CodingTaskRefusal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.reason_code())
    }
}
impl std::error::Error for CodingTaskRefusal {}
