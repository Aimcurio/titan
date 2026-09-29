use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", content = "code", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum OutcomeVariant {
    Pass(PassCode),
    Fail(FailCode),
    Blocked(BlockedCode),
    Unknown(UnknownCode),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PassCode {
    GatePassed,
    WorkCompleted,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FailCode {
    WorkFailed,
    VerificationFailed,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockedCode {
    Unauthorized,
    InsufficientEvidence,
    TargetIdentityMismatch,
    ScopeViolation,
    EnvironmentFailure,
    PreconditionDrift,
    ContractInvalid,
    BlockedAuthorityConflict,
    BlockedNoActiveGoverningAuthority,
    BlockedPromotionEligibilityStale,
    BlockedCanonicalStateChanged,
    AuthorityStale,
    Revoked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UnknownCode {
    Interrupted,
    PartialEffectUnreconciled,
    EvidenceUnavailable,
}
