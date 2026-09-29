use serde::{Deserialize, Serialize};

use crate::outcome::OutcomeVariant;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordEnvelope {
    pub record_type: RecordType,
    pub schema_version: u32,
    pub namespace: Namespace,
    pub record_id: String,
    pub creator_ref: String,
    pub created_at_unix_ms: u64,
    pub payload: RecordPayload,
    pub integrity: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RecordType {
    ProjectBinding,
    ActorBinding,
    AuthorityRecord,
    ExecutionContract,
    EvidenceRef,
    Assessment,
    PromotionEligibilityRecord,
    Checkpoint,
    Outcome,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Namespace {
    Fixture,
    Operational,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecordPayload {
    ProjectBinding(ProjectBinding),
    ActorBinding(ActorBinding),
    AuthorityRecord(AuthorityRecord),
    ExecutionContract(ExecutionContract),
    EvidenceRef(EvidenceRef),
    Assessment(Assessment),
    PromotionEligibilityRecord(PromotionEligibilityRecord),
    Checkpoint(Checkpoint),
    Outcome(Outcome),
}

impl RecordPayload {
    pub fn record_type(&self) -> RecordType {
        match self {
            Self::ProjectBinding(_) => RecordType::ProjectBinding,
            Self::ActorBinding(_) => RecordType::ActorBinding,
            Self::AuthorityRecord(_) => RecordType::AuthorityRecord,
            Self::ExecutionContract(_) => RecordType::ExecutionContract,
            Self::EvidenceRef(_) => RecordType::EvidenceRef,
            Self::Assessment(_) => RecordType::Assessment,
            Self::PromotionEligibilityRecord(_) => RecordType::PromotionEligibilityRecord,
            Self::Checkpoint(_) => RecordType::Checkpoint,
            Self::Outcome(_) => RecordType::Outcome,
        }
    }

    pub fn primary_id(&self) -> &str {
        match self {
            Self::ProjectBinding(v) => &v.project_id,
            Self::ActorBinding(v) => &v.actor_id,
            Self::AuthorityRecord(v) => &v.authority_id,
            Self::ExecutionContract(v) => &v.contract_id,
            Self::EvidenceRef(v) => &v.evidence_id,
            Self::Assessment(v) => &v.assessment_id,
            Self::PromotionEligibilityRecord(v) => &v.eligibility_id,
            Self::Checkpoint(v) => &v.checkpoint_id,
            Self::Outcome(v) => &v.outcome_id,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    Requester,
    DecisionAuthority,
    Executor,
    Verifier,
    PromotionAuthority,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BindingState {
    Proposed,
    Active,
    Superseded,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuthorityClass {
    Decision,
    Authorization,
    Approval,
    Revocation,
    Reinstatement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResourceMatch {
    Exact,
    Subtree,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Provision {
    Permit,
    Forbid,
    Approve,
    Revoke,
    Reinstate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EvidenceStatus {
    Current,
    Superseded,
    Invalidated,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AssessmentDecision {
    Pass,
    Fail,
    Blocked,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EligibilityOutcome {
    Eligible,
    Ineligible,
    Blocked,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClaimAtom {
    pub project_binding_ref: String,
    pub resource_ref: String,
    pub resource_match: ResourceMatch,
    pub action: String,
    pub provision: Provision,
    pub effect: String,
    pub lifecycle_contexts: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OverrideEdge {
    pub predecessor_claim_ref: String,
    pub successor_claim_ref: String,
    pub coverage_atoms: Vec<ClaimAtom>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactIdentity {
    pub artifact_ref: String,
    pub digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectBinding {
    pub project_id: String,
    pub canonical_root: String,
    pub repository_id: Option<u64>,
    pub repository_url: Option<String>,
    pub authority_source_ref: String,
    pub binding_revision: u32,
    pub state: BindingState,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorBinding {
    pub actor_id: String,
    pub principal_ref: String,
    pub auth_method_ref: String,
    pub roles: Vec<Role>,
    pub issued_by_ref: String,
    pub valid_from_ms: u64,
    pub valid_until_ms: Option<u64>,
    pub revocation_ref: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRecord {
    pub authority_id: String,
    pub class: AuthorityClass,
    pub issuer_actor_ref: String,
    pub exercised_role: Role,
    pub effective_at_ms: u64,
    pub target_binding_ref: Option<String>,
    pub contract_digest: Option<String>,
    pub claim_atoms: Vec<ClaimAtom>,
    pub override_edges: Vec<OverrideEdge>,
    pub evidence_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionContract {
    pub contract_id: String,
    pub contract_version: u32,
    pub mission: String,
    pub project_binding_ref: String,
    pub target_ref: String,
    pub expected_target_state: String,
    pub actor_ref: String,
    pub capability_code: String,
    pub allowed_operations: Vec<String>,
    pub read_scopes: Vec<String>,
    pub allowed_mutations: Vec<String>,
    pub prohibited_mutations: Vec<String>,
    pub precondition_refs: Vec<String>,
    pub required_evidence_refs: Vec<String>,
    pub verification_gate_refs: Vec<String>,
    pub stop_codes: Vec<String>,
    pub escalation_ref: String,
    pub expected_deliverables: Vec<String>,
    pub requester_boundary: String,
    pub network_allowed: bool,
    pub secret_access_allowed: bool,
    pub cross_surface_delivery_allowed: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceRef {
    pub evidence_id: String,
    pub kind: String,
    pub locator: String,
    pub content_digest: String,
    pub producer_ref: String,
    pub method: String,
    pub subject_ref: String,
    pub subject_revision: String,
    pub observed_at_ms: u64,
    pub contract_ref: String,
    pub run_ref: String,
    pub gate_ref: Option<String>,
    pub status: EvidenceStatus,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assessment {
    pub assessment_id: String,
    pub subject_ref: String,
    pub gate_result_refs: Vec<String>,
    pub verifier_actor_ref: String,
    pub independence_claimed: bool,
    pub evidence_refs: Vec<String>,
    pub decision: AssessmentDecision,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionEligibilityRecord {
    pub eligibility_id: String,
    pub candidate_ref: String,
    pub candidate_revision: String,
    pub expected_prior_canonical_ref: String,
    pub expected_prior_canonical_version: String,
    pub promotion_subject_ref: String,
    pub promotion_scope: String,
    pub contract_ref: String,
    pub contract_digest: String,
    pub authorization_ref: String,
    pub policy_ref: String,
    pub policy_version: u32,
    pub assurance_rule_ref: String,
    pub assurance_rule_version: u32,
    pub eligibility_rule_version: u32,
    pub evidence_set_ref: String,
    pub evidence_artifacts: Vec<ArtifactIdentity>,
    pub verification_result_refs: Vec<String>,
    pub approval_refs: Vec<String>,
    pub authority_state_ref: String,
    pub evaluated_outcome: EligibilityOutcome,
    pub input_refs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    pub checkpoint_id: String,
    pub run_ref: String,
    pub contract_digest: String,
    pub target_ref: String,
    pub target_state: String,
    pub last_valid_step: String,
    pub completed_gate_refs: Vec<String>,
    pub blocker_codes: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub pending_action: String,
    pub partial_effect_refs: Vec<String>,
    pub resume_authority_ref: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    pub outcome_id: String,
    pub status_and_code: OutcomeVariant,
    pub scope_ref: String,
    pub evidence_refs: Vec<String>,
    pub next_action: String,
    pub detail: String,
}
