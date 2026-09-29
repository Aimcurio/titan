use std::{error::Error, fmt};

use serde::Serialize;

use crate::records::{
    ActorBinding, ArtifactIdentity, Assessment, AuthorityClass, AuthorityRecord, Checkpoint,
    ClaimAtom, EvidenceRef, ExecutionContract, Namespace, Outcome, OverrideEdge, ProjectBinding,
    PromotionEligibilityRecord, RecordEnvelope, RecordPayload, RecordType,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ValidationStage {
    InputSize,
    Parse,
    Shape,
    Canonical,
    Integrity,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ValidationError {
    pub stage: ValidationStage,
    pub reason: &'static str,
}

impl ValidationError {
    pub(crate) const fn new(stage: ValidationStage, reason: &'static str) -> Self {
        Self { stage, reason }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}: {}", self.stage, self.reason)
    }
}

impl Error for ValidationError {}

fn bad(reason: &'static str) -> ValidationError {
    ValidationError::new(ValidationStage::Shape, reason)
}

pub(crate) fn fx_id(value: &str, expected_kind: Option<&str>) -> Result<(), ValidationError> {
    let mut parts = value.split(':');
    let Some("fx") = parts.next() else {
        return Err(bad("fixture ID prefix required"));
    };
    let Some(kind) = parts.next() else {
        return Err(bad("fixture ID kind required"));
    };
    let Some(slug) = parts.next() else {
        return Err(bad("fixture ID slug required"));
    };
    if parts.next().is_some()
        || kind.is_empty()
        || !kind.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')
        || slug.is_empty()
        || slug.len() > 64
        || !slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(bad("invalid fixture ID form"));
    }
    if expected_kind.is_some_and(|expected| expected != kind) {
        return Err(bad("fixture ID kind mismatch"));
    }
    Ok(())
}

pub(crate) fn digest(value: &str) -> Result<(), ValidationError> {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return Err(bad("sha256 digest prefix required"));
    };
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(bad("invalid lowercase sha256 digest"));
    }
    Ok(())
}

fn text(value: &str) -> Result<(), ValidationError> {
    if value.is_empty() || value.len() > 4096 || value.trim().is_empty() {
        return Err(bad("text must be nonempty and at most 4096 UTF-8 bytes"));
    }
    Ok(())
}

fn code(value: &str) -> Result<(), ValidationError> {
    if value.is_empty()
        || value.len() > 64
        || !value.as_bytes()[0].is_ascii_uppercase()
        || !value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
    {
        return Err(bad("invalid uppercase code"));
    }
    Ok(())
}

fn version(value: u32) -> Result<(), ValidationError> {
    if value == 0 {
        Err(bad("version must be positive"))
    } else {
        Ok(())
    }
}

fn set<T: Serialize>(values: &[T]) -> Result<(), ValidationError> {
    let mut previous: Option<Vec<u8>> = None;
    for value in values {
        let bytes = serde_json::to_vec(value).map_err(|_| bad("set serialization failed"))?;
        if previous.as_ref().is_some_and(|old| *old >= bytes) {
            return Err(bad("set must be sorted and duplicate-free"));
        }
        previous = Some(bytes);
    }
    Ok(())
}

fn ids(values: &[String]) -> Result<(), ValidationError> {
    set(values)?;
    for value in values {
        fx_id(value, None)?;
    }
    Ok(())
}

fn codes(values: &[String]) -> Result<(), ValidationError> {
    set(values)?;
    for value in values {
        code(value)?;
    }
    Ok(())
}

fn texts(values: &[String]) -> Result<(), ValidationError> {
    set(values)?;
    for value in values {
        text(value)?;
    }
    Ok(())
}

fn claim(atom: &ClaimAtom) -> Result<(), ValidationError> {
    fx_id(&atom.project_binding_ref, Some("project"))?;
    text(&atom.resource_ref)?;
    code(&atom.action)?;
    code(&atom.effect)?;
    codes(&atom.lifecycle_contexts)?;
    if atom.lifecycle_contexts.is_empty() {
        return Err(bad("claim lifecycle contexts required"));
    }
    Ok(())
}

fn edge(edge: &OverrideEdge) -> Result<(), ValidationError> {
    fx_id(&edge.predecessor_claim_ref, Some("claim"))?;
    fx_id(&edge.successor_claim_ref, Some("claim"))?;
    set(&edge.coverage_atoms)?;
    for atom in &edge.coverage_atoms {
        claim(atom)?;
    }
    Ok(())
}

fn artifact(item: &ArtifactIdentity) -> Result<(), ValidationError> {
    fx_id(&item.artifact_ref, None)?;
    digest(&item.digest)
}

fn project(v: &ProjectBinding) -> Result<(), ValidationError> {
    fx_id(&v.project_id, Some("project"))?;
    text(&v.canonical_root)?;
    if !v.canonical_root.starts_with("fixture://")
        || v.canonical_root
            .eq_ignore_ascii_case("E:\\Pipeline\\titan-forward")
    {
        return Err(bad("fixture project root required"));
    }
    if v.repository_id.is_some() != v.repository_url.is_some()
        || v.repository_id == Some(1_396_000_355)
        || v.repository_id == Some(0)
        || v.repository_url.as_ref().is_some_and(|url| {
            url.trim_end_matches('/')
                .eq_ignore_ascii_case("https://github.com/Aimcurio/titan")
                || url.eq_ignore_ascii_case("https://github.com/Aimcurio/titan.git")
        })
    {
        return Err(bad("fixture repository binding invalid"));
    }
    if let Some(url) = &v.repository_url {
        text(url)?;
        if !url.starts_with("fixture://") {
            return Err(bad("fixture repository URL required"));
        }
    }
    fx_id(&v.authority_source_ref, None)?;
    version(v.binding_revision)
}

fn actor(v: &ActorBinding) -> Result<(), ValidationError> {
    fx_id(&v.actor_id, Some("actor"))?;
    fx_id(&v.principal_ref, None)?;
    fx_id(&v.auth_method_ref, None)?;
    set(&v.roles)?;
    if v.roles.is_empty() {
        return Err(bad("actor roles required"));
    }
    fx_id(&v.issued_by_ref, Some("actor"))?;
    if v.valid_until_ms.is_some_and(|end| end <= v.valid_from_ms) {
        return Err(bad("actor validity interval invalid"));
    }
    if let Some(value) = &v.revocation_ref {
        fx_id(value, None)?;
    }
    Ok(())
}

fn authority(v: &AuthorityRecord) -> Result<(), ValidationError> {
    fx_id(&v.authority_id, Some("authority"))?;
    fx_id(&v.issuer_actor_ref, Some("actor"))?;
    if let Some(value) = &v.target_binding_ref {
        fx_id(value, Some("project"))?;
    }
    if let Some(value) = &v.contract_digest {
        digest(value)?;
    }
    set(&v.claim_atoms)?;
    for atom in &v.claim_atoms {
        claim(atom)?;
    }
    set(&v.override_edges)?;
    for item in &v.override_edges {
        edge(item)?;
    }
    ids(&v.evidence_refs)?;
    if v.claim_atoms.is_empty()
        && !(matches!(
            v.class,
            AuthorityClass::Revocation | AuthorityClass::Reinstatement
        ) && !v.override_edges.is_empty())
    {
        return Err(bad("authority claim or revocation edge required"));
    }
    Ok(())
}

fn contract(v: &ExecutionContract) -> Result<(), ValidationError> {
    fx_id(&v.contract_id, Some("contract"))?;
    version(v.contract_version)?;
    text(&v.mission)?;
    fx_id(&v.project_binding_ref, Some("project"))?;
    fx_id(&v.target_ref, None)?;
    text(&v.expected_target_state)?;
    fx_id(&v.actor_ref, Some("actor"))?;
    code(&v.capability_code)?;
    codes(&v.allowed_operations)?;
    if v.allowed_operations.is_empty() {
        return Err(bad("allowed operation required"));
    }
    texts(&v.read_scopes)?;
    texts(&v.allowed_mutations)?;
    texts(&v.prohibited_mutations)?;
    ids(&v.precondition_refs)?;
    ids(&v.required_evidence_refs)?;
    ids(&v.verification_gate_refs)?;
    codes(&v.stop_codes)?;
    if v.stop_codes.is_empty() {
        return Err(bad("stop code required"));
    }
    fx_id(&v.escalation_ref, None)?;
    texts(&v.expected_deliverables)?;
    text(&v.requester_boundary)?;
    if v.network_allowed || v.secret_access_allowed || v.cross_surface_delivery_allowed {
        return Err(bad("F01 fixture contract access flags must be false"));
    }
    Ok(())
}

fn evidence(v: &EvidenceRef) -> Result<(), ValidationError> {
    fx_id(&v.evidence_id, Some("evidence"))?;
    code(&v.kind)?;
    text(&v.locator)?;
    if !v.locator.starts_with("fixture://") {
        return Err(bad("fixture evidence locator required"));
    }
    digest(&v.content_digest)?;
    fx_id(&v.producer_ref, None)?;
    text(&v.method)?;
    fx_id(&v.subject_ref, None)?;
    text(&v.subject_revision)?;
    fx_id(&v.contract_ref, Some("contract"))?;
    fx_id(&v.run_ref, Some("run"))?;
    if let Some(value) = &v.gate_ref {
        fx_id(value, None)?;
    }
    Ok(())
}

fn assessment(v: &Assessment) -> Result<(), ValidationError> {
    fx_id(&v.assessment_id, Some("assessment"))?;
    fx_id(&v.subject_ref, None)?;
    ids(&v.gate_result_refs)?;
    fx_id(&v.verifier_actor_ref, Some("actor"))?;
    ids(&v.evidence_refs)?;
    text(&v.reason)
}

fn eligibility(v: &PromotionEligibilityRecord) -> Result<(), ValidationError> {
    fx_id(&v.eligibility_id, Some("eligibility"))?;
    fx_id(&v.candidate_ref, None)?;
    text(&v.candidate_revision)?;
    fx_id(&v.expected_prior_canonical_ref, None)?;
    text(&v.expected_prior_canonical_version)?;
    fx_id(&v.promotion_subject_ref, None)?;
    text(&v.promotion_scope)?;
    fx_id(&v.contract_ref, Some("contract"))?;
    digest(&v.contract_digest)?;
    fx_id(&v.authorization_ref, None)?;
    fx_id(&v.policy_ref, None)?;
    version(v.policy_version)?;
    fx_id(&v.assurance_rule_ref, None)?;
    version(v.assurance_rule_version)?;
    version(v.eligibility_rule_version)?;
    fx_id(&v.evidence_set_ref, None)?;
    set(&v.evidence_artifacts)?;
    for item in &v.evidence_artifacts {
        artifact(item)?;
    }
    ids(&v.verification_result_refs)?;
    ids(&v.approval_refs)?;
    fx_id(&v.authority_state_ref, None)?;
    ids(&v.input_refs)
}

fn checkpoint(v: &Checkpoint) -> Result<(), ValidationError> {
    fx_id(&v.checkpoint_id, Some("checkpoint"))?;
    fx_id(&v.run_ref, Some("run"))?;
    digest(&v.contract_digest)?;
    fx_id(&v.target_ref, None)?;
    text(&v.target_state)?;
    text(&v.last_valid_step)?;
    ids(&v.completed_gate_refs)?;
    codes(&v.blocker_codes)?;
    ids(&v.evidence_refs)?;
    text(&v.pending_action)?;
    ids(&v.partial_effect_refs)?;
    fx_id(&v.resume_authority_ref, None)
}

fn outcome(v: &Outcome) -> Result<(), ValidationError> {
    fx_id(&v.outcome_id, Some("outcome"))?;
    fx_id(&v.scope_ref, None)?;
    ids(&v.evidence_refs)?;
    text(&v.next_action)?;
    text(&v.detail)
}

pub(crate) fn validate_record(record: &RecordEnvelope) -> Result<(), ValidationError> {
    if record.schema_version != 1 {
        return Err(bad("UNSUPPORTED_VERSION"));
    }
    if record.namespace != Namespace::Fixture {
        return Err(bad("operational namespace rejected by F01"));
    }
    let kind = match record.record_type {
        RecordType::ProjectBinding => "project",
        RecordType::ActorBinding => "actor",
        RecordType::AuthorityRecord => "authority",
        RecordType::ExecutionContract => "contract",
        RecordType::EvidenceRef => "evidence",
        RecordType::Assessment => "assessment",
        RecordType::PromotionEligibilityRecord => "eligibility",
        RecordType::Checkpoint => "checkpoint",
        RecordType::Outcome => "outcome",
    };
    fx_id(&record.record_id, Some(kind))?;
    fx_id(&record.creator_ref, Some("actor"))?;
    if record.payload.record_type() != record.record_type
        || record.payload.primary_id() != record.record_id
    {
        return Err(bad("record type or payload identity mismatch"));
    }
    match &record.payload {
        RecordPayload::ProjectBinding(v) => project(v),
        RecordPayload::ActorBinding(v) => actor(v),
        RecordPayload::AuthorityRecord(v) => authority(v),
        RecordPayload::ExecutionContract(v) => contract(v),
        RecordPayload::EvidenceRef(v) => evidence(v),
        RecordPayload::Assessment(v) => assessment(v),
        RecordPayload::PromotionEligibilityRecord(v) => eligibility(v),
        RecordPayload::Checkpoint(v) => checkpoint(v),
        RecordPayload::Outcome(v) => outcome(v),
    }?;
    digest(&record.integrity)
}
