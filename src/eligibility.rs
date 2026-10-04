//! Fixture-only K5. This module validates external approval; it cannot issue one.
use crate::{
    authority::resolve_fixture_request,
    codec::{ValidatedRecord, validate_bytes},
    evidence::{FixtureEventV1, FixtureStoreV1, replay_fixture_history},
    fixture_projection::{FixtureAuthoritySeedV1, FixtureProjection},
    records::{
        AuthorityClass, ClaimAtom, EvidenceStatus, Provision, RecordPayload, ResourceMatch, Role,
    },
    selector::normalize_fixture_selector,
    verification::{self as v, *},
};
use serde::{Deserialize, Serialize};
pub const APPROVAL_DOMAIN: &[u8] = b"TITAN-FWD-F06\0approval-v1\0";
const ELIGIBILITY_DOMAIN: &[u8] = b"TITAN-FWD-F06\0eligibility-v1\0";
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ApprovalDecisionV1 {
    Approve,
    Deny,
}
/// External inert approval transport. No F06 approval constructor exists.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureApprovalBodyV1 {
    pub namespace: String,
    pub version: u32,
    pub candidate: FixtureCandidateV1,
    pub approver_actor_id: String,
    pub approver_binding_digest: String,
    pub required_role: Role,
    pub authorization_id: String,
    pub authorization_digest: String,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_digest: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub consequence: ConsequenceV1,
    pub expected_prior: ExpectedPriorCanonicalV1,
    pub authority_state_id: String,
    pub status_state_ref: String,
    pub status: EvidenceStatus,
    pub valid_from_epoch: u64,
    pub valid_until_epoch: u64,
    pub decision: ApprovalDecisionV1,
    /// F02-accepted Decision claim authorizing this approver for the exact scope.
    /// This is not manufactured or refreshed by K5.
    pub governing_decision_bytes: Vec<u8>,
}
pub type FixtureApprovalRecordV1 = FixtureRecordV1<FixtureApprovalBodyV1>;
pub struct FixtureEligibilityInput<'a> {
    pub candidate: &'a FixtureCandidateV1,
    pub project: &'a ValidatedRecord,
    pub contract: &'a ValidatedRecord,
    pub seed: &'a FixtureAuthoritySeedV1,
    pub authority_state: &'a FixtureProjection,
    pub expected_authority_state_id: &'a str,
    pub authorization: &'a ValidatedRecord,
    pub store: &'a FixtureStoreV1,
    pub evidence_set: &'a FixtureEvidenceSetV1,
    pub verification_bytes: &'a [u8],
    pub approval_bytes: Option<&'a [u8]>,
    pub policy: &'a FixtureAssurancePolicyV1,
    pub consequence: ConsequenceV1,
    pub rule_version: u32,
    pub expected_prior: Option<&'a ExpectedPriorCanonicalV1>,
    pub evaluation_epoch: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct EligibilityBodyV1 {
    namespace: &'static str,
    version: u32,
    outcome: &'static str,
    candidate: FixtureCandidateV1,
    candidate_record_digest: String,
    project_digest: String,
    contract_digest: String,
    seed_digest: String,
    authorization_id: String,
    authorization_digest: String,
    assurance_policy: FixtureAssurancePolicyV1,
    policy_digest: String,
    eligibility_rule: &'static str,
    rule_version: u32,
    consequence: ConsequenceV1,
    evidence_set: FixtureEvidenceSetV1,
    history_id: String,
    history_head: String,
    verification: FixtureVerificationRecordV1,
    approval: FixtureApprovalRecordV1,
    executor_binding_digest: String,
    authority_state_id: String,
    expected_prior: ExpectedPriorCanonicalV1,
    evaluation_epoch: u64,
}
/// Immutable output: no deserializer, public fields, setter, or transition method.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixturePromotionEligibilityV1 {
    body: EligibilityBodyV1,
    body_digest: String,
    record_id: String,
    #[serde(skip)]
    canonical_bytes: Vec<u8>,
}
impl FixturePromotionEligibilityV1 {
    pub fn canonical_bytes(&self) -> &[u8] {
        &self.canonical_bytes
    }
    pub fn record_id(&self) -> &str {
        &self.record_id
    }
    pub fn body_digest(&self) -> &str {
        &self.body_digest
    }
}
fn governing_decision(
    r: &ValidatedRecord,
    i: &FixtureEligibilityInput<'_>,
    action: &str,
    provision: Provision,
) -> F06Result<String> {
    let RecordPayload::AuthorityRecord(a) = &r.record().payload else {
        return Err(F06Error::BlockedAuthorityStale);
    };
    if a.class != AuthorityClass::Decision
        || a.exercised_role != Role::DecisionAuthority
        || r.record().creator_ref != a.issuer_actor_ref
        || a.effective_at_ms > i.evaluation_epoch
        || a.target_binding_ref.as_ref() != Some(&i.candidate.project_id)
        || a.contract_digest.as_ref() != Some(&i.candidate.contract_digest)
        || i.authority_state.accepted_records.get(&a.authority_id) != Some(&r.record().integrity)
    {
        return Err(F06Error::BlockedAuthorityStale);
    }
    v::actor(
        i.seed,
        &a.issuer_actor_ref,
        Role::DecisionAuthority,
        i.evaluation_epoch,
    )?;
    let request = normalize_fixture_selector(
        &ClaimAtom {
            project_binding_ref: i.candidate.project_id.clone(),
            resource_ref: i.candidate.scope.clone(),
            resource_match: ResourceMatch::Exact,
            action: action.into(),
            provision: provision.clone(),
            effect: "PROMOTION_ELIGIBILITY".into(),
            lifecycle_contexts: vec!["READY".into()],
        },
        &i.authority_state.profile,
    )
    .map_err(|_| F06Error::BlockedAuthorityStale)?;
    let resolved =
        resolve_fixture_request(i.authority_state, i.expected_authority_state_id, &request)
            .map_err(|_| F06Error::BlockedAuthorityStale)?;
    if resolved.cells.is_empty()
        || resolved.cells.iter().any(|cell| {
            cell.provision != provision
                || !cell.governing_claim_ids.iter().any(|id| {
                    i.authority_state
                        .claims
                        .get(id)
                        .is_some_and(|claim| claim.source_record_id == a.authority_id)
                })
        })
    {
        return Err(F06Error::BlockedAuthorityStale);
    }
    Ok(a.issuer_actor_ref.clone())
}
/// Read-only evaluation. Neither F02 events nor F03/F05 execution APIs are called.
pub fn evaluate_fixture_eligibility_v1(
    i: FixtureEligibilityInput<'_>,
) -> F06Result<FixturePromotionEligibilityV1> {
    let c = i.candidate;
    v::validate_context(
        c,
        i.project,
        i.contract,
        i.seed,
        i.authority_state,
        i.evaluation_epoch,
    )?;
    if i.policy.profile != POLICY || i.policy.version != 1 || i.rule_version != 1 {
        return Err(F06Error::BlockedPolicyStale);
    }
    if i.expected_authority_state_id != i.authority_state.state_id {
        return Err(F06Error::BlockedAuthorityStale);
    }
    let prior = i.expected_prior.ok_or(F06Error::BlockedIncompleteBasis)?;
    prior.validate(c)?;
    let bytes = v::candidate_bytes(c)?;
    let candidate_record = validate_bytes(&bytes).map_err(|_| F06Error::BlockedIntegrity)?;
    governing_decision(i.authorization, &i, "CONSIDER_PROMOTION", Provision::Permit)?;
    let names = i
        .evidence_set
        .members
        .iter()
        .map(|m| m.evidence_id.clone())
        .collect::<Vec<_>>();
    let current = bind_fixture_evidence_set(i.store, c, i.contract, &names)?;
    if &current != i.evidence_set {
        return Err(F06Error::BlockedEvidenceInvalid);
    }
    for m in &current.members {
        if v::actor(
            i.seed,
            &m.producer_actor_id,
            Role::Verifier,
            i.evaluation_epoch,
        )
        .is_err()
            && v::actor(
                i.seed,
                &m.producer_actor_id,
                Role::Executor,
                i.evaluation_epoch,
            )
            .is_err()
        {
            return Err(F06Error::BlockedIdentityMismatch);
        }
    }
    let history = replay_fixture_history(i.store).map_err(|_| F06Error::BlockedEvidenceInvalid)?;
    let seed_digest = i
        .seed
        .digest()
        .map_err(|_| F06Error::BlockedAuthorityStale)?;
    for entry in &history.entries {
        if let FixtureEventV1::Observation {
            seed_digest: observed_seed,
            producer,
            ..
        } = &entry.event
            && (observed_seed != &seed_digest || !i.seed.actor_records.contains(producer))
        {
            return Err(F06Error::BlockedEvidenceInvalid);
        }
    }
    if let Some(receipt) = &c.effect_receipt_id {
        let matches = history.entries.iter().any(|entry| {
            &entry.entry_id == receipt
                && entry.run_id == c.run_id
                && match &entry.event {
                    FixtureEventV1::Outcome { record, .. } => record == &bytes,
                    _ => false,
                }
        });
        if !matches {
            return Err(F06Error::BlockedEvidenceInvalid);
        }
    }
    let verification: FixtureVerificationRecordV1 =
        v::decode_record(i.verification_bytes, VERIFICATION_DOMAIN, "verification")?;
    let b = &verification.body;
    let policy_digest = i.policy.digest()?;
    if b.policy_id != POLICY
        || b.policy_version != 1
        || b.policy_digest != policy_digest
        || b.rule_id != RULE
        || b.rule_version != 1
    {
        return Err(F06Error::BlockedPolicyStale);
    }
    if b.authority_state_id != i.authority_state.state_id {
        return Err(F06Error::BlockedAuthorityStale);
    }
    if b.authorization_id != i.authorization.record().record_id
        || b.authorization_digest != i.authorization.record().integrity
        || &b.expected_prior != prior
        || b.consequence != i.consequence
    {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    v::validate_verification(b, c, &current, i.seed, i.policy, i.evaluation_epoch)?;
    let assessment = validate_bytes(&b.assessment_bytes).map_err(|_| F06Error::BlockedIntegrity)?;
    let RecordPayload::Assessment(a) = &assessment.record().payload else {
        return Err(F06Error::BlockedIntegrity);
    };
    let RecordPayload::ExecutionContract(k) = &i.contract.record().payload else {
        return Err(F06Error::BlockedIdentityMismatch);
    };
    if k.verification_gate_refs.is_empty() || a.gate_result_refs != k.verification_gate_refs {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    let approval: FixtureApprovalRecordV1 = v::decode_record(
        i.approval_bytes.ok_or(F06Error::IneligibleApproval)?,
        APPROVAL_DOMAIN,
        "approval",
    )?;
    let a = &approval.body;
    if a.decision != ApprovalDecisionV1::Approve {
        return Err(F06Error::IneligibleApproval);
    }
    if a.namespace != "FIXTURE"
        || a.version != 1
        || &a.candidate != c
        || a.required_role != Role::DecisionAuthority
        || a.authorization_id != i.authorization.record().record_id
        || a.authorization_digest != i.authorization.record().integrity
        || &a.expected_prior != prior
        || a.consequence != i.consequence
    {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    if a.policy_id != POLICY
        || a.policy_version != 1
        || a.policy_digest != policy_digest
        || a.rule_id != RULE
        || a.rule_version != 1
    {
        return Err(F06Error::BlockedPolicyStale);
    }
    if a.authority_state_id != i.authority_state.state_id
        || a.status_state_ref != i.authority_state.state_id
    {
        return Err(F06Error::BlockedAuthorityStale);
    }
    if a.status != EvidenceStatus::Current
        || a.valid_from_epoch >= a.valid_until_epoch
        || i.evaluation_epoch < a.valid_from_epoch
        || i.evaluation_epoch >= a.valid_until_epoch
    {
        return Err(F06Error::IneligibleApproval);
    }
    let (_, approver_digest) = v::actor(
        i.seed,
        &a.approver_actor_id,
        Role::DecisionAuthority,
        i.evaluation_epoch,
    )?;
    if approver_digest != a.approver_binding_digest {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    let decision =
        validate_bytes(&a.governing_decision_bytes).map_err(|_| F06Error::BlockedIntegrity)?;
    if governing_decision(&decision, &i, "APPROVE", Provision::Approve)? != a.approver_actor_id {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    let (_, executor_binding_digest) = v::actor(
        i.seed,
        &c.executor_actor_id,
        Role::Executor,
        i.evaluation_epoch,
    )?;
    // Establish a stable observed basis across the bounded read sequence. No
    // lock or future transition freshness is claimed; F07 must re-resolve it.
    if v::candidate_bytes(c)? != bytes
        || bind_fixture_evidence_set(i.store, c, i.contract, &names)? != current
        || replay_fixture_history(i.store)
            .map_err(|_| F06Error::BlockedEvidenceInvalid)?
            .head_id()
            != history.head_id()
    {
        return Err(F06Error::BlockedEvidenceInvalid);
    }
    let body = EligibilityBodyV1 {
        namespace: "FIXTURE",
        version: 1,
        outcome: "ELIGIBLE",
        candidate: c.clone(),
        candidate_record_digest: candidate_record.record().integrity.clone(),
        project_digest: i.project.record().integrity.clone(),
        contract_digest: i.contract.record().integrity.clone(),
        seed_digest: i
            .seed
            .digest()
            .map_err(|_| F06Error::BlockedAuthorityStale)?,
        authorization_id: i.authorization.record().record_id.clone(),
        authorization_digest: i.authorization.record().integrity.clone(),
        assurance_policy: i.policy.clone(),
        policy_digest,
        eligibility_rule: RULE,
        rule_version: 1,
        consequence: i.consequence,
        evidence_set: current,
        history_id: history
            .history_id(i.store.case_id())
            .map_err(|_| F06Error::BlockedEvidenceInvalid)?,
        history_head: history.head_id().into(),
        verification,
        approval,
        executor_binding_digest,
        authority_state_id: i.authority_state.state_id.clone(),
        expected_prior: prior.clone(),
        evaluation_epoch: i.evaluation_epoch,
    };
    let body_digest = v::body_digest(ELIGIBILITY_DOMAIN, &body)?;
    let mut record = FixturePromotionEligibilityV1 {
        record_id: format!("fx:eligibility:{}", &body_digest[7..]),
        body,
        body_digest,
        canonical_bytes: Vec::new(),
    };
    record.canonical_bytes = serde_json::to_vec(&record).map_err(|_| F06Error::BlockedIntegrity)?;
    Ok(record)
}
/// Never refreshes a previous determination. A changed valid basis is still stale for reuse.
pub fn validate_fixture_eligibility_reuse_v1(
    record: &FixturePromotionEligibilityV1,
    input: FixtureEligibilityInput<'_>,
) -> F06Result<()> {
    let current = evaluate_fixture_eligibility_v1(input)?;
    if current.canonical_bytes() != record.canonical_bytes() {
        return Err(F06Error::BlockedIncompleteBasis);
    }
    Ok(())
}
