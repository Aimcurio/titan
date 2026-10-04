//! Closed fixture K5 record checks. Supplied PASS is not approval or operational authority.
use crate::{
    codec::{ValidatedRecord, validate_bytes},
    evidence::{FixtureStoreV1, hash, replay_fixture_history},
    fixture_projection::{FixtureAuthoritySeedV1, FixtureProjection},
    records::{
        ActorBinding, AssessmentDecision, BindingState, EvidenceStatus, RecordPayload, Role,
    },
};
use serde::{Deserialize, Serialize};
use std::{fs, io::Read, path::Path};
pub const POLICY: &str = "F06_FIXTURE_ASSURANCE_POLICY_V1";
pub const RULE: &str = "F06_ELIGIBILITY_RULE_V1";
pub const ROOT: &str =
    r"C:\Users\15103\Documents\Codex\2026-09-29\files-pasted-by-the-user-titan\work\f06-fixtures";
pub const VERIFICATION_DOMAIN: &[u8] = b"TITAN-FWD-F06\0verification-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum F06Error {
    IneligibleVerification,
    IneligibleApproval,
    BlockedIdentityMismatch,
    BlockedEvidenceInvalid,
    BlockedIndependenceRequired,
    BlockedPolicyStale,
    BlockedAuthorityStale,
    BlockedIncompleteBasis,
    BlockedIntegrity,
    BlockedEnvironment,
}
pub type F06Result<T> = Result<T, F06Error>;
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsequenceV1 {
    LowImpactFixture,
    HighImpactFixture,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum SelfVerificationV1 {
    SelfVerificationAllowed,
    IndependentOnly,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureAssurancePolicyV1 {
    pub profile: String,
    pub version: u32,
    pub low_impact: Option<SelfVerificationV1>,
}
impl FixtureAssurancePolicyV1 {
    pub fn digest(&self) -> F06Result<String> {
        body_digest(b"TITAN-FWD-F06\0policy-v1\0", self)
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IndependenceV1 {
    Independent,
    SelfVerification,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum VerificationOutcomeV1 {
    Pass,
    Fail,
    Blocked,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCandidateV1 {
    pub namespace: String,
    pub version: u32,
    pub project_id: String,
    pub candidate_id: String,
    pub revision: String,
    pub content_digest: String,
    pub subject_id: String,
    pub subject_revision: String,
    pub scope: String,
    pub contract_id: String,
    pub contract_digest: String,
    pub run_id: String,
    pub effect_receipt_id: Option<String>,
    pub executor_actor_id: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedPriorCanonicalV1 {
    pub namespace: String,
    pub pointer_id: String,
    pub subject_id: String,
    pub scope: String,
    pub genesis: bool,
    pub candidate_id: Option<String>,
    pub candidate_digest: Option<String>,
    pub version: Option<u64>,
}
impl ExpectedPriorCanonicalV1 {
    pub(crate) fn validate(&self, c: &FixtureCandidateV1) -> F06Result<()> {
        if self.namespace != "FIXTURE"
            || !fx(&self.pointer_id, "canonical")
            || self.subject_id != c.subject_id
            || self.scope != c.scope
            || self.version.is_none()
        {
            return Err(F06Error::BlockedIncompleteBasis);
        }
        let valid = if self.genesis {
            self.version == Some(0)
                && self.candidate_id.is_none()
                && self.candidate_digest.is_none()
        } else {
            self.version.is_some_and(|v| v > 0)
                && self
                    .candidate_id
                    .as_ref()
                    .is_some_and(|s| fx(s, "candidate"))
                && self.candidate_digest.as_ref().is_some_and(|s| digest(s))
        };
        if !valid {
            return Err(F06Error::BlockedIncompleteBasis);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEvidenceArtifactV1 {
    pub namespace: String,
    pub version: u32,
    pub candidate_id: String,
    pub candidate_revision: String,
    pub candidate_digest: String,
    pub candidate_bytes: Vec<u8>,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEvidenceMemberV1 {
    pub evidence_id: String,
    pub record_digest: String,
    pub content_digest: String,
    pub producer_actor_id: String,
    pub method: String,
    pub subject_id: String,
    pub subject_revision: String,
    pub contract_id: String,
    pub contract_digest: String,
    pub run_id: String,
    pub gate_id: String,
    pub status: EvidenceStatus,
    pub candidate_digest: String,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEvidenceSetV1 {
    pub evidence_set_id: String,
    pub digest: String,
    pub members: Vec<FixtureEvidenceMemberV1>,
}
/// Transport for externally supplied records, not a signing or approval factory.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureRecordV1<T> {
    pub body: T,
    pub body_digest: String,
    pub record_id: String,
}
pub(crate) fn decode_record<T: for<'a> Deserialize<'a> + Serialize>(
    bytes: &[u8],
    domain: &[u8],
    kind: &str,
) -> F06Result<FixtureRecordV1<T>> {
    if bytes.is_empty() || bytes.len() > 1_048_576 {
        return Err(F06Error::BlockedIntegrity);
    }
    let r: FixtureRecordV1<T> =
        serde_json::from_slice(bytes).map_err(|_| F06Error::BlockedIntegrity)?;
    let d = body_digest(domain, &r.body)?;
    if serde_json::to_vec(&r).map_err(|_| F06Error::BlockedIntegrity)? != bytes
        || r.body_digest != d
        || r.record_id != format!("fx:{kind}:{}", &d[7..])
    {
        return Err(F06Error::BlockedIntegrity);
    }
    Ok(r)
}
pub(crate) fn body_digest<T: Serialize>(domain: &[u8], body: &T) -> F06Result<String> {
    Ok(hash(
        domain,
        &serde_json::to_vec(body).map_err(|_| F06Error::BlockedIntegrity)?,
    ))
}
pub(crate) fn digest(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}
pub(crate) fn fx(s: &str, kind: &str) -> bool {
    s.strip_prefix(&format!("fx:{kind}:")).is_some_and(|v| {
        !v.is_empty()
            && v.len() <= 64
            && v.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    })
}
pub(crate) fn actor(
    seed: &FixtureAuthoritySeedV1,
    id: &str,
    role: Role,
    epoch: u64,
) -> F06Result<(ActorBinding, String)> {
    let mut matches = Vec::new();
    for bytes in &seed.actor_records {
        let r = validate_bytes(bytes).map_err(|_| F06Error::BlockedIntegrity)?;
        if let RecordPayload::ActorBinding(a) = &r.record().payload
            && a.actor_id == id
        {
            matches.push((a.clone(), r.record().integrity.clone()));
        }
    }
    if matches.len() != 1 {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    let (a, d) = matches.pop().expect("one actor");
    if !a.roles.contains(&role)
        || a.revocation_ref.is_some()
        || epoch < a.valid_from_ms
        || a.valid_until_ms.is_some_and(|end| epoch >= end)
    {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    Ok((a, d))
}
pub(crate) fn validate_context(
    c: &FixtureCandidateV1,
    project: &ValidatedRecord,
    contract: &ValidatedRecord,
    seed: &FixtureAuthoritySeedV1,
    state: &FixtureProjection,
    epoch: u64,
) -> F06Result<()> {
    state
        .verify_state_identity()
        .map_err(|_| F06Error::BlockedAuthorityStale)?;
    if seed.digest().map_err(|_| F06Error::BlockedAuthorityStale)? != state.seed_digest
        || seed.project_record != project.canonical_bytes()
        || state.project_binding_id != c.project_id
    {
        return Err(F06Error::BlockedAuthorityStale);
    }
    let RecordPayload::ProjectBinding(p) = &project.record().payload else {
        return Err(F06Error::BlockedIdentityMismatch);
    };
    let RecordPayload::ExecutionContract(k) = &contract.record().payload else {
        return Err(F06Error::BlockedIdentityMismatch);
    };
    if p.project_id != c.project_id
        || p.state != BindingState::Active
        || k.project_binding_ref != c.project_id
        || k.contract_id != c.contract_id
        || contract.record().integrity != c.contract_digest
        || k.target_ref != c.subject_id
        || k.actor_ref != c.executor_actor_id
        || epoch == 0
        || c.namespace != "FIXTURE"
        || c.version != 1
        || c.revision.is_empty()
        || c.revision.len() > 64
        || !fx(&c.candidate_id, "candidate")
        || !fx(&c.subject_id, "target")
        || !fx(&c.run_id, "run")
        || !digest(&c.content_digest)
        || c.subject_revision.is_empty()
        || !k
            .read_scopes
            .iter()
            .chain(&k.allowed_mutations)
            .any(|scope| {
                scope == &c.scope
                    || scope.strip_suffix("/*").is_some_and(|base| {
                        state.profile.canonical_resource(base).ok().as_deref() == Some(base)
                            && c.scope.starts_with(&format!("{base}/"))
                    })
            })
        || state.profile.canonical_resource(&c.scope).ok().as_ref() != Some(&c.scope)
    {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    actor(seed, &c.executor_actor_id, Role::Executor, epoch)?;
    Ok(())
}
pub(crate) fn candidate_bytes(c: &FixtureCandidateV1) -> F06Result<Vec<u8>> {
    let case = c
        .candidate_id
        .strip_prefix("fx:candidate:")
        .filter(|_| fx(&c.candidate_id, "candidate"))
        .ok_or(F06Error::BlockedIdentityMismatch)?;
    let root = Path::new(ROOT);
    let parent = root.join("cases").join(case);
    for p in parent.ancestors() {
        let m = fs::symlink_metadata(p).map_err(|_| F06Error::BlockedEnvironment)?;
        let mut link = m.file_type().is_symlink();
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            link |= m.file_attributes() & 0x400 != 0;
        }
        if link || !m.is_dir() {
            return Err(F06Error::BlockedEnvironment);
        }
    }
    let path = parent.join("candidate.json");
    let before = fs::symlink_metadata(&path).map_err(|_| F06Error::BlockedEnvironment)?;
    let mut link = before.file_type().is_symlink();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        link |= before.file_attributes() & 0x400 != 0;
    }
    if link || !before.is_file() || before.len() > 65536 {
        return Err(F06Error::BlockedEnvironment);
    }
    let canonical = fs::canonicalize(&path).map_err(|_| F06Error::BlockedEnvironment)?;
    if !canonical.starts_with(fs::canonicalize(root).map_err(|_| F06Error::BlockedEnvironment)?) {
        return Err(F06Error::BlockedEnvironment);
    }
    let mut file = fs::File::open(&path).map_err(|_| F06Error::BlockedEnvironment)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(65537)
        .read_to_end(&mut bytes)
        .map_err(|_| F06Error::BlockedEnvironment)?;
    let after = fs::symlink_metadata(&path).map_err(|_| F06Error::BlockedEnvironment)?;
    let mut after_link = after.file_type().is_symlink();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        after_link |= after.file_attributes() & 0x400 != 0;
    }
    if after_link
        || !after.is_file()
        || bytes.len() > 65536
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || fs::canonicalize(&path).ok().as_ref() != Some(&canonical)
    {
        return Err(F06Error::BlockedEnvironment);
    }
    let record = validate_bytes(&bytes).map_err(|_| F06Error::BlockedIntegrity)?;
    if hash(b"", &bytes) != c.content_digest {
        return Err(F06Error::BlockedIntegrity);
    }
    if record.record().creator_ref != c.executor_actor_id {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    let RecordPayload::Outcome(o) = &record.record().payload else {
        return Err(F06Error::BlockedIdentityMismatch);
    };
    if o.scope_ref != c.run_id {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    Ok(bytes)
}
/// Read-only current F04 basis, exact contract-required membership, order-independent identity.
pub fn bind_fixture_evidence_set(
    store: &FixtureStoreV1,
    c: &FixtureCandidateV1,
    contract: &ValidatedRecord,
    ids: &[String],
) -> F06Result<FixtureEvidenceSetV1> {
    let RecordPayload::ExecutionContract(k) = &contract.record().payload else {
        return Err(F06Error::BlockedIdentityMismatch);
    };
    let mut names = ids.to_vec();
    names.sort();
    if names.is_empty()
        || names.windows(2).any(|w| w[0] == w[1])
        || names != k.required_evidence_refs
    {
        return Err(F06Error::BlockedEvidenceInvalid);
    }
    let h = replay_fixture_history(store).map_err(|_| F06Error::BlockedEvidenceInvalid)?;
    if !h.unresolved_fingerprints().is_empty() || h.blockers.values().any(|(_, active)| *active) {
        return Err(F06Error::BlockedEvidenceInvalid);
    }
    let mut members = Vec::new();
    for id in names {
        if !h.current_evidence(&id) {
            return Err(F06Error::BlockedEvidenceInvalid);
        }
        let (e, contract_digest) = h
            .observations
            .get(&id)
            .ok_or(F06Error::BlockedEvidenceInvalid)?;
        let d = h
            .observation_digests
            .get(&id)
            .ok_or(F06Error::BlockedEvidenceInvalid)?;
        if e.subject_ref != c.subject_id
            || e.subject_revision != c.subject_revision
            || e.contract_ref != c.contract_id
            || contract_digest != &c.contract_digest
            || e.run_ref != c.run_id
            || e.method != "FIXTURE_PROBE"
            || e.gate_ref
                .as_ref()
                .is_none_or(|g| !k.verification_gate_refs.contains(g))
        {
            return Err(F06Error::BlockedEvidenceInvalid);
        }
        let raw = store
            .read_raw(&e.locator, &e.content_digest)
            .map_err(|_| F06Error::BlockedEvidenceInvalid)?;
        let a: FixtureEvidenceArtifactV1 =
            serde_json::from_slice(&raw).map_err(|_| F06Error::BlockedEvidenceInvalid)?;
        if serde_json::to_vec(&a).map_err(|_| F06Error::BlockedEvidenceInvalid)? != raw
            || a.namespace != "FIXTURE"
            || a.version != 1
            || a.candidate_id != c.candidate_id
            || a.candidate_revision != c.revision
            || a.candidate_digest != c.content_digest
            || hash(b"", &a.candidate_bytes) != c.content_digest
            || validate_bytes(&a.candidate_bytes).is_err()
        {
            return Err(F06Error::BlockedEvidenceInvalid);
        }
        members.push(FixtureEvidenceMemberV1 {
            evidence_id: id,
            record_digest: d.clone(),
            content_digest: e.content_digest.clone(),
            producer_actor_id: e.producer_ref.clone(),
            method: e.method.clone(),
            subject_id: e.subject_ref.clone(),
            subject_revision: e.subject_revision.clone(),
            contract_id: e.contract_ref.clone(),
            contract_digest: contract_digest.clone(),
            run_id: e.run_ref.clone(),
            gate_id: e.gate_ref.clone().expect("checked gate"),
            status: EvidenceStatus::Current,
            candidate_digest: c.content_digest.clone(),
        });
    }
    let digest = body_digest(b"TITAN-FWD-F06\0evidence-set-v1\0", &members)?;
    Ok(FixtureEvidenceSetV1 {
        evidence_set_id: format!("fx:evidence-set:{}", &digest[7..]),
        digest,
        members,
    })
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureVerificationBodyV1 {
    pub namespace: String,
    pub version: u32,
    pub candidate: FixtureCandidateV1,
    pub evidence_set_id: String,
    pub evidence_set_digest: String,
    pub method: String,
    pub method_version: u32,
    pub verifier_actor_id: String,
    pub producer_actor_id: String,
    pub verifier_binding_digest: String,
    pub display_name: String,
    pub independence: IndependenceV1,
    pub consequence: ConsequenceV1,
    pub policy_id: String,
    pub policy_version: u32,
    pub policy_digest: String,
    pub rule_id: String,
    pub rule_version: u32,
    pub authority_state_id: String,
    pub authorization_id: String,
    pub authorization_digest: String,
    pub expected_prior: ExpectedPriorCanonicalV1,
    pub assessment_bytes: Vec<u8>,
    pub outcome: VerificationOutcomeV1,
}
pub type FixtureVerificationRecordV1 = FixtureRecordV1<FixtureVerificationBodyV1>;
pub(crate) fn validate_verification(
    v: &FixtureVerificationBodyV1,
    c: &FixtureCandidateV1,
    set: &FixtureEvidenceSetV1,
    seed: &FixtureAuthoritySeedV1,
    policy: &FixtureAssurancePolicyV1,
    epoch: u64,
) -> F06Result<()> {
    if v.namespace != "FIXTURE"
        || v.version != 1
        || &v.candidate != c
        || v.evidence_set_id != set.evidence_set_id
        || v.evidence_set_digest != set.digest
        || v.method != "FIXTURE_KNOWN_ANSWER_V1"
        || v.method_version != 1
        || v.verifier_actor_id != v.producer_actor_id
    {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    let (verifier, d) = actor(seed, &v.verifier_actor_id, Role::Verifier, epoch)?;
    let (executor, _) = actor(seed, &c.executor_actor_id, Role::Executor, epoch)?;
    if d != v.verifier_binding_digest {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    let independent =
        verifier.actor_id != executor.actor_id && verifier.principal_ref != executor.principal_ref;
    if (independent && v.independence != IndependenceV1::Independent)
        || (!independent
            && (v.independence != IndependenceV1::SelfVerification
                || v.consequence == ConsequenceV1::HighImpactFixture
                || policy.low_impact != Some(SelfVerificationV1::SelfVerificationAllowed)))
    {
        return Err(F06Error::BlockedIndependenceRequired);
    }
    let a = validate_bytes(&v.assessment_bytes).map_err(|_| F06Error::BlockedIntegrity)?;
    let RecordPayload::Assessment(assessment) = &a.record().payload else {
        return Err(F06Error::BlockedIntegrity);
    };
    let result = match v.outcome {
        VerificationOutcomeV1::Pass => AssessmentDecision::Pass,
        VerificationOutcomeV1::Fail => AssessmentDecision::Fail,
        VerificationOutcomeV1::Blocked => AssessmentDecision::Blocked,
        VerificationOutcomeV1::Unknown => AssessmentDecision::Unknown,
    };
    let ids = set
        .members
        .iter()
        .map(|m| m.evidence_id.clone())
        .collect::<Vec<_>>();
    if assessment.subject_ref != c.candidate_id
        || assessment.verifier_actor_ref != v.verifier_actor_id
        || a.record().creator_ref != v.verifier_actor_id
        || assessment.independence_claimed != independent
        || assessment.evidence_refs != ids
        || assessment.decision != result
    {
        return Err(F06Error::BlockedIdentityMismatch);
    }
    if v.outcome != VerificationOutcomeV1::Pass {
        return Err(F06Error::IneligibleVerification);
    }
    Ok(())
}
