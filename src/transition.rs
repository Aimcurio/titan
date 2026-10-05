//! Test-only K2. The imported SQLite rows, not external files, are its transaction domain.
//! A digest proves byte identity only; this adapter enrolls no operational authority.
use crate::{
    eligibility::{
        FixtureEligibilityInput, FixturePromotionEligibilityV1,
        validate_fixture_eligibility_reuse_v1,
    },
    evidence::{hash, replay_fixture_history},
    fixture_projection::FixtureAuthoritySeedV1,
    records::Role,
    test_store::FixtureTransitionStoreV1,
    verification::{self as v, *},
};
use rusqlite::{OptionalExtension, TransactionBehavior, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

const ELIGIBILITY_DOMAIN: &[u8] = b"TITAN-FWD-F06\0eligibility-v1\0";
const SNAPSHOT_DOMAIN: &[u8] = b"TITAN-FWD-F07\0snapshot-v1\0";
const RECEIPT_DOMAIN: &[u8] = b"TITAN-FWD-F07\0receipt-v1\0";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum F07Error {
    BlockedPromotionEligibilityStale,
    BlockedCanonicalStateChanged,
    BlockedEligibilityConsumed,
    BlockedIntegrity,
    BlockedEnvironment,
}
pub type F07Result<T> = Result<T, F07Error>;
pub(crate) fn environment(_: rusqlite::Error) -> F07Error {
    F07Error::BlockedEnvironment
}
pub(crate) fn encode<T: Serialize>(value: &T) -> F07Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| F07Error::BlockedIntegrity)
}
pub(crate) fn decode<T: for<'a> Deserialize<'a> + Serialize>(bytes: &[u8]) -> F07Result<T> {
    if bytes.is_empty() || bytes.len() > 8_388_608 {
        return Err(F07Error::BlockedIntegrity);
    }
    let value = serde_json::from_slice(bytes).map_err(|_| F07Error::BlockedIntegrity)?;
    if encode(&value)? != bytes {
        return Err(F07Error::BlockedIntegrity);
    }
    Ok(value)
}

// Exact closed F06 transport mirror; F06 itself stays immutable and unchanged.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EligibilityBodyV1 {
    namespace: String,
    version: u32,
    outcome: String,
    candidate: FixtureCandidateV1,
    candidate_record_digest: String,
    project_digest: String,
    contract_digest: String,
    seed_digest: String,
    authorization_id: String,
    authorization_digest: String,
    assurance_policy: FixtureAssurancePolicyV1,
    policy_digest: String,
    eligibility_rule: String,
    rule_version: u32,
    consequence: ConsequenceV1,
    evidence_set: FixtureEvidenceSetV1,
    history_id: String,
    history_head: String,
    verification: FixtureVerificationRecordV1,
    approval: crate::eligibility::FixtureApprovalRecordV1,
    executor_binding_digest: String,
    authority_state_id: String,
    expected_prior: ExpectedPriorCanonicalV1,
    evaluation_epoch: u64,
}
pub(crate) type EligibilityRecordV1 = FixtureRecordV1<EligibilityBodyV1>;
pub(crate) fn eligibility_record(bytes: &[u8]) -> F07Result<EligibilityRecordV1> {
    let record: EligibilityRecordV1 = v::decode_record(bytes, ELIGIBILITY_DOMAIN, "eligibility")
        .map_err(|_| F07Error::BlockedIntegrity)?;
    let b = &record.body;
    if b.namespace != "FIXTURE"
        || b.version != 1
        || b.outcome != "ELIGIBLE"
        || b.eligibility_rule != RULE
        || b.rule_version != 1
        || b.assurance_policy.profile != POLICY
        || b.assurance_policy.version != 1
        || b.candidate.namespace != "FIXTURE"
        || b.candidate.version != 1
        || !v::fx(&b.candidate.candidate_id, "candidate")
        || !v::fx(&b.candidate.subject_id, "target")
        || !b.candidate.scope.starts_with("fixture://")
        || b.expected_prior.validate(&b.candidate).is_err()
    {
        return Err(F07Error::BlockedIntegrity);
    }
    Ok(record)
}

/// Independently captured CURRENT upstream inputs. Capture validates reuse once,
/// before registration; execution cannot invoke K5 or refresh this determination.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureDependencySnapshotV1 {
    eligibility_id: String,
    eligibility_digest: String,
    pub(crate) rows: BTreeMap<String, Vec<u8>>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SnapshotTransportV1 {
    eligibility_id: String,
    eligibility_digest: String,
    rows: BTreeMap<String, Vec<u8>>,
}
fn decode_snapshot(bytes: &[u8]) -> F07Result<FixtureDependencySnapshotV1> {
    let transport: SnapshotTransportV1 = decode(bytes)?;
    Ok(FixtureDependencySnapshotV1 {
        eligibility_id: transport.eligibility_id,
        eligibility_digest: transport.eligibility_digest,
        rows: transport.rows,
    })
}
impl FixtureDependencySnapshotV1 {
    pub fn capture(
        eligibility: &FixturePromotionEligibilityV1,
        i: FixtureEligibilityInput<'_>,
    ) -> F07Result<Self> {
        let mut rows = BTreeMap::new();
        macro_rules! row {
            ($name:literal, $value:expr) => {
                rows.insert($name.into(), encode(&$value)?);
            };
        }
        row!("candidate", i.candidate);
        rows.insert(
            "candidate_bytes".into(),
            v::candidate_bytes(i.candidate)
                .map_err(|_| F07Error::BlockedPromotionEligibilityStale)?,
        );
        rows.insert("project".into(), i.project.canonical_bytes().to_vec());
        rows.insert("contract".into(), i.contract.canonical_bytes().to_vec());
        row!("seed", i.seed);
        row!("authority_state", i.authority_state);
        rows.insert(
            "authorization".into(),
            i.authorization.canonical_bytes().to_vec(),
        );
        row!("evidence_set", i.evidence_set);
        let history = replay_fixture_history(i.store)
            .map_err(|_| F07Error::BlockedPromotionEligibilityStale)?;
        row!(
            "history_id",
            history
                .history_id(i.store.case_id())
                .map_err(|_| F07Error::BlockedIntegrity)?
        );
        row!("history_head", history.head_id());
        rows.insert("verification".into(), i.verification_bytes.to_vec());
        rows.insert(
            "approval".into(),
            i.approval_bytes
                .ok_or(F07Error::BlockedPromotionEligibilityStale)?
                .to_vec(),
        );
        row!("policy", i.policy);
        row!("rule_version", i.rule_version);
        row!("consequence", i.consequence);
        row!(
            "expected_prior",
            i.expected_prior
                .ok_or(F07Error::BlockedPromotionEligibilityStale)?
        );
        row!("evaluation_epoch", i.evaluation_epoch);
        for member in &i.evidence_set.members {
            let (observation, _) = history
                .observations
                .get(&member.evidence_id)
                .ok_or(F07Error::BlockedPromotionEligibilityStale)?;
            rows.insert(
                format!("evidence_blob:{}", member.evidence_id),
                i.store
                    .read_raw(&observation.locator, &member.content_digest)
                    .map_err(|_| F07Error::BlockedPromotionEligibilityStale)?,
            );
        }
        validate_fixture_eligibility_reuse_v1(eligibility, i)
            .map_err(|_| F07Error::BlockedPromotionEligibilityStale)?;
        Ok(Self {
            eligibility_id: eligibility.record_id().into(),
            eligibility_digest: eligibility.body_digest().into(),
            rows,
        })
    }
    pub fn names(&self) -> Vec<String> {
        self.rows.keys().cloned().collect()
    }
    pub(crate) fn digest(&self) -> F07Result<String> {
        Ok(hash(SNAPSHOT_DOMAIN, &encode(self)?))
    }
    pub(crate) fn matches(&self, record: &EligibilityRecordV1) -> F07Result<()> {
        if self.eligibility_id != record.record_id || self.eligibility_digest != record.body_digest
        {
            return Err(F07Error::BlockedIntegrity);
        }
        let b = &record.body;
        let expected = [
            ("candidate", encode(&b.candidate)?),
            ("evidence_set", encode(&b.evidence_set)?),
            ("verification", encode(&b.verification)?),
            ("approval", encode(&b.approval)?),
            ("policy", encode(&b.assurance_policy)?),
            ("rule_version", encode(&b.rule_version)?),
            ("consequence", encode(&b.consequence)?),
            ("expected_prior", encode(&b.expected_prior)?),
            ("evaluation_epoch", encode(&b.evaluation_epoch)?),
            ("history_id", encode(&b.history_id)?),
            ("history_head", encode(&b.history_head)?),
        ];
        for (name, bytes) in expected {
            if self.rows.get(name) != Some(&bytes) {
                return Err(F07Error::BlockedIntegrity);
            }
        }
        let raw = self
            .rows
            .get("candidate_bytes")
            .ok_or(F07Error::BlockedIntegrity)?;
        if hash(b"", raw) != b.candidate.content_digest {
            return Err(F07Error::BlockedIntegrity);
        }
        let candidate = crate::validate_bytes(raw).map_err(|_| F07Error::BlockedIntegrity)?;
        if candidate.record().integrity != b.candidate_record_digest {
            return Err(F07Error::BlockedIntegrity);
        }
        for (name, digest) in [
            ("project", &b.project_digest),
            ("contract", &b.contract_digest),
            ("authorization", &b.authorization_digest),
        ] {
            let record =
                crate::validate_bytes(self.rows.get(name).ok_or(F07Error::BlockedIntegrity)?)
                    .map_err(|_| F07Error::BlockedIntegrity)?;
            if &record.record().integrity != digest {
                return Err(F07Error::BlockedIntegrity);
            }
            if name == "authorization" && record.record().record_id != b.authorization_id {
                return Err(F07Error::BlockedIntegrity);
            }
        }
        let seed: FixtureAuthoritySeedV1 =
            decode(self.rows.get("seed").ok_or(F07Error::BlockedIntegrity)?)?;
        if seed.digest().map_err(|_| F07Error::BlockedIntegrity)? != b.seed_digest {
            return Err(F07Error::BlockedIntegrity);
        }
        let state: crate::fixture_projection::FixtureProjection = decode(
            self.rows
                .get("authority_state")
                .ok_or(F07Error::BlockedIntegrity)?,
        )?;
        if state.verify_state_identity().is_err()
            || state.state_id != b.authority_state_id
            || state.seed_digest != b.seed_digest
        {
            return Err(F07Error::BlockedIntegrity);
        }
        if self.rows.len() != 17 + b.evidence_set.members.len() {
            return Err(F07Error::BlockedIntegrity);
        }
        for member in &b.evidence_set.members {
            let raw = self
                .rows
                .get(&format!("evidence_blob:{}", member.evidence_id))
                .ok_or(F07Error::BlockedIntegrity)?;
            if hash(b"", raw) != member.content_digest {
                return Err(F07Error::BlockedIntegrity);
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureTransitionRequestV1 {
    pub transition_id: String,
    pub eligibility_id: String,
    pub eligibility_digest: String,
    pub candidate: FixtureCandidateV1,
    pub expected_prior: ExpectedPriorCanonicalV1,
}
impl FixtureTransitionRequestV1 {
    pub fn from_eligibility(
        transition_slug: &str,
        eligibility: &FixturePromotionEligibilityV1,
    ) -> F07Result<Self> {
        let transition_id = format!("fx:transition:{transition_slug}");
        if !v::fx(&transition_id, "transition") {
            return Err(F07Error::BlockedEnvironment);
        }
        let record = eligibility_record(eligibility.canonical_bytes())?;
        Ok(Self {
            transition_id,
            eligibility_id: record.record_id,
            eligibility_digest: record.body_digest,
            candidate: record.body.candidate,
            expected_prior: record.body.expected_prior,
        })
    }
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureTransitionReceiptBodyV1 {
    pub namespace: String,
    pub version: u32,
    pub request: FixtureTransitionRequestV1,
    /// Exact F06 basis binds all candidate, authority, approval, policy, rule and evidence identities.
    pub eligibility_bytes: Vec<u8>,
    pub dependency_snapshot_digest: String,
    pub resulting_state: ExpectedPriorCanonicalV1,
    pub resulting_store_version: u64,
    pub transition_epoch: u64,
}
pub type FixtureTransitionReceiptV1 = FixtureRecordV1<FixtureTransitionReceiptBodyV1>;
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureTransitionResultV1 {
    pub receipt: FixtureTransitionReceiptV1,
    pub replayed: bool,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FailurePointV1 {
    None,
    BeforePointer,
    AfterPointer,
    AfterConsumption,
    AfterReceipt,
}

fn fresh(
    snapshot: &FixtureDependencySnapshotV1,
    b: &EligibilityBodyV1,
    epoch: u64,
) -> F07Result<()> {
    let stale = F07Error::BlockedPromotionEligibilityStale;
    if epoch < b.evaluation_epoch
        || epoch < b.approval.body.valid_from_epoch
        || epoch >= b.approval.body.valid_until_epoch
    {
        return Err(stale);
    }
    let seed: FixtureAuthoritySeedV1 = decode(snapshot.rows.get("seed").ok_or(stale)?)?;
    let authorization = crate::validate_bytes(snapshot.rows.get("authorization").ok_or(stale)?)
        .map_err(|_| stale)?;
    let crate::records::RecordPayload::AuthorityRecord(authority) = &authorization.record().payload
    else {
        return Err(stale);
    };
    v::actor(
        &seed,
        &authority.issuer_actor_ref,
        Role::DecisionAuthority,
        epoch,
    )
    .map_err(|_| stale)?;
    for (actor, role, digest) in [
        (
            &b.candidate.executor_actor_id,
            Role::Executor,
            &b.executor_binding_digest,
        ),
        (
            &b.verification.body.verifier_actor_id,
            Role::Verifier,
            &b.verification.body.verifier_binding_digest,
        ),
        (
            &b.approval.body.approver_actor_id,
            Role::DecisionAuthority,
            &b.approval.body.approver_binding_digest,
        ),
    ] {
        let (_, current) = v::actor(&seed, actor, role, epoch).map_err(|_| stale)?;
        if &current != digest {
            return Err(stale);
        }
    }
    for member in &b.evidence_set.members {
        if v::actor(&seed, &member.producer_actor_id, Role::Verifier, epoch).is_err()
            && v::actor(&seed, &member.producer_actor_id, Role::Executor, epoch).is_err()
        {
            return Err(stale);
        }
    }
    Ok(())
}
pub(crate) fn validate_receipt(bytes: &[u8]) -> F07Result<FixtureTransitionReceiptV1> {
    let receipt: FixtureTransitionReceiptV1 =
        v::decode_record(bytes, RECEIPT_DOMAIN, "transition-receipt")
            .map_err(|_| F07Error::BlockedIntegrity)?;
    let b = &receipt.body;
    let record = eligibility_record(&b.eligibility_bytes)?;
    if b.namespace != "FIXTURE"
        || b.version != 1
        || b.request.eligibility_id != record.record_id
        || b.request.eligibility_digest != record.body_digest
        || b.request.candidate != record.body.candidate
        || b.request.expected_prior != record.body.expected_prior
        || !v::fx(&b.request.transition_id, "transition")
        || !v::digest(&b.dependency_snapshot_digest)
        || b.transition_epoch < record.body.evaluation_epoch
        || b.resulting_store_version
            != record
                .body
                .expected_prior
                .version
                .ok_or(F07Error::BlockedIntegrity)?
                .checked_add(1)
                .ok_or(F07Error::BlockedIntegrity)?
        || b.resulting_state != resulting(&record.body)?
    {
        return Err(F07Error::BlockedIntegrity);
    }
    Ok(receipt)
}
fn resulting(b: &EligibilityBodyV1) -> F07Result<ExpectedPriorCanonicalV1> {
    let mut result = b.expected_prior.clone();
    result.genesis = false;
    result.candidate_id = Some(b.candidate.candidate_id.clone());
    result.candidate_digest = Some(b.candidate.content_digest.clone());
    result.version = Some(
        result
            .version
            .ok_or(F07Error::BlockedIntegrity)?
            .checked_add(1)
            .ok_or(F07Error::BlockedIntegrity)?,
    );
    Ok(result)
}

/// One IMMEDIATE transaction owns all SQLite snapshot reads and all effects.
/// No F05 invocation, filesystem evidence repair, approval issuance or K5 refresh exists here.
pub fn execute_fixture_transition_v1(
    store: &mut FixtureTransitionStoreV1,
    request: &FixtureTransitionRequestV1,
    current_epoch: u64,
    failure: FailurePointV1,
) -> F07Result<FixtureTransitionResultV1> {
    store.check_path()?;
    if !v::fx(&request.transition_id, "transition") {
        return Err(F07Error::BlockedEnvironment);
    }
    let tx = store
        .connection
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(environment)?;
    crate::test_store::validate_schema(&tx)?;
    let (eligibility_bytes, snapshot_bytes, binding): (Vec<u8>, Vec<u8>, String) = tx
        .query_row(
            "SELECT eligibility,snapshot,digest FROM basis WHERE eligibility_id=?1",
            [&request.eligibility_id],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(environment)?
        .ok_or(F07Error::BlockedIntegrity)?;
    if binding != crate::test_store::basis_digest(&eligibility_bytes, &snapshot_bytes) {
        return Err(F07Error::BlockedIntegrity);
    }
    let record = eligibility_record(&eligibility_bytes)?;
    if record.record_id != request.eligibility_id {
        return Err(F07Error::BlockedIntegrity);
    }
    let snapshot = decode_snapshot(&snapshot_bytes)?;
    snapshot.matches(&record)?;
    if request.eligibility_digest != record.body_digest
        || request.candidate != record.body.candidate
        || request.expected_prior != record.body.expected_prior
    {
        return Err(F07Error::BlockedEligibilityConsumed);
    }
    let prior_bytes: Vec<u8> = tx
        .query_row("SELECT value FROM pointer WHERE singleton=1", [], |r| {
            r.get(0)
        })
        .map_err(environment)?;
    let prior: ExpectedPriorCanonicalV1 = decode(&prior_bytes)?;
    let consumed: Option<String> = tx
        .query_row(
            "SELECT transition_id FROM consumed WHERE eligibility_id=?1",
            [&request.eligibility_id],
            |r| r.get(0),
        )
        .optional()
        .map_err(environment)?;
    let receipts: i64 = tx
        .query_row("SELECT count(*) FROM receipts", [], |r| r.get(0))
        .map_err(environment)?;
    if let Some(id) = consumed {
        if id != request.transition_id {
            return Err(F07Error::BlockedEligibilityConsumed);
        }
        let bytes: Vec<u8> = tx
            .query_row(
                "SELECT receipt FROM receipts WHERE transition_id=?1 AND eligibility_id=?2",
                params![id, request.eligibility_id],
                |r| r.get(0),
            )
            .optional()
            .map_err(environment)?
            .ok_or(F07Error::BlockedIntegrity)?;
        let receipt = validate_receipt(&bytes)?;
        if receipts != 1
            || receipt.body.request != *request
            || receipt.body.eligibility_bytes != eligibility_bytes
            || receipt.body.dependency_snapshot_digest != snapshot.digest()?
            || receipt.body.resulting_state != prior
        {
            return Err(F07Error::BlockedIntegrity);
        }
        tx.commit().map_err(environment)?;
        return Ok(FixtureTransitionResultV1 {
            receipt,
            replayed: true,
        });
    }
    if receipts != 0 {
        return Err(F07Error::BlockedIntegrity);
    }
    let current = {
        let mut statement = tx
            .prepare("SELECT name,value FROM dependencies ORDER BY name")
            .map_err(environment)?;
        let values = statement
            .query_map([], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, Vec<u8>>(1)?))
            })
            .map_err(environment)?;
        let mut current = BTreeMap::new();
        for value in values {
            let (name, bytes) = value.map_err(environment)?;
            current.insert(name, bytes);
        }
        current
    };
    if current != snapshot.rows {
        return Err(F07Error::BlockedPromotionEligibilityStale);
    }
    fresh(&snapshot, &record.body, current_epoch)?;
    if prior != request.expected_prior {
        return Err(F07Error::BlockedCanonicalStateChanged);
    }
    let result = resulting(&record.body)?;
    if failure == FailurePointV1::BeforePointer {
        return Err(F07Error::BlockedEnvironment);
    }
    let changed = tx
        .execute(
            "UPDATE pointer SET value=?1 WHERE singleton=1 AND value=?2",
            params![encode(&result)?, prior_bytes],
        )
        .map_err(environment)?;
    if changed != 1 {
        return Err(F07Error::BlockedCanonicalStateChanged);
    }
    if failure == FailurePointV1::AfterPointer {
        return Err(F07Error::BlockedEnvironment);
    }
    tx.execute(
        "INSERT INTO consumed(eligibility_id,transition_id) VALUES(?1,?2)",
        params![request.eligibility_id, request.transition_id],
    )
    .map_err(environment)?;
    if failure == FailurePointV1::AfterConsumption {
        return Err(F07Error::BlockedEnvironment);
    }
    let body = FixtureTransitionReceiptBodyV1 {
        namespace: "FIXTURE".into(),
        version: 1,
        request: request.clone(),
        eligibility_bytes,
        dependency_snapshot_digest: snapshot.digest()?,
        resulting_store_version: result.version.ok_or(F07Error::BlockedIntegrity)?,
        resulting_state: result,
        transition_epoch: current_epoch,
    };
    let body_digest = hash(RECEIPT_DOMAIN, &encode(&body)?);
    let receipt = FixtureRecordV1 {
        record_id: format!("fx:transition-receipt:{}", &body_digest[7..]),
        body,
        body_digest,
    };
    validate_receipt(&encode(&receipt)?)?;
    tx.execute(
        "INSERT INTO receipts(transition_id,eligibility_id,receipt) VALUES(?1,?2,?3)",
        params![
            request.transition_id,
            request.eligibility_id,
            encode(&receipt)?
        ],
    )
    .map_err(environment)?;
    if failure == FailurePointV1::AfterReceipt {
        return Err(F07Error::BlockedEnvironment);
    }
    let persisted_pointer: Vec<u8> = tx
        .query_row("SELECT value FROM pointer WHERE singleton=1", [], |r| {
            r.get(0)
        })
        .map_err(environment)?;
    let persisted_consumed: String = tx
        .query_row(
            "SELECT transition_id FROM consumed WHERE eligibility_id=?1",
            [&request.eligibility_id],
            |r| r.get(0),
        )
        .map_err(environment)?;
    let persisted_receipt: Vec<u8> = tx
        .query_row(
            "SELECT receipt FROM receipts WHERE transition_id=?1 AND eligibility_id=?2",
            params![request.transition_id, request.eligibility_id],
            |r| r.get(0),
        )
        .map_err(environment)?;
    if persisted_pointer != encode(&receipt.body.resulting_state)?
        || persisted_consumed != request.transition_id
        || persisted_receipt != encode(&receipt)?
    {
        return Err(F07Error::BlockedIntegrity);
    }
    tx.commit().map_err(environment)?;
    Ok(FixtureTransitionResultV1 {
        receipt,
        replayed: false,
    })
}
