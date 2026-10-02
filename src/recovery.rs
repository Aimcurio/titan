//! Fixture-only K4 checkpoint and inert resume decision. No work is executed.

use serde::{Deserialize, Serialize};

use crate::{
    ValidatedRecord,
    admission::{FixtureAdmissionInput, FixtureAdmissionV1, revalidate_fixture_admission},
    authority::FixtureResult,
    codec::validate_bytes,
    encode_fixture,
    evidence::{
        FixtureEventV1, FixtureHistoryV1, FixtureStoreV1, append_fixture_event, fail, hash,
        replay_fixture_history,
    },
    outcome::{BlockedCode, OutcomeVariant, PassCode, UnknownCode},
    records::{
        ActorBinding, Checkpoint, ExecutionContract, Namespace, ProjectBinding, RecordEnvelope,
        RecordPayload,
    },
    target::construct_fixture_target_snapshot,
};

pub const CHECKPOINT_MARKER: &str = "TITAN_F04_FIXTURE_CHECKPOINT_V1";
pub const RESUME_MARKER: &str = "TITAN_F04_FIXTURE_RESUME_DECISION_V1";
const ZERO: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCheckpointMaterialV1 {
    pub case_id: String,
    pub run_id: String,
    pub project_id: String,
    pub project_digest: String,
    pub actor_id: String,
    pub actor_digest: String,
    pub contract_id: String,
    pub contract_digest: String,
    pub admission_id: String,
    pub admission_digest: String,
    pub authority_state_id: String,
    pub target_id: String,
    pub target_state_id: String,
    pub capability: String,
    pub operation: String,
    pub pending_step: String,
    pub action_id: String,
    pub idempotency_id: String,
    pub action_fingerprint: String,
    pub last_valid_step: String,
    pub completed_gate_refs: Vec<String>,
    pub evidence_refs: Vec<String>,
    pub active_blockers: Vec<(String, BlockedCode)>,
    pub unresolved_effect_refs: Vec<String>,
    pub resume_authority_ref: String,
    pub history_id: String,
    pub epoch: u64,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCheckpointV1 {
    pub marker: String,
    pub version: u32,
    pub material: FixtureCheckpointMaterialV1,
    pub f01_record: Vec<u8>,
    pub checkpoint_id: String,
    pub checkpoint_digest: String,
}
impl FixtureCheckpointV1 {
    pub fn canonical_bytes(&self) -> FixtureResult<Vec<u8>> {
        serde_json::to_vec(self)
            .map_err(|_| fail(BlockedCode::ContractInvalid, "checkpoint serialization"))
    }
    pub fn verify(&self) -> FixtureResult<()> {
        if self.marker != CHECKPOINT_MARKER || self.version != 1 {
            return Err(fail(
                BlockedCode::ContractInvalid,
                "checkpoint marker/version",
            ));
        }
        let m = &self.material;
        let material = serde_json::to_vec(&(self.version, m))
            .map_err(|_| fail(BlockedCode::ContractInvalid, "checkpoint material"))?;
        let id = format!(
            "fx:checkpoint:{}",
            hash(b"TITAN-FWD-F04\0checkpoint-id-v1\0", &material).trim_start_matches("sha256:")
        );
        if self.checkpoint_id != id {
            return Err(fail(BlockedCode::ContractInvalid, "checkpoint ID mismatch"));
        }
        let v = validate_bytes(&self.f01_record)
            .map_err(|_| fail(BlockedCode::ContractInvalid, "invalid F01 checkpoint"))?;
        let RecordPayload::Checkpoint(c) = &v.record().payload else {
            return Err(fail(
                BlockedCode::ContractInvalid,
                "F01 checkpoint required",
            ));
        };
        let mut codes = m
            .active_blockers
            .iter()
            .map(|(_, code)| format!("{code:?}").to_ascii_uppercase())
            .collect::<Vec<_>>();
        codes.sort();
        codes.dedup();
        if c.checkpoint_id != id
            || c.run_ref != m.run_id
            || c.contract_digest != m.contract_digest
            || c.target_ref != m.target_id
            || c.target_state != m.target_state_id
            || c.last_valid_step != m.last_valid_step
            || c.completed_gate_refs != m.completed_gate_refs
            || c.evidence_refs != m.evidence_refs
            || c.partial_effect_refs != m.unresolved_effect_refs
            || c.resume_authority_ref != m.resume_authority_ref
            || c.pending_action != m.action_id
            || c.blocker_codes != codes
        {
            return Err(fail(
                BlockedCode::ContractInvalid,
                "F01/F04 checkpoint disagreement",
            ));
        }
        let digest = hash(
            b"TITAN-FWD-F04\0checkpoint-digest-v1\0",
            &serde_json::to_vec(&(
                self.marker.as_str(),
                self.version,
                m,
                &self.f01_record,
                &self.checkpoint_id,
            ))
            .map_err(|_| fail(BlockedCode::ContractInvalid, "checkpoint digest material"))?,
        );
        if digest != self.checkpoint_digest {
            return Err(fail(
                BlockedCode::ContractInvalid,
                "checkpoint digest mismatch",
            ));
        }
        Ok(())
    }
}

fn contract(record: &ValidatedRecord) -> FixtureResult<&ExecutionContract> {
    let RecordPayload::ExecutionContract(c) = &record.record().payload else {
        return Err(fail(BlockedCode::ContractInvalid, "contract required"));
    };
    Ok(c)
}
fn project(record: &ValidatedRecord) -> FixtureResult<&ProjectBinding> {
    let RecordPayload::ProjectBinding(p) = &record.record().payload else {
        return Err(fail(BlockedCode::ContractInvalid, "project required"));
    };
    Ok(p)
}
fn actor(record: &ValidatedRecord) -> FixtureResult<&ActorBinding> {
    let RecordPayload::ActorBinding(a) = &record.record().payload else {
        return Err(fail(BlockedCode::ContractInvalid, "actor required"));
    };
    Ok(a)
}
fn exact_set(v: &[String]) -> FixtureResult<Vec<String>> {
    let mut sorted = v.to_vec();
    sorted.sort();
    if sorted.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(fail(
            BlockedCode::ContractInvalid,
            "duplicate checkpoint reference",
        ));
    }
    Ok(sorted)
}
fn blocker_code(code: &BlockedCode) -> String {
    format!("{code:?}").to_ascii_uppercase()
}

fn completed_gates_supported(h: &FixtureHistoryV1, m: &FixtureCheckpointMaterialV1) -> bool {
    m.completed_gate_refs.iter().all(|gate| {
        m.evidence_refs.iter().any(|id| {
            h.current_evidence(id)
                && h.observations.get(id).is_some_and(|(e, digest)| {
                    e.gate_ref.as_ref() == Some(gate)
                        && e.run_ref == m.run_id
                        && e.contract_ref == m.contract_id
                        && digest == &m.contract_digest
                        && e.subject_ref == m.target_id
                        && e.subject_revision == m.target_state_id
                })
        })
    })
}

pub struct FixtureCheckpointInput<'a> {
    pub admission: &'a FixtureAdmissionV1,
    pub current: &'a FixtureAdmissionInput<'a>,
    pub run_id: &'a str,
    pub capability: &'a str,
    pub operation: &'a str,
    pub pending_step: &'a str,
    pub action_id: &'a str,
    pub idempotency_id: &'a str,
    pub action_fingerprint: &'a str,
    pub last_valid_step: &'a str,
    pub completed_gate_refs: &'a [String],
    pub evidence_refs: &'a [String],
    pub resume_authority_ref: &'a str,
    pub epoch: u64,
}

pub fn make_fixture_checkpoint(
    store: &FixtureStoreV1,
    history: &FixtureHistoryV1,
    input: &FixtureCheckpointInput<'_>,
) -> FixtureResult<FixtureCheckpointV1> {
    if replay_fixture_history(store)?.history_id(store.case_id())?
        != history.history_id(store.case_id())?
    {
        return Err(fail(
            BlockedCode::PreconditionDrift,
            "checkpoint history input stale",
        ));
    }
    revalidate_fixture_admission(input.admission, input.current)?;
    let c = contract(input.current.contract)?;
    let p = project(input.current.project)?;
    let a = actor(input.current.actor)?;
    let target = construct_fixture_target_snapshot(input.current.target_policy)?;
    if input.capability != input.current.requested_capability
        || input.operation != input.current.requested_operation
        || input.admission.target_state_id() != target.state_id
        || input.admission.authority_state_id() != input.current.authority_state.state_id
    {
        return Err(fail(
            BlockedCode::PreconditionDrift,
            "checkpoint admission basis differs",
        ));
    }
    let active_blockers = history
        .blockers
        .iter()
        .filter(|(_, (_, active))| *active)
        .map(|(id, (code, _))| (id.clone(), code.clone()))
        .collect::<Vec<_>>();
    let unresolved_effect_refs = history
        .effects
        .iter()
        .filter(|(_, (_, _, s))| s.unresolved())
        .map(|(id, _)| id.clone())
        .collect::<Vec<_>>();
    let m = FixtureCheckpointMaterialV1 {
        case_id: store.case_id().into(),
        run_id: input.run_id.into(),
        project_id: p.project_id.clone(),
        project_digest: input.current.project.record().integrity.clone(),
        actor_id: a.actor_id.clone(),
        actor_digest: input.current.actor.record().integrity.clone(),
        contract_id: c.contract_id.clone(),
        contract_digest: input.current.contract.record().integrity.clone(),
        admission_id: input.admission.admission_id().into(),
        admission_digest: hash(
            b"TITAN-FWD-F04\0admission-bytes-v1\0",
            &input.admission.canonical_bytes()?,
        ),
        authority_state_id: input.current.authority_state.state_id.clone(),
        target_id: target.target_id,
        target_state_id: target.state_id,
        capability: input.capability.into(),
        operation: input.operation.into(),
        pending_step: input.pending_step.into(),
        action_id: input.action_id.into(),
        idempotency_id: input.idempotency_id.into(),
        action_fingerprint: input.action_fingerprint.into(),
        last_valid_step: input.last_valid_step.into(),
        completed_gate_refs: exact_set(input.completed_gate_refs)?,
        evidence_refs: exact_set(input.evidence_refs)?,
        active_blockers,
        unresolved_effect_refs,
        resume_authority_ref: input.resume_authority_ref.into(),
        history_id: history.history_id(store.case_id())?,
        epoch: input.epoch,
    };
    if !m.run_id.starts_with("fx:run:")
        || !m.action_id.starts_with("fx:action:")
        || !m.idempotency_id.starts_with("fx:idempotency:")
        || !m.action_fingerprint.starts_with("sha256:")
        || !m.resume_authority_ref.starts_with("fx:authority:")
        || m.pending_step.is_empty()
        || m.last_valid_step.is_empty()
    {
        return Err(fail(
            BlockedCode::ContractInvalid,
            "checkpoint identity malformed",
        ));
    }
    if !completed_gates_supported(history, &m) {
        return Err(fail(
            BlockedCode::InsufficientEvidence,
            "completed gate lacks current observation",
        ));
    }
    let material = serde_json::to_vec(&(1_u32, &m))
        .map_err(|_| fail(BlockedCode::ContractInvalid, "checkpoint material"))?;
    let id = format!(
        "fx:checkpoint:{}",
        hash(b"TITAN-FWD-F04\0checkpoint-id-v1\0", &material).trim_start_matches("sha256:")
    );
    let mut codes = m
        .active_blockers
        .iter()
        .map(|(_, code)| blocker_code(code))
        .collect::<Vec<_>>();
    codes.sort();
    codes.dedup();
    let c01 = Checkpoint {
        checkpoint_id: id.clone(),
        run_ref: m.run_id.clone(),
        contract_digest: m.contract_digest.clone(),
        target_ref: m.target_id.clone(),
        target_state: m.target_state_id.clone(),
        last_valid_step: m.last_valid_step.clone(),
        completed_gate_refs: m.completed_gate_refs.clone(),
        blocker_codes: codes,
        evidence_refs: m.evidence_refs.clone(),
        pending_action: m.action_id.clone(),
        partial_effect_refs: m.unresolved_effect_refs.clone(),
        resume_authority_ref: m.resume_authority_ref.clone(),
    };
    let f01 = encode_fixture(RecordEnvelope {
        record_type: RecordPayload::Checkpoint(c01.clone()).record_type(),
        schema_version: 1,
        namespace: Namespace::Fixture,
        record_id: id.clone(),
        creator_ref: a.actor_id.clone(),
        created_at_unix_ms: m.epoch,
        payload: RecordPayload::Checkpoint(c01),
        integrity: ZERO.into(),
    })
    .map_err(|_| fail(BlockedCode::ContractInvalid, "F01 checkpoint encoding"))?;
    let mut result = FixtureCheckpointV1 {
        marker: CHECKPOINT_MARKER.into(),
        version: 1,
        material: m,
        f01_record: f01.canonical_bytes().to_vec(),
        checkpoint_id: id,
        checkpoint_digest: String::new(),
    };
    result.checkpoint_digest = hash(
        b"TITAN-FWD-F04\0checkpoint-digest-v1\0",
        &serde_json::to_vec(&(
            result.marker.as_str(),
            result.version,
            &result.material,
            &result.f01_record,
            &result.checkpoint_id,
        ))
        .map_err(|_| fail(BlockedCode::ContractInvalid, "checkpoint digest encoding"))?,
    );
    result.verify()?;
    Ok(result)
}

pub fn append_fixture_checkpoint(
    store: &FixtureStoreV1,
    history: &FixtureHistoryV1,
    checkpoint: &FixtureCheckpointV1,
) -> FixtureResult<()> {
    checkpoint.verify()?;
    if checkpoint.material.case_id != store.case_id()
        || checkpoint.material.history_id != history.history_id(store.case_id())?
        || replay_fixture_history(store)?.history_id(store.case_id())?
            != history.history_id(store.case_id())?
    {
        return Err(fail(
            BlockedCode::PreconditionDrift,
            "checkpoint history stale",
        ));
    }
    append_fixture_event(
        store,
        &checkpoint.material.run_id,
        history.head_id(),
        FixtureEventV1::Checkpoint {
            checkpoint_id: checkpoint.checkpoint_id.clone(),
            bytes: checkpoint.canonical_bytes()?,
        },
    )?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResumeSemanticV1 {
    Resumable,
    Blocked,
    ReconciliationRequired,
    StaleCheckpoint,
    InvalidEvidence,
    UnresolvedEffect,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureResumeDecisionV1 {
    pub marker: String,
    pub namespace: String,
    pub semantic: ResumeSemanticV1,
    pub outcome: OutcomeVariant,
    pub checkpoint_id: String,
    pub checkpoint_digest: String,
    pub history_id: String,
    pub admission_id: String,
    pub authority_state_id: String,
    pub target_state_id: String,
    pub action_id: String,
    pub decision_id: String,
}
fn decision(
    c: &FixtureCheckpointV1,
    h: &FixtureHistoryV1,
    semantic: ResumeSemanticV1,
    outcome: OutcomeVariant,
) -> FixtureResult<FixtureResumeDecisionV1> {
    let mut d = FixtureResumeDecisionV1 {
        marker: RESUME_MARKER.into(),
        namespace: "FIXTURE".into(),
        semantic,
        outcome,
        checkpoint_id: c.checkpoint_id.clone(),
        checkpoint_digest: c.checkpoint_digest.clone(),
        history_id: h.history_id(&c.material.case_id)?,
        admission_id: c.material.admission_id.clone(),
        authority_state_id: c.material.authority_state_id.clone(),
        target_state_id: c.material.target_state_id.clone(),
        action_id: c.material.action_id.clone(),
        decision_id: String::new(),
    };
    let b = serde_json::to_vec(&d).map_err(|_| {
        fail(
            BlockedCode::ContractInvalid,
            "resume decision serialization",
        )
    })?;
    d.decision_id = format!(
        "fx:resume-decision:{}",
        hash(b"TITAN-FWD-F04\0resume-v1\0", &b).trim_start_matches("sha256:")
    );
    Ok(d)
}
fn blocked(
    c: &FixtureCheckpointV1,
    h: &FixtureHistoryV1,
    semantic: ResumeSemanticV1,
    code: BlockedCode,
) -> FixtureResult<FixtureResumeDecisionV1> {
    decision(c, h, semantic, OutcomeVariant::Blocked(code))
}

/// Pure fixture dependency comparison; the F03 observer supplies the observed identities.
pub fn check_fixture_target_dependency(
    expected_id: &str,
    expected_state: &str,
    observed_id: &str,
    observed_state: &str,
) -> FixtureResult<()> {
    if expected_id != observed_id {
        return Err(fail(
            BlockedCode::TargetIdentityMismatch,
            "target identity changed",
        ));
    }
    if expected_state != observed_state {
        return Err(fail(BlockedCode::PreconditionDrift, "target state changed"));
    }
    Ok(())
}

pub fn evaluate_fixture_resume(
    store: &FixtureStoreV1,
    checkpoint: &FixtureCheckpointV1,
    current: &FixtureCheckpointInput<'_>,
) -> FixtureResult<FixtureResumeDecisionV1> {
    let h = replay_fixture_history(store)?;
    checkpoint.verify()?;
    if checkpoint.material.case_id != store.case_id()
        || h.checkpoints.get(&checkpoint.checkpoint_id) != Some(&checkpoint.canonical_bytes()?)
        || !matches!(h.entries.last().map(|e|&e.event),Some(FixtureEventV1::Checkpoint{checkpoint_id,..}) if checkpoint_id==&checkpoint.checkpoint_id)
    {
        return blocked(
            checkpoint,
            &h,
            ResumeSemanticV1::StaleCheckpoint,
            BlockedCode::PreconditionDrift,
        );
    }
    let m = &checkpoint.material;
    if h.entries.last().map(|e| e.previous_id.as_str())
        != h.entries
            .len()
            .checked_sub(2)
            .and_then(|index| h.entries.get(index))
            .map(|e| e.entry_id.as_str())
            .or(Some("GENESIS"))
    {
        return Err(fail(
            BlockedCode::EnvironmentFailure,
            "checkpoint predecessor mismatch",
        ));
    }
    if h.effects
        .values()
        .any(|(fingerprint, _, state)| fingerprint == &m.action_fingerprint && state.unresolved())
    {
        return decision(
            checkpoint,
            &h,
            ResumeSemanticV1::ReconciliationRequired,
            OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled),
        );
    }
    if m.run_id != current.run_id
        || m.action_id != current.action_id
        || m.idempotency_id != current.idempotency_id
        || m.action_fingerprint != current.action_fingerprint
        || m.pending_step != current.pending_step
        || m.capability != current.capability
        || m.operation != current.operation
        || m.resume_authority_ref != current.resume_authority_ref
    {
        return blocked(
            checkpoint,
            &h,
            ResumeSemanticV1::StaleCheckpoint,
            BlockedCode::PreconditionDrift,
        );
    }
    let p = project(current.current.project)?;
    let a = actor(current.current.actor)?;
    let c = contract(current.current.contract)?;
    if p.project_id != m.project_id
        || current.current.project.record().integrity != m.project_digest
        || a.actor_id != m.actor_id
        || current.current.actor.record().integrity != m.actor_digest
        || c.contract_id != m.contract_id
        || current.current.contract.record().integrity != m.contract_digest
    {
        return blocked(
            checkpoint,
            &h,
            ResumeSemanticV1::StaleCheckpoint,
            BlockedCode::PreconditionDrift,
        );
    }
    if current.current.authority_state.state_id != m.authority_state_id {
        return blocked(
            checkpoint,
            &h,
            ResumeSemanticV1::StaleCheckpoint,
            BlockedCode::AuthorityStale,
        );
    }
    let target = construct_fixture_target_snapshot(current.current.target_policy)?;
    if let Err(e) = check_fixture_target_dependency(
        &m.target_id,
        &m.target_state_id,
        &target.target_id,
        &target.state_id,
    ) {
        return blocked(checkpoint, &h, ResumeSemanticV1::StaleCheckpoint, e.code);
    }
    if current.admission.admission_id() != m.admission_id
        || hash(
            b"TITAN-FWD-F04\0admission-bytes-v1\0",
            &current.admission.canonical_bytes()?,
        ) != m.admission_digest
    {
        return blocked(
            checkpoint,
            &h,
            ResumeSemanticV1::StaleCheckpoint,
            BlockedCode::PreconditionDrift,
        );
    }
    if let Err(e) = revalidate_fixture_admission(current.admission, current.current) {
        return blocked(checkpoint, &h, ResumeSemanticV1::StaleCheckpoint, e.code);
    }
    for id in c
        .required_evidence_refs
        .iter()
        .chain(m.evidence_refs.iter())
    {
        if !h.observations.contains_key(id) {
            return blocked(
                checkpoint,
                &h,
                ResumeSemanticV1::Blocked,
                BlockedCode::InsufficientEvidence,
            );
        }
        if !h.current_evidence(id) {
            return blocked(
                checkpoint,
                &h,
                ResumeSemanticV1::InvalidEvidence,
                BlockedCode::PreconditionDrift,
            );
        }
        let (e, digest) = h.observations.get(id).expect("checked");
        if e.run_ref != m.run_id
            || e.contract_ref != m.contract_id
            || digest != &m.contract_digest
            || e.subject_ref != m.target_id
            || e.subject_revision != m.target_state_id
        {
            return blocked(
                checkpoint,
                &h,
                ResumeSemanticV1::InvalidEvidence,
                BlockedCode::PreconditionDrift,
            );
        }
    }
    if !completed_gates_supported(&h, m) {
        return blocked(
            checkpoint,
            &h,
            ResumeSemanticV1::InvalidEvidence,
            BlockedCode::InsufficientEvidence,
        );
    }
    if let Some((_, (code, _))) = h.blockers.iter().find(|(_, (_, active))| *active) {
        return blocked(checkpoint, &h, ResumeSemanticV1::Blocked, code.clone());
    }
    if m.active_blockers
        != h.blockers
            .iter()
            .filter(|(_, (_, active))| *active)
            .map(|(id, (code, _))| (id.clone(), code.clone()))
            .collect::<Vec<_>>()
        || m.unresolved_effect_refs
            != h.effects
                .iter()
                .filter(|(_, (_, _, s))| s.unresolved())
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
    {
        return blocked(
            checkpoint,
            &h,
            ResumeSemanticV1::StaleCheckpoint,
            BlockedCode::PreconditionDrift,
        );
    }
    decision(
        checkpoint,
        &h,
        ResumeSemanticV1::Resumable,
        OutcomeVariant::Pass(PassCode::GatePassed),
    )
}
