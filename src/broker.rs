//! Fixture-only one-shot K3 dispatch. Qualified F03/F04 remain the enforcement dependencies.

use crate::{
    ValidatedRecord,
    admission::{FixtureAdmissionInput, FixtureAdmissionV1, revalidate_fixture_admission},
    authority::{FixtureFailure, FixtureResult, invalid},
    capability::{self, CAPABILITY, FixtureFaultV1, FixtureMarkerV1, HANDLER, OPERATION, PROFILE},
    codec::{encode_fixture, validate_bytes},
    evidence::{
        ActionSpecV1, EffectStateV1, FixtureEffectProbeV1, FixtureEventV1, FixtureOutcomeContextV1,
        FixtureStoreV1, ReconciliationConclusionV1, append_fixture_event, fail, hash,
        observation_event, replay_fixture_history,
    },
    outcome::{BlockedCode, FailCode, OutcomeVariant, PassCode, UnknownCode},
    records::{
        EvidenceRef, EvidenceStatus, Namespace, Outcome, RecordEnvelope, RecordPayload,
        ResourceMatch,
    },
};
use serde::{Deserialize, Serialize};
use std::{fs::OpenOptions, io::Write};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureBrokerRequestV1 {
    pub profile: String,
    pub admission_bytes: Vec<u8>,
    pub admission_digest: String,
    pub admission_id: String,
    pub project_id: String,
    pub project_digest: String,
    pub actor_id: String,
    pub actor_digest: String,
    pub contract_id: String,
    pub contract_digest: String,
    pub authority_state_id: String,
    pub target_id: String,
    pub target_state_id: String,
    pub capability: String,
    pub operation: String,
    pub resource: String,
    pub handler: String,
    pub case_id: String,
    pub relative_marker: String,
    pub run_id: String,
    pub logical_step: String,
    pub action_id: String,
    pub idempotency_id: String,
    pub payload: Vec<u8>,
    pub payload_digest: String,
    pub gate_ref: String,
}
impl FixtureBrokerRequestV1 {
    pub fn intent_id(&self) -> FixtureResult<String> {
        let b = serde_json::to_vec(self).map_err(|_| invalid("F05 intent encoding"))?;
        Ok(format!(
            "fx:effect-intent:{}",
            hash(b"TITAN-FWD-F05\0intent-v1\0", &b).trim_start_matches("sha256:")
        ))
    }
    pub fn action_spec(&self) -> ActionSpecV1 {
        ActionSpecV1 {
            project_id: self.project_id.clone(),
            target_id: self.target_id.clone(),
            contract_digest: self.contract_digest.clone(),
            capability: self.capability.clone(),
            operation: self.operation.clone(),
            normalized_scope: self.resource.clone(),
            logical_step: self.logical_step.clone(),
            before_state: hash(
                b"TITAN-FWD-F05\0absent-marker-v1\0",
                self.resource.as_bytes(),
            ),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureDispatchResultV1 {
    pub namespace: String,
    pub decision_id: String,
    pub intent_id: Option<String>,
    pub admission_id: String,
    pub action_id: String,
    pub fingerprint: Option<String>,
    pub history_id: Option<String>,
    pub history_head: Option<String>,
    pub effect_state: Option<EffectStateV1>,
    pub outcome: OutcomeVariant,
    pub handler_invocations: u32,
    pub detail: String,
    pub revalidation_evidence_ref: Option<String>,
}
fn result(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    outcome: OutcomeVariant,
    count: u32,
    detail: &str,
) -> FixtureDispatchResultV1 {
    let h = replay_fixture_history(store).ok();
    let mut d = FixtureDispatchResultV1 {
        namespace: "FIXTURE".into(),
        decision_id: String::new(),
        intent_id: r.intent_id().ok(),
        admission_id: r.admission_id.clone(),
        action_id: r.action_id.clone(),
        fingerprint: r.action_spec().fingerprint().ok(),
        history_id: h.as_ref().and_then(|v| v.history_id(store.case_id()).ok()),
        history_head: h.as_ref().map(|v| v.head_id().to_owned()),
        effect_state: h
            .as_ref()
            .and_then(|v| v.effects.get(&r.action_id).map(|x| x.2)),
        outcome,
        handler_invocations: count,
        detail: detail.into(),
        revalidation_evidence_ref: r
            .action_spec()
            .fingerprint()
            .ok()
            .map(|fp| format!("fx:evidence:fresh-{}", &fp[7..39]))
            .filter(|id| h.as_ref().is_some_and(|v| v.current_evidence(id))),
    };
    let bytes = serde_json::to_vec(&d).expect("closed fixture result serializes");
    d.decision_id = format!(
        "fx:dispatch-decision:{}",
        hash(b"TITAN-FWD-F05\0decision-v1\0", &bytes).trim_start_matches("sha256:")
    );
    d
}
fn blocked(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    e: FixtureFailure,
) -> FixtureDispatchResultV1 {
    result(store, r, OutcomeVariant::Blocked(e.code), 0, e.reason)
}
fn unknown(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    count: u32,
    reason: &str,
) -> FixtureDispatchResultV1 {
    result(
        store,
        r,
        OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled),
        count,
        reason,
    )
}
fn id(s: &str, kind: &str) -> bool {
    s.strip_prefix(&format!("fx:{kind}:"))
        .is_some_and(capability::slug)
}

fn validate_request(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    admission: &FixtureAdmissionV1,
    current: &FixtureAdmissionInput<'_>,
) -> FixtureResult<ValidatedRecord> {
    if r.profile != PROFILE
        || r.capability != CAPABILITY
        || r.operation != OPERATION
        || r.handler != HANDLER
    {
        return Err(fail(
            BlockedCode::Unauthorized,
            "F05 exact registry tuple mismatch",
        ));
    }
    if r.admission_bytes.len() > 65536
        || r.admission_bytes != admission.canonical_bytes()?
        || r.admission_id != admission.admission_id()
        || r.admission_digest != hash(b"TITAN-FWD-F05\0admission-bytes-v1\0", &r.admission_bytes)
    {
        return Err(invalid("F05 stored admission identity mismatch"));
    }
    let v: serde_json::Value =
        serde_json::from_slice(&r.admission_bytes).map_err(|_| invalid("F05 admission bytes"))?;
    for (field, expected) in [
        ("project_id", &r.project_id),
        ("project_digest", &r.project_digest),
        ("actor_id", &r.actor_id),
        ("actor_digest", &r.actor_digest),
        ("contract_id", &r.contract_id),
        ("contract_digest", &r.contract_digest),
        ("authority_state_id", &r.authority_state_id),
        ("target_id", &r.target_id),
        ("target_state_id", &r.target_state_id),
        ("capability", &r.capability),
        ("operation", &r.operation),
    ] {
        if v[field].as_str() != Some(expected.as_str()) {
            return Err(invalid("F05 admission attribution mismatch"));
        }
    }
    if r.case_id != store.case_id()
        || !id(&r.run_id, "run")
        || !id(&r.action_id, "action")
        || !id(&r.idempotency_id, "idempotency")
        || !id(&r.gate_ref, "gate")
        || !capability::slug(&r.logical_step)
        || current.network_requested
        || current.secret_requested
        || current.cross_surface_requested
    {
        return Err(invalid("F05 fixture identity or forbidden access"));
    }
    capability::payload_valid(&r.payload, &r.payload_digest)?;
    if !current.requested_read_scopes.is_empty()
        || current.requested_mutation_scopes.len() != 1
        || current.requested_mutation_scopes[0].match_kind != ResourceMatch::Exact
        || current.requested_mutation_scopes[0].resource_ref != r.resource
        || current
            .authority_state
            .profile
            .canonical_resource(&r.resource)
            .ok()
            .as_ref()
            != Some(&r.resource)
    {
        return Err(fail(
            BlockedCode::ScopeViolation,
            "F05 requires one exact canonical mutation scope",
        ));
    }
    let RecordPayload::ExecutionContract(contract) = &current.contract.record().payload else {
        return Err(invalid("F05 F01 contract required"));
    };
    if !contract.verification_gate_refs.contains(&r.gate_ref) {
        return Err(invalid("F05 gate outside contract"));
    }
    // Use the admitted producer from the qualified roster; a changed current actor is checked by F03.
    let producer = current
        .seed
        .actor_records
        .iter()
        .filter_map(|b| validate_bytes(b).ok())
        .find(|a| a.record().record_id == r.actor_id && a.record().integrity == r.actor_digest)
        .ok_or_else(|| {
            fail(
                BlockedCode::Unauthorized,
                "F05 producer missing from fixture seed",
            )
        })?;
    r.action_spec().fingerprint()?;
    Ok(producer)
}
fn append(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    event: FixtureEventV1,
) -> FixtureResult<()> {
    let h = replay_fixture_history(store)?;
    append_fixture_event(store, &r.run_id, h.head_id(), event)?;
    Ok(())
}
fn envelope(r: &FixtureBrokerRequestV1, payload: RecordPayload) -> FixtureResult<ValidatedRecord> {
    encode_fixture(RecordEnvelope {
        record_type: payload.record_type(),
        schema_version: 1,
        namespace: Namespace::Fixture,
        record_id: payload.primary_id().to_owned(),
        creator_ref: r.actor_id.clone(),
        created_at_unix_ms: 1,
        payload,
        integrity: format!("sha256:{}", "0".repeat(64)),
    })
    .map_err(|_| invalid("F05 F01 evidence encoding"))
}
struct RawObservationInput<'a> {
    name: &'a str,
    method: &'a str,
    bytes: &'a [u8],
    revision: &'a str,
}
fn observation(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    current: &FixtureAdmissionInput<'_>,
    producer: &ValidatedRecord,
    raw: RawObservationInput<'_>,
) -> FixtureResult<String> {
    let RawObservationInput {
        name,
        method,
        bytes,
        revision,
    } = raw;
    store.check_paths()?;
    let path = store.raw_path(name)?;
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .map_err(|_| {
            fail(
                BlockedCode::EnvironmentFailure,
                "F05 raw observation slot unavailable",
            )
        })?;
    f.write_all(bytes).and_then(|_| f.sync_all()).map_err(|_| {
        fail(
            BlockedCode::EnvironmentFailure,
            "F05 observation persistence failed",
        )
    })?;
    let evidence_id = format!("fx:evidence:{name}");
    let record = envelope(
        r,
        RecordPayload::EvidenceRef(EvidenceRef {
            evidence_id: evidence_id.clone(),
            kind: "OBSERVATION".into(),
            locator: format!("fixture://f04/raw/{name}"),
            content_digest: hash(b"", bytes),
            producer_ref: r.actor_id.clone(),
            method: method.into(),
            subject_ref: r.target_id.clone(),
            subject_revision: revision.into(),
            observed_at_ms: 1,
            contract_ref: r.contract_id.clone(),
            run_ref: r.run_id.clone(),
            gate_ref: Some(r.gate_ref.clone()),
            status: EvidenceStatus::Current,
        }),
    )?;
    append(
        store,
        r,
        observation_event(current.seed, &record, producer, &r.contract_digest)?,
    )?;
    Ok(evidence_id)
}
fn probe(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    current: &FixtureAdmissionInput<'_>,
    producer: &ValidatedRecord,
    conclusion: ReconciliationConclusionV1,
    after: &str,
) -> FixtureResult<String> {
    let spec = r.action_spec();
    let p = FixtureEffectProbeV1 {
        action_id: r.action_id.clone(),
        fingerprint: spec.fingerprint()?,
        target_id: r.target_id.clone(),
        before_state: spec.before_state,
        after_state: after.into(),
        conclusion,
    };
    let name = format!("effect-{}", &p.fingerprint[7..39]);
    observation(
        store,
        r,
        current,
        producer,
        RawObservationInput {
            name: &name,
            method: "EFFECT_PROBE",
            bytes: &serde_json::to_vec(&p).map_err(|_| invalid("F05 effect probe encoding"))?,
            revision: after,
        },
    )
}
fn outcome_event(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    status: OutcomeVariant,
    refs: Vec<String>,
    revision: &str,
) -> FixtureResult<()> {
    let record = envelope(
        r,
        RecordPayload::Outcome(Outcome {
            outcome_id: format!("fx:outcome:{}", &r.action_spec().fingerprint()?[7..39]),
            status_and_code: status,
            scope_ref: r.run_id.clone(),
            evidence_refs: refs,
            next_action: "RETURN_TO_CONTROL_ROOM_NO_AUTOMATIC_RETRY".into(),
            detail: "F05 synthetic dispatch only".into(),
        }),
    )?;
    append(
        store,
        r,
        FixtureEventV1::Outcome {
            record: record.canonical_bytes().to_vec(),
            context: FixtureOutcomeContextV1 {
                action: r.action_spec(),
                contract_id: r.contract_id.clone(),
                subject_revision: revision.into(),
                gate_ref: r.gate_ref.clone(),
            },
        },
    )
}
fn effect(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    state: EffectStateV1,
    refs: Vec<String>,
) -> FixtureResult<()> {
    append(
        store,
        r,
        FixtureEventV1::Effect {
            action_id: r.action_id.clone(),
            spec: r.action_spec(),
            fingerprint: r.action_spec().fingerprint()?,
            idempotency_id: r.idempotency_id.clone(),
            state,
            evidence_ids: refs,
        },
    )
}

pub fn dispatch_fixture_operation(
    store: &FixtureStoreV1,
    r: &FixtureBrokerRequestV1,
    admission: &FixtureAdmissionV1,
    current: &FixtureAdmissionInput<'_>,
    fault: FixtureFaultV1,
) -> FixtureDispatchResultV1 {
    let producer = match validate_request(store, r, admission, current) {
        Ok(v) => v,
        Err(e) => return blocked(store, r, e),
    };
    let h = match replay_fixture_history(store) {
        Ok(h) => h,
        Err(e) => return blocked(store, r, e),
    };
    if !h.unresolved_fingerprints().is_empty() {
        return unknown(store, r, 0, "F04 unresolved history; no retry");
    }
    if let Some((_, (code, _))) = h.blockers.iter().find(|(_, (_, active))| *active) {
        return blocked(store, r, fail(code.clone(), "F04 active blocker"));
    }
    if h.observations.values().any(|(e, _)| {
        e.method == "FIXTURE_PROBE"
            && store
                .read_raw(&e.locator, &e.content_digest)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<FixtureBrokerRequestV1>(&bytes).ok())
                .is_some_and(|intent| intent.resource == r.resource)
    }) {
        return blocked(
            store,
            r,
            fail(
                BlockedCode::PreconditionDrift,
                "existing F04 pending intent; no local retry authority",
            ),
        );
    }
    if h.effects.contains_key(&r.action_id)
        || h.effects.values().any(|(fp, idem, _)| {
            Some(fp) == r.action_spec().fingerprint().ok().as_ref() || idem == &r.idempotency_id
        })
        || h.entries.iter().any(|e| e.run_id == r.run_id)
    {
        return blocked(
            store,
            r,
            fail(
                BlockedCode::PreconditionDrift,
                "F04 duplicate run/action/idempotency/fingerprint",
            ),
        );
    }
    let path = match capability::fixture_marker_path(&r.case_id, &r.resource, &r.relative_marker)
        .and_then(|p| {
            capability::require_absent(&p)?;
            Ok(p)
        }) {
        Ok(v) => v,
        Err(e) => return blocked(store, r, e),
    };
    // Pending intent is an immutable F04 observation, not a second insertion of the same Effect.
    // Its create-new raw slot is bound to the stable fingerprint, independent of mutable IDs.
    let fp = r
        .action_spec()
        .fingerprint()
        .expect("validated fingerprint");
    let pending_name = format!("intent-{}", &fp[7..39]);
    let pending = serde_json::to_vec(r).expect("closed request serializes");
    if let Err(e) = observation(
        store,
        r,
        current,
        &producer,
        RawObservationInput {
            name: &pending_name,
            method: "FIXTURE_PROBE",
            bytes: &pending,
            revision: &r.action_spec().before_state,
        },
    ) {
        return blocked(store, r, e);
    }
    let drift;
    let check = if fault == FixtureFaultV1::BeforeRevalidationDrift {
        drift = {
            let mut v = current.preconditions.clone();
            if let Some(c) = v.conditions.first_mut() {
                c.fixture_revision.push_str("-drift");
            }
            v
        };
        let changed = FixtureAdmissionInput {
            preconditions: &drift,
            ..*current
        };
        revalidate_fixture_admission(admission, &changed)
    } else {
        revalidate_fixture_admission(admission, current)
    };
    if let Err(e) = check {
        let state = r.action_spec().before_state;
        let recorded = probe(
            store,
            r,
            current,
            &producer,
            ReconciliationConclusionV1::DidNotOccur,
            &state,
        )
        .and_then(|id| {
            effect(
                store,
                r,
                EffectStateV1::FailedBeforeOccurrence,
                vec![id.clone()],
            )?;
            outcome_event(
                store,
                r,
                OutcomeVariant::Blocked(e.code.clone()),
                vec![id],
                &state,
            )
        });
        if recorded.is_err() {
            return blocked(
                store,
                r,
                fail(
                    BlockedCode::InsufficientEvidence,
                    "F03 blocked; no handler; recording failed",
                ),
            );
        }
        return blocked(store, r, e);
    }
    let fresh = serde_json::to_vec(&(
        "F05_FRESH_F03_REVALIDATION_V1",
        &r.admission_id,
        &r.admission_digest,
        &r.authority_state_id,
        &r.target_state_id,
        &r.contract_digest,
    ))
    .expect("closed revalidation observation serializes");
    if let Err(e) = observation(
        store,
        r,
        current,
        &producer,
        RawObservationInput {
            name: &format!("fresh-{}", &fp[7..39]),
            method: "FIXTURE_PROBE",
            bytes: &fresh,
            revision: &r.target_state_id,
        },
    ) {
        return blocked(store, r, e);
    }
    // Durable conservative state precedes the sole handler call. Failure here never invokes it.
    if let Err(e) = effect(store, r, EffectStateV1::PossiblyOccurredInterrupted, vec![]) {
        return blocked(store, r, e);
    }
    if fault == FixtureFaultV1::InterruptBeforeHandler {
        return unknown(store, r, 0, "injected interruption after durable arming");
    }
    // Recheck closed path immediately at invocation, but never replace F03's freshness check.
    if capability::fixture_marker_path(&r.case_id, &r.resource, &r.relative_marker).is_err()
        || capability::require_absent(&path).is_err()
    {
        return unknown(
            store,
            r,
            0,
            "target changed after arming; preserve uncertainty",
        );
    }
    let marker = FixtureMarkerV1 {
        marker: HANDLER.into(),
        namespace: "FIXTURE".into(),
        case_id: r.case_id.clone(),
        resource: r.resource.clone(),
        action_id: r.action_id.clone(),
        idempotency_id: r.idempotency_id.clone(),
        payload_digest: r.payload_digest.clone(),
    };
    let expected = serde_json::to_vec(&marker).expect("closed marker serializes");
    let observation_result = capability::invoke_once(&path, &expected, fault);
    let count = 1;
    let observed = capability::observe_marker(&path);
    if fault == FixtureFaultV1::PostEffectRecordingFailure || observation_result.interrupted {
        return unknown(
            store,
            r,
            count,
            "possible/partial/interrupted effect; no completion proof",
        );
    }
    let (conclusion, revision, status) = if observation_result.proven_before_write {
        (
            ReconciliationConclusionV1::DidNotOccur,
            r.action_spec().before_state,
            OutcomeVariant::Fail(FailCode::WorkFailed),
        )
    } else if observed.is_ok_and(|b| b == expected) {
        (
            ReconciliationConclusionV1::Occurred,
            hash(b"TITAN-FWD-F05\0marker-state-v1\0", &expected),
            OutcomeVariant::Pass(PassCode::WorkCompleted),
        )
    } else {
        return unknown(store, r, count, "marker occurrence unestablished");
    };
    let record = probe(store, r, current, &producer, conclusion, &revision).and_then(|proof| {
        append(
            store,
            r,
            FixtureEventV1::Reconciliation {
                action_id: r.action_id.clone(),
                conclusion,
                evidence_ids: vec![proof.clone()],
            },
        )?;
        outcome_event(store, r, status.clone(), vec![proof], &revision)
    });
    if record.is_err() {
        return unknown(
            store,
            r,
            count,
            "post-effect evidence/history recording failed; no reusable success",
        );
    }
    result(
        store,
        r,
        status,
        count,
        "one bounded fixture handler invocation; no retry",
    )
}
