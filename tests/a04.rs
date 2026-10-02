//! A04 exercises synthetic F04 bytes only. F03's pre-existing accepted target is read-only here.

use std::{fs, path::PathBuf};

use titan_kernel::{
    ValidatedRecord,
    admission::{
        FixtureAdmissionInput, FixtureAdmissionV1, FixtureConditionStatus, FixtureConditionValueV1,
        FixturePreconditionSnapshotV1, FixtureScopeV1, evaluate_fixture_admission,
    },
    authority::{ResolvedFixtureOutcome, resolve_fixture_request},
    encode_fixture,
    evidence::{
        ActionSpecV1, BlockerResolutionMechanismV1, EffectStateV1, F04_ROOT, FixtureBlockerProbeV1,
        FixtureEffectProbeV1, FixtureEventV1, FixtureStoreV1, ReconciliationConclusionV1,
        append_fixture_event, hash, observation_event, replay_fixture_history,
    },
    fixture_projection::{
        FixtureAuthoritySeedV1, FixtureEventKind, FixtureEventV1 as AuthorityEvent,
        FixtureProjection, IssuerScopeV1, apply_fixture_event,
    },
    outcome::{BlockedCode, OutcomeVariant, PassCode, UnknownCode},
    records::{
        ActorBinding, AuthorityClass, AuthorityRecord, BindingState, ClaimAtom, EvidenceRef,
        EvidenceStatus, ExecutionContract, Namespace, Outcome, ProjectBinding, Provision,
        RecordEnvelope, RecordPayload, ResourceMatch, Role,
    },
    recovery::{
        FixtureCheckpointInput, FixtureCheckpointV1, ResumeSemanticV1, append_fixture_checkpoint,
        check_fixture_target_dependency, evaluate_fixture_resume, make_fixture_checkpoint,
    },
    selector::{NormalizedSelector, SelectorProfileV1, normalize_fixture_selector},
    target::{APPROVED_FIXTURE_ROOT, FixtureTargetPolicyV1, construct_fixture_target_snapshot},
};

const PROJECT: &str = "fx:project:lab";
const ACTOR: &str = "fx:actor:synthetic";
const TARGET: &str = "fx:target:a03-01";
const RESOURCE: &str = "fixture://resource/lab";
const ZERO: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn record(payload: RecordPayload) -> ValidatedRecord {
    let id = payload.primary_id().to_owned();
    encode_fixture(RecordEnvelope {
        record_type: payload.record_type(),
        schema_version: 1,
        namespace: Namespace::Fixture,
        record_id: id,
        creator_ref: ACTOR.into(),
        created_at_unix_ms: 3,
        payload,
        integrity: ZERO.into(),
    })
    .unwrap()
}
fn evidence_of(v: &ValidatedRecord) -> EvidenceRef {
    let RecordPayload::EvidenceRef(e) = &v.record().payload else {
        panic!("fixture evidence required")
    };
    e.clone()
}
fn project() -> ValidatedRecord {
    record(RecordPayload::ProjectBinding(ProjectBinding {
        project_id: PROJECT.into(),
        canonical_root: "fixture://project/lab".into(),
        repository_id: None,
        repository_url: None,
        authority_source_ref: "fx:authority:seed".into(),
        binding_revision: 1,
        state: BindingState::Active,
    }))
}
fn actor() -> ValidatedRecord {
    record(RecordPayload::ActorBinding(ActorBinding {
        actor_id: ACTOR.into(),
        principal_ref: "fx:principal:synthetic".into(),
        auth_method_ref: "fx:method:fixture".into(),
        roles: vec![Role::DecisionAuthority],
        issued_by_ref: ACTOR.into(),
        valid_from_ms: 1,
        valid_until_ms: None,
        revocation_ref: None,
    }))
}
fn profile() -> SelectorProfileV1 {
    SelectorProfileV1 {
        normalizer_version: 1,
        compatibility_version: 1,
        actions: vec!["READ".into(), "UPDATE".into()],
        effects: vec!["READ_RESOURCE".into(), "MUTATE_RESOURCE".into()],
        contexts: vec!["READY".into()],
        aliases: vec![],
    }
}
fn atom(resource: &str, kind: ResourceMatch, action: &str, effect: &str) -> ClaimAtom {
    ClaimAtom {
        project_binding_ref: PROJECT.into(),
        resource_ref: resource.into(),
        resource_match: kind,
        action: action.into(),
        provision: Provision::Permit,
        effect: effect.into(),
        lifecycle_contexts: vec!["READY".into()],
    }
}
fn normalized(atom: &ClaimAtom, profile: &SelectorProfileV1) -> Vec<NormalizedSelector> {
    normalize_fixture_selector(atom, profile).unwrap()
}
fn seed(p: &ValidatedRecord, a: &ValidatedRecord) -> FixtureAuthoritySeedV1 {
    let profile = profile();
    let mut broad = normalized(
        &atom(RESOURCE, ResourceMatch::Subtree, "READ", "READ_RESOURCE"),
        &profile,
    );
    broad.extend(normalized(
        &atom(
            RESOURCE,
            ResourceMatch::Subtree,
            "UPDATE",
            "MUTATE_RESOURCE",
        ),
        &profile,
    ));
    broad.sort();
    FixtureAuthoritySeedV1 {
        project_record: p.canonical_bytes().to_vec(),
        actor_records: vec![a.canonical_bytes().to_vec()],
        profile,
        issuers: vec![IssuerScopeV1 {
            actor_id: ACTOR.into(),
            role: Role::DecisionAuthority,
            claim_scope: broad.clone(),
            override_scope: broad.clone(),
            revocation_scope: broad.clone(),
            reinstatement_scope: broad,
        }],
    }
}
fn claim(
    state: &mut FixtureProjection,
    seed: &FixtureAuthoritySeedV1,
    slug: &str,
    action: &str,
    effect: &str,
) {
    let id = format!("fx:authority:{slug}");
    let r = record(RecordPayload::AuthorityRecord(AuthorityRecord {
        authority_id: id.clone(),
        class: AuthorityClass::Decision,
        issuer_actor_ref: ACTOR.into(),
        exercised_role: Role::DecisionAuthority,
        effective_at_ms: 3,
        target_binding_ref: Some(PROJECT.into()),
        contract_digest: None,
        claim_atoms: vec![atom(RESOURCE, ResourceMatch::Subtree, action, effect)],
        override_edges: vec![],
        evidence_refs: vec![],
    }));
    let e = AuthorityEvent {
        event_id: format!("fx:event:{slug}"),
        kind: FixtureEventKind::ClaimAcceptance,
        record_id: id,
        record_digest: r.record().integrity.clone(),
        issuer_actor_id: ACTOR.into(),
        expected_prior_state_id: state.state_id.clone(),
        target_claim_id: None,
        target_edge_id: None,
    };
    apply_fixture_event(state, seed, &r, &e).unwrap();
}

struct Harness {
    project: ValidatedRecord,
    actor: ValidatedRecord,
    contract: ValidatedRecord,
    seed: FixtureAuthoritySeedV1,
    state: FixtureProjection,
    resolution: ResolvedFixtureOutcome,
    policy: FixtureTargetPolicyV1,
    read: Vec<FixtureScopeV1>,
    preconditions: FixturePreconditionSnapshotV1,
    expected_id: String,
    expected_digest: String,
    store: FixtureStoreV1,
    run: String,
}
impl Harness {
    fn new(case: &str) -> Self {
        let project = project();
        let actor = actor();
        let seed = seed(&project, &actor);
        let name = format!("a04-{case}-{}", std::process::id());
        let store = FixtureStoreV1::open(&name, &seed).unwrap();
        let mut state = FixtureProjection::from_seed(&seed).unwrap();
        claim(&mut state, &seed, "a04-read", "READ", "READ_RESOURCE");
        let read = vec![FixtureScopeV1 {
            resource_ref: format!("{RESOURCE}/a"),
            match_kind: ResourceMatch::Exact,
        }];
        let request = normalized(
            &atom(
                &read[0].resource_ref,
                ResourceMatch::Exact,
                "READ",
                "READ_RESOURCE",
            ),
            &seed.profile,
        );
        let resolution = resolve_fixture_request(&state, &state.state_id, &request).unwrap();
        // A04 only observes the already-existing F03 target; it does not create or rewrite it.
        let marker = PathBuf::from(APPROVED_FIXTURE_ROOT).join("targets/a03-01.json");
        assert!(
            marker.is_file(),
            "accepted F03 fixture prerequisite absent: {}",
            marker.display()
        );
        let policy = FixtureTargetPolicyV1 {
            project_id: PROJECT.into(),
            project_digest: project.record().integrity.clone(),
            project_uri: "fixture://project/lab".into(),
            approved_root: PathBuf::from(APPROVED_FIXTURE_ROOT),
            target_id: TARGET.into(),
            relative_marker_path: PathBuf::from("targets/a03-01.json"),
        };
        let target = construct_fixture_target_snapshot(&policy).unwrap();
        let contract = record(RecordPayload::ExecutionContract(ExecutionContract {
            contract_id: "fx:contract:a04".into(),
            contract_version: 1,
            mission: "Synthetic observation and inert resume".into(),
            project_binding_ref: PROJECT.into(),
            target_ref: TARGET.into(),
            expected_target_state: target.state_id,
            actor_ref: ACTOR.into(),
            capability_code: "FIXTURE_OPERATION".into(),
            allowed_operations: vec!["READ".into()],
            read_scopes: vec![format!("{RESOURCE}/*")],
            allowed_mutations: vec![],
            prohibited_mutations: vec![format!("{RESOURCE}/blocked")],
            precondition_refs: vec!["fx:precondition:ready".into()],
            required_evidence_refs: vec!["fx:evidence:ready".into()],
            verification_gate_refs: vec!["fx:gate:ready".into()],
            stop_codes: vec!["STOP_NOW".into()],
            escalation_ref: "fx:route:control-room".into(),
            expected_deliverables: vec!["fixture decision".into()],
            requester_boundary: "fixture only".into(),
            network_allowed: false,
            secret_access_allowed: false,
            cross_surface_delivery_allowed: false,
        }));
        let preconditions = FixturePreconditionSnapshotV1 {
            conditions: [
                "fx:evidence:ready",
                "fx:gate:ready",
                "fx:precondition:ready",
            ]
            .iter()
            .map(|r| FixtureConditionValueV1 {
                reference: (*r).into(),
                fixture_revision: "r1".into(),
                fixture_digest: ZERO.into(),
                status: FixtureConditionStatus::Satisfied,
            })
            .collect(),
            active_stop_codes: vec![],
            fixture_epoch_ms: 3,
        };
        let expected_id = contract.record().record_id.clone();
        let expected_digest = contract.record().integrity.clone();
        Self {
            project,
            actor,
            contract,
            seed,
            state,
            resolution,
            policy,
            read,
            preconditions,
            expected_id,
            expected_digest,
            store,
            run: format!("fx:run:{name}"),
        }
    }
    fn input(&self) -> FixtureAdmissionInput<'_> {
        FixtureAdmissionInput {
            project: &self.project,
            actor: &self.actor,
            contract: &self.contract,
            expected_contract_id: &self.expected_id,
            expected_contract_digest: &self.expected_digest,
            seed: &self.seed,
            authority_state: &self.state,
            supplied_resolution: &self.resolution,
            target_policy: &self.policy,
            requested_capability: "FIXTURE_OPERATION",
            requested_operation: "READ",
            requested_read_scopes: &self.read,
            requested_mutation_scopes: &[],
            network_requested: false,
            secret_requested: false,
            cross_surface_requested: false,
            preconditions: &self.preconditions,
        }
    }
    fn admission(&self) -> FixtureAdmissionV1 {
        evaluate_fixture_admission(&self.input()).unwrap()
    }
    fn append(&self, event: FixtureEventV1) -> titan_kernel::evidence::FixtureHistoryEntryV1 {
        let head = replay_fixture_history(&self.store)
            .unwrap()
            .head_id()
            .to_owned();
        append_fixture_event(&self.store, &self.run, &head, event).unwrap()
    }
    fn reject(&self, event: FixtureEventV1, code: BlockedCode) {
        let before = replay_fixture_history(&self.store).unwrap();
        let head = before.head_id().to_owned();
        let result = append_fixture_event(&self.store, &self.run, &head, event);
        assert!(
            matches!(result,Err(ref e) if e.code==code),
            "expected {code:?}, got {result:?}"
        );
        assert_eq!(
            before.history_id(self.store.case_id()).unwrap(),
            replay_fixture_history(&self.store)
                .unwrap()
                .history_id(self.store.case_id())
                .unwrap()
        );
    }
    fn raw_observation(&self, id: &str, method: &str, bytes: &[u8]) -> ValidatedRecord {
        let path = self.store.raw_path(id).unwrap();
        fs::write(&path, bytes).unwrap();
        let target = construct_fixture_target_snapshot(&self.policy).unwrap();
        record(RecordPayload::EvidenceRef(EvidenceRef {
            evidence_id: format!("fx:evidence:{id}"),
            kind: "OBSERVATION".into(),
            locator: format!("fixture://f04/raw/{id}"),
            content_digest: hash(b"", bytes),
            producer_ref: ACTOR.into(),
            method: method.into(),
            subject_ref: TARGET.into(),
            subject_revision: target.state_id,
            observed_at_ms: 3,
            contract_ref: self.expected_id.clone(),
            run_ref: self.run.clone(),
            gate_ref: Some("fx:gate:ready".into()),
            status: EvidenceStatus::Current,
        }))
    }
    fn observe(&self, id: &str, method: &str, bytes: &[u8]) -> ValidatedRecord {
        let evidence = self.raw_observation(id, method, bytes);
        let event =
            observation_event(&self.seed, &evidence, &self.actor, &self.expected_digest).unwrap();
        self.append(event);
        evidence
    }
    fn ready(&self) {
        self.observe("ready", "FIXTURE_PROBE", b"ready");
    }
    fn blocker_proof(&self, id: &str, blocker: &str) -> ValidatedRecord {
        let state = construct_fixture_target_snapshot(&self.policy)
            .unwrap()
            .state_id;
        let probe = FixtureBlockerProbeV1 {
            blocker_id: blocker.into(),
            dependency: TARGET.into(),
            subject_revision: state,
            resolved: true,
        };
        self.observe(
            id,
            "BLOCKER_RESOLUTION",
            &serde_json::to_vec(&probe).unwrap(),
        )
    }
    fn checkpoint_input<'a>(
        &'a self,
        admission: &'a FixtureAdmissionV1,
        input: &'a FixtureAdmissionInput<'a>,
        fingerprint: &'a str,
    ) -> FixtureCheckpointInput<'a> {
        FixtureCheckpointInput {
            admission,
            current: input,
            run_id: &self.run,
            capability: "FIXTURE_OPERATION",
            operation: "READ",
            pending_step: "step",
            action_id: "fx:action:a04",
            idempotency_id: "fx:idempotency:a04",
            action_fingerprint: fingerprint,
            last_valid_step: "ready",
            completed_gate_refs: &[],
            evidence_refs: &[],
            resume_authority_ref: "fx:authority:synthetic",
            epoch: 3,
        }
    }
    fn spec(&self) -> ActionSpecV1 {
        ActionSpecV1 {
            project_id: PROJECT.into(),
            target_id: TARGET.into(),
            contract_digest: self.expected_digest.clone(),
            capability: "FIXTURE_OPERATION".into(),
            operation: "READ".into(),
            normalized_scope: format!("{RESOURCE}/a"),
            logical_step: "step".into(),
            before_state: construct_fixture_target_snapshot(&self.policy)
                .unwrap()
                .state_id,
        }
    }
    fn effect(&self, state: EffectStateV1, action: &str, idempotency: &str) -> FixtureEventV1 {
        let spec = self.spec();
        let fingerprint = spec.fingerprint().unwrap();
        FixtureEventV1::Effect {
            action_id: action.into(),
            spec,
            fingerprint,
            idempotency_id: idempotency.into(),
            state,
            evidence_ids: vec![],
        }
    }
    fn checkpoint(&self) -> (FixtureAdmissionV1, FixtureCheckpointV1) {
        let admission = self.admission();
        let current = self.input();
        let fingerprint = self.spec().fingerprint().unwrap();
        let input = self.checkpoint_input(&admission, &current, &fingerprint);
        let before = replay_fixture_history(&self.store).unwrap();
        let checkpoint = make_fixture_checkpoint(&self.store, &before, &input).unwrap();
        append_fixture_checkpoint(&self.store, &before, &checkpoint).unwrap();
        (admission, checkpoint)
    }
}

#[test]
fn a04_01_append_and_replay_identity() {
    let h = Harness::new("01");
    h.observe("one", "FIXTURE_PROBE", b"one");
    let first = replay_fixture_history(&h.store).unwrap();
    let second = replay_fixture_history(&h.store).unwrap();
    assert_eq!(
        first.history_id(h.store.case_id()).unwrap(),
        second.history_id(h.store.case_id()).unwrap()
    );
    assert_eq!(first.entries.len(), 1);
    assert_eq!(first.entries[0].sequence, 1);
}

#[test]
fn a04_02_observation_binding_and_raw_digest() {
    let h = Harness::new("02");
    let base = h.raw_observation("two", "FIXTURE_PROBE", b"two");
    let mut e = evidence_of(&base);
    e.producer_ref = "fx:actor:other".into();
    let wrong = record(RecordPayload::EvidenceRef(e));
    h.reject(
        FixtureEventV1::Observation {
            record: wrong.canonical_bytes().to_vec(),
            producer: h.actor.canonical_bytes().to_vec(),
            seed_digest: h.seed.digest().unwrap(),
            contract_digest: h.expected_digest.clone(),
        },
        BlockedCode::ContractInvalid,
    );
    let event = observation_event(&h.seed, &base, &h.actor, &h.expected_digest).unwrap();
    fs::write(h.store.raw_path("two").unwrap(), b"different").unwrap();
    h.reject(event, BlockedCode::PreconditionDrift);
}

#[test]
fn a04_03_invalidation_retains_old_bytes() {
    let h = Harness::new("03");
    let prior = h.observe("three", "FIXTURE_PROBE", b"three");
    h.observe("review", "EVIDENCE_REVIEW", b"invalid");
    let old = replay_fixture_history(&h.store).unwrap().entries[0]
        .entry_id
        .clone();
    h.append(FixtureEventV1::EvidenceInvalidated {
        evidence_id: "fx:evidence:three".into(),
        prior_digest: prior.record().integrity.clone(),
        source_evidence_id: "fx:evidence:review".into(),
        reason_code: "INVALIDATED_BY_REVIEW".into(),
        actor_id: ACTOR.into(),
        epoch: 4,
    });
    let replay = replay_fixture_history(&h.store).unwrap();
    assert_eq!(replay.entries[0].entry_id, old);
    assert!(!replay.current_evidence("fx:evidence:three"));
    assert_eq!(
        replay.evidence_status["fx:evidence:three"],
        EvidenceStatus::Invalidated
    );
}

#[test]
fn a04_04_supersession_preserves_both_records() {
    let h = Harness::new("04");
    let old = h.observe("old", "FIXTURE_PROBE", b"old");
    h.observe("new", "FIXTURE_PROBE", b"new");
    h.append(FixtureEventV1::EvidenceSuperseded {
        old_id: "fx:evidence:old".into(),
        new_id: "fx:evidence:new".into(),
        prior_digest: old.record().integrity.clone(),
        source_evidence_id: "fx:evidence:new".into(),
        reason_code: "SUPERSEDED_BY_NEW_OBSERVATION".into(),
        actor_id: ACTOR.into(),
        epoch: 4,
    });
    let r = replay_fixture_history(&h.store).unwrap();
    assert_eq!(r.observations.len(), 2);
    assert!(!r.current_evidence("fx:evidence:old"));
    assert!(r.current_evidence("fx:evidence:new"));
}

#[test]
fn a04_05_inference_cannot_be_raw_observation() {
    let h = Harness::new("05");
    let base = h.raw_observation("inference", "FIXTURE_PROBE", b"inference");
    let mut e = evidence_of(&base);
    e.kind = "INFERENCE".into();
    let invalid = record(RecordPayload::EvidenceRef(e));
    h.reject(
        FixtureEventV1::Observation {
            record: invalid.canonical_bytes().to_vec(),
            producer: h.actor.canonical_bytes().to_vec(),
            seed_digest: h.seed.digest().unwrap(),
            contract_digest: h.expected_digest.clone(),
        },
        BlockedCode::ContractInvalid,
    );
}

#[test]
fn a04_06_approval_cannot_be_raw_observation() {
    let h = Harness::new("06");
    let base = h.raw_observation("approval", "FIXTURE_PROBE", b"approval");
    let mut e = evidence_of(&base);
    e.kind = "APPROVAL".into();
    let invalid = record(RecordPayload::EvidenceRef(e));
    h.reject(
        FixtureEventV1::Observation {
            record: invalid.canonical_bytes().to_vec(),
            producer: h.actor.canonical_bytes().to_vec(),
            seed_digest: h.seed.digest().unwrap(),
            contract_digest: h.expected_digest.clone(),
        },
        BlockedCode::ContractInvalid,
    );
}

#[test]
fn a04_07_checkpoint_identity_is_deterministic() {
    let h = Harness::new("07");
    h.ready();
    let admission = h.admission();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let history = replay_fixture_history(&h.store).unwrap();
    let a = make_fixture_checkpoint(&h.store, &history, &input).unwrap();
    let b = make_fixture_checkpoint(&h.store, &history, &input).unwrap();
    assert_eq!(a, b);
    a.verify().unwrap();
    append_fixture_checkpoint(&h.store, &history, &a).unwrap();
    assert_eq!(
        replay_fixture_history(&h.store).unwrap().checkpoints[&a.checkpoint_id],
        a.canonical_bytes().unwrap()
    );
}

#[test]
fn a04_08_missing_checkpoint_cannot_resume() {
    let h = Harness::new("08");
    h.ready();
    let admission = h.admission();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let history = replay_fixture_history(&h.store).unwrap();
    let checkpoint = make_fixture_checkpoint(&h.store, &history, &input).unwrap();
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(result.semantic, ResumeSemanticV1::StaleCheckpoint);
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::PreconditionDrift)
    ));
}

#[test]
fn a04_09_changed_contract_blocks_resume() {
    let mut h = Harness::new("09");
    h.ready();
    let (admission, checkpoint) = h.checkpoint();
    let RecordPayload::ExecutionContract(mut c) = h.contract.record().payload.clone() else {
        panic!()
    };
    c.mission = "changed synthetic contract".into();
    h.contract = record(RecordPayload::ExecutionContract(c));
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(result.semantic, ResumeSemanticV1::StaleCheckpoint);
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::PreconditionDrift)
    ));
}

#[test]
fn a04_10_changed_target_state_is_precondition_drift() {
    // Pure comparison tests the same branch used after F03 observation without writing F03's fixture root.
    let h = Harness::new("10");
    let observed = construct_fixture_target_snapshot(&h.policy).unwrap();
    assert!(
        check_fixture_target_dependency(TARGET, &observed.state_id, TARGET, &observed.state_id)
            .is_ok()
    );
    let result =
        check_fixture_target_dependency(TARGET, "different-state", TARGET, &observed.state_id);
    assert!(matches!(result,Err(ref e) if e.code==BlockedCode::PreconditionDrift));
}

#[test]
fn a04_11_authority_state_drift_blocks_resume() {
    let mut h = Harness::new("11");
    h.ready();
    let (admission, checkpoint) = h.checkpoint();
    h.state.state_id =
        "sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::AuthorityStale)
    ));
}

#[test]
fn a04_12_invalidated_evidence_blocks_current_use() {
    let h = Harness::new("12");
    let prior = h.observe("ready", "FIXTURE_PROBE", b"ready");
    h.observe("review", "EVIDENCE_REVIEW", b"invalid");
    h.append(FixtureEventV1::EvidenceInvalidated {
        evidence_id: "fx:evidence:ready".into(),
        prior_digest: prior.record().integrity.clone(),
        source_evidence_id: "fx:evidence:review".into(),
        reason_code: "INVALIDATED_BY_REVIEW".into(),
        actor_id: ACTOR.into(),
        epoch: 4,
    });
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(result.semantic, ResumeSemanticV1::InvalidEvidence);
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::PreconditionDrift)
    ));
}

#[test]
fn a04_13_missing_required_evidence_blocks_resume() {
    let h = Harness::new("13");
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::InsufficientEvidence)
    ));
}

#[test]
fn a04_14_active_blocker_is_preserved() {
    let h = Harness::new("14");
    h.ready();
    h.append(FixtureEventV1::BlockerOpened {
        blocker_id: "fx:blocker:halt".into(),
        code: BlockedCode::ScopeViolation,
        dependency: "fx:dependency:scope".into(),
    });
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::ScopeViolation)
    ));
    assert!(replay_fixture_history(&h.store).unwrap().blockers["fx:blocker:halt"].1);
}

#[test]
fn a04_15_conversation_claim_cannot_clear_blocker() {
    let h = Harness::new("15");
    h.ready();
    h.append(FixtureEventV1::BlockerOpened {
        blocker_id: "fx:blocker:halt".into(),
        code: BlockedCode::ScopeViolation,
        dependency: "fx:dependency:scope".into(),
    });
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let before = replay_fixture_history(&h.store)
        .unwrap()
        .history_id(h.store.case_id())
        .unwrap();
    let _untrusted_chat = "The blocker was resolved.";
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::ScopeViolation)
    ));
    assert_eq!(
        before,
        replay_fixture_history(&h.store)
            .unwrap()
            .history_id(h.store.case_id())
            .unwrap()
    );
}

#[test]
fn a04_16_exact_observed_blocker_resolution() {
    let h = Harness::new("16");
    h.ready();
    h.append(FixtureEventV1::BlockerOpened {
        blocker_id: "fx:blocker:halt".into(),
        code: BlockedCode::ScopeViolation,
        dependency: TARGET.into(),
    });
    let proof = h.blocker_proof("resolution", "fx:blocker:halt");
    h.append(FixtureEventV1::BlockerResolved {
        blocker_id: "fx:blocker:halt".into(),
        mechanism: BlockerResolutionMechanismV1::Observation,
        evidence_ids: vec!["fx:evidence:resolution".into()],
        support_digests: vec![proof.record().integrity.clone()],
        actor_id: ACTOR.into(),
        reason: "fixture observation".into(),
        epoch: 4,
    });
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(result.semantic, ResumeSemanticV1::Resumable);
    assert!(!replay_fixture_history(&h.store).unwrap().blockers["fx:blocker:halt"].1);
}

#[test]
fn a04_17_pre_effect_and_possible_effect_are_distinct() {
    let h = Harness::new("17");
    h.append(h.effect(
        EffectStateV1::NotAttempted,
        "fx:action:before",
        "fx:idempotency:before",
    ));
    let mut distinct = h.spec();
    distinct.logical_step = "later-step".into();
    h.append(FixtureEventV1::Effect {
        action_id: "fx:action:possible".into(),
        fingerprint: distinct.fingerprint().unwrap(),
        spec: distinct,
        idempotency_id: "fx:idempotency:possible".into(),
        state: EffectStateV1::PossiblyOccurredInterrupted,
        evidence_ids: vec![],
    });
    let r = replay_fixture_history(&h.store).unwrap();
    assert_eq!(r.effects["fx:action:before"].2, EffectStateV1::NotAttempted);
    assert_eq!(
        r.effects["fx:action:possible"].2,
        EffectStateV1::PossiblyOccurredInterrupted
    );
}

#[test]
fn a04_18_possible_effect_yields_unknown() {
    let h = Harness::new("18");
    h.ready();
    h.append(h.effect(
        EffectStateV1::PossiblyOccurredInterrupted,
        "fx:action:a04",
        "fx:idempotency:a04",
    ));
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(result.semantic, ResumeSemanticV1::ReconciliationRequired);
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled)
    ));
}

#[test]
fn a04_19_partial_effect_cannot_be_pass_or_fail() {
    let h = Harness::new("19");
    h.ready();
    h.append(h.effect(
        EffectStateV1::PartiallyOccurred,
        "fx:action:a04",
        "fx:idempotency:a04",
    ));
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert!(matches!(
        result.outcome,
        OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled)
    ));
}

#[test]
fn a04_20_new_retry_identity_cannot_bypass_unresolved_fingerprint() {
    let h = Harness::new("20");
    h.append(h.effect(
        EffectStateV1::OutcomeUnestablished,
        "fx:action:old",
        "fx:idempotency:old",
    ));
    h.reject(
        h.effect(
            EffectStateV1::NotAttempted,
            "fx:action:new",
            "fx:idempotency:new",
        ),
        BlockedCode::PreconditionDrift,
    );
    let reopened = FixtureStoreV1::open(h.store.case_id(), &h.seed).unwrap();
    assert_eq!(replay_fixture_history(&reopened).unwrap().effects.len(), 1);
}

fn append_probe(
    h: &Harness,
    id: &str,
    action: &str,
    spec: &ActionSpecV1,
    conclusion: ReconciliationConclusionV1,
    after_state: &str,
) -> String {
    let probe = FixtureEffectProbeV1 {
        action_id: action.into(),
        fingerprint: spec.fingerprint().unwrap(),
        target_id: TARGET.into(),
        before_state: spec.before_state.clone(),
        after_state: after_state.into(),
        conclusion,
    };
    let bytes = serde_json::to_vec(&probe).unwrap();
    let base = h.raw_observation(id, "EFFECT_PROBE", &bytes);
    let mut evidence = evidence_of(&base);
    evidence.subject_revision = after_state.into();
    let r = record(RecordPayload::EvidenceRef(evidence));
    h.append(observation_event(&h.seed, &r, &h.actor, &h.expected_digest).unwrap());
    format!("fx:evidence:{id}")
}

#[test]
fn a04_21_reconciliation_observed_occurrence() {
    let h = Harness::new("21");
    let mut spec = h.spec();
    spec.before_state = "state-before".into();
    let fingerprint = spec.fingerprint().unwrap();
    let action = "fx:action:occurrence";
    h.append(FixtureEventV1::Effect {
        action_id: action.into(),
        spec: spec.clone(),
        fingerprint,
        idempotency_id: "fx:idempotency:occurrence".into(),
        state: EffectStateV1::PossiblyOccurredInterrupted,
        evidence_ids: vec![],
    });
    let after = construct_fixture_target_snapshot(&h.policy)
        .unwrap()
        .state_id;
    let proof = append_probe(
        &h,
        "occurred",
        action,
        &spec,
        ReconciliationConclusionV1::Occurred,
        &after,
    );
    h.append(FixtureEventV1::Reconciliation {
        action_id: action.into(),
        conclusion: ReconciliationConclusionV1::Occurred,
        evidence_ids: vec![proof],
    });
    let replay = replay_fixture_history(&h.store).unwrap();
    assert_eq!(replay.effects[action].2, EffectStateV1::CompletedObserved);
    h.reject(
        h.effect(
            EffectStateV1::NotAttempted,
            "fx:action:replay",
            "fx:idempotency:replay",
        ),
        BlockedCode::PreconditionDrift,
    );
    assert!(
        replay
            .entries
            .iter()
            .any(|e| matches!(e.event, FixtureEventV1::Reconciliation { .. }))
    );
}

#[test]
fn a04_22_nonoccurrence_requires_separate_fresh_evaluation() {
    let h = Harness::new("22");
    let spec = h.spec();
    let action = "fx:action:a04";
    h.append(FixtureEventV1::Effect {
        action_id: action.into(),
        fingerprint: spec.fingerprint().unwrap(),
        spec: spec.clone(),
        idempotency_id: "fx:idempotency:a04".into(),
        state: EffectStateV1::OutcomeUnestablished,
        evidence_ids: vec![],
    });
    let proof = append_probe(
        &h,
        "not-occurred",
        action,
        &spec,
        ReconciliationConclusionV1::DidNotOccur,
        &spec.before_state,
    );
    h.append(FixtureEventV1::Reconciliation {
        action_id: action.into(),
        conclusion: ReconciliationConclusionV1::DidNotOccur,
        evidence_ids: vec![proof],
    });
    let replay = replay_fixture_history(&h.store).unwrap();
    assert_eq!(
        replay.effects[action].2,
        EffectStateV1::FailedBeforeOccurrence
    );
    assert!(replay.checkpoints.is_empty());
    h.ready();
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = spec.fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let decision = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(decision.semantic, ResumeSemanticV1::Resumable);
}

#[test]
fn a04_23_opposed_probes_remain_unknown() {
    let h = Harness::new("23");
    let mut spec = h.spec();
    spec.before_state = "state-before".into();
    let action = "fx:action:opposed";
    h.append(FixtureEventV1::Effect {
        action_id: action.into(),
        fingerprint: spec.fingerprint().unwrap(),
        spec: spec.clone(),
        idempotency_id: "fx:idempotency:opposed".into(),
        state: EffectStateV1::PartiallyOccurred,
        evidence_ids: vec![],
    });
    let now = construct_fixture_target_snapshot(&h.policy)
        .unwrap()
        .state_id;
    let occurred = append_probe(
        &h,
        "opposed-occurred",
        action,
        &spec,
        ReconciliationConclusionV1::Occurred,
        &now,
    );
    let not = append_probe(
        &h,
        "opposed-not",
        action,
        &spec,
        ReconciliationConclusionV1::DidNotOccur,
        &spec.before_state,
    );
    h.append(FixtureEventV1::Reconciliation {
        action_id: action.into(),
        conclusion: ReconciliationConclusionV1::Contradictory,
        evidence_ids: vec![occurred, not],
    });
    assert_eq!(
        replay_fixture_history(&h.store).unwrap().effects[action].2,
        EffectStateV1::PartiallyOccurred
    );
}

#[test]
fn a04_24_corrupt_history_fails_closed_without_repair() {
    let h = Harness::new("24");
    h.ready();
    let p = h.store.case_path().join("events/0000000001.json");
    fs::write(&p, b"{torn").unwrap();
    let before = fs::read(&p).unwrap();
    let result = replay_fixture_history(&h.store);
    assert!(matches!(result,Err(ref e) if e.code==BlockedCode::EnvironmentFailure));
    assert_eq!(before, fs::read(&p).unwrap());

    let raw = Harness::new("24-raw");
    raw.ready();
    let raw_path = raw.store.raw_path("ready").unwrap();
    fs::write(&raw_path, b"changed raw bytes").unwrap();
    let raw_before = fs::read(&raw_path).unwrap();
    assert!(
        matches!(replay_fixture_history(&raw.store),Err(ref e) if e.code==BlockedCode::PreconditionDrift)
    );
    assert_eq!(raw_before, fs::read(&raw_path).unwrap());

    let evidence = Harness::new("24-evidence");
    evidence.ready();
    let evidence_path = evidence.store.case_path().join("events/0000000001.json");
    let mut bytes = fs::read(&evidence_path).unwrap();
    bytes.push(b' ');
    fs::write(&evidence_path, &bytes).unwrap();
    assert!(
        matches!(replay_fixture_history(&evidence.store),Err(ref e) if e.code==BlockedCode::EnvironmentFailure)
    );
    assert_eq!(bytes, fs::read(&evidence_path).unwrap());

    let checkpoint = Harness::new("24-checkpoint");
    checkpoint.ready();
    let (_, mut cp) = checkpoint.checkpoint();
    cp.checkpoint_digest = ZERO.into();
    assert!(matches!(cp.verify(),Err(ref e) if e.code==BlockedCode::ContractInvalid));
    assert_eq!(
        replay_fixture_history(&checkpoint.store)
            .unwrap()
            .checkpoints
            .len(),
        1
    );
}

#[test]
fn a04_25_close_and_reopen_replays_same_state() {
    let h = Harness::new("25");
    h.ready();
    h.append(FixtureEventV1::BlockerOpened {
        blocker_id: "fx:blocker:persist".into(),
        code: BlockedCode::ScopeViolation,
        dependency: "fx:dependency:persist".into(),
    });
    let before = replay_fixture_history(&h.store).unwrap();
    let reopened = FixtureStoreV1::open(h.store.case_id(), &h.seed).unwrap();
    let after = replay_fixture_history(&reopened).unwrap();
    assert_eq!(
        before.history_id(h.store.case_id()).unwrap(),
        after.history_id(reopened.case_id()).unwrap()
    );
    assert_eq!(before.blockers, after.blockers);
    assert_eq!(before.effects, after.effects);
}

#[test]
fn a04_26_unordered_refs_have_one_checkpoint_identity() {
    let h = Harness::new("26");
    h.ready();
    h.observe("other", "FIXTURE_PROBE", b"other");
    let admission = h.admission();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let mut a = h.checkpoint_input(&admission, &current, &fingerprint);
    let refs_a = ["fx:evidence:ready".into(), "fx:evidence:other".into()];
    let refs_b = ["fx:evidence:other".into(), "fx:evidence:ready".into()];
    let history = replay_fixture_history(&h.store).unwrap();
    a.evidence_refs = &refs_a;
    let first = make_fixture_checkpoint(&h.store, &history, &a).unwrap();
    a.evidence_refs = &refs_b;
    let second = make_fixture_checkpoint(&h.store, &history, &a).unwrap();
    assert_eq!(first.checkpoint_id, second.checkpoint_id);
    let dup = ["fx:evidence:ready".into(), "fx:evidence:ready".into()];
    a.evidence_refs = &dup;
    assert!(make_fixture_checkpoint(&h.store, &history, &a).is_err());
}

#[test]
fn a04_27_current_f03_precondition_drift_blocks_resume() {
    let mut h = Harness::new("27");
    h.ready();
    let (admission, checkpoint) = h.checkpoint();
    h.preconditions.conditions[0].fixture_revision = "r2".into();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_ne!(result.semantic, ResumeSemanticV1::Resumable);
    assert!(matches!(result.outcome, OutcomeVariant::Blocked(_)));
}

#[test]
fn a04_guard_pass_requires_current_evidence_and_no_unknown_effect() {
    let h = Harness::new("guard-pass");
    let pass = record(RecordPayload::Outcome(Outcome {
        outcome_id: "fx:outcome:pass".into(),
        status_and_code: OutcomeVariant::Pass(PassCode::GatePassed),
        scope_ref: h.run.clone(),
        evidence_refs: vec![],
        next_action: "NONE".into(),
        detail: "fixture gate".into(),
    }));
    h.reject(
        FixtureEventV1::Outcome {
            record: pass.canonical_bytes().to_vec(),
        },
        BlockedCode::InsufficientEvidence,
    );
    h.ready();
    h.append(h.effect(
        EffectStateV1::PossiblyOccurredInterrupted,
        "fx:action:guard",
        "fx:idempotency:guard",
    ));
    let pass = record(RecordPayload::Outcome(Outcome {
        outcome_id: "fx:outcome:pass".into(),
        status_and_code: OutcomeVariant::Pass(PassCode::GatePassed),
        scope_ref: h.run.clone(),
        evidence_refs: vec!["fx:evidence:ready".into()],
        next_action: "NONE".into(),
        detail: "fixture gate".into(),
    }));
    h.reject(
        FixtureEventV1::Outcome {
            record: pass.canonical_bytes().to_vec(),
        },
        BlockedCode::InsufficientEvidence,
    );
}

#[test]
fn a04_guard_invalidated_reconciliation_support_reopens_unknown() {
    let h = Harness::new("guard-reopen");
    let spec = h.spec();
    let action = "fx:action:reopen";
    h.append(FixtureEventV1::Effect {
        action_id: action.into(),
        fingerprint: spec.fingerprint().unwrap(),
        spec: spec.clone(),
        idempotency_id: "fx:idempotency:reopen".into(),
        state: EffectStateV1::OutcomeUnestablished,
        evidence_ids: vec![],
    });
    let proof = append_probe(
        &h,
        "reopen",
        action,
        &spec,
        ReconciliationConclusionV1::DidNotOccur,
        &spec.before_state,
    );
    h.append(FixtureEventV1::Reconciliation {
        action_id: action.into(),
        conclusion: ReconciliationConclusionV1::DidNotOccur,
        evidence_ids: vec![proof.clone()],
    });
    assert_eq!(
        replay_fixture_history(&h.store).unwrap().effects[action].2,
        EffectStateV1::FailedBeforeOccurrence
    );
    let prior_digest = replay_fixture_history(&h.store)
        .unwrap()
        .observation_digests[&proof]
        .clone();
    h.observe("review", "EVIDENCE_REVIEW", b"invalid probe");
    h.append(FixtureEventV1::EvidenceInvalidated {
        evidence_id: proof,
        prior_digest,
        source_evidence_id: "fx:evidence:review".into(),
        reason_code: "INVALIDATED_BY_REVIEW".into(),
        actor_id: ACTOR.into(),
        epoch: 5,
    });
    assert_eq!(
        replay_fixture_history(&h.store).unwrap().effects[action].2,
        EffectStateV1::OutcomeUnestablished
    );
}

#[test]
fn a04_guard_unrelated_blocker_survives_resolution() {
    let h = Harness::new("guard-blocker");
    for name in ["one", "two"] {
        h.append(FixtureEventV1::BlockerOpened {
            blocker_id: format!("fx:blocker:{name}"),
            code: BlockedCode::ScopeViolation,
            dependency: TARGET.into(),
        });
    }
    let proof = h.blocker_proof("blocker-proof", "fx:blocker:one");
    h.append(FixtureEventV1::BlockerResolved {
        blocker_id: "fx:blocker:one".into(),
        mechanism: BlockerResolutionMechanismV1::Observation,
        evidence_ids: vec!["fx:evidence:blocker-proof".into()],
        support_digests: vec![proof.record().integrity.clone()],
        actor_id: ACTOR.into(),
        reason: "only one".into(),
        epoch: 5,
    });
    let state = replay_fixture_history(&h.store).unwrap();
    assert!(!state.blockers["fx:blocker:one"].1);
    assert!(state.blockers["fx:blocker:two"].1);
}

#[test]
fn a04_guard_action_identity_change_blocks_resume() {
    let h = Harness::new("guard-action");
    h.ready();
    let (admission, checkpoint) = h.checkpoint();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let mut input = h.checkpoint_input(&admission, &current, &fingerprint);
    input.idempotency_id = "fx:idempotency:forged";
    let result = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(result.semantic, ResumeSemanticV1::StaleCheckpoint);
}

#[test]
fn a04_guard_invalid_locator_and_duplicate_slot_reject() {
    let h = Harness::new("guard-path");
    let base = h.raw_observation("valid", "FIXTURE_PROBE", b"valid");
    let mut e = evidence_of(&base);
    e.locator = "fixture://f04/raw/%76alid".into();
    let malformed = record(RecordPayload::EvidenceRef(e));
    h.reject(
        FixtureEventV1::Observation {
            record: malformed.canonical_bytes().to_vec(),
            producer: h.actor.canonical_bytes().to_vec(),
            seed_digest: h.seed.digest().unwrap(),
            contract_digest: h.expected_digest.clone(),
        },
        BlockedCode::ContractInvalid,
    );
    h.append(observation_event(&h.seed, &base, &h.actor, &h.expected_digest).unwrap());
    let stale_head = "GENESIS";
    let result = append_fixture_event(
        &h.store,
        &h.run,
        stale_head,
        FixtureEventV1::BlockerOpened {
            blocker_id: "fx:blocker:late".into(),
            code: BlockedCode::ScopeViolation,
            dependency: TARGET.into(),
        },
    );
    assert!(matches!(result,Err(ref e) if e.code==BlockedCode::PreconditionDrift));
    assert_eq!(replay_fixture_history(&h.store).unwrap().entries.len(), 1);
}

#[test]
fn a04_guard_fixture_root_and_real_reparse_if_supported() {
    let h = Harness::new("guard-reparse");
    assert!(h.store.case_path().starts_with(F04_ROOT));
    let target = h.store.raw_path("real").unwrap();
    fs::write(&target, b"safe fixture").unwrap();
    let hardlink = h.store.raw_path("hardlink").unwrap();
    fs::hard_link(&target, &hardlink).unwrap();
    let alias = h
        .store
        .read_raw("fixture://f04/raw/hardlink", &hash(b"", b"safe fixture"));
    assert!(matches!(alias,Err(ref e) if e.code==BlockedCode::EnvironmentFailure));
    #[cfg(windows)]
    {
        let link = h.store.raw_path("link").unwrap();
        match std::os::windows::fs::symlink_file(&target, &link) {
            Ok(()) => {
                let result = h
                    .store
                    .read_raw("fixture://f04/raw/link", &hash(b"", b"safe fixture"));
                assert!(matches!(result,Err(ref e) if e.code==BlockedCode::EnvironmentFailure));
            }
            Err(e) => {
                eprintln!("OS file symlink unavailable; locator confinement remains tested: {e}")
            }
        }
    }
    assert!(
        h.store
            .read_raw("fixture://f04/raw/../real", &hash(b"", b"safe fixture"))
            .is_err()
    );
}

#[test]
fn a04_guard_completed_gate_needs_current_matching_evidence() {
    let h = Harness::new("guard-gate");
    h.ready();
    let admission = h.admission();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let mut input = h.checkpoint_input(&admission, &current, &fingerprint);
    let gates = ["fx:gate:ready".into()];
    input.completed_gate_refs = &gates;
    let history = replay_fixture_history(&h.store).unwrap();
    assert!(
        matches!(make_fixture_checkpoint(&h.store,&history,&input),Err(ref e)
        if e.code==BlockedCode::InsufficientEvidence)
    );
    let evidence = ["fx:evidence:ready".into()];
    input.evidence_refs = &evidence;
    make_fixture_checkpoint(&h.store, &history, &input).unwrap();
}

#[test]
fn a04_guard_effect_conclusion_needs_typed_bound_probe() {
    let h = Harness::new("guard-effect-proof");
    h.reject(
        h.effect(
            EffectStateV1::CompletedObserved,
            "fx:action:claim",
            "fx:idempotency:claim",
        ),
        BlockedCode::InsufficientEvidence,
    );
    h.observe("generic", "FIXTURE_PROBE", b"claimed");
    let mut event = h.effect(
        EffectStateV1::FailedBeforeOccurrence,
        "fx:action:claim",
        "fx:idempotency:claim",
    );
    if let FixtureEventV1::Effect { evidence_ids, .. } = &mut event {
        evidence_ids.push("fx:evidence:generic".into());
    }
    h.reject(event, BlockedCode::ContractInvalid);
}

#[test]
fn a04_28_fully_resumable_is_inert() {
    let h = Harness::new("28");
    h.ready();
    let admission = h.admission();
    let current = h.input();
    let fingerprint = h.spec().fingerprint().unwrap();
    let input = h.checkpoint_input(&admission, &current, &fingerprint);
    let before = replay_fixture_history(&h.store).unwrap();
    let checkpoint = make_fixture_checkpoint(&h.store, &before, &input).unwrap();
    append_fixture_checkpoint(&h.store, &before, &checkpoint).unwrap();
    let bytes = fs::read(h.store.raw_path("ready").unwrap()).unwrap();
    let first = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    let second = evaluate_fixture_resume(&h.store, &checkpoint, &input).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.semantic, ResumeSemanticV1::Resumable);
    assert_eq!(first.namespace, "FIXTURE");
    assert!(first.decision_id.starts_with("fx:resume-decision:"));
    assert_eq!(bytes, fs::read(h.store.raw_path("ready").unwrap()).unwrap());
}
