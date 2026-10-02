//! A05: one fixture-only bounded consequence, with qualified F03/F04 dependencies.

use std::{fs, path::PathBuf};

use titan_kernel::{
    ValidatedRecord,
    admission::{
        FixtureAdmissionInput, FixtureConditionStatus, FixtureConditionValueV1,
        FixturePreconditionSnapshotV1, FixtureScopeV1, decode_fixture_admission,
        evaluate_fixture_admission,
    },
    authority::{ResolvedFixtureOutcome, resolve_fixture_request},
    encode_fixture,
    fixture_projection::{
        FixtureAuthoritySeedV1, FixtureEventKind, FixtureEventV1, FixtureProjection, IssuerScopeV1,
        apply_fixture_event,
    },
    outcome::BlockedCode,
    records::{
        ActorBinding, AuthorityClass, AuthorityRecord, BindingState, ClaimAtom, ExecutionContract,
        Namespace, ProjectBinding, Provision, RecordEnvelope, RecordPayload, ResourceMatch, Role,
    },
    selector::{AliasEntry, NormalizedSelector, SelectorProfileV1, normalize_fixture_selector},
    target::{
        APPROVED_FIXTURE_ROOT, FixtureTargetMarkerV1, FixtureTargetPolicyV1,
        construct_fixture_target_snapshot,
    },
    validate_bytes,
};

const PROJECT: &str = "fx:project:lab";
const ACTOR: &str = "fx:actor:synthetic";
const ZERO: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const RESOURCE: &str = "fixture://resource/lab";

fn record(payload: RecordPayload) -> ValidatedRecord {
    let id = payload.primary_id().to_owned();
    encode_fixture(RecordEnvelope {
        record_type: payload.record_type(),
        schema_version: 1,
        namespace: Namespace::Fixture,
        record_id: id,
        creator_ref: ACTOR.into(),
        created_at_unix_ms: 2,
        payload,
        integrity: ZERO.into(),
    })
    .unwrap()
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
        effects: vec!["MUTATE_RESOURCE".into(), "READ_RESOURCE".into()],
        contexts: vec!["READY".into()],
        aliases: vec![AliasEntry {
            alias: "fixture://alias/lab".into(),
            canonical_resource: RESOURCE.into(),
        }],
    }
}

fn scope(resource: &str, match_kind: ResourceMatch) -> FixtureScopeV1 {
    FixtureScopeV1 {
        resource_ref: resource.into(),
        match_kind,
    }
}

fn atom(
    resource: &str,
    kind: ResourceMatch,
    operation: &str,
    effect: &str,
    provision: Provision,
) -> ClaimAtom {
    ClaimAtom {
        project_binding_ref: PROJECT.into(),
        resource_ref: resource.into(),
        resource_match: kind,
        action: operation.into(),
        provision,
        effect: effect.into(),
        lifecycle_contexts: vec!["READY".into()],
    }
}

fn normalized(atom: &ClaimAtom, profile: &SelectorProfileV1) -> Vec<NormalizedSelector> {
    normalize_fixture_selector(atom, profile).unwrap()
}

fn make_seed(project: &ValidatedRecord, actor: &ValidatedRecord) -> FixtureAuthoritySeedV1 {
    let p = profile();
    let mut broad = Vec::new();
    for (operation, effect) in [("READ", "READ_RESOURCE"), ("UPDATE", "MUTATE_RESOURCE")] {
        broad.extend(normalized(
            &atom(
                RESOURCE,
                ResourceMatch::Subtree,
                operation,
                effect,
                Provision::Permit,
            ),
            &p,
        ));
    }
    broad.sort();
    FixtureAuthoritySeedV1 {
        project_record: project.canonical_bytes().to_vec(),
        actor_records: vec![actor.canonical_bytes().to_vec()],
        profile: p,
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

fn add_claim(
    state: &mut FixtureProjection,
    seed: &FixtureAuthoritySeedV1,
    slug: &str,
    operation: &str,
    effect: &str,
    resource: &str,
    provision: Provision,
) {
    let id = format!("fx:authority:{slug}");
    let authority = record(RecordPayload::AuthorityRecord(AuthorityRecord {
        authority_id: id.clone(),
        class: AuthorityClass::Decision,
        issuer_actor_ref: ACTOR.into(),
        exercised_role: Role::DecisionAuthority,
        effective_at_ms: 2,
        target_binding_ref: Some(PROJECT.into()),
        contract_digest: None,
        claim_atoms: vec![atom(
            resource,
            ResourceMatch::Subtree,
            operation,
            effect,
            provision,
        )],
        override_edges: vec![],
        evidence_refs: vec![],
    }));
    let event = FixtureEventV1 {
        event_id: format!("fx:event:{slug}"),
        kind: FixtureEventKind::ClaimAcceptance,
        record_id: id,
        record_digest: authority.record().integrity.clone(),
        issuer_actor_id: ACTOR.into(),
        expected_prior_state_id: state.state_id.clone(),
        target_claim_id: None,
        target_edge_id: None,
    };
    apply_fixture_event(state, seed, &authority, &event).unwrap();
}

struct AdmissionHarness {
    project: ValidatedRecord,
    actor: ValidatedRecord,
    contract: ValidatedRecord,
    seed: FixtureAuthoritySeedV1,
    state: FixtureProjection,
    resolution: ResolvedFixtureOutcome,
    policy: FixtureTargetPolicyV1,
    read: Vec<FixtureScopeV1>,
    mutation: Vec<FixtureScopeV1>,
    preconditions: FixturePreconditionSnapshotV1,
    expected_id: String,
    expected_digest: String,
    capability: String,
    operation: String,
    network: bool,
    secret: bool,
    cross_surface: bool,
    marker_path: PathBuf,
}

impl AdmissionHarness {
    fn new(slug: &str) -> Self {
        let project = project();
        let actor = actor();
        let root = PathBuf::from(APPROVED_FIXTURE_ROOT);
        fs::create_dir_all(root.join("targets")).unwrap();
        let target_id = format!("fx:target:{slug}");
        let relative = PathBuf::from(format!("targets/{slug}.json"));
        let marker_path = root.join(&relative);
        let marker = FixtureTargetMarkerV1 {
            namespace: "FIXTURE".into(),
            target_id: target_id.clone(),
            revision: "r1".into(),
            state_code: "COMMITTED".into(),
        };
        fs::write(&marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
        let policy = FixtureTargetPolicyV1 {
            project_id: PROJECT.into(),
            project_digest: project.record().integrity.clone(),
            project_uri: "fixture://project/lab".into(),
            approved_root: root,
            target_id: target_id.clone(),
            relative_marker_path: relative,
        };
        let target = construct_fixture_target_snapshot(&policy).unwrap();
        let contract = record(RecordPayload::ExecutionContract(ExecutionContract {
            contract_id: format!("fx:contract:{slug}"),
            contract_version: 1,
            mission: "Fixture read and mutation; prose has no authority".into(),
            project_binding_ref: PROJECT.into(),
            target_ref: target_id,
            expected_target_state: target.state_id,
            actor_ref: ACTOR.into(),
            capability_code: "FIXTURE_OPERATION".into(),
            allowed_operations: vec!["READ".into(), "UPDATE".into()],
            read_scopes: vec![format!("{RESOURCE}/*")],
            allowed_mutations: vec![format!("{RESOURCE}/*")],
            prohibited_mutations: vec![format!("{RESOURCE}/blocked")],
            precondition_refs: vec!["fx:precondition:ready".into()],
            required_evidence_refs: vec!["fx:evidence:ready".into()],
            verification_gate_refs: vec!["fx:gate:ready".into()],
            stop_codes: vec!["STOP_NOW".into()],
            escalation_ref: "fx:route:control-room".into(),
            expected_deliverables: vec!["fixture admission".into()],
            requester_boundary: "fixture only".into(),
            network_allowed: false,
            secret_access_allowed: false,
            cross_surface_delivery_allowed: false,
        }));
        let seed = make_seed(&project, &actor);
        let mut state = FixtureProjection::from_seed(&seed).unwrap();
        add_claim(
            &mut state,
            &seed,
            &format!("{slug}-read"),
            "READ",
            "READ_RESOURCE",
            RESOURCE,
            Provision::Permit,
        );
        add_claim(
            &mut state,
            &seed,
            &format!("{slug}-update"),
            "UPDATE",
            "MUTATE_RESOURCE",
            RESOURCE,
            Provision::Permit,
        );
        let read = vec![scope(&format!("{RESOURCE}/a"), ResourceMatch::Exact)];
        let request = normalized(
            &atom(
                &read[0].resource_ref,
                ResourceMatch::Exact,
                "READ",
                "READ_RESOURCE",
                Provision::Permit,
            ),
            &seed.profile,
        );
        let resolution = resolve_fixture_request(&state, &state.state_id, &request).unwrap();
        let preconditions = FixturePreconditionSnapshotV1 {
            conditions: [
                "fx:evidence:ready",
                "fx:gate:ready",
                "fx:precondition:ready",
            ]
            .iter()
            .map(|reference| FixtureConditionValueV1 {
                reference: (*reference).into(),
                fixture_revision: "r1".into(),
                fixture_digest: ZERO.into(),
                status: FixtureConditionStatus::Satisfied,
            })
            .collect(),
            active_stop_codes: vec![],
            fixture_epoch_ms: 3,
        };
        Self {
            expected_id: contract.record().record_id.clone(),
            expected_digest: contract.record().integrity.clone(),
            project,
            actor,
            contract,
            seed,
            state,
            resolution,
            policy,
            read,
            mutation: vec![],
            preconditions,
            capability: "FIXTURE_OPERATION".into(),
            operation: "READ".into(),
            network: false,
            secret: false,
            cross_surface: false,
            marker_path,
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
            requested_capability: &self.capability,
            requested_operation: &self.operation,
            requested_read_scopes: &self.read,
            requested_mutation_scopes: &self.mutation,
            network_requested: self.network,
            secret_requested: self.secret,
            cross_surface_requested: self.cross_surface,
            preconditions: &self.preconditions,
        }
    }

    fn refresh_resolution(&mut self) {
        let mut request = Vec::new();
        for item in &self.read {
            request.extend(normalized(
                &atom(
                    &item.resource_ref,
                    item.match_kind.clone(),
                    &self.operation,
                    "READ_RESOURCE",
                    Provision::Permit,
                ),
                &self.seed.profile,
            ));
        }
        for item in &self.mutation {
            request.extend(normalized(
                &atom(
                    &item.resource_ref,
                    item.match_kind.clone(),
                    &self.operation,
                    "MUTATE_RESOURCE",
                    Provision::Permit,
                ),
                &self.seed.profile,
            ));
        }
        request.sort();
        request.dedup();
        self.resolution =
            resolve_fixture_request(&self.state, &self.state.state_id, &request).unwrap();
    }

    fn block(&self, code: BlockedCode) {
        let before = fs::read(&self.marker_path).unwrap();
        let result = evaluate_fixture_admission(&self.input());
        assert!(
            matches!(result, Err(ref error) if error.code == code),
            "expected {code:?}, got {result:?}"
        );
        assert_eq!(before, fs::read(&self.marker_path).unwrap());
    }
}

use titan_kernel::{
    broker::{FixtureBrokerRequestV1, FixtureDispatchResultV1, dispatch_fixture_operation},
    capability::{
        CAPABILITY, F05_ROOT, FixtureFaultV1, FixtureMarkerV1, FixturePayloadV1, HANDLER,
        OPERATION, PROFILE, fixture_capability_v1, fixture_marker_path,
    },
    evidence::{
        EffectStateV1, FixtureEventV1 as HistoryEvent, FixtureStoreV1, append_fixture_event, hash,
        replay_fixture_history,
    },
    outcome::{FailCode, OutcomeVariant, PassCode, UnknownCode},
};

struct BrokerHarness {
    foundation: AdmissionHarness,
    admission: titan_kernel::admission::FixtureAdmissionV1,
    request: FixtureBrokerRequestV1,
    store: FixtureStoreV1,
}
impl BrokerHarness {
    fn new(name: &str) -> Self {
        let case = format!("a05-{name}-{}", std::process::id());
        let mut foundation = AdmissionHarness::new(&case);
        let resource = format!("{RESOURCE}/{case}/marker");
        foundation.read.clear();
        foundation.mutation = vec![scope(&resource, ResourceMatch::Exact)];
        foundation.operation = "UPDATE".into();
        foundation.refresh_resolution();
        let admission = evaluate_fixture_admission(&foundation.input()).unwrap();
        let store = FixtureStoreV1::open(&case, &foundation.seed).unwrap();
        fs::create_dir_all(
            PathBuf::from(F05_ROOT)
                .join("cases")
                .join(&case)
                .join("markers"),
        )
        .unwrap();
        let payload = serde_json::to_vec(&FixturePayloadV1 {
            label: "synthetic-marker".into(),
        })
        .unwrap();
        let admission_bytes = admission.canonical_bytes().unwrap();
        let request = FixtureBrokerRequestV1 {
            profile: PROFILE.into(),
            admission_digest: hash(b"TITAN-FWD-F05\0admission-bytes-v1\0", &admission_bytes),
            admission_bytes,
            admission_id: admission.admission_id().into(),
            project_id: PROJECT.into(),
            project_digest: foundation.project.record().integrity.clone(),
            actor_id: ACTOR.into(),
            actor_digest: foundation.actor.record().integrity.clone(),
            contract_id: foundation.expected_id.clone(),
            contract_digest: foundation.expected_digest.clone(),
            authority_state_id: foundation.state.state_id.clone(),
            target_id: foundation.policy.target_id.clone(),
            target_state_id: admission.target_state_id().into(),
            capability: CAPABILITY.into(),
            operation: OPERATION.into(),
            resource,
            handler: HANDLER.into(),
            case_id: case.clone(),
            relative_marker: "markers/marker.json".into(),
            run_id: format!("fx:run:{case}"),
            logical_step: "create-marker".into(),
            action_id: format!("fx:action:{case}"),
            idempotency_id: format!("fx:idempotency:{case}"),
            payload_digest: hash(b"TITAN-FWD-F05\0payload-v1\0", &payload),
            payload,
            gate_ref: "fx:gate:ready".into(),
        };
        Self {
            foundation,
            admission,
            request,
            store,
        }
    }
    fn call(&self, fault: FixtureFaultV1) -> FixtureDispatchResultV1 {
        dispatch_fixture_operation(
            &self.store,
            &self.request,
            &self.admission,
            &self.foundation.input(),
            fault,
        )
    }
    fn path(&self) -> PathBuf {
        fixture_marker_path(
            self.store.case_id(),
            &format!("{RESOURCE}/{}/marker", self.store.case_id()),
            "markers/marker.json",
        )
        .unwrap()
    }
    fn target_bytes(&self) -> Vec<(String, Vec<u8>)> {
        let parent = self.path().parent().unwrap().to_path_buf();
        let mut bytes = fs::read_dir(parent)
            .unwrap()
            .map(|e| {
                let p = e.unwrap().path();
                (
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    fs::read(p).unwrap(),
                )
            })
            .collect::<Vec<_>>();
        bytes.sort();
        bytes
    }
    fn reject(&self, code: BlockedCode) -> FixtureDispatchResultV1 {
        let before = self.target_bytes();
        let f03 = fs::read(&self.foundation.marker_path).unwrap();
        let result = self.call(FixtureFaultV1::None);
        assert_eq!(result.handler_invocations, 0, "{result:?}");
        assert_eq!(result.outcome, OutcomeVariant::Blocked(code), "{result:?}");
        assert_eq!(before, self.target_bytes());
        assert_eq!(f03, fs::read(&self.foundation.marker_path).unwrap());
        assert_eq!(result.namespace, "FIXTURE");
        result
    }
    fn event(&self, event: HistoryEvent) {
        let h = replay_fixture_history(&self.store).unwrap();
        append_fixture_event(&self.store, &self.request.run_id, h.head_id(), event).unwrap();
    }
    fn unknown_and_no_retry(&mut self, fault: FixtureFaultV1, count: u32) {
        let f03 = fs::read(&self.foundation.marker_path).unwrap();
        let first = self.call(fault);
        assert_eq!(
            first.outcome,
            OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled)
        );
        assert_eq!(first.handler_invocations, count);
        let before = self.target_bytes();
        let history = replay_fixture_history(&self.store).unwrap();
        let original = self.request.action_id.clone();
        let fingerprint = self.request.action_spec().fingerprint().unwrap();
        assert!(history.effects[&original].2.unresolved());
        let reopened = FixtureStoreV1::open(self.store.case_id(), &self.foundation.seed).unwrap();
        let reloaded = replay_fixture_history(&reopened).unwrap();
        assert_eq!(
            history.history_id(self.store.case_id()).unwrap(),
            reloaded.history_id(self.store.case_id()).unwrap()
        );
        assert_eq!(history.effects, reloaded.effects);
        self.store = reopened;
        self.request.run_id = "fx:run:changed".into();
        self.request.action_id = "fx:action:changed".into();
        self.request.idempotency_id = "fx:idempotency:changed".into();
        assert_eq!(
            fingerprint,
            self.request.action_spec().fingerprint().unwrap()
        );
        let again = self.call(FixtureFaultV1::None);
        assert_eq!(again.handler_invocations, 0);
        assert_eq!(
            again.outcome,
            OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled)
        );
        assert_eq!(
            before,
            self.target_bytes(),
            "no automatic cleanup or second effect"
        );
        assert_eq!(
            history.head_id(),
            replay_fixture_history(&self.store).unwrap().head_id(),
            "read-only retry block"
        );
        assert_eq!(f03, fs::read(&self.foundation.marker_path).unwrap());
    }
}

#[test]
fn a05_01_one_valid_effect() {
    let h = BrokerHarness::new("01");
    let before = fs::read(&h.foundation.marker_path).unwrap();
    let result = h.call(FixtureFaultV1::None);
    assert_eq!(result.handler_invocations, 1);
    assert_eq!(
        result.outcome,
        OutcomeVariant::Pass(PassCode::WorkCompleted)
    );
    assert_eq!(result.effect_state, Some(EffectStateV1::CompletedObserved));
    assert!(result.revalidation_evidence_ref.is_some());
    assert_eq!(h.target_bytes().len(), 1);
    assert_eq!(before, fs::read(&h.foundation.marker_path).unwrap());
    // Representative byte-bound admission/intent/action/history evidence goes only into this fixture case.
    fs::write(
        h.store.raw_path("a05-result").unwrap(),
        serde_json::to_vec(&result).unwrap(),
    )
    .unwrap();
    fs::write(
        h.store.raw_path("a05-request").unwrap(),
        serde_json::to_vec(&h.request).unwrap(),
    )
    .unwrap();
}
#[test]
fn a05_02_unknown_capability() {
    let mut h = BrokerHarness::new("02");
    h.request.capability = "OTHER".into();
    h.reject(BlockedCode::Unauthorized);
}
#[test]
fn a05_03_unknown_operation() {
    let mut h = BrokerHarness::new("03");
    h.request.operation = "UNKNOWN".into();
    h.reject(BlockedCode::Unauthorized);
}
#[test]
fn a05_04_operation_capability_mismatch() {
    let mut h = BrokerHarness::new("04");
    h.request.operation = "READ".into();
    h.reject(BlockedCode::Unauthorized);
}
#[test]
fn a05_05_no_handler_fallback() {
    let mut h = BrokerHarness::new("05");
    h.request.handler = "CREATE_FIXTURE_MARKER_V2".into();
    h.reject(BlockedCode::Unauthorized);
}
#[test]
fn a05_06_stale_admission() {
    let mut h = BrokerHarness::new("06");
    h.foundation.preconditions.conditions[0].fixture_revision = "r2".into();
    let result = h.reject(BlockedCode::PreconditionDrift);
    assert_eq!(
        result.effect_state,
        Some(EffectStateV1::FailedBeforeOccurrence)
    );
    assert!(result.revalidation_evidence_ref.is_none());
}
#[test]
fn a05_07_target_drift() {
    let h = BrokerHarness::new("07");
    let mut marker: FixtureTargetMarkerV1 =
        serde_json::from_slice(&fs::read(&h.foundation.marker_path).unwrap()).unwrap();
    marker.revision = "r2".into();
    fs::write(
        &h.foundation.marker_path,
        serde_json::to_vec(&marker).unwrap(),
    )
    .unwrap();
    h.reject(BlockedCode::PreconditionDrift);
}
#[test]
fn a05_08_authority_state_drift() {
    let mut h = BrokerHarness::new("08");
    add_claim(
        &mut h.foundation.state,
        &h.foundation.seed,
        "a05-new-claim",
        "UPDATE",
        "MUTATE_RESOURCE",
        RESOURCE,
        Provision::Permit,
    );
    h.reject(BlockedCode::AuthorityStale);
}
#[test]
fn a05_09_outside_admission_scope() {
    let mut h = BrokerHarness::new("09");
    h.request.resource = format!("{RESOURCE}/other/marker");
    h.reject(BlockedCode::ScopeViolation);
}
#[test]
fn a05_10_escape_and_ambiguous_mapping() {
    let mut h = BrokerHarness::new("10");
    for path in [
        "../marker.json",
        "C:/marker.json",
        "//server/share",
        "markers/%2fmarker.json",
        "markers/other.json",
    ] {
        h.request.relative_marker = path.into();
        h.reject(BlockedCode::TargetIdentityMismatch);
    }
    for resource in [
        format!("{RESOURCE}/{}/../marker", h.store.case_id()),
        format!("{RESOURCE}/{}/%2fmarker", h.store.case_id()),
        "fixture://alias/lab/marker".into(),
    ] {
        assert!(fixture_marker_path(h.store.case_id(), &resource, "markers/marker.json").is_err());
    }
}
#[test]
fn a05_11_existing_target_not_overwritten() {
    let h = BrokerHarness::new("11");
    fs::write(h.path(), b"preexisting bytes").unwrap();
    h.reject(BlockedCode::PreconditionDrift);
}
#[test]
fn a05_12_missing_malformed_idempotency() {
    let mut h = BrokerHarness::new("12");
    for id in ["", "operational:id", "fx:idempotency:../bad"] {
        h.request.idempotency_id = id.into();
        h.reject(BlockedCode::ContractInvalid);
    }
}
#[test]
fn a05_13_duplicate_action_and_idempotency() {
    for (name, change) in [("13-action", false), ("13-idempotency", true)] {
        let mut h = BrokerHarness::new(name);
        assert_eq!(h.call(FixtureFaultV1::None).handler_invocations, 1);
        h.request.run_id = "fx:run:second".into();
        if change {
            h.request.action_id = "fx:action:second".into();
        }
        h.reject(BlockedCode::PreconditionDrift);
    }
}
#[test]
fn a05_14_new_identity_unresolved_fingerprint() {
    let mut h = BrokerHarness::new("14");
    h.unknown_and_no_retry(FixtureFaultV1::InterruptBeforeHandler, 0);
}
#[test]
fn a05_15_pending_precedes_boundary() {
    let h = BrokerHarness::new("15");
    let result = h.call(FixtureFaultV1::None);
    assert_eq!(result.handler_invocations, 1);
    let history = replay_fixture_history(&h.store).unwrap();
    let HistoryEvent::Observation { record, .. } = &history.entries[0].event else {
        panic!("intent observation required")
    };
    let r = validate_bytes(record).unwrap();
    let RecordPayload::EvidenceRef(e) = &r.record().payload else {
        panic!("observation required")
    };
    let pending: FixtureBrokerRequestV1 =
        serde_json::from_slice(&h.store.read_raw(&e.locator, &e.content_digest).unwrap()).unwrap();
    assert_eq!(pending.action_id, h.request.action_id);
    assert_eq!(pending.idempotency_id, h.request.idempotency_id);
    assert!(matches!(
        history.entries[2].event,
        HistoryEvent::Effect {
            state: EffectStateV1::PossiblyOccurredInterrupted,
            ..
        }
    ));
    assert!(history.entries[1].event.clone() != history.entries[0].event);
}
#[test]
fn a05_16_freshness_changes_after_pending() {
    let h = BrokerHarness::new("16");
    let before = h.target_bytes();
    let result = h.call(FixtureFaultV1::BeforeRevalidationDrift);
    assert_eq!(result.handler_invocations, 0);
    assert_eq!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::PreconditionDrift)
    );
    assert_eq!(
        result.effect_state,
        Some(EffectStateV1::FailedBeforeOccurrence)
    );
    assert_eq!(before, h.target_bytes());
    let history = replay_fixture_history(&h.store).unwrap();
    assert!(matches!(
        history.entries[0].event,
        HistoryEvent::Observation { .. }
    ));
    assert!(!history.entries.iter().any(|e| matches!(
        e.event,
        HistoryEvent::Effect {
            state: EffectStateV1::PossiblyOccurredInterrupted,
            ..
        }
    )));
}
#[test]
fn a05_17_exact_marker_and_one_write() {
    let h = BrokerHarness::new("17");
    assert_eq!(h.call(FixtureFaultV1::None).handler_invocations, 1);
    let expected = FixtureMarkerV1 {
        marker: HANDLER.into(),
        namespace: "FIXTURE".into(),
        case_id: h.request.case_id.clone(),
        resource: h.request.resource.clone(),
        action_id: h.request.action_id.clone(),
        idempotency_id: h.request.idempotency_id.clone(),
        payload_digest: h.request.payload_digest.clone(),
    };
    assert_eq!(
        h.target_bytes(),
        vec![("marker.json".into(), serde_json::to_vec(&expected).unwrap())]
    );
    let history = replay_fixture_history(&h.store).unwrap();
    assert_eq!(
        history.effects[&h.request.action_id].2,
        EffectStateV1::CompletedObserved
    );
    assert_eq!(history.effect_support[&h.request.action_id].len(), 1);
}
#[test]
fn a05_18_proven_failure_before_write() {
    let h = BrokerHarness::new("18");
    let result = h.call(FixtureFaultV1::FailBeforeWrite);
    assert_eq!(result.handler_invocations, 1);
    assert_eq!(result.outcome, OutcomeVariant::Fail(FailCode::WorkFailed));
    assert_eq!(
        result.effect_state,
        Some(EffectStateV1::FailedBeforeOccurrence)
    );
    assert!(h.target_bytes().is_empty());
    assert!(result.revalidation_evidence_ref.is_some());
}
#[test]
fn a05_19_interrupted_after_possible_effect() {
    let mut h = BrokerHarness::new("19");
    h.unknown_and_no_retry(FixtureFaultV1::InterruptAfterWrite, 1);
    assert!(h.path().exists());
}
#[test]
fn a05_20_partial_marker_preserves_unknown() {
    let mut h = BrokerHarness::new("20");
    h.unknown_and_no_retry(FixtureFaultV1::PartialWrite, 1);
    assert!(serde_json::from_slice::<FixtureMarkerV1>(&fs::read(h.path()).unwrap()).is_err());
}
#[test]
fn a05_21_no_automatic_retry() {
    let mut h = BrokerHarness::new("21");
    h.unknown_and_no_retry(FixtureFaultV1::InterruptBeforeHandler, 0);
}
#[test]
fn a05_22_restart_preserves_block() {
    let mut h = BrokerHarness::new("22");
    h.unknown_and_no_retry(FixtureFaultV1::InterruptAfterWrite, 1);
}
#[test]
fn a05_23_recording_failure_unknown() {
    let mut h = BrokerHarness::new("23");
    h.unknown_and_no_retry(FixtureFaultV1::PostEffectRecordingFailure, 1);
    assert!(h.path().exists());
}
#[test]
fn a05_24_equivalent_handler_cannot_substitute() {
    let mut h = BrokerHarness::new("24");
    h.request.handler = "ALTERNATIVE_CREATE_NEW_HANDLER".into();
    h.reject(BlockedCode::Unauthorized);
}
#[test]
fn a05_25_inert_result_and_closed_registry() {
    let h = BrokerHarness::new("25");
    let r = h.call(FixtureFaultV1::None);
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["namespace"], "FIXTURE");
    for field in [
        "executor",
        "credential",
        "token",
        "retry",
        "grant",
        "promotion_authority",
    ] {
        assert!(json.get(field).is_none());
    }
    let capability = fixture_capability_v1();
    assert!(
        !capability.network
            && !capability.secrets
            && !capability.processes
            && !capability.cross_surface
    );
    assert_eq!(capability.capability, CAPABILITY);
    assert_eq!(capability.operation, OPERATION);
    assert_eq!(capability.handler, HANDLER);
}
#[test]
fn a05_26_declared_fixture_domains() {
    let h = BrokerHarness::new("26");
    let f03 = fs::read(&h.foundation.marker_path).unwrap();
    let r = h.call(FixtureFaultV1::None);
    assert_eq!(r.handler_invocations, 1);
    assert!(h.path().starts_with(F05_ROOT));
    assert!(
        h.store
            .case_path()
            .starts_with(titan_kernel::evidence::F04_ROOT)
    );
    assert!(h.foundation.marker_path.starts_with(APPROVED_FIXTURE_ROOT));
    assert_eq!(f03, fs::read(&h.foundation.marker_path).unwrap());
    assert_eq!(h.target_bytes().len(), 1);
}
#[test]
fn a05_guard_request_attribution() {
    for field in [
        "project",
        "actor",
        "contract",
        "admission-id",
        "admission-digest",
        "case",
        "payload",
        "target",
        "authority",
        "gate",
    ] {
        let mut h = BrokerHarness::new(&format!("guard-{field}"));
        match field {
            "project" => h.request.project_id = "fx:project:wrong".into(),
            "actor" => h.request.actor_id = "fx:actor:wrong".into(),
            "contract" => h.request.contract_digest = ZERO.into(),
            "admission-id" => h.request.admission_id = "fx:admission:wrong".into(),
            "admission-digest" => h.request.admission_digest = ZERO.into(),
            "case" => h.request.case_id = "other".into(),
            "payload" => h.request.payload_digest = ZERO.into(),
            "target" => h.request.target_id = "fx:target:wrong".into(),
            "authority" => h.request.authority_state_id = "wrong".into(),
            "gate" => h.request.gate_ref = "fx:gate:wrong".into(),
            _ => unreachable!(),
        }
        h.reject(BlockedCode::ContractInvalid);
    }
}
#[test]
fn a05_guard_active_blocker() {
    let h = BrokerHarness::new("guard-blocker");
    h.event(HistoryEvent::BlockerOpened {
        blocker_id: "fx:blocker:a05".into(),
        code: BlockedCode::ScopeViolation,
        dependency: h.request.resource.clone(),
    });
    h.reject(BlockedCode::ScopeViolation);
}
#[test]
fn a05_guard_corrupt_history() {
    let h = BrokerHarness::new("guard-corrupt");
    h.event(HistoryEvent::BlockerOpened {
        blocker_id: "fx:blocker:a05".into(),
        code: BlockedCode::ScopeViolation,
        dependency: h.request.resource.clone(),
    });
    let path = h.store.case_path().join("events/0000000001.json");
    fs::write(&path, b"{").unwrap();
    let bytes = fs::read(&path).unwrap();
    h.reject(BlockedCode::EnvironmentFailure);
    assert_eq!(bytes, fs::read(path).unwrap());
}
#[test]
fn a05_guard_real_posteffect_raw_slot_collision() {
    let mut h = BrokerHarness::new("guard-record-collision");
    let fingerprint = h.request.action_spec().fingerprint().unwrap();
    let path = h
        .store
        .raw_path(&format!("effect-{}", &fingerprint[7..39]))
        .unwrap();
    fs::write(&path, b"occupied evidence slot").unwrap();
    h.unknown_and_no_retry(FixtureFaultV1::None, 1);
    assert_eq!(fs::read(path).unwrap(), b"occupied evidence slot");
}
#[test]
fn a05_guard_payload_canonical_and_no_extra_fields() {
    let mut h = BrokerHarness::new("guard-payload-canonical");
    h.request.payload = br#"{ "label": "synthetic-marker" }"#.to_vec();
    h.request.payload_digest = hash(b"TITAN-FWD-F05\0payload-v1\0", &h.request.payload);
    h.reject(BlockedCode::ContractInvalid);
    let mut value = serde_json::to_value(&h.request).unwrap();
    value["executor"] = "not permitted".into();
    assert!(serde_json::from_value::<FixtureBrokerRequestV1>(value).is_err());
}
#[test]
fn a05_guard_f03_positive_mutation_profile_unchanged() {
    let mut h = BrokerHarness::new("guard-profile");
    assert_eq!(h.foundation.capability, "FIXTURE_OPERATION");
    assert_eq!(h.foundation.operation, "UPDATE");
    let decoded = decode_fixture_admission(
        &h.admission.canonical_bytes().unwrap(),
        &h.foundation.input(),
    )
    .unwrap();
    assert_eq!(decoded, h.admission);
    h.foundation.preconditions.conditions[0].status = FixtureConditionStatus::Unsatisfied;
    h.foundation.block(BlockedCode::PreconditionDrift);
    h.reject(BlockedCode::PreconditionDrift);
}
#[test]
fn a05_guard_unknown_cannot_be_evaded_by_new_step() {
    let mut h = BrokerHarness::new("guard-step");
    assert_eq!(
        h.call(FixtureFaultV1::InterruptBeforeHandler)
            .handler_invocations,
        0
    );
    h.request.run_id = "fx:run:new".into();
    h.request.action_id = "fx:action:new".into();
    h.request.idempotency_id = "fx:idempotency:new".into();
    h.request.logical_step = "another-step".into();
    let before = h.target_bytes();
    let r = h.call(FixtureFaultV1::None);
    assert_eq!(r.handler_invocations, 0);
    assert_eq!(
        r.outcome,
        OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled)
    );
    assert_eq!(before, h.target_bytes());
}

#[test]
fn a05_guard_windows_device_resources_rejected() {
    let mut h = BrokerHarness::new("guard-devices");
    for leaf in ["con", "aux", "nul", "prn", "com1", "lpt9"] {
        h.request.resource = format!("{RESOURCE}/{}/{leaf}", h.store.case_id());
        h.request.relative_marker = format!("markers/{leaf}.json");
        h.foundation.mutation[0].resource_ref = h.request.resource.clone();
        h.reject(BlockedCode::ScopeViolation);
    }
}

#[test]
fn a05_guard_existing_hardlink_alias_not_overwritten() {
    let h = BrokerHarness::new("guard-hardlink");
    let other = h.path().with_file_name("other.json");
    fs::write(&other, b"test-owned alias bytes").unwrap();
    fs::hard_link(&other, h.path()).unwrap();
    h.reject(BlockedCode::PreconditionDrift);
    assert_eq!(fs::read(other).unwrap(), b"test-owned alias bytes");
}

#[test]
fn a05_guard_pending_intent_blocks_changed_identity_and_step() {
    let mut h = BrokerHarness::new("guard-pending");
    let raw = "pending-before-freshness";
    let bytes = serde_json::to_vec(&h.request).unwrap();
    fs::write(h.store.raw_path(raw).unwrap(), &bytes).unwrap();
    let e = record(RecordPayload::EvidenceRef(
        titan_kernel::records::EvidenceRef {
            evidence_id: "fx:evidence:pending".into(),
            kind: "OBSERVATION".into(),
            locator: format!("fixture://f04/raw/{raw}"),
            content_digest: hash(b"", &bytes),
            producer_ref: ACTOR.into(),
            method: "FIXTURE_PROBE".into(),
            subject_ref: h.request.target_id.clone(),
            subject_revision: h.request.target_state_id.clone(),
            observed_at_ms: 2,
            contract_ref: h.request.contract_id.clone(),
            run_ref: h.request.run_id.clone(),
            gate_ref: Some(h.request.gate_ref.clone()),
            status: titan_kernel::records::EvidenceStatus::Current,
        },
    ));
    h.event(
        titan_kernel::evidence::observation_event(
            &h.foundation.seed,
            &e,
            &h.foundation.actor,
            &h.request.contract_digest,
        )
        .unwrap(),
    );
    h.request.run_id = "fx:run:new".into();
    h.request.action_id = "fx:action:new".into();
    h.request.idempotency_id = "fx:idempotency:new".into();
    h.request.logical_step = "changed-step".into();
    h.reject(BlockedCode::PreconditionDrift);
}

// F05-A1 additions only. The original 36 tests and their harness remain unchanged.
use titan_kernel::{
    broker::{FixtureReadRequestV1, FixtureReadResultV1, read_fixture_operation},
    capability::{READ_CAPABILITY, READ_HANDLER, READ_OPERATION, fixture_capabilities_v1},
};

#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
struct ReadInventoryEntry {
    path: String,
    kind: String,
    len: u64,
    digest: String,
    modified_ns: u128,
    readonly: bool,
    attributes: u32,
}

fn read_inventory_path(path: &std::path::Path, rows: &mut Vec<ReadInventoryEntry>) {
    let m = match fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            rows.push(ReadInventoryEntry {
                path: path.to_string_lossy().into(),
                kind: "ABSENT".into(),
                len: 0,
                digest: String::new(),
                modified_ns: 0,
                readonly: false,
                attributes: 0,
            });
            return;
        }
        Err(e) => panic!("inventory failed: {e}"),
    };
    #[cfg(windows)]
    let attributes = {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes()
    };
    #[cfg(not(windows))]
    let attributes = 0;
    let reparse = m.file_type().is_symlink() || attributes & 0x400 != 0;
    let kind = if reparse {
        "REPARSE"
    } else if m.is_dir() {
        "DIRECTORY"
    } else {
        "FILE"
    };
    rows.push(ReadInventoryEntry {
        path: path.to_string_lossy().into(),
        kind: kind.into(),
        len: m.len(),
        digest: if reparse {
            fs::read_link(path).unwrap().to_string_lossy().into()
        } else if m.is_file() {
            hash(b"", &fs::read(path).unwrap())
        } else {
            String::new()
        },
        modified_ns: m
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos(),
        readonly: m.permissions().readonly(),
        attributes,
    });
    if m.is_dir() && !reparse {
        let mut children = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        children.sort();
        for child in children {
            read_inventory_path(&child, rows);
        }
    }
}

struct ReadHarness {
    broker: BrokerHarness,
    request: FixtureReadRequestV1,
    expected: Vec<u8>,
    calls: std::cell::Cell<u32>,
    write_admission: titan_kernel::admission::FixtureAdmissionV1,
}
impl ReadHarness {
    fn new(name: &str) -> Self {
        let mut broker = BrokerHarness::new(&format!("a1-{name}"));
        let write_admission = broker.admission.clone();
        let resource = broker.request.resource.clone();
        let f = &mut broker.foundation;
        let RecordPayload::ExecutionContract(old) = &f.contract.record().payload else {
            unreachable!()
        };
        let mut c = old.clone();
        c.capability_code = READ_CAPABILITY.into();
        c.allowed_operations = vec![READ_OPERATION.into()];
        c.read_scopes = vec![resource.clone()];
        c.allowed_mutations.clear();
        f.contract = record(RecordPayload::ExecutionContract(c));
        f.expected_digest = f.contract.record().integrity.clone();
        f.read = vec![scope(&resource, ResourceMatch::Exact)];
        f.mutation.clear();
        f.capability = READ_CAPABILITY.into();
        f.operation = READ_OPERATION.into();
        f.refresh_resolution();
        broker.admission = evaluate_fixture_admission(&f.input()).unwrap();
        let admission_bytes = broker.admission.canonical_bytes().unwrap();
        let expected = br#"{"namespace":"FIXTURE","observation":"synthetic-read-only"}"#.to_vec();
        fs::write(broker.path(), &expected).unwrap(); // fixture setup, never the read handler
        let request = FixtureReadRequestV1 {
            profile: PROFILE.into(),
            admission_digest: hash(b"TITAN-FWD-F05\0admission-bytes-v1\0", &admission_bytes),
            admission_bytes,
            admission_id: broker.admission.admission_id().into(),
            project_id: broker.request.project_id.clone(),
            project_digest: broker.request.project_digest.clone(),
            actor_id: broker.request.actor_id.clone(),
            actor_digest: broker.request.actor_digest.clone(),
            contract_id: broker.foundation.expected_id.clone(),
            contract_digest: broker.foundation.expected_digest.clone(),
            authority_state_id: broker.foundation.state.state_id.clone(),
            target_id: broker.foundation.policy.target_id.clone(),
            target_state_id: broker.admission.target_state_id().into(),
            capability: READ_CAPABILITY.into(),
            operation: READ_OPERATION.into(),
            resource,
            handler: READ_HANDLER.into(),
            case_id: broker.store.case_id().into(),
            relative_marker: "markers/marker.json".into(),
            expected_content_digest: hash(b"", &expected),
            gate_ref: "fx:gate:ready".into(),
        };
        Self {
            broker,
            request,
            expected,
            calls: std::cell::Cell::new(0),
            write_admission,
        }
    }
    fn inventory(&self) -> Vec<ReadInventoryEntry> {
        // Entire owned read domain plus all admitted target/history dependencies, not just marker bytes.
        // Other full-suite tests own different cases and can run concurrently.
        let mut rows = Vec::new();
        for path in [
            PathBuf::from(F05_ROOT)
                .join("cases")
                .join(self.broker.store.case_id()),
            self.broker.store.case_path().to_owned(),
            self.broker.foundation.marker_path.clone(),
        ] {
            read_inventory_path(&path, &mut rows);
        }
        rows.sort_by(|a, b| a.path.cmp(&b.path));
        rows
    }
    fn captured<T: serde::Serialize>(&self, invoke: impl FnOnce() -> T) -> T {
        let before = self.inventory();
        let value = invoke();
        let after = self.inventory();
        let ordinal = self.calls.get() + 1;
        self.calls.set(ordinal);
        let evidence = PathBuf::from(F05_ROOT)
            .parent()
            .unwrap()
            .join("f05-evidence/a1-zero-effects")
            .join(self.broker.store.case_id());
        fs::create_dir_all(&evidence).unwrap();
        let record = serde_json::json!({
            "case": self.broker.store.case_id(), "call": ordinal, "before": before, "after": after,
            "effects": if before == after { Vec::<String>::new() } else { vec!["INVENTORY_MISMATCH".into()] },
            "result": value,
        });
        fs::write(
            evidence.join(format!("{ordinal:03}.json")),
            serde_json::to_vec(&record).unwrap(),
        )
        .unwrap();
        assert_eq!(
            before, after,
            "read or rejected routing must have zero fixture effect"
        );
        value
    }
    fn read(&self) -> FixtureReadResultV1 {
        self.captured(|| {
            read_fixture_operation(
                &self.request,
                &self.broker.admission,
                &self.broker.foundation.input(),
            )
        })
    }
    fn reject(&self, code: BlockedCode) -> FixtureReadResultV1 {
        let r = self.read();
        assert_eq!(r.outcome, OutcomeVariant::Blocked(code), "{r:?}");
        assert!(r.observation.is_none());
        r
    }
    fn success(&self) -> FixtureReadResultV1 {
        let r = self.read();
        assert_eq!(r.outcome, OutcomeVariant::Pass(PassCode::WorkCompleted));
        assert_eq!(r.handler_invocations, 1);
        assert_eq!(
            r.revalidated_admission_digest.as_deref(),
            Some(self.request.admission_digest.as_str())
        );
        let observation = r.observation.as_ref().unwrap();
        assert_eq!(observation.bytes, self.expected);
        assert_eq!(observation.resource, self.request.resource);
        assert_eq!(observation.content_digest, hash(b"", &self.expected));
        assert_eq!(observation.trust, "UNTRUSTED_FIXTURE_DATA");
        assert_eq!(observation.namespace, "FIXTURE");
        r
    }
}

#[test]
fn a05_a1_01_exact_read_returns_inert_observation() {
    let h = ReadHarness::new("01");
    let first = h.success();
    assert_eq!(
        first,
        h.success(),
        "identical basis has deterministic observation identity"
    );
    assert!(
        replay_fixture_history(&h.broker.store)
            .unwrap()
            .entries
            .is_empty()
    );
}
#[test]
fn a05_a1_02_full_inventory_empty_including_metadata() {
    let h = ReadHarness::new("02");
    let before = h.inventory();
    h.success();
    assert_eq!(before, h.inventory());
}
#[test]
fn a05_a1_03_read_cannot_create_missing_marker() {
    let h = ReadHarness::new("03");
    fs::rename(
        h.broker.path(),
        h.broker.path().with_file_name("saved.json"),
    )
    .unwrap();
    h.reject(BlockedCode::InsufficientEvidence);
    assert!(!h.broker.path().exists());
}
#[test]
fn a05_a1_04_read_operation_write_handler_rejected() {
    let mut h = ReadHarness::new("04");
    h.request.handler = HANDLER.into();
    assert_eq!(h.reject(BlockedCode::Unauthorized).handler_invocations, 0);
    h.broker.request.capability = READ_CAPABILITY.into();
    h.broker.request.operation = READ_OPERATION.into();
    let result = h.captured(|| h.broker.call(FixtureFaultV1::None));
    assert_eq!(result.handler_invocations, 0);
    assert_eq!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::Unauthorized)
    );
}
#[test]
fn a05_a1_05_write_operation_read_handler_rejected() {
    let mut h = ReadHarness::new("05");
    h.request.operation = OPERATION.into();
    assert_eq!(h.reject(BlockedCode::Unauthorized).handler_invocations, 0);
    h.broker.request.handler = READ_HANDLER.into();
    let result = h.captured(|| h.broker.call(FixtureFaultV1::None));
    assert_eq!(result.handler_invocations, 0);
    assert_eq!(
        result.outcome,
        OutcomeVariant::Blocked(BlockedCode::Unauthorized)
    );
}
#[test]
fn a05_a1_06_read_capability_cannot_widen_to_write() {
    let mut h = ReadHarness::new("06");
    h.request.operation = OPERATION.into();
    h.request.handler = HANDLER.into();
    h.reject(BlockedCode::Unauthorized);
    h.broker.request.capability = READ_CAPABILITY.into();
    let r = h.captured(|| h.broker.call(FixtureFaultV1::None));
    assert_eq!(r.handler_invocations, 0);
    assert_eq!(
        r.outcome,
        OutcomeVariant::Blocked(BlockedCode::Unauthorized)
    );
}
#[test]
fn a05_a1_07_out_of_scope_resource_rejected() {
    let mut h = ReadHarness::new("07");
    h.request.resource = format!("{RESOURCE}/other/marker");
    assert_eq!(h.reject(BlockedCode::ScopeViolation).handler_invocations, 0);
}
#[test]
fn a05_a1_08_f03_target_drift_rejected() {
    let h = ReadHarness::new("08");
    let mut m: FixtureTargetMarkerV1 =
        serde_json::from_slice(&fs::read(&h.broker.foundation.marker_path).unwrap()).unwrap();
    m.revision = "r2".into();
    fs::write(
        &h.broker.foundation.marker_path,
        serde_json::to_vec(&m).unwrap(),
    )
    .unwrap();
    assert_eq!(
        h.reject(BlockedCode::PreconditionDrift).handler_invocations,
        0
    );
}
#[test]
fn a05_a1_09_stale_admission_rejected() {
    let mut h = ReadHarness::new("09");
    h.broker.foundation.preconditions.conditions[0].fixture_revision = "r2".into();
    assert_eq!(
        h.reject(BlockedCode::PreconditionDrift).handler_invocations,
        0
    );
}
#[test]
fn a05_a1_10_path_escape_and_alias_rejected() {
    let mut h = ReadHarness::new("10");
    for path in [
        "../marker.json",
        "C:/marker.json",
        "markers/%2fmarker.json",
        "markers/other.json",
    ] {
        h.request.relative_marker = path.into();
        assert_eq!(
            h.reject(BlockedCode::TargetIdentityMismatch)
                .handler_invocations,
            0
        );
    }
    h.request.resource = "fixture://alias/lab/marker".into();
    h.reject(BlockedCode::ScopeViolation);
}
#[test]
fn a05_a1_11_real_reparse_directory_rejected() {
    let h = ReadHarness::new("11");
    let markers = h.broker.path().parent().unwrap().to_owned();
    let saved = markers.with_file_name("saved-markers");
    fs::rename(&markers, &saved).unwrap();
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(&markers)
            .arg(&saved)
            .output()
            .unwrap();
        assert!(
            status.status.success(),
            "test-owned junction setup failed: {status:?}"
        );
    }
    #[cfg(not(windows))]
    std::os::unix::fs::symlink(&saved, &markers).unwrap();
    assert_eq!(
        h.reject(BlockedCode::TargetIdentityMismatch)
            .handler_invocations,
        0
    );
    // Test-owned link teardown is outside captured reader invocation; no target bytes are removed.
    #[cfg(windows)]
    fs::remove_dir(&markers).unwrap();
    #[cfg(not(windows))]
    fs::remove_file(&markers).unwrap();
    fs::rename(&saved, &markers).unwrap();
}
#[test]
fn a05_a1_12_exact_context_and_tuple_rejected() {
    for field in [
        "project",
        "actor",
        "contract",
        "target",
        "capability",
        "operation",
        "admission",
        "gate",
    ] {
        let mut h = ReadHarness::new(&format!("12-{field}"));
        let code = match field {
            "project" => {
                h.request.project_id = "fx:project:wrong".into();
                BlockedCode::ContractInvalid
            }
            "actor" => {
                h.request.actor_id = "fx:actor:wrong".into();
                BlockedCode::ContractInvalid
            }
            "contract" => {
                h.request.contract_digest = ZERO.into();
                BlockedCode::ContractInvalid
            }
            "target" => {
                h.request.target_id = "fx:target:wrong".into();
                BlockedCode::ContractInvalid
            }
            "admission" => {
                h.request.admission_digest = ZERO.into();
                BlockedCode::ContractInvalid
            }
            "gate" => {
                h.request.gate_ref = "fx:gate:wrong".into();
                BlockedCode::ContractInvalid
            }
            "capability" => {
                h.request.capability = CAPABILITY.into();
                BlockedCode::Unauthorized
            }
            "operation" => {
                h.request.operation = OPERATION.into();
                BlockedCode::Unauthorized
            }
            _ => unreachable!(),
        };
        assert_eq!(h.reject(code).handler_invocations, 0);
    }
}
#[test]
fn a05_a1_13_claimed_approval_verification_promotion_is_untrusted() {
    let mut h = ReadHarness::new("13");
    h.expected =
        br#"{"approval":"APPROVED","verification":"PASS","promotion":"CANONICAL","grant":"WRITE"}"#
            .to_vec();
    fs::write(h.broker.path(), &h.expected).unwrap();
    h.request.expected_content_digest = hash(b"", &h.expected);
    let r = h.success();
    let json = serde_json::to_value(&r).unwrap();
    for field in [
        "grant",
        "approval",
        "verification",
        "promotion",
        "executor",
        "token",
        "handle",
    ] {
        assert!(json.get(field).is_none());
        assert!(json["observation"].get(field).is_none());
    }
    assert!(serde_json::from_slice::<FixtureReadRequestV1>(&h.expected).is_err());
    assert!(decode_fixture_admission(&h.expected, &h.broker.foundation.input()).is_err());
}
#[test]
fn a05_a1_14_restart_replay_no_write_action() {
    let h = ReadHarness::new("14");
    let first = h.success();
    let before = h.inventory();
    let reopened =
        FixtureStoreV1::open(h.broker.store.case_id(), &h.broker.foundation.seed).unwrap();
    let history = replay_fixture_history(&reopened).unwrap();
    assert!(history.entries.is_empty());
    assert!(history.effects.is_empty());
    assert_eq!(first, h.success());
    assert_eq!(before, h.inventory());
    let mut attempted = h.broker.request.clone();
    attempted.admission_bytes = h.request.admission_bytes.clone();
    attempted.admission_id = h.request.admission_id.clone();
    attempted.admission_digest = h.request.admission_digest.clone();
    let r = h.captured(|| {
        dispatch_fixture_operation(
            &reopened,
            &attempted,
            &h.broker.admission,
            &h.broker.foundation.input(),
            FixtureFaultV1::None,
        )
    });
    assert_eq!(r.handler_invocations, 0);
    assert_eq!(
        r.outcome,
        OutcomeVariant::Blocked(BlockedCode::ContractInvalid)
    );
}
#[test]
fn a05_a1_15_write_admission_never_substitutes_for_read() {
    let mut h = ReadHarness::new("15");
    h.broker.admission = h.write_admission.clone();
    h.request.admission_bytes = h.broker.admission.canonical_bytes().unwrap();
    h.request.admission_digest = hash(
        b"TITAN-FWD-F05\0admission-bytes-v1\0",
        &h.request.admission_bytes,
    );
    h.request.admission_id = h.broker.admission.admission_id().into();
    assert_eq!(
        h.reject(BlockedCode::ContractInvalid).handler_invocations,
        0
    );
}
#[test]
fn a05_a1_16_current_project_actor_contract_drift_rejected() {
    for field in ["project", "actor", "contract"] {
        let mut h = ReadHarness::new(&format!("16-{field}"));
        match field {
            "project" => {
                let RecordPayload::ProjectBinding(p) =
                    &h.broker.foundation.project.record().payload
                else {
                    unreachable!()
                };
                let mut p = p.clone();
                p.binding_revision += 1;
                h.broker.foundation.project = record(RecordPayload::ProjectBinding(p));
            }
            "actor" => {
                let RecordPayload::ActorBinding(a) = &h.broker.foundation.actor.record().payload
                else {
                    unreachable!()
                };
                let mut a = a.clone();
                a.valid_until_ms = Some(3);
                h.broker.foundation.actor = record(RecordPayload::ActorBinding(a));
            }
            "contract" => {
                let RecordPayload::ExecutionContract(c) =
                    &h.broker.foundation.contract.record().payload
                else {
                    unreachable!()
                };
                let mut c = c.clone();
                c.allowed_operations = vec![OPERATION.into()];
                h.broker.foundation.contract = record(RecordPayload::ExecutionContract(c));
            }
            _ => unreachable!(),
        }
        let r = h.read();
        assert!(matches!(r.outcome, OutcomeVariant::Blocked(_)));
        assert_eq!(r.handler_invocations, 0);
    }
}
#[test]
fn a05_a1_17_marker_content_drift_rejected() {
    let h = ReadHarness::new("17");
    fs::write(h.broker.path(), b"changed fixture content").unwrap();
    assert_eq!(
        h.reject(BlockedCode::PreconditionDrift).handler_invocations,
        1
    );
}
#[test]
fn a05_a1_18_closed_registry_and_no_mutation_requests() {
    let mut h = ReadHarness::new("18");
    let registry = fixture_capabilities_v1();
    assert_eq!(registry.len(), 2);
    assert_eq!(registry[0], fixture_capability_v1());
    assert_eq!(registry[1].capability, READ_CAPABILITY);
    assert_eq!(registry[1].operation, READ_OPERATION);
    assert_eq!(registry[1].handler, READ_HANDLER);
    assert_eq!(registry[1].write_shape, "NONE");
    assert_ne!(registry[0].capability, registry[1].capability);
    assert!(
        !registry[1].network
            && !registry[1].secrets
            && !registry[1].processes
            && !registry[1].cross_surface
    );
    h.broker.foundation.mutation = vec![scope(&h.request.resource, ResourceMatch::Exact)];
    assert_eq!(h.reject(BlockedCode::ScopeViolation).handler_invocations, 0);
    let mut value = serde_json::to_value(&h.request).unwrap();
    value["write_handle"] = "not allowed".into();
    assert!(serde_json::from_value::<FixtureReadRequestV1>(value).is_err());
}
#[test]
fn a05_a1_19_authority_drift_and_forbidden_access_rejected() {
    let mut h = ReadHarness::new("19");
    add_claim(
        &mut h.broker.foundation.state,
        &h.broker.foundation.seed,
        "a1-new-read-claim",
        READ_OPERATION,
        "READ_RESOURCE",
        RESOURCE,
        Provision::Permit,
    );
    assert_eq!(h.reject(BlockedCode::AuthorityStale).handler_invocations, 0);
    for field in ["network", "secret", "cross"] {
        let mut h = ReadHarness::new(&format!("19-{field}"));
        match field {
            "network" => h.broker.foundation.network = true,
            "secret" => h.broker.foundation.secret = true,
            "cross" => h.broker.foundation.cross_surface = true,
            _ => unreachable!(),
        }
        assert_eq!(
            h.reject(BlockedCode::ContractInvalid).handler_invocations,
            0
        );
    }
}
