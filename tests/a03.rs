use std::{fs, path::PathBuf};

use titan_kernel::{
    ValidatedRecord,
    admission::{
        FixtureAdmissionInput, FixtureConditionStatus, FixtureConditionValueV1,
        FixturePreconditionSnapshotV1, FixtureScopeV1, decode_fixture_admission,
        evaluate_fixture_admission, revalidate_fixture_admission, validate_fixture_contract,
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

struct Harness {
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

impl Harness {
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

#[test]
fn a03_01_positive_exact_binding() {
    let h = Harness::new("a03-01");
    let valid = validate_fixture_contract(&h.contract, &h.seed.profile).unwrap();
    assert_eq!(valid.status, "CONTRACT_VALID");
    let first = evaluate_fixture_admission(&h.input()).unwrap();
    let second = evaluate_fixture_admission(&h.input()).unwrap();
    assert_eq!(first, second);
    assert!(first.admission_id().starts_with("fx:admission:"));
    assert_eq!(first.authority_state_id(), h.state.state_id);
    assert_eq!(
        first.target_state_id(),
        construct_fixture_target_snapshot(&h.policy)
            .unwrap()
            .state_id
    );
    assert!(!first.governing_resolution_id().is_empty());
    assert!(!first.precondition_snapshot_id().is_empty());
    eprintln!(
        "A03-01 IDS admission={} target={} authority={} governing={} precondition={}",
        first.admission_id(),
        first.target_state_id(),
        first.authority_state_id(),
        first.governing_resolution_id(),
        first.precondition_snapshot_id()
    );
    let value: serde_json::Value =
        serde_json::from_slice(&first.canonical_bytes().unwrap()).unwrap();
    assert_eq!(value["namespace"], "FIXTURE");
    assert_eq!(value["contract_digest"], h.expected_digest);
    assert_eq!(value["marker"], "TITAN_F03_FIXTURE_ADMISSION_V1");
    revalidate_fixture_admission(&first, &h.input()).unwrap();
    let decoded = decode_fixture_admission(&first.canonical_bytes().unwrap(), &h.input()).unwrap();
    assert_eq!(decoded, first);
}

#[test]
fn a03_02_contract_valid_no_governor() {
    let mut h = Harness::new("a03-02");
    assert_eq!(
        validate_fixture_contract(&h.contract, &h.seed.profile)
            .unwrap()
            .status,
        "CONTRACT_VALID"
    );
    h.state = FixtureProjection::from_seed(&h.seed).unwrap();
    h.block(BlockedCode::BlockedNoActiveGoverningAuthority);
}
#[test]
fn a03_03_wrong_project() {
    let mut h = Harness::new("a03-03");
    h.project = record(RecordPayload::ProjectBinding(ProjectBinding {
        project_id: "fx:project:other".into(),
        canonical_root: "fixture://project/other".into(),
        repository_id: None,
        repository_url: None,
        authority_source_ref: "fx:authority:seed".into(),
        binding_revision: 1,
        state: BindingState::Active,
    }));
    h.block(BlockedCode::TargetIdentityMismatch);
}
#[test]
fn a03_04_wrong_actor() {
    let mut h = Harness::new("a03-04");
    let mut a = match &h.actor.record().payload {
        RecordPayload::ActorBinding(a) => a.clone(),
        _ => unreachable!(),
    };
    a.actor_id = "fx:actor:other".into();
    h.actor = record(RecordPayload::ActorBinding(a));
    h.block(BlockedCode::Unauthorized);
}
#[test]
fn a03_05_wrong_contract_id() {
    let mut h = Harness::new("a03-05");
    h.expected_id = "fx:contract:other".into();
    h.block(BlockedCode::ContractInvalid);
}
#[test]
fn a03_06_wrong_contract_digest() {
    let mut h = Harness::new("a03-06");
    h.expected_digest = ZERO.into();
    h.block(BlockedCode::ContractInvalid);
}
#[test]
fn a03_07_wrong_target() {
    let mut h = Harness::new("a03-07");
    h.policy.target_id = "fx:target:other".into();
    h.block(BlockedCode::TargetIdentityMismatch);
}
#[test]
fn a03_08_target_revision_drift() {
    let h = Harness::new("a03-08");
    let marker = FixtureTargetMarkerV1 {
        namespace: "FIXTURE".into(),
        target_id: h.policy.target_id.clone(),
        revision: "r2".into(),
        state_code: "COMMITTED".into(),
    };
    fs::write(&h.marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
    h.block(BlockedCode::PreconditionDrift);
}
#[test]
fn a03_09_unresolved_target() {
    let mut h = Harness::new("a03-09");
    h.policy.relative_marker_path = PathBuf::from("targets/missing.json");
    h.block(BlockedCode::TargetIdentityMismatch);
}
#[test]
fn a03_10_wrong_capability() {
    let mut h = Harness::new("a03-10");
    h.capability = "OTHER".into();
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_11_wrong_operation() {
    let mut h = Harness::new("a03-11");
    h.operation = "DELETE".into();
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_12_read_outside_bounds() {
    let mut h = Harness::new("a03-12");
    h.read = vec![scope("fixture://resource/other", ResourceMatch::Exact)];
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_13_mutation_outside_bounds() {
    let mut h = Harness::new("a03-13");
    h.mutation = vec![scope("fixture://resource/other", ResourceMatch::Exact)];
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_14_prohibited_mutation() {
    let mut h = Harness::new("a03-14");
    h.mutation = vec![scope(&format!("{RESOURCE}/blocked"), ResourceMatch::Exact)];
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_15_network_denied() {
    let mut h = Harness::new("a03-15");
    h.network = true;
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_16_secret_denied() {
    let mut h = Harness::new("a03-16");
    h.secret = true;
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_17_cross_surface_denied() {
    let mut h = Harness::new("a03-17");
    h.cross_surface = true;
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_18_stale_supplied_state() {
    let mut h = Harness::new("a03-18");
    h.resolution.authority_state_id = "fx:authority-state:stale".into();
    h.block(BlockedCode::AuthorityStale);
}
#[test]
fn a03_19_conflicting_governors() {
    let mut h = Harness::new("a03-19");
    add_claim(
        &mut h.state,
        &h.seed,
        "a03-19-forbid",
        "READ",
        "READ_RESOURCE",
        RESOURCE,
        Provision::Forbid,
    );
    h.block(BlockedCode::BlockedAuthorityConflict);
}
#[test]
fn a03_20_partial_governance_gap() {
    let mut h = Harness::new("a03-20");
    h.mutation = vec![scope(&format!("{RESOURCE}/a"), ResourceMatch::Exact)];
    h.state = FixtureProjection::from_seed(&h.seed).unwrap();
    add_claim(
        &mut h.state,
        &h.seed,
        "a03-20-read",
        "READ",
        "READ_RESOURCE",
        RESOURCE,
        Provision::Permit,
    );
    h.block(BlockedCode::BlockedNoActiveGoverningAuthority);
}
#[test]
fn a03_21_partial_supplied_result() {
    let mut h = Harness::new("a03-21");
    h.read
        .push(scope(&format!("{RESOURCE}/b"), ResourceMatch::Exact));
    h.refresh_resolution();
    h.resolution.cells.pop();
    h.block(BlockedCode::Unauthorized);
}
#[test]
fn a03_22_prose_cannot_widen_bounds() {
    let mut h = Harness::new("a03-22");
    h.operation = "DELETE".into();
    h.block(BlockedCode::ScopeViolation);
}
#[test]
fn a03_23_missing_precondition() {
    let mut h = Harness::new("a03-23");
    h.preconditions
        .conditions
        .retain(|c| c.reference != "fx:precondition:ready");
    h.block(BlockedCode::PreconditionDrift);
}
#[test]
fn a03_24_bad_precondition_status() {
    let mut h = Harness::new("a03-24");
    h.preconditions.conditions[0].status = FixtureConditionStatus::Unknown;
    h.block(BlockedCode::PreconditionDrift);
}
#[test]
fn a03_25_target_changes_after_admission() {
    let h = Harness::new("a03-25");
    let prior = evaluate_fixture_admission(&h.input()).unwrap();
    let saved = prior.canonical_bytes().unwrap();
    let marker = FixtureTargetMarkerV1 {
        namespace: "FIXTURE".into(),
        target_id: h.policy.target_id.clone(),
        revision: "r2".into(),
        state_code: "COMMITTED".into(),
    };
    fs::write(&h.marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
    let result = revalidate_fixture_admission(&prior, &h.input());
    assert!(matches!(result, Err(ref e) if e.code == BlockedCode::PreconditionDrift));
    assert_eq!(saved, prior.canonical_bytes().unwrap());
}
#[test]
fn a03_26_authority_changes_after_admission() {
    let mut h = Harness::new("a03-26");
    let prior = evaluate_fixture_admission(&h.input()).unwrap();
    let saved = prior.canonical_bytes().unwrap();
    add_claim(
        &mut h.state,
        &h.seed,
        "a03-26-extra",
        "UPDATE",
        "MUTATE_RESOURCE",
        RESOURCE,
        Provision::Permit,
    );
    let result = revalidate_fixture_admission(&prior, &h.input());
    assert!(matches!(result, Err(ref e) if e.code == BlockedCode::AuthorityStale));
    assert_eq!(saved, prior.canonical_bytes().unwrap());
}
#[test]
fn a03_27_precondition_changes_after_admission() {
    let mut h = Harness::new("a03-27");
    let prior = evaluate_fixture_admission(&h.input()).unwrap();
    let saved = prior.canonical_bytes().unwrap();
    h.preconditions.conditions[0].fixture_revision = "r2".into();
    let result = revalidate_fixture_admission(&prior, &h.input());
    assert!(matches!(result, Err(ref e) if e.code == BlockedCode::PreconditionDrift));
    assert_eq!(saved, prior.canonical_bytes().unwrap());
}
#[test]
fn a03_28_outside_root() {
    let mut h = Harness::new("a03-28");
    h.policy.approved_root = PathBuf::from(r"E:\Pipeline\titan-forward");
    h.block(BlockedCode::TargetIdentityMismatch);
}
#[test]
fn a03_29_real_link_escape() {
    let mut h = Harness::new("a03-29");
    let link = h
        .policy
        .approved_root
        .join("targets")
        .join("a03-29-link.json");
    let outside = h.policy.approved_root.join("outside-a03-29.json");
    fs::write(&outside, fs::read(&h.marker_path).unwrap()).unwrap();
    #[cfg(windows)]
    if fs::symlink_metadata(&link).is_err()
        && let Err(error) = std::os::windows::fs::symlink_file(&outside, &link)
    {
        assert_eq!(
            error.raw_os_error(),
            Some(1314),
            "unexpected link failure: {error}"
        );
        eprintln!("A03-29 NOT_EXECUTED_ENVIRONMENT_LIMIT: Windows symlink privilege unavailable");
        h.policy.relative_marker_path = PathBuf::from("targets/../outside-a03-29.json");
        h.block(BlockedCode::TargetIdentityMismatch);
        return;
    }
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, &link).expect("real file symlink fixture required");
    h.policy.relative_marker_path = PathBuf::from("targets/a03-29-link.json");
    h.policy.target_id = "fx:target:a03-29-link".into();
    h.block(BlockedCode::TargetIdentityMismatch);
}
#[test]
fn a03_29_real_junction_component_rejected() {
    if std::env::var_os("TITAN_F03_REPARSE_MODE").is_none() {
        return;
    }
    let p = project();
    let policy = FixtureTargetPolicyV1 {
        project_id: PROJECT.into(),
        project_digest: p.record().integrity.clone(),
        project_uri: "fixture://project/lab".into(),
        approved_root: PathBuf::from(APPROVED_FIXTURE_ROOT),
        target_id: "fx:target:a03-29".into(),
        relative_marker_path: PathBuf::from("targets/a03-29.json"),
    };
    let targets = policy.approved_root.join("targets");
    let metadata = fs::symlink_metadata(&targets).unwrap();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        assert_ne!(
            metadata.file_attributes() & 0x400,
            0,
            "real junction required"
        );
    }
    #[cfg(not(windows))]
    assert!(
        metadata.file_type().is_symlink(),
        "real directory link required"
    );
    let result = construct_fixture_target_snapshot(&policy);
    assert!(matches!(result, Err(ref e) if e.code == BlockedCode::TargetIdentityMismatch));
}
#[test]
fn a03_30_alias_equivalent_presentation() {
    let mut h = Harness::new("a03-30");
    h.read = vec![scope(RESOURCE, ResourceMatch::Exact)];
    h.refresh_resolution();
    let original = evaluate_fixture_admission(&h.input()).unwrap();
    h.read = vec![scope("fixture://alias/lab", ResourceMatch::Exact)];
    h.preconditions.conditions.reverse();
    let equivalent = evaluate_fixture_admission(&h.input()).unwrap();
    assert_eq!(original.admission_id(), equivalent.admission_id());
}

#[test]
fn a03_guard_non_permit_and_evidence_stops() {
    for (slug, provision) in [
        ("a03-guard-forbid", Provision::Forbid),
        ("a03-guard-approve", Provision::Approve),
    ] {
        let mut h = Harness::new(slug);
        h.state = FixtureProjection::from_seed(&h.seed).unwrap();
        add_claim(
            &mut h.state,
            &h.seed,
            &format!("{slug}-claim"),
            "READ",
            "READ_RESOURCE",
            RESOURCE,
            provision,
        );
        h.refresh_resolution();
        h.block(BlockedCode::Unauthorized);
    }
    let mut h = Harness::new("a03-guard-evidence");
    h.preconditions
        .conditions
        .retain(|c| c.reference != "fx:evidence:ready");
    h.block(BlockedCode::InsufficientEvidence);
    let mut h = Harness::new("a03-guard-stop");
    h.preconditions.active_stop_codes.push("STOP_NOW".into());
    h.block(BlockedCode::PreconditionDrift);
}

#[test]
fn a03_guard_actor_scope_and_profile() {
    let mut h = Harness::new("a03-guard-expired");
    let mut a = match &h.actor.record().payload {
        RecordPayload::ActorBinding(a) => a.clone(),
        _ => unreachable!(),
    };
    a.valid_until_ms = Some(3);
    h.actor = record(RecordPayload::ActorBinding(a));
    h.seed.actor_records = vec![h.actor.canonical_bytes().to_vec()];
    h.state = FixtureProjection::from_seed(&h.seed).unwrap();
    h.block(BlockedCode::Unauthorized);
    let mut h = Harness::new("a03-guard-scope");
    h.read = vec![scope("fixture://resource/lab/ab", ResourceMatch::Exact)];
    let mut contract = match &h.contract.record().payload {
        RecordPayload::ExecutionContract(c) => c.clone(),
        _ => unreachable!(),
    };
    contract.read_scopes = vec!["fixture://resource/lab/a/*".into()];
    h.contract = record(RecordPayload::ExecutionContract(contract));
    h.expected_digest = h.contract.record().integrity.clone();
    h.block(BlockedCode::ScopeViolation);
}

#[test]
fn a03_guard_mutation_positive_and_inert_decode() {
    let mut h = Harness::new("a03-guard-mutate");
    h.read.clear();
    h.mutation = vec![scope(&format!("{RESOURCE}/a"), ResourceMatch::Exact)];
    h.operation = "UPDATE".into();
    h.refresh_resolution();
    let before = fs::read(&h.marker_path).unwrap();
    let admission = evaluate_fixture_admission(&h.input()).unwrap();
    assert_eq!(before, fs::read(&h.marker_path).unwrap());
    let bytes = admission.canonical_bytes().unwrap();
    let mut tampered: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    tampered["namespace"] = "OPERATIONAL".into();
    assert!(
        matches!(decode_fixture_admission(&serde_json::to_vec(&tampered).unwrap(), &h.input()),
        Err(ref e) if e.code == BlockedCode::ContractInvalid)
    );
    tampered["namespace"] = "FIXTURE".into();
    tampered["marker"] = "FAKE".into();
    assert!(
        matches!(decode_fixture_admission(&serde_json::to_vec(&tampered).unwrap(), &h.input()),
        Err(ref e) if e.code == BlockedCode::ContractInvalid)
    );
}

#[test]
fn a03_guard_revoked_actor_and_unsupported_scope() {
    let mut h = Harness::new("a03-guard-revoked");
    let mut a = match &h.actor.record().payload {
        RecordPayload::ActorBinding(a) => a.clone(),
        _ => unreachable!(),
    };
    a.revocation_ref = Some("fx:authority:revocation".into());
    h.actor = record(RecordPayload::ActorBinding(a));
    h.block(BlockedCode::Revoked);
    let mut h = Harness::new("a03-guard-invalid-scope");
    h.read = vec![scope("fixture://resource/lab/%2e%2e", ResourceMatch::Exact)];
    h.block(BlockedCode::ContractInvalid);
    let mut h = Harness::new("a03-guard-duplicate-scope");
    h.read.push(h.read[0].clone());
    h.block(BlockedCode::ContractInvalid);
}

#[test]
fn a03_guard_unborn_and_binding_drift() {
    let h = Harness::new("a03-guard-unborn");
    let marker = FixtureTargetMarkerV1 {
        namespace: "FIXTURE".into(),
        target_id: h.policy.target_id.clone(),
        revision: "none".into(),
        state_code: "UNBORN".into(),
    };
    fs::write(&h.marker_path, serde_json::to_vec(&marker).unwrap()).unwrap();
    h.block(BlockedCode::PreconditionDrift);
    let mut h = Harness::new("a03-guard-contract-drift");
    let prior = evaluate_fixture_admission(&h.input()).unwrap();
    let mut c = match &h.contract.record().payload {
        RecordPayload::ExecutionContract(c) => c.clone(),
        _ => unreachable!(),
    };
    c.mission = "changed fixture mission".into();
    h.contract = record(RecordPayload::ExecutionContract(c));
    h.expected_digest = h.contract.record().integrity.clone();
    assert!(matches!(revalidate_fixture_admission(&prior, &h.input()),
        Err(ref e) if e.code == BlockedCode::PreconditionDrift));
}

#[test]
fn a03_guard_profile_actor_project_and_gate_drift() {
    let h = Harness::new("a03-guard-profile");
    let mut unsupported = h.seed.profile.clone();
    unsupported.normalizer_version = 99;
    assert!(
        matches!(validate_fixture_contract(&h.contract, &unsupported),
        Err(ref e) if e.code == BlockedCode::ContractInvalid)
    );

    let mut h = Harness::new("a03-guard-actor-drift");
    let prior = evaluate_fixture_admission(&h.input()).unwrap();
    let mut changed = match &h.actor.record().payload {
        RecordPayload::ActorBinding(a) => a.clone(),
        _ => unreachable!(),
    };
    changed.principal_ref = "fx:principal:other".into();
    h.actor = record(RecordPayload::ActorBinding(changed));
    assert!(matches!(revalidate_fixture_admission(&prior, &h.input()),
        Err(ref e) if e.code == BlockedCode::PreconditionDrift));

    let mut h = Harness::new("a03-guard-project-drift");
    let prior = evaluate_fixture_admission(&h.input()).unwrap();
    let mut changed = match &h.project.record().payload {
        RecordPayload::ProjectBinding(p) => p.clone(),
        _ => unreachable!(),
    };
    changed.binding_revision = 2;
    h.project = record(RecordPayload::ProjectBinding(changed));
    assert!(matches!(revalidate_fixture_admission(&prior, &h.input()),
        Err(ref e) if e.code == BlockedCode::TargetIdentityMismatch));

    let mut h = Harness::new("a03-guard-gate");
    h.preconditions
        .conditions
        .retain(|c| c.reference != "fx:gate:ready");
    h.block(BlockedCode::InsufficientEvidence);
}
