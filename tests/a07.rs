//! A07 imports a genuine F06 basis; only the disposable SQLite pointer may transition.
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
    sync::{
        Arc, Barrier,
        atomic::{AtomicU32, Ordering},
    },
};
use titan_kernel::{
    ValidatedRecord,
    eligibility::*,
    encode_fixture,
    evidence::{
        FixtureEventV1 as HistoryEvent, FixtureStoreV1, append_fixture_event, hash,
        observation_event, replay_fixture_history,
    },
    fixture_projection::{
        FixtureAuthoritySeedV1, FixtureEventKind, FixtureEventV1, FixtureProjection, IssuerScopeV1,
        apply_fixture_event,
    },
    outcome::{OutcomeVariant, PassCode},
    records::*,
    selector::{SelectorProfileV1, normalize_fixture_selector},
    test_store::*,
    transition::*,
    verification::*,
};
const PROJECT: &str = "fx:project:lab";
const EXECUTOR: &str = "fx:actor:executor";
const VERIFIER: &str = "fx:actor:verifier";
const APPROVER: &str = "fx:actor:approver";
const AUTHORIZER: &str = "fx:actor:authorizer";
const TASK: &str = titan_kernel::FIXTURE_WORK_ROOT;
fn record(payload: RecordPayload, creator: &str) -> ValidatedRecord {
    encode_fixture(RecordEnvelope {
        record_type: payload.record_type(),
        schema_version: 1,
        namespace: Namespace::Fixture,
        record_id: payload.primary_id().into(),
        creator_ref: creator.into(),
        created_at_unix_ms: 2,
        payload,
        integrity: format!("sha256:{}", "0".repeat(64)),
    })
    .unwrap()
}
fn actor_record(id: &str, roles: Vec<Role>) -> ValidatedRecord {
    record(
        RecordPayload::ActorBinding(ActorBinding {
            actor_id: id.into(),
            principal_ref: id.replace("actor", "principal"),
            auth_method_ref: "fx:method:fixture".into(),
            roles,
            issued_by_ref: APPROVER.into(),
            valid_from_ms: 1,
            valid_until_ms: Some(1000),
            revocation_ref: None,
        }),
        APPROVER,
    )
}
fn atom(resource: &str, kind: ResourceMatch, action: &str, provision: Provision) -> ClaimAtom {
    ClaimAtom {
        project_binding_ref: PROJECT.into(),
        resource_ref: resource.into(),
        resource_match: kind,
        action: action.into(),
        provision,
        effect: "PROMOTION_ELIGIBILITY".into(),
        lifecycle_contexts: vec!["READY".into()],
    }
}
fn packet<T: Serialize + Clone>(body: &T, domain: &[u8], kind: &str) -> Vec<u8> {
    let digest = hash(domain, &serde_json::to_vec(body).unwrap());
    serde_json::to_vec(&FixtureRecordV1 {
        body: body.clone(),
        record_id: format!("fx:{kind}:{}", &digest[7..]),
        body_digest: digest,
    })
    .unwrap()
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
struct InventoryRow {
    path: String,
    kind: String,
    digest: String,
    len: u64,
    modified: Option<u128>,
    attributes: u32,
}
fn inventory(path: &Path, rows: &mut Vec<InventoryRow>) {
    let Ok(m) = fs::symlink_metadata(path) else {
        rows.push(InventoryRow {
            path: path.display().to_string(),
            kind: "ABSENT".into(),
            digest: String::new(),
            len: 0,
            modified: None,
            attributes: 0,
        });
        return;
    };
    #[cfg(windows)]
    let attributes = {
        use std::os::windows::fs::MetadataExt;
        m.file_attributes()
    };
    #[cfg(not(windows))]
    let attributes = 0;
    let link = m.file_type().is_symlink() || attributes & 0x400 != 0;
    rows.push(InventoryRow {
        path: path.display().to_string(),
        kind: if link {
            "LINK"
        } else if m.is_file() {
            "FILE"
        } else {
            "DIRECTORY"
        }
        .into(),
        digest: if m.is_file() && !link {
            hash(b"", &fs::read(path).unwrap())
        } else {
            String::new()
        },
        len: if m.is_file() { m.len() } else { 0 },
        modified: m
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_nanos()),
        attributes,
    });
    if m.is_dir() && !link {
        let mut paths = fs::read_dir(path)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect::<Vec<_>>();
        paths.sort();
        for p in paths {
            inventory(&p, rows);
        }
    }
}
struct Harness {
    project: ValidatedRecord,
    contract: ValidatedRecord,
    seed: FixtureAuthoritySeedV1,
    state: FixtureProjection,
    authorization: ValidatedRecord,
    store: FixtureStoreV1,
    candidate: FixtureCandidateV1,
    set: FixtureEvidenceSetV1,
    verification: FixtureVerificationBodyV1,
    approval: FixtureApprovalBodyV1,
    policy: FixtureAssurancePolicyV1,
    prior: ExpectedPriorCanonicalV1,
    expected_state: String,
    consequence: ConsequenceV1,
    rule: u32,
    epoch: u64,
    missing_approval: bool,
    missing_prior: bool,
    candidate_path: PathBuf,
}
#[allow(dead_code)]
impl Harness {
    fn new(slug: &str) -> Self {
        Self::with_alias(slug, false)
    }
    fn with_alias(slug: &str, alias: bool) -> Self {
        Self::with_options(slug, alias, None)
    }
    fn with_options(slug: &str, alias: bool, authorizer_expiry: Option<u64>) -> Self {
        let case = format!("a07-{slug}-{}", std::process::id());
        let project = record(
            RecordPayload::ProjectBinding(ProjectBinding {
                project_id: PROJECT.into(),
                canonical_root: "fixture://project/lab".into(),
                repository_id: None,
                repository_url: None,
                authority_source_ref: "fx:authority:fixture-seed".into(),
                binding_revision: 1,
                state: BindingState::Active,
            }),
            APPROVER,
        );
        let mut actors = vec![
            actor_record(EXECUTOR, vec![Role::Executor, Role::Verifier]),
            actor_record(VERIFIER, vec![Role::Verifier]),
            actor_record(APPROVER, vec![Role::DecisionAuthority]),
        ];
        if let Some(expiry) = authorizer_expiry {
            let mut payload = actor_record(AUTHORIZER, vec![Role::DecisionAuthority])
                .record()
                .payload
                .clone();
            if let RecordPayload::ActorBinding(binding) = &mut payload {
                binding.valid_until_ms = Some(expiry);
            }
            actors.push(record(payload, APPROVER));
        }
        if alias {
            let mut payload = actors[1].record().payload.clone();
            if let RecordPayload::ActorBinding(binding) = &mut payload {
                binding.principal_ref = "fx:principal:executor".into();
            }
            actors[1] = record(payload, APPROVER);
        }
        let profile = SelectorProfileV1 {
            normalizer_version: 1,
            compatibility_version: 1,
            actions: vec!["APPROVE".into(), "CONSIDER_PROMOTION".into()],
            effects: vec!["PROMOTION_ELIGIBILITY".into()],
            contexts: vec!["READY".into()],
            aliases: vec![],
        };
        let mut broad = Vec::new();
        for action in ["APPROVE", "CONSIDER_PROMOTION"] {
            broad.extend(
                normalize_fixture_selector(
                    &atom(
                        "fixture://resource/lab",
                        ResourceMatch::Subtree,
                        action,
                        Provision::Permit,
                    ),
                    &profile,
                )
                .unwrap(),
            );
        }
        broad.sort();
        let mut seed = FixtureAuthoritySeedV1 {
            project_record: project.canonical_bytes().to_vec(),
            actor_records: actors
                .iter()
                .map(|a| a.canonical_bytes().to_vec())
                .collect(),
            profile,
            issuers: vec![IssuerScopeV1 {
                actor_id: APPROVER.into(),
                role: Role::DecisionAuthority,
                claim_scope: broad.clone(),
                override_scope: broad.clone(),
                revocation_scope: broad.clone(),
                reinstatement_scope: broad,
            }],
        };
        if authorizer_expiry.is_some() {
            let mut issuer = seed.issuers[0].clone();
            issuer.actor_id = AUTHORIZER.into();
            seed.issuers.push(issuer);
        }
        let mut state = FixtureProjection::from_seed(&seed).unwrap();
        let target = format!("fx:target:{case}");
        let run = format!("fx:run:{case}");
        let scope = format!("fixture://resource/lab/{case}");
        let ids = vec![
            format!("fx:evidence:{case}-a"),
            format!("fx:evidence:{case}-b"),
        ];
        let contract = record(
            RecordPayload::ExecutionContract(ExecutionContract {
                contract_id: format!("fx:contract:{case}"),
                contract_version: 1,
                mission: "fixture candidate only".into(),
                project_binding_ref: PROJECT.into(),
                target_ref: target.clone(),
                expected_target_state: "r1".into(),
                actor_ref: EXECUTOR.into(),
                capability_code: "FIXTURE_OPERATION".into(),
                allowed_operations: vec!["UPDATE".into()],
                read_scopes: vec![scope.clone()],
                allowed_mutations: vec![scope.clone()],
                prohibited_mutations: vec![],
                precondition_refs: vec![],
                required_evidence_refs: ids.clone(),
                verification_gate_refs: vec!["fx:gate:ready".into()],
                stop_codes: vec!["STOP_NOW".into()],
                escalation_ref: "fx:route:control-room".into(),
                expected_deliverables: vec!["inert fixture candidate".into()],
                requester_boundary: "fixture only".into(),
                network_allowed: false,
                secret_access_allowed: false,
                cross_surface_delivery_allowed: false,
            }),
            EXECUTOR,
        );
        let mut decisions = Vec::new();
        for (suffix, action, provision) in [
            ("authorization", "CONSIDER_PROMOTION", Provision::Permit),
            ("approval-scope", "APPROVE", Provision::Approve),
        ] {
            let issuer = if suffix == "authorization" && authorizer_expiry.is_some() {
                AUTHORIZER
            } else {
                APPROVER
            };
            let decision = record(
                RecordPayload::AuthorityRecord(AuthorityRecord {
                    authority_id: format!("fx:authority:{case}-{suffix}"),
                    class: AuthorityClass::Decision,
                    issuer_actor_ref: issuer.into(),
                    exercised_role: Role::DecisionAuthority,
                    effective_at_ms: 2,
                    target_binding_ref: Some(PROJECT.into()),
                    contract_digest: Some(contract.record().integrity.clone()),
                    claim_atoms: vec![atom(&scope, ResourceMatch::Exact, action, provision)],
                    override_edges: vec![],
                    evidence_refs: vec![],
                }),
                issuer,
            );
            let event = FixtureEventV1 {
                event_id: format!("fx:event:{case}-{suffix}"),
                kind: FixtureEventKind::ClaimAcceptance,
                record_id: decision.record().record_id.clone(),
                record_digest: decision.record().integrity.clone(),
                issuer_actor_id: issuer.into(),
                expected_prior_state_id: state.state_id.clone(),
                target_claim_id: None,
                target_edge_id: None,
            };
            apply_fixture_event(&mut state, &seed, &decision, &event).unwrap();
            decisions.push(decision);
        }
        let candidate_record = record(
            RecordPayload::Outcome(Outcome {
                outcome_id: format!("fx:outcome:{case}"),
                status_and_code: OutcomeVariant::Pass(PassCode::WorkCompleted),
                scope_ref: run.clone(),
                evidence_refs: vec![],
                next_action: "Control Room review only".into(),
                detail: "claimed verified approved eligible promoted; inert candidate text".into(),
            }),
            EXECUTOR,
        );
        let candidate_path = PathBuf::from(ROOT)
            .join("cases")
            .join(&case)
            .join("candidate.json");
        fs::create_dir_all(candidate_path.parent().unwrap()).unwrap();
        fs::write(&candidate_path, candidate_record.canonical_bytes()).unwrap();
        let candidate = FixtureCandidateV1 {
            namespace: "FIXTURE".into(),
            version: 1,
            project_id: PROJECT.into(),
            candidate_id: format!("fx:candidate:{case}"),
            revision: "r1".into(),
            content_digest: hash(b"", candidate_record.canonical_bytes()),
            subject_id: target,
            subject_revision: "r1".into(),
            scope,
            contract_id: contract.record().record_id.clone(),
            contract_digest: contract.record().integrity.clone(),
            run_id: run.clone(),
            effect_receipt_id: None,
            executor_actor_id: EXECUTOR.into(),
        };
        let store = FixtureStoreV1::open(&case, &seed).unwrap();
        let artifact = FixtureEvidenceArtifactV1 {
            namespace: "FIXTURE".into(),
            version: 1,
            candidate_id: candidate.candidate_id.clone(),
            candidate_revision: candidate.revision.clone(),
            candidate_digest: candidate.content_digest.clone(),
            candidate_bytes: candidate_record.canonical_bytes().to_vec(),
        };
        let raw = serde_json::to_vec(&artifact).unwrap();
        for (i, id) in ids.iter().enumerate() {
            let name = format!("proof-{i}");
            fs::write(store.raw_path(&name).unwrap(), &raw).unwrap();
            let e = record(
                RecordPayload::EvidenceRef(EvidenceRef {
                    evidence_id: id.clone(),
                    kind: "OBSERVATION".into(),
                    locator: format!("fixture://f04/raw/{name}"),
                    content_digest: hash(b"", &raw),
                    producer_ref: VERIFIER.into(),
                    method: "FIXTURE_PROBE".into(),
                    subject_ref: candidate.subject_id.clone(),
                    subject_revision: candidate.subject_revision.clone(),
                    observed_at_ms: 3,
                    contract_ref: candidate.contract_id.clone(),
                    run_ref: run.clone(),
                    gate_ref: Some("fx:gate:ready".into()),
                    status: EvidenceStatus::Current,
                }),
                VERIFIER,
            );
            let h = replay_fixture_history(&store).unwrap();
            append_fixture_event(
                &store,
                &run,
                h.head_id(),
                observation_event(&seed, &e, &actors[1], &candidate.contract_digest).unwrap(),
            )
            .unwrap();
        }
        let set = bind_fixture_evidence_set(&store, &candidate, &contract, &ids).unwrap();
        let policy = FixtureAssurancePolicyV1 {
            profile: POLICY.into(),
            version: 1,
            low_impact: None,
        };
        let prior = ExpectedPriorCanonicalV1 {
            namespace: "FIXTURE".into(),
            pointer_id: format!("fx:canonical:{case}"),
            subject_id: candidate.subject_id.clone(),
            scope: candidate.scope.clone(),
            genesis: true,
            candidate_id: None,
            candidate_digest: None,
            version: Some(0),
        };
        let authorization = decisions.remove(0);
        let verification = FixtureVerificationBodyV1 {
            namespace: "FIXTURE".into(),
            version: 1,
            candidate: candidate.clone(),
            evidence_set_id: set.evidence_set_id.clone(),
            evidence_set_digest: set.digest.clone(),
            method: "FIXTURE_KNOWN_ANSWER_V1".into(),
            method_version: 1,
            verifier_actor_id: VERIFIER.into(),
            producer_actor_id: VERIFIER.into(),
            verifier_binding_digest: actors[1].record().integrity.clone(),
            display_name: "independent fixture verifier".into(),
            independence: IndependenceV1::Independent,
            consequence: ConsequenceV1::HighImpactFixture,
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: policy.digest().unwrap(),
            rule_id: RULE.into(),
            rule_version: 1,
            authority_state_id: state.state_id.clone(),
            authorization_id: authorization.record().record_id.clone(),
            authorization_digest: authorization.record().integrity.clone(),
            expected_prior: prior.clone(),
            assessment_bytes: Vec::new(),
            outcome: VerificationOutcomeV1::Pass,
        };
        let approval = FixtureApprovalBodyV1 {
            namespace: "FIXTURE".into(),
            version: 1,
            candidate: candidate.clone(),
            approver_actor_id: APPROVER.into(),
            approver_binding_digest: actors[2].record().integrity.clone(),
            required_role: Role::DecisionAuthority,
            authorization_id: authorization.record().record_id.clone(),
            authorization_digest: authorization.record().integrity.clone(),
            policy_id: POLICY.into(),
            policy_version: 1,
            policy_digest: policy.digest().unwrap(),
            rule_id: RULE.into(),
            rule_version: 1,
            consequence: ConsequenceV1::HighImpactFixture,
            expected_prior: prior.clone(),
            authority_state_id: state.state_id.clone(),
            status_state_ref: state.state_id.clone(),
            status: EvidenceStatus::Current,
            valid_from_epoch: 1,
            valid_until_epoch: 100,
            decision: ApprovalDecisionV1::Approve,
            governing_decision_bytes: decisions[0].canonical_bytes().to_vec(),
        };
        let expected_state = state.state_id.clone();
        let mut h = Self {
            project,
            contract,
            seed,
            state,
            authorization,
            store,
            candidate,
            set,
            verification,
            approval,
            policy,
            prior,
            expected_state,
            consequence: ConsequenceV1::HighImpactFixture,
            rule: 1,
            epoch: 10,
            missing_approval: false,
            missing_prior: false,
            candidate_path,
        };
        h.assessment();
        h
    }
    fn assessment(&mut self) {
        let decision = match self.verification.outcome {
            VerificationOutcomeV1::Pass => AssessmentDecision::Pass,
            VerificationOutcomeV1::Fail => AssessmentDecision::Fail,
            VerificationOutcomeV1::Blocked => AssessmentDecision::Blocked,
            VerificationOutcomeV1::Unknown => AssessmentDecision::Unknown,
        };
        self.verification.assessment_bytes = record(
            RecordPayload::Assessment(Assessment {
                assessment_id: "fx:assessment:verification".into(),
                subject_ref: self.candidate.candidate_id.clone(),
                gate_result_refs: vec!["fx:gate:ready".into()],
                verifier_actor_ref: self.verification.verifier_actor_id.clone(),
                independence_claimed: self.verification.independence == IndependenceV1::Independent,
                evidence_refs: self
                    .set
                    .members
                    .iter()
                    .map(|m| m.evidence_id.clone())
                    .collect(),
                decision,
                reason: "external known-answer fixture assessment".into(),
            }),
            &self.verification.verifier_actor_id,
        )
        .canonical_bytes()
        .to_vec();
    }
    fn input<'a>(&'a self, v: &'a [u8], a: &'a [u8]) -> FixtureEligibilityInput<'a> {
        FixtureEligibilityInput {
            candidate: &self.candidate,
            project: &self.project,
            contract: &self.contract,
            seed: &self.seed,
            authority_state: &self.state,
            expected_authority_state_id: &self.expected_state,
            authorization: &self.authorization,
            store: &self.store,
            evidence_set: &self.set,
            verification_bytes: v,
            approval_bytes: if self.missing_approval { None } else { Some(a) },
            policy: &self.policy,
            consequence: self.consequence,
            rule_version: self.rule,
            expected_prior: if self.missing_prior {
                None
            } else {
                Some(&self.prior)
            },
            evaluation_epoch: self.epoch,
        }
    }
    fn invalidate(&self) {
        // Preparation only: a distinct current EVIDENCE_REVIEW supports invalidation.
        let id = format!("fx:evidence:{}-review", self.store.case_id());
        let raw = b"independent fixture review: invalidate proof-0";
        fs::write(self.store.raw_path("review").unwrap(), raw).unwrap();
        let evidence = record(
            RecordPayload::EvidenceRef(EvidenceRef {
                evidence_id: id.clone(),
                kind: "OBSERVATION".into(),
                locator: "fixture://f04/raw/review".into(),
                content_digest: hash(b"", raw),
                producer_ref: VERIFIER.into(),
                method: "EVIDENCE_REVIEW".into(),
                subject_ref: self.candidate.subject_id.clone(),
                subject_revision: self.candidate.subject_revision.clone(),
                observed_at_ms: 9,
                contract_ref: self.candidate.contract_id.clone(),
                run_ref: self.candidate.run_id.clone(),
                gate_ref: Some("fx:gate:ready".into()),
                status: EvidenceStatus::Current,
            }),
            VERIFIER,
        );
        let producer = titan_kernel::validate_bytes(&self.seed.actor_records[1]).unwrap();
        let head = replay_fixture_history(&self.store)
            .unwrap()
            .head_id()
            .to_owned();
        append_fixture_event(
            &self.store,
            &self.candidate.run_id,
            &head,
            observation_event(
                &self.seed,
                &evidence,
                &producer,
                &self.candidate.contract_digest,
            )
            .unwrap(),
        )
        .unwrap();
        let history = replay_fixture_history(&self.store).unwrap();
        append_fixture_event(
            &self.store,
            &self.candidate.run_id,
            history.head_id(),
            HistoryEvent::EvidenceInvalidated {
                evidence_id: self.set.members[0].evidence_id.clone(),
                prior_digest: self.set.members[0].record_digest.clone(),
                source_evidence_id: id,
                reason_code: "INVALIDATED_BY_REVIEW".into(),
                actor_id: VERIFIER.into(),
                epoch: 10,
            },
        )
        .unwrap();
    }
}

static CALL: AtomicU32 = AtomicU32::new(0);

struct Case {
    h: Harness,
    eligibility: FixturePromotionEligibilityV1,
    store: FixtureTransitionStoreV1,
    request: FixtureTransitionRequestV1,
}
impl Case {
    fn new(slug: &str) -> Self {
        let h = Harness::new(slug);
        Self::from_harness(h)
    }
    fn from_harness(h: Harness) -> Self {
        let v = packet(&h.verification, VERIFICATION_DOMAIN, "verification");
        let a = packet(&h.approval, APPROVAL_DOMAIN, "approval");
        let eligibility = evaluate_fixture_eligibility_v1(h.input(&v, &a)).unwrap();
        let snapshot = FixtureDependencySnapshotV1::capture(&eligibility, h.input(&v, &a)).unwrap();
        let store =
            FixtureTransitionStoreV1::create(h.store.case_id(), &eligibility, &snapshot).unwrap();
        let request =
            FixtureTransitionRequestV1::from_eligibility("transition", &eligibility).unwrap();
        Self {
            h,
            eligibility,
            store,
            request,
        }
    }
    fn upstream(&self) -> Vec<InventoryRow> {
        let mut rows = Vec::new();
        inventory(self.h.candidate_path.parent().unwrap(), &mut rows);
        inventory(&self.h.store.case_path(), &mut rows);
        inventory(&PathBuf::from(TASK).join("f05-fixtures"), &mut rows);
        rows
    }
    fn state(&self) -> serde_json::Value {
        serde_json::to_value(self.store.state().unwrap()).unwrap()
    }
    fn run(
        &mut self,
        request: &FixtureTransitionRequestV1,
        epoch: u64,
        failure: FailurePointV1,
    ) -> Result<FixtureTransitionResultV1, F07Error> {
        let before = self.state();
        let upstream_before = self.upstream();
        let dependencies_before = self
            .store
            .dependency_names()
            .unwrap()
            .into_iter()
            .map(|name| {
                let bytes = self.store.dependency(&name).unwrap();
                (name, bytes)
            })
            .collect::<Vec<_>>();
        let result = execute_fixture_transition_v1(&mut self.store, request, epoch, failure);
        let after = self.state();
        let upstream_after = self.upstream();
        let dependencies_after = self
            .store
            .dependency_names()
            .unwrap()
            .into_iter()
            .map(|name| {
                let bytes = self.store.dependency(&name).unwrap();
                (name, bytes)
            })
            .collect::<Vec<_>>();
        assert_eq!(
            upstream_before, upstream_after,
            "transition changed F04/F05/F06 fixture inputs"
        );
        assert_eq!(
            dependencies_before, dependencies_after,
            "transition repaired a dependency"
        );
        if result.is_err() {
            assert_eq!(
                before, after,
                "blocked transition changed pointer/receipt/consumption"
            );
        }
        let path = PathBuf::from(TASK)
            .join("f07-evidence/cases")
            .join(self.h.store.case_id());
        fs::create_dir_all(&path).unwrap();
        let sequence = CALL.fetch_add(1, Ordering::Relaxed);
        fs::write(path.join(format!("{sequence:06}.json")), serde_json::to_vec(&serde_json::json!({
            "case": self.h.store.case_id(),
            "fixture_setup": "genuine F06 candidate plus F04 observations; independent external approval/verification fixtures; explicit SQLite imported current snapshot",
            "request": request, "epoch": epoch, "failure_point": format!("{failure:?}"),
            "eligibility_id": self.eligibility.record_id(),
            "eligibility_digest": self.eligibility.body_digest(),
            "before": before, "after": after,
            "upstream_before": upstream_before, "upstream_after": upstream_after,
            "upstream_effects": [], "dependency_repair_effects": [],
            "dependencies_before": dependencies_before, "dependencies_after": dependencies_after,
            "result": result_value(&result),
            "sqlite_path": self.store.path()
        })).unwrap()).unwrap();
        result
    }
    fn execute(&mut self) -> Result<FixtureTransitionResultV1, F07Error> {
        let request = self.request.clone();
        self.run(&request, 11, FailurePointV1::None)
    }
}

#[test]
fn a07_01_fresh_basis_transitions_once_and_receipt_binds_entire_basis() {
    let mut c = Case::new("01");
    let before = c.state();
    let r = c.execute().unwrap();
    assert!(!r.replayed);
    let after = c.state();
    assert_ne!(before, after);
    assert_eq!(after["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(after["consumed"].as_array().unwrap().len(), 1);
    let receipt = serde_json::to_value(&r.receipt).unwrap();
    let text = serde_json::to_string(&receipt).unwrap();
    assert!(text.contains(c.eligibility.record_id()));
    assert!(text.contains(c.eligibility.body_digest()));
    assert!(text.contains(&c.h.candidate.candidate_id));
    assert!(text.contains(&c.h.prior.pointer_id));
    assert_eq!(
        r.receipt.body.eligibility_bytes,
        c.eligibility.canonical_bytes()
    );
    let basis: serde_json::Value =
        serde_json::from_slice(&r.receipt.body.eligibility_bytes).unwrap();
    assert_eq!(
        basis["body"]["evidence_set"]["evidence_set_id"],
        c.h.set.evidence_set_id
    );
    assert_eq!(basis["body"]["authority_state_id"], c.h.state.state_id);
}

#[test]
fn a07_02_every_material_current_dependency_drift_causes_zero_transition() {
    let mut c = Case::new("02");
    let names = c.store.dependency_names().unwrap();
    assert!(
        names.len() >= 18,
        "complete material binding inventory required"
    );
    for name in names {
        let original = c.store.dependency(&name).unwrap();
        c.store
            .set_dependency(&name, b"\"STALE_CURRENT_DEPENDENCY\"")
            .unwrap();
        assert_eq!(
            c.execute().unwrap_err(),
            F07Error::BlockedPromotionEligibilityStale,
            "{name}"
        );
        c.store.set_dependency(&name, &original).unwrap();
    }
    assert!(!c.execute().unwrap().replayed);
}

#[test]
fn a07_03_every_material_dependency_missing_blocks() {
    let mut c = Case::new("03");
    for name in c.store.dependency_names().unwrap() {
        let bytes = c.store.dependency(&name).unwrap();
        c.store.remove_dependency(&name).unwrap();
        assert_eq!(
            c.execute().unwrap_err(),
            F07Error::BlockedPromotionEligibilityStale,
            "{name}"
        );
        rusqlite::Connection::open(c.store.path())
            .unwrap()
            .execute(
                "INSERT INTO dependencies(name,value) VALUES(?1,?2)",
                rusqlite::params![name, bytes],
            )
            .unwrap();
    }
}

#[test]
fn a07_04_before_pointer_injected_failure_is_atomic_rollback() {
    let mut c = Case::new("04");
    assert_eq!(
        c.run(&c.request.clone(), 11, FailurePointV1::BeforePointer)
            .unwrap_err(),
        F07Error::BlockedEnvironment
    );
    assert!(!c.execute().unwrap().replayed);
}
#[test]
fn a07_05_after_pointer_injected_failure_is_atomic_rollback() {
    let mut c = Case::new("05");
    assert_eq!(
        c.run(&c.request.clone(), 11, FailurePointV1::AfterPointer)
            .unwrap_err(),
        F07Error::BlockedEnvironment
    );
    assert!(!c.execute().unwrap().replayed);
}
#[test]
fn a07_06_after_consumption_injected_failure_is_atomic_rollback() {
    let mut c = Case::new("06");
    assert_eq!(
        c.run(&c.request.clone(), 11, FailurePointV1::AfterConsumption)
            .unwrap_err(),
        F07Error::BlockedEnvironment
    );
    assert!(!c.execute().unwrap().replayed);
}
#[test]
fn a07_07_after_receipt_injected_failure_is_atomic_rollback() {
    let mut c = Case::new("07");
    assert_eq!(
        c.run(&c.request.clone(), 11, FailurePointV1::AfterReceipt)
            .unwrap_err(),
        F07Error::BlockedEnvironment
    );
    assert!(!c.execute().unwrap().replayed);
}

#[test]
fn a07_08_restart_recovers_pointer_receipt_and_consumption() {
    let mut c = Case::new("08");
    c.execute().unwrap();
    let committed = c.state();
    let reopened = FixtureTransitionStoreV1::open(c.h.store.case_id()).unwrap();
    assert_eq!(
        serde_json::to_value(reopened.state().unwrap()).unwrap(),
        committed
    );
    c.store = reopened;
    let replay = c.execute().unwrap();
    assert!(replay.replayed);
    assert_eq!(c.state(), committed);
}
#[test]
fn a07_09_exact_replay_returns_identical_receipt_without_update() {
    let mut c = Case::new("09");
    let original = c.execute().unwrap();
    let committed = c.state();
    let replay = c.execute().unwrap();
    assert!(replay.replayed);
    assert_eq!(original.receipt, replay.receipt);
    assert_eq!(c.state(), committed);
}

#[test]
fn a07_10_consumed_basis_different_transition_is_not_exact_replay() {
    let mut c = Case::new("10");
    c.execute().unwrap();
    let request = FixtureTransitionRequestV1::from_eligibility("another", &c.eligibility).unwrap();
    assert_eq!(
        c.run(&request, 11, FailurePointV1::None).unwrap_err(),
        F07Error::BlockedEligibilityConsumed
    );
}
#[test]
fn a07_11_consumed_basis_cannot_change_candidate() {
    let mut c = Case::new("11");
    c.execute().unwrap();
    let mut request = c.request.clone();
    request.candidate.candidate_id = "fx:candidate:another".into();
    assert!(c.run(&request, 11, FailurePointV1::None).is_err());
}
#[test]
fn a07_12_consumed_basis_cannot_change_subject_scope() {
    let mut c = Case::new("12");
    c.execute().unwrap();
    let mut request = c.request.clone();
    request.candidate.subject_id = "fx:target:another".into();
    request.candidate.scope = "fixture://resource/lab/another".into();
    assert!(c.run(&request, 11, FailurePointV1::None).is_err());
}
#[test]
fn a07_13_consumed_basis_cannot_change_prior_pointer_version() {
    let mut c = Case::new("13");
    c.execute().unwrap();
    let mut request = c.request.clone();
    request.expected_prior.pointer_id = "fx:canonical:another".into();
    request.expected_prior.version = Some(2);
    assert!(c.run(&request, 11, FailurePointV1::None).is_err());
}

#[test]
fn a07_14_approval_expiration_checked_at_transition_not_eligibility_time() {
    let mut c = Case::new("14");
    assert_eq!(
        c.run(&c.request.clone(), 100, FailurePointV1::None)
            .unwrap_err(),
        F07Error::BlockedPromotionEligibilityStale
    );
}
#[test]
fn a07_15_transition_time_cannot_precede_evaluation_time() {
    let mut c = Case::new("15");
    assert!(c.run(&c.request.clone(), 9, FailurePointV1::None).is_err());
}
#[test]
fn a07_16_operational_pointer_request_blocks() {
    let mut c = Case::new("16");
    let mut request = c.request.clone();
    request.expected_prior.pointer_id = "https://github.com/Aimcurio/titan".into();
    assert!(c.run(&request, 11, FailurePointV1::None).is_err());
}
#[test]
fn a07_17_operational_candidate_namespace_blocks() {
    let mut c = Case::new("17");
    let mut request = c.request.clone();
    request.candidate.namespace = "OPERATIONAL".into();
    assert!(c.run(&request, 11, FailurePointV1::None).is_err());
}
#[test]
fn a07_18_store_case_path_cannot_escape_fixture_domain() {
    for slug in [
        "../escape",
        r"..\escape",
        r"E:\Pipeline\titan-forward",
        "https://github.com/Aimcurio/titan",
        ".git",
        "",
    ] {
        assert!(FixtureTransitionStoreV1::open(slug).is_err(), "{slug}");
    }
}

#[test]
fn a07_19_distinct_request_concurrent_writers_have_exactly_one_winner() {
    let c = Case::new("19");
    let before = c.upstream();
    let gate = Arc::new(Barrier::new(8));
    let threads = (0..8)
        .map(|index| {
            let case = c.h.store.case_id().to_owned();
            let mut request = c.request.clone();
            request.transition_id = format!("fx:transition:writer-{index}");
            let gate = gate.clone();
            std::thread::spawn(move || {
                let mut store = FixtureTransitionStoreV1::open(&case).unwrap();
                gate.wait();
                execute_fixture_transition_v1(&mut store, &request, 11, FailurePointV1::None)
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(|r| !r.replayed))
            .count(),
        1
    );
    assert_eq!(results.iter().filter(|r| r.is_err()).count(), 7);
    let state = c.state();
    assert_eq!(state["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(state["consumed"].as_array().unwrap().len(), 1);
    assert_eq!(before, c.upstream());
    record_race(&c, &results, "distinct_requests");
}
#[test]
fn a07_20_identical_concurrent_requests_have_one_transition_then_replays() {
    let c = Case::new("20");
    let before = c.upstream();
    let gate = Arc::new(Barrier::new(8));
    let threads = (0..8)
        .map(|_| {
            let case = c.h.store.case_id().to_owned();
            let request = c.request.clone();
            let gate = gate.clone();
            std::thread::spawn(move || {
                let mut store = FixtureTransitionStoreV1::open(&case).unwrap();
                gate.wait();
                execute_fixture_transition_v1(&mut store, &request, 11, FailurePointV1::None)
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(|r| !r.replayed))
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .filter(|r| r.as_ref().is_ok_and(|r| r.replayed))
            .count(),
        7
    );
    assert_eq!(c.state()["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(before, c.upstream());
    record_race(&c, &results, "exact_request");
}
fn record_race(c: &Case, results: &[Result<FixtureTransitionResultV1, F07Error>], kind: &str) {
    let path = PathBuf::from(TASK).join("f07-evidence/races");
    fs::create_dir_all(&path).unwrap();
    fs::write(
        path.join(format!("{}.json", c.h.store.case_id())),
        serde_json::to_vec(&serde_json::json!({
            "kind":kind,"results":results.iter().map(result_value).collect::<Vec<_>>(),"after":c.state(),"upstream_effects":[],
            "independent_connections":8,"synchronized_barrier":true
        }))
        .unwrap(),
    )
    .unwrap();
}
fn result_value(result: &Result<FixtureTransitionResultV1, F07Error>) -> serde_json::Value {
    match result {
        Ok(r) => serde_json::json!({"receipt":r.receipt,"replayed":r.replayed}),
        Err(e) => serde_json::json!({"blocked":format!("{e:?}")}),
    }
}
#[test]
fn a07_21_changed_current_prior_blocks_without_receipt() {
    let mut c = Case::new("21");
    let mut prior = c.h.prior.clone();
    prior.genesis = false;
    prior.version = Some(1);
    prior.candidate_id = Some("fx:candidate:other".into());
    prior.candidate_digest = Some(format!("sha256:{}", "0".repeat(64)));
    let connection = rusqlite::Connection::open(c.store.path()).unwrap();
    connection
        .execute(
            "UPDATE pointer SET value=?1 WHERE singleton=1",
            [serde_json::to_vec(&prior).unwrap()],
        )
        .unwrap();
    assert_eq!(
        c.execute().unwrap_err(),
        F07Error::BlockedCanonicalStateChanged
    );
}
#[test]
fn a07_22_other_connection_prior_commit_invalidates_snapshot() {
    let mut c = Case::new("22");
    let case = c.h.store.case_id().to_owned();
    let mut prior = c.h.prior.clone();
    prior.genesis = false;
    prior.version = Some(1);
    prior.candidate_id = Some("fx:candidate:other".into());
    prior.candidate_digest = Some(format!("sha256:{}", "0".repeat(64)));
    let thread = std::thread::spawn(move || {
        let store = FixtureTransitionStoreV1::open(&case).unwrap();
        let connection = rusqlite::Connection::open(store.path()).unwrap();
        connection
            .execute(
                "UPDATE pointer SET value=?1 WHERE singleton=1",
                [serde_json::to_vec(&prior).unwrap()],
            )
            .unwrap();
    });
    thread.join().unwrap();
    assert_eq!(
        c.execute().unwrap_err(),
        F07Error::BlockedCanonicalStateChanged
    );
}
#[test]
fn a07_23_persisted_malformed_eligibility_blocks_without_transition() {
    let mut c = Case::new("23");
    rusqlite::Connection::open(c.store.path())
        .unwrap()
        .execute("UPDATE basis SET eligibility=?1", [b"{malformed".to_vec()])
        .unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_24_persisted_eligibility_digest_corruption_blocks() {
    let mut c = Case::new("24");
    let mut value: serde_json::Value =
        serde_json::from_slice(c.eligibility.canonical_bytes()).unwrap();
    value["body_digest"] = serde_json::Value::String(format!("sha256:{}", "0".repeat(64)));
    rusqlite::Connection::open(c.store.path())
        .unwrap()
        .execute(
            "UPDATE basis SET eligibility=?1",
            [serde_json::to_vec(&value).unwrap()],
        )
        .unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_25_persisted_snapshot_corruption_blocks() {
    let mut c = Case::new("25");
    rusqlite::Connection::open(c.store.path())
        .unwrap()
        .execute("UPDATE basis SET snapshot=?1", [b"{}".to_vec()])
        .unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_26_persisted_import_integrity_digest_corruption_blocks() {
    let mut c = Case::new("26");
    rusqlite::Connection::open(c.store.path())
        .unwrap()
        .execute("UPDATE basis SET digest=?1", ["sha256:corrupt"])
        .unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_27_changed_request_eligibility_digest_never_authorizes() {
    let mut c = Case::new("27");
    let mut request = c.request.clone();
    request.eligibility_digest = format!("sha256:{}", "0".repeat(64));
    assert!(c.run(&request, 11, FailurePointV1::None).is_err());
}
#[test]
fn a07_28_different_basis_identity_never_authorizes() {
    let mut c = Case::new("28");
    let mut request = c.request.clone();
    request.eligibility_id = "fx:eligibility:other".into();
    assert!(c.run(&request, 11, FailurePointV1::None).is_err());
}
#[test]
fn a07_29_missing_current_pointer_blocks() {
    let mut c = Case::new("29");
    let connection = rusqlite::Connection::open(c.store.path()).unwrap();
    connection.execute("DELETE FROM pointer", []).unwrap();
    let before = database_rows(&connection);
    assert!(
        execute_fixture_transition_v1(&mut c.store, &c.request, 11, FailurePointV1::None).is_err()
    );
    assert_eq!(before, database_rows(&connection));
}
#[test]
fn a07_30_consumed_without_receipt_is_integrity_block_not_replay() {
    let mut c = Case::new("30");
    c.execute().unwrap();
    let connection = rusqlite::Connection::open(c.store.path()).unwrap();
    connection.execute("DELETE FROM receipts", []).unwrap();
    let before = database_rows(&connection);
    assert_eq!(
        execute_fixture_transition_v1(&mut c.store, &c.request, 11, FailurePointV1::None)
            .unwrap_err(),
        F07Error::BlockedIntegrity
    );
    assert_eq!(before, database_rows(&connection));
}
#[test]
fn a07_31_corrupt_receipt_is_not_idempotent_success() {
    let mut c = Case::new("31");
    c.execute().unwrap();
    let connection = rusqlite::Connection::open(c.store.path()).unwrap();
    connection
        .execute("UPDATE receipts SET receipt=?1", [b"{}".to_vec()])
        .unwrap();
    let before = database_rows(&connection);
    assert_eq!(
        execute_fixture_transition_v1(&mut c.store, &c.request, 11, FailurePointV1::None)
            .unwrap_err(),
        F07Error::BlockedIntegrity
    );
    assert_eq!(before, database_rows(&connection));
}
fn database_rows(connection: &rusqlite::Connection) -> Vec<(String, Vec<String>)> {
    ["basis", "dependencies", "pointer", "consumed", "receipts"].into_iter().map(|table| {
        let columns = match table {
            "basis" => "quote(eligibility_id)||'|'||quote(eligibility)||'|'||quote(snapshot)||'|'||quote(digest)",
            "dependencies" => "quote(name)||'|'||quote(value)",
            "pointer" => "quote(singleton)||'|'||quote(value)",
            "consumed" => "quote(eligibility_id)||'|'||quote(transition_id)",
            "receipts" => "quote(transition_id)||'|'||quote(eligibility_id)||'|'||quote(receipt)",
            _ => unreachable!()
        };
        let mut statement = connection.prepare(&format!("SELECT {columns} FROM {table} ORDER BY 1")).unwrap();
        let rows = statement.query_map([], |r| r.get::<_,String>(0)).unwrap().collect::<Result<Vec<_>,_>>().unwrap();
        (table.into(), rows)
    }).collect()
}
#[test]
fn a07_32_precommit_failure_survives_connection_restart() {
    let mut c = Case::new("32");
    let initial = c.state();
    c.run(&c.request.clone(), 11, FailurePointV1::AfterReceipt)
        .unwrap_err();
    c.store = FixtureTransitionStoreV1::open(c.h.store.case_id()).unwrap();
    assert_eq!(initial, c.state());
    assert!(!c.execute().unwrap().replayed);
}
#[test]
fn a07_33_genuine_basis_import_rejects_changed_candidate_bytes() {
    let h = Harness::new("33");
    let v = packet(&h.verification, VERIFICATION_DOMAIN, "verification");
    let a = packet(&h.approval, APPROVAL_DOMAIN, "approval");
    let eligibility = evaluate_fixture_eligibility_v1(h.input(&v, &a)).unwrap();
    fs::write(&h.candidate_path, b"corrupt candidate").unwrap();
    assert_eq!(
        FixtureDependencySnapshotV1::capture(&eligibility, h.input(&v, &a)).unwrap_err(),
        F07Error::BlockedPromotionEligibilityStale
    );
}
#[test]
fn a07_34_genuine_basis_import_rejects_invalidated_evidence() {
    let h = Harness::new("34");
    let v = packet(&h.verification, VERIFICATION_DOMAIN, "verification");
    let a = packet(&h.approval, APPROVAL_DOMAIN, "approval");
    let eligibility = evaluate_fixture_eligibility_v1(h.input(&v, &a)).unwrap();
    h.invalidate();
    assert_eq!(
        FixtureDependencySnapshotV1::capture(&eligibility, h.input(&v, &a)).unwrap_err(),
        F07Error::BlockedPromotionEligibilityStale
    );
}
#[test]
fn a07_35_create_cannot_overwrite_existing_store_or_success() {
    let mut c = Case::new("35");
    c.execute().unwrap();
    let before = c.state();
    let v = packet(&c.h.verification, VERIFICATION_DOMAIN, "verification");
    let a = packet(&c.h.approval, APPROVAL_DOMAIN, "approval");
    let snapshot = FixtureDependencySnapshotV1::capture(&c.eligibility, c.h.input(&v, &a)).unwrap();
    assert!(
        FixtureTransitionStoreV1::create(c.h.store.case_id(), &c.eligibility, &snapshot).is_err()
    );
    assert_eq!(before, c.state());
}
#[test]
fn a07_36_uniqueness_constraints_reject_second_consumption_and_receipt() {
    let mut c = Case::new("36");
    c.execute().unwrap();
    let connection = rusqlite::Connection::open(c.store.path()).unwrap();
    let before = database_rows(&connection);
    assert!(
        connection
            .execute(
                "INSERT INTO consumed(eligibility_id,transition_id) VALUES(?1,?2)",
                rusqlite::params![c.eligibility.record_id(), "fx:transition:second"]
            )
            .is_err()
    );
    assert!(connection.execute("INSERT INTO receipts(transition_id,eligibility_id,receipt) SELECT 'fx:transition:second',eligibility_id,receipt FROM receipts",[]).is_err());
    assert_eq!(before, database_rows(&connection));
}
#[test]
fn a07_37_distinct_authorization_issuer_expiration_blocks_at_t2() {
    let h = Harness::with_options("37", false, Some(15));
    let mut c = Case::from_harness(h);
    assert_eq!(
        c.run(&c.request.clone(), 20, FailurePointV1::None)
            .unwrap_err(),
        F07Error::BlockedPromotionEligibilityStale
    );
}
#[test]
fn a07_38_no_f05_invocation_or_upstream_repair_surface() {
    for source in [
        include_str!("../src/transition.rs"),
        include_str!("../src/test_store.rs"),
    ] {
        for forbidden in [
            "crate::broker",
            "crate::capability",
            "execute_fixture_capability",
            "append_fixture_event",
            "apply_fixture_event",
            "std::process",
            "reqwest",
            "Command::",
        ] {
            assert!(
                !source.contains(forbidden),
                "forbidden production invocation: {forbidden}"
            );
        }
    }
    let mut c = Case::new("38");
    c.execute().unwrap();
    let name = c
        .store
        .dependency_names()
        .unwrap()
        .into_iter()
        .next()
        .unwrap();
    c.store.set_dependency(&name, b"INVALID").unwrap();
    // An exact successful operation may only return its already durable receipt.
    let before = c.state();
    let replay = c.execute().unwrap();
    assert!(replay.replayed);
    assert_eq!(before, c.state());
}
#[test]
fn a07_39_wrong_basis_database_key_does_not_manufacture_consumption() {
    let mut c = Case::new("39");
    let connection = rusqlite::Connection::open(c.store.path()).unwrap();
    connection
        .execute(
            "UPDATE basis SET eligibility_id='fx:eligibility:another'",
            [],
        )
        .unwrap();
    let mut request = c.request.clone();
    request.eligibility_id = "fx:eligibility:another".into();
    assert_eq!(
        c.run(&request, 11, FailurePointV1::None).unwrap_err(),
        F07Error::BlockedIntegrity
    );
}
#[test]
fn a07_40_pointer_restoring_trigger_blocks_before_any_write() {
    let mut c = Case::new("40");
    rusqlite::Connection::open(c.store.path()).unwrap().execute_batch(
        "CREATE TRIGGER restore_pointer AFTER UPDATE ON pointer BEGIN UPDATE pointer SET value=OLD.value WHERE singleton=1; END;"
    ).unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_41_dependency_mutating_trigger_blocks_before_any_write() {
    let mut c = Case::new("41");
    rusqlite::Connection::open(c.store.path()).unwrap().execute_batch(
        "CREATE TRIGGER stale_dependency AFTER UPDATE ON pointer BEGIN UPDATE dependencies SET value=X'00' WHERE name='approval'; END;"
    ).unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_42_extra_view_blocks_closed_schema() {
    let mut c = Case::new("42");
    rusqlite::Connection::open(c.store.path())
        .unwrap()
        .execute_batch("CREATE VIEW unexpected AS SELECT value FROM pointer;")
        .unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_43_removed_uniqueness_constraint_blocks_closed_schema() {
    let mut c = Case::new("43");
    rusqlite::Connection::open(c.store.path()).unwrap().execute_batch(
        "DROP TABLE receipts; CREATE TABLE receipts(transition_id TEXT,eligibility_id TEXT,receipt BLOB);"
    ).unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_44_extra_table_blocks_closed_schema() {
    let mut c = Case::new("44");
    rusqlite::Connection::open(c.store.path())
        .unwrap()
        .execute_batch("CREATE TABLE operational_pointer(value BLOB);")
        .unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
#[test]
fn a07_45_hard_linked_database_cannot_escape_fixture_identity() {
    let c = Case::new("45");
    let alias = c.store.path().parent().unwrap().join("alias.sqlite");
    fs::hard_link(c.store.path(), &alias).unwrap();
    assert!(FixtureTransitionStoreV1::open(c.h.store.case_id()).is_err());
    fs::remove_file(alias).unwrap();
    let reopened = FixtureTransitionStoreV1::open(c.h.store.case_id()).unwrap();
    assert_eq!(reopened.state().unwrap().receipts.len(), 0);
}
#[test]
fn a07_46_concurrent_observer_never_reads_torn_pointer_receipt_state() {
    let c = Case::new("46");
    let gate = Arc::new(Barrier::new(2));
    let done = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let writer_gate = gate.clone();
    let writer_done = done.clone();
    let case = c.h.store.case_id().to_owned();
    let request = c.request.clone();
    let writer = std::thread::spawn(move || {
        let mut store = FixtureTransitionStoreV1::open(&case).unwrap();
        writer_gate.wait();
        let result =
            execute_fixture_transition_v1(&mut store, &request, 11, FailurePointV1::None).unwrap();
        writer_done.store(true, Ordering::Release);
        result
    });
    gate.wait();
    let mut observations = Vec::new();
    loop {
        let state = c.store.state().unwrap();
        match state.pointer.version {
            Some(0) => {
                assert!(state.receipts.is_empty());
                assert!(state.consumed.is_empty());
            }
            Some(1) => {
                assert_eq!(state.receipts.len(), 1);
                assert_eq!(state.consumed.len(), 1);
            }
            version => panic!("unexpected pointer version {version:?}"),
        }
        observations.push(state);
        if done.load(Ordering::Acquire) {
            break;
        }
    }
    assert!(!writer.join().unwrap().replayed);
    let path = PathBuf::from(TASK).join("f07-evidence/races");
    fs::create_dir_all(&path).unwrap();
    fs::write(
        path.join(format!("{}-observer.json", c.h.store.case_id())),
        serde_json::to_vec(&serde_json::json!({
            "states":observations,"atomic_observer":true,"after":c.state()
        }))
        .unwrap(),
    )
    .unwrap();
}
#[test]
fn a07_47_extra_index_blocks_closed_schema() {
    let mut c = Case::new("47");
    rusqlite::Connection::open(c.store.path())
        .unwrap()
        .execute_batch("CREATE INDEX unexpected ON dependencies(value);")
        .unwrap();
    assert_eq!(c.execute().unwrap_err(), F07Error::BlockedIntegrity);
}
