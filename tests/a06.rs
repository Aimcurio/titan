//! A06 setup creates synthetic records. Each K5 call is separately zero-effect inventoried.
use serde::Serialize;
use std::{
    cell::Cell,
    fs,
    path::{Path, PathBuf},
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
    verification::*,
};
const PROJECT: &str = "fx:project:lab";
const EXECUTOR: &str = "fx:actor:executor";
const VERIFIER: &str = "fx:actor:verifier";
const APPROVER: &str = "fx:actor:approver";
const TASK: &str = r"C:\Users\15103\Documents\Codex\2026-09-29\files-pasted-by-the-user-titan\work";
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
    calls: Cell<u32>,
}
impl Harness {
    fn new(slug: &str) -> Self {
        Self::with_alias(slug, false)
    }
    fn with_alias(slug: &str, alias: bool) -> Self {
        let case = format!("a06-{slug}-{}", std::process::id());
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
        let mut actors = [
            actor_record(EXECUTOR, vec![Role::Executor, Role::Verifier]),
            actor_record(VERIFIER, vec![Role::Verifier]),
            actor_record(APPROVER, vec![Role::DecisionAuthority]),
        ];
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
        let seed = FixtureAuthoritySeedV1 {
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
            let decision = record(
                RecordPayload::AuthorityRecord(AuthorityRecord {
                    authority_id: format!("fx:authority:{case}-{suffix}"),
                    class: AuthorityClass::Decision,
                    issuer_actor_ref: APPROVER.into(),
                    exercised_role: Role::DecisionAuthority,
                    effective_at_ms: 2,
                    target_binding_ref: Some(PROJECT.into()),
                    contract_digest: Some(contract.record().integrity.clone()),
                    claim_atoms: vec![atom(&scope, ResourceMatch::Exact, action, provision)],
                    override_edges: vec![],
                    evidence_refs: vec![],
                }),
                APPROVER,
            );
            let event = FixtureEventV1 {
                event_id: format!("fx:event:{case}-{suffix}"),
                kind: FixtureEventKind::ClaimAcceptance,
                record_id: decision.record().record_id.clone(),
                record_digest: decision.record().integrity.clone(),
                issuer_actor_id: APPROVER.into(),
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
            pointer_id: "fx:canonical:lab".into(),
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
            calls: Cell::new(0),
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
    fn snapshot(&self) -> Vec<InventoryRow> {
        let mut rows = Vec::new();
        inventory(self.candidate_path.parent().unwrap(), &mut rows);
        inventory(&self.store.case_path(), &mut rows);
        // Cargo runs A01-A06 test binaries sequentially. A06 does not invoke
        // either F05 handler; inventory the entire F05 domain on every call.
        inventory(&PathBuf::from(TASK).join("f05-fixtures"), &mut rows);
        // Only an absence sentinel, not a selected/created F07 canonical store.
        inventory(&PathBuf::from(TASK).join("f07-fixtures"), &mut rows);
        rows
    }
    fn call(
        &self,
        reuse: Option<&FixturePromotionEligibilityV1>,
        v: Option<&[u8]>,
        a: Option<&[u8]>,
    ) -> F06Result<FixturePromotionEligibilityV1> {
        let default_v = packet(&self.verification, VERIFICATION_DOMAIN, "verification");
        let default_a = packet(&self.approval, APPROVAL_DOMAIN, "approval");
        let before = self.snapshot();
        let result = if let Some(old) = reuse {
            validate_fixture_eligibility_reuse_v1(
                old,
                self.input(v.unwrap_or(&default_v), a.unwrap_or(&default_a)),
            )
            .map(|()| old.clone())
        } else {
            evaluate_fixture_eligibility_v1(
                self.input(v.unwrap_or(&default_v), a.unwrap_or(&default_a)),
            )
        };
        let after = self.snapshot();
        let call = self.calls.get() + 1;
        self.calls.set(call);
        let path = PathBuf::from(TASK)
            .join("f06-evidence/zero-effects")
            .join(self.store.case_id());
        fs::create_dir_all(&path).unwrap();
        let data = serde_json::json!({"case":self.store.case_id(),"call":call,"setup_effects":"outside evaluation: F06 candidate + two F04 raw proofs/observations; external actors/decisions/approvals in memory",
            "before":before,"after":after,"inventory_equal":before==after,"effects":[],"decision":match &result{Ok(_)=>"ELIGIBLE".into(),Err(e)=>format!("{e:?}")},
            "eligibility":result.as_ref().ok(),"eligibility_canonical_bytes":result.as_ref().ok().map(|r|r.canonical_bytes()),
            "verification_canonical_bytes":v.unwrap_or(&default_v),"approval_canonical_bytes":a.unwrap_or(&default_a),
            "verification_record":serde_json::from_slice::<serde_json::Value>(v.unwrap_or(&default_v)).ok(),"approval_record":serde_json::from_slice::<serde_json::Value>(a.unwrap_or(&default_a)).ok()});
        fs::write(
            path.join(format!("{call:03}.json")),
            serde_json::to_vec(&data).unwrap(),
        )
        .unwrap();
        assert_eq!(before, after, "K5 product mutated fixture state");
        result
    }
    fn eval(&self) -> F06Result<FixturePromotionEligibilityV1> {
        self.call(None, None, None)
    }
    fn rejects(&self) {
        assert!(self.eval().is_err());
    }
    fn self_verify(&mut self) {
        self.verification.verifier_actor_id = EXECUTOR.into();
        self.verification.producer_actor_id = EXECUTOR.into();
        let a = titan_kernel::validate_bytes(&self.seed.actor_records[0]).unwrap();
        self.verification.verifier_binding_digest = a.record().integrity.clone();
        self.verification.independence = IndependenceV1::SelfVerification;
        self.assessment();
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

#[test]
fn a06_01_complete_independent_basis_is_eligible() {
    let h = Harness::new("01");
    let r = h.eval().unwrap();
    assert!(r.record_id().starts_with("fx:eligibility:"));
    let b: serde_json::Value = serde_json::from_slice(r.canonical_bytes()).unwrap();
    assert_eq!(
        b["body"]["candidate"]["content_digest"],
        h.candidate.content_digest
    );
    assert_eq!(
        b["body"]["verification"]["body"]["verifier_actor_id"],
        VERIFIER
    );
    assert_eq!(b["body"]["approval"]["body"]["approver_actor_id"], APPROVER);
}
#[test]
fn a06_02_candidate_byte_drift() {
    let h = Harness::new("02");
    fs::write(&h.candidate_path, b"changed").unwrap();
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedIntegrity);
}
#[test]
fn a06_03_candidate_revision_drift() {
    let mut h = Harness::new("03");
    h.candidate.revision = "r2".into();
    h.rejects();
}
#[test]
fn a06_04_wrong_project_subject_scope() {
    for i in 0..3 {
        let mut h = Harness::new(&format!("04-{i}"));
        match i {
            0 => h.candidate.project_id = "fx:project:other".into(),
            1 => h.candidate.subject_id = "fx:target:other".into(),
            _ => h.candidate.scope = "fixture://resource/lab/other".into(),
        };
        h.rejects();
    }
}
#[test]
fn a06_05_wrong_contract_id_digest() {
    for i in 0..2 {
        let mut h = Harness::new(&format!("05-{i}"));
        if i == 0 {
            h.candidate.contract_id = "fx:contract:other".into()
        } else {
            h.candidate.contract_digest = hash(b"", b"changed")
        };
        h.rejects();
    }
}
#[test]
fn a06_06_wrong_run() {
    let mut h = Harness::new("06");
    h.candidate.run_id = "fx:run:other".into();
    h.rejects();
}
#[test]
fn a06_07_membership_add_remove_substitute() {
    for i in 0..3 {
        let mut h = Harness::new(&format!("07-{i}"));
        match i {
            0 => {
                h.set.members.push(h.set.members[0].clone());
            }
            1 => {
                h.set.members.pop();
            }
            _ => h.set.members[0].evidence_id = "fx:evidence:substitution".into(),
        };
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedEvidenceInvalid);
    }
}
#[test]
fn a06_08_member_and_content_digest_drift() {
    for i in 0..2 {
        let mut h = Harness::new(&format!("08-{i}"));
        if i == 0 {
            h.set.members[0].record_digest = hash(b"", b"changed")
        } else {
            h.set.members[0].content_digest = hash(b"", b"changed")
        };
        h.rejects();
    }
}
#[test]
fn a06_09_invalidated_evidence() {
    let h = Harness::new("09");
    h.invalidate();
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedEvidenceInvalid);
}
#[test]
fn a06_10_corrupt_missing_evidence() {
    for i in 0..2 {
        let h = Harness::new(&format!("10-{i}"));
        let p = h.store.raw_path("proof-0").unwrap();
        if i == 0 {
            fs::write(p, b"corrupt").unwrap()
        } else {
            fs::remove_file(p).unwrap()
        };
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedEvidenceInvalid);
    }
}
#[test]
fn a06_11_verification_fail() {
    let mut h = Harness::new("11");
    h.verification.outcome = VerificationOutcomeV1::Fail;
    h.assessment();
    assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleVerification);
}
#[test]
fn a06_12_blocked_unknown_not_pass() {
    for (i, outcome) in [
        VerificationOutcomeV1::Blocked,
        VerificationOutcomeV1::Unknown,
    ]
    .into_iter()
    .enumerate()
    {
        let mut h = Harness::new(&format!("12-{i}"));
        h.verification.outcome = outcome;
        h.assessment();
        assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleVerification);
    }
}
#[test]
fn a06_13_missing_verifier_identity() {
    let mut h = Harness::new("13");
    h.verification.verifier_actor_id = "fx:actor:missing".into();
    h.verification.producer_actor_id = "fx:actor:missing".into();
    h.assessment();
    h.rejects();
}
#[test]
fn a06_14_wrong_verifier_role() {
    let mut h = Harness::new("14");
    h.verification.verifier_actor_id = APPROVER.into();
    h.verification.producer_actor_id = APPROVER.into();
    h.verification.verifier_binding_digest = h.approval.approver_binding_digest.clone();
    h.assessment();
    h.rejects();
}
#[test]
fn a06_15_high_impact_self_blocks() {
    let mut h = Harness::new("15");
    h.self_verify();
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedIndependenceRequired);
}
#[test]
fn a06_16_same_actor_display_name_attack() {
    let mut h = Harness::new("16");
    h.self_verify();
    for display in ["Astra independent verifier", "different session Bubba"] {
        h.verification.display_name = display.into();
        h.verification.independence = IndependenceV1::Independent;
        h.assessment();
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedIndependenceRequired);
    }
}
#[test]
fn a06_17_high_impact_exact_independent_actor() {
    let h = Harness::new("17");
    assert_ne!(
        h.candidate.executor_actor_id,
        h.verification.verifier_actor_id
    );
    h.eval().unwrap();
}
#[test]
fn a06_18_low_impact_self_only_explicit() {
    let mut h = Harness::new("18");
    h.self_verify();
    h.consequence = ConsequenceV1::LowImpactFixture;
    h.verification.consequence = h.consequence;
    h.approval.consequence = h.consequence;
    for entry in [None, Some(SelfVerificationV1::IndependentOnly)] {
        h.policy.low_impact = entry;
        h.verification.policy_digest = h.policy.digest().unwrap();
        h.approval.policy_digest = h.policy.digest().unwrap();
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedIndependenceRequired);
    }
    h.policy.low_impact = Some(SelfVerificationV1::SelfVerificationAllowed);
    h.verification.policy_digest = h.policy.digest().unwrap();
    h.approval.policy_digest = h.policy.digest().unwrap();
    h.eval().unwrap();
    h.missing_approval = true;
    assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleApproval);
}
#[test]
fn a06_19_missing_approval() {
    let mut h = Harness::new("19");
    h.missing_approval = true;
    assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleApproval);
}
#[test]
fn a06_20_pass_cannot_substitute_approval() {
    let h = Harness::new("20");
    let v = packet(&h.verification, VERIFICATION_DOMAIN, "verification");
    assert_eq!(
        h.call(None, None, Some(&v)).unwrap_err(),
        F06Error::BlockedIntegrity
    );
}
fn surface_guard() {
    let source = format!(
        "{}\n{}",
        include_str!("../src/eligibility.rs"),
        include_str!("../src/verification.rs")
    );
    for forbidden in [
        "pub fn create_approval",
        "pub fn make_approval",
        "pub fn approve(",
        "append_fixture_event(",
        "apply_fixture_event(",
        "dispatch_fixture_operation(",
        "read_fixture_marker(",
        "fs::write(",
        "create_dir(",
        "OpenOptions",
        "std::process",
        "Command::",
        "TcpStream",
        "reqwest",
        "std::env",
        "std::net",
    ] {
        assert!(
            !source.contains(forbidden),
            "forbidden product surface: {forbidden}"
        );
    }
}
#[test]
fn a06_21_no_approval_creation_path() {
    surface_guard();
    let mut h = Harness::new("21");
    h.missing_approval = true;
    h.rejects();
}
#[test]
fn a06_22_deny() {
    let mut h = Harness::new("22");
    h.approval.decision = ApprovalDecisionV1::Deny;
    assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleApproval);
}
#[test]
fn a06_23_wrong_approver_actor_role() {
    for i in 0..3 {
        let mut h = Harness::new(&format!("23-{i}"));
        match i {
            0 => h.approval.approver_actor_id = "fx:actor:missing".into(),
            1 => h.approval.approver_actor_id = VERIFIER.into(),
            _ => h.approval.required_role = Role::Verifier,
        };
        h.rejects();
    }
}
#[test]
fn a06_24_wrong_approval_project_candidate_subject_scope() {
    for i in 0..4 {
        let mut h = Harness::new(&format!("24-{i}"));
        match i {
            0 => h.approval.candidate.project_id = "fx:project:other".into(),
            1 => h.approval.candidate.candidate_id = "fx:candidate:other".into(),
            2 => h.approval.candidate.subject_id = "fx:target:other".into(),
            _ => h.approval.candidate.scope = "fixture://resource/lab/other".into(),
        };
        h.rejects();
    }
}
#[test]
fn a06_25_wrong_approval_contract_authorization() {
    for i in 0..4 {
        let mut h = Harness::new(&format!("25-{i}"));
        match i {
            0 => h.approval.candidate.contract_id = "fx:contract:other".into(),
            1 => h.approval.candidate.contract_digest = hash(b"", b"other"),
            2 => h.approval.authorization_id = "fx:authority:other".into(),
            _ => h.approval.authorization_digest = hash(b"", b"other"),
        };
        h.rejects();
    }
}
#[test]
fn a06_26_expired_not_yet_valid_approval() {
    for i in 0..2 {
        let mut h = Harness::new(&format!("26-{i}"));
        if i == 0 {
            h.approval.valid_until_epoch = 10
        } else {
            h.approval.valid_from_epoch = 11
        };
        assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleApproval);
    }
}
#[test]
fn a06_27_revoked_superseded_approval() {
    for (i, status) in [
        EvidenceStatus::Invalidated,
        EvidenceStatus::Superseded,
        EvidenceStatus::Unknown,
    ]
    .into_iter()
    .enumerate()
    {
        let mut h = Harness::new(&format!("27-{i}"));
        h.approval.status = status;
        assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleApproval);
    }
}
#[test]
fn a06_28_policy_version_drift() {
    for i in 0..3 {
        let mut h = Harness::new(&format!("28-{i}"));
        match i {
            0 => h.policy.version = 2,
            1 => h.verification.policy_version = 2,
            _ => h.approval.policy_version = 2,
        };
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedPolicyStale);
    }
}
#[test]
fn a06_29_rule_version_drift() {
    for i in 0..3 {
        let mut h = Harness::new(&format!("29-{i}"));
        match i {
            0 => h.rule = 2,
            1 => h.verification.rule_version = 2,
            _ => h.approval.rule_version = 2,
        };
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedPolicyStale);
    }
}
#[test]
fn a06_30_authority_state_drift() {
    for i in 0..4 {
        let mut h = Harness::new(&format!("30-{i}"));
        match i {
            0 => h.expected_state = "fx:authority-state:other".into(),
            1 => h.verification.authority_state_id = "fx:authority-state:other".into(),
            2 => h.approval.authority_state_id = "fx:authority-state:other".into(),
            _ => h.approval.status_state_ref = "fx:authority-state:other".into(),
        };
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedAuthorityStale);
    }
}
#[test]
fn a06_31_missing_prior_identity_version() {
    for i in 0..3 {
        let mut h = Harness::new(&format!("31-{i}"));
        match i {
            0 => h.missing_prior = true,
            1 => h.prior.version = None,
            _ => h.prior.pointer_id = String::new(),
        };
        assert_eq!(h.eval().unwrap_err(), F06Error::BlockedIncompleteBasis);
    }
}
#[test]
fn a06_32_changed_prior_invalidates_old_basis() {
    let mut h = Harness::new("32");
    let old = h.eval().unwrap();
    h.prior.pointer_id = "fx:canonical:other".into();
    h.rejects();
    h.verification.expected_prior = h.prior.clone();
    h.approval.expected_prior = h.prior.clone();
    assert!(h.call(Some(&old), None, None).is_err());
    let new = h.eval().unwrap();
    assert_ne!(old.record_id(), new.record_id());
}
#[test]
fn a06_33_identical_basis_identical_bytes_id() {
    let h = Harness::new("33");
    let a = h.eval().unwrap();
    let b = h.eval().unwrap();
    assert_eq!(a.canonical_bytes(), b.canonical_bytes());
    assert_eq!(a.record_id(), b.record_id());
    h.call(Some(&a), None, None).unwrap();
}
#[test]
fn a06_34_material_dependency_change_prevents_reuse() {
    for i in 0..10 {
        let mut h = Harness::new(&format!("34-{i}"));
        let old = h.eval().unwrap();
        match i {
            0 => h.epoch += 1,
            1 => h.verification.display_name = "changed input".into(),
            2 => h.candidate.revision = "r2".into(),
            3 => h.set.members[0].method = "OTHER".into(),
            4 => h.approval.valid_until_epoch += 1,
            5 => h.prior.version = None,
            6 => h.rule = 2,
            7 => h.policy.version = 2,
            8 => h.approval.decision = ApprovalDecisionV1::Deny,
            _ => h.invalidate(),
        };
        assert!(h.call(Some(&old), None, None).is_err());
    }
}
#[test]
fn a06_35_eligibility_inert_fixture_no_live_handle() {
    let h = Harness::new("35");
    let r = h.eval().unwrap();
    let b: serde_json::Value = serde_json::from_slice(r.canonical_bytes()).unwrap();
    assert_eq!(b["body"]["namespace"], "FIXTURE");
    assert_eq!(b["body"]["expected_prior"]["version"], 0);
    for key in [
        "promotion_method",
        "credential",
        "executor_handle",
        "canonical_path",
        "network_endpoint",
        "retry_instruction",
    ] {
        assert!(b["body"].get(key).is_none());
    }
}
#[test]
fn a06_36_candidate_claims_do_not_authorize() {
    let mut h = Harness::new("36");
    assert!(
        String::from_utf8(fs::read(&h.candidate_path).unwrap())
            .unwrap()
            .contains("approved")
    );
    h.missing_approval = true;
    assert_eq!(h.eval().unwrap_err(), F06Error::IneligibleApproval);
}
#[test]
fn a06_37_no_f05_invocation_positive_negative() {
    surface_guard();
    let mut h = Harness::new("37");
    h.eval().unwrap();
    h.missing_approval = true;
    h.rejects();
}
#[test]
fn a06_38_no_f05_target_changes() {
    let h = Harness::new("38");
    h.eval().unwrap();
    assert!(
        h.snapshot()
            .iter()
            .any(|r| r.path.contains("a05-01-27240") && r.kind == "FILE")
    );
}
#[test]
fn a06_39_no_f04_history_append_repair() {
    let h = Harness::new("39");
    let before = replay_fixture_history(&h.store)
        .unwrap()
        .head_id()
        .to_owned();
    h.eval().unwrap();
    assert_eq!(before, replay_fixture_history(&h.store).unwrap().head_id());
}
#[test]
fn a06_40_no_canonical_pointer_created_or_selected() {
    let h = Harness::new("40");
    assert!(!PathBuf::from(TASK).join("f07-fixtures").exists());
    h.eval().unwrap();
    assert!(!PathBuf::from(TASK).join("f07-fixtures").exists());
}
#[test]
fn a06_41_no_network_credentials_process_surface() {
    surface_guard();
    let h = Harness::new("41");
    h.eval().unwrap();
}
#[test]
fn a06_guard_noncanonical_integrity_and_extra_fields() {
    let h = Harness::new("guard-json");
    let mut v = packet(&h.verification, VERIFICATION_DOMAIN, "verification");
    v.push(b' ');
    assert_eq!(
        h.call(None, Some(&v), None).unwrap_err(),
        F06Error::BlockedIntegrity
    );
    let mut a: serde_json::Value =
        serde_json::from_slice(&packet(&h.approval, APPROVAL_DOMAIN, "approval")).unwrap();
    a["write_handle"] = true.into();
    assert_eq!(
        h.call(None, None, Some(&serde_json::to_vec(&a).unwrap()))
            .unwrap_err(),
        F06Error::BlockedIntegrity
    );
}
#[test]
fn a06_guard_verification_producer_method_gate() {
    for i in 0..3 {
        let mut h = Harness::new(&format!("guard-verifier-{i}"));
        match i {
            0 => h.verification.producer_actor_id = EXECUTOR.into(),
            1 => h.verification.method_version = 2,
            _ => {
                let r = titan_kernel::validate_bytes(&h.verification.assessment_bytes).unwrap();
                let mut p = r.record().payload.clone();
                if let RecordPayload::Assessment(a) = &mut p {
                    a.gate_result_refs = vec!["fx:gate:other".into()]
                };
                h.verification.assessment_bytes = record(p, VERIFIER).canonical_bytes().to_vec();
            }
        };
        h.rejects();
    }
}
#[test]
fn a06_guard_scope_authorization_not_just_record_text() {
    let mut h = Harness::new("guard-scope");
    h.approval.governing_decision_bytes = h.authorization.canonical_bytes().to_vec();
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedAuthorityStale);
}
#[test]
fn a06_guard_replay_keeps_invalidation() {
    let h = Harness::new("guard-replay");
    h.invalidate();
    let store = FixtureStoreV1::open(h.store.case_id(), &h.seed).unwrap();
    assert!(
        !replay_fixture_history(&store)
            .unwrap()
            .current_evidence(&h.set.members[0].evidence_id)
    );
    h.rejects();
}
#[test]
fn a06_guard_evidence_membership_order_identity() {
    let h = Harness::new("guard-order");
    let mut ids = h
        .set
        .members
        .iter()
        .map(|m| m.evidence_id.clone())
        .collect::<Vec<_>>();
    ids.reverse();
    assert_eq!(
        bind_fixture_evidence_set(&h.store, &h.candidate, &h.contract, &ids).unwrap(),
        h.set
    );
    h.eval().unwrap();
}

// Setup uses qualified F02 events; K5 merely checks the resulting projection.
fn supersede_approval_scope(
    h: &mut Harness,
    provision: Provision,
    suffix: &str,
) -> (ValidatedRecord, String) {
    let old = titan_kernel::validate_bytes(&h.approval.governing_decision_bytes).unwrap();
    let predecessor = h
        .state
        .claims
        .values()
        .find(|c| c.source_record_id == old.record().record_id)
        .unwrap()
        .id
        .clone();
    let successor_atom = atom(
        &h.candidate.scope,
        ResourceMatch::Exact,
        "APPROVE",
        provision,
    );
    let id = format!("fx:authority:{}-{suffix}", h.store.case_id());
    let successor_id =
        titan_kernel::authority::derive_claim_id(&id, &successor_atom, &h.seed.profile).unwrap();
    let record = record(
        RecordPayload::AuthorityRecord(AuthorityRecord {
            authority_id: id.clone(),
            class: AuthorityClass::Decision,
            issuer_actor_ref: APPROVER.into(),
            exercised_role: Role::DecisionAuthority,
            effective_at_ms: 3,
            target_binding_ref: Some(PROJECT.into()),
            contract_digest: Some(h.candidate.contract_digest.clone()),
            claim_atoms: vec![successor_atom.clone()],
            override_edges: vec![OverrideEdge {
                predecessor_claim_ref: predecessor,
                successor_claim_ref: successor_id.clone(),
                coverage_atoms: vec![successor_atom],
            }],
            evidence_refs: vec![],
        }),
        APPROVER,
    );
    let event = FixtureEventV1 {
        event_id: format!("fx:event:{}-{suffix}", h.store.case_id()),
        kind: FixtureEventKind::OverrideAcceptance,
        record_id: id,
        record_digest: record.record().integrity.clone(),
        issuer_actor_id: APPROVER.into(),
        expected_prior_state_id: h.state.state_id.clone(),
        target_claim_id: None,
        target_edge_id: None,
    };
    apply_fixture_event(&mut h.state, &h.seed, &record, &event).unwrap();
    h.expected_state = h.state.state_id.clone();
    h.verification.authority_state_id = h.state.state_id.clone();
    h.approval.authority_state_id = h.state.state_id.clone();
    h.approval.status_state_ref = h.state.state_id.clone();
    (record, successor_id)
}
#[test]
fn a06_guard_superseded_governor_cannot_support_approval() {
    let mut h = Harness::new("guard-supersede");
    let (denied, _) = supersede_approval_scope(&mut h, Provision::Forbid, "deny");
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedAuthorityStale);
    h.approval.governing_decision_bytes = denied.canonical_bytes().to_vec();
    let (new, _) = supersede_approval_scope(&mut h, Provision::Approve, "new-approval");
    h.approval.governing_decision_bytes = new.canonical_bytes().to_vec();
    h.eval().unwrap();
}
#[test]
fn a06_guard_revoked_governor_no_resurrection() {
    let mut h = Harness::new("guard-revoked");
    let (denied, _) = supersede_approval_scope(&mut h, Provision::Forbid, "deny");
    h.approval.governing_decision_bytes = denied.canonical_bytes().to_vec();
    let (new, claim) = supersede_approval_scope(&mut h, Provision::Approve, "new-approval");
    h.approval.governing_decision_bytes = new.canonical_bytes().to_vec();
    h.eval().unwrap();
    let r = record(
        RecordPayload::AuthorityRecord(AuthorityRecord {
            authority_id: format!("fx:authority:{}-revoke", h.store.case_id()),
            class: AuthorityClass::Revocation,
            issuer_actor_ref: APPROVER.into(),
            exercised_role: Role::DecisionAuthority,
            effective_at_ms: 4,
            target_binding_ref: Some(PROJECT.into()),
            contract_digest: Some(h.candidate.contract_digest.clone()),
            claim_atoms: vec![atom(
                &h.candidate.scope,
                ResourceMatch::Exact,
                "APPROVE",
                Provision::Revoke,
            )],
            override_edges: vec![],
            evidence_refs: vec![],
        }),
        APPROVER,
    );
    let event = FixtureEventV1 {
        event_id: format!("fx:event:{}-revoke", h.store.case_id()),
        kind: FixtureEventKind::SuccessorRevocation,
        record_id: r.record().record_id.clone(),
        record_digest: r.record().integrity.clone(),
        issuer_actor_id: APPROVER.into(),
        expected_prior_state_id: h.state.state_id.clone(),
        target_claim_id: Some(claim),
        target_edge_id: None,
    };
    apply_fixture_event(&mut h.state, &h.seed, &r, &event).unwrap();
    h.expected_state = h.state.state_id.clone();
    h.verification.authority_state_id = h.state.state_id.clone();
    h.approval.authority_state_id = h.state.state_id.clone();
    h.approval.status_state_ref = h.state.state_id.clone();
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedAuthorityStale);
}
#[test]
fn a06_guard_evidence_supersession_unusable_old_set() {
    let h = Harness::new("guard-evidence-super");
    let history = replay_fixture_history(&h.store).unwrap();
    append_fixture_event(
        &h.store,
        &h.candidate.run_id,
        history.head_id(),
        HistoryEvent::EvidenceSuperseded {
            old_id: h.set.members[0].evidence_id.clone(),
            new_id: h.set.members[1].evidence_id.clone(),
            prior_digest: h.set.members[0].record_digest.clone(),
            source_evidence_id: h.set.members[1].evidence_id.clone(),
            reason_code: "SUPERSEDED_BY_NEW_OBSERVATION".into(),
            actor_id: VERIFIER.into(),
            epoch: 10,
        },
    )
    .unwrap();
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedEvidenceInvalid);
}
#[test]
fn a06_guard_candidate_environment_and_receipt() {
    let mut h = Harness::new("guard-receipt");
    h.candidate.effect_receipt_id = Some("fx:history-entry:missing".into());
    h.rejects();
    h.candidate.effect_receipt_id = None;
    let p = h.candidate_path.with_extension("saved");
    fs::rename(&h.candidate_path, &p).unwrap();
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedEnvironment);
    fs::rename(p, &h.candidate_path).unwrap();
    h.eval().unwrap();
}

#[test]
fn a06_guard_actor_alias_cannot_fake_independence() {
    let h = Harness::with_alias("guard-actor-alias", true);
    assert_eq!(h.eval().unwrap_err(), F06Error::BlockedIndependenceRequired);
}
#[test]
fn a06_guard_candidate_executor_and_subject_revision_drift() {
    for i in 0..2 {
        let mut h = Harness::new(&format!("guard-candidate-{i}"));
        if i == 0 {
            h.candidate.executor_actor_id = VERIFIER.into()
        } else {
            h.candidate.subject_revision = "r2".into()
        };
        h.rejects();
    }
}
#[test]
fn a06_guard_approval_binding_and_verification_identity_integrity() {
    for i in 0..4 {
        let mut h = Harness::new(&format!("guard-binding-{i}"));
        match i {
            0 => h.approval.approver_binding_digest = hash(b"", b"drift"),
            1 => h.verification.verifier_binding_digest = hash(b"", b"drift"),
            2 => h.approval.candidate.revision = "r2".into(),
            _ => h.verification.authorization_digest = hash(b"", b"drift"),
        };
        h.rejects();
    }
}
