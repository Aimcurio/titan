use titan_kernel::{
    encode_fixture,
    outcome::{BlockedCode, FailCode, OutcomeVariant, PassCode, UnknownCode},
    records::{
        ActorBinding, ArtifactIdentity, Assessment, AssessmentDecision, AuthorityClass,
        AuthorityRecord, BindingState, Checkpoint, ClaimAtom, EligibilityOutcome, EvidenceRef,
        EvidenceStatus, ExecutionContract, Namespace, Outcome, ProjectBinding,
        PromotionEligibilityRecord, Provision, RecordEnvelope, RecordPayload, ResourceMatch, Role,
    },
    validate_bytes,
    validation::ValidationStage,
};

const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn claim() -> ClaimAtom {
    ClaimAtom {
        project_binding_ref: "fx:project:alpha".into(),
        resource_ref: "fixture://resource/alpha".into(),
        resource_match: ResourceMatch::Exact,
        action: "READ".into(),
        provision: Provision::Permit,
        effect: "OBSERVE".into(),
        lifecycle_contexts: vec!["READY".into()],
    }
}

fn sample_payloads() -> Vec<RecordPayload> {
    vec![
        RecordPayload::ProjectBinding(ProjectBinding {
            project_id: "fx:project:alpha".into(),
            canonical_root: "fixture://project/alpha".into(),
            repository_id: None,
            repository_url: None,
            authority_source_ref: "fx:authority:seed".into(),
            binding_revision: 1,
            state: BindingState::Proposed,
        }),
        RecordPayload::ActorBinding(ActorBinding {
            actor_id: "fx:actor:executor".into(),
            principal_ref: "fx:principal:synthetic".into(),
            auth_method_ref: "fx:method:fixture".into(),
            roles: vec![Role::Executor],
            issued_by_ref: "fx:actor:author".into(),
            valid_from_ms: 1,
            valid_until_ms: Some(2),
            revocation_ref: None,
        }),
        RecordPayload::AuthorityRecord(AuthorityRecord {
            authority_id: "fx:authority:seed".into(),
            class: AuthorityClass::Decision,
            issuer_actor_ref: "fx:actor:author".into(),
            exercised_role: Role::DecisionAuthority,
            effective_at_ms: 1,
            target_binding_ref: Some("fx:project:alpha".into()),
            contract_digest: None,
            claim_atoms: vec![claim()],
            override_edges: vec![],
            evidence_refs: vec![],
        }),
        RecordPayload::ExecutionContract(ExecutionContract {
            contract_id: "fx:contract:one".into(),
            contract_version: 1,
            mission: "fixture read".into(),
            project_binding_ref: "fx:project:alpha".into(),
            target_ref: "fx:target:alpha".into(),
            expected_target_state: "unborn".into(),
            actor_ref: "fx:actor:executor".into(),
            capability_code: "READ_ONLY".into(),
            allowed_operations: vec!["READ".into()],
            read_scopes: vec!["fixture://project/alpha".into()],
            allowed_mutations: vec![],
            prohibited_mutations: vec!["fixture://project/alpha".into()],
            precondition_refs: vec![],
            required_evidence_refs: vec!["fx:evidence:one".into()],
            verification_gate_refs: vec!["fx:gate:one".into()],
            stop_codes: vec!["UNAUTHORIZED".into()],
            escalation_ref: "fx:route:control-room".into(),
            expected_deliverables: vec!["fixture report".into()],
            requester_boundary: "fixture only".into(),
            network_allowed: false,
            secret_access_allowed: false,
            cross_surface_delivery_allowed: false,
        }),
        RecordPayload::EvidenceRef(EvidenceRef {
            evidence_id: "fx:evidence:one".into(),
            kind: "OBSERVATION".into(),
            locator: "fixture://evidence/one".into(),
            content_digest: ZERO_DIGEST.into(),
            producer_ref: "fx:actor:executor".into(),
            method: "fixture".into(),
            subject_ref: "fx:target:alpha".into(),
            subject_revision: "unborn".into(),
            observed_at_ms: 2,
            contract_ref: "fx:contract:one".into(),
            run_ref: "fx:run:one".into(),
            gate_ref: Some("fx:gate:one".into()),
            status: EvidenceStatus::Current,
        }),
        RecordPayload::Assessment(Assessment {
            assessment_id: "fx:assessment:one".into(),
            subject_ref: "fx:target:alpha".into(),
            gate_result_refs: vec!["fx:outcome:pass".into()],
            verifier_actor_ref: "fx:actor:verifier".into(),
            independence_claimed: true,
            evidence_refs: vec!["fx:evidence:one".into()],
            decision: AssessmentDecision::Pass,
            reason: "fixture observation".into(),
        }),
        RecordPayload::PromotionEligibilityRecord(PromotionEligibilityRecord {
            eligibility_id: "fx:eligibility:one".into(),
            candidate_ref: "fx:candidate:one".into(),
            candidate_revision: "r1".into(),
            expected_prior_canonical_ref: "fx:canonical:one".into(),
            expected_prior_canonical_version: "r0".into(),
            promotion_subject_ref: "fx:subject:one".into(),
            promotion_scope: "fixture scope".into(),
            contract_ref: "fx:contract:one".into(),
            contract_digest: ZERO_DIGEST.into(),
            authorization_ref: "fx:authority:seed".into(),
            policy_ref: "fx:policy:one".into(),
            policy_version: 1,
            assurance_rule_ref: "fx:rule:one".into(),
            assurance_rule_version: 1,
            eligibility_rule_version: 1,
            evidence_set_ref: "fx:evidence-set:one".into(),
            evidence_artifacts: vec![ArtifactIdentity {
                artifact_ref: "fx:artifact:one".into(),
                digest: ZERO_DIGEST.into(),
            }],
            verification_result_refs: vec!["fx:assessment:one".into()],
            approval_refs: vec!["fx:authority:approval".into()],
            authority_state_ref: "fx:authority-state:one".into(),
            evaluated_outcome: EligibilityOutcome::Eligible,
            input_refs: vec!["fx:evidence:one".into()],
        }),
        RecordPayload::Checkpoint(Checkpoint {
            checkpoint_id: "fx:checkpoint:one".into(),
            run_ref: "fx:run:one".into(),
            contract_digest: ZERO_DIGEST.into(),
            target_ref: "fx:target:alpha".into(),
            target_state: "unborn".into(),
            last_valid_step: "fixture step".into(),
            completed_gate_refs: vec!["fx:gate:one".into()],
            blocker_codes: vec!["UNAUTHORIZED".into()],
            evidence_refs: vec!["fx:evidence:one".into()],
            pending_action: "inspect fixture".into(),
            partial_effect_refs: vec![],
            resume_authority_ref: "fx:authority:seed".into(),
        }),
        outcome_payload(OutcomeVariant::Pass(PassCode::GatePassed), "pass"),
    ]
}

fn outcome_payload(status_and_code: OutcomeVariant, slug: &str) -> RecordPayload {
    RecordPayload::Outcome(Outcome {
        outcome_id: format!("fx:outcome:{slug}"),
        status_and_code,
        scope_ref: "fx:target:alpha".into(),
        evidence_refs: vec!["fx:evidence:one".into()],
        next_action: "fixture next step".into(),
        detail: "fixture result".into(),
    })
}

fn wrap(payload: RecordPayload) -> RecordEnvelope {
    RecordEnvelope {
        record_type: payload.record_type(),
        schema_version: 1,
        namespace: Namespace::Fixture,
        record_id: payload.primary_id().into(),
        creator_ref: "fx:actor:author".into(),
        created_at_unix_ms: 1,
        payload,
        integrity: ZERO_DIGEST.into(),
    }
}

fn encoded(payload: RecordPayload) -> Vec<u8> {
    encode_fixture(wrap(payload))
        .expect("valid fixture")
        .canonical_bytes()
        .to_vec()
}

#[test]
fn all_nine_record_classes_round_trip() {
    let samples = sample_payloads();
    assert_eq!(samples.len(), 9);
    for payload in samples {
        let expected_type = payload.record_type();
        let expected_id = payload.primary_id().to_owned();
        let record = encode_fixture(wrap(payload)).unwrap();
        let again = validate_bytes(record.canonical_bytes()).unwrap();
        assert_eq!(again.canonical_bytes(), record.canonical_bytes());
        assert_eq!(again.record().record_type, expected_type);
        assert_eq!(again.record().record_id, expected_id);
        assert_eq!(again.record().schema_version, 1);
        assert_eq!(again.record().creator_ref, "fx:actor:author");
        assert_eq!(again.record().created_at_unix_ms, 1);
        assert!(again.record().integrity.starts_with("sha256:"));
    }
}

#[test]
fn four_outcomes_remain_distinct() {
    let variants = [
        (OutcomeVariant::Pass(PassCode::GatePassed), "pass", "PASS"),
        (OutcomeVariant::Fail(FailCode::WorkFailed), "fail", "FAIL"),
        (
            OutcomeVariant::Blocked(BlockedCode::Unauthorized),
            "blocked",
            "BLOCKED",
        ),
        (
            OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled),
            "unknown",
            "UNKNOWN",
        ),
    ];
    for (variant, slug, status) in variants {
        let bytes = encoded(outcome_payload(variant.clone(), slug));
        let result = validate_bytes(&bytes).unwrap();
        let RecordPayload::Outcome(outcome) = &result.record().payload else {
            panic!("outcome payload required")
        };
        assert_eq!(outcome.status_and_code, variant);
        assert_eq!(outcome.scope_ref, "fx:target:alpha");
        assert_eq!(outcome.evidence_refs, vec!["fx:evidence:one"]);
        assert_eq!(outcome.next_action, "fixture next step");
        assert!(
            String::from_utf8(bytes)
                .unwrap()
                .contains(&format!("\"status\":\"{status}\""))
        );
    }
}

#[test]
fn explicit_blocked_and_unknown_examples_cannot_be_success() {
    for (variant, slug, expected) in [
        (
            OutcomeVariant::Blocked(BlockedCode::Unauthorized),
            "no-grant",
            "UNAUTHORIZED",
        ),
        (
            OutcomeVariant::Blocked(BlockedCode::EnvironmentFailure),
            "no-env",
            "ENVIRONMENT_FAILURE",
        ),
        (
            OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled),
            "uncertain",
            "PARTIAL_EFFECT_UNRECONCILED",
        ),
    ] {
        let bytes = encoded(outcome_payload(variant, slug));
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains(expected));
        assert!(!text.contains("\"status\":\"PASS\""));
        assert!(!text.contains("\"status\":\"FAIL\""));
    }
}

#[test]
fn stale_digest_and_byte_changes_are_rejected() {
    let original = encoded(sample_payloads().remove(0));
    let text = String::from_utf8(original.clone()).unwrap();
    let changed = text.replace("fixture://project/alpha", "fixture://project/bravo");
    assert_ne!(changed.as_bytes(), original);
    assert_eq!(
        validate_bytes(changed.as_bytes()).unwrap_err().stage,
        ValidationStage::Integrity
    );
    let mut new_record = wrap(sample_payloads().remove(0));
    let RecordPayload::ProjectBinding(project) = &mut new_record.payload else {
        unreachable!()
    };
    project.canonical_root = "fixture://project/bravo".into();
    let new_bytes = encode_fixture(new_record)
        .unwrap()
        .canonical_bytes()
        .to_vec();
    assert_ne!(original, new_bytes);
    assert!(validate_bytes(&new_bytes).is_ok());
}

#[test]
fn malformed_identity_namespace_and_version_fail_closed() {
    let raw = wrap(sample_payloads().remove(0));
    for mut wrong in [
        {
            let mut v = raw.clone();
            v.record_id = "fx:project:other".into();
            v
        },
        {
            let mut v = raw.clone();
            v.record_id = "fx:actor:alpha".into();
            v
        },
        {
            let mut v = raw.clone();
            v.record_id = "op:project:alpha".into();
            v
        },
        {
            let mut v = raw.clone();
            v.namespace = Namespace::Operational;
            v
        },
        {
            let mut v = raw.clone();
            v.schema_version = 2;
            v
        },
        {
            let mut v = raw.clone();
            v.record_type = titan_kernel::records::RecordType::ActorBinding;
            v
        },
    ] {
        assert!(encode_fixture(wrong.clone()).is_err());
        wrong.integrity = ZERO_DIGEST.into();
    }
    let mut missing = raw.clone();
    let RecordPayload::ProjectBinding(project) = &mut missing.payload else {
        unreachable!()
    };
    project.authority_source_ref.clear();
    assert!(encode_fixture(missing).is_err());
}

#[test]
fn real_target_and_operational_access_are_rejected() {
    let raw = wrap(sample_payloads().remove(0));
    for mutation in 0..4 {
        let mut candidate = raw.clone();
        let RecordPayload::ProjectBinding(project) = &mut candidate.payload else {
            unreachable!()
        };
        match mutation {
            0 => project.canonical_root = "E:\\Pipeline\\titan-forward".into(),
            1 => {
                project.repository_id = Some(1_396_000_355);
                project.repository_url = Some("fixture://repository/alpha".into());
            }
            2 => {
                project.repository_id = Some(123);
                project.repository_url = Some("https://github.com/Aimcurio/titan".into());
            }
            _ => project.canonical_root = "fixture://".replace("fixture://", "file://"),
        }
        assert!(encode_fixture(candidate).is_err());
    }
    let mut contract = wrap(sample_payloads().remove(3));
    let RecordPayload::ExecutionContract(payload) = &mut contract.payload else {
        unreachable!()
    };
    payload.network_allowed = true;
    assert!(encode_fixture(contract).is_err());
}

#[test]
fn canonical_json_is_required() {
    let bytes = encoded(sample_payloads().remove(0));
    let text = String::from_utf8(bytes).unwrap();
    let cases = [
        format!(" {text}"),
        format!("{text} "),
        text.replace(
            "\"record_type\":\"PROJECT_BINDING\",\"schema_version\":1",
            "\"schema_version\":1,\"record_type\":\"PROJECT_BINDING\"",
        ),
        text.replace(
            "\"schema_version\":1,\"namespace\"",
            "\"namespace\":\"FIXTURE\",\"schema_version\":1,\"namespace\"",
        ),
        text.replace(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
        ),
        text.replace("\"PROJECT_BINDING\"", "\"UNKNOWN_CLASS\""),
        text.replace("\"integrity\"", "\"unexpected\":1,\"integrity\""),
    ];
    for candidate in cases {
        assert!(validate_bytes(candidate.as_bytes()).is_err());
    }
    let whitespace = format!("{text}\n");
    assert!(validate_bytes(whitespace.as_bytes()).is_err());
}

#[test]
fn invalid_json_size_depth_and_digest_are_rejected() {
    assert!(validate_bytes(&[0xff]).is_err());
    assert_eq!(
        validate_bytes(&vec![b'x'; 1_048_577]).unwrap_err().stage,
        ValidationStage::InputSize
    );
    let nested = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    assert!(validate_bytes(nested.as_bytes()).is_err());
    let bytes = encoded(sample_payloads().remove(0));
    let mut text = String::from_utf8(bytes).unwrap();
    text = text.replace("sha256:", "SHA256:");
    assert!(validate_bytes(text.as_bytes()).is_err());
}

#[test]
fn unordered_or_duplicate_sets_and_bad_interval_are_rejected() {
    let mut actor = wrap(sample_payloads().remove(1));
    if let RecordPayload::ActorBinding(payload) = &mut actor.payload {
        payload.roles = vec![Role::Executor, Role::Verifier];
    }
    assert!(encode_fixture(actor.clone()).is_ok());
    if let RecordPayload::ActorBinding(payload) = &mut actor.payload {
        payload.roles = vec![Role::Verifier, Role::Executor];
    }
    assert!(encode_fixture(actor.clone()).is_err());
    if let RecordPayload::ActorBinding(payload) = &mut actor.payload {
        payload.roles = vec![Role::Executor, Role::Executor];
    }
    assert!(encode_fixture(actor.clone()).is_err());
    if let RecordPayload::ActorBinding(payload) = &mut actor.payload {
        payload.roles.clear();
    }
    assert!(encode_fixture(actor.clone()).is_err());
    if let RecordPayload::ActorBinding(payload) = &mut actor.payload {
        payload.roles = vec![Role::Executor];
        payload.valid_until_ms = Some(payload.valid_from_ms);
    }
    assert!(encode_fixture(actor).is_err());
}

#[test]
fn substantive_fixture_changes_change_integrity() {
    let baseline = wrap(sample_payloads().remove(2));
    let baseline_integrity = encode_fixture(baseline.clone())
        .unwrap()
        .record()
        .integrity
        .clone();
    let mut changed_effect = baseline.clone();
    let RecordPayload::AuthorityRecord(authority) = &mut changed_effect.payload else {
        unreachable!()
    };
    authority.claim_atoms[0].effect = "INSPECT".into();
    assert_ne!(
        encode_fixture(changed_effect).unwrap().record().integrity,
        baseline_integrity
    );
    let mut changed_id = baseline.clone();
    changed_id.record_id = "fx:authority:seed2".into();
    let RecordPayload::AuthorityRecord(authority) = &mut changed_id.payload else {
        unreachable!()
    };
    authority.authority_id = "fx:authority:seed2".into();
    assert_ne!(
        encode_fixture(changed_id).unwrap().record().integrity,
        baseline_integrity
    );
    let mut changed_set = baseline;
    let RecordPayload::AuthorityRecord(authority) = &mut changed_set.payload else {
        unreachable!()
    };
    authority.claim_atoms[0].lifecycle_contexts = vec!["REVIEW".into()];
    assert_ne!(
        encode_fixture(changed_set).unwrap().record().integrity,
        baseline_integrity
    );
}

#[test]
fn missing_text_and_status_code_mismatch_are_rejected() {
    let mut record = wrap(sample_payloads().remove(0));
    let RecordPayload::ProjectBinding(project) = &mut record.payload else {
        unreachable!()
    };
    project.canonical_root.clear();
    assert!(encode_fixture(record).is_err());

    let bytes = encoded(outcome_payload(
        OutcomeVariant::Pass(PassCode::GatePassed),
        "pass",
    ));
    let text = String::from_utf8(bytes).unwrap();
    let mismatched = text.replace("GATE_PASSED", "UNAUTHORIZED");
    assert!(validate_bytes(mismatched.as_bytes()).is_err());
}

#[test]
fn golden_vectors_are_byte_stable() {
    let samples = sample_payloads();
    let fixtures = [
        (
            samples[0].clone(),
            r#"{"record_type":"PROJECT_BINDING","schema_version":1,"namespace":"FIXTURE","record_id":"fx:project:alpha","creator_ref":"fx:actor:author","created_at_unix_ms":1,"payload":{"project_id":"fx:project:alpha","canonical_root":"fixture://project/alpha","repository_id":null,"repository_url":null,"authority_source_ref":"fx:authority:seed","binding_revision":1,"state":"PROPOSED"},"integrity":"sha256:d9e2e87f78ec177900398fba833ffcdc95ec881325d217c03c2bda579e75b60d"}"#,
        ),
        (
            samples[2].clone(),
            r#"{"record_type":"AUTHORITY_RECORD","schema_version":1,"namespace":"FIXTURE","record_id":"fx:authority:seed","creator_ref":"fx:actor:author","created_at_unix_ms":1,"payload":{"authority_id":"fx:authority:seed","class":"DECISION","issuer_actor_ref":"fx:actor:author","exercised_role":"DECISION_AUTHORITY","effective_at_ms":1,"target_binding_ref":"fx:project:alpha","contract_digest":null,"claim_atoms":[{"project_binding_ref":"fx:project:alpha","resource_ref":"fixture://resource/alpha","resource_match":"EXACT","action":"READ","provision":"PERMIT","effect":"OBSERVE","lifecycle_contexts":["READY"]}],"override_edges":[],"evidence_refs":[]},"integrity":"sha256:80ab88c9ee1cae5c207f98317fea4fb7fa5318740fe9c5dfe16710acd51755c7"}"#,
        ),
        (
            samples[6].clone(),
            r#"{"record_type":"PROMOTION_ELIGIBILITY_RECORD","schema_version":1,"namespace":"FIXTURE","record_id":"fx:eligibility:one","creator_ref":"fx:actor:author","created_at_unix_ms":1,"payload":{"eligibility_id":"fx:eligibility:one","candidate_ref":"fx:candidate:one","candidate_revision":"r1","expected_prior_canonical_ref":"fx:canonical:one","expected_prior_canonical_version":"r0","promotion_subject_ref":"fx:subject:one","promotion_scope":"fixture scope","contract_ref":"fx:contract:one","contract_digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","authorization_ref":"fx:authority:seed","policy_ref":"fx:policy:one","policy_version":1,"assurance_rule_ref":"fx:rule:one","assurance_rule_version":1,"eligibility_rule_version":1,"evidence_set_ref":"fx:evidence-set:one","evidence_artifacts":[{"artifact_ref":"fx:artifact:one","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000"}],"verification_result_refs":["fx:assessment:one"],"approval_refs":["fx:authority:approval"],"authority_state_ref":"fx:authority-state:one","evaluated_outcome":"ELIGIBLE","input_refs":["fx:evidence:one"]},"integrity":"sha256:bbcfc68a6bb9d8f486b3c4c253a8136d73d33fcd20fee6c16a90a4c6a42fd419"}"#,
        ),
        (
            outcome_payload(OutcomeVariant::Pass(PassCode::GatePassed), "pass"),
            r#"{"record_type":"OUTCOME","schema_version":1,"namespace":"FIXTURE","record_id":"fx:outcome:pass","creator_ref":"fx:actor:author","created_at_unix_ms":1,"payload":{"outcome_id":"fx:outcome:pass","status_and_code":{"status":"PASS","code":"GATE_PASSED"},"scope_ref":"fx:target:alpha","evidence_refs":["fx:evidence:one"],"next_action":"fixture next step","detail":"fixture result"},"integrity":"sha256:7f8aad4a971ad6afd8d347c9c752e33b8e5188b8285da62156b9f0e57411946b"}"#,
        ),
        (
            outcome_payload(OutcomeVariant::Fail(FailCode::WorkFailed), "fail"),
            r#"{"record_type":"OUTCOME","schema_version":1,"namespace":"FIXTURE","record_id":"fx:outcome:fail","creator_ref":"fx:actor:author","created_at_unix_ms":1,"payload":{"outcome_id":"fx:outcome:fail","status_and_code":{"status":"FAIL","code":"WORK_FAILED"},"scope_ref":"fx:target:alpha","evidence_refs":["fx:evidence:one"],"next_action":"fixture next step","detail":"fixture result"},"integrity":"sha256:f14e89e41549a7c54d51fcbb411984c78ebbb1b1361a5e52970f9a281675570e"}"#,
        ),
        (
            outcome_payload(
                OutcomeVariant::Blocked(BlockedCode::Unauthorized),
                "blocked",
            ),
            r#"{"record_type":"OUTCOME","schema_version":1,"namespace":"FIXTURE","record_id":"fx:outcome:blocked","creator_ref":"fx:actor:author","created_at_unix_ms":1,"payload":{"outcome_id":"fx:outcome:blocked","status_and_code":{"status":"BLOCKED","code":"UNAUTHORIZED"},"scope_ref":"fx:target:alpha","evidence_refs":["fx:evidence:one"],"next_action":"fixture next step","detail":"fixture result"},"integrity":"sha256:5b6c5f5a49da8748c02c4e7d7840d330581c625ed77074ab71f9d14f045bbc87"}"#,
        ),
        (
            outcome_payload(
                OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled),
                "unknown",
            ),
            r#"{"record_type":"OUTCOME","schema_version":1,"namespace":"FIXTURE","record_id":"fx:outcome:unknown","creator_ref":"fx:actor:author","created_at_unix_ms":1,"payload":{"outcome_id":"fx:outcome:unknown","status_and_code":{"status":"UNKNOWN","code":"PARTIAL_EFFECT_UNRECONCILED"},"scope_ref":"fx:target:alpha","evidence_refs":["fx:evidence:one"],"next_action":"fixture next step","detail":"fixture result"},"integrity":"sha256:b9198930970336efadf470b04e841705aac9f6c51331253b280f864a788acc96"}"#,
        ),
    ];
    for (payload, expected) in fixtures {
        let actual = encoded(payload);
        assert_eq!(actual, expected.as_bytes());
        assert_eq!(
            validate_bytes(expected.as_bytes())
                .unwrap()
                .canonical_bytes(),
            actual
        );
    }
}
