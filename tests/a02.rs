use std::{fs, path::PathBuf};

use titan_kernel::{
    ValidatedRecord,
    authority::{FixtureFailure, derive_claim_id, resolve_fixture_request},
    encode_fixture,
    fixture_projection::{
        FixtureAuthoritySeedV1, FixtureEventKind, FixtureEventV1, FixtureProjection, IssuerScopeV1,
        apply_fixture_event, fixture_snapshot_bytes, project_fixture_events,
        replay_fixture_projection,
    },
    outcome::BlockedCode,
    records::{
        ActorBinding, AuthorityClass, AuthorityRecord, BindingState, ClaimAtom, Namespace,
        OverrideEdge, ProjectBinding, Provision, RecordEnvelope, RecordPayload, ResourceMatch,
        Role,
    },
    selector::{
        AliasEntry, SelectorProfileV1, compare_fixture_sets, normalize_fixture_selector,
        set_is_subset,
    },
};

const PROJECT: &str = "fx:project:lab";
const ACTOR: &str = "fx:actor:synthetic";
const ZERO: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn record(id: &str, payload: RecordPayload) -> ValidatedRecord {
    encode_fixture(RecordEnvelope {
        record_type: payload.record_type(),
        schema_version: 1,
        namespace: Namespace::Fixture,
        record_id: id.to_owned(),
        creator_ref: ACTOR.to_owned(),
        created_at_unix_ms: 2,
        payload,
        integrity: ZERO.to_owned(),
    })
    .unwrap()
}

fn atom(resource: &str, match_kind: ResourceMatch, provision: Provision) -> ClaimAtom {
    ClaimAtom {
        project_binding_ref: PROJECT.to_owned(),
        resource_ref: resource.to_owned(),
        resource_match: match_kind,
        action: "READ".into(),
        provision,
        effect: "OBSERVE".into(),
        lifecycle_contexts: vec!["READY".into()],
    }
}

fn exact(resource: &str, provision: Provision) -> ClaimAtom {
    atom(resource, ResourceMatch::Exact, provision)
}

fn subtree(resource: &str, provision: Provision) -> ClaimAtom {
    atom(resource, ResourceMatch::Subtree, provision)
}

fn profile() -> SelectorProfileV1 {
    SelectorProfileV1 {
        normalizer_version: 1,
        compatibility_version: 1,
        actions: vec!["READ".into()],
        effects: vec!["OBSERVE".into()],
        contexts: vec!["READY".into()],
        aliases: vec![
            AliasEntry {
                alias: "fixture://alias/one".into(),
                canonical_resource: "fixture://resource/lab/a".into(),
            },
            AliasEntry {
                alias: "fixture://alias/two".into(),
                canonical_resource: "fixture://resource/lab/a".into(),
            },
        ],
    }
}

fn seed() -> FixtureAuthoritySeedV1 {
    let project = record(
        PROJECT,
        RecordPayload::ProjectBinding(ProjectBinding {
            project_id: PROJECT.into(),
            canonical_root: "fixture://project/lab".into(),
            repository_id: None,
            repository_url: None,
            authority_source_ref: "fx:authority:synthetic-seed".into(),
            binding_revision: 1,
            state: BindingState::Active,
        }),
    );
    let actor = record(
        ACTOR,
        RecordPayload::ActorBinding(ActorBinding {
            actor_id: ACTOR.into(),
            principal_ref: "fx:principal:synthetic".into(),
            auth_method_ref: "fx:method:fixture".into(),
            roles: vec![Role::DecisionAuthority],
            issued_by_ref: ACTOR.into(),
            valid_from_ms: 1,
            valid_until_ms: None,
            revocation_ref: None,
        }),
    );
    let p = profile();
    let broad =
        normalize_fixture_selector(&subtree("fixture://resource/lab", Provision::Permit), &p)
            .unwrap();
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

fn authority(
    slug: &str,
    class: AuthorityClass,
    atoms: Vec<ClaimAtom>,
    edges: Vec<OverrideEdge>,
) -> ValidatedRecord {
    authority_at(slug, class, atoms, edges, 2)
}

fn authority_at(
    slug: &str,
    class: AuthorityClass,
    atoms: Vec<ClaimAtom>,
    edges: Vec<OverrideEdge>,
    effective_at_ms: u64,
) -> ValidatedRecord {
    let id = format!("fx:authority:{slug}");
    record(
        &id,
        RecordPayload::AuthorityRecord(AuthorityRecord {
            authority_id: id.clone(),
            class,
            issuer_actor_ref: ACTOR.into(),
            exercised_role: Role::DecisionAuthority,
            effective_at_ms,
            target_binding_ref: Some(PROJECT.into()),
            contract_digest: None,
            claim_atoms: atoms,
            override_edges: edges,
            evidence_refs: vec![],
        }),
    )
}

fn decision(slug: &str, claim: ClaimAtom) -> ValidatedRecord {
    authority(slug, AuthorityClass::Decision, vec![claim], vec![])
}

fn event(
    state: &FixtureProjection,
    item: &ValidatedRecord,
    kind: FixtureEventKind,
    target_claim: Option<&str>,
    target_edge: Option<&str>,
) -> FixtureEventV1 {
    FixtureEventV1 {
        event_id: item
            .record()
            .record_id
            .replace("fx:authority:", "fx:event:"),
        kind,
        record_id: item.record().record_id.clone(),
        record_digest: item.record().integrity.clone(),
        issuer_actor_id: ACTOR.into(),
        expected_prior_state_id: state.state_id.clone(),
        target_claim_id: target_claim.map(str::to_owned),
        target_edge_id: target_edge.map(str::to_owned),
    }
}

fn accept(
    state: &mut FixtureProjection,
    seed: &FixtureAuthoritySeedV1,
    item: &ValidatedRecord,
    kind: FixtureEventKind,
    claim: Option<&str>,
    edge: Option<&str>,
) -> FixtureEventV1 {
    let e = event(state, item, kind, claim, edge);
    apply_fixture_event(state, seed, item, &e).unwrap();
    e
}

fn accept_claim(
    state: &mut FixtureProjection,
    seed: &FixtureAuthoritySeedV1,
    item: &ValidatedRecord,
) {
    accept(
        state,
        seed,
        item,
        FixtureEventKind::ClaimAcceptance,
        None,
        None,
    );
}

fn query(
    seed: &FixtureAuthoritySeedV1,
    atoms: &[ClaimAtom],
) -> Vec<titan_kernel::selector::NormalizedSelector> {
    atoms
        .iter()
        .flat_map(|item| normalize_fixture_selector(item, &seed.profile).unwrap())
        .collect()
}

fn resolved(
    state: &FixtureProjection,
    request: &[titan_kernel::selector::NormalizedSelector],
) -> titan_kernel::authority::ResolvedFixtureOutcome {
    resolve_fixture_request(state, &state.state_id, request).unwrap()
}

fn blocked(
    state: &FixtureProjection,
    request: &[titan_kernel::selector::NormalizedSelector],
    code: BlockedCode,
) {
    let result = resolve_fixture_request(state, &state.state_id, request);
    assert!(matches!(result, Err(FixtureFailure { code: observed, .. }) if observed == code));
}

fn unchanged_rejection(
    state: &mut FixtureProjection,
    seed: &FixtureAuthoritySeedV1,
    item: &ValidatedRecord,
    e: &FixtureEventV1,
    code: BlockedCode,
) {
    let before = state.clone();
    let result = apply_fixture_event(state, seed, item, e);
    assert!(matches!(result, Err(FixtureFailure { code: observed, .. }) if observed == code));
    assert_eq!(*state, before, "rejected event mutated projection or masks");
}

fn override_record(
    seed: &FixtureAuthoritySeedV1,
    slug: &str,
    predecessor: &str,
    successor: ClaimAtom,
    coverage: ClaimAtom,
) -> (ValidatedRecord, String) {
    let authority_id = format!("fx:authority:{slug}");
    let successor_id = derive_claim_id(&authority_id, &successor, &seed.profile).unwrap();
    let edge = OverrideEdge {
        predecessor_claim_ref: predecessor.to_owned(),
        successor_claim_ref: successor_id.clone(),
        coverage_atoms: vec![coverage],
    };
    (
        authority(slug, AuthorityClass::Decision, vec![successor], vec![edge]),
        successor_id,
    )
}

fn base_override() -> (
    FixtureAuthoritySeedV1,
    FixtureProjection,
    String,
    String,
    String,
) {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let pred_atom = exact("fixture://resource/lab/a", Provision::Permit);
    let pred = decision("predecessor", pred_atom.clone());
    let pred_id = derive_claim_id("fx:authority:predecessor", &pred_atom, &seed.profile).unwrap();
    accept_claim(&mut state, &seed, &pred);
    let (successor, succ_id) = override_record(
        &seed,
        "successor",
        &pred_id,
        exact("fixture://resource/lab/a", Provision::Forbid),
        exact("fixture://resource/lab/a", Provision::Forbid),
    );
    accept(
        &mut state,
        &seed,
        &successor,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    let edge_id = state.edges.keys().next().unwrap().clone();
    (seed, state, pred_id, succ_id, edge_id)
}

fn revoke(seed: &FixtureAuthoritySeedV1, state: &mut FixtureProjection, successor: &str) {
    let item = authority(
        "revoke-successor",
        AuthorityClass::Revocation,
        vec![exact("fixture://resource/lab/a", Provision::Revoke)],
        vec![],
    );
    accept(
        state,
        seed,
        &item,
        FixtureEventKind::SuccessorRevocation,
        Some(successor),
        None,
    );
}

#[test]
fn a02_01_disjoint_claims_and_multi_cell_result() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let a = decision(
        "disjoint-a",
        exact("fixture://resource/lab/a", Provision::Permit),
    );
    let b = decision(
        "disjoint-b",
        exact("fixture://resource/lab/b", Provision::Forbid),
    );
    accept_claim(&mut state, &seed, &a);
    accept_claim(&mut state, &seed, &b);
    let out = resolved(
        &state,
        &query(
            &seed,
            &[
                exact("fixture://resource/lab/a", Provision::Permit),
                exact("fixture://resource/lab/b", Provision::Permit),
            ],
        ),
    );
    assert_eq!(out.authority_state_id, state.state_id);
    assert_eq!(out.cells.len(), 2);
    assert_eq!(out.cells[0].governing_claim_ids.len(), 1);
    assert_eq!(out.cells[1].governing_claim_ids.len(), 1);
    assert_ne!(
        out.cells[0].governing_claim_ids,
        out.cells[1].governing_claim_ids
    );
}

#[test]
fn a02_02_compatible_multiple_active_claims() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let a = decision(
        "compatible-a",
        exact("fixture://resource/lab/a", Provision::Permit),
    );
    let b = decision(
        "compatible-b",
        exact("fixture://resource/lab/a", Provision::Permit),
    );
    accept_claim(&mut state, &seed, &a);
    accept_claim(&mut state, &seed, &b);
    let out = resolved(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
    );
    assert_eq!(out.cells.len(), 1);
    assert_eq!(out.cells[0].governing_claim_ids.len(), 2);
    assert_eq!(out.cells[0].provision, Provision::Permit);
}

#[test]
fn a02_03_same_key_incompatible_overlap_blocks_whole_request() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    accept_claim(
        &mut state,
        &seed,
        &decision(
            "same-key-a",
            exact("fixture://resource/lab/a", Provision::Permit),
        ),
    );
    accept_claim(
        &mut state,
        &seed,
        &decision(
            "same-key-b",
            exact("fixture://resource/lab/a", Provision::Forbid),
        ),
    );
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
}

#[test]
fn a02_04_different_record_keys_do_not_decide_same_governed_action() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    accept_claim(
        &mut state,
        &seed,
        &decision(
            "different-key-one",
            exact("fixture://resource/lab/a", Provision::Permit),
        ),
    );
    accept_claim(
        &mut state,
        &seed,
        &decision(
            "different-key-two",
            exact("fixture://alias/one", Provision::Forbid),
        ),
    );
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
}

#[test]
fn a02_05_broad_narrow_specificity_never_decides_precedence() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    accept_claim(
        &mut state,
        &seed,
        &decision(
            "broad",
            subtree("fixture://resource/lab", Provision::Permit),
        ),
    );
    accept_claim(
        &mut state,
        &seed,
        &decision(
            "narrow",
            exact("fixture://resource/lab/a", Provision::Forbid),
        ),
    );
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
    let out = resolved(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/b", Provision::Permit)],
        ),
    );
    assert_eq!(out.cells[0].provision, Provision::Permit);
}

#[test]
fn a02_06_partial_intersection_subset_and_difference_are_exact() {
    let seed = seed();
    let broad = query(
        &seed,
        &[subtree("fixture://resource/lab", Provision::Permit)],
    );
    let narrow = query(
        &seed,
        &[subtree("fixture://resource/lab/a", Provision::Permit)],
    );
    let comparison = compare_fixture_sets(&broad, &narrow);
    assert!(!comparison.intersection.is_empty());
    assert!(!comparison.left_only.is_empty());
    assert!(comparison.right_only.is_empty());
    assert!(set_is_subset(&narrow, &broad));
    assert!(!set_is_subset(&broad, &narrow));
    let a = query(
        &seed,
        &[exact("fixture://resource/lab/a", Provision::Permit)],
    );
    let ab = query(
        &seed,
        &[exact("fixture://resource/lab/ab", Provision::Permit)],
    );
    assert!(compare_fixture_sets(&a, &ab).intersection.is_empty());
}

#[test]
fn a02_07_alias_equivalent_resources_have_identical_cells() {
    let seed = seed();
    let canonical = query(
        &seed,
        &[exact("fixture://resource/lab/a", Provision::Permit)],
    );
    let alias = query(&seed, &[exact("fixture://alias/one", Provision::Permit)]);
    assert_eq!(canonical, alias);
    assert_eq!(seed.profile.alias_digest().unwrap(), {
        let mut permuted = seed.profile.clone();
        permuted.aliases.reverse();
        permuted.alias_digest().unwrap()
    });
}

#[test]
fn a02_08_ambiguous_unresolved_or_changed_alias_fails_closed() {
    let mut bad = seed();
    bad.profile.aliases.push(AliasEntry {
        alias: "fixture://alias/one".into(),
        canonical_resource: "fixture://resource/lab/b".into(),
    });
    assert_eq!(
        FixtureProjection::from_seed(&bad).unwrap_err().code,
        BlockedCode::ContractInvalid
    );
    let mut chained = seed();
    chained.profile.aliases[0].canonical_resource = "fixture://alias/two".into();
    assert_eq!(
        FixtureProjection::from_seed(&chained).unwrap_err().code,
        BlockedCode::ContractInvalid
    );
    let seed = seed();
    assert!(
        seed.profile
            .canonical_resource("fixture://alias/missing")
            .is_err()
    );
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    state.profile.aliases.push(AliasEntry {
        alias: "fixture://alias/one".into(),
        canonical_resource: "fixture://resource/lab/b".into(),
    });
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
}

#[test]
fn a02_09_valid_override_covers_full_conflicting_intersection() {
    let (seed, state, predecessor, successor, edge) = base_override();
    let out = resolved(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
    );
    assert_eq!(out.cells[0].governing_claim_ids, vec![successor]);
    assert_eq!(out.cells[0].provision, Provision::Forbid);
    assert_eq!(state.edges[&edge].predecessor_claim_id, predecessor);
    assert!(state.edges[&edge].reinstatements.is_empty());
}

#[test]
fn a02_10_partial_override_leaves_uncovered_conflict() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let pred_atom = subtree("fixture://resource/lab", Provision::Permit);
    let pred = decision("partial-pred", pred_atom.clone());
    let pred_id = derive_claim_id("fx:authority:partial-pred", &pred_atom, &seed.profile).unwrap();
    accept_claim(&mut state, &seed, &pred);
    let (succ, _) = override_record(
        &seed,
        "partial-succ",
        &pred_id,
        subtree("fixture://resource/lab", Provision::Forbid),
        exact("fixture://resource/lab/a", Provision::Forbid),
    );
    accept(
        &mut state,
        &seed,
        &succ,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    assert_eq!(
        resolved(
            &state,
            &query(
                &seed,
                &[exact("fixture://resource/lab/a", Provision::Permit)]
            )
        )
        .cells[0]
            .provision,
        Provision::Forbid
    );
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/b", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
}

#[test]
fn a02_11_invalid_or_missing_predecessor_rejects_without_mutation() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let (item, _) = override_record(
        &seed,
        "missing-pred",
        "fx:claim:missing",
        exact("fixture://resource/lab/a", Provision::Forbid),
        exact("fixture://resource/lab/a", Provision::Forbid),
    );
    let e = event(
        &state,
        &item,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    unchanged_rejection(&mut state, &seed, &item, &e, BlockedCode::ContractInvalid);
}

#[test]
fn a02_12_issuer_scope_does_not_contain_override() {
    let mut seed = seed();
    seed.issuers[0].override_scope = query(
        &seed,
        &[exact("fixture://resource/lab/b", Provision::Permit)],
    );
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let pred_atom = exact("fixture://resource/lab/a", Provision::Permit);
    let pred = decision("scope-pred", pred_atom.clone());
    let pred_id = derive_claim_id("fx:authority:scope-pred", &pred_atom, &seed.profile).unwrap();
    accept_claim(&mut state, &seed, &pred);
    let (item, _) = override_record(
        &seed,
        "scope-succ",
        &pred_id,
        exact("fixture://resource/lab/a", Provision::Forbid),
        exact("fixture://resource/lab/a", Provision::Forbid),
    );
    let e = event(
        &state,
        &item,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    unchanged_rejection(&mut state, &seed, &item, &e, BlockedCode::ContractInvalid);
}

#[test]
fn a02_13_self_edge_cycle_is_structurally_rejected() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let atom = exact("fixture://resource/lab/a", Provision::Permit);
    let id = derive_claim_id("fx:authority:self-edge", &atom, &seed.profile).unwrap();
    let item = authority(
        "self-edge",
        AuthorityClass::Decision,
        vec![atom.clone()],
        vec![OverrideEdge {
            predecessor_claim_ref: id.clone(),
            successor_claim_ref: id,
            coverage_atoms: vec![atom],
        }],
    );
    let e = event(
        &state,
        &item,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    unchanged_rejection(&mut state, &seed, &item, &e, BlockedCode::ContractInvalid);
}

#[test]
fn a02_14_record_alias_event_input_order_does_not_change_state() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let a = decision(
        "order-a",
        exact("fixture://resource/lab/a", Provision::Permit),
    );
    let b = decision(
        "order-b",
        exact("fixture://resource/lab/b", Provision::Forbid),
    );
    let e1 = accept(
        &mut state,
        &seed,
        &a,
        FixtureEventKind::ClaimAcceptance,
        None,
        None,
    );
    let e2 = accept(
        &mut state,
        &seed,
        &b,
        FixtureEventKind::ClaimAcceptance,
        None,
        None,
    );
    let mut permuted_seed = seed.clone();
    permuted_seed.profile.aliases.reverse();
    let replayed = project_fixture_events(&permuted_seed, &[b, a], &[e2, e1]).unwrap();
    assert_eq!(replayed.state_id, state.state_id);
    let request = query(
        &seed,
        &[exact("fixture://resource/lab/a", Provision::Permit)],
    );
    assert_eq!(resolved(&state, &request), resolved(&replayed, &request));
}

#[test]
fn a02_15_unsupported_versions_fail_closed() {
    let mut bad = seed();
    bad.profile.compatibility_version = 2;
    assert_eq!(
        FixtureProjection::from_seed(&bad).unwrap_err().code,
        BlockedCode::ContractInvalid
    );
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    state.profile.normalizer_version = 2;
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
}

#[test]
fn a02_16_successor_revocation_preserves_predecessor_mask() {
    let (seed, mut state, predecessor, successor, edge) = base_override();
    let original_coverage = state.edges[&edge].coverage.clone();
    revoke(&seed, &mut state, &successor);
    assert!(state.claims[&successor].revoked);
    assert!(!state.claims[&predecessor].revoked);
    assert_eq!(state.edges[&edge].coverage, original_coverage);
    assert!(state.edges[&edge].reinstatements.is_empty());
}

#[test]
fn a02_17_other_active_compatible_claim_governs_after_revocation() {
    let (seed, mut state, predecessor, successor, _) = base_override();
    let other = decision(
        "other-valid",
        exact("fixture://resource/lab/a", Provision::Permit),
    );
    let other_id = derive_claim_id(
        "fx:authority:other-valid",
        &exact("fixture://resource/lab/a", Provision::Permit),
        &seed.profile,
    )
    .unwrap();
    accept_claim(&mut state, &seed, &other);
    revoke(&seed, &mut state, &successor);
    let out = resolved(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
    );
    assert_eq!(out.cells[0].governing_claim_ids, vec![other_id]);
    assert!(!out.cells[0].governing_claim_ids.contains(&predecessor));
}

#[test]
fn a02_18_revocation_gap_blocks_without_resurrection() {
    let (seed, mut state, predecessor, successor, _) = base_override();
    revoke(&seed, &mut state, &successor);
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedNoActiveGoverningAuthority,
    );
    assert!(!state.claims[&predecessor].revoked);
}

#[test]
fn a02_19_explicit_authorized_reinstatement_only_restores_named_mask() {
    let (seed, mut state, predecessor, successor, edge) = base_override();
    revoke(&seed, &mut state, &successor);
    let reinstate = authority(
        "reinstate-pred",
        AuthorityClass::Reinstatement,
        vec![exact("fixture://resource/lab/a", Provision::Reinstate)],
        vec![],
    );
    accept(
        &mut state,
        &seed,
        &reinstate,
        FixtureEventKind::ExplicitReinstatement,
        None,
        Some(&edge),
    );
    let out = resolved(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
    );
    assert_eq!(out.cells[0].governing_claim_ids, vec![predecessor]);
    assert_eq!(state.edges[&edge].reinstatements.len(), 1);
}

#[test]
fn a02_20_governed_plus_ungoverned_cell_has_no_partial_result() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    accept_claim(
        &mut state,
        &seed,
        &decision(
            "only-a",
            exact("fixture://resource/lab/a", Provision::Permit),
        ),
    );
    blocked(
        &state,
        &query(
            &seed,
            &[
                exact("fixture://resource/lab/a", Provision::Permit),
                exact("fixture://resource/lab/b", Provision::Permit),
            ],
        ),
        BlockedCode::BlockedNoActiveGoverningAuthority,
    );
}

#[test]
fn a02_guard_replay_snapshot_and_corruption_fail_closed() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let pred_atom = exact("fixture://resource/lab/a", Provision::Permit);
    let pred = decision("replay-pred", pred_atom.clone());
    let pred_id = derive_claim_id("fx:authority:replay-pred", &pred_atom, &seed.profile).unwrap();
    let e1 = accept(
        &mut state,
        &seed,
        &pred,
        FixtureEventKind::ClaimAcceptance,
        None,
        None,
    );
    let (succ, successor) = override_record(
        &seed,
        "replay-succ",
        &pred_id,
        exact("fixture://resource/lab/a", Provision::Forbid),
        exact("fixture://resource/lab/a", Provision::Forbid),
    );
    let e2 = accept(
        &mut state,
        &seed,
        &succ,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    let rev = authority(
        "replay-revoke",
        AuthorityClass::Revocation,
        vec![exact("fixture://resource/lab/a", Provision::Revoke)],
        vec![],
    );
    let e3 = accept(
        &mut state,
        &seed,
        &rev,
        FixtureEventKind::SuccessorRevocation,
        Some(&successor),
        None,
    );
    let bytes = fixture_snapshot_bytes(&seed, &[rev, succ, pred], &[e3, e2, e1]).unwrap();
    let dir = PathBuf::from(
        std::env::var("TITAN_F02_FIXTURE_DIR").expect("isolated F02 fixture directory required"),
    );
    assert!(dir.is_dir());
    assert!(!dir.to_string_lossy().contains("titan-forward"));
    let path = dir.join(format!("a02-replay-{}.json", std::process::id()));
    fs::write(&path, &bytes).unwrap();
    let reloaded = fs::read(&path).unwrap();
    let replayed = replay_fixture_projection(&reloaded).unwrap();
    assert_eq!(replayed.state_id, state.state_id);
    assert_eq!(replayed.edges, state.edges);
    blocked(
        &replayed,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedNoActiveGoverningAuthority,
    );
    let mut corrupt = reloaded;
    corrupt[0] ^= 1;
    assert_eq!(
        replay_fixture_projection(&corrupt).unwrap_err().code,
        BlockedCode::ContractInvalid
    );
}

#[test]
fn a02_guard_invalid_resource_spellings_and_stale_state() {
    let seed = seed();
    for bad in [
        "fixture://resource/lab/a/",
        "fixture://resource/lab/../a",
        "fixture://resource/lab\\a",
        "fixture://resource/lab/%61",
        "fixture://resource/lab/À",
        "fixture://resource/Lab/a",
        "E:\\Pipeline\\titan-forward",
        "https://github.com/Aimcurio/titan",
    ] {
        assert!(
            seed.profile.canonical_resource(bad).is_err(),
            "accepted {bad}"
        );
    }
    let state = FixtureProjection::from_seed(&seed).unwrap();
    let request = query(
        &seed,
        &[exact("fixture://resource/lab/a", Provision::Permit)],
    );
    assert_eq!(
        resolve_fixture_request(&state, "sha256:stale", &request)
            .unwrap_err()
            .code,
        BlockedCode::AuthorityStale
    );
}

#[test]
fn a02_guard_missing_link_fork_and_timestamp_do_not_pick_winner() {
    let seed = seed();
    let state = FixtureProjection::from_seed(&seed).unwrap();
    let a = decision(
        "fork-a",
        exact("fixture://resource/lab/a", Provision::Permit),
    );
    let b = authority_at(
        "fork-b",
        AuthorityClass::Decision,
        vec![exact("fixture://resource/lab/a", Provision::Forbid)],
        vec![],
        999,
    );
    let e1 = event(&state, &a, FixtureEventKind::ClaimAcceptance, None, None);
    let e2 = event(&state, &b, FixtureEventKind::ClaimAcceptance, None, None);
    assert_eq!(
        project_fixture_events(&seed, &[a.clone(), b.clone()], &[e1, e2])
            .unwrap_err()
            .code,
        BlockedCode::ContractInvalid
    );
    let mut accepted = state;
    accept_claim(&mut accepted, &seed, &a);
    accept_claim(&mut accepted, &seed, &b);
    blocked(
        &accepted,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
}

#[test]
fn a02_guard_two_incompatible_successors_do_not_gain_order_precedence() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let pred_atom = exact("fixture://resource/lab/a", Provision::Permit);
    let pred = decision("two-succ-pred", pred_atom.clone());
    let pred_id = derive_claim_id("fx:authority:two-succ-pred", &pred_atom, &seed.profile).unwrap();
    accept_claim(&mut state, &seed, &pred);
    let (first, first_id) = override_record(
        &seed,
        "two-succ-first",
        &pred_id,
        exact("fixture://resource/lab/a", Provision::Forbid),
        exact("fixture://resource/lab/a", Provision::Forbid),
    );
    accept(
        &mut state,
        &seed,
        &first,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    let (second, second_id) = override_record(
        &seed,
        "two-succ-second",
        &pred_id,
        exact("fixture://resource/lab/a", Provision::Approve),
        exact("fixture://resource/lab/a", Provision::Approve),
    );
    accept(
        &mut state,
        &seed,
        &second,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    assert!(!state.claims[&first_id].revoked);
    assert!(!state.claims[&second_id].revoked);
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/a", Provision::Permit)],
        ),
        BlockedCode::BlockedAuthorityConflict,
    );
}

#[test]
fn a02_guard_override_beyond_intersection_is_transactionally_rejected() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let pred_atom = exact("fixture://resource/lab/a", Provision::Permit);
    let pred = decision("excess-pred", pred_atom.clone());
    let pred_id = derive_claim_id("fx:authority:excess-pred", &pred_atom, &seed.profile).unwrap();
    accept_claim(&mut state, &seed, &pred);
    let (item, _) = override_record(
        &seed,
        "excess-succ",
        &pred_id,
        exact("fixture://resource/lab/b", Provision::Forbid),
        exact("fixture://resource/lab/a", Provision::Forbid),
    );
    let e = event(
        &state,
        &item,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    unchanged_rejection(&mut state, &seed, &item, &e, BlockedCode::ContractInvalid);
}

#[test]
fn a02_guard_reinstatement_excess_scope_is_transactionally_rejected() {
    let (seed, mut state, _, successor, edge) = base_override();
    revoke(&seed, &mut state, &successor);
    let item = authority(
        "reinstate-excess",
        AuthorityClass::Reinstatement,
        vec![subtree("fixture://resource/lab", Provision::Reinstate)],
        vec![],
    );
    let e = event(
        &state,
        &item,
        FixtureEventKind::ExplicitReinstatement,
        None,
        Some(&edge),
    );
    unchanged_rejection(&mut state, &seed, &item, &e, BlockedCode::ContractInvalid);
}

#[test]
fn a02_guard_partial_reinstatement_splits_broad_mask_without_resurrection_elsewhere() {
    let seed = seed();
    let mut state = FixtureProjection::from_seed(&seed).unwrap();
    let pred_atom = subtree("fixture://resource/lab", Provision::Permit);
    let pred = decision("split-pred", pred_atom.clone());
    let pred_id = derive_claim_id("fx:authority:split-pred", &pred_atom, &seed.profile).unwrap();
    accept_claim(&mut state, &seed, &pred);
    let (succ, successor) = override_record(
        &seed,
        "split-succ",
        &pred_id,
        subtree("fixture://resource/lab", Provision::Forbid),
        subtree("fixture://resource/lab", Provision::Forbid),
    );
    accept(
        &mut state,
        &seed,
        &succ,
        FixtureEventKind::OverrideAcceptance,
        None,
        None,
    );
    let edge = state.edges.keys().next().unwrap().clone();
    let rev = authority(
        "split-revoke",
        AuthorityClass::Revocation,
        vec![subtree("fixture://resource/lab", Provision::Revoke)],
        vec![],
    );
    accept(
        &mut state,
        &seed,
        &rev,
        FixtureEventKind::SuccessorRevocation,
        Some(&successor),
        None,
    );
    let reinstate = authority(
        "split-reinstate",
        AuthorityClass::Reinstatement,
        vec![exact("fixture://resource/lab/a", Provision::Reinstate)],
        vec![],
    );
    accept(
        &mut state,
        &seed,
        &reinstate,
        FixtureEventKind::ExplicitReinstatement,
        None,
        Some(&edge),
    );
    assert_eq!(
        resolved(
            &state,
            &query(
                &seed,
                &[exact("fixture://resource/lab/a", Provision::Permit)]
            )
        )
        .cells[0]
            .governing_claim_ids,
        vec![pred_id]
    );
    blocked(
        &state,
        &query(
            &seed,
            &[exact("fixture://resource/lab/b", Provision::Permit)],
        ),
        BlockedCode::BlockedNoActiveGoverningAuthority,
    );
    blocked(
        &state,
        &query(
            &seed,
            &[subtree("fixture://resource/lab", Provision::Permit)],
        ),
        BlockedCode::BlockedNoActiveGoverningAuthority,
    );
}

#[test]
fn a02_guard_fixture_identity_evidence() {
    let (seed, state, _, _, _) = base_override();
    let alias = seed.profile.alias_digest().unwrap();
    let catalog = seed.profile.catalog_digest().unwrap();
    let seed_id = seed.digest().unwrap();
    println!(
        "A02_IDENTITY alias={alias} catalog={catalog} seed={seed_id} positive_state={}",
        state.state_id
    );
    for value in [&alias, &catalog, &seed_id, &state.state_id] {
        assert!(value.starts_with("sha256:"));
        assert_eq!(value.len(), 71);
    }
}
