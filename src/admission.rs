//! Inert fixture-only K2 admission; structural validity is never permission.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    ValidatedRecord,
    authority::{
        FixtureFailure, FixtureResult, ResolvedFixtureOutcome, invalid, resolve_fixture_request,
    },
    fixture_projection::{FixtureAuthoritySeedV1, FixtureProjection},
    outcome::BlockedCode,
    records::{
        ActorBinding, BindingState, ClaimAtom, ExecutionContract, ProjectBinding, Provision,
        RecordPayload, ResourceMatch,
    },
    selector::{
        NormalizedSelector, SelectorProfileV1, compare_fixture_sets, normalize_fixture_selector,
        set_contains_cell, set_is_subset,
    },
    target::{FixtureTargetPolicyV1, FixtureTargetSnapshotV1, construct_fixture_target_snapshot},
};

pub const ADMISSION_VERSION: u32 = 1;
pub const ADMISSION_MARKER: &str = "TITAN_F03_FIXTURE_ADMISSION_V1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractValidationV1 {
    pub status: &'static str,
    pub contract_id: String,
    pub contract_digest: String,
    pub normalized_declarations_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureScopeV1 {
    pub resource_ref: String,
    pub match_kind: ResourceMatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum FixtureConditionStatus {
    Satisfied,
    Unsatisfied,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FixtureConditionValueV1 {
    pub reference: String,
    pub fixture_revision: String,
    pub fixture_digest: String,
    pub status: FixtureConditionStatus,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixturePreconditionSnapshotV1 {
    pub conditions: Vec<FixtureConditionValueV1>,
    pub active_stop_codes: Vec<String>,
    pub fixture_epoch_ms: u64,
}

pub struct FixtureAdmissionInput<'a> {
    pub project: &'a ValidatedRecord,
    pub actor: &'a ValidatedRecord,
    pub contract: &'a ValidatedRecord,
    pub expected_contract_id: &'a str,
    pub expected_contract_digest: &'a str,
    pub seed: &'a FixtureAuthoritySeedV1,
    pub authority_state: &'a FixtureProjection,
    pub supplied_resolution: &'a ResolvedFixtureOutcome,
    pub target_policy: &'a FixtureTargetPolicyV1,
    pub requested_capability: &'a str,
    pub requested_operation: &'a str,
    pub requested_read_scopes: &'a [FixtureScopeV1],
    pub requested_mutation_scopes: &'a [FixtureScopeV1],
    pub network_requested: bool,
    pub secret_requested: bool,
    pub cross_surface_requested: bool,
    pub preconditions: &'a FixturePreconditionSnapshotV1,
}

/// Private fields prevent callers from constructing a valid admission directly.
/// Serialization is for inspection only, never an operational token.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureAdmissionV1 {
    marker: String,
    version: u32,
    namespace: String,
    project_id: String,
    project_digest: String,
    actor_id: String,
    actor_digest: String,
    contract_id: String,
    contract_digest: String,
    target_id: String,
    target_root: String,
    target_relative_path: String,
    target_state_id: String,
    capability: String,
    operation: String,
    read_selectors: Vec<NormalizedSelector>,
    mutation_selectors: Vec<NormalizedSelector>,
    network_requested: bool,
    secret_requested: bool,
    cross_surface_requested: bool,
    seed_digest: String,
    authority_state_id: String,
    governing_resolution_id: String,
    precondition_snapshot_id: String,
    admission_id: String,
}

impl FixtureAdmissionV1 {
    pub fn admission_id(&self) -> &str {
        &self.admission_id
    }
    pub fn target_state_id(&self) -> &str {
        &self.target_state_id
    }
    pub fn authority_state_id(&self) -> &str {
        &self.authority_state_id
    }
    pub fn governing_resolution_id(&self) -> &str {
        &self.governing_resolution_id
    }
    pub fn precondition_snapshot_id(&self) -> &str {
        &self.precondition_snapshot_id
    }
    pub fn canonical_bytes(&self) -> FixtureResult<Vec<u8>> {
        serde_json::to_vec(self).map_err(|_| invalid("fixture admission serialization failed"))
    }
}

fn block(code: BlockedCode, reason: &'static str) -> FixtureFailure {
    FixtureFailure::new(code, reason)
}

fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

fn digest_form(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn target_state_form(value: &str) -> bool {
    value.strip_prefix("fx-state-v1:").is_some_and(digest_form)
}

fn contract_payload(record: &ValidatedRecord) -> FixtureResult<&ExecutionContract> {
    let RecordPayload::ExecutionContract(contract) = &record.record().payload else {
        return Err(invalid("F01 execution contract required"));
    };
    Ok(contract)
}

fn project_payload(record: &ValidatedRecord) -> FixtureResult<&ProjectBinding> {
    let RecordPayload::ProjectBinding(project) = &record.record().payload else {
        return Err(invalid("F01 project binding required"));
    };
    Ok(project)
}

fn actor_payload(record: &ValidatedRecord) -> FixtureResult<&ActorBinding> {
    let RecordPayload::ActorBinding(actor) = &record.record().payload else {
        return Err(invalid("F01 actor binding required"));
    };
    Ok(actor)
}

fn parse_scope(value: &str, profile: &SelectorProfileV1) -> FixtureResult<FixtureScopeV1> {
    let (resource_ref, match_kind) = if let Some(base) = value.strip_suffix("/*") {
        (base, ResourceMatch::Subtree)
    } else {
        (value, ResourceMatch::Exact)
    };
    profile
        .canonical_resource(resource_ref)
        .map_err(|_| invalid("invalid or unresolved fixture scope"))?;
    Ok(FixtureScopeV1 {
        resource_ref: resource_ref.to_owned(),
        match_kind,
    })
}

fn parse_declarations(
    values: &[String],
    profile: &SelectorProfileV1,
) -> FixtureResult<Vec<FixtureScopeV1>> {
    let mut normalized = Vec::new();
    let mut seen = BTreeSet::new();
    for value in values {
        let scope = parse_scope(value, profile)?;
        let canonical = profile
            .canonical_resource(&scope.resource_ref)
            .map_err(|_| invalid("unresolved fixture scope"))?;
        let key = (
            canonical,
            matches!(scope.match_kind, ResourceMatch::Subtree),
        );
        if !seen.insert(key.clone()) {
            return Err(invalid("duplicate normalized contract scope"));
        }
        normalized.push((key, scope));
    }
    normalized.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(normalized.into_iter().map(|(_, value)| value).collect())
}

pub fn validate_fixture_contract(
    record: &ValidatedRecord,
    profile: &SelectorProfileV1,
) -> FixtureResult<ContractValidationV1> {
    profile
        .validate()
        .map_err(|_| invalid("invalid F02 fixture profile"))?;
    let contract = contract_payload(record)?;
    if !target_state_form(&contract.expected_target_state) {
        return Err(invalid("unsupported fixture target-state identity"));
    }
    let read = parse_declarations(&contract.read_scopes, profile)?;
    let mutations = parse_declarations(&contract.allowed_mutations, profile)?;
    let prohibited = parse_declarations(&contract.prohibited_mutations, profile)?;
    if contract.allowed_operations.is_empty() || contract.stop_codes.is_empty() {
        return Err(invalid("fixture contract lacks operation or stop rule"));
    }
    let canonical = |scopes: &[FixtureScopeV1]| -> FixtureResult<Vec<(String, ResourceMatch)>> {
        scopes
            .iter()
            .map(|item| {
                Ok((
                    profile
                        .canonical_resource(&item.resource_ref)
                        .map_err(|_| invalid("unresolved fixture scope"))?,
                    item.match_kind.clone(),
                ))
            })
            .collect()
    };
    let encoded = serde_json::to_vec(&(
        canonical(&read)?,
        canonical(&mutations)?,
        canonical(&prohibited)?,
    ))
    .map_err(|_| invalid("contract declarations serialization failed"))?;
    Ok(ContractValidationV1 {
        status: "CONTRACT_VALID",
        contract_id: contract.contract_id.clone(),
        contract_digest: record.record().integrity.clone(),
        normalized_declarations_digest: hash(b"TITAN-FWD-F03\0declarations-v1\0", &encoded),
    })
}

fn normalize_scopes(
    scopes: &[FixtureScopeV1],
    project_id: &str,
    operation: &str,
    effect: &str,
    profile: &SelectorProfileV1,
) -> FixtureResult<Vec<NormalizedSelector>> {
    let mut normalized = Vec::new();
    for scope in scopes {
        let atom = ClaimAtom {
            project_binding_ref: project_id.to_owned(),
            resource_ref: scope.resource_ref.clone(),
            resource_match: scope.match_kind.clone(),
            action: operation.to_owned(),
            provision: Provision::Permit, // inert normalization adapter, not an accepted claim
            effect: effect.to_owned(),
            lifecycle_contexts: vec!["READY".into()],
        };
        normalized.extend(
            normalize_fixture_selector(&atom, profile)
                .map_err(|_| invalid("unsupported F03 fixture selector"))?,
        );
    }
    normalized.sort();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(invalid("duplicate normalized fixture request scope"));
    }
    Ok(normalized)
}

fn normalize_contract_scopes(
    values: &[String],
    project_id: &str,
    operation: &str,
    effect: &str,
    profile: &SelectorProfileV1,
) -> FixtureResult<Vec<NormalizedSelector>> {
    let scopes = parse_declarations(values, profile)?;
    normalize_scopes(&scopes, project_id, operation, effect, profile)
}

fn code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn precondition_id(
    contract: &ExecutionContract,
    snapshot: &FixturePreconditionSnapshotV1,
    target_state_id: &str,
    authority_state_id: &str,
) -> FixtureResult<String> {
    let expected = contract
        .precondition_refs
        .iter()
        .chain(contract.required_evidence_refs.iter())
        .chain(contract.verification_gate_refs.iter())
        .collect::<BTreeSet<_>>();
    let mut conditions = BTreeMap::new();
    for condition in &snapshot.conditions {
        if condition.fixture_revision.is_empty()
            || !digest_form(&condition.fixture_digest)
            || conditions.insert(&condition.reference, condition).is_some()
        {
            return Err(invalid("malformed or duplicate fixture precondition"));
        }
    }
    if conditions.keys().copied().collect::<BTreeSet<_>>() != expected {
        let missing_evidence = contract
            .required_evidence_refs
            .iter()
            .chain(contract.verification_gate_refs.iter())
            .any(|reference| !conditions.contains_key(reference));
        return Err(block(
            if missing_evidence {
                BlockedCode::InsufficientEvidence
            } else {
                BlockedCode::PreconditionDrift
            },
            "required fixture precondition reference set mismatch",
        ));
    }
    if conditions
        .values()
        .any(|item| item.status != FixtureConditionStatus::Satisfied)
    {
        return Err(block(
            BlockedCode::PreconditionDrift,
            "fixture precondition not satisfied",
        ));
    }
    let stops = snapshot.active_stop_codes.iter().collect::<BTreeSet<_>>();
    if stops.len() != snapshot.active_stop_codes.len()
        || snapshot.active_stop_codes.iter().any(|item| !code(item))
    {
        return Err(invalid("active stop-code set malformed"));
    }
    if contract.stop_codes.iter().any(|item| stops.contains(item)) {
        return Err(block(
            BlockedCode::PreconditionDrift,
            "contract stop code active",
        ));
    }
    let material = serde_json::to_vec(&(
        conditions,
        stops,
        snapshot.fixture_epoch_ms,
        target_state_id,
        authority_state_id,
    ))
    .map_err(|_| invalid("precondition identity serialization failed"))?;
    Ok(hash(b"TITAN-FWD-F03\0preconditions-v1\0", &material))
}

fn exact_bindings(
    input: &FixtureAdmissionInput<'_>,
    contract: &ExecutionContract,
) -> FixtureResult<(String, String)> {
    let project = project_payload(input.project)?;
    let actor = actor_payload(input.actor)?;
    if input.seed.digest()? != input.authority_state.seed_digest {
        return Err(block(
            BlockedCode::AuthorityStale,
            "F02 seed identity changed",
        ));
    }
    input.authority_state.verify_state_identity()?;
    if input.project.canonical_bytes() != input.seed.project_record
        || project.project_id != contract.project_binding_ref
        || project.project_id != input.authority_state.project_binding_id
        || project.state != BindingState::Active
        || input.target_policy.project_id != project.project_id
        || input.target_policy.project_digest != input.project.record().integrity
        || input.target_policy.project_uri != project.canonical_root
    {
        return Err(block(
            BlockedCode::TargetIdentityMismatch,
            "fixture project binding mismatch",
        ));
    }
    if actor.actor_id == contract.actor_ref && actor.revocation_ref.is_some() {
        return Err(block(BlockedCode::Revoked, "fixture actor revoked"));
    }
    if actor.actor_id != contract.actor_ref
        || !input
            .seed
            .actor_records
            .iter()
            .any(|bytes| bytes == input.actor.canonical_bytes())
    {
        return Err(block(
            BlockedCode::Unauthorized,
            "fixture actor binding mismatch",
        ));
    }
    let epoch = input.preconditions.fixture_epoch_ms;
    if epoch < actor.valid_from_ms || actor.valid_until_ms.is_some_and(|end| epoch >= end) {
        return Err(block(
            BlockedCode::Unauthorized,
            "fixture actor validity interval expired",
        ));
    }
    Ok((project.project_id.clone(), actor.actor_id.clone()))
}

fn check_target(
    input: &FixtureAdmissionInput<'_>,
    contract: &ExecutionContract,
) -> FixtureResult<FixtureTargetSnapshotV1> {
    if input.target_policy.target_id != contract.target_ref {
        return Err(block(
            BlockedCode::TargetIdentityMismatch,
            "contract target mismatch",
        ));
    }
    let observed = construct_fixture_target_snapshot(input.target_policy)?;
    if observed.target_id != contract.target_ref {
        return Err(block(
            BlockedCode::TargetIdentityMismatch,
            "observed target mismatch",
        ));
    }
    if observed.state_id != contract.expected_target_state {
        return Err(block(
            BlockedCode::PreconditionDrift,
            "fixture target state changed",
        ));
    }
    Ok(observed)
}

fn check_scopes(
    input: &FixtureAdmissionInput<'_>,
    contract: &ExecutionContract,
    project_id: &str,
) -> FixtureResult<(Vec<NormalizedSelector>, Vec<NormalizedSelector>)> {
    if !code(input.requested_capability)
        || !code(input.requested_operation)
        || input.requested_capability != contract.capability_code
        || !contract
            .allowed_operations
            .iter()
            .any(|op| op == input.requested_operation)
    {
        return Err(block(
            BlockedCode::ScopeViolation,
            "capability or operation not declared",
        ));
    }
    if (input.network_requested && !contract.network_allowed)
        || (input.secret_requested && !contract.secret_access_allowed)
        || (input.cross_surface_requested && !contract.cross_surface_delivery_allowed)
    {
        return Err(block(
            BlockedCode::ScopeViolation,
            "requested consequence flag disallowed",
        ));
    }
    let profile = &input.authority_state.profile;
    let read = normalize_scopes(
        input.requested_read_scopes,
        project_id,
        input.requested_operation,
        "READ_RESOURCE",
        profile,
    )?;
    let mutation = normalize_scopes(
        input.requested_mutation_scopes,
        project_id,
        input.requested_operation,
        "MUTATE_RESOURCE",
        profile,
    )?;
    if read.is_empty() && mutation.is_empty() {
        return Err(invalid("fixture request must name at least one scope"));
    }
    let allowed_read = normalize_contract_scopes(
        &contract.read_scopes,
        project_id,
        input.requested_operation,
        "READ_RESOURCE",
        profile,
    )?;
    let allowed_mutation = normalize_contract_scopes(
        &contract.allowed_mutations,
        project_id,
        input.requested_operation,
        "MUTATE_RESOURCE",
        profile,
    )?;
    let prohibited = normalize_contract_scopes(
        &contract.prohibited_mutations,
        project_id,
        input.requested_operation,
        "MUTATE_RESOURCE",
        profile,
    )?;
    if (!read.is_empty() && !set_is_subset(&read, &allowed_read))
        || (!mutation.is_empty() && !set_is_subset(&mutation, &allowed_mutation))
        || !compare_fixture_sets(&mutation, &prohibited)
            .intersection
            .is_empty()
    {
        return Err(block(
            BlockedCode::ScopeViolation,
            "requested fixture scope outside contract bounds",
        ));
    }
    Ok((read, mutation))
}

fn governing_resolution(
    input: &FixtureAdmissionInput<'_>,
    request: &[NormalizedSelector],
) -> FixtureResult<String> {
    let fresh = resolve_fixture_request(
        input.authority_state,
        &input.authority_state.state_id,
        request,
    )?;
    if input.supplied_resolution.authority_state_id != input.authority_state.state_id {
        return Err(block(
            BlockedCode::AuthorityStale,
            "supplied F02 state ID stale",
        ));
    }
    if *input.supplied_resolution != fresh
        || fresh.cells.is_empty()
        || fresh
            .cells
            .iter()
            .any(|resolved| !set_contains_cell(request, &resolved.cell))
    {
        return Err(block(
            BlockedCode::Unauthorized,
            "partial or mismatched F02 result",
        ));
    }
    if fresh
        .cells
        .iter()
        .any(|resolved| resolved.provision != Provision::Permit)
    {
        return Err(block(
            BlockedCode::Unauthorized,
            "F02 outcome is not a PERMIT",
        ));
    }
    let mut selectors = request.to_vec();
    selectors.sort();
    selectors.dedup();
    let bytes = serde_json::to_vec(&(selectors, &fresh))
        .map_err(|_| invalid("F02 governing resolution serialization failed"))?;
    Ok(hash(b"TITAN-FWD-F03\0governing-resolution-v1\0", &bytes))
}

/// Construct only an inert synthetic admission; no execution path exists here.
pub fn evaluate_fixture_admission(
    input: &FixtureAdmissionInput<'_>,
) -> FixtureResult<FixtureAdmissionV1> {
    let validation = validate_fixture_contract(input.contract, &input.authority_state.profile)?;
    let contract = contract_payload(input.contract)?;
    if input.expected_contract_id != validation.contract_id
        || input.expected_contract_digest != validation.contract_digest
    {
        return Err(invalid("fixture contract identity or digest mismatch"));
    }
    let (project_id, actor_id) = exact_bindings(input, contract)?;
    let target = check_target(input, contract)?;
    let (read, mutation) = check_scopes(input, contract, &project_id)?;
    let precondition_snapshot_id = precondition_id(
        contract,
        input.preconditions,
        &target.state_id,
        &input.authority_state.state_id,
    )?;
    let request = read
        .iter()
        .chain(mutation.iter())
        .cloned()
        .collect::<Vec<_>>();
    let governing_resolution_id = governing_resolution(input, &request)?;
    let mut result = FixtureAdmissionV1 {
        marker: ADMISSION_MARKER.into(),
        version: ADMISSION_VERSION,
        namespace: "FIXTURE".into(),
        project_id,
        project_digest: input.project.record().integrity.clone(),
        actor_id,
        actor_digest: input.actor.record().integrity.clone(),
        contract_id: validation.contract_id,
        contract_digest: validation.contract_digest,
        target_id: target.target_id,
        target_root: target.canonical_root,
        target_relative_path: target.relative_marker_path,
        target_state_id: target.state_id,
        capability: input.requested_capability.to_owned(),
        operation: input.requested_operation.to_owned(),
        read_selectors: read,
        mutation_selectors: mutation,
        network_requested: input.network_requested,
        secret_requested: input.secret_requested,
        cross_surface_requested: input.cross_surface_requested,
        seed_digest: input.seed.digest()?,
        authority_state_id: input.authority_state.state_id.clone(),
        governing_resolution_id,
        precondition_snapshot_id,
        admission_id: String::new(),
    };
    let bytes = result.canonical_bytes()?;
    result.admission_id = format!(
        "fx:admission:{}",
        hash(b"TITAN-FWD-F03\0admission-v1\0", &bytes).trim_start_matches("sha256:")
    );
    Ok(result)
}

/// Decode only when the complete current synthetic basis reproduces the record.
/// Serialized bytes cannot manufacture a validated admission or an effect.
pub fn decode_fixture_admission(
    bytes: &[u8],
    current: &FixtureAdmissionInput<'_>,
) -> FixtureResult<FixtureAdmissionV1> {
    let decoded: FixtureAdmissionV1 =
        serde_json::from_slice(bytes).map_err(|_| invalid("fixture admission malformed"))?;
    if decoded.marker != ADMISSION_MARKER
        || decoded.version != ADMISSION_VERSION
        || decoded.namespace != "FIXTURE"
        || decoded.canonical_bytes()? != bytes
    {
        return Err(invalid(
            "fixture admission marker or canonical form invalid",
        ));
    }
    let expected = evaluate_fixture_admission(current)?;
    if decoded != expected {
        return Err(block(
            BlockedCode::PreconditionDrift,
            "fixture admission basis mismatch",
        ));
    }
    Ok(decoded)
}

/// Pure revalidation. A changed input never refreshes the stored admission.
pub fn revalidate_fixture_admission(
    admission: &FixtureAdmissionV1,
    current: &FixtureAdmissionInput<'_>,
) -> FixtureResult<()> {
    let reevaluated =
        evaluate_fixture_admission(current).map_err(|failure| match failure.code {
            BlockedCode::AuthorityStale
            | BlockedCode::BlockedAuthorityConflict
            | BlockedCode::BlockedNoActiveGoverningAuthority
            | BlockedCode::TargetIdentityMismatch
            | BlockedCode::EnvironmentFailure
            | BlockedCode::PreconditionDrift
            | BlockedCode::InsufficientEvidence => failure,
            _ => block(
                BlockedCode::PreconditionDrift,
                "stored admission dependency changed",
            ),
        })?;
    if &reevaluated != admission {
        return Err(block(
            BlockedCode::PreconditionDrift,
            "stored fixture admission is stale",
        ));
    }
    Ok(())
}
