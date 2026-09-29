//! Synthetic, replayable authority-event projection. It authenticates nobody.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    ValidatedRecord,
    authority::{
        FixtureFailure, FixtureResult, ProjectedClaim, ProjectedEdge, ReinstatementReceipt,
        derive_claim_id, derive_edge_id, invalid, validate_selector_set,
    },
    codec::validate_bytes,
    records::{
        ActorBinding, AuthorityClass, AuthorityRecord, BindingState, ClaimAtom, OverrideEdge,
        ProjectBinding, Provision, RecordPayload, Role,
    },
    selector::{
        NormalizedSelector, SelectorProfileV1, compare_fixture_sets, normalize_fixture_selector,
        set_is_equal, set_is_subset,
    },
};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IssuerScopeV1 {
    pub actor_id: String,
    pub role: Role,
    pub claim_scope: Vec<NormalizedSelector>,
    pub override_scope: Vec<NormalizedSelector>,
    pub revocation_scope: Vec<NormalizedSelector>,
    pub reinstatement_scope: Vec<NormalizedSelector>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureAuthoritySeedV1 {
    pub project_record: Vec<u8>,
    pub actor_records: Vec<Vec<u8>>,
    pub profile: SelectorProfileV1,
    pub issuers: Vec<IssuerScopeV1>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum FixtureEventKind {
    ClaimAcceptance,
    OverrideAcceptance,
    SuccessorRevocation,
    ExplicitReinstatement,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureEventV1 {
    pub event_id: String,
    pub kind: FixtureEventKind,
    pub record_id: String,
    pub record_digest: String,
    pub issuer_actor_id: String,
    pub expected_prior_state_id: String,
    pub target_claim_id: Option<String>,
    pub target_edge_id: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureProjection {
    pub seed_digest: String,
    pub project_binding_id: String,
    pub profile: SelectorProfileV1,
    pub claims: BTreeMap<String, ProjectedClaim>,
    pub edges: BTreeMap<String, ProjectedEdge>,
    pub accepted_records: BTreeMap<String, String>,
    pub accepted_events: Vec<FixtureEventV1>,
    pub state_id: String,
}

#[derive(Serialize)]
struct StateMaterial<'a> {
    seed_digest: &'a str,
    project_binding_id: &'a str,
    normalizer_version: u32,
    compatibility_version: u32,
    alias_digest: String,
    catalog_digest: String,
    claims: &'a BTreeMap<String, ProjectedClaim>,
    edges: &'a BTreeMap<String, ProjectedEdge>,
    accepted_records: &'a BTreeMap<String, String>,
    accepted_events: &'a [FixtureEventV1],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct FixtureSnapshotV1 {
    seed: FixtureAuthoritySeedV1,
    authority_records: Vec<Vec<u8>>,
    events: Vec<FixtureEventV1>,
    expected_projection: FixtureProjection,
}

fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn event_id_valid(value: &str) -> bool {
    let Some(slug) = value.strip_prefix("fx:event:") else {
        return false;
    };
    !slug.is_empty()
        && slug.len() <= 64
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn record(bytes: &[u8]) -> FixtureResult<ValidatedRecord> {
    validate_bytes(bytes).map_err(|_| invalid("invalid F01 fixture record"))
}

fn project_binding(seed: &FixtureAuthoritySeedV1) -> FixtureResult<ProjectBinding> {
    let project = record(&seed.project_record)?;
    let RecordPayload::ProjectBinding(binding) = &project.record().payload else {
        return Err(invalid("seed project record type mismatch"));
    };
    if binding.state != BindingState::Active {
        return Err(invalid("fixture project binding is not active"));
    }
    Ok(binding.clone())
}

fn actor_bindings(seed: &FixtureAuthoritySeedV1) -> FixtureResult<BTreeMap<String, ActorBinding>> {
    let mut result = BTreeMap::new();
    for bytes in &seed.actor_records {
        let actor = record(bytes)?;
        let RecordPayload::ActorBinding(binding) = &actor.record().payload else {
            return Err(invalid("seed actor record type mismatch"));
        };
        if result
            .insert(binding.actor_id.clone(), binding.clone())
            .is_some()
        {
            return Err(invalid("duplicate seed actor"));
        }
    }
    Ok(result)
}

impl FixtureAuthoritySeedV1 {
    pub fn validate(&self) -> FixtureResult<String> {
        self.profile
            .validate()
            .map_err(|_| invalid("invalid fixture profile"))?;
        let project = project_binding(self)?;
        let actors = actor_bindings(self)?;
        if self.issuers.is_empty() {
            return Err(invalid("synthetic issuer scope required"));
        }
        let mut seen = BTreeSet::new();
        for issuer in &self.issuers {
            let Some(actor) = actors.get(&issuer.actor_id) else {
                return Err(invalid("issuer not present in F01 actor bindings"));
            };
            if !seen.insert(&issuer.actor_id)
                || !actor.roles.contains(&issuer.role)
                || actor.revocation_ref.is_some()
            {
                return Err(invalid("invalid fixture issuer"));
            }
            for scopes in [
                &issuer.claim_scope,
                &issuer.override_scope,
                &issuer.revocation_scope,
                &issuer.reinstatement_scope,
            ] {
                if !scopes.is_empty() {
                    validate_selector_set(scopes, &project.project_id, &self.profile)?;
                }
            }
        }
        Ok(project.project_id)
    }

    pub fn digest(&self) -> FixtureResult<String> {
        let project_id = self.validate()?;
        let mut actors = self.actor_records.clone();
        actors.sort();
        let mut issuers = self.issuers.clone();
        issuers.sort_by(|a, b| a.actor_id.cmp(&b.actor_id));
        for issuer in &mut issuers {
            issuer.claim_scope.sort();
            issuer.override_scope.sort();
            issuer.revocation_scope.sort();
            issuer.reinstatement_scope.sort();
        }
        let material = (
            project_id,
            &self.project_record,
            actors,
            issuers,
            self.profile.normalizer_version,
            self.profile.compatibility_version,
            self.profile
                .alias_digest()
                .map_err(|_| invalid("invalid aliases"))?,
            self.profile
                .catalog_digest()
                .map_err(|_| invalid("invalid catalog"))?,
        );
        let bytes =
            serde_json::to_vec(&material).map_err(|_| invalid("seed serialization failed"))?;
        Ok(hash(b"TITAN-FWD-F02\0seed-v1\0", &bytes))
    }
}

impl FixtureProjection {
    pub fn from_seed(seed: &FixtureAuthoritySeedV1) -> FixtureResult<Self> {
        let mut state = Self {
            seed_digest: seed.digest()?,
            project_binding_id: seed.validate()?,
            profile: seed.profile.clone(),
            claims: BTreeMap::new(),
            edges: BTreeMap::new(),
            accepted_records: BTreeMap::new(),
            accepted_events: Vec::new(),
            state_id: String::new(),
        };
        state.refresh_state_id()?;
        Ok(state)
    }

    fn refresh_state_id(&mut self) -> FixtureResult<()> {
        let material = StateMaterial {
            seed_digest: &self.seed_digest,
            project_binding_id: &self.project_binding_id,
            normalizer_version: self.profile.normalizer_version,
            compatibility_version: self.profile.compatibility_version,
            alias_digest: self
                .profile
                .alias_digest()
                .map_err(|_| invalid("invalid aliases"))?,
            catalog_digest: self
                .profile
                .catalog_digest()
                .map_err(|_| invalid("invalid catalog"))?,
            claims: &self.claims,
            edges: &self.edges,
            accepted_records: &self.accepted_records,
            accepted_events: &self.accepted_events,
        };
        let bytes =
            serde_json::to_vec(&material).map_err(|_| invalid("state serialization failed"))?;
        self.state_id = hash(b"TITAN-FWD-F02\0authority-state-v1\0", &bytes);
        Ok(())
    }

    pub fn verify_state_identity(&self) -> FixtureResult<()> {
        let mut checked = self.clone();
        checked.refresh_state_id().map_err(|_| {
            crate::authority::conflict("accepted fixture state dependency is undecidable")
        })?;
        if checked.state_id != self.state_id {
            return Err(crate::authority::conflict(
                "fixture authority state identity changed",
            ));
        }
        Ok(())
    }
}

fn normalized_atoms(
    atoms: &[ClaimAtom],
    state: &FixtureProjection,
    required_provision: Option<Provision>,
) -> FixtureResult<Vec<NormalizedSelector>> {
    if atoms.is_empty() {
        return Err(invalid("event claims required"));
    }
    let mut result = Vec::new();
    for atom in atoms {
        if atom.project_binding_ref != state.project_binding_id
            || required_provision
                .as_ref()
                .is_some_and(|p| *p != atom.provision)
        {
            return Err(invalid("event atom project/provision mismatch"));
        }
        result.extend(
            normalize_fixture_selector(atom, &state.profile)
                .map_err(|_| invalid("unsupported event selector"))?,
        );
    }
    result.sort();
    result.dedup();
    Ok(result)
}

fn active_provision(provision: &Provision) -> bool {
    matches!(
        provision,
        Provision::Permit | Provision::Forbid | Provision::Approve
    )
}

fn proposed_claims(
    authority: &AuthorityRecord,
    state: &FixtureProjection,
) -> FixtureResult<Vec<ProjectedClaim>> {
    let mut result = Vec::new();
    let mut normalized_seen = BTreeSet::new();
    for atom in &authority.claim_atoms {
        if !active_provision(&atom.provision) {
            return Err(invalid("non-governing provision in claim event"));
        }
        let selectors = normalized_atoms(std::slice::from_ref(atom), state, None)?;
        let key = serde_json::to_vec(&(selectors.clone(), &atom.provision))
            .map_err(|_| invalid("claim serialization failed"))?;
        if !normalized_seen.insert(key) {
            return Err(invalid("duplicate normalized claim atom"));
        }
        result.push(ProjectedClaim {
            id: derive_claim_id(&authority.authority_id, atom, &state.profile)?,
            source_record_id: authority.authority_id.clone(),
            selectors,
            provision: atom.provision.clone(),
            revoked: false,
        });
    }
    if result.is_empty() {
        return Err(invalid("claim event has no claims"));
    }
    Ok(result)
}

fn issuer_scope<'a>(
    seed: &'a FixtureAuthoritySeedV1,
    event: &FixtureEventV1,
    authority: &AuthorityRecord,
) -> FixtureResult<&'a IssuerScopeV1> {
    let issuer = seed
        .issuers
        .iter()
        .find(|item| item.actor_id == event.issuer_actor_id)
        .ok_or_else(|| invalid("event issuer not in prior synthetic seed"))?;
    let actors = actor_bindings(seed)?;
    let actor = actors
        .get(&issuer.actor_id)
        .ok_or_else(|| invalid("event actor binding missing"))?;
    if authority.issuer_actor_ref != issuer.actor_id
        || authority.exercised_role != issuer.role
        || authority.effective_at_ms < actor.valid_from_ms
        || actor
            .valid_until_ms
            .is_some_and(|end| authority.effective_at_ms >= end)
    {
        return Err(invalid("event issuer/role/fixture interval mismatch"));
    }
    Ok(issuer)
}

fn within_scope(items: &[NormalizedSelector], scope: &[NormalizedSelector]) -> bool {
    !scope.is_empty() && set_is_subset(items, scope)
}

fn override_cycle(edges: &BTreeMap<String, ProjectedEdge>) -> bool {
    for edge in edges.values() {
        let start = &edge.successor_claim_id;
        let target = &edge.predecessor_claim_id;
        if start == target {
            return true;
        }
        let mut seen = BTreeSet::new();
        let mut pending = vec![start.clone()];
        while let Some(current) = pending.pop() {
            if &current == target {
                return true;
            }
            if seen.insert(current.clone()) {
                pending.extend(
                    edges
                        .values()
                        .filter(|item| item.predecessor_claim_id == current)
                        .map(|item| item.successor_claim_id.clone()),
                );
            }
        }
    }
    false
}

fn override_edge(
    edge: &OverrideEdge,
    record_id: &str,
    state: &FixtureProjection,
    issuer: &IssuerScopeV1,
    successor_ids: &BTreeSet<String>,
) -> FixtureResult<ProjectedEdge> {
    let predecessor = state
        .claims
        .get(&edge.predecessor_claim_ref)
        .ok_or_else(|| invalid("override predecessor missing"))?;
    let successor = state
        .claims
        .get(&edge.successor_claim_ref)
        .ok_or_else(|| invalid("override successor missing"))?;
    if !successor_ids.contains(&successor.id)
        || predecessor.revoked
        || predecessor.provision == successor.provision
    {
        return Err(invalid("override relationship invalid"));
    }
    let coverage = normalized_atoms(
        &edge.coverage_atoms,
        state,
        Some(successor.provision.clone()),
    )?;
    if !set_is_subset(&coverage, &predecessor.selectors)
        || !set_is_subset(&coverage, &successor.selectors)
        || !within_scope(&coverage, &issuer.override_scope)
    {
        return Err(invalid(
            "override coverage exceeds intersection or issuer scope",
        ));
    }
    Ok(ProjectedEdge {
        id: derive_edge_id(record_id, edge, &state.profile)?,
        source_record_id: record_id.to_owned(),
        predecessor_claim_id: predecessor.id.clone(),
        successor_claim_id: successor.id.clone(),
        coverage,
        reinstatements: Vec::new(),
    })
}

/// Apply one accepted fixture event transactionally. Failure leaves `state` byte-for-byte unchanged.
pub fn apply_fixture_event(
    state: &mut FixtureProjection,
    seed: &FixtureAuthoritySeedV1,
    authority_record: &ValidatedRecord,
    event: &FixtureEventV1,
) -> FixtureResult<()> {
    state.verify_state_identity()?;
    if state.seed_digest != seed.digest()? || state.project_binding_id != seed.validate()? {
        return Err(invalid("fixture seed changed"));
    }
    if event.expected_prior_state_id != state.state_id {
        return Err(FixtureFailure::new(
            crate::outcome::BlockedCode::AuthorityStale,
            "fixture event prior state mismatch",
        ));
    }
    if !event_id_valid(&event.event_id)
        || state
            .accepted_events
            .iter()
            .any(|old| old.event_id == event.event_id)
        || authority_record.record().record_id != event.record_id
        || authority_record.record().integrity != event.record_digest
        || state.accepted_records.contains_key(&event.record_id)
    {
        return Err(invalid("duplicate or mismatched fixture event/record"));
    }
    let RecordPayload::AuthorityRecord(authority) = &authority_record.record().payload else {
        return Err(invalid("event requires F01 AuthorityRecord"));
    };
    if authority.authority_id != event.record_id
        || authority.target_binding_ref.as_deref() != Some(&state.project_binding_id)
    {
        return Err(invalid("authority record identity/binding mismatch"));
    }
    let issuer = issuer_scope(seed, event, authority)?;
    let mut next = state.clone();
    match event.kind {
        FixtureEventKind::ClaimAcceptance => {
            if authority.class != AuthorityClass::Decision
                || !authority.override_edges.is_empty()
                || event.target_claim_id.is_some()
                || event.target_edge_id.is_some()
            {
                return Err(invalid("claim event shape invalid"));
            }
            let claims = proposed_claims(authority, &next)?;
            for claim in claims {
                if !within_scope(&claim.selectors, &issuer.claim_scope)
                    || next.claims.insert(claim.id.clone(), claim).is_some()
                {
                    return Err(invalid("claim exceeds issuer scope or duplicates ID"));
                }
            }
        }
        FixtureEventKind::OverrideAcceptance => {
            if authority.class != AuthorityClass::Decision
                || authority.override_edges.is_empty()
                || event.target_claim_id.is_some()
                || event.target_edge_id.is_some()
            {
                return Err(invalid("override event shape invalid"));
            }
            let claims = proposed_claims(authority, &next)?;
            let successor_ids = claims
                .iter()
                .map(|claim| claim.id.clone())
                .collect::<BTreeSet<_>>();
            for claim in claims {
                if !within_scope(&claim.selectors, &issuer.claim_scope)
                    || next.claims.insert(claim.id.clone(), claim).is_some()
                {
                    return Err(invalid("successor claim outside scope or duplicate"));
                }
            }
            for edge in &authority.override_edges {
                let projected =
                    override_edge(edge, &event.record_id, &next, issuer, &successor_ids)?;
                if next.edges.insert(projected.id.clone(), projected).is_some() {
                    return Err(invalid("duplicate override edge"));
                }
            }
            let linked_successors = authority
                .override_edges
                .iter()
                .map(|edge| edge.successor_claim_ref.clone())
                .collect::<BTreeSet<_>>();
            if linked_successors != successor_ids {
                return Err(invalid("unlinked successor claim in override event"));
            }
            if override_cycle(&next.edges) {
                return Err(invalid("override cycle"));
            }
        }
        FixtureEventKind::SuccessorRevocation => {
            if authority.class != AuthorityClass::Revocation
                || !authority.override_edges.is_empty()
                || event.target_edge_id.is_some()
            {
                return Err(invalid("successor revocation shape invalid"));
            }
            let target = event
                .target_claim_id
                .as_ref()
                .ok_or_else(|| invalid("revocation target missing"))?;
            let coverage =
                normalized_atoms(&authority.claim_atoms, &next, Some(Provision::Revoke))?;
            let Some(claim) = next.claims.get_mut(target) else {
                return Err(invalid("revocation target claim missing"));
            };
            if claim.revoked
                || !next
                    .edges
                    .values()
                    .any(|edge| edge.successor_claim_id == *target)
                || !set_is_equal(&coverage, &claim.selectors)
                || !within_scope(&coverage, &issuer.revocation_scope)
            {
                return Err(invalid("revocation target/coverage/scope invalid"));
            }
            claim.revoked = true;
        }
        FixtureEventKind::ExplicitReinstatement => {
            if authority.class != AuthorityClass::Reinstatement
                || !authority.override_edges.is_empty()
                || event.target_claim_id.is_some()
            {
                return Err(invalid("reinstatement event shape invalid"));
            }
            let target = event
                .target_edge_id
                .as_ref()
                .ok_or_else(|| invalid("reinstatement edge missing"))?;
            let coverage =
                normalized_atoms(&authority.claim_atoms, &next, Some(Provision::Reinstate))?;
            let Some(edge) = next.edges.get_mut(target) else {
                return Err(invalid("reinstatement edge not accepted"));
            };
            if next
                .claims
                .get(&edge.predecessor_claim_id)
                .is_none_or(|claim| claim.revoked)
                || !set_is_subset(&coverage, &edge.coverage)
                || !within_scope(&coverage, &issuer.reinstatement_scope)
                || edge.reinstatements.iter().any(|prior| {
                    !compare_fixture_sets(&coverage, &prior.selectors)
                        .intersection
                        .is_empty()
                })
            {
                return Err(invalid("reinstatement target/coverage/scope invalid"));
            }
            edge.reinstatements.push(ReinstatementReceipt {
                event_id: event.event_id.clone(),
                selectors: coverage,
            });
        }
    }
    next.accepted_records
        .insert(event.record_id.clone(), event.record_digest.clone());
    next.accepted_events.push(event.clone());
    next.refresh_state_id()?;
    *state = next;
    Ok(())
}

/// Presentation order does not determine event order: the unique prior-state chain does.
pub fn project_fixture_events(
    seed: &FixtureAuthoritySeedV1,
    authority_records: &[ValidatedRecord],
    events: &[FixtureEventV1],
) -> FixtureResult<FixtureProjection> {
    let mut state = FixtureProjection::from_seed(seed)?;
    let mut records = BTreeMap::new();
    for item in authority_records {
        if records
            .insert(item.record().record_id.clone(), item)
            .is_some()
        {
            return Err(invalid("duplicate F01 authority record"));
        }
    }
    let mut pending = events.iter().collect::<Vec<_>>();
    let mut ids = BTreeSet::new();
    if events.iter().any(|event| !ids.insert(&event.event_id)) {
        return Err(invalid("duplicate fixture event ID"));
    }
    while !pending.is_empty() {
        let matches = pending
            .iter()
            .enumerate()
            .filter(|(_, event)| event.expected_prior_state_id == state.state_id)
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if matches.len() != 1 {
            return Err(invalid("fixture event chain missing link or fork"));
        }
        let event = pending.remove(matches[0]);
        let item = records
            .get(&event.record_id)
            .ok_or_else(|| invalid("event F01 record missing"))?;
        apply_fixture_event(&mut state, seed, item, event)?;
    }
    if state.accepted_records.len() != records.len() {
        return Err(invalid("unreferenced F01 authority record"));
    }
    Ok(state)
}

/// The caller may persist these bytes only in the isolated fixture test directory.
pub fn fixture_snapshot_bytes(
    seed: &FixtureAuthoritySeedV1,
    authority_records: &[ValidatedRecord],
    events: &[FixtureEventV1],
) -> FixtureResult<Vec<u8>> {
    let projection = project_fixture_events(seed, authority_records, events)?;
    let mut records = authority_records
        .iter()
        .map(|item| item.canonical_bytes().to_vec())
        .collect::<Vec<_>>();
    records.sort();
    let snapshot = FixtureSnapshotV1 {
        seed: seed.clone(),
        authority_records: records,
        events: projection.accepted_events.clone(),
        expected_projection: projection,
    };
    serde_json::to_vec(&snapshot).map_err(|_| invalid("snapshot serialization failed"))
}

pub fn replay_fixture_projection(bytes: &[u8]) -> FixtureResult<FixtureProjection> {
    let snapshot: FixtureSnapshotV1 =
        serde_json::from_slice(bytes).map_err(|_| invalid("invalid fixture snapshot"))?;
    if serde_json::to_vec(&snapshot).map_err(|_| invalid("snapshot serialization failed"))? != bytes
    {
        return Err(invalid("noncanonical fixture snapshot"));
    }
    let records = snapshot
        .authority_records
        .iter()
        .map(|bytes| record(bytes))
        .collect::<FixtureResult<Vec<_>>>()?;
    let projection = project_fixture_events(&snapshot.seed, &records, &snapshot.events)?;
    if projection != snapshot.expected_projection {
        return Err(invalid("fixture replay state/mask mismatch"));
    }
    Ok(projection)
}
