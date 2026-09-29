//! Deterministic resolution over accepted synthetic authority state only.

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    fixture_projection::FixtureProjection,
    outcome::{BlockedCode, OutcomeVariant},
    records::{ClaimAtom, OverrideEdge, Provision},
    selector::{
        GovernedCell, NormalizedSelector, SelectorProfileV1, partition_cells, set_contains_cell,
    },
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureFailure {
    pub code: BlockedCode,
    pub reason: &'static str,
}

impl FixtureFailure {
    pub const fn new(code: BlockedCode, reason: &'static str) -> Self {
        Self { code, reason }
    }

    pub fn outcome(&self) -> OutcomeVariant {
        OutcomeVariant::Blocked(self.code.clone())
    }
}

pub type FixtureResult<T> = Result<T, FixtureFailure>;

pub fn invalid(reason: &'static str) -> FixtureFailure {
    FixtureFailure::new(BlockedCode::ContractInvalid, reason)
}

pub fn conflict(reason: &'static str) -> FixtureFailure {
    FixtureFailure::new(BlockedCode::BlockedAuthorityConflict, reason)
}

fn hash_parts(domain: &[u8], parts: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part);
    }
    format!("{:x}", hasher.finalize())
}

pub fn derive_claim_id(
    authority_id: &str,
    atom: &ClaimAtom,
    profile: &SelectorProfileV1,
) -> FixtureResult<String> {
    let bytes = serde_json::to_vec(atom).map_err(|_| invalid("claim serialization failed"))?;
    let alias = profile
        .alias_digest()
        .map_err(|_| invalid("invalid alias table"))?;
    let catalog = profile
        .catalog_digest()
        .map_err(|_| invalid("invalid catalog"))?;
    Ok(format!(
        "fx:claim:{}",
        hash_parts(
            b"TITAN-FWD-F02\0claim-id-v1\0",
            &[
                authority_id.as_bytes(),
                &bytes,
                &profile.normalizer_version.to_be_bytes(),
                &profile.compatibility_version.to_be_bytes(),
                alias.as_bytes(),
                catalog.as_bytes(),
            ],
        )
    ))
}

pub fn derive_edge_id(
    record_id: &str,
    edge: &OverrideEdge,
    profile: &SelectorProfileV1,
) -> FixtureResult<String> {
    let bytes = serde_json::to_vec(edge).map_err(|_| invalid("edge serialization failed"))?;
    let alias = profile
        .alias_digest()
        .map_err(|_| invalid("invalid alias table"))?;
    Ok(format!(
        "fx:edge:{}",
        hash_parts(
            b"TITAN-FWD-F02\0edge-id-v1\0",
            &[record_id.as_bytes(), &bytes, alias.as_bytes()],
        )
    ))
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectedClaim {
    pub id: String,
    pub source_record_id: String,
    pub selectors: Vec<NormalizedSelector>,
    pub provision: Provision,
    pub revoked: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ReinstatementReceipt {
    pub event_id: String,
    pub selectors: Vec<NormalizedSelector>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ProjectedEdge {
    pub id: String,
    pub source_record_id: String,
    pub predecessor_claim_id: String,
    pub successor_claim_id: String,
    pub coverage: Vec<NormalizedSelector>,
    pub reinstatements: Vec<ReinstatementReceipt>,
}

impl ProjectedEdge {
    pub fn suppresses(&self, claim_id: &str, cell: &GovernedCell) -> bool {
        self.predecessor_claim_id == claim_id
            && set_contains_cell(&self.coverage, cell)
            && !self
                .reinstatements
                .iter()
                .any(|receipt| set_contains_cell(&receipt.selectors, cell))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedCell {
    pub cell: GovernedCell,
    pub governing_claim_ids: Vec<String>,
    pub provision: Provision,
    pub effect: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResolvedFixtureOutcome {
    pub authority_state_id: String,
    pub cells: Vec<ResolvedCell>,
}

pub fn validate_selector_set(
    selectors: &[NormalizedSelector],
    project: &str,
    profile: &SelectorProfileV1,
) -> FixtureResult<()> {
    profile
        .validate()
        .map_err(|_| invalid("invalid selector profile"))?;
    if selectors.is_empty() {
        return Err(invalid("selector set is empty"));
    }
    for selector in selectors {
        if selector.project != project
            || !profile.actions.contains(&selector.action)
            || !profile.effects.contains(&selector.effect)
            || !profile.contexts.contains(&selector.context)
            || profile
                .canonical_resource(&selector.resource)
                .map_err(|_| invalid("invalid resource"))?
                != selector.resource
        {
            return Err(invalid("selector outside closed fixture profile"));
        }
    }
    Ok(())
}

/// A fixture result is not a grant. Any conflicted or ungoverned requested cell
/// blocks the entire request, so no partial resolved value escapes.
pub fn resolve_fixture_request(
    state: &FixtureProjection,
    expected_state_id: &str,
    request: &[NormalizedSelector],
) -> FixtureResult<ResolvedFixtureOutcome> {
    state.verify_state_identity()?;
    if expected_state_id != state.state_id {
        return Err(FixtureFailure::new(
            BlockedCode::AuthorityStale,
            "expected fixture authority state changed",
        ));
    }
    validate_selector_set(request, &state.project_binding_id, &state.profile)?;
    let sets = std::iter::once(request)
        .chain(
            state
                .claims
                .values()
                .map(|claim| claim.selectors.as_slice()),
        )
        .chain(state.edges.values().map(|edge| edge.coverage.as_slice()))
        .chain(state.edges.values().flat_map(|edge| {
            edge.reinstatements
                .iter()
                .map(|item| item.selectors.as_slice())
        }))
        .collect::<Vec<_>>();
    let mut resolved = Vec::new();
    for cell in partition_cells(&sets)
        .into_iter()
        .filter(|cell| set_contains_cell(request, cell))
    {
        let mut governors = state
            .claims
            .values()
            .filter(|claim| {
                !claim.revoked
                    && set_contains_cell(&claim.selectors, &cell)
                    && !state
                        .edges
                        .values()
                        .any(|edge| edge.suppresses(&claim.id, &cell))
            })
            .collect::<Vec<_>>();
        governors.sort_by(|a, b| a.id.cmp(&b.id));
        let Some(first) = governors.first() else {
            return Err(FixtureFailure::new(
                BlockedCode::BlockedNoActiveGoverningAuthority,
                "requested fixture cell has no active governor",
            ));
        };
        if governors
            .iter()
            .any(|claim| claim.provision != first.provision)
        {
            return Err(conflict("incompatible active claims overlap"));
        }
        resolved.push(ResolvedCell {
            cell: cell.clone(),
            governing_claim_ids: governors.iter().map(|claim| claim.id.clone()).collect(),
            provision: first.provision.clone(),
            effect: cell.effect.clone(),
        });
    }
    if resolved.is_empty() {
        return Err(invalid("request has no governed cells"));
    }
    Ok(ResolvedFixtureOutcome {
        authority_state_id: state.state_id.clone(),
        cells: resolved,
    })
}
