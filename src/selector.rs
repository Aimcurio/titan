//! Closed, synthetic selector algebra. No selector can name an operational path.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::records::{ClaimAtom, ResourceMatch};

pub const NORMALIZER_VERSION: u32 = 1;
pub const COMPATIBILITY_VERSION: u32 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AliasEntry {
    pub alias: String,
    pub canonical_resource: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct SelectorProfileV1 {
    pub normalizer_version: u32,
    pub compatibility_version: u32,
    pub actions: Vec<String>,
    pub effects: Vec<String>,
    pub contexts: Vec<String>,
    pub aliases: Vec<AliasEntry>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub enum ResourceKind {
    Exact,
    Subtree,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct NormalizedSelector {
    pub project: String,
    pub resource: String,
    pub resource_kind: ResourceKind,
    pub action: String,
    pub effect: String,
    pub context: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct ResourceCell {
    pub anchor: String,
    pub residual_descendants: bool,
    /// Immediate known child roots excluded from a residual descendant cell.
    pub excluded_children: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
pub struct GovernedCell {
    pub project: String,
    pub resource: ResourceCell,
    pub action: String,
    pub effect: String,
    pub context: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SetComparison {
    pub intersection: Vec<GovernedCell>,
    pub left_only: Vec<GovernedCell>,
    pub right_only: Vec<GovernedCell>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorError {
    UnsupportedVersion,
    InvalidCatalog,
    InvalidResource,
    InvalidAlias,
    UnsupportedCode,
}

fn code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.as_bytes()[0].is_ascii_uppercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

fn catalog(values: &[String]) -> bool {
    !values.is_empty()
        && values.iter().all(|value| code(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn valid_uri(value: &str, kind: &str) -> bool {
    let Some(path) = value.strip_prefix(kind) else {
        return false;
    };
    !path.is_empty()
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

impl SelectorProfileV1 {
    pub fn validate(&self) -> Result<(), SelectorError> {
        if self.normalizer_version != NORMALIZER_VERSION
            || self.compatibility_version != COMPATIBILITY_VERSION
        {
            return Err(SelectorError::UnsupportedVersion);
        }
        if !catalog(&self.actions) || !catalog(&self.effects) || !catalog(&self.contexts) {
            return Err(SelectorError::InvalidCatalog);
        }
        let mut seen = BTreeSet::new();
        for entry in &self.aliases {
            if !valid_uri(&entry.alias, "fixture://alias/")
                || !valid_uri(&entry.canonical_resource, "fixture://resource/")
                || !seen.insert(&entry.alias)
            {
                return Err(SelectorError::InvalidAlias);
            }
        }
        Ok(())
    }

    pub fn alias_digest(&self) -> Result<String, SelectorError> {
        self.validate()?;
        let aliases: BTreeMap<_, _> = self
            .aliases
            .iter()
            .map(|item| (&item.alias, &item.canonical_resource))
            .collect();
        let bytes = serde_json::to_vec(&aliases).map_err(|_| SelectorError::InvalidAlias)?;
        Ok(digest(b"TITAN-FWD-F02\0aliases-v1\0", &bytes))
    }

    pub fn catalog_digest(&self) -> Result<String, SelectorError> {
        self.validate()?;
        let values = (
            self.actions.iter().collect::<BTreeSet<_>>(),
            self.effects.iter().collect::<BTreeSet<_>>(),
            self.contexts.iter().collect::<BTreeSet<_>>(),
            self.compatibility_version,
        );
        let bytes = serde_json::to_vec(&values).map_err(|_| SelectorError::InvalidCatalog)?;
        Ok(digest(b"TITAN-FWD-F02\0catalog-v1\0", &bytes))
    }

    pub fn canonical_resource(&self, input: &str) -> Result<String, SelectorError> {
        self.validate()?;
        if valid_uri(input, "fixture://resource/") {
            return Ok(input.to_owned());
        }
        if !valid_uri(input, "fixture://alias/") {
            return Err(SelectorError::InvalidResource);
        }
        self.aliases
            .iter()
            .find(|entry| entry.alias == input)
            .map(|entry| entry.canonical_resource.clone())
            .ok_or(SelectorError::InvalidAlias)
    }
}

/// Expand one F01 atom's finite lifecycle contexts into canonical selector keys.
pub fn normalize_fixture_selector(
    atom: &ClaimAtom,
    profile: &SelectorProfileV1,
) -> Result<Vec<NormalizedSelector>, SelectorError> {
    profile.validate()?;
    if !profile.actions.contains(&atom.action)
        || !profile.effects.contains(&atom.effect)
        || atom.lifecycle_contexts.is_empty()
        || atom
            .lifecycle_contexts
            .iter()
            .any(|context| !profile.contexts.contains(context))
    {
        return Err(SelectorError::UnsupportedCode);
    }
    let resource = profile.canonical_resource(&atom.resource_ref)?;
    let resource_kind = match atom.resource_match {
        ResourceMatch::Exact => ResourceKind::Exact,
        ResourceMatch::Subtree => ResourceKind::Subtree,
    };
    let mut selectors = atom
        .lifecycle_contexts
        .iter()
        .map(|context| NormalizedSelector {
            project: atom.project_binding_ref.clone(),
            resource: resource.clone(),
            resource_kind,
            action: atom.action.clone(),
            effect: atom.effect.clone(),
            context: context.clone(),
        })
        .collect::<Vec<_>>();
    selectors.sort();
    selectors.dedup();
    Ok(selectors)
}

fn prefixes(uri: &str) -> Vec<String> {
    let path = uri.strip_prefix("fixture://resource/").unwrap_or("");
    let mut result = Vec::new();
    let mut current = String::from("fixture://resource");
    for part in path.split('/') {
        current.push('/');
        current.push_str(part);
        result.push(current.clone());
    }
    result
}

fn immediate_child(parent: &str, descendant: &str) -> bool {
    descendant
        .strip_prefix(parent)
        .and_then(|rest| rest.strip_prefix('/'))
        .is_some_and(|rest| !rest.contains('/'))
}

fn resource_cells(selectors: &[NormalizedSelector]) -> Vec<ResourceCell> {
    let nodes = selectors
        .iter()
        .flat_map(|selector| prefixes(&selector.resource))
        .collect::<BTreeSet<_>>();
    let mut cells = Vec::new();
    for node in &nodes {
        cells.push(ResourceCell {
            anchor: node.clone(),
            residual_descendants: false,
            excluded_children: Vec::new(),
        });
        let children = nodes
            .iter()
            .filter(|other| immediate_child(node, other))
            .cloned()
            .collect();
        cells.push(ResourceCell {
            anchor: node.clone(),
            residual_descendants: true,
            excluded_children: children,
        });
    }
    cells
}

fn resource_contains(selector: &NormalizedSelector, cell: &ResourceCell) -> bool {
    if selector.resource_kind == ResourceKind::Exact {
        return !cell.residual_descendants && selector.resource == cell.anchor;
    }
    cell.anchor == selector.resource
        || cell
            .anchor
            .strip_prefix(&selector.resource)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

pub fn selector_contains_cell(selector: &NormalizedSelector, cell: &GovernedCell) -> bool {
    selector.project == cell.project
        && selector.action == cell.action
        && selector.effect == cell.effect
        && selector.context == cell.context
        && resource_contains(selector, &cell.resource)
}

pub fn set_contains_cell(selectors: &[NormalizedSelector], cell: &GovernedCell) -> bool {
    selectors
        .iter()
        .any(|selector| selector_contains_cell(selector, cell))
}

/// Partition a finite collection of selector sets at every known resource boundary.
/// A residual descendant cell is symbolic and never assumed empty.
pub fn partition_cells(sets: &[&[NormalizedSelector]]) -> Vec<GovernedCell> {
    let all = sets
        .iter()
        .flat_map(|set| set.iter())
        .cloned()
        .collect::<Vec<_>>();
    let keys = all
        .iter()
        .map(|s| (&s.project, &s.action, &s.effect, &s.context))
        .collect::<BTreeSet<_>>();
    let resources = resource_cells(&all);
    let mut cells = Vec::new();
    for (project, action, effect, context) in keys {
        for resource in &resources {
            let cell = GovernedCell {
                project: project.clone(),
                resource: resource.clone(),
                action: action.clone(),
                effect: effect.clone(),
                context: context.clone(),
            };
            if all
                .iter()
                .any(|selector| selector_contains_cell(selector, &cell))
            {
                cells.push(cell);
            }
        }
    }
    cells.sort();
    cells.dedup();
    cells
}

pub fn compare_fixture_sets(
    left: &[NormalizedSelector],
    right: &[NormalizedSelector],
) -> SetComparison {
    let mut result = SetComparison {
        intersection: Vec::new(),
        left_only: Vec::new(),
        right_only: Vec::new(),
    };
    for cell in partition_cells(&[left, right]) {
        match (
            set_contains_cell(left, &cell),
            set_contains_cell(right, &cell),
        ) {
            (true, true) => result.intersection.push(cell),
            (true, false) => result.left_only.push(cell),
            (false, true) => result.right_only.push(cell),
            (false, false) => {}
        }
    }
    result
}

pub fn set_is_subset(left: &[NormalizedSelector], right: &[NormalizedSelector]) -> bool {
    compare_fixture_sets(left, right).left_only.is_empty()
}

pub fn set_is_equal(left: &[NormalizedSelector], right: &[NormalizedSelector]) -> bool {
    let comparison = compare_fixture_sets(left, right);
    comparison.left_only.is_empty() && comparison.right_only.is_empty()
}
