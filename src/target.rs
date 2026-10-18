//! Read-only observation of one disposable F03 fixture target.

use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    authority::{FixtureFailure, FixtureResult, invalid},
    outcome::BlockedCode,
};

pub const APPROVED_FIXTURE_ROOT: &str =
    concat!(env!("OUT_DIR"), "/f03-fixtures");

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureTargetPolicyV1 {
    pub project_id: String,
    pub project_digest: String,
    pub project_uri: String,
    pub approved_root: PathBuf,
    pub target_id: String,
    pub relative_marker_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureTargetMarkerV1 {
    pub namespace: String,
    pub target_id: String,
    pub revision: String,
    pub state_code: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FixtureTargetSnapshotV1 {
    pub project_id: String,
    pub project_digest: String,
    pub project_uri: String,
    pub canonical_root: String,
    pub relative_marker_path: String,
    pub target_id: String,
    pub revision: String,
    pub state_code: String,
    pub marker_sha256: String,
    pub state_id: String,
}

fn mismatch(reason: &'static str) -> FixtureFailure {
    FixtureFailure::new(BlockedCode::TargetIdentityMismatch, reason)
}

fn environment(reason: &'static str) -> FixtureFailure {
    FixtureFailure::new(BlockedCode::EnvironmentFailure, reason)
}

fn digest(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

fn marker_relative(path: &Path, target_id: &str) -> FixtureResult<String> {
    let slug = target_id
        .strip_prefix("fx:target:")
        .filter(|slug| valid_slug(slug))
        .ok_or_else(|| mismatch("invalid fixture target ID"))?;
    let components = path.components().collect::<Vec<_>>();
    let file_name = format!("{slug}.json");
    if components.len() != 2
        || !matches!(components[0], Component::Normal(value) if value == "targets")
        || !matches!(components[1], Component::Normal(value) if value.to_str() == Some(file_name.as_str()))
    {
        return Err(mismatch(
            "target marker locator outside closed fixture profile",
        ));
    }
    Ok(format!("targets/{slug}.json"))
}

fn is_reparse(path: &Path) -> FixtureResult<bool> {
    let meta = fs::symlink_metadata(path).map_err(|_| mismatch("fixture path unresolved"))?;
    if meta.file_type().is_symlink() {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(meta.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}

fn check_marker(marker: &FixtureTargetMarkerV1, expected_id: &str) -> FixtureResult<()> {
    if marker.namespace != "FIXTURE" || marker.target_id != expected_id {
        return Err(mismatch("fixture marker identity mismatch"));
    }
    let valid_revision = match marker.state_code.as_str() {
        "UNBORN" => marker.revision == "none",
        "COMMITTED" => marker.revision.strip_prefix('r').is_some_and(|digits| {
            !digits.is_empty() && digits.len() <= 30 && digits.bytes().all(|b| b.is_ascii_digit())
        }),
        _ => false,
    };
    if !valid_revision {
        return Err(invalid("fixture target state/revision unsupported"));
    }
    Ok(())
}

/// Reads only the exact, isolated fixture marker. No target or repository write.
pub fn construct_fixture_target_snapshot(
    policy: &FixtureTargetPolicyV1,
) -> FixtureResult<FixtureTargetSnapshotV1> {
    if policy.approved_root != Path::new(APPROVED_FIXTURE_ROOT)
        || !policy.project_id.starts_with("fx:project:")
        || !policy.project_uri.starts_with("fixture://project/")
    {
        return Err(mismatch("fixture root or project policy mismatch"));
    }
    let relative = marker_relative(&policy.relative_marker_path, &policy.target_id)?;
    let root = &policy.approved_root;
    for ancestor in root.ancestors() {
        if is_reparse(ancestor)? {
            return Err(mismatch("fixture root ancestor is reparse point"));
        }
    }
    let targets = root.join("targets");
    if is_reparse(&targets)? {
        return Err(mismatch("fixture target directory is reparse point"));
    }
    let marker_path = root.join(&policy.relative_marker_path);
    if is_reparse(&marker_path)? {
        return Err(mismatch("fixture marker is reparse point"));
    }
    let canonical_root = fs::canonicalize(root).map_err(|_| mismatch("fixture root unresolved"))?;
    let canonical_marker =
        fs::canonicalize(&marker_path).map_err(|_| mismatch("fixture marker unresolved"))?;
    if !canonical_marker.starts_with(&canonical_root) {
        return Err(mismatch("fixture marker escaped approved root"));
    }
    let before = fs::metadata(&marker_path).map_err(|_| mismatch("fixture marker unresolved"))?;
    if !before.is_file() {
        return Err(mismatch("fixture marker is not regular file"));
    }
    let bytes = fs::read(&marker_path).map_err(|_| environment("fixture marker read failed"))?;
    if bytes.is_empty() || bytes.len() > 65_536 {
        return Err(invalid("fixture marker size unsupported"));
    }
    let after = fs::metadata(&marker_path)
        .map_err(|_| environment("fixture marker changed during read"))?;
    if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
        return Err(environment("fixture marker changed during read"));
    }
    if is_reparse(&marker_path)?
        || fs::canonicalize(&marker_path).ok().as_ref() != Some(&canonical_marker)
        || fs::canonicalize(root).ok().as_ref() != Some(&canonical_root)
    {
        return Err(environment("fixture path changed during observation"));
    }
    let marker: FixtureTargetMarkerV1 =
        serde_json::from_slice(&bytes).map_err(|_| invalid("fixture marker malformed"))?;
    if serde_json::to_vec(&marker).map_err(|_| invalid("fixture marker serialization failed"))?
        != bytes
    {
        return Err(invalid("fixture marker noncanonical"));
    }
    check_marker(&marker, &policy.target_id)?;
    let marker_sha256 = digest(b"TITAN-FWD-F03\0target-marker-v1\0", &bytes);
    let root_string = canonical_root.to_string_lossy().into_owned();
    let identity_bytes = serde_json::to_vec(&(
        &policy.project_id,
        &policy.project_digest,
        &policy.project_uri,
        &root_string,
        &relative,
        &marker.target_id,
        &marker.revision,
        &marker.state_code,
        &marker_sha256,
    ))
    .map_err(|_| invalid("target identity serialization failed"))?;
    let state_id = format!(
        "fx-state-v1:{}",
        digest(b"TITAN-FWD-F03\0target-state-v1\0", &identity_bytes)
    );
    Ok(FixtureTargetSnapshotV1 {
        project_id: policy.project_id.clone(),
        project_digest: policy.project_digest.clone(),
        project_uri: policy.project_uri.clone(),
        canonical_root: root_string,
        relative_marker_path: relative,
        target_id: marker.target_id,
        revision: marker.revision,
        state_code: marker.state_code,
        marker_sha256,
        state_id,
    })
}
