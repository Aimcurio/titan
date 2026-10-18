//! One closed synthetic handler. Availability is not authority.

use crate::{
    authority::{FixtureResult, invalid},
    evidence::{fail, hash},
    outcome::BlockedCode,
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const PROFILE: &str = "F05_FIXTURE_CAPABILITY_V1";
pub const CAPABILITY: &str = "FIXTURE_OPERATION";
pub const OPERATION: &str = "UPDATE";
pub const HANDLER: &str = "CREATE_FIXTURE_MARKER_V1";
pub const EFFECT: &str = "MUTATE_RESOURCE";
pub const READ_CAPABILITY: &str = "FIXTURE_READ_ONLY";
pub const READ_OPERATION: &str = "READ";
pub const READ_HANDLER: &str = "READ_FIXTURE_MARKER_V1";
pub const F05_ROOT: &str =
    concat!(env!("OUT_DIR"), "/f05-fixtures");

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureCapabilityV1 {
    pub profile: String,
    pub capability: String,
    pub operation: String,
    pub handler: String,
    pub effect: String,
    pub write_shape: String,
    pub resource_mapping: String,
    pub network: bool,
    pub secrets: bool,
    pub processes: bool,
    pub cross_surface: bool,
}
pub fn fixture_capability_v1() -> FixtureCapabilityV1 {
    FixtureCapabilityV1 {
        profile: PROFILE.into(),
        capability: CAPABILITY.into(),
        operation: OPERATION.into(),
        handler: HANDLER.into(),
        effect: EFFECT.into(),
        write_shape: "CREATE_NEW_ONE_CANONICAL_JSON_MARKER".into(),
        resource_mapping:
            "fixture://resource/lab/<case>/<leaf> -> cases/<case>/markers/<leaf>.json".into(),
        network: false,
        secrets: false,
        processes: false,
        cross_surface: false,
    }
}

/// Exactly two closed tuples. Registry availability does not grant either operation.
pub fn fixture_capabilities_v1() -> [FixtureCapabilityV1; 2] {
    let read = FixtureCapabilityV1 {
        profile: PROFILE.into(),
        capability: READ_CAPABILITY.into(),
        operation: READ_OPERATION.into(),
        handler: READ_HANDLER.into(),
        effect: "READ_RESOURCE".into(),
        write_shape: "NONE".into(),
        resource_mapping:
            "fixture://resource/lab/<case>/<leaf> -> cases/<case>/markers/<leaf>.json".into(),
        network: false,
        secrets: false,
        processes: false,
        cross_surface: false,
    };
    [fixture_capability_v1(), read]
}

/// No file handle or write operation escapes this closed reader.
pub(crate) fn read_fixture_marker(path: &Path) -> FixtureResult<Vec<u8>> {
    let bytes = observe_marker(path)?;
    if bytes.len() > 65536 {
        return Err(invalid("F05 read observation exceeds fixture bound"));
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixturePayloadV1 {
    pub label: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureMarkerV1 {
    pub marker: String,
    pub namespace: String,
    pub case_id: String,
    pub resource: String,
    pub action_id: String,
    pub idempotency_id: String,
    pub payload_digest: String,
}
pub(crate) fn slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
pub(crate) fn ordinary(path: &Path) -> FixtureResult<()> {
    for p in path.ancestors() {
        let m = fs::symlink_metadata(p)
            .map_err(|_| fail(BlockedCode::EnvironmentFailure, "F05 path unresolved"))?;
        let mut link = m.file_type().is_symlink();
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            link |= m.file_attributes() & 0x400 != 0;
        }
        if link || !m.is_dir() {
            return Err(fail(
                BlockedCode::TargetIdentityMismatch,
                "F05 non-ordinary directory",
            ));
        }
    }
    Ok(())
}
fn file_slug(s: &str) -> bool {
    slug(s)
        && !matches!(s, "con" | "prn" | "aux" | "nul")
        && !s
            .strip_prefix("com")
            .or_else(|| s.strip_prefix("lpt"))
            .is_some_and(|n| matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}
pub fn fixture_marker_path(case: &str, resource: &str, relative: &str) -> FixtureResult<PathBuf> {
    if !file_slug(case) {
        return Err(invalid("invalid F05 case"));
    }
    let leaf = resource
        .strip_prefix(&format!("fixture://resource/lab/{case}/"))
        .filter(|v| file_slug(v))
        .ok_or_else(|| {
            fail(
                BlockedCode::ScopeViolation,
                "F05 resource outside closed mapping",
            )
        })?;
    if relative != format!("markers/{leaf}.json") {
        return Err(fail(
            BlockedCode::TargetIdentityMismatch,
            "F05 marker mapping mismatch",
        ));
    }
    let root = Path::new(F05_ROOT);
    let parent = root.join("cases").join(case).join("markers");
    ordinary(&parent)?;
    let canonical_root = fs::canonicalize(root).map_err(|_| invalid("F05 root unresolved"))?;
    let canonical_parent =
        fs::canonicalize(&parent).map_err(|_| invalid("F05 parent unresolved"))?;
    if !canonical_parent.starts_with(&canonical_root) {
        return Err(fail(
            BlockedCode::TargetIdentityMismatch,
            "F05 canonical escape",
        ));
    }
    Ok(parent.join(format!("{leaf}.json")))
}
pub(crate) fn require_absent(path: &Path) -> FixtureResult<()> {
    match fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        _ => Err(fail(
            BlockedCode::PreconditionDrift,
            "F05 target exists or cannot be established absent",
        )),
    }
}
pub(crate) fn observe_marker(path: &Path) -> FixtureResult<Vec<u8>> {
    ordinary(
        path.parent()
            .ok_or_else(|| invalid("F05 marker parent missing"))?,
    )?;
    let before = fs::symlink_metadata(path)
        .map_err(|_| fail(BlockedCode::InsufficientEvidence, "F05 marker not observed"))?;
    let mut link = before.file_type().is_symlink();
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        link |= before.file_attributes() & 0x400 != 0;
    }
    if link || !before.is_file() || before.len() > 65536 {
        return Err(fail(
            BlockedCode::TargetIdentityMismatch,
            "F05 marker not ordinary/bounded",
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|_| invalid("F05 marker unresolved"))?;
    let root = fs::canonicalize(F05_ROOT).map_err(|_| invalid("F05 root unresolved"))?;
    if !canonical.starts_with(root) {
        return Err(fail(
            BlockedCode::TargetIdentityMismatch,
            "F05 marker escaped",
        ));
    }
    let bytes = fs::read(path)
        .map_err(|_| fail(BlockedCode::InsufficientEvidence, "F05 marker unreadable"))?;
    let after = fs::symlink_metadata(path).map_err(|_| invalid("F05 marker changed"))?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || fs::canonicalize(path).ok().as_ref() != Some(&canonical)
    {
        return Err(fail(
            BlockedCode::PreconditionDrift,
            "F05 marker changed during observation",
        ));
    }
    Ok(bytes)
}
pub(crate) fn payload_valid(bytes: &[u8], digest: &str) -> FixtureResult<()> {
    if bytes.len() > 512 || hash(b"TITAN-FWD-F05\0payload-v1\0", bytes) != digest {
        return Err(invalid("F05 payload digest mismatch"));
    }
    let v: FixturePayloadV1 =
        serde_json::from_slice(bytes).map_err(|_| invalid("F05 payload malformed"))?;
    if !slug(&v.label)
        || serde_json::to_vec(&v).map_err(|_| invalid("F05 payload encoding"))? != bytes
    {
        return Err(invalid("F05 payload noncanonical"));
    }
    Ok(())
}

/// Closed synthetic fault points, not a configurable executor or callback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FixtureFaultV1 {
    None,
    BeforeRevalidationDrift,
    FailBeforeWrite,
    InterruptBeforeHandler,
    InterruptAfterWrite,
    PartialWrite,
    PostEffectRecordingFailure,
}
pub(crate) struct HandlerObservation {
    pub proven_before_write: bool,
    pub interrupted: bool,
}
pub(crate) fn invoke_once(path: &Path, bytes: &[u8], fault: FixtureFaultV1) -> HandlerObservation {
    if fault == FixtureFaultV1::FailBeforeWrite {
        return HandlerObservation {
            proven_before_write: true,
            interrupted: false,
        };
    }
    // No directory creation, overwrite, rename, deletion or cleanup exists in this handler.
    let result = (|| -> std::io::Result<()> {
        let mut f = OpenOptions::new().write(true).create_new(true).open(path)?;
        let data = if fault == FixtureFaultV1::PartialWrite {
            &bytes[..bytes.len() / 2]
        } else {
            bytes
        };
        f.write_all(data)?;
        f.sync_all()
    })();
    HandlerObservation {
        proven_before_write: false,
        interrupted: result.is_err()
            || matches!(
                fault,
                FixtureFaultV1::InterruptAfterWrite | FixtureFaultV1::PartialWrite
            ),
    }
}
