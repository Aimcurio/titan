//! Fixture-only append-only history. Hashes establish byte identity, not trust.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::{
    ValidatedRecord,
    authority::{FixtureFailure, FixtureResult, invalid},
    codec::validate_bytes,
    fixture_projection::FixtureAuthoritySeedV1,
    outcome::{BlockedCode, OutcomeVariant, UnknownCode},
    records::{ActorBinding, EvidenceRef, EvidenceStatus, Outcome, RecordPayload},
};

pub const F04_ROOT: &str =
    r"C:\Users\15103\Documents\Codex\2026-09-29\files-pasted-by-the-user-titan\work\f04-fixtures";
pub const HISTORY_MARKER: &str = "TITAN_F04_FIXTURE_HISTORY_V1";

pub fn hash(domain: &[u8], bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(domain);
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}
pub fn fail(code: BlockedCode, reason: &'static str) -> FixtureFailure {
    FixtureFailure::new(code, reason)
}
fn env(reason: &'static str) -> FixtureFailure {
    fail(BlockedCode::EnvironmentFailure, reason)
}
fn slug(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}
fn digest_form(s: &str) -> bool {
    s.strip_prefix("sha256:").is_some_and(|x| {
        x.len() == 64
            && x.bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    })
}
fn fixture_id(s: &str, kind: &str) -> bool {
    s.strip_prefix(&format!("fx:{kind}:")).is_some_and(slug)
}

fn reparse(path: &Path) -> FixtureResult<bool> {
    let m = fs::symlink_metadata(path).map_err(|_| env("fixture path unresolved"))?;
    if m.file_type().is_symlink() {
        return Ok(true);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        Ok(m.file_attributes() & 0x400 != 0)
    }
    #[cfg(not(windows))]
    {
        Ok(false)
    }
}
fn ordinary(path: &Path) -> FixtureResult<()> {
    for p in path.ancestors() {
        if reparse(p)? {
            return Err(env("fixture reparse component"));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn windows_link_count(file: &fs::File) -> FixtureResult<u32> {
    use std::{mem::MaybeUninit, os::windows::io::AsRawHandle};
    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }
    #[repr(C)]
    struct ByHandleFileInformation {
        attributes: u32,
        creation: FileTime,
        last_access: FileTime,
        last_write: FileTime,
        volume_serial: u32,
        size_high: u32,
        size_low: u32,
        number_of_links: u32,
        index_high: u32,
        index_low: u32,
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetFileInformationByHandle(
            handle: *mut std::ffi::c_void,
            info: *mut ByHandleFileInformation,
        ) -> i32;
    }
    let mut info = MaybeUninit::<ByHandleFileInformation>::uninit();
    let ok = unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) };
    if ok == 0 {
        return Err(env("raw file link count unavailable"));
    }
    let info = unsafe { info.assume_init() };
    Ok(info.number_of_links)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureStoreV1 {
    root: PathBuf,
    case_id: String,
    seed: FixtureAuthoritySeedV1,
    seed_digest: String,
}
impl FixtureStoreV1 {
    pub fn open(case_id: &str, seed: &FixtureAuthoritySeedV1) -> FixtureResult<Self> {
        if !slug(case_id) {
            return Err(invalid("invalid fixture case"));
        }
        let seed_digest = seed.digest()?;
        let root = PathBuf::from(F04_ROOT);
        ordinary(&root)?;
        let cases = root.join("cases");
        if !cases.exists() {
            fs::create_dir(&cases).map_err(|_| env("fixture cases create failed"))?;
        }
        ordinary(&cases)?;
        let case = cases.join(case_id);
        if !case.exists() {
            fs::create_dir(&case).map_err(|_| env("fixture case create failed"))?;
        }
        ordinary(&case)?;
        for name in ["events", "raw"] {
            let p = case.join(name);
            if !p.exists() {
                fs::create_dir(&p).map_err(|_| env("fixture directory create failed"))?;
            }
            ordinary(&p)?;
        }
        Ok(Self {
            root,
            case_id: case_id.into(),
            seed: seed.clone(),
            seed_digest,
        })
    }
    pub fn case_id(&self) -> &str {
        &self.case_id
    }
    pub fn case_path(&self) -> PathBuf {
        self.root.join("cases").join(&self.case_id)
    }
    pub fn raw_path(&self, name: &str) -> FixtureResult<PathBuf> {
        if !slug(name) {
            return Err(invalid("invalid raw fixture name"));
        }
        Ok(self.case_path().join("raw").join(name))
    }
    fn events(&self) -> PathBuf {
        self.case_path().join("events")
    }
    pub fn check_paths(&self) -> FixtureResult<()> {
        if self.root != Path::new(F04_ROOT) {
            return Err(env("fixture root changed"));
        }
        if self.seed.digest()? != self.seed_digest {
            return Err(invalid("fixture seed changed"));
        }
        ordinary(&self.events())?;
        ordinary(&self.case_path().join("raw"))?;
        Ok(())
    }
    pub fn read_raw(&self, locator: &str, expected: &str) -> FixtureResult<Vec<u8>> {
        let name = locator
            .strip_prefix("fixture://f04/raw/")
            .filter(|v| slug(v))
            .ok_or_else(|| invalid("unsupported raw locator"))?;
        if !digest_form(expected) {
            return Err(invalid("invalid raw digest"));
        }
        self.check_paths()?;
        let p = self.raw_path(name)?;
        ordinary(&p)?;
        let mut file = OpenOptions::new()
            .read(true)
            .open(&p)
            .map_err(|_| fail(BlockedCode::InsufficientEvidence, "raw fixture missing"))?;
        let before = file
            .metadata()
            .map_err(|_| fail(BlockedCode::InsufficientEvidence, "raw fixture missing"))?;
        if !before.is_file() || before.len() > 65_536 {
            return Err(invalid("raw fixture type or size"));
        }
        #[cfg(windows)]
        {
            if windows_link_count(&file)? != 1 {
                return Err(env("raw fixture hardlink or unknown link count"));
            }
        }
        let canonical_root =
            fs::canonicalize(self.case_path()).map_err(|_| env("case unresolved"))?;
        let canonical = fs::canonicalize(&p).map_err(|_| env("raw fixture unresolved"))?;
        if !canonical.starts_with(&canonical_root) {
            return Err(env("raw fixture escaped case"));
        }
        let mut bytes = Vec::new();
        (&mut file)
            .take(65_537)
            .read_to_end(&mut bytes)
            .map_err(|_| env("raw fixture read failed"))?;
        if bytes.len() > 65_536 {
            return Err(invalid("raw fixture grew beyond limit"));
        }
        let after = file.metadata().map_err(|_| env("raw fixture changed"))?;
        if before.len() != after.len()
            || before.modified().ok() != after.modified().ok()
            || reparse(&p)?
            || fs::canonicalize(&p).ok().as_ref() != Some(&canonical)
        {
            return Err(env("raw fixture changed during read"));
        }
        #[cfg(windows)]
        if windows_link_count(&file)? != 1 {
            return Err(env("raw fixture hardlink changed during read"));
        }
        if hash(b"", &bytes) != expected {
            return Err(fail(BlockedCode::PreconditionDrift, "raw digest changed"));
        }
        Ok(bytes)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EffectStateV1 {
    NotAttempted,
    FailedBeforeOccurrence,
    CompletedObserved,
    PossiblyOccurredInterrupted,
    PartiallyOccurred,
    OutcomeUnestablished,
}
impl EffectStateV1 {
    pub fn unresolved(self) -> bool {
        matches!(
            self,
            Self::PossiblyOccurredInterrupted
                | Self::PartiallyOccurred
                | Self::OutcomeUnestablished
        )
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ReconciliationConclusionV1 {
    Occurred,
    DidNotOccur,
    StillUnknown,
    Contradictory,
}
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BlockerResolutionMechanismV1 {
    Observation,
}
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureBlockerProbeV1 {
    pub blocker_id: String,
    pub dependency: String,
    pub subject_revision: String,
    pub resolved: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionSpecV1 {
    pub project_id: String,
    pub target_id: String,
    pub contract_digest: String,
    pub capability: String,
    pub operation: String,
    pub normalized_scope: String,
    pub logical_step: String,
    pub before_state: String,
}
impl ActionSpecV1 {
    pub fn fingerprint(&self) -> FixtureResult<String> {
        if !fixture_id(&self.project_id, "project")
            || !fixture_id(&self.target_id, "target")
            || !digest_form(&self.contract_digest)
            || self.capability.is_empty()
            || self.operation.is_empty()
            || self.normalized_scope.is_empty()
            || self.logical_step.is_empty()
            || self.before_state.is_empty()
        {
            return Err(invalid("invalid fixture action specification"));
        }
        let b = serde_json::to_vec(&(
            self.project_id.as_str(),
            self.target_id.as_str(),
            self.contract_digest.as_str(),
            self.capability.as_str(),
            self.operation.as_str(),
            self.normalized_scope.as_str(),
            self.logical_step.as_str(),
        ))
        .map_err(|_| invalid("action fingerprint serialization"))?;
        Ok(hash(b"TITAN-FWD-F04\0action-fingerprint-v1\0", &b))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureEffectProbeV1 {
    pub action_id: String,
    pub fingerprint: String,
    pub target_id: String,
    pub before_state: String,
    pub after_state: String,
    pub conclusion: ReconciliationConclusionV1,
}

/// Explicit F04 attribution; the F01 outcome itself has only a run scope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureOutcomeContextV1 {
    pub action: ActionSpecV1,
    pub contract_id: String,
    pub subject_revision: String,
    pub gate_ref: String,
}

/// Both the typed observation bytes and raw artifact bytes support the conclusion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FixtureEffectSupportV1 {
    pub evidence_id: String,
    pub record_digest: String,
    pub content_digest: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "data", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FixtureEventV1 {
    Observation {
        record: Vec<u8>,
        producer: Vec<u8>,
        seed_digest: String,
        contract_digest: String,
    },
    EvidenceInvalidated {
        evidence_id: String,
        prior_digest: String,
        source_evidence_id: String,
        reason_code: String,
        actor_id: String,
        epoch: u64,
    },
    EvidenceSuperseded {
        old_id: String,
        new_id: String,
        prior_digest: String,
        source_evidence_id: String,
        reason_code: String,
        actor_id: String,
        epoch: u64,
    },
    Outcome {
        record: Vec<u8>,
        context: FixtureOutcomeContextV1,
    },
    Checkpoint {
        checkpoint_id: String,
        bytes: Vec<u8>,
    },
    BlockerOpened {
        blocker_id: String,
        code: BlockedCode,
        dependency: String,
    },
    BlockerResolved {
        blocker_id: String,
        mechanism: BlockerResolutionMechanismV1,
        evidence_ids: Vec<String>,
        support_digests: Vec<String>,
        actor_id: String,
        reason: String,
        epoch: u64,
    },
    Effect {
        action_id: String,
        spec: ActionSpecV1,
        fingerprint: String,
        idempotency_id: String,
        state: EffectStateV1,
        evidence_ids: Vec<String>,
    },
    Reconciliation {
        action_id: String,
        conclusion: ReconciliationConclusionV1,
        evidence_ids: Vec<String>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixtureHistoryEntryV1 {
    pub marker: String,
    pub version: u32,
    pub case_id: String,
    pub sequence: u64,
    pub previous_id: String,
    pub run_id: String,
    pub event: FixtureEventV1,
    pub entry_id: String,
}
impl FixtureHistoryEntryV1 {
    fn computed_id(&self) -> FixtureResult<String> {
        let bytes = serde_json::to_vec(&(
            self.marker.as_str(),
            self.version,
            self.case_id.as_str(),
            self.sequence,
            self.previous_id.as_str(),
            self.run_id.as_str(),
            &self.event,
        ))
        .map_err(|_| invalid("entry serialization"))?;
        Ok(format!(
            "fx:history-entry:{}",
            hash(b"TITAN-FWD-F04\0entry-v1\0", &bytes).trim_start_matches("sha256:")
        ))
    }
}

#[derive(Clone, Debug, Default)]
pub struct FixtureHistoryV1 {
    pub entries: Vec<FixtureHistoryEntryV1>,
    pub observations: BTreeMap<String, (EvidenceRef, String)>,
    pub observation_digests: BTreeMap<String, String>,
    pub evidence_status: BTreeMap<String, EvidenceStatus>,
    pub blockers: BTreeMap<String, (BlockedCode, bool)>,
    pub effects: BTreeMap<String, (String, String, EffectStateV1)>,
    pub effect_specs: BTreeMap<String, ActionSpecV1>,
    pub effect_runs: BTreeMap<String, String>,
    pub reconciliation_support: BTreeMap<String, Vec<String>>,
    pub effect_support: BTreeMap<String, Vec<FixtureEffectSupportV1>>,
    pub blocker_support: BTreeMap<String, Vec<String>>,
    pub checkpoints: BTreeMap<String, Vec<u8>>,
    pub outcomes: Vec<Outcome>,
}
impl FixtureHistoryV1 {
    pub fn head_id(&self) -> &str {
        self.entries
            .last()
            .map_or("GENESIS", |e| e.entry_id.as_str())
    }
    pub fn history_id(&self, case_id: &str) -> FixtureResult<String> {
        let b = serde_json::to_vec(&(case_id, self.entries.len(), self.head_id()))
            .map_err(|_| invalid("history serialization"))?;
        Ok(format!(
            "fx:history:{}",
            hash(b"TITAN-FWD-F04\0history-v1\0", &b).trim_start_matches("sha256:")
        ))
    }
    pub fn unresolved_fingerprints(&self) -> BTreeSet<&str> {
        self.effects
            .values()
            .filter(|(_, _, s)| s.unresolved())
            .map(|(f, _, _)| f.as_str())
            .collect()
    }
    pub fn current_evidence(&self, id: &str) -> bool {
        self.observations.contains_key(id)
            && self.evidence_status.get(id) == Some(&EvidenceStatus::Current)
    }
    fn retain_effect_support(&mut self, action: &str, ids: &[String]) -> FixtureResult<()> {
        let support = ids
            .iter()
            .map(|id| {
                let (e, _) = self
                    .observations
                    .get(id)
                    .ok_or_else(|| invalid("effect support missing"))?;
                let record_digest = self
                    .observation_digests
                    .get(id)
                    .ok_or_else(|| invalid("effect support digest missing"))?;
                Ok(FixtureEffectSupportV1 {
                    evidence_id: id.clone(),
                    record_digest: record_digest.clone(),
                    content_digest: e.content_digest.clone(),
                })
            })
            .collect::<FixtureResult<Vec<_>>>()?;
        self.effect_support.insert(action.into(), support);
        Ok(())
    }
    fn reopen_unsupported_effects(&mut self, store: &FixtureStoreV1) {
        let unsupported = self
            .effect_support
            .iter()
            .filter(|(_, refs)| {
                refs.iter().any(|support| {
                    !self.current_evidence(&support.evidence_id)
                        || self.observation_digests.get(&support.evidence_id)
                            != Some(&support.record_digest)
                        || self
                            .observations
                            .get(&support.evidence_id)
                            .is_none_or(|(e, _)| {
                                e.content_digest != support.content_digest
                                    || store.read_raw(&e.locator, &support.content_digest).is_err()
                            })
                })
            })
            .map(|(action, _)| action.clone())
            .collect::<Vec<_>>();
        for action in unsupported {
            if let Some((_, _, state)) = self.effects.get_mut(&action) {
                *state = EffectStateV1::OutcomeUnestablished;
            }
        }
    }
}

fn observed(record: &[u8]) -> FixtureResult<EvidenceRef> {
    let validated = validate_bytes(record).map_err(|_| invalid("invalid F01 evidence"))?;
    let RecordPayload::EvidenceRef(v) = &validated.record().payload else {
        return Err(invalid("F01 evidence required"));
    };
    if v.kind != "OBSERVATION"
        || !matches!(v.status, EvidenceStatus::Current | EvidenceStatus::Unknown)
    {
        return Err(invalid("raw observation kind or status invalid"));
    }
    Ok(v.clone())
}
fn outcome(record: &[u8]) -> FixtureResult<Outcome> {
    let v = validate_bytes(record).map_err(|_| invalid("invalid F01 outcome"))?;
    let RecordPayload::Outcome(o) = &v.record().payload else {
        return Err(invalid("F01 outcome required"));
    };
    Ok(o.clone())
}
fn actor(record: &[u8]) -> FixtureResult<ActorBinding> {
    let v = validate_bytes(record).map_err(|_| invalid("invalid F01 actor"))?;
    let RecordPayload::ActorBinding(a) = &v.record().payload else {
        return Err(invalid("F01 actor required"));
    };
    Ok(a.clone())
}

fn checked_effect_probe(
    h: &FixtureHistoryV1,
    store: &FixtureStoreV1,
    evidence_id: &str,
    run_id: &str,
    action_id: &str,
    spec: &ActionSpecV1,
) -> FixtureResult<ReconciliationConclusionV1> {
    if !h.current_evidence(evidence_id) {
        return Err(fail(
            BlockedCode::InsufficientEvidence,
            "effect probe not current",
        ));
    }
    let (e, contract_digest) = h
        .observations
        .get(evidence_id)
        .ok_or_else(|| invalid("effect probe missing"))?;
    if e.method != "EFFECT_PROBE"
        || e.subject_ref != spec.target_id
        || e.run_ref != run_id
        || contract_digest != &spec.contract_digest
    {
        return Err(invalid("effect probe attribution mismatch"));
    }
    let bytes = store.read_raw(&e.locator, &e.content_digest)?;
    let probe: FixtureEffectProbeV1 =
        serde_json::from_slice(&bytes).map_err(|_| invalid("effect probe malformed"))?;
    if serde_json::to_vec(&probe).map_err(|_| invalid("effect probe encoding"))? != bytes
        || probe.action_id != action_id
        || probe.fingerprint != spec.fingerprint()?
        || probe.target_id != spec.target_id
        || probe.before_state != spec.before_state
        || probe.after_state != e.subject_revision
    {
        return Err(invalid("effect probe binding mismatch"));
    }
    match probe.conclusion {
        ReconciliationConclusionV1::Occurred if probe.after_state == probe.before_state => {
            Err(invalid("occurrence not observed"))
        }
        ReconciliationConclusionV1::DidNotOccur if probe.after_state != probe.before_state => {
            Err(invalid("nonoccurrence not observed"))
        }
        _ => Ok(probe.conclusion),
    }
}

fn history_matches_checkpoint_run(
    h: &FixtureHistoryV1,
    m: &crate::recovery::FixtureCheckpointMaterialV1,
) -> bool {
    h.observations
        .values()
        .filter(|(e, _)| e.run_ref == m.run_id)
        .all(|(e, digest)| {
            e.producer_ref == m.actor_id
                && e.contract_ref == m.contract_id
                && digest == &m.contract_digest
                && e.subject_ref == m.target_id
        })
        && h.effect_runs
            .iter()
            .filter(|(_, run)| *run == &m.run_id)
            .all(|(action, _)| {
                h.effect_specs.get(action).is_some_and(|spec| {
                    spec.project_id == m.project_id
                        && spec.target_id == m.target_id
                        && spec.contract_digest == m.contract_digest
                        && spec.capability == m.capability
                        && spec.operation == m.operation
                })
            })
        && h.effects
            .get(&m.action_id)
            .is_none_or(|(fingerprint, idempotency, _)| {
                fingerprint == &m.action_fingerprint && idempotency == &m.idempotency_id
            })
}

fn apply(
    h: &mut FixtureHistoryV1,
    store: &FixtureStoreV1,
    entry: &FixtureHistoryEntryV1,
) -> FixtureResult<()> {
    match &entry.event {
        FixtureEventV1::Observation {
            record,
            producer,
            seed_digest,
            contract_digest,
        } => {
            let e = observed(record)?;
            let a = actor(producer)?;
            if a.actor_id != e.producer_ref
                || seed_digest != &store.seed_digest
                || !store.seed.actor_records.iter().any(|v| v == producer)
                || !digest_form(contract_digest)
                || !fixture_id(&e.run_ref, "run")
                || !fixture_id(&e.subject_ref, "target")
                || !fixture_id(&e.contract_ref, "contract")
                || !matches!(
                    e.method.as_str(),
                    "FIXTURE_PROBE" | "EFFECT_PROBE" | "BLOCKER_RESOLUTION" | "EVIDENCE_REVIEW"
                )
                || e.subject_revision.is_empty()
                || h.observations.contains_key(&e.evidence_id)
            {
                return Err(invalid("observation binding or duplicate"));
            }
            if entry.run_id != e.run_ref {
                return Err(invalid("observation run mismatch"));
            }
            store.read_raw(&e.locator, &e.content_digest)?;
            let validated =
                validate_bytes(record).map_err(|_| invalid("observation record invalid"))?;
            h.observation_digests
                .insert(e.evidence_id.clone(), validated.record().integrity.clone());
            h.evidence_status
                .insert(e.evidence_id.clone(), e.status.clone());
            h.observations
                .insert(e.evidence_id.clone(), (e, contract_digest.clone()));
        }
        FixtureEventV1::EvidenceInvalidated {
            evidence_id,
            prior_digest,
            source_evidence_id,
            reason_code,
            actor_id,
            epoch,
        } => {
            if reason_code != "INVALIDATED_BY_REVIEW"
                || *epoch == 0
                || !store
                    .seed
                    .actor_records
                    .iter()
                    .any(|record| actor(record).is_ok_and(|a| a.actor_id == *actor_id))
                || !h.current_evidence(evidence_id)
                || h.observation_digests.get(evidence_id) != Some(prior_digest)
                || evidence_id == source_evidence_id
                || !h.current_evidence(source_evidence_id)
                || h.observations
                    .get(source_evidence_id)
                    .is_none_or(|(source, _)| {
                        h.observations.get(evidence_id).is_none_or(|(old, _)| {
                            source.method != "EVIDENCE_REVIEW"
                                || source.subject_ref != old.subject_ref
                                || source.run_ref != entry.run_id
                        })
                    })
            {
                return Err(invalid("invalid evidence invalidation"));
            }
            h.evidence_status
                .insert(evidence_id.clone(), EvidenceStatus::Invalidated);
            h.reopen_unsupported_effects(store);
            for (blocker, refs) in &h.blocker_support {
                if refs.contains(evidence_id)
                    && let Some((_, active)) = h.blockers.get_mut(blocker)
                {
                    *active = true;
                }
            }
        }
        FixtureEventV1::EvidenceSuperseded {
            old_id,
            new_id,
            prior_digest,
            source_evidence_id,
            reason_code,
            actor_id,
            epoch,
        } => {
            if old_id == new_id
                || reason_code != "SUPERSEDED_BY_NEW_OBSERVATION"
                || *epoch == 0
                || !store
                    .seed
                    .actor_records
                    .iter()
                    .any(|record| actor(record).is_ok_and(|a| a.actor_id == *actor_id))
                || !h.current_evidence(old_id)
                || !h.current_evidence(new_id)
                || h.observation_digests.get(old_id) != Some(prior_digest)
                || source_evidence_id != new_id
                || h.observations
                    .get(old_id)
                    .zip(h.observations.get(new_id))
                    .is_none_or(|((old, _), (new, _))| {
                        old.subject_ref != new.subject_ref || new.run_ref != entry.run_id
                    })
            {
                return Err(invalid("invalid evidence supersession"));
            }
            h.evidence_status
                .insert(old_id.clone(), EvidenceStatus::Superseded);
            h.reopen_unsupported_effects(store);
            for (blocker, refs) in &h.blocker_support {
                if refs.contains(old_id)
                    && let Some((_, active)) = h.blockers.get_mut(blocker)
                {
                    *active = true;
                }
            }
        }
        FixtureEventV1::Outcome { record, context } => {
            let o = outcome(record)?;
            let fingerprint = context.action.fingerprint()?;
            let project = validate_bytes(&store.seed.project_record)
                .map_err(|_| invalid("outcome project invalid"))?;
            let RecordPayload::ProjectBinding(project) = &project.record().payload else {
                return Err(invalid("outcome project binding required"));
            };
            if o.scope_ref != entry.run_id
                || context.action.project_id != project.project_id
                || !fixture_id(&context.contract_id, "contract")
                || !fixture_id(&context.gate_ref, "gate")
                || context.subject_revision.is_empty()
                || o.evidence_refs.iter().any(|id| {
                    h.observations.get(id).is_none_or(|(e, digest)| {
                        e.run_ref != entry.run_id
                            || e.contract_ref != context.contract_id
                            || digest != &context.action.contract_digest
                            || e.subject_ref != context.action.target_id
                            || e.subject_revision != context.subject_revision
                            || e.gate_ref.as_ref() != Some(&context.gate_ref)
                    })
                })
            {
                return Err(invalid("outcome context or evidence attribution mismatch"));
            }
            if o.evidence_refs.iter().any(|id| !h.current_evidence(id)) {
                return Err(fail(
                    BlockedCode::InsufficientEvidence,
                    "outcome evidence not current",
                ));
            }
            for id in &o.evidence_refs {
                let (e, _) = &h.observations[id];
                store.read_raw(&e.locator, &e.content_digest)?;
            }
            h.reopen_unsupported_effects(store);
            let unresolved = h.unresolved_fingerprints();
            if matches!(
                o.status_and_code,
                OutcomeVariant::Pass(_) | OutcomeVariant::Fail(_)
            ) && (o.evidence_refs.is_empty()
                    || unresolved.contains(fingerprint.as_str())
                    // A run-scoped terminal outcome cannot hide other uncertainty in this case.
                    || !unresolved.is_empty())
            {
                return Err(fail(
                    BlockedCode::InsufficientEvidence,
                    "unsupported terminal outcome; reconciliation required",
                ));
            }
            h.outcomes.push(o);
        }
        FixtureEventV1::Checkpoint {
            checkpoint_id,
            bytes,
        } => {
            let checkpoint: crate::recovery::FixtureCheckpointV1 =
                serde_json::from_slice(bytes).map_err(|_| invalid("checkpoint bytes malformed"))?;
            checkpoint.verify()?;
            if checkpoint.canonical_bytes()? != *bytes
                || checkpoint.checkpoint_id != *checkpoint_id
                || checkpoint.material.run_id != entry.run_id
                || checkpoint.material.case_id != store.case_id
                || checkpoint.material.history_id != h.history_id(store.case_id())?
                || !history_matches_checkpoint_run(h, &checkpoint.material)
                || checkpoint.material.active_blockers
                    != h.blockers
                        .iter()
                        .filter(|(_, (_, active))| *active)
                        .map(|(id, (code, _))| (id.clone(), code.clone()))
                        .collect::<Vec<_>>()
                || checkpoint.material.unresolved_effect_refs
                    != h.effects
                        .iter()
                        .filter(|(_, (_, _, s))| s.unresolved())
                        .map(|(id, _)| id.clone())
                        .collect::<Vec<_>>()
                || h.checkpoints.contains_key(checkpoint_id)
            {
                return Err(invalid("checkpoint identity or projection mismatch"));
            }
            h.checkpoints.insert(checkpoint_id.clone(), bytes.clone());
        }
        FixtureEventV1::BlockerOpened {
            blocker_id,
            code,
            dependency,
        } => {
            if !fixture_id(blocker_id, "blocker")
                || dependency.is_empty()
                || h.blockers.contains_key(blocker_id)
            {
                return Err(invalid("blocker identity or duplicate"));
            }
            h.blockers.insert(blocker_id.clone(), (code.clone(), true));
        }
        FixtureEventV1::BlockerResolved {
            blocker_id,
            mechanism,
            evidence_ids,
            support_digests,
            actor_id,
            reason,
            epoch,
        } => {
            let dependency = h
                .blockers
                .get(blocker_id)
                .filter(|(_, active)| *active)
                .and_then(|_| {
                    h.entries.iter().rev().find_map(|e| match &e.event {
                        FixtureEventV1::BlockerOpened {
                            blocker_id: id,
                            dependency,
                            ..
                        } if id == blocker_id => Some(dependency.as_str()),
                        _ => None,
                    })
                })
                .ok_or_else(|| invalid("unknown or inactive blocker"))?;
            if !matches!(mechanism, BlockerResolutionMechanismV1::Observation)
                || reason.is_empty()
                || *epoch == 0
                || !store
                    .seed
                    .actor_records
                    .iter()
                    .any(|record| actor(record).is_ok_and(|a| a.actor_id == *actor_id))
                || evidence_ids.is_empty()
                || evidence_ids.len() != support_digests.len()
                || evidence_ids.iter().collect::<BTreeSet<_>>().len() != evidence_ids.len()
                || evidence_ids.iter().any(|id| {
                    !h.current_evidence(id)
                        || h.observations.get(id).is_none_or(|(e, _)| {
                            e.subject_ref != dependency
                                || e.run_ref != entry.run_id
                                || e.method != "BLOCKER_RESOLUTION"
                        })
                })
            {
                return Err(fail(
                    BlockedCode::InsufficientEvidence,
                    "unsupported blocker resolution",
                ));
            }
            for (id, digest) in evidence_ids.iter().zip(support_digests) {
                if h.observation_digests.get(id) != Some(digest) {
                    return Err(fail(
                        BlockedCode::InsufficientEvidence,
                        "blocker support digest mismatch",
                    ));
                }
                let (e, _) = h
                    .observations
                    .get(id)
                    .ok_or_else(|| invalid("blocker support missing"))?;
                let bytes = store.read_raw(&e.locator, &e.content_digest)?;
                let probe: FixtureBlockerProbeV1 = serde_json::from_slice(&bytes)
                    .map_err(|_| invalid("blocker probe malformed"))?;
                if serde_json::to_vec(&probe).map_err(|_| invalid("blocker probe encoding"))?
                    != bytes
                    || probe.blocker_id != *blocker_id
                    || probe.dependency != dependency
                    || probe.subject_revision != e.subject_revision
                    || !probe.resolved
                {
                    return Err(fail(
                        BlockedCode::InsufficientEvidence,
                        "blocker probe does not resolve dependency",
                    ));
                }
            }
            h.blockers.get_mut(blocker_id).expect("checked").1 = false;
            h.blocker_support
                .insert(blocker_id.clone(), evidence_ids.clone());
        }
        FixtureEventV1::Effect {
            action_id,
            spec,
            fingerprint,
            idempotency_id,
            state,
            evidence_ids,
        } => {
            if !fixture_id(action_id, "action")
                || spec.fingerprint()? != *fingerprint
                || !fixture_id(idempotency_id, "idempotency")
                || h.effects.contains_key(action_id)
                || h.effects
                    .values()
                    .any(|(_, existing, _)| existing == idempotency_id)
            {
                return Err(invalid("invalid or repeated action identity"));
            }
            if h.effects
                .values()
                .any(|(existing, _, _)| existing == fingerprint)
            {
                return Err(fail(
                    BlockedCode::PreconditionDrift,
                    "existing action fingerprint cannot be reissued",
                ));
            }
            if matches!(
                state,
                EffectStateV1::CompletedObserved | EffectStateV1::FailedBeforeOccurrence
            ) {
                if evidence_ids.is_empty() {
                    return Err(fail(
                        BlockedCode::InsufficientEvidence,
                        "effect conclusion lacks observation",
                    ));
                }
                let expected = if *state == EffectStateV1::CompletedObserved {
                    ReconciliationConclusionV1::Occurred
                } else {
                    ReconciliationConclusionV1::DidNotOccur
                };
                for id in evidence_ids {
                    if checked_effect_probe(h, store, id, &entry.run_id, action_id, spec)?
                        != expected
                    {
                        return Err(fail(
                            BlockedCode::InsufficientEvidence,
                            "effect proof does not establish claimed state",
                        ));
                    }
                }
            }
            h.effects.insert(
                action_id.clone(),
                (fingerprint.clone(), idempotency_id.clone(), *state),
            );
            h.effect_specs.insert(action_id.clone(), spec.clone());
            h.effect_runs
                .insert(action_id.clone(), entry.run_id.clone());
            if matches!(
                state,
                EffectStateV1::CompletedObserved | EffectStateV1::FailedBeforeOccurrence
            ) {
                h.retain_effect_support(action_id, evidence_ids)?;
            }
        }
        FixtureEventV1::Reconciliation {
            action_id,
            conclusion,
            evidence_ids,
        } => {
            if evidence_ids.is_empty() || evidence_ids.iter().any(|id| !h.current_evidence(id)) {
                return Err(fail(
                    BlockedCode::InsufficientEvidence,
                    "reconciliation evidence missing",
                ));
            }
            let spec = h
                .effect_specs
                .get(action_id)
                .ok_or_else(|| invalid("unknown reconciled action"))?;
            let mut probes = BTreeSet::new();
            let run_id = h
                .effect_runs
                .get(action_id)
                .ok_or_else(|| invalid("effect run missing"))?;
            for evidence_id in evidence_ids {
                probes.insert(
                    checked_effect_probe(h, store, evidence_id, run_id, action_id, spec)? as u8,
                );
            }
            let actual = if probes.contains(&(ReconciliationConclusionV1::Contradictory as u8))
                || (probes.contains(&(ReconciliationConclusionV1::Occurred as u8))
                    && probes.contains(&(ReconciliationConclusionV1::DidNotOccur as u8)))
            {
                ReconciliationConclusionV1::Contradictory
            } else if probes.contains(&(ReconciliationConclusionV1::StillUnknown as u8)) {
                ReconciliationConclusionV1::StillUnknown
            } else if probes.contains(&(ReconciliationConclusionV1::Occurred as u8)) {
                ReconciliationConclusionV1::Occurred
            } else {
                ReconciliationConclusionV1::DidNotOccur
            };
            if actual != *conclusion {
                return Err(invalid(
                    "claimed reconciliation conclusion differs from raw probes",
                ));
            }
            let Some((_, _, state)) = h.effects.get_mut(action_id) else {
                return Err(invalid("unknown reconciled action"));
            };
            if !state.unresolved() {
                return Err(fail(
                    BlockedCode::InsufficientEvidence,
                    "reconciliation evidence missing",
                ));
            }
            match conclusion {
                ReconciliationConclusionV1::Occurred => *state = EffectStateV1::CompletedObserved,
                ReconciliationConclusionV1::DidNotOccur => {
                    *state = EffectStateV1::FailedBeforeOccurrence
                }
                ReconciliationConclusionV1::StillUnknown
                | ReconciliationConclusionV1::Contradictory => {}
            }
            h.reconciliation_support
                .insert(action_id.clone(), evidence_ids.clone());
            h.retain_effect_support(action_id, evidence_ids)?;
        }
    }
    Ok(())
}

pub fn replay_fixture_history(store: &FixtureStoreV1) -> FixtureResult<FixtureHistoryV1> {
    store.check_paths()?;
    let mut paths = fs::read_dir(store.events())
        .map_err(|_| env("fixture events unreadable"))?
        .map(|v| {
            v.map(|e| e.path())
                .map_err(|_| env("fixture event unreadable"))
        })
        .collect::<FixtureResult<Vec<_>>>()?;
    paths.sort();
    let mut h = FixtureHistoryV1::default();
    for (index, path) in paths.iter().enumerate() {
        ordinary(path)?;
        if path.file_name().and_then(|x| x.to_str())
            != Some(format!("{:010}.json", index + 1).as_str())
        {
            return Err(env("fixture history sequence gap or fork"));
        }
        let bytes = fs::read(path).map_err(|_| env("fixture event unreadable"))?;
        if bytes.is_empty() || bytes.len() > 131_072 {
            return Err(env("fixture event size invalid"));
        }
        let entry: FixtureHistoryEntryV1 =
            serde_json::from_slice(&bytes).map_err(|_| env("fixture event corrupted"))?;
        if serde_json::to_vec(&entry).map_err(|_| env("fixture event encoding"))? != bytes
            || entry.marker != HISTORY_MARKER
            || entry.version != 1
            || entry.case_id != store.case_id
            || entry.sequence != index as u64 + 1
            || entry.previous_id != h.head_id()
            || !fixture_id(&entry.run_id, "run")
            || entry.entry_id != entry.computed_id()?
        {
            return Err(env("fixture history identity mismatch"));
        }
        apply(&mut h, store, &entry)?;
        h.entries.push(entry);
    }
    h.reopen_unsupported_effects(store);
    Ok(h)
}

pub fn append_fixture_event(
    store: &FixtureStoreV1,
    run_id: &str,
    expected_head: &str,
    event: FixtureEventV1,
) -> FixtureResult<FixtureHistoryEntryV1> {
    if !fixture_id(run_id, "run") {
        return Err(invalid("invalid fixture run"));
    }
    let mut h = replay_fixture_history(store)?;
    if h.head_id() != expected_head {
        return Err(fail(BlockedCode::PreconditionDrift, "history head changed"));
    }
    let mut e = FixtureHistoryEntryV1 {
        marker: HISTORY_MARKER.into(),
        version: 1,
        case_id: store.case_id.clone(),
        sequence: h.entries.len() as u64 + 1,
        previous_id: expected_head.into(),
        run_id: run_id.into(),
        event,
        entry_id: String::new(),
    };
    apply(&mut h, store, &e)?;
    e.entry_id = e.computed_id()?;
    let bytes = serde_json::to_vec(&e).map_err(|_| invalid("entry encoding"))?;
    let path = store.events().join(format!("{:010}.json", e.sequence));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&path)
        .map_err(|_| env("fixture sequence slot occupied"))?;
    f.write_all(&bytes)
        .map_err(|_| env("fixture event append incomplete"))?;
    f.sync_all().map_err(|_| env("fixture event sync failed"))?;
    let observed = replay_fixture_history(store)?;
    if observed.head_id() != e.entry_id {
        return Err(env("fixture append replay mismatch"));
    }
    Ok(e)
}

pub fn observation_event(
    seed: &FixtureAuthoritySeedV1,
    evidence: &ValidatedRecord,
    producer: &ValidatedRecord,
    contract_digest: &str,
) -> FixtureResult<FixtureEventV1> {
    if !seed
        .actor_records
        .iter()
        .any(|v| v == producer.canonical_bytes())
        || !digest_form(contract_digest)
    {
        return Err(fail(
            BlockedCode::Unauthorized,
            "fixture producer not in seed",
        ));
    }
    let e = observed(evidence.canonical_bytes())?;
    let a = actor(producer.canonical_bytes())?;
    if e.producer_ref != a.actor_id {
        return Err(fail(BlockedCode::Unauthorized, "fixture producer mismatch"));
    }
    Ok(FixtureEventV1::Observation {
        record: evidence.canonical_bytes().to_vec(),
        producer: producer.canonical_bytes().to_vec(),
        seed_digest: seed.digest()?,
        contract_digest: contract_digest.into(),
    })
}

pub fn uncertain_outcome() -> OutcomeVariant {
    OutcomeVariant::Unknown(UnknownCode::PartialEffectUnreconciled)
}
