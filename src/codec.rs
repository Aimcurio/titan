use serde::Serialize;
use sha2::{Digest as _, Sha256};

use crate::{
    records::{Namespace, RecordEnvelope, RecordPayload, RecordType},
    validation::{ValidationError, ValidationStage, validate_record},
};

const MAX_INPUT_BYTES: usize = 1_048_576;
const DOMAIN: &[u8] = b"TITAN-FWD-F01\0f01-json-v1\0";

#[derive(Clone, Debug)]
pub struct ValidatedRecord {
    record: RecordEnvelope,
    bytes: Vec<u8>,
}

impl ValidatedRecord {
    pub fn record(&self) -> &RecordEnvelope {
        &self.record
    }

    pub fn canonical_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Serialize)]
struct UnsignedEnvelope<'a> {
    record_type: &'a RecordType,
    schema_version: u32,
    namespace: &'a Namespace,
    record_id: &'a str,
    creator_ref: &'a str,
    created_at_unix_ms: u64,
    payload: &'a RecordPayload,
}

fn unsigned_bytes(record: &RecordEnvelope) -> Result<Vec<u8>, ValidationError> {
    let unsigned = UnsignedEnvelope {
        record_type: &record.record_type,
        schema_version: record.schema_version,
        namespace: &record.namespace,
        record_id: &record.record_id,
        creator_ref: &record.creator_ref,
        created_at_unix_ms: record.created_at_unix_ms,
        payload: &record.payload,
    };
    serde_json::to_vec(&unsigned)
        .map_err(|_| ValidationError::new(ValidationStage::Canonical, "serialization failed"))
}

fn expected_integrity(record: &RecordEnvelope) -> Result<String, ValidationError> {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update(unsigned_bytes(record)?);
    let digest = hasher.finalize();
    let mut result = String::from("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String is infallible");
    }
    Ok(result)
}

fn fixed_length_equal(expected: &str, supplied: &str) -> bool {
    if expected.len() != supplied.len() {
        return false;
    }
    let mut difference = 0_u8;
    for (left, right) in expected.bytes().zip(supplied.bytes()) {
        difference |= left ^ right;
    }
    difference == 0
}

/// Construct a canonical fixture record. The supplied integrity is replaced,
/// never trusted. This does not authenticate its creator or references.
pub fn encode_fixture(mut record: RecordEnvelope) -> Result<ValidatedRecord, ValidationError> {
    record.integrity = format!("sha256:{}", "0".repeat(64));
    validate_record(&record)?;
    record.integrity = expected_integrity(&record)?;
    let bytes = serde_json::to_vec(&record)
        .map_err(|_| ValidationError::new(ValidationStage::Canonical, "serialization failed"))?;
    validate_bytes(&bytes)
}

/// Accept only the exact canonical byte representation of a fixture record.
pub fn validate_bytes(input: &[u8]) -> Result<ValidatedRecord, ValidationError> {
    if input.is_empty() || input.len() > MAX_INPUT_BYTES {
        return Err(ValidationError::new(
            ValidationStage::InputSize,
            "input must be 1..=1 MiB",
        ));
    }
    let record: RecordEnvelope = serde_json::from_slice(input)
        .map_err(|_| ValidationError::new(ValidationStage::Parse, "invalid closed JSON record"))?;
    validate_record(&record)?;
    let canonical = serde_json::to_vec(&record)
        .map_err(|_| ValidationError::new(ValidationStage::Canonical, "serialization failed"))?;
    if canonical != input {
        return Err(ValidationError::new(
            ValidationStage::Canonical,
            "input differs from canonical bytes",
        ));
    }
    let expected = expected_integrity(&record)?;
    if !fixed_length_equal(&expected, &record.integrity) {
        return Err(ValidationError::new(
            ValidationStage::Integrity,
            "digest mismatch",
        ));
    }
    Ok(ValidatedRecord {
        record,
        bytes: canonical,
    })
}
