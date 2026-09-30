//! Fixture-only typed substrate for the Titan Forward minimal kernel.
//! No value validated by this crate is an operational authority record.

pub mod admission;
pub mod authority;
pub mod codec;
pub mod fixture_projection;
pub mod outcome;
pub mod records;
pub mod selector;
pub mod target;
pub mod validation;

pub use codec::{ValidatedRecord, encode_fixture, validate_bytes};
pub use validation::{ValidationError, ValidationStage};
