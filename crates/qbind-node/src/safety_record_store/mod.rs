//! Run 422 D7-D14 — the isolated, **disabled-by-default** safety-record storage
//! component (accepted D14 contract, § 13 of
//! `QBIND_CONSENSUS_RECOVERY_SIGNING_HISTORY_CORRESPONDENCE_CONTRACT.md`).
//!
//! # Scope and isolation
//!
//! This component is an isolated bounded storage successor. It is **not** wired
//! into `BasicHotStuffEngine`, `binary_consensus_loop`, production startup, or
//! any signer call path; it adds no public CLI command. The backend policy
//! defaults to [`backend::SafetyBackendPolicy::Disabled`] and refuses to open,
//! and MainNet is always refused. The component is constructed only from its own
//! focused tests (and any future, explicitly non-default, opt-in integration).
//!
//! It implements:
//!
//! * versioned safety-record encoding + **bounded** decoding ([`codec`]),
//! * structural + semantic validation with independently supplied inputs
//!   ([`validate`]) — stage-2 crypto verification is deliberately unwired, so
//!   every validated record is carried [`record::EvidenceStatus::Unverified`],
//! * O1 initialize / O2 open / O3 read-validate / O4 publish / O5 re-acknowledge
//!   with one shared serialization domain + expected-revision fencing
//!   ([`owner`], [`backend`]),
//! * executable component-level allocation admission + accounting
//!   ([`accounting`], [`profile`]).
//!
//! # What it does NOT establish
//!
//! Durable anti-rollback, genesis-authority activation, engine / prepared-decision
//! integration, recovery-time signature verification, peer-driven apply, or
//! readiness promotion. Process termination in its tests is not power-loss
//! testing; CRC/binding checks are not certificate authentication; local synced
//! writes do not establish whole-copy anti-rollback or cross-host exclusivity.

pub mod accounting;
pub mod backend;
pub mod codec;
pub mod error;
pub mod owner;
pub mod profile;
pub mod record;
pub mod validate;

pub use backend::{InjectFault, PublishOutcome, SafetyBackend, SafetyBackendPolicy};
pub use error::SafetyStoreError;
pub use owner::{PublishResult, SafetyMeta, SafetyRecordOwner};
pub use profile::PinnedSafetyContext;
pub use record::{
    DecodedRecord, EvidenceStatus, LockedRecord, SafetyRecord, SupportingEvidence, ValidatedRecord,
};
pub use validate::{CommittedHistory, FixtureCommittedHistory};

/// Source/test-only: record CRC-32 over a body (for re-sealing mutated buffers
/// in tests). Never used by production code paths.
pub fn codec_crc_for_test(body: &[u8]) -> u32 {
    codec::record_crc32_for_test(body)
}

/// Compile-time guard that the whole-enum decoded-generation wrapper does not
/// exceed its proposed `GEN_STRUCT_MAX` ceiling on the supported 64-bit target
/// (§ 13.7A(c)). If the measured native layout ever exceeds this ceiling the
/// build fails here — the discrepancy is surfaced, never concealed by omitting
/// retained fields or silently relaxing the bound.
const _: () = {
    assert!(
        std::mem::size_of::<record::RetainedGeneration>() as u128 <= profile::GEN_STRUCT_MAX,
        "RetainedGeneration native layout exceeds GEN_STRUCT_MAX; surface the measured discrepancy"
    );
};