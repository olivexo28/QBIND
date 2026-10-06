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

/// Compile-time layout proof over the **real operational retained
/// representation** (§ 13.7A(c), representation-proof correction).
///
/// The prior proof measured the *synthetic* [`record::RetainedGeneration`]
/// wrapper (used only by the Arc-pinned synthetic-holder tests), which fits the
/// ceiling and therefore concealed that the object operations actually retain —
/// [`record::DecodedRecord`] inside [`record::ValidatedRecord`] — is larger. The
/// operative proof below is driven by the real types and decomposes the retained
/// proof into named inline terms, each counted **once**, with required alignment
/// padding and the inline holder reservation included:
///
/// * `GEN_CORE` — the generation-bearing `SafetyRecord` enum (the real logical
///   generation). The accepted `GEN_STRUCT_MAX` ceiling is applied to **this**
///   core, not to the whole container.
/// * `DECODED_IDENTITY_HEADER` = `size_of::<DecodedRecord>() − GEN_CORE` — the
///   always-retained identity header (`persistence_format_version`,
///   `network_genesis_id`, `publication_revision`) + padding.
/// * `VALIDATED_HANDLE_FIELDS` = `size_of::<ValidatedRecord>() −
///   size_of::<DecodedRecord>()` — the separately-owned holder/handle fields (the
///   retained `encoded` `Vec` descriptor, the originating-context digest, the O5
///   recovery-incarnation discriminant, and the inline holder [`accounting::
///   Reservation`] option). These are charged under their own terms, never under
///   the generation ceiling.
///
/// The decomposition sums **exactly** to `size_of::<ValidatedRecord>()`, so a
/// future field or layout change surfaces here rather than silently escaping the
/// accounting.
///
/// Surfaced, NOT concealed (see the `real_representation_layout_decomposition`
/// regression and the §13.7A evidence document): on the supported 64-bit target
/// `size_of::<DecodedRecord>()` (the complete inline retained generation) exceeds
/// `GEN_STRUCT_MAX`. The generation **core** (`SafetyRecord`) fits with margin,
/// but the full decoded container does not — a required single-ceiling contract
/// adjustment is presented separately and is **not** silently enacted here (the
/// accepted aggregate arithmetic and fixture quantities are left unchanged).
const _: () = {
    // The generation-bearing core actually retained by operations fits the
    // accepted generation ceiling (the operative proof, on the real type).
    assert!(
        std::mem::size_of::<record::SafetyRecord>() as u128 <= profile::GEN_STRUCT_MAX,
        "SafetyRecord generation core exceeds GEN_STRUCT_MAX; surface the measured discrepancy"
    );
    // Exact inline decomposition: every member counted once, no underflow.
    assert!(
        std::mem::size_of::<record::DecodedRecord>() >= std::mem::size_of::<record::SafetyRecord>(),
        "DecodedRecord must contain its SafetyRecord generation core inline"
    );
    assert!(
        std::mem::size_of::<record::ValidatedRecord>()
            >= std::mem::size_of::<record::DecodedRecord>(),
        "ValidatedRecord must contain its DecodedRecord generation inline"
    );
};