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
    DecodedRecord, EvidenceStatus, LockedRecord, RetainedRecord, SafetyRecord, SupportingEvidence,
    ValidatedRecord,
};
pub use validate::{CommittedHistory, FixtureCommittedHistory};

/// Source/test-only: record CRC-32 over a body (for re-sealing mutated buffers
/// in tests). Never used by production code paths.
pub fn codec_crc_for_test(body: &[u8]) -> u32 {
    codec::record_crc32_for_test(body)
}

/// Compile-time **representation-and-charge** proof over the **real operational
/// retained representation** (§ 13.7A(c.4), D7-D14 representation correction).
///
/// The prior proof measured the *synthetic* [`record::RetainedGeneration`]
/// wrapper (used only by the Arc-pinned synthetic-holder tests) and, in its
/// corrected form, surfaced that the then-retained [`record::DecodedRecord`]
/// exceeded the ceiling — concluding a ceiling increase was required. That
/// conclusion is **withdrawn**: `DecodedRecord` was only over the ceiling because
/// it still retained the two header fields the § 13.7A(c.4) inventory requires be
/// **discarded** after validation (`persistence_format_version`,
/// `network_genesis_id`). The operative retained object is now
/// [`record::RetainedRecord`] (post-validation fields only) held inside
/// [`record::ValidatedRecord`], and it **fits** the accepted `GEN_STRUCT_MAX`
/// with margin — no ceiling increase is necessary.
///
/// The proof connects complete objects to enforced charges rather than relying on
/// size-subtraction identities:
///
/// * `RETAINED_GEN` = `size_of::<RetainedRecord>()` — the real retained
///   generation (publication revision + the `SafetyRecord` core). The accepted
///   `GEN_STRUCT_MAX` ceiling is applied to **this complete object**, not to a
///   partial core, and it holds.
/// * `VALIDATED_HANDLE_FIELDS` = `size_of::<ValidatedRecord>() −
///   size_of::<RetainedRecord>()` — the separately-owned holder/handle fields (the
///   retained `encoded` `Vec` descriptor, the originating-context digest, the O5
///   recovery-incarnation discriminant, and the inline holder
///   [`accounting::Reservation`] option). These are charged under their own terms
///   (the holder reservation and the encoded-buffer term), never under the
///   generation ceiling.
///
/// The decomposition sums **exactly** to `size_of::<ValidatedRecord>()`, so a
/// future field or layout change surfaces here (and in the
/// `real_representation_layout_decomposition` regression) rather than silently
/// escaping the accounting. The transient [`record::DecodedRecord`] is **not**
/// part of the retained representation — it exists only across decode→validation
/// and is charged as transient validation scratch — so its size is deliberately
/// not folded into the retained generation.
const _: () = {
    // The complete retained generation actually held by operations fits the
    // accepted generation ceiling (the operative proof, on the real retained
    // object — not a partial core, and not the transient decoded container).
    assert!(
        std::mem::size_of::<record::RetainedRecord>() as u128 <= profile::GEN_STRUCT_MAX,
        "RetainedRecord retained generation exceeds GEN_STRUCT_MAX; surface the discrepancy"
    );
    // The retained generation contains its SafetyRecord generation core inline.
    assert!(
        std::mem::size_of::<record::RetainedRecord>()
            >= std::mem::size_of::<record::SafetyRecord>(),
        "RetainedRecord must contain its SafetyRecord generation core inline"
    );
    // ValidatedRecord = the retained generation inline + separately-charged
    // holder/handle fields; the decomposition must not underflow.
    assert!(
        std::mem::size_of::<record::ValidatedRecord>()
            >= std::mem::size_of::<record::RetainedRecord>(),
        "ValidatedRecord must contain its RetainedRecord generation inline"
    );
    // The handle/holder fields are a genuinely non-empty separately-charged term.
    assert!(
        std::mem::size_of::<record::ValidatedRecord>()
            > std::mem::size_of::<record::RetainedRecord>(),
        "ValidatedRecord must carry separately-charged holder/handle fields"
    );
    // INDEPENDENT COVERAGE INEQUALITY (§ 13.7B finding-#2 correction): the
    // complete inline `ValidatedRecord` representation is covered by the retained
    // generation core PLUS the independently-inventoried holder-handle charge
    // (`validated_holder_handle_bytes`, summed from the field inventory + one
    // alignment allowance — NOT by subtracting the two sizes). This is a real
    // inequality, not a `retained + (validated − retained) == validated`
    // tautology: if a future field or padding change outgrows the inventory the
    // charge no longer covers the layout and this assertion fails at compile
    // time, surfacing the discrepancy rather than letting handle bytes escape the
    // enforced per-proof holder charge.
    let handle_inventory = std::mem::size_of::<record::EvidenceStatus>()
        + std::mem::size_of::<Vec<u8>>()
        + std::mem::size_of::<[u8; 32]>()
        + std::mem::size_of::<Option<u64>>()
        + std::mem::size_of::<Option<accounting::Reservation>>()
        + std::mem::align_of::<record::ValidatedRecord>();
    assert!(
        std::mem::size_of::<record::ValidatedRecord>()
            <= std::mem::size_of::<record::RetainedRecord>() + handle_inventory,
        "the independently-inventoried holder-handle charge must cover the real \
         inline ValidatedRecord layout beyond its RetainedRecord generation"
    );
};