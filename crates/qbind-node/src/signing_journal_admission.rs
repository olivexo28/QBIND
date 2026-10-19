//! Run 422 — crate-internal workspace admission for the additive, isolated
//! retained-signature retrieval path.
//!
//! This module owns the *admission* of two fixed-capacity working buffers used
//! by [`crate::signing_reservation_journal::SigningReservationJournal::retrieve_retained`]:
//!
//! * [`AdmittedOutput`] — the caller-owned `[u8; OUTPUT_CAP]` signature output
//!   whose coverage must survive the retrieval return until its owner drops.
//! * [`EnvelopeScratch`] — the transient `[u8; ENVELOPE_CAP]` record/envelope
//!   scratch plus the admitted `[u8; JOURNAL_KEY_LEN]` journal key, released as
//!   soon as the owner drops it.
//!
//! Both buffers are admitted through the **existing** operational
//! [`SharedAccountant`] and its shared [`AggregateAuthority`]; no new ledger,
//! ceiling, partition, or multiplicity is introduced. The journal borrows the
//! admitted workspace; it never owns or reconstructs the safety accountant.
//!
//! Ownership/lifetime contract (type-enforced where noted, otherwise a trusted
//! implementation obligation):
//!
//! * Each buffer field is declared **before** its [`Reservation`] field. Rust
//!   drops fields in declaration order, so the covered bytes are destroyed first
//!   and the reservation (coverage) is released strictly afterwards — there is no
//!   release-then-recharge window and no interval where live bytes are uncharged.
//!   (Type-enforced by field order; the `res`-last invariant is a trusted
//!   obligation preserved by this module.)
//! * Both reservations are acquired in [`RetrievalWorkspaceOwner::admit`] BEFORE
//!   either covered buffer is constructed; if the second admission refuses, the
//!   first is released with no buffer ever built (clean rollback).
//! * The `charge()` amounts are compile-time `size_of` of the actual wrapper
//!   layouts plus the concrete working objects (backend-local prefixed key,
//!   borrowing decoder, checksum accumulator) — not an "admitted" marker flag.

// This additive retained-retrieval workspace has NO production caller yet (it is
// an isolated implementation-and-test path); every item below is exercised by
// the in-crate tests. Allow dead_code ONLY in non-test builds so a genuinely
// unused item is still reported under `cargo test`.
#![cfg_attr(not(test), allow(dead_code))]

use crate::safety_record_store::accounting::{Reservation, SharedAccountant};
use crate::safety_record_store::{SafetyBackend, SafetyStoreError};

/// Fixed signature-output workspace capacity (ML-DSA-44 signature bytes). The
/// journal's global signature/record format bounds are intentionally larger; a
/// valid record whose signature exceeds this capacity is a bounded refusal, not
/// corruption and not a trigger for a larger allocation.
pub(crate) const OUTPUT_CAP: usize = 2420;

/// Fixed record/envelope scratch capacity: the 4-byte outer storage checksum
/// envelope over the maximum supported journal record for this configuration
/// (`4 + 92 header + 2420 signature + 4 inner CRC = 2520`). This is the supported
/// MAXIMUM envelope length, not the length of every record.
pub(crate) const ENVELOPE_CAP: usize = 2520;

/// Canonical journal position-key length (`b"sj:v1:"`(6) + kind(1) + validator_id
/// BE(8) + network_genesis(32) + originating_view BE(8)).
pub(crate) const JOURNAL_KEY_LEN: usize = 55;

/// Backend-prefixed key length (`b"sig:"`(4) + [`JOURNAL_KEY_LEN`]).
pub(crate) const BACKEND_KEY_LEN: usize = 59;

/// Outer storage-checksum envelope length (big-endian CRC-32 prefix).
pub(crate) const OUTER_CRC_LEN: usize = 4;

/// Fixed record header length preceding the signature bytes (magic(4) + ver(2) +
/// kind(1) + stage(1) + validator_id(8) + genesis(32) + view(8) + sig_len(4)).
pub(crate) const RECORD_HEADER_LEN: usize = 92;

/// Inner journal record CRC-32 length (trailing, big-endian).
pub(crate) const INNER_CRC_LEN: usize = 4;

/// Envelope offset at which the signature bytes begin: the outer CRC (4) plus the
/// record header (92).
pub(crate) const ENVELOPE_SIG_OFFSET: usize = OUTER_CRC_LEN + RECORD_HEADER_LEN;

/// Minimum well-formed envelope length: a `Reserved` record carries zero
/// signature bytes, so its envelope is `4 + 92 + 4 = 100` bytes.
pub(crate) const MIN_ENVELOPE_LEN: usize = OUTER_CRC_LEN + RECORD_HEADER_LEN + INNER_CRC_LEN;

/// A bounded capacity refusal: the attempted length exceeds a fixed workspace
/// capacity. Carries no application-created `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WorkspaceCapacity {
    /// The attempted length.
    pub(crate) len: usize,
    /// The fixed capacity it exceeded.
    pub(crate) capacity: usize,
}

/// Structural (length/checksum) faults discovered while parsing an envelope into
/// a [`BorrowedRecordView`]. Fixed codes, no application-created `String`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EnvelopeStructureError {
    /// The envelope is shorter than the minimum well-formed length, or an
    /// internal region is shorter than its fixed layout requires.
    Truncated,
    /// The outer storage checksum does not match the record bytes.
    OuterChecksum,
    /// The inner journal record checksum does not match the record body.
    InnerChecksum,
    /// The declared signature length does not exactly consume the record body.
    LengthMismatch,
}

/// A zero-copy, non-allocating view of one stored envelope. All fields borrow the
/// admitted scratch buffer; nothing is copied out. Semantic validation (magic,
/// version, tag→enum, stage/signature consistency, position, binding) is the
/// journal's responsibility — this view only establishes structural bounds and
/// both checksum layers.
#[derive(Debug)]
pub(crate) struct BorrowedRecordView<'e> {
    /// `record_format_version` (persistence identifier).
    pub(crate) version: u16,
    /// Raw kind tag byte (validated to an enum by the journal).
    pub(crate) kind_tag: u8,
    /// Raw stage tag byte (validated to an enum by the journal).
    pub(crate) stage_tag: u8,
    /// Validator identity.
    pub(crate) validator_id: u64,
    /// Pinned network/genesis identity (32 bytes, borrowed).
    pub(crate) network_genesis: &'e [u8],
    /// Originating consensus view.
    pub(crate) originating_view: u64,
    /// Exact-message binding digest (32 bytes, borrowed).
    pub(crate) binding: &'e [u8],
    /// Record magic (4 bytes, borrowed).
    pub(crate) magic: &'e [u8],
    /// Retained signature bytes (borrowed; empty for a `Reserved` record).
    pub(crate) signature: &'e [u8],
}

impl<'e> BorrowedRecordView<'e> {
    /// Parse and structurally validate `envelope` (exactly `used` bytes) WITHOUT
    /// allocating. Verifies both checksum layers and every internal length
    /// relationship before exposing any borrowed region.
    pub(crate) fn parse(envelope: &'e [u8]) -> Result<Self, EnvelopeStructureError> {
        if envelope.len() < MIN_ENVELOPE_LEN {
            return Err(EnvelopeStructureError::Truncated);
        }
        // Outer storage checksum envelope: `[crc(4) | record]`.
        let stored_outer =
            u32::from_be_bytes([envelope[0], envelope[1], envelope[2], envelope[3]]);
        let record = &envelope[OUTER_CRC_LEN..];
        if crate::storage::signing_journal_crc32(record) != stored_outer {
            return Err(EnvelopeStructureError::OuterChecksum);
        }
        // Inner journal record checksum: `record = [body | crc(4)]`.
        if record.len() < RECORD_HEADER_LEN + INNER_CRC_LEN {
            return Err(EnvelopeStructureError::Truncated);
        }
        let (body, inner_crc) = record.split_at(record.len() - INNER_CRC_LEN);
        let stored_inner =
            u32::from_be_bytes([inner_crc[0], inner_crc[1], inner_crc[2], inner_crc[3]]);
        if crate::storage::signing_journal_crc32(body) != stored_inner {
            return Err(EnvelopeStructureError::InnerChecksum);
        }
        // `body.len() >= RECORD_HEADER_LEN` guaranteed by the check above.
        let sig_len = u32::from_be_bytes([body[88], body[89], body[90], body[91]]) as usize;
        // The declared signature length must EXACTLY consume the remaining body.
        if body.len() != RECORD_HEADER_LEN + sig_len {
            return Err(EnvelopeStructureError::LengthMismatch);
        }
        Ok(Self {
            magic: &body[0..4],
            version: u16::from_be_bytes([body[4], body[5]]),
            kind_tag: body[6],
            stage_tag: body[7],
            validator_id: u64::from_be_bytes(body[8..16].try_into().unwrap()),
            network_genesis: &body[16..48],
            originating_view: u64::from_be_bytes(body[48..56].try_into().unwrap()),
            binding: &body[56..88],
            signature: &body[RECORD_HEADER_LEN..RECORD_HEADER_LEN + sig_len],
        })
    }

    /// The retained signature length (zero for a `Reserved` record).
    pub(crate) fn sig_len(&self) -> usize {
        self.signature.len()
    }
}

/// The caller-owned signature output buffer. Its [`Reservation`] coverage
/// survives the retrieval return and is released only when this value drops.
///
/// Field order is load-bearing: `buf` is declared before `res`, so on drop the
/// covered bytes are destroyed first and the coverage is released afterwards.
#[derive(Debug)]
pub(crate) struct AdmittedOutput {
    buf: [u8; OUTPUT_CAP],
    used: usize,
    res: Reservation,
}

impl AdmittedOutput {
    fn new(res: Reservation) -> Self {
        Self {
            buf: [0u8; OUTPUT_CAP],
            used: 0,
            res,
        }
    }

    /// The fixed output capacity.
    pub(crate) fn capacity(&self) -> usize {
        OUTPUT_CAP
    }

    /// The number of valid signature bytes currently held.
    pub(crate) fn used(&self) -> usize {
        self.used
    }

    /// A borrowed view of the valid output bytes.
    pub(crate) fn view(&self) -> &[u8] {
        &self.buf[..self.used]
    }

    /// Copy `src` into the output, validating capacity BEFORE any mutation. On a
    /// capacity refusal the buffer and `used` are left unchanged.
    pub(crate) fn set(&mut self, src: &[u8]) -> Result<(), WorkspaceCapacity> {
        if src.len() > OUTPUT_CAP {
            return Err(WorkspaceCapacity {
                len: src.len(),
                capacity: OUTPUT_CAP,
            });
        }
        self.buf[..src.len()].copy_from_slice(src);
        self.used = src.len();
        Ok(())
    }

    /// The charge this output's reservation holds (test/diagnostic observer).
    pub(crate) fn charge(&self) -> u128 {
        self.res.charge()
    }
}

/// The transient record/envelope scratch plus the admitted journal key. Released
/// as soon as the owner drops it (its reservation is the last field).
#[derive(Debug)]
pub(crate) struct EnvelopeScratch {
    envelope: [u8; ENVELOPE_CAP],
    jkey: [u8; JOURNAL_KEY_LEN],
    jkey_len: usize,
    used: usize,
    res: Reservation,
}

impl EnvelopeScratch {
    fn new(res: Reservation) -> Self {
        Self {
            envelope: [0u8; ENVELOPE_CAP],
            jkey: [0u8; JOURNAL_KEY_LEN],
            jkey_len: 0,
            used: 0,
            res,
        }
    }

    /// The fixed journal-key buffer, for the non-allocating key encoder to write
    /// the canonical key into.
    pub(crate) fn journal_key_buf(&mut self) -> &mut [u8; JOURNAL_KEY_LEN] {
        &mut self.jkey
    }

    /// Record the validated journal-key length after encoding.
    pub(crate) fn set_jkey_len(&mut self, n: usize) {
        self.jkey_len = n;
    }

    /// The encoded journal key bytes.
    pub(crate) fn journal_key(&self) -> &[u8] {
        &self.jkey[..self.jkey_len]
    }

    /// The valid envelope bytes (exactly `used`).
    pub(crate) fn envelope(&self) -> &[u8] {
        &self.envelope[..self.used]
    }

    /// Record the validated envelope length after a bounded read.
    pub(crate) fn set_used(&mut self, n: usize) -> Result<(), WorkspaceCapacity> {
        if n > ENVELOPE_CAP {
            return Err(WorkspaceCapacity {
                len: n,
                capacity: ENVELOPE_CAP,
            });
        }
        self.used = n;
        Ok(())
    }

    /// Disjoint borrows of the journal key (read) and the full mutable envelope
    /// buffer (write), so a bounded backend read can fill the envelope while
    /// referencing the key simultaneously without a second key allocation.
    pub(crate) fn key_and_envelope(&mut self) -> (&[u8], &mut [u8]) {
        (&self.jkey[..self.jkey_len], &mut self.envelope[..])
    }

    /// The charge this scratch's reservation holds (test/diagnostic observer).
    pub(crate) fn charge(&self) -> u128 {
        self.res.charge()
    }
}

/// The compile-time charge for an [`AdmittedOutput`]: its actual wrapper layout
/// (the `[u8; OUTPUT_CAP]`, the `used` field, and the embedded [`Reservation`]).
pub(crate) const fn output_charge() -> u128 {
    core::mem::size_of::<AdmittedOutput>() as u128
}

/// The compile-time charge for an [`EnvelopeScratch`]: its actual wrapper layout
/// PLUS the concrete working objects used during a retrieval — the backend-local
/// fixed prefixed key (`[u8; BACKEND_KEY_LEN]` built on the backend stack), the
/// borrowing decoder, and the checksum accumulator.
pub(crate) fn envelope_charge() -> u128 {
    (core::mem::size_of::<EnvelopeScratch>()
        + BACKEND_KEY_LEN
        + core::mem::size_of::<BorrowedRecordView<'static>>()
        + core::mem::size_of::<u32>()) as u128
}

/// The owner that admits and constructs the retrieval workspace. It holds a clone
/// of the backend's EXISTING operational [`SharedAccountant`] (which shares its
/// [`AggregateAuthority`] with the sibling partition); it does not own, expose,
/// or reconstruct the safety accountant, and it never substitutes a fresh ledger.
#[derive(Debug)]
pub(crate) struct RetrievalWorkspaceOwner {
    accountant: SharedAccountant,
}

impl RetrievalWorkspaceOwner {
    /// Construct an owner against the backend's existing operational accountant.
    pub(crate) fn new(backend: &SafetyBackend) -> Self {
        Self {
            accountant: backend.accounting().clone(),
        }
    }

    /// Admit both workspace buffers. The output reservation is taken first, then
    /// the envelope reservation; if the second refuses, the first is released and
    /// NEITHER buffer is constructed (clean rollback). Both reservations are held
    /// before either covered buffer exists.
    pub(crate) fn admit(&self) -> Result<(AdmittedOutput, EnvelopeScratch), SafetyStoreError> {
        let out_res = self.accountant.reserve(output_charge())?;
        let env_res = match self.accountant.reserve(envelope_charge()) {
            Ok(r) => r,
            Err(e) => {
                out_res.release_now();
                return Err(e);
            }
        };
        Ok((AdmittedOutput::new(out_res), EnvelopeScratch::new(env_res)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_trust_bundle::TrustBundleEnvironment;
    use crate::safety_record_store::{
        PinnedSafetyContext, SafetyBackend, SafetyBackendPolicy, SafetyRecordOwner, ValidatedRecord,
    };
    use crate::signing_reservation_journal::{
        BindingDigest, RefuseReason, RetainedDelivery, RetrievalError, SigningDecisionRecord,
        SigningJournalStorage, SigningKind, SigningOwnershipDomain, SigningPosition,
        SigningRecordStage, SigningReservationJournal, SIGNING_RECORD_FORMAT_VERSION,
    };
    use crate::storage::{InMemoryConsensusStorage, RocksDbConsensusStorage, StorageError};
    use qbind_consensus::ValidatorId;
    use std::sync::Arc;

    // ---- fixtures ---------------------------------------------------------

    fn ctx(n: u64, s_sig: usize) -> PinnedSafetyContext {
        PinnedSafetyContext {
            network_genesis_id: [1u8; 32],
            authority_context_ref: [2u8; 32],
            chain_id: 42,
            epoch: 7,
            qc_suite_id: 7,
            timeout_suite_id: 100,
            s_sig,
            validators: (0..n).map(|i| (ValidatorId::new(i), 1u64)).collect(),
            require_height_equals_round: false,
        }
    }

    /// Open an enabled test backend, bind its accountant via `attach`, and
    /// establish the bootstrap record.
    fn bound_owner(c: PinnedSafetyContext) -> (tempfile::TempDir, SafetyRecordOwner) {
        let dir = tempfile::tempdir().unwrap();
        let backend = SafetyBackend::open_or_initialize(
            dir.path(),
            SafetyBackendPolicy::EnabledForTesting,
            TrustBundleEnvironment::Devnet,
        )
        .unwrap();
        let owner = SafetyRecordOwner::attach(backend, c).unwrap();
        owner.initialize(true).unwrap();
        (dir, owner)
    }

    fn pos(view: u64) -> SigningPosition {
        SigningPosition {
            validator_id: 3,
            network_genesis: [9u8; 32],
            kind: SigningKind::Proposal,
            originating_view: view,
        }
    }

    fn bind(b: u8) -> BindingDigest {
        BindingDigest([b; 32])
    }

    fn encode_record(
        position: SigningPosition,
        binding: BindingDigest,
        stage: SigningRecordStage,
        sig_len: usize,
    ) -> Vec<u8> {
        let retained_signature = match stage {
            SigningRecordStage::Signed => Some(vec![0xABu8; sig_len]),
            SigningRecordStage::Reserved => None,
        };
        SigningDecisionRecord {
            record_format_version: SIGNING_RECORD_FORMAT_VERSION,
            position,
            binding,
            stage,
            retained_signature,
        }
        .encode()
        .unwrap()
    }

    /// Build a MODEL-backed journal over an `InMemoryConsensusStorage`, writing
    /// each `(position, encoded_record)` directly at its canonical journal key.
    fn model_journal(
        records: &[(SigningPosition, Vec<u8>)],
    ) -> (Arc<InMemoryConsensusStorage>, SigningReservationJournal) {
        let store = Arc::new(InMemoryConsensusStorage::new());
        for (p, bytes) in records {
            store
                .put_signing_record_synced(&p.storage_key(), bytes)
                .unwrap();
        }
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        (store, journal)
    }

    // ---- 1. admission / rollback / coverage -------------------------------

    #[test]
    fn admit_charges_both_before_any_buffer_and_releases_on_drop() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let baseline = backend.accounting_current();
        {
            let (output, scratch) = RetrievalWorkspaceOwner::new(backend).admit().unwrap();
            // Both reservations are live and equal to the exact compile-time charges.
            assert_eq!(output.charge(), output_charge());
            assert_eq!(scratch.charge(), envelope_charge());
            assert_eq!(
                backend.accounting_current(),
                baseline + output_charge() + envelope_charge()
            );
        }
        // Both released after the owners drop.
        assert_eq!(backend.accounting_current(), baseline);
    }

    #[test]
    fn admit_second_refusal_rolls_back_the_first_cleanly() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let baseline = backend.accounting_current();
        let cap = backend.accounting_cap().unwrap();
        // Leave headroom for exactly the OUTPUT charge but NOT the envelope charge,
        // so the FIRST reservation succeeds and the SECOND refuses.
        let headroom = output_charge() + envelope_charge() / 2;
        let fill = cap - baseline - headroom;
        let standing = backend.reserve_standing_for_test(fill).unwrap();
        let err = RetrievalWorkspaceOwner::new(backend).admit();
        assert!(err.is_err(), "second admission must refuse");
        // Clean rollback: the first reservation was released, nothing leaked.
        assert_eq!(backend.accounting_current(), baseline + fill);
        drop(standing);
        assert_eq!(backend.accounting_current(), baseline);
    }

    #[test]
    fn scratch_releases_while_output_coverage_survives() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let baseline = backend.accounting_current();
        let (output, scratch) = RetrievalWorkspaceOwner::new(backend).admit().unwrap();
        assert_eq!(
            backend.accounting_current(),
            baseline + output_charge() + envelope_charge()
        );
        drop(scratch);
        // Output coverage survives after the scratch is released.
        assert_eq!(backend.accounting_current(), baseline + output_charge());
        drop(output);
        assert_eq!(backend.accounting_current(), baseline);
    }

    // ---- 2. non-allocating key encoding -----------------------------------

    #[test]
    fn encode_key_into_matches_legacy_storage_key() {
        for (kind, view) in [
            (SigningKind::Proposal, 0u64),
            (SigningKind::Vote, 1),
            (SigningKind::Proposal, u64::MAX),
            (SigningKind::Vote, 0x0102_0304_0506_0708),
        ] {
            let p = SigningPosition {
                validator_id: 0xAABB_CCDD_1122_3344,
                network_genesis: [7u8; 32],
                kind,
                originating_view: view,
            };
            let legacy = p.storage_key();
            let mut fixed = [0u8; JOURNAL_KEY_LEN];
            let n = p.encode_key_into(&mut fixed).unwrap();
            assert_eq!(n, JOURNAL_KEY_LEN);
            assert_eq!(legacy.len(), JOURNAL_KEY_LEN);
            assert_eq!(&fixed[..], legacy.as_slice());
        }
    }

    // ---- 3. classification over the model backend -------------------------

    fn admit_ws(owner: &SafetyRecordOwner) -> (AdmittedOutput, EnvelopeScratch) {
        RetrievalWorkspaceOwner::new(owner.backend_for_test())
            .admit()
            .unwrap()
    }

    #[test]
    fn reserved_record_recovers_as_potentially_signed() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(5);
        let b = bind(1);
        let (_s, journal) = model_journal(&[(p, encode_record(p, b, SigningRecordStage::Reserved, 0))]);
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r, RetainedDelivery::PotentiallySigned));
        assert_eq!(output.used(), 0);
    }

    #[test]
    fn signed_recovered_reissues_and_delivers_cache_free_repeatedly() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(6);
        let b = bind(2);
        let (store, journal) =
            model_journal(&[(p, encode_record(p, b, SigningRecordStage::Signed, 2420))]);
        // First recovered delivery.
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        match r {
            RetainedDelivery::Retained(sig) => {
                assert_eq!(sig.len(), 2420);
                assert!(sig.iter().all(|&x| x == 0xAB));
            }
            other => panic!("expected Retained, got {other:?}"),
        }
        assert_eq!(output.used(), 2420);
        // Record is preserved record-only (model), unchanged by reissue.
        let stored = store.get_signing_record(&p.storage_key()).unwrap().unwrap();
        assert_eq!(stored, encode_record(p, b, SigningRecordStage::Signed, 2420));
        // Repeated recovered acknowledgement, still cache-free, still delivers.
        let mut output2 = output;
        let r2 = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output2)
            .unwrap();
        assert!(matches!(r2, RetainedDelivery::Retained(_)));
    }

    #[test]
    fn signed_live_unacked_is_potentially_signed_without_delivery() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(7);
        let b = bind(3);
        let (_s, journal) =
            model_journal(&[(p, encode_record(p, b, SigningRecordStage::Signed, 64))]);
        journal.insert_live_for_test(p, b, false);
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r, RetainedDelivery::PotentiallySigned));
        assert_eq!(output.used(), 0);
    }

    #[test]
    fn signed_live_acked_delivers_without_reissue() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(8);
        let b = bind(4);
        let (_s, journal) =
            model_journal(&[(p, encode_record(p, b, SigningRecordStage::Signed, 100))]);
        journal.insert_live_for_test(p, b, true);
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r, RetainedDelivery::Retained(_)));
        assert_eq!(output.used(), 100);
    }

    #[test]
    fn missing_record_returns_missing() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(9);
        let b = bind(5);
        let (_s, journal) = model_journal(&[]);
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r, RetainedDelivery::Missing));
        assert_eq!(output.used(), 0);
    }

    #[test]
    fn position_mismatch_is_typed_refusal() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let want = pos(10);
        let other = pos(11);
        let b = bind(6);
        // Store a record encoding `other` at `want`'s key.
        let store = Arc::new(InMemoryConsensusStorage::new());
        store
            .put_signing_record_synced(
                &want.storage_key(),
                &encode_record(other, b, SigningRecordStage::Signed, 32),
            )
            .unwrap();
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        let r = journal
            .retrieve_retained(&want, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(
            r,
            RetainedDelivery::Refused(RefuseReason::PositionMismatch)
        ));
        assert_eq!(output.used(), 0);
    }

    #[test]
    fn binding_conflict_is_typed_refusal() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(12);
        let stored_binding = bind(7);
        let request_binding = bind(8);
        let (_s, journal) = model_journal(&[(
            p,
            encode_record(p, stored_binding, SigningRecordStage::Signed, 32),
        )]);
        let r = journal
            .retrieve_retained(&p, &request_binding, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(
            r,
            RetainedDelivery::Refused(RefuseReason::BindingConflict)
        ));
        assert_eq!(output.used(), 0);
    }

    #[test]
    fn malformed_and_truncated_records_are_refused() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(13);
        let b = bind(9);
        // Truncated: below the minimum record length.
        let store = Arc::new(InMemoryConsensusStorage::new());
        store
            .put_signing_record_synced(&p.storage_key(), &vec![0u8; 40])
            .unwrap();
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(
            r,
            RetainedDelivery::Refused(RefuseReason::MalformedRecord)
        ));
        // Garbage of a plausible length: inner CRC / magic fail.
        store
            .put_signing_record_synced(&p.storage_key(), &vec![0u8; 120])
            .unwrap();
        let r2 = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(
            r2,
            RetainedDelivery::Refused(RefuseReason::MalformedRecord)
        ));
        assert_eq!(output.used(), 0);
    }

    #[test]
    fn valid_record_exceeding_workspace_is_distinct_capacity_refusal() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(14);
        let b = bind(10);
        // A VALID Signed record whose signature (3000) is within the global format
        // limit (8 KiB) but exceeds the admitted workspace: a distinct bounded
        // refusal, never corruption, never a larger allocation.
        let (_s, journal) =
            model_journal(&[(p, encode_record(p, b, SigningRecordStage::Signed, 3000))]);
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(
            r,
            RetainedDelivery::Refused(RefuseReason::WorkspaceCapacityExceeded)
        ));
        assert_eq!(output.used(), 0);
    }

    // ---- 4. uncertainty blocking (zero side effects) ----------------------

    #[test]
    fn uncertainty_blocks_with_zero_side_effects() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(15);
        let b = bind(11);
        let (store, journal) =
            model_journal(&[(p, encode_record(p, b, SigningRecordStage::Signed, 2420))]);
        journal.set_accounting_uncertain_for_test(true);
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r, RetainedDelivery::Blocked));
        // No output mutation, no scratch read, no reissue, no latch clearing.
        assert_eq!(output.used(), 0);
        assert_eq!(scratch.journal_key().len(), 0);
        let stored = store.get_signing_record(&p.storage_key()).unwrap().unwrap();
        assert_eq!(stored, encode_record(p, b, SigningRecordStage::Signed, 2420));
    }

    // ---- 5. unsupported backend refuses -----------------------------------

    #[derive(Debug, Default)]
    struct UnsupportedStore {
        domain: std::sync::OnceLock<Arc<SigningOwnershipDomain>>,
    }

    impl SigningJournalStorage for UnsupportedStore {
        fn get_signing_record(&self, _key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }
        fn put_signing_record_synced(&self, _key: &[u8], _v: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            Ok(None)
        }
        fn put_signing_metadata_synced(&self, _v: &[u8]) -> Result<(), StorageError> {
            Ok(())
        }
        fn put_signing_record_and_metadata_synced(
            &self,
            _rk: &[u8],
            _rv: &[u8],
            _mv: &[u8],
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn for_each_signing_namespace_entry(
            &self,
            _visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            Ok(())
        }
        fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
            self.domain
                .get_or_init(SigningOwnershipDomain::new)
                .clone()
        }
    }

    #[test]
    fn default_unsupported_backend_refuses() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let p = pos(16);
        let b = bind(12);
        let store = Arc::new(UnsupportedStore::default());
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store as Arc<dyn SigningJournalStorage>,
        );
        let r = journal.retrieve_retained(&p, &b, &mut scratch, &mut output);
        assert!(matches!(r, Err(RetrievalError::Unsupported)));
        assert_eq!(output.used(), 0);
    }

    // ---- 6. real RocksDB envelope preservation ----------------------------

    #[test]
    fn rocksdb_recovered_envelope_is_preserved_byte_for_byte() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let (mut output, mut scratch) = admit_ws(&owner);
        let jdir = tempfile::tempdir().unwrap();
        let store = Arc::new(RocksDbConsensusStorage::open(jdir.path()).unwrap());
        let p = pos(17);
        let b = bind(13);
        let record = encode_record(p, b, SigningRecordStage::Signed, 2420);
        // Durable backend wraps the record in its outer CRC envelope on write.
        store
            .put_signing_record_synced(&p.storage_key(), &record)
            .unwrap();
        let before = store.get_signing_record(&p.storage_key()).unwrap().unwrap();
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        // Recovered (no live entry) → exact-envelope synced reissue before delivery.
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r, RetainedDelivery::Retained(_)));
        assert_eq!(output.used(), 2420);
        // The stored record is byte-for-byte identical after the reissue (the exact
        // already-validated envelope was rewritten, not re-wrapped).
        let after = store.get_signing_record(&p.storage_key()).unwrap().unwrap();
        assert_eq!(before, after);
    }

    // ---- 7. measured coexistence gate (N=4, S_sig=2420) -------------------

    #[test]
    fn measured_coexistence_within_both_unchanged_caps() {
        let (_d, owner) = bound_owner(ctx(4, 2420));

        // Hold a REAL ValidatedRecord throughout retrieval (its retained-holder
        // reservation is live in the operational partition; it is NOT a
        // PreparedPin or DecidedVote).
        let validated: ValidatedRecord = owner
            .read_validate(None::<&crate::safety_record_store::FixtureCommittedHistory>)
            .expect("bootstrap record validates");

        let backend = owner.backend_for_test();
        let op_cap = backend.accounting_cap().expect("operational cap bound");
        let agg_cap = backend
            .accounting_aggregate_cap()
            .expect("aggregate cap bound");
        let baseline_op = backend.accounting_current();
        let baseline_agg = backend.accounting_aggregate_current();
        // Context ownership is charged in the aggregate (distinct partition).
        assert!(baseline_agg >= baseline_op);

        // Admit the workspace against the EXISTING accountant.
        let (mut output, mut scratch) = RetrievalWorkspaceOwner::new(backend).admit().unwrap();
        let peak_op = backend.accounting_current();
        let peak_agg = backend.accounting_aggregate_current();
        assert_eq!(
            peak_op,
            baseline_op + output_charge() + envelope_charge()
        );
        // Both unchanged caps are respected at the retrieval peak.
        assert!(peak_op <= op_cap, "operational peak {peak_op} <= {op_cap}");
        assert!(peak_agg <= agg_cap, "aggregate peak {peak_agg} <= {agg_cap}");

        // A successful retrieval within both caps.
        let p = pos(18);
        let bdg = bind(14);
        let (_s, journal) =
            model_journal(&[(p, encode_record(p, bdg, SigningRecordStage::Signed, 2420))]);
        let r = journal
            .retrieve_retained(&p, &bdg, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r, RetainedDelivery::Retained(_)));
        assert_eq!(output.used(), 2420);

        // Scratch cleanup with the output still charged.
        drop(scratch);
        assert_eq!(backend.accounting_current(), baseline_op + output_charge());
        // Final output cleanup returns to baseline (the ValidatedRecord is retained).
        drop(output);
        assert_eq!(backend.accounting_current(), baseline_op);

        // The required live ValidatedRecord object is still held here; drop it
        // only now, after the workspace lifecycle has been fully observed.
        drop(validated);
    }

    // ---- 8. pressure refusal and retry after pressure removal -------------

    #[test]
    fn pressure_refuses_then_retry_succeeds() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let baseline = backend.accounting_current();
        // The aggregate authority is the binding constraint (it also carries the
        // context-ownership charge). Consume all AGGREGATE headroom so admission
        // refuses.
        let fill = backend.accounting_aggregate_cap().unwrap()
            - backend.accounting_aggregate_current();
        let standing = backend.reserve_standing_for_test(fill).unwrap();
        assert!(RetrievalWorkspaceOwner::new(backend).admit().is_err());
        // Remove the pressure; admission now succeeds.
        drop(standing);
        let (output, scratch) = RetrievalWorkspaceOwner::new(backend).admit().unwrap();
        assert_eq!(
            backend.accounting_current(),
            baseline + output_charge() + envelope_charge()
        );
        drop((output, scratch));
        assert_eq!(backend.accounting_current(), baseline);
    }
}