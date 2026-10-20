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

    /// RUN 422 — begin writing a fresh signature directly into the admitted
    /// output buffer. Logical validity is cleared (`used = 0`) BEFORE any
    /// mutable access is granted, so a previously committed length or its
    /// trailing bytes can never be observed as part of a new, uncommitted (or
    /// abandoned) write. The returned [`OutputWriter`] exclusively borrows this
    /// output; it does not own or release the covering reservation.
    pub(crate) fn begin_write(&mut self) -> OutputWriter<'_> {
        self.used = 0;
        OutputWriter { out: self }
    }

    /// The charge this output's reservation holds (test/diagnostic observer).
    pub(crate) fn charge(&self) -> u128 {
        self.res.charge()
    }

    /// RUN 422 — true iff this output's LIVE covering reservation was issued by
    /// `acct` (its exact operational partition AND aggregate authority). The
    /// covering reservation is a private field constructed only by [`admit`] /
    /// [`admit_output`] and released only by a consuming `release_now`/drop, so a
    /// positive result establishes that THIS buffer's coverage is live and owned
    /// by `acct`. Non-allocating; acquires no accounting lock; exposes nothing.
    pub(crate) fn is_covered_by(&self, acct: &SharedAccountant) -> bool {
        self.res.is_issued_by(acct)
    }
}

/// RUN 422 — a scoped, exclusive writer over an [`AdmittedOutput`]. Obtained
/// from [`AdmittedOutput::begin_write`], which clears logical validity first, so
/// while this writer is live the output holds no valid bytes (`used == 0`). The
/// writer borrows the output mutably and neither owns nor releases its covering
/// reservation; dropping it without a successful [`commit`](OutputWriter::commit)
/// leaves the output empty. A successful commit establishes a valid byte span
/// ONLY — never signature verification, authorization, journal acknowledgement,
/// or delivery permission.
#[derive(Debug)]
pub(crate) struct OutputWriter<'a> {
    out: &'a mut AdmittedOutput,
}

impl OutputWriter<'_> {
    /// The full fixed-capacity output buffer to write the signature into:
    /// exactly [`OUTPUT_CAP`] bytes, matching [`AdmittedOutput::capacity`].
    pub(crate) fn buffer(&mut self) -> &mut [u8] {
        &mut self.out.buf[..]
    }

    /// Commit exactly `n` written bytes as the valid output span, validating the
    /// length BEFORE recording it. On a capacity refusal `used` stays `0` (the
    /// output remains empty / logically invalid) and the bytes already in the
    /// buffer are never exposed as a committed result. A zero-length commit is
    /// structurally permitted here; exact signature-length validation remains a
    /// future caller obligation.
    pub(crate) fn commit(self, n: usize) -> Result<usize, WorkspaceCapacity> {
        if n > OUTPUT_CAP {
            return Err(WorkspaceCapacity {
                len: n,
                capacity: OUTPUT_CAP,
            });
        }
        self.out.used = n;
        Ok(n)
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

    /// RUN 422 — true iff this scratch's LIVE covering reservation was issued by
    /// `acct` (its exact operational partition AND aggregate authority). Same
    /// guarantees as [`AdmittedOutput::is_covered_by`]: non-allocating, lock-free,
    /// and exposing neither the reservation nor its charge.
    pub(crate) fn is_covered_by(&self, acct: &SharedAccountant) -> bool {
        self.res.is_issued_by(acct)
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

    /// RUN 422 — construct an owner from an accountant handle ALREADY INSTALLED
    /// in a signing domain's association (cloned by the caller under the
    /// journal-domain guard and moved in here). Unlike [`new`](RetrievalWorkspaceOwner::new),
    /// it reads no backend and selects no ledger: the caller supplies the installed
    /// operational accountant directly, so no caller-selected substitute backend can
    /// be introduced and no fresh ledger is allocated.
    pub(crate) fn from_installed(accountant: SharedAccountant) -> Self {
        Self { accountant }
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

    /// RUN 422 — admit ONLY the caller-owned output buffer, reserving exactly
    /// [`output_charge()`] through the SAME existing operational accountant
    /// (which shares its aggregate authority with the sibling partition). No
    /// envelope scratch is allocated or charged, and no new accountant,
    /// partition, ceiling, multiplicity, or independent allowance is introduced.
    /// On a reservation refusal nothing is constructed and both ledgers are
    /// unchanged. The paired [`admit`](RetrievalWorkspaceOwner::admit) is left
    /// unchanged.
    pub(crate) fn admit_output(&self) -> Result<AdmittedOutput, SafetyStoreError> {
        let out_res = self.accountant.reserve(output_charge())?;
        Ok(AdmittedOutput::new(out_res))
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
        BindingDigest, CheckedRetrievalError, RefuseReason, RetainedDelivery, RetrievalError,
        SigningDecisionRecord, SigningJournalStorage, SigningKind, SigningOwnershipDomain,
        SigningPosition, SigningRecordStage, SigningReservationJournal, WorkspaceAdmissionError,
        SIGNING_RECORD_FORMAT_VERSION,
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

    // ---- 8. pressure refusal then ACTUAL retrieval after relief -----------

    #[test]
    fn pressure_refuses_then_retry_succeeds() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();

        // Hold a REAL ValidatedRecord proof live throughout (its retained-holder
        // reservation is live in the operational partition; it is NOT a
        // PreparedPin or DecidedVote).
        let validated: ValidatedRecord = owner
            .read_validate(None::<&crate::safety_record_store::FixtureCommittedHistory>)
            .expect("bootstrap record validates");

        // (1) Operational and aggregate baselines recorded SEPARATELY; context
        // ownership is charged in the aggregate (distinct partition).
        let baseline_op = backend.accounting_current();
        let baseline_agg = backend.accounting_aggregate_current();
        assert!(baseline_agg >= baseline_op);
        // Existing profile ceilings are observed and preserved, never modified.
        let op_cap = backend.accounting_cap().expect("operational cap bound");
        let agg_cap = backend
            .accounting_aggregate_cap()
            .expect("aggregate cap bound");

        // (2) Temporary pressure: consume all AGGREGATE headroom so workspace
        // admission refuses. The standing reservation is taken against the shared
        // operational accountant, so it raises BOTH the operational partition and
        // the shared aggregate authority by `fill`.
        let fill = agg_cap - backend.accounting_aggregate_current();
        let standing = backend.reserve_standing_for_test(fill).unwrap();
        let pressured_op = backend.accounting_current();
        let pressured_agg = backend.accounting_aggregate_current();
        assert_eq!(pressured_op, baseline_op + fill);
        assert_eq!(pressured_agg, baseline_agg + fill);
        // Admission refuses, and the failed admission leaks NOTHING (complete
        // rollback leaves both ledgers exactly at their pressured values).
        assert!(RetrievalWorkspaceOwner::new(backend).admit().is_err());
        assert_eq!(backend.accounting_current(), pressured_op);
        assert_eq!(backend.accounting_aggregate_current(), pressured_agg);

        // (3) Remove the pressure WITHOUT dropping the proof.
        drop(standing);
        assert_eq!(backend.accounting_current(), baseline_op);
        assert_eq!(backend.accounting_aggregate_current(), baseline_agg);

        // (4) Admit the workspace and execute an ACTUAL retrieval.
        let (mut output, mut scratch) =
            RetrievalWorkspaceOwner::new(backend).admit().unwrap();
        let peak_op = backend.accounting_current();
        let peak_agg = backend.accounting_aggregate_current();
        assert_eq!(peak_op, baseline_op + output_charge() + envelope_charge());
        // Both UNCHANGED caps are respected at the retrieval peak.
        assert!(peak_op <= op_cap, "operational peak {peak_op} <= {op_cap}");
        assert!(peak_agg <= agg_cap, "aggregate peak {peak_agg} <= {agg_cap}");

        let p = pos(19);
        let bdg = bind(15);
        let (_s, journal) = model_journal(&[(
            p,
            encode_record(p, bdg, SigningRecordStage::Signed, 2420),
        )]);
        let r = journal
            .retrieve_retained(&p, &bdg, &mut scratch, &mut output)
            .unwrap();

        // (5) Success means RETRIEVAL: the exact 2,420-byte signature is delivered.
        match r {
            RetainedDelivery::Retained(sig) => {
                assert_eq!(sig.len(), 2420);
                assert!(sig.iter().all(|&x| x == 0xAB));
            }
            other => panic!("expected Retained after pressure relief, got {other:?}"),
        }
        assert_eq!(output.used(), 2420);

        // (6) Drop the scratch while the output remains covered, then drop the
        // output while the proof stays live; assert exact restoration of BOTH
        // ledgers at each boundary.
        drop(scratch);
        assert_eq!(backend.accounting_current(), baseline_op + output_charge());
        assert_eq!(
            backend.accounting_aggregate_current(),
            baseline_agg + output_charge()
        );
        drop(output);
        assert_eq!(backend.accounting_current(), baseline_op);
        assert_eq!(backend.accounting_aggregate_current(), baseline_agg);

        // The required live proof is still held; drop it only now, after the whole
        // pressure/relief/retrieval lifecycle has been observed.
        drop(validated);
    }

    // ---- 9. failed-reissue fault injection → DeliverySuppressed + retry ----

    /// The injected reissue fault mode for [`FaultReissueStore`].
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum ReissueFault {
        /// No fault: delegate the synced reissue to the inner backend.
        None,
        /// Return an error WITHOUT performing the underlying synced write.
        ErrorBeforeWrite,
        /// Perform the underlying synced write, THEN return an error (an uncertain
        /// durability acknowledgement where the bytes did reach the backend).
        WriteThenError,
    }

    /// A test-only [`SigningJournalStorage`] wrapper over a real
    /// [`InMemoryConsensusStorage`] that injects a controllable fault into
    /// [`SigningJournalStorage::reissue_signing_envelope_synced`] and RECORDS how
    /// many reissue calls were made and how many underlying synced writes actually
    /// reached the inner backend. Every other trait method delegates unchanged, so
    /// the retrieval read/validate path and the ownership domain are the real ones.
    /// Because the recovered reissue intentionally rewrites IDENTICAL bytes,
    /// byte-identity cannot prove whether the second (write-then-error) write
    /// occurred — the recorded `underlying_writes` counter is the distinguishing
    /// evidence.
    struct FaultReissueStore {
        inner: Arc<InMemoryConsensusStorage>,
        fault: std::sync::RwLock<ReissueFault>,
        reissue_calls: std::sync::atomic::AtomicUsize,
        underlying_writes: std::sync::atomic::AtomicUsize,
    }

    impl FaultReissueStore {
        fn new(inner: Arc<InMemoryConsensusStorage>) -> Self {
            Self {
                inner,
                fault: std::sync::RwLock::new(ReissueFault::None),
                reissue_calls: std::sync::atomic::AtomicUsize::new(0),
                underlying_writes: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn set_fault(&self, f: ReissueFault) {
            *self.fault.write().unwrap() = f;
        }
        fn reissue_calls(&self) -> usize {
            self.reissue_calls.load(std::sync::atomic::Ordering::SeqCst)
        }
        fn underlying_writes(&self) -> usize {
            self.underlying_writes
                .load(std::sync::atomic::Ordering::SeqCst)
        }
    }

    impl SigningJournalStorage for FaultReissueStore {
        fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get_signing_record(key)
        }
        fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.inner.put_signing_record_synced(key, value)
        }
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get_signing_metadata()
        }
        fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
            self.inner.put_signing_metadata_synced(value)
        }
        fn put_signing_record_and_metadata_synced(
            &self,
            record_key: &[u8],
            record_value: &[u8],
            metadata_value: &[u8],
        ) -> Result<(), StorageError> {
            self.inner.put_signing_record_and_metadata_synced(
                record_key,
                record_value,
                metadata_value,
            )
        }
        fn for_each_signing_namespace_entry(
            &self,
            visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            self.inner.for_each_signing_namespace_entry(visitor)
        }
        fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
            self.inner.signing_ownership_domain()
        }
        fn read_signing_envelope_into(
            &self,
            journal_key: &[u8],
            dst: &mut [u8],
        ) -> Result<Option<usize>, crate::signing_reservation_journal::BoundedStorageError> {
            self.inner.read_signing_envelope_into(journal_key, dst)
        }
        fn reissue_signing_envelope_synced(
            &self,
            journal_key: &[u8],
            envelope: &[u8],
        ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
            use crate::signing_reservation_journal::{BoundedDiag, BoundedStorageError};
            use std::sync::atomic::Ordering::SeqCst;
            self.reissue_calls.fetch_add(1, SeqCst);
            match *self.fault.read().unwrap() {
                ReissueFault::None => {
                    self.inner
                        .reissue_signing_envelope_synced(journal_key, envelope)?;
                    self.underlying_writes.fetch_add(1, SeqCst);
                    Ok(())
                }
                ReissueFault::ErrorBeforeWrite => {
                    // Fail BEFORE touching the inner backend: no underlying write.
                    Err(BoundedStorageError::Io(BoundedDiag::WriteIo))
                }
                ReissueFault::WriteThenError => {
                    // The underlying synced write reaches the inner backend FIRST,
                    // then an uncertain-acknowledgement error is returned.
                    self.inner
                        .reissue_signing_envelope_synced(journal_key, envelope)?;
                    self.underlying_writes.fetch_add(1, SeqCst);
                    Err(BoundedStorageError::Io(BoundedDiag::WriteIo))
                }
            }
        }
    }

    /// Build a recovered-`Signed` scenario over a [`FaultReissueStore`]: a
    /// 2,420-byte `Signed` record is written at `p`/`b` with NO live entry, so
    /// [`SigningReservationJournal::retrieve_retained`] takes the recovered
    /// exact-envelope synced-reissue branch.
    fn fault_scenario(
        p: SigningPosition,
        b: BindingDigest,
    ) -> (Arc<FaultReissueStore>, SigningReservationJournal, Vec<u8>) {
        let inner = Arc::new(InMemoryConsensusStorage::new());
        let record = encode_record(p, b, SigningRecordStage::Signed, 2420);
        inner
            .put_signing_record_synced(&p.storage_key(), &record)
            .unwrap();
        let store = Arc::new(FaultReissueStore::new(inner));
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        (store, journal, record)
    }

    /// Drive one failed-reissue case end-to-end: inject `fault`, attempt a
    /// recovered retrieval (expect `DeliverySuppressed` with zero caller-visible
    /// effect and exact accounting restoration while the workspace AND proof stay
    /// alive), then clear the fault and prove the SAME `retrieve_retained` route
    /// delivers on retry and reissues AGAIN cache-free. `writes_during_fault` is
    /// the number of underlying synced writes that must have reached the inner
    /// backend while the fault was active (0 for error-before-write, 1 for
    /// write-then-error).
    fn drive_failed_reissue_case(fault: ReissueFault, writes_during_fault: usize) {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();

        // A real ValidatedRecord proof held live throughout (NOT a PreparedPin or
        // DecidedVote).
        let validated: ValidatedRecord = owner
            .read_validate(None::<&crate::safety_record_store::FixtureCommittedHistory>)
            .expect("bootstrap record validates");

        let (mut output, mut scratch) =
            RetrievalWorkspaceOwner::new(backend).admit().unwrap();

        let p = pos(20);
        let b = bind(20);
        let (store, journal, record) = fault_scenario(p, b);

        // Distinguishable PRE-EXISTING output state that must survive suppression.
        let sentinel = [0xCDu8; 7];
        output.set(&sentinel).unwrap();
        assert_eq!(output.used(), 7);

        // Pre-attempt ledgers, measured WITH the workspace + proof already alive.
        let op_before = backend.accounting_current();
        let agg_before = backend.accounting_aggregate_current();
        // Context ownership is charged in the aggregate (distinct partition).
        assert!(agg_before >= op_before);
        let stored_before = store.get_signing_record(&p.storage_key()).unwrap().unwrap();

        // ---- failed reissue → DeliverySuppressed -------------------------
        store.set_fault(fault);
        let r = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(
            matches!(r, RetainedDelivery::DeliverySuppressed),
            "expected DeliverySuppressed, got {r:?}"
        );
        // A reissue WAS attempted; the recorded underlying-write count distinguishes
        // the two fault cases (identical reissued bytes cannot).
        assert_eq!(store.reissue_calls(), 1);
        assert_eq!(store.underlying_writes(), writes_during_fault);
        // The complete caller output buffer AND its used length are unchanged.
        assert_eq!(output.used(), 7);
        assert_eq!(output.view(), &sentinel);
        // The retained stored envelope is byte-identical.
        let stored_after = store.get_signing_record(&p.storage_key()).unwrap().unwrap();
        assert_eq!(stored_after, stored_before);
        assert_eq!(stored_after, record);
        // Both ledgers returned to their pre-attempt values; workspace + proof live.
        assert_eq!(backend.accounting_current(), op_before);
        assert_eq!(backend.accounting_aggregate_current(), agg_before);

        // ---- clear the fault and retry through the SAME route -------------
        store.set_fault(ReissueFault::None);
        let r2 = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        match r2 {
            RetainedDelivery::Retained(sig) => {
                assert_eq!(sig.len(), 2420);
                assert!(sig.iter().all(|&x| x == 0xAB));
            }
            other => panic!("expected Retained on retry, got {other:?}"),
        }
        assert_eq!(output.used(), 2420);
        // The retry performed a NEW successful synced reissue BEFORE delivery.
        assert_eq!(store.reissue_calls(), 2);
        assert_eq!(store.underlying_writes(), writes_during_fault + 1);

        // A further recovered retrieval reissues AGAIN (cache-free).
        let r3 = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(r3, RetainedDelivery::Retained(_)));
        assert_eq!(output.used(), 2420);
        assert_eq!(store.reissue_calls(), 3);
        assert_eq!(store.underlying_writes(), writes_during_fault + 2);

        // No fresh signing obligation was created on ANY of these retrievals: the
        // operational charge still equals the pre-attempt workspace baseline (the
        // retrieval route takes no reservation and never invokes a signer).
        assert_eq!(backend.accounting_current(), op_before);
        assert_eq!(backend.accounting_aggregate_current(), agg_before);

        // Drop the workspace; the proof remains live until the very end.
        drop(scratch);
        drop(output);
        drop(validated);
    }

    #[test]
    fn recovered_reissue_error_before_write_suppresses_delivery() {
        drive_failed_reissue_case(ReissueFault::ErrorBeforeWrite, 0);
    }

    #[test]
    fn recovered_reissue_write_then_error_suppresses_delivery() {
        drive_failed_reissue_case(ReissueFault::WriteThenError, 1);
    }

    // ---- 4. RUN 422 scoped writable-output lifecycle ----------------------
    //
    // Buffer-validity assertions below are kept DISTINCT from reservation-counter
    // assertions: these cases never read the accountant, and the admission cases
    // further down never inspect buffer contents.

    /// A freshly admitted output exposes the full capacity but holds no valid
    /// bytes yet.
    #[test]
    fn output_begins_empty() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let out = RetrievalWorkspaceOwner::new(owner.backend_for_test())
            .admit_output()
            .unwrap();
        assert_eq!(out.capacity(), OUTPUT_CAP);
        assert_eq!(out.used(), 0);
        assert!(out.view().is_empty());
    }

    /// Beginning a write clears any previously committed contents; an abandoned
    /// writer leaves the output empty (invalidation is not deferred to commit).
    #[test]
    fn begin_write_invalidates_previous_commit_on_abandon() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let mut out = RetrievalWorkspaceOwner::new(owner.backend_for_test())
            .admit_output()
            .unwrap();
        {
            let mut w = out.begin_write();
            for byte in w.buffer()[..20].iter_mut() {
                *byte = 0xCC;
            }
            assert_eq!(w.commit(20).unwrap(), 20);
        }
        assert_eq!(out.used(), 20);
        // Begin another write and ABANDON it (drop without commit).
        drop(out.begin_write());
        assert_eq!(out.used(), 0);
        assert!(out.view().is_empty());
    }

    /// A successful commit exposes exactly the written prefix, in order.
    #[test]
    fn commit_exposes_exact_prefix() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let mut out = RetrievalWorkspaceOwner::new(owner.backend_for_test())
            .admit_output()
            .unwrap();
        {
            let mut w = out.begin_write();
            let buf = w.buffer();
            assert_eq!(buf.len(), OUTPUT_CAP);
            for (i, byte) in buf[..5].iter_mut().enumerate() {
                *byte = (i as u8) + 1;
            }
            assert_eq!(w.commit(5).unwrap(), 5);
        }
        assert_eq!(out.view(), &[1u8, 2, 3, 4, 5]);
    }

    /// The capacity boundary commits; one past it is refused and leaves the
    /// output empty.
    #[test]
    fn capacity_boundary_accepted_plus_one_refused() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let mut out = RetrievalWorkspaceOwner::new(owner.backend_for_test())
            .admit_output()
            .unwrap();
        {
            let mut w = out.begin_write();
            for byte in w.buffer().iter_mut() {
                *byte = 0x5A;
            }
            assert_eq!(w.commit(OUTPUT_CAP).unwrap(), OUTPUT_CAP);
        }
        assert_eq!(out.used(), OUTPUT_CAP);
        {
            let w = out.begin_write();
            let err = w.commit(OUTPUT_CAP + 1).unwrap_err();
            assert_eq!(
                err,
                WorkspaceCapacity {
                    len: OUTPUT_CAP + 1,
                    capacity: OUTPUT_CAP,
                }
            );
        }
        // The over-length commit left the output logically invalid.
        assert_eq!(out.used(), 0);
        assert!(out.view().is_empty());
    }

    /// A long committed result followed by a short reuse exposes ONLY the new
    /// short prefix — never the stale trailing bytes of the prior write.
    #[test]
    fn long_then_short_reuse_exposes_only_new_prefix() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let mut out = RetrievalWorkspaceOwner::new(owner.backend_for_test())
            .admit_output()
            .unwrap();
        {
            let mut w = out.begin_write();
            for byte in w.buffer()[..100].iter_mut() {
                *byte = 0xAA;
            }
            assert_eq!(w.commit(100).unwrap(), 100);
        }
        assert_eq!(out.used(), 100);
        {
            let mut w = out.begin_write();
            for byte in w.buffer()[..10].iter_mut() {
                *byte = 0xBB;
            }
            assert_eq!(w.commit(10).unwrap(), 10);
        }
        assert_eq!(out.view().len(), 10);
        assert!(out.view().iter().all(|&byte| byte == 0xBB));
    }

    /// A zero-length commit is structurally permitted and yields an empty valid
    /// span.
    #[test]
    fn zero_length_commit_is_structurally_valid_empty() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let mut out = RetrievalWorkspaceOwner::new(owner.backend_for_test())
            .admit_output()
            .unwrap();
        {
            let mut w = out.begin_write();
            for byte in w.buffer()[..7].iter_mut() {
                *byte = 0x11;
            }
            assert_eq!(w.commit(7).unwrap(), 7);
        }
        assert_eq!(out.used(), 7);
        {
            let w = out.begin_write();
            assert_eq!(w.commit(0).unwrap(), 0);
        }
        assert_eq!(out.used(), 0);
        assert!(out.view().is_empty());
    }

    /// Output-only admission charges exactly `output_charge()` (and NO envelope
    /// charge) on BOTH the operational and the shared aggregate ledgers, and
    /// releases both on drop.
    #[test]
    fn admit_output_charges_output_only_on_both_ledgers() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let base_op = backend.accounting_current();
        let base_agg = backend.accounting_aggregate_current();
        {
            let out = RetrievalWorkspaceOwner::new(backend).admit_output().unwrap();
            assert_eq!(out.charge(), output_charge());
            assert_eq!(backend.accounting_current(), base_op + output_charge());
            assert_eq!(
                backend.accounting_aggregate_current(),
                base_agg + output_charge()
            );
            // Strictly the output charge: the envelope scratch is never admitted.
            assert_ne!(output_charge(), output_charge() + envelope_charge());
        }
        assert_eq!(backend.accounting_current(), base_op);
        assert_eq!(backend.accounting_aggregate_current(), base_agg);
    }

    /// A refused output-only admission leaves BOTH ledgers exactly at baseline.
    #[test]
    fn admit_output_refusal_leaves_both_ledgers_unchanged() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let base_op = backend.accounting_current();
        let base_agg = backend.accounting_aggregate_current();
        let cap = backend.accounting_cap().unwrap();
        // Leave strictly less headroom than the output charge, so admission fails.
        let fill = cap - base_op - (output_charge() - 1);
        let standing = backend.reserve_standing_for_test(fill).unwrap();
        let op_after_fill = backend.accounting_current();
        let agg_after_fill = backend.accounting_aggregate_current();
        assert!(RetrievalWorkspaceOwner::new(backend)
            .admit_output()
            .is_err());
        // Neither ledger moved across the refusal.
        assert_eq!(backend.accounting_current(), op_after_fill);
        assert_eq!(backend.accounting_aggregate_current(), agg_after_fill);
        drop(standing);
        assert_eq!(backend.accounting_current(), base_op);
        assert_eq!(backend.accounting_aggregate_current(), base_agg);
    }

    /// Pressure relief: once a standing reservation is released, output-only
    /// admission succeeds; dropping the admitted output restores BOTH baselines.
    #[test]
    fn pressure_relief_permits_admit_output_then_drop_restores_both() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let base_op = backend.accounting_current();
        let base_agg = backend.accounting_aggregate_current();
        let cap = backend.accounting_cap().unwrap();
        let fill = cap - base_op - (output_charge() - 1);
        let standing = backend.reserve_standing_for_test(fill).unwrap();
        assert!(RetrievalWorkspaceOwner::new(backend)
            .admit_output()
            .is_err());
        // Relieve the pressure; admission is now permitted.
        drop(standing);
        {
            let out = RetrievalWorkspaceOwner::new(backend).admit_output().unwrap();
            assert_eq!(backend.accounting_current(), base_op + output_charge());
            assert_eq!(
                backend.accounting_aggregate_current(),
                base_agg + output_charge()
            );
        }
        assert_eq!(backend.accounting_current(), base_op);
        assert_eq!(backend.accounting_aggregate_current(), base_agg);
    }

    // ===================================================================
    // RUN 422 — journal-associated workspace admission + checked retained
    // retrieval. These exercise the NEW opt-in methods only; the legacy
    // `retrieve_retained` and existing admission helpers are unchanged.
    // ===================================================================

    /// A read-counting [`SigningJournalStorage`] wrapper over a real
    /// [`InMemoryConsensusStorage`]. It records how many bounded envelope reads
    /// reached the backend, so a test can establish that a checked-retrieval
    /// refusal happened BEFORE any delegated storage access. Every method
    /// delegates unchanged and the ownership domain is the real one.
    struct ReadCountingStore {
        inner: Arc<InMemoryConsensusStorage>,
        reads: std::sync::atomic::AtomicUsize,
    }
    impl ReadCountingStore {
        fn new(inner: Arc<InMemoryConsensusStorage>) -> Self {
            Self {
                inner,
                reads: std::sync::atomic::AtomicUsize::new(0),
            }
        }
        fn reads(&self) -> usize {
            self.reads.load(std::sync::atomic::Ordering::SeqCst)
        }
    }
    impl SigningJournalStorage for ReadCountingStore {
        fn get_signing_record(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get_signing_record(key)
        }
        fn put_signing_record_synced(&self, key: &[u8], value: &[u8]) -> Result<(), StorageError> {
            self.inner.put_signing_record_synced(key, value)
        }
        fn get_signing_metadata(&self) -> Result<Option<Vec<u8>>, StorageError> {
            self.inner.get_signing_metadata()
        }
        fn put_signing_metadata_synced(&self, value: &[u8]) -> Result<(), StorageError> {
            self.inner.put_signing_metadata_synced(value)
        }
        fn put_signing_record_and_metadata_synced(
            &self,
            record_key: &[u8],
            record_value: &[u8],
            metadata_value: &[u8],
        ) -> Result<(), StorageError> {
            self.inner
                .put_signing_record_and_metadata_synced(record_key, record_value, metadata_value)
        }
        fn for_each_signing_namespace_entry(
            &self,
            visitor: &mut dyn FnMut(&[u8], &[u8]) -> Result<(), StorageError>,
        ) -> Result<(), StorageError> {
            self.inner.for_each_signing_namespace_entry(visitor)
        }
        fn signing_ownership_domain(&self) -> Arc<SigningOwnershipDomain> {
            self.inner.signing_ownership_domain()
        }
        fn read_signing_envelope_into(
            &self,
            journal_key: &[u8],
            dst: &mut [u8],
        ) -> Result<Option<usize>, crate::signing_reservation_journal::BoundedStorageError> {
            self.reads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.inner.read_signing_envelope_into(journal_key, dst)
        }
        fn reissue_signing_envelope_synced(
            &self,
            journal_key: &[u8],
            envelope: &[u8],
        ) -> Result<(), crate::signing_reservation_journal::BoundedStorageError> {
            self.inner.reissue_signing_envelope_synced(journal_key, envelope)
        }
    }

    /// A model journal over a [`ReadCountingStore`] holding ONE recovered
    /// `Signed` record (no live entry) at `p`/`b`.
    fn counting_journal(
        p: SigningPosition,
        b: BindingDigest,
    ) -> (Arc<ReadCountingStore>, SigningReservationJournal) {
        let inner = Arc::new(InMemoryConsensusStorage::new());
        let record = encode_record(p, b, SigningRecordStage::Signed, 2420);
        inner
            .put_signing_record_synced(&p.storage_key(), &record)
            .unwrap();
        let store = Arc::new(ReadCountingStore::new(inner));
        let journal = SigningReservationJournal::attach_unestablished_for_test(
            store.clone() as Arc<dyn SigningJournalStorage>,
        );
        (store, journal)
    }

    // ---- 1. missing association refuses BOTH admission and checked retrieval

    #[test]
    fn checked_missing_association_refuses_admission_and_retrieval() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(30);
        let b = bind(30);
        let (store, journal) = counting_journal(p, b);
        // No association installed: admission refuses with a fixed-size code and
        // reserves nothing.
        let base = backend.accounting_current();
        assert_eq!(
            journal.admit_retrieval_workspace().unwrap_err(),
            WorkspaceAdmissionError::NoAssociation
        );
        assert_eq!(backend.accounting_current(), base);
        // A separately-admitted (matching-backend) workspace still cannot be used
        // through the checked route without an installed association, and no read
        // occurs.
        let (mut output, mut scratch) = RetrievalWorkspaceOwner::new(backend).admit().unwrap();
        output.set(&[0x11u8; 2420]).unwrap();
        let before = output.view().to_vec();
        assert_eq!(
            journal
                .retrieve_retained_checked(&p, &b, &mut scratch, &mut output)
                .unwrap_err(),
            CheckedRetrievalError::NoAssociation
        );
        assert_eq!(store.reads(), 0, "no delegated read on NoAssociation");
        assert_eq!(output.view(), &before[..], "output bytes preserved");
        assert_eq!(output.used(), 2420, "output length preserved");
    }

    // ---- 2. matching association admits and retrieves a REAL signature

    #[test]
    fn checked_matching_association_admits_and_retrieves() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(31);
        let b = bind(31);
        let (store, journal) = counting_journal(p, b);
        journal.install_accountant_association(backend.accounting()).unwrap();
        // Admission is sourced from the INSTALLED association (not a caller handle).
        let (mut output, mut scratch) = journal.admit_retrieval_workspace().unwrap();
        assert_eq!(output.charge(), output_charge());
        assert_eq!(scratch.charge(), envelope_charge());
        let d = journal
            .retrieve_retained_checked(&p, &b, &mut scratch, &mut output)
            .unwrap();
        match d {
            RetainedDelivery::Retained(sig) => {
                assert_eq!(sig.len(), 2420);
                assert!(sig.iter().all(|&x| x == 0xAB));
            }
            other => panic!("expected Retained, got {other:?}"),
        }
        assert_eq!(output.used(), 2420);
        assert!(store.reads() >= 1, "a delegated read occurred");
    }

    // ---- 3/4/5. foreign output, foreign scratch, and both foreign refuse
    //            BEFORE any delegated read, with the output preserved.

    #[test]
    fn checked_foreign_coverage_refuses_before_any_read() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        // A SEPARATE backend = a foreign operational ledger.
        let (_d2, owner2) = bound_owner(ctx(4, 2420));
        let backend2 = owner2.backend_for_test();

        let p = pos(32);
        let b = bind(32);
        let (store, journal) = counting_journal(p, b);
        journal.install_accountant_association(backend.accounting()).unwrap();

        // Matching pair (installed ledger) and a foreign pair (backend2).
        let (mut out_ok, mut scr_ok) = journal.admit_retrieval_workspace().unwrap();
        let (mut out_foreign, mut scr_foreign) =
            RetrievalWorkspaceOwner::new(backend2).admit().unwrap();
        // Pre-fill the matching output to prove preservation on refusal.
        out_ok.set(&[0x22u8; 2420]).unwrap();
        let ok_bytes = out_ok.view().to_vec();

        // (3) foreign OUTPUT + matching scratch.
        assert_eq!(
            journal
                .retrieve_retained_checked(&p, &b, &mut scr_ok, &mut out_foreign)
                .unwrap_err(),
            CheckedRetrievalError::ForeignWorkspace
        );
        // (4) matching OUTPUT + foreign scratch.
        assert_eq!(
            journal
                .retrieve_retained_checked(&p, &b, &mut scr_foreign, &mut out_ok)
                .unwrap_err(),
            CheckedRetrievalError::ForeignWorkspace
        );
        // (5) both foreign.
        assert_eq!(
            journal
                .retrieve_retained_checked(&p, &b, &mut scr_foreign, &mut out_foreign)
                .unwrap_err(),
            CheckedRetrievalError::ForeignWorkspace
        );
        assert_eq!(store.reads(), 0, "no delegated read on any foreign refusal");
        assert_eq!(out_ok.view(), &ok_bytes[..], "matching output bytes preserved");
        assert_eq!(out_ok.used(), 2420, "matching output length preserved");
    }

    // ---- 6. same-ledger clone accepted; two domains sharing one ledger accept
    //         the same workspace coverage (accounting identity, not domain id).

    #[test]
    fn checked_same_ledger_clone_and_shared_domains_accepted() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(33);
        let b = bind(33);

        // Journal A installs a CLONE of the operational accountant.
        let (_sa, journal_a) = counting_journal(p, b);
        journal_a
            .install_accountant_association(&backend.accounting().clone())
            .unwrap();
        // Journal B is a DISTINCT ownership domain sharing the SAME ledger.
        let (_sb, journal_b) = counting_journal(p, b);
        journal_b.install_accountant_association(backend.accounting()).unwrap();

        // One workspace admitted against that shared ledger.
        let (mut output, mut scratch) = journal_a.admit_retrieval_workspace().unwrap();
        // Accepted by A (clone install).
        assert!(matches!(
            journal_a.retrieve_retained_checked(&p, &b, &mut scratch, &mut output),
            Ok(RetainedDelivery::Retained(_))
        ));
        // And accepted by B (separate domain, same accounting identity).
        assert!(matches!(
            journal_b.retrieve_retained_checked(&p, &b, &mut scratch, &mut output),
            Ok(RetainedDelivery::Retained(_))
        ));
    }

    // ---- 7. real reservation pressure forces paired-admission rollback;
    //         observe BOTH ledgers directly.

    #[test]
    fn admit_paired_rollback_under_real_pressure() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(34);
        let b = bind(34);
        let (_s, journal) = counting_journal(p, b);
        journal.install_accountant_association(backend.accounting()).unwrap();

        let base_op = backend.accounting_current();
        let base_agg = backend.accounting_aggregate_current();
        let agg_cap = backend.accounting_aggregate_cap().unwrap();
        // Leave headroom for the OUTPUT charge but not the full envelope charge, so
        // the first reservation succeeds and the second refuses.
        let headroom = output_charge() + envelope_charge() / 2;
        let fill = agg_cap - base_agg - headroom;
        let standing = backend.reserve_standing_for_test(fill).unwrap();
        let pressured_op = backend.accounting_current();
        let pressured_agg = backend.accounting_aggregate_current();
        // Admission sourced from the installed association refuses; complete
        // rollback leaves BOTH ledgers exactly at the pressured values.
        assert!(journal.admit_retrieval_workspace().is_err());
        assert_eq!(backend.accounting_current(), pressured_op);
        assert_eq!(backend.accounting_aggregate_current(), pressured_agg);
        drop(standing);
        assert_eq!(backend.accounting_current(), base_op);
        assert_eq!(backend.accounting_aggregate_current(), base_agg);
    }

    // ---- 8. pressure relief, then an ACTUAL successful checked retrieval.

    #[test]
    fn pressure_relief_then_checked_retrieval() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(35);
        let b = bind(35);
        let (_s, journal) = counting_journal(p, b);
        journal.install_accountant_association(backend.accounting()).unwrap();

        let base_agg = backend.accounting_aggregate_current();
        let agg_cap = backend.accounting_aggregate_cap().unwrap();
        let fill = agg_cap - base_agg;
        let standing = backend.reserve_standing_for_test(fill).unwrap();
        assert!(journal.admit_retrieval_workspace().is_err());
        drop(standing);
        let (mut output, mut scratch) = journal.admit_retrieval_workspace().unwrap();
        let d = journal
            .retrieve_retained_checked(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(d, RetainedDelivery::Retained(_)));
        assert_eq!(output.used(), 2420);
    }

    // ---- 9. a checked refusal preserves the complete output buffer and length.

    #[test]
    fn checked_refusal_preserves_full_output_bytes_and_used() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(36);
        let b = bind(36);
        let (store, journal) = counting_journal(p, b);
        journal.install_accountant_association(backend.accounting()).unwrap();

        let (mut output, _scratch_ok) = journal.admit_retrieval_workspace().unwrap();
        // A foreign scratch to force refusal while the matching output is full.
        let (_d2, owner2) = bound_owner(ctx(4, 2420));
        let (_out_foreign, mut scr_foreign) =
            RetrievalWorkspaceOwner::new(owner2.backend_for_test()).admit().unwrap();

        output.set(&[0x7Eu8; 2420]).unwrap();
        let before = output.view().to_vec();
        assert_eq!(
            journal
                .retrieve_retained_checked(&p, &b, &mut scr_foreign, &mut output)
                .unwrap_err(),
            CheckedRetrievalError::ForeignWorkspace
        );
        assert_eq!(store.reads(), 0);
        assert_eq!(output.view(), &before[..]);
        assert_eq!(output.used(), 2420);
    }

    // ---- 10. staged scratch-then-output cleanup restores BOTH ledgers exactly.

    #[test]
    fn staged_cleanup_restores_both_ledgers() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(37);
        let b = bind(37);
        let (_s, journal) = counting_journal(p, b);
        journal.install_accountant_association(backend.accounting()).unwrap();

        let base_op = backend.accounting_current();
        let base_agg = backend.accounting_aggregate_current();
        let (output, scratch) = journal.admit_retrieval_workspace().unwrap();
        assert_eq!(
            backend.accounting_current(),
            base_op + output_charge() + envelope_charge()
        );
        assert_eq!(
            backend.accounting_aggregate_current(),
            base_agg + output_charge() + envelope_charge()
        );
        // Release the scratch while the output coverage remains live.
        drop(scratch);
        assert_eq!(backend.accounting_current(), base_op + output_charge());
        assert_eq!(
            backend.accounting_aggregate_current(),
            base_agg + output_charge()
        );
        drop(output);
        assert_eq!(backend.accounting_current(), base_op);
        assert_eq!(backend.accounting_aggregate_current(), base_agg);
    }

    // ---- 11. uncertainty blocking, failed-reissue suppression, and repeated
    //          cache-free reissue, all through the CHECKED route.

    #[test]
    fn checked_route_preserves_uncertainty_suppression_and_cachefree() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(38);
        let b = bind(38);

        // (a) Uncertainty latch blocks after the identity check, before any read.
        let (store, journal) = counting_journal(p, b);
        journal.install_accountant_association(backend.accounting()).unwrap();
        let (mut output, mut scratch) = journal.admit_retrieval_workspace().unwrap();
        journal.set_accounting_uncertain_for_test(true);
        assert!(matches!(
            journal.retrieve_retained_checked(&p, &b, &mut scratch, &mut output),
            Ok(RetainedDelivery::Blocked)
        ));
        assert_eq!(store.reads(), 0, "uncertainty blocks before any read");
        journal.set_accounting_uncertain_for_test(false);

        // (b) Failed reissue suppresses delivery; a cleared fault then delivers,
        //     reissuing AGAIN cache-free (reissue_calls increments each delivery).
        let inner = Arc::new(InMemoryConsensusStorage::new());
        let record = encode_record(p, b, SigningRecordStage::Signed, 2420);
        inner
            .put_signing_record_synced(&p.storage_key(), &record)
            .unwrap();
        let fstore = Arc::new(FaultReissueStore::new(inner));
        let fjournal = SigningReservationJournal::attach_unestablished_for_test(
            fstore.clone() as Arc<dyn SigningJournalStorage>,
        );
        fjournal.install_accountant_association(backend.accounting()).unwrap();
        let (mut out2, mut scr2) = fjournal.admit_retrieval_workspace().unwrap();
        out2.set(&[0x5Au8; 2420]).unwrap();
        let preserved = out2.view().to_vec();

        fstore.set_fault(ReissueFault::ErrorBeforeWrite);
        assert!(matches!(
            fjournal.retrieve_retained_checked(&p, &b, &mut scr2, &mut out2),
            Ok(RetainedDelivery::DeliverySuppressed)
        ));
        assert_eq!(fstore.reissue_calls(), 1);
        assert_eq!(fstore.underlying_writes(), 0);
        assert_eq!(out2.view(), &preserved[..], "output unchanged on suppression");

        fstore.set_fault(ReissueFault::None);
        assert!(matches!(
            fjournal.retrieve_retained_checked(&p, &b, &mut scr2, &mut out2),
            Ok(RetainedDelivery::Retained(_))
        ));
        // A SECOND reissue occurred cache-free on the successful delivery.
        assert_eq!(fstore.reissue_calls(), 2);
        assert_eq!(fstore.underlying_writes(), 1);
        assert_eq!(out2.used(), 2420);
    }

    // ---- 12. legacy behavior unchanged without an installed association.

    #[test]
    fn legacy_retrieve_retained_unchanged_without_association() {
        let (_d, owner) = bound_owner(ctx(4, 2420));
        let backend = owner.backend_for_test();
        let p = pos(39);
        let b = bind(39);
        // Existing constructor admits a workspace (no association involved).
        let (mut output, mut scratch) = RetrievalWorkspaceOwner::new(backend).admit().unwrap();
        let (_s, journal) = counting_journal(p, b);
        // The UNCHANGED legacy route still delivers with no association installed.
        let d = journal
            .retrieve_retained(&p, &b, &mut scratch, &mut output)
            .unwrap();
        assert!(matches!(d, RetainedDelivery::Retained(_)));
        assert_eq!(output.used(), 2420);
    }
}