//! RUN 422 D7-D10 — Real-storage recovery evidence for the local
//! signing-reservation journal.
//!
//! These are the D10 storage/recovery integration cases required by
//! `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`.
//! They exercise the journal over a *real* `RocksDbConsensusStorage` backend
//! (durable `set_sync(true)` writes) using genuine close/reopen controls, plus
//! a child-process death/reopen case using test-only self re-exec
//! orchestration. The child runner is NOT a bounded or classified-termination
//! runner (it waits with an unbounded `.status()` and only checks "not
//! success"); it therefore does not close Correction F.
//!
//! Scope / honesty notes:
//! * A "restart" or "reopen" is modelled by dropping the `RocksDbConsensusStorage`
//!   handle and its journal, then `open`ing the same on-disk directory again and
//!   attaching a *fresh* journal. The in-memory live-permit map is lost exactly
//!   as it would be after process death; only the durable records survive.
//! * The child-process case terminates a live child with `std::process::abort()`
//!   AFTER a durable reservation is acknowledged but BEFORE any signed result is
//!   recorded. Process termination is deliberately NOT presented as power-loss
//!   evidence — it demonstrates crash-consistency of the local journal only.
//! * The retained "signature" bytes used here are opaque fixtures: this target
//!   validates storage/recovery of records, not cryptographic verification,
//!   which is covered by the colocated `binary_consensus_loop` D10 tests using
//!   real signers/verifiers.

use std::sync::Arc;

use qbind_node::signing_reservation_journal::{
    BindingDigest, JournalError, ReservationOutcome, ResultPublicationCapability,
    SigningJournalStorage, SigningKind, SigningPosition, SigningReservationJournal,
    DEFAULT_MAX_RESERVED_POSITIONS, MAX_RECORD_LEN, METADATA_ENCODED_LEN,
};
// Run 422 D7-D10 Correction F: the version-fabrication helper is a test-only
// seam gated behind `test-utils`. Import it (and the record-format constant it
// pairs with) ONLY under that feature so the default-feature integration target
// compiles; the single feature-specific case that uses it is gated to match.
#[cfg(feature = "test-utils")]
use qbind_node::signing_reservation_journal::{
    fabricate_reserved_record_bytes_with_version, SIGNING_RECORD_FORMAT_VERSION,
};
use qbind_node::storage::RocksDbConsensusStorage;

/// Environment variable that switches a single re-executed test binary into the
/// "child" mode used by [`reserved_only_child_death_then_reopen_refuses`].
const CHILD_DB_ENV: &str = "QBIND_D7D10_CHILD_DB";

/// Run 422 D7-D10 Correction F-B — the distinctive readiness marker the child
/// emits (and flushes) to stderr ONLY after the real RocksDB reservation has
/// returned its successful durability acknowledgement (`FreshlyReserved`) and
/// IMMEDIATELY before the intentional `abort()` (which precedes any signer
/// invocation or result publication). The bounded parent requires this marker,
/// captured completely, before it will accept a crash as reservation-before-abort
/// evidence; a SIGABRT without this marker is NOT accepted.
const CHILD_RESERVED_MARKER: &str = "D7D10-CHILD: reserved-durable-ack-before-abort";

fn genesis() -> [u8; 32] {
    [7u8; 32]
}

fn proposal_position(view: u64) -> SigningPosition {
    SigningPosition {
        validator_id: 3,
        network_genesis: genesis(),
        kind: SigningKind::Proposal,
        originating_view: view,
    }
}

fn vote_position(view: u64) -> SigningPosition {
    SigningPosition {
        validator_id: 3,
        network_genesis: genesis(),
        kind: SigningKind::Vote,
        originating_view: view,
    }
}

fn binding(tag: u8) -> BindingDigest {
    BindingDigest([tag; 32])
}

/// Open a real RocksDB-backed consensus storage at `path` and wrap it as a
/// shared signing-journal backend.
fn open_store(path: &std::path::Path) -> Arc<RocksDbConsensusStorage> {
    Arc::new(RocksDbConsensusStorage::open(path).expect("open rocksdb consensus storage"))
}

/// Test-fixture setup helper (NOT a mirror of production selection): a fresh
/// (empty) signing namespace is explicitly initialized at the default supported
/// limit and durably publishes bounded initialization metadata; an established
/// namespace is opened and validated (never falling back to initialization).
/// Both routes validate. Production journal initialization remains unwired; this
/// selector exists only to set up these tests.
fn journal(store: Arc<dyn SigningJournalStorage>) -> SigningReservationJournal {
    if store
        .get_signing_metadata()
        .expect("metadata probe must not fail in fixture setup")
        .is_some()
    {
        SigningReservationJournal::open(store).expect("open established journal")
    } else {
        SigningReservationJournal::initialize(store, DEFAULT_MAX_RESERVED_POSITIONS)
            .expect("initialize fresh journal")
    }
}

/// Reserve a fresh decision and consume its one-use continuation, returning the
/// operation-bound publication capability (models the reserve→invoke boundary).
fn reserve_and_invoke(
    journal: &SigningReservationJournal,
    pos: &SigningPosition,
    bind: &BindingDigest,
) -> ResultPublicationCapability {
    match journal.reserve_for_sign(pos, bind).expect("reserve must succeed") {
        ReservationOutcome::FreshlyReserved(cont) => {
            journal.consume_for_signing(cont).expect("consume continuation")
        }
        other => panic!("expected FreshlyReserved, got {:?}", other),
    }
}

/// Reserved-only recovery: after a durable reservation with no retained result,
/// reopening the store and attaching a fresh journal must treat the position as
/// potentially-signed and refuse re-signing, without altering the record.
#[test]
fn reserved_only_survives_reopen_and_refuses_resigning() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(5);
    let bind = binding(0xA1);

    {
        let store = open_store(dir.path());
        let journal = journal(store.clone() as Arc<dyn SigningJournalStorage>);
        // Fresh reservation acknowledged durably; the live operation dies before
        // recording any signed result (we drop the one-use continuation here).
        match journal
            .reserve_for_sign(&pos, &bind)
            .expect("reserve must succeed")
        {
            ReservationOutcome::FreshlyReserved(_cont) => { /* dropped: crash before sign */ }
            other => panic!("expected FreshlyReserved, got {:?}", other),
        }
    }

    // Reopen: fresh journal (fresh ownership domain), empty live table — exactly
    // the crash posture.
    let store = open_store(dir.path());
    let journal = journal(store as Arc<dyn SigningJournalStorage>);
    assert!(
        matches!(
            journal
                .reserve_for_sign(&pos, &bind)
                .expect("reservation lookup must not error"),
            ReservationOutcome::PotentiallySigned
        ),
        "a recovered Reserved record with no live continuation must be potentially-signed"
    );

    // A conflicting request at the same position must remain refused, and must
    // not alter the original obligation.
    assert!(matches!(
        journal
            .reserve_for_sign(&pos, &binding(0xB2))
            .expect("conflict lookup must not error"),
        ReservationOutcome::Conflict
    ));

    // The original obligation is still potentially-signed after the conflict.
    assert!(matches!(
        journal
            .reserve_for_sign(&pos, &bind)
            .expect("re-lookup must not error"),
        ReservationOutcome::PotentiallySigned
    ));
}

/// A signed result survives a reopen and supports an exact resend (retained
/// signature reuse), while conflicting content stays refused.
///
/// Run 422 D7-D10 Correction B: after reopen the retained resend is offered only
/// once the recovered `Signed` record has had its signing-record durability
/// barrier established (the identical record is reissued through the synced-write
/// operation). Over this real RocksDB backend the synced write succeeds, so the
/// exact-retry retained signature is served; the acknowledgement is thereafter
/// cached bound to the exact record.
#[test]
fn signed_result_survives_reopen_and_supports_exact_resend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = vote_position(9);
    let bind = binding(0x33);
    let signature = vec![0xEE, 0xAB, 0xCD, 0x01, 0x02, 0x03];

    {
        let store = open_store(dir.path());
        let journal = journal(store.clone() as Arc<dyn SigningJournalStorage>);
        // Reserve → consume the one-use continuation → publish through the
        // matching operation's capability.
        let cap = reserve_and_invoke(&journal, &pos, &bind);
        journal
            .record_signed_result(&cap, &signature)
            .expect("record signed result durably");
    }

    // Reopen: the signed record must survive and yield an exact-retry retained
    // signature (resend without signing again).
    let store = open_store(dir.path());
    let journal = journal(store as Arc<dyn SigningJournalStorage>);
    match journal.reserve_for_sign(&pos, &bind).expect("lookup") {
        ReservationOutcome::ExactRetryRetained(sig) => assert_eq!(sig, signature),
        other => panic!("expected ExactRetryRetained, got {:?}", other),
    }

    // Conflicting content at the same position stays refused after reopen.
    assert!(matches!(
        journal
            .reserve_for_sign(&pos, &binding(0x44))
            .expect("conflict lookup"),
        ReservationOutcome::Conflict
    ));

    // The recovery acknowledgement is cached bound to the exact record: a
    // second exact retry over the SAME reopened journal remains a retained
    // resend of the identical signature (no additional durability op is needed).
    match journal.reserve_for_sign(&pos, &bind).expect("second retry lookup") {
        ReservationOutcome::ExactRetryRetained(sig) => assert_eq!(sig, signature),
        other => panic!("expected ExactRetryRetained, got {:?}", other),
    }
}

/// Run 422 D7-D10 Correction A over the real RocksDB backend: an empty signed
/// result is refused at the checked publication boundary; the durable bytes are
/// unchanged (still a valid RESERVED record that decodes); the oversized refusal
/// is preserved; and a valid nonempty result still publishes and is retained for
/// an exact retry.
#[test]
fn empty_result_publication_refused_over_real_storage() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(17);
    let bind = binding(0x2E);

    let store = open_store(dir.path());
    let journal =
        journal(store.clone() as Arc<dyn SigningJournalStorage>);
    let cap = reserve_and_invoke(&journal, &pos, &bind);

    // Snapshot the durable RESERVED bytes before the invalid publication attempt.
    let key = pos.storage_key();
    let before = store
        .get_signing_record(&key)
        .expect("read")
        .expect("reserved present");

    // Publishing an EMPTY result is refused with a typed error before any write.
    assert!(matches!(
        journal.record_signed_result(&cap, b""),
        Err(JournalError::InvalidResultPublication(_))
    ));

    // The durable bytes are byte-identical and unchanged.
    let after = store
        .get_signing_record(&key)
        .expect("read")
        .expect("still present");
    assert_eq!(before, after, "empty publication must not alter stored bytes");

    // The oversized refusal is unaffected (control); MAX_RETAINED_SIGNATURE_LEN
    // is 8 KiB, so 8 KiB + 1 is over-bound.
    let oversized = vec![0x5Au8; 8 * 1024 + 1];
    assert!(matches!(
        journal.record_signed_result(&cap, &oversized),
        Err(JournalError::OversizeRecord { .. })
    ));

    // A valid nonempty result publishes durably and is retained for exact retry.
    let signature = vec![0x91, 0x92, 0x93, 0x94];
    journal
        .record_signed_result(&cap, &signature)
        .expect("valid nonempty publish");
    match journal.reserve_for_sign(&pos, &bind).expect("retry lookup") {
        ReservationOutcome::ExactRetryRetained(sig) => assert_eq!(sig, signature),
        other => panic!("expected ExactRetryRetained, got {:?}", other),
    }
}

/// A Proposal and a self-Vote at the same view are distinct decisions and each
/// gets its own durable record that survives reopen independently.
#[test]
fn proposal_and_vote_same_view_are_independent_records_across_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let prop = proposal_position(12);
    let vote = vote_position(12);

    {
        let store = open_store(dir.path());
        let journal = journal(store.clone() as Arc<dyn SigningJournalStorage>);
        assert!(matches!(
            journal.reserve_for_sign(&prop, &binding(1)).expect("reserve proposal"),
            ReservationOutcome::FreshlyReserved(_)
        ));
        assert!(matches!(
            journal.reserve_for_sign(&vote, &binding(2)).expect("reserve vote"),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    let store = open_store(dir.path());
    let journal = journal(store as Arc<dyn SigningJournalStorage>);
    // Both recovered independently as potentially-signed (distinct keys).
    assert!(matches!(
        journal.reserve_for_sign(&prop, &binding(1)).expect("lookup proposal"),
        ReservationOutcome::PotentiallySigned
    ));
    assert!(matches!(
        journal.reserve_for_sign(&vote, &binding(2)).expect("lookup vote"),
        ReservationOutcome::PotentiallySigned
    ));
}

/// Corruption of a stored record on reopen must fail closed (no permit).
#[test]
fn corrupt_record_on_reopen_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(3);
    let bind = binding(0x5A);

    {
        let store = open_store(dir.path());
        let journal = journal(store.clone() as Arc<dyn SigningJournalStorage>);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    // Read back the exact record bytes through the public backend, corrupt a
    // body byte, and re-store under a valid checksum envelope. The inner record
    // CRC now mismatches → decode fails closed.
    let store = open_store(dir.path());
    let key = pos.storage_key();
    let mut bytes = store
        .get_signing_record(&key)
        .expect("read record")
        .expect("record present");
    bytes[20] ^= 0xFF;
    store
        .put_signing_record_synced(&key, &bytes)
        .expect("rewrite corrupted record");

    // Eager open-time streaming validation surfaces the corruption: opening the
    // established journal fails closed (no handle, no permit) rather than
    // deferring to the first reservation lookup.
    let err = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect_err("corrupt record must fail closed at open");
    assert!(matches!(err, JournalError::Corruption(_)), "got {:?}", err);
}

/// Truncation of a stored record on reopen must fail closed.
#[test]
fn truncated_record_on_reopen_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = vote_position(4);
    let bind = binding(0x5B);

    {
        let store = open_store(dir.path());
        let journal = journal(store.clone() as Arc<dyn SigningJournalStorage>);
        assert!(matches!(
            journal.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    let store = open_store(dir.path());
    let key = pos.storage_key();
    let bytes = store
        .get_signing_record(&key)
        .expect("read record")
        .expect("record present");
    // Truncate below the fixed header length.
    let truncated = bytes[..10].to_vec();
    store
        .put_signing_record_synced(&key, &truncated)
        .expect("rewrite truncated record");

    let err = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect_err("truncated record must fail closed at open");
    assert!(matches!(err, JournalError::Truncated), "got {:?}", err);
}

/// An otherwise well-formed record declaring an unsupported record-format
/// version must fail closed on reopen.
#[cfg(feature = "test-utils")]
#[test]
fn unknown_version_record_on_reopen_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(6);
    let bind = binding(0x5C);

    let store = open_store(dir.path());
    // Establish the journal first (durable initialization metadata) so this is
    // an OPEN of an established journal — the unsupported-version record is then
    // surfaced by streaming validation, not masked by a legacy-records refusal.
    SigningReservationJournal::initialize(
        store.clone() as Arc<dyn SigningJournalStorage>,
        DEFAULT_MAX_RESERVED_POSITIONS,
    )
    .expect("initialize fresh journal");
    let key = pos.storage_key();
    // Inject a correctly-checksummed record with a bumped format version.
    let injected =
        fabricate_reserved_record_bytes_with_version(&pos, &bind, SIGNING_RECORD_FORMAT_VERSION + 7);
    store
        .put_signing_record_synced(&key, &injected)
        .expect("store unsupported-version record");

    // Drop the in-process established domain by reopening the backend directory,
    // forcing a full streaming revalidation of the on-disk namespace.
    drop(store);
    let store = open_store(dir.path());
    let err = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect_err("unsupported version must fail closed at open");
    assert!(
        matches!(err, JournalError::UnsupportedRecordVersion(v) if v == SIGNING_RECORD_FORMAT_VERSION + 7),
        "got {:?}",
        err
    );
}

/// A signed record whose retained signature is missing (structurally
/// inconsistent) must fail closed rather than resend an empty signature.
#[test]
fn missing_expected_signature_on_reopen_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = vote_position(8);
    let bind = binding(0x5D);
    let signature = vec![0x11, 0x22, 0x33, 0x44];

    {
        let store = open_store(dir.path());
        let journal = journal(store.clone() as Arc<dyn SigningJournalStorage>);
        let cap = reserve_and_invoke(&journal, &pos, &bind);
        journal
            .record_signed_result(&cap, &signature)
            .expect("record signed");
    }

    // Corrupt the signed record by flipping a signature body byte under a valid
    // outer envelope — the inner CRC now mismatches → fail closed.
    let store = open_store(dir.path());
    let key = pos.storage_key();
    let mut bytes = store
        .get_signing_record(&key)
        .expect("read")
        .expect("present");
    let last = bytes.len() - 6; // inside the retained signature region
    bytes[last] ^= 0xFF;
    store
        .put_signing_record_synced(&key, &bytes)
        .expect("rewrite");

    let err = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect_err("corrupt signed record must fail closed at open");
    assert!(matches!(err, JournalError::Corruption(_)), "got {:?}", err);
}

// ---------------------------------------------------------------------------
// Direct-read size bounds (Run 422 D7-D10 Correction E, Section 3).
//
// These exercise the REAL RocksDB direct-read APIs `get_signing_record` and
// `get_signing_metadata` — distinct from the open-time namespace iterator. Each
// bound is applied to the backend-owned stored bytes BEFORE the payload is
// copied out / the checksum envelope is unwrapped. The underlying RocksDB `get`
// still allocates its own value; the bound limits only subsequent
// application-owned copying/decoding (NOT a complete storage DoS audit).
// ---------------------------------------------------------------------------

/// Valid control + genuine absence: a well-formed record round-trips through the
/// direct record read, and a never-written position reads back as `None` (not an
/// error).
#[test]
fn direct_read_record_valid_control_and_absence() {
    let dir = tempfile::tempdir().expect("tempdir");
    let present = proposal_position(31);
    let absent = proposal_position(32);
    let bind = binding(0x3A);

    let store = open_store(dir.path());
    let journal = journal(store.clone() as Arc<dyn SigningJournalStorage>);
    assert!(matches!(
        journal.reserve_for_sign(&present, &bind).expect("reserve"),
        ReservationOutcome::FreshlyReserved(_)
    ));

    // Present: direct read returns Some(bytes) under the bound.
    let got = store
        .get_signing_record(&present.storage_key())
        .expect("record read must not error");
    assert!(got.is_some(), "a written record must read back as Some");
    // Genuine absence stays None (never an error).
    let missing = store
        .get_signing_record(&absent.storage_key())
        .expect("absent record read must not error");
    assert!(missing.is_none(), "an unwritten position must read as None");
}

/// Valid control + genuine absence for the metadata direct read.
#[test]
fn direct_read_metadata_valid_control_and_absence() {
    // Absence first: a fresh backend with no initialization has no metadata.
    let empty_dir = tempfile::tempdir().expect("tempdir");
    let empty = open_store(empty_dir.path());
    assert!(
        empty
            .get_signing_metadata()
            .expect("metadata read must not error")
            .is_none(),
        "uninitialized backend must report metadata absence as None"
    );

    // Present: after initialization the fixed-length metadata reads back Some.
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(dir.path());
    SigningReservationJournal::initialize(
        store.clone() as Arc<dyn SigningJournalStorage>,
        DEFAULT_MAX_RESERVED_POSITIONS,
    )
    .expect("initialize fresh journal");
    assert!(
        store
            .get_signing_metadata()
            .expect("metadata read must not error")
            .is_some(),
        "initialized backend must read metadata back as Some"
    );
}

/// An oversized stored record value (one byte beyond the bounded decision-record
/// size, under a valid checksum envelope) is refused by the direct record read
/// BEFORE the payload is unwrapped — it does not silently return bytes.
#[test]
fn direct_read_oversized_record_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(33);
    let store = open_store(dir.path());
    // Write an over-long payload through the public synced writer; the stored
    // enveloped value is `4 + (MAX_RECORD_LEN + 1)`, exceeding `4 + MAX_RECORD_LEN`.
    let over = vec![0u8; MAX_RECORD_LEN + 1];
    store
        .put_signing_record_synced(&pos.storage_key(), &over)
        .expect("store oversized record");
    let err = store
        .get_signing_record(&pos.storage_key())
        .expect_err("oversized record must be refused");
    assert!(
        matches!(err, qbind_node::storage::StorageError::Corruption(_)),
        "oversized record must be a Corruption refusal, got {:?}",
        err
    );
}

/// An exactly-at-limit record value passes the size gate (the bound is a
/// strict `>` ceiling); the direct read returns the stored payload.
#[test]
fn direct_read_record_at_limit_is_returned() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(34);
    let store = open_store(dir.path());
    // Payload exactly `MAX_RECORD_LEN` ⇒ stored enveloped value `4 + MAX_RECORD_LEN`
    // ⇒ equal to the bound, not greater; the size gate permits it.
    let at = vec![0u8; MAX_RECORD_LEN];
    store
        .put_signing_record_synced(&pos.storage_key(), &at)
        .expect("store at-limit record");
    let got = store
        .get_signing_record(&pos.storage_key())
        .expect("at-limit record must pass the size gate");
    assert_eq!(got.expect("payload present").len(), MAX_RECORD_LEN);
}

/// An oversized stored metadata value (one byte beyond the fixed metadata
/// encoding size, under a valid envelope) is refused by the direct metadata read
/// BEFORE unwrapping.
#[test]
fn direct_read_oversized_metadata_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(dir.path());
    let over = vec![0u8; METADATA_ENCODED_LEN + 1];
    store
        .put_signing_metadata_synced(&over)
        .expect("store oversized metadata");
    let err = store
        .get_signing_metadata()
        .expect_err("oversized metadata must be refused");
    assert!(
        matches!(err, qbind_node::storage::StorageError::Corruption(_)),
        "oversized metadata must be a Corruption refusal, got {:?}",
        err
    );
}

/// A truncated (sub-envelope-length) RAW stored record value is refused by the
/// direct read: the size gate passes (it is under the ceiling) but the envelope
/// unwrap then rejects the too-short value fail-closed. Uses the test-only raw
/// seam to bypass the checksum writer.
#[cfg(feature = "test-utils")]
#[test]
fn direct_read_truncated_record_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(35);
    let store = open_store(dir.path());
    // Two raw bytes: below the 4-byte checksum envelope minimum.
    store
        .put_signing_namespace_raw_for_test(Some(&pos.storage_key()), &[0xAA, 0xBB])
        .expect("raw truncated write");
    let err = store
        .get_signing_record(&pos.storage_key())
        .expect_err("truncated record must be refused");
    assert!(
        matches!(err, qbind_node::storage::StorageError::Corruption(_)),
        "truncated record must be a Corruption refusal, got {:?}",
        err
    );
}

/// A truncated (sub-envelope-length) RAW stored metadata value is refused by the
/// direct metadata read. Uses the test-only raw seam.
#[cfg(feature = "test-utils")]
#[test]
fn direct_read_truncated_metadata_refused() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(dir.path());
    store
        .put_signing_namespace_raw_for_test(None, &[0x01])
        .expect("raw truncated metadata write");
    let err = store
        .get_signing_metadata()
        .expect_err("truncated metadata must be refused");
    assert!(
        matches!(err, qbind_node::storage::StorageError::Corruption(_)),
        "truncated metadata must be a Corruption refusal, got {:?}",
        err
    );
}

/// An oversized RAW stored record (beyond the envelope bound) is refused by the
/// direct read BEFORE any unwrap, even when written with the raw seam (no valid
/// checksum). This proves the size gate precedes envelope validation.
#[cfg(feature = "test-utils")]
#[test]
fn direct_read_oversized_raw_record_refused_before_unwrap() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(36);
    let store = open_store(dir.path());
    // Raw bytes beyond `4 + MAX_RECORD_LEN`, with NO valid checksum: the size
    // gate must refuse before the envelope is ever examined.
    let over = vec![0x7Au8; 4 + MAX_RECORD_LEN + 32];
    store
        .put_signing_namespace_raw_for_test(Some(&pos.storage_key()), &over)
        .expect("raw oversized write");
    let err = store
        .get_signing_record(&pos.storage_key())
        .expect_err("oversized raw record must be refused");
    assert!(
        matches!(err, qbind_node::storage::StorageError::Corruption(_)),
        "oversized raw record must be a Corruption refusal, got {:?}",
        err
    );
}

/// A second journal handle over the *same* durable store cannot obtain a second
/// live signing permit for an already-reserved position: the earlier durable
/// reservation is visible and treated as potentially-signed.
#[test]
fn second_handle_over_same_store_cannot_get_second_permit() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(2);
    let bind = binding(0x7E);

    let store = open_store(dir.path());
    let journal_a = journal(store.clone() as Arc<dyn SigningJournalStorage>);
    assert!(matches!(
        journal_a.reserve_for_sign(&pos, &bind).expect("reserve A"),
        ReservationOutcome::FreshlyReserved(_)
    ));

    // A second, independently-attached handle sharing the SAME durable store
    // (same backend instance ⇒ ONE shared ownership domain).
    let journal_b = journal(store as Arc<dyn SigningJournalStorage>);
    assert!(
        matches!(
            journal_b
                .reserve_for_sign(&pos, &bind)
                .expect("reserve B lookup"),
            ReservationOutcome::PotentiallySigned
        ),
        "a second handle must not manufacture a second live continuation from a durable Reserved record"
    );
}

// ---------------------------------------------------------------------------
// Correction E — explicit initialization / established-open validation and
// persistent journal-wide capacity over the real RocksDB backend.
// ---------------------------------------------------------------------------

/// Explicit empty-namespace initialization succeeds and durably publishes
/// initialization metadata; a real close/reopen then *opens and validates* the
/// established journal (never re-initializing it).
#[test]
fn initialize_empty_namespace_succeeds_and_reopen_validates() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(31);
    let bind = binding(0x11);

    {
        let store = open_store(dir.path());
        let j = SigningReservationJournal::initialize(
            store.clone() as Arc<dyn SigningJournalStorage>,
            DEFAULT_MAX_RESERVED_POSITIONS,
        )
        .expect("explicit initialize of empty namespace");
        // Initialization metadata is durably present.
        assert!(
            store.get_signing_metadata().expect("meta read").is_some(),
            "initialization must durably publish metadata"
        );
        // The initialized journal admits a fresh reservation.
        assert!(matches!(
            j.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    // Reopen the same on-disk directory and OPEN (validate) the established
    // journal; the recovered reservation is potentially-signed.
    let store = open_store(dir.path());
    let j = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect("open established journal after reopen");
    assert!(matches!(
        j.reserve_for_sign(&pos, &bind).expect("recovered lookup"),
        ReservationOutcome::PotentiallySigned
    ));
}

/// Opening an established journal on absent metadata refuses fail-closed with
/// `NotInitialized` and does NOT create metadata (never falls back to init).
#[test]
fn open_absent_metadata_refuses_not_initialized_without_creating_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let store = open_store(dir.path());
    let err = SigningReservationJournal::open(store.clone() as Arc<dyn SigningJournalStorage>)
        .expect_err("absent metadata must refuse");
    assert!(matches!(err, JournalError::NotInitialized), "got {:?}", err);
    // Refusal must not have written any initialization metadata.
    assert!(
        store.get_signing_metadata().expect("meta read").is_none(),
        "a refused open must not create metadata"
    );
}

/// Records present without initialization metadata refuse fail-closed as legacy
/// records; they are neither adopted, migrated, nor deleted.
#[test]
fn records_without_metadata_refuses_as_legacy() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(33);
    let store = open_store(dir.path());
    // A record byte-blob exists under a valid record key, but NO initialization
    // metadata was ever published (a legacy / foreign namespace).
    store
        .put_signing_record_synced(&pos.storage_key(), &[0x01, 0x02, 0x03, 0x04])
        .expect("write legacy record");
    let err = SigningReservationJournal::open(store.clone() as Arc<dyn SigningJournalStorage>)
        .expect_err("records without metadata must refuse");
    assert!(
        matches!(err, JournalError::LegacyRecordsWithoutMetadata),
        "got {:?}",
        err
    );
    // The legacy record is left untouched (not migrated or deleted).
    assert!(
        store
            .get_signing_record(&pos.storage_key())
            .expect("read")
            .is_some(),
        "a refused open must not delete legacy records"
    );
}

/// Repeated initialization over an established (reopened) backend refuses with
/// `AlreadyInitialized` and preserves the established state — it never resets.
#[test]
fn duplicate_initialize_over_reopened_backend_refuses_and_preserves_state() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(35);
    let bind = binding(0x22);

    {
        let store = open_store(dir.path());
        let j = SigningReservationJournal::initialize(
            store as Arc<dyn SigningJournalStorage>,
            4,
        )
        .expect("initialize");
        assert!(matches!(
            j.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved(_)
        ));
    }

    // Reopen: a repeated initialization must be refused (metadata present).
    let store = open_store(dir.path());
    let err = SigningReservationJournal::initialize(
        store.clone() as Arc<dyn SigningJournalStorage>,
        4,
    )
    .expect_err("repeat initialize must refuse");
    assert!(matches!(err, JournalError::AlreadyInitialized), "got {:?}", err);

    // The established state is intact: opening validates and the earlier
    // reservation is recovered as potentially-signed.
    let j = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect("open established after refused re-init");
    assert!(matches!(
        j.reserve_for_sign(&pos, &bind).expect("recovered lookup"),
        ReservationOutcome::PotentiallySigned
    ));
}

/// One journal-wide position limit is enforced, both `Reserved` positions count
/// toward it, refusal at capacity is `Exhausted`, and the same limit survives a
/// real close/reopen. Recovery of an existing position never frees capacity.
#[test]
fn capacity_limit_enforced_and_survives_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p1 = proposal_position(41);
    let p2 = vote_position(41);
    let p3 = proposal_position(42);

    {
        let store = open_store(dir.path());
        let j = SigningReservationJournal::initialize(
            store as Arc<dyn SigningJournalStorage>,
            2,
        )
        .expect("initialize with limit 2");
        assert!(matches!(
            j.reserve_for_sign(&p1, &binding(1)).expect("reserve p1"),
            ReservationOutcome::FreshlyReserved(_)
        ));
        assert!(matches!(
            j.reserve_for_sign(&p2, &binding(2)).expect("reserve p2"),
            ReservationOutcome::FreshlyReserved(_)
        ));
        // At capacity (two distinct persisted positions): a third distinct
        // position is refused.
        assert!(matches!(
            j.reserve_for_sign(&p3, &binding(3)).expect("reserve p3"),
            ReservationOutcome::Exhausted
        ));
    }

    // Reopen: the persisted count (2) and limit (2) are restored from metadata
    // and validated against the two stored records.
    let store = open_store(dir.path());
    let j = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect("open established journal");
    // Still at capacity after reopen.
    assert!(matches!(
        j.reserve_for_sign(&p3, &binding(3)).expect("reserve p3 after reopen"),
        ReservationOutcome::Exhausted
    ));
    // Recovering an existing position does not consume a further position and
    // does not free capacity for a new one.
    assert!(matches!(
        j.reserve_for_sign(&p1, &binding(1)).expect("recovered p1"),
        ReservationOutcome::PotentiallySigned
    ));
    assert!(matches!(
        j.reserve_for_sign(&p3, &binding(3)).expect("reserve p3 again"),
        ReservationOutcome::Exhausted
    ));
}

/// A second supported handle over the same backend inherits the one established
/// limit and cannot relax it, and re-initialization to a larger limit is refused.
#[test]
fn second_handle_cannot_relax_capacity() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p1 = proposal_position(51);
    let p2 = proposal_position(52);

    let store = open_store(dir.path());
    let j_a = SigningReservationJournal::initialize(
        store.clone() as Arc<dyn SigningJournalStorage>,
        1,
    )
    .expect("initialize with limit 1");
    assert!(matches!(
        j_a.reserve_for_sign(&p1, &binding(1)).expect("reserve p1"),
        ReservationOutcome::FreshlyReserved(_)
    ));

    // A second handle over the SAME backend instance shares the ownership domain
    // and inherits the established limit; it cannot admit a new position.
    let j_b = SigningReservationJournal::open(store.clone() as Arc<dyn SigningJournalStorage>)
        .expect("open second handle");
    assert!(
        matches!(
            j_b.reserve_for_sign(&p2, &binding(2)).expect("reserve p2 via B"),
            ReservationOutcome::Exhausted
        ),
        "a second handle must not relax the established capacity"
    );

    // Re-initialization to a larger limit over the established backend refuses.
    let err = SigningReservationJournal::initialize(
        store as Arc<dyn SigningJournalStorage>,
        DEFAULT_MAX_RESERVED_POSITIONS,
    )
    .expect_err("re-initialize to relax capacity must refuse");
    assert!(matches!(err, JournalError::AlreadyInitialized), "got {:?}", err);
}

/// A stored key that does not match its record's canonical position is an
/// accounting inconsistency and refuses fail-closed on open.
#[test]
fn key_record_mismatch_refuses_on_open() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p1 = proposal_position(61);
    let p2 = proposal_position(62);
    let bind = binding(0x77);

    // Establish a journal with one genuine reservation and capture its exact
    // stored record bytes.
    let record_bytes = {
        let store = open_store(dir.path());
        let j = SigningReservationJournal::initialize(
            store.clone() as Arc<dyn SigningJournalStorage>,
            4,
        )
        .expect("initialize");
        assert!(matches!(
            j.reserve_for_sign(&p1, &bind).expect("reserve p1"),
            ReservationOutcome::FreshlyReserved(_)
        ));
        store
            .get_signing_record(&p1.storage_key())
            .expect("read p1")
            .expect("p1 present")
    };

    // Reopen and store p1's record bytes under p2's key: the stored key no longer
    // matches the record's canonical position.
    let store = open_store(dir.path());
    store
        .put_signing_record_synced(&p2.storage_key(), &record_bytes)
        .expect("write mismatched record");
    drop(store);

    let store = open_store(dir.path());
    let err = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect_err("key/record mismatch must refuse");
    assert!(
        matches!(err, JournalError::AccountingInconsistent(_)),
        "got {:?}",
        err
    );
}

/// Explicit observable capacity accounting after a real reopen (uses the
/// `test-utils` introspection accessors).
#[cfg(feature = "test-utils")]
#[test]
fn established_limit_and_count_are_observable_after_reopen() {
    let dir = tempfile::tempdir().expect("tempdir");
    let p1 = proposal_position(71);
    let p2 = vote_position(71);

    {
        let store = open_store(dir.path());
        let j = SigningReservationJournal::initialize(
            store as Arc<dyn SigningJournalStorage>,
            3,
        )
        .expect("initialize with limit 3");
        assert_eq!(j.established_limit(), 3);
        assert_eq!(j.reserved_position_count(), 0);
        let _ = j.reserve_for_sign(&p1, &binding(1)).expect("reserve p1");
        let _ = j.reserve_for_sign(&p2, &binding(2)).expect("reserve p2");
        assert_eq!(j.reserved_position_count(), 2);
    }

    let store = open_store(dir.path());
    let j = SigningReservationJournal::open(store as Arc<dyn SigningJournalStorage>)
        .expect("open established journal");
    // The established limit and the counted positions are restored from durable
    // metadata and validated against the two stored records.
    assert_eq!(j.established_limit(), 3);
    assert_eq!(j.reserved_position_count(), 2);
}

// ---------------------------------------------------------------------------
// Child-process death / reopen (unbounded, unclassified runner — does NOT
// close Correction F).
// ---------------------------------------------------------------------------

/// Correction C over the real RocksDB backend: idempotent identical publication
/// is accepted once durably acknowledged, a conflicting overwrite with different
/// bytes is refused, and the original retained signature is preserved for an
/// exact resend.
#[test]
fn publication_is_idempotent_and_refuses_conflicting_overwrite() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(21);
    let bind = binding(0x6C);
    let signature = vec![0xC0, 0xFF, 0xEE, 0x01];

    let store = open_store(dir.path());
    let journal = journal(store as Arc<dyn SigningJournalStorage>);
    let cap = reserve_and_invoke(&journal, &pos, &bind);
    journal
        .record_signed_result(&cap, &signature)
        .expect("first durable publish");
    // Idempotent identical republication through the same capability is accepted
    // (this operation already holds a durable acknowledgement).
    journal
        .record_signed_result(&cap, &signature)
        .expect("idempotent identical republish");
    // A conflicting overwrite with DIFFERENT bytes is refused — an existing
    // signed obligation is never replaced with different content.
    assert!(matches!(
        journal.record_signed_result(&cap, &[0xDE, 0xAD]),
        Err(JournalError::InvalidResultPublication(_))
    ));
    // The original retained signature is intact for exact retry.
    match journal.reserve_for_sign(&pos, &bind).expect("retry lookup") {
        ReservationOutcome::ExactRetryRetained(sig) => assert_eq!(sig, signature),
        other => panic!("expected ExactRetryRetained, got {:?}", other),
    }
}

/// Child mode: open the real store at `$QBIND_D7D10_CHILD_DB`, durably reserve a
/// fixed Proposal position, emit+flush the [`CHILD_RESERVED_MARKER`] readiness
/// line AFTER the reservation's successful durability acknowledgement, then abort
/// BEFORE recording any signed result. This is invoked by re-executing this test
/// binary with the env var set; a normal (unset) run of this `#[ignore]`d test is
/// a harmless no-op.
#[test]
#[ignore = "child-mode helper; only meaningful when re-executed with QBIND_D7D10_CHILD_DB set"]
fn d7d10_child_reserve_then_abort() {
    let Some(db) = std::env::var_os(CHILD_DB_ENV) else {
        // Not in child mode: nothing to do.
        return;
    };
    let path = std::path::PathBuf::from(db);
    let store = open_store(&path);
    let journal = journal(store as Arc<dyn SigningJournalStorage>);
    match journal
        .reserve_for_sign(&child_position(), &child_binding())
        .expect("child reservation must succeed")
    {
        ReservationOutcome::FreshlyReserved(_cont) => { /* durable ack; drop before sign */ }
        other => panic!("expected FreshlyReserved, got {:?}", other),
    }
    // Durable reservation acknowledged. Emit+flush the distinctive readiness
    // marker BEFORE the intentional abort, so the bounded parent can require
    // reliable, complete capture of "reservation acknowledged, not yet signed".
    // The abort precedes any signer invocation or result publication.
    {
        use std::io::Write as _;
        let mut err = std::io::stderr();
        let _ = writeln!(err, "{}", CHILD_RESERVED_MARKER);
        let _ = err.flush();
    }
    std::process::abort();
}

fn child_position() -> SigningPosition {
    SigningPosition {
        validator_id: 11,
        network_genesis: [0x2Cu8; 32],
        kind: SigningKind::Proposal,
        originating_view: 42,
    }
}

fn child_binding() -> BindingDigest {
    BindingDigest([0x9Fu8; 32])
}

/// Run 422 D7-D10 Correction F-B — a deadline-bounded, explicitly
/// termination-classified child-process runner, adapted MINIMALLY from the
/// established D3 process-runner patterns
/// (`run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`). It does
/// NOT duplicate the whole D3 target: only the piped-capture + bounded
/// process-status-wait + pure-classification pieces this test needs are
/// reproduced, retargeted at THIS integration-test executable (re-executed in
/// child mode) and at small single-process `sh` control children.
///
/// Platform restriction (honest): terminating-signal classification uses the
/// Unix `ExitStatusExt::signal()` and the POSIX-fixed SIGABRT value, so the
/// bounded parent and the runner controls are `#[cfg(unix)]`. On the supported
/// Unix/Linux profile the parent requires the child's intentional
/// `std::process::abort()` to surface as SIGABRT; an ordinary nonzero exit, a
/// panic (nonzero exit, no signal), an unrelated terminating signal, or a
/// deadline cannot pass.
#[cfg(unix)]
mod bounded_child_runner {
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    /// SIGABRT. `std::process::abort()` raises this on Unix; `std` has no
    /// constant, and 6 is the POSIX-fixed value.
    pub(super) const EXPECTED_ABORT_SIGNAL: i32 = 6;

    const CAPTURE_CAP_BYTES: usize = 256 * 1024;

    #[derive(Default)]
    struct CapturedStream {
        buf: String,
        dropped: usize,
        read_outcome: Option<Result<(), String>>,
    }

    fn lock_recover(m: &Mutex<CapturedStream>) -> MutexGuard<'_, CapturedStream> {
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn drain_into(mut r: impl Read, sink: Arc<Mutex<CapturedStream>>) {
        let mut chunk = [0u8; 8192];
        let terminal: Result<(), String> = loop {
            match r.read(&mut chunk) {
                Ok(0) => break Ok(()),
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk[..n]);
                    let mut g = lock_recover(&sink);
                    let remaining = CAPTURE_CAP_BYTES.saturating_sub(g.buf.len());
                    if remaining == 0 {
                        g.dropped += text.len();
                    } else if text.len() <= remaining {
                        g.buf.push_str(&text);
                    } else {
                        let mut end = remaining;
                        while end > 0 && !text.is_char_boundary(end) {
                            end -= 1;
                        }
                        g.buf.push_str(&text[..end]);
                        g.dropped += text.len() - end;
                    }
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => break Err(format!("read error kind={:?}", e.kind())),
            }
        };
        lock_recover(&sink).read_outcome = Some(terminal);
    }

    /// Completed capture integrity for the drained stderr stream, resolvable
    /// only AFTER the drain thread is joined. A missing-marker/absence claim —
    /// or a present-marker claim — may only rest on [`CaptureOutcome::Complete`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum CaptureOutcome {
        Complete,
        Truncated { dropped: usize },
        ReadFailed { detail: String },
        ThreadPanicked,
        StillDraining,
    }

    impl CaptureOutcome {
        pub(super) fn is_complete(&self) -> bool {
            matches!(self, CaptureOutcome::Complete)
        }
    }

    fn classify_capture(s: &CapturedStream, panicked: bool) -> CaptureOutcome {
        if panicked {
            return CaptureOutcome::ThreadPanicked;
        }
        match &s.read_outcome {
            None => CaptureOutcome::StillDraining,
            Some(Err(d)) => CaptureOutcome::ReadFailed { detail: d.clone() },
            Some(Ok(())) => {
                if s.dropped > 0 {
                    CaptureOutcome::Truncated { dropped: s.dropped }
                } else {
                    CaptureOutcome::Complete
                }
            }
        }
    }

    /// A deadline-bounded child with drained stdout/stderr. `Drop` always
    /// kills+reaps, so an assertion unwind never leaks the child or blocks on a
    /// surviving descendant.
    pub(super) struct BoundedChild {
        child: Child,
        stderr: Arc<Mutex<CapturedStream>>,
        stderr_thread: Option<JoinHandle<()>>,
        stdout_thread: Option<JoinHandle<()>>,
        stderr_join_failed: bool,
        reaped: bool,
    }

    impl BoundedChild {
        /// Spawn `command` with piped stdio and start the drain threads.
        /// Per-`Command` configuration only — the caller sets env on the
        /// `Command`, never via process-global `std::env::set_var`.
        pub(super) fn spawn(mut command: Command, ctx: &'static str) -> Self {
            let mut child = command
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .unwrap_or_else(|e| panic!("TEST FAILURE: {ctx}: spawn failed: {e}"));
            let stderr = Arc::new(Mutex::new(CapturedStream::default()));
            let stdout = Arc::new(Mutex::new(CapturedStream::default()));
            let e = child.stderr.take().expect("piped stderr");
            let o = child.stdout.take().expect("piped stdout");
            let se = stderr.clone();
            let stderr_thread = Some(thread::spawn(move || drain_into(e, se)));
            let stdout_thread = Some(thread::spawn(move || drain_into(o, stdout)));
            BoundedChild {
                child,
                stderr,
                stderr_thread,
                stdout_thread,
                stderr_join_failed: false,
                reaped: false,
            }
        }

        fn stderr_snapshot(&self) -> String {
            lock_recover(&self.stderr).buf.clone()
        }

        fn stderr_capture(&self) -> CaptureOutcome {
            classify_capture(&lock_recover(&self.stderr), self.stderr_join_failed)
        }

        fn join_drains(&mut self) {
            if let Some(h) = self.stderr_thread.take() {
                if h.join().is_err() {
                    self.stderr_join_failed = true;
                }
            }
            if let Some(h) = self.stdout_thread.take() {
                // stdout is not asserted on, but it must still be joined so a
                // large stdout can never leave a drain thread blocked.
                let _ = h.join();
            }
        }

        /// Explicit cleanup: kill the child and reap it, then join the drain
        /// threads. Only marks cleanup complete when reaping actually succeeded,
        /// so `Drop` retries a failed reap.
        pub(super) fn kill_and_reap(&mut self) {
            if !self.reaped {
                let _ = self.child.kill();
                if self.child.wait().is_ok() {
                    self.reaped = true;
                }
            }
            self.join_drains();
        }

        /// Wait for the child to terminate ON ITS OWN within `deadline` via
        /// repeated process-status polling (`try_wait`, NOT a fixed sleep
        /// guessing the child has exited). On natural exit the FULL `ExitStatus`
        /// (signal preserved) is returned with drained+joined capture. A
        /// deadline is a hard failure: the child is killed/reaped and `Timeout`
        /// is returned — NEVER reinterpreted as a crash. `try_wait` errors are
        /// handled explicitly (kill+reap, then panic).
        pub(super) fn wait_self_termination(&mut self, deadline: Duration) -> SelfTermination {
            let start = Instant::now();
            loop {
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.reaped = true;
                        self.join_drains();
                        return SelfTermination::Exited {
                            status,
                            stderr: self.stderr_snapshot(),
                            capture: self.stderr_capture(),
                        };
                    }
                    Ok(None) => {
                        if start.elapsed() >= deadline {
                            let stderr = self.stderr_snapshot();
                            self.kill_and_reap();
                            return SelfTermination::Timeout { stderr };
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => {
                        self.kill_and_reap();
                        panic!("TEST FAILURE: try_wait errored while waiting for child: {e}");
                    }
                }
            }
        }
    }

    impl Drop for BoundedChild {
        fn drop(&mut self) {
            self.kill_and_reap();
        }
    }

    /// Result of a bounded self-termination wait. `Timeout` is a failure
    /// condition (the child did not die on its own in time); the child has been
    /// killed and reaped before it is returned.
    #[derive(Debug)]
    pub(super) enum SelfTermination {
        Exited {
            status: ExitStatus,
            stderr: String,
            capture: CaptureOutcome,
        },
        Timeout {
            stderr: String,
        },
    }

    /// Pure classification of a completed child termination over its full
    /// `ExitStatus`, the readiness-marker presence and the stderr capture
    /// integrity. Deterministically unit-testable with constructed statuses.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum ChildCrashClass {
        /// The only accepted positive: terminated by the expected abort signal
        /// AND the readiness marker was present in a COMPLETE capture.
        AbortedAfterMarker { signal: i32 },
        /// Terminated by the expected abort signal but the marker was absent or
        /// the capture was not complete — NOT accepted (cannot establish
        /// reservation-before-abort).
        SignalButMarkerUnusable { signal: i32 },
        /// Terminated by a DIFFERENT terminating signal (e.g. a panic abort is
        /// never a normal exit; a crash signal other than SIGABRT). Not accepted.
        UnexpectedSignal { signal: i32 },
        /// Exited with a code and no terminating signal (ordinary success/
        /// nonzero exit, including a Rust panic's nonzero exit). Not accepted.
        NormalExit { code: Option<i32> },
    }

    pub(super) fn classify_child_crash(
        status: ExitStatus,
        marker_present: bool,
        capture: &CaptureOutcome,
        expected_signal: i32,
    ) -> ChildCrashClass {
        match status.signal() {
            None => ChildCrashClass::NormalExit { code: status.code() },
            Some(sig) if sig == expected_signal => {
                if marker_present && capture.is_complete() {
                    ChildCrashClass::AbortedAfterMarker { signal: sig }
                } else {
                    ChildCrashClass::SignalButMarkerUnusable { signal: sig }
                }
            }
            Some(sig) => ChildCrashClass::UnexpectedSignal { signal: sig },
        }
    }
}

/// Run 422 D7-D10 Correction F-B — bounded, classified child-death-then-reopen.
///
/// Boundary (what this establishes): an integration-test child executable (THIS
/// binary, re-executed in child mode) performs a REAL `RocksDbConsensusStorage`
/// reservation, emits+flushes a readiness marker only after the durable
/// acknowledgement, then intentionally `abort()`s before any signer invocation
/// or result publication. The parent waits with an INTERNAL deadline and
/// explicit process-status observation, preserves the FULL `ExitStatus`, and
/// accepts the crash ONLY when it is SIGABRT AND the readiness marker was
/// captured completely. It then opens a FRESH RocksDB handle + ownership domain
/// and asserts the recovered reserved-only record refuses re-signing and that
/// refusals leave the durable record and accounting byte-identical.
///
/// This demonstrates crash-consistency of the LOCAL journal across real process
/// death; it is explicitly NOT empirical power-loss / rollback-resistance
/// evidence (no DB-wide monotonic anchor is established here).
#[cfg(unix)]
#[test]
fn reserved_only_child_death_then_reopen_refuses() {
    use bounded_child_runner::*;
    use std::time::Duration;

    /// Internal child deadline. Generous for a loaded CI host but a hard bound:
    /// exceeding it is a test failure, not crash evidence.
    const CHILD_DEADLINE: Duration = Duration::from_secs(120);

    // Isolate the RocksDB directory outside the child so it survives the abort.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("child_journal_db");

    let exe = std::env::current_exe().expect("current test exe");
    let mut command = std::process::Command::new(exe);
    command
        .args([
            "--exact",
            "d7d10_child_reserve_then_abort",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        // Per-`Command` environment configuration only (no process-global
        // `set_var`): this child-helper selection cannot leak into siblings.
        .env(CHILD_DB_ENV, &db_path);
    let mut child = BoundedChild::spawn(command, "spawn d7d10 child test executable");

    let (status, stderr, capture) = match child.wait_self_termination(CHILD_DEADLINE) {
        SelfTermination::Exited {
            status,
            stderr,
            capture,
        } => (status, stderr, capture),
        SelfTermination::Timeout { stderr } => panic!(
            "TEST FAILURE: child did not self-terminate within {CHILD_DEADLINE:?}; a timeout is \
             not crash evidence (child was killed+reaped). stderr so far=\n{stderr}"
        ),
    };

    let marker_present = stderr.contains(CHILD_RESERVED_MARKER);
    match classify_child_crash(status, marker_present, &capture, EXPECTED_ABORT_SIGNAL) {
        ChildCrashClass::AbortedAfterMarker { signal } => {
            assert_eq!(signal, EXPECTED_ABORT_SIGNAL, "intentional abort ⇒ SIGABRT");
        }
        other => panic!(
            "TEST FAILURE: child termination is not an accepted reserve-then-SIGABRT crash: \
             {other:?}; status={status:?}, marker_present={marker_present}, capture={capture:?}, \
             stderr=\n{stderr}"
        ),
    }

    // Reopen a FRESH RocksDB handle + ownership domain (the post-death posture:
    // durable records survive, the in-memory live-permit map does not).
    let store = open_store(&db_path);
    let store_for_raw = store.clone();
    let journal = journal(store as Arc<dyn SigningJournalStorage>);

    // Inspect the expected valid Reserved record at the exact position/binding,
    // and snapshot the raw record + persistent accounting so the refusals below
    // can be shown to leave them byte-identical.
    let rec_before = store_for_raw
        .get_signing_record(&child_position().storage_key())
        .expect("record read must not error")
        .expect("a reserved record must be present after the child's durable reservation");
    let meta_before = store_for_raw
        .get_signing_metadata()
        .expect("metadata read must not error");

    // Exact retry MUST return PotentiallySigned — never a fresh continuation or a
    // retained signed result (the child never signed; this is a recovered
    // Reserved record).
    assert!(
        matches!(
            journal
                .reserve_for_sign(&child_position(), &child_binding())
                .expect("post-death exact-retry lookup must not error"),
            ReservationOutcome::PotentiallySigned
        ),
        "a reservation recovered after child death must refuse re-signing (PotentiallySigned)"
    );

    // A conflicting binding MUST return Conflict.
    assert!(
        matches!(
            journal
                .reserve_for_sign(&child_position(), &binding(0x01))
                .expect("post-death conflict lookup must not error"),
            ReservationOutcome::Conflict
        ),
        "a conflicting binding at the recovered position must be refused as Conflict"
    );

    // The record and persistent accounting are unchanged across the refusals.
    let rec_after = store_for_raw
        .get_signing_record(&child_position().storage_key())
        .expect("record read must not error")
        .expect("the reserved record must still be present after refused attempts");
    let meta_after = store_for_raw
        .get_signing_metadata()
        .expect("metadata read must not error");
    assert_eq!(
        rec_before, rec_after,
        "the recovered Reserved record is byte-identical across refused attempts"
    );
    assert_eq!(
        meta_before, meta_after,
        "persistent accounting is unchanged across refused attempts"
    );
}

// ============================================================================
// Run 422 D7-D10 Correction F-B — runner negative/positive CONTROLS.
//
// These exercise the SAME bounded runner + classification path with controlled
// single-process `sh` children (no pipe-holding descendant, so cleanup is
// bounded). They do NOT touch RocksDB: they establish the runner's termination
// decision table against real processes, complementing the pure
// constructed-status table below. No fixed sleep stands in for a child's exit,
// and no outer tool timeout is used as the runner deadline.
// ============================================================================

/// Build a single-process `sh -c <script>` control child command.
#[cfg(unix)]
fn sh_control_command(script: &str) -> std::process::Command {
    let mut c = std::process::Command::new("sh");
    c.arg("-c").arg(script);
    c
}

/// A controlled child that emits the readiness marker then intentionally aborts
/// (SIGABRT) is ACCEPTED — the positive control for the runner itself.
#[cfg(unix)]
#[test]
fn runner_control_marker_then_sigabrt_is_accepted() {
    use bounded_child_runner::*;
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(10);

    let script = format!("printf '%s\\n' '{CHILD_RESERVED_MARKER}' 1>&2; kill -s ABRT $$");
    let mut child = BoundedChild::spawn(sh_control_command(&script), "spawn sh ABRT control");
    match child.wait_self_termination(DEADLINE) {
        SelfTermination::Exited {
            status,
            stderr,
            capture,
        } => {
            let marker = stderr.contains(CHILD_RESERVED_MARKER);
            assert_eq!(
                classify_child_crash(status, marker, &capture, EXPECTED_ABORT_SIGNAL),
                ChildCrashClass::AbortedAfterMarker {
                    signal: EXPECTED_ABORT_SIGNAL
                },
                "marker + SIGABRT with complete capture is the accepted positive; stderr=\n{stderr}"
            );
        }
        SelfTermination::Timeout { stderr } => {
            panic!("control child should have aborted promptly; stderr=\n{stderr}")
        }
    }
}

/// A child that emits the marker but exits with a NORMAL nonzero code is
/// REJECTED (no terminating signal ⇒ not a crash), even though the marker is
/// present.
#[cfg(unix)]
#[test]
fn runner_control_marker_then_nonzero_exit_is_rejected() {
    use bounded_child_runner::*;
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(10);

    let script = format!("printf '%s\\n' '{CHILD_RESERVED_MARKER}' 1>&2; exit 7");
    let mut child = BoundedChild::spawn(sh_control_command(&script), "spawn sh nonzero-exit control");
    match child.wait_self_termination(DEADLINE) {
        SelfTermination::Exited {
            status,
            stderr,
            capture,
        } => {
            assert!(stderr.contains(CHILD_RESERVED_MARKER), "marker WAS emitted");
            let marker = stderr.contains(CHILD_RESERVED_MARKER);
            assert_eq!(
                classify_child_crash(status, marker, &capture, EXPECTED_ABORT_SIGNAL),
                ChildCrashClass::NormalExit { code: Some(7) },
                "a normal nonzero exit is rejected even with the marker present; stderr=\n{stderr}"
            );
        }
        SelfTermination::Timeout { stderr } => {
            panic!("control child should have exited promptly; stderr=\n{stderr}")
        }
    }
}

/// A child that emits the marker but terminates with an UNEXPECTED signal
/// (SIGTERM) is REJECTED.
#[cfg(unix)]
#[test]
fn runner_control_marker_then_unexpected_signal_is_rejected() {
    use bounded_child_runner::*;
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(10);

    // SIGTERM (15) — a terminating signal that is NOT the expected SIGABRT.
    let script = format!("printf '%s\\n' '{CHILD_RESERVED_MARKER}' 1>&2; kill -s TERM $$");
    let mut child = BoundedChild::spawn(sh_control_command(&script), "spawn sh SIGTERM control");
    match child.wait_self_termination(DEADLINE) {
        SelfTermination::Exited {
            status,
            stderr,
            capture,
        } => {
            let marker = stderr.contains(CHILD_RESERVED_MARKER);
            match classify_child_crash(status, marker, &capture, EXPECTED_ABORT_SIGNAL) {
                ChildCrashClass::UnexpectedSignal { signal } => {
                    assert_ne!(signal, EXPECTED_ABORT_SIGNAL, "a non-SIGABRT signal is rejected");
                }
                other => panic!(
                    "expected UnexpectedSignal rejection, got {other:?}; stderr=\n{stderr}"
                ),
            }
        }
        SelfTermination::Timeout { stderr } => {
            panic!("control child should have signalled promptly; stderr=\n{stderr}")
        }
    }
}

/// A child that aborts with SIGABRT but WITHOUT emitting the marker cannot
/// establish reservation-before-abort — it is REJECTED despite the right signal.
#[cfg(unix)]
#[test]
fn runner_control_sigabrt_without_marker_is_rejected() {
    use bounded_child_runner::*;
    use std::time::Duration;
    const DEADLINE: Duration = Duration::from_secs(10);

    let mut child = BoundedChild::spawn(sh_control_command("kill -s ABRT $$"), "spawn sh ABRT-no-marker control");
    match child.wait_self_termination(DEADLINE) {
        SelfTermination::Exited {
            status,
            stderr,
            capture,
        } => {
            let marker = stderr.contains(CHILD_RESERVED_MARKER);
            assert!(!marker, "the control emitted no marker");
            assert_eq!(
                classify_child_crash(status, marker, &capture, EXPECTED_ABORT_SIGNAL),
                ChildCrashClass::SignalButMarkerUnusable {
                    signal: EXPECTED_ABORT_SIGNAL
                },
                "SIGABRT without the readiness marker is not accepted; stderr=\n{stderr}"
            );
        }
        SelfTermination::Timeout { stderr } => {
            panic!("control child should have aborted promptly; stderr=\n{stderr}")
        }
    }
}

/// A child that stays alive past the internal deadline yields a TIMEOUT failure
/// and is cleaned up/reaped; the result returns within a generous outer bound
/// (so cleanup is proven not to wait on the surviving sleep).
#[cfg(unix)]
#[test]
fn runner_control_alive_past_deadline_times_out_and_is_reaped() {
    use bounded_child_runner::*;
    use std::time::{Duration, Instant};
    const SHORT_DEADLINE: Duration = Duration::from_secs(2);
    const OUTER_BOUND: Duration = Duration::from_secs(20);

    // `exec sleep 30` replaces the shell, so the ONLY process holding the pipes
    // is the sleep — killing it closes them at once (no surviving descendant).
    let mut child = BoundedChild::spawn(sh_control_command("exec sleep 30"), "spawn sh sleep control");
    let start = Instant::now();
    let outcome = child.wait_self_termination(SHORT_DEADLINE);
    let elapsed = start.elapsed();
    match outcome {
        SelfTermination::Timeout { .. } => {}
        other => panic!("expected a bounded Timeout failure, got {other:?}"),
    }
    assert!(
        elapsed < OUTER_BOUND,
        "deadline+cleanup must return within the generous outer bound (no wait on the surviving \
         sleep); elapsed={elapsed:?}"
    );
}

/// Constructed-status decision table for [`classify_child_crash`] — pure over
/// its inputs (no process scheduling), using `ExitStatus::from_raw`.
#[cfg(unix)]
#[test]
fn classify_child_crash_decision_table() {
    use bounded_child_runner::*;
    use std::os::unix::process::ExitStatusExt;
    use std::process::ExitStatus;

    let sigabrt = ExitStatus::from_raw(EXPECTED_ABORT_SIGNAL);
    // (a) SIGABRT + marker + complete capture ⇒ accepted.
    assert_eq!(
        classify_child_crash(sigabrt, true, &CaptureOutcome::Complete, EXPECTED_ABORT_SIGNAL),
        ChildCrashClass::AbortedAfterMarker {
            signal: EXPECTED_ABORT_SIGNAL
        }
    );
    // (b) SIGABRT but marker absent ⇒ rejected.
    assert_eq!(
        classify_child_crash(sigabrt, false, &CaptureOutcome::Complete, EXPECTED_ABORT_SIGNAL),
        ChildCrashClass::SignalButMarkerUnusable {
            signal: EXPECTED_ABORT_SIGNAL
        }
    );
    // (c) SIGABRT + marker but TRUNCATED capture ⇒ rejected (unusable capture).
    assert_eq!(
        classify_child_crash(
            sigabrt,
            true,
            &CaptureOutcome::Truncated { dropped: 1 },
            EXPECTED_ABORT_SIGNAL
        ),
        ChildCrashClass::SignalButMarkerUnusable {
            signal: EXPECTED_ABORT_SIGNAL
        }
    );
    // (d) A different terminating signal (SIGTERM=15) ⇒ rejected.
    let sigterm = ExitStatus::from_raw(15);
    assert_eq!(
        classify_child_crash(sigterm, true, &CaptureOutcome::Complete, EXPECTED_ABORT_SIGNAL),
        ChildCrashClass::UnexpectedSignal { signal: 15 }
    );
    // (e) A normal nonzero exit (code 7, no signal) ⇒ rejected even with marker.
    let exit7 = ExitStatus::from_raw(7 << 8);
    assert_eq!(exit7.code(), Some(7));
    assert_eq!(exit7.signal(), None);
    assert_eq!(
        classify_child_crash(exit7, true, &CaptureOutcome::Complete, EXPECTED_ABORT_SIGNAL),
        ChildCrashClass::NormalExit { code: Some(7) }
    );
}