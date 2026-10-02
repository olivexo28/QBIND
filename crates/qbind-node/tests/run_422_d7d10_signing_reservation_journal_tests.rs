//! RUN 422 D7-D10 — Real-storage recovery evidence for the local
//! signing-reservation journal.
//!
//! These are the D10 storage/recovery integration cases required by
//! `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`.
//! They exercise the journal over a *real* `RocksDbConsensusStorage` backend
//! (durable `set_sync(true)` writes) using genuine close/reopen controls, plus
//! a child-process death/reopen case using test-only self re-exec
//! orchestration. The child runner is a `#[cfg(unix)]` deadline-bounded,
//! termination-classified runner: it waits for the child with repeated
//! `try_wait` process-status polling under an internal deadline, bounds
//! subsequent output draining and cleanup with separate finite budgets
//! (deadline-aware non-blocking pipe drains + `try_wait`-based reaping), and
//! only accepts an expected SIGABRT when the readiness marker was captured
//! completely.
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
    // The abort precedes any signer invocation or result publication. A marker
    // write/flush FAILURE must fail the helper (nonzero/panic exit, no SIGABRT),
    // never be silently discarded so the parent sees a marker-less abort.
    {
        use std::io::Write as _;
        let mut err = std::io::stderr();
        writeln!(err, "{}", CHILD_RESERVED_MARKER).expect("child must emit readiness marker");
        err.flush().expect("child must flush readiness marker before abort");
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
    use std::os::unix::io::{AsRawFd, RawFd};
    use std::os::unix::process::ExitStatusExt;
    use std::process::{Child, Command, ExitStatus, Stdio};
    use std::sync::{Arc, Mutex, MutexGuard};
    use std::thread::{self, JoinHandle};
    use std::time::{Duration, Instant};

    /// SIGABRT. `std::process::abort()` raises this on Unix; `std` has no
    /// constant, and 6 is the POSIX-fixed value.
    pub(super) const EXPECTED_ABORT_SIGNAL: i32 = 6;

    const CAPTURE_CAP_BYTES: usize = 256 * 1024;

    // ---- Overall deadline policy (honest statement) --------------------------
    // The process-status wait (`wait_self_termination`) bounds how long we wait
    // for the child to die ON ITS OWN. Two SEPARATE finite budgets then bound the
    // work that follows it, so NO blocking boundary is unbounded:
    //
    //   * CAPTURE_FINALIZE_BUDGET bounds output draining. Draining is deadline
    //     aware (non-blocking pipe reads + an armed stop deadline), so a drain
    //     thread can never block indefinitely on a descendant that inherited the
    //     pipe after the direct child exited — it stops and the join completes.
    //   * REAP_BUDGET bounds termination + reaping via `try_wait` polling (never
    //     a blocking `Child::wait()` on a potentially live child).
    //
    // Overall wall-clock bound for one runner call ≈ status deadline
    // + REAP_BUDGET (timeout path only) + CAPTURE_FINALIZE_BUDGET. These are hard
    // budgets on a cooperating Unix kernel; they are NOT a proof the kernel will
    // always complete termination. Inability to verify reaping within the budget
    // is surfaced as an explicit cleanup failure (see `CleanupResult`), never as a
    // success claim.
    pub(super) const CAPTURE_FINALIZE_BUDGET: Duration = Duration::from_secs(5);
    pub(super) const REAP_BUDGET: Duration = Duration::from_secs(5);
    const DRAIN_POLL_STEP: Duration = Duration::from_millis(5);
    const REAP_POLL_STEP: Duration = Duration::from_millis(10);

    /// A shared, one-shot "stop draining by" deadline. Drain threads normally run
    /// until EOF (so pipe pressure can never deadlock the live child); once the
    /// parent is finalizing capture it ARMS this deadline, and a drain thread
    /// checks it on EVERY loop iteration (not only on `WouldBlock`). A thread that
    /// is still seeing successful reads, repeated `Interrupted` retries, or
    /// `WouldBlock` (a descendant is holding the pipe open) therefore stops at the
    /// deadline instead of draining forever. This is the mechanism that makes the
    /// join in `finalize_drains` bounded — joining is NOT itself a deadline.
    #[derive(Default)]
    struct DrainDeadline {
        at: Mutex<Option<Instant>>,
    }

    impl DrainDeadline {
        fn arm(&self, when: Instant) {
            let mut g = self.at.lock().unwrap_or_else(|p| p.into_inner());
            if g.is_none() {
                *g = Some(when);
            }
        }
        fn expired(&self) -> bool {
            let g = self.at.lock().unwrap_or_else(|p| p.into_inner());
            matches!(*g, Some(t) if Instant::now() >= t)
        }
    }

    /// Put a raw fd into non-blocking mode so the drain loop can poll it and
    /// honour the stop deadline rather than blocking inside `read(2)`.
    fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
        // SAFETY: `fd` is the pipe fd owned by the `ChildStdout`/`ChildStderr`
        // handle the calling thread moved in; we only read/alter its O_NONBLOCK
        // flag and never close or duplicate it here.
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let rc = unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// How a drain thread stopped. `DeadlineReached` is a deliberate, explicit
    /// stop (the stream never reached EOF before the armed deadline), NOT a
    /// silent abandonment — the thread returns and is joined.
    enum DrainTerminal {
        Eof,
        DeadlineReached,
        ReadFailed(String),
    }

    #[derive(Default)]
    struct CapturedStream {
        buf: String,
        dropped: usize,
        terminal: Option<DrainTerminal>,
    }

    fn lock_recover(m: &Mutex<CapturedStream>) -> MutexGuard<'_, CapturedStream> {
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    /// Deadline-aware drain loop. The stream fd is made non-blocking; the armed
    /// stop deadline is checked on EVERY iteration, independent of the outcome of
    /// `read()`, so the loop always terminates and is joinable:
    ///
    ///   * continuous successful reads (`Ok(n)`) cannot postpone or reset it;
    ///   * repeated `Interrupted` retries cannot bypass it;
    ///   * output that keeps arriving after the capture cap is reached still stops
    ///     at the deadline (the cap drops bytes, it does not end the loop).
    ///
    /// A capture-size cap bounds MEMORY only — it is NOT a timing mechanism; the
    /// armed deadline is the sole timing bound, and it makes the drain worker
    /// return under the documented scheduling/kernel assumptions WITHOUT relying
    /// on EOF or an eventual `WouldBlock`.
    fn drain_into(
        mut r: impl Read + AsRawFd,
        sink: Arc<Mutex<CapturedStream>>,
        deadline: Arc<DrainDeadline>,
    ) {
        let terminal = run_drain(&mut r, &sink, &deadline);
        lock_recover(&sink).terminal = Some(terminal);
    }

    fn run_drain(
        r: &mut (impl Read + AsRawFd),
        sink: &Mutex<CapturedStream>,
        deadline: &DrainDeadline,
    ) -> DrainTerminal {
        if let Err(e) = set_nonblocking(r.as_raw_fd()) {
            return DrainTerminal::ReadFailed(format!("set_nonblocking failed: {}", e.kind()));
        }
        let mut chunk = [0u8; 8192];
        loop {
            // Enforce the armed stop deadline on EVERY iteration, BEFORE the next
            // read and regardless of the previous read's outcome. This is what
            // makes expiry independent of `read()`: continuous successful reads
            // and repeated `Interrupted` retries both return here and cannot
            // bypass an armed, expired deadline. The capture cap below bounds
            // memory only; it is not a timing mechanism.
            if deadline.expired() {
                break DrainTerminal::DeadlineReached;
            }
            match r.read(&mut chunk) {
                Ok(0) => break DrainTerminal::Eof,
                Ok(n) => {
                    let text = String::from_utf8_lossy(&chunk[..n]);
                    let mut g = lock_recover(sink);
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
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    // No separate expiry check is needed here: the top-of-loop
                    // check already owns the deadline. Just back off briefly so a
                    // descendant-held idle pipe is polled rather than busy-spun.
                    thread::sleep(DRAIN_POLL_STEP);
                }
                Err(e) => break DrainTerminal::ReadFailed(format!("read error kind={:?}", e.kind())),
            }
        }
    }

    /// Completed capture integrity for the drained stderr stream, resolvable
    /// only AFTER the drain thread is joined. A missing-marker/absence claim —
    /// or a present-marker claim — may only rest on [`CaptureOutcome::Complete`].
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(super) enum CaptureOutcome {
        Complete,
        Truncated { dropped: usize },
        ReadFailed { detail: String },
        /// The drain stop deadline fired before the stream reached EOF (e.g. a
        /// descendant kept the pipe open after the direct child exited). An
        /// UNUSABLE capture — it cannot support a marker present/absent claim.
        DeadlineExceeded,
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
        match &s.terminal {
            None => CaptureOutcome::StillDraining,
            Some(DrainTerminal::ReadFailed(d)) => CaptureOutcome::ReadFailed { detail: d.clone() },
            Some(DrainTerminal::DeadlineReached) => CaptureOutcome::DeadlineExceeded,
            Some(DrainTerminal::Eof) => {
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
        /// Shared stop-deadline both drain threads observe; armed by
        /// `finalize_drains` so a join can never wait on an indefinitely blocked
        /// drain.
        drain_deadline: Arc<DrainDeadline>,
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
            let drain_deadline = Arc::new(DrainDeadline::default());
            let ed = drain_deadline.clone();
            let od = drain_deadline.clone();
            let stderr_thread = Some(thread::spawn(move || drain_into(e, se, ed)));
            let stdout_thread = Some(thread::spawn(move || drain_into(o, stdout, od)));
            BoundedChild {
                child,
                stderr,
                stderr_thread,
                stdout_thread,
                drain_deadline,
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

        /// Finalize output draining within `budget`. Arms the shared stop
        /// deadline FIRST (so any drain thread still blocked only by a
        /// descendant-held pipe stops at the deadline rather than forever), then
        /// joins both drain threads. Because the threads self-terminate at the
        /// armed deadline, these joins are bounded — joining is not itself a
        /// deadline, the armed stop is. A child's exit alone does NOT establish
        /// capture completion; only the joined `terminal` does.
        fn finalize_drains(&mut self, budget: Duration) {
            self.drain_deadline.arm(Instant::now() + budget);
            if let Some(h) = self.stderr_thread.take() {
                if h.join().is_err() {
                    self.stderr_join_failed = true;
                }
            }
            if let Some(h) = self.stdout_thread.take() {
                // stdout is not asserted on, but it must still be joined so a
                // large/held-open stdout can never leave a drain thread blocked.
                let _ = h.join();
            }
        }

        /// Explicit, deadline-bounded cleanup. Requests termination and verifies
        /// reaping via `try_wait` polling within `reap_budget` (NEVER a blocking
        /// `Child::wait()` on a potentially live child), then finalizes draining
        /// within `capture_budget`. Returns the structured [`CleanupResult`];
        /// `reaped` is set ONLY on an observation that establishes reaping, so a
        /// failed cleanup leaves `reaped=false` and is reported as such (it is
        /// never silently described as "killed and reaped").
        pub(super) fn kill_and_reap(
            &mut self,
            reap_budget: Duration,
            capture_budget: Duration,
        ) -> CleanupResult {
            let result = {
                let mut ops = ChildCleanupOps {
                    child: &mut self.child,
                };
                drive_cleanup(self.reaped, &mut ops, reap_budget, REAP_POLL_STEP)
            };
            if matches!(
                result,
                CleanupResult::AlreadyReaped | CleanupResult::KilledAndReaped
            ) {
                self.reaped = true;
            }
            self.finalize_drains(capture_budget);
            result
        }

        /// Wait for the child to terminate ON ITS OWN within `deadline` via
        /// repeated process-status polling (`try_wait`, NOT a fixed sleep
        /// guessing the child has exited). On natural exit the FULL `ExitStatus`
        /// (signal preserved) is returned with drained+joined, deadline-bounded
        /// capture. A deadline is a hard failure: the child is killed/reaped
        /// within the cleanup budget and `Timeout` carries the CONCRETE cleanup
        /// result + capture outcome — NEVER reinterpreted as a crash, and never
        /// claiming reaping the observations do not support. `try_wait` errors are
        /// handled explicitly (bounded kill+reap, then panic).
        pub(super) fn wait_self_termination(&mut self, deadline: Duration) -> SelfTermination {
            let start = Instant::now();
            loop {
                match self.child.try_wait() {
                    Ok(Some(status)) => {
                        self.reaped = true;
                        self.finalize_drains(CAPTURE_FINALIZE_BUDGET);
                        return SelfTermination::Exited {
                            status,
                            stderr: self.stderr_snapshot(),
                            capture: self.stderr_capture(),
                        };
                    }
                    Ok(None) => {
                        if start.elapsed() >= deadline {
                            let cleanup = self.kill_and_reap(REAP_BUDGET, CAPTURE_FINALIZE_BUDGET);
                            return SelfTermination::Timeout {
                                stderr: self.stderr_snapshot(),
                                cleanup,
                                capture: self.stderr_capture(),
                            };
                        }
                        thread::sleep(Duration::from_millis(20));
                    }
                    Err(e) => {
                        let _ = self.kill_and_reap(REAP_BUDGET, CAPTURE_FINALIZE_BUDGET);
                        panic!("TEST FAILURE: try_wait errored while waiting for child: {e}");
                    }
                }
            }
        }
    }

    impl Drop for BoundedChild {
        fn drop(&mut self) {
            // Best-effort, non-panicking, and already deadline-bounded: no
            // unconditional blocking work is reintroduced after the explicit
            // deadline path returned.
            let _ = self.kill_and_reap(REAP_BUDGET, CAPTURE_FINALIZE_BUDGET);
        }
    }

    /// Observable, inspectable termination/reaping operations behind a seam so
    /// the cleanup decision ([`drive_cleanup`]) can be exercised with injected
    /// error/expiry paths without a real child (see the Correction B seam tests).
    pub(super) trait ChildCleanup {
        /// Request termination of the child (e.g. SIGKILL).
        fn request_termination(&mut self) -> Result<(), String>;
        /// Observe reaping status WITHOUT blocking: `Ok(true)` = reaped,
        /// `Ok(false)` = still running, `Err` = status observation failed.
        fn poll_reaped(&mut self) -> Result<bool, String>;
    }

    struct ChildCleanupOps<'a> {
        child: &'a mut Child,
    }

    impl ChildCleanup for ChildCleanupOps<'_> {
        fn request_termination(&mut self) -> Result<(), String> {
            self.child.kill().map_err(|e| e.to_string())
        }
        fn poll_reaped(&mut self) -> Result<bool, String> {
            match self.child.try_wait() {
                Ok(Some(_status)) => Ok(true),
                Ok(None) => Ok(false),
                Err(e) => Err(e.to_string()),
            }
        }
    }

    /// Structured, inspectable cleanup outcome. `reaped=true` may be claimed ONLY
    /// for the two reaped variants; the failure variants carry the evidence and
    /// are never collapsed into a success/crash result.
    #[derive(Debug, PartialEq, Eq)]
    pub(super) enum CleanupResult {
        /// The child had already exited and been reaped before cleanup ran.
        AlreadyReaped,
        /// Termination was requested AND subsequent reaping was verified by an
        /// explicit status observation. (Covers the exit-vs-kill race: a kill
        /// error whose child is then observed reaped is still verified reaping.)
        KilledAndReaped,
        /// The termination request itself failed and reaping could not be
        /// verified within the budget.
        TerminationRequestFailed { detail: String },
        /// A status/reap observation errored.
        ReapObservationFailed { detail: String },
        /// The cleanup budget expired without a verified reaping observation.
        DeadlineExpired,
    }

    /// Pure cleanup driver over the [`ChildCleanup`] seam. Marks reaping ONLY on
    /// an `Ok(true)` observation; on expiry it distinguishes a prior failed
    /// termination request from a plain deadline, and a status-observation error
    /// is surfaced distinctly. A kill error is NEVER silently treated as success:
    /// it only yields `KilledAndReaped` if reaping is independently observed.
    pub(super) fn drive_cleanup(
        already_reaped: bool,
        ops: &mut impl ChildCleanup,
        budget: Duration,
        poll_step: Duration,
    ) -> CleanupResult {
        if already_reaped {
            return CleanupResult::AlreadyReaped;
        }
        let termination = ops.request_termination();
        let start = Instant::now();
        loop {
            match ops.poll_reaped() {
                Ok(true) => return CleanupResult::KilledAndReaped,
                Ok(false) => {
                    if start.elapsed() >= budget {
                        return match termination {
                            Err(detail) => CleanupResult::TerminationRequestFailed { detail },
                            Ok(()) => CleanupResult::DeadlineExpired,
                        };
                    }
                    thread::sleep(poll_step);
                }
                Err(detail) => return CleanupResult::ReapObservationFailed { detail },
            }
        }
    }

    /// Result of a bounded self-termination wait. `Timeout` is a failure
    /// condition (the child did not die on its own in time); it carries the
    /// CONCRETE [`CleanupResult`] and capture outcome rather than an implicit
    /// "killed and reaped" claim.
    #[derive(Debug)]
    pub(super) enum SelfTermination {
        Exited {
            status: ExitStatus,
            stderr: String,
            capture: CaptureOutcome,
        },
        Timeout {
            stderr: String,
            cleanup: CleanupResult,
            capture: CaptureOutcome,
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

    /// Spawn `direct` with its stdout+stderr wired to TEST-OWNED pipes that are
    /// ALSO inherited by a separately spawned `holder` process, which keeps those
    /// write ends open after the direct child exits. The drained streams then
    /// never reach EOF until the holder is terminated — exercising the armed-
    /// deadline drain bound against a pipe held open past direct-child death.
    ///
    /// Unlike a backgrounded descendant orphaned to init, the returned
    /// [`OwnedHolder`] is a child THIS TEST owns: its cleanup guard is installed
    /// immediately (its `Drop` protects assertion unwinds), and the normal path
    /// verifies bounded kill+reap via [`OwnedHolder::verify_cleanup`] instead of
    /// assuming init reaps an orphan. The direct child's own abort is observed
    /// independently of the holder. No process group, subreaper, or process-global
    /// signal handler is used, so parallel tests are unaffected.
    impl BoundedChild {
        pub(super) fn spawn_with_pipe_holder(
            mut direct: Command,
            mut holder: Command,
            ctx: &'static str,
        ) -> (Self, OwnedHolder) {
            // TEST-OWNED pipes: the parent builds them, hands the read ends to the
            // drain threads, and hands cloned write ends to BOTH children.
            let (out_r, out_w) = std::io::pipe()
                .unwrap_or_else(|e| panic!("TEST FAILURE: {ctx}: stdout pipe: {e}"));
            let (err_r, err_w) = std::io::pipe()
                .unwrap_or_else(|e| panic!("TEST FAILURE: {ctx}: stderr pipe: {e}"));
            let dup = |w: &std::io::PipeWriter, which: &str| -> Stdio {
                Stdio::from(
                    w.try_clone()
                        .unwrap_or_else(|e| panic!("TEST FAILURE: {ctx}: dup {which}: {e}")),
                )
            };

            direct
                .stdin(Stdio::null())
                .stdout(dup(&out_w, "direct stdout"))
                .stderr(dup(&err_w, "direct stderr"));
            holder
                .stdin(Stdio::null())
                .stdout(dup(&out_w, "holder stdout"))
                .stderr(dup(&err_w, "holder stderr"));

            let child = direct
                .spawn()
                .unwrap_or_else(|e| panic!("TEST FAILURE: {ctx}: spawn direct child: {e}"));
            // Install the holder's cleanup guard IMMEDIATELY after creating it and
            // BEFORE any fallible observation below: `owned`'s `Drop` now protects
            // every later panic/unwind (including a panic inside this constructor).
            let holder_child = holder
                .spawn()
                .unwrap_or_else(|e| panic!("TEST FAILURE: {ctx}: spawn pipe holder: {e}"));
            let owned = OwnedHolder::new(holder_child);

            // The parent keeps NO write end open (only the two children do), so EOF
            // arrives promptly once BOTH children have released the pipe.
            drop(out_w);
            drop(err_w);

            let stderr = Arc::new(Mutex::new(CapturedStream::default()));
            let stdout = Arc::new(Mutex::new(CapturedStream::default()));
            let drain_deadline = Arc::new(DrainDeadline::default());
            let ed = drain_deadline.clone();
            let od = drain_deadline.clone();
            let se = stderr.clone();
            let stderr_thread = Some(thread::spawn(move || drain_into(err_r, se, ed)));
            let stdout_thread = Some(thread::spawn(move || drain_into(out_r, stdout, od)));
            (
                BoundedChild {
                    child,
                    stderr,
                    stderr_thread,
                    stdout_thread,
                    drain_deadline,
                    stderr_join_failed: false,
                    reaped: false,
                },
                owned,
            )
        }
    }

    /// A pipe-holder child whose lifetime THIS TEST owns. The cleanup guard is
    /// installed at construction: `Drop` performs a best-effort, non-panicking,
    /// bounded kill+reap so an assertion unwind cannot leak it. The normal path
    /// must additionally call [`OwnedHolder::verify_cleanup`], which returns the
    /// structured [`CleanupResult`] — it never discards the kill error and never
    /// claims reaping merely because a signal was sent, so a cleanup failure is
    /// REPORTED rather than assumed. (Best-effort `Drop` is a fallback; it does
    /// NOT replace the normal-path verification.)
    pub(super) struct OwnedHolder {
        child: Child,
        reaped: bool,
    }

    impl OwnedHolder {
        fn new(child: Child) -> Self {
            OwnedHolder {
                child,
                reaped: false,
            }
        }

        /// Spawn a STANDALONE test-owned holder process (all stdio nulled) with
        /// its cleanup guard installed at construction. Used by the unwind control
        /// to show the guard runs during an assertion unwind, independent of the
        /// shared-pipe constructor.
        pub(super) fn spawn(mut command: Command, ctx: &'static str) -> Self {
            let child = command
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap_or_else(|e| panic!("TEST FAILURE: {ctx}: spawn owned holder: {e}"));
            OwnedHolder::new(child)
        }

        /// Terminate the owned holder and VERIFY reaping via bounded `try_wait`
        /// polling within `reap_budget` (NEVER a blocking `wait()`). Reuses the
        /// pure [`drive_cleanup`] driver, so `reaped` is set ONLY on an observed
        /// status: a kill error followed by an observed reap is still verified
        /// reaping (the exit-vs-kill race), while a kill error with no reaping is
        /// reported as `TerminationRequestFailed`, not a false success.
        pub(super) fn verify_cleanup(&mut self, reap_budget: Duration) -> CleanupResult {
            let result = {
                let mut ops = ChildCleanupOps {
                    child: &mut self.child,
                };
                drive_cleanup(self.reaped, &mut ops, reap_budget, REAP_POLL_STEP)
            };
            if matches!(
                result,
                CleanupResult::AlreadyReaped | CleanupResult::KilledAndReaped
            ) {
                self.reaped = true;
            }
            result
        }

        /// The holder's PID (for independent liveness/ESRCH observation in the
        /// unwind-guard control).
        pub(super) fn holder_pid(&self) -> u32 {
            self.child.id()
        }
    }

    impl Drop for OwnedHolder {
        fn drop(&mut self) {
            // Best-effort unwind protection: bounded, non-panicking kill+reap. It
            // does NOT substitute for the normal-path `verify_cleanup` assertion.
            if !self.reaped {
                let _ = self.verify_cleanup(REAP_BUDGET);
            }
        }
    }

    // ------------------------------------------------------------------------
    // Correction A — deterministic reader-seam controls (NO real process).
    //
    // These drive the ACTUAL `run_drain` loop logic with synthetic `Read`
    // fixtures to prove the armed deadline is enforced on EVERY iteration,
    // independent of the read outcome. Each fixture is bounded INDEPENDENTLY of
    // the runner deadline (its own `fixture_cap`): a regression that ignored the
    // deadline reaches that cap and reports EOF — a DIFFERENT terminal — so the
    // assertion fails WITHOUT the test hanging. A real fd (`/dev/null`) only
    // satisfies `run_drain`'s `set_nonblocking`; the synthetic `read()` drives
    // the loop.
    // ------------------------------------------------------------------------

    /// A: continuous successful reads cannot bypass an armed, expired deadline.
    #[cfg(unix)]
    #[test]
    fn drain_deadline_enforced_across_continuous_successful_reads() {
        use std::fs::File;
        use std::io::Read;

        struct AlwaysOk {
            fd: File,
            calls: usize,
            arm_at: usize,
            fixture_cap: usize,
            deadline: Arc<DrainDeadline>,
        }
        impl Read for AlwaysOk {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                // Independent fixture bound: a regression that never checks the
                // deadline stops HERE (as EOF), so the test fails fast, not hangs.
                if self.calls > self.fixture_cap {
                    return Ok(0);
                }
                // Arm the runner deadline (already expired) after a few real
                // successful reads: reads before expiry are fine, but once it is
                // armed+expired the loop must stop at the next iteration.
                if self.calls == self.arm_at {
                    self.deadline.arm(Instant::now());
                }
                let n = buf.len().min(64);
                for b in &mut buf[..n] {
                    *b = b'x';
                }
                Ok(n)
            }
        }
        impl AsRawFd for AlwaysOk {
            fn as_raw_fd(&self) -> RawFd {
                self.fd.as_raw_fd()
            }
        }

        const ARM_AT: usize = 3;
        const FIXTURE_CAP: usize = 10_000; // >> ARM_AT; bounds a regression's spin.
        let deadline = Arc::new(DrainDeadline::default());
        let mut reader = AlwaysOk {
            fd: File::open("/dev/null").expect("open /dev/null for a real fd"),
            calls: 0,
            arm_at: ARM_AT,
            fixture_cap: FIXTURE_CAP,
            deadline: deadline.clone(),
        };
        let sink = Mutex::new(CapturedStream::default());
        let terminal = run_drain(&mut reader, &sink, &deadline);

        assert!(
            matches!(terminal, DrainTerminal::DeadlineReached),
            "continuous successful reads must stop at the armed deadline, not run to the \
             fixture's EOF cap (a non-DeadlineReached terminal ⇒ the loop ignored expiry)"
        );
        // Stopped at the first iteration after expiry was armed, NOT at the
        // fixture cap — the runner deadline is distinct from the fixture bound.
        assert_eq!(
            reader.calls, ARM_AT,
            "the drain must stop at the first iteration after expiry was armed; calls={} \
             (fixture cap={FIXTURE_CAP})",
            reader.calls
        );
    }

    /// B: repeated `Interrupted` retries cannot bypass an armed, expired deadline.
    #[cfg(unix)]
    #[test]
    fn drain_deadline_enforced_across_repeated_interrupted_reads() {
        use std::fs::File;
        use std::io::{Error, ErrorKind, Read};

        struct AlwaysInterrupted {
            fd: File,
            calls: usize,
            arm_at: usize,
            fixture_cap: usize,
            deadline: Arc<DrainDeadline>,
        }
        impl Read for AlwaysInterrupted {
            fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
                self.calls += 1;
                if self.calls > self.fixture_cap {
                    // Regression fallback: EOF ⇒ a failed assertion, never a hang.
                    return Ok(0);
                }
                if self.calls == self.arm_at {
                    self.deadline.arm(Instant::now());
                }
                Err(Error::from(ErrorKind::Interrupted))
            }
        }
        impl AsRawFd for AlwaysInterrupted {
            fn as_raw_fd(&self) -> RawFd {
                self.fd.as_raw_fd()
            }
        }

        const ARM_AT: usize = 4;
        const FIXTURE_CAP: usize = 10_000;
        let deadline = Arc::new(DrainDeadline::default());
        let mut reader = AlwaysInterrupted {
            fd: File::open("/dev/null").expect("open /dev/null for a real fd"),
            calls: 0,
            arm_at: ARM_AT,
            fixture_cap: FIXTURE_CAP,
            deadline: deadline.clone(),
        };
        let sink = Mutex::new(CapturedStream::default());
        let terminal = run_drain(&mut reader, &sink, &deadline);

        assert!(
            matches!(terminal, DrainTerminal::DeadlineReached),
            "repeated Interrupted retries must stop at the armed deadline, not spin until the \
             fixture EOF cap (a non-DeadlineReached terminal ⇒ Interrupted bypassed expiry)"
        );
        assert_eq!(
            reader.calls, ARM_AT,
            "the drain must stop at the first iteration after expiry was armed; calls={} \
             (fixture cap={FIXTURE_CAP})",
            reader.calls
        );
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
        SelfTermination::Timeout { stderr, .. } => panic!(
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
        SelfTermination::Timeout { stderr, .. } => {
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
        SelfTermination::Timeout { stderr, .. } => {
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
        SelfTermination::Timeout { stderr, .. } => {
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
        SelfTermination::Timeout { stderr, .. } => {
            panic!("control child should have aborted promptly; stderr=\n{stderr}")
        }
    }
}

/// A child that stays alive past the internal deadline yields a TIMEOUT failure
/// whose CONCRETE cleanup result is verified reaping (`KilledAndReaped`) with a
/// bounded capture, and the runner returns within a generous outer bound. The
/// elapsed-time bound is CORROBORATION that cleanup did not wait on the surviving
/// process; the asserted mechanism enforcing the deadline is the structured
/// cleanup result, not the clock.
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
        SelfTermination::Timeout { cleanup, capture, .. } => {
            // The timeout directly establishes verified reaping — not merely a
            // `Timeout` tag plus a short elapsed time.
            assert_eq!(
                cleanup,
                CleanupResult::KilledAndReaped,
                "a timeout must verify reaping, not assume it; cleanup={cleanup:?}"
            );
            // Killing the sole pipe holder closes the pipe, so draining
            // completes within budget (no descendant keeps it open).
            assert!(
                matches!(capture, CaptureOutcome::Complete | CaptureOutcome::Truncated { .. }),
                "cleanup draining must complete within budget, got {capture:?}"
            );
        }
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

// ============================================================================
// Run 422 D7-D10 Correction F-B (repaired boundaries) — focused evidence.
// ============================================================================

/// Focused control C — REAL active-output capture. A test-OWNED writer keeps
/// output arriving on the captured stream AFTER the direct child exits, so the
/// corrected runner's every-iteration deadline (Correction A) is the enforcement
/// mechanism even under continuous successful reads.
///
/// A real `sh` direct child emits the readiness marker to stderr then SIGABRTs.
/// A SEPARATE, test-owned `holder` process (NOT a backgrounded orphan) shares the
/// same stderr pipe and writes to it continuously; the stream therefore never
/// reaches EOF within the capture-finalize budget. Requirements demonstrated:
///   * the runner returns within its declared capture policy (its join is bounded
///     by the armed drain deadline under continuous output, not by the writer);
///   * the capture is classified UNUSABLE (`DeadlineExceeded`);
///   * the incomplete capture is NOT accepted as `AbortedAfterMarker` even though
///     the signal is SIGABRT;
///   * the test-owned writer's cleanup is EXPLICITLY verified (`KilledAndReaped`),
///     not assumed or left to init.
///
/// Runner-resource evidence, NOT journal recovery. Timing is corroboration; the
/// drain-loop deadline is the enforcement mechanism.
#[cfg(unix)]
#[test]
fn runner_active_output_after_direct_child_exit_is_unusable_and_writer_reaped() {
    use bounded_child_runner::*;
    use std::time::{Duration, Instant};

    const STATUS_DEADLINE: Duration = Duration::from_secs(60);
    const OUTER_BOUND: Duration = Duration::from_secs(20);

    // Direct child: marker to stderr, then self-abort (no backgrounding).
    let direct = sh_control_command(&format!(
        "printf '%s\\n' '{CHILD_RESERVED_MARKER}' 1>&2; kill -s ABRT $$"
    ));
    // Test-owned ACTIVE writer: a POSIX sh loop (no external binary) that keeps
    // writing to the SHARED stderr pipe, so the captured stream stays active past
    // the direct child's exit — exercising continuous successful reads.
    let holder = sh_control_command("while :; do printf 'yyyy\\n' 1>&2; done");

    let (mut child, mut writer) =
        BoundedChild::spawn_with_pipe_holder(direct, holder, "spawn active-output held-pipe control");

    let start = Instant::now();
    let outcome = child.wait_self_termination(STATUS_DEADLINE);
    let elapsed = start.elapsed();

    // (1) The join did NOT block on the active writer.
    assert!(
        elapsed < OUTER_BOUND,
        "runner must return within the capture policy under continuous output, not block on the \
         writer; elapsed={elapsed:?}"
    );

    match outcome {
        SelfTermination::Exited {
            status,
            stderr,
            capture,
        } => {
            // (2) Continuous output ⇒ never EOF ⇒ explicitly unusable.
            assert_eq!(
                capture,
                CaptureOutcome::DeadlineExceeded,
                "an active writer kept the stream open ⇒ capture is unusable (DeadlineExceeded), \
                 got {capture:?}"
            );
            // (3) The incomplete capture is NOT accepted as AbortedAfterMarker,
            // despite the SIGABRT (marker presence is irrelevant once the capture
            // is not Complete).
            let marker = stderr.contains(CHILD_RESERVED_MARKER);
            assert_eq!(
                classify_child_crash(status, marker, &capture, EXPECTED_ABORT_SIGNAL),
                ChildCrashClass::SignalButMarkerUnusable {
                    signal: EXPECTED_ABORT_SIGNAL
                },
                "an incomplete (active) capture cannot establish reservation-before-abort"
            );
        }
        SelfTermination::Timeout {
            cleanup,
            capture,
            stderr,
        } => panic!(
            "the direct child aborts promptly; expected Exited(SIGABRT), got Timeout \
             cleanup={cleanup:?} capture={capture:?} stderr=\n{stderr}"
        ),
    }

    // (4) NORMAL-PATH cleanup of the test-owned writer is EXPLICITLY verified and
    // its result reported — not discarded, and not left to init.
    let cleanup = writer.verify_cleanup(REAP_BUDGET);
    assert_eq!(
        cleanup,
        CleanupResult::KilledAndReaped,
        "the test-owned active writer must be explicitly killed+reaped on the normal path, got \
         {cleanup:?}"
    );
}

/// Focused control D — REAL idle held-pipe capture + owned-helper cleanup. A
/// test-OWNED idle holder keeps the pipe open (no output) past the direct child's
/// marker-then-SIGABRT, so the captured stream never reaches EOF and the drain
/// stops at the armed deadline via the `WouldBlock` poll path. Requirements:
///   * the runner returns within its capture policy (bounded join, not a block);
///   * the capture is UNUSABLE (`DeadlineExceeded`) even though the marker bytes
///     arrived and the signal is SIGABRT (`SignalButMarkerUnusable`);
///   * the test-owned holder is EXPLICITLY cleaned up (`KilledAndReaped`) on the
///     normal path — no orphan, no reliance on init.
///
/// Runner-resource evidence, NOT journal recovery.
#[cfg(unix)]
#[test]
fn runner_idle_held_pipe_after_direct_child_exit_is_unusable_and_holder_reaped() {
    use bounded_child_runner::*;
    use std::time::{Duration, Instant};

    const STATUS_DEADLINE: Duration = Duration::from_secs(60);
    const OUTER_BOUND: Duration = Duration::from_secs(20);

    let direct = sh_control_command(&format!(
        "printf '%s\\n' '{CHILD_RESERVED_MARKER}' 1>&2; kill -s ABRT $$"
    ));
    // Test-owned IDLE holder: replaces the shell so the ONLY thing keeping the
    // shared pipes open is this owned `sleep` (no output of its own).
    let holder = sh_control_command("exec sleep 45");

    let (mut child, mut owned) =
        BoundedChild::spawn_with_pipe_holder(direct, holder, "spawn idle held-pipe control");

    let start = Instant::now();
    let outcome = child.wait_self_termination(STATUS_DEADLINE);
    let elapsed = start.elapsed();

    assert!(
        elapsed < OUTER_BOUND,
        "runner must return within the capture policy, not block on the idle held pipe; \
         elapsed={elapsed:?}"
    );

    match outcome {
        SelfTermination::Exited {
            status,
            stderr,
            capture,
        } => {
            let marker = stderr.contains(CHILD_RESERVED_MARKER);
            // The idle holder adds no bytes, so the marker is retained; the
            // capture is still unusable because EOF never arrived.
            assert!(
                marker,
                "the direct child's marker should be captured before the held-open stall; \
                 stderr=\n{stderr}"
            );
            assert_eq!(
                capture,
                CaptureOutcome::DeadlineExceeded,
                "an idle descendant held the pipe open ⇒ capture is unusable (DeadlineExceeded), \
                 got {capture:?}; stderr=\n{stderr}"
            );
            assert_eq!(
                classify_child_crash(status, marker, &capture, EXPECTED_ABORT_SIGNAL),
                ChildCrashClass::SignalButMarkerUnusable {
                    signal: EXPECTED_ABORT_SIGNAL
                },
                "an incomplete capture cannot establish reservation-before-abort; stderr=\n{stderr}"
            );
        }
        SelfTermination::Timeout {
            cleanup,
            capture,
            stderr,
        } => panic!(
            "the direct child aborts promptly; expected Exited(SIGABRT), got Timeout \
             cleanup={cleanup:?} capture={capture:?} stderr=\n{stderr}"
        ),
    }

    // NORMAL-PATH cleanup of the test-owned holder is EXPLICITLY verified.
    let cleanup = owned.verify_cleanup(REAP_BUDGET);
    assert_eq!(
        cleanup,
        CleanupResult::KilledAndReaped,
        "the test-owned idle holder must be explicitly killed+reaped on the normal path, got \
         {cleanup:?}"
    );
}

/// Focused control — the owned-helper cleanup GUARD is installed immediately and
/// RUNS during an assertion unwind, so an early panic cannot leak the test-owned
/// holder. Demonstrates the Correction-B requirement that cleanup protection is
/// in place BEFORE fallible observations and executes during unwinding.
///
/// Runner-resource evidence, NOT journal recovery.
#[cfg(unix)]
#[test]
fn owned_holder_cleanup_guard_runs_on_unwind() {
    use bounded_child_runner::*;
    use std::time::{Duration, Instant};

    let holder = OwnedHolder::spawn(sh_control_command("exec sleep 45"), "unwind-control holder");
    let pid = holder.holder_pid() as i32;

    // Sanity: the holder is alive before the unwind.
    assert_eq!(
        unsafe { libc::kill(pid, 0) },
        0,
        "the owned holder must be alive before the unwind"
    );

    // Move the holder INTO a closure that panics after installation; the panic
    // unwinds through `holder`'s Drop, which performs the bounded kill+reap. The
    // guard is therefore exercised exactly as it would be on an assertion failure.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _guard = holder; // owned here; its Drop runs on the panic below
        panic!("deliberate early failure to exercise the owned-holder cleanup guard");
    }));
    assert!(result.is_err(), "the closure must have panicked");

    // After the unwind the guard must have killed AND reaped the holder: its PID
    // is no longer a live process (`kill(pid, 0)` → ESRCH). Bounded poll avoids a
    // scheduling race; a leak would keep the PID live until this deadline.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut gone = false;
    while Instant::now() < deadline {
        if unsafe { libc::kill(pid, 0) } == -1 {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        gone,
        "the cleanup guard must kill+reap the owned holder during unwind (pid {pid} still live)"
    );
}

/// Focused control B — SEAM-based cleanup classification. Uses the private
/// [`bounded_child_runner::ChildCleanup`] seam to deterministically exercise the
/// kill/observe/expiry paths of the pure [`bounded_child_runner::drive_cleanup`]
/// driver WITHOUT a real child, proving that a cleanup failure cannot masquerade
/// as verified reaping. Labelled separately from the real-process controls: no
/// process is spawned here.
#[cfg(unix)]
#[test]
fn drive_cleanup_classifies_failures_without_false_reaping() {
    use bounded_child_runner::{drive_cleanup, ChildCleanup, CleanupResult};
    use std::time::Duration;

    /// A scripted `ChildCleanup`: a fixed termination result plus a queue of
    /// `poll_reaped` observations (defaulting to "still alive" once exhausted).
    struct ScriptedCleanup {
        termination: Result<(), String>,
        polls: std::collections::VecDeque<Result<bool, String>>,
    }
    impl ChildCleanup for ScriptedCleanup {
        fn request_termination(&mut self) -> Result<(), String> {
            self.termination.clone()
        }
        fn poll_reaped(&mut self) -> Result<bool, String> {
            self.polls.pop_front().unwrap_or(Ok(false))
        }
    }
    fn ops(
        termination: Result<(), String>,
        polls: Vec<Result<bool, String>>,
    ) -> ScriptedCleanup {
        ScriptedCleanup {
            termination,
            polls: polls.into_iter().collect(),
        }
    }

    // A tiny budget keeps the deadline/failure cases fast and deterministic.
    const BUDGET: Duration = Duration::from_millis(60);
    const STEP: Duration = Duration::from_millis(5);

    // (a) Already reaped before cleanup ran ⇒ AlreadyReaped (no kill attempted).
    assert_eq!(
        drive_cleanup(true, &mut ops(Ok(()), vec![]), BUDGET, STEP),
        CleanupResult::AlreadyReaped
    );

    // (b) Kill ok, reaping then verified ⇒ KilledAndReaped (the only reaped
    //     non-already variant).
    assert_eq!(
        drive_cleanup(
            false,
            &mut ops(Ok(()), vec![Ok(false), Ok(true)]),
            BUDGET,
            STEP
        ),
        CleanupResult::KilledAndReaped
    );

    // (c) Exit-vs-kill race: kill reports an error, but the child is then
    //     observed reaped ⇒ KilledAndReaped (verified, NOT silently assumed).
    assert_eq!(
        drive_cleanup(
            false,
            &mut ops(Err("ESRCH".into()), vec![Ok(true)]),
            BUDGET,
            STEP
        ),
        CleanupResult::KilledAndReaped
    );

    // (d) Kill failed and reaping never verified ⇒ TerminationRequestFailed
    //     (NOT a false reaped=true, NOT a success).
    assert_eq!(
        drive_cleanup(
            false,
            &mut ops(Err("kill boom".into()), vec![Ok(false)]),
            BUDGET,
            STEP
        ),
        CleanupResult::TerminationRequestFailed {
            detail: "kill boom".into()
        }
    );

    // (e) A status/reap observation error ⇒ ReapObservationFailed (distinct;
    //     never collapsed into reaped/crash).
    assert_eq!(
        drive_cleanup(
            false,
            &mut ops(Ok(()), vec![Ok(false), Err("waitpid boom".into())]),
            BUDGET,
            STEP
        ),
        CleanupResult::ReapObservationFailed {
            detail: "waitpid boom".into()
        }
    );

    // (f) Kill ok but the child never reaps within the budget ⇒ DeadlineExpired
    //     (explicit cleanup-deadline expiry, NOT a verified reaping).
    assert_eq!(
        drive_cleanup(false, &mut ops(Ok(()), vec![]), BUDGET, STEP),
        CleanupResult::DeadlineExpired
    );
}