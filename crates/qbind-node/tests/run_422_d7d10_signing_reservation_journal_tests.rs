//! RUN 422 D7-D10 — Real-storage recovery evidence for the local
//! signing-reservation journal.
//!
//! These are the D10 storage/recovery integration cases required by
//! `docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`.
//! They exercise the journal over a *real* `RocksDbConsensusStorage` backend
//! (durable `set_sync(true)` writes) using genuine close/reopen controls, plus
//! a bounded child-process death/reopen case using test-only self re-exec
//! orchestration.
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
    fabricate_reserved_record_bytes_with_version, BindingDigest, JournalError, ReservationOutcome,
    SigningJournalStorage, SigningKind, SigningPosition, SigningReservationJournal,
    SIGNING_RECORD_FORMAT_VERSION,
};
use qbind_node::storage::RocksDbConsensusStorage;

/// Environment variable that switches a single re-executed test binary into the
/// bounded "child" mode used by [`reserved_only_child_death_then_reopen_refuses`].
const CHILD_DB_ENV: &str = "QBIND_D7D10_CHILD_DB";

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
        let journal = SigningReservationJournal::attach(store.clone() as Arc<dyn SigningJournalStorage>);
        // Fresh reservation acknowledged durably; the live operation dies before
        // recording any signed result (we simply drop it here).
        let outcome = journal
            .reserve_for_sign(&pos, &bind)
            .expect("reserve must succeed");
        assert_eq!(outcome, ReservationOutcome::FreshlyReserved);
    }

    // Reopen: fresh journal, empty live-permit map — exactly the crash posture.
    let store = open_store(dir.path());
    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let outcome = journal
        .reserve_for_sign(&pos, &bind)
        .expect("reservation lookup must not error");
    assert_eq!(
        outcome,
        ReservationOutcome::PotentiallySigned,
        "a recovered Reserved record with no live permit must be potentially-signed"
    );

    // A conflicting request at the same position must remain refused, and must
    // not alter the original obligation.
    let conflict = journal
        .reserve_for_sign(&pos, &binding(0xB2))
        .expect("conflict lookup must not error");
    assert_eq!(conflict, ReservationOutcome::Conflict);

    // The original obligation is still potentially-signed after the conflict.
    let again = journal
        .reserve_for_sign(&pos, &bind)
        .expect("re-lookup must not error");
    assert_eq!(again, ReservationOutcome::PotentiallySigned);
}

/// A signed result survives a reopen and supports an exact resend (retained
/// signature reuse), while conflicting content stays refused.
#[test]
fn signed_result_survives_reopen_and_supports_exact_resend() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = vote_position(9);
    let bind = binding(0x33);
    let signature = vec![0xEE, 0xAB, 0xCD, 0x01, 0x02, 0x03];

    {
        let store = open_store(dir.path());
        let journal = SigningReservationJournal::attach(store.clone() as Arc<dyn SigningJournalStorage>);
        assert_eq!(
            journal.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved
        );
        journal.note_signer_invoked(&pos).expect("note signer");
        journal
            .record_signed_result(&pos, &bind, &signature)
            .expect("record signed result durably");
    }

    // Reopen: the signed record must survive and yield an exact-retry retained
    // signature (resend without signing again).
    let store = open_store(dir.path());
    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    match journal.reserve_for_sign(&pos, &bind).expect("lookup") {
        ReservationOutcome::ExactRetryRetained(sig) => assert_eq!(sig, signature),
        other => panic!("expected ExactRetryRetained, got {:?}", other),
    }

    // Conflicting content at the same position stays refused after reopen.
    assert_eq!(
        journal
            .reserve_for_sign(&pos, &binding(0x44))
            .expect("conflict lookup"),
        ReservationOutcome::Conflict
    );
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
        let journal = SigningReservationJournal::attach(store.clone() as Arc<dyn SigningJournalStorage>);
        assert_eq!(
            journal.reserve_for_sign(&prop, &binding(1)).expect("reserve proposal"),
            ReservationOutcome::FreshlyReserved
        );
        assert_eq!(
            journal.reserve_for_sign(&vote, &binding(2)).expect("reserve vote"),
            ReservationOutcome::FreshlyReserved
        );
    }

    let store = open_store(dir.path());
    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    // Both recovered independently as potentially-signed (distinct keys).
    assert_eq!(
        journal.reserve_for_sign(&prop, &binding(1)).expect("lookup proposal"),
        ReservationOutcome::PotentiallySigned
    );
    assert_eq!(
        journal.reserve_for_sign(&vote, &binding(2)).expect("lookup vote"),
        ReservationOutcome::PotentiallySigned
    );
}

/// Corruption of a stored record on reopen must fail closed (no permit).
#[test]
fn corrupt_record_on_reopen_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(3);
    let bind = binding(0x5A);

    {
        let store = open_store(dir.path());
        let journal = SigningReservationJournal::attach(store.clone() as Arc<dyn SigningJournalStorage>);
        assert_eq!(
            journal.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved
        );
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

    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let err = journal
        .reserve_for_sign(&pos, &bind)
        .expect_err("corrupt record must fail closed");
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
        let journal = SigningReservationJournal::attach(store.clone() as Arc<dyn SigningJournalStorage>);
        assert_eq!(
            journal.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved
        );
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

    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let err = journal
        .reserve_for_sign(&pos, &bind)
        .expect_err("truncated record must fail closed");
    assert!(matches!(err, JournalError::Truncated), "got {:?}", err);
}

/// An otherwise well-formed record declaring an unsupported record-format
/// version must fail closed on reopen.
#[test]
fn unknown_version_record_on_reopen_fails_closed() {
    let dir = tempfile::tempdir().expect("tempdir");
    let pos = proposal_position(6);
    let bind = binding(0x5C);

    let store = open_store(dir.path());
    let key = pos.storage_key();
    // Inject a correctly-checksummed record with a bumped format version.
    let injected =
        fabricate_reserved_record_bytes_with_version(&pos, &bind, SIGNING_RECORD_FORMAT_VERSION + 7);
    store
        .put_signing_record_synced(&key, &injected)
        .expect("store unsupported-version record");

    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let err = journal
        .reserve_for_sign(&pos, &bind)
        .expect_err("unsupported version must fail closed");
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
        let journal = SigningReservationJournal::attach(store.clone() as Arc<dyn SigningJournalStorage>);
        assert_eq!(
            journal.reserve_for_sign(&pos, &bind).expect("reserve"),
            ReservationOutcome::FreshlyReserved
        );
        journal.note_signer_invoked(&pos).expect("note signer");
        journal
            .record_signed_result(&pos, &bind, &signature)
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

    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let err = journal
        .reserve_for_sign(&pos, &bind)
        .expect_err("corrupt signed record must fail closed");
    assert!(matches!(err, JournalError::Corruption(_)), "got {:?}", err);
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
    let journal_a = SigningReservationJournal::attach(store.clone() as Arc<dyn SigningJournalStorage>);
    assert_eq!(
        journal_a.reserve_for_sign(&pos, &bind).expect("reserve A"),
        ReservationOutcome::FreshlyReserved
    );

    // A second, independently-attached handle sharing the SAME durable store.
    let journal_b = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let outcome = journal_b
        .reserve_for_sign(&pos, &bind)
        .expect("reserve B lookup");
    assert_eq!(
        outcome,
        ReservationOutcome::PotentiallySigned,
        "a second handle must not manufacture a second live permit from a durable Reserved record"
    );
}

// ---------------------------------------------------------------------------
// Bounded child-process death / reopen.
// ---------------------------------------------------------------------------

/// Child mode: open the real store at `$QBIND_D7D10_CHILD_DB`, durably reserve a
/// fixed Proposal position, then abort BEFORE recording any signed result. This
/// is invoked by re-executing this test binary with the env var set; a normal
/// (unset) run of this `#[ignore]`d test is a harmless no-op.
#[test]
#[ignore = "child-mode helper; only meaningful when re-executed with QBIND_D7D10_CHILD_DB set"]
fn d7d10_child_reserve_then_abort() {
    let Some(db) = std::env::var_os(CHILD_DB_ENV) else {
        // Not in child mode: nothing to do.
        return;
    };
    let path = std::path::PathBuf::from(db);
    let store = open_store(&path);
    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let outcome = journal
        .reserve_for_sign(&child_position(), &child_binding())
        .expect("child reservation must succeed");
    assert_eq!(outcome, ReservationOutcome::FreshlyReserved);
    // Durable reservation acknowledged; simulate crash before signing/recording.
    std::io::Write::flush(&mut std::io::stdout()).ok();
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

/// Bounded child-process death then reopen: spawn this test binary in child
/// mode, let it durably reserve and then abort, then reopen the same store in
/// the parent and assert the recovered reserved-only record refuses re-signing.
#[test]
fn reserved_only_child_death_then_reopen_refuses() {
    // Isolate the RocksDB directory outside the child so it survives the abort.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("child_journal_db");

    let exe = std::env::current_exe().expect("current test exe");
    let status = std::process::Command::new(exe)
        .args([
            "--exact",
            "d7d10_child_reserve_then_abort",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_DB_ENV, &db_path)
        .status()
        .expect("spawn child test process");

    // The child aborted: it must NOT have exited successfully.
    assert!(
        !status.success(),
        "child was expected to abort before completing, got {:?}",
        status
    );

    // Reopen the store the child left behind; a fresh journal has an empty
    // live-permit map, exactly the post-death posture.
    let store = open_store(&db_path);
    let journal = SigningReservationJournal::attach(store as Arc<dyn SigningJournalStorage>);
    let outcome = journal
        .reserve_for_sign(&child_position(), &child_binding())
        .expect("post-death lookup must not error");
    assert_eq!(
        outcome,
        ReservationOutcome::PotentiallySigned,
        "a reservation recovered after child death must refuse re-signing"
    );

    // A conflicting request after death is refused without altering the record.
    assert_eq!(
        journal
            .reserve_for_sign(&child_position(), &binding(0x01))
            .expect("post-death conflict lookup"),
        ReservationOutcome::Conflict
    );
}
