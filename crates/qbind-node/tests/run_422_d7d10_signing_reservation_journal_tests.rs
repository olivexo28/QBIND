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
    BindingDigest, JournalError, ReservationOutcome, ResultPublicationCapability,
    SigningJournalStorage, SigningKind, SigningPosition, SigningReservationJournal,
    DEFAULT_MAX_RESERVED_POSITIONS,
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
// Bounded child-process death / reopen.
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
    let journal = journal(store as Arc<dyn SigningJournalStorage>);
    match journal
        .reserve_for_sign(&child_position(), &child_binding())
        .expect("child reservation must succeed")
    {
        ReservationOutcome::FreshlyReserved(_cont) => { /* durable ack; drop before sign */ }
        other => panic!("expected FreshlyReserved, got {:?}", other),
    }
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
///
/// Correction-F boundary (NOT closed under E): this parent is the ACTIVE test;
/// [`d7d10_child_reserve_then_abort`] is the `#[ignore]`d child-mode helper it
/// re-executes. The child runner here is deliberately left UNCORRECTED under E:
/// * It waits with an UNBOUNDED [`std::process::Command::status`] — there is no
///   timeout or runtime bound on the child; a hung child would block here, so
///   this does NOT establish bounded process termination.
/// * It accepts ANY unsuccessful exit (`!status.success()`) — it does not
///   classify the termination (e.g. it does not require the specific SIGABRT
///   from `std::process::abort()` vs. any other nonzero/​signalled exit), so it
///   does NOT establish classified process termination either.
///
/// Consequently a PASS here evidences only durable reserved-only recovery across
/// a real child death; it does NOT close Correction F. An outer command/tool
/// timeout wrapping the whole test run is not a child bound and does not close F.
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

    // The child aborted: it must NOT have exited successfully. NOTE (Correction
    // F, unmet under E): this only checks "not success" — it neither bounds the
    // child's runtime nor classifies HOW it terminated, so it does not establish
    // bounded/classified termination.
    assert!(
        !status.success(),
        "child was expected to abort before completing, got {:?}",
        status
    );

    // Reopen the store the child left behind; a fresh journal has an empty
    // live-permit map, exactly the post-death posture.
    let store = open_store(&db_path);
    let journal = journal(store as Arc<dyn SigningJournalStorage>);
    assert!(
        matches!(
            journal
                .reserve_for_sign(&child_position(), &child_binding())
                .expect("post-death lookup must not error"),
            ReservationOutcome::PotentiallySigned
        ),
        "a reservation recovered after child death must refuse re-signing"
    );

    // A conflicting request after death is refused without altering the record.
    assert!(matches!(
        journal
            .reserve_for_sign(&child_position(), &binding(0x01))
            .expect("post-death conflict lookup"),
        ReservationOutcome::Conflict
    ));
}