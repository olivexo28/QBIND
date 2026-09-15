//! Run 422 D7-C1 — real-storage and recovery tests for the read-only,
//! non-authorizing consensus-storage observation boundary
//! (`qbind_node::consensus_storage_observation`).
//!
//! These tests drive [`observe_consensus_storage`] against **real temporary
//! RocksDB databases** (opened via the production storage APIs) plus a small,
//! explicitly-labelled fault-injection storage for the deterministic I/O-error
//! case. Enum literals alone are not treated as evidence: every persisted-state
//! case is set up through the existing storage API and, where relevant,
//! survives dropping the handle and reopening the database.
//!
//! Coverage (task §5):
//!   A. No handle
//!   B. Existing database without committed epoch
//!   C. Explicit epoch zero
//!   D. Later epoch and stale startup summary
//!   E. Schema compatibility (supported / legacy / unsupported / malformed)
//!   F. Epoch corruption (malformed encoding / corrupted checksum)
//!   G. Incomplete transition (marker present / malformed marker)
//!   H. Read failure (injected)
//!   I. Snapshot-epoch parity (None / explicit zero / idempotent / conflict)
//!
//! The observed epoch is storage evidence only; none of these tests convert an
//! observation into any authorization state, owner, snapshot, or ticket.

use std::sync::atomic::{AtomicUsize, Ordering};

use tempfile::TempDir;

use qbind_node::consensus_storage_observation::{
    observe_consensus_storage, ConsensusStorageObservation, ConsensusStorageObservationError,
};
use qbind_node::node_config::NodeConfig;
use qbind_node::production_consensus_storage::{
    open_production_consensus_storage, persist_restored_snapshot_epoch, ConsensusStorageState,
    ProductionConsensusStorageError,
};
use qbind_node::storage::{
    ConsensusStorage, EpochTransitionBatch, EpochTransitionMarker, InMemoryConsensusStorage,
    RocksDbConsensusStorage, StorageError,
};
use qbind_wire::consensus::{BlockProposal, QuorumCertificate};

// ============================================================================
// Helpers
// ============================================================================

/// Open a fresh RocksDB consensus storage under a unique subdirectory of `tmp`.
fn open_rocks(tmp: &TempDir, name: &str) -> RocksDbConsensusStorage {
    RocksDbConsensusStorage::open(tmp.path().join(name)).expect("open rocksdb")
}

/// Write raw bytes directly to a key in an existing (closed) RocksDB, bypassing
/// the storage API to simulate on-disk corruption. Mirrors the pattern used by
/// `storage_corruption_tests::corrupt_rocksdb_key`.
fn raw_put(db_path: &std::path::Path, key: &[u8], bytes: &[u8]) {
    let mut opts = rocksdb::Options::default();
    opts.create_if_missing(false);
    let db = rocksdb::DB::open(&opts, db_path).expect("reopen rocksdb for raw put");
    db.put(key, bytes).expect("raw put");
}

fn devnet_with_data_dir(data_dir: &std::path::Path) -> NodeConfig {
    NodeConfig::devnet().with_data_dir(data_dir)
}

// ============================================================================
// A. No handle
// ============================================================================

#[test]
fn d7c1_a_no_handle_reports_unavailable_and_creates_nothing() {
    let tmp = TempDir::new().unwrap();
    let would_be_db = tmp.path().join("never-created");

    // No storage handle: observation reports unavailable storage explicitly.
    let obs = observe_consensus_storage::<RocksDbConsensusStorage>(None).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::NoStorageHandle);
    assert!(!obs.has_storage_handle());
    assert_eq!(obs.committed_epoch(), None);

    // The reader created no directory or database.
    assert!(
        !would_be_db.exists(),
        "observation with no handle must not create any directory or database"
    );
}

// ============================================================================
// B. Existing database without committed epoch
// ============================================================================

#[test]
fn d7c1_b_present_without_committed_epoch_is_never_zero_across_reopen() {
    let tmp = TempDir::new().unwrap();

    {
        let storage = open_rocks(&tmp, "db-b");
        let obs = observe_consensus_storage(Some(&storage)).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);
        assert_eq!(obs.committed_epoch(), None, "missing epoch is never 0");
    } // drop handle → release RocksDB lock

    // Reopen: the missing-epoch vs explicit-zero distinction is preserved.
    let reopened = open_rocks(&tmp, "db-b");
    let obs = observe_consensus_storage(Some(&reopened)).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);
    assert_eq!(obs.committed_epoch(), None);
}

// ============================================================================
// C. Explicit epoch zero (persisted evidence only — NOT authorization)
// ============================================================================

#[test]
fn d7c1_c_explicit_epoch_zero_persists_and_survives_reopen() {
    let tmp = TempDir::new().unwrap();

    {
        let storage = open_rocks(&tmp, "db-c");
        storage
            .put_current_epoch(0)
            .expect("persist explicit epoch zero via existing API");
        let obs = observe_consensus_storage(Some(&storage)).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(0));
        assert_eq!(obs.committed_epoch(), Some(0));
    } // drop handles, reopen the database

    let reopened = open_rocks(&tmp, "db-c");
    let obs = observe_consensus_storage(Some(&reopened)).unwrap();
    assert_eq!(
        obs,
        ConsensusStorageObservation::CommittedEpoch(0),
        "explicit persisted epoch zero must remain distinguishable after reopen"
    );
    // Persisted epoch zero is storage evidence ONLY; it yields no authorization.
    // (The observation type is intentionally not convertible to any
    // authorization state / owner / snapshot / ticket.)
}

// ============================================================================
// D. Later epoch and stale startup summary
// ============================================================================

#[test]
fn d7c1_d_reader_observes_new_epoch_despite_stale_startup_summary() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());

    // Establish an initial committed epoch, then open production storage so its
    // startup summary caches CommittedEpoch(5).
    {
        let storage =
            RocksDbConsensusStorage::open(cfg.consensus_storage_dir().unwrap()).unwrap();
        storage.put_current_epoch(5).unwrap();
    }
    let opened = open_production_consensus_storage(&cfg).expect("open production storage");
    assert_eq!(opened.state, ConsensusStorageState::CommittedEpoch(5));

    // Update the actual epoch through the retained handle.
    opened
        .handle
        .as_ref()
        .expect("handle present")
        .put_current_epoch(9)
        .expect("advance epoch via existing handle");

    // The new reader observes the NEW persisted epoch on its next invocation,
    // even though the retained startup summary still says 5.
    let obs = observe_consensus_storage(opened.handle.as_deref()).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(9));
    assert_eq!(
        opened.state,
        ConsensusStorageState::CommittedEpoch(5),
        "the cached startup summary is intentionally stale; the reader does not use it"
    );

    // Reopen control: a fresh production open re-probes and reports 9.
    // (This is a serialized test; it does NOT claim concurrent-invalidation
    // protection.)
    drop(opened);
    let reopened = open_production_consensus_storage(&cfg).expect("reopen");
    assert_eq!(reopened.state, ConsensusStorageState::CommittedEpoch(9));
    let obs = observe_consensus_storage(reopened.handle.as_deref()).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(9));
}

// ============================================================================
// E. Schema compatibility
// ============================================================================

#[test]
fn d7c1_e_supported_and_legacy_schema_yield_epoch_results() {
    let tmp = TempDir::new().unwrap();

    // Legacy v0: no schema key at all → compatible.
    {
        let storage = open_rocks(&tmp, "db-e-legacy");
        storage.put_current_epoch(2).unwrap();
        let obs = observe_consensus_storage(Some(&storage)).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(2));
    }

    // Supported current schema (v1) explicitly stored → compatible.
    {
        let storage = open_rocks(&tmp, "db-e-v1");
        storage.put_schema_version(1).unwrap();
        storage.put_current_epoch(4).unwrap();
        let obs = observe_consensus_storage(Some(&storage)).unwrap();
        assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(4));
    }
}

#[test]
fn d7c1_e_unsupported_newer_schema_is_rejected_not_an_epoch() {
    let tmp = TempDir::new().unwrap();
    let storage = open_rocks(&tmp, "db-e-newer");
    storage.put_schema_version(2).unwrap(); // newer than CURRENT_SCHEMA_VERSION (1)
    storage.put_current_epoch(7).unwrap();

    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    match err {
        ConsensusStorageObservationError::IncompatibleSchema {
            stored_version,
            current_version,
        } => {
            assert_eq!(stored_version, 2);
            assert_eq!(current_version, 1);
        }
        other => panic!("expected IncompatibleSchema, got {other:?}"),
    }
}

#[test]
fn d7c1_e_malformed_schema_metadata_errors_rather_than_epoch() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("db-e-malformed");
    {
        let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
        storage.put_current_epoch(3).unwrap();
    } // drop to release lock

    // Corrupt schema version to an invalid length (must be 4 bytes).
    raw_put(&db_path, b"meta:schema_version", &[0xFF, 0xFE]);

    let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    assert!(
        matches!(
            err,
            ConsensusStorageObservationError::MalformedMetadata { .. }
        ),
        "malformed schema data must produce an error, not an epoch result: {err:?}"
    );
}

// ============================================================================
// F. Epoch corruption (real temporary databases)
// ============================================================================

#[test]
fn d7c1_f_malformed_epoch_encoding_errors_not_no_epoch() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("db-f-len");
    {
        let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
        storage.put_current_epoch(1).unwrap();
    }
    // Wrong-length epoch payload (neither legacy 8 nor checksummed 12 bytes).
    raw_put(&db_path, b"meta:current_epoch", &[0x00, 0x01, 0x02]);

    let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    assert!(
        matches!(
            err,
            ConsensusStorageObservationError::MalformedMetadata { .. }
        ),
        "malformed epoch encoding must not be reported as 'no epoch': {err:?}"
    );
}

#[test]
fn d7c1_f_corrupted_checksummed_epoch_errors_not_no_epoch() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("db-f-crc");
    {
        let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
        storage.put_current_epoch(42).unwrap();
    }
    // Checksummed-format length (4-byte crc + 8-byte payload) but a bad crc:
    // this must be detected as corruption, never silently accepted or dropped.
    let mut corrupt = Vec::new();
    corrupt.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // wrong checksum
    corrupt.extend_from_slice(&42u64.to_be_bytes()); // plausible payload
    raw_put(&db_path, b"meta:current_epoch", &corrupt);

    let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    assert!(
        matches!(
            err,
            ConsensusStorageObservationError::MalformedMetadata { .. }
        ),
        "corrupted checksummed epoch must produce a corruption error, not 'no epoch': {err:?}"
    );
}

// ============================================================================
// G. Incomplete transition
// ============================================================================

#[test]
fn d7c1_g_incomplete_transition_marker_rejected_without_mutation() {
    let tmp = TempDir::new().unwrap();
    let storage = open_rocks(&tmp, "db-g");

    // A readable epoch key AND an in-progress transition marker.
    storage.put_current_epoch(6).unwrap();
    let marker = EpochTransitionMarker {
        target_epoch: 7,
        previous_epoch: 6,
        started_at_ms: 123,
        reconfig_block_id: [0xABu8; 32],
    };
    storage.write_epoch_transition_marker(&marker).unwrap();

    // Observation must reject even though the epoch key is readable.
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    match err {
        ConsensusStorageObservationError::IncompleteEpochTransition {
            target_epoch,
            previous_epoch,
        } => {
            assert_eq!(target_epoch, 7);
            assert_eq!(previous_epoch, 6);
        }
        other => panic!("expected IncompleteEpochTransition, got {other:?}"),
    }

    // Observation did not clear the marker or change the epoch.
    assert!(
        storage
            .check_for_incomplete_epoch_transition()
            .unwrap()
            .is_some(),
        "observation must not clear the transition marker"
    );
    assert_eq!(
        storage.get_current_epoch().unwrap(),
        Some(6),
        "observation must not change the stored epoch"
    );
}

#[test]
fn d7c1_g_malformed_transition_marker_errors() {
    let tmp = TempDir::new().unwrap();
    let db_path = tmp.path().join("db-g-malformed");
    {
        let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
        storage.put_current_epoch(6).unwrap();
    }
    // Marker key present but not decodable as a marker (too short to be a
    // checksum envelope; not valid JSON).
    raw_put(&db_path, b"meta:epoch_transition_marker", &[0x00, 0x01]);

    let storage = RocksDbConsensusStorage::open(&db_path).unwrap();
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    assert!(
        matches!(
            err,
            ConsensusStorageObservationError::MalformedMetadata { .. }
        ),
        "a malformed transition marker must surface as an explicit error: {err:?}"
    );
}

// ============================================================================
// H. Read failure (INJECTED — not a real disk failure)
// ============================================================================

/// A narrow fault-injection `ConsensusStorage` that returns a deterministic I/O
/// error from a chosen read. All other reads report empty/compatible state.
/// This is used ONLY to exercise the observation reader's read-failure path; it
/// is NOT a real disk failure and performs no persistence.
struct FaultInjectingStorage {
    fail_schema: bool,
    fail_epoch: bool,
}

impl ConsensusStorage for FaultInjectingStorage {
    fn put_block(&self, _: &[u8; 32], _: &BlockProposal) -> Result<(), StorageError> {
        panic!("read-only reader must not write");
    }
    fn get_block(&self, _: &[u8; 32]) -> Result<Option<BlockProposal>, StorageError> {
        Ok(None)
    }
    fn put_qc(&self, _: &[u8; 32], _: &QuorumCertificate) -> Result<(), StorageError> {
        panic!("read-only reader must not write");
    }
    fn get_qc(&self, _: &[u8; 32]) -> Result<Option<QuorumCertificate>, StorageError> {
        Ok(None)
    }
    fn put_last_committed(&self, _: &[u8; 32]) -> Result<(), StorageError> {
        panic!("read-only reader must not write");
    }
    fn get_last_committed(&self) -> Result<Option<[u8; 32]>, StorageError> {
        Ok(None)
    }
    fn put_current_epoch(&self, _: u64) -> Result<(), StorageError> {
        panic!("read-only reader must not write");
    }
    fn get_current_epoch(&self) -> Result<Option<u64>, StorageError> {
        if self.fail_epoch {
            Err(StorageError::Io("injected epoch read failure".to_string()))
        } else {
            Ok(None)
        }
    }
    fn put_schema_version(&self, _: u32) -> Result<(), StorageError> {
        panic!("read-only reader must not write");
    }
    fn get_schema_version(&self) -> Result<Option<u32>, StorageError> {
        if self.fail_schema {
            Err(StorageError::Io("injected schema read failure".to_string()))
        } else {
            Ok(None)
        }
    }
    fn apply_epoch_transition_atomic(&self, _: EpochTransitionBatch) -> Result<(), StorageError> {
        panic!("read-only reader must not apply transitions");
    }
    fn write_epoch_transition_marker(
        &self,
        _: &EpochTransitionMarker,
    ) -> Result<(), StorageError> {
        panic!("read-only reader must not write markers");
    }
    fn check_for_incomplete_epoch_transition(
        &self,
    ) -> Result<Option<EpochTransitionMarker>, StorageError> {
        Ok(None)
    }
    fn verify_epoch_consistency_on_startup(&self) -> Result<(), StorageError> {
        Ok(())
    }
}

#[test]
fn d7c1_h_injected_epoch_read_failure_surfaces_as_read_failed() {
    let storage = FaultInjectingStorage {
        fail_schema: false,
        fail_epoch: true,
    };
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    match err {
        ConsensusStorageObservationError::ReadFailed { surface, .. } => {
            assert_eq!(surface, "current epoch");
        }
        other => panic!("expected ReadFailed, got {other:?}"),
    }
}

#[test]
fn d7c1_h_injected_schema_read_failure_surfaces_as_read_failed() {
    let storage = FaultInjectingStorage {
        fail_schema: true,
        fail_epoch: false,
    };
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    assert!(
        matches!(err, ConsensusStorageObservationError::ReadFailed { .. }),
        "injected schema read failure must surface as ReadFailed, not 'no epoch': {err:?}"
    );
}

// ============================================================================
// I. Snapshot-epoch parity (restore writes are separate from the read-only
//    observation).
// ============================================================================

#[test]
fn d7c1_i_snapshot_epoch_none_does_not_synthesize_zero() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());
    let opened = open_production_consensus_storage(&cfg).expect("open");
    assert_eq!(opened.state, ConsensusStorageState::PresentNoCommittedEpoch);

    // Restore write with no snapshot epoch: nothing is persisted.
    let wrote = persist_restored_snapshot_epoch(&opened, None).expect("restore ok");
    assert!(!wrote, "None snapshot epoch must not write");

    // The read-only reader still reports missing epoch — never Some(0).
    let obs = observe_consensus_storage(opened.handle.as_deref()).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);
}

#[test]
fn d7c1_i_explicit_snapshot_epoch_zero_is_distinguishable() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());
    let opened = open_production_consensus_storage(&cfg).expect("open");

    let wrote = persist_restored_snapshot_epoch(&opened, Some(0)).expect("restore ok");
    assert!(wrote, "explicit snapshot epoch 0 must be persisted");

    let obs = observe_consensus_storage(opened.handle.as_deref()).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(0));

    // Survives reopen as explicit zero (not absence).
    drop(opened);
    let reopened = open_production_consensus_storage(&cfg).expect("reopen");
    let obs = observe_consensus_storage(reopened.handle.as_deref()).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(0));
}

#[test]
fn d7c1_i_matching_existing_epoch_is_idempotent() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());
    {
        let storage =
            RocksDbConsensusStorage::open(cfg.consensus_storage_dir().unwrap()).unwrap();
        storage.put_current_epoch(11).unwrap();
    }
    let opened = open_production_consensus_storage(&cfg).expect("open");
    assert_eq!(opened.state, ConsensusStorageState::CommittedEpoch(11));

    let wrote = persist_restored_snapshot_epoch(&opened, Some(11)).expect("idempotent restore");
    assert!(!wrote, "matching epoch restore is a no-op");

    let obs = observe_consensus_storage(opened.handle.as_deref()).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(11));
}

#[test]
fn d7c1_i_conflicting_existing_epoch_is_rejected_not_overwritten() {
    let tmp = TempDir::new().unwrap();
    let cfg = devnet_with_data_dir(tmp.path());
    {
        let storage =
            RocksDbConsensusStorage::open(cfg.consensus_storage_dir().unwrap()).unwrap();
        storage.put_current_epoch(11).unwrap();
    }
    let opened = open_production_consensus_storage(&cfg).expect("open");

    // Conflicting restore epoch is refused (never silently overwritten).
    let err = persist_restored_snapshot_epoch(&opened, Some(99)).unwrap_err();
    assert!(matches!(
        err,
        ProductionConsensusStorageError::RestoreEpochInconsistent { .. }
    ));

    // The read-only reader observes the unchanged pre-existing epoch.
    let obs = observe_consensus_storage(opened.handle.as_deref()).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(11));
}

// ============================================================================
// Read-only guarantee — write-call instrumentation.
// ============================================================================

/// A wrapper that delegates reads to an inner in-memory storage while counting
/// any write/mutation call. Used to assert the observation reader performs no
/// writes regardless of the observed state.
struct WriteCountingStorage {
    inner: InMemoryConsensusStorage,
    writes: AtomicUsize,
}

impl WriteCountingStorage {
    fn new() -> Self {
        Self {
            inner: InMemoryConsensusStorage::new(),
            writes: AtomicUsize::new(0),
        }
    }
    fn write_count(&self) -> usize {
        self.writes.load(Ordering::SeqCst)
    }
    fn bump(&self) {
        self.writes.fetch_add(1, Ordering::SeqCst);
    }
}

impl ConsensusStorage for WriteCountingStorage {
    fn put_block(&self, id: &[u8; 32], b: &BlockProposal) -> Result<(), StorageError> {
        self.bump();
        self.inner.put_block(id, b)
    }
    fn get_block(&self, id: &[u8; 32]) -> Result<Option<BlockProposal>, StorageError> {
        self.inner.get_block(id)
    }
    fn put_qc(&self, id: &[u8; 32], q: &QuorumCertificate) -> Result<(), StorageError> {
        self.bump();
        self.inner.put_qc(id, q)
    }
    fn get_qc(&self, id: &[u8; 32]) -> Result<Option<QuorumCertificate>, StorageError> {
        self.inner.get_qc(id)
    }
    fn put_last_committed(&self, id: &[u8; 32]) -> Result<(), StorageError> {
        self.bump();
        self.inner.put_last_committed(id)
    }
    fn get_last_committed(&self) -> Result<Option<[u8; 32]>, StorageError> {
        self.inner.get_last_committed()
    }
    fn put_current_epoch(&self, e: u64) -> Result<(), StorageError> {
        self.bump();
        self.inner.put_current_epoch(e)
    }
    fn get_current_epoch(&self) -> Result<Option<u64>, StorageError> {
        self.inner.get_current_epoch()
    }
    fn put_schema_version(&self, v: u32) -> Result<(), StorageError> {
        self.bump();
        self.inner.put_schema_version(v)
    }
    fn get_schema_version(&self) -> Result<Option<u32>, StorageError> {
        self.inner.get_schema_version()
    }
    fn apply_epoch_transition_atomic(&self, b: EpochTransitionBatch) -> Result<(), StorageError> {
        self.bump();
        self.inner.apply_epoch_transition_atomic(b)
    }
    fn write_epoch_transition_marker(
        &self,
        m: &EpochTransitionMarker,
    ) -> Result<(), StorageError> {
        self.bump();
        self.inner.write_epoch_transition_marker(m)
    }
    fn check_for_incomplete_epoch_transition(
        &self,
    ) -> Result<Option<EpochTransitionMarker>, StorageError> {
        self.inner.check_for_incomplete_epoch_transition()
    }
    fn verify_epoch_consistency_on_startup(&self) -> Result<(), StorageError> {
        self.inner.verify_epoch_consistency_on_startup()
    }
}

#[test]
fn d7c1_reader_performs_no_writes_for_present_no_epoch() {
    let storage = WriteCountingStorage::new();
    let obs = observe_consensus_storage(Some(&storage)).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::PresentNoCommittedEpoch);
    assert_eq!(storage.write_count(), 0, "observation must issue no writes");
}

#[test]
fn d7c1_reader_performs_no_writes_for_committed_epoch() {
    let storage = WriteCountingStorage::new();
    storage.put_current_epoch(5).unwrap(); // setup write (counted)
    let baseline = storage.write_count();
    let obs = observe_consensus_storage(Some(&storage)).unwrap();
    assert_eq!(obs, ConsensusStorageObservation::CommittedEpoch(5));
    assert_eq!(
        storage.write_count(),
        baseline,
        "observation must not add any writes beyond setup"
    );
}

#[test]
fn d7c1_reader_performs_no_writes_when_marker_present() {
    let storage = WriteCountingStorage::new();
    storage
        .write_epoch_transition_marker(&EpochTransitionMarker {
            target_epoch: 2,
            previous_epoch: 1,
            started_at_ms: 0,
            reconfig_block_id: [0u8; 32],
        })
        .unwrap();
    let baseline = storage.write_count();
    let err = observe_consensus_storage(Some(&storage)).unwrap_err();
    assert!(matches!(
        err,
        ConsensusStorageObservationError::IncompleteEpochTransition { .. }
    ));
    assert_eq!(
        storage.write_count(),
        baseline,
        "rejecting an incomplete transition must not clear or write anything"
    );
}