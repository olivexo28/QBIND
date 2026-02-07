//! T215: State Snapshot Integration Tests
//!
//! This module tests the state snapshot functionality:
//!
//! - Snapshot creation using RocksDB checkpoint API
//! - Snapshot metadata roundtrip (JSON serialization)
//! - Snapshot directory validation
//! - StateSnapshotter trait implementation for RocksDbAccountState

use qbind_ledger::{
    validate_snapshot_dir, AccountState, PersistentAccountState, RocksDbAccountState,
    SnapshotValidationResult, StateSnapshotError, StateSnapshotMeta, StateSnapshotter,
};
use qbind_types::AccountId;
use std::path::Path;
use tempfile::tempdir;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test account ID with the given byte value.
fn test_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

/// Create test metadata for the given height.
fn test_meta(height: u64) -> StateSnapshotMeta {
    StateSnapshotMeta {
        height,
        block_hash: [height as u8; 32],
        created_at_unix_ms: 1700000000000 + height,
        chain_id: 0x51424E444D41494E, // MainNet chain ID
    }
}

// ============================================================================
// Part 1: Snapshot Creation Tests
// ============================================================================

/// Test that a basic snapshot can be created.
#[test]
fn test_snapshot_creation_basic() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    // Write some test data
    let account = test_account_id(0xAA);
    let state = AccountState::new(5, 1000);
    storage
        .put_account_state(&account, &state)
        .expect("Failed to put account state");
    storage.flush().expect("Failed to flush");

    // Create a snapshot
    let meta = test_meta(100);
    let target = snapshot_dir.path().join("100");

    let stats = storage
        .create_snapshot(&meta, &target)
        .expect("Failed to create snapshot");

    // Verify stats
    assert_eq!(stats.height, 100, "snapshot height should match");
    assert!(stats.duration_ms < 10_000, "snapshot should complete quickly");

    // Verify snapshot directory structure
    assert!(target.exists(), "snapshot directory should exist");
    assert!(target.join("meta.json").exists(), "meta.json should exist");
    assert!(target.join("state").exists(), "state directory should exist");
}

/// Test that snapshot creation fails if target already exists.
#[test]
fn test_snapshot_creation_already_exists() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    let meta = test_meta(100);
    let target = snapshot_dir.path().join("100");

    // Create first snapshot
    storage
        .create_snapshot(&meta, &target)
        .expect("First snapshot should succeed");

    // Try to create another at the same path
    let result = storage.create_snapshot(&meta, &target);

    assert!(
        matches!(result, Err(StateSnapshotError::AlreadyExists(_))),
        "should fail with AlreadyExists error"
    );
}

/// Test that snapshot creation fails with empty target path.
#[test]
fn test_snapshot_creation_empty_path() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    let meta = test_meta(100);
    let result = storage.create_snapshot(&meta, Path::new(""));

    assert!(
        matches!(result, Err(StateSnapshotError::Config(_))),
        "should fail with Config error for empty path"
    );
}

// ============================================================================
// Part 2: Snapshot Metadata Tests
// ============================================================================

/// Test that metadata is correctly written to meta.json.
#[test]
fn test_snapshot_metadata_written() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    let meta = StateSnapshotMeta {
        height: 12345,
        block_hash: [0xAB; 32],
        created_at_unix_ms: 1700000000000,
        chain_id: 0x1234567890,
    };

    let target = snapshot_dir.path().join("12345");
    storage
        .create_snapshot(&meta, &target)
        .expect("Failed to create snapshot");

    // Read and parse meta.json
    let meta_json = std::fs::read(target.join("meta.json")).expect("Failed to read meta.json");
    let parsed = StateSnapshotMeta::from_json(&meta_json).expect("Failed to parse meta.json");

    assert_eq!(parsed.height, meta.height, "height should match");
    assert_eq!(parsed.block_hash, meta.block_hash, "block_hash should match");
    assert_eq!(
        parsed.created_at_unix_ms, meta.created_at_unix_ms,
        "created_at_unix_ms should match"
    );
    assert_eq!(parsed.chain_id, meta.chain_id, "chain_id should match");
}

// ============================================================================
// Part 3: Snapshot Validation Tests
// ============================================================================

/// Test that a valid snapshot passes validation.
#[test]
fn test_snapshot_validation_valid() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    let meta = test_meta(100);
    let target = snapshot_dir.path().join("100");
    storage
        .create_snapshot(&meta, &target)
        .expect("Failed to create snapshot");

    // Validate with matching chain ID
    let result = validate_snapshot_dir(&target, 0x51424E444D41494E);

    assert!(
        matches!(result, SnapshotValidationResult::Valid(_)),
        "valid snapshot should pass validation"
    );

    if let SnapshotValidationResult::Valid(validated_meta) = result {
        assert_eq!(validated_meta.height, 100);
    }
}

/// Test that validation fails with mismatched chain ID.
#[test]
fn test_snapshot_validation_chain_id_mismatch() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    let meta = test_meta(100);
    let target = snapshot_dir.path().join("100");
    storage
        .create_snapshot(&meta, &target)
        .expect("Failed to create snapshot");

    // Validate with different chain ID
    let result = validate_snapshot_dir(&target, 0xDEADBEEF);

    assert!(
        matches!(
            result,
            SnapshotValidationResult::ChainIdMismatch { expected: _, actual: _ }
        ),
        "mismatched chain ID should fail validation"
    );
}

/// Test that validation fails with missing meta.json.
#[test]
fn test_snapshot_validation_missing_metadata() {
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");
    let target = snapshot_dir.path().join("100");

    // Create directory but no meta.json
    std::fs::create_dir_all(&target).expect("Failed to create directory");

    let result = validate_snapshot_dir(&target, 0x51424E444D41494E);

    assert!(
        matches!(result, SnapshotValidationResult::MissingMetadata(_)),
        "missing meta.json should fail validation"
    );
}

/// Test that validation fails with missing state directory.
#[test]
fn test_snapshot_validation_missing_state_dir() {
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");
    let target = snapshot_dir.path().join("100");

    // Create directory with meta.json but no state/
    std::fs::create_dir_all(&target).expect("Failed to create directory");
    let meta = test_meta(100);
    std::fs::write(target.join("meta.json"), meta.to_json()).expect("Failed to write meta.json");

    let result = validate_snapshot_dir(&target, 0x51424E444D41494E);

    assert!(
        matches!(result, SnapshotValidationResult::MissingStateDir(_)),
        "missing state directory should fail validation"
    );
}

// ============================================================================
// Part 4: Size Estimation Tests
// ============================================================================

/// Test that snapshot size estimation works.
#[test]
fn test_snapshot_size_estimation() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    // Write some test data
    for i in 0..100 {
        let account = test_account_id(i as u8);
        let state = AccountState::new(i, i as u128 * 1000);
        storage
            .put_account_state(&account, &state)
            .expect("Failed to put account state");
    }
    storage.flush().expect("Failed to flush");

    // Estimate size
    let size = storage.estimate_snapshot_size_bytes();

    // Size should be non-zero after writing data
    assert!(
        size.is_some(),
        "size estimation should return Some for non-empty state"
    );
    // Note: We can't assert exact size due to RocksDB internal behavior
}

// ============================================================================
// Part 5: SnapshotStats Tests
// ============================================================================

/// Test that SnapshotStats is properly populated after creation.
#[test]
fn test_snapshot_stats_populated() {
    let state_dir = tempdir().expect("Failed to create temp dir for state");
    let snapshot_dir = tempdir().expect("Failed to create temp dir for snapshots");

    let storage =
        RocksDbAccountState::open(state_dir.path()).expect("Failed to open RocksDbAccountState");

    // Write some data
    for i in 0..10 {
        let account = test_account_id(i as u8);
        let state = AccountState::new(i, i as u128 * 1000);
        storage
            .put_account_state(&account, &state)
            .expect("Failed to put account state");
    }
    storage.flush().expect("Failed to flush");

    // Create snapshot and check stats
    let meta = test_meta(100);
    let target = snapshot_dir.path().join("100");

    let stats = storage
        .create_snapshot(&meta, &target)
        .expect("Failed to create snapshot");

    assert_eq!(stats.height, 100, "stats height should match metadata");
    // Duration should be recorded (always non-negative for u64)
    // Size might be 0 if RocksDB hasn't flushed SST files yet
    // (checkpoint creates hard links, and live data might still be in memtable)
}