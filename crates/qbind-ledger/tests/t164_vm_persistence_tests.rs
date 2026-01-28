//! T164: VM v0 State Persistence Unit Tests
//!
//! This module tests the persistent account state backend for VM v0:
//!
//! - Basic put/get roundtrip
//! - Default state for missing accounts
//! - Persistence across reopen (restart simulation)
//! - CachedPersistentAccountState wrapper behavior

use qbind_ledger::{
    AccountState, AccountStateUpdater, AccountStateView, CachedPersistentAccountState,
    PersistentAccountState, RocksDbAccountState, StorageError,
};
use qbind_types::AccountId;
use tempfile::tempdir;

// ============================================================================
// Helper Functions
// ============================================================================

/// Create a test account ID with the given byte value.
fn test_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

// ============================================================================
// Part 4.1: RocksDbAccountState Unit Tests
// ============================================================================

/// Test that a basic put/get roundtrip works correctly.
#[test]
fn basic_put_get_roundtrip() {
    let dir = tempdir().expect("Failed to create temp dir");
    let storage =
        RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");

    let account = test_account_id(0xAA);
    let state = AccountState::new(5, 1000);

    // Store the state
    storage
        .put_account_state(&account, &state)
        .expect("Failed to put account state");

    // Read it back
    let loaded = storage.get_account_state(&account);

    assert_eq!(loaded.nonce, 5, "nonce should match");
    assert_eq!(loaded.balance, 1000, "balance should match");
}

/// Test that a missing account returns the default state (nonce=0, balance=0).
#[test]
fn default_state_for_missing_account() {
    let dir = tempdir().expect("Failed to create temp dir");
    let storage =
        RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");

    let account = test_account_id(0xBB);

    // No write for this account
    let loaded = storage.get_account_state(&account);

    assert_eq!(loaded.nonce, 0, "nonce should be 0 for missing account");
    assert_eq!(loaded.balance, 0, "balance should be 0 for missing account");
}

/// Test that state persists across reopen (simulating a node restart).
#[test]
fn persist_across_reopen() {
    let dir = tempdir().expect("Failed to create temp dir");
    let account = test_account_id(0xCC);
    let state = AccountState::new(42, 999_999);

    // First session: write and flush
    {
        let storage =
            RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");

        storage
            .put_account_state(&account, &state)
            .expect("Failed to put account state");
        storage.flush().expect("Failed to flush");
    }

    // Second session: reopen and read (simulating restart)
    {
        let storage =
            RocksDbAccountState::open(dir.path()).expect("Failed to reopen RocksDbAccountState");

        let loaded = storage.get_account_state(&account);

        assert_eq!(loaded.nonce, 42, "nonce should survive restart");
        assert_eq!(loaded.balance, 999_999, "balance should survive restart");
    }
}

/// Test that multiple accounts can be stored and retrieved independently.
#[test]
fn multiple_accounts() {
    let dir = tempdir().expect("Failed to create temp dir");
    let storage =
        RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");

    let account1 = test_account_id(0x01);
    let account2 = test_account_id(0x02);
    let account3 = test_account_id(0x03);

    storage
        .put_account_state(&account1, &AccountState::new(1, 100))
        .unwrap();
    storage
        .put_account_state(&account2, &AccountState::new(2, 200))
        .unwrap();
    storage
        .put_account_state(&account3, &AccountState::new(3, 300))
        .unwrap();
    storage.flush().unwrap();

    assert_eq!(
        storage.get_account_state(&account1),
        AccountState::new(1, 100)
    );
    assert_eq!(
        storage.get_account_state(&account2),
        AccountState::new(2, 200)
    );
    assert_eq!(
        storage.get_account_state(&account3),
        AccountState::new(3, 300)
    );
}

/// Test that state can be updated (overwritten).
#[test]
fn state_update() {
    let dir = tempdir().expect("Failed to create temp dir");
    let storage =
        RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");

    let account = test_account_id(0xDD);

    // Initial state
    storage
        .put_account_state(&account, &AccountState::new(0, 100))
        .unwrap();
    assert_eq!(storage.get_account_state(&account).balance, 100);

    // Update state
    storage
        .put_account_state(&account, &AccountState::new(1, 50))
        .unwrap();

    let loaded = storage.get_account_state(&account);
    assert_eq!(loaded.nonce, 1);
    assert_eq!(loaded.balance, 50);
}

// ============================================================================
// Part 4.1: AccountState Serialization Tests
// ============================================================================

/// Test AccountState serialization and deserialization.
#[test]
fn account_state_serialization_roundtrip() {
    let state = AccountState::new(12345, 999_000_000_000_000_000);

    let bytes = state.to_bytes();
    assert_eq!(bytes.len(), AccountState::SERIALIZED_SIZE);

    let deserialized = AccountState::from_bytes(&bytes).expect("Failed to deserialize");
    assert_eq!(deserialized.nonce, state.nonce);
    assert_eq!(deserialized.balance, state.balance);
}

/// Test that deserializing wrong-size data returns None.
#[test]
fn account_state_deserialize_wrong_size() {
    assert!(AccountState::from_bytes(&[]).is_none());
    assert!(AccountState::from_bytes(&[0u8; 23]).is_none());
    assert!(AccountState::from_bytes(&[0u8; 25]).is_none());
    assert!(AccountState::from_bytes(&[0u8; 100]).is_none());
}

/// Test serialization of boundary values.
#[test]
fn account_state_boundary_values() {
    // Max values
    let max_state = AccountState::new(u64::MAX, u128::MAX);
    let max_bytes = max_state.to_bytes();
    let max_loaded = AccountState::from_bytes(&max_bytes).unwrap();
    assert_eq!(max_loaded.nonce, u64::MAX);
    assert_eq!(max_loaded.balance, u128::MAX);

    // Zero values (default)
    let zero_state = AccountState::default();
    let zero_bytes = zero_state.to_bytes();
    let zero_loaded = AccountState::from_bytes(&zero_bytes).unwrap();
    assert_eq!(zero_loaded.nonce, 0);
    assert_eq!(zero_loaded.balance, 0);
}

// ============================================================================
// Part 4.1: CachedPersistentAccountState Tests
// ============================================================================

/// Test CachedPersistentAccountState basic functionality.
#[test]
fn cached_state_basic() {
    let dir = tempdir().expect("Failed to create temp dir");
    let persistent =
        RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
    let mut cached = CachedPersistentAccountState::new(persistent);

    let account = test_account_id(0xEE);

    // Initially, account should return default state
    assert_eq!(cached.get_account_state(&account), AccountState::default());

    // Set account state
    cached.set_account_state(&account, AccountState::new(10, 500));

    // Should now return the updated state
    let loaded = cached.get_account_state(&account);
    assert_eq!(loaded.nonce, 10);
    assert_eq!(loaded.balance, 500);
}

/// Test that CachedPersistentAccountState writes through to persistent storage.
#[test]
fn cached_state_write_through() {
    let dir = tempdir().expect("Failed to create temp dir");
    let account = test_account_id(0xFF);

    // First session: write via cached wrapper
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
        let mut cached = CachedPersistentAccountState::new(persistent);

        cached.set_account_state(&account, AccountState::new(7, 777));
        cached.flush().expect("Failed to flush");
    }

    // Second session: verify data persisted via direct access
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to reopen RocksDbAccountState");

        let loaded = persistent.get_account_state(&account);
        assert_eq!(loaded.nonce, 7, "nonce should persist through cache");
        assert_eq!(loaded.balance, 777, "balance should persist through cache");
    }
}

/// Test that cached state reads from persistent store on cache miss.
#[test]
fn cached_state_read_through() {
    let dir = tempdir().expect("Failed to create temp dir");
    let account = test_account_id(0x11);

    // First session: write directly to persistent storage
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to open RocksDbAccountState");
        persistent
            .put_account_state(&account, &AccountState::new(3, 333))
            .unwrap();
        persistent.flush().unwrap();
    }

    // Second session: read via cached wrapper (should load from persistent)
    {
        let persistent =
            RocksDbAccountState::open(dir.path()).expect("Failed to reopen RocksDbAccountState");
        let cached = CachedPersistentAccountState::new(persistent);

        let loaded = cached.get_account_state(&account);
        assert_eq!(loaded.nonce, 3, "should read from persistent on cache miss");
        assert_eq!(loaded.balance, 333);
    }
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Test that opening a non-existent directory creates it.
#[test]
fn open_creates_directory() {
    let dir = tempdir().expect("Failed to create temp dir");
    let db_path = dir.path().join("subdir").join("deep").join("vm_state");

    // Path doesn't exist yet
    assert!(!db_path.exists());

    // Opening should create it
    let storage = RocksDbAccountState::open(&db_path);
    assert!(storage.is_ok(), "Should create nested directories");

    // Now the path should exist
    assert!(db_path.exists());
}

/// Test StorageError display formatting.
#[test]
fn storage_error_display() {
    let io_err = StorageError::Io("test io error".to_string());
    assert!(format!("{}", io_err).contains("I/O error"));

    let corrupt_err = StorageError::Corrupt("test corruption".to_string());
    assert!(format!("{}", corrupt_err).contains("corruption"));
}
