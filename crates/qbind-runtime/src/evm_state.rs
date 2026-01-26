//! EVM state management for QBIND execution.
//!
//! This module provides:
//! - `EvmLedger`: Storage for EVM account states
//! - `LedgerStateView`: Adapter implementing `StateView` for `EvmLedger`
//!
//! ## Design
//!
//! The EVM ledger is separate from the system account store (`AccountStore`).
//! System programs (keyset, validator, governance) use the native QBIND account
//! model, while EVM execution uses the Ethereum-compatible account model.
//!
//! This separation allows:
//! - Independent evolution of both systems
//! - Clear separation of concerns
//! - Easier testing and verification

use crate::block::H256;
use crate::evm_state_storage::{EvmStateSnapshot, SerializableAccountState};
use crate::evm_types::{Address, EvmAccountState, U256};
use crate::execution_engine::StateView;
use std::collections::HashMap;

// ============================================================================
// EvmLedger: Storage for EVM accounts
// ============================================================================

/// EVM ledger storing Ethereum-compatible account states.
///
/// This is separate from the native QBIND account store (`AccountStore`).
/// All EVM transactions are executed against this ledger.
#[derive(Clone, Debug, Default)]
pub struct EvmLedger {
    /// Account states indexed by address.
    accounts: HashMap<Address, EvmAccountState>,
}

impl EvmLedger {
    /// Create a new empty EVM ledger.
    pub fn new() -> Self {
        EvmLedger {
            accounts: HashMap::new(),
        }
    }

    /// Get an account state by address.
    pub fn get_account(&self, addr: &Address) -> Option<&EvmAccountState> {
        self.accounts.get(addr)
    }

    /// Get a mutable reference to an account.
    pub fn get_account_mut(&mut self, addr: &Address) -> Option<&mut EvmAccountState> {
        self.accounts.get_mut(addr)
    }

    /// Insert or update an account.
    pub fn put_account(&mut self, addr: Address, account: EvmAccountState) {
        if account.is_empty() {
            self.accounts.remove(&addr);
        } else {
            self.accounts.insert(addr, account);
        }
    }

    /// Remove an account.
    pub fn remove_account(&mut self, addr: &Address) {
        self.accounts.remove(addr);
    }

    /// Check if an account exists.
    pub fn account_exists(&self, addr: &Address) -> bool {
        self.accounts
            .get(addr)
            .map(|a| !a.is_empty())
            .unwrap_or(false)
    }

    /// Get the number of accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// Iterate over all accounts.
    pub fn iter(&self) -> impl Iterator<Item = (&Address, &EvmAccountState)> {
        self.accounts.iter()
    }

    /// Compute a deterministic state root over the ledger.
    ///
    /// NOTE: This is a temporary implementation that hashes a canonical
    /// serialization of the entire state. A proper Merkle Patricia Trie
    /// will be introduced in a later task.
    ///
    /// ## Performance
    ///
    /// This implementation has O(n log n) complexity where n = accounts + storage slots.
    /// The sorting is required for determinism. This is acceptable for T151 testing
    /// but will become a bottleneck as state grows. Production use requires an
    /// incremental trie structure.
    ///
    /// ## Serialization Format
    ///
    /// - account_count (8 bytes)
    /// - for each account (sorted by address):
    ///   - address (20 bytes)
    ///   - balance (32 bytes)
    ///   - nonce (8 bytes)
    ///   - code_hash (32 bytes) - SHA3 of code
    ///   - storage_count (8 bytes)
    ///   - for each storage slot (sorted by key):
    ///     - key (32 bytes)
    ///     - value (32 bytes)
    pub fn compute_state_root(&self) -> H256 {
        let mut preimage = Vec::with_capacity(1024);

        // Sort accounts by address for determinism
        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_by_key(|(addr, _)| *addr);

        // account_count
        preimage.extend_from_slice(&(sorted_accounts.len() as u64).to_be_bytes());

        for (addr, account) in sorted_accounts {
            // address
            preimage.extend_from_slice(addr.as_bytes());

            // balance
            preimage.extend_from_slice(account.balance.as_bytes());

            // nonce
            preimage.extend_from_slice(&account.nonce.to_be_bytes());

            // code_hash
            if account.code.is_empty() {
                // Empty code hash (Keccak of empty string in Ethereum)
                // For QBIND we use SHA3-256 of empty
                preimage.extend_from_slice(&qbind_hash::sha3_256(&[]));
            } else {
                preimage.extend_from_slice(&qbind_hash::sha3_256(&account.code));
            }

            // Sort storage by key for determinism
            let mut sorted_storage: Vec<_> = account.storage.iter().collect();
            sorted_storage.sort_by_key(|(key, _)| *key);

            // storage_count
            preimage.extend_from_slice(&(sorted_storage.len() as u64).to_be_bytes());

            for (key, value) in sorted_storage {
                preimage.extend_from_slice(key.as_bytes());
                preimage.extend_from_slice(value.as_bytes());
            }
        }

        qbind_hash::sha3_256(&preimage)
    }

    /// Create a snapshot of the current state.
    ///
    /// Returns a clone of all account data for rollback purposes.
    pub fn snapshot(&self) -> EvmLedgerSnapshot {
        EvmLedgerSnapshot {
            accounts: self.accounts.clone(),
        }
    }

    /// Restore state from a snapshot.
    pub fn restore(&mut self, snapshot: EvmLedgerSnapshot) {
        self.accounts = snapshot.accounts;
    }

    /// Create a persistent state snapshot.
    ///
    /// This converts the ledger state to a deterministic `EvmStateSnapshot`
    /// that can be serialized and persisted to storage.
    ///
    /// ## Determinism
    ///
    /// The snapshot is deterministic: accounts are sorted by address in
    /// lexicographic order. This ensures that identical ledger states
    /// produce identical snapshots.
    ///
    /// ## Arguments
    ///
    /// - `state_root`: The state root computed over this ledger state.
    ///   This is passed in rather than recomputed to avoid duplicate work.
    pub fn to_snapshot(&self, state_root: H256) -> EvmStateSnapshot {
        // Collect and sort accounts by address
        let mut sorted_accounts: Vec<_> = self.accounts.iter().collect();
        sorted_accounts.sort_by_key(|(addr, _)| *addr);

        // Convert to serializable format
        let accounts = sorted_accounts
            .into_iter()
            .map(|(addr, account)| (*addr, SerializableAccountState::from_account_state(account)))
            .collect();

        EvmStateSnapshot::new(accounts, state_root)
    }

    /// Restore ledger state from a persistent snapshot.
    ///
    /// This creates a new `EvmLedger` and populates it with the account
    /// states from the snapshot.
    ///
    /// ## Determinism
    ///
    /// After restoring from a snapshot, calling `compute_state_root()` on
    /// the restored ledger should yield the same state root stored in the
    /// snapshot (assuming the snapshot was created correctly).
    pub fn from_snapshot(snapshot: &EvmStateSnapshot) -> Self {
        let mut accounts = HashMap::new();

        for (addr, serializable) in &snapshot.accounts {
            accounts.insert(*addr, serializable.to_account_state());
        }

        EvmLedger { accounts }
    }
}

/// Snapshot of EVM ledger state for rollback.
#[derive(Clone, Debug)]
pub struct EvmLedgerSnapshot {
    accounts: HashMap<Address, EvmAccountState>,
}

// ============================================================================
// LedgerStateView: StateView adapter for EvmLedger
// ============================================================================

/// Adapter that implements `StateView` for `EvmLedger`.
///
/// This allows the `RevmExecutionEngine` to read and write state
/// through the ledger.
///
/// ## Determinism Requirements
///
/// All reads and writes go through this adapter. Do not bypass it
/// with direct ledger mutation during execution.
pub struct LedgerStateView<'a> {
    ledger: &'a mut EvmLedger,
}

impl<'a> LedgerStateView<'a> {
    /// Create a new state view wrapping a ledger.
    pub fn new(ledger: &'a mut EvmLedger) -> Self {
        LedgerStateView { ledger }
    }

    /// Get the underlying ledger for inspection (read-only).
    pub fn ledger(&self) -> &EvmLedger {
        self.ledger
    }
}

impl StateView for LedgerStateView<'_> {
    fn get_account(&self, addr: &Address) -> Option<EvmAccountState> {
        self.ledger.get_account(addr).cloned()
    }

    fn put_account(&mut self, addr: &Address, account: EvmAccountState) {
        self.ledger.put_account(*addr, account);
    }

    fn get_storage(&self, addr: &Address, key: &U256) -> U256 {
        self.ledger
            .get_account(addr)
            .map(|acc| acc.get_storage(key))
            .unwrap_or(U256::zero())
    }

    fn set_storage(&mut self, addr: &Address, key: U256, value: U256) {
        if let Some(account) = self.ledger.get_account_mut(addr) {
            account.set_storage(key, value);
        } else {
            // Create account if it doesn't exist
            let mut account = EvmAccountState::default();
            account.set_storage(key, value);
            self.ledger.put_account(*addr, account);
        }
    }

    fn get_code(&self, addr: &Address) -> Vec<u8> {
        self.ledger
            .get_account(addr)
            .map(|acc| acc.code.clone())
            .unwrap_or_default()
    }

    fn account_exists(&self, addr: &Address) -> bool {
        self.ledger.account_exists(addr)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_evm_ledger_basic_operations() {
        let mut ledger = EvmLedger::new();

        let addr = make_test_addr(1);
        let account = EvmAccountState::with_balance(U256::from_u64(1000));

        ledger.put_account(addr, account.clone());

        assert!(ledger.account_exists(&addr));
        assert_eq!(ledger.account_count(), 1);

        let retrieved = ledger.get_account(&addr).unwrap();
        assert_eq!(retrieved.balance.to_u64(), Some(1000));
    }

    #[test]
    fn test_evm_ledger_remove_empty_account() {
        let mut ledger = EvmLedger::new();

        let addr = make_test_addr(1);
        let empty_account = EvmAccountState::default();

        // Putting an empty account should not store it
        ledger.put_account(addr, empty_account);
        assert_eq!(ledger.account_count(), 0);
    }

    #[test]
    fn test_state_root_determinism() {
        let mut ledger1 = EvmLedger::new();
        let mut ledger2 = EvmLedger::new();

        let addr1 = make_test_addr(1);
        let addr2 = make_test_addr(2);

        let account1 = EvmAccountState::with_balance(U256::from_u64(1000));
        let account2 = EvmAccountState::with_balance(U256::from_u64(2000));

        // Add in different order
        ledger1.put_account(addr1, account1.clone());
        ledger1.put_account(addr2, account2.clone());

        ledger2.put_account(addr2, account2);
        ledger2.put_account(addr1, account1);

        // Roots should be identical despite insertion order
        assert_eq!(ledger1.compute_state_root(), ledger2.compute_state_root());
    }

    #[test]
    fn test_state_root_changes_with_state() {
        let mut ledger = EvmLedger::new();

        let root_empty = ledger.compute_state_root();

        let addr = make_test_addr(1);
        ledger.put_account(addr, EvmAccountState::with_balance(U256::from_u64(1000)));

        let root_with_account = ledger.compute_state_root();
        assert_ne!(root_empty, root_with_account);
    }

    #[test]
    fn test_ledger_state_view() {
        let mut ledger = EvmLedger::new();
        let addr = make_test_addr(1);
        ledger.put_account(addr, EvmAccountState::with_balance(U256::from_u64(1000)));

        {
            let mut view = LedgerStateView::new(&mut ledger);

            // Read through view
            let account = view.get_account(&addr).unwrap();
            assert_eq!(account.balance.to_u64(), Some(1000));

            // Write through view
            let mut updated = account;
            updated.balance = U256::from_u64(2000);
            view.put_account(&addr, updated);
        }

        // Verify write persisted
        assert_eq!(
            ledger.get_account(&addr).unwrap().balance.to_u64(),
            Some(2000)
        );
    }

    #[test]
    fn test_snapshot_and_restore() {
        let mut ledger = EvmLedger::new();
        let addr = make_test_addr(1);

        ledger.put_account(addr, EvmAccountState::with_balance(U256::from_u64(1000)));

        // Take snapshot
        let snapshot = ledger.snapshot();

        // Modify ledger
        ledger.put_account(addr, EvmAccountState::with_balance(U256::from_u64(9999)));

        // Restore
        ledger.restore(snapshot);

        // Verify original value restored
        assert_eq!(
            ledger.get_account(&addr).unwrap().balance.to_u64(),
            Some(1000)
        );
    }

    #[test]
    fn test_to_snapshot_roundtrip() {
        let mut ledger = EvmLedger::new();

        let addr1 = make_test_addr(1);
        let addr2 = make_test_addr(2);

        // Create account with storage
        let mut account1 = EvmAccountState::with_balance(U256::from_u64(1000));
        account1.nonce = 5;
        account1.set_storage(U256::from_u64(1), U256::from_u64(100));
        account1.set_storage(U256::from_u64(2), U256::from_u64(200));

        // Create contract account
        let mut account2 =
            EvmAccountState::with_code(vec![0x60, 0x80, 0x60, 0x40], U256::from_u64(500));
        account2.set_storage(U256::from_u64(99), U256::from_u64(999));

        ledger.put_account(addr1, account1);
        ledger.put_account(addr2, account2);

        // Compute state root
        let state_root = ledger.compute_state_root();

        // Create snapshot
        let snapshot = ledger.to_snapshot(state_root);

        // Restore from snapshot
        let restored_ledger = EvmLedger::from_snapshot(&snapshot);

        // Verify state root matches
        let restored_root = restored_ledger.compute_state_root();
        assert_eq!(state_root, restored_root);

        // Verify account 1
        let r1 = restored_ledger
            .get_account(&addr1)
            .expect("addr1 should exist");
        assert_eq!(r1.balance.to_u64(), Some(1000));
        assert_eq!(r1.nonce, 5);
        assert_eq!(r1.get_storage(&U256::from_u64(1)).to_u64(), Some(100));
        assert_eq!(r1.get_storage(&U256::from_u64(2)).to_u64(), Some(200));

        // Verify account 2
        let r2 = restored_ledger
            .get_account(&addr2)
            .expect("addr2 should exist");
        assert_eq!(r2.balance.to_u64(), Some(500));
        assert_eq!(r2.code, vec![0x60, 0x80, 0x60, 0x40]);
        assert_eq!(r2.get_storage(&U256::from_u64(99)).to_u64(), Some(999));
    }

    #[test]
    fn test_from_snapshot_empty() {
        let empty_snapshot = crate::evm_state_storage::EvmStateSnapshot::empty();
        let ledger = EvmLedger::from_snapshot(&empty_snapshot);

        assert_eq!(ledger.account_count(), 0);
    }

    #[test]
    fn test_snapshot_determinism() {
        // Create two ledgers with accounts inserted in different order
        let mut ledger1 = EvmLedger::new();
        let mut ledger2 = EvmLedger::new();

        let addr1 = make_test_addr(1);
        let addr2 = make_test_addr(2);
        let addr3 = make_test_addr(3);

        let account1 = EvmAccountState::with_balance(U256::from_u64(100));
        let account2 = EvmAccountState::with_balance(U256::from_u64(200));
        let account3 = EvmAccountState::with_balance(U256::from_u64(300));

        // Insert in order 1, 2, 3
        ledger1.put_account(addr1, account1.clone());
        ledger1.put_account(addr2, account2.clone());
        ledger1.put_account(addr3, account3.clone());

        // Insert in order 3, 1, 2
        ledger2.put_account(addr3, account3);
        ledger2.put_account(addr1, account1);
        ledger2.put_account(addr2, account2);

        let root1 = ledger1.compute_state_root();
        let root2 = ledger2.compute_state_root();

        // Roots must match
        assert_eq!(root1, root2);

        // Snapshots must be identical
        let snap1 = ledger1.to_snapshot(root1);
        let snap2 = ledger2.to_snapshot(root2);

        assert_eq!(snap1.accounts.len(), snap2.accounts.len());
        for i in 0..snap1.accounts.len() {
            assert_eq!(snap1.accounts[i].0, snap2.accounts[i].0);
            assert_eq!(snap1.accounts[i].1, snap2.accounts[i].1);
        }
    }
}