//! T151 Mempool abstraction and in-memory implementation for QbindTransaction.
//!
//! This module provides:
//! - `Mempool` trait for transaction admission and candidate selection
//! - `InMemoryMempool` reference implementation with:
//!   - Signature verification on admission
//!   - Basic per-sender nonce handling
//!   - Capacity and size limits
//!   - Deterministic FIFO ordering
//!
//! The mempool is the admission layer before transactions are included in blocks
//! and executed. It enforces basic validity checks and provides a pool of
//! ready-to-execute transactions for block proposers.

use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use qbind_ledger::{QbindTransaction, UserPublicKey};
use qbind_types::AccountId;

// ============================================================================
// Mempool Trait
// ============================================================================

/// Mempool abstraction for QbindTransactions.
///
/// The mempool is responsible for:
/// - Admitting valid transactions (signature + basic checks)
/// - Rejecting invalid or duplicate transactions
/// - Providing ordered candidates for block proposals
/// - Evicting committed transactions
pub trait Mempool: Send + Sync {
    /// Insert a transaction into the mempool.
    ///
    /// This method performs admission checks:
    /// - Capacity check (is mempool full?)
    /// - Signature verification
    /// - Basic nonce sanity (if implemented)
    ///
    /// # Arguments
    ///
    /// * `tx` - The transaction to insert
    ///
    /// # Returns
    ///
    /// `Ok(())` if the transaction was admitted, `Err(MempoolError)` otherwise.
    fn insert(&self, tx: QbindTransaction) -> Result<(), MempoolError>;

    /// Get block candidates for a proposal.
    ///
    /// Returns up to `max_txs` transactions in deterministic order.
    /// This method does NOT remove transactions from the mempool;
    /// removal happens on commit via `remove_committed()`.
    ///
    /// # Arguments
    ///
    /// * `max_txs` - Maximum number of transactions to return
    ///
    /// # Returns
    ///
    /// A vector of transactions ready for inclusion in a block.
    fn get_block_candidates(&self, max_txs: usize) -> Vec<QbindTransaction>;

    /// Remove committed transactions from the mempool.
    ///
    /// This is called when a block is committed to evict its transactions.
    ///
    /// # Arguments
    ///
    /// * `committed` - The transactions that were committed
    fn remove_committed(&self, committed: &[QbindTransaction]);

    /// Get the current size of the mempool.
    ///
    /// # Returns
    ///
    /// The number of transactions currently in the mempool.
    fn size(&self) -> usize;
}

/// Errors that can occur during mempool operations.
#[derive(Debug, thiserror::Error)]
pub enum MempoolError {
    /// The mempool is at capacity.
    #[error("mempool full")]
    Full,
    /// The transaction is invalid.
    #[error("invalid transaction: {0}")]
    Invalid(String),
}

// ============================================================================
// InMemoryMempool Implementation
// ============================================================================

/// Configuration for InMemoryMempool.
#[derive(Clone, Debug)]
pub struct MempoolConfig {
    /// Maximum number of transactions in the mempool.
    pub max_txs: usize,
    /// Maximum nonce gap to allow per sender (0 = no gap check).
    /// If > 0, reject txs with nonce > max_seen_nonce + max_nonce_gap.
    pub max_nonce_gap: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_txs: 10000,
            max_nonce_gap: 1000,
        }
    }
}

/// In-memory mempool implementation for QbindTransactions.
///
/// This is the reference implementation for T151:
/// - FIFO ordering (insertion order)
/// - Signature verification on admission
/// - Basic per-sender nonce tracking to prevent spam
/// - Capacity limits
///
/// ## Thread Safety
///
/// Uses `parking_lot::RwLock` for interior mutability, allowing shared
/// `&self` access while protecting mutable state.
pub struct InMemoryMempool {
    inner: RwLock<MempoolInner>,
    config: MempoolConfig,
    /// Optional key provider for signature verification.
    /// If None, signature verification is skipped (test-only mode).
    key_provider: Option<Arc<dyn KeyProvider>>,
}

/// Internal mempool state (protected by RwLock).
struct MempoolInner {
    /// Transactions in insertion order.
    txs: Vec<QbindTransaction>,
    /// Per-sender nonce tracking: sender -> max nonce seen.
    /// Used to reject txs with nonces far in the future (spam prevention).
    nonce_tracker: HashMap<AccountId, u64>,
}

impl InMemoryMempool {
    /// Create a new mempool with default configuration.
    pub fn new() -> Self {
        Self::with_config(MempoolConfig::default())
    }

    /// Create a new mempool with custom configuration.
    pub fn with_config(config: MempoolConfig) -> Self {
        Self {
            inner: RwLock::new(MempoolInner {
                txs: Vec::new(),
                nonce_tracker: HashMap::new(),
            }),
            config,
            key_provider: None,
        }
    }

    /// Create a mempool with a key provider for signature verification.
    pub fn with_key_provider(config: MempoolConfig, key_provider: Arc<dyn KeyProvider>) -> Self {
        Self {
            inner: RwLock::new(MempoolInner {
                txs: Vec::new(),
                nonce_tracker: HashMap::new(),
            }),
            config,
            key_provider: Some(key_provider),
        }
    }
}

impl Default for InMemoryMempool {
    fn default() -> Self {
        Self::new()
    }
}

impl Mempool for InMemoryMempool {
    fn insert(&self, tx: QbindTransaction) -> Result<(), MempoolError> {
        let mut inner = self.inner.write();

        // 1. Capacity check
        if inner.txs.len() >= self.config.max_txs {
            return Err(MempoolError::Full);
        }

        // 2. Signature verification (if key provider is set)
        if let Some(ref provider) = self.key_provider {
            let pk = provider
                .get_public_key(&tx.sender)
                .map_err(|e| MempoolError::Invalid(format!("key lookup failed: {}", e)))?;

            tx.verify_signature(&pk).map_err(|e| {
                MempoolError::Invalid(format!("signature verification failed: {}", e))
            })?;
        }

        // 3. Basic nonce sanity check (if max_nonce_gap > 0)
        if self.config.max_nonce_gap > 0 {
            const MAX_NONCE_GAP_BEHIND: u64 = 10; // How far behind max_nonce we allow

            if let Some(&max_nonce) = inner.nonce_tracker.get(&tx.sender) {
                // Reject if nonce is too far in the future
                if tx.nonce > max_nonce + self.config.max_nonce_gap {
                    return Err(MempoolError::Invalid(format!(
                        "nonce {} too far ahead of max seen {} (gap limit {})",
                        tx.nonce, max_nonce, self.config.max_nonce_gap
                    )));
                }
                // Also reject if nonce is too far in the past (already executed)
                if tx.nonce < max_nonce.saturating_sub(MAX_NONCE_GAP_BEHIND) {
                    return Err(MempoolError::Invalid(format!(
                        "nonce {} too far behind max seen {}",
                        tx.nonce, max_nonce
                    )));
                }
            }

            // Update max nonce seen for this sender
            inner
                .nonce_tracker
                .entry(tx.sender)
                .and_modify(|max| {
                    if tx.nonce > *max {
                        *max = tx.nonce;
                    }
                })
                .or_insert(tx.nonce);
        }

        // 4. Insert the transaction
        inner.txs.push(tx);

        Ok(())
    }

    fn get_block_candidates(&self, max_txs: usize) -> Vec<QbindTransaction> {
        let inner = self.inner.read();

        // Simple FIFO: take up to max_txs from the front
        inner.txs.iter().take(max_txs).cloned().collect()
    }

    fn remove_committed(&self, committed: &[QbindTransaction]) {
        let mut inner = self.inner.write();

        // For each committed tx, remove matching (sender, nonce) from mempool
        for committed_tx in committed {
            inner
                .txs
                .retain(|tx| tx.sender != committed_tx.sender || tx.nonce != committed_tx.nonce);
        }
    }

    fn size(&self) -> usize {
        let inner = self.inner.read();
        inner.txs.len()
    }
}

// ============================================================================
// Key Provider Trait
// ============================================================================

/// Trait for resolving AccountId to UserPublicKey for signature verification.
///
/// This abstraction allows different implementations:
/// - Test mode: in-memory map of account -> key
/// - Production: query state or key registry
pub trait KeyProvider: Send + Sync {
    /// Get the public key for an account.
    ///
    /// # Arguments
    ///
    /// * `account` - The account ID
    ///
    /// # Returns
    ///
    /// The public key if found, or an error.
    fn get_public_key(&self, account: &AccountId) -> Result<UserPublicKey, KeyProviderError>;
}

/// Errors from key provider.
#[derive(Debug, thiserror::Error)]
pub enum KeyProviderError {
    /// The key was not found.
    #[error("key not found for account")]
    NotFound,
    /// An internal error occurred.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Simple in-memory key provider for testing.
pub struct InMemoryKeyProvider {
    keys: HashMap<AccountId, UserPublicKey>,
}

impl InMemoryKeyProvider {
    /// Create an empty key provider.
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Register a key for an account.
    pub fn register(&mut self, account: AccountId, key: UserPublicKey) {
        self.keys.insert(account, key);
    }
}

impl Default for InMemoryKeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyProvider for InMemoryKeyProvider {
    fn get_public_key(&self, account: &AccountId) -> Result<UserPublicKey, KeyProviderError> {
        self.keys
            .get(account)
            .cloned()
            .ok_or(KeyProviderError::NotFound)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;

    fn test_account_id(byte: u8) -> AccountId {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn make_signed_tx(sender: AccountId, nonce: u64, sk: &[u8]) -> QbindTransaction {
        let mut tx = QbindTransaction::new(sender, nonce, b"payload".to_vec());
        tx.sign(sk).expect("signing should succeed");
        tx
    }

    #[test]
    fn test_mempool_insertion_and_capacity() {
        let config = MempoolConfig {
            max_txs: 2,
            max_nonce_gap: 0, // Disable nonce checks for this test
        };
        let mempool = InMemoryMempool::with_config(config);

        let sender = test_account_id(0xAA);
        let tx1 = QbindTransaction::new(sender, 0, b"tx1".to_vec());
        let tx2 = QbindTransaction::new(sender, 1, b"tx2".to_vec());
        let tx3 = QbindTransaction::new(sender, 2, b"tx3".to_vec());

        // Insert two txs (should succeed)
        assert!(mempool.insert(tx1).is_ok());
        assert_eq!(mempool.size(), 1);

        assert!(mempool.insert(tx2).is_ok());
        assert_eq!(mempool.size(), 2);

        // Third insert should fail (capacity reached)
        let result = mempool.insert(tx3);
        assert!(result.is_err());
        assert!(matches!(result, Err(MempoolError::Full)));
    }

    #[test]
    fn test_mempool_signature_verification() {
        // Generate a keypair
        let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let pk = UserPublicKey::ml_dsa_44(pk_bytes);

        // Create key provider
        let sender = test_account_id(0xBB);
        let mut key_provider = InMemoryKeyProvider::new();
        key_provider.register(sender, pk);

        let config = MempoolConfig {
            max_txs: 10,
            max_nonce_gap: 0,
        };
        let mempool = InMemoryMempool::with_key_provider(config, Arc::new(key_provider));

        // Valid signature should succeed
        let valid_tx = make_signed_tx(sender, 0, &sk);
        assert!(mempool.insert(valid_tx).is_ok());
        assert_eq!(mempool.size(), 1);

        // Invalid signature should fail
        let mut invalid_tx = QbindTransaction::new(sender, 1, b"invalid".to_vec());
        invalid_tx.signature = qbind_ledger::UserSignature::new(vec![0u8; 2420]);
        let result = mempool.insert(invalid_tx);
        assert!(result.is_err());
        assert!(matches!(result, Err(MempoolError::Invalid(_))));
        assert_eq!(mempool.size(), 1); // Size unchanged
    }

    #[test]
    fn test_mempool_nonce_handling() {
        let config = MempoolConfig {
            max_txs: 100,
            max_nonce_gap: 5, // Allow gap of 5
        };
        let mempool = InMemoryMempool::with_config(config);

        let sender = test_account_id(0xCC);

        // Insert tx with nonce 0
        let tx0 = QbindTransaction::new(sender, 0, b"tx0".to_vec());
        assert!(mempool.insert(tx0).is_ok());

        // Insert tx with nonce 5 (gap of 5, should succeed)
        let tx5 = QbindTransaction::new(sender, 5, b"tx5".to_vec());
        assert!(mempool.insert(tx5).is_ok());

        // Insert tx with nonce 11 (gap > 5 from max seen, should fail)
        let tx11 = QbindTransaction::new(sender, 11, b"tx11".to_vec());
        let result = mempool.insert(tx11);
        assert!(result.is_err());
        assert!(matches!(result, Err(MempoolError::Invalid(_))));
    }

    #[test]
    fn test_mempool_get_block_candidates() {
        let mempool = InMemoryMempool::new();
        let sender = test_account_id(0xDD);

        // Insert 5 txs
        for i in 0..5 {
            let tx = QbindTransaction::new(sender, i, format!("tx{}", i).into_bytes());
            mempool.insert(tx).unwrap();
        }

        // Get 3 candidates (should be txs 0, 1, 2 in FIFO order)
        let candidates = mempool.get_block_candidates(3);
        assert_eq!(candidates.len(), 3);
        assert_eq!(candidates[0].nonce, 0);
        assert_eq!(candidates[1].nonce, 1);
        assert_eq!(candidates[2].nonce, 2);

        // Get 10 candidates (should return all 5)
        let all_candidates = mempool.get_block_candidates(10);
        assert_eq!(all_candidates.len(), 5);

        // Mempool size should be unchanged (get_block_candidates doesn't remove)
        assert_eq!(mempool.size(), 5);
    }

    #[test]
    fn test_mempool_remove_committed() {
        let mempool = InMemoryMempool::new();
        let sender = test_account_id(0xEE);

        // Insert 5 txs
        let mut txs = Vec::new();
        for i in 0..5 {
            let tx = QbindTransaction::new(sender, i, format!("tx{}", i).into_bytes());
            mempool.insert(tx.clone()).unwrap();
            txs.push(tx);
        }

        assert_eq!(mempool.size(), 5);

        // Remove txs 1 and 3
        mempool.remove_committed(&[txs[1].clone(), txs[3].clone()]);

        // Should have 3 txs remaining (0, 2, 4)
        assert_eq!(mempool.size(), 3);

        let remaining = mempool.get_block_candidates(10);
        assert_eq!(remaining.len(), 3);
        assert_eq!(remaining[0].nonce, 0);
        assert_eq!(remaining[1].nonce, 2);
        assert_eq!(remaining[2].nonce, 4);
    }

    #[test]
    fn test_mempool_deterministic_order() {
        // Create two mempools with same config
        let config = MempoolConfig {
            max_txs: 100,
            max_nonce_gap: 0,
        };
        let mempool1 = InMemoryMempool::with_config(config.clone());
        let mempool2 = InMemoryMempool::with_config(config);

        let sender = test_account_id(0xFF);

        // Insert same txs in same order
        for i in 0..5 {
            let tx = QbindTransaction::new(sender, i, format!("tx{}", i).into_bytes());
            mempool1.insert(tx.clone()).unwrap();
            mempool2.insert(tx).unwrap();
        }

        // Both should return same candidates in same order
        let candidates1 = mempool1.get_block_candidates(10);
        let candidates2 = mempool2.get_block_candidates(10);

        assert_eq!(candidates1.len(), candidates2.len());
        for (tx1, tx2) in candidates1.iter().zip(candidates2.iter()) {
            assert_eq!(tx1.sender, tx2.sender);
            assert_eq!(tx1.nonce, tx2.nonce);
            assert_eq!(tx1.payload, tx2.payload);
        }
    }
}