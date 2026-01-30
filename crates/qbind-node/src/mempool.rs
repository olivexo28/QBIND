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

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use parking_lot::RwLock;
use qbind_ledger::{QbindTransaction, UserPublicKey};
use qbind_types::AccountId;

use crate::metrics::{MempoolMetrics, MempoolRejectReason};

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

    // T168: Gas-related admission errors
    /// Transaction's gas cost exceeds its gas limit (T168).
    #[error("insufficient gas limit: required {required}, limit {limit}")]
    InsufficientGasLimit {
        /// The required gas for this transaction.
        required: u64,
        /// The gas limit specified in the transaction.
        limit: u64,
    },

    /// Sender doesn't have enough balance to cover amount + fee (T168).
    #[error("insufficient balance for fee: balance {balance}, needed {needed}")]
    InsufficientBalanceForFee {
        /// The sender's current balance.
        balance: u128,
        /// The total amount needed (transfer amount + max fee).
        needed: u128,
    },

    /// T169: Transaction dropped because its priority is lower than everything in the mempool.
    #[error("transaction priority too low for admission")]
    LowPriorityDropped,
}

// ============================================================================
// T169: Fee-aware Priority & Scoring
// ============================================================================

/// Cost parameters for a transaction in the mempool (T169).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxMempoolCost {
    /// Estimated gas cost for execution.
    pub gas_cost: u64,
    /// Maximum gas limit specified in the transaction.
    pub gas_limit: u64,
    /// Maximum fee the sender is willing to pay per unit of gas.
    pub max_fee_per_gas: u128,
    /// Total fee if all gas is consumed (gas_limit * max_fee_per_gas).
    pub effective_fee: u128,
    /// The actual fee density (max_fee_per_gas).
    pub fee_per_gas: u128,
}

/// Priority score for ranking transactions in the mempool (T169).
///
/// Transactions are ordered by:
/// 1. `fee_per_gas` (higher is better)
/// 2. `effective_fee` (higher is better)
/// 3. `arrival_id` (lower is better/older)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TxPriorityScore {
    /// Fee per gas (primary key).
    pub fee_per_gas: u128,
    /// Total effective fee (secondary key).
    pub effective_fee: u128,
    /// Monotonic arrival counter (tertiary key).
    pub arrival_id: u64,
}

impl Ord for TxPriorityScore {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.fee_per_gas
            .cmp(&other.fee_per_gas)
            .then_with(|| self.effective_fee.cmp(&other.effective_fee))
            // Lower arrival_id means higher priority (comes first in FIFO)
            // So we want smaller arrival_id to be "Greater" in priority
            .then_with(|| other.arrival_id.cmp(&self.arrival_id))
    }
}

impl PartialOrd for TxPriorityScore {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

/// Helper to compute mempool cost parameters for a transaction (T169).
pub fn compute_tx_mempool_cost(tx: &QbindTransaction) -> Result<TxMempoolCost, MempoolError> {
    use qbind_ledger::compute_gas_for_vm_v0_tx;

    let gas_result = compute_gas_for_vm_v0_tx(tx).map_err(|_| {
        MempoolError::Invalid("failed to compute gas: malformed payload".to_string())
    })?;

    let effective_fee = (gas_result.gas_limit as u128) * gas_result.max_fee_per_gas;

    Ok(TxMempoolCost {
        gas_cost: gas_result.gas_cost,
        gas_limit: gas_result.gas_limit,
        max_fee_per_gas: gas_result.max_fee_per_gas,
        effective_fee,
        fee_per_gas: gas_result.max_fee_per_gas,
    })
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
    /// Gas enforcement configuration (T168).
    /// When enabled, mempool performs gas legality and balance checks.
    pub gas_config: Option<qbind_ledger::ExecutionGasConfig>,
    /// T169: Whether to enable fee-based priority and eviction.
    /// When true, transactions are ranked by fee_per_gas and effective_fee.
    pub enable_fee_priority: bool,
}

impl MempoolConfig {
    /// Enforce configuration constraints (T169).
    ///
    /// This method ensures that:
    /// - If gas is disabled, fee priority is also disabled
    ///
    /// Returns a sanitized config.
    pub fn enforce_constraints(mut self) -> Self {
        if (self.gas_config.is_none() || !self.gas_config.as_ref().unwrap().enabled)
            && self.enable_fee_priority
        {
            // Fee priority requires gas enforcement; silently disable
            self.enable_fee_priority = false;
        }
        self
    }
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            max_txs: 10000,
            max_nonce_gap: 1000,
            gas_config: None, // Disabled by default for backward compatibility
            enable_fee_priority: false,
        }
    }
}

/// In-memory mempool implementation for QbindTransactions.
///
/// This is the reference implementation for T151 with T168 gas support:
/// - FIFO ordering (insertion order)
/// - Signature verification on admission
/// - Basic per-sender nonce tracking to prevent spam
/// - Capacity limits
/// - Gas legality and balance checks when enabled (T168)
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
    /// Optional balance provider for gas-aware admission (T168).
    /// Required when gas_config is enabled.
    balance_provider: Option<Arc<dyn BalanceProvider>>,
    /// Optional metrics for observability (T169).
    metrics: Option<Arc<MempoolMetrics>>,
}

/// Internal mempool state (protected by RwLock).
struct MempoolInner {
    /// Transactions in insertion order (FIFO mode).
    txs: Vec<QbindTransaction>,
    /// Priority-ordered transactions (Priority mode).
    priority_index: BTreeMap<TxPriorityScore, QbindTransaction>,
    /// Map of (sender, nonce) -> priority score for removal.
    tx_scores: HashMap<(AccountId, u64), TxPriorityScore>,
    /// Monotonic arrival counter for tie-breaking.
    arrival_counter: u64,
    /// Per-sender nonce tracking: sender -> max nonce seen.
    /// Used to reject txs with nonces far in the future (spam prevention).
    nonce_tracker: HashMap<AccountId, u64>,
}

impl MempoolInner {
    /// Get the total number of transactions in the mempool.
    fn tx_count(&self) -> usize {
        self.txs.len() + self.priority_index.len()
    }
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
                priority_index: BTreeMap::new(),
                tx_scores: HashMap::new(),
                arrival_counter: 0,
                nonce_tracker: HashMap::new(),
            }),
            config,
            key_provider: None,
            balance_provider: None,
            metrics: None,
        }
    }

    /// Set metrics for the mempool (T169).
    pub fn with_metrics(mut self, metrics: Arc<MempoolMetrics>) -> Self {
        metrics.set_priority_enabled(self.config.enable_fee_priority);
        self.metrics = Some(metrics);
        self
    }

    /// Create a mempool with a key provider for signature verification.
    pub fn with_key_provider(config: MempoolConfig, key_provider: Arc<dyn KeyProvider>) -> Self {
        Self {
            inner: RwLock::new(MempoolInner {
                txs: Vec::new(),
                priority_index: BTreeMap::new(),
                tx_scores: HashMap::new(),
                arrival_counter: 0,
                nonce_tracker: HashMap::new(),
            }),
            config,
            key_provider: Some(key_provider),
            balance_provider: None,
            metrics: None,
        }
    }

    /// Create a mempool with key and balance providers (T168).
    ///
    /// This constructor enables both signature verification and gas-aware admission.
    pub fn with_providers(
        config: MempoolConfig,
        key_provider: Arc<dyn KeyProvider>,
        balance_provider: Arc<dyn BalanceProvider>,
    ) -> Self {
        Self {
            inner: RwLock::new(MempoolInner {
                txs: Vec::new(),
                priority_index: BTreeMap::new(),
                tx_scores: HashMap::new(),
                arrival_counter: 0,
                nonce_tracker: HashMap::new(),
            }),
            config,
            key_provider: Some(key_provider),
            balance_provider: Some(balance_provider),
            metrics: None,
        }
    }

    /// Check if gas enforcement is enabled.
    pub fn is_gas_enabled(&self) -> bool {
        self.config
            .gas_config
            .as_ref()
            .map(|c| c.enabled)
            .unwrap_or(false)
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

        // 1. Capacity check & optional priority eviction (T169)
        if inner.tx_count() >= self.config.max_txs {
            if self.config.enable_fee_priority {
                let cost = compute_tx_mempool_cost(&tx)?;
                let score = TxPriorityScore {
                    fee_per_gas: cost.fee_per_gas,
                    effective_fee: cost.effective_fee,
                    arrival_id: inner.arrival_counter,
                };

                // Find the lowest priority entry
                if let Some((&lowest_score, _)) = inner.priority_index.iter().next() {
                    if score > lowest_score {
                        // Evict lowest
                        if let Some((_evicted_score, evicted_tx)) = inner.priority_index.pop_first()
                        {
                            inner
                                .tx_scores
                                .remove(&(evicted_tx.sender, evicted_tx.nonce));

                            if let Some(ref m) = self.metrics {
                                m.inc_evicted_low_priority();
                            }
                        }
                    } else {
                        if let Some(ref m) = self.metrics {
                            m.inc_rejected(MempoolRejectReason::LowPriority);
                        }
                        return Err(MempoolError::LowPriorityDropped);
                    }
                } else {
                    if let Some(ref m) = self.metrics {
                        m.inc_rejected(MempoolRejectReason::Full);
                    }
                    return Err(MempoolError::Full);
                }
            } else {
                if let Some(ref m) = self.metrics {
                    m.inc_rejected(MempoolRejectReason::Full);
                }
                return Err(MempoolError::Full);
            }
        }

        // 2. Signature verification (if key provider is set)
        if let Some(ref provider) = self.key_provider {
            let pk = provider.get_public_key(&tx.sender).map_err(|e| {
                if let Some(ref m) = self.metrics {
                    m.inc_rejected(MempoolRejectReason::Other);
                }
                MempoolError::Invalid(format!("key lookup failed: {}", e))
            })?;

            tx.verify_signature(&pk).map_err(|e| {
                if let Some(ref m) = self.metrics {
                    m.inc_rejected(MempoolRejectReason::InvalidSignature);
                }
                MempoolError::Invalid(format!("signature verification failed: {}", e))
            })?;
        }

        // 3. Gas legality and balance checks (T168) - only when gas is enabled
        if self.is_gas_enabled() {
            if let Err(e) = self.check_gas_admission(&tx) {
                if let Some(ref m) = self.metrics {
                    m.inc_rejected(MempoolRejectReason::Other);
                }
                return Err(e);
            }
        }

        // 4. Basic nonce sanity check (if max_nonce_gap > 0)
        if self.config.max_nonce_gap > 0 {
            const MAX_NONCE_GAP_BEHIND: u64 = 10; // How far behind max_nonce we allow

            if let Some(&max_nonce) = inner.nonce_tracker.get(&tx.sender) {
                // Reject if nonce is too far in the future
                if tx.nonce > max_nonce + self.config.max_nonce_gap {
                    if let Some(ref m) = self.metrics {
                        m.inc_rejected(MempoolRejectReason::InvalidNonce);
                    }
                    return Err(MempoolError::Invalid(format!(
                        "nonce {} too far ahead of max seen {} (gap limit {})",
                        tx.nonce, max_nonce, self.config.max_nonce_gap
                    )));
                }
                // Also reject if nonce is too far in the past (already executed)
                if tx.nonce < max_nonce.saturating_sub(MAX_NONCE_GAP_BEHIND) {
                    if let Some(ref m) = self.metrics {
                        m.inc_rejected(MempoolRejectReason::InvalidNonce);
                    }
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

        // 5. Insert the transaction
        if self.config.enable_fee_priority {
            let cost = compute_tx_mempool_cost(&tx)?;
            let score = TxPriorityScore {
                fee_per_gas: cost.fee_per_gas,
                effective_fee: cost.effective_fee,
                arrival_id: inner.arrival_counter,
            };
            inner.arrival_counter += 1;
            inner.tx_scores.insert((tx.sender, tx.nonce), score);
            inner.priority_index.insert(score, tx);
        } else {
            inner.txs.push(tx);
        }

        // Update metrics
        if let Some(ref m) = self.metrics {
            m.inc_inserted();
            m.set_size(inner.tx_count() as u64);
        }

        Ok(())
    }

    fn get_block_candidates(&self, max_txs: usize) -> Vec<QbindTransaction> {
        let inner = self.inner.read();

        if self.config.enable_fee_priority {
            // Priority mode: take up to max_txs from the back (highest priority)
            inner
                .priority_index
                .values()
                .rev()
                .take(max_txs)
                .cloned()
                .collect()
        } else {
            // Simple FIFO: take up to max_txs from the front
            inner.txs.iter().take(max_txs).cloned().collect()
        }
    }

    fn remove_committed(&self, committed: &[QbindTransaction]) {
        let mut inner = self.inner.write();

        if self.config.enable_fee_priority {
            // Priority mode: remove by score
            for committed_tx in committed {
                if let Some(score) = inner
                    .tx_scores
                    .remove(&(committed_tx.sender, committed_tx.nonce))
                {
                    inner.priority_index.remove(&score);
                    if let Some(ref m) = self.metrics {
                        m.inc_committed();
                    }
                }
            }
        } else {
            // FIFO mode: remove matching (sender, nonce) from mempool
            for committed_tx in committed {
                let old_len = inner.txs.len();
                inner.txs.retain(|tx| {
                    tx.sender != committed_tx.sender || tx.nonce != committed_tx.nonce
                });

                if let Some(ref m) = self.metrics {
                    if inner.txs.len() < old_len {
                        m.inc_committed();
                    }
                }
            }
        }

        // Update size metric
        if let Some(ref m) = self.metrics {
            m.set_size(inner.tx_count() as u64);
        }
    }

    fn size(&self) -> usize {
        let inner = self.inner.read();
        inner.tx_count()
    }
}

impl InMemoryMempool {
    /// Check gas legality and balance for a transaction (T168).
    ///
    /// This is called during admission when gas enforcement is enabled.
    fn check_gas_admission(&self, tx: &QbindTransaction) -> Result<(), MempoolError> {
        use qbind_ledger::compute_gas_for_vm_v0_tx;

        // Compute gas cost and parameters
        let gas_result = compute_gas_for_vm_v0_tx(tx).map_err(|_| {
            MempoolError::Invalid("failed to compute gas: malformed payload".to_string())
        })?;

        let gas_cost = gas_result.gas_cost;
        let gas_limit = gas_result.gas_limit;
        let max_fee_per_gas = gas_result.max_fee_per_gas;

        // Check gas limit is sufficient
        if gas_cost > gas_limit {
            return Err(MempoolError::InsufficientGasLimit {
                required: gas_cost,
                limit: gas_limit,
            });
        }

        // Check balance is sufficient for amount + max_fee (if balance provider is available)
        if let Some(ref balance_provider) = self.balance_provider {
            // Decode payload to get amount
            let amount = match qbind_ledger::decode_transfer_payload(&tx.payload) {
                Ok(qbind_ledger::TransferPayloadDecoded::V0(p)) => p.amount,
                Ok(qbind_ledger::TransferPayloadDecoded::V1(p)) => p.amount,
                Err(_) => {
                    return Err(MempoolError::Invalid(
                        "malformed payload for balance check".to_string(),
                    ))
                }
            };

            // Compute max fee (worst case: all gas used)
            let max_fee = (gas_limit as u128) * max_fee_per_gas;
            let total_needed = amount.saturating_add(max_fee);

            // Get sender's balance
            let sender_balance = balance_provider.get_balance(&tx.sender);

            if sender_balance < total_needed {
                return Err(MempoolError::InsufficientBalanceForFee {
                    balance: sender_balance,
                    needed: total_needed,
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Balance Provider Trait (T168)
// ============================================================================

/// Trait for querying account balances for gas-aware mempool admission (T168).
///
/// This abstraction allows different implementations:
/// - Test mode: in-memory map of account -> balance
/// - Production: query current execution state
pub trait BalanceProvider: Send + Sync {
    /// Get the current balance for an account.
    ///
    /// # Arguments
    ///
    /// * `account` - The account ID
    ///
    /// # Returns
    ///
    /// The account balance, or 0 if the account doesn't exist.
    fn get_balance(&self, account: &AccountId) -> u128;
}

/// Simple in-memory balance provider for testing (T168).
pub struct InMemoryBalanceProvider {
    balances: parking_lot::RwLock<HashMap<AccountId, u128>>,
}

impl InMemoryBalanceProvider {
    /// Create an empty balance provider.
    pub fn new() -> Self {
        Self {
            balances: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    /// Set the balance for an account.
    pub fn set_balance(&self, account: AccountId, balance: u128) {
        self.balances.write().insert(account, balance);
    }
}

impl Default for InMemoryBalanceProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl BalanceProvider for InMemoryBalanceProvider {
    fn get_balance(&self, account: &AccountId) -> u128 {
        self.balances.read().get(account).copied().unwrap_or(0)
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
            gas_config: None,
            enable_fee_priority: false,
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
            gas_config: None,
            enable_fee_priority: false,
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
            gas_config: None,
            enable_fee_priority: false,
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
            gas_config: None,
            enable_fee_priority: false,
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
