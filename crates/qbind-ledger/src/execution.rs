//! Execution layer abstractions for T150.
//!
//! This module provides the core execution types and traits for the QBIND
//! post-quantum blockchain's L1 execution layer:
//!
//! - `QbindTransaction`: PQC-signed user transaction model
//! - `StateView` / `StateUpdater`: Key-value state access traits
//! - `ExecutionEngine`: Transaction execution interface
//! - `InMemoryState`: Simple in-memory state implementation
//! - `NonceExecutionEngine`: Reference implementation tracking account nonces
//!
//! ## Design Goals
//!
//! 1. Clean separation between consensus and execution
//! 2. PQC (ML-DSA-44) signatures for user transactions
//! 3. Deterministic state transitions
//! 4. Extensible for future VM, gas, and L2 integration
//!
//! ## Non-Goals for T150
//!
//! - Full VM implementation
//! - Gas accounting beyond placeholders
//! - Balance transfers or token logic
//!
//! ## T159: Chain-Aware Domain Separation
//!
//! As of T159, all signing preimages include the chain ID to prevent cross-chain
//! replay attacks. Use `signing_preimage_with_chain_id()` with the appropriate
//! `ChainId` for the network environment (DevNet, TestNet, MainNet).

use qbind_crypto::ml_dsa44::{MlDsa44Backend, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE};
use qbind_types::domain::{domain_prefix, DomainKind};
use qbind_types::{AccountId, ChainId, QBIND_DEVNET_CHAIN_ID};
use std::collections::HashMap;

// ============================================================================
// User Public Key and Signature Types
// ============================================================================

/// ML-DSA-44 suite ID for user transactions.
///
/// This is distinct from the consensus suite ID. User transactions use
/// ML-DSA-44 (suite_id = 100) to sign payloads.
pub const USER_ML_DSA_44_SUITE_ID: u16 = 100;

/// A user's public key for transaction verification.
///
/// Currently uses ML-DSA-44 (1312 bytes). The suite_id field allows
/// future cryptographic agility.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserPublicKey {
    /// The raw public key bytes.
    pub bytes: Vec<u8>,
    /// The signature suite identifier.
    pub suite_id: u16,
}

impl UserPublicKey {
    /// Create a new user public key with ML-DSA-44 suite.
    pub fn ml_dsa_44(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
            suite_id: USER_ML_DSA_44_SUITE_ID,
        }
    }

    /// Get the public key bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// A user signature over a transaction.
///
/// Currently uses ML-DSA-44 (2420 bytes max). The suite_id is carried
/// in the transaction itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UserSignature {
    /// The raw signature bytes.
    pub bytes: Vec<u8>,
}

impl UserSignature {
    /// Create a new user signature from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Get the signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ============================================================================
// Transaction Model
// ============================================================================

/// Legacy domain separator for QbindTransaction signing preimages.
///
/// **DEPRECATED (T159)**: Use `domain_prefix(chain_id, DomainKind::UserTx)` instead.
///
/// This constant is provided for backward compatibility. New code should use
/// `signing_preimage_with_chain_id()` with the appropriate `ChainId`.
///
/// Changing this is a consensus-breaking change.
pub const TX_DOMAIN_TAG: &[u8] = b"QBIND:TX:v1";

/// A QBIND L1 user transaction with PQC signature.
///
/// This transaction model is intentionally minimal for T150:
/// - `sender`: The account initiating the transaction
/// - `nonce`: Replay protection (must match sender's stored nonce)
/// - `payload`: Opaque data (interpreted by higher layers)
/// - `signature`: ML-DSA-44 signature over the signing preimage
/// - `suite_id`: Signature suite identifier (100 = ML-DSA-44)
///
/// ## Signing (T159: Chain-Aware)
///
/// The signature covers `signing_preimage_with_chain_id(chain_id)`, which includes:
/// - Domain tag (e.g., "QBIND:DEV:TX:v1" for DevNet)
/// - sender (32 bytes)
/// - nonce (8 bytes, little-endian)
/// - payload length (4 bytes, little-endian)
/// - payload bytes
/// - suite_id (2 bytes, little-endian)
///
/// ## Verification
///
/// Use `verify_signature_with_chain_id()` with the sender's `UserPublicKey` and the
/// chain ID for the network environment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QbindTransaction {
    /// The account ID of the sender.
    pub sender: AccountId,
    /// The transaction nonce (must match stored nonce for sender).
    pub nonce: u64,
    /// Opaque payload data.
    pub payload: Vec<u8>,
    /// ML-DSA-44 signature over the signing preimage.
    pub signature: UserSignature,
    /// Signature suite identifier (100 = ML-DSA-44 for user txs).
    pub suite_id: u16,
}

impl QbindTransaction {
    /// Create a new unsigned transaction.
    ///
    /// Use `sign_with_chain_id()` or set `signature` manually after calling this.
    pub fn new(sender: AccountId, nonce: u64, payload: Vec<u8>) -> Self {
        Self {
            sender,
            nonce,
            payload,
            signature: UserSignature::new(Vec::new()),
            suite_id: USER_ML_DSA_44_SUITE_ID,
        }
    }

    /// Compute the canonical signing preimage for this transaction with chain ID (T159).
    ///
    /// The preimage layout is:
    /// ```text
    /// domain_tag:   "QBIND:<SCOPE>:TX:v1" (variable length based on scope)
    /// sender:       [u8; 32]
    /// nonce:        u64 (little-endian)
    /// payload_len:  u32 (little-endian)
    /// payload:      [u8; payload_len]
    /// suite_id:     u16 (little-endian)
    /// ```
    ///
    /// Where `<SCOPE>` is:
    /// - "DEV" for DevNet (`QBIND_DEVNET_CHAIN_ID`)
    /// - "TST" for TestNet (`QBIND_TESTNET_CHAIN_ID`)
    /// - "MAIN" for MainNet (`QBIND_MAINNET_CHAIN_ID`)
    ///
    /// Note: The signature field is NOT included in the preimage.
    pub fn signing_preimage_with_chain_id(&self, chain_id: ChainId) -> Vec<u8> {
        let domain_tag = domain_prefix(chain_id, DomainKind::UserTx);
        let mut out = Vec::with_capacity(domain_tag.len() + 32 + 8 + 4 + self.payload.len() + 2);

        // Domain separator (chain-aware)
        out.extend_from_slice(&domain_tag);

        // sender (32 bytes)
        out.extend_from_slice(&self.sender);

        // nonce (u64, little-endian)
        out.extend_from_slice(&self.nonce.to_le_bytes());

        // payload_len (u32, little-endian) + payload
        let payload_len = self.payload.len() as u32;
        out.extend_from_slice(&payload_len.to_le_bytes());
        out.extend_from_slice(&self.payload);

        // suite_id (u16, little-endian)
        out.extend_from_slice(&self.suite_id.to_le_bytes());

        out
    }

    /// Compute the signing preimage using the default DevNet chain ID.
    ///
    /// **Note (T159)**: This method defaults to `QBIND_DEVNET_CHAIN_ID`. For
    /// explicit chain control, use `signing_preimage_with_chain_id()` instead.
    ///
    /// The preimage layout is:
    /// ```text
    /// domain_tag:   "QBIND:DEV:TX:v1" (15 bytes for DevNet)
    /// sender:       [u8; 32]
    /// nonce:        u64 (little-endian)
    /// payload_len:  u32 (little-endian)
    /// payload:      [u8; payload_len]
    /// suite_id:     u16 (little-endian)
    /// ```
    ///
    /// Note: The signature field is NOT included in the preimage.
    pub fn signing_preimage(&self) -> Vec<u8> {
        self.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID)
    }

    /// Verify the transaction signature against the given public key with chain ID (T159).
    ///
    /// # Arguments
    ///
    /// * `pk` - The sender's public key (must be ML-DSA-44 for suite_id = 100)
    /// * `chain_id` - The chain ID for domain separation
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(TxVerifyError)` otherwise.
    pub fn verify_signature_with_chain_id(
        &self,
        pk: &UserPublicKey,
        chain_id: ChainId,
    ) -> Result<(), TxVerifyError> {
        // Check suite_id compatibility
        if self.suite_id != pk.suite_id {
            return Err(TxVerifyError::SuiteMismatch {
                tx_suite: self.suite_id,
                pk_suite: pk.suite_id,
            });
        }

        // Currently only ML-DSA-44 is supported
        if self.suite_id != USER_ML_DSA_44_SUITE_ID {
            return Err(TxVerifyError::UnsupportedSuite(self.suite_id));
        }

        // Check key size
        if pk.bytes.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(TxVerifyError::InvalidPublicKey);
        }

        // Check signature size
        if self.signature.bytes.len() != ML_DSA_44_SIGNATURE_SIZE {
            return Err(TxVerifyError::InvalidSignature);
        }

        // Compute preimage and verify with chain ID
        let preimage = self.signing_preimage_with_chain_id(chain_id);

        MlDsa44Backend::verify(&pk.bytes, &preimage, &self.signature.bytes)
            .map_err(|_| TxVerifyError::SignatureVerificationFailed)
    }

    /// Verify the transaction signature using the default DevNet chain ID.
    ///
    /// **Note (T159)**: This method defaults to `QBIND_DEVNET_CHAIN_ID`. For
    /// explicit chain control, use `verify_signature_with_chain_id()` instead.
    ///
    /// # Arguments
    ///
    /// * `pk` - The sender's public key (must be ML-DSA-44 for suite_id = 100)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err(TxVerifyError)` otherwise.
    pub fn verify_signature(&self, pk: &UserPublicKey) -> Result<(), TxVerifyError> {
        self.verify_signature_with_chain_id(pk, QBIND_DEVNET_CHAIN_ID)
    }

    /// Sign this transaction with the given secret key and chain ID (T159).
    ///
    /// This sets the `signature` field using ML-DSA-44.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key bytes (must be ML_DSA_44_SECRET_KEY_SIZE bytes)
    /// * `chain_id` - The chain ID for domain separation
    ///
    /// # Returns
    ///
    /// `Ok(())` if signing succeeded, `Err` otherwise.
    pub fn sign_with_chain_id(
        &mut self,
        sk: &[u8],
        chain_id: ChainId,
    ) -> Result<(), TxVerifyError> {
        let preimage = self.signing_preimage_with_chain_id(chain_id);
        let sig_bytes =
            MlDsa44Backend::sign(sk, &preimage).map_err(|_| TxVerifyError::SigningFailed)?;
        self.signature = UserSignature::new(sig_bytes);
        Ok(())
    }

    /// Sign this transaction using the default DevNet chain ID.
    ///
    /// **Note (T159)**: This method defaults to `QBIND_DEVNET_CHAIN_ID`. For
    /// explicit chain control, use `sign_with_chain_id()` instead.
    ///
    /// This sets the `signature` field using ML-DSA-44.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key bytes (must be ML_DSA_44_SECRET_KEY_SIZE bytes)
    ///
    /// # Returns
    ///
    /// `Ok(())` if signing succeeded, `Err` otherwise.
    pub fn sign(&mut self, sk: &[u8]) -> Result<(), TxVerifyError> {
        self.sign_with_chain_id(sk, QBIND_DEVNET_CHAIN_ID)
    }
}

/// Errors that can occur during transaction verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxVerifyError {
    /// Transaction suite_id doesn't match public key suite_id.
    SuiteMismatch { tx_suite: u16, pk_suite: u16 },
    /// Signature suite is not supported.
    UnsupportedSuite(u16),
    /// Public key is malformed or wrong size.
    InvalidPublicKey,
    /// Signature is malformed or wrong size.
    InvalidSignature,
    /// Signature verification failed (signature doesn't match message/key).
    SignatureVerificationFailed,
    /// Signing operation failed.
    SigningFailed,
}

impl std::fmt::Display for TxVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TxVerifyError::SuiteMismatch { tx_suite, pk_suite } => {
                write!(
                    f,
                    "suite mismatch: tx suite_id={}, pk suite_id={}",
                    tx_suite, pk_suite
                )
            }
            TxVerifyError::UnsupportedSuite(id) => write!(f, "unsupported suite_id: {}", id),
            TxVerifyError::InvalidPublicKey => write!(f, "invalid public key"),
            TxVerifyError::InvalidSignature => write!(f, "invalid signature"),
            TxVerifyError::SignatureVerificationFailed => {
                write!(f, "signature verification failed")
            }
            TxVerifyError::SigningFailed => write!(f, "signing failed"),
        }
    }
}

impl std::error::Error for TxVerifyError {}

// ============================================================================
// State Traits
// ============================================================================

/// Read-only view of state.
///
/// State is a key-value store with byte keys and byte values.
pub trait StateView {
    /// Get the value for a key, or None if not present.
    fn get(&self, key: &[u8]) -> Option<Vec<u8>>;
}

/// Mutable state updater.
///
/// Provides put and delete operations for state modifications.
pub trait StateUpdater: StateView {
    /// Set a key to a value.
    fn put(&mut self, key: &[u8], value: Vec<u8>);

    /// Delete a key.
    fn delete(&mut self, key: &[u8]);
}

// ============================================================================
// In-Memory State
// ============================================================================

/// Simple in-memory key-value state implementation.
///
/// This is suitable for testing and lightweight execution scenarios.
/// Production deployments should use a persistent backend.
#[derive(Debug, Clone, Default)]
pub struct InMemoryState {
    inner: HashMap<Vec<u8>, Vec<u8>>,
}

impl InMemoryState {
    /// Create a new empty in-memory state.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Get the number of keys in the state.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the state is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over all key-value pairs.
    pub fn iter(&self) -> impl Iterator<Item = (&Vec<u8>, &Vec<u8>)> {
        self.inner.iter()
    }
}

impl StateView for InMemoryState {
    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.inner.get(key).cloned()
    }
}

impl StateUpdater for InMemoryState {
    fn put(&mut self, key: &[u8], value: Vec<u8>) {
        self.inner.insert(key.to_vec(), value);
    }

    fn delete(&mut self, key: &[u8]) {
        self.inner.remove(key);
    }
}

// ============================================================================
// Execution Types
// ============================================================================

/// Events emitted during transaction execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEvent {
    /// A transaction was successfully accepted.
    TxAccepted {
        /// The sender account ID.
        sender: AccountId,
        /// The transaction nonce.
        nonce: u64,
    },
    /// A transaction failed validation.
    TxRejected {
        /// The sender account ID.
        sender: AccountId,
        /// Reason for rejection.
        reason: String,
    },
}

/// Outcome of executing a single transaction.
#[derive(Debug, Clone)]
pub struct ExecutionOutcome {
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Events emitted during execution.
    pub events: Vec<ExecutionEvent>,
    /// Gas used (placeholder for future gas accounting).
    pub gas_used: u64,
}

impl ExecutionOutcome {
    /// Create a successful outcome with events.
    pub fn success(events: Vec<ExecutionEvent>, gas_used: u64) -> Self {
        Self {
            success: true,
            events,
            gas_used,
        }
    }

    /// Create a failed outcome.
    pub fn failure(events: Vec<ExecutionEvent>, gas_used: u64) -> Self {
        Self {
            success: false,
            events,
            gas_used,
        }
    }
}

/// Errors that can occur during transaction execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExecutionEngineError {
    /// Transaction signature is invalid.
    InvalidSignature,
    /// Transaction nonce doesn't match expected value.
    NonceMismatch {
        /// The expected nonce (from state).
        expected: u64,
        /// The actual nonce (in transaction).
        actual: u64,
    },
    /// Account not found in state.
    AccountNotFound,
    /// Internal execution error.
    InternalError(String),
}

impl std::fmt::Display for ExecutionEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExecutionEngineError::InvalidSignature => write!(f, "invalid signature"),
            ExecutionEngineError::NonceMismatch { expected, actual } => {
                write!(f, "nonce mismatch: expected {}, got {}", expected, actual)
            }
            ExecutionEngineError::AccountNotFound => write!(f, "account not found"),
            ExecutionEngineError::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl std::error::Error for ExecutionEngineError {}

// ============================================================================
// Execution Engine Trait
// ============================================================================

/// Execution engine interface.
///
/// An execution engine processes transactions against state and produces
/// outcomes. Different engines can implement different execution semantics
/// (nonce-only, VM-based, etc.).
pub trait ExecutionEngine: Send + Sync {
    /// Execute a transaction against state.
    ///
    /// # Arguments
    ///
    /// * `state` - Mutable state to read from and write to
    /// * `tx` - The transaction to execute
    ///
    /// # Returns
    ///
    /// `Ok(ExecutionOutcome)` on success, `Err(ExecutionEngineError)` on failure.
    ///
    /// # Note
    ///
    /// On error, the engine should NOT have modified state. Implementations
    /// should either:
    /// 1. Check all preconditions before modifying state, OR
    /// 2. Use a transaction/rollback mechanism
    fn execute_tx(
        &self,
        state: &mut dyn StateUpdater,
        tx: &QbindTransaction,
    ) -> Result<ExecutionOutcome, ExecutionEngineError>;
}

// ============================================================================
// Nonce-Only Reference Execution Engine
// ============================================================================

/// Key prefix for account nonces in state.
pub const NONCE_KEY_PREFIX: &[u8] = b"nonce:";

/// Build the nonce key for an account.
fn nonce_key(account_id: &AccountId) -> Vec<u8> {
    let mut key = Vec::with_capacity(NONCE_KEY_PREFIX.len() + 32);
    key.extend_from_slice(NONCE_KEY_PREFIX);
    key.extend_from_slice(account_id);
    key
}

/// Get the current nonce for an account from state.
///
/// Returns 0 if the account has no nonce entry (new account).
pub fn get_account_nonce(state: &dyn StateView, account_id: &AccountId) -> u64 {
    let key = nonce_key(account_id);
    match state.get(&key) {
        Some(bytes) if bytes.len() == 8 => {
            let arr: [u8; 8] = bytes.try_into().unwrap();
            u64::from_le_bytes(arr)
        }
        _ => 0,
    }
}

/// Set the nonce for an account in state.
pub fn set_account_nonce(state: &mut dyn StateUpdater, account_id: &AccountId, nonce: u64) {
    let key = nonce_key(account_id);
    state.put(&key, nonce.to_le_bytes().to_vec());
}

/// A reference execution engine that only tracks account nonces.
///
/// This is the minimal T150 implementation:
/// 1. Verifies transaction signature (if `verify_signatures` is true)
/// 2. Checks nonce matches stored value
/// 3. Increments nonce on success
/// 4. Emits `TxAccepted` event
///
/// ## Nonce Semantics
///
/// For a new account (no nonce in state), the expected nonce is 0.
/// Each successful transaction increments the nonce by 1.
///
/// ## Signature Verification
///
/// When `verify_signatures` is true, the engine looks up the sender's
/// public key using the provided key lookup function. If no function
/// is provided or the key is not found, signature verification fails.
#[derive(Clone)]
pub struct NonceExecutionEngine {
    /// Whether to verify transaction signatures.
    verify_signatures: bool,
    /// Optional public key lookup for signature verification.
    /// Takes an AccountId and returns the UserPublicKey, if known.
    #[allow(clippy::type_complexity)]
    pk_lookup: Option<std::sync::Arc<dyn Fn(&AccountId) -> Option<UserPublicKey> + Send + Sync>>,
}

impl Default for NonceExecutionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl NonceExecutionEngine {
    /// Create a new nonce execution engine with signature verification disabled.
    ///
    /// Use `with_signature_verification()` to enable signature checks.
    pub fn new() -> Self {
        Self {
            verify_signatures: false,
            pk_lookup: None,
        }
    }

    /// Enable signature verification with the given public key lookup.
    ///
    /// # Arguments
    ///
    /// * `pk_lookup` - Function that returns the public key for an account ID
    pub fn with_signature_verification<F>(mut self, pk_lookup: F) -> Self
    where
        F: Fn(&AccountId) -> Option<UserPublicKey> + Send + Sync + 'static,
    {
        self.verify_signatures = true;
        self.pk_lookup = Some(std::sync::Arc::new(pk_lookup));
        self
    }

    /// Create an engine with signature verification enabled but no key lookup.
    ///
    /// Signature verification will always fail because no keys can be found.
    /// This is useful for testing error paths.
    pub fn with_signature_verification_no_keys(mut self) -> Self {
        self.verify_signatures = true;
        self.pk_lookup = None;
        self
    }
}

impl std::fmt::Debug for NonceExecutionEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NonceExecutionEngine")
            .field("verify_signatures", &self.verify_signatures)
            .field("has_pk_lookup", &self.pk_lookup.is_some())
            .finish()
    }
}

impl ExecutionEngine for NonceExecutionEngine {
    fn execute_tx(
        &self,
        state: &mut dyn StateUpdater,
        tx: &QbindTransaction,
    ) -> Result<ExecutionOutcome, ExecutionEngineError> {
        // 1. Verify signature (if enabled)
        if self.verify_signatures {
            let pk = match &self.pk_lookup {
                Some(lookup) => lookup(&tx.sender).ok_or(ExecutionEngineError::AccountNotFound)?,
                None => return Err(ExecutionEngineError::AccountNotFound),
            };

            tx.verify_signature(&pk)
                .map_err(|_| ExecutionEngineError::InvalidSignature)?;
        }

        // 2. Check nonce
        let stored_nonce = get_account_nonce(state, &tx.sender);
        if tx.nonce != stored_nonce {
            return Err(ExecutionEngineError::NonceMismatch {
                expected: stored_nonce,
                actual: tx.nonce,
            });
        }

        // 3. Update nonce
        let new_nonce = stored_nonce + 1;
        set_account_nonce(state, &tx.sender, new_nonce);

        // 4. Emit event
        let event = ExecutionEvent::TxAccepted {
            sender: tx.sender,
            nonce: tx.nonce,
        };

        Ok(ExecutionOutcome::success(vec![event], 0))
    }
}

// ============================================================================
// T157: Stage A Parallel Execution (Sender-Partitioned)
// ============================================================================

use rayon::prelude::*;

/// Transaction receipt for execution result tracking.
///
/// This mirrors `ExecutionOutcome` but is designed for lightweight result
/// aggregation in parallel execution scenarios.
#[derive(Debug, Clone)]
pub struct TxReceipt {
    /// Whether the transaction succeeded.
    pub success: bool,
    /// Events emitted during execution.
    pub events: Vec<ExecutionEvent>,
    /// Gas used (placeholder).
    pub gas_used: u64,
}

impl TxReceipt {
    /// Create a success receipt.
    pub fn success(events: Vec<ExecutionEvent>, gas_used: u64) -> Self {
        Self {
            success: true,
            events,
            gas_used,
        }
    }

    /// Create a failure receipt.
    pub fn failure(events: Vec<ExecutionEvent>, gas_used: u64) -> Self {
        Self {
            success: false,
            events,
            gas_used,
        }
    }

    /// Convert from ExecutionOutcome.
    pub fn from_outcome(outcome: ExecutionOutcome) -> Self {
        Self {
            success: outcome.success,
            events: outcome.events,
            gas_used: outcome.gas_used,
        }
    }
}

/// Configuration for Stage A parallel execution.
///
/// # Parameters
///
/// * `max_workers` - Maximum worker threads. 0 means auto-detect (rayon default).
/// * `min_senders_for_parallel` - Minimum distinct senders required to use parallel
///   execution. Below this threshold, falls back to sequential for lower overhead.
#[derive(Debug, Clone)]
pub struct ParallelExecConfig {
    /// Maximum worker threads (0 = auto-detect from available cores).
    pub max_workers: usize,
    /// Minimum number of distinct senders to enable parallel execution.
    /// Below this threshold, fall back to sequential for lower overhead.
    pub min_senders_for_parallel: usize,
}

impl Default for ParallelExecConfig {
    fn default() -> Self {
        Self {
            max_workers: 0, // Auto-detect
            min_senders_for_parallel: 2,
        }
    }
}

impl ParallelExecConfig {
    /// Create a new config with default settings.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum worker threads.
    pub fn with_max_workers(mut self, workers: usize) -> Self {
        self.max_workers = workers;
        self
    }

    /// Set minimum senders threshold for parallel execution.
    pub fn with_min_senders(mut self, min_senders: usize) -> Self {
        self.min_senders_for_parallel = min_senders;
        self
    }

    /// Create a config that forces sequential execution.
    pub fn sequential() -> Self {
        Self {
            max_workers: 1,
            min_senders_for_parallel: usize::MAX,
        }
    }
}

/// Execution statistics from parallel block execution.
///
/// These stats are used for metrics and observability.
#[derive(Debug, Clone, Default)]
pub struct ParallelExecStats {
    /// Number of distinct senders (partitions) in the block.
    pub num_senders: usize,
    /// Number of workers actually used (may be less than num_senders).
    pub workers_used: usize,
    /// Whether parallel execution was used (vs sequential fallback).
    pub used_parallel: bool,
}

/// Stage A sender-partitioned parallel executor for the nonce-only engine.
///
/// This executor implements Stage A of the QBIND parallel execution design:
/// - Partition transactions by sender
/// - Execute per-sender chains in parallel
/// - Merge nonce updates back into state (commutative for nonce-only)
/// - Reassemble receipts in original block order
///
/// # Determinism Guarantee
///
/// For the nonce-only engine, any schedule that:
/// - Preserves per-sender order, and
/// - Applies all transactions in the block
///
/// yields the same final state and the same set of receipts.
///
/// # Thread Safety
///
/// This executor is `Send + Sync` and can be shared across threads.
/// It uses rayon for work-stealing parallel execution.
pub struct SenderPartitionedNonceExecutor {
    /// Configuration for parallel execution.
    config: ParallelExecConfig,
}

impl std::fmt::Debug for SenderPartitionedNonceExecutor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderPartitionedNonceExecutor")
            .field("config", &self.config)
            .finish()
    }
}

/// Internal structure for tracking indexed transactions.
struct IndexedTx {
    /// Original index in the block's transaction list.
    index: usize,
    /// The transaction.
    tx: QbindTransaction,
}

/// Per-sender execution result.
struct SenderResult {
    /// The sender's account ID.
    sender: AccountId,
    /// Final nonce after executing all transactions.
    final_nonce: u64,
    /// Receipts with their original indices.
    receipts: Vec<(usize, TxReceipt)>,
}

impl SenderPartitionedNonceExecutor {
    /// Create a new parallel executor with the given configuration.
    pub fn new(config: ParallelExecConfig) -> Self {
        Self { config }
    }

    /// Create a new parallel executor with default configuration.
    pub fn default_config() -> Self {
        Self::new(ParallelExecConfig::default())
    }

    /// Get the executor configuration.
    pub fn config(&self) -> &ParallelExecConfig {
        &self.config
    }

    /// Execute a block using sender-partitioned parallel execution.
    ///
    /// This is the main entry point for Stage A parallel execution.
    ///
    /// # Arguments
    ///
    /// * `transactions` - The transactions to execute in block order
    /// * `state` - The mutable state to execute against
    ///
    /// # Returns
    ///
    /// A tuple of (receipts, stats) where receipts are in the same order as
    /// the input transactions.
    ///
    /// # Errors
    ///
    /// Returns an error only for internal failures (e.g., thread panic).
    /// Individual transaction failures are recorded in receipts.
    pub fn execute_block_sender_partitioned(
        &self,
        transactions: &[QbindTransaction],
        state: &mut InMemoryState,
    ) -> Result<(Vec<TxReceipt>, ParallelExecStats), ExecutionEngineError> {
        if transactions.is_empty() {
            return Ok((
                Vec::new(),
                ParallelExecStats {
                    num_senders: 0,
                    workers_used: 0,
                    used_parallel: false,
                },
            ));
        }

        // Step 1: Partition by sender while preserving original indices
        let mut per_sender: HashMap<AccountId, Vec<IndexedTx>> = HashMap::new();
        for (index, tx) in transactions.iter().enumerate() {
            per_sender.entry(tx.sender).or_default().push(IndexedTx {
                index,
                tx: tx.clone(),
            });
        }

        let num_senders = per_sender.len();

        // Step 2: Decide whether to parallelize
        let use_parallel =
            num_senders >= self.config.min_senders_for_parallel && self.config.max_workers != 1;

        // Step 3: Fetch initial nonces for each sender
        let sender_initial_nonces: HashMap<AccountId, u64> = per_sender
            .keys()
            .map(|sender| (*sender, get_account_nonce(state, sender)))
            .collect();

        // Step 4: Execute (parallel or sequential)
        let sender_results: Vec<SenderResult> = if use_parallel {
            self.execute_parallel(&per_sender, &sender_initial_nonces)
        } else {
            self.execute_sequential(&per_sender, &sender_initial_nonces)
        };

        let workers_used = if use_parallel {
            num_senders.min(rayon::current_num_threads())
        } else {
            1
        };

        // Step 5: Merge per-sender nonce updates into state
        for result in &sender_results {
            set_account_nonce(state, &result.sender, result.final_nonce);
        }

        // Step 6: Reassemble receipts in original block order
        let mut receipts: Vec<Option<TxReceipt>> = vec![None; transactions.len()];
        for result in sender_results {
            for (index, receipt) in result.receipts {
                receipts[index] = Some(receipt);
            }
        }

        // Verify no gaps (should never happen if algorithm is correct)
        let receipts: Vec<TxReceipt> = receipts
            .into_iter()
            .enumerate()
            .map(|(i, r)| {
                r.ok_or_else(|| {
                    ExecutionEngineError::InternalError(format!("missing receipt for tx {}", i))
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let stats = ParallelExecStats {
            num_senders,
            workers_used,
            used_parallel: use_parallel,
        };

        Ok((receipts, stats))
    }

    /// Execute transactions sequentially (fallback path).
    fn execute_sequential(
        &self,
        per_sender: &HashMap<AccountId, Vec<IndexedTx>>,
        initial_nonces: &HashMap<AccountId, u64>,
    ) -> Vec<SenderResult> {
        per_sender
            .iter()
            .map(|(sender, indexed_txs)| {
                let initial_nonce = *initial_nonces.get(sender).unwrap_or(&0);
                self.execute_sender_chain(*sender, indexed_txs, initial_nonce)
            })
            .collect()
    }

    /// Execute transactions in parallel using rayon.
    fn execute_parallel(
        &self,
        per_sender: &HashMap<AccountId, Vec<IndexedTx>>,
        initial_nonces: &HashMap<AccountId, u64>,
    ) -> Vec<SenderResult> {
        // Collect into Vec for parallel iteration (HashMap doesn't implement IntoParallelIterator)
        let sender_chains: Vec<_> = per_sender.iter().collect();

        sender_chains
            .par_iter()
            .map(|(sender, indexed_txs)| {
                let initial_nonce = *initial_nonces.get(*sender).unwrap_or(&0);
                self.execute_sender_chain(**sender, indexed_txs, initial_nonce)
            })
            .collect()
    }

    /// Execute a single sender's transaction chain.
    ///
    /// This is the core execution logic for one sender. Transactions are
    /// executed in order, checking nonces and incrementing on success.
    fn execute_sender_chain(
        &self,
        sender: AccountId,
        indexed_txs: &[IndexedTx],
        initial_nonce: u64,
    ) -> SenderResult {
        let mut local_nonce = initial_nonce;
        let mut receipts = Vec::with_capacity(indexed_txs.len());

        for itx in indexed_txs {
            let receipt = if itx.tx.nonce == local_nonce {
                // Success: increment nonce
                local_nonce += 1;
                TxReceipt::success(
                    vec![ExecutionEvent::TxAccepted {
                        sender,
                        nonce: itx.tx.nonce,
                    }],
                    0,
                )
            } else {
                // Nonce mismatch: record failure but continue processing
                TxReceipt::failure(
                    vec![ExecutionEvent::TxRejected {
                        sender,
                        reason: format!(
                            "nonce mismatch: expected {}, got {}",
                            local_nonce, itx.tx.nonce
                        ),
                    }],
                    0,
                )
            };
            receipts.push((itx.index, receipt));
        }

        SenderResult {
            sender,
            final_nonce: local_nonce,
            receipts,
        }
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

    #[test]
    fn test_signing_preimage_is_stable() {
        let sender = test_account_id(0xAA);
        let tx = QbindTransaction::new(sender, 42, b"hello".to_vec());

        let preimage1 = tx.signing_preimage();
        let preimage2 = tx.signing_preimage();

        assert_eq!(preimage1, preimage2, "preimage should be deterministic");

        // T159: Default signing_preimage() uses DevNet chain ID
        let devnet_tx_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::UserTx);
        assert!(
            preimage1.starts_with(&devnet_tx_tag),
            "should start with DevNet domain tag"
        );
    }

    #[test]
    fn test_sign_and_verify_roundtrip() {
        let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let pk = UserPublicKey::ml_dsa_44(pk_bytes);

        let sender = test_account_id(0xBB);
        let mut tx = QbindTransaction::new(sender, 0, b"test payload".to_vec());

        tx.sign(&sk).expect("signing should succeed");

        assert!(!tx.signature.bytes.is_empty(), "signature should be set");
        assert!(
            tx.verify_signature(&pk).is_ok(),
            "verification should succeed"
        );
    }

    #[test]
    fn test_verify_fails_for_wrong_key() {
        let (pk_bytes1, sk1) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (pk_bytes2, _) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        let pk1 = UserPublicKey::ml_dsa_44(pk_bytes1);
        let pk2 = UserPublicKey::ml_dsa_44(pk_bytes2);

        let sender = test_account_id(0xCC);
        let mut tx = QbindTransaction::new(sender, 0, b"test".to_vec());
        tx.sign(&sk1).expect("signing should succeed");

        // Verify with correct key
        assert!(tx.verify_signature(&pk1).is_ok());

        // Verify with wrong key
        assert!(matches!(
            tx.verify_signature(&pk2),
            Err(TxVerifyError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_verify_fails_for_modified_payload() {
        let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let pk = UserPublicKey::ml_dsa_44(pk_bytes);

        let sender = test_account_id(0xDD);
        let mut tx = QbindTransaction::new(sender, 0, b"original".to_vec());
        tx.sign(&sk).expect("signing should succeed");

        // Modify payload after signing
        tx.payload = b"modified".to_vec();

        assert!(matches!(
            tx.verify_signature(&pk),
            Err(TxVerifyError::SignatureVerificationFailed)
        ));
    }

    #[test]
    fn test_in_memory_state() {
        let mut state = InMemoryState::new();

        assert!(state.is_empty());
        assert!(state.get(b"key1").is_none());

        state.put(b"key1", b"value1".to_vec());
        assert_eq!(state.get(b"key1"), Some(b"value1".to_vec()));
        assert_eq!(state.len(), 1);

        state.put(b"key2", b"value2".to_vec());
        assert_eq!(state.len(), 2);

        state.delete(b"key1");
        assert!(state.get(b"key1").is_none());
        assert_eq!(state.len(), 1);
    }

    #[test]
    fn test_nonce_helpers() {
        let mut state = InMemoryState::new();
        let account = test_account_id(0xEE);

        // New account has nonce 0
        assert_eq!(get_account_nonce(&state, &account), 0);

        // Set nonce
        set_account_nonce(&mut state, &account, 5);
        assert_eq!(get_account_nonce(&state, &account), 5);

        // Update nonce
        set_account_nonce(&mut state, &account, 10);
        assert_eq!(get_account_nonce(&state, &account), 10);
    }

    #[test]
    fn test_nonce_engine_basic_execution() {
        let mut state = InMemoryState::new();
        let engine = NonceExecutionEngine::new();

        let sender = test_account_id(0xFF);
        let tx = QbindTransaction::new(sender, 0, b"tx0".to_vec());

        // Execute first tx (nonce 0)
        let result = engine.execute_tx(&mut state, &tx).expect("should succeed");
        assert!(result.success);
        assert_eq!(get_account_nonce(&state, &sender), 1);

        // Execute second tx (nonce 1)
        let tx2 = QbindTransaction::new(sender, 1, b"tx1".to_vec());
        let result2 = engine.execute_tx(&mut state, &tx2).expect("should succeed");
        assert!(result2.success);
        assert_eq!(get_account_nonce(&state, &sender), 2);
    }

    #[test]
    fn test_nonce_engine_wrong_nonce() {
        let mut state = InMemoryState::new();
        let engine = NonceExecutionEngine::new();

        let sender = test_account_id(0xAB);

        // Try to execute with wrong nonce (1 instead of 0)
        let tx = QbindTransaction::new(sender, 1, b"wrong nonce".to_vec());
        let result = engine.execute_tx(&mut state, &tx);

        assert!(matches!(
            result,
            Err(ExecutionEngineError::NonceMismatch {
                expected: 0,
                actual: 1
            })
        ));

        // State should be unchanged
        assert_eq!(get_account_nonce(&state, &sender), 0);
    }

    #[test]
    fn test_nonce_engine_with_signature_verification() {
        let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let pk = UserPublicKey::ml_dsa_44(pk_bytes);

        let sender = test_account_id(0xCD);
        let mut tx = QbindTransaction::new(sender, 0, b"signed tx".to_vec());
        tx.sign(&sk).expect("signing should succeed");

        // Create engine with signature verification
        let pk_clone = pk.clone();
        let engine = NonceExecutionEngine::new()
            .with_signature_verification(move |_| Some(pk_clone.clone()));

        let mut state = InMemoryState::new();
        let result = engine.execute_tx(&mut state, &tx).expect("should succeed");
        assert!(result.success);
        assert_eq!(get_account_nonce(&state, &sender), 1);
    }

    #[test]
    fn test_nonce_engine_signature_verification_fails() {
        let (_, sk1) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (pk_bytes2, _) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let wrong_pk = UserPublicKey::ml_dsa_44(pk_bytes2);

        let sender = test_account_id(0xDE);
        let mut tx = QbindTransaction::new(sender, 0, b"bad sig".to_vec());
        tx.sign(&sk1).expect("signing should succeed");

        // Create engine that returns wrong public key
        let engine = NonceExecutionEngine::new()
            .with_signature_verification(move |_| Some(wrong_pk.clone()));

        let mut state = InMemoryState::new();
        let result = engine.execute_tx(&mut state, &tx);

        assert!(matches!(
            result,
            Err(ExecutionEngineError::InvalidSignature)
        ));
        assert_eq!(get_account_nonce(&state, &sender), 0);
    }

    #[test]
    fn test_execution_events() {
        let mut state = InMemoryState::new();
        let engine = NonceExecutionEngine::new();

        let sender = test_account_id(0x11);
        let tx = QbindTransaction::new(sender, 0, b"event test".to_vec());

        let result = engine.execute_tx(&mut state, &tx).expect("should succeed");

        assert_eq!(result.events.len(), 1);
        assert!(matches!(
            &result.events[0],
            ExecutionEvent::TxAccepted { sender: s, nonce: 0 } if *s == sender
        ));
    }
}