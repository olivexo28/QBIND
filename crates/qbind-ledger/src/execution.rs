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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
// T163: VM v0 State Model (Account with Nonce + Balance)
// ============================================================================

/// Account state for VM v0 (T163).
///
/// This represents the minimal account state needed for a VM with balance transfers:
/// - `nonce`: Transaction replay protection (must match tx.nonce)
/// - `balance`: Account balance for transfers
///
/// # Default Value
///
/// New accounts have `nonce = 0` and `balance = 0`.
///
/// # Usage
///
/// ```rust,ignore
/// use qbind_ledger::execution::AccountState;
///
/// let mut state = AccountState::default();
/// assert_eq!(state.nonce, 0);
/// assert_eq!(state.balance, 0);
///
/// // After transfer of 100 units
/// state.balance = 100;
/// state.nonce = 1;
/// ```
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountState {
    /// Transaction nonce (replay protection).
    pub nonce: u64,
    /// Account balance.
    pub balance: u128,
}

impl AccountState {
    /// Create a new account state with the given nonce and balance.
    pub fn new(nonce: u64, balance: u128) -> Self {
        Self { nonce, balance }
    }

    /// Create an account state with zero nonce and the given balance.
    ///
    /// Useful for initializing accounts with a balance.
    pub fn with_balance(balance: u128) -> Self {
        Self { nonce: 0, balance }
    }
}

/// Read-only view of account state (T163).
pub trait AccountStateView {
    /// Get the account state for an account ID.
    ///
    /// Returns the default `AccountState` (nonce=0, balance=0) for absent accounts.
    fn get_account_state(&self, account: &AccountId) -> AccountState;
}

/// Mutable updater for account state (T163).
pub trait AccountStateUpdater: AccountStateView {
    /// Set the account state for an account ID.
    fn set_account_state(&mut self, account: &AccountId, state: AccountState);
}

/// In-memory account state backend for VM v0 (T163).
///
/// This is a simple HashMap-based implementation suitable for testing
/// and in-memory execution. Production deployments should use a
/// persistent backend (e.g., RocksDB).
///
/// # Default Values
///
/// Accounts not in the map are treated as having the default `AccountState`
/// (nonce = 0, balance = 0).
#[derive(Clone, Debug, Default)]
pub struct InMemoryAccountState {
    inner: HashMap<AccountId, AccountState>,
}

impl InMemoryAccountState {
    /// Create a new empty in-memory account state.
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Get the number of accounts in the state.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Check if the state is empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate over all account states.
    pub fn iter(&self) -> impl Iterator<Item = (&AccountId, &AccountState)> {
        self.inner.iter()
    }

    /// Initialize an account with the given balance (for testing/genesis).
    pub fn init_account(&mut self, account: &AccountId, balance: u128) {
        self.inner
            .insert(*account, AccountState::with_balance(balance));
    }
}

impl AccountStateView for InMemoryAccountState {
    fn get_account_state(&self, account: &AccountId) -> AccountState {
        self.inner.get(account).cloned().unwrap_or_default()
    }
}

impl AccountStateUpdater for InMemoryAccountState {
    fn set_account_state(&mut self, account: &AccountId, state: AccountState) {
        self.inner.insert(*account, state);
    }
}

// ============================================================================
// T164: Persistent Account State Abstraction
// ============================================================================

/// Error type for persistent storage operations (T164).
///
/// This enum represents errors that can occur when reading from or writing to
/// a persistent account state backend.
#[derive(Debug)]
pub enum StorageError {
    /// I/O error during storage operation.
    Io(String),
    /// Data corruption or decode error.
    Corrupt(String),
}

impl std::fmt::Display for StorageError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StorageError::Io(msg) => write!(f, "storage I/O error: {}", msg),
            StorageError::Corrupt(msg) => write!(f, "storage corruption: {}", msg),
        }
    }
}

impl std::error::Error for StorageError {}

impl From<std::io::Error> for StorageError {
    fn from(e: std::io::Error) -> Self {
        StorageError::Io(e.to_string())
    }
}

/// Trait for persistent account state backends (T164).
///
/// Implementations of this trait provide durable storage for VM v0 account state.
/// The state must survive node restarts and be deterministically recoverable.
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow shared access across threads.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::{PersistentAccountState, AccountState, StorageError};
/// use qbind_types::AccountId;
///
/// fn persist_state<P: PersistentAccountState>(
///     storage: &P,
///     account: &AccountId,
///     state: &AccountState,
/// ) -> Result<(), StorageError> {
///     storage.put_account_state(account, state)?;
///     storage.flush()?;
///     Ok(())
/// }
/// ```
pub trait PersistentAccountState: Send + Sync {
    /// Load the account state for an account ID.
    ///
    /// Returns the default `AccountState` (nonce=0, balance=0) if the account
    /// is not found in storage.
    fn get_account_state(&self, account: &AccountId) -> AccountState;

    /// Store the account state for an account ID.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the write fails.
    fn put_account_state(
        &self,
        account: &AccountId,
        state: &AccountState,
    ) -> Result<(), StorageError>;

    /// Flush all pending writes to durable storage.
    ///
    /// After this call returns successfully, the state is guaranteed to be
    /// persisted and will survive a process restart.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the flush fails.
    fn flush(&self) -> Result<(), StorageError>;
}

// ============================================================================
// AccountState Serialization (T164)
// ============================================================================

impl AccountState {
    /// Size of the serialized account state in bytes.
    ///
    /// Format: nonce (8 bytes, big-endian) + balance (16 bytes, big-endian) = 24 bytes.
    pub const SERIALIZED_SIZE: usize = 24;

    /// Serialize the account state to a fixed-size byte array.
    ///
    /// # Wire Format
    ///
    /// ```text
    /// nonce:   u64  BE (bytes 0..8)
    /// balance: u128 BE (bytes 8..24)
    /// ```
    pub fn to_bytes(&self) -> [u8; Self::SERIALIZED_SIZE] {
        let mut buf = [0u8; Self::SERIALIZED_SIZE];
        buf[0..8].copy_from_slice(&self.nonce.to_be_bytes());
        buf[8..24].copy_from_slice(&self.balance.to_be_bytes());
        buf
    }

    /// Deserialize an account state from bytes.
    ///
    /// # Errors
    ///
    /// Returns `None` if the slice is not exactly 24 bytes.
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != Self::SERIALIZED_SIZE {
            return None;
        }
        let nonce = u64::from_be_bytes(data[0..8].try_into().ok()?);
        let balance = u128::from_be_bytes(data[8..24].try_into().ok()?);
        Some(Self { nonce, balance })
    }
}

// ============================================================================
// T164: RocksDB-backed Persistent Account State
// ============================================================================

use std::path::Path;

/// Key prefix for account state entries in RocksDB.
///
/// Format: "acct:" || account_id_bytes (32 bytes)
const ACCOUNT_PREFIX: &[u8] = b"acct:";

/// RocksDB-backed persistent account state backend (T164).
///
/// This implementation provides durable storage for VM v0 account state using
/// RocksDB as the underlying key-value store.
///
/// # Key Format
///
/// Account states are stored with keys of the form:
/// ```text
/// "acct:" || account_id (32 bytes)
/// ```
///
/// # Value Format
///
/// Account states are stored as fixed 24-byte binary:
/// ```text
/// nonce:   u64  (8 bytes, big-endian)
/// balance: u128 (16 bytes, big-endian)
/// ```
///
/// # Thread Safety
///
/// `RocksDbAccountState` is `Send + Sync` and can be safely shared across threads.
/// RocksDB handles internal synchronization.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::RocksDbAccountState;
/// use std::path::Path;
///
/// let storage = RocksDbAccountState::open(Path::new("/data/vm_v0_state"))?;
///
/// // Store and retrieve account state
/// let account = AccountId::from_bytes([0xAA; 32]);
/// storage.put_account_state(&account, &AccountState::new(1, 1000))?;
/// storage.flush()?;
///
/// let state = storage.get_account_state(&account);
/// assert_eq!(state.nonce, 1);
/// assert_eq!(state.balance, 1000);
/// ```
pub struct RocksDbAccountState {
    /// The underlying RocksDB instance.
    db: rocksdb::DB,
}

impl std::fmt::Debug for RocksDbAccountState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbAccountState")
            .field("path", &self.db.path())
            .finish()
    }
}

impl RocksDbAccountState {
    /// Open or create a RocksDB database at the given path.
    ///
    /// Creates the database and parent directories if they don't exist.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database directory.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the database cannot be opened or created.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_ledger::RocksDbAccountState;
    /// use std::path::Path;
    ///
    /// let storage = RocksDbAccountState::open(Path::new("/data/vm_v0_state"))?;
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, StorageError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        let db = rocksdb::DB::open(&opts, path).map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(Self { db })
    }

    /// Build the storage key for an account.
    fn account_key(account: &AccountId) -> Vec<u8> {
        let mut key = Vec::with_capacity(ACCOUNT_PREFIX.len() + 32);
        key.extend_from_slice(ACCOUNT_PREFIX);
        key.extend_from_slice(account);
        key
    }
}

impl PersistentAccountState for RocksDbAccountState {
    fn get_account_state(&self, account: &AccountId) -> AccountState {
        let key = Self::account_key(account);

        match self.db.get(&key) {
            Ok(Some(value)) => AccountState::from_bytes(&value).unwrap_or_default(),
            Ok(None) => AccountState::default(),
            Err(_) => AccountState::default(),
        }
    }

    fn put_account_state(
        &self,
        account: &AccountId,
        state: &AccountState,
    ) -> Result<(), StorageError> {
        let key = Self::account_key(account);
        let value = state.to_bytes();

        self.db
            .put(&key, value)
            .map_err(|e| StorageError::Io(e.to_string()))
    }

    fn flush(&self) -> Result<(), StorageError> {
        self.db.flush().map_err(|e| StorageError::Io(e.to_string()))
    }
}

// ============================================================================
// T208: StatePruner Implementation for RocksDbAccountState
// ============================================================================

use crate::state_pruning::{PruneStats, StatePruner};

impl StatePruner for RocksDbAccountState {
    type Error = StorageError;

    /// Prune state data below the specified block height.
    ///
    /// For the current account state model, we don't have height-indexed data,
    /// so this implementation provides a basic no-op that returns stats about
    /// the current state. Height-based pruning will be meaningful when we add
    /// historical state snapshots or versioned account data.
    ///
    /// # Arguments
    ///
    /// * `_prune_below_height` - Block height threshold (currently unused)
    ///
    /// # Returns
    ///
    /// `Ok(PruneStats)` with statistics about the operation.
    fn prune_below(&mut self, _prune_below_height: u64) -> Result<PruneStats, StorageError> {
        use std::time::Instant;
        let start = Instant::now();

        // Count keys in the database
        let mut keys_scanned: u64 = 0;
        let keys_pruned: u64 = 0;

        // Iterate over all account entries
        // Note: In the current data model, account state is not versioned by height.
        // This implementation scans and reports stats, but does not actually prune
        // because current account state must be retained.
        //
        // When historical state snapshots are added, this will prune old snapshots
        // below the specified height threshold.
        let mut iter_errors: u64 = 0;
        let iter = self.db.prefix_iterator(ACCOUNT_PREFIX);
        for result in iter {
            match result {
                Ok((key, _)) => {
                    // Only count keys with our prefix
                    if key.starts_with(ACCOUNT_PREFIX) {
                        keys_scanned += 1;
                    } else {
                        // Prefix iterator may overshoot, stop when prefix no longer matches
                        break;
                    }
                }
                Err(e) => {
                    // Log iterator errors but continue scanning.
                    // In production, these would be reported to metrics.
                    iter_errors += 1;
                    eprintln!(
                        "[T208] StatePruner: iterator error during scan (error {}): {}",
                        iter_errors, e
                    );
                    continue;
                }
            }
        }

        // Currently no actual pruning happens (current state is always retained)
        // keys_pruned will be > 0 when historical snapshots are implemented

        let duration = start.elapsed();
        Ok(PruneStats::from_duration(
            keys_scanned,
            keys_pruned,
            duration,
        ))
    }

    /// Get the estimated state size in bytes.
    ///
    /// Uses RocksDB's property API to estimate the on-disk size.
    fn estimated_size_bytes(&self) -> Result<u64, StorageError> {
        // Use RocksDB's estimated live data size
        let size_str = self
            .db
            .property_value("rocksdb.estimate-live-data-size")
            .map_err(|e| StorageError::Io(e.to_string()))?;

        match size_str {
            Some(s) => s.parse().map_err(|_| {
                StorageError::Corrupt("cannot parse rocksdb.estimate-live-data-size".to_string())
            }),
            None => {
                // Fall back to total-sst-files-size if estimate-live-data-size is unavailable
                let sst_size = self
                    .db
                    .property_value("rocksdb.total-sst-files-size")
                    .map_err(|e| StorageError::Io(e.to_string()))?;

                match sst_size {
                    Some(s) => s.parse().map_err(|_| {
                        StorageError::Corrupt(
                            "cannot parse rocksdb.total-sst-files-size".to_string(),
                        )
                    }),
                    None => Ok(0), // Unknown size
                }
            }
        }
    }
}

// ============================================================================
// T215: StateSnapshotter Implementation for RocksDbAccountState
// ============================================================================

use crate::state_snapshot::{
    SnapshotStats, StateSnapshotError, StateSnapshotMeta, StateSnapshotter,
};

impl StateSnapshotter for RocksDbAccountState {
    /// Create a point-in-time snapshot of the RocksDB account state.
    ///
    /// Uses RocksDB's checkpoint API for efficient, consistent snapshots.
    /// The checkpoint creates hard links to SST files when possible,
    /// making it fast and space-efficient.
    ///
    /// # Directory Layout
    ///
    /// Creates the following structure:
    /// ```text
    /// target_dir/
    /// ├── meta.json   # Snapshot metadata
    /// └── state/      # RocksDB checkpoint files
    /// ```
    ///
    /// # Arguments
    ///
    /// * `meta` - Snapshot metadata (height, block hash, chain ID)
    /// * `target_dir` - Directory to write snapshot (must not exist)
    ///
    /// # Errors
    ///
    /// - `Config`: Invalid target directory
    /// - `AlreadyExists`: Target directory already exists
    /// - `Io`: File system errors
    /// - `Backend`: RocksDB checkpoint errors
    fn create_snapshot(
        &self,
        meta: &StateSnapshotMeta,
        target_dir: &Path,
    ) -> Result<SnapshotStats, StateSnapshotError> {
        use std::time::Instant;
        let start = Instant::now();

        // Validate target directory
        if target_dir.as_os_str().is_empty() {
            return Err(StateSnapshotError::Config(
                "target directory path is empty".to_string(),
            ));
        }

        // Check if target directory already exists
        if target_dir.exists() {
            return Err(StateSnapshotError::AlreadyExists(
                target_dir.display().to_string(),
            ));
        }

        // Create parent directories if needed
        if let Some(parent) = target_dir.parent() {
            std::fs::create_dir_all(parent).map_err(|e| {
                StateSnapshotError::Io(format!("cannot create parent directory: {}", e))
            })?;
        }

        // Create target directory
        std::fs::create_dir(target_dir).map_err(|e| {
            StateSnapshotError::Io(format!("cannot create snapshot directory: {}", e))
        })?;

        // Write metadata file
        let meta_path = target_dir.join("meta.json");
        std::fs::write(&meta_path, meta.to_json())
            .map_err(|e| StateSnapshotError::Io(format!("cannot write meta.json: {}", e)))?;

        // Create state subdirectory for RocksDB checkpoint
        let state_dir = target_dir.join("state");

        // Flush WAL and memtable before checkpoint to ensure consistency
        self.db.flush().map_err(|e| {
            StateSnapshotError::Backend(format!("cannot flush before checkpoint: {}", e))
        })?;

        // Create RocksDB checkpoint
        let checkpoint = rocksdb::checkpoint::Checkpoint::new(&self.db).map_err(|e| {
            StateSnapshotError::Backend(format!("cannot create checkpoint object: {}", e))
        })?;

        checkpoint.create_checkpoint(&state_dir).map_err(|e| {
            StateSnapshotError::Backend(format!("checkpoint creation failed: {}", e))
        })?;

        let duration = start.elapsed();

        // Estimate snapshot size by summing checkpoint directory files
        let size_bytes = Self::estimate_dir_size(&state_dir).unwrap_or(0);

        Ok(SnapshotStats::new(meta.height, size_bytes, duration))
    }

    /// Estimate the current state size in bytes.
    ///
    /// Returns the estimated live data size from RocksDB.
    fn estimate_snapshot_size_bytes(&self) -> Option<u64> {
        self.estimated_size_bytes().ok()
    }
}

impl RocksDbAccountState {
    /// Estimate the total size of files in a directory (recursive).
    fn estimate_dir_size(dir: &Path) -> Option<u64> {
        let mut total: u64 = 0;
        let entries = std::fs::read_dir(dir).ok()?;

        for entry in entries.flatten() {
            let metadata = entry.metadata().ok()?;
            if metadata.is_file() {
                total += metadata.len();
            } else if metadata.is_dir() {
                if let Some(subdir_size) = Self::estimate_dir_size(&entry.path()) {
                    total += subdir_size;
                }
            }
        }

        Some(total)
    }
}

// ============================================================================
// T164: Cached Persistent Account State
// ============================================================================

/// A cached wrapper around a persistent account state backend (T164).
///
/// This struct combines an in-memory cache with a persistent backend:
/// - Reads check the cache first, then fall back to the persistent store.
/// - Writes go to both the cache and the persistent store immediately.
/// - The `flush` method ensures all data is durably persisted.
///
/// This allows the `VmV0ExecutionEngine` (which requires `AccountStateUpdater`)
/// to work with persistent storage while maintaining fast in-memory access.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::{CachedPersistentAccountState, RocksDbAccountState};
/// use std::path::Path;
///
/// let persistent = RocksDbAccountState::open(Path::new("/data/vm_v0_state"))?;
/// let mut cached = CachedPersistentAccountState::new(persistent)?;
///
/// // Use with VmV0ExecutionEngine
/// let engine = VmV0ExecutionEngine::new();
/// let results = engine.execute_block(&mut cached, &transactions);
///
/// // Flush to ensure durability
/// cached.flush()?;
/// ```
pub struct CachedPersistentAccountState<P: PersistentAccountState> {
    /// In-memory cache for fast access.
    cache: InMemoryAccountState,
    /// Underlying persistent backend.
    persistent: P,
}

impl<P: PersistentAccountState> CachedPersistentAccountState<P> {
    /// Create a new cached wrapper around the given persistent backend.
    ///
    /// The cache starts empty; entries are loaded on-demand from the persistent
    /// store.
    pub fn new(persistent: P) -> Self {
        Self {
            cache: InMemoryAccountState::new(),
            persistent,
        }
    }

    /// Flush all cached state to the persistent backend.
    ///
    /// This ensures all state changes are durably persisted.
    ///
    /// # Errors
    ///
    /// Returns `StorageError::Io` if the flush fails.
    pub fn flush(&self) -> Result<(), StorageError> {
        // All writes are already written through to persistent storage,
        // so we just need to call flush to ensure durability.
        self.persistent.flush()
    }

    /// Get a reference to the underlying persistent backend.
    pub fn persistent(&self) -> &P {
        &self.persistent
    }
}

impl<P: PersistentAccountState> AccountStateView for CachedPersistentAccountState<P> {
    fn get_account_state(&self, account: &AccountId) -> AccountState {
        // Check cache first
        let cached = self.cache.get_account_state(account);
        if cached != AccountState::default() {
            return cached;
        }

        // Fall back to persistent store
        self.persistent.get_account_state(account)
    }
}

impl<P: PersistentAccountState> AccountStateUpdater for CachedPersistentAccountState<P> {
    fn set_account_state(&mut self, account: &AccountId, state: AccountState) {
        // Update cache
        self.cache.set_account_state(account, state.clone());

        // Write through to persistent store (ignore errors for now, they'll
        // be caught at flush time)
        let _ = self.persistent.put_account_state(account, &state);
    }
}

impl<P: PersistentAccountState> std::fmt::Debug for CachedPersistentAccountState<P> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CachedPersistentAccountState")
            .field("cache_size", &self.cache.len())
            .finish()
    }
}

// ============================================================================
// T163: VM v0 Execution Engine
// ============================================================================

/// Error type for VM v0 transaction execution (T163, T168).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmV0Error {
    /// Transaction nonce doesn't match the expected value.
    NonceMismatch {
        /// The expected nonce (from state).
        expected: u64,
        /// The actual nonce (in transaction).
        got: u64,
    },
    /// Sender doesn't have enough balance for the transfer.
    InsufficientBalance {
        /// The sender's current balance.
        balance: u128,
        /// The amount needed (transfer amount).
        needed: u128,
    },
    /// Transaction payload is malformed and cannot be decoded.
    MalformedPayload,

    // T168: Gas-related error variants
    /// Transaction's gas cost exceeds its gas limit (T168).
    GasLimitExceeded {
        /// The required gas for this transaction.
        required: u64,
        /// The gas limit specified in the transaction.
        limit: u64,
    },

    /// Sender doesn't have enough balance to cover the fee (T168).
    InsufficientBalanceForFee {
        /// The sender's current balance.
        balance: u128,
        /// The total amount needed (transfer amount + fee).
        needed: u128,
    },

    // M18: Arithmetic safety error variants
    /// Arithmetic overflow detected during fee/balance calculation (M18).
    ///
    /// This indicates that a gas, fee, or balance calculation would exceed
    /// the maximum representable value. The transaction is rejected to
    /// maintain determinism and fail-closed semantics.
    ArithmeticOverflow {
        /// Description of which operation overflowed.
        operation: &'static str,
    },
}

impl std::fmt::Display for VmV0Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmV0Error::NonceMismatch { expected, got } => {
                write!(f, "nonce mismatch: expected {}, got {}", expected, got)
            }
            VmV0Error::InsufficientBalance { balance, needed } => {
                write!(f, "insufficient balance: have {}, need {}", balance, needed)
            }
            VmV0Error::MalformedPayload => write!(f, "malformed payload"),
            VmV0Error::GasLimitExceeded { required, limit } => {
                write!(
                    f,
                    "gas limit exceeded: required {}, limit {}",
                    required, limit
                )
            }
            VmV0Error::InsufficientBalanceForFee { balance, needed } => {
                write!(
                    f,
                    "insufficient balance for fee: have {}, need {}",
                    balance, needed
                )
            }
            VmV0Error::ArithmeticOverflow { operation } => {
                write!(f, "arithmetic overflow in {}", operation)
            }
        }
    }
}

impl std::error::Error for VmV0Error {}

/// Result of executing a VM v0 transaction (T163, T168, T193).
#[derive(Debug, Clone)]
pub struct VmV0TxResult {
    /// Whether the transaction was successful.
    pub success: bool,
    /// Error details if the transaction failed.
    pub error: Option<VmV0Error>,
    /// Gas used by this transaction (T168).
    /// Only meaningful when gas enforcement is enabled.
    pub gas_used: u64,
    /// Fee paid (total deducted from sender) by this transaction (T168).
    /// Only meaningful when gas enforcement is enabled.
    /// This equals `fee_burned + fee_to_proposer`.
    pub fee_paid: u128,
    /// Fee burned (removed from circulation) by this transaction (T193).
    /// Only meaningful when gas enforcement is enabled.
    pub fee_burned: u128,
    /// Fee credited to block proposer by this transaction (T193).
    /// Only meaningful when gas enforcement is enabled and proposer rewards are active.
    pub fee_to_proposer: u128,
}

impl VmV0TxResult {
    /// Create a success result.
    pub fn success() -> Self {
        Self {
            success: true,
            error: None,
            gas_used: 0,
            fee_paid: 0,
            fee_burned: 0,
            fee_to_proposer: 0,
        }
    }

    /// Create a success result with gas information (T168).
    /// Assumes all fees are burned (backward compatible).
    pub fn success_with_gas(gas_used: u64, fee_paid: u128) -> Self {
        Self {
            success: true,
            error: None,
            gas_used,
            fee_paid,
            fee_burned: fee_paid, // Backward compatible: all burned
            fee_to_proposer: 0,
        }
    }

    /// Create a success result with full fee distribution (T193).
    ///
    /// # Arguments
    ///
    /// * `gas_used` - Gas consumed by the transaction
    /// * `fee_burned` - Portion of fee that was burned
    /// * `fee_to_proposer` - Portion of fee credited to proposer
    pub fn success_with_fee_distribution(
        gas_used: u64,
        fee_burned: u128,
        fee_to_proposer: u128,
    ) -> Self {
        Self {
            success: true,
            error: None,
            gas_used,
            fee_paid: fee_burned.saturating_add(fee_to_proposer),
            fee_burned,
            fee_to_proposer,
        }
    }

    /// Create a failure result with the given error.
    pub fn failure(error: VmV0Error) -> Self {
        Self {
            success: false,
            error: Some(error),
            gas_used: 0,
            fee_paid: 0,
            fee_burned: 0,
            fee_to_proposer: 0,
        }
    }

    /// Create a failure result with gas information (T168).
    pub fn failure_with_gas(error: VmV0Error, gas_used: u64) -> Self {
        Self {
            success: false,
            error: Some(error),
            gas_used,
            fee_paid: 0,
            fee_burned: 0,
            fee_to_proposer: 0,
        }
    }
}

/// VM v0 transfer payload structure (T163).
///
/// This is the canonical format for transfer transactions in VM v0:
/// - `recipient`: 32-byte account ID of the transfer recipient
/// - `amount`: u128 amount in big-endian format (16 bytes)
///
/// Total payload size: 48 bytes.
///
/// # Wire Format
///
/// ```text
/// recipient: [u8; 32]  (bytes 0..32)
/// amount:    u128 BE   (bytes 32..48)
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferPayload {
    /// The recipient account ID.
    pub recipient: AccountId,
    /// The amount to transfer.
    pub amount: u128,
}

/// Size of a valid transfer payload in bytes.
pub const TRANSFER_PAYLOAD_SIZE: usize = 32 + 16; // recipient (32) + amount (16)

impl TransferPayload {
    /// Create a new transfer payload.
    pub fn new(recipient: AccountId, amount: u128) -> Self {
        Self { recipient, amount }
    }

    /// Encode the transfer payload to bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(TRANSFER_PAYLOAD_SIZE);
        out.extend_from_slice(&self.recipient);
        out.extend_from_slice(&self.amount.to_be_bytes());
        out
    }

    /// Decode a transfer payload from bytes.
    ///
    /// Returns `None` if the payload is malformed.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != TRANSFER_PAYLOAD_SIZE {
            return None;
        }

        let recipient: AccountId = bytes[0..32].try_into().ok()?;
        let amount = u128::from_be_bytes(bytes[32..48].try_into().ok()?);

        Some(Self { recipient, amount })
    }
}

/// VM v0 execution engine (T163, T168).
///
/// This engine implements the VM v0 execution semantics:
/// - Decode payload as a transfer (recipient, amount)
/// - Check nonce matches sender's stored nonce
/// - Check sender has sufficient balance
/// - Update sender: decrement balance, increment nonce
/// - Update recipient: increment balance (create account if absent)
///
/// # Gas Enforcement (T168)
///
/// When gas enforcement is enabled via `ExecutionGasConfig`:
/// - Compute gas cost from payload and account access patterns
/// - Enforce gas_limit: reject if gas_cost > gas_limit
/// - Compute and deduct fee: sender.balance -= amount + (gas_cost * max_fee_per_gas)
/// - Fees are burned (not credited anywhere) in TestNet
///
/// # Determinism
///
/// Transactions are executed sequentially in block order.
/// All state transitions are deterministic.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::{VmV0ExecutionEngine, InMemoryAccountState, QbindTransaction, TransferPayload};
///
/// let mut state = InMemoryAccountState::new();
/// state.init_account(&sender, 100);
///
/// let engine = VmV0ExecutionEngine::new();
/// let payload = TransferPayload::new(recipient, 50).encode();
/// let tx = QbindTransaction::new(sender, 0, payload);
///
/// let result = engine.execute_tx(&mut state, &tx);
/// assert!(result.success);
/// ```
#[derive(Debug, Clone, Default)]
pub struct VmV0ExecutionEngine {
    /// Gas configuration (T168).
    gas_config: crate::execution_gas::ExecutionGasConfig,
}

impl VmV0ExecutionEngine {
    /// Create a new VM v0 execution engine with gas disabled (default).
    pub fn new() -> Self {
        Self {
            gas_config: crate::execution_gas::ExecutionGasConfig::disabled(),
        }
    }

    /// Create a new VM v0 execution engine with the specified gas configuration.
    pub fn with_gas_config(gas_config: crate::execution_gas::ExecutionGasConfig) -> Self {
        Self { gas_config }
    }

    /// Check if gas enforcement is enabled.
    pub fn is_gas_enabled(&self) -> bool {
        self.gas_config.enabled
    }

    /// Get the gas configuration.
    pub fn gas_config(&self) -> &crate::execution_gas::ExecutionGasConfig {
        &self.gas_config
    }

    /// Execute a transaction against the given account state.
    ///
    /// # Arguments
    ///
    /// * `state` - The mutable account state
    /// * `tx` - The transaction to execute
    ///
    /// # Returns
    ///
    /// A `VmV0TxResult` indicating success or failure.
    ///
    /// # State Mutations
    ///
    /// On success:
    /// - Sender's balance is decremented by the transfer amount (+ fee if gas enabled)
    /// - Sender's nonce is incremented by 1
    /// - Recipient's balance is incremented by the transfer amount
    /// - Recipient account is created if it doesn't exist
    ///
    /// On failure:
    /// - No state changes are made
    pub fn execute_tx<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        tx: &QbindTransaction,
    ) -> VmV0TxResult {
        // Use the gas-aware path when gas is enabled
        if self.gas_config.enabled {
            return self.execute_tx_with_gas(state, tx);
        }

        // Original path when gas is disabled (backward compatible)
        // Step 1: Decode payload as transfer
        let transfer = match TransferPayload::decode(&tx.payload) {
            Some(t) => t,
            None => return VmV0TxResult::failure(VmV0Error::MalformedPayload),
        };

        // Step 2: Fetch sender's current state
        let sender_state = state.get_account_state(&tx.sender);

        // Step 3: Check nonce
        if tx.nonce != sender_state.nonce {
            return VmV0TxResult::failure(VmV0Error::NonceMismatch {
                expected: sender_state.nonce,
                got: tx.nonce,
            });
        }

        // Step 4: Check balance
        if sender_state.balance < transfer.amount {
            return VmV0TxResult::failure(VmV0Error::InsufficientBalance {
                balance: sender_state.balance,
                needed: transfer.amount,
            });
        }

        // Step 5: Update sender (decrement balance, increment nonce)
        let new_sender_state = AccountState {
            nonce: sender_state.nonce + 1,
            balance: sender_state.balance - transfer.amount,
        };
        state.set_account_state(&tx.sender, new_sender_state);

        // Step 6: Update recipient (increment balance, create if absent)
        let recipient_state = state.get_account_state(&transfer.recipient);
        let new_recipient_state = AccountState {
            nonce: recipient_state.nonce,
            balance: recipient_state.balance + transfer.amount,
        };
        state.set_account_state(&transfer.recipient, new_recipient_state);

        VmV0TxResult::success()
    }

    /// Execute a transaction with gas enforcement (T168).
    ///
    /// This is the gas-aware execution path used when `gas_config.enabled = true`.
    /// Uses burn-only fee distribution (backward compatible).
    fn execute_tx_with_gas<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        tx: &QbindTransaction,
    ) -> VmV0TxResult {
        self.execute_tx_with_gas_and_proposer(state, tx, None)
    }

    /// Execute a transaction with gas enforcement and optional proposer reward (T168, T193).
    ///
    /// This is the gas-aware execution path that supports hybrid fee distribution.
    /// When a proposer is provided and the fee policy has proposer rewards, the
    /// proposer's account will be credited.
    ///
    /// # Arguments
    ///
    /// * `state` - The mutable account state
    /// * `tx` - The transaction to execute
    /// * `proposer` - Optional proposer account to credit rewards to
    fn execute_tx_with_gas_and_proposer<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        tx: &QbindTransaction,
        proposer: Option<&AccountId>,
    ) -> VmV0TxResult {
        use crate::execution_gas::{
            compute_gas_for_vm_v0_tx, decode_transfer_payload, TransferPayloadDecoded,
        };

        // Step 1: Compute gas and decode payload
        let gas_result = match compute_gas_for_vm_v0_tx(tx) {
            Ok(r) => r,
            Err(_) => return VmV0TxResult::failure(VmV0Error::MalformedPayload),
        };

        let gas_cost = gas_result.gas_cost;
        let gas_limit = gas_result.gas_limit;
        let max_fee_per_gas = gas_result.max_fee_per_gas;

        // Step 2: Enforce gas limit
        if gas_cost > gas_limit {
            return VmV0TxResult::failure(VmV0Error::GasLimitExceeded {
                required: gas_cost,
                limit: gas_limit,
            });
        }

        // Step 3: Extract transfer details from decoded payload
        let (recipient, amount) = match decode_transfer_payload(&tx.payload) {
            Ok(TransferPayloadDecoded::V0(p)) => (p.recipient, p.amount),
            Ok(TransferPayloadDecoded::V1(p)) => (p.recipient, p.amount),
            Err(_) => return VmV0TxResult::failure(VmV0Error::MalformedPayload),
        };

        // Step 4: Compute fee (fee = gas_cost * max_fee_per_gas)
        // M18: Use checked arithmetic to prevent overflow
        let total_fee = match (gas_cost as u128).checked_mul(max_fee_per_gas) {
            Some(fee) => fee,
            None => {
                return VmV0TxResult::failure_with_gas(
                    VmV0Error::ArithmeticOverflow {
                        operation: "fee calculation (gas_cost * max_fee_per_gas)",
                    },
                    gas_cost,
                );
            }
        };

        // M18: Use checked arithmetic for total_debit
        let total_debit = match amount.checked_add(total_fee) {
            Some(debit) => debit,
            None => {
                return VmV0TxResult::failure_with_gas(
                    VmV0Error::ArithmeticOverflow {
                        operation: "total debit calculation (amount + fee)",
                    },
                    gas_cost,
                );
            }
        };

        // Step 5: Fetch sender's current state
        let sender_state = state.get_account_state(&tx.sender);

        // Step 6: Check nonce
        if tx.nonce != sender_state.nonce {
            return VmV0TxResult::failure_with_gas(
                VmV0Error::NonceMismatch {
                    expected: sender_state.nonce,
                    got: tx.nonce,
                },
                gas_cost,
            );
        }

        // Step 7: Check balance covers amount + fee
        if sender_state.balance < total_debit {
            return VmV0TxResult::failure_with_gas(
                VmV0Error::InsufficientBalanceForFee {
                    balance: sender_state.balance,
                    needed: total_debit,
                },
                gas_cost,
            );
        }

        // ======================================================================
        // M18: Pre-validate ALL overflow conditions BEFORE any state changes
        // This ensures ATOM-1: state changes commit atomically or not at all
        // ======================================================================

        // Pre-validate nonce increment
        let new_nonce = match sender_state.nonce.checked_add(1) {
            Some(n) => n,
            None => {
                return VmV0TxResult::failure_with_gas(
                    VmV0Error::ArithmeticOverflow {
                        operation: "nonce increment",
                    },
                    gas_cost,
                );
            }
        };

        let is_self_transfer = recipient == tx.sender;

        // Pre-validate sender balance decrement (defense-in-depth after Step 7 check)
        let mut new_sender_balance = match sender_state.balance.checked_sub(total_debit) {
            Some(b) => b,
            None => {
                return VmV0TxResult::failure_with_gas(
                    VmV0Error::ArithmeticOverflow {
                        operation: "sender balance decrement",
                    },
                    gas_cost,
                );
            }
        };

        // Self-transfer: net effect should not include the transfer amount
        if is_self_transfer {
            new_sender_balance = match new_sender_balance.checked_add(amount) {
                Some(b) => b,
                None => {
                    return VmV0TxResult::failure_with_gas(
                        VmV0Error::ArithmeticOverflow {
                            operation: "self-transfer balance restoration",
                        },
                        gas_cost,
                    );
                }
            };
        }

        // Pre-validate recipient balance increment (skip for self-transfer)
        let recipient_state = if is_self_transfer {
            None
        } else {
            Some(state.get_account_state(&recipient))
        };
        let new_recipient_balance = if let Some(state) = recipient_state.as_ref() {
            match state.balance.checked_add(amount) {
                Some(b) => Some(b),
                None => {
                    return VmV0TxResult::failure_with_gas(
                        VmV0Error::ArithmeticOverflow {
                            operation: "recipient balance increment",
                        },
                        gas_cost,
                    );
                }
            }
        } else {
            None
        };

        // Pre-calculate fee distribution
        let (fee_burned, fee_to_proposer) = self
            .gas_config
            .fee_distribution_policy
            .distribute_fee(total_fee);

        // ======================================================================
        // Handle special cases where proposer overlaps with sender or recipient
        // M18: Compute final balances correctly for all overlap scenarios
        // ======================================================================

        // Compute final balances, handling overlap cases:
        // Case 1: proposer == sender: sender pays (debit) and receives (fee reward)
        // Case 2: proposer == recipient: recipient receives (transfer) and receives (fee reward)
        // Case 3: all three are same: sender == recipient == proposer (self-transfer with reward)
        // Case 4: all different (normal case)

        let proposer_id_opt = proposer;
        let proposer_is_sender = proposer_id_opt.map_or(false, |p| p == &tx.sender);
        let proposer_is_recipient = proposer_id_opt.map_or(false, |p| p == &recipient);

        // Calculate final sender balance (may include proposer reward if proposer == sender)
        let final_sender_balance = if proposer_is_sender && fee_to_proposer > 0 {
            // Sender loses debit but gains proposer reward
            match new_sender_balance.checked_add(fee_to_proposer) {
                Some(b) => b,
                None => {
                    return VmV0TxResult::failure_with_gas(
                        VmV0Error::ArithmeticOverflow {
                            operation: "sender-proposer combined balance",
                        },
                        gas_cost,
                    );
                }
            }
        } else {
            new_sender_balance
        };

        // Calculate final recipient balance (may include proposer reward if proposer == recipient)
        let final_recipient_balance = if let Some(new_recipient_balance) = new_recipient_balance {
            if proposer_is_recipient && fee_to_proposer > 0 && !proposer_is_sender {
                // Recipient gains transfer and proposer reward (unless already handled as sender)
                match new_recipient_balance.checked_add(fee_to_proposer) {
                    Some(b) => Some(b),
                    None => {
                        return VmV0TxResult::failure_with_gas(
                            VmV0Error::ArithmeticOverflow {
                                operation: "recipient-proposer combined balance",
                            },
                            gas_cost,
                        );
                    }
                }
            } else {
                Some(new_recipient_balance)
            }
        } else {
            None
        };

        // Calculate final proposer balance (only if proposer is different from sender and recipient)
        let update_proposer_separately = proposer_id_opt.map_or(false, |p| {
            p != &tx.sender && p != &recipient
        }) && fee_to_proposer > 0;

        let separate_proposer_state = if update_proposer_separately {
            let proposer_id = proposer_id_opt.unwrap(); // Safe: we checked it's Some above
            let proposer_state = state.get_account_state(proposer_id);
            match proposer_state.balance.checked_add(fee_to_proposer) {
                Some(b) => Some((proposer_id, AccountState {
                    nonce: proposer_state.nonce,
                    balance: b,
                })),
                None => {
                    return VmV0TxResult::failure_with_gas(
                        VmV0Error::ArithmeticOverflow {
                            operation: "proposer balance increment",
                        },
                        gas_cost,
                    );
                }
            }
        } else {
            None
        };

        // ======================================================================
        // All pre-validations passed - now apply state changes atomically
        // ======================================================================

        // Step 8: Update sender
        let new_sender_state = AccountState {
            nonce: new_nonce,
            balance: final_sender_balance,
        };
        state.set_account_state(&tx.sender, new_sender_state);

        // Step 9: Update recipient (if different from sender)
        if let Some(recipient_state) = recipient_state {
            let final_recipient_balance = final_recipient_balance.unwrap_or(recipient_state.balance);
            let new_recipient_state = AccountState {
                nonce: recipient_state.nonce,
                balance: final_recipient_balance,
            };
            state.set_account_state(&recipient, new_recipient_state);
        }

        // Step 10: Credit proposer if separate from sender and recipient
        if let Some((proposer_id, proposer_account)) = separate_proposer_state {
            state.set_account_state(proposer_id, proposer_account);
        }

        // Success with full fee distribution information
        VmV0TxResult::success_with_fee_distribution(gas_cost, fee_burned, fee_to_proposer)
    }

    /// Execute a block of transactions sequentially.
    ///
    /// # Arguments
    ///
    /// * `state` - The mutable account state
    /// * `transactions` - The transactions to execute in order
    ///
    /// # Returns
    ///
    /// A vector of `VmV0TxResult` in the same order as the input transactions.
    pub fn execute_block<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        transactions: &[QbindTransaction],
    ) -> Vec<VmV0TxResult> {
        // Use gas-aware block execution when gas is enabled
        if self.gas_config.enabled {
            return self.execute_block_with_gas(state, transactions);
        }

        // Original path when gas is disabled
        transactions
            .iter()
            .map(|tx| self.execute_tx(state, tx))
            .collect()
    }

    /// Execute a block with gas enforcement and per-block gas limit (T168).
    ///
    /// # Gas Accounting Policy
    ///
    /// - Malformed transactions are treated as having `MINIMUM_GAS_LIMIT` gas to prevent DoS
    /// - Failed transactions (nonce mismatch, insufficient balance) do NOT consume gas
    ///   (they are rejected before any state changes, similar to pre-flight validation)
    /// - Only successful transactions consume gas from the block limit
    ///
    /// # M18: Checked Arithmetic
    ///
    /// All block gas accounting uses checked arithmetic. Overflow is not expected
    /// under normal conditions but triggers fail-closed behavior if it occurs.
    fn execute_block_with_gas<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        transactions: &[QbindTransaction],
    ) -> Vec<VmV0TxResult> {
        use crate::execution_gas::{compute_gas_for_vm_v0_tx, MINIMUM_GAS_LIMIT};

        let block_gas_limit = self.gas_config.block_gas_limit;
        let mut block_gas_used: u64 = 0;
        let mut results = Vec::with_capacity(transactions.len());

        for tx in transactions {
            // Pre-compute gas cost to check block limit
            // Malformed transactions get MINIMUM_GAS_LIMIT to prevent DoS via many small malformed txs
            let gas_cost = compute_gas_for_vm_v0_tx(tx)
                .map(|r| r.gas_cost)
                .unwrap_or(MINIMUM_GAS_LIMIT);

            // M18: Check if adding this tx would exceed block gas limit
            // Use checked_add to detect overflow (fail-closed)
            let projected_gas = match block_gas_used.checked_add(gas_cost) {
                Some(g) => g,
                None => {
                    // Overflow: block is full by definition; stop processing
                    break;
                }
            };

            if projected_gas > block_gas_limit {
                // Block is full; stop processing further transactions
                // Remaining transactions are not executed in this block
                break;
            }

            // Execute the transaction
            let result = self.execute_tx_with_gas(state, tx);

            // Update block gas used
            // Policy: Only count gas for successful transactions
            // Failed transactions are rejected before state changes (like pre-flight validation)
            // M18: Use checked_add for determinism
            if result.success {
                block_gas_used = match block_gas_used.checked_add(result.gas_used) {
                    Some(g) => g,
                    None => {
                        // This should not happen given gas_limit constraints, but fail-closed
                        // by stopping block processing. No more transactions are executed.
                        break;
                    }
                };
            }

            results.push(result);
        }

        results
    }

    /// Execute a block with gas enforcement and proposer rewards (T193).
    ///
    /// This method is used when hybrid fee distribution is enabled.
    /// A portion of transaction fees will be credited to the proposer's account.
    ///
    /// # Arguments
    ///
    /// * `state` - The mutable account state
    /// * `transactions` - The transactions to execute in order
    /// * `proposer` - The block proposer's account ID (receives fee rewards)
    ///
    /// # Returns
    ///
    /// A vector of `VmV0TxResult` in the same order as the input transactions.
    ///
    /// # Fee Distribution
    ///
    /// For each successful transaction, the fee is split according to
    /// `self.gas_config.fee_distribution_policy`:
    /// - The burn portion is removed from circulation (sender pays, nobody receives)
    /// - The proposer portion is credited to the proposer's account
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// let engine = VmV0ExecutionEngine::with_gas_config(
    ///     ExecutionGasConfig::mainnet()  // 50% burn, 50% proposer
    /// );
    ///
    /// let proposer = test_account_id(0xFF);
    /// let results = engine.execute_block_with_proposer(&mut state, &txs, &proposer);
    ///
    /// // Proposer should have received 50% of all fees
    /// let proposer_balance = state.get_account_state(&proposer).balance;
    /// ```
    pub fn execute_block_with_proposer<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        transactions: &[QbindTransaction],
        proposer: &AccountId,
    ) -> Vec<VmV0TxResult> {
        if !self.gas_config.enabled {
            // If gas is disabled, no fees to distribute
            return self.execute_block(state, transactions);
        }

        use crate::execution_gas::{compute_gas_for_vm_v0_tx, MINIMUM_GAS_LIMIT};

        let block_gas_limit = self.gas_config.block_gas_limit;
        let mut block_gas_used: u64 = 0;
        let mut results = Vec::with_capacity(transactions.len());

        for tx in transactions {
            // Pre-compute gas cost to check block limit
            let gas_cost = compute_gas_for_vm_v0_tx(tx)
                .map(|r| r.gas_cost)
                .unwrap_or(MINIMUM_GAS_LIMIT);

            // M18: Check if adding this tx would exceed block gas limit
            // Use checked_add for overflow detection
            let projected_gas = match block_gas_used.checked_add(gas_cost) {
                Some(g) => g,
                None => break, // Overflow: block full
            };

            if projected_gas > block_gas_limit {
                break;
            }

            // Execute the transaction with proposer rewards
            let result = self.execute_tx_with_gas_and_proposer(state, tx, Some(proposer));

            // M18: Use checked_add for block gas accounting
            if result.success {
                block_gas_used = match block_gas_used.checked_add(result.gas_used) {
                    Some(g) => g,
                    None => break, // Overflow: stop block processing
                };
            }

            results.push(result);
        }

        results
    }

    /// Execute a block with proposer rewards and return block statistics (T193).
    ///
    /// This variant returns both the transaction results and block-level statistics,
    /// including the total fees credited to the proposer.
    ///
    /// # Arguments
    ///
    /// * `state` - The mutable account state
    /// * `transactions` - The transactions to execute in order
    /// * `proposer` - The block proposer's account ID (receives fee rewards)
    ///
    /// # Returns
    ///
    /// A tuple of (results, stats) where:
    /// - results: Vector of `VmV0TxResult` for each transaction
    /// - stats: `VmV0BlockStats` with block-level gas and fee information
    pub fn execute_block_with_proposer_and_stats<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        transactions: &[QbindTransaction],
        proposer: &AccountId,
    ) -> (Vec<VmV0TxResult>, VmV0BlockStats) {
        let results = self.execute_block_with_proposer(state, transactions, proposer);

        let stats = VmV0BlockStats {
            total_gas_used: results.iter().map(|r| r.gas_used).sum(),
            total_fees_burned: results.iter().map(|r| r.fee_burned).sum(),
            total_fees_to_proposer: results.iter().map(|r| r.fee_to_proposer).sum(),
            txs_executed: results.len(),
            txs_succeeded: results.iter().filter(|r| r.success).count(),
        };

        (results, stats)
    }

    /// Execute a block with gas enforcement and return block statistics (T168).
    ///
    /// This variant returns both the transaction results and block-level statistics.
    ///
    /// # Arguments
    ///
    /// * `state` - The mutable account state
    /// * `transactions` - The transactions to execute in order
    ///
    /// # Returns
    ///
    /// A tuple of (results, stats) where:
    /// - results: Vector of `VmV0TxResult` for each transaction (may be shorter than input if block limit reached)
    /// - stats: `VmV0BlockStats` with block-level gas information
    pub fn execute_block_with_stats<S: AccountStateUpdater>(
        &self,
        state: &mut S,
        transactions: &[QbindTransaction],
    ) -> (Vec<VmV0TxResult>, VmV0BlockStats) {
        let results = if self.gas_config.enabled {
            self.execute_block_with_gas(state, transactions)
        } else {
            self.execute_block(state, transactions)
        };

        let stats = VmV0BlockStats {
            total_gas_used: results.iter().map(|r| r.gas_used).sum(),
            total_fees_burned: results.iter().map(|r| r.fee_burned).sum(),
            total_fees_to_proposer: results.iter().map(|r| r.fee_to_proposer).sum(),
            txs_executed: results.len(),
            txs_succeeded: results.iter().filter(|r| r.success).count(),
        };

        (results, stats)
    }
}

/// Block-level execution statistics (T168, T193).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VmV0BlockStats {
    /// Total gas used by all executed transactions.
    pub total_gas_used: u64,
    /// Total fees burned (removed from supply) by all transactions.
    pub total_fees_burned: u128,
    /// Total fees credited to block proposer by all transactions (T193).
    pub total_fees_to_proposer: u128,
    /// Number of transactions executed (may be less than submitted if block limit reached).
    pub txs_executed: usize,
    /// Number of transactions that succeeded.
    pub txs_succeeded: usize,
}

impl VmV0BlockStats {
    /// Get the total fees charged (burned + proposer).
    ///
    /// M18: Uses checked arithmetic to prevent overflow. Returns None on overflow.
    pub fn total_fees(&self) -> Option<u128> {
        self.total_fees_burned.checked_add(self.total_fees_to_proposer)
    }

    /// Get the total fees charged (burned + proposer), saturating on overflow.
    ///
    /// Use `total_fees()` for checked arithmetic in consensus-critical code.
    pub fn total_fees_saturating(&self) -> u128 {
        self.total_fees_burned
            .saturating_add(self.total_fees_to_proposer)
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