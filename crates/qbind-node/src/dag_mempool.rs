//! T158 DAG mempool v0: Local batches + DAG structure.
//!
//! This module provides the core data structures and in-memory implementation
//! for a DAG-based mempool as described in `QBIND_DAG_MEMPOOL_DESIGN.md`:
//!
//! - `QbindBatch`: A batch of transactions created by a validator
//! - `BatchId`: SHA3-256 hash identifying a batch
//! - `BatchRef`: Reference to a batch (creator + batch_id)
//! - `BatchSignature`: ML-DSA-44 signature over batch metadata
//! - `DagMempool` trait: Interface for DAG mempool operations
//! - `InMemoryDagMempool`: In-memory implementation for DevNet v0
//!
//! ## Design Goals (T158)
//!
//! 1. Define `QbindBatch` and related types consistent with the design doc
//! 2. Implement local tx → batch → DAG handling
//! 3. Provide frontier selection for block proposals
//! 4. Support feature-flagged integration with proposer (optional)
//! 5. Track metrics for DAG operations
//!
//! ## Non-Goals (T158)
//!
//! - Full Narwhal-style availability certificates (future task)
//! - Cross-node certificate protocol (future task)
//! - Changing consensus rules or HotStuff finality
//!
//! ## Canonical Encoding
//!
//! All batch encoding uses deterministic, portable byte layouts:
//! - Integers: little-endian encoding
//! - Lengths: u32 little-endian prefix
//! - Arrays: length-prefixed with elements concatenated
//!
//! This ensures `batch_id` is identical on all nodes for the same input.
//!
//! ## T159: Chain-Aware Domain Separation
//!
//! As of T159, all signing preimages include the chain ID to prevent cross-chain
//! replay attacks. Use `signing_preimage_with_chain_id()` with the appropriate
//! `ChainId` for the network environment (DevNet, TestNet, MainNet).

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use parking_lot::RwLock;
use qbind_consensus::ids::ValidatorId;
use qbind_hash::sha3_256;
use qbind_ledger::QbindTransaction;
use qbind_types::domain::{domain_prefix, DomainKind};
use qbind_types::{ChainId, QBIND_DEVNET_CHAIN_ID};

// ============================================================================
// Domain Tags
// ============================================================================

/// Legacy domain separator for batch signing preimages.
///
/// **DEPRECATED (T159)**: Use `domain_prefix(chain_id, DomainKind::Batch)` instead.
///
/// Format: `QBIND:BATCH:v1` || creator || view_hint || parents || tx_root
///
/// This tag prevents cross-protocol signature reuse and ensures domain
/// separation as required by the DAG mempool design spec.
pub const BATCH_DOMAIN_TAG: &[u8] = b"QBIND:BATCH:v1";

// ============================================================================
// Batch Identifier Types
// ============================================================================

/// A 32-byte batch identifier computed as SHA3-256 of canonical batch encoding.
///
/// The batch ID is computed over:
/// - creator (u64, little-endian)
/// - view_hint (u64, little-endian)
/// - parents (length-prefixed array of BatchRef)
/// - txs (length-prefixed array of canonical tx encodings)
///
/// The signature is NOT included in the batch ID computation.
pub type BatchId = [u8; 32];

/// Reference to a batch in the DAG.
///
/// A batch reference consists of:
/// - `creator`: The validator who created the batch
/// - `batch_id`: The SHA3-256 hash identifying the batch
///
/// Batch references are used in parent links to form the DAG structure.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct BatchRef {
    /// The validator who created the referenced batch.
    pub creator: ValidatorId,
    /// The batch ID (SHA3-256 hash).
    pub batch_id: BatchId,
}

impl BatchRef {
    /// Create a new batch reference.
    pub fn new(creator: ValidatorId, batch_id: BatchId) -> Self {
        Self { creator, batch_id }
    }

    /// Compute canonical encoding for hashing/signing.
    ///
    /// Format: creator (8 bytes, LE) || batch_id (32 bytes)
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 32);
        out.extend_from_slice(&self.creator.as_u64().to_le_bytes());
        out.extend_from_slice(&self.batch_id);
        out
    }
}

/// ML-DSA-44 signature over batch metadata.
///
/// The signature covers the batch signing preimage (domain-separated),
/// NOT the full batch including transactions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchSignature {
    /// The raw signature bytes.
    pub bytes: Vec<u8>,
}

impl BatchSignature {
    /// Create a new batch signature from bytes.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create an empty (unsigned) batch signature.
    pub fn empty() -> Self {
        Self { bytes: Vec::new() }
    }

    /// Check if the signature is empty (unsigned).
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Get the signature bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

// ============================================================================
// T165: Batch Acknowledgment & Availability Certificate Types
// ============================================================================

/// A batch acknowledgment from a validator (T165).
///
/// A `BatchAck` represents a validator's attestation that they have stored
/// a specific batch. When ≥2f+1 validators acknowledge a batch, the batch
/// can form a `BatchCertificate` proving data availability.
///
/// ## Signing Preimage
///
/// ```text
/// QBIND:<SCOPE>:BATCH_ACK:v1  (variable length based on scope)
/// batch_ref.creator           (8 bytes, little-endian)
/// batch_ref.batch_id          (32 bytes)
/// validator_id                (8 bytes, little-endian)
/// view_hint                   (8 bytes, little-endian)
/// ```
///
/// ## Security Properties
///
/// - Chain-aware domain separation prevents cross-chain ack replay
/// - Each validator can only submit one ack per batch
/// - Signature covers batch_ref to prevent ack reuse across batches
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchAck {
    /// Reference to the acknowledged batch (creator + batch_id).
    pub batch_ref: BatchRef,
    /// The validator who is acknowledging the batch.
    pub validator_id: ValidatorId,
    /// View hint at the time of acknowledgment (for ordering/debugging).
    pub view_hint: u64,
    /// Signature suite ID (100 for ML-DSA-44).
    pub suite_id: u16,
    /// ML-DSA-44 signature over the acknowledgment preimage.
    pub signature: Vec<u8>,
}

/// Type alias for signature bytes used in BatchAck.
pub type SignatureBytes = Vec<u8>;

impl BatchAck {
    /// Compute the signing preimage for a batch acknowledgment with chain ID.
    ///
    /// ## Format
    ///
    /// ```text
    /// QBIND:<SCOPE>:BATCH_ACK:v1  (variable length based on scope)
    /// batch_ref.creator           (8 bytes, little-endian)
    /// batch_ref.batch_id          (32 bytes)
    /// validator_id                (8 bytes, little-endian)
    /// view_hint                   (8 bytes, little-endian)
    /// ```
    pub fn signing_preimage_with_chain_id(
        chain_id: ChainId,
        batch_ref: &BatchRef,
        validator_id: ValidatorId,
        view_hint: u64,
    ) -> Vec<u8> {
        let domain_tag = domain_prefix(chain_id, DomainKind::BatchAck);
        let mut out = Vec::with_capacity(domain_tag.len() + 8 + 32 + 8 + 8);

        // Domain tag (chain-aware)
        out.extend_from_slice(&domain_tag);

        // Batch reference (creator + batch_id)
        out.extend_from_slice(&batch_ref.creator.as_u64().to_le_bytes());
        out.extend_from_slice(&batch_ref.batch_id);

        // Validator ID (8 bytes, LE)
        out.extend_from_slice(&validator_id.as_u64().to_le_bytes());

        // View hint (8 bytes, LE)
        out.extend_from_slice(&view_hint.to_le_bytes());

        out
    }

    /// Create a new signed batch acknowledgment.
    ///
    /// # Arguments
    ///
    /// * `batch_ref` - Reference to the batch being acknowledged
    /// * `validator_id` - The validator creating this ack
    /// * `view_hint` - Current view hint for ordering
    /// * `chain_id` - Chain ID for domain separation
    /// * `suite_id` - Signature suite ID (100 for ML-DSA-44)
    /// * `sign_fn` - Signing function that takes preimage and returns signature
    ///
    /// # Returns
    ///
    /// A signed `BatchAck` if signing succeeds.
    pub fn new_signed<F, E>(
        batch_ref: BatchRef,
        validator_id: ValidatorId,
        view_hint: u64,
        chain_id: ChainId,
        suite_id: u16,
        sign_fn: F,
    ) -> Result<Self, E>
    where
        F: FnOnce(&[u8]) -> Result<Vec<u8>, E>,
    {
        let preimage =
            Self::signing_preimage_with_chain_id(chain_id, &batch_ref, validator_id, view_hint);
        let signature = sign_fn(&preimage)?;

        Ok(Self {
            batch_ref,
            validator_id,
            view_hint,
            suite_id,
            signature,
        })
    }

    /// Create an unsigned batch acknowledgment (for testing).
    pub fn new_unsigned(
        batch_ref: BatchRef,
        validator_id: ValidatorId,
        view_hint: u64,
        suite_id: u16,
    ) -> Self {
        Self {
            batch_ref,
            validator_id,
            view_hint,
            suite_id,
            signature: Vec::new(),
        }
    }

    /// Check if this ack is unsigned (empty signature).
    pub fn is_unsigned(&self) -> bool {
        self.signature.is_empty()
    }

    /// Get the batch ID being acknowledged.
    pub fn batch_id(&self) -> &BatchId {
        &self.batch_ref.batch_id
    }
}

/// A batch availability certificate (T165 v1).
///
/// A `BatchCertificate` proves that a batch has been stored by ≥2f+1 validators,
/// guaranteeing data availability. This is the v1 implementation that stores
/// the list of acknowledging validators without signature aggregation.
///
/// ## Invariants
///
/// - `signers.len() >= quorum_size` (typically 2f+1)
/// - All signers must have provided valid acks for the same `batch_ref`
/// - The certificate is immutable once formed
///
/// ## Future Versions
///
/// V2 may include:
/// - Aggregated signatures (when PQ aggregate schemes mature)
/// - More compact signer representation (bitfields)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BatchCertificate {
    /// Reference to the certified batch.
    pub batch_ref: BatchRef,
    /// Canonical view at which this certificate was formed.
    pub view: u64,
    /// Validators who acknowledged this batch (2f+1 or more).
    pub signers: Vec<ValidatorId>,
    /// Placeholder for future aggregated signature.
    /// In v1, this is always `None`.
    pub aggregated: Option<SignatureBytes>,
}

impl BatchCertificate {
    /// Create a new batch certificate from acknowledged signers.
    ///
    /// # Arguments
    ///
    /// * `batch_ref` - Reference to the certified batch
    /// * `view` - View at which the certificate was formed
    /// * `signers` - Validators who acknowledged the batch
    ///
    /// # Panics (debug)
    ///
    /// Debug builds will assert that signers is not empty.
    pub fn new(batch_ref: BatchRef, view: u64, signers: Vec<ValidatorId>) -> Self {
        debug_assert!(
            !signers.is_empty(),
            "certificate must have at least one signer"
        );
        Self {
            batch_ref,
            view,
            signers,
            aggregated: None,
        }
    }

    /// Get the batch ID for this certificate.
    pub fn batch_id(&self) -> &BatchId {
        &self.batch_ref.batch_id
    }

    /// Get the number of signers in this certificate.
    pub fn num_signers(&self) -> usize {
        self.signers.len()
    }

    /// Check if this certificate has enough signers for the given quorum.
    pub fn has_quorum(&self, quorum_size: usize) -> bool {
        self.signers.len() >= quorum_size
    }

    /// Check if a validator is a signer of this certificate.
    pub fn has_signer(&self, validator_id: ValidatorId) -> bool {
        self.signers.contains(&validator_id)
    }
}

// ============================================================================
// T165: Batch Ack Tracker
// ============================================================================

/// Result of inserting a batch acknowledgment into the tracker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchAckResult {
    /// Ack was accepted and stored.
    Accepted,
    /// Ack was accepted and a certificate was formed (quorum reached).
    CertificateFormed(BatchCertificate),
    /// Ack was rejected because the validator already acked this batch.
    DuplicateAck,
    /// Ack was rejected because the batch is unknown.
    UnknownBatch,
    /// Ack was rejected due to invalid signature.
    InvalidSignature,
    /// Ack was rejected for another reason.
    Rejected(String),
}

/// Tracker for batch acknowledgments and certificate formation (T165).
///
/// The `BatchAckTracker` accumulates acknowledgments for batches and
/// automatically forms `BatchCertificate`s when quorum is reached.
///
/// ## Design
///
/// - Each batch can accumulate acks from multiple validators
/// - When ack count reaches `quorum_size`, a certificate is formed
/// - Duplicate acks from the same validator are rejected
/// - Once a certificate is formed, additional acks are still tracked
///   but do not affect the certificate
///
/// ## Thread Safety
///
/// This struct is NOT thread-safe. It should be protected by the
/// parent `InMemoryDagMempool`'s lock.
#[derive(Debug)]
pub struct BatchAckTracker {
    /// Acks indexed by batch ID.
    acks: HashMap<BatchId, Vec<BatchAck>>,
    /// Certificates formed for batches.
    certs: HashMap<BatchId, BatchCertificate>,
    /// Quorum size required for certificate formation.
    quorum_size: usize,
    /// View at which tracker was last updated (for cert view assignment).
    current_view: u64,
}

impl BatchAckTracker {
    /// Create a new batch ack tracker with the given quorum size.
    ///
    /// # Arguments
    ///
    /// * `quorum_size` - Number of acks required to form a certificate (typically 2f+1)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// // For 4 validators (f=1, n=3f+1=4), quorum = 2f+1 = 3
    /// let tracker = BatchAckTracker::new(3);
    /// ```
    pub fn new(quorum_size: usize) -> Self {
        Self {
            acks: HashMap::new(),
            certs: HashMap::new(),
            quorum_size,
            current_view: 0,
        }
    }

    /// Set the current view for certificate formation.
    pub fn set_current_view(&mut self, view: u64) {
        self.current_view = view;
    }

    /// Get the quorum size.
    pub fn quorum_size(&self) -> usize {
        self.quorum_size
    }

    /// Insert a batch acknowledgment.
    ///
    /// This method assumes the ack's signature has already been verified.
    /// Use the result to determine metrics updates.
    ///
    /// # Arguments
    ///
    /// * `ack` - The batch acknowledgment to insert
    /// * `batch_exists` - Whether the batch exists in the mempool
    ///
    /// # Returns
    ///
    /// The result of the insertion:
    /// - `Accepted`: Ack stored, no certificate formed yet
    /// - `CertificateFormed`: Ack stored and certificate formed (quorum reached)
    /// - `DuplicateAck`: Same validator already acked this batch
    /// - `UnknownBatch`: Batch not found in mempool
    pub fn insert_ack(&mut self, ack: BatchAck, batch_exists: bool) -> BatchAckResult {
        let batch_id = *ack.batch_id();

        // Check if batch exists (if required)
        if !batch_exists {
            return BatchAckResult::UnknownBatch;
        }

        // Check for duplicate ack from the same validator
        if let Some(existing_acks) = self.acks.get(&batch_id) {
            if existing_acks
                .iter()
                .any(|a| a.validator_id == ack.validator_id)
            {
                return BatchAckResult::DuplicateAck;
            }
        }

        // Insert the ack
        let acks = self.acks.entry(batch_id).or_default();
        let batch_ref = ack.batch_ref.clone();
        acks.push(ack);

        // Check if we've reached quorum and don't already have a cert
        if acks.len() >= self.quorum_size && !self.certs.contains_key(&batch_id) {
            // Form a certificate
            let signers: Vec<ValidatorId> = acks.iter().map(|a| a.validator_id).collect();
            let cert = BatchCertificate::new(batch_ref, self.current_view, signers);
            let cert_clone = cert.clone();
            self.certs.insert(batch_id, cert);
            return BatchAckResult::CertificateFormed(cert_clone);
        }

        BatchAckResult::Accepted
    }

    /// Check if a batch has a certificate.
    pub fn has_certificate(&self, batch_id: &BatchId) -> bool {
        self.certs.contains_key(batch_id)
    }

    /// Get the certificate for a batch, if it exists.
    pub fn certificate(&self, batch_id: &BatchId) -> Option<&BatchCertificate> {
        self.certs.get(batch_id)
    }

    /// Get the number of acks for a batch.
    pub fn ack_count(&self, batch_id: &BatchId) -> usize {
        self.acks.get(batch_id).map(|a| a.len()).unwrap_or(0)
    }

    /// Get all batch IDs that have pending acks but no certificate.
    pub fn pending_batch_ids(&self) -> Vec<BatchId> {
        self.acks
            .keys()
            .filter(|id| !self.certs.contains_key(*id))
            .cloned()
            .collect()
    }

    /// Get the number of batches with certificates.
    pub fn cert_count(&self) -> usize {
        self.certs.len()
    }

    /// Get the number of batches with pending acks (no cert yet).
    pub fn pending_count(&self) -> usize {
        self.acks
            .keys()
            .filter(|id| !self.certs.contains_key(*id))
            .count()
    }

    /// Mark a batch as known (creates empty ack entry if not present).
    ///
    /// This is useful when a batch is inserted and we want to track
    /// that it exists even before any acks arrive.
    pub fn mark_batch_known(&mut self, batch_id: BatchId) {
        self.acks.entry(batch_id).or_default();
    }

    /// Clear all acks and certificates (for testing/reset).
    #[cfg(test)]
    pub fn clear(&mut self) {
        self.acks.clear();
        self.certs.clear();
    }
}

// ============================================================================
// QbindBatch
// ============================================================================

/// A batch of transactions created by a validator for the DAG mempool.
///
/// Batches form the nodes of the DAG mempool structure. Each batch:
/// - Is created by a single validator (`creator`)
/// - Contains a set of transactions (`txs`)
/// - References parent batches from previous rounds (`parents`)
/// - Is signed by the creator (`signature`)
///
/// ## Canonical Encoding (for batch_id computation)
///
/// The batch ID is the SHA3-256 hash of:
/// ```text
/// creator:    u64 (8 bytes, little-endian)
/// view_hint:  u64 (8 bytes, little-endian)
/// num_parents: u32 (4 bytes, little-endian)
/// parents:    [BatchRef] (each 40 bytes: creator + batch_id)
/// num_txs:    u32 (4 bytes, little-endian)
/// txs:        [tx_canonical_bytes] (each tx's signing preimage)
/// ```
///
/// The signature is NOT included in the batch ID.
///
/// ## Signing Preimage
///
/// The signing preimage is:
/// ```text
/// QBIND:BATCH:v1 || creator || view_hint || parents_root || tx_root
/// ```
///
/// Where `parents_root` and `tx_root` are SHA3-256 hashes of the respective
/// arrays, providing a compact commitment for signing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QbindBatch {
    /// Unique identifier for this batch (SHA3-256 of canonical encoding).
    pub batch_id: BatchId,
    /// The validator who created this batch.
    pub creator: ValidatorId,
    /// Logical round/view hint (for future HotStuff round alignment).
    /// This doesn't drive consensus in T158 but is included for forward compatibility.
    pub view_hint: u64,
    /// References to parent batches (from previous rounds).
    pub parents: Vec<BatchRef>,
    /// Transactions included in this batch.
    pub txs: Vec<QbindTransaction>,
    /// ML-DSA-44 signature over the batch signing preimage.
    pub signature: BatchSignature,
}

impl QbindBatch {
    /// Create a new unsigned batch.
    ///
    /// The batch_id is computed automatically from the canonical encoding.
    /// Use `sign()` to add a signature after creation.
    pub fn new(
        creator: ValidatorId,
        view_hint: u64,
        parents: Vec<BatchRef>,
        txs: Vec<QbindTransaction>,
    ) -> Self {
        let batch_id = compute_batch_id(creator, view_hint, &parents, &txs);
        Self {
            batch_id,
            creator,
            view_hint,
            parents,
            txs,
            signature: BatchSignature::empty(),
        }
    }

    /// Create a batch with an existing signature.
    ///
    /// Verifies that the batch_id matches the computed value.
    pub fn with_signature(
        creator: ValidatorId,
        view_hint: u64,
        parents: Vec<BatchRef>,
        txs: Vec<QbindTransaction>,
        signature: BatchSignature,
    ) -> Self {
        let batch_id = compute_batch_id(creator, view_hint, &parents, &txs);
        Self {
            batch_id,
            creator,
            view_hint,
            parents,
            txs,
            signature,
        }
    }

    /// Compute the signing preimage for this batch with chain ID (T159).
    ///
    /// Format: `QBIND:<SCOPE>:BATCH:v1 || creator || view_hint || parents_root || tx_root`
    ///
    /// Where `<SCOPE>` is "DEV", "TST", "MAIN", or "UNK" based on the chain ID.
    ///
    /// This is what gets signed by the creator's ML-DSA-44 key.
    pub fn signing_preimage_with_chain_id(&self, chain_id: ChainId) -> Vec<u8> {
        batch_signing_preimage_with_chain_id(
            chain_id,
            self.creator,
            self.view_hint,
            &self.parents,
            &self.txs,
        )
    }

    /// Compute the signing preimage using the default DevNet chain ID.
    ///
    /// **Note (T159)**: This method defaults to `QBIND_DEVNET_CHAIN_ID`. For
    /// explicit chain control, use `signing_preimage_with_chain_id()` instead.
    ///
    /// Format: `QBIND:DEV:BATCH:v1 || creator || view_hint || parents_root || tx_root`
    ///
    /// This is what gets signed by the creator's ML-DSA-44 key.
    pub fn signing_preimage(&self) -> Vec<u8> {
        self.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID)
    }

    /// Sign this batch with the given secret key and chain ID (T159).
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key bytes (must be ML_DSA_44_SECRET_KEY_SIZE bytes)
    /// * `chain_id` - The chain ID for domain separation
    ///
    /// # Returns
    ///
    /// `Ok(())` if signing succeeded, `Err` otherwise.
    pub fn sign_with_chain_id(&mut self, sk: &[u8], chain_id: ChainId) -> Result<(), BatchError> {
        use qbind_crypto::ml_dsa44::MlDsa44Backend;

        let preimage = self.signing_preimage_with_chain_id(chain_id);
        let sig_bytes =
            MlDsa44Backend::sign(sk, &preimage).map_err(|_| BatchError::SigningFailed)?;
        self.signature = BatchSignature::new(sig_bytes);
        Ok(())
    }

    /// Sign this batch using the default DevNet chain ID.
    ///
    /// **Note (T159)**: This method defaults to `QBIND_DEVNET_CHAIN_ID`. For
    /// explicit chain control, use `sign_with_chain_id()` instead.
    ///
    /// # Arguments
    ///
    /// * `sk` - The secret key bytes (must be ML_DSA_44_SECRET_KEY_SIZE bytes)
    ///
    /// # Returns
    ///
    /// `Ok(())` if signing succeeded, `Err` otherwise.
    pub fn sign(&mut self, sk: &[u8]) -> Result<(), BatchError> {
        self.sign_with_chain_id(sk, QBIND_DEVNET_CHAIN_ID)
    }

    /// Verify the batch signature against the given public key with chain ID (T159).
    ///
    /// # Arguments
    ///
    /// * `pk` - The creator's public key bytes (ML-DSA-44)
    /// * `chain_id` - The chain ID for domain separation
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err` otherwise.
    pub fn verify_signature_with_chain_id(
        &self,
        pk: &[u8],
        chain_id: ChainId,
    ) -> Result<(), BatchError> {
        use qbind_crypto::ml_dsa44::{
            MlDsa44Backend, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE,
        };

        if pk.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(BatchError::InvalidPublicKey);
        }

        if self.signature.bytes.len() != ML_DSA_44_SIGNATURE_SIZE {
            return Err(BatchError::InvalidSignature);
        }

        let preimage = self.signing_preimage_with_chain_id(chain_id);
        MlDsa44Backend::verify(pk, &preimage, &self.signature.bytes)
            .map_err(|_| BatchError::SignatureVerificationFailed)
    }

    /// Verify the batch signature using the default DevNet chain ID.
    ///
    /// **Note (T159)**: This method defaults to `QBIND_DEVNET_CHAIN_ID`. For
    /// explicit chain control, use `verify_signature_with_chain_id()` instead.
    ///
    /// # Arguments
    ///
    /// * `pk` - The creator's public key bytes (ML-DSA-44)
    ///
    /// # Returns
    ///
    /// `Ok(())` if the signature is valid, `Err` otherwise.
    pub fn verify_signature(&self, pk: &[u8]) -> Result<(), BatchError> {
        self.verify_signature_with_chain_id(pk, QBIND_DEVNET_CHAIN_ID)
    }

    /// Get the number of transactions in this batch.
    pub fn tx_count(&self) -> usize {
        self.txs.len()
    }

    /// Check if this batch has been signed.
    pub fn is_signed(&self) -> bool {
        !self.signature.is_empty()
    }
}

/// Errors that can occur during batch operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchError {
    /// Signing operation failed.
    SigningFailed,
    /// Public key is malformed or wrong size.
    InvalidPublicKey,
    /// Signature is malformed or wrong size.
    InvalidSignature,
    /// Signature verification failed.
    SignatureVerificationFailed,
    /// Batch ID mismatch (computed != provided).
    BatchIdMismatch,
}

impl std::fmt::Display for BatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BatchError::SigningFailed => write!(f, "batch signing failed"),
            BatchError::InvalidPublicKey => write!(f, "invalid public key"),
            BatchError::InvalidSignature => write!(f, "invalid signature"),
            BatchError::SignatureVerificationFailed => write!(f, "signature verification failed"),
            BatchError::BatchIdMismatch => write!(f, "batch ID mismatch"),
        }
    }
}

impl std::error::Error for BatchError {}

// ============================================================================
// Batch Hashing & Signing Helpers
// ============================================================================

/// Compute the canonical encoding of batch metadata for hashing.
///
/// This encoding is used to compute the batch ID (SHA3-256).
///
/// ## Format
///
/// ```text
/// creator:     u64 (8 bytes, little-endian)
/// view_hint:   u64 (8 bytes, little-endian)
/// num_parents: u32 (4 bytes, little-endian)
/// parents:     [BatchRef] (each 40 bytes: 8 + 32)
/// num_txs:     u32 (4 bytes, little-endian)
/// txs:         [tx_preimage] (each tx's signing preimage bytes)
/// ```
fn batch_canonical_encoding(
    creator: ValidatorId,
    view_hint: u64,
    parents: &[BatchRef],
    txs: &[QbindTransaction],
) -> Vec<u8> {
    let mut out = Vec::new();

    // Creator (8 bytes, LE)
    out.extend_from_slice(&creator.as_u64().to_le_bytes());

    // View hint (8 bytes, LE)
    out.extend_from_slice(&view_hint.to_le_bytes());

    // Parents (length-prefixed)
    let num_parents = parents.len() as u32;
    out.extend_from_slice(&num_parents.to_le_bytes());
    for parent in parents {
        out.extend_from_slice(&parent.canonical_bytes());
    }

    // Transactions (length-prefixed)
    let num_txs = txs.len() as u32;
    out.extend_from_slice(&num_txs.to_le_bytes());
    for tx in txs {
        // Use the transaction's signing preimage as canonical encoding
        let tx_bytes = tx.signing_preimage();
        let tx_len = tx_bytes.len() as u32;
        out.extend_from_slice(&tx_len.to_le_bytes());
        out.extend_from_slice(&tx_bytes);
    }

    out
}

/// Compute the batch ID as SHA3-256 of canonical encoding.
///
/// # Arguments
///
/// * `creator` - The validator who created this batch
/// * `view_hint` - Logical round/view hint
/// * `parents` - References to parent batches
/// * `txs` - Transactions in this batch
///
/// # Returns
///
/// A 32-byte batch ID.
pub fn compute_batch_id(
    creator: ValidatorId,
    view_hint: u64,
    parents: &[BatchRef],
    txs: &[QbindTransaction],
) -> BatchId {
    let encoding = batch_canonical_encoding(creator, view_hint, parents, txs);
    sha3_256(&encoding)
}

/// Compute the signing preimage for a batch with chain ID (T159).
///
/// ## Format
///
/// ```text
/// QBIND:<SCOPE>:BATCH:v1  (variable length based on scope)
/// creator                  (8 bytes, little-endian)
/// view_hint                (8 bytes, little-endian)
/// parents_root             (32 bytes, SHA3-256 of parents encoding)
/// tx_root                  (32 bytes, SHA3-256 of txs encoding)
/// ```
///
/// Where `<SCOPE>` is "DEV", "TST", "MAIN", or "UNK" based on the chain ID.
///
/// Using roots instead of full data keeps the preimage compact for signing.
pub fn batch_signing_preimage_with_chain_id(
    chain_id: ChainId,
    creator: ValidatorId,
    view_hint: u64,
    parents: &[BatchRef],
    txs: &[QbindTransaction],
) -> Vec<u8> {
    let domain_tag = domain_prefix(chain_id, DomainKind::Batch);
    let mut out = Vec::with_capacity(domain_tag.len() + 8 + 8 + 32 + 32);

    // Domain tag (chain-aware)
    out.extend_from_slice(&domain_tag);

    // Creator (8 bytes, LE)
    out.extend_from_slice(&creator.as_u64().to_le_bytes());

    // View hint (8 bytes, LE)
    out.extend_from_slice(&view_hint.to_le_bytes());

    // Parents root (SHA3-256 of parents encoding)
    let mut parents_bytes = Vec::new();
    let num_parents = parents.len() as u32;
    parents_bytes.extend_from_slice(&num_parents.to_le_bytes());
    for parent in parents {
        parents_bytes.extend_from_slice(&parent.canonical_bytes());
    }
    let parents_root = sha3_256(&parents_bytes);
    out.extend_from_slice(&parents_root);

    // Tx root (SHA3-256 of txs encoding) - use chain-aware tx preimage
    let mut txs_bytes = Vec::new();
    let num_txs = txs.len() as u32;
    txs_bytes.extend_from_slice(&num_txs.to_le_bytes());
    for tx in txs {
        let tx_preimage = tx.signing_preimage_with_chain_id(chain_id);
        let tx_len = tx_preimage.len() as u32;
        txs_bytes.extend_from_slice(&tx_len.to_le_bytes());
        txs_bytes.extend_from_slice(&tx_preimage);
    }
    let tx_root = sha3_256(&txs_bytes);
    out.extend_from_slice(&tx_root);

    out
}

/// Compute the signing preimage for a batch using DevNet chain ID.
///
/// **Note (T159)**: This function defaults to `QBIND_DEVNET_CHAIN_ID`. For
/// explicit chain control, use `batch_signing_preimage_with_chain_id()` instead.
///
/// ## Format
///
/// ```text
/// QBIND:DEV:BATCH:v1  (18 bytes for DevNet)
/// creator              (8 bytes, little-endian)
/// view_hint            (8 bytes, little-endian)
/// parents_root         (32 bytes, SHA3-256 of parents encoding)
/// tx_root              (32 bytes, SHA3-256 of txs encoding)
/// ```
///
/// Using roots instead of full data keeps the preimage compact for signing.
pub fn batch_signing_preimage(
    creator: ValidatorId,
    view_hint: u64,
    parents: &[BatchRef],
    txs: &[QbindTransaction],
) -> Vec<u8> {
    batch_signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID, creator, view_hint, parents, txs)
}

// ============================================================================
// Transaction ID for Deduplication
// ============================================================================

/// A transaction ID for deduplication purposes.
///
/// Computed as (sender, nonce) tuple hash to identify unique transactions.
pub type TxId = [u8; 32];

/// Compute a transaction ID for deduplication.
///
/// Uses (sender, nonce) as the unique identifier.
pub fn compute_tx_id(tx: &QbindTransaction) -> TxId {
    let mut bytes = Vec::with_capacity(32 + 8);
    bytes.extend_from_slice(&tx.sender);
    bytes.extend_from_slice(&tx.nonce.to_le_bytes());
    sha3_256(&bytes)
}

// ============================================================================
// DagMempool Trait
// ============================================================================

/// Errors that can occur during DAG mempool operations.
#[derive(Debug, thiserror::Error)]
pub enum DagMempoolError {
    /// The DAG mempool is at capacity.
    #[error("dag mempool full")]
    Full,
    /// The batch is invalid.
    #[error("invalid batch: {0}")]
    Invalid(String),
    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

/// Statistics about the DAG mempool state.
#[derive(Debug, Clone, Default)]
pub struct DagMempoolStats {
    /// Total number of batches in the DAG.
    pub num_batches: usize,
    /// Total number of edges (parent references) in the DAG.
    pub num_edges: usize,
    /// Total number of transactions across all batches.
    pub num_txs: usize,
    /// Number of pending (unbatched) transactions.
    pub pending_txs: usize,
    /// Number of committed transactions.
    pub committed_txs: usize,
}

/// DAG mempool abstraction for QBIND.
///
/// The DAG mempool provides an alternative to the FIFO mempool that:
/// - Organizes transactions into signed batches
/// - Forms a DAG structure via parent references
/// - Allows parallel batch creation by all validators
/// - Provides deterministic frontier selection for proposals
///
/// ## Thread Safety
///
/// Implementations must be `Send + Sync` to support concurrent access
/// from consensus and network threads.
pub trait DagMempool: Send + Sync {
    /// Inject locally-generated transactions.
    ///
    /// The mempool will batch these transactions into `QbindBatch` structures
    /// according to its batching policy (e.g., batch size, timing).
    ///
    /// # Arguments
    ///
    /// * `txs` - Transactions to add to the pending pool
    ///
    /// # Returns
    ///
    /// `Ok(())` if transactions were accepted, `Err` if the mempool is full
    /// or the transactions are invalid.
    fn insert_local_txs(&self, txs: Vec<QbindTransaction>) -> Result<(), DagMempoolError>;

    /// Handle a fully-formed batch from another validator.
    ///
    /// This is called when a remote batch is received via the network.
    /// The batch should be validated (signature, parents) before insertion.
    ///
    /// # Arguments
    ///
    /// * `batch` - The batch to insert
    ///
    /// # Returns
    ///
    /// `Ok(())` if the batch was accepted, `Err` if invalid or DAG is full.
    fn insert_remote_batch(&self, batch: QbindBatch) -> Result<(), DagMempoolError>;

    /// Select transactions from the DAG frontier for a block proposal.
    ///
    /// Returns up to `max_txs` transactions from batches that:
    /// - Have not been included in a committed block
    /// - Are not duplicates (same sender + nonce)
    ///
    /// The selection order is deterministic (same inputs → same outputs).
    ///
    /// # Arguments
    ///
    /// * `max_txs` - Maximum number of transactions to return
    ///
    /// # Returns
    ///
    /// A vector of transactions ready for inclusion in a block.
    fn select_frontier_txs(&self, max_txs: usize) -> Vec<QbindTransaction>;

    /// Mark transactions as committed after a block is finalized.
    ///
    /// This removes the committed transactions from future frontier selections
    /// and may trigger garbage collection of fully-committed batches.
    ///
    /// # Arguments
    ///
    /// * `committed` - The transactions that were committed
    fn mark_committed(&self, committed: &[QbindTransaction]);

    /// Get statistics about the current DAG state.
    fn stats(&self) -> DagMempoolStats;
}

// ============================================================================
// InMemoryDagMempool
// ============================================================================

/// Configuration for the in-memory DAG mempool.
#[derive(Clone, Debug)]
pub struct DagMempoolConfig {
    /// Maximum number of batches in the DAG.
    pub max_batches: usize,
    /// Maximum number of pending (unbatched) transactions.
    pub max_pending_txs: usize,
    /// Number of transactions per batch.
    pub batch_size: usize,
    /// Local validator ID (for batch creation).
    pub local_validator_id: ValidatorId,
    /// T169: Whether to enable fee-based priority and eviction.
    pub enable_fee_priority: bool,
}

impl Default for DagMempoolConfig {
    fn default() -> Self {
        Self {
            max_batches: 1000,
            max_pending_txs: 10000,
            batch_size: 100,
            local_validator_id: ValidatorId::new(0),
            enable_fee_priority: false,
        }
    }
}

impl DagMempoolConfig {
    /// Enforce configuration constraints (T169).
    ///
    /// Fee priority is typically coupled with gas enforcement in the execution layer.
    /// If you need to enable fee priority in DAG mempool, ensure gas is enabled in
    /// the execution config as well.
    ///
    /// This method is provided for explicit validation.
    pub fn with_fee_priority(mut self, enabled: bool) -> Self {
        self.enable_fee_priority = enabled;
        self
    }
}

/// Internal state for the DAG mempool.
struct DagInner {
    /// Next sequence number for local batches (reserved for future use).
    #[allow(dead_code)]
    next_local_batch_seq: u64,
    /// Batches indexed by batch ID.
    batches_by_id: HashMap<BatchId, StoredBatch>,
    /// Children mapping: batch_id -> list of child batch IDs.
    children: HashMap<BatchId, Vec<BatchId>>,
    /// Pending transactions not yet batched.
    pending_txs: Vec<QbindTransaction>,
    /// Tie-breaking arrival counter for priority (T169).
    arrival_counter: u64,
    /// Map of (sender, nonce) -> arrival_id to preserve arrival order (T169).
    tx_arrivals: HashMap<(qbind_types::AccountId, u64), u64>,
    /// Set of seen transaction IDs for deduplication.
    tx_seen: HashSet<TxId>,
    /// Set of committed transaction IDs.
    tx_committed: HashSet<TxId>,
    /// Configuration.
    config: DagMempoolConfig,
    /// Latest batch ID per validator (for parent selection).
    latest_batch_per_validator: HashMap<ValidatorId, BatchId>,
    /// Current view hint (incremented for each local batch).
    current_view_hint: u64,
}

/// A batch stored in the DAG with metadata.
#[derive(Clone, Debug)]
struct StoredBatch {
    /// The batch itself.
    batch: QbindBatch,
    /// Whether this batch is fully acknowledged (reserved for future availability certs).
    #[allow(dead_code)]
    acknowledged: bool,
    /// Whether all txs in this batch are committed.
    fully_committed: bool,
}

impl StoredBatch {
    fn new(batch: QbindBatch) -> Self {
        Self {
            batch,
            acknowledged: false,
            fully_committed: false,
        }
    }
}

/// In-memory DAG mempool implementation for DevNet v0.
///
/// This is a simple implementation that:
/// - Batches local transactions when `batch_size` is reached
/// - Uses the latest known batch from each validator as parents
/// - Provides deterministic frontier selection via topological ordering
/// - Tracks committed transactions for deduplication
///
/// ## T165: Availability Certificates
///
/// When `availability_enabled` is true, the mempool also:
/// - Tracks batch acknowledgments from validators
/// - Forms `BatchCertificate`s when quorum is reached
/// - Exposes certificate status via `batch_certificate()` and `has_certificate()`
///
/// ## Thread Safety
///
/// Uses `parking_lot::RwLock` for interior mutability.
pub struct InMemoryDagMempool {
    inner: RwLock<DagInner>,
    /// Optional metrics for observability.
    metrics: Option<Arc<DagMempoolMetrics>>,
    /// Batch ack tracker for availability certificates (T165).
    ack_tracker: RwLock<BatchAckTracker>,
    /// Whether availability certificates are enabled.
    availability_enabled: bool,
}

impl InMemoryDagMempool {
    /// Create a new in-memory DAG mempool with default configuration.
    pub fn new(local_validator_id: ValidatorId) -> Self {
        let config = DagMempoolConfig {
            local_validator_id,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new in-memory DAG mempool with custom configuration.
    pub fn with_config(config: DagMempoolConfig) -> Self {
        // Default quorum_size = 1 (single node test), will be updated via enable_availability
        Self {
            inner: RwLock::new(DagInner {
                next_local_batch_seq: 0,
                batches_by_id: HashMap::new(),
                children: HashMap::new(),
                pending_txs: Vec::new(),
                arrival_counter: 0,
                tx_arrivals: HashMap::new(),
                tx_seen: HashSet::new(),
                tx_committed: HashSet::new(),
                config,
                latest_batch_per_validator: HashMap::new(),
                current_view_hint: 0,
            }),
            metrics: None,
            ack_tracker: RwLock::new(BatchAckTracker::new(1)),
            availability_enabled: false,
        }
    }

    /// Create a new in-memory DAG mempool with availability certificates enabled (T165).
    ///
    /// # Arguments
    ///
    /// * `config` - DAG mempool configuration
    /// * `quorum_size` - Number of acks required for certificate formation
    pub fn with_availability(config: DagMempoolConfig, quorum_size: usize) -> Self {
        Self {
            inner: RwLock::new(DagInner {
                next_local_batch_seq: 0,
                batches_by_id: HashMap::new(),
                children: HashMap::new(),
                pending_txs: Vec::new(),
                arrival_counter: 0,
                tx_arrivals: HashMap::new(),
                tx_seen: HashSet::new(),
                tx_committed: HashSet::new(),
                config,
                latest_batch_per_validator: HashMap::new(),
                current_view_hint: 0,
            }),
            metrics: None,
            ack_tracker: RwLock::new(BatchAckTracker::new(quorum_size)),
            availability_enabled: true,
        }
    }

    /// Enable availability certificates with the given quorum size (T165).
    ///
    /// This can be called after construction to enable availability tracking.
    pub fn enable_availability(&mut self, quorum_size: usize) {
        self.availability_enabled = true;
        *self.ack_tracker.write() = BatchAckTracker::new(quorum_size);
    }

    /// Check if availability certificates are enabled.
    pub fn is_availability_enabled(&self) -> bool {
        self.availability_enabled
    }

    /// Attach metrics for observability.
    pub fn with_metrics(mut self, metrics: Arc<DagMempoolMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Get the metrics instance, if attached.
    pub fn metrics(&self) -> Option<&Arc<DagMempoolMetrics>> {
        self.metrics.as_ref()
    }

    // ========================================================================
    // T165: Batch Ack & Certificate Methods
    // ========================================================================

    /// Handle a batch acknowledgment (T165).
    ///
    /// This method processes a BatchAck and updates the ack tracker.
    /// If quorum is reached, a certificate is formed.
    ///
    /// # Arguments
    ///
    /// * `ack` - The batch acknowledgment to process
    ///
    /// # Returns
    ///
    /// The result of processing the ack:
    /// - `Accepted`: Ack stored, no certificate formed yet
    /// - `CertificateFormed`: Quorum reached, certificate created
    /// - `DuplicateAck`: This validator already acked this batch
    /// - `UnknownBatch`: The batch doesn't exist in the mempool
    ///
    /// # Note
    ///
    /// This method assumes the ack's signature has been verified by the caller.
    /// If availability is disabled, returns `Rejected`.
    pub fn handle_batch_ack(&self, ack: BatchAck) -> BatchAckResult {
        if !self.availability_enabled {
            return BatchAckResult::Rejected("availability not enabled".to_string());
        }

        let batch_id = *ack.batch_id();

        // Check if batch exists
        let batch_exists = {
            let inner = self.inner.read();
            inner.batches_by_id.contains_key(&batch_id)
        };

        // Process the ack
        let result = {
            let mut tracker = self.ack_tracker.write();
            tracker.insert_ack(ack, batch_exists)
        };

        // Update metrics
        if let Some(ref m) = self.metrics {
            match &result {
                BatchAckResult::Accepted => m.inc_batch_acks_accepted(),
                BatchAckResult::CertificateFormed(_) => {
                    m.inc_batch_acks_accepted();
                    m.inc_batch_certs_total();
                }
                BatchAckResult::DuplicateAck => m.inc_batch_acks_rejected_duplicate(),
                BatchAckResult::UnknownBatch => m.inc_batch_acks_rejected_unknown(),
                BatchAckResult::InvalidSignature => m.inc_batch_acks_rejected_bad_sig(),
                BatchAckResult::Rejected(_) => m.inc_batch_acks_rejected_other(),
            }
        }

        result
    }

    /// Check if a batch has a certificate (T165).
    ///
    /// Returns `true` if the batch has received >=quorum_size acks and
    /// a certificate has been formed.
    pub fn has_certificate(&self, batch_id: &BatchId) -> bool {
        if !self.availability_enabled {
            return false;
        }
        self.ack_tracker.read().has_certificate(batch_id)
    }

    /// Get the certificate for a batch, if it exists (T165).
    ///
    /// Returns `None` if:
    /// - Availability is disabled
    /// - The batch doesn't have a certificate yet
    pub fn batch_certificate(&self, batch_id: &BatchId) -> Option<BatchCertificate> {
        if !self.availability_enabled {
            return None;
        }
        self.ack_tracker.read().certificate(batch_id).cloned()
    }

    /// Get the number of acks for a batch (T165).
    ///
    /// Returns 0 if availability is disabled or batch has no acks.
    pub fn ack_count(&self, batch_id: &BatchId) -> usize {
        if !self.availability_enabled {
            return 0;
        }
        self.ack_tracker.read().ack_count(batch_id)
    }

    /// Get the number of batches with certificates (T165).
    pub fn cert_count(&self) -> usize {
        if !self.availability_enabled {
            return 0;
        }
        self.ack_tracker.read().cert_count()
    }

    /// Get the number of batches with pending acks but no certificate (T165).
    pub fn pending_cert_count(&self) -> usize {
        if !self.availability_enabled {
            return 0;
        }
        self.ack_tracker.read().pending_count()
    }

    /// Set the current view for certificate formation (T165).
    pub fn set_current_view(&self, view: u64) {
        if self.availability_enabled {
            self.ack_tracker.write().set_current_view(view);
        }
    }

    /// Check if a batch exists in the mempool.
    pub fn has_batch(&self, batch_id: &BatchId) -> bool {
        self.inner.read().batches_by_id.contains_key(batch_id)
    }

    /// Create a batch from pending transactions (internal helper).
    ///
    /// This is called when we have enough pending txs to form a batch.
    /// T169: If fee_priority is enabled, selects highest-priority txs.
    fn create_local_batch(inner: &mut DagInner) -> Option<QbindBatch> {
        if inner.pending_txs.is_empty() {
            return None;
        }

        // T169: Sort pending_txs by priority if enabled
        if inner.config.enable_fee_priority {
            inner.pending_txs.sort_by(|a, b| {
                use crate::mempool::compute_tx_mempool_cost;

                // Compute costs
                let cost_a = compute_tx_mempool_cost(a).ok();
                let cost_b = compute_tx_mempool_cost(b).ok();

                match (cost_a, cost_b) {
                    (Some(ca), Some(cb)) => {
                        // Sort by descending fee_per_gas, then descending effective_fee, then arrival_id
                        let arrival_a = inner
                            .tx_arrivals
                            .get(&(a.sender, a.nonce))
                            .copied()
                            .unwrap_or(0);
                        let arrival_b = inner
                            .tx_arrivals
                            .get(&(b.sender, b.nonce))
                            .copied()
                            .unwrap_or(0);

                        cb.fee_per_gas
                            .cmp(&ca.fee_per_gas)
                            .then_with(|| cb.effective_fee.cmp(&ca.effective_fee))
                            .then_with(|| arrival_a.cmp(&arrival_b))
                    }
                    (Some(_), None) => std::cmp::Ordering::Less, // Valid comes before invalid
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            });
        }

        // Take up to batch_size transactions (from the front, which are now highest priority)
        let batch_size = inner.config.batch_size.min(inner.pending_txs.len());
        let txs: Vec<_> = inner.pending_txs.drain(..batch_size).collect();

        // Clean up arrival tracking for batched txs
        for tx in &txs {
            inner.tx_arrivals.remove(&(tx.sender, tx.nonce));
        }

        // Collect parent references (latest batch from each known validator)
        let parents: Vec<BatchRef> = inner
            .latest_batch_per_validator
            .iter()
            .map(|(vid, bid)| BatchRef::new(*vid, *bid))
            .collect();

        // Create the batch
        let view_hint = inner.current_view_hint;
        inner.current_view_hint += 1;

        let batch = QbindBatch::new(inner.config.local_validator_id, view_hint, parents, txs);

        Some(batch)
    }

    /// Insert a batch into the DAG (internal helper).
    fn insert_batch_inner(inner: &mut DagInner, batch: QbindBatch) -> Result<(), DagMempoolError> {
        // Check capacity
        if inner.batches_by_id.len() >= inner.config.max_batches {
            return Err(DagMempoolError::Full);
        }

        let batch_id = batch.batch_id;
        let creator = batch.creator;

        // Verify batch ID matches computed value
        let expected_id =
            compute_batch_id(batch.creator, batch.view_hint, &batch.parents, &batch.txs);
        if batch_id != expected_id {
            return Err(DagMempoolError::Invalid("batch ID mismatch".to_string()));
        }

        // Check for duplicate batch
        if inner.batches_by_id.contains_key(&batch_id) {
            // Silently ignore duplicate
            return Ok(());
        }

        // Add transaction IDs to seen set
        for tx in &batch.txs {
            let tx_id = compute_tx_id(tx);
            inner.tx_seen.insert(tx_id);
        }

        // Update children mapping for parents
        for parent in &batch.parents {
            inner
                .children
                .entry(parent.batch_id)
                .or_default()
                .push(batch_id);
        }

        // Update latest batch for this validator
        inner.latest_batch_per_validator.insert(creator, batch_id);

        // Store the batch
        inner
            .batches_by_id
            .insert(batch_id, StoredBatch::new(batch));

        Ok(())
    }
}

impl DagMempool for InMemoryDagMempool {
    fn insert_local_txs(&self, txs: Vec<QbindTransaction>) -> Result<(), DagMempoolError> {
        let mut inner = self.inner.write();

        // Check pending capacity
        if inner.pending_txs.len() + txs.len() > inner.config.max_pending_txs {
            return Err(DagMempoolError::Full);
        }

        // Filter duplicates and add to pending
        let mut added = 0;
        for tx in txs {
            let tx_id = compute_tx_id(&tx);
            if !inner.tx_seen.contains(&tx_id) && !inner.tx_committed.contains(&tx_id) {
                inner.tx_seen.insert(tx_id);

                // T169: Track arrival for priority
                if inner.config.enable_fee_priority {
                    let arrival_id = inner.arrival_counter;
                    inner.arrival_counter += 1;
                    inner.tx_arrivals.insert((tx.sender, tx.nonce), arrival_id);
                }

                inner.pending_txs.push(tx);
                added += 1;
            }
        }

        // Update metrics
        if let Some(ref m) = self.metrics {
            m.inc_txs_total(added as u64);
        }

        // Create batches if we have enough pending txs
        while inner.pending_txs.len() >= inner.config.batch_size {
            if let Some(batch) = Self::create_local_batch(&mut inner) {
                // Update metrics before insertion
                if let Some(ref m) = self.metrics {
                    m.inc_batches_total();
                    m.inc_edges_total(batch.parents.len() as u64);
                }
                Self::insert_batch_inner(&mut inner, batch)?;
            }
        }

        Ok(())
    }

    fn insert_remote_batch(&self, batch: QbindBatch) -> Result<(), DagMempoolError> {
        // For T158, we accept remote batches without full verification
        // (no availability certificates yet). Basic validation only.

        let batch_parents_len = batch.parents.len() as u64;
        let batch_txs_len = batch.txs.len() as u64;

        let mut inner = self.inner.write();
        Self::insert_batch_inner(&mut inner, batch)?;

        // Update metrics only after successful insertion
        if let Some(ref m) = self.metrics {
            m.inc_batches_total();
            m.inc_edges_total(batch_parents_len);
            m.inc_txs_total(batch_txs_len);
        }

        Ok(())
    }

    fn select_frontier_txs(&self, max_txs: usize) -> Vec<QbindTransaction> {
        let inner = self.inner.read();
        let mut result = Vec::with_capacity(max_txs);
        let mut seen_tx_ids: HashSet<TxId> = HashSet::new();

        // Update metrics
        if let Some(ref m) = self.metrics {
            m.inc_frontier_select_total();
        }

        // T169: Collect all candidate transactions first if priority is enabled
        if inner.config.enable_fee_priority {
            let mut candidates: Vec<QbindTransaction> = Vec::new();

            // Collect batches and sort for deterministic ordering:
            // Order by (view_hint, creator, batch_id)
            let mut batches: Vec<_> = inner.batches_by_id.values().collect();
            batches.sort_by(|a, b| {
                let a_batch = &a.batch;
                let b_batch = &b.batch;
                (a_batch.view_hint, a_batch.creator, a_batch.batch_id).cmp(&(
                    b_batch.view_hint,
                    b_batch.creator,
                    b_batch.batch_id,
                ))
            });

            // Collect transactions from batches
            for stored in batches {
                if stored.fully_committed {
                    continue;
                }

                for tx in &stored.batch.txs {
                    let tx_id = compute_tx_id(tx);
                    if !inner.tx_committed.contains(&tx_id) && !seen_tx_ids.contains(&tx_id) {
                        seen_tx_ids.insert(tx_id);
                        candidates.push(tx.clone());
                    }
                }
            }

            // Also include pending transactions
            for tx in &inner.pending_txs {
                let tx_id = compute_tx_id(tx);
                if !inner.tx_committed.contains(&tx_id) && !seen_tx_ids.contains(&tx_id) {
                    seen_tx_ids.insert(tx_id);
                    candidates.push(tx.clone());
                }
            }

            // Sort candidates by priority
            candidates.sort_by(|a, b| {
                use crate::mempool::compute_tx_mempool_cost;

                let cost_a = compute_tx_mempool_cost(a).ok();
                let cost_b = compute_tx_mempool_cost(b).ok();

                match (cost_a, cost_b) {
                    (Some(ca), Some(cb)) => {
                        // Descending fee_per_gas, then descending effective_fee
                        cb.fee_per_gas
                            .cmp(&ca.fee_per_gas)
                            .then_with(|| cb.effective_fee.cmp(&ca.effective_fee))
                    }
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => std::cmp::Ordering::Equal,
                }
            });

            // Take up to max_txs from sorted candidates
            result = candidates.into_iter().take(max_txs).collect();
        } else {
            // Original FIFO behavior (without priority)
            // Collect batches and sort for deterministic ordering:
            // Order by (view_hint, creator, batch_id)
            let mut batches: Vec<_> = inner.batches_by_id.values().collect();
            batches.sort_by(|a, b| {
                let a_batch = &a.batch;
                let b_batch = &b.batch;
                (a_batch.view_hint, a_batch.creator, a_batch.batch_id).cmp(&(
                    b_batch.view_hint,
                    b_batch.creator,
                    b_batch.batch_id,
                ))
            });

            // Iterate through batches and collect transactions
            for stored in batches {
                if result.len() >= max_txs {
                    break;
                }

                // Skip fully committed batches
                if stored.fully_committed {
                    continue;
                }

                for tx in &stored.batch.txs {
                    if result.len() >= max_txs {
                        break;
                    }

                    let tx_id = compute_tx_id(tx);

                    // Skip committed or already-selected transactions
                    if inner.tx_committed.contains(&tx_id) || seen_tx_ids.contains(&tx_id) {
                        continue;
                    }

                    seen_tx_ids.insert(tx_id);
                    result.push(tx.clone());
                }
            }

            // Also include pending transactions that aren't batched yet
            for tx in &inner.pending_txs {
                if result.len() >= max_txs {
                    break;
                }

                let tx_id = compute_tx_id(tx);
                if inner.tx_committed.contains(&tx_id) || seen_tx_ids.contains(&tx_id) {
                    continue;
                }

                seen_tx_ids.insert(tx_id);
                result.push(tx.clone());
            }
        }

        // Update metrics
        if let Some(ref m) = self.metrics {
            m.inc_frontier_txs_selected_total(result.len() as u64);
        }

        result
    }

    fn mark_committed(&self, committed: &[QbindTransaction]) {
        let mut inner = self.inner.write();

        for tx in committed {
            let tx_id = compute_tx_id(tx);
            inner.tx_committed.insert(tx_id);
        }

        // Check if any batches are now fully committed
        // First, collect tx_committed reference to avoid borrow issues
        let committed_set = &inner.tx_committed;
        let batch_ids: Vec<BatchId> = inner.batches_by_id.keys().cloned().collect();

        // Collect batch IDs that need to be marked as fully committed
        let mut batches_to_mark: Vec<BatchId> = Vec::new();
        for batch_id in &batch_ids {
            if let Some(stored) = inner.batches_by_id.get(batch_id) {
                if !stored.fully_committed {
                    let all_committed = stored
                        .batch
                        .txs
                        .iter()
                        .all(|tx| committed_set.contains(&compute_tx_id(tx)));
                    if all_committed {
                        batches_to_mark.push(*batch_id);
                    }
                }
            }
        }

        // Now mark them
        for batch_id in batches_to_mark {
            if let Some(stored) = inner.batches_by_id.get_mut(&batch_id) {
                stored.fully_committed = true;
            }
        }

        // Remove committed pending transactions
        // Clone the committed set to avoid borrow issues with retain
        let committed_tx_ids: HashSet<TxId> = inner.tx_committed.clone();
        inner.pending_txs.retain(|tx| {
            let tx_id = compute_tx_id(tx);
            !committed_tx_ids.contains(&tx_id)
        });
    }

    fn stats(&self) -> DagMempoolStats {
        let inner = self.inner.read();

        let num_batches = inner.batches_by_id.len();
        let num_edges: usize = inner.children.values().map(|c| c.len()).sum();
        let num_txs: usize = inner
            .batches_by_id
            .values()
            .map(|b| b.batch.txs.len())
            .sum();
        let pending_txs = inner.pending_txs.len();
        let committed_txs = inner.tx_committed.len();

        DagMempoolStats {
            num_batches,
            num_edges,
            num_txs,
            pending_txs,
            committed_txs,
        }
    }
}

// ============================================================================
// DAG Mempool Metrics
// ============================================================================

/// Metrics for DAG mempool operations (T158).
///
/// Tracks counters and gauges for:
/// - Batches created/received
/// - Edges in the DAG
/// - Transactions processed
/// - Frontier selection operations
/// - T165: Batch acks and certificates
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
#[derive(Debug, Default)]
pub struct DagMempoolMetrics {
    /// Total number of batches in the DAG.
    batches_total: AtomicU64,
    /// Total number of edges (parent references) in the DAG.
    edges_total: AtomicU64,
    /// Total number of transactions processed.
    txs_total: AtomicU64,
    /// Number of frontier selection operations.
    frontier_select_total: AtomicU64,
    /// Total number of transactions selected for proposals.
    frontier_txs_selected_total: AtomicU64,

    // T165: Batch ack and certificate metrics
    /// Total number of accepted batch acks.
    batch_acks_accepted: AtomicU64,
    /// Total number of batch acks rejected due to duplicate.
    batch_acks_rejected_duplicate: AtomicU64,
    /// Total number of batch acks rejected due to unknown batch.
    batch_acks_rejected_unknown: AtomicU64,
    /// Total number of batch acks rejected due to bad signature.
    batch_acks_rejected_bad_sig: AtomicU64,
    /// Total number of batch acks rejected for other reasons.
    batch_acks_rejected_other: AtomicU64,
    /// Total number of batch certificates formed.
    batch_certs_total: AtomicU64,
}

impl DagMempoolMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get the total number of batches.
    pub fn batches_total(&self) -> u64 {
        self.batches_total.load(Ordering::Relaxed)
    }

    /// Increment the batches counter.
    pub fn inc_batches_total(&self) {
        self.batches_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total number of edges.
    pub fn edges_total(&self) -> u64 {
        self.edges_total.load(Ordering::Relaxed)
    }

    /// Increment the edges counter.
    pub fn inc_edges_total(&self, count: u64) {
        self.edges_total.fetch_add(count, Ordering::Relaxed);
    }

    /// Get the total number of transactions.
    pub fn txs_total(&self) -> u64 {
        self.txs_total.load(Ordering::Relaxed)
    }

    /// Increment the transactions counter.
    pub fn inc_txs_total(&self, count: u64) {
        self.txs_total.fetch_add(count, Ordering::Relaxed);
    }

    /// Get the number of frontier selections.
    pub fn frontier_select_total(&self) -> u64 {
        self.frontier_select_total.load(Ordering::Relaxed)
    }

    /// Increment the frontier selection counter.
    pub fn inc_frontier_select_total(&self) {
        self.frontier_select_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total transactions selected.
    pub fn frontier_txs_selected_total(&self) -> u64 {
        self.frontier_txs_selected_total.load(Ordering::Relaxed)
    }

    /// Increment the selected transactions counter.
    pub fn inc_frontier_txs_selected_total(&self, count: u64) {
        self.frontier_txs_selected_total
            .fetch_add(count, Ordering::Relaxed);
    }

    // ========================================================================
    // T165: Batch Ack & Certificate Metrics
    // ========================================================================

    /// Get the total accepted batch acks.
    pub fn batch_acks_accepted(&self) -> u64 {
        self.batch_acks_accepted.load(Ordering::Relaxed)
    }

    /// Increment the accepted batch acks counter.
    pub fn inc_batch_acks_accepted(&self) {
        self.batch_acks_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total rejected batch acks (duplicate).
    pub fn batch_acks_rejected_duplicate(&self) -> u64 {
        self.batch_acks_rejected_duplicate.load(Ordering::Relaxed)
    }

    /// Increment the rejected duplicate batch acks counter.
    pub fn inc_batch_acks_rejected_duplicate(&self) {
        self.batch_acks_rejected_duplicate
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total rejected batch acks (unknown batch).
    pub fn batch_acks_rejected_unknown(&self) -> u64 {
        self.batch_acks_rejected_unknown.load(Ordering::Relaxed)
    }

    /// Increment the rejected unknown batch acks counter.
    pub fn inc_batch_acks_rejected_unknown(&self) {
        self.batch_acks_rejected_unknown
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total rejected batch acks (bad signature).
    pub fn batch_acks_rejected_bad_sig(&self) -> u64 {
        self.batch_acks_rejected_bad_sig.load(Ordering::Relaxed)
    }

    /// Increment the rejected bad signature batch acks counter.
    pub fn inc_batch_acks_rejected_bad_sig(&self) {
        self.batch_acks_rejected_bad_sig
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total rejected batch acks (other reasons).
    pub fn batch_acks_rejected_other(&self) -> u64 {
        self.batch_acks_rejected_other.load(Ordering::Relaxed)
    }

    /// Increment the rejected other batch acks counter.
    pub fn inc_batch_acks_rejected_other(&self) {
        self.batch_acks_rejected_other
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total batch certificates formed.
    pub fn batch_certs_total(&self) -> u64 {
        self.batch_certs_total.load(Ordering::Relaxed)
    }

    /// Increment the batch certificates counter.
    pub fn inc_batch_certs_total(&self) {
        self.batch_certs_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total rejected batch acks (all reasons).
    pub fn batch_acks_rejected_total(&self) -> u64 {
        self.batch_acks_rejected_duplicate()
            + self.batch_acks_rejected_unknown()
            + self.batch_acks_rejected_bad_sig()
            + self.batch_acks_rejected_other()
    }

    /// Format metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# DAG Mempool Metrics (T158)\n");
        output.push_str(&format!(
            "qbind_dag_batches_total {}\n",
            self.batches_total()
        ));
        output.push_str(&format!("qbind_dag_edges_total {}\n", self.edges_total()));
        output.push_str(&format!("qbind_dag_txs_total {}\n", self.txs_total()));
        output.push_str(&format!(
            "qbind_dag_frontier_select_total {}\n",
            self.frontier_select_total()
        ));
        output.push_str(&format!(
            "qbind_dag_frontier_txs_selected_total {}\n",
            self.frontier_txs_selected_total()
        ));

        // T165: Batch ack and certificate metrics
        output.push_str("\n# DAG Availability Metrics (T165)\n");
        output.push_str(&format!(
            "qbind_dag_batch_acks_total{{result=\"accepted\"}} {}\n",
            self.batch_acks_accepted()
        ));
        output.push_str(&format!(
            "qbind_dag_batch_acks_total{{result=\"rejected\"}} {}\n",
            self.batch_acks_rejected_total()
        ));
        output.push_str(&format!(
            "qbind_dag_batch_acks_invalid_total{{reason=\"duplicate\"}} {}\n",
            self.batch_acks_rejected_duplicate()
        ));
        output.push_str(&format!(
            "qbind_dag_batch_acks_invalid_total{{reason=\"unknown_batch\"}} {}\n",
            self.batch_acks_rejected_unknown()
        ));
        output.push_str(&format!(
            "qbind_dag_batch_acks_invalid_total{{reason=\"bad_sig\"}} {}\n",
            self.batch_acks_rejected_bad_sig()
        ));
        output.push_str(&format!(
            "qbind_dag_batch_certs_total {}\n",
            self.batch_certs_total()
        ));
        output
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;

    fn test_account_id(byte: u8) -> [u8; 32] {
        let mut id = [0u8; 32];
        id[0] = byte;
        id
    }

    fn make_test_tx(sender_byte: u8, nonce: u64) -> QbindTransaction {
        QbindTransaction::new(test_account_id(sender_byte), nonce, vec![0xAB; 32])
    }

    // ========================================================================
    // Batch ID Stability Tests
    // ========================================================================

    #[test]
    fn test_batch_id_is_stable() {
        // Create a batch with specific inputs
        let creator = ValidatorId::new(1);
        let view_hint = 42;
        let parents = vec![BatchRef::new(ValidatorId::new(0), [0xAA; 32])];
        let txs = vec![make_test_tx(0x11, 0), make_test_tx(0x22, 1)];

        // Compute batch ID twice
        let id1 = compute_batch_id(creator, view_hint, &parents, &txs);
        let id2 = compute_batch_id(creator, view_hint, &parents, &txs);

        // Should be identical
        assert_eq!(id1, id2, "batch ID should be stable for same inputs");
    }

    #[test]
    fn test_batch_id_differs_for_different_inputs() {
        let creator = ValidatorId::new(1);
        let view_hint = 42;
        let parents = vec![BatchRef::new(ValidatorId::new(0), [0xAA; 32])];
        let txs = vec![make_test_tx(0x11, 0)];

        let id1 = compute_batch_id(creator, view_hint, &parents, &txs);

        // Different creator
        let id2 = compute_batch_id(ValidatorId::new(2), view_hint, &parents, &txs);
        assert_ne!(id1, id2, "batch ID should differ for different creator");

        // Different view_hint
        let id3 = compute_batch_id(creator, 99, &parents, &txs);
        assert_ne!(id1, id3, "batch ID should differ for different view_hint");

        // Different parents
        let id4 = compute_batch_id(creator, view_hint, &[], &txs);
        assert_ne!(id1, id4, "batch ID should differ for different parents");

        // Different txs
        let txs2 = vec![make_test_tx(0x33, 5)];
        let id5 = compute_batch_id(creator, view_hint, &parents, &txs2);
        assert_ne!(id1, id5, "batch ID should differ for different txs");
    }

    // ========================================================================
    // Signing Preimage Tests
    // ========================================================================

    #[test]
    fn test_signing_preimage_is_stable() {
        let creator = ValidatorId::new(1);
        let view_hint = 10;
        let parents = vec![BatchRef::new(ValidatorId::new(0), [0xBB; 32])];
        let txs = vec![make_test_tx(0x44, 2)];

        let preimage1 = batch_signing_preimage(creator, view_hint, &parents, &txs);
        let preimage2 = batch_signing_preimage(creator, view_hint, &parents, &txs);

        assert_eq!(preimage1, preimage2, "signing preimage should be stable");
    }

    #[test]
    fn test_signing_preimage_starts_with_domain_tag() {
        use qbind_types::domain::{domain_prefix, DomainKind};
        use qbind_types::QBIND_DEVNET_CHAIN_ID;

        let creator = ValidatorId::new(1);
        let view_hint = 10;
        let parents = vec![];
        let txs = vec![];

        let preimage = batch_signing_preimage(creator, view_hint, &parents, &txs);

        // batch_signing_preimage uses QBIND_DEVNET_CHAIN_ID by default,
        // so the preimage should start with the chain-aware domain tag.
        let expected_prefix = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Batch);
        assert!(
            preimage.starts_with(&expected_prefix),
            "signing preimage should start with chain-aware domain tag (QBIND:DEV:BATCH:v1)"
        );
    }

    // ========================================================================
    // Sign/Verify Round-Trip Tests
    // ========================================================================

    #[test]
    fn test_batch_sign_verify_roundtrip() {
        // Generate a keypair
        let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        // Create a batch
        let creator = ValidatorId::new(1);
        let mut batch = QbindBatch::new(
            creator,
            5,
            vec![],
            vec![make_test_tx(0x55, 0), make_test_tx(0x66, 1)],
        );

        // Sign it
        batch.sign(&sk).expect("signing should succeed");
        assert!(batch.is_signed(), "batch should be signed");

        // Verify with correct public key
        batch
            .verify_signature(&pk_bytes)
            .expect("verification should succeed");
    }

    #[test]
    fn test_batch_verify_fails_with_wrong_key() {
        // Generate two keypairs
        let (pk1_bytes, sk1) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (pk2_bytes, _sk2) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        // Create and sign a batch with sk1
        let creator = ValidatorId::new(1);
        let mut batch = QbindBatch::new(creator, 5, vec![], vec![make_test_tx(0x77, 0)]);
        batch.sign(&sk1).expect("signing should succeed");

        // Verify with wrong public key (pk2)
        let result = batch.verify_signature(&pk2_bytes);
        assert!(result.is_err(), "verification should fail with wrong key");

        // Verify with correct public key
        batch
            .verify_signature(&pk1_bytes)
            .expect("verification should succeed with correct key");
    }

    // ========================================================================
    // QbindBatch Tests
    // ========================================================================

    #[test]
    fn test_batch_new_computes_id() {
        let creator = ValidatorId::new(1);
        let batch = QbindBatch::new(creator, 10, vec![], vec![make_test_tx(0x88, 0)]);

        // Verify batch_id matches manual computation
        let expected_id = compute_batch_id(creator, 10, &[], &batch.txs);
        assert_eq!(batch.batch_id, expected_id, "batch_id should match");
    }

    #[test]
    fn test_batch_tx_count() {
        let creator = ValidatorId::new(1);
        let txs = vec![make_test_tx(0x99, 0), make_test_tx(0xAA, 1)];
        let batch = QbindBatch::new(creator, 0, vec![], txs);

        assert_eq!(batch.tx_count(), 2, "tx_count should be 2");
    }

    // ========================================================================
    // BatchRef Tests
    // ========================================================================

    #[test]
    fn test_batch_ref_canonical_bytes() {
        let batch_ref = BatchRef::new(ValidatorId::new(123), [0xCC; 32]);
        let bytes = batch_ref.canonical_bytes();

        // Should be 8 + 32 = 40 bytes
        assert_eq!(bytes.len(), 40, "canonical bytes should be 40 bytes");

        // First 8 bytes should be creator (LE)
        let creator_bytes = &bytes[0..8];
        assert_eq!(
            creator_bytes,
            &123u64.to_le_bytes(),
            "creator should be LE encoded"
        );

        // Last 32 bytes should be batch_id
        let batch_id_bytes = &bytes[8..40];
        assert_eq!(batch_id_bytes, &[0xCC; 32], "batch_id should follow");
    }

    // ========================================================================
    // InMemoryDagMempool Tests
    // ========================================================================

    #[test]
    fn test_dag_mempool_insert_local_txs() {
        let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

        // Insert some transactions
        let txs = vec![make_test_tx(0xDD, 0), make_test_tx(0xDD, 1)];
        mempool
            .insert_local_txs(txs)
            .expect("insert should succeed");

        let stats = mempool.stats();
        assert!(
            stats.pending_txs > 0 || stats.num_txs > 0,
            "should have txs"
        );
    }

    #[test]
    fn test_dag_mempool_batching() {
        let config = DagMempoolConfig {
            local_validator_id: ValidatorId::new(1),
            batch_size: 2, // Small batch size for testing
            ..Default::default()
        };
        let mempool = InMemoryDagMempool::with_config(config);

        // Insert 3 transactions
        let txs = vec![
            make_test_tx(0xEE, 0),
            make_test_tx(0xEE, 1),
            make_test_tx(0xEE, 2),
        ];
        mempool
            .insert_local_txs(txs)
            .expect("insert should succeed");

        let stats = mempool.stats();
        // Should have created 1 batch (2 txs) with 1 pending
        assert_eq!(stats.num_batches, 1, "should have 1 batch");
        assert_eq!(stats.pending_txs, 1, "should have 1 pending tx");
    }

    #[test]
    fn test_dag_mempool_select_frontier_txs() {
        let config = DagMempoolConfig {
            local_validator_id: ValidatorId::new(1),
            batch_size: 100, // Don't auto-batch
            ..Default::default()
        };
        let mempool = InMemoryDagMempool::with_config(config);

        // Insert 5 transactions
        let txs = (0..5).map(|i| make_test_tx(0xFF, i as u64)).collect();
        mempool
            .insert_local_txs(txs)
            .expect("insert should succeed");

        // Select 3 transactions
        let selected = mempool.select_frontier_txs(3);
        assert_eq!(selected.len(), 3, "should select 3 txs");

        // Select again - should get same order (deterministic)
        let selected2 = mempool.select_frontier_txs(3);
        assert_eq!(selected, selected2, "selection should be deterministic");
    }

    #[test]
    fn test_dag_mempool_mark_committed() {
        let config = DagMempoolConfig {
            local_validator_id: ValidatorId::new(1),
            batch_size: 100,
            ..Default::default()
        };
        let mempool = InMemoryDagMempool::with_config(config);

        // Insert 5 transactions
        let txs: Vec<_> = (0..5).map(|i| make_test_tx(0xAA, i as u64)).collect();
        mempool
            .insert_local_txs(txs.clone())
            .expect("insert should succeed");

        // Mark first 2 as committed
        mempool.mark_committed(&txs[0..2]);

        // Select - should not include committed
        let selected = mempool.select_frontier_txs(10);
        assert_eq!(selected.len(), 3, "should have 3 uncommitted txs");

        // Verify committed txs are not in selection
        for tx in &selected {
            assert!(tx.nonce >= 2, "committed txs should not be selected");
        }
    }

    #[test]
    fn test_dag_mempool_deduplication() {
        let config = DagMempoolConfig {
            local_validator_id: ValidatorId::new(1),
            batch_size: 100,
            ..Default::default()
        };
        let mempool = InMemoryDagMempool::with_config(config);

        // Insert same transaction twice
        let tx = make_test_tx(0xBB, 0);
        mempool
            .insert_local_txs(vec![tx.clone()])
            .expect("first insert should succeed");
        mempool
            .insert_local_txs(vec![tx])
            .expect("duplicate insert should succeed");

        let stats = mempool.stats();
        // Should only have 1 transaction
        assert_eq!(stats.pending_txs, 1, "duplicate should be filtered");
    }

    #[test]
    fn test_dag_mempool_insert_remote_batch() {
        let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

        // Create a remote batch
        let remote_batch = QbindBatch::new(
            ValidatorId::new(2), // Different creator
            0,
            vec![],
            vec![make_test_tx(0xCC, 0)],
        );

        mempool
            .insert_remote_batch(remote_batch)
            .expect("remote batch insert should succeed");

        let stats = mempool.stats();
        assert_eq!(stats.num_batches, 1, "should have 1 batch");
        assert_eq!(stats.num_txs, 1, "should have 1 tx in batches");
    }

    #[test]
    fn test_dag_mempool_parent_references() {
        let config = DagMempoolConfig {
            local_validator_id: ValidatorId::new(1),
            batch_size: 2,
            ..Default::default()
        };
        let mempool = InMemoryDagMempool::with_config(config);

        // Insert first batch
        mempool
            .insert_local_txs(vec![make_test_tx(0xDD, 0), make_test_tx(0xDD, 1)])
            .expect("insert should succeed");

        let stats1 = mempool.stats();
        assert_eq!(stats1.num_batches, 1, "should have 1 batch");

        // Insert second batch - should reference first as parent
        mempool
            .insert_local_txs(vec![make_test_tx(0xDD, 2), make_test_tx(0xDD, 3)])
            .expect("insert should succeed");

        let stats2 = mempool.stats();
        assert_eq!(stats2.num_batches, 2, "should have 2 batches");
        assert!(stats2.num_edges > 0, "should have parent edges");
    }

    #[test]
    fn test_dag_mempool_stats() {
        let mempool = InMemoryDagMempool::new(ValidatorId::new(1));

        let initial_stats = mempool.stats();
        assert_eq!(initial_stats.num_batches, 0);
        assert_eq!(initial_stats.num_edges, 0);
        assert_eq!(initial_stats.num_txs, 0);
        assert_eq!(initial_stats.pending_txs, 0);
        assert_eq!(initial_stats.committed_txs, 0);
    }

    // ========================================================================
    // DagMempoolMetrics Tests
    // ========================================================================

    #[test]
    fn test_dag_mempool_metrics() {
        let metrics = DagMempoolMetrics::new();

        // Initial values should be zero
        assert_eq!(metrics.batches_total(), 0);
        assert_eq!(metrics.edges_total(), 0);
        assert_eq!(metrics.txs_total(), 0);

        // Increment and verify
        metrics.inc_batches_total();
        metrics.inc_edges_total(5);
        metrics.inc_txs_total(10);
        metrics.inc_frontier_select_total();
        metrics.inc_frontier_txs_selected_total(3);

        assert_eq!(metrics.batches_total(), 1);
        assert_eq!(metrics.edges_total(), 5);
        assert_eq!(metrics.txs_total(), 10);
        assert_eq!(metrics.frontier_select_total(), 1);
        assert_eq!(metrics.frontier_txs_selected_total(), 3);
    }

    #[test]
    fn test_dag_mempool_metrics_format() {
        let metrics = DagMempoolMetrics::new();
        metrics.inc_batches_total();
        metrics.inc_txs_total(5);

        let output = metrics.format_metrics();
        assert!(output.contains("qbind_dag_batches_total 1"));
        assert!(output.contains("qbind_dag_txs_total 5"));
    }
}
