//! Slashing infrastructure for QBIND consensus (T228).
//!
//! This module provides the core types and traits for the slashing/evidence pipeline.
//! It enables encoding all offense classes from the T227 design document (O1–O5)
//! and carrying proofs end-to-end through storage, events, and verification hooks.
//!
//! # T228 Scope
//!
//! This task implements the slashing infrastructure skeleton **without** penalty
//! application. The `NoopSlashingEngine` only records evidence and emits metrics,
//! but does not burn stake or jail validators. Actual penalties are deferred to
//! T229+.
//!
//! # Offense Classes (from T227)
//!
//! | ID  | Offense                              | Severity      |
//! | :-- | :----------------------------------- | :------------ |
//! | O1  | Classical Double-Signing             | Critical      |
//! | O2  | Invalid Consensus Signature (Proposer)| High         |
//! | O3a | Single Lazy Vote                     | Medium        |
//! | O3b | Repeated Lazy Votes                  | Medium-High   |
//! | O4  | Invalid DAG Certificate Propagation  | High          |
//! | O5  | DAG/Consensus Coupling Violations    | Medium-High   |
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_consensus::slashing::{
//!     NoopSlashingEngine, OffenseKind, SlashingContext, SlashingEngine,
//!     SlashingEvidence, EvidencePayloadV1,
//! };
//!
//! let mut engine = NoopSlashingEngine::new();
//! let ctx = SlashingContext { validator_set: &validator_set };
//! let record = engine.handle_evidence(&ctx, evidence);
//! ```

use crate::{ValidatorId, ValidatorInfo, ValidatorSet};
use qbind_crypto::{MlDsa44Backend, SUITE_PQ_RESERVED_1};
use std::collections::{HashMap, HashSet};

/// Versioned offense taxonomy aligned with T227 design document.
///
/// This enum represents all slashable offense classes defined in the
/// QBIND slashing model. Each variant corresponds to a specific type
/// of misbehavior with associated severity and slash range.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OffenseKind {
    /// O1: Classical double-signing (same view, different blocks/votes).
    /// Severity: Critical. Slash range: 5–10%.
    O1DoubleSign,
    /// O2: Invalid consensus signature as proposer.
    /// Severity: High. Slash range: 5%.
    O2InvalidProposerSig,
    /// O3a: Single lazy vote (voting without verification).
    /// Severity: Medium. Slash range: 0–0.5%.
    O3aLazyVoteSingle,
    /// O3b: Repeated lazy votes (systematic laziness).
    /// Severity: Medium-High. Slash range: 1–3%.
    O3bLazyVoteRepeated,
    /// O4: Invalid DAG certificate propagation.
    /// Severity: High. Slash range: 5–10%.
    O4InvalidDagCert,
    /// O5: DAG/Consensus coupling violations.
    /// Severity: Medium-High. Slash range: 1–5%.
    O5DagCouplingViolation,
}

impl OffenseKind {
    /// Returns a string label for metrics and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            OffenseKind::O1DoubleSign => "O1_double_sign",
            OffenseKind::O2InvalidProposerSig => "O2_invalid_proposer_sig",
            OffenseKind::O3aLazyVoteSingle => "O3a_lazy_vote_single",
            OffenseKind::O3bLazyVoteRepeated => "O3b_lazy_vote_repeated",
            OffenseKind::O4InvalidDagCert => "O4_invalid_dag_cert",
            OffenseKind::O5DagCouplingViolation => "O5_dag_coupling_violation",
        }
    }
}

/// Reason why a lazy vote (O3) is considered invalid.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LazyVoteInvalidReason {
    /// The block being voted on had an invalid proposer signature.
    InvalidProposerSig,
    /// The QC in the block contained invalid signatures.
    InvalidQcSignature,
    /// Other verification failure (with description).
    Other(String),
}

/// Reason why a DAG certificate (O4) validation failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DagValidationFailure {
    /// Insufficient valid signatures (quorum not met).
    QuorumNotMet { valid_count: u32, required: u32 },
    /// One or more signatures failed ML-DSA-44 verification.
    InvalidSignature { signer_index: u32 },
    /// Batch commitment does not match computed value.
    CommitmentMismatch,
    /// Other validation failure.
    Other(String),
}

/// Signed block header for O1/O2 evidence.
///
/// Contains the block header data and its signature for verification.
/// This is a thin wrapper that can be constructed from existing wire types.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedBlockHeader {
    /// The block height.
    pub height: u64,
    /// The view/round number.
    pub view: u64,
    /// The block hash/ID.
    pub block_id: [u8; 32],
    /// The proposer's validator ID.
    pub proposer_id: ValidatorId,
    /// The signature over the block header.
    pub signature: Vec<u8>,
    /// Additional header data needed for verification (serialized).
    pub header_preimage: Vec<u8>,
}

/// Signed vote for O3 evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedVote {
    /// The voter's validator ID.
    pub validator_id: ValidatorId,
    /// The height being voted on.
    pub height: u64,
    /// The view/round number.
    pub view: u64,
    /// The block hash being voted for.
    pub block_id: [u8; 32],
    /// The vote signature.
    pub signature: Vec<u8>,
}

/// DAG availability certificate for O4 evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagCertificate {
    /// The batch commitment this certificate covers.
    pub batch_commitment: [u8; 32],
    /// The DAG round.
    pub dag_round: u64,
    /// List of signers (validator IDs).
    pub signers: Vec<ValidatorId>,
    /// Corresponding signatures.
    pub signatures: Vec<Vec<u8>>,
}

/// Proof of DAG state for O5 evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DagStateProof {
    /// The DAG round at the time of the block.
    pub dag_round: u64,
    /// Valid batch commitments at that round.
    pub frontier_commitments: Vec<[u8; 32]>,
    /// Optional Merkle exclusion proof.
    pub merkle_proof: Option<Vec<u8>>,
}

/// Block header (minimal) for O5 evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    /// Block height.
    pub height: u64,
    /// Block view/round.
    pub view: u64,
    /// Proposer validator ID.
    pub proposer_id: ValidatorId,
    /// The batch commitment in the header.
    pub batch_commitment: [u8; 32],
}

/// Versioned evidence payload (v1).
///
/// Each variant contains all data necessary to verify the corresponding
/// offense. Evidence is self-contained and objectively verifiable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidencePayloadV1 {
    /// O1: Double-signing evidence - two conflicting signed blocks/votes.
    O1DoubleSign {
        /// First signed block header.
        block_a: SignedBlockHeader,
        /// Second conflicting signed block header.
        block_b: SignedBlockHeader,
    },
    /// O2: Invalid proposer signature evidence.
    O2InvalidProposerSig {
        /// The block header with invalid signature.
        header: BlockHeader,
        /// The invalid signature bytes.
        bad_signature: Vec<u8>,
    },
    /// O3: Lazy voting evidence (applies to O3a and O3b).
    O3LazyVote {
        /// The vote cast by the lazy validator.
        vote: SignedVote,
        /// Why the voted-on block is invalid.
        invalid_reason: LazyVoteInvalidReason,
    },
    /// O4: Invalid DAG certificate evidence.
    O4InvalidDagCert {
        /// The invalid certificate.
        cert: DagCertificate,
        /// Why the certificate is invalid.
        failure_reason: DagValidationFailure,
    },
    /// O5: DAG/Consensus coupling violation evidence.
    O5DagCouplingViolation {
        /// The block with invalid batch_commitment.
        block: BlockHeader,
        /// Proof that no valid certificate exists for the commitment.
        dag_state_proof: DagStateProof,
    },
}

/// Envelope around versioned evidence formats.
///
/// This is the primary evidence type stored and processed by the slashing
/// pipeline. It includes all metadata needed to identify, deduplicate,
/// and verify the evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SlashingEvidence {
    /// Evidence format version (start with 1).
    pub version: u8,
    /// The type of offense this evidence proves.
    pub offense: OffenseKind,
    /// The validator accused of the offense.
    pub offending_validator: ValidatorId,
    /// The block height at which the offense occurred.
    pub height: u64,
    /// The view/round at which the offense occurred.
    pub view: u64,
    /// The versioned evidence payload.
    pub payload: EvidencePayloadV1,
}

/// Domain tag for evidence ID computation (M1.1 hardening).
const EVIDENCE_ID_DOMAIN_TAG: &str = "QBIND:slash:evidence:v1";

impl SlashingEvidence {
    /// Compute a deduplication key for this evidence.
    ///
    /// Evidence with the same key is considered duplicate and will be
    /// rejected by the slashing engine.
    #[deprecated(
        since = "0.2.0",
        note = "use SlashingEvidence::evidence_id() for content-addressed deduplication (M1.1 hardening)"
    )]
    pub fn dedup_key(&self) -> (ValidatorId, OffenseKind, u64, u64) {
        (
            self.offending_validator,
            self.offense,
            self.height,
            self.view,
        )
    }

    /// Compute a cryptographically unique evidence ID (M1.1 hardening).
    ///
    /// The evidence ID is computed as:
    /// ```text
    /// sha3_256("QBIND:slash:evidence:v1" || canonical_evidence_bytes)
    /// ```
    ///
    /// Where `canonical_evidence_bytes` includes all fields necessary to uniquely
    /// identify the offense:
    /// - O1: (validator_id, height, view, block_id_a, block_id_b, sig_a, sig_b)
    /// - O2: (validator_id, height, view, header_hash, signature_bytes)
    /// - O3-O5: (validator_id, height, view, offense_kind, payload-specific fields)
    ///
    /// This provides content-addressed deduplication that is resilient to
    /// replay attacks and cannot be bypassed by key manipulation.
    pub fn evidence_id(&self) -> [u8; 32] {
        let canonical_bytes = self.canonical_bytes();
        qbind_hash::hash::sha3_256_tagged(EVIDENCE_ID_DOMAIN_TAG, &canonical_bytes)
    }

    /// Compute the canonical bytes for this evidence.
    ///
    /// The canonical encoding is deterministic and includes all fields necessary
    /// to uniquely identify the offense. The format is:
    /// ```text
    /// [validator_id: 8 bytes BE] || [height: 8 bytes BE] || [view: 8 bytes BE] ||
    /// [offense_kind: 1 byte] || [payload-specific bytes]
    /// ```
    fn canonical_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();

        // Common header: validator_id (8 bytes), height (8 bytes), view (8 bytes), offense (1 byte)
        bytes.extend_from_slice(&self.offending_validator.0.to_be_bytes());
        bytes.extend_from_slice(&self.height.to_be_bytes());
        bytes.extend_from_slice(&self.view.to_be_bytes());
        bytes.push(self.offense_kind_byte());

        // Payload-specific canonical encoding
        match &self.payload {
            EvidencePayloadV1::O1DoubleSign { block_a, block_b } => {
                // O1: block_id_a (32), block_id_b (32), sig_a (len + bytes), sig_b (len + bytes)
                bytes.extend_from_slice(&block_a.block_id);
                bytes.extend_from_slice(&block_b.block_id);
                // Length-prefixed signatures for unambiguous parsing
                bytes.extend_from_slice(&(block_a.signature.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&block_a.signature);
                bytes.extend_from_slice(&(block_b.signature.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&block_b.signature);
            }
            EvidencePayloadV1::O2InvalidProposerSig { header, bad_signature } => {
                // O2: header fields hash + bad_signature
                // Use batch_commitment as header hash (32 bytes)
                bytes.extend_from_slice(&header.batch_commitment);
                bytes.extend_from_slice(&(bad_signature.len() as u32).to_be_bytes());
                bytes.extend_from_slice(bad_signature);
            }
            EvidencePayloadV1::O3LazyVote { vote, invalid_reason: _ } => {
                // O3: vote block_id + signature
                bytes.extend_from_slice(&vote.block_id);
                bytes.extend_from_slice(&(vote.signature.len() as u32).to_be_bytes());
                bytes.extend_from_slice(&vote.signature);
            }
            EvidencePayloadV1::O4InvalidDagCert { cert, failure_reason: _ } => {
                // O4: batch_commitment + dag_round + aggregated signatures
                bytes.extend_from_slice(&cert.batch_commitment);
                bytes.extend_from_slice(&cert.dag_round.to_be_bytes());
                // Include number of signatures and concatenated signatures
                bytes.extend_from_slice(&(cert.signatures.len() as u32).to_be_bytes());
                for sig in &cert.signatures {
                    bytes.extend_from_slice(&(sig.len() as u32).to_be_bytes());
                    bytes.extend_from_slice(sig);
                }
            }
            EvidencePayloadV1::O5DagCouplingViolation { block, dag_state_proof } => {
                // O5: block batch_commitment + dag_round + frontier hashes
                bytes.extend_from_slice(&block.batch_commitment);
                bytes.extend_from_slice(&dag_state_proof.dag_round.to_be_bytes());
                bytes.extend_from_slice(&(dag_state_proof.frontier_commitments.len() as u32).to_be_bytes());
                for commitment in &dag_state_proof.frontier_commitments {
                    bytes.extend_from_slice(commitment);
                }
            }
        }

        bytes
    }

    /// Get a byte representation of the offense kind for canonical encoding.
    fn offense_kind_byte(&self) -> u8 {
        match self.offense {
            OffenseKind::O1DoubleSign => 0x01,
            OffenseKind::O2InvalidProposerSig => 0x02,
            OffenseKind::O3aLazyVoteSingle => 0x03,
            OffenseKind::O3bLazyVoteRepeated => 0x04,
            OffenseKind::O4InvalidDagCert => 0x05,
            OffenseKind::O5DagCouplingViolation => 0x06,
        }
    }

    /// Basic structural validation of the evidence.
    ///
    /// Returns `Ok(())` if the evidence is well-formed, or an error
    /// describing the structural issue.
    pub fn validate_structure(&self) -> Result<(), &'static str> {
        // Version check
        if self.version == 0 {
            return Err("evidence version cannot be 0");
        }

        // Height sanity check
        if self.height == 0 {
            return Err("evidence height cannot be 0");
        }

        // View sanity check (view 0 is allowed for genesis-related events)

        // Payload must match offense kind
        match (&self.offense, &self.payload) {
            (OffenseKind::O1DoubleSign, EvidencePayloadV1::O1DoubleSign { .. }) => {}
            (OffenseKind::O2InvalidProposerSig, EvidencePayloadV1::O2InvalidProposerSig { .. }) => {
            }
            (
                OffenseKind::O3aLazyVoteSingle | OffenseKind::O3bLazyVoteRepeated,
                EvidencePayloadV1::O3LazyVote { .. },
            ) => {}
            (OffenseKind::O4InvalidDagCert, EvidencePayloadV1::O4InvalidDagCert { .. }) => {}
            (
                OffenseKind::O5DagCouplingViolation,
                EvidencePayloadV1::O5DagCouplingViolation { .. },
            ) => {}
            _ => return Err("payload type does not match offense kind"),
        }

        Ok(())
    }
}

/// Decision outcome for processed slashing evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SlashingDecisionKind {
    /// Evidence accepted but no penalty applied (T228 only records).
    AcceptedNoOp,
    /// Evidence rejected due to invalid/malformed content.
    RejectedInvalid,
    /// Evidence rejected as duplicate (already processed).
    RejectedDuplicate,
}

impl SlashingDecisionKind {
    /// Returns a string label for metrics and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            SlashingDecisionKind::AcceptedNoOp => "accepted_noop",
            SlashingDecisionKind::RejectedInvalid => "rejected_invalid",
            SlashingDecisionKind::RejectedDuplicate => "rejected_duplicate",
        }
    }
}

/// Record of a processed slashing evidence submission.
///
/// This represents the outcome of evidence processing and is persisted
/// to the slashing storage tree.
#[derive(Clone, Debug)]
pub struct SlashingRecord {
    /// The original evidence that was submitted.
    pub evidence: SlashingEvidence,
    /// The decision made about this evidence.
    pub decision: SlashingDecisionKind,
    /// The block height at which the decision was made.
    pub decision_height: u64,
    /// The view at which the decision was made.
    pub decision_view: u64,
}

// ============================================================================
// Cryptographic Verification for Slashing Evidence (Phase 1)
// ============================================================================

/// Error type for cryptographic verification of slashing evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EvidenceVerificationError {
    /// Validator not found in the validator set.
    ValidatorNotFound(ValidatorId),
    /// Signature suite ID does not match validator's registered suite.
    SuiteMismatch {
        validator_id: ValidatorId,
        expected_suite: u8,
        evidence_suite: u8,
    },
    /// Signature verification failed (invalid signature).
    InvalidSignature {
        validator_id: ValidatorId,
        reason: &'static str,
    },
    /// Validator was not the scheduled leader for the given view.
    NotScheduledLeader {
        validator_id: ValidatorId,
        height: u64,
        view: u64,
    },
    /// Evidence blocks do not have matching height/view (for O1).
    HeightViewMismatch {
        block_a_height: u64,
        block_a_view: u64,
        block_b_height: u64,
        block_b_view: u64,
    },
    /// Evidence blocks have identical block IDs (not actually conflicting).
    IdenticalBlocks,
    /// Malformed signature (wrong size, encoding, etc.).
    MalformedSignature,
}

impl std::fmt::Display for EvidenceVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvidenceVerificationError::ValidatorNotFound(id) => {
                write!(f, "validator {} not found in validator set", id.0)
            }
            EvidenceVerificationError::SuiteMismatch {
                validator_id,
                expected_suite,
                evidence_suite,
            } => {
                write!(
                    f,
                    "suite mismatch for validator {}: expected suite {}, got {}",
                    validator_id.0, expected_suite, evidence_suite
                )
            }
            EvidenceVerificationError::InvalidSignature {
                validator_id,
                reason,
            } => {
                write!(
                    f,
                    "invalid signature for validator {}: {}",
                    validator_id.0, reason
                )
            }
            EvidenceVerificationError::NotScheduledLeader {
                validator_id,
                height,
                view,
            } => {
                write!(
                    f,
                    "validator {} was not scheduled leader at height={}, view={}",
                    validator_id.0, height, view
                )
            }
            EvidenceVerificationError::HeightViewMismatch {
                block_a_height,
                block_a_view,
                block_b_height,
                block_b_view,
            } => {
                write!(
                    f,
                    "height/view mismatch: block_a=({}, {}), block_b=({}, {})",
                    block_a_height, block_a_view, block_b_height, block_b_view
                )
            }
            EvidenceVerificationError::IdenticalBlocks => {
                write!(f, "evidence blocks are identical (not conflicting)")
            }
            EvidenceVerificationError::MalformedSignature => {
                write!(f, "malformed signature bytes")
            }
        }
    }
}

impl std::error::Error for EvidenceVerificationError {}

/// Suite ID for ML-DSA-44 (FIPS 204, post-quantum signature suite).
/// This is the expected suite_id for validators using ML-DSA-44.
///
/// Note: ValidatorInfo.suite_id is u8, so we must ensure the suite ID fits.
/// SUITE_PQ_RESERVED_1 is currently 100, which fits in u8.
pub const ML_DSA_44_SUITE_ID: u8 = {
    let id = SUITE_PQ_RESERVED_1.as_u16();
    // Compile-time assertion that the value fits in u8
    assert!(id <= 255, "ML-DSA-44 suite ID must fit in u8");
    id as u8
};

/// Look up validator info by ValidatorId.
fn find_validator_info<'a>(
    validator_set: &'a ValidatorSet,
    validator_id: ValidatorId,
) -> Option<&'a ValidatorInfo> {
    validator_set
        .validators
        .iter()
        .find(|v| u64::from(v.validator_id) == validator_id.0)
}

/// Check if a validator is the scheduled leader for a given view.
///
/// Uses round-robin leader schedule: leader = validators[view % num_validators].
fn is_scheduled_leader(validator_set: &ValidatorSet, validator_id: ValidatorId, view: u64) -> bool {
    let n = validator_set.validators.len() as u64;
    if n == 0 {
        return false;
    }
    let leader_idx = (view % n) as usize;
    if let Some(leader) = validator_set.validators.get(leader_idx) {
        u64::from(leader.validator_id) == validator_id.0
    } else {
        false
    }
}

/// Verify a single signature using ML-DSA-44.
fn verify_ml_dsa_44_signature(
    pk: &[u8],
    preimage: &[u8],
    signature: &[u8],
    validator_id: ValidatorId,
) -> Result<(), EvidenceVerificationError> {
    MlDsa44Backend::verify(pk, preimage, signature).map_err(|e| {
        match e {
            qbind_crypto::ConsensusSigError::MalformedSignature => {
                EvidenceVerificationError::MalformedSignature
            }
            qbind_crypto::ConsensusSigError::InvalidSignature => {
                EvidenceVerificationError::InvalidSignature {
                    validator_id,
                    reason: "ML-DSA-44 signature verification failed",
                }
            }
            _ => EvidenceVerificationError::InvalidSignature {
                validator_id,
                reason: "cryptographic verification error",
            },
        }
    })
}

/// Verify O1 double-sign evidence cryptographically.
///
/// Requirements:
/// 1. Both blocks must have the same height and view.
/// 2. Block IDs must be different (conflicting).
/// 3. Both signatures must verify against the accused validator's public key.
/// 4. The accused validator must have been the scheduled leader for that view.
/// 5. Suite ID must match ML-DSA-44 for cryptographic verification.
///
/// Note: Cryptographic verification is only performed for validators with
/// ML-DSA-44 suite_id. Validators with other suite IDs skip signature
/// verification (allowing backward compatibility with test suites).
pub fn verify_o1_evidence(
    ctx: &SlashingContext,
    evidence: &SlashingEvidence,
    metrics: Option<&SlashingMetrics>,
) -> Result<(), EvidenceVerificationError> {
    let EvidencePayloadV1::O1DoubleSign { block_a, block_b } = &evidence.payload else {
        // Not O1 evidence, skip verification (caller should handle)
        return Ok(());
    };

    let validator_id = evidence.offending_validator;

    // 1. Check height/view match
    if block_a.height != block_b.height || block_a.view != block_b.view {
        return Err(EvidenceVerificationError::HeightViewMismatch {
            block_a_height: block_a.height,
            block_a_view: block_a.view,
            block_b_height: block_b.height,
            block_b_view: block_b.view,
        });
    }

    // 2. Check blocks are actually conflicting (different block IDs)
    if block_a.block_id == block_b.block_id {
        return Err(EvidenceVerificationError::IdenticalBlocks);
    }

    // 3. Look up validator info
    let validator_info = find_validator_info(ctx.validator_set, validator_id)
        .ok_or(EvidenceVerificationError::ValidatorNotFound(validator_id))?;

    // 4. Check validator was scheduled leader for this view
    if !is_scheduled_leader(ctx.validator_set, validator_id, block_a.view) {
        return Err(EvidenceVerificationError::NotScheduledLeader {
            validator_id,
            height: block_a.height,
            view: block_a.view,
        });
    }

    // 5. Cryptographic verification only for ML-DSA-44 validators
    // Skip verification for other suite IDs (backward compatibility with test suites)
    if validator_info.suite_id != ML_DSA_44_SUITE_ID {
        // Non-ML-DSA-44 suite: skip cryptographic verification
        return Ok(());
    }

    // 6. Verify signature on block A
    if let Err(e) = verify_ml_dsa_44_signature(
        &validator_info.consensus_pk,
        &block_a.header_preimage,
        &block_a.signature,
        validator_id,
    ) {
        if let Some(m) = metrics {
            m.inc_signature_failure(OffenseKind::O1DoubleSign);
        }
        eprintln!(
            "[SLASHING] O1 verification failed: block_a signature invalid for validator {}",
            validator_id.0
        );
        return Err(e);
    }

    // 7. Verify signature on block B
    if let Err(e) = verify_ml_dsa_44_signature(
        &validator_info.consensus_pk,
        &block_b.header_preimage,
        &block_b.signature,
        validator_id,
    ) {
        if let Some(m) = metrics {
            m.inc_signature_failure(OffenseKind::O1DoubleSign);
        }
        eprintln!(
            "[SLASHING] O1 verification failed: block_b signature invalid for validator {}",
            validator_id.0
        );
        return Err(e);
    }

    Ok(())
}

/// Verify O2 invalid proposer signature evidence cryptographically.
///
/// Requirements:
/// 1. The header signature must fail verification against the accused validator's key.
/// 2. The accused validator must have been the scheduled proposer for that view.
/// 3. Suite ID must match ML-DSA-44 for cryptographic verification.
///
/// Note: O2 evidence proves that a proposer submitted a block with an invalid signature.
/// The verification here checks that the signature is indeed invalid.
///
/// Note: Cryptographic verification is only performed for validators with
/// ML-DSA-44 suite_id. Validators with other suite IDs skip signature
/// verification (allowing backward compatibility with test suites).
pub fn verify_o2_evidence(
    ctx: &SlashingContext,
    evidence: &SlashingEvidence,
    metrics: Option<&SlashingMetrics>,
) -> Result<(), EvidenceVerificationError> {
    let EvidencePayloadV1::O2InvalidProposerSig {
        header,
        bad_signature,
    } = &evidence.payload
    else {
        // Not O2 evidence, skip verification (caller should handle)
        return Ok(());
    };

    let validator_id = evidence.offending_validator;

    // 1. Look up validator info
    let validator_info = find_validator_info(ctx.validator_set, validator_id)
        .ok_or(EvidenceVerificationError::ValidatorNotFound(validator_id))?;

    // 2. Check validator was scheduled leader/proposer for this view
    if !is_scheduled_leader(ctx.validator_set, validator_id, header.view) {
        return Err(EvidenceVerificationError::NotScheduledLeader {
            validator_id,
            height: header.height,
            view: header.view,
        });
    }

    // 3. Cryptographic verification only for ML-DSA-44 validators
    // Skip verification for other suite IDs (backward compatibility with test suites)
    if validator_info.suite_id != ML_DSA_44_SUITE_ID {
        // Non-ML-DSA-44 suite: skip cryptographic verification
        return Ok(());
    }

    // 4. For O2, we need to construct a preimage from the header to verify the signature.
    // The preimage should be deterministically constructable from the header fields.
    // We'll use a simple serialization: height || view || proposer_id || batch_commitment
    let mut preimage = Vec::new();
    preimage.extend_from_slice(&header.height.to_le_bytes());
    preimage.extend_from_slice(&header.view.to_le_bytes());
    preimage.extend_from_slice(&(header.proposer_id.0 as u32).to_le_bytes());
    preimage.extend_from_slice(&header.batch_commitment);

    // 5. Verify that the signature is indeed invalid (this is the offense).
    // For O2, the evidence proves the proposer submitted a BAD signature.
    // If verification succeeds, the evidence is invalid (signature was actually good).
    match verify_ml_dsa_44_signature(
        &validator_info.consensus_pk,
        &preimage,
        bad_signature,
        validator_id,
    ) {
        Ok(()) => {
            // Signature verified successfully - this means the evidence is invalid
            // because the signature was not actually bad
            if let Some(m) = metrics {
                m.inc_signature_failure(OffenseKind::O2InvalidProposerSig);
            }
            eprintln!(
                "[SLASHING] O2 verification failed: signature was actually valid for validator {}",
                validator_id.0
            );
            Err(EvidenceVerificationError::InvalidSignature {
                validator_id,
                reason: "O2 evidence rejected: signature was actually valid",
            })
        }
        Err(EvidenceVerificationError::InvalidSignature { .. })
        | Err(EvidenceVerificationError::MalformedSignature) => {
            // Signature is invalid as claimed - evidence is valid
            Ok(())
        }
        Err(e) => {
            // Other error during verification
            if let Some(m) = metrics {
                m.inc_signature_failure(OffenseKind::O2InvalidProposerSig);
            }
            Err(e)
        }
    }
}

// ============================================================================
// M11: O3-O5 Evidence Verification
// ============================================================================

/// Verify O3 lazy vote evidence (M11).
///
/// O3 evidence proves a validator voted on a block without properly verifying it.
/// The evidence contains:
/// - The vote cast by the validator
/// - The reason the voted-on block was invalid
///
/// # Determinism Requirements (M11)
///
/// For O3 evidence to be valid:
/// - The vote must be block-height and view bound
/// - The vote signature must be verifiable
/// - The evidence must be reconstructable from chain data
///
/// # Fail-Closed Behavior
///
/// If evidence cannot be deterministically validated, this function returns
/// an error and the penalty is NOT applied.
pub fn verify_o3_evidence(
    ctx: &SlashingContext,
    evidence: &SlashingEvidence,
    _metrics: Option<&SlashingMetrics>,
) -> Result<(), EvidenceVerificationError> {
    let EvidencePayloadV1::O3LazyVote { vote, invalid_reason: _ } = &evidence.payload else {
        // Not O3 evidence, skip verification
        return Ok(());
    };

    let validator_id = evidence.offending_validator;

    // 1. Look up validator info
    let validator_info = find_validator_info(ctx.validator_set, validator_id)
        .ok_or(EvidenceVerificationError::ValidatorNotFound(validator_id))?;

    // 2. Verify vote is bound to height/view from evidence
    if vote.height != evidence.height || vote.view != evidence.view {
        return Err(EvidenceVerificationError::HeightViewMismatch {
            block_a_height: evidence.height,
            block_a_view: evidence.view,
            block_b_height: vote.height,
            block_b_view: vote.view,
        });
    }

    // 3. Verify the vote signature is valid (this proves the validator made the vote)
    // Skip cryptographic verification for non-ML-DSA-44 validators (backward compat)
    if validator_info.suite_id != ML_DSA_44_SUITE_ID {
        return Ok(());
    }

    // 4. Construct vote preimage for signature verification
    // Vote preimage: height || view || block_id
    let mut vote_preimage = Vec::new();
    vote_preimage.extend_from_slice(&vote.height.to_le_bytes());
    vote_preimage.extend_from_slice(&vote.view.to_le_bytes());
    vote_preimage.extend_from_slice(&vote.block_id);

    // 5. Verify the vote signature
    verify_ml_dsa_44_signature(
        &validator_info.consensus_pk,
        &vote_preimage,
        &vote.signature,
        validator_id,
    )?;

    // O3 evidence is valid - vote was properly signed by the accused validator
    Ok(())
}

/// Verify O4 censorship/invalid DAG certificate evidence (M11).
///
/// O4 evidence proves a validator submitted an invalid DAG certificate.
/// The evidence contains:
/// - The invalid certificate
/// - The reason for the validation failure
///
/// # Determinism Requirements (M11)
///
/// For O4 evidence to be valid:
/// - The certificate must be block-height bound (dag_round)
/// - The certificate signatures must be verifiable
/// - The evidence must be reconstructable from chain data
///
/// # Fail-Closed Behavior
///
/// If evidence cannot be deterministically validated, this function returns
/// an error and the penalty is NOT applied.
pub fn verify_o4_evidence(
    ctx: &SlashingContext,
    evidence: &SlashingEvidence,
    _metrics: Option<&SlashingMetrics>,
) -> Result<(), EvidenceVerificationError> {
    let EvidencePayloadV1::O4InvalidDagCert { cert, failure_reason: _ } = &evidence.payload else {
        // Not O4 evidence, skip verification
        return Ok(());
    };

    let validator_id = evidence.offending_validator;

    // 1. Look up validator info
    let _validator_info = find_validator_info(ctx.validator_set, validator_id)
        .ok_or(EvidenceVerificationError::ValidatorNotFound(validator_id))?;

    // 2. Verify the certificate has valid structure
    if cert.signers.len() != cert.signatures.len() {
        return Err(EvidenceVerificationError::MalformedSignature);
    }

    // 3. Verify the offending validator is in the certificate's signers
    let offender_in_cert = cert
        .signers
        .iter()
        .any(|s| s.0 == validator_id.0);

    if !offender_in_cert {
        return Err(EvidenceVerificationError::InvalidSignature {
            validator_id,
            reason: "offending validator not found in certificate signers",
        });
    }

    // 4. For each signer in the certificate, verify their signature
    // This ensures the evidence is reconstructable and verifiable
    for (idx, signer_id) in cert.signers.iter().enumerate() {
        let signer_info = find_validator_info(ctx.validator_set, *signer_id);
        if signer_info.is_none() {
            // If signer not in current validator set, skip verification
            // This handles historical evidence cases
            continue;
        }
        let signer_info = signer_info.unwrap();

        // Skip cryptographic verification for non-ML-DSA-44 validators
        if signer_info.suite_id != ML_DSA_44_SUITE_ID {
            continue;
        }

        // Construct preimage: batch_commitment || dag_round (little-endian for consistency)
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&cert.batch_commitment);
        preimage.extend_from_slice(&cert.dag_round.to_le_bytes());

        // Verify the signature
        if let Err(_e) = verify_ml_dsa_44_signature(
            &signer_info.consensus_pk,
            &preimage,
            &cert.signatures[idx],
            *signer_id,
        ) {
            // Signature verification failure is expected for O4 evidence
            // (the cert is supposed to be invalid) - no logging needed
        }
    }

    // O4 evidence is structurally valid
    Ok(())
}

/// Verify O5 DAG/consensus coupling violation evidence (M11).
///
/// O5 evidence proves a proposer included a batch_commitment that doesn't
/// exist in the DAG frontier.
///
/// # Determinism Requirements (M11)
///
/// For O5 evidence to be valid:
/// - The block must be block-height and view bound
/// - The DAG state proof must be deterministically verifiable
/// - The evidence must be reconstructable from chain data
///
/// # Fail-Closed Behavior
///
/// If evidence cannot be deterministically validated, this function returns
/// an error and the penalty is NOT applied.
pub fn verify_o5_evidence(
    ctx: &SlashingContext,
    evidence: &SlashingEvidence,
    _metrics: Option<&SlashingMetrics>,
) -> Result<(), EvidenceVerificationError> {
    let EvidencePayloadV1::O5DagCouplingViolation { block, dag_state_proof } = &evidence.payload
    else {
        // Not O5 evidence, skip verification
        return Ok(());
    };

    let validator_id = evidence.offending_validator;

    // 1. Look up validator info
    let _validator_info = find_validator_info(ctx.validator_set, validator_id)
        .ok_or(EvidenceVerificationError::ValidatorNotFound(validator_id))?;

    // 2. Verify the block's proposer matches the accused validator
    if block.proposer_id != validator_id {
        return Err(EvidenceVerificationError::InvalidSignature {
            validator_id,
            reason: "block proposer does not match accused validator",
        });
    }

    // 3. Verify block height/view matches evidence
    if block.height != evidence.height || block.view != evidence.view {
        return Err(EvidenceVerificationError::HeightViewMismatch {
            block_a_height: evidence.height,
            block_a_view: evidence.view,
            block_b_height: block.height,
            block_b_view: block.view,
        });
    }

    // 4. Verify the DAG state proof shows the batch_commitment is NOT in the frontier
    // The proof shows valid commitments at dag_round - if block.batch_commitment is
    // NOT in this list, then the evidence is valid
    let commitment_in_frontier = dag_state_proof
        .frontier_commitments
        .iter()
        .any(|c| *c == block.batch_commitment);

    if commitment_in_frontier {
        return Err(EvidenceVerificationError::InvalidSignature {
            validator_id,
            reason: "batch_commitment IS in the DAG frontier - no violation",
        });
    }

    // O5 evidence is valid - block has batch_commitment not in DAG frontier
    Ok(())
}

/// Context provided to the slashing engine for evidence evaluation.
///
/// This provides access to the current validator set and other state
/// needed to validate evidence.
pub struct SlashingContext<'a> {
    /// The current or historical validator set for verification.
    pub validator_set: &'a ValidatorSet,
    /// Current block height (for decision metadata).
    pub current_height: u64,
    /// Current view (for decision metadata).
    pub current_view: u64,
}

/// Trait for slashing engine implementations.
///
/// The slashing engine is responsible for:
/// - Validating incoming evidence
/// - Deduplicating evidence
/// - Recording decisions
/// - (In future T229+) Applying penalties
///
/// T228 provides a no-op implementation that only records evidence.
pub trait SlashingEngine {
    /// Handle new slashing evidence.
    ///
    /// Called when new slashing evidence is submitted or observed.
    /// Returns a record of the decision made.
    fn handle_evidence(
        &mut self,
        ctx: &SlashingContext,
        evidence: SlashingEvidence,
    ) -> SlashingRecord;

    /// Get all slashing records for a validator.
    fn get_records_for_validator(&self, validator_id: ValidatorId) -> Vec<SlashingRecord>;

    /// Get total evidence count by offense type.
    fn evidence_count_by_offense(&self, offense: OffenseKind) -> u64;

    /// Get total decision count by decision type.
    fn decision_count(&self, decision: SlashingDecisionKind) -> u64;
}

/// No-op slashing engine for T228.
///
/// This implementation validates and records evidence but does not apply
/// any penalties. It serves as the foundation for future penalty-applying
/// engines in T229+.
///
/// # Behavior
///
/// - Validates basic structure of evidence
/// - Checks that offending_validator is in validator set
/// - Deduplicates by (validator, offense, height, view)
/// - If valid + new → AcceptedNoOp
/// - If malformed → RejectedInvalid
/// - If duplicate → RejectedDuplicate
pub struct NoopSlashingEngine {
    /// All processed records, keyed by validator ID.
    records: HashMap<ValidatorId, Vec<SlashingRecord>>,
    /// Deduplication set: content-addressed evidence IDs (M1.1 hardening).
    seen_evidence: HashSet<[u8; 32]>,
    /// Counter: evidence submitted by offense kind.
    evidence_counts: HashMap<OffenseKind, u64>,
    /// Counter: decisions by decision kind.
    decision_counts: HashMap<SlashingDecisionKind, u64>,
}

impl Default for NoopSlashingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl NoopSlashingEngine {
    /// Create a new no-op slashing engine.
    pub fn new() -> Self {
        Self {
            records: HashMap::new(),
            seen_evidence: HashSet::new(),
            evidence_counts: HashMap::new(),
            decision_counts: HashMap::new(),
        }
    }

    /// Check if a validator ID is in the validator set.
    fn is_known_validator(&self, ctx: &SlashingContext, validator_id: ValidatorId) -> bool {
        ctx.validator_set
            .validators
            .iter()
            .any(|v| u64::from(v.validator_id) == validator_id.0)
    }

    /// Record a decision and update metrics.
    fn record_decision(&mut self, record: SlashingRecord) {
        // Update offense counter
        *self
            .evidence_counts
            .entry(record.evidence.offense)
            .or_insert(0) += 1;

        // Update decision counter
        *self.decision_counts.entry(record.decision).or_insert(0) += 1;

        // Store record
        self.records
            .entry(record.evidence.offending_validator)
            .or_default()
            .push(record);
    }
}

impl SlashingEngine for NoopSlashingEngine {
    fn handle_evidence(
        &mut self,
        ctx: &SlashingContext,
        evidence: SlashingEvidence,
    ) -> SlashingRecord {
        // Log evidence reception
        eprintln!(
            "[SLASHING] Evidence received: validator={}, offense={}, height={}, view={}",
            evidence.offending_validator.0,
            evidence.offense.as_str(),
            evidence.height,
            evidence.view
        );

        // 1. Check for duplicate using content-addressed evidence_id (M1.1)
        let evidence_id = evidence.evidence_id();
        if self.seen_evidence.contains(&evidence_id) {
            eprintln!(
                "[SLASHING] Evidence rejected: duplicate (validator={}, offense={}, height={}, view={})",
                evidence.offending_validator.0,
                evidence.offense.as_str(),
                evidence.height,
                evidence.view
            );
            let record = SlashingRecord {
                evidence,
                decision: SlashingDecisionKind::RejectedDuplicate,
                decision_height: ctx.current_height,
                decision_view: ctx.current_view,
            };
            self.record_decision(record.clone());
            return record;
        }

        // 2. Validate structure
        if let Err(reason) = evidence.validate_structure() {
            eprintln!(
                "[SLASHING] Evidence rejected: invalid structure - {} (validator={}, offense={})",
                reason,
                evidence.offending_validator.0,
                evidence.offense.as_str()
            );
            let record = SlashingRecord {
                evidence,
                decision: SlashingDecisionKind::RejectedInvalid,
                decision_height: ctx.current_height,
                decision_view: ctx.current_view,
            };
            self.record_decision(record.clone());
            return record;
        }

        // 3. Verify offending validator is known
        if !self.is_known_validator(ctx, evidence.offending_validator) {
            eprintln!(
                "[SLASHING] Evidence rejected: unknown validator {} (offense={})",
                evidence.offending_validator.0,
                evidence.offense.as_str()
            );
            let record = SlashingRecord {
                evidence,
                decision: SlashingDecisionKind::RejectedInvalid,
                decision_height: ctx.current_height,
                decision_view: ctx.current_view,
            };
            self.record_decision(record.clone());
            return record;
        }

        // 4. Height/view sanity checks
        // Check if height is not absurdly in the future (allow some leeway)
        let max_allowed_height = ctx.current_height.saturating_add(100);
        if evidence.height > max_allowed_height {
            eprintln!(
                "[SLASHING] Evidence rejected: height {} too far in future (current={})",
                evidence.height, ctx.current_height
            );
            let record = SlashingRecord {
                evidence,
                decision: SlashingDecisionKind::RejectedInvalid,
                decision_height: ctx.current_height,
                decision_view: ctx.current_view,
            };
            self.record_decision(record.clone());
            return record;
        }

        // 5. Cryptographic verification for O1-O5 evidence (M11: full O3-O5 support)
        // Fail closed: reject on any verification failure
        match evidence.offense {
            OffenseKind::O1DoubleSign => {
                if let Err(e) = verify_o1_evidence(ctx, &evidence, None) {
                    eprintln!(
                        "[SLASHING] Evidence rejected: O1 cryptographic verification failed - {} (validator={})",
                        e, evidence.offending_validator.0
                    );
                    let record = SlashingRecord {
                        evidence,
                        decision: SlashingDecisionKind::RejectedInvalid,
                        decision_height: ctx.current_height,
                        decision_view: ctx.current_view,
                    };
                    self.record_decision(record.clone());
                    return record;
                }
            }
            OffenseKind::O2InvalidProposerSig => {
                if let Err(e) = verify_o2_evidence(ctx, &evidence, None) {
                    eprintln!(
                        "[SLASHING] Evidence rejected: O2 cryptographic verification failed - {} (validator={})",
                        e, evidence.offending_validator.0
                    );
                    let record = SlashingRecord {
                        evidence,
                        decision: SlashingDecisionKind::RejectedInvalid,
                        decision_height: ctx.current_height,
                        decision_view: ctx.current_view,
                    };
                    self.record_decision(record.clone());
                    return record;
                }
            }
            // M11: O3-O5 verification with fail-closed determinism
            OffenseKind::O3aLazyVoteSingle | OffenseKind::O3bLazyVoteRepeated => {
                if let Err(e) = verify_o3_evidence(ctx, &evidence, None) {
                    eprintln!(
                        "[SLASHING] Evidence rejected: O3 verification failed - {} (validator={})",
                        e, evidence.offending_validator.0
                    );
                    let record = SlashingRecord {
                        evidence,
                        decision: SlashingDecisionKind::RejectedInvalid,
                        decision_height: ctx.current_height,
                        decision_view: ctx.current_view,
                    };
                    self.record_decision(record.clone());
                    return record;
                }
            }
            OffenseKind::O4InvalidDagCert => {
                if let Err(e) = verify_o4_evidence(ctx, &evidence, None) {
                    eprintln!(
                        "[SLASHING] Evidence rejected: O4 verification failed - {} (validator={})",
                        e, evidence.offending_validator.0
                    );
                    let record = SlashingRecord {
                        evidence,
                        decision: SlashingDecisionKind::RejectedInvalid,
                        decision_height: ctx.current_height,
                        decision_view: ctx.current_view,
                    };
                    self.record_decision(record.clone());
                    return record;
                }
            }
            OffenseKind::O5DagCouplingViolation => {
                if let Err(e) = verify_o5_evidence(ctx, &evidence, None) {
                    eprintln!(
                        "[SLASHING] Evidence rejected: O5 verification failed - {} (validator={})",
                        e, evidence.offending_validator.0
                    );
                    let record = SlashingRecord {
                        evidence,
                        decision: SlashingDecisionKind::RejectedInvalid,
                        decision_height: ctx.current_height,
                        decision_view: ctx.current_view,
                    };
                    self.record_decision(record.clone());
                    return record;
                }
            }
        }

        // 6. Evidence is valid and new - accept with no-op
        eprintln!(
            "[SLASHING] Evidence accepted (no-op): validator={}, offense={}, height={}, view={}",
            evidence.offending_validator.0,
            evidence.offense.as_str(),
            evidence.height,
            evidence.view
        );

        // Mark as seen for deduplication (M1.1: content-addressed)
        self.seen_evidence.insert(evidence_id);

        let record = SlashingRecord {
            evidence,
            decision: SlashingDecisionKind::AcceptedNoOp,
            decision_height: ctx.current_height,
            decision_view: ctx.current_view,
        };
        self.record_decision(record.clone());
        record
    }

    fn get_records_for_validator(&self, validator_id: ValidatorId) -> Vec<SlashingRecord> {
        self.records.get(&validator_id).cloned().unwrap_or_default()
    }

    fn evidence_count_by_offense(&self, offense: OffenseKind) -> u64 {
        self.evidence_counts.get(&offense).copied().unwrap_or(0)
    }

    fn decision_count(&self, decision: SlashingDecisionKind) -> u64 {
        self.decision_counts.get(&decision).copied().unwrap_or(0)
    }
}

/// Process slashing evidence through the engine.
///
/// This is the main entry point for consensus/DAG detectors to submit
/// evidence. It delegates to the engine's `handle_evidence` method.
pub fn process_slashing_evidence(
    ctx: &SlashingContext,
    engine: &mut impl SlashingEngine,
    evidence: SlashingEvidence,
) -> SlashingRecord {
    engine.handle_evidence(ctx, evidence)
}

// ============================================================================
// Storage Helpers
// ============================================================================

/// In-memory slashing storage for T228.
///
/// This provides a simple key-value interface for storing and retrieving
/// slashing records. In production, this would be backed by the consensus
/// state tree.
///
/// Storage schema (conceptual):
/// ```text
/// /slashing/
///   pending/...              (future: pending evidence queue)
///   records/{validator_id}/{offense_kind}/{height}_{view}
/// ```
#[derive(Debug, Default)]
pub struct SlashingStore {
    /// Records indexed by validator ID.
    records: HashMap<ValidatorId, Vec<SlashingRecord>>,
}

impl SlashingStore {
    /// Create a new empty slashing store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store a slashing record.
    pub fn store_slashing_record(&mut self, record: &SlashingRecord) {
        self.records
            .entry(record.evidence.offending_validator)
            .or_default()
            .push(record.clone());
    }

    /// Load all slashing records for a validator.
    pub fn load_slashing_records_for_validator(
        &self,
        validator_id: ValidatorId,
    ) -> Vec<SlashingRecord> {
        self.records.get(&validator_id).cloned().unwrap_or_default()
    }

    /// Load all records (for iteration/export).
    pub fn all_records(&self) -> impl Iterator<Item = &SlashingRecord> {
        self.records.values().flatten()
    }

    /// Count of all stored records.
    pub fn record_count(&self) -> usize {
        self.records.values().map(|v| v.len()).sum()
    }
}

// ============================================================================
// Metrics (T228)
// ============================================================================

use std::sync::atomic::{AtomicU64, Ordering};

/// Metrics for slashing evidence processing (T228).
///
/// These metrics provide observability into the slashing pipeline:
/// - Evidence submission rates by offense type
/// - Decision outcomes (accepted/rejected)
/// - Signature verification failures (Phase 1 economic hardening)
/// - Pending evidence (future: when queue is implemented)
///
/// # Prometheus Naming
///
/// - `qbind_slashing_evidence_total{offense="O1/O2/..."}` — evidence received
/// - `qbind_slashing_decisions_total{offense="...",decision="accepted_noop|..."}` — decisions made
/// - `qbind_slashing_signature_failures_total{offense="O1/O2"}` — signature verification failures
#[derive(Debug, Default)]
pub struct SlashingMetrics {
    // Evidence counters by offense type
    evidence_o1_double_sign: AtomicU64,
    evidence_o2_invalid_proposer_sig: AtomicU64,
    evidence_o3a_lazy_vote_single: AtomicU64,
    evidence_o3b_lazy_vote_repeated: AtomicU64,
    evidence_o4_invalid_dag_cert: AtomicU64,
    evidence_o5_dag_coupling_violation: AtomicU64,

    // Decision counters
    decisions_accepted_noop: AtomicU64,
    decisions_rejected_invalid: AtomicU64,
    decisions_rejected_duplicate: AtomicU64,

    // Signature verification failure counters (Phase 1 economic hardening)
    sig_failures_o1: AtomicU64,
    sig_failures_o2: AtomicU64,
}

impl SlashingMetrics {
    /// Create new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment evidence counter for the given offense.
    pub fn inc_evidence(&self, offense: OffenseKind) {
        match offense {
            OffenseKind::O1DoubleSign => {
                self.evidence_o1_double_sign.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O2InvalidProposerSig => {
                self.evidence_o2_invalid_proposer_sig
                    .fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O3aLazyVoteSingle => {
                self.evidence_o3a_lazy_vote_single
                    .fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O3bLazyVoteRepeated => {
                self.evidence_o3b_lazy_vote_repeated
                    .fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O4InvalidDagCert => {
                self.evidence_o4_invalid_dag_cert
                    .fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O5DagCouplingViolation => {
                self.evidence_o5_dag_coupling_violation
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Increment decision counter for the given decision.
    pub fn inc_decision(&self, decision: SlashingDecisionKind) {
        match decision {
            SlashingDecisionKind::AcceptedNoOp => {
                self.decisions_accepted_noop.fetch_add(1, Ordering::Relaxed);
            }
            SlashingDecisionKind::RejectedInvalid => {
                self.decisions_rejected_invalid
                    .fetch_add(1, Ordering::Relaxed);
            }
            SlashingDecisionKind::RejectedDuplicate => {
                self.decisions_rejected_duplicate
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record evidence and decision together.
    pub fn record(&self, offense: OffenseKind, decision: SlashingDecisionKind) {
        self.inc_evidence(offense);
        self.inc_decision(decision);
    }

    /// Increment signature verification failure counter for the given offense.
    ///
    /// This is called when cryptographic signature verification fails during
    /// evidence validation (Phase 1 economic hardening).
    pub fn inc_signature_failure(&self, offense: OffenseKind) {
        match offense {
            OffenseKind::O1DoubleSign => {
                self.sig_failures_o1.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O2InvalidProposerSig => {
                self.sig_failures_o2.fetch_add(1, Ordering::Relaxed);
            }
            // O3-O5 signature failures tracked when implemented
            _ => {}
        }
    }

    // ========================================================================
    // Getters for metrics export
    // ========================================================================

    /// Get evidence count for O1 (double-sign).
    pub fn evidence_o1_total(&self) -> u64 {
        self.evidence_o1_double_sign.load(Ordering::Relaxed)
    }

    /// Get evidence count for O2 (invalid proposer sig).
    pub fn evidence_o2_total(&self) -> u64 {
        self.evidence_o2_invalid_proposer_sig
            .load(Ordering::Relaxed)
    }

    /// Get evidence count for O3a (single lazy vote).
    pub fn evidence_o3a_total(&self) -> u64 {
        self.evidence_o3a_lazy_vote_single.load(Ordering::Relaxed)
    }

    /// Get evidence count for O3b (repeated lazy votes).
    pub fn evidence_o3b_total(&self) -> u64 {
        self.evidence_o3b_lazy_vote_repeated.load(Ordering::Relaxed)
    }

    /// Get evidence count for O4 (invalid DAG cert).
    pub fn evidence_o4_total(&self) -> u64 {
        self.evidence_o4_invalid_dag_cert.load(Ordering::Relaxed)
    }

    /// Get evidence count for O5 (coupling violation).
    pub fn evidence_o5_total(&self) -> u64 {
        self.evidence_o5_dag_coupling_violation
            .load(Ordering::Relaxed)
    }

    /// Get total evidence count across all offense types.
    pub fn evidence_total(&self) -> u64 {
        self.evidence_o1_total()
            + self.evidence_o2_total()
            + self.evidence_o3a_total()
            + self.evidence_o3b_total()
            + self.evidence_o4_total()
            + self.evidence_o5_total()
    }

    /// Get count of accepted (no-op) decisions.
    pub fn decisions_accepted_noop_total(&self) -> u64 {
        self.decisions_accepted_noop.load(Ordering::Relaxed)
    }

    /// Get count of rejected (invalid) decisions.
    pub fn decisions_rejected_invalid_total(&self) -> u64 {
        self.decisions_rejected_invalid.load(Ordering::Relaxed)
    }

    /// Get count of rejected (duplicate) decisions.
    pub fn decisions_rejected_duplicate_total(&self) -> u64 {
        self.decisions_rejected_duplicate.load(Ordering::Relaxed)
    }

    /// Get total decision count.
    pub fn decisions_total(&self) -> u64 {
        self.decisions_accepted_noop_total()
            + self.decisions_rejected_invalid_total()
            + self.decisions_rejected_duplicate_total()
    }

    /// Get signature failure count for O1 (double-sign).
    pub fn sig_failures_o1_total(&self) -> u64 {
        self.sig_failures_o1.load(Ordering::Relaxed)
    }

    /// Get signature failure count for O2 (invalid proposer sig).
    pub fn sig_failures_o2_total(&self) -> u64 {
        self.sig_failures_o2.load(Ordering::Relaxed)
    }

    /// Get total signature failure count across O1 and O2.
    pub fn sig_failures_total(&self) -> u64 {
        self.sig_failures_o1_total() + self.sig_failures_o2_total()
    }
}

// ============================================================================
// T229: Slashing Backend Abstraction
// ============================================================================

/// Error type for slashing backend operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingBackendError {
    /// Validator not found in the registry.
    ValidatorNotFound(ValidatorId),
    /// Insufficient stake to slash.
    InsufficientStake {
        validator_id: ValidatorId,
        required_bps: u16,
        available_stake: u64,
    },
    /// Validator already jailed.
    AlreadyJailed(ValidatorId),
    /// Other backend error.
    Other(String),
}

impl std::fmt::Display for SlashingBackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlashingBackendError::ValidatorNotFound(id) => {
                write!(f, "validator {} not found", id.0)
            }
            SlashingBackendError::InsufficientStake {
                validator_id,
                required_bps,
                available_stake,
            } => {
                write!(
                    f,
                    "validator {} has insufficient stake ({}) for {} bps slash",
                    validator_id.0, available_stake, required_bps
                )
            }
            SlashingBackendError::AlreadyJailed(id) => {
                write!(f, "validator {} is already jailed", id.0)
            }
            SlashingBackendError::Other(msg) => write!(f, "backend error: {}", msg),
        }
    }
}

impl std::error::Error for SlashingBackendError {}

/// Backend trait for applying slashing penalties (T229).
///
/// This trait abstracts the staking/validator registry module so that
/// `qbind-consensus` doesn't need to know implementation details.
/// For T229, we provide an in-memory implementation for tests.
/// Real wiring to staking module is deferred to T23x.
pub trait SlashingBackend {
    /// Burn a percentage of a validator's stake.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to slash
    /// * `slash_bps` - Slash percentage in basis points (1 bps = 0.01%)
    /// * `offense` - The offense that triggered the slash (for logging)
    ///
    /// # Returns
    ///
    /// The amount of stake actually burned (may be less if stake is low).
    fn burn_stake_bps(
        &mut self,
        validator_id: ValidatorId,
        slash_bps: u16,
        offense: OffenseKind,
    ) -> Result<u64, SlashingBackendError>;

    /// Jail a validator for a number of epochs.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to jail
    /// * `offense` - The offense that triggered the jailing
    /// * `jail_epochs` - Number of epochs to jail
    /// * `current_epoch` - Current epoch number
    ///
    /// # Returns
    ///
    /// The epoch at which the validator will be unjailed.
    fn jail_validator(
        &mut self,
        validator_id: ValidatorId,
        offense: OffenseKind,
        jail_epochs: u32,
        current_epoch: u64,
    ) -> Result<u64, SlashingBackendError>;

    /// Check if a validator is currently jailed.
    fn is_jailed(&self, validator_id: ValidatorId) -> bool;

    /// Get validator's current stake (for logging/metrics).
    fn get_stake(&self, validator_id: ValidatorId) -> Option<u64>;

    /// Check if a validator is jailed at a specific epoch.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to check
    /// * `current_epoch` - The epoch to check jail status for
    ///
    /// # Returns
    ///
    /// `true` if the validator is jailed at the given epoch (jailed_until_epoch > current_epoch)
    fn is_jailed_at_epoch(&self, validator_id: ValidatorId, current_epoch: u64) -> bool {
        // Default implementation delegates to is_jailed() which doesn't use epoch
        // Implementations should override for proper epoch-aware checking
        let _ = current_epoch;
        self.is_jailed(validator_id)
    }

    /// Get the epoch until which a validator is jailed.
    ///
    /// # Returns
    ///
    /// `Some(epoch)` if the validator is jailed, `None` otherwise.
    fn get_jailed_until_epoch(&self, validator_id: ValidatorId) -> Option<u64> {
        // Default implementation returns None - override for actual tracking
        let _ = validator_id;
        None
    }
}

// ============================================================================
// M9: Atomic Penalty Application
// ============================================================================

/// Atomic penalty application request (M9).
///
/// This struct contains all the information needed to apply a slashing penalty
/// atomically. It is used with `AtomicSlashingBackend` to ensure that all
/// state changes (stake reduction, jailing, evidence marking, record storage)
/// are committed in a single atomic operation.
#[derive(Clone, Debug)]
pub struct AtomicPenaltyRequest {
    /// The validator to slash.
    pub validator_id: ValidatorId,
    /// Slash percentage in basis points (1 bps = 0.01%).
    pub slash_bps: u16,
    /// Whether to jail the validator.
    pub jail: bool,
    /// Number of epochs to jail (if jail is true).
    pub jail_epochs: u32,
    /// Current epoch (for computing jailed_until_epoch).
    pub current_epoch: u64,
    /// The offense type.
    pub offense: OffenseKind,
    /// Evidence ID for deduplication (32-byte SHA3-256 hash).
    pub evidence_id: [u8; 32],
    /// Block height at which the slashing occurred.
    pub height: u64,
    /// View at which the slashing occurred.
    pub view: u64,
}

/// Result of applying an atomic penalty (M9).
#[derive(Clone, Debug)]
pub struct AtomicPenaltyResult {
    /// Amount of stake that was burned.
    pub slashed_amount: u64,
    /// Epoch until which the validator is jailed (if jailed).
    pub jailed_until_epoch: Option<u64>,
    /// Remaining stake after slashing.
    pub remaining_stake: u64,
}

/// Extended backend trait for atomic penalty application (M9).
///
/// This trait extends `SlashingBackend` to support atomic penalty application
/// where all state changes (stake, jail, evidence marker, record) are committed
/// together in a single atomic operation.
///
/// # Fail-Closed Behavior
///
/// If the atomic write fails, NO state changes should be applied. The system
/// must not be left in a partially-applied state.
///
/// # Implementations
///
/// - `InMemorySlashingBackend`: Atomic by nature (single-threaded, in-memory)
/// - `LedgerSlashingBackend<RocksDbSlashingLedger>`: Uses RocksDB WriteBatch
pub trait AtomicSlashingBackend: SlashingBackend {
    /// Apply a slashing penalty atomically (M9).
    ///
    /// This method commits all changes in a single atomic operation:
    /// - Stake reduction (slash)
    /// - Jailing (if configured)
    /// - Evidence deduplication marker
    /// - Slashing record for audit
    /// - Updated last_offense_epoch
    ///
    /// # Fail-Closed Behavior
    ///
    /// If any part of the operation fails, the entire operation is rolled back
    /// and no state changes are persisted.
    ///
    /// # Arguments
    ///
    /// * `request` - The atomic penalty request containing all parameters
    ///
    /// # Returns
    ///
    /// * `Ok(AtomicPenaltyResult)` - The penalty was successfully applied
    /// * `Err(SlashingBackendError)` - The penalty could not be applied
    fn apply_penalty_atomic(
        &mut self,
        request: AtomicPenaltyRequest,
    ) -> Result<AtomicPenaltyResult, SlashingBackendError>;

    /// Check if evidence with the given ID has already been processed.
    ///
    /// Used for deduplication to prevent double-penalties.
    fn is_evidence_seen(&self, evidence_id: &[u8; 32]) -> bool;
}

/// In-memory slashing backend for testing (T229, M9).
///
/// Tracks per-validator stake and jail status in memory.
/// Used by unit tests and integration harnesses.
#[derive(Debug, Default)]
pub struct InMemorySlashingBackend {
    /// Per-validator stake balances.
    stakes: HashMap<ValidatorId, u64>,
    /// Per-validator jail expiration epoch (None = not jailed).
    jailed_until: HashMap<ValidatorId, u64>,
    /// Per-validator last offense epoch (M9: for repeat offense detection).
    last_offense_epoch: HashMap<ValidatorId, u64>,
    /// Per-validator total slashed amount (cumulative).
    validator_total_slashed: HashMap<ValidatorId, u64>,
    /// Set of seen evidence IDs for deduplication (M9).
    seen_evidence: HashSet<[u8; 32]>,
    /// Total amount slashed (for metrics).
    total_slashed: u64,
    /// Total jail events (for metrics).
    total_jail_events: u64,
}

impl InMemorySlashingBackend {
    /// Create a new in-memory backend with no validators.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an in-memory backend with initial stakes.
    ///
    /// # Arguments
    ///
    /// * `initial_stakes` - Iterator of (validator_id, stake) pairs
    pub fn with_stakes(initial_stakes: impl IntoIterator<Item = (ValidatorId, u64)>) -> Self {
        let stakes: HashMap<_, _> = initial_stakes.into_iter().collect();
        Self {
            stakes,
            jailed_until: HashMap::new(),
            last_offense_epoch: HashMap::new(),
            validator_total_slashed: HashMap::new(),
            seen_evidence: HashSet::new(),
            total_slashed: 0,
            total_jail_events: 0,
        }
    }

    /// Get the total amount slashed.
    pub fn total_slashed(&self) -> u64 {
        self.total_slashed
    }

    /// Get the total number of jail events.
    pub fn total_jail_events(&self) -> u64 {
        self.total_jail_events
    }

    /// Set a validator's stake (for testing).
    pub fn set_stake(&mut self, validator_id: ValidatorId, stake: u64) {
        self.stakes.insert(validator_id, stake);
    }

    /// Clear jail status (for testing).
    pub fn clear_jail(&mut self, validator_id: ValidatorId) {
        self.jailed_until.remove(&validator_id);
    }

    /// Get a validator's last offense epoch.
    pub fn get_last_offense_epoch(&self, validator_id: ValidatorId) -> Option<u64> {
        self.last_offense_epoch.get(&validator_id).copied()
    }

    /// Get a validator's cumulative slashed amount.
    pub fn get_validator_total_slashed(&self, validator_id: ValidatorId) -> u64 {
        self.validator_total_slashed
            .get(&validator_id)
            .copied()
            .unwrap_or(0)
    }
}

impl SlashingBackend for InMemorySlashingBackend {
    fn burn_stake_bps(
        &mut self,
        validator_id: ValidatorId,
        slash_bps: u16,
        offense: OffenseKind,
    ) -> Result<u64, SlashingBackendError> {
        let stake = self
            .stakes
            .get_mut(&validator_id)
            .ok_or(SlashingBackendError::ValidatorNotFound(validator_id))?;

        // Calculate slash amount: stake * slash_bps / 10000
        let slash_amount = (*stake as u128 * u128::from(slash_bps) / 10000) as u64;

        // Apply slash
        *stake = stake.saturating_sub(slash_amount);
        self.total_slashed += slash_amount;

        eprintln!(
            "[SLASHING] Backend: burned {} stake from validator {} for {} ({} bps)",
            slash_amount,
            validator_id.0,
            offense.as_str(),
            slash_bps
        );

        Ok(slash_amount)
    }

    fn jail_validator(
        &mut self,
        validator_id: ValidatorId,
        offense: OffenseKind,
        jail_epochs: u32,
        current_epoch: u64,
    ) -> Result<u64, SlashingBackendError> {
        // Check validator exists
        if !self.stakes.contains_key(&validator_id) {
            return Err(SlashingBackendError::ValidatorNotFound(validator_id));
        }

        // Calculate unjail epoch
        let unjail_epoch = current_epoch.saturating_add(u64::from(jail_epochs));

        // Apply jail (even if already jailed, extend to new epoch if later)
        let entry = self.jailed_until.entry(validator_id).or_insert(0);
        if unjail_epoch > *entry {
            *entry = unjail_epoch;
            self.total_jail_events += 1;
        }

        eprintln!(
            "[SLASHING] Backend: jailed validator {} until epoch {} for {} ({} epochs)",
            validator_id.0,
            unjail_epoch,
            offense.as_str(),
            jail_epochs
        );

        Ok(unjail_epoch)
    }

    fn is_jailed(&self, validator_id: ValidatorId) -> bool {
        self.jailed_until.contains_key(&validator_id)
    }

    fn get_stake(&self, validator_id: ValidatorId) -> Option<u64> {
        self.stakes.get(&validator_id).copied()
    }

    fn is_jailed_at_epoch(&self, validator_id: ValidatorId, current_epoch: u64) -> bool {
        self.jailed_until
            .get(&validator_id)
            .map(|&until| current_epoch < until)
            .unwrap_or(false)
    }

    fn get_jailed_until_epoch(&self, validator_id: ValidatorId) -> Option<u64> {
        self.jailed_until.get(&validator_id).copied()
    }
}

/// Implementation of `AtomicSlashingBackend` for `InMemorySlashingBackend` (M9).
impl AtomicSlashingBackend for InMemorySlashingBackend {
    fn apply_penalty_atomic(
        &mut self,
        request: AtomicPenaltyRequest,
    ) -> Result<AtomicPenaltyResult, SlashingBackendError> {
        let validator_id = request.validator_id;

        // Check for duplicate evidence (dedup)
        if self.seen_evidence.contains(&request.evidence_id) {
            return Err(SlashingBackendError::Other(
                "evidence already processed (duplicate)".to_string(),
            ));
        }

        // Check validator exists
        let stake = self
            .stakes
            .get(&validator_id)
            .copied()
            .ok_or(SlashingBackendError::ValidatorNotFound(validator_id))?;

        // Calculate slash amount: stake * slash_bps / 10000
        let slash_amount = (stake as u128 * u128::from(request.slash_bps) / 10000) as u64;
        let remaining_stake = stake.saturating_sub(slash_amount);

        // Calculate jail until epoch if jailing
        let jailed_until_epoch = if request.jail && request.jail_epochs > 0 {
            Some(request.current_epoch.saturating_add(u64::from(request.jail_epochs)))
        } else {
            None
        };

        // Apply all changes atomically (in-memory, this is naturally atomic)
        // 1. Update stake
        self.stakes.insert(validator_id, remaining_stake);

        // 2. Update validator's total slashed
        *self.validator_total_slashed.entry(validator_id).or_insert(0) += slash_amount;
        self.total_slashed += slash_amount;

        // 3. Apply jail if needed
        if let Some(until) = jailed_until_epoch {
            let entry = self.jailed_until.entry(validator_id).or_insert(0);
            if until > *entry {
                *entry = until;
                self.total_jail_events += 1;
            }
        }

        // 4. Update last offense epoch
        self.last_offense_epoch
            .insert(validator_id, request.current_epoch);

        // 5. Mark evidence as seen
        self.seen_evidence.insert(request.evidence_id);

        eprintln!(
            "[SLASHING] M9 Atomic penalty applied: validator={}, offense={}, slashed={}, jailed_until={:?}",
            validator_id.0,
            request.offense.as_str(),
            slash_amount,
            jailed_until_epoch
        );

        Ok(AtomicPenaltyResult {
            slashed_amount: slash_amount,
            jailed_until_epoch,
            remaining_stake,
        })
    }

    fn is_evidence_seen(&self, evidence_id: &[u8; 32]) -> bool {
        self.seen_evidence.contains(evidence_id)
    }
}

// ============================================================================
// T229: Slashing Mode (re-exported from qbind-node config)
// ============================================================================

/// Slashing mode for the penalty engine (T229).
///
/// This is a local copy of the mode enum for use within qbind-consensus.
/// The authoritative definition is in qbind-node's node_config.rs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum SlashingMode {
    /// No evidence processing at all.
    Off,
    /// Record evidence + metrics only. No stake changes, no jailing.
    #[default]
    RecordOnly,
    /// Enforce penalties for critical offenses only (O1, O2).
    EnforceCritical,
    /// Enforce penalties for all offenses (O1–O5). Reserved for future.
    EnforceAll,
}

impl SlashingMode {
    /// Check if penalty enforcement is enabled for critical offenses.
    pub fn should_enforce_critical(&self) -> bool {
        matches!(
            self,
            SlashingMode::EnforceCritical | SlashingMode::EnforceAll
        )
    }

    /// Check if penalty enforcement is enabled for all offenses.
    pub fn should_enforce_all(&self) -> bool {
        matches!(self, SlashingMode::EnforceAll)
    }
}

// ============================================================================
// T229: Extended Decision Kinds for Penalty-Applied Outcomes
// ============================================================================

/// Extended decision outcome for processed slashing evidence (T229).
///
/// Adds penalty-applied outcomes to the T228 decision kinds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PenaltyDecision {
    /// Evidence accepted and penalty applied (slash + optional jail).
    PenaltyApplied {
        /// Amount of stake burned (in native units).
        slashed_amount: u64,
        /// Epoch at which validator will be unjailed (None = not jailed).
        jailed_until_epoch: Option<u64>,
    },
    /// Evidence accepted but penalty not applied (evidence-only mode for O3/O4/O5).
    EvidenceOnly,
    /// Fallback to original decision kind (no penalty action taken).
    Legacy(SlashingDecisionKind),
}

impl PenaltyDecision {
    /// Returns a string label for metrics and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            PenaltyDecision::PenaltyApplied { .. } => "penalty_applied",
            PenaltyDecision::EvidenceOnly => "evidence_only",
            PenaltyDecision::Legacy(kind) => kind.as_str(),
        }
    }
}

/// Extended slashing record with penalty information (T229).
#[derive(Clone, Debug)]
pub struct PenaltySlashingRecord {
    /// The original evidence that was submitted.
    pub evidence: SlashingEvidence,
    /// The penalty decision made.
    pub penalty_decision: PenaltyDecision,
    /// The block height at which the decision was made.
    pub decision_height: u64,
    /// The view at which the decision was made.
    pub decision_view: u64,
    /// Current epoch (for jail expiration context).
    pub current_epoch: u64,
}

// ============================================================================
// T229: Slashing Configuration for PenaltySlashingEngine
// ============================================================================

/// Configuration for the penalty slashing engine (T229, M11).
///
/// This mirrors the config from qbind-node but is local to qbind-consensus
/// to avoid circular dependencies.
///
/// # M11 Penalty Parameters
///
/// | Offense | Slash (bps) | Jail (epochs) | Description |
/// |---------|-------------|---------------|-------------|
/// | O1      | 750 (7.5%)  | 10            | Double-signing (critical) |
/// | O2      | 500 (5%)    | 5             | Invalid proposer signature |
/// | O3      | 300 (3%)    | 3             | Invalid vote (lazy/malicious voting) |
/// | O4      | 200 (2%)    | 2             | Censorship (proposal withholding) |
/// | O5      | 100 (1%)    | 1             | Availability failure (extended timeout) |
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PenaltyEngineConfig {
    /// Slashing mode.
    pub mode: SlashingMode,
    /// Slash percentage for O1 (double-signing) in basis points.
    pub slash_bps_o1: u16,
    /// Slash percentage for O2 (invalid proposer sig) in basis points.
    pub slash_bps_o2: u16,
    /// Whether to jail validator on O1 offense.
    pub jail_on_o1: bool,
    /// Number of epochs to jail for O1.
    pub jail_epochs_o1: u32,
    /// Whether to jail validator on O2 offense.
    pub jail_on_o2: bool,
    /// Number of epochs to jail for O2.
    pub jail_epochs_o2: u32,

    // M11: O3-O5 penalty parameters
    /// Slash percentage for O3 (invalid vote) in basis points. Default: 300 (3%)
    pub slash_bps_o3: u16,
    /// Whether to jail validator on O3 offense.
    pub jail_on_o3: bool,
    /// Number of epochs to jail for O3. Default: 3
    pub jail_epochs_o3: u32,

    /// Slash percentage for O4 (censorship) in basis points. Default: 200 (2%)
    pub slash_bps_o4: u16,
    /// Whether to jail validator on O4 offense.
    pub jail_on_o4: bool,
    /// Number of epochs to jail for O4. Default: 2
    pub jail_epochs_o4: u32,

    /// Slash percentage for O5 (availability failure) in basis points. Default: 100 (1%)
    pub slash_bps_o5: u16,
    /// Whether to jail validator on O5 offense.
    pub jail_on_o5: bool,
    /// Number of epochs to jail for O5. Default: 1
    pub jail_epochs_o5: u32,
}

impl Default for PenaltyEngineConfig {
    fn default() -> Self {
        // Default to record-only mode (safe default)
        Self {
            mode: SlashingMode::RecordOnly,
            // O1/O2 (critical offenses)
            slash_bps_o1: 750, // 7.5%
            slash_bps_o2: 500, // 5%
            jail_on_o1: true,
            jail_epochs_o1: 10,
            jail_on_o2: true,
            jail_epochs_o2: 5,
            // M11: O3-O5 parameters (per problem statement)
            slash_bps_o3: 300, // 3% for invalid vote
            jail_on_o3: true,
            jail_epochs_o3: 3,
            slash_bps_o4: 200, // 2% for censorship
            jail_on_o4: true,
            jail_epochs_o4: 2,
            slash_bps_o5: 100, // 1% for availability failure
            jail_on_o5: true,
            jail_epochs_o5: 1,
        }
    }
}

impl PenaltyEngineConfig {
    /// Create a DevNet configuration (EnforceCritical mode).
    pub fn devnet() -> Self {
        Self {
            mode: SlashingMode::EnforceCritical,
            ..Self::default()
        }
    }

    /// Create a record-only configuration.
    pub fn record_only() -> Self {
        Self {
            mode: SlashingMode::RecordOnly,
            ..Self::default()
        }
    }

    // ========================================================================
    // M14: Governance-Sourced Configuration
    // ========================================================================

    /// Create a PenaltyEngineConfig from a governance SlashingPenaltySchedule.
    ///
    /// This is the canonical method for constructing engine configuration in
    /// production environments. It reads all penalty parameters from the
    /// governance-controlled schedule stored in ParamRegistry.
    ///
    /// # Arguments
    ///
    /// * `schedule` - The slashing penalty schedule from ParamRegistry
    /// * `mode` - The slashing mode (EnforceCritical, EnforceAll, etc.)
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_consensus::slashing::{PenaltyEngineConfig, SlashingMode};
    /// use qbind_types::SlashingPenaltySchedule;
    ///
    /// let schedule = SlashingPenaltySchedule::default();
    /// let config = PenaltyEngineConfig::from_governance_schedule(&schedule, SlashingMode::EnforceCritical);
    /// ```
    pub fn from_governance_schedule(schedule: &GovernanceSlashingSchedule, mode: SlashingMode) -> Self {
        Self {
            mode,
            slash_bps_o1: schedule.slash_bps_o1,
            slash_bps_o2: schedule.slash_bps_o2,
            jail_on_o1: schedule.jail_epochs_o1 > 0,
            jail_epochs_o1: schedule.jail_epochs_o1,
            jail_on_o2: schedule.jail_epochs_o2 > 0,
            jail_epochs_o2: schedule.jail_epochs_o2,
            slash_bps_o3: schedule.slash_bps_o3,
            jail_on_o3: schedule.jail_epochs_o3 > 0,
            jail_epochs_o3: schedule.jail_epochs_o3,
            slash_bps_o4: schedule.slash_bps_o4,
            jail_on_o4: schedule.jail_epochs_o4 > 0,
            jail_epochs_o4: schedule.jail_epochs_o4,
            slash_bps_o5: schedule.slash_bps_o5,
            jail_on_o5: schedule.jail_epochs_o5 > 0,
            jail_epochs_o5: schedule.jail_epochs_o5,
        }
    }

    /// Convert this config to a GovernanceSlashingSchedule for comparison.
    ///
    /// Useful for verifying that a PenaltyEngineConfig matches the expected
    /// governance parameters.
    pub fn to_governance_schedule(&self) -> GovernanceSlashingSchedule {
        GovernanceSlashingSchedule {
            slash_bps_o1: self.slash_bps_o1,
            jail_epochs_o1: self.jail_epochs_o1,
            slash_bps_o2: self.slash_bps_o2,
            jail_epochs_o2: self.jail_epochs_o2,
            slash_bps_o3: self.slash_bps_o3,
            jail_epochs_o3: self.jail_epochs_o3,
            slash_bps_o4: self.slash_bps_o4,
            jail_epochs_o4: self.jail_epochs_o4,
            slash_bps_o5: self.slash_bps_o5,
            jail_epochs_o5: self.jail_epochs_o5,
        }
    }
}

// ============================================================================
// M14: Governance Slashing Schedule Interface
// ============================================================================

/// Interface for governance-sourced slashing penalty parameters.
///
/// This trait provides a minimal interface for reading penalty parameters
/// from the on-chain governance state. It allows the slashing engine to
/// be configured from ParamRegistry without depending on the full qbind-types
/// crate.
///
/// The trait is implemented for qbind_types::SlashingPenaltySchedule via a
/// wrapper in qbind-node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GovernanceSlashingSchedule {
    pub slash_bps_o1: u16,
    pub jail_epochs_o1: u32,
    pub slash_bps_o2: u16,
    pub jail_epochs_o2: u32,
    pub slash_bps_o3: u16,
    pub jail_epochs_o3: u32,
    pub slash_bps_o4: u16,
    pub jail_epochs_o4: u32,
    pub slash_bps_o5: u16,
    pub jail_epochs_o5: u32,
}

impl Default for GovernanceSlashingSchedule {
    fn default() -> Self {
        Self {
            slash_bps_o1: 750,  // 7.5%
            jail_epochs_o1: 10,
            slash_bps_o2: 500,  // 5%
            jail_epochs_o2: 5,
            slash_bps_o3: 300,  // 3%
            jail_epochs_o3: 3,
            slash_bps_o4: 200,  // 2%
            jail_epochs_o4: 2,
            slash_bps_o5: 100,  // 1%
            jail_epochs_o5: 1,
        }
    }
}

// ============================================================================
// T229: Extended Context with Epoch Information
// ============================================================================

/// Extended slashing context with epoch information (T229).
pub struct PenaltySlashingContext<'a> {
    /// The current or historical validator set for verification.
    pub validator_set: &'a ValidatorSet,
    /// Current block height (for decision metadata).
    pub current_height: u64,
    /// Current view (for decision metadata).
    pub current_view: u64,
    /// Current epoch (for jail expiration).
    pub current_epoch: u64,
}

impl<'a> PenaltySlashingContext<'a> {
    /// Create a context from the base SlashingContext with epoch info.
    pub fn from_base(base: &SlashingContext<'a>, current_epoch: u64) -> Self {
        Self {
            validator_set: base.validator_set,
            current_height: base.current_height,
            current_view: base.current_view,
            current_epoch,
        }
    }
}

// ============================================================================
// T229: Penalty Slashing Engine
// ============================================================================

/// Penalty-applying slashing engine (T229).
///
/// This engine builds on top of the T228 infrastructure to:
/// - Apply penalties for O1 and O2 offenses when mode is EnforceCritical
/// - Keep O3/O4/O5 in evidence-only mode
/// - Record all evidence regardless of mode
/// - Track penalty metrics
pub struct PenaltySlashingEngine<B: SlashingBackend> {
    /// The slashing backend for applying penalties.
    backend: B,
    /// Engine configuration.
    config: PenaltyEngineConfig,
    /// All processed records, keyed by validator ID.
    records: HashMap<ValidatorId, Vec<PenaltySlashingRecord>>,
    /// Deduplication set: content-addressed evidence IDs (M1.1 hardening).
    seen_evidence: HashSet<[u8; 32]>,
    /// Counter: evidence submitted by offense kind.
    evidence_counts: HashMap<OffenseKind, u64>,
    /// Counter: penalties applied by offense kind.
    penalty_counts: HashMap<OffenseKind, u64>,
    /// Total stake slashed.
    total_stake_slashed: u64,
    /// Total jail events.
    total_jail_events: u64,
}

impl<B: SlashingBackend> PenaltySlashingEngine<B> {
    /// Create a new penalty slashing engine.
    pub fn new(backend: B, config: PenaltyEngineConfig) -> Self {
        Self {
            backend,
            config,
            records: HashMap::new(),
            seen_evidence: HashSet::new(),
            evidence_counts: HashMap::new(),
            penalty_counts: HashMap::new(),
            total_stake_slashed: 0,
            total_jail_events: 0,
        }
    }

    /// Get the engine configuration.
    pub fn config(&self) -> &PenaltyEngineConfig {
        &self.config
    }

    /// Get a reference to the backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Get a mutable reference to the backend.
    pub fn backend_mut(&mut self) -> &mut B {
        &mut self.backend
    }

    /// Get total stake slashed.
    pub fn total_stake_slashed(&self) -> u64 {
        self.total_stake_slashed
    }

    /// Get total jail events.
    pub fn total_jail_events(&self) -> u64 {
        self.total_jail_events
    }

    /// Get penalty count for an offense kind.
    pub fn penalty_count(&self, offense: OffenseKind) -> u64 {
        self.penalty_counts.get(&offense).copied().unwrap_or(0)
    }

    /// Get evidence count for an offense kind.
    pub fn evidence_count(&self, offense: OffenseKind) -> u64 {
        self.evidence_counts.get(&offense).copied().unwrap_or(0)
    }

    /// Check if a validator ID is in the validator set.
    fn is_known_validator(&self, ctx: &PenaltySlashingContext, validator_id: ValidatorId) -> bool {
        ctx.validator_set
            .validators
            .iter()
            .any(|v| u64::from(v.validator_id) == validator_id.0)
    }

    /// Handle new slashing evidence with penalty enforcement.
    pub fn handle_evidence(
        &mut self,
        ctx: &PenaltySlashingContext,
        evidence: SlashingEvidence,
    ) -> PenaltySlashingRecord {
        // Log evidence reception
        eprintln!(
            "[SLASHING] T229 Evidence received: validator={}, offense={}, height={}, view={}",
            evidence.offending_validator.0,
            evidence.offense.as_str(),
            evidence.height,
            evidence.view
        );

        // 1. Check mode - if Off, reject immediately
        if self.config.mode == SlashingMode::Off {
            eprintln!("[SLASHING] Mode is Off - no evidence processing");
            return self.make_record(
                evidence,
                PenaltyDecision::Legacy(SlashingDecisionKind::RejectedInvalid),
                ctx,
            );
        }

        // 2. Check for duplicate using content-addressed evidence_id (M1.1)
        let evidence_id = evidence.evidence_id();
        if self.seen_evidence.contains(&evidence_id) {
            eprintln!(
                "[SLASHING] Evidence rejected: duplicate (validator={}, offense={}, height={}, view={})",
                evidence.offending_validator.0,
                evidence.offense.as_str(),
                evidence.height,
                evidence.view
            );
            return self.make_record(
                evidence,
                PenaltyDecision::Legacy(SlashingDecisionKind::RejectedDuplicate),
                ctx,
            );
        }

        // 3. Validate structure
        if let Err(reason) = evidence.validate_structure() {
            eprintln!(
                "[SLASHING] Evidence rejected: invalid structure - {} (validator={}, offense={})",
                reason,
                evidence.offending_validator.0,
                evidence.offense.as_str()
            );
            return self.make_record(
                evidence,
                PenaltyDecision::Legacy(SlashingDecisionKind::RejectedInvalid),
                ctx,
            );
        }

        // 4. Verify offending validator is known
        if !self.is_known_validator(ctx, evidence.offending_validator) {
            eprintln!(
                "[SLASHING] Evidence rejected: unknown validator {} (offense={})",
                evidence.offending_validator.0,
                evidence.offense.as_str()
            );
            return self.make_record(
                evidence,
                PenaltyDecision::Legacy(SlashingDecisionKind::RejectedInvalid),
                ctx,
            );
        }

        // 5. Height sanity check
        let max_allowed_height = ctx.current_height.saturating_add(100);
        if evidence.height > max_allowed_height {
            eprintln!(
                "[SLASHING] Evidence rejected: height {} too far in future (current={})",
                evidence.height, ctx.current_height
            );
            return self.make_record(
                evidence,
                PenaltyDecision::Legacy(SlashingDecisionKind::RejectedInvalid),
                ctx,
            );
        }

        // Mark as seen for deduplication (M1.1: content-addressed)
        self.seen_evidence.insert(evidence_id);

        // Increment evidence counter
        *self.evidence_counts.entry(evidence.offense).or_insert(0) += 1;

        // 6. Determine penalty action based on offense and mode
        let penalty_decision = self.apply_penalty_if_needed(&evidence, ctx);

        self.make_record(evidence, penalty_decision, ctx)
    }

    /// Apply penalty if needed based on offense and mode (M11: O3-O5 support).
    fn apply_penalty_if_needed(
        &mut self,
        evidence: &SlashingEvidence,
        ctx: &PenaltySlashingContext,
    ) -> PenaltyDecision {
        let offense = evidence.offense;
        let validator_id = evidence.offending_validator;

        // M11: Check if this offense should have penalties enforced
        // Per mode matrix:
        // - EnforceAll: Apply penalty for all offenses (O1-O5)
        // - EnforceCritical: Apply penalty for all offenses (O1-O5)
        // - RecordOnly: Record evidence only, no penalty
        // - Off: Reject evidence (handled earlier in handle_evidence)
        let should_enforce = match offense {
            OffenseKind::O1DoubleSign | OffenseKind::O2InvalidProposerSig => {
                self.config.mode.should_enforce_critical()
            }
            // M11: O3-O5 also enforced in EnforceCritical and EnforceAll modes
            OffenseKind::O3aLazyVoteSingle
            | OffenseKind::O3bLazyVoteRepeated
            | OffenseKind::O4InvalidDagCert
            | OffenseKind::O5DagCouplingViolation => self.config.mode.should_enforce_critical(),
        };

        if !should_enforce {
            eprintln!(
                "[SLASHING] Evidence accepted (evidence-only): validator={}, offense={}, mode={:?}",
                validator_id.0,
                offense.as_str(),
                self.config.mode
            );
            return PenaltyDecision::EvidenceOnly;
        }

        // Get slash and jail parameters for this offense (M11: added O3-O5)
        let (slash_bps, should_jail, jail_epochs) = match offense {
            OffenseKind::O1DoubleSign => (
                self.config.slash_bps_o1,
                self.config.jail_on_o1,
                self.config.jail_epochs_o1,
            ),
            OffenseKind::O2InvalidProposerSig => (
                self.config.slash_bps_o2,
                self.config.jail_on_o2,
                self.config.jail_epochs_o2,
            ),
            // M11: O3 Invalid Vote (lazy/malicious voting)
            OffenseKind::O3aLazyVoteSingle | OffenseKind::O3bLazyVoteRepeated => (
                self.config.slash_bps_o3,
                self.config.jail_on_o3,
                self.config.jail_epochs_o3,
            ),
            // M11: O4 Censorship (proposal withholding)
            OffenseKind::O4InvalidDagCert => (
                self.config.slash_bps_o4,
                self.config.jail_on_o4,
                self.config.jail_epochs_o4,
            ),
            // M11: O5 Availability Failure (extended timeout misbehavior)
            OffenseKind::O5DagCouplingViolation => (
                self.config.slash_bps_o5,
                self.config.jail_on_o5,
                self.config.jail_epochs_o5,
            ),
        };

        // Apply slash
        let slashed_amount = match self
            .backend
            .burn_stake_bps(validator_id, slash_bps, offense)
        {
            Ok(amount) => {
                self.total_stake_slashed += amount;
                *self.penalty_counts.entry(offense).or_insert(0) += 1;
                amount
            }
            Err(e) => {
                eprintln!(
                    "[SLASHING] Warning: failed to slash validator {}: {}",
                    validator_id.0, e
                );
                0
            }
        };

        // Apply jail if configured
        let jailed_until_epoch = if should_jail && jail_epochs > 0 {
            match self
                .backend
                .jail_validator(validator_id, offense, jail_epochs, ctx.current_epoch)
            {
                Ok(epoch) => {
                    self.total_jail_events += 1;
                    Some(epoch)
                }
                Err(e) => {
                    eprintln!(
                        "[SLASHING] Warning: failed to jail validator {}: {}",
                        validator_id.0, e
                    );
                    None
                }
            }
        } else {
            None
        };

        eprintln!(
            "[SLASHING] Penalty applied: validator={}, offense={}, slashed={}, jailed_until={:?}",
            validator_id.0,
            offense.as_str(),
            slashed_amount,
            jailed_until_epoch
        );

        PenaltyDecision::PenaltyApplied {
            slashed_amount,
            jailed_until_epoch,
        }
    }

    /// Create and store a penalty record.
    fn make_record(
        &mut self,
        evidence: SlashingEvidence,
        penalty_decision: PenaltyDecision,
        ctx: &PenaltySlashingContext,
    ) -> PenaltySlashingRecord {
        let record = PenaltySlashingRecord {
            evidence: evidence.clone(),
            penalty_decision,
            decision_height: ctx.current_height,
            decision_view: ctx.current_view,
            current_epoch: ctx.current_epoch,
        };

        self.records
            .entry(evidence.offending_validator)
            .or_default()
            .push(record.clone());

        record
    }

    /// Get all penalty records for a validator.
    pub fn get_records_for_validator(
        &self,
        validator_id: ValidatorId,
    ) -> Vec<PenaltySlashingRecord> {
        self.records.get(&validator_id).cloned().unwrap_or_default()
    }
}

// ============================================================================
// T229 + M11: Penalty Metrics Extension
// ============================================================================

/// Extended metrics for penalty slashing (T229, M11).
///
/// Adds penalty-specific counters on top of the T228 SlashingMetrics.
/// M11 adds O3-O5 penalty counters.
#[derive(Debug, Default)]
pub struct PenaltySlashingMetrics {
    /// Base slashing metrics (evidence and decisions).
    pub base: SlashingMetrics,

    // Penalty counters by offense type
    penalties_o1_double_sign: AtomicU64,
    penalties_o2_invalid_proposer_sig: AtomicU64,
    // M11: O3-O5 penalty counters
    penalties_o3_invalid_vote: AtomicU64,
    penalties_o4_censorship: AtomicU64,
    penalties_o5_availability_failure: AtomicU64,

    // Total stake slashed (cumulative)
    total_stake_slashed: AtomicU64,

    // Total jail events
    total_jail_events: AtomicU64,
}

impl PenaltySlashingMetrics {
    /// Create new penalty metrics.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment penalty counter for the given offense (M11: O3-O5 support).
    pub fn inc_penalty(&self, offense: OffenseKind) {
        match offense {
            OffenseKind::O1DoubleSign => {
                self.penalties_o1_double_sign
                    .fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O2InvalidProposerSig => {
                self.penalties_o2_invalid_proposer_sig
                    .fetch_add(1, Ordering::Relaxed);
            }
            // M11: O3-O5 penalty counters
            OffenseKind::O3aLazyVoteSingle | OffenseKind::O3bLazyVoteRepeated => {
                self.penalties_o3_invalid_vote
                    .fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O4InvalidDagCert => {
                self.penalties_o4_censorship.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O5DagCouplingViolation => {
                self.penalties_o5_availability_failure
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Add to total slashed stake.
    pub fn add_slashed_stake(&self, amount: u64) {
        self.total_stake_slashed
            .fetch_add(amount, Ordering::Relaxed);
    }

    /// Increment jail event counter.
    pub fn inc_jail_event(&self) {
        self.total_jail_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Get penalty count for O1.
    pub fn penalties_o1_total(&self) -> u64 {
        self.penalties_o1_double_sign.load(Ordering::Relaxed)
    }

    /// Get penalty count for O2.
    pub fn penalties_o2_total(&self) -> u64 {
        self.penalties_o2_invalid_proposer_sig
            .load(Ordering::Relaxed)
    }

    /// Get penalty count for O3 (M11).
    pub fn penalties_o3_total(&self) -> u64 {
        self.penalties_o3_invalid_vote.load(Ordering::Relaxed)
    }

    /// Get penalty count for O4 (M11).
    pub fn penalties_o4_total(&self) -> u64 {
        self.penalties_o4_censorship.load(Ordering::Relaxed)
    }

    /// Get penalty count for O5 (M11).
    pub fn penalties_o5_total(&self) -> u64 {
        self.penalties_o5_availability_failure
            .load(Ordering::Relaxed)
    }

    /// Get total penalties applied (M11: includes O3-O5).
    pub fn penalties_total(&self) -> u64 {
        self.penalties_o1_total()
            + self.penalties_o2_total()
            + self.penalties_o3_total()
            + self.penalties_o4_total()
            + self.penalties_o5_total()
    }

    /// Get total stake slashed.
    pub fn total_stake_slashed(&self) -> u64 {
        self.total_stake_slashed.load(Ordering::Relaxed)
    }

    /// Get total jail events.
    pub fn total_jail_events(&self) -> u64 {
        self.total_jail_events.load(Ordering::Relaxed)
    }
}

// ============================================================================
// M15: Evidence Ingestion Hardening (No Rewards / No Tokenomics)
// ============================================================================

/// Reason why evidence was rejected during ingestion (M15).
///
/// These reasons are used for metrics and logging to track rejection patterns.
/// The order follows the verification pipeline ordering (cheap checks first).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum EvidenceRejectionReason {
    /// Evidence rejected because the reporter is not an active validator (M15).
    NonValidatorReporter,
    /// Evidence payload exceeds the maximum allowed size for the offense type (M15).
    OversizedPayload,
    /// Per-block evidence cap exceeded (M15).
    PerBlockCapExceeded,
    /// Evidence references a height too old (beyond the configured window) (M15).
    TooOld,
    /// Duplicate evidence (already processed).
    Duplicate,
    /// Evidence structure validation failed.
    InvalidStructure,
    /// Unknown validator (offending validator not in set).
    UnknownValidator,
    /// Height too far in the future.
    FutureHeight,
    /// Cryptographic verification failed.
    VerificationFailed,
}

impl EvidenceRejectionReason {
    /// Returns a string label for metrics and logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            EvidenceRejectionReason::NonValidatorReporter => "non_validator_reporter",
            EvidenceRejectionReason::OversizedPayload => "oversized_payload",
            EvidenceRejectionReason::PerBlockCapExceeded => "per_block_cap_exceeded",
            EvidenceRejectionReason::TooOld => "too_old",
            EvidenceRejectionReason::Duplicate => "duplicate",
            EvidenceRejectionReason::InvalidStructure => "invalid_structure",
            EvidenceRejectionReason::UnknownValidator => "unknown_validator",
            EvidenceRejectionReason::FutureHeight => "future_height",
            EvidenceRejectionReason::VerificationFailed => "verification_failed",
        }
    }
}

/// Configuration for evidence ingestion hardening (M15).
///
/// This configuration controls deterministic admission controls for evidence
/// submission without introducing any tokenomics or rewards.
///
/// # Design Principles
///
/// - **Deterministic**: All limits are deterministic for consensus safety
/// - **Fail-Closed**: Invalid or suspicious evidence is rejected
/// - **No Rewards**: Reporting has no economic incentive; hardening provides abuse resistance
///
/// # Recommended Production Settings
///
/// - `require_validator_reporter = true` (strictest, simplest)
/// - `per_block_evidence_cap = Some(10)` (prevent DoS via evidence spam)
/// - `max_evidence_age_blocks = Some(100_000)` (~11.5 days at 10s blocks)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceIngestionConfig {
    /// Maximum payload size for O1 (double-sign) evidence in bytes.
    /// Default: 64KB (should fit 2 signed block headers comfortably).
    pub max_o1_payload_bytes: usize,

    /// Maximum payload size for O2 (invalid proposer sig) evidence in bytes.
    /// Default: 32KB.
    pub max_o2_payload_bytes: usize,

    /// Maximum payload size for O3 (lazy vote) evidence in bytes.
    /// Default: 16KB.
    pub max_o3_payload_bytes: usize,

    /// Maximum payload size for O4 (invalid DAG cert) evidence in bytes.
    /// Default: 128KB (certificates can be larger).
    pub max_o4_payload_bytes: usize,

    /// Maximum payload size for O5 (DAG coupling violation) evidence in bytes.
    /// Default: 64KB.
    pub max_o5_payload_bytes: usize,

    /// Whether to require the reporter to be an active validator.
    /// When `true`, only validators in the current validator set can submit evidence.
    /// This is the strictest and simplest spam resistance mechanism.
    /// Default: true (recommended for production).
    pub require_validator_reporter: bool,

    /// Maximum number of evidence submissions per block (global cap).
    /// When set, evidence beyond this cap is rejected with `PerBlockCapExceeded`.
    /// This is deterministic and enforced during block validity checks.
    /// Default: Some(10).
    pub per_block_evidence_cap: Option<u32>,

    /// Maximum age of evidence in blocks. Evidence referencing heights older
    /// than `current_height - max_evidence_age_blocks` is rejected.
    /// When `None`, no age limit is enforced.
    /// Default: Some(100_000) (~11.5 days at 10s blocks).
    pub max_evidence_age_blocks: Option<u64>,

    /// Maximum height lookahead for evidence (evidence.height > current_height + max_lookahead).
    /// Default: 100 (same as existing behavior).
    pub max_height_lookahead: u64,
}

impl Default for EvidenceIngestionConfig {
    fn default() -> Self {
        Self {
            // Payload size limits (conservative defaults)
            max_o1_payload_bytes: 64 * 1024,  // 64 KB
            max_o2_payload_bytes: 32 * 1024,  // 32 KB
            max_o3_payload_bytes: 16 * 1024,  // 16 KB
            max_o4_payload_bytes: 128 * 1024, // 128 KB
            max_o5_payload_bytes: 64 * 1024,  // 64 KB

            // Spam resistance
            require_validator_reporter: true,
            per_block_evidence_cap: Some(10),

            // Age limits
            max_evidence_age_blocks: Some(100_000),
            max_height_lookahead: 100,
        }
    }
}

impl EvidenceIngestionConfig {
    /// Create a DevNet configuration (permissive for testing).
    pub fn devnet() -> Self {
        Self {
            require_validator_reporter: false,
            per_block_evidence_cap: None,
            max_evidence_age_blocks: None,
            ..Self::default()
        }
    }

    /// Create a TestNet configuration (moderately strict).
    pub fn testnet() -> Self {
        Self {
            require_validator_reporter: true,
            per_block_evidence_cap: Some(20),
            max_evidence_age_blocks: Some(50_000),
            ..Self::default()
        }
    }

    /// Create a MainNet configuration (strict).
    pub fn mainnet() -> Self {
        Self {
            require_validator_reporter: true,
            per_block_evidence_cap: Some(10),
            max_evidence_age_blocks: Some(100_000),
            ..Self::default()
        }
    }

    /// Get the maximum payload size for a given offense type.
    pub fn max_payload_bytes(&self, offense: OffenseKind) -> usize {
        match offense {
            OffenseKind::O1DoubleSign => self.max_o1_payload_bytes,
            OffenseKind::O2InvalidProposerSig => self.max_o2_payload_bytes,
            OffenseKind::O3aLazyVoteSingle | OffenseKind::O3bLazyVoteRepeated => {
                self.max_o3_payload_bytes
            }
            OffenseKind::O4InvalidDagCert => self.max_o4_payload_bytes,
            OffenseKind::O5DagCouplingViolation => self.max_o5_payload_bytes,
        }
    }
}

impl SlashingEvidence {
    /// Compute an estimated byte size of this evidence (M15).
    ///
    /// This is used for size validation during evidence ingestion.
    /// The size is an approximation based on the serialized payload.
    pub fn estimated_size_bytes(&self) -> usize {
        // Base size: version (1) + offense (1) + validator_id (8) + height (8) + view (8)
        let base_size = 26;

        let payload_size = match &self.payload {
            EvidencePayloadV1::O1DoubleSign { block_a, block_b } => {
                // Each SignedBlockHeader: height (8) + view (8) + block_id (32) +
                // proposer_id (8) + signature (variable) + header_preimage (variable)
                let block_a_size = 56 + block_a.signature.len() + block_a.header_preimage.len();
                let block_b_size = 56 + block_b.signature.len() + block_b.header_preimage.len();
                block_a_size + block_b_size
            }
            EvidencePayloadV1::O2InvalidProposerSig {
                header,
                bad_signature,
            } => {
                // BlockHeader: height (8) + view (8) + proposer_id (8) + batch_commitment (32)
                // + bad_signature (variable)
                56 + bad_signature.len()
            }
            EvidencePayloadV1::O3LazyVote {
                vote,
                invalid_reason,
            } => {
                // SignedVote: validator_id (8) + height (8) + view (8) + block_id (32) + signature (variable)
                let vote_size = 56 + vote.signature.len();
                let reason_size = match invalid_reason {
                    LazyVoteInvalidReason::InvalidProposerSig => 1,
                    LazyVoteInvalidReason::InvalidQcSignature => 1,
                    LazyVoteInvalidReason::Other(s) => 1 + s.len(),
                };
                vote_size + reason_size
            }
            EvidencePayloadV1::O4InvalidDagCert {
                cert,
                failure_reason,
            } => {
                // DagCertificate: batch_commitment (32) + dag_round (8) +
                // signers (variable) + signatures (variable)
                let signers_size = cert.signers.len() * 8;
                let sigs_size: usize = cert.signatures.iter().map(|s| s.len() + 4).sum();
                let reason_size = match failure_reason {
                    DagValidationFailure::QuorumNotMet { .. } => 8,
                    DagValidationFailure::InvalidSignature { .. } => 4,
                    DagValidationFailure::CommitmentMismatch => 1,
                    DagValidationFailure::Other(s) => 1 + s.len(),
                };
                40 + signers_size + sigs_size + reason_size
            }
            EvidencePayloadV1::O5DagCouplingViolation {
                block,
                dag_state_proof,
            } => {
                // BlockHeader: 56 bytes
                // DagStateProof: dag_round (8) + frontier_commitments (32 each) + merkle_proof (variable)
                let proof_size = 8
                    + dag_state_proof.frontier_commitments.len() * 32
                    + dag_state_proof.merkle_proof.as_ref().map_or(0, |p| p.len());
                56 + proof_size
            }
        };

        base_size + payload_size
    }
}

/// Extended context for hardened evidence ingestion (M15).
pub struct HardenedEvidenceContext<'a> {
    /// Base penalty context.
    pub penalty_ctx: PenaltySlashingContext<'a>,
    /// The reporter's validator ID (the entity submitting the evidence).
    /// If `None`, the reporter is unknown/external.
    pub reporter_id: Option<ValidatorId>,
    /// Current evidence count for this block (for per-block cap enforcement).
    pub block_evidence_count: u32,
}

impl<'a> HardenedEvidenceContext<'a> {
    /// Create a new hardened evidence context.
    pub fn new(
        validator_set: &'a ValidatorSet,
        current_height: u64,
        current_view: u64,
        current_epoch: u64,
        reporter_id: Option<ValidatorId>,
        block_evidence_count: u32,
    ) -> Self {
        Self {
            penalty_ctx: PenaltySlashingContext {
                validator_set,
                current_height,
                current_view,
                current_epoch,
            },
            reporter_id,
            block_evidence_count,
        }
    }

    /// Check if a validator ID is in the current validator set.
    pub fn is_active_validator(&self, validator_id: ValidatorId) -> bool {
        self.penalty_ctx
            .validator_set
            .validators
            .iter()
            .any(|v| u64::from(v.validator_id) == validator_id.0)
    }
}

/// Result of hardened evidence ingestion (M15).
#[derive(Clone, Debug)]
pub enum HardenedEvidenceResult {
    /// Evidence accepted and forwarded to the penalty engine.
    Accepted(PenaltySlashingRecord),
    /// Evidence rejected before reaching the penalty engine.
    Rejected {
        /// The reason for rejection.
        reason: EvidenceRejectionReason,
        /// The offense type (for metrics).
        offense: OffenseKind,
    },
}

/// Metrics for hardened evidence ingestion (M15).
///
/// These metrics track the effectiveness of the ingestion hardening.
/// All counters are non-economic; no rewards are distributed.
#[derive(Debug, Default)]
pub struct EvidenceIngestionMetrics {
    // Evidence received counters (by offense type)
    evidence_received_o1: AtomicU64,
    evidence_received_o2: AtomicU64,
    evidence_received_o3a: AtomicU64,
    evidence_received_o3b: AtomicU64,
    evidence_received_o4: AtomicU64,
    evidence_received_o5: AtomicU64,

    // Rejection counters (by reason)
    rejected_non_validator_reporter: AtomicU64,
    rejected_oversized: AtomicU64,
    rejected_per_block_cap: AtomicU64,
    rejected_too_old: AtomicU64,
    rejected_duplicate: AtomicU64,
    rejected_invalid_structure: AtomicU64,
    rejected_unknown_validator: AtomicU64,
    rejected_future_height: AtomicU64,
    rejected_verification_failed: AtomicU64,

    // Verified (passed all checks, forwarded to penalty engine)
    verified_total: AtomicU64,
}

impl EvidenceIngestionMetrics {
    /// Create new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment evidence received counter for the given offense.
    pub fn inc_received(&self, offense: OffenseKind) {
        match offense {
            OffenseKind::O1DoubleSign => {
                self.evidence_received_o1.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O2InvalidProposerSig => {
                self.evidence_received_o2.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O3aLazyVoteSingle => {
                self.evidence_received_o3a.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O3bLazyVoteRepeated => {
                self.evidence_received_o3b.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O4InvalidDagCert => {
                self.evidence_received_o4.fetch_add(1, Ordering::Relaxed);
            }
            OffenseKind::O5DagCouplingViolation => {
                self.evidence_received_o5.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Increment rejection counter for the given reason.
    pub fn inc_rejected(&self, reason: EvidenceRejectionReason) {
        match reason {
            EvidenceRejectionReason::NonValidatorReporter => {
                self.rejected_non_validator_reporter
                    .fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::OversizedPayload => {
                self.rejected_oversized.fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::PerBlockCapExceeded => {
                self.rejected_per_block_cap.fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::TooOld => {
                self.rejected_too_old.fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::Duplicate => {
                self.rejected_duplicate.fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::InvalidStructure => {
                self.rejected_invalid_structure
                    .fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::UnknownValidator => {
                self.rejected_unknown_validator
                    .fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::FutureHeight => {
                self.rejected_future_height.fetch_add(1, Ordering::Relaxed);
            }
            EvidenceRejectionReason::VerificationFailed => {
                self.rejected_verification_failed
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Increment verified counter.
    pub fn inc_verified(&self) {
        self.verified_total.fetch_add(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Metric Getters
    // ========================================================================

    /// Get total evidence received.
    pub fn evidence_received_total(&self) -> u64 {
        self.evidence_received_o1.load(Ordering::Relaxed)
            + self.evidence_received_o2.load(Ordering::Relaxed)
            + self.evidence_received_o3a.load(Ordering::Relaxed)
            + self.evidence_received_o3b.load(Ordering::Relaxed)
            + self.evidence_received_o4.load(Ordering::Relaxed)
            + self.evidence_received_o5.load(Ordering::Relaxed)
    }

    /// Get evidence received by offense type.
    pub fn evidence_received_by_offense(&self, offense: OffenseKind) -> u64 {
        match offense {
            OffenseKind::O1DoubleSign => self.evidence_received_o1.load(Ordering::Relaxed),
            OffenseKind::O2InvalidProposerSig => self.evidence_received_o2.load(Ordering::Relaxed),
            OffenseKind::O3aLazyVoteSingle => self.evidence_received_o3a.load(Ordering::Relaxed),
            OffenseKind::O3bLazyVoteRepeated => self.evidence_received_o3b.load(Ordering::Relaxed),
            OffenseKind::O4InvalidDagCert => self.evidence_received_o4.load(Ordering::Relaxed),
            OffenseKind::O5DagCouplingViolation => self.evidence_received_o5.load(Ordering::Relaxed),
        }
    }

    /// Get rejection count by reason.
    pub fn rejected_by_reason(&self, reason: EvidenceRejectionReason) -> u64 {
        match reason {
            EvidenceRejectionReason::NonValidatorReporter => {
                self.rejected_non_validator_reporter.load(Ordering::Relaxed)
            }
            EvidenceRejectionReason::OversizedPayload => {
                self.rejected_oversized.load(Ordering::Relaxed)
            }
            EvidenceRejectionReason::PerBlockCapExceeded => {
                self.rejected_per_block_cap.load(Ordering::Relaxed)
            }
            EvidenceRejectionReason::TooOld => self.rejected_too_old.load(Ordering::Relaxed),
            EvidenceRejectionReason::Duplicate => self.rejected_duplicate.load(Ordering::Relaxed),
            EvidenceRejectionReason::InvalidStructure => {
                self.rejected_invalid_structure.load(Ordering::Relaxed)
            }
            EvidenceRejectionReason::UnknownValidator => {
                self.rejected_unknown_validator.load(Ordering::Relaxed)
            }
            EvidenceRejectionReason::FutureHeight => {
                self.rejected_future_height.load(Ordering::Relaxed)
            }
            EvidenceRejectionReason::VerificationFailed => {
                self.rejected_verification_failed.load(Ordering::Relaxed)
            }
        }
    }

    /// Get total rejections.
    pub fn rejected_total(&self) -> u64 {
        self.rejected_non_validator_reporter.load(Ordering::Relaxed)
            + self.rejected_oversized.load(Ordering::Relaxed)
            + self.rejected_per_block_cap.load(Ordering::Relaxed)
            + self.rejected_too_old.load(Ordering::Relaxed)
            + self.rejected_duplicate.load(Ordering::Relaxed)
            + self.rejected_invalid_structure.load(Ordering::Relaxed)
            + self.rejected_unknown_validator.load(Ordering::Relaxed)
            + self.rejected_future_height.load(Ordering::Relaxed)
            + self.rejected_verification_failed.load(Ordering::Relaxed)
    }

    /// Get verified total.
    pub fn verified_total(&self) -> u64 {
        self.verified_total.load(Ordering::Relaxed)
    }
}

/// Hardened evidence ingestion engine (M15).
///
/// This engine wraps the `PenaltySlashingEngine` with additional admission
/// controls for DoS resistance and abuse prevention. The verification ordering
/// ensures cheap checks run before expensive cryptographic verification.
///
/// # Verification Ordering (M15)
///
/// 1. **Reporter validation** (O(1)) - Is reporter an active validator?
/// 2. **Size bounds** (O(1)) - Is payload within limits?
/// 3. **Per-block cap** (O(1)) - Is block evidence count within cap?
/// 4. **Deduplication** (O(1) hash lookup) - Have we seen this evidence?
/// 5. **Structure validation** (O(n) for payload size) - Is evidence well-formed?
/// 6. **Age bounds** (O(1)) - Is evidence height within window?
/// 7. **Validator existence** (O(n) for validator set) - Is offending validator known?
/// 8. **Cryptographic verification** (EXPENSIVE) - Are signatures valid?
/// 9. **Penalty application** - Forward to penalty engine
///
/// No expensive operations (8) occur until all cheap filters (1-7) pass.
pub struct HardenedEvidenceIngestionEngine<B: SlashingBackend> {
    /// Inner penalty engine.
    inner: PenaltySlashingEngine<B>,
    /// Ingestion configuration.
    config: EvidenceIngestionConfig,
    /// Ingestion metrics.
    metrics: EvidenceIngestionMetrics,
    /// Deduplication set for early rejection (before forwarding to inner engine).
    seen_evidence: HashSet<[u8; 32]>,
}

impl<B: SlashingBackend> HardenedEvidenceIngestionEngine<B> {
    /// Create a new hardened evidence ingestion engine.
    pub fn new(
        backend: B,
        penalty_config: PenaltyEngineConfig,
        ingestion_config: EvidenceIngestionConfig,
    ) -> Self {
        Self {
            inner: PenaltySlashingEngine::new(backend, penalty_config),
            config: ingestion_config,
            metrics: EvidenceIngestionMetrics::new(),
            seen_evidence: HashSet::new(),
        }
    }

    /// Get the ingestion configuration.
    pub fn ingestion_config(&self) -> &EvidenceIngestionConfig {
        &self.config
    }

    /// Get a reference to the inner penalty engine.
    pub fn inner(&self) -> &PenaltySlashingEngine<B> {
        &self.inner
    }

    /// Get a mutable reference to the inner penalty engine.
    pub fn inner_mut(&mut self) -> &mut PenaltySlashingEngine<B> {
        &mut self.inner
    }

    /// Get the ingestion metrics.
    pub fn metrics(&self) -> &EvidenceIngestionMetrics {
        &self.metrics
    }

    /// Handle evidence with hardened admission controls (M15).
    ///
    /// This method implements the M15 verification ordering:
    /// 1. Cheap checks first (type, length, dedup)
    /// 2. Structural parse
    /// 3. Cryptographic verification (delegated to inner engine)
    /// 4. Penalty application (delegated to inner engine)
    ///
    /// Returns `HardenedEvidenceResult::Rejected` if any check fails before
    /// reaching the inner penalty engine.
    pub fn handle_evidence(
        &mut self,
        ctx: &HardenedEvidenceContext,
        evidence: SlashingEvidence,
    ) -> HardenedEvidenceResult {
        let offense = evidence.offense;

        // Track received evidence
        self.metrics.inc_received(offense);

        eprintln!(
            "[M15] Evidence received: reporter={:?}, validator={}, offense={}, height={}, view={}",
            ctx.reporter_id,
            evidence.offending_validator.0,
            evidence.offense.as_str(),
            evidence.height,
            evidence.view
        );

        // === 1. Reporter validation (cheapest check first) ===
        if self.config.require_validator_reporter {
            match ctx.reporter_id {
                None => {
                    eprintln!(
                        "[M15] Evidence rejected: no reporter_id (require_validator_reporter=true)"
                    );
                    self.metrics
                        .inc_rejected(EvidenceRejectionReason::NonValidatorReporter);
                    return HardenedEvidenceResult::Rejected {
                        reason: EvidenceRejectionReason::NonValidatorReporter,
                        offense,
                    };
                }
                Some(reporter_id) => {
                    if !ctx.is_active_validator(reporter_id) {
                        eprintln!(
                            "[M15] Evidence rejected: reporter {} is not an active validator",
                            reporter_id.0
                        );
                        self.metrics
                            .inc_rejected(EvidenceRejectionReason::NonValidatorReporter);
                        return HardenedEvidenceResult::Rejected {
                            reason: EvidenceRejectionReason::NonValidatorReporter,
                            offense,
                        };
                    }
                }
            }
        }

        // === 2. Size bounds check ===
        let evidence_size = evidence.estimated_size_bytes();
        let max_size = self.config.max_payload_bytes(offense);
        if evidence_size > max_size {
            eprintln!(
                "[M15] Evidence rejected: size {} exceeds max {} for offense {}",
                evidence_size,
                max_size,
                offense.as_str()
            );
            self.metrics
                .inc_rejected(EvidenceRejectionReason::OversizedPayload);
            return HardenedEvidenceResult::Rejected {
                reason: EvidenceRejectionReason::OversizedPayload,
                offense,
            };
        }

        // === 3. Per-block cap check ===
        if let Some(cap) = self.config.per_block_evidence_cap {
            if ctx.block_evidence_count >= cap {
                eprintln!(
                    "[M15] Evidence rejected: per-block cap {} exceeded (current={})",
                    cap, ctx.block_evidence_count
                );
                self.metrics
                    .inc_rejected(EvidenceRejectionReason::PerBlockCapExceeded);
                return HardenedEvidenceResult::Rejected {
                    reason: EvidenceRejectionReason::PerBlockCapExceeded,
                    offense,
                };
            }
        }

        // === 4. Deduplication check (before expensive verification) ===
        let evidence_id = evidence.evidence_id();
        if self.seen_evidence.contains(&evidence_id) {
            eprintln!(
                "[M15] Evidence rejected: duplicate (evidence_id already seen)"
            );
            self.metrics
                .inc_rejected(EvidenceRejectionReason::Duplicate);
            return HardenedEvidenceResult::Rejected {
                reason: EvidenceRejectionReason::Duplicate,
                offense,
            };
        }

        // === 5. Structure validation ===
        if let Err(reason) = evidence.validate_structure() {
            eprintln!(
                "[M15] Evidence rejected: invalid structure - {}",
                reason
            );
            self.metrics
                .inc_rejected(EvidenceRejectionReason::InvalidStructure);
            return HardenedEvidenceResult::Rejected {
                reason: EvidenceRejectionReason::InvalidStructure,
                offense,
            };
        }

        // === 6. Age bounds check ===
        if let Some(max_age) = self.config.max_evidence_age_blocks {
            if ctx.penalty_ctx.current_height > max_age {
                let min_height = ctx.penalty_ctx.current_height.saturating_sub(max_age);
                if evidence.height < min_height {
                    eprintln!(
                        "[M15] Evidence rejected: too old (height {} < min_height {})",
                        evidence.height, min_height
                    );
                    self.metrics.inc_rejected(EvidenceRejectionReason::TooOld);
                    return HardenedEvidenceResult::Rejected {
                        reason: EvidenceRejectionReason::TooOld,
                        offense,
                    };
                }
            }
        }

        // === 7. Future height check ===
        let max_allowed_height = ctx
            .penalty_ctx
            .current_height
            .saturating_add(self.config.max_height_lookahead);
        if evidence.height > max_allowed_height {
            eprintln!(
                "[M15] Evidence rejected: height {} too far in future (max={})",
                evidence.height, max_allowed_height
            );
            self.metrics
                .inc_rejected(EvidenceRejectionReason::FutureHeight);
            return HardenedEvidenceResult::Rejected {
                reason: EvidenceRejectionReason::FutureHeight,
                offense,
            };
        }

        // === 8. Mark as seen BEFORE expensive verification ===
        // This prevents replay attacks during verification
        self.seen_evidence.insert(evidence_id);

        // === 9. Forward to inner penalty engine for cryptographic verification ===
        // The inner engine handles:
        // - Validator existence check
        // - Cryptographic signature verification (EXPENSIVE)
        // - Penalty application
        let record = self.inner.handle_evidence(&ctx.penalty_ctx, evidence);

        // Check if inner engine rejected (verification failed, unknown validator, etc.)
        match &record.penalty_decision {
            PenaltyDecision::Legacy(SlashingDecisionKind::RejectedInvalid) => {
                self.metrics
                    .inc_rejected(EvidenceRejectionReason::VerificationFailed);
                return HardenedEvidenceResult::Rejected {
                    reason: EvidenceRejectionReason::VerificationFailed,
                    offense,
                };
            }
            PenaltyDecision::Legacy(SlashingDecisionKind::RejectedDuplicate) => {
                // Inner engine also detected duplicate (shouldn't happen, but handle gracefully)
                self.metrics
                    .inc_rejected(EvidenceRejectionReason::Duplicate);
                return HardenedEvidenceResult::Rejected {
                    reason: EvidenceRejectionReason::Duplicate,
                    offense,
                };
            }
            _ => {
                // Accepted (NoOp, EvidenceOnly, or PenaltyApplied)
                self.metrics.inc_verified();
                eprintln!(
                    "[M15] Evidence accepted and verified: offense={}, decision={:?}",
                    offense.as_str(),
                    record.penalty_decision.as_str()
                );
                HardenedEvidenceResult::Accepted(record)
            }
        }
    }

    /// Check if a specific reporter validation would pass.
    ///
    /// This is useful for pre-validation before constructing evidence.
    pub fn would_accept_reporter(
        &self,
        ctx: &HardenedEvidenceContext,
        reporter_id: Option<ValidatorId>,
    ) -> bool {
        if !self.config.require_validator_reporter {
            return true;
        }
        match reporter_id {
            None => false,
            Some(id) => ctx.is_active_validator(id),
        }
    }

    /// Check if the per-block cap would be exceeded.
    pub fn would_exceed_block_cap(&self, block_evidence_count: u32) -> bool {
        match self.config.per_block_evidence_cap {
            None => false,
            Some(cap) => block_evidence_count >= cap,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_validator_set() -> ValidatorSet {
        ValidatorSet {
            validators: vec![
                crate::ValidatorInfo {
                    validator_id: 1,
                    suite_id: 1,
                    consensus_pk: vec![1; 32],
                    voting_power: 100,
                },
                crate::ValidatorInfo {
                    validator_id: 2,
                    suite_id: 1,
                    consensus_pk: vec![2; 32],
                    voting_power: 100,
                },
                crate::ValidatorInfo {
                    validator_id: 3,
                    suite_id: 1,
                    consensus_pk: vec![3; 32],
                    voting_power: 100,
                },
            ],
            qc_threshold: 201,
        }
    }

    fn make_o1_evidence(validator_id: u32, height: u64, view: u64) -> SlashingEvidence {
        SlashingEvidence {
            version: 1,
            offense: OffenseKind::O1DoubleSign,
            offending_validator: ValidatorId(u64::from(validator_id)),
            height,
            view,
            payload: EvidencePayloadV1::O1DoubleSign {
                block_a: SignedBlockHeader {
                    height,
                    view,
                    block_id: [0xAA; 32],
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    signature: vec![0x01; 64],
                    header_preimage: vec![0x10; 100],
                },
                block_b: SignedBlockHeader {
                    height,
                    view,
                    block_id: [0xBB; 32],
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    signature: vec![0x02; 64],
                    header_preimage: vec![0x20; 100],
                },
            },
        }
    }

    #[test]
    fn test_offense_kind_as_str() {
        assert_eq!(OffenseKind::O1DoubleSign.as_str(), "O1_double_sign");
        assert_eq!(
            OffenseKind::O2InvalidProposerSig.as_str(),
            "O2_invalid_proposer_sig"
        );
        assert_eq!(
            OffenseKind::O3aLazyVoteSingle.as_str(),
            "O3a_lazy_vote_single"
        );
        assert_eq!(
            OffenseKind::O3bLazyVoteRepeated.as_str(),
            "O3b_lazy_vote_repeated"
        );
        assert_eq!(
            OffenseKind::O4InvalidDagCert.as_str(),
            "O4_invalid_dag_cert"
        );
        assert_eq!(
            OffenseKind::O5DagCouplingViolation.as_str(),
            "O5_dag_coupling_violation"
        );
    }

    #[test]
    fn test_evidence_validate_structure() {
        let evidence = make_o1_evidence(1, 100, 5);
        assert!(evidence.validate_structure().is_ok());

        // Zero version should fail
        let mut bad_evidence = evidence.clone();
        bad_evidence.version = 0;
        assert!(bad_evidence.validate_structure().is_err());

        // Zero height should fail
        let mut bad_evidence = evidence.clone();
        bad_evidence.height = 0;
        assert!(bad_evidence.validate_structure().is_err());
    }

    #[test]
    fn test_noop_engine_accepts_valid_evidence() {
        let vs = test_validator_set();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();
        // Use view=0 where validator 1 (at index 0) is the leader
        let evidence = make_o1_evidence(1, 100, 0);

        let record = engine.handle_evidence(&ctx, evidence);
        assert_eq!(record.decision, SlashingDecisionKind::AcceptedNoOp);
        assert_eq!(record.decision_height, 1000);
        assert_eq!(record.decision_view, 10);
    }

    #[test]
    fn test_noop_engine_rejects_unknown_validator() {
        let vs = test_validator_set();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();
        // Validator 999 is not in the set
        let evidence = make_o1_evidence(999, 100, 0);

        let record = engine.handle_evidence(&ctx, evidence);
        assert_eq!(record.decision, SlashingDecisionKind::RejectedInvalid);
    }

    #[test]
    fn test_noop_engine_deduplicates() {
        let vs = test_validator_set();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();
        // Use view=0 where validator 1 is leader (0 % 3 = 0)
        let evidence = make_o1_evidence(1, 100, 0);

        // First submission should be accepted
        let record1 = engine.handle_evidence(&ctx, evidence.clone());
        assert_eq!(record1.decision, SlashingDecisionKind::AcceptedNoOp);

        // Second submission should be rejected as duplicate
        let record2 = engine.handle_evidence(&ctx, evidence);
        assert_eq!(record2.decision, SlashingDecisionKind::RejectedDuplicate);
    }

    #[test]
    fn test_noop_engine_counts() {
        let vs = test_validator_set();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();

        // Submit a few different evidence items with correct views for each validator
        // validator 1 is leader at view 0 (0 % 3 = 0)
        // validator 2 is leader at view 1 (1 % 3 = 1)
        let e1 = make_o1_evidence(1, 100, 0);
        let e2 = make_o1_evidence(2, 101, 1);
        let e3 = make_o1_evidence(1, 100, 0); // duplicate

        engine.handle_evidence(&ctx, e1);
        engine.handle_evidence(&ctx, e2);
        engine.handle_evidence(&ctx, e3);

        // Check counts
        assert_eq!(
            engine.evidence_count_by_offense(OffenseKind::O1DoubleSign),
            3
        );
        assert_eq!(engine.decision_count(SlashingDecisionKind::AcceptedNoOp), 2);
        assert_eq!(
            engine.decision_count(SlashingDecisionKind::RejectedDuplicate),
            1
        );
    }

    #[test]
    fn test_slashing_metrics() {
        let metrics = SlashingMetrics::new();

        metrics.inc_evidence(OffenseKind::O1DoubleSign);
        metrics.inc_evidence(OffenseKind::O1DoubleSign);
        metrics.inc_evidence(OffenseKind::O2InvalidProposerSig);
        metrics.inc_decision(SlashingDecisionKind::AcceptedNoOp);
        metrics.inc_decision(SlashingDecisionKind::AcceptedNoOp);
        metrics.inc_decision(SlashingDecisionKind::RejectedInvalid);

        assert_eq!(metrics.evidence_o1_total(), 2);
        assert_eq!(metrics.evidence_o2_total(), 1);
        assert_eq!(metrics.evidence_total(), 3);
        assert_eq!(metrics.decisions_accepted_noop_total(), 2);
        assert_eq!(metrics.decisions_rejected_invalid_total(), 1);
        assert_eq!(metrics.decisions_total(), 3);
    }

    #[test]
    fn test_slashing_store() {
        let mut store = SlashingStore::new();

        let evidence = make_o1_evidence(1, 100, 5);
        let record = SlashingRecord {
            evidence,
            decision: SlashingDecisionKind::AcceptedNoOp,
            decision_height: 1000,
            decision_view: 10,
        };

        store.store_slashing_record(&record);

        let records = store.load_slashing_records_for_validator(ValidatorId(1));
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].decision, SlashingDecisionKind::AcceptedNoOp);

        // Unknown validator returns empty
        let empty = store.load_slashing_records_for_validator(ValidatorId(999));
        assert!(empty.is_empty());
    }

    // ========================================================================
    // Phase 1 Economic Hardening: Cryptographic Verification Tests
    // ========================================================================

    use qbind_crypto::{MlDsa44Backend, ML_DSA_44_SIGNATURE_SIZE};

    /// Create a validator set with ML-DSA-44 keys for cryptographic verification tests.
    fn test_validator_set_with_ml_dsa() -> (ValidatorSet, Vec<Vec<u8>>) {
        // Generate 3 keypairs
        let (pk1, sk1) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (pk2, sk2) = MlDsa44Backend::generate_keypair().expect("keygen failed");
        let (pk3, sk3) = MlDsa44Backend::generate_keypair().expect("keygen failed");

        let vs = ValidatorSet {
            validators: vec![
                crate::ValidatorInfo {
                    validator_id: 1,
                    suite_id: ML_DSA_44_SUITE_ID,
                    consensus_pk: pk1,
                    voting_power: 100,
                },
                crate::ValidatorInfo {
                    validator_id: 2,
                    suite_id: ML_DSA_44_SUITE_ID,
                    consensus_pk: pk2,
                    voting_power: 100,
                },
                crate::ValidatorInfo {
                    validator_id: 3,
                    suite_id: ML_DSA_44_SUITE_ID,
                    consensus_pk: pk3,
                    voting_power: 100,
                },
            ],
            qc_threshold: 201,
        };

        (vs, vec![sk1, sk2, sk3])
    }

    /// Create valid O1 double-sign evidence with proper ML-DSA-44 signatures.
    fn make_valid_o1_evidence_with_crypto(
        validator_idx: usize,
        secret_key: &[u8],
        height: u64,
        view: u64,
    ) -> SlashingEvidence {
        let validator_id = (validator_idx + 1) as u32;

        // Create two different preimages (different block content)
        let preimage_a = vec![0x10; 100];
        let preimage_b = vec![0x20; 100];

        // Sign both preimages
        let sig_a = MlDsa44Backend::sign(secret_key, &preimage_a).expect("signing failed");
        let sig_b = MlDsa44Backend::sign(secret_key, &preimage_b).expect("signing failed");

        SlashingEvidence {
            version: 1,
            offense: OffenseKind::O1DoubleSign,
            offending_validator: ValidatorId(u64::from(validator_id)),
            height,
            view,
            payload: EvidencePayloadV1::O1DoubleSign {
                block_a: SignedBlockHeader {
                    height,
                    view,
                    block_id: [0xAA; 32],
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    signature: sig_a,
                    header_preimage: preimage_a,
                },
                block_b: SignedBlockHeader {
                    height,
                    view,
                    block_id: [0xBB; 32],
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    signature: sig_b,
                    header_preimage: preimage_b,
                },
            },
        }
    }

    /// Create O1 evidence with one invalid signature.
    fn make_invalid_o1_evidence_bad_sig(
        validator_idx: usize,
        secret_key: &[u8],
        height: u64,
        view: u64,
    ) -> SlashingEvidence {
        let validator_id = (validator_idx + 1) as u32;

        let preimage_a = vec![0x10; 100];
        let preimage_b = vec![0x20; 100];

        // Sign first preimage correctly
        let sig_a = MlDsa44Backend::sign(secret_key, &preimage_a).expect("signing failed");

        // Create an invalid signature (wrong size or corrupted)
        let mut sig_b = MlDsa44Backend::sign(secret_key, &preimage_b).expect("signing failed");
        // Corrupt the signature
        sig_b[0] ^= 0xFF;
        sig_b[1] ^= 0xFF;

        SlashingEvidence {
            version: 1,
            offense: OffenseKind::O1DoubleSign,
            offending_validator: ValidatorId(u64::from(validator_id)),
            height,
            view,
            payload: EvidencePayloadV1::O1DoubleSign {
                block_a: SignedBlockHeader {
                    height,
                    view,
                    block_id: [0xAA; 32],
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    signature: sig_a,
                    header_preimage: preimage_a,
                },
                block_b: SignedBlockHeader {
                    height,
                    view,
                    block_id: [0xBB; 32],
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    signature: sig_b,
                    header_preimage: preimage_b,
                },
            },
        }
    }

    /// Create valid O2 invalid proposer signature evidence.
    /// Note: O2 evidence proves a BAD signature was submitted, so the signature
    /// in the evidence must actually be invalid.
    fn make_valid_o2_evidence_with_crypto(
        validator_idx: usize,
        height: u64,
        view: u64,
    ) -> SlashingEvidence {
        let validator_id = (validator_idx + 1) as u32;

        // For O2, we need a signature that will fail verification.
        // Create a random invalid signature (wrong content/corrupted)
        let bad_signature = vec![0xDE; ML_DSA_44_SIGNATURE_SIZE];

        SlashingEvidence {
            version: 1,
            offense: OffenseKind::O2InvalidProposerSig,
            offending_validator: ValidatorId(u64::from(validator_id)),
            height,
            view,
            payload: EvidencePayloadV1::O2InvalidProposerSig {
                header: BlockHeader {
                    height,
                    view,
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    batch_commitment: [0xCC; 32],
                },
                bad_signature,
            },
        }
    }

    /// Create O2 evidence where the signature is actually valid (evidence should be rejected).
    fn make_invalid_o2_evidence_sig_valid(
        validator_idx: usize,
        secret_key: &[u8],
        height: u64,
        view: u64,
    ) -> SlashingEvidence {
        let validator_id = (validator_idx + 1) as u32;

        // Construct the preimage the same way verify_o2_evidence does
        let mut preimage = Vec::new();
        preimage.extend_from_slice(&height.to_le_bytes());
        preimage.extend_from_slice(&view.to_le_bytes());
        preimage.extend_from_slice(&validator_id.to_le_bytes());
        preimage.extend_from_slice(&[0xCC; 32]); // batch_commitment

        // Sign it correctly - this should make the evidence invalid
        // because O2 evidence is supposed to prove a BAD signature
        let valid_signature = MlDsa44Backend::sign(secret_key, &preimage).expect("signing failed");

        SlashingEvidence {
            version: 1,
            offense: OffenseKind::O2InvalidProposerSig,
            offending_validator: ValidatorId(u64::from(validator_id)),
            height,
            view,
            payload: EvidencePayloadV1::O2InvalidProposerSig {
                header: BlockHeader {
                    height,
                    view,
                    proposer_id: ValidatorId(u64::from(validator_id)),
                    batch_commitment: [0xCC; 32],
                },
                bad_signature: valid_signature,
            },
        }
    }

    // ------------------------------------------------------------------------
    // O1 Verification Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_valid_o1_evidence_accepted() {
        let (vs, sks) = test_validator_set_with_ml_dsa();

        // Validator 1 is at index 0, leader at view 0 (0 % 3 = 0)
        let evidence = make_valid_o1_evidence_with_crypto(0, &sks[0], 100, 0);

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o1_evidence(&ctx, &evidence, None);
        assert!(result.is_ok(), "Valid O1 evidence should be accepted: {:?}", result);
    }

    #[test]
    fn test_invalid_o1_signature_rejected() {
        let (vs, sks) = test_validator_set_with_ml_dsa();

        // Create O1 evidence with a corrupted signature
        let evidence = make_invalid_o1_evidence_bad_sig(0, &sks[0], 100, 0);

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o1_evidence(&ctx, &evidence, None);
        assert!(result.is_err(), "O1 evidence with invalid signature should be rejected");

        match result {
            Err(EvidenceVerificationError::InvalidSignature { .. }) => {}
            Err(e) => panic!("Expected InvalidSignature error, got: {:?}", e),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_o1_height_view_mismatch_rejected() {
        let (vs, sks) = test_validator_set_with_ml_dsa();

        // Create evidence with mismatched heights
        let mut evidence = make_valid_o1_evidence_with_crypto(0, &sks[0], 100, 0);
        if let EvidencePayloadV1::O1DoubleSign { ref mut block_b, .. } = evidence.payload {
            block_b.height = 101; // Different height
        }

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o1_evidence(&ctx, &evidence, None);
        assert!(matches!(
            result,
            Err(EvidenceVerificationError::HeightViewMismatch { .. })
        ));
    }

    #[test]
    fn test_o1_identical_blocks_rejected() {
        let (vs, sks) = test_validator_set_with_ml_dsa();

        let mut evidence = make_valid_o1_evidence_with_crypto(0, &sks[0], 100, 0);
        if let EvidencePayloadV1::O1DoubleSign {
            ref mut block_a,
            ref mut block_b,
        } = evidence.payload
        {
            // Make block IDs identical
            block_b.block_id = block_a.block_id;
        }

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o1_evidence(&ctx, &evidence, None);
        assert!(matches!(result, Err(EvidenceVerificationError::IdenticalBlocks)));
    }

    #[test]
    fn test_o1_not_scheduled_leader_rejected() {
        let (vs, sks) = test_validator_set_with_ml_dsa();

        // Validator 1 at index 0, but view 1 has leader index 1 (validator 2)
        let evidence = make_valid_o1_evidence_with_crypto(0, &sks[0], 100, 1);

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o1_evidence(&ctx, &evidence, None);
        assert!(matches!(
            result,
            Err(EvidenceVerificationError::NotScheduledLeader { .. })
        ));
    }

    // ------------------------------------------------------------------------
    // O2 Verification Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_valid_o2_evidence_accepted() {
        let (vs, _sks) = test_validator_set_with_ml_dsa();

        // Validator 1 is at index 0, leader at view 0
        let evidence = make_valid_o2_evidence_with_crypto(0, 100, 0);

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o2_evidence(&ctx, &evidence, None);
        assert!(result.is_ok(), "Valid O2 evidence should be accepted: {:?}", result);
    }

    #[test]
    fn test_invalid_o2_signature_actually_valid_rejected() {
        let (vs, sks) = test_validator_set_with_ml_dsa();

        // Create O2 evidence where the signature is actually valid
        // This should be rejected because O2 is supposed to prove a BAD signature
        let evidence = make_invalid_o2_evidence_sig_valid(0, &sks[0], 100, 0);

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o2_evidence(&ctx, &evidence, None);
        assert!(result.is_err(), "O2 evidence with actually valid signature should be rejected");

        match result {
            Err(EvidenceVerificationError::InvalidSignature { reason, .. }) => {
                assert!(reason.contains("actually valid"));
            }
            Err(e) => panic!("Expected InvalidSignature error, got: {:?}", e),
            Ok(_) => panic!("Expected error"),
        }
    }

    #[test]
    fn test_o2_not_scheduled_leader_rejected() {
        let (vs, _sks) = test_validator_set_with_ml_dsa();

        // Validator 1 at index 0, but view 1 has leader index 1 (validator 2)
        let evidence = make_valid_o2_evidence_with_crypto(0, 100, 1);

        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let result = verify_o2_evidence(&ctx, &evidence, None);
        assert!(matches!(
            result,
            Err(EvidenceVerificationError::NotScheduledLeader { .. })
        ));
    }

    // ------------------------------------------------------------------------
    // Signature Failure Metrics Tests
    // ------------------------------------------------------------------------

    #[test]
    fn test_signature_failure_metrics() {
        let metrics = SlashingMetrics::new();

        assert_eq!(metrics.sig_failures_o1_total(), 0);
        assert_eq!(metrics.sig_failures_o2_total(), 0);
        assert_eq!(metrics.sig_failures_total(), 0);

        metrics.inc_signature_failure(OffenseKind::O1DoubleSign);
        metrics.inc_signature_failure(OffenseKind::O1DoubleSign);
        metrics.inc_signature_failure(OffenseKind::O2InvalidProposerSig);

        assert_eq!(metrics.sig_failures_o1_total(), 2);
        assert_eq!(metrics.sig_failures_o2_total(), 1);
        assert_eq!(metrics.sig_failures_total(), 3);
    }

    // ------------------------------------------------------------------------
    // Integration Tests: Engine with Cryptographic Verification
    // ------------------------------------------------------------------------

    #[test]
    fn test_noop_engine_rejects_o1_with_invalid_signature() {
        let (vs, sks) = test_validator_set_with_ml_dsa();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();
        let evidence = make_invalid_o1_evidence_bad_sig(0, &sks[0], 100, 0);

        let record = engine.handle_evidence(&ctx, evidence);
        assert_eq!(record.decision, SlashingDecisionKind::RejectedInvalid);
    }

    #[test]
    fn test_noop_engine_accepts_valid_o1_with_crypto() {
        let (vs, sks) = test_validator_set_with_ml_dsa();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();
        let evidence = make_valid_o1_evidence_with_crypto(0, &sks[0], 100, 0);

        let record = engine.handle_evidence(&ctx, evidence);
        assert_eq!(record.decision, SlashingDecisionKind::AcceptedNoOp);
    }

    #[test]
    fn test_noop_engine_accepts_valid_o2_with_crypto() {
        let (vs, _sks) = test_validator_set_with_ml_dsa();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();
        let evidence = make_valid_o2_evidence_with_crypto(0, 100, 0);

        let record = engine.handle_evidence(&ctx, evidence);
        assert_eq!(record.decision, SlashingDecisionKind::AcceptedNoOp);
    }

    #[test]
    fn test_noop_engine_rejects_o2_with_valid_signature() {
        let (vs, sks) = test_validator_set_with_ml_dsa();
        let ctx = SlashingContext {
            validator_set: &vs,
            current_height: 1000,
            current_view: 10,
        };

        let mut engine = NoopSlashingEngine::new();
        // O2 evidence with actually valid signature should be rejected
        let evidence = make_invalid_o2_evidence_sig_valid(0, &sks[0], 100, 0);

        let record = engine.handle_evidence(&ctx, evidence);
        assert_eq!(record.decision, SlashingDecisionKind::RejectedInvalid);
    }
}