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

use crate::{ValidatorId, ValidatorSet};
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

impl SlashingEvidence {
    /// Compute a deduplication key for this evidence.
    ///
    /// Evidence with the same key is considered duplicate and will be
    /// rejected by the slashing engine.
    pub fn dedup_key(&self) -> (ValidatorId, OffenseKind, u64, u64) {
        (self.offending_validator, self.offense, self.height, self.view)
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
            (OffenseKind::O2InvalidProposerSig, EvidencePayloadV1::O2InvalidProposerSig { .. }) => {}
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
    /// Deduplication set: (validator, offense, height, view).
    seen_evidence: HashSet<(ValidatorId, OffenseKind, u64, u64)>,
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

        // 1. Check for duplicate
        let dedup_key = evidence.dedup_key();
        if self.seen_evidence.contains(&dedup_key) {
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

        // 5. Evidence is valid and new - accept with no-op
        eprintln!(
            "[SLASHING] Evidence accepted (no-op): validator={}, offense={}, height={}, view={}",
            evidence.offending_validator.0,
            evidence.offense.as_str(),
            evidence.height,
            evidence.view
        );

        // Mark as seen for deduplication
        self.seen_evidence.insert(dedup_key);

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
        self.records
            .get(&validator_id)
            .cloned()
            .unwrap_or_default()
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
        self.records
            .get(&validator_id)
            .cloned()
            .unwrap_or_default()
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
/// - Pending evidence (future: when queue is implemented)
///
/// # Prometheus Naming
///
/// - `qbind_slashing_evidence_total{offense="O1/O2/..."}` — evidence received
/// - `qbind_slashing_decisions_total{offense="...",decision="accepted_noop|..."}` — decisions made
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

    // ========================================================================
    // Getters for metrics export
    // ========================================================================

    /// Get evidence count for O1 (double-sign).
    pub fn evidence_o1_total(&self) -> u64 {
        self.evidence_o1_double_sign.load(Ordering::Relaxed)
    }

    /// Get evidence count for O2 (invalid proposer sig).
    pub fn evidence_o2_total(&self) -> u64 {
        self.evidence_o2_invalid_proposer_sig.load(Ordering::Relaxed)
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
        assert_eq!(OffenseKind::O4InvalidDagCert.as_str(), "O4_invalid_dag_cert");
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
        let evidence = make_o1_evidence(1, 100, 5);

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
        let evidence = make_o1_evidence(999, 100, 5);

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
        let evidence = make_o1_evidence(1, 100, 5);

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

        // Submit a few different evidence items
        let e1 = make_o1_evidence(1, 100, 5);
        let e2 = make_o1_evidence(2, 101, 6);
        let e3 = make_o1_evidence(1, 100, 5); // duplicate

        engine.handle_evidence(&ctx, e1);
        engine.handle_evidence(&ctx, e2);
        engine.handle_evidence(&ctx, e3);

        // Check counts
        assert_eq!(
            engine.evidence_count_by_offense(OffenseKind::O1DoubleSign),
            3
        );
        assert_eq!(
            engine.decision_count(SlashingDecisionKind::AcceptedNoOp),
            2
        );
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
}