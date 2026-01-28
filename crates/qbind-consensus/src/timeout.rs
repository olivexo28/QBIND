//! Timeout message types for HotStuff view-change protocol (T146).
//!
//! This module provides the timeout and view-change message types needed for
//! HotStuff liveness under faulty leaders:
//!
//! - [`TimeoutMsg`]: A message a validator sends when they time out waiting for progress
//! - [`TimeoutCertificate`]: Aggregation of 2f+1 timeout messages enabling view change
//!
//! # Protocol Overview
//!
//! When a validator detects no progress (no valid proposal or QC) for the current view
//! within the timeout period, it broadcasts a `TimeoutMsg` containing:
//! - The view being timed out
//! - The validator's highest known QC (high_qc)
//! - A signature over the timeout data
//!
//! When 2f+1 validators have sent timeout messages for the same view (or higher), a
//! `TimeoutCertificate` (TC) can be formed. The TC allows the network to safely advance
//! to a higher view with a new leader.
//!
//! # Safety Invariants
//!
//! The protocol maintains HotStuff safety:
//! - The TC carries the maximum high_qc from all included timeout messages
//! - New proposals in the next view must be justified by this high_qc
//! - The locked QC semantics remain intact
//!
//! # T159: Chain-Aware Domain Separation
//!
//! As of T159, all signing preimages include the chain ID to prevent cross-chain
//! replay attacks. Use `signing_bytes_with_chain_id()` with the appropriate
//! `ChainId` for the network environment (DevNet, TestNet, MainNet).

use crate::ids::ValidatorId;
use crate::qc::QuorumCertificate;
use crate::validator_set::ConsensusValidatorSet;
use qbind_types::domain::{domain_prefix, DomainKind};
use qbind_types::{ChainId, QBIND_DEVNET_CHAIN_ID};

/// Suite ID for timeout message signatures (ML-DSA-44, same as votes/proposals).
pub const TIMEOUT_SUITE_ID: u8 = 100;

/// Legacy domain separator for timeout message signing.
///
/// **DEPRECATED (T159)**: Use `domain_prefix(chain_id, DomainKind::Timeout)` instead.
///
/// This constant is provided for documentation purposes. New code should use
/// `timeout_signing_bytes_with_chain_id()` with the appropriate chain ID.
#[allow(dead_code)]
const TIMEOUT_DOMAIN_SEPARATOR: &[u8] = b"QBIND_TIMEOUT_V1";

/// A timeout message sent by a validator when they detect lack of progress.
///
/// When a validator sees no valid proposal or QC for their current view within
/// the configured timeout period, they broadcast this message to signal they
/// want to advance to the next view.
///
/// # Fields
///
/// - `view`: The view number being timed out (the view with no progress)
/// - `high_qc`: The highest QC known to this validator at timeout time
/// - `validator_id`: The validator sending this timeout message
/// - `signature`: ML-DSA-44 signature over the timeout signing bytes
///
/// # Signing (T159: Chain-Aware)
///
/// The signature covers:
/// - Domain separator (e.g., "QBIND:DEV:TIMEOUT:v1" for DevNet)
/// - View number
/// - High QC's block_id and view
/// - Validator ID
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutMsg<BlockIdT> {
    /// The view being timed out.
    pub view: u64,
    /// The highest QC known to the signer when timing out.
    /// This may be None if the validator has not seen any QC yet.
    pub high_qc: Option<QuorumCertificate<BlockIdT>>,
    /// The validator sending this timeout message.
    pub validator_id: ValidatorId,
    /// The signature suite ID (should be 100 for ML-DSA-44).
    pub suite_id: u8,
    /// ML-DSA-44 signature over the timeout signing bytes.
    pub signature: Vec<u8>,
}

impl<BlockIdT: Clone + AsRef<[u8]>> TimeoutMsg<BlockIdT> {
    /// Create a new unsigned timeout message.
    ///
    /// The signature field is left empty. Call `set_signature` after signing.
    pub fn new(
        view: u64,
        high_qc: Option<QuorumCertificate<BlockIdT>>,
        validator_id: ValidatorId,
    ) -> Self {
        TimeoutMsg {
            view,
            high_qc,
            validator_id,
            suite_id: TIMEOUT_SUITE_ID,
            signature: Vec::new(),
        }
    }

    /// Set the signature after signing.
    pub fn set_signature(&mut self, signature: Vec<u8>) {
        self.signature = signature;
    }

    /// Compute the signing bytes for this timeout message with chain ID (T159).
    ///
    /// The signing bytes include:
    /// - Domain separator (e.g., "QBIND:DEV:TIMEOUT:v1" for DevNet)
    /// - View number (8 bytes, little-endian)
    /// - High QC block_id (32 bytes) or zeros if None
    /// - High QC view (8 bytes, little-endian) or zeros if None
    /// - Validator ID (8 bytes, little-endian)
    pub fn signing_bytes_with_chain_id(&self, chain_id: ChainId) -> Vec<u8> {
        timeout_signing_bytes_with_chain_id(
            chain_id,
            self.view,
            self.high_qc.as_ref(),
            self.validator_id,
        )
    }

    /// Compute the signing bytes using the default DevNet chain ID.
    ///
    /// **Note (T159)**: This method defaults to `QBIND_DEVNET_CHAIN_ID`. For
    /// explicit chain control, use `signing_bytes_with_chain_id()` instead.
    ///
    /// The signing bytes include:
    /// - Domain separator ("QBIND:DEV:TIMEOUT:v1" for DevNet)
    /// - View number (8 bytes, little-endian)
    /// - High QC block_id (32 bytes) or zeros if None
    /// - High QC view (8 bytes, little-endian) or zeros if None
    /// - Validator ID (8 bytes, little-endian)
    pub fn signing_bytes(&self) -> Vec<u8> {
        self.signing_bytes_with_chain_id(QBIND_DEVNET_CHAIN_ID)
    }
}

/// Compute the signing bytes for a timeout message with chain ID (T159).
///
/// This function is public to allow verification of timeout signatures.
///
/// # Arguments
///
/// - `chain_id`: The chain ID for domain separation
/// - `view`: The view being timed out
/// - `high_qc`: The highest QC known to the signer (optional)
/// - `validator_id`: The validator ID
///
/// # Returns
///
/// A byte vector suitable for signing with ML-DSA-44.
pub fn timeout_signing_bytes_with_chain_id<BlockIdT: Clone + AsRef<[u8]>>(
    chain_id: ChainId,
    view: u64,
    high_qc: Option<&QuorumCertificate<BlockIdT>>,
    validator_id: ValidatorId,
) -> Vec<u8> {
    let domain_tag = domain_prefix(chain_id, DomainKind::Timeout);
    let mut bytes = Vec::with_capacity(domain_tag.len() + 8 + 32 + 8 + 8);

    // Domain separator (chain-aware)
    bytes.extend_from_slice(&domain_tag);

    // View number (8 bytes, little-endian)
    bytes.extend_from_slice(&view.to_le_bytes());

    // High QC block_id (32 bytes) or zeros
    if let Some(qc) = high_qc {
        let block_id_bytes = qc.block_id.as_ref();
        bytes.extend_from_slice(block_id_bytes);
        // High QC view (8 bytes, little-endian)
        bytes.extend_from_slice(&qc.view.to_le_bytes());
    } else {
        // No high QC - use zeros
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&0u64.to_le_bytes());
    }

    // Validator ID (8 bytes, little-endian)
    bytes.extend_from_slice(&validator_id.0.to_le_bytes());

    bytes
}

/// Compute the signing bytes for a timeout message using DevNet chain ID.
///
/// **Note (T159)**: This function defaults to `QBIND_DEVNET_CHAIN_ID`. For
/// explicit chain control, use `timeout_signing_bytes_with_chain_id()` instead.
///
/// This function is public to allow verification of timeout signatures.
///
/// # Arguments
///
/// - `view`: The view being timed out
/// - `high_qc`: The highest QC known to the signer (optional)
/// - `validator_id`: The validator ID
///
/// # Returns
///
/// A byte vector suitable for signing with ML-DSA-44.
pub fn timeout_signing_bytes<BlockIdT: Clone + AsRef<[u8]>>(
    view: u64,
    high_qc: Option<&QuorumCertificate<BlockIdT>>,
    validator_id: ValidatorId,
) -> Vec<u8> {
    timeout_signing_bytes_with_chain_id(QBIND_DEVNET_CHAIN_ID, view, high_qc, validator_id)
}

/// A Timeout Certificate (TC) formed from 2f+1 timeout messages.
///
/// When 2f+1 validators have sent timeout messages for a view, a TC can be
/// formed that enables the network to safely advance to a higher view.
///
/// # Fields
///
/// - `view`: The view this TC is for (typically the timed-out view + 1 or the max view)
/// - `high_qc`: The maximum high_qc from all included timeout messages
/// - `signers`: The set of validators who contributed timeout messages
/// - `timeout_view`: The view that was timed out
///
/// # Safety
///
/// The TC carries the highest high_qc from the included timeouts. New proposals
/// in the next view must be justified by a QC at least as recent as this high_qc,
/// maintaining HotStuff safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TimeoutCertificate<BlockIdT> {
    /// The view this TC enables transition to.
    /// Typically this is timeout_view + 1.
    pub view: u64,
    /// The maximum high_qc from all included timeout messages.
    /// This becomes the justify_qc for the next proposal.
    pub high_qc: Option<QuorumCertificate<BlockIdT>>,
    /// The set of validators who signed timeout messages.
    /// Size must be >= 2f+1.
    pub signers: Vec<ValidatorId>,
    /// The view that was timed out.
    pub timeout_view: u64,
}

/// Errors that can occur during timeout message/certificate validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutValidationError {
    /// A signer is not in the validator set.
    NonMemberSigner(ValidatorId),
    /// Duplicate signer detected.
    DuplicateSigner(ValidatorId),
    /// Total voting power of signers is below 2/3 threshold.
    InsufficientQuorum {
        /// The accumulated voting power of the signers.
        accumulated_vp: u64,
        /// The required voting power for a valid TC.
        required_vp: u64,
    },
    /// Invalid signature on a timeout message.
    InvalidSignature(ValidatorId),
    /// View mismatch in timeout certificate.
    ViewMismatch { expected: u64, actual: u64 },
}

impl std::fmt::Display for TimeoutValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeoutValidationError::NonMemberSigner(id) => {
                write!(f, "non-member signer: {:?}", id)
            }
            TimeoutValidationError::DuplicateSigner(id) => {
                write!(f, "duplicate signer: {:?}", id)
            }
            TimeoutValidationError::InsufficientQuorum {
                accumulated_vp,
                required_vp,
            } => {
                write!(
                    f,
                    "insufficient quorum: have {} VP, need {} VP",
                    accumulated_vp, required_vp
                )
            }
            TimeoutValidationError::InvalidSignature(id) => {
                write!(f, "invalid signature from: {:?}", id)
            }
            TimeoutValidationError::ViewMismatch { expected, actual } => {
                write!(f, "view mismatch: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for TimeoutValidationError {}

impl<BlockIdT: Clone + Eq> TimeoutCertificate<BlockIdT> {
    /// Create a new timeout certificate from aggregated timeout messages.
    ///
    /// # Arguments
    ///
    /// - `timeout_view`: The view that was timed out
    /// - `high_qc`: The maximum high_qc from all timeout messages
    /// - `signers`: The validators who sent timeout messages
    pub fn new(
        timeout_view: u64,
        high_qc: Option<QuorumCertificate<BlockIdT>>,
        signers: Vec<ValidatorId>,
    ) -> Self {
        TimeoutCertificate {
            view: timeout_view.saturating_add(1), // TC enables transition to next view
            high_qc,
            signers,
            timeout_view,
        }
    }

    /// Validate the timeout certificate against a validator set.
    ///
    /// This performs logical validation:
    /// 1. All signers must be members of the validator set
    /// 2. No duplicate signers
    /// 3. Total voting power must meet 2/3 threshold
    ///
    /// # Note
    ///
    /// This does NOT verify individual signatures. Signature verification
    /// should be done when collecting individual TimeoutMsg.
    pub fn validate(
        &self,
        validators: &ConsensusValidatorSet,
    ) -> Result<(), TimeoutValidationError> {
        use std::collections::HashSet;

        let mut seen = HashSet::new();
        let mut acc_vp: u64 = 0;

        for id in &self.signers {
            // Check membership
            if !validators.contains(*id) {
                return Err(TimeoutValidationError::NonMemberSigner(*id));
            }

            // Check for duplicates
            if !seen.insert(*id) {
                return Err(TimeoutValidationError::DuplicateSigner(*id));
            }

            // Accumulate voting power
            let idx = validators.index_of(*id).expect("contains check passed");
            let entry = validators.get(idx).expect("index_of should be valid");
            acc_vp = acc_vp.saturating_add(entry.voting_power);
        }

        // Check quorum threshold (2/3)
        let required = validators.two_thirds_vp();
        if acc_vp < required {
            return Err(TimeoutValidationError::InsufficientQuorum {
                accumulated_vp: acc_vp,
                required_vp: required,
            });
        }

        Ok(())
    }

    /// Get the view number this TC enables transition to.
    pub fn target_view(&self) -> u64 {
        self.view
    }
}

/// Select the maximum high_qc from a collection of timeout messages.
///
/// The "maximum" is determined by the QC's view number. If two QCs have the
/// same view, either can be selected (they should be for the same block in
/// a correct network).
///
/// # Arguments
///
/// - `timeouts`: Iterator over timeout messages
///
/// # Returns
///
/// The high_qc with the highest view number, or None if all timeouts have None.
pub fn select_max_high_qc<'a, BlockIdT, I>(timeouts: I) -> Option<QuorumCertificate<BlockIdT>>
where
    BlockIdT: Clone + 'a,
    I: Iterator<Item = &'a TimeoutMsg<BlockIdT>>,
{
    let mut max_qc: Option<QuorumCertificate<BlockIdT>> = None;
    let mut max_view: u64 = 0;

    for timeout in timeouts {
        if let Some(ref qc) = timeout.high_qc {
            if max_qc.is_none() || qc.view > max_view {
                max_qc = Some(qc.clone());
                max_view = qc.view;
            }
        }
    }

    max_qc
}

// ============================================================================
// TimeoutAccumulator - Collects timeout messages and forms TCs (T146)
// ============================================================================

/// Accumulator for timeout messages that forms TimeoutCertificates.
///
/// This struct collects `TimeoutMsg` and forms a `TimeoutCertificate` when
/// 2f+1 validators have sent timeout messages for the same view.
///
/// # Memory Limits
///
/// Similar to `VoteAccumulator`, this struct enforces limits:
/// - `max_tracked_views`: Maximum views to track simultaneously
/// - `max_timeouts_per_view`: Maximum timeouts per view
///
/// When limits are exceeded, old views are evicted.
///
/// # Type Parameter
///
/// - `BlockIdT`: The block identifier type (typically `[u8; 32]`)
#[derive(Debug)]
pub struct TimeoutAccumulator<BlockIdT> {
    /// Map from view to collected timeout messages.
    /// Key is the view number, value is a map from validator_id to their TimeoutMsg.
    entries: std::collections::HashMap<
        u64,
        std::collections::HashMap<ValidatorId, TimeoutMsg<BlockIdT>>,
    >,
    /// Sorted set of tracked views for eviction.
    tracked_views: std::collections::BTreeSet<u64>,
    /// Maximum number of views to track.
    max_tracked_views: usize,
    /// Maximum timeouts to store per view.
    max_timeouts_per_view: usize,
    /// Counter for evicted views.
    evicted_views: u64,
}

impl<BlockIdT> Default for TimeoutAccumulator<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<BlockIdT> TimeoutAccumulator<BlockIdT>
where
    BlockIdT: Eq + std::hash::Hash + Clone,
{
    /// Create a new timeout accumulator with default limits.
    pub fn new() -> Self {
        Self::with_limits(128, 256)
    }

    /// Create a timeout accumulator with custom limits.
    pub fn with_limits(max_tracked_views: usize, max_timeouts_per_view: usize) -> Self {
        TimeoutAccumulator {
            entries: std::collections::HashMap::new(),
            tracked_views: std::collections::BTreeSet::new(),
            max_tracked_views,
            max_timeouts_per_view,
            evicted_views: 0,
        }
    }

    /// Get the number of evicted views.
    pub fn evicted_views(&self) -> u64 {
        self.evicted_views
    }

    /// Get the number of currently tracked views.
    pub fn tracked_view_count(&self) -> usize {
        self.tracked_views.len()
    }

    /// Evict oldest views to make room for new ones.
    fn evict_oldest_views(&mut self) {
        while self.tracked_views.len() >= self.max_tracked_views {
            if let Some(&oldest) = self.tracked_views.iter().next() {
                self.entries.remove(&oldest);
                self.tracked_views.remove(&oldest);
                self.evicted_views += 1;
            } else {
                break;
            }
        }
    }

    /// Ingest a timeout message.
    ///
    /// Returns `Ok(true)` if this is a new timeout message,
    /// `Ok(false)` if it was a duplicate or dropped due to limits.
    ///
    /// # Arguments
    ///
    /// - `validators`: The validator set to check membership
    /// - `timeout`: The timeout message to ingest
    ///
    /// # Errors
    ///
    /// Returns `Err(TimeoutValidationError::NonMemberSigner)` if the signer
    /// is not in the validator set.
    ///
    /// # Note
    ///
    /// This method does NOT verify the signature. Signature verification
    /// should be done before calling this method.
    pub fn on_timeout(
        &mut self,
        validators: &ConsensusValidatorSet,
        timeout: TimeoutMsg<BlockIdT>,
    ) -> Result<bool, TimeoutValidationError> {
        // Check membership
        if !validators.contains(timeout.validator_id) {
            return Err(TimeoutValidationError::NonMemberSigner(
                timeout.validator_id,
            ));
        }

        let view = timeout.view;
        let validator_id = timeout.validator_id;

        // Handle view tracking and eviction
        if !self.tracked_views.contains(&view) {
            if self.tracked_views.len() >= self.max_tracked_views {
                self.evict_oldest_views();
            }
            self.tracked_views.insert(view);
        }

        // Get or create entry for this view
        let view_entries = self.entries.entry(view).or_default();

        // Check per-view limit
        if view_entries.len() >= self.max_timeouts_per_view {
            // Check if this is a duplicate (already present)
            if view_entries.contains_key(&validator_id) {
                return Ok(false); // Duplicate
            }
            // Drop new timeout due to limit
            return Ok(false);
        }

        // Check for duplicate
        if view_entries.contains_key(&validator_id) {
            return Ok(false); // Duplicate
        }

        // Insert the timeout
        view_entries.insert(validator_id, timeout);
        Ok(true)
    }

    /// Attempt to form a TimeoutCertificate for the given view.
    ///
    /// Returns `Some(tc)` if 2f+1 validators have sent timeout messages,
    /// `None` otherwise.
    ///
    /// # Arguments
    ///
    /// - `validators`: The validator set for quorum calculation
    /// - `view`: The view to check
    pub fn maybe_tc_for(
        &self,
        validators: &ConsensusValidatorSet,
        view: u64,
    ) -> Option<TimeoutCertificate<BlockIdT>> {
        let view_entries = self.entries.get(&view)?;

        // Collect signers and their voting power
        let mut signers = Vec::new();
        let mut acc_vp: u64 = 0;

        for validator_id in view_entries.keys() {
            if let Some(idx) = validators.index_of(*validator_id) {
                if let Some(entry) = validators.get(idx) {
                    signers.push(*validator_id);
                    acc_vp = acc_vp.saturating_add(entry.voting_power);
                }
            }
        }

        // Check quorum
        let required = validators.two_thirds_vp();
        if acc_vp < required {
            return None;
        }

        // Select max high_qc from all timeouts
        let high_qc = select_max_high_qc(view_entries.values());

        Some(TimeoutCertificate::new(view, high_qc, signers))
    }

    /// Get the number of timeout messages collected for a view.
    pub fn timeout_count(&self, view: u64) -> usize {
        self.entries.get(&view).map(|e| e.len()).unwrap_or(0)
    }

    /// Clear timeout messages for a view (e.g., after TC is formed).
    pub fn clear_view(&mut self, view: u64) {
        self.entries.remove(&view);
        self.tracked_views.remove(&view);
    }

    /// Get all timeout messages for a view (for debugging/testing).
    pub fn get_timeouts(
        &self,
        view: u64,
    ) -> Option<&std::collections::HashMap<ValidatorId, TimeoutMsg<BlockIdT>>> {
        self.entries.get(&view)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::validator_set::ValidatorSetEntry;

    fn make_validator_set(num: u64) -> ConsensusValidatorSet {
        let entries: Vec<ValidatorSetEntry> = (1..=num)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        ConsensusValidatorSet::new(entries).expect("valid set")
    }

    #[test]
    fn timeout_msg_signing_bytes_are_deterministic() {
        let qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);

        let bytes1 = timeout_signing_bytes(10, Some(&qc), ValidatorId(1));
        let bytes2 = timeout_signing_bytes(10, Some(&qc), ValidatorId(1));

        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn timeout_msg_signing_bytes_differ_for_different_views() {
        let qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);

        let bytes1 = timeout_signing_bytes(10, Some(&qc), ValidatorId(1));
        let bytes2 = timeout_signing_bytes(11, Some(&qc), ValidatorId(1));

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn timeout_msg_signing_bytes_differ_for_different_validators() {
        let qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);

        let bytes1 = timeout_signing_bytes(10, Some(&qc), ValidatorId(1));
        let bytes2 = timeout_signing_bytes(10, Some(&qc), ValidatorId(2));

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn timeout_msg_signing_bytes_differ_for_different_high_qc() {
        let qc1 = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);
        let qc2 = QuorumCertificate::new([2u8; 32], 5, vec![ValidatorId(1)]);

        let bytes1 = timeout_signing_bytes(10, Some(&qc1), ValidatorId(1));
        let bytes2 = timeout_signing_bytes(10, Some(&qc2), ValidatorId(1));

        assert_ne!(bytes1, bytes2);
    }

    #[test]
    fn timeout_msg_signing_bytes_with_none_high_qc() {
        let bytes1: Vec<u8> = timeout_signing_bytes::<[u8; 32]>(10, None, ValidatorId(1));
        let bytes2: Vec<u8> = timeout_signing_bytes::<[u8; 32]>(10, None, ValidatorId(1));

        assert_eq!(bytes1, bytes2);

        // Should differ from bytes with a high_qc
        let qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);
        let bytes_with_qc = timeout_signing_bytes(10, Some(&qc), ValidatorId(1));
        assert_ne!(bytes1, bytes_with_qc);
    }

    #[test]
    fn timeout_certificate_validates_with_quorum() {
        let validators = make_validator_set(4);

        // 4 validators with VP=1 each, total=4, threshold=ceil(4*2/3)=3
        // 3 signers should meet quorum
        let tc = TimeoutCertificate::<[u8; 32]>::new(
            5,
            None,
            vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        );

        assert!(tc.validate(&validators).is_ok());
    }

    #[test]
    fn timeout_certificate_fails_without_quorum() {
        let validators = make_validator_set(4);

        // Only 2 signers - not enough for quorum
        let tc = TimeoutCertificate::<[u8; 32]>::new(5, None, vec![ValidatorId(1), ValidatorId(2)]);

        let result = tc.validate(&validators);
        assert!(matches!(
            result,
            Err(TimeoutValidationError::InsufficientQuorum { .. })
        ));
    }

    #[test]
    fn timeout_certificate_fails_with_non_member() {
        let validators = make_validator_set(4);

        // Validator 99 is not in the set
        let tc = TimeoutCertificate::<[u8; 32]>::new(
            5,
            None,
            vec![ValidatorId(1), ValidatorId(2), ValidatorId(99)],
        );

        let result = tc.validate(&validators);
        assert!(matches!(
            result,
            Err(TimeoutValidationError::NonMemberSigner(ValidatorId(99)))
        ));
    }

    #[test]
    fn timeout_certificate_fails_with_duplicate_signer() {
        let validators = make_validator_set(4);

        // Validator 1 appears twice
        let tc = TimeoutCertificate::<[u8; 32]>::new(
            5,
            None,
            vec![ValidatorId(1), ValidatorId(1), ValidatorId(2)],
        );

        let result = tc.validate(&validators);
        assert!(matches!(
            result,
            Err(TimeoutValidationError::DuplicateSigner(ValidatorId(1)))
        ));
    }

    #[test]
    fn select_max_high_qc_finds_highest_view() {
        let qc1 = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);
        let qc2 = QuorumCertificate::new([2u8; 32], 10, vec![ValidatorId(1)]);
        let qc3 = QuorumCertificate::new([3u8; 32], 3, vec![ValidatorId(1)]);

        let timeout1 = TimeoutMsg::new(20, Some(qc1), ValidatorId(1));
        let timeout2 = TimeoutMsg::new(20, Some(qc2.clone()), ValidatorId(2));
        let timeout3 = TimeoutMsg::new(20, Some(qc3), ValidatorId(3));

        let timeouts = [timeout1, timeout2, timeout3];
        let max_qc = select_max_high_qc(timeouts.iter());

        assert!(max_qc.is_some());
        assert_eq!(max_qc.unwrap().view, 10);
    }

    #[test]
    fn select_max_high_qc_handles_all_none() {
        let timeout1: TimeoutMsg<[u8; 32]> = TimeoutMsg::new(20, None, ValidatorId(1));
        let timeout2: TimeoutMsg<[u8; 32]> = TimeoutMsg::new(20, None, ValidatorId(2));

        let timeouts = [timeout1, timeout2];
        let max_qc = select_max_high_qc(timeouts.iter());

        assert!(max_qc.is_none());
    }

    #[test]
    fn select_max_high_qc_handles_mixed_none_and_some() {
        let qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);

        let timeout1: TimeoutMsg<[u8; 32]> = TimeoutMsg::new(20, None, ValidatorId(1));
        let timeout2 = TimeoutMsg::new(20, Some(qc.clone()), ValidatorId(2));
        let timeout3: TimeoutMsg<[u8; 32]> = TimeoutMsg::new(20, None, ValidatorId(3));

        let timeouts = [timeout1, timeout2, timeout3];
        let max_qc = select_max_high_qc(timeouts.iter());

        assert!(max_qc.is_some());
        assert_eq!(max_qc.unwrap().view, 5);
    }

    #[test]
    fn timeout_certificate_target_view_is_next_view() {
        let tc = TimeoutCertificate::<[u8; 32]>::new(
            5,
            None,
            vec![ValidatorId(1), ValidatorId(2), ValidatorId(3)],
        );

        assert_eq!(tc.timeout_view, 5);
        assert_eq!(tc.target_view(), 6);
    }

    #[test]
    fn timeout_msg_new_creates_unsigned_message() {
        let qc = QuorumCertificate::new([1u8; 32], 5, vec![ValidatorId(1)]);
        let timeout = TimeoutMsg::new(10, Some(qc), ValidatorId(1));

        assert_eq!(timeout.view, 10);
        assert_eq!(timeout.validator_id, ValidatorId(1));
        assert_eq!(timeout.suite_id, TIMEOUT_SUITE_ID);
        assert!(timeout.signature.is_empty());
    }

    #[test]
    fn timeout_msg_set_signature_works() {
        let mut timeout: TimeoutMsg<[u8; 32]> = TimeoutMsg::new(10, None, ValidatorId(1));
        assert!(timeout.signature.is_empty());

        timeout.set_signature(vec![1, 2, 3, 4]);
        assert_eq!(timeout.signature, vec![1, 2, 3, 4]);
    }

    // ========================================================================
    // TimeoutAccumulator tests
    // ========================================================================

    #[test]
    fn timeout_accumulator_collects_timeouts() {
        let validators = make_validator_set(4);
        let mut acc = TimeoutAccumulator::<[u8; 32]>::new();

        let timeout1 = TimeoutMsg::new(5, None, ValidatorId(1));
        let timeout2 = TimeoutMsg::new(5, None, ValidatorId(2));

        assert!(acc.on_timeout(&validators, timeout1).unwrap());
        assert!(acc.on_timeout(&validators, timeout2).unwrap());

        assert_eq!(acc.timeout_count(5), 2);
    }

    #[test]
    fn timeout_accumulator_rejects_non_member() {
        let validators = make_validator_set(4);
        let mut acc = TimeoutAccumulator::<[u8; 32]>::new();

        let timeout = TimeoutMsg::new(5, None, ValidatorId(99));
        let result = acc.on_timeout(&validators, timeout);

        assert!(matches!(
            result,
            Err(TimeoutValidationError::NonMemberSigner(ValidatorId(99)))
        ));
    }

    #[test]
    fn timeout_accumulator_rejects_duplicate() {
        let validators = make_validator_set(4);
        let mut acc = TimeoutAccumulator::<[u8; 32]>::new();

        let timeout1 = TimeoutMsg::new(5, None, ValidatorId(1));
        let timeout2 = TimeoutMsg::new(5, None, ValidatorId(1)); // Same validator

        assert!(acc.on_timeout(&validators, timeout1).unwrap());
        assert!(!acc.on_timeout(&validators, timeout2).unwrap()); // Duplicate

        assert_eq!(acc.timeout_count(5), 1);
    }

    #[test]
    fn timeout_accumulator_forms_tc_at_quorum() {
        let validators = make_validator_set(4);
        // 4 validators, VP=1 each, threshold = ceil(4*2/3) = 3
        let mut acc = TimeoutAccumulator::<[u8; 32]>::new();

        let timeout1 = TimeoutMsg::new(5, None, ValidatorId(1));
        let timeout2 = TimeoutMsg::new(5, None, ValidatorId(2));

        acc.on_timeout(&validators, timeout1).unwrap();
        acc.on_timeout(&validators, timeout2).unwrap();

        // Not enough for quorum yet
        assert!(acc.maybe_tc_for(&validators, 5).is_none());

        // Third timeout reaches quorum
        let timeout3 = TimeoutMsg::new(5, None, ValidatorId(3));
        acc.on_timeout(&validators, timeout3).unwrap();

        let tc = acc.maybe_tc_for(&validators, 5);
        assert!(tc.is_some());

        let tc = tc.unwrap();
        assert_eq!(tc.timeout_view, 5);
        assert_eq!(tc.target_view(), 6);
        assert_eq!(tc.signers.len(), 3);
    }

    #[test]
    fn timeout_accumulator_tc_includes_max_high_qc() {
        let validators = make_validator_set(4);
        let mut acc = TimeoutAccumulator::<[u8; 32]>::new();

        let qc1 = QuorumCertificate::new([1u8; 32], 3, vec![ValidatorId(1)]);
        let qc2 = QuorumCertificate::new([2u8; 32], 7, vec![ValidatorId(1)]); // Higher view
        let qc3 = QuorumCertificate::new([3u8; 32], 5, vec![ValidatorId(1)]);

        let timeout1 = TimeoutMsg::new(10, Some(qc1), ValidatorId(1));
        let timeout2 = TimeoutMsg::new(10, Some(qc2), ValidatorId(2));
        let timeout3 = TimeoutMsg::new(10, Some(qc3), ValidatorId(3));

        acc.on_timeout(&validators, timeout1).unwrap();
        acc.on_timeout(&validators, timeout2).unwrap();
        acc.on_timeout(&validators, timeout3).unwrap();

        let tc = acc.maybe_tc_for(&validators, 10).unwrap();

        // Should have the max high_qc (view 7)
        assert!(tc.high_qc.is_some());
        assert_eq!(tc.high_qc.unwrap().view, 7);
    }

    #[test]
    fn timeout_accumulator_clears_view() {
        let validators = make_validator_set(4);
        let mut acc = TimeoutAccumulator::<[u8; 32]>::new();

        let timeout = TimeoutMsg::new(5, None, ValidatorId(1));
        acc.on_timeout(&validators, timeout).unwrap();
        assert_eq!(acc.timeout_count(5), 1);

        acc.clear_view(5);
        assert_eq!(acc.timeout_count(5), 0);
    }

    #[test]
    fn timeout_accumulator_evicts_old_views() {
        let validators = make_validator_set(4);
        let mut acc = TimeoutAccumulator::<[u8; 32]>::with_limits(3, 10);

        // Add timeouts for views 1, 2, 3
        for view in 1..=3 {
            let timeout = TimeoutMsg::new(view, None, ValidatorId(1));
            acc.on_timeout(&validators, timeout).unwrap();
        }

        assert_eq!(acc.tracked_view_count(), 3);

        // Adding view 4 should evict view 1
        let timeout4 = TimeoutMsg::new(4, None, ValidatorId(1));
        acc.on_timeout(&validators, timeout4).unwrap();

        assert_eq!(acc.tracked_view_count(), 3);
        assert_eq!(acc.evicted_views(), 1);
        assert_eq!(acc.timeout_count(1), 0); // View 1 was evicted
        assert_eq!(acc.timeout_count(4), 1); // View 4 is present
    }
}