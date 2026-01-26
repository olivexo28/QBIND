//! Consensus verification interface.
//!
//! This module defines the `ConsensusVerifier` trait and related types for
//! verifying consensus messages (votes and proposals). It provides:
//!
//! - `VerificationError`: Error type for verification failures
//! - `ConsensusVerifier`: Trait for signature verification
//! - `NoopConsensusVerifier`: Default implementation that accepts everything

use crate::ids::ValidatorId;
use qbind_crypto::ConsensusSigSuiteId;
use qbind_wire::consensus::{BlockProposal, Vote};

/// Errors that can occur during consensus message verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationError {
    /// The signature is invalid.
    InvalidSignature,
    /// The validator's public key is not in the registry.
    MissingKey(ValidatorId),
    /// The suite ID on the wire does not match the governance-configured suite.
    ///
    /// This error indicates a misconfiguration or malicious message where:
    /// - `wire_suite` is the suite_id carried in the Vote/BlockProposal on the wire
    /// - `governance_suite` is the suite_id returned by the key governance system
    ///
    /// This is a hard validation failure: the message cannot be verified.
    SuiteMismatch {
        /// The validator whose message has mismatched suites.
        validator_id: ValidatorId,
        /// The suite_id carried on the wire (in Vote or BlockProposal).
        wire_suite: ConsensusSigSuiteId,
        /// The suite_id from governance (via ConsensusKeyGovernance).
        governance_suite: ConsensusSigSuiteId,
    },
    /// The QC's suite ID does not match the epoch's expected suite ID.
    ///
    /// Under the single-suite-per-epoch policy (T115), each QC's suite_id must
    /// match the epoch's single suite ID. This error indicates a QC with a
    /// different suite ID than expected for the current epoch.
    ///
    /// This is a hard validation failure: the QC cannot be verified.
    QcSuiteMismatch {
        /// The suite_id carried on the wire in the QC.
        qc_suite: ConsensusSigSuiteId,
        /// The expected suite_id for the epoch.
        epoch_suite: ConsensusSigSuiteId,
    },
    /// Other verification error.
    Other(String),
}

impl std::fmt::Display for VerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerificationError::InvalidSignature => write!(f, "invalid signature"),
            VerificationError::MissingKey(id) => {
                write!(f, "missing public key for validator {:?}", id)
            }
            VerificationError::SuiteMismatch {
                validator_id,
                wire_suite,
                governance_suite,
            } => {
                write!(
                    f,
                    "suite mismatch for validator {:?}: wire suite {} != governance suite {}",
                    validator_id, wire_suite, governance_suite
                )
            }
            VerificationError::QcSuiteMismatch {
                qc_suite,
                epoch_suite,
            } => {
                write!(
                    f,
                    "QC suite mismatch: QC suite {} != epoch suite {}",
                    qc_suite, epoch_suite
                )
            }
            VerificationError::Other(s) => write!(f, "verification error: {}", s),
        }
    }
}

impl std::error::Error for VerificationError {}

/// Ensure that a QC's suite ID matches the epoch's expected suite ID.
///
/// Under the single-suite-per-epoch policy (T115), each QC's suite_id must
/// match the epoch's single suite ID. This function performs that check.
///
/// # Arguments
///
/// * `qc_suite` - The suite_id from the QC on the wire.
/// * `epoch_suite` - The expected suite_id for the epoch.
///
/// # Returns
///
/// * `Ok(())` if the suites match.
/// * `Err(VerificationError::QcSuiteMismatch { .. })` if they differ.
///
/// # Example
///
/// ```ignore
/// use qbind_consensus::verify::ensure_qc_suite_matches_epoch;
/// use qbind_crypto::ConsensusSigSuiteId;
///
/// let qc_suite = ConsensusSigSuiteId::new(0);
/// let epoch_suite = ConsensusSigSuiteId::new(0);
/// assert!(ensure_qc_suite_matches_epoch(qc_suite, epoch_suite).is_ok());
///
/// let wrong_suite = ConsensusSigSuiteId::new(100);
/// assert!(ensure_qc_suite_matches_epoch(wrong_suite, epoch_suite).is_err());
/// ```
pub fn ensure_qc_suite_matches_epoch(
    qc_suite: ConsensusSigSuiteId,
    epoch_suite: ConsensusSigSuiteId,
) -> Result<(), VerificationError> {
    if qc_suite != epoch_suite {
        return Err(VerificationError::QcSuiteMismatch {
            qc_suite,
            epoch_suite,
        });
    }
    Ok(())
}

/// Trait for verifying consensus messages.
///
/// Implementors of this trait provide cryptographic verification of votes
/// and proposals. The verifier is called by the consensus driver before
/// processing incoming messages.
///
/// # Design Notes
///
/// - This trait does not use `ValidatorPublicKey` yet; that will be added
///   when real PQ signature verification is implemented.
/// - The trait is `Send + Sync` to allow sharing across threads.
pub trait ConsensusVerifier: Send + Sync + std::fmt::Debug {
    /// Verify a vote from a validator.
    ///
    /// Returns `Ok(())` if the vote is valid, or an error describing why
    /// verification failed.
    fn verify_vote(&self, validator: ValidatorId, vote: &Vote) -> Result<(), VerificationError>;

    /// Verify a block proposal from a validator.
    ///
    /// Returns `Ok(())` if the proposal is valid, or an error describing why
    /// verification failed.
    fn verify_proposal(
        &self,
        validator: ValidatorId,
        proposal: &BlockProposal,
    ) -> Result<(), VerificationError>;
}

/// A no-op verifier that accepts all messages.
///
/// This is the default verifier used in tests and until real cryptographic
/// verification is wired in. It always returns `Ok(())` for both votes
/// and proposals.
#[derive(Debug, Default, Clone)]
pub struct NoopConsensusVerifier;

impl ConsensusVerifier for NoopConsensusVerifier {
    fn verify_vote(&self, _validator: ValidatorId, _vote: &Vote) -> Result<(), VerificationError> {
        Ok(())
    }

    fn verify_proposal(
        &self,
        _validator: ValidatorId,
        _proposal: &BlockProposal,
    ) -> Result<(), VerificationError> {
        Ok(())
    }
}
