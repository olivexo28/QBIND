//! Verification job abstraction for multi-threaded consensus message verification (T147).
//!
//! This module provides generic job descriptions for consensus message verification:
//! - [`ConsensusMsgKind`]: The type of consensus message (proposal, vote, timeout)
//! - [`ConsensusVerifyJob`]: A job description carrying everything needed for verification
//! - [`ConsensusVerifyResult`]: The result of a verification job
//!
//! # Design
//!
//! The job abstraction is designed to be:
//! - **Agnostic of wire format**: Uses pre-computed signing preimages
//! - **Thread-safe**: Jobs can be processed by multiple worker threads
//! - **Complete**: Jobs carry all data needed for verification (suite_id, validator_id, etc.)
//!
//! # Usage
//!
//! ```ignore
//! // Create a job from an incoming vote
//! let job = ConsensusVerifyJob {
//!     kind: ConsensusMsgKind::Vote,
//!     view: vote.round,
//!     block_id: Some(vote.block_id),
//!     validator_id: ValidatorId::new(vote.validator_index as u64),
//!     suite_id: vote.suite_id,
//!     message_bytes: vote.signing_preimage(),
//!     signature: vote.signature.clone(),
//! };
//!
//! // Submit to verification pool
//! pool.submit(job)?;
//!
//! // Receive result
//! let result = pool.try_recv()?;
//! if result.ok {
//!     // Process verified message
//! }
//! ```

use crate::ids::ValidatorId;

/// The kind of consensus message being verified.
///
/// This enum distinguishes between different message types to enable
/// appropriate metrics tracking and logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConsensusMsgKind {
    /// A block proposal from a leader.
    Proposal,
    /// A vote for a block from a validator.
    Vote,
    /// A timeout message from a validator.
    Timeout,
    // Future: QC gossip, etc.
}

impl std::fmt::Display for ConsensusMsgKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConsensusMsgKind::Proposal => write!(f, "proposal"),
            ConsensusMsgKind::Vote => write!(f, "vote"),
            ConsensusMsgKind::Timeout => write!(f, "timeout"),
        }
    }
}

/// A job description for consensus message verification.
///
/// This struct carries everything a verifier worker needs to verify a consensus
/// message without requiring access to the original message structure or wire format.
///
/// # Type Parameter
///
/// - `BlockIdT`: The block identifier type (typically `[u8; 32]`)
///
/// # Fields
///
/// - `kind`: The type of message (proposal, vote, timeout)
/// - `view`: The view/round number of the message
/// - `block_id`: The block being referenced (optional for timeouts)
/// - `validator_id`: The validator who signed the message
/// - `suite_id`: The consensus signature suite identifier
/// - `message_bytes`: The canonical preimage to verify against
/// - `signature`: The signature to verify
///
/// # Note
///
/// The `message_bytes` should be the result of calling the appropriate
/// `signing_preimage()` or `signing_bytes()` method on the original message:
/// - For votes: `Vote::signing_preimage()`
/// - For proposals: `BlockProposal::signing_preimage()`
/// - For timeouts: `timeout_signing_bytes()`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusVerifyJob<BlockIdT: Eq> {
    /// The kind of consensus message.
    pub kind: ConsensusMsgKind,
    /// The view/round number this message is for.
    pub view: u64,
    /// The block ID being referenced, if applicable.
    /// Timeout messages may not have a specific block.
    pub block_id: Option<BlockIdT>,
    /// The validator who signed this message.
    pub validator_id: ValidatorId,
    /// The consensus signature suite identifier.
    /// Should be 100 for ML-DSA-44 in production.
    pub suite_id: u16,
    /// The canonical preimage bytes to verify.
    /// This is the output of the signing_preimage/signing_bytes function
    /// for the specific message type.
    pub message_bytes: Vec<u8>,
    /// The signature bytes to verify against the preimage.
    pub signature: Vec<u8>,
}

impl<BlockIdT: Clone + Eq> ConsensusVerifyJob<BlockIdT> {
    /// Create a new verification job for a vote.
    ///
    /// # Arguments
    ///
    /// - `view`: The view/round number of the vote
    /// - `block_id`: The block being voted for
    /// - `validator_id`: The validator who cast the vote
    /// - `suite_id`: The signature suite identifier
    /// - `message_bytes`: The signing preimage (from `Vote::signing_preimage()`)
    /// - `signature`: The signature bytes
    pub fn new_vote(
        view: u64,
        block_id: BlockIdT,
        validator_id: ValidatorId,
        suite_id: u16,
        message_bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        ConsensusVerifyJob {
            kind: ConsensusMsgKind::Vote,
            view,
            block_id: Some(block_id),
            validator_id,
            suite_id,
            message_bytes,
            signature,
        }
    }

    /// Create a new verification job for a proposal.
    ///
    /// # Arguments
    ///
    /// - `view`: The view/round number of the proposal
    /// - `block_id`: The block being proposed (payload_hash)
    /// - `validator_id`: The proposer's validator ID
    /// - `suite_id`: The signature suite identifier
    /// - `message_bytes`: The signing preimage (from `BlockProposal::signing_preimage()`)
    /// - `signature`: The signature bytes
    pub fn new_proposal(
        view: u64,
        block_id: BlockIdT,
        validator_id: ValidatorId,
        suite_id: u16,
        message_bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        ConsensusVerifyJob {
            kind: ConsensusMsgKind::Proposal,
            view,
            block_id: Some(block_id),
            validator_id,
            suite_id,
            message_bytes,
            signature,
        }
    }

    /// Create a new verification job for a timeout message.
    ///
    /// # Arguments
    ///
    /// - `view`: The view being timed out
    /// - `validator_id`: The validator sending the timeout
    /// - `suite_id`: The signature suite identifier
    /// - `message_bytes`: The signing bytes (from `timeout_signing_bytes()`)
    /// - `signature`: The signature bytes
    pub fn new_timeout(
        view: u64,
        validator_id: ValidatorId,
        suite_id: u16,
        message_bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        ConsensusVerifyJob {
            kind: ConsensusMsgKind::Timeout,
            view,
            block_id: None,
            validator_id,
            suite_id,
            message_bytes,
            signature,
        }
    }
}

/// The result of a consensus message verification job.
///
/// This struct is returned by verification worker threads to indicate
/// whether a job succeeded or failed.
///
/// # Type Parameter
///
/// - `BlockIdT`: The block identifier type (typically `[u8; 32]`)
///
/// # Fields
///
/// - `job`: The original verification job
/// - `ok`: Whether verification succeeded
/// - `error`: Optional error message if verification failed
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusVerifyResult<BlockIdT: Eq> {
    /// The original job that was verified.
    pub job: ConsensusVerifyJob<BlockIdT>,
    /// Whether the verification succeeded.
    pub ok: bool,
    /// Error detail if verification failed.
    /// Only set when `ok == false`.
    pub error: Option<String>,
}

impl<BlockIdT: Clone + Eq> ConsensusVerifyResult<BlockIdT> {
    /// Create a successful verification result.
    pub fn success(job: ConsensusVerifyJob<BlockIdT>) -> Self {
        ConsensusVerifyResult {
            job,
            ok: true,
            error: None,
        }
    }

    /// Create a failed verification result.
    pub fn failure(job: ConsensusVerifyJob<BlockIdT>, error: impl Into<String>) -> Self {
        ConsensusVerifyResult {
            job,
            ok: false,
            error: Some(error.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consensus_msg_kind_display() {
        assert_eq!(ConsensusMsgKind::Proposal.to_string(), "proposal");
        assert_eq!(ConsensusMsgKind::Vote.to_string(), "vote");
        assert_eq!(ConsensusMsgKind::Timeout.to_string(), "timeout");
    }

    #[test]
    fn test_new_vote_job() {
        let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
            10,
            [1u8; 32],
            ValidatorId::new(1),
            100,
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        assert_eq!(job.kind, ConsensusMsgKind::Vote);
        assert_eq!(job.view, 10);
        assert_eq!(job.block_id, Some([1u8; 32]));
        assert_eq!(job.validator_id, ValidatorId::new(1));
        assert_eq!(job.suite_id, 100);
        assert_eq!(job.message_bytes, vec![1, 2, 3]);
        assert_eq!(job.signature, vec![4, 5, 6]);
    }

    #[test]
    fn test_new_proposal_job() {
        let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_proposal(
            20,
            [2u8; 32],
            ValidatorId::new(2),
            100,
            vec![7, 8, 9],
            vec![10, 11, 12],
        );

        assert_eq!(job.kind, ConsensusMsgKind::Proposal);
        assert_eq!(job.view, 20);
        assert_eq!(job.block_id, Some([2u8; 32]));
        assert_eq!(job.validator_id, ValidatorId::new(2));
        assert_eq!(job.suite_id, 100);
    }

    #[test]
    fn test_new_timeout_job() {
        let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_timeout(
            30,
            ValidatorId::new(3),
            100,
            vec![13, 14, 15],
            vec![16, 17, 18],
        );

        assert_eq!(job.kind, ConsensusMsgKind::Timeout);
        assert_eq!(job.view, 30);
        assert_eq!(job.block_id, None);
        assert_eq!(job.validator_id, ValidatorId::new(3));
        assert_eq!(job.suite_id, 100);
    }

    #[test]
    fn test_verify_result_success() {
        let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
            10,
            [1u8; 32],
            ValidatorId::new(1),
            100,
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        let result = ConsensusVerifyResult::success(job);
        assert!(result.ok);
        assert!(result.error.is_none());
        assert_eq!(result.job.kind, ConsensusMsgKind::Vote);
    }

    #[test]
    fn test_verify_result_failure() {
        let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
            10,
            [1u8; 32],
            ValidatorId::new(1),
            100,
            vec![1, 2, 3],
            vec![4, 5, 6],
        );

        let result = ConsensusVerifyResult::failure(job, "invalid signature");
        assert!(!result.ok);
        assert_eq!(result.error, Some("invalid signature".to_string()));
    }
}
