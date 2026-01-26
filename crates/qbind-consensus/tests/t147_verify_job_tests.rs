//! T147: Unit tests for ConsensusVerifyJob types.
//!
//! These tests verify that:
//! - ConsensusVerifyJob creation works correctly for votes, proposals, and timeouts
//! - message_bytes matches existing signing preimage functions
//! - suite_id and validator_id are preserved correctly

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::timeout::timeout_signing_bytes;
use qbind_consensus::verify_job::{ConsensusMsgKind, ConsensusVerifyJob, ConsensusVerifyResult};
use qbind_consensus::QuorumCertificate;

// ============================================================================
// ConsensusMsgKind tests
// ============================================================================

#[test]
fn test_consensus_msg_kind_display() {
    assert_eq!(ConsensusMsgKind::Proposal.to_string(), "proposal");
    assert_eq!(ConsensusMsgKind::Vote.to_string(), "vote");
    assert_eq!(ConsensusMsgKind::Timeout.to_string(), "timeout");
}

#[test]
fn test_consensus_msg_kind_equality() {
    assert_eq!(ConsensusMsgKind::Proposal, ConsensusMsgKind::Proposal);
    assert_eq!(ConsensusMsgKind::Vote, ConsensusMsgKind::Vote);
    assert_eq!(ConsensusMsgKind::Timeout, ConsensusMsgKind::Timeout);
    assert_ne!(ConsensusMsgKind::Proposal, ConsensusMsgKind::Vote);
}

#[test]
fn test_consensus_msg_kind_hash() {
    use std::collections::HashSet;

    let mut set = HashSet::new();
    set.insert(ConsensusMsgKind::Proposal);
    set.insert(ConsensusMsgKind::Vote);
    set.insert(ConsensusMsgKind::Timeout);

    assert!(set.contains(&ConsensusMsgKind::Proposal));
    assert!(set.contains(&ConsensusMsgKind::Vote));
    assert!(set.contains(&ConsensusMsgKind::Timeout));
    assert_eq!(set.len(), 3);
}

// ============================================================================
// ConsensusVerifyJob creation tests
// ============================================================================

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
    assert_eq!(job.message_bytes, vec![7, 8, 9]);
    assert_eq!(job.signature, vec![10, 11, 12]);
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
    assert_eq!(job.block_id, None); // Timeout messages don't have a block_id
    assert_eq!(job.validator_id, ValidatorId::new(3));
    assert_eq!(job.suite_id, 100);
    assert_eq!(job.message_bytes, vec![13, 14, 15]);
    assert_eq!(job.signature, vec![16, 17, 18]);
}

// ============================================================================
// Signing preimage consistency tests
// ============================================================================

#[test]
fn test_vote_job_preimage_matches_wire() {
    use qbind_wire::consensus::Vote;

    // Create a vote and get its signing preimage
    let vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 100,
        round: 10,
        step: 0,
        block_id: [1u8; 32],
        validator_index: 1,
        suite_id: 100,
        signature: vec![0u8; 64],
    };

    let preimage = vote.signing_preimage();

    // Create a job with the same preimage
    let job = ConsensusVerifyJob::new_vote(
        vote.round,
        vote.block_id,
        ValidatorId::new(vote.validator_index as u64),
        vote.suite_id,
        preimage.clone(),
        vote.signature.clone(),
    );

    // The job's message_bytes should match the vote's signing_preimage
    assert_eq!(job.message_bytes, preimage);
    assert_eq!(job.suite_id, vote.suite_id);
    assert_eq!(
        job.validator_id,
        ValidatorId::new(vote.validator_index as u64)
    );
}

#[test]
fn test_proposal_job_preimage_matches_wire() {
    use qbind_wire::consensus::{BlockHeader, BlockProposal};

    // Create a proposal and get its signing preimage
    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 100,
            round: 10,
            parent_block_id: [0u8; 32],
            payload_hash: [2u8; 32],
            proposer_index: 1,
            suite_id: 100,
            tx_count: 0,
            timestamp: 12345,
            payload_kind: 0,
            next_epoch: 0,
        },
        qc: None,
        txs: vec![],
        signature: vec![0u8; 64],
    };

    let preimage = proposal.signing_preimage();

    // Create a job with the same preimage
    let job = ConsensusVerifyJob::new_proposal(
        proposal.header.round,
        proposal.header.payload_hash,
        ValidatorId::new(proposal.header.proposer_index as u64),
        proposal.header.suite_id,
        preimage.clone(),
        proposal.signature.clone(),
    );

    // The job's message_bytes should match the proposal's signing_preimage
    assert_eq!(job.message_bytes, preimage);
    assert_eq!(job.suite_id, proposal.header.suite_id);
}

#[test]
fn test_timeout_job_preimage_matches_timeout_signing_bytes() {
    let view = 10u64;
    let validator_id = ValidatorId::new(1);
    let high_qc = Some(QuorumCertificate::new([1u8; 32], 5, vec![validator_id]));

    // Get the timeout signing bytes
    let preimage = timeout_signing_bytes(view, high_qc.as_ref(), validator_id);

    // Create a job with the same preimage
    let job: ConsensusVerifyJob<[u8; 32]> =
        ConsensusVerifyJob::new_timeout(view, validator_id, 100, preimage.clone(), vec![0u8; 64]);

    // The job's message_bytes should match the timeout_signing_bytes
    assert_eq!(job.message_bytes, preimage);
}

#[test]
fn test_timeout_signing_bytes_without_high_qc() {
    let view = 20u64;
    let validator_id = ValidatorId::new(2);

    // Get the timeout signing bytes without a high_qc
    let preimage: Vec<u8> = timeout_signing_bytes::<[u8; 32]>(view, None, validator_id);

    // Create a job with the same preimage
    let job: ConsensusVerifyJob<[u8; 32]> =
        ConsensusVerifyJob::new_timeout(view, validator_id, 100, preimage.clone(), vec![0u8; 64]);

    // Verify the preimage is stored correctly
    assert_eq!(job.message_bytes, preimage);
    assert_eq!(job.view, view);
    assert_eq!(job.validator_id, validator_id);
}

// ============================================================================
// ConsensusVerifyResult tests
// ============================================================================

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

    let result = ConsensusVerifyResult::success(job.clone());

    assert!(result.ok);
    assert!(result.error.is_none());
    assert_eq!(result.job.kind, ConsensusMsgKind::Vote);
    assert_eq!(result.job.view, 10);
    assert_eq!(result.job.validator_id, ValidatorId::new(1));
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

    let result = ConsensusVerifyResult::failure(job.clone(), "invalid signature");

    assert!(!result.ok);
    assert_eq!(result.error, Some("invalid signature".to_string()));
    assert_eq!(result.job.kind, ConsensusMsgKind::Vote);
}

#[test]
fn test_verify_result_failure_with_string_error() {
    let job: ConsensusVerifyJob<[u8; 32]> =
        ConsensusVerifyJob::new_proposal(20, [2u8; 32], ValidatorId::new(2), 100, vec![], vec![]);

    let error = String::from("missing key for validator");
    let result = ConsensusVerifyResult::failure(job.clone(), error);

    assert!(!result.ok);
    assert_eq!(result.error, Some("missing key for validator".to_string()));
}

// ============================================================================
// Job cloning tests
// ============================================================================

#[test]
fn test_job_clone() {
    let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
        10,
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![1, 2, 3, 4, 5],
        vec![6, 7, 8, 9, 10],
    );

    let cloned = job.clone();

    assert_eq!(cloned.kind, job.kind);
    assert_eq!(cloned.view, job.view);
    assert_eq!(cloned.block_id, job.block_id);
    assert_eq!(cloned.validator_id, job.validator_id);
    assert_eq!(cloned.suite_id, job.suite_id);
    assert_eq!(cloned.message_bytes, job.message_bytes);
    assert_eq!(cloned.signature, job.signature);
}

#[test]
fn test_result_clone() {
    let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
        10,
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![1, 2, 3],
        vec![4, 5, 6],
    );

    let result = ConsensusVerifyResult::failure(job, "test error");
    let cloned = result.clone();

    assert_eq!(cloned.ok, result.ok);
    assert_eq!(cloned.error, result.error);
    assert_eq!(cloned.job.view, result.job.view);
}

// ============================================================================
// Suite ID preservation tests
// ============================================================================

#[test]
fn test_suite_id_preserved_for_ml_dsa_44() {
    // ML-DSA-44 suite ID is 100
    const ML_DSA_44_SUITE_ID: u16 = 100;

    let job = ConsensusVerifyJob::new_vote(
        10,
        [1u8; 32],
        ValidatorId::new(1),
        ML_DSA_44_SUITE_ID,
        vec![],
        vec![],
    );

    assert_eq!(job.suite_id, ML_DSA_44_SUITE_ID);
}

#[test]
fn test_suite_id_preserved_for_different_suites() {
    // Test with different suite IDs
    for suite_id in [0u16, 1, 100, 200, u16::MAX] {
        let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
            10,
            [1u8; 32],
            ValidatorId::new(1),
            suite_id,
            vec![],
            vec![],
        );

        assert_eq!(
            job.suite_id, suite_id,
            "suite_id {} was not preserved",
            suite_id
        );
    }
}

// ============================================================================
// ValidatorId preservation tests
// ============================================================================

#[test]
fn test_validator_id_preserved() {
    for id in [0u64, 1, 100, u64::MAX] {
        let validator_id = ValidatorId::new(id);
        let job: ConsensusVerifyJob<[u8; 32]> =
            ConsensusVerifyJob::new_vote(10, [1u8; 32], validator_id, 100, vec![], vec![]);

        assert_eq!(job.validator_id, validator_id);
        assert_eq!(job.validator_id.as_u64(), id);
    }
}

// ============================================================================
// Edge case tests
// ============================================================================

#[test]
fn test_job_with_empty_signature() {
    let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
        10,
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![1, 2, 3],
        vec![], // Empty signature
    );

    assert!(job.signature.is_empty());
}

#[test]
fn test_job_with_empty_message_bytes() {
    let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
        10,
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![], // Empty message bytes
        vec![1, 2, 3],
    );

    assert!(job.message_bytes.is_empty());
}

#[test]
fn test_job_with_large_signature() {
    // ML-DSA-44 signatures are about 2420 bytes
    let large_sig = vec![0xABu8; 2420];

    let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
        10,
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![1, 2, 3],
        large_sig.clone(),
    );

    assert_eq!(job.signature.len(), 2420);
    assert_eq!(job.signature, large_sig);
}

#[test]
fn test_job_view_zero() {
    let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
        0, // View 0
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![],
        vec![],
    );

    assert_eq!(job.view, 0);
}

#[test]
fn test_job_view_max() {
    let job: ConsensusVerifyJob<[u8; 32]> = ConsensusVerifyJob::new_vote(
        u64::MAX, // Max view
        [1u8; 32],
        ValidatorId::new(1),
        100,
        vec![],
        vec![],
    );

    assert_eq!(job.view, u64::MAX);
}
