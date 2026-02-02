//! T101: Epoch field roundtrip and preimage tests.
//!
//! These tests verify:
//! - Vote, QC, and BlockProposal encode/decode preserve epoch field
//! - Changing epoch produces different signing preimages
//! - Different epochs produce different vote digests

use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};
use qbind_wire::io::{WireDecode, WireEncode};

// ============================================================================
// Vote epoch tests
// ============================================================================

#[test]
fn vote_roundtrip_preserves_epoch() {
    for epoch in [0, 1, 100, u64::MAX] {
        let vote = Vote {
            version: 1,
            chain_id: 42,
            epoch,
            height: 100,
            round: 5,
            step: 0,
            block_id: [0xAB; 32],
            validator_index: 7,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![0x11, 0x22],
        };

        let mut encoded = Vec::new();
        vote.encode(&mut encoded);

        let mut input = encoded.as_slice();
        let decoded = Vote::decode(&mut input).unwrap();

        assert_eq!(
            decoded.epoch, epoch,
            "Vote epoch should be preserved through roundtrip"
        );
        assert_eq!(vote, decoded);
    }
}

#[test]
fn vote_signing_preimage_changes_with_epoch() {
    let vote1 = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![],
    };

    let vote2 = Vote {
        epoch: 1, // Different epoch
        ..vote1.clone()
    };

    let preimage1 = vote1.signing_preimage();
    let preimage2 = vote2.signing_preimage();

    assert_ne!(
        preimage1, preimage2,
        "Different epochs must produce different signing preimages"
    );
}

#[test]
fn vote_same_epoch_same_preimage() {
    let vote1 = Vote {
        version: 1,
        chain_id: 1,
        epoch: 42,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![0x11],
    };

    let vote2 = Vote {
        signature: vec![0x22], // Different signature, same epoch
        ..vote1.clone()
    };

    let preimage1 = vote1.signing_preimage();
    let preimage2 = vote2.signing_preimage();

    assert_eq!(
        preimage1, preimage2,
        "Same epoch votes with different signatures should have same preimage"
    );
}

// ============================================================================
// QuorumCertificate epoch tests
// ============================================================================

#[test]
fn qc_roundtrip_preserves_epoch() {
    for epoch in [0, 1, 100, u64::MAX] {
        let qc = QuorumCertificate {
            version: 1,
            chain_id: 42,
            epoch,
            height: 100,
            round: 5,
            step: 1,
            block_id: [0xCD; 32],
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signer_bitmap: vec![0xFF],
            signatures: vec![vec![0x01, 0x02]],
        };

        let mut encoded = Vec::new();
        qc.encode(&mut encoded);

        let mut input = encoded.as_slice();
        let decoded = QuorumCertificate::decode(&mut input).unwrap();

        assert_eq!(
            decoded.epoch, epoch,
            "QuorumCertificate epoch should be preserved through roundtrip"
        );
        assert_eq!(qc, decoded);
    }
}

// ============================================================================
// BlockProposal epoch tests
// ============================================================================

#[test]
fn block_proposal_roundtrip_preserves_epoch() {
    for epoch in [0, 1, 100, u64::MAX] {
        let proposal = BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 42,
                epoch,
                height: 100,
                round: 5,
                parent_block_id: [0x11; 32],
                payload_hash: [0x22; 32],
                proposer_index: 3,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 1234567890,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: vec![],
            signature: vec![0xDE, 0xAD],
        };

        let mut encoded = Vec::new();
        proposal.encode(&mut encoded);

        let mut input = encoded.as_slice();
        let decoded = BlockProposal::decode(&mut input).unwrap();

        assert_eq!(
            decoded.header.epoch, epoch,
            "BlockProposal header.epoch should be preserved through roundtrip"
        );
        assert_eq!(proposal, decoded);
    }
}

#[test]
fn proposal_signing_preimage_changes_with_epoch() {
    let proposal1 = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    let proposal2 = BlockProposal {
        header: BlockHeader {
            epoch: 1, // Different epoch
            ..proposal1.header.clone()
        },
        ..proposal1.clone()
    };

    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_ne!(
        preimage1, preimage2,
        "Different epochs must produce different signing preimages"
    );
}

#[test]
fn proposal_with_qc_roundtrip_preserves_both_epochs() {
    let header_epoch = 5;
    let qc_epoch = 4; // QC from previous epoch

    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        epoch: qc_epoch,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0xFF],
        signatures: vec![vec![0xAA, 0xBB]],
    };

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            epoch: header_epoch,
            height: 100,
            round: 5,
            parent_block_id: [0x44; 32],
            payload_hash: [0x55; 32],
            proposer_index: 7,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 9876543210,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: Some(qc),
        txs: vec![],
        signature: vec![0x12, 0x34],
    };

    let mut encoded = Vec::new();
    proposal.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = BlockProposal::decode(&mut input).unwrap();

    assert_eq!(
        decoded.header.epoch, header_epoch,
        "BlockProposal header.epoch should be preserved"
    );
    assert_eq!(
        decoded.qc.as_ref().unwrap().epoch,
        qc_epoch,
        "Embedded QC epoch should be preserved"
    );
    assert_eq!(proposal, decoded);
}
