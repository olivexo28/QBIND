//! T102.1: BlockPayloadType roundtrip tests.
//!
//! These tests verify:
//! - BlockProposal encode/decode preserves payload_kind and next_epoch fields
//! - Changing payload_kind or next_epoch produces different signing preimages
//! - Normal and reconfig blocks round-trip correctly

use qbind_wire::consensus::{BlockHeader, BlockProposal};
use qbind_wire::io::{WireDecode, WireEncode};
use qbind_wire::{PAYLOAD_KIND_NORMAL, PAYLOAD_KIND_RECONFIG};

// ============================================================================
// BlockPayloadType roundtrip tests
// ============================================================================

#[test]
fn block_proposal_roundtrip_preserves_payload_kind_normal() {
    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            epoch: 0,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: PAYLOAD_KIND_NORMAL,
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
        decoded.header.payload_kind, PAYLOAD_KIND_NORMAL,
        "Normal payload_kind should survive roundtrip"
    );
    assert_eq!(
        decoded.header.next_epoch, 0,
        "next_epoch should survive roundtrip for normal blocks"
    );
    assert_eq!(proposal, decoded);
}

#[test]
fn block_proposal_roundtrip_preserves_payload_kind_reconfig() {
    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            epoch: 5,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: PAYLOAD_KIND_RECONFIG,
            next_epoch: 6, // Transition to epoch 6
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
        decoded.header.payload_kind, PAYLOAD_KIND_RECONFIG,
        "Reconfig payload_kind should survive roundtrip"
    );
    assert_eq!(
        decoded.header.next_epoch, 6,
        "next_epoch should survive roundtrip for reconfig blocks"
    );
    assert_eq!(proposal, decoded);
}

#[test]
fn block_proposal_roundtrip_preserves_various_next_epoch_values() {
    for next_epoch in [0, 1, 100, u64::MAX] {
        let proposal = BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 42,
                epoch: next_epoch.saturating_sub(1),
                height: 100,
                round: 5,
                parent_block_id: [0x11; 32],
                payload_hash: [0x22; 32],
                proposer_index: 3,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 1234567890,
                payload_kind: PAYLOAD_KIND_RECONFIG,
                next_epoch,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: vec![],
            signature: vec![],
        };

        let mut encoded = Vec::new();
        proposal.encode(&mut encoded);

        let mut input = encoded.as_slice();
        let decoded = BlockProposal::decode(&mut input).unwrap();

        assert_eq!(
            decoded.header.next_epoch, next_epoch,
            "next_epoch {} should survive roundtrip",
            next_epoch
        );
    }
}

// ============================================================================
// Signing preimage tests for payload_kind and next_epoch
// ============================================================================

#[test]
fn proposal_signing_preimage_changes_with_payload_kind() {
    let proposal_normal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 5,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    let proposal_reconfig = BlockProposal {
        header: BlockHeader {
            payload_kind: PAYLOAD_KIND_RECONFIG,
            next_epoch: 6, // Set a proper next_epoch for reconfig block
            ..proposal_normal.header.clone()
        },
        ..proposal_normal.clone()
    };

    let preimage_normal = proposal_normal.signing_preimage();
    let preimage_reconfig = proposal_reconfig.signing_preimage();

    assert_ne!(
        preimage_normal, preimage_reconfig,
        "Different payload_kind must produce different signing preimages"
    );
}

#[test]
fn proposal_signing_preimage_changes_with_next_epoch() {
    let proposal1 = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 5,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: PAYLOAD_KIND_RECONFIG,
            next_epoch: 6,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    let proposal2 = BlockProposal {
        header: BlockHeader {
            next_epoch: 7, // Different next_epoch
            ..proposal1.header.clone()
        },
        ..proposal1.clone()
    };

    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_ne!(
        preimage1, preimage2,
        "Different next_epoch must produce different signing preimages"
    );
}

#[test]
fn proposal_same_payload_type_same_preimage() {
    let proposal1 = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 5,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: PAYLOAD_KIND_RECONFIG,
            next_epoch: 6,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![0x11], // Different signature
    };

    let proposal2 = BlockProposal {
        signature: vec![0x22], // Different signature
        ..proposal1.clone()
    };

    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_eq!(
        preimage1, preimage2,
        "Same payload type with different signatures should have same preimage"
    );
}
