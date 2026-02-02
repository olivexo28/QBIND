use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};
use qbind_wire::io::{WireDecode, WireEncode};

#[test]
fn roundtrip_vote() {
    let vote = Vote {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let mut encoded = Vec::new();
    vote.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = Vote::decode(&mut input).unwrap();

    assert_eq!(vote, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_qc() {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 100,
        round: 5,
        step: 1,
        block_id: [0xCD; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0xFF, 0x00, 0xFF, 0x00, 0xAA, 0xBB, 0xCC, 0xDD],
        signatures: vec![
            vec![0x01, 0x02, 0x03, 0x04, 0x05],
            vec![0x06, 0x07, 0x08, 0x09, 0x0A],
        ],
    };

    let mut encoded = Vec::new();
    qc.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = QuorumCertificate::decode(&mut input).unwrap();

    assert_eq!(qc, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_block_proposal_no_qc() {
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
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
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

    assert_eq!(proposal, decoded);
    assert!(input.is_empty());
}

#[test]
fn roundtrip_block_proposal_with_qc_and_txs() {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00],
        signatures: vec![
            vec![0xAA, 0xBB, 0xCC, 0xDD, 0xEE],
            vec![0x11, 0x22, 0x33, 0x44, 0x55],
        ],
    };

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 42,
            epoch: 0,
            height: 100,
            round: 5,
            parent_block_id: [0x44; 32],
            payload_hash: [0x55; 32],
            proposer_index: 7,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 2,
            timestamp: 9876543210,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: Some(qc),
        txs: vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05, 0x06, 0x07]],
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    let mut encoded = Vec::new();
    proposal.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = BlockProposal::decode(&mut input).unwrap();

    assert_eq!(proposal, decoded);
    assert!(input.is_empty());
}

#[test]
fn vote_encoded_length_ml_dsa_like() {
    // Test Vote with ML-DSA-like sig length (3309 bytes)
    let vote = Vote {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![0x00; 3309], // ML-DSA-like signature
    };

    let mut encoded = Vec::new();
    vote.encode(&mut encoded);

    // Expected length (with epoch field):
    // msg_type: 1 + version: 1 + chain_id: 4 + epoch: 8 + height: 8 + round: 8 + step: 1 +
    // block_id: 32 + validator_index: 2 + suite_id: 2 + sig_len: 2 + sig: 3309
    // = 1 + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2 + 2 + 3309 = 3378
    assert_eq!(
        encoded.len(),
        1 + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2 + 2 + 3309
    );

    // Verify round-trip
    let mut input = encoded.as_slice();
    let decoded = Vote::decode(&mut input).unwrap();
    assert_eq!(vote, decoded);
}

#[test]
fn qc_encoded_length() {
    // Test QC with bitmap_len = 8, 2 signatures of len 5 each
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 100,
        round: 5,
        step: 1,
        block_id: [0xCD; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0xFF, 0x00, 0xFF, 0x00, 0xAA, 0xBB, 0xCC, 0xDD], // 8 bytes
        signatures: vec![
            vec![0x01, 0x02, 0x03, 0x04, 0x05], // 5 bytes
            vec![0x06, 0x07, 0x08, 0x09, 0x0A], // 5 bytes
        ],
    };

    let mut encoded = Vec::new();
    qc.encode(&mut encoded);

    // Expected length (with epoch field):
    // msg_type: 1 + version: 1 + chain_id: 4 + epoch: 8 + height: 8 + round: 8 + step: 1 +
    // block_id: 32 + suite_id: 2 + bitmap_len: 2 + signer_bitmap: 8 + sig_count: 2 +
    // (sig_len: 2 + sig: 5) * 2
    // = 1 + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2 + 8 + 2 + (2 + 5) * 2
    // = 77 + 14 = 91
    assert_eq!(
        encoded.len(),
        1 + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2 + 8 + 2 + 14
    );

    // Verify round-trip
    let mut input = encoded.as_slice();
    let decoded = QuorumCertificate::decode(&mut input).unwrap();
    assert_eq!(qc, decoded);
}

// ============================================================================
// T81: suite_id preservation tests
// ============================================================================

/// Test that Vote serialization roundtrip preserves suite_id.
/// This test uses a non-default suite ID to verify it's actually being encoded/decoded.
#[test]
fn vote_serialization_roundtrip_preserves_suite_id() {
    // Use a custom suite_id (not the default 0) to verify it's actually being preserved
    let custom_suite_id: u16 = 42;

    let vote = Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 100,
        round: 5,
        step: 0,
        block_id: [0xAB; 32],
        validator_index: 7,
        suite_id: custom_suite_id,
        signature: vec![0x11, 0x22, 0x33, 0x44, 0x55],
    };

    let mut encoded = Vec::new();
    vote.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = Vote::decode(&mut input).unwrap();

    // Explicitly check suite_id is preserved
    assert_eq!(
        decoded.suite_id, custom_suite_id,
        "Vote suite_id must be preserved through serialization"
    );
    assert_eq!(vote, decoded);
    assert!(input.is_empty());
}

/// Test that QuorumCertificate serialization roundtrip preserves suite_id.
/// This test uses a non-default suite ID to verify it's actually being encoded/decoded.
#[test]
fn qc_serialization_roundtrip_preserves_suite_id() {
    // Use a custom suite_id (not the default 0) to verify it's actually being preserved
    let custom_suite_id: u16 = 123;

    let qc = QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 100,
        round: 5,
        step: 1,
        block_id: [0xCD; 32],
        suite_id: custom_suite_id,
        signer_bitmap: vec![0xFF, 0x00],
        signatures: vec![vec![0x01, 0x02, 0x03]],
    };

    let mut encoded = Vec::new();
    qc.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = QuorumCertificate::decode(&mut input).unwrap();

    // Explicitly check suite_id is preserved
    assert_eq!(
        decoded.suite_id, custom_suite_id,
        "QuorumCertificate suite_id must be preserved through serialization"
    );
    assert_eq!(qc, decoded);
    assert!(input.is_empty());
}

/// Test that BlockProposal serialization roundtrip preserves suite_id in header.
/// This test uses a non-default suite ID to verify it's actually being encoded/decoded.
#[test]
fn block_proposal_serialization_roundtrip_preserves_suite_id() {
    // Use a custom suite_id (not the default 0) to verify it's actually being preserved
    let custom_suite_id: u16 = 999;

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 100,
            round: 5,
            parent_block_id: [0x11; 32],
            payload_hash: [0x22; 32],
            proposer_index: 3,
            suite_id: custom_suite_id,
            tx_count: 0,
            timestamp: 1234567890,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
    };

    let mut encoded = Vec::new();
    proposal.encode(&mut encoded);

    let mut input = encoded.as_slice();
    let decoded = BlockProposal::decode(&mut input).unwrap();

    // Explicitly check suite_id is preserved
    assert_eq!(
        decoded.header.suite_id, custom_suite_id,
        "BlockProposal header.suite_id must be preserved through serialization"
    );
    assert_eq!(proposal, decoded);
    assert!(input.is_empty());
}

/// Test that BlockProposal with embedded QC preserves both suite_ids.
#[test]
fn block_proposal_with_qc_preserves_both_suite_ids() {
    let header_suite_id: u16 = 111;
    let qc_suite_id: u16 = 222;

    let qc = QuorumCertificate {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        suite_id: qc_suite_id,
        signer_bitmap: vec![0xFF],
        signatures: vec![vec![0xAA, 0xBB]],
    };

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 100,
            round: 5,
            parent_block_id: [0x33; 32],
            payload_hash: [0x44; 32],
            proposer_index: 7,
            suite_id: header_suite_id,
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

    // Check both suite_ids are preserved
    assert_eq!(
        decoded.header.suite_id, header_suite_id,
        "BlockProposal header.suite_id must be preserved"
    );
    assert_eq!(
        decoded.qc.as_ref().unwrap().suite_id,
        qc_suite_id,
        "Embedded QC suite_id must be preserved"
    );
    assert_eq!(proposal, decoded);
    assert!(input.is_empty());
}