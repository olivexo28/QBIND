//! Tests for signing preimage helpers on Vote and BlockProposal.
//!
//! These tests verify:
//! - signing_preimage() excludes the signature field
//! - signing_preimage() produces stable output for fixed inputs
//! - Changing signature does not change the preimage
//!
//! ## T159: Chain-Aware Domain Separation
//!
//! These tests verify the default DevNet chain-aware domain tags.
//! The `signing_preimage()` method now defaults to `QBIND_DEVNET_CHAIN_ID`,
//! producing domain tags like "QBIND:DEV:VOTE:v1" instead of "QBIND:VOTE:v1".

use qbind_types::domain::{domain_prefix, DomainKind};
use qbind_types::{QBIND_DEVNET_CHAIN_ID, QBIND_TESTNET_CHAIN_ID};
use qbind_wire::consensus::{BlockHeader, BlockProposal, QuorumCertificate, Vote};

// ============================================================================
// Vote signing preimage tests
// ============================================================================

/// Helper to create a dummy Vote for testing.
fn make_dummy_vote() -> Vote {
    Vote {
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
    }
}

#[test]
fn vote_signing_preimage_excludes_signature() {
    // Build a Vote with non-empty signature bytes
    let sig = vec![0x11, 0x22, 0x33, 0x44, 0x55];
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
        signature: sig.clone(),
    };

    // Call signing_preimage()
    let preimage = vote.signing_preimage();

    // Assert that the resulting bytes do not contain the exact signature byte sequence
    let found = preimage.windows(sig.len()).any(|w| w == sig.as_slice());
    assert!(
        !found,
        "signing_preimage() should not contain the exact signature bytes"
    );

    // Also assert that changing the signature field does not change the preimage
    let mut vote2 = vote.clone();
    vote2.signature = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let preimage2 = vote2.signing_preimage();
    assert_eq!(
        preimage, preimage2,
        "Changing signature should not change the preimage"
    );

    // And a vote with empty signature should produce the same preimage
    let mut vote3 = vote.clone();
    vote3.signature = vec![];
    let preimage3 = vote3.signing_preimage();
    assert_eq!(
        preimage, preimage3,
        "Empty signature should produce the same preimage"
    );
}

#[test]
fn vote_signing_preimage_stable_for_fields() {
    // Create a Vote with fixed field values and empty signature
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
        signature: vec![],
    };

    // Call signing_preimage() and compare to expected
    let preimage = vote.signing_preimage();

    // T159: Domain tag is now chain-aware
    // Build expected preimage manually (with epoch field - T101, chain-aware - T159):
    // domain_tag: "QBIND:DEV:VOTE:v1" (17 bytes for DevNet)
    // version: u8 (1)
    // chain_id: u32 LE (42)
    // epoch: u64 LE (0)
    // height: u64 LE (100)
    // round: u64 LE (5)
    // step: u8 (0)
    // block_id: [0xAB; 32]
    // validator_index: u16 LE (7)
    // suite_id: u16 LE (0)
    let devnet_vote_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Vote);
    let mut expected = Vec::new();
    expected.extend_from_slice(&devnet_vote_tag); // "QBIND:DEV:VOTE:v1"
    expected.push(1u8); // version
    expected.extend_from_slice(&42u32.to_le_bytes()); // chain_id
    expected.extend_from_slice(&0u64.to_le_bytes()); // epoch (T101)
    expected.extend_from_slice(&100u64.to_le_bytes()); // height
    expected.extend_from_slice(&5u64.to_le_bytes()); // round
    expected.push(0u8); // step
    expected.extend_from_slice(&[0xAB; 32]); // block_id
    expected.extend_from_slice(&7u16.to_le_bytes()); // validator_index
    expected.extend_from_slice(&0u16.to_le_bytes()); // suite_id

    assert_eq!(
        preimage, expected,
        "Vote signing preimage does not match expected layout"
    );

    // T159: Hard-coded expected bytes updated for chain-aware domain tag
    // "QBIND:DEV:VOTE:v1" = [0x51, 0x42, 0x49, 0x4e, 0x44, 0x3a, 0x44, 0x45, 0x56, 0x3a, 0x56, 0x4f, 0x54, 0x45, 0x3a, 0x76, 0x31] (17 bytes)
    let expected_bytes: Vec<u8> = vec![
        // "QBIND:DEV:VOTE:v1" (17 bytes)
        0x51, 0x42, 0x49, 0x4e, 0x44, 0x3a, 0x44, 0x45, 0x56, 0x3a, 0x56, 0x4f, 0x54, 0x45, 0x3a,
        0x76, 0x31, // version: 1
        0x01, // chain_id: 42 (LE)
        0x2a, 0x00, 0x00, 0x00, // epoch: 0 (LE) - T101
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // height: 100 (LE)
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // round: 5 (LE)
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // step: 0
        0x00, // block_id: [0xAB; 32]
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
        0xab, 0xab, // validator_index: 7 (LE)
        0x07, 0x00, // suite_id: 0 (LE)
        0x00, 0x00,
    ];
    assert_eq!(
        preimage, expected_bytes,
        "Vote signing preimage bytes do not match hard-coded expected value"
    );
}

#[test]
fn vote_signing_preimage_starts_with_domain_tag() {
    let vote = make_dummy_vote();
    let preimage = vote.signing_preimage();

    // T159: Domain tag is now chain-aware (DevNet by default)
    let devnet_vote_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Vote);
    assert!(
        preimage.starts_with(&devnet_vote_tag),
        "Vote signing preimage must start with DevNet domain tag"
    );
}

#[test]
fn vote_signing_preimage_length_is_correct() {
    let vote = make_dummy_vote();
    let preimage = vote.signing_preimage();

    // T159: Expected length with chain-aware domain tag
    // domain_tag: 17 bytes ("QBIND:DEV:VOTE:v1")
    // version: 1
    // chain_id: 4
    // epoch: 8
    // height: 8
    // round: 8
    // step: 1
    // block_id: 32
    // validator_index: 2
    // suite_id: 2
    // Total: 17 + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2 = 83
    let expected_len = 17 + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2;
    assert_eq!(preimage.len(), expected_len);
}

// ============================================================================
// BlockProposal signing preimage tests
// ============================================================================

/// Helper to create a dummy BlockProposal for testing.
fn make_dummy_block_proposal() -> BlockProposal {
    BlockProposal {
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
        },
        qc: None,
        txs: vec![],
        signature: vec![0xDE, 0xAD, 0xBE, 0xEF],
    }
}

/// Helper to create a BlockProposal with a QC.
fn make_proposal_with_qc() -> BlockProposal {
    let qc = QuorumCertificate {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0xFF, 0x00],
        signatures: vec![vec![0xAA, 0xBB]],
    };

    BlockProposal {
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
            tx_count: 2,
            timestamp: 1234567890,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
        },
        qc: Some(qc),
        txs: vec![vec![0x01, 0x02, 0x03], vec![0x04, 0x05]],
        signature: vec![0xDE, 0xAD],
    }
}

#[test]
fn proposal_signing_preimage_excludes_signature() {
    // Build a BlockProposal with non-empty signature bytes
    let sig = vec![0xDE, 0xAD, 0xBE, 0xEF];
    let mut proposal = make_dummy_block_proposal();
    proposal.signature = sig.clone();

    // Call signing_preimage()
    let preimage = proposal.signing_preimage();

    // Assert that the resulting bytes do not contain the exact signature byte sequence
    let found = preimage.windows(sig.len()).any(|w| w == sig.as_slice());
    assert!(
        !found,
        "signing_preimage() should not contain the exact signature bytes"
    );

    // Also assert that changing the signature field does not change the preimage
    let mut proposal2 = proposal.clone();
    proposal2.signature = vec![0x11, 0x22, 0x33, 0x44, 0x55];
    let preimage2 = proposal2.signing_preimage();
    assert_eq!(
        preimage, preimage2,
        "Changing signature should not change the preimage"
    );

    // And a proposal with empty signature should produce the same preimage
    let mut proposal3 = proposal.clone();
    proposal3.signature = vec![];
    let preimage3 = proposal3.signing_preimage();
    assert_eq!(
        preimage, preimage3,
        "Empty signature should produce the same preimage"
    );
}

#[test]
fn proposal_signing_preimage_stable_for_fields() {
    // Create a BlockProposal with fixed field values and empty signature, no QC, no txs
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
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    };

    // Call signing_preimage()
    let preimage = proposal.signing_preimage();

    // T159: Build expected preimage manually with chain-aware domain tag
    // domain_tag: "QBIND:DEV:PROPOSAL:v1" (21 bytes for DevNet)
    // version: u8 (1)
    // chain_id: u32 LE (42)
    // epoch: u64 LE (0)
    // height: u64 LE (100)
    // round: u64 LE (5)
    // parent_block_id: [0x11; 32]
    // payload_hash: [0x22; 32]
    // proposer_index: u16 LE (3)
    // suite_id: u16 LE (0)
    // tx_count: u32 LE (0)
    // timestamp: u64 LE (1234567890)
    // payload_kind: u8 (0) - T102.1
    // next_epoch: u64 LE (0) - T102.1
    // qc_len: u32 LE (0)
    // (no qc_bytes)
    // (no txs)
    let devnet_proposal_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Proposal);
    let mut expected = Vec::new();
    expected.extend_from_slice(&devnet_proposal_tag); // "QBIND:DEV:PROPOSAL:v1"
    expected.push(1u8); // version
    expected.extend_from_slice(&42u32.to_le_bytes()); // chain_id
    expected.extend_from_slice(&0u64.to_le_bytes()); // epoch (T101)
    expected.extend_from_slice(&100u64.to_le_bytes()); // height
    expected.extend_from_slice(&5u64.to_le_bytes()); // round
    expected.extend_from_slice(&[0x11; 32]); // parent_block_id
    expected.extend_from_slice(&[0x22; 32]); // payload_hash
    expected.extend_from_slice(&3u16.to_le_bytes()); // proposer_index
    expected.extend_from_slice(&0u16.to_le_bytes()); // suite_id
    expected.extend_from_slice(&0u32.to_le_bytes()); // tx_count
    expected.extend_from_slice(&1234567890u64.to_le_bytes()); // timestamp
    expected.push(0u8); // payload_kind (T102.1)
    expected.extend_from_slice(&0u64.to_le_bytes()); // next_epoch (T102.1)
    expected.extend_from_slice(&0u32.to_le_bytes()); // qc_len = 0

    assert_eq!(
        preimage, expected,
        "BlockProposal signing preimage does not match expected layout"
    );

    // T159: Hard-coded expected bytes updated for chain-aware domain tag
    // "QBIND:DEV:PROPOSAL:v1" (21 bytes)
    let expected_bytes: Vec<u8> = vec![
        // "QBIND:DEV:PROPOSAL:v1" (21 bytes)
        0x51, 0x42, 0x49, 0x4e, 0x44, 0x3a, 0x44, 0x45, 0x56, 0x3a, 0x50, 0x52, 0x4f, 0x50, 0x4f,
        0x53, 0x41, 0x4c, 0x3a, 0x76, 0x31, // version: 1
        0x01, // chain_id: 42 (LE)
        0x2a, 0x00, 0x00, 0x00, // epoch: 0 (LE) - T101
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // height: 100 (LE)
        0x64, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // round: 5 (LE)
        0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // parent_block_id: [0x11; 32]
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
        0x11, 0x11, // payload_hash: [0x22; 32]
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
        0x22, 0x22, // proposer_index: 3 (LE)
        0x03, 0x00, // suite_id: 0 (LE)
        0x00, 0x00, // tx_count: 0 (LE)
        0x00, 0x00, 0x00, 0x00, // timestamp: 1234567890 (LE)
        0xd2, 0x02, 0x96, 0x49, 0x00, 0x00, 0x00, 0x00, // payload_kind: 0 (T102.1)
        0x00, // next_epoch: 0 (LE) (T102.1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qc_len: 0 (LE)
        0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(
        preimage, expected_bytes,
        "BlockProposal signing preimage bytes do not match hard-coded expected value"
    );
}

#[test]
fn proposal_signing_preimage_starts_with_domain_tag() {
    let proposal = make_dummy_block_proposal();
    let preimage = proposal.signing_preimage();

    // T159: Domain tag is now chain-aware (DevNet by default)
    let devnet_proposal_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Proposal);
    assert!(
        preimage.starts_with(&devnet_proposal_tag),
        "BlockProposal signing preimage must start with DevNet domain tag"
    );
}

#[test]
fn proposal_signing_preimage_includes_qc_and_txs() {
    // Create proposal with QC and transactions
    let proposal = make_proposal_with_qc();
    let preimage = proposal.signing_preimage();

    // The preimage should include QC bytes and transaction bytes
    // We verify this by checking the length is larger than a proposal without QC/txs
    let proposal_no_qc = make_dummy_block_proposal();
    let preimage_no_qc = proposal_no_qc.signing_preimage();

    assert!(
        preimage.len() > preimage_no_qc.len(),
        "Proposal with QC and txs should have larger preimage"
    );

    // T159: Verify the preimage still starts with DevNet domain tag
    let devnet_proposal_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Proposal);
    assert!(preimage.starts_with(&devnet_proposal_tag));
}

#[test]
fn proposal_signing_preimage_length_no_qc_no_txs() {
    let proposal = make_dummy_block_proposal();
    let preimage = proposal.signing_preimage();

    // T159: Expected length with chain-aware domain tag (no QC, no txs)
    // domain_tag: 21 bytes ("QBIND:DEV:PROPOSAL:v1")
    // version: 1
    // chain_id: 4
    // epoch: 8
    // height: 8
    // round: 8
    // parent_block_id: 32
    // payload_hash: 32
    // proposer_index: 2
    // suite_id: 2
    // tx_count: 4
    // timestamp: 8
    // payload_kind: 1 (T102.1)
    // next_epoch: 8 (T102.1)
    // qc_len: 4
    // Total: 21 + 1 + 4 + 8 + 8 + 8 + 32 + 32 + 2 + 2 + 4 + 8 + 1 + 8 + 4 = 143
    let expected_len = 21 + 1 + 4 + 8 + 8 + 8 + 32 + 32 + 2 + 2 + 4 + 8 + 1 + 8 + 4;
    assert_eq!(preimage.len(), expected_len);
}

#[test]
fn proposal_signing_preimage_different_txs_produce_different_preimages() {
    let mut proposal1 = make_dummy_block_proposal();
    proposal1.txs = vec![vec![0x01, 0x02, 0x03]];
    proposal1.header.tx_count = 1;

    let mut proposal2 = make_dummy_block_proposal();
    proposal2.txs = vec![vec![0x04, 0x05, 0x06]];
    proposal2.header.tx_count = 1;

    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_ne!(
        preimage1, preimage2,
        "Different transactions should produce different preimages"
    );
}

#[test]
fn proposal_signing_preimage_different_qcs_produce_different_preimages() {
    let qc1 = QuorumCertificate {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x33; 32],
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0xFF],
        signatures: vec![vec![0xAA]],
    };

    let qc2 = QuorumCertificate {
        version: 1,
        chain_id: 42,
        epoch: 0,
        height: 99,
        round: 4,
        step: 1,
        block_id: [0x44; 32], // Different block_id
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signer_bitmap: vec![0xFF],
        signatures: vec![vec![0xAA]],
    };

    let mut proposal1 = make_dummy_block_proposal();
    proposal1.qc = Some(qc1);

    let mut proposal2 = make_dummy_block_proposal();
    proposal2.qc = Some(qc2);

    let preimage1 = proposal1.signing_preimage();
    let preimage2 = proposal2.signing_preimage();

    assert_ne!(
        preimage1, preimage2,
        "Different QCs should produce different preimages"
    );
}

// ============================================================================
// T159: Cross-chain separation tests
// ============================================================================

#[test]
fn vote_different_chains_produce_different_preimages() {
    // Critical security test: Same vote data with different chain IDs must produce different preimages
    let vote = make_dummy_vote();

    let devnet_preimage = vote.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
    let testnet_preimage = vote.signing_preimage_with_chain_id(QBIND_TESTNET_CHAIN_ID);

    assert_ne!(
        devnet_preimage, testnet_preimage,
        "DevNet and TestNet vote preimages must differ"
    );

    // Verify both start with correct chain-specific tags
    let devnet_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Vote);
    let testnet_tag = domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::Vote);

    assert!(devnet_preimage.starts_with(&devnet_tag));
    assert!(testnet_preimage.starts_with(&testnet_tag));
}

#[test]
fn proposal_different_chains_produce_different_preimages() {
    // Critical security test: Same proposal data with different chain IDs must produce different preimages
    let proposal = make_dummy_block_proposal();

    let devnet_preimage = proposal.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
    let testnet_preimage = proposal.signing_preimage_with_chain_id(QBIND_TESTNET_CHAIN_ID);

    assert_ne!(
        devnet_preimage, testnet_preimage,
        "DevNet and TestNet proposal preimages must differ"
    );

    // Verify both start with correct chain-specific tags
    let devnet_tag = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Proposal);
    let testnet_tag = domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::Proposal);

    assert!(devnet_preimage.starts_with(&devnet_tag));
    assert!(testnet_preimage.starts_with(&testnet_tag));
}