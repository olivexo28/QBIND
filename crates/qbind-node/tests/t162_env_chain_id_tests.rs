//! T162 Integration Tests: Network Environment Selection + Chain-ID Plumbing
//!
//! These tests verify the environment selection and chain-id plumbing functionality:
//! - NodeConfig environment selection
//! - CLI parsing for --env flag
//! - Chain-id separation for all signed object types
//! - Cross-chain signature rejection

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_ledger::QbindTransaction;
use qbind_node::{
    parse_environment, BatchRef, NodeConfig, QbindBatch, DEFAULT_ENVIRONMENT, VALID_ENVIRONMENTS,
};
use qbind_types::{
    NetworkEnvironment, QBIND_DEVNET_CHAIN_ID, QBIND_MAINNET_CHAIN_ID, QBIND_TESTNET_CHAIN_ID,
};
use qbind_wire::consensus::{BlockProposal, Vote};

// ============================================================================
// Part 1: NodeConfig Tests
// ============================================================================

/// Test that NodeConfig::default() returns DevNet environment.
#[test]
fn test_node_config_default_is_devnet() {
    let config = NodeConfig::default();
    assert_eq!(config.environment, NetworkEnvironment::Devnet);
    assert_eq!(config.chain_id(), QBIND_DEVNET_CHAIN_ID);
    assert_eq!(config.scope(), "DEV");
}

/// Test NodeConfig for each environment.
#[test]
fn test_node_config_environments() {
    // DevNet
    let devnet = NodeConfig::devnet();
    assert_eq!(devnet.environment, NetworkEnvironment::Devnet);
    assert_eq!(devnet.chain_id(), QBIND_DEVNET_CHAIN_ID);
    assert_eq!(devnet.scope(), "DEV");

    // TestNet
    let testnet = NodeConfig::testnet();
    assert_eq!(testnet.environment, NetworkEnvironment::Testnet);
    assert_eq!(testnet.chain_id(), QBIND_TESTNET_CHAIN_ID);
    assert_eq!(testnet.scope(), "TST");

    // MainNet
    let mainnet = NodeConfig::mainnet();
    assert_eq!(mainnet.environment, NetworkEnvironment::Mainnet);
    assert_eq!(mainnet.chain_id(), QBIND_MAINNET_CHAIN_ID);
    assert_eq!(mainnet.scope(), "MAIN");
}

/// Test that chain IDs are unique across environments.
#[test]
fn test_chain_ids_are_unique() {
    let devnet = NodeConfig::devnet().chain_id();
    let testnet = NodeConfig::testnet().chain_id();
    let mainnet = NodeConfig::mainnet().chain_id();

    assert_ne!(
        devnet, testnet,
        "DevNet and TestNet should have different chain IDs"
    );
    assert_ne!(
        devnet, mainnet,
        "DevNet and MainNet should have different chain IDs"
    );
    assert_ne!(
        testnet, mainnet,
        "TestNet and MainNet should have different chain IDs"
    );
}

/// Test startup info string format.
#[test]
fn test_startup_info_string() {
    let config = NodeConfig::testnet();
    let info = config.startup_info_string(Some("V1"));

    assert!(
        info.contains("environment=TestNet"),
        "Should contain environment"
    );
    assert!(
        info.contains("chain_id=0x51424e4454535400"),
        "Should contain chain_id"
    );
    assert!(info.contains("scope=TST"), "Should contain scope");
    assert!(info.contains("validator=V1"), "Should contain validator ID");
}

// ============================================================================
// Part 2: CLI Parsing Tests
// ============================================================================

/// Test parsing valid environment strings (case-insensitive).
#[test]
fn test_parse_environment_valid() {
    // Lowercase
    assert_eq!(
        parse_environment("devnet").unwrap(),
        NetworkEnvironment::Devnet
    );
    assert_eq!(
        parse_environment("testnet").unwrap(),
        NetworkEnvironment::Testnet
    );
    assert_eq!(
        parse_environment("mainnet").unwrap(),
        NetworkEnvironment::Mainnet
    );

    // Uppercase
    assert_eq!(
        parse_environment("DEVNET").unwrap(),
        NetworkEnvironment::Devnet
    );
    assert_eq!(
        parse_environment("TESTNET").unwrap(),
        NetworkEnvironment::Testnet
    );
    assert_eq!(
        parse_environment("MAINNET").unwrap(),
        NetworkEnvironment::Mainnet
    );

    // Mixed case
    assert_eq!(
        parse_environment("DevNet").unwrap(),
        NetworkEnvironment::Devnet
    );
    assert_eq!(
        parse_environment("TestNet").unwrap(),
        NetworkEnvironment::Testnet
    );
    assert_eq!(
        parse_environment("MainNet").unwrap(),
        NetworkEnvironment::Mainnet
    );
}

/// Test parsing invalid environment strings.
#[test]
fn test_parse_environment_invalid() {
    let result = parse_environment("invalid");
    assert!(result.is_err());

    let err = result.unwrap_err();
    assert_eq!(err.invalid_value, "invalid");
    assert!(err.to_string().contains("invalid"));
    assert!(err.to_string().contains("devnet"));
    assert!(err.to_string().contains("testnet"));
    assert!(err.to_string().contains("mainnet"));
}

/// Test default environment constant.
#[test]
fn test_default_environment_constant() {
    assert_eq!(DEFAULT_ENVIRONMENT, "devnet");
    assert_eq!(
        parse_environment(DEFAULT_ENVIRONMENT).unwrap(),
        NetworkEnvironment::Devnet
    );
}

/// Test valid environments list.
#[test]
fn test_valid_environments_list() {
    assert_eq!(VALID_ENVIRONMENTS, &["devnet", "testnet", "mainnet"]);

    // All valid environments should parse successfully
    for env_str in VALID_ENVIRONMENTS {
        assert!(parse_environment(env_str).is_ok());
    }
}

// ============================================================================
// Part 3: Chain-ID Separation Tests
// ============================================================================

fn test_account_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = byte;
    id
}

fn make_test_tx(sender_byte: u8, nonce: u64) -> QbindTransaction {
    QbindTransaction::new(test_account_id(sender_byte), nonce, vec![0xAA; 32])
}

/// Test that QbindTransaction signing preimages differ by chain ID.
#[test]
fn test_tx_signing_preimage_differs_by_chain_id() {
    let tx = make_test_tx(0xAA, 1);

    let devnet_preimage = tx.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
    let testnet_preimage = tx.signing_preimage_with_chain_id(QBIND_TESTNET_CHAIN_ID);
    let mainnet_preimage = tx.signing_preimage_with_chain_id(QBIND_MAINNET_CHAIN_ID);

    assert_ne!(
        devnet_preimage, testnet_preimage,
        "DevNet and TestNet preimages should differ"
    );
    assert_ne!(
        devnet_preimage, mainnet_preimage,
        "DevNet and MainNet preimages should differ"
    );
    assert_ne!(
        testnet_preimage, mainnet_preimage,
        "TestNet and MainNet preimages should differ"
    );
}

/// Test that a DevNet-signed transaction fails verification under TestNet chain ID.
#[test]
fn test_tx_cross_chain_signature_rejection() {
    // Generate a keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = qbind_ledger::UserPublicKey::ml_dsa_44(pk_bytes);

    // Sign transaction with DevNet chain ID
    let mut tx = make_test_tx(0xBB, 1);
    tx.sign_with_chain_id(&sk, QBIND_DEVNET_CHAIN_ID)
        .expect("signing should succeed");

    // Verification should succeed with DevNet chain ID
    assert!(
        tx.verify_signature_with_chain_id(&pk, QBIND_DEVNET_CHAIN_ID)
            .is_ok(),
        "DevNet signature should verify with DevNet chain ID"
    );

    // Verification should FAIL with TestNet chain ID
    assert!(
        tx.verify_signature_with_chain_id(&pk, QBIND_TESTNET_CHAIN_ID)
            .is_err(),
        "DevNet signature should NOT verify with TestNet chain ID"
    );

    // Verification should FAIL with MainNet chain ID
    assert!(
        tx.verify_signature_with_chain_id(&pk, QBIND_MAINNET_CHAIN_ID)
            .is_err(),
        "DevNet signature should NOT verify with MainNet chain ID"
    );
}

/// Test that Vote signing preimages differ by chain ID.
#[test]
fn test_vote_signing_preimage_differs_by_chain_id() {
    let vote = Vote {
        version: 1,
        chain_id: QBIND_DEVNET_CHAIN_ID.as_u64() as u32,
        epoch: 0,
        height: 10,
        round: 5,
        step: 0,
        block_id: [0xCC; 32],
        validator_index: 1,
        suite_id: 100,
        signature: vec![],
    };

    let devnet_preimage = vote.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
    let testnet_preimage = vote.signing_preimage_with_chain_id(QBIND_TESTNET_CHAIN_ID);
    let mainnet_preimage = vote.signing_preimage_with_chain_id(QBIND_MAINNET_CHAIN_ID);

    assert_ne!(
        devnet_preimage, testnet_preimage,
        "Vote: DevNet and TestNet preimages should differ"
    );
    assert_ne!(
        devnet_preimage, mainnet_preimage,
        "Vote: DevNet and MainNet preimages should differ"
    );
    assert_ne!(
        testnet_preimage, mainnet_preimage,
        "Vote: TestNet and MainNet preimages should differ"
    );
}

/// Test that BlockProposal signing preimages differ by chain ID.
#[test]
fn test_proposal_signing_preimage_differs_by_chain_id() {
    use qbind_wire::consensus::{BlockHeader, QuorumCertificate};

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: QBIND_DEVNET_CHAIN_ID.as_u64() as u32,
            epoch: 0,
            height: 10,
            round: 5,
            parent_block_id: [0xAA; 32],
            payload_hash: [0xBB; 32],
            proposer_index: 1,
            suite_id: 100,
            tx_count: 0,
            timestamp: 12345,
            payload_kind: 0,
            next_epoch: 0,
        },
        qc: Some(QuorumCertificate {
            version: 1,
            chain_id: QBIND_DEVNET_CHAIN_ID.as_u64() as u32,
            epoch: 0,
            height: 9,
            round: 4,
            step: 0,
            block_id: [0xAA; 32],
            suite_id: 100,
            signer_bitmap: vec![],
            signatures: vec![],
        }),
        txs: vec![],
        signature: vec![],
    };

    let devnet_preimage = proposal.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
    let testnet_preimage = proposal.signing_preimage_with_chain_id(QBIND_TESTNET_CHAIN_ID);
    let mainnet_preimage = proposal.signing_preimage_with_chain_id(QBIND_MAINNET_CHAIN_ID);

    assert_ne!(
        devnet_preimage, testnet_preimage,
        "Proposal: DevNet and TestNet preimages should differ"
    );
    assert_ne!(
        devnet_preimage, mainnet_preimage,
        "Proposal: DevNet and MainNet preimages should differ"
    );
    assert_ne!(
        testnet_preimage, mainnet_preimage,
        "Proposal: TestNet and MainNet preimages should differ"
    );
}

/// Test that QbindBatch signing preimages differ by chain ID.
#[test]
fn test_batch_signing_preimage_differs_by_chain_id() {
    let creator = ValidatorId::new(1);
    let view_hint = 10;
    let parents = vec![BatchRef::new(ValidatorId::new(0), [0xAA; 32])];
    let txs = vec![make_test_tx(0xCC, 0)];

    let batch = QbindBatch::new(creator, view_hint, parents, txs);

    let devnet_preimage = batch.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
    let testnet_preimage = batch.signing_preimage_with_chain_id(QBIND_TESTNET_CHAIN_ID);
    let mainnet_preimage = batch.signing_preimage_with_chain_id(QBIND_MAINNET_CHAIN_ID);

    assert_ne!(
        devnet_preimage, testnet_preimage,
        "Batch: DevNet and TestNet preimages should differ"
    );
    assert_ne!(
        devnet_preimage, mainnet_preimage,
        "Batch: DevNet and MainNet preimages should differ"
    );
    assert_ne!(
        testnet_preimage, mainnet_preimage,
        "Batch: TestNet and MainNet preimages should differ"
    );
}

/// Test that a DevNet-signed batch fails verification under TestNet chain ID.
#[test]
fn test_batch_cross_chain_signature_rejection() {
    // Generate a keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

    let creator = ValidatorId::new(1);
    let view_hint = 10;
    let parents = vec![];
    let txs = vec![make_test_tx(0xDD, 0)];

    // Sign batch with DevNet chain ID
    let mut batch = QbindBatch::new(creator, view_hint, parents, txs);
    batch
        .sign_with_chain_id(&sk, QBIND_DEVNET_CHAIN_ID)
        .expect("signing should succeed");

    // Verification should succeed with DevNet chain ID
    assert!(
        batch
            .verify_signature_with_chain_id(&pk_bytes, QBIND_DEVNET_CHAIN_ID)
            .is_ok(),
        "DevNet batch signature should verify with DevNet chain ID"
    );

    // Verification should FAIL with TestNet chain ID
    assert!(
        batch
            .verify_signature_with_chain_id(&pk_bytes, QBIND_TESTNET_CHAIN_ID)
            .is_err(),
        "DevNet batch signature should NOT verify with TestNet chain ID"
    );

    // Verification should FAIL with MainNet chain ID
    assert!(
        batch
            .verify_signature_with_chain_id(&pk_bytes, QBIND_MAINNET_CHAIN_ID)
            .is_err(),
        "DevNet batch signature should NOT verify with MainNet chain ID"
    );
}

/// Test timeout signing bytes differ by chain ID.
#[test]
fn test_timeout_signing_bytes_differs_by_chain_id() {
    use qbind_consensus::timeout::timeout_signing_bytes_with_chain_id;
    use qbind_consensus::QuorumCertificate;

    let view = 10u64;
    let validator_id = ValidatorId::new(1);
    let high_qc: QuorumCertificate<[u8; 32]> = QuorumCertificate::new(
        [0xAA; 32],
        5,
        vec![ValidatorId::new(0), ValidatorId::new(1)],
    );

    let devnet_bytes: Vec<u8> = timeout_signing_bytes_with_chain_id(
        QBIND_DEVNET_CHAIN_ID,
        view,
        Some(&high_qc),
        validator_id,
    );
    let testnet_bytes: Vec<u8> = timeout_signing_bytes_with_chain_id(
        QBIND_TESTNET_CHAIN_ID,
        view,
        Some(&high_qc),
        validator_id,
    );
    let mainnet_bytes: Vec<u8> = timeout_signing_bytes_with_chain_id(
        QBIND_MAINNET_CHAIN_ID,
        view,
        Some(&high_qc),
        validator_id,
    );

    assert_ne!(
        devnet_bytes, testnet_bytes,
        "Timeout: DevNet and TestNet bytes should differ"
    );
    assert_ne!(
        devnet_bytes, mainnet_bytes,
        "Timeout: DevNet and MainNet bytes should differ"
    );
    assert_ne!(
        testnet_bytes, mainnet_bytes,
        "Timeout: TestNet and MainNet bytes should differ"
    );
}

// ============================================================================
// Part 4: Smoke Tests
// ============================================================================

/// Smoke test: Build NodeConfig with TestNet and verify chain ID usage.
#[test]
fn test_smoke_testnet_config() {
    let config = NodeConfig::testnet();

    // Verify environment
    assert_eq!(config.environment, NetworkEnvironment::Testnet);

    // Verify chain ID value
    assert_eq!(config.chain_id().as_u64(), 0x51424E44_54535400);

    // Verify scope
    assert_eq!(config.scope(), "TST");

    // Verify startup info contains expected values
    let info = config.startup_info_string(Some("test-validator"));
    assert!(info.contains("TestNet"));
    assert!(info.contains("TST"));
    assert!(info.contains("test-validator"));
}

/// Smoke test: Sign and verify a transaction with TestNet chain ID.
#[test]
fn test_smoke_testnet_tx_sign_verify() {
    let config = NodeConfig::testnet();
    let chain_id = config.chain_id();

    // Generate keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");
    let pk = qbind_ledger::UserPublicKey::ml_dsa_44(pk_bytes);

    // Create and sign transaction
    let mut tx = make_test_tx(0xEE, 42);
    tx.sign_with_chain_id(&sk, chain_id)
        .expect("signing should succeed");

    // Verify signature
    assert!(
        tx.verify_signature_with_chain_id(&pk, chain_id).is_ok(),
        "TestNet signature should verify with TestNet chain ID"
    );
}

/// Smoke test: Sign and verify a batch with TestNet chain ID.
#[test]
fn test_smoke_testnet_batch_sign_verify() {
    let config = NodeConfig::testnet();
    let chain_id = config.chain_id();

    // Generate keypair
    let (pk_bytes, sk) = MlDsa44Backend::generate_keypair().expect("keygen failed");

    // Create and sign batch
    let mut batch = QbindBatch::new(
        ValidatorId::new(1),
        100,
        vec![],
        vec![make_test_tx(0xFF, 0)],
    );
    batch
        .sign_with_chain_id(&sk, chain_id)
        .expect("signing should succeed");

    // Verify signature
    assert!(
        batch
            .verify_signature_with_chain_id(&pk_bytes, chain_id)
            .is_ok(),
        "TestNet batch signature should verify with TestNet chain ID"
    );
}

// ============================================================================
// Part 5: Environment Metrics Tests
// ============================================================================

/// Test environment metrics creation and format.
#[test]
fn test_environment_metrics() {
    use qbind_node::EnvironmentMetrics;

    // DevNet
    let devnet_metrics = EnvironmentMetrics::new(NetworkEnvironment::Devnet);
    assert_eq!(devnet_metrics.network(), "devnet");
    assert_eq!(devnet_metrics.chain_id_hex(), "0x51424e4444455600");
    assert_eq!(devnet_metrics.scope(), "DEV");

    // TestNet
    let testnet_metrics = EnvironmentMetrics::new(NetworkEnvironment::Testnet);
    assert_eq!(testnet_metrics.network(), "testnet");
    assert_eq!(testnet_metrics.chain_id_hex(), "0x51424e4454535400");
    assert_eq!(testnet_metrics.scope(), "TST");

    // MainNet
    let mainnet_metrics = EnvironmentMetrics::new(NetworkEnvironment::Mainnet);
    assert_eq!(mainnet_metrics.network(), "mainnet");
    assert_eq!(mainnet_metrics.chain_id_hex(), "0x51424e444d41494e");
    assert_eq!(mainnet_metrics.scope(), "MAIN");
}

/// Test environment metrics Prometheus format.
#[test]
fn test_environment_metrics_format() {
    use qbind_node::EnvironmentMetrics;

    let metrics = EnvironmentMetrics::new(NetworkEnvironment::Testnet);
    let output = metrics.format_metrics();

    // Should contain the environment gauge
    assert!(output.contains("qbind_build_env{network=\"testnet\"} 1"));

    // Should contain the chain ID info metric
    assert!(output.contains("qbind_chain_id{"));
    assert!(output.contains("network=\"testnet\""));
    assert!(output.contains("chain_id=\"0x51424e4454535400\""));
    assert!(output.contains("scope=\"TST\""));
}

/// Test NodeMetrics environment integration.
#[test]
fn test_node_metrics_environment() {
    use qbind_node::NodeMetrics;

    let metrics = NodeMetrics::new();

    // Initially, environment should be None
    assert!(metrics.environment().is_none());

    // Set environment
    metrics.set_environment(NetworkEnvironment::Testnet);

    // Now environment should be Some
    let env = metrics.environment().expect("environment should be set");
    assert_eq!(env.network(), "testnet");

    // Format metrics should include environment section
    let output = metrics.format_metrics();
    assert!(output.contains("Environment metrics (T162)"));
    assert!(output.contains("qbind_build_env{network=\"testnet\"} 1"));
}
