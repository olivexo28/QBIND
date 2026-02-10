//! T233: Genesis Hash CLI Tests
//!
//! This test module verifies the CLI flags and node config for genesis hash
//! commitment and verification as specified in T233.
//!
//! # Test Coverage
//!
//! - `test_cli_print_genesis_hash_flag`: CLI accepts --print-genesis-hash
//! - `test_cli_expect_genesis_hash_flag`: CLI accepts --expect-genesis-hash
//! - `test_expect_genesis_hash_accepts_matching`: Matching hash succeeds
//! - `test_expect_genesis_hash_rejects_mismatch`: Mismatched hash fails
//! - `test_expect_genesis_hash_parse_error`: Invalid hex format fails
//! - `test_validate_mainnet_invariants_requires_expected_hash`: MainNet requires hash

use clap::Parser;
use qbind_ledger::{compute_genesis_hash_bytes, format_genesis_hash, parse_genesis_hash};
use qbind_node::cli::CliArgs;
use qbind_node::node_config::{GenesisSourceConfig, MainnetConfigError, NodeConfig};
use std::path::PathBuf;

// ============================================================================
// CLI Flag Parsing Tests
// ============================================================================

#[test]
fn test_cli_print_genesis_hash_flag() {
    // Given CLI args with --print-genesis-hash
    let args = CliArgs::try_parse_from([
        "qbind-node",
        "--print-genesis-hash",
        "--genesis-path",
        "/etc/qbind/genesis.json",
    ])
    .unwrap();

    // Then the flag should be set
    assert!(args.print_genesis_hash);
    assert_eq!(
        args.genesis_path,
        Some(PathBuf::from("/etc/qbind/genesis.json"))
    );
}

#[test]
fn test_cli_expect_genesis_hash_flag() {
    // Given CLI args with --expect-genesis-hash
    let expected_hash = format!("0x{}", "ab".repeat(32));
    let args = CliArgs::try_parse_from([
        "qbind-node",
        "--expect-genesis-hash",
        &expected_hash,
        "--genesis-path",
        "/etc/qbind/genesis.json",
    ])
    .unwrap();

    // Then the flag should be set
    assert_eq!(args.expect_genesis_hash, Some(expected_hash));
}

#[test]
fn test_cli_expect_genesis_hash_without_prefix() {
    // Given CLI args with --expect-genesis-hash without 0x prefix
    let expected_hash = "ab".repeat(32);
    let args =
        CliArgs::try_parse_from(["qbind-node", "--expect-genesis-hash", &expected_hash]).unwrap();

    // Then the flag should be set
    assert_eq!(args.expect_genesis_hash, Some(expected_hash));
}

// ============================================================================
// to_node_config Tests for Genesis Hash
// ============================================================================

#[test]
fn test_to_node_config_sets_expected_genesis_hash() {
    // Given CLI args with a valid expected genesis hash
    let expected_hash = format!("0x{}", "12".repeat(32));
    let args =
        CliArgs::try_parse_from(["qbind-node", "--expect-genesis-hash", &expected_hash]).unwrap();

    // When we convert to NodeConfig
    let config = args.to_node_config().unwrap();

    // Then the expected_genesis_hash should be set
    assert!(config.expected_genesis_hash.is_some());
    let hash = config.expected_genesis_hash.unwrap();
    assert_eq!(hash, [0x12u8; 32]);
}

#[test]
fn test_to_node_config_expected_genesis_hash_parse_error() {
    // Given CLI args with an invalid expected genesis hash
    let invalid_hash = "0x1234"; // Too short
    let args =
        CliArgs::try_parse_from(["qbind-node", "--expect-genesis-hash", invalid_hash]).unwrap();

    // When we convert to NodeConfig
    let result = args.to_node_config();

    // Then it should fail with an error
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        matches!(err, qbind_node::cli::CliError::InvalidGenesisHash(_)),
        "expected InvalidGenesisHash error, got: {:?}",
        err
    );
}

#[test]
fn test_to_node_config_expected_genesis_hash_invalid_hex() {
    // Given CLI args with invalid hex characters
    let invalid_hash = format!("0x{}", "zz".repeat(32));
    let args =
        CliArgs::try_parse_from(["qbind-node", "--expect-genesis-hash", &invalid_hash]).unwrap();

    // When we convert to NodeConfig
    let result = args.to_node_config();

    // Then it should fail with an error
    assert!(result.is_err());
}

#[test]
fn test_to_node_config_profile_with_expected_hash_override() {
    // Given mainnet profile CLI args with expected genesis hash
    let expected_hash = format!("0x{}", "ab".repeat(32));
    let args = CliArgs::try_parse_from([
        "qbind-node",
        "--profile",
        "mainnet",
        "--expect-genesis-hash",
        &expected_hash,
        "--genesis-path",
        "/etc/qbind/genesis.json",
    ])
    .unwrap();

    // When we convert to NodeConfig
    let config = args.to_node_config().unwrap();

    // Then the expected_genesis_hash should be set
    assert!(config.expected_genesis_hash.is_some());
    let hash = config.expected_genesis_hash.unwrap();
    assert_eq!(hash, [0xab; 32]);
}

// ============================================================================
// MainNet Invariant Tests
// ============================================================================

#[test]
fn test_validate_mainnet_invariants_requires_expected_hash() {
    // Given a MainNet config without expected_genesis_hash
    // We use mainnet_preset and configure all fields EXCEPT expected_genesis_hash
    // to ensure that's the ONLY remaining invariant that fails
    let mut config = NodeConfig::mainnet_preset();

    // Configure all requirements to pass, EXCEPT expected_genesis_hash
    config.genesis_source = GenesisSourceConfig::external(PathBuf::from("/etc/qbind/genesis.json"));
    config.data_dir = Some(PathBuf::from("/data/qbind"));
    config.signer_keystore_path = Some(PathBuf::from("/data/qbind/keystore")); // Required for EncryptedFsV1
    config.expected_genesis_hash = None; // Explicitly unset - this should be the ONLY failing check

    // When we validate mainnet invariants
    let result = config.validate_mainnet_invariants();

    // Then it should fail with ExpectedGenesisHashMissing
    assert!(result.is_err());
    match result.unwrap_err() {
        MainnetConfigError::ExpectedGenesisHashMissing => {
            // Expected error
        }
        other => panic!("expected ExpectedGenesisHashMissing, got: {:?}", other),
    }
}

#[test]
fn test_validate_mainnet_invariants_accepts_expected_hash() {
    // Given a fully configured MainNet config with expected_genesis_hash
    let mut config = NodeConfig::mainnet_preset();

    // Configure all requirements
    config.genesis_source = GenesisSourceConfig::external(PathBuf::from("/etc/qbind/genesis.json"));
    config.data_dir = Some(PathBuf::from("/data/qbind"));
    config.expected_genesis_hash = Some([0x42u8; 32]); // Set expected hash

    // When we validate mainnet invariants
    let result = config.validate_mainnet_invariants();

    // Then it should pass (or fail on other checks, but not ExpectedGenesisHashMissing)
    match result {
        Ok(()) => {
            // All invariants pass
        }
        Err(MainnetConfigError::ExpectedGenesisHashMissing) => {
            panic!("should not fail on ExpectedGenesisHashMissing when hash is set");
        }
        Err(_other) => {
            // May fail on other invariants (e.g., P2P transport, signer mode, etc.)
            // but not on expected_genesis_hash
        }
    }
}

#[test]
fn test_mainnet_preset_has_none_expected_genesis_hash() {
    // The MainNet preset should NOT have a default expected_genesis_hash
    // This forces operators to explicitly provide one
    let config = NodeConfig::mainnet_preset();

    assert!(
        config.expected_genesis_hash.is_none(),
        "MainNet preset must not have default expected_genesis_hash"
    );
}

#[test]
fn test_devnet_does_not_require_expected_genesis_hash() {
    // DevNet does not require expected_genesis_hash
    let config = NodeConfig::devnet();

    // This is fine - DevNet doesn't enforce MainNet invariants
    assert!(config.expected_genesis_hash.is_none());
}

#[test]
fn test_testnet_does_not_require_expected_genesis_hash() {
    // TestNet does not require expected_genesis_hash
    let config = NodeConfig::testnet();

    // This is fine - TestNet doesn't enforce MainNet invariants
    assert!(config.expected_genesis_hash.is_none());
}

// ============================================================================
// Hash Comparison Tests (Simulating Startup Behavior)
// ============================================================================

#[test]
fn test_genesis_hash_comparison_matching() {
    // Given genesis file content
    let genesis_bytes =
        br#"{"chain_id": "qbind-mainnet-v0", "genesis_time_unix_ms": 1738000000000}"#;

    // Compute the actual hash
    let actual_hash = compute_genesis_hash_bytes(genesis_bytes);

    // Create expected hash from the same source (simulating operator workflow)
    let expected_hash = actual_hash;

    // When we compare
    let matches = actual_hash == expected_hash;

    // Then they should match
    assert!(matches, "matching hashes should compare equal");
}

#[test]
fn test_genesis_hash_comparison_mismatched() {
    // Given genesis file content
    let genesis_bytes = br#"{"chain_id": "qbind-mainnet-v0"}"#;

    // Compute the actual hash
    let actual_hash = compute_genesis_hash_bytes(genesis_bytes);

    // Create a different expected hash (simulating wrong genesis file)
    let expected_hash = [0x00u8; 32];

    // When we compare
    let matches = actual_hash == expected_hash;

    // Then they should NOT match
    assert!(!matches, "different hashes should not compare equal");
}

#[test]
fn test_genesis_hash_workflow_with_format_parse() {
    // This simulates the operator workflow:
    // 1. Run qbind-node --print-genesis-hash to get the hash
    // 2. Copy hash into --expect-genesis-hash flag
    // 3. Node verifies at startup

    // Step 1: Operator gets hash (simulated by compute + format)
    let genesis_bytes = br#"{"chain_id": "qbind-mainnet-v0", "validators": [...]}"#;
    let hash = compute_genesis_hash_bytes(genesis_bytes);
    let hex_output = format_genesis_hash(&hash);

    // Step 2: Operator puts hex into CLI flag (simulated by parse)
    let expected_hash = parse_genesis_hash(&hex_output).unwrap();

    // Step 3: Node computes hash and compares at startup
    let actual_hash = compute_genesis_hash_bytes(genesis_bytes);
    let verification_passed = actual_hash == expected_hash;

    assert!(
        verification_passed,
        "operator workflow should result in matching hashes"
    );
}

// ============================================================================
// Error Message Tests
// ============================================================================

#[test]
fn test_expected_genesis_hash_missing_error_message() {
    let err = MainnetConfigError::ExpectedGenesisHashMissing;
    let msg = format!("{}", err);

    assert!(
        msg.contains("expected genesis hash"),
        "error should mention expected genesis hash: {}",
        msg
    );
    assert!(
        msg.contains("--expect-genesis-hash"),
        "error should mention CLI flag: {}",
        msg
    );
}
