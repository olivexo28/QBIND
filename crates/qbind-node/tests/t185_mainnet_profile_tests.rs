//! T185 MainNet Profile Tests
//!
//! This module tests the MainNet v0 configuration profile and safety rails.
//!
//! ## Test Coverage
//!
//! 1. Preset correctness tests
//! 2. Profile mapping tests
//! 3. Validation success tests
//! 4. Validation failure tests (one per invariant)
//! 5. CLI integration tests
//! 6. T210 Signer mode validation tests
//! 7. T214 Signer failure mode validation tests

use qbind_node::node_config::{
    parse_config_profile, ConfigProfile, ExecutionProfile, MainnetConfigError, MempoolMode,
    NetworkMode, NodeConfig, SignerFailureMode, SignerMode,
};
use qbind_types::NetworkEnvironment;

// ============================================================================
// Part 1: Preset Correctness Tests
// ============================================================================

/// Test that mainnet_preset() produces configuration matching the spec defaults.
///
/// See QBIND_MAINNET_V0_SPEC.md Section 7.2 for the canonical defaults.
#[test]
fn mainnet_preset_matches_spec_defaults() {
    let config = NodeConfig::mainnet_preset();

    // Environment: MainNet (QBIND_MAINNET_CHAIN_ID)
    assert_eq!(
        config.environment,
        NetworkEnvironment::Mainnet,
        "MainNet preset should use MainNet environment"
    );

    // Execution: VmV0
    assert_eq!(
        config.execution_profile,
        ExecutionProfile::VmV0,
        "MainNet preset should use VmV0 execution profile"
    );

    // Gas: Enabled (cannot be disabled)
    assert!(
        config.gas_enabled,
        "MainNet preset should have gas enforcement ENABLED"
    );

    // Fee Priority: Enabled (cannot be disabled)
    assert!(
        config.enable_fee_priority,
        "MainNet preset should have fee-priority ENABLED"
    );

    // Mempool: DAG (required for validators)
    assert_eq!(
        config.mempool_mode,
        MempoolMode::Dag,
        "MainNet preset should use DAG mempool"
    );

    // DAG Availability: Enabled (required)
    assert!(
        config.dag_availability_enabled,
        "MainNet preset should have DAG availability ENABLED"
    );

    // Network: P2P (required for validators)
    assert_eq!(
        config.network_mode,
        NetworkMode::P2p,
        "MainNet preset should use P2P network mode"
    );

    // P2P: Enabled (required)
    assert!(
        config.network.enable_p2p,
        "MainNet preset should have P2P ENABLED"
    );

    // Data dir: Not set by preset (caller must supply)
    assert!(
        config.data_dir.is_none(),
        "MainNet preset should NOT set data_dir (caller responsibility)"
    );
}

/// Test that mainnet_preset_localmesh() provides LocalMesh for testing.
#[test]
fn mainnet_preset_localmesh_for_testing() {
    let config = NodeConfig::mainnet_preset_localmesh();

    // Should have all MainNet features
    assert_eq!(config.environment, NetworkEnvironment::Mainnet);
    assert!(config.gas_enabled);
    assert!(config.enable_fee_priority);
    assert_eq!(config.mempool_mode, MempoolMode::Dag);
    assert!(config.dag_availability_enabled);

    // But with LocalMesh networking for single-machine testing
    assert_eq!(
        config.network_mode,
        NetworkMode::LocalMesh,
        "mainnet_preset_localmesh should use LocalMesh"
    );
    assert!(
        !config.network.enable_p2p,
        "mainnet_preset_localmesh should have P2P disabled"
    );
}

// ============================================================================
// Part 2: Profile Mapping Tests
// ============================================================================

/// Test that from_profile(ConfigProfile::MainNet) uses mainnet_preset().
#[test]
fn from_profile_mainnet_uses_mainnet_preset() {
    let from_profile = NodeConfig::from_profile(ConfigProfile::MainNet);
    let direct_preset = NodeConfig::mainnet_preset();

    // All fields should match (except data_dir which is None in both)
    assert_eq!(from_profile.environment, direct_preset.environment);
    assert_eq!(
        from_profile.execution_profile,
        direct_preset.execution_profile
    );
    assert_eq!(from_profile.gas_enabled, direct_preset.gas_enabled);
    assert_eq!(
        from_profile.enable_fee_priority,
        direct_preset.enable_fee_priority
    );
    assert_eq!(from_profile.mempool_mode, direct_preset.mempool_mode);
    assert_eq!(
        from_profile.dag_availability_enabled,
        direct_preset.dag_availability_enabled
    );
    assert_eq!(from_profile.network_mode, direct_preset.network_mode);
    assert_eq!(
        from_profile.network.enable_p2p,
        direct_preset.network.enable_p2p
    );
}

/// Test that parse_config_profile accepts "mainnet" and variants.
#[test]
fn parse_config_profile_accepts_mainnet() {
    assert_eq!(
        parse_config_profile("mainnet"),
        Some(ConfigProfile::MainNet)
    );
    assert_eq!(
        parse_config_profile("MAINNET"),
        Some(ConfigProfile::MainNet)
    );
    assert_eq!(
        parse_config_profile("MainNet"),
        Some(ConfigProfile::MainNet)
    );
    assert_eq!(
        parse_config_profile("mainnet-v0"),
        Some(ConfigProfile::MainNet)
    );
}

/// Test that ConfigProfile::MainNet displays as "mainnet".
#[test]
fn config_profile_mainnet_display() {
    assert_eq!(format!("{}", ConfigProfile::MainNet), "mainnet");
}

// ============================================================================
// Part 3: Validation Success Tests
// ============================================================================

/// Test that a valid MainNet config passes validation.
#[test]
fn validate_mainnet_invariants_accepts_canonical_config() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_keystore_path("/data/qbind/keystore"); // T210: Must provide keystore path

    let result = config.validate_mainnet_invariants();
    assert!(
        result.is_ok(),
        "Valid MainNet config should pass validation: {:?}",
        result
    );
}

// ============================================================================
// Part 4: Validation Failure Tests (one per invariant)
// ============================================================================

/// Test: Gas disabled → error
#[test]
fn validate_mainnet_invariants_rejects_gas_disabled() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_keystore_path("/data/qbind/keystore") // T210
        .with_gas_enabled(false);

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::GasDisabled) => (),
        Err(e) => panic!("Expected GasDisabled error, got: {:?}", e),
        Ok(()) => panic!("Expected error for gas disabled"),
    }
}

/// Test: Fee priority disabled → error
#[test]
fn validate_mainnet_invariants_rejects_fee_priority_disabled() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_fee_priority(false);

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::FeePriorityDisabled) => (),
        Err(e) => panic!("Expected FeePriorityDisabled error, got: {:?}", e),
        Ok(()) => panic!("Expected error for fee priority disabled"),
    }
}

/// Test: Mempool mode != Dag → error
#[test]
fn validate_mainnet_invariants_rejects_fifo_mempool() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_mempool_mode(MempoolMode::Fifo);

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::WrongMempoolMode { expected, actual }) => {
            assert_eq!(expected, MempoolMode::Dag);
            assert_eq!(actual, MempoolMode::Fifo);
        }
        Err(e) => panic!("Expected WrongMempoolMode error, got: {:?}", e),
        Ok(()) => panic!("Expected error for FIFO mempool"),
    }
}

/// Test: DAG availability disabled → error
#[test]
fn validate_mainnet_invariants_rejects_dag_availability_disabled() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_dag_availability(false);

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::DagAvailabilityDisabled) => (),
        Err(e) => panic!("Expected DagAvailabilityDisabled error, got: {:?}", e),
        Ok(()) => panic!("Expected error for DAG availability disabled"),
    }
}

/// Test: Network mode != P2p → error
#[test]
fn validate_mainnet_invariants_rejects_localmesh_network() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_network_mode(NetworkMode::LocalMesh);

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::WrongNetworkMode { expected, actual }) => {
            assert_eq!(expected, NetworkMode::P2p);
            assert_eq!(actual, NetworkMode::LocalMesh);
        }
        Err(e) => panic!("Expected WrongNetworkMode error, got: {:?}", e),
        Ok(()) => panic!("Expected error for LocalMesh network mode"),
    }
}

/// Test: P2P disabled → error
#[test]
fn validate_mainnet_invariants_rejects_p2p_disabled() {
    // Create a config with P2P mode but enable_p2p=false
    let mut config = NodeConfig::mainnet_preset().with_data_dir("/data/qbind");
    config.network.enable_p2p = false;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::P2pDisabled) => (),
        Err(e) => panic!("Expected P2pDisabled error, got: {:?}", e),
        Ok(()) => panic!("Expected error for P2P disabled"),
    }
}

/// Test: Missing data_dir → error
#[test]
fn validate_mainnet_invariants_rejects_missing_data_dir() {
    // mainnet_preset() has no data_dir by default
    let config = NodeConfig::mainnet_preset();

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::MissingDataDir) => (),
        Err(e) => panic!("Expected MissingDataDir error, got: {:?}", e),
        Ok(()) => panic!("Expected error for missing data_dir"),
    }
}

/// Test: Wrong environment → error
#[test]
fn validate_mainnet_invariants_rejects_wrong_environment() {
    // Start with TestNet Beta (which has all features enabled)
    // but wrong environment
    let mut config = NodeConfig::testnet_beta_preset().with_data_dir("/data/qbind");
    // Manually set all the flags that MainNet requires
    config.gas_enabled = true;
    config.enable_fee_priority = true;
    config.mempool_mode = MempoolMode::Dag;
    config.dag_availability_enabled = true;
    config.network_mode = NetworkMode::P2p;
    config.network.enable_p2p = true;
    // But environment is still TestNet!

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::WrongEnvironment { expected, actual }) => {
            assert_eq!(expected, NetworkEnvironment::Mainnet);
            assert_eq!(actual, NetworkEnvironment::Testnet);
        }
        Err(e) => panic!("Expected WrongEnvironment error, got: {:?}", e),
        Ok(()) => panic!("Expected error for wrong environment"),
    }
}

// ============================================================================
// Part 5: Error Display Tests
// ============================================================================

/// Test that MainnetConfigError has readable Display messages.
#[test]
fn mainnet_config_error_display_messages() {
    let error = MainnetConfigError::GasDisabled;
    let msg = format!("{}", error);
    assert!(msg.contains("gas enforcement must be enabled"));
    assert!(msg.contains("--enable-gas=true"));

    let error = MainnetConfigError::FeePriorityDisabled;
    let msg = format!("{}", error);
    assert!(msg.contains("fee-priority ordering must be enabled"));

    let error = MainnetConfigError::WrongMempoolMode {
        expected: MempoolMode::Dag,
        actual: MempoolMode::Fifo,
    };
    let msg = format!("{}", error);
    assert!(msg.contains("mempool mode must be dag"));

    let error = MainnetConfigError::DagAvailabilityDisabled;
    let msg = format!("{}", error);
    assert!(msg.contains("DAG availability certificates must be enabled"));

    let error = MainnetConfigError::WrongNetworkMode {
        expected: NetworkMode::P2p,
        actual: NetworkMode::LocalMesh,
    };
    let msg = format!("{}", error);
    assert!(msg.contains("network mode must be p2p"));

    let error = MainnetConfigError::P2pDisabled;
    let msg = format!("{}", error);
    assert!(msg.contains("P2P transport must be enabled"));

    let error = MainnetConfigError::MissingDataDir;
    let msg = format!("{}", error);
    assert!(msg.contains("data directory must be configured"));
    assert!(msg.contains("--data-dir"));
}

// ============================================================================
// Part 6: Startup Info String Tests
// ============================================================================

/// Test that startup_info_string includes MainNet-specific fields.
#[test]
fn startup_info_string_includes_mainnet_fields() {
    let config = NodeConfig::mainnet_preset().with_data_dir("/data/qbind");

    let info = config.startup_info_string(Some("V1"));

    // Should show MainNet environment
    assert!(
        info.contains("environment=MainNet"),
        "Should show environment=MainNet: {}",
        info
    );

    // Should show gas=on
    assert!(info.contains("gas=on"), "Should show gas=on: {}", info);

    // Should show fee-priority=on
    assert!(
        info.contains("fee-priority=on"),
        "Should show fee-priority=on: {}",
        info
    );

    // Should show mempool=dag
    assert!(
        info.contains("mempool=dag"),
        "Should show mempool=dag: {}",
        info
    );

    // Should show dag_availability=enabled
    assert!(
        info.contains("dag_availability=enabled"),
        "Should show dag_availability=enabled: {}",
        info
    );

    // Should show network=p2p
    assert!(
        info.contains("network=p2p"),
        "Should show network=p2p: {}",
        info
    );

    // Should show p2p=enabled
    assert!(
        info.contains("p2p=enabled"),
        "Should show p2p=enabled: {}",
        info
    );
}

// ============================================================================
// Part 7: Existing Profile Behavior Preserved
// ============================================================================

/// Test that DevNet and TestNet profiles are unchanged by T185.
#[test]
fn t185_does_not_change_devnet_or_testnet_behavior() {
    // DevNet v0 preset should be unchanged
    let devnet = NodeConfig::from_profile(ConfigProfile::DevNetV0);
    assert_eq!(devnet.environment, NetworkEnvironment::Devnet);
    assert!(!devnet.gas_enabled);
    assert!(!devnet.enable_fee_priority);
    assert_eq!(devnet.mempool_mode, MempoolMode::Fifo);
    assert_eq!(devnet.network_mode, NetworkMode::LocalMesh);

    // TestNet Alpha preset should be unchanged
    let alpha = NodeConfig::from_profile(ConfigProfile::TestNetAlpha);
    assert_eq!(alpha.environment, NetworkEnvironment::Testnet);
    assert!(!alpha.gas_enabled);
    assert_eq!(alpha.mempool_mode, MempoolMode::Fifo);
    assert_eq!(alpha.network_mode, NetworkMode::LocalMesh);

    // TestNet Beta preset should be unchanged
    let beta = NodeConfig::from_profile(ConfigProfile::TestNetBeta);
    assert_eq!(beta.environment, NetworkEnvironment::Testnet);
    assert!(beta.gas_enabled);
    assert!(beta.enable_fee_priority);
    assert_eq!(beta.mempool_mode, MempoolMode::Dag);
    assert_eq!(beta.network_mode, NetworkMode::P2p);
}

// ============================================================================
// Part 8: CLI Integration Tests
// ============================================================================

use clap::Parser;
use qbind_node::cli::CliArgs;

/// Test: CLI --profile mainnet builds MainNet config.
#[test]
fn cli_profile_mainnet_builds_mainnet_preset() {
    let args = CliArgs::try_parse_from([
        "qbind-node",
        "--profile",
        "mainnet",
        "--data-dir",
        "/tmp/qbind-mainnet",
    ])
    .unwrap();

    assert_eq!(args.profile, Some("mainnet".to_string()));

    let config = args.to_node_config().unwrap();

    // Verify MainNet defaults
    assert_eq!(
        config.environment,
        NetworkEnvironment::Mainnet,
        "CLI --profile mainnet should produce MainNet environment"
    );
    assert!(
        config.gas_enabled,
        "CLI --profile mainnet should enable gas"
    );
    assert!(
        config.enable_fee_priority,
        "CLI --profile mainnet should enable fee priority"
    );
    assert_eq!(
        config.mempool_mode,
        MempoolMode::Dag,
        "CLI --profile mainnet should use DAG mempool"
    );
    assert!(
        config.dag_availability_enabled,
        "CLI --profile mainnet should enable DAG availability"
    );
    assert_eq!(
        config.network_mode,
        NetworkMode::P2p,
        "CLI --profile mainnet should use P2P network mode"
    );
    assert!(
        config.network.enable_p2p,
        "CLI --profile mainnet should enable P2P"
    );
}

/// Test: CLI --profile mainnet with --enable-gas=false builds config but fails validation.
#[test]
fn cli_profile_mainnet_with_bad_override_fails_validation() {
    let args = CliArgs::try_parse_from([
        "qbind-node",
        "--profile",
        "mainnet",
        "--enable-gas",
        "false",
        "--data-dir",
        "/tmp/qbind-mainnet",
    ])
    .unwrap();

    // Config construction should succeed (override is applied)
    let config = args.to_node_config().unwrap();
    assert!(!config.gas_enabled, "CLI override should have disabled gas");

    // But MainNet validation should fail
    let result = config.validate_mainnet_invariants();
    assert!(
        result.is_err(),
        "MainNet validation should reject gas-disabled config"
    );
    match result {
        Err(MainnetConfigError::GasDisabled) => (),
        Err(e) => panic!("Expected GasDisabled error, got: {:?}", e),
        Ok(()) => panic!("Expected validation error"),
    }
}

/// Test: CLI short flag -P mainnet works.
#[test]
fn cli_short_flag_mainnet_works() {
    let args =
        CliArgs::try_parse_from(["qbind-node", "-P", "mainnet", "-d", "/tmp/qbind"]).unwrap();

    let config = args.to_node_config().unwrap();

    // Verify full MainNet preset
    assert_eq!(config.environment, NetworkEnvironment::Mainnet);
    assert!(config.gas_enabled);
    assert!(config.enable_fee_priority);
    assert_eq!(config.mempool_mode, MempoolMode::Dag);
    assert_eq!(config.network_mode, NetworkMode::P2p);
    assert!(config.dag_availability_enabled);
}

/// Test: CLI --profile mainnet-v0 is accepted.
#[test]
fn cli_profile_mainnet_v0_accepted() {
    let args = CliArgs::try_parse_from([
        "qbind-node",
        "--profile",
        "mainnet-v0",
        "--data-dir",
        "/tmp/qbind",
    ])
    .unwrap();

    let config = args.to_node_config().unwrap();

    // Verify full MainNet preset
    assert_eq!(config.environment, NetworkEnvironment::Mainnet);
    assert!(config.gas_enabled);
    assert!(config.enable_fee_priority);
    assert_eq!(config.mempool_mode, MempoolMode::Dag);
}

/// Test: CLI profile error message includes "mainnet".
#[test]
fn cli_invalid_profile_error_includes_mainnet() {
    let args = CliArgs::try_parse_from(["qbind-node", "--profile", "invalid-profile"]).unwrap();

    let result = args.to_node_config();
    assert!(result.is_err());

    // Error message should mention "mainnet" as a valid option
    let err_msg = format!("{}", result.unwrap_err());
    assert!(
        err_msg.contains("mainnet"),
        "Error message should mention 'mainnet' as valid option: {}",
        err_msg
    );
}

// ============================================================================
// T205: Discovery / Liveness Config Tests
// ============================================================================

/// Test: MainNet preset has discovery enabled.
#[test]
fn mainnet_preset_has_discovery_enabled() {
    let config = NodeConfig::mainnet_preset();

    assert!(
        config.network.discovery_enabled,
        "MainNet preset should have discovery_enabled = true"
    );
    assert_eq!(
        config.network.target_outbound_peers, 16,
        "MainNet preset should have target_outbound_peers = 16"
    );
}

/// Test: Discovery disabled → error (T205)
#[test]
fn validate_mainnet_invariants_rejects_discovery_disabled() {
    let mut config = NodeConfig::mainnet_preset().with_data_dir("/data/qbind");
    config.network.discovery_enabled = false;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::DiscoveryDisabled) => (),
        Err(e) => panic!("Expected DiscoveryDisabled error, got: {:?}", e),
        Ok(()) => panic!("Expected error for discovery disabled"),
    }
}

/// Test: Insufficient target_outbound_peers → error (T205)
#[test]
fn validate_mainnet_invariants_rejects_low_outbound_peers() {
    let mut config = NodeConfig::mainnet_preset().with_data_dir("/data/qbind");
    config.network.target_outbound_peers = 4; // Below minimum of 8

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::InsufficientTargetOutboundPeers { minimum, actual }) => {
            assert_eq!(minimum, 8);
            assert_eq!(actual, 4);
        }
        Err(e) => panic!(
            "Expected InsufficientTargetOutboundPeers error, got: {:?}",
            e
        ),
        Ok(()) => panic!("Expected error for low target_outbound_peers"),
    }
}

/// Test: DevNet allows discovery disabled.
#[test]
fn devnet_allows_discovery_disabled() {
    let config = NodeConfig::devnet_v0_preset();

    // DevNet should NOT have discovery enabled by default
    assert!(
        !config.network.discovery_enabled,
        "DevNet preset should have discovery_enabled = false"
    );

    // DevNet doesn't need to pass mainnet invariants, so no validation error
}

/// Test: TestNet Alpha/Beta defaults have discovery enabled.
#[test]
fn testnet_presets_have_appropriate_discovery_settings() {
    // TestNet Alpha: discovery disabled by default
    let alpha = NodeConfig::testnet_alpha_preset();
    assert!(
        !alpha.network.discovery_enabled,
        "TestNet Alpha should have discovery_enabled = false"
    );

    // TestNet Beta: discovery enabled
    let beta = NodeConfig::testnet_beta_preset();
    assert!(
        beta.network.discovery_enabled,
        "TestNet Beta should have discovery_enabled = true"
    );
    assert_eq!(
        beta.network.target_outbound_peers, 8,
        "TestNet Beta should have target_outbound_peers = 8"
    );
}

// ============================================================================
// Part 7: T210 Signer Mode Validation Tests
// ============================================================================

/// Test: MainNet preset has EncryptedFsV1 as default signer mode.
#[test]
fn mainnet_preset_has_encrypted_fs_signer_mode() {
    let config = NodeConfig::mainnet_preset();
    assert_eq!(
        config.signer_mode,
        SignerMode::EncryptedFsV1,
        "MainNet preset should default to EncryptedFsV1 signer mode"
    );
}

/// Test: DevNet preset has LoopbackTesting as default signer mode.
#[test]
fn devnet_preset_has_loopback_signer_mode() {
    let config = NodeConfig::devnet_v0_preset();
    assert_eq!(
        config.signer_mode,
        SignerMode::LoopbackTesting,
        "DevNet preset should default to LoopbackTesting signer mode"
    );
}

/// Test: TestNet Alpha/Beta presets have EncryptedFsV1 as default signer mode.
#[test]
fn testnet_presets_have_encrypted_fs_signer_mode() {
    let alpha = NodeConfig::testnet_alpha_preset();
    assert_eq!(
        alpha.signer_mode,
        SignerMode::EncryptedFsV1,
        "TestNet Alpha preset should default to EncryptedFsV1 signer mode"
    );

    let beta = NodeConfig::testnet_beta_preset();
    assert_eq!(
        beta.signer_mode,
        SignerMode::EncryptedFsV1,
        "TestNet Beta preset should default to EncryptedFsV1 signer mode"
    );
}

/// Test: LoopbackTesting signer mode is rejected on MainNet.
#[test]
fn validate_mainnet_invariants_rejects_loopback_signer_mode() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_mode(SignerMode::LoopbackTesting);

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::SignerModeLoopbackForbidden) => (),
        Err(e) => panic!("Expected SignerModeLoopbackForbidden error, got: {:?}", e),
        Ok(()) => panic!("Expected error for LoopbackTesting signer mode on MainNet"),
    }
}

/// Test: EncryptedFsV1 signer mode without keystore path is rejected on MainNet.
#[test]
fn validate_mainnet_invariants_rejects_missing_keystore_path() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_mode(SignerMode::EncryptedFsV1);
    // Note: signer_keystore_path is None

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::SignerKeystorePathMissing) => (),
        Err(e) => panic!("Expected SignerKeystorePathMissing error, got: {:?}", e),
        Ok(()) => panic!("Expected error for missing keystore path"),
    }
}

/// Test: RemoteSigner mode without URL is rejected on MainNet.
#[test]
fn validate_mainnet_invariants_rejects_missing_remote_signer_url() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_mode(SignerMode::RemoteSigner);
    // Note: remote_signer_url is None

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::RemoteSignerUrlMissing) => (),
        Err(e) => panic!("Expected RemoteSignerUrlMissing error, got: {:?}", e),
        Ok(()) => panic!("Expected error for missing remote signer URL"),
    }
}

/// Test: HsmPkcs11 signer mode without config path is rejected on MainNet.
#[test]
fn validate_mainnet_invariants_rejects_missing_hsm_config_path() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_mode(SignerMode::HsmPkcs11);
    // Note: hsm_config_path is None

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::HsmConfigPathMissing) => (),
        Err(e) => panic!("Expected HsmConfigPathMissing error, got: {:?}", e),
        Ok(()) => panic!("Expected error for missing HSM config path"),
    }
}

/// Test: Valid MainNet config with RemoteSigner passes validation.
#[test]
fn validate_mainnet_invariants_accepts_remote_signer_with_url() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_mode(SignerMode::RemoteSigner)
        .with_remote_signer_url("grpc://localhost:50051");

    let result = config.validate_mainnet_invariants();
    assert!(
        result.is_ok(),
        "Valid MainNet config with RemoteSigner should pass validation: {:?}",
        result
    );
}

/// Test: Valid MainNet config with HsmPkcs11 passes validation.
#[test]
fn validate_mainnet_invariants_accepts_hsm_with_config_path() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_mode(SignerMode::HsmPkcs11)
        .with_hsm_config_path("/etc/qbind/hsm.toml");

    let result = config.validate_mainnet_invariants();
    assert!(
        result.is_ok(),
        "Valid MainNet config with HsmPkcs11 should pass validation: {:?}",
        result
    );
}

/// Test: DevNet allows LoopbackTesting signer mode.
#[test]
fn devnet_allows_loopback_signer_mode() {
    let config = NodeConfig::devnet_v0_preset();
    assert_eq!(
        config.signer_mode,
        SignerMode::LoopbackTesting,
        "DevNet should allow LoopbackTesting signer mode"
    );
    // DevNet doesn't enforce MainNet invariants, so no validation error
}
// ============================================================================
// Part 8: T214 Signer Failure Mode Validation Tests
// ============================================================================

/// Test: MainNet preset has ExitOnFailure as default signer failure mode.
#[test]
fn mainnet_preset_has_exit_on_failure_mode() {
    let config = NodeConfig::mainnet_preset();
    assert_eq!(
        config.signer_failure_mode,
        SignerFailureMode::ExitOnFailure,
        "MainNet preset should default to ExitOnFailure signer failure mode"
    );
}

/// Test: MainNet rejects LogAndContinue signer failure mode.
#[test]
fn test_mainnet_rejects_signer_failure_mode_log_and_continue() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_signer_failure_mode(SignerFailureMode::LogAndContinue);

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err());
    match result {
        Err(MainnetConfigError::SignerFailureModeInvalid { actual }) => {
            assert_eq!(actual, SignerFailureMode::LogAndContinue);
        }
        Err(e) => panic!("Expected SignerFailureModeInvalid error, got: {:?}", e),
        Ok(()) => panic!("Expected error for LogAndContinue signer failure mode on MainNet"),
    }
}

/// Test: TestNet allows LogAndContinue signer failure mode (chaos testing).
#[test]
fn test_non_mainnet_allows_signer_failure_mode_log_and_continue() {
    // TestNet can use LogAndContinue for chaos testing
    let testnet_config = NodeConfig::testnet_beta_preset()
        .with_signer_failure_mode(SignerFailureMode::LogAndContinue);
    assert_eq!(
        testnet_config.signer_failure_mode,
        SignerFailureMode::LogAndContinue,
        "TestNet should allow LogAndContinue for chaos testing"
    );
    // Note: TestNet doesn't run validate_mainnet_invariants(), so this is valid

    // DevNet can also use LogAndContinue
    let devnet_config = NodeConfig::devnet_v0_preset()
        .with_signer_failure_mode(SignerFailureMode::LogAndContinue);
    assert_eq!(
        devnet_config.signer_failure_mode,
        SignerFailureMode::LogAndContinue,
        "DevNet should allow LogAndContinue for testing"
    );
}

/// Test: Valid MainNet config with ExitOnFailure passes validation.
#[test]
fn validate_mainnet_invariants_accepts_exit_on_failure() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_signer_failure_mode(SignerFailureMode::ExitOnFailure);

    let result = config.validate_mainnet_invariants();
    assert!(
        result.is_ok(),
        "Valid MainNet config with ExitOnFailure should pass validation: {:?}",
        result
    );
}

/// Test: All presets default to ExitOnFailure.
#[test]
fn all_presets_default_to_exit_on_failure() {
    let devnet = NodeConfig::devnet_v0_preset();
    assert_eq!(
        devnet.signer_failure_mode,
        SignerFailureMode::ExitOnFailure,
        "DevNet preset should default to ExitOnFailure"
    );

    let alpha = NodeConfig::testnet_alpha_preset();
    assert_eq!(
        alpha.signer_failure_mode,
        SignerFailureMode::ExitOnFailure,
        "TestNet Alpha preset should default to ExitOnFailure"
    );

    let beta = NodeConfig::testnet_beta_preset();
    assert_eq!(
        beta.signer_failure_mode,
        SignerFailureMode::ExitOnFailure,
        "TestNet Beta preset should default to ExitOnFailure"
    );

    let mainnet = NodeConfig::mainnet_preset();
    assert_eq!(
        mainnet.signer_failure_mode,
        SignerFailureMode::ExitOnFailure,
        "MainNet preset should default to ExitOnFailure"
    );
}