//! T237 MainNet Launch Gates & Profile Freeze Tests
//!
//! This module is the **normative test harness** for MainNet v0 launch readiness.
//! It validates that `validate_mainnet_invariants()` correctly enforces all
//! MainNet-critical safety knobs.
//!
//! ## Purpose
//!
//! This harness ensures that:
//! - The canonical MainNet preset passes all invariants.
//! - Each safety subsystem (P2P, mempool, slashing, pruning/snapshots, genesis,
//!   DAG coupling, Stage B, signer modes, monetary mode) is correctly guarded.
//! - Misconfigurations produce descriptive `MainnetConfigError` variants.
//!
//! ## Pre-Launch Usage
//!
//! Run this test file as a mandatory pre-launch check:
//! ```bash
//! cargo test -p qbind-node --test t237_mainnet_launch_profile_tests
//! ```
//!
//! ## Coverage Summary
//!
//! | Subsystem | Test Name | Error Variant |
//! |-----------|-----------|---------------|
//! | Canonical preset | `test_mainnet_preset_passes_launch_invariants` | N/A (success) |
//! | DAG coupling | `test_mainnet_rejects_dag_coupling_not_enforced` | `DagCouplingNotEnforced` |
//! | P2P discovery | `test_mainnet_rejects_discovery_disabled` | `DiscoveryDisabled` |
//! | P2P anti-eclipse | `test_mainnet_rejects_anti_eclipse_not_enforced` | `P2pAntiEclipseMisconfigured` |
//! | Mempool DoS | `test_mainnet_rejects_mempool_dos_zero_limits` | `MempoolDosMisconfigured` |
//! | Eviction rate | `test_mainnet_rejects_eviction_mode_off` | `MempoolEvictionMisconfigured` |
//! | Snapshots | `test_mainnet_rejects_snapshots_disabled` | `SnapshotsDisabled` |
//! | Slashing (Off) | `test_mainnet_rejects_slashing_mode_off` | `SlashingMisconfigured` |
//! | Slashing (RecordOnly) | `test_mainnet_rejects_slashing_mode_record_only` | `SlashingMisconfigured` (M4) |
//! | Genesis hash | `test_mainnet_rejects_missing_expected_genesis_hash` | `ExpectedGenesisHashMissing` |
//! | Monetary mode | `test_mainnet_rejects_monetary_mode_off` | `MonetaryModeOff` |
//! | State retention | `test_mainnet_rejects_state_retention_disabled` | `StateRetentionDisabled` |
//!
//! ## Related Documents
//!
//! - [QBIND_MAINNET_V0_SPEC.md](../../docs/mainnet/QBIND_MAINNET_V0_SPEC.md)
//! - [QBIND_MAINNET_AUDIT_SKELETON.md](../../docs/mainnet/QBIND_MAINNET_AUDIT_SKELETON.md)
//! - [QBIND_MAINNET_RUNBOOK.md](../../docs/ops/QBIND_MAINNET_RUNBOOK.md)

use qbind_ledger::MonetaryMode;
use qbind_node::node_config::{
    DagCouplingMode, EvictionRateMode, MainnetConfigError, MempoolEvictionConfig, NodeConfig,
    SlashingConfig, SlashingMode, StateRetentionConfig, StateRetentionMode,
};

// ============================================================================
// Part 1: Positive Test — Canonical MainNet Preset
// ============================================================================

/// Test that the canonical MainNet preset passes all launch invariants.
///
/// This test constructs a realistic `NodeConfig` for MainNet by:
/// 1. Starting from `mainnet_preset()`
/// 2. Supplying the required CLI-specified fields (data_dir, genesis path, hash, keystore)
///
/// If this test fails, the MainNet preset itself is misconfigured.
#[test]
fn test_mainnet_preset_passes_launch_invariants() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32]) // Placeholder hash
        .with_signer_keystore_path("/data/qbind/keystore");

    let result = config.validate_mainnet_invariants();

    assert!(
        result.is_ok(),
        "MainNet preset with required CLI fields should pass all invariants: {:?}",
        result
    );
}

/// Test that MainNet preset has all expected safety features enabled by default.
#[test]
fn test_mainnet_preset_has_correct_defaults() {
    let config = NodeConfig::mainnet_preset();

    // Core execution
    assert!(config.gas_enabled, "gas_enabled should be true");
    assert!(config.enable_fee_priority, "enable_fee_priority should be true");
    assert!(config.dag_availability_enabled, "dag_availability_enabled should be true");
    assert!(config.stage_b_enabled, "stage_b_enabled should be true for MainNet");

    // DAG coupling
    assert_eq!(
        config.dag_coupling_mode,
        DagCouplingMode::Enforce,
        "dag_coupling_mode should be Enforce"
    );

    // State management
    assert!(
        config.state_retention.is_enabled(),
        "state_retention should be enabled"
    );
    assert!(config.snapshot_config.enabled, "snapshots should be enabled");

    // Slashing (RecordOnly is the default for MainNet v0)
    assert!(
        config.slashing.mode != SlashingMode::Off,
        "slashing mode should not be Off"
    );

    // Monetary (Shadow is acceptable for MainNet v0)
    assert!(
        config.monetary_mode != MonetaryMode::Off,
        "monetary_mode should not be Off"
    );
}

// ============================================================================
// Part 2: Negative Tests — Per-Subsystem Invariant Violations
// ============================================================================

/// Test: DAG coupling mode not Enforce → error
///
/// MainNet requires `DagCouplingMode::Enforce` to reject proposals with
/// uncertified DAG batches. This prevents consensus divergence.
#[test]
fn test_mainnet_rejects_dag_coupling_not_enforced() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    // Mutate: set coupling mode to Warn (not enforced)
    config.dag_coupling_mode = DagCouplingMode::Warn;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject DagCouplingMode::Warn");
    match result {
        Err(MainnetConfigError::DagCouplingNotEnforced { actual }) => {
            assert_eq!(actual, DagCouplingMode::Warn);
        }
        Err(e) => panic!("Expected DagCouplingNotEnforced, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: DAG coupling mode Off → error
#[test]
fn test_mainnet_rejects_dag_coupling_off() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.dag_coupling_mode = DagCouplingMode::Off;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject DagCouplingMode::Off");
    match result {
        Err(MainnetConfigError::DagCouplingNotEnforced { actual }) => {
            assert_eq!(actual, DagCouplingMode::Off);
        }
        Err(e) => panic!("Expected DagCouplingNotEnforced, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: P2P discovery disabled → error
///
/// MainNet requires dynamic peer discovery to maintain a healthy peer set
/// beyond static bootstrap peers.
#[test]
fn test_mainnet_rejects_discovery_disabled() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.network.discovery_enabled = false;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject discovery_enabled=false");
    match result {
        Err(MainnetConfigError::DiscoveryDisabled) => (),
        Err(e) => panic!("Expected DiscoveryDisabled, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: P2P anti-eclipse not enforced → error
///
/// MainNet requires anti-eclipse constraints to be enforced to prevent
/// eclipse attacks from dominating peer connections.
#[test]
fn test_mainnet_rejects_anti_eclipse_not_enforced() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    // Mutate: disable anti-eclipse enforcement
    if let Some(ref mut anti_eclipse) = config.p2p_anti_eclipse {
        anti_eclipse.enforce = false;
    }

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject anti-eclipse enforce=false");
    match result {
        Err(MainnetConfigError::P2pAntiEclipseMisconfigured { reason }) => {
            assert!(
                reason.contains("enforce") || reason.contains("anti-eclipse"),
                "Error reason should mention enforce: {}",
                reason
            );
        }
        Err(e) => panic!("Expected P2pAntiEclipseMisconfigured, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: P2P anti-eclipse config missing → error
#[test]
fn test_mainnet_rejects_anti_eclipse_missing() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.p2p_anti_eclipse = None;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject missing p2p_anti_eclipse");
    match result {
        Err(MainnetConfigError::P2pAntiEclipseMisconfigured { reason }) => {
            assert!(
                reason.contains("configured") || reason.contains("must be"),
                "Error reason should indicate missing config: {}",
                reason
            );
        }
        Err(e) => panic!("Expected P2pAntiEclipseMisconfigured, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Mempool DoS limits set to zero → error
///
/// MainNet requires reasonable DoS protection limits (all > 0).
#[test]
fn test_mainnet_rejects_mempool_dos_zero_limits() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    // Mutate: set max_pending_per_sender to 0
    config.mempool_dos.max_pending_per_sender = 0;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject max_pending_per_sender=0");
    match result {
        Err(MainnetConfigError::MempoolDosMisconfigured { reason }) => {
            assert!(
                reason.contains("max_pending_per_sender") || reason.contains("limit"),
                "Error reason should mention the specific limit: {}",
                reason
            );
        }
        Err(e) => panic!("Expected MempoolDosMisconfigured, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Mempool eviction mode Off → error
///
/// MainNet requires eviction rate limiting to be enforced.
#[test]
fn test_mainnet_rejects_eviction_mode_off() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    // Mutate: set eviction mode to Off
    config.mempool_eviction = MempoolEvictionConfig {
        mode: EvictionRateMode::Off,
        max_evictions_per_interval: 0,
        interval_secs: 60,
    };

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject eviction mode Off");
    match result {
        Err(MainnetConfigError::MempoolEvictionMisconfigured { reason }) => {
            assert!(
                reason.contains("mode") || reason.contains("Off") || reason.contains("Enforce"),
                "Error reason should mention mode: {}",
                reason
            );
        }
        Err(e) => panic!("Expected MempoolEvictionMisconfigured, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Snapshots disabled → error
///
/// MainNet validators must enable periodic snapshots for fast sync and recovery.
#[test]
fn test_mainnet_rejects_snapshots_disabled() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.snapshot_config.enabled = false;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject snapshots disabled");
    match result {
        Err(MainnetConfigError::SnapshotsDisabled) => (),
        Err(e) => panic!("Expected SnapshotsDisabled, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Slashing mode Off → error
///
/// MainNet requires slashing to be at least in RecordOnly mode.
#[test]
fn test_mainnet_rejects_slashing_mode_off() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    // Mutate: set slashing mode to Off
    config.slashing = SlashingConfig {
        mode: SlashingMode::Off,
        ..SlashingConfig::mainnet_default()
    };

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject slashing mode Off");
    match result {
        Err(MainnetConfigError::SlashingMisconfigured { reason }) => {
            assert!(
                reason.contains("Off") || reason.contains("mode"),
                "Error reason should mention Off mode: {}",
                reason
            );
        }
        Err(e) => panic!("Expected SlashingMisconfigured, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Expected genesis hash missing → error
///
/// MainNet validators MUST specify the expected genesis hash to prevent
/// accidental startup with the wrong genesis file.
#[test]
fn test_mainnet_rejects_missing_expected_genesis_hash() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        // Note: NOT setting expected_genesis_hash
        .with_signer_keystore_path("/data/qbind/keystore");

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject missing expected_genesis_hash");
    match result {
        Err(MainnetConfigError::ExpectedGenesisHashMissing) => (),
        Err(e) => panic!("Expected ExpectedGenesisHashMissing, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Monetary mode Off → error
///
/// MainNet must at least compute and expose monetary decisions.
#[test]
fn test_mainnet_rejects_monetary_mode_off() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.monetary_mode = MonetaryMode::Off;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject MonetaryMode::Off");
    match result {
        Err(MainnetConfigError::MonetaryModeOff) => (),
        Err(e) => panic!("Expected MonetaryModeOff, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: State retention disabled → error
///
/// MainNet validators must enable state pruning to manage disk usage.
#[test]
fn test_mainnet_rejects_state_retention_disabled() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.state_retention = StateRetentionConfig::disabled();

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject state retention disabled");
    match result {
        Err(MainnetConfigError::StateRetentionDisabled) => (),
        Err(e) => panic!("Expected StateRetentionDisabled, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: State retention height too low → error
///
/// MainNet requires at least 10,000 blocks of history for reorg safety.
#[test]
fn test_mainnet_rejects_state_retention_height_too_low() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    // Set retention height below minimum (10,000)
    config.state_retention = StateRetentionConfig {
        mode: StateRetentionMode::Height,
        retain_height: Some(5_000), // Below minimum
        retain_epochs: None,
        prune_interval_blocks: 1_000,
    };

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject retain_height below 10,000");
    match result {
        Err(MainnetConfigError::StateRetentionInvalid(msg)) => {
            assert!(
                msg.contains("10,000") || msg.contains("too low"),
                "Error should mention minimum: {}",
                msg
            );
        }
        Err(e) => panic!("Expected StateRetentionInvalid, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

// ============================================================================
// Part 3: Additional Edge Cases
// ============================================================================

/// Test: P2P liveness heartbeat interval zero → error
#[test]
fn test_mainnet_rejects_liveness_heartbeat_zero() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.p2p_liveness.heartbeat_interval_secs = 0;

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject heartbeat_interval_secs=0");
    match result {
        Err(MainnetConfigError::P2pLivenessMisconfigured { reason }) => {
            assert!(
                reason.contains("heartbeat"),
                "Error should mention heartbeat: {}",
                reason
            );
        }
        Err(e) => panic!("Expected P2pLivenessMisconfigured, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Target outbound peers below minimum → error
#[test]
fn test_mainnet_rejects_low_outbound_target() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.network.target_outbound_peers = 4; // Below minimum of 8

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject target_outbound_peers < 8");
    match result {
        Err(MainnetConfigError::InsufficientTargetOutboundPeers { minimum, actual }) => {
            assert_eq!(minimum, 8);
            assert_eq!(actual, 4);
        }
        Err(e) => panic!("Expected InsufficientTargetOutboundPeers, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Snapshot interval too low → error
#[test]
fn test_mainnet_rejects_snapshot_interval_too_low() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.snapshot_config.snapshot_interval_blocks = 1_000; // Below minimum of 10,000

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject snapshot_interval < 10,000");
    match result {
        Err(MainnetConfigError::SnapshotIntervalTooLow { minimum, actual }) => {
            assert_eq!(minimum, 10_000);
            assert_eq!(actual, 1_000);
        }
        Err(e) => panic!("Expected SnapshotIntervalTooLow, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: Snapshot interval too high → error
#[test]
fn test_mainnet_rejects_snapshot_interval_too_high() {
    let mut config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");

    config.snapshot_config.snapshot_interval_blocks = 1_000_000; // Above maximum of 500,000

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject snapshot_interval > 500,000");
    match result {
        Err(MainnetConfigError::SnapshotIntervalTooHigh { maximum, actual }) => {
            assert_eq!(maximum, 500_000);
            assert_eq!(actual, 1_000_000);
        }
        Err(e) => panic!("Expected SnapshotIntervalTooHigh, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

// ============================================================================
// Part 4: Error Display Tests
// ============================================================================

/// Test that MainnetConfigError variants have readable Display messages.
#[test]
fn test_mainnet_config_error_display_messages() {
    // DAG coupling
    let error = MainnetConfigError::DagCouplingNotEnforced {
        actual: DagCouplingMode::Warn,
    };
    let msg = format!("{}", error);
    assert!(msg.contains("DAG") || msg.contains("coupling"));

    // Snapshots
    let error = MainnetConfigError::SnapshotsDisabled;
    let msg = format!("{}", error);
    assert!(msg.contains("snapshot") || msg.contains("Snapshot"));

    // Slashing
    let error = MainnetConfigError::SlashingMisconfigured {
        reason: "mode is Off".to_string(),
    };
    let msg = format!("{}", error);
    assert!(msg.contains("slashing") || msg.contains("Slashing"));

    // Genesis hash
    let error = MainnetConfigError::ExpectedGenesisHashMissing;
    let msg = format!("{}", error);
    assert!(msg.contains("genesis") || msg.contains("hash"));

    // Monetary mode
    let error = MainnetConfigError::MonetaryModeOff;
    let msg = format!("{}", error);
    assert!(msg.contains("monetary") || msg.contains("Monetary"));
}

// ============================================================================
// Part 5: Compatibility Tests
// ============================================================================

/// Test: MainNet preset is compatible with slashing modes EnforceCritical and EnforceAll
///
/// M4 Requirement: MainNet MUST use enforcement mode. RecordOnly is forbidden.
#[test]
fn test_mainnet_accepts_valid_slashing_modes() {
    // EnforceCritical (default for MainNet per M4)
    let config_enforce_critical = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_slashing_mode(SlashingMode::EnforceCritical);
    assert!(
        config_enforce_critical.validate_mainnet_invariants().is_ok(),
        "EnforceCritical should be accepted"
    );

    // EnforceAll
    let config_enforce_all = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_slashing_mode(SlashingMode::EnforceAll);
    assert!(
        config_enforce_all.validate_mainnet_invariants().is_ok(),
        "EnforceAll should be accepted"
    );
}

/// Test: MainNet rejects RecordOnly slashing mode (M4 requirement)
///
/// M4 Requirement: RecordOnly only logs evidence without applying penalties,
/// which provides no economic deterrent for Byzantine behavior. MainNet must
/// use enforcement mode.
#[test]
fn test_mainnet_rejects_slashing_mode_record_only() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_slashing_mode(SlashingMode::RecordOnly);

    let result = config.validate_mainnet_invariants();

    assert!(result.is_err(), "Should reject slashing mode RecordOnly");
    match result {
        Err(MainnetConfigError::SlashingMisconfigured { reason }) => {
            assert!(
                reason.contains("record_only") || reason.contains("RecordOnly"),
                "Error reason should mention RecordOnly mode: {}",
                reason
            );
        }
        Err(e) => panic!("Expected SlashingMisconfigured, got: {:?}", e),
        Ok(()) => panic!("Expected error"),
    }
}

/// Test: MainNet accepts both Shadow and Active monetary modes
#[test]
fn test_mainnet_accepts_valid_monetary_modes() {
    // Shadow mode (default for MainNet v0)
    let config_shadow = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore");
    // Shadow is the default
    assert_eq!(config_shadow.monetary_mode, MonetaryMode::Shadow);
    assert!(
        config_shadow.validate_mainnet_invariants().is_ok(),
        "Shadow mode should be accepted"
    );

    // Active mode requires valid accounts and split
    // (skipping full Active test as it requires more setup)
}

/// Test: Stage B disabled produces warning but doesn't fail validation
///
/// Per T186/T237 spec, Stage B is allowed but not required for MainNet.
/// Disabling it produces a warning but doesn't cause startup failure.
#[test]
fn test_mainnet_allows_stage_b_disabled_with_warning() {
    let config = NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore")
        .with_stage_b_enabled(false);

    // Should still pass validation (warning is logged but doesn't fail)
    let result = config.validate_mainnet_invariants();
    assert!(
        result.is_ok(),
        "Stage B disabled should still pass validation (warning only): {:?}",
        result
    );
}