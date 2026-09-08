//! M4 Slashing Mode Enforcement Tests
//!
//! This module tests the M4 requirement: MainNet cannot run with slashing disabled
//! (RecordOnly / Off modes). Fail fast at startup if misconfigured.
//!
//! ## Coverage Summary
//!
//! | Network | Mode | Expected Result |
//! |---------|------|-----------------|
//! | MainNet | Off | REJECT (error) |
//! | MainNet | RecordOnly | REJECT (error) |
//! | MainNet | EnforceCritical | ACCEPT |
//! | MainNet | EnforceAll | ACCEPT |
//! | TestNet | Off | REJECT (error) |
//! | TestNet | RecordOnly | ACCEPT (warning) |
//! | TestNet | EnforceCritical | ACCEPT (preferred) |
//! | TestNet | EnforceAll | ACCEPT |
//! | DevNet | Off | ACCEPT |
//! | DevNet | RecordOnly | ACCEPT |
//! | DevNet | EnforceCritical | ACCEPT |
//! | DevNet | EnforceAll | ACCEPT |
//!
//! ## Related Requirements
//!
//! - M4: Enforce slashing mode for MainNet (ban RecordOnly)
//! - T229: Slashing penalty engine infrastructure

use qbind_node::node_config::{SlashingConfig, SlashingMode};

// ============================================================================
// MainNet Slashing Mode Tests
// ============================================================================

/// Test: MainNet rejects SlashingMode::Off
#[test]
fn test_mainnet_rejects_slashing_mode_off() {
    let config = SlashingConfig {
        mode: SlashingMode::Off,
        ..SlashingConfig::mainnet_default()
    };

    let result = config.validate_for_mainnet();

    assert!(result.is_err(), "MainNet should reject SlashingMode::Off");
    let err = result.unwrap_err();
    assert!(
        err.contains("off") || err.contains("Off"),
        "Error should mention 'off' mode: {}",
        err
    );
}

/// Test: MainNet rejects SlashingMode::RecordOnly (M4 core requirement)
#[test]
fn test_mainnet_rejects_slashing_mode_record_only() {
    let config = SlashingConfig {
        mode: SlashingMode::RecordOnly,
        ..SlashingConfig::mainnet_default()
    };

    let result = config.validate_for_mainnet();

    assert!(
        result.is_err(),
        "MainNet should reject SlashingMode::RecordOnly (M4)"
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("record_only") || err.contains("RecordOnly"),
        "Error should mention 'record_only' mode: {}",
        err
    );
    assert!(
        err.contains("M4") || err.contains("forbidden"),
        "Error should indicate this is forbidden: {}",
        err
    );
}

/// Test: MainNet accepts SlashingMode::EnforceCritical
#[test]
fn test_mainnet_accepts_slashing_mode_enforce_critical() {
    let config = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        ..SlashingConfig::mainnet_default()
    };

    let result = config.validate_for_mainnet();

    assert!(
        result.is_ok(),
        "MainNet should accept SlashingMode::EnforceCritical: {:?}",
        result
    );
}

/// Test: MainNet accepts SlashingMode::EnforceAll
#[test]
fn test_mainnet_accepts_slashing_mode_enforce_all() {
    let config = SlashingConfig {
        mode: SlashingMode::EnforceAll,
        ..SlashingConfig::mainnet_default()
    };

    let result = config.validate_for_mainnet();

    assert!(
        result.is_ok(),
        "MainNet should accept SlashingMode::EnforceAll: {:?}",
        result
    );
}

/// Test: MainNet default configuration uses EnforceCritical (M4 requirement)
#[test]
fn test_mainnet_default_uses_enforce_critical() {
    let config = SlashingConfig::mainnet_default();

    assert_eq!(
        config.mode,
        SlashingMode::EnforceCritical,
        "MainNet default should be EnforceCritical per M4"
    );

    // Should pass validation
    assert!(
        config.validate_for_mainnet().is_ok(),
        "MainNet default should pass validation"
    );
}

// ============================================================================
// TestNet Slashing Mode Tests
// ============================================================================

/// Test: TestNet rejects SlashingMode::Off
#[test]
fn test_testnet_rejects_slashing_mode_off() {
    let config = SlashingConfig {
        mode: SlashingMode::Off,
        ..SlashingConfig::testnet_alpha_default()
    };

    let result = config.validate_for_testnet();

    assert!(result.is_err(), "TestNet should reject SlashingMode::Off");
    let err = result.unwrap_err();
    assert!(
        err.contains("off") || err.contains("Off"),
        "Error should mention 'off' mode: {}",
        err
    );
}

/// Test: TestNet allows SlashingMode::RecordOnly (with warning, returns false)
#[test]
fn test_testnet_allows_slashing_mode_record_only_with_warning() {
    let config = SlashingConfig {
        mode: SlashingMode::RecordOnly,
        ..SlashingConfig::testnet_alpha_default()
    };

    let result = config.validate_for_testnet();

    // Should succeed but return false (warning logged)
    assert!(
        result.is_ok(),
        "TestNet should allow SlashingMode::RecordOnly (with warning)"
    );
    assert_eq!(
        result.unwrap(),
        false,
        "RecordOnly should return false (indicates warning was logged)"
    );
}

/// Test: TestNet accepts SlashingMode::EnforceCritical (preferred, returns true)
#[test]
fn test_testnet_accepts_slashing_mode_enforce_critical() {
    let config = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        ..SlashingConfig::testnet_alpha_default()
    };

    let result = config.validate_for_testnet();

    assert!(
        result.is_ok(),
        "TestNet should accept SlashingMode::EnforceCritical"
    );
    assert_eq!(
        result.unwrap(),
        true,
        "EnforceCritical should return true (preferred mode)"
    );
}

/// Test: TestNet accepts SlashingMode::EnforceAll (returns true)
#[test]
fn test_testnet_accepts_slashing_mode_enforce_all() {
    let config = SlashingConfig {
        mode: SlashingMode::EnforceAll,
        ..SlashingConfig::testnet_alpha_default()
    };

    let result = config.validate_for_testnet();

    assert!(
        result.is_ok(),
        "TestNet should accept SlashingMode::EnforceAll"
    );
    assert_eq!(
        result.unwrap(),
        true,
        "EnforceAll should return true (valid enforcing mode)"
    );
}

/// Test: TestNet default configuration uses EnforceCritical (M4 preference)
#[test]
fn test_testnet_default_uses_enforce_critical() {
    let alpha_config = SlashingConfig::testnet_alpha_default();
    let beta_config = SlashingConfig::testnet_beta_default();

    assert_eq!(
        alpha_config.mode,
        SlashingMode::EnforceCritical,
        "TestNet Alpha default should be EnforceCritical per M4"
    );
    assert_eq!(
        beta_config.mode,
        SlashingMode::EnforceCritical,
        "TestNet Beta default should be EnforceCritical per M4"
    );
}

// ============================================================================
// DevNet Slashing Mode Tests
// ============================================================================

/// Test: DevNet allows SlashingMode::Off (testing flexibility)
#[test]
fn test_devnet_allows_slashing_mode_off() {
    let config = SlashingConfig {
        mode: SlashingMode::Off,
        ..SlashingConfig::devnet_default()
    };

    let result = config.validate_for_devnet();

    assert!(
        result.is_ok(),
        "DevNet should allow SlashingMode::Off for testing"
    );
}

/// Test: DevNet allows SlashingMode::RecordOnly (testing flexibility)
#[test]
fn test_devnet_allows_slashing_mode_record_only() {
    let config = SlashingConfig {
        mode: SlashingMode::RecordOnly,
        ..SlashingConfig::devnet_default()
    };

    let result = config.validate_for_devnet();

    assert!(
        result.is_ok(),
        "DevNet should allow SlashingMode::RecordOnly for testing"
    );
}

/// Test: DevNet allows SlashingMode::EnforceCritical
#[test]
fn test_devnet_allows_slashing_mode_enforce_critical() {
    let config = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        ..SlashingConfig::devnet_default()
    };

    let result = config.validate_for_devnet();

    assert!(
        result.is_ok(),
        "DevNet should allow SlashingMode::EnforceCritical"
    );
}

/// Test: DevNet allows SlashingMode::EnforceAll
#[test]
fn test_devnet_allows_slashing_mode_enforce_all() {
    let config = SlashingConfig {
        mode: SlashingMode::EnforceAll,
        ..SlashingConfig::devnet_default()
    };

    let result = config.validate_for_devnet();

    assert!(
        result.is_ok(),
        "DevNet should allow SlashingMode::EnforceAll"
    );
}

/// Test: DevNet default configuration uses EnforceCritical (for practical testing)
#[test]
fn test_devnet_default_uses_enforce_critical() {
    let config = SlashingConfig::devnet_default();

    assert_eq!(
        config.mode,
        SlashingMode::EnforceCritical,
        "DevNet default should be EnforceCritical for practical testing"
    );
}

// ============================================================================
// Parameter Validation Tests
// ============================================================================

/// Test: MainNet validates slash parameters when enforcing
#[test]
fn test_mainnet_validates_slash_parameters() {
    // Invalid O1 slash percentage (too low)
    let config_low = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1_double_sign: 100, // Below 500 minimum
        ..SlashingConfig::mainnet_default()
    };
    assert!(
        config_low.validate_for_mainnet().is_err(),
        "Should reject O1 slash below 500 bps"
    );

    // Invalid O1 slash percentage (too high)
    let config_high = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1_double_sign: 2000, // Above 1000 maximum
        ..SlashingConfig::mainnet_default()
    };
    assert!(
        config_high.validate_for_mainnet().is_err(),
        "Should reject O1 slash above 1000 bps"
    );

    // Valid O1 slash percentage
    let config_valid = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o1_double_sign: 750, // Within range
        ..SlashingConfig::mainnet_default()
    };
    assert!(
        config_valid.validate_for_mainnet().is_ok(),
        "Should accept O1 slash at 750 bps"
    );
}

/// Test: TestNet validates slash parameters when enforcing
#[test]
fn test_testnet_validates_slash_parameters() {
    // Invalid O2 slash percentage (too low)
    let config_low = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o2_invalid_proposer_sig: 100, // Below 450 minimum
        ..SlashingConfig::testnet_alpha_default()
    };
    let result = config_low.validate_for_testnet();
    assert!(
        result.is_err(),
        "Should reject O2 slash below 450 bps"
    );

    // Invalid O2 slash percentage (too high)
    let config_high = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o2_invalid_proposer_sig: 1000, // Above 550 maximum
        ..SlashingConfig::testnet_alpha_default()
    };
    let result = config_high.validate_for_testnet();
    assert!(
        result.is_err(),
        "Should reject O2 slash above 550 bps"
    );

    // Valid O2 slash percentage
    let config_valid = SlashingConfig {
        mode: SlashingMode::EnforceCritical,
        slash_bps_o2_invalid_proposer_sig: 500, // Within range
        ..SlashingConfig::testnet_alpha_default()
    };
    let result = config_valid.validate_for_testnet();
    assert!(
        result.is_ok(),
        "Should accept O2 slash at 500 bps"
    );
}

// ============================================================================
// Environment Isolation Tests
// ============================================================================

/// Test: Configuration created for one environment doesn't accidentally
/// validate for a stricter environment
#[test]
fn test_environment_isolation() {
    // DevNet config with Off mode should NOT pass MainNet validation
    let devnet_config = SlashingConfig {
        mode: SlashingMode::Off,
        ..SlashingConfig::devnet_default()
    };
    assert!(
        devnet_config.validate_for_devnet().is_ok(),
        "DevNet config should pass DevNet validation"
    );
    assert!(
        devnet_config.validate_for_mainnet().is_err(),
        "DevNet Off config should NOT pass MainNet validation"
    );

    // TestNet config with RecordOnly should NOT pass MainNet validation
    let testnet_config = SlashingConfig {
        mode: SlashingMode::RecordOnly,
        ..SlashingConfig::testnet_alpha_default()
    };
    assert!(
        testnet_config.validate_for_testnet().is_ok(),
        "TestNet RecordOnly config should pass TestNet validation"
    );
    assert!(
        testnet_config.validate_for_mainnet().is_err(),
        "TestNet RecordOnly config should NOT pass MainNet validation"
    );
}

/// Test: MainNet config passes all environment validations
#[test]
fn test_mainnet_config_passes_all_validations() {
    let mainnet_config = SlashingConfig::mainnet_default();

    assert!(
        mainnet_config.validate_for_mainnet().is_ok(),
        "MainNet default should pass MainNet validation"
    );
    assert!(
        mainnet_config.validate_for_testnet().is_ok(),
        "MainNet default should pass TestNet validation"
    );
    assert!(
        mainnet_config.validate_for_devnet().is_ok(),
        "MainNet default should pass DevNet validation"
    );
}