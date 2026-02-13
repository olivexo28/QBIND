//! M8: Mutual Auth Mode Environment Gating tests.
//!
//! These tests verify that:
//! 1. MainNet rejects Disabled and Optional modes
//! 2. TestNet rejects Disabled mode but allows Optional with warning
//! 3. DevNet allows all modes
//! 4. Default configurations are correct for each environment

use qbind_node::node_config::{MutualAuthConfig, MutualAuthMode, parse_mutual_auth_mode};

// ============================================================================
// Parsing Tests
// ============================================================================

#[test]
fn test_parse_mutual_auth_mode_required() {
    assert_eq!(parse_mutual_auth_mode("required"), Some(MutualAuthMode::Required));
    assert_eq!(parse_mutual_auth_mode("REQUIRED"), Some(MutualAuthMode::Required));
    assert_eq!(parse_mutual_auth_mode("require"), Some(MutualAuthMode::Required));
}

#[test]
fn test_parse_mutual_auth_mode_optional() {
    assert_eq!(parse_mutual_auth_mode("optional"), Some(MutualAuthMode::Optional));
    assert_eq!(parse_mutual_auth_mode("OPTIONAL"), Some(MutualAuthMode::Optional));
    assert_eq!(parse_mutual_auth_mode("opt"), Some(MutualAuthMode::Optional));
}

#[test]
fn test_parse_mutual_auth_mode_disabled() {
    assert_eq!(parse_mutual_auth_mode("disabled"), Some(MutualAuthMode::Disabled));
    assert_eq!(parse_mutual_auth_mode("DISABLED"), Some(MutualAuthMode::Disabled));
    assert_eq!(parse_mutual_auth_mode("disable"), Some(MutualAuthMode::Disabled));
    assert_eq!(parse_mutual_auth_mode("off"), Some(MutualAuthMode::Disabled));
    assert_eq!(parse_mutual_auth_mode("none"), Some(MutualAuthMode::Disabled));
}

#[test]
fn test_parse_mutual_auth_mode_invalid() {
    assert_eq!(parse_mutual_auth_mode("invalid"), None);
    assert_eq!(parse_mutual_auth_mode(""), None);
    assert_eq!(parse_mutual_auth_mode("enable"), None);
}

// ============================================================================
// Default Configuration Tests
// ============================================================================

#[test]
fn test_default_config_is_required() {
    let config = MutualAuthConfig::default();
    assert_eq!(config.mode, MutualAuthMode::Required);
}

#[test]
fn test_devnet_default_is_disabled() {
    let config = MutualAuthConfig::devnet_default();
    assert_eq!(config.mode, MutualAuthMode::Disabled);
}

#[test]
fn test_testnet_alpha_default_is_required() {
    let config = MutualAuthConfig::testnet_alpha_default();
    assert_eq!(config.mode, MutualAuthMode::Required);
}

#[test]
fn test_testnet_beta_default_is_required() {
    let config = MutualAuthConfig::testnet_beta_default();
    assert_eq!(config.mode, MutualAuthMode::Required);
}

#[test]
fn test_mainnet_default_is_required() {
    let config = MutualAuthConfig::mainnet_default();
    assert_eq!(config.mode, MutualAuthMode::Required);
}

// ============================================================================
// MainNet Validation Tests (M8)
// ============================================================================

#[test]
fn test_mainnet_accepts_required_mode() {
    let config = MutualAuthConfig {
        mode: MutualAuthMode::Required,
    };
    assert!(config.validate_for_mainnet().is_ok());
}

#[test]
fn test_mainnet_rejects_optional_mode() {
    let config = MutualAuthConfig {
        mode: MutualAuthMode::Optional,
    };
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("optional"));
    assert!(err.contains("MainNet"));
    assert!(err.contains("M8"));
}

#[test]
fn test_mainnet_rejects_disabled_mode() {
    let config = MutualAuthConfig {
        mode: MutualAuthMode::Disabled,
    };
    let result = config.validate_for_mainnet();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("disabled"));
    assert!(err.contains("MainNet"));
    assert!(err.contains("M8"));
}

// ============================================================================
// TestNet Validation Tests (M8)
// ============================================================================

#[test]
fn test_testnet_accepts_required_mode() {
    let config = MutualAuthConfig {
        mode: MutualAuthMode::Required,
    };
    assert!(config.validate_for_testnet().is_ok());
}

#[test]
fn test_testnet_accepts_optional_mode_with_warning() {
    let config = MutualAuthConfig {
        mode: MutualAuthMode::Optional,
    };
    // Optional is allowed but should log a warning (we can't test the warning directly)
    assert!(config.validate_for_testnet().is_ok());
}

#[test]
fn test_testnet_rejects_disabled_mode() {
    let config = MutualAuthConfig {
        mode: MutualAuthMode::Disabled,
    };
    let result = config.validate_for_testnet();
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(err.contains("disabled"));
    assert!(err.contains("TestNet"));
    assert!(err.contains("M8"));
}

// ============================================================================
// DevNet Flexibility Tests (M8)
// ============================================================================

#[test]
fn test_devnet_allows_all_modes() {
    // DevNet doesn't have validate_for_devnet() because all modes are allowed
    // This test verifies that all modes can be constructed without error
    let _required = MutualAuthConfig { mode: MutualAuthMode::Required };
    let _optional = MutualAuthConfig { mode: MutualAuthMode::Optional };
    let _disabled = MutualAuthConfig { mode: MutualAuthMode::Disabled };
    
    // DevNet default is Disabled for testing flexibility
    let devnet = MutualAuthConfig::devnet_default();
    assert_eq!(devnet.mode, MutualAuthMode::Disabled);
}

// ============================================================================
// Display Tests
// ============================================================================

#[test]
fn test_mutual_auth_mode_display() {
    assert_eq!(format!("{}", MutualAuthMode::Required), "required");
    assert_eq!(format!("{}", MutualAuthMode::Optional), "optional");
    assert_eq!(format!("{}", MutualAuthMode::Disabled), "disabled");
}