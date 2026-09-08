//! M10.1 Signer Policy Enforcement Tests
//!
//! Tests for production-ready signer policy enforcement (M10.1).
//!
//! # Test Categories
//!
//! 1. **Policy validation functions**: MainNet/TestNet/DevNet signer mode validation
//! 2. **LoopbackTesting rejection**: Rejected on MainNet/TestNet, allowed on DevNet
//! 3. **MainNet configuration**: RemoteSigner requires KEMTLS cert paths
//! 4. **Production signer modes**: EncryptedFsV1, RemoteSigner, HsmPkcs11 accepted

use qbind_node::node_config::{
    is_production_signer_mode, validate_signer_mode_for_devnet,
    validate_signer_mode_for_mainnet, validate_signer_mode_for_testnet, MainnetConfigError,
    NodeConfig, SignerMode,
};
use std::path::PathBuf;

// ============================================================================
// Helper: Create a fully-configured MainNet config for testing
// ============================================================================

/// Create a MainNet config that passes all validation except the signer-related checks.
fn make_mainnet_config_for_signer_testing() -> NodeConfig {
    // Start with mainnet preset and provide all required fields
    NodeConfig::mainnet_preset()
        .with_data_dir("/data/qbind")
        .with_genesis_path("/data/qbind/genesis.json")
        .with_expected_genesis_hash([0xAB; 32])
        .with_signer_keystore_path("/data/qbind/keystore")
}

// ============================================================================
// Policy Validation Function Tests (M10.1)
// ============================================================================

#[test]
fn m10_1_validate_signer_mode_mainnet_rejects_loopback() {
    // LoopbackTesting is FORBIDDEN on MainNet
    let result = validate_signer_mode_for_mainnet(SignerMode::LoopbackTesting);
    assert!(result.is_err(), "LoopbackTesting should be rejected on MainNet");
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("FORBIDDEN") && err_msg.contains("MainNet"),
        "Error should mention FORBIDDEN and MainNet: {}",
        err_msg
    );
}

#[test]
fn m10_1_validate_signer_mode_mainnet_accepts_encrypted_fs() {
    // EncryptedFsV1 is allowed (with recommendation for higher security)
    let result = validate_signer_mode_for_mainnet(SignerMode::EncryptedFsV1);
    assert!(result.is_ok(), "EncryptedFsV1 should be accepted on MainNet");
}

#[test]
fn m10_1_validate_signer_mode_mainnet_accepts_remote_signer() {
    // RemoteSigner is PREFERRED on MainNet
    let result = validate_signer_mode_for_mainnet(SignerMode::RemoteSigner);
    assert!(result.is_ok(), "RemoteSigner should be accepted on MainNet");
}

#[test]
fn m10_1_validate_signer_mode_mainnet_accepts_hsm_pkcs11() {
    // HsmPkcs11 is PREFERRED on MainNet
    let result = validate_signer_mode_for_mainnet(SignerMode::HsmPkcs11);
    assert!(result.is_ok(), "HsmPkcs11 should be accepted on MainNet");
}

#[test]
fn m10_1_validate_signer_mode_testnet_rejects_loopback() {
    // LoopbackTesting is FORBIDDEN on TestNet (same security posture as MainNet)
    let result = validate_signer_mode_for_testnet(SignerMode::LoopbackTesting);
    assert!(result.is_err(), "LoopbackTesting should be rejected on TestNet");
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("FORBIDDEN") && err_msg.contains("TestNet"),
        "Error should mention FORBIDDEN and TestNet: {}",
        err_msg
    );
}

#[test]
fn m10_1_validate_signer_mode_testnet_accepts_production_modes() {
    // All production modes are allowed on TestNet
    assert!(validate_signer_mode_for_testnet(SignerMode::EncryptedFsV1).is_ok());
    assert!(validate_signer_mode_for_testnet(SignerMode::RemoteSigner).is_ok());
    assert!(validate_signer_mode_for_testnet(SignerMode::HsmPkcs11).is_ok());
}

#[test]
fn m10_1_validate_signer_mode_devnet_allows_all_modes() {
    // DevNet allows all modes, including LoopbackTesting for development convenience
    assert!(validate_signer_mode_for_devnet(SignerMode::LoopbackTesting).is_ok());
    assert!(validate_signer_mode_for_devnet(SignerMode::EncryptedFsV1).is_ok());
    assert!(validate_signer_mode_for_devnet(SignerMode::RemoteSigner).is_ok());
    assert!(validate_signer_mode_for_devnet(SignerMode::HsmPkcs11).is_ok());
}

// ============================================================================
// is_production_signer_mode Tests (M10.1)
// ============================================================================

#[test]
fn m10_1_is_production_signer_mode_loopback_false() {
    assert!(!is_production_signer_mode(SignerMode::LoopbackTesting));
}

#[test]
fn m10_1_is_production_signer_mode_encrypted_fs_true() {
    assert!(is_production_signer_mode(SignerMode::EncryptedFsV1));
}

#[test]
fn m10_1_is_production_signer_mode_remote_signer_true() {
    assert!(is_production_signer_mode(SignerMode::RemoteSigner));
}

#[test]
fn m10_1_is_production_signer_mode_hsm_pkcs11_true() {
    assert!(is_production_signer_mode(SignerMode::HsmPkcs11));
}

// ============================================================================
// MainNet Configuration Validation Tests (M10.1)
// ============================================================================

#[test]
fn m10_1_mainnet_config_rejects_loopback_signer_mode() {
    let mut config = make_mainnet_config_for_signer_testing();
    config.signer_mode = SignerMode::LoopbackTesting;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err(), "MainNet should reject LoopbackTesting signer mode");

    match result {
        Err(MainnetConfigError::SignerModeLoopbackForbidden) => {
            // Expected error
        }
        Err(other) => {
            panic!(
                "Expected SignerModeLoopbackForbidden, got {:?}",
                other
            );
        }
        Ok(()) => panic!("Should have failed validation"),
    }
}

#[test]
fn m10_1_mainnet_config_requires_remote_signer_url() {
    let mut config = make_mainnet_config_for_signer_testing();
    config.signer_mode = SignerMode::RemoteSigner;
    config.remote_signer_url = None;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err(), "MainNet should require remote_signer_url when RemoteSigner mode");

    match result {
        Err(MainnetConfigError::RemoteSignerUrlMissing) => {
            // Expected error
        }
        Err(other) => {
            panic!(
                "Expected RemoteSignerUrlMissing, got {:?}",
                other
            );
        }
        Ok(()) => panic!("Should have failed validation"),
    }
}

#[test]
fn m10_1_mainnet_config_requires_remote_signer_cert_paths() {
    let mut config = make_mainnet_config_for_signer_testing();
    config.signer_mode = SignerMode::RemoteSigner;
    config.remote_signer_url = Some("kemtls://signer.local:9443".to_string());
    config.remote_signer_cert_path = None;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err(), "MainNet should require remote_signer_cert_path when RemoteSigner mode");

    match result {
        Err(MainnetConfigError::RemoteSignerCertPathMissing) => {
            // Expected error
        }
        Err(other) => {
            panic!(
                "Expected RemoteSignerCertPathMissing, got {:?}",
                other
            );
        }
        Ok(()) => panic!("Should have failed validation"),
    }
}

#[test]
fn m10_1_mainnet_config_requires_remote_signer_client_cert() {
    let mut config = make_mainnet_config_for_signer_testing();
    config.signer_mode = SignerMode::RemoteSigner;
    config.remote_signer_url = Some("kemtls://signer.local:9443".to_string());
    config.remote_signer_cert_path = Some(PathBuf::from("/etc/qbind/signer_cert.pem"));
    config.remote_signer_client_cert_path = None;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err(), "MainNet should require remote_signer_client_cert_path when RemoteSigner mode");

    match result {
        Err(MainnetConfigError::RemoteSignerClientCertPathMissing) => {
            // Expected error
        }
        Err(other) => {
            panic!(
                "Expected RemoteSignerClientCertPathMissing, got {:?}",
                other
            );
        }
        Ok(()) => panic!("Should have failed validation"),
    }
}

#[test]
fn m10_1_mainnet_config_requires_remote_signer_client_key() {
    let mut config = make_mainnet_config_for_signer_testing();
    config.signer_mode = SignerMode::RemoteSigner;
    config.remote_signer_url = Some("kemtls://signer.local:9443".to_string());
    config.remote_signer_cert_path = Some(PathBuf::from("/etc/qbind/signer_cert.pem"));
    config.remote_signer_client_cert_path = Some(PathBuf::from("/etc/qbind/client_cert.pem"));
    config.remote_signer_client_key_path = None;

    let result = config.validate_mainnet_invariants();
    assert!(result.is_err(), "MainNet should require remote_signer_client_key_path when RemoteSigner mode");

    match result {
        Err(MainnetConfigError::RemoteSignerClientKeyPathMissing) => {
            // Expected error
        }
        Err(other) => {
            panic!(
                "Expected RemoteSignerClientKeyPathMissing, got {:?}",
                other
            );
        }
        Ok(()) => panic!("Should have failed validation"),
    }
}

// ============================================================================
// SignerMode Display and Parse Tests (M10.1)
// ============================================================================

#[test]
fn m10_1_signer_mode_display() {
    assert_eq!(format!("{}", SignerMode::LoopbackTesting), "loopback-testing");
    assert_eq!(format!("{}", SignerMode::EncryptedFsV1), "encrypted-fs");
    assert_eq!(format!("{}", SignerMode::RemoteSigner), "remote-signer");
    assert_eq!(format!("{}", SignerMode::HsmPkcs11), "hsm-pkcs11");
}

#[test]
fn m10_1_parse_signer_mode() {
    use qbind_node::node_config::parse_signer_mode;

    assert_eq!(parse_signer_mode("loopback-testing"), Some(SignerMode::LoopbackTesting));
    assert_eq!(parse_signer_mode("loopback"), Some(SignerMode::LoopbackTesting));
    assert_eq!(parse_signer_mode("testing"), Some(SignerMode::LoopbackTesting));

    assert_eq!(parse_signer_mode("encrypted-fs"), Some(SignerMode::EncryptedFsV1));
    assert_eq!(parse_signer_mode("encrypted-fs-v1"), Some(SignerMode::EncryptedFsV1));
    assert_eq!(parse_signer_mode("encrypted"), Some(SignerMode::EncryptedFsV1));

    assert_eq!(parse_signer_mode("remote-signer"), Some(SignerMode::RemoteSigner));
    assert_eq!(parse_signer_mode("remote"), Some(SignerMode::RemoteSigner));

    assert_eq!(parse_signer_mode("hsm-pkcs11"), Some(SignerMode::HsmPkcs11));
    assert_eq!(parse_signer_mode("hsm"), Some(SignerMode::HsmPkcs11));
    assert_eq!(parse_signer_mode("pkcs11"), Some(SignerMode::HsmPkcs11));

    assert_eq!(parse_signer_mode("invalid"), None);
    assert_eq!(parse_signer_mode(""), None);
}

// ============================================================================
// Error Message Quality Tests (M10.1)
// ============================================================================

#[test]
fn m10_1_error_message_contains_guidance() {
    // LoopbackTesting rejection on MainNet should mention alternatives
    let result = validate_signer_mode_for_mainnet(SignerMode::LoopbackTesting);
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("remote-signer") || err_msg.contains("hsm-pkcs11") || err_msg.contains("encrypted-fs"),
        "Error message should suggest alternatives: {}",
        err_msg
    );
}

#[test]
fn m10_1_error_message_explains_reason() {
    // LoopbackTesting rejection should explain the security concern
    let result = validate_signer_mode_for_mainnet(SignerMode::LoopbackTesting);
    let err_msg = result.unwrap_err();
    assert!(
        err_msg.contains("key") || err_msg.contains("plaintext") || err_msg.contains("protect"),
        "Error message should explain security concern: {}",
        err_msg
    );
}
