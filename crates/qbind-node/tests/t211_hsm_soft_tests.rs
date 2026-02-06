//! T211 – SoftHSM integration tests for PKCS#11 signer adapter.
//!
//! These tests are `#[ignore]` by default because they require:
//! - SoftHSM2 installed (`apt install softhsm2`)
//! - A token pre-provisioned with an ML-DSA-44 key labeled `qbind-consensus-42`
//!
//! # SoftHSM Setup
//!
//! ```bash
//! # Install SoftHSM2
//! sudo apt-get install -y softhsm2
//!
//! # Initialize a token
//! softhsm2-util --init-token --slot 0 \
//!     --label "qbind-validator" \
//!     --pin 1234 --so-pin 5678
//!
//! # Set the PIN environment variable
//! export QBIND_HSM_PIN=1234
//!
//! # Run the integration tests
//! cargo test -p qbind-node --test t211_hsm_soft_tests --features hsm-pkcs11 -- --ignored
//! ```
//!
//! # Notes
//!
//! - The SoftHSM library is typically at `/usr/lib/softhsm/libsofthsm2.so`
//!   or `/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so`
//! - ML-DSA-44 key provisioning in SoftHSM requires vendor-specific tooling;
//!   for initial testing, any key type that exercises the C_Sign path is acceptable
//! - These tests validate the config → signer → sign flow, not cryptographic correctness

use qbind_node::hsm_pkcs11::{HsmMetrics, HsmPkcs11Config, HsmPkcs11Error, HsmPkcs11Signer};
use qbind_node::validator_signer::ValidatorSigner;

use qbind_consensus::ids::ValidatorId;
use std::path::PathBuf;
use std::sync::Arc;

// ============================================================================
// Config-only tests (no HSM needed)
// ============================================================================

/// Verify that a complete config parses without error.
#[test]
fn config_roundtrip_toml() {
    let toml = r#"
        library_path = "/usr/lib/softhsm/libsofthsm2.so"
        token_label  = "qbind-validator"
        key_label    = "qbind-consensus-42"
        pin_env_var  = "QBIND_HSM_PIN"
    "#;

    let cfg = HsmPkcs11Config::from_toml(toml).expect("valid TOML");
    assert_eq!(cfg.token_label, "qbind-validator");
    assert_eq!(cfg.key_label, "qbind-consensus-42");
    assert_eq!(cfg.pin_env_var, "QBIND_HSM_PIN");
    assert!(cfg.mechanism.is_none());
}

/// Verify that config with mechanism parses correctly.
#[test]
fn config_with_mechanism_parses() {
    let toml = r#"
        library_path = "/usr/lib/softhsm/libsofthsm2.so"
        token_label  = "qbind-validator"
        key_label    = "qbind-consensus-42"
        pin_env_var  = "QBIND_HSM_PIN"
        mechanism    = "vendor-ml-dsa-44"
    "#;

    let cfg = HsmPkcs11Config::from_toml(toml).expect("valid TOML");
    assert_eq!(cfg.mechanism.as_deref(), Some("vendor-ml-dsa-44"));
}

/// Verify that missing fields produce clear errors.
#[test]
fn config_missing_fields_errors() {
    // Missing all required fields
    let toml = "";
    let err = HsmPkcs11Config::from_toml(toml);
    assert!(err.is_err());

    // Missing just key_label
    let toml = r#"
        library_path = "/usr/lib/test.so"
        token_label  = "test"
        pin_env_var  = "PIN"
    "#;
    let err = HsmPkcs11Config::from_toml(toml).unwrap_err();
    assert!(matches!(err, HsmPkcs11Error::MissingConfigField("key_label")));
}

/// Verify feature-not-enabled error message.
#[test]
fn feature_not_enabled_error() {
    let err = qbind_node::hsm_pkcs11::hsm_feature_not_enabled_error();
    let msg = format!("{}", err);
    assert!(msg.contains("hsm-pkcs11 feature"));
}

// ============================================================================
// SoftHSM Integration Tests (require SoftHSM2 + provisioned token)
// ============================================================================

/// Full sign cycle using SoftHSM.
///
/// # Prerequisites
///
/// - SoftHSM2 installed and configured
/// - Token labeled "qbind-validator" initialized
/// - Key labeled "qbind-consensus-42" provisioned
/// - `QBIND_HSM_PIN` environment variable set
///
/// # Run
///
/// ```bash
/// cargo test -p qbind-node --test t211_hsm_soft_tests --features hsm-pkcs11 -- --ignored
/// ```
#[test]
#[ignore]
fn softhsm_sign_operations() {
    let config = HsmPkcs11Config {
        library_path: PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        token_label: "qbind-validator".to_string(),
        key_label: "qbind-consensus-42".to_string(),
        pin_env_var: "QBIND_HSM_PIN".to_string(),
        mechanism: None,
    };

    let metrics = Arc::new(HsmMetrics::new());
    let validator_id = ValidatorId::new(42);

    let signer = HsmPkcs11Signer::new(validator_id, 100, config, metrics.clone())
        .expect("HSM signer init should succeed");

    // Perform signing operations
    let proposal_sig = signer
        .sign_proposal(b"test proposal")
        .expect("proposal signing should succeed");
    assert!(!proposal_sig.is_empty(), "signature should not be empty");

    let vote_sig = signer
        .sign_vote(b"test vote")
        .expect("vote signing should succeed");
    assert!(!vote_sig.is_empty(), "signature should not be empty");

    let timeout_sig = signer
        .sign_timeout(10, None)
        .expect("timeout signing should succeed");
    assert!(
        !timeout_sig.is_empty(),
        "timeout signature should not be empty"
    );

    // Verify metrics were updated
    assert_eq!(
        metrics.sign_success_total(),
        3,
        "3 successful sign operations"
    );
    assert_eq!(
        metrics.sign_error_config_total(),
        0,
        "no config errors expected"
    );
    assert_eq!(
        metrics.sign_error_runtime_total(),
        0,
        "no runtime errors expected"
    );
}

/// Verify that metrics format includes HSM counters.
#[test]
#[ignore]
fn softhsm_metrics_format() {
    let config = HsmPkcs11Config {
        library_path: PathBuf::from("/usr/lib/softhsm/libsofthsm2.so"),
        token_label: "qbind-validator".to_string(),
        key_label: "qbind-consensus-42".to_string(),
        pin_env_var: "QBIND_HSM_PIN".to_string(),
        mechanism: None,
    };

    let metrics = Arc::new(HsmMetrics::new());
    let validator_id = ValidatorId::new(42);

    let signer = HsmPkcs11Signer::new(validator_id, 100, config, metrics.clone())
        .expect("HSM signer init should succeed");

    // Sign once
    signer
        .sign_proposal(b"test")
        .expect("signing should succeed");

    // Check metrics format
    let output = metrics.format_metrics();
    assert!(output.contains("qbind_hsm_sign_success_total 1"));
    assert!(output.contains("qbind_hsm_sign_error_total"));
    assert!(output.contains("qbind_hsm_sign_last_latency_ms"));
}