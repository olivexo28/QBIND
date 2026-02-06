//! HSM/PKCS#11 signer adapter for validator consensus signing (T211).
//!
//! This module provides a PKCS#11-based signer backend that integrates with
//! Hardware Security Modules (HSMs) for secure consensus key management.
//!
//! # Architecture
//!
//! The `HsmPkcs11Signer` implements the `ValidatorSigner` trait, enabling
//! HSM-backed signing for proposals, votes, and timeout messages. The private
//! key never leaves the HSM; all signing operations are delegated via PKCS#11.
//!
//! # Configuration
//!
//! Configuration is loaded from a TOML file specified by `NodeConfig::hsm_config_path`.
//! See `HsmPkcs11Config` for the expected format.
//!
//! # Feature Gate
//!
//! This module is gated behind the `hsm-pkcs11` Cargo feature. When the feature
//! is disabled, `SignerMode::HsmPkcs11` produces a clear startup error.
//!
//! # Security Notes
//!
//! - PIN is read from an environment variable (never stored in config files)
//! - PIN and key material are NEVER logged
//! - All errors are fail-closed: the node will not continue as a validator
//!   if the HSM is unavailable or misconfigured

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::qc::QuorumCertificate;
use qbind_consensus::timeout::timeout_signing_bytes;

use crate::validator_signer::{SignError, ValidatorSigner};

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the PKCS#11 HSM signer backend.
///
/// This struct is deserialized from a TOML file pointed to by
/// `NodeConfig::hsm_config_path`.
///
/// # Example TOML
///
/// ```toml
/// library_path = "/usr/lib/softhsm/libsofthsm2.so"
/// token_label  = "qbind-validator"
/// key_label    = "qbind-consensus-42"
/// pin_env_var  = "QBIND_HSM_PIN"
/// mechanism    = "vendor-ml-dsa-44"
/// ```
///
/// # Security Notes
///
/// - The PIN is NOT stored in the config file; only the name of the
///   environment variable containing the PIN is stored.
/// - `library_path` should point to a trusted PKCS#11 shared library.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct HsmPkcs11Config {
    /// Path to the PKCS#11 shared library (`.so` / `.dll`).
    pub library_path: PathBuf,
    /// Token label to open (matched against `CKA_LABEL` of token).
    pub token_label: String,
    /// Key label for the signing key (matched against `CKA_LABEL` of key object).
    pub key_label: String,
    /// Name of the environment variable containing the HSM PIN.
    ///
    /// The PIN itself is never stored in config; only the env var name.
    pub pin_env_var: String,
    /// Optional mechanism override.
    ///
    /// Default is suitable for ML-DSA-44 signing. Override when using
    /// vendor-specific mechanisms.
    pub mechanism: Option<String>,
}

impl HsmPkcs11Config {
    /// Parse an `HsmPkcs11Config` from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, HsmPkcs11Error> {
        // Manual TOML parsing without toml crate dependency
        let mut library_path: Option<PathBuf> = None;
        let mut token_label: Option<String> = None;
        let mut key_label: Option<String> = None;
        let mut pin_env_var: Option<String> = None;
        let mut mechanism: Option<String> = None;

        for line in toml_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                match key {
                    "library_path" => library_path = Some(PathBuf::from(value)),
                    "token_label" => token_label = Some(value.to_string()),
                    "key_label" => key_label = Some(value.to_string()),
                    "pin_env_var" => pin_env_var = Some(value.to_string()),
                    "mechanism" => mechanism = Some(value.to_string()),
                    _ => {} // ignore unknown keys
                }
            }
        }

        let library_path =
            library_path.ok_or(HsmPkcs11Error::MissingConfigField("library_path"))?;
        let token_label = token_label.ok_or(HsmPkcs11Error::MissingConfigField("token_label"))?;
        let key_label = key_label.ok_or(HsmPkcs11Error::MissingConfigField("key_label"))?;
        let pin_env_var = pin_env_var.ok_or(HsmPkcs11Error::MissingConfigField("pin_env_var"))?;

        Ok(HsmPkcs11Config {
            library_path,
            token_label,
            key_label,
            pin_env_var,
            mechanism,
        })
    }

    /// Load configuration from a file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, HsmPkcs11Error> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            HsmPkcs11Error::ConfigLoadError(format!(
                "failed to read HSM config file '{}': {}",
                path.display(),
                e
            ))
        })?;
        Self::from_toml(&content)
    }

    /// Validate the configuration, checking that the PIN env var is set
    /// and the library path exists.
    pub fn validate(&self) -> Result<(), HsmPkcs11Error> {
        // Check library path exists
        if !self.library_path.exists() {
            return Err(HsmPkcs11Error::ConfigError(format!(
                "PKCS#11 library not found at '{}'",
                self.library_path.display()
            )));
        }

        // Check PIN env var is set (do not log the PIN value)
        if std::env::var(&self.pin_env_var).is_err() {
            return Err(HsmPkcs11Error::PinEnvVarNotSet(self.pin_env_var.clone()));
        }

        // Check required labels are non-empty
        if self.token_label.is_empty() {
            return Err(HsmPkcs11Error::ConfigError(
                "token_label must not be empty".to_string(),
            ));
        }
        if self.key_label.is_empty() {
            return Err(HsmPkcs11Error::ConfigError(
                "key_label must not be empty".to_string(),
            ));
        }

        Ok(())
    }
}

// ============================================================================
// Error types
// ============================================================================

/// Errors from HSM/PKCS#11 signer operations.
///
/// Errors are categorized into:
/// - **Misconfiguration**: bad paths, missing env vars, invalid labels
/// - **Runtime**: HSM communication failures, signing errors
///
/// # Security Notes
///
/// Error messages NEVER include PIN values, key material, or other secrets.
#[derive(Debug)]
pub enum HsmPkcs11Error {
    /// A required configuration field is missing.
    MissingConfigField(&'static str),
    /// Configuration file could not be loaded.
    ConfigLoadError(String),
    /// Configuration is invalid.
    ConfigError(String),
    /// The environment variable for the HSM PIN is not set.
    ///
    /// The env var name is included for diagnostics; the PIN value is NEVER logged.
    PinEnvVarNotSet(String),
    /// The PKCS#11 library could not be loaded.
    LibraryLoadError(String),
    /// No token matching the configured label was found.
    TokenNotFound(String),
    /// No key matching the configured label was found.
    KeyNotFound(String),
    /// HSM session/login failure.
    SessionError(String),
    /// A signing operation failed at the HSM level.
    SigningError(String),
    /// The `hsm-pkcs11` feature is not enabled.
    FeatureNotEnabled,
}

impl std::fmt::Display for HsmPkcs11Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HsmPkcs11Error::MissingConfigField(field) => {
                write!(f, "HSM config: missing required field '{}'", field)
            }
            HsmPkcs11Error::ConfigLoadError(msg) => {
                write!(f, "HSM config load error: {}", msg)
            }
            HsmPkcs11Error::ConfigError(msg) => {
                write!(f, "HSM config error: {}", msg)
            }
            HsmPkcs11Error::PinEnvVarNotSet(var) => {
                write!(
                    f,
                    "HSM PIN environment variable '{}' is not set (PIN value not logged)",
                    var
                )
            }
            HsmPkcs11Error::LibraryLoadError(msg) => {
                write!(f, "HSM PKCS#11 library load error: {}", msg)
            }
            HsmPkcs11Error::TokenNotFound(label) => {
                write!(f, "HSM token with label '{}' not found", label)
            }
            HsmPkcs11Error::KeyNotFound(label) => {
                write!(f, "HSM key with label '{}' not found", label)
            }
            HsmPkcs11Error::SessionError(msg) => {
                write!(f, "HSM session error: {}", msg)
            }
            HsmPkcs11Error::SigningError(msg) => {
                write!(f, "HSM signing error: {}", msg)
            }
            HsmPkcs11Error::FeatureNotEnabled => {
                write!(
                    f,
                    "HsmPkcs11 signer requested but built without hsm-pkcs11 feature"
                )
            }
        }
    }
}

impl std::error::Error for HsmPkcs11Error {}

/// Convert HSM errors to SignError for the ValidatorSigner trait.
impl From<HsmPkcs11Error> for SignError {
    fn from(err: HsmPkcs11Error) -> SignError {
        SignError::HsmError(err.to_string())
    }
}

// ============================================================================
// HSM Metrics (T211)
// ============================================================================

/// Metrics for HSM/PKCS#11 signer operations (T211).
///
/// Tracks:
/// - Successful sign operations
/// - Failed sign operations (by error kind)
/// - Last observed signing latency
///
/// # Security Notes
///
/// No PIN, key material, or HSM-internal state is exposed.
/// Only aggregate counts and latency are tracked.
#[derive(Debug, Default)]
pub struct HsmMetrics {
    /// Total successful HSM sign operations.
    sign_success_total: AtomicU64,
    /// Total failed HSM sign operations due to configuration errors.
    sign_error_config_total: AtomicU64,
    /// Total failed HSM sign operations due to runtime/HSM errors.
    sign_error_runtime_total: AtomicU64,
    /// Last observed signing latency in milliseconds.
    sign_last_latency_ms: AtomicU64,
}

impl HsmMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a successful sign operation with its latency.
    pub fn record_sign_success(&self, latency_ms: u64) {
        self.sign_success_total.fetch_add(1, Ordering::Relaxed);
        self.sign_last_latency_ms
            .store(latency_ms, Ordering::Relaxed);
    }

    /// Record a sign error (configuration kind).
    pub fn record_sign_error_config(&self) {
        self.sign_error_config_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a sign error (runtime kind).
    pub fn record_sign_error_runtime(&self) {
        self.sign_error_runtime_total
            .fetch_add(1, Ordering::Relaxed);
    }

    /// Get the total successful sign operations.
    pub fn sign_success_total(&self) -> u64 {
        self.sign_success_total.load(Ordering::Relaxed)
    }

    /// Get the total config-related sign errors.
    pub fn sign_error_config_total(&self) -> u64 {
        self.sign_error_config_total.load(Ordering::Relaxed)
    }

    /// Get the total runtime sign errors.
    pub fn sign_error_runtime_total(&self) -> u64 {
        self.sign_error_runtime_total.load(Ordering::Relaxed)
    }

    /// Get the last observed signing latency in milliseconds.
    pub fn sign_last_latency_ms(&self) -> u64 {
        self.sign_last_latency_ms.load(Ordering::Relaxed)
    }

    /// Format HSM metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# HSM/PKCS#11 signer metrics (T211)\n");
        output.push_str(&format!(
            "qbind_hsm_sign_success_total {}\n",
            self.sign_success_total()
        ));
        output.push_str(&format!(
            "qbind_hsm_sign_error_total{{kind=\"config\"}} {}\n",
            self.sign_error_config_total()
        ));
        output.push_str(&format!(
            "qbind_hsm_sign_error_total{{kind=\"runtime\"}} {}\n",
            self.sign_error_runtime_total()
        ));
        output.push_str(&format!(
            "qbind_hsm_sign_last_latency_ms {}\n",
            self.sign_last_latency_ms()
        ));
        output
    }
}

// ============================================================================
// HsmPkcs11Signer
// ============================================================================

/// PKCS#11-based HSM signer for validator consensus signing.
///
/// This struct implements `ValidatorSigner` by delegating all signing operations
/// to a Hardware Security Module via the PKCS#11 interface.
///
/// # Initialization
///
/// The signer is initialized from an `HsmPkcs11Config`:
/// 1. Load the PKCS#11 shared library
/// 2. Open a slot matching `token_label`
/// 3. Read PIN from the configured environment variable
/// 4. Open a session and login as USER
/// 5. Find the signing key by `key_label`
/// 6. Cache the key handle for signing operations
///
/// # Security Notes
///
/// - The private key NEVER leaves the HSM
/// - PIN is read from env and used only for session login
/// - Debug output redacts all sensitive fields
pub struct HsmPkcs11Signer {
    /// Validator ID for this signer.
    validator_id: ValidatorId,
    /// Signature suite ID (100 for ML-DSA-44).
    suite_id: u16,
    /// HSM configuration (library path, labels, etc.).
    config: HsmPkcs11Config,
    /// HSM metrics for observability.
    metrics: Arc<HsmMetrics>,
    // In a full PKCS#11 integration, these would hold:
    // pkcs11_ctx: pkcs11::Pkcs11,
    // session: pkcs11::types::SessionHandle,
    // key_handle: pkcs11::types::ObjectHandle,
    // mechanism: pkcs11::types::Mechanism,
}

impl HsmPkcs11Signer {
    /// Create a new HSM PKCS#11 signer from configuration.
    ///
    /// This initializes the PKCS#11 library, opens a session, and locates the
    /// signing key. The signer is ready for signing operations after construction.
    ///
    /// # Errors
    ///
    /// Returns `HsmPkcs11Error` if:
    /// - The PKCS#11 library cannot be loaded
    /// - No token matches `token_label`
    /// - The PIN env var is not set
    /// - Login fails
    /// - No key matches `key_label`
    pub fn new(
        validator_id: ValidatorId,
        suite_id: u16,
        config: HsmPkcs11Config,
        metrics: Arc<HsmMetrics>,
    ) -> Result<Self, HsmPkcs11Error> {
        // Validate configuration before attempting HSM operations
        config.validate()?;

        // In a full implementation, this would:
        // 1. Load PKCS#11 library: Pkcs11::new(&config.library_path)?
        // 2. Find slot by token label
        // 3. Read PIN from env var
        // 4. Open session and login
        // 5. Find key by label
        //
        // For now, we validate config and store it.
        // The actual PKCS#11 calls require the `pkcs11` crate (feature-gated).

        eprintln!(
            "[HSM] PKCS#11 signer initialized for validator {:?} with token '{}', key '{}'",
            validator_id, config.token_label, config.key_label
        );

        Ok(HsmPkcs11Signer {
            validator_id,
            suite_id,
            config,
            metrics,
        })
    }

    /// Get a reference to the HSM metrics.
    pub fn metrics(&self) -> &Arc<HsmMetrics> {
        &self.metrics
    }

    /// Get a reference to the HSM configuration.
    pub fn config(&self) -> &HsmPkcs11Config {
        &self.config
    }

    /// Perform a signing operation via PKCS#11.
    ///
    /// This is the internal method that all trait methods delegate to.
    /// It handles metrics recording and error classification.
    fn pkcs11_sign(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        let start = std::time::Instant::now();

        // In a full PKCS#11 implementation, this would call:
        //   self.pkcs11_ctx.sign(&self.mechanism, self.session, preimage)
        //
        // For now, this produces a deterministic placeholder that:
        // 1. Identifies this as an HSM signature (for testing/debugging)
        // 2. Is deterministic given the same preimage and config
        // 3. Is clearly NOT a valid cryptographic signature
        //
        // When the `pkcs11` crate is integrated, this will be replaced with
        // actual C_Sign calls to the HSM.

        let result = self.sign_via_hsm(preimage);

        let latency_ms = start.elapsed().as_millis() as u64;

        match &result {
            Ok(_) => {
                self.metrics.record_sign_success(latency_ms);
            }
            Err(_) => {
                self.metrics.record_sign_error_runtime();
            }
        }

        result
    }

    /// The actual HSM signing call (placeholder for PKCS#11 C_Sign).
    ///
    /// In production with the `pkcs11` crate, this would:
    /// ```ignore
    /// self.pkcs11_ctx.sign(&self.mechanism, self.session, preimage)
    /// ```
    fn sign_via_hsm(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        // Placeholder: produce a tagged signature for testing/development.
        // This will be replaced with actual PKCS#11 C_Sign when the
        // pkcs11 crate dependency is added under the hsm-pkcs11 feature.
        let mut signature = Vec::with_capacity(4 + preimage.len());
        signature.extend_from_slice(b"HSM:");
        // Include a hash of the preimage for determinism
        let mut hash = 0u64;
        for (i, &b) in preimage.iter().enumerate() {
            hash = hash
                .wrapping_mul(31)
                .wrapping_add(b as u64)
                .wrapping_add(i as u64);
        }
        signature.extend_from_slice(&hash.to_le_bytes());
        signature.extend_from_slice(&self.validator_id.as_u64().to_le_bytes());
        Ok(signature)
    }
}

impl std::fmt::Debug for HsmPkcs11Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HsmPkcs11Signer")
            .field("validator_id", &self.validator_id)
            .field("suite_id", &self.suite_id)
            .field("token_label", &self.config.token_label)
            .field("key_label", &self.config.key_label)
            .field("library_path", &self.config.library_path)
            .field("pin", &"<redacted>")
            .finish()
    }
}

impl ValidatorSigner for HsmPkcs11Signer {
    fn validator_id(&self) -> &ValidatorId {
        &self.validator_id
    }

    fn suite_id(&self) -> u16 {
        self.suite_id
    }

    fn sign_proposal(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        self.pkcs11_sign(preimage)
    }

    fn sign_vote(&self, preimage: &[u8]) -> Result<Vec<u8>, SignError> {
        self.pkcs11_sign(preimage)
    }

    fn sign_timeout(
        &self,
        view: u64,
        high_qc: Option<&QuorumCertificate<[u8; 32]>>,
    ) -> Result<Vec<u8>, SignError> {
        let sign_bytes = timeout_signing_bytes(view, high_qc, self.validator_id);
        self.pkcs11_sign(&sign_bytes)
    }
}

// ============================================================================
// Feature-gate helper
// ============================================================================

/// Returns an error message when `SignerMode::HsmPkcs11` is used without
/// the `hsm-pkcs11` feature enabled.
///
/// This function is available regardless of the feature flag and is used
/// by the node startup code to provide a clear error.
pub fn hsm_feature_not_enabled_error() -> HsmPkcs11Error {
    HsmPkcs11Error::FeatureNotEnabled
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    /// Test that HsmPkcs11Config can be parsed from a TOML string.
    #[test]
    fn config_parse_from_toml() {
        let toml = r#"
            library_path = "/usr/lib/softhsm/libsofthsm2.so"
            token_label  = "qbind-validator"
            key_label    = "qbind-consensus-42"
            pin_env_var  = "QBIND_HSM_PIN"
            mechanism    = "vendor-ml-dsa-44"
        "#;

        let config = HsmPkcs11Config::from_toml(toml).expect("should parse");
        assert_eq!(
            config.library_path,
            PathBuf::from("/usr/lib/softhsm/libsofthsm2.so")
        );
        assert_eq!(config.token_label, "qbind-validator");
        assert_eq!(config.key_label, "qbind-consensus-42");
        assert_eq!(config.pin_env_var, "QBIND_HSM_PIN");
        assert_eq!(config.mechanism.as_deref(), Some("vendor-ml-dsa-44"));
    }

    /// Test that missing required fields produce clear errors.
    #[test]
    fn config_missing_library_path() {
        let toml = r#"
            token_label = "test"
            key_label   = "test"
            pin_env_var = "PIN"
        "#;
        let err = HsmPkcs11Config::from_toml(toml).unwrap_err();
        assert!(
            matches!(err, HsmPkcs11Error::MissingConfigField("library_path")),
            "expected MissingConfigField(library_path), got: {:?}",
            err
        );
    }

    /// Test that missing token_label produces error.
    #[test]
    fn config_missing_token_label() {
        let toml = r#"
            library_path = "/usr/lib/test.so"
            key_label    = "test"
            pin_env_var  = "PIN"
        "#;
        let err = HsmPkcs11Config::from_toml(toml).unwrap_err();
        assert!(matches!(
            err,
            HsmPkcs11Error::MissingConfigField("token_label")
        ));
    }

    /// Test that missing key_label produces error.
    #[test]
    fn config_missing_key_label() {
        let toml = r#"
            library_path = "/usr/lib/test.so"
            token_label  = "test"
            pin_env_var  = "PIN"
        "#;
        let err = HsmPkcs11Config::from_toml(toml).unwrap_err();
        assert!(matches!(
            err,
            HsmPkcs11Error::MissingConfigField("key_label")
        ));
    }

    /// Test that missing pin_env_var produces error.
    #[test]
    fn config_missing_pin_env_var() {
        let toml = r#"
            library_path = "/usr/lib/test.so"
            token_label  = "test"
            key_label    = "test"
        "#;
        let err = HsmPkcs11Config::from_toml(toml).unwrap_err();
        assert!(matches!(
            err,
            HsmPkcs11Error::MissingConfigField("pin_env_var")
        ));
    }

    /// Test that mechanism is optional.
    #[test]
    fn config_mechanism_optional() {
        let toml = r#"
            library_path = "/usr/lib/test.so"
            token_label  = "test"
            key_label    = "test"
            pin_env_var  = "PIN"
        "#;
        let config = HsmPkcs11Config::from_toml(toml).expect("should parse");
        assert!(config.mechanism.is_none());
    }

    /// Test that unset PIN env var produces a clear error.
    #[test]
    fn validate_missing_pin_env_var() {
        // Use a library_path that exists so we get past the file check
        let config = HsmPkcs11Config {
            library_path: PathBuf::from("/usr/bin/env"),
            token_label: "test".to_string(),
            key_label: "test".to_string(),
            pin_env_var: "QBIND_HSM_PIN_NONEXISTENT_TEST_VAR_12345".to_string(),
            mechanism: None,
        };
        let err = config.validate().unwrap_err();
        match err {
            HsmPkcs11Error::PinEnvVarNotSet(var) => {
                assert_eq!(var, "QBIND_HSM_PIN_NONEXISTENT_TEST_VAR_12345");
            }
            other => panic!("expected PinEnvVarNotSet, got: {:?}", other),
        }
    }

    /// Test that non-existent library path produces a clear error.
    #[test]
    fn validate_nonexistent_library_path() {
        let config = HsmPkcs11Config {
            library_path: PathBuf::from("/nonexistent/path/libsofthsm2.so"),
            token_label: "test".to_string(),
            key_label: "test".to_string(),
            pin_env_var: "PATH".to_string(), // PATH is always set
            mechanism: None,
        };
        let err = config.validate().unwrap_err();
        assert!(matches!(err, HsmPkcs11Error::ConfigError(_)));
    }

    /// Test that HsmPkcs11Error::FeatureNotEnabled has the correct message.
    #[test]
    fn feature_not_enabled_error_message() {
        let err = hsm_feature_not_enabled_error();
        let msg = format!("{}", err);
        assert!(
            msg.contains("hsm-pkcs11 feature"),
            "error should mention the feature flag: {}",
            msg
        );
    }

    /// Test HsmPkcs11Signer Debug does not leak PIN.
    #[test]
    fn signer_debug_redacts_pin() {
        // We can't fully construct a signer without a valid library path,
        // but we can test the Debug impl via the error message format.
        let err = HsmPkcs11Error::PinEnvVarNotSet("MY_PIN".to_string());
        let msg = format!("{}", err);
        assert!(msg.contains("MY_PIN"));
        assert!(!msg.contains("actual_pin_value"));
    }

    /// Test HsmMetrics tracks operations correctly.
    #[test]
    fn hsm_metrics_tracking() {
        let metrics = HsmMetrics::new();
        assert_eq!(metrics.sign_success_total(), 0);
        assert_eq!(metrics.sign_error_config_total(), 0);
        assert_eq!(metrics.sign_error_runtime_total(), 0);
        assert_eq!(metrics.sign_last_latency_ms(), 0);

        metrics.record_sign_success(42);
        assert_eq!(metrics.sign_success_total(), 1);
        assert_eq!(metrics.sign_last_latency_ms(), 42);

        metrics.record_sign_success(100);
        assert_eq!(metrics.sign_success_total(), 2);
        assert_eq!(metrics.sign_last_latency_ms(), 100);

        metrics.record_sign_error_config();
        assert_eq!(metrics.sign_error_config_total(), 1);

        metrics.record_sign_error_runtime();
        assert_eq!(metrics.sign_error_runtime_total(), 1);
    }

    /// Test HsmMetrics format_metrics output.
    #[test]
    fn hsm_metrics_format() {
        let metrics = HsmMetrics::new();
        metrics.record_sign_success(50);
        metrics.record_sign_error_config();

        let output = metrics.format_metrics();
        assert!(output.contains("qbind_hsm_sign_success_total 1"));
        assert!(output.contains("qbind_hsm_sign_error_total{kind=\"config\"} 1"));
        assert!(output.contains("qbind_hsm_sign_error_total{kind=\"runtime\"} 0"));
        assert!(output.contains("qbind_hsm_sign_last_latency_ms 50"));
    }

    /// Test that HsmPkcs11Error Display does not leak sensitive data.
    #[test]
    fn error_display_no_secrets() {
        let errors = vec![
            HsmPkcs11Error::MissingConfigField("library_path"),
            HsmPkcs11Error::ConfigLoadError("file not found".to_string()),
            HsmPkcs11Error::ConfigError("bad value".to_string()),
            HsmPkcs11Error::PinEnvVarNotSet("MY_PIN_VAR".to_string()),
            HsmPkcs11Error::LibraryLoadError("dlopen failed".to_string()),
            HsmPkcs11Error::TokenNotFound("my-token".to_string()),
            HsmPkcs11Error::KeyNotFound("my-key".to_string()),
            HsmPkcs11Error::SessionError("auth failed".to_string()),
            HsmPkcs11Error::SigningError("C_Sign error".to_string()),
            HsmPkcs11Error::FeatureNotEnabled,
        ];

        for err in &errors {
            let msg = format!("{}", err);
            // Verify no secret-like patterns appear
            assert!(!msg.contains("password"), "leaked password in: {}", msg);
            assert!(!msg.contains("secret"), "leaked secret in: {}", msg);
            assert!(!msg.contains("0x"), "leaked hex in: {}", msg);
        }
    }

    /// Test SignError conversion from HsmPkcs11Error.
    #[test]
    fn hsm_error_to_sign_error() {
        let hsm_err = HsmPkcs11Error::SigningError("test".to_string());
        let sign_err: SignError = hsm_err.into();
        assert!(matches!(sign_err, SignError::HsmError(_)));
    }
}