//! qbind-remote-signer: Remote signer daemon for QBIND validator nodes (T212).
//!
//! This daemon provides a signing service that allows consensus nodes to request
//! signatures without holding private key material locally.
//!
//! # Security Notes
//!
//! - Private key material never leaves the signer host
//! - Request validation prevents unauthorized signing
//! - Rate limiting prevents DoS attacks
//! - PIN and key material are NEVER logged

use std::net::TcpListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser;
use qbind_consensus::ids::ValidatorId;
use qbind_node::remote_signer::{
    RemoteSignError, RemoteSignRequest, RemoteSignRequestKind, RemoteSignResponse,
    MAX_PREIMAGE_SIZE,
};
use qbind_node::validator_signer::ValidatorSigner;

// ============================================================================
// Configuration
// ============================================================================

/// Configuration for the remote signer daemon.
#[derive(Debug, Clone)]
pub struct RemoteSignerConfig {
    /// TCP address to listen on (e.g., "0.0.0.0:9443").
    pub listen_addr: String,
    /// Validator ID that this signer serves.
    pub validator_id: u64,
    /// Backend signer mode: "encrypted-fs" or "hsm-pkcs11".
    pub backend_mode: String,
    /// Path to the encrypted keystore (for encrypted-fs mode).
    pub keystore_path: Option<PathBuf>,
    /// Keystore entry ID (for encrypted-fs mode).
    pub keystore_entry_id: Option<String>,
    /// Path to the HSM configuration file (for hsm-pkcs11 mode).
    pub hsm_config_path: Option<PathBuf>,
    /// Rate limit: maximum requests per second per connection.
    pub rate_limit_rps: u32,
    /// Name of environment variable containing the keystore passphrase.
    pub passphrase_env_var: String,
}

impl RemoteSignerConfig {
    /// Parse configuration from a TOML string.
    pub fn from_toml(toml_str: &str) -> Result<Self, ConfigError> {
        let mut listen_addr: Option<String> = None;
        let mut validator_id: Option<u64> = None;
        let mut backend_mode: Option<String> = None;
        let mut keystore_path: Option<PathBuf> = None;
        let mut keystore_entry_id: Option<String> = None;
        let mut hsm_config_path: Option<PathBuf> = None;
        let mut rate_limit_rps: u32 = 100;
        let mut passphrase_env_var = "QBIND_KEYSTORE_PASSPHRASE".to_string();

        for line in toml_str.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim().trim_matches('"');
                match key {
                    "listen_addr" => listen_addr = Some(value.to_string()),
                    "validator_id" => validator_id = value.parse().ok(),
                    "backend_mode" => backend_mode = Some(value.to_string()),
                    "keystore_path" => keystore_path = Some(PathBuf::from(value)),
                    "keystore_entry_id" => keystore_entry_id = Some(value.to_string()),
                    "hsm_config_path" => hsm_config_path = Some(PathBuf::from(value)),
                    "rate_limit_rps" => {
                        if let Ok(v) = value.parse() {
                            rate_limit_rps = v;
                        }
                    }
                    "passphrase_env_var" => passphrase_env_var = value.to_string(),
                    _ => {}
                }
            }
        }

        Ok(RemoteSignerConfig {
            listen_addr: listen_addr.ok_or(ConfigError::MissingField("listen_addr"))?,
            validator_id: validator_id.ok_or(ConfigError::MissingField("validator_id"))?,
            backend_mode: backend_mode.ok_or(ConfigError::MissingField("backend_mode"))?,
            keystore_path,
            keystore_entry_id,
            hsm_config_path,
            rate_limit_rps,
            passphrase_env_var,
        })
    }

    /// Load configuration from a file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, ConfigError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| ConfigError::FileError(format!("failed to read config: {}", e)))?;
        Self::from_toml(&content)
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ConfigError> {
        match self.backend_mode.as_str() {
            "encrypted-fs" => {
                if self.keystore_path.is_none() {
                    return Err(ConfigError::InvalidConfig("keystore_path required".into()));
                }
                if self.keystore_entry_id.is_none() {
                    return Err(ConfigError::InvalidConfig(
                        "keystore_entry_id required".into(),
                    ));
                }
            }
            "hsm-pkcs11" => {
                if self.hsm_config_path.is_none() {
                    return Err(ConfigError::InvalidConfig(
                        "hsm_config_path required".into(),
                    ));
                }
            }
            other => {
                return Err(ConfigError::InvalidConfig(format!(
                    "unknown backend: {}",
                    other
                )));
            }
        }
        Ok(())
    }
}

/// Configuration errors.
#[derive(Debug)]
pub enum ConfigError {
    MissingField(&'static str),
    InvalidConfig(String),
    FileError(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::MissingField(field) => write!(f, "missing field: {}", field),
            ConfigError::InvalidConfig(msg) => write!(f, "invalid config: {}", msg),
            ConfigError::FileError(msg) => write!(f, "file error: {}", msg),
        }
    }
}

impl std::error::Error for ConfigError {}

// ============================================================================
// Rate Limiter
// ============================================================================

struct RateLimiter {
    max_rps: u32,
    window_start: Instant,
    request_count: u32,
}

impl RateLimiter {
    fn new(max_rps: u32) -> Self {
        RateLimiter {
            max_rps,
            window_start: Instant::now(),
            request_count: 0,
        }
    }

    fn check(&mut self) -> bool {
        let now = Instant::now();
        if now.duration_since(self.window_start) >= Duration::from_secs(1) {
            self.window_start = now;
            self.request_count = 0;
        }
        if self.request_count >= self.max_rps {
            return false;
        }
        self.request_count += 1;
        true
    }
}

// ============================================================================
// Metrics
// ============================================================================

#[derive(Debug, Default)]
pub struct DaemonMetrics {
    connections_total: AtomicU64,
    requests_total: AtomicU64,
    signatures_total: AtomicU64,
    rejected_total: AtomicU64,
    rate_limited_total: AtomicU64,
}

impl DaemonMetrics {
    fn new() -> Self {
        Self::default()
    }
    fn inc_connections(&self) {
        self.connections_total.fetch_add(1, Ordering::Relaxed);
    }
    #[allow(dead_code)]
    fn inc_requests(&self) {
        self.requests_total.fetch_add(1, Ordering::Relaxed);
    }
    #[allow(dead_code)]
    fn inc_signatures(&self) {
        self.signatures_total.fetch_add(1, Ordering::Relaxed);
    }
    #[allow(dead_code)]
    fn inc_rejected(&self) {
        self.rejected_total.fetch_add(1, Ordering::Relaxed);
    }
    #[allow(dead_code)]
    fn inc_rate_limited(&self) {
        self.rate_limited_total.fetch_add(1, Ordering::Relaxed);
    }
    fn connections_total(&self) -> u64 {
        self.connections_total.load(Ordering::Relaxed)
    }
    fn requests_total(&self) -> u64 {
        self.requests_total.load(Ordering::Relaxed)
    }
    fn signatures_total(&self) -> u64 {
        self.signatures_total.load(Ordering::Relaxed)
    }
    fn rejected_total(&self) -> u64 {
        self.rejected_total.load(Ordering::Relaxed)
    }
    fn rate_limited_total(&self) -> u64 {
        self.rate_limited_total.load(Ordering::Relaxed)
    }
    fn format(&self) -> String {
        format!(
            "conn={} req={} sig={} rej={} rl={}",
            self.connections_total(),
            self.requests_total(),
            self.signatures_total(),
            self.rejected_total(),
            self.rate_limited_total()
        )
    }
}

// ============================================================================
// Protocol
// ============================================================================

fn decode_request(data: &[u8]) -> Result<RemoteSignRequest, RemoteSignError> {
    if data.len() < 24 {
        return Err(RemoteSignError::TransportError);
    }
    let validator_id = u64::from_le_bytes([
        data[0], data[1], data[2], data[3], data[4], data[5], data[6], data[7],
    ]);
    let suite_id = u16::from_le_bytes([data[8], data[9]]);
    let kind = match data[10] {
        0 => RemoteSignRequestKind::Proposal,
        1 => RemoteSignRequestKind::Vote,
        2 => RemoteSignRequestKind::Timeout,
        _ => return Err(RemoteSignError::TransportError),
    };
    let view = if data[11] != 0 {
        Some(u64::from_le_bytes([
            data[12], data[13], data[14], data[15], data[16], data[17], data[18], data[19],
        ]))
    } else {
        None
    };
    let preimage_len = u32::from_le_bytes([data[20], data[21], data[22], data[23]]) as usize;
    if data.len() < 24 + preimage_len {
        return Err(RemoteSignError::TransportError);
    }
    Ok(RemoteSignRequest {
        validator_id: ValidatorId::new(validator_id),
        suite_id,
        kind,
        view,
        preimage: data[24..24 + preimage_len].to_vec(),
    })
}

fn encode_response(response: &RemoteSignResponse) -> Vec<u8> {
    if let Some(ref sig) = response.signature {
        let mut buf = Vec::with_capacity(5 + sig.len());
        buf.push(0u8);
        buf.extend_from_slice(&(sig.len() as u32).to_le_bytes());
        buf.extend_from_slice(sig);
        buf
    } else if let Some(ref err) = response.error {
        let code = match err {
            RemoteSignError::InvalidKey => 1u8,
            RemoteSignError::CryptoError => 2,
            RemoteSignError::Unauthorized => 3,
            RemoteSignError::TransportError => 4,
            RemoteSignError::Timeout => 5,
            RemoteSignError::RateLimited => 6,
            RemoteSignError::ServerError => 7,
        };
        vec![1u8, code]
    } else {
        vec![1u8, 7u8]
    }
}

// ============================================================================
// Backend
// ============================================================================

fn create_backend_signer(config: &RemoteSignerConfig) -> Result<Arc<dyn ValidatorSigner>, String> {
    let validator_id = ValidatorId::new(config.validator_id);
    match config.backend_mode.as_str() {
        "encrypted-fs" => {
            let keystore_path = config
                .keystore_path
                .as_ref()
                .ok_or("keystore_path required")?;
            let entry_id = config
                .keystore_entry_id
                .as_ref()
                .ok_or("keystore_entry_id required")?;
            use qbind_node::keystore::{
                EncryptedFsValidatorKeystore, EncryptedKeystoreConfig, LocalKeystoreEntryId,
                ValidatorKeystore,
            };
            let enc_config = EncryptedKeystoreConfig {
                passphrase_env_var: config.passphrase_env_var.clone(),
                kdf_iterations: 100_000,
            };
            let keystore = EncryptedFsValidatorKeystore::new(keystore_path.clone(), enc_config);
            let signing_key = keystore
                .load_signing_key(&LocalKeystoreEntryId(entry_id.clone()))
                .map_err(|e| format!("load key failed: {}", e))?;
            let signer = qbind_node::validator_signer::LocalKeySigner::new(
                validator_id,
                100,
                Arc::new(signing_key),
            );
            Ok(Arc::new(signer))
        }
        "hsm-pkcs11" => {
            #[cfg(feature = "hsm-pkcs11")]
            {
                let hsm_config_path = config
                    .hsm_config_path
                    .as_ref()
                    .ok_or("hsm_config_path required")?;
                use qbind_node::hsm_pkcs11::{HsmMetrics, HsmPkcs11Config, HsmPkcs11Signer};
                let hsm_config = HsmPkcs11Config::from_file(hsm_config_path)
                    .map_err(|e| format!("HSM config: {}", e))?;
                let metrics = Arc::new(HsmMetrics::new());
                let signer = HsmPkcs11Signer::new(validator_id, 100, hsm_config, metrics)
                    .map_err(|e| format!("HSM signer: {}", e))?;
                Ok(Arc::new(signer))
            }
            #[cfg(not(feature = "hsm-pkcs11"))]
            Err("hsm-pkcs11 feature not enabled".to_string())
        }
        other => Err(format!("unknown backend: {}", other)),
    }
}

// ============================================================================
// Connection Handler
// ============================================================================

#[allow(dead_code)]
fn handle_connection(
    mut channel: qbind_node::secure_channel::SecureChannel,
    signer: Arc<dyn ValidatorSigner>,
    config: &RemoteSignerConfig,
    metrics: Arc<DaemonMetrics>,
) {
    metrics.inc_connections();
    let mut rate_limiter = RateLimiter::new(config.rate_limit_rps);
    let _ = channel
        .stream()
        .set_read_timeout(Some(Duration::from_secs(30)));
    let _ = channel
        .stream()
        .set_write_timeout(Some(Duration::from_secs(10)));

    loop {
        let request_data = match channel.recv_app() {
            Ok(data) => data,
            Err(qbind_node::secure_channel::ChannelError::Io(ref e))
                if e.kind() == std::io::ErrorKind::TimedOut
                    || e.kind() == std::io::ErrorKind::WouldBlock =>
            {
                continue
            }
            Err(qbind_node::secure_channel::ChannelError::Io(ref e))
                if e.kind() == std::io::ErrorKind::UnexpectedEof
                    || e.kind() == std::io::ErrorKind::ConnectionReset =>
            {
                break
            }
            Err(_) => break,
        };

        metrics.inc_requests();

        if !rate_limiter.check() {
            metrics.inc_rate_limited();
            let resp = RemoteSignResponse {
                signature: None,
                error: Some(RemoteSignError::RateLimited),
            };
            if channel.send_app(&encode_response(&resp)).is_err() {
                break;
            }
            continue;
        }

        let request = match decode_request(&request_data) {
            Ok(r) => r,
            Err(_) => {
                metrics.inc_rejected();
                let resp = RemoteSignResponse {
                    signature: None,
                    error: Some(RemoteSignError::TransportError),
                };
                if channel.send_app(&encode_response(&resp)).is_err() {
                    break;
                }
                continue;
            }
        };

        let response = validate_and_sign(&request, signer.as_ref(), &metrics);
        if channel.send_app(&encode_response(&response)).is_err() {
            break;
        }
    }
}

#[allow(dead_code)]
fn validate_and_sign(
    request: &RemoteSignRequest,
    signer: &dyn ValidatorSigner,
    metrics: &DaemonMetrics,
) -> RemoteSignResponse {
    if request.validator_id != *signer.validator_id() {
        metrics.inc_rejected();
        return RemoteSignResponse {
            signature: None,
            error: Some(RemoteSignError::Unauthorized),
        };
    }
    if request.suite_id != 100 {
        metrics.inc_rejected();
        return RemoteSignResponse {
            signature: None,
            error: Some(RemoteSignError::Unauthorized),
        };
    }
    if request.preimage.len() > MAX_PREIMAGE_SIZE {
        metrics.inc_rejected();
        return RemoteSignResponse {
            signature: None,
            error: Some(RemoteSignError::TransportError),
        };
    }

    let result = match request.kind {
        RemoteSignRequestKind::Proposal => signer.sign_proposal(&request.preimage),
        RemoteSignRequestKind::Vote | RemoteSignRequestKind::Timeout => {
            signer.sign_vote(&request.preimage)
        }
    };

    match result {
        Ok(signature) => {
            metrics.inc_signatures();
            RemoteSignResponse {
                signature: Some(signature),
                error: None,
            }
        }
        Err(e) => {
            metrics.inc_rejected();
            let error = match e {
                qbind_node::validator_signer::SignError::InvalidKey => RemoteSignError::InvalidKey,
                qbind_node::validator_signer::SignError::CryptoError => {
                    RemoteSignError::CryptoError
                }
                qbind_node::validator_signer::SignError::HsmError(_) => {
                    RemoteSignError::ServerError
                }
            };
            RemoteSignResponse {
                signature: None,
                error: Some(error),
            }
        }
    }
}

// ============================================================================
// CLI
// ============================================================================

#[derive(Parser, Debug)]
#[command(
    name = "qbind-remote-signer",
    about = "Remote signer daemon for QBIND validator nodes (T212)"
)]
struct CliArgs {
    #[arg(short, long, default_value = "/etc/qbind/remote_signer.toml")]
    config: PathBuf,
    #[arg(long)]
    listen_addr: Option<String>,
}

// ============================================================================
// Main
// ============================================================================

fn main() {
    let args = CliArgs::parse();
    eprintln!("[INFO] qbind-remote-signer starting...");
    eprintln!("[INFO] Config: {}", args.config.display());

    let mut config = match RemoteSignerConfig::from_file(&args.config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[ERROR] Config: {}", e);
            std::process::exit(1);
        }
    };
    if let Some(addr) = args.listen_addr {
        config.listen_addr = addr;
    }
    if let Err(e) = config.validate() {
        eprintln!("[ERROR] {}", e);
        std::process::exit(1);
    }

    eprintln!("[INFO] Validator ID: {}", config.validator_id);
    eprintln!("[INFO] Backend: {}", config.backend_mode);
    eprintln!("[INFO] Listen: {}", config.listen_addr);

    let signer = match create_backend_signer(&config) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[ERROR] Signer: {}", e);
            std::process::exit(1);
        }
    };
    eprintln!("[INFO] Backend signer initialized");

    let metrics = Arc::new(DaemonMetrics::new());
    let listener = match TcpListener::bind(&config.listen_addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[ERROR] Bind: {}", e);
            std::process::exit(1);
        }
    };

    eprintln!("[INFO] Listening on {}", config.listen_addr);
    eprintln!("[INFO] Note: Full KEMTLS server requires proper key configuration.");
    eprintln!("[INFO]       See docs/keys/QBIND_KEY_MANAGEMENT_DESIGN.md for details.");

    for stream in listener.incoming() {
        match stream {
            Ok(_tcp_stream) => {
                // Note: Full implementation would spawn a thread with handle_connection()
                // after performing KEMTLS handshake. This placeholder demonstrates the
                // architecture; production use requires KEMTLS server key setup.
                let _signer = Arc::clone(&signer);
                let _config = config.clone();
                let m = Arc::clone(&metrics);
                m.inc_connections();
                eprintln!("[DEBUG] Connection received (KEMTLS handshake not yet implemented)");
            }
            Err(e) => eprintln!("[WARN] Accept: {}", e),
        }
        let conn_count = metrics.connections_total();
        if conn_count > 0 && conn_count.is_multiple_of(100) {
            eprintln!("[INFO] Metrics: {}", metrics.format());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_parse() {
        let toml = r#"
listen_addr = "0.0.0.0:9443"
validator_id = 42
backend_mode = "encrypted-fs"
keystore_path = "/etc/qbind/keystore"
keystore_entry_id = "validator42"
"#;
        let config = RemoteSignerConfig::from_toml(toml).expect("parse");
        assert_eq!(config.listen_addr, "0.0.0.0:9443");
        assert_eq!(config.validator_id, 42);
    }

    #[test]
    fn test_rate_limiter() {
        let mut rl = RateLimiter::new(2);
        assert!(rl.check());
        assert!(rl.check());
        assert!(!rl.check());
    }

    #[test]
    fn test_decode_request() {
        let mut data = Vec::new();
        data.extend_from_slice(&42u64.to_le_bytes());
        data.extend_from_slice(&100u16.to_le_bytes());
        data.push(0);
        data.push(0);
        data.extend_from_slice(&0u64.to_le_bytes());
        data.extend_from_slice(&4u32.to_le_bytes());
        data.extend_from_slice(&[1, 2, 3, 4]);
        let req = decode_request(&data).unwrap();
        assert_eq!(req.validator_id, ValidatorId::new(42));
        assert_eq!(req.preimage, vec![1, 2, 3, 4]);
    }

    #[test]
    fn test_encode_response_success() {
        let resp = RemoteSignResponse {
            signature: Some(vec![1, 2, 3]),
            error: None,
        };
        let enc = encode_response(&resp);
        assert_eq!(enc[0], 0);
    }

    #[test]
    fn test_metrics() {
        let m = DaemonMetrics::new();
        m.inc_connections();
        assert_eq!(m.connections_total(), 1);
    }
}