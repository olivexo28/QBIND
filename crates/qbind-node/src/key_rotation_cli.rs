//! T213: Key Rotation CLI Helper.
//!
//! This module provides CLI helpers for initiating key rotation events.
//! The generated event descriptor can be used by governance/ops to submit
//! the rotation, without pushing anything on-chain directly.
//!
//! # Usage
//!
//! Generate a scheduled rotation event:
//! ```bash
//! qbind-key-rotation init \
//!     --validator-id 42 \
//!     --key-role consensus \
//!     --new-public-key-file /path/to/new_pk.bin \
//!     --effective-epoch 100 \
//!     --grace-epochs 2 \
//!     --output /path/to/rotation_event.json
//! ```
//!
//! Generate an emergency rotation event:
//! ```bash
//! qbind-key-rotation init \
//!     --validator-id 42 \
//!     --key-role consensus \
//!     --new-public-key-file /path/to/new_pk.bin \
//!     --effective-epoch 100 \
//!     --grace-epochs 1 \
//!     --emergency \
//!     --output /path/to/rotation_event.json
//! ```

use std::fs;
use std::path::PathBuf;

use qbind_consensus::key_rotation::{KeyRole, KeyRotationEvent, KeyRotationKind};

// ============================================================================
// Key Rotation Init Command
// ============================================================================

/// Arguments for the key-rotation-init command.
#[derive(Debug, Clone)]
pub struct KeyRotationInitArgs {
    /// Validator ID (u64).
    pub validator_id: u64,
    /// Key role: "consensus", "batch-signing", or "p2p-identity".
    pub key_role: KeyRole,
    /// New public key bytes (loaded from file or provided directly).
    pub new_public_key: Vec<u8>,
    /// Effective epoch when grace period starts.
    pub effective_epoch: u64,
    /// Number of epochs for the grace period.
    pub grace_epochs: u64,
    /// If true, this is an emergency rotation.
    pub emergency: bool,
    /// Output file path for the JSON descriptor.
    pub output_path: Option<PathBuf>,
}

/// Result of a key rotation init operation.
#[derive(Debug, Clone)]
pub struct KeyRotationInitResult {
    /// The generated event.
    pub event: KeyRotationEvent,
    /// JSON representation of the event.
    pub json: String,
}

/// Errors that can occur during key rotation init.
#[derive(Debug)]
pub enum KeyRotationInitError {
    /// Failed to read the public key file.
    PublicKeyReadError(std::io::Error),
    /// Public key is empty.
    EmptyPublicKey,
    /// Failed to serialize the event to JSON.
    JsonSerializeError(serde_json::Error),
    /// Failed to write the output file.
    OutputWriteError(std::io::Error),
    /// Invalid key role string.
    InvalidKeyRole(String),
}

impl std::fmt::Display for KeyRotationInitError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyRotationInitError::PublicKeyReadError(e) => {
                write!(f, "failed to read public key file: {}", e)
            }
            KeyRotationInitError::EmptyPublicKey => {
                write!(f, "public key is empty")
            }
            KeyRotationInitError::JsonSerializeError(e) => {
                write!(f, "failed to serialize event to JSON: {}", e)
            }
            KeyRotationInitError::OutputWriteError(e) => {
                write!(f, "failed to write output file: {}", e)
            }
            KeyRotationInitError::InvalidKeyRole(s) => {
                write!(
                    f,
                    "invalid key role '{}': expected 'consensus', 'batch-signing', or 'p2p-identity'",
                    s
                )
            }
        }
    }
}

impl std::error::Error for KeyRotationInitError {}

/// Parse a key role from a string.
pub fn parse_key_role(s: &str) -> Result<KeyRole, KeyRotationInitError> {
    match s.to_lowercase().as_str() {
        "consensus" => Ok(KeyRole::Consensus),
        "batch-signing" | "batchsigning" | "batch_signing" => Ok(KeyRole::BatchSigning),
        "p2p-identity" | "p2pidentity" | "p2p_identity" | "p2p" => Ok(KeyRole::P2pIdentity),
        _ => Err(KeyRotationInitError::InvalidKeyRole(s.to_string())),
    }
}

/// Initialize a key rotation event and return the JSON descriptor.
///
/// This function:
/// 1. Validates the inputs (public key must not be empty)
/// 2. Creates a `KeyRotationEvent` struct
/// 3. Serializes it to JSON
/// 4. Optionally writes to an output file (if `output_path` is `Some`)
///
/// # Arguments
///
/// * `args` - The rotation init arguments
///
/// # Output Behavior
///
/// If `args.output_path` is `Some`, the JSON is written to that file path and
/// a log message is printed to stderr. If `None`, the JSON is only returned
/// in the result struct without file I/O.
///
/// # Returns
///
/// * `Ok(KeyRotationInitResult)` with the event and JSON on success
/// * `Err(KeyRotationInitError)` on failure
///
/// # Example
///
/// ```ignore
/// use qbind_node::key_rotation_cli::{init_key_rotation, KeyRotationInitArgs, parse_key_role};
///
/// let args = KeyRotationInitArgs {
///     validator_id: 42,
///     key_role: parse_key_role("consensus").unwrap(),
///     new_public_key: vec![1, 2, 3, 4, 5],
///     effective_epoch: 100,
///     grace_epochs: 2,
///     emergency: false,
///     output_path: None,
/// };
///
/// let result = init_key_rotation(&args).unwrap();
/// println!("Generated rotation event:\n{}", result.json);
/// // The JSON can then be submitted via governance/ops tooling
/// ```
pub fn init_key_rotation(
    args: &KeyRotationInitArgs,
) -> Result<KeyRotationInitResult, KeyRotationInitError> {
    // Validate public key
    if args.new_public_key.is_empty() {
        return Err(KeyRotationInitError::EmptyPublicKey);
    }

    // Create the event
    let event = if args.emergency {
        KeyRotationEvent::emergency(
            args.validator_id,
            args.key_role,
            args.new_public_key.clone(),
            args.effective_epoch,
            args.grace_epochs,
        )
    } else {
        KeyRotationEvent::scheduled(
            args.validator_id,
            args.key_role,
            args.new_public_key.clone(),
            args.effective_epoch,
            args.grace_epochs,
        )
    };

    // Serialize to JSON
    let json =
        serde_json::to_string_pretty(&event).map_err(KeyRotationInitError::JsonSerializeError)?;

    // Optionally write to file
    if let Some(ref output_path) = args.output_path {
        fs::write(output_path, &json).map_err(KeyRotationInitError::OutputWriteError)?;
        eprintln!(
            "[T213] Key rotation event written to: {}",
            output_path.display()
        );
    }

    Ok(KeyRotationInitResult { event, json })
}

/// Read a public key from a file.
///
/// Reads the raw bytes from the specified file path.
pub fn read_public_key_file(path: &PathBuf) -> Result<Vec<u8>, KeyRotationInitError> {
    fs::read(path).map_err(KeyRotationInitError::PublicKeyReadError)
}

/// Compute a short fingerprint for logging purposes.
///
/// Returns a hex string of the first 4 bytes followed by "..." for keys longer
/// than 4 bytes. For shorter keys, returns the full hex encoding.
///
/// # Example
///
/// ```ignore
/// let key = vec![0xAB, 0xCD, 0xEF, 0x12, 0x34];
/// assert_eq!(key_fingerprint(&key), "abcdef12...");
/// ```
pub fn key_fingerprint(key: &[u8]) -> String {
    if key.len() < 4 {
        return hex::encode(key);
    }
    format!("{}...", hex::encode(&key[..4]))
}

// ============================================================================
// Logging Helpers (T213)
// ============================================================================

/// Log a key rotation event being applied.
pub fn log_rotation_event_applied(event: &KeyRotationEvent, current_epoch: u64) {
    let kind_str = match event.kind {
        KeyRotationKind::Scheduled => "SCHEDULED",
        KeyRotationKind::Emergency => "EMERGENCY",
    };

    eprintln!(
        "[T213] {} key rotation initiated for validator {} (role: {})",
        kind_str, event.validator_id, event.key_role
    );
    eprintln!(
        "[T213]   New key fingerprint: {}",
        key_fingerprint(&event.new_public_key)
    );
    eprintln!(
        "[T213]   Grace period: epochs {} to {} ({} epochs)",
        event.effective_epoch,
        event.grace_end_epoch(),
        event.grace_epochs
    );
    eprintln!("[T213]   Current epoch: {}", current_epoch);
}

/// Log a rotation being committed.
pub fn log_rotation_committed(validator_id: u64, key_role: KeyRole, epoch: u64) {
    eprintln!(
        "[T213] Key rotation COMMITTED for validator {} (role: {}) at epoch {}",
        validator_id, key_role, epoch
    );
}

/// Log dual-key validation.
pub fn log_dual_key_validation(
    validator_id: u64,
    key_role: KeyRole,
    is_current: bool,
    is_pending: bool,
    epoch: u64,
) {
    if is_pending && !is_current {
        eprintln!(
            "[T213] Signature validated using PENDING key for validator {} (role: {}) at epoch {}",
            validator_id, key_role, epoch
        );
    }
}

// ============================================================================
// Metrics Helpers (T213)
// ============================================================================

/// Metrics for key rotation tracking.
#[derive(Debug, Clone, Default)]
pub struct KeyRotationMetrics {
    /// Total scheduled rotations initiated.
    pub scheduled_rotations_initiated: u64,
    /// Total emergency rotations initiated.
    pub emergency_rotations_initiated: u64,
    /// Total rotations committed.
    pub rotations_committed: u64,
    /// Current number of pending rotations.
    pub pending_rotations: u64,
    /// Total dual-key validations (signatures verified against pending key).
    pub dual_key_validations: u64,
}

impl KeyRotationMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a rotation being initiated.
    pub fn record_rotation_initiated(&mut self, kind: KeyRotationKind) {
        match kind {
            KeyRotationKind::Scheduled => self.scheduled_rotations_initiated += 1,
            KeyRotationKind::Emergency => self.emergency_rotations_initiated += 1,
        }
        self.pending_rotations += 1;
    }

    /// Record a rotation being committed.
    pub fn record_rotation_committed(&mut self) {
        self.rotations_committed += 1;
        self.pending_rotations = self.pending_rotations.saturating_sub(1);
    }

    /// Record a dual-key validation.
    pub fn record_dual_key_validation(&mut self) {
        self.dual_key_validations += 1;
    }

    /// Get a summary string for logging.
    pub fn summary(&self) -> String {
        format!(
            "KeyRotationMetrics {{ scheduled={}, emergency={}, committed={}, pending={}, dual_key_validations={} }}",
            self.scheduled_rotations_initiated,
            self.emergency_rotations_initiated,
            self.rotations_committed,
            self.pending_rotations,
            self.dual_key_validations
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_key_role() {
        assert_eq!(parse_key_role("consensus").unwrap(), KeyRole::Consensus);
        assert_eq!(parse_key_role("CONSENSUS").unwrap(), KeyRole::Consensus);
        assert_eq!(
            parse_key_role("batch-signing").unwrap(),
            KeyRole::BatchSigning
        );
        assert_eq!(
            parse_key_role("batch_signing").unwrap(),
            KeyRole::BatchSigning
        );
        assert_eq!(
            parse_key_role("p2p-identity").unwrap(),
            KeyRole::P2pIdentity
        );
        assert_eq!(parse_key_role("p2p").unwrap(), KeyRole::P2pIdentity);

        assert!(parse_key_role("invalid").is_err());
    }

    #[test]
    fn test_key_fingerprint() {
        assert_eq!(
            key_fingerprint(&[0x01, 0x02, 0x03, 0x04, 0x05]),
            "01020304..."
        );
        assert_eq!(key_fingerprint(&[0xAB, 0xCD]), "abcd");
        assert_eq!(key_fingerprint(&[]), "");
    }

    #[test]
    fn test_init_key_rotation_scheduled() {
        let args = KeyRotationInitArgs {
            validator_id: 42,
            key_role: KeyRole::Consensus,
            new_public_key: vec![1, 2, 3, 4, 5],
            effective_epoch: 100,
            grace_epochs: 2,
            emergency: false,
            output_path: None,
        };

        let result = init_key_rotation(&args).unwrap();
        assert_eq!(result.event.validator_id, 42);
        assert_eq!(result.event.kind, KeyRotationKind::Scheduled);
        assert!(result.json.contains("\"validator_id\": 42"));
        assert!(result.json.contains("\"kind\": \"Scheduled\""));
    }

    #[test]
    fn test_init_key_rotation_emergency() {
        let args = KeyRotationInitArgs {
            validator_id: 1,
            key_role: KeyRole::BatchSigning,
            new_public_key: vec![10, 20, 30],
            effective_epoch: 50,
            grace_epochs: 1,
            emergency: true,
            output_path: None,
        };

        let result = init_key_rotation(&args).unwrap();
        assert_eq!(result.event.kind, KeyRotationKind::Emergency);
    }

    #[test]
    fn test_init_key_rotation_empty_key() {
        let args = KeyRotationInitArgs {
            validator_id: 42,
            key_role: KeyRole::Consensus,
            new_public_key: vec![],
            effective_epoch: 100,
            grace_epochs: 2,
            emergency: false,
            output_path: None,
        };

        let result = init_key_rotation(&args);
        assert!(matches!(result, Err(KeyRotationInitError::EmptyPublicKey)));
    }

    #[test]
    fn test_metrics() {
        let mut metrics = KeyRotationMetrics::new();

        metrics.record_rotation_initiated(KeyRotationKind::Scheduled);
        metrics.record_rotation_initiated(KeyRotationKind::Emergency);
        assert_eq!(metrics.scheduled_rotations_initiated, 1);
        assert_eq!(metrics.emergency_rotations_initiated, 1);
        assert_eq!(metrics.pending_rotations, 2);

        metrics.record_rotation_committed();
        assert_eq!(metrics.rotations_committed, 1);
        assert_eq!(metrics.pending_rotations, 1);

        metrics.record_dual_key_validation();
        assert_eq!(metrics.dual_key_validations, 1);
    }
}
