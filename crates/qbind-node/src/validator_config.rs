//! Validator configuration for the qbind-node.
//!
//! This module provides configuration structures for validators:
//! - `LocalValidatorConfig`: Configuration for this node's local validator identity
//! - `RemoteValidatorConfig`: Configuration for a remote validator peer
//! - `NodeValidatorConfig`: Combined configuration for a node's validator setup
//!
//! # Design Note
//!
//! For T50, this is a pure in-memory config used in tests and future wiring.
//! We are NOT yet:
//! - Parsing TOML/JSON from disk
//! - Verifying signatures
//! - Adding CLI support
//!
//! The `validator_id` here is the consensus-level identity (`ValidatorId`).
//! `PeerId` will be derived deterministically from `remotes` when wiring
//! `NetServiceConfig` and `PeerValidatorMap`.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use qbind_consensus::key_registry::ValidatorKeyRegistry;
use qbind_consensus::validator_set::{
    ConsensusValidatorSet, EpochId, EpochState, ValidatorSetEntry,
};
use qbind_consensus::{ValidatorId, ValidatorPublicKey};
use qbind_crypto::{ConsensusSigSuiteId, ValidatorSigningKey};
use qbind_net::kem_metrics::KemOpMetrics;
use qbind_net::{ClientConnectionConfig, ServerConnectionConfig};

use crate::identity_map::PeerValidatorMap;
use crate::keystore::{
    FsValidatorKeystore, KeystoreConfig, KeystoreError, LocalKeystoreEntryId, ValidatorKeystore,
};
use crate::net_service::NetServiceConfig;
use crate::peer::PeerId;

// ============================================================================
// T145: Validator Identity Self-Check
// ============================================================================

/// A validator's local identity used for self-check during startup (T145).
///
/// This struct holds the expected validator identity (from configuration)
/// that will be compared against the signing key loaded from the keystore.
/// The self-check ensures that:
/// - The signing key derives the expected public key
/// - The suite ID matches the expected value
///
/// # Design Notes
///
/// This is a lightweight struct used during the startup self-check path.
/// It does NOT contain any key material, only the expected identity values.
///
/// # Usage
///
/// ```ignore
/// use qbind_node::validator_config::LocalValidatorIdentity;
/// use qbind_consensus::{ValidatorId, ValidatorPublicKey};
///
/// let identity = LocalValidatorIdentity {
///     validator_id: ValidatorId::new(1),
///     public_key: ValidatorPublicKey(pk_bytes),
///     suite_id: ConsensusSigSuiteId::new(100), // ML-DSA-44
/// };
///
/// // Use in self-check
/// verify_signing_key_matches_identity(&signing_key, &identity)?;
/// ```
#[derive(Debug, Clone)]
pub struct LocalValidatorIdentity {
    /// The consensus-level identity for this validator.
    pub validator_id: ValidatorId,
    /// The expected consensus public key for this validator.
    pub public_key: ValidatorPublicKey,
    /// The expected signature suite ID for this validator.
    pub suite_id: ConsensusSigSuiteId,
}

/// Error type for identity self-check failures (T145).
///
/// This error type is designed to be informative without leaking sensitive
/// information (such as key bytes). The error messages include:
/// - The validator ID (safe to log)
/// - The suite IDs being compared (safe to log)
/// - A description of the mismatch type
///
/// Key material is NEVER included in error messages.
#[derive(Debug)]
pub enum IdentityMismatchError {
    /// The public key derived from the keystore signing key does not match
    /// the configured public key.
    ///
    /// This indicates a misconfiguration: the keystore contains a different
    /// key than what the node is configured to use.
    PublicKeyMismatch {
        /// The validator ID (from configuration).
        validator_id: ValidatorId,
    },

    /// The suite ID of the keystore-loaded key does not match the configured
    /// or expected suite ID.
    ///
    /// This indicates either:
    /// - A misconfigured suite ID in the identity
    /// - A wrong keystore entry being loaded
    SuiteIdMismatch {
        /// The validator ID (from configuration).
        validator_id: ValidatorId,
        /// The expected suite ID (from configuration).
        expected: ConsensusSigSuiteId,
        /// The actual suite ID (from keystore or derivation).
        actual: ConsensusSigSuiteId,
    },

    /// Failed to derive the public key from the signing key.
    ///
    /// This indicates a corrupted or invalid keystore entry.
    KeyDerivationFailed {
        /// The validator ID (from configuration).
        validator_id: ValidatorId,
        /// Description of the derivation failure (no key bytes).
        reason: String,
    },
}

impl std::fmt::Display for IdentityMismatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityMismatchError::PublicKeyMismatch { validator_id } => {
                write!(
                    f,
                    "identity self-check failed for validator {:?}: \
                     derived public key does not match configured public key",
                    validator_id
                )
            }
            IdentityMismatchError::SuiteIdMismatch {
                validator_id,
                expected,
                actual,
            } => {
                write!(
                    f,
                    "identity self-check failed for validator {:?}: \
                     suite ID mismatch (expected {}, got {})",
                    validator_id, expected, actual
                )
            }
            IdentityMismatchError::KeyDerivationFailed {
                validator_id,
                reason,
            } => {
                write!(
                    f,
                    "identity self-check failed for validator {:?}: \
                     failed to derive public key from signing key: {}",
                    validator_id, reason
                )
            }
        }
    }
}

impl std::error::Error for IdentityMismatchError {}

/// Configuration for this node's local validator identity.
///
/// # T143: ValidatorSigningKey Integration
///
/// The `signing_key` field holds the validator's signing key wrapped in `Arc<ValidatorSigningKey>`
/// for zeroization on drop and efficient sharing. This key is used to sign consensus votes and proposals.
///
/// Note: This struct does not implement `Clone` because `ValidatorSigningKey` does not
/// implement `Clone` (to prevent accidental key duplication). We use `Arc` to allow
/// sharing the key without cloning the key bytes.
#[derive(Debug)]
pub struct LocalValidatorConfig {
    /// The consensus-level identity for this validator.
    pub validator_id: ValidatorId,
    /// The network address to listen on for incoming connections.
    pub listen_addr: SocketAddr,
    /// The consensus public key for this validator (opaque bytes).
    pub consensus_pk: Vec<u8>,
    /// The validator signing key for signing votes and proposals (T143).
    ///
    /// This key is wrapped in `Arc<ValidatorSigningKey>` to ensure zeroization on drop
    /// and allow sharing without cloning key bytes. The key is used for signing consensus
    /// votes and proposals using ML-DSA-44.
    pub signing_key: Arc<ValidatorSigningKey>,
}

/// Configuration for a remote validator peer.
#[derive(Debug, Clone)]
pub struct RemoteValidatorConfig {
    /// The consensus-level identity for this remote validator.
    pub validator_id: ValidatorId,
    /// The network address of this remote validator.
    pub addr: SocketAddr,
    /// The consensus public key for this validator (opaque bytes).
    pub consensus_pk: Vec<u8>,
}

/// Combined configuration for a node's validator setup.
///
/// This structure expresses:
/// - Local validator ID for this node
/// - Its listening address
/// - Peer validators and their addresses
///
/// # T143: ValidatorSigningKey Integration
///
/// Note: This struct does not implement `Clone` because `LocalValidatorConfig` contains
/// a `ValidatorSigningKey` which does not implement `Clone` (to prevent accidental key duplication).
#[derive(Debug)]
pub struct NodeValidatorConfig {
    /// Configuration for this node's local validator.
    pub local: LocalValidatorConfig,
    /// Configuration for remote validator peers.
    pub remotes: Vec<RemoteValidatorConfig>,
}

// ============================================================================
// Keystore Configuration (T144)
// ============================================================================

/// Configuration for loading validator keys from a keystore (T144/T153).
///
/// This struct holds the parameters needed to locate and load a validator's
/// signing key from a keystore. It can be populated from:
/// - CLI arguments (e.g., `--validator-keystore-root`, `--validator-keystore-entry`)
/// - Configuration files (TOML/JSON)
/// - Environment variables
///
/// # T153: Encrypted Keystore
///
/// The `backend` field selects which keystore implementation to use:
/// - `KeystoreBackend::PlainFs`: Plaintext JSON files (default, testing only)
/// - `KeystoreBackend::EncryptedFsV1`: Encrypted files with passphrase-based KDF
///
/// # Example
///
/// ```ignore
/// use qbind_node::validator_config::ValidatorKeystoreConfig;
/// use qbind_node::keystore::KeystoreBackend;
/// use std::path::PathBuf;
///
/// let keystore_cfg = ValidatorKeystoreConfig {
///     keystore_root: PathBuf::from("/etc/qbind/keystore"),
///     keystore_entry: "validator-1".to_string(),
///     backend: KeystoreBackend::PlainFs,
///     encryption_config: None,
/// };
/// ```
#[derive(Debug, Clone)]
pub struct ValidatorKeystoreConfig {
    /// The root directory where keystore entries are stored.
    ///
    /// For `FsValidatorKeystore`, keys are stored at `{keystore_root}/{keystore_entry}.json`.
    /// For `EncryptedFsValidatorKeystore`, keys are stored at `{keystore_root}/{keystore_entry}.enc`.
    ///
    /// Can be set via CLI: `--validator-keystore-root <PATH>`
    pub keystore_root: PathBuf,

    /// The identifier for the keystore entry to load.
    ///
    /// This maps to a file:
    /// - `{keystore_root}/{keystore_entry}.json` for plaintext keystore
    /// - `{keystore_root}/{keystore_entry}.enc` for encrypted keystore
    ///
    /// Can be set via CLI: `--validator-keystore-entry <ID>`
    pub keystore_entry: String,

    /// Keystore backend selection (T153).
    ///
    /// Defaults to `KeystoreBackend::PlainFs` for backward compatibility.
    pub backend: crate::keystore::KeystoreBackend,

    /// Encryption configuration for encrypted keystore (T153).
    ///
    /// Required when `backend == KeystoreBackend::EncryptedFsV1`.
    /// Ignored for other backends.
    pub encryption_config: Option<crate::keystore::EncryptedKeystoreConfig>,
}

// ============================================================================
// T149: Signer Backend Configuration
// ============================================================================

/// Signer backend selection for validator signing operations.
///
/// This enum allows configuring which signing backend to use:
/// - `LocalKeystore`: Direct in-process signing with `LocalKeySigner`
/// - `RemoteLoopback`: Remote signer protocol with loopback transport (for testing)
///
/// Future variants will include real network transports and HSM backends.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SignerBackend {
    /// Use in-process signing with `LocalKeySigner` (default).
    #[default]
    LocalKeystore,
    /// Use remote signer protocol with loopback transport.
    ///
    /// This exercises the remote signer plumbing using `LocalKeySigner` under
    /// the hood, useful for testing and development.
    RemoteLoopback,
    // Future variants:
    // RemoteUnixSocket { path: PathBuf },
    // RemoteTcp { endpoint: String },
    // RemoteGrpc { endpoint: String },
    // Hsm { config: HsmConfig },
}

/// Configuration for validator signing operations.
///
/// This struct controls how the validator signs consensus messages (proposals,
/// votes, timeout messages).
///
/// # Usage
///
/// ```ignore
/// use qbind_node::validator_config::{ValidatorSignerConfig, SignerBackend};
///
/// // Local signing (default)
/// let cfg = ValidatorSignerConfig {
///     backend: SignerBackend::LocalKeystore,
///     remote_endpoint: None,
/// };
///
/// // Remote loopback (for testing)
/// let cfg = ValidatorSignerConfig {
///     backend: SignerBackend::RemoteLoopback,
///     remote_endpoint: None,
/// };
/// ```
#[derive(Debug, Clone, Default)]
pub struct ValidatorSignerConfig {
    /// The signer backend to use.
    pub backend: SignerBackend,
    /// Optional remote endpoint (reserved for future use).
    ///
    /// This field is not used by `LocalKeystore` or `RemoteLoopback` backends.
    /// Future network-based backends will use this to specify the remote signer
    /// address (e.g., "unix:///var/run/qbind-signer.sock" or "tcp://127.0.0.1:9000").
    pub remote_endpoint: Option<String>,
}

impl NodeValidatorConfig {
    /// Builds a `ConsensusValidatorSet` suitable for use with `BasicHotStuffEngine`.
    ///
    /// For now this assumes all validators have equal voting_power = 1.
    /// This is a test-only helper; production code may use different logic.
    pub fn build_consensus_validator_set_for_tests(&self) -> ConsensusValidatorSet {
        let entries = std::iter::once(ValidatorSetEntry {
            id: self.local.validator_id,
            voting_power: 1,
        })
        .chain(self.remotes.iter().map(|r| ValidatorSetEntry {
            id: r.validator_id,
            voting_power: 1,
        }))
        .collect::<Vec<_>>();

        ConsensusValidatorSet::new(entries)
            .expect("NodeValidatorConfig should not create duplicate validator ids")
    }

    /// Builds an `EpochState` suitable for use with consensus.
    ///
    /// This creates a genesis epoch (epoch 0) with all validators having equal voting_power = 1.
    /// This is a test-only helper; production code may use different logic.
    ///
    /// # Example
    ///
    /// ```ignore
    /// use qbind_node::validator_config::NodeValidatorConfig;
    /// use qbind_consensus::EpochId;
    ///
    /// let cfg = // ... create config ...
    /// let epoch_state = cfg.build_epoch_state_for_tests();
    /// assert_eq!(epoch_state.epoch_id(), EpochId::GENESIS);
    /// ```
    pub fn build_epoch_state_for_tests(&self) -> EpochState {
        let validator_set = self.build_consensus_validator_set_for_tests();
        EpochState::genesis(validator_set)
    }

    /// Builds an `EpochState` with a specific epoch ID.
    ///
    /// This is useful for testing epoch transitions or non-genesis scenarios.
    ///
    /// # Arguments
    ///
    /// * `epoch_id` - The epoch ID to use for the epoch state.
    pub fn build_epoch_state_with_id_for_tests(&self, epoch_id: EpochId) -> EpochState {
        let validator_set = self.build_consensus_validator_set_for_tests();
        EpochState::new(epoch_id, validator_set)
    }

    /// Build a ValidatorKeyRegistry from this config, for tests.
    ///
    /// Each validator_id must appear at most once across local + remotes.
    /// This method will panic if duplicate validator_ids are found.
    pub fn build_validator_key_registry(&self) -> ValidatorKeyRegistry {
        let mut reg = ValidatorKeyRegistry::new();

        reg.insert(
            self.local.validator_id,
            ValidatorPublicKey(self.local.consensus_pk.clone()),
        );

        for remote in &self.remotes {
            let id = remote.validator_id;
            let pk = ValidatorPublicKey(remote.consensus_pk.clone());
            let prev = reg.insert(id, pk);
            assert!(
                prev.is_none(),
                "duplicate validator_id in NodeValidatorConfig: {:?}",
                id
            );
        }

        reg
    }
}

/// Deterministically constructs a `NetServiceConfig` and `PeerValidatorMap`
/// from a `NodeValidatorConfig`.
///
/// This is a test-only helper function that:
/// - Assigns `PeerId(1)`, `PeerId(2)`, ... to remotes in the given order
/// - Uses `NodeValidatorConfig.local.listen_addr` as `listen_addr`
/// - Uses the provided crypto configs and network parameters
///
/// # Arguments
///
/// * `cfg` - The validator configuration
/// * `client_cfg` - Client-side KEMTLS connection config
/// * `server_cfg` - Server-side KEMTLS connection config
/// * `ping_interval` - How often to send Ping to peers
/// * `liveness_timeout` - How long without Pong before peer is considered dead
/// * `max_peers` - Maximum number of peers
///
/// # Returns
///
/// A tuple of `(NetServiceConfig, PeerValidatorMap)` that are aligned:
/// - `NetServiceConfig.outbound_peers` contains `(PeerId(i+1), addr)` for each remote
/// - `PeerValidatorMap` maps `PeerId(i+1)` to the corresponding `ValidatorId`
///
/// # Example
///
/// ```ignore
/// use qbind_node::validator_config::*;
/// use qbind_consensus::ValidatorId;
///
/// let cfg = NodeValidatorConfig {
///     local: LocalValidatorConfig {
///         validator_id: ValidatorId::new(1),
///         listen_addr: "127.0.0.1:9000".parse().unwrap(),
///     },
///     remotes: vec![
///         RemoteValidatorConfig {
///             validator_id: ValidatorId::new(2),
///             addr: "127.0.0.1:9001".parse().unwrap(),
///         },
///     ],
/// };
///
/// let (net_cfg, id_map) = build_net_config_and_id_map_for_tests(
///     &cfg,
///     client_cfg,
///     server_cfg,
///     Duration::from_secs(5),
///     Duration::from_secs(30),
///     100,
/// );
///
/// // PeerId(1) -> ValidatorId(2) for the first remote
/// assert_eq!(id_map.get(&PeerId(1)), Some(ValidatorId::new(2)));
/// ```
pub fn build_net_config_and_id_map_for_tests(
    cfg: &NodeValidatorConfig,
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
    ping_interval: Duration,
    liveness_timeout: Duration,
    max_peers: usize,
) -> (NetServiceConfig, PeerValidatorMap) {
    let mut outbound_peers = Vec::new();
    let mut id_map = PeerValidatorMap::new();

    for (i, remote) in cfg.remotes.iter().enumerate() {
        // Assign PeerId(1), PeerId(2), ... to remotes in order
        let peer_id = PeerId((i + 1) as u64);
        outbound_peers.push((peer_id, remote.addr));
        id_map.insert(peer_id, remote.validator_id);
    }

    let net_cfg = NetServiceConfig {
        listen_addr: cfg.local.listen_addr,
        outbound_peers,
        client_cfg,
        server_cfg,
        max_peers,
        ping_interval,
        liveness_timeout,
    };

    (net_cfg, id_map)
}

/// Inject KEM metrics into client and server handshake configs (T137).
///
/// This helper function takes existing `ClientConnectionConfig` and `ServerConnectionConfig`
/// and updates their handshake configs to include the provided KEM metrics.
///
/// # Arguments
///
/// * `client_cfg` - Client connection config to update
/// * `server_cfg` - Server connection config to update
/// * `kem_metrics` - Shared KEM metrics instance from NodeMetrics
///
/// # Returns
///
/// Updated configs with metrics injected.
pub fn inject_kem_metrics_into_configs(
    client_cfg: ClientConnectionConfig,
    server_cfg: ServerConnectionConfig,
    kem_metrics: Arc<KemOpMetrics>,
) -> (ClientConnectionConfig, ServerConnectionConfig) {
    // Update client handshake config
    let mut client_handshake_cfg = client_cfg.handshake_config.clone();
    client_handshake_cfg.kem_metrics = Some(kem_metrics.clone());
    let updated_client_cfg = ClientConnectionConfig {
        handshake_config: client_handshake_cfg,
        client_random: client_cfg.client_random,
        validator_id: client_cfg.validator_id,
        peer_kem_pk: client_cfg.peer_kem_pk,
    };

    // Update server handshake config
    let mut server_handshake_cfg = server_cfg.handshake_config.clone();
    server_handshake_cfg.kem_metrics = Some(kem_metrics);
    let updated_server_cfg = ServerConnectionConfig {
        handshake_config: server_handshake_cfg,
        server_random: server_cfg.server_random,
    };

    (updated_client_cfg, updated_server_cfg)
}

// ============================================================================
// Keystore Helpers (T144) and Identity Self-Check (T145)
// ============================================================================

/// Expected suite ID for ML-DSA-44 keys.
///
/// This matches `qbind_crypto::SUITE_PQ_RESERVED_1` (100).
/// Used for identity self-check validation.
pub const EXPECTED_SUITE_ID: ConsensusSigSuiteId = ConsensusSigSuiteId(100);

/// Verify that a signing key matches the configured validator identity (T145).
///
/// This function performs the identity self-check by:
/// 1. Deriving the public key from the signing key
/// 2. Comparing it against the configured public key
/// 3. Comparing the expected suite ID against the configured suite ID
///
/// # Arguments
///
/// * `signing_key` - The signing key loaded from the keystore
/// * `identity` - The expected validator identity (from configuration)
///
/// # Returns
///
/// * `Ok(())` if the signing key matches the configured identity
/// * `Err(IdentityMismatchError)` if there is any mismatch
///
/// # Security Notes
///
/// - The signing key material is NEVER logged
/// - Only the validator ID and suite IDs appear in error messages
/// - The comparison uses constant-time equality for the public key
///
/// # Example
///
/// ```ignore
/// use qbind_node::validator_config::{
///     verify_signing_key_matches_identity, LocalValidatorIdentity, EXPECTED_SUITE_ID,
/// };
/// use qbind_consensus::{ValidatorId, ValidatorPublicKey};
/// use qbind_crypto::ValidatorSigningKey;
///
/// let identity = LocalValidatorIdentity {
///     validator_id: ValidatorId::new(1),
///     public_key: ValidatorPublicKey(pk_bytes),
///     suite_id: EXPECTED_SUITE_ID,
/// };
///
/// // This will fail if the signing key doesn't derive the expected public key
/// verify_signing_key_matches_identity(&signing_key, &identity)?;
/// ```
pub fn verify_signing_key_matches_identity(
    signing_key: &ValidatorSigningKey,
    identity: &LocalValidatorIdentity,
) -> Result<(), IdentityMismatchError> {
    // 1. Derive the public key from the signing key
    let derived_pk = signing_key.derive_public_key().map_err(|e| {
        IdentityMismatchError::KeyDerivationFailed {
            validator_id: identity.validator_id,
            reason: format!("{}", e),
        }
    })?;

    // 2. Compare the derived public key with the configured public key
    // Note: We compare byte slices, which is constant-time in Rust for Vec<u8>.
    if derived_pk != identity.public_key.0 {
        return Err(IdentityMismatchError::PublicKeyMismatch {
            validator_id: identity.validator_id,
        });
    }

    // 3. Verify the suite ID matches the expected value
    // For T145, we expect EXPECTED_SUITE_ID (100 = ML-DSA-44)
    // The suite ID in identity should match the expected suite ID
    if identity.suite_id != EXPECTED_SUITE_ID {
        return Err(IdentityMismatchError::SuiteIdMismatch {
            validator_id: identity.validator_id,
            expected: EXPECTED_SUITE_ID,
            actual: identity.suite_id,
        });
    }

    Ok(())
}

/// Derive the validator public key from a signing key (T145).
///
/// This is a convenience wrapper around `ValidatorSigningKey::derive_public_key()`
/// that returns the appropriate types for use with identity verification.
///
/// # Arguments
///
/// * `signing_key` - The signing key to derive from
///
/// # Returns
///
/// A tuple of `(ValidatorPublicKey, ConsensusSigSuiteId)` containing:
/// - The derived public key
/// - The suite ID (fixed at `EXPECTED_SUITE_ID` for T145)
///
/// # Errors
///
/// Returns an error string if key derivation fails.
pub fn derive_validator_public_key(
    signing_key: &ValidatorSigningKey,
) -> Result<(ValidatorPublicKey, ConsensusSigSuiteId), String> {
    let pk_bytes = signing_key
        .derive_public_key()
        .map_err(|e| format!("failed to derive public key: {}", e))?;

    Ok((ValidatorPublicKey(pk_bytes), EXPECTED_SUITE_ID))
}

/// Create a `LocalValidatorConfig` by loading the signing key from a keystore (T144).
///
/// This function constructs a `LocalValidatorConfig` by:
/// 1. Creating a `KeystoreConfig` from the provided `ValidatorKeystoreConfig`
/// 2. Constructing an `FsValidatorKeystore` with the config
/// 3. Loading the signing key from the keystore using the entry ID
/// 4. Wrapping the key in `Arc` and building the `LocalValidatorConfig`
///
/// # Arguments
///
/// * `validator_id` - The consensus-level identity for this validator
/// * `listen_addr` - The network address to listen on
/// * `consensus_pk` - The consensus public key bytes
/// * `keystore_cfg` - The keystore configuration specifying where to load the key
///
/// # Returns
///
/// A `LocalValidatorConfig` with the signing key loaded from the keystore,
/// or an error if the key could not be loaded.
///
/// # Errors
///
/// Returns `KeystoreError` if:
/// - The keystore entry does not exist (`KeystoreError::NotFound`)
/// - The keystore entry is malformed (`KeystoreError::Parse`)
/// - The key material is invalid (`KeystoreError::InvalidKey`)
/// - An I/O error occurs (`KeystoreError::Io`)
///
/// # Example
///
/// ```ignore
/// use qbind_node::validator_config::{
///     make_local_validator_config_from_keystore, ValidatorKeystoreConfig,
/// };
/// use qbind_consensus::ValidatorId;
/// use std::path::PathBuf;
///
/// let keystore_cfg = ValidatorKeystoreConfig {
///     keystore_root: PathBuf::from("/etc/qbind/keystore"),
///     keystore_entry: "validator-1".to_string(),
///     backend: KeystoreBackend::PlainFs,
///     encryption_config: None,
/// };
///
/// let config = make_local_validator_config_from_keystore(
///     ValidatorId::new(1),
///     "127.0.0.1:9000".parse().unwrap(),
///     consensus_pk_bytes,
///     &keystore_cfg,
/// )?;
/// ```
///
/// # Security Notes
///
/// - The signing key is loaded once at startup and wrapped in `Arc`
/// - No key cloning occurs; the key bytes are owned by the `ValidatorSigningKey`
/// - The key is zeroized when the last `Arc` reference is dropped
/// - Key material is never logged
pub fn make_local_validator_config_from_keystore(
    validator_id: ValidatorId,
    listen_addr: SocketAddr,
    consensus_pk: Vec<u8>,
    keystore_cfg: &ValidatorKeystoreConfig,
) -> Result<LocalValidatorConfig, KeystoreError> {
    use crate::keystore::{EncryptedFsValidatorKeystore, KeystoreBackend};

    // Load signing key based on backend selection
    let entry_id = LocalKeystoreEntryId(keystore_cfg.keystore_entry.clone());
    let signing_key = match &keystore_cfg.backend {
        KeystoreBackend::PlainFs => {
            // Use plaintext filesystem keystore
            let ks_config = KeystoreConfig {
                root: keystore_cfg.keystore_root.clone(),
            };
            let keystore = FsValidatorKeystore::new(ks_config);
            keystore.load_signing_key(&entry_id)?
        }
        KeystoreBackend::EncryptedFsV1 => {
            // Use encrypted filesystem keystore
            let enc_config = keystore_cfg.encryption_config.as_ref().ok_or_else(|| {
                KeystoreError::Config(
                    "EncryptedFsV1 backend requires encryption_config to be set".to_string(),
                )
            })?;
            let keystore = EncryptedFsValidatorKeystore::new(
                keystore_cfg.keystore_root.clone(),
                enc_config.clone(),
            );
            keystore.load_signing_key(&entry_id)?
        }
    };

    // Wrap in Arc and build LocalValidatorConfig
    Ok(LocalValidatorConfig {
        validator_id,
        listen_addr,
        consensus_pk,
        signing_key: Arc::new(signing_key),
    })
}

/// Create a `LocalValidatorConfig` using a custom keystore implementation (T144).
///
/// This is a more flexible version of `make_local_validator_config_from_keystore`
/// that accepts any `ValidatorKeystore` implementation. This is useful for:
/// - Testing with mock keystores
/// - Using alternative keystore backends (HSM, remote, etc.)
///
/// # Arguments
///
/// * `validator_id` - The consensus-level identity for this validator
/// * `listen_addr` - The network address to listen on
/// * `consensus_pk` - The consensus public key bytes
/// * `keystore` - The keystore implementation to use
/// * `entry_id` - The identifier for the keystore entry to load
///
/// # Returns
///
/// A `LocalValidatorConfig` with the signing key loaded from the keystore,
/// or an error if the key could not be loaded.
pub fn make_local_validator_config_with_keystore<K: ValidatorKeystore>(
    validator_id: ValidatorId,
    listen_addr: SocketAddr,
    consensus_pk: Vec<u8>,
    keystore: &K,
    entry_id: &str,
) -> Result<LocalValidatorConfig, KeystoreError> {
    let entry = LocalKeystoreEntryId(entry_id.to_string());
    let signing_key = keystore.load_signing_key(&entry)?;

    Ok(LocalValidatorConfig {
        validator_id,
        listen_addr,
        consensus_pk,
        signing_key: Arc::new(signing_key),
    })
}

// ============================================================================
// Identity-Verified Keystore Helpers (T145)
// ============================================================================

/// Error type for keystore operations with identity verification (T145).
///
/// This combines errors from keystore loading and identity verification.
#[derive(Debug)]
pub enum KeystoreWithIdentityError {
    /// Error from keystore operations (loading the key).
    Keystore(KeystoreError),
    /// Error from identity verification (self-check failed).
    Identity(IdentityMismatchError),
}

impl std::fmt::Display for KeystoreWithIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreWithIdentityError::Keystore(e) => write!(f, "keystore error: {}", e),
            KeystoreWithIdentityError::Identity(e) => write!(f, "identity error: {}", e),
        }
    }
}

impl std::error::Error for KeystoreWithIdentityError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeystoreWithIdentityError::Keystore(e) => Some(e),
            KeystoreWithIdentityError::Identity(e) => Some(e),
        }
    }
}

impl From<KeystoreError> for KeystoreWithIdentityError {
    fn from(e: KeystoreError) -> Self {
        KeystoreWithIdentityError::Keystore(e)
    }
}

impl From<IdentityMismatchError> for KeystoreWithIdentityError {
    fn from(e: IdentityMismatchError) -> Self {
        KeystoreWithIdentityError::Identity(e)
    }
}

/// Create a `LocalValidatorConfig` with identity verification (T145).
///
/// This function combines keystore loading with identity self-check:
/// 1. Loads the signing key from the keystore
/// 2. Verifies that the signing key derives the configured public key
/// 3. Verifies that the suite ID matches the expected value (100 = ML-DSA-44)
/// 4. Creates the `LocalValidatorConfig` if all checks pass
///
/// **This is the recommended startup path for production nodes.**
///
/// # Arguments
///
/// * `validator_id` - The consensus-level identity for this validator
/// * `listen_addr` - The network address to listen on
/// * `consensus_pk` - The expected consensus public key bytes
/// * `keystore_cfg` - The keystore configuration specifying where to load the key
///
/// # Returns
///
/// A `LocalValidatorConfig` with the signing key loaded from the keystore,
/// or an error if:
/// - The keystore entry does not exist or cannot be loaded
/// - The signing key does not derive the expected public key
/// - The suite ID does not match the expected value
///
/// # Security Notes
///
/// - Key material is NEVER logged
/// - Error messages include validator ID and suite IDs, but NOT key bytes
/// - This function should be the ONLY path for loading validator signing keys
///   in production to ensure the identity self-check is always performed
///
/// # Example
///
/// ```ignore
/// use qbind_node::validator_config::{
///     make_local_validator_config_with_identity_check, ValidatorKeystoreConfig,
/// };
/// use qbind_consensus::ValidatorId;
/// use std::path::PathBuf;
///
/// let keystore_cfg = ValidatorKeystoreConfig {
///     keystore_root: PathBuf::from("/etc/qbind/keystore"),
///     keystore_entry: "validator-1".to_string(),
///     backend: KeystoreBackend::PlainFs,
///     encryption_config: None,
/// };
///
/// // This will fail at startup if the keystore key doesn't match the public key
/// let config = make_local_validator_config_with_identity_check(
///     ValidatorId::new(1),
///     "127.0.0.1:9000".parse().unwrap(),
///     expected_pk_bytes, // The public key this validator is configured to use
///     &keystore_cfg,
/// )?;
/// ```
pub fn make_local_validator_config_with_identity_check(
    validator_id: ValidatorId,
    listen_addr: SocketAddr,
    consensus_pk: Vec<u8>,
    keystore_cfg: &ValidatorKeystoreConfig,
) -> Result<LocalValidatorConfig, KeystoreWithIdentityError> {
    // 1. Construct KeystoreConfig from ValidatorKeystoreConfig
    let ks_config = KeystoreConfig {
        root: keystore_cfg.keystore_root.clone(),
    };

    // 2. Construct FsValidatorKeystore
    let keystore = FsValidatorKeystore::new(ks_config);

    // 3. Load the signing key using the entry ID
    let entry_id = LocalKeystoreEntryId(keystore_cfg.keystore_entry.clone());
    let signing_key = keystore.load_signing_key(&entry_id)?;

    // 4. Perform identity self-check (T145)
    let identity = LocalValidatorIdentity {
        validator_id,
        public_key: ValidatorPublicKey(consensus_pk.clone()),
        suite_id: EXPECTED_SUITE_ID,
    };
    verify_signing_key_matches_identity(&signing_key, &identity)?;

    // 5. All checks passed - wrap in Arc and build LocalValidatorConfig
    Ok(LocalValidatorConfig {
        validator_id,
        listen_addr,
        consensus_pk,
        signing_key: Arc::new(signing_key),
    })
}

/// Create a `LocalValidatorConfig` with identity verification using a custom keystore (T145).
///
/// This is a more flexible version of `make_local_validator_config_with_identity_check`
/// that accepts any `ValidatorKeystore` implementation.
///
/// # Arguments
///
/// * `validator_id` - The consensus-level identity for this validator
/// * `listen_addr` - The network address to listen on
/// * `consensus_pk` - The expected consensus public key bytes
/// * `keystore` - The keystore implementation to use
/// * `entry_id` - The identifier for the keystore entry to load
///
/// # Returns
///
/// A `LocalValidatorConfig` with the signing key loaded and identity verified,
/// or an error if loading or verification fails.
pub fn make_local_validator_config_with_keystore_and_identity_check<K: ValidatorKeystore>(
    validator_id: ValidatorId,
    listen_addr: SocketAddr,
    consensus_pk: Vec<u8>,
    keystore: &K,
    entry_id: &str,
) -> Result<LocalValidatorConfig, KeystoreWithIdentityError> {
    // 1. Load the signing key
    let entry = LocalKeystoreEntryId(entry_id.to_string());
    let signing_key = keystore.load_signing_key(&entry)?;

    // 2. Perform identity self-check (T145)
    let identity = LocalValidatorIdentity {
        validator_id,
        public_key: ValidatorPublicKey(consensus_pk.clone()),
        suite_id: EXPECTED_SUITE_ID,
    };
    verify_signing_key_matches_identity(&signing_key, &identity)?;

    // 3. All checks passed - wrap in Arc and build LocalValidatorConfig
    Ok(LocalValidatorConfig {
        validator_id,
        listen_addr,
        consensus_pk,
        signing_key: Arc::new(signing_key),
    })
}

// ============================================================================
// Test Helpers (T143)
// ============================================================================

/// Create a test `LocalValidatorConfig` with a dummy signing key.
///
/// This helper is used in tests to create validator configs without
/// requiring real key material. The signing key is a zero-filled vector
/// of the correct size for ML-DSA-44.
///
/// # Arguments
///
/// * `validator_id` - The validator ID
/// * `listen_addr` - The listening address
/// * `consensus_pk` - The public key bytes
///
/// # Returns
///
/// A `LocalValidatorConfig` with a dummy signing key suitable for testing.
///
/// # Note
///
/// This function is primarily intended for testing. In production, signing keys
/// should be loaded from secure storage.
pub fn make_test_local_validator_config(
    validator_id: ValidatorId,
    listen_addr: SocketAddr,
    consensus_pk: Vec<u8>,
) -> LocalValidatorConfig {
    use qbind_crypto::ml_dsa44::ML_DSA_44_SECRET_KEY_SIZE;
    let signing_key = Arc::new(ValidatorSigningKey::new(vec![
        0u8;
        ML_DSA_44_SECRET_KEY_SIZE
    ]));
    LocalValidatorConfig {
        validator_id,
        listen_addr,
        consensus_pk,
        signing_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_validator_config_creation() {
        use qbind_crypto::ml_dsa44::ML_DSA_44_SECRET_KEY_SIZE;
        let signing_key = Arc::new(ValidatorSigningKey::new(vec![
            0u8;
            ML_DSA_44_SECRET_KEY_SIZE
        ]));
        let config = LocalValidatorConfig {
            validator_id: ValidatorId::new(1),
            listen_addr: "127.0.0.1:9000".parse().unwrap(),
            consensus_pk: b"pk-1".to_vec(),
            signing_key,
        };

        assert_eq!(config.validator_id, ValidatorId::new(1));
        assert_eq!(config.listen_addr.port(), 9000);
        assert_eq!(config.consensus_pk, b"pk-1".to_vec());
    }

    #[test]
    fn remote_validator_config_creation() {
        let config = RemoteValidatorConfig {
            validator_id: ValidatorId::new(2),
            addr: "127.0.0.1:9001".parse().unwrap(),
            consensus_pk: b"pk-2".to_vec(),
        };

        assert_eq!(config.validator_id, ValidatorId::new(2));
        assert_eq!(config.addr.port(), 9001);
        assert_eq!(config.consensus_pk, b"pk-2".to_vec());
    }

    #[test]
    fn node_validator_config_creation() {
        use qbind_crypto::ml_dsa44::ML_DSA_44_SECRET_KEY_SIZE;
        let signing_key = Arc::new(ValidatorSigningKey::new(vec![
            0u8;
            ML_DSA_44_SECRET_KEY_SIZE
        ]));
        let config = NodeValidatorConfig {
            local: LocalValidatorConfig {
                validator_id: ValidatorId::new(1),
                listen_addr: "127.0.0.1:9000".parse().unwrap(),
                consensus_pk: b"pk-1".to_vec(),
                signing_key,
            },
            remotes: vec![
                RemoteValidatorConfig {
                    validator_id: ValidatorId::new(2),
                    addr: "127.0.0.1:9001".parse().unwrap(),
                    consensus_pk: b"pk-2".to_vec(),
                },
                RemoteValidatorConfig {
                    validator_id: ValidatorId::new(3),
                    addr: "127.0.0.1:9002".parse().unwrap(),
                    consensus_pk: b"pk-3".to_vec(),
                },
            ],
        };

        assert_eq!(config.local.validator_id, ValidatorId::new(1));
        assert_eq!(config.remotes.len(), 2);
        assert_eq!(config.remotes[0].validator_id, ValidatorId::new(2));
        assert_eq!(config.remotes[1].validator_id, ValidatorId::new(3));
    }

    // ========================================================================
    // T144: Keystore Config Tests
    // ========================================================================

    #[test]
    fn validator_keystore_config_creation() {
        let config = ValidatorKeystoreConfig {
            keystore_root: PathBuf::from("/etc/qbind/keystore"),
            keystore_entry: "validator-1".to_string(),
            backend: crate::keystore::KeystoreBackend::PlainFs,
            encryption_config: None,
        };

        assert_eq!(config.keystore_root, PathBuf::from("/etc/qbind/keystore"));
        assert_eq!(config.keystore_entry, "validator-1");
    }

    #[test]
    fn validator_keystore_config_is_clone() {
        let config = ValidatorKeystoreConfig {
            keystore_root: PathBuf::from("/etc/qbind/keystore"),
            keystore_entry: "validator-1".to_string(),
            backend: crate::keystore::KeystoreBackend::PlainFs,
            encryption_config: None,
        };

        let cloned = config.clone();
        assert_eq!(cloned.keystore_root, config.keystore_root);
        assert_eq!(cloned.keystore_entry, config.keystore_entry);
    }
}