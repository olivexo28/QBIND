//! T175: P2P Node Builder
//!
//! This module provides `P2pNodeBuilder`, which wires up the P2P transport
//! components for a QBIND node:
//!
//! - `TcpKemTlsP2pService`: The P2P transport service
//! - `P2pInboundDemuxer`: Routes inbound messages to handlers
//! - `P2pConsensusNetwork`: Outbound consensus message sending
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       P2pNodeBuilder                            │
//! │                                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │              TcpKemTlsP2pService                          │ │
//! │  │                       │                                   │ │
//! │  │           ┌───────────┴───────────┐                      │ │
//! │  │           ▼                       ▼                      │ │
//! │  │    subscribe()             broadcast() / send_to()       │ │
//! │  │           │                       ▲                      │ │
//! │  └───────────┼───────────────────────┼──────────────────────┘ │
//! │              │                       │                        │
//! │              ▼                       │                        │
//! │  ┌───────────────────────────────────┴──────────────────────┐ │
//! │  │              P2pInboundDemuxer                            │ │
//! │  │                      │                                    │ │
//! │  │    ┌─────────────────┼─────────────────┐                 │ │
//! │  │    ▼                 ▼                 ▼                 │ │
//! │  │ Consensus       DAG Handler     Control Handler          │ │
//! │  │ Handler                                                  │ │
//! │  └──────────────────────────────────────────────────────────┘ │
//! │                                                                │
//! │  ┌──────────────────────────────────────────────────────────┐ │
//! │  │           P2pConsensusNetwork                             │ │
//! │  │  (implements ConsensusNetworkFacade)                      │ │
//! │  └──────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_node::p2p_node_builder::P2pNodeBuilder;
//!
//! let builder = P2pNodeBuilder::new();
//! let context = builder.build(&config, validator_id).await?;
//!
//! // ... run node ...
//!
//! P2pNodeBuilder::shutdown(context).await?;
//! ```

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::task::JoinHandle;

use crate::consensus_net_p2p::{P2pConsensusNetwork, SimpleValidatorNodeMapping};
use crate::identity_map::PeerValidatorMap;
use crate::metrics::P2pMetrics;
use crate::node_config::NodeConfig;
use crate::p2p::{NodeId, P2pService};
use crate::p2p_inbound::{
    ConsensusInboundHandler, ControlInboundHandler, DagInboundHandler, NullConsensusHandler,
    NullControlHandler, NullDagHandler, P2pInboundDemuxer,
};
use crate::p2p_tcp::{P2pTransportError, TcpKemTlsP2pService};

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::{
    AeadSuite, ChaCha20Poly1305Backend, CryptoError, KemSuite, MlDsa44SignatureSuite,
    MlKem768Backend, SignatureSuite, StaticCryptoProvider, AEAD_SUITE_CHACHA20_POLY1305,
    KEM_SUITE_ML_KEM_768,
};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, LeafCertRevocationList,
    MutualAuthMode, ServerConnectionConfig, ServerHandshakeConfig, TrustedClientRoots,
};

use crate::pqc_root_config::{
    decode_network_delegation_cert, validate_ml_kem_768_leaf_cert_shape,
    validate_ml_kem_768_leaf_material, PqcRootMode, PqcStaticRootConfig,
    PQC_TRANSPORT_SUITE_ML_DSA_44,
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during P2P node building and operation.
#[derive(Debug)]
pub enum P2pNodeError {
    /// Transport error.
    Transport(P2pTransportError),
    /// Configuration error.
    Config(String),
    /// IO error.
    Io(std::io::Error),
    /// Crypto error.
    Crypto(String),
}

impl std::fmt::Display for P2pNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P2pNodeError::Transport(e) => write!(f, "P2P transport error: {:?}", e),
            P2pNodeError::Config(msg) => write!(f, "P2P config error: {}", msg),
            P2pNodeError::Io(e) => write!(f, "P2P I/O error: {}", e),
            P2pNodeError::Crypto(msg) => write!(f, "P2P crypto error: {}", msg),
        }
    }
}

impl std::error::Error for P2pNodeError {}

impl From<P2pTransportError> for P2pNodeError {
    fn from(e: P2pTransportError) -> Self {
        P2pNodeError::Transport(e)
    }
}

impl From<std::io::Error> for P2pNodeError {
    fn from(e: std::io::Error) -> Self {
        P2pNodeError::Io(e)
    }
}

// ============================================================================
// P2pNodeContext
// ============================================================================

/// Context holding all P2P node components.
///
/// This struct holds references to all P2P components that need to be
/// kept alive while the node is running.
pub struct P2pNodeContext {
    /// The P2P transport service.
    pub p2p_service: Arc<TcpKemTlsP2pService>,
    /// The P2P consensus network facade.
    pub consensus_network: P2pConsensusNetwork,
    /// Handle to the demuxer task.
    pub demuxer_handle: JoinHandle<()>,
    /// P2P metrics.
    pub metrics: Arc<P2pMetrics>,
    /// Local validator ID.
    pub validator_id: ValidatorId,
    /// B7: peer-validator identity closure on the dialer side.
    ///
    /// For each outbound static peer parsed as `vid@addr`, this map records
    /// the binding `NodeId(deterministic from peer's test KEM public key) →
    /// ValidatorId(vid)` at dial-config time. This is what closes the
    /// peer-validator identity mapping for the dialer: the deterministic
    /// `NodeId` here is exactly the one `SimpleValidatorNodeMapping` (and
    /// therefore `P2pConsensusNetwork::send_to`) will look up when asked to
    /// address `ValidatorId(vid)`. Inbound sessions still admit under a
    /// temporary session NodeId because the current test-grade KEMTLS-PDK
    /// protocol does not exchange a client cert; that is acknowledged in
    /// `p2p_tcp::handle_inbound_connection` and tracked under C4 in
    /// `docs/whitepaper/contradiction.md`.
    pub peer_validator_map: Arc<RwLock<PeerValidatorMap>>,
}

impl std::fmt::Debug for P2pNodeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pNodeContext")
            .field("validator_id", &self.validator_id)
            .finish()
    }
}

// ============================================================================
// Dummy Crypto Implementations (T175 Testing)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
/// Used for P2P testing without real PQC crypto overhead.
struct DummyKem {
    suite_id: u8,
}

impl DummyKem {
    fn new(suite_id: u8) -> Self {
        DummyKem { suite_id }
    }
}

impl KemSuite for DummyKem {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn secret_key_len(&self) -> usize {
        32
    }

    fn ciphertext_len(&self) -> usize {
        48
    }

    fn shared_secret_len(&self) -> usize {
        48
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok(ss)
    }
}

/// A DummySig that always verifies successfully (for testing only).
struct DummySig {
    suite_id: u8,
}

impl DummySig {
    fn new(suite_id: u8) -> Self {
        DummySig { suite_id }
    }
}

impl SignatureSuite for DummySig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        32
    }

    fn signature_len(&self) -> usize {
        64
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// A DummyAead that XORs with a single-byte key (test-only).
struct DummyAead {
    suite_id: u8,
}

impl DummyAead {
    fn new(suite_id: u8) -> Self {
        DummyAead { suite_id }
    }
}

impl AeadSuite for DummyAead {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn key_len(&self) -> usize {
        32
    }

    fn nonce_len(&self) -> usize {
        12
    }

    fn tag_len(&self) -> usize {
        1
    }

    fn seal(
        &self,
        key: &[u8],
        _nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ key_byte).collect();
        // Dummy tag: XOR of aad bytes
        let tag = aad.iter().fold(0u8, |acc, b| acc ^ b);
        ciphertext.push(tag);
        Ok(ciphertext)
    }

    fn open(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        let key_byte = key.first().copied().unwrap_or(0);
        // Strip tag
        let ct_len = ciphertext.len() - self.tag_len();
        let plaintext: Vec<u8> = ciphertext[..ct_len].iter().map(|b| b ^ key_byte).collect();
        Ok(plaintext)
    }
}

/// Create a test crypto provider for P2P.
fn make_test_crypto_provider(
    kem_suite_id: u8,
    aead_suite_id: u8,
    sig_suite_id: u8,
) -> Arc<StaticCryptoProvider> {
    Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
            .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
            .with_signature_suite(Arc::new(DummySig::new(sig_suite_id))),
    )
}

/// Run 037: production-honest crypto provider for the
/// `PqcRootMode::PqcStaticRoot` path.
///
/// Differences from `make_test_crypto_provider`:
/// - the signature suite is the **real** `MlDsa44SignatureSuite` (FIPS
///   204 ML-DSA-44, reusing the same backend as validator vote /
///   proposal / timeout signing — no parallel crypto path);
/// - the registered `sig_suite_id` is the canonical PQC transport
///   suite ID (`100` = ML-DSA-44);
/// - **Run 039:** the registered KEM suite is the **real**
///   `MlKem768Backend` at suite_id=`KEM_SUITE_ML_KEM_768` (=100), not
///   `DummyKem`;
/// - **Run 040:** the registered AEAD suite is the **real**
///   `ChaCha20Poly1305Backend` at suite_id=`AEAD_SUITE_CHACHA20_POLY1305`
///   (=101), not `DummyAead`. The 32-byte AEAD key length matches the
///   key length used in the existing `qbind_net::keys::SessionKeys`
///   key schedule, the 12-byte nonce matches the existing
///   `flag(1) || session_id(3) || counter(8)` nonce layout in
///   `qbind_net::session::AeadSession`, and the 16-byte Poly1305 tag
///   replaces the 1-byte `DummyAead` marker tag — fail-closed on bad
///   tag / wrong key / wrong nonce / wrong AAD / malformed ciphertext.
///
/// This provider does NOT claim CA / cert rotation / cert revocation /
/// signed root-distribution lifecycle is solved; those remain operator-
/// out-of-band and are tracked under C4 in
/// `docs/whitepaper/contradiction.md`.
fn make_pqc_static_root_crypto_provider(
    sig_suite_id: u8,
) -> Arc<StaticCryptoProvider> {
    Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(MlKem768Backend::new()))
            .with_aead_suite(Arc::new(ChaCha20Poly1305Backend::new()))
            .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(sig_suite_id))),
    )
}

// ============================================================================
// B7: Test-grade deterministic KEM keypair / NodeId derivation
//
// These helpers are the *single source of truth* for the test-grade KEMTLS
// bring-up rule used on the binary path. They MUST be in agreement on every
// node that wants to talk to validator `vid`:
//
//   - the listener for validator `vid` derives its own KEM keypair from
//     `derive_test_kem_keypair_from_validator_id(vid)` (server-side cert +
//     `local_kem_sk`);
//   - the dialer for validator `vid` derives the *peer's* KEM public key
//     from `derive_test_kem_keypair_from_validator_id(vid).0` and uses it
//     as `ClientConnectionConfig.peer_kem_pk` so the KEMTLS handshake can
//     actually encapsulate to the peer's static KEM key;
//   - the consensus mapping (`SimpleValidatorNodeMapping`) and the
//     transport's local-NodeId field both use
//     `derive_test_node_id_from_validator_id(vid)` so that
//     `send_to(ValidatorId)` looks up the *same* NodeId the dialer
//     registered for that connection.
//
// This layer is bounded to DevNet / test-grade evidence runs. Production
// PQC keypair / certificate distribution remains tracked under C4 in
// `docs/whitepaper/contradiction.md`.
// ============================================================================

/// Derive the test-grade KEM keypair for a given validator id (DevNet only).
///
/// Returns `(public_key, secret_key)` matching the in-memory `DummyKem`
/// shape (32-byte pk, 32-byte sk). The rule is intentionally trivial and
/// deterministic: every node that wants to dial validator `vid` derives
/// the same `pk` here, and the listener for `vid` derives the same `sk`.
///
/// **Not for production.** Real PQC keypairs and a certificate path are
/// tracked separately under C4.
pub fn derive_test_kem_keypair_from_validator_id(vid: u64) -> (Vec<u8>, Vec<u8>) {
    let pk: Vec<u8> = (0u8..32u8).map(|i| i.wrapping_add(vid as u8)).collect();
    let sk: Vec<u8> = pk.iter().map(|x| x ^ 0xFF).collect();
    (pk, sk)
}

/// Derive the deterministic test-grade NodeId for a validator id.
///
/// Returns `NodeId = sha3_256_tagged("QBIND:nodeid:v1", test_kem_pk(vid))`.
/// This MUST match what `TcpKemTlsP2pService::dial_peer` computes from the
/// dialer's `ClientConnectionConfig.peer_kem_pk` once it has been
/// overridden to the peer's pk — see `p2p_tcp.rs` and B7 evidence.
pub fn derive_test_node_id_from_validator_id(vid: u64) -> NodeId {
    let (pk, _sk) = derive_test_kem_keypair_from_validator_id(vid);
    NodeId::new(qbind_hash::derive_node_id_from_pubkey(&pk))
}

/// Recover the dialer's local validator id from the `client_random`
/// field of a server-accepted `ClientInit` (B8 — listener-side identity
/// closure, test-grade).
///
/// `P2pNodeBuilder::create_connection_configs` deterministically embeds
/// the ASCII prefix `"qbind-client-<N>"` (zero-padded to 32 bytes) in
/// the dialer's `client_random` (see the `client_random` construction
/// there). This helper inverts that rule: given a 32-byte
/// `client_random`, it returns `Some(N)` if the prefix matches the
/// expected `"qbind-client-"` literal followed by an ASCII decimal
/// integer, and `None` otherwise.
///
/// # Security semantics
///
/// This is **test-grade only**. The `client_random` field is NOT
/// authenticated by the test-grade KEMTLS handshake under
/// `MutualAuthMode::Disabled` — a malicious dialer could spoof any vid
/// here. Production-grade peer identity binding requires mutual KEMTLS
/// auth (`MutualAuthMode::Required` in `qbind-net`), which is tracked
/// under C4 in `docs/whitepaper/contradiction.md`. B8 deliberately does
/// NOT change that.
///
/// What B8 does provide is enough determinism for two cooperating
/// `qbind-node` binaries on the test-grade DevNet path to register
/// inbound sessions under the same NodeId the dialer side already uses
/// — closing the listener-side "temporary session NodeId" gap observed
/// in DevNet Evidence Run 006 — without inventing a new identity
/// system.
pub fn parse_test_validator_id_from_client_random(client_random: &[u8; 32]) -> Option<u64> {
    const PREFIX: &[u8] = b"qbind-client-";
    if !client_random.starts_with(PREFIX) {
        return None;
    }
    // Take the digits after the prefix, stopping at the first non-ASCII-digit
    // byte (which will typically be the trailing zero-padding).
    let tail = &client_random[PREFIX.len()..];
    let mut end = 0usize;
    while end < tail.len() && tail[end].is_ascii_digit() {
        end += 1;
    }
    if end == 0 {
        return None;
    }
    // Bound the number of digits we accept to avoid surprises (a `u64`
    // fits in 20 ASCII decimal digits).
    if end > 20 {
        return None;
    }
    // SAFETY: tail[..end] is by construction all ASCII digits.
    let s = std::str::from_utf8(&tail[..end]).ok()?;
    s.parse::<u64>().ok()
}

/// B12 — recover a test-grade validator id from the 32-byte
/// `validator_id` field of a verified client `NetworkDelegationCert`.
///
/// `P2pNodeBuilder::create_connection_configs` deterministically
/// embeds the ASCII string `"qbind-val-<N>"` (zero-padded to 32
/// bytes) in the cert's `validator_id` field (this is the same
/// `qbind-val-<N>` byte pattern used everywhere for the test-grade
/// validator identity, including by the per-peer
/// `peer_validator_id_overrides` installed by `build()`). This
/// helper inverts that rule: given a 32-byte `validator_id`, it
/// returns `Some(N)` if the prefix matches the literal
/// `"qbind-val-"` followed by an ASCII decimal integer, and `None`
/// otherwise.
///
/// # Security semantics
///
/// Unlike [`parse_test_validator_id_from_client_random`], the
/// `validator_id` bytes consumed here come from a
/// `NetworkDelegationCert` whose signature is parsed and (when
/// `trusted_client_roots` is configured) verified by the
/// listener's `qbind_net::handshake::parse_and_verify_client_cert`
/// path BEFORE the resolver fires, and whose `leaf_kem_pk` is the
/// same field the AEAD transcript binds — so completion of the
/// mutual-auth handshake cryptographically constrains *which* peer
/// could have produced this cert.
///
/// Caller-side responsibility: this helper is only consulted by
/// the B12 resolver when
/// `AcceptedPeerInit::mutual_auth_complete == true` and only on the
/// `verified_peer_validator_id` bytes (never on the self-asserted
/// `ClientInit.validator_id`).
pub fn parse_test_validator_id_from_cert_validator_id(validator_id: &[u8; 32]) -> Option<u64> {
    const PREFIX: &[u8] = b"qbind-val-";
    if !validator_id.starts_with(PREFIX) {
        return None;
    }
    let tail = &validator_id[PREFIX.len()..];
    let mut end = 0usize;
    while end < tail.len() && tail[end].is_ascii_digit() {
        end += 1;
    }
    // u64::MAX is 20 decimal digits, so any longer prefix cannot
    // fit in a `u64` — reject without attempting to parse.
    if end == 0 || end > 20 {
        return None;
    }
    let s = std::str::from_utf8(&tail[..end]).ok()?;
    s.parse::<u64>().ok()
}

/// Parse a `--p2p-peer` spec which may be either `addr` or `vid@addr`.
///
/// Returns `Ok((Some(vid), addr))` when the spec is `vid@addr` (e.g.
/// `1@127.0.0.1:19001`), or `Ok((None, addr))` when it is bare `addr`.
///
/// The `vid@addr` form is required for the multi-validator binary-path
/// KEMTLS bring-up because the dialer needs to know which validator it
/// is dialing in order to derive the correct `peer_kem_pk` (see B7,
/// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md` §13). The bare `addr`
/// form is preserved for single-validator / DevNet smoke / legacy tests.
pub fn parse_peer_spec(s: &str) -> Result<(Option<u64>, String), String> {
    if let Some((vid_str, addr)) = s.split_once('@') {
        let vid = vid_str
            .parse::<u64>()
            .map_err(|e| format!("invalid validator-id prefix in --p2p-peer '{}': {}", s, e))?;
        if addr.is_empty() {
            return Err(format!("empty address after '@' in --p2p-peer '{}'", s));
        }
        Ok((Some(vid), addr.to_string()))
    } else {
        Ok((None, s.to_string()))
    }
}

fn validator_id_bytes_for_index(vid: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    let name = format!("qbind-val-{}", vid);
    out[..name.len().min(32)].copy_from_slice(name.as_bytes());
    out
}

fn verify_cert_with_configured_root(
    crypto: &StaticCryptoProvider,
    cfg: &PqcStaticRootConfig,
    cert: &qbind_wire::net::NetworkDelegationCert,
) -> Result<(), String> {
    let root = cfg
        .lookup_root_pk(&cert.root_key_id)
        .ok_or_else(|| "untrusted root_key_id".to_string())?;
    qbind_net::verify_delegation_cert(crypto, cert, &root.root_pk)
        .map_err(|e| format!("delegation cert verification failed: {:?}", e))
}

fn certified_peer_kem_pk_for_validator(
    crypto: &StaticCryptoProvider,
    cfg: &PqcStaticRootConfig,
    peer_vid: u64,
) -> Result<Vec<u8>, String> {
    let peer = cfg
        .peer_leaf_certs
        .iter()
        .find(|p| p.validator_index == peer_vid)
        .ok_or_else(|| {
            format!(
                "missing --p2p-peer-leaf-cert for validator {} in pqc-static-root mode",
                peer_vid
            )
        })?;
    let cert = decode_network_delegation_cert(&peer.cert_bytes)?;
    validate_ml_kem_768_leaf_cert_shape(&cert)?;
    verify_cert_with_configured_root(crypto, cfg, &cert)?;
    let expected_vid = validator_id_bytes_for_index(peer_vid);
    if cert.validator_id != expected_vid {
        return Err(format!(
            "peer leaf cert validator_id mismatch for validator {}",
            peer_vid
        ));
    }
    Ok(cert.leaf_kem_pk)
}

// ============================================================================
// P2pNodeBuilder
// ============================================================================

/// Builder for P2P node components (T175).
///
/// This builder creates and wires all the P2P components needed for
/// a QBIND node to operate in P2P mode.
pub struct P2pNodeBuilder {
    /// Number of validators in the network (default: 4).
    num_validators: usize,
    /// Consensus inbound handler (optional override).
    consensus_handler: Option<Arc<dyn ConsensusInboundHandler>>,
    /// DAG inbound handler (optional override).
    dag_handler: Option<Arc<dyn DagInboundHandler>>,
    /// Control inbound handler (optional override).
    control_handler: Option<Arc<dyn ControlInboundHandler>>,
    /// B12 — mutual KEMTLS authentication mode for the binary path.
    ///
    /// Defaults to `MutualAuthMode::Disabled` to preserve the
    /// pre-B12 test-grade `qbind-node` behaviour bit-for-bit when no
    /// explicit selection is made (so all existing
    /// `b1`/`b3`/`b5`/`b6`/`b7`/`b8`/`b9`/`b10`/`b11`/c4_b6/t172/t175
    /// regression tests continue to exercise the same Disabled-mode
    /// path). When set to `Required`, the listener turns on the
    /// `qbind_net::handshake::handle_client_init` mutual-auth code
    /// path (which already exists), the dialer attaches a client
    /// `NetworkDelegationCert`, and the listener-side
    /// `InboundIdentityResolver` is replaced with one that consults
    /// the *verified* `AcceptedPeerInit.verified_peer_validator_id`
    /// instead of the dialer's self-asserted `client_random`.
    mutual_auth_mode: MutualAuthMode,
    /// Run 037 (C4 piece (c)): production-honest PQC KEMTLS root-key
    /// distribution config.
    ///
    /// When this is `Some(cfg)` with `cfg.mode == PqcRootMode::PqcStaticRoot`,
    /// the builder:
    /// - registers the real `MlDsa44SignatureSuite` under suite_id 100
    ///   (replacing the test-grade `DummySig` for that suite_id);
    /// - replaces the deterministic `TrustedClientRoots` resolver with
    ///   one that consults `cfg.trusted_roots`;
    /// - if `cfg.leaf_credentials` is set, uses those bytes as the
    ///   on-wire `NetworkDelegationCert` (real ML-DSA-44-signed) and
    ///   the corresponding KEM secret key, instead of the test-grade
    ///   deterministic `make_dummy_delegation_cert` pair.
    ///
    /// When this is `None` or `cfg.mode == PqcRootMode::TestGradeDummySig`,
    /// the builder keeps the pre-Run-037 B12 wiring bit-for-bit.
    pqc_root_config: Option<PqcStaticRootConfig>,
    /// Run 043: optional caller-supplied `P2pMetrics` Arc.
    ///
    /// When set, `build()` uses this `Arc<P2pMetrics>` instead of creating
    /// a fresh local one. This lets `qbind-node`'s `main.rs` share the
    /// **same** `P2pMetrics` instance between (a) the live P2P transport
    /// path (which increments cert-verify / per-reason rejection counters)
    /// and (b) the live `/metrics` HTTP scrape served from
    /// `NodeMetrics::format_metrics`. Without this shared handle, the
    /// builder's local `Arc<P2pMetrics>` and `NodeMetrics::p2p` are two
    /// separate instances and the `qbind_p2p_pqc_*` family on `/metrics`
    /// stays at zero even under live `pqc-static-root` operation. When
    /// `None`, `build()` falls back to creating a fresh local instance
    /// (preserving pre-Run-043 behaviour for builder-only tests).
    p2p_metrics: Option<Arc<P2pMetrics>>,
    /// Run 052: optional revoked leaf-cert fingerprint set, derived
    /// from the loaded trust bundle's currently-active
    /// `revocations[i].leaf_cert_fingerprint` entries. Default is
    /// `None`, in which case no leaf-cert revocation enforcement is
    /// installed and the handshake engine takes the zero-cost no-op
    /// path. The set is shared by Arc so the same revocation list
    /// flows into both client- and server-side handshake configs
    /// without re-allocation.
    pqc_revoked_leaf_fingerprints: Option<Arc<HashSet<[u8; 32]>>>,
}

impl Default for P2pNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl P2pNodeBuilder {
    /// Create a new P2P node builder with default settings.
    pub fn new() -> Self {
        Self {
            num_validators: 4,
            consensus_handler: None,
            dag_handler: None,
            control_handler: None,
            // Preserve the pre-B12 default for full backward
            // compatibility with existing DevNet test-grade evidence
            // runs and harnesses. The hardened `Required` path is
            // explicitly opted into via `with_mutual_auth_mode`.
            mutual_auth_mode: MutualAuthMode::Disabled,
            // Run 037: defaults to None to preserve pre-Run-037
            // behaviour bit-for-bit. Production-honest mode is opted
            // into via `with_pqc_root_config`.
            pqc_root_config: None,
            // Run 043: defaults to None — `build()` creates a fresh
            // local `Arc<P2pMetrics>`. The live binary path
            // (`qbind-node`'s `main.rs`) wires this through
            // `with_p2p_metrics(node_metrics.p2p_arc())` so that the
            // `qbind_p2p_pqc_*` counters surfaced on the live
            // `/metrics` endpoint reflect real cert-verify activity.
            p2p_metrics: None,
            // Run 052: leaf-cert revocations default to none so that
            // pre-Run-052 builders behave bit-for-bit identically.
            // The live binary wires this from the loaded trust bundle.
            pqc_revoked_leaf_fingerprints: None,
        }
    }

    /// Set the number of validators in the network.
    pub fn with_num_validators(mut self, n: usize) -> Self {
        self.num_validators = n;
        self
    }

    /// Set a custom consensus inbound handler.
    pub fn with_consensus_handler(mut self, handler: Arc<dyn ConsensusInboundHandler>) -> Self {
        self.consensus_handler = Some(handler);
        self
    }

    /// Set a custom DAG inbound handler.
    pub fn with_dag_handler(mut self, handler: Arc<dyn DagInboundHandler>) -> Self {
        self.dag_handler = Some(handler);
        self
    }

    /// Set a custom control inbound handler.
    pub fn with_control_handler(mut self, handler: Arc<dyn ControlInboundHandler>) -> Self {
        self.control_handler = Some(handler);
        self
    }

    /// B12 — opt into mutual KEMTLS authentication on the binary
    /// path.
    ///
    /// `MutualAuthMode::Required` makes the listener:
    /// 1. require a v2 `ClientInit` carrying a client
    ///    `NetworkDelegationCert`,
    /// 2. parse + verify the client cert (signature path is exercised
    ///    when `trusted_client_roots` is configured),
    /// 3. transcript-bind the client cert into the AEAD key schedule,
    /// 4. surface the cert-bound peer validator id and NodeId via
    ///    [`AcceptedPeerInit::verified_peer_validator_id`] /
    ///    [`AcceptedPeerInit::verified_client_node_id`] /
    ///    [`AcceptedPeerInit::mutual_auth_complete`].
    ///
    /// The dialer side of the same builder also attaches a client
    /// cert, so two `qbind-node` binaries running with this mode set
    /// to `Required` complete a full mutual-auth handshake.
    ///
    /// `Disabled` (the default) preserves the pre-B12 test-grade
    /// behaviour where the listener-side resolver consumes the
    /// self-asserted `client_random` (see B8). `Optional` is supported
    /// by the underlying handshake but not directly exercised by the
    /// binary path; it falls back to the `Disabled`-shaped resolver.
    pub fn with_mutual_auth_mode(mut self, mode: MutualAuthMode) -> Self {
        self.mutual_auth_mode = mode;
        self
    }

    /// Run 037 (C4 piece (c)): opt into production-honest PQC root-key
    /// distribution.
    ///
    /// When called with a config whose `mode == PqcRootMode::PqcStaticRoot`:
    /// - The crypto provider registers the real `MlDsa44SignatureSuite`
    ///   under suite_id `100` instead of the test-grade `DummySig`.
    /// - The listener-side `TrustedClientRoots` resolver consults the
    ///   operator-configured roots; unknown `root_key_id` ⇒ rejected
    ///   with `NetError::ClientCertInvalid("untrusted root")`.
    /// - When `leaf_credentials` is provided, the dialer presents the
    ///   real ML-DSA-44-signed `NetworkDelegationCert` from disk
    ///   (matching `cert.leaf_kem_pk` to the loaded KEM secret key).
    ///
    /// When called with `mode == PqcRootMode::TestGradeDummySig` (or
    /// not called at all), pre-Run-037 B12 wiring is preserved
    /// bit-for-bit.
    pub fn with_pqc_root_config(mut self, cfg: PqcStaticRootConfig) -> Self {
        self.pqc_root_config = Some(cfg);
        self
    }

    /// Run 043: install a caller-supplied `Arc<P2pMetrics>` so that the
    /// live transport path and the live `/metrics` HTTP endpoint
    /// scrape the **same** `P2pMetrics` instance.
    ///
    /// Without this, `build()` creates a fresh local `Arc<P2pMetrics>`
    /// (preserving pre-Run-043 behaviour for builder-only unit tests),
    /// but in the live binary that local instance is never reached by
    /// `NodeMetrics::format_metrics`, so the `qbind_p2p_pqc_*` family on
    /// the live `/metrics` endpoint reads as zero even under
    /// `pqc-static-root` Required mode. `qbind-node`'s `main.rs` wires
    /// this via `with_p2p_metrics(node_metrics.p2p_arc())`.
    pub fn with_p2p_metrics(mut self, metrics: Arc<P2pMetrics>) -> Self {
        self.p2p_metrics = Some(metrics);
        self
    }

    /// Run 052: install a caller-supplied set of revoked leaf-cert
    /// fingerprints (the active subset of
    /// `revocations[i].leaf_cert_fingerprint` from the loaded trust
    /// bundle). On the production-honest PQC mutual-auth path
    /// (`MutualAuthMode::Required` or `Optional` + `PqcStaticRoot`),
    /// this set is wrapped in a `LeafCertRevocationList` and wired
    /// into both client- and server-side handshake configs so that a
    /// verified leaf cert whose fingerprint matches an entry fails
    /// closed with `NetError::ClientCertInvalid("cert revoked")`. On
    /// the test-grade DummySig path the set is ignored — the leaf-
    /// revocation surface is intentionally PQC-only, mirroring the
    /// Run 044 cert-verify metrics sink wiring discipline.
    pub fn with_pqc_leaf_revocations(
        mut self,
        revoked_leaf_fingerprints: Arc<HashSet<[u8; 32]>>,
    ) -> Self {
        self.pqc_revoked_leaf_fingerprints = Some(revoked_leaf_fingerprints);
        self
    }

    /// Build the P2P node context.
    ///
    /// This method:
    /// 1. Creates the TcpKemTlsP2pService
    /// 2. Starts the service (listen + dial peers)
    /// 3. Creates the P2pInboundDemuxer
    /// 4. Creates the P2pConsensusNetwork
    /// 5. Spawns the demuxer loop
    ///
    /// # Arguments
    ///
    /// * `config` - The node configuration
    /// * `validator_id` - The local validator ID
    ///
    /// # Returns
    ///
    /// A P2pNodeContext containing all wired components.
    pub async fn build(
        self,
        config: &NodeConfig,
        validator_id: u64,
    ) -> Result<P2pNodeContext, P2pNodeError> {
        let validator_id = ValidatorId::new(validator_id);

        // B7: local NodeId is derived from the local validator's *test-grade
        // KEM public key* via the same `sha3_256_tagged("QBIND:nodeid:v1", pk)`
        // rule that `TcpKemTlsP2pService::dial_peer` applies to derive a
        // dialed peer's NodeId, and that `SimpleValidatorNodeMapping` uses to
        // address validators by `ValidatorId`. Aligning these three deriva-
        // tions is what closes peer-validator identity for `send_to(...)` on
        // the binary path: the consensus mapping → NodeId → P2P peer connec-
        // tion now round-trips on every node.
        let pqc_active = matches!(
            self.pqc_root_config.as_ref().map(|c| c.mode),
            Some(PqcRootMode::PqcStaticRoot)
        );
        let node_id = if pqc_active {
            let creds = self
                .pqc_root_config
                .as_ref()
                .and_then(|cfg| cfg.leaf_credentials.as_ref())
                .ok_or_else(|| {
                    P2pNodeError::Config(
                        "pqc-static-root requires local ML-KEM-768 leaf credentials".to_string(),
                    )
                })?;
            let cert = validate_ml_kem_768_leaf_material(&creds.cert_bytes, &creds.kem_sk_bytes)
                .map_err(P2pNodeError::Config)?;
            NodeId::new(qbind_hash::derive_node_id_from_pubkey(&cert.leaf_kem_pk))
        } else {
            derive_test_node_id_from_validator_id(validator_id.as_u64())
        };

        // Create crypto provider.
        //
        // Test-grade default: DummySig at suite_id=3, used by all
        // pre-Run-037 evidence runs (B7..B12, T175, etc.).
        //
        // Run 037 production-honest mode: when the operator opted into
        // `with_pqc_root_config(cfg)` with `cfg.mode == PqcStaticRoot`,
        // we register the real `MlDsa44SignatureSuite` at suite_id=100
        // (the canonical PQC transport suite ID) instead of `DummySig`.
        // Cert verification then runs through the existing
        // `qbind_net::handshake::verify_delegation_cert` path against
        // the operator-configured root pks. KEM/AEAD remain on the
        // existing test-grade primitives — production ML-KEM-768 /
        // AEAD wiring on this binary surface is a separate C4 piece
        // (NOT C4(c)), tracked in `docs/whitepaper/contradiction.md`.
        let kem_suite_id: u8 = if pqc_active { KEM_SUITE_ML_KEM_768 } else { 1 };
        // Run 040: when pqc-static-root is active on this binary path,
        // the AEAD suite is the real ChaCha20-Poly1305 backend at
        // suite_id=101 (`AEAD_SUITE_CHACHA20_POLY1305`). The pre-Run-040
        // test-grade default keeps suite_id=2 + DummyAead so existing
        // B7/B8/B12 / T138 / T143 / T144 / T160 / T222 etc. tests
        // remain bit-for-bit. Both ends agree because (a) the same
        // `pqc_active` decision is taken from
        // `with_pqc_root_config(...)` on each side, and (b)
        // `aead_suite_id` is mixed into the HKDF info parameter inside
        // `qbind_net::keys::SessionKeys::derive`, so a mismatched suite
        // id between dialer and listener fails closed at handshake.
        let aead_suite_id: u8 = if pqc_active {
            AEAD_SUITE_CHACHA20_POLY1305
        } else {
            2
        };
        let sig_suite_id: u8 = if pqc_active {
            PQC_TRANSPORT_SUITE_ML_DSA_44
        } else {
            3
        };
        let crypto = if pqc_active {
            make_pqc_static_root_crypto_provider(sig_suite_id)
        } else {
            make_test_crypto_provider(kem_suite_id, aead_suite_id, sig_suite_id)
        };
        eprintln!(
            "[Run040] P2pNodeBuilder: pqc_root_mode={} sig_suite_id={} \
             transport_kem_suite_id={} transport_kem_suite_name={} dummy_kem_registered={} \
             transport_aead_suite_id={} transport_aead_suite_name={} dummy_aead_registered={} \
             configured_roots={} leaf_credentials_present={}",
            self.pqc_root_config
                .as_ref()
                .map(|c| c.mode.to_string())
                .unwrap_or_else(|| "test-grade-dummy-sig".to_string()),
            sig_suite_id,
            kem_suite_id,
            if pqc_active {
                "ml-kem-768"
            } else {
                "dummy-kem"
            },
            !pqc_active,
            aead_suite_id,
            if pqc_active {
                "chacha20-poly1305"
            } else {
                "dummy-aead"
            },
            !pqc_active,
            self.pqc_root_config
                .as_ref()
                .map(|c| c.trusted_roots.len())
                .unwrap_or(0),
            self.pqc_root_config
                .as_ref()
                .map(|c| c.leaf_credentials.is_some())
                .unwrap_or(false),
        );

        // Create connection configs
        let (server_cfg, client_cfg) = self.create_connection_configs(
            validator_id,
            crypto.clone(),
            kem_suite_id,
            aead_suite_id,
            sig_suite_id,
            self.mutual_auth_mode,
        )?;

        // B7: parse `static_peers` for the optional `vid@addr` syntax and
        // build per-peer overrides:
        //
        //   - `peer_kem_pk_overrides`: addr → peer's test-grade KEM public
        //     key. Threaded into `TcpKemTlsP2pService` so each outbound dial
        //     uses the *peer's* KEM public key as `peer_kem_pk` (instead of
        //     the local node's, which was the Run 005 blocker).
        //   - `peer_validator_map`: NodeId(deterministic from peer kem pk)
        //     → ValidatorId. Closes the peer-validator identity binding on
        //     the dialer side at config time so `send_to(ValidatorId)`
        //     resolves to the same NodeId the dialed connection registers
        //     under.
        let mut peer_kem_pk_overrides: HashMap<String, Vec<u8>> = HashMap::new();
        let mut peer_vid_overrides: HashMap<String, [u8; 32]> = HashMap::new();
        let mut peer_node_id_by_vid: HashMap<u64, NodeId> = HashMap::new();
        let mut peer_validator_map = PeerValidatorMap::new();
        let mut had_unspec_peer = false;
        for spec in &config.network.static_peers {
            let (peer_vid_opt, addr) =
                parse_peer_spec(spec).map_err(|e| P2pNodeError::Config(e))?;
            if let Some(peer_vid) = peer_vid_opt {
                let peer_pk = if pqc_active {
                    let cfg = self.pqc_root_config.as_ref().ok_or_else(|| {
                        P2pNodeError::Config("missing pqc-static-root config".to_string())
                    })?;
                    certified_peer_kem_pk_for_validator(crypto.as_ref(), cfg, peer_vid)
                        .map_err(P2pNodeError::Config)?
                } else {
                    let (peer_pk, _peer_sk) = derive_test_kem_keypair_from_validator_id(peer_vid);
                    peer_pk
                };
                peer_kem_pk_overrides.insert(addr.clone(), peer_pk.clone());
                // The 32-byte validator-id field expected by KEMTLS must
                // exactly match what the peer's listener side puts into
                // `ServerHandshakeConfig.local_validator_id` AND into the
                // delegation cert's `validator_id`. The current builder
                // (see `create_connection_configs` below) uses the
                // 8-bit-ASCII string `qbind-val-<N>` zero-padded to 32
                // bytes, so we mirror that *exact* byte pattern here.
                // Any divergence causes
                // `delegation_cert.validator_id != client_init.validator_id`
                // and the dialer aborts with `client handle_server_accept
                // failed`.
                let mut vid_bytes = [0u8; 32];
                let name = format!("qbind-val-{}", peer_vid);
                let n = name.len().min(32);
                vid_bytes[..n].copy_from_slice(&name.as_bytes()[..n]);
                peer_vid_overrides.insert(addr.clone(), vid_bytes);
                let peer_node_id = NodeId::new(qbind_hash::derive_node_id_from_pubkey(&peer_pk));
                peer_node_id_by_vid.insert(peer_vid, peer_node_id);
                let peer_id_u64 =
                    u64::from_le_bytes(peer_node_id.as_bytes()[..8].try_into().unwrap_or([0u8; 8]));
                peer_validator_map
                    .insert(crate::peer::PeerId(peer_id_u64), ValidatorId::new(peer_vid));
            } else {
                had_unspec_peer = true;
            }
        }
        // For the multi-validator binary path, refuse to silently dial a
        // bare `addr` (no `vid@`) because we cannot then derive the peer's
        // test-grade KEM public key, which is exactly the Run 005 failure
        // mode. Single-validator / no-peer setups never hit this branch.
        if had_unspec_peer
            && peer_kem_pk_overrides.is_empty()
            && config.network.static_peers.len() > 1
        {
            return Err(P2pNodeError::Config(
                "B7: --p2p-peer entries must be of the form 'vid@addr' on \
                 the multi-validator binary path so the dialer can derive \
                 the peer's test-grade KEM public key. See \
                 docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md §13."
                    .to_string(),
            ));
        }

        // Create P2P service
        //
        // B7: hand the transport a `NetworkTransportConfig` whose
        // `static_peers` list has been stripped of any `vid@` prefix —
        // the transport itself stays oblivious to the syntax and just
        // dials raw `addr` strings, while the per-peer `peer_kem_pk`
        // overrides (computed above and keyed by the same stripped addr)
        // are installed before `start()` so each dial picks up the
        // correct peer KEM public key.
        let mut transport_config = config.network.clone();
        let mut stripped_peers: Vec<String> =
            Vec::with_capacity(transport_config.static_peers.len());
        for spec in &transport_config.static_peers {
            let (_vid_opt, addr) = parse_peer_spec(spec).map_err(|e| P2pNodeError::Config(e))?;
            stripped_peers.push(addr);
        }
        transport_config.static_peers = stripped_peers;

        let mut p2p_service =
            TcpKemTlsP2pService::new(node_id, transport_config, crypto, server_cfg, client_cfg)?;
        // B7: install per-peer KEM-pk + validator-id overrides before `start()` dials.
        if !peer_kem_pk_overrides.is_empty() {
            p2p_service.set_peer_kem_pk_overrides(peer_kem_pk_overrides);
            p2p_service.set_peer_validator_id_overrides(peer_vid_overrides);
        }

        // B8/B12: install the listener-side identity resolver.
        //
        // The resolver is responsible for binding an accepted inbound
        // session to a deterministic, routable NodeId so that
        // `send_to(ValidatorId)` resolves to a registered transport
        // session in BOTH directions. There are two shapes:
        //
        //   1. **B12 (mutual-auth, hardened)** — when
        //      `mutual_auth_mode == MutualAuthMode::Required`, the
        //      `qbind_net::handshake::parse_and_verify_client_cert`
        //      path on the listener has already parsed the dialer's
        //      client `NetworkDelegationCert`, transcript-bound it
        //      into the AEAD key schedule, and (when
        //      `trusted_client_roots` is configured) verified its
        //      signature against the configured root. The resolver
        //      consumes the cert-derived
        //      `AcceptedPeerInit.verified_peer_validator_id` and maps
        //      it through `parse_test_validator_id_from_cert_validator_id`
        //      → `derive_test_node_id_from_validator_id(vid)` to
        //      produce the SAME deterministic NodeId the dialer side
        //      registers under (so the resulting NodeId on both ends
        //      is byte-identical to the B7/B8 deterministic-NodeId
        //      shape, but is now sourced from a cryptographically
        //      bound cert field rather than from the dialer's
        //      self-asserted `client_random`).
        //
        //      In Required mode, the resolver fails closed: if the
        //      handshake completed but `mutual_auth_complete == false`
        //      (impossible under Required mode by design, but
        //      defensive), or if the verified validator id bytes do
        //      not parse, the resolver returns `None` and the
        //      transport falls back to the legacy temporary-NodeId
        //      path. The transport itself does not silently accept
        //      sessions under temporary NodeIds when the validator
        //      identity cannot be derived; downstream
        //      `send_to(ValidatorId)` simply fails to resolve.
        //
        //   2. **B8 (test-grade, default)** — when
        //      `mutual_auth_mode == MutualAuthMode::Disabled` (the
        //      pre-B12 default), the resolver consumes the dialer's
        //      already-on-the-wire `client_random` (deterministically
        //      prefixed by `qbind-client-<N>` in
        //      `create_connection_configs` below) to recover the
        //      dialer's local validator id `N`, then derives the SAME
        //      deterministic NodeId via
        //      `derive_test_node_id_from_validator_id`. This is
        //      strictly self-asserted and is documented as such; B12
        //      did not change it.
        //
        // No silent override of prior behaviour: when the resolver
        // returns `None` (e.g. an unrelated tool connects with a
        // non-`qbind-client-N` `client_random`, or the cert's
        // `validator_id` field doesn't parse to a known shape), the
        // transport falls back to the legacy temporary-session-NodeId
        // path automatically.
        let resolver_mode = self.mutual_auth_mode;
        let resolver_pqc_active = pqc_active;
        let resolver_peer_node_ids = peer_node_id_by_vid.clone();
        p2p_service.set_inbound_identity_resolver(Arc::new(
            move |peer_init: &crate::secure_channel::AcceptedPeerInit| -> Option<NodeId> {
                match resolver_mode {
                    MutualAuthMode::Required | MutualAuthMode::Optional => {
                        // B12 — hardened path: only accept identity
                        // sourced from the *verified* cert. If the
                        // peer did not actually complete mutual auth,
                        // do NOT fall back to the self-asserted
                        // `client_random` path — that would silently
                        // weaken the hardened guarantee.
                        if !peer_init.mutual_auth_complete {
                            return None;
                        }
                        let vid_bytes = peer_init.verified_peer_validator_id?;
                        let vid = parse_test_validator_id_from_cert_validator_id(&vid_bytes)?;
                        if resolver_pqc_active {
                            return resolver_peer_node_ids.get(&vid).copied();
                        }
                        Some(derive_test_node_id_from_validator_id(vid))
                    }
                    MutualAuthMode::Disabled => {
                        // B8 — test-grade self-asserted path.
                        let vid =
                            parse_test_validator_id_from_client_random(&peer_init.client_random)?;
                        Some(derive_test_node_id_from_validator_id(vid))
                    }
                }
            },
        ));

        // Start the service
        p2p_service.start().await?;

        let p2p_service = Arc::new(p2p_service);

        // Create metrics. Run 043: prefer a caller-supplied
        // `Arc<P2pMetrics>` (so the live `qbind-node` binary path shares
        // exactly one `P2pMetrics` instance between the transport and
        // the `/metrics` HTTP scrape served from
        // `NodeMetrics::format_metrics`). Falls back to a fresh local
        // instance for builder-only tests, preserving pre-Run-043
        // behaviour bit-for-bit when `with_p2p_metrics` is not called.
        let metrics = self
            .p2p_metrics
            .clone()
            .unwrap_or_else(|| Arc::new(P2pMetrics::new()));

        // Run 037: surface PQC root distribution mode in metrics so
        // operators / scrapers can confirm at a glance whether the
        // production-honest path is active and how many roots are
        // configured. No private key bytes are exposed.
        let (pqc_mode_n, pqc_roots_n) = match self.pqc_root_config.as_ref() {
            Some(cfg) => {
                let m = match cfg.mode {
                    PqcRootMode::TestGradeDummySig => 0u64,
                    PqcRootMode::PqcStaticRoot => 1u64,
                };
                (m, cfg.trusted_roots.len() as u64)
            }
            None => (0u64, 0u64),
        };
        metrics.set_pqc_root_mode(pqc_mode_n);
        metrics.set_pqc_roots_configured(pqc_roots_n);

        // Get inbound receiver from P2P service.
        //
        // C4/B6 fix: previously this code created a fresh, immediately-dropped
        // mpsc channel and plugged its receiver into the demuxer, which meant
        // every frame the transport actually delivered (via its internal
        // `inbound_tx`) was silently lost — the demuxer received nothing,
        // regardless of which `ConsensusInboundHandler` was wired in. We now
        // call `p2p_service.subscribe().await`, which is the real fan-out
        // surface exposed by `TcpKemTlsP2pService` over its shared inbound
        // queue, so inbound consensus / DAG / control frames actually reach
        // the demuxer (and from there, whatever handler the caller installed).
        let inbound_rx = p2p_service.subscribe().await;

        // Create handlers (use provided or default null handlers)
        let consensus_handler: Arc<dyn ConsensusInboundHandler> = self
            .consensus_handler
            .unwrap_or_else(|| Arc::new(NullConsensusHandler));
        let dag_handler: Arc<dyn DagInboundHandler> =
            self.dag_handler.unwrap_or_else(|| Arc::new(NullDagHandler));
        let control_handler: Arc<dyn ControlInboundHandler> = self
            .control_handler
            .unwrap_or_else(|| Arc::new(NullControlHandler));

        // Create demuxer
        let demuxer = P2pInboundDemuxer::new(
            inbound_rx,
            consensus_handler,
            dag_handler,
            Some(control_handler),
        )
        .with_metrics(metrics.clone());

        // Spawn demuxer loop
        let demuxer_handle = tokio::spawn(async move {
            demuxer.run().await;
        });

        // Create P2P consensus network
        let consensus_network = P2pConsensusNetwork::new(
            p2p_service.clone() as Arc<dyn P2pService>,
            self.num_validators,
        )
        .with_local_validator(validator_id);

        println!(
            "[T175] P2P node builder: validator={:?} node_id={:?} num_validators={} \
             peer_kem_overrides={} mutual_auth={:?}",
            validator_id,
            node_id,
            self.num_validators,
            peer_validator_map.len(),
            self.mutual_auth_mode,
        );

        Ok(P2pNodeContext {
            p2p_service,
            consensus_network,
            demuxer_handle,
            metrics,
            validator_id,
            peer_validator_map: Arc::new(RwLock::new(peer_validator_map)),
        })
    }

    /// Create KEMTLS connection configs for the node.
    fn create_connection_configs(
        &self,
        validator_id: ValidatorId,
        crypto: Arc<StaticCryptoProvider>,
        kem_suite_id: u8,
        aead_suite_id: u8,
        sig_suite_id: u8,
        mutual_auth_mode: MutualAuthMode,
    ) -> Result<(ServerConnectionConfig, ClientConnectionConfig), P2pNodeError> {
        // Create validator identity bytes
        let mut validator_id_bytes = [0u8; 32];
        let name = format!("qbind-val-{}", validator_id.as_u64());
        validator_id_bytes[..name.len().min(32)].copy_from_slice(name.as_bytes());

        // Create root key ID
        let mut root_key_id = [0u8; 32];
        root_key_id[0..8].copy_from_slice(b"root-key");

        // B7: derive the local validator's KEM keypair via the centralized
        // test-grade rule. The dialer/listener agreement on this rule is
        // what allows two `qbind-node` processes to actually complete the
        // KEMTLS handshake — see `derive_test_kem_keypair_from_validator_id`
        // and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md` §13.
        let (server_kem_pk, server_kem_sk) =
            derive_test_kem_keypair_from_validator_id(validator_id.as_u64());

        // Create a test-grade dummy delegation certificate (used by
        // default and when the PQC mode is not active OR when the
        // operator did not supply leaf_credentials).
        let dummy_cert = self.make_dummy_delegation_cert(
            validator_id_bytes,
            root_key_id,
            server_kem_pk.clone(),
            kem_suite_id,
            sig_suite_id,
        );

        // Encode test-grade certificate
        use qbind_wire::io::WireEncode;
        let mut dummy_cert_bytes = Vec::new();
        dummy_cert.encode(&mut dummy_cert_bytes);

        // Run 037: when the operator opted into pqc-static-root and
        // supplied a real ML-DSA-44-signed leaf cert + KEM sk via
        // `--p2p-leaf-cert*`, present those bytes on the wire instead
        // of the test-grade dummy. The leaf KEM pk is bound by the
        // cert (the offline helper wrote it there); the corresponding
        // KEM sk is read from disk and wrapped into `KemPrivateKey`
        // (zeroize-on-drop) below.
        //
        // We deliberately do not auto-mint a cert at runtime in
        // production-required mode — the offline helper
        // `pqc_devnet_helper::issue_leaf_delegation_cert` is the
        // single source of cert issuance.
        let pqc_cfg = self
            .pqc_root_config
            .as_ref()
            .filter(|cfg| matches!(cfg.mode, PqcRootMode::PqcStaticRoot));
        let pqc_leaf = pqc_cfg.and_then(|cfg| cfg.leaf_credentials.as_ref());
        let (cert_bytes, server_kem_pk_final, server_kem_sk_final) = match (pqc_cfg, pqc_leaf) {
            (Some(cfg), Some(creds)) => {
                let cert =
                    validate_ml_kem_768_leaf_material(&creds.cert_bytes, &creds.kem_sk_bytes)
                        .map_err(P2pNodeError::Config)?;
                verify_cert_with_configured_root(crypto.as_ref(), cfg, &cert)
                    .map_err(P2pNodeError::Config)?;
                if cert.validator_id != validator_id_bytes {
                    return Err(P2pNodeError::Config(
                        "local leaf cert validator_id does not match --validator-id".to_string(),
                    ));
                }
                (
                    creds.cert_bytes.clone(),
                    cert.leaf_kem_pk,
                    creds.kem_sk_bytes.clone(),
                )
            }
            (Some(_), None) => {
                return Err(P2pNodeError::Config(
                    "pqc-static-root requires local ML-KEM-768 leaf credentials".to_string(),
                ));
            }
            (None, _) => (dummy_cert_bytes, server_kem_pk, server_kem_sk),
        };

        // Root network public key.
        //
        // Pre-Run-037 / test-grade default: a 32-byte dummy. The
        // `DummySig::verify` path accepts any signature so the actual
        // root pk bytes don't matter on either dialer or listener
        // side.
        //
        // Run 037: when the operator is in `PqcStaticRoot` mode, the
        // dialer's `peer_root_network_pk` and the server's
        // `local_root_network_pk` must both be the operator-configured
        // root pk (the SAME ML-DSA-44 pk that signed our leaf cert).
        // The dialer uses it to verify the listener's ServerAccept
        // cert; the listener uses it as the local cert's binding
        // material. We pick the first configured trusted root for
        // this DevNet shape (single-root); a future multi-root /
        // rotated path is tracked under C4 in
        // `docs/whitepaper/contradiction.md`.
        let root_network_pk: Vec<u8> = match self
            .pqc_root_config
            .as_ref()
            .filter(|cfg| matches!(cfg.mode, PqcRootMode::PqcStaticRoot))
            .and_then(|cfg| cfg.trusted_roots.first())
        {
            Some(r) => r.root_pk.clone(),
            None => vec![0u8; 32],
        };

        // Random values for handshake
        let mut client_random = [0u8; 32];
        let client_name = format!("qbind-client-{}", validator_id.as_u64());
        client_random[..client_name.len().min(32)].copy_from_slice(client_name.as_bytes());

        let mut server_random = [0u8; 32];
        let server_name = format!("qbind-server-{}", validator_id.as_u64());
        server_random[..server_name.len().min(32)].copy_from_slice(server_name.as_bytes());

        // B12 — under `MutualAuthMode::Required` the dialer must
        // present a v2 `ClientInit` carrying a `NetworkDelegationCert`
        // for its OWN validator identity. We reuse the same dummy
        // delegation cert this node uses on its server side (which
        // binds `cert.validator_id = qbind-val-<N>` and
        // `cert.leaf_kem_pk = test_kem_pk(N)`), so when this node
        // dials a peer, the peer's listener parses our cert and binds
        // the inbound session to `qbind-val-<N>` →
        // `derive_test_node_id_from_validator_id(N)`. The cert bytes
        // are byte-identical on both server and client sides, which
        // is intentional: this is a self-issued test-grade delegation
        // cert (a real production-grade flow would rotate the leaf
        // cert independently from the long-term root). Under
        // `Disabled` we keep the pre-B12 behaviour and present no
        // client cert (protocol v1).
        let local_client_cert = match mutual_auth_mode {
            MutualAuthMode::Required | MutualAuthMode::Optional => Some(cert_bytes.clone()),
            MutualAuthMode::Disabled => None,
        };

        // B12 — under hardened mode, install a trusted-client-roots
        // resolver so the listener actually exercises the
        // `verify_delegation_cert` signature path on the dialer's
        // cert (rather than returning `Vec::new()` from
        // `parse_and_verify_client_cert` and skipping signature
        // verification). The resolver maps any `root_key_id` to a
        // deterministic 32-byte dummy root key — the actual
        // signature byte pattern that passes `DummySig::verify` is
        // owned by the cert's `sig_bytes` field below. A dialer that
        // produces a cert whose `sig_bytes` does not satisfy the
        // configured signature suite (e.g. a non-test-grade or
        // tampered cert) is rejected with `NetError::KeySchedule`
        // before the AEAD session is established. Production PQC
        // root key distribution is tracked separately under C4.
        // Run 037: under `PqcStaticRoot` + `Required`/`Optional`,
        // install a `TrustedClientRoots` resolver that consults the
        // operator-configured PQC root pks. Unknown `root_key_id` ⇒
        // `parse_and_verify_client_cert` returns
        // `NetError::ClientCertInvalid("untrusted root")` — fail
        // closed, no silent fallback.
        //
        // Pre-Run-037 / test-grade default: keep the deterministic
        // `Some(vec![0x01u8; 32])` resolver that the existing B12
        // tests exercise, so all those tests remain bit-for-bit.
        //
        // The two paths are mutually exclusive: when PQC is active,
        // the registered signature suite is real ML-DSA-44 and the
        // dummy 32-byte resolver pk would not pass verification
        // anyway; when PQC is inactive, the registered signature
        // suite is the always-true DummySig and any resolver pk is
        // accepted.
        let trusted_client_roots = match (mutual_auth_mode, self.pqc_root_config.as_ref()) {
            (MutualAuthMode::Required | MutualAuthMode::Optional, Some(cfg))
                if matches!(cfg.mode, PqcRootMode::PqcStaticRoot) =>
            {
                let cfg = cfg.clone();
                Some(TrustedClientRoots::new(move |root_key_id: &[u8; 32]| {
                    cfg.lookup_root_pk(root_key_id).map(|r| r.root_pk.clone())
                }))
            }
            (MutualAuthMode::Required | MutualAuthMode::Optional, _) => {
                Some(TrustedClientRoots::new(|_root_key_id: &[u8; 32]| {
                    Some(vec![0x01u8; 32])
                }))
            }
            (MutualAuthMode::Disabled, _) => None,
        };

        // Run 044 — observability-only: install the cert-verify metrics
        // sink ONLY on the production-honest PQC path (mutual auth on +
        // `PqcRootMode::PqcStaticRoot`). The test-grade DummySig path
        // intentionally leaves the sink `None` so the
        // `qbind_p2p_pqc_cert_verify_*` family is never bumped by
        // non-PQC verifications — preserving the contract that those
        // counters reflect real PQC delegation-cert verification events
        // only. When `self.p2p_metrics` is also unset (builder-only
        // tests / non-binary callers), the sink stays `None` and the
        // handshake path is the zero-cost no-op path.
        let cert_verify_metrics: Option<Arc<dyn qbind_net::CertVerifyMetricsSink>> = match (
            mutual_auth_mode,
            self.pqc_root_config.as_ref(),
            self.p2p_metrics.as_ref(),
        ) {
            (
                MutualAuthMode::Required | MutualAuthMode::Optional,
                Some(cfg),
                Some(p2p_metrics),
            ) if matches!(cfg.mode, PqcRootMode::PqcStaticRoot) => {
                let arc_metrics: Arc<dyn qbind_net::CertVerifyMetricsSink> = p2p_metrics.clone();
                Some(arc_metrics)
            }
            _ => None,
        };

        // Run 052 — leaf-level certificate revocation enforcement:
        // wrap the configured revoked-leaf fingerprint set into a
        // `LeafCertRevocationList` ONLY on the production-honest PQC
        // path (mutual auth on + `PqcRootMode::PqcStaticRoot`).
        // The test-grade DummySig path intentionally leaves the
        // revocation list `None` so the legacy B12 / pre-Run-037
        // tests remain bit-for-bit unchanged. When no revocations are
        // configured (`with_pqc_leaf_revocations` not called, or the
        // bundle's active leaf-revocation set is empty), the list is
        // also left `None` so the handshake takes the zero-cost no-op
        // path (preserves Run 050/051 behaviour).
        let leaf_cert_revocations: Option<LeafCertRevocationList> = match (
            mutual_auth_mode,
            self.pqc_root_config.as_ref(),
            self.pqc_revoked_leaf_fingerprints.as_ref(),
        ) {
            (
                MutualAuthMode::Required | MutualAuthMode::Optional,
                Some(cfg),
                Some(revoked_set),
            ) if matches!(cfg.mode, PqcRootMode::PqcStaticRoot) && !revoked_set.is_empty() => {
                let active_count = revoked_set.len();
                let revoked_set_for_closure = revoked_set.clone();
                Some(LeafCertRevocationList::new(
                    active_count,
                    move |fp: &[u8; 32]| revoked_set_for_closure.contains(fp),
                ))
            }
            _ => None,
        };

        // Create handshake configs
        let client_handshake_cfg = ClientHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto: crypto.clone(),
            peer_root_network_pk: root_network_pk.clone(),
            kem_metrics: None,
            local_delegation_cert: local_client_cert,
            cert_verify_metrics: cert_verify_metrics.clone(),
            leaf_cert_revocations: leaf_cert_revocations.clone(),
        };

        let server_handshake_cfg = ServerHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto,
            local_root_network_pk: root_network_pk,
            local_delegation_cert: cert_bytes,
            local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk_final)),
            kem_metrics: None,
            cookie_config: None,
            local_validator_id: validator_id_bytes,
            mutual_auth_mode,
            trusted_client_roots,
            cert_verify_metrics,
            leaf_cert_revocations,
        };

        // Create connection configs
        //
        // B7 note: `client_cfg.peer_kem_pk` is set to the *local* KEM
        // public key here only as a placeholder for the no-static-peers
        // case (single-validator / smoke / legacy tests, where no dial
        // ever happens). On the multi-validator binary path, this
        // default is overridden per-peer at dial time via
        // `TcpKemTlsP2pService::set_peer_kem_pk_overrides(...)` so that
        // each outbound dial actually carries the *peer's* KEM public
        // key — which is the prerequisite for the KEMTLS handshake to
        // complete. See `build()` above and
        // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md` §13.
        let client_cfg = ClientConnectionConfig {
            handshake_config: client_handshake_cfg,
            client_random,
            validator_id: validator_id_bytes,
            peer_kem_pk: server_kem_pk_final,
        };

        let server_cfg = ServerConnectionConfig {
            handshake_config: server_handshake_cfg,
            server_random,
        };

        Ok((server_cfg, client_cfg))
    }

    /// Create a dummy delegation certificate for testing.
    fn make_dummy_delegation_cert(
        &self,
        validator_id: [u8; 32],
        root_key_id: [u8; 32],
        leaf_kem_pk: Vec<u8>,
        kem_suite_id: u8,
        sig_suite_id: u8,
    ) -> qbind_wire::net::NetworkDelegationCert {
        qbind_wire::net::NetworkDelegationCert {
            version: 1,
            validator_id,
            root_key_id,
            leaf_kem_suite_id: kem_suite_id,
            leaf_kem_pk,
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: vec![],
            sig_suite_id,
            sig_bytes: vec![0u8; 64],
        }
    }

    /// Shutdown the P2P node.
    ///
    /// This method gracefully shuts down all P2P components:
    /// 1. Stops the demuxer loop
    /// 2. Stops the P2P transport service
    ///
    /// # Arguments
    ///
    /// * `context` - The P2P node context to shutdown
    pub async fn shutdown(context: P2pNodeContext) -> Result<(), P2pNodeError> {
        println!(
            "[T175] Shutting down P2P node for validator {:?}",
            context.validator_id
        );

        // Abort the demuxer task
        context.demuxer_handle.abort();

        // Wait for demuxer to finish (with timeout)
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), context.demuxer_handle).await;

        // Note: TcpKemTlsP2pService shutdown is handled via its internal
        // shutdown channel when it's dropped

        println!("[T175] P2P node shutdown complete");
        Ok(())
    }
}

// ============================================================================
// SimpleValidatorNodeMapping Extension
// ============================================================================

impl SimpleValidatorNodeMapping {
    /// Derive a NodeId from a validator index (public helper for T175).
    ///
    /// **B7**: thin public re-export of the private
    /// `node_id_from_validator_index` rule so callers can compute the
    /// same NodeId the consensus mapping uses without going through a
    /// full mapping instance. Always agrees with
    /// `derive_test_node_id_from_validator_id`.
    pub fn node_id_from_index(index: usize) -> NodeId {
        derive_test_node_id_from_validator_id(index as u64)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus_net_p2p::ValidatorNodeMapping;
    use crate::node_config::{
        DagCouplingMode, MempoolMode, NetworkMode, NetworkTransportConfig, SignerMode,
    };
    use qbind_ledger::{FeeDistributionPolicy, MonetaryMode, SeigniorageSplit};
    use qbind_types::NetworkEnvironment;

    fn make_test_config() -> NodeConfig {
        NodeConfig {
            environment: NetworkEnvironment::Testnet,
            execution_profile: crate::node_config::ExecutionProfile::VmV0,
            data_dir: None,
            network: NetworkTransportConfig {
                enable_p2p: true,
                max_outbound: 4,
                max_inbound: 8,
                gossip_fanout: 3,
                listen_addr: Some("127.0.0.1:0".to_string()),
                advertised_addr: None,
                static_peers: vec![],
                static_peer_consensus_keys: Vec::new(),
                // T205: Discovery and liveness defaults for test
                discovery_enabled: false,
                discovery_interval_secs: 30,
                max_known_peers: 200,
                target_outbound_peers: 8,
                liveness_probe_interval_secs: 30,
                liveness_failure_threshold: 3,
                liveness_min_score: 30,
                // T206: Diversity defaults for test
                diversity_mode: crate::p2p_diversity::DiversityEnforcementMode::Off,
                max_peers_per_ipv4_prefix24: 2,
                max_peers_per_ipv4_prefix16: 8,
                min_outbound_diversity_buckets: 4,
                max_single_bucket_fraction_bps: 2500,
            },
            network_mode: NetworkMode::P2p,
            // T180 fields
            gas_enabled: false,
            enable_fee_priority: false,
            mempool_mode: MempoolMode::Fifo,
            dag_availability_enabled: false,
            // T189 field
            dag_coupling_mode: DagCouplingMode::Off,
            // T186 field
            stage_b_enabled: false,
            // T193 field
            fee_distribution_policy: FeeDistributionPolicy::burn_only(),
            // T197 fields
            monetary_mode: MonetaryMode::Off,
            monetary_accounts: None,
            seigniorage_split: SeigniorageSplit::default(),
            // T208 field
            state_retention: crate::node_config::StateRetentionConfig::disabled(),
            // T215 fields
            snapshot_config: crate::node_config::SnapshotConfig::disabled(),
            fast_sync_config: crate::node_config::FastSyncConfig::disabled(),
            // T210 fields
            signer_mode: SignerMode::LoopbackTesting,
            signer_keystore_path: None,
            remote_signer_url: None,
            // M10.1: Remote signer KEMTLS cert paths
            remote_signer_cert_path: None,
            remote_signer_client_cert_path: None,
            remote_signer_client_key_path: None,
            hsm_config_path: None,
            // T214 field
            signer_failure_mode: crate::node_config::SignerFailureMode::ExitOnFailure,
            // T218 field
            mempool_dos: crate::node_config::MempoolDosConfig::devnet_default(),
            // T219 field
            mempool_eviction: crate::node_config::MempoolEvictionConfig::devnet_default(),
            // T226 fields
            p2p_discovery: crate::node_config::P2pDiscoveryConfig::devnet_default(),
            p2p_liveness: crate::node_config::P2pLivenessConfig::devnet_default(),
            // T231 field
            p2p_anti_eclipse: Some(crate::node_config::P2pAntiEclipseConfig::devnet_default()),
            // T229 field
            slashing: crate::node_config::SlashingConfig::devnet_default(),
            // M2 field
            validator_stake: crate::node_config::ValidatorStakeConfig::devnet_default(),
            // T232 field
            genesis_source: crate::node_config::GenesisSourceConfig::devnet_default(),
            expected_genesis_hash: None,
        }
    }

    #[test]
    fn test_p2p_node_builder_new() {
        let builder = P2pNodeBuilder::new();
        assert_eq!(builder.num_validators, 4);
    }

    #[test]
    fn test_p2p_node_builder_with_num_validators() {
        let builder = P2pNodeBuilder::new().with_num_validators(7);
        assert_eq!(builder.num_validators, 7);
    }

    #[test]
    fn test_simple_validator_node_mapping_node_id() {
        let node_id_0 = SimpleValidatorNodeMapping::node_id_from_index(0);
        let node_id_1 = SimpleValidatorNodeMapping::node_id_from_index(1);

        assert_ne!(node_id_0, node_id_1);
    }

    #[tokio::test]
    async fn test_p2p_node_builder_build() {
        let config = make_test_config();
        let builder = P2pNodeBuilder::new().with_num_validators(4);

        let result = builder.build(&config, 0).await;
        assert!(
            result.is_ok(),
            "Should build P2P node context: {:?}",
            result.err()
        );

        let context = result.unwrap();
        assert_eq!(context.validator_id.as_u64(), 0);
        // B7: empty static_peers ⇒ no peer-validator entries on the dialer side.
        assert_eq!(context.peer_validator_map.read().len(), 0);

        // Shutdown
        let shutdown_result = P2pNodeBuilder::shutdown(context).await;
        assert!(shutdown_result.is_ok());
    }

    // ====================================================================
    // B7 — test-grade KEMTLS bring-up + peer-validator identity closure
    // ====================================================================

    /// B7.A: distinct validator ids produce distinct test-grade KEM
    /// public keys and the listener's own keypair matches the one the
    /// dialer would pick when dialing it. This is the smallest
    /// invariant whose violation caused Run 005 to fail.
    #[test]
    fn b7_test_kem_keypair_is_distinct_per_validator_and_round_trips() {
        let (pk0, sk0) = derive_test_kem_keypair_from_validator_id(0);
        let (pk1, _sk1) = derive_test_kem_keypair_from_validator_id(1);
        let (pk2, _sk2) = derive_test_kem_keypair_from_validator_id(2);

        // Distinct validators => distinct KEM public keys (this is what
        // the dialer side must derive when targeting a specific peer).
        assert_ne!(pk0, pk1, "vid 0 and vid 1 must have distinct KEM pks");
        assert_ne!(pk1, pk2, "vid 1 and vid 2 must have distinct KEM pks");

        // Round-trip: the listener for vid `i` derives the same `(pk, sk)`
        // pair every dialer expects to encapsulate to.
        let (pk0_again, sk0_again) = derive_test_kem_keypair_from_validator_id(0);
        assert_eq!(pk0, pk0_again);
        assert_eq!(sk0, sk0_again);

        // The keypair shape must be 32B/32B (matches `DummyKem` and
        // `qbind_net::ClientConnectionConfig.peer_kem_pk` expectations).
        assert_eq!(pk0.len(), 32);
        assert_eq!(sk0.len(), 32);
    }

    /// B7.B: every layer that converts ValidatorId↔NodeId must agree.
    /// The dialer derives the peer NodeId via
    /// `derive_node_id_from_pubkey(peer_kem_pk)`; the consensus mapping
    /// must produce the same NodeId for the same validator id, otherwise
    /// `send_to(ValidatorId)` cannot find the actually-registered
    /// outbound connection. (Pre-B7 these two derivations disagreed —
    /// `SimpleValidatorNodeMapping` packed the index into the first 8
    /// bytes while the dialer used sha3-of-pk.)
    #[test]
    fn b7_node_id_derivation_agrees_across_layers() {
        for vid in 0u64..4u64 {
            let from_helper = derive_test_node_id_from_validator_id(vid);
            let from_pubkey = {
                let (pk, _) = derive_test_kem_keypair_from_validator_id(vid);
                NodeId::new(qbind_hash::derive_node_id_from_pubkey(&pk))
            };
            assert_eq!(from_helper, from_pubkey, "helper vs pubkey for vid {}", vid);

            // Same NodeId comes back from the public mapping helper
            // and from the SimpleValidatorNodeMapping forward lookup.
            let from_mapping_static = SimpleValidatorNodeMapping::node_id_from_index(vid as usize);
            let mapping = SimpleValidatorNodeMapping::new(4);
            let from_mapping_lookup = mapping.get_node_id(ValidatorId::new(vid)).unwrap();
            assert_eq!(from_mapping_static, from_helper);
            assert_eq!(from_mapping_lookup, from_helper);
        }
    }

    /// B7.C: `parse_peer_spec` accepts both syntaxes and rejects malformed input.
    #[test]
    fn b7_parse_peer_spec_accepts_both_syntaxes() {
        let (vid, addr) = parse_peer_spec("127.0.0.1:19001").unwrap();
        assert_eq!(vid, None);
        assert_eq!(addr, "127.0.0.1:19001");

        let (vid, addr) = parse_peer_spec("1@127.0.0.1:19001").unwrap();
        assert_eq!(vid, Some(1));
        assert_eq!(addr, "127.0.0.1:19001");

        let (vid, addr) = parse_peer_spec("42@hostname:9000").unwrap();
        assert_eq!(vid, Some(42));
        assert_eq!(addr, "hostname:9000");

        // Malformed: non-numeric vid, or empty addr
        assert!(parse_peer_spec("foo@127.0.0.1:1").is_err());
        assert!(parse_peer_spec("1@").is_err());
    }

    /// B7.D: a multi-validator P2P config that uses bare-addr static_peers
    /// (no `vid@`) is rejected with a clear error rather than silently
    /// producing a broken handshake — this is the directly-reported Run
    /// 005 failure mode in static form.
    #[tokio::test]
    async fn b7_multi_validator_bare_addr_peers_are_rejected() {
        let mut config = make_test_config();
        config.network.static_peers =
            vec!["127.0.0.1:19101".to_string(), "127.0.0.1:19102".to_string()];
        let builder = P2pNodeBuilder::new().with_num_validators(3);
        let err = builder
            .build(&config, 0)
            .await
            .expect_err("must reject bare-addr peers in multi-validator path");
        let msg = format!("{}", err);
        assert!(
            msg.contains("vid@addr"),
            "error must mention vid@addr: {}",
            msg
        );
    }

    /// B7.E: `vid@addr` static peers produce non-empty per-peer
    /// overrides AND a populated `peer_validator_map` whose entries
    /// agree with `SimpleValidatorNodeMapping`.
    #[tokio::test]
    async fn b7_vid_at_addr_peers_close_validator_identity() {
        let mut config = make_test_config();
        // Two peer specs targeting bogus addresses; we never actually
        // start `start()`-time dials succeed because nothing is listening,
        // but `build()` configures the overrides + mapping *before*
        // attempting any dial, and `start()` swallows individual dial
        // failures (`[P2P] Failed to dial …`) so `build()` returns Ok.
        config.network.static_peers =
            vec!["1@127.0.0.1:1".to_string(), "2@127.0.0.1:2".to_string()];
        let builder = P2pNodeBuilder::new().with_num_validators(3);
        let context = builder
            .build(&config, 0)
            .await
            .expect("build with vid@addr peers must succeed");

        // Identity closure: peer-validator map is populated for both peers.
        let map = context.peer_validator_map.read();
        assert_eq!(map.len(), 2);
        // The PeerId key is the first-8-bytes projection of the
        // deterministic NodeId of the peer's validator. Spot-check that
        // ValidatorId(1) and ValidatorId(2) are both present as values
        // and that they map back through SimpleValidatorNodeMapping to
        // the same underlying NodeId.
        let mut seen: Vec<u64> = map.iter().map(|(_, v)| v.as_u64()).collect();
        seen.sort();
        assert_eq!(seen, vec![1, 2]);

        let mapping = SimpleValidatorNodeMapping::new(3);
        for vid in [1u64, 2u64] {
            let expected_node_id = mapping.get_node_id(ValidatorId::new(vid)).unwrap();
            // `derive_test_node_id_from_validator_id` agrees, which is
            // exactly what was broken before B7 (Run 005).
            assert_eq!(expected_node_id, derive_test_node_id_from_validator_id(vid));
        }
        drop(map);

        let _ = P2pNodeBuilder::shutdown(context).await;
    }

    /// B7.F: a malformed `vid@addr` spec (e.g. non-numeric vid) is
    /// surfaced as a `P2pNodeError::Config` from `build()` rather than
    /// being silently dropped or causing a panic later.
    #[tokio::test]
    async fn b7_malformed_vid_at_addr_is_rejected_with_clear_error() {
        let mut config = make_test_config();
        config.network.static_peers = vec!["bogus@127.0.0.1:1".to_string()];
        let builder = P2pNodeBuilder::new().with_num_validators(2);
        let err = builder
            .build(&config, 0)
            .await
            .expect_err("malformed vid@addr must error");
        let msg = format!("{}", err);
        assert!(
            msg.contains("invalid validator-id"),
            "error must explain the parse failure: {}",
            msg
        );
    }
}