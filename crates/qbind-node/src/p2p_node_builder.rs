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

use std::collections::HashMap;
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
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, MutualAuthMode,
    ServerConnectionConfig, ServerHandshakeConfig,
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
        let node_id = derive_test_node_id_from_validator_id(validator_id.as_u64());

        // Create crypto provider (using test crypto for T175)
        let kem_suite_id: u8 = 1;
        let aead_suite_id: u8 = 2;
        let sig_suite_id: u8 = 3;
        let crypto = make_test_crypto_provider(kem_suite_id, aead_suite_id, sig_suite_id);

        // Create connection configs
        let (server_cfg, client_cfg) = self.create_connection_configs(
            validator_id,
            crypto.clone(),
            kem_suite_id,
            aead_suite_id,
            sig_suite_id,
        );

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
        let mut peer_validator_map = PeerValidatorMap::new();
        let mut had_unspec_peer = false;
        for spec in &config.network.static_peers {
            let (peer_vid_opt, addr) = parse_peer_spec(spec)
                .map_err(|e| P2pNodeError::Config(e))?;
            if let Some(peer_vid) = peer_vid_opt {
                let (peer_pk, _peer_sk) =
                    derive_test_kem_keypair_from_validator_id(peer_vid);
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
                let peer_node_id = NodeId::new(
                    qbind_hash::derive_node_id_from_pubkey(&peer_pk),
                );
                let peer_id_u64 = u64::from_le_bytes(
                    peer_node_id.as_bytes()[..8].try_into().unwrap_or([0u8; 8]),
                );
                peer_validator_map.insert(
                    crate::peer::PeerId(peer_id_u64),
                    ValidatorId::new(peer_vid),
                );
            } else {
                had_unspec_peer = true;
            }
        }
        // For the multi-validator binary path, refuse to silently dial a
        // bare `addr` (no `vid@`) because we cannot then derive the peer's
        // test-grade KEM public key, which is exactly the Run 005 failure
        // mode. Single-validator / no-peer setups never hit this branch.
        if had_unspec_peer && peer_kem_pk_overrides.is_empty()
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
        let mut stripped_peers: Vec<String> = Vec::with_capacity(transport_config.static_peers.len());
        for spec in &transport_config.static_peers {
            let (_vid_opt, addr) = parse_peer_spec(spec)
                .map_err(|e| P2pNodeError::Config(e))?;
            stripped_peers.push(addr);
        }
        transport_config.static_peers = stripped_peers;

        let mut p2p_service = TcpKemTlsP2pService::new(
            node_id,
            transport_config,
            crypto,
            server_cfg,
            client_cfg,
        )?;
        // B7: install per-peer KEM-pk + validator-id overrides before `start()` dials.
        if !peer_kem_pk_overrides.is_empty() {
            p2p_service.set_peer_kem_pk_overrides(peer_kem_pk_overrides);
            p2p_service.set_peer_validator_id_overrides(peer_vid_overrides);
        }

        // B8: install the test-grade listener-side identity resolver.
        //
        // The resolver inspects the dialer's already-on-the-wire
        // `client_random` (deterministically prefixed by
        // `qbind-client-<N>` in `create_connection_configs` below) to
        // recover the dialer's local validator id `N`, then derives the
        // SAME deterministic NodeId the dialer side already registers
        // its own connection under (via
        // `derive_test_node_id_from_validator_id`). This closes the
        // listener-side gap that DevNet Evidence Run 006 documented:
        // accepted inbound sessions are now bound to the validator-
        // derived deterministic NodeId rather than to a temporary
        // session NodeId, so `send_to(ValidatorId)` resolves to a
        // registered transport session in BOTH directions.
        //
        // **Security semantics:** test-grade only. Under the current
        // `MutualAuthMode::Disabled` configuration the dialer's
        // `client_random` is self-asserted; production-grade peer
        // identity binding still requires mutual KEMTLS auth and is
        // tracked under C4 in `docs/whitepaper/contradiction.md`. This
        // is strictly no weaker than the pre-B8 temporary-NodeId path
        // — it just gives that NodeId a deterministic, routable shape
        // when the dialer cooperates.
        //
        // If the resolver returns `None` (e.g. an unrelated tool
        // connects with a non-`qbind-client-N` `client_random`), the
        // transport falls back to the legacy temporary-session-NodeId
        // path automatically. No silent override.
        p2p_service.set_inbound_identity_resolver(Arc::new(
            |peer_init: &crate::secure_channel::AcceptedPeerInit| -> Option<NodeId> {
                let vid =
                    parse_test_validator_id_from_client_random(&peer_init.client_random)?;
                Some(derive_test_node_id_from_validator_id(vid))
            },
        ));

        // Start the service
        p2p_service.start().await?;

        let p2p_service = Arc::new(p2p_service);

        // Create metrics
        let metrics = Arc::new(P2pMetrics::new());

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
             peer_kem_overrides={}",
            validator_id,
            node_id,
            self.num_validators,
            peer_validator_map.len(),
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
    ) -> (ServerConnectionConfig, ClientConnectionConfig) {
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

        // Create a dummy delegation certificate
        let cert = self.make_dummy_delegation_cert(
            validator_id_bytes,
            root_key_id,
            server_kem_pk.clone(),
            kem_suite_id,
            sig_suite_id,
        );

        // Encode certificate
        use qbind_wire::io::WireEncode;
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);

        // Root network public key (dummy)
        let root_network_pk: Vec<u8> = vec![0u8; 32];

        // Random values for handshake
        let mut client_random = [0u8; 32];
        let client_name = format!("qbind-client-{}", validator_id.as_u64());
        client_random[..client_name.len().min(32)].copy_from_slice(client_name.as_bytes());

        let mut server_random = [0u8; 32];
        let server_name = format!("qbind-server-{}", validator_id.as_u64());
        server_random[..server_name.len().min(32)].copy_from_slice(server_name.as_bytes());

        // Create handshake configs
        let client_handshake_cfg = ClientHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto: crypto.clone(),
            peer_root_network_pk: root_network_pk.clone(),
            kem_metrics: None,
            local_delegation_cert: None, // M8: No client cert for backward compat tests
        };

        let server_handshake_cfg = ServerHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto,
            local_root_network_pk: root_network_pk,
            local_delegation_cert: cert_bytes,
            local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
            kem_metrics: None,
            cookie_config: None, // M6: Cookie protection not enforced in legacy test builder
            local_validator_id: validator_id_bytes,
            mutual_auth_mode: MutualAuthMode::Disabled, // M8: Disabled for backward compat tests
            trusted_client_roots: None,
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
            peer_kem_pk: server_kem_pk,
        };

        let server_cfg = ServerConnectionConfig {
            handshake_config: server_handshake_cfg,
            server_random,
        };

        (server_cfg, client_cfg)
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
        config.network.static_peers = vec![
            "127.0.0.1:19101".to_string(),
            "127.0.0.1:19102".to_string(),
        ];
        let builder = P2pNodeBuilder::new().with_num_validators(3);
        let err = builder
            .build(&config, 0)
            .await
            .expect_err("must reject bare-addr peers in multi-validator path");
        let msg = format!("{}", err);
        assert!(msg.contains("vid@addr"), "error must mention vid@addr: {}", msg);
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
        config.network.static_peers = vec![
            "1@127.0.0.1:1".to_string(),
            "2@127.0.0.1:2".to_string(),
        ];
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