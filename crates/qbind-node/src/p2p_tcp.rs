//! T172: TCP + KEMTLS P2P Transport Implementation
//!
//! This module provides `TcpKemTlsP2pService`, a minimal P2P transport service
//! that implements the `P2pService` trait using TCP and KEMTLS for encrypted
//! connections.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                    TcpKemTlsP2pService                          │
//! │                                                                 │
//! │  ┌───────────────┐         ┌───────────────────────┐            │
//! │  │  Listener     │────────▶│  Accept Loop          │            │
//! │  │  (tokio)      │         │  (KEMTLS handshake)   │            │
//! │  └───────────────┘         └───────────────────────┘            │
//! │                                     │                           │
//! │                                     ▼                           │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                   Per-Peer Handlers                      │   │
//! │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐         │   │
//! │  │  │ Read Loop  │  │ Read Loop  │  │ Read Loop  │         │   │
//! │  │  └──────┬─────┘  └──────┬─────┘  └──────┬─────┘         │   │
//! │  │         │                │                │              │   │
//! │  │         └────────────────┴────────────────┘              │   │
//! │  │                          │                               │   │
//! │  │                          ▼                               │   │
//! │  │            ┌─────────────────────────────┐              │   │
//! │  │            │  Inbound Channel (mpsc)     │              │   │
//! │  │            └──────────────┬──────────────┘              │   │
//! │  └───────────────────────────┼─────────────────────────────┘   │
//! │                              │                                  │
//! │                              ▼                                  │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │              subscribe() → Receiver<P2pMessage>         │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                                                                 │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                  Outbound Path                           │   │
//! │  │       broadcast() / send_to()                            │   │
//! │  │               │                                          │   │
//! │  │               ▼                                          │   │
//! │  │  ┌────────────────────────────────────────────────┐     │   │
//! │  │  │     Per-Peer Write Channels                    │     │   │
//! │  │  │     NodeId → mpsc::Sender<P2pMessage>          │     │   │
//! │  │  └──────────────────┬─────────────────────────────┘     │   │
//! │  │                     │                                   │   │
//! │  │                     ▼                                   │   │
//! │  │  ┌────────────┐  ┌────────────┐  ┌────────────┐        │   │
//! │  │  │ Write Loop │  │ Write Loop │  │ Write Loop │        │   │
//! │  │  └────────────┘  └────────────┘  └────────────┘        │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Framing
//!
//! Simple length-prefixed framing over KEMTLS:
//! - `u8 discriminator`: 0=Consensus, 1=Dag, 2=Control
//! - `u32 length`: payload length (big-endian)
//! - `[u8; length]`: serialized payload (bincode)
//!
//! # Static Peers
//!
//! At startup, the service:
//! 1. Binds to the configured `listen_addr`
//! 2. Dials all peers in the `static_peers` list
//! 3. Spawns read/write loops for each connection
//!
//! # Shutdown
//!
//! Graceful shutdown via a broadcast channel:
//! - All tasks listen for shutdown signal
//! - On shutdown, all connections are closed and tasks terminate

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::node_config::NetworkTransportConfig;
use crate::p2p::{NodeId, P2pMessage, P2pService};
use crate::secure_channel::{
    accept_kemtls_async_with_peer_init, connect_kemtls_async, AcceptedPeerInit, SecureChannelAsync,
};
use qbind_crypto::CryptoProvider;
use qbind_hash::{derive_node_id_from_pubkey, INBOUND_SESSION_DOMAIN_TAG};
use qbind_net::{ClientConnectionConfig, ServerConnectionConfig};

// ============================================================================
// Error Types
// ============================================================================

/// Error type for P2P transport operations.
#[derive(Debug)]
pub enum P2pTransportError {
    /// I/O error.
    Io(std::io::Error),
    /// Encoding/decoding error.
    Encoding(String),
    /// KEMTLS handshake error.
    Handshake(String),
    /// Configuration error.
    Config(String),
}

impl std::fmt::Display for P2pTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P2pTransportError::Io(e) => write!(f, "I/O error: {}", e),
            P2pTransportError::Encoding(msg) => write!(f, "Encoding error: {}", msg),
            P2pTransportError::Handshake(msg) => write!(f, "Handshake error: {}", msg),
            P2pTransportError::Config(msg) => write!(f, "Config error: {}", msg),
        }
    }
}

impl std::error::Error for P2pTransportError {}

impl From<std::io::Error> for P2pTransportError {
    fn from(e: std::io::Error) -> Self {
        P2pTransportError::Io(e)
    }
}

// ============================================================================
// Frame Encoding
// ============================================================================

/// Message discriminator constants for framing.
const DISCRIMINATOR_CONSENSUS: u8 = 0;
const DISCRIMINATOR_DAG: u8 = 1;
const DISCRIMINATOR_CONTROL: u8 = 2;

/// Encode a P2pMessage into a length-prefixed frame.
///
/// Format: discriminator (u8) || length (u32 BE) || payload (bincode)
fn encode_frame(msg: &P2pMessage) -> Result<Vec<u8>, P2pTransportError> {
    let (discriminator, payload) = match msg {
        P2pMessage::Consensus(_) => {
            let payload =
                bincode::serialize(&msg).map_err(|e| P2pTransportError::Encoding(e.to_string()))?;
            (DISCRIMINATOR_CONSENSUS, payload)
        }
        P2pMessage::Dag(_) => {
            let payload =
                bincode::serialize(&msg).map_err(|e| P2pTransportError::Encoding(e.to_string()))?;
            (DISCRIMINATOR_DAG, payload)
        }
        P2pMessage::Control(_) => {
            let payload =
                bincode::serialize(&msg).map_err(|e| P2pTransportError::Encoding(e.to_string()))?;
            (DISCRIMINATOR_CONTROL, payload)
        }
    };

    let len = payload.len() as u32;
    let mut frame = Vec::with_capacity(1 + 4 + payload.len());
    frame.push(discriminator);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);

    Ok(frame)
}

/// Decode a P2pMessage from a length-prefixed frame.
///
/// Expects: discriminator (u8) || length (u32 BE) || payload (bincode)
fn decode_frame(frame: &[u8]) -> Result<P2pMessage, P2pTransportError> {
    if frame.len() < 5 {
        return Err(P2pTransportError::Encoding("frame too short".to_string()));
    }

    let discriminator = frame[0];
    let len = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;

    if frame.len() < 5 + len {
        return Err(P2pTransportError::Encoding("frame truncated".to_string()));
    }

    let payload = &frame[5..5 + len];
    let msg: P2pMessage =
        bincode::deserialize(payload).map_err(|e| P2pTransportError::Encoding(e.to_string()))?;

    // Validate discriminator matches message type
    match (&msg, discriminator) {
        (P2pMessage::Consensus(_), DISCRIMINATOR_CONSENSUS) => Ok(msg),
        (P2pMessage::Dag(_), DISCRIMINATOR_DAG) => Ok(msg),
        (P2pMessage::Control(_), DISCRIMINATOR_CONTROL) => Ok(msg),
        _ => Err(P2pTransportError::Encoding(
            "discriminator mismatch".to_string(),
        )),
    }
}

// ============================================================================
// B8: Listener-side inbound identity resolver
// ============================================================================

/// Resolver for binding accepted inbound sessions to a deterministic
/// NodeId derived from the dialer's already-on-the-wire identity hints
/// (B8 — listener-side identity closure).
///
/// The closure is invoked after the KEMTLS handshake completes with the
/// dialer-supplied `AcceptedPeerInit` (containing `client_random` +
/// `validator_id`). If it returns `Some(node_id)`, the accepted session
/// is registered under that NodeId. If it returns `None`, the transport
/// falls back to the legacy temporary session-unique NodeId path
/// (preserving the pre-B8 behaviour for paths that don't install a
/// resolver).
///
/// **Security semantics:** test-grade only. The fields it consumes are
/// self-asserted by the dialer under `MutualAuthMode::Disabled`. See
/// `secure_channel::AcceptedPeerInit` and
/// `p2p_node_builder::parse_test_validator_id_from_client_random`.
pub type InboundIdentityResolver =
    Arc<dyn Fn(&AcceptedPeerInit) -> Option<NodeId> + Send + Sync>;

// ============================================================================
// B8: Initial-dial retry policy
// ============================================================================

/// Bounded retry policy applied by `TcpKemTlsP2pService::start` to each
/// configured static-peer initial dial (B8 — initial-dial retry).
///
/// Two `qbind-node` processes started with a stagger (e.g. node 0 starts
/// before node 1's listener is up) lose the initial dial with
/// `Connection refused`. Pre-B8 this was a single-shot attempt and the
/// dialer simply gave up, leaving the cluster in a one-direction-only
/// transport topology (DevNet Evidence Run 006 §10–§12).
///
/// The retry path is intentionally bounded:
/// - retries only the *initial* dial of each configured static peer;
/// - retries only on transient I/O errors that look like a startup race
///   (`ConnectionRefused`, `ConnectionReset`, `TimedOut`, `NotFound`,
///   address-not-available) — not on KEMTLS handshake errors;
/// - capped at `max_attempts` total attempts;
/// - exponential backoff capped at `max_backoff`;
/// - logs each retry and the final outcome.
///
/// This is NOT a general peer-management redesign: long-running peer
/// reconnect / churn handling stays out of scope. See B8 in C4
/// (`docs/whitepaper/contradiction.md`).
#[derive(Clone, Debug)]
pub struct DialRetryPolicy {
    /// Maximum number of attempts (including the first attempt).
    pub max_attempts: u32,
    /// Initial backoff between retries.
    pub initial_backoff: Duration,
    /// Multiplier applied to the backoff after each failed attempt.
    pub backoff_multiplier: u32,
    /// Cap on the per-step backoff so we never wait too long on retry.
    pub max_backoff: Duration,
}

impl Default for DialRetryPolicy {
    /// Default policy suitable for DevNet evidence runs:
    /// 8 attempts with backoff sequence `{100, 200, 400, 800, 1000,
    /// 1000, 1000, 1000}` ms = ~5.5 s of cumulative *backoff* between
    /// attempts (the wall-clock duration before the dialer gives up
    /// is this plus the per-attempt TCP connect / KEMTLS handshake
    /// time, which is typically dominated by the
    /// `Connection refused` fast-path).
    fn default() -> Self {
        Self {
            max_attempts: 8,
            initial_backoff: Duration::from_millis(100),
            backoff_multiplier: 2,
            max_backoff: Duration::from_millis(1000),
        }
    }
}

impl DialRetryPolicy {
    /// A "no retry" policy: behaves exactly like the pre-B8 single-shot dial.
    /// Useful for tests that want to pin the legacy behaviour.
    pub fn no_retry() -> Self {
        Self {
            max_attempts: 1,
            initial_backoff: Duration::from_millis(0),
            backoff_multiplier: 1,
            max_backoff: Duration::from_millis(0),
        }
    }
}

/// Classify whether a dial error should be retried under the B8
/// initial-dial retry policy.
///
/// We only retry transient TCP-level errors that are characteristic of
/// a startup race against a peer listener that has not yet bound
/// (`ConnectionRefused`, `ConnectionReset`, `TimedOut`,
/// `AddrNotAvailable`, `NotFound`). Handshake-level failures and
/// configuration errors are NOT retried — those are real bugs and
/// retrying would just produce noisy churn.
fn is_transient_dial_error(err: &P2pTransportError) -> bool {
    match err {
        P2pTransportError::Io(io_err) => matches!(
            io_err.kind(),
            std::io::ErrorKind::ConnectionRefused
                | std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::AddrNotAvailable
                | std::io::ErrorKind::NotFound
        ),
        // Handshake / encoding / config errors are not transient.
        _ => false,
    }
}

// ============================================================================
// Peer Connection State
// ============================================================================

/// State for a single peer connection.
struct PeerConnection {
    /// Remote peer's NodeId.
    #[allow(dead_code)]
    node_id: NodeId,
    /// Channel for sending outbound messages to this peer.
    tx: mpsc::Sender<P2pMessage>,
    /// Task handle for the write loop.
    write_handle: JoinHandle<()>,
    /// Task handle for the read loop.
    read_handle: JoinHandle<()>,
}

impl PeerConnection {
    /// Shutdown the peer connection gracefully.
    async fn shutdown(self) {
        // Close the write channel
        drop(self.tx);

        // Wait for tasks to complete
        let _ = self.write_handle.await;
        let _ = self.read_handle.await;
    }
}

// ============================================================================
// TcpKemTlsP2pService
// ============================================================================

/// TCP + KEMTLS P2P transport service (T172).
///
/// This service implements the `P2pService` trait and provides:
/// - Static peer connections via TCP + KEMTLS
/// - Simple length-prefixed framing
/// - Broadcast and direct messaging
/// - Subscription to inbound messages
///
/// # NodeId Derivation (M7)
///
/// **Outbound connections**: NodeId is derived from the peer server's KEM public
/// key via domain-separated SHA3-256: `node_id = sha3_256("QBIND:nodeid:v1" || peer_kem_pk)`.
/// This provides cryptographic binding between the NodeId and the KEMTLS identity.
///
/// **Inbound connections**: The current KEMTLS-PDK protocol does not include client
/// certificate exchange, so the connecting client's identity cannot be cryptographically
/// derived from the handshake alone. Inbound connections use a session-unique temporary
/// identifier until proper identity is established through application-layer protocols
/// (e.g., the first consensus message from the peer reveals their validator identity).
pub struct TcpKemTlsP2pService {
    /// Local NodeId.
    local_node_id: NodeId,
    /// Configuration.
    config: NetworkTransportConfig,
    /// Connected peers.
    peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
    /// Inbound message channel (sender).
    inbound_tx: mpsc::Sender<P2pMessage>,
    /// Inbound message channel (receiver) for cloning.
    inbound_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<P2pMessage>>>,
    /// Shutdown signal broadcaster.
    shutdown_tx: broadcast::Sender<()>,
    /// Listener task handle (optional).
    listener_handle: Option<JoinHandle<()>>,
    /// Crypto provider (for KEMTLS).
    #[allow(dead_code)]
    crypto: Arc<dyn CryptoProvider>,
    /// Server KEMTLS config.
    server_cfg: ServerConnectionConfig,
    /// Client KEMTLS config template.
    client_cfg: ClientConnectionConfig,
    /// Connection counter for metrics.
    connections_current: Arc<AtomicU64>,
    /// Bytes sent counter.
    bytes_sent: Arc<AtomicU64>,
    /// Bytes received counter.
    bytes_received: Arc<AtomicU64>,
    /// Inbound session counter for generating unique temporary NodeIds (M7).
    inbound_session_counter: Arc<AtomicU64>,
    /// B7: per-peer KEM public key overrides keyed by static-peer address.
    ///
    /// When `dial_peer(addr)` finds an entry here, it clones `client_cfg`
    /// and replaces `peer_kem_pk` with the per-peer value before handing
    /// the config to `connect_kemtls_async`. This is the smallest honest
    /// fix to the Run 005 KEMTLS bring-up failure: each side now dials
    /// with the *peer's* KEM public key rather than its own. The dialer's
    /// resulting `NodeId = sha3_256_tagged("QBIND:nodeid:v1", peer_kem_pk)`
    /// then matches the deterministic NodeId every other layer derives for
    /// that validator (see `consensus_net_p2p::SimpleValidatorNodeMapping`
    /// and `p2p_node_builder::derive_test_node_id_from_validator_id`).
    ///
    /// Empty by default — the no-static-peers / single-validator path is
    /// unaffected. Set via `set_peer_kem_pk_overrides`.
    peer_kem_pk_overrides: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    /// B7: per-peer expected validator id overrides keyed by static-peer
    /// address.
    ///
    /// The KEMTLS-PDK protocol verifies that the server's delegation
    /// cert's `validator_id` equals the value the client put in its
    /// `ClientInit.validator_id` (i.e., "the validator I expect to be
    /// connecting to" — see `qbind_net::connection::ClientConnectionConfig`
    /// docs and `qbind_net::handshake::handle_server_accept`). When
    /// `dial_peer(addr)` finds an entry here, it also overrides
    /// `client_cfg.validator_id` so this check passes. Without it the
    /// dialer always sends its own local validator id and the handshake
    /// fails with `client handle_server_accept failed` even after
    /// `peer_kem_pk` is correct.
    peer_validator_id_overrides: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    /// B8: optional resolver that maps an accepted dialer's
    /// `AcceptedPeerInit` to a deterministic NodeId.
    ///
    /// When present and returning `Some(node_id)`, the listener
    /// registers the accepted session under `node_id` instead of a
    /// fresh temporary session-unique NodeId. When absent or returning
    /// `None`, the legacy temporary-session-NodeId behaviour is
    /// preserved (no silent override).
    inbound_identity_resolver: Arc<RwLock<Option<InboundIdentityResolver>>>,
    /// B8: bounded retry policy applied to each configured static-peer
    /// initial dial.
    dial_retry_policy: Arc<RwLock<DialRetryPolicy>>,
    /// B8: handles for background per-peer initial-dial-with-retry tasks
    /// spawned by `start()`. Tracked so `shutdown()` can abort them
    /// cleanly and so tests can observe completion.
    dial_handles: Arc<RwLock<Vec<JoinHandle<()>>>>,
}

impl std::fmt::Debug for TcpKemTlsP2pService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpKemTlsP2pService")
            .field("local_node_id", &self.local_node_id)
            .field("config", &self.config)
            .field("peer_count", &self.peers.read().len())
            .finish()
    }
}

impl TcpKemTlsP2pService {
    /// Create a new TCP + KEMTLS P2P service.
    ///
    /// This does NOT start the service; call `start()` to begin listening and dialing.
    pub fn new(
        local_node_id: NodeId,
        config: NetworkTransportConfig,
        crypto: Arc<dyn CryptoProvider>,
        server_cfg: ServerConnectionConfig,
        client_cfg: ClientConnectionConfig,
    ) -> Result<Self, P2pTransportError> {
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let (shutdown_tx, _) = broadcast::channel(16);

        Ok(Self {
            local_node_id,
            config,
            peers: Arc::new(RwLock::new(HashMap::new())),
            inbound_tx,
            inbound_rx: Arc::new(tokio::sync::Mutex::new(inbound_rx)),
            shutdown_tx,
            listener_handle: None,
            crypto,
            server_cfg,
            client_cfg,
            connections_current: Arc::new(AtomicU64::new(0)),
            bytes_sent: Arc::new(AtomicU64::new(0)),
            bytes_received: Arc::new(AtomicU64::new(0)),
            inbound_session_counter: Arc::new(AtomicU64::new(0)),
            peer_kem_pk_overrides: Arc::new(RwLock::new(HashMap::new())),
            peer_validator_id_overrides: Arc::new(RwLock::new(HashMap::new())),
            inbound_identity_resolver: Arc::new(RwLock::new(None)),
            dial_retry_policy: Arc::new(RwLock::new(DialRetryPolicy::default())),
            dial_handles: Arc::new(RwLock::new(Vec::new())),
        })
    }

    /// B7: install per-peer KEM public key overrides used by `dial_peer`.
    ///
    /// Each entry maps a static-peer address (the same string from
    /// `NetworkTransportConfig::static_peers`, after stripping any
    /// `vid@` prefix) to the *peer's* test-grade KEM public key. When
    /// `start()` walks `static_peers` and dials each address, the dial
    /// path consults this map and uses the per-peer pk as
    /// `client_cfg.peer_kem_pk` so the KEMTLS handshake actually
    /// encapsulates to the correct peer. See
    /// `crates/qbind-node/src/p2p_node_builder.rs::P2pNodeBuilder::build`
    /// (the only current caller) and
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_005.md` §13.
    pub fn set_peer_kem_pk_overrides(&mut self, overrides: HashMap<String, Vec<u8>>) {
        let mut guard = self.peer_kem_pk_overrides.write();
        *guard = overrides;
    }

    /// B7: install per-peer expected-validator-id overrides used by `dial_peer`.
    ///
    /// Each entry maps a static-peer address (after `vid@` stripping)
    /// to the 32-byte `validator_id` field that the dialer should put
    /// in its `ClientInit` so the protocol-level check
    /// `delegation_cert.validator_id == client_init.validator_id`
    /// (`qbind_net::handshake::handle_server_accept`) passes. The
    /// dialer otherwise defaults to its own local validator id which
    /// would fail this check the moment two distinct binaries try to
    /// connect to each other.
    pub fn set_peer_validator_id_overrides(
        &mut self,
        overrides: HashMap<String, [u8; 32]>,
    ) {
        let mut guard = self.peer_validator_id_overrides.write();
        *guard = overrides;
    }

    /// B8: install a resolver that binds accepted inbound sessions to a
    /// deterministic NodeId derived from the dialer's already-on-the-wire
    /// identity hints.
    ///
    /// When the resolver returns `Some(node_id)` for an accepted
    /// session, the transport registers that session under `node_id`
    /// instead of a temporary session-unique NodeId — closing the
    /// listener-side identity-binding gap observed in DevNet Evidence
    /// Run 006.
    ///
    /// When `None` is returned (or no resolver is installed at all),
    /// the legacy temporary-NodeId path is preserved exactly. This is
    /// the default for paths that don't opt in to B8.
    pub fn set_inbound_identity_resolver(&mut self, resolver: InboundIdentityResolver) {
        let mut guard = self.inbound_identity_resolver.write();
        *guard = Some(resolver);
    }

    /// B8: install a bounded initial-dial retry policy.
    ///
    /// See [`DialRetryPolicy`] for semantics. The default is a small
    /// bounded retry suitable for DevNet evidence runs; tests can
    /// install [`DialRetryPolicy::no_retry`] to pin the legacy
    /// single-shot behaviour.
    pub fn set_dial_retry_policy(&mut self, policy: DialRetryPolicy) {
        *self.dial_retry_policy.write() = policy;
    }

    /// Start the P2P service: listen on configured address and dial static peers.
    ///
    /// **B8 — initial-dial retry**: each configured static-peer dial is
    /// spawned as a background task that retries transient TCP errors
    /// (most importantly `ConnectionRefused` from a stagger-started
    /// peer that hasn't yet bound its listener) under a bounded
    /// [`DialRetryPolicy`]. `start()` itself returns once the listener
    /// is up; the dial tasks proceed independently. This preserves the
    /// previous "no-static-peers / single-validator" behaviour exactly
    /// (no dial tasks are spawned in that case).
    pub async fn start(&mut self) -> Result<(), P2pTransportError> {
        // Start listener if configured
        if let Some(listen_addr) = &self.config.listen_addr {
            let listener = TcpListener::bind(listen_addr).await?;
            println!(
                "[P2P] Listening on {} (node_id={:?})",
                listen_addr, self.local_node_id
            );

            let listener_handle = self.spawn_accept_loop(listener);
            self.listener_handle = Some(listener_handle);
        }

        // Spawn a per-peer initial-dial-with-retry task for each
        // configured static peer. We do NOT block `start()` on these:
        // a stagger-started two-node cluster needs both sides' listeners
        // to be up before either dial can succeed, which is exactly
        // what motivated the retry path. Each task is bounded by
        // `DialRetryPolicy` and is tracked in `dial_handles` so
        // `shutdown()` can clean up if needed.
        for peer_addr in &self.config.static_peers {
            let peer_addr_owned = peer_addr.clone();
            let policy = self.dial_retry_policy.read().clone();
            let dialer = self.dialer_handle();
            let handle = tokio::spawn(async move {
                dialer.dial_with_retry(peer_addr_owned, policy).await;
            });
            self.dial_handles.write().push(handle);
        }

        Ok(())
    }

    /// Spawn the accept loop for inbound connections.
    fn spawn_accept_loop(&self, listener: TcpListener) -> JoinHandle<()> {
        let peers = Arc::clone(&self.peers);
        let inbound_tx = self.inbound_tx.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        let server_cfg = self.server_cfg.clone();
        let connections_current = Arc::clone(&self.connections_current);
        let bytes_received = Arc::clone(&self.bytes_received);
        let inbound_session_counter = Arc::clone(&self.inbound_session_counter);
        let inbound_identity_resolver = Arc::clone(&self.inbound_identity_resolver);

        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                println!("[P2P] Accepted connection from {}", peer_addr);

                                let peers_clone = Arc::clone(&peers);
                                let inbound_tx_clone = inbound_tx.clone();
                                let server_cfg_clone = server_cfg.clone();
                                let connections_current_clone = Arc::clone(&connections_current);
                                let bytes_received_clone = Arc::clone(&bytes_received);
                                let inbound_session_counter_clone = Arc::clone(&inbound_session_counter);
                                let resolver_clone = Arc::clone(&inbound_identity_resolver);

                                tokio::spawn(async move {
                                    if let Err(e) = Self::handle_inbound_connection(
                                        stream,
                                        peer_addr,
                                        server_cfg_clone,
                                        peers_clone,
                                        inbound_tx_clone,
                                        connections_current_clone,
                                        bytes_received_clone,
                                        inbound_session_counter_clone,
                                        resolver_clone,
                                    )
                                    .await
                                    {
                                        eprintln!("[P2P] Inbound connection error: {}", e);
                                    }
                                });
                            }
                            Err(e) => {
                                eprintln!("[P2P] Accept error: {}", e);
                            }
                        }
                    }
                }
            }
        })
    }

    /// Handle an inbound connection: KEMTLS handshake + spawn read/write loops.
    ///
    /// # Listener-side NodeId selection (M7 → B8)
    ///
    /// **Pre-B8 (M7) behaviour:** the test-grade KEMTLS-PDK path
    /// (`MutualAuthMode::Disabled`) does not include client cert
    /// exchange, so the dialer's identity cannot be derived from the
    /// handshake itself. Inbound sessions were therefore admitted under
    /// a temporary session-unique NodeId derived from
    /// `(local_validator_id || session_counter || peer_addr)`.
    ///
    /// **B8 — listener-side identity closure:** when an
    /// [`InboundIdentityResolver`] is installed via
    /// [`TcpKemTlsP2pService::set_inbound_identity_resolver`], it is
    /// consulted with the dialer-supplied `AcceptedPeerInit` (parsed
    /// from `ClientInit` by the `_with_peer_init` accept variant). If
    /// it returns `Some(deterministic_node_id)`, the accepted session
    /// is registered under that NodeId. Otherwise the legacy
    /// temporary-session-NodeId path is preserved exactly.
    ///
    /// This is the smallest honest fix to the Run 006 listener-side
    /// gap: the dialer side already binds outbound peers to their
    /// deterministic `NodeId` via `derive_test_node_id_from_validator_id`,
    /// so once the listener also registers under that same NodeId,
    /// `send_to(ValidatorId)` round-trips on both directions.
    ///
    /// Production-grade peer identity binding still requires mutual
    /// KEMTLS authentication (`MutualAuthMode::Required`); B8 is
    /// bounded to the test-grade DevNet path. See C4 in
    /// `docs/whitepaper/contradiction.md`.
    async fn handle_inbound_connection(
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        server_cfg: ServerConnectionConfig,
        peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
        inbound_tx: mpsc::Sender<P2pMessage>,
        connections_current: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        inbound_session_counter: Arc<AtomicU64>,
        inbound_identity_resolver: Arc<RwLock<Option<InboundIdentityResolver>>>,
    ) -> Result<(), P2pTransportError> {
        // Convert Tokio stream to std::net::TcpStream for KEMTLS handshake.
        //
        // B7: a tokio `TcpStream` returned from `into_std()` keeps the
        // underlying socket in non-blocking mode. The KEMTLS handshake
        // performed by `accept_kemtls_async` -> `SecureChannel::from_accepted`
        // does *blocking* reads, so without flipping the mode back to
        // blocking we observe `Io { kind: WouldBlock, "Resource
        // temporarily unavailable" }` on the very first handshake read
        // and the inbound session is dropped — which is the second
        // half of the Run 005 negative finding (handshake never
        // completes between two real binaries). Setting blocking mode
        // here is the smallest honest fix; the post-handshake async
        // wrapper (`SecureChannelAsync::try_new`) is the one that flips
        // the socket back to non-blocking for the worker loop.
        let std_stream = stream.into_std().map_err(P2pTransportError::Io)?;
        std_stream
            .set_nonblocking(false)
            .map_err(P2pTransportError::Io)?;

        // B8: perform the KEMTLS handshake AND surface the dialer's
        // `client_random` + `validator_id` from `ClientInit`. The
        // handshake itself is identical to the pre-B8 path.
        let (channel, peer_init) =
            accept_kemtls_async_with_peer_init(std_stream, server_cfg.clone())
                .await
                .map_err(|e| P2pTransportError::Handshake(e.to_string()))?;

        // B8: ask the optional inbound identity resolver whether this
        // accepted session should be registered under a deterministic
        // NodeId (rather than a fresh temporary session NodeId).
        let resolved_node_id: Option<NodeId> = {
            let guard = inbound_identity_resolver.read();
            guard.as_ref().and_then(|f| f(&peer_init))
        };

        let node_id = match resolved_node_id {
            Some(resolved) => {
                println!(
                    "[P2P] Inbound connection from {} bound to deterministic NodeId {:?} \
                     via inbound identity resolver (B8, test-grade)",
                    peer_addr, resolved
                );
                resolved
            }
            None => {
                // Pre-B8 fallback: temporary session-unique NodeId.
                // Derived from (local_validator_id || session counter
                // || peer addr). NOT cryptographically bound to the
                // dialer's identity. Preserved here so paths that do
                // NOT install a resolver continue to behave exactly as
                // they did before.
                let session_id = inbound_session_counter.fetch_add(1, Ordering::Relaxed);
                let mut preimage = Vec::new();
                preimage.extend_from_slice(INBOUND_SESSION_DOMAIN_TAG.as_bytes());
                preimage.extend_from_slice(b":");
                preimage.extend_from_slice(&server_cfg.handshake_config.local_validator_id);
                preimage.extend_from_slice(&session_id.to_be_bytes());
                preimage.extend_from_slice(peer_addr.to_string().as_bytes());
                let node_id_bytes = qbind_hash::sha3_256(&preimage);
                let temp_node_id = NodeId::new(node_id_bytes);
                println!(
                    "[P2P] Inbound connection from {} assigned temporary session NodeId {:?} \
                     (no inbound identity resolver / resolver returned None)",
                    peer_addr, temp_node_id
                );
                temp_node_id
            }
        };

        connections_current.fetch_add(1, Ordering::Relaxed);

        // Spawn read/write loops
        Self::spawn_peer_handlers(
            node_id,
            channel,
            peers,
            inbound_tx,
            connections_current,
            bytes_received,
        )
        .await;

        Ok(())
    }

    /// Dial an outbound peer (single-shot, no retry).
    ///
    /// **B8 note:** as of B8 the public `start()` path uses
    /// [`DialerHandle::dial_with_retry`] to spawn each initial dial as
    /// a background task with bounded retry, so this method is no
    /// longer reachable from `start()`. It is preserved on the type to
    /// keep the previous, well-tested single-shot dial behaviour
    /// available for tests and any future callers (the implementation
    /// is intentionally a near-copy of `DialerHandle::dial_once`).
    #[allow(dead_code)]
    async fn dial_peer(&self, peer_addr: String) -> Result<(), P2pTransportError> {
        println!("[P2P] Dialing {}", peer_addr);

        // Connect via TCP
        let stream = TcpStream::connect(&peer_addr).await?;

        // Convert to std::net::TcpStream for KEMTLS handshake
        let _std_stream = stream.into_std().map_err(P2pTransportError::Io)?;

        // B7: clone the template `client_cfg` and, if a per-peer override
        // exists for this address, replace `peer_kem_pk` (so the KEMTLS
        // KEM ciphertext actually encapsulates to the peer's static
        // KEM key) AND `validator_id` (so the protocol-level check
        // `delegation_cert.validator_id == client_init.validator_id`
        // in `handle_server_accept` passes). This is the concrete fix
        // for the Run 005 failure mode where the dialer was both
        // encapsulating to its own KEM pk and sending its own validator
        // id as the expected-server identity.
        let client_cfg = {
            let mut cfg = self.client_cfg.clone();
            let pk_opt = self.peer_kem_pk_overrides.read().get(&peer_addr).cloned();
            let vid_opt = self
                .peer_validator_id_overrides
                .read()
                .get(&peer_addr)
                .cloned();
            if let Some(pk) = pk_opt {
                cfg.peer_kem_pk = pk;
                if let Some(vid) = vid_opt {
                    cfg.validator_id = vid;
                }
                println!(
                    "[P2P] Dial {}: using per-peer KEM pk + validator-id override (pk_len={}, has_vid={})",
                    peer_addr,
                    cfg.peer_kem_pk.len(),
                    vid_opt.is_some(),
                );
            } else {
                eprintln!(
                    "[P2P] WARN: dialing {} without a per-peer KEM pk override; \
                     handshake will only succeed if the peer happens to share \
                     this node's KEM keypair (single-validator / smoke only). \
                     Multi-validator binary-path runs must use --p2p-peer \
                     'vid@addr' so the dialer can derive the peer's KEM pk.",
                    peer_addr
                );
            }
            cfg
        };

        // Perform KEMTLS handshake (blocking)
        let channel = connect_kemtls_async(peer_addr.clone(), client_cfg.clone())
            .await
            .map_err(|e| P2pTransportError::Handshake(e.to_string()))?;

        // M7: Derive NodeId from peer's KEM public key (cryptographic binding)
        // The peer_kem_pk in client_cfg is the server's KEM public key that we
        // are connecting to. NodeId = sha3_256("QBIND:nodeid:v1" || peer_kem_pk)
        //
        // B7: with the override applied above, this NodeId is now the
        // deterministic test-grade NodeId of the peer's validator (matching
        // `SimpleValidatorNodeMapping`), which is what closes peer-validator
        // identity for `send_to(ValidatorId)` on the dialer side.
        let node_id_bytes = derive_node_id_from_pubkey(&client_cfg.peer_kem_pk);
        let node_id = NodeId::new(node_id_bytes);

        self.connections_current.fetch_add(1, Ordering::Relaxed);

        // Spawn read/write loops
        Self::spawn_peer_handlers(
            node_id,
            channel,
            Arc::clone(&self.peers),
            self.inbound_tx.clone(),
            Arc::clone(&self.connections_current),
            Arc::clone(&self.bytes_received),
        )
        .await;

        Ok(())
    }

    /// Spawn read/write handlers for a peer connection.
    async fn spawn_peer_handlers(
        node_id: NodeId,
        channel: SecureChannelAsync,
        peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
        inbound_tx: mpsc::Sender<P2pMessage>,
        _connections_current: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
    ) {
        // Create outbound channel for this peer
        let (peer_tx, peer_rx) = mpsc::channel::<P2pMessage>(64);

        // Spawn write loop
        let channel_write = channel.clone();
        let write_handle = tokio::spawn(async move {
            Self::write_loop(channel_write, peer_rx).await;
        });

        // Spawn read loop
        let channel_read = channel;
        let inbound_tx_clone = inbound_tx.clone();
        let bytes_received_clone = Arc::clone(&bytes_received);
        let read_handle = tokio::spawn(async move {
            Self::read_loop(channel_read, inbound_tx_clone, bytes_received_clone).await;
        });

        // Register peer connection
        let conn = PeerConnection {
            node_id,
            tx: peer_tx,
            write_handle,
            read_handle,
        };

        peers.write().insert(node_id, conn);

        println!("[P2P] Peer {:?} connected", node_id);
    }

    /// Read loop: continuously read frames and push to inbound channel.
    async fn read_loop(
        channel: SecureChannelAsync,
        inbound_tx: mpsc::Sender<P2pMessage>,
        bytes_received: Arc<AtomicU64>,
    ) {
        loop {
            match channel.recv().await {
                Ok(frame_bytes) => {
                    bytes_received.fetch_add(frame_bytes.len() as u64, Ordering::Relaxed);

                    match decode_frame(&frame_bytes) {
                        Ok(msg) => {
                            if inbound_tx.send(msg).await.is_err() {
                                break; // Receiver dropped
                            }
                        }
                        Err(e) => {
                            eprintln!("[P2P] Frame decode error: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[P2P] Read error: {}", e);
                    break;
                }
            }
        }
    }

    /// Write loop: receive messages from channel and write frames.
    async fn write_loop(channel: SecureChannelAsync, mut rx: mpsc::Receiver<P2pMessage>) {
        while let Some(msg) = rx.recv().await {
            match encode_frame(&msg) {
                Ok(frame) => {
                    if let Err(e) = channel.send(&frame).await {
                        eprintln!("[P2P] Write error: {}", e);
                        break;
                    }
                }
                Err(e) => {
                    eprintln!("[P2P] Frame encode error: {}", e);
                    break;
                }
            }
        }
    }

    /// Subscribe to inbound messages.
    ///
    /// Returns a receiver that receives all inbound P2pMessages from all peers.
    pub async fn subscribe(&self) -> mpsc::Receiver<P2pMessage> {
        let (tx, rx) = mpsc::channel(256);

        // Spawn a task to forward messages from the shared receiver to the new subscriber
        let inbound_rx = Arc::clone(&self.inbound_rx);
        tokio::spawn(async move {
            let mut shared_rx = inbound_rx.lock().await;
            while let Some(msg) = shared_rx.recv().await {
                if tx.send(msg).await.is_err() {
                    break; // Subscriber dropped
                }
            }
        });

        rx
    }

    /// Shutdown the service gracefully.
    pub async fn shutdown(&mut self) {
        // Send shutdown signal to all tasks
        let _ = self.shutdown_tx.send(());

        // B8: abort any in-flight initial-dial-with-retry tasks.
        // Aborting is safe: each task only writes to `connections_current`
        // / `peers` AFTER a successful dial, and a successful dial has
        // already produced a registered `PeerConnection` whose
        // `tx`/`read_handle`/`write_handle` will be drained by the
        // peer-shutdown loop below.
        let dial_handles = {
            let mut guard = self.dial_handles.write();
            std::mem::take(&mut *guard)
        };
        for h in dial_handles {
            h.abort();
            let _ = h.await;
        }

        // Shutdown all peer connections
        let peers = {
            let mut peers_lock = self.peers.write();
            std::mem::take(&mut *peers_lock)
        };

        for (_node_id, conn) in peers {
            conn.shutdown().await;
        }

        // Wait for listener to terminate
        if let Some(handle) = self.listener_handle.take() {
            let _ = handle.await;
        }

        self.connections_current.store(0, Ordering::Relaxed);
    }

    /// Build a [`DialerHandle`] that can be moved into a `tokio::spawn`
    /// task to perform an initial dial (with bounded retry) without
    /// holding `&self`.
    fn dialer_handle(&self) -> DialerHandle {
        DialerHandle {
            crypto: Arc::clone(&self.crypto),
            client_cfg: self.client_cfg.clone(),
            peer_kem_pk_overrides: Arc::clone(&self.peer_kem_pk_overrides),
            peer_validator_id_overrides: Arc::clone(&self.peer_validator_id_overrides),
            peers: Arc::clone(&self.peers),
            inbound_tx: self.inbound_tx.clone(),
            connections_current: Arc::clone(&self.connections_current),
            bytes_received: Arc::clone(&self.bytes_received),
        }
    }

    /// Get current connection count.
    pub fn connections_current(&self) -> u64 {
        self.connections_current.load(Ordering::Relaxed)
    }

    /// Get total bytes sent.
    pub fn bytes_sent_total(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Get total bytes received.
    pub fn bytes_received_total(&self) -> u64 {
        self.bytes_received.load(Ordering::Relaxed)
    }
}

// ============================================================================
// B8: DialerHandle — cloneable per-peer initial-dial state for retry tasks.
// ============================================================================

/// Cloneable view of the dialer-relevant state of a
/// `TcpKemTlsP2pService`, used by background initial-dial-with-retry
/// tasks (B8).
///
/// The fields here are exactly the ones [`TcpKemTlsP2pService::dial_peer`]
/// reads or mutates: the cloned `client_cfg` template, the per-peer
/// `peer_kem_pk` / `validator_id` override maps, the `peers` registry,
/// the inbound mpsc, and the connection-count / bytes-received atomics.
/// Cloning a `DialerHandle` is cheap (Arc bumps).
struct DialerHandle {
    crypto: Arc<dyn CryptoProvider>,
    client_cfg: ClientConnectionConfig,
    peer_kem_pk_overrides: Arc<RwLock<HashMap<String, Vec<u8>>>>,
    peer_validator_id_overrides: Arc<RwLock<HashMap<String, [u8; 32]>>>,
    peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
    inbound_tx: mpsc::Sender<P2pMessage>,
    connections_current: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
}

impl DialerHandle {
    /// Perform a single dial attempt against `peer_addr`, mirroring
    /// `TcpKemTlsP2pService::dial_peer`. Kept here as a separate
    /// function so the retry loop in [`Self::dial_with_retry`] can
    /// spawn without borrowing `&self` from the outer service.
    async fn dial_once(&self, peer_addr: String) -> Result<(), P2pTransportError> {
        // The implementation below intentionally mirrors
        // `TcpKemTlsP2pService::dial_peer` step-for-step. Keeping the
        // two paths textually similar makes it obvious that the only
        // delta the B8 retry loop introduces is *when* `dial_once`
        // runs, not *what* it does.
        // Touching the `crypto` Arc here keeps the field non-dead even
        // when the underlying `connect_kemtls_async` doesn't need it
        // directly (it consumes the cloned `client_cfg.handshake_config`
        // which already holds its own crypto reference).
        let _crypto: &Arc<dyn CryptoProvider> = &self.crypto;

        // Connect via TCP
        let stream = TcpStream::connect(&peer_addr).await?;
        let _std_stream = stream.into_std().map_err(P2pTransportError::Io)?;

        // Build the per-peer ClientConnectionConfig (B7).
        let client_cfg = {
            let mut cfg = self.client_cfg.clone();
            let pk_opt = self.peer_kem_pk_overrides.read().get(&peer_addr).cloned();
            let vid_opt = self
                .peer_validator_id_overrides
                .read()
                .get(&peer_addr)
                .cloned();
            if let Some(pk) = pk_opt {
                cfg.peer_kem_pk = pk;
                if let Some(vid) = vid_opt {
                    cfg.validator_id = vid;
                }
                println!(
                    "[P2P] Dial {}: using per-peer KEM pk + validator-id override (pk_len={}, has_vid={})",
                    peer_addr,
                    cfg.peer_kem_pk.len(),
                    vid_opt.is_some(),
                );
            } else {
                eprintln!(
                    "[P2P] WARN: dialing {} without a per-peer KEM pk override; \
                     handshake will only succeed if the peer happens to share \
                     this node's KEM keypair (single-validator / smoke only).",
                    peer_addr
                );
            }
            cfg
        };

        // Perform KEMTLS handshake (blocking, in spawn_blocking).
        let channel = connect_kemtls_async(peer_addr.clone(), client_cfg.clone())
            .await
            .map_err(|e| P2pTransportError::Handshake(e.to_string()))?;

        // B7: NodeId derived from the peer's KEM pk (deterministic,
        // matches `derive_test_node_id_from_validator_id`).
        let node_id_bytes = derive_node_id_from_pubkey(&client_cfg.peer_kem_pk);
        let node_id = NodeId::new(node_id_bytes);

        self.connections_current.fetch_add(1, Ordering::Relaxed);

        // Spawn read/write loops (same as `dial_peer`).
        TcpKemTlsP2pService::spawn_peer_handlers(
            node_id,
            channel,
            Arc::clone(&self.peers),
            self.inbound_tx.clone(),
            Arc::clone(&self.connections_current),
            Arc::clone(&self.bytes_received),
        )
        .await;

        Ok(())
    }

    /// Bounded retry of the initial dial against `peer_addr`. Returns
    /// once the dial succeeds, the policy's attempt budget is
    /// exhausted, or a non-transient error is encountered. See
    /// [`DialRetryPolicy`].
    async fn dial_with_retry(&self, peer_addr: String, policy: DialRetryPolicy) {
        let max_attempts = policy.max_attempts.max(1);
        let mut backoff = policy.initial_backoff;
        for attempt in 1..=max_attempts {
            match self.dial_once(peer_addr.clone()).await {
                Ok(()) => {
                    if attempt > 1 {
                        println!(
                            "[P2P] dial {} succeeded on attempt {}/{} (B8 initial-dial retry)",
                            peer_addr, attempt, max_attempts,
                        );
                    }
                    return;
                }
                Err(e) => {
                    let transient = is_transient_dial_error(&e);
                    if attempt < max_attempts && transient {
                        println!(
                            "[P2P] dial {} attempt {}/{} failed (transient: {}); \
                             retrying in {}ms (B8 initial-dial retry)",
                            peer_addr,
                            attempt,
                            max_attempts,
                            e,
                            backoff.as_millis(),
                        );
                        tokio::time::sleep(backoff).await;
                        // Exponential backoff with cap.
                        let next_ms = backoff
                            .as_millis()
                            .saturating_mul(policy.backoff_multiplier as u128)
                            .min(policy.max_backoff.as_millis())
                            as u64;
                        backoff = Duration::from_millis(next_ms);
                    } else {
                        eprintln!(
                            "[P2P] dial {} giving up after {} attempt(s): {} \
                             (transient={}, max_attempts={})",
                            peer_addr, attempt, e, transient, max_attempts,
                        );
                        return;
                    }
                }
            }
        }
    }
}

impl P2pService for TcpKemTlsP2pService {
    fn broadcast(&self, msg: P2pMessage) {
        let peers = self.peers.read();
        for (node_id, conn) in peers.iter() {
            if let Err(e) = conn.tx.try_send(msg.clone()) {
                eprintln!("[P2P] Failed to broadcast to {:?}: {}", node_id, e);
            }
        }
    }

    fn send_to(&self, peer: NodeId, msg: P2pMessage) {
        let peers = self.peers.read();
        if let Some(conn) = peers.get(&peer) {
            if let Err(e) = conn.tx.try_send(msg) {
                eprintln!("[P2P] Failed to send to {:?}: {}", peer, e);
            }
        }
    }

    fn local_node_id(&self) -> NodeId {
        self.local_node_id
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        self.peers.read().keys().copied().collect()
    }
}