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

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch};
use tokio::task::JoinHandle;

use crate::node_config::NetworkTransportConfig;
use crate::p2p::{NodeId, P2pMessage, P2pService};
use crate::p2p_inbound::InboundP2pEnvelope;
use crate::peer_consensus_binding::AuthenticatedConsensusOrigin;
use crate::secure_channel::{
    AcceptedPeerInit, ChannelError, SecureChannel, SecureChannelAsync, TaskOutcome,
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
    /// A peer identity is held by an unfinished session retirement.
    SessionRetirement(String),
}

impl std::fmt::Display for P2pTransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P2pTransportError::Io(e) => write!(f, "I/O error: {}", e),
            P2pTransportError::Encoding(msg) => write!(f, "Encoding error: {}", msg),
            P2pTransportError::Handshake(msg) => write!(f, "Handshake error: {}", msg),
            P2pTransportError::Config(msg) => write!(f, "Config error: {}", msg),
            P2pTransportError::SessionRetirement(msg) => {
                write!(f, "peer session retirement error: {}", msg)
            }
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
pub type InboundIdentityResolver = Arc<dyn Fn(&AcceptedPeerInit) -> Option<NodeId> + Send + Sync>;

/// Run 418: resolver that maps an accepted inbound session's **verified**
/// KEMTLS identity to an [`AuthenticatedConsensusOrigin`], or `None` when the
/// session did not establish a verified mutual-auth identity.
///
/// Unlike [`InboundIdentityResolver`] (which is test-grade and may consume
/// self-asserted `client_random`), this resolver must only ever produce an
/// origin from the cert-verified fields of `AcceptedPeerInit`
/// (`mutual_auth_complete`, `verified_client_node_id`,
/// `verified_peer_validator_id`). When it returns `None`, the read loop
/// forwards consensus frames with no origin and the consensus ingress gate
/// fails closed.
pub type InboundConsensusOriginResolver =
    Arc<dyn Fn(&AcceptedPeerInit) -> Option<AuthenticatedConsensusOrigin> + Send + Sync>;

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
    /// Run 080: bounded channel for sending OUT-OF-BAND raw P2P
    /// frame bytes that the existing `encode_frame` consensus/DAG/
    /// control encoder cannot produce.
    ///
    /// The transport accepts bytes here verbatim and writes them to
    /// the per-peer KEMTLS-encrypted secure channel. The caller is
    /// responsible for the framing header (discriminator + u32-BE
    /// length + payload) — by construction the only producer in the
    /// production binary is the Run 080
    /// `LivePeerCandidateWirePublisher`, which encodes through
    /// `crate::pqc_peer_candidate_wire::encode_peer_candidate_wire_frame`
    /// and enforces the wire-frame size cap BEFORE enqueueing.
    ///
    /// Bounded capacity (small, see `RAW_FRAME_CHANNEL_CAPACITY`)
    /// so a slow / unhealthy peer cannot accumulate an unbounded
    /// backlog of out-of-band frames. `try_send` is used at the
    /// producer; queue-full surfaces as a per-peer send failure to
    /// the caller, never as backpressure on the consensus/DAG/
    /// control encoder path.
    raw_tx: mpsc::Sender<Vec<u8>>,
    retirement: Arc<PeerRetirement>,
}

struct PeerLoopTasks {
    reader: Option<JoinHandle<()>>,
    writer: Option<JoinHandle<()>>,
    reader_outcome: Option<TaskOutcome>,
    writer_outcome: Option<TaskOutcome>,
}

struct PeerRetirement {
    session_id: u64,
    channel: SecureChannelAsync,
    cancel_tx: watch::Sender<bool>,
    tasks: tokio::sync::Mutex<PeerLoopTasks>,
    loop_failure: std::sync::Mutex<Option<String>>,
    read_failure: Arc<std::sync::Mutex<Option<String>>>,
    monitor: tokio::sync::Mutex<Option<JoinHandle<Result<(), String>>>>,
}

impl PeerRetirement {
    fn begin(&self) {
        self.channel.invalidate_for_retirement();
        let _ = self.cancel_tx.send(true);
    }

    async fn finish(&self) -> Result<(), String> {
        self.channel
            .begin_retirement()
            .map_err(|error| error.to_string())?;

        let mut tasks = self.tasks.lock().await;
        // A later join may remain pending across timeout/cancellation.
        // Save each observed outcome before relinquishing its handle.
        if let Some(reader) = tasks.reader.as_mut() {
            let outcome = TaskOutcome::from_join(reader.await);
            if let TaskOutcome::Failed(error) = &outcome {
                self.record_loop_failure(format!("peer read loop: {error}"));
            }
            tasks.reader_outcome = Some(outcome);
            tasks.reader = None;
        }
        if let Some(writer) = tasks.writer.as_mut() {
            let outcome = TaskOutcome::from_join(writer.await);
            if let TaskOutcome::Failed(error) = &outcome {
                self.record_loop_failure(format!("peer write loop: {error}"));
            }
            tasks.writer_outcome = Some(outcome);
            tasks.writer = None;
        }
        drop(tasks);

        self.channel
            .finish_retirement()
            .await
            .map_err(|error| error.to_string())?;
        if let Some(error) = self.loop_failure.lock().unwrap().clone() {
            return Err(error);
        }
        Ok(())
    }

    async fn finish_and_wait(&self) -> Result<(), String> {
        self.begin();
        use std::future::Future;
        let mut monitor = self.monitor.lock().await;
        if let Some(task) = monitor.as_mut() {
            let result = std::future::poll_fn(|cx| std::pin::Pin::new(&mut *task).poll(cx)).await;
            *monitor = None;
            match result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => return Err(error),
                Err(error) => return Err(format!("peer read monitor failed: {error}")),
            }
        }
        drop(monitor);
        self.finish().await
    }

    fn record_loop_failure(&self, error: String) {
        let mut failure = self.loop_failure.lock().unwrap();
        match failure.as_mut() {
            Some(existing) => {
                existing.push_str("; ");
                existing.push_str(&error);
            }
            None => *failure = Some(error),
        }
    }
}

#[derive(Default)]
struct PeerRegistry {
    active: HashMap<NodeId, PeerConnection>,
    retiring: HashMap<NodeId, Arc<PeerRetirement>>,
    registering: HashSet<NodeId>,
    candidates: HashMap<NodeId, Arc<std::net::TcpStream>>,
    closed: bool,
    handshakes: HashMap<u64, Arc<PendingHandshake>>,
    #[cfg(test)]
    before_publish: Option<Arc<RegistrationPause>>,
    #[cfg(test)]
    after_publish: Option<Arc<RegistrationPause>>,
    #[cfg(test)]
    after_eviction_snapshot: Option<Arc<(std::sync::Barrier, std::sync::Barrier)>>,
    #[cfg(test)]
    before_fatal_retirement: Option<Arc<RegistrationPause>>,
}

#[cfg(test)]
#[derive(Default)]
struct RegistrationPause {
    entered: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

#[cfg(test)]
impl RegistrationPause {
    async fn wait(&self) {
        self.entered.notify_one();
        self.release.notified().await;
    }
}

type HandshakeResult = Result<(SecureChannel, Option<AcceptedPeerInit>), ChannelError>;

struct PendingHandshake {
    shutdown_stream: std::net::TcpStream,
    task: tokio::sync::Mutex<Option<JoinHandle<HandshakeResult>>>,
    failure: std::sync::Mutex<Option<String>>,
}

impl PendingHandshake {
    async fn join(&self) -> Result<Option<HandshakeResult>, String> {
        let mut task = self.task.lock().await;
        if let Some(handle) = task.as_mut() {
            let result = handle.await;
            // Persist the join outcome before relinquishing its handle.
            if let Err(error) = &result {
                *self.failure.lock().unwrap() = Some(error.to_string());
            }
            *task = None;
            return result.map(Some).map_err(|error| error.to_string());
        }
        match self.failure.lock().unwrap().clone() {
            Some(error) => Err(error),
            None => Ok(None),
        }
    }
}

struct RegistrationReservation {
    node_id: NodeId,
    peers: Arc<RwLock<PeerRegistry>>,
    armed: bool,
}

impl Drop for RegistrationReservation {
    fn drop(&mut self) {
        if self.armed {
            let mut registry = self.peers.write();
            registry.registering.remove(&self.node_id);
            registry.candidates.remove(&self.node_id);
        }
    }
}

/// Run 080 — bounded outbound raw-frame channel capacity per peer.
/// Small by design: the publisher today is operator-triggered
/// publish-once; the only legitimate burst is "one frame to one
/// peer". A small cap also lets `try_send` honestly surface
/// queue-full as a per-peer failure on an unhealthy peer instead of
/// silently absorbing the frame into a long queue.
const RAW_FRAME_CHANNEL_CAPACITY: usize = 8;
const PEER_RETIREMENT_TIMEOUT: Duration = Duration::from_secs(5);
static NEXT_PEER_SESSION_ID: AtomicU64 = AtomicU64::new(1);

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
    peers: Arc<RwLock<PeerRegistry>>,
    /// Inbound message channel (sender).
    inbound_tx: mpsc::Sender<InboundP2pEnvelope>,
    /// Inbound message channel (receiver) for cloning.
    inbound_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<InboundP2pEnvelope>>>,
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
    /// Run 079: optional sink for peer-candidate wire frames
    /// (discriminator [`crate::pqc_peer_candidate_wire::DISCRIMINATOR_PEER_CANDIDATE_WIRE`]).
    ///
    /// When set, the per-peer `read_loop` routes any received frame
    /// whose first byte equals the peer-candidate wire discriminator
    /// through the sink and continues — it does NOT call the
    /// existing `decode_frame` consensus/DAG/control demuxer on
    /// those frames (so the read loop is not poisoned by an
    /// "unknown discriminator" close).
    ///
    /// When `None` (the default and the bit-for-bit pre-Run-079
    /// behaviour for callers that don't opt in), peer-candidate
    /// wire frames are dropped cheaply at the read loop — the
    /// transport never decodes their payload and never bumps any
    /// metric (the metric handle lives inside the sink).
    ///
    /// Wired through `set_peer_candidate_wire_frame_sink` on the
    /// production-binary path by `p2p_node_builder` when the
    /// `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`
    /// flag is set.
    peer_candidate_wire_sink:
        Arc<RwLock<Option<Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>>>>,
    /// Run 362: optional runtime-owned abuse/DoS connection-rate limiter
    /// state consulted at the top of the accept loop, before any expensive
    /// per-connection admission work (KEMTLS handshake, trust-bundle /
    /// genesis checks).
    ///
    /// `None` by default (and whenever the operator has not enabled the
    /// connection-rate limiter), in which case the accept loop is bit-for-bit
    /// unchanged. When `Some`, an over-budget inbound connection is refused
    /// and closed early and the `qbind_p2p_connection_rate_drop_total` metric
    /// is incremented; an under-budget (or disabled-limiter) connection
    /// proceeds to the unchanged admission path. A refusal never admits a
    /// peer, never mutates trust state, and never writes any sequence/marker
    /// file. Installed via
    /// [`TcpKemTlsP2pService::set_abuse_dos_runtime_state`].
    abuse_dos_runtime: Arc<
        RwLock<
            Option<Arc<crate::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeState>>,
        >,
    >,
    /// Run 369: optional deployed inbound per-peer message-rate limiter
    /// consulted by every per-peer `read_loop` AFTER a frame decodes to a
    /// structured `P2pMessage` and BEFORE it is forwarded to the inbound
    /// demuxer / handlers.
    ///
    /// `None` by default (bit-for-bit pre-Run-369 behaviour). When installed
    /// (via [`TcpKemTlsP2pService::set_inbound_per_peer_limiter`]), an
    /// over-budget frame is dropped, the adapter's bounded per-peer drop
    /// counter is incremented, and the existing per-peer
    /// `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter is bumped
    /// if a metrics handle was installed. Dropping a frame never tears down the
    /// connection, never touches the connection-rate limiter, and never mutates
    /// admission / trust / sequence / validator / epoch state. The default
    /// posture is `1000` msg/s + `100` burst so normal traffic is unaffected.
    inbound_per_peer_limiter: Arc<
        RwLock<
            Option<Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>>,
        >,
    >,
    /// Run 418: optional resolver that maps an accepted inbound session's
    /// **verified** KEMTLS identity to an authenticated consensus origin.
    ///
    /// When present and returning `Some(origin)` for an accepted session, the
    /// per-peer read loop tags every inbound consensus frame from that session
    /// with the origin so the consensus ingress gate can bind the claimed
    /// sender to the authenticated validator. When absent or returning `None`,
    /// consensus frames are forwarded with no origin and the ingress gate (when
    /// installed) fails closed. Installed via
    /// [`TcpKemTlsP2pService::set_inbound_consensus_origin_resolver`].
    inbound_consensus_origin_resolver: Arc<RwLock<Option<InboundConsensusOriginResolver>>>,
    /// Run 418: static-peer outbound authenticated consensus origins keyed by
    /// dial address (the same string from `NetworkTransportConfig::static_peers`
    /// after stripping any `vid@` prefix).
    ///
    /// When `dial_peer(addr)` completes a KEMTLS handshake and finds an entry
    /// here, the resulting per-peer read loop tags inbound consensus frames from
    /// that connection with the configured origin (bound to handshake success).
    /// Empty by default. Installed via
    /// [`TcpKemTlsP2pService::set_outbound_consensus_origins`].
    outbound_consensus_origins: Arc<RwLock<HashMap<String, AuthenticatedConsensusOrigin>>>,
}

impl std::fmt::Debug for TcpKemTlsP2pService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TcpKemTlsP2pService")
            .field("local_node_id", &self.local_node_id)
            .field("config", &self.config)
            .field("peer_count", &self.peers.read().active.len())
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
            peers: Arc::new(RwLock::new(PeerRegistry::default())),
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
            peer_candidate_wire_sink: Arc::new(RwLock::new(None)),
            abuse_dos_runtime: Arc::new(RwLock::new(None)),
            inbound_per_peer_limiter: Arc::new(RwLock::new(None)),
            inbound_consensus_origin_resolver: Arc::new(RwLock::new(None)),
            outbound_consensus_origins: Arc::new(RwLock::new(HashMap::new())),
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
    pub fn set_peer_validator_id_overrides(&mut self, overrides: HashMap<String, [u8; 32]>) {
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

    /// Run 418: install the inbound authenticated-consensus-origin resolver.
    ///
    /// When installed, every accepted inbound session has its consensus frames
    /// tagged with the origin the resolver derives from the session's
    /// **verified** KEMTLS identity (see [`InboundConsensusOriginResolver`]).
    pub fn set_inbound_consensus_origin_resolver(
        &mut self,
        resolver: InboundConsensusOriginResolver,
    ) {
        let mut guard = self.inbound_consensus_origin_resolver.write();
        *guard = Some(resolver);
    }

    /// Run 418: install the static-peer outbound authenticated consensus
    /// origins keyed by dial address.
    pub fn set_outbound_consensus_origins(
        &mut self,
        origins: HashMap<String, AuthenticatedConsensusOrigin>,
    ) {
        let mut guard = self.outbound_consensus_origins.write();
        *guard = origins;
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

    /// Run 079: install (or replace) the peer-candidate wire frame
    /// sink consulted by every per-peer `read_loop` whenever a
    /// frame's first byte equals
    /// [`crate::pqc_peer_candidate_wire::DISCRIMINATOR_PEER_CANDIDATE_WIRE`].
    ///
    /// When set, the read loop routes `0x05` frames through the
    /// sink and CONTINUES (so the connection is NOT closed on a
    /// peer-supplied `0x05` frame). The sink is responsible for
    /// the Run 078 fail-closed decode + Run 076 validator pipeline.
    ///
    /// When the sink is `None` (the default), `0x05` frames are
    /// dropped cheaply by the read loop. Existing
    /// consensus/DAG/control discriminators (`0x00`/`0x01`/`0x02`)
    /// remain bit-for-bit unaffected.
    ///
    /// This is the production-binary entry point used by
    /// `p2p_node_builder` when the operator opts in via
    /// `--p2p-trust-bundle-peer-candidate-wire-validation-enabled`.
    pub fn set_peer_candidate_wire_frame_sink(
        &self,
        sink: Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>,
    ) {
        *self.peer_candidate_wire_sink.write() = Some(sink);
    }

    /// Run 079: read accessor used by tests / observability code to
    /// confirm a sink has (or has not) been installed. The sink
    /// itself is hidden behind an `Arc<dyn>` so the return type is
    /// just a boolean to avoid leaking the trait object.
    pub fn has_peer_candidate_wire_frame_sink(&self) -> bool {
        self.peer_candidate_wire_sink.read().is_some()
    }

    /// Run 362: install the runtime-owned abuse/DoS connection-rate limiter
    /// state consulted by the accept loop.
    ///
    /// Must be called before `start()` so the very first accepted connection
    /// is already subject to the limiter. Default (never called, or the
    /// operator did not enable the limiter) leaves the accept loop bit-for-bit
    /// unchanged. This is the production-binary entry point used by
    /// `p2p_node_builder` when the operator opts in via the hidden
    /// `--p2p-connection-rate-limit-enabled` flag family.
    pub fn set_abuse_dos_runtime_state(
        &self,
        state: Arc<crate::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeState>,
    ) {
        *self.abuse_dos_runtime.write() = Some(state);
    }

    /// Run 362: whether a runtime-owned abuse/DoS connection-rate limiter has
    /// been installed (tests / observability). Returns `false` in the default
    /// configuration.
    pub fn has_abuse_dos_runtime_state(&self) -> bool {
        self.abuse_dos_runtime.read().is_some()
    }

    /// Run 369: install (or replace) the deployed inbound per-peer
    /// message-rate limiter consulted by every per-peer `read_loop`.
    ///
    /// Must be called before `start()` so the very first inbound frame from
    /// the very first accepted connection is already subject to the limiter.
    /// Default (never called) leaves the read loop bit-for-bit unchanged. This
    /// is the production-binary entry point used by `p2p_node_builder`, which
    /// installs an adapter carrying the CLI-derived per-peer thresholds (or the
    /// documented `1000` msg/s + `100` burst default).
    pub fn set_inbound_per_peer_limiter(
        &self,
        limiter: Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>,
    ) {
        *self.inbound_per_peer_limiter.write() = Some(limiter);
    }

    /// Run 369: whether a deployed inbound per-peer message-rate limiter has
    /// been installed (tests / observability). Returns `false` in the default
    /// configuration.
    pub fn has_inbound_per_peer_limiter(&self) -> bool {
        self.inbound_per_peer_limiter.read().is_some()
    }

    // ------------------------------------------------------------------
    // Run 080 — out-of-band raw frame send surface.
    //
    // The methods below are the smallest honest "send a raw,
    // already-framed P2P frame to authenticated peers" path that
    // does NOT introduce a new transport, a new listener, a new
    // gossip subscription, or a parallel networking architecture.
    // They are the production-binary entry points used by the
    // `LivePeerCandidateWirePublisher` in
    // `crate::pqc_peer_candidate_wire`.
    //
    // Strict scope:
    // - the caller MUST have already produced a valid 5-byte
    //   length-prefixed wire frame (discriminator + u32-BE length
    //   + payload). The transport writes the bytes verbatim to the
    //   per-peer KEMTLS-encrypted channel.
    // - the caller MUST have enforced its own size cap. The
    //   transport does NOT inspect the bytes, does NOT bump any
    //   `peer_candidate_*` metric, does NOT touch any
    //   `LivePqcTrustState` or sequence file.
    // - the methods are non-blocking on the producer side: they
    //   call `mpsc::Sender::try_send` against the bounded per-peer
    //   raw-frame channel. `Err(_)` is surfaced truthfully via
    //   `RawFrameSendOutcome` so the publisher's send-failure
    //   counter can bump on a per-peer basis without coupling the
    //   transport to publisher-side accounting.
    // ------------------------------------------------------------------

    /// Run 080 — number of currently authenticated peers in the
    /// session registry. Same as [`live_session_count`] but kept
    /// under a Run-080-stable name so the publisher does not bind
    /// to a Run 072 method that may evolve independently.
    pub fn connected_peer_count(&self) -> usize {
        self.peers.read().active.len()
    }

    /// Run 080 — snapshot the currently authenticated peer NodeIds
    /// in registration order. Cheap (single read lock).
    pub fn connected_peer_node_ids(&self) -> Vec<NodeId> {
        self.peers.read().active.keys().copied().collect()
    }

    /// Run 080 — enqueue `frame_bytes` for asynchronous transmission
    /// to **every** currently authenticated peer.
    ///
    /// The frame is **not** validated by the transport (the
    /// publisher is responsible for the wire format and the size
    /// cap). For each peer, a non-blocking `try_send` is performed
    /// against the per-peer bounded raw-frame channel and a single
    /// [`RawFramePeerSendOutcome`] is recorded in the returned
    /// [`RawFrameSendReport`].
    ///
    /// **Non-mutation contract:** this method never mutates any
    /// trust state, sequence file, P2P session, or `peer_candidate_*`
    /// metric. It only enqueues bytes onto already-established
    /// per-peer outbound channels.
    pub fn send_raw_frame_to_all_peers(
        &self,
        frame_bytes: Vec<u8>,
    ) -> crate::pqc_peer_candidate_wire::RawFrameSendReport {
        // Snapshot the peer set under the registry's read lock so
        // we don't hold the lock across the per-peer `try_send`
        // calls (a slow / contended channel must not block the
        // registry).
        let peer_snapshot: Vec<(NodeId, mpsc::Sender<Vec<u8>>)> = {
            let guard = self.peers.read();
            guard
                .active
                .iter()
                .map(|(id, conn)| (*id, conn.raw_tx.clone()))
                .collect()
        };

        let mut per_peer: Vec<(
            NodeId,
            crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome,
        )> = Vec::with_capacity(peer_snapshot.len());
        for (peer, tx) in peer_snapshot {
            let outcome = match tx.try_send(frame_bytes.clone()) {
                Ok(()) => crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome::Enqueued,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome::QueueFull
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome::ChannelClosed
                }
            };
            per_peer.push((peer, outcome));
        }
        crate::pqc_peer_candidate_wire::RawFrameSendReport::from_per_peer(per_peer)
    }

    /// Run 088 — enqueue `frame_bytes` for a selected set of peers.
    /// Used by validation-before-rebroadcast propagation to exclude
    /// the source peer and bound fanout.
    pub fn send_raw_frame_to_selected_peers(
        &self,
        frame_bytes: Vec<u8>,
        selected_peers: &[NodeId],
    ) -> crate::pqc_peer_candidate_wire::RawFrameSendReport {
        let peer_snapshot: Vec<(NodeId, mpsc::Sender<Vec<u8>>)> = {
            let guard = self.peers.read();
            selected_peers
                .iter()
                .filter_map(|id| guard.active.get(id).map(|conn| (*id, conn.raw_tx.clone())))
                .collect()
        };

        let mut per_peer: Vec<(
            NodeId,
            crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome,
        )> = Vec::with_capacity(selected_peers.len());
        for selected in selected_peers {
            if !peer_snapshot.iter().any(|(peer, _)| peer == selected) {
                per_peer.push((
                    *selected,
                    crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome::ChannelClosed,
                ));
            }
        }
        for (peer, tx) in peer_snapshot {
            let outcome = match tx.try_send(frame_bytes.clone()) {
                Ok(()) => crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome::Enqueued,
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome::QueueFull
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    crate::pqc_peer_candidate_wire::RawFramePeerSendOutcome::ChannelClosed
                }
            };
            per_peer.push((peer, outcome));
        }
        crate::pqc_peer_candidate_wire::RawFrameSendReport::from_per_peer(per_peer)
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
        if self.peers.read().closed {
            return Err(P2pTransportError::SessionRetirement(
                "service shutdown is terminal; construct a new service to restart".to_owned(),
            ));
        }
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
        let peer_candidate_wire_sink = Arc::clone(&self.peer_candidate_wire_sink);
        let abuse_dos_runtime = Arc::clone(&self.abuse_dos_runtime);
        let inbound_per_peer_limiter = Arc::clone(&self.inbound_per_peer_limiter);
        let inbound_consensus_origin_resolver = Arc::clone(&self.inbound_consensus_origin_resolver);

        tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            let mut handlers = tokio::task::JoinSet::new();

            loop {
                tokio::select! {
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                    result = handlers.join_next(), if !handlers.is_empty() => {
                        if let Some(Err(error)) = result {
                            eprintln!("[P2P] inbound handler failed: {error}");
                        }
                    }
                    result = listener.accept() => {
                        match result {
                            Ok((stream, peer_addr)) => {
                                // Run 362: consult the runtime-owned inbound
                                // connection-rate limiter (if installed and
                                // enabled) BEFORE any expensive per-connection
                                // admission work. Over-budget connections are
                                // refused deterministically and the socket is
                                // dropped early; the KEMTLS handshake,
                                // trust-bundle and genesis checks never run for
                                // a refused connection, and no peer is admitted.
                                // Default (no limiter installed) skips this
                                // block entirely and preserves prior behavior.
                                let admit = {
                                    let guard = abuse_dos_runtime.read();
                                    match guard.as_ref() {
                                        Some(state) => {
                                            state.should_admit(peer_addr, std::time::Instant::now())
                                        }
                                        None => true,
                                    }
                                };
                                if !admit {
                                    println!(
                                        "[P2P] Connection-rate limited inbound from {}",
                                        peer_addr
                                    );
                                    drop(stream);
                                    continue;
                                }

                                println!("[P2P] Accepted connection from {}", peer_addr);

                                let peers_clone = Arc::clone(&peers);
                                let inbound_tx_clone = inbound_tx.clone();
                                let server_cfg_clone = server_cfg.clone();
                                let connections_current_clone = Arc::clone(&connections_current);
                                let bytes_received_clone = Arc::clone(&bytes_received);
                                let inbound_session_counter_clone = Arc::clone(&inbound_session_counter);
                                let resolver_clone = Arc::clone(&inbound_identity_resolver);
                                let wire_sink_clone = Arc::clone(&peer_candidate_wire_sink);
                                let inbound_per_peer_limiter_clone =
                                    Arc::clone(&inbound_per_peer_limiter);
                                let inbound_consensus_origin_resolver_clone =
                                    Arc::clone(&inbound_consensus_origin_resolver);

                                handlers.spawn(async move {
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
                                        wire_sink_clone,
                                        inbound_per_peer_limiter_clone,
                                        inbound_consensus_origin_resolver_clone,
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
            handlers.abort_all();
            while let Some(result) = handlers.join_next().await {
                if let Err(error) = result {
                    if !error.is_cancelled() {
                        eprintln!("[P2P] inbound handler failed during shutdown: {error}");
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
        peers: Arc<RwLock<PeerRegistry>>,
        inbound_tx: mpsc::Sender<InboundP2pEnvelope>,
        connections_current: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        inbound_session_counter: Arc<AtomicU64>,
        inbound_identity_resolver: Arc<RwLock<Option<InboundIdentityResolver>>>,
        peer_candidate_wire_sink: Arc<
            RwLock<Option<Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>>>,
        >,
        inbound_per_peer_limiter: Arc<
            RwLock<
                Option<
                    Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>,
                >,
            >,
        >,
        inbound_consensus_origin_resolver: Arc<RwLock<Option<InboundConsensusOriginResolver>>>,
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
        let handshake_cfg = server_cfg.clone();
        let (channel, peer_init) =
            Self::tracked_handshake(Arc::clone(&peers), std_stream, move |stream| {
                SecureChannel::from_accepted_with_peer_init(stream, handshake_cfg)
                    .map(|(channel, init)| (channel, Some(init)))
            })
            .await?;
        let peer_init = peer_init.ok_or_else(|| {
            P2pTransportError::Handshake("inbound handshake omitted peer init".to_owned())
        })?;

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

        // Run 418: derive the authenticated consensus origin from this
        // session's *verified* KEMTLS identity (never from self-asserted
        // fields). When no resolver is installed or the session did not
        // authenticate, the origin is `None` and downstream consensus frames
        // are forwarded without an origin (the ingress gate fails closed).
        let consensus_origin: Option<AuthenticatedConsensusOrigin> = {
            let guard = inbound_consensus_origin_resolver.read();
            guard.as_ref().and_then(|f| f(&peer_init))
        };

        // Spawn read/write loops
        Self::spawn_peer_handlers(
            node_id,
            channel,
            peers,
            inbound_tx,
            connections_current,
            bytes_received,
            peer_candidate_wire_sink,
            inbound_per_peer_limiter,
            consensus_origin,
        )
        .await?;

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

        // Perform KEMTLS handshake (blocking), surfacing the ACTUAL verified
        // server identity established by the handshake (Run 418, F6).
        let channel =
            Self::tracked_dial(Arc::clone(&self.peers), &peer_addr, client_cfg.clone()).await?;
        let verified_server_identity = channel.verified_server_identity();

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

        // Run 418 (F6): the authenticated outbound consensus origin is derived
        // from the ACTUAL verified server certificate identity surfaced by the
        // KEMTLS handshake — NOT by looking up the dial address. The configured
        // `vid@addr` map (`outbound_consensus_origins`) records only the
        // *expected* pair for that address; the verified pair must match it
        // exactly (full 32-byte NodeId AND validator id AND authenticated
        // state), or the session is rejected. The dial address alone never
        // mints the authenticated origin.
        let expected_origin: Option<AuthenticatedConsensusOrigin> = self
            .outbound_consensus_origins
            .read()
            .get(&peer_addr)
            .cloned();
        let consensus_origin: Option<AuthenticatedConsensusOrigin> = match expected_origin {
            Some(expected) => {
                let verified = verified_server_identity.ok_or_else(|| {
                    P2pTransportError::Handshake(format!(
                        "Run 418: dial {} completed without a verified server identity; \
                         refusing to mint an authenticated origin from the dial address",
                        peer_addr
                    ))
                })?;
                let verified_vid =
                    crate::p2p_node_builder::parse_test_validator_id_from_cert_validator_id(
                        &verified.validator_id,
                    );
                let node_matches = verified.node_id == *expected.node_id().as_bytes();
                let vid_matches = verified_vid == Some(expected.validator_id().as_u64());
                if !verified.authenticated || !node_matches || !vid_matches {
                    return Err(P2pTransportError::Handshake(format!(
                        "Run 418: verified server identity for {} does not match the configured \
                         authoritative mapping (authenticated={}, node_match={}, vid_match={}); \
                         rejecting session",
                        peer_addr, verified.authenticated, node_matches, vid_matches
                    )));
                }
                // Build the origin from the VERIFIED identity (identical to the
                // expected pair on a match).
                Some(AuthenticatedConsensusOrigin::new(
                    NodeId::new(verified.node_id),
                    expected.validator_id(),
                ))
            }
            // No configured expectation for this address: do not fabricate an
            // authenticated origin. The consensus ingress gate fails closed on
            // a `None` origin, so unauthenticated remote consensus cannot enter.
            None => None,
        };

        // Spawn read/write loops
        Self::spawn_peer_handlers(
            node_id,
            channel,
            Arc::clone(&self.peers),
            self.inbound_tx.clone(),
            Arc::clone(&self.connections_current),
            Arc::clone(&self.bytes_received),
            Arc::clone(&self.peer_candidate_wire_sink),
            Arc::clone(&self.inbound_per_peer_limiter),
            consensus_origin,
        )
        .await?;

        Ok(())
    }

    async fn tracked_handshake(
        peers: Arc<RwLock<PeerRegistry>>,
        stream: std::net::TcpStream,
        handshake: impl FnOnce(std::net::TcpStream) -> HandshakeResult + Send + 'static,
    ) -> Result<(SecureChannel, Option<AcceptedPeerInit>), P2pTransportError> {
        let shutdown_stream = stream.try_clone().map_err(P2pTransportError::Io)?;
        let id = NEXT_PEER_SESSION_ID.fetch_add(1, Ordering::Relaxed);
        let owner = {
            let mut registry = peers.write();
            if registry.closed {
                return Err(P2pTransportError::SessionRetirement(
                    "service shutdown refuses handshake".to_owned(),
                ));
            }
            let owner = Arc::new(PendingHandshake {
                shutdown_stream,
                task: tokio::sync::Mutex::new(Some(tokio::task::spawn_blocking(move || {
                    handshake(stream)
                }))),
                failure: std::sync::Mutex::new(None),
            });
            registry.handshakes.insert(id, Arc::clone(&owner));
            owner
        };
        let result = owner.join().await.map_err(P2pTransportError::Handshake)?;
        {
            let mut registry = peers.write();
            if registry
                .handshakes
                .get(&id)
                .is_some_and(|current| Arc::ptr_eq(current, &owner))
            {
                registry.handshakes.remove(&id);
            }
        }
        result
            .ok_or_else(|| {
                P2pTransportError::SessionRetirement(
                    "handshake consumed by service shutdown".to_owned(),
                )
            })?
            .map_err(|error| P2pTransportError::Handshake(format!("{error:?}")))
    }

    async fn tracked_dial(
        peers: Arc<RwLock<PeerRegistry>>,
        addr: &str,
        cfg: ClientConnectionConfig,
    ) -> Result<SecureChannel, P2pTransportError> {
        // Tokio owns a cancellable TCP connect; after establishment the
        // registry retains the independent shutdown handle and blocking join.
        if peers.read().closed {
            return Err(P2pTransportError::SessionRetirement(
                "service shutdown refuses dial".to_owned(),
            ));
        }
        let stream = TcpStream::connect(addr)
            .await
            .map_err(P2pTransportError::Io)?;
        let stream = stream.into_std().map_err(P2pTransportError::Io)?;
        stream
            .set_nonblocking(false)
            .map_err(P2pTransportError::Io)?;
        Self::tracked_handshake(peers, stream, move |stream| {
            SecureChannel::connect_on_stream(stream, cfg).map(|channel| (channel, None))
        })
        .await
        .map(|(channel, _)| channel)
    }

    /// Spawn read/write handlers for a peer connection.
    async fn spawn_peer_handlers(
        node_id: NodeId,
        channel: SecureChannel,
        peers: Arc<RwLock<PeerRegistry>>,
        inbound_tx: mpsc::Sender<InboundP2pEnvelope>,
        connections_current: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        peer_candidate_wire_sink: Arc<
            RwLock<Option<Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>>>,
        >,
        inbound_per_peer_limiter: Arc<
            RwLock<
                Option<
                    Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>,
                >,
            >,
        >,
        consensus_origin: Option<AuthenticatedConsensusOrigin>,
    ) -> Result<(), P2pTransportError> {
        let candidate_shutdown = Arc::new(
            channel
                .stream()
                .try_clone()
                .map_err(P2pTransportError::Io)?,
        );
        let retirement = {
            let mut registry = peers.write();
            if registry.closed {
                return Err(P2pTransportError::SessionRetirement(
                    "service shutdown refuses registration".to_owned(),
                ));
            }
            if registry.registering.contains(&node_id) {
                return Err(P2pTransportError::SessionRetirement(format!(
                    "NodeId {:?} already has a registration in progress",
                    node_id
                )));
            }
            registry.registering.insert(node_id);
            registry.candidates.insert(node_id, candidate_shutdown);

            if let Some(retirement) = registry.retiring.get(&node_id) {
                Some(Arc::clone(retirement))
            } else if let Some(displaced) = registry.active.remove(&node_id) {
                displaced.retirement.begin();
                let retirement = Arc::clone(&displaced.retirement);
                registry.retiring.insert(node_id, Arc::clone(&retirement));
                drop(displaced.tx);
                drop(displaced.raw_tx);
                connections_current.store(registry.active.len() as u64, Ordering::Relaxed);
                Some(retirement)
            } else {
                None
            }
        };
        let mut reservation = RegistrationReservation {
            node_id,
            peers: Arc::clone(&peers),
            armed: true,
        };

        if let Some(retirement) = retirement {
            let result =
                tokio::time::timeout(PEER_RETIREMENT_TIMEOUT, retirement.finish_and_wait())
                    .await
                    .map_err(|_| "peer retirement timed out; ownership retained".to_owned())
                    .and_then(|result| result);
            if let Err(error) = result {
                eprintln!(
                    "[P2P] refusing replacement for {:?}: retirement of session {} is incomplete: {}",
                    node_id, retirement.session_id, error
                );
                return Err(P2pTransportError::SessionRetirement(format!(
                    "NodeId {:?} remains blocked by session {}: {}",
                    node_id, retirement.session_id, error
                )));
            }

            let mut registry = peers.write();
            match registry.retiring.get(&node_id) {
                Some(current) if Arc::ptr_eq(current, &retirement) => {
                    registry.retiring.remove(&node_id);
                }
                None => {}
                _ => {
                    return Err(P2pTransportError::SessionRetirement(format!(
                        "retired session {} lost registry ownership",
                        retirement.session_id
                    )));
                }
            }
        }

        #[cfg(test)]
        {
            let pause = peers.write().before_publish.take();
            if let Some(pause) = pause {
                pause.wait().await;
            }
        }

        // No await occurs between this admission check, worker creation and
        // registry publication. Shutdown/eviction see either no candidate
        // workers or a fully owned registered session.
        {
            let mut registry = peers.write();
            if registry.closed {
                return Err(P2pTransportError::SessionRetirement(
                    "service shutdown refuses reserved registration".to_owned(),
                ));
            }
            if !registry.registering.contains(&node_id)
                || registry.active.contains_key(&node_id)
                || registry.retiring.contains_key(&node_id)
            {
                return Err(P2pTransportError::SessionRetirement(
                    "registration reservation was lost before worker creation".to_owned(),
                ));
            }
            let channel = SecureChannelAsync::try_new(channel)
                .map_err(|error| P2pTransportError::SessionRetirement(error.to_string()))?;

            // Create outbound channel for this peer
            let (peer_tx, peer_rx) = mpsc::channel::<P2pMessage>(64);
            // Run 080 — bounded raw-frame outbound channel. Small
            // capacity so a slow / unhealthy peer cannot accumulate an
            // unbounded backlog of out-of-band frames (the producer
            // uses `try_send` and treats queue-full as a per-peer
            // failure rather than backpressure on the structured
            // consensus/DAG/control encoder path).
            let (peer_raw_tx, peer_raw_rx) = mpsc::channel::<Vec<u8>>(RAW_FRAME_CHANNEL_CAPACITY);

            let (cancel_tx, cancel_rx) = watch::channel(false);

            let channel_owner = channel.clone();
            let read_failure = Arc::new(std::sync::Mutex::new(None));

            // Spawn write loop
            let channel_write = channel.clone();
            let write_cancel = cancel_rx.clone();
            let write_handle = tokio::spawn(async move {
                Self::write_loop(channel_write, peer_rx, peer_raw_rx, write_cancel).await;
            });

            // Spawn read loop
            let channel_read = channel;
            let read_cancel = cancel_rx;
            let inbound_tx_clone = inbound_tx.clone();
            let bytes_received_clone = Arc::clone(&bytes_received);
            let wire_sink_clone = Arc::clone(&peer_candidate_wire_sink);
            let inbound_per_peer_limiter_clone = Arc::clone(&inbound_per_peer_limiter);
            let read_failure_clone = Arc::clone(&read_failure);
            let read_handle = tokio::spawn(async move {
                Self::read_loop(
                    node_id,
                    channel_read,
                    inbound_tx_clone,
                    bytes_received_clone,
                    wire_sink_clone,
                    inbound_per_peer_limiter_clone,
                    consensus_origin,
                    read_cancel,
                    read_failure_clone,
                )
                .await;
            });

            let retirement = Arc::new(PeerRetirement {
                session_id: NEXT_PEER_SESSION_ID.fetch_add(1, Ordering::Relaxed),
                channel: channel_owner,
                cancel_tx,
                tasks: tokio::sync::Mutex::new(PeerLoopTasks {
                    reader: Some(read_handle),
                    writer: Some(write_handle),
                    reader_outcome: None,
                    writer_outcome: None,
                }),
                loop_failure: std::sync::Mutex::new(None),
                read_failure,
                monitor: tokio::sync::Mutex::new(None),
            });

            // Register peer connection
            let conn = PeerConnection {
                node_id,
                tx: peer_tx,
                raw_tx: peer_raw_tx,
                retirement: Arc::clone(&retirement),
            };

            {
                let mut monitor = retirement
                    .monitor
                    .try_lock()
                    .expect("new peer monitor slot is not contended");
                *monitor = Some(tokio::spawn(Self::monitor_peer_reader(
                    node_id,
                    Arc::clone(&peers),
                    Arc::clone(&connections_current),
                    Arc::clone(&retirement),
                )));
            }

            {
                registry.registering.remove(&node_id);
                registry.candidates.remove(&node_id);
                registry.active.insert(node_id, conn);
                connections_current.store(registry.active.len() as u64, Ordering::Relaxed);
                reservation.armed = false;
            }
        }
        #[cfg(test)]
        {
            let pause = peers.write().after_publish.take();
            if let Some(pause) = pause {
                pause.wait().await;
            }
        }

        println!("[P2P] Peer {:?} connected", node_id);
        Ok(())
    }

    async fn monitor_peer_reader(
        node_id: NodeId,
        peers: Arc<RwLock<PeerRegistry>>,
        connections_current: Arc<AtomicU64>,
        retirement: Arc<PeerRetirement>,
    ) -> Result<(), String> {
        let reader = {
            let mut tasks = retirement.tasks.lock().await;
            tasks.reader.take()
        };
        let Some(reader) = reader else {
            return Ok(());
        };
        let outcome = TaskOutcome::from_join(reader.await);
        {
            let mut tasks = retirement.tasks.lock().await;
            if let TaskOutcome::Failed(error) = &outcome {
                retirement.record_loop_failure(format!("peer read loop: {error}"));
                let mut failure = retirement.read_failure.lock().unwrap();
                if failure.is_none() {
                    *failure = Some(format!("peer read loop failed: {error}"));
                }
            }
            tasks.reader_outcome = Some(outcome);
        }

        let failure = retirement.read_failure.lock().unwrap().clone();
        let Some(failure) = failure else {
            return Ok(());
        };

        #[cfg(test)]
        {
            let pause = peers.write().before_fatal_retirement.take();
            if let Some(pause) = pause {
                pause.wait().await;
            }
        }

        let owns_retirement =
            Self::mark_failed_peer_retiring(node_id, &peers, &connections_current, &retirement);
        if !owns_retirement {
            return Ok(());
        }

        let result = tokio::time::timeout(PEER_RETIREMENT_TIMEOUT, retirement.finish())
            .await
            .map_err(|_| "peer fatal-read retirement timed out; ownership retained".to_owned())
            .and_then(|result| result);
        if let Err(error) = result {
            eprintln!(
                "[P2P] fatal read for {:?} left session {} in owned retirement: {}",
                node_id, retirement.session_id, error
            );
            return Err(error);
        }
        let mut registry = peers.write();
        if registry
            .retiring
            .get(&node_id)
            .is_some_and(|current| Arc::ptr_eq(current, &retirement))
        {
            registry.retiring.remove(&node_id);
        }
        eprintln!(
            "[P2P] retired session {} for {:?} after terminal read failure: {}",
            retirement.session_id, node_id, failure
        );
        Ok(())
    }

    fn mark_failed_peer_retiring(
        node_id: NodeId,
        peers: &Arc<RwLock<PeerRegistry>>,
        connections_current: &Arc<AtomicU64>,
        retirement: &Arc<PeerRetirement>,
    ) -> bool {
        let (owns_retirement, displaced) = {
            let mut registry = peers.write();
            if registry
                .active
                .get(&node_id)
                .is_some_and(|connection| Arc::ptr_eq(&connection.retirement, &retirement))
            {
                let connection = registry
                    .active
                    .remove(&node_id)
                    .expect("matching active peer was present");
                retirement.begin();
                registry.retiring.insert(node_id, Arc::clone(&retirement));
                connections_current.store(registry.active.len() as u64, Ordering::Relaxed);
                (true, Some(connection))
            } else if registry
                .retiring
                .get(&node_id)
                .is_some_and(|current| Arc::ptr_eq(current, &retirement))
            {
                retirement.begin();
                (true, None)
            } else {
                (false, None)
            }
        };
        if let Some(connection) = displaced {
            drop(connection.tx);
            drop(connection.raw_tx);
        }
        owns_retirement
    }

    /// Read loop: continuously read frames and push to inbound channel.
    ///
    /// # Run 079 peer-candidate wire dispatch
    ///
    /// Before each frame is handed to the existing length-prefixed
    /// `decode_frame` consensus/DAG/control demuxer, the first byte
    /// is peeked and compared against
    /// [`crate::pqc_peer_candidate_wire::DISCRIMINATOR_PEER_CANDIDATE_WIRE`]
    /// (`0x05`). Frames whose first byte matches are routed through
    /// the installed
    /// [`crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink`]
    /// (if any) or dropped cheaply (if none), and the read loop
    /// CONTINUES — they do NOT poison the connection. Frames whose
    /// first byte does NOT match fall through to the existing
    /// `decode_frame` path bit-for-bit, including the existing
    /// "break on decode error" close-connection policy for
    /// honest-traffic discriminators (`0x00`/`0x01`/`0x02`).
    async fn read_loop(
        source_peer: NodeId,
        channel: SecureChannelAsync,
        inbound_tx: mpsc::Sender<InboundP2pEnvelope>,
        bytes_received: Arc<AtomicU64>,
        peer_candidate_wire_sink: Arc<
            RwLock<Option<Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>>>,
        >,
        inbound_per_peer_limiter: Arc<
            RwLock<
                Option<
                    Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>,
                >,
            >,
        >,
        consensus_origin: Option<AuthenticatedConsensusOrigin>,
        mut cancel: watch::Receiver<bool>,
        read_failure: Arc<std::sync::Mutex<Option<String>>>,
    ) {
        let failure = tokio::select! {
            _ = cancel.changed() => None,
            failure = Self::read_loop_inner(
                source_peer,
                channel,
                inbound_tx,
                bytes_received,
                peer_candidate_wire_sink,
                inbound_per_peer_limiter,
                consensus_origin,
            ) => failure,
        };
        if let Some(failure) = failure {
            if !*cancel.borrow() {
                *read_failure.lock().unwrap() = Some(failure);
            }
        }
    }

    async fn read_loop_inner(
        source_peer: NodeId,
        channel: SecureChannelAsync,
        inbound_tx: mpsc::Sender<InboundP2pEnvelope>,
        bytes_received: Arc<AtomicU64>,
        peer_candidate_wire_sink: Arc<
            RwLock<Option<Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>>>,
        >,
        inbound_per_peer_limiter: Arc<
            RwLock<
                Option<
                    Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>,
                >,
            >,
        >,
        consensus_origin: Option<AuthenticatedConsensusOrigin>,
    ) -> Option<String> {
        loop {
            match channel.recv().await {
                Ok(frame_bytes) => {
                    bytes_received.fetch_add(frame_bytes.len() as u64, Ordering::Relaxed);

                    // Run 079: peek the first byte and route
                    // peer-candidate wire frames (`0x05`) to the
                    // installed sink (or cheap-drop) WITHOUT calling
                    // the existing decode_frame demuxer.
                    let sink_snapshot = peer_candidate_wire_sink.read().clone();
                    let decision = crate::pqc_peer_candidate_wire::read_loop_dispatch_peer_candidate_wire_frame_from_peer(
                        &frame_bytes,
                        sink_snapshot.as_ref(),
                        Some(source_peer),
                    );
                    if matches!(
                        decision,
                        crate::pqc_peer_candidate_wire::ReadLoopFrameDecision::ConsumedPeerCandidateWire,
                    ) {
                        continue;
                    }

                    match decode_frame(&frame_bytes) {
                        Ok(msg) => {
                            // Run 369: consult the deployed inbound per-peer
                            // message-rate limiter (if installed) AFTER the
                            // frame decodes to a structured `P2pMessage` and
                            // BEFORE it is forwarded to the demuxer/handlers.
                            // An over-budget frame is dropped (the read loop
                            // CONTINUES — a per-peer message-rate drop never
                            // tears down the connection) and the adapter bumps
                            // its own per-peer drop counter (and the existing
                            // `qbind_net_per_peer_drops_total{reason="rate_limit"}`
                            // metric if a handle is installed). The
                            // connection-rate limiter and its metric are never
                            // touched here. Default (no limiter installed)
                            // skips this block and preserves prior behavior.
                            let limiter_snapshot = inbound_per_peer_limiter.read().clone();
                            if let Some(limiter) = limiter_snapshot {
                                if !limiter.allow_node(&source_peer, std::time::Instant::now()) {
                                    continue;
                                }
                            }

                            // Run 418: tag every inbound structured frame with
                            // this connection's authenticated consensus origin
                            // (may be `None` for unauthenticated sessions). The
                            // origin is bound to the KEMTLS session, never
                            // derived from the frame payload.
                            let envelope = InboundP2pEnvelope::new(consensus_origin.clone(), msg);
                            if inbound_tx.send(envelope).await.is_err() {
                                return None; // Receiver dropped
                            }
                        }
                        Err(e) => {
                            eprintln!("[P2P] Frame decode error: {}", e);
                            return Some(format!("frame decode error: {e}"));
                        }
                    }
                }
                Err(e) => {
                    eprintln!("[P2P] Read error: {}", e);
                    return Some(format!("read error: {e}"));
                }
            }
        }
    }

    /// Write loop: receive messages from channel and write frames.
    ///
    /// # Run 080 raw-frame multiplexing
    ///
    /// The loop multiplexes two outbound channels via `tokio::select!`:
    /// the existing structured `mpsc::Receiver<P2pMessage>` (whose
    /// items are encoded through `encode_frame`) AND a new bounded
    /// `mpsc::Receiver<Vec<u8>>` carrying RAW already-framed bytes.
    ///
    /// Raw bytes are written to the secure channel verbatim — the
    /// transport does NOT inspect, re-encode, or re-frame them. The
    /// only production caller of the raw channel is the Run 080
    /// `LivePeerCandidateWirePublisher`, which enforces the wire
    /// frame's 5-byte length-prefixed framing AND the
    /// `MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES` cap BEFORE it ever
    /// reaches this loop.
    ///
    /// The loop exits when BOTH channels are closed (both `recv()`s
    /// return `None`). A single closed channel does NOT terminate
    /// the loop because legitimate Run 080 usage opens the raw
    /// channel for the lifetime of the connection while the
    /// structured channel keeps flowing consensus traffic (and vice
    /// versa).
    async fn write_loop(
        channel: SecureChannelAsync,
        rx: mpsc::Receiver<P2pMessage>,
        raw_rx: mpsc::Receiver<Vec<u8>>,
        mut cancel: watch::Receiver<bool>,
    ) {
        tokio::select! {
            _ = cancel.changed() => {},
            _ = Self::write_loop_inner(channel, rx, raw_rx) => {},
        }
    }

    async fn write_loop_inner(
        channel: SecureChannelAsync,
        mut rx: mpsc::Receiver<P2pMessage>,
        mut raw_rx: mpsc::Receiver<Vec<u8>>,
    ) {
        loop {
            tokio::select! {
                maybe_msg = rx.recv() => {
                    match maybe_msg {
                        Some(msg) => {
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
                        None => {
                            // Structured channel closed. Continue to
                            // drain raw frames until the raw channel
                            // is also closed.
                            if raw_rx.is_closed() {
                                break;
                            }
                            // Replace `rx` with a closed receiver
                            // (drop) so the next iteration only
                            // observes `raw_rx`.
                            // We use a future that never resolves
                            // by re-entering select: rx is now
                            // disabled by checking `is_closed`
                            // via a noop path below.
                            // Simpler: just drain raw_rx to
                            // completion in a tight loop here.
                            while let Some(raw) = raw_rx.recv().await {
                                if let Err(e) = channel.send(&raw).await {
                                    eprintln!("[P2P] Write error (raw): {}", e);
                                    return;
                                }
                            }
                            break;
                        }
                    }
                }
                maybe_raw = raw_rx.recv() => {
                    match maybe_raw {
                        Some(frame) => {
                            // Raw frame: write the bytes verbatim.
                            // The producer is responsible for
                            // discriminator + u32-BE length +
                            // payload framing (Run 080
                            // `encode_peer_candidate_wire_frame`).
                            if let Err(e) = channel.send(&frame).await {
                                eprintln!("[P2P] Write error (raw): {}", e);
                                break;
                            }
                        }
                        None => {
                            // Raw channel closed. Continue to drain
                            // the structured channel to completion.
                            if rx.is_closed() {
                                break;
                            }
                            while let Some(msg) = rx.recv().await {
                                match encode_frame(&msg) {
                                    Ok(frame) => {
                                        if let Err(e) = channel.send(&frame).await {
                                            eprintln!("[P2P] Write error: {}", e);
                                            return;
                                        }
                                    }
                                    Err(e) => {
                                        eprintln!("[P2P] Frame encode error: {}", e);
                                        return;
                                    }
                                }
                            }
                            break;
                        }
                    }
                }
            }
        }
    }

    /// Subscribe to inbound messages.
    ///
    /// Returns a receiver that receives all inbound P2P message envelopes
    /// (message + authenticated transport origin) from all peers.
    pub async fn subscribe(&self) -> mpsc::Receiver<InboundP2pEnvelope> {
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

    /// Terminal registration fence followed by bounded cleanup attempts.
    /// Failures are logged and their owners retained for another shutdown
    /// attempt; returning does not certify complete socket reclamation.
    pub async fn shutdown(&mut self) {
        // The fence is terminal and precedes every cancellable await.
        // Cleanup owners stay in the registry until their joins succeed.
        let candidate_sockets = {
            let mut registry = self.peers.write();
            registry.closed = true;
            let active = std::mem::take(&mut registry.active);
            for (id, conn) in active {
                conn.retirement.begin();
                registry.retiring.insert(id, Arc::clone(&conn.retirement));
            }
            self.connections_current.store(0, Ordering::Relaxed);
            registry.candidates.values().cloned().collect::<Vec<_>>()
        };
        // Reserved candidates have no application workers yet, but their
        // sockets remain owned and independently interruptible until their
        // registration futures observe the fence or are dropped.
        for socket in candidate_sockets {
            if let Err(error) = socket.shutdown(std::net::Shutdown::Both) {
                if error.kind() != std::io::ErrorKind::NotConnected {
                    eprintln!(
                        "[P2P] candidate shutdown failed; reservation retains ownership: {error}"
                    );
                }
            }
        }
        let _ = self.shutdown_tx.send(());

        // Dial cancellation cannot erase ownership: established handshake
        // workers and registered peers are already retained by the registry.
        // Abort is only a request. Keep the handles in the service if this
        // shutdown future is cancelled before their completion is observed.
        for handle in self.dial_handles.read().iter() {
            handle.abort();
        }
        let dial_joins = std::future::poll_fn(|cx| {
            use std::future::Future;
            let mut handles = self.dial_handles.write();
            let mut index = 0;
            while index < handles.len() {
                match std::pin::Pin::new(&mut handles[index]).poll(cx) {
                    std::task::Poll::Ready(result) => {
                        drop(handles.swap_remove(index));
                        if let Err(error) = result {
                            if !error.is_cancelled() {
                                eprintln!("[P2P] dial task failed during shutdown: {error}");
                            }
                        }
                    }
                    std::task::Poll::Pending => index += 1,
                }
            }
            if handles.is_empty() {
                std::task::Poll::Ready(())
            } else {
                std::task::Poll::Pending
            }
        });
        if tokio::time::timeout(PEER_RETIREMENT_TIMEOUT, dial_joins)
            .await
            .is_err()
        {
            eprintln!("[P2P] dial task shutdown timed out; handles retained");
        }

        // The listener owns its inbound JoinSet (including handlers not yet
        // polled). Its shutdown aborts and observes those async tasks; any
        // blocking handshake work remains in the registry for the next pass.
        if let Some(handle) = self.listener_handle.as_mut() {
            match tokio::time::timeout(PEER_RETIREMENT_TIMEOUT, handle).await {
                Ok(result) => {
                    if let Err(error) = result {
                        eprintln!("[P2P] listener task failed during shutdown: {error}");
                    }
                    self.listener_handle = None;
                }
                Err(_) => eprintln!("[P2P] listener shutdown timed out; handle retained"),
            }
        }

        let (retiring, handshakes) = {
            let registry = self.peers.read();
            (registry.retiring.clone(), registry.handshakes.clone())
        };
        for (node_id, owner) in retiring {
            let result = tokio::time::timeout(PEER_RETIREMENT_TIMEOUT, owner.finish_and_wait())
                .await
                .map_err(|_| "peer retirement timed out".to_owned())
                .and_then(|result| result);
            if let Err(error) = result {
                eprintln!(
                    "[P2P] retained retirement for {:?} is incomplete: {}",
                    node_id, error
                );
            } else {
                let mut registry = self.peers.write();
                if registry
                    .retiring
                    .get(&node_id)
                    .is_some_and(|current| Arc::ptr_eq(current, &owner))
                {
                    registry.retiring.remove(&node_id);
                }
            }
        }
        for (id, owner) in handshakes {
            let result = async {
                match owner.shutdown_stream.shutdown(std::net::Shutdown::Both) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotConnected => {}
                    Err(error) => return Err(error.to_string()),
                }
                // The handshake's protocol refusal after socket shutdown is
                // expected. Only worker join failure makes cleanup incomplete.
                drop(owner.join().await?);
                Ok::<_, String>(())
            };
            match tokio::time::timeout(PEER_RETIREMENT_TIMEOUT, result).await {
                Ok(Ok(())) => {
                    let mut registry = self.peers.write();
                    if registry
                        .handshakes
                        .get(&id)
                        .is_some_and(|current| Arc::ptr_eq(current, &owner))
                    {
                        registry.handshakes.remove(&id);
                    }
                }
                outcome => eprintln!(
                    "[P2P] handshake {id} shutdown incomplete; owner retained: {outcome:?}"
                ),
            }
        }
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
            peer_candidate_wire_sink: Arc::clone(&self.peer_candidate_wire_sink),
            inbound_per_peer_limiter: Arc::clone(&self.inbound_per_peer_limiter),
            outbound_consensus_origins: Arc::clone(&self.outbound_consensus_origins),
        }
    }

    /// Active registry entries, not live sockets, authenticated origins, or
    /// pending handshakes/retirements. Updated with every active-map mutation
    /// under the registry write lock; it is an atomic instantaneous snapshot.
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

    // ------------------------------------------------------------------
    // Run 072 — production-honest synchronous P2P session-eviction hook.
    //
    // See `crate::p2p_session_eviction` for the policy contract. This
    // method is also surfaced via the
    // `crate::p2p_session_eviction::P2pSessionEvictor` impl below so a
    // future Run 073 `LiveTrustApplyContext` adapter can hold a
    // `&dyn P2pSessionEvictor` without depending on `TcpKemTlsP2pService`.
    // ------------------------------------------------------------------

    /// Run 072 helper: number of currently authenticated peer
    /// sessions in the registry. Cheap (single read lock).
    pub fn live_session_count(&self) -> usize {
        self.peers.read().active.len()
    }

    /// Run 072 entry point: synchronously evict every currently
    /// authenticated P2P session.
    ///
    /// Semantics: see `crate::p2p_session_eviction` module docs.
    ///
    /// Implementation notes (race safety):
    /// - The full peer map is drained under a single
    ///   `parking_lot::RwLock` write guard via `std::mem::take`. After
    ///   the guard drops, the listener / dialer may immediately
    ///   register new peers under fresh KEMTLS handshakes — these new
    ///   peers are NOT part of the eviction call's `attempted` count
    ///   and remain alive after this returns.
    /// - For each drained `PeerConnection`, we drop both outbound
    ///   senders and abort the async peer loops. Their join results are
    ///   later observed by the retained owner, while blocking-worker
    ///   completion and socket release remain separate observations.
    ///   A later replacement or service shutdown requests socket
    ///   shutdown and joins those workers before releasing the owner.
    /// - `connections_current` is reset to the post-eviction registry
    ///   size, observed under the same write guard.
    /// - The listener task handle and the B8 initial-dial-with-retry
    ///   handles are deliberately NOT touched — Run 072 is a session
    ///   eviction, not a transport shutdown.
    ///
    /// Returns:
    /// - `Ok(EvictionReport)` with `attempted == evicted` in the
    ///   happy path. The current implementation has no failure mode
    ///   short of a `RwLock` panic; partial failure would be reported
    ///   truthfully on a future implementation that gains one.
    /// - `Err(EvictionError::UnsupportedSessionEviction(_))` is never
    ///   produced by this implementation (the registry is always
    ///   available); it is reserved for stub transports like
    ///   `NullP2pService`.
    pub fn evict_all_sessions(
        &self,
        reason: crate::p2p_session_eviction::EvictionReason,
    ) -> Result<
        crate::p2p_session_eviction::EvictionReport,
        crate::p2p_session_eviction::EvictionError,
    > {
        let drained: Vec<(NodeId, PeerConnection)> = {
            let mut guard = self.peers.write();
            let taken: HashMap<NodeId, PeerConnection> = std::mem::take(&mut guard.active);
            for (node_id, conn) in &taken {
                conn.retirement.begin();
                guard
                    .retiring
                    .insert(*node_id, Arc::clone(&conn.retirement));
            }
            self.connections_current
                .store(guard.active.len() as u64, Ordering::Relaxed);
            taken.into_iter().collect()
        };
        let attempted = drained.len();
        #[cfg(test)]
        {
            let barriers = self.peers.write().after_eviction_snapshot.take();
            if let Some(barriers) = barriers {
                barriers.0.wait();
                barriers.1.wait();
            }
        }
        let mut evicted = 0usize;
        for (_node_id, conn) in drained {
            let PeerConnection {
                tx,
                raw_tx,
                retirement,
                ..
            } = conn;
            drop(tx);
            drop(raw_tx);
            if let Ok(tasks) = retirement.tasks.try_lock() {
                if let Some(reader) = tasks.reader.as_ref() {
                    reader.abort();
                }
                if let Some(writer) = tasks.writer.as_ref() {
                    writer.abort();
                }
            }
            evicted += 1;
        }
        // The eviction loop above has no fallible step in Run 072;
        // every drained peer is counted as evicted. `failed=0` is
        // truthful here. (If a future implementation gains a fallible
        // close path, it MUST flip individual entries into `failed`
        // instead of silently claiming success.)
        let failed = attempted - evicted;
        Ok(crate::p2p_session_eviction::EvictionReport::new(
            reason, attempted, evicted, failed,
        ))
    }
}

// ------------------------------------------------------------------
// Run 072 — `P2pSessionEvictor` impl forwards to the sync method.
//
// Living on the concrete type lets a future Run 073 adapter accept a
// generic `&dyn P2pSessionEvictor` (or `Arc<dyn P2pSessionEvictor>`)
// without coupling to `TcpKemTlsP2pService`.
// ------------------------------------------------------------------
impl crate::p2p_session_eviction::P2pSessionEvictor for TcpKemTlsP2pService {
    fn connected_session_count(&self) -> usize {
        self.live_session_count()
    }
    fn evict_all_sessions(
        &self,
        reason: crate::p2p_session_eviction::EvictionReason,
    ) -> Result<
        crate::p2p_session_eviction::EvictionReport,
        crate::p2p_session_eviction::EvictionError,
    > {
        TcpKemTlsP2pService::evict_all_sessions(self, reason)
    }
}

impl crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSender for TcpKemTlsP2pService {
    fn connected_peer_node_ids(&self) -> Vec<NodeId> {
        self.connected_peer_node_ids()
    }

    fn send_raw_frame_to_all_peers(
        &self,
        frame_bytes: Vec<u8>,
    ) -> crate::pqc_peer_candidate_wire::RawFrameSendReport {
        self.send_raw_frame_to_all_peers(frame_bytes)
    }

    fn send_raw_frame_to_selected_peers(
        &self,
        frame_bytes: Vec<u8>,
        selected_peers: &[NodeId],
    ) -> crate::pqc_peer_candidate_wire::RawFrameSendReport {
        self.send_raw_frame_to_selected_peers(frame_bytes, selected_peers)
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
    peers: Arc<RwLock<PeerRegistry>>,
    inbound_tx: mpsc::Sender<InboundP2pEnvelope>,
    connections_current: Arc<AtomicU64>,
    bytes_received: Arc<AtomicU64>,
    /// Run 079: shared optional wire sink (cloned from
    /// `TcpKemTlsP2pService::peer_candidate_wire_sink`). Threaded
    /// into `spawn_peer_handlers` so retry-dialed peers' read loops
    /// see the same sink the accept-loop sees. Default `None` →
    /// cheap-drop behaviour preserved bit-for-bit.
    peer_candidate_wire_sink:
        Arc<RwLock<Option<Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>>>>,
    /// Run 369: shared optional deployed inbound per-peer message-rate
    /// limiter (cloned from `TcpKemTlsP2pService::inbound_per_peer_limiter`).
    /// Threaded into `spawn_peer_handlers` so retry-dialed peers' read loops
    /// are subject to the same limiter the accept-loop peers are. Default
    /// `None` → prior behaviour preserved bit-for-bit.
    inbound_per_peer_limiter: Arc<
        RwLock<
            Option<Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>>,
        >,
    >,
    /// Run 418: static-peer outbound authenticated consensus origins keyed by
    /// dial address (cloned from
    /// `TcpKemTlsP2pService::outbound_consensus_origins`). Threaded into
    /// `spawn_peer_handlers` so retry-dialed peers tag inbound consensus frames
    /// with the configured origin (bound to handshake success). Empty by
    /// default → no origin, ingress gate fails closed.
    outbound_consensus_origins: Arc<RwLock<HashMap<String, AuthenticatedConsensusOrigin>>>,
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

        // Perform KEMTLS handshake (blocking, in spawn_blocking), surfacing the
        // ACTUAL verified server identity established by the handshake
        // (Run 418, F6).
        let channel = TcpKemTlsP2pService::tracked_dial(
            Arc::clone(&self.peers),
            &peer_addr,
            client_cfg.clone(),
        )
        .await?;
        let verified_server_identity = channel.verified_server_identity();

        // B7: NodeId derived from the peer's KEM pk (deterministic,
        // matches `derive_test_node_id_from_validator_id`).
        let node_id_bytes = derive_node_id_from_pubkey(&client_cfg.peer_kem_pk);
        let node_id = NodeId::new(node_id_bytes);

        // Run 418 (F6): derive the authenticated outbound consensus origin from
        // the ACTUAL verified server certificate identity, matched against the
        // configured authoritative mapping. Never mint the origin from the dial
        // address. (Mirrors `TcpKemTlsP2pService::dial_peer`.)
        let expected_origin: Option<AuthenticatedConsensusOrigin> = self
            .outbound_consensus_origins
            .read()
            .get(&peer_addr)
            .cloned();
        let consensus_origin: Option<AuthenticatedConsensusOrigin> = match expected_origin {
            Some(expected) => {
                let verified = verified_server_identity.ok_or_else(|| {
                    P2pTransportError::Handshake(format!(
                        "Run 418: dial {} completed without a verified server identity; \
                         refusing to mint an authenticated origin from the dial address",
                        peer_addr
                    ))
                })?;
                let verified_vid =
                    crate::p2p_node_builder::parse_test_validator_id_from_cert_validator_id(
                        &verified.validator_id,
                    );
                let node_matches = verified.node_id == *expected.node_id().as_bytes();
                let vid_matches = verified_vid == Some(expected.validator_id().as_u64());
                if !verified.authenticated || !node_matches || !vid_matches {
                    return Err(P2pTransportError::Handshake(format!(
                        "Run 418: verified server identity for {} does not match the configured \
                         authoritative mapping (authenticated={}, node_match={}, vid_match={}); \
                         rejecting session",
                        peer_addr, verified.authenticated, node_matches, vid_matches
                    )));
                }
                Some(AuthenticatedConsensusOrigin::new(
                    NodeId::new(verified.node_id),
                    expected.validator_id(),
                ))
            }
            None => None,
        };

        // Spawn read/write loops (same as `dial_peer`).
        TcpKemTlsP2pService::spawn_peer_handlers(
            node_id,
            channel,
            Arc::clone(&self.peers),
            self.inbound_tx.clone(),
            Arc::clone(&self.connections_current),
            Arc::clone(&self.bytes_received),
            Arc::clone(&self.peer_candidate_wire_sink),
            Arc::clone(&self.inbound_per_peer_limiter),
            consensus_origin,
        )
        .await?;

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
        for (node_id, conn) in peers.active.iter() {
            if let Err(e) = conn.tx.try_send(msg.clone()) {
                eprintln!("[P2P] Failed to broadcast to {:?}: {}", node_id, e);
            }
        }
    }

    fn send_to(&self, peer: NodeId, msg: P2pMessage) {
        let peers = self.peers.read();
        if let Some(conn) = peers.active.get(&peer) {
            if let Err(e) = conn.tx.try_send(msg) {
                eprintln!("[P2P] Failed to send to {:?}: {}", peer, e);
            }
        }
    }

    fn local_node_id(&self) -> NodeId {
        self.local_node_id
    }

    fn connected_peers(&self) -> Vec<NodeId> {
        self.peers.read().active.keys().copied().collect()
    }
}

#[cfg(test)]
mod peer_retirement_tests {
    use super::*;
    use crate::secure_channel::{encrypted_write_tests::pair_channels, ChannelError};
    use std::future::Future;

    #[derive(Clone)]
    struct Harness {
        peers: Arc<RwLock<PeerRegistry>>,
        inbound_tx: mpsc::Sender<InboundP2pEnvelope>,
        inbound_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<InboundP2pEnvelope>>>,
        connections_current: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        peer_candidate_wire_sink: Arc<
            RwLock<Option<Arc<dyn crate::pqc_peer_candidate_wire::PeerCandidateWireFrameSink>>>,
        >,
        inbound_per_peer_limiter: Arc<
            RwLock<
                Option<
                    Arc<crate::deployed_inbound_per_peer_limiter::DeployedInboundPerPeerLimiter>,
                >,
            >,
        >,
    }

    impl Harness {
        fn for_service(service: &TcpKemTlsP2pService) -> Self {
            Self {
                peers: Arc::clone(&service.peers),
                inbound_tx: service.inbound_tx.clone(),
                inbound_rx: Arc::clone(&service.inbound_rx),
                connections_current: Arc::clone(&service.connections_current),
                bytes_received: Arc::clone(&service.bytes_received),
                peer_candidate_wire_sink: Arc::clone(&service.peer_candidate_wire_sink),
                inbound_per_peer_limiter: Arc::clone(&service.inbound_per_peer_limiter),
            }
        }

        fn new(inbound_capacity: usize) -> Self {
            let (inbound_tx, inbound_rx) = mpsc::channel(inbound_capacity);
            Self {
                peers: Arc::new(RwLock::new(PeerRegistry::default())),
                inbound_tx,
                inbound_rx: Arc::new(tokio::sync::Mutex::new(inbound_rx)),
                connections_current: Arc::new(AtomicU64::new(0)),
                bytes_received: Arc::new(AtomicU64::new(0)),
                peer_candidate_wire_sink: Arc::new(RwLock::new(None)),
                inbound_per_peer_limiter: Arc::new(RwLock::new(None)),
            }
        }

        async fn register(
            &self,
            node_id: NodeId,
            channel: SecureChannel,
        ) -> Result<(), P2pTransportError> {
            TcpKemTlsP2pService::spawn_peer_handlers(
                node_id,
                channel,
                Arc::clone(&self.peers),
                self.inbound_tx.clone(),
                Arc::clone(&self.connections_current),
                Arc::clone(&self.bytes_received),
                Arc::clone(&self.peer_candidate_wire_sink),
                Arc::clone(&self.inbound_per_peer_limiter),
                None,
            )
            .await
        }

        fn session_id(&self, node_id: NodeId) -> u64 {
            self.peers.read().active[&node_id].retirement.session_id
        }

        async fn receive(&self) -> InboundP2pEnvelope {
            tokio::time::timeout(Duration::from_secs(3), self.inbound_rx.lock().await.recv())
                .await
                .expect("inbound message should arrive")
                .expect("inbound channel remains open")
        }
    }

    fn node_id(byte: u8) -> NodeId {
        NodeId::new([byte; 32])
    }

    fn service() -> TcpKemTlsP2pService {
        let (client, server) = crate::secure_channel::encrypted_write_tests::channel_configs();
        TcpKemTlsP2pService::new(
            node_id(99),
            NetworkTransportConfig::default(),
            Arc::clone(&server.handshake_config.crypto),
            server,
            client,
        )
        .unwrap()
    }

    fn assert_registry_count(harness: &Harness, expected: u64) {
        let registry = harness.peers.read();
        assert_eq!(registry.active.len() as u64, expected);
        assert_eq!(
            harness.connections_current.load(Ordering::Relaxed),
            expected
        );
        assert!(registry
            .active
            .keys()
            .all(|id| !registry.retiring.contains_key(id)));
    }

    fn heartbeat(view: u64) -> P2pMessage {
        P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat {
            view,
            timestamp_ms: view,
        })
    }

    fn heartbeat_frame(view: u64) -> Vec<u8> {
        encode_frame(&heartbeat(view)).expect("encode heartbeat")
    }

    #[tokio::test]
    async fn observed_eof_retires_registered_session_and_joins_workers() {
        let harness = Harness::new(8);
        let id = node_id(17);
        let (local, remote) = pair_channels(true);
        harness.register(id, local).await.unwrap();
        let owner = Arc::clone(&harness.peers.read().active[&id].retirement);
        drop(remote);

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if owner.read_failure.lock().unwrap().is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("registered read loop should observe remote EOF");

        owner.finish_and_wait().await.unwrap();
        assert!(!harness.peers.read().active.contains_key(&id));
        assert!(!harness.peers.read().retiring.contains_key(&id));
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 0);
        assert!(matches!(
            owner.tasks.lock().await.reader_outcome,
            Some(TaskOutcome::Completed)
        ));
        let workers = owner.channel.worker_outcomes_for_test().await;
        assert!(workers.0.is_some());
        assert!(workers.1.is_some());
        assert!(owner
            .read_failure
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|failure| failure.contains("read error")));
    }

    #[tokio::test]
    async fn observed_frame_decode_failure_retires_and_closes_remote_socket() {
        let harness = Harness::new(8);
        let id = node_id(18);
        let (local, remote) = pair_channels(true);
        harness.register(id, local).await.unwrap();
        let owner = Arc::clone(&harness.peers.read().active[&id].retirement);

        let (remote, result) = send_app_and_return(remote, vec![0xff, 0, 0, 0, 0]).await;
        result.unwrap();

        tokio::time::timeout(Duration::from_secs(3), async {
            while owner.read_failure.lock().unwrap().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("registered read loop should observe frame-decode failure");
        owner.finish_and_wait().await.unwrap();
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 0);
        assert!(owner
            .read_failure
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|failure| failure.contains("frame decode error")));
        expect_remote_eof(remote).await;
    }

    #[tokio::test]
    async fn idle_healthy_and_unrelated_peer_remain_registered_after_fatal_read() {
        let harness = Harness::new(8);
        let broken_id = node_id(19);
        let healthy_id = node_id(20);
        let (broken_local, broken_remote) = pair_channels(true);
        harness.register(broken_id, broken_local).await.unwrap();
        let broken_owner = Arc::clone(&harness.peers.read().active[&broken_id].retirement);
        let (healthy_local, healthy_remote) = pair_channels(true);
        harness.register(healthy_id, healthy_local).await.unwrap();
        let healthy_session = harness.session_id(healthy_id);

        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_registry_count(&harness, 2);
        assert!(broken_owner.read_failure.lock().unwrap().is_none());
        let (healthy_remote, result) =
            send_app_and_return(healthy_remote, heartbeat_frame(21)).await;
        result.unwrap();
        assert!(matches!(
            harness.receive().await.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 21, .. })
        ));

        drop(broken_remote);
        tokio::time::timeout(Duration::from_secs(3), async {
            while broken_owner.read_failure.lock().unwrap().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("broken reader should observe EOF");
        broken_owner.finish_and_wait().await.unwrap();
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 1);
        assert_eq!(harness.session_id(healthy_id), healthy_session);
        let (healthy_remote, result) =
            send_app_and_return(healthy_remote, heartbeat_frame(22)).await;
        result.unwrap();
        assert!(matches!(
            harness.receive().await.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 22, .. })
        ));
        assert_eq!(harness.session_id(healthy_id), healthy_session);
        drop(healthy_remote);
    }

    #[tokio::test]
    async fn delayed_old_failure_cannot_retire_replacement_session() {
        let harness = Harness::new(8);
        let id = node_id(23);
        let pause = Arc::new(RegistrationPause::default());
        harness.peers.write().before_fatal_retirement = Some(Arc::clone(&pause));
        let (old_local, old_remote) = pair_channels(true);
        harness.register(id, old_local).await.unwrap();
        let old_owner = Arc::clone(&harness.peers.read().active[&id].retirement);
        let old_session = old_owner.session_id;
        drop(old_remote);
        pause.entered.notified().await;

        let replacement = {
            let harness = harness.clone();
            tokio::spawn(async move {
                let (channel, remote) = pair_channels(true);
                (harness.register(id, channel).await, remote)
            })
        };
        tokio::time::timeout(Duration::from_secs(3), async {
            while !harness.peers.read().registering.contains(&id) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("replacement should reserve the NodeId");
        pause.release.notify_one();
        let (result, new_remote) = replacement.await.unwrap();
        result.unwrap();

        let new_session = harness.session_id(id);
        assert_ne!(old_session, new_session);
        assert!(!TcpKemTlsP2pService::mark_failed_peer_retiring(
            id,
            &harness.peers,
            &harness.connections_current,
            &old_owner,
        ));
        assert_registry_count(&harness, 1);
        let (new_remote, result) = send_app_and_return(new_remote, heartbeat_frame(24)).await;
        result.unwrap();
        assert!(matches!(
            harness.receive().await.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 24, .. })
        ));
        assert_eq!(harness.session_id(id), new_session);
        drop(new_remote);
    }

    #[tokio::test]
    async fn fatal_read_cleanup_failure_stays_owned_and_replacement_retries() {
        let harness = Harness::new(8);
        let id = node_id(25);
        let (local, remote) = pair_channels(true);
        harness.register(id, local).await.unwrap();
        let owner = Arc::clone(&harness.peers.read().active[&id].retirement);
        owner.channel.fail_shutdown_for_test(true);
        let (remote, result) = send_app_and_return(remote, vec![0xff, 0, 0, 0, 0]).await;
        result.unwrap();

        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if owner
                    .monitor
                    .lock()
                    .await
                    .as_ref()
                    .is_some_and(JoinHandle::is_finished)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed cleanup attempt should finish and remain observable");
        assert!(owner.finish_and_wait().await.is_err());
        assert!(!harness.peers.read().active.contains_key(&id));
        assert!(Arc::ptr_eq(&harness.peers.read().retiring[&id], &owner));
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 0);

        owner.channel.fail_shutdown_for_test(false);
        let (replacement, _) = pair_channels(true);
        harness.register(id, replacement).await.unwrap();
        assert!(harness.peers.read().retiring.get(&id).is_none());
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 1);
        expect_remote_eof(remote).await;
    }

    #[tokio::test]
    async fn fatal_read_racing_shutdown_keeps_owner_across_cancelled_cleanup() {
        let mut service = service();
        let harness = Harness::for_service(&service);
        let id = node_id(26);
        let pause = Arc::new(RegistrationPause::default());
        harness.peers.write().before_fatal_retirement = Some(Arc::clone(&pause));
        let (local, remote) = pair_channels(true);
        harness.register(id, local).await.unwrap();
        let owner = Arc::clone(&harness.peers.read().active[&id].retirement);
        drop(remote);
        pause.entered.notified().await;

        assert!(
            tokio::time::timeout(Duration::from_millis(25), service.shutdown())
                .await
                .is_err()
        );
        assert!(harness.peers.read().closed);
        assert!(!harness.peers.read().active.contains_key(&id));
        assert!(Arc::ptr_eq(&harness.peers.read().retiring[&id], &owner));
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 0);

        pause.release.notify_one();
        service.shutdown().await;
        assert!(harness.peers.read().retiring.is_empty());
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn fatal_read_racing_eviction_preserves_later_unrelated_peer() {
        let service = service();
        let harness = Harness::for_service(&service);
        let failed_id = node_id(27);
        let later_id = node_id(28);
        let pause = Arc::new(RegistrationPause::default());
        harness.peers.write().before_fatal_retirement = Some(Arc::clone(&pause));
        let (local, remote) = pair_channels(true);
        harness.register(failed_id, local).await.unwrap();
        let old_owner = Arc::clone(&harness.peers.read().active[&failed_id].retirement);
        drop(remote);
        pause.entered.notified().await;

        let report = service
            .evict_all_sessions(crate::p2p_session_eviction::EvictionReason::OperatorTest)
            .unwrap();
        assert_eq!((report.attempted, report.evicted, report.failed), (1, 1, 0));
        assert!(Arc::ptr_eq(
            &harness.peers.read().retiring[&failed_id],
            &old_owner
        ));

        let (later, later_remote) = pair_channels(true);
        harness.register(later_id, later).await.unwrap();
        assert_registry_count(&harness, 1);
        let later_session = harness.session_id(later_id);
        pause.release.notify_one();
        old_owner.finish_and_wait().await.unwrap();
        assert!(!harness.peers.read().retiring.contains_key(&failed_id));
        let (later_remote, result) = send_app_and_return(later_remote, heartbeat_frame(29)).await;
        result.unwrap();
        assert!(matches!(
            harness.receive().await.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 29, .. })
        ));
        assert_eq!(harness.session_id(later_id), later_session);
        drop(later_remote);
    }

    #[tokio::test]
    async fn queue_blocked_read_does_not_claim_fatal_error_observed() {
        let harness = Harness::new(1);
        let id = node_id(30);
        let (local, remote) = pair_channels(true);
        harness.register(id, local).await.unwrap();
        let owner = Arc::clone(&harness.peers.read().active[&id].retirement);
        let frame_len = heartbeat_frame(0).len() as u64;
        let (remote, result) = send_app_and_return(remote, heartbeat_frame(0)).await;
        result.unwrap();
        let (remote, result) = send_app_and_return(remote, heartbeat_frame(1)).await;
        result.unwrap();
        drop(remote);

        tokio::time::timeout(Duration::from_secs(3), async {
            while harness.bytes_received.load(Ordering::Relaxed) < frame_len * 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("second frame should be held behind the full inbound queue");
        assert!(owner.read_failure.lock().unwrap().is_none());
        assert_registry_count(&harness, 1);

        assert!(matches!(
            harness.receive().await.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 0, .. })
        ));
        assert!(matches!(
            harness.receive().await.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 1, .. })
        ));
        tokio::time::timeout(Duration::from_secs(3), async {
            while owner.read_failure.lock().unwrap().is_none() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("reader should observe EOF after downstream queue drains");
        owner.finish_and_wait().await.unwrap();
        assert_eq!(harness.connections_current.load(Ordering::Relaxed), 0);
    }

    async fn send_app(channel: SecureChannel, bytes: Vec<u8>) -> Result<(), ChannelError> {
        tokio::task::spawn_blocking(move || {
            let mut channel = channel;
            channel.send_app(&bytes)
        })
        .await
        .expect("loopback sender task")
    }

    async fn send_app_and_return(
        channel: SecureChannel,
        bytes: Vec<u8>,
    ) -> (SecureChannel, Result<(), ChannelError>) {
        tokio::task::spawn_blocking(move || {
            let mut channel = channel;
            let result = channel.send_app(&bytes);
            (channel, result)
        })
        .await
        .expect("loopback sender task")
    }

    async fn expect_remote_eof(channel: SecureChannel) {
        let result = tokio::time::timeout(
            Duration::from_secs(3),
            tokio::task::spawn_blocking(move || {
                let mut channel = channel;
                channel.recv_app()
            }),
        )
        .await
        .expect("retirement should interrupt remote socket read")
        .expect("remote reader task");
        assert!(matches!(result, Err(ChannelError::Io(_))));
    }

    #[tokio::test]
    async fn replacement_retires_only_displaced_session_and_preserves_new_and_other_peers() {
        let harness = Harness::new(1);
        let id = node_id(1);
        let other_id = node_id(2);
        let (old_local, old_remote) = pair_channels(true);
        harness.register(id, old_local).await.unwrap();
        let old_retirement = Arc::clone(&harness.peers.read().active[&id].retirement);
        let old_session = old_retirement.session_id;
        let (old_sender, old_raw_sender) = {
            let connection = &harness.peers.read().active[&id];
            (connection.tx.clone(), connection.raw_tx.clone())
        };
        old_sender.send(heartbeat(9)).await.unwrap();
        let (old_remote, progressed_frame) = tokio::task::spawn_blocking(move || {
            let mut remote = old_remote;
            let frame = remote.recv_app();
            (remote, frame)
        })
        .await
        .expect("old peer reader");
        let progressed_frame = progressed_frame.expect("already-progressed send is delivered");
        assert!(matches!(
            decode_frame(&progressed_frame).unwrap(),
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 9, .. })
        ));

        let (other_local, other_remote) = pair_channels(true);
        harness.register(other_id, other_local).await.unwrap();
        let other_session = harness.session_id(other_id);

        let (new_local, new_remote) = pair_channels(true);
        harness.register(id, new_local).await.unwrap();
        let new_session = harness.session_id(id);
        assert_ne!(old_session, new_session);
        assert_eq!(harness.session_id(other_id), other_session);
        assert!(!harness.peers.read().retiring.contains_key(&id));

        expect_remote_eof(old_remote).await;
        assert!(old_sender.send(heartbeat(10)).await.is_err());
        assert!(old_raw_sender.send(vec![0]).await.is_err());

        send_app(other_remote, heartbeat_frame(20)).await.unwrap();
        let other_message = harness.receive().await;
        assert!(matches!(
            other_message.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 20, .. })
        ));

        let (new_remote, result) = send_app_and_return(new_remote, heartbeat_frame(30)).await;
        result.unwrap();
        let new_message = harness.receive().await;
        assert!(matches!(
            new_message.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 30, .. })
        ));

        // A late completion observed through the old owner cannot mutate the
        // newer registry entry because retirement is session-specific.
        old_retirement.finish_and_wait().await.unwrap();
        assert_eq!(harness.session_id(id), new_session);
        drop(new_remote);
    }

    #[tokio::test]
    async fn active_read_and_queued_inbound_work_are_interrupted_without_replay() {
        let harness = Harness::new(1);
        let id = node_id(3);
        let (old_local, old_remote) = pair_channels(true);
        harness.register(id, old_local).await.unwrap();
        let old_owner = Arc::clone(&harness.peers.read().active[&id].retirement);
        let old_owner_weak = Arc::downgrade(&old_owner);
        drop(old_owner);

        let sender = tokio::task::spawn_blocking(move || {
            let mut remote = old_remote;
            let mut sent = 0;
            for view in 0..96 {
                if remote.send_app(&heartbeat_frame(view)).is_err() {
                    break;
                }
                sent += 1;
            }
            (remote, sent)
        });

        let frame_len = heartbeat_frame(0).len() as u64;
        tokio::time::timeout(Duration::from_secs(3), async {
            while harness.bytes_received.load(Ordering::Relaxed) < frame_len * 2 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("read loop should block on the full inbound queue");
        let (old_remote, sent) = sender.await.expect("sender task");
        assert!(sent >= 2);
        let old_sender = harness.peers.read().active[&id].tx.clone();
        let mut queued = 0;
        for view in 1_000..1_064 {
            if old_sender.try_send(heartbeat(view)).is_ok() {
                queued += 1;
            }
        }
        assert!(queued > 0);

        let (new_local, new_remote) = pair_channels(true);
        harness.register(id, new_local).await.unwrap();
        assert!(old_owner_weak.upgrade().is_none());
        assert!(old_sender.send(heartbeat(2_000)).await.is_err());
        let (old_frames, remote_error) = tokio::task::spawn_blocking(move || {
            let mut remote = old_remote;
            let mut frames = Vec::new();
            loop {
                match remote.recv_app() {
                    Ok(frame) => frames.push(frame),
                    Err(error) => return (frames, error),
                }
            }
        })
        .await
        .expect("old peer reader");
        assert!(matches!(remote_error, ChannelError::Io(_)));
        assert!(old_frames.len() <= queued);
        for frame in old_frames {
            assert!(matches!(
                decode_frame(&frame).unwrap(),
                P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view, .. })
                    if (1_000..1_064).contains(&view)
            ));
        }

        let first = harness.receive().await;
        assert!(matches!(
            first.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 0, .. })
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(100), harness.receive())
                .await
                .is_err()
        );

        send_app(new_remote, heartbeat_frame(100)).await.unwrap();
        let replacement_message = harness.receive().await;
        assert!(matches!(
            replacement_message.message,
            P2pMessage::Control(crate::p2p::ControlMsg::Heartbeat { view: 100, .. })
        ));
    }

    #[tokio::test]
    async fn concurrent_replacement_is_refused_while_owned_cleanup_is_in_progress() {
        let harness = Harness::new(8);
        let id = node_id(4);
        let (old_local, old_remote) = pair_channels(true);
        harness.register(id, old_local).await.unwrap();
        let old_retirement = Arc::clone(&harness.peers.read().active[&id].retirement);
        let old_session = old_retirement.session_id;
        let held_tasks = old_retirement.tasks.lock().await;

        let first_harness = harness.clone();
        let first = tokio::spawn(async move {
            let (channel, remote) = pair_channels(true);
            (first_harness.register(id, channel).await, remote)
        });
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if harness.peers.read().registering.contains(&id) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first replacement reserves identity");

        let (second_channel, _second_remote) = pair_channels(true);
        let second = harness.register(id, second_channel).await;
        assert!(matches!(
            second,
            Err(P2pTransportError::SessionRetirement(_))
        ));

        drop(held_tasks);
        let (first_result, first_remote) = first.await.expect("first replacement task");
        first_result.unwrap();
        let newest_session = harness.session_id(id);
        assert_ne!(newest_session, old_session);
        expect_remote_eof(old_remote).await;
        old_retirement.finish().await.unwrap();
        assert_eq!(harness.session_id(id), newest_session);
        assert_eq!(harness.peers.read().retiring.len(), 0);
        drop(first_remote);
    }

    #[tokio::test]
    async fn failed_shutdown_remains_tracked_and_blocks_replacement_until_retry_succeeds() {
        let harness = Harness::new(8);
        let id = node_id(5);
        let other_id = node_id(6);
        let (old_local, old_remote) = pair_channels(true);
        harness.register(id, old_local).await.unwrap();
        let old = Arc::clone(&harness.peers.read().active[&id].retirement);
        let old_session = old.session_id;
        old.channel.fail_shutdown_for_test(true);

        let (other_local, _other_remote) = pair_channels(true);
        harness.register(other_id, other_local).await.unwrap();
        let other_session = harness.session_id(other_id);

        let (rejected_local, _rejected_remote) = pair_channels(true);
        assert!(matches!(
            harness.register(id, rejected_local).await,
            Err(P2pTransportError::SessionRetirement(_))
        ));
        assert_eq!(harness.peers.read().retiring[&id].session_id, old_session);
        assert!(!harness.peers.read().active.contains_key(&id));
        assert_eq!(harness.session_id(other_id), other_session);

        let (also_rejected_local, _also_rejected_remote) = pair_channels(true);
        assert!(matches!(
            harness.register(id, also_rejected_local).await,
            Err(P2pTransportError::SessionRetirement(_))
        ));
        assert_eq!(harness.peers.read().retiring.len(), 1);
        assert_eq!(harness.peers.read().retiring[&id].session_id, old_session);

        old.channel.fail_shutdown_for_test(false);
        let (replacement_local, _replacement_remote) = pair_channels(true);
        harness.register(id, replacement_local).await.unwrap();
        let replacement_session = harness.session_id(id);
        assert_ne!(replacement_session, old_session);
        assert!(!harness.peers.read().retiring.contains_key(&id));
        expect_remote_eof(old_remote).await;
        assert_eq!(harness.session_id(other_id), other_session);
    }

    #[tokio::test]
    async fn peer_join_failure_survives_timeout_and_cancelled_retry() {
        for timed_out in [true, false] {
            let harness = Harness::new(8);
            let id = node_id(7);
            let (local, remote) = pair_channels(true);
            harness.register(id, local).await.unwrap();
            let owner = Arc::clone(&harness.peers.read().active[&id].retirement);
            owner.begin();
            owner.finish().await.unwrap();
            expect_remote_eof(remote).await;
            let (release, pending) = tokio::sync::oneshot::channel::<()>();
            let reader = tokio::spawn(async { panic!("retained peer failure") });
            while !reader.is_finished() {
                tokio::task::yield_now().await;
            }
            {
                let mut tasks = owner.tasks.lock().await;
                tasks.reader = Some(reader);
                tasks.writer = Some(tokio::spawn(async move {
                    pending.await.unwrap();
                }));
            }
            let mut attempt = Box::pin(owner.finish());
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(attempt.as_mut().poll(&mut cx).is_pending());
            if timed_out {
                assert!(tokio::time::timeout(Duration::from_millis(20), attempt)
                    .await
                    .is_err());
            } else {
                drop(attempt);
            }
            assert!(owner.tasks.lock().await.reader.is_none());
            assert!(
                matches!(owner.tasks.lock().await.reader_outcome, Some(TaskOutcome::Failed(ref error))
                if error.contains("retained peer failure"))
            );
            release.send(()).unwrap();
            assert!(owner
                .finish()
                .await
                .unwrap_err()
                .contains("retained peer failure"));
            let (candidate, candidate_remote) = pair_channels(true);
            let result = harness.register(id, candidate).await;
            assert!(
                matches!(result, Err(P2pTransportError::SessionRetirement(ref error))
                if error.contains("retained peer failure"))
            );
            expect_remote_eof(candidate_remote).await;
            assert!(!harness.peers.read().active.contains_key(&id));
            assert!(Arc::ptr_eq(&harness.peers.read().retiring[&id], &owner));
        }
    }

    #[tokio::test]
    async fn blocking_failure_after_interrupted_retirement_refuses_replacement() {
        let harness = Harness::new(8);
        let id = node_id(8);
        let (local, remote) = pair_channels(true);
        harness.register(id, local).await.unwrap();
        let owner = Arc::clone(&harness.peers.read().active[&id].retirement);
        owner.begin();
        owner.finish().await.unwrap();
        let release = owner.channel.inject_worker_failure_for_test().await;
        let mut attempt = Box::pin(owner.finish());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(attempt.as_mut().poll(&mut cx).is_pending());
        assert!(tokio::time::timeout(Duration::from_millis(20), attempt)
            .await
            .is_err());
        release.send(()).unwrap();
        assert!(owner
            .finish()
            .await
            .unwrap_err()
            .contains("retained blocking failure"));
        let (candidate, candidate_remote) = pair_channels(true);
        let error = harness.register(id, candidate).await.unwrap_err();
        assert!(error.to_string().contains("retained blocking failure"));
        assert_registry_count(&harness, 0);
        assert!(Arc::ptr_eq(&harness.peers.read().retiring[&id], &owner));
        expect_remote_eof(remote).await;
        expect_remote_eof(candidate_remote).await;
    }

    #[tokio::test]
    async fn shutdown_fences_inflight_registration_and_retains_cleanup_until_retry() {
        for fail in [false, true] {
            let mut service = service();
            let harness = Harness::for_service(&service);
            let id = node_id(9);
            let (local, remote) = pair_channels(true);
            harness.register(id, local).await.unwrap();
            let owner = Arc::clone(&harness.peers.read().active[&id].retirement);
            let held_tasks = owner.tasks.lock().await;
            owner.channel.fail_shutdown_for_test(fail);
            let mut shutdown = Box::pin(service.shutdown());
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            if fail {
                shutdown.as_mut().await;
            } else {
                assert!(shutdown.as_mut().poll(&mut cx).is_pending());
            }
            assert!(harness.peers.read().closed);
            assert!(Arc::ptr_eq(&harness.peers.read().retiring[&id], &owner));
            assert_registry_count(&harness, 0);
            let (candidate, candidate_remote) = pair_channels(true);
            assert!(harness.register(id, candidate).await.is_err());
            expect_remote_eof(candidate_remote).await;
            drop(held_tasks);
            if !fail {
                shutdown.await;
            } else {
                drop(shutdown);
            }
            assert_registry_count(&harness, 0);
            if fail {
                assert_eq!(harness.peers.read().retiring.len(), 1);
                owner.channel.fail_shutdown_for_test(false);
                service.shutdown().await;
            }
            assert!(harness.peers.read().retiring.is_empty());
            assert!(harness.peers.read().handshakes.is_empty());
            expect_remote_eof(remote).await;
            assert!(service.start().await.is_err());
        }
    }

    #[tokio::test]
    async fn reserved_registration_cannot_publish_after_shutdown() {
        let mut service = service();
        let harness = Harness::for_service(&service);
        let pause = Arc::new(RegistrationPause::default());
        harness.peers.write().before_publish = Some(Arc::clone(&pause));
        let (candidate, remote) = pair_channels(true);
        let registering = {
            let harness = harness.clone();
            tokio::spawn(async move { harness.register(node_id(10), candidate).await })
        };
        pause.entered.notified().await;
        assert_eq!(harness.peers.read().registering.len(), 1);
        service.shutdown().await;
        assert_registry_count(&harness, 0);
        assert_eq!(harness.peers.read().candidates.len(), 1);
        expect_remote_eof(remote).await;
        pause.release.notify_one();
        assert!(registering.await.unwrap().is_err());
        assert!(harness.peers.read().registering.is_empty());
        assert!(harness.peers.read().retiring.is_empty());
        assert!(harness.peers.read().candidates.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn published_count_cannot_wrap_when_replaced_before_caller_returns() {
        let harness = Harness::new(8);
        let pause = Arc::new(RegistrationPause::default());
        harness.peers.write().after_publish = Some(Arc::clone(&pause));
        let id = node_id(11);
        let (local, remote) = pair_channels(true);
        let registering = {
            let harness = harness.clone();
            tokio::spawn(async move { harness.register(id, local).await })
        };
        pause.entered.notified().await;
        assert_registry_count(&harness, 1);
        let (replacement, replacement_remote) = pair_channels(true);
        harness.register(id, replacement).await.unwrap();
        assert_registry_count(&harness, 1);
        expect_remote_eof(remote).await;
        pause.release.notify_one();
        registering.await.unwrap().unwrap();
        assert_registry_count(&harness, 1);
        drop(replacement_remote);
    }

    #[tokio::test]
    async fn shutdown_owns_published_session_before_registration_returns() {
        let mut service = service();
        let harness = Harness::for_service(&service);
        let pause = Arc::new(RegistrationPause::default());
        harness.peers.write().after_publish = Some(Arc::clone(&pause));
        let (local, remote) = pair_channels(true);
        let registering = {
            let harness = harness.clone();
            tokio::spawn(async move { harness.register(node_id(14), local).await })
        };
        pause.entered.notified().await;
        assert_registry_count(&harness, 1);
        service.shutdown().await;
        assert_registry_count(&harness, 0);
        expect_remote_eof(remote).await;
        pause.release.notify_one();
        // Publication preceded shutdown. Successful registration is not a
        // delivery/liveness acknowledgement after that linearization point.
        registering.await.unwrap().unwrap();
        assert_registry_count(&harness, 0);
        assert!(harness.peers.read().retiring.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn eviction_snapshot_preserves_later_admission_and_count() {
        let service = Arc::new(service());
        let harness = Harness::for_service(&service);
        let (local, remote) = pair_channels(true);
        harness.register(node_id(12), local).await.unwrap();
        let barriers = Arc::new((std::sync::Barrier::new(2), std::sync::Barrier::new(2)));
        harness.peers.write().after_eviction_snapshot = Some(Arc::clone(&barriers));
        let evicting = {
            let service = Arc::clone(&service);
            tokio::task::spawn_blocking(move || {
                service
                    .evict_all_sessions(crate::p2p_session_eviction::EvictionReason::OperatorTest)
            })
        };
        let reached = Arc::clone(&barriers);
        tokio::task::spawn_blocking(move || {
            reached.0.wait();
        })
        .await
        .unwrap();
        assert_registry_count(&harness, 0);
        let pause = Arc::new(RegistrationPause::default());
        harness.peers.write().after_publish = Some(Arc::clone(&pause));
        let (later, later_remote) = pair_channels(true);
        let registering = {
            let harness = harness.clone();
            tokio::spawn(async move { harness.register(node_id(13), later).await })
        };
        pause.entered.notified().await;
        assert_registry_count(&harness, 1);
        barriers.1.wait();
        let report = evicting.await.unwrap().unwrap();
        assert_eq!((report.attempted, report.evicted, report.failed), (1, 1, 0));
        assert_registry_count(&harness, 1);
        pause.release.notify_one();
        registering.await.unwrap().unwrap();
        assert_registry_count(&harness, 1);
        send_app(later_remote, heartbeat_frame(13)).await.unwrap();
        harness.receive().await;
        let old = Arc::clone(&harness.peers.read().retiring[&node_id(12)]);
        old.finish().await.unwrap();
        expect_remote_eof(remote).await;
    }

    #[tokio::test]
    async fn service_shutdown_joins_blocked_inbound_handshake() {
        let mut service = service();
        let harness = Harness::for_service(&service);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        service.listener_handle = Some(service.spawn_accept_loop(listener));
        let mut remote = TcpStream::connect(addr).await.unwrap();
        // Registration of the join/shutdown owner is the barrier, not a sleep.
        tokio::time::timeout(Duration::from_secs(3), async {
            while harness.peers.read().handshakes.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let owner = Arc::clone(harness.peers.read().handshakes.values().next().unwrap());
        service.shutdown().await;
        assert!(service.listener_handle.is_none());
        assert!(owner.task.lock().await.is_none());
        assert!(harness.peers.read().handshakes.is_empty());
        assert_registry_count(&harness, 0);
        use tokio::io::AsyncReadExt;
        let mut byte = [0];
        assert_eq!(remote.read(&mut byte).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn successful_inbound_handshake_reserved_during_shutdown_is_refused() {
        for fail in [false, true] {
            let mut service = service();
            let harness = Harness::for_service(&service);
            let (old, old_remote) = pair_channels(true);
            harness.register(node_id(15), old).await.unwrap();
            let old_owner = Arc::clone(&harness.peers.read().active[&node_id(15)].retirement);
            old_owner.channel.fail_shutdown_for_test(fail);
            let pause = Arc::new(RegistrationPause::default());
            harness.peers.write().before_publish = Some(Arc::clone(&pause));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap().to_string();
            let cfg = service.client_cfg.clone();
            let client =
                tokio::task::spawn_blocking(move || SecureChannel::connect(&addr, cfg).unwrap());
            let (stream, addr) = listener.accept().await.unwrap();
            let handler = {
                let cfg = service.server_cfg.clone();
                let harness = harness.clone();
                tokio::spawn(async move {
                    TcpKemTlsP2pService::handle_inbound_connection(
                        stream,
                        addr,
                        cfg,
                        harness.peers,
                        harness.inbound_tx,
                        harness.connections_current,
                        harness.bytes_received,
                        Arc::new(AtomicU64::new(0)),
                        Arc::new(RwLock::new(None)),
                        harness.peer_candidate_wire_sink,
                        harness.inbound_per_peer_limiter,
                        Arc::new(RwLock::new(None)),
                    )
                    .await
                })
            };
            pause.entered.notified().await;
            let client = client.await.unwrap();
            assert!(client.is_established());
            assert_eq!(harness.peers.read().candidates.len(), 1);
            assert!(harness.peers.read().handshakes.is_empty());
            service.shutdown().await;
            assert_registry_count(&harness, 0);
            expect_remote_eof(client).await;
            pause.release.notify_one();
            assert!(handler.await.unwrap().is_err());
            assert!(harness.peers.read().registering.is_empty());
            assert!(harness.peers.read().candidates.is_empty());
            if fail {
                assert!(Arc::ptr_eq(
                    &harness.peers.read().retiring[&node_id(15)],
                    &old_owner
                ));
                old_owner.channel.fail_shutdown_for_test(false);
                service.shutdown().await;
            }
            assert!(harness.peers.read().retiring.is_empty());
            expect_remote_eof(old_remote).await;
        }
    }

    #[tokio::test]
    async fn cancelled_shutdown_keeps_old_owner_for_later_join() {
        let mut service = service();
        let harness = Harness::for_service(&service);
        let (local, remote) = pair_channels(true);
        harness.register(node_id(16), local).await.unwrap();
        let owner = Arc::clone(&harness.peers.read().active[&node_id(16)].retirement);
        let held = owner.tasks.lock().await;
        let mut shutdown = Box::pin(service.shutdown());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(shutdown.as_mut().poll(&mut cx).is_pending());
        drop(shutdown);
        assert!(Arc::ptr_eq(
            &harness.peers.read().retiring[&node_id(16)],
            &owner
        ));
        assert_registry_count(&harness, 0);
        drop(held);
        service.shutdown().await;
        assert!(harness.peers.read().retiring.is_empty());
        expect_remote_eof(remote).await;
    }

    #[tokio::test]
    async fn cancelled_outbound_dial_keeps_handshake_worker_for_shutdown() {
        let mut service = service();
        let harness = Harness::for_service(&service);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let dial = {
            let cfg = service.client_cfg.clone();
            let peers = Arc::clone(&harness.peers);
            tokio::spawn(async move { TcpKemTlsP2pService::tracked_dial(peers, &addr, cfg).await })
        };
        let (mut remote, _) = listener.accept().await.unwrap();
        tokio::time::timeout(Duration::from_secs(3), async {
            while harness.peers.read().handshakes.is_empty() {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        let owner = Arc::clone(harness.peers.read().handshakes.values().next().unwrap());
        dial.abort();
        assert!(dial.await.unwrap_err().is_cancelled());
        assert_eq!(harness.peers.read().handshakes.len(), 1);
        service.shutdown().await;
        assert!(owner.task.lock().await.is_none());
        assert!(harness.peers.read().handshakes.is_empty());
        assert_registry_count(&harness, 0);
        use tokio::io::AsyncReadExt;
        let mut bytes = Vec::new();
        remote.read_to_end(&mut bytes).await.unwrap();
    }

    async fn outbound_single_connection(retry_path: bool, budget: usize) {
        let mut service = service();
        let harness = Harness::for_service(&service);
        let dialer = service.dialer_handle();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server_cfg = service.server_cfg.clone();
        let server = async move {
            let mut workers = tokio::task::JoinSet::new();
            let mut accepted = 0;
            let mut rejected = 0;
            let channel = loop {
                tokio::select! {
                    incoming = listener.accept() => {
                        let (stream, _) = incoming.unwrap();
                        accepted += 1;
                        if accepted > budget {
                            rejected += 1;
                            drop(stream);
                            continue;
                        }
                        let cfg = server_cfg.clone();
                        workers.spawn_blocking(move || {
                            let stream = stream.into_std().unwrap();
                            stream.set_nonblocking(false).unwrap();
                            stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
                            SecureChannel::from_accepted(stream, cfg)
                        });
                    }
                    result = workers.join_next(), if !workers.is_empty() => {
                        match result.unwrap().unwrap() {
                            Ok(channel) => break Ok(channel),
                            Err(error) if workers.is_empty() => break Err(error),
                            Err(_) => {}
                        }
                    }
                }
            };
            while workers.join_next().await.is_some() {}
            (accepted, rejected, channel)
        };
        let dial = async {
            if retry_path {
                dialer.dial_once(addr).await
            } else {
                service.dial_peer(addr).await
            }
        };
        let (dial_result, (accepted, rejected, channel)) =
            tokio::time::timeout(Duration::from_secs(6), async { tokio::join!(dial, server) })
                .await
                .unwrap();
        println!(
            "outbound retry_path={retry_path} budget={budget} accepted={accepted} \
             rejected={rejected} dial_ok={} handshake_ok={}",
            dial_result.is_ok(),
            channel.is_ok()
        );
        // Observe cleanup even when the baseline dial/handshake failed.
        service.shutdown().await;
        assert_eq!(accepted, 1, "one accepted socket per outbound attempt");
        assert_eq!(rejected, 0, "one-slot admission budget must suffice");
        dial_result.expect("outbound entry point should complete handshake");
        let channel = channel.expect("the sole accepted socket must carry KEMTLS");
        expect_remote_eof(channel).await;
        assert_registry_count(&harness, 0);
        assert!(harness.peers.read().handshakes.is_empty());
    }

    #[tokio::test]
    async fn outbound_service_single_connection_carries_handshake() {
        outbound_single_connection(false, usize::MAX).await;
    }

    #[tokio::test]
    async fn outbound_retry_single_connection_carries_handshake() {
        outbound_single_connection(true, usize::MAX).await;
    }

    #[tokio::test]
    async fn outbound_service_single_connection_budget() {
        outbound_single_connection(false, 1).await;
    }

    #[tokio::test]
    async fn outbound_retry_single_connection_budget() {
        outbound_single_connection(true, 1).await;
    }

    async fn outbound_entry_cancellation(retry_path: bool) {
        use tokio::io::AsyncReadExt;

        let mut service = service();
        let harness = Harness::for_service(&service);
        let dialer = service.dialer_handle();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let mut remote = {
            let dial = async {
                if retry_path {
                    dialer.dial_once(addr).await
                } else {
                    service.dial_peer(addr).await
                }
            };
            tokio::pin!(dial);
            let (mut remote, _) = tokio::select! {
                incoming = listener.accept() => incoming.unwrap(),
                result = &mut dial => panic!("dial completed without server handshake: {result:?}"),
            };
            tokio::time::timeout(Duration::from_secs(3), async {
                tokio::select! {
                    result = &mut dial => panic!("pending handshake completed: {result:?}"),
                    result = remote.read_u8() => { result.expect("first socket carries handshake bytes"); }
                }
                assert_eq!(harness.peers.read().handshakes.len(), 1);
                assert!(harness.peers.read().active.is_empty());
            })
            .await
            .unwrap();
            remote
            // Dropping this scope cancels the actual entry-point future.
        };
        let owner = Arc::clone(harness.peers.read().handshakes.values().next().unwrap());
        assert!(owner.task.lock().await.is_some());
        assert_eq!(harness.peers.read().handshakes.len(), 1);
        service.shutdown().await;
        assert!(owner.task.lock().await.is_none());
        assert!(harness.peers.read().handshakes.is_empty());
        assert_registry_count(&harness, 0);
        assert!(harness.peers.read().closed);
        let mut remaining = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), remote.read_to_end(&mut remaining))
            .await
            .unwrap()
            .unwrap();
        let refused = if retry_path {
            dialer
                .dial_once(listener.local_addr().unwrap().to_string())
                .await
        } else {
            service
                .dial_peer(listener.local_addr().unwrap().to_string())
                .await
        };
        assert!(matches!(
            refused,
            Err(P2pTransportError::SessionRetirement(_))
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), listener.accept())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn outbound_service_cancellation_retains_handshake_owner() {
        outbound_entry_cancellation(false).await;
    }

    #[tokio::test]
    async fn outbound_retry_cancellation_retains_handshake_owner() {
        outbound_entry_cancellation(true).await;
    }
}
