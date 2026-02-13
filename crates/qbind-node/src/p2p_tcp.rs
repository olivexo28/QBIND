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

use parking_lot::RwLock;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::node_config::NetworkTransportConfig;
use crate::p2p::{NodeId, P2pMessage, P2pService};
use crate::secure_channel::{accept_kemtls_async, connect_kemtls_async, SecureChannelAsync};
use qbind_crypto::CryptoProvider;
use qbind_hash::derive_node_id_from_pubkey;
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
        })
    }

    /// Start the P2P service: listen on configured address and dial static peers.
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

        // Dial static peers
        for peer_addr in &self.config.static_peers {
            let result = self.dial_peer(peer_addr.clone()).await;
            if let Err(e) = result {
                eprintln!("[P2P] Failed to dial {}: {}", peer_addr, e);
            }
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
    /// # M7: NodeId for Inbound Connections
    ///
    /// The current KEMTLS-PDK protocol does not include client certificate exchange,
    /// so the connecting client's cryptographic identity cannot be derived from the
    /// handshake. For inbound connections, we generate a temporary session-unique
    /// NodeId based on:
    /// - The server's local validator ID (provides server identity binding)
    /// - A monotonic session counter (provides uniqueness)
    /// - The peer's remote address (provides additional context)
    ///
    /// The actual peer identity will be established through application-layer
    /// protocols (e.g., when the peer sends their first consensus message).
    /// A future protocol enhancement could add mutual KEMTLS authentication.
    async fn handle_inbound_connection(
        stream: TcpStream,
        peer_addr: std::net::SocketAddr,
        server_cfg: ServerConnectionConfig,
        peers: Arc<RwLock<HashMap<NodeId, PeerConnection>>>,
        inbound_tx: mpsc::Sender<P2pMessage>,
        connections_current: Arc<AtomicU64>,
        bytes_received: Arc<AtomicU64>,
        inbound_session_counter: Arc<AtomicU64>,
    ) -> Result<(), P2pTransportError> {
        // Convert Tokio stream to std::net::TcpStream for KEMTLS handshake
        let _std_stream = stream.into_std().map_err(P2pTransportError::Io)?;

        // Perform KEMTLS handshake (blocking)
        let channel = accept_kemtls_async(_std_stream, server_cfg.clone())
            .await
            .map_err(|e| P2pTransportError::Handshake(e.to_string()))?;

        // M7: Generate a temporary session-unique NodeId for inbound connections.
        // This is NOT cryptographically bound to the client's identity (protocol limitation).
        // The NodeId is derived from:
        // - server's local_validator_id: provides server identity context
        // - session counter: ensures uniqueness across connections
        // - peer address: provides additional entropy and debugging context
        //
        // Note: True client identity binding requires mutual KEMTLS authentication
        // (client sends their delegation cert) which is not in the current protocol.
        let session_id = inbound_session_counter.fetch_add(1, Ordering::Relaxed);
        let mut preimage = Vec::new();
        preimage.extend_from_slice(b"QBIND:inbound:session:v1:");
        preimage.extend_from_slice(&server_cfg.handshake_config.local_validator_id);
        preimage.extend_from_slice(&session_id.to_be_bytes());
        preimage.extend_from_slice(peer_addr.to_string().as_bytes());
        let node_id_bytes = qbind_hash::sha3_256(&preimage);
        let node_id = NodeId::new(node_id_bytes);

        // Log that this is a temporary session ID (not cryptographically bound to peer)
        println!(
            "[P2P] Inbound connection from {} assigned temporary session NodeId {:?}",
            peer_addr, node_id
        );

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

    /// Dial an outbound peer.
    async fn dial_peer(&self, peer_addr: String) -> Result<(), P2pTransportError> {
        println!("[P2P] Dialing {}", peer_addr);

        // Connect via TCP
        let stream = TcpStream::connect(&peer_addr).await?;

        // Convert to std::net::TcpStream for KEMTLS handshake
        let _std_stream = stream.into_std().map_err(P2pTransportError::Io)?;

        // Perform KEMTLS handshake (blocking)
        let channel = connect_kemtls_async(peer_addr.clone(), self.client_cfg.clone())
            .await
            .map_err(|e| P2pTransportError::Handshake(e.to_string()))?;

        // M7: Derive NodeId from peer's KEM public key (cryptographic binding)
        // The peer_kem_pk in client_cfg is the server's KEM public key that we
        // are connecting to. NodeId = sha3_256("QBIND:nodeid:v1" || peer_kem_pk)
        let node_id_bytes = derive_node_id_from_pubkey(&self.client_cfg.peer_kem_pk);
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
