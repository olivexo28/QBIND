//! Secure channel abstraction for encrypted TCP communication.
//!
//! This module provides `SecureChannel`, which combines a `TcpStream` with a
//! `Connection` (from qbind-net) to perform KEMTLS handshakes and send/receive
//! encrypted application data.
//!
//! # SecureChannel I/O Model (T92 Part A)
//!
//! `SecureChannel` provides blocking, synchronous I/O for encrypted messaging:
//!
//! ## Sending Data
//! ```text
//! SecureChannel::send_app(&mut self, plaintext: &[u8]) -> Result<(), ChannelError>
//! ```
//! - Encrypts plaintext using the established AEAD session (via `Connection::encrypt_app`)
//! - Produces a `TransportFrame` with msg_type (u8) + length (u32 BE) + ciphertext
//! - Writes the entire frame to the underlying TCP socket and flushes
//!
//! ## Receiving Data
//! ```text
//! SecureChannel::recv_app(&mut self) -> Result<Vec<u8>, ChannelError>
//! ```
//! - Reads a length-prefixed `TransportFrame` from the TCP socket (blocking)
//! - Decrypts the ciphertext using the established AEAD session
//! - Returns the decrypted plaintext
//!
//! ## Frame Format
//! ```text
//! TransportFrame wire format:
//!   - msg_type: u8 (0x01 for APP_MESSAGE)
//!   - len: u32 BE (ciphertext length)
//!   - ciphertext: [u8; len] (AEAD encrypted payload)
//! ```
//!
//! The framing is handled by `qbind_net::framed_io`:
//! - `write_transport_frame` / `read_transport_frame` for application data
//! - `write_handshake_packet` / `read_handshake_packet` for handshake messages
//!
//! # SecureChannelAsync (T92 Part B)
//!
//! `SecureChannelAsync` is a transitional async wrapper over `SecureChannel` that
//! allows integration with Tokio-based async code. It uses `spawn_blocking` for
//! all I/O operations since `SecureChannel` is inherently blocking.
//!
//! **Design Notes:**
//! - Uses `Arc<std::sync::Mutex<SecureChannel>>` for thread-safe shared ownership
//! - Each `send`/`recv` operation spawns a blocking task
//! - This is a transitional design; a fully async implementation would require
//!   refactoring `Connection` to use async I/O primitives
//!
//! **Performance Considerations:**
//! - `spawn_blocking` has overhead (~1-5µs per call) but is acceptable for
//!   consensus message rates (typically <1000 msg/s per peer)
//! - Future optimization: batch multiple messages per `spawn_blocking` call
//!
//! # Usage with AsyncPeerManagerImpl
//!
//! When `TransportSecurityMode::Kemtls` is configured:
//! 1. Server-side: `SecureChannel::from_accepted()` runs in `spawn_blocking`
//! 2. Client-side: `SecureChannel::connect()` runs in `spawn_blocking`
//! 3. After handshake, the channel is wrapped in `SecureChannelAsync`
//! 4. Reader/writer tasks use `SecureChannelAsync::recv()`/`send()` for encrypted I/O

#[cfg(test)]
#[path = "secure_channel/encrypted_write_tests.rs"]
pub(crate) mod encrypted_write_tests;

#[cfg(test)]
#[path = "secure_channel/partial_read_tests.rs"]
mod partial_read_tests;

use std::io::{self, Read};
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qbind_net::{
    read_handshake_packet, read_transport_frame, unpack_client_init, write_handshake_packet,
    write_transport_frame, ClientConnectionConfig, Connection, HandshakePacket, NetError,
    ServerConnectionConfig, TransportFrame,
};

/// Snapshot of the dialer-supplied fields surfaced from a server-side
/// KEMTLS handshake (B8 — listener-side identity closure).
///
/// These fields come from the dialer's `ClientInit` and are exposed
/// from the server-side accept path so that the transport can register
/// the accepted session under a NodeId derived from the dialer's
/// already-on-the-wire identity hints, rather than only a temporary
/// session-unique NodeId.
///
/// # Security semantics (test-grade)
///
/// - In the current test-grade DevNet bring-up
///   (`MutualAuthMode::Disabled` in `p2p_node_builder::create_connection_configs`),
///   the dialer does NOT send a client cert, so these fields are
///   *self-asserted*: the dialer is trusted (or not) the same way it is
///   under the legacy temporary-session-NodeId path. This is strictly
///   no weaker than the pre-B8 behaviour.
/// - `validator_id` here is the value the dialer put in
///   `ClientInit.validator_id`; per `qbind_net::handshake::handle_server_accept`
///   the dialer sets that to the *server's* expected validator id (so
///   the cert check `delegation_cert.validator_id == client_init.validator_id`
///   passes). It is NOT the dialer's own validator id.
/// - `client_random` is the dialer's random contribution to the
///   handshake. The QBIND test-grade `P2pNodeBuilder::create_connection_configs`
///   deterministically embeds the ASCII prefix `"qbind-client-<N>"` at
///   the start of `client_random`, where `<N>` is the dialer's local
///   validator id. The transport can therefore extract the dialer's vid
///   from `client_random` for test-grade routing — see
///   `p2p_node_builder::parse_test_validator_id_from_client_random`.
/// - Production-grade peer identity binding is mutual KEMTLS auth
///   (`MutualAuthMode::Required`), tracked under C4 in
///   `docs/whitepaper/contradiction.md`. B8 does NOT change that.
#[derive(Clone, Copy, Debug)]
pub struct AcceptedPeerInit {
    /// The dialer's `ClientInit.client_random` field (32 bytes).
    pub client_random: [u8; 32],
    /// The dialer's `ClientInit.validator_id` field (32 bytes).
    ///
    /// **Note:** this is the *server's* expected validator id from the
    /// dialer's perspective (see type-level docs), NOT the dialer's
    /// own identity. The dialer's identity hint is recovered from
    /// `client_random`, not from this field. We surface it here only
    /// for completeness / future use; current consumers (e.g. the
    /// `InboundIdentityResolver` installed by `P2pNodeBuilder`) parse
    /// `client_random`.
    pub validator_id: [u8; 32],
    /// B12 — peer's validator id derived from the *verified* client
    /// `NetworkDelegationCert` (`MutualAuthMode::Required` only).
    ///
    /// `Some(vid)` iff the server-side `Connection` reported
    /// `mutual_auth_complete() == true`, in which case `vid` is the
    /// `validator_id` field of the client cert. Under
    /// `MutualAuthMode::Disabled` this is `None` — the listener-side
    /// session identity must then be sourced from the legacy
    /// self-asserted `client_random`/`validator_id` fields above.
    pub verified_peer_validator_id: Option<[u8; 32]>,
    /// B12 — peer's NodeId derived from the *verified* client
    /// `NetworkDelegationCert` via `derive_node_id_from_cert`
    /// (`MutualAuthMode::Required` only). `None` otherwise.
    pub verified_client_node_id: Option<[u8; 32]>,
    /// B12 — whether the listener completed mutual KEMTLS authentication
    /// for this session.
    ///
    /// True iff the client presented a v2 `ClientInit` with a
    /// `NetworkDelegationCert` AND the server's `MutualAuthMode` was
    /// not `Disabled` (so the cert went through
    /// `parse_and_verify_client_cert`). When this is `true`, both
    /// `verified_peer_validator_id` and `verified_client_node_id` are
    /// `Some`, and the transport SHOULD prefer them as the source of
    /// truth for accepted-session identity registration over the
    /// self-asserted `client_random`-derived path.
    pub mutual_auth_complete: bool,
}

/// Default timeout for socket read/write operations (in seconds).
const DEFAULT_SOCKET_TIMEOUT_SECS: u64 = 10;

/// Run 418 (F6): the actual verified server identity surfaced from a
/// successful client-side KEMTLS `Connection`.
///
/// Both `node_id` and `validator_id` are established by the client's
/// verification of the server's delegation certificate during the handshake
/// (parse → root-verify → validator-id-match → revocation-check). Neither is
/// derived from the dial address or any self-asserted field. The dial address
/// and `vid@addr` identify the *expected* peer, but MUST NOT themselves mint
/// the authenticated origin.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedServerIdentity {
    /// Full 32-byte cert-derived NodeId of the verified server certificate.
    pub node_id: [u8; 32],
    /// `validator_id` field of the verified server certificate.
    pub validator_id: [u8; 32],
    /// Whether mutual authentication completed for this session (client cert
    /// presented and the server's `MutualAuthMode` was not `Disabled`).
    pub authenticated: bool,
}

/// Error type for SecureChannel operations.
///
/// Separates I/O errors from protocol/crypto errors.
#[derive(Debug)]
pub enum ChannelError {
    /// I/O error (TCP read/write failure).
    Io(io::Error),
    /// Protocol or crypto error from qbind-net.
    Net(NetError),
}

impl From<io::Error> for ChannelError {
    fn from(err: io::Error) -> Self {
        ChannelError::Io(err)
    }
}

impl From<NetError> for ChannelError {
    fn from(err: NetError) -> Self {
        ChannelError::Net(err)
    }
}

struct FrameProgress<'a, R> {
    reader: &'a mut R,
    consumed: usize,
}

impl<R: Read> Read for FrameProgress<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.reader.read(buf)?;
        self.consumed += n;
        Ok(n)
    }
    // Use Read's default read_exact, so every successful read is counted,
    // even if the underlying reader overrides read_exact.
}

fn read_counted_frame<R: Read>(reader: &mut R) -> (io::Result<TransportFrame>, usize) {
    let mut progress = FrameProgress {
        reader,
        consumed: 0,
    };
    let result = read_transport_frame(&mut progress);
    (result, progress.consumed)
}

#[derive(Debug)]
struct PartialFrameError {
    consumed: usize,
    cause: io::Error,
}

impl std::fmt::Display for PartialFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "transport frame failed after {} bytes; session invalidated: {}",
            self.consumed, self.cause
        )
    }
}

impl std::error::Error for PartialFrameError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.cause)
    }
}

/// Configure socket options for responsiveness.
fn configure_socket(stream: &TcpStream) {
    stream.set_nodelay(true).ok();
    stream
        .set_read_timeout(Some(Duration::from_secs(DEFAULT_SOCKET_TIMEOUT_SECS)))
        .ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(DEFAULT_SOCKET_TIMEOUT_SECS)))
        .ok();
}

/// A secure, encrypted TCP channel.
///
/// `SecureChannel` wraps a `TcpStream` and an established `Connection` to
/// provide encrypted application-level messaging over TCP.
///
/// # Invariant
///
/// By the time a `SecureChannel` is constructed, the KEMTLS handshake is
/// complete and `conn.is_established()` returns `true`.
#[derive(Debug)]
pub struct SecureChannel {
    stream: TcpStream,
    conn: Connection,
    invalidated: Arc<AtomicBool>,
    #[cfg(test)]
    write_fault: Option<encrypted_write_tests::WriteFault>,
    #[cfg(test)]
    read_fault: Option<partial_read_tests::ReadFault>,
}

impl SecureChannel {
    fn established(stream: TcpStream, conn: Connection) -> Self {
        Self {
            stream,
            conn,
            invalidated: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            write_fault: None,
            #[cfg(test)]
            read_fault: None,
        }
    }

    fn ensure_usable(&self) -> Result<(), ChannelError> {
        if self.invalidated.load(Ordering::SeqCst) {
            return Err(Self::invalidated_error());
        }
        Ok(())
    }

    fn invalidated_error() -> ChannelError {
        ChannelError::Net(NetError::Protocol("secure channel session invalidated"))
    }

    /// Get a reference to the underlying TCP stream.
    ///
    /// This is useful for setting socket options like timeouts.
    /// Raw socket I/O is outside the guarded application-message API.
    pub fn stream(&self) -> &TcpStream {
        &self.stream
    }

    /// Blocking client-side connect + KEMTLS handshake.
    ///
    /// # Arguments
    ///
    /// * `addr` - Remote socket address (host:port)
    /// * `cfg` - Client handshake / suite configuration
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if the TCP connection fails, the handshake fails,
    /// or the protocol is violated.
    pub fn connect(addr: &str, cfg: ClientConnectionConfig) -> Result<Self, ChannelError> {
        let mut stream = TcpStream::connect(addr)?;
        configure_socket(&stream);

        // 1. Create client Connection
        let mut conn = Connection::new_client(cfg);

        // 2. Start handshake, get the first frame to send
        let first = conn.start_handshake()?;

        // 3. Decode into HandshakePacket and send via framed_io
        let pkt = HandshakePacket::decode(&first)?;
        write_handshake_packet(&mut stream, &pkt)?;

        // 4. Read server reply as HandshakePacket
        let reply_pkt = read_handshake_packet(&mut stream)?;

        // 5. Let Connection process the reply
        let reply_bytes_opt = conn.handle_handshake_frame(&reply_pkt.encode())?;

        // Client should not produce any further handshake frames
        if reply_bytes_opt.is_some() {
            return Err(NetError::Protocol(
                "client handshake produced unexpected additional frame after server reply",
            )
            .into());
        }

        if !conn.is_established() {
            return Err(NetError::Protocol("client handshake not established").into());
        }

        Ok(Self::established(stream, conn))
    }

    /// Blocking server-side handshake on an already-accepted `TcpStream`.
    ///
    /// Does not call `accept`; the caller must accept connections and pass the
    /// stream in.
    ///
    /// # Arguments
    ///
    /// * `stream` - An already-accepted TCP stream
    /// * `cfg` - Server handshake / suite configuration
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if the handshake fails or the protocol is violated.
    pub fn from_accepted(
        mut stream: TcpStream,
        cfg: ServerConnectionConfig,
    ) -> Result<Self, ChannelError> {
        configure_socket(&stream);

        // 1. Create server Connection
        let mut conn = Connection::new_server(cfg);

        // 2. Read client's ClientInit packet
        let client_pkt = read_handshake_packet(&mut stream)?;

        // 3. Let Connection process and produce ServerAccept
        let reply_bytes_opt = conn.handle_handshake_frame(&client_pkt.encode())?;
        let reply_bytes = reply_bytes_opt.ok_or(ChannelError::Net(NetError::Protocol(
            "server did not produce reply",
        )))?;

        // 4. Send ServerAccept
        let reply_pkt = HandshakePacket::decode(&reply_bytes)?;
        write_handshake_packet(&mut stream, &reply_pkt)?;

        if !conn.is_established() {
            return Err(NetError::Protocol("server handshake not established").into());
        }

        Ok(Self::established(stream, conn))
    }

    /// Like [`SecureChannel::from_accepted`], but additionally surfaces
    /// the dialer-supplied `client_random` and `validator_id` fields
    /// from the parsed `ClientInit` so the caller can register the
    /// accepted session under a non-temporary, deterministic NodeId
    /// (B8 — listener-side identity closure).
    ///
    /// The handshake itself is identical: `ClientInit` → `ServerAccept`
    /// is processed by `Connection::handle_handshake_frame` exactly as
    /// `from_accepted` does. The only difference is that this method
    /// also runs `unpack_client_init` on the same incoming packet so it
    /// can return the relevant dialer-supplied fields alongside the
    /// established channel. The cost is one extra parse of bytes the
    /// server already had to read.
    ///
    /// See [`AcceptedPeerInit`] for the semantics (test-grade,
    /// self-asserted; not stronger than the pre-B8 behaviour).
    pub fn from_accepted_with_peer_init(
        mut stream: TcpStream,
        cfg: ServerConnectionConfig,
    ) -> Result<(Self, AcceptedPeerInit), ChannelError> {
        configure_socket(&stream);

        // 1. Create server Connection
        let mut conn = Connection::new_server(cfg);

        // 2. Read client's ClientInit packet
        let client_pkt = read_handshake_packet(&mut stream)?;

        // 2b. Parse the dialer's ClientInit so we can surface the
        //     `client_random` and `validator_id` fields. The fully
        //     authoritative cert/cookie/KEM checks still happen below
        //     inside `Connection::handle_handshake_frame`.
        let client_init = unpack_client_init(&client_pkt)?;

        // 3. Let Connection process and produce ServerAccept
        let reply_bytes_opt = conn.handle_handshake_frame(&client_pkt.encode())?;
        let reply_bytes = reply_bytes_opt.ok_or(ChannelError::Net(NetError::Protocol(
            "server did not produce reply",
        )))?;

        // 4. Send ServerAccept
        let reply_pkt = HandshakePacket::decode(&reply_bytes)?;
        write_handshake_packet(&mut stream, &reply_pkt)?;

        if !conn.is_established() {
            return Err(NetError::Protocol("server handshake not established").into());
        }

        // B12 — once the handshake is established, surface the verified
        // peer identity captured by `Connection` from its underlying
        // `HandshakeResult`. `Connection::peer_validator_id` /
        // `peer_node_id` are already gated internally on
        // `mutual_auth_complete` for the server-cert-bound NodeId
        // (`peer_node_id`) — we only additionally gate
        // `verified_peer_validator_id` on `mutual_auth_complete` here
        // because the server side ALWAYS captures
        // `peer_validator_id` (even under `Disabled`, from the
        // server's own cert path), and consumers of `AcceptedPeerInit`
        // expect `verified_peer_validator_id = Some(_)` to imply that
        // the bytes came from the *verified client cert*, not from
        // the server's reflection.
        let mutual_auth_complete = conn.mutual_auth_complete();
        let verified_peer_validator_id = if mutual_auth_complete {
            conn.peer_validator_id()
        } else {
            None
        };
        let verified_client_node_id = conn.peer_node_id();
        let peer_init = AcceptedPeerInit {
            client_random: client_init.client_random,
            validator_id: client_init.validator_id,
            verified_peer_validator_id,
            verified_client_node_id,
            mutual_auth_complete,
        };

        Ok((Self::established(stream, conn), peer_init))
    }

    /// Encrypt and send an application message.
    ///
    /// # Errors
    ///
    /// Returns the original error if encryption, framing, write or flush fails.
    /// Such failures permanently invalidate application sends and receives,
    /// including shared handles: encryption may already have advanced a nonce
    /// and a failed write may have delivered any prefix (or the entire frame).
    /// Socket shutdown is attempted, but invalidation does not depend on it.
    /// Delivery is uncertain; this method never replays the plaintext.
    pub fn send_app(&mut self, plaintext: &[u8]) -> Result<(), ChannelError> {
        self.ensure_usable()?;
        let result = self.encrypt_and_write(plaintext);
        if result.is_err() {
            self.invalidated.store(true, Ordering::SeqCst);
            let shutdown_result = self.shutdown_socket();
            if let Err(error) = shutdown_result {
                eprintln!(
                    "[SecureChannel] socket shutdown failed after send failure; session remains invalidated: {}",
                    error
                );
            }
        }
        result
    }

    fn shutdown_socket(&self) -> io::Result<()> {
        #[cfg(test)]
        if let Some(fault) = &self.read_fault {
            fault.before_shutdown()?;
        }
        #[cfg(test)]
        if let Some(fault) = &self.write_fault {
            fault.before_shutdown()?;
        }
        self.stream.shutdown(Shutdown::Both)
    }

    fn encrypt_and_write(&mut self, plaintext: &[u8]) -> Result<(), ChannelError> {
        let frame_bytes = self.conn.encrypt_app(plaintext)?;
        let frame = TransportFrame::decode(&frame_bytes)?;
        #[cfg(test)]
        if let Some(fault) = &mut self.write_fault {
            write_transport_frame(&mut fault.writer(&mut self.stream), &frame)?;
            return Ok(());
        }
        write_transport_frame(&mut self.stream, &frame)?;
        Ok(())
    }

    /// Receive and decrypt a single application message.
    ///
    /// This blocks until one full transport frame is read or an I/O error occurs.
    ///
    /// # Errors
    ///
    /// Zero-progress idle WouldBlock/TimedOut errors remain retryable. Any
    /// framing error after consuming bytes invalidates the shared session and
    /// attempts socket shutdown. It returns Io(InvalidData) with the original
    /// I/O error as a source, never a retryable timeout-shaped error.
    /// Also fails if already invalidated, or if decryption fails.
    pub fn recv_app(&mut self) -> Result<Vec<u8>, ChannelError> {
        self.ensure_usable()?;
        #[cfg(test)]
        let (result, consumed) = if let Some(fault) = &mut self.read_fault {
            read_counted_frame(&mut fault.reader(&mut self.stream))
        } else {
            read_counted_frame(&mut self.stream)
        };
        #[cfg(not(test))]
        let (result, consumed) = read_counted_frame(&mut self.stream);
        let frame = match result {
            Ok(frame) => frame,
            Err(cause) if consumed > 0 => {
                self.invalidated.store(true, Ordering::SeqCst);
                if let Err(error) = self.shutdown_socket() {
                    eprintln!(
                        "[SecureChannel] socket shutdown failed after frame read failure; session remains invalidated: {}",
                        error
                    );
                }
                return Err(ChannelError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    PartialFrameError { consumed, cause },
                )));
            }
            Err(error) => return Err(error.into()),
        };
        let plaintext = self.conn.decrypt_app(&frame.encode()?)?;
        Ok(plaintext)
    }

    /// Check if the connection is established and ready for app data.
    pub fn is_established(&self) -> bool {
        !self.invalidated.load(Ordering::SeqCst) && self.conn.is_established()
    }

    /// Run 418 (F6): the verified server identity established by a successful
    /// client-side KEMTLS handshake, or `None` if called before the handshake
    /// completed on a server-side channel.
    ///
    /// `node_id` is the full 32-byte cert-derived NodeId of the verified server
    /// delegation certificate; `validator_id` is that certificate's
    /// `validator_id` field. Both come exclusively from the verified server
    /// certificate the client parsed, root-verified, validator-id-matched and
    /// revocation-checked during the handshake — never from the dial address.
    pub fn verified_server_identity(&self) -> Option<VerifiedServerIdentity> {
        let node_id = self.conn.peer_node_id()?;
        let validator_id = self.conn.peer_validator_id()?;
        Some(VerifiedServerIdentity {
            node_id,
            validator_id,
            authenticated: self.conn.mutual_auth_complete(),
        })
    }

    /// Set the socket to non-blocking mode for recv operations.
    ///
    /// This should be called after the handshake is complete to enable
    /// non-blocking reads for application data.
    ///
    /// # Errors
    ///
    /// Returns `ChannelError::Io` if setting non-blocking mode fails.
    pub fn set_nonblocking(&mut self, nonblocking: bool) -> Result<(), ChannelError> {
        self.stream.set_nonblocking(nonblocking)?;
        Ok(())
    }
}

// ============================================================================
// SecureChannelAsync (T92 Part B, T106 Refactor)
// ============================================================================

/// Error type for async secure channel operations.
///
/// Extends `ChannelError` with async-specific error variants.
#[derive(Debug)]
pub enum AsyncChannelError {
    /// Underlying channel error (I/O or protocol).
    Channel(ChannelError),
    /// The spawn_blocking task was cancelled or panicked.
    TaskJoin(String),
    /// The channel mutex was poisoned (a previous panic occurred).
    MutexPoisoned,
    /// Channel closed (worker terminated).
    ChannelClosed,
}

impl AsyncChannelError {
    /// Check if this error is a timeout or would-block error.
    ///
    /// These errors are expected when using short timeouts for shutdown checks.
    pub fn is_timeout(&self) -> bool {
        match self {
            AsyncChannelError::Channel(ChannelError::Io(io_err)) => {
                io_err.kind() == io::ErrorKind::WouldBlock
                    || io_err.kind() == io::ErrorKind::TimedOut
            }
            _ => false,
        }
    }

    /// Check if this error indicates an unexpected EOF (peer disconnected).
    pub fn is_eof(&self) -> bool {
        match self {
            AsyncChannelError::Channel(ChannelError::Io(io_err)) => {
                io_err.kind() == io::ErrorKind::UnexpectedEof
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for AsyncChannelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsyncChannelError::Channel(e) => write!(f, "channel error: {:?}", e),
            AsyncChannelError::TaskJoin(msg) => write!(f, "task join error: {}", msg),
            AsyncChannelError::MutexPoisoned => write!(f, "channel mutex poisoned"),
            AsyncChannelError::ChannelClosed => write!(f, "channel closed"),
        }
    }
}

impl std::error::Error for AsyncChannelError {}

impl From<ChannelError> for AsyncChannelError {
    fn from(err: ChannelError) -> Self {
        AsyncChannelError::Channel(err)
    }
}

/// Command sent to the writer worker.
enum WriteCommand {
    /// Send data, with a oneshot to signal completion.
    Send {
        data: Vec<u8>,
        response: tokio::sync::oneshot::Sender<Result<(), ChannelError>>,
    },
    Retire,
}

struct WorkerTasks {
    reader: Option<tokio::task::JoinHandle<()>>,
    writer: Option<tokio::task::JoinHandle<()>>,
    completion: Option<Result<(), String>>,
}

/// Async wrapper over `SecureChannel` for integration with Tokio (T92 Part B, T106 Refactor).
///
/// This uses long-lived per-peer blocking workers (reader and writer) to minimize
/// `spawn_blocking` overhead. Instead of spawning a blocking task per send/recv,
/// we spawn two persistent workers per channel that handle all I/O operations.
///
/// # Architecture (T106)
///
/// - **Reader worker**: Runs in a `spawn_blocking` loop, continuously calls
///   `SecureChannel::recv_app()`, and pushes decrypted messages to an async
///   mpsc channel.
///
/// - **Writer worker**: Runs in a `spawn_blocking` loop, receives write commands
///   from an async mpsc channel, calls `SecureChannel::send_app()`, and signals
///   completion via oneshot channels.
///
/// This design reduces `spawn_blocking` usage from O(messages) to O(peers).
///
/// # Metrics Impact (T106)
///
/// With the new architecture, `spawn_blocking` is called only twice per channel
/// (once for reader worker, once for writer worker), not once per message.
/// This dramatically reduces spawn_blocking overhead and thread pool contention
/// under high message rates.
///
/// The `SpawnBlockingMetrics` in `NodeMetrics` will now reflect:
/// - O(peers) spawn_blocking calls instead of O(messages)
/// - Per-message latency is now reflected in async channel operations, not spawn_blocking
///
/// # Thread Safety
///
/// Each worker owns its own mutable reference to the `SecureChannel` (via mutex),
/// ensuring proper serialization of blocking I/O operations.
///
/// # Shutdown
///
/// Workers terminate when:
/// - The async side drops all senders (for reader) or the receiver (for writer)
/// - The underlying SecureChannel encounters a fatal error (EOF, protocol error, etc.)
#[derive(Clone)]
#[allow(clippy::type_complexity)]
pub struct SecureChannelAsync {
    invalidated: Arc<AtomicBool>,
    shutdown_stream: Option<Arc<TcpStream>>,
    shutdown_complete: Arc<AtomicBool>,
    #[cfg(test)]
    fail_shutdown: Arc<AtomicBool>,
    worker_tasks: Arc<tokio::sync::Mutex<WorkerTasks>>,
    /// Channel for sending write commands to the writer worker.
    write_tx: tokio::sync::mpsc::Sender<WriteCommand>,
    /// Channel for receiving decrypted messages from the reader worker.
    read_rx: Arc<tokio::sync::Mutex<tokio::sync::mpsc::Receiver<Result<Vec<u8>, ChannelError>>>>,
}

impl std::fmt::Debug for SecureChannelAsync {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureChannelAsync")
            .field("write_tx", &"<mpsc::Sender>")
            .field("read_rx", &"<mpsc::Receiver>")
            .finish()
    }
}

impl SecureChannelAsync {
    /// Create a new async wrapper from an established `SecureChannel`.
    ///
    /// This spawns two long-lived blocking workers (reader and writer) to handle
    /// all I/O operations for this channel.
    ///
    /// # Panics
    ///
    /// Panics if the channel is not established (handshake not complete).
    /// For a non-panicking alternative, use `try_new()`.
    pub fn new(channel: SecureChannel) -> Self {
        Self::try_new(channel).expect("SecureChannelAsync requires an established SecureChannel")
    }

    /// Try to create a new async wrapper from a `SecureChannel`.
    ///
    /// Returns `Err` if the channel is not established (handshake not complete).
    ///
    /// This spawns two long-lived blocking workers (reader and writer) to handle
    /// all I/O operations for this channel.
    pub fn try_new(channel: SecureChannel) -> Result<Self, AsyncChannelError> {
        Self::try_new_with_shutdown_factory(channel, TcpStream::try_clone)
    }

    fn try_new_with_shutdown_factory(
        channel: SecureChannel,
        create_shutdown_stream: impl FnOnce(&TcpStream) -> io::Result<TcpStream>,
    ) -> Result<Self, AsyncChannelError> {
        let shutdown_stream = create_shutdown_stream(channel.stream())
            .map_err(|e| AsyncChannelError::Channel(ChannelError::Io(e)))?;
        Self::try_new_with_shutdown_stream(channel, shutdown_stream)
    }

    fn try_new_with_shutdown_stream(
        channel: SecureChannel,
        shutdown_stream: TcpStream,
    ) -> Result<Self, AsyncChannelError> {
        if !channel.is_established() {
            return Err(AsyncChannelError::Channel(ChannelError::Net(
                qbind_net::NetError::Protocol("channel handshake not established"),
            )));
        }

        // Set a short read timeout to allow the reader worker to periodically release
        // the mutex, enabling the writer worker to send data. Without this, the reader
        // would hold the mutex indefinitely while blocked on recv_app(), causing deadlock.
        channel
            .stream()
            .set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|e| AsyncChannelError::Channel(ChannelError::Io(e)))?;

        // Create channels for communication with workers
        let (write_tx, write_rx) = tokio::sync::mpsc::channel::<WriteCommand>(32);
        let (read_tx, read_rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, ChannelError>>(32);

        let invalidated = Arc::clone(&channel.invalidated);
        // Wrap the channel in Arc<Mutex> for sharing between workers
        let channel = Arc::new(Mutex::new(channel));

        // Spawn reader worker
        let reader_channel = Arc::clone(&channel);
        let reader = tokio::task::spawn_blocking(move || {
            Self::reader_worker(reader_channel, read_tx);
        });

        // Spawn writer worker
        let writer_channel = Arc::clone(&channel);
        let writer = tokio::task::spawn_blocking(move || {
            Self::writer_worker(writer_channel, write_rx);
        });

        Ok(SecureChannelAsync {
            invalidated,
            shutdown_stream: Some(Arc::new(shutdown_stream)),
            shutdown_complete: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fail_shutdown: Arc::new(AtomicBool::new(false)),
            worker_tasks: Arc::new(tokio::sync::Mutex::new(WorkerTasks {
                reader: Some(reader),
                writer: Some(writer),
                completion: None,
            })),
            write_tx,
            read_rx: Arc::new(tokio::sync::Mutex::new(read_rx)),
        })
    }

    /// Reader worker: continuously reads from SecureChannel and pushes to async channel.
    fn reader_worker(
        channel: Arc<Mutex<SecureChannel>>,
        tx: tokio::sync::mpsc::Sender<Result<Vec<u8>, ChannelError>>,
    ) {
        loop {
            // Read one message
            let result = {
                let mut ch = match channel.lock() {
                    Ok(ch) => ch,
                    Err(_) => {
                        // Mutex poisoned, terminate
                        break;
                    }
                };
                ch.recv_app()
            };

            match result {
                Ok(data) => {
                    // Successfully read data, send to async side
                    if tx.blocking_send(Ok(data)).is_err() {
                        // Async side has dropped the receiver; terminate
                        break;
                    }
                }
                // recv_app preserves timeout kinds only with zero frame progress.
                Err(ChannelError::Io(io_err))
                    if io_err.kind() == io::ErrorKind::TimedOut
                        || io_err.kind() == io::ErrorKind::WouldBlock =>
                {
                    // Check if the channel is still open
                    if tx.is_closed() {
                        // Async side has closed; terminate
                        break;
                    }
                    // Yield briefly to give writer worker a chance to acquire the mutex.
                    // Without this, the reader can starve the writer by continuously
                    // re-acquiring the mutex after each timeout.
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    // Fatal error, send to async side and terminate
                    let _ = tx.blocking_send(Err(e));
                    break;
                }
            }
        }
    }

    /// Writer worker: receives write commands and executes them.
    fn writer_worker(
        channel: Arc<Mutex<SecureChannel>>,
        mut rx: tokio::sync::mpsc::Receiver<WriteCommand>,
    ) {
        while let Some(cmd) = rx.blocking_recv() {
            match cmd {
                WriteCommand::Send { data, response } => {
                    // A failed encrypted write has uncertain delivery, even on
                    // WouldBlock. Never re-encrypt or replay this command.
                    let result = {
                        let mut ch = match channel.lock() {
                            Ok(ch) => ch,
                            Err(_) => {
                                // Mutex poisoned, signal error and terminate
                                let _ = response.send(Err(ChannelError::Io(io::Error::other(
                                    "mutex poisoned",
                                ))));
                                // Terminate the worker thread
                                return;
                            }
                        };
                        ch.send_app(&data)
                    };

                    // Check if result is error before sending (to avoid move)
                    let is_err = result.is_err();

                    // Send result back (ignore if receiver dropped)
                    let _ = response.send(result);

                    // If send_app failed with a fatal error, terminate
                    if is_err {
                        break;
                    }
                }
                WriteCommand::Retire => break,
            }
        }
    }

    /// Create from an existing Arc<Mutex<SecureChannel>>.
    ///
    /// This allows sharing a channel between multiple async handles.
    /// This method spawns new workers for the shared channel.
    ///
    /// If cloning the independent shutdown handle fails, this legacy
    /// infallible constructor returns a non-established, invalidated wrapper
    /// without spawning workers. Sends are refused and the failed wrapper
    /// does not retain the shared channel.
    pub fn from_shared(inner: Arc<Mutex<SecureChannel>>) -> Self {
        // Set a short read timeout to allow the reader worker to periodically release
        // the mutex, enabling the writer worker to send data.
        let shutdown_stream = {
            match inner.lock() {
                Ok(ch) => {
                    let _ = ch
                        .stream()
                        .set_read_timeout(Some(Duration::from_millis(100)));
                    ch.stream().try_clone().ok()
                }
                Err(_) => None,
            }
        };
        Self::from_shared_with_shutdown_stream(inner, shutdown_stream)
    }

    fn from_shared_with_shutdown_stream(
        inner: Arc<Mutex<SecureChannel>>,
        shutdown_stream: Option<TcpStream>,
    ) -> Self {
        let invalidated = match inner.lock() {
            Ok(channel) => Arc::clone(&channel.invalidated),
            Err(_) => Arc::new(AtomicBool::new(true)),
        };
        let shutdown_stream = shutdown_stream.map(Arc::new);

        // Create channels for communication with workers
        let (write_tx, write_rx) = tokio::sync::mpsc::channel::<WriteCommand>(32);
        let (read_tx, read_rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, ChannelError>>(32);

        if shutdown_stream.is_none() {
            invalidated.store(true, Ordering::SeqCst);
            drop(write_rx);
            drop(read_tx);
            return SecureChannelAsync {
                invalidated,
                shutdown_stream: None,
                shutdown_complete: Arc::new(AtomicBool::new(false)),
                #[cfg(test)]
                fail_shutdown: Arc::new(AtomicBool::new(false)),
                worker_tasks: Arc::new(tokio::sync::Mutex::new(WorkerTasks {
                    reader: None,
                    writer: None,
                    completion: Some(Err(
                        "shutdown capability unavailable; shared session refused".to_owned(),
                    )),
                })),
                write_tx,
                read_rx: Arc::new(tokio::sync::Mutex::new(read_rx)),
            };
        }

        // Spawn reader worker
        let reader_channel = Arc::clone(&inner);
        let reader = tokio::task::spawn_blocking(move || {
            Self::reader_worker(reader_channel, read_tx);
        });

        // Spawn writer worker
        let writer_channel = Arc::clone(&inner);
        let writer = tokio::task::spawn_blocking(move || {
            Self::writer_worker(writer_channel, write_rx);
        });

        SecureChannelAsync {
            invalidated,
            shutdown_stream,
            shutdown_complete: Arc::new(AtomicBool::new(false)),
            #[cfg(test)]
            fail_shutdown: Arc::new(AtomicBool::new(false)),
            worker_tasks: Arc::new(tokio::sync::Mutex::new(WorkerTasks {
                reader: Some(reader),
                writer: Some(writer),
                completion: None,
            })),
            write_tx,
            read_rx: Arc::new(tokio::sync::Mutex::new(read_rx)),
        }
    }

    pub(crate) fn begin_retirement(&self) -> Result<(), AsyncChannelError> {
        self.invalidated.store(true, Ordering::SeqCst);
        let _ = self.write_tx.try_send(WriteCommand::Retire);
        if self.shutdown_complete.load(Ordering::SeqCst) {
            return Ok(());
        }
        #[cfg(test)]
        if self.fail_shutdown.load(Ordering::SeqCst) {
            return Err(AsyncChannelError::Channel(ChannelError::Io(
                io::Error::other("injected shutdown capability failure"),
            )));
        }
        let shutdown_stream = self.shutdown_stream.as_ref().ok_or_else(|| {
            AsyncChannelError::Channel(ChannelError::Io(io::Error::other(
                "secure-channel shutdown capability unavailable",
            )))
        })?;
        match shutdown_stream.shutdown(Shutdown::Both) {
            Ok(()) => {
                self.shutdown_complete.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotConnected => {
                self.shutdown_complete.store(true, Ordering::SeqCst);
                Ok(())
            }
            Err(error) => Err(AsyncChannelError::Channel(ChannelError::Io(error))),
        }
    }

    #[cfg(test)]
    pub(crate) fn fail_shutdown_for_test(&self, fail: bool) {
        self.fail_shutdown.store(fail, Ordering::SeqCst);
    }

    pub(crate) fn invalidate_for_retirement(&self) {
        self.invalidated.store(true, Ordering::SeqCst);
        let _ = self.write_tx.try_send(WriteCommand::Retire);
    }

    pub(crate) async fn finish_retirement(&self) -> Result<(), AsyncChannelError> {
        {
            let mut receiver = self.read_rx.lock().await;
            receiver.close();
            while receiver.try_recv().is_ok() {}
        }

        let mut tasks = self.worker_tasks.lock().await;
        if let Some(result) = &tasks.completion {
            return result
                .as_ref()
                .map(|()| ())
                .map_err(|error| AsyncChannelError::TaskJoin(error.clone()));
        }

        let mut failures = Vec::new();
        if let Some(reader) = tasks.reader.as_mut() {
            if let Err(error) = reader.await {
                failures.push(format!("reader worker: {error}"));
            }
            tasks.reader = None;
        }
        if let Some(writer) = tasks.writer.as_mut() {
            if let Err(error) = writer.await {
                failures.push(format!("writer worker: {error}"));
            }
            tasks.writer = None;
        }

        let result = if failures.is_empty() {
            Ok(())
        } else {
            Err(failures.join("; "))
        };
        tasks.completion = Some(result.clone());
        result.map_err(AsyncChannelError::TaskJoin)
    }

    /// Get a clone of the inner Arc for sharing.
    ///
    /// # Deprecated
    ///
    /// This method is deprecated with the new per-peer worker architecture (T106).
    /// Instead of sharing the underlying SecureChannel, clone the SecureChannelAsync
    /// handle directly, which will share the same worker channels.
    ///
    /// # Returns
    ///
    /// Always returns an error indicating the operation is not supported.
    #[deprecated(
        since = "0.1.0",
        note = "Use clone() instead; shared() is not compatible with per-peer workers"
    )]
    pub fn shared(&self) -> Arc<Mutex<SecureChannel>> {
        // This method cannot be implemented efficiently with the new architecture
        // because we don't store a reference to the underlying SecureChannel after
        // spawning workers. Users should clone SecureChannelAsync instead.
        panic!(
            "shared() is deprecated and not supported with per-peer workers; \
             clone SecureChannelAsync instead"
        )
    }

    /// Send an application message asynchronously.
    ///
    /// This sends a write command to the writer worker and awaits completion.
    /// No `spawn_blocking` is called per send; the writer worker handles all sends.
    ///
    /// # Arguments
    ///
    /// * `plaintext` - The message to encrypt and send
    ///
    /// # Errors
    ///
    /// Returns `AsyncChannelError` if:
    /// - Encryption fails
    /// - TCP write fails
    /// - The writer worker has terminated
    /// - The session was invalidated by a send or partial-frame read failure
    pub async fn send(&self, plaintext: &[u8]) -> Result<(), AsyncChannelError> {
        if self.invalidated.load(Ordering::SeqCst) {
            return Err(SecureChannel::invalidated_error().into());
        }
        let (response_tx, response_rx) = tokio::sync::oneshot::channel();

        let cmd = WriteCommand::Send {
            data: plaintext.to_vec(),
            response: response_tx,
        };

        // Send command to writer worker
        self.write_tx
            .send(cmd)
            .await
            .map_err(|_| AsyncChannelError::ChannelClosed)?;

        // Wait for completion
        response_rx
            .await
            .map_err(|_| AsyncChannelError::ChannelClosed)?
            .map_err(AsyncChannelError::Channel)
    }

    /// Receive and decrypt an application message asynchronously.
    ///
    /// This receives the next message from the reader worker's channel.
    /// No `spawn_blocking` is called per recv; the reader worker handles all reads.
    ///
    /// # Returns
    ///
    /// The decrypted plaintext message.
    ///
    /// # Errors
    ///
    /// Returns `AsyncChannelError` if:
    /// - TCP read fails (including timeout or EOF)
    /// - Decryption fails
    /// - The reader worker has terminated
    /// - The session was invalidated by a send or partial-frame read failure
    pub async fn recv(&self) -> Result<Vec<u8>, AsyncChannelError> {
        if self.invalidated.load(Ordering::SeqCst) {
            return Err(SecureChannel::invalidated_error().into());
        }
        let mut rx = self.read_rx.lock().await;

        let result = rx
            .recv()
            .await
            .ok_or(AsyncChannelError::ChannelClosed)?
            .map_err(AsyncChannelError::Channel);
        // Keep fatal error details, but never release queued plaintext after
        // session invalidation.
        if result.is_ok() && self.invalidated.load(Ordering::SeqCst) {
            return Err(SecureChannel::invalidated_error().into());
        }
        result
    }

    /// Check if the underlying connection is established.
    ///
    /// Requires an open writer queue and a session not invalidated by an I/O
    /// failure. This does not establish reader/worker completion or peer removal.
    ///
    /// # Returns
    ///
    /// `true` if the session is not invalidated and the writer queue is open.
    pub fn is_established(&self) -> bool {
        !self.invalidated.load(Ordering::SeqCst) && !self.write_tx.is_closed()
    }

    /// Set the socket timeout for blocking operations.
    ///
    /// Note: With the new per-peer worker architecture, socket timeouts are configured
    /// when the channel is created. This method is kept for backward compatibility but
    /// does nothing.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())`.
    pub async fn set_read_timeout(
        &self,
        _timeout: Option<Duration>,
    ) -> Result<(), AsyncChannelError> {
        // Socket timeout is already configured in try_new()
        // This is a no-op for backward compatibility
        Ok(())
    }

    /// Set the socket timeout for write operations.
    ///
    /// Note: With the new per-peer worker architecture, socket timeouts are configured
    /// when the channel is created. This method is kept for backward compatibility but
    /// does nothing.
    ///
    /// # Returns
    ///
    /// Always returns `Ok(())`.
    pub async fn set_write_timeout(
        &self,
        _timeout: Option<Duration>,
    ) -> Result<(), AsyncChannelError> {
        // Socket timeout is already configured in try_new()
        // This is a no-op for backward compatibility
        Ok(())
    }
}

// ============================================================================
// Async Client/Server Handshake Helpers (T92 Part D)
// ============================================================================

/// Perform a blocking client-side KEMTLS connection in a spawn_blocking task.
///
/// This is a helper for `AsyncPeerManagerImpl` to establish outbound connections
/// using KEMTLS encryption.
///
/// # Arguments
///
/// * `addr` - Remote socket address (host:port)
/// * `cfg` - Client handshake configuration
///
/// # Returns
///
/// A `SecureChannelAsync` ready for encrypted communication.
///
/// # Errors
///
/// Returns `AsyncChannelError` if:
/// - TCP connection fails
/// - KEMTLS handshake fails
/// - The spawn_blocking task panics
pub async fn connect_kemtls_async(
    addr: String,
    cfg: ClientConnectionConfig,
) -> Result<SecureChannelAsync, AsyncChannelError> {
    // Perform the blocking connect in spawn_blocking
    let channel = tokio::task::spawn_blocking(move || SecureChannel::connect(&addr, cfg))
        .await
        .map_err(|e| AsyncChannelError::TaskJoin(e.to_string()))?
        .map_err(AsyncChannelError::Channel)?;

    // Create the async wrapper outside the blocking context
    // This spawns the reader/writer workers
    let async_channel = SecureChannelAsync::try_new(channel)?;

    // Give workers a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(async_channel)
}

/// Like [`connect_kemtls_async`], but additionally surfaces the actual verified
/// server identity established by the successful client-side KEMTLS handshake
/// (Run 418, F6).
///
/// The returned [`VerifiedServerIdentity`] is read from the established
/// `Connection` (verified server cert-derived NodeId + validator id +
/// authentication state). It is `None` only if the underlying connection did
/// not surface a server cert identity. Callers on the production
/// `MutualAuthMode::Required` + `pqc-static-root` path MUST compare this actual
/// identity against the configured authoritative map and reject the session on
/// any mismatch, rather than minting an origin from the dial address.
pub async fn connect_kemtls_async_with_server_identity(
    addr: String,
    cfg: ClientConnectionConfig,
) -> Result<(SecureChannelAsync, Option<VerifiedServerIdentity>), AsyncChannelError> {
    let (channel, server_identity) =
        connect_kemtls_secure_channel_with_server_identity(addr, cfg).await?;

    // Create the async wrapper outside the blocking context
    // This spawns the reader/writer workers
    let async_channel = SecureChannelAsync::try_new(channel)?;

    // Give workers a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok((async_channel, server_identity))
}

pub async fn connect_kemtls_secure_channel_with_server_identity(
    addr: String,
    cfg: ClientConnectionConfig,
) -> Result<(SecureChannel, Option<VerifiedServerIdentity>), AsyncChannelError> {
    tokio::task::spawn_blocking(move || match SecureChannel::connect(&addr, cfg) {
        Ok(channel) => {
            let identity = channel.verified_server_identity();
            Ok((channel, identity))
        }
        Err(error) => Err(error),
    })
    .await
    .map_err(|error| AsyncChannelError::TaskJoin(error.to_string()))?
    .map_err(AsyncChannelError::Channel)
}

/// Perform a blocking server-side KEMTLS handshake in a spawn_blocking task.
///
/// This is a helper for `AsyncPeerManagerImpl` to accept inbound connections
/// using KEMTLS encryption.
///
/// # Arguments
///
/// * `stream` - An already-accepted std::net::TcpStream
/// * `cfg` - Server handshake configuration
///
/// # Returns
///
/// A `SecureChannelAsync` ready for encrypted communication.
///
/// # Errors
///
/// Returns `AsyncChannelError` if:
/// - KEMTLS handshake fails
/// - The spawn_blocking task panics
pub async fn accept_kemtls_async(
    stream: TcpStream,
    cfg: ServerConnectionConfig,
) -> Result<SecureChannelAsync, AsyncChannelError> {
    // Perform the blocking handshake in spawn_blocking
    let channel = tokio::task::spawn_blocking(move || SecureChannel::from_accepted(stream, cfg))
        .await
        .map_err(|e| AsyncChannelError::TaskJoin(e.to_string()))?
        .map_err(AsyncChannelError::Channel)?;

    // Create the async wrapper outside the blocking context
    // This spawns the reader/writer workers
    let async_channel = SecureChannelAsync::try_new(channel)?;

    // Give workers a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok(async_channel)
}

/// Like [`accept_kemtls_async`], but additionally returns the
/// dialer-supplied `client_random` and `validator_id` fields from the
/// parsed `ClientInit` so the caller can register the accepted session
/// under a non-temporary, deterministic NodeId (B8 — listener-side
/// identity closure).
///
/// See [`AcceptedPeerInit`] for the semantics (test-grade,
/// self-asserted; not stronger than the pre-B8 behaviour).
pub async fn accept_kemtls_async_with_peer_init(
    stream: TcpStream,
    cfg: ServerConnectionConfig,
) -> Result<(SecureChannelAsync, AcceptedPeerInit), AsyncChannelError> {
    let (channel, peer_init) = accept_kemtls_secure_channel_with_peer_init(stream, cfg).await?;

    // Create the async wrapper outside the blocking context
    let async_channel = SecureChannelAsync::try_new(channel)?;

    // Give workers a moment to start
    tokio::time::sleep(Duration::from_millis(100)).await;

    Ok((async_channel, peer_init))
}

pub async fn accept_kemtls_secure_channel_with_peer_init(
    stream: TcpStream,
    cfg: ServerConnectionConfig,
) -> Result<(SecureChannel, AcceptedPeerInit), AsyncChannelError> {
    tokio::task::spawn_blocking(move || SecureChannel::from_accepted_with_peer_init(stream, cfg))
        .await
        .map_err(|error| AsyncChannelError::TaskJoin(error.to_string()))?
        .map_err(AsyncChannelError::Channel)
}
