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

use std::io;
use std::net::TcpStream;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use qbind_net::{
    read_handshake_packet, read_transport_frame, write_handshake_packet, write_transport_frame,
    ClientConnectionConfig, Connection, HandshakePacket, NetError, ServerConnectionConfig,
    TransportFrame,
};

/// Default timeout for socket read/write operations (in seconds).
const DEFAULT_SOCKET_TIMEOUT_SECS: u64 = 10;

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
}

impl SecureChannel {
    /// Get a reference to the underlying TCP stream.
    ///
    /// This is useful for setting socket options like timeouts.
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

        Ok(SecureChannel { stream, conn })
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

        Ok(SecureChannel { stream, conn })
    }

    /// Encrypt and send an application message.
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if encryption fails or the TCP write fails.
    pub fn send_app(&mut self, plaintext: &[u8]) -> Result<(), ChannelError> {
        let frame_bytes = self.conn.encrypt_app(plaintext)?;
        let frame = TransportFrame::decode(&frame_bytes)?;
        write_transport_frame(&mut self.stream, &frame)?;
        Ok(())
    }

    /// Receive and decrypt a single application message.
    ///
    /// This blocks until one full transport frame is read or an I/O error occurs.
    ///
    /// # Errors
    ///
    /// Returns `ChannelError` if the TCP read fails or decryption fails.
    pub fn recv_app(&mut self) -> Result<Vec<u8>, ChannelError> {
        let frame = read_transport_frame(&mut self.stream)?;
        let plaintext = self.conn.decrypt_app(&frame.encode()?)?;
        Ok(plaintext)
    }

    /// Check if the connection is established and ready for app data.
    pub fn is_established(&self) -> bool {
        self.conn.is_established()
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

        // Wrap the channel in Arc<Mutex> for sharing between workers
        let channel = Arc::new(Mutex::new(channel));

        // Spawn reader worker
        let reader_channel = Arc::clone(&channel);
        tokio::task::spawn_blocking(move || {
            Self::reader_worker(reader_channel, read_tx);
        });

        // Spawn writer worker
        let writer_channel = Arc::clone(&channel);
        tokio::task::spawn_blocking(move || {
            Self::writer_worker(writer_channel, write_rx);
        });

        Ok(SecureChannelAsync {
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
                // Both TimedOut and WouldBlock are treated as non-fatal, retryable conditions:
                // - TimedOut: socket read timeout expired, no data available yet
                // - WouldBlock: on some Linux systems, socket timeouts return EAGAIN instead of ETIMEDOUT
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
                    // Retry loop for WouldBlock errors
                    let result = loop {
                        let send_result = {
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

                        match send_result {
                            Ok(()) => break Ok(()),
                            Err(ChannelError::Io(ref io_err))
                                if io_err.kind() == io::ErrorKind::WouldBlock =>
                            {
                                // WouldBlock is retryable - yield briefly and retry
                                std::thread::sleep(Duration::from_millis(1));
                                continue;
                            }
                            Err(e) => break Err(e),
                        }
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
            }
        }
    }

    /// Create from an existing Arc<Mutex<SecureChannel>>.
    ///
    /// This allows sharing a channel between multiple async handles.
    /// This method spawns new workers for the shared channel.
    pub fn from_shared(inner: Arc<Mutex<SecureChannel>>) -> Self {
        // Set a short read timeout to allow the reader worker to periodically release
        // the mutex, enabling the writer worker to send data.
        {
            if let Ok(ch) = inner.lock() {
                let _ = ch
                    .stream()
                    .set_read_timeout(Some(Duration::from_millis(100)));
            }
        }

        // Create channels for communication with workers
        let (write_tx, write_rx) = tokio::sync::mpsc::channel::<WriteCommand>(32);
        let (read_tx, read_rx) = tokio::sync::mpsc::channel::<Result<Vec<u8>, ChannelError>>(32);

        // Spawn reader worker
        let reader_channel = Arc::clone(&inner);
        tokio::task::spawn_blocking(move || {
            Self::reader_worker(reader_channel, read_tx);
        });

        // Spawn writer worker
        let writer_channel = Arc::clone(&inner);
        tokio::task::spawn_blocking(move || {
            Self::writer_worker(writer_channel, write_rx);
        });

        SecureChannelAsync {
            write_tx,
            read_rx: Arc::new(tokio::sync::Mutex::new(read_rx)),
        }
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
    pub async fn send(&self, plaintext: &[u8]) -> Result<(), AsyncChannelError> {
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
    pub async fn recv(&self) -> Result<Vec<u8>, AsyncChannelError> {
        let mut rx = self.read_rx.lock().await;

        rx.recv()
            .await
            .ok_or(AsyncChannelError::ChannelClosed)?
            .map_err(AsyncChannelError::Channel)
    }

    /// Check if the underlying connection is established.
    ///
    /// With the new architecture, we consider the connection established if
    /// the write channel is still open (i.e., the writer worker is still running).
    ///
    /// # Returns
    ///
    /// `true` if the connection is established and workers are running.
    pub fn is_established(&self) -> bool {
        !self.write_tx.is_closed()
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
