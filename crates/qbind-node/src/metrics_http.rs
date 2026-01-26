//! Minimal HTTP server for exposing /metrics endpoint (T126).
//!
//! This module provides a lightweight HTTP server for Prometheus scraping
//! of `NodeMetrics`. It uses only tokio + std (no hyper or other HTTP crates).
//!
//! # Design
//!
//! - Listens on a configurable TCP address
//! - Handles simple HTTP/1.1 GET requests
//! - Returns 200 OK for GET /metrics with Prometheus-format output
//! - Returns 404 Not Found for all other paths
//! - Gracefully shuts down when signaled
//!
//! # Example
//!
//! ```ignore
//! use std::sync::Arc;
//! use tokio::sync::watch;
//! use qbind_node::metrics::NodeMetrics;
//! use qbind_node::metrics_http::{MetricsHttpConfig, spawn_metrics_http_server};
//!
//! #[tokio::main]
//! async fn main() {
//!     let metrics = Arc::new(NodeMetrics::new());
//!     let config = MetricsHttpConfig::from_addr("127.0.0.1:9100");
//!     let (shutdown_tx, shutdown_rx) = watch::channel(());
//!
//!     let handle = spawn_metrics_http_server(metrics, config, shutdown_rx);
//!
//!     // ... run node ...
//!
//!     // To shut down:
//!     drop(shutdown_tx);
//!     handle.await.unwrap();
//! }
//! ```
//!
//! # Configuration via Environment
//!
//! Set `QBIND_METRICS_HTTP_ADDR` to enable the server:
//! - `QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100` - Enable on localhost:9100
//! - Not set - Server disabled (default)
//! - Invalid address - Warning logged, server disabled

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::async_peer_manager::KemtlsMetrics;
use crate::metrics::NodeMetrics;
use qbind_consensus::ConsensusSigMetrics;

// ============================================================================
// Configuration
// ============================================================================

/// Environment variable name for the metrics HTTP bind address.
pub const METRICS_HTTP_ADDR_ENV: &str = "QBIND_METRICS_HTTP_ADDR";

/// Configuration for the metrics HTTP server.
///
/// # Fields
///
/// - `bind_addr`: The address to bind the HTTP server to
/// - `enabled`: Whether the server should start
///
/// # Defaults
///
/// By default, the server is disabled. Use `from_env()` to enable it via
/// environment variable, or construct explicitly with `from_addr()`.
#[derive(Debug, Clone)]
pub struct MetricsHttpConfig {
    /// The address to bind the HTTP server to.
    pub bind_addr: SocketAddr,
    /// Whether the server is enabled.
    pub enabled: bool,
}

impl Default for MetricsHttpConfig {
    fn default() -> Self {
        Self::disabled()
    }
}

impl MetricsHttpConfig {
    /// Create a disabled configuration (default).
    ///
    /// Use this when you don't want to expose metrics over HTTP.
    pub fn disabled() -> Self {
        MetricsHttpConfig {
            bind_addr: "127.0.0.1:0".parse().unwrap(),
            enabled: false,
        }
    }

    /// Create an enabled configuration from a socket address.
    ///
    /// # Arguments
    ///
    /// * `addr` - The address to bind to (e.g., "127.0.0.1:9100")
    ///
    /// # Panics
    ///
    /// Panics if the address cannot be parsed.
    pub fn from_addr(addr: &str) -> Self {
        MetricsHttpConfig {
            bind_addr: addr.parse().expect("invalid bind address"),
            enabled: true,
        }
    }

    /// Create an enabled configuration from a parsed socket address.
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        MetricsHttpConfig {
            bind_addr: addr,
            enabled: true,
        }
    }

    /// Load configuration from environment variables.
    ///
    /// Reads `QBIND_METRICS_HTTP_ADDR`:
    /// - If set and valid: Returns enabled config bound to that address
    /// - If set but invalid: Logs warning, returns disabled config
    /// - If not set: Returns disabled config
    ///
    /// # Example
    ///
    /// ```bash
    /// QBIND_METRICS_HTTP_ADDR=127.0.0.1:9100 cargo run
    /// ```
    pub fn from_env() -> Self {
        match std::env::var(METRICS_HTTP_ADDR_ENV) {
            Ok(addr_str) => match addr_str.parse::<SocketAddr>() {
                Ok(addr) => {
                    eprintln!(
                        "[metrics_http] Enabling metrics HTTP server on {} (from {})",
                        addr, METRICS_HTTP_ADDR_ENV
                    );
                    MetricsHttpConfig {
                        bind_addr: addr,
                        enabled: true,
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[metrics_http] WARNING: Invalid {} value '{}': {}. Server disabled.",
                        METRICS_HTTP_ADDR_ENV, addr_str, e
                    );
                    Self::disabled()
                }
            },
            Err(_) => {
                // Not set - disabled by default
                Self::disabled()
            }
        }
    }

    /// Check if the server is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }
}

// ============================================================================
// Metrics HTTP Server
// ============================================================================

/// Shared references for crypto metrics (optional).
///
/// These are passed to the server so it can include PQC metrics in the output.
#[derive(Clone, Default)]
pub struct CryptoMetricsRefs {
    /// Consensus signature metrics (per-suite verification counts).
    pub consensus_sig_metrics: Option<Arc<ConsensusSigMetrics>>,
    /// KEMTLS handshake metrics.
    pub kemtls_metrics: Option<Arc<KemtlsMetrics>>,
}

impl CryptoMetricsRefs {
    /// Create empty crypto metrics refs.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set consensus signature metrics.
    pub fn with_consensus_sig(mut self, metrics: Arc<ConsensusSigMetrics>) -> Self {
        self.consensus_sig_metrics = Some(metrics);
        self
    }

    /// Set KEMTLS metrics.
    pub fn with_kemtls(mut self, metrics: Arc<KemtlsMetrics>) -> Self {
        self.kemtls_metrics = Some(metrics);
        self
    }
}

/// Spawn the metrics HTTP server as an async task.
///
/// If the configuration is disabled, returns a no-op task that completes immediately.
///
/// # Arguments
///
/// * `metrics` - Arc reference to NodeMetrics
/// * `config` - Server configuration (bind address, enabled flag)
/// * `shutdown_rx` - Watch receiver for shutdown signal
///
/// # Returns
///
/// A JoinHandle that completes when the server shuts down.
///
/// # Example
///
/// ```ignore
/// let metrics = Arc::new(NodeMetrics::new());
/// let config = MetricsHttpConfig::from_addr("127.0.0.1:9100");
/// let (shutdown_tx, shutdown_rx) = watch::channel(());
///
/// let handle = spawn_metrics_http_server(metrics, config, shutdown_rx);
///
/// // Shutdown by dropping the sender
/// drop(shutdown_tx);
/// handle.await.unwrap();
/// ```
pub fn spawn_metrics_http_server(
    metrics: Arc<NodeMetrics>,
    config: MetricsHttpConfig,
    shutdown_rx: watch::Receiver<()>,
) -> JoinHandle<()> {
    spawn_metrics_http_server_with_crypto(metrics, config, CryptoMetricsRefs::new(), shutdown_rx)
}

/// Spawn the metrics HTTP server with crypto/PQC metrics.
///
/// This variant includes additional crypto metrics (ConsensusSigMetrics, KemtlsMetrics)
/// in the /metrics output.
///
/// # Arguments
///
/// * `metrics` - Arc reference to NodeMetrics
/// * `config` - Server configuration (bind address, enabled flag)
/// * `crypto_refs` - Optional crypto metrics references
/// * `shutdown_rx` - Watch receiver for shutdown signal
pub fn spawn_metrics_http_server_with_crypto(
    metrics: Arc<NodeMetrics>,
    config: MetricsHttpConfig,
    crypto_refs: CryptoMetricsRefs,
    shutdown_rx: watch::Receiver<()>,
) -> JoinHandle<()> {
    if !config.enabled {
        // Return a no-op task that completes immediately
        return tokio::spawn(async {});
    }

    tokio::spawn(async move {
        if let Err(e) =
            run_metrics_http_server(metrics, config.bind_addr, crypto_refs, shutdown_rx).await
        {
            eprintln!("[metrics_http] Server error: {}", e);
        }
    })
}

/// Spawn the metrics HTTP server and return the actual bound address.
///
/// This is useful for testing when binding to port 0 (OS-assigned).
///
/// # Arguments
///
/// * `metrics` - Arc reference to NodeMetrics
/// * `config` - Server configuration (bind address, enabled flag)
/// * `crypto_refs` - Optional crypto metrics references  
/// * `shutdown_rx` - Watch receiver for shutdown signal
///
/// # Returns
///
/// A tuple of (JoinHandle, Option<SocketAddr>). The SocketAddr is Some if the server
/// was enabled and bound successfully.
pub async fn spawn_metrics_http_server_with_addr(
    metrics: Arc<NodeMetrics>,
    config: MetricsHttpConfig,
    crypto_refs: CryptoMetricsRefs,
    shutdown_rx: watch::Receiver<()>,
) -> (JoinHandle<()>, Option<SocketAddr>) {
    if !config.enabled {
        return (tokio::spawn(async {}), None);
    }

    // Bind first to get the actual address
    let listener = match TcpListener::bind(config.bind_addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!(
                "[metrics_http] Failed to bind to {}: {}",
                config.bind_addr, e
            );
            return (tokio::spawn(async {}), None);
        }
    };

    let local_addr = listener.local_addr().ok();
    if let Some(addr) = local_addr {
        eprintln!("[metrics_http] Listening on {}", addr);
    }

    let handle = tokio::spawn(async move {
        if let Err(e) =
            run_metrics_http_server_with_listener(metrics, listener, crypto_refs, shutdown_rx).await
        {
            eprintln!("[metrics_http] Server error: {}", e);
        }
    });

    (handle, local_addr)
}

/// Run the metrics HTTP server main loop.
async fn run_metrics_http_server(
    metrics: Arc<NodeMetrics>,
    bind_addr: SocketAddr,
    crypto_refs: CryptoMetricsRefs,
    shutdown_rx: watch::Receiver<()>,
) -> Result<(), MetricsHttpError> {
    let listener = TcpListener::bind(bind_addr)
        .await
        .map_err(MetricsHttpError::Bind)?;

    let local_addr = listener.local_addr().map_err(MetricsHttpError::Bind)?;
    eprintln!("[metrics_http] Listening on {}", local_addr);

    run_metrics_http_server_with_listener(metrics, listener, crypto_refs, shutdown_rx).await
}

/// Run the metrics HTTP server with an existing listener.
async fn run_metrics_http_server_with_listener(
    metrics: Arc<NodeMetrics>,
    listener: TcpListener,
    crypto_refs: CryptoMetricsRefs,
    mut shutdown_rx: watch::Receiver<()>,
) -> Result<(), MetricsHttpError> {
    loop {
        tokio::select! {
            // Accept incoming connections
            accept_result = listener.accept() => {
                match accept_result {
                    Ok((stream, peer_addr)) => {
                        // Handle each connection in its own task (short-lived)
                        let metrics = metrics.clone();
                        let crypto_refs = crypto_refs.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream, &metrics, &crypto_refs).await {
                                eprintln!("[metrics_http] Connection from {} error: {}", peer_addr, e);
                            }
                        });
                    }
                    Err(e) => {
                        // Log but continue - transient accept errors are common
                        eprintln!("[metrics_http] Accept error: {}", e);
                    }
                }
            }
            // Shutdown signal
            _ = shutdown_rx.changed() => {
                eprintln!("[metrics_http] Shutting down");
                break;
            }
        }
    }

    Ok(())
}

/// Handle a single HTTP connection.
async fn handle_connection(
    mut stream: TcpStream,
    metrics: &NodeMetrics,
    crypto_refs: &CryptoMetricsRefs,
) -> Result<(), MetricsHttpError> {
    // Read the HTTP request (just enough to parse the method and path)
    let mut reader = BufReader::new(&mut stream);
    let mut request_line = String::new();

    // Read the first line (request line: GET /path HTTP/1.1)
    reader
        .read_line(&mut request_line)
        .await
        .map_err(MetricsHttpError::Io)?;

    // Read remaining headers until we see \r\n\r\n (we don't parse them, just skip)
    let mut header_line = String::new();
    loop {
        header_line.clear();
        let bytes_read = reader
            .read_line(&mut header_line)
            .await
            .map_err(MetricsHttpError::Io)?;
        if bytes_read == 0 || header_line == "\r\n" || header_line == "\n" {
            break;
        }
    }

    // Parse the request line
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        // Malformed request - send 400
        send_response(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        )
        .await?;
        return Ok(());
    }

    let method = parts[0];
    let path = parts[1];

    // Only handle GET requests
    if method != "GET" {
        send_response(
            &mut stream,
            405,
            "Method Not Allowed",
            "text/plain",
            b"Method Not Allowed",
        )
        .await?;
        return Ok(());
    }

    // Route based on path
    if path == "/metrics" || path == "/metrics/" {
        // Generate metrics output
        let body = format_metrics_output(metrics, crypto_refs);
        send_response(
            &mut stream,
            200,
            "OK",
            "text/plain; version=0.0.4; charset=utf-8",
            body.as_bytes(),
        )
        .await?;
    } else {
        // 404 for anything else
        send_response(&mut stream, 404, "Not Found", "text/plain", b"Not Found").await?;
    }

    Ok(())
}

/// Generate the metrics output string.
fn format_metrics_output(metrics: &NodeMetrics, crypto_refs: &CryptoMetricsRefs) -> String {
    // Use format_metrics_with_crypto if we have crypto metrics, otherwise plain format_metrics
    let sig_metrics = crypto_refs
        .consensus_sig_metrics
        .as_ref()
        .map(|a| a.as_ref());
    let kemtls = crypto_refs.kemtls_metrics.as_ref().map(|a| a.as_ref());

    if sig_metrics.is_some() || kemtls.is_some() {
        metrics.format_metrics_with_crypto(sig_metrics, kemtls)
    } else {
        metrics.format_metrics()
    }
}

/// Send an HTTP response.
async fn send_response(
    stream: &mut TcpStream,
    status_code: u16,
    status_text: &str,
    content_type: &str,
    body: &[u8],
) -> Result<(), MetricsHttpError> {
    let response = format!(
        "HTTP/1.1 {} {}\r\n\
         Content-Type: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n",
        status_code,
        status_text,
        content_type,
        body.len()
    );

    stream
        .write_all(response.as_bytes())
        .await
        .map_err(MetricsHttpError::Io)?;
    stream.write_all(body).await.map_err(MetricsHttpError::Io)?;
    stream.flush().await.map_err(MetricsHttpError::Io)?;

    Ok(())
}

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur in the metrics HTTP server.
#[derive(Debug)]
pub enum MetricsHttpError {
    /// Failed to bind to the address.
    Bind(std::io::Error),
    /// I/O error during request/response handling.
    Io(std::io::Error),
}

impl std::fmt::Display for MetricsHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MetricsHttpError::Bind(e) => write!(f, "bind error: {}", e),
            MetricsHttpError::Io(e) => write!(f, "I/O error: {}", e),
        }
    }
}

impl std::error::Error for MetricsHttpError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            MetricsHttpError::Bind(e) | MetricsHttpError::Io(e) => Some(e),
        }
    }
}
