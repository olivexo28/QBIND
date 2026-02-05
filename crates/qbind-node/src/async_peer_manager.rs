//! Async peer manager for post-quantum consensus networking (T90.1, T91).
//!
//! This module provides `AsyncPeerManager`, a trait that abstracts what the
//! consensus layer needs from the peer networking layer, and `AsyncPeerManagerImpl`,
//! a concrete implementation using Tokio networking primitives.
//!
//! # Design Overview
//!
//! The async peer manager provides a clean separation between:
//! - **Consensus logic**: Synchronous, deterministic HotStuff engines
//! - **Network layer**: Async, event-driven peer management
//!
//! # High-Level Model
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                     AsyncPeerManagerImpl                        │
//! │                                                                 │
//! │  ┌─────────────┐     ┌─────────────────────────────────────┐     │
//! │  │  Listener   │───▶│  Inbound Connection Acceptance     │     │
//! │  │  (TCP)      │    │  (spawn_blocking KEMTLS handshake)  │    │
//! │  └─────────────┘    └─────────────────────────────────────┘    │
//! │                                     │                           │
//! │                                     ▼                           │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                   Per-Peer Tasks                         │   │
//! │  │  ┌───────────┐   ┌───────────┐   ┌───────────┐          │   │
//! │  │  │  Reader   │   │  Reader   │   │  Reader   │          │   │
//! │  │  │  Task     │   │  Task     │   │  Task     │          │   │
//! │  │  └─────┬─────┘   └─────┬─────┘   └─────┬─────┘          │   │
//! │  │        │               │               │                 │   │
//! │  │        ▼               ▼               ▼                 │   │
//! │  │  ┌─────────────────────────────────────────────────┐    │   │
//! │  │  │              Inbound Event Channel              │    │   │
//! │  │  │     ConsensusNetworkEvent<PeerId> mpsc          │    │   │
//! │  │  └─────────────────────┬───────────────────────────┘    │   │
//! │  └────────────────────────┼─────────────────────────────────┘   │
//! │                           │                                     │
//! │                           ▼                                     │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                   recv_event()                          │   │
//! │  │     Returns ConsensusNetworkEvent<PeerId>               │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! │                                                                 │
//! │  ┌─────────────────────────────────────────────────────────┐   │
//! │  │                  Outbound Path                           │   │
//! │  │  send_vote_to / broadcast_vote / broadcast_proposal      │   │
//! │  │              │                                           │   │
//! │  │              ▼                                           │   │
//! │  │  ┌───────────────────────────────────────────────────┐  │   │
//! │  │  │            Per-Peer Write Channels                │  │   │
//! │  │  │  PeerId -> mpsc::Sender<NetMessage>               │  │   │
//! │  │  └───────────────────────┬───────────────────────────┘  │   │
//! │  │                          │                              │   │
//! │  │                          ▼                              │   │
//! │  │  ┌───────────┐   ┌───────────┐   ┌───────────┐         │   │
//! │  │  │  Writer   │   │  Writer   │   │  Writer   │         │   │
//! │  │  │  Task     │   │  Task     │   │  Task     │         │   │
//! │  │  └───────────┘   └───────────┘   └───────────┘         │   │
//! │  └─────────────────────────────────────────────────────────┘   │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # KEMTLS Handshake Handling (T91)
//!
//! The existing KEMTLS implementation (`qbind-net`) is blocking. Handshakes are
//! performed inside `spawn_blocking` calls:
//! - Handshake happens once per connection during setup
//! - After handshake completes, the underlying std::net::TcpStream is converted
//!   to a Tokio TcpStream for async read/write
//!
//! ## Transport Security Modes
//!
//! The peer manager supports two transport security modes:
//! - `PlainTcp`: Raw TCP without encryption (for tests/load harness)
//! - `Kemtls`: KEMTLS-secured TCP with PQ cryptography (for production)
//!
//! The mode is selected via configuration and can be set with the environment
//! variable `QBIND_TRANSPORT_SECURITY_MODE=plain|kemtls`.
//!
//! ## Blocking Boundary (T91)
//!
//! The blocking KEMTLS handshake code is confined to `spawn_blocking` calls:
//! - `perform_server_kemtls_handshake()` - server-side handshake
//! - `perform_client_kemtls_handshake()` - client-side handshake
//!
//! After the handshake completes successfully:
//! 1. The SecureChannel's inner TcpStream is NOT used for reading/writing messages
//! 2. Instead, the handshake extracts the raw std::net::TcpStream (before SecureChannel takes ownership)
//! 3. Post-handshake, we create a fresh Tokio TcpStream from the raw socket
//! 4. All subsequent reads/writes are async and do not block
//!
//! Note: The current implementation uses PlainTcp by default. Full KEMTLS integration
//! requires configuring the KEMTLS parameters (ServerConnectionConfig).
//!
//! # Feature Flag
//!
//! This module is gated behind the `async-peer-manager` feature flag.
//! When enabled, `AsyncPeerManagerImpl` replaces the blocking `PeerManager`
//! path in the consensus networking stack.
//!
//! # Logging
//!
//! NOTE: This skeleton uses `eprintln!` for debug output. In production,
//! this should be replaced with a proper logging framework (e.g., `tracing`
//! or `log`) to enable configurable log levels and structured logging.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, mpsc, watch, Mutex, RwLock, Semaphore};
use tokio::task::JoinHandle;

use crate::channel_config::ChannelCapacityConfig;
use crate::metrics::{DisconnectReason, InboundMsgKind, NodeMetrics};
use crate::peer::PeerId;
use crate::peer_rate_limiter::PeerRateLimiter;
use crate::secure_channel::{SecureChannel, SecureChannelAsync};
use qbind_consensus::network::{ConsensusNetworkEvent, NetworkError};
use qbind_net::{ClientConnectionConfig, ServerConnectionConfig};
use qbind_wire::consensus::{BlockProposal, Vote};
use qbind_wire::io::{WireDecode, WireEncode};
use qbind_wire::net::NetMessage;

// ============================================================================
// Transport Security Mode (T91)
// ============================================================================

/// Transport security mode for peer connections.
///
/// This enum determines whether connections use KEMTLS encryption or plain TCP.
///
/// # Usage
///
/// For production/devnet, use `Kemtls` for post-quantum security.
/// For tests and the load harness, use `PlainTcp` to avoid cryptographic setup.
///
/// # Environment Variable
///
/// The mode can be set via the `QBIND_TRANSPORT_SECURITY_MODE` environment variable:
/// - `"plain"` or `"plaintcp"` → `PlainTcp`
/// - `"kemtls"` (default) → `Kemtls`
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransportSecurityMode {
    /// Plain TCP without encryption.
    ///
    /// Use for tests, load harness, and development environments where
    /// cryptographic setup is not required.
    PlainTcp,

    /// KEMTLS-secured TCP with post-quantum cryptography.
    ///
    /// Use for production, devnet, and testnet where security is required.
    /// This mode performs a KEMTLS handshake on each connection using the
    /// blocking `SecureChannel` implementation via `spawn_blocking`.
    #[default]
    Kemtls,
}

impl TransportSecurityMode {
    /// Parse from a string (case-insensitive).
    ///
    /// Returns `PlainTcp` for "plain" or "plaintcp", `Kemtls` for "kemtls".
    /// Returns `None` for unrecognized values.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "plain" | "plaintcp" => Some(TransportSecurityMode::PlainTcp),
            "kemtls" => Some(TransportSecurityMode::Kemtls),
            _ => None,
        }
    }

    /// Load from the `QBIND_TRANSPORT_SECURITY_MODE` environment variable.
    ///
    /// Returns the configured mode, or `None` if the variable is not set
    /// or has an unrecognized value.
    pub fn from_env() -> Option<Self> {
        std::env::var("QBIND_TRANSPORT_SECURITY_MODE")
            .ok()
            .and_then(|s| Self::from_str(&s))
    }

    /// Check if this mode uses KEMTLS encryption.
    pub fn is_kemtls(&self) -> bool {
        matches!(self, TransportSecurityMode::Kemtls)
    }
}

impl std::fmt::Display for TransportSecurityMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportSecurityMode::PlainTcp => write!(f, "PlainTcp"),
            TransportSecurityMode::Kemtls => write!(f, "Kemtls"),
        }
    }
}

// ============================================================================
// KEMTLS Metrics (T91)
// ============================================================================

/// Reason for a KEMTLS handshake failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemtlsHandshakeFailureReason {
    /// I/O error during handshake (e.g., connection reset).
    Io,
    /// Protocol error (e.g., invalid handshake message).
    Protocol,
    /// Cryptographic error (e.g., decryption failure).
    Crypto,
    /// Timeout during handshake.
    Timeout,
    /// Other/unknown error.
    Other,
}

impl std::fmt::Display for KemtlsHandshakeFailureReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemtlsHandshakeFailureReason::Io => write!(f, "io"),
            KemtlsHandshakeFailureReason::Protocol => write!(f, "protocol"),
            KemtlsHandshakeFailureReason::Crypto => write!(f, "crypto"),
            KemtlsHandshakeFailureReason::Timeout => write!(f, "timeout"),
            KemtlsHandshakeFailureReason::Other => write!(f, "other"),
        }
    }
}

/// KEMTLS handshake role (T120).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KemtlsRole {
    /// Client-side handshake (outbound connection).
    Client,
    /// Server-side handshake (inbound connection).
    Server,
}

impl std::fmt::Display for KemtlsRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KemtlsRole::Client => write!(f, "client"),
            KemtlsRole::Server => write!(f, "server"),
        }
    }
}

/// Metrics for KEMTLS handshake operations (T91, T113, T120).
///
/// Tracks the number of successful and failed handshakes, as well as
/// coarse-grained latency distribution.
///
/// # Role Metrics (T120)
///
/// Tracks client vs server handshakes separately:
/// - `kemtls_handshake_success_total{role="client"}`
/// - `kemtls_handshake_success_total{role="server"}`
/// - `kemtls_handshake_failure_total{role="client",reason="..."}`
/// - `kemtls_handshake_failure_total{role="server",reason="..."}`
/// - `kemtls_handshake_duration_bucket{role="client",le="..."}`
/// - `kemtls_handshake_duration_bucket{role="server",le="..."}`
///
/// # Concurrency Metrics (T113)
///
/// When a concurrency limit is configured, these metrics track:
/// - `handshake_started_total`: Total handshakes initiated (permit acquired)
/// - `handshake_completed_total`: Total handshakes finished (success or failure)
/// - `handshake_in_flight`: Current number of handshakes in progress (gauge)
///
/// # Thread Safety
///
/// All counters use `AtomicU64` with relaxed ordering for performance.
/// The `Default` derive initializes all atomic counters to 0, which is the
/// correct initial state for all metrics.
#[derive(Debug, Default)]
pub struct KemtlsMetrics {
    /// Total number of successful KEMTLS handshakes.
    handshake_success_total: AtomicU64,

    /// Number of failed handshakes by reason.
    handshake_failure_io: AtomicU64,
    handshake_failure_protocol: AtomicU64,
    handshake_failure_crypto: AtomicU64,
    handshake_failure_timeout: AtomicU64,
    handshake_failure_other: AtomicU64,

    /// Latency buckets for successful handshakes.
    latency_under_10ms: AtomicU64,
    latency_10ms_to_100ms: AtomicU64,
    latency_100ms_to_1s: AtomicU64,
    latency_over_1s: AtomicU64,

    // ========================================================================
    // Concurrency metrics (T113)
    // ========================================================================
    /// Total number of handshakes started (permit acquired).
    handshake_started_total: AtomicU64,

    /// Total number of handshakes completed (success or failure).
    handshake_completed_total: AtomicU64,

    /// Current number of handshakes in flight (gauge).
    /// This is incremented when a permit is acquired and decremented when released.
    handshake_in_flight: AtomicU64,

    // ========================================================================
    // Role-based metrics (T120)
    // ========================================================================
    /// Client-side handshake success count.
    client_success_total: AtomicU64,
    /// Server-side handshake success count.
    server_success_total: AtomicU64,

    /// Client-side handshake failure counts by reason.
    client_failure_io: AtomicU64,
    client_failure_protocol: AtomicU64,
    client_failure_crypto: AtomicU64,
    client_failure_timeout: AtomicU64,
    client_failure_other: AtomicU64,

    /// Server-side handshake failure counts by reason.
    server_failure_io: AtomicU64,
    server_failure_protocol: AtomicU64,
    server_failure_crypto: AtomicU64,
    server_failure_timeout: AtomicU64,
    server_failure_other: AtomicU64,

    /// Client-side latency buckets.
    client_latency_under_10ms: AtomicU64,
    client_latency_10ms_to_100ms: AtomicU64,
    client_latency_100ms_to_1s: AtomicU64,
    client_latency_over_1s: AtomicU64,

    /// Server-side latency buckets.
    server_latency_under_10ms: AtomicU64,
    server_latency_10ms_to_100ms: AtomicU64,
    server_latency_100ms_to_1s: AtomicU64,
    server_latency_over_1s: AtomicU64,
}

impl KemtlsMetrics {
    /// Create a new metrics instance with all counters at zero.
    pub fn new() -> Self {
        Self::default()
    }

    /// Get count of successful handshakes.
    pub fn handshake_success_total(&self) -> u64 {
        self.handshake_success_total.load(Ordering::Relaxed)
    }

    /// Increment successful handshake counter.
    pub fn inc_handshake_success(&self) {
        self.handshake_success_total.fetch_add(1, Ordering::Relaxed);
    }

    /// Get count of failed handshakes by reason.
    pub fn handshake_failure_by_reason(&self, reason: KemtlsHandshakeFailureReason) -> u64 {
        match reason {
            KemtlsHandshakeFailureReason::Io => self.handshake_failure_io.load(Ordering::Relaxed),
            KemtlsHandshakeFailureReason::Protocol => {
                self.handshake_failure_protocol.load(Ordering::Relaxed)
            }
            KemtlsHandshakeFailureReason::Crypto => {
                self.handshake_failure_crypto.load(Ordering::Relaxed)
            }
            KemtlsHandshakeFailureReason::Timeout => {
                self.handshake_failure_timeout.load(Ordering::Relaxed)
            }
            KemtlsHandshakeFailureReason::Other => {
                self.handshake_failure_other.load(Ordering::Relaxed)
            }
        }
    }

    /// Total number of failed handshakes (all reasons).
    pub fn handshake_failure_total(&self) -> u64 {
        self.handshake_failure_io.load(Ordering::Relaxed)
            + self.handshake_failure_protocol.load(Ordering::Relaxed)
            + self.handshake_failure_crypto.load(Ordering::Relaxed)
            + self.handshake_failure_timeout.load(Ordering::Relaxed)
            + self.handshake_failure_other.load(Ordering::Relaxed)
    }

    /// Increment failed handshake counter by reason.
    pub fn inc_handshake_failure(&self, reason: KemtlsHandshakeFailureReason) {
        match reason {
            KemtlsHandshakeFailureReason::Io => {
                self.handshake_failure_io.fetch_add(1, Ordering::Relaxed);
            }
            KemtlsHandshakeFailureReason::Protocol => {
                self.handshake_failure_protocol
                    .fetch_add(1, Ordering::Relaxed);
            }
            KemtlsHandshakeFailureReason::Crypto => {
                self.handshake_failure_crypto
                    .fetch_add(1, Ordering::Relaxed);
            }
            KemtlsHandshakeFailureReason::Timeout => {
                self.handshake_failure_timeout
                    .fetch_add(1, Ordering::Relaxed);
            }
            KemtlsHandshakeFailureReason::Other => {
                self.handshake_failure_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Record a successful handshake with its duration.
    ///
    /// This increments the success counter and the appropriate latency bucket.
    pub fn record_handshake_success(&self, duration: Duration) {
        self.inc_handshake_success();

        let millis = duration.as_millis();
        if millis < 10 {
            self.latency_under_10ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 100 {
            self.latency_10ms_to_100ms.fetch_add(1, Ordering::Relaxed);
        } else if millis < 1000 {
            self.latency_100ms_to_1s.fetch_add(1, Ordering::Relaxed);
        } else {
            self.latency_over_1s.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get latency bucket counts as (under_10ms, 10ms_to_100ms, 100ms_to_1s, over_1s).
    pub fn latency_buckets(&self) -> (u64, u64, u64, u64) {
        (
            self.latency_under_10ms.load(Ordering::Relaxed),
            self.latency_10ms_to_100ms.load(Ordering::Relaxed),
            self.latency_100ms_to_1s.load(Ordering::Relaxed),
            self.latency_over_1s.load(Ordering::Relaxed),
        )
    }

    // ========================================================================
    // Concurrency metrics (T113)
    // ========================================================================

    /// Get total number of handshakes started.
    pub fn handshake_started_total(&self) -> u64 {
        self.handshake_started_total.load(Ordering::Relaxed)
    }

    /// Get total number of handshakes completed.
    pub fn handshake_completed_total(&self) -> u64 {
        self.handshake_completed_total.load(Ordering::Relaxed)
    }

    /// Get current number of handshakes in flight.
    pub fn handshake_in_flight(&self) -> u64 {
        self.handshake_in_flight.load(Ordering::Relaxed)
    }

    /// Record that a handshake has started (permit acquired).
    ///
    /// This increments `handshake_started_total` and `handshake_in_flight`.
    pub fn record_handshake_started(&self) {
        self.handshake_started_total.fetch_add(1, Ordering::Relaxed);
        self.handshake_in_flight.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that a handshake has completed (permit released).
    ///
    /// This increments `handshake_completed_total` and decrements `handshake_in_flight`.
    pub fn record_handshake_completed(&self) {
        self.handshake_completed_total
            .fetch_add(1, Ordering::Relaxed);
        // Note: fetch_sub can wrap on underflow, but in practice this should never
        // underflow as long as record_handshake_started() is called before
        // record_handshake_completed(). The code assumes correct usage.
        self.handshake_in_flight.fetch_sub(1, Ordering::Relaxed);
    }

    // ========================================================================
    // Role-based metrics (T120)
    // ========================================================================

    /// Get successful handshake count by role.
    pub fn handshake_success_by_role(&self, role: KemtlsRole) -> u64 {
        match role {
            KemtlsRole::Client => self.client_success_total.load(Ordering::Relaxed),
            KemtlsRole::Server => self.server_success_total.load(Ordering::Relaxed),
        }
    }

    /// Get failure count by role and reason.
    pub fn handshake_failure_by_role_and_reason(
        &self,
        role: KemtlsRole,
        reason: KemtlsHandshakeFailureReason,
    ) -> u64 {
        match (role, reason) {
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Io) => {
                self.client_failure_io.load(Ordering::Relaxed)
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Protocol) => {
                self.client_failure_protocol.load(Ordering::Relaxed)
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Crypto) => {
                self.client_failure_crypto.load(Ordering::Relaxed)
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Timeout) => {
                self.client_failure_timeout.load(Ordering::Relaxed)
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Other) => {
                self.client_failure_other.load(Ordering::Relaxed)
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Io) => {
                self.server_failure_io.load(Ordering::Relaxed)
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Protocol) => {
                self.server_failure_protocol.load(Ordering::Relaxed)
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Crypto) => {
                self.server_failure_crypto.load(Ordering::Relaxed)
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Timeout) => {
                self.server_failure_timeout.load(Ordering::Relaxed)
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Other) => {
                self.server_failure_other.load(Ordering::Relaxed)
            }
        }
    }

    /// Get latency buckets by role as (under_10ms, 10ms_to_100ms, 100ms_to_1s, over_1s).
    pub fn latency_buckets_by_role(&self, role: KemtlsRole) -> (u64, u64, u64, u64) {
        match role {
            KemtlsRole::Client => (
                self.client_latency_under_10ms.load(Ordering::Relaxed),
                self.client_latency_10ms_to_100ms.load(Ordering::Relaxed),
                self.client_latency_100ms_to_1s.load(Ordering::Relaxed),
                self.client_latency_over_1s.load(Ordering::Relaxed),
            ),
            KemtlsRole::Server => (
                self.server_latency_under_10ms.load(Ordering::Relaxed),
                self.server_latency_10ms_to_100ms.load(Ordering::Relaxed),
                self.server_latency_100ms_to_1s.load(Ordering::Relaxed),
                self.server_latency_over_1s.load(Ordering::Relaxed),
            ),
        }
    }

    /// Record a successful handshake with its duration and role (T120).
    ///
    /// This increments the success counter and the appropriate latency bucket
    /// for both aggregate and role-specific metrics.
    pub fn record_handshake_success_with_role(&self, duration: Duration, role: KemtlsRole) {
        // Record aggregate metrics
        self.record_handshake_success(duration);

        // Record role-specific success
        match role {
            KemtlsRole::Client => {
                self.client_success_total.fetch_add(1, Ordering::Relaxed);
            }
            KemtlsRole::Server => {
                self.server_success_total.fetch_add(1, Ordering::Relaxed);
            }
        }

        // Record role-specific latency
        let millis = duration.as_millis();
        match role {
            KemtlsRole::Client => {
                if millis < 10 {
                    self.client_latency_under_10ms
                        .fetch_add(1, Ordering::Relaxed);
                } else if millis < 100 {
                    self.client_latency_10ms_to_100ms
                        .fetch_add(1, Ordering::Relaxed);
                } else if millis < 1000 {
                    self.client_latency_100ms_to_1s
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.client_latency_over_1s.fetch_add(1, Ordering::Relaxed);
                }
            }
            KemtlsRole::Server => {
                if millis < 10 {
                    self.server_latency_under_10ms
                        .fetch_add(1, Ordering::Relaxed);
                } else if millis < 100 {
                    self.server_latency_10ms_to_100ms
                        .fetch_add(1, Ordering::Relaxed);
                } else if millis < 1000 {
                    self.server_latency_100ms_to_1s
                        .fetch_add(1, Ordering::Relaxed);
                } else {
                    self.server_latency_over_1s.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }

    /// Increment failed handshake counter by reason and role (T120).
    pub fn inc_handshake_failure_with_role(
        &self,
        reason: KemtlsHandshakeFailureReason,
        role: KemtlsRole,
    ) {
        // Record aggregate failure
        self.inc_handshake_failure(reason);

        // Record role-specific failure
        match (role, reason) {
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Io) => {
                self.client_failure_io.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Protocol) => {
                self.client_failure_protocol.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Crypto) => {
                self.client_failure_crypto.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Timeout) => {
                self.client_failure_timeout.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Client, KemtlsHandshakeFailureReason::Other) => {
                self.client_failure_other.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Io) => {
                self.server_failure_io.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Protocol) => {
                self.server_failure_protocol.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Crypto) => {
                self.server_failure_crypto.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Timeout) => {
                self.server_failure_timeout.fetch_add(1, Ordering::Relaxed);
            }
            (KemtlsRole::Server, KemtlsHandshakeFailureReason::Other) => {
                self.server_failure_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Format metrics as Prometheus-style output.
    pub fn format_metrics(&self) -> String {
        let mut output = String::new();
        output.push_str("\n# KEMTLS handshake metrics (T91, T113, T120)\n");

        // Aggregate success/failure metrics
        output.push_str(&format!(
            "kemtls_handshake_success_total {}\n",
            self.handshake_success_total()
        ));
        output.push_str(&format!(
            "kemtls_handshake_failure_total{{reason=\"io\"}} {}\n",
            self.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Io)
        ));
        output.push_str(&format!(
            "kemtls_handshake_failure_total{{reason=\"protocol\"}} {}\n",
            self.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Protocol)
        ));
        output.push_str(&format!(
            "kemtls_handshake_failure_total{{reason=\"crypto\"}} {}\n",
            self.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Crypto)
        ));
        output.push_str(&format!(
            "kemtls_handshake_failure_total{{reason=\"timeout\"}} {}\n",
            self.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Timeout)
        ));
        output.push_str(&format!(
            "kemtls_handshake_failure_total{{reason=\"other\"}} {}\n",
            self.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Other)
        ));

        // Aggregate latency buckets
        let (under_10ms, to_100ms, to_1s, over_1s) = self.latency_buckets();
        output.push_str(&format!(
            "kemtls_handshake_duration_bucket{{le=\"0.01\"}} {}\n",
            under_10ms
        ));
        output.push_str(&format!(
            "kemtls_handshake_duration_bucket{{le=\"0.1\"}} {}\n",
            under_10ms + to_100ms
        ));
        output.push_str(&format!(
            "kemtls_handshake_duration_bucket{{le=\"1.0\"}} {}\n",
            under_10ms + to_100ms + to_1s
        ));
        output.push_str(&format!(
            "kemtls_handshake_duration_bucket{{le=\"+Inf\"}} {}\n",
            under_10ms + to_100ms + to_1s + over_1s
        ));

        // Role-based success metrics (T120)
        output.push_str(&format!(
            "kemtls_handshake_success_total{{role=\"client\"}} {}\n",
            self.handshake_success_by_role(KemtlsRole::Client)
        ));
        output.push_str(&format!(
            "kemtls_handshake_success_total{{role=\"server\"}} {}\n",
            self.handshake_success_by_role(KemtlsRole::Server)
        ));

        // Role-based failure metrics (T120)
        for role in [KemtlsRole::Client, KemtlsRole::Server] {
            for reason in [
                KemtlsHandshakeFailureReason::Io,
                KemtlsHandshakeFailureReason::Protocol,
                KemtlsHandshakeFailureReason::Crypto,
                KemtlsHandshakeFailureReason::Timeout,
                KemtlsHandshakeFailureReason::Other,
            ] {
                output.push_str(&format!(
                    "kemtls_handshake_failure_total{{role=\"{}\",reason=\"{}\"}} {}\n",
                    role,
                    reason,
                    self.handshake_failure_by_role_and_reason(role, reason)
                ));
            }
        }

        // Role-based latency buckets (T120)
        for role in [KemtlsRole::Client, KemtlsRole::Server] {
            let (r_under_10ms, r_to_100ms, r_to_1s, r_over_1s) = self.latency_buckets_by_role(role);
            output.push_str(&format!(
                "kemtls_handshake_duration_bucket{{role=\"{}\",le=\"0.01\"}} {}\n",
                role, r_under_10ms
            ));
            output.push_str(&format!(
                "kemtls_handshake_duration_bucket{{role=\"{}\",le=\"0.1\"}} {}\n",
                role,
                r_under_10ms + r_to_100ms
            ));
            output.push_str(&format!(
                "kemtls_handshake_duration_bucket{{role=\"{}\",le=\"1.0\"}} {}\n",
                role,
                r_under_10ms + r_to_100ms + r_to_1s
            ));
            output.push_str(&format!(
                "kemtls_handshake_duration_bucket{{role=\"{}\",le=\"+Inf\"}} {}\n",
                role,
                r_under_10ms + r_to_100ms + r_to_1s + r_over_1s
            ));
        }

        // Concurrency metrics (T113)
        output.push_str(&format!(
            "kemtls_handshake_started_total {}\n",
            self.handshake_started_total()
        ));
        output.push_str(&format!(
            "kemtls_handshake_completed_total {}\n",
            self.handshake_completed_total()
        ));
        output.push_str(&format!(
            "kemtls_handshake_in_flight {}\n",
            self.handshake_in_flight()
        ));

        output
    }
}

// ============================================================================
// AsyncPeerManager Trait (Part A)
// ============================================================================

/// Trait that abstracts what consensus needs from the peer networking layer.
///
/// This trait provides an async API for:
/// - Receiving consensus network events from any peer
/// - Sending votes to specific peers
/// - Broadcasting votes and proposals to all peers
///
/// # Design Notes
///
/// - The trait is `Send + Sync` to allow sharing across async tasks.
/// - Methods use `&self` where possible to enable concurrent access.
/// - `recv_event` uses `&mut self` to allow stateful receive operations.
///
/// This trait intentionally does NOT expose:
/// - KEMTLS or cryptographic details
/// - TCP/socket-level operations
/// - Connection management internals
///
/// These are implementation details hidden behind the trait.
#[allow(async_fn_in_trait)]
pub trait AsyncPeerManager: Send + Sync {
    /// Receive the next consensus network event from any peer.
    ///
    /// Returns:
    /// - `Some(event)` when a consensus message is available
    /// - `None` when the manager is shutting down or all peers disconnected
    ///
    /// This method blocks (asynchronously) until an event is available.
    async fn recv_event(&mut self) -> Option<ConsensusNetworkEvent<PeerId>>;

    /// Send a vote to a specific peer.
    ///
    /// # Arguments
    ///
    /// - `peer`: The target peer ID
    /// - `vote`: The vote message to send
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if the peer is not found or send fails.
    async fn send_vote_to(&self, peer: PeerId, vote: Vote) -> Result<(), NetworkError>;

    /// Broadcast a vote to all connected peers.
    ///
    /// # Arguments
    ///
    /// - `vote`: The vote message to broadcast
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if broadcasting fails.
    async fn broadcast_vote(&self, vote: Vote) -> Result<(), NetworkError>;

    /// Broadcast a block proposal to all connected peers.
    ///
    /// # Arguments
    ///
    /// - `proposal`: The block proposal to broadcast
    ///
    /// # Errors
    ///
    /// Returns `NetworkError` if broadcasting fails.
    async fn broadcast_proposal(&self, proposal: BlockProposal) -> Result<(), NetworkError>;
}

// ============================================================================
// AsyncPeerManagerError
// ============================================================================

/// Error type for `AsyncPeerManagerImpl` operations.
#[derive(Debug)]
pub enum AsyncPeerManagerError {
    /// I/O error (TCP operations).
    Io(io::Error),
    /// Network protocol error.
    Protocol(String),
    /// Peer not found.
    PeerNotFound(PeerId),
    /// Channel send failed.
    ChannelSend(String),
    /// Manager is shutting down.
    Shutdown,
    /// Connection rejected because peer limit exceeded (T105).
    ConnectionLimitExceeded {
        /// Current number of active peers.
        current: usize,
        /// Maximum allowed peers.
        limit: usize,
    },
}

impl std::fmt::Display for AsyncPeerManagerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AsyncPeerManagerError::Io(e) => write!(f, "I/O error: {}", e),
            AsyncPeerManagerError::Protocol(msg) => write!(f, "protocol error: {}", msg),
            AsyncPeerManagerError::PeerNotFound(id) => write!(f, "peer not found: {:?}", id),
            AsyncPeerManagerError::ChannelSend(msg) => write!(f, "channel send failed: {}", msg),
            AsyncPeerManagerError::Shutdown => write!(f, "peer manager is shutting down"),
            AsyncPeerManagerError::ConnectionLimitExceeded { current, limit } => {
                write!(
                    f,
                    "connection limit exceeded: {} active peers, limit is {}",
                    current, limit
                )
            }
        }
    }
}

impl std::error::Error for AsyncPeerManagerError {}

impl From<io::Error> for AsyncPeerManagerError {
    fn from(e: io::Error) -> Self {
        AsyncPeerManagerError::Io(e)
    }
}

impl From<AsyncPeerManagerError> for NetworkError {
    fn from(e: AsyncPeerManagerError) -> Self {
        NetworkError::Other(e.to_string())
    }
}

// ============================================================================
// Peer State
// ============================================================================

/// State for a single connected peer.
///
/// Each peer has:
/// - A channel for sending outbound messages
/// - Handles to its reader/writer tasks
struct PeerState {
    /// Channel for sending messages to this peer's writer task.
    outbound_tx: mpsc::Sender<NetMessage>,
    /// Handle to the reader task (for cleanup).
    _reader_handle: JoinHandle<()>,
    /// Handle to the writer task (for cleanup).
    _writer_handle: JoinHandle<()>,
}

// ============================================================================
// AsyncPeerManagerImpl (Part A)
// ============================================================================

/// Configuration for `AsyncPeerManagerImpl`.
///
/// # Transport Security (T91)
///
/// The `transport_security_mode` field controls whether connections use
/// KEMTLS encryption or plain TCP:
/// - `PlainTcp`: Raw TCP without encryption (for tests/load harness)
/// - `Kemtls`: KEMTLS-secured TCP (requires `server_config` to be set)
///
/// For KEMTLS mode, you must also provide a `server_config` with the
/// appropriate cryptographic parameters.
///
/// # Connection Limits (T105)
///
/// The `max_peers` field controls the maximum number of simultaneous peer
/// connections (both inbound and outbound combined):
/// - `None` → no limit enforced (default, backward compatible behavior)
/// - `Some(n)` → at most `n` active peers; attempts to add peer `n+1` are rejected
///
/// When a connection is rejected due to limits:
/// - Inbound: socket is closed immediately, metric incremented
/// - Outbound: `ConnectionLimitExceeded` error is returned
///
/// # KEMTLS Handshake Concurrency (T113)
///
/// The `max_concurrent_kemtls_handshakes` field controls how many KEMTLS
/// handshakes can run concurrently in `spawn_blocking`:
/// - `None` → no limit enforced (default, backward compatible behavior)
/// - `Some(n)` → at most `n` concurrent handshakes; additional handshakes
///   wait (queue) until a permit is available
///
/// This prevents Tokio's spawn_blocking thread pool from being exhausted
/// during connection storms.
#[derive(Debug, Clone)]
pub struct AsyncPeerManagerConfig {
    /// Address to listen on for inbound connections.
    pub listen_addr: SocketAddr,
    /// Capacity of the inbound event channel.
    pub inbound_channel_capacity: usize,
    /// Capacity of per-peer outbound channels.
    pub outbound_channel_capacity: usize,
    /// Transport security mode (T91): PlainTcp or Kemtls.
    pub transport_security_mode: TransportSecurityMode,
    /// Server-side KEMTLS configuration (required for Kemtls mode).
    ///
    /// This is wrapped in Option<Arc<...>> to allow sharing across tasks
    /// and to make it optional for PlainTcp mode.
    pub server_config: Option<Arc<ServerConnectionConfig>>,
    /// Maximum number of simultaneous peers (T105).
    ///
    /// This is the total limit for both inbound and outbound connections.
    /// - `None` → no limit enforced (default, backward compatible)
    /// - `Some(n)` → at most `n` active peers
    pub max_peers: Option<usize>,
    /// Maximum number of concurrent KEMTLS handshakes (T113).
    ///
    /// Controls the concurrency limit on KEMTLS handshakes in spawn_blocking.
    /// - `None` → no limit enforced (default, backward compatible)
    /// - `Some(n)` → at most `n` concurrent handshakes; others wait for permit
    ///
    /// Only applies when `transport_security_mode` is `Kemtls`.
    pub max_concurrent_kemtls_handshakes: Option<usize>,
}

impl Default for AsyncPeerManagerConfig {
    fn default() -> Self {
        // NOTE: Default to PlainTcp for backward compatibility with existing tests.
        // This intentionally differs from TransportSecurityMode::default() (Kemtls)
        // to avoid breaking test code that doesn't set up KEMTLS credentials.
        //
        // For production use, set QBIND_TRANSPORT_SECURITY_MODE=kemtls or use
        // .with_transport_security_mode(TransportSecurityMode::Kemtls)
        // along with .with_server_config(...).
        let mode = TransportSecurityMode::from_env().unwrap_or(TransportSecurityMode::PlainTcp);

        AsyncPeerManagerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            inbound_channel_capacity: 1024,
            outbound_channel_capacity: 256,
            transport_security_mode: mode,
            server_config: None,
            max_peers: None,                        // No limit by default (T105)
            max_concurrent_kemtls_handshakes: None, // No limit by default (T113)
        }
    }
}

impl AsyncPeerManagerConfig {
    /// Create a new configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new configuration from a `ChannelCapacityConfig`.
    ///
    /// This constructor uses:
    /// - `async_peer_inbound_capacity` for the inbound channel
    /// - `async_peer_outbound_capacity` for per-peer outbound channels
    /// - Default listen address (127.0.0.1:0)
    /// - Transport security mode from environment variable or PlainTcp
    /// - No connection limit (max_peers = None)
    /// - No handshake concurrency limit (max_concurrent_kemtls_handshakes = None)
    ///
    /// Use the builder methods to customize the listen address and security.
    pub fn from_channel_config(config: &ChannelCapacityConfig) -> Self {
        let mode = TransportSecurityMode::from_env().unwrap_or(TransportSecurityMode::PlainTcp);

        AsyncPeerManagerConfig {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            inbound_channel_capacity: config.async_peer_inbound_capacity,
            outbound_channel_capacity: config.async_peer_outbound_capacity,
            transport_security_mode: mode,
            server_config: None,
            max_peers: None,                        // No limit by default (T105)
            max_concurrent_kemtls_handshakes: None, // No limit by default (T113)
        }
    }

    /// Set the listen address.
    pub fn with_listen_addr(mut self, addr: SocketAddr) -> Self {
        self.listen_addr = addr;
        self
    }

    /// Set the inbound channel capacity.
    pub fn with_inbound_channel_capacity(mut self, capacity: usize) -> Self {
        self.inbound_channel_capacity = capacity;
        self
    }

    /// Set the per-peer outbound channel capacity.
    pub fn with_outbound_channel_capacity(mut self, capacity: usize) -> Self {
        self.outbound_channel_capacity = capacity;
        self
    }

    /// Set the transport security mode (T91).
    pub fn with_transport_security_mode(mut self, mode: TransportSecurityMode) -> Self {
        self.transport_security_mode = mode;
        self
    }

    /// Set the server-side KEMTLS configuration (T91).
    ///
    /// Required for `TransportSecurityMode::Kemtls`.
    pub fn with_server_config(mut self, config: ServerConnectionConfig) -> Self {
        self.server_config = Some(Arc::new(config));
        self
    }

    /// Check if KEMTLS is enabled but server config is missing.
    ///
    /// Returns `true` if the configuration is invalid (KEMTLS enabled but no server config).
    pub fn is_kemtls_config_missing(&self) -> bool {
        self.transport_security_mode.is_kemtls() && self.server_config.is_none()
    }

    /// Set the maximum number of simultaneous peers (T105).
    ///
    /// This controls the total limit for both inbound and outbound connections.
    /// - `None` → no limit enforced (default, backward compatible)
    /// - `Some(n)` → at most `n` active peers
    ///
    /// When a connection is rejected due to limits:
    /// - Inbound: socket is closed immediately, rejection metric incremented
    /// - Outbound: `ConnectionLimitExceeded` error is returned
    pub fn with_max_peers(mut self, max_peers: Option<usize>) -> Self {
        self.max_peers = max_peers;
        self
    }

    /// Set the maximum number of concurrent KEMTLS handshakes (T113).
    ///
    /// This controls the concurrency limit on KEMTLS handshakes in spawn_blocking.
    /// - `None` → no limit enforced (default, backward compatible)
    /// - `Some(n)` → at most `n` concurrent handshakes; others wait for permit
    ///
    /// Only applies when `transport_security_mode` is `Kemtls`. When the limit
    /// is reached, additional handshake requests will queue until a permit
    /// becomes available.
    ///
    /// # Recommended Values
    ///
    /// - For production with high connection storms: `Some(32)` to `Some(64)`
    /// - For testing: `Some(1)` or `Some(2)` to verify limit enforcement
    /// - For backward compatibility: `None` (default)
    pub fn with_max_concurrent_kemtls_handshakes(mut self, limit: Option<usize>) -> Self {
        self.max_concurrent_kemtls_handshakes = limit;
        self
    }
}

/// Async implementation of peer management using Tokio networking primitives.
///
/// # Architecture
///
/// - **Listener task**: Accepts inbound TCP connections, performs KEMTLS
///   handshake (via `spawn_blocking`), and creates per-peer tasks.
///
/// - **Per-peer reader task**: Reads from the socket, decodes messages,
///   and pushes `ConsensusNetworkEvent` to the inbound channel.
///
/// - **Per-peer writer task**: Receives messages from a per-peer channel
///   and writes them to the socket.
///
/// - **Peer state map**: `HashMap<PeerId, PeerState>` tracks connected peers
///   and their outbound channels.
///
/// # Thread Safety
///
/// - `peers` is protected by `RwLock` for concurrent read access and
///   exclusive write access when adding/removing peers.
/// - `inbound_rx` is protected by `Mutex` since only one task should
///   consume events at a time.
///
/// # KEMTLS Handling (T91)
///
/// When `TransportSecurityMode::Kemtls` is configured:
/// - Inbound connections run a server-side KEMTLS handshake via `spawn_blocking`
/// - The handshake is performed once per connection during setup
/// - After handshake completes, the socket is used with async read/write
/// - KEMTLS metrics (success/failure counts, latency) are tracked
///
/// The blocking boundary is confined to `spawn_blocking` calls in
/// `handle_inbound_connection()`.
///
/// # KEMTLS Handshake Concurrency (T113)
///
/// When `max_concurrent_kemtls_handshakes` is configured:
/// - A semaphore limits concurrent KEMTLS handshakes in spawn_blocking
/// - Handshakes queue until a permit is available (blocking-wait semantics)
/// - Metrics track started/completed handshakes and in-flight count
///
/// # Shutdown Semantics (T90.4)
///
/// When `shutdown()` is called:
/// 1. The shutdown watch channel is signaled
/// 2. Reader and writer tasks observe the signal via `tokio::select!`
/// 3. Tasks exit promptly, closing sockets
/// 4. Pending in-flight messages may be lost during shutdown (best-effort)
///
/// # Per-Peer Metrics (T90.4)
///
/// When configured with `NodeMetrics`, the manager tracks:
/// - Inbound message counts per peer (vote, proposal, other)
/// - Disconnect counts per peer (EOF, error)
/// - These metrics flow through to `NodeMetrics::peer_network()`
///
/// # KEMTLS Metrics (T91)
///
/// The manager tracks KEMTLS handshake metrics via `KemtlsMetrics`:
/// - Successful handshake count
/// - Failed handshake count by reason (io, protocol, crypto, timeout, other)
/// - Handshake latency buckets (<10ms, 10-100ms, 100ms-1s, >1s)
/// - Concurrency metrics: started_total, completed_total, in_flight (T113)
pub struct AsyncPeerManagerImpl {
    /// Configuration.
    config: AsyncPeerManagerConfig,

    /// Receiver for inbound consensus events (from all peer reader tasks).
    inbound_rx: Mutex<mpsc::Receiver<ConsensusNetworkEvent<PeerId>>>,

    /// Sender for inbound events (cloned to each peer reader task).
    inbound_tx: mpsc::Sender<ConsensusNetworkEvent<PeerId>>,

    /// Broadcast sender for event fan-out to SharedAsyncPeerManager instances (T90.4).
    /// Each event is also sent here so that SharedAsyncPeerManager::recv() works.
    event_broadcast_tx: broadcast::Sender<ConsensusNetworkEvent<PeerId>>,

    /// Map of connected peers and their state.
    peers: RwLock<HashMap<PeerId, PeerState>>,

    /// Counter for generating peer IDs.
    next_peer_id: AtomicU64,

    /// Shutdown flag.
    shutdown: AtomicBool,

    /// Shutdown signal sender (T90.4).
    /// Used to signal reader/writer tasks to exit gracefully.
    shutdown_tx: watch::Sender<bool>,

    /// Handle to the listener task (if running).
    listener_handle: Mutex<Option<JoinHandle<()>>>,

    /// The TCP listener (wrapped for access from multiple places).
    listener: Option<Arc<TcpListener>>,

    /// Local address the listener is bound to (useful when using port 0).
    local_addr: Mutex<Option<SocketAddr>>,

    /// Optional metrics handle for per-peer tracking (T90.4).
    metrics: Option<Arc<NodeMetrics>>,

    /// KEMTLS handshake metrics (T91).
    kemtls_metrics: Arc<KemtlsMetrics>,

    /// Semaphore for limiting concurrent KEMTLS handshakes (T113).
    ///
    /// This is `None` when `max_concurrent_kemtls_handshakes` is `None`,
    /// meaning no limit is enforced. When `Some`, the semaphore controls
    /// the maximum number of concurrent KEMTLS handshakes.
    kemtls_handshake_semaphore: Option<Arc<Semaphore>>,

    /// Per-peer inbound message rate limiter (T123).
    ///
    /// This is shared across all reader tasks and provides per-peer rate limiting
    /// to prevent Byzantine peers from flooding the node with messages.
    rate_limiter: Arc<crate::peer_rate_limiter::PeerRateLimiter>,
}

impl std::fmt::Debug for AsyncPeerManagerImpl {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AsyncPeerManagerImpl")
            .field("config", &self.config)
            .field("shutdown", &self.shutdown.load(Ordering::SeqCst))
            .field("has_metrics", &self.metrics.is_some())
            .field(
                "transport_security_mode",
                &self.config.transport_security_mode,
            )
            .finish()
    }
}

impl AsyncPeerManagerImpl {
    /// Create a new `AsyncPeerManagerImpl` with the given configuration.
    ///
    /// This does NOT start the listener. Call `start_listener()` to begin
    /// accepting connections.
    pub fn new(config: AsyncPeerManagerConfig) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(config.inbound_channel_capacity);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        // Broadcast channel with capacity for event fan-out
        let (event_broadcast_tx, _) = broadcast::channel(config.inbound_channel_capacity);

        // Create semaphore for KEMTLS handshake concurrency limit (T113)
        let kemtls_handshake_semaphore = config
            .max_concurrent_kemtls_handshakes
            .map(|limit| Arc::new(Semaphore::new(limit)));

        AsyncPeerManagerImpl {
            config,
            inbound_rx: Mutex::new(inbound_rx),
            inbound_tx,
            event_broadcast_tx,
            peers: RwLock::new(HashMap::new()),
            next_peer_id: AtomicU64::new(1),
            shutdown: AtomicBool::new(false),
            shutdown_tx,
            listener_handle: Mutex::new(None),
            listener: None,
            local_addr: Mutex::new(None),
            metrics: None,
            kemtls_metrics: Arc::new(KemtlsMetrics::new()),
            kemtls_handshake_semaphore,
            rate_limiter: Arc::new(PeerRateLimiter::with_defaults()),
        }
    }

    /// Create a new `AsyncPeerManagerImpl` with default configuration.
    pub fn new_default() -> Self {
        Self::new(AsyncPeerManagerConfig::default())
    }

    /// Create a new `AsyncPeerManagerImpl` with metrics enabled (T90.4).
    ///
    /// When metrics are provided, per-peer inbound/disconnect counters are tracked.
    pub fn with_metrics(config: AsyncPeerManagerConfig, metrics: Arc<NodeMetrics>) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(config.inbound_channel_capacity);
        let (shutdown_tx, _shutdown_rx) = watch::channel(false);
        let (event_broadcast_tx, _) = broadcast::channel(config.inbound_channel_capacity);

        // Create semaphore for KEMTLS handshake concurrency limit (T113)
        let kemtls_handshake_semaphore = config
            .max_concurrent_kemtls_handshakes
            .map(|limit| Arc::new(Semaphore::new(limit)));

        AsyncPeerManagerImpl {
            config,
            inbound_rx: Mutex::new(inbound_rx),
            inbound_tx,
            event_broadcast_tx,
            peers: RwLock::new(HashMap::new()),
            next_peer_id: AtomicU64::new(1),
            shutdown: AtomicBool::new(false),
            shutdown_tx,
            listener_handle: Mutex::new(None),
            listener: None,
            local_addr: Mutex::new(None),
            metrics: Some(metrics),
            kemtls_metrics: Arc::new(KemtlsMetrics::new()),
            kemtls_handshake_semaphore,
            rate_limiter: Arc::new(PeerRateLimiter::with_defaults()),
        }
    }

    /// Get the KEMTLS metrics (T91).
    pub fn kemtls_metrics(&self) -> &Arc<KemtlsMetrics> {
        &self.kemtls_metrics
    }

    /// Get the configured transport security mode (T91).
    pub fn transport_security_mode(&self) -> TransportSecurityMode {
        self.config.transport_security_mode
    }

    /// Get the configured maximum concurrent KEMTLS handshakes limit (T113).
    ///
    /// Returns `None` if no limit is configured.
    pub fn max_concurrent_kemtls_handshakes(&self) -> Option<usize> {
        self.config.max_concurrent_kemtls_handshakes
    }

    /// Bind the listener to the configured address.
    ///
    /// Returns the actual bound address (useful when port is 0).
    ///
    /// # Errors
    ///
    /// Returns `AsyncPeerManagerError::Io` if binding fails.
    pub async fn bind(&mut self) -> Result<SocketAddr, AsyncPeerManagerError> {
        let listener = TcpListener::bind(self.config.listen_addr).await?;
        let local_addr = listener.local_addr()?;

        *self.local_addr.lock().await = Some(local_addr);
        self.listener = Some(Arc::new(listener));

        Ok(local_addr)
    }

    /// Get the local address the listener is bound to.
    pub async fn local_addr(&self) -> Option<SocketAddr> {
        *self.local_addr.lock().await
    }

    /// Start the background listener task.
    ///
    /// The listener task:
    /// 1. Accepts incoming TCP connections
    /// 2. Performs KEMTLS handshake (via spawn_blocking)
    /// 3. Creates per-peer reader/writer tasks
    /// 4. Adds the peer to the peer map
    ///
    /// # Panics
    ///
    /// Panics if `bind()` has not been called.
    pub async fn start_listener(self: &Arc<Self>) {
        let listener = self
            .listener
            .clone()
            .expect("bind() must be called before start_listener()");

        let manager = Arc::clone(self);

        let handle = tokio::spawn(async move {
            eprintln!(
                "[AsyncPeerManagerImpl] Listener started on {:?}",
                manager.local_addr.lock().await
            );

            loop {
                if manager.shutdown.load(Ordering::SeqCst) {
                    eprintln!("[AsyncPeerManagerImpl] Listener shutting down");
                    break;
                }

                // Accept with a timeout so we can check shutdown periodically
                let accept_result =
                    tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                        .await;

                match accept_result {
                    Ok(Ok((stream, addr))) => {
                        eprintln!("[AsyncPeerManagerImpl] Accepted connection from {}", addr);

                        // Spawn a task to handle the new connection
                        let manager_clone = Arc::clone(&manager);
                        tokio::spawn(async move {
                            if let Err(e) = manager_clone.handle_inbound_connection(stream).await {
                                eprintln!(
                                    "[AsyncPeerManagerImpl] Failed to handle inbound connection: {}",
                                    e
                                );
                            }
                        });
                    }
                    Ok(Err(e)) => {
                        eprintln!("[AsyncPeerManagerImpl] Accept error: {}", e);
                    }
                    Err(_) => {
                        // Timeout - continue to check shutdown flag
                    }
                }
            }
        });

        *self.listener_handle.lock().await = Some(handle);
    }

    /// Handle an inbound TCP connection.
    ///
    /// This method:
    /// 1. Checks if connection limit is exceeded (T105)
    /// 2. If KEMTLS mode: performs KEMTLS handshake via `spawn_blocking`
    /// 3. Creates per-peer reader/writer tasks
    /// 4. Adds the peer to the peer map
    ///
    /// # Connection Limits (T105)
    ///
    /// Before registering a new peer, this method checks if the configured
    /// `max_peers` limit would be exceeded. If so:
    /// - The inbound rejection metric is incremented
    /// - A warning is logged with the peer address
    /// - The socket is dropped (closing the connection)
    /// - An error is returned
    ///
    /// # KEMTLS Handshake (T91)
    ///
    /// When `TransportSecurityMode::Kemtls` is configured:
    /// - The raw Tokio TcpStream is converted to std::net::TcpStream
    /// - The blocking `SecureChannel::from_accepted()` handshake runs in `spawn_blocking`
    /// - After successful handshake, we convert back to Tokio TcpStream for async I/O
    /// - KEMTLS metrics are updated (success/failure counts, latency)
    ///
    /// Note: The SecureChannel is established but not used for message encryption in this
    /// implementation. The handshake establishes the secure session, but for simplicity,
    /// subsequent reads/writes use the raw TCP stream. Full encrypted transport would
    /// require wrapping all I/O through SecureChannel.send_app/recv_app.
    async fn handle_inbound_connection(
        self: &Arc<Self>,
        stream: TcpStream,
    ) -> Result<(), AsyncPeerManagerError> {
        // T105: Check connection limit before accepting the connection
        if let Some(max_peers) = self.config.max_peers {
            let current_count = self.peers.read().await.len();
            if current_count >= max_peers {
                // Increment rejection metric
                if let Some(ref m) = self.metrics {
                    m.connection_limit().inc_inbound_rejected();
                }

                // Log warning with peer address
                let peer_addr = stream.peer_addr().ok();
                eprintln!(
                    "[AsyncPeerManagerImpl] Rejecting inbound connection from {:?}: limit exceeded ({}/{} peers)",
                    peer_addr, current_count, max_peers
                );

                // Drop the stream to close the connection
                drop(stream);

                return Err(AsyncPeerManagerError::ConnectionLimitExceeded {
                    current: current_count,
                    limit: max_peers,
                });
            }
        }

        // Generate a peer ID
        let peer_id = PeerId(self.next_peer_id.fetch_add(1, Ordering::SeqCst));

        // Handle based on transport security mode
        let final_stream = match self.config.transport_security_mode {
            TransportSecurityMode::PlainTcp => {
                // PlainTcp mode: use the stream directly
                stream.set_nodelay(true)?;
                stream
            }
            TransportSecurityMode::Kemtls => {
                // KEMTLS mode: perform handshake via spawn_blocking with concurrency limit (T113)
                let server_config = self.config.server_config.clone().ok_or_else(|| {
                    AsyncPeerManagerError::Protocol(
                        "KEMTLS mode requires server_config to be set".to_string(),
                    )
                })?;

                let kemtls_metrics = self.kemtls_metrics.clone();
                let handshake_start = std::time::Instant::now();

                // Convert Tokio TcpStream to std::net::TcpStream for blocking handshake
                let std_stream = stream.into_std().map_err(|e| {
                    kemtls_metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Io);
                    AsyncPeerManagerError::Io(e)
                })?;

                // Clone the config for the blocking task (it's wrapped in Arc)
                let server_cfg_inner = (*server_config).clone();

                // T113: Acquire semaphore permit if concurrency limit is configured
                // The permit is held for the duration of the spawn_blocking handshake
                let _permit = if let Some(ref semaphore) = self.kemtls_handshake_semaphore {
                    // Record that a handshake is starting (waiting for permit)
                    kemtls_metrics.record_handshake_started();
                    // Blocking-wait semantics: handshakes queue until permit is available
                    let permit = semaphore.acquire().await.map_err(|e| {
                        kemtls_metrics.record_handshake_completed();
                        AsyncPeerManagerError::Protocol(format!(
                            "KEMTLS handshake semaphore closed: {}",
                            e
                        ))
                    })?;
                    Some(permit)
                } else {
                    // No limit configured, record handshake start for metrics consistency
                    kemtls_metrics.record_handshake_started();
                    None
                };

                // Perform blocking KEMTLS handshake in spawn_blocking
                let handshake_result = tokio::task::spawn_blocking(move || {
                    SecureChannel::from_accepted(std_stream, server_cfg_inner)
                })
                .await
                .map_err(|e| {
                    kemtls_metrics.record_handshake_completed();
                    kemtls_metrics.inc_handshake_failure_with_role(
                        KemtlsHandshakeFailureReason::Other,
                        KemtlsRole::Server,
                    );
                    AsyncPeerManagerError::Protocol(format!("spawn_blocking join error: {}", e))
                })?;

                // Check handshake result and wrap in SecureChannelAsync
                let secure_channel = match handshake_result {
                    Ok(channel) => {
                        let handshake_duration = handshake_start.elapsed();
                        // T120: Record with server role
                        kemtls_metrics.record_handshake_success_with_role(
                            handshake_duration,
                            KemtlsRole::Server,
                        );
                        kemtls_metrics.record_handshake_completed();
                        eprintln!(
                            "[AsyncPeerManagerImpl] KEMTLS handshake succeeded for {:?} in {:?}",
                            peer_id, handshake_duration
                        );
                        channel
                    }
                    Err(e) => {
                        // Categorize the error for metrics
                        let reason = match &e {
                            crate::secure_channel::ChannelError::Io(_) => {
                                KemtlsHandshakeFailureReason::Io
                            }
                            crate::secure_channel::ChannelError::Net(net_err) => {
                                // Categorize based on NetError type
                                match net_err {
                                    qbind_net::NetError::KeySchedule(_)
                                    | qbind_net::NetError::Aead(_)
                                    | qbind_net::NetError::UnsupportedSuite(_) => {
                                        KemtlsHandshakeFailureReason::Crypto
                                    }
                                    qbind_net::NetError::Protocol(_)
                                    | qbind_net::NetError::NonceOverflow => {
                                        KemtlsHandshakeFailureReason::Protocol
                                    }
                                }
                            }
                        };
                        // T120: Record failure with server role
                        kemtls_metrics.inc_handshake_failure_with_role(reason, KemtlsRole::Server);
                        kemtls_metrics.record_handshake_completed();
                        eprintln!(
                            "[AsyncPeerManagerImpl] KEMTLS handshake failed for {:?}: {:?}",
                            peer_id, e
                        );
                        return Err(AsyncPeerManagerError::Protocol(format!(
                            "KEMTLS handshake failed: {:?}",
                            e
                        )));
                    }
                };

                // T92: Wrap the SecureChannel in SecureChannelAsync for encrypted message transport
                let secure_channel_async = SecureChannelAsync::new(secure_channel);

                // Register the peer with the secure channel
                self.register_secure_peer(peer_id, secure_channel_async)
                    .await?;

                eprintln!(
                    "[AsyncPeerManagerImpl] Peer {:?} connected (KEMTLS)",
                    peer_id
                );

                return Ok(());
            }
        };

        // Create per-peer channels and tasks (PlainTcp mode)
        self.register_peer(peer_id, final_stream).await?;

        eprintln!(
            "[AsyncPeerManagerImpl] Peer {:?} connected (PlainTcp)",
            peer_id
        );

        Ok(())
    }

    /// Add a peer to the manager with an existing TCP stream.
    ///
    /// This is useful for:
    /// - Outbound connections (after connect + handshake)
    /// - Testing with pre-established streams
    pub async fn add_peer_with_stream(
        self: &Arc<Self>,
        peer_id: PeerId,
        stream: TcpStream,
    ) -> Result<(), AsyncPeerManagerError> {
        self.register_peer(peer_id, stream).await
    }

    /// Add a peer to the manager with an existing secure channel (T92).
    ///
    /// This is useful for:
    /// - Outbound KEMTLS connections (after connect + handshake)
    /// - Testing with pre-established secure channels
    pub async fn add_peer_with_secure_channel(
        self: &Arc<Self>,
        peer_id: PeerId,
        channel: SecureChannelAsync,
    ) -> Result<(), AsyncPeerManagerError> {
        self.register_secure_peer(peer_id, channel).await
    }

    /// Connect to a remote peer and establish a secure connection (T92 Part D).
    ///
    /// This method:
    /// 1. Checks if connection limit is exceeded (T105)
    /// 2. Establishes a TCP connection to the remote address
    /// 3. If KEMTLS mode: performs client-side KEMTLS handshake
    /// 4. If PlainTcp mode: uses raw TCP
    /// 5. Creates reader/writer tasks for the peer
    ///
    /// # Arguments
    ///
    /// * `addr` - Remote socket address (e.g., "127.0.0.1:8080")
    /// * `client_config` - Optional client KEMTLS configuration (required for KEMTLS mode)
    ///
    /// # Returns
    ///
    /// The assigned `PeerId` for the new peer.
    ///
    /// # Errors
    ///
    /// Returns `AsyncPeerManagerError` if:
    /// - Connection limit is exceeded (T105)
    /// - TCP connection fails
    /// - KEMTLS handshake fails (in Kemtls mode)
    /// - Client config is missing for KEMTLS mode
    pub async fn connect_peer(
        self: &Arc<Self>,
        addr: &str,
        client_config: Option<ClientConnectionConfig>,
    ) -> Result<PeerId, AsyncPeerManagerError> {
        // T105: Check connection limit before connecting
        if let Some(max_peers) = self.config.max_peers {
            let current_count = self.peers.read().await.len();
            if current_count >= max_peers {
                // Increment rejection metric
                if let Some(ref m) = self.metrics {
                    m.connection_limit().inc_outbound_rejected();
                }

                // Log warning with target address
                eprintln!(
                    "[AsyncPeerManagerImpl] Rejecting outbound connection to {}: limit exceeded ({}/{} peers)",
                    addr, current_count, max_peers
                );

                return Err(AsyncPeerManagerError::ConnectionLimitExceeded {
                    current: current_count,
                    limit: max_peers,
                });
            }
        }

        // Generate a peer ID
        let peer_id = PeerId(self.next_peer_id.fetch_add(1, Ordering::SeqCst));

        match self.config.transport_security_mode {
            TransportSecurityMode::PlainTcp => {
                // PlainTcp mode: establish raw TCP connection
                let stream = TcpStream::connect(addr).await?;
                stream.set_nodelay(true)?;
                self.register_peer(peer_id, stream).await?;
                eprintln!(
                    "[AsyncPeerManagerImpl] Connected to peer {:?} at {} (PlainTcp)",
                    peer_id, addr
                );
            }
            TransportSecurityMode::Kemtls => {
                // KEMTLS mode: perform client-side handshake with concurrency limit (T113)
                let cfg = client_config.ok_or_else(|| {
                    AsyncPeerManagerError::Protocol(
                        "KEMTLS mode requires client_config for outbound connections".to_string(),
                    )
                })?;

                let kemtls_metrics = self.kemtls_metrics.clone();
                let handshake_start = std::time::Instant::now();
                let addr_owned = addr.to_string();

                // T113: Acquire semaphore permit if concurrency limit is configured
                // The permit is held for the duration of the spawn_blocking handshake
                let _permit = if let Some(ref semaphore) = self.kemtls_handshake_semaphore {
                    // Record that a handshake is starting (waiting for permit)
                    kemtls_metrics.record_handshake_started();
                    // Blocking-wait semantics: handshakes queue until permit is available
                    let permit = semaphore.acquire().await.map_err(|e| {
                        kemtls_metrics.record_handshake_completed();
                        AsyncPeerManagerError::Protocol(format!(
                            "KEMTLS handshake semaphore closed: {}",
                            e
                        ))
                    })?;
                    Some(permit)
                } else {
                    // No limit configured, record handshake start for metrics consistency
                    kemtls_metrics.record_handshake_started();
                    None
                };

                // Perform blocking client handshake in spawn_blocking
                let handshake_result =
                    tokio::task::spawn_blocking(move || SecureChannel::connect(&addr_owned, cfg))
                        .await
                        .map_err(|e| {
                            kemtls_metrics.record_handshake_completed();
                            kemtls_metrics.inc_handshake_failure_with_role(
                                KemtlsHandshakeFailureReason::Other,
                                KemtlsRole::Client,
                            );
                            AsyncPeerManagerError::Protocol(format!(
                                "spawn_blocking join error: {}",
                                e
                            ))
                        })?;

                // Check handshake result
                let secure_channel = match handshake_result {
                    Ok(channel) => {
                        let handshake_duration = handshake_start.elapsed();
                        // T120: Record with client role
                        kemtls_metrics.record_handshake_success_with_role(
                            handshake_duration,
                            KemtlsRole::Client,
                        );
                        kemtls_metrics.record_handshake_completed();
                        eprintln!(
                            "[AsyncPeerManagerImpl] Client KEMTLS handshake succeeded for {:?} in {:?}",
                            peer_id, handshake_duration
                        );
                        channel
                    }
                    Err(e) => {
                        // Categorize the error for metrics
                        let reason = match &e {
                            crate::secure_channel::ChannelError::Io(_) => {
                                KemtlsHandshakeFailureReason::Io
                            }
                            crate::secure_channel::ChannelError::Net(net_err) => match net_err {
                                qbind_net::NetError::KeySchedule(_)
                                | qbind_net::NetError::Aead(_)
                                | qbind_net::NetError::UnsupportedSuite(_) => {
                                    KemtlsHandshakeFailureReason::Crypto
                                }
                                qbind_net::NetError::Protocol(_)
                                | qbind_net::NetError::NonceOverflow => {
                                    KemtlsHandshakeFailureReason::Protocol
                                }
                            },
                        };
                        // T120: Record failure with client role
                        kemtls_metrics.inc_handshake_failure_with_role(reason, KemtlsRole::Client);
                        kemtls_metrics.record_handshake_completed();
                        eprintln!(
                            "[AsyncPeerManagerImpl] Client KEMTLS handshake failed for {:?}: {:?}",
                            peer_id, e
                        );
                        return Err(AsyncPeerManagerError::Protocol(format!(
                            "Client KEMTLS handshake failed: {:?}",
                            e
                        )));
                    }
                };

                // Wrap in SecureChannelAsync and register
                let secure_channel_async = SecureChannelAsync::new(secure_channel);
                self.register_secure_peer(peer_id, secure_channel_async)
                    .await?;
                eprintln!(
                    "[AsyncPeerManagerImpl] Connected to peer {:?} at {} (KEMTLS)",
                    peer_id, addr
                );
            }
        }

        Ok(peer_id)
    }

    /// Register a peer by creating reader/writer tasks.
    async fn register_peer(
        self: &Arc<Self>,
        peer_id: PeerId,
        stream: TcpStream,
    ) -> Result<(), AsyncPeerManagerError> {
        // Split the stream into read and write halves
        let (read_half, write_half) = stream.into_split();

        // Create the outbound channel for this peer
        let (outbound_tx, outbound_rx) = mpsc::channel(self.config.outbound_channel_capacity);

        // Clone shutdown receiver for reader and writer tasks (T90.4)
        let reader_shutdown_rx = self.shutdown_tx.subscribe();
        let writer_shutdown_rx = self.shutdown_tx.subscribe();

        // Clone metrics handle if available (T90.4)
        let reader_metrics = self.metrics.clone();

        // Clone broadcast sender for event fan-out (T90.4)
        let event_broadcast_tx = self.event_broadcast_tx.clone();

        // Clone rate limiter for reader task (T123)
        let reader_rate_limiter = self.rate_limiter.clone();

        // Spawn the reader task with shutdown signal and metrics
        let inbound_tx = self.inbound_tx.clone();
        let reader_peer_id = peer_id;
        let reader_handle = tokio::spawn(async move {
            Self::peer_reader_task(
                reader_peer_id,
                read_half,
                inbound_tx,
                event_broadcast_tx,
                reader_shutdown_rx,
                reader_metrics,
                reader_rate_limiter,
            )
            .await;
        });

        // Spawn the writer task with shutdown signal
        let writer_peer_id = peer_id;
        let writer_handle = tokio::spawn(async move {
            Self::peer_writer_task(writer_peer_id, write_half, outbound_rx, writer_shutdown_rx)
                .await;
        });

        // Add to peer map
        let state = PeerState {
            outbound_tx,
            _reader_handle: reader_handle,
            _writer_handle: writer_handle,
        };

        let mut peers = self.peers.write().await;
        peers.insert(peer_id, state);

        Ok(())
    }

    /// Register a peer with a secure channel for KEMTLS mode (T92).
    ///
    /// Similar to `register_peer`, but uses `SecureChannelAsync` for encrypted
    /// message transport instead of raw TCP streams.
    async fn register_secure_peer(
        self: &Arc<Self>,
        peer_id: PeerId,
        secure_channel: SecureChannelAsync,
    ) -> Result<(), AsyncPeerManagerError> {
        // Create the outbound channel for this peer
        let (outbound_tx, outbound_rx) = mpsc::channel(self.config.outbound_channel_capacity);

        // Clone shutdown receiver for reader and writer tasks
        let reader_shutdown_rx = self.shutdown_tx.subscribe();
        let writer_shutdown_rx = self.shutdown_tx.subscribe();

        // Clone metrics handle if available
        let reader_metrics = self.metrics.clone();

        // Clone broadcast sender for event fan-out
        let event_broadcast_tx = self.event_broadcast_tx.clone();

        // Clone rate limiter for reader task (T123)
        let reader_rate_limiter = self.rate_limiter.clone();

        // Clone inbound tx for the reader
        let inbound_tx = self.inbound_tx.clone();

        // Clone the secure channel for reader and writer
        let reader_channel = secure_channel.clone();
        let writer_channel = secure_channel;

        // Spawn the secure reader task
        let reader_peer_id = peer_id;
        let reader_handle = tokio::spawn(async move {
            Self::secure_peer_reader_task(
                reader_peer_id,
                reader_channel,
                inbound_tx,
                event_broadcast_tx,
                reader_shutdown_rx,
                reader_metrics,
                reader_rate_limiter,
            )
            .await;
        });

        // Spawn the secure writer task
        let writer_peer_id = peer_id;
        let writer_handle = tokio::spawn(async move {
            Self::secure_peer_writer_task(
                writer_peer_id,
                writer_channel,
                outbound_rx,
                writer_shutdown_rx,
            )
            .await;
        });

        // Add to peer map
        let state = PeerState {
            outbound_tx,
            _reader_handle: reader_handle,
            _writer_handle: writer_handle,
        };

        let mut peers = self.peers.write().await;
        peers.insert(peer_id, state);

        Ok(())
    }

    /// Reader task for a single peer (T90.4).
    ///
    /// Reads messages from the socket, decodes them, and pushes consensus
    /// events to both the inbound channel and broadcast channel.
    ///
    /// # Shutdown Handling (T90.4)
    ///
    /// The task uses `tokio::select!` to observe a shutdown signal. When the
    /// shutdown signal is received:
    /// - The task exits promptly
    /// - Socket is implicitly closed when `read_half` is dropped
    /// - Per-peer disconnect metrics are recorded
    ///
    /// # Per-Peer Metrics (T90.4)
    ///
    /// When metrics are provided:
    /// - Inbound message counts are incremented per (peer, kind)
    /// - Disconnect reasons (EOF, error) are tracked per-peer
    async fn peer_reader_task(
        peer_id: PeerId,
        mut read_half: tokio::net::tcp::OwnedReadHalf,
        inbound_tx: mpsc::Sender<ConsensusNetworkEvent<PeerId>>,
        event_broadcast_tx: broadcast::Sender<ConsensusNetworkEvent<PeerId>>,
        mut shutdown_rx: watch::Receiver<bool>,
        metrics: Option<Arc<NodeMetrics>>,
        rate_limiter: Arc<PeerRateLimiter>,
    ) {
        eprintln!(
            "[AsyncPeerManagerImpl] Reader task started for {:?}",
            peer_id
        );

        // Helper to record disconnect metric
        let record_disconnect = |reason: DisconnectReason| {
            if let Some(ref m) = metrics {
                m.peer_network().inc_disconnect(peer_id, reason);
            }
        };

        loop {
            // Read length-prefixed message with shutdown signal
            // Format: 4-byte big-endian length + message bytes
            let mut len_buf = [0u8; 4];

            let read_result = tokio::select! {
                biased;

                // Priority: check shutdown first
                _ = shutdown_rx.changed() => {
                    eprintln!("[AsyncPeerManagerImpl] Reader task {:?} received shutdown signal", peer_id);
                    record_disconnect(DisconnectReason::Shutdown);
                    break;
                }

                result = read_half.read_exact(&mut len_buf) => result,
            };

            match read_result {
                Ok(_) => {}
                Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                    eprintln!(
                        "[AsyncPeerManagerImpl] Peer {:?} disconnected (EOF)",
                        peer_id
                    );
                    record_disconnect(DisconnectReason::Eof);
                    break;
                }
                Err(e) => {
                    eprintln!(
                        "[AsyncPeerManagerImpl] Reader error for {:?}: {}",
                        peer_id, e
                    );
                    record_disconnect(DisconnectReason::Error);
                    break;
                }
            }

            let msg_len = u32::from_be_bytes(len_buf) as usize;

            // Sanity check on message size
            if msg_len > 10 * 1024 * 1024 {
                // 10 MB limit
                eprintln!(
                    "[AsyncPeerManagerImpl] Message too large from {:?}: {} bytes",
                    peer_id, msg_len
                );
                record_disconnect(DisconnectReason::Error);
                break;
            }

            // Read message bytes with shutdown signal
            let mut msg_buf = vec![0u8; msg_len];

            let read_body_result = tokio::select! {
                biased;

                _ = shutdown_rx.changed() => {
                    eprintln!("[AsyncPeerManagerImpl] Reader task {:?} received shutdown during body read", peer_id);
                    record_disconnect(DisconnectReason::Shutdown);
                    break;
                }

                result = read_half.read_exact(&mut msg_buf) => result,
            };

            match read_body_result {
                Ok(_) => {}
                Err(e) => {
                    eprintln!(
                        "[AsyncPeerManagerImpl] Failed to read message from {:?}: {}",
                        peer_id, e
                    );
                    record_disconnect(DisconnectReason::Error);
                    break;
                }
            }

            // Decode the message
            let mut slice: &[u8] = &msg_buf;
            let net_msg = match NetMessage::decode(&mut slice) {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!(
                        "[AsyncPeerManagerImpl] Failed to decode message from {:?}: {:?}",
                        peer_id, e
                    );
                    continue;
                }
            };

            // Per-peer rate limiting check (T123)
            // Check rate limit AFTER decode but BEFORE forwarding to consensus
            if !rate_limiter.allow(&peer_id, Instant::now()) {
                // Message rate-limited: increment metric and drop
                if let Some(ref m) = metrics {
                    m.peer_network().inc_rate_limit_drop(peer_id);
                }
                // Log at debug/trace level to avoid log spam
                eprintln!(
                    "[AsyncPeerManagerImpl] Rate-limited message from {:?} (dropping)",
                    peer_id
                );
                continue;
            }

            // Convert to consensus event and record per-peer metrics
            let (event, msg_kind) = match net_msg {
                NetMessage::ConsensusVote(vote) => (
                    Some(ConsensusNetworkEvent::IncomingVote {
                        from: peer_id,
                        vote,
                    }),
                    Some(InboundMsgKind::Vote),
                ),
                NetMessage::BlockProposal(proposal) => (
                    Some(ConsensusNetworkEvent::IncomingProposal {
                        from: peer_id,
                        proposal,
                    }),
                    Some(InboundMsgKind::Proposal),
                ),
                NetMessage::Ping(_) | NetMessage::Pong(_) => {
                    // Handle ping/pong internally (future enhancement)
                    (None, Some(InboundMsgKind::Other))
                }
                NetMessage::PeerListMsg(_) => {
                    // T205: Discovery message - handled by discovery layer
                    (None, Some(InboundMsgKind::Other))
                }
            };

            // Record per-peer inbound metric (T90.4)
            if let Some(kind) = msg_kind {
                if let Some(ref m) = metrics {
                    m.peer_network().inc_inbound(peer_id, kind);
                }
            }

            if let Some(evt) = event {
                // Send to inbound channel
                if let Err(e) = inbound_tx.send(evt.clone()).await {
                    eprintln!(
                        "[AsyncPeerManagerImpl] Failed to send event to inbound channel: {}",
                        e
                    );
                    break;
                }

                // Also broadcast for SharedAsyncPeerManager (T90.4)
                // Best-effort: if no subscribers or lagged, ignore errors
                let _ = event_broadcast_tx.send(evt);
            }
        }

        eprintln!(
            "[AsyncPeerManagerImpl] Reader task exiting for {:?}",
            peer_id
        );
    }

    /// Writer task for a single peer (T90.4).
    ///
    /// Receives messages from the per-peer channel and writes them to the socket.
    ///
    /// # Shutdown Handling (T90.4)
    ///
    /// The task uses `tokio::select!` to observe a shutdown signal. When shutdown
    /// is signaled, the task exits promptly, dropping the write half and closing
    /// the connection.
    async fn peer_writer_task(
        peer_id: PeerId,
        mut write_half: tokio::net::tcp::OwnedWriteHalf,
        mut outbound_rx: mpsc::Receiver<NetMessage>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        eprintln!(
            "[AsyncPeerManagerImpl] Writer task started for {:?}",
            peer_id
        );

        loop {
            let msg = tokio::select! {
                biased;

                // Priority: check shutdown first
                _ = shutdown_rx.changed() => {
                    eprintln!("[AsyncPeerManagerImpl] Writer task {:?} received shutdown signal", peer_id);
                    break;
                }

                maybe_msg = outbound_rx.recv() => {
                    match maybe_msg {
                        Some(m) => m,
                        None => {
                            // Channel closed
                            eprintln!("[AsyncPeerManagerImpl] Writer channel closed for {:?}", peer_id);
                            break;
                        }
                    }
                }
            };

            // Encode the message
            let mut msg_bytes = Vec::new();
            msg.encode(&mut msg_bytes);

            // Write length prefix + message
            let len_bytes = (msg_bytes.len() as u32).to_be_bytes();

            if let Err(e) = write_half.write_all(&len_bytes).await {
                eprintln!(
                    "[AsyncPeerManagerImpl] Failed to write length for {:?}: {}",
                    peer_id, e
                );
                break;
            }

            if let Err(e) = write_half.write_all(&msg_bytes).await {
                eprintln!(
                    "[AsyncPeerManagerImpl] Failed to write message for {:?}: {}",
                    peer_id, e
                );
                break;
            }

            if let Err(e) = write_half.flush().await {
                eprintln!(
                    "[AsyncPeerManagerImpl] Failed to flush for {:?}: {}",
                    peer_id, e
                );
                break;
            }
        }

        eprintln!(
            "[AsyncPeerManagerImpl] Writer task exiting for {:?}",
            peer_id
        );
    }

    /// Secure reader task for a KEMTLS peer (T92).
    ///
    /// Reads encrypted messages from the `SecureChannelAsync`, decodes them, and
    /// pushes consensus events to both the inbound channel and broadcast channel.
    ///
    /// # Transport Security
    ///
    /// All data is encrypted/decrypted through the KEMTLS-established session.
    /// The underlying `SecureChannelAsync::recv()` uses `spawn_blocking` for the
    /// blocking decryption operations.
    ///
    /// # Shutdown Handling
    ///
    /// The task periodically checks the shutdown signal. Because the recv operation
    /// blocks in `spawn_blocking`, we use a short read timeout to allow frequent
    /// shutdown checks.
    async fn secure_peer_reader_task(
        peer_id: PeerId,
        channel: SecureChannelAsync,
        inbound_tx: mpsc::Sender<ConsensusNetworkEvent<PeerId>>,
        event_broadcast_tx: broadcast::Sender<ConsensusNetworkEvent<PeerId>>,
        shutdown_rx: watch::Receiver<bool>,
        metrics: Option<Arc<NodeMetrics>>,
        rate_limiter: Arc<PeerRateLimiter>,
    ) {
        eprintln!(
            "[AsyncPeerManagerImpl] Secure reader task started for {:?}",
            peer_id
        );

        // Set a short read timeout to allow periodic shutdown checks
        // The recv will return a timeout error, but we'll retry after checking shutdown
        if let Err(e) = channel
            .set_read_timeout(Some(Duration::from_millis(500)))
            .await
        {
            eprintln!(
                "[AsyncPeerManagerImpl] Failed to set read timeout for {:?}: {}",
                peer_id, e
            );
        }

        // Helper to record disconnect metric
        let record_disconnect = |reason: DisconnectReason| {
            if let Some(ref m) = metrics {
                m.peer_network().inc_disconnect(peer_id, reason);
            }
        };

        loop {
            // Check shutdown first
            if *shutdown_rx.borrow() {
                eprintln!(
                    "[AsyncPeerManagerImpl] Secure reader task {:?} received shutdown signal",
                    peer_id
                );
                record_disconnect(DisconnectReason::Shutdown);
                break;
            }

            // Try to receive an encrypted message
            let recv_result = channel.recv().await;

            // Check shutdown again after potentially blocking operation
            if *shutdown_rx.borrow() {
                record_disconnect(DisconnectReason::Shutdown);
                break;
            }

            let plaintext = match recv_result {
                Ok(data) => data,
                Err(e) => {
                    // Check if it's a timeout error (expected for shutdown checks)
                    if e.is_timeout() {
                        // Timeout is expected, retry after checking shutdown
                        continue;
                    }

                    // Check for EOF
                    if e.is_eof() {
                        eprintln!(
                            "[AsyncPeerManagerImpl] Secure peer {:?} disconnected (EOF)",
                            peer_id
                        );
                        record_disconnect(DisconnectReason::Eof);
                    } else {
                        eprintln!(
                            "[AsyncPeerManagerImpl] Secure reader error for {:?}: {}",
                            peer_id, e
                        );
                        record_disconnect(DisconnectReason::Error);
                    }
                    break;
                }
            };

            // Decode the plaintext message
            let mut slice: &[u8] = &plaintext;
            let net_msg = match NetMessage::decode(&mut slice) {
                Ok(msg) => msg,
                Err(e) => {
                    eprintln!(
                        "[AsyncPeerManagerImpl] Failed to decode secure message from {:?}: {:?}",
                        peer_id, e
                    );
                    continue;
                }
            };

            // Per-peer rate limiting check (T123)
            // Check rate limit AFTER decode but BEFORE forwarding to consensus
            if !rate_limiter.allow(&peer_id, Instant::now()) {
                // Message rate-limited: increment metric and drop
                if let Some(ref m) = metrics {
                    m.peer_network().inc_rate_limit_drop(peer_id);
                }
                // Log at debug/trace level to avoid log spam
                eprintln!(
                    "[AsyncPeerManagerImpl] Rate-limited secure message from {:?} (dropping)",
                    peer_id
                );
                continue;
            }

            // Convert to consensus event and record per-peer metrics
            let (event, msg_kind) = match net_msg {
                NetMessage::ConsensusVote(vote) => (
                    Some(ConsensusNetworkEvent::IncomingVote {
                        from: peer_id,
                        vote,
                    }),
                    Some(InboundMsgKind::Vote),
                ),
                NetMessage::BlockProposal(proposal) => (
                    Some(ConsensusNetworkEvent::IncomingProposal {
                        from: peer_id,
                        proposal,
                    }),
                    Some(InboundMsgKind::Proposal),
                ),
                NetMessage::Ping(_) | NetMessage::Pong(_) => (None, Some(InboundMsgKind::Other)),
                NetMessage::PeerListMsg(_) => {
                    // T205: Discovery message - handled by discovery layer
                    (None, Some(InboundMsgKind::Other))
                }
            };

            // Record per-peer inbound metric
            if let Some(kind) = msg_kind {
                if let Some(ref m) = metrics {
                    m.peer_network().inc_inbound(peer_id, kind);
                }
            }

            if let Some(evt) = event {
                // Send to inbound channel
                if let Err(e) = inbound_tx.send(evt.clone()).await {
                    eprintln!(
                        "[AsyncPeerManagerImpl] Failed to send secure event to inbound channel: {}",
                        e
                    );
                    break;
                }

                // Also broadcast for SharedAsyncPeerManager
                let _ = event_broadcast_tx.send(evt);
            }
        }

        eprintln!(
            "[AsyncPeerManagerImpl] Secure reader task exiting for {:?}",
            peer_id
        );
    }

    /// Secure writer task for a KEMTLS peer (T92).
    ///
    /// Receives messages from the per-peer channel and sends them encrypted through
    /// the `SecureChannelAsync`.
    ///
    /// # Transport Security
    ///
    /// All data is encrypted through the KEMTLS-established session before being
    /// sent over the wire. The underlying `SecureChannelAsync::send()` uses
    /// `spawn_blocking` for the blocking encryption operations.
    async fn secure_peer_writer_task(
        peer_id: PeerId,
        channel: SecureChannelAsync,
        mut outbound_rx: mpsc::Receiver<NetMessage>,
        mut shutdown_rx: watch::Receiver<bool>,
    ) {
        eprintln!(
            "[AsyncPeerManagerImpl] Secure writer task started for {:?}",
            peer_id
        );

        loop {
            let msg = tokio::select! {
                biased;

                // Priority: check shutdown first
                _ = shutdown_rx.changed() => {
                    eprintln!("[AsyncPeerManagerImpl] Secure writer task {:?} received shutdown signal", peer_id);
                    break;
                }

                maybe_msg = outbound_rx.recv() => {
                    match maybe_msg {
                        Some(m) => m,
                        None => {
                            // Channel closed
                            eprintln!("[AsyncPeerManagerImpl] Secure writer channel closed for {:?}", peer_id);
                            break;
                        }
                    }
                }
            };

            // Encode the message to wire format
            let mut msg_bytes = Vec::new();
            msg.encode(&mut msg_bytes);

            // Send encrypted through the secure channel
            if let Err(e) = channel.send(&msg_bytes).await {
                eprintln!(
                    "[AsyncPeerManagerImpl] Failed to send secure message for {:?}: {}",
                    peer_id, e
                );
                break;
            }
        }

        eprintln!(
            "[AsyncPeerManagerImpl] Secure writer task exiting for {:?}",
            peer_id
        );
    }

    /// Signal shutdown to the peer manager (T90.4).
    ///
    /// This will:
    /// - Set the shutdown flag (for legacy compatibility)
    /// - Signal all reader/writer tasks via the watch channel
    /// - Stop the listener task
    ///
    /// # Shutdown Guarantees
    ///
    /// - Reader/writer tasks will exit promptly on next `select!` cycle
    /// - Sockets are closed when task-local handles are dropped
    /// - In-flight messages may be lost (best-effort drain)
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
        // Signal all tasks via watch channel
        let _ = self.shutdown_tx.send(true);
    }

    /// Check if the peer manager is shutting down.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Get the number of connected peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    /// Get a list of connected peer IDs.
    pub async fn peer_ids(&self) -> Vec<PeerId> {
        self.peers.read().await.keys().copied().collect()
    }

    /// Remove a peer from the manager.
    pub async fn remove_peer(&self, peer_id: PeerId) -> Result<(), AsyncPeerManagerError> {
        let mut peers = self.peers.write().await;
        if peers.remove(&peer_id).is_some() {
            eprintln!("[AsyncPeerManagerImpl] Removed peer {:?}", peer_id);
            Ok(())
        } else {
            Err(AsyncPeerManagerError::PeerNotFound(peer_id))
        }
    }

    /// Send a message to a specific peer.
    async fn send_to_peer(
        &self,
        peer_id: PeerId,
        msg: NetMessage,
    ) -> Result<(), AsyncPeerManagerError> {
        let peers = self.peers.read().await;
        let state = peers
            .get(&peer_id)
            .ok_or(AsyncPeerManagerError::PeerNotFound(peer_id))?;

        state
            .outbound_tx
            .send(msg)
            .await
            .map_err(|e| AsyncPeerManagerError::ChannelSend(e.to_string()))
    }

    /// Broadcast a message to all connected peers.
    async fn broadcast(&self, msg: NetMessage) -> Result<(), AsyncPeerManagerError> {
        let peers = self.peers.read().await;

        for (_peer_id, state) in peers.iter() {
            // Best-effort broadcast - don't fail if one peer fails
            let _ = state.outbound_tx.send(msg.clone()).await;
        }

        Ok(())
    }

    /// Try to receive an event from the inbound channel with a timeout.
    ///
    /// This method is useful for testing when you have an `Arc<AsyncPeerManagerImpl>`
    /// and need to receive events without consuming the manager.
    ///
    /// Returns `None` if no event is available within the timeout.
    pub async fn try_recv_event_timeout(
        &self,
        timeout: Duration,
    ) -> Option<ConsensusNetworkEvent<PeerId>> {
        if self.is_shutdown() {
            return None;
        }

        let mut rx = self.inbound_rx.lock().await;
        tokio::time::timeout(timeout, rx.recv())
            .await
            .ok()
            .flatten()
    }
}

// ============================================================================
// AsyncPeerManager trait implementation
// ============================================================================

impl AsyncPeerManager for AsyncPeerManagerImpl {
    async fn recv_event(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        if self.is_shutdown() {
            return None;
        }

        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await
    }

    async fn send_vote_to(&self, peer: PeerId, vote: Vote) -> Result<(), NetworkError> {
        let msg = NetMessage::ConsensusVote(vote);
        self.send_to_peer(peer, msg)
            .await
            .map_err(|e| NetworkError::Other(e.to_string()))
    }

    async fn broadcast_vote(&self, vote: Vote) -> Result<(), NetworkError> {
        let msg = NetMessage::ConsensusVote(vote);
        self.broadcast(msg)
            .await
            .map_err(|e| NetworkError::Other(e.to_string()))
    }

    async fn broadcast_proposal(&self, proposal: BlockProposal) -> Result<(), NetworkError> {
        let msg = NetMessage::BlockProposal(proposal);
        self.broadcast(msg)
            .await
            .map_err(|e| NetworkError::Other(e.to_string()))
    }
}

// ============================================================================
// ConsensusNetService implementation (Part B)
// ============================================================================

use crate::consensus_net_worker::ConsensusNetService;

impl ConsensusNetService for AsyncPeerManagerImpl {
    async fn recv(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        self.recv_event().await
    }

    async fn send_vote_to(&mut self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
        AsyncPeerManager::send_vote_to(self, to, vote.clone()).await
    }

    async fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError> {
        AsyncPeerManager::broadcast_vote(self, vote.clone()).await
    }

    async fn broadcast_proposal(&mut self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        AsyncPeerManager::broadcast_proposal(self, proposal.clone()).await
    }
}

// ============================================================================
// Wrapper for Arc<AsyncPeerManagerImpl>
// ============================================================================

/// Wrapper to implement ConsensusNetService for Arc<AsyncPeerManagerImpl> (T90.4).
///
/// This allows the async peer manager to be shared across tasks while
/// still implementing the ConsensusNetService trait.
///
/// # Event Reception (T90.4)
///
/// This wrapper uses a broadcast channel to receive events. Each
/// `SharedAsyncPeerManager` instance subscribes to the broadcast and
/// receives its own copy of events. This enables multiple consumers
/// to receive the same events concurrently.
///
/// # Limitations
///
/// - If the broadcast channel fills up (lagged receiver), some events
///   may be dropped for slow consumers.
/// - For best performance, consumers should process events promptly.
pub struct SharedAsyncPeerManager {
    inner: Arc<AsyncPeerManagerImpl>,
    /// Broadcast receiver for event fan-out (T90.4).
    /// Each SharedAsyncPeerManager gets its own receiver subscribed to
    /// the manager's broadcast channel.
    broadcast_rx: broadcast::Receiver<ConsensusNetworkEvent<PeerId>>,
}

impl SharedAsyncPeerManager {
    /// Create a new shared wrapper around an `AsyncPeerManagerImpl` (T90.4).
    ///
    /// This subscribes to the manager's event broadcast channel, enabling
    /// this wrapper's `recv()` method to receive real events.
    ///
    /// # Note
    ///
    /// Multiple `SharedAsyncPeerManager` instances can be created from the
    /// same `Arc<AsyncPeerManagerImpl>`. Each will receive its own copy of
    /// all events via the broadcast channel.
    pub fn new(inner: Arc<AsyncPeerManagerImpl>) -> Self {
        // Subscribe to the broadcast channel for event fan-out
        let broadcast_rx = inner.event_broadcast_tx.subscribe();

        SharedAsyncPeerManager {
            inner,
            broadcast_rx,
        }
    }

    /// Get a reference to the inner manager.
    pub fn inner(&self) -> &Arc<AsyncPeerManagerImpl> {
        &self.inner
    }
}

impl ConsensusNetService for SharedAsyncPeerManager {
    async fn recv(&mut self) -> Option<ConsensusNetworkEvent<PeerId>> {
        // Receive from broadcast channel (T90.4)
        // This properly receives events from the manager's reader tasks.
        loop {
            match self.broadcast_rx.recv().await {
                Ok(event) => return Some(event),
                Err(broadcast::error::RecvError::Closed) => {
                    // Broadcast channel closed (manager shutting down)
                    return None;
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    // Receiver lagged behind - some messages were dropped
                    eprintln!(
                        "[SharedAsyncPeerManager] WARNING: receiver lagged, {} messages dropped",
                        n
                    );
                    // Continue to receive the next available message
                    continue;
                }
            }
        }
    }

    async fn send_vote_to(&mut self, to: PeerId, vote: &Vote) -> Result<(), NetworkError> {
        AsyncPeerManager::send_vote_to(self.inner.as_ref(), to, vote.clone()).await
    }

    async fn broadcast_vote(&mut self, vote: &Vote) -> Result<(), NetworkError> {
        AsyncPeerManager::broadcast_vote(self.inner.as_ref(), vote.clone()).await
    }

    async fn broadcast_proposal(&mut self, proposal: &BlockProposal) -> Result<(), NetworkError> {
        AsyncPeerManager::broadcast_proposal(self.inner.as_ref(), proposal.clone()).await
    }
}

// ============================================================================
// Test utilities
// ============================================================================

#[cfg(test)]
pub mod testing {
    use super::*;

    /// Create a connected pair of TCP streams for testing.
    ///
    /// Returns (client_stream, server_stream) where client connected to server.
    pub async fn create_connected_streams() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let connect_future = TcpStream::connect(addr);
        let accept_future = listener.accept();

        let (client_result, accept_result) = tokio::join!(connect_future, accept_future);

        let client = client_result.unwrap();
        let (server, _addr) = accept_result.unwrap();

        (client, server)
    }

    /// Create a dummy Vote for testing.
    pub fn make_test_vote(height: u64, round: u64) -> Vote {
        Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round,
            step: 0,
            block_id: [0u8; 32],
            validator_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            signature: vec![],
        }
    }

    /// Create a dummy BlockProposal for testing.
    pub fn make_test_proposal(height: u64, round: u64) -> BlockProposal {
        use qbind_wire::consensus::BlockHeader;

        BlockProposal {
            header: BlockHeader {
                version: 1,
                chain_id: 1,
                epoch: 0,
                height,
                round,
                parent_block_id: [0u8; 32],
                payload_hash: [0u8; 32],
                proposer_index: 0,
                suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
                tx_count: 0,
                timestamp: 0,
                payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
                next_epoch: 0,
                batch_commitment: [0u8; 32],
            },
            qc: None,
            txs: vec![],
            signature: vec![],
        }
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::testing::*;
    use super::*;

    #[test]
    fn async_peer_manager_config_default() {
        let config = AsyncPeerManagerConfig::default();
        assert_eq!(config.inbound_channel_capacity, 1024);
        assert_eq!(config.outbound_channel_capacity, 256);
    }

    #[tokio::test]
    async fn async_peer_manager_can_bind() {
        let mut manager = AsyncPeerManagerImpl::new_default();
        let addr = manager.bind().await.expect("bind should succeed");
        assert_ne!(addr.port(), 0);
    }

    #[tokio::test]
    async fn async_peer_manager_shutdown_flag() {
        let manager = AsyncPeerManagerImpl::new_default();
        assert!(!manager.is_shutdown());
        manager.shutdown();
        assert!(manager.is_shutdown());
    }

    #[tokio::test]
    async fn async_peer_manager_error_display() {
        let err = AsyncPeerManagerError::PeerNotFound(PeerId(42));
        let display = err.to_string();
        assert!(display.contains("42"));
        assert!(display.contains("not found"));
    }

    #[tokio::test]
    async fn peer_registration_and_count() {
        let config = AsyncPeerManagerConfig::default();
        let manager = Arc::new(AsyncPeerManagerImpl::new(config));

        // Create a connected pair of streams
        let (client_stream, _server_stream) = create_connected_streams().await;

        // Register a peer
        manager
            .add_peer_with_stream(PeerId(1), client_stream)
            .await
            .expect("registration should succeed");

        assert_eq!(manager.peer_count().await, 1);
        assert!(manager.peer_ids().await.contains(&PeerId(1)));
    }

    #[tokio::test]
    async fn peer_removal() {
        let config = AsyncPeerManagerConfig::default();
        let manager = Arc::new(AsyncPeerManagerImpl::new(config));

        let (stream, _) = create_connected_streams().await;
        manager
            .add_peer_with_stream(PeerId(1), stream)
            .await
            .unwrap();

        assert_eq!(manager.peer_count().await, 1);

        manager.remove_peer(PeerId(1)).await.unwrap();
        assert_eq!(manager.peer_count().await, 0);

        // Removing again should error
        let result = manager.remove_peer(PeerId(1)).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn send_to_nonexistent_peer_fails() {
        let manager = AsyncPeerManagerImpl::new_default();
        let vote = make_test_vote(1, 0);

        let result = manager
            .send_to_peer(PeerId(999), NetMessage::ConsensusVote(vote))
            .await;
        assert!(result.is_err());
    }

    // ========================================================================
    // T90.4 Tests - Per-peer metrics, SharedAsyncPeerManager, and shutdown
    // ========================================================================

    #[tokio::test]
    async fn async_peer_manager_with_metrics_tracks_inbound() {
        use crate::metrics::NodeMetrics;

        let metrics = Arc::new(NodeMetrics::new());
        let config = AsyncPeerManagerConfig::default();
        let manager = Arc::new(AsyncPeerManagerImpl::with_metrics(config, metrics.clone()));

        // Create a connected pair
        let (client, mut server) = create_connected_streams().await;

        manager
            .add_peer_with_stream(PeerId(1), client)
            .await
            .unwrap();

        // Send a vote from server to client (the manager's peer)
        let vote = make_test_vote(10, 5);
        let msg = NetMessage::ConsensusVote(vote);
        let mut msg_bytes = Vec::new();
        msg.encode(&mut msg_bytes);
        let len_bytes = (msg_bytes.len() as u32).to_be_bytes();

        server.write_all(&len_bytes).await.unwrap();
        server.write_all(&msg_bytes).await.unwrap();
        server.flush().await.unwrap();

        // Wait a bit for the reader task to process
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Check per-peer metrics
        let (votes, proposals, _other) = metrics
            .peer_network()
            .peer_inbound_counts(PeerId(1))
            .unwrap();
        assert_eq!(votes, 1, "expected 1 inbound vote for peer 1");
        assert_eq!(proposals, 0, "expected 0 inbound proposals for peer 1");

        manager.shutdown();
    }

    #[tokio::test]
    async fn async_peer_manager_shutdown_terminates_tasks() {
        let config = AsyncPeerManagerConfig::default();
        let manager = Arc::new(AsyncPeerManagerImpl::new(config));

        // Create a connected pair
        let (client, _server) = create_connected_streams().await;

        manager
            .add_peer_with_stream(PeerId(1), client)
            .await
            .unwrap();
        assert_eq!(manager.peer_count().await, 1);

        // Shutdown
        manager.shutdown();

        // Give tasks time to exit
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The manager should still show the peer count (removal happens separately)
        // but tasks should have terminated. We can't directly test task termination
        // in unit tests, but the test completing without hanging confirms it works.
    }

    #[tokio::test]
    async fn shared_async_peer_manager_receives_real_events() {
        let config = AsyncPeerManagerConfig::default();
        let manager = Arc::new(AsyncPeerManagerImpl::new(config));

        // Create a connected pair
        let (client, mut server) = create_connected_streams().await;

        manager
            .add_peer_with_stream(PeerId(1), client)
            .await
            .unwrap();

        // Create SharedAsyncPeerManager
        let mut shared = SharedAsyncPeerManager::new(Arc::clone(&manager));

        // Send a vote from server to client (the manager's peer)
        let vote = make_test_vote(20, 10);
        let msg = NetMessage::ConsensusVote(vote);
        let mut msg_bytes = Vec::new();
        msg.encode(&mut msg_bytes);
        let len_bytes = (msg_bytes.len() as u32).to_be_bytes();

        server.write_all(&len_bytes).await.unwrap();
        server.write_all(&msg_bytes).await.unwrap();
        server.flush().await.unwrap();

        // Use ConsensusNetService::recv to receive via SharedAsyncPeerManager
        // Use a timeout to avoid hanging if something is wrong
        let event = tokio::time::timeout(
            Duration::from_secs(2),
            ConsensusNetService::recv(&mut shared),
        )
        .await
        .expect("should receive within timeout")
        .expect("should receive event");

        match event {
            ConsensusNetworkEvent::IncomingVote { from, vote: v } => {
                assert_eq!(from, PeerId(1));
                assert_eq!(v.height, 20);
                assert_eq!(v.round, 10);
            }
            _ => panic!("expected IncomingVote"),
        }

        manager.shutdown();
    }

    #[tokio::test]
    async fn shutdown_signal_stops_recv_event_timeout() {
        let config = AsyncPeerManagerConfig::default();
        let manager = Arc::new(AsyncPeerManagerImpl::new(config));

        // Create a connected pair but don't send any messages
        let (client, _server) = create_connected_streams().await;

        manager
            .add_peer_with_stream(PeerId(1), client)
            .await
            .unwrap();

        // Shutdown before trying to receive
        manager.shutdown();

        // try_recv_event_timeout should return None quickly due to shutdown
        let start = std::time::Instant::now();
        let result = manager.try_recv_event_timeout(Duration::from_secs(5)).await;
        let elapsed = start.elapsed();

        assert!(result.is_none(), "expected None after shutdown");
        // Should be much faster than 5 seconds due to shutdown
        assert!(
            elapsed < Duration::from_secs(1),
            "should return quickly after shutdown"
        );
    }

    #[test]
    fn async_peer_manager_impl_with_metrics_debug_shows_has_metrics() {
        use crate::metrics::NodeMetrics;

        let metrics = Arc::new(NodeMetrics::new());
        let config = AsyncPeerManagerConfig::default();
        let manager = AsyncPeerManagerImpl::with_metrics(config, metrics);

        let debug_str = format!("{:?}", manager);
        assert!(debug_str.contains("has_metrics: true"));
    }

    // ========================================================================
    // T91 Tests - Transport Security Mode and KEMTLS Metrics
    // ========================================================================

    #[test]
    fn transport_security_mode_from_str() {
        assert_eq!(
            TransportSecurityMode::from_str("plain"),
            Some(TransportSecurityMode::PlainTcp)
        );
        assert_eq!(
            TransportSecurityMode::from_str("PlainTcp"),
            Some(TransportSecurityMode::PlainTcp)
        );
        assert_eq!(
            TransportSecurityMode::from_str("PLAINTCP"),
            Some(TransportSecurityMode::PlainTcp)
        );
        assert_eq!(
            TransportSecurityMode::from_str("kemtls"),
            Some(TransportSecurityMode::Kemtls)
        );
        assert_eq!(
            TransportSecurityMode::from_str("KEMTLS"),
            Some(TransportSecurityMode::Kemtls)
        );
        assert_eq!(TransportSecurityMode::from_str("invalid"), None);
    }

    #[test]
    fn transport_security_mode_display() {
        assert_eq!(TransportSecurityMode::PlainTcp.to_string(), "PlainTcp");
        assert_eq!(TransportSecurityMode::Kemtls.to_string(), "Kemtls");
    }

    #[test]
    fn transport_security_mode_is_kemtls() {
        assert!(!TransportSecurityMode::PlainTcp.is_kemtls());
        assert!(TransportSecurityMode::Kemtls.is_kemtls());
    }

    #[test]
    fn kemtls_metrics_new_creates_zero_counters() {
        let metrics = KemtlsMetrics::new();
        assert_eq!(metrics.handshake_success_total(), 0);
        assert_eq!(metrics.handshake_failure_total(), 0);
    }

    #[test]
    fn kemtls_metrics_increments_success() {
        let metrics = KemtlsMetrics::new();

        metrics.inc_handshake_success();
        metrics.inc_handshake_success();

        assert_eq!(metrics.handshake_success_total(), 2);
    }

    #[test]
    fn kemtls_metrics_increments_failures_by_reason() {
        let metrics = KemtlsMetrics::new();

        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Io);
        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Protocol);
        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Crypto);
        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Timeout);
        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Other);

        assert_eq!(
            metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Io),
            1
        );
        assert_eq!(
            metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Protocol),
            1
        );
        assert_eq!(
            metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Crypto),
            1
        );
        assert_eq!(
            metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Timeout),
            1
        );
        assert_eq!(
            metrics.handshake_failure_by_reason(KemtlsHandshakeFailureReason::Other),
            1
        );
        assert_eq!(metrics.handshake_failure_total(), 5);
    }

    #[test]
    fn kemtls_metrics_record_handshake_success_with_latency() {
        let metrics = KemtlsMetrics::new();

        // Under 10ms
        metrics.record_handshake_success(Duration::from_millis(5));
        // 10ms to 100ms
        metrics.record_handshake_success(Duration::from_millis(50));
        // 100ms to 1s
        metrics.record_handshake_success(Duration::from_millis(500));
        // Over 1s
        metrics.record_handshake_success(Duration::from_secs(2));

        assert_eq!(metrics.handshake_success_total(), 4);

        let (under_10ms, to_100ms, to_1s, over_1s) = metrics.latency_buckets();
        assert_eq!(under_10ms, 1);
        assert_eq!(to_100ms, 1);
        assert_eq!(to_1s, 1);
        assert_eq!(over_1s, 1);
    }

    #[test]
    fn kemtls_metrics_format_metrics() {
        let metrics = KemtlsMetrics::new();

        metrics.record_handshake_success(Duration::from_millis(5));
        metrics.inc_handshake_failure(KemtlsHandshakeFailureReason::Io);

        let output = metrics.format_metrics();

        assert!(output.contains("# KEMTLS handshake metrics (T91, T113, T120)"));
        assert!(output.contains("kemtls_handshake_success_total 1"));
        assert!(output.contains("kemtls_handshake_failure_total{reason=\"io\"} 1"));
        assert!(output.contains("kemtls_handshake_duration_bucket{le=\"0.01\"} 1"));
    }

    #[test]
    fn async_peer_manager_config_transport_security_mode() {
        let config = AsyncPeerManagerConfig::default()
            .with_transport_security_mode(TransportSecurityMode::PlainTcp);

        assert_eq!(
            config.transport_security_mode,
            TransportSecurityMode::PlainTcp
        );
        assert!(!config.is_kemtls_config_missing());
    }

    #[test]
    fn async_peer_manager_config_kemtls_without_server_config_is_invalid() {
        let config = AsyncPeerManagerConfig::default()
            .with_transport_security_mode(TransportSecurityMode::Kemtls);

        assert!(config.is_kemtls_config_missing());
    }

    #[test]
    fn async_peer_manager_impl_has_kemtls_metrics() {
        let manager = AsyncPeerManagerImpl::new_default();

        assert_eq!(manager.kemtls_metrics().handshake_success_total(), 0);
        assert_eq!(manager.kemtls_metrics().handshake_failure_total(), 0);
    }

    #[test]
    fn async_peer_manager_impl_transport_security_mode_accessor() {
        let config = AsyncPeerManagerConfig::default()
            .with_transport_security_mode(TransportSecurityMode::PlainTcp);
        let manager = AsyncPeerManagerImpl::new(config);

        assert_eq!(
            manager.transport_security_mode(),
            TransportSecurityMode::PlainTcp
        );
    }

    #[test]
    fn kemtls_handshake_failure_reason_display() {
        assert_eq!(KemtlsHandshakeFailureReason::Io.to_string(), "io");
        assert_eq!(
            KemtlsHandshakeFailureReason::Protocol.to_string(),
            "protocol"
        );
        assert_eq!(KemtlsHandshakeFailureReason::Crypto.to_string(), "crypto");
        assert_eq!(KemtlsHandshakeFailureReason::Timeout.to_string(), "timeout");
        assert_eq!(KemtlsHandshakeFailureReason::Other.to_string(), "other");
    }
}