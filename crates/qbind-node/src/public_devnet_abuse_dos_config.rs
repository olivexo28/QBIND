//! Run 361 — Public DevNet abuse/DoS hardening: operator-configurable rate-limit
//! posture + bounded inbound connection-rate limiter boundary (source/test only).
//!
//! # Scope
//!
//! This module is a **source/test-only boundary**. It makes the public DevNet
//! abuse/DoS posture *operator-configurable at the type level* and introduces a
//! *pure, deterministic* inbound connection-rate limiter model. It does **not**
//! change any live runtime behavior, does **not** add any public CLI flag, and
//! does **not** alter the existing hardcoded runtime defaults of
//! [`crate::peer_rate_limiter::PeerRateLimiter`]. Release-binary / runtime
//! evidence is deferred to Run 362.
//!
//! Because of that, M12 (abuse/DoS protections) is intentionally **not** marked
//! Green by this run: it moves from `Yellow/Partial` to `Yellow/stronger`, with
//! Green deferred until runtime wiring + release-binary evidence exist.
//!
//! # What this module provides
//!
//! 1. [`AbuseDosConfig`] — a typed, validated config model for the public DevNet
//!    abuse/DoS posture (per-peer message rate + burst, global inbound
//!    connection-rate window + burst, optional per-remote-address window,
//!    fail-open/fail-closed marker, environment binding, optional genesis-hash
//!    binding, and an explicit profile marker).
//! 2. A **safe default profile** ([`AbuseDosConfig::default`]) that exactly
//!    preserves the current hardcoded per-peer behavior
//!    (`1000` msg/s + `100` burst) and leaves the connection-rate limiter
//!    **disabled** unless explicitly enabled — so importing this module changes
//!    nothing at runtime.
//! 3. [`AbuseDosConfig::validate`] — rejects zero / nonsensical / unbounded /
//!    wrong-environment / genesis-mismatch / MainNet values.
//! 4. [`ConnectionRateLimiter`] + [`ConnectionRateLimiterState`] — a pure,
//!    non-mutating (outside caller-owned fixture state) inbound connection-rate
//!    limiter with deterministic [`ConnectionDecision`] outcomes.
//! 5. [`inbound_connection_adapter_shape`] — a doc/adapter shape describing how
//!    `p2p_tcp` *would* consult this config/limiter before accepting inbound
//!    connections, **without** wiring live behavior in Run 361.
//!
//! # Non-goals (explicitly out of scope for Run 361)
//!
//! - No runtime wiring into the live accept loop.
//! - No public CLI flag.
//! - No change to `PeerRateLimiter` defaults or the P2P wire format.
//! - No peer-admission or trust-bundle weakening.
//! - No metrics registration (see [`connection_rate_metric_plan`]).

use std::collections::HashMap;
use std::time::{Duration, Instant};

use qbind_types::primitives::NetworkEnvironment;

use crate::peer_rate_limiter::{
    PeerRateLimiterConfig, DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND,
};

// ============================================================================
// Bounds
// ============================================================================

/// Documented maximum sustained per-peer message rate accepted by a config.
///
/// Values above this are rejected as unbounded/unsafe unless a config is
/// explicitly constructed with an override policy (not exposed in Run 361).
pub const MAX_MESSAGES_PER_SECOND: u64 = 1_000_000;

/// Documented maximum per-peer burst allowance accepted by a config.
pub const MAX_BURST_ALLOWANCE: u64 = 1_000_000;

/// Documented maximum number of inbound connections per window accepted by a
/// config.
pub const MAX_CONNECTIONS_PER_WINDOW: u64 = 1_000_000;

/// Documented maximum connection-rate window (guards against effectively
/// unbounded windows that would disable protection accidentally).
pub const MAX_CONNECTION_WINDOW_SECS: u64 = 24 * 60 * 60;

// ============================================================================
// Fail behavior marker
// ============================================================================

/// Whether the abuse/DoS surface fails **open** (allow on internal error) or
/// **closed** (deny on internal error).
///
/// The existing per-peer [`crate::peer_rate_limiter::PeerRateLimiter`] fails
/// **open** on lock poisoning; the safe default here records that same posture
/// so this module does not silently change behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailMode {
    /// Allow traffic if an internal error occurs (matches current runtime).
    FailOpen,
    /// Deny traffic if an internal error occurs (stricter; opt-in only).
    FailClosed,
}

// ============================================================================
// Profile marker
// ============================================================================

/// Explicit profile marker for an [`AbuseDosConfig`].
///
/// The marker is descriptive only; it does not itself change runtime behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AbuseDosProfile {
    /// Compatibility default: preserves current hardcoded per-peer behavior and
    /// leaves the connection limiter disabled. Importing this module and using
    /// the default profile changes nothing at runtime.
    CompatibilityDefault,
    /// Public DevNet recommended (stricter) profile. Source/test only in Run
    /// 361; must be explicitly selected and is never applied to runtime
    /// defaults by this run.
    PublicDevnetRecommended,
    /// A fully operator-supplied custom profile.
    Custom,
}

// ============================================================================
// Errors
// ============================================================================

/// Validation failures for [`AbuseDosConfig`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbuseDosConfigError {
    /// Per-peer max messages/sec was zero (would starve all traffic once the
    /// burst drains).
    ZeroMaxMessagesPerSecond,
    /// Per-peer max messages/sec exceeds [`MAX_MESSAGES_PER_SECOND`].
    MaxMessagesPerSecondTooLarge(u64),
    /// Per-peer burst allowance exceeds [`MAX_BURST_ALLOWANCE`] (effectively
    /// unbounded — would disable protection accidentally).
    BurstAllowanceTooLarge(u64),
    /// Connection limiter is enabled but the window duration is zero
    /// (an impossible window).
    ZeroConnectionRateWindow,
    /// Connection limiter is enabled but the window exceeds
    /// [`MAX_CONNECTION_WINDOW_SECS`].
    ConnectionRateWindowTooLarge(u64),
    /// Connection limiter is enabled but allows zero connections per window
    /// (would deny everything — nonsensical for an allow-limiter).
    ZeroConnectionsPerWindow,
    /// Connection limiter allows more than [`MAX_CONNECTIONS_PER_WINDOW`]
    /// per window (effectively unbounded).
    ConnectionsPerWindowTooLarge(u64),
    /// The configured environment is not DevNet where DevNet was required.
    WrongEnvironment(NetworkEnvironment),
    /// The configured genesis-hash binding did not match the expected value.
    GenesisBindingMismatch,
    /// MainNet use was requested without a production policy (never granted in
    /// Run 361).
    MainNetRefused,
    /// A readiness claim (TestNet/MainNet) was requested; refused.
    ReadinessClaimRefused,
}

impl std::fmt::Display for AbuseDosConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroMaxMessagesPerSecond => {
                write!(f, "per-peer max messages/sec must be non-zero")
            }
            Self::MaxMessagesPerSecondTooLarge(v) => {
                write!(f, "per-peer max messages/sec {v} exceeds maximum {MAX_MESSAGES_PER_SECOND}")
            }
            Self::BurstAllowanceTooLarge(v) => {
                write!(f, "per-peer burst allowance {v} exceeds maximum {MAX_BURST_ALLOWANCE}")
            }
            Self::ZeroConnectionRateWindow => {
                write!(f, "connection-rate window must be non-zero when the limiter is enabled")
            }
            Self::ConnectionRateWindowTooLarge(v) => {
                write!(f, "connection-rate window {v}s exceeds maximum {MAX_CONNECTION_WINDOW_SECS}s")
            }
            Self::ZeroConnectionsPerWindow => {
                write!(f, "connections per window must be non-zero when the limiter is enabled")
            }
            Self::ConnectionsPerWindowTooLarge(v) => {
                write!(f, "connections per window {v} exceeds maximum {MAX_CONNECTIONS_PER_WINDOW}")
            }
            Self::WrongEnvironment(env) => {
                write!(f, "expected DevNet environment, found {env:?}")
            }
            Self::GenesisBindingMismatch => write!(f, "genesis-hash binding mismatch"),
            Self::MainNetRefused => {
                write!(f, "MainNet use refused: no production abuse/DoS policy exists")
            }
            Self::ReadinessClaimRefused => {
                write!(f, "TestNet/MainNet readiness claim refused for this run")
            }
        }
    }
}

impl std::error::Error for AbuseDosConfigError {}

// ============================================================================
// AbuseDosConfig
// ============================================================================

/// Typed, validated config model for the public DevNet abuse/DoS posture.
///
/// This is a source/test model only. Constructing it never mutates any runtime
/// state, and it does not itself alter [`PeerRateLimiter`](crate::peer_rate_limiter::PeerRateLimiter)
/// defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbuseDosConfig {
    /// Environment this posture is bound to.
    pub environment: NetworkEnvironment,

    /// Optional genesis-hash binding (32-byte hash). When present,
    /// [`AbuseDosConfig::check_genesis_binding`] enforces it.
    pub genesis_hash: Option<[u8; 32]>,

    /// Per-peer sustained max messages per second.
    pub per_peer_max_messages_per_second: u64,

    /// Per-peer burst allowance.
    pub per_peer_burst_allowance: u64,

    /// Whether the global inbound connection-rate limiter is enabled.
    ///
    /// Default is `false` (disabled) so importing this module changes nothing.
    pub connection_limiter_enabled: bool,

    /// Global inbound connection-rate window.
    pub connection_rate_window: Duration,

    /// Maximum inbound connections accepted per [`Self::connection_rate_window`].
    pub max_connections_per_window: u64,

    /// Additional global connection burst allowance above the window rate.
    pub connection_burst_allowance: u64,

    /// Optional per-remote-address connection-rate window (source support:
    /// keyed by [`RemoteAddr`]). When `None`, only the global limiter applies.
    pub per_address_rate_window: Option<Duration>,

    /// Maximum connections per [`Self::per_address_rate_window`] per remote
    /// address (only meaningful when the per-address window is `Some`).
    pub max_connections_per_address_window: u64,

    /// Fail-open vs fail-closed behavior marker.
    pub fail_mode: FailMode,

    /// Explicit profile marker.
    pub profile: AbuseDosProfile,
}

impl Default for AbuseDosConfig {
    /// The safe compatibility default: preserves the current hardcoded per-peer
    /// behavior (`1000` msg/s + `100` burst), leaves the connection limiter
    /// **disabled**, records fail-open (matching current runtime), and binds to
    /// DevNet with no genesis binding.
    fn default() -> Self {
        Self {
            environment: NetworkEnvironment::Devnet,
            genesis_hash: None,
            per_peer_max_messages_per_second: DEFAULT_MAX_MESSAGES_PER_SECOND,
            per_peer_burst_allowance: DEFAULT_BURST_ALLOWANCE,
            connection_limiter_enabled: false,
            connection_rate_window: Duration::from_secs(1),
            max_connections_per_window: 0,
            connection_burst_allowance: 0,
            per_address_rate_window: None,
            max_connections_per_address_window: 0,
            fail_mode: FailMode::FailOpen,
            profile: AbuseDosProfile::CompatibilityDefault,
        }
    }
}

impl AbuseDosConfig {
    /// The safe compatibility default. Alias for [`Default::default`] with an
    /// explicit name for readability at call sites.
    pub fn compatibility_default() -> Self {
        Self::default()
    }

    /// A stricter *recommended* public DevNet profile (source/test only).
    ///
    /// This tightens the per-peer rate and enables the global connection-rate
    /// limiter. It is **never** applied to runtime defaults by Run 361; callers
    /// must select it explicitly.
    pub fn public_devnet_recommended() -> Self {
        Self {
            environment: NetworkEnvironment::Devnet,
            genesis_hash: None,
            per_peer_max_messages_per_second: 500,
            per_peer_burst_allowance: 50,
            connection_limiter_enabled: true,
            connection_rate_window: Duration::from_secs(1),
            max_connections_per_window: 20,
            connection_burst_allowance: 10,
            per_address_rate_window: Some(Duration::from_secs(1)),
            max_connections_per_address_window: 5,
            fail_mode: FailMode::FailClosed,
            profile: AbuseDosProfile::PublicDevnetRecommended,
        }
    }

    /// Bind this config to a genesis hash (builder-style).
    pub fn with_genesis_hash(mut self, genesis_hash: [u8; 32]) -> Self {
        self.genesis_hash = Some(genesis_hash);
        self
    }

    /// Set the environment (builder-style).
    pub fn with_environment(mut self, environment: NetworkEnvironment) -> Self {
        self.environment = environment;
        self
    }

    /// Whether this config represents an accepted DevNet source/test profile.
    ///
    /// A TestNet/MainNet-bound config is **not** a DevNet profile, so it cannot
    /// be accidentally accepted as one.
    pub fn is_devnet_profile(&self) -> bool {
        self.environment == NetworkEnvironment::Devnet
    }

    /// Whether this config preserves the current hardcoded per-peer runtime
    /// defaults (`1000` msg/s + `100` burst).
    pub fn preserves_runtime_defaults(&self) -> bool {
        self.per_peer_max_messages_per_second == DEFAULT_MAX_MESSAGES_PER_SECOND
            && self.per_peer_burst_allowance == DEFAULT_BURST_ALLOWANCE
            && !self.connection_limiter_enabled
    }

    /// Derive the [`PeerRateLimiterConfig`] this posture would apply to the
    /// existing per-peer limiter. This does not construct or mutate any live
    /// limiter.
    pub fn peer_rate_limiter_config(&self) -> PeerRateLimiterConfig {
        PeerRateLimiterConfig::new(
            self.per_peer_max_messages_per_second,
            self.per_peer_burst_allowance,
        )
    }

    /// Validate the config, rejecting zero / nonsensical / unbounded /
    /// wrong-environment / MainNet values.
    ///
    /// Genesis binding is validated separately via
    /// [`Self::check_genesis_binding`] because the expected hash is supplied by
    /// the caller.
    pub fn validate(&self) -> Result<(), AbuseDosConfigError> {
        // MainNet is refused outright: no production policy exists in Run 361.
        if self.environment == NetworkEnvironment::Mainnet {
            return Err(AbuseDosConfigError::MainNetRefused);
        }

        // Per-peer message-rate sanity.
        if self.per_peer_max_messages_per_second == 0 {
            return Err(AbuseDosConfigError::ZeroMaxMessagesPerSecond);
        }
        if self.per_peer_max_messages_per_second > MAX_MESSAGES_PER_SECOND {
            return Err(AbuseDosConfigError::MaxMessagesPerSecondTooLarge(
                self.per_peer_max_messages_per_second,
            ));
        }
        if self.per_peer_burst_allowance > MAX_BURST_ALLOWANCE {
            return Err(AbuseDosConfigError::BurstAllowanceTooLarge(
                self.per_peer_burst_allowance,
            ));
        }

        // Connection-rate sanity — only enforced when the limiter is enabled.
        if self.connection_limiter_enabled {
            self.validate_connection_window(
                self.connection_rate_window,
                self.max_connections_per_window,
            )?;
            if self.connection_burst_allowance > MAX_CONNECTIONS_PER_WINDOW {
                return Err(AbuseDosConfigError::ConnectionsPerWindowTooLarge(
                    self.connection_burst_allowance,
                ));
            }
            if let Some(window) = self.per_address_rate_window {
                self.validate_connection_window(window, self.max_connections_per_address_window)?;
            }
        }

        Ok(())
    }

    fn validate_connection_window(
        &self,
        window: Duration,
        max_per_window: u64,
    ) -> Result<(), AbuseDosConfigError> {
        if window.is_zero() {
            return Err(AbuseDosConfigError::ZeroConnectionRateWindow);
        }
        if window.as_secs() > MAX_CONNECTION_WINDOW_SECS {
            return Err(AbuseDosConfigError::ConnectionRateWindowTooLarge(
                window.as_secs(),
            ));
        }
        if max_per_window == 0 {
            return Err(AbuseDosConfigError::ZeroConnectionsPerWindow);
        }
        if max_per_window > MAX_CONNECTIONS_PER_WINDOW {
            return Err(AbuseDosConfigError::ConnectionsPerWindowTooLarge(
                max_per_window,
            ));
        }
        Ok(())
    }

    /// Validate that this config is an accepted DevNet source/test profile.
    ///
    /// Combines [`Self::validate`] with a DevNet environment check.
    pub fn validate_devnet(&self) -> Result<(), AbuseDosConfigError> {
        if self.environment != NetworkEnvironment::Devnet {
            return Err(AbuseDosConfigError::WrongEnvironment(self.environment));
        }
        self.validate()
    }

    /// Enforce the optional genesis-hash binding against an expected value.
    ///
    /// - If no binding is set, this is a no-op success.
    /// - If a binding is set and matches, success.
    /// - If a binding is set and differs, [`AbuseDosConfigError::GenesisBindingMismatch`].
    pub fn check_genesis_binding(&self, expected: &[u8; 32]) -> Result<(), AbuseDosConfigError> {
        match self.genesis_hash {
            None => Ok(()),
            Some(bound) if &bound == expected => Ok(()),
            Some(_) => Err(AbuseDosConfigError::GenesisBindingMismatch),
        }
    }
}

// ============================================================================
// Connection-rate limiter boundary
// ============================================================================

/// Opaque remote-address key for the connection-rate limiter.
///
/// A pure/source-test representation of a remote peer or address; the runtime
/// would derive this from the accepted socket's peer address. It carries no
/// network capability and performs no I/O.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RemoteAddr(pub String);

impl RemoteAddr {
    /// Construct a remote-address key from any displayable value.
    pub fn new(addr: impl Into<String>) -> Self {
        Self(addr.into())
    }
}

/// Deterministic outcome of a connection-rate check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionDecision {
    /// The connection is within budget and would be accepted.
    ConnectionAllowed,
    /// The connection is over budget and would be rejected.
    ConnectionRateLimited,
    /// The connection limiter is disabled by config (no limiting applied).
    ConnectionLimiterDisabled,
    /// The config is invalid (limiter refuses to make a decision).
    InvalidConfig(AbuseDosConfigError),
    /// MainNet was requested without a production policy.
    MainNetRefused,
    /// Required limiter state was unavailable (fail-open/closed per config).
    StateUnavailable,
}

/// Internal token bucket for the connection-rate limiter.
///
/// Uses the same fractional-token refill semantics as the per-peer limiter, but
/// keyed by window duration rather than per-second so that operator-facing
/// "connections per window" maps directly onto refill.
#[derive(Debug, Clone)]
struct ConnTokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last_update: Instant,
}

impl ConnTokenBucket {
    fn new(max_per_window: u64, burst: u64, window: Duration, now: Instant) -> Self {
        let capacity = (max_per_window + burst) as f64;
        let window_secs = window.as_secs_f64();
        // window validated non-zero before construction.
        let refill_per_sec = max_per_window as f64 / window_secs;
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last_update: now,
        }
    }

    fn refill(&mut self, now: Instant) {
        let elapsed = now.saturating_duration_since(self.last_update).as_secs_f64();
        if elapsed > 0.0 {
            let add = elapsed * self.refill_per_sec;
            self.tokens = (self.tokens + add).min(self.capacity);
            self.last_update = now;
        }
    }

    fn try_consume(&mut self, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// Caller-owned fixture state for the connection-rate limiter.
///
/// The limiter writes **only** into this state; it never touches any global,
/// process-wide, or runtime state. This makes the boundary safe to exercise in
/// tests and to embed later behind a runtime-owned handle.
#[derive(Debug, Default)]
pub struct ConnectionRateLimiterState {
    /// Global inbound connection bucket (created on first use).
    global: Option<ConnTokenBucket>,
    /// Per-remote-address buckets (created on first use), only used when the
    /// config enables a per-address window.
    per_address: HashMap<RemoteAddr, ConnTokenBucket>,
}

impl ConnectionRateLimiterState {
    /// Create empty limiter state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of tracked remote addresses (testing/metrics).
    pub fn tracked_address_count(&self) -> usize {
        self.per_address.len()
    }

    /// Whether the global bucket has been initialized (testing).
    pub fn global_initialized(&self) -> bool {
        self.global.is_some()
    }
}

/// A pure, deterministic inbound connection-rate limiter.
///
/// The limiter owns an immutable, pre-validated [`AbuseDosConfig`] and operates
/// on caller-supplied [`ConnectionRateLimiterState`]. It performs no I/O and
/// makes no allocations outside the caller-owned state.
#[derive(Debug, Clone)]
pub struct ConnectionRateLimiter {
    config: AbuseDosConfig,
}

impl ConnectionRateLimiter {
    /// Construct a limiter from a config, validating it up front.
    ///
    /// Returns the offending [`AbuseDosConfigError`] if the config is invalid,
    /// so the runtime never installs a nonsensical limiter.
    pub fn new(config: AbuseDosConfig) -> Result<Self, AbuseDosConfigError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The config backing this limiter.
    pub fn config(&self) -> &AbuseDosConfig {
        &self.config
    }

    /// Decide whether an inbound connection from `remote` at `now` is within
    /// budget, updating only the caller-owned `state`.
    pub fn check(
        &self,
        state: &mut ConnectionRateLimiterState,
        remote: &RemoteAddr,
        now: Instant,
    ) -> ConnectionDecision {
        if self.config.environment == NetworkEnvironment::Mainnet {
            return ConnectionDecision::MainNetRefused;
        }
        if !self.config.connection_limiter_enabled {
            return ConnectionDecision::ConnectionLimiterDisabled;
        }
        // Re-validate defensively; a limiter is only constructed from a valid
        // config, but this keeps `check` total and self-describing.
        if let Err(e) = self.config.validate() {
            return ConnectionDecision::InvalidConfig(e);
        }

        // Global bucket first.
        let global = state.global.get_or_insert_with(|| {
            ConnTokenBucket::new(
                self.config.max_connections_per_window,
                self.config.connection_burst_allowance,
                self.config.connection_rate_window,
                now,
            )
        });
        if !global.try_consume(now) {
            return ConnectionDecision::ConnectionRateLimited;
        }

        // Optional per-address bucket.
        if let Some(window) = self.config.per_address_rate_window {
            let bucket = state.per_address.entry(remote.clone()).or_insert_with(|| {
                ConnTokenBucket::new(
                    self.config.max_connections_per_address_window,
                    0,
                    window,
                    now,
                )
            });
            if !bucket.try_consume(now) {
                return ConnectionDecision::ConnectionRateLimited;
            }
        }

        ConnectionDecision::ConnectionAllowed
    }
}

// ============================================================================
// Integration adapter shape (documentation-only for Run 361)
// ============================================================================

/// Adapter shape describing how `p2p_tcp` *would* consult the abuse/DoS config
/// and connection-rate limiter before accepting an inbound connection.
///
/// **Run 361 does not wire this into the live accept loop.** This function is a
/// pure decision helper that mirrors the intended call site so the shape can be
/// reviewed and tested without changing runtime behavior. A later run (Run 362
/// or beyond) is required to install it in [`crate::p2p_tcp`] behind a
/// runtime-owned [`ConnectionRateLimiter`] + [`ConnectionRateLimiterState`] and
/// to produce release-binary/runtime evidence.
///
/// Intended runtime call site (not wired here):
/// in the listener accept loop, after a TCP connection is accepted and before
/// the KEMTLS handshake begins, the runtime would call this with the remote
/// address; on [`ConnectionDecision::ConnectionRateLimited`] it would close the
/// socket early and increment a connection-rate-drop metric (see
/// [`connection_rate_metric_plan`]).
pub fn inbound_connection_adapter_shape(
    limiter: &ConnectionRateLimiter,
    state: &mut ConnectionRateLimiterState,
    remote: &RemoteAddr,
    now: Instant,
) -> ConnectionDecision {
    limiter.check(state, remote, now)
}

// ============================================================================
// Metrics surface plan (documentation-only for Run 361)
// ============================================================================

/// The metric name that a future run must register for connection-rate drops.
///
/// Run 361 **does not** register this metric (no metric is added without an
/// implemented + tested runtime call site). It is recorded here so the future
/// name is reserved and reviewed, and so tests can assert the plan is stable.
pub const PLANNED_CONNECTION_RATE_DROP_METRIC: &str = "qbind_p2p_connection_rate_drop_total";

/// Returns the authoritative existing metrics for the abuse/DoS surface and the
/// single planned-but-not-yet-registered metric for connection-rate drops.
///
/// The existing per-peer message-rate drop counters remain authoritative for
/// message-level abuse; the connection-rate drop metric is *planned only*.
pub fn connection_rate_metric_plan() -> (&'static [&'static str], &'static str) {
    const AUTHORITATIVE_EXISTING: &[&str] = &[
        // Per-peer inbound message-rate drops (authoritative today).
        "total_rate_limit_drops",
        // Peer disconnect / inbound counters (authoritative today).
        "consensus_net_peer_disconnect_total",
        "consensus_net_peer_inbound_total",
    ];
    (AUTHORITATIVE_EXISTING, PLANNED_CONNECTION_RATE_DROP_METRIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_preserves_runtime_defaults() {
        let cfg = AbuseDosConfig::default();
        assert_eq!(cfg.per_peer_max_messages_per_second, 1000);
        assert_eq!(cfg.per_peer_burst_allowance, 100);
        assert!(!cfg.connection_limiter_enabled);
        assert!(cfg.preserves_runtime_defaults());
        assert_eq!(cfg.fail_mode, FailMode::FailOpen);
    }

    #[test]
    fn default_validates() {
        assert!(AbuseDosConfig::default().validate().is_ok());
    }

    #[test]
    fn mainnet_refused() {
        let cfg = AbuseDosConfig::default().with_environment(NetworkEnvironment::Mainnet);
        assert_eq!(cfg.validate(), Err(AbuseDosConfigError::MainNetRefused));
    }
}