//! Run 362 — Public DevNet abuse/DoS runtime wiring.
//!
//! # Scope
//!
//! Run 361 introduced a pure, source/test-only abuse/DoS config model and a
//! bounded inbound connection-rate limiter boundary in
//! [`crate::public_devnet_abuse_dos_config`]. It did **not** wire the limiter
//! into the live runtime, did **not** own any limiter state, and did **not**
//! provide a metric or operator surface.
//!
//! Run 362 provides the **runtime-owned** holder that composes the Run 361
//! model and can be installed into the P2P accept path without any global
//! mutable state:
//!
//! - [`PublicDevnetAbuseDosRuntimeConfig`] — a validated, operator-facing
//!   config wrapper. Its [`disabled_default`](PublicDevnetAbuseDosRuntimeConfig::disabled_default)
//!   preserves current behavior exactly (per-peer `1000` msg/s + `100` burst,
//!   connection limiter disabled). Any enabled profile must pass
//!   [`AbuseDosConfig::validate`] before a runtime state can be built, so a
//!   nonsensical config fails **closed** at construction.
//! - [`PublicDevnetAbuseDosRuntimeState`] — owns the immutable
//!   [`ConnectionRateLimiter`] and the mutable
//!   [`ConnectionRateLimiterState`] behind a runtime-owned `Mutex` (never
//!   test-only caller state, never a global), plus bounded drop/allow
//!   counters and an optional [`P2pMetrics`] handle used to bump the
//!   registered `qbind_p2p_connection_rate_drop_total` counter on refusal.
//!
//! # Safety / non-goals
//!
//! - The default profile leaves the connection limiter **disabled**, so the
//!   accept loop is bit-for-bit unchanged unless the operator explicitly
//!   enables and configures the limiter.
//! - A refusal only closes the inbound socket early: it never admits a peer,
//!   never mutates trust state, never writes any sequence/marker file, and
//!   never bypasses KEMTLS / trust-bundle / genesis checks for admitted
//!   connections (those run unchanged on connections the limiter allows).
//! - MainNet is refused: an enabled MainNet config never validates (Run 361),
//!   and [`PublicDevnetAbuseDosRuntimeState::check_inbound`] returns
//!   [`ConnectionDecision::MainNetRefused`] defensively.
//! - Lock poisoning recovers into the inner state (fail-open, matching the
//!   existing per-peer limiter posture) so a poisoned lock never panics the
//!   accept loop and never spuriously refuses a connection.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use crate::metrics::P2pMetrics;
use crate::public_devnet_abuse_dos_config::{
    AbuseDosConfig, AbuseDosConfigError, ConnectionDecision, ConnectionRateLimiter,
    ConnectionRateLimiterState, RemoteAddr,
};

/// Operator-facing, validated runtime config wrapper for the public DevNet
/// abuse/DoS posture.
///
/// Construction never mutates any runtime state. An enabled config is validated
/// up front so the runtime never installs a nonsensical limiter.
#[derive(Debug, Clone)]
pub struct PublicDevnetAbuseDosRuntimeConfig {
    config: AbuseDosConfig,
}

impl PublicDevnetAbuseDosRuntimeConfig {
    /// The safe compatibility default: preserves current runtime behavior
    /// exactly (per-peer `1000` msg/s + `100` burst, connection limiter
    /// disabled). Installing a runtime state built from this changes nothing at
    /// runtime.
    pub fn disabled_default() -> Self {
        Self {
            config: AbuseDosConfig::compatibility_default(),
        }
    }

    /// Wrap an operator-supplied [`AbuseDosConfig`], validating it up front.
    ///
    /// Returns the offending [`AbuseDosConfigError`] (fail-closed) if the config
    /// is invalid, so an over-budget/zero/unbounded/wrong-environment/MainNet
    /// config can never become a runtime state.
    pub fn from_config(config: AbuseDosConfig) -> Result<Self, AbuseDosConfigError> {
        config.validate()?;
        Ok(Self { config })
    }

    /// The backing config.
    pub fn config(&self) -> &AbuseDosConfig {
        &self.config
    }

    /// Whether the global inbound connection-rate limiter is enabled.
    pub fn connection_limiter_enabled(&self) -> bool {
        self.config.connection_limiter_enabled
    }

    /// Whether this config preserves the current hardcoded per-peer runtime
    /// defaults and leaves the connection limiter disabled.
    pub fn preserves_runtime_defaults(&self) -> bool {
        self.config.preserves_runtime_defaults()
    }

    /// Build the runtime-owned state from this config, optionally wiring the
    /// registered connection-rate-drop metric.
    ///
    /// The config is re-validated defensively; a runtime state is only ever
    /// built from a valid config.
    pub fn into_runtime_state(
        self,
        metrics: Option<Arc<P2pMetrics>>,
    ) -> Result<PublicDevnetAbuseDosRuntimeState, AbuseDosConfigError> {
        let limiter = ConnectionRateLimiter::new(self.config)?;
        Ok(PublicDevnetAbuseDosRuntimeState {
            limiter,
            state: Mutex::new(ConnectionRateLimiterState::new()),
            drop_count: AtomicU64::new(0),
            allow_count: AtomicU64::new(0),
            metrics,
        })
    }
}

impl Default for PublicDevnetAbuseDosRuntimeConfig {
    fn default() -> Self {
        Self::disabled_default()
    }
}

/// Runtime-owned abuse/DoS state installed into the P2P accept path.
///
/// Owns the immutable [`ConnectionRateLimiter`] and the mutable
/// [`ConnectionRateLimiterState`]. All limiter mutation happens through this
/// handle's `Mutex`; no global or process-wide state is used.
#[derive(Debug)]
pub struct PublicDevnetAbuseDosRuntimeState {
    limiter: ConnectionRateLimiter,
    state: Mutex<ConnectionRateLimiterState>,
    drop_count: AtomicU64,
    allow_count: AtomicU64,
    metrics: Option<Arc<P2pMetrics>>,
}

impl PublicDevnetAbuseDosRuntimeState {
    /// The config backing the installed limiter.
    pub fn config(&self) -> &AbuseDosConfig {
        self.limiter.config()
    }

    /// Whether the global inbound connection-rate limiter is enabled.
    pub fn connection_limiter_enabled(&self) -> bool {
        self.limiter.config().connection_limiter_enabled
    }

    /// Number of inbound connections refused by the connection-rate limiter.
    pub fn drop_count(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }

    /// Number of inbound connections allowed to proceed (or observed while the
    /// limiter is disabled).
    pub fn allow_count(&self) -> u64 {
        self.allow_count.load(Ordering::Relaxed)
    }

    /// Decide whether an inbound connection from `remote` at `now` is within
    /// budget, updating only this runtime-owned state.
    ///
    /// On [`ConnectionDecision::ConnectionRateLimited`] the bounded drop counter
    /// is incremented and, if a [`P2pMetrics`] handle is installed, the
    /// registered `qbind_p2p_connection_rate_drop_total` counter is bumped. No
    /// other decision touches the metric.
    pub fn check_inbound(&self, remote: SocketAddr, now: Instant) -> ConnectionDecision {
        // `SocketAddr::to_string` never panics on any valid parsed remote
        // address; the runtime only ever passes an accepted peer address here.
        let key = RemoteAddr::new(remote.to_string());
        let decision = {
            // Recover into the inner state on poisoning (fail-open, matching the
            // existing per-peer limiter posture) so the accept loop never
            // panics and never spuriously refuses a connection.
            let mut guard = self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            self.limiter.check(&mut guard, &key, now)
        };
        match &decision {
            ConnectionDecision::ConnectionRateLimited => {
                self.drop_count.fetch_add(1, Ordering::Relaxed);
                if let Some(metrics) = &self.metrics {
                    metrics.record_connection_rate_drop();
                }
            }
            ConnectionDecision::ConnectionAllowed
            | ConnectionDecision::ConnectionLimiterDisabled => {
                self.allow_count.fetch_add(1, Ordering::Relaxed);
            }
            // Invalid/MainNet/StateUnavailable: do not count as allow or drop.
            _ => {}
        }
        decision
    }

    /// Whether an inbound connection should be admitted to normal peer
    /// admission. Only an explicit
    /// [`ConnectionDecision::ConnectionRateLimited`] refuses; every other
    /// outcome (allowed, disabled, or a defensive non-decision) admits so the
    /// unchanged KEMTLS / trust-bundle / genesis path runs.
    pub fn should_admit(&self, remote: SocketAddr, now: Instant) -> bool {
        !matches!(
            self.check_inbound(remote, now),
            ConnectionDecision::ConnectionRateLimited
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::public_devnet_abuse_dos_config::AbuseDosProfile;
    use qbind_types::primitives::NetworkEnvironment;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn remote(port: u16) -> SocketAddr {
        // RFC 5737 TEST-NET-1 documentation address; never a live endpoint.
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)), port)
    }

    #[test]
    fn disabled_default_preserves_behavior() {
        let cfg = PublicDevnetAbuseDosRuntimeConfig::disabled_default();
        assert!(!cfg.connection_limiter_enabled());
        assert!(cfg.preserves_runtime_defaults());
        let state = cfg.into_runtime_state(None).unwrap();
        assert!(!state.connection_limiter_enabled());
        // Disabled limiter never refuses.
        let now = Instant::now();
        assert!(state.should_admit(remote(1), now));
        assert_eq!(
            state.check_inbound(remote(2), now),
            ConnectionDecision::ConnectionLimiterDisabled
        );
        assert_eq!(state.drop_count(), 0);
    }

    #[test]
    fn enabled_profile_refuses_over_budget() {
        let cfg =
            PublicDevnetAbuseDosRuntimeConfig::from_config(AbuseDosConfig::public_devnet_recommended())
                .unwrap();
        assert!(cfg.connection_limiter_enabled());
        assert_eq!(cfg.config().profile, AbuseDosProfile::PublicDevnetRecommended);
        let state = cfg.into_runtime_state(None).unwrap();
        // Capacity = max_per_window (20) + burst (10) = 30 global tokens at t0.
        let now = Instant::now();
        let mut allowed = 0u64;
        for i in 0..30 {
            if state.should_admit(remote(i), now) {
                allowed += 1;
            }
        }
        assert_eq!(allowed, 30);
        assert_eq!(state.drop_count(), 0);
        // The 31st is over the global budget within the same instant.
        assert_eq!(
            state.check_inbound(remote(999), now),
            ConnectionDecision::ConnectionRateLimited
        );
        assert_eq!(state.drop_count(), 1);
    }

    #[test]
    fn invalid_config_fails_closed() {
        // Enabled limiter with a zero window is nonsensical -> refused at build.
        let mut bad = AbuseDosConfig::public_devnet_recommended();
        bad.connection_rate_window = Duration::from_secs(0);
        assert!(PublicDevnetAbuseDosRuntimeConfig::from_config(bad).is_err());
    }

    #[test]
    fn mainnet_refused() {
        let cfg = AbuseDosConfig::default().with_environment(NetworkEnvironment::Mainnet);
        assert!(matches!(
            PublicDevnetAbuseDosRuntimeConfig::from_config(cfg),
            Err(AbuseDosConfigError::MainNetRefused)
        ));
    }

    #[test]
    fn metric_increments_on_refusal_only() {
        let metrics = Arc::new(P2pMetrics::new());
        let mut cfg = AbuseDosConfig::public_devnet_recommended();
        // Tighten to a single global token so the second attempt refuses.
        cfg.max_connections_per_window = 1;
        cfg.connection_burst_allowance = 0;
        cfg.per_address_rate_window = None;
        let state = PublicDevnetAbuseDosRuntimeConfig::from_config(cfg)
            .unwrap()
            .into_runtime_state(Some(Arc::clone(&metrics)))
            .unwrap();
        let now = Instant::now();
        assert!(state.should_admit(remote(1), now));
        assert_eq!(metrics.connection_rate_drop_total(), 0);
        assert!(!state.should_admit(remote(2), now));
        assert_eq!(metrics.connection_rate_drop_total(), 1);
    }
}