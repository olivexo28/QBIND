//! Run 369 — Deployed inbound per-peer message-rate limiter adapter.
//!
//! # Scope
//!
//! Run 363 built a live [`PeerRateLimiter`] from the validated per-peer
//! thresholds carried by [`PublicDevnetAbuseDosRuntimeConfig`], and Run 365
//! threaded that config into the deployed `AsyncPeerManagerImpl` construction
//! path. However, the *deployed* `qbind-node` inbound receive path is **not**
//! `AsyncPeerManagerImpl` — that type is never spawned by `main.rs`. The
//! deployed inbound path is:
//!
//! ```text
//! TcpKemTlsP2pService::read_loop (per-peer NodeId known)
//!     → inbound_tx → subscribe() → P2pInboundDemuxer → handlers
//! ```
//!
//! Before Run 369 that path never consulted [`PeerRateLimiter`], so the
//! per-peer message-rate posture never actually protected the deployed
//! transport (Run 368 proved it only at the `AsyncPeerManagerImpl` layer).
//!
//! Run 369 provides [`DeployedInboundPerPeerLimiter`], a thin adapter that:
//!
//! - wraps a [`PeerRateLimiter`] built from the same validated
//!   [`PeerRateLimiterConfig`] the deployed builder already derives from
//!   `CliArgs` / [`PublicDevnetAbuseDosRuntimeConfig`] / `P2pNodeBuilder`
//!   (defaulting to the documented `1000` msg/s + `100` burst posture);
//! - evaluates the rate limit for an inbound frame **before** it is handed to
//!   the demuxer / handlers, keyed by the connection's `NodeId`;
//! - drops an over-budget frame, increments a self-contained bounded per-peer
//!   drop counter, and (if a [`NodeMetrics`] handle is installed) bumps the
//!   existing `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter;
//! - never touches the connection-rate limiter or its
//!   `qbind_p2p_connection_rate_drop_total` metric.
//!
//! # Peer keying (honest limitation)
//!
//! The rate-limiter buckets are keyed by [`PeerId`], a `u64`. The deployed
//! transport's stable per-connection identity is a 32-byte [`NodeId`] (M7:
//! derived from the peer's KEM public key on outbound connections; on the
//! listener side it may still be a temporary session-unique value until B8
//! identity binding resolves it). [`DeployedInboundPerPeerLimiter`] derives the
//! bucket key deterministically from the first 8 bytes of the `NodeId`
//! (big-endian). This derivation is used **solely** to select a rate-limiting
//! token bucket. It is **not** an identity or authentication claim, is never
//! persisted, and never feeds peer admission, trust-bundle validation, or any
//! consensus/authority decision. Two distinct `NodeId`s that happen to share
//! their first 8 bytes would share a bucket; this is acceptable for coarse
//! abuse/DoS rate limiting and is documented honestly here rather than being
//! presented as a peer identity.
//!
//! # Fail-open
//!
//! The adapter inherits [`PeerRateLimiter`]'s fail-open posture: any internal
//! error inside the limiter causes the frame to be *allowed* rather than
//! dropped, so a transient limiter fault never silently blackholes traffic.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;

use crate::metrics::NodeMetrics;
use crate::p2p::NodeId;
use crate::peer::PeerId;
use crate::peer_rate_limiter::{PeerRateLimiter, PeerRateLimiterConfig};
use crate::public_devnet_abuse_dos_runtime::PublicDevnetAbuseDosRuntimeConfig;

/// Deployed inbound per-peer message-rate limiter adapter.
///
/// Installed on [`crate::p2p_tcp::TcpKemTlsP2pService`] and consulted by the
/// per-peer read loop before an inbound frame is forwarded to the demuxer.
pub struct DeployedInboundPerPeerLimiter {
    /// The underlying token-bucket rate limiter (per bucket key).
    limiter: PeerRateLimiter,
    /// Self-contained bounded count of frames dropped by this adapter.
    ///
    /// This is always available (independent of whether a [`NodeMetrics`]
    /// handle is installed), so the deployed drop path is observable at the
    /// source/test level even on the builder path that only carries a
    /// `P2pMetrics` handle.
    drops: AtomicU64,
    /// Optional shared node metrics used to bump the existing per-peer
    /// `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter. Never a
    /// connection-rate metric.
    metrics: Option<Arc<NodeMetrics>>,
}

impl std::fmt::Debug for DeployedInboundPerPeerLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeployedInboundPerPeerLimiter")
            .field("config", self.limiter.config())
            .field("drops", &self.drops.load(Ordering::Relaxed))
            .field("has_metrics", &self.metrics.is_some())
            .finish()
    }
}

impl DeployedInboundPerPeerLimiter {
    /// Build an adapter from an explicit validated [`PeerRateLimiterConfig`].
    pub fn new(config: PeerRateLimiterConfig, metrics: Option<Arc<NodeMetrics>>) -> Self {
        Self {
            limiter: PeerRateLimiter::new(config),
            drops: AtomicU64::new(0),
            metrics,
        }
    }

    /// Build an adapter with the documented default posture
    /// (`1000` msg/s + `100` burst), matching
    /// [`PeerRateLimiter::with_defaults`].
    pub fn with_defaults(metrics: Option<Arc<NodeMetrics>>) -> Self {
        Self::new(PeerRateLimiterConfig::default(), metrics)
    }

    /// Build an adapter from an optional deployed per-peer override.
    ///
    /// - `None` → the documented default posture (`1000` msg/s + `100` burst),
    ///   bit-for-bit matching [`PeerRateLimiter::with_defaults`];
    /// - `Some(cfg)` → the validated override (Run 362/363 guarantees the
    ///   config is non-zero and bounded).
    ///
    /// This is the seam through which
    /// [`crate::p2p_node_builder::P2pNodeBuilder::deployed_peer_rate_limiter_config`]
    /// reaches the deployed inbound receive path.
    pub fn from_optional_config(
        config: Option<PeerRateLimiterConfig>,
        metrics: Option<Arc<NodeMetrics>>,
    ) -> Self {
        match config {
            Some(cfg) => Self::new(cfg, metrics),
            None => Self::with_defaults(metrics),
        }
    }

    /// Build an adapter directly from a validated runtime config, using its
    /// derived per-peer [`PeerRateLimiterConfig`].
    pub fn from_runtime_config(
        config: &PublicDevnetAbuseDosRuntimeConfig,
        metrics: Option<Arc<NodeMetrics>>,
    ) -> Self {
        Self::new(config.peer_rate_limiter_config(), metrics)
    }

    /// The effective per-peer configuration this adapter enforces.
    pub fn config(&self) -> &PeerRateLimiterConfig {
        self.limiter.config()
    }

    /// Total frames dropped by this adapter (self-contained bounded counter).
    pub fn drop_count(&self) -> u64 {
        self.drops.load(Ordering::Relaxed)
    }

    /// Whether a shared [`NodeMetrics`] handle is installed.
    pub fn has_metrics(&self) -> bool {
        self.metrics.is_some()
    }

    /// Derive the rate-limiting bucket key for a connection `NodeId`.
    ///
    /// See the module-level "Peer keying" note: this is a coarse bucket
    /// selector, **not** an identity/authentication claim. It reads the first
    /// 8 bytes of the 32-byte `NodeId` as a big-endian `u64`.
    pub fn bucket_key(node_id: &NodeId) -> PeerId {
        let bytes = node_id.as_bytes();
        let mut key = [0u8; 8];
        key.copy_from_slice(&bytes[..8]);
        PeerId(u64::from_be_bytes(key))
    }

    /// Check whether an inbound frame from `node_id` at `now` is within budget.
    ///
    /// Returns `true` if the frame should be forwarded to the demuxer/handlers,
    /// `false` if it should be dropped. On a drop the self-contained counter is
    /// incremented and, if installed, the shared per-peer rate-limit metric is
    /// bumped. The connection-rate metric is never touched.
    pub fn allow_node(&self, node_id: &NodeId, now: Instant) -> bool {
        let key = Self::bucket_key(node_id);
        self.allow_key(key, now)
    }

    /// Lower-level check keyed directly by bucket [`PeerId`] (test seam).
    pub fn allow_key(&self, key: PeerId, now: Instant) -> bool {
        if self.limiter.allow(&key, now) {
            true
        } else {
            self.drops.fetch_add(1, Ordering::Relaxed);
            if let Some(metrics) = &self.metrics {
                metrics.peer_network().inc_rate_limit_drop(key);
            }
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer_rate_limiter::{DEFAULT_BURST_ALLOWANCE, DEFAULT_MAX_MESSAGES_PER_SECOND};

    fn node(seed: u8) -> NodeId {
        let mut bytes = [0u8; 32];
        bytes[0] = seed;
        NodeId::new(bytes)
    }

    #[test]
    fn defaults_are_1000_100() {
        let adapter = DeployedInboundPerPeerLimiter::with_defaults(None);
        assert_eq!(
            adapter.config().max_messages_per_second,
            DEFAULT_MAX_MESSAGES_PER_SECOND
        );
        assert_eq!(adapter.config().burst_allowance, DEFAULT_BURST_ALLOWANCE);
    }

    #[test]
    fn from_optional_none_matches_defaults() {
        let adapter = DeployedInboundPerPeerLimiter::from_optional_config(None, None);
        assert_eq!(adapter.config().max_messages_per_second, 1000);
        assert_eq!(adapter.config().burst_allowance, 100);
    }

    #[test]
    fn over_budget_drops_and_counts() {
        let adapter = DeployedInboundPerPeerLimiter::new(
            PeerRateLimiterConfig::new(5, 0),
            None,
        );
        let now = Instant::now();
        let n = node(7);
        for _ in 0..5 {
            assert!(adapter.allow_node(&n, now));
        }
        assert!(!adapter.allow_node(&n, now));
        assert_eq!(adapter.drop_count(), 1);
    }

    #[test]
    fn metrics_counter_increments_on_drop() {
        let metrics = Arc::new(NodeMetrics::new());
        let adapter = DeployedInboundPerPeerLimiter::new(
            PeerRateLimiterConfig::new(1, 0),
            Some(Arc::clone(&metrics)),
        );
        let now = Instant::now();
        let n = node(3);
        assert!(adapter.allow_node(&n, now));
        assert!(!adapter.allow_node(&n, now));
        assert_eq!(metrics.peer_network().total_rate_limit_drops(), 1);
    }

    #[test]
    fn bucket_key_is_deterministic_first_8_bytes() {
        let mut bytes = [0u8; 32];
        bytes[..8].copy_from_slice(&[0, 0, 0, 0, 0, 0, 0, 9]);
        let n = NodeId::new(bytes);
        assert_eq!(DeployedInboundPerPeerLimiter::bucket_key(&n), PeerId(9));
    }
}