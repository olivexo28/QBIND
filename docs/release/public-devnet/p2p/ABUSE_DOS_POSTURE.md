# QBIND Public DevNet — Abuse / DoS Posture (Run 360)

> **Safety label:** experimental · resettable · no value · no MainNet readiness claim · no C4/C5
> closure claim.

This document describes the **abuse / DoS posture** for QBIND public DevNet against the **existing**
source surfaces (`crates/qbind-node/src/peer_rate_limiter.rs`, `metrics.rs`, `p2p_tcp.rs`). Run 360
changes **no** rate-limiter implementation, adds **no** CLI flag, and invents **no** threshold. Where
a configurable production threshold does not exist, that gap is recorded honestly (see §7).

## 1. Existing peer rate-limiter surface

The node ships a **per-peer inbound message rate limiter** implemented in
`crates/qbind-node/src/peer_rate_limiter.rs`:

- **Type:** `PeerRateLimiter` with `PeerRateLimiterConfig { max_messages_per_second, burst_allowance }`.
- **Algorithm:** a sharded token bucket per peer. Bucket capacity =
  `max_messages_per_second + burst_allowance`; refill rate = `max_messages_per_second` tokens/sec;
  each admitted message consumes one token, and a peer over budget has its message **dropped** (the
  connection itself is not torn down by the limiter).
- **Sharding:** peers are sharded across `NUM_SHARDS = 16` for concurrency.
- **Scope:** it limits **inbound consensus message rate per peer**. It is a message-rate control, not
  a connection-admission control.

## 2. Current defaults

The rate limiter is constructed with hardcoded defaults (`peer_rate_limiter.rs`):

| Constant | Value | Meaning |
|----------|-------|---------|
| `DEFAULT_MAX_MESSAGES_PER_SECOND` | `1000` | Sustained inbound messages/sec per peer. |
| `DEFAULT_BURST_ALLOWANCE` | `100` | Extra token-bucket capacity for short bursts (epoch transitions, view changes). |
| `NUM_SHARDS` | `16` | Peer shard count. |

The source rationale: for a ~100-validator network at ~10 rounds/sec, legitimate aggregate traffic is
on the order of ~1000 msgs/sec (~10/s per peer); the 1000/s per-peer limit is deliberately
conservative (high) to avoid false positives while still catching abusive floods.

## 3. What is enabled by default vs configurable

- **Enabled by default:** the per-peer rate limiter is active — the node uses
  `PeerRateLimiter::with_defaults()`, so the `1000` msg/s + `100` burst posture applies without any
  operator action.
- **Not operator-configurable via CLI:** the thresholds are **hardcoded constants**. There is **no**
  `qbind-node` CLI flag (and no documented config-file key in `qbind-node --help`) to change
  `max_messages_per_second` or `burst_allowance`. An operator cannot retune them without a source
  change, which is out of scope for Run 360.
- **Failure mode:** the limiter fails **open** on internal lock poisoning (it returns "allow") — it
  is a best-effort abuse control, not a hard security boundary.

## 4. Connection / handshake surfaces

- **P2P disabled by default:** `--enable-p2p` defaults to `false`, so a default node accepts **no**
  inbound connections at all (strongest default DoS posture).
- **Peer tracking cap:** metrics track at most `MAX_TRACKED_PEERS = 128` distinct peers
  (`metrics.rs`); this bounds per-peer metric memory, not connection count.
- **Admission is fail-closed:** untrusted/malformed/wrong-genesis peers are rejected at the KEMTLS
  handshake / trust-bundle load (see `PEER_ADMISSION_POLICY.md` §7), so malformed peers are dropped
  before consuming consensus resources.
- **Dial retry policy:** outbound dials to `--p2p-peer` use a retry policy in `p2p_tcp.rs`; operators
  should avoid configuring unreachable static peers to prevent avoidable outbound dial loops.

## 5. Metrics / logs operators should watch

Exact metric/counter surfaces (`crates/qbind-node/src/metrics.rs`):

- **Rate-limit drops (primary abuse signal):**
  - per-peer `rate_limit_drop` counter (`inc_rate_limit_drop`, `peer_rate_limit_drop_count`);
  - aggregate `total_rate_limit_drops()`.
- **Per-peer disconnects:** `consensus_net_peer_disconnect_total{peer,reason="eof|error|shutdown"}`.
- **Per-peer inbound volume:** `consensus_net_peer_inbound_total{peer,kind="vote|proposal|other"}`.
- **Outbound drops:** `consensus_net_peer_outbound_drop_total{peer}`,
  `consensus_net_outbound_dropped_total{priority}`.
- **Trust-bundle / handshake health:**
  `qbind_p2p_pqc_trust_bundle_loaded`, `qbind_p2p_pqc_trust_bundle_environment`,
  `qbind_p2p_pqc_trust_bundle_active_roots`, `qbind_p2p_pqc_trust_bundle_revoked_roots`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total`,
  `qbind_p2p_pqc_trust_bundle_signature_rejected_total`,
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`.

See the monitoring baseline (`docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md`) and the PQC trust
lifecycle runbook (`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`) for alerting guidance.

## 6. Minimum public DevNet recommended posture

For a future public DevNet seed exposure, the minimum recommended posture is:

- **Inbound connection rate:** keep `--p2p-mutual-auth required` so unauthenticated inbound peers are
  rejected at the handshake; front the public port with host-level firewalling appropriate to the
  advertised port. (No per-connection-rate CLI knob exists in `qbind-node`; enforce at the host/LB
  layer.)
- **Outbound dial failure loops:** configure only reachable `--p2p-peer` entries (only `status:
  "live"` seed-list entries); never dial placeholder/non-routable hosts. Watch
  `consensus_net_peer_disconnect_total{reason="error"}` for repeated failures.
- **Malformed peer traffic:** rely on fail-closed admission (untrusted/malformed peers rejected at
  handshake); alert on spikes in disconnects with `reason="error"`.
- **Handshake failures:** alert on rising trust-bundle signature rejections
  (`qbind_p2p_pqc_trust_bundle_signature_rejected_total`) and disconnect-error rates.
- **Trust-bundle validation failures:** alert on `qbind_p2p_pqc_trust_bundle_signature_rejected_total`
  and `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`; treat sustained rejection as a
  possible poisoning attempt.
- **Per-peer message floods:** watch per-peer `rate_limit_drop` / `total_rate_limit_drops()`; the
  default `1000` msg/s + `100` burst limit applies automatically per peer.
- **Peer-candidate propagation limits:** peer claims are advisory only and do not bypass ratification
  (see `PEER_ADMISSION_POLICY.md` §8); there is no operator-tunable propagation-limit CLI knob, so
  monitor rather than retune.
- **Log volume / storage hygiene:** rate-limit drops and repeated handshake failures can inflate log
  volume under abuse; rotate/cap logs and provision disk for the exposed period. Never log secret
  key material (KEM secret keys are never logged by design).

## 7. What this run does NOT implement

- Run 360 implements **no** new rate-limiter, connection-rate limiter, or DoS control, and adds **no**
  configurable threshold. It documents the **existing** per-peer message rate limiter and metrics
  only.
- **Gap (kept honest):** the per-peer rate-limiter thresholds are **hardcoded** and there is **no**
  operator-facing CLI/config surface to tune them, and there is **no** per-connection-rate or global
  inbound-connection-rate limiter exposed in `qbind-node`. Because the abuse/DoS surface is real and
  documented but the key thresholds are **not operator-configurable** and connection-rate limiting
  must be enforced externally, **M12 remains Yellow/Partial** — see
  `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`.

## 8. Future work required before TestNet

Before a public TestNet, at minimum:

- Expose operator-configurable rate-limiter thresholds (or document a supported config surface).
- Add per-connection and global inbound-connection-rate limiting at the node layer.
- Publish tuned thresholds validated under real inbound load, with alerting wired to the metrics in
  §5.

None of this is claimed complete by Run 360; this document publishes posture and records the gap.