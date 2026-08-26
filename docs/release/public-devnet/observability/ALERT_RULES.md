# QBIND Public DevNet — Alert Rules (M14)

The canonical machine-readable rules are
[`prometheus-alerts.example.yml`](./prometheus-alerts.example.yml). This document
explains each rule, its **severity**, and links to the operator response in
[`RUNBOOK.md`](./RUNBOOK.md). Response actions are in the runbook so this file
stays a single source of *what fires and how loud*.

## Severity levels

| Severity | Meaning | Response channel |
|---|---|---|
| **page** | Safety/liveness impacting. Wake a human now. | On-call page |
| **ticket** | Actionable but not an immediate page. | Ticket / next business action |
| **observe** | Informational; correlate, do not page. | Dashboard / evidence only |

## Enabled rules (metric verified present in the baseline scrape)

| Alert | Severity | Expression (summary) | Fires when |
|---|---|---|---|
| `QbindNodeDown` | page | `up{job="qbind-node"} == 0` for 2m | Node down / metrics endpoint down. |
| `QbindConsensusNoProgress` | page | `changes(qbind_consensus_committed_height[10m]) == 0` while up | Committed height not advancing 10m. |
| `QbindNodeNoP2PConnections` | ticket | `qbind_p2p_connections_current == 0` for 15m while up | Node isolated / P2P listener unreachable. |
| `QbindConnectionRateDropsSustained` | ticket | `increase(qbind_p2p_connection_rate_drop_total[15m]) > 0` for 15m | Sustained M12 connection-rate drops (flood/abuse). |
| `QbindTrustBundleSignatureRejections` | ticket | `increase(qbind_p2p_pqc_trust_bundle_signature_rejected_total[10m]) > 0` | Trust-bundle signature rejections. |
| `QbindTrustBundleSequencePersistFailure` | page | `increase(qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total[10m]) > 0` | Durable trust sequence unwritable. |
| `QbindSnapshotFailures` | ticket | `increase(qbind_snapshot_failure_total[1h]) > 0` | Snapshot/storage subsystem degraded. |
| `QbindRestoreCatchupStuck` | ticket | `qbind_restore_catchup_mode_active == 1` for 30m | Node stuck in catch-up. |
| `QbindPeerCandidateRejectionsHigh` | observe | `increase(qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total[15m]) > 0` for 15m | Peer-candidate rejections; correlate. |

**Coverage notes (honest):**

- *Node down / metrics endpoint down* → `QbindNodeDown` (via Prometheus `up`).
- *P2P listener unavailable* → **no dedicated listener-up metric exists**; it is
  covered indirectly by `QbindNodeNoP2PConnections` (+ `up`). A distinct
  listener-up signal is a future improvement.
- *Connection-rate drops sustained* → `QbindConnectionRateDropsSustained`
  (M12 connection-rate limiter, production-wired, Run 371 Green).
- *Trust-bundle load/apply failures* → `QbindTrustBundleSignatureRejections` +
  `QbindTrustBundleSequencePersistFailure` (live-reload apply-failure counters
  also exist for future use).
- *Consensus no-progress* → `QbindConsensusNoProgress`.
- *Disk/storage issue* → `QbindSnapshotFailures` proxies storage health; a true
  free-disk alert is **FUTURE** (see below).
- *High error/rejection counters* → trust-bundle + peer-candidate rejection rules.

## FUTURE / NOT ENABLED rules (metric absent from the baseline scrape)

These are shipped **disabled by intent** (`status: future`, severity `observe`)
in the `qbind-devnet-observability-future-not-enabled` group. They parse as YAML,
never fire until the underlying series exists, and must **not** be counted as
active coverage:

| Alert | Absent metric | Why future |
|---|---|---|
| `QbindPerPeerRateLimitDropsSustained` | `qbind_net_per_peer_drops_total` | Emitted per-peer only after a per-peer rate-limit drop; absent in the clean scrape; deployed per-peer message-rate override is construction-path-only (see `ABUSE_DOS_POSTURE.md`). |
| `QbindNodeDiskSpaceLow` | `qbind_state_size_bytes` (and no free-disk gauge) | Not present in the default scrape; do disk alerting via node-exporter (`node_filesystem_avail_bytes`). |

## Validation

Both YAML files parse cleanly and are checked by the Run 379 harness
(`scripts/devnet/run_379_public_devnet_observability_baseline.sh`) and
[`VERIFY.md`](./VERIFY.md). If `promtool` is available, `promtool check rules`
and `promtool check config` may be run as an optional stronger check; the harness
uses a dependency-free Python YAML parse so it works without Prometheus installed.
