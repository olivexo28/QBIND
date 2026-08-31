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
| `QbindPerPeerRateLimitDropsSustained` | observe | `increase(qbind_net_per_peer_drops_total[5m]) > 0` for 10m | Sustained M12 per-peer message-rate drops (per-`peer` abuse). |
| `QbindNodeDiskSpaceLow` | ticket | `qbind_node_data_dir_free_bytes < 5368709120` for 15m | Data-dir free space below ~5 GiB (qbind-owned gauge, Run 381). |

**Coverage notes (honest):**

- *Node down / metrics endpoint down* → `QbindNodeDown` (via Prometheus `up`).
- *P2P listener unavailable* → **no dedicated listener-up metric exists**; it is
  covered indirectly by `QbindNodeNoP2PConnections` (+ `up`). A distinct
  listener-up signal is a future improvement.
- *Connection-rate drops sustained* → `QbindConnectionRateDropsSustained`
  (M12 connection-rate limiter, production-wired, Run 371 Green).
- *Per-peer message-rate drops sustained* → `QbindPerPeerRateLimitDropsSustained`
  (M12 per-peer limiter enforced over the deployed KEMTLS live socket, Runs
  371–373 Green; the series `qbind_net_per_peer_drops_total` is absent until the
  first per-peer drop and is proven present after an induced drop by Run 380).
- *Trust-bundle load/apply failures* → `QbindTrustBundleSignatureRejections` +
  `QbindTrustBundleSequencePersistFailure` (live-reload apply-failure counters
  also exist for future use).
- *Consensus no-progress* → `QbindConsensusNoProgress`.
- *Disk/storage issue* → `QbindNodeDiskSpaceLow` (**ENABLED**, Run 381) alerts on
  the qbind-owned `qbind_node_data_dir_free_bytes` gauge; `QbindSnapshotFailures`
  additionally proxies storage-subsystem health. Operators may still complement
  with node-exporter host metrics.
- *Node/build/chain identity* → `qbind_node_build_info` (Run 381) is a static
  low-cardinality info gauge (value `1`) for build/version/chain correlation; it
  is informational and has no alert.
- *High error/rejection counters* → trust-bundle + peer-candidate rejection rules.

## FUTURE / NOT ENABLED rules (metric absent from the baseline scrape)

These are shipped **disabled by intent** (`status: future`, severity `observe`)
in the `qbind-devnet-observability-future-not-enabled` group. They parse as YAML,
never fire until the underlying series exists, and must **not** be counted as
active coverage:

| Alert | Absent metric | Why future |
|---|---|---|
| `QbindStateSizeHigh` | `qbind_state_size_bytes` | The legacy estimated-state-size gauge exists in source but is **not** exported in the default release scrape (Run 379/380/381 confirm it absent). For qbind-owned free-space alerting use the ENABLED `QbindNodeDiskSpaceLow` rule (`qbind_node_data_dir_free_bytes`). |

> **Run 381 note:** `QbindNodeDiskSpaceLow` was promoted from the future group to
> the **enabled** rules above. It now references the qbind-owned
> `qbind_node_data_dir_free_bytes` gauge, which Run 381 proves present in a
> release-binary scrape when `--data-dir` is set. The future group now carries only
> the still-absent `qbind_state_size_bytes` legacy gauge (`QbindStateSizeHigh`).

> **Run 380 note:** `QbindPerPeerRateLimitDropsSustained` was promoted from this
> future group to the **enabled** rules above. Its metric
> `qbind_net_per_peer_drops_total` is absent in a clean scrape until a per-peer
> rate-limit drop occurs, but Runs 371–373 prove deployed KEMTLS live-socket
> enforcement and Run 380 provides release-binary scrape evidence that the series
> becomes present after an induced per-peer drop.

## Validation

Both YAML files parse cleanly and are checked by the Run 380 harness
(`scripts/devnet/run_380_public_devnet_observability_hardening.sh`), the earlier
Run 379 harness (`scripts/devnet/run_379_public_devnet_observability_baseline.sh`),
and [`VERIFY.md`](./VERIFY.md). If `promtool` is available, `promtool check rules`
and `promtool check config` may be run as an optional stronger check; the harness
uses a dependency-free Python YAML parse so it works without Prometheus installed.