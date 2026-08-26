# QBIND Public DevNet — Metrics Families (M13)

All names below were **verified by scraping the release `qbind-node` binary**
(`cargo build -p qbind-node --release`) over loopback with
`QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>`; see [`VERIFY.md`](./VERIFY.md) and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`. No metric name is invented: every
name is present in `crates/qbind-node/src/metrics.rs` **and** was observed in a
live scrape, except where explicitly marked *absent* or *conditional*.

## 0. Endpoint & format

- Exposition format: Prometheus text (`Content-Type: text/plain; version=0.0.4`).
- The output is bare `name value` / `name{labels} value` lines grouped under
  `# <section>` comment headers. It does **not** emit `# TYPE` / `# HELP` lines;
  do not write alert expressions that depend on `HELP`/`TYPE` metadata.
- Only the default `NodeMetrics` surface is served (main.rs passes an empty
  `CryptoMetricsRefs`), so PQC signature-suite / KEMTLS-handshake / DAG-mempool
  crypto sub-metrics are **not** in the default `/metrics` and are **absent** for
  public DevNet operators unless a future run wires them in.

## 1. Node liveness / progress (REQUIRED for launch operations)

The single most important liveness signal is **whether the scrape succeeds at
all** — Prometheus synthesizes an `up` series per target (`up == 1` when the
node's `/metrics` answered). Beyond `up`, these observed families prove the node
is making consensus progress:

| Metric | Type | Meaning |
|---|---|---|
| `qbind_consensus_committed_height` | gauge | Height of the last committed block. Should advance over time. |
| `qbind_consensus_current_view` | gauge | Current HotStuff view. |
| `qbind_consensus_view_number` | gauge | View number (progress signal). |
| `qbind_consensus_qcs_formed_total` | counter | Quorum certificates formed (progress). |
| `consensus_runtime_ticks_per_second` | gauge | Consensus runtime tick rate. |
| `consensus_events_total{kind="tick"}` | counter | Consensus loop ticks (liveness). |

> There is **no** dedicated `qbind_node_up` / `qbind_build_env` / `qbind_chain_id`
> gauge in the default scrape. Node liveness is inferred from Prometheus `up` plus
> `increase(qbind_consensus_committed_height)` / tick progress. This is documented
> honestly rather than inventing an info gauge.

## 2. P2P networking, incl. M12 abuse/DoS drop counters (REQUIRED)

| Metric | Type | Meaning |
|---|---|---|
| `qbind_p2p_connections_current` | gauge | Current live P2P connections. |
| `qbind_p2p_inbound_peers` / `qbind_p2p_outbound_peers` | gauge | Peer counts by direction. |
| `qbind_p2p_known_peers` | gauge | Peers in the peer store. |
| `qbind_p2p_connection_rate_drop_total` | counter | **M12 connection-rate limiter** drops. Production-wired on the deployed socket (Run 371 Green). |
| `qbind_p2p_bytes_received_total` / `qbind_p2p_bytes_sent_total` | counter | Byte throughput. |
| `qbind_p2p_messages_received_total` / `qbind_p2p_messages_sent_total` | counter | Message throughput. |
| `qbind_p2p_heartbeat_timeout_total` / `qbind_p2p_heartbeat_failed_total` | counter | Heartbeat failures. |
| `qbind_p2p_peer_evicted_total` | counter | Peer evictions. |
| `qbind_p2p_peer_rejected_diversity_total` / `qbind_p2p_diversity_violation_total` | counter | Diversity-policy rejections. |
| `qbind_p2p_session_eviction_*_total` | counter | Session eviction outcomes. |

**Per-peer rate-limit drops — `qbind_net_per_peer_drops_total{peer,reason="rate_limit"}`
(CONDITIONAL / effectively FUTURE for alerting).** This series is emitted by the
release binary **only after a per-peer rate-limit drop has occurred**
(`metrics.rs` renders it per-peer guarded by `rate_limit_drop > 0`) and it was
**absent from the clean baseline scrape**. It is also consistent with the M12
posture that the per-peer *message-rate* override is construction-path-only on the
deployed node (see `ABUSE_DOS_POSTURE.md`). Alert rules on this series are marked
**FUTURE / not enabled** in [`ALERT_RULES.md`](./ALERT_RULES.md) because the series
is absent until the first drop.

## 3. PQC trust-bundle & peer-candidate propagation (REQUIRED)

Observed families (all present in the baseline scrape):

- Load / activation state: `qbind_p2p_pqc_trust_bundle_loaded`,
  `qbind_p2p_pqc_trust_bundle_active_roots`,
  `qbind_p2p_pqc_trust_bundle_activation_rejected_total`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total`,
  `qbind_p2p_pqc_trust_bundle_signature_rejected_total`,
  `qbind_p2p_pqc_trust_bundle_sequence`,
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`,
  `qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total`.
- Live-reload (observability only — no live apply is performed on DevNet):
  `qbind_p2p_trust_bundle_live_reload_apply_success_total`,
  `qbind_p2p_trust_bundle_live_reload_apply_failure_total`,
  `qbind_p2p_trust_bundle_live_reload_trigger_total`.
- Peer-candidate propagation:
  `qbind_p2p_pqc_trust_bundle_peer_candidate_received_total`,
  `qbind_p2p_pqc_trust_bundle_peer_candidate_validated_total`,
  `qbind_p2p_pqc_trust_bundle_peer_candidate_rejected_total`,
  `qbind_p2p_pqc_trust_bundle_peer_candidate_rate_limited_total`,
  `qbind_p2p_pqc_trust_bundle_peer_candidate_propagation_sent_total`,
  `qbind_p2p_pqc_trust_bundle_peer_candidate_dropped_oversize_total`.
- PQC cert verification: `qbind_p2p_pqc_cert_verify_accepted_total`,
  `qbind_p2p_pqc_cert_verify_rejected_total`,
  `qbind_p2p_pqc_cert_rejected_bad_signature_total`,
  `qbind_p2p_pqc_cert_rejected_unknown_root_total`,
  `qbind_p2p_pqc_cert_verify_rejected_revoked_total`.

## 4. Consensus / HotStuff detail (BEST-EFFORT for operators)

Rich verification/rejection counters are present, e.g.
`qbind_consensus_votes_total`, `qbind_consensus_proposals_total`,
`qbind_consensus_timeouts_total`, `qbind_consensus_view_changes_total`,
`qbind_consensus_inbound_newview_rejected_*_total`,
`qbind_consensus_inbound_timeout_rejected_*_total`,
`qbind_consensus_qc_formation_latency_ms_*`,
`qbind_consensus_validator_equivocations_total`. Operators watch the summary
progress signals in §1; the per-reason rejection counters are best-effort
diagnostics.

## 5. Storage / snapshot / restore (BEST-EFFORT, useful for disk health)

| Metric | Type | Meaning |
|---|---|---|
| `qbind_snapshot_success_total` / `qbind_snapshot_failure_total` | counter | Snapshot outcomes. |
| `qbind_snapshot_in_progress` | gauge | 1 while a snapshot runs. |
| `qbind_snapshot_last_height` / `qbind_snapshot_last_size_bytes` / `qbind_snapshot_last_duration_ms` | gauge | Last snapshot facts. |
| `qbind_restore_catchup_mode_active` | gauge | 1 while the node is in restore/catch-up. |
| `qbind_restore_catchup_blocks_applied_total` | counter | Blocks applied during catch-up. |
| `qbind_restore_catchup_responses_rejected_total` | counter | Rejected catch-up responses. |

> There is **no** dedicated free-disk-bytes / storage-size gauge in the default
> scrape (`qbind_state_size_bytes` exists in source but was **not** observed in the
> baseline scrape). Disk-space alerting must use node-exporter / host metrics, not
> the qbind endpoint — documented as **absent**, alert marked FUTURE.

## 6. Other observed families (BEST-EFFORT)

Mempool (`qbind_mempool_txs_total`, `qbind_mempool_rejected_total`), execution
(`qbind_execution_txs_applied_total`, `qbind_execution_errors_total`,
`qbind_execution_queue_len`), monetary shadow metrics (`qbind_monetary_*`),
keystore (`qbind_keystore_load_failure_total`), KEM
(`qbind_net_kem_encaps_total`, `qbind_net_kem_decaps_total`), and DAG coupling
(`qbind_dag_coupling_rejected_total`).

## 7. Required vs best-effort vs absent — summary

| Class | Metrics | For launch ops? |
|---|---|---|
| **Required** | Prometheus `up`; `qbind_consensus_committed_height`; `qbind_p2p_connections_current`; `qbind_p2p_connection_rate_drop_total`; trust-bundle load/verify/reject | **Yes** |
| **Best-effort** | detailed consensus rejection counters; snapshot/restore; mempool/execution; monetary; KEM | Recommended |
| **Conditional** | `qbind_net_per_peer_drops_total` (only after first per-peer drop) | Watch; alert FUTURE |
| **Absent (default scrape)** | node/build/chain info gauge; free-disk gauge; PQC-suite / KEMTLS-handshake crypto sub-metrics; `qbind_state_size_bytes` | Use host metrics / future run |
