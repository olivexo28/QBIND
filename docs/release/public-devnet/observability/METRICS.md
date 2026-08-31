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
(CONDITIONAL: absent until the first per-peer drop; ENABLED for alerting).** This
series is emitted by the release binary **only after a per-peer rate-limit drop
has occurred** (`metrics.rs` renders it per-peer guarded by `rate_limit_drop > 0`),
so it is **absent in a clean scrape until a per-peer rate-limit drop occurs**. It
is **not** an unwired series: **Runs 371–373 prove deployed KEMTLS live-socket
enforcement** — a KEMTLS-admitted peer that floods over-budget frames through the
deployed `TcpKemTlsP2pService::read_loop` trips the deployed per-peer limiter and
makes `qbind_net_per_peer_drops_total{reason="rate_limit"}` appear on the live
`/metrics` endpoint (M12 Green). **Run 380** reproduces this against the release
binary: a clean scrape shows the series absent, then an induced per-peer drop makes
it present, while `qbind_p2p_connection_rate_drop_total` stays independent. Its
alert `QbindPerPeerRateLimitDropsSustained` is therefore **ENABLED** in
[`ALERT_RULES.md`](./ALERT_RULES.md); `increase(...)` over an absent-until-first-drop
series simply does not fire until the first real drop, which is the correct
behaviour (see `ABUSE_DOS_POSTURE.md` §7k–§7m for the deployed live-socket proof).

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

### 5a. qbind-owned data-dir free space (Run 381) — ENABLED

| Metric | Type | Meaning |
|---|---|---|
| `qbind_node_data_dir_free_bytes` | gauge | Free bytes on the filesystem backing the qbind data directory (from `--data-dir`). Value only — **no** path/mount/hostname label. |

> Run 381 adds a **qbind-owned** free-space gauge derived from `statvfs(3)` on the
> `--data-dir` filesystem. It is emitted **only** when `--data-dir` is set and the
> syscall succeeds (unix); otherwise the gauge is simply omitted (no panic, no
> fabricated value). Because it is proven present in the Run 381 release scrape,
> `QbindNodeDiskSpaceLow` is promoted **FUTURE → ENABLED** against this metric.
> The legacy `qbind_state_size_bytes` remains **absent** from the default scrape;
> operators may still complement with node-exporter host metrics.

## 6. Other observed families (BEST-EFFORT)

Mempool (`qbind_mempool_txs_total`, `qbind_mempool_rejected_total`), execution
(`qbind_execution_txs_applied_total`, `qbind_execution_errors_total`,
`qbind_execution_queue_len`), monetary shadow metrics (`qbind_monetary_*`),
keystore (`qbind_keystore_load_failure_total`), KEM
(`qbind_net_kem_encaps_total`, `qbind_net_kem_decaps_total`), and DAG coupling
(`qbind_dag_coupling_rejected_total`).

### 6a. Node/build/chain info (Run 381) — ENABLED

| Metric | Type | Meaning |
|---|---|---|
| `qbind_node_build_info{version,build_id,git_commit,env,chain_id}` | gauge | Static info metric; value always `1`. Labels are low-cardinality and secret-free. `git_commit` is auto-derived to a short git commit hash at build time (Run 382 `build.rs`) or set via `QBIND_GIT_COMMIT`; `build_id` is a harness/CI-injected `QBIND_BUILD_ID` (never derived from git or the ELF). Both render `unknown` when not injected/derivable. The metric `build_id` label is **distinct** from the binary ELF `.note.gnu.build-id` (see `../binary/BUILDINFO.md`). `env` is the fixed vocabulary `devnet`/`testnet`/`mainnet`; `chain_id` is canonical hex. **No** path, hostname, branch, dirty-status, or private-endpoint label is ever emitted. |

## 7. Required vs best-effort vs absent — summary

| Class | Metrics | For launch ops? |
|---|---|---|
| **Required** | Prometheus `up`; `qbind_consensus_committed_height`; `qbind_p2p_connections_current`; `qbind_p2p_connection_rate_drop_total`; trust-bundle load/verify/reject | **Yes** |
| **Best-effort** | detailed consensus rejection counters; snapshot/restore; mempool/execution; monetary; KEM | Recommended |
| **Conditional** | `qbind_net_per_peer_drops_total` (only after first per-peer drop) | Conditional; alert ENABLED after Run 380 induced-drop evidence |
| **Info / gauge (Run 381)** | `qbind_node_build_info`; `qbind_node_data_dir_free_bytes` | Node/build/chain identity + qbind-owned disk visibility; disk alert ENABLED |
| **Absent (default scrape)** | PQC-suite / KEMTLS-handshake crypto sub-metrics; `qbind_state_size_bytes` | Use host metrics / future run |