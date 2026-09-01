# QBIND Public DevNet — Observability Runbook (M14)

Operator response for each alert in
[`prometheus-alerts.example.yml`](./prometheus-alerts.example.yml). Anchors match
the `runbook:` annotations. This runbook is DevNet-scoped: the network has **no
value** and is **resettable**; the goal is to restore node liveness and capture
evidence, not to protect funds.

General first steps for any alert:

1. Confirm the alert against the node's own `/metrics` over loopback
   (`curl -s http://127.0.0.1:<port>/metrics`) and the node log.
2. Note whether the condition is **local** (one node) or **network-wide** (many
   nodes) — see `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` principle 4.
3. Preserve evidence (logs, scrape snapshots) before restart; see
   `docs/ops/QBIND_INCIDENT_RESPONSE.md` (internal) and, for the public-DevNet
   operator incident-response process (severity levels, incident classes,
   evidence + redaction, escalation, publication),
   `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`. For when/how DevNet
   state is wiped and the operator actions around a reset, see
   `docs/release/public-devnet/ops/RESET_POLICY.md`.

---

## QbindNodeDown
**Severity: page.** The metrics endpoint (and likely the process) is unreachable.
- Check the process is alive and `QBIND_METRICS_HTTP_ADDR` is still bound to
  loopback; check host resources.
- If the process died, capture the tail of the log, then restart per
  `operator/QUICKSTART.md`. If many nodes are down simultaneously, treat as a
  network-wide incident (`QBIND_INCIDENT_RESPONSE.md`).

## QbindConsensusNoProgress
**Severity: page.** `qbind_consensus_committed_height` is flat for 10m while up.
- Correlate `qbind_consensus_current_view`, `consensus_events_total{kind="tick"}`,
  and peer counts. A stalled view with no commits suggests a quorum/liveness fault.
- Check whether the node is isolated (`qbind_p2p_connections_current`); if
  network-wide, escalate — this is a consensus-liveness condition.

## QbindNodeNoP2PConnections
**Severity: ticket.** Zero live peers for 15m.
- Verify the P2P listener address and that the node can reach configured
  seeds/peers. Restart P2P bring-up per `operator/QUICKSTART.md`.
- If external reachability is suspected, note that M4 external seed reachability
  is **not** proven (Run 377/378); this is expected on an un-launched DevNet.

## QbindConnectionRateDropsSustained
**Severity: ticket.** The M12 connection-rate limiter is shedding connections.
- Inspect source addresses at the host/firewall. Sustained drops indicate a
  connection flood; the limiter is working as designed (Run 371).
- Consider tightening host firewall rules. See `p2p/ABUSE_DOS_POSTURE.md`.

## QbindTrustBundleSignatureRejections
**Severity: ticket.** PQC trust-bundle signatures are being rejected.
- Confirm the configured roots/bundle match the DevNet package; a
  misconfigured/stale bundle is the common cause. Correlate
  `qbind_p2p_pqc_trust_bundle_activation_rejected_total` and
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total`.
- No live trust-bundle apply is performed on DevNet; fix configuration and
  restart. Do **not** attempt any authority-lifecycle change (C4/C5 OPEN).

## QbindTrustBundleSequencePersistFailure
**Severity: page.** The durable trust-bundle sequence cannot be persisted.
- Check the data dir for disk-full / permission / I/O errors. Durable trust state
  that cannot be written is a fail-closed condition — stop and remediate storage
  before continuing.

## QbindSnapshotFailures
**Severity: ticket.** Snapshots are failing.
- Check disk space and the data dir. Correlate `qbind_snapshot_last_height` /
  `qbind_snapshot_in_progress`. Storage remediation, then re-run.

## QbindRestoreCatchupStuck
**Severity: ticket.** Node stuck in restore/catch-up for 30m.
- Check `qbind_restore_catchup_responses_rejected_total` and peer availability. If
  no peer can serve catch-up, the node cannot reach head — verify peers and, if
  needed, reset the (valueless) DevNet data dir and re-bootstrap.

## QbindPeerCandidateRejectionsHigh
**Severity: observe.** Peer-candidate trust-bundle propagations are being
rejected. Correlate with `..._peer_candidate_received_total` /
`..._validated_total`. Informational unless paired with a page-level alert.

## QbindPerPeerRateLimitDropsSustained
**Severity: observe.** The deployed M12 per-peer message-rate limiter is dropping
frames from one or more peers. `qbind_net_per_peer_drops_total{reason="rate_limit"}`
is absent until the first per-peer drop, then increments per offending `peer`
label; Runs 371–373 prove this enforcement over the deployed KEMTLS live socket and
Run 380 provides release-binary scrape evidence. Respond as for
`QbindConnectionRateDropsSustained`, but scope to the offending `peer` label:
confirm locally, classify local vs network-wide, preserve evidence, and correlate
with `qbind_p2p_connection_rate_drop_total` (the two controls are independent — a
per-peer drop does not increment the connection-rate counter and vice versa).

---

## QbindNodeDiskSpaceLow
**Severity: ticket.** *(ENABLED, Run 381.)* The qbind-owned gauge
`qbind_node_data_dir_free_bytes` — free bytes on the filesystem backing
`--data-dir`, derived from `statvfs(3)` — has fallen below the configured floor
(example: 5 GiB) for 15m. Low free space risks failed snapshots and unwritable
durable state (correlate with `QbindSnapshotFailures` /
`QbindTrustBundleSequencePersistFailure`). Respond:
1. Confirm on the affected instance which volume backs `--data-dir` and its true
   free space (`df -h <data-dir>`). The gauge is value-only; it carries **no**
   path/mount/hostname label, so map the instance → volume from your inventory.
2. Reclaim space: prune old snapshots/logs off the data volume, or grow the
   volume. Do not delete live consensus/state files.
3. If free space cannot be restored promptly, plan a controlled restart onto a
   larger volume using the standard restore/catch-up path.
4. Tune the alert threshold to the real volume size; the shipped 5 GiB floor is a
   conservative DevNet example, not a guarantee.

The gauge is emitted only when `--data-dir` is set and the syscall succeeds; if
it is absent, this rule cannot fire (verify `--data-dir` and platform support).

---

## FUTURE / NOT ENABLED

### QbindStateSizeHigh (future)
The legacy `qbind_state_size_bytes` estimated-state-size gauge exists in source
but is **not** exported in the default release scrape (Run 379/380/381 confirm it
absent), so this rule cannot fire. For qbind-owned free-space alerting use the
ENABLED `QbindNodeDiskSpaceLow` rule (`qbind_node_data_dir_free_bytes`). Operators
may additionally use host/node-exporter metrics (`node_filesystem_avail_bytes`).