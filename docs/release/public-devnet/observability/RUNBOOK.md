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
   `docs/ops/QBIND_INCIDENT_RESPONSE.md`.

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

---

## FUTURE / NOT ENABLED

### QbindPerPeerRateLimitDropsSustained (future)
`qbind_net_per_peer_drops_total` is absent until a per-peer rate-limit drop
occurs, and the deployed per-peer message-rate override is construction-path-only.
When a future run wires the deployed per-peer limiter to emit this series, enable
this rule and respond as for `QbindConnectionRateDropsSustained` but scoped to the
offending `peer` label.

### QbindNodeDiskSpaceLow (future)
qbind-node emits no free-disk gauge. Do disk alerting with host/node-exporter
metrics (`node_filesystem_avail_bytes`). Until then this rule stays disabled.
