# QBIND DevNet Evidence - Run 380

Public DevNet observability hardening on top of the accepted Run 379 baseline.
Run 380 deepens the M13 telemetry / metrics and M14 monitoring / alerting
baselines by (1) correcting stale per-peer / M12 observability wording, (2)
producing release-binary scrape evidence that
qbind_net_per_peer_drops_total{reason="rate_limit"} becomes present after an
induced per-peer rate-limit drop over the deployed KEMTLS live socket, and (3)
promoting that alert from FUTURE to ENABLED - all with no production Rust source
change.

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only
by default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet
readiness, no MainNet readiness, C4/C5 OPEN. This hardening does not imply launch,
TestNet, MainNet, C4, or C5 readiness. No production source change; no new public
endpoint; no P2P wire-format change; no peer-admission weakening; no
trust/validator/epoch/sequence/marker/LivePqcTrustState mutation.

## 1. Exact verdict

PASS / public-DevNet observability hardening POSITIVE. Stale
"construction-path-only" per-peer wording is corrected; release-binary scrape
evidence lands (qbind_net_per_peer_drops_total{reason="rate_limit"}=47 present
only after an induced per-peer drop, absent in a clean scrape); the per-peer alert
is promoted FUTURE to ENABLED; scrape + alert configs parse; the only remaining
future alert backs a genuinely absent (disk) metric; and tests/scans/provenance
pass. M12, M13, M14 remain Green; M4 remains Yellow; M6 remains Yellow/Partial; the
public DevNet remains NOT launch-ready; C4/C5 remain OPEN; TestNet/MainNet
untouched.

## 2. Files changed

Observability package (docs correction + alert promotion):

- docs/release/public-devnet/observability/METRICS.md
- docs/release/public-devnet/observability/ALERT_RULES.md
- docs/release/public-devnet/observability/RUNBOOK.md
- docs/release/public-devnet/observability/VERIFY.md
- docs/release/public-devnet/observability/README.md
- docs/release/public-devnet/observability/prometheus-alerts.example.yml

P2P posture / verification:

- docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md (7n added; 5 note corrected)
- docs/release/public-devnet/p2p/VERIFY.md (Run 380 cross-reference)

Harness + archive + evidence:

- scripts/devnet/run_380_public_devnet_observability_hardening.sh (new harness).
- docs/devnet/run_380_public_devnet_observability_hardening/ (README.md,
  summary.txt, .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md (this evidence record).

Narrow run-log updates:

- docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
- docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
- docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
- docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md
- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
- docs/whitepaper/contradiction.md

No production Rust source change. The per-peer drop metric is already emitted by
the deployed TcpKemTlsP2pService::read_loop per-peer limiter
(crates/qbind-node/src/metrics.rs, guarded by rate_limit_drop > 0); Run 380 only
exercises and documents it. No run_380_* Rust tests file is needed because no
production source changed.

## 3. Decision gate route

Route A for the per-peer drop metric: existing source already produces the series
after a real per-peer drop over the deployed KEMTLS live socket (Runs 371-373).
Run 380 reuses the Run 371 helper (dial-flood mode) to induce a drop against the
release binary and scrapes it present; no production source change.

Route C for node/build-info and disk/storage gauges: qbind-node emits no owned
qbind_node_build_info and no free-disk / storage-capacity gauge, and adding them
was judged out of appetite for a no-source-change hardening run. The disk alert
stays future / not-enabled; disk alerting is delegated to host/node-exporter
(node_filesystem_avail_bytes). The exact blocker: no qbind-owned disk gauge exists
in metrics.rs, and a build-info gauge would require threading build/version/env
into main.rs plus a build script.

Route B (small production metrics additions) was not taken.

## 4. Documentation correction

The stale "construction-path-only" per-peer wording is removed from the
observability package and the P2P posture note and replaced with: "series is
absent in a clean scrape until a per-peer rate-limit drop occurs; Runs 371-373
prove deployed KEMTLS live-socket enforcement." Corrected in METRICS.md section 2,
ALERT_RULES.md, RUNBOOK.md, prometheus-alerts.example.yml, and
p2p/ABUSE_DOS_POSTURE.md section 5. This does not downgrade M12: it aligns the
docs with the deployed live-socket enforcement proven in Runs 371-373 (see
ABUSE_DOS_POSTURE.md sections 7k-7m). The historical Run 364 log entries (which
describe a separate AsyncPeerManagerImpl CLI-threading gap) are left unchanged as
history.

## 5. Metrics endpoint surface

Unchanged and pre-existing: the metrics_http HTTP/1.1 server serves GET /metrics
(Prometheus text version=0.0.4) and is enabled only when
QBIND_METRICS_HTTP_ADDR=host:port is set. The harness confirms a node started
without that env var never logs "[metrics_http] Listening" (disabled by default),
and a node started with QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port> binds loopback. No
new CLI flag exists (--help asserted clean).

## 6. Per-peer drop scrape evidence

From scripts/devnet/run_380_public_devnet_observability_hardening.sh against the
release binary plus the Run 371 helper:

- Clean scrape: per_peer_clean_scrape=ABSENT -
  qbind_net_per_peer_drops_total is absent before any flood.
- Induced drop: a KEMTLS-admitted peer completes mutual auth against the running
  target/release/qbind-node and floods 60 over-budget frames through the deployed
  read loop, giving per_peer_induced_scrape=PRESENT
  qbind_net_per_peer_drops_total{reason="rate_limit"}=47.
- Independence (per-peer side): the flood left
  qbind_p2p_connection_rate_drop_total=0.
- Independence (connection side): a separate connection-rate flood (10 conns, max
  3, 7 refused) incremented qbind_p2p_connection_rate_drop_total=7 while the
  per-peer metric stayed absent.

## 7. Node / build / chain info metric evidence

None added (Route C). No qbind_node_build_info gauge exists in the release
/metrics; the harness confirms it is absent. Node liveness continues to use the
Prometheus-synthesized up series plus consensus progress
(qbind_consensus_committed_height). A build/version/chain-id info gauge remains a
documented future improvement (would require a small production source change plus
CodeQL plus re-scrape).

## 8. Disk / storage metric evidence

None added (Route C). qbind-node emits no owned free-disk / storage-capacity
gauge; the harness confirms qbind_node_data_dir_free_bytes, qbind_disk_free_bytes,
and qbind_state_size_bytes are all absent. The QbindNodeDiskSpaceLow alert stays
future / not-enabled; disk alerting is recommended via host/node-exporter
(node_filesystem_avail_bytes).

## 9. Alert rule changes

- QbindPerPeerRateLimitDropsSustained promoted FUTURE to ENABLED in the
  qbind-devnet-observability group. Its metric is absent in a clean scrape until
  the first per-peer drop; increase(...) over an absent-until-first-drop series
  simply does not fire until a real drop, and Run 380 proves the series becomes
  present. The harness asserts the alert now precedes the future-group marker.
- QbindNodeDiskSpaceLow stays in the
  qbind-devnet-observability-future-not-enabled group (absent disk metric; use
  node-exporter). The harness asserts the future group no longer references the
  per-peer metric and still carries the disk alert.

## 10. Scrape config evidence

prometheus-scrape.example.yml is unchanged (loopback / RFC 5737 targets,
metrics_path: /metrics, scrape_interval: 15s) and parses as YAML -
scrape_config_yaml=OK.

## 11. Runbook evidence

RUNBOOK.md now carries QbindPerPeerRateLimitDropsSustained as an enabled response
(scope to the offending peer label; correlate with the connection-rate counter;
controls are independent) and keeps QbindNodeDiskSpaceLow under FUTURE. The runbook
anchors match the runbook: annotations in the alert YAML.

## 12. Rejection / non-claim checks

The harness non_claim_check=OK greps the observability package for forbidden
readiness claims (launch-ready, M4 Green, C4/C5 closed, TestNet/MainNet ready) and
passes (only negations remain). No live seed, faucet, RPC, explorer, or status
page is created; no external port is opened; no peer-admission or wire-format
change is made.

## 13. Default compatibility / no runtime behavior change

No production source change. With QBIND_METRICS_HTTP_ADDR unset the metrics server
stays disabled; the harness confirms this. Enabling it changes no consensus, P2P,
trust, or admission behavior - it only serves read-only counters over a loopback
socket. The per-peer flags (--p2p-max-messages-per-second /
--p2p-burst-allowance) are the pre-existing hidden DevNet flags used by Runs
371-373; their default (1000 msg/s + 100 burst) is preserved.

## 14. Readiness matrix delta for M13

M13 telemetry / metrics baseline: remains Green. Hardening preserves the Run 379
guarantees (loopback /metrics, HTTP 200, required families present) and adds
release-binary evidence that the per-peer drop series is exposable on demand. No
downgrade.

## 15. Readiness matrix delta for M14

M14 monitoring / alerting baseline: remains Green. The per-peer alert is now
enabled with backing scrape evidence, the scrape + alert YAML still parse, and the
only future alert backs a genuinely absent (disk) metric. No downgrade.

## 16. Current public DevNet readiness status

NOT launch-ready. Observability is further hardened (M12/M13/M14 Green), but M4
external seed reachability is still Yellow/launch-blocking, so the public DevNet
cannot launch.

## 17. Remaining public DevNet blockers

- M4: a real, externally reachable seed/bootnode with external reachability
  evidence (Run 378 Route C prerequisites) - primary blocker.
- M6 live-registration half (M4-gated).
- All other Yellow/Red must-haves per the readiness matrix.

## 18. Public TestNet blockers

No TestNet readiness is claimed or approached; TestNet identity material is refused
by the identity path and the DevNet track does not gate TestNet.

## 19. MainNet blockers

MainNet authority rotation/revocation remains Red; no custody, no value, no MainNet
readiness.

## 20. C4 / C5 status

C4 OPEN, C5 OPEN. No authority-lifecycle runtime wiring, no trust-bundle live
apply, no peer-driven apply, no validator-set mutation, no epoch transition. The
hardening is read-only telemetry/monitoring and closes neither.

## 21. Tests run

- cargo build -p qbind-node --release --bin qbind-node - OK.
- cargo build -p qbind-node --release --example
  run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_helper - OK.
- scripts/devnet/run_380_public_devnet_observability_hardening.sh -
  RESULT=POSITIVE (build OK; no new CLI flag; metrics disabled by default;
  loopback /metrics HTTP 200; per-peer metric ABSENT clean then PRESENT=47 after
  induced drop; both independence checks OK; Route C gauges absent; scrape + alert
  YAML parse OK; per-peer alert enabled; future group carries only disk; non-claim
  OK).
- YAML parse check for prometheus-scrape.example.yml - OK.
- YAML parse check for prometheus-alerts.example.yml - OK.
- Non-claim grep over the observability package - OK.
- cargo test -p qbind-node --lib - PASS (test result: ok. 1394 passed; 0 failed;
  0 ignored; no production source changed, so results match the Run 379 baseline).

## 22. Security scans

- runtime-tools-secret_scanning over all changed files - no secrets.
- No credential, bearer token, webhook URL, private hostname, private IP, key, data
  dir, raw log, or metrics dump is committed. All addresses are loopback
  (127.0.0.1) or RFC 5737 (192.0.2.0/24) documentation examples. The harness
  removes its node data dirs, node logs, raw scrape dumps, and helper flood outputs
  on exit; the archive .gitignore is a backstop and the tracked summary.txt carries
  only publish-safe hashes/status lines (plus loopback ports and a synthetic drop
  count).

## 23. CodeQL

No production Rust source change in this run (docs + shell harness + one YAML edit
+ a copied summary.txt). CodeQL is therefore not meaningful for Run 380 (no changed
production source to analyze); this is not a clean bill of health, it reflects the
absence of an analyzable production change.

## 24. Provenance

From scripts/devnet/run_380_public_devnet_observability_hardening.sh (host-local;
reproduced by re-running the harness - SHA-256 / BuildID are host-specific):

    release_binary sha256   = e6f264f05d5e6d310abd0ffe4c3dee9cef90ee377d60964b599c4a8b29c552dd
    release_binary build_id = 578f4539bdd654080975344f00fed0811b2d3917
    helper_binary sha256    = b52b65aee379b2b4f082bac8a321e1911dff537a0e594d4653de9590a7bbd421
    toolchain               = rustc 1.98.0 (88d9e12ae 2026-08-18) / cargo 1.98.0 (797e8a9bc 2026-08-05)
    induced per-peer drops  = qbind_net_per_peer_drops_total{reason="rate_limit"}=47

## 25. Honest limitations

- The scrape was taken from a single loopback DevNet node driven by an in-repo
  helper, not a live public network; it proves the per-peer series is exposable on
  the release binary after a real deployed-limiter drop, not multi-node production
  behavior.
- qbind_net_per_peer_drops_total remains absent until the first per-peer drop by
  design; the enabled alert therefore only fires after a real drop, which is the
  intended semantics.
- No node/build/chain-info gauge and no free-disk gauge were added (Route C); disk
  alerting still relies on host/node-exporter, and the disk alert stays
  future/not-enabled.
- The example configs are loopback / RFC 5737 documentation examples; a real
  central Prometheus must be fenced behind an authenticating reverse proxy plus
  firewall, which this run does not deploy.
- This run does not launch, does not prove M4, does not move M6, and closes neither
  C4 nor C5.

## 26. Suggested Run 381 next step

Either (a) return to M4: execute Route A on real infrastructure per
network/reachability/RUN_378_qbind-devnet-seed-1.md section 14 (durable operator
seed identity, externally reachable KEMTLS static-root listener, external-vantage
TCP + handshake evidence) to attempt M4 Yellow to Green and unblock M6's live half;
or (b) take Route B for the remaining observability gaps - add a low-cardinality
qbind_node_build_info gauge and a portable qbind_node_data_dir_free_bytes gauge to
the default /metrics, wire them read-only, add
crates/qbind-node/tests/run_381_public_devnet_observability_metrics_tests.rs,
promote QbindNodeDiskSpaceLow to enabled, and re-run CodeQL plus release-binary
scrape re-evidence.
