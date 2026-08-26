# QBIND DevNet Evidence — Run 379

Public DevNet **M13 telemetry / metrics baseline** and **M14 monitoring /
alerting baseline** evidence. Run 379 publishes an operator-facing observability
package and proves, against the **release** `qbind-node` binary, that the
pre-existing `/metrics` endpoint plus new docs / scrape config / alert rules /
runbook are sufficient to move **M13 and M14 Yellow → Green** — **without** any
production Rust source change, new CLI flag, public exposure, live seed, or
launch.

> **Safety label:** DevNet · experimental · **no value** · resettable · metrics
> loopback-only by default · **NOT public-DevNet launch-ready** · no M4 Green · no
> TestNet readiness · no MainNet readiness · **C4/C5 OPEN**. Observability landing
> does **not** imply launch, TestNet, MainNet, C4, or C5 readiness. No production
> source change; no new public endpoint; no P2P wire-format change; no
> peer-admission weakening; no trust/validator/epoch/sequence/marker/
> `LivePqcTrustState` mutation.

## 1. Exact verdict

**POSITIVE / public-DevNet observability baseline — M13 telemetry / metrics
baseline and M14 monitoring / alerting baseline move Yellow → Green (Route B).**
Both must-haves land with real release-binary scrape evidence, parsed scrape and
alert configs, an operator runbook, a harness, and provenance. **M4 remains
Yellow** (external seed reachability unproven — Run 377/378), **M6 remains
Yellow/Partial**, **M12 remains Green**, the public DevNet remains **NOT
launch-ready**, and **C4/C5 remain OPEN**. MainNet/TestNet untouched.

## 2. Files changed

New observability package:
- `docs/release/public-devnet/observability/README.md`
- `docs/release/public-devnet/observability/METRICS.md`
- `docs/release/public-devnet/observability/SCRAPE_CONFIG.md`
- `docs/release/public-devnet/observability/ALERT_RULES.md`
- `docs/release/public-devnet/observability/RUNBOOK.md`
- `docs/release/public-devnet/observability/VERIFY.md`
- `docs/release/public-devnet/observability/prometheus-scrape.example.yml`
- `docs/release/public-devnet/observability/prometheus-alerts.example.yml`

Harness + archive + evidence:
- `scripts/devnet/run_379_public_devnet_observability_baseline.sh` — **new**
  release-binary harness.
- `docs/devnet/run_379_public_devnet_observability_baseline/{README.md,summary.txt,.gitignore}`
  — **new** archive.
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md` — this evidence record.

Narrow updates:
- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md` (M13/M14 Green).
- `docs/release/public-devnet/operator/QUICKSTART.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/whitepaper/contradiction.md`

**No production Rust source change.** Metrics exposure is the pre-existing
`metrics_http` server gated by `QBIND_METRICS_HTTP_ADDR`
(`crates/qbind-node/src/metrics_http.rs`, `crates/qbind-node/src/main.rs`), which
Run 379 documents and exercises but does not modify.

## 3. Decision gate route

**Route B — a small docs + machine-readable helper/harness is enough.** The
existing metrics HTTP endpoint and metric families are sufficient to operate a
DevNet node; what was missing was an operator-facing package (exposure guide,
verified family list, scrape config, alert rules, runbook, verification) plus
release-binary scrape evidence. Run 379 lands exactly that with **no** production
source change. Route A (endpoint/families already sufficient, publish docs only)
was close, but the machine-readable scrape/alert examples + harness add value, so
Route B is recorded. Route C (metrics too incomplete to move Green) does **not**
apply for M13/M14 — but the honest per-metric gaps (per-peer drop series absent
until first drop; no free-disk gauge; PQC-suite/KEMTLS crypto sub-metrics not in
the default scrape) are documented and their alerts kept **future**.

## 4. Observability package contents

Six operator docs + two machine-readable YAML examples under
`docs/release/public-devnet/observability/`: `README.md` (index + golden rules),
`METRICS.md` (verified family list; required/best-effort/conditional/absent),
`SCRAPE_CONFIG.md` (safe enable + scrape), `ALERT_RULES.md` (rules + severity),
`RUNBOOK.md` (per-alert response), `VERIFY.md` (reproducible checks),
`prometheus-scrape.example.yml`, `prometheus-alerts.example.yml`.

## 5. Metrics endpoint surface

Unchanged and pre-existing: the `metrics_http` HTTP/1.1 server serves
`GET /metrics` (Prometheus text `version=0.0.4`) and is enabled **only** when
`QBIND_METRICS_HTTP_ADDR=host:port` is set; unset ⇒ disabled; invalid ⇒ warning +
disabled. Recommended bind is `127.0.0.1:<port>` (loopback; no auth, no TLS). No
new CLI flag exists — the harness asserts `qbind-node --help` exposes none. The
release binary logs `[metrics_http] Listening on 127.0.0.1:<port>`.

## 6. Verified metric families

Confirmed by a live loopback scrape (505 lines) of the release binary:

- **Liveness/progress:** `qbind_consensus_committed_height` (observed advancing,
  e.g. 78), `qbind_consensus_current_view`, `qbind_consensus_view_number`,
  `qbind_consensus_qcs_formed_total`, `consensus_runtime_ticks_per_second`,
  `consensus_events_total{kind="tick"}`; plus Prometheus-synthesized `up`.
- **P2P + M12:** `qbind_p2p_connections_current`,
  `qbind_p2p_connection_rate_drop_total` (M12 connection-rate limiter,
  production-wired, Run 371 Green), `qbind_p2p_inbound_peers` /
  `_outbound_peers`, heartbeat/eviction/diversity counters.
- **PQC trust-bundle + peer-candidate:** `qbind_p2p_pqc_trust_bundle_loaded`,
  `..._signature_verified_total` / `..._signature_rejected_total`,
  `..._sequence`, `..._sequence_persist_failures_total`,
  `..._peer_candidate_received_total` / `..._validated_total` /
  `..._rejected_total`, PQC cert verify counters.
- **Consensus detail (best-effort):** votes/proposals/timeouts/view-changes and
  per-reason newview/timeout rejection counters, QC-formation latency.
- **Storage/snapshot/restore (best-effort):** `qbind_snapshot_success_total` /
  `_failure_total` / `_in_progress` / `_last_height`, `qbind_restore_catchup_*`.
- **Other:** mempool, execution, monetary (shadow), KEM, DAG-coupling.

**Honest gaps (documented, not invented):** `qbind_net_per_peer_drops_total` is
emitted per-peer **only after** a per-peer rate-limit drop (guarded by
`rate_limit_drop > 0` in `metrics.rs`) and was **absent** from the clean scrape;
no node/build/chain info gauge, no free-disk gauge, and no
`qbind_state_size_bytes` appeared in the default scrape; PQC-suite / KEMTLS /
DAG-mempool crypto sub-metrics are not served because `main.rs` passes an empty
`CryptoMetricsRefs`.

## 7. Scrape config evidence

`prometheus-scrape.example.yml` uses `metrics_path: /metrics`, loopback / RFC 5737
targets only, `scrape_interval: 15s`, and references the alert rules file. It
**parses as YAML** (PyYAML `safe_load`, with a dependency-free structural
fallback) — harness line `scrape_config_yaml=OK`.

## 8. Alert rules evidence

`prometheus-alerts.example.yml` has two groups: **ENABLED**
(`qbind-devnet-observability`, 9 rules, every expr metric verified present) and
**FUTURE / NOT ENABLED** (`qbind-devnet-observability-future-not-enabled`, 2 rules
whose metrics are absent). Severities use `page` / `ticket` / `observe`. It
**parses as YAML** and the harness confirms the future group and the per-peer-drop
future alert are present — lines `alert_rules_yaml=OK`,
`alert_rules_future_group=OK`. Enabled rules cover: node/metrics-endpoint down
(`up==0`, page), consensus no-progress (page), zero P2P connections (ticket),
sustained connection-rate drops (ticket), trust-bundle signature rejections
(ticket), trust-bundle sequence-persist failure (page), snapshot failures
(ticket), restore/catch-up stuck (ticket), peer-candidate rejections (observe).
Future/not-enabled: per-peer rate-limit drops and disk-space (absent metrics).

## 9. Operator runbook evidence

`RUNBOOK.md` gives a first-response for each enabled alert (confirm locally,
classify local vs network-wide, preserve evidence, remediate) plus the two future
rules, with anchors matching the `runbook:` annotations in the YAML. It
cross-references `QBIND_INCIDENT_RESPONSE.md`, `QBIND_MONITORING_AND_ALERTING_BASELINE.md`,
`operator/QUICKSTART.md`, and `p2p/ABUSE_DOS_POSTURE.md`.

## 10. Rejection / non-claim checks

The harness `non_claim_check=OK` greps the package for forbidden readiness claims
(`launch-ready`, `M4 Green`, `C4/C5 closed`, `TestNet/MainNet ready`) and passes
(only negations/`NOT`-qualified statements remain). No live seed, faucet, RPC,
explorer, or status page is created; no external port is opened; no peer-admission
or wire-format change is made.

## 11. Default compatibility / no runtime behavior change

No production source change. With `QBIND_METRICS_HTTP_ADDR` unset the metrics
server stays disabled (default). Enabling it changes no consensus, P2P, trust, or
admission behavior — it only serves read-only counters over a loopback socket.
The release-binary SHA-256 is identical to Run 376/377/378 (`ae1e699b…`),
confirming no production code changed.

## 12. Readiness matrix delta for M13

**M13 telemetry / metrics baseline: Yellow → Green.** Operator-facing metrics
exposure docs (`README.md`, `METRICS.md`, `SCRAPE_CONFIG.md`), verification
commands (`VERIFY.md`), and **release-binary scrape evidence** (HTTP 200 loopback
scrape; required families present) all land, satisfying the M13 Green rule.

## 13. Readiness matrix delta for M14

**M14 monitoring / alerting baseline: Yellow → Green.** Alert rules
(`ALERT_RULES.md` + `prometheus-alerts.example.yml`), scrape config
(`prometheus-scrape.example.yml`), and a response runbook (`RUNBOOK.md`) land and
**parse successfully**, with absent-metric alerts clearly marked **future / not
enabled**, satisfying the M14 Green rule.

## 14. Current public DevNet readiness status

**NOT launch-ready.** Observability is now operator-ready (M13/M14 Green), but M4
external seed reachability is still Yellow/launch-blocking, so the public DevNet
cannot launch.

## 15. Remaining public DevNet blockers

- **M4:** a real, externally reachable seed/bootnode with external reachability
  evidence (Run 378 Route C prerequisites) — primary blocker.
- **M6** live-registration half (M4-gated).
- All other Yellow/Red must-haves per the readiness matrix.

## 16. Public TestNet blockers

No TestNet readiness is claimed or approached; TestNet identity material is
refused by the identity path and the DevNet track does not gate TestNet.

## 17. MainNet blockers

MainNet authority rotation/revocation remains **Red**; no custody, no value, no
MainNet readiness.

## 18. C4 / C5 status

**C4 OPEN, C5 OPEN.** No authority-lifecycle runtime wiring, no trust-bundle live
apply, no peer-driven apply, no validator-set mutation, no epoch transition. The
observability package is read-only telemetry/monitoring and closes neither.

## 19. Tests run

- `cargo build -p qbind-node --release --bin qbind-node` — **OK**.
- `scripts/devnet/run_379_public_devnet_observability_baseline.sh` —
  **RESULT=POSITIVE** (build OK; no new CLI flag; loopback `/metrics` HTTP 200;
  10 enabled-alert metrics verified present; 2 absent metrics confirmed absent;
  scrape + alert YAML parse OK; non-claim check OK).
- YAML parse check for `prometheus-scrape.example.yml` — **OK**.
- YAML parse check for `prometheus-alerts.example.yml` — **OK**.
- Non-claim grep over the observability package — **OK** (no launch-ready /
  M4-Green / C4/C5-closure / TestNet/MainNet claim).
- `cargo test -p qbind-node --lib` — **PASS** (see §20 counts).

## 20. Security scans

- `runtime-tools-secret_scanning` over all changed files — no secrets.
- No credential, bearer token, webhook URL, private hostname, private IP, key,
  data dir, raw log, or metrics dump is committed. All addresses are loopback
  (`127.0.0.1`) or RFC 5737 (`192.0.2.0/24`) documentation examples. The harness
  removes its node data dir, node log, and raw scrape dump on exit; the archive
  `.gitignore` is a backstop and the tracked `summary.txt` carries only
  publish-safe hashes/status lines.

## 21. CodeQL

**No production Rust source change** in this run (docs + shell harness + two YAML
examples + a copied `summary.txt`). CodeQL is therefore **not meaningful** for
Run 379 (no changed production source to analyze); this is **not** a clean bill of
health, it reflects the absence of an analyzable production change.

## 22. Provenance

From `scripts/devnet/run_379_public_devnet_observability_baseline.sh`:

```
release_binary sha256 = ae1e699b0d6f1cbafb2913719e111877c8b90a67c0bbfac09fb23afe8acbfa96
build_id              = 8d34c1b1c5c5f8209060a2a63a939d45c7f9667e
toolchain             = rustc 1.97.1 (8bab26f4f 2026-07-14) / cargo 1.97.1 (c980f4866 2026-06-30)
```

(SHA-256 / BuildID are host-specific and reproduced locally by re-running the
harness; only publish-safe values are archived. Identical to the Run 376/377/378
release-binary hash because no production source changed.)

## 23. Honest limitations

- The scrape was taken from a **single loopback DevNet node**, not a live public
  network; it proves exposure and family presence, not multi-node behavior.
- `qbind_net_per_peer_drops_total` is **absent** until the first per-peer
  rate-limit drop, and the deployed per-peer message-rate override is
  construction-path-only; its alert is therefore **future / not enabled**.
- There is **no** node/build/chain info gauge and **no** free-disk gauge in the
  default scrape; node liveness uses Prometheus `up` + consensus progress, and
  disk alerting must use host/node-exporter metrics (future).
- PQC-suite / KEMTLS-handshake / DAG-mempool crypto sub-metrics are not served by
  default (`main.rs` passes an empty `CryptoMetricsRefs`); wiring them is future.
- The example configs are **loopback / RFC 5737** documentation examples; a real
  central Prometheus must be fenced behind an authenticating reverse proxy +
  firewall, which this run does not deploy.
- This run does not launch, does not prove M4, and closes neither C4 nor C5.

## 24. Suggested Run 380 next step

Either (a) return to **M4**: execute Route A on real infrastructure per
`network/reachability/RUN_378_qbind-devnet-seed-1.md` §14 (durable operator seed
identity, externally reachable KEMTLS static-root listener, external-vantage TCP +
handshake evidence) to attempt M4 Yellow → Green and unblock M6's live half; or
(b) deepen observability by wiring the deployed per-peer rate-limit drop counter
(`qbind_net_per_peer_drops_total`) and a node/build info + free-disk gauge into the
default `/metrics`, then promote the two future alerts to enabled — a small
production change that would require CodeQL and release-binary scrape re-evidence.
