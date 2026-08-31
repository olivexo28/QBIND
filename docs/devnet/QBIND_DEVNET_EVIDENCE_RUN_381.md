# QBIND DevNet Evidence - Run 381

Public DevNet observability GAUGE hardening on top of the accepted Run 380
hardening. Run 381 extends the M13 telemetry / metrics and M14 monitoring /
alerting baselines by (1) correcting the stale Run 380 per-peer summary row in
METRICS.md, (2) adding a minimal, read-only production metrics source change
(decision gate Route B) that exposes two low-cardinality, secret-free series on
the release-binary /metrics scrape - qbind_node_build_info (node/build/chain info)
and the qbind-owned qbind_node_data_dir_free_bytes (data-dir free space) - and (3)
promoting the QbindNodeDiskSpaceLow alert FUTURE -> ENABLED against the proven
disk gauge.

Safety label: DevNet, experimental, no value, resettable, metrics loopback-only
by default, NOT public-DevNet launch-ready, no M4 Green, no M6 Green, no TestNet
readiness, no MainNet readiness, C4/C5 OPEN. This hardening does not imply launch,
TestNet, MainNet, C4, or C5 readiness. The Rust source change is confined to
read-only metrics emission; no new public endpoint; no P2P wire-format change; no
peer-admission weakening; no trust/validator/epoch/sequence/marker/LivePqcTrustState
mutation.

## 1. Exact verdict

PASS / public-DevNet observability gauge hardening POSITIVE. The stale Run 380
per-peer METRICS summary row is corrected ("Watch; alert FUTURE" -> "Conditional;
alert ENABLED after Run 380 induced-drop evidence"). A minimal read-only source
change lands two new series on the release binary: qbind_node_build_info{version,
build_id,git_commit,env,chain_id} 1 (labels low-cardinality and secret-free;
unknown values render as unknown) and qbind_node_data_dir_free_bytes (value only,
no path/mount/hostname label). The QbindNodeDiskSpaceLow alert is promoted FUTURE
-> ENABLED against qbind_node_data_dir_free_bytes; the only remaining future rule
(QbindStateSizeHigh) backs the still-absent legacy qbind_state_size_bytes gauge.
Scrape + alert configs parse; enabled alert expressions reference present metrics;
tests/scans/provenance pass. M12, M13, M14 remain Green; M4 remains Yellow; M6
remains Yellow/Partial; the public DevNet remains NOT launch-ready; C4/C5 remain
OPEN; TestNet/MainNet untouched.

## 2. Files changed

Production source (minimal, read-only metrics):

- crates/qbind-node/src/metrics.rs (BuildInfoContext, sanitize_info_label,
  data_dir_free_bytes, build_context/data_dir fields + setters, and the
  qbind_node_build_info + qbind_node_data_dir_free_bytes emission in
  format_metrics).
- crates/qbind-node/src/main.rs (wire config env/chain_id + data_dir into
  node_metrics via set_build_context / set_data_dir).
- crates/qbind-node/Cargo.toml (cfg(unix) libc dependency for statvfs(3); already
  present in the workspace lockfile).

Tests:

- crates/qbind-node/tests/run_381_public_devnet_observability_gauges_tests.rs (new;
  6 tests).

Observability package (docs correction + alert promotion):

- docs/release/public-devnet/observability/METRICS.md
- docs/release/public-devnet/observability/ALERT_RULES.md
- docs/release/public-devnet/observability/RUNBOOK.md
- docs/release/public-devnet/observability/VERIFY.md
- docs/release/public-devnet/observability/README.md
- docs/release/public-devnet/observability/prometheus-alerts.example.yml

P2P posture / verification (cross-reference only):

- docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md (7o added)
- docs/release/public-devnet/p2p/VERIFY.md (Run 381 cross-reference)

Harness + archive + evidence:

- scripts/devnet/run_381_public_devnet_observability_gauges.sh (new harness).
- docs/devnet/run_381_public_devnet_observability_gauges/ (README.md, summary.txt,
  .gitignore) (new archive).
- docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md (this evidence record).

Narrow run-log updates:

- docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md
- docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
- docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md
- docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md
- docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md
- docs/whitepaper/contradiction.md

## 3. Decision gate route

Route B. A minimal, read-only production metrics source change was required
because neither an owned build/chain info gauge nor an owned free-disk gauge
existed (Run 380 confirmed both absent under Route C). The change adds only
read-only exposition (no behavioral change), gated exactly as before by
QBIND_METRICS_HTTP_ADDR (loopback, disabled by default), with no new CLI flag.
Because the qbind-owned disk gauge is now proven present in the release scrape,
QbindNodeDiskSpaceLow is promoted FUTURE -> ENABLED. The legacy
qbind_state_size_bytes gauge stays absent, so QbindStateSizeHigh stays future.

## 4. Run 380 cleanup

The stale METRICS.md summary row
`qbind_net_per_peer_drops_total ... Watch; alert FUTURE`
is corrected to
`Conditional; alert ENABLED after Run 380 induced-drop evidence`.
M12/M13/M14 are not downgraded.

## 5. Metrics endpoint surface

Unchanged transport: the pre-existing metrics_http server
(crates/qbind-node/src/metrics_http.rs) gated by QBIND_METRICS_HTTP_ADDR. Disabled
by default; binds loopback (127.0.0.1) in the harness; GET /metrics returns HTTP
200 with Prometheus text. No new CLI flag; qbind-node --help exposes no
metrics/observability/scrape/prometheus/telemetry/build-info/disk flag.

## 6. Node/build/chain info metric evidence

Observed on the release binary (summary.txt):

    qbind_node_build_info{version="0.1.0",build_id="unknown",git_commit="unknown",env="devnet",chain_id="51424e4444455600"} 1

- Value is always 1 (info metric).
- version from CARGO_PKG_VERSION; build_id/git_commit from option_env!(QBIND_BUILD_ID)
  / option_env!(QBIND_GIT_COMMIT), rendering `unknown` when unset (never a panic).
- env from the fixed vocabulary devnet/testnet/mainnet; chain_id is canonical hex.
- All labels are sanitized to [A-Za-z0-9._-] and capped in length: no path,
  hostname, private-endpoint, whitespace, quote, or backslash character can appear.
  The harness asserts the label section contains no `/`, `@`, `\`, space, `:`, and
  no secret-ish token.

## 7. Disk/free-space metric evidence

Observed on the release binary (summary.txt):

    qbind_node_data_dir_free_bytes 84525117440

- Value only - no path, mount, or hostname label (harness asserts no `{`).
- Derived from statvfs(3) on the --data-dir filesystem under cfg(unix); on error
  or non-unix targets the gauge is honestly omitted (no panic, no fabricated
  value). Without --data-dir the gauge is absent (unit test
  data_dir_free_bytes_absent_without_data_dir).
- The data-dir path itself is never emitted (unit test asserts the path string
  does not appear anywhere in the output).

## 8. Alert rule changes

- QbindPerPeerRateLimitDropsSustained: remains ENABLED (Run 380).
- QbindNodeDiskSpaceLow: promoted FUTURE -> ENABLED, expr
  `qbind_node_data_dir_free_bytes < 5368709120` (~5 GiB example floor) for 15m,
  severity ticket. Enabled only because the metric is proven present in the
  release scrape.
- QbindStateSizeHigh: new future/not-enabled placeholder for the still-absent
  legacy qbind_state_size_bytes gauge (the only rule left in the
  qbind-devnet-observability-future-not-enabled group).

## 9. Scrape config evidence

prometheus-scrape.example.yml parses as YAML (pyyaml_ok). Unchanged this run; the
loopback-only, disabled-by-default scrape guidance is preserved.

## 10. Runbook evidence

RUNBOOK.md gains an ENABLED QbindNodeDiskSpaceLow section (confirm volume, reclaim
space, plan controlled restart, tune threshold; note the gauge is value-only and
absent when --data-dir is unset) and moves the future entry to QbindStateSizeHigh.

## 11. Rejection / non-claim checks

- non_claim_check=OK: no launch-ready / M4-Green / TestNet / MainNet / C4 / C5
  closure claim in the observability docs.
- future_group_absent_only=OK: the future group references only the still-absent
  qbind_state_size_bytes.
- enabled_exprs_present=OK: every enabled alert expr references a metric present in
  the fresh scrape, the Prometheus `up` series, or the Run-380-proven
  absent-until-drop per-peer series.
- legacy_state_size_absent=OK: qbind_state_size_bytes stays absent.

## 12. Default compatibility / no runtime behavior change

metrics_disabled_by_default=OK: a node started without QBIND_METRICS_HTTP_ADDR logs
no /metrics bind. The new series are pure read-only exposition appended to
format_metrics; no consensus, networking, storage, or trust path is altered. The
build context and data-dir are populated once from config at startup.

## 13. Readiness matrix delta for M13

M13 remains Green. Operator telemetry is widened (node/build/chain identity +
qbind-owned data-dir free space) while every prior Run 379/380 required family
remains present in the release scrape; exposure stays loopback-only and disabled
by default.

## 14. Readiness matrix delta for M14

M14 remains Green. Alert YAML still parses; the newly enabled QbindNodeDiskSpaceLow
references a metric proven present; the future/not-enabled group contains only the
genuinely absent qbind_state_size_bytes. No alert references a non-existent series.

## 15. Current public DevNet readiness status

NOT launch-ready. Observability is an operator-facing telemetry/alerting baseline
on a valueless, resettable DevNet; it does not launch a network.

## 16. Remaining public DevNet blockers

M4 (external seed reachability) remains Yellow / launch-blocking; M6 remains
Yellow/Partial (M4-gated). No live seed/bootnode, faucet, RPC gateway, explorer,
or status page. These are all out of scope for Run 381.

## 17. Public TestNet blockers

All public DevNet blockers above, plus TestNet-grade validator set / economics /
upgrade governance and sustained multi-operator soak - untouched by Run 381.

## 18. MainNet blockers

MainNet custody and MainNet authority rotation/revocation remain Red; C4/C5 must
close first. Untouched by Run 381.

## 19. C4/C5 status

C4 OPEN. C5 OPEN. Run 381 makes no closure claim and touches no
authority-lifecycle / validator-set / epoch / sequence / marker /
LivePqcTrustState surface.

## 20. Tests run

- cargo build -p qbind-node --release --bin qbind-node: OK (release profile,
  finished in ~7m; sha256 26b4f091914436d1952d6e2bce8523f7cb302586b1aaf2ef3908fb666a9e50fc,
  BuildID 3a96efbeadfd6e7ea282449247268e74a8c25507).
- scripts/devnet/run_381_public_devnet_observability_gauges.sh: RESULT=POSITIVE
  (all checks OK; see summary.txt).
- cargo test -p qbind-node --test run_381_public_devnet_observability_gauges_tests:
  6 passed, 0 failed.
- cargo test -p qbind-node --lib: (recorded in the PR run log).
- YAML parse (scrape + alerts): pyyaml_ok for both example files.
- non-claim grep over the observability package: OK.

## 21. Security scans

secret_scanning over all changed files: no secrets. The harness commits no private
key, credential, private hostname, raw log, data dir, or raw /metrics dump; only
publish-safe hashes and status lines appear in the tracked summary. Only loopback
(127.0.0.1) and no external endpoints are used.

## 22. CodeQL

CodeQL (rust) was invoked on the change set and returned: analysis SKIPPED
because the database size is too large (0 alerts, but the analysis did not run to
completion). Per policy this is NOT recorded as "clean". Manual review of the only
production source change (read-only metrics emission plus a guarded cfg(unix)
statvfs(3) call): the syscall return code is checked before any struct field is
read, the path is passed as a validated NUL-terminated CString, and the struct is
zero-initialized; label values are sanitized to [A-Za-z0-9._-] with a length cap,
so no exposition-format injection is possible.

## 23. Provenance

Release binary sha256 26b4f091914436d1952d6e2bce8523f7cb302586b1aaf2ef3908fb666a9e50fc,
BuildID 3a96efbeadfd6e7ea282449247268e74a8c25507, toolchain rustc 1.98.0 / cargo
1.98.0. Metrics observed by live loopback scrape of that binary.

## 24. Honest limitations

- build_id / git_commit render `unknown` unless injected at build time via
  QBIND_BUILD_ID / QBIND_GIT_COMMIT; Run 381 adds the labels but does not add a
  build.rs to auto-populate them (kept minimal and dependency-free).
- qbind_node_data_dir_free_bytes is unix-only (statvfs) and requires --data-dir;
  it is omitted on non-unix targets or when the syscall fails.
- The 5 GiB QbindNodeDiskSpaceLow threshold is a conservative DevNet example, not
  a tuned production floor; operators must set it to their volume size.
- The metrics endpoint is loopback-only with no auth/TLS and must stay loopback.

## 25. Suggested Run 382 next step

Optionally add a build.rs (or CI-injected QBIND_BUILD_ID / QBIND_GIT_COMMIT) so
qbind_node_build_info carries a real git commit / build id in release artifacts,
and/or begin M4 external seed reachability work (out of scope here) which is the
actual launch-blocking gap.
