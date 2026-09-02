# QBIND Public DevNet Readiness Criteria and Gap Matrix

> **Run 396 — readiness-matrix canonicalization / stale-row cleanup (docs + verification harness only; Route A).**
> This run does **not** change any readiness semantics or add functionality. It reconciles the document so every
> checklist, status table, gap matrix, blocker summary, and next-run recommendation agrees with the canonical
> per-item status established by Runs 356–395. The §10 current-status table (and §4/§5 checklists) are the source
> of truth; the older §16 consolidated gap matrix and §17 summary carried legacy statuses for items already
> updated by later runs and are reconciled here. **Canonical status after Run 395:** must-haves **M1–M3, M5,
> M7–M20 Green**, **M4 Yellow / launch-blocking**, **M6 Yellow / Partial**; should-haves **S1–S4, S6 Green**,
> **S5 Yellow**, **S7 Yellow**; **public DevNet remains NOT launch-ready**; **C4 and C5 remain OPEN**;
> TestNet/MainNet untouched (N1–N7 Red). No public CLI flag, no Rust/`build.rs`/runtime change; no
> seed/bootnode/faucet/RPC/explorer/status-service deployment. Verified by
> `scripts/devnet/run_396_public_devnet_readiness_matrix_canonicalization.sh`; evidence
> `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_396.md`.

**Status:** Canonical (Run 355 deliverable — public network release-readiness track, kickoff; updated Run 356 —
M1/M19/M20 moved to Green with the published DevNet genesis package; updated Run 357 — M4 moved Red → Yellow with
the published seed-list format + placeholder artifact, M4 remains a launch blocker; updated Run 358 —
M5/M17/M18 moved Yellow → Green with the published external operator onboarding package
(`docs/release/public-devnet/operator/`), M6 stays Yellow/Partial pending an operator-facing identity-generation
command, and M3/M4 are unchanged so public DevNet remains NOT launch-ready; updated Run 359 — M2 moved Yellow → Green
and M3 moved Red → Green with the published release-binary provenance + reproducibility/BuildID package
(`docs/release/public-devnet/binary/`): a canonical operator-verifiable provenance record plus a same-host,
clean-tree two-build reproducibility result (byte-identical `qbind-node`, SHA-256 `f916af6d…b22990`, stable ELF
BuildID `274fdaf3…5208b`); M4 remains Yellow/launch-blocking and M6–M15 remain Yellow/Red, so public DevNet remains
NOT launch-ready; updated Run 360 — M10 (public P2P port posture) and M11 (peer admission policy) moved Yellow → Green
with the published P2P posture package (`docs/release/public-devnet/p2p/`), validated against the existing `qbind-node`
CLI/transport/trust-bundle surfaces; M12 (abuse/DoS protections) stays Yellow/Partial — the per-peer rate limiter and
metrics are documented against source, but its thresholds are hardcoded (not operator-configurable) and no
per-connection-rate limiter is exposed; M4 remains Yellow/launch-blocking and M6–M9/M13–M15 unchanged, so public DevNet
remains NOT launch-ready; updated Run 361 — M12 stays Yellow but is **strengthened**: a source/test-only
operator-configurable abuse/DoS config model plus a pure, deterministic bounded inbound connection-rate limiter boundary
landed (`crates/qbind-node/src/public_devnet_abuse_dos_config.rs` + `tests/run_361_public_devnet_abuse_dos_hardening_tests.rs`),
with the safe default preserving the current `1000` msg/s + `100` burst behavior and leaving the connection limiter disabled;
no runtime wiring, no CLI flag, no default change — M12 Green is **deferred to Run 362** pending runtime wiring +
release-binary evidence; M4 remains Yellow/launch-blocking and M6–M9/M13–M15 unchanged, so public DevNet
remains NOT launch-ready; updated Run 362 — M12 remains **Yellow/Partial** but is further **strengthened**:
the Run 361 abuse/DoS config model + bounded inbound connection-rate limiter are now **wired into the live
`p2p_tcp` accept loop** behind runtime-owned, default-off state, a `qbind_p2p_connection_rate_drop_total`
metric is added, and hidden/devnet-only operator CLI flags expose the connection-rate posture; defaults are
preserved bit-for-bit and release-binary evidence landed (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md`).
**M12 does NOT move Green** because the live per-peer message-rate limiter is still not operator-configurable at
runtime (the message-rate flags are validated but inert against the live per-peer limiter); M4 remains
Yellow/launch-blocking and M6–M9/M13–M15 unchanged, so public DevNet remains NOT launch-ready);
updated Run 363 — M12 stays **Yellow/Partial** but is further **strengthened**: the per-peer
message-rate runtime override is wired into the live `AsyncPeerManagerImpl` `PeerRateLimiter`
construction path at source/test level (the Run 362 hidden `--p2p-max-messages-per-second` /
`--p2p-burst-allowance` flags now affect the live limiter), defaults preserved; release-binary
evidence deferred to Run 364; updated Run 364 — M12 stays **Yellow/Partial** (strengthened):
release-binary evidence for **both** controls landed
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md`; real `target/release/qbind-node` + release helper,
7/7 scenarios). **M12 does NOT move Green** because the per-peer message-rate override reaches only
the live peer-manager *construction path* — the deployed `qbind-node` (`main.rs` / `p2p_node_builder`)
does not yet thread the CLI-derived `peer_rate_limiter_config` into its live `AsyncPeerManagerImpl`,
so per-peer operator effect on a running node is not yet delivered; the connection-rate limiter is
production-wired and release-proven. M4 remains Yellow/launch-blocking; public DevNet remains NOT
launch-ready;
updated Run 365 — M12 stays **Yellow/Partial** (strengthened): the deployed `qbind-node` builder now
threads the CLI-derived `peer_rate_limiter_config` into the live `AsyncPeerManagerImpl` construction
path (`P2pNodeBuilder::build_deployed_peer_manager`), closing the source/test gap Run 364 flagged
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_365.md`). **M12 does NOT move Green** — release-binary
end-to-end evidence is deferred to Run 366. Defaults preserved; connection-rate limiter behaviour
unchanged; no new public CLI flags; M4 remains Yellow/launch-blocking; public DevNet remains NOT
launch-ready;
updated Run 366 — M12 stays **Yellow/Partial** (strengthened): release-binary evidence now proves the
deployed `P2pNodeBuilder` path (`with_abuse_dos_runtime_config` → `deployed_peer_rate_limiter_config` →
`build_deployed_peer_manager`) honors **both** the connection-rate limiter and the per-peer message-rate
override on real `target/release/qbind-node` + a release helper (8/8 scenarios,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md`,
`docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/`). **M12 does NOT move
Green:** a running `qbind-node` cannot be driven over its live P2P inbound/message socket path in this
environment because DevNet runs in LocalMesh mode (`--enable-p2p` ignored), so the end-to-end evidence
is deployed-builder-path release-binary, not live-socket. Defaults preserved; no new public CLI flags;
no production source change; M4 remains Yellow/launch-blocking; public DevNet remains NOT launch-ready.
updated Run 367 — M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**: Run 367
fixes the Run 366 blocker by launching the real `target/release/qbind-node` in a P2P-capable loopback
mode (`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`) and proves the accept-loop
**connection-rate** control **live-socket** — under-budget inbound TCP connections admitted with
`qbind_p2p_connection_rate_drop_total` at 0, over-budget refused with the metric incrementing by exactly
the over-budget count (10 connections, max 3 → 3 accepted / 7 refused, metric = 7), observed on the live
`/metrics` endpoint (`crates/qbind-node/examples/run_367_public_devnet_abuse_dos_live_socket_helper.rs`,
`scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md`,
`docs/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary/`, helper 8/8; no production
source change). The per-peer **message-rate** control is still NOT driven over an admitted live peer
socket (it enforces on the `AsyncPeerManagerImpl` receive path and needs a second KEMTLS peer flood
harness), so it remains deployed-builder-path evidence; because M12 Green requires **both** controls
over a live socket, Green is deferred to a Run 368 two-node message-flood harness. Defaults preserved;
M4 remains Yellow/launch-blocking; public DevNet remains NOT launch-ready.
updated Run 368 — M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**. Run 368
strengthens the per-peer **message-rate** evidence from Run 367's synchronous construction-path
`PeerRateLimiter::allow()` proof to a **real admitted-peer socket** proof: it stands up a loopback TCP
socket pair, registers one side as an admitted peer on a live `AsyncPeerManagerImpl` (which owns the
per-peer `PeerRateLimiter`), and floods `NetMessage` frames — under-budget accepted (0 drops),
over-budget dropped (≈75 of 80), with `qbind_net_per_peer_drops_total{...,reason="rate_limit"}` /
`total_rate_limit_drops()` incrementing — and re-runs the Run 367 connection-rate live-socket proof as a
regression (`crates/qbind-node/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper.rs`,
`scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md`,
`docs/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary/`, helper 9/9; no
production source change). **Decision gate = Route C:** the **deployed** `qbind-node` inbound path
(`TcpKemTlsP2pService::subscribe` → `P2pInboundDemuxer` → handlers) does NOT consult the
`PeerRateLimiter`, and `build_deployed_peer_manager()` / `AsyncPeerManagerImpl` is never spawned by
`main.rs`, so the per-peer proof is at the `AsyncPeerManagerImpl` layer (plain-TCP admitted peer), not
the deployed socket and not KEMTLS mutual-auth. Because M12 Green requires **both** controls over the
**deployed** live socket, M12 stays Yellow/Partial; the remaining blocker is wiring the `PeerRateLimiter`
onto the deployed TcpKemTls receive path (recommended Run 369). Defaults preserved; M4 remains
Yellow/launch-blocking; public DevNet remains NOT launch-ready.
updated Run 369 — M12 stays **Yellow/Partial** but is further **strengthened — deployed TcpKemTls
receive-path source/test wiring landed**, and **does NOT move Green**. Run 369 closes the Run 368
Route-C blocker at the source/test level: the deployed inbound receive path
(`TcpKemTlsP2pService::read_loop` → `inbound_tx` → `subscribe()` → `P2pInboundDemuxer` → handlers) now
consults a per-peer `PeerRateLimiter` via the new `DeployedInboundPerPeerLimiter` adapter
(`crates/qbind-node/src/deployed_inbound_per_peer_limiter.rs`), installed by `P2pNodeBuilder::start()`
from the CLI-derived `deployed_peer_rate_limiter_config()` (default `1000` msg/s + `100` burst). An
over-budget inbound frame is dropped before demuxer dispatch, the adapter's per-peer drop counter (and
the existing `qbind_net_per_peer_drops_total{reason="rate_limit"}` metric when a `NodeMetrics` handle is
installed) increments, the connection is not torn down, and the connection-rate limiter /
`qbind_p2p_connection_rate_drop_total` metric are never touched
(`crates/qbind-node/tests/run_369_public_devnet_deployed_per_peer_limiter_wiring_tests.rs`, 24/24;
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_369.md`). Bucket keying derives a `PeerId` from the first 8 bytes
of the connection `NodeId` for rate-limit bucket selection only — **not** an identity/auth claim. **M12
does NOT move Green:** this is a source/test run; release-binary live-socket deployed-path evidence
(both connection-rate and per-peer message-rate over the deployed TcpKemTls receive path) is deferred to
Run 370. Defaults preserved; no new public CLI flags; M4 remains Yellow/launch-blocking; public DevNet
remains NOT launch-ready.
updated Run 370 — M12 stays **Yellow/Partial** but is further **strengthened — deployed per-peer drop
metric wired end-to-end (Route B) + release-binary live-socket evidence**, and **does NOT move Green**.
Run 370 closes the Run 369 "honest limitation" that the deployed `DeployedInboundPerPeerLimiter` was
installed with `metrics = None` (the builder held a `P2pMetrics`, not the `NodeMetrics` that owns the
per-peer counter): a narrow, default-preserving source change threads an optional live `NodeMetrics`
handle through `P2pNodeBuilder::with_node_metrics` and the shared
`build_deployed_inbound_per_peer_limiter()` seam that `start()` uses, wired in `main.rs` with the SAME
`Arc<NodeMetrics>` the live `/metrics` endpoint scrapes, so a per-peer message-rate drop on the deployed
`TcpKemTls` read loop now bumps the exported `qbind_net_per_peer_drops_total{reason="rate_limit"}` counter
(`crates/qbind-node/tests/run_370_public_devnet_deployed_live_socket_m12_tests.rs`, 20/20). The Run 370
release harness proves on real `target/release/qbind-node`: the **connection-rate** control live-socket
(10 inbound TCP connections, max 3 → 3 accepted / 7 refused, live `qbind_p2p_connection_rate_drop_total = 7`),
default no-flag posture (connection limiter disabled, per-peer `1000/100`), invalid/unbounded/MainNet
configs fail the binary closed, hidden CLI surface preserved; and the Run 370 release helper (10/10) drives
the exact deployed adapter object `start()` installs on the read loop and shows the exported per-peer
counter incrementing on over-budget drops with the two controls independent
(`crates/qbind-node/examples/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_helper.rs`,
`scripts/devnet/run_370_public_devnet_abuse_dos_m12_deployed_live_socket_release_binary.sh`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_370.md`). **Decision gate = Route B.** **M12 does NOT move Green:**
the residual blocker is a **KEMTLS-admitted deployed per-peer socket flood** — driving over-budget frames
over a real second-peer KEMTLS handshake through the deployed read loop and observing the exported metric
on live `/metrics` — which this run does not stand up; the deployed per-peer evidence is the deployed
adapter object exercised in the release helper, not a fully live KEMTLS socket flood. Defaults preserved;
no new public CLI flags; no admission/trust/wire-format change; M4 remains Yellow/launch-blocking; public
DevNet remains NOT launch-ready.
updated Run 371 — M12 **moves Green for the abuse/DoS deployed live-socket controls** (both the
connection-rate and the KEMTLS-admitted deployed per-peer message-rate control now proven over real
sockets on the release binary), closing the Run 370 residual blocker. **Decision gate = Route A (no
production source change).** Run 370 already wired the exported
`qbind_net_per_peer_drops_total{reason="rate_limit"}` counter end-to-end onto the deployed
`TcpKemTlsP2pService::read_loop` per-peer limiter, so the only remaining gap was the *driver*. Run 371 uses
production public APIs to stand up a **second KEMTLS-admitted peer** (the Run 371 helper in `dial-flood`
mode, built from `P2pNodeBuilder`) that completes a **real KEMTLS mutual-auth handshake over a real
loopback socket** against a separate running `target/release/qbind-node`, then floods structured
`P2pMessage::Consensus` frames (discriminator `0`, so they reach the deployed per-peer limiter after
`decode_frame`). Under-budget frames → **0 per-peer drops** (metric ABSENT); over-budget frames → live
`/metrics` exposes `qbind_net_per_peer_drops_total{reason="rate_limit"}` incrementing (~47 of 60 in a
representative run) with the connection kept up (no teardown). The Run 367/370 connection-rate live-socket
proof is preserved in the same harness (10 inbound TCP connections, max 3 → 3 accepted / 7 refused, live
`qbind_p2p_connection_rate_drop_total = 7`); the two controls are independent; invalid/unbounded/MainNet
configs fail the binary closed; hidden CLI surface preserved; helper scenario suite 10/10
(`crates/qbind-node/examples/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_helper.rs`,
`scripts/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary.sh`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`,
`docs/devnet/run_371_public_devnet_m12_kemtls_per_peer_live_socket_flood_release_binary/`). **M12 Green is
scoped to these two abuse/DoS deployed live-socket controls only** — it does **not** move M4/M6, does not
make public DevNet launch-ready, and does not close C4/C5. The KEMTLS flood runs over loopback with the
default deterministic test-grade KEM keypairs and default (Disabled) mutual-auth admission; no production
source change; no admission/trust/wire-format change; M4 remains Yellow/launch-blocking; public DevNet
remains NOT launch-ready.
updated Run 372 — M12 **remains Green** with added **strict-mutual-auth + multi-peer concurrent flood**
hardening evidence (still **Route A**, no production source change). Run 372 re-proves the Run 371 result
under stricter admission and multi-peer conditions: the deployed `target/release/qbind-node` runs with the
pre-existing **public** flag `--p2p-mutual-auth required`, and **two** KEMTLS-admitted peers (an honest
under-budget peer and an abusive over-budget peer, the Run 372 helper in `dial-flood` mode) each complete
the full `MutualAuthMode::Required` handshake before flooding the deployed `TcpKemTlsP2pService::read_loop`.
On live `/metrics` the abusive peer's drops are isolated to its **own** per-peer bucket
(`qbind_net_per_peer_drops_total{peer="<abusive key>",reason="rate_limit"}` > 0) while the honest peer's
bucket label is **ABSENT** — the abusive flood does not consume the honest peer's budget. The release helper
additionally proves the strict-auth path with **production-grade `PqcRootMode::PqcStaticRoot`** material
(runtime-generated ML-DSA-44 + ML-KEM-768, never written to disk). The connection-rate live-socket
regression and control-independence are preserved; helper scenario suite 13/13
(`crates/qbind-node/examples/run_372_public_devnet_m12_strict_auth_multi_peer_flood_helper.rs`,
`scripts/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary.sh`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_372.md`,
`docs/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary/`). **No new public CLI
flags** (`--p2p-mutual-auth` is pre-existing and public; abuse/DoS flags stay hidden); strict mutual-auth
only **tightens** admission; no trust/wire-format change; M4/M6 unchanged; public DevNet remains NOT
launch-ready; C4/C5 remain OPEN.
updated Run 373 — M12 **remains Green** with added **cross-process `PqcRootMode::PqcStaticRoot`
strict-auth** hardening evidence (still **Route A**, no production source change). Run 373 extends Run 372's
**in-process** static-root proof to the standalone binary: `devnet_pqc_root_helper` mints **temporary**
ML-DSA-44 root + ML-KEM-768 leaf material (root signing key in memory only, never on disk) and the deployed
`target/release/qbind-node` runs with the pre-existing **public** flags `--p2p-mutual-auth required
--p2p-pqc-root-mode pqc-static-root --p2p-trusted-root … --p2p-leaf-cert … --p2p-leaf-cert-key …` (live
`/metrics` exports `qbind_p2p_pqc_root_mode 1` / `qbind_p2p_pqc_roots_configured 1`). **Two** KEMTLS-admitted
peers built from the same operator material (honest under-budget + abusive over-budget) each complete the
full `MutualAuthMode::Required` + PqcStaticRoot handshake; on live `/metrics` the abusive peer's drops
isolate to its **own cert-derived** per-peer bucket while the honest peer's label is **ABSENT**. The
connection-rate live-socket regression and control-independence are preserved; helper suite 13/13
(`crates/qbind-node/examples/run_373_public_devnet_m12_pqc_static_root_cross_process_helper.rs`,
`scripts/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary.sh`,
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_373.md`,
`docs/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary/`). **No new public CLI
flags** (the static-root/strict-auth flags are pre-existing and public; abuse/DoS flags stay hidden); no
trust-bundle/wire-format change; M4/M6 unchanged; public DevNet remains NOT launch-ready; C4/C5 remain OPEN.
Updated Run 395 — **S6 alert-rule/scrape-config moves Red → Green (reconciled; Route A) and S5
status page moves Red → Yellow (should-have; Route B — docs + schema + verification harness only, no
production source change)**: Run 395 resolves the two remaining observability-adjacent should-haves.
For **S6**, the readiness matrix previously kept "alert-rule definitions / scrape config shipped
alongside the metrics baseline" as Red / "None shipped" even though **M14** already recorded the
alert rules, scrape config, runbook, and machine-readable Prometheus examples as shipped and
YAML-verified in Runs 379–381 (`docs/release/public-devnet/observability/ALERT_RULES.md`,
`SCRAPE_CONFIG.md`, `RUNBOOK.md`, `prometheus-scrape.example.yml`, `prometheus-alerts.example.yml`).
Run 395 reconciles this inconsistency honestly by moving **S6 Red → Green** citing those already
shipped files (both YAML re-parsed by the Run 395 harness) — **no** alert/scrape content is
duplicated. For **S5**, no live status service is deployed (a live aggregate health view depends on
M4, which is Yellow); instead a **publish-safe static** status-page decision + future health-view
schema/example package is published under `docs/release/public-devnet/status/` (`README.md`,
`STATUS_PAGE_DECISION.md`, `STATUS_HEALTH_VIEW_SCHEMA.json`, `EXAMPLE_STATUS_HEALTH_VIEW.json`,
`SAFETY.md`, `VERIFY.md`) with a fixed safety envelope (`launch_ready:false`, `uptime_sla:false`,
`example_data_only`, no TestNet/MainNet readiness, C4/C5 not closed) and redaction rules; the example
validates against the schema and is marked `data_source: static-example`. **S5 stays Yellow, not
Green** — no externally usable status page is deployed or maintained; live status is deferred to M4.
Harness `scripts/devnet/run_395_public_devnet_status_s6_reconciliation.sh` (`RESULT=POSITIVE`),
evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_395.md` and archive
`docs/devnet/run_395_public_devnet_status_s6_reconciliation/`. **No production Rust source change; no
`build.rs` change; no new public CLI flag.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial,
S7 stays Yellow, M12/M13/M14/M15/M16 remain Green; public DevNet remains NOT launch-ready; C4/C5
remain OPEN; MainNet/TestNet untouched.
Updated Run 401 — **M6 better documented but remains Yellow/Partial (Route B — docs + verification
harness only, no production source change, no `build.rs` change, no new CLI flag)**: publishes the
public DevNet **operator identity continuity** package under
`docs/release/public-devnet/identity/` — `IDENTITY_CONTINUITY.md` (durable operator identity reuse
across DevNet restarts: reuse the same `leaf.kem.sk.bin` + `leaf.cert.bin` to preserve
`node_id`/`peer_id`; public-vs-private material handling; exactly what may be reused; what must not be
rotated/edited by hand) and `ROTATION_REVOCATION_DEFERRAL.md` (production rotation/revocation is **NOT
implemented** and is **explicitly deferred** to C4/C5/MainNet). Verified against the **existing**
first-class `qbind-node identity` (`generate`/`verify`/`print-public`/`seed-candidate`/`register-check`)
surfaces by `scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh` (`RESULT=POSITIVE`), with
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_401.md` and archive
`docs/devnet/run_401_public_devnet_m6_identity_continuity/`. It adds **no** CLI flag, opens **no** port,
applies **no** trust bundle, and mutates **no** validator/epoch/sequence/marker/`LivePqcTrustState`
state. **M6 does NOT move Green** — no live public DevNet to register a continuous identity into
(M4-gated) and operator-supplied root reuse/rotation/revocation is C4/C5-OPEN. **M4 stays
Yellow/launch-blocking; S5/S7 stay Yellow; M12–M16 remain Green; public DevNet stays NOT launch-ready;
C4/C5 remain OPEN; MainNet/TestNet untouched.**
Updated Run 402 — **launch go/no-go gate + blocker register published; no readiness item moves (Route B —
docs + verification harness only, no production source change, no `build.rs` change, no new CLI flag)**:
publishes the operator-facing public DevNet **launch decision gate** — `docs/release/public-devnet/LAUNCH_GO_NO_GO.md`
(DevNet-only / experimental / resettable / no-value label; current decision **NO-GO / NOT launch-ready**;
Green-items summary; blocking-items summary; exact M4 Green prerequisites; exact M6 Green prerequisites;
S5/S7 M4-gated explanation; C4/C5 OPEN statement; TestNet/MainNet non-claim; final go/no-go rule) and
`docs/release/public-devnet/BLOCKER_REGISTER.md` (the M4/M6/S5/S7 blockers with owner/action/evidence-needed/status
columns; "no launch until every must-have is Green and launch is explicitly in scope"). Verified against this
canonical readiness matrix by `scripts/devnet/run_402_public_devnet_launch_go_no_go_gate.sh` (`RESULT=POSITIVE`),
with `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_402.md` and archive
`docs/devnet/run_402_public_devnet_launch_go_no_go_gate/`. It adds **no** CLI flag, opens **no** port, deploys
**no** seed/bootnode/faucet/RPC/explorer/status service, applies **no** trust bundle, and mutates **no**
validator/epoch/sequence/marker/`LivePqcTrustState` state. **No readiness item moves Green** — this run adds
clarity only. **M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow; M1–M3/M5/M7–M20
remain Green; public DevNet stays NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.**
Updated Run 403 — **release package index + operator verification map published; no readiness item moves
(Route B — docs + verification harness only, no production source change, no `build.rs` change, no new CLI
flag)**: publishes the operator/reviewer public DevNet **navigation index** — `docs/release/public-devnet/ARTIFACT_INDEX.md`
(DevNet-only / experimental / resettable / no-value label; thirteen artifact groups — genesis; binary
provenance/reproducibility/manifest; operator quickstart; identity; P2P/peer admission;
network/seed-list/M4 checklist; security/PQC trust bootstrap; observability/alerting; ops/reset/incident
response; recovery/backup/upgrade/rollback; status decision; launch go/no-go; blocker register — each with
path / purpose / readiness item / verification command or document / current status / non-claims) and
`docs/release/public-devnet/OPERATOR_VERIFICATION_MAP.md` (recommended read orders for an external operator,
a security reviewer, and a release manager; an exact verification map for genesis / binary provenance /
identity / P2P posture / observability / recovery / go-no-go verification; and a four-part launch stop rule:
no launch while M4/M6 Yellow, no `devnet-seeds.live.json` without real M4 evidence, no TestNet/MainNet
readiness claim, no C4/C5 closure claim). Verified against the on-disk package tree and this canonical
readiness matrix by `scripts/devnet/run_403_public_devnet_artifact_index_verification_map.sh`
(`RESULT=POSITIVE`), with `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_403.md` and archive
`docs/devnet/run_403_public_devnet_artifact_index_verification_map/`. It adds **no** CLI flag, opens **no**
port, deploys **no** seed/bootnode/faucet/RPC/explorer/status service, applies **no** trust bundle, and
mutates **no** validator/epoch/sequence/marker/`LivePqcTrustState` state. **No readiness item moves Green** —
this run adds navigation + clarity only. **M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7
stay Yellow; M1–M3/M5/M7–M20 remain Green; public DevNet stays NOT launch-ready; C4/C5 remain OPEN;
MainNet/TestNet untouched.**
Updated Run 404 — **package integrity manifest published; no readiness item moves (Route B — docs + schema +
verification harness only, no production source change, no `build.rs` change, no `Cargo.toml` change, no new
CLI flag)**: publishes the operator/reviewer public DevNet **package integrity manifest** —
`docs/release/public-devnet/PACKAGE_INTEGRITY_MANIFEST.schema.json` (draft-07 schema fixing `manifest_version`,
`generated_for_run: 404`, `scope: public-devnet-docs-release-package`, the eight safety labels, `package_root:
docs/release/public-devnet`, per-file `relative_path`/`sha256`/`byte_size`/`artifact_group`/`readiness_item`/
`status`/`verification_reference` entries, and the eleven non-claim booleans all `false`),
`PACKAGE_INTEGRITY_MANIFEST.example.json` (a schema-valid example over 16 covered files — one `VERIFY.md` anchor
per artifact group plus the five top-level package documents — whose per-file SHA-256 + byte size match the
current on-disk tree), and `PACKAGE_INTEGRITY.md` (operator guide: how to regenerate the manifest, verify file
hashes, how it differs from binary provenance, why it is not a launch artifact, why it moves no readiness item,
why C4/C5 remain OPEN, and how to run the integrity check before `OPERATOR_VERIFICATION_MAP.md`). Verified
against the on-disk package tree and this canonical readiness matrix by
`scripts/devnet/run_404_public_devnet_package_integrity_manifest.sh` (`RESULT=POSITIVE`; 21 checks), with
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_404.md` and archive
`docs/devnet/run_404_public_devnet_package_integrity_manifest/`; `ARTIFACT_INDEX.md` and
`OPERATOR_VERIFICATION_MAP.md` are narrowly updated to reference the integrity check. It adds **no** CLI flag,
opens **no** port, deploys **no** seed/bootnode/faucet/RPC/explorer/status service, applies **no** trust bundle,
and mutates **no** validator/epoch/sequence/marker/`LivePqcTrustState` state. **No readiness item moves Green** —
this run adds integrity coverage only. **M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay
Yellow; M1–M3/M5/M7–M20 remain Green; public DevNet stays NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet
untouched.**
Updated Run 405 — **full-tree package integrity verifier published; no readiness item moves (Route B — docs +
schema + shell + optional CI only, no production source change, no `build.rs` change, no `Cargo.toml` change, no new
CLI flag)**: adds the operator/reviewer public DevNet **full-tree package integrity verifier** —
`docs/release/public-devnet/PACKAGE_INTEGRITY_FULL_TREE_MANIFEST.schema.json` (draft-07 schema fixing
`manifest_version`, `generated_for_run: 405`, `scope: public-devnet-docs-release-package-full-tree`,
`coverage: full-tree`, the eight safety labels, `package_root: docs/release/public-devnet`, `file_count`, minimal
per-file `relative_path`/`sha256`/`byte_size` entries, and the eleven non-claim booleans all `false`),
`PACKAGE_INTEGRITY_FULL_TREE.md` (guide: how full-tree verification differs from the Run 404 anchor manifest, why the
full-tree manifest is generated transiently rather than committed, how to run the verifier locally and in CI, why it
is not binary provenance, why it is not launch evidence, and why M4/M6/S5/S7 and C4/C5 are unchanged), the harness
`scripts/devnet/run_405_public_devnet_full_tree_package_integrity.sh`, and the least-privilege
`.github/workflows/public-devnet-package-integrity.yml` (contents:read; no secrets; no deployment; no commit/push;
runs only the Run 405 verifier). The verifier generates a full-tree manifest into a temp dir **outside** the package
tree (never committed) covering **every** publish-safe file under `docs/release/public-devnet` (86 files), validates
it against the schema, asserts the manifest file set equals the on-disk set, re-hashes every file, re-validates the
Run 404 anchor manifest (whose three narrowly-edited entries had their SHA-256/byte size refreshed with no status
change), and runs the secret/non-claim scans. Verified against the on-disk package tree and this canonical readiness
matrix by that harness (`RESULT=POSITIVE`; 21 checks), with `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_405.md` and archive
`docs/devnet/run_405_public_devnet_full_tree_package_integrity/`; `ARTIFACT_INDEX.md` and
`OPERATOR_VERIFICATION_MAP.md` are narrowly updated to reference full-tree verification (and the external-operator
read-order numbering was cleaned to a consecutive 1..11). It adds **no** CLI flag, opens **no** port, deploys **no**
seed/bootnode/faucet/RPC/explorer/status service, applies **no** trust bundle, and mutates **no**
validator/epoch/sequence/marker/`LivePqcTrustState` state. **No readiness item moves Green** — this run adds full-tree
integrity coverage only. **M4 stays Yellow/launch-blocking; M6 stays Yellow/Partial; S5/S7 stay Yellow;
M1–M3/M5/M7–M20 remain Green; public DevNet stays NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.**
Updated Run 374 — **M6 materially narrowed but remains Yellow/Partial**: a stable, release-built operator-facing
identity **generation + verification** package is published under
`docs/release/public-devnet/identity/` (`README.md`, `IDENTITY_GENERATION.md`, `IDENTITY_VERIFY.md`,
`OPERATOR_IDENTITY_SCHEMA.json`, `EXAMPLE_PUBLIC_IDENTITY.json`, `SAFETY.md`, `VERIFY.md`) backed by the
release-built example `run_374_public_devnet_identity_generation_helper` (Route B — no production source change,
no new `qbind-node` CLI flag), the harness `scripts/devnet/run_374_public_devnet_identity_generation.sh`, and
evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_374.md`. The helper generates node / seed / validator-candidate
identity material (root ML-DSA-44 signing key in memory only; ML-KEM-768 leaf secret written `0600` to an
operator-selected temp path), emits a schema-validated public identity JSON, deterministically re-derives the
NodeId from the public cert, inserts into the Run 357 seed-list without schema violation, and is accepted by a
real loopback `target/release/qbind-node` boot under `--p2p-mutual-auth required --p2p-pqc-root-mode
pqc-static-root` (`qbind_p2p_pqc_root_mode 1`); MainNet/TestNet generation and mismatched material fail closed.
M6 stays Yellow/Partial because generation is a release-built example (not a first-class CLI subcommand) and no
live registration path exists (M4-gated). M4 remains Yellow/launch-blocking; M12 remains Green; public DevNet
remains NOT launch-ready; C4/C5 remain OPEN.
Updated Run 375 — **M6 first-class generation half now Green-for-scope; M6 as a whole remains Yellow/Partial**:
the Run 374 identity-generation + verification workflow is promoted into a stable, first-class
`qbind-node identity` command (`generate` / `verify` / `print-public` / `seed-candidate`) implemented in
`crates/qbind-node/src/identity_cli.rs` (Route B — DevNet-gated, default-safe; only reached when `identity` is
the first CLI token; no runtime/wire/admission change). The Run 374 example is now a thin wrapper over the same
implementation, so all Run 374 evidence stays reproducible. Evidence:
`scripts/devnet/run_375_public_devnet_identity_cli.sh`,
`crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs`, and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`. **M6 does NOT move fully Green** because a **live registration
path** into a running public DevNet is still absent (M4-gated) and operator-supplied root reuse/rotation/
revocation remains C4/C5-OPEN. M4 remains Yellow/launch-blocking; M12 remains Green; public DevNet remains NOT
launch-ready; C4/C5 remain OPEN. No M4 Green and no C4/C5 closure is claimed.
Updated Run 376 — **M6 registration/admission-check half now Green-for-scope; M6 as a whole remains
Yellow/Partial**: a **non-mutating** `qbind-node identity register-check` subcommand is added to
`crates/qbind-node/src/identity_cli.rs` (Route B — DevNet-gated, default-safe; only reached when
`identity` is the first CLI token; no runtime/wire/admission change). It reads public material only,
validates `public-identity.json` against the operator-identity schema rules, maps it into a
`devnet-seed-list.schema.json` `seed_node` candidate, verifies the NodeId deterministically from the
leaf cert, and fails closed on embedded private material, malformed fields, wrong environment,
MainNet/TestNet material, mismatched cert, `status=live` without reachability evidence, and
`planned`+reachability. Evidence:
`scripts/devnet/run_376_public_devnet_identity_registration.sh`,
`crates/qbind-node/tests/run_376_public_devnet_identity_registration_tests.rs` (14 tests), and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md`. **M6 does NOT move fully Green** because the *live*
registration path is inseparable from M4 live seed reachability, which has not landed; the verdict
explicitly sets `socket_opened=false`, `runtime_state_mutated=false`, `live_reachability_claim=false`,
`m4_green_claim=false`, `c4_c5_closure_claim=false`. M4 remains Yellow/launch-blocking; M12 remains
Green; public DevNet remains NOT launch-ready; C4/C5 remain OPEN. No M4 Green and no C4/C5 closure is
claimed.
Updated Run 377 — **M4 remains Yellow/launch-blocking (strengthened, Partial-positive); no Green move**:
Run 377 produces bounded M4 live seed/bootnode reachability evidence with **no production source
change** — the `qbind-node identity register-check --status live --reachability-evidence <ref>`
admission gate already exists (Run 376). **Decision gate = Route B (Partial-positive):** in this
sandboxed environment only **loopback / same-host** reachability can be demonstrated — a real release
`qbind-node` P2P listener is booted on `127.0.0.1:<port>` (pre-existing `--network-mode p2p
--enable-p2p` default posture) and a same-host TCP dial is accepted (`[P2P] Accepted connection`), but
**external reachability from outside the seed operator's own host/NAT is NOT proven**, so **M4 does NOT
move Green**. The run lands a schema-valid **preflight** live-seed candidate
(`docs/release/public-devnet/network/devnet-seeds.live-candidate.json`, single entry `status: planned`,
real Run-375-path public `node_id`/`peer_id`, RFC 5737 host, null reachability — no false live claim), a
reachability evidence record (`docs/release/public-devnet/network/reachability/RUN_377_qbind-devnet-seed-1.md`),
`scripts/devnet/run_377_public_devnet_live_seed_reachability.sh`,
`crates/qbind-node/tests/run_377_public_devnet_live_seed_reachability_tests.rs` (4 tests), and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_377.md`. The live admission gate is release-proven (admits a
cert-verified live candidate WITH an evidence reference; fails closed WITHOUT it and on
`planned`+reachability) yet still sets `m4_green_claim=false` / `live_reachability_claim=false` — it is a
structural admission decision, not a reachability proof. M6 remains Yellow/Partial; M12 remains Green;
public DevNet remains NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.
Updated Run 378 — **M4 remains Yellow/launch-blocking (Route C — no safe external seed infrastructure);
no Green move**: Run 378 attempts **Route A** (deploy/use a real externally reachable seed and prove
reachability from an **independent external vantage point**) with **no production source change**. The
sandboxed environment has **no external ingress and no independent external vantage point**, so a real
endpoint cannot be exposed and external reachability from outside the seed operator's own host/NAT
**cannot be proven** — recorded honestly as **Route C** rather than fabricating an external result, so
**M4 does NOT move Green**. Run 378 re-proves the `register-check --status live --reachability-evidence
<ref>` admission gate (admits a cert-verified live candidate WITH an evidence reference; fails closed
WITHOUT it and on `planned`+reachability; `m4_green_claim=false`) and the loopback preflight, and lands a
Run 378 reachability record
(`docs/release/public-devnet/network/reachability/RUN_378_qbind-devnet-seed-1.md`, documenting the Route A
infrastructure prerequisites), `scripts/devnet/run_378_public_devnet_external_seed_reachability.sh`
(`RESULT=NEGATIVE-FOR-EXTERNAL`), `crates/qbind-node/tests/run_378_public_devnet_external_seed_reachability_tests.rs`
(4 tests), and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_378.md`. The committed live-seed candidate stays
`status: planned` with null reachability (text refreshed to reference Run 378). M6 remains Yellow/Partial;
M12 remains Green; public DevNet remains NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.
Updated Run 388 — **M4 remains Yellow/launch-blocking (Route C — no safe external seed infrastructure);
no Green move**: Run 388 executes the same **Route A** objective as Run 378 (deploy/use a real externally
reachable seed and prove reachability from an **independent off-host vantage point**) with **no production
source change**, and reaches the **same Route C finding** — the sandboxed environment has **no external
ingress and no independent off-host vantage point**, so external reachability **cannot be proven** and
**M4 does NOT move Green** (Run 386/387 preflight posture `signed_release=false` / `slsa_grade=false` is
unchanged). Run 388 re-proves the `register-check --status live --reachability-evidence <ref>` admission
gate (admits a cert-verified live candidate WITH an evidence reference; fails closed WITHOUT it and on
`planned`+reachability; `m4_green_claim=false`) and the loopback preflight, and lands a Run 388 reachability
record (`docs/release/public-devnet/network/reachability/RUN_388_qbind-devnet-seed-1.md`, documenting the
Route A infrastructure prerequisites),
`scripts/devnet/run_388_public_devnet_m4_external_seed_reachability.sh` (`RESULT=NEGATIVE-FOR-EXTERNAL`),
`crates/qbind-node/tests/run_388_public_devnet_m4_external_seed_reachability_tests.rs` (4 tests), and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_388.md`. The committed live-seed candidate stays `status: planned`
with null reachability (text refreshed to reference Run 388). M6 remains Yellow/Partial; M12/M13/M14 remain
Green; public DevNet remains NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.
Updated Run 393 — **M4 remains Yellow/launch-blocking (Route C — no safe external seed infrastructure);
no Green move**: Run 393 executes the **Route A** objective (deploy/validate a real externally reachable
seed under strict KEMTLS static-root, pin the Run 356 genesis, and prove external TCP + KEMTLS
reachability from an independent off-host vantage point) following the Run 392 seed-node operations
runbook / M4 Route-A checklist, and reaches the **same Route C finding** as Run 378/388/391 (no external
ingress / no independent off-host vantage point). External TCP + KEMTLS reachability is **NOT proven**, so
**M4 does NOT move Green** and **no `devnet-seeds.live.json` is published**. Run 393 re-proves the
`register-check --status live --reachability-evidence <ref>` admission gate (accepts a cert-verified live
candidate; fails closed without evidence and on `planned`+reachability; `m4_green_claim=false`) and the
loopback preflight, and lands a Run 393 reachability record
(`docs/release/public-devnet/network/reachability/RUN_393_qbind-devnet-seed-1.md`, documenting the Route A
prerequisites), the harness
`scripts/devnet/run_393_public_devnet_m4_real_external_seed_reachability.sh` (`RESULT=NEGATIVE-FOR-EXTERNAL`),
and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_393.md`. The committed live-seed candidate stays `status:
planned` with null reachability. M6 remains Yellow/Partial; S7 remains Yellow; M12/M13/M14/M15/M16 remain
Green; public DevNet remains NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched. No production
Rust source change; no new public CLI flag.
Updated Run 394 — **S1 backup/restore, S2 data retention, S3 upgrade, S4 rollback move Yellow → Green
(should-have; Route B — docs + verification harness only, no production source change); M4 stays
Yellow, M6 stays Yellow/Partial, S7 stays Yellow**: Run 394 publishes the operator-facing public
DevNet recovery package (`docs/release/public-devnet/recovery/` — `README.md`, `BACKUP_RESTORE.md`,
`DATA_RETENTION.md`, `UPGRADE_PROCEDURE.md`, `ROLLBACK_PROCEDURE.md`, `SAFETY.md`, `VERIFY.md`) and
verifies it against the real `qbind-node` CLI/help surfaces via
`scripts/devnet/run_394_public_devnet_operator_recovery_package.sh` (`RESULT=POSITIVE`): every
documented recovery flag (`--data-dir`, `--snapshot-dir`, `--snapshot-interval-blocks`,
`--snapshot-max-snapshots`, `--restore-from-snapshot`, `--state-retention-mode`,
`--state-retain-height`, `--state-prune-interval`, `--genesis-path`, `--print-genesis-hash`,
`--expect-genesis-hash`) is pre-existing in `--help` with no invented flag; safety labels, required
sections, and cross-links present; non-claim grep passes; no private/raw artifact committed. Backup /
restore is scoped as best-effort DevNet convenience (fail-closed `--restore-from-snapshot`, genesis
pinning, wipe-and-rejoin default) with **no guarantee of data permanence and no uptime SLA**. It adds
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_394.md` and the archive
`docs/devnet/run_394_public_devnet_operator_recovery_package/`. **No production Rust source change; no
new public CLI flag.** M4 stays Yellow/launch-blocking, M6 stays Yellow/Partial, S7 stays Yellow,
M12/M13/M14/M15/M16 remain Green; public DevNet remains NOT launch-ready; C4/C5 remain OPEN;
MainNet/TestNet untouched.
Updated Run 392 — **S7 seed-node operational runbook moves Red → Yellow (should-have; Route B — docs +
verification harness only, no production source change); M4 stays Yellow, M6 stays Yellow/Partial**:
Run 392 publishes the operator-facing public DevNet seed-node operations package
(`docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md`,
`M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`, `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`) and verifies it against
the real `qbind-node` CLI/help + seed-list schema surfaces via
`scripts/devnet/run_392_public_devnet_seed_ops_route_a_checklist.sh` (`RESULT=POSITIVE`): all documented
seed P2P/genesis flags pre-existing in `cli.rs` + `--help` with no invented flag; `identity generate` /
`register-check` subcommands present; `devnet-seeds.live-candidate.json` still schema-valid and non-live;
required doc sections + cross-links present; non-claim grep passes; no private/raw artifact committed.
The runbook makes it unambiguous what a real seed operator must do before M4 can move Green (durable
identity custody, strict KEMTLS static-root startup, genesis pinning, independent off-host external
TCP + KEMTLS verification, seed-list promotion, register-check live admission, retirement) **without
faking any external endpoint or reachability**. It adds `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_392.md`
and the archive `docs/devnet/run_392_public_devnet_seed_ops_route_a_checklist/`. **M4 does NOT move
Green** (no externally reachable seed / no independent off-host vantage); **M6 stays Yellow/Partial**
(live registration is M4-gated); M12/M13/M14/M15/M16 remain Green; public DevNet remains NOT
launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.
Updated Run 391 — **M4 remains Yellow/launch-blocking (Route C — no safe external seed infrastructure);
no Green move**: Run 391 re-executes the same **Route A** objective as Run 378/388 (deploy/use a real
externally reachable seed and prove reachability from an **independent off-host vantage point**) with **no
production source change**, and reaches the **same Route C finding** — the sandboxed environment has **no
external ingress and no independent off-host vantage point**, so external reachability **cannot be proven**
and **M4 does NOT move Green** (Run 386/387 preflight posture `signed_release=false` / `slsa_grade=false`
is unchanged). Run 391 re-proves the `register-check --status live --reachability-evidence <ref>` admission
gate (admits a cert-verified live candidate WITH an evidence reference; fails closed WITHOUT it and on
`planned`+reachability; `m4_green_claim=false`) and the loopback preflight, and lands a Run 391 reachability
record (`docs/release/public-devnet/network/reachability/RUN_391_qbind-devnet-seed-1.md`, documenting the
Route A infrastructure prerequisites),
`scripts/devnet/run_391_public_devnet_m4_external_seed_reachability.sh` (`RESULT=NEGATIVE-FOR-EXTERNAL`),
`crates/qbind-node/tests/run_391_public_devnet_m4_external_seed_reachability_tests.rs` (4 tests), and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_391.md`. The committed live-seed candidate stays `status: planned`
with null reachability (text refreshed to reference Run 391). M6 remains Yellow/Partial; M12/M13/M14 remain
Green; public DevNet remains NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.
Updated Run 389 — **M7 key-management, M8 PQC trust-bundle bootstrap, and M9 PQC root/signing-key
guidance move Yellow → Green (Green-for-scope; Route B; no production source change)**: Run 389 publishes
the operator-facing public DevNet **security** package (`docs/release/public-devnet/security/` —
`README.md`, `KEY_MANAGEMENT.md`, `PQC_TRUST_BOOTSTRAP.md`, `PQC_ROOT_AND_SIGNING_KEYS.md`, `SAFETY.md`,
`VERIFY.md`) and verifies it against the real `qbind-node` CLI/help surfaces and the existing
`devnet_pqc_trust_bundle_helper` example via
`scripts/devnet/run_389_public_devnet_security_key_trust_bootstrap.sh` (`RESULT=POSITIVE`): all 13
documented key/trust flags present in `--help` with no invented flag; a DevNet identity generated
(`0600` KEM secret; root signing key never on disk) and re-verified; a signed DevNet trust bundle
reload-checked (`signature_verified=true` / `VERDICT=valid`, validation-only, no live apply) with a
tampered bundle and MainNet/TestNet generation failing closed. Evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_389.md`, archive
`docs/devnet/run_389_public_devnet_security_key_trust_bootstrap/`; identity tests
(run_375 13/13, run_376 14/14) rerun green with no Rust source change. **M4 remains Yellow/launch-blocking**
and **M6 remains Yellow/Partial**; M12/M13/M14 remain Green; public DevNet remains NOT launch-ready; C4/C5
remain OPEN; TestNet/MainNet untouched. No M4 Green, no M6 fully-Green, and no C4/C5 closure is claimed.
Updated Run 390 — **M15 DevNet reset policy moves Yellow → Green and M16 incident-response is reconciled
to Green (Route B; docs + verification harness only; no production source change, no new CLI flag)**:
Run 390 publishes the operator-facing public DevNet **ops** package (`docs/release/public-devnet/ops/` —
`README.md`, `RESET_POLICY.md`, `INCIDENT_RESPONSE.md`, `SAFETY.md`, `VERIFY.md`) and verifies it against
the real `qbind-node` CLI/help + source surfaces via
`scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh` (`RESULT=POSITIVE`). `RESET_POLICY.md`
(M15) covers the DevNet-only safety label, what a reset means (state wipe / genesis pinned-or-successor /
no value), reset triggers, notice policy (pre-announce when possible, emergency-without-notice for safety,
UTC-timestamped record required), operator actions, what-never-changes-silently, a publish-safe reset
evidence-record shape, and the pre-existing **hidden offline** `--authority-state-reset` posture (documents
exactly what it does/does not reset; no live governance / authority / C4-C5 closure). `INCIDENT_RESPONSE.md`
(M16) publishes a **public-DevNet-scoped** operator incident-response process (severity levels, incident
classes, first-response steps, evidence-capture + redaction rules, escalation & rollback/reset decision
points, cross-links, publication policy, explicit non-claims) that references and defers to the **internal**
Beta-scoped `docs/ops/QBIND_INCIDENT_RESPONSE.md` — reconciling the previously ambiguous M16 status (its
prior Green rested only on that internal, non-public-DevNet-scoped document). Evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md`, archive
`docs/devnet/run_390_public_devnet_ops_reset_incident_response/`. **M4 remains Yellow/launch-blocking** and
**M6 remains Yellow/Partial**; M12/M13/M14 remain Green; public DevNet remains NOT launch-ready; C4/C5
remain OPEN; TestNet/MainNet untouched. No M4 Green, no M6 fully-Green, and no C4/C5 closure is claimed.
Updated Run 379 — **M13 telemetry / metrics and M14 monitoring / alerting move Yellow → Green
(Route B; no production source change)**: Run 379 publishes an operator-facing public DevNet
observability package (`docs/release/public-devnet/observability/` — `README.md`, `METRICS.md`,
`SCRAPE_CONFIG.md`, `ALERT_RULES.md`, `RUNBOOK.md`, `VERIFY.md`, plus machine-readable
`prometheus-scrape.example.yml` / `prometheus-alerts.example.yml`) documenting safe metrics exposure
via the pre-existing `metrics_http` endpoint gated by `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>`
(loopback-only, no auth/TLS, disabled by default — no new CLI flag). Every listed metric family is
**verified by a live loopback scrape of the release `qbind-node` binary** (HTTP 200; required families
`qbind_consensus_committed_height`, `qbind_p2p_connections_current`,
`qbind_p2p_connection_rate_drop_total`, `qbind_p2p_pqc_trust_bundle_*` present), and honest gaps are
documented rather than invented — `qbind_net_per_peer_drops_total` is absent until the first per-peer
drop, there is no build/chain/free-disk info gauge, and PQC-suite/KEMTLS crypto sub-metrics are not
served by default. Alert rules carry `page`/`ticket`/`observe` severities and a per-alert runbook;
alerts on **absent** metrics are kept in a clearly-marked **future / not-enabled** group. The harness
`scripts/devnet/run_379_public_devnet_observability_baseline.sh` (`RESULT=POSITIVE`) builds the release
binary, boots it with a loopback metrics endpoint, scrapes `/metrics`, YAML-parses both example configs,
and asserts no launch/M4-Green/C4-C5/TestNet/MainNet claim; evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`, archive
`docs/devnet/run_379_public_devnet_observability_baseline/`. **M4 remains Yellow/launch-blocking**, M6
remains Yellow/Partial, M12 remains Green, public DevNet remains NOT launch-ready, and C4/C5 remain OPEN;
MainNet/TestNet untouched.
Updated Run 380 — **observability hardening (M13/M14 remain Green)**: Run 380 deepens the Run 379
baseline with **no production source change** — decision gate **Route A** for the per-peer drop metric
(the deployed `TcpKemTlsP2pService::read_loop` per-peer limiter already emits
`qbind_net_per_peer_drops_total{reason="rate_limit"}` after a real drop — Runs 371–373) and **Route C**
for node/build-info + disk gauges (none added; disk alert stays future → node-exporter). It corrects the
stale "construction-path-only" per-peer wording in the observability/P2P docs to "absent in a clean scrape
until a per-peer rate-limit drop occurs; Runs 371–373 prove deployed KEMTLS live-socket enforcement",
promotes the `QbindPerPeerRateLimitDropsSustained` alert **future → enabled**, and lands release-binary
scrape evidence via `scripts/devnet/run_380_public_devnet_observability_hardening.sh` (`RESULT=POSITIVE`):
metrics disabled without `QBIND_METRICS_HTTP_ADDR`; loopback `/metrics` HTTP 200; per-peer series ABSENT
in a clean scrape then PRESENT (=47) after an induced KEMTLS over-budget flood; per-peer drop leaves
`qbind_p2p_connection_rate_drop_total=0` and a connection-rate flood leaves the per-peer metric absent
(controls independent); scrape + alert YAML parse; non-claim check OK. Evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`, archive
`docs/devnet/run_380_public_devnet_observability_hardening/`. **M12, M13, and M14 remain Green**; M4 stays
Yellow/launch-blocking; M6 remains Yellow/Partial; public DevNet remains NOT launch-ready; C4/C5 remain
OPEN; MainNet/TestNet untouched.
Updated Run 381 — **observability gauge hardening (M13/M14 remain Green)**: Run 381 adds a minimal,
read-only production metrics source change (decision gate **Route B**) that exposes two low-cardinality,
secret-free series on the release-binary `/metrics` scrape: `qbind_node_build_info{version,build_id,
git_commit,env,chain_id} 1` (static node/build/chain info; unknown values render as `unknown`; no path/
hostname/endpoint label) and the qbind-owned `qbind_node_data_dir_free_bytes` gauge (value only, no path/
mount/hostname label; derived from `statvfs(3)` on `--data-dir`, omitted when unavailable). Because the
disk gauge is proven present, the `QbindNodeDiskSpaceLow` alert is promoted **future → enabled** against
`qbind_node_data_dir_free_bytes`; the future/not-enabled group now carries only the still-absent legacy
`qbind_state_size_bytes` gauge (`QbindStateSizeHigh`). It corrects the stale Run 380 per-peer summary row in
`METRICS.md` ("Watch; alert FUTURE" → "Conditional; alert ENABLED after Run 380 induced-drop evidence").
No new CLI flag (exposure stays `QBIND_METRICS_HTTP_ADDR` loopback-only, disabled by default); no P2P
wire-format change; no peer-admission weakening; no trust/validator/epoch/sequence/marker mutation. Release
evidence via `scripts/devnet/run_381_public_devnet_observability_gauges.sh` (`RESULT=POSITIVE`): build-info
+ free-bytes present; labels low-cardinality/secret-free; metrics disabled without env; loopback `/metrics`
HTTP 200; baseline families still present; scrape + alert YAML parse; enabled exprs reference present
metrics; non-claim check OK. Evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`, archive
`docs/devnet/run_381_public_devnet_observability_gauges/`. **M12, M13, and M14 remain Green**; M4 stays
Yellow/launch-blocking; M6 remains Yellow/Partial; public DevNet remains NOT launch-ready; C4/C5 remain
OPEN; MainNet/TestNet untouched.

Updated Run 382 — **build-info provenance hardening (M13/M14 remain Green)**: Run 382 adds a minimal
build-time provenance bridge (decision gate **Route B**), `crates/qbind-node/build.rs`, that populates the
Run 381 `qbind_node_build_info` labels without any runtime change: `git_commit` is auto-derived to a short
git commit hash (or an explicit `QBIND_GIT_COMMIT` override) and `build_id` is a harness/CI-injected
`QBIND_BUILD_ID` (never derived from git or the ELF). Missing provenance still renders `unknown`; all label
values are sanitized to `[A-Za-z0-9._-]` (no path/host/branch/dirty/endpoint/secret leak). The metric
`build_id` label is documented as distinct from the binary ELF `.note.gnu.build-id`. No metric/alert/scrape
change; the Run 381 `qbind_node_data_dir_free_bytes` gauge is intact; no new CLI flag (exposure stays
`QBIND_METRICS_HTTP_ADDR` loopback-only, disabled by default); no P2P wire-format change; no
peer-admission weakening; no trust/validator/epoch/sequence/marker mutation. Release evidence via
`scripts/devnet/run_382_public_devnet_build_info_provenance.sh` (`RESULT=POSITIVE`): default build
auto-fills `git_commit` while `build_id` stays `unknown`; an injected build honours both; ELF BuildID kept
separate from the metric `build_id`; disk gauge intact; metrics disabled without env; loopback `/metrics`
HTTP 200; scrape + alert YAML parse; non-claim check OK. Evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_382.md`, archive
`docs/devnet/run_382_public_devnet_build_info_provenance/`. **M12, M13, and M14 remain Green**; M4 stays
Yellow/launch-blocking; M6 remains Yellow/Partial; public DevNet remains NOT launch-ready; C4/C5 remain
OPEN; MainNet/TestNet untouched.

Updated Run 383 — **canonical injected release provenance + same-input reproducibility (M13/M14 remain
Green)**: Run 383 is a **docs/harness-only** run (decision gate **Route A**, no production source
change, no CLI flag) that wires the Run 382 `build.rs` provenance bridge to **canonical injected**
values for a published release artifact and proves the injected build is same-input reproducible. The
release harness injects `QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)"` and a canonical
low-cardinality non-secret `QBIND_BUILD_ID="qbind-devnet-<version>-<short-commit>"`, so a live loopback
`qbind_node_build_info` scrape shows both labels populated (injected `git_commit` equals the expected
short commit; injected `build_id` equals the canonical release id). Two clean `--locked` builds with the
same source, lockfile, toolchain, and injected provenance produce a **byte-identical** binary on the
reference host; changing the injected `build_id` changes the hash (recorded as expected); the
missing-injection fallback (`build_id="unknown"`) is preserved; the ELF `.note.gnu.build-id` is captured
separately and stays distinct from the metric `build_id`. No metric/alert/scrape change; the
`qbind_node_data_dir_free_bytes` gauge is intact; no new CLI flag (exposure stays
`QBIND_METRICS_HTTP_ADDR` loopback-only, disabled by default); no P2P wire-format change; no
peer-admission weakening; no trust/validator/epoch/sequence/marker mutation. Release evidence via
`scripts/devnet/run_383_public_devnet_release_provenance_injected_repro.sh` (`RESULT=POSITIVE`):
canonical injected build; both labels in a live scrape; same-input reproducibility byte-identical;
changed-input hash difference; ELF BuildID separate; metrics disabled without env; loopback `/metrics`
HTTP 200; scrape + alert YAML parse; non-claim check OK. Evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_383.md`, archive
`docs/devnet/run_383_public_devnet_release_provenance_injected_repro/`. **M12, M13, and M14 remain
Green**; M4 stays Yellow/launch-blocking; M6 remains Yellow/Partial; public DevNet remains NOT
launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.

Updated Run 384 — **canonical CI/release-artifact manifest (M13/M14 remain Green)**: Run 384 is a
**docs/harness/schema-only** run (decision gate **Route A**, no production source change, no `build.rs`
change, no runtime change, no CLI flag) that records the Run 383 canonical injected build as a
machine-readable, publish-safe **release-artifact manifest**. It adds
`docs/release/public-devnet/binary/RELEASE_ARTIFACT_MANIFEST.schema.json` (JSON-Schema draft-07
contract) and `RELEASE_ARTIFACT_MANIFEST.example.json` (generated from the real build), the harness
`scripts/devnet/run_384_public_devnet_release_artifact_manifest.sh`, the archive
`docs/devnet/run_384_public_devnet_release_artifact_manifest/`, and evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md`. The harness builds the canonical injected artifact
(`QBIND_GIT_COMMIT="$(git rev-parse --short=12 HEAD)"`,
`QBIND_BUILD_ID="qbind-devnet-<version>-<short-commit>"`), generates the manifest from the actual
binary (SHA-256, ELF BuildID) plus a live loopback `qbind_node_build_info` scrape (metric `build_id` /
`git_commit`), records the `Cargo.lock` hash, toolchain, and target triple, and validates the manifest
**and** the committed example against the schema (`RESULT=POSITIVE`). The manifest keeps `metric_build_id`
a **separate field** from and distinct from `elf_build_id`, carries same-host/per-input
`reproducibility_scope` referencing Run 383 (not cross-host / SLSA), all non-claim fields true, and no
absolute path / hostname / endpoint / secret / raw `/metrics` dump. No metric/alert/scrape change; no new
CLI flag (exposure stays `QBIND_METRICS_HTTP_ADDR` loopback-only, disabled by default); no P2P
wire-format / peer-admission / trust / validator / epoch / sequence / marker change. Evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_384.md`, archive
`docs/devnet/run_384_public_devnet_release_artifact_manifest/`. **M12, M13, and M14 remain Green**; M4
stays Yellow/launch-blocking; M6 remains Yellow/Partial; public DevNet remains NOT launch-ready; C4/C5
remain OPEN; MainNet/TestNet untouched.

Updated Run 387 — **hosted-CI keyless attestation execution attempt (M13/M14 remain Green)**: Run 387
is a **harness/docs-only** run (decision gate **Route C**, no production source change, no `build.rs`
change, no runtime change, no CLI flag) that attempts to execute the Run 386 protected signing path for
real — dispatch with `confirm=yes`, mint + verify a keyless build-provenance attestation for
`target/release/qbind-node`. From the offline sandbox that path is not reachable (`gh` unauthenticated,
`api.github.com` DNS-blocked, no OIDC issuer, no ability to create the protected `release-signing`
environment or dispatch), so it is **Negative-for-attestation** and preserves the Run 386 preflight
posture. It adds the publish-safe verify harness
`scripts/devnet/run_387_public_devnet_hosted_ci_attestation_verify.sh` (run-time Route A/Route C gating;
runs the real `gh attestation verify` binding only inside hosted CI; never fakes a PASS), the archive
`docs/devnet/run_387_public_devnet_hosted_ci_attestation/`, and evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_387.md`. No signature/attestation/private key is produced or
committed; `signed_release`/`slsa_grade` stay `false` and the committed manifest schema still pins both
to `const:false`. No metric/alert/scrape change; no new CLI flag (exposure stays `QBIND_METRICS_HTTP_ADDR`
loopback-only, disabled by default); no P2P wire-format / peer-admission / trust / validator / epoch /
sequence / marker change. **M12, M13, and M14 remain Green**; M4 stays Yellow/launch-blocking; M6 remains
Yellow/Partial; public DevNet remains NOT launch-ready; C4/C5 remain OPEN; MainNet/TestNet untouched.

Updated Run 386 — **optional, disabled-by-default signing/attestation CI preflight (M13/M14 remain
Green)**: Run 386 is a **CI/workflow + harness/docs-only** run (decision gate **Route B**, no production
source change, no `build.rs` change, no runtime change, no CLI flag) that adds an optional, protected
release **signing/attestation** preflight while keeping `signed_release=false` and `slsa_grade=false`
honest. A real, **secret-free** attestation path exists (GitHub artifact attestation via
`actions/attest-build-provenance`, keyless Sigstore over GitHub OIDC) but needs elevated
`id-token`+`attestations` writes and a protected CI environment and cannot be minted/verified offline, so
the workflow ships disabled by default. It adds
`.github/workflows/public-devnet-release-signing-attestation.yml` (manual-only; `confirm` input defaults
to `no`; single job gated on `confirm == 'yes'`; protected `release-signing` environment; top-level
`permissions: contents: read`; job elevates only `id-token: write` + `attestations: write`; no secrets;
no release/tag/deployment; no commit/push), the preflight harness
`scripts/devnet/run_386_public_devnet_release_signing_attestation_preflight.sh` (reuses the Run 385
wrapper; `RESULT=POSITIVE`), the archive
`docs/devnet/run_386_public_devnet_release_signing_attestation_preflight/`, and evidence
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_386.md`. No signature/attestation/private key is produced or
committed; the committed manifest schema still pins `signed_release`/`slsa_grade` to `const:false`. The
only non-doc changes to existing files are content-preserving CRLF→LF normalizations of the Run 384/385
harnesses so CI can execute them. No metric/alert/scrape change; no new CLI flag (exposure stays
`QBIND_METRICS_HTTP_ADDR` loopback-only, disabled by default); no P2P wire-format / peer-admission /
trust / validator / epoch / sequence / marker change. **M12, M13, and M14 remain Green**; M4 stays
Yellow/launch-blocking; M6 remains Yellow/Partial; public DevNet remains NOT launch-ready; C4/C5 remain
OPEN; MainNet/TestNet untouched.

Updated Run 385 — **CI generation of the release-artifact manifest (M13/M14 remain Green)**: Run 385 is
a **CI/workflow + harness/docs-only** run (decision gate **Route A**, no production source change, no
`build.rs` change, no runtime change, no CLI flag) that wires the Run 384 manifest generation into CI so
every published DevNet release build can emit a schema-validated `RELEASE_ARTIFACT_MANIFEST.json` as a
**CI artifact** — never a committed, changing file. It adds
`.github/workflows/public-devnet-release-artifact-manifest.yml` (manual / release-track scoped;
least-privilege `permissions: contents: read`; no secrets; no release/tag/deployment; no commit/push),
the local dry-run wrapper `scripts/devnet/run_385_public_devnet_ci_release_artifact_manifest.sh` (reuses
the Run 384 harness), the archive `docs/devnet/run_385_public_devnet_ci_release_artifact_manifest/`, and
evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_385.md`. The wrapper lints the workflow YAML, builds the
canonical injected artifact, generates the manifest from the actual binary (SHA-256, ELF BuildID) plus a
live loopback `qbind_node_build_info` scrape, validates it against the committed schema
(`RESULT=POSITIVE`), and stages only publish-safe CI artifacts (`RELEASE_ARTIFACT_MANIFEST.json`,
`qbind-node.sha256`, `MANIFEST_VALIDATION_SUMMARY.txt`, `BUILDID.txt`) excluding raw logs/metrics/data
dirs, with `signed_release=false` / `slsa_grade=false` recorded and the generated manifest **not**
committed. The only non-doc change to an existing file is a content-preserving CRLF→LF normalization of
the Run 384 harness so CI can execute it. No metric/alert/scrape change; no new CLI flag (exposure stays
`QBIND_METRICS_HTTP_ADDR` loopback-only, disabled by default); no P2P wire-format / peer-admission /
trust / validator / epoch / sequence / marker change. **M12, M13, and M14 remain Green**; M4 stays
Yellow/launch-blocking; M6 remains Yellow/Partial; public DevNet remains NOT launch-ready; C4/C5 remain
OPEN; MainNet/TestNet untouched.
**Track:** Public network release-readiness. This is a **separate track** from the internal
authority-lifecycle boundary track (Run 130–354) and from C4/C5 closure.
**Scope of this document:** source/docs/test-only audit and gap matrix. It introduces public DevNet
readiness as a tracked classification. It does **not** launch, deploy, or declare any public network ready.
**Audience:** Internal — protocol engineering, ops, release management.

---

## 0. Relationship to existing documents

This document is intentionally **separate** from, and cross-references, the existing checklists:

- `docs/devnet/QBIND_DEVNET_READINESS_AUDIT.md` — the EXE-2 bring-up audit. It answers a narrower
  question ("can a minimal DevNet be brought up now for internal evidence collection?"). It is **not** a
  public-network launch checklist. This document extends that work into public-DevNet launch classification.
- `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` — operator bring-up practices for internal DevNet.
- `docs/release/QBIND_RELEASE_TRACK_SPEC.md` — DevNet → TestNet → MainNet stage sequencing and exit gates.
- `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` — MainNet-only readiness gate (not DevNet).
- `docs/testnet/QBIND_TESTNET_ALPHA_PLAN.md`, `docs/testnet/QBIND_TESTNET_BETA_PLAN.md` — TestNet stages.
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` — C4/C5 closure criteria (both remain **OPEN**).

No generic release/MainNet checklist is duplicated here; where an item is owned by one of those documents,
this matrix references it rather than restating it.

---

## 1. Public DevNet launch definition

A **QBIND public DevNet** is an **experimental, externally-reachable, resettable** network that
outside operators may join to run validator/full nodes for evaluation and integration testing.

A public DevNet launch means, at minimum:

1. A canonical, published DevNet **genesis package** (genesis file + published genesis hash + network parameters).
2. A published, **provenance-attested release binary** that external operators can obtain and verify.
3. A published **seed/bootnode entry list** enabling an outside node to join the network.
4. A published **operator quickstart** sufficient for an external party to run a node unassisted.
5. Published **safety disclaimers** (experimental, resettable, no value, no readiness claim).
6. Operational **incident-response, monitoring, and abuse-handling** posture appropriate for an open port.

A public DevNet launch **explicitly is not** claimed by this document. This document only classifies which of
the above are Green (evidenced), Yellow (partial), Red (missing), or N/A for DevNet.

---

## 2. Explicit public DevNet non-goals

- No faucet deployment.
- No public JSON-RPC gateway deployment.
- No block explorer or public status-page deployment.
- No public genesis package published *as ready* by this run.
- No seed-node/bootnode deployment by this run.
- No public TestNet readiness claim.
- No MainNet readiness claim.
- No C4 closure. No C5 closure.
- No runtime wiring of any authority-lifecycle boundary (Run 353/354 stays dead code from runtime).
- No public CLI enablement flag.
- No reinterpretation of any Green-for-scope authority-lifecycle boundary as production readiness.
- No marketing language; evidence-grounded status only.

---

## 3. Public DevNet safety label

Any future public DevNet, when launched, **must** carry and publish this label:

- **experimental** — software and network may fail, fork, or be discontinued at any time;
- **resettable** — network state may be wiped without notice; no state durability guarantee;
- **no value** — no token, asset, or balance on DevNet has or represents monetary value;
- **no MainNet readiness claim** — DevNet participation implies nothing about MainNet readiness;
- **no C4/C5 closure claim** — C4 and C5 remain OPEN irrespective of any DevNet activity.

This label is a **must-have** and is a launch precondition, not a post-launch addendum.

---

## 4. Must-have checklist (public DevNet launch preconditions)

Each item must be genuinely **Green** and evidenced before public DevNet launch. See §10/§16 matrix for status.

- [x] M1. Canonical DevNet genesis package published (file + hash + parameters). — **Green (Run 356)**; see `docs/release/public-devnet/genesis/`.
- [x] M2. Release binary provenance published (source commit, build inputs, SHA-256). — **Green (Run 359)**; see `docs/release/public-devnet/binary/RELEASE_PROVENANCE.md` (commit `420bb571…`, toolchain 1.97.1, `cargo build -p qbind-node --release --locked`, SHA-256 `f916af6d…b22990`).
- [x] M3. Release binary reproducibility / BuildID documented (deterministic or documented non-determinism). — **Green (Run 359)**; see `docs/release/public-devnet/binary/REPRODUCIBILITY.md` — same-host, clean-tree two-build reproducibility (byte-identical `qbind-node`) + ELF BuildID `274fdaf3…5208b`. Cross-host/SLSA/signed-release **not** claimed.
- [ ] M4. Seed/bootnode list published for public join. — **Yellow (Run 357; strengthened Run 377; external attempt Run 378; external execution Run 388; re-execution Run 391)**: canonical seed-list format + placeholder artifact published (`docs/release/public-devnet/network/`); **Run 377** adds a schema-valid **preflight** live-seed candidate (`devnet-seeds.live-candidate.json`, `status: planned`), a reachability evidence record (`network/reachability/RUN_377_qbind-devnet-seed-1.md`), a release harness, and 4 tests, and release-proves the `register-check --status live --reachability-evidence` admission gate — but **only loopback/same-host reachability was demonstrated**. **Run 378** attempts **Route A** (real external reachability from an independent external vantage point) and records **Route C** — no external ingress / no independent external vantage point is available in the sandboxed environment, so no real endpoint can be exposed and external reachability is **NOT proven** (`network/reachability/RUN_378_qbind-devnet-seed-1.md` documents the Route A infrastructure prerequisites; `run_378_public_devnet_external_seed_reachability.sh` + 4 tests). **Run 388** re-executes the Route A objective and reaches the **same Route C finding** (`network/reachability/RUN_388_qbind-devnet-seed-1.md`; `run_388_public_devnet_m4_external_seed_reachability.sh` `RESULT=NEGATIVE-FOR-EXTERNAL` + 4 tests). **Run 391** re-executes the Route A objective again and reaches the **same Route C finding** (`network/reachability/RUN_391_qbind-devnet-seed-1.md`; `run_391_public_devnet_m4_external_seed_reachability.sh` `RESULT=NEGATIVE-FOR-EXTERNAL` + 4 tests). **Run 393** executes the real-external Route A objective once more (following the Run 392 runbook / M4 Route-A checklist) and reaches the **same Route C finding** — no external ingress / no independent off-host vantage point; external TCP + KEMTLS reachability **NOT proven**; **no `devnet-seeds.live.json` published** (`network/reachability/RUN_393_qbind-devnet-seed-1.md`; `run_393_public_devnet_m4_real_external_seed_reachability.sh` `RESULT=NEGATIVE-FOR-EXTERNAL`). **Still a launch blocker** — no live, externally reachable seed.
- [x] M5. Validator/full-node onboarding quickstart for external operators. — **Green (Run 358)**: external operator quickstart published (`docs/release/public-devnet/operator/QUICKSTART.md`), validated against the real `qbind-node` CLI surface (`--help`), the Run 356 genesis package, and the Run 357 seed-list format.
- [ ] M6. Validator identity guidance (node identity/key generation) published. — **Yellow / Partial (Run 358; materially narrowed Run 374; first-class generation half Green-for-scope Run 375)**: identity guidance published (`docs/release/public-devnet/operator/IDENTITY.md`) and validated against pre-existing identity/signer **loading/selection** flags; **Run 374** adds a stable, release-built operator-facing identity **generation + verification** package (`docs/release/public-devnet/identity/` + `run_374_public_devnet_identity_generation_helper` + harness + `OPERATOR_IDENTITY_SCHEMA.json`) that generates node/seed/validator-candidate material, emits a schema-validated public identity, deterministically re-derives the NodeId, inserts into the seed-list, and is accepted by a real loopback strict-auth `qbind-node` boot (MainNet/TestNet + mismatch fail closed). **Run 375** promotes this into a stable **first-class `qbind-node identity generate/verify/print-public/seed-candidate` command** (`crates/qbind-node/src/identity_cli.rs`; Route B / DevNet-gated / default-safe), with the Run 374 example now a thin wrapper (`crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs`, `scripts/devnet/run_375_public_devnet_identity_cli.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`) — the **generation + verification half of M6 is Green-for-scope**. **Run 376** adds a **non-mutating** `qbind-node identity register-check` admission verifier (reads public material only; validates against operator-identity + seed-list schema rules; deterministic NodeId cert verification; fails closed on private material, malformed fields, wrong env, MainNet/TestNet, mismatched cert, `status=live` without reachability, `planned`+reachability) with `crates/qbind-node/tests/run_376_public_devnet_identity_registration_tests.rs` (14 tests), `scripts/devnet/run_376_public_devnet_identity_registration.sh`, and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md` — the **registration/admission-check half of M6 is now Green-for-scope**. **Remaining gap:** no live public DevNet exists to register into (M4-gated) and operator-supplied root reuse/rotation/revocation is C4/C5-OPEN — M6 stays Yellow/Partial until a live registration path lands. **Run 401** adds the operator identity **continuity** package (`docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md`, `ROTATION_REVOCATION_DEFERRAL.md`) documenting durable identity reuse across DevNet restarts and explicitly deferring production rotation/revocation to C4/C5/MainNet (verified against the existing `identity` CLI surfaces; `scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_401.md`) — better documented, **still Yellow/Partial**.
- [x] M7. Validator key-management guidance (local keystore / remote signer / HSM options) published. — **Green (Run 389, Green-for-scope)**: consolidated operator-facing key-management guidance published (`docs/release/public-devnet/security/KEY_MANAGEMENT.md`), verified against the real `--signer-mode` (loopback-testing / encrypted-fs / remote-signer / hsm-pkcs11) + `--signer-keystore-path` / `--remote-signer-url` / `--hsm-config-path` surfaces and the `0600` private-key permission requirement; remote-signer/HSM documented as posture/integration surface (not production custody); no MainNet custody claim; C4/C5 remain OPEN.
- [x] M8. PQC trust-bundle bootstrap process for DevNet trust roots published. — **Green (Run 389, Green-for-scope)**: DevNet trust-bundle bootstrap procedure published (`docs/release/public-devnet/security/PQC_TRUST_BOOTSTRAP.md`), verified against the real `--p2p-trust-bundle` / `--p2p-trust-bundle-signing-key` loader via `--p2p-trust-bundle-reload-check` (signed DevNet bundle `signature_verified=true` / `VERDICT=valid`, tampered bundle fails closed), with genesis pinning, transport-root vs bundle-signing-key separation, no peer-driven live apply, and no fallback/hidden anchors; no live trust apply.
- [x] M9. PQC root / signing-key guidance for DevNet published. — **Green (Run 389, Green-for-scope)**: DevNet PQC root/leaf/signing-key generation + verification guidance published (`docs/release/public-devnet/security/PQC_ROOT_AND_SIGNING_KEYS.md`), verified against the real root/leaf/signing-key helpers and `--p2p-trusted-root` / `identity verify` derivation, with public-vs-private file rules (`*.kem.sk.bin` `0600`; root + bundle signing secrets in memory only) and wrong-chain/env/genesis detection; C4/C5 remain OPEN.
- [x] M10. Public P2P port posture defined (listen/advertise, `--enable-p2p` default, NAT guidance). — **Green (Run 360)**: public P2P port posture published (`docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md`), validated against the existing `qbind-node` CLI surface (`--enable-p2p` default `false`, `--p2p-listen-addr` default `127.0.0.1:0`, `--p2p-advertised-addr`, `--p2p-peer`, `--expect-genesis-hash`, all present in `--help`); no new flag, no default behaviour change, no discovery claim.
- [x] M11. Peer admission policy defined for an open network. — **Green (Run 360)**: peer-admission policy published (`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`), validated against the existing KEMTLS mutual-auth (`--p2p-mutual-auth`), PQC root (`--p2p-pqc-root-mode`, `--p2p-trusted-root`, `--p2p-leaf-cert`/`-key`, `--p2p-peer-leaf-cert`) and trust-bundle (`--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`) surfaces; fail-closed failure matrix documented; peer claims advisory-only, peer-driven apply out of scope; no admission-logic change.
- [ ] M12. Abuse / DoS protections documented and enabled (per-peer rate limiting posture). — **Yellow / Partial, strengthened (Run 362)**: abuse/DoS posture published Run 360 (`docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`) against the real per-peer rate limiter (`peer_rate_limiter.rs`: default `1000` msg/s + `100` burst, enabled by default); **Run 361** added a source/test-only operator-configurable abuse/DoS config model + a bounded inbound **connection-rate limiter** boundary; **Run 362** wires that connection-rate limiter into the live `p2p_tcp` accept loop behind runtime-owned, default-off state, adds the `qbind_p2p_connection_rate_drop_total` metric, and exposes hidden/devnet-only operator CLI flags (`crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs`, tests `tests/run_362_public_devnet_abuse_dos_runtime_tests.rs`, evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md`). Safe default preserves current behavior bit-for-bit (`1000` msg/s + `100` burst; connection limiter disabled). **Run 363** wired the per-peer message-rate runtime override into the live `AsyncPeerManagerImpl` `PeerRateLimiter` construction path at source/test level (the Run 362 hidden `--p2p-max-messages-per-second` / `--p2p-burst-allowance` flags now affect the live limiter; tests `tests/run_363_public_devnet_per_peer_message_rate_runtime_tests.rs`). **Run 364** produced release-binary evidence for **both** controls on real `target/release/qbind-node` + a release helper (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md`, `docs/devnet/run_364_public_devnet_abuse_dos_m12_release_binary/`, 7/7 scenarios). **Gap remaining:** the deployed `qbind-node` (`main.rs` / `p2p_node_builder`) does not yet thread the CLI-derived `peer_rate_limiter_config` into its live `AsyncPeerManagerImpl`, so the per-peer message-rate override reaches only the peer-manager *construction path*, not the running node end-to-end. M12 stays **Yellow/Partial** (strengthened); **Green still deferred** pending per-peer message-rate end-to-end production threading + load evidence. **Run 365** threads the CLI-derived `peer_rate_limiter_config` through the deployed `P2pNodeBuilder` into the live `AsyncPeerManagerImpl` construction path (`P2pNodeBuilder::deployed_peer_rate_limiter_config` / `build_deployed_peer_manager`, `P2pNodeContext.peer_rate_limiter_config`; tests `tests/run_365_public_devnet_deployed_peer_rate_threading_tests.rs`, evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_365.md`), closing the source/test gap Run 364 flagged with defaults preserved and no new public CLI flags. M12 stays **Yellow/Partial** (strengthened); **Green still deferred to Run 366** pending release-binary end-to-end evidence. **Run 366** lands release-binary evidence that the deployed `P2pNodeBuilder` path (`with_abuse_dos_runtime_config` → `deployed_peer_rate_limiter_config` → `build_deployed_peer_manager`) honors **both** controls on real `target/release/qbind-node` + a release helper (`crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs`, `scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md`, `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/`, 8/8 scenarios; no production source change). M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**: a running `qbind-node` cannot be driven over its live P2P inbound/message socket path here because DevNet runs in LocalMesh mode (`--enable-p2p` ignored), so the evidence is deployed-builder-path release-binary, not live-socket; Green remains deferred pending live-socket end-to-end + load evidence. **Run 367** drives the real `target/release/qbind-node` in a P2P-capable loopback mode (`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`) — fixing the Run 366 LocalMesh blocker — and proves the accept-loop **connection-rate** control **live-socket**: under-budget inbound TCP connections admitted with `qbind_p2p_connection_rate_drop_total` at 0, over-budget refused with the metric incrementing by exactly the over-budget count (10 connections, max 3 → 3 accepted / 7 refused, metric = 7), observed on the live `/metrics` endpoint (`crates/qbind-node/examples/run_367_public_devnet_abuse_dos_live_socket_helper.rs`, `scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md`, helper 8/8; no production source change). M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**: the per-peer **message-rate** control is still not driven over an admitted live peer socket (it enforces on the `AsyncPeerManagerImpl` receive path and needs a second KEMTLS peer flood harness), so it remains deployed-builder-path evidence; since M12 Green requires **both** controls over a live socket, Green is deferred to a Run 368 two-node message-flood harness. **Run 368** strengthens the per-peer message-rate evidence to a **real admitted-peer socket** proof: it registers a peer on a live `AsyncPeerManagerImpl` over a loopback TCP socket pair and floods `NetMessage` frames — under-budget accepted, over-budget dropped by the live `PeerRateLimiter` (≈75 of 80) with `qbind_net_per_peer_drops_total{...,reason="rate_limit"}` / `total_rate_limit_drops()` incrementing — and re-runs the Run 367 connection-rate live-socket proof (`crates/qbind-node/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper.rs`, `scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md`, helper 9/9; no production source change). **Decision gate = Route C:** the **deployed** `qbind-node` inbound path (`TcpKemTlsP2pService::subscribe` → `P2pInboundDemuxer` → handlers) does NOT consult the `PeerRateLimiter` and `AsyncPeerManagerImpl` is never spawned by `main.rs`, so this is `AsyncPeerManagerImpl`-layer evidence (plain-TCP admitted peer), not the deployed socket and not KEMTLS. M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**; remaining blocker: wire the `PeerRateLimiter` onto the deployed TcpKemTls receive path (recommended Run 369). **Run 369** wires that per-peer `PeerRateLimiter` onto the deployed inbound receive path (`TcpKemTlsP2pService::read_loop` → `inbound_tx` → `subscribe()` → `P2pInboundDemuxer` → handlers) via the new `DeployedInboundPerPeerLimiter` adapter (`crates/qbind-node/src/deployed_inbound_per_peer_limiter.rs`), installed by `P2pNodeBuilder::start()` from `deployed_peer_rate_limiter_config()` (default `1000` msg/s + `100` burst). Over-budget inbound frames are dropped before demuxer dispatch with the adapter's per-peer drop counter (and `qbind_net_per_peer_drops_total{reason="rate_limit"}` when a `NodeMetrics` handle is present) incrementing; the connection is not torn down and the connection-rate metric is never touched (`tests/run_369_public_devnet_deployed_per_peer_limiter_wiring_tests.rs`, 24/24; evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_369.md`). Bucket keying derives a `PeerId` from the first 8 bytes of the connection `NodeId` for rate-limit bucket selection only — not an identity/auth claim. M12 stays **Yellow/Partial — deployed TcpKemTls receive-path source/test wiring landed** and **does NOT move Green**: release-binary live-socket deployed-path evidence for **both** controls is deferred to Run 370. Defaults preserved; no new public CLI flags; no admission/trust/wire-format change.
- [x] M13. Telemetry / metrics baseline available to operators. — **Green (Run 379)**: operator-facing public DevNet observability package published (`docs/release/public-devnet/observability/` — `README.md`, `METRICS.md`, `SCRAPE_CONFIG.md`, `VERIFY.md`) documenting safe metrics exposure via the pre-existing `metrics_http` endpoint gated by `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>` (loopback-only; no auth/TLS; disabled by default), with every listed metric family **verified by a live loopback scrape of the release `qbind-node` binary** (HTTP 200; required families `qbind_consensus_committed_height`, `qbind_p2p_connections_current`, `qbind_p2p_connection_rate_drop_total`, `qbind_p2p_pqc_trust_bundle_*` present; honest gaps — per-peer drop series absent until first drop, no build/chain/free-disk gauge, crypto sub-metrics unserved — documented). Harness `scripts/devnet/run_379_public_devnet_observability_baseline.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`; **no production source change, no new CLI flag.** No launch/M4-Green/C4-C5/TestNet/MainNet claim. **Still Green (Run 380)**: hardening (Route A/C, no production source change) adds release-binary evidence that `qbind_net_per_peer_drops_total{reason="rate_limit"}` is exposable on demand (absent in a clean scrape, present after an induced per-peer drop) and confirms `/metrics` stays disabled without `QBIND_METRICS_HTTP_ADDR`; evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`. **Still Green (Run 381)**: a minimal read-only source change (Route B) adds the low-cardinality secret-free `qbind_node_build_info{version,build_id,git_commit,env,chain_id}` info gauge and the qbind-owned `qbind_node_data_dir_free_bytes` free-space gauge (value only, no path/host label) to the release scrape; `/metrics` stays disabled without `QBIND_METRICS_HTTP_ADDR`; harness `scripts/devnet/run_381_public_devnet_observability_gauges.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`.
- [x] M14. Monitoring / alerting baseline available to operators. — **Green (Run 379)**: operator-facing alerting baseline published (`docs/release/public-devnet/observability/ALERT_RULES.md`, `RUNBOOK.md`, machine-readable `prometheus-scrape.example.yml` + `prometheus-alerts.example.yml`) — example Prometheus scrape config + alert rules that **parse as YAML** (verified by the Run 379 harness), with `page`/`ticket`/`observe` severities and a per-alert operator runbook. Enabled rules reference only metrics verified present in the release-binary scrape (node/metrics-endpoint down, consensus no-progress, zero P2P connections, sustained M12 connection-rate drops, trust-bundle signature rejections + sequence-persist failure, snapshot failures, restore/catch-up stuck, peer-candidate rejections); alerts on **absent** metrics (`qbind_net_per_peer_drops_total`, `qbind_state_size_bytes`) are kept in a clearly-marked **future / not-enabled** group. Evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`; **no production source change.** No launch/M4-Green/C4-C5/TestNet/MainNet claim. **Still Green (Run 380)**: the per-peer alert `QbindPerPeerRateLimitDropsSustained` is promoted **future → enabled** with release-binary scrape evidence (metric present after an induced per-peer drop; connection-rate control independent); only the absent disk metric remains in the future/not-enabled group (use node-exporter). Harness `scripts/devnet/run_380_public_devnet_observability_hardening.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`; **no production source change.** **Still Green (Run 381)**: the disk alert `QbindNodeDiskSpaceLow` is promoted **future → enabled** against the new qbind-owned `qbind_node_data_dir_free_bytes` gauge proven present in the release scrape; the future/not-enabled group now carries only the still-absent legacy `qbind_state_size_bytes` gauge (`QbindStateSizeHigh`); scrape + alert YAML still parse. Harness `scripts/devnet/run_381_public_devnet_observability_gauges.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`; minimal read-only metrics source change only.
- [x] M15. Reset policy published (when/how DevNet state is wiped). — **Green (Run 390)**: DevNet reset policy published (`docs/release/public-devnet/ops/RESET_POLICY.md`) — safety label, what a reset means (state wipe / genesis pinned-or-successor / no value), reset triggers, notice policy (pre-announce when possible, emergency-without-notice for safety, UTC-timestamped record required), operator actions, what-never-changes-silently, publish-safe reset evidence-record shape, and the pre-existing hidden offline `--authority-state-reset` posture (documents exactly what it does/does not reset; no live governance / C4-C5 closure). Verified by `scripts/devnet/run_390_public_devnet_ops_reset_incident_response.sh` (`RESULT=POSITIVE`); no production source change, no new CLI flag.
- [x] M16. Incident-response process published. — **Green (Run 390, reconciled)**: the prior Green rested only on the **internal**, Beta/MainNet-readiness-scoped `docs/ops/QBIND_INCIDENT_RESPONSE.md` (explicitly not a public status page and not written for the public DevNet audience). Run 390 publishes a **public-DevNet-scoped** operator-facing incident-response process (`docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`) — DevNet severity levels, incident classes (seed unreachable / trust-bundle-root-signing-key mismatch / suspected key compromise / peer flood-DoS / chain halt / bad release artifact / reset event), first-response steps, evidence-capture + redaction rules, escalation & rollback/reset decision points, cross-links, publication policy, and explicit non-claims — that references and defers to the internal procedure. M16 is preserved as **Green** on the basis of this public-DevNet scoped evidence.
- [x] M17. Public documentation (how to run a node) sufficient for unassisted external bring-up. — **Green (Run 358)**: external how-to-run-a-node package published (`docs/release/public-devnet/operator/` — `README.md`, `QUICKSTART.md`, `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`), cross-linked from this readiness track and validated against the real `qbind-node` startup path.
- [x] M18. User-facing disclaimers published (the §3 safety label). — **Green (Run 358)**: the §3 safety label is published in operator-facing material (`docs/release/public-devnet/operator/SAFETY.md` and the header of every operator doc), not only in this internal matrix.
- [x] M19. Network parameter publication (chain id, env scope, consensus/timing params). — **Green (Run 356)**; see `docs/release/public-devnet/genesis/devnet-network-parameters.md`.
- [x] M20. Genesis hash publication (canonical hash operators verify with `--expect-genesis-hash`). — **Green (Run 356)**; hash `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`, see `docs/release/public-devnet/genesis/VERIFY.md`.

---

## 5. Should-have checklist (strongly recommended, not launch-blocking)

- [x] S1. Snapshot / backup / restore baseline usable by operators (creation + restore path). — **Green (Run 394)**: public-DevNet backup/restore baseline published (`docs/release/public-devnet/recovery/BACKUP_RESTORE.md`) and verified against the real pre-existing snapshot/restore CLI surfaces (`--snapshot-dir`, `--snapshot-interval-blocks`, `--snapshot-max-snapshots`, `--restore-from-snapshot`, `--expect-genesis-hash`). Best-effort DevNet convenience only — no guarantee of data permanence; wipe-and-rejoin is the DevNet-safe default.
- [x] S2. Data-retention posture documented for DevNet. — **Green (Run 394)**: `docs/release/public-devnet/recovery/DATA_RETENTION.md` is explicit about reset / no-SLA / no-value, suggested best-effort local windows, redaction rules, and reset-policy cross-link.
- [x] S3. Upgrade procedure documented (binary upgrade / rolling restart). — **Green (Run 394)**: `docs/release/public-devnet/recovery/UPGRADE_PROCEDURE.md` ties the upgrade to release-artifact/manifest/provenance verification, stop → back-up → replace → restart-with-same-genesis-pin → verify build-info, with rollback criteria.
- [x] S4. Rollback procedure documented. — **Green (Run 394)**: `docs/release/public-devnet/recovery/ROLLBACK_PROCEDURE.md` is fail-closed on unsafe state edits (no hand-edit of trust/authority/sequence/marker state), rolls back only under matching genesis/data assumptions, and prefers wipe-and-rejoin when compatibility is uncertain.
- [~] S5. Status page or aggregate health view. — **Yellow (Run 395, Route B)**: no live status service is deployed (a live health view would depend on M4, which is Yellow), so instead a **publish-safe static** status-page decision + future aggregate-health-view schema/example package is published (`docs/release/public-devnet/status/README.md`, `STATUS_PAGE_DECISION.md`, `STATUS_HEALTH_VIEW_SCHEMA.json`, `EXAMPLE_STATUS_HEALTH_VIEW.json`, `SAFETY.md`, `VERIFY.md`). The schema fixes the required fields (genesis hash, build info, seed-list status, M4/M6 status, metrics-endpoint status, alerts summary, incidents/reset notices), a fixed safety envelope (`launch_ready:false`, `uptime_sla:false`, `example_data_only`, no TestNet/MainNet readiness, C4/C5 not closed), and redaction rules (no private endpoints, raw logs, raw metrics dumps, secrets, data dirs, or absolute paths); the example validates against the schema and is marked `data_source: static-example`. S5 stays **Yellow, not Green** — no externally usable status page is deployed or maintained; live status is explicitly deferred until M4. Evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_395.md`; no production source change.
- [x] S6. Alert-rule definitions / scrape config shipped alongside the metrics baseline. — **Green (Run 395, reconciled; Route A)**: this row previously read Red / "None shipped" while **M14** already recorded the alert-rule definitions, scrape config, runbook, and machine-readable Prometheus examples as shipped and YAML-verified in Runs 379–381 — a genuine internal inconsistency. Run 395 reconciles it honestly against the already-shipped observability package: `docs/release/public-devnet/observability/ALERT_RULES.md`, `docs/release/public-devnet/observability/SCRAPE_CONFIG.md`, `docs/release/public-devnet/observability/RUNBOOK.md`, `docs/release/public-devnet/observability/prometheus-scrape.example.yml`, and `docs/release/public-devnet/observability/prometheus-alerts.example.yml` (both YAML files re-parsed by the Run 395 harness), with per-alert severities (`page`/`ticket`/`observe`), enabled rules referencing only metrics verified present in the release-binary scrape, and absent-metric alerts kept in a clearly-marked future/not-enabled group. No alert/scrape content is duplicated. Evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_395.md` (and the underlying `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`/`_380.md`/`_381.md`); no production source change.
- [~] S7. Seed-node operational runbook (operating the published seeds). — **Yellow (Run 392)**: a seed-node operations runbook, an M4 Route-A deployment checklist, and a reachability evidence template are published (`docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md`, `M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`, `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`) and verified against the real `qbind-node` CLI/help + seed-list schema surfaces. Operating a **live** seed still depends on M4 (no externally reachable seed exists), so S7 stays Yellow, not Green.

---

## 6. TestNet-deferred checklist (not required for public DevNet)

- [ ] T1. Faucet service.
- [ ] T2. Public JSON-RPC gateway.
- [ ] T3. RPC rate limiting.
- [ ] T4. Block explorer.
- [ ] T5. Governance proof production surface hardening at network scale.
- [ ] T6. Validator-set rotation exercised on a live shared network.
- [ ] T7. Formal data-retention SLAs.
- [ ] T8. Multi-region / soak / chaos operational evidence.

---

## 7. MainNet-deferred checklist (not required for public DevNet or TestNet)

- [ ] N1. MainNet custody (production key custody under production authority).
- [ ] N2. MainNet authority rotation / revocation under production custody (**Red**).
- [ ] N3. Runtime wiring of the authority-lifecycle boundary chain into production execution.
- [ ] N4. Reproducible-build hardening / signed release provenance (SLSA-grade) for value-bearing releases.
- [ ] N5. C4 closure (**OPEN**).
- [ ] N6. C5 closure (**OPEN**).
- [ ] N7. Production economic finalization.

---

## 8. Evidence required for each must-have item

| Item | Evidence required to move to Green |
|------|-------------------------------------|
| M1 | Committed canonical genesis artifact + a run that publishes it and records its hash. |
| M2 | Published provenance record: source commit, toolchain, build command, artifact SHA-256. |
| M3 | Documented reproducible-build result or documented, bounded non-determinism. |
| M4 | Committed, published seed/bootnode list + reachability evidence. |
| M5 | Committed external quickstart doc validated against the real `qbind-node` startup path. |
| M6 | Committed node-identity/key-generation guidance validated against CLI. |
| M7 | Committed key-management guidance covering `--signer-mode` local/remote + HSM options. |
| M8 | Committed DevNet trust-root bootstrap procedure validated against `pqc_trust_bundle` surfaces. |
| M9 | Committed PQC root/signing-key guidance referencing `--p2p-trusted-root` / `--p2p-trust-bundle-signing-key`. |
| M10 | Documented listen/advertise/`--enable-p2p`/NAT posture for public exposure. |
| M11 | Documented peer-admission policy (mutual-auth mode, trust-bundle gating) for an open port. |
| M12 | Documented + enabled rate-limiter posture (`peer_rate_limiter`) with configured thresholds. |
| M13 | Operator-facing metrics endpoint doc (`metrics_http` / `QBIND_METRICS_HTTP_ADDR`). |
| M14 | Operator-facing alerting baseline referencing `QBIND_MONITORING_AND_ALERTING_BASELINE.md`. |
| M15 | Published reset policy referencing `--authority-state-reset` and network-wide reset intent. |
| M16 | Public-DevNet-scoped incident-response process (`docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`) referencing `docs/ops/QBIND_INCIDENT_RESPONSE.md`. |
| M17 | Public how-to-run-a-node doc validated against real startup. |
| M18 | The §3 safety label published in operator-facing material. |
| M19 | Network parameters published (chain id per `NetworkEnvironment`, timing/consensus params). |
| M20 | Canonical genesis hash published + verifiable via `--print-genesis-hash` / `--expect-genesis-hash`. |

---

## 9. Owner / source file / evidence location per item

| Item | Owner | Primary source / evidence location |
|------|-------|-------------------------------------|
| M1, M19, M20 | Protocol eng | `crates/qbind-genesis/src/lib.rs`, `crates/qbind-node/src/pqc_boot_genesis.rs`, CLI `--print-genesis-hash`/`--expect-genesis-hash` |
| M2, M3 | Release mgmt | `docs/release/public-devnet/binary/` (Run 359: `README.md`, `RELEASE_PROVENANCE.md`, `REPRODUCIBILITY.md`, `BUILDINFO.md`, `qbind-node.sha256`, `VERIFY.md`); `docs/whitepaper/build.sh`; per-run `artifact_sha256.txt`; M2/M3 Green |
| M4, M7 | Ops | CLI `--p2p-peer`; no published seed list; `crates/qbind-remote-signer/` |
| M5, M6, M17 | Docs | `docs/release/public-devnet/operator/` external onboarding package (Run 358: `README.md`, `QUICKSTART.md`, `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`); `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`; M5/M17 Green, M6 Yellow (no identity-generation command yet) |
| M8, M9 | Ops / security | `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `crates/qbind-node/src/pqc_trust_bundle.rs` |
| M10, M11, M12 | Security / net | `docs/release/public-devnet/p2p/` (Run 360: `README.md`, `P2P_PORT_POSTURE.md`, `PEER_ADMISSION_POLICY.md`, `ABUSE_DOS_POSTURE.md`, `VERIFY.md`); `crates/qbind-node/src/cli.rs`, `peer_rate_limiter.rs`, `QBIND_PEER_TRUST_BUNDLE_PROPAGATION_SAFETY.md`; M10/M11 Green, M12 Yellow/Partial |
| M13, M14 | Observability | `crates/qbind-node/src/metrics_http.rs`, `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` |
| M15 | Ops | `docs/release/public-devnet/ops/RESET_POLICY.md` (Run 390); CLI `--authority-state-reset`, `crates/qbind-node/src/pqc_authority_state_reset.rs` |
| M16 | Ops | `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md` (Run 390), `docs/ops/QBIND_INCIDENT_RESPONSE.md`, `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md` |
| M18 | Docs | This document §3 |
| S1, S2 | Ops | `docs/release/public-devnet/recovery/BACKUP_RESTORE.md`, `DATA_RETENTION.md` (Run 394); `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`, `crates/qbind-ledger/src/state_snapshot.rs` |
| S3, S4 | Release mgmt | `docs/release/public-devnet/recovery/UPGRADE_PROCEDURE.md`, `ROLLBACK_PROCEDURE.md` (Run 394); `docs/release/QBIND_RELEASE_TRACK_SPEC.md` |
| N1, N2, N3 | Governance / custody | `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`, `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md` |
| N5, N6 | Protocol eng | `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` |

---

## 10. Current status per item

Legend: 🟢 Green (evidenced enough for public DevNet) · 🟡 Yellow (partial / needs one or more runs) ·
🔴 Red (missing) · ⚪ N/A for DevNet.

| Item | Status | Basis |
|------|--------|-------|
| M1 genesis package | 🟢 | **Run 356:** canonical `docs/release/public-devnet/genesis/devnet-genesis.json` committed, hash + SHA-256 published + operator-verifiable. |
| M2 release provenance | 🟢 | **Run 359:** canonical operator-verifiable provenance record published (`docs/release/public-devnet/binary/RELEASE_PROVENANCE.md`): commit `420bb571…`, toolchain 1.97.1, `cargo build -p qbind-node --release --locked`, SHA-256 `f916af6d…b22990`, BuildID `274fdaf3…5208b`. |
| M3 reproducibility / BuildID | 🟢 | **Run 359:** same-host, clean-tree two-build reproducibility (byte-identical `qbind-node`) + ELF BuildID recorded (`docs/release/public-devnet/binary/REPRODUCIBILITY.md`). Cross-host/SLSA/signed-release **not** claimed. |
| M4 seed/bootnodes | 🟡 | **Run 357:** canonical seed-list format (`devnet-seed-list.schema.json`) + placeholder artifact (`devnet-seeds.placeholder.json`) published under `docs/release/public-devnet/network/`, verified + genesis-pinned. **Run 377 (strengthened, Partial-positive):** a schema-valid **preflight** live-seed candidate (`devnet-seeds.live-candidate.json`, `status: planned`, real Run-375-path public `node_id`/`peer_id`, RFC 5737 host, null reachability), a reachability evidence record (`network/reachability/RUN_377_qbind-devnet-seed-1.md`), `scripts/devnet/run_377_public_devnet_live_seed_reachability.sh`, `crates/qbind-node/tests/run_377_public_devnet_live_seed_reachability_tests.rs` (4 tests), and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_377.md` land with **no production source change**; the `register-check --status live --reachability-evidence` gate (Run 376) is release-proven and a real loopback `qbind-node` P2P listener is dialed same-host. **Decision gate = Route B:** external reachability from outside the operator host/NAT was **NOT proven**, so **M4 does not move Green**. Still **Red-equivalent for launch**: no live, externally reachable seed, static `--p2p-peer` only, no discovery. **Run 378/388/391/393 (Route C):** repeated real-external Route A executions all find no external ingress / no independent off-host vantage point in the sandbox, so external TCP + KEMTLS reachability stays **NOT proven** and no `devnet-seeds.live.json` is published (`network/reachability/RUN_393_qbind-devnet-seed-1.md`; `run_393_public_devnet_m4_real_external_seed_reachability.sh` `RESULT=NEGATIVE-FOR-EXTERNAL`; `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_393.md`). **Launch blocker.** |
| M5 validator onboarding | 🟢 | **Run 358:** external operator quickstart published (`docs/release/public-devnet/operator/QUICKSTART.md`), validated against the real `qbind-node --help` CLI surface, the Run 356 genesis package, and the Run 357 seed-list format. |
| M6 validator identity | 🟡 | **Run 358:** identity guidance published (`docs/release/public-devnet/operator/IDENTITY.md`), validated against pre-existing identity/signer **loading/selection** flags. **Run 374 (materially narrowed):** stable, release-built operator-facing identity **generation + verification** package published (`docs/release/public-devnet/identity/` + `run_374_public_devnet_identity_generation_helper` + `scripts/devnet/run_374_public_devnet_identity_generation.sh` + `OPERATOR_IDENTITY_SCHEMA.json`, Route B / no production source change); generates node/seed/validator-candidate material (root signing key in-memory only, ML-KEM-768 leaf secret `0600`), emits schema-validated public identity, deterministically re-derives NodeId, inserts into the seed-list, accepted by a real loopback `qbind-node` strict-auth + static-root boot (`qbind_p2p_pqc_root_mode 1`); MainNet/TestNet + mismatched material fail closed (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_374.md`). **Run 375 (first-class command):** the workflow is promoted into a stable **first-class `qbind-node identity` command** (`crates/qbind-node/src/identity_cli.rs`; `generate`/`verify`/`print-public`/`seed-candidate`; Route B, DevNet-gated, default-safe, no runtime/wire/admission change; the Run 374 example is now a thin wrapper), with `crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs`, `scripts/devnet/run_375_public_devnet_identity_cli.sh`, and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`. The generation + verification half of M6 is now **Green-for-scope**. **Run 376 (registration/admission-check):** a **non-mutating** `qbind-node identity register-check` admission verifier is added (`crates/qbind-node/src/identity_cli.rs`; reads public material only; validates against the operator-identity + seed-list schema rules; deterministic NodeId cert verification; fails closed on embedded private material, malformed fields, wrong env, MainNet/TestNet, mismatched cert, `status=live` without reachability, `planned`+reachability), with `crates/qbind-node/tests/run_376_public_devnet_identity_registration_tests.rs` (14 tests), `scripts/devnet/run_376_public_devnet_identity_registration.sh`, and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md` — the registration/admission-check half of M6 is now **Green-for-scope**. **Gap:** no live public DevNet to register into (M4-gated) and operator-supplied root reuse/rotation/revocation is C4/C5-OPEN — stays Yellow/Partial. **Run 401 (better documented):** publishes the operator identity **continuity** package (`docs/release/public-devnet/identity/IDENTITY_CONTINUITY.md`, `ROTATION_REVOCATION_DEFERRAL.md`) documenting durable identity reuse across DevNet restarts and explicitly deferring production rotation/revocation to C4/C5/MainNet, verified against the existing `identity` CLI surfaces (`scripts/devnet/run_401_public_devnet_m6_identity_continuity.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_401.md`); **M6 stays Yellow/Partial** (no live registration path; C4/C5-OPEN). |
| M7 key-management | 🟢 | Consolidated key-management guide published + verified (Run 389, `security/KEY_MANAGEMENT.md`; Green-for-scope, no MainNet custody). |
| M8 trust-bundle bootstrap | 🟢 | DevNet trust-bundle bootstrap published + verified against reload-check (Run 389, `security/PQC_TRUST_BOOTSTRAP.md`; no live apply). |
| M9 PQC root / signing-key guidance | 🟢 | DevNet PQC root/signing-key guide published + verified (Run 389, `security/PQC_ROOT_AND_SIGNING_KEYS.md`; C4/C5 OPEN). |
| M10 public P2P port posture | 🟢 | **Run 360:** public P2P port/listen/advertise/NAT/`--enable-p2p` posture published (`docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md`), CLI-validated. No new flag; no discovery claim. |
| M11 peer admission policy | 🟢 | **Run 360:** open-network peer-admission policy published (`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`) against existing KEMTLS mutual-auth + PQC trust-root/trust-bundle surfaces; fail-closed matrix; peer claims advisory-only. |
| M12 abuse / DoS protections | 🟢 | **Run 360:** abuse/DoS posture published (`docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`) against `peer_rate_limiter` (default `1000` msg/s + `100` burst, on by default) + metrics. **Run 361:** source/test-only operator-configurable config model + bounded inbound connection-rate limiter boundary. **Run 362 (strengthened):** connection-rate limiter wired into the live `p2p_tcp` accept loop behind runtime-owned, default-off state; `qbind_p2p_connection_rate_drop_total` metric added; hidden/devnet-only operator CLI flags; release-binary evidence (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md`, 38 tests). **Run 363:** per-peer message-rate runtime override wired into the live `AsyncPeerManagerImpl` `PeerRateLimiter` construction path at source/test level (21 tests). **Run 364 (strengthened):** release-binary evidence for **both** controls on real `target/release/qbind-node` + a release helper (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md`, 7/7 scenarios). **Run 365–370:** deployed `P2pNodeBuilder` threading (365), deployed-builder-path release-binary evidence (366), connection-rate **live-socket** proof on P2P-capable `target/release/qbind-node` (367), admitted-peer per-peer socket flood on `AsyncPeerManagerImpl` (368), per-peer `PeerRateLimiter` wired onto the deployed `TcpKemTlsP2pService::read_loop` receive path via `DeployedInboundPerPeerLimiter` (369), and deployed per-peer drop metric wired end-to-end onto the deployed read loop with release-binary live-socket evidence (370, Route B). **Run 371 (Green):** a **second KEMTLS-admitted peer** completes real mutual auth over a real loopback socket against `target/release/qbind-node`, floods over-budget `P2pMessage::Consensus` frames through the deployed `read_loop`, and live `/metrics` exposes `qbind_net_per_peer_drops_total{reason="rate_limit"}` incrementing (~47 of 60) while under-budget stays absent; the Run 367/370 connection-rate live-socket proof is preserved and independent (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`, Route A / no production source change, helper 10/10). **Green scoped to these two abuse/DoS deployed live-socket controls;** defaults preserved; does not move M4/M6 or close C4/C5. **Run 372 (Green, hardening):** re-proves the Run 371 result under **strict mutual-auth admission** (`--p2p-mutual-auth required`) and **multi-peer concurrent flood** — two KEMTLS-admitted peers (honest under-budget + abusive over-budget) complete `MutualAuthMode::Required` handshakes against `target/release/qbind-node`, and live `/metrics` isolates the abusive peer's drops to its **own** per-peer bucket while the honest peer's bucket stays clean; the release helper also proves the strict-auth path with production-grade `PqcRootMode::PqcStaticRoot` material (ML-DSA-44 + ML-KEM-768) (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_372.md`, Route A / no production source change, helper 13/13). No new public CLI flags; strict mutual-auth only tightens admission; M4/M6 unchanged; C4/C5 remain OPEN. **Run 373 (Green, hardening):** extends Run 372's in-process PqcStaticRoot proof **cross-process** to the standalone binary — `devnet_pqc_root_helper` mints temporary ML-DSA-44 root + ML-KEM-768 leaf material (root signing key in memory only), and `target/release/qbind-node` runs under the pre-existing public flags `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root --p2p-trusted-root/--p2p-leaf-cert/--p2p-leaf-cert-key` (live `/metrics` `qbind_p2p_pqc_root_mode 1` / `qbind_p2p_pqc_roots_configured 1`); two KEMTLS-admitted peers built from the same operator material (honest under-budget + abusive over-budget) complete `MutualAuthMode::Required` + PqcStaticRoot handshakes and live `/metrics` isolates the abusive peer's drops to its own **cert-derived** per-peer bucket while the honest bucket stays clean (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_373.md`, Route A / no production source change, helper 13/13). No new public CLI flags; no trust-bundle weakening; M4/M6 unchanged; C4/C5 remain OPEN. |
| M13 telemetry / metrics | 🟢 | **Run 379:** operator observability package (`docs/release/public-devnet/observability/README.md`,`METRICS.md`,`SCRAPE_CONFIG.md`,`VERIFY.md`) documents safe `QBIND_METRICS_HTTP_ADDR` loopback exposure of the pre-existing `metrics_http` endpoint, with every metric family **verified by a live release-binary loopback scrape** (HTTP 200; required families present; honest gaps documented). Route B; no production source change; no launch/M4-Green claim. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`. |
| M14 monitoring / alerting | 🟢 | **Run 379:** alerting baseline (`ALERT_RULES.md`,`RUNBOOK.md`,`prometheus-scrape.example.yml`,`prometheus-alerts.example.yml`) — scrape config + `page`/`ticket`/`observe` alert rules that **parse as YAML** (harness-verified), enabled only for metrics present in the scrape; absent-metric alerts (`qbind_net_per_peer_drops_total`,`qbind_state_size_bytes`) kept in a **future/not-enabled** group; per-alert operator runbook. Route B; no production source change. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`. |
| M15 reset policy | 🟢 | **Run 390:** DevNet reset policy published + verified (`docs/release/public-devnet/ops/RESET_POLICY.md`): safety label, reset meaning, triggers, notice policy, operator actions, what-never-changes-silently, publish-safe reset evidence-record shape, hidden offline `--authority-state-reset` posture (no live governance / C4-C5 closure). Route B; no production source change; no new CLI flag. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md`. |
| M16 incident response | 🟢 | **Run 390 (reconciled):** prior Green rested only on the **internal** Beta-scoped `QBIND_INCIDENT_RESPONSE.md`; Run 390 publishes a **public-DevNet-scoped** operator incident-response process (`docs/release/public-devnet/ops/INCIDENT_RESPONSE.md` — severity, classes, first-response, evidence + redaction, escalation, publication, non-claims) that defers to the internal procedure. Green preserved on public-DevNet scoped evidence. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_390.md`. |
| M17 public documentation | 🟢 | **Run 358:** external how-to-run-a-node package published (`docs/release/public-devnet/operator/`), cross-linked from this readiness track and validated against real startup. |
| M18 user-facing disclaimers | 🟢 | **Run 358:** §3 safety label published in operator-facing material (`docs/release/public-devnet/operator/SAFETY.md` + every operator-doc header), not only in this internal matrix. |
| M19 network parameter publication | 🟢 | **Run 356:** `devnet-network-parameters.md` published as canonical operator artifact, checked against genesis + `QBIND_DEVNET_CHAIN_ID`. |
| M20 genesis hash publication | 🟢 | **Run 356:** canonical hash `0x48b3a862…af18145f` published + verifiable via `--print-genesis-hash` / `--expect-genesis-hash`. |
| S1 snapshot / backup / restore | 🟢 | **Run 394:** public-DevNet backup/restore baseline published (`docs/release/public-devnet/recovery/BACKUP_RESTORE.md`), verified against real pre-existing snapshot/restore CLI surfaces. Best-effort DevNet convenience; no data-permanence guarantee; wipe-and-rejoin default. |
| S2 data retention | 🟢 | **Run 394:** DevNet data-retention posture published (`docs/release/public-devnet/recovery/DATA_RETENTION.md`) — explicit reset / no-SLA / no-value, best-effort windows, redaction rules, reset-policy cross-link. |
| S3 upgrade procedure | 🟢 | **Run 394:** binary upgrade / rolling-restart procedure published (`docs/release/public-devnet/recovery/UPGRADE_PROCEDURE.md`), tied to release provenance verification + genesis pinning. |
| S4 rollback procedure | 🟢 | **Run 394:** rollback procedure published (`docs/release/public-devnet/recovery/ROLLBACK_PROCEDURE.md`), fail-closed on unsafe state edits; wipe-and-rejoin when compatibility uncertain. |
| S5 status page | 🟡 | **Run 395 (Route B):** no live status service (health view is M4-gated); publish-safe static status-page decision + future health-view schema/example published (`docs/release/public-devnet/status/` — `README.md`, `STATUS_PAGE_DECISION.md`, `STATUS_HEALTH_VIEW_SCHEMA.json`, `EXAMPLE_STATUS_HEALTH_VIEW.json`, `SAFETY.md`, `VERIFY.md`); example validates against schema and is marked `static-example`. Yellow, not Green — no deployed/maintained page; live status deferred to M4. |
| S6 alert rules / scrape config | 🟢 | **Run 395 (reconciled, Route A):** previously Red/"None shipped" — an inconsistency with M14, which already shipped these in Runs 379–381. Reconciled against the shipped observability package (`docs/release/public-devnet/observability/ALERT_RULES.md`, `SCRAPE_CONFIG.md`, `RUNBOOK.md`, `prometheus-scrape.example.yml`, `prometheus-alerts.example.yml`; both YAML re-parsed by the Run 395 harness). No content duplicated. |
| S7 seed-node runbook | 🟡 | **Run 392:** seed-node operations runbook + M4 Route-A deployment checklist + reachability evidence template published (`docs/release/public-devnet/network/SEED_NODE_OPERATIONS.md`, `M4_ROUTE_A_DEPLOYMENT_CHECKLIST.md`, `SEED_REACHABILITY_EVIDENCE_TEMPLATE.md`), verified against real CLI/help + seed-list schema. Operating a live seed remains M4-gated. |
| T1 faucet | ⚪ | Explicit DevNet non-goal; TestNet-deferred. |
| T2 RPC gateway | ⚪ | Explicit DevNet non-goal; TestNet-deferred. |
| T3 RPC rate limiting | ⚪ | Depends on T2; TestNet-deferred. |
| T4 explorer | ⚪ | TestNet-deferred. |
| T5 governance proof surface (scale) | 🟡 | Green-for-scope boundaries exist; network-scale hardening TestNet-deferred. |
| T6 validator-set rotation (live) | 🟡 | Green-for-scope boundary only; live-network exercise TestNet-deferred. |
| T7 data-retention SLAs | ⚪ | TestNet-deferred. |
| T8 soak / chaos / multi-region | ⚪ | TestNet-deferred. |
| N1 MainNet custody | 🔴 | MainNet-only. |
| N2 MainNet authority rotation/revocation | 🔴 | **Red**; MainNet-only. |
| N3 runtime authority-lifecycle wiring | 🔴 | Parked future work; Green-for-scope boundary is dead code from runtime. |
| N4 SLSA-grade provenance | 🔴 | MainNet-only. |
| N5 C4 | 🔴 | **OPEN**. |
| N6 C5 | 🔴 | **OPEN**. |
| N7 production economic finalization | 🔴 | MainNet-only. |

---

## 11. Exact next run recommendation for each Red/Yellow must-have

| Item | Status | Next-run recommendation |
|------|--------|--------------------------|
| M1 | 🟢 | **Done (Run 356):** canonical DevNet genesis artifact published + hash recorded (`docs/release/public-devnet/genesis/`). |
| M2 | 🟢 | **Done (Run 359):** published release-provenance record (commit + toolchain + build cmd + SHA-256 + BuildID) at `docs/release/public-devnet/binary/RELEASE_PROVENANCE.md`. |
| M3 | 🟢 | **Done (Run 359):** same-host, clean-tree two-build reproducibility (byte-identical `qbind-node`) + ELF BuildID documented (`docs/release/public-devnet/binary/REPRODUCIBILITY.md`). Cross-host/SLSA/signed-release **not** claimed. |
| M4 | 🟡 | **Format landed (Run 357):** seed-list schema + placeholder published (`docs/release/public-devnet/network/`). **Preflight (Run 377, Partial-positive):** schema-valid preflight live-seed candidate + reachability record + harness + tests; live admission gate release-proven; **only loopback/same-host reachability demonstrated — external reachability NOT proven (Route B), so no Green move.** **Next:** deploy a real, externally reachable seed/bootnode and capture external (off-host) reachability evidence, then promote the candidate to `status: live` to move Green. |
| M5 | 🟢 | **Done (Run 358):** external validator/full-node quickstart published + CLI-validated (`docs/release/public-devnet/operator/QUICKSTART.md`). |
| M6 | 🟡 | **Partial (Run 358; materially narrowed Run 374; first-class generation half Green-for-scope Run 375; registration/admission-check half Green-for-scope Run 376):** identity guidance + CLI-validated loading/selection, plus a stable operator-facing identity **generation + verification** package (`docs/release/public-devnet/identity/`, schema + harness), now exposed as a **first-class `qbind-node identity` command** (`crates/qbind-node/src/identity_cli.rs`; `generate`/`verify`/`print-public`/`seed-candidate`; Route B, DevNet-gated, default-safe; Run 374 example is now a thin wrapper), plus a **non-mutating `register-check` admission verifier** (Run 376; schema + deterministic-NodeId admission decision; fails closed on private material/malformed/wrong-env/mismatch/live-without-reachability). **Next:** add operator-supplied-root reuse/rotation and a live registration path (M4-gated) to move Green. |
| M7 | 🟢 | Done (Run 389): key-management guide consolidated + verified (`security/KEY_MANAGEMENT.md`). |
| M8 | 🟢 | Done (Run 389): DevNet trust-bundle bootstrap procedure published + verified (`security/PQC_TRUST_BOOTSTRAP.md`). |
| M9 | 🟢 | Done (Run 389): DevNet PQC root/signing-key guidance published + verified (`security/PQC_ROOT_AND_SIGNING_KEYS.md`). |
| M10 | 🟢 | **Done (Run 360):** public P2P port/NAT/`--enable-p2p` posture published (`docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md`). |
| M11 | 🟢 | **Done (Run 360):** open-network peer-admission policy published (`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`). |
| M12 | 🟢 | **Green (Run 371):** both abuse/DoS deployed live-socket controls proven on real `target/release/qbind-node`. Run 362 wired the bounded inbound connection-rate limiter into the live `p2p_tcp` accept loop (default-off, `qbind_p2p_connection_rate_drop_total` metric, hidden/devnet-only CLI flags, release-binary evidence). Run 363 wired the **per-peer message-rate runtime override** into the live `AsyncPeerManagerImpl` `PeerRateLimiter` construction path. Run 364 produced release-binary evidence for both controls (7/7). Run 365 threaded the CLI-derived `peer_rate_limiter_config` through the deployed `P2pNodeBuilder`; Run 366 landed deployed-builder-path release-binary evidence (8/8, LocalMesh blocked live sockets); **Run 367** proved the **connection-rate** control **live-socket** (10 inbound TCP connections, max 3 → 3 accepted / 7 refused, live `qbind_p2p_connection_rate_drop_total = 7`); Run 368 drove an admitted-peer per-peer flood on `AsyncPeerManagerImpl`; Run 369 wired the per-peer `PeerRateLimiter` onto the deployed `TcpKemTlsP2pService::read_loop`; Run 370 wired the deployed per-peer drop metric end-to-end with release-binary live-socket evidence (Route B). **Run 371** stands up a **second KEMTLS-admitted peer** that completes real mutual auth over a real loopback socket against `target/release/qbind-node`, floods over-budget `P2pMessage::Consensus` frames through the deployed `read_loop`, and observes live `/metrics` expose `qbind_net_per_peer_drops_total{reason="rate_limit"}` incrementing (~47 of 60) while under-budget stays absent — with the connection-rate live-socket proof preserved and independent (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`, Route A / no production source change, helper 10/10). **Green scoped to these two abuse/DoS deployed live-socket controls; defaults preserved; does not move M4/M6 or close C4/C5.** |
| M13 | 🟢 | **Done (Run 379):** operator metrics exposure guide published (`docs/release/public-devnet/observability/`), verified by a live release-binary loopback scrape. |
| M14 | 🟢 | **Done (Run 379):** alert-rule definitions + scrape config + runbook shipped (`docs/release/public-devnet/observability/`, `prometheus-*.example.yml`), YAML-parsed; absent-metric alerts marked future/not-enabled. |
| M15 | 🟢 | **Done (Run 390):** DevNet reset policy published + verified (`docs/release/public-devnet/ops/RESET_POLICY.md`). |
| M16 | 🟢 | **Done (Run 390, reconciled):** public-DevNet-scoped incident-response process published (`docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`), deferring to the internal `QBIND_INCIDENT_RESPONSE.md`. |
| M17 | 🟢 | **Done (Run 358):** external how-to-run-a-node package published (`docs/release/public-devnet/operator/`). |
| M18 | 🟢 | **Done (Run 358):** §3 safety label published in operator-facing material (`docs/release/public-devnet/operator/SAFETY.md`). |
| M19 | 🟢 | **Done (Run 356):** canonical network-parameter artifact published (`devnet-network-parameters.md`). |
| M20 | 🟢 | **Done (Run 356):** canonical genesis hash published + operator-verifiable (`VERIFY.md`). |

Note: several Yellow items can be closed by a small number of consolidated documentation/publication runs
(genesis+params+hash landed in Run 356; remaining: onboarding+identity+key-management+quickstart together;
trust-root bootstrap+PQC guidance together; monitoring+alerting together; port posture+admission+abuse together).

---

## 12. Public DevNet launch blocker summary

Public DevNet is **NOT yet launch-ready**. As of **Run 395 (reconciled Run 396)**, the remaining launch blocker
among the tracked must-haves is **M4** (Yellow, seed/bootnodes) with **M6** Yellow/Partial (identity); **M7, M8,
M9** are Green (Run 389), **M12** is Green (Run 371), **M13/M14** are Green (Run 379+), and **M15/M16** are Green
(Run 390 — reset policy published; incident-response reconciled). Among the non-blocking should-haves, **S1–S4**
are Green (Run 394) and **S6** is Green (Run 395, reconciled), while **S5** (status page) and **S7** (seed-node
runbook) remain Yellow (both live-status/live-seed paths are M4-gated). The launch blockers are, at minimum:

- **Red:** *(none among the tracked must-haves — M3 moved to Green in Run 359).*
- **Yellow (must reach Green):** M4 (seed/bootnodes — format+placeholder landed Run 357, external reachability
  still not proven Run 378/388/391, so still a launch blocker until live seeds + reachability evidence land),
  M6 (identity — generation/verification + register-check are Green-for-scope Run 375/376, but a live
  registration path is M4-gated and operator-root reuse/rotation/revocation is C4/C5-OPEN).

Because at least one must-have is not Green, this document does **not** mark public DevNet ready.

## 13. Public TestNet blocker summary

Beyond all DevNet must-haves, TestNet additionally requires (distinct from DevNet):

- Faucet (T1), public RPC gateway + rate limiting (T2/T3), explorer (T4).
- Governance-proof surface hardening at network scale (T5) and live validator-set rotation exercise (T6).
- Formal data-retention SLAs (T7) and soak/chaos/multi-region evidence (T8).
- The TestNet Alpha/Beta plan exit gates in `docs/testnet/`.

## 14. MainNet blocker summary

Beyond all DevNet and TestNet items, MainNet additionally requires (distinct from TestNet):

- MainNet custody (N1) and MainNet authority rotation/revocation under production custody (N2 — **Red**).
- Runtime wiring of the authority-lifecycle boundary chain into production execution (N3).
- SLSA-grade signed provenance for value-bearing releases (N4).
- **C4 closure (N5) and C5 closure (N6)** — both **OPEN**.
- Production economic finalization (N7), plus the full `QBIND_MAINNET_READINESS_CHECKLIST.md` gate.

---

## 15. C4/C5 non-closure statement

This document does **not** close C4 or C5. Full **C4 remains OPEN**. **C5 remains OPEN**. The Run 353/354
live epoch-transition authority-activation execution-sink prewrite / sink-commit-readiness boundary remains
**Green-for-scope only** and is not reinterpreted as production readiness or as C4/C5 closure. Public DevNet
readiness is a **separate release-readiness track** introduced here; progress on it does not affect the C4/C5
status, and C4/C5 closure is **not** a public DevNet launch precondition (it is MainNet-deferred).

---

## 16. Consolidated gap matrix

Columns: item · release stage · category · status · evidence source · blocker · risk if launched without it · next-run recommendation.

| Item | Stage | Category | Status | Evidence source | Blocker | Risk if launched without | Next run |
|------|-------|----------|--------|-----------------|---------|--------------------------|----------|
| genesis package | DevNet | network | 🟢 | `docs/release/public-devnet/genesis/` (Run 356) | Published + verified | Operators join divergent chains | Done (Run 356) |
| release binary provenance | DevNet | binary | 🟢 | `docs/release/public-devnet/binary/RELEASE_PROVENANCE.md` (Run 359) | Published + operator-verifiable | Unverifiable binaries | Done (Run 359) |
| release reproducibility / SHA / BuildID | DevNet | binary | 🟢 | `docs/release/public-devnet/binary/REPRODUCIBILITY.md` (Run 359) | Same-host two-build reproducibility + BuildID recorded | Cannot attest what operators run | Done (Run 359); cross-host/SLSA not claimed |
| seed nodes / bootnodes | DevNet | network | 🟡 | `docs/release/public-devnet/network/` (Run 357; preflight Run 377; Route-C external Runs 378/388/391/393) | Format + placeholder + preflight candidate published; external reachability NOT proven | Outsiders cannot join a live seed | **Launch blocker** — deploy a live externally reachable seed + capture off-host reachability evidence (M4) |
| validator onboarding | DevNet | docs | 🟢 | `docs/release/public-devnet/operator/QUICKSTART.md` (Run 358) | External quickstart published + CLI-validated | Onboarding failures/misconfig | Done (Run 358) |
| validator identity | DevNet | security | 🟡 | `docs/release/public-devnet/operator/IDENTITY.md`, `docs/release/public-devnet/identity/`, `identity_cli.rs` (Run 358/374/375/376; continuity docs Run 401) | Guidance + first-class `identity` generate/verify/register-check Green-for-scope; continuity/rotation-revocation-deferral documented (Run 401); live registration M4-gated, root reuse/rotation C4/C5-OPEN | Identity collisions/misconfig | Live registration path (M4-gated) + operator-root reuse/rotation |
| validator key-management guidance | DevNet | security | 🟢 | `docs/release/public-devnet/security/KEY_MANAGEMENT.md` (Run 389) | Consolidated guide published + verified (Green-for-scope; no MainNet custody) | Key mishandling | Done (Run 389) |
| trust-bundle bootstrap | DevNet | security | 🟢 | `docs/release/public-devnet/security/PQC_TRUST_BOOTSTRAP.md` (Run 389) | DevNet root bootstrap published + reload-check verified (no live apply) | Trust misconfiguration | Done (Run 389) |
| PQC root / signing-key guidance | DevNet | security | 🟢 | `docs/release/public-devnet/security/PQC_ROOT_AND_SIGNING_KEYS.md` (Run 389) | DevNet root/signing-key guidance published + verified (C4/C5 OPEN) | Weak/incorrect roots | Done (Run 389) |
| faucet | TestNet | ops | ⚪ | n/a (DevNet non-goal) | Deferred | n/a for DevNet | TestNet |
| RPC gateway | TestNet | network | ⚪ | n/a (DevNet non-goal) | Deferred | n/a for DevNet | TestNet |
| RPC rate limiting | TestNet | security | ⚪ | n/a | Deferred | n/a for DevNet | TestNet |
| public P2P port posture | DevNet | network | 🟢 | `docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md` (Run 360) | Public exposure/NAT posture published + CLI-validated | Unintended exposure/NAT issues | Done (Run 360) |
| peer admission policy | DevNet | security | 🟢 | `docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md` (Run 360) | Open-network admission policy published + fail-closed matrix | Eclipse/spam admission | Done (Run 360) |
| telemetry / metrics | DevNet | observability | 🟢 | `docs/release/public-devnet/observability/` (Run 379–381) | Operator exposure guide published + release-binary scrape-verified | Blind operations | Done (Run 379) |
| monitoring / alerting | DevNet | observability | 🟢 | `docs/release/public-devnet/observability/ALERT_RULES.md`, `prometheus-*.example.yml` (Run 379–381) | Alert rules + scrape config shipped + YAML-verified | Missed incidents | Done (Run 379) |
| status page | DevNet | observability | 🟡 | `docs/release/public-devnet/status/` (Run 395) | Static decision + health-view schema published; live status M4-gated | No shared health view yet | Deploy live view once M4 Green |
| explorer | TestNet | observability | ⚪ | n/a | Deferred | n/a for DevNet | TestNet |
| reset policy | DevNet | ops | 🟢 | `docs/release/public-devnet/ops/RESET_POLICY.md` (Run 390); CLI `--authority-state-reset` | Published + verified | — | Done (Run 390) |
| incident response | DevNet | ops | 🟢 | `docs/release/public-devnet/ops/INCIDENT_RESPONSE.md` (Run 390) + internal `QBIND_INCIDENT_RESPONSE.md` | Public-DevNet-scoped process published (reconciled) | — | Done (Run 390) |
| abuse handling | DevNet | security | 🟢 | `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`, `peer_rate_limiter.rs` (Run 360–373) | Posture published; both deployed live-socket controls proven (Run 371) | DoS/flooding | Done (Run 371); scoped to abuse/DoS controls only |
| snapshot / backup / restore | DevNet | ops | 🟢 | `docs/release/public-devnet/recovery/BACKUP_RESTORE.md` (Run 394); `--restore-from-snapshot`, `state_snapshot.rs` | Published + verified (best-effort DevNet convenience) | Data loss on reset (accepted; wipe-and-rejoin default) | Done (Run 394) |
| data retention | DevNet | ops | 🟢 | `docs/release/public-devnet/recovery/DATA_RETENTION.md` (Run 394) | Published (reset / no-SLA / no-value explicit) | — | Done (Run 394) |
| upgrade procedure | DevNet | ops | 🟢 | `docs/release/public-devnet/recovery/UPGRADE_PROCEDURE.md` (Run 394) | Published + tied to release provenance | — | Done (Run 394) |
| rollback procedure | DevNet | ops | 🟢 | `docs/release/public-devnet/recovery/ROLLBACK_PROCEDURE.md` (Run 394) | Published + fail-closed on unsafe state edits | — | Done (Run 394) |
| public documentation | DevNet | docs | 🟢 | `docs/release/public-devnet/operator/` (Run 358) | External how-to-run package published + validated | Operators cannot self-serve | Done (Run 358) |
| user-facing disclaimers | DevNet | docs | 🟢 | `docs/release/public-devnet/operator/SAFETY.md` + operator-doc headers (Run 358) | §3 safety label published in release material | Misperceived value/stability | Done (Run 358) |
| network parameter publication | DevNet | network | 🟢 | `devnet-network-parameters.md` (Run 356) | Published + checked vs source | Config divergence | Done (Run 356) |
| genesis hash publication | DevNet | network | 🟢 | `--print-genesis-hash` + `VERIFY.md` (Run 356) | Canonical hash published | Chain divergence | Done (Run 356) |
| DevNet authority lifecycle | DevNet | governance | 🟡 | authority-lifecycle evidence runs | Green-for-scope only | Overclaiming readiness | Keep scoped |
| governance proof status | TestNet | governance | 🟡 | governance evidence runs, surface audit | Scale hardening deferred | Overclaiming readiness | TestNet |
| validator-set rotation status | TestNet | governance | 🟡 | Run 303–310 boundaries | Green-for-scope only; not live | Overclaiming readiness | TestNet |
| runtime wiring for authority lifecycle | MainNet | governance | 🔴 | Run 353/354 (dead code from runtime) | Parked future work | Unsafe activation | MainNet track |
| MainNet custody | MainNet | custody | 🔴 | trust-anchor authority model | MainNet-only | Value at risk | MainNet track |
| MainNet authority rotation/revocation | MainNet | custody | 🔴 | authority model | **Red** | Loss of control of authority | MainNet track |
| C4 | MainNet | governance | 🔴 | `QBIND_C4_C5_CLOSURE_CRITERIA.md` | **OPEN** | Incomplete production governance | MainNet track |
| C5 | MainNet | custody | 🔴 | `QBIND_C4_C5_CLOSURE_CRITERIA.md` | **OPEN** | Incomplete production custody | MainNet track |

---

## 17. Summary

Public DevNet readiness is a **tracked, evidence-grounded classification**. As of **Run 359**, the canonical
DevNet genesis package, network parameters, and genesis hash (Run 356) are published and operator-verifiable,
keeping **M1, M19, M20** Green (joining **M16 incident response**); Run 357 added the canonical seed-list format +
placeholder artifact, moving **M4 Red → Yellow** while keeping it a launch blocker; Run 358 publishes the external
operator onboarding package (`docs/release/public-devnet/operator/`), moving **M5, M17, M18 Yellow → Green** and
keeping **M6 Yellow/Partial** (identity guidance published, but no operator-facing identity-generation command yet);
Run 359 publishes the release-binary provenance + reproducibility/BuildID package
(`docs/release/public-devnet/binary/`), moving **M2 Yellow → Green** and **M3 Red → Green** on the basis of a
canonical operator-verifiable provenance record plus a same-host, clean-tree two-build reproducibility result
(byte-identical `qbind-node`, SHA-256 `f916af6d…b22990`, stable ELF BuildID `274fdaf3…5208b`; cross-host/SLSA/signed
not claimed); Run 360 publishes the P2P exposure / peer-admission / abuse-DoS posture package
(`docs/release/public-devnet/p2p/`), moving **M10, M11 Yellow → Green** (public P2P port posture and open-network
peer-admission policy, validated against the existing CLI/transport/trust-bundle surfaces) and keeping **M12
Yellow/Partial** (abuse/DoS posture published against the real per-peer rate limiter + metrics, but its thresholds are
hardcoded with no operator-facing config surface and no per-connection-rate limiter is exposed); Run 361 **strengthens
M12** with a source/test-only operator-configurable abuse/DoS config model + a pure, deterministic bounded inbound
connection-rate limiter boundary (`crates/qbind-node/src/public_devnet_abuse_dos_config.rs`), whose safe default
preserves the current `1000` msg/s + `100` burst behavior and leaves the connection limiter disabled; Run 362 further
**strengthens M12** by wiring that connection-rate limiter into the live `p2p_tcp` accept loop behind runtime-owned,
default-off state (`crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs`), adding the
`qbind_p2p_connection_rate_drop_total` metric, and exposing hidden/devnet-only operator CLI flags with release-binary
evidence; Run 363 further **strengthens M12** by wiring the **per-peer message-rate runtime override** into the live
per-peer `PeerRateLimiter` construction path used by `AsyncPeerManager` at source/test level (the Run 362 hidden
`--p2p-max-messages-per-second` / `--p2p-burst-allowance` flags now affect the live limiter; default preserved);
Run 364 further **strengthens M12** by producing **release-binary evidence for both controls** on real
`target/release/qbind-node` + a release helper (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md`, 7/7 scenarios) — but
**M12 stays Yellow/Partial (stronger)** because the deployed `qbind-node` does not yet thread the CLI-derived
`peer_rate_limiter_config` into its live `AsyncPeerManagerImpl` (the per-peer override reaches only the peer-manager
construction path, not the running node end-to-end; connection-rate is production-wired), so **Green remains deferred**.
**Run 365** threaded the override through the deployed builder; **Run 366** produced deployed-builder-path release-binary
evidence for both controls (LocalMesh blocked live sockets); **Run 367** proves the **connection-rate** control
**live-socket** on a running P2P-capable `target/release/qbind-node` (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md`),
but the per-peer message-rate live-admitted-peer path is still a Run 368 blocker, so **Green remains deferred**.
Public DevNet is still **not launch-ready**: **M4 remains Yellow-but-blocking** for seed/bootnodes until real
live seeds + reachability evidence land, and **M6 remains Yellow/Partial** (identity generation/verification +
register-check are Green-for-scope, but a live registration path is M4-gated). **M7/M8/M9 are Green (Run 389)**,
**M12 is Green (Run 371)**, **M13/M14 are Green (Run 379+)**, and **Run 390 moves M15 Yellow → Green (DevNet
reset policy published — `docs/release/public-devnet/ops/RESET_POLICY.md`) and reconciles M16 to Green** with a
public-DevNet-scoped incident-response process (`docs/release/public-devnet/ops/INCIDENT_RESPONSE.md`) that
defers to the internal `docs/ops/QBIND_INCIDENT_RESPONSE.md`.
C4 and C5 remain **OPEN**, MainNet authority rotation/revocation remains **Red**, and the Run 353/354 boundary
remains Green-for-scope only. The most efficient remaining path forward is real external seed reachability
(M4) plus the M4-gated live identity registration path (M6).

**Canonical current status (as of Run 395, reconciled Run 396).** Must-haves: **M1, M2, M3 Green**; **M4 Yellow /
launch-blocking**; **M5 Green**; **M6 Yellow / Partial**; **M7, M8, M9 Green (Green-for-scope)**; **M10, M11, M12,
M13, M14, M15, M16, M17, M18, M19, M20 Green**. Should-haves: **S1, S2, S3, S4 Green**; **S5 Yellow**; **S6 Green**;
**S7 Yellow**. TestNet-deferred: **T1–T4, T7, T8 N/A / deferred for DevNet**; **T5, T6 Yellow (TestNet-deferred
boundary-only)**. MainNet-deferred: **N1, N2, N3, N4, N7 Red**; **N5 (C4) OPEN / Red**; **N6 (C5) OPEN / Red**.
Because at least one must-have (M4) is not Green, **public DevNet remains NOT launch-ready**; C4 and C5 remain
**OPEN**; no TestNet or MainNet readiness is claimed. Run 396 is a documentation-consistency reconciliation only
(the §10 status table and §4/§5 checklists are the source of truth); it changes no readiness semantics and adds no
functionality.