# QBIND Public DevNet Readiness Criteria and Gap Matrix

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
- [ ] M4. Seed/bootnode list published for public join. — **Yellow (Run 357; strengthened Run 377; external attempt Run 378)**: canonical seed-list format + placeholder artifact published (`docs/release/public-devnet/network/`); **Run 377** adds a schema-valid **preflight** live-seed candidate (`devnet-seeds.live-candidate.json`, `status: planned`), a reachability evidence record (`network/reachability/RUN_377_qbind-devnet-seed-1.md`), a release harness, and 4 tests, and release-proves the `register-check --status live --reachability-evidence` admission gate — but **only loopback/same-host reachability was demonstrated**. **Run 378** attempts **Route A** (real external reachability from an independent external vantage point) and records **Route C** — no external ingress / no independent external vantage point is available in the sandboxed environment, so no real endpoint can be exposed and external reachability is **NOT proven** (`network/reachability/RUN_378_qbind-devnet-seed-1.md` documents the Route A infrastructure prerequisites; `run_378_public_devnet_external_seed_reachability.sh` + 4 tests). **Still a launch blocker** — no live, externally reachable seed.
- [x] M5. Validator/full-node onboarding quickstart for external operators. — **Green (Run 358)**: external operator quickstart published (`docs/release/public-devnet/operator/QUICKSTART.md`), validated against the real `qbind-node` CLI surface (`--help`), the Run 356 genesis package, and the Run 357 seed-list format.
- [ ] M6. Validator identity guidance (node identity/key generation) published. — **Yellow / Partial (Run 358; materially narrowed Run 374; first-class generation half Green-for-scope Run 375)**: identity guidance published (`docs/release/public-devnet/operator/IDENTITY.md`) and validated against pre-existing identity/signer **loading/selection** flags; **Run 374** adds a stable, release-built operator-facing identity **generation + verification** package (`docs/release/public-devnet/identity/` + `run_374_public_devnet_identity_generation_helper` + harness + `OPERATOR_IDENTITY_SCHEMA.json`) that generates node/seed/validator-candidate material, emits a schema-validated public identity, deterministically re-derives the NodeId, inserts into the seed-list, and is accepted by a real loopback strict-auth `qbind-node` boot (MainNet/TestNet + mismatch fail closed). **Run 375** promotes this into a stable **first-class `qbind-node identity generate/verify/print-public/seed-candidate` command** (`crates/qbind-node/src/identity_cli.rs`; Route B / DevNet-gated / default-safe), with the Run 374 example now a thin wrapper (`crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs`, `scripts/devnet/run_375_public_devnet_identity_cli.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`) — the **generation + verification half of M6 is Green-for-scope**. **Run 376** adds a **non-mutating** `qbind-node identity register-check` admission verifier (reads public material only; validates against operator-identity + seed-list schema rules; deterministic NodeId cert verification; fails closed on private material, malformed fields, wrong env, MainNet/TestNet, mismatched cert, `status=live` without reachability, `planned`+reachability) with `crates/qbind-node/tests/run_376_public_devnet_identity_registration_tests.rs` (14 tests), `scripts/devnet/run_376_public_devnet_identity_registration.sh`, and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md` — the **registration/admission-check half of M6 is now Green-for-scope**. **Remaining gap:** no live public DevNet exists to register into (M4-gated) and operator-supplied root reuse/rotation/revocation is C4/C5-OPEN — M6 stays Yellow/Partial until a live registration path lands.
- [ ] M7. Validator key-management guidance (local keystore / remote signer / HSM options) published.
- [ ] M8. PQC trust-bundle bootstrap process for DevNet trust roots published.
- [ ] M9. PQC root / signing-key guidance for DevNet published.
- [x] M10. Public P2P port posture defined (listen/advertise, `--enable-p2p` default, NAT guidance). — **Green (Run 360)**: public P2P port posture published (`docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md`), validated against the existing `qbind-node` CLI surface (`--enable-p2p` default `false`, `--p2p-listen-addr` default `127.0.0.1:0`, `--p2p-advertised-addr`, `--p2p-peer`, `--expect-genesis-hash`, all present in `--help`); no new flag, no default behaviour change, no discovery claim.
- [x] M11. Peer admission policy defined for an open network. — **Green (Run 360)**: peer-admission policy published (`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`), validated against the existing KEMTLS mutual-auth (`--p2p-mutual-auth`), PQC root (`--p2p-pqc-root-mode`, `--p2p-trusted-root`, `--p2p-leaf-cert`/`-key`, `--p2p-peer-leaf-cert`) and trust-bundle (`--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`) surfaces; fail-closed failure matrix documented; peer claims advisory-only, peer-driven apply out of scope; no admission-logic change.
- [ ] M12. Abuse / DoS protections documented and enabled (per-peer rate limiting posture). — **Yellow / Partial, strengthened (Run 362)**: abuse/DoS posture published Run 360 (`docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`) against the real per-peer rate limiter (`peer_rate_limiter.rs`: default `1000` msg/s + `100` burst, enabled by default); **Run 361** added a source/test-only operator-configurable abuse/DoS config model + a bounded inbound **connection-rate limiter** boundary; **Run 362** wires that connection-rate limiter into the live `p2p_tcp` accept loop behind runtime-owned, default-off state, adds the `qbind_p2p_connection_rate_drop_total` metric, and exposes hidden/devnet-only operator CLI flags (`crates/qbind-node/src/public_devnet_abuse_dos_runtime.rs`, tests `tests/run_362_public_devnet_abuse_dos_runtime_tests.rs`, evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md`). Safe default preserves current behavior bit-for-bit (`1000` msg/s + `100` burst; connection limiter disabled). **Run 363** wired the per-peer message-rate runtime override into the live `AsyncPeerManagerImpl` `PeerRateLimiter` construction path at source/test level (the Run 362 hidden `--p2p-max-messages-per-second` / `--p2p-burst-allowance` flags now affect the live limiter; tests `tests/run_363_public_devnet_per_peer_message_rate_runtime_tests.rs`). **Run 364** produced release-binary evidence for **both** controls on real `target/release/qbind-node` + a release helper (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md`, `docs/devnet/run_364_public_devnet_abuse_dos_m12_release_binary/`, 7/7 scenarios). **Gap remaining:** the deployed `qbind-node` (`main.rs` / `p2p_node_builder`) does not yet thread the CLI-derived `peer_rate_limiter_config` into its live `AsyncPeerManagerImpl`, so the per-peer message-rate override reaches only the peer-manager *construction path*, not the running node end-to-end. M12 stays **Yellow/Partial** (strengthened); **Green still deferred** pending per-peer message-rate end-to-end production threading + load evidence. **Run 365** threads the CLI-derived `peer_rate_limiter_config` through the deployed `P2pNodeBuilder` into the live `AsyncPeerManagerImpl` construction path (`P2pNodeBuilder::deployed_peer_rate_limiter_config` / `build_deployed_peer_manager`, `P2pNodeContext.peer_rate_limiter_config`; tests `tests/run_365_public_devnet_deployed_peer_rate_threading_tests.rs`, evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_365.md`), closing the source/test gap Run 364 flagged with defaults preserved and no new public CLI flags. M12 stays **Yellow/Partial** (strengthened); **Green still deferred to Run 366** pending release-binary end-to-end evidence. **Run 366** lands release-binary evidence that the deployed `P2pNodeBuilder` path (`with_abuse_dos_runtime_config` → `deployed_peer_rate_limiter_config` → `build_deployed_peer_manager`) honors **both** controls on real `target/release/qbind-node` + a release helper (`crates/qbind-node/examples/run_366_public_devnet_abuse_dos_m12_end_to_end_release_helper.rs`, `scripts/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_366.md`, `docs/devnet/run_366_public_devnet_abuse_dos_m12_end_to_end_release_binary/`, 8/8 scenarios; no production source change). M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**: a running `qbind-node` cannot be driven over its live P2P inbound/message socket path here because DevNet runs in LocalMesh mode (`--enable-p2p` ignored), so the evidence is deployed-builder-path release-binary, not live-socket; Green remains deferred pending live-socket end-to-end + load evidence. **Run 367** drives the real `target/release/qbind-node` in a P2P-capable loopback mode (`--network-mode p2p --enable-p2p --p2p-listen-addr 127.0.0.1:<port>`) — fixing the Run 366 LocalMesh blocker — and proves the accept-loop **connection-rate** control **live-socket**: under-budget inbound TCP connections admitted with `qbind_p2p_connection_rate_drop_total` at 0, over-budget refused with the metric incrementing by exactly the over-budget count (10 connections, max 3 → 3 accepted / 7 refused, metric = 7), observed on the live `/metrics` endpoint (`crates/qbind-node/examples/run_367_public_devnet_abuse_dos_live_socket_helper.rs`, `scripts/devnet/run_367_public_devnet_abuse_dos_live_socket_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_367.md`, helper 8/8; no production source change). M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**: the per-peer **message-rate** control is still not driven over an admitted live peer socket (it enforces on the `AsyncPeerManagerImpl` receive path and needs a second KEMTLS peer flood harness), so it remains deployed-builder-path evidence; since M12 Green requires **both** controls over a live socket, Green is deferred to a Run 368 two-node message-flood harness. **Run 368** strengthens the per-peer message-rate evidence to a **real admitted-peer socket** proof: it registers a peer on a live `AsyncPeerManagerImpl` over a loopback TCP socket pair and floods `NetMessage` frames — under-budget accepted, over-budget dropped by the live `PeerRateLimiter` (≈75 of 80) with `qbind_net_per_peer_drops_total{...,reason="rate_limit"}` / `total_rate_limit_drops()` incrementing — and re-runs the Run 367 connection-rate live-socket proof (`crates/qbind-node/examples/run_368_public_devnet_abuse_dos_per_peer_live_socket_helper.rs`, `scripts/devnet/run_368_public_devnet_abuse_dos_per_peer_live_socket_release_binary.sh`, `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_368.md`, helper 9/9; no production source change). **Decision gate = Route C:** the **deployed** `qbind-node` inbound path (`TcpKemTlsP2pService::subscribe` → `P2pInboundDemuxer` → handlers) does NOT consult the `PeerRateLimiter` and `AsyncPeerManagerImpl` is never spawned by `main.rs`, so this is `AsyncPeerManagerImpl`-layer evidence (plain-TCP admitted peer), not the deployed socket and not KEMTLS. M12 stays **Yellow/Partial** (strengthened) and **does NOT move Green**; remaining blocker: wire the `PeerRateLimiter` onto the deployed TcpKemTls receive path (recommended Run 369). **Run 369** wires that per-peer `PeerRateLimiter` onto the deployed inbound receive path (`TcpKemTlsP2pService::read_loop` → `inbound_tx` → `subscribe()` → `P2pInboundDemuxer` → handlers) via the new `DeployedInboundPerPeerLimiter` adapter (`crates/qbind-node/src/deployed_inbound_per_peer_limiter.rs`), installed by `P2pNodeBuilder::start()` from `deployed_peer_rate_limiter_config()` (default `1000` msg/s + `100` burst). Over-budget inbound frames are dropped before demuxer dispatch with the adapter's per-peer drop counter (and `qbind_net_per_peer_drops_total{reason="rate_limit"}` when a `NodeMetrics` handle is present) incrementing; the connection is not torn down and the connection-rate metric is never touched (`tests/run_369_public_devnet_deployed_per_peer_limiter_wiring_tests.rs`, 24/24; evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_369.md`). Bucket keying derives a `PeerId` from the first 8 bytes of the connection `NodeId` for rate-limit bucket selection only — not an identity/auth claim. M12 stays **Yellow/Partial — deployed TcpKemTls receive-path source/test wiring landed** and **does NOT move Green**: release-binary live-socket deployed-path evidence for **both** controls is deferred to Run 370. Defaults preserved; no new public CLI flags; no admission/trust/wire-format change.
- [x] M13. Telemetry / metrics baseline available to operators. — **Green (Run 379)**: operator-facing public DevNet observability package published (`docs/release/public-devnet/observability/` — `README.md`, `METRICS.md`, `SCRAPE_CONFIG.md`, `VERIFY.md`) documenting safe metrics exposure via the pre-existing `metrics_http` endpoint gated by `QBIND_METRICS_HTTP_ADDR=127.0.0.1:<port>` (loopback-only; no auth/TLS; disabled by default), with every listed metric family **verified by a live loopback scrape of the release `qbind-node` binary** (HTTP 200; required families `qbind_consensus_committed_height`, `qbind_p2p_connections_current`, `qbind_p2p_connection_rate_drop_total`, `qbind_p2p_pqc_trust_bundle_*` present; honest gaps — per-peer drop series absent until first drop, no build/chain/free-disk gauge, crypto sub-metrics unserved — documented). Harness `scripts/devnet/run_379_public_devnet_observability_baseline.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`; **no production source change, no new CLI flag.** No launch/M4-Green/C4-C5/TestNet/MainNet claim. **Still Green (Run 380)**: hardening (Route A/C, no production source change) adds release-binary evidence that `qbind_net_per_peer_drops_total{reason="rate_limit"}` is exposable on demand (absent in a clean scrape, present after an induced per-peer drop) and confirms `/metrics` stays disabled without `QBIND_METRICS_HTTP_ADDR`; evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`. **Still Green (Run 381)**: a minimal read-only source change (Route B) adds the low-cardinality secret-free `qbind_node_build_info{version,build_id,git_commit,env,chain_id}` info gauge and the qbind-owned `qbind_node_data_dir_free_bytes` free-space gauge (value only, no path/host label) to the release scrape; `/metrics` stays disabled without `QBIND_METRICS_HTTP_ADDR`; harness `scripts/devnet/run_381_public_devnet_observability_gauges.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`.
- [x] M14. Monitoring / alerting baseline available to operators. — **Green (Run 379)**: operator-facing alerting baseline published (`docs/release/public-devnet/observability/ALERT_RULES.md`, `RUNBOOK.md`, machine-readable `prometheus-scrape.example.yml` + `prometheus-alerts.example.yml`) — example Prometheus scrape config + alert rules that **parse as YAML** (verified by the Run 379 harness), with `page`/`ticket`/`observe` severities and a per-alert operator runbook. Enabled rules reference only metrics verified present in the release-binary scrape (node/metrics-endpoint down, consensus no-progress, zero P2P connections, sustained M12 connection-rate drops, trust-bundle signature rejections + sequence-persist failure, snapshot failures, restore/catch-up stuck, peer-candidate rejections); alerts on **absent** metrics (`qbind_net_per_peer_drops_total`, `qbind_state_size_bytes`) are kept in a clearly-marked **future / not-enabled** group. Evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`; **no production source change.** No launch/M4-Green/C4-C5/TestNet/MainNet claim. **Still Green (Run 380)**: the per-peer alert `QbindPerPeerRateLimitDropsSustained` is promoted **future → enabled** with release-binary scrape evidence (metric present after an induced per-peer drop; connection-rate control independent); only the absent disk metric remains in the future/not-enabled group (use node-exporter). Harness `scripts/devnet/run_380_public_devnet_observability_hardening.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_380.md`; **no production source change.** **Still Green (Run 381)**: the disk alert `QbindNodeDiskSpaceLow` is promoted **future → enabled** against the new qbind-owned `qbind_node_data_dir_free_bytes` gauge proven present in the release scrape; the future/not-enabled group now carries only the still-absent legacy `qbind_state_size_bytes` gauge (`QbindStateSizeHigh`); scrape + alert YAML still parse. Harness `scripts/devnet/run_381_public_devnet_observability_gauges.sh` (`RESULT=POSITIVE`), evidence `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_381.md`; minimal read-only metrics source change only.
- [ ] M15. Reset policy published (when/how DevNet state is wiped).
- [ ] M16. Incident-response process published.
- [x] M17. Public documentation (how to run a node) sufficient for unassisted external bring-up. — **Green (Run 358)**: external how-to-run-a-node package published (`docs/release/public-devnet/operator/` — `README.md`, `QUICKSTART.md`, `IDENTITY.md`, `SAFETY.md`, `VERIFY.md`), cross-linked from this readiness track and validated against the real `qbind-node` startup path.
- [x] M18. User-facing disclaimers published (the §3 safety label). — **Green (Run 358)**: the §3 safety label is published in operator-facing material (`docs/release/public-devnet/operator/SAFETY.md` and the header of every operator doc), not only in this internal matrix.
- [x] M19. Network parameter publication (chain id, env scope, consensus/timing params). — **Green (Run 356)**; see `docs/release/public-devnet/genesis/devnet-network-parameters.md`.
- [x] M20. Genesis hash publication (canonical hash operators verify with `--expect-genesis-hash`). — **Green (Run 356)**; hash `0x48b3a862befe50e31bad5e1e11ba1ad282dc65723b1989e9ce2091b4af18145f`, see `docs/release/public-devnet/genesis/VERIFY.md`.

---

## 5. Should-have checklist (strongly recommended, not launch-blocking)

- [ ] S1. Snapshot / backup / restore baseline usable by operators (creation + restore path).
- [ ] S2. Data-retention posture documented for DevNet.
- [ ] S3. Upgrade procedure documented (binary upgrade / rolling restart).
- [ ] S4. Rollback procedure documented.
- [ ] S5. Status page or aggregate health view.
- [ ] S6. Alert-rule definitions / scrape config shipped alongside the metrics baseline.
- [ ] S7. Seed-node operational runbook (operating the published seeds).

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
| M16 | Reference to `docs/ops/QBIND_INCIDENT_RESPONSE.md` scoped for public DevNet. |
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
| M15 | Ops | CLI `--authority-state-reset`, `crates/qbind-ledger/src/authority_state_reset.rs` |
| M16 | Ops | `docs/ops/QBIND_INCIDENT_RESPONSE.md`, `docs/ops/QBIND_OPERATOR_DRILL_CATALOG.md` |
| M18 | Docs | This document §3 |
| S1, S2 | Ops | `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md`, `crates/qbind-ledger/src/state_snapshot.rs` |
| S3, S4 | Release mgmt | `docs/release/QBIND_RELEASE_TRACK_SPEC.md`; no staged upgrade/rollback runbook yet |
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
| M4 seed/bootnodes | 🟡 | **Run 357:** canonical seed-list format (`devnet-seed-list.schema.json`) + placeholder artifact (`devnet-seeds.placeholder.json`) published under `docs/release/public-devnet/network/`, verified + genesis-pinned. **Run 377 (strengthened, Partial-positive):** a schema-valid **preflight** live-seed candidate (`devnet-seeds.live-candidate.json`, `status: planned`, real Run-375-path public `node_id`/`peer_id`, RFC 5737 host, null reachability), a reachability evidence record (`network/reachability/RUN_377_qbind-devnet-seed-1.md`), `scripts/devnet/run_377_public_devnet_live_seed_reachability.sh`, `crates/qbind-node/tests/run_377_public_devnet_live_seed_reachability_tests.rs` (4 tests), and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_377.md` land with **no production source change**; the `register-check --status live --reachability-evidence` gate (Run 376) is release-proven and a real loopback `qbind-node` P2P listener is dialed same-host. **Decision gate = Route B:** external reachability from outside the operator host/NAT was **NOT proven**, so **M4 does not move Green**. Still **Red-equivalent for launch**: no live, externally reachable seed, static `--p2p-peer` only, no discovery. **Launch blocker.** |
| M5 validator onboarding | 🟢 | **Run 358:** external operator quickstart published (`docs/release/public-devnet/operator/QUICKSTART.md`), validated against the real `qbind-node --help` CLI surface, the Run 356 genesis package, and the Run 357 seed-list format. |
| M6 validator identity | 🟡 | **Run 358:** identity guidance published (`docs/release/public-devnet/operator/IDENTITY.md`), validated against pre-existing identity/signer **loading/selection** flags. **Run 374 (materially narrowed):** stable, release-built operator-facing identity **generation + verification** package published (`docs/release/public-devnet/identity/` + `run_374_public_devnet_identity_generation_helper` + `scripts/devnet/run_374_public_devnet_identity_generation.sh` + `OPERATOR_IDENTITY_SCHEMA.json`, Route B / no production source change); generates node/seed/validator-candidate material (root signing key in-memory only, ML-KEM-768 leaf secret `0600`), emits schema-validated public identity, deterministically re-derives NodeId, inserts into the seed-list, accepted by a real loopback `qbind-node` strict-auth + static-root boot (`qbind_p2p_pqc_root_mode 1`); MainNet/TestNet + mismatched material fail closed (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_374.md`). **Run 375 (first-class command):** the workflow is promoted into a stable **first-class `qbind-node identity` command** (`crates/qbind-node/src/identity_cli.rs`; `generate`/`verify`/`print-public`/`seed-candidate`; Route B, DevNet-gated, default-safe, no runtime/wire/admission change; the Run 374 example is now a thin wrapper), with `crates/qbind-node/tests/run_375_public_devnet_identity_cli_tests.rs`, `scripts/devnet/run_375_public_devnet_identity_cli.sh`, and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_375.md`. The generation + verification half of M6 is now **Green-for-scope**. **Run 376 (registration/admission-check):** a **non-mutating** `qbind-node identity register-check` admission verifier is added (`crates/qbind-node/src/identity_cli.rs`; reads public material only; validates against the operator-identity + seed-list schema rules; deterministic NodeId cert verification; fails closed on embedded private material, malformed fields, wrong env, MainNet/TestNet, mismatched cert, `status=live` without reachability, `planned`+reachability), with `crates/qbind-node/tests/run_376_public_devnet_identity_registration_tests.rs` (14 tests), `scripts/devnet/run_376_public_devnet_identity_registration.sh`, and `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_376.md` — the registration/admission-check half of M6 is now **Green-for-scope**. **Gap:** no live public DevNet to register into (M4-gated) and operator-supplied root reuse/rotation/revocation is C4/C5-OPEN — stays Yellow/Partial. |
| M7 key-management | 🟡 | Local keystore / remote signer / HSM surfaces exist; no consolidated guide. |
| M8 trust-bundle bootstrap | 🟡 | Runbook + `pqc_trust_bundle` exist; DevNet root bootstrap not published. |
| M9 PQC root / signing-key guidance | 🟡 | CLI + runbook exist; DevNet-specific guidance not consolidated. |
| M10 public P2P port posture | 🟢 | **Run 360:** public P2P port/listen/advertise/NAT/`--enable-p2p` posture published (`docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md`), CLI-validated. No new flag; no discovery claim. |
| M11 peer admission policy | 🟢 | **Run 360:** open-network peer-admission policy published (`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`) against existing KEMTLS mutual-auth + PQC trust-root/trust-bundle surfaces; fail-closed matrix; peer claims advisory-only. |
| M12 abuse / DoS protections | 🟢 | **Run 360:** abuse/DoS posture published (`docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`) against `peer_rate_limiter` (default `1000` msg/s + `100` burst, on by default) + metrics. **Run 361:** source/test-only operator-configurable config model + bounded inbound connection-rate limiter boundary. **Run 362 (strengthened):** connection-rate limiter wired into the live `p2p_tcp` accept loop behind runtime-owned, default-off state; `qbind_p2p_connection_rate_drop_total` metric added; hidden/devnet-only operator CLI flags; release-binary evidence (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_362.md`, 38 tests). **Run 363:** per-peer message-rate runtime override wired into the live `AsyncPeerManagerImpl` `PeerRateLimiter` construction path at source/test level (21 tests). **Run 364 (strengthened):** release-binary evidence for **both** controls on real `target/release/qbind-node` + a release helper (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_364.md`, 7/7 scenarios). **Run 365–370:** deployed `P2pNodeBuilder` threading (365), deployed-builder-path release-binary evidence (366), connection-rate **live-socket** proof on P2P-capable `target/release/qbind-node` (367), admitted-peer per-peer socket flood on `AsyncPeerManagerImpl` (368), per-peer `PeerRateLimiter` wired onto the deployed `TcpKemTlsP2pService::read_loop` receive path via `DeployedInboundPerPeerLimiter` (369), and deployed per-peer drop metric wired end-to-end onto the deployed read loop with release-binary live-socket evidence (370, Route B). **Run 371 (Green):** a **second KEMTLS-admitted peer** completes real mutual auth over a real loopback socket against `target/release/qbind-node`, floods over-budget `P2pMessage::Consensus` frames through the deployed `read_loop`, and live `/metrics` exposes `qbind_net_per_peer_drops_total{reason="rate_limit"}` incrementing (~47 of 60) while under-budget stays absent; the Run 367/370 connection-rate live-socket proof is preserved and independent (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`, Route A / no production source change, helper 10/10). **Green scoped to these two abuse/DoS deployed live-socket controls;** defaults preserved; does not move M4/M6 or close C4/C5. **Run 372 (Green, hardening):** re-proves the Run 371 result under **strict mutual-auth admission** (`--p2p-mutual-auth required`) and **multi-peer concurrent flood** — two KEMTLS-admitted peers (honest under-budget + abusive over-budget) complete `MutualAuthMode::Required` handshakes against `target/release/qbind-node`, and live `/metrics` isolates the abusive peer's drops to its **own** per-peer bucket while the honest peer's bucket stays clean; the release helper also proves the strict-auth path with production-grade `PqcRootMode::PqcStaticRoot` material (ML-DSA-44 + ML-KEM-768) (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_372.md`, Route A / no production source change, helper 13/13). No new public CLI flags; strict mutual-auth only tightens admission; M4/M6 unchanged; C4/C5 remain OPEN. **Run 373 (Green, hardening):** extends Run 372's in-process PqcStaticRoot proof **cross-process** to the standalone binary — `devnet_pqc_root_helper` mints temporary ML-DSA-44 root + ML-KEM-768 leaf material (root signing key in memory only), and `target/release/qbind-node` runs under the pre-existing public flags `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root --p2p-trusted-root/--p2p-leaf-cert/--p2p-leaf-cert-key` (live `/metrics` `qbind_p2p_pqc_root_mode 1` / `qbind_p2p_pqc_roots_configured 1`); two KEMTLS-admitted peers built from the same operator material (honest under-budget + abusive over-budget) complete `MutualAuthMode::Required` + PqcStaticRoot handshakes and live `/metrics` isolates the abusive peer's drops to its own **cert-derived** per-peer bucket while the honest bucket stays clean (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_373.md`, Route A / no production source change, helper 13/13). No new public CLI flags; no trust-bundle weakening; M4/M6 unchanged; C4/C5 remain OPEN. |
| M13 telemetry / metrics | 🟢 | **Run 379:** operator observability package (`docs/release/public-devnet/observability/README.md`,`METRICS.md`,`SCRAPE_CONFIG.md`,`VERIFY.md`) documents safe `QBIND_METRICS_HTTP_ADDR` loopback exposure of the pre-existing `metrics_http` endpoint, with every metric family **verified by a live release-binary loopback scrape** (HTTP 200; required families present; honest gaps documented). Route B; no production source change; no launch/M4-Green claim. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`. |
| M14 monitoring / alerting | 🟢 | **Run 379:** alerting baseline (`ALERT_RULES.md`,`RUNBOOK.md`,`prometheus-scrape.example.yml`,`prometheus-alerts.example.yml`) — scrape config + `page`/`ticket`/`observe` alert rules that **parse as YAML** (harness-verified), enabled only for metrics present in the scrape; absent-metric alerts (`qbind_net_per_peer_drops_total`,`qbind_state_size_bytes`) kept in a **future/not-enabled** group; per-alert operator runbook. Route B; no production source change. `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_379.md`. |
| M15 reset policy | 🟡 | `--authority-state-reset` exists; network-wide reset policy not published. |
| M16 incident response | 🟢 | `QBIND_INCIDENT_RESPONSE.md` comprehensive; DevNet scoping is a small doc note. |
| M17 public documentation | 🟢 | **Run 358:** external how-to-run-a-node package published (`docs/release/public-devnet/operator/`), cross-linked from this readiness track and validated against real startup. |
| M18 user-facing disclaimers | 🟢 | **Run 358:** §3 safety label published in operator-facing material (`docs/release/public-devnet/operator/SAFETY.md` + every operator-doc header), not only in this internal matrix. |
| M19 network parameter publication | 🟢 | **Run 356:** `devnet-network-parameters.md` published as canonical operator artifact, checked against genesis + `QBIND_DEVNET_CHAIN_ID`. |
| M20 genesis hash publication | 🟢 | **Run 356:** canonical hash `0x48b3a862…af18145f` published + verifiable via `--print-genesis-hash` / `--expect-genesis-hash`. |
| S1 snapshot / backup / restore | 🟡 | Creation supported; restore path partial. |
| S2 data retention | 🟡 | Baseline exists; DevNet retention not formalized. |
| S3 upgrade procedure | 🟡 | Release track spec exists; no staged upgrade runbook. |
| S4 rollback procedure | 🟡 | Authority reset only; no staged rollback runbook. |
| S5 status page | 🔴 | None. |
| S6 alert rules / scrape config | 🔴 | None shipped. |
| S7 seed-node runbook | 🔴 | None (depends on M4). |
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
| M7 | 🟡 | Run: consolidate key-management guide (`--signer-mode`, keystore, remote signer, HSM). |
| M8 | 🟡 | Run: publish DevNet trust-root bootstrap procedure. |
| M9 | 🟡 | Run: publish DevNet PQC root/signing-key guidance (fold into M8 run if convenient). |
| M10 | 🟢 | **Done (Run 360):** public P2P port/NAT/`--enable-p2p` posture published (`docs/release/public-devnet/p2p/P2P_PORT_POSTURE.md`). |
| M11 | 🟢 | **Done (Run 360):** open-network peer-admission policy published (`docs/release/public-devnet/p2p/PEER_ADMISSION_POLICY.md`). |
| M12 | 🟢 | **Green (Run 371):** both abuse/DoS deployed live-socket controls proven on real `target/release/qbind-node`. Run 362 wired the bounded inbound connection-rate limiter into the live `p2p_tcp` accept loop (default-off, `qbind_p2p_connection_rate_drop_total` metric, hidden/devnet-only CLI flags, release-binary evidence). Run 363 wired the **per-peer message-rate runtime override** into the live `AsyncPeerManagerImpl` `PeerRateLimiter` construction path. Run 364 produced release-binary evidence for both controls (7/7). Run 365 threaded the CLI-derived `peer_rate_limiter_config` through the deployed `P2pNodeBuilder`; Run 366 landed deployed-builder-path release-binary evidence (8/8, LocalMesh blocked live sockets); **Run 367** proved the **connection-rate** control **live-socket** (10 inbound TCP connections, max 3 → 3 accepted / 7 refused, live `qbind_p2p_connection_rate_drop_total = 7`); Run 368 drove an admitted-peer per-peer flood on `AsyncPeerManagerImpl`; Run 369 wired the per-peer `PeerRateLimiter` onto the deployed `TcpKemTlsP2pService::read_loop`; Run 370 wired the deployed per-peer drop metric end-to-end with release-binary live-socket evidence (Route B). **Run 371** stands up a **second KEMTLS-admitted peer** that completes real mutual auth over a real loopback socket against `target/release/qbind-node`, floods over-budget `P2pMessage::Consensus` frames through the deployed `read_loop`, and observes live `/metrics` expose `qbind_net_per_peer_drops_total{reason="rate_limit"}` incrementing (~47 of 60) while under-budget stays absent — with the connection-rate live-socket proof preserved and independent (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_371.md`, Route A / no production source change, helper 10/10). **Green scoped to these two abuse/DoS deployed live-socket controls; defaults preserved; does not move M4/M6 or close C4/C5.** |
| M13 | 🟢 | **Done (Run 379):** operator metrics exposure guide published (`docs/release/public-devnet/observability/`), verified by a live release-binary loopback scrape. |
| M14 | 🟢 | **Done (Run 379):** alert-rule definitions + scrape config + runbook shipped (`docs/release/public-devnet/observability/`, `prometheus-*.example.yml`), YAML-parsed; absent-metric alerts marked future/not-enabled. |
| M15 | 🟡 | Run: publish DevNet reset policy (trigger conditions, notice, audit trail). |
| M17 | 🟢 | **Done (Run 358):** external how-to-run-a-node package published (`docs/release/public-devnet/operator/`). |
| M18 | 🟢 | **Done (Run 358):** §3 safety label published in operator-facing material (`docs/release/public-devnet/operator/SAFETY.md`). |
| M19 | 🟢 | **Done (Run 356):** canonical network-parameter artifact published (`devnet-network-parameters.md`). |
| M20 | 🟢 | **Done (Run 356):** canonical genesis hash published + operator-verifiable (`VERIFY.md`). |

Note: several Yellow items can be closed by a small number of consolidated documentation/publication runs
(genesis+params+hash landed in Run 356; remaining: onboarding+identity+key-management+quickstart together;
trust-root bootstrap+PQC guidance together; monitoring+alerting together; port posture+admission+abuse together).

---

## 12. Public DevNet launch blocker summary

Public DevNet is **NOT yet launch-ready**. As of **Run 360**, the Green must-haves are **M1, M2, M3, M5, M10, M11,
M16, M17, M18, M19, M20**; every other must-have remains **Yellow or Red**. The launch blockers are, at minimum:

- **Red:** *(none among the tracked must-haves — M3 moved to Green in Run 359).*
- **Yellow (must reach Green):** M4 (seed/bootnodes — format+placeholder landed Run 357, still a launch blocker
  until live seeds + reachability evidence land), M6 (identity — guidance landed Run 358, generation command still
  missing), M7, M8, M9, M12 (abuse/DoS — posture landed Run 360; Run 361 added a source/test-only config model +
  connection-rate limiter boundary; Run 362 wired the connection-rate limiter into runtime with release-binary
  evidence; Run 363 wired the per-peer message-rate runtime override at source/test level; Run 364 landed
  release-binary evidence for both controls but M12 stays Yellow because the deployed node does not yet
  thread the per-peer override into its live `AsyncPeerManagerImpl` — Green deferred pending per-peer
  end-to-end production threading), M13, M14, M15.

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
| seed nodes / bootnodes | DevNet | network | 🔴 | CLI `--p2p-peer` | No published seeds/discovery | Outsiders cannot join | Publish seed-list format + list |
| validator onboarding | DevNet | docs | 🟡 | `QBIND_DEVNET_OPERATIONAL_GUIDE.md` | No external quickstart | Onboarding failures/misconfig | Author external quickstart |
| validator identity | DevNet | security | 🟡 | `cli.rs`, `peer_key_provider.rs` | No identity guide | Identity collisions/misconfig | Identity guide run |
| validator key-management guidance | DevNet | security | 🟡 | `--signer-mode`, `qbind-remote-signer` | No consolidated guide | Key mishandling | Key-management guide run |
| trust-bundle bootstrap | DevNet | security | 🟡 | `pqc_trust_bundle.rs`, PQC runbook | DevNet root bootstrap unpublished | Trust misconfiguration | Trust-root bootstrap run |
| PQC root / signing-key guidance | DevNet | security | 🟡 | CLI trust-root flags, PQC runbook | DevNet guidance not consolidated | Weak/incorrect roots | Fold into bootstrap run |
| faucet | TestNet | ops | ⚪ | n/a (DevNet non-goal) | Deferred | n/a for DevNet | TestNet |
| RPC gateway | TestNet | network | ⚪ | n/a (DevNet non-goal) | Deferred | n/a for DevNet | TestNet |
| RPC rate limiting | TestNet | security | ⚪ | n/a | Deferred | n/a for DevNet | TestNet |
| public P2P port posture | DevNet | network | 🟡 | `cli.rs` (`--p2p-listen-addr`, `--enable-p2p`) | Public exposure posture unpublished | Unintended exposure/NAT issues | Port-posture doc run |
| peer admission policy | DevNet | security | 🟡 | mutual-auth, trust-bundle gating | Open-network policy unpublished | Eclipse/spam admission | Admission-policy doc run |
| telemetry / metrics | DevNet | observability | 🟡 | `metrics_http.rs` | Operator exposure doc partial | Blind operations | Metrics exposure guide |
| monitoring / alerting | DevNet | observability | 🟡 | `QBIND_MONITORING_AND_ALERTING_BASELINE.md` | Alert rules absent | Missed incidents | Ship alert rules |
| status page | DevNet | observability | 🔴 | none | Missing | No shared health view | Should-have run |
| explorer | TestNet | observability | ⚪ | n/a | Deferred | n/a for DevNet | TestNet |
| reset policy | DevNet | ops | 🟡 | `--authority-state-reset`, `authority_state_reset.rs` | Network reset policy unpublished | Surprise wipes / disputes | Reset-policy doc run |
| incident response | DevNet | ops | 🟢 | `QBIND_INCIDENT_RESPONSE.md` | — (scope note only) | — | — |
| abuse handling | DevNet | security | 🟡 | `peer_rate_limiter.rs` | Public thresholds unpublished | DoS/flooding | Abuse-posture doc run |
| snapshot / backup / restore | DevNet | ops | 🟡 | `state_snapshot.rs`, backup baseline | Restore path partial | Data loss on reset | Should-have run |
| data retention | DevNet | ops | 🟡 | backup baseline | DevNet retention not formalized | Unclear retention | Should-have run |
| upgrade procedure | DevNet | ops | 🟡 | `QBIND_RELEASE_TRACK_SPEC.md` | No staged upgrade runbook | Botched upgrades | Should-have run |
| rollback procedure | DevNet | ops | 🟡 | authority reset only | No staged rollback runbook | Unrecoverable bad upgrade | Should-have run |
| public documentation | DevNet | docs | 🟡 | `README.md`, operational guide | No external how-to-run | Operators cannot self-serve | Public docs run |
| user-facing disclaimers | DevNet | docs | 🟡 | this doc §3 | Not in release material | Misperceived value/stability | Publish label |
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
Public DevNet is still **not launch-ready**: M4 and the remaining must-haves (M6–M9, M12–M15) remain
Yellow or Red — notably **Yellow-but-blocking** for seed/bootnodes (M4) until real live seeds + reachability evidence
land.
C4 and C5 remain **OPEN**, MainNet authority rotation/revocation remains **Red**, and the Run 353/354 boundary
remains Green-for-scope only. The most efficient path forward is a small series of consolidated
documentation/publication runs (onboarding+identity+key-management+quickstart+disclaimers; trust-root bootstrap+PQC
guidance; monitoring+alerting; port-posture+admission+abuse; reset policy;
seed/bootnode list).