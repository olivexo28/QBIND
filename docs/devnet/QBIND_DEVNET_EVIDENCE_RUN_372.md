# QBIND DevNet Evidence — Run 372

Release-binary **live-socket** hardening evidence that the Run 371 M12 Green
result still holds under **stricter admission** (`MutualAuthMode::Required`) and
**multi-peer concurrent flood** conditions. Run 372 stands up a deployed
`target/release/qbind-node` running with `--p2p-mutual-auth required` and a low
per-peer budget, then drives **two simultaneous KEMTLS-admitted peers** — an
honest peer (under budget) and an abusive peer (over budget) — that each complete
the full `MutualAuthMode::Required` handshake before flooding structured frames
through the deployed `TcpKemTlsP2pService::read_loop`. On **live `/metrics`** the
abusive peer's drops are isolated to its own per-peer bucket
(`qbind_net_per_peer_drops_total{peer="…",reason="rate_limit"}`) while the honest
peer's bucket stays clean. The release helper additionally proves the strict
admission path with **production-grade `PqcRootMode::PqcStaticRoot`** material
(runtime-generated ML-DSA-44 + ML-KEM-768). The Run 367/370 connection-rate
live-socket proof is preserved in the same harness.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route A**
> (no production source change — production public APIs only; no new CLI flag; no
> live deployment; no P2P wire-format change; no KEMTLS / trust-bundle /
> peer-admission weakening — strict mutual-auth only TIGHTENS admission).

## 1. Exact verdict

**PASS / public-DevNet M12 strict-auth multi-peer hardening POSITIVE — M12
remains Green for scope.**

- **Strict mutual-auth admission** is proven **live-socket**: the deployed node
  runs under `MutualAuthMode::Required` (pre-existing public flag
  `--p2p-mutual-auth required`) and both flooding peers complete the full
  Required KEMTLS handshake; the listener registers each peer under its
  **verified cert-derived NodeId**.
- **Multi-peer bucket isolation** is proven **live-socket**: an abusive
  over-budget flood surfaces `qbind_net_per_peer_drops_total{peer="<abusive
  key>",reason="rate_limit"}` = 47 (representative) while the honest peer's
  bucket label is **ABSENT** (0 drops). The abusive peer does **not** consume the
  honest peer's budget.
- **Production-grade / PQC-static-root material** is proven (helper): a two-node
  `PqcRootMode::PqcStaticRoot` Required mutual-auth handshake completes with real
  runtime-generated ML-DSA-44 root + ML-KEM-768 leaf material (never written to
  disk); each side observes the other's cert-derived NodeId.
- **Connection-rate control preserved live-socket**: 10 inbound TCP connections
  against a max of 3 → 3 accepted / 7 refused, `qbind_p2p_connection_rate_drop_total = 7`.
- **Controls independent**: the strict-auth multi-peer flood leaves
  `qbind_p2p_connection_rate_drop_total = 0`; the connection-rate flood leaves
  `qbind_net_per_peer_drops_total` ABSENT.
- Defaults preserved; invalid / unbounded / MainNet configs fail the binary
  closed at startup; hidden abuse/DoS flags remain hidden; the over-budget flood
  does **not** tear the connection down.

**M12 remains Green** for the abuse/DoS deployed live-socket controls; this run
adds strict-auth + multi-peer hardening evidence **without broadening scope**.
M4 remains Yellow/launch-blocking; public DevNet remains **NOT launch-ready**;
full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_372_public_devnet_m12_strict_auth_multi_peer_flood_helper.rs`
  — release helper with three modes: an in-process strict-auth multi-peer flood
  scenario suite (default), a `dial-flood` cross-process Required-mutual-auth
  dialer, and a `bucket-key <vid>` helper that prints the deterministic per-peer
  metric label.
- `scripts/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary.sh`
  — release harness (build, hashes, helper scenarios, CLI surface, fail-closed,
  live-socket connection-rate regression, strict-auth multi-peer per-peer flood
  with per-bucket isolation on live `/metrics`, independence, no-teardown).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_372.md` — this file.
- `docs/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary/`
  — archive (`README.md`, `summary.txt`, `.gitignore`; only these three tracked).

Modified (production Rust source): **none — Route A.**

Modified (docs, narrow):

- `docs/release/QBIND_PUBLIC_DEVNET_READINESS_CRITERIA.md`
- `docs/release/public-devnet/p2p/ABUSE_DOS_POSTURE.md`
- `docs/release/public-devnet/p2p/VERIFY.md`
- `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
- `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
- `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
- `docs/whitepaper/contradiction.md`

## 3. Release artifacts and hashes

Representative run (SHA-256 and Build IDs are host/build-specific and change per
rebuild; the harness re-captures them each run):

```
toolchain: rustc 1.97.1 (8bab26f4f 2026-07-14) / cargo 1.97.1 (c980f4866 2026-06-30)

target/release/qbind-node
  sha256:   e28775a2c44d02466b3c86dfff5e5641d93d983bde89e6d0f4701cc257131669
  build_id: 05e9e0b9b78599fe1c4d5f6bd1fd8786f3a4b9ec

target/release/examples/run_372_public_devnet_m12_strict_auth_multi_peer_flood_helper
  sha256:   f45dd1c2024760d10c157441d296029c33b37b5b963c861cce8599d37b692b8d
  build_id: e9c140626c94c386c7e5a8ebc323e59e3319a806
```

## 4. Decision gate route

**Route A** — no production source change. The helper and harness use only
production public APIs (`P2pNodeBuilder::with_mutual_auth_mode`,
`with_pqc_root_config`, `with_node_metrics`, `with_abuse_dos_runtime_config`,
`pqc_devnet_helper`), the pre-existing public `--p2p-mutual-auth` flag, and the
pre-existing hidden abuse/DoS flags. No new CLI flag, no wire-format change.

## 5. Strict mutual-auth evidence

- Helper scenario `02_strict_mutual_auth_admission`: the honest peer completes a
  `MutualAuthMode::Required` KEMTLS handshake against node A and node A observes
  its **cert-derived** NodeId (`derive_test_node_id_from_validator_id(1)`) in
  `connected_peers()` — not a self-asserted `client_random`.
- Live socket: the deployed node logs `mutual_auth=Required` and both dial-flood
  peers report `connected: true` + `target_node_id_seen: true`
  (`multi_peer_kemtls_admitted`).

## 6. PQC / static-root material evidence

- Helper scenario `03_pqc_static_root_or_production_grade_material_path`: a
  two-node cluster built with `PqcRootMode::PqcStaticRoot` + `MutualAuthMode::Required`,
  using runtime-generated ML-DSA-44 root and ML-KEM-768 leaf certificates
  (`mint_devnet_root` + `issue_leaf_delegation_cert`), completes the mutual-auth
  handshake; each side observes the other's cert-derived NodeId
  (`dialer_saw_listener=true listener_saw_dialer=true`). Material is ephemeral,
  in-memory, and never written to disk or committed.

## 7. Multi-peer flood evidence

- Live socket: two dial-flood peers run **concurrently** against the same
  deployed node — honest (vid 1, 4 frames @ 400 ms, under the 5 msg/s budget) and
  abusive (vid 2, 60 frames @ 8 ms, over budget). Both complete Required
  mutual-auth. The abusive peer's over-budget frames are dropped by the deployed
  per-peer limiter and surface on live `/metrics`.

## 8. Per-peer bucket isolation

- Live `/metrics` (representative):
  `qbind_net_per_peer_drops_total{peer="16923200116091377281",reason="rate_limit"} 47`
  (abusive bucket) and **no line** for `peer="10525299210378515360"` (honest
  bucket). The bucket labels are computed deterministically by the release helper
  (`bucket-key <vid>`) from the strict-auth cert-derived NodeId.
- Helper scenarios `06_multi_peer_bucket_isolation` (abusive bucket drops > 0,
  honest bucket = 0, distinct labels) and
  `07_abusive_peer_does_not_consume_honest_peer_budget` (honest peer still under
  budget after the abusive flood; its bucket stays at 0).

## 9. Connection-rate regression

- Live socket preserved: 10 inbound TCP connections, max 3 → 3 accepted / 7
  refused, `qbind_p2p_connection_rate_drop_total = 7`; under-budget (3) admitted
  with the metric still 0. Helper scenario `08_connection_rate_regression`
  confirms the connection-rate config validates and installs independently, with
  per-peer defaults untouched.

## 10. Combined limiter independence

- Live socket: the strict-auth multi-peer per-peer flood leaves
  `qbind_p2p_connection_rate_drop_total = 0`; the connection-rate flood leaves
  `qbind_net_per_peer_drops_total` ABSENT. Helper scenario
  `09_combined_limiter_independence` confirms the per-peer flood never touches the
  connection-rate counter.

## 11. CLI / config surface

- No new public CLI flags. The abuse/DoS flags remain **hidden** from `--help`;
  the strict-auth flag `--p2p-mutual-auth` is a **pre-existing public** flag (not
  introduced by this run). Invented flags are rejected; real hidden flags parse.
  Helper scenario `12_hidden_cli_surface_checked`.

## 12. Default compatibility

- No abuse/DoS flags → connection limiter DISABLED,
  `qbind_p2p_connection_rate_drop_total = 0`, per-peer defaults 1000 msg/s + 100
  burst, adapter metrics None. Helper scenario `01_default_preserves_behavior`
  and live-socket `default_preserves_behavior`.

## 13. Rejection / fail-closed evidence

- Real binary exits non-zero for: zero per-peer max, unbounded per-peer max, zero
  connection-rate max, and an enabled MainNet abuse/DoS config. Helper scenarios
  `10_invalid_configs_fail_closed` and `11_mainnet_refused`.

## 14. Non-mutation evidence

- The abuse/DoS runtime config is observability-only; strict mutual-auth only
  tightens admission. No `LivePqcTrustState`, validator-set, epoch, sequence, or
  marker write occurs. Helper scenario `13_non_mutation_guards`. Loopback-only,
  temp dirs, ephemeral in-memory PQC material.

## 15. Readiness matrix delta

- **M12 remains Green** (strict-auth + multi-peer hardening evidence passes;
  scope unchanged — abuse/DoS deployed live-socket controls only).
- **M4** Yellow/launch-blocking — UNCHANGED (no live seed/bootnode reachability).
- **M6** Yellow/Partial — UNCHANGED (no stable identity generation).
- **M7–M9, M13–M15** — UNCHANGED.

## 16. Current public DevNet readiness status

**NOT launch-ready.** M12 Green (scoped) does not by itself make the public
DevNet launch-ready; other must-haves remain outstanding.

## 17. Remaining public DevNet blockers

- **M4** (live seed/bootnode reachability) — Yellow/launch-blocking.
- **M6** (stable identity generation) — Yellow/Partial.
- No faucet, RPC gateway, explorer, or status page (out of scope, not launched).

## 18. Public TestNet blockers

- No TestNet readiness claim. TestNet requires the full C4/C5 closure track plus
  authority-lifecycle runtime wiring, none of which this run addresses.

## 19. MainNet blockers

- MainNet authority rotation/revocation remains **Red**. An enabled MainNet
  abuse/DoS config is refused at startup. No MainNet readiness claim.

## 20. C4 / C5 status

- **C4 remains OPEN**; **C5 remains OPEN.** This run makes no closure claim. It
  does add hardening evidence that the B12 strict mutual-auth path
  (`MutualAuthMode::Required`) and the production-honest `PqcRootMode::PqcStaticRoot`
  path both function over the deployed abuse/DoS harness, but does not close any
  C4/C5 residual.

## 21. Tests run

- `cargo build -p qbind-node --release`
- `cargo build -p qbind-node --release --example run_372_public_devnet_m12_strict_auth_multi_peer_flood_helper`
- `scripts/devnet/run_372_public_devnet_m12_strict_auth_multi_peer_flood_release_binary.sh` → verdict PASS
- `cargo test -p qbind-node --test run_370_public_devnet_deployed_live_socket_m12_tests`
- `cargo test -p qbind-node --test run_369_public_devnet_deployed_per_peer_limiter_wiring_tests`
- `cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests`
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests`
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests`
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests`
- `cargo test -p qbind-node --lib`

(See the run log for exact results; the harness and helper both report PASS.)

## 22. Security scans

- Secret scanning run over all changed files: **no secrets**. Generated
  PQC/KEMTLS material is temporary, dev-only, in-memory, and gitignored. No
  private keys, mnemonics, credentials, tokens, private infrastructure, real
  production hostnames, or live endpoints are committed.

## 23. CodeQL

- CodeQL invoked over the Rust example changes (the only code change; docs and
  scripts are non-Rust). Result recorded honestly in the PR/run log — not
  asserted clean unless the run reports clean.

## 24. Provenance

- Route A, production public APIs only. Toolchain, SHA-256, and Build IDs are
  captured by the harness at run time (see §3). All sockets are loopback on
  OS-assigned ports; all data dirs and PQC material are temporary.

## 25. Honest limitations

- The **helper** in-process scenarios run all peers inside the release helper
  process (real KEMTLS sockets + real read loop + real deployed limiter, but node
  A is not the standalone binary) — "helper-only" evidence by the readiness
  rules. The **harness** provides the cross-process live-socket evidence against
  `target/release/qbind-node` for strict-auth admission and multi-peer bucket
  isolation.
- The multi-peer bucket key is derived from the first 8 bytes of the peer NodeId
  (documented coarse abuse/DoS keying, not an identity claim); under strict
  mutual-auth the NodeId is the verified cert-derived value, so the label is
  deterministic and matches live `/metrics`.
- Exact per-peer drop counts vary slightly with scheduling; the invariant is
  under-budget ⇒ 0 drops (bucket absent) and over-budget ⇒ drops > 0 attributed
  to the abusive bucket only, honest bucket clean.
- PQC-static-root evidence is proven in-process in the helper; it is not driven
  cross-process against the standalone binary in this run (recorded as hardening
  outstanding for a future cross-process PQC-static-root live-socket run).

## 26. Suggested Run 373 next step

Drive the **cross-process** live-socket strict-auth flood with
**production-grade `PqcRootMode::PqcStaticRoot`** material end-to-end against
`target/release/qbind-node` (operator-configured `--p2p-trusted-root` /
`--p2p-leaf-cert` inputs), extending Run 372's in-process PQC-static-root proof
to the standalone binary — while keeping M4/M6 untouched and public DevNet NOT
launch-ready.
