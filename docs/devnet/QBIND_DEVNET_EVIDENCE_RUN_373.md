# QBIND DevNet Evidence — Run 373

Release-binary **cross-process** live-socket hardening evidence that the Run
371/372 M12 Green result still holds when the standalone
`target/release/qbind-node` is run under strict admission
(`MutualAuthMode::Required`) with **operator-configured `PqcRootMode::PqcStaticRoot`
material loaded from files** (`--p2p-trusted-root` / `--p2p-leaf-cert` /
`--p2p-leaf-cert-key`). This extends Run 372's **in-process** PqcStaticRoot proof
to a standalone-binary, cross-process loopback proof.

The harness mints **temporary** ML-DSA-44 root + ML-KEM-768 leaf material with the
pre-existing `devnet_pqc_root_helper` example (root signing key in memory only,
never on disk), stands up a deployed `target/release/qbind-node` under
`--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root
--p2p-trusted-root … --p2p-leaf-cert … --p2p-leaf-cert-key …` with a low per-peer
budget, then drives **two simultaneous KEMTLS-admitted peers** built from the same
operator material — an honest peer (under budget) and an abusive peer (over
budget). On **live `/metrics`** the abusive peer's drops are isolated to its own
**cert-derived** per-peer bucket
(`qbind_net_per_peer_drops_total{peer="…",reason="rate_limit"}`) while the honest
peer's bucket stays clean, and `qbind_p2p_pqc_root_mode 1` /
`qbind_p2p_pqc_roots_configured 1` confirm the static-root path is active. The Run
367/370 connection-rate live-socket proof is preserved in the same harness.

> **Safety label:** experimental · resettable · no value · no MainNet readiness
> claim · no C4/C5 closure claim · NOT public-DevNet launch-ready · **Route A**
> (no production source change — production public APIs + pre-existing public CLI
> only; no new CLI flag; no live deployment; no P2P wire-format change; no KEMTLS /
> trust-bundle / peer-admission weakening — strict mutual-auth only TIGHTENS
> admission).

## 1. Exact verdict

**PASS / public-DevNet M12 cross-process PqcStaticRoot strict-auth hardening
POSITIVE — M12 remains Green for scope.**

- **Cross-process static-root strict-auth admission** is proven **live-socket**:
  the standalone `target/release/qbind-node` runs under `MutualAuthMode::Required`
  + `PqcRootMode::PqcStaticRoot` (pre-existing public flags `--p2p-mutual-auth
  required` / `--p2p-pqc-root-mode pqc-static-root` with operator-supplied
  `--p2p-trusted-root` / `--p2p-leaf-cert` / `--p2p-leaf-cert-key`); live
  `/metrics` exports `qbind_p2p_pqc_root_mode 1` and
  `qbind_p2p_pqc_roots_configured 1`. Both flooding peers, built from the same
  operator material, complete the full Required + PqcStaticRoot KEMTLS handshake.
- **Cert-derived identity** is proven **live-socket**: under PqcStaticRoot the
  NodeId is derived from the certified leaf ML-KEM-768 public key; the deployed
  listener registers each peer under its **verified cert-derived NodeId** and each
  peer observes the deployed node's cert-derived NodeId in return.
- **Multi-peer bucket isolation** is proven **live-socket**: an abusive
  over-budget flood surfaces
  `qbind_net_per_peer_drops_total{peer="7076916635622004226",reason="rate_limit"}`
  = 47 (representative) while the honest peer's cert-derived bucket label
  (`1683391479773513313`, representative) is **ABSENT** (0 drops). The abusive
  peer does **not** consume the honest peer's budget.
- **Connection-rate control preserved live-socket**: 10 inbound TCP connections
  against a max of 3 → 3 accepted / 7 refused,
  `qbind_p2p_connection_rate_drop_total = 7`.
- **Controls independent**: the static-root multi-peer flood leaves
  `qbind_p2p_connection_rate_drop_total = 0`; the connection-rate flood leaves
  `qbind_net_per_peer_drops_total` ABSENT.
- Defaults preserved; invalid / unbounded / malformed-root / MainNet configs fail
  the binary closed at startup; hidden abuse/DoS flags remain hidden; the
  over-budget flood does **not** tear the connection down.

**M12 remains Green** for the abuse/DoS deployed live-socket controls; this run
adds cross-process PqcStaticRoot strict-auth hardening evidence **without
broadening scope**. M4 remains Yellow/launch-blocking; M6 remains Yellow/Partial;
public DevNet remains **NOT launch-ready**; full **C4 / C5 remain OPEN**.

## 2. Files changed

New:

- `crates/qbind-node/examples/run_373_public_devnet_m12_pqc_static_root_cross_process_helper.rs`
  — release helper with three modes: an in-process cross-process-shaped
  static-root strict-auth scenario suite (`run-scenarios`, default), a
  `dial-flood-static-root` cross-process Required + PqcStaticRoot dialer that loads
  operator material from files, and a `bucket-key-cert <cert_file>` helper that
  prints the cert-derived per-peer metric label.
- `scripts/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary.sh`
  — release harness (build, hashes, helper scenarios, CLI surface, fail-closed,
  temporary static-root material generation, live-socket connection-rate
  regression, cross-process static-root strict-auth multi-peer per-peer flood with
  per-bucket isolation on live `/metrics`, independence, no-teardown).
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_373.md` — this file.
- `docs/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary/`
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

target/release/examples/run_373_public_devnet_m12_pqc_static_root_cross_process_helper
  sha256:   dca1fbdfaab57d4c67a806e14145851a5845fcba7edc69ba62beccaadd653488
  build_id: b99ac10f4a26d54f02e30d1bfff2e31cb1fb94c4

target/release/examples/devnet_pqc_root_helper
  sha256:   0351fb6dd73668c0d1ee3dc03c22b89bebd0bb8ad07353eaf4f5a1ddae6a0461
```

## 4. Decision gate route

**Route A** — no production source change. The helper and harness use only
production public APIs (`P2pNodeBuilder::with_mutual_auth_mode`,
`with_pqc_root_config`, `with_node_metrics`, `with_abuse_dos_runtime_config`,
`with_num_validators`; the public static-root loaders
`parse_pqc_trusted_root_specs`, `PqcLeafCredentialPaths::load`,
`parse_pqc_peer_leaf_cert_spec`, `PqcStaticRootConfig`), the pre-existing public
CLI flags `--p2p-mutual-auth` / `--p2p-pqc-root-mode` / `--p2p-trusted-root` /
`--p2p-leaf-cert` / `--p2p-leaf-cert-key`, and the pre-existing hidden abuse/DoS
flags. The pre-existing `devnet_pqc_root_helper` example mints the operator
material. No new CLI flag, no wire-format change.

## 5. Static-root material generation

- The harness runs `devnet_pqc_root_helper <tempdir> 3` to mint a shared ML-DSA-44
  root and per-validator ML-KEM-768 leaf certificates + KEM secret keys into a
  **temporary** directory. Representative:
  `root_id=704db1a00e6d894b983c6b94d58b39ded9e36bd0a8ee2198b3bacd643d4a3cc4`,
  `suite=100` (ML-DSA-44 / ML-KEM-768), `validators=3`.
- `trusted-root.spec` (`ROOT_ID_HEX:100:ROOT_PK_HEX`) is loaded into node A via
  `--p2p-trusted-root`; each node loads its own `vN.cert.bin` + `vN.kem.sk.bin` via
  `--p2p-leaf-cert` / `--p2p-leaf-cert-key`; peers are pinned with
  `--p2p-peer-leaf-cert VID:PATH`.
- The **root signing key is held in memory only and never written to disk.** All
  material lives in a temporary directory that is **removed on exit** and is
  **gitignored**. Scenario `temporary_pqc_static_root_material_generated` records
  this.

## 6. Cross-process strict-auth admission evidence

- Live socket: the deployed `target/release/qbind-node` runs under
  `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` and exports
  `qbind_p2p_pqc_root_mode 1` + `qbind_p2p_pqc_roots_configured 1` on live
  `/metrics` (`cross_process_static_root_admission_live`).
- Both `dial-flood-static-root` peers, built from the same operator material,
  report `connected: true` + `target_node_id_seen: true`
  (`multi_peer_static_root_kemtls_admitted`): **TWO peers complete the full
  Required + PqcStaticRoot KEMTLS handshake against the standalone binary.**

## 7. Cert-derived identity evidence

- Under PqcStaticRoot the NodeId is
  `NodeId::new(derive_node_id_from_pubkey(&cert.leaf_kem_pk))`. The deployed
  listener registers each peer under exactly that **verified cert-derived NodeId**
  (resolved from the certified leaf ML-KEM-768 pk, not a self-asserted
  `client_random`), and each peer observes the deployed node's cert-derived NodeId
  in return (`cert_derived_node_id_observed_live`).
- The per-peer bucket labels are computed by the release helper
  (`bucket-key-cert <cert_file>`) directly from the shared leaf cert, so they match
  live `/metrics`. Representative: honest vid 1 → `1683391479773513313`; abusive
  vid 2 → `7076916635622004226`.

## 8. Per-peer static-root flood evidence

- Live socket: two `dial-flood-static-root` peers run **concurrently** against the
  same deployed node — honest (vid 1, under the 5 msg/s budget) and abusive (vid 2,
  60 frames over budget). Both complete Required + PqcStaticRoot mutual-auth. The
  abusive peer's over-budget frames are dropped by the deployed per-peer limiter
  and surface on live `/metrics`
  (`over_budget_static_root_peer_live`); the honest peer's under-budget frames
  produce **no** drops (`under_budget_static_root_peer_live`, its label ABSENT).

## 9. Multi-peer bucket isolation

- Live `/metrics` (representative):
  `qbind_net_per_peer_drops_total{peer="7076916635622004226",reason="rate_limit"} 47`
  (abusive bucket) and **no line** for `peer="1683391479773513313"` (honest
  bucket) — `multi_peer_bucket_isolation_live`. The abusive peer does **not**
  consume the honest peer's budget
  (`abusive_peer_does_not_consume_honest_peer_budget_live`).
- Helper scenarios `07_multi_peer_bucket_isolation` (abusive bucket drops > 0,
  honest bucket = 0, distinct cert-derived labels) and
  `08_abusive_peer_does_not_consume_honest_peer_budget`.

## 10. Connection-rate regression

- Live socket preserved: 10 inbound TCP connections, max 3 → 3 accepted / 7
  refused, `qbind_p2p_connection_rate_drop_total = 7`; under-budget (3) admitted
  with the metric still 0. Helper scenario `09_connection_rate_regression` confirms
  the connection-rate config validates and installs independently, with per-peer
  defaults untouched.

## 11. Combined limiter independence

- Live socket: the static-root multi-peer per-peer flood leaves
  `qbind_p2p_connection_rate_drop_total = 0`
  (`combined_limiter_independence_per_peer_side`); the connection-rate flood leaves
  `qbind_net_per_peer_drops_total` ABSENT
  (`combined_limiter_independence_conn_side`). Helper scenario
  `10_combined_limiter_independence` confirms the per-peer flood never touches the
  connection-rate counter.

## 12. CLI / config surface

- No new public CLI flags. The abuse/DoS flags remain **hidden** from `--help`;
  the strict-auth flag `--p2p-mutual-auth` and the static-root flags
  `--p2p-pqc-root-mode` / `--p2p-trusted-root` / `--p2p-leaf-cert` /
  `--p2p-leaf-cert-key` are all **pre-existing public** flags (not introduced by
  this run). Invented flags are rejected (rc=2); real hidden flags parse (rc=0).
  Helper scenario `13_hidden_cli_surface_and_non_mutation_guards`.

## 13. Default compatibility

- No abuse/DoS flags → connection limiter DISABLED,
  `qbind_p2p_connection_rate_drop_total = 0`, per-peer defaults 1000 msg/s + 100
  burst, adapter metrics None. Helper scenario `01_default_preserves_behavior` and
  live-socket `default_preserves_behavior`.

## 14. Rejection / fail-closed evidence

- Real binary exits non-zero for: zero per-peer max, unbounded per-peer max, zero
  connection-rate max, **malformed `--p2p-trusted-root`**, and an enabled MainNet
  abuse/DoS config. Helper scenarios `11_invalid_configs_fail_closed` and
  `12_mainnet_refused`.

## 15. Non-mutation evidence

- The abuse/DoS runtime config is observability-only; strict mutual-auth +
  static-root only tighten admission. No `LivePqcTrustState`, validator-set, epoch,
  sequence, or marker write occurs; no trust-bundle or peer-admission weakening; no
  Run 070 path. Helper scenario `13_hidden_cli_surface_and_non_mutation_guards`.
  Loopback-only, temp dirs, temporary file-loaded PQC material removed on exit.

## 16. Readiness matrix delta

- **M12 remains Green** (cross-process PqcStaticRoot strict-auth hardening
  evidence passes; scope unchanged — abuse/DoS deployed live-socket controls only).
- **M4** Yellow/launch-blocking — UNCHANGED (no live seed/bootnode reachability).
- **M6** Yellow/Partial — UNCHANGED (no stable identity generation).
- **M7–M9, M13–M15** — UNCHANGED.

## 17. Current public DevNet readiness status

**NOT launch-ready.** M12 Green (scoped) does not by itself make the public DevNet
launch-ready; other must-haves remain outstanding.

## 18. Remaining public DevNet blockers

- **M4** (live seed/bootnode reachability) — Yellow/launch-blocking.
- **M6** (stable identity generation) — Yellow/Partial.
- No faucet, RPC gateway, explorer, or status page (out of scope, not launched).

## 19. Public TestNet blockers

- No TestNet readiness claim. TestNet requires the full C4/C5 closure track plus
  authority-lifecycle runtime wiring, none of which this run addresses.

## 20. MainNet blockers

- MainNet authority rotation/revocation remains **Red**. An enabled MainNet
  abuse/DoS config is refused at startup. No MainNet readiness claim.

## 21. C4 / C5 status

- **C4 remains OPEN**; **C5 remains OPEN.** This run makes no closure claim. It
  adds hardening evidence that the strict mutual-auth path
  (`MutualAuthMode::Required`) and the operator-configured, file-loaded
  `PqcRootMode::PqcStaticRoot` path both function cross-process against the
  standalone binary over the deployed abuse/DoS harness, but does not close any
  C4/C5 residual.

## 22. Tests run

- `cargo build -p qbind-node --release`
- `cargo build -p qbind-node --release --example run_373_public_devnet_m12_pqc_static_root_cross_process_helper`
- `scripts/devnet/run_373_public_devnet_m12_pqc_static_root_cross_process_release_binary.sh` → verdict PASS
- `cargo test -p qbind-node --test run_370_public_devnet_deployed_live_socket_m12_tests`
- `cargo test -p qbind-node --test run_369_public_devnet_deployed_per_peer_limiter_wiring_tests`
- `cargo test -p qbind-node --test run_365_public_devnet_deployed_peer_rate_threading_tests`
- `cargo test -p qbind-node --test run_363_public_devnet_per_peer_message_rate_runtime_tests`
- `cargo test -p qbind-node --test run_362_public_devnet_abuse_dos_runtime_tests`
- `cargo test -p qbind-node --test run_361_public_devnet_abuse_dos_hardening_tests`
- `cargo test -p qbind-node --lib`

(See the run log for exact results; the harness and helper both report PASS.)

## 23. Security scans

- Secret scanning run over all changed files: **no secrets**. Generated
  PQC/KEMTLS material (including private KEM secret keys) is temporary, dev-only,
  written only into temp dirs, removed on exit, and gitignored. The root signing
  key is held in memory only. No private keys, mnemonics, credentials, tokens,
  private infrastructure, real production hostnames, or live endpoints are
  committed.

## 24. CodeQL

- CodeQL invoked over the Rust example changes (the only code change; docs and
  scripts are non-Rust). Result is recorded exactly as returned by the runner in
  the final response — no clean bill of health is asserted beyond what the tool
  reported. The required cargo test suite (§22) passed.

## 25. Provenance

- Route A, production public APIs + pre-existing public CLI only. Toolchain,
  SHA-256, and Build IDs are captured by the harness at run time (see §3). All
  sockets are loopback on OS-assigned ports; all data dirs and PQC material are
  temporary and removed on exit.

## 26. Honest limitations

- The **helper** in-process scenarios run all peers inside the release helper
  process (real KEMTLS sockets + real read loop + real deployed limiter, but node A
  is not the standalone binary) — "helper-only" evidence by the readiness rules.
  The **harness** provides the cross-process live-socket evidence against
  `target/release/qbind-node` for static-root strict-auth admission and multi-peer
  bucket isolation.
- Under static-root, the deployed listener resolves an inbound peer's cert-derived
  NodeId only when that peer's validator id is listed among node A's `--p2p-peer`
  static peers (the inbound identity resolver is populated from `static_peers`); the
  harness therefore lists the flooding peers as static peers (full-mesh shape). This
  is an operator-configuration property of the deployed builder, not a code change.
- The per-peer bucket key is derived from the peer NodeId (documented coarse
  abuse/DoS keying, not an identity claim); under static-root the NodeId is the
  verified cert-derived value, so the label is computed from the actual generated
  cert and matches live `/metrics`.
- Exact per-peer drop counts and cert-derived bucket labels vary per run (random
  ML-KEM keypairs + scheduling); the invariant is under-budget ⇒ 0 drops (bucket
  absent) and over-budget ⇒ drops > 0 attributed to the abusive cert-derived bucket
  only, honest bucket clean.

## 27. Suggested Run 374 next step

Extend the cross-process static-root proof to **trust-bundle-signed** operator
material end-to-end: drive the standalone `target/release/qbind-node` under
`PqcRootMode::PqcStaticRoot` with a `devnet_pqc_trust_bundle_helper`-signed bundle
(rotation/next-root staging) cross-process against a KEMTLS-admitted strict-auth
flood, proving the trust-bundle load + rotation-staging path over live sockets —
while keeping M4/M6 untouched, C4/C5 OPEN, and public DevNet NOT launch-ready.
Alternatively, begin the M4 live seed/bootnode reachability track, which is the
next launch-blocking readiness gap.
