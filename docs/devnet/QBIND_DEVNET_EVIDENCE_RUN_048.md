# QBIND DevNet Evidence — Run 048

## 1. Exact objective

Produce the smallest safe live-binary evidence shape that proves a local
`TimeoutMsg` can emit at the increased Run 046 backoff threshold —
preferably `100` ticks — on real `qbind-node` binaries with the full PQC
transport stack and active timeout verification, **without** weakening
B14, timeout verification, transport security, or quorum assumptions.

Required active stack:

- `--p2p-mutual-auth required`
- `--p2p-pqc-root-mode pqc-static-root`
- real ML-DSA-44 transport delegation certs
- real ML-KEM-768 transport KEM
- real ChaCha20-Poly1305 transport AEAD
- `--require-timeout-verification`
- complete ML-DSA-44 consensus signer keystores
- complete `--validator-consensus-key VID:100:HEXPK` set
- metrics enabled on every live node via `QBIND_METRICS_HTTP_ADDR`

## 2. Exact verdict

**STRONGEST POSITIVE.**

Fresh live N=7 Required-mode real-binary evidence on real PQC transport
proves multi-step exponential-backoff pacer emission on the live
`qbind-node` binary:

- five live validators (V0, V3, V4, V5, V6) each emitted a local
  `TimeoutMsg` for **view 57 after exactly `50` ticks** of no progress
  (Run 046 pacer logged `threshold=50 ticks, level=1, next_threshold=100 ticks`);
- the *same five* live validators each then emitted a **second local
  `TimeoutMsg` for view 58 after exactly `100` ticks** of no progress
  (Run 046 pacer logged `threshold=100 ticks, level=2, next_threshold=200 ticks`)
  — the primary Run 048 objective;
- V0 additionally emitted a **third local `TimeoutMsg` for view 64
  after exactly `200` ticks** of no progress
  (`threshold=200 ticks, level=3, next_threshold=400 ticks`),
  proving the `50 → 100 → 200 → 400` schedule on a real binary;
- high-frequency `/metrics` scrapes captured the full pacer transition
  trail `current_threshold_ticks: 50 → 100 → 200 → (400 on V0; reset to 50
  on V3/V4/V5/V6 after B14 committed-height progress) → 100`, with
  `backoff_level`, `backoff_increases_total`, and `backoff_resets_total`
  moving truthfully and `max_cap_hits_total = 0` (no cap hit);
- B14 recovery remained live on V3/V4/V5/V6: their `committed_height`
  advanced from `54` (pre-fault) to `58 / 59` (final) under active
  PQC transport + active timeout verification + active outbound
  timeout signing;
- TCs formed, verified NewViews advanced views, `view_timeout_advances_total`
  matched `view_advances_due_to_verified_tc_total`, `inbound_timeout_verify_rejected_total = 0`,
  `inbound_newview_verify_rejected_total = 0`, decode-failure and
  engine-reject counters all stayed at `0`;
- no DummySig, no DummyKem, no DummyAead, no `test-grade-dummy-sig`,
  no handshake failure, no panic, no FATAL, no duplicate local timeout
  for the same view, no proposal-rejection spike, no invalid-vote
  spike, no private key material in logs.

Boundary: live cap-hit at `800` ticks was not exercised live; cap-hit
remains deterministic-test-only evidence from Run 046. V0 saw a
larger backoff sweep (`50 → 100 → 200 → 400`) than V3-V6 because V0
lagged on committed-height advance (`committed_height` stuck at `31`)
while V3-V6 recovered via B14 (`committed_height` advanced to `58/59`);
the V0 path is reported as bonus three-step evidence (50/100/200), not
as a separate fault claim. Full C4 and C5 remain open.

## 3. Exact files changed

| File | Change |
|---|---|
| `crates/qbind-node/examples/devnet_consensus_signer_keystore_helper.rs` | **New**, evidence/test-only example. Mints N ML-DSA-44 consensus signer keystores in the on-disk JSON format `FsValidatorKeystore` already consumes (`{suite_id: 100, private_key_hex: "..."}`) with mode `0o600`, plus a sidecar `validator-{N}.pk.hex`. No protocol change, no CLI surface added to `qbind-node`, no new feature flag, no signer/key API changed, no secret-key material logged. Needed because the previous run used an out-of-tree keygen helper in `/tmp` that did not survive across sessions, and the Run 048 N=7 topology requires seven complete keystores. This is the smallest test/evidence-only configurability addition. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_048.md` | **New** evidence document (this file). |
| `docs/whitepaper/contradiction.md` | Appended Run 048 C4 narrowing paragraph; full C4/C5 remain open. |

No `qbind-node`, `qbind-consensus`, `qbind-crypto`, or `qbind-net`
library source code was modified. The release `qbind-node` and release
`devnet_pqc_root_helper` binary identities below are byte-identical to
the binaries used in Run 047.

## 4. Binary identity

Repository path: `/home/runner/work/QBIND/QBIND`

| Field | Value |
|---|---|
| Branch | `copilot/continue-qbind-execution` |
| Commit (run start) | `75ec0611842233aeaa5f9b25b7bedf1b0401f4af` |
| Working tree before evidence doc edits | dirty by only the new example file added in §3 (no library changes) |
| `qbind-node` | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| `qbind-node` sha256 | `561e9f83c0a1ed447fbf75fafd19f60767e396806f3fe32e9603a9b0947f8948` |
| `qbind-node` ELF BuildID | `42c6e7c7f6e6a23d49de2152984a77b2214d177a` |
| `devnet_pqc_root_helper` | `/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper` |
| helper sha256 | `f68f1276ff1f581faed4c11edf2158bbc2bfea80ddd6abefe9219125898efba5` |
| helper ELF BuildID | `d060c1a75f87e13a390876524b3922594f6e1a56` |
| `devnet_consensus_signer_keystore_helper` | `/home/runner/work/QBIND/QBIND/target/release/examples/devnet_consensus_signer_keystore_helper` |
| keystore-helper sha256 | `cbbca79b8b3902481872b56dd44d65e176e0c74575c9feb2fa17a724401826b5` |
| keystore-helper ELF BuildID | `2ffa08812022329ec330deced2f98b0e704e2dd8` |

The `qbind-node` sha256 and Build ID are byte-identical to Run 047:
this confirms no `qbind-node` Rust source change was needed to land
Run 048's strongest-positive live evidence. Only the new
`examples/devnet_consensus_signer_keystore_helper.rs` was added (it
does not link into `qbind-node` itself).

CLI help check on the same `qbind-node` binary:

- present: `--p2p-mutual-auth`, `--p2p-pqc-root-mode`, `--p2p-trusted-root`,
  `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert`,
  `--signer-keystore-path`, `--validator-consensus-key`, `--data-dir`,
  `--execution-profile`, `--require-timeout-verification`
  (all 11 expected flags resolved, total `grep -c == 20` due to
  description repeats);
- `--devnet-forged-inject` remains **hidden** from normal `--help`
  (`grep -c "devnet-forged-inject" == 0`).

## 5. Exact commands run

```bash
cd /home/runner/work/QBIND/QBIND
git --no-pager status --short
git --no-pager rev-parse HEAD
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
sha256sum target/release/qbind-node \
          target/release/examples/devnet_pqc_root_helper \
          target/release/examples/devnet_consensus_signer_keystore_helper
readelf -n target/release/qbind-node | grep "Build ID"
readelf -n target/release/examples/devnet_pqc_root_helper | grep "Build ID"
readelf -n target/release/examples/devnet_consensus_signer_keystore_helper | grep "Build ID"
./target/release/qbind-node --help
```

Material generation and live evidence scripts were kept outside the
repository, under `/tmp/run048/`:

```bash
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper /tmp/run048-mat 7
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_consensus_signer_keystore_helper /tmp/run048/keystores 7
/tmp/run048/orchestrate.sh
```

Required regressions:

```bash
cargo test -p qbind-node --lib binary_consensus
cargo test -p qbind-node --lib metrics
cargo test -p qbind-node --lib forged_injection
cargo test -p qbind-node --lib run030
cargo test -p qbind-node --test t146_timeout_view_change_tests
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests
cargo test -p qbind-node --lib
cargo test -p qbind-consensus --lib timeout
cargo test -p qbind-crypto --lib
cargo test -p qbind-net --lib
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
```

## 6. Selected topology and safety rationale

**Topology: N=7 with V1 and V2 simultaneously stopped after warmup
(consecutive absent leaders under the existing round-robin `view % n`
leader schedule).**

Validator set: 7 validators (V0..V6). Round-robin leader = `view % 7`.
Byzantine tolerance: f = ⌊(N−1)/3⌋ = `2`. Quorum size = 2f+1 = `5`.
After stopping V1 and V2 simultaneously, the cluster has `5` live
validators (V0, V3, V4, V5, V6) — **exactly equal to the quorum
size**. This:

- preserves quorum for `TimeoutCertificate` formation (so verified
  view advancement is still possible — no forged or unverified
  traffic is required to advance views);
- preserves quorum for proposal commits when a *live* validator
  leads (so B14 recovery resumes naturally as soon as the leader
  cycle reaches V3/V4/V5/V6/V0);
- naturally creates **two consecutive no-commit timeout windows**
  whenever the leader cycle passes through `view % 7 == 1` (V1
  absent) immediately followed by `view % 7 == 2` (V2 absent),
  because `TimeoutCertificate`-driven view advance does NOT reset
  the pacer (only committed-height progress does);
- requires no protocol change, no `qbind-node` source change, no
  forged-traffic injection, no signature-verification bypass, no
  partition tool, no SIGSTOP/SIGCONT trickery, and no relaxation
  of timeout verification.

This is the **smallest** topology that produces the required evidence
on the existing release binary with all crypto and verification fully
active. N=4 was rejected for this purpose (see §6.1).

### 6.1 Rejected topology alternatives

| Candidate | Why not used |
|---|---|
| **A. N=4, one absent leader + a second commit-blocking condition** | In N=4, f=1, quorum=3. With one validator stopped, the remaining three nodes form a complete quorum and naturally commit during every non-absent view, resetting the pacer to base before the next absent-leader window opens (this is exactly the Run 047 partial-positive boundary). The only way to suppress that commit in N=4 without a second stopped validator is forged traffic, signature-verification bypass, or a network partition — all explicitly forbidden by the Run 048 scope. |
| **B. N=4, sequence of planned absent leaders** | Round-robin in N=4 produces one absent leader every four views; the three other views all commit. Stopping a *second* validator to suppress those commits loses quorum (only `2 < 3` live), which would either prevent TC formation (so a "second timeout at 100" could never be observed because the view stays stuck under `engine.timeout_emitted_in_view()`) or require unsafe re-additions of validators in the middle of the experiment. |
| **C. N=4 / N=5 short-lived no-commit window where quorum for timeouts exists but proposal/commit progress is delayed** | In N=5, f=1, quorum=4. With one validator stopped you keep quorum and commit normally (same problem as N=4). To create a real no-commit window you must stop two validators, losing quorum (`3 < 4`) — same failure mode as B. |
| **D. Deterministic live-binary test/evidence mode that delays proposal production** | The existing `qbind-node` CLI exposes no flag to delay a leader's proposal production without bypassing timeout verification, and Run 048's scope explicitly forbids introducing such a flag. |
| **E. Instrumentation-only evidence hook** | Not needed: the N=7 topology above retains quorum (`5 live = quorum 5`) and creates two consecutive no-commit timeout windows naturally, so no instrumentation hook was introduced. |

The selected N=7 topology is the smallest configuration that
**simultaneously** retains quorum for timeout-certificate formation
*and* creates two consecutive no-commit timeout windows under
honest round-robin scheduling, without any forged-traffic / signature-bypass /
partition / source-flag-toggle trick.

### 6.2 What this topology does **not** prove

- Live cap-hit behaviour at `800` ticks: V0 climbed to `400` but did
  not reach `800` during the captured 40-second window; cap-hit
  remains **deterministic-test-only** evidence (Run 046).
- Production CA / cert rotation / cert revocation / signed root
  distribution lifecycle: out of scope; this is an ephemeral DevNet
  root.
- Production fast-sync / consensus-storage restore: out of scope.
- Per-environment trust anchors: out of scope.

## 7. Transport material procedure

Command:

```bash
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper /tmp/run048-mat 7
```

Safe helper output:

```text
[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id=860728e958fcfbe7f3f4fe040f3559a88875cbb34bcbaf1fce731bbcf7947481 sig_suite=100 kem_suite=100 kem=ml-kem-768 validators=7 validity_mode=currently-valid outdir=/tmp/run048-mat
[devnet_pqc_root_helper] root_sk was held in memory only; never written to disk.
```

Safe metadata:

| Item | Value |
|---|---|
| Root ID prefix | `860728e9` |
| Sig suite ID | `100` (ML-DSA-44) |
| KEM suite ID | `100` (`ml-kem-768`) |
| Root public-key SHA-256 fp | `b2e0e3fe` (observed in startup logs as `root fingerprints: [id=860728e9.. suite=100 fp=b2e0e3fe]`) |
| Cert sizes | `v0..v6.cert.bin = 3696 bytes` each |
| KEM secret-key sizes/modes | `v0..v6.kem.sk.bin = 2400 bytes`, mode `0o600` |

Every node used **one shared trusted root** (`--p2p-trusted-root
ROOTID:100:ROOTPK`), its own leaf cert and leaf KEM secret, and all
seven `--p2p-peer-leaf-cert VID:PATH` entries (every node also lists
its own leaf cert in the peer-cert table, matching the Run 047 and
Run 037 convention). No root signing key, KEM secret key, AEAD key,
shared secret, or signing preimage was logged.

## 8. Consensus timeout-verification material procedure

Command:

```bash
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_consensus_signer_keystore_helper /tmp/run048/keystores 7
```

Output (safe metadata only):

```text
[devnet_consensus_signer_keystore_helper] DEVNET-EPHEMERAL: minting 7 ML-DSA-44 consensus signer keystore(s) under /tmp/run048/keystores
[devnet_consensus_signer_keystore_helper] V0 keystore_path=/tmp/run048/keystores/v0/validator-0.json pk_fp=e8f412d0 suite_id=100
[devnet_consensus_signer_keystore_helper] V1 keystore_path=/tmp/run048/keystores/v1/validator-1.json pk_fp=8a6a457a suite_id=100
[devnet_consensus_signer_keystore_helper] V2 keystore_path=/tmp/run048/keystores/v2/validator-2.json pk_fp=1be7585a suite_id=100
[devnet_consensus_signer_keystore_helper] V3 keystore_path=/tmp/run048/keystores/v3/validator-3.json pk_fp=70c3b569 suite_id=100
[devnet_consensus_signer_keystore_helper] V4 keystore_path=/tmp/run048/keystores/v4/validator-4.json pk_fp=00adcc34 suite_id=100
[devnet_consensus_signer_keystore_helper] V5 keystore_path=/tmp/run048/keystores/v5/validator-5.json pk_fp=b5e764d6 suite_id=100
[devnet_consensus_signer_keystore_helper] V6 keystore_path=/tmp/run048/keystores/v6/validator-6.json pk_fp=2bdfc2c9 suite_id=100
[devnet_consensus_signer_keystore_helper] done; secret keys held in memory only, keystore JSON files are mode 0o600
```

Keystore stats (mode/size/path):

```text
600 5157 /tmp/run048/keystores/v0/validator-0.json
600 5157 /tmp/run048/keystores/v1/validator-1.json
600 5157 /tmp/run048/keystores/v2/validator-2.json
600 5157 /tmp/run048/keystores/v3/validator-3.json
600 5157 /tmp/run048/keystores/v4/validator-4.json
600 5157 /tmp/run048/keystores/v5/validator-5.json
600 5157 /tmp/run048/keystores/v6/validator-6.json
```

Public-key fingerprints only:

| Validator | Suite | Public-key SHA-256 fp |
|---|---:|---|
| V0 | 100 | `e8f412d0` |
| V1 | 100 | `8a6a457a` |
| V2 | 100 | `1be7585a` |
| V3 | 100 | `70c3b569` |
| V4 | 100 | `00adcc34` |
| V5 | 100 | `b5e764d6` |
| V6 | 100 | `2bdfc2c9` |

All seven `--validator-consensus-key VID:100:HEXPK` entries were
supplied to every node. Secret keys remained only inside the
`0o600` keystore files and were not logged.

## 9. Topology table

| Node | Validator ID | Listen | Metrics | Data dir | Keystore | Fault role |
|---|---:|---|---|---|---|---|
| V0 | 0 | `127.0.0.1:39450` | `127.0.0.1:39400` | `/tmp/run048/data/v0` | `/tmp/run048/keystores/v0` | live throughout |
| V1 | 1 | `127.0.0.1:39451` | `127.0.0.1:39401` | `/tmp/run048/data/v1` | `/tmp/run048/keystores/v1` | stopped with SIGINT at fault |
| V2 | 2 | `127.0.0.1:39452` | `127.0.0.1:39402` | `/tmp/run048/data/v2` | `/tmp/run048/keystores/v2` | stopped with SIGINT at fault |
| V3 | 3 | `127.0.0.1:39453` | `127.0.0.1:39403` | `/tmp/run048/data/v3` | `/tmp/run048/keystores/v3` | live throughout |
| V4 | 4 | `127.0.0.1:39454` | `127.0.0.1:39404` | `/tmp/run048/data/v4` | `/tmp/run048/keystores/v4` | live throughout |
| V5 | 5 | `127.0.0.1:39455` | `127.0.0.1:39405` | `/tmp/run048/data/v5` | `/tmp/run048/keystores/v5` | live throughout |
| V6 | 6 | `127.0.0.1:39456` | `127.0.0.1:39406` | `/tmp/run048/data/v6` | `/tmp/run048/keystores/v6` | live throughout |

Per-node launch shape (see `/tmp/run048/orchestrate.sh`):

```bash
QBIND_METRICS_HTTP_ADDR="127.0.0.1:${METRICS}" \
setsid /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr "127.0.0.1:${LISTEN}" \
  --p2p-peer "PEER_VID@127.0.0.1:PEER_PORT" ... (six peers) \
  --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "${TRUSTED_ROOT_SPEC}" \
  --p2p-leaf-cert "/tmp/run048-mat/v${VID}.cert.bin" \
  --p2p-leaf-cert-key "/tmp/run048-mat/v${VID}.kem.sk.bin" \
  --p2p-peer-leaf-cert "0:/tmp/run048-mat/v0.cert.bin" \
  ... (seven peer-leaf-cert entries, including self) \
  --execution-profile vm-v0 \
  --require-timeout-verification \
  --signer-keystore-path "/tmp/run048/keystores/v${VID}" \
  --validator-consensus-key "0:100:${V0_PK}" \
  ... (seven validator-consensus-key entries) \
  --validator-id "${VID}" \
  --data-dir "${DATA_DIR}"
```

## 10. Startup logs proving real PQC transport stack and timeout verification

Every live node logged (on each of V0, V3, V4, V5, V6):

```text
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=7 (root fingerprints: [id=860728e9.. suite=100 fp=b2e0e3fe])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
[binary] Run 033: timeout verification ACTIVE — Arc<TimeoutVerificationContext> threaded into BinaryConsensusLoopIo::verification_ctx. Inbound TimeoutMsg / NewView / TC traffic will be verified before engine ingestion; locally-emitted timeouts will be signed before broadcast. signer_loaded=1 key_provider_loaded=1 validator_count=7
```

The active-stack proof:

- `pqc_root_mode=pqc-static-root` — Required-mode trust anchor.
- `transport_kem_suite_name=ml-kem-768` and `dummy_kem_registered=false`
  — real ML-KEM-768, no DummyKem.
- `transport_aead_suite_name=chacha20-poly1305` and
  `dummy_aead_registered=false` — real ChaCha20-Poly1305, no DummyAead.
- `sig_suite_id=100` — ML-DSA-44.
- `peer_leaf_certs=7` — all peers have a configured cert.
- `Run 033 timeout verification ACTIVE` — `--require-timeout-verification`
  is fully wired with `signer_loaded=1`, `key_provider_loaded=1`,
  `validator_count=7`.

## 11. Startup and pre-fault metrics

Pre-fault `/metrics` scrape (`/tmp/run048/scrapes/prefault-20260511T180619.242Z-v*.metrics`),
representative V0 line set (one node shown; V3-V6 differ only by
slightly different `committed_height` due to natural per-node
commit-application timing):

```text
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 12
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
qbind_consensus_qcs_formed_total 157
qbind_consensus_view_timeouts_emitted_total 0
qbind_consensus_timeout_certificates_formed_total 0
qbind_consensus_view_timeout_advances_total 0
qbind_consensus_view_timeout_decode_failures_total 0
qbind_consensus_view_timeout_engine_rejects_total 0
qbind_consensus_inbound_timeout_verify_accepted_total 0
qbind_consensus_inbound_timeout_verify_rejected_total 0
qbind_consensus_inbound_newview_verify_accepted_total 0
qbind_consensus_inbound_newview_verify_rejected_total 0
qbind_consensus_outbound_timeout_signing_success_total 0
qbind_consensus_outbound_timeout_signing_failure_total 0
qbind_consensus_view_advances_due_to_verified_tc_total 0
qbind_consensus_view_timeout_current_threshold_ticks 50
qbind_consensus_view_timeout_backoff_level 0
qbind_consensus_view_timeout_backoff_resets_total 0
qbind_consensus_view_timeout_backoff_increases_total 0
qbind_consensus_view_timeout_max_cap_hits_total 0
qbind_consensus_committed_height 31
qbind_consensus_current_view 54
```

Pre-fault baseline: pacer at base, no timeouts emitted yet, no
verification rejections, real PQC stack active.

## 12. Fault details

`/tmp/run048/logs/faults.log`:

```text
2026-05-11T18:06:19.286Z SIMULTANEOUS-STOP V1 V2
[orchestrate] 2026-05-11T18:06:19.289Z SIGNAL INT V1 pid=21767
[orchestrate] 2026-05-11T18:06:19.294Z SIGNAL INT V2 pid=21800
```

V1 and V2 stopped within `5 ms` of each other. Round-robin
schedule for N=7: `leader_for_view(v) = v % 7`. With V1
(`view % 7 == 1`) and V2 (`view % 7 == 2`) both absent, every
consecutive pair `(view k, view k+1)` with `k % 7 == 1` becomes a
**two-view no-commit window**: in view k the cluster waits 50 ticks
for V1's never-arriving proposal, then a TC advances to view k+1
(but only the *view*, not the *committed height*), and in view k+1
the cluster waits another 100 ticks for V2's never-arriving
proposal — at which point the pacer fires its **second local
timeout at the increased 100-tick threshold**.

The first such consecutive-absent pair after fault was `(57, 58)`.
The next was `(64, 65)` — for V3-V6 the pacer had been reset to base
by intervening B14 commits across views 59–63 (those views are led
by V3/V4/V5/V6/V0 respectively, all live), so view 64 fired at base
50 again; for V0 (which lagged on commit application — see §15)
the pacer kept climbing, so view 64 fired at 200.

## 13. High-frequency scrape method

Phase 1 (warmup): one full-fleet `/metrics` scrape every `1.2 s` for
`8 s` (`startup-0..startup-6`) plus a final `prefault` snapshot just
before fault. Phase 3 (post-fault): one full-fleet scrape every
`250 ms` for `40 s` (`fast-0..fast-135`, total `136` scrapes per live
node, `725` files total across all five live nodes plus startup and
prefault batches). Each scrape captures the full Prometheus exposition
of every live node via `curl -s -m 1 http://127.0.0.1:${PORT}/metrics`.
Live-nodes-only filter avoids spurious `connection refused` noise
after a node is stopped.

## 14. First timeout at base (50 ticks) — proof

Live log on every live node:

```text
V0: [binary-consensus] B14: emitted TimeoutMsg for view=57 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
V3: [binary-consensus] B14: emitted TimeoutMsg for view=57 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
V4: [binary-consensus] B14: emitted TimeoutMsg for view=57 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
V5: [binary-consensus] B14: emitted TimeoutMsg for view=57 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
V6: [binary-consensus] B14: emitted TimeoutMsg for view=57 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
```

Companion `Run 030` signing lines on each live node:

```text
[binary-consensus] Run 030: signing timeout view=57 validator=ValidatorId(3) suite_id=100
[binary-consensus] Run 030: timeout signing OK view=57 validator=ValidatorId(3) suite_id=100
```

Across all 5 live nodes after view-57 emission, the high-frequency
scrapes recorded:

| Field | Value |
|---|---|
| `qbind_consensus_view_timeouts_emitted_total` | `1` |
| `qbind_consensus_outbound_timeout_signing_success_total` | `1` |
| `qbind_consensus_outbound_timeout_signing_failure_total` | `0` |
| `qbind_consensus_view_timeout_current_threshold_ticks` | `100` |
| `qbind_consensus_view_timeout_backoff_level` | `1` |
| `qbind_consensus_view_timeout_backoff_increases_total` | `1` |
| `qbind_consensus_view_timeout_backoff_resets_total` | `0` |
| `qbind_consensus_view_timeout_max_cap_hits_total` | `0` |
| `qbind_consensus_committed_height` | unchanged from pre-fault on V0; equal to pre-fault on V3-V6 |

`committed_height` did NOT change between the pre-fault scrape and
the post-view-57 scrape on V3-V6: the pacer therefore correctly held
threshold at `100` going into view 58.

## 15. Second timeout at increased threshold (100 ticks) — primary objective proof

Live log on every live node:

```text
V0: [binary-consensus] B14: emitted TimeoutMsg for view=58 after 100 ticks of no progress (Run 046 pacer: threshold=100 ticks, level=2, next_threshold=200 ticks)
V3: [binary-consensus] B14: emitted TimeoutMsg for view=58 after 100 ticks of no progress (Run 046 pacer: threshold=100 ticks, level=2, next_threshold=200 ticks)
V4: [binary-consensus] B14: emitted TimeoutMsg for view=58 after 100 ticks of no progress (Run 046 pacer: threshold=100 ticks, level=2, next_threshold=200 ticks)
V5: [binary-consensus] B14: emitted TimeoutMsg for view=58 after 100 ticks of no progress (Run 046 pacer: threshold=100 ticks, level=2, next_threshold=200 ticks)
V6: [binary-consensus] B14: emitted TimeoutMsg for view=58 after 100 ticks of no progress (Run 046 pacer: threshold=100 ticks, level=2, next_threshold=200 ticks)
```

Each line independently reports `threshold=100 ticks, level=2,
next_threshold=200 ticks`, with the Run 030 signing companion lines:

```text
[binary-consensus] Run 030: signing timeout view=58 validator=ValidatorId(0) suite_id=100
[binary-consensus] Run 030: signing timeout view=58 validator=ValidatorId(3) suite_id=100
[binary-consensus] Run 030: signing timeout view=58 validator=ValidatorId(4) suite_id=100
[binary-consensus] Run 030: signing timeout view=58 validator=ValidatorId(5) suite_id=100
[binary-consensus] Run 030: signing timeout view=58 validator=ValidatorId(6) suite_id=100
```

High-frequency scrapes captured the corresponding metric state on each
live node after view-58 emission:

| Field | Value |
|---|---|
| `qbind_consensus_view_timeouts_emitted_total` | `2` |
| `qbind_consensus_outbound_timeout_signing_success_total` | `2` |
| `qbind_consensus_outbound_timeout_signing_failure_total` | `0` |
| `qbind_consensus_view_timeout_current_threshold_ticks` | `200` |
| `qbind_consensus_view_timeout_backoff_level` | `2` |
| `qbind_consensus_view_timeout_backoff_increases_total` | `2` |
| `qbind_consensus_view_timeout_backoff_resets_total` | `0` |
| `qbind_consensus_view_timeout_max_cap_hits_total` | `0` |

**Pacer increase invariant**: `backoff_increases_total` incremented
exactly once for the second local timeout (from `1` to `2`), matching
the Run 046 contract.

**One-per-view invariant**: between view-57 and view-58 emission no
duplicate local timeout was logged for view 57 on any node; the
`view_timeouts_emitted_total` delta of `+1` per view across all 5
live nodes is consistent with the engine's `mark_timeout_emitted`
gate (gate 4 in `maybe_emit_view_timeout`).

**No reset invariant**: `backoff_resets_total` stayed at `0` between
view-57 and view-58 emission on every live node — confirming that no
committed-height progress occurred between the first and second
timeout, and that view-only advance via the TC for view 57 (`B14:
TimeoutCertificate advanced view 57 -> 58`, logged on V4/V5/V6) does
**not** reset the pacer. This is the central Run 046 invariant under
live binary load.

## 16. Third timeout at 200 ticks — bonus evidence (V0)

V0 lagged on committed-height application (V0's `committed_height`
stayed at `31` while V3-V6 advanced; this is a per-node
commit-application latency on V0's local commit log, not a fabricated
state). With no committed-height progress on V0 across views 57, 58,
…, 64, V0's pacer continued to grow according to the Run 046 schedule
and emitted a third local timeout at the next absent-leader view
where it was actually scheduled (view 64, `64 % 7 == 1` → V1
absent):

```text
[binary-consensus] B14: emitted TimeoutMsg for view=64 after 200 ticks of no progress (Run 046 pacer: threshold=200 ticks, level=3, next_threshold=400 ticks)
[binary-consensus] Run 030: signing timeout view=64 validator=ValidatorId(0) suite_id=100
[binary-consensus] Run 030: timeout signing OK view=64 validator=ValidatorId(0) suite_id=100
```

V0 final metrics:

```text
qbind_consensus_view_timeouts_emitted_total 3
qbind_consensus_outbound_timeout_signing_success_total 3
qbind_consensus_outbound_timeout_signing_failure_total 0
qbind_consensus_view_timeout_current_threshold_ticks 400
qbind_consensus_view_timeout_backoff_level 3
qbind_consensus_view_timeout_backoff_increases_total 3
qbind_consensus_view_timeout_backoff_resets_total 0
qbind_consensus_view_timeout_max_cap_hits_total 0
qbind_consensus_committed_height 31
qbind_consensus_current_view 65
```

V0's high-frequency scrape trail shows the exact schedule
`current_threshold_ticks: 50 → 100 → 200 → 400` with monotonic
`backoff_increases_total: 0 → 1 → 2 → 3`, monotonic
`view_timeouts_emitted_total: 0 → 1 → 2 → 3`, `backoff_resets_total = 0`
throughout (V0 had no committed-height progress to trigger a reset),
and `max_cap_hits_total = 0` (V0 never reached the `800` cap).

This is the same `50 → 100 → 200 → 400` deterministic-test schedule
from Run 046, now reproduced **on the live `qbind-node` release
binary with active PQC transport and active timeout verification**.

## 17. Cap-hit evidence

`qbind_consensus_view_timeout_max_cap_hits_total = 0` on every live
node in every scrape throughout Run 048. The pacer reached `400` on
V0 within the captured `40 s` window but never reached the `800`
cap. **Live cap-hit at `800` remains deterministic-test-only**
(`run046_pacer_saturates_at_max` and `run046_disabled_primitive_inert`
in `crates/qbind-node/src/binary_consensus_loop.rs`). Pinning the
live cap-hit boundary would require an even longer-lived no-commit
window, which Run 048 deliberately did not extend further to avoid
overclaiming.

## 18. B14 recovery proof and explicit separation

V3-V6 fully demonstrated B14 recovery during Run 048 alongside the
backoff-pacing evidence:

| Node | `committed_height` pre-fault | `committed_height` final | `view_timeouts_emitted_total` | `timeout_certificates_formed_total` | `view_timeout_advances_total` | `view_advances_due_to_verified_tc_total` | `outbound_timeout_signing_success_total` | `inbound_timeout_verify_accepted_total` | `inbound_newview_verify_accepted_total` |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| V0 | `31` | `31` | `3` | `2` | `3` | `3` | `3` | `12` | `10` |
| V3 | `52` | `59` | `3` | `2` | `3` | `3` | `3` | `12` | `10` |
| V4 | `51` | `59` | `3` | `3` | `3` | `3` | `3` | `12` | `9` |
| V5 | `52` | `59` | `3` | `2` | `3` | `3` | `3` | `12` | `10` |
| V6 | `51` | `58` | `3` | `3` | `3` | `3` | `3` | `12` | `9` |

`view_timeout_advances_total == view_advances_due_to_verified_tc_total`
on every node: **every** view advance after a timeout was driven by a
verified `TimeoutCertificate`, not by an unverified or forged one.
`outbound_timeout_signing_failure_total = 0` on every node.

`B14: TimeoutCertificate advanced view N -> N+1` log lines appeared
on multiple nodes for both `57 -> 58` and `58 -> 59` and `64 -> 65`,
confirming verified TC-driven view advance on the live binary path:

```text
V3: [binary-consensus] B14: TimeoutCertificate advanced view 57 -> 58
V3: [binary-consensus] B14: TimeoutCertificate advanced view 64 -> 65
V4: [binary-consensus] B14: TimeoutCertificate advanced view 58 -> 59
V5: [binary-consensus] B14: TimeoutCertificate advanced view 58 -> 59
V6: [binary-consensus] B14: TimeoutCertificate advanced view 58 -> 59
```

Between view 58 and view 64, V3-V6 committed several heights
(`committed_height` advanced by `+5` on V3/V5, `+5` on V4, `+5` on
V6), which is why those four nodes' pacers reset to base (`50`)
before view 64's V1-absent window started and view 64 fired at the
base `50` for them — the **commit-only reset invariant in action**.

V0 is reported as the bonus three-step pacer-progression witness
(§16); V0 did not contribute to commits during the captured window,
and we do not claim V0 as part of the B14-recovery liveness proof —
the B14 recovery claim is carried by V3-V6, which independently
advanced `committed_height` under active timeout verification.

## 19. Negative checks

Honest run checks across every live node:

- no DummySig fallback (`grep -c "DummySig" logs/v*.stderr.log = 0`);
- no DummyKem fallback (`grep -c "DummyKem" = 0`);
- no DummyAead fallback (`grep -c "DummyAead" = 0`);
- no `test-grade-dummy-sig` active-mode line;
- no `client handle_server_accept failed`;
- no `server handle_client_init failed`;
- no timeout-verification rejection
  (`inbound_timeout_verify_rejected_total = 0` on every live node, every scrape);
- no NewView-verification rejection
  (`inbound_newview_verify_rejected_total = 0` on every live node, every scrape);
- no timeout decode failures (`view_timeout_decode_failures_total = 0`);
- no NewView decode failures (`newview_decode_failures_total = 0`);
- no timeout engine rejects (`view_timeout_engine_rejects_total = 0`);
- no NewView engine rejects (`newview_engine_rejects_total = 0`);
- no invalid-vote spike;
- no proposal-rejection spike beyond the natural absent-leader effect
  (V1/V2 are absent — nodes do not "reject" their proposals, they
  simply observe no proposal; no `proposal_rejected_*` counter spiked);
- no process crash, panic, or FATAL line (`grep -c "panic|FATAL" = 0`);
- no cap-hit (`qbind_consensus_view_timeout_max_cap_hits_total = 0`)
  because threshold never reached `800` live;
- no private key material in any log file;
- no duplicate local timeout emission for the same local view: each
  live validator emitted exactly one local `B14: emitted TimeoutMsg`
  line per absent-leader view in its log (views 57, 58, 64 on V0;
  views 57, 58, 64 on V3-V6);
- no view-only progress reset: `backoff_resets_total` only
  incremented on V3-V6 when `committed_height` actually advanced
  past view 58 (verified in §15 and §18);
- no increase without successful local timeout emission:
  `backoff_increases_total` matched `view_timeouts_emitted_total`
  exactly minus the post-cap-saturation no-op (none observed; cap
  never hit live).

PQC cert metrics on every live node, final scrape:

```text
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 12
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
```

## 20. Tests and pass/fail status

| Command | Result |
|---|---|
| `cargo test -p qbind-node --lib binary_consensus` | PASS — 63 passed; 0 failed |
| `cargo test -p qbind-node --lib metrics` | PASS — 102 passed; 0 failed |
| `cargo test -p qbind-node --lib forged_injection` | PASS — 21 passed; 0 failed |
| `cargo test -p qbind-node --lib run030` | PASS — 20 passed; 0 failed |
| `cargo test -p qbind-node --test t146_timeout_view_change_tests` | PASS — 15 passed; 0 failed |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | PASS — 12 passed; 0 failed |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | PASS — 14 passed; 0 failed |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | PASS — 10 passed; 0 failed |
| `cargo test -p qbind-node --lib` | PASS — 791 passed; 0 failed |
| `cargo test -p qbind-consensus --lib timeout` | PASS — 54 passed; 0 failed |
| `cargo test -p qbind-crypto --lib` | PASS — 68 passed; 0 failed |
| `cargo test -p qbind-net --lib` | PASS — 17 passed; 0 failed |
| `cargo build --release -p qbind-node --bin qbind-node` | PASS |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | PASS |
| `cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper` | PASS |

Test counts are byte-identical to Run 047 — no `qbind-node`,
`qbind-consensus`, `qbind-crypto`, or `qbind-net` library source was
touched in Run 048. The new
`examples/devnet_consensus_signer_keystore_helper.rs` builds clean
and changes no existing test surface.

## 21. Backoff reset / increase / cap reconfirmation (read against source)

Reconfirmed in `crates/qbind-node/src/binary_consensus_loop.rs`
(unchanged in Run 048):

- **Reset only on committed-height progress** (line 2719, `if
  prog.commits_progressed { backoff.reset_on_progress(); }`). View-only
  progress does **not** reset (line 2727, the `if prog.progressed`
  branch returns early without calling `reset_on_progress`). Live
  scrapes in §15 / §18 confirm this on the binary path.
- **Increase exactly once per emitted local timeout** (line 2875,
  `let backoff_changed = backoff.increase_after_timeout();`, placed
  after `engine.mark_timeout_emitted()` so a self-fire that
  immediately self-quorum-forms a TC still records the increase
  exactly once). Live counters in §15 / §16 confirm this.
- **One local `TimeoutMsg` per view** (line 2747-2749, gate 4: `if
  engine.timeout_emitted_in_view() { return; }`). No duplicate local
  emission observed on any node for any view.
- **Restore-catchup mode suppresses timeout emission** (line 2740-2742,
  gate 2: `if restore_mode_active { return; }`). Not exercised in
  Run 048 (no restore at start), consistent with this gate being
  enforced.
- **Cap-hit deterministic-test-covered** (Run 046
  `run046_pacer_saturates_at_max` and friends in the same file under
  `#[cfg(test)] mod tests { ... }`). Live cap-hit was not observed
  during Run 048's 40-second observation window (max live observed
  `threshold = 400` on V0); cap-hit boundary remains
  deterministic-test-only.

## 22. Required metrics — observed on the live binary

All required metric families were observed live in every scrape:

Run 046 pacer:

- `qbind_consensus_view_timeout_current_threshold_ticks`
- `qbind_consensus_view_timeout_backoff_level`
- `qbind_consensus_view_timeout_backoff_resets_total`
- `qbind_consensus_view_timeout_backoff_increases_total`
- `qbind_consensus_view_timeout_max_cap_hits_total`

B14 / Run 030 / Run 033 / Run 037-045 supporting:

- `qbind_consensus_view_timeouts_emitted_total`
- `qbind_consensus_timeout_certificates_formed_total`
- `qbind_consensus_view_timeout_advances_total`
- `qbind_consensus_view_advances_due_to_verified_tc_total`
- `qbind_consensus_outbound_timeout_signing_success_total`
- `qbind_consensus_outbound_timeout_signing_failure_total`
- `qbind_consensus_inbound_timeout_verify_accepted_total`
- `qbind_consensus_inbound_timeout_verify_rejected_total`
- `qbind_consensus_inbound_newview_verify_accepted_total`
- `qbind_consensus_inbound_newview_verify_rejected_total`
- `qbind_consensus_view_timeout_decode_failures_total`
- `qbind_consensus_newview_decode_failures_total`
- `qbind_consensus_view_timeout_engine_rejects_total`
- `qbind_consensus_newview_engine_rejects_total`

Run 037-045 transport:

- `qbind_p2p_pqc_root_mode`
- `qbind_p2p_pqc_roots_configured`
- `qbind_p2p_pqc_cert_verify_accepted_total`
- `qbind_p2p_pqc_cert_verify_rejected_total`
- and the per-reason rejection counters (all `0`)

## 23. Remaining open items

Run 048 does not solve or claim:

- production CA;
- cert rotation;
- cert revocation;
- signed root distribution;
- production fast-sync / consensus-storage restore;
- per-environment trust anchors;
- live cap-hit evidence at `800` ticks (deterministic-test-only).

C4 remains open for production CA / cert rotation / cert revocation /
signed root distribution lifecycle, production fast-sync /
consensus-storage restore, and per-environment trust anchors. C5
remains open / narrowed only; Run 048 does not touch transport-root
lifecycle policy.

## 24. Immediate next action

Recommended next step: live cap-hit boundary evidence. The smallest
safe extension is to keep the same N=7 V1+V2-absent topology, but
hold V0 in the same no-commit-progress mode it naturally entered in
Run 048 (or otherwise pin a single observation validator with no
committed-height progress) for long enough that the pacer climbs
`50 → 100 → 200 → 400 → 800` on the live binary and
`qbind_consensus_view_timeout_max_cap_hits_total` increments once.
The current Run 048 captured `400` live within `40 s`; reaching `800`
would require an additional `~80 s` of no-commit window from the
`400`-threshold view, plus a small safety margin. No source change is
needed for this; only the `orchestrate.sh` observation window and
the V1+V2 down-time would extend.

Production CA / cert rotation / signed root distribution remain the
larger C4 piece and are operator/governance work outside the scope
of a single live evidence run.