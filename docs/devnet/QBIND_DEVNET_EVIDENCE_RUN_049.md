# QBIND DevNet Evidence — Run 049

## 1. Exact objective

Produce live cap-hit evidence for the Run 046 binary-path view-timeout exponential-backoff pacer at the `800`-tick maximum threshold, using the Run 048 N=7 quorum-preserving topology if feasible, with the full Required PQC transport and timeout-verification stack active and without changing protocol behavior or fabricating metrics.

Required active stack: `--p2p-mutual-auth required`, `--p2p-pqc-root-mode pqc-static-root`, real ML-DSA-44 transport delegation certs, real ML-KEM-768 transport KEM, real ChaCha20-Poly1305 transport AEAD, `--require-timeout-verification`, ML-DSA-44 consensus signer keystores, complete `--validator-consensus-key VID:100:HEXPK` set, and metrics enabled on every live node via `QBIND_METRICS_HTTP_ADDR`.

## 2. Exact verdict

**STRONGEST POSITIVE.** Fresh live N=7 Required-mode real-binary evidence proves the Run 046 bounded timeout pacer reaches and saturates at the `800`-tick cap on the live `qbind-node` binary:

- V0 emitted local `TimeoutMsg`s at `50`, `100`, `200`, `400`, and `800` ticks with the logged schedule `50 → 100 → 200 → 400 → 800 → 800`.
- V6 independently emitted local `TimeoutMsg`s at `50`, `100`, `200`, `400`, and `800` ticks with the same cap behavior.
- High-frequency `/metrics` scrapes captured threshold progression to `800`, `backoff_level = 4`, and `qbind_consensus_view_timeout_max_cap_hits_total` moving from `0 → 1` exactly on first cap arrival and `1 → 2` only after a later local timeout attempted to grow while already saturated.
- Threshold never exceeded `800`; a further local timeout at cap used `threshold=800` and logged `next_threshold=800`; no overflow, wraparound, duplicate local timeout, fabricated cap-hit, or cap-hit-before-threshold-800 was observed.
- B14 safety remained preserved for the live quorum: timeout certificates formed, verified timeout/NewView traffic advanced views, and honest verification rejection/decode/engine-reject counters stayed at zero.
- Real PQC transport and active timeout verification remained enabled; no DummySig/DummyKem/DummyAead fallback was observed.

Boundary: the original first attempt accidentally signalled wrapper shell PIDs, not the `setsid` process groups, so V1/V2 did not actually stop and normal commits reset the pacer before cap. That failed attempt is retained under `/tmp/run049` as negative operational evidence but is not used for the positive verdict. The final run used process-group SIGINT and the same safe N=7 topology.

## 3. Exact files changed

| File | Change |
|---|---|
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_049.md` | New evidence document. |
| `docs/whitepaper/contradiction.md` | C4 Run 049 update: live cap-hit at `800` is now complete for the binary path; full C4 remains open for CA/root lifecycle, production fast-sync/consensus-storage restore, and per-environment trust anchors. |

No `qbind-node`, `qbind-consensus`, `qbind-crypto`, `qbind-net`, wire-format, transport-crypto, KEMTLS, signer, timeout-verification, or protocol source code changed.

## 4. Binary identity

Repository path: `/home/runner/work/QBIND/QBIND`

| Field | Value |
|---|---|
| Branch | `copilot/continue-qbind-implementation` |
| Commit at evidence start | `dac7c1ec6da7218f15758e8f3bd01570d314475a` |
| Working tree before evidence-doc edits | clean |
| `qbind-node` sha256 | `561e9f83c0a1ed447fbf75fafd19f60767e396806f3fe32e9603a9b0947f8948` |
| `qbind-node` ELF BuildID | `42c6e7c7f6e6a23d49de2152984a77b2214d177a` |
| `devnet_pqc_root_helper` sha256 / BuildID | `f68f1276ff1f581faed4c11edf2158bbc2bfea80ddd6abefe9219125898efba5` / `d060c1a75f87e13a390876524b3922594f6e1a56` |
| `devnet_consensus_signer_keystore_helper` sha256 / BuildID | `18f455bd0e8891381ee00dd31472beade2409d843ddae25fcf327843620d8b4c` / `ebb61100054d043ad0e0d2dc4272968641233f38` |

The release `qbind-node` sha256 and BuildID are byte-identical to Run 048. CLI help still exposes the required flags and keeps `--devnet-forged-inject` hidden from normal `--help` (`forged_help_count=0`).

## 5. Exact commands run

```bash
cd /home/runner/work/QBIND/QBIND
git --no-pager status --short
git --no-pager branch --show-current
git --no-pager rev-parse HEAD
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
sha256sum target/release/qbind-node target/release/examples/devnet_pqc_root_helper target/release/examples/devnet_consensus_signer_keystore_helper
readelf -n target/release/qbind-node | grep 'Build ID'
readelf -n target/release/examples/devnet_pqc_root_helper | grep 'Build ID'
readelf -n target/release/examples/devnet_consensus_signer_keystore_helper | grep 'Build ID'
./target/release/qbind-node --help
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper /tmp/run049-fixed-n7-mat 7
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_consensus_signer_keystore_helper /tmp/run049-fixed-n7/keystores 7
RUN_DIR=/tmp/run049-fixed-n7 MAT_DIR=/tmp/run049-fixed-n7-mat N=7 STOP_SET='1 2' LISTEN_BASE=40950 METRICS_BASE=40900 POST_FAULT_SCRAPES=960 SCRAPE_SLEEP=0.25 WARMUP_SCRAPES=12 /tmp/run049-orchestrate-fixed.sh
```

Required regression commands:

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
cargo build --release -p qbind-node --example devnet_consensus_signer_keystore_helper
```

## 6. Tests run and pass/fail status

| Command | Result |
|---|---:|
| `cargo test -p qbind-node --lib binary_consensus` | PASS, 63/63 |
| `cargo test -p qbind-node --lib metrics` | PASS, 102/102 |
| `cargo test -p qbind-node --lib forged_injection` | PASS, 21/21 |
| `cargo test -p qbind-node --lib run030` | PASS, 20/20 |
| `cargo test -p qbind-node --test t146_timeout_view_change_tests` | PASS, 15/15 |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | PASS, 12/12 |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | PASS, 14/14 |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | PASS, 10/10 |
| `cargo test -p qbind-node --lib` | PASS, 791/791 |
| `cargo test -p qbind-consensus --lib timeout` | PASS, 54/54 selected |
| `cargo test -p qbind-crypto --lib` | PASS, 68/68 |
| `cargo test -p qbind-net --lib` | PASS, 17/17 |
| Release builds for `qbind-node` and both helpers | PASS |

## 7. Topology and safety rationale

Selected topology: **N=7 with V1 and V2 simultaneously stopped after warmup**, identical to Run 048 after fixing signal targeting to process groups.

| Node | Validator ID | Listen | Metrics | Data dir | Fault role |
|---|---:|---|---|---|---|
| V0 | 0 | `127.0.0.1:40950` | `127.0.0.1:40900` | `/tmp/run049-fixed-n7/data/v0` | live cap witness |
| V1 | 1 | `127.0.0.1:40951` | `127.0.0.1:40901` | `/tmp/run049-fixed-n7/data/v1` | stopped with process-group SIGINT |
| V2 | 2 | `127.0.0.1:40952` | `127.0.0.1:40902` | `/tmp/run049-fixed-n7/data/v2` | stopped with process-group SIGINT |
| V3 | 3 | `127.0.0.1:40953` | `127.0.0.1:40903` | `/tmp/run049-fixed-n7/data/v3` | live recovery witness |
| V4 | 4 | `127.0.0.1:40954` | `127.0.0.1:40904` | `/tmp/run049-fixed-n7/data/v4` | live recovery witness |
| V5 | 5 | `127.0.0.1:40955` | `127.0.0.1:40905` | `/tmp/run049-fixed-n7/data/v5` | live recovery witness |
| V6 | 6 | `127.0.0.1:40956` | `127.0.0.1:40906` | `/tmp/run049-fixed-n7/data/v6` | live cap witness |

For N=7, f=2 and quorum is `2f+1 = 5`. After V1 and V2 stop, the five live validators V0/V3/V4/V5/V6 are exactly a quorum. This preserves TC formation and live-led-view recovery without forged traffic, unsafe partitioning, or signature/verification bypass. V0 and V6 lagged on committed-height progress after the fault and therefore served as cap witnesses. V3/V4/V5 also demonstrated B14 recovery and reset behavior after committed-height progress.

## 8. Transport material procedure

Command:

```bash
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper /tmp/run049-fixed-n7-mat 7
```

Safe helper output:

```text
[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id=fc4755e2b329067062e976a8bdffbdff3f27fb9774cee366a3a98b8fd4b62c51 sig_suite=100 kem_suite=100 kem=ml-kem-768 validators=7 validity_mode=currently-valid outdir=/tmp/run049-fixed-n7-mat
[devnet_pqc_root_helper] root_sk was held in memory only; never written to disk.
```

Safe metadata: root ID prefix `fc4755e2`; sig suite `100`; KEM suite `100` (`ml-kem-768`); startup root public-key fingerprint `315eb55a`; cert sizes `3696` bytes each; KEM secret-key files `2400` bytes each, mode `0o600`.

Every node used one shared trusted root, its own leaf cert, its own leaf KEM secret, and all seven peer leaf cert mappings. No root signing key, KEM secret key, AEAD key, shared secret, signing preimage, or root signing key material was logged.

## 9. Consensus signer/key material procedure

Command:

```bash
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_consensus_signer_keystore_helper /tmp/run049-fixed-n7/keystores 7
```

Safe public-key fingerprints:

| Validator | Suite | Public-key fp |
|---|---:|---|
| V0 | 100 | `12ca021a` |
| V1 | 100 | `f6a249e3` |
| V2 | 100 | `3f6806a7` |
| V3 | 100 | `14ec5b44` |
| V4 | 100 | `98ab905d` |
| V5 | 100 | `d5dc3741` |
| V6 | 100 | `da194a06` |

Keystore files were mode `0o600`, size `5157` bytes each. All seven `--validator-consensus-key VID:100:HEXPK` entries were supplied to every node. Only public-key fingerprints were recorded.

## 10. Startup logs proving real PQC transport stack and timeout verification

Every live node logged the Required-mode PQC stack, for example V0:

```text
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=7 (root fingerprints: [id=fc4755e2.. suite=100 fp=315eb55a])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
[binary] Run 033: timeout verification ACTIVE — Arc<TimeoutVerificationContext> threaded into BinaryConsensusLoopIo::verification_ctx. Inbound TimeoutMsg / NewView / TC traffic will be verified before engine ingestion; locally-emitted timeouts will be signed before broadcast. signer_loaded=1 key_provider_loaded=1 validator_count=7
```

This proves `pqc-static-root`, real ML-DSA-44 cert verification, real ML-KEM-768, real ChaCha20-Poly1305, no DummyKem, no DummyAead, and active timeout verification.

## 11. Startup and pre-fault metrics

Representative pre-fault V0 scrape (`/tmp/run049-fixed-n7/scrapes/prefault-20260511T184732.064Z-v0.metrics`):

```text
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 12
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_consensus_qcs_formed_total 179
qbind_consensus_view_timeouts_emitted_total 1
qbind_consensus_timeout_certificates_formed_total 1
qbind_consensus_view_timeout_advances_total 1
qbind_consensus_inbound_timeout_verify_accepted_total 4
qbind_consensus_inbound_timeout_verify_rejected_total 0
qbind_consensus_inbound_newview_verify_accepted_total 4
qbind_consensus_inbound_newview_verify_rejected_total 0
qbind_consensus_outbound_timeout_signing_success_total 1
qbind_consensus_outbound_timeout_signing_failure_total 0
qbind_consensus_view_advances_due_to_verified_tc_total 1
qbind_consensus_view_timeout_current_threshold_ticks 50
qbind_consensus_view_timeout_backoff_level 0
qbind_consensus_view_timeout_backoff_resets_total 1
qbind_consensus_view_timeout_backoff_increases_total 1
qbind_consensus_view_timeout_max_cap_hits_total 0
qbind_consensus_committed_height 54
qbind_consensus_current_view 63
```

The startup-time view-0 timeout was already reset to base by committed-height progress before the fault; the post-fault cap proof below is independent.

## 12. Fault/no-commit-window details

`/tmp/run049-fixed-n7/logs/orchestrate.log`:

```text
[orchestrate] 2026-05-11T18:47:32.109Z SIMULTANEOUS-STOP 1 2
[orchestrate] 2026-05-11T18:47:32.113Z SIGNAL INT V1 pid=30207
[orchestrate] 2026-05-11T18:47:32.116Z SIGNAL INT V2 pid=30247
[orchestrate] 2026-05-11T18:47:33.121Z fast scrape start count=960 sleep=0.25
[orchestrate] 2026-05-11T18:50:12.625Z early success condition met at fast-560 (V0 threshold=800 cap_hits>=2)
```

The fixed script sent SIGINT to process groups (`kill -INT -- -$pid`), so V1/V2 actually stopped. V0 and V6 then remained without committed-height progress long enough to climb from `400` to `800` and to emit again while capped.

## 13. High-frequency scrape method

Warmup: 12 full-fleet scrapes, approximately every 1.2 s. Post-fault: full live-node scrapes every 250 ms for up to 960 iterations. The run stopped early at `fast-560` after the success condition `threshold=800` and `cap_hits>=2` was observed on V0, then captured a final full live-node scrape. Total metric files under `/tmp/run049-fixed-n7/scrapes`: 2901.

## 14. Pre-cap timeout schedule proof

V0 live log:

```text
[binary-consensus] B14: emitted TimeoutMsg for view=64 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
[binary-consensus] B14: emitted TimeoutMsg for view=65 after 100 ticks of no progress (Run 046 pacer: threshold=100 ticks, level=2, next_threshold=200 ticks)
[binary-consensus] B14: emitted TimeoutMsg for view=71 after 200 ticks of no progress (Run 046 pacer: threshold=200 ticks, level=3, next_threshold=400 ticks)
[binary-consensus] B14: emitted TimeoutMsg for view=72 after 400 ticks of no progress (Run 046 pacer: threshold=400 ticks, level=4, next_threshold=800 ticks)
```

V6 independently logged the same pre-cap thresholds for views 64, 65, 71, and 72.

Metrics transition trail on V0:

| Scrape | Threshold | Level | Increases | Cap hits | Timeouts | Committed height | Current view |
|---|---:|---:|---:|---:|---:|---:|---:|
| `fast-0000-v0` | 50 | 0 | 1 | 0 | 1 | 54 | 64 |
| `fast-0015-v0` | 100 | 1 | 2 | 0 | 2 | 54 | 65 |
| `fast-0050-v0` | 200 | 2 | 3 | 0 | 3 | 54 | 65 |
| `fast-0126-v0` | 400 | 3 | 4 | 0 | 4 | 54 | 72 |

Metrics transition trail on V6:

| Scrape | Threshold | Level | Increases | Cap hits | Timeouts | Committed height | Current view |
|---|---:|---:|---:|---:|---:|---:|---:|
| `fast-0000-v6` | 50 | 0 | 0 | 0 | 0 | 49 | 64 |
| `fast-0015-v6` | 100 | 1 | 1 | 0 | 1 | 49 | 65 |
| `fast-0051-v6` | 200 | 2 | 2 | 0 | 2 | 49 | 66 |
| `fast-0125-v6` | 400 | 3 | 3 | 0 | 3 | 49 | 71 |

The committed-height gauges stayed constant for the cap witnesses across the pre-cap climb, so view-only progress did not reset the pacer.

## 15. 800-cap-hit proof

V0 live log:

```text
[binary-consensus] B14: emitted TimeoutMsg for view=78 after 800 ticks of no progress (Run 046 pacer: threshold=800 ticks, level=4, next_threshold=800 ticks)
```

V6 live log:

```text
[binary-consensus] B14: emitted TimeoutMsg for view=78 after 800 ticks of no progress (Run 046 pacer: threshold=800 ticks, level=4, next_threshold=800 ticks)
```

V0 metrics prove cap arrival and capped re-emission:

| Scrape | Threshold | Level | Increases | Cap hits | Timeouts | Signing success | Committed height | Current view |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `fast-0267-v0` | 800 | 4 | 5 | 1 | 5 | 5 | 54 | 74 |
| `fast-0552-v0` | 800 | 4 | 5 | 2 | 6 | 6 | 54 | 79 |
| final V0 | 800 | 4 | 5 | 2 | 6 | 6 | 54 | 79 |

V6 metrics prove the same cap behavior independently:

| Scrape | Threshold | Level | Increases | Cap hits | Timeouts | Signing success | Committed height | Current view |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `fast-0266-v6` | 800 | 4 | 4 | 1 | 4 | 4 | 49 | 72 |
| `fast-0551-v6` | 800 | 4 | 4 | 2 | 5 | 5 | 49 | 78 |
| final V6 | 800 | 4 | 4 | 2 | 5 | 5 | 49 | 79 |

Run 046 semantics match exactly: cap hit `0 → 1` occurs when growth from `400` lands on/saturates at `800`; `backoff_increases_total` increments for real threshold raises and stays unchanged for the already-at-cap attempt; cap hit `1 → 2` occurs only when a later successful local timeout emission attempts to grow while already saturated; `current_threshold_ticks` remains `800`, never above cap.

A repository-wide scrape check found `0` samples with `qbind_consensus_view_timeout_current_threshold_ticks > 800` and `0` samples where `max_cap_hits_total > 0` while threshold was below `800`.

## 16. B14 recovery and verification preservation

Final metrics show timeout signing, verified timeout/NewView traffic, TC formation, and view advancement stayed active under honest traffic.

V0 final scrape:

```text
qbind_consensus_view_timeouts_emitted_total 6
qbind_consensus_timeout_certificates_formed_total 5
qbind_consensus_view_timeout_advances_total 6
qbind_consensus_inbound_timeout_verify_accepted_total 24
qbind_consensus_inbound_timeout_verify_rejected_total 0
qbind_consensus_inbound_newview_verify_accepted_total 16
qbind_consensus_inbound_newview_verify_rejected_total 0
qbind_consensus_outbound_timeout_signing_success_total 6
qbind_consensus_outbound_timeout_signing_failure_total 0
qbind_consensus_view_advances_due_to_verified_tc_total 6
qbind_consensus_committed_height 54
qbind_consensus_current_view 79
```

V3/V4/V5 recovery witnesses reached committed heights `70`, `40`, and `70` respectively by final scrape while keeping timeout/NewView rejection, decode-failure, and engine-reject counters at zero. V0/V6 are explicitly reported as cap witnesses; they are not overclaimed as the strongest B14 commit-recovery witnesses in this run.

## 17. Negative checks

Observed negative checks:

- no DummySig fallback in startup logs;
- no DummyKem fallback (`dummy_kem_registered=false`);
- no DummyAead fallback (`dummy_aead_registered=false`);
- no `test-grade-dummy-sig` active mode;
- `qbind_p2p_pqc_cert_verify_rejected_total = 0` and every per-reason PQC cert rejection counter = 0 on final live-node scrapes;
- timeout/NewView verification rejections = 0;
- timeout/NewView decode failures = 0;
- timeout/NewView engine rejects = 0;
- outbound timeout signing failures = 0;
- duplicate local timeout per same validator/view check returned no rows;
- threshold-exceeds-800 check returned `0` rows;
- cap-hit-before-threshold-800 check returned `0` rows;
- no panic or FATAL in live-node logs;
- no private-key material logged.

## 18. Remaining open items

Run 049 closes the Run 048 boundary for **live cap-hit behavior at 800 ticks** on the real binary path.

Full C4 remains open for production CA / cert rotation / cert revocation / signed root distribution lifecycle, production fast-sync / consensus-storage restore, and per-environment trust anchors.

C5 remains open / not claimed closed. Run 049 does not change transport-root lifecycle policy, forged-traffic policy, KEMTLS wire formats, timeout/NewView wire formats, or any signature/verification semantics.

## 19. Exact immediate next action

Proceed to the next C4 open item: production CA / certificate rotation / revocation / signed root distribution design-and-evidence, while preserving the Run 037–049 Required-mode PQC transport and timeout-verification stack.