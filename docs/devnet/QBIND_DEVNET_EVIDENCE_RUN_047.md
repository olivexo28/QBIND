# QBIND DevNet Evidence — Run 047

## 1. Exact objective

Execute live N=4 Required-mode real-binary evidence for the Run 046 bounded exponential-backoff timeout pacer, while preserving B14 recovery liveness, active timeout verification, and the current PQC transport stack:

- `--p2p-mutual-auth required`
- `--p2p-pqc-root-mode pqc-static-root`
- real ML-DSA-44 transport delegation certs
- real ML-KEM-768 transport KEM
- real ChaCha20-Poly1305 transport AEAD
- `--require-timeout-verification`
- four ML-DSA-44 consensus signer keystores
- metrics enabled on every node through `QBIND_METRICS_HTTP_ADDR`

No QBIND Rust source code was modified. Run 047 is an evidence/documentation run.

## 2. Exact verdict

**PARTIAL POSITIVE.**

Fresh N=4 Required-mode real-binary evidence proves that the Run 046 pacer moves truthfully on live binaries for the base-to-increase-and-reset path:

- startup `/metrics` showed `qbind_consensus_view_timeout_current_threshold_ticks 50`, `backoff_level 0`, `backoff_increases_total 0`, `max_cap_hits_total 0` on every node;
- after V1A was stopped, live logs on V0/V2A/V3A showed local `TimeoutMsg` emission after exactly `50` ticks of no progress;
- the emitted-timeout log line reported `threshold=50 ticks, level=1, next_threshold=100 ticks`;
- high-frequency live scrapes captured `qbind_consensus_view_timeout_current_threshold_ticks 100` and `qbind_consensus_view_timeout_backoff_level 1` after successful local timeout emission;
- committed-height progress then reset the live threshold to `50` and level to `0`, with `qbind_consensus_view_timeout_backoff_resets_total` incrementing only after non-zero backoff;
- B14 recovery remained live: TCs formed, verified NewViews advanced views, committed height advanced, timeout verification stayed active, and all required deterministic regressions passed;
- no DummySig, DummyKem, DummyAead, timeout-verification rejection, NewView rejection, decode failure, engine reject, invalid vote spike, proposal-rejection spike, panic, or FATAL line appeared in the honest run logs.

Boundary: the live topology did **not** prove a later local timeout emitted at `100` ticks or `200` ticks, because normal B14 recovery committed between absent-V1A windows and reset the pacer to base before the next absent-leader timeout. Cap-hit remains deterministic-test-only evidence. Full C4 and C5 remain open.

## 3. Exact files changed

| File | Change |
|---|---|
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_047.md` | New evidence document. |
| `docs/whitepaper/contradiction.md` | Appended Run 047 C4 narrowing paragraph; full C4/C5 remain open. |

## 4. Binary identity

Repository path: `/home/runner/work/QBIND/QBIND`

| Field | Value |
|---|---|
| Branch | `copilot/continue-qbind-development-4d03ad79-e3b8-4cd8-85ed-8a80fe3bdfd9` |
| Commit | `b29dbca50f6e8b603b3a057b483b82be7298dd8b` |
| Working tree before evidence doc edits | clean (`git status --porcelain` count `0`) |
| `qbind-node` | `/home/runner/work/QBIND/QBIND/target/release/qbind-node` |
| `qbind-node` sha256 | `561e9f83c0a1ed447fbf75fafd19f60767e396806f3fe32e9603a9b0947f8948` |
| `qbind-node` ELF BuildID | `42c6e7c7f6e6a23d49de2152984a77b2214d177a` |
| `devnet_pqc_root_helper` | `/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper` |
| helper sha256 | `f68f1276ff1f581faed4c11edf2158bbc2bfea80ddd6abefe9219125898efba5` |
| helper ELF BuildID | `d060c1a75f87e13a390876524b3922594f6e1a56` |

CLI help check:

- present: `--p2p-mutual-auth`, `--p2p-pqc-root-mode`, `--p2p-trusted-root`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert`, `--signer-keystore-path`, `--validator-consensus-key`, `--data-dir`, `--execution-profile`, `--require-timeout-verification`;
- `--devnet-forged-inject` hidden from normal help (`grep -c == 0`);
- no dedicated `--metrics` CLI flag is exposed on this binary; metrics HTTP remains enabled by the existing `QBIND_METRICS_HTTP_ADDR` environment variable, as used by prior runs and by Run 047.

## 5. Exact commands run

```bash
cd /home/runner/work/QBIND/QBIND
git --no-pager status --short
git --no-pager branch --show-current
git --no-pager rev-parse HEAD
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
sha256sum target/release/qbind-node target/release/examples/devnet_pqc_root_helper
readelf -n target/release/qbind-node | sed -n '/Build ID/p'
readelf -n target/release/examples/devnet_pqc_root_helper | sed -n '/Build ID/p'
./target/release/qbind-node --help > /tmp/run047-help.txt
```

Material generation and live evidence scripts were kept outside the repository:

```bash
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper /tmp/run047-mat 4
cd /tmp/run047-keygen && cargo build --release
/tmp/run047-keygen/target/release/keygen /tmp/run047/keystores 4
/tmp/run047/orchestrate.sh
/tmp/run047b/orchestrate_fast.sh
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

## 6. Transport material procedure

Command:

```bash
/home/runner/work/QBIND/QBIND/target/release/examples/devnet_pqc_root_helper /tmp/run047-mat 4
```

Safe helper output:

```text
[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id=74803607a07c86e577c06a5abe87295ca6cc876e8162f380585f608a022c7dd1 sig_suite=100 kem_suite=100 kem=ml-kem-768 validators=4 validity_mode=currently-valid outdir=/tmp/run047-mat
[devnet_pqc_root_helper] root_sk was held in memory only; never written to disk.
```

Safe metadata:

| Item | Value |
|---|---|
| Root ID prefix | `74803607` |
| Sig suite ID | `100` |
| KEM suite ID | `100` (`ml-kem-768`) |
| Root public-key SHA-256 fp | `5564a252` |
| Cert sizes | `v0..v3.cert.bin = 3696 bytes` each |
| KEM secret-key sizes/modes | `v0..v3.kem.sk.bin = 2400 bytes`, mode `0o600` |

Every node used one shared trusted root (`--p2p-trusted-root ROOTID:100:ROOTPK`), its own leaf cert and leaf KEM secret, and all four `--p2p-peer-leaf-cert VID:PATH` entries. No root signing key, KEM secret key, shared secret, AEAD key, or plaintext secret was logged.

## 7. Consensus timeout-verification material procedure

An out-of-tree `/tmp/run047-keygen` helper generated four ML-DSA-44 consensus signer keystores using `fips204::ml_dsa_44::try_keygen()`. The helper wrote `LocalKeystorePlain` JSON files only under `/tmp/run047/keystores/v{N}/validator-{N}.json` with mode `0o600`.

Keystore stats:

```text
600 /tmp/run047/keystores/v0/validator-0.json 5157
600 /tmp/run047/keystores/v1/validator-1.json 5157
600 /tmp/run047/keystores/v2/validator-2.json 5157
600 /tmp/run047/keystores/v3/validator-3.json 5157
```

Public-key fingerprints only:

| Validator | Suite | Public-key SHA-256 fp |
|---|---:|---|
| V0 | 100 | `dc01d8ce` |
| V1A | 100 | `b0312367` |
| V2A | 100 | `1c989ed0` |
| V3A | 100 | `55243200` |

All four `--validator-consensus-key VID:100:HEXPK` entries were supplied to every node. Secret keys remained only inside the 0o600 keystore files and were not logged.

## 8. Topology

| Node | Validator ID | Listen | Metrics | Data dir | Keystore | Fault role |
|---|---:|---|---|---|---|---|
| V0 | 0 | `127.0.0.1:39250` / fast rerun `39350` | `127.0.0.1:39200` / fast `39300` | `/tmp/run047/data/v0` / `/tmp/run047b/data/v0` | `/tmp/run047/keystores/v0` | live throughout |
| V1A | 1 | `127.0.0.1:39251` / fast `39351` | `127.0.0.1:39201` / fast `39301` | `/tmp/run047/data/v1a` / `/tmp/run047b/data/v1a` | `/tmp/run047/keystores/v1` | stopped with SIGINT |
| V2A | 2 | `127.0.0.1:39252` / fast `39352` | `127.0.0.1:39202` / fast `39302` | `/tmp/run047/data/v2a` / `/tmp/run047b/data/v2a` | `/tmp/run047/keystores/v2` | live throughout |
| V3A | 3 | `127.0.0.1:39253` / fast `39353` | `127.0.0.1:39203` / fast `39303` | `/tmp/run047/data/v3a` / `/tmp/run047b/data/v3a` | `/tmp/run047/keystores/v3` | live throughout |

Per-node launch shape:

```bash
QBIND_METRICS_HTTP_ADDR="127.0.0.1:${METRICS}" \
setsid /home/runner/work/QBIND/QBIND/target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr "127.0.0.1:${LISTEN}" \
  --p2p-peer "PEER_VID@127.0.0.1:PEER_PORT" ... \
  --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "${TRUSTED_ROOT_SPEC}" \
  --p2p-leaf-cert "/tmp/run047-mat/v${VID}.cert.bin" \
  --p2p-leaf-cert-key "/tmp/run047-mat/v${VID}.kem.sk.bin" \
  --p2p-peer-leaf-cert "0:/tmp/run047-mat/v0.cert.bin" \
  --p2p-peer-leaf-cert "1:/tmp/run047-mat/v1.cert.bin" \
  --p2p-peer-leaf-cert "2:/tmp/run047-mat/v2.cert.bin" \
  --p2p-peer-leaf-cert "3:/tmp/run047-mat/v3.cert.bin" \
  --execution-profile vm-v0 \
  --require-timeout-verification \
  --signer-keystore-path "/tmp/run047/keystores/v${VID}" \
  --validator-consensus-key "0:100:${V0_PK}" \
  --validator-consensus-key "1:100:${V1_PK}" \
  --validator-consensus-key "2:100:${V2_PK}" \
  --validator-consensus-key "3:100:${V3_PK}" \
  --validator-id "${VID}" \
  --data-dir "${DATA_DIR}"
```

## 9. Startup logs proving real PQC transport stack and timeout verification

Every node logged:

```text
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=4 (root fingerprints: [id=74803607.. suite=100 fp=fe344222])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
[binary] Run 033: timeout verification ACTIVE — Arc<TimeoutVerificationContext> threaded into BinaryConsensusLoopIo::verification_ctx. Inbound TimeoutMsg / NewView / TC traffic will be verified before engine ingestion; locally-emitted timeouts will be signed before broadcast. signer_loaded=1 key_provider_loaded=1 validator_count=4
```

V0 also logged:

```text
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=3, proposal_reemits_total=1, vote_reemits_total=1)
```

The B9+B10 line is gated on mutual-auth-complete peer connectivity and proves all three peers reached the verified cert-derived transport identity path.

## 10. Startup and pre-fault metrics

Initial Run 047 startup scrape (`/tmp/run047/scrapes/startup-*`):

| Node | committed_height | current_view | qcs_formed_total | threshold | level | resets | increases | cap_hits | timeout verification |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---|
| V0 | 56 | 59 | 114 | 50 | 0 | 0 | 0 | 0 | active/signer/key-provider=1, validators=4 |
| V2A | 56 | 59 | 118 | 50 | 0 | 0 | 0 | 0 | active/signer/key-provider=1, validators=4 |
| V3A | 56 | 59 | 118 | 50 | 0 | 0 | 0 | 0 | active/signer/key-provider=1, validators=4 |

Pre-fault scrape (`/tmp/run047/scrapes/prefault-*`):

| Node | committed_height | current_view | qcs_formed_total | timeouts | threshold | level | resets | increases | cap_hits |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| V0 | 105 | 108 | 210 | 0 | 50 | 0 | 0 | 0 | 0 |
| V2A | 105 | 108 | 215 | 0 | 50 | 0 | 0 | 0 | 0 |
| V3A | 105 | 108 | 216 | 0 | 50 | 0 | 0 | 0 | 0 |

PQC cert metrics were live: `qbind_p2p_pqc_root_mode 1`, `qbind_p2p_pqc_roots_configured 1`, `qbind_p2p_pqc_cert_verify_accepted_total 6`, `qbind_p2p_pqc_cert_verify_rejected_total 0` on live nodes.

## 11. Fault details and absent-leader views

Initial run fault:

```text
2026-05-11T17:26:45Z SIGNAL INT v1a pid=11377
```

High-frequency confirmation run fault:

```text
2026-05-11T17:29:21.212Z SIGNAL INT v1a pid=12031
```

V1A leads round-robin views where `view % 4 == 1`. In the high-frequency run, after prefault `current_view=80`, the stopped validator led absent views `81`, `85`, `89`, and `93`.

## 12. Mid-fault and post-recovery evidence

Initial run mid/post metrics showed repeated recovery cycles:

| Scrape | Node | committed_height | current_view | timeouts | TCs | timeout advances | verified-TC advances | threshold | level | resets | increases | cap_hits |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| fault+6s | V0 | 109 | 113 | 1 | 1 | 1 | 1 | 50 | 0 | 1 | 1 | 0 |
| fault+6s | V2A | 109 | 113 | 1 | 0 | 1 | 1 | 50 | 0 | 1 | 1 | 0 |
| fault+6s | V3A | 109 | 113 | 1 | 1 | 1 | 1 | 50 | 0 | 1 | 1 | 0 |
| fault+12s | V0 | 112 | 117 | 2 | 2 | 2 | 2 | 50 | 0 | 2 | 2 | 0 |
| fault+24s | V0 | 115 | 121 | 3 | 3 | 3 | 3 | 50 | 0 | 3 | 3 | 0 |
| final | V0 | 118 | 125 | 4 | 4 | 4 | 4 | 50 | 0 | 4 | 4 | 0 |

High-frequency scrapes (`/tmp/run047b/scrapes/fast-*`) caught the transient post-timeout increased threshold before commit reset:

| Scrape file | Node | timeouts | threshold | level | resets | increases | committed_height | current_view |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| `fast-24-20260511T172926.443Z-v0.metrics` | V0 | 1 | 100 | 1 | 0 | 1 | 78 | 82 |
| `fast-24-20260511T172926.443Z-v2a.metrics` | V2A | 1 | 100 | 1 | 0 | 1 | 78 | 82 |
| `fast-24-20260511T172926.443Z-v3a.metrics` | V3A | 1 | 100 | 1 | 0 | 1 | 78 | 82 |
| `fast-50-20260511T172932.086Z-v0.metrics` | V0 | 2 | 100 | 1 | 1 | 2 | 81 | 86 |
| `fast-77-20260511T172937.965Z-v0.metrics` | V0 | 3 | 100 | 1 | 2 | 3 | 84 | 90 |
| `final-v0.metrics` | V0 | 4 | 50 | 0 | 4 | 4 | 90 | 97 |

This proves live metric movement `50 -> 100 -> 50` after successful timeout emission and committed-height progress. It does not prove a later local timeout emitted at `100` ticks, because recovery commits reset the pacer before that condition occurs.

## 13. Log proof of base timeout and B14 recovery

Representative high-frequency run lines:

```text
[binary-consensus] B14: emitted TimeoutMsg for view=81 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
[binary-consensus] B14: TimeoutCertificate advanced view 81 -> 82
[binary-consensus] B14: emitted TimeoutMsg for view=85 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
[binary-consensus] B14: TimeoutCertificate advanced view 85 -> 86
[binary-consensus] B14: emitted TimeoutMsg for view=89 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
[binary-consensus] B14: TimeoutCertificate advanced view 89 -> 90
[binary-consensus] B14: emitted TimeoutMsg for view=93 after 50 ticks of no progress (Run 046 pacer: threshold=50 ticks, level=1, next_threshold=100 ticks)
[binary-consensus] B14: TimeoutCertificate advanced view 93 -> 94
```

Signing stayed active and successful on every live node:

```text
[binary-consensus] Run 030: signing timeout view=109 validator=ValidatorId(0) suite_id=100
[binary-consensus] Run 030: timeout signing OK view=109 validator=ValidatorId(0) suite_id=100
```

## 14. Negative checks

Honest run checks:

- no DummySig fallback;
- no DummyKem fallback;
- no DummyAead fallback;
- no `test-grade-dummy-sig` active-mode line;
- no `client handle_server_accept failed`;
- no `server handle_client_init failed`;
- no timeout verification rejection (`inbound_timeout_verify_rejected_total 0` throughout);
- no NewView verification rejection (`inbound_newview_verify_rejected_total 0` throughout);
- no timeout decode failures;
- no NewView decode failures;
- no timeout engine rejects;
- no NewView engine rejects;
- no invalid vote spike;
- no proposal rejection spike;
- no process crash, panic, or FATAL;
- no cap-hit (`qbind_consensus_view_timeout_max_cap_hits_total 0`) because threshold never reached 800 live;
- no private key material in node logs.

Duplicate local timeout emissions were not observed: each live validator emitted one local timeout per absent V1A-led view in the run logs (`81`, `85`, `89`, `93` in the high-frequency run; `109`, `113`, `117`, `121` in the first run).

## 15. Tests and pass/fail status

| Command | Result |
|---|---|
| `cargo test -p qbind-node --lib binary_consensus` | PASS — 63 passed |
| `cargo test -p qbind-node --lib metrics` | PASS — 102 passed |
| `cargo test -p qbind-node --lib forged_injection` | PASS — 21 passed |
| `cargo test -p qbind-node --lib run030` | PASS — 20 passed |
| `cargo test -p qbind-node --test t146_timeout_view_change_tests` | PASS — 15 passed |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | PASS — 12 passed |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | PASS — 14 passed |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | PASS — 10 passed |
| `cargo test -p qbind-node --lib` | PASS — 791 passed |
| `cargo test -p qbind-consensus --lib timeout` | PASS — 54 passed |
| `cargo test -p qbind-crypto --lib` | PASS — 68 passed |
| `cargo test -p qbind-net --lib` | PASS — 17 passed |
| `cargo build --release -p qbind-node --bin qbind-node` | PASS |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | PASS |

## 16. Remaining open items

Run 047 does not solve or claim:

- production CA;
- cert rotation;
- cert revocation;
- signed root distribution;
- production fast-sync / consensus-storage restore;
- per-environment trust anchors;
- live cap-hit evidence at 800 ticks;
- live evidence of a subsequent local timeout emitted at `100` or `200` ticks under consecutive no-commit timeout windows.

C4 remains open. C5 remains open / narrowed only; Run 047 does not change transport-root lifecycle policy.

## 17. Immediate next action

If operators require strongest-positive live backoff timing evidence beyond base-to-100-and-reset, run the smallest safe topology that creates consecutive no-commit timeout windows while retaining a quorum capable of producing verified timeout certificates, then capture high-frequency `/metrics` scrapes proving a local timeout emitted at the increased `100`-tick threshold and, if feasible, `200` ticks. Do not alter timeout verification, B14 wire formats, KEMTLS, or certificate lifecycle to force that evidence.