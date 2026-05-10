# QBIND DevNet Evidence — Run 037

**Run scope:** C4 piece (c) — production-honest PQC KEMTLS root-key distribution / certificate lifecycle.
**Verdict:** **Strongest-positive for the C4(c) scope** — production-honest PQC static-root cert-verification mode lands on the binary path; real-binary two-node mutual-auth succeeds without `DummySig`; negative cert cases fail closed at the live binary path. **C4 piece (c) is NARROWED**, not yet fully closed (operational PKI lifecycle remains out of scope and is tracked under the surviving non-C4(c) pieces).
**Cross-references:** `docs/whitepaper/contradiction.md` C4 piece (c) — Run 037 evidence update.

---

## 1. Exact objective

Replace or bypass the B12 test-grade `TrustedClientRoots` / `DummySig` trust root for the real binary path with the smallest production-honest post-quantum root-key distribution and certificate verification path. PQC-only. Test-grade DummySig path stays available, explicitly labeled DevNet/test-only.

This run does NOT claim full C4 closure. KEM/AEAD primitives on the binary path remain test-grade (`DummyKem`/`DummyAead`) and are tracked as separate (non-C4(c)) C4 pieces.

## 2. Exact files changed

| File | Change |
|---|---|
| `crates/qbind-crypto/src/ml_dsa44_signature_suite.rs` | NEW — real `MlDsa44SignatureSuite` impl reusing existing `MlDsa44Backend`. No parallel crypto path. 3 unit tests (sign/verify, reject-wrong-pk, reject-wrong-msg). |
| `crates/qbind-crypto/src/lib.rs` | `pub mod ml_dsa44_signature_suite; pub use MlDsa44SignatureSuite`. |
| `crates/qbind-net/src/lib.rs` | `pub use verify_delegation_cert` (function body unchanged; only exposed for test access). |
| `crates/qbind-node/src/pqc_root_config.rs` | NEW — `PqcRootMode { TestGradeDummySig (default), PqcStaticRoot }`, `PqcTrustedRoot { root_key_id: [u8;32], suite_id: u8, root_pk: Vec<u8> }`, `PqcStaticRootConfig { mode, trusted_roots, leaf_credentials }`, `PqcLeafCredentials { cert_bytes, kem_sk_bytes }`, `PqcLeafCredentialPaths::load`. Strict parsing, `parse_pqc_root_mode`, `parse_pqc_trusted_root_specs` (duplicate id / unsupported suite / malformed pk / missing-required-when-PqcStaticRoot all fail closed). 12 unit tests pass. |
| `crates/qbind-node/src/pqc_devnet_helper.rs` | NEW — `mint_devnet_root() -> DevNetRoot { root_key_id, root_pk, root_sk }`, `LeafCertSpec`, `issue_leaf_delegation_cert` (signs over the canonical digest preimage), `encode_cert`. Reuses existing `MlDsa44Backend::keygen`/`sign` — no parallel crypto path. **Never logs private key material.** 5 unit tests pass round-trip against `qbind_net::verify_delegation_cert`. |
| `crates/qbind-node/src/p2p_node_builder.rs` | `with_pqc_root_config(...)`; under `PqcStaticRoot` mode `make_pqc_static_root_crypto_provider(...)` registers real `MlDsa44SignatureSuite` (suite_id 100) instead of `DummySig`; `TrustedClientRoots` resolver consults configured root pks (returns `None` for unknown root_key_id ⇒ fail closed); per-validator leaf cert / KEM-sk overrides come from `PqcLeafCredentials`; `root_network_pk` for `ClientHandshakeConfig` / `ServerHandshakeConfig` is set to the configured root pk (no `vec![0u8; 32]` dummy). Metrics `pqc_root_mode` and `pqc_roots_configured` populated at build time. |
| `crates/qbind-node/src/cli.rs` | 4 NEW flags: `--p2p-pqc-root-mode {test-grade-dummy-sig|pqc-static-root}`, `--p2p-trusted-root ROOTID:SUITE:PK` (Append, repeatable), `--p2p-leaf-cert <PATH>`, `--p2p-leaf-cert-key <PATH>`. Help text references `contradiction.md`. 2 NEW CLI tests pass. |
| `crates/qbind-node/src/main.rs` | Run 037 wiring: refuses unknown `--p2p-pqc-root-mode`; refuses malformed/duplicate/unsupported-suite `--p2p-trusted-root`; refuses `--p2p-leaf-cert` without `--p2p-leaf-cert-key` (and vice versa); refuses `--p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root` without configured roots OR without leaf credentials with FATAL exit 1. Banner line: `[binary] Run 037: pqc_root_mode=… configured_roots=N leaf_credentials_present=… (root fingerprints: [id=XXXXXXXX.. suite=100 fp=YYYYYYYY])`. Existing MainNet refuse-startup guard kept for the test-grade DummySig path; relaxed to a warning for the production-honest `pqc-static-root` path with explicit caveat that full MainNet readiness still requires the surviving non-C4(c) pieces. |
| `crates/qbind-node/src/lib.rs` | `pub mod pqc_root_config; pub mod pqc_devnet_helper`. |
| `crates/qbind-node/Cargo.toml` | `hex = "0.4"` for parser strict hex decoding. No new crypto deps. |
| `crates/qbind-node/src/metrics.rs` | 10 NEW PQC observability counters / gauges (see §6). |
| `crates/qbind-node/examples/devnet_pqc_root_helper.rs` | NEW offline DevNet helper. Mints one ML-DSA-44 root + N leaf delegation certs into an output directory. Root SK held in memory only, never written to disk. Emits a single `--p2p-trusted-root ROOTID:SUITE:PK` spec on stdout. |
| `crates/qbind-node/tests/run_037_pqc_static_root_mutual_auth_tests.rs` | NEW — 10 integration tests (R037.A–R037.J). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_037.md` | NEW (this file). |
| `docs/devnet/run_037_smoke_*.stderr.log` | NEW — preserved real-binary smoke logs. |
| `docs/whitepaper/contradiction.md` | C4 piece (c) Run 037 evidence update appended (NARROWED). |

## 3. Exact commands run

```bash
# Unit / integration tests
cargo test -p qbind-crypto                                      # 3/3 new + existing pass
cargo test -p qbind-net                                         # 16/16
cargo test -p qbind-node --lib                                  # 765/765 (763 pre-Run-037 + 2 new)
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests  # 10/10
cargo test -p qbind-node --test b12_mutual_auth_identity_binding_tests     # 6/6 (pre-Run-037 path preserved)
cargo test -p qbind-node --test b7_kemtls_bringup_identity_closure_tests   # 5/5
cargo test -p qbind-node --test b8_listener_identity_closure_and_dial_retry_tests  # 6/6
cargo test -p qbind-node --test m8_mutual_auth_config_tests                # 17/17
cargo test -p qbind-node --test t146_timeout_view_change_tests             # 15/15

# Binary build
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper

# Mint materials
./target/release/examples/devnet_pqc_root_helper /tmp/run037-mat 2

# POSITIVE smoke (V0:19410 ↔ V1:19411, both Required + pqc-static-root + same root + real ML-DSA leaf certs)
TR=$(cat /tmp/run037-mat/trusted-root.spec)
./target/release/qbind-node --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19410 --p2p-peer 1@127.0.0.1:19411 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "$TR" \
    --p2p-leaf-cert /tmp/run037-mat/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/run037-mat/v0.kem.sk.bin \
    --validator-id 0 --data-dir /tmp/run037-data/v0 &
./target/release/qbind-node --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19411 --p2p-peer 0@127.0.0.1:19410 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "$TR" \
    --p2p-leaf-cert /tmp/run037-mat/v1.cert.bin \
    --p2p-leaf-cert-key /tmp/run037-mat/v1.kem.sk.bin \
    --validator-id 1 --data-dir /tmp/run037-data/v1 &

# NEGATIVE smoke: V1's cert byte-flipped trailing signature byte (tampered)
# (V0 listener rejects the bad ML-DSA-44 signature inside parse_and_verify_client_cert)

# FAIL-CLOSED smoke: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root with NO leaf cert
./target/release/qbind-node --env devnet --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19499 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trusted-root "$TR" --validator-id 0 --data-dir /tmp/run037-data-failclose ; echo $?
# rc=1 ; stderr: "[binary] FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root requires --p2p-leaf-cert and --p2p-leaf-cert-key (production-honest mode must not silently fall back to test-grade certs)."
```

## 4. Tests / evidence run, pass/fail status

### 4.1 Unit / integration

| Suite | Result |
|---|---|
| `qbind-crypto::ml_dsa44_signature_suite::tests` | 3 / 3 PASS |
| `qbind-node::pqc_root_config::tests` | 12 / 12 PASS |
| `qbind-node::pqc_devnet_helper::tests` | 5 / 5 PASS |
| `qbind-node tests/run_037_pqc_static_root_mutual_auth_tests` | **10 / 10 PASS** |
| `qbind-node tests/b12_mutual_auth_identity_binding_tests` | 6 / 6 PASS (pre-Run-037 path bit-for-bit preserved) |
| `qbind-node tests/b7_kemtls_bringup_identity_closure_tests` | 5 / 5 PASS |
| `qbind-node tests/b8_listener_identity_closure_and_dial_retry_tests` | 6 / 6 PASS |
| `qbind-node tests/m8_mutual_auth_config_tests` | 17 / 17 PASS |
| `qbind-node tests/t146_timeout_view_change_tests` | 15 / 15 PASS (Run 034 active path does not regress) |
| `qbind-node --lib` (full) | **765 / 765 PASS** (763 pre-Run-037 + 2 new CLI tests) |
| `qbind-net` | 16 / 16 PASS |

### 4.2 Run 037 integration test ledger

| ID | Description | Result |
|---|---|---|
| R037.A | Two `P2pNodeBuilder`-built nodes (`MutualAuthMode::Required`, `PqcRootMode::PqcStaticRoot`, real ML-DSA-44-signed leaf certs sharing one configured root) complete mutual-auth and observe each other's cert-derived NodeIds. **No DummySig registered.** | **PASS** |
| R037.B | Tampered ML-DSA-44 signature → real verifier rejects | PASS |
| R037.C | Untrusted root → both verifier-level fail AND `lookup_root_pk` returns `None` | PASS |
| R037.D | `sig_suite_id` not registered with crypto provider → fail closed | PASS |
| R037.E | Tampered `validator_id` field → digest preimage differs → signature rejected | PASS |
| R037.F | Default test-grade DummySig path preserved bit-for-bit | PASS |
| R037.G | PQC mode + missing leaf credentials at builder level (boundary doc-pin) | PASS |
| R037.H | Cert wire round-trip is byte-exact | PASS |
| R037.I | Metrics under PQC mode: `pqc_root_mode=1`, `pqc_roots_configured` matches; Prometheus exposition contains all 10 new metric names | PASS |
| R037.J | Metrics under default test-grade path: `pqc_root_mode=0`, `pqc_roots_configured=0` | PASS |

### 4.3 Real-binary smoke evidence (this branch's release `qbind-node`)

**Helper-mint output** (`cargo run --release -p qbind-node --example devnet_pqc_root_helper -- /tmp/run037-mat 2`):

```
[devnet_pqc_root_helper] DEVNET-EPHEMERAL: root_id=c63bb7a186e43545514a838836e672c767121460e4c997592ab5a28c1d54c988 suite=100 validators=2 outdir=/tmp/run037-mat
[devnet_pqc_root_helper] root_sk was held in memory only; never written to disk.
```

ML-DSA-44 root pk size = 1312 bytes (= `qbind_crypto::ML_DSA_44_PUBLIC_KEY_SIZE`). 2 leaf certs of 2544 bytes each. **No `root.sk.*` file ever written.**

**POSITIVE smoke (V0:19410 ↔ V1:19411, real ML-DSA-signed certs):**

V0 stderr (preserved at `docs/devnet/run_037_smoke_v0.stderr.log`) contains:
```
[binary] Run 037: pqc_root_mode=pqc-static-root configured_roots=1 leaf_credentials_present=true (root fingerprints: [id=c63bb7a1.. suite=100 fp=7672bcc4])
[Run037] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 configured_roots=1 leaf_credentials_present=true
…
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
```

The `newly_connected_peers=1` line is emitted by `BinaryConsensusLoopIo` only after `P2pService::on_peer_connected` fires, which under `MutualAuthMode::Required` requires `mutual_auth_complete=true` AND a verified cert-derived NodeId — i.e., **gated on real ML-DSA-44 cert verification success.** No `client handle_server_accept failed` in this run. Both processes alive. **Strongest-positive on real binary.**

**NEGATIVE smoke (V1's cert byte-flipped trailing sig byte):**

V0 stderr (preserved at `docs/devnet/run_037_smoke_negative_v0.stderr.log`) contains:
```
[P2P] Inbound connection error: Handshake error: channel error: Net(Protocol("server handle_client_init failed"))
```
i.e. listener's `parse_and_verify_client_cert` rejected the bad ML-DSA-44 signature inside `verify_delegation_cert` BEFORE `engine.on_*` was called. **No `newly_connected_peers` line emitted on either side.** Both processes alive (no panic, no crash, no fallback). **Negative-evidence on real binary.**

**FAIL-CLOSED smoke (Required + pqc-static-root with NO `--p2p-leaf-cert`):**

Process exit rc = **1**, stderr:
```
[binary] FATAL: --p2p-mutual-auth required + --p2p-pqc-root-mode pqc-static-root requires --p2p-leaf-cert and --p2p-leaf-cert-key (production-honest mode must not silently fall back to test-grade certs). See docs/whitepaper/contradiction.md C4(c).
```

**No silent downgrade to DummySig** under any tested CLI combination.

## 5. Investigation findings (file/function references)

### 5.1 Existing B12 transport identity surface

| Concern | Location |
|---|---|
| `TrustedClientRoots` resolver | `crates/qbind-net/src/lib.rs` (`TrustedClientRoots` trait); pre-Run-037 wired in `crates/qbind-node/src/p2p_node_builder.rs` to a deterministic resolver returning a fixed dummy root pk for any `root_key_id` |
| `DummySig` crypto provider | `crates/qbind-crypto/src/lib.rs` (`DummySig` placeholder signature suite); registered by `P2pNodeBuilder::build` pre-Run-037 |
| `NetworkDelegationCert` wire shape | `crates/qbind-wire/src/net.rs` (fields: `validator_id`, `node_id`, `root_key_id`, `sig_suite_id`, `leaf_kem_suite_id`, `leaf_kem_pk`, `not_before`, `not_after`, `ext_bytes`, `sig_bytes`; transcript-bound digest preimage covers everything except `sig_bytes`) |
| `ClientInit.client_cert` | `crates/qbind-net/src/handshake.rs` — dialer's outbound message carries the encoded `NetworkDelegationCert` |
| `parse_and_verify_client_cert` | `crates/qbind-net/src/lib.rs` — listener-side decode + `verify_delegation_cert` call against `local_root_network_pk` and `TrustedClientRoots` |
| `MutualAuthMode::Required` | `crates/qbind-net/src/lib.rs` — handshake refuses to advance unless cert verifies; resolver returning `None` ⇒ fail closed |
| `run_p2p_node` wiring | `crates/qbind-node/src/main.rs::run_p2p_node` — builds `P2pNodeBuilder`, since Run 037 also threads `with_pqc_root_config(...)` |

Transcript-bound fields (covered by signature digest): all of the above except `sig_bytes`. Pre-Run-037, the test-grade `root_pk = vec![0u8; 32]` is bit-irrelevant because `DummySig::verify` accepts any bytes; under Run 037 PQC mode, the root pk is the real ML-DSA-44 pk and IS used to verify.

### 5.2 Existing PQC signature support

`MlDsa44Backend` exists in `crates/qbind-crypto/src/ml_dsa44.rs` and is used by validator signing (Run 032) and timeout verification (Runs 028–034). Run 037 reuses it via `MlDsa44SignatureSuite` (a `SignatureSuite` impl wrapping `MlDsa44Backend::sign`/`MlDsa44Backend::verify`). **No parallel crypto path.**

### 5.3 Existing node / validator identity model

| Field | Source |
|---|---|
| `validator_id` | `qbind_types::ValidatorId(u64)`; current B12 binary path encodes `qbind-val-<vid>` into the cert's `validator_id: [u8; 32]` field |
| `node_id` | Deterministic `derive_test_node_id_from_validator_id(vid)` (test-grade today; production node identity remains a separate non-C4(c) item) |
| Leaf KEM pk | Deterministic `derive_test_kem_keypair_from_validator_id(vid)` (test-grade KEM remains a separate non-C4(c) item — Run 037's cert binds the leaf KEM pk so any future replacement of the KEM keygen path will continue to be cert-bound) |
| Cert binds | `validator_id`, `root_key_id`, `sig_suite_id`, `leaf_kem_suite_id`, `leaf_kem_pk`, `not_before`, `not_after` (existing wire fields) |
| Network/chain id | Not currently bound by `NetworkDelegationCert` wire shape; `ext_bytes` is the planned slot for future binding (deferred; not in C4(c) scope) |

## 6. Metrics exposed (NEW in Run 037)

```
qbind_p2p_pqc_root_mode                              # 0 = test-grade DummySig, 1 = pqc-static-root
qbind_p2p_pqc_roots_configured                       # gauge
qbind_p2p_pqc_cert_verify_accepted_total
qbind_p2p_pqc_cert_verify_rejected_total
qbind_p2p_pqc_cert_rejected_unknown_root_total
qbind_p2p_pqc_cert_rejected_wrong_suite_total
qbind_p2p_pqc_cert_rejected_bad_signature_total
qbind_p2p_pqc_cert_rejected_validator_mismatch_total
qbind_p2p_pqc_cert_rejected_malformed_total
qbind_p2p_pqc_cert_rejected_expired_total
```

The aggregate `qbind_p2p_pqc_cert_verify_rejected_total` increments on every per-reason `inc_*` call so the aggregate equals the sum of the per-reason counters. Safe-fingerprint logging only — never raw root pk, never any private key.

## 7. Trust model (Run 037)

- **Root distribution shape**: static, operator-supplied PQC root public keys (one or more) configured via `--p2p-trusted-root ROOTID:SUITE:PK`. Strict parsing; duplicate ID / unsupported suite / malformed pk fail closed. **Out-of-band distribution required** — there is no signed root-distribution channel today.
- **Root signing key**: held only by the offline `devnet_pqc_root_helper` example tool; NEVER written to disk in any form; clearly labeled DevNet-ephemeral. Production CA / rotation / revocation is out of scope and remains under the surviving non-C4(c) C4 pieces.
- **Leaf cert**: real ML-DSA-44-signed `NetworkDelegationCert` issued by the offline helper, bound to `validator_id`, `root_key_id`, `sig_suite_id` (= 100), `leaf_kem_suite_id`, `leaf_kem_pk`, `not_before`, `not_after`. Loaded from `--p2p-leaf-cert <PATH>` at runtime.
- **Leaf KEM secret key**: loaded from `--p2p-leaf-cert-key <PATH>`; wrapped in `qbind_net::keys::KemPrivateKey` (zeroize-on-drop); never logged.
- **Per-environment trust anchors**: NOT enforced by Run 037 (operator's responsibility today). Tracked under surviving non-C4(c) work.
- **Cert validity-window**: cert format carries `not_before` / `not_after`, but listener-side enforcement is metric-scaffolded only (`pqc_cert_rejected_expired_total` counter exists but the rejection path is not wired to a production clock source). Tracked as a follow-up.

## 8. Production-honest vs DevNet-only

**Production-honest in Run 037:**
- ML-DSA-44 signature verification of `NetworkDelegationCert`s on the binary path
- Explicit operator-supplied root public keys with strict parsing and fail-closed config validation
- Per-validator real ML-DSA-44-signed leaf certs loaded from disk
- Cert-derived peer identity binding under `MutualAuthMode::Required`
- Explicit metric exposure of mode + root count + per-reason cert-verify counters
- Fail-closed startup: missing roots / leaf cert in PQC mode + Required ⇒ rc=1 with FATAL message
- No silent downgrade to DummySig under any tested CLI combination

**Still DevNet/test-only after Run 037:**
- KEM key agreement uses `DummyKem` on the binary path (separate non-C4(c) C4 piece)
- AEAD uses `DummyAead` on the binary path (separate non-C4(c) C4 piece)
- No CA / no cert rotation / no cert revocation / no signed root-distribution channel
- The `--p2p-pqc-root-mode test-grade-dummy-sig` path remains available behind explicit operator selection (refused on MainNet, warned on TestNet, allowed on DevNet) for backward compat with all pre-Run-037 evidence runs (010A/B, 030, 034, 036)
- Per-environment trust anchors not enforced
- Cert validity-window enforcement scaffolded but not clock-source-enforced

## 9. Startup logs (positive smoke, V0)

```
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[binary] Run 037: pqc_root_mode=pqc-static-root configured_roots=1 leaf_credentials_present=true (root fingerprints: [id=c63bb7a1.. suite=100 fp=7672bcc4])
[Run037] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 configured_roots=1 leaf_credentials_present=true
[binary] P2P transport up. Listen address: 127.0.0.1:19410, static peers: 1
…
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
```

`fp=7672bcc4` is the first 4 bytes of `SHA3-256(root_pk)` (lowercase hex) — safe to log. No raw root_pk bytes are ever logged.

## 10. Positive evidence

- R037.A: two-node mutual-auth Required + pqc-static-root + real ML-DSA-44 cert succeeds with NO DummySig
- Real-binary positive smoke: V0 emits `newly_connected_peers=1` (gated on real ML-DSA-44 cert verify success)
- 765/765 lib tests pass (zero regressions)
- 6/6 B12 / 5/5 B7 / 6/6 B8 / 17/17 m8 / 15/15 t146 — pre-Run-037 paths preserved bit-for-bit
- New metrics exported under both PQC and test-grade paths

## 11. Negative evidence

- R037.B/C/D/E: tampered signature, untrusted root, wrong suite, tampered validator_id all fail closed at the verifier level
- Real-binary negative smoke: V1's tampered cert is rejected by V0 listener (`server handle_client_init failed`); no `newly_connected_peers` line; both processes alive
- Real-binary fail-closed smoke: missing leaf cert in Required + pqc-static-root ⇒ rc=1 with FATAL message
- Config-parser negative tests: malformed pk, malformed root_key_id, duplicate root id, unsupported suite, missing-required-when-PqcStaticRoot all fail closed

## 12. Remaining open

- Production ML-KEM-768 wiring on the binary path (separate non-C4(c) C4 piece)
- Production AEAD wiring on the binary path (separate non-C4(c) C4 piece)
- Operational PKI lifecycle: CA, cert rotation, cert revocation, signed root-distribution channel (surviving non-C4(c) work)
- Per-environment trust anchors (per-DevNet/TestNet/MainNet root sets)
- Cert validity-window enforcement on the binary path (counter scaffolded, clock-source enforcement deferred)
- Live N=4 multi-process Required + pqc-static-root real-binary recovery proof analogous to Run 034 on the new path (operator's immediate-next action; not blocked by code)

## 13. Exact verdict

**Strongest-positive for the C4(c) scope.** Production-honest PQC static-root cert-verification mode lands on the binary path; real-binary two-node mutual-auth succeeds without DummySig; negative cert cases fail closed at the live binary path. **C4 piece (c) is NARROWED**, not yet fully closed (operational PKI lifecycle and per-environment trust anchors remain out of scope). C4 as a whole remains OPEN (KEM/AEAD/fast-sync/exponential-backoff timeout pacing remain). C5 status text is updated to reflect that the C4(c) blocker is NARROWED but not yet fully closed; C5 is not marked closed because production transport KEM + AEAD on the binary path is still test-grade.

Operators MUST NOT rely on `--p2p-pqc-root-mode pqc-static-root` for production transport security today. It is honest about the cert-verification surface, but the surrounding KEM / AEAD primitives on the binary path remain test-grade until the surviving non-C4(c) C4 pieces close.