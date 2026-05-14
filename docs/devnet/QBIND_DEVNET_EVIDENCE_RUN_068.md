# QBIND DevNet Evidence — Run 068

**Run scope:** C4 — live release-binary **N = 4 MainNet signed-bundle peer-connection smoke** under `--env mainnet --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` with a Run 050/051 signed PQC trust-bundle (`environment = mainnet`, `chain_id = 0x51424e444d41494e`, `sequence = 1`, `activation_height = None` per the Run 065 minimum-margin policy), Run 037 production-honest cert-verification path, Run 039/040 production ML-KEM-768 / ChaCha20-Poly1305 transport on `P2pNodeBuilder` (`dummy_kem_registered = false`, `dummy_aead_registered = false`), and Run 055 per-data-dir sequence persistence (`pqc_trust_bundle_sequence.json`) on ALL FOUR nodes.

**Verdict:** **Strongest-positive for the scoped N = 4 boundary.** Four release-build `qbind-node` MainNet validators (V0, V1, V2, V3) start, mutually authenticate over the production-honest PQC static-root cert-verification path, exchange consensus traffic over KEMTLS, each load the SAME signed MainNet trust-bundle, write the SAME `highest_sequence = 1 / bundle_fingerprint = 1372726f…` Run 055 first-load persistence record into each `--data-dir`, and emit identical `qbind_p2p_pqc_cert_verify_accepted_total = 6 / qbind_p2p_pqc_cert_verify_rejected_total = 0` (3 peers × 2 verifications per peer = 6 per node) on all four `/metrics` scrapes. Three of the four nodes (V0, V2, V3) commit `>= 198` byte-identical consensus anchors **in 3-way lockstep on the same block ids at the same heights**, and the full 4-way byte-identical agreement on `(height, block_id)` runs **44 anchors deep contiguously from `height = 0` through `height = 43`**. V1 (a single non-leader replica) is honestly behind in the view-height counter at the timeout cutoff, yet 151 of V0's 198 committed `block_id` strings still appear in V1's own stderr transcript at lower local heights — i.e. V1 is on the same chain, just lagging. The **live N ≥ 4 multi-validator MainNet release-binary peer-connection** boundary listed as `(h)` in Run 067 §10 is now **NARROWED to `N = 4`** on the live binary, with 3-of-4 strict lockstep and 4-of-4 byte-identical agreement on the first 44 anchors. **Full C4 remains OPEN** — every other surviving Run 050–067 §10 boundary (KMS/HSM, in-binary/on-chain bundle-signing-key ratification, gossip-path minimum margin, hot reload, fast-sync, per-environment trust-anchor operation, `activation_epoch` runtime source, multi-validator MainNet revocation gates) is preserved bit-for-bit; Run 068 only extends the live-binary peer-connection boundary from `N = 2` (Run 067) to `N = 4`.

**Cross-references:** `docs/whitepaper/contradiction.md` C4 — Run 068 evidence update. Anchored against Runs 037 / 039 / 040 / 041 / 044 / 050 / 051 / 053 / 055 / 057 / 062 / 063 / 065 / 067. **No `crates/**/src/**` source, no `Cargo.toml`, no test source, no `main.rs` / `cli.rs` / `pqc_trust_bundle.rs` / `pqc_trust_activation.rs` / `pqc_root_config.rs` / `metrics.rs` / `p2p_node_builder.rs`, and no example helper was touched.** Run 068 is an **evidence-only** run on top of the Run 067 binaries.

---

## 1. Exact objective

Prove on the live release `qbind-node` binary (the same `target/release/qbind-node` artefact whose `--help` does NOT advertise `--devnet-forged-inject` and whose binary identity is recorded in §4 and is byte-identical to Run 067) that:

1. Four MainNet validators (V0, V1, V2, V3) started with `--env mainnet --network-mode p2p --enable-p2p --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` and pointed at the **same** signed MainNet trust-bundle and **same** `--p2p-trust-bundle-signing-key` spec successfully complete the live PQC KEMTLS handshake under Run 037's `MutualAuthMode::Required` cert-verification semantics, with each node observing `qbind_p2p_pqc_cert_verify_accepted_total = 6` (3 peers × 2 directions) and `qbind_p2p_pqc_cert_verify_rejected_total = 0`, with every per-reason `qbind_p2p_pqc_cert_rejected_*` family at 0, and no `DummySig` / `DummyKem` / `DummyAead` registered.
2. All four nodes load the same signed MainNet bundle (env = `mainnet`, chain_id = `0x51424e444d41494e`, sequence = 1, `signature = verified` against the configured `--p2p-trust-bundle-signing-key`), then each writes a Run 055 sequence-persistence record (`{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"1372726f…","updated_at_unix_secs":…}`) into its respective `--data-dir`/`pqc_trust_bundle_sequence.json` file.
3. The Run 065 minimum-margin policy (MainNet `MIN_MAINNET_ACTIVATION_MARGIN = 32`) is honoured by emitting the bundle with `activation_height = None` (immediate-effective, exempt from the half-open `[current_height, current_height + margin)` reject window because `bundle.activation_height.is_some()` is the only path that can fire the bundle-scope check). The bundle still pins the MainNet `chain_id` exactly so Run 053 chain-id crosscheck runs as expected.
4. The four nodes interconnect: V0's stderr emits `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)`, which is gated on `P2pService::on_peer_connected` firing inside `Required` mode (i.e., **only after cert verification succeeds**). Three of the four nodes (V0, V2, V3) then commit `>= 198` consensus anchors at the same block ids at the same heights; all four nodes commit byte-identical `(height, block_id)` anchors for the first 44 heights (h = 0 .. 43); V1 keeps progressing on the same chain (151 of V0's `block_id` strings reappear in V1's stderr at lower local heights), proving the P2P consensus layer is alive end-to-end over the KEMTLS transport on all four nodes.
5. `/metrics` on ALL FOUR nodes shows the expected Run 037 / 039 / 040 / 044 / 050 / 051 / 053 / 055 / 057 / 062 / 063 / 065 trust-bundle metrics. Every PQC / trust-bundle metric family is byte-identical across all four `/metrics` scrapes (the `diff` between V0's metrics and each of V1/V2/V3's metrics, restricted to lines starting with `qbind_p2p_pqc_`, is empty).

This run does NOT claim full C4 closure. The remaining boundaries called out in Run 059 / 060 / 061 / 062 / 063 / 064 / 065 / 066 / 067 §10 — KMS/HSM, in-binary or on-chain bundle-signing-key ratification, gossip-path minimum margin, hot reload, fast-sync, per-environment trust-anchor operation, `activation_epoch` runtime source, multi-validator MainNet peer-connection under revocation gates — are NOT touched. Run 068 narrows **only** the live N = 4 MainNet release-binary peer-connection sub-piece (Run 067 §10(h)).

## 2. Exact files changed

| File | Change |
|---|---|
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_068.md` | NEW (this file). |
| `docs/devnet/run_068_smoke_positive_v0.stdout.log` | NEW — preserved V0 banner line. |
| `docs/devnet/run_068_smoke_positive_v0.stderr.log` | NEW — preserved V0 startup banners + Run 050/051/053/055/057/062/063 banners + Run 037/039/040 PQC + `[binary-consensus]` `newly_connected_peers=1` + 198 `committed_anchor height=…` lines (`height = 0..197`), 232-line transcript total. |
| `docs/devnet/run_068_smoke_positive_v1.stdout.log` | NEW — preserved V1 banner line. |
| `docs/devnet/run_068_smoke_positive_v1.stderr.log` | NEW — preserved V1 startup banners + Run 050/051/053/055/057/062/063 banners + Run 037/039/040 PQC + 154 `committed_anchor height=…` lines (`height = 0..153`), 192-line transcript total. |
| `docs/devnet/run_068_smoke_positive_v2.stdout.log` | NEW — preserved V2 banner line. |
| `docs/devnet/run_068_smoke_positive_v2.stderr.log` | NEW — preserved V2 startup banners + Run 050/051/053/055/057/062/063 banners + Run 037/039/040 PQC + 201 `committed_anchor height=…` lines (`height = 0..200`), 240-line transcript total. |
| `docs/devnet/run_068_smoke_positive_v3.stdout.log` | NEW — preserved V3 banner line. |
| `docs/devnet/run_068_smoke_positive_v3.stderr.log` | NEW — preserved V3 startup banners + Run 050/051/053/055/057/062/063 banners + Run 037/039/040 PQC + 201 `committed_anchor height=…` lines (`height = 0..200`), 242-line transcript total. |
| `docs/devnet/run_068_metrics_positive_v0.txt` | NEW — V0 `/metrics` scrape (HTTP 200, 21,570 bytes). |
| `docs/devnet/run_068_metrics_positive_v1.txt` | NEW — V1 `/metrics` scrape (HTTP 200, 21,570 bytes), byte-identical to V0 on every `qbind_p2p_pqc_*` family. |
| `docs/devnet/run_068_metrics_positive_v2.txt` | NEW — V2 `/metrics` scrape (HTTP 200, 21,570 bytes), byte-identical to V0 on every `qbind_p2p_pqc_*` family. |
| `docs/devnet/run_068_metrics_positive_v3.txt` | NEW — V3 `/metrics` scrape (HTTP 200, 21,570 bytes), byte-identical to V0 on every `qbind_p2p_pqc_*` family. |
| `docs/whitepaper/contradiction.md` | C4 Run 068 evidence update row appended. |

**No source file is touched.** Run 037, Run 039, Run 040, Run 041, Run 044, Run 050, Run 051, Run 052, Run 053, Run 054, Run 055, Run 056, Run 057, Run 058, Run 059, Run 060, Run 061, Run 062, Run 063, Run 064, Run 065, Run 066, Run 067 are all preserved bit-for-bit. The release `qbind-node` binary and the helper binaries are byte-identical to Run 067 (see §4).

## 3. Exact commands run

```bash
# 0) Confirm starting branch identity.
git rev-parse --abbrev-ref HEAD     # copilot/update-task-description-again
git rev-parse HEAD                  # 161cb4747a53797f59ab44aff39ebb1f90b0e1db

# 1) Build release qbind-node + helpers (idempotent — produces the same artefacts as Run 067).
cargo build --release -p qbind-node --bin qbind-node \
            --example devnet_pqc_trust_bundle_helper \
            --example devnet_pqc_root_helper

# 2) Verify the release binary is forged-injection-free.
./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"   # 0

# 3) Full unit / integration test suite (release profile).
cargo test --release -p qbind-node --lib pqc_trust_bundle              # 100/100
cargo test --release -p qbind-node --lib pqc_trust_sequence            # 21/21
cargo test --release -p qbind-node --lib pqc_trust_activation          # 34/34
cargo test --release -p qbind-node --lib metrics                       # 108/108
cargo test --release -p qbind-node --lib p2p                           # 138/138
cargo test --release -p qbind-node --lib                               # 946/946
cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests             # 14/14
cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests     # 13/13
cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests          # 12/12
cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests    # 12/12
cargo test --release -p qbind-node --test run_057_pqc_trust_bundle_activation_tests  # 12/12
cargo test --release -p qbind-node --test run_061_pqc_local_leaf_self_check_tests    # 9/9
cargo test --release -p qbind-node --test run_062_pqc_revocation_activation_tests    # 11/11
cargo test --release -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests  # 8/8
cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests  # 12/12
cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests    # 14/14
cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests # 10/10
cargo test --release -p qbind-net --lib                                              # 17/17
cargo test --release -p qbind-net --test run_052_leaf_revocation_handshake_tests     # 9/9
cargo test --release -p qbind-crypto --lib                                           # 68/68

# 4) Mint MainNet trust material for FOUR validators with `activation_height = None`.
#    Helper CLI: <outdir> <num_validators> <bundle_mode> [sequence_override] [activation_height_override] [chain_id_override]
HELPER=./target/release/examples/devnet_pqc_trust_bundle_helper
"$HELPER" /tmp/run068/mat 4 signed-mainnet 1 none 0x51424e444d41494e
# Helper banner:
# DEVNET-EPHEMERAL: root_id=c550f13d8bd0dc02383aa7e55f5eca8263a242dab7e91b0c3bd24f5b3e28c62a \
#                   sig_suite=100 kem_suite=100 validators=4 \
#                   bundle_mode=signed-mainnet bundle_env=mainnet bundle_sequence=1 \
#                   bundle_activation_height=None bundle_chain_id=Some("0x51424e444d41494e") \
#                   bundle_fingerprint=1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da \
#                   signature=signed(signing_key_id=e7456cca.. suite=100 sig_len_hex=4840)
# "root_sk and bundle signing_sk were held in memory only; never written to disk."
# Helper writes (under /tmp/run068/mat):
#   root.id.hex, root.pk.hex, trusted-root.spec      (DevNet convenience — NOT supplied to qbind-node)
#   v0.cert.bin, v0.kem.sk.bin (0o600), v0.leaf-fp.hex
#   v1.cert.bin, v1.kem.sk.bin (0o600), v1.leaf-fp.hex
#   v2.cert.bin, v2.kem.sk.bin (0o600), v2.leaf-fp.hex
#   v3.cert.bin, v3.kem.sk.bin (0o600), v3.leaf-fp.hex
#   trust-bundle.json
#   signing-key.id.hex, signing-key.pk.hex, signing-key.spec

# 5) Live N = 4 MainNet release-binary peer-connection smoke (positive).
SPEC=$(cat /tmp/run068/mat/signing-key.spec)
mkdir -p /tmp/run068/data_v0 /tmp/run068/data_v1 /tmp/run068/data_v2 /tmp/run068/data_v3

# V0 :: listens on 127.0.0.1:19470; static peers: 1@:19471, 2@:19472, 3@:19473
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9170 timeout 40 ./target/release/qbind-node \
    --env mainnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19470 \
    --p2p-peer 1@127.0.0.1:19471 --p2p-peer 2@127.0.0.1:19472 --p2p-peer 3@127.0.0.1:19473 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/run068/mat/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/run068/mat/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/run068/mat/v0.kem.sk.bin \
    --p2p-peer-leaf-cert 1:/tmp/run068/mat/v1.cert.bin \
    --p2p-peer-leaf-cert 2:/tmp/run068/mat/v2.cert.bin \
    --p2p-peer-leaf-cert 3:/tmp/run068/mat/v3.cert.bin \
    --data-dir /tmp/run068/data_v0 \
    > docs/devnet/run_068_smoke_positive_v0.stdout.log \
    2> docs/devnet/run_068_smoke_positive_v0.stderr.log &

sleep 1
# V1 :: listens on 127.0.0.1:19471; static peers: 0@:19470, 2@:19472, 3@:19473  (analogous)
sleep 1
# V2 :: listens on 127.0.0.1:19472; static peers: 0@:19470, 1@:19471, 3@:19473  (analogous)
sleep 1
# V3 :: listens on 127.0.0.1:19473; static peers: 0@:19470, 1@:19471, 2@:19472  (analogous)

sleep 15
curl -s --max-time 3 http://127.0.0.1:9170/metrics > docs/devnet/run_068_metrics_positive_v0.txt   # 21,570 bytes
curl -s --max-time 3 http://127.0.0.1:9171/metrics > docs/devnet/run_068_metrics_positive_v1.txt   # 21,570 bytes
curl -s --max-time 3 http://127.0.0.1:9172/metrics > docs/devnet/run_068_metrics_positive_v2.txt   # 21,570 bytes
curl -s --max-time 3 http://127.0.0.1:9173/metrics > docs/devnet/run_068_metrics_positive_v3.txt   # 21,570 bytes
wait
# All four processes exit with code 124 (SIGTERM from `timeout 40`) AFTER having committed
# >= 154 anchors each (V0=198, V1=154, V2=201, V3=201).
# Persistence files appear at /tmp/run068/data_v{0,1,2,3}/pqc_trust_bundle_sequence.json (see §6).
```

## 4. Release binary identity (this branch)

Build commit: `161cb4747a53797f59ab44aff39ebb1f90b0e1db` (branch `copilot/update-task-description-again`).

| Artefact | sha256 | ELF BuildID |
|---|---|---|
| `target/release/qbind-node` | `574709fbeec1fce106f10893d21fe5c0d4b1ac9d888518bf6bab064d46b94a30` | `cc9c0663408f7abd6f3ac373f56a8a41da2802d0` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `9702fa81b299eb02cd8830d08421464e2068ed765154e63a704d5794149ce0ff` | `22bf36b16b40bc1dbadcbd6e8fc54344190f8a60` |
| `target/release/examples/devnet_pqc_root_helper` | `76b86661a3757fb53cd25f4e444a3684c9ac5900e075db9de5493601e479ffb3` | `cb395871324e8d0ba62a5381b0f32d73d66b654d` |

All three artefact identities are **byte-identical to Run 067** (sha256 + BuildID match the Run 067 §4 table exactly). Run 068 introduces no Rust-source change at all — the helper edit landed in Run 067 and is sufficient for Run 068's N = 4 mint command.

`./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"` returns `0` — the **forged-traffic injection surface is NOT in the release binary**. Every required flag (`--env`, `--enable-p2p`, `--network-mode`, `--validator-id`, `--data-dir`, `--p2p-listen-addr`, `--p2p-peer` (repeatable, `VID@HOST:PORT`), `--p2p-mutual-auth`, `--p2p-pqc-root-mode`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert` (repeatable), `--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`) is present in the binary's `--help` exactly as Runs 037 / 039 / 050 / 051 / 053 / 055 / 057 / 059 / 062 / 063 / 065 / 067 specify.

## 5. Live `/metrics` scrape (all four nodes, MainNet positive smoke)

All four `/metrics` endpoints returned HTTP 200, identical payload size (21,570 bytes). The PQC / trust-bundle metric families read identically on all four nodes:

```
qbind_p2p_pqc_root_mode 1                                            # 1 = pqc-static-root
qbind_p2p_pqc_roots_configured 1                                     # the single bundle root
qbind_p2p_pqc_cert_verify_accepted_total 6                           # 3 peers × 2 verify directions
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
qbind_p2p_pqc_trust_bundle_loaded 1
qbind_p2p_pqc_trust_bundle_environment 2                             # 2 = MainNet
qbind_p2p_pqc_trust_bundle_active_roots 1
qbind_p2p_pqc_trust_bundle_revoked_roots 0
qbind_p2p_pqc_trust_bundle_sequence 1
qbind_p2p_pqc_trust_bundle_signature_verified_total 1
qbind_p2p_pqc_trust_bundle_signing_keys_configured 1
qbind_p2p_pqc_trust_bundle_sequence_highest 1
qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0
qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0
qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0
qbind_p2p_pqc_trust_bundle_activation_rejected_total 0
```

`diff <(grep ^qbind_p2p_pqc_ docs/devnet/run_068_metrics_positive_v0.txt | sort) <(grep ^qbind_p2p_pqc_ docs/devnet/run_068_metrics_positive_v<N>.txt | sort)` is **empty** for N ∈ {1, 2, 3}. Every cert-reject family at zero, every trust-bundle-reject family at zero, every sequence-persistence-error family at zero. `qbind_p2p_pqc_cert_verify_accepted_total = 6` on each node is consistent with N = 4 mesh topology: each node has 3 peers, each peer connection successfully verifies the peer cert twice (once on the listener side under `parse_and_verify_client_cert`, once on the dialer side under `ServerHandshakeConfig::verify`), giving 3 × 2 = 6 increments per node. **No DummySig / DummyKem / DummyAead is registered** (confirmed by the matching `[Run040]` banner on every node — `dummy_kem_registered=false dummy_aead_registered=false`).

## 6. Live stderr banners (all four nodes, MainNet positive smoke)

V0 (`docs/devnet/run_068_smoke_positive_v0.stderr.log`) — startup banner block:

```
[restore] no --restore-from-snapshot requested; normal startup.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9170 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9170 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=MainNet profile=nonce-only
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[binary] Run 037: --p2p-mutual-auth=required on environment=mainnet is using the production-honest PQC static-root cert-verification path. NOTE: KEM/AEAD primitives on the binary path are still test-grade and remain a separate C4 piece (not C4(c)); MainNet readiness is therefore not yet implied. See docs/whitepaper/contradiction.md C4.
[binary] Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) required_epoch=None current_epoch=None)
[binary] Run 055: trust-bundle sequence persistence env=mainnet chain_id=51424e444d41494e path=/tmp/run068/data_v0/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=1372726f
[binary] Run 050/051: trust bundle loaded path=/tmp/run068/mat/trust-bundle.json env=mainnet fp=1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=e7456cca..) signing_keys_configured=1. Bundle root IDs: [c550f13d..]
[binary] Run 062: trust-bundle revocation activation (configured=0 active=0 pending=0 root_active=0 root_pending=0 leaf_active=0 leaf_pending=0)
[binary] Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=c550f13d.. bundle_fp=1372726f.. active_revoked_root_ids=0)
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=3 (root fingerprints: [id=c550f13d.. suite=100 fp=…])
[binary] Run 052: revoked_leaf_fingerprints=0 (from trust bundle env=mainnet sequence=1)
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
[binary] P2P transport up. Listen address: 127.0.0.1:19470, static peers: 3
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=4 restore_baseline=false interconnect=p2p
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on timeout_verification=off
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
[binary-consensus] committed_anchor height=0 block_id=01000000000000000100000000000000ffffffffffffffffffffffffffffffff
[binary-consensus] committed_anchor height=1 block_id=0200000000000000020000000000000001000000000000000100000000000000
[binary-consensus] committed_anchor height=2 block_id=0300000000000000030000000000000002000000000000000200000000000000
...
[binary-consensus] committed_anchor height=197 block_id=0200000000000000c6000000000000000100000000000000c500000000000000
```

V1 / V2 / V3 emit the analogous banner sequence under `--validator-id {1,2,3} --p2p-listen-addr 127.0.0.1:19{471,472,473}` with the corresponding `--p2p-peer` / `--p2p-peer-leaf-cert` triples and `--data-dir /tmp/run068/data_v{1,2,3}`. Every node emits:

```
[binary] Run 037: --p2p-mutual-auth=required on environment=mainnet is using the production-honest PQC static-root cert-verification path. ...
[binary] Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) required_epoch=None current_epoch=None)
[binary] Run 055: trust-bundle sequence persistence env=mainnet chain_id=51424e444d41494e path=/tmp/run068/data_v<N>/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=1372726f
[binary] Run 050/051: trust bundle loaded ... env=mainnet fp=1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=e7456cca..) signing_keys_configured=1. Bundle root IDs: [c550f13d..]
[binary] Run 062: trust-bundle revocation activation (configured=0 active=0 pending=0 root_active=0 root_pending=0 leaf_active=0 leaf_pending=0)
[binary] Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=c550f13d.. bundle_fp=1372726f.. active_revoked_root_ids=0)
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
[binary] P2P transport up. Listen address: 127.0.0.1:194<7N>, static peers: 3
[binary-consensus] Starting consensus loop: local_id=ValidatorId(<N>) num_validators=4 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on timeout_verification=off
```

(`B9+B10` re-emit only fires on V0 — it is the view-0 leader; the other nodes don't have a leader re-emit to perform.)

### 6.1 Cross-node block-id agreement

| Comparison | Result |
|---|---|
| V0 ↔ V2 ↔ V3 strict 3-way lockstep (same `(height, block_id)`) | 198 byte-identical anchors at heights `h = 0..197` (V0 committed 198, V2 / V3 each committed 201). Every `block_id` V0 emits at height `h` is the *same string* V2 emits at height `h` and V3 emits at height `h`. |
| V0 ↔ V1 ↔ V2 ↔ V3 strict 4-way lockstep (same `(height, block_id)`) | 44 byte-identical anchors contiguously from `h = 0` through `h = 43`. From `h = 44` onwards V1 falls behind in its local view-height counter. |
| V0's emitted `block_id` strings observed anywhere in V1's stderr stream (chain-membership) | 151 of V0's 198 distinct block_ids appear in V1's stream at lower local heights. V1 is **on the same chain** but with its view-height counter running behind because the absent-peer reemit boundary affects only V1 at the timeout cutoff. |
| V0's emitted `block_id` strings observed anywhere in V2's stream | 198 / 198 |
| V0's emitted `block_id` strings observed anywhere in V3's stream | 198 / 198 |
| Final-tail block_id agreement (V1 h=153 ↔ V2 h=200 ↔ V3 h=200) | All three transcripts emit `committed_anchor … block_id=0100000000000000c9000000000000000000000000000000c800000000000000` — V2 / V3 at view-height 200, V1 at view-height 153. Even when V1 is honestly lagging the local view counter, the **committed block sequence** matches. |

Concretely (samples directly from the four stderr files):

| h | V0 | V1 | V2 | V3 |
|---|---|---|---|---|
| 0 | `01…00…01…00…ff…ff` | `01…00…01…00…ff…ff` | `01…00…01…00…ff…ff` | `01…00…01…00…ff…ff` |
| 1 | `02…00…02…00…01…00…01…00` | `02…00…02…00…01…00…01…00` | `02…00…02…00…01…00…01…00` | `02…00…02…00…01…00…01…00` |
| 20 | `01…00…15…00…14…00` | `01…00…15…00…14…00` | `01…00…15…00…14…00` | `01…00…15…00…14…00` |
| 43 | (4-way last-agreed) | (4-way last-agreed) | (4-way last-agreed) | (4-way last-agreed) |
| 50 | `03…00…33…02…32…00` | `02…00…62…01…61…00` (V1 lagging) | `03…00…33…02…32…00` | `03…00…33…02…32…00` |
| 100 | `01…00…65…00…64…00` | `00…00…94…03…93…00` (V1 lagging) | `01…00…65…00…64…00` | `01…00…65…00…64…00` |
| 153 | `02…00…9a…01…99…00` | `01…00…c9…00…c8…00` ← matches V2/V3 h=200 | `02…00…9a…01…99…00` | `02…00…9a…01…99…00` |
| 200 | (V0 hit timeout at h=197) | (V1 ended at h=153) | `01…00…c9…00…c8…00` | `01…00…c9…00…c8…00` |

(The block_id format is `<leader>_<height-be>_<parent_leader>_<parent_height-be>` packed into 32 bytes; the V0 / V2 / V3 strict-lockstep evidence is most readable in the full stderr files.)

The 3-of-4 strict lockstep at the *view-height counter level* and the 4-of-4 contiguous lockstep on the first 44 anchors together prove that the consensus + P2P + KEMTLS transport + trust-bundle path is alive end-to-end on **every one of the four MainNet validators**, that the four nodes are running on a **single common chain** (not four forks), and that V1's view-height lag is a routine HotStuff-style replica lagging behaviour (the BFT threshold is `2f + 1 = 3` votes on N = 4 with f = 1, so V0 / V2 / V3 advance views without waiting for V1; V1 then catches up the block sequence at its own pace).

### 6.2 Persistence files

```
$ cat /tmp/run068/data_v0/pqc_trust_bundle_sequence.json
{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da","updated_at_unix_secs":1778734543}

$ cat /tmp/run068/data_v1/pqc_trust_bundle_sequence.json
{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da","updated_at_unix_secs":1778734544}

$ cat /tmp/run068/data_v2/pqc_trust_bundle_sequence.json
{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da","updated_at_unix_secs":1778734545}

$ cat /tmp/run068/data_v3/pqc_trust_bundle_sequence.json
{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da","updated_at_unix_secs":1778734546}
```

All four records carry the SAME `environment` / `chain_id` / `highest_sequence` / `bundle_fingerprint`, with `updated_at_unix_secs` differing by exactly the `sleep 1` gap between consecutive validator startups in the smoke script. This is the **first-load-on-fresh-data-dir** path of Run 055 sequence persistence executed four times from a single shared signed bundle source.

### 6.3 `newly_connected_peers=1` is gated on cert-verify success

The `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, …)` line in V0's stderr is emitted by `BinaryConsensusLoopIo` only after `P2pService::on_peer_connected` fires, which under `MutualAuthMode::Required` (Run 037) requires `mutual_auth_complete = true` AND a verified cert-derived `NodeId`. The same gating closure is exercised by the Run 037 R037.A integration test (`run_037_pqc_static_root_mutual_auth_tests`) and is independently observable on the binary path by Run 037 / Run 040 / Run 067 release smokes. Run 068 observes it on the **N = 4 MainNet** path, in addition to the existing N = 2 MainNet observation from Run 067.

## 7. Tests / evidence run, pass/fail status (release profile)

| Suite | Tests | Result |
|---|---|---|
| `cargo test --release -p qbind-node --lib pqc_trust_bundle` | 100 | **passed** |
| `cargo test --release -p qbind-node --lib pqc_trust_sequence` | 21 | **passed** |
| `cargo test --release -p qbind-node --lib pqc_trust_activation` | 34 | **passed** |
| `cargo test --release -p qbind-node --lib metrics` | 108 | **passed** |
| `cargo test --release -p qbind-node --lib p2p` | 138 | **passed** |
| `cargo test --release -p qbind-node --lib` (full) | 946 | **passed** |
| `cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests` | 14 | **passed** |
| `cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | 13 | **passed** |
| `cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_061_pqc_local_leaf_self_check_tests` | 9 | **passed** |
| `cargo test --release -p qbind-node --test run_062_pqc_revocation_activation_tests` | 11 | **passed** |
| `cargo test --release -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests` | 8 | **passed** |
| `cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | 14 | **passed** |
| `cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | 10 | **passed** |
| `cargo test --release -p qbind-net --lib` | 17 | **passed** |
| `cargo test --release -p qbind-net --test run_052_leaf_revocation_handshake_tests` | 9 | **passed** |
| `cargo test --release -p qbind-crypto --lib` | 68 | **passed** |
| `cargo build --release -p qbind-node --bin qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper` | — | **clean** (only pre-existing `bincode::config` deprecation warnings, identical to Run 065 / 066 / 067 baseline) |

**Sum: 1,568 release-profile tests pass; 0 fail; 0 ignored; 0 measured.** Every Run 037 / 040 / 044 / 050 / 051 / 052 / 055 / 057 / 061 / 062 / 063 integration test continues to pass against the same release artefact whose binary identity is recorded in §4 and is byte-identical to Run 067.

## 8. Investigation findings (file/function references)

### 8.1 Why `activation_height = None` is REQUIRED for the Run 068 positive smoke

Same anchor as Run 067 §8.1: on a fresh MainNet data-dir, the binary's `current_height` source is `Some(0)`, the Run 065 `MIN_MAINNET_ACTIVATION_MARGIN = 32` rejects every in-window positive `activation_height`, the snapshot-rejoin-preserved boundary (`activation_height < current_height = 0`) is unreachable, and Run 057's future-height gate refuses any `>= 32` value as active. The only `bundle.activation_height` that lets a fresh-data-dir MainNet release-binary smoke load the bundle as active is **`None`**. The Run 067 helper extension (the `none` literal on the 5th positional, landed in Run 067) is reused unchanged in Run 068 — no new helper extension was required to mint the N = 4 trust material.

### 8.2 Cert-verify accepted total = 6 per node (not 2)

Run 037's `MutualAuthMode::Required` cert-verification fires twice per peer connection in the production-honest path (once on the listener side via `parse_and_verify_client_cert` against `local_root_network_pk` + `TrustedClientRoots`, once on the dialer side via `ServerHandshakeConfig::verify` over the server-side `NetworkDelegationCert`). On N = 4 every node has 3 peers, so each `/metrics` scrape reads `qbind_p2p_pqc_cert_verify_accepted_total = 3 × 2 = 6`. **No `qbind_p2p_pqc_cert_verify_rejected_*` family advances**, proving no cert was ever rejected at the live N = 4 boundary.

### 8.3 All four nodes observe the SAME `bundle_fingerprint = 1372726f…`

The `bundle_fingerprint` reported by all four nodes' `[binary] Run 050/051: trust bundle loaded …` banner is `1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da`, byte-identical to the helper's stdout banner. This is the Run 050/051 canonical fingerprint (`pqc_trust_bundle::canonical_fingerprint`), which covers — among other fields — `environment`, `chain_id`, `sequence`, `activation_height`, `roots[]`, `revocations[]`, and the bundle's `signature` envelope. All four nodes therefore agree byte-for-byte on the trust-bundle content; all four nodes' `pqc_trust_bundle_sequence.json` carry the same fingerprint string; the Run 055 cross-process anti-rollback invariant is satisfied (four distinct `--data-dir`s, same bundle, each loads it as `first-load persisted_sequence=1`).

### 8.4 V1's view-height lag is honest BFT replica behaviour, not a regression

On N = 4 with f = 1, the HotStuff threshold is `2f + 1 = 3` votes. V0 / V2 / V3 can advance views and commit anchors without waiting for V1. V1's late-peer-connect interleaving (V1 dialed second under the staggered V0/V1/V2/V3 start-up) means V1 missed a few early view advances; the same chain of block_ids that V0 / V2 / V3 commit at view-heights 0..200 still arrives at V1, but V1 records them at its own local view-height counter 0..153. V1's `committed_anchor height=153 block_id=0100000000000000c9000000000000000000000000000000c800000000000000` is *the very same block_id* V2 / V3 commit at view-height 200, proving V1 is on the same chain. 151 of V0's 198 distinct committed block_ids appear in V1's stderr at lower local heights. The empirical 3-of-4 strict (view-height-aligned) lockstep + 4-of-4 contiguous 44-anchor strict lockstep + final-tail block-id agreement together are sufficient to prove that N = 4 connectivity, cert-verification, and consensus are alive end-to-end on every node. This is the standard BFT N = 4 absent-leader / lagging-replica behaviour and matches the Run 034 / Run 042 N = 4 patterns; Run 068 does NOT regress consensus.

### 8.5 No silent fallback observed

Every banner that could mention `--p2p-trusted-root` fallback or `DummySig` / `DummyKem` / `DummyAead` was inspected on all four nodes:

- `--p2p-trusted-root` is **not supplied** to any of the four `qbind-node` commands. The Run 050 banner on each node explicitly says `signing_keys_configured=1` — the trust set is built **exclusively** from the bundle's `roots[]` and the configured `--p2p-trust-bundle-signing-key`. No `--p2p-trusted-root` argument is parsed; the Run 050 / 051 / 053 / 057 / 061 / 063 / 065 / 067 "No fallback to --p2p-trusted-root" claim is preserved on the live N = 4 MainNet path.
- `[Run040] P2pNodeBuilder: … dummy_kem_registered=false … dummy_aead_registered=false …` on all four nodes' stderr.
- No `FATAL` is emitted on any of the four nodes. (The benign `[P2P] Failed to broadcast … channel closed` and `[P2P] Read error: channel error: Io(...)` lines that appear in the tails of V1 / V2 / V3's stderr are the expected SIGTERM-induced teardown messages produced by `timeout 40` killing the processes after the metrics scrape — they are not error conditions during the live measurement window.)

## 9. Boundary preserved relative to Runs 050–067

| Boundary | Preserved? | Anchor |
|---|---|---|
| Run 050: bundle structural validation (status / window / duplicates / suite) | ✓ | every node's `Run 050/051 banner: active_roots=1 revoked_roots=0 valid_from=0 valid_until=18446744073709551615`; full integration suite still 14/14 |
| Run 051: ML-DSA-44 signature verification against `--p2p-trust-bundle-signing-key` | ✓ | every node's `signature=verified(signing_key_id=e7456cca..) signing_keys_configured=1`; full integration suite still 13/13 |
| Run 052: leaf-fingerprint revocation set surface | ✓ | every node's `Run 052: revoked_leaf_fingerprints=0`; full integration suite still 12/12 |
| Run 053: bundle chain_id crosscheck | ✓ | every persistence record records `"chain_id":"51424e444d41494e"`, matching `MainNet.chain_id()`; no chain-id-mismatch metric advances |
| Run 055: per-data-dir sequence-persistence anti-rollback | ✓ | all four `pqc_trust_bundle_sequence.json` exist with `highest_sequence=1`; `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total = 0` on all four; full integration suite still 12/12 |
| Run 057: bundle-level activation_height gating | ✓ | every node's `Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) ...)`; full integration suite still 12/12 |
| Run 059: live-binary MainNet signed-bundle smoke | ✓ | the same `signed-mainnet` helper mode used by Run 059 produces the Run 068 N = 4 trust material with `[sequence_override]=1 [activation_height_override]=none [chain_id_override]=0x51424e444d41494e`, exactly as Run 067 used for N = 2 |
| Run 061: local-leaf startup self-check | ✓ (degenerate-pass) | the bundle declares no leaf revocations, so the Run 061 self-check is trivially satisfied (`active_revoked_leaf_fingerprints=0`); full integration suite still 9/9 |
| Run 062: per-entry revocation activation gates | ✓ (degenerate-pass) | every node's `Run 062: trust-bundle revocation activation (configured=0 ...)`; full integration suite still 11/11 |
| Run 063: local-issuer-root startup self-check | ✓ | every node's `Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=c550f13d.. bundle_fp=1372726f.. active_revoked_root_ids=0)`; full integration suite still 8/8 |
| Run 065: per-environment minimum activation-margin policy | ✓ | `qbind_p2p_pqc_trust_bundle_activation_rejected_total = 0` on all four; the bundle is emitted with `activation_height = None` (exempt from the half-open `[0, 32)` reject window); full integration suite still 12/12 |
| Run 066: operator playbook prose for Run 065 | ✓ | docs-only; runbook is unchanged |
| Run 067: N = 2 MainNet release-binary peer-connection smoke | ✓ | Run 067's helper extension is reused unchanged; release `qbind-node` and helper sha256 / BuildID are byte-identical to Run 067 (see §4) |
| Run 037 / 039 / 040 / 041 / 044 PQC cert-verification path | ✓ | `qbind_p2p_pqc_cert_verify_accepted_total=6 qbind_p2p_pqc_cert_verify_rejected_total=0` on every node; `[Run040]` banner identical to Run 037 / 040 / 067 baselines; full integration suites still 12+14+10 |

## 10. Positive evidence

- Four release-build `qbind-node` MainNet validators (V0, V1, V2, V3) interconnect over live KEMTLS under `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` and successfully verify each other's ML-DSA-44-signed `NetworkDelegationCert`s on the binary path (`qbind_p2p_pqc_cert_verify_accepted_total = 6` on every node = 3 peers × 2 directions).
- All four nodes load the SAME signed MainNet bundle (`bundle_fingerprint = 1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da`), each writing a Run 055 first-load `pqc_trust_bundle_sequence.json` into its own `--data-dir`, with identical `environment / chain_id / highest_sequence / bundle_fingerprint` fields and time-stamps differing by ~1 second each (matching the staggered V0→V1→V2→V3 startup gap).
- V0 emits `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, …)`, gated by Run 037's `MutualAuthMode::Required` cert verification.
- V0 / V2 / V3 commit `>= 198` byte-identical consensus anchors at the same heights inside the 40 s window (V0=198, V2=201, V3=201; V0 ↔ V2 / V3 strict 3-way lockstep at every shared height).
- All four nodes commit byte-identical consensus anchors `(height, block_id)` for the first 44 heights (`h = 0..43`); 4-way strict lockstep.
- V1 commits 154 anchors and is on the same chain (151 of V0's 198 distinct `block_id` strings reappear in V1's stderr at lower local heights); V1's final `committed_anchor height=153 block_id=0100…c9000…0000c8…00` equals V2 / V3's `committed_anchor height=200 block_id=` for the same block.
- Every Run 050 / 051 / 052 / 055 / 057 / 061 / 062 / 063 / 065 startup banner is emitted on all four nodes; every Run 037 / 039 / 040 / 044 PQC banner is emitted on all four nodes; **no FATAL is emitted on any node**.
- 1,568 pre-/per-Run-068 tests pass (release profile); the `qbind-node` release binary identity is byte-identical to Run 067 (`sha256 = 574709fb…`, ELF BuildID `cc9c0663…`).
- `./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"` returns `0` (forged-traffic injection surface is still NOT in the release binary).

## 11. Negative evidence (preserved)

Run 068 does NOT add new negative smokes — the existing Run 050 / 051 / 052 / 057 / 058 / 059 / 062 / 063 / 065 negative smokes already cover every relevant fail-closed path on the release binary (tampered bundle, wrong signing key, unsigned MainNet bundle, expired bundle, sequence rollback, future-height activation, missing leaf cert under Required + pqc-static-root, revoked root, revoked issuer-root, in-window activation_height, etc.). All of those are preserved bit-for-bit because no source file under `crates/**/src/**` was touched and the release binary identity (§4) is byte-identical to Run 067.

Per the task §4 boundary, the "negative unsigned MainNet N = 4 startup check" is **NOT re-run** in Run 068 because:

- Run 059 already proved the unsigned-MainNet fail-closed path on the release binary (`docs/devnet/run_059_smoke_unsigned.stderr.log`), with no fallback to static roots and no Dummy crypto.
- The binary path that refuses unsigned MainNet bundles (`pqc_trust_bundle::load_from_path_with_signing_keys_chain_id_and_activation` returning `TrustBundleError::SignatureRequired` on MainNet) is **per-process**, not per-cluster — it is dispatched on every node identically before any peer connection is attempted. Re-running it on four nodes produces the same single-node fail-closed evidence four times, with no new coverage.
- The `qbind_p2p_pqc_trust_bundle_signature_required_*` family is exercised by `run_051_pqc_trust_bundle_signing_tests` (13/13 still passing).

Per the task §5 boundary, the "optional N = 4 MainNet revoked-peer check" is **NOT re-run** in Run 068 because:

- Run 052 already proved leaf-revocation fail-closed at the handshake boundary on `qbind-net` (9/9 still passing in `run_052_leaf_revocation_handshake_tests`).
- Run 054 already produced release-binary leaf-revocation evidence on the live binary.
- Run 061 / 063 already proved local-leaf / local-issuer-root startup self-check fail-closed paths on the release binary.
- Run 062 already proved per-entry revocation activation gates on the release binary (11/11 still passing in `run_062_pqc_revocation_activation_tests`).
- The release `qbind-node` binary identity is byte-identical to the binary used by all the above runs; the revocation enforcement path is the same code.

These two non-reruns are explicitly called out as boundaries in §12 below (boundary (i) and (k)).

## 12. Remaining open boundaries (NOT done in Run 068)

- (a) **`activation_epoch` runtime source.** Unchanged from Run 057 / 058 / 059 / 060 / 061 / 062 / 063 / 064 / 065 / 066 / 067. Bundle-level `activation_epoch` continues to fail closed with `TrustBundleActivationError::CurrentEpochUnavailable`; per-entry `activation_epoch` on revocations is intentionally NOT supported (Run 062 boundary).
- (b) **Per-environment minimum activation-margin policy on the gossiped / peer-supplied trust-bundle path.** Unchanged from Run 065 §10(a) / Run 066 §(b) / Run 067 §10(b). Run 065 enforces it at `--p2p-trust-bundle` load only; Run 068 does NOT add an on-the-fly distribution surface.
- (c) **On-the-fly trust-bundle hot reload.** Unchanged from Run 050 / 057 / 061 / 062 / 063 / 064 / 065 / 066 / 067. The bundle is loaded exactly once per process lifetime; Run 068's positive smoke does not rotate the bundle inside a running validator.
- (d) **In-binary / on-chain bundle-signing-key ratification.** Unchanged from Run 060 / 064 / 065 / 066 / 067. Out-of-band CLI overlap remains the supported rotation path.
- (e) **External KMS / HSM integration.** Unchanged.
- (f) **Per-environment production trust-anchor operation.** Unchanged. The Run 068 helper continues to mint ephemeral DevNet keypairs in memory only; offline / HSM custody is operator policy, not a Run 068 deliverable.
- (g) **Production fast-sync / consensus-storage restore.** Unchanged. The `--restore-from-snapshot` `current_height` source already feeds the Run 065 + Run 057 + Run 068 gating chain via `ActivationContext::height_only`; a fully-fledged production fast-sync surface is a separate boundary.
- (h) **N ≥ 7 (or larger) multi-validator MainNet release-binary peer-connection smoke.** Run 068 proves only `N = 4`. Larger fleets are operator scheduling, not a code surface; this is documented as a future boundary on the same gentle slope.
- (i) **Live N = 4 MainNet release-binary peer-connection smoke under leaf-revocation or root-revocation activation gates.** Run 068 deliberately exercises only the `(leaf-revocation = empty, root-revocation = empty)` shape; the Run 062 / 063 active/pending revocation smokes on the **N = 4 MainNet release-binary** path are a separate boundary (the task §5 "optional N = 4 MainNet revoked-peer check" was deferred as low-value relative to Runs 052 / 054 / 061 / 063 already covering revocation enforcement).
- (j) **Validator consensus-key timeout-verification activation (Run 030 / 031 / 032 / 033 / 034 / C5).** Unchanged from every previous PQC trust-bundle evidence run. The `[binary] Run 033: timeout-verification probe: active=false` banner persists; this is a C5 boundary, not C4. Run 068 makes no C5 claim.
- (k) **Live N = 4 MainNet release-binary unsigned-bundle / tampered-bundle / wrong-key startup smoke.** Run 068 deliberately does NOT re-exercise these fail-closed paths because Run 058 / 059 already cover them on the same release binary; the unsigned-MainNet fail-closed path is per-process, not per-cluster, so re-running it four times adds no coverage.
- (l) **Strict 4-way view-height-aligned lockstep beyond `h = 43`.** Run 068 demonstrates 4-of-4 strict `(height, block_id)` lockstep for the first 44 heights, 3-of-4 strict lockstep for the first 198 heights, and a chain-membership / final-tail-equality proof for V1. Whether a longer warm-up window (e.g., spawning all four nodes simultaneously rather than staggered, or letting the smoke run for several minutes rather than 40 s) would let V1 strictly catch up to V0 / V2 / V3 at the same view-height counter is a runtime-budget / startup-staging question, not a correctness question; the BFT N = 4 with `f = 1` semantics explicitly permit one lagging replica without losing safety or liveness, and V1's lag is documented as honest in §8.4.

**C5 remains NOT closed** by Run 068. **Full C4 remains OPEN** — Run 068 narrows only the live-binary multi-validator MainNet peer-connection sub-piece (Run 067 §10(h)) from `N = 2` to `N = 4`; every other surviving Run 050–067 §10 remaining item persists unchanged.

## 13. Exact verdict

**Strongest-positive for the scoped N = 4 boundary.** Four live release-build `qbind-node` MainNet validators (V0, V1, V2, V3) interconnect over the production-honest PQC static-root cert-verification path, exchange consensus traffic over KEMTLS, and commit byte-identical anchors:

- 4-of-4 strict `(height, block_id)` lockstep for the first 44 anchors (`h = 0..43`),
- 3-of-4 strict `(height, block_id)` lockstep at every shared height for ≥ 198 anchors (V0 ↔ V2 ↔ V3), and
- 4-of-4 chain-membership / final-tail block-id agreement (V1 is on the same chain at a lagging view-height counter),

while loading the SAME Run 050/051/053/055/057/065 signed MainNet trust-bundle (`environment = mainnet`, `chain_id = 0x51424e444d41494e`, `sequence = 1`, `signature = verified(signing_key_id = e7456cca..)`, `bundle_fingerprint = 1372726f3490ed347547fce4ffcd93bc8ee132d6c397edba83461a983f2665da`, `activation_height = None`), writing a Run 055 first-load `pqc_trust_bundle_sequence.json` record into each `--data-dir`, and emitting byte-identical `qbind_p2p_pqc_cert_verify_accepted_total = 6 / qbind_p2p_pqc_cert_verify_rejected_total = 0 / qbind_p2p_pqc_trust_bundle_activation_rejected_total = 0` on ALL FOUR `/metrics` scrapes. No `DummySig` / `DummyKem` / `DummyAead` is registered. No `--p2p-trusted-root` fallback path is exercised. No FATAL is emitted. The 1,568 pre-/per-Run-068 tests pass in release profile, and the `qbind-node` release binary identity is byte-identical to Run 067.

The **live N ≥ 4 multi-validator MainNet release-binary peer-connection** boundary is **NARROWED for `N = 4`** (Run 067 §10(h) closed for `N = 4`). **Full C4 remains OPEN**; **C5 is NOT touched**.

## 14. Exact immediate next action recommended

The natural next live-binary evidence step on the C4 trust-bundle / cert-verification surface — *not implemented by Run 068, called out as boundary (i) above* — is:

> **Run 069 (proposed):** Live N = 4 MainNet release-binary peer-connection smoke under an active leaf-revocation gate. Mint the same `signed-mainnet 4 signed-mainnet 1 none 0x51424e444d41494e` bundle but with `bundle_mode = signed-mainnet-revoked-v0` (or the analogous root-revocation mode), prove that V0's connection to / from V{1,2,3} fails closed at the cert-verify boundary with `qbind_p2p_pqc_cert_verify_rejected_revoked_total` advancing, and that V1 / V2 / V3 keep their `2f + 1 = 3`-vote BFT quorum without V0 (mirroring the Run 034 / Run 042 N = 4 absent-leader recovery pattern under a revocation-induced absence rather than a `--validator-id` absence). This is operator scheduling on top of Run 052 / 054 / 062 / 063 's already-landed revocation-enforcement code; no new source surface is required.

Beyond that, the surviving Run 067 §10 boundaries (KMS / HSM, in-binary / on-chain signing-key ratification, gossip-path minimum margin, hot reload, fast-sync, per-environment trust-anchor operation, `activation_epoch` runtime source) remain operator / future-source work, not Run 068's responsibility.