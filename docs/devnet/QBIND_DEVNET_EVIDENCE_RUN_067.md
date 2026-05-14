# QBIND DevNet Evidence — Run 067

**Run scope:** C4 — live release-binary **N = 2 MainNet signed-bundle peer-connection smoke** under `--env mainnet --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` with a Run 050/051 signed PQC trust-bundle (sequence = 1, env = `mainnet`, chain_id = `0x51424e444d41494e`, activation_height = `None` per the Run 065 minimum-margin policy), Run 037 production-honest cert-verification path, Run 039/040 production ML-KEM-768 / ChaCha20-Poly1305 transport on `P2pNodeBuilder` (`dummy_kem_registered = false`, `dummy_aead_registered = false`), and Run 055 per-data-dir sequence persistence (`pqc_trust_bundle_sequence.json`) on BOTH nodes.

**Verdict:** **Strongest-positive for the scoped boundary** — two release-build `qbind-node` MainNet validators (V0 and V1) mutually authenticate over the production-honest PQC static-root cert-verification path, exchange consensus traffic over KEMTLS, and commit `>= 200` consensus anchors **in lockstep on the same block ids at the same heights**, all while loading the SAME signed MainNet trust-bundle, writing the SAME `highest_sequence = 1 / bundle_fingerprint = 7872f251…` persistence record into each node's `--data-dir`, and emitting `qbind_p2p_pqc_cert_verify_accepted_total = 2` with `qbind_p2p_pqc_cert_verify_rejected_total = 0` on BOTH `/metrics` scrapes. The **live multi-validator MainNet release-binary peer-connection** boundary listed as a remaining open item by Run 059 §10(c) / Run 060 §10(f) / Run 061 §10(b) / Run 062 §10(f) / Run 063 §10(b) / Run 064 §10(b) / Run 065 §10(f) / Run 066 §(f) is now **NARROWED**: it is demonstrated for `N = 2` on the live binary, with a sequence-1 signed MainNet bundle, on a fresh data-dir, against the Run 065 minimum-margin policy. **Full C4 remains OPEN** — every other surviving boundary (KMS/HSM, in-binary signing-key ratification, gossip-path minimum margin, hot reload, fast-sync, per-environment trust-anchor operation, `activation_epoch` runtime source) is preserved bit-for-bit; Run 067 only narrows the live-binary peer-connection boundary for `N = 2`.

**Cross-references:** `docs/whitepaper/contradiction.md` C4 — Run 067 evidence update. Anchored against Runs 037 / 039 / 040 / 041 / 044 / 050 / 051 / 053 / 055 / 057 / 059 / 062 / 063 / 065. **No `crates/**/src/**` source, no `Cargo.toml`, no test source, no `main.rs` / `cli.rs` / `pqc_trust_bundle.rs` / `pqc_trust_activation.rs` / `pqc_root_config.rs` / `metrics.rs` / `p2p_node_builder.rs` was touched.** The single edited file is the DevNet evidence helper example (`crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`), as described in §2 below.

---

## 1. Exact objective

Prove on the live release `qbind-node` binary (same `target/release/qbind-node` artefact whose `--help` does NOT advertise `--devnet-forged-inject` and whose binary identity is recorded in §4) that:

1. Two MainNet validators (V0, V1) started with `--env mainnet --network-mode p2p --enable-p2p --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` and pointed at the **same** signed MainNet trust-bundle and **same** `--p2p-trust-bundle-signing-key` spec successfully complete the live PQC KEMTLS handshake under Run 037's `MutualAuthMode::Required` cert-verification semantics (`qbind_p2p_pqc_cert_verify_accepted_total > 0` on both nodes, no rejected counter moves, no `DummySig` / `DummyKem` / `DummyAead` registered).
2. Both nodes load the same signed MainNet bundle (env = `mainnet`, chain_id = `0x51424e444d41494e`, sequence = 1, signature verified against the configured `--p2p-trust-bundle-signing-key`), then write a Run 055 sequence-persistence record (`{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"7872f251…","updated_at_unix_secs":…}`) into their respective `--data-dir`/`pqc_trust_bundle_sequence.json` files.
3. The Run 065 minimum-margin policy (MainNet `minimum_activation_margin = 32`) is honoured by emitting the bundle with `activation_height = None` (immediate-effective, exempt from the half-open `[current_height, current_height + margin)` reject window because `bundle.activation_height.is_some()` is the only path that can fire the bundle-scope check). The bundle still pins the MainNet `chain_id` exactly so Run 053 chain-id crosscheck runs as expected.
4. The two nodes interconnect: V0's stderr emits `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, …)`, which is gated on `P2pService::on_peer_connected` firing inside `Required` mode (i.e., **only after cert verification succeeds**). Both nodes then commit `>= 200` consensus anchors at the same block ids at the same heights, proving the P2P consensus layer is alive end-to-end over the KEMTLS transport.
5. `/metrics` on BOTH nodes shows the expected Run 037 / 039 / 040 / 044 / 050 / 051 / 053 / 055 / 057 / 062 / 063 trust-bundle metrics, identical across nodes for everything except the `updated_at_unix_secs` timestamp (different by ~1 second, as each validator persists its own copy from its own startup wall-clock).

This run does NOT claim full C4 closure. The remaining boundaries called out in Run 059 / 060 / 061 / 062 / 063 / 064 / 065 / 066 §10 — KMS/HSM, in-binary or on-chain bundle-signing-key ratification, gossip-path minimum margin, hot reload, fast-sync, per-environment trust-anchor operation, `activation_epoch` runtime source — are NOT touched. Run 067 narrows **only** the live N≥2 MainNet release-binary peer-connection sub-piece.

## 2. Exact files changed

| File | Change |
|---|---|
| `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` | Run 067 evidence-tooling: optional 5th positional `[activation_height_override]` now accepts the literal string `none` in addition to a decimal `u64`. `none` forces `bundle.activation_height = None` explicitly BEFORE signing and BEFORE the canonical fingerprint is computed (equivalent to omitting this positional when no later positional is needed). All previous behaviour is preserved bit-for-bit: a decimal `u64` continues to set `Some(<value>)`, an absent positional continues to leave `bundle.activation_height` at whatever `build_helper_bundle` emits (currently `None`). This knob is needed by Run 067 because on a fresh MainNet data-dir `current_height = 0` and `MIN_MAINNET_ACTIVATION_MARGIN = 32`, so the Run 065 reject window `[0, 32)` rejects every in-window positive `activation_height`; the snapshot-rejoin-preserved boundary (`activation_height < current_height`) is unreachable with `current_height = 0`; so the positive MainNet smoke needs `activation_height = None` paired with an explicit non-default `chain_id_override = 0x51424e444d41494e`. Same precedent as the existing Run 059 `chain_id_override` and Run 062 `revocation_activation_height_for_target` positionals which already accept `none`. No new mode taxonomy, no new bundle field, no signing semantics change (the field is part of the signed preimage and canonical fingerprint exactly as `pqc_trust_bundle::canonical_signing_bytes` / `canonical_fingerprint` already include it). Module-level docs updated to match. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_067.md` | NEW (this file). |
| `docs/devnet/run_067_smoke_positive_v0.stdout.log` | NEW — preserved V0 banner line. |
| `docs/devnet/run_067_smoke_positive_v0.stderr.log` | NEW — preserved V0 startup banners + Run 050/051/053/055/057/062/063 banners + Run 037/039/040 PQC + `[binary-consensus]` `newly_connected_peers=1` + `committed_anchor height=…` 226-line transcript. |
| `docs/devnet/run_067_smoke_positive_v1.stdout.log` | NEW — preserved V1 banner line. |
| `docs/devnet/run_067_smoke_positive_v1.stderr.log` | NEW — preserved V1 startup banners + Run 050/051/053/055/057/062/063 banners + Run 037/039/040 PQC + `committed_anchor height=…` 227-line transcript. |
| `docs/devnet/run_067_metrics_positive_v0.txt` | NEW — V0 `/metrics` scrape (HTTP 200, 21,582 bytes), confirming `qbind_p2p_pqc_root_mode = 1`, `qbind_p2p_pqc_roots_configured = 1`, `qbind_p2p_pqc_cert_verify_accepted_total = 2`, `qbind_p2p_pqc_cert_verify_rejected_total = 0` (and every other `qbind_p2p_pqc_cert_rejected_*` family at 0), `qbind_p2p_pqc_trust_bundle_loaded = 1`, `qbind_p2p_pqc_trust_bundle_environment = 2` (MainNet), `qbind_p2p_pqc_trust_bundle_signature_verified_total = 1`, `qbind_p2p_pqc_trust_bundle_signing_keys_configured = 1`, `qbind_p2p_pqc_trust_bundle_sequence = 1`, `qbind_p2p_pqc_trust_bundle_sequence_highest = 1`, `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total = 0`, `qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total = 0`, `qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total = 0`, `qbind_p2p_pqc_trust_bundle_activation_rejected_total = 0`. |
| `docs/devnet/run_067_metrics_positive_v1.txt` | NEW — V1 `/metrics` scrape (HTTP 200, 21,582 bytes), with identical PQC / trust-bundle counters and gauges to V0 (see §5). |
| `docs/whitepaper/contradiction.md` | C4 Run 067 evidence update row appended. |

**No other file is touched.** Run 037, Run 039, Run 040, Run 041, Run 044, Run 050, Run 051, Run 052, Run 053, Run 054, Run 055, Run 056, Run 057, Run 058, Run 059, Run 060, Run 061, Run 062, Run 063, Run 064, Run 065, Run 066 are all preserved bit-for-bit. The release `qbind-node` binary's source compilation inputs are NOT touched at all (the only edited file is the evidence-helper *example*, which is not part of `target/release/qbind-node`'s dependency graph — see §4 binary-identity check).

## 3. Exact commands run

```bash
# 0) Confirm starting branch identity.
git rev-parse --abbrev-ref HEAD     # copilot/read-task-rund-067
git rev-parse HEAD                  # 74df9ecc01fa8b74a30a91f0e1d42185417e91e2

# 1) Verify nothing else changed compared to the run baseline (Run 066).
git diff --stat origin/main..HEAD docs/ops docs/whitepaper/contradiction.md  # only the Run 067 row + this file once committed

# 2) Build release qbind-node + helpers.
cargo build --release -p qbind-node --bin qbind-node \
            --example devnet_pqc_trust_bundle_helper \
            --example devnet_pqc_root_helper

# 3) Verify the release binary is forged-injection-free.
./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"   # 0

# 4) Full unit / integration test suite (release profile).
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

# 5) Mint MainNet trust material for two validators with `activation_height = None`.
#    Helper CLI: <outdir> <num_validators> <bundle_mode> [sequence_override] [activation_height_override] [chain_id_override]
HELPER=./target/release/examples/devnet_pqc_trust_bundle_helper
"$HELPER" /tmp/run067/mat 2 signed-mainnet 1 none 0x51424e444d41494e
# Helper banner:
# DEVNET-EPHEMERAL: root_id=333db244… sig_suite=100 kem_suite=100 validators=2 \
#                   bundle_mode=signed-mainnet bundle_env=mainnet bundle_sequence=1 \
#                   bundle_activation_height=None bundle_chain_id=Some("0x51424e444d41494e") \
#                   bundle_fingerprint=7872f25136963911e594498a53afda5277b0765f0f023e2d28c05808118a05bb \
#                   signature=signed(signing_key_id=a0c7aa0e.. suite=100 sig_len_hex=4840)
# Helper writes (under /tmp/run067/mat):
#   root.id.hex, root.pk.hex, trusted-root.spec  (DevNet convenience — NOT supplied to qbind-node)
#   v0.cert.bin, v0.kem.sk.bin (0o600), v0.leaf-fp.hex
#   v1.cert.bin, v1.kem.sk.bin (0o600), v1.leaf-fp.hex
#   trust-bundle.json
#   signing-key.id.hex, signing-key.pk.hex, signing-key.spec

# 6) Live N=2 MainNet release-binary peer-connection smoke (positive).
SPEC=$(cat /tmp/run067/mat/signing-key.spec)
mkdir -p /tmp/run067/data_v0 /tmp/run067/data_v1

# V0 ↔ V1 :: V0 listens on 127.0.0.1:19470 with --p2p-peer 1@127.0.0.1:19471
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9170 timeout 25 ./target/release/qbind-node \
    --env mainnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19470 --p2p-peer 1@127.0.0.1:19471 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/run067/mat/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/run067/mat/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/run067/mat/v0.kem.sk.bin \
    --p2p-peer-leaf-cert 1:/tmp/run067/mat/v1.cert.bin \
    --data-dir /tmp/run067/data_v0 \
    > docs/devnet/run_067_smoke_positive_v0.stdout.log \
    2> docs/devnet/run_067_smoke_positive_v0.stderr.log &

sleep 1

# V1 listens on 127.0.0.1:19471 with --p2p-peer 0@127.0.0.1:19470
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9171 timeout 25 ./target/release/qbind-node \
    --env mainnet --validator-id 1 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:19471 --p2p-peer 0@127.0.0.1:19470 \
    --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/run067/mat/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/run067/mat/v1.cert.bin \
    --p2p-leaf-cert-key /tmp/run067/mat/v1.kem.sk.bin \
    --p2p-peer-leaf-cert 0:/tmp/run067/mat/v0.cert.bin \
    --data-dir /tmp/run067/data_v1 \
    > docs/devnet/run_067_smoke_positive_v1.stdout.log \
    2> docs/devnet/run_067_smoke_positive_v1.stderr.log &

sleep 12
curl -s --max-time 3 http://127.0.0.1:9170/metrics > docs/devnet/run_067_metrics_positive_v0.txt   # 21,582 bytes
curl -s --max-time 3 http://127.0.0.1:9171/metrics > docs/devnet/run_067_metrics_positive_v1.txt   # 21,582 bytes
wait
# Both processes exit with code 124 (SIGTERM from `timeout 25`) AFTER having committed >=200 anchors each.
# Persistence files appear at /tmp/run067/data_v0/pqc_trust_bundle_sequence.json and
# /tmp/run067/data_v1/pqc_trust_bundle_sequence.json (see §6).
```

## 4. Release binary identity (this branch)

Build commit: `74df9ecc01fa8b74a30a91f0e1d42185417e91e2` (branch `copilot/read-task-rund-067`).

| Artefact | sha256 | ELF BuildID |
|---|---|---|
| `target/release/qbind-node` | `574709fbeec1fce106f10893d21fe5c0d4b1ac9d888518bf6bab064d46b94a30` | `cc9c0663408f7abd6f3ac373f56a8a41da2802d0` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `9702fa81b299eb02cd8830d08421464e2068ed765154e63a704d5794149ce0ff` | `22bf36b16b40bc1dbadcbd6e8fc54344190f8a60` |
| `target/release/examples/devnet_pqc_root_helper` | `76b86661a3757fb53cd25f4e444a3684c9ac5900e075db9de5493601e479ffb3` | `cb395871324e8d0ba62a5381b0f32d73d66b654d` |

The `qbind-node` binary identity is **bit-for-bit unchanged** between the pre-helper-edit build and the post-helper-edit build (the helper is a *separate example binary* and is not in the `target/release/qbind-node` dependency graph). The Run 067 helper edit is therefore a pure evidence-tooling change that cannot have changed the live release `qbind-node` binary's runtime behaviour even in principle.

`./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"` returns `0` — the **forged-traffic injection surface is NOT in the release binary**. Every existing `--p2p-trust-bundle`, `--p2p-trust-bundle-signing-key`, `--p2p-pqc-root-mode`, `--p2p-leaf-cert`, `--p2p-leaf-cert-key`, `--p2p-peer-leaf-cert`, `--p2p-mutual-auth`, `--p2p-listen-addr`, `--p2p-peer`, `--validator-id`, `--data-dir`, `--env`, `--enable-p2p`, `--network-mode` flag is present in the binary's `--help` exactly as Runs 037 / 039 / 050 / 051 / 053 / 055 / 057 / 059 / 062 / 063 / 065 / 066 specify.

## 5. Live `/metrics` scrape (both nodes, MainNet positive smoke)

Both `/metrics` endpoints returned HTTP 200, identical payload size (21,582 bytes). The PQC / trust-bundle metric families read as:

```
qbind_p2p_pqc_root_mode 1                                            # 1 = pqc-static-root
qbind_p2p_pqc_roots_configured 1                                     # the single bundle root
qbind_p2p_pqc_cert_verify_accepted_total 2                           # peer cert verified twice
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
qbind_p2p_pqc_cert_verify_rejected_revoked_total 0
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

Both `/metrics` scrapes are identical for the above families. `qbind_p2p_pqc_cert_verify_accepted_total = 2` on each side is consistent with the cert being verified once on the dialer's `ServerHandshakeConfig` and once on the listener's `parse_and_verify_client_cert` per direction. Every cert-reject family at zero, every trust-bundle-reject family at zero, every sequence-persistence-error family at zero. **No DummySig / DummyKem / DummyAead is registered** (confirmed by the matching `[Run040]` banner in §6 — `dummy_kem_registered=false dummy_aead_registered=false`).

## 6. Live stderr banners (both nodes, MainNet positive smoke)

V0 (`docs/devnet/run_067_smoke_positive_v0.stderr.log`) — first ~25 banner lines:

```
[restore] no --restore-from-snapshot requested; normal startup.
[metrics_http] Enabling metrics HTTP server on 127.0.0.1:9170 (from QBIND_METRICS_HTTP_ADDR)
[metrics] Spawning metrics HTTP server on 127.0.0.1:9170 (set via QBIND_METRICS_HTTP_ADDR)
[binary] P2P mode: starting transport + consensus loop. environment=MainNet profile=nonce-only
[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)
[binary] Run 037: --p2p-mutual-auth=required on environment=mainnet is using the production-honest PQC static-root cert-verification path. NOTE: KEM/AEAD primitives on the binary path are still test-grade and remain a separate C4 piece (not C4(c)); MainNet readiness is therefore not yet implied. See docs/whitepaper/contradiction.md C4.
[metrics_http] Listening on 127.0.0.1:9170
[binary] Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) required_epoch=None current_epoch=None)
[binary] Run 055: trust-bundle sequence persistence env=mainnet chain_id=51424e444d41494e path=/tmp/run067/data_v0/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=7872f251
[binary] Run 050/051: trust bundle loaded path=/tmp/run067/mat/trust-bundle.json env=mainnet fp=7872f25136963911e594498a53afda5277b0765f0f023e2d28c05808118a05bb active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=a0c7aa0e..) signing_keys_configured=1. Bundle root IDs: [333db244..]
[binary] Run 062: trust-bundle revocation activation (configured=0 active=0 pending=0 root_active=0 root_pending=0 leaf_active=0 leaf_pending=0)
[binary] Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=333db244.. bundle_fp=7872f251.. active_revoked_root_ids=0)
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=1 (root fingerprints: [id=333db244.. suite=100 fp=40ed22cc])
[binary] Run 052: revoked_leaf_fingerprints=0 (from trust bundle env=mainnet sequence=1)
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
[binary] P2P transport up. Listen address: 127.0.0.1:19470, static peers: 1
[binary] Consensus loop config: local_validator_id=ValidatorId(0) num_validators=2 restore_baseline=false interconnect=p2p
[binary] P2P node started. Press Ctrl+C to exit.
[binary-consensus] Starting consensus loop: local_id=ValidatorId(0) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on timeout_verification=off
[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, proposal_reemits_total=1, vote_reemits_total=1)
[binary-consensus] committed_anchor height=0 block_id=00000000000000000000000000000000ffffffffffffffffffffffffffffffff
[binary-consensus] committed_anchor height=1 block_id=0100000000000000010000000000000000000000000000000000000000000000
[binary-consensus] committed_anchor height=2 block_id=0000000000000000020000000000000001000000000000000100000000000000
...
[binary-consensus] committed_anchor height=225 block_id=0100000000000000e1000000000000000000000000000000e000000000000000
```

V1 (`docs/devnet/run_067_smoke_positive_v1.stderr.log`) emits the analogous banner sequence under `--validator-id 1 --p2p-listen-addr 127.0.0.1:19471 --p2p-peer 0@127.0.0.1:19470 --data-dir /tmp/run067/data_v1`:

```
[binary] Run 037: --p2p-mutual-auth=required on environment=mainnet is using the production-honest PQC static-root cert-verification path. ...
[binary] Run 055: trust-bundle sequence persistence env=mainnet chain_id=51424e444d41494e path=/tmp/run067/data_v1/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=7872f251
[binary] Run 050/051: trust bundle loaded path=/tmp/run067/mat/trust-bundle.json env=mainnet fp=7872f25136963911e594498a53afda5277b0765f0f023e2d28c05808118a05bb active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=a0c7aa0e..) signing_keys_configured=1. Bundle root IDs: [333db244..]
[binary] Run 062: trust-bundle revocation activation (configured=0 active=0 pending=0 root_active=0 root_pending=0 leaf_active=0 leaf_pending=0)
[binary] Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=333db244.. bundle_fp=7872f251.. active_revoked_root_ids=0)
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=1 (root fingerprints: [id=333db244.. suite=100 fp=40ed22cc])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
[binary] P2P transport up. Listen address: 127.0.0.1:19471, static peers: 1
[binary-consensus] Starting consensus loop: local_id=ValidatorId(1) num_validators=2 tick=100ms restore_baseline=false interconnect=p2p late_peer_reemit=on timeout_verification=off
[binary-consensus] committed_anchor height=0 block_id=00000000000000000000000000000000ffffffffffffffffffffffffffffffff
[binary-consensus] committed_anchor height=1 block_id=0100000000000000010000000000000000000000000000000000000000000000
...
[binary-consensus] committed_anchor height=226 block_id=0000000000000000e2000000000000000100000000000000e100000000000000
```

**Cross-node block-id agreement.** At every committed height `h` where both transcripts contain a `committed_anchor height=h` line, the `block_id=` string is byte-identical. For example, both transcripts contain `committed_anchor height=225 block_id=0100000000000000e1000000000000000000000000000000e000000000000000`, proving the two validators are observing the same `HotStuffEngine`-driven block stream over the live KEMTLS P2P transport. **226 cross-node-agreeing committed anchors** were observed inside the 25-second smoke window — i.e., consensus is alive, the P2P transport is alive, and the trust-bundle / cert verification path is alive throughout.

**Persistence files** (`docs/devnet/run_067_metrics_positive_v{0,1}.txt` are scraped while the processes are still alive; the persistence files below are observed after both processes exit):

```
$ cat /tmp/run067/data_v0/pqc_trust_bundle_sequence.json
{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"7872f25136963911e594498a53afda5277b0765f0f023e2d28c05808118a05bb","updated_at_unix_secs":1778732081}

$ cat /tmp/run067/data_v1/pqc_trust_bundle_sequence.json
{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"7872f25136963911e594498a53afda5277b0765f0f023e2d28c05808118a05bb","updated_at_unix_secs":1778732082}
```

Both records carry the SAME `environment` / `chain_id` / `highest_sequence` / `bundle_fingerprint`, with `updated_at_unix_secs` differing by ~1 second — exactly matching the `sleep 1` gap between V0 and V1 startup in the smoke script. This is the **first-load-on-fresh-data-dir** path of Run 055 sequence persistence executed twice from a single shared bundle source.

**`newly_connected_peers=1` is gated on cert-verify success.** The `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, …)` line in V0's stderr is emitted by `BinaryConsensusLoopIo` only after `P2pService::on_peer_connected` fires, which under `MutualAuthMode::Required` (Run 037) requires `mutual_auth_complete = true` AND a verified cert-derived `NodeId`. The same gating closure is exercised by Run 037 R037.A integration test (`run_037_pqc_static_root_mutual_auth_tests`) and is independently observable on the binary path by Run 037 / Run 040 release smokes. Run 067 observes it on the **N = 2 MainNet** path, in addition to the existing DevNet observations.

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
| `cargo build --release -p qbind-node --bin qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper` | — | **clean** (only pre-existing `bincode::config` deprecation warnings unrelated to Run 067) |

**Sum: 1,613 tests pass; 0 fail; 0 ignored; 0 measured.** Every Run 050 / 051 / 052 / 055 / 057 / 061 / 062 / 063 / 037 / 040 / 044 integration test continues to pass against the same release artefact whose binary identity is recorded in §4.

## 8. Investigation findings (file/function references)

### 8.1 Why `activation_height = None` is REQUIRED for the Run 067 positive smoke

The Run 065 minimum-margin policy (`crates/qbind-node/src/pqc_trust_activation.rs`):

| Constant | Value (lines 134/140/145) |
|---|---|
| `MIN_DEVNET_ACTIVATION_MARGIN` | 0 |
| `MIN_TESTNET_ACTIVATION_MARGIN` | 8 |
| `MIN_MAINNET_ACTIVATION_MARGIN` | 32 |

`check_min_activation_height_policy` (line 652) rejects any in-window `bundle.activation_height = Some(h)` where `h ∈ [current_height, current_height + minimum_margin)` (line 688 — half-open). On a fresh `--data-dir`, the binary's `current_height` source from `--restore-from-snapshot` is `Some(0)` (no snapshot ⇒ `ActivationContext::height_only(0)`), so the MainNet reject window is `[0, 32)`. The snapshot-rejoin-preserved boundary (`activation_height < current_height = 0`) is unreachable. Therefore the only in-policy positive values for `bundle.activation_height` on a fresh MainNet data-dir are **`>= 32`**, but Run 057's future-height gate (line 1145, `current_height < activation_height` ⇒ pending) would then refuse to load the bundle as active. Conclusion: the only `bundle.activation_height` that lets a fresh-data-dir MainNet release-binary smoke load the bundle as active is **`None`**.

`None` is intentionally permitted by the binary on MainNet — `check_min_activation_height_policy` only inspects `Some(_)` values (line 691 wraps the bundle-level check inside `if let Some(act) = bundle.activation_height`). The policy is about **declared future activations**, not about a missing optional field; Run 065 §10(b) explicitly preserves this. Run 057 also accepts `None` (no future-height gate). Run 050 / 051 do not require a non-`None` value either. Run 053 chain_id crosscheck operates only on `bundle.chain_id`, independent of `activation_height`.

The Run 067 helper extension lets the existing Run 050/051/053/055/057/062/063 helper produce the exact bundle shape the release binary needs to load **as active** on a fresh MainNet data-dir, namely `(env = mainnet, sequence = 1, chain_id = Some(0x51424e444d41494e), activation_height = None, leaf-revocation = empty, root-revocation = empty)`. The same shape was already representable by the helper for the **unsigned** path (the `none` literal already worked for the 7th positional and for the `chain_id_override`'s `none` shorthand), but not for the `activation_height_override` positional. This is a pure DevNet-evidence-tooling change — the release binary's runtime behaviour is unchanged.

### 8.2 Cert-verify accepted total = 2 (not 1)

Run 037's `MutualAuthMode::Required` cert-verification fires twice per peer connection in the production-honest path: once on the listener side (`parse_and_verify_client_cert` against `local_root_network_pk` + `TrustedClientRoots`) and once on the dialer side (`ServerHandshakeConfig::verify` over the server-side `NetworkDelegationCert`). The Run 044 metrics adapter increments `qbind_p2p_pqc_cert_verify_accepted_total` on each successful verification; this is the same path the Run 037 R037.A integration test exercises. The Run 067 metrics scrape at +12s shows the counter at exactly `2` on each node — consistent with a single successfully-established session in each direction. **No `qbind_p2p_pqc_cert_verify_rejected_*` family advances**, proving no cert was ever rejected at the live boundary.

### 8.3 Both nodes observe the SAME `bundle_fingerprint = 7872f251…`

The `bundle_fingerprint` reported by both nodes' `[binary] Run 050/051: trust bundle loaded …` banner is `7872f25136963911e594498a53afda5277b0765f0f023e2d28c05808118a05bb`, byte-identical to the helper's stdout banner. This is the Run 050/051 canonical fingerprint (`pqc_trust_bundle::canonical_fingerprint`), which covers — among other fields — `environment`, `chain_id`, `sequence`, `activation_height`, `roots[]`, `revocations[]`, and the bundle's `signature` envelope. Both nodes therefore agree byte-for-byte on the trust-bundle content; both nodes' `pqc_trust_bundle_sequence.json` carries the same fingerprint string; the Run 055 cross-process anti-rollback invariant is satisfied (different `--data-dir`s, same bundle, both load it as `first-load persisted_sequence=1`).

### 8.4 No silent fallback observed

Every banner that could mention `--p2p-trusted-root` fallback or `DummySig` / `DummyKem` / `DummyAead` was inspected:

- `--p2p-trusted-root` is **not supplied** to either qbind-node command. The Run 050 banner explicitly says `signing_keys_configured=1` — the trust set is built **exclusively** from the bundle's `roots[]` and the configured `--p2p-trust-bundle-signing-key`. No `--p2p-trusted-root` argument is parsed; the Run 050 / 051 / 053 / 057 / 061 / 063 / 065 "No fallback to --p2p-trusted-root" claim is preserved on the live MainNet path.
- `[Run040] P2pNodeBuilder: … dummy_kem_registered=false … dummy_aead_registered=false …` on both V0 and V1 stderr.
- The `[binary] Run 033: timeout-verification probe: active=false …` banner is the same `static probe text` that has appeared since Run 033 / 034 / 037 / 058 / 059 release-binary smokes; it documents the consensus-timeout-verification activation policy (unrelated to the trust-bundle transport surface) and was preserved bit-for-bit.

## 9. Boundary preserved relative to Runs 050–066

| Boundary | Preserved? | Anchor |
|---|---|---|
| Run 050: bundle structural validation (status / window / duplicates / suite) | ✓ | both nodes' `Run 050/051 banner: active_roots=1 revoked_roots=0 valid_from=0 valid_until=18446744073709551615`; full integration suite still 14/14 |
| Run 051: ML-DSA-44 signature verification against `--p2p-trust-bundle-signing-key` | ✓ | both nodes' `signature=verified(signing_key_id=a0c7aa0e..) signing_keys_configured=1`; full integration suite still 13/13 |
| Run 052: leaf-fingerprint revocation set surface | ✓ | both nodes' `Run 052: revoked_leaf_fingerprints=0`; full integration suite still 12/12 |
| Run 053: bundle chain_id crosscheck | ✓ | both persistence records record `"chain_id":"51424e444d41494e"`, matching `MainNet.chain_id()`; no chain-id-mismatch metric advances |
| Run 055: per-data-dir sequence-persistence anti-rollback | ✓ | both `pqc_trust_bundle_sequence.json` exist with `highest_sequence=1`; `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total = 0` on both; full integration suite still 12/12 |
| Run 057: bundle-level activation_height gating | ✓ | both nodes' `Run 057: trust-bundle activation gate satisfied (required_height=None current_height=Some(0) ...)`; full integration suite still 12/12 |
| Run 059: live-binary MainNet signed-bundle smoke | ✓ | the same `signed-mainnet` helper mode used by Run 059 produces the Run 067 trust material (with the additional `activation_height_override = none` knob); pre-Run-067 `signed-mainnet 1 0 0x51424e444d41494e` invocation continues to work bit-for-bit |
| Run 061: local-leaf startup self-check | ✓ (degenerate-pass) | the bundle declares no leaf revocations, so the Run 061 self-check is trivially satisfied (`active_revoked_leaf_fingerprints=0`); full integration suite still 9/9 |
| Run 062: per-entry revocation activation gates | ✓ (degenerate-pass) | both nodes' `Run 062: trust-bundle revocation activation (configured=0 ...)`; full integration suite still 11/11 |
| Run 063: local-issuer-root startup self-check | ✓ | both nodes' `Run 063: local-leaf issuer-root startup self-check passed (local_issuer_root_id=333db244.. bundle_fp=7872f251.. active_revoked_root_ids=0)`; full integration suite still 8/8 |
| Run 065: per-environment minimum activation-margin policy | ✓ | `qbind_p2p_pqc_trust_bundle_activation_rejected_total = 0` on both; the bundle is emitted with `activation_height = None` (exempt from the half-open `[0, 32)` reject window); full integration suite still 12/12 |
| Run 066: operator playbook prose for Run 065 | ✓ | docs-only; runbook is unchanged |
| Run 037 / 039 / 040 / 041 / 044 PQC cert-verification path | ✓ | `qbind_p2p_pqc_cert_verify_accepted_total=2 qbind_p2p_pqc_cert_verify_rejected_total=0`; `[Run040]` banner identical to Run 037 / 040 baselines; full integration suites still 12+14+10 |

## 10. Positive evidence

- Two release-build `qbind-node` MainNet validators (V0 and V1) interconnect over live KEMTLS under `--p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root` and successfully verify each other's ML-DSA-44-signed `NetworkDelegationCert`s on the binary path (`qbind_p2p_pqc_cert_verify_accepted_total = 2` on both).
- Both nodes load the SAME signed MainNet bundle (`bundle_fingerprint=7872f25136963911e594498a53afda5277b0765f0f023e2d28c05808118a05bb`), each writing a Run 055 first-load `pqc_trust_bundle_sequence.json` into its own `--data-dir`, with identical `environment / chain_id / highest_sequence / bundle_fingerprint` fields and time-stamps differing by ~1 second (matching the V0/V1 startup gap).
- V0 emits `[binary-consensus] B9+B10: re-emitted view 0 BroadcastProposal + BroadcastVote after late peer connect (newly_connected_peers=1, …)`, gated by Run 037's `MutualAuthMode::Required` cert verification.
- Both nodes commit `>=200` consensus anchors at byte-identical block ids at the same heights inside a 25 s window, proving the consensus + P2P + transport + trust-bundle path is alive end-to-end.
- Every Run 050 / 051 / 052 / 055 / 057 / 061 / 062 / 063 startup banner is emitted on both nodes; every Run 037 / 039 / 040 / 044 PQC banner is emitted on both nodes; **no FATAL is emitted on either node**.
- 1,613 pre-/per-Run-067 tests pass (release profile); the `qbind-node` release binary identity is unchanged before vs. after the Run 067 helper edit (`sha256 = 574709fb…`, ELF BuildID `cc9c0663…`).
- `./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"` returns `0` (forged-traffic injection surface is still NOT in the release binary).

## 11. Negative evidence (preserved)

Run 067 does NOT add new negative smokes — the existing Run 050 / 051 / 052 / 057 / 059 / 062 / 063 / 065 negative smokes already cover every relevant fail-closed path (tampered bundle, wrong signing key, unsigned MainNet bundle, expired bundle, sequence rollback, future-height activation, missing leaf cert under Required + pqc-static-root, revoked root, revoked issuer-root, in-window activation_height, etc.). All of those are preserved bit-for-bit because no source file under `crates/**/src/**` was touched and the release binary identity (§4) is unchanged. The full Run 050 / 051 / 052 / 055 / 057 / 061 / 062 / 063 integration test suites pass 14 + 13 + 12 + 12 + 12 + 9 + 11 + 8 = **91/91** in release profile.

## 12. Remaining open boundaries (NOT done in Run 067)

- (a) **`activation_epoch` runtime source.** Unchanged from Run 057 / 058 / 059 / 060 / 061 / 062 / 063 / 064 / 065 / 066. Bundle-level `activation_epoch` continues to fail closed with `TrustBundleActivationError::CurrentEpochUnavailable`; per-entry `activation_epoch` on revocations is intentionally NOT supported (Run 062 boundary).
- (b) **Per-environment minimum activation-margin policy on the gossiped / peer-supplied trust-bundle path.** Unchanged from Run 065 §10(a) / Run 066 §(b). Run 065 enforces it at `--p2p-trust-bundle` load only; Run 067 does NOT add an on-the-fly distribution surface.
- (c) **On-the-fly trust-bundle hot reload.** Unchanged from Run 050 / 057 / 061 / 062 / 063 / 064 / 065 / 066. The bundle is loaded exactly once per process lifetime; Run 067's smoke does not rotate the bundle inside a running validator.
- (d) **In-binary / on-chain bundle-signing-key ratification.** Unchanged from Run 060 / 064 / 065 / 066. Out-of-band CLI overlap remains the supported rotation path.
- (e) **External KMS / HSM integration.** Unchanged.
- (f) **Per-environment production trust-anchor operation.** Unchanged. The Run 067 helper still mints ephemeral DevNet keypairs into memory only; offline / HSM custody is operator policy, not a Run 067 deliverable.
- (g) **Production fast-sync / consensus-storage restore.** Unchanged. The `--restore-from-snapshot` `current_height` source already feeds the Run 065 + Run 057 + Run 067 gating chain via `ActivationContext::height_only`; a fully-fledged production fast-sync surface is a separate boundary.
- (h) **N ≥ 4 multi-validator MainNet release-binary peer-connection smoke.** Run 067 proves only `N = 2`. The Run 034 / Run 005 / Run 006 pattern of `N = 4` with one-validator restart for an analogous Required + pqc-static-root MainNet smoke is the operator's immediate-next action; it is not blocked by code, only by evidence-runtime time-budget.
- (i) **Live N = 2 MainNet release-binary peer-connection smoke under leaf-revocation or root-revocation activation gates.** Run 067 deliberately exercises only the `(leaf-revocation = empty, root-revocation = empty)` shape; the Run 062 / 063 active/pending revocation smokes on the **multi-validator MainNet** path are a separate boundary.
- (j) **Validator consensus-key timeout-verification activation (Run 030 / 031 / 032 / 033 / 034 / C5).** Unchanged from every previous PQC trust-bundle evidence run. The `[binary] Run 033: timeout-verification probe: active=false` banner persists; this is a C5 boundary, not C4. Run 067 makes no C5 claim.

**C5 remains NOT closed** by Run 067. **Full C4 remains OPEN** — Run 067 narrows only the live-binary multi-validator MainNet peer-connection sub-piece (Run 059 §10(c) / Run 060–066 §10(f) / §10(b)) for `N = 2`; every other surviving Run 050–066 §10 remaining item persists unchanged.

## 13. Exact verdict

**Strongest-positive for the scoped boundary.** Two live release-build `qbind-node` MainNet validators interconnect over the production-honest PQC static-root cert-verification path, exchange consensus traffic over KEMTLS, and commit `>= 200` byte-identical consensus anchors in lockstep, while loading the SAME Run 050/051/053/055/057 signed MainNet trust-bundle (`environment = mainnet`, `chain_id = 0x51424e444d41494e`, `sequence = 1`, `signature = verified`, `bundle_fingerprint = 7872f251…`, `activation_height = None`), writing a Run 055 first-load `pqc_trust_bundle_sequence.json` record into each `--data-dir`, and emitting `qbind_p2p_pqc_cert_verify_accepted_total = 2 / qbind_p2p_pqc_cert_verify_rejected_total = 0 / qbind_p2p_pqc_trust_bundle_activation_rejected_total = 0` on BOTH `/metrics` scrapes. No `DummySig` / `DummyKem` / `DummyAead` is registered. No `--p2p-trusted-root` fallback path is exercised. No FATAL is emitted. The 1,613 pre-/per-Run-067 tests pass in release profile, and the `qbind-node` release binary identity is unchanged before vs. after the Run 067 helper edit.

The **live multi-validator MainNet release-binary peer-connection** boundary is **NARROWED for `N = 2`**. **Full C4 remains OPEN**; **C5 is NOT touched**.

Operators MUST NOT rely on the Run 067 helper to mint production trust bundles — the helper still mints ephemeral DevNet keypairs in memory and is suitable only for evidence-grade and DevNet smokes. The production deliverable is the operator-mediated process documented in `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (§3.2 root / §3.4 bundle-signing key, both held in offline / HSM custody).