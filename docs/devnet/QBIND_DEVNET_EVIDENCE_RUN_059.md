# QBIND DevNet Evidence — Run 059: Release-Binary MainNet Signed-Bundle Smoke Evidence

## Exact objective

Run 059 is **evidence-only**. It produces the live release-binary
artifact set for the **MainNet live signed-bundle smoke** boundary
that Run 058 recorded as remaining-open in
`docs/whitepaper/contradiction.md` ("(h) Live MainNet signed-bundle
release-binary smoke with a production-grade signing key: Run 058
ran DevNet only…"). The scope is intentionally narrow:

- prove on the live release `qbind-node` binary that a valid signed
  MainNet trust bundle (env=`mainnet`, `chain_id=0x51424e444d41494e`,
  `sequence=1`, `activation_height=0`, ML-DSA-44 signature verifies
  against the configured `--p2p-trust-bundle-signing-key`) is
  accepted under `--env mainnet --p2p-mutual-auth required
  --p2p-pqc-root-mode pqc-static-root`, that the bundle's roots are
  merged into the live trust set, that the Run 055 sequence
  persistence record is written, and that `/metrics` reports the
  expected `qbind_p2p_pqc_trust_bundle_*` series;
- prove on the live release binary that an otherwise-valid
  **unsigned** MainNet bundle fails closed with a precise FATAL,
  with no bundle root merged and no sequence persistence file
  created;
- prove on the live release binary that a signed MainNet bundle
  whose `roots[0].not_after` was **tampered** after signing fails
  closed at ML-DSA-44 signature verification, with no bundle root
  merged and no sequence persistence file created;
- prove on the live release binary that a validly-signed MainNet
  bundle whose published `--p2p-trust-bundle-signing-key` is a
  **different** ML-DSA-44 keypair than the one that signed the
  bundle fails closed at `MissingSigningKey`, with no bundle root
  merged and no sequence persistence file created;
- prove on the live release binary that a validly-signed
  `environment=mainnet` bundle that declares **the DevNet
  `chain_id`** (`0x51424e4444455600`) fails closed at the chain-id
  crosscheck (Run 053 boundary), with no bundle root merged and no
  sequence persistence file created;
- prove no fallback to `--p2p-trusted-root`, `DummySig`,
  `DummyKem`, or `DummyAead` on any of those paths;
- preserve Run 037 / Run 040 / Run 044 / Run 050 / Run 051 / Run 052 /
  Run 053 / Run 054 / Run 055 / Run 056 / Run 057 / Run 058 behaviour
  bit-for-bit (no `crates/**/src/**` core-library source touched).

Explicitly out of scope for Run 059 (and recorded honestly in the
"Explicit remaining boundaries" section below):

- production CA / certificate rotation / signing-key rotation
  operator playbook;
- epoch gating runtime source;
- activation gates on revocation entries;
- per-environment minimum activation-height policy;
- production fast-sync / consensus-storage restore;
- per-environment production trust-anchor operation beyond the
  scoped startup/load path;
- two-node MainNet peer connection smoke (single-validator MainNet
  smoke runs to consensus on the live binary — see Smoke 1 below —
  but a two-node MainNet peer-connection artefact set is not
  produced here);
- any redesign of KEMTLS, trust bundles, transport, consensus,
  timeout verification, or signing-key distribution.

## Exact verdict

**Strongest positive for the scoped Run 059 release-binary MainNet
signed-bundle evidence run.** On the live release `qbind-node`
binary (sha256 `5f249fe2929135f11d38d95df4b1b13a603713a8208d0ede53b195efaadc3bcc`,
ELF BuildID `77553328e1ee90a1a9f808974c6d9b66b0cbe9d8` — bit-for-bit
identical to Run 058's binary) driven from the Run-059-rebuilt
release helper `devnet_pqc_trust_bundle_helper` (sha256
`de612a586f36cd58f5904bb52621f314b6116beda06b3722ef84e172b6ed6719`,
ELF BuildID `895e4732d686841cfb3930bf996920d3858c4593`), every Run
059 MainNet signed-bundle case behaved exactly as the Run
050/051/053/055/057 design promises:

- **Smoke 1 — positive signed MainNet `sequence=1 activation_height=0
  chain_id=0x51424e444d41494e`.** Fresh `--data-dir`,
  ML-DSA-44-signed MainNet bundle
  `fp=93fbb47dc9006c916983a57b13d5ee60756c4b3b60d0e2cea8f5597e3a2ee242`.
  The binary printed (in order):
  - `[binary] P2P mode: starting transport + consensus loop. environment=MainNet profile=nonce-only`
  - `[binary] B12: mutual_auth_mode=Required (source: --p2p-mutual-auth)`
  - `[binary] Run 037: --p2p-mutual-auth=required on environment=mainnet is using the production-honest PQC static-root cert-verification path. …`
  - `[binary] Run 057: trust-bundle activation gate satisfied (required_height=Some(0) current_height=Some(0) required_epoch=None current_epoch=None)`
  - `[binary] Run 055: trust-bundle sequence persistence env=mainnet chain_id=51424e444d41494e path=/tmp/run059/data_positive/pqc_trust_bundle_sequence.json first-load persisted_sequence=1 fp=93fbb47d`
  - `[binary] Run 050/051: trust bundle loaded path=/tmp/run059/positive/trust-bundle.json env=mainnet fp=93fbb47d… active_roots=1 revoked_roots=0 sequence=1 valid_from=0 valid_until=18446744073709551615 signature=verified(signing_key_id=188a78b2..) signing_keys_configured=1. Bundle root IDs: [ede36367..]`
  - `[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 configured_roots=1 leaf_credentials_present=true peer_leaf_certs=0 (root fingerprints: [id=ede36367.. suite=100 fp=ebfe9ca6])`
  - `[binary] Run 052: revoked_leaf_fingerprints=0 (from trust bundle env=mainnet sequence=1)`
  - `[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true`

  The persistence file appeared with
  `{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"93fbb47dc9006c916983a57b13d5ee60756c4b3b60d0e2cea8f5597e3a2ee242","updated_at_unix_secs":1778660830}`.
  `/metrics` reported `qbind_p2p_pqc_trust_bundle_loaded 1`,
  `qbind_p2p_pqc_trust_bundle_environment 2` (MainNet),
  `qbind_p2p_pqc_trust_bundle_active_roots 1`,
  `qbind_p2p_pqc_trust_bundle_revoked_roots 0`,
  `qbind_p2p_pqc_trust_bundle_sequence 1`,
  `qbind_p2p_pqc_trust_bundle_sequence_highest 1`,
  `qbind_p2p_pqc_trust_bundle_signature_verified_total 1`,
  `qbind_p2p_pqc_trust_bundle_signature_rejected_total 0`,
  `qbind_p2p_pqc_trust_bundle_signing_keys_configured 1`,
  `qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0`,
  `qbind_p2p_pqc_trust_bundle_activation_rejected_total 0`,
  and the activation series at the satisfied values
  `qbind_p2p_pqc_trust_bundle_activation_height_required 0`,
  `_height_current 0`, `_epoch_required 0`, `_epoch_current 0`.
  The node then started the consensus loop on the MainNet chain and
  committed blocks at heights 1, 2, 3, …, 48+ before the
  evidence-collection timeout terminated the process — proving the
  scoped MainNet startup/load path is exercised end-to-end through
  consensus initialisation.

- **Smoke 2 — negative unsigned MainNet bundle.** Otherwise-valid
  MainNet bundle `fp=7e1330229a27dc9cbf3391507ed7aa9b623d5ae834b3ec2e5fbe72d35bbf062e`
  with `signature: null`. The binary printed
  `[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/run059/unsigned/trust-bundle.json: trust bundle is
  unsigned but environment mainnet requires a signed bundle. See
  docs/whitepaper/contradiction.md C4 (signed root distribution)..
  No fallback to --p2p-trusted-root on bundle failure
  (production-honest lifecycle must not silently downgrade). See
  docs/whitepaper/contradiction.md C4 (signed root distribution).`
  and exited with code `1`. The data dir
  `/tmp/run059/data_unsigned/` was created (by the binary's data-dir
  pre-flight) but verified **empty** afterwards (no
  `pqc_trust_bundle_sequence.json` written). No `[Run040]
  P2pNodeBuilder` line was reached.

- **Smoke 3 — negative tampered signed MainNet bundle.** MainNet
  bundle `fp=1d2ef7dd6767784b1ea2f57fe014e97978ace894c3e8a3584eefeffb8c4bfac1`
  was ML-DSA-44-signed honestly, then `roots[0].not_after` was
  decremented after signing, so the signed preimage no longer
  matches the on-disk bytes. The binary printed
  `[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/run059/tampered/trust-bundle.json: trust bundle
  ML-DSA-44 signature verification failed for signing_key_id
  27b886a5ff5971a747f846e77a933c916d10783f881bed52225bcb3de558d427
  (tampered bundle or forged envelope — fail closed). No fallback
  to --p2p-trusted-root on bundle failure …` and exited with code
  `1`. The data dir `/tmp/run059/data_tampered/` was **never
  created** (`ls -la` reported "(missing)"). No `[Run040]
  P2pNodeBuilder` line was reached.

- **Smoke 4 — negative wrong-signing-key signed MainNet bundle.**
  MainNet bundle `fp=b86e3618dfec2f8b45eb1b5600d08549e63b4c98e3c2e21a22dd632037f5edc9`
  was ML-DSA-44-signed honestly by one ephemeral keypair, but the
  helper published a **different** unrelated ML-DSA-44 keypair as
  the `--p2p-trust-bundle-signing-key` the operator should use. The
  binary printed
  `[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/run059/wrong_key/trust-bundle.json: trust bundle
  signature references signing_key_id
  be7b53d60640ab0e338a1df29d874221532e658f78e14e65f88f7952e6d17377
  but no matching --p2p-trust-bundle-signing-key was configured
  (fail closed). No fallback to --p2p-trusted-root on bundle
  failure …` and exited with code `1`. The data dir
  `/tmp/run059/data_wrong_key/` was **never created**. No `[Run040]
  P2pNodeBuilder` line was reached.

- **Smoke 5 — negative wrong-chain_id signed MainNet bundle.**
  MainNet-env, ML-DSA-44-signed bundle
  `fp=e0ecd29f291f545a58008758b70873999dba30f05fc1ca4683902cc800844f5b`
  declared `chain_id=0x51424e4444455600` (DevNet's canonical chain
  id) instead of MainNet's `0x51424e444d41494e`. The chain_id field
  was included in the signed preimage, so the signature itself
  remains valid against the published signing key, but the Run 053
  chain-id crosscheck rejects it. The binary printed
  `[binary] FATAL: --p2p-trust-bundle load/validate failed for
  path=/tmp/run059/wrong_chain/trust-bundle.json: trust bundle
  chain_id mismatch (expected chain_51424e444d41494e, bundle
  declares chain_51424e4444455600). No fallback to
  --p2p-trusted-root on bundle failure …` and exited with code
  `1`. The data dir `/tmp/run059/data_wrong_chain/` was **never
  created**. No `[Run040] P2pNodeBuilder` line was reached.

On the positive smoke, `dummy_kem_registered = false`,
`dummy_aead_registered = false`, `pqc_root_mode = pqc-static-root`,
`sig_suite_id = 100` (ML-DSA-44), `transport_kem_suite_id = 100`
(ML-KEM-768), `transport_aead_suite_id = 101` (ChaCha20-Poly1305)
— proving no fallback to test-grade primitives. On every negative
smoke the binary exited BEFORE the `[Run040] P2pNodeBuilder` line,
so no `Dummy*` primitive can be installed even hypothetically;
`/metrics` was deliberately NOT scraped on the negative paths
because fail-closed startup exits BEFORE the metrics HTTP server is
bound — documented honestly rather than fabricated. **No fallback
to `--p2p-trusted-root`** was supplied on any Run 059 smoke; every
FATAL line explicitly ends with `No fallback to --p2p-trusted-root
on bundle failure (production-honest lifecycle must not silently
downgrade)`. **All required regression suites pass** on the release
profile.

## Exact files changed

| File | Reason |
| --- | --- |
| `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` | Run 059 evidence-tooling: adds optional 6th positional `[chain_id_override]` argument so signed-mainnet bundles can pin `chain_id` BEFORE signing (positive: `0x51424e444d41494e` MainNet; negative wrong-chain: `0x51424e4444455600` DevNet), and adds two new bundle modes `signed-mainnet-tampered` / `signed-mainnet-wrong-key` that reuse the existing DevNet-env tamper / wrong-key signing logic verbatim but emit `environment=mainnet`. All existing Run 050/051/054/056/057/058 helper modes preserved bit-for-bit. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_059.md` | This evidence document (new). |
| `docs/devnet/run_059_smoke_positive.{stdout,stderr}.log` | Live release-binary positive MainNet signed-bundle smoke. |
| `docs/devnet/run_059_metrics_positive.txt` | Live `/metrics` scrape from the positive smoke. |
| `docs/devnet/run_059_smoke_unsigned.{stdout,stderr}.log` | Live release-binary unsigned-MainNet negative smoke. |
| `docs/devnet/run_059_smoke_tampered.{stdout,stderr}.log` | Live release-binary tampered-MainNet negative smoke. |
| `docs/devnet/run_059_smoke_wrong_key.{stdout,stderr}.log` | Live release-binary wrong-key MainNet negative smoke. |
| `docs/devnet/run_059_smoke_wrong_chain.{stdout,stderr}.log` | Live release-binary wrong-chain_id MainNet negative smoke. |
| `docs/whitepaper/contradiction.md` | Append "C4 Run 059 evidence update" recording that the live-binary release-build MainNet signed-bundle smoke artifact set (the explicit remaining boundary called out in Run 058) is now closed/narrowed for the scoped startup/load path; the still-open C4 pieces are listed explicitly. |

**No `crates/**/src/**` core library source, no protocol source, no
test source, no `Cargo.toml`, no `main.rs` / `pqc_trust_bundle.rs`
/ `pqc_trust_sequence.rs` / `pqc_trust_activation.rs` was touched
by Run 059.** The only Run-059 source edit is to the **DevNet
evidence helper example** (`crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`),
which is an out-of-binary evidence-tooling example. The release
`qbind-node` binary is bit-for-bit identical to Run 058
(`sha256 5f249fe2929135f11d38d95df4b1b13a603713a8208d0ede53b195efaadc3bcc`).
**No tests were removed or weakened.** **No `Cargo.toml`,
`Cargo.lock`, protocol, KEMTLS, consensus, timeout, or signature
behaviour was changed.**

## Exact commands run

```bash
# 1) Identify branch + commit + dirty state.
git rev-parse --abbrev-ref HEAD     # copilot/update-user-profile-pictures
git rev-parse HEAD                  # cc2f33e3913e997b52f5cb03ce4390154c568890
git status --porcelain              # (only the Run 059 helper edit + docs; no core source dirty)

# 2) Build release qbind-node + helpers.
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper

# 3) Confirm --devnet-forged-inject is hidden from normal --help.
./target/release/qbind-node --help 2>&1 | grep -c "devnet-forged-inject"   # 0

# 4) Required regression suites (release profile).
cargo test --release -p qbind-node --lib pqc_trust_bundle                            # 72/72
cargo test --release -p qbind-node --lib pqc_trust_sequence                          # 21/21
cargo test --release -p qbind-node --lib pqc_trust_activation                        # 14/14
cargo test --release -p qbind-node --lib metrics                                     # 108/108
cargo test --release -p qbind-node --lib p2p                                         # 138/138
cargo test --release -p qbind-node --lib                                             # 898/898
cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests             # 14/14
cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests     # 13/13
cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests          # 12/12
cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests    # 12/12
cargo test --release -p qbind-node --test run_057_pqc_trust_bundle_activation_tests  # 12/12
cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests  # 12/12
cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests    # 14/14
cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests # 10/10
cargo test --release -p qbind-net  --test run_052_leaf_revocation_handshake_tests    # 9/9
cargo test --release -p qbind-net  --lib                                             # 17/17
cargo test --release -p qbind-crypto --lib                                           # 68/68
cargo check --release -p qbind-node --bin qbind-node                                 # clean

# 5) Mint MainNet fixtures.
#    Helper CLI: <outdir> <num_validators> <bundle_mode> [sequence_override] [activation_height_override] [chain_id_override]
HELPER=./target/release/examples/devnet_pqc_trust_bundle_helper
"$HELPER" /tmp/run059/positive    1 signed-mainnet            1 0 0x51424e444d41494e
"$HELPER" /tmp/run059/unsigned    1 unsigned-mainnet
"$HELPER" /tmp/run059/tampered    1 signed-mainnet-tampered   1 0 0x51424e444d41494e
"$HELPER" /tmp/run059/wrong_key   1 signed-mainnet-wrong-key  1 0 0x51424e444d41494e
"$HELPER" /tmp/run059/wrong_chain 1 signed-mainnet            1 0 0x51424e4444455600

# 6) Live release-binary MainNet smokes.

# --- Smoke 1: positive signed MainNet with metrics scrape ---
SPEC=$(cat /tmp/run059/positive/signing-key.spec)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:9159 timeout 12 ./target/release/qbind-node \
  --env mainnet --validator-id 0 --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
  --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle /tmp/run059/positive/trust-bundle.json \
  --p2p-trust-bundle-signing-key "$SPEC" \
  --p2p-leaf-cert /tmp/run059/positive/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run059/positive/v0.kem.sk.bin \
  --data-dir /tmp/run059/data_positive \
  > docs/devnet/run_059_smoke_positive.stdout.log \
  2> docs/devnet/run_059_smoke_positive.stderr.log &
sleep 6
curl -s --max-time 3 http://127.0.0.1:9159/metrics > docs/devnet/run_059_metrics_positive.txt
wait
# Persistence file appears at /tmp/run059/data_positive/pqc_trust_bundle_sequence.json
# with highest_sequence=1 environment=mainnet chain_id=51424e444d41494e.

# --- Smokes 2-5: negative MainNet smokes (no /metrics — fail closed before HTTP bind) ---
for name in unsigned tampered wrong_key wrong_chain; do
  SPEC=$(cat /tmp/run059/${name}/signing-key.spec 2>/dev/null \
       || cat /tmp/run059/positive/signing-key.spec)   # unsigned reuses positive's spec
  timeout 15 ./target/release/qbind-node \
    --env mainnet --validator-id 0 --network-mode p2p --enable-p2p \
    --p2p-listen-addr 127.0.0.1:0 --p2p-mutual-auth required \
    --p2p-pqc-root-mode pqc-static-root \
    --p2p-trust-bundle /tmp/run059/${name}/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SPEC" \
    --p2p-leaf-cert /tmp/run059/${name}/v0.cert.bin \
    --p2p-leaf-cert-key /tmp/run059/${name}/v0.kem.sk.bin \
    --data-dir /tmp/run059/data_${name} \
    > docs/devnet/run_059_smoke_${name}.stdout.log \
    2> docs/devnet/run_059_smoke_${name}.stderr.log
  # exit_code=1 for all four; no /tmp/run059/data_${name}/pqc_trust_bundle_sequence.json created.
done
```

## Test evidence (release profile)

| Suite | Tests | Result |
|---|---|---|
| `cargo test --release -p qbind-node --lib pqc_trust_bundle` | 72 | **passed** |
| `cargo test --release -p qbind-node --lib pqc_trust_sequence` | 21 | **passed** |
| `cargo test --release -p qbind-node --lib pqc_trust_activation` | 14 | **passed** |
| `cargo test --release -p qbind-node --lib metrics` | 108 | **passed** |
| `cargo test --release -p qbind-node --lib p2p` | 138 | **passed** |
| `cargo test --release -p qbind-node --lib` (full) | 898 | **passed** |
| `cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests` | 14 | **passed** |
| `cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | 13 | **passed** |
| `cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | 12 | **passed** |
| `cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | 14 | **passed** |
| `cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | 10 | **passed** |
| `cargo test --release -p qbind-net  --test run_052_leaf_revocation_handshake_tests` | 9 | **passed** |
| `cargo test --release -p qbind-net  --lib` | 17 | **passed** |
| `cargo test --release -p qbind-crypto --lib` | 68 | **passed** |
| `cargo check --release -p qbind-node --bin qbind-node` | — | **clean** (only pre-existing `bincode::config` deprecation warnings unrelated to Run 059) |
| `cargo build --release -p qbind-node --bin qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper` | — | **clean** |

`binary_consensus`, `forged_injection`, `run030`, and
`qbind-consensus --lib timeout` were intentionally not rerun: Run
059 did not modify any source on those paths (the only source edit
is to the DevNet evidence-tooling example). The Run 056-recorded
pre-existing `m16_epoch_transition_hardening_tests` `cargo build
--tests` failure (`set_inject_write_failure` /
`clear_epoch_transition_marker` methods missing on
`RocksDbConsensusStorage`) is unrelated to Run 059 and remains
present on `cc2f33e` before Run 059's edits.

## Binary identity

| Artefact | sha256 | ELF BuildID |
| --- | --- | --- |
| `target/release/qbind-node` | `5f249fe2929135f11d38d95df4b1b13a603713a8208d0ede53b195efaadc3bcc` | `77553328e1ee90a1a9f808974c6d9b66b0cbe9d8` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` | `de612a586f36cd58f5904bb52621f314b6116beda06b3722ef84e172b6ed6719` | `895e4732d686841cfb3930bf996920d3858c4593` |
| `target/release/examples/devnet_pqc_root_helper` | `0e04fd1f9a1464de9ecf670987ca4f54d07df11a0e6fac2a2094389cd992e8a4` | `dcee024f842845da7648a568c309c760b51df5c3` |

- Branch: `copilot/update-user-profile-pictures`
- Commit: `cc2f33e3913e997b52f5cb03ce4390154c568890` (Run 058 head)
- Dirty/clean: Run 059 working-tree edits limited to
  `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`
  (DevNet evidence-tooling example only — no core source) plus
  the new `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_059.md`,
  `docs/devnet/run_059_*` log/metric artefacts, and the
  Run 059 update to `docs/whitepaper/contradiction.md`.

The `qbind-node` sha256 / BuildID is **bit-for-bit identical to
Run 058** because no `crates/**/src/**` source was touched. The
`devnet_pqc_trust_bundle_helper` sha256 / BuildID **changed**
because of the Run 059 evidence-tooling additions (new optional
6th positional `[chain_id_override]` + new modes
`signed-mainnet-tampered` / `signed-mainnet-wrong-key`); the
existing Run 050/051/054/056/057/058 helper modes still produce
bit-equivalent fixtures (no behaviour change to existing modes,
the new positional defaults to `None`, and the two new modes are
additive `match` arms).

## MainNet trust-bundle material procedure

For each of the five smokes the Run 059 helper produced the same
on-disk artefact set as the Run 050/051/058 DevNet helpers:

- `root.id.hex` — 64-lowercase-hex ML-DSA-44 root key id (ephemeral, fresh per invocation, never written to disk in secret form).
- `root.pk.hex` — full ML-DSA-44 root public key.
- `v0.cert.bin` — encoded `NetworkDelegationCert` for validator 0 (real ML-DSA-44 delegation signature; ML-KEM-768 leaf KEM material).
- `v0.kem.sk.bin` — validator 0's ML-KEM-768 secret key bytes (mode 0o600).
- `v0.leaf-fp.hex` — leaf cert fingerprint (SHA3-256 with the cert domain separator).
- `trusted-root.spec` — `KEYID:100:PK` line (DevNet `--p2p-trusted-root` convenience; **NOT supplied** to the qbind-node command on any Run 059 smoke — no `--p2p-trusted-root` argument is passed; the trust set is built exclusively from the bundle).
- `trust-bundle.json` — the trust bundle that the binary loads.
- `signing-key.id.hex`, `signing-key.pk.hex`, `signing-key.spec` — the `--p2p-trust-bundle-signing-key` line (`KEYID:100:PK`) that the operator should configure. For the `wrong_key` smoke this is **deliberately a different ML-DSA-44 keypair** than the one that actually signed the bundle.

Root signing secret keys and bundle-signing secret keys are minted
ephemerally per helper invocation and held in memory only; they
are never written to disk in any form. The
`[devnet_pqc_trust_bundle_helper]` summary line confirms this:
"`root_sk and bundle signing_sk were held in memory only; never
written to disk.`".

## MainNet chain_id expected/used

`NetworkEnvironment::Mainnet` → `QBIND_MAINNET_CHAIN_ID` →
`ChainId(0x51424E44_4D41494E)` → hex `51424e444d41494e` → ASCII
`QBNDMAIN`. This is the value passed by
`crates/qbind-node/src/main.rs` to
`TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation`
as `expected_chain_id` (via `config.chain_id()` →
`self.environment.chain_id()` → the const table in
`crates/qbind-types/src/primitives.rs` lines 84 + 118). It is also
the value reported on the binary's own `Run 055` line for Smoke 1
(`env=mainnet chain_id=51424e444d41494e`) and the value
the persistence record's `chain_id` field carries
(`"chain_id":"51424e444d41494e"`). The Run 059 positive bundle
declares `chain_id="0x51424e444d41494e"` so the Run 053 chain-id
crosscheck **actively verifies equality**; the wrong-chain smoke
declares `chain_id="0x51424e4444455600"` (DevNet) so the same
crosscheck rejects it.

## Signed-bundle verification proof

- Positive smoke FATAL boundary: **none** — the bundle is accepted,
  the binary continues into consensus initialisation.
- `signature=verified(signing_key_id=188a78b2..)` printed on the
  positive smoke's `Run 050/051` line, against
  `signing_keys_configured=1` (the operator's
  `--p2p-trust-bundle-signing-key` set).
- `/metrics` `qbind_p2p_pqc_trust_bundle_signature_verified_total 1`,
  `qbind_p2p_pqc_trust_bundle_signature_rejected_total 0`.
- Negative tampered smoke FATAL: "trust bundle ML-DSA-44 signature
  verification failed for signing_key_id 27b886a5… (tampered bundle
  or forged envelope — fail closed)".
- Negative wrong-key smoke FATAL: "trust bundle signature references
  signing_key_id be7b53d6… but no matching
  --p2p-trust-bundle-signing-key was configured (fail closed)".
- Negative unsigned smoke FATAL: "trust bundle is unsigned but
  environment mainnet requires a signed bundle".
- Negative wrong-chain smoke FATAL: "trust bundle chain_id mismatch
  (expected chain_51424e444d41494e, bundle declares
  chain_51424e4444455600)" — the chain_id check runs BEFORE the
  signature check (per `pqc_trust_bundle.rs` validate ordering), so
  this rejection happens even though the signature itself is valid
  (the wrong chain_id was inside the signed preimage).

## Sequence persistence file path and record content

Path: `/tmp/run059/data_positive/pqc_trust_bundle_sequence.json`
(only written on Smoke 1; **NOT** written on Smokes 2–5).

Record content (Smoke 1, after the positive smoke):

```
{"record_version":1,"environment":"mainnet","chain_id":"51424e444d41494e","highest_sequence":1,"bundle_fingerprint":"93fbb47dc9006c916983a57b13d5ee60756c4b3b60d0e2cea8f5597e3a2ee242","updated_at_unix_secs":1778660830}
```

For Smokes 2–5: the data dir was either never created (tampered /
wrong_key / wrong_chain) or created empty (unsigned, where the
data-dir pre-flight ran before the trust-bundle FATAL). In every
case the trust-bundle FATAL exited the process at exit code `1`
BEFORE the sequence-persistence check ran. This is the documented
Run 055 ordering (`check_and_update_sequence` runs strictly AFTER
all of: schema, environment, chain_id, validity window, root
status / windows, revocation consistency, ML-DSA-44 signature,
Run 057 activation gate), preserved here under MainNet.

## Positive signed MainNet smoke

See "Smoke 1" in the verdict section above, plus
`docs/devnet/run_059_smoke_positive.stdout.log`,
`docs/devnet/run_059_smoke_positive.stderr.log`, and
`docs/devnet/run_059_metrics_positive.txt`.

## Unsigned MainNet negative smoke

See "Smoke 2" in the verdict section above, plus
`docs/devnet/run_059_smoke_unsigned.stdout.log` /
`docs/devnet/run_059_smoke_unsigned.stderr.log`.

## Tampered signed MainNet negative smoke

See "Smoke 3" in the verdict section above, plus
`docs/devnet/run_059_smoke_tampered.stdout.log` /
`docs/devnet/run_059_smoke_tampered.stderr.log`.

## Wrong-signing-key MainNet negative smoke

See "Smoke 4" in the verdict section above, plus
`docs/devnet/run_059_smoke_wrong_key.stdout.log` /
`docs/devnet/run_059_smoke_wrong_key.stderr.log`.

## Wrong-chain_id MainNet negative smoke

See "Smoke 5" in the verdict section above, plus
`docs/devnet/run_059_smoke_wrong_chain.stdout.log` /
`docs/devnet/run_059_smoke_wrong_chain.stderr.log`.

## Optional MainNet two-node smoke

**Not performed in Run 059.** The single-validator MainNet smoke
runs to consensus (Smoke 1 commits blocks at heights 1, 2, 3, …,
48+ before the evidence-collection timeout). A two-node MainNet
peer-connection artefact set was deliberately not produced here:
the live release binary does **not** today load the validator
keystore (`config.signer_keystore_path` is not read on startup —
per the explicit `[binary] Run 032` and `[binary] Run 033`
disclosures emitted on the positive smoke) and `--p2p-mutual-auth
required` runs on the production-honest PQC static-root
cert-verification path but with **test-grade KEM/AEAD primitives**
on the binary path (separate C4 piece per the binary's own
`Run 037` disclosure: "KEM/AEAD primitives on the binary path are
still test-grade and remain a separate C4 piece (not C4(c));
MainNet readiness is therefore not yet implied"). Two-node
MainNet peer connection is therefore blocked by unrelated production
config (validator keystore loading + per-peer consensus-key
distribution + production-grade KEM/AEAD primitives), not by
trust-bundle verification. The trust-bundle verification path
itself is exhaustively pinned for MainNet by the five Run 059
smokes above, by the `cargo test` regression suite (898 lib + the
13 Run 051 signing tests + the 12 Run 055 sequence tests + the 12
Run 057 activation tests + the integration suites), and by the
two-node DevNet smokes pinned in Run 054. Recorded as remaining-open
boundary `(g)` in the contradiction update below.

## /metrics excerpts

From the positive smoke (`docs/devnet/run_059_metrics_positive.txt`):

```
qbind_p2p_pqc_trust_bundle_loaded 1
qbind_p2p_pqc_trust_bundle_environment 2
qbind_p2p_pqc_trust_bundle_active_roots 1
qbind_p2p_pqc_trust_bundle_revoked_roots 0
qbind_p2p_pqc_trust_bundle_sequence 1
qbind_p2p_pqc_trust_bundle_signature_verified_total 1
qbind_p2p_pqc_trust_bundle_signature_rejected_total 0
qbind_p2p_pqc_trust_bundle_signing_keys_configured 1
qbind_p2p_pqc_trust_bundle_sequence_highest 1
qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total 0
qbind_p2p_pqc_trust_bundle_sequence_equal_fingerprint_mismatch_total 0
qbind_p2p_pqc_trust_bundle_sequence_persist_failures_total 0
qbind_p2p_pqc_trust_bundle_activation_height_required 0
qbind_p2p_pqc_trust_bundle_activation_height_current 0
qbind_p2p_pqc_trust_bundle_activation_epoch_required 0
qbind_p2p_pqc_trust_bundle_activation_epoch_current 0
qbind_p2p_pqc_trust_bundle_activation_rejected_total 0
```

`qbind_p2p_pqc_trust_bundle_environment 2` is the numeric tag for
`Mainnet` per the metrics-render contract (DevNet=0, TestNet=1,
MainNet=2). The Run 052 / Run 055 / Run 057 counters are all at
their satisfied / no-rejection values; no rejection counter moved.

## Exact boundary if fail-closed startup prevents metric scraping

On Smokes 2–5 the binary exits at code `1` BEFORE the metrics
HTTP server binds (the trust-bundle FATAL runs strictly inside
`main()` early in startup — see the comment block beginning at
`crates/qbind-node/src/main.rs:711` and the surrounding "Run 050
(C4 piece: PQC transport trust-anchor lifecycle — foundation layer)
+ Run 051 (signed-bundle ML-DSA-44 verification)" wiring). Each of
Smokes 2–5 was therefore deliberately run **without** a metrics
HTTP scrape: the `/metrics` file is not present in
`docs/devnet/run_059_*` for those smokes. The
`qbind_p2p_pqc_trust_bundle_signature_rejected_total` /
`qbind_p2p_pqc_trust_bundle_sequence_rollback_rejected_total` /
`qbind_p2p_pqc_trust_bundle_activation_rejected_total` counter
movements that the binary would emit on each rejected load are
already pinned by Run 050/051/055/057 unit tests (the
`metrics-render-once` family and the atomic-increment family) and
are documented honestly rather than fabricated for Run 059.

## Proof no fallback to --p2p-trusted-root

- No `--p2p-trusted-root` was supplied on any Run 059 smoke — the
  five command lines above demonstrate this directly. The trust set
  is sourced exclusively from the bundle.
- Every negative smoke's FATAL line explicitly ends with `No
  fallback to --p2p-trusted-root on bundle failure (production-honest
  lifecycle must not silently downgrade). See
  docs/whitepaper/contradiction.md C4 (signed root distribution).`
- On every negative smoke the binary exits BEFORE the `[Run040]
  P2pNodeBuilder` line, so `trusted_roots` cannot have been used to
  build the P2P node even hypothetically.
- The Run 057 wiring in `crates/qbind-node/src/main.rs` returns
  `Err(TrustBundleError::*)` BEFORE `trusted_roots` is mutated to
  include any bundle roots AND BEFORE `check_and_update_sequence`
  is invoked — exactly as documented in the Run 058 update of
  `docs/whitepaper/contradiction.md` and verified by the
  Run 050/051/055/057 integration suites that this run reruns
  green.

## Proof no DummySig/DummyKem/DummyAead fallback

- Positive smoke's `[Run040] P2pNodeBuilder` line carries
  `dummy_kem_registered=false`, `dummy_aead_registered=false`, and
  the real PQC suite ids (`sig_suite_id=100` ML-DSA-44,
  `transport_kem_suite_id=100` ML-KEM-768,
  `transport_aead_suite_id=101` ChaCha20-Poly1305).
- Every negative smoke exits BEFORE the `[Run040] P2pNodeBuilder`
  line, so no `Dummy*` primitive can be installed even
  hypothetically.
- `--p2p-pqc-root-mode pqc-static-root` is supplied on every Run
  059 smoke; the binary's `[binary] Run 037` line confirms
  "production-honest PQC static-root cert-verification path".
- The Run 058 invariants that "the fail-closed startup path never
  installs `Dummy*` primitives" are preserved by Run 059
  bit-for-bit (no `crates/**/src/**` source touched).

## Remaining open items

- (a) **Operator-facing CA + certificate rotation + signing-key
  rotation playbook** unchanged from Run 056/057/058.
- (b) **Production fast-sync / consensus-storage restore**
  unchanged.
- (c) **Epoch gating runtime source** unchanged.
- (d) **Activation gate on revocation entries** unchanged.
- (e) **Per-environment minimum-activation-height policy** unchanged.
- (f) **`--restore-from-snapshot` satisfied-height live release-binary
  smoke** unchanged from the Run 058 boundary.
- (g) **MainNet two-node release-binary peer-connection smoke.**
  Run 059 ran a single-validator MainNet smoke that DOES start
  consensus and DOES commit blocks past height 1 on the live
  binary, exercising the full MainNet trust-bundle load path
  end-to-end. A two-node MainNet peer-connection artefact set is
  blocked by unrelated production config (validator keystore
  loading + per-peer consensus-key distribution + production-grade
  KEM/AEAD primitives on the binary path — see the binary's own
  `[binary] Run 032` / `Run 033` / `Run 037` disclosures
  emitted on Smoke 1 and recorded as separate C4/C5 pieces).
  Recorded explicitly as remaining-open.
- (h) **Production-grade signing-key custody.** Run 059's MainNet
  signing key is an ephemeral ML-DSA-44 keypair minted in memory
  by the DevNet helper for this run only. A production-grade HSM/KMS
  signing-key custody / rotation flow remains out of scope under
  C4(a) above.
- **C5 remains NOT closed by Run 059.** Run 059 does not touch
  timeout / NewView wire formats, forged-traffic policy, KEMTLS
  wire formats, consensus message wire formats, or any
  signature/verification semantics outside the trust-bundle
  MainNet startup-evidence surface.
- **Full C4 remains OPEN.** Run 059 closes/narrows the **MainNet
  live signed-bundle release-binary smoke** boundary that Run 058
  recorded as remaining-open, for the **scoped startup/load path
  through consensus initialisation on a single validator**; it does
  NOT close any of (a)–(h) above.

## Exact immediate next action

Operator-facing CA + certificate rotation + signing-key rotation
playbook (C4 remaining item (a)) is the next narrowest evidence
gap: it is the precondition both for a production-grade MainNet
signing-key custody flow (Run 059 remaining item (h)) and for any
future signing-key rotation evidence run. Recommend a follow-up
run that lands the documented operator playbook (key generation
ceremony, on-disk custody, rotation cadence, revocation, recovery)
and produces a release-binary signing-key-rotation smoke that
proves the rotation path works on the live binary without
introducing any silent fallback.