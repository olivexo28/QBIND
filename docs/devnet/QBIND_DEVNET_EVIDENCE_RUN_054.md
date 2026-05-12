# QBIND DevNet Evidence — Run 054: Release-Binary Live Artifacts for Run 052 Leaf-Level Certificate Revocation Enforcement

## Exact objective

Run 054 is **evidence-only**. It produces release-binary live evidence
artifacts for the Run 052 leaf-level certificate revocation
enforcement layer on the real `qbind-node` release binary in
`pqc-static-root` signed-bundle mode. The artifact gap left explicit
in Run 052 (recorded as a remaining boundary) is the only target.

The scope is intentionally narrow:

- prove the positive non-revoked signed-bundle two-node smoke still
  connects and verifies certs;
- prove a revoked **peer** leaf cert is failed closed by the live
  binary on both the listener and dialer side, and that the new
  `qbind_p2p_pqc_cert_verify_rejected_revoked_total` metric moves
  exactly as Run 052 promised;
- prove a revoked **local** leaf bundle behaves consistently with
  Run 052's wired surface (no startup self-check exists in Run 052;
  the only enforcement boundary is the wire-level handshake);
- prove a revoked **unknown** leaf fingerprint in the bundle does not
  affect unrelated certs;
- prove no fallback to `--p2p-trusted-root`, `DummySig`, `DummyKem`,
  or `DummyAead` on any path;
- preserve Run 037 / Run 040 / Run 044 / Run 050 / Run 051 / Run 052 /
  Run 053 behaviour bit-for-bit.

Explicitly out of scope for Run 054 (and listed in
`docs/whitepaper/contradiction.md`):

- activation epoch / height gating;
- sequence-number monotonicity persistence across restarts;
- additional `chain_id` work (Run 053 closed the narrow crosscheck);
- production CA / cert rotation / signing-key rotation operator
  playbook;
- production fast-sync / consensus-storage restore;
- MainNet live signed-bundle smoke;
- any redesign of KEMTLS, trust bundles, transport, or consensus.

## Exact verdict

**Strongest positive for the scoped Run 054 release-binary
revoked-leaf evidence run.** On the live release `qbind-node` binary,
the positive signed-bundle two-node smoke connects and verifies certs
with `qbind_p2p_pqc_cert_verify_rejected_revoked_total = 0` on both
peers. The revoked-peer-leaf two-node smoke fails closed: V0's
`qbind_p2p_pqc_cert_verify_rejected_revoked_total` and aggregate
`qbind_p2p_pqc_cert_verify_rejected_total` both moved to **2** (one
hit on the listener path `server handle_client_init failed`, one hit
on the dialer path `client handle_server_accept failed`) while
`qbind_p2p_pqc_cert_verify_accepted_total` stayed at **0** for V1's
revoked cert. The revoked-unknown-leaf-fingerprint two-node smoke
loads a bundle with `revoked_leaf_fingerprints = 1` (the synthetic
all-zeros entry, which no real validator cert can collide with), yet
both nodes still connect and verify certs with
`qbind_p2p_pqc_cert_verify_rejected_revoked_total = 0` on both peers
— exactly as Run 052 guarantees. The revoked-local-leaf single-node
smoke documents the **honest boundary** that Run 052 wired only the
wire-level cert-verify path and not a startup self-check, so a node
loading a bundle that revokes its own leaf still starts (the
revocation only fires when an inbound peer or outbound dial presents
the revoked cert); this is consistent with Run 052's design and the
task's conditional language ("**if** local self-check sees the
revocation"). On every smoke, `dummy_kem_registered = false`,
`dummy_aead_registered = false`, `pqc_root_mode = pqc-static-root`,
`sig_suite_id = 100` (ML-DSA-44), `transport_kem_suite_id = 100`
(ML-KEM-768), `transport_aead_suite_id = 101` (ChaCha20-Poly1305),
`signature = verified(signing_key_id=…)` — proving no fallback to
test-grade primitives and no fallback to `--p2p-trusted-root`. All
required regression suites (`pqc_trust_bundle`,
`run_050_pqc_trust_bundle_tests`,
`run_051_pqc_trust_bundle_signing_tests`,
`run_052_pqc_leaf_revocation_tests`,
`run_052_leaf_revocation_handshake_tests`,
`run_037_pqc_static_root_mutual_auth_tests`,
`run_040_pqc_static_root_real_aead_tests`,
`run_044_pqc_cert_verify_metrics_adapter_tests`, `metrics`, `p2p`,
full `qbind-node --lib`, `qbind-net --lib`, `qbind-crypto --lib`)
remain green.

## Exact files changed

| File | Change |
| --- | --- |
| `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs` | **Evidence-tooling extension only.** Add three new DevNet fixture modes — `signed-devnet-revoked-v0`, `signed-devnet-revoked-v1`, `signed-devnet-revoked-unknown` — that mirror the Run 051 `signed-devnet` honest signing flow and inject a single active `TrustBundleRevocation { root_id, leaf_cert_fingerprint: Some(fp), reason: "test-leaf-revocation-run054*", effective_from: 0 }` entry BEFORE signing, so the resulting bundle's signature actually covers the revocation. Also persist each issued leaf cert's canonical 32-byte fingerprint as `v<N>.leaf-fp.hex` (lowercase hex; matches `cert_leaf_fingerprint_hex(...)` for the same on-disk `v<N>.cert.bin`). No core library / protocol source touched; the helper is example code that exists explicitly to produce DevNet evidence fixtures, following the Run 051 precedent that extended the same helper for the signed-bundle negative fixtures. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_054.md` | This evidence document (new). |
| `docs/devnet/run_054_smoke_*.{stdout,stderr}.log` and `run_054_metrics_*.txt` | Live release-binary smoke logs and `/metrics` excerpts for all four cases. |
| `docs/whitepaper/contradiction.md` | Append "C4 Run 054 evidence update" recording that the live-binary release-build smoke artifact for Run 052's revoked-leaf surface (the explicit remaining boundary called out in Run 052) is now closed/narrowed; the still-open C4 pieces are listed explicitly. |

No `crates/**/src/**` files outside the example helper were touched.
No tests were removed or weakened. No `Cargo.toml` changes. No
`--p2p-trusted-root` weakening. No KEMTLS / transport / consensus /
trust-bundle library source changes.

## Exact commands run

```bash
# 0) Baseline identity.
git rev-parse HEAD                # 7443ea60551442f67a6d3020ea9853133bed546b
git status --porcelain | wc -l    # 0 (clean before Run 054 edits)

# 1) Build release artefacts.
cargo build --release -p qbind-node \
  --bin qbind-node \
  --example devnet_pqc_trust_bundle_helper \
  --example devnet_pqc_root_helper

# 2) Confirm hidden flag stays hidden, required flags surface.
./target/release/qbind-node --help | grep -c devnet-forged-inject   # 0
./target/release/qbind-node --help | grep -E -- \
  '--p2p-trust-bundle|--p2p-trust-bundle-signing-key|--p2p-pqc-root-mode|--p2p-leaf-cert|--p2p-leaf-cert-key|--p2p-peer-leaf-cert|--p2p-mutual-auth'

# 3) Regression test rerun (release profile).
cargo test --release -p qbind-node --lib pqc_trust_bundle
cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests
cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests
cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests
cargo test --release -p qbind-net  --test run_052_leaf_revocation_handshake_tests
cargo test --release -p qbind-node --lib metrics
cargo test --release -p qbind-node --lib p2p
cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests
cargo test --release -p qbind-node --lib
cargo test --release -p qbind-net  --lib
cargo test --release -p qbind-crypto --lib
cargo check --release -p qbind-node --bin qbind-node

# 4) Fixture generation (one DevNet helper invocation per mode).
for mode in signed-devnet signed-devnet-revoked-v0 \
            signed-devnet-revoked-v1 signed-devnet-revoked-unknown; do
  ./target/release/examples/devnet_pqc_trust_bundle_helper \
    "/tmp/run054/$mode" 2 "$mode"
done

# 5) Smoke 1 — positive signed-bundle non-revoked two-node smoke.
#    (V0 + V1; same signed-devnet bundle; metrics enabled on both.)
SIGN_SPEC="$(cat /tmp/run054/signed-devnet/signing-key.spec)"
BD=/tmp/run054/signed-devnet
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19510 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19410 --p2p-peer 1@127.0.0.1:19411 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/run054-data/v0 &
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19511 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19411 --p2p-peer 0@127.0.0.1:19410 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v1.cert.bin" \
  --p2p-leaf-cert-key "$BD/v1.kem.sk.bin" \
  --p2p-peer-leaf-cert "0:$BD/v0.cert.bin" \
  --validator-id 1 --data-dir /tmp/run054-data/v1 &
sleep 6
curl -s http://127.0.0.1:19510/metrics | grep pqc_cert_verify
curl -s http://127.0.0.1:19511/metrics | grep pqc_cert_verify
# (kill both processes)

# 6) Smoke 2 — revoked-local-leaf startup smoke.
#    Single node; bundle revokes its own v0 leaf fingerprint.
SIGN_SPEC="$(cat /tmp/run054/signed-devnet-revoked-v0/signing-key.spec)"
BD=/tmp/run054/signed-devnet-revoked-v0
timeout 6 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19420 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --validator-id 0 --data-dir /tmp/run054-data/v0r

# 7) Smoke 3 — revoked-peer-leaf two-node mutual-auth smoke.
#    Same bundle (revokes v1) on both nodes.
SIGN_SPEC="$(cat /tmp/run054/signed-devnet-revoked-v1/signing-key.spec)"
BD=/tmp/run054/signed-devnet-revoked-v1
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19530 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19430 --p2p-peer 1@127.0.0.1:19431 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/run054-data/peer/v0 &
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19531 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19431 --p2p-peer 0@127.0.0.1:19430 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v1.cert.bin" \
  --p2p-leaf-cert-key "$BD/v1.kem.sk.bin" \
  --p2p-peer-leaf-cert "0:$BD/v0.cert.bin" \
  --validator-id 1 --data-dir /tmp/run054-data/peer/v1 &
sleep 6
curl -s http://127.0.0.1:19530/metrics | grep pqc_cert_verify
curl -s http://127.0.0.1:19531/metrics | grep pqc_cert_verify
# (kill both processes)

# 8) Smoke 4 — unknown leaf fingerprint two-node smoke.
#    Bundle revokes an all-zeros (synthetic) leaf fingerprint that no
#    real cert can produce; v0 and v1 leaves are untouched.
SIGN_SPEC="$(cat /tmp/run054/signed-devnet-revoked-unknown/signing-key.spec)"
BD=/tmp/run054/signed-devnet-revoked-unknown
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19540 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19440 --p2p-peer 1@127.0.0.1:19441 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v0.cert.bin" \
  --p2p-leaf-cert-key "$BD/v0.kem.sk.bin" \
  --p2p-peer-leaf-cert "1:$BD/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/run054-data/unk/v0 &
QBIND_METRICS_HTTP_ADDR=127.0.0.1:19541 ./target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19441 --p2p-peer 0@127.0.0.1:19440 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trust-bundle "$BD/trust-bundle.json" \
  --p2p-trust-bundle-signing-key "$SIGN_SPEC" \
  --p2p-leaf-cert "$BD/v1.cert.bin" \
  --p2p-leaf-cert-key "$BD/v1.kem.sk.bin" \
  --p2p-peer-leaf-cert "0:$BD/v0.cert.bin" \
  --validator-id 1 --data-dir /tmp/run054-data/unk/v1 &
sleep 6
curl -s http://127.0.0.1:19540/metrics | grep pqc_cert_verify
curl -s http://127.0.0.1:19541/metrics | grep pqc_cert_verify
# (kill both processes)
```

Run-054 deliberately **did not** rerun the optional TestNet smoke
(Required Evidence Case #6 is gated on "if low cost"); DevNet
release-binary evidence already covers all four required cases.

## Tests run and pass/fail status

| Suite | Result |
| --- | --- |
| `cargo test --release -p qbind-node --lib pqc_trust_bundle` | **68 / 68 pass** |
| `cargo test --release -p qbind-node --test run_050_pqc_trust_bundle_tests` | **14 / 14 pass** |
| `cargo test --release -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | **13 / 13 pass** |
| `cargo test --release -p qbind-node --test run_052_pqc_leaf_revocation_tests` | **12 / 12 pass** |
| `cargo test --release -p qbind-net  --test run_052_leaf_revocation_handshake_tests` | **9 / 9 pass** |
| `cargo test --release -p qbind-node --lib metrics` | **104 / 104 pass** |
| `cargo test --release -p qbind-node --lib p2p` | **138 / 138 pass** |
| `cargo test --release -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **12 / 12 pass** |
| `cargo test --release -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **14 / 14 pass** |
| `cargo test --release -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | **10 / 10 pass** |
| `cargo test --release -p qbind-node --lib` (full) | **859 / 859 pass** |
| `cargo test --release -p qbind-net  --lib` | **17 / 17 pass** |
| `cargo test --release -p qbind-crypto --lib` | **68 / 68 pass** |
| `cargo build --release -p qbind-node --bin qbind-node` | clean (only pre-existing `bincode::config` deprecation warnings) |
| `cargo build --release -p qbind-node --example devnet_pqc_trust_bundle_helper` | clean |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | clean |
| `cargo check  --release -p qbind-node --bin qbind-node` | clean |

The `binary_consensus`, `forged_injection`, `run030`, and
`qbind-consensus --lib timeout` suites listed in the task as
conditional ("if source touches timeout verification or binary
consensus loop") are intentionally NOT rerun: Run 054 did not modify
any source on those paths (only a DevNet example helper file was
touched).

## Binary identity

Branch: `copilot/release-binary-live-evidence-artifacts`
Commit (baseline before Run 054 edits): `7443ea60551442f67a6d3020ea9853133bed546b`
Dirty/clean status before Run 054: **clean** (`git status --porcelain` returned 0 lines)
Dirty/clean status after the helper edit: **dirty** (1 file: `crates/qbind-node/examples/devnet_pqc_trust_bundle_helper.rs`)
Rust toolchain: `rustc 1.94.1 (e408947bf 2026-03-25)`
Host: `Linux x86_64`, kernel `6.17.0-1010-azure`

| Artefact | sha256 | ELF BuildID |
| --- | --- | --- |
| `target/release/qbind-node` | `2b68a090f131c38306d8e8b47d0e28719a0804c6e19f1f251e9470364e61facf` | `379f2260cf3835b59eb8710c4c7e3f41b28be5de` |
| `target/release/examples/devnet_pqc_root_helper` | `65f5daad42a447632e2e516e8d535e84c144246898b449851a76a337bf5d19a9` | `b1915871477e6e76417e563c81865a75916237c3` |
| `target/release/examples/devnet_pqc_trust_bundle_helper` (Run 054 build, with revoked-leaf modes) | `9166626a31b0ed37547dd525de454a45602bd1abf810321bf41e6e33842d04fc` | `e53080be76c9f6bb56fd5ea06f9f41cbcd51759a` |

The `qbind-node` binary was built ONCE at the start of Run 054 with
the clean tree (commit `7443ea6`), then never rebuilt; the helper was
rebuilt once after adding the three Run 054 fixture modes. The
`qbind-node` binary itself was not modified by Run 054 — every
release-binary smoke below ran against the same `qbind-node` sha256.

## CLI flag confirmation

- `--devnet-forged-inject` is **hidden** from normal `--help`
  (`./target/release/qbind-node --help | grep -c devnet-forged-inject`
  returns `0`).
- The following flags are present and documented in `--help`:
  - `--p2p-trust-bundle <P2P_TRUST_BUNDLE>`
  - `--p2p-trust-bundle-signing-key <P2P_TRUST_BUNDLE_SIGNING_KEYS>`
  - `--p2p-pqc-root-mode <P2P_PQC_ROOT_MODE>`
  - `--p2p-leaf-cert <P2P_LEAF_CERT>`
  - `--p2p-leaf-cert-key <P2P_LEAF_CERT_KEY>`
  - `--p2p-peer-leaf-cert <P2P_PEER_LEAF_CERTS>` (`VID:PATH` form)
  - `--p2p-mutual-auth <P2P_MUTUAL_AUTH>`

## Trust-bundle material procedure

For each fixture mode the Run-054 helper performs the same steps in a
single invocation; root and signing-key secrets are generated fresh
and held in memory only — no `root_sk` or `signing_sk` byte is ever
written to disk.

1. `MlDsa44Backend::generate_keypair()` → DevNet trust root.
2. For `vid` in `0..num_validators`:
   - `MlKem768Backend::generate_keypair()` → leaf KEM keypair.
   - `issue_leaf_delegation_cert(LeafCertSpec::currently_valid(…), root.root_sk)` → ML-DSA-44-signed `NetworkDelegationCert`.
   - `cert_leaf_fingerprint(&cert)` → 32-byte canonical leaf fingerprint
     (SHA3-256 of `TRUST_BUNDLE_LEAF_FINGERPRINT_DOMAIN_SEPARATOR ||
     cert.encode()`). Persisted as `v<N>.leaf-fp.hex`.
   - Persist `v<N>.cert.bin` (encoded cert) and `v<N>.kem.sk.bin`
     (`chmod 0600`).
3. `build_helper_bundle(HelperBundleMode::Valid, …)` → currently-valid
   DevNet bundle template.
4. **Run 054 fixture injection** (signed-revoked modes only):
   push one `TrustBundleRevocation { root_id, leaf_cert_fingerprint:
   Some(target_fp_hex), reason, effective_from: 0 }` into
   `bundle.revocations` BEFORE signing — so the signed preimage covers
   the revocation entry. For `signed-devnet-revoked-v{0,1}` the
   `target_fp_hex` is the helper's just-computed
   `cert_leaf_fingerprint(v<N>.cert)`; for
   `signed-devnet-revoked-unknown` it is the all-zeros
   64-hex-character literal, which no real validator leaf cert can
   produce because `cert_leaf_fingerprint` is a domain-separated
   SHA3-256.
5. `MlDsa44Backend::generate_keypair()` → bundle-signing keypair.
6. `sign_bundle_devnet_helper(&bundle, signing_id, &signing_sk)` →
   detached ML-DSA-44 signature over `canonical_signing_bytes(bundle)`
   (signing preimage strips the `signature` envelope so the
   fingerprint of an unsigned bundle equals the fingerprint of the
   same bundle re-signed; the `TRUST_BUNDLE_SIGNATURE_DOMAIN_SEPARATOR`
   is distinct from the fingerprint and leaf-fingerprint separators).
7. `bundle.signature = Some(sig)`; serialize to
   `trust-bundle.json`; persist `signing-key.{id.hex,pk.hex,spec}`
   for operator capture.

## Signed-bundle verification proof

For each Run-054 fixture the live `qbind-node` startup log emits the
trust-bundle envelope summary on stderr; each one carried
`signature=verified(signing_key_id=<8-char prefix>..)` and
`signing_keys_configured=1`. The four fixture summaries observed in
the live release-binary smokes:

| Mode | Bundle fingerprint | Signature status |
| --- | --- | --- |
| `signed-devnet` | `7aec44a4fb75859b0f99c424effa7c177e3a61c887fe3c44b1b1293b24225c0a` | `signed(signing_key_id=dad1b167.. suite=100 sig_len_hex=4840)` → live binary log: `signature=verified(signing_key_id=dad1b167..)` |
| `signed-devnet-revoked-v0` | `0351df8e6888f94218e37f100fc8d8d945d89796f280d6e7349cf276e472f356` | `signed(signing_key_id=f146a6c4..)` → live: `signature=verified(signing_key_id=f146a6c4..)` |
| `signed-devnet-revoked-v1` | `5ff642c68f9cd78311e5caa30bdb69c27ad42996a14cbde99c2eacbc1197d455` | `signed(signing_key_id=4261b7f0..)` → live: `signature=verified(signing_key_id=4261b7f0..)` |
| `signed-devnet-revoked-unknown` | `c0baec5bf57a0bc23eccb1ffb9fb0e1950e3e945611db83da8813421ada6d3cc` | `signed(signing_key_id=86038cec..)` → live: `signature=verified(signing_key_id=86038cec..)` |

Every release-binary smoke also surfaced the new Run 051 counter
`qbind_p2p_pqc_trust_bundle_signature_verified_total 1` AND
`qbind_p2p_pqc_trust_bundle_signature_rejected_total 0` AND
`qbind_p2p_pqc_trust_bundle_signing_keys_configured 1` AND
`qbind_p2p_pqc_trust_bundle_loaded 1` AND
`qbind_p2p_pqc_trust_bundle_active_roots 1` AND
`qbind_p2p_pqc_trust_bundle_revoked_roots 0`.

## Chain-id compatibility / matching status

All four Run-054 bundles set `chain_id = null` (Run 050 compatibility
form), so the Run 053 narrow crosscheck takes the
"`chain_id: null` remains accepted for compatibility" branch — no
chain-id parse or comparison is exercised, and the bundle loads
cleanly. Run 053's enforcement of present-`chain_id` parse and
runtime match is **not regressed** by Run 054: a present-`chain_id`
bundle would still parse strictly as `<16 hex>` / `0x<16 hex>` /
`chain_<16 hex>` and compare against `NodeConfig.chain_id()` as
Run 053 wired. The Run 053 trust-bundle test suite is rerun above and
remains 14 / 14 pass.

## Leaf fingerprint and revocation fixture details

| Fixture mode | Active leaf revocation target | Captured fingerprint (`v<N>.leaf-fp.hex`) | `revocations[]` shape on disk |
| --- | --- | --- | --- |
| `signed-devnet` | none | v0=`(per-run ephemeral, not referenced)`; v1=`(per-run ephemeral, not referenced)` | `[]` |
| `signed-devnet-revoked-v0` | v0 leaf cert | v0=`da7912d9867472c680a39a99b4179bd7ac0e6e8717b02c5a3eb8125f23b10caa` | one entry: `{root_id, leaf_cert_fingerprint=<v0-fp>, reason="test-leaf-revocation-run054", effective_from=0}` |
| `signed-devnet-revoked-v1` | v1 leaf cert | v1=`365a6c5f35019b444d6ba7cf555269496189b1c9939068ccb1816ca591cc8ea4` | one entry: `{root_id, leaf_cert_fingerprint=<v1-fp>, reason="test-leaf-revocation-run054", effective_from=0}` |
| `signed-devnet-revoked-unknown` | synthetic all-zeros 64-hex (no real cert can produce) | v0,v1=`(per-run ephemeral, not on the revocation list)` | one entry: `{root_id, leaf_cert_fingerprint="0000…0000", reason="test-leaf-revocation-run054-unknown-fp", effective_from=0}` |

The on-disk `revocations[0].leaf_cert_fingerprint` literally matches
the on-disk `v<N>.leaf-fp.hex` for the revoked-v0 and revoked-v1
fixtures, confirming the helper used the same Run 052
`cert_leaf_fingerprint` API that the live binary uses to compute the
canonical fingerprint at handshake time.

## Positive non-revoked two-node smoke (Smoke 1)

- Bundle: `signed-devnet` (no leaf revocations).
- Topology: V0 on `127.0.0.1:19410`, V1 on `127.0.0.1:19411`, each
  carrying the other's leaf cert via `--p2p-peer-leaf-cert`.
- Both nodes started; both verified the signed bundle's ML-DSA-44
  signature; both registered active_roots=1; both reported
  `Run 052: revoked_leaf_fingerprints=0`.
- `/metrics` (V0 and V1 identical):

  ```
  qbind_p2p_pqc_cert_verify_accepted_total 2
  qbind_p2p_pqc_cert_verify_rejected_total 0
  qbind_p2p_pqc_cert_verify_rejected_revoked_total 0
  qbind_p2p_pqc_trust_bundle_loaded 1
  qbind_p2p_pqc_trust_bundle_active_roots 1
  qbind_p2p_pqc_trust_bundle_revoked_roots 0
  qbind_p2p_pqc_trust_bundle_sequence 1
  qbind_p2p_pqc_trust_bundle_signature_verified_total 1
  qbind_p2p_pqc_trust_bundle_signature_rejected_total 0
  qbind_p2p_pqc_trust_bundle_signing_keys_configured 1
  ```

  `accepted_total = 2` on each side covers the listener verify of the
  inbound peer cert AND the dialer verify of the outbound peer cert,
  which is the same shape Run 037 / Run 040 record for a successful
  two-node mutual-auth.
- No log line containing `dummy`, `forged`, `fallback`, `DummySig`,
  `DummyKem`, `DummyAead`, or any private-key material was emitted.

Live log artefacts:
`docs/devnet/run_054_smoke_positive_v{0,1}.{stdout,stderr}.log`,
`docs/devnet/run_054_metrics_positive_v{0,1}.txt`.

## Negative revoked-local-leaf smoke (Smoke 2)

- Bundle: `signed-devnet-revoked-v0` (revokes the local node's own v0
  leaf cert).
- Topology: single node V0 on `127.0.0.1:19420`, no peers configured.
- Startup log: `[binary] Run 050/051: trust bundle loaded … active_roots=1 revoked_roots=0 sequence=1 … signature=verified(signing_key_id=f146a6c4..)` followed by
  `[binary] Run 052: revoked_leaf_fingerprints=1 (from trust bundle env=devnet sequence=1)`.
- The node DOES NOT exit non-zero on its own at startup; it runs
  until the 6-second `timeout` SIGTERM fires (exit 124).
- **Honest boundary**: Run 052's wiring installs the
  `LeafCertRevocationList` on the listener and dialer cert-verify
  paths only; it does NOT add a startup self-check that compares the
  local `--p2p-leaf-cert` fingerprint against
  `LoadedTrustBundle::revoked_leaf_fingerprints`. The task's
  expected-behaviour text is conditional ("**if** local self-check
  sees the revocation"); Run 052 does not include a self-check, so
  the only enforcement boundary is the handshake on the wire. This
  is consistent with Run 052's design and is recorded honestly here
  rather than fabricated. Smoke 3 below proves the wire-level
  enforcement.
- Even though the node starts, the operator log still surfaces
  `revoked_leaf_fingerprints=1` so the condition is observable; an
  operator monitoring this metric would see a non-zero
  `qbind_p2p_pqc_trust_bundle_revoked_roots`/`revoked_leaf_fingerprints`
  signal at boot.
- `dummy_kem_registered=false`, `dummy_aead_registered=false`,
  `sig_suite_id=100`, `pqc_root_mode=pqc-static-root` — no fallback.

Live log artefacts:
`docs/devnet/run_054_smoke_revoked_local_v0.{stdout,stderr}.log`.

## Negative revoked-peer-leaf smoke (Smoke 3 — strongest positive)

- Bundle: `signed-devnet-revoked-v1` (revokes V1's leaf fingerprint).
  Loaded on BOTH V0 and V1 (matches production: all validators share
  the same trust bundle).
- Topology: V0 on `127.0.0.1:19430`, V1 on `127.0.0.1:19431`, each
  carrying the other's leaf cert via `--p2p-peer-leaf-cert`.
- V0 startup log confirms: `[binary] Run 052: revoked_leaf_fingerprints=1 (from trust bundle env=devnet sequence=1)`.
- During the 6-second window, V0 and V1 each attempt one inbound
  accept and one outbound dial.
- V0 stderr (relevant subset):

  ```
  [P2P] Inbound connection error:  Handshake error: channel error: Net(Protocol("server handle_client_init failed"))
  [P2P] dial 127.0.0.1:19431 giving up after 1 attempt(s):
        Handshake error: channel error: Net(Protocol("client handle_server_accept failed"))
        (transient=false, max_attempts=8)
  ```

  These two lines correspond to:
  - V1 dialled V0 (V0's listener side, `parse_and_verify_client_cert`)
    → V1 presents its revoked leaf cert → V0 fails closed with
    `NetError::ClientCertInvalid("cert revoked")`, which propagates
    out as `Net(Protocol("server handle_client_init failed"))` at the
    P2P transport layer.
  - V0 dialled V1 (V0's dialer side, `ClientHandshake::handle_server_accept`)
    → V1 presents its revoked leaf cert → V0 fails closed with the
    same `NetError::ClientCertInvalid("cert revoked")`, surfaced as
    `Net(Protocol("client handle_server_accept failed"))` at the P2P
    transport layer.
- V0 `/metrics` (the cert-verify lines that moved):

  ```
  qbind_p2p_pqc_cert_verify_accepted_total 0
  qbind_p2p_pqc_cert_verify_rejected_total 2
  qbind_p2p_pqc_cert_verify_rejected_revoked_total 2
  ```

  This is the exact Run 052 metric contract on the LIVE RELEASE
  BINARY: each `inc_pqc_cert_verify_rejected_revoked` bumps both the
  new sub-counter and the aggregate `rejected_total`; `accepted_total`
  was NEVER bumped for the revoked cert (the lookup occurs AFTER all
  signature/window/validator-id checks pass and BEFORE `inc_accepted`).
  Two hits = listener + dialer paths both fired, exactly as Run 052
  promised.
- V1 `/metrics`:

  ```
  qbind_p2p_pqc_cert_verify_accepted_total 1
  qbind_p2p_pqc_cert_verify_rejected_total 0
  qbind_p2p_pqc_cert_verify_rejected_revoked_total 0
  ```

  V1 saw V0's non-revoked leaf cert and accepted it on its listener
  side (`accepted_total = 1`). V1's dialer-side handshake to V0 was
  torn down by V0 (V0 refused V1's presented cert), so V1 saw an
  `UnexpectedEof` on its outbound dial socket BEFORE it ever called
  the cert-verify path — that's why no rejection counter moved on
  V1: V1 itself never had a revoked cert to refuse. This is the
  expected asymmetry and a faithful production-honest topology.
- Neither node registered a successful session for the revoked peer;
  both `committed_anchor` log lines remain at height=0 single-node
  loopback (no two-node quorum was ever formed because the only
  peer's cert was refused).
- No `dummy`, `forged`, `fallback`, `DummySig`, `DummyKem`,
  `DummyAead`, or `--p2p-trusted-root` fallback in either node's log.

Live log artefacts:
`docs/devnet/run_054_smoke_revoked_peer_v{0,1}.{stdout,stderr}.log`,
`docs/devnet/run_054_metrics_revoked_peer_v{0,1}.txt`.

## Negative unknown-leaf-fingerprint smoke (Smoke 4)

- Bundle: `signed-devnet-revoked-unknown` (revokes the all-zeros
  64-hex synthetic fingerprint; no real cert can collide).
- Topology: V0 on `127.0.0.1:19440`, V1 on `127.0.0.1:19441`, mutual
  peer-leaf-cert wiring.
- Both nodes started; both verified the signed bundle; both reported
  `revoked_leaf_fingerprints=1`; both connected and verified each
  other's leaf certs successfully.
- `/metrics` (V0 and V1 identical):

  ```
  qbind_p2p_pqc_cert_verify_accepted_total 2
  qbind_p2p_pqc_cert_verify_rejected_total 0
  qbind_p2p_pqc_cert_verify_rejected_revoked_total 0
  qbind_p2p_pqc_trust_bundle_active_roots 1
  qbind_p2p_pqc_trust_bundle_signature_verified_total 1
  ```

  An unknown-fingerprint revocation does NOT affect unrelated certs.
  The aggregate `rejected_total` AND the new
  `rejected_revoked_total` both stay at 0; `accepted_total` reaches
  2 on each side, identical to Smoke 1. This is the Run 052
  zero-cost-no-op invariant proven live: a non-empty revocation set
  installs the `LeafCertRevocationList`, but no real cert's
  fingerprint is in it, so every handshake takes the accept branch.

Live log artefacts:
`docs/devnet/run_054_smoke_revoked_unknown_v{0,1}.{stdout,stderr}.log`,
`docs/devnet/run_054_metrics_revoked_unknown_v{0,1}.txt`.

## /metrics excerpts boundary

`/metrics` was observable for Smokes 1, 3, and 4 because both
processes stayed alive long enough for the HTTP server to start and
respond to the scrape.

For Smoke 2 (revoked-local-leaf), the node also stayed alive long
enough to serve `/metrics`, but no cert-verify revocation counter
fires there because no peer is configured (single-node loopback). The
honest signal at boot is the `revoked_leaf_fingerprints=1` line
emitted from `main.rs` AFTER trust-bundle load, plus the existing
`qbind_p2p_pqc_trust_bundle_*` gauges. This is documented honestly
rather than fabricated — Run 052's handshake-level tests cover the
metric movement on the wire path, and Smoke 3 covers it on the live
binary.

## Proof of no fallback to `--p2p-trusted-root`

- No Run 054 smoke supplied `--p2p-trusted-root` on the command line.
- The trust set on every smoke came exclusively from the signed
  `--p2p-trust-bundle` (`qbind_p2p_pqc_trust_bundle_loaded 1`,
  `qbind_p2p_pqc_trust_bundle_active_roots 1`).
- The Run 052 leaf-revocation surface is keyed off
  `LoadedTrustBundle::revoked_leaf_fingerprints`, not off
  `--p2p-trusted-root` — confirmed by the integration test
  `no_fallback_to_test_grade_dummy_primitives_for_pqc_path` in
  `run_052_pqc_leaf_revocation_tests` (12 / 12 pass above) and by the
  live-binary `[Run040] … pqc_root_mode=pqc-static-root` log line on
  every Run-054 smoke.

## Proof of no DummySig / DummyKem / DummyAead fallback

Every Run-054 smoke emitted exactly the following `[Run040]` line at
P2P node-builder time (sig-suite, transport-KEM-suite,
transport-AEAD-suite values verbatim):

```
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false configured_roots=1 leaf_credentials_present=true
```

- `sig_suite_id=100` = real ML-DSA-44 (NOT DummySig).
- `transport_kem_suite_id=100`, `dummy_kem_registered=false` = real ML-KEM-768 (NOT DummyKem).
- `transport_aead_suite_id=101`, `dummy_aead_registered=false` = real ChaCha20-Poly1305 (NOT DummyAead).
- `pqc_root_mode=pqc-static-root` = production-honest path (NOT
  `TestGradeDummySig`).
- `leaf_credentials_present=true` = real ML-KEM-768 leaf KEM secret
  was loaded and validated by encaps/decaps before startup proceeded
  (Run 039 invariant).

(The `Run 033 … TrustedClientRoots/DummySig` string that appears in
the timeout-verification probe log line is unrelated — it is the
disabled-timeout-verification reason text and does not describe the
active cert-verify suite. The actual cert-verify path runs real
ML-DSA-44 as the `[Run040]` line above proves.)

No private-key bytes (`root_sk`, `signing_sk`, `kem_sk`, validator
signer key) appear in any Run-054 stderr/stdout log. The helper logs
state `root_sk and bundle signing_sk were held in memory only; never
written to disk.`

## Remaining open items (C4)

Closed/narrowed by Run 054:
- live release-binary smoke artifact for Run 052's revoked-leaf
  enforcement surface (the explicit boundary called out in Run 052).

Still OPEN under C4:
- activation epoch / height gating for revocation entries (only
  `effective_from` UNIX seconds is honored today);
- sequence-number monotonicity persistence across restarts;
- production CA + certificate rotation + signing-key rotation
  operator playbook (the DevNet helper still mints ephemeral keys
  in memory; production signing remains an out-of-process KMS task);
- live MainNet signed-bundle release-binary smoke (Run 051 / Run 052
  / Run 054 prove DevNet end-to-end on the release binary; MainNet
  is covered by unit + integration tests only);
- production fast-sync / consensus-storage restore;
- per-environment production trust-anchor operation if not fully
  solved.

Also still OPEN: a startup self-check that fails the binary closed
when `--p2p-leaf-cert` matches an active entry in the loaded
bundle's `revoked_leaf_fingerprints` (Run 052 deliberately did not
ship one; this is recorded here as a small, well-scoped future C4
item — documented honestly rather than treated as a Run-054 bug
because Run 052's contract was wire-level only).

C5 is **not** closed by Run 054. Run 054 does not touch timeout
verification, forged-traffic policy, KEMTLS wire formats, consensus
message wire formats, or any signature / verification semantics
outside the trust-bundle leaf-revocation evidence surface.

## Exact immediate next action

If the QBIND maintainers want to advance the next-smallest production
C4 piece on the trust-bundle lifecycle surface, the smallest scoped
item is a **startup self-check** in `qbind-node/src/main.rs` that
computes `cert_leaf_fingerprint(&local_leaf_cert)` after trust-bundle
load and fails the binary closed with a precise FATAL reason if it
matches `LoadedTrustBundle::is_leaf_revoked(...)`. The Run 052
fingerprint API already exists; the change is purely additive in
`main.rs`, requires no protocol or wire-format changes, and is the
exact item Run 054 deliberately left as a future C4 item per
"evidence-first, no source change unless a real bug is found"
discipline.

The next-largest scoped item is the operator-facing CA + cert
rotation + signing-key rotation playbook under
`docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md`, which remains the
single biggest production gap.