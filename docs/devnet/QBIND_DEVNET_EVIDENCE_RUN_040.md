# QBIND DevNet Evidence — Run 040

**Run:** 040 — Real AEAD on the `pqc-static-root` binary path (replaces `DummyAead`)
**Date:** 2026-05-10
**Status:** ✅ **Strongest positive** for the AEAD-only objective. C4 remains OPEN for CA / cert rotation / cert revocation / signed root distribution lifecycle and for `qbind_p2p_pqc_*` live `/metrics` exposure (out of scope for Run 040).

---

## 1. Exact objective

Replace the test-grade `DummyAead` used by the `pqc-static-root` binary path with the existing production-honest AEAD primitive (`ChaCha20Poly1305Backend` already present in `crates/qbind-crypto/src/chacha20poly1305.rs`), without redesigning KEMTLS or transport identity. Preserve the Run 037 ML-DSA-44 cert path and the Run 039 ML-KEM-768 KEM path bit-for-bit; preserve the pre-Run-040 test-grade B7/B8/B12 `DummyAead` path bit-for-bit on its own explicit mode.

Out of scope (explicitly): production CA / cert rotation / cert revocation / signed root distribution lifecycle; `qbind_p2p_pqc_*` live `/metrics` exposure; HotStuff / B14 / snapshot/restore redesign.

---

## 2. Investigation findings (exact file/function references)

### 2.1 Current `DummyAead` registration site

- **`crates/qbind-node/src/p2p_node_builder.rs:269-328`** — the test-grade `DummyAead` definition (XOR with a single-byte key, 1-byte “tag” = XOR of AAD bytes). Pre-Run-040 it was registered both by `make_test_crypto_provider` (line 339, suite id `2`) and by `make_pqc_static_root_crypto_provider` (line 364, also suite id `2`). The test-grade `DummyAead` is left in place for the explicit `PqcRootMode::TestGradeDummySig` (default) so B7/B8/B12 / T138 / T143 / T160 / T222 etc. tests remain bit-for-bit.
- **`crates/qbind-node/src/p2p_node_builder.rs:813`** (pre-Run-040) — the binary-path build site set `aead_suite_id: u8 = 2` regardless of `pqc_active`, then passed it to either `make_pqc_static_root_crypto_provider(aead_suite_id, sig_suite_id)` or `make_test_crypto_provider(...)`.

### 2.2 AEAD abstraction used by `qbind-net` / KEMTLS

- **`crates/qbind-crypto/src/aead.rs`** — `AeadSuite` trait (`suite_id`, `key_len`, `nonce_len`, `tag_len`, `seal`, `open`).
- **`crates/qbind-crypto/src/provider.rs:30-67`** — `StaticCryptoProvider` registers AEAD suites by id and exposes them via `CryptoProvider::aead_suite(suite_id) -> Option<&dyn AeadSuite>`.
- **`crates/qbind-net/src/handshake.rs`** — `ClientHandshakeConfig.aead_suite_id` (line 156), `ServerHandshakeConfig.aead_suite_id` (line 392). On `client handle_server_accept` and `server handle_client_init`, the code calls `crypto.aead_suite(aead_suite_id)` and fails closed with `NetError::UnsupportedSuite(aead_suite_id)` if it is not registered (`handshake.rs:330-331`, `:561-562`, `:716-717`, `:874-875`). The resulting AEAD suite is passed into `AeadSession::new(...)` together with `SessionKeys`.
- **`crates/qbind-net/src/keys.rs:260-316`** — `SessionKeys::derive` uses `info = [kem_suite_id, aead_suite_id]` inside HKDF-Expand-Label, so a mismatched `aead_suite_id` between dialer and listener produces a different key on each side and immediately fails closed at the first encrypted frame. `key_len` is taken from `AeadSuite::key_len()`.
- **`crates/qbind-net/src/session.rs:6-148`** — nonce layout is `flag(1) || session_id(3) || counter(8)` (12 bytes total, fits ChaCha20-Poly1305’s 96-bit nonce), counter increments per direction; `AeadKeyMaterial` zeroizes on drop; `AeadSession` zeroizes its keys on drop (`session.rs:97`).

### 2.3 Existing production AEAD implementation

- **`crates/qbind-crypto/src/chacha20poly1305.rs`** — full `ChaCha20Poly1305Backend` already implemented and unit-tested (round trip, tampered ciphertext, wrong key, wrong nonce, wrong AAD, truncated, large message, invalid key length, invalid nonce length, suite constants — 14 tests passing). Suite id is `AEAD_SUITE_CHACHA20_POLY1305 = 101`. Key 32 bytes, nonce 12 bytes, tag 16 bytes. Failure on bad tag / wrong key / wrong nonce / malformed ciphertext returns `CryptoError::InvalidCiphertext`. The cipher state is constructed per-call from the key, so there is no long-lived plaintext state to log.

### 2.4 Key schedule integration

The KEMTLS key schedule already mixes `aead_suite_id` into HKDF-Expand-Label info (`crates/qbind-net/src/keys.rs:292`). It assumed nothing about the body of the AEAD beyond `key_len`, which `ChaCha20Poly1305Backend::key_len() == 32` matches the `DummyAead::key_len() == 32` it replaces. **No change to the key schedule is required, and none was made.** Transcript binding (certified peer identity via the ML-DSA-44 delegation cert, root/cert verification state, ML-KEM-768 KEM result, and any existing chain/network binding established by Runs 037–039) is unchanged.

---

## 3. Files changed (exact)

| File | Change |
|---|---|
| `crates/qbind-node/src/p2p_node_builder.rs` | (a) Import `ChaCha20Poly1305Backend` and `AEAD_SUITE_CHACHA20_POLY1305` from `qbind_crypto`. (b) Rewrite `make_pqc_static_root_crypto_provider` to register `Arc::new(ChaCha20Poly1305Backend::new())` instead of `Arc::new(DummyAead::new(aead_suite_id))`; drop the now-unused `aead_suite_id` parameter. (c) In `build()`, set `aead_suite_id = AEAD_SUITE_CHACHA20_POLY1305` when `pqc_active`, otherwise keep the pre-Run-040 default `2`. (d) Update the startup log from `[Run039]` to `[Run040]` and add `transport_aead_suite_id`, `transport_aead_suite_name`, and `dummy_aead_registered` fields. `DummyAead` definition unchanged and remains registered only by `make_test_crypto_provider` (test/dev mode). |
| `crates/qbind-node/tests/run_040_pqc_static_root_real_aead_tests.rs` | New file. 14 tests: provider-shape (3) + AEAD fail-closed (9) + two-node Required + `pqc-static-root` real-AEAD smoke (1) + test-grade preservation (1). |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_040.md` | New file (this document). |
| `docs/whitepaper/contradiction.md` | Append Run 040 narrowing paragraph after the Run 039 paragraph. |

---

## 4. Exact commands run

```bash
# Build check
cargo check -p qbind-node --lib
# Build the binary on the same tree the integration tests load
cargo build -p qbind-node --bin qbind-node

# Run 040 tests (provider/AEAD/handshake)
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests \
  r040_c_two_node -- --nocapture     # captures the [Run040] startup log

# Regression suites
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test -p qbind-node --test t138_three_node_pqc_full_stack_tests
cargo test -p qbind-node --test t139_real_pqc_kemtls_two_node_tests
cargo test -p qbind-node --test kemtls_handshake_concurrency_tests
cargo test -p qbind-node --test kemtls_encrypted_transport_tests
cargo test -p qbind-node --test t160_devnet_cluster_harness
cargo test -p qbind-node --lib
cargo test -p qbind-crypto --lib
cargo test -p qbind-net --lib

# Binary identity
sha256sum target/debug/qbind-node
file target/debug/qbind-node | grep -oE 'BuildID\[sha1\]=[0-9a-f]+'
git rev-parse HEAD
git status --porcelain
```

---

## 5. Tests run and pass/fail status

| Suite | Result |
|---|---|
| `qbind-node --test run_040_pqc_static_root_real_aead_tests` | **14 passed; 0 failed** |
| `qbind-node --test run_037_pqc_static_root_mutual_auth_tests` (Run 037 + Run 039) | **12 passed; 0 failed** |
| `qbind-node --test t138_three_node_pqc_full_stack_tests` | **15 passed; 0 failed** |
| `qbind-node --test t139_real_pqc_kemtls_two_node_tests` | **4 passed; 0 failed** |
| `qbind-node --test kemtls_handshake_concurrency_tests` | **8 passed; 0 failed** |
| `qbind-node --test kemtls_encrypted_transport_tests` | **8 passed; 0 failed** (incl. `real_aead_detects_ciphertext_tampering`, `mlkem768_chacha20poly1305_full_stack_test`) |
| `qbind-node --test t160_devnet_cluster_harness` | **7 passed; 0 failed; 2 ignored** (pre-existing ignore on long soak) |
| `qbind-node --lib` | **767 passed; 0 failed** |
| `qbind-crypto --lib` | **68 passed; 0 failed** (incl. `chacha20poly1305::tests::*` — 14 fail-closed tests at the AEAD primitive level) |
| `qbind-net --lib` | **15 passed; 0 failed** |

The 14 new Run 040 tests:

```
r040_a_pqc_static_root_provider_does_not_register_dummy_aead ............ ok
r040_a_pqc_static_root_provider_keeps_ml_kem_768_and_ml_dsa_44 .......... ok
r040_a_pqc_static_root_provider_registers_real_chacha20_poly1305 ........ ok
r040_b_real_aead_malformed_key_fails_closed ............................. ok
r040_b_real_aead_malformed_nonce_fails_closed ........................... ok
r040_b_real_aead_round_trip_succeeds .................................... ok
r040_b_real_aead_tampered_ciphertext_fails_closed ....................... ok
r040_b_real_aead_tampered_tag_fails_closed .............................. ok
r040_b_real_aead_truncated_frame_fails_closed ........................... ok
r040_b_real_aead_wrong_aad_fails_closed ................................. ok
r040_b_real_aead_wrong_key_fails_closed ................................. ok
r040_b_real_aead_wrong_nonce_fails_closed ............................... ok
r040_c_two_node_required_pqc_static_root_real_aead_succeeds ............. ok
r040_d_test_grade_provider_still_registers_dummy_aead_at_suite_id_2 ..... ok
```

---

## 6. AEAD suite wiring explanation

`P2pNodeBuilder::build` decides `pqc_active` from `with_pqc_root_config(cfg)` where `cfg.mode == PqcStaticRoot`. When `pqc_active`:

- `kem_suite_id = KEM_SUITE_ML_KEM_768 = 100` (Run 039 invariant; real `MlKem768Backend`).
- `sig_suite_id = PQC_TRANSPORT_SUITE_ML_DSA_44 = 100` (Run 037 invariant; real `MlDsa44SignatureSuite`).
- **`aead_suite_id = AEAD_SUITE_CHACHA20_POLY1305 = 101`** (**Run 040 change**; real `ChaCha20Poly1305Backend`).
- `crypto = make_pqc_static_root_crypto_provider(sig_suite_id)` registers all three real backends in a `StaticCryptoProvider`. **`DummyAead` is not registered on this provider.**

The dialer and listener both consume the same `pqc_active` decision via their own `with_pqc_root_config(...)` call, so the `aead_suite_id` advertised in `ClientInit` (`crates/qbind-net/src/handshake.rs:272`) matches the `ServerHandshakeConfig.aead_suite_id` configured on the listener (`handshake.rs:561`, `:874`). A mismatch fails closed with `NetError::UnsupportedSuite(...)` at the listener, and a silent suite-id rewrite by an attacker fails closed at the first encrypted frame because `aead_suite_id` is mixed into the HKDF info parameter (`crates/qbind-net/src/keys.rs:292`).

When `pqc_active` is false (the explicit `PqcRootMode::TestGradeDummySig` default), the builder still selects `aead_suite_id = 2` and builds `make_test_crypto_provider(...)` which registers `DummyAead` at suite id `2`. This path is unchanged by Run 040 and is exercised bit-for-bit by R037.F, R040.D, T138, T143, T160, T222, etc.

The `[Run040] P2pNodeBuilder: ...` startup log (printed once at build time, never logging keys, nonces, plaintext, shared secrets, or handshake secrets) is the operator-facing signal that real AEAD is active. Sample (captured live from `r040_c_two_node_required_pqc_static_root_real_aead_succeeds -- --nocapture`):

```
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 \
  transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false \
  transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false \
  configured_roots=1 leaf_credentials_present=true
```

And, for explicit comparison, the test-grade default (captured live from `r037_f_test_grade_dummy_sig_path_preserved -- --nocapture`):

```
[Run040] P2pNodeBuilder: pqc_root_mode=test-grade-dummy-sig sig_suite_id=3 \
  transport_kem_suite_id=1 transport_kem_suite_name=dummy-kem dummy_kem_registered=true \
  transport_aead_suite_id=2 transport_aead_suite_name=dummy-aead dummy_aead_registered=true \
  configured_roots=0 leaf_credentials_present=false
```

These two log shapes are intentionally diff-able. There is no path in `P2pNodeBuilder::build` that emits `dummy_aead_registered=false` while silently registering `DummyAead`, because the `transport_aead_suite_name` and `dummy_aead_registered` fields are derived from the same `pqc_active` boolean that selects the provider.

---

## 7. Key schedule / transcript-binding explanation

No change. Run 040 is strictly an AEAD-suite swap, not a key-schedule change:

- HKDF-Extract salt = `"QBIND:KDF" || transcript_hash` (unchanged).
- HKDF-Expand-Label info = `[kem_suite_id, aead_suite_id]` (unchanged shape; `aead_suite_id` value moves from `2` to `101` in pqc-static-root mode, which is the desired behaviour).
- `key_len` from `AeadSuite::key_len()` (unchanged at `32` because both `DummyAead` and `ChaCha20Poly1305Backend` report 32).
- Nonce layout `flag(1) || session_id(3) || counter(8)` (unchanged; ChaCha20-Poly1305’s 96-bit nonce accepts this layout).
- Transcript binding established by Runs 037–039 (certified peer identity via ML-DSA-44 delegation cert; root/cert verification via operator-configured trusted roots; ML-KEM-768 ciphertext / shared secret) is **unchanged and untouched**.

Counter overflow protection: the existing `AeadSession` counter (`crates/qbind-net/src/session.rs:6-148`) is `u64` and rejects overflow; this is unchanged by Run 040.

---

## 8. Binary identity

```
branch:                  copilot/continue-qbind-current-state-please-work
commit (pre-Run-040):    01a528bf6e0e8a70357eb34597f3671873bd2179
git status --porcelain:  M crates/qbind-node/src/p2p_node_builder.rs
                         ?? crates/qbind-node/tests/run_040_pqc_static_root_real_aead_tests.rs
                         (clean apart from this PR's changes)
binary path:             target/debug/qbind-node
binary sha256:           5a8ae3740984f745edc24e6e7c34a50ff543833f5d9a431594a6298c6dbcb12d
ELF BuildID[sha1]:       463f6f303c602723e8b1f7d7cf395269d4cb5acd
binary size:             291,119,992 bytes (debug)
```

Helper not rebuilt for Run 040 (no helper change; `pqc_devnet_helper` and `devnet_pqc_root_helper` example are unchanged from Run 039).

---

## 9. Topology

The Run 040 real-binary positive evidence reuses the same `P2pNodeBuilder` build-and-listen path that the production binary `crates/qbind-node/src/main.rs::run_p2p_node` uses; specifically:

- `R040.C`: two-node N=2 mesh, `127.0.0.1:<rand>` ↔ `127.0.0.1:<rand>`, V0 ↔ V1, both under `MutualAuthMode::Required` + `PqcRootMode::PqcStaticRoot` with one shared DevNet root, real ML-DSA-44-signed `NetworkDelegationCert` per node, real ML-KEM-768 leaf KEM material per node, real ChaCha20-Poly1305 AEAD on both sides. Each side carries the other's leaf cert via `--p2p-peer-leaf-cert VID:PATH` (Run 039 invariant).

The N=4 Required + `pqc-static-root` + `--require-timeout-verification` absent-leader B14 recovery shape from Run 038/039 is deliberately not re-executed in this evidence pass under Run 040 because the binary's transport-AEAD selection is a per-provider decision driven by the same `pqc_active` switch that Runs 038/039 already validated end-to-end on N=4 — i.e. the only thing changed for those validators between Run 039 and Run 040 is `with_aead_suite(...)` from `DummyAead(2)` to `ChaCha20Poly1305Backend(101)`. The Run 040 R040.C two-node real-binary handshake is therefore the smallest honest evidence that proves real AEAD is active on the same builder path the N=4 Required + `pqc-static-root` Run 039 evidence already exercised; an N=4 Run 040 capture is recommended as a follow-up confirmatory smoke under §13 below but is not load-bearing for the AEAD claim.

---

## 10. Logs proving real AEAD is active

Captured live (above) from the integration test:

```
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 \
  transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false \
  transport_aead_suite_id=101 transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false \
  configured_roots=1 leaf_credentials_present=true
```

Programmatic proof in addition to the log: `r040_a_pqc_static_root_provider_registers_real_chacha20_poly1305` directly inspects the `StaticCryptoProvider` built by the same recipe `make_pqc_static_root_crypto_provider` uses and asserts `aead_suite(101).suite_id() == 101 && key_len() == 32 && nonce_len() == 12 && tag_len() == 16`; `r040_a_pqc_static_root_provider_does_not_register_dummy_aead` asserts `aead_suite(2).is_none()` and `aead_suite(0).is_none()`.

Concrete handshake-level proof: `r040_c_two_node_required_pqc_static_root_real_aead_succeeds` runs two real `P2pNodeBuilder`-built P2P services and waits for each side to observe the other's cert-derived `NodeId` among connected peers. Because `aead_suite_id=101` is mixed into the HKDF info on both sides, the only way both directions can succeed is if both sides resolved suite id `101` to a real ChaCha20-Poly1305 backend; if either side were still registering only `DummyAead(2)`, `qbind_net::handshake` would fail closed with `NetError::UnsupportedSuite(101)`.

---

## 11. Metrics proving real AEAD active

Run 040 does **not** add new live `/metrics` counters. The Run 038/039 observability gap on `qbind_p2p_pqc_*` live `/metrics` exposure is **explicitly carried forward as OPEN** (see §14). Run 040 relies on:

1. The deterministic startup log `[Run040] P2pNodeBuilder: ... transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false ...` (above);
2. The provider-shape unit tests (R040.A) that fail loudly if anyone reverts the wiring;
3. The two-node real-binary handshake test (R040.C) that fails with `UnsupportedSuite(101)` if `DummyAead` were still on the binary path.

The existing `qbind_kemtls_*` and `qbind_aead_*` metrics defined elsewhere in the codebase are unchanged; they continue to count handshake/AEAD operations once the live metrics endpoint is wired (a separate C4 follow-up).

---

## 12. Positive evidence (summary)

- ✅ `pqc-static-root` Required mode registers real `ChaCha20Poly1305Backend` at suite id `101` and registers no AEAD at suite id `2`.
- ✅ Real AEAD round trip succeeds; tag length is exactly 16 bytes.
- ✅ Two-node `MutualAuthMode::Required` + `PqcRootMode::PqcStaticRoot` + real ML-DSA-44 cert + real ML-KEM-768 KEM + real ChaCha20-Poly1305 AEAD handshake completes; both sides observe each other's cert-derived `NodeId`.
- ✅ Startup log honestly reports `transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false` on the pqc-static-root path.
- ✅ Run 037 cert-verification path passes unchanged (12/12).
- ✅ Run 039 ML-KEM-768 KEM negative cases pass unchanged (mismatched secret, missing peer leaf cert — both fail closed at build).
- ✅ B7/B8/B12 / T138 / T139 / T160 / T222 / VM-v0 snapshot suites pass unchanged (full `qbind-node` lib 767/767, plus the listed integration suites).
- ✅ `qbind-crypto` lib 68/68 (incl. all 14 ChaCha20-Poly1305 fail-closed tests at the primitive level).
- ✅ `qbind-net` lib 15/15.

## 13. Negative evidence (summary)

- ✅ Wrong AEAD key fails closed (`r040_b_real_aead_wrong_key_fails_closed`).
- ✅ Wrong AEAD nonce fails closed (`r040_b_real_aead_wrong_nonce_fails_closed`).
- ✅ Wrong AAD fails closed (`r040_b_real_aead_wrong_aad_fails_closed`).
- ✅ Tampered ciphertext fails closed (`r040_b_real_aead_tampered_ciphertext_fails_closed` and the existing `kemtls_encrypted_transport_tests::real_aead_detects_ciphertext_tampering`).
- ✅ Tampered authentication tag fails closed (`r040_b_real_aead_tampered_tag_fails_closed`).
- ✅ Truncated frame (shorter than 16-byte tag) fails closed (`r040_b_real_aead_truncated_frame_fails_closed`).
- ✅ Malformed AEAD key length fails closed (`r040_b_real_aead_malformed_key_fails_closed`).
- ✅ Malformed AEAD nonce length fails closed (`r040_b_real_aead_malformed_nonce_fails_closed`).
- ✅ Mismatched ML-KEM-768 leaf secret still fails closed at build (Run 039 invariant: `r039_mismatched_ml_kem_leaf_secret_fails_closed_at_build`).
- ✅ Missing certified peer leaf cert under `Required` + `pqc-static-root` still fails closed before any DummyKem fallback (Run 039 invariant: `r039_missing_peer_leaf_cert_fails_closed_before_dummy_kem_fallback`).
- ✅ Tampered ML-DSA-44 cert still fails closed (Run 037 invariant: `r037_b_tampered_signature_rejected_by_real_pqc_verifier`).
- ✅ Untrusted root id still fails closed (Run 037 invariant: `r037_c_untrusted_root_rejected`).
- ✅ Wrong sig suite id still fails closed (Run 037 invariant: `r037_d_wrong_sig_suite_rejected`).
- ✅ No silent fallback to `DummyAead` — `r040_a_pqc_static_root_provider_does_not_register_dummy_aead` directly asserts `provider.aead_suite(2).is_none()`. The startup log additionally prints `dummy_aead_registered=false`.
- ✅ No silent fallback to `DummyKem` — Run 039 invariant preserved.
- ✅ No silent fallback to `DummySig` — Run 037 invariant preserved.
- ✅ Process remains alive across all positive and negative cases (rust integration tests would surface a panic; none observed).

**Boundary explicitly stated:** Tampered encrypted-frame injection on the live two-node binary surface is not exercised in this evidence pass because there is no existing in-process encrypted-frame injection harness on the Run 037/038/039 path. AEAD authentication-failure coverage in this run therefore relies on the provider/AEAD primitive tests above (R040.B and the existing `chacha20poly1305::tests::*` and `kemtls_encrypted_transport_tests::real_aead_detects_ciphertext_tampering`), which exercise the exact same `ChaCha20Poly1305Backend` instance that the binary path now registers on its `StaticCryptoProvider`. An end-to-end live tampered-frame injection harness is recommended as a follow-up (see §15).

---

## 14. Remaining open items (explicit non-claims)

- ❌ **CA / cert rotation / cert revocation / signed root-distribution lifecycle is NOT solved.** Production root-key distribution, cert rotation, cert revocation, OCSP/CRL-equivalent, and root distribution channel remain operator-out-of-band. Tracked under C4.
- ❌ **Full C4 is NOT closed.** Run 040 narrows C4 only on the AEAD piece. Lifecycle, observability (`qbind_p2p_pqc_*` `/metrics`), production fast-sync/consensus-storage restore, and exponential-backoff timeout pacing remain open under C4.
- ❌ **`qbind_p2p_pqc_*` live `/metrics` exposure remains OPEN** (Run 038/039 gap; not addressed by Run 040). Run 040 uses startup logs + provider-shape tests + a two-node real-binary handshake as the AEAD-active proof, not live `/metrics` counters.
- ❌ **Production transport lifecycle remains operator-out-of-band.** Run 040 does not change this.
- ❌ **Test-grade provider path remains test/dev only.** `make_test_crypto_provider` still registers `DummyKem` (suite id `1`), `DummyAead` (suite id `2`), and `DummySig` (suite id `3`) for the explicit `PqcRootMode::TestGradeDummySig` default; this path is not active under `--p2p-pqc-root-mode pqc-static-root` and Run 040 does not reuse those suite ids on the production-honest path.
- ❌ **N=4 Run 040 real-binary B14 absent-leader recovery capture is not in this evidence pass.** It is recommended as a follow-up confirmatory smoke (§15) but is not load-bearing for the AEAD claim because the only delta from Run 039 on the binary path is the AEAD provider registration, which is verified on the same `P2pNodeBuilder` recipe by R040.A and exercised end-to-end on a two-node Required + pqc-static-root smoke by R040.C.

---

## 15. Exact verdict

✅ **Strongest positive (AEAD-only, scope-bounded).**

`DummyAead` is replaced by real `ChaCha20Poly1305Backend` on the `pqc-static-root` Required-mode binary path. The two-node real-binary positive smoke under `--p2p-mutual-auth required` + `--p2p-pqc-root-mode pqc-static-root` + real ML-DSA-44 cert + real ML-KEM-768 KEM + real ChaCha20-Poly1305 AEAD passes. Negative AEAD/KEM/cert smokes fail closed. No `DummySig`/`DummyKem`/`DummyAead` fallback in pqc-static-root mode (`provider.aead_suite(2).is_none()`, `provider.kem_suite(1).is_none()`, `provider.signature_suite(3).is_none()`). Run 037 / Run 038 / Run 039 / B7/B8/B12 / VM-v0 / B14 timeout-verification regression suites continue to pass.

**Run 040 does NOT claim full production transport security.** CA / cert rotation / cert revocation / signed root distribution remain operator-out-of-band, and `qbind_p2p_pqc_*` live `/metrics` exposure remains OPEN. C4 remains OPEN; Run 040 narrows the AEAD piece only.

---

## 16. Immediate next action recommended

1. **Confirmatory N=4 real-binary capture (operator follow-up).** Re-run the Run 038/039 N=4 Required-mode + `--p2p-pqc-root-mode pqc-static-root` + `--require-timeout-verification` + four signer keystores + four `--validator-consensus-key` entries + four `--p2p-peer-leaf-cert VID:PATH` entries B14 absent-leader recovery shape with the Run 040 binary, capture the `[Run040] ... transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false` log on every node, and confirm the same `committed_height` / `current_view` / TC formation / verified-timeout/NewView accept counters / zero-rejection invariants the Run 038/039 evidence already documented hold under the real-AEAD wiring. (Not load-bearing for the AEAD claim, but recommended for ops sign-off.)
2. **Live `/metrics` exposure of `qbind_p2p_pqc_*`** (Run 038/039 OPEN gap) — separate small task, can be its own run.
3. **Begin design of CA / cert-rotation / cert-revocation / signed root-distribution lifecycle** (C4 piece (c) lifecycle subitem). Out of Run 040 scope.