# QBIND DevNet Evidence Run 039 — ML-KEM-768 transport KEM for pqc-static-root

## Objective

Replace the test-grade `DummyKem` on the `pqc-static-root` binary path with real ML-KEM-768 while preserving Run 038's Required-mode B14 recovery shape. Scope is transport KEM only; `DummyAead` remains and full C4 is not closed.

## Files changed

- `Cargo.lock`
- `crates/qbind-node/src/p2p_node_builder.rs`
- `crates/qbind-node/src/pqc_root_config.rs`
- `crates/qbind-node/src/pqc_devnet_helper.rs`
- `crates/qbind-node/examples/devnet_pqc_root_helper.rs`
- `crates/qbind-node/src/cli.rs`
- `crates/qbind-node/src/main.rs`
- `crates/qbind-node/tests/run_037_pqc_static_root_mutual_auth_tests.rs`
- `docs/whitepaper/contradiction.md`
- `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_039.md`

## Investigation findings

- `make_pqc_static_root_crypto_provider` registered `DummyKem::new(kem_suite_id)` in `crates/qbind-node/src/p2p_node_builder.rs`; Run 039 changes that provider to register `MlKem768Backend::new()`.
- KEM suite selection is explicit via `ClientHandshakeConfig.kem_suite_id` / `ServerHandshakeConfig.kem_suite_id` and provider lookup in `qbind-net/src/handshake.rs::ClientHandshake::start` and `ServerHandshake::handle_client_init_inner`.
- The KEM abstraction was already pluggable through `qbind_crypto::KemSuite` and `StaticCryptoProvider::with_kem_suite`.
- Existing ML-KEM-768 support is `crates/qbind-crypto/src/ml_kem768.rs`: suite id `100`, public key 1184 bytes, secret key 2400 bytes, ciphertext 1088 bytes, shared secret 32 bytes; malformed public keys/secret keys/ciphertexts fail closed through `CryptoError`.
- KEM secret material is wrapped by `qbind_net::keys::KemPrivateKey` and shared secrets by `SharedSecret`, both zeroize on drop.
- `NetworkDelegationCert.leaf_kem_pk` is consumed from `--p2p-leaf-cert`; Run 039 validates that it is ML-KEM-768 suite id 100 and 1184 bytes, and validates the supplied `--p2p-leaf-cert-key` by an encaps/decaps match before startup proceeds.
- Dialer-side certified peer KEM public keys are supplied explicitly through new repeated `--p2p-peer-leaf-cert VID:PATH`; `P2pNodeBuilder` verifies each peer cert against configured roots before using `leaf_kem_pk` for ClientInit encapsulation.

## KEM suite wiring

`pqc-static-root` mode now uses `KEM_SUITE_ML_KEM_768` (`100`) for KEMTLS. The production-honest provider registers ML-KEM-768 and ML-DSA-44; `DummyKem` remains only on the explicit default/test-grade provider path. Logs prove the active binary path with:

```text
[Run039] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false
```

## Helper material format

`devnet_pqc_root_helper` now writes:

- `vN.cert.bin`: ML-DSA-44-signed `NetworkDelegationCert` with `leaf_kem_suite_id=100` and a real ML-KEM-768 1184-byte public key.
- `vN.kem.sk.bin`: matching 2400-byte ML-KEM-768 secret key, written `0600` on Unix.
- Root signing key remains memory-only.

Observed:

```text
-rw------- ... /tmp/run039-mat/v0.kem.sk.bin
wc -c: 2400 /tmp/run039-mat/v0.kem.sk.bin; 3696 /tmp/run039-mat/v0.cert.bin
[devnet_pqc_root_helper] ... sig_suite=100 kem_suite=100 kem=ml-kem-768 ...
```

## Binary/helper identity

- Branch: `copilot/continue-qbind-development-82cd2ac7-b3f2-4e42-a8fa-b67b1f910018`
- Commit used for evidence: `3328fa1473b01363c8a189ece02469bf9881626c` plus this evidence/contradiction doc update pending at capture time.
- `qbind-node` sha256: `a21738f06725767baedcc119fdf3e24d4a877d67288a0c23cd17f21d98672e49`
- `qbind-node` ELF BuildID: `e9c17f1e673a0d7b244e2f24339d00fe750a97b6`
- `devnet_pqc_root_helper` sha256: `a7591e8ebf5a300997541938d383dc17a21fae474640f5334086dad253eb4cac`
- `devnet_pqc_root_helper` ELF BuildID: `a4eea378b030d5a7e183df1e3ebcf79b262f222f`

## Commands run

```sh
cargo test -p qbind-crypto ml_kem768 --lib
cargo test -p qbind-node --lib pqc_root_config
cargo test -p qbind-node --lib pqc_devnet_helper
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo check -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper
./target/release/examples/devnet_pqc_root_helper /tmp/run039-mat 4
# two-node Required + pqc-static-root smoke with --p2p-peer-leaf-cert on both nodes
# negative smokes: mismatched leaf secret, malformed leaf secret, tampered cert
# N=4 Required + pqc-static-root + --require-timeout-verification timeout-based absent-leader smoke
```

## Test status

- PASS: `cargo test -p qbind-crypto ml_kem768 --lib` — 12/12.
- PASS: `cargo test -p qbind-node --lib pqc_root_config` — 14/14.
- PASS: `cargo test -p qbind-node --lib pqc_devnet_helper` — 5/5.
- PASS: `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` — 12/12.
- PASS: `cargo check -p qbind-node --bin qbind-node`.
- PASS: release builds for node and helper.

## Positive evidence

### Two-node smoke

Two nodes started with `--p2p-mutual-auth required`, `--p2p-pqc-root-mode pqc-static-root`, real ML-DSA-44 certs, real ML-KEM-768 leaf material, and explicit peer leaf certs. Both logs showed `transport_kem_suite_name=ml-kem-768 dummy_kem_registered=false`; both reported `P2P transport up`; both reported peer connected. No `FATAL`, no `handshake failed`, no DummyKem fallback.

### N=4 B14-shaped smoke

Topology: V0, V1, V2, V3; V0-first stagger; V1 process timed out earlier to simulate absent leader; V0/V2/V3 remained live. All four nodes used Required mutual auth, `pqc-static-root`, one trusted root, real ML-DSA-44 certs, real ML-KEM-768 KEM, `--require-timeout-verification`, signer keystores, and four `--validator-consensus-key` entries.

Evidence from V0:

```text
prefault: committed_height=79 current_view=82 timeout_verify_accepted=0 newview_verify_accepted=0
post:     committed_height=100 current_view=105 timeout_verify_accepted=4 newview_verify_accepted=3
rejected counters: timeout_verify_rejected=0 newview_verify_rejected=0 proposals_rejected=0 votes_invalid=0
```

V2 matched V0; V3 had `newview_verify_accepted=4` and the same `committed_height=100 current_view=105`. Logs showed timeout verification ACTIVE and outbound timeout signing OK.

## Negative evidence

- Mismatched leaf KEM secret: startup failed closed with `ML-KEM-768 secret key does not match certified public key`.
- Malformed leaf KEM secret file: startup failed closed with `malformed ML-KEM-768 secret key: expected 2400 bytes, got 3`.
- Tampered cert: build failed closed with `delegation cert verification failed: KeySchedule("signature verify error")`.
- No DummyKem fallback observed in `pqc-static-root`; logs show `dummy_kem_registered=false`.
- No DummySig fallback observed on active path. The string `DummySig` still appears in an unrelated timeout-verification diagnostic prose when signer material is intentionally omitted in small negative smokes; active runtime mode remains `pqc-static-root`.

## Metrics / observability

`qbind_p2p_pqc_*` live HTTP metrics remain not exposed through `/metrics` in this run; grep of captured `/metrics` returned no `qbind_p2p_pqc` lines. Run 039 relies on startup logs for active KEM proof and keeps the Run 038 observability follow-up open.

## Non-claims / remaining open items

- `DummyAead` still remains on the binary path.
- Production AEAD is not solved by Run 039.
- Production CA, cert rotation, revocation, and signed root distribution are not solved.
- Full C4 remains open.
- C5 remains open if policy treats production AEAD as part of the remaining transport dependency.
- The N=4 run was timeout-based process absence rather than a graceful SIGINT absent-leader script, but it preserved the Run 038 Required + pqc-static-root + verified-timeout shape and demonstrated post-fault progress.

## Verdict

Strongest positive for Run 039 transport KEM scope: ML-KEM-768 replaces DummyKem in `pqc-static-root` Required mode; two-node and N=4 real-binary evidence pass; negative KEM/cert smokes fail closed; no DummyKem/DummySig fallback on the active path; tests pass. Full C4 remains open for AEAD and lifecycle items.