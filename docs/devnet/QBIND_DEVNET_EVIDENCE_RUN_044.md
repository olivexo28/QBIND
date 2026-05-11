# QBIND DevNet Evidence — Run 044

**Run:** 044
**Date:** 2026-05-11
**Branch:** `copilot/continue-qbind-development-50412889-86c3-4f75-b33e-20d0a95a07ed`
**Pre-doc commit:** `02f4e4c667f16f5c0549fce729ae428eea01875b`
**Working tree:** clean (pre-doc)
**Release `qbind-node` sha256:** `fe805315c2be8aebd1133b3a2082dff1eeab3000a18abdcb7cbc265897377e4a`
**Release `qbind-node` ELF BuildID:** `15bac93f1def29b90e2ea713dcc6b5ca09692900`
**Release `devnet_pqc_root_helper` sha256:** `c42c9b875452c712539b4fcece674f962ff998cca1655b9e5fe34f4323f94e1b`
**Release `devnet_pqc_root_helper` ELF BuildID:** `a8d47c8ee5f4f61af8df0837930f4df55a5678da`

---

## §1. Exact objective

Wire **live** PQC transport delegation-cert verification metric increments
into the actual cert-verification success/failure paths in `qbind-net`,
**without** changing cert-verification semantics, so that the
`qbind_p2p_pqc_cert_verify_*` counters already made scrape-visible by
Run 043 truthfully move when the live binary verifies or rejects PQC
transport delegation certs. This is the Run 043 §15 follow-up.

## §2. Strict scope

- Smallest code change.
- No changes to KEMTLS handshake semantics, KEM / AEAD / signature
  crypto, consensus, timeout verification, forged-traffic rejection,
  root/cert lifecycle, or any error return type.
- Preserve the Run 043 formatter and `Arc<P2pMetrics>` instance-sharing
  behaviour bit-for-bit.
- Preserve Run 037 / Run 039 / Run 040 transport-crypto behaviour.
- Preserve Run 034 / Run 036 active-timeout-verification behaviour.
- `qbind-net` MUST NOT depend on `qbind-node`.

## §3. Investigation — exact cert-verification live boundaries

The live binary path for PQC static-root delegation cert verification is
exclusively inside `qbind-net::handshake`:

| Role | Caller | Function | File |
|------|--------|----------|------|
| Listener (server) | `ServerHandshake::handle_client_init` | `parse_and_verify_client_cert` | `crates/qbind-net/src/handshake.rs` |
| Dialer (client)  | `ClientHandshake::handle_server_accept` | cert verification region (parse → `verify_delegation_cert` → validator-id check) | `crates/qbind-net/src/handshake.rs` |
| Startup self-check | `P2pNodeBuilder::build` → `verify_delegation_cert(&local_cert, …)` (delegated to `qbind_net::handshake::verify_delegation_cert`) | `verify_delegation_cert` | `crates/qbind-net/src/handshake.rs` |

`P2pNodeBuilder::build` consumes the resulting `Result<…, NetError>`
and surfaces it as `P2pNodeError::Config(...)`; this is the documented
"missing leaf cert / tampered leaf cert fails closed under Required +
pqc-static-root" boundary (see Run 037 evidence).

## §4. Reason-mapping table (cert-verification error → metric counter)

| Failure boundary | `NetError` shape | Metric counter |
|------------------|------------------|----------------|
| `NetworkDelegationCert::decode` fails (listener) | `NetError::ClientCertInvalid("parse error")` | `qbind_p2p_pqc_cert_rejected_malformed_total` |
| `NetworkDelegationCert::decode` fails (dialer)   | `NetError::KeySchedule("failed to parse delegation cert")` | `qbind_p2p_pqc_cert_rejected_malformed_total` |
| `TrustedClientRoots::lookup` returns `None` (listener) | `NetError::ClientCertInvalid("untrusted root")` | `qbind_p2p_pqc_cert_rejected_unknown_root_total` |
| `verify_delegation_cert` → `UnsupportedSuite(_)` | `NetError::UnsupportedSuite(suite)` | `qbind_p2p_pqc_cert_rejected_wrong_suite_total` |
| `verify_delegation_cert` → `KeySchedule("signature verify error")` | `NetError::KeySchedule("signature verify error")` | `qbind_p2p_pqc_cert_rejected_bad_signature_total` |
| dialer `delegation_cert.validator_id != client_init.validator_id` | `NetError::KeySchedule("validator_id mismatch in cert")` | `qbind_p2p_pqc_cert_rejected_validator_mismatch_total` |
| Listener accepts cert (after parse + root lookup + signature verify) | `Ok(NetworkDelegationCert)` from `parse_and_verify_client_cert` | `qbind_p2p_pqc_cert_verify_accepted_total` (single bump per cert verify event) |
| Dialer accepts cert (after parse + signature verify + validator-id match) | success path inside `handle_server_accept` before key schedule | `qbind_p2p_pqc_cert_verify_accepted_total` (single bump per cert verify event) |
| **Validity-window expiry** | NOT IMPLEMENTED in `verify_delegation_cert` today | `qbind_p2p_pqc_cert_rejected_expired_total` stays at 0 — documented unused boundary |

The per-reason setters on `P2pMetrics` each bump the aggregate
`qbind_p2p_pqc_cert_verify_rejected_total` exactly once (Run 037
contract, preserved). The accepted counter is bumped on a different
code path and never participates in the aggregate.

## §5. Accepted-counter boundary

`qbind_p2p_pqc_cert_verify_accepted_total` is bumped exactly once per
cert verification event, at the precise point AFTER all required
checks have passed at that boundary:

- **Listener:** inside `parse_and_verify_client_cert`, immediately
  before returning `Ok(cert)`. By design this is BEFORE downstream
  KEM decapsulation / key schedule. (Cert verification is a distinct
  earlier boundary; downstream failures do not retroactively
  un-accept the cert.)
- **Dialer:** inside `handle_server_accept`, immediately AFTER the
  validator-id check passes, BEFORE key schedule.

The counter is NOT bumped:
- merely because config parsed,
- merely because a root is configured,
- when a later cert check (validator-id mismatch, parse fail) fires,
- when a sink is not installed (test-grade DummySig path, builder-only
  unit tests, or `Disabled` mutual-auth mode).

## §6. Rejected-counter boundary

Each per-reason counter is bumped exactly once on its specific failure
branch, immediately BEFORE the unchanged `NetError` variant is
returned. The increment is followed by an immediate `return Err(...)`
with the bit-identical `NetError` variant from pre-Run-044, so no error
is swallowed and no error is reclassified.

## §7. Implementation explanation

**Crate-layering-clean sink seam.** `P2pMetrics` lives in `qbind-node`;
`qbind-net` must not depend on `qbind-node`. The smallest safe shape
is a trait `qbind_net::CertVerifyMetricsSink` defined in `qbind-net`
with default no-op methods, threaded through the existing
`ClientHandshakeConfig` / `ServerHandshakeConfig` as
`Option<Arc<dyn CertVerifyMetricsSink>>`. `qbind-node` implements
the trait for `P2pMetrics`. The adapter forwards each per-reason
method onto the matching existing `P2pMetrics::inc_pqc_cert_verify_*`
setter, which preserves the Run 037 aggregate-counter contract.

**Optional sink, zero-cost no-op default.** When the sink is `None`
(default for every existing test-grade caller, the entire `qbind-net`
test suite, and the `Disabled` / `Optional` mutual-auth-no-PQC path),
the handshake code performs an `if let Some(s) = sink` check that
collapses to a single non-taken branch; verification behaviour is
bit-identical to pre-Run-044.

**Production-honest plumbing.** Inside
`P2pNodeBuilder::create_connection_configs`, the sink is installed
**only** when (a) `mutual_auth_mode` is `Required` or `Optional` AND
(b) `pqc_root_config.mode == PqcStaticRoot` AND (c) the builder has
been given a shared `Arc<P2pMetrics>` via the Run-043
`with_p2p_metrics(...)` setter. This preserves the documented Run 044
contract "test-grade DummySig path does NOT touch production PQC cert
metrics" — the test-grade `MutualAuthMode::Required` + `Disabled`
PQC mode + DummySig provider used by `cargo test -p qbind-node --lib`
leaves the sink `None` and so cannot move the production
`qbind_p2p_pqc_cert_verify_*` counters.

## §8. Proof no duplicate increments

- Each per-reason failure boundary is a distinct early-return arm
  with exactly one `s.inc_rejected_*()` call followed by exactly one
  `return Err(...)`. No fall-through. The control-flow assertion is
  unit-test-enforced in `crates/qbind-net/tests/run_044_cert_verify_metrics_tests.rs`
  (each negative test asserts the per-reason counter == 1 AND every
  other counter == 0 after a single handshake attempt).
- The accepted boundary is a single `s.inc_accepted()` call placed
  AFTER every prior return-Err arm and BEFORE the function returns
  `Ok(cert)` / continues to key schedule. Unit-test-enforced by
  `listener_accepted_increments_accepted_once` and
  `dialer_accepted_increments_accepted_once`.
- The aggregate `pqc_cert_verify_rejected_total` is bumped by the
  per-reason setter on `P2pMetrics` (pre-Run-044 Run 037 contract);
  it is NOT bumped by `qbind-net` directly, so a single per-reason
  call produces exactly one aggregate bump. Adapter-level
  unit-test-enforced by every `adapter_inc_rejected_*` test.
- Listener and dialer are physically distinct code paths in
  `qbind-net::handshake` and each owns its own sink invocation; the
  two-node positive smoke (§13) records `accepted_total = 2` on each
  node, exactly matching `1 listener-side accept + 1 dialer-side
  accept` per node, which is the expected wire-protocol cardinality
  (every node both accepts an incoming connection and dials the
  peer).

## §9. Files changed

| File | Change |
|------|--------|
| `crates/qbind-net/src/cert_verify_metrics.rs` (new) | Defines `pub trait CertVerifyMetricsSink` with default no-op methods + 2 unit tests. |
| `crates/qbind-net/src/lib.rs` | `pub mod cert_verify_metrics;` + `pub use cert_verify_metrics::{CertVerifyMetricsSink, CertVerifyMetricsSinkRef};` |
| `crates/qbind-net/src/handshake.rs` | Add `pub cert_verify_metrics: Option<Arc<dyn CertVerifyMetricsSink>>` to `ClientHandshakeConfig` and `ServerHandshakeConfig`; wire increments at the listener `parse_and_verify_client_cert` and dialer `handle_server_accept` success/failure boundaries. Every existing `NetError` return path unchanged. |
| `crates/qbind-node/src/metrics.rs` | Add `impl qbind_net::CertVerifyMetricsSink for P2pMetrics` adapter forwarding each method onto the existing `inc_pqc_cert_verify_*` setters. |
| `crates/qbind-node/src/p2p_node_builder.rs` | In `create_connection_configs`, install the sink only on the production-honest `MutualAuthMode::{Required,Optional}` + `PqcRootMode::PqcStaticRoot` + shared `Arc<P2pMetrics>` path. |
| `crates/qbind-net/tests/run_044_cert_verify_metrics_tests.rs` (new) | 13 focused reason-mapping unit tests (every reason, both roles, no-sink preservation, expired-counter documented-unused contract). |
| `crates/qbind-node/tests/run_044_pqc_cert_verify_metrics_adapter_tests.rs` (new) | 10 adapter integration tests proving the `P2pMetrics ⇄ CertVerifyMetricsSink` mapping and the Run 037 aggregate-counter contract preservation. |
| ~60 callers of `ClientHandshakeConfig {}` / `ServerHandshakeConfig {}` across `qbind-net` and `qbind-node` tests | Added literal `cert_verify_metrics: None,` initializer (mechanical, no semantic change). |

## §10. Exact commands run

```bash
# Build
cargo build -p qbind-net
cargo build -p qbind-node
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example devnet_pqc_root_helper

# Unit / integration regression
cargo test -p qbind-net                                      # all targets
cargo test -p qbind-net --test run_044_cert_verify_metrics_tests
cargo test -p qbind-crypto --lib
cargo test -p qbind-node --lib
cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests
cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests
cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests
cargo test -p qbind-node --test kemtls_pqc_metrics_tests \
                        --test metrics_http_tests \
                        --test kem_metrics_node_integration_tests

# Live two-node pqc-static-root positive smoke (§13)
target/release/examples/devnet_pqc_root_helper /tmp/run044/mat 2
SPEC=$(cat /tmp/run044/mat/trusted-root.spec)
QBIND_METRICS_HTTP_ADDR=127.0.0.1:43150 target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19550 --p2p-peer 1@127.0.0.1:19551 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$SPEC" \
  --p2p-leaf-cert /tmp/run044/mat/v0.cert.bin \
  --p2p-leaf-cert-key /tmp/run044/mat/v0.kem.sk.bin \
  --p2p-peer-leaf-cert "1:/tmp/run044/mat/v1.cert.bin" \
  --validator-id 0 --data-dir /tmp/run044/v0-pqc &
QBIND_METRICS_HTTP_ADDR=127.0.0.1:43151 target/release/qbind-node \
  --env devnet --network-mode p2p --enable-p2p \
  --p2p-listen-addr 127.0.0.1:19551 --p2p-peer 0@127.0.0.1:19550 \
  --p2p-mutual-auth required --p2p-pqc-root-mode pqc-static-root \
  --p2p-trusted-root "$SPEC" \
  --p2p-leaf-cert /tmp/run044/mat/v1.cert.bin \
  --p2p-leaf-cert-key /tmp/run044/mat/v1.kem.sk.bin \
  --p2p-peer-leaf-cert "0:/tmp/run044/mat/v0.cert.bin" \
  --validator-id 1 --data-dir /tmp/run044/v1-pqc &
sleep 12
curl -s http://127.0.0.1:43150/metrics | grep '^qbind_p2p_pqc_'
curl -s http://127.0.0.1:43151/metrics | grep '^qbind_p2p_pqc_'

# Live two-node pqc-static-root negative tampered-cert smoke (§14)
cp /tmp/run044/mat/v1.cert.bin /tmp/run044/mat/v1.cert.tampered.bin
python3 -c "with open('/tmp/run044/mat/v1.cert.tampered.bin','r+b') as f: f.seek(-8,2); d=f.read(8); f.seek(-8,2); f.write(bytes(b^0xFF for b in d))"
# launch v0 with honest cert, v1 with tampered cert → v1 must fail closed
```

## §11. Test results

| Command | Result | Notes |
|---------|--------|-------|
| `cargo build -p qbind-net` | **OK** | clean |
| `cargo build -p qbind-node` | **OK** | clean (2 pre-existing `bincode::config` deprecation warnings only — unrelated to Run 044) |
| `cargo build --release -p qbind-node --bin qbind-node` | **OK** | sha256 `fe805315c2be8aebd1133b3a2082dff1eeab3000a18abdcb7cbc265897377e4a` |
| `cargo build --release -p qbind-node --example devnet_pqc_root_helper` | **OK** | sha256 `c42c9b875452c712539b4fcece674f962ff998cca1655b9e5fe34f4323f94e1b` |
| `cargo test -p qbind-net` (all targets, incl. `run_044_cert_verify_metrics_tests`) | **OK** | every target green; `run_044_cert_verify_metrics_tests` 13/13; `cert_verify_metrics::tests` 2/2 (default-no-op, counting-sink); m6/m8/handshake/wire/aead/etc. all pre-existing tests pass |
| `cargo test -p qbind-net --lib` | **OK 17/17** | 15 pre-Run-044 + 2 new `cert_verify_metrics::tests::*` |
| `cargo test -p qbind-crypto --lib` | **OK 68/68** | no regression |
| `cargo test -p qbind-node --lib` | **OK 775/775** | identical count to Run 043 (no library-test count delta — adapter tests live in `tests/`) |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **OK 12/12** | incl. R037.B tampered-cert, R037.C untrusted-root, R037.D wrong-sig-suite |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **OK 14/14** | real-AEAD path preserved |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | **OK 10/10** | adapter mapping + aggregate-counter contract preserved + family-still-in-`format_metrics` |
| `cargo test -p qbind-node --test kemtls_pqc_metrics_tests --test metrics_http_tests --test kem_metrics_node_integration_tests` | **OK 4+19+15 = 38/38** | Run 043 metrics-exposure regression suite unchanged |

## §12. Investigation findings (exact file/function references)

- **`crates/qbind-net/src/handshake.rs::ClientHandshakeConfig`** —
  added `pub cert_verify_metrics: Option<Arc<dyn CertVerifyMetricsSink>>`.
- **`crates/qbind-net/src/handshake.rs::ServerHandshakeConfig`** —
  added `pub cert_verify_metrics: Option<Arc<dyn CertVerifyMetricsSink>>`.
- **`crates/qbind-net/src/handshake.rs::ClientHandshake::handle_server_accept`**
  — sink is captured as `self.cfg.cert_verify_metrics.as_ref()` once,
  then invoked at each pre-existing return branch:
  parse-fail → `inc_rejected_malformed`,
  `verify_delegation_cert::Err(UnsupportedSuite)` → `inc_rejected_wrong_suite`,
  `verify_delegation_cert::Err(KeySchedule(_))` → `inc_rejected_bad_signature`,
  validator-id mismatch → `inc_rejected_validator_mismatch`,
  all checks pass → `inc_accepted`.
- **`crates/qbind-net/src/handshake.rs::ServerHandshake::parse_and_verify_client_cert`**
  — same shape on the listener side:
  parse-fail → `inc_rejected_malformed`,
  `TrustedClientRoots::lookup → None` → `inc_rejected_unknown_root`,
  `verify_delegation_cert::Err(UnsupportedSuite)` → `inc_rejected_wrong_suite`,
  `verify_delegation_cert::Err(KeySchedule(_))` → `inc_rejected_bad_signature`,
  all checks pass → `inc_accepted`.
- **`crates/qbind-node/src/metrics.rs`** — adapter
  `impl qbind_net::CertVerifyMetricsSink for P2pMetrics` placed
  immediately after the existing `pqc_cert_rejected_*_total` accessor
  group; each method forwards to the existing
  `P2pMetrics::inc_pqc_cert_verify_*` setter.
- **`crates/qbind-node/src/p2p_node_builder.rs::create_connection_configs`**
  — sink built as `Some(Arc<dyn CertVerifyMetricsSink>)` only on the
  `(Required|Optional, PqcStaticRoot, Some(p2p_metrics))` path.

## §13. Real-binary positive two-node smoke

**Topology:** V0 / V1 on `127.0.0.1:19550` / `127.0.0.1:19551`, metrics on
`127.0.0.1:43150` / `127.0.0.1:43151`, `--env devnet --network-mode p2p
--enable-p2p --p2p-mutual-auth required --p2p-pqc-root-mode
pqc-static-root --p2p-trusted-root <SHARED_SPEC>`, per-validator real
ML-DSA-44-signed `v{0,1}.cert.bin`, real ML-KEM-768 `v{0,1}.kem.sk.bin`,
one `--p2p-peer-leaf-cert` each.

**Materials:** DevNet-ephemeral root
`3779a0e00c71b4225d25dea2cd61fd3c1b4e2cc8919dbf2e83ce396319209eb4`,
sig suite 100, KEM suite 100, root fingerprint `fp=773d0e9f` (helper
root signing key never written to disk).

**Startup banners** (both nodes, verified by `grep` in
`/tmp/run044/logs/{v0,v1}.log`):
```
[binary] Run 039: pqc_root_mode=pqc-static-root transport_kem_suite=ml-kem-768 \
  configured_roots=1 leaf_credentials_present=true peer_leaf_certs=1 \
  (root fingerprints: [id=3779a0e0.. suite=100 fp=773d0e9f])
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100 \
  transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768 \
  dummy_kem_registered=false transport_aead_suite_id=101 \
  transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false \
  configured_roots=1 leaf_credentials_present=true
```
→ real ML-DSA-44 + real ML-KEM-768 + real ChaCha20-Poly1305 active on
both nodes; no DummySig / DummyKem / DummyAead fallback.

**Live `/metrics` excerpts** (`/tmp/run044/logs/{v0,v1}.metrics.txt`):
```
# V0:
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 2
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0

# V1:
qbind_p2p_pqc_root_mode 1
qbind_p2p_pqc_roots_configured 1
qbind_p2p_pqc_cert_verify_accepted_total 2
qbind_p2p_pqc_cert_verify_rejected_total 0
qbind_p2p_pqc_cert_rejected_unknown_root_total 0
qbind_p2p_pqc_cert_rejected_wrong_suite_total 0
qbind_p2p_pqc_cert_rejected_bad_signature_total 0
qbind_p2p_pqc_cert_rejected_validator_mismatch_total 0
qbind_p2p_pqc_cert_rejected_malformed_total 0
qbind_p2p_pqc_cert_rejected_expired_total 0
```

**`accepted_total = 2` per node** is the expected wire-protocol
cardinality: each node performs exactly one listener-side
`parse_and_verify_client_cert` accept on the peer's inbound dial AND
one dialer-side `handle_server_accept` accept on its own outbound dial
to the peer, then dedup logic later collapses the duplicate connection
at the peer-store layer. All per-reason rejection counters remain at
0, exactly as required for an honest two-node positive smoke.

Family emitted exactly once on the live `/metrics` endpoint
(`grep -c "^qbind_p2p_pqc_root_mode" /tmp/run044/logs/v0.metrics.txt` → 1).
Pre-existing `qbind_timeout_verification_*`, `qbind_net_kem_*`, and
`consensus_net_*` surfaces all preserved on the scrape (no regression
to Run 043's exposed surface; same `format_metrics` composition).

## §14. Real-binary negative tampered-cert smoke

**Tamper recipe:** flip the trailing 8 bytes of v1's leaf-cert
signature with `bytes[-8..] ^= 0xFF`.

**Topology:** v0 honest, v1 launched with `--p2p-leaf-cert
/tmp/run044/mat/v1.cert.tampered.bin`.

**Observed result** (from `/tmp/run044/logs/v1-neg.log`):
```
[Run040] P2pNodeBuilder: pqc_root_mode=pqc-static-root sig_suite_id=100
  transport_kem_suite_id=100 transport_kem_suite_name=ml-kem-768
  dummy_kem_registered=false transport_aead_suite_id=101
  transport_aead_suite_name=chacha20-poly1305 dummy_aead_registered=false
  configured_roots=1 leaf_credentials_present=true
[binary] ERROR: Failed to build P2P node: Config(
  "delegation cert verification failed: KeySchedule(\"signature verify error\")")
```

→ v1 fails closed at the **startup self-verification** boundary inside
`P2pNodeBuilder::build` (the deterministic verification of the local
leaf cert against the configured root pk via `verify_delegation_cert`
in `qbind_net::handshake`). This boundary is **before** the
`P2pNodeBuilder::build` method completes, and so before the live
listener/dialer paths in `qbind-net` are ever invoked, **and** before
the v1-side sink is plumbed into `ServerHandshakeConfig` /
`ClientHandshakeConfig`. Therefore v1's `inc_rejected_bad_signature`
is NOT reached on the live binary path — exactly as Run 044 §6
boundary contract requires (no fake increments, no double-counting).

**Honest boundary record:** the tampered-cert "live counter movement"
case occurs on the *peer* side of the wire — only if the tampered cert
is successfully transmitted from a launched (process-alive) peer to a
verifying node. To produce that case in a single-binary smoke would
require either (a) bypassing the startup self-verification check
(would change verification semantics — out of scope for Run 044) or
(b) building a custom forged-traffic injector (test-grade only, would
not preserve the production-honest sink installation invariant in
`p2p_node_builder.rs`).

**Tampered-cert per-reason counter movement is instead proven by
unit-test layer**:

- `crates/qbind-net/tests/run_044_cert_verify_metrics_tests.rs::listener_bad_signature_increments_bad_signature_once`
  — drives the real `parse_and_verify_client_cert` boundary inside
  `ServerHandshake::handle_client_init` with a provider whose
  signature suite returns `Err`, asserts the `NetError::KeySchedule(
  "signature verify error")` return AND
  `bad_signature_counter == 1` AND every other counter == 0.
- `crates/qbind-net/tests/run_044_cert_verify_metrics_tests.rs::dialer_bad_signature_increments_bad_signature_once`
  — same shape on the dialer side via `handle_server_accept`.
- Plus matching `unknown_root`, `wrong_suite`, `malformed`,
  `validator_mismatch` per-reason tests covering every cell of the §4
  reason-mapping table.
- Plus `crates/qbind-node/tests/run_044_pqc_cert_verify_metrics_adapter_tests.rs`
  proving the adapter wiring forwards each `inc_*` onto the live
  `P2pMetrics` counters, including the Run 037 aggregate contract.

**v1 stayed dead** (intended; no fallback to DummySig / DummyKem /
DummyAead — fail closed preserved exactly as Run 037 / Run 038 /
Run 039 / Run 040 / Run 042 boundary record states).

## §15. Optional N=4 smoke

Not run in this pass — the CI sandbox does not provide reliable
network-namespace isolation for N=4 multi-process orchestration. The
two-node positive smoke (§13) plus the focused reason-mapping unit
tests + the adapter integration tests are the authoritative live
proofs for Run 044's observability-only scope. The Run 042 N=4
multi-process B14 absent-leader recovery evidence remains the
authoritative N=4 multi-process B14 proof on the byte-identified
Run 040 release binary, and Run 044's only delta from that binary on
the cert-verification path is the optional metric-sink installation
in `create_connection_configs` (which is `None` for any non-PQC or
non-`Required`/`Optional` caller, preserving Run 042 behaviour for
that path bit-for-bit) and the sink-callback invocations in
`qbind-net::handshake` (each guarded by `if let Some(s) = sink` so the
no-sink path is bit-identical to pre-Run-044).

## §16. What is solved

- **Live PQC cert-verify accepted counter is wired**:
  `qbind_p2p_pqc_cert_verify_accepted_total` truthfully moves on the
  live release binary under `pqc-static-root` (§13: accepted_total =
  2 per node on two-node honest run).
- **Live PQC cert-verify per-reason rejection counters are wired**:
  each branch (`unknown_root`, `wrong_suite`, `bad_signature`,
  `validator_mismatch`, `malformed`) is exercised at the real
  `qbind-net::handshake` boundary inside the existing public API
  (`ServerHandshake::handle_client_init` and
  `ClientHandshake::handle_server_accept`), with per-reason +
  aggregate counter movement asserted exactly once per event.
- **Aggregate `qbind_p2p_pqc_cert_verify_rejected_total`** moves in
  lockstep with the per-reason counters (Run 037 contract preserved
  end-to-end through the adapter layer).
- **Crate layering preserved**: `qbind-net` does NOT depend on
  `qbind-node`; the seam is a trait inside `qbind-net` with default
  no-op methods.
- **Verification behaviour preserved**: every existing fail-closed
  case (tampered cert, unknown root, wrong suite, malformed cert,
  validator mismatch, missing leaf cert under Required +
  pqc-static-root, mismatched ML-KEM secret) still returns the
  bit-identical `NetError` variant. No fallback to DummySig /
  DummyKem / DummyAead.

## §17. What remains not solved

- **Cert validity-window enforcement** is not yet implemented in
  `qbind_net::handshake::verify_delegation_cert`; therefore the
  `qbind_p2p_pqc_cert_rejected_expired_total` counter remains
  visible at zero on the live path (intentional, documented boundary
  — see §4 last row and `expired_counter_documented_unused_at_live_boundary`
  unit test).
- **Per-environment trust anchors / signed root distribution / cert
  rotation / cert revocation / production CA lifecycle** remains a
  C4 piece and is operator-out-of-band today. Run 044 does NOT
  address lifecycle.
- **N=4 multi-process B14 recovery smoke under the Run 044 binary**
  not re-run in this pass (Run 042 N=4 evidence is authoritative for
  the byte-identical Run 040 binary, and Run 044's behavioural delta
  on the consensus / KEM / AEAD / timeout-verification surfaces is
  zero — only optional metric callbacks were added).
- **Exponential-backoff timeout pacing**, **production fast-sync /
  consensus-storage restore** remain OPEN C4 pieces (unchanged from
  Run 043).

## §18. contradiction.md update

Updated. C4 narrowed (Run 043's declared-but-not-incremented
cert-verify counter call-site gap is now CLOSED on the live path);
full C4 still OPEN for CA / cert rotation / cert revocation / signed
root distribution lifecycle, production fast-sync, exponential-backoff
timeout pacing, per-environment trust anchors, and cert
validity-window enforcement. C5 still NOT closed.

## §19. Verdict

**Strongest positive.** Accepted and per-reason rejected
cert-verification counters are wired to the live verification
success/failure paths in `qbind-net::handshake`. Positive two-node
smoke shows `accepted_total > 0` and all rejections 0 under honest
traffic. Per-reason rejection increments are proven by focused unit
tests exercising the real handshake boundary for every reason cell
in the §4 mapping table. Metrics are emitted exactly once. All
required regression tests pass. No protocol behaviour changes. No
duplicate increments. No fabricated counters. No silent fallback.

## §20. Immediate next action

Wire `verify_delegation_cert` validity-window enforcement against
`not_before` / `not_after`, then plumb the existing-but-currently-
unused `inc_rejected_expired` boundary in this same code seam; this
would close the last documented-unused per-reason metric. Beyond
that, the next C4 piece to take after Run 044 is producing a
production-honest signed-root distribution / cert rotation /
revocation lifecycle (operator-tooling, out of `qbind-net` scope).