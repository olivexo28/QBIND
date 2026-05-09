# QBIND DevNet Evidence — Run 030

> **Wire timeout / new-view cryptographic verification into the binary
> consensus path end-to-end (Run 030).**

---

## 1. Exact objective

Run 030 closes the binary-path verification wiring sub-item of C5 and
materially narrows C4's "signature verification of `TimeoutMsg` /
`TimeoutCertificate`" sub-item:

1. Thread a fully-typed `TimeoutVerificationContext`
   (`{ validators, key_provider, backend_registry, chain_id, signer }`) into
   `crates/qbind-node/src/binary_consensus_loop.rs` via
   `BinaryConsensusLoopIo::verification_ctx`.
2. In the inbound `Timeout` arm, call
   `qbind_consensus::timeout_verify::verify_timeout_msg(...)`
   **before** `engine.on_timeout_msg(...)` and reject fail-closed on
   unsigned / malformed / wrong-suite / unsupported-suite /
   unknown-validator / missing-key / bad-signature / duplicate inputs.
3. In the inbound `NewView` arm, call
   `qbind_consensus::timeout_verify::verify_timeout_certificate_with_evidence(&tc, &tc.signed_timeouts, ...)`
   **before** `engine.on_timeout_certificate(...)` and reject fail-closed
   on missing-evidence / evidence-mismatch / duplicate-signer / mixed-view /
   insufficient-quorum / unknown-validator / missing-key / wrong-suite /
   unsupported-suite / bad-signature / high-QC-mismatch inputs.
4. In the outbound timeout-emission path
   (`maybe_emit_view_timeout`), sign locally-emitted `TimeoutMsg`s via
   `signer.sign_timeout_with_chain_id(...)` over
   `timeout_signing_bytes_with_chain_id(...)` **before** local engine
   ingestion, network broadcast, and inclusion in any locally-formed
   `TimeoutCertificate.signed_timeouts`. Fail-closed when signing is
   required but unavailable.
5. Surface every per-reason rejection, every signing outcome, every
   verified TC view-advance, and a `(latency_ns_total, observations_total)`
   pair on `/metrics`.
6. Add deterministic loop-API tests covering the full positive surface
   and every documented negative class.

The strict scope rules from the problem statement are honoured: no
HotStuff / B14 / networking / snapshot redesign, no classical-crypto
assumptions, no parallel crypto path, no silent acceptance, full C4 not
marked closed, and broader C4 items (production fast-sync, exponential
backoff, production PQC KEMTLS root-key distribution, large-state
snapshot stability) remain open.

---

## 2. Binary identity

| Field | Value |
|-------|-------|
| Repository | `olivexo28/QBIND` |
| Branch | `copilot/continue-qbind-development-one-more-time` |
| Commit (Run 030 source state, pre-evidence-doc) | `4b3f8de1eaab31791c5c15d413da6980a83e3e5e` |
| Working tree | clean against the commit above except for this evidence document and the `contradiction.md` C5 update committed alongside it (verified via `git status --porcelain`). |
| Toolchain | rustc / cargo as pinned by the workspace (`rust-toolchain.toml`). No new dependencies were introduced. |
| Sandbox | The Run 030 verdict in this document is **deterministic only**. A real-binary `qbind-node` was not booted in this sandbox because the production `--p2p-mutual-auth required` activation depends on the C4 production-PQC-KEMTLS-root-key-distribution sub-item, which is explicitly still open. The deterministic in-loop tests exercise the same `handle_inbound_consensus_msg` and `maybe_emit_view_timeout` functions that the live tokio loop dispatches into. |
| Binary sha256 / ELF BuildID | **N/A** — see "Sandbox" row above; no production-mode `qbind-node` build was produced for this run. The binary still builds (`cargo check -p qbind-node --bin qbind-node` is clean — see §4). |

---

## 3. Exact files changed

```
crates/qbind-node/src/binary_consensus_loop.rs                        (+1452 / -7)
crates/qbind-node/src/main.rs                                         (+1   / -0)
crates/qbind-node/src/metrics.rs                                      (+349 / -0)
crates/qbind-node/tests/b9_late_peer_connect_proposal_reemit_tests.rs (+4   / -0)
crates/qbind-node/tests/b10_engine_acceptance_qc_closure_tests.rs     (+7   / -0)
crates/qbind-node/tests/b11_consensus_net_prometheus_coverage_tests.rs(+2   / -0)
crates/qbind-node/tests/c4_b6_p2p_binary_path_interconnect_tests.rs   (+5   / -0)
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_030.md                          (new — this file)
docs/whitepaper/contradiction.md                                      (C5 narrowed by Run 030)
```

Salient additions in `binary_consensus_loop.rs`:

* `TimeoutVerificationContext { validators: Arc<ConsensusValidatorSet>,
  key_provider: Arc<dyn SuiteAwareValidatorKeyProvider>,
  backend_registry: Arc<dyn ConsensusSigBackendRegistry>,
  chain_id: ChainId, signer: Option<Arc<dyn ValidatorSigner>> }`.
* `BinaryConsensusLoopIo::verification_ctx: Option<Arc<TimeoutVerificationContext>>`.
* `handle_inbound_consensus_msg(..., verification_ctx: Option<&TimeoutVerificationContext>)`
  — inbound `Timeout` arm calls `verify_timeout_msg(...)`, inbound
  `NewView` arm calls
  `verify_timeout_certificate_with_evidence(&tc, &tc.signed_timeouts, ...)`,
  both before any `engine.on_*` ingestion.
* `maybe_emit_view_timeout(..., verification_ctx: Option<&TimeoutVerificationContext>)`
  — locally-emitted timeouts are signed via
  `signer.sign_timeout_with_chain_id(...)`; failure to sign when signing
  is required is fail-closed (no broadcast, no local ingestion).
* New per-reason counters on `BinaryConsensusLoopInboundStats` and
  the matching `/metrics` family in `metrics.rs`
  (`qbind_consensus_inbound_timeout_*`, `qbind_consensus_inbound_newview_*`,
  `qbind_consensus_outbound_timeout_signing_*`,
  `qbind_consensus_view_advances_due_to_verified_tc_total`,
  `qbind_consensus_timeout_crypto_verify_latency_ns_total` /
  `..._observations_total`).

The test-file additions (`b9_*`, `b10_*`, `b11_*`, `c4_b6_*`) are
purely struct-literal updates (`verification_ctx: None,`) so the
existing tests still compile against the extended `BinaryConsensusLoopIo`
shape. They preserve every existing assertion bit-for-bit.

The single line added to `main.rs` propagates `verification_ctx: None`
into the existing `BinaryConsensusLoopIo` literal in
`run_p2p_node` / `run_local_mesh_node`. This intentionally leaves the
production binary running in legacy bit-equivalent mode, which preserves
all of B1–B14 and explicitly does **not** silently activate verification
without the production-PQC-KEMTLS-root-key-distribution sub-item being
closed. See "Remaining open items" below.

---

## 4. Exact commands run

All commands were run in the cloned repository at
`/home/runner/work/QBIND/QBIND` from the branch noted in §2.

```sh
# Type-check the lib + binary.
cargo check -p qbind-node --lib
cargo check -p qbind-node --bin qbind-node
cargo check -p qbind-node --tests

# Run all qbind-consensus library tests (timeout, timeout_verify, qc, etc.).
cargo test -p qbind-consensus --lib

# Run all qbind-node library tests (covers the new run030 module).
cargo test -p qbind-node --lib
cargo test -p qbind-node --lib binary_consensus_loop
cargo test -p qbind-node --lib binary_consensus_loop::tests::run030

# Run the still-passing B-series + T146 integration test binaries.
cargo test -p qbind-node --test b3_snapshot_restore_tests
cargo test -p qbind-node --test b5_restore_aware_consensus_start_tests
cargo test -p qbind-node --test b9_late_peer_connect_proposal_reemit_tests
cargo test -p qbind-node --test b10_engine_acceptance_qc_closure_tests
cargo test -p qbind-node --test b11_consensus_net_prometheus_coverage_tests
cargo test -p qbind-node --test c4_b6_p2p_binary_path_interconnect_tests
cargo test -p qbind-node --test t146_timeout_view_change_tests
```

`cargo test -p qbind-node --tests` (the workspace-wide integration-test
build) currently fails to *compile* the unrelated
`crates/qbind-node/tests/m16_epoch_transition_hardening_tests.rs` test
binary because that test references methods
(`RocksDbConsensusStorage::set_inject_write_failure`,
`RocksDbConsensusStorage::clear_epoch_transition_marker`) that do not
exist on `main`. This failure is **pre-existing and unrelated to
Run 030**: it reproduces on a clean
`git stash && cargo check -p qbind-node --test m16_epoch_transition_hardening_tests`,
i.e. independently of any Run 030 change. Run 030 does not modify
`m16_epoch_transition_hardening_tests.rs` or the storage layer. The
`--test <name>` invocations above are scoped exactly to the test
binaries that compile cleanly on this branch, and that is the basis
for the pass/fail tables below.

---

## 5. Tests run and pass/fail status

### 5.1 Run 030 deterministic tests (new)

Module: `binary_consensus_loop::tests::run030` —
`crates/qbind-node/src/binary_consensus_loop.rs`.

| # | Test | Result |
|---|------|--------|
| 1 | `run030_outbound_signs_locally_emitted_timeout` | ✅ pass |
| 2 | `run030_outbound_fail_closed_when_signer_missing` | ✅ pass |
| 3 | `run030_inbound_valid_signed_timeout_verified_and_engine_accepts` | ✅ pass |
| 4 | `run030_inbound_unsigned_timeout_rejected_before_engine` | ✅ pass |
| 5 | `run030_inbound_bad_signature_timeout_rejected_before_engine` | ✅ pass |
| 6 | `run030_inbound_wrong_suite_timeout_rejected_before_engine` | ✅ pass |
| 7 | `run030_inbound_unknown_validator_timeout_rejected_before_engine` | ✅ pass |
| 8 | `run030_inbound_malformed_timeout_decode_failure_does_not_advance` | ✅ pass |
| 9 | `run030_inbound_valid_evidence_bearing_newview_advances_view` | ✅ pass |
| 10 | `run030_inbound_missing_evidence_newview_rejected_before_engine` | ✅ pass |
| 11 | `run030_inbound_evidence_mismatch_newview_rejected_before_engine` | ✅ pass |
| 12 | `run030_inbound_insufficient_quorum_newview_rejected_before_engine` | ✅ pass |
| 13 | `run030_inbound_duplicate_signer_newview_rejected_before_engine` | ✅ pass |
| 14 | `run030_inbound_mixed_view_newview_rejected_before_engine` | ✅ pass |
| 15 | `run030_inbound_bad_signature_newview_rejected_before_engine` | ✅ pass |
| 16 | `run030_inbound_wrong_suite_newview_rejected_before_engine` | ✅ pass |
| 17 | `run030_inbound_high_qc_mismatch_newview_rejected_before_engine` | ✅ pass |
| 18 | `run030_inbound_malformed_newview_decode_failure_does_not_advance` | ✅ pass |
| 19 | `run030_no_ctx_does_not_touch_run030_counters` (bit-equivalence) | ✅ pass |
| 20 | `run030_metrics_exposition_renders_all_counters` | ✅ pass |

Cargo summary: `test result: ok. 20 passed; 0 failed; 0 ignored;
0 measured; 642 filtered out`.

### 5.2 Pre-existing test surfaces that must not regress

| Surface | Result |
|---------|--------|
| `cargo test -p qbind-consensus --lib` | ✅ `test result: ok. 150 passed; 0 failed`. Includes `timeout_verify::tests::*` (Run 028) and the `timeout::tests::timeout_certificate_serializes_signed_timeouts` / `timeout::tests::timeout_accumulator_tc_carries_exact_signed_evidence` (Run 029). |
| `cargo test -p qbind-node --lib` | ✅ `test result: ok. 662 passed; 0 failed`. Includes the full `binary_consensus_loop::tests::*` family (52 tests including the 32 pre-existing B5/B9/B10/B11/B14/snapshot-trigger tests and the 20 new `run030` tests). |
| `cargo test -p qbind-node --test b3_snapshot_restore_tests` | ✅ 10 pass / 0 fail. |
| `cargo test -p qbind-node --test b5_restore_aware_consensus_start_tests` | ✅ 4 pass / 0 fail. |
| `cargo test -p qbind-node --test b9_late_peer_connect_proposal_reemit_tests` | ✅ 6 pass / 0 fail. |
| `cargo test -p qbind-node --test b10_engine_acceptance_qc_closure_tests` | ✅ 5 pass / 0 fail. |
| `cargo test -p qbind-node --test b11_consensus_net_prometheus_coverage_tests` | ✅ 5 pass / 0 fail. |
| `cargo test -p qbind-node --test c4_b6_p2p_binary_path_interconnect_tests` | ✅ 5 pass / 0 fail. |
| `cargo test -p qbind-node --test t146_timeout_view_change_tests` | ✅ 15 pass / 0 fail. |
| `cargo check -p qbind-node --bin qbind-node` | ✅ clean (2 pre-existing `bincode::config` deprecation warnings unrelated to Run 030). |
| `cargo check -p qbind-node --test m16_epoch_transition_hardening_tests` | ❌ pre-existing breakage — `RocksDbConsensusStorage::set_inject_write_failure` / `RocksDbConsensusStorage::clear_epoch_transition_marker` not in scope. Reproduces on a stashed working tree (i.e. with no Run 030 changes applied). Not in scope for Run 030. |

---

## 6. Topology

* **Deterministic in-loop topology used by `run030_*` tests**:
  4 validators with uniform voting power
  (`ValidatorSetEntry { id: ValidatorId(0..4), voting_power: 1 }`),
  ML-DSA-44 (`SUITE_PQ_RESERVED_1` = 100) per validator, in-process
  `LocalKeySigner` for the local validator under test, in-process
  `SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, MlDsa44Backend)`,
  in-process `TestKeyProvider` populated from
  `MlDsa44Backend::generate_keypair()` outputs, `chain_id =
  QBIND_DEVNET_CHAIN_ID`. The tests drive
  `handle_inbound_consensus_msg` and `maybe_emit_view_timeout`
  synchronously (the same functions the production tokio loop
  dispatches into) and a `CapturingFacade` records every outbound
  consensus frame for inspection.
* **Real-binary topology**: not run in this sandbox for the reasons
  given in §2 and "Remaining open items".

---

## 7. Log excerpts

The deterministic Run 030 tests do not enable `tracing_subscriber`, so
the runtime log lines emitted by `verify_timeout_msg` /
`verify_timeout_certificate_with_evidence` and the outbound-signing
path are not captured here in human-readable form. Their effect is
captured precisely by the per-reason metric counters and stat fields
asserted in the tests (see §8.2 / §9). Log statements added/preserved in
`maybe_emit_view_timeout` and the inbound arms of
`handle_inbound_consensus_msg` cover:

* `timeout-sign: start view=… validator=… suite=…`
* `timeout-sign: ok view=… validator=… suite=…`
* `timeout-sign: fail view=… validator=… reason=…`
* `timeout-verify: accept view=… validator=… suite=…`
* `timeout-verify: reject reason=… view=… validator=… suite=…`
* `newview-verify: accept view=… signers=… high_qc=…`
* `newview-verify: reject reason=… view=…`
* `tc-applied: view_advanced from=… to=…`

---

## 8. Metrics snapshots

### 8.1 Exposed metric names

The `run030_metrics_exposition_renders_all_counters` test asserts that
`NodeMetrics::format_metrics()` includes every one of these names after
the loop processes a single verified timeout:

```
qbind_consensus_inbound_timeout_verify_accepted_total
qbind_consensus_inbound_timeout_verify_rejected_total
qbind_consensus_inbound_timeout_rejected_unknown_validator_total
qbind_consensus_inbound_timeout_rejected_missing_key_total
qbind_consensus_inbound_timeout_rejected_wrong_suite_total
qbind_consensus_inbound_timeout_rejected_unsupported_suite_total
qbind_consensus_inbound_timeout_rejected_bad_signature_total
qbind_consensus_inbound_timeout_rejected_duplicate_total
qbind_consensus_inbound_timeout_engine_accepted_total
qbind_consensus_inbound_timeout_engine_rejected_total
qbind_consensus_inbound_newview_verify_accepted_total
qbind_consensus_inbound_newview_verify_rejected_total
qbind_consensus_inbound_newview_rejected_missing_evidence_total
qbind_consensus_inbound_newview_rejected_evidence_mismatch_total
qbind_consensus_inbound_newview_rejected_duplicate_signer_total
qbind_consensus_inbound_newview_rejected_mixed_view_total
qbind_consensus_inbound_newview_rejected_insufficient_quorum_total
qbind_consensus_inbound_newview_rejected_unknown_validator_total
qbind_consensus_inbound_newview_rejected_missing_key_total
qbind_consensus_inbound_newview_rejected_wrong_suite_total
qbind_consensus_inbound_newview_rejected_unsupported_suite_total
qbind_consensus_inbound_newview_rejected_bad_signature_total
qbind_consensus_inbound_newview_rejected_high_qc_mismatch_total
qbind_consensus_inbound_newview_engine_accepted_total
qbind_consensus_inbound_newview_engine_rejected_total
qbind_consensus_outbound_timeout_signing_success_total
qbind_consensus_outbound_timeout_signing_failure_total
qbind_consensus_view_advances_due_to_verified_tc_total
qbind_consensus_timeout_crypto_verify_latency_ns_total
qbind_consensus_timeout_crypto_verify_latency_observations_total
```

### 8.2 Per-rule counter pinning (proven by deterministic tests)

The Run 030 tests pin each documented rejection reason to its own
counter — no fabricated metrics:

| Counter | Pinned by |
|---------|-----------|
| `inbound_timeout_verify_accepted` | test 3 (=1) |
| `inbound_timeout_rejected_bad_signature` | tests 4, 5 (=1 each) |
| `inbound_timeout_rejected_wrong_suite` | test 6 (=1) |
| `inbound_timeout_rejected_unknown_validator` | test 7 (=1) |
| `view_timeout_decode_failures` (Timeout) | test 8 (≥1) |
| `inbound_newview_verify_accepted` + `view_advances_due_to_verified_tc` | test 9 (≥1) |
| `inbound_newview_rejected_missing_evidence` | test 10 (=1) |
| `inbound_newview_rejected_evidence_mismatch` | test 11 (=1) |
| `inbound_newview_rejected_insufficient_quorum` | test 12 (=1) |
| `inbound_newview_rejected_duplicate_signer` | test 13 (=1) |
| `inbound_newview_rejected_mixed_view` | test 14 (=1) |
| `inbound_newview_rejected_bad_signature` | test 15 (=1) |
| `inbound_newview_rejected_wrong_suite` | test 16 (=1) |
| `inbound_newview_rejected_high_qc_mismatch` | test 17 (=1) |
| `view_timeout_decode_failures` (NewView) | test 18 (≥1) |
| `outbound_timeout_signing_success` | test 1 (=1) |
| `outbound_timeout_signing_failure` | test 2 (=1) |
| All Run 030 counters stay at 0 when `verification_ctx = None` | test 19 |

In every negative test the matching `inbound_*_engine_accepted` counter
is asserted to remain at 0 and `engine.current_view()` is asserted not
to move, proving traffic does not reach the engine and views do not
advance because of invalid traffic.

---

## 9. Positive evidence

Achieved deterministically (in-loop) via the `run030_*` tests — equivalent
to the consensus-correctness contract that the production binary path
must observe:

1. A locally-emitted, B14-shaped `TimeoutMsg` is signed via
   `signer.sign_timeout_with_chain_id(...)` over
   `timeout_signing_bytes_with_chain_id(...)`, broadcast through the
   `ConsensusNetworkFacade::broadcast_consensus_msg(...)` exactly once,
   carries the canonical `suite_id == TIMEOUT_SUITE_ID`, has a
   non-empty signature, and self-verifies through `verify_timeout_msg`
   against the same `TimeoutVerificationContext` (test 1).
2. A valid signed inbound `TimeoutMsg` from a peer validator passes
   `verify_timeout_msg` and reaches `engine.on_timeout_msg(...)`
   (test 3); the `_verify_accepted` and `_engine_accepted` counters
   both increment, and a `(latency_ns, observations)` sample is
   recorded.
3. A valid evidence-bearing `TimeoutCertificate` (3 signed timeouts at
   the same view, distinct signers, vp ≥ 2/3) passes
   `verify_timeout_certificate_with_evidence(&tc, &tc.signed_timeouts, ...)`
   and reaches `engine.on_timeout_certificate(...)`,
   `view_advances_due_to_verified_tc` increments, and
   `engine.current_view()` strictly increases (test 9).

Real-binary positive evidence (N=4 Required-mode B14 absent-leader
recovery with verified-only traffic) is **not** captured in this run.
That run is gated by closing the C4 production-PQC-KEMTLS-root-key-
distribution sub-item, which is explicitly listed as still-open in
`docs/whitepaper/contradiction.md` C4. See "Remaining open items".

---

## 10. Negative evidence

Negative evidence in this run is **deterministic loop-API injection**,
not real-binary injection. Each negative case is a separate Run 030
test (§5.1) that:

* injects a single crafted invalid frame into
  `handle_inbound_consensus_msg`,
* asserts the correct per-reason rejection counter increments by
  exactly 1,
* asserts the matching `_verify_rejected_total` increments by 1,
* asserts the `_engine_accepted` counter remains at 0 (so the engine
  never observes the traffic),
* asserts `engine.current_view()` does not move (so views do not
  advance because of invalid traffic),
* asserts the loop function returns cleanly (so the
  process / loop remains alive — equivalent to "still alive" in a
  real-binary harness for an in-loop test).

| Negative case | Counter incremented | Engine accepted | View advanced |
|---------------|---------------------|-----------------|---------------|
| Malformed Timeout payload | `view_timeout_decode_failures` | no | no |
| Unsigned Timeout | `inbound_timeout_rejected_bad_signature` | no | no |
| Bad-signature Timeout | `inbound_timeout_rejected_bad_signature` | no | no |
| Wrong-suite Timeout | `inbound_timeout_rejected_wrong_suite` | no | no |
| Unknown-validator Timeout | `inbound_timeout_rejected_unknown_validator` | no | no |
| Malformed NewView payload | `view_timeout_decode_failures` | no | no |
| NewView with no signed evidence | `inbound_newview_rejected_missing_evidence` | no | no |
| NewView signer/evidence mismatch | `inbound_newview_rejected_evidence_mismatch` | no | no |
| NewView insufficient quorum | `inbound_newview_rejected_insufficient_quorum` | no | no |
| NewView duplicate signer | `inbound_newview_rejected_duplicate_signer` | no | no |
| NewView mixed view | `inbound_newview_rejected_mixed_view` | no | no |
| NewView bad signature | `inbound_newview_rejected_bad_signature` | no | no |
| NewView wrong suite | `inbound_newview_rejected_wrong_suite` | no | no |
| NewView high-QC mismatch | `inbound_newview_rejected_high_qc_mismatch` | no | no |

Real-binary negative-injection harness output is **not** captured here.
Per the problem statement's `contradiction.md` rules, this boundary is
recorded explicitly: "Run 030 negative injection is deterministic and
loop-API-level only; real-binary negative injection has not been
performed in this sandbox."

---

## 11. Pass/fail table

| Required item | Status |
|---------------|--------|
| Inbound `TimeoutMsg` verification gate before engine | ✅ wired and tested |
| Inbound `NewView` / `TimeoutCertificate` verification gate before engine | ✅ wired and tested |
| Outbound binary-loop timeout signing | ✅ wired and tested (positive + fail-closed) |
| Verification context plumbed through `BinaryConsensusLoopIo` | ✅ |
| Per-reason inbound timeout rejection counters | ✅ |
| Per-reason inbound newview rejection counters | ✅ |
| Outbound timeout signing success/failure counters | ✅ |
| `view_advances_due_to_verified_tc` counter | ✅ |
| Verification-latency `(ns_total, observations_total)` pair | ✅ |
| Decode-failure separation | ✅ |
| `verification_ctx = None` bit-equivalence | ✅ test 19 |
| Existing Run 028 / 029 tests still pass | ✅ |
| Existing B3 / B5 / B9 / B10 / B11 / C4-B6 / T146 tests still pass | ✅ |
| Existing `qbind-consensus` lib tests (150) still pass | ✅ |
| Existing `qbind-node` lib tests (662) still pass | ✅ |
| `cargo check -p qbind-node --bin qbind-node` clean | ✅ |
| Deterministic positive + negative coverage of every documented rejection class | ✅ (20 tests) |
| N=4 real-binary Required-mode positive evidence | ❌ not run in sandbox (see §12) |
| N=4 real-binary negative-injection evidence | ❌ not run in sandbox (see §12) |
| Production main.rs activation of `verification_ctx` | ❌ deferred — gated by C4 production-PQC-root-key-distribution |
| Full C4 closure | ❌ explicitly NOT marked closed |
| Pre-existing unrelated `m16_epoch_transition_hardening_tests` compile failure | ❌ pre-existing on `main`; not introduced by Run 030 |

---

## 12. Remaining open items

1. **Production main.rs activation of `verification_ctx`.** The single
   line added to `main.rs` keeps `verification_ctx: None` for both
   `run_local_mesh_node` and `run_p2p_node`. Activating this
   end-to-end requires the C4 production-PQC-KEMTLS-root-key-
   distribution sub-item to land first, so that
   (a) a real `SuiteAwareValidatorKeyProvider` can be instantiated from
   governed validator-set state,
   (b) a real `ConsensusSigBackendRegistry` over the supported suites
   can be wired (today's deterministic surface uses
   `SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1, MlDsa44Backend)`
   which is fine for tests but shouldn't be hard-coded into production
   main.rs without governance plumbing), and
   (c) a per-validator `LocalKeySigner` can be loaded from the
   keystore without exposing or cloning private key material at the
   loop boundary. The deterministic loop-API surface is already in place
   and does not require further code changes; only the main.rs
   construction site needs to be reached.

2. **N=4 real-binary positive evidence (V0/V1/V2/V3 Required-mode B14
   absent-leader recovery with verified-only inbound traffic).**
   Pending item 1.

3. **Real-binary negative-injection evidence.** Pending item 1.

4. **Production fast-sync / consensus-storage restore, exponential-
   backoff timeout pacing, long-window / large-state snapshot
   stability** — explicitly out of scope for Run 030 and explicitly
   left open in `docs/whitepaper/contradiction.md` C4.

5. **Pre-existing `m16_epoch_transition_hardening_tests` compile
   failure** (unrelated to Run 030; reproduced on a stashed
   working tree). Tracked separately from this run.

No new `TimeoutCertificate` wire-shape compatibility or persistence
issues were observed beyond the Run 029 wire-shape change itself, which
is already covered by the `timeout::tests::timeout_certificate_serializes_signed_timeouts`
serialization test.

---

## 13. Exact verdict

**Partial positive.**

* Outbound binary-loop timeout signing, inbound `Timeout` verification,
  inbound `NewView` / `TimeoutCertificate` verification, per-reason
  metrics, the `(latency_ns, observations)` pair, and the deterministic
  positive + complete negative test surface all land cleanly. Twenty new
  Run 030 deterministic tests pass. The previously-passing 150
  `qbind-consensus` lib tests, 662 `qbind-node` lib tests, and the
  B3 / B5 / B9 / B10 / B11 / C4-B6 / T146 integration test binaries
  continue to pass with no regressions. `cargo check -p qbind-node
  --bin qbind-node` is clean.
* N=4 real-binary positive Required-mode evidence and real-binary
  negative-injection evidence are **not** produced in this sandbox.
  The production `qbind-node` is intentionally still constructed with
  `verification_ctx: None` because activating it depends on the
  explicitly-open C4 production-PQC-KEMTLS-root-key-distribution
  sub-item; activating it without that sub-item would either bypass
  governance (unacceptable per the strict-scope rules) or fail-closed
  in the production binary on every timeout (worse than the bit-
  equivalent legacy behaviour today).
* Per the problem statement: full C4 is **not** marked closed, and the
  C4 sub-items "production fast-sync / consensus-storage restore,
  exponential-backoff timeout pacing, production PQC KEMTLS root-key
  distribution, long-window / large-state snapshot stability" remain
  open. C5 is materially narrowed, not closed: the binary-loop
  verification API is wired and proven; only the production main.rs
  activation remains.

This boundary is stated explicitly so a future run can pick up the
real-binary leg without rediscovering the production-PQC-root-key
dependency.