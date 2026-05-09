# QBIND DevNet Evidence Run 028

**Run ID**: 028  
**Date**: 2026-05-09  
**Scope**: C4 / smallest honest binary-path cryptographic verification hardening for `TimeoutMsg` and `TimeoutCertificate`  
**Status**: ⚠️ **PARTIAL** — engine-level cryptographic verification primitive landed and unit-tested. Binary-path inbound wiring, on-the-wire per-signer TC evidence, and outbound timeout signing wiring are explicitly **NOT** closed in this pass. C4 remains open.

---

## 1. Verdict

**Partial / smallest honest boundary reached.**

This run lands the smallest honest cryptographic verification primitive for HotStuff timeout traffic. It is implemented as a free-standing module that reuses the **existing** `SuiteAwareValidatorKeyProvider` + `ConsensusSigBackendRegistry` abstractions already used to verify proposals and votes (see `crates/qbind-consensus/src/crypto_verifier.rs` and `crates/qbind-node/src/verify_pool.rs`). It does not introduce a new parallel crypto path. It does not redesign HotStuff, B14, networking, or snapshot/restore. It does not change B3/B5/B13/B14 semantics. It does not bypass any existing PQ verification abstraction. It does not silently accept unsigned or malformed timeout traffic.

Run 028 does **NOT** claim full C4 closure. The remaining timeout-traffic gaps are listed explicitly in section 7.

---

## 2. Exact files changed

| File | Change |
|------|--------|
| `crates/qbind-consensus/src/timeout_verify.rs` | **New module.** Pure verification primitives `verify_timeout_msg` and `verify_timeout_certificate_with_evidence` plus `TimeoutVerifyError` / `TimeoutVerifyOutcome` types. 19 unit tests covering positive and negative paths. |
| `crates/qbind-consensus/src/lib.rs` | Declare `pub mod timeout_verify;` and re-export `TimeoutVerifyError`, `TimeoutVerifyOutcome`, `verify_timeout_msg`, `verify_timeout_certificate_with_evidence`. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_028.md` | **New.** This document. |
| `docs/whitepaper/contradiction.md` | New entry C5: `TimeoutCertificate` wire shape carries `signers: Vec<ValidatorId>` only — no per-signer signature evidence on the wire — so binary-path inbound TC verification cannot be closed without an evidence-bearing wire field. |

No changes to:
- `crates/qbind-consensus/src/timeout.rs` (unchanged — `TimeoutMsg` already carries `view`, `validator_id`, `suite_id`, `signature`, `high_qc`).
- `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (B14 surface untouched).
- `crates/qbind-node/src/binary_consensus_loop.rs` (inbound dispatch untouched in this pass).
- `crates/qbind-node/src/main.rs` (no plumbing changes).
- `crates/qbind-node/src/validator_signer.rs` (outbound timeout signing untouched in this pass).

---

## 3. Exact commands run

```text
cargo build -p qbind-consensus
cargo test -p qbind-consensus --lib
cargo test -p qbind-consensus --lib timeout_verify
cargo test -p qbind-consensus --tests
cargo check -p qbind-node --bin qbind-node
cargo test -p qbind-node --lib vm_v0_runtime
```

All commands exited 0.

---

## 4. Exact tests / evidence run and pass/fail status

### 4.1 New `timeout_verify` unit tests (19 tests, all pass)

Run: `cargo test -p qbind-consensus --lib timeout_verify`

Result: `19 passed; 0 failed; 0 ignored`.

| Test | Coverage | Status |
|------|----------|--------|
| `verify_valid_signed_timeout_is_accepted` | A real ML-DSA-44 signed `TimeoutMsg` over `timeout_signing_bytes_with_chain_id(QBIND_DEVNET_CHAIN_ID, ...)` is accepted. | ✅ |
| `verify_unsigned_timeout_is_rejected` | A `TimeoutMsg` with empty `signature` is rejected fail-closed. | ✅ |
| `verify_bad_signature_timeout_is_rejected` | A signed `TimeoutMsg` with one byte flipped in the signature returns `InvalidSignature(validator_id)`. | ✅ |
| `verify_wrong_suite_timeout_is_rejected` | A signed `TimeoutMsg` whose wire `suite_id` differs from the governance-configured suite for the signer returns `SuiteMismatch{validator, wire, governance}`. | ✅ |
| `verify_unknown_validator_timeout_is_rejected` | A signed `TimeoutMsg` from a validator not in the active set returns `UnknownValidator(validator_id)`. | ✅ |
| `verify_missing_governance_key_is_rejected_with_missing_key` | A `TimeoutMsg` from a member whose governance key is absent returns `MissingKey(validator_id)`. | ✅ |
| `verify_unsupported_governance_suite_is_rejected` | A `TimeoutMsg` whose governance suite has no registered backend returns `UnsupportedSuite{validator, governance_suite}`. | ✅ |
| `verify_timeout_outcome_classifier_matches_errors` | The metrics-bucket classifier maps `UnknownValidator → UnknownValidator`, `SuiteMismatch → WrongSuite`, `InvalidSignature → BadSignature`, otherwise `Other`. | ✅ |
| `verify_valid_2f_plus_1_tc_is_accepted` | A 4-validator set, 3 honest signed timeouts at view=11 with `high_qc=None` and `tc.signers={1,2,3}` is accepted; returned `acc_vp ≥ 2f+1`. | ✅ |
| `verify_tc_high_qc_is_deterministic_max_view` | When evidence carries 3 distinct `high_qc`s at views {5,8,6}, the deterministic max derivation returns `view=8` and the TC is accepted iff its `high_qc` matches that derivation. | ✅ |
| `verify_insufficient_quorum_tc_is_rejected` | A 4-validator set with only 2 valid signed timeouts returns `InsufficientQuorum{accumulated_vp, required_vp}`. | ✅ |
| `verify_duplicate_signer_tc_is_rejected` | A TC with `signers=[V1, V2, V1]` and matching evidence returns `DuplicateSigner(V1)`. | ✅ |
| `verify_mixed_view_tc_is_rejected` | A TC at `view=9` whose evidence contains one signed timeout at `view=10` returns `MixedView{expected: 9, actual: 10}`. | ✅ |
| `verify_tc_with_one_bad_signature_is_rejected` | A 3-signer TC where one evidence signature has been corrupted returns `InvalidSignature(_)`. | ✅ |
| `verify_tc_with_wrong_suite_signer_is_rejected` | A 3-signer TC where one evidence's wire `suite_id` differs from governance returns `SuiteMismatch{..}`. | ✅ |
| `verify_tc_with_unknown_signer_is_rejected` | A TC that includes a signer outside the active set returns `UnknownValidator(outside)` even though the outsider's signature is itself cryptographically valid. | ✅ |
| `verify_tc_with_evidence_mismatch_is_rejected` | When `tc.signers` and the evidence's `validator_id`s do not form the same set, returns `EvidenceMismatch`. | ✅ |
| `verify_tc_with_empty_evidence_is_rejected` | An empty evidence vector returns `EvidenceMismatch` (fail-closed; never silently accepted). | ✅ |
| `verify_tc_high_qc_mismatch_is_rejected` | Evidence with `high_qc=Some(qc)` but `tc.high_qc=None` returns `HighQcMismatch` (deterministic max-`high_qc` is not satisfied). | ✅ |

### 4.2 Existing `qbind-consensus` lib tests — no regression

Run: `cargo test -p qbind-consensus --lib`

Baseline before changes: `129 passed`.  
After changes: `148 passed; 0 failed; 0 ignored` (the 19 new `timeout_verify` tests + the 129 pre-existing tests, including all `timeout::tests::*`, `t146_timeout_types_tests::*` accumulator/TC/pacemaker tests, `qc::tests::*`, `validator_set::tests::*`, `slashing::tests::*`).

### 4.3 Existing `qbind-consensus` integration tests — no regression

Run: `cargo test -p qbind-consensus --tests`

All integration test binaries pass. Includes the existing `t146_timeout_types_tests` and `m5_timeout_view_change_tests` suites that exercise `TimeoutMsg` / `TimeoutAccumulator` / `TimeoutCertificate` / `TimeoutPacemaker` semantics that B14 relies on.

### 4.4 `qbind-node` builds clean

Run: `cargo check -p qbind-node --bin qbind-node`

Result: `Finished` (exit 0). The two pre-existing `bincode::config` deprecation warnings are unchanged (not introduced by Run 028).

### 4.5 VM-v0 / snapshot-trigger tests still pass

Run: `cargo test -p qbind-node --lib vm_v0_runtime`

Result: `9 passed; 0 failed`. The Run 022/023/025/026/027 snapshot-trigger surface (`vm_v0_snapshot_trigger_*`, `restored_state_dir_is_opened_by_runtime`) is **not** affected by this change — there is no overlap.

---

## 5. What was fixed

1. The qbind-consensus crate now exposes a free-standing, pure-function cryptographic verification primitive for HotStuff timeout traffic that:
   - **Reuses** the same governance suite-and-key source (`SuiteAwareValidatorKeyProvider`) used by proposal/vote verification.
   - **Reuses** the same suite-dispatch registry (`ConsensusSigBackendRegistry`) used by proposal/vote verification.
   - **Reuses** the canonical chain-aware preimage (`timeout_signing_bytes_with_chain_id`) already defined in `crates/qbind-consensus/src/timeout.rs`.
   - **Reuses** the existing ML-DSA-44 backend (`MlDsa44Backend`) at the `verify_vote` entry consistent with the existing `verify_pool.rs` mapping `ConsensusMsgKind::Timeout → backend.verify_vote`.
   - **Fail-closed**: every error path returns a typed `TimeoutVerifyError` with sufficient context (`validator_id`, `wire_suite`, `governance_suite`, `accumulated_vp`, `required_vp`, etc.) for the caller to drive precise rejection counters.
2. The TC-level helper enforces, in a single deterministic pass:
   - signers are unique;
   - every evidence timeout is for the same view as the TC;
   - every evidence signature verifies against governed suite/key for its signer;
   - every signer is in the active validator set;
   - accumulated voting power is ≥ `validators.two_thirds_vp()`;
   - the deterministic max-`high_qc` over the evidence matches the certificate's `high_qc`.
3. A `TimeoutVerifyOutcome` classifier categorizes errors into the metrics buckets the binary path will need (`UnknownValidator`, `WrongSuite`, `BadSignature`, `Other`) so callers can wire counters without re-implementing the mapping.

---

## 6. What was proven

**On real ML-DSA-44 keys, on the canonical chain-aware preimage, against the existing PQ verification abstractions:**

- A valid signed `TimeoutMsg` is accepted (Run 028 / 4.1 / `verify_valid_signed_timeout_is_accepted`).
- An unsigned `TimeoutMsg` is rejected fail-closed (4.1 / `verify_unsigned_timeout_is_rejected`).
- A bad-signature `TimeoutMsg` is rejected fail-closed (4.1 / `verify_bad_signature_timeout_is_rejected`).
- A wrong-suite `TimeoutMsg` is rejected with explicit `SuiteMismatch` context (4.1).
- An unknown-validator `TimeoutMsg` is rejected even when the outsider's own signature is cryptographically valid (4.1 / `verify_unknown_validator_timeout_is_rejected`).
- Missing-governance-key and unsupported-governance-suite both fail closed with distinct error variants (4.1).
- A valid `2f+1` TC with proper evidence is accepted and yields the deterministic max-`high_qc` (4.1).
- Insufficient-quorum, duplicate-signer, mixed-view, single-bad-signature-inside-TC, wrong-suite-signer-inside-TC, unknown-signer-inside-TC, evidence/signers-set mismatch, empty-evidence, and `high_qc` mismatch are all rejected fail-closed with distinct error variants (4.1).
- No regression in any existing `qbind-consensus` lib or integration test (4.2, 4.3).
- No regression in `qbind-node` build (4.4) or VM-v0 / snapshot-trigger tests (4.5).

---

## 7. What remains not solved

These items are intentionally **not** addressed in Run 028. They are tracked here so the next pass can pick them up without fabricating closure.

### 7.1 Binary-path inbound wiring (NOT WIRED)

`crates/qbind-node/src/binary_consensus_loop.rs` `ConsensusNetMsg::Timeout` and `ConsensusNetMsg::NewView` arms (lines 1736–1897) still route inbound payloads directly to `engine.on_timeout_msg` / `engine.on_timeout_certificate` without first calling `verify_timeout_msg` / `verify_timeout_certificate_with_evidence`. The existing fail-closed comments in those arms explicitly note this gap (`// We do NOT verify the timeout's signature here.`, `binary_consensus_loop.rs:1752`). Plumbing a `Arc<dyn SuiteAwareValidatorKeyProvider>` + `Arc<dyn ConsensusSigBackendRegistry>` + `ChainId` through `BinaryConsensusLoopIo` and adding the per-reason counters (`inbound_timeouts_sig_ok`, `inbound_timeouts_sig_failed`, `inbound_timeouts_wrong_suite`, `inbound_timeouts_unknown_validator`, `inbound_new_views_sig_ok`, `inbound_new_views_sig_failed`, etc.) is the next pass.

### 7.2 `TimeoutCertificate` wire shape lacks per-signer evidence (BLOCKER for inbound TC sig verification)

`crates/qbind-consensus/src/timeout.rs` `TimeoutCertificate` carries `signers: Vec<ValidatorId>` and `high_qc: Option<QuorumCertificate<BlockIdT>>` only — **no per-signer signature, no per-signer suite_id**. `verify_timeout_certificate_with_evidence` therefore takes the per-signer `Vec<TimeoutMsg>` evidence as a *separate* parameter. This is sound for **locally-formed** TCs (where the evidence is the local `TimeoutAccumulator`'s entries) but means an **inbound** `NewView` payload arrives without the cryptographic evidence required for full per-signer verification.

The smallest, lowest-risk path is to add an explicit evidence-bearing field (e.g. `signed_timeouts: Vec<TimeoutMsg<BlockIdT>>`) to `TimeoutCertificate`, populate it in `TimeoutAccumulator::maybe_tc_for`, and have the binary path require a non-empty evidence field on inbound TCs. This is a wire-format change — existing serialized TCs would not decode under the new struct. We are explicitly deferring it to a separate Run because:
1. It changes a serialized type and warrants its own evidence run.
2. It interacts with the persisted TC formats consumed by `binary_consensus_loop` decode paths (see 4.4 deprecation warnings already on the bincode call sites).
3. It does **not** weaken the safety of the primitive we just landed; it only blocks the *binary-path* application of it for inbound TCs.

Tracked as new entry **C5** in `docs/whitepaper/contradiction.md`.

### 7.3 Outbound timeout signing wiring (NOT WIRED)

`crates/qbind-node/src/binary_consensus_loop.rs:1998-2025` (`apply_local_tc_and_broadcast_new_view` / view-timeout emission path) builds locally-emitted `TimeoutMsg`s via `engine.create_timeout_msg()` (which returns an unsigned message with `signature: vec![]`) and broadcasts the bincode encoding directly. There is no call into `validator_signer::ValidatorSigner` to sign the canonical preimage. The next pass should mirror the existing `BlockProposal` / `Vote` outbound signing path (see `crates/qbind-node/src/validator_signer.rs`) by adding a small `sign_timeout_msg(&self, view, high_qc, validator_id) -> Vec<u8>` entry and threading it through. This pass intentionally did **not** add it because doing so safely requires plumbing a signer reference into the binary loop and exercising it in a real-binary N=4 run, both of which are out of scope for the smallest honest primitive boundary.

### 7.4 N=4 real-binary Required-mode evidence run (NOT EXECUTED)

The original Run 028 ask included a real-binary N=4 `--p2p-mutual-auth required` run with B14 absent-leader recovery exercised under timeout/new-view verification, plus a negative injection harness for malformed timeout/new-view traffic. Because 7.1, 7.2, and 7.3 are explicitly **not** wired in this pass, executing such a run would not exercise the new verification primitive on the binary path — it would only re-prove Run 027's already-established state. We deliberately do **not** run a misleading "binary still ticks" experiment under the Run 028 banner. The N=4 real-binary verification run is deferred to the next pass that closes 7.1+7.2+7.3.

### 7.5 No metrics added in this pass

Per (5) above, this pass only landed the verification primitive. No new metrics (`inbound_timeouts_sig_ok`, etc.) were added because there is no caller yet. They will be added together with the binary-path wiring (7.1) so that increment/accept counter pairing can be proven end-to-end in a single run, rather than fabricated against an absent caller.

### 7.6 Verification latency histogram

The existing `ConsensusSigMetrics` per-suite latency buckets (`crypto_verifier.rs:439-457`) handle vote and proposal latency only. Extending the same pattern to `timeout` is straightforward but requires the binary-path caller to thread metrics through; it is paired with 7.1.

---

## 8. Was `contradiction.md` updated, and why

**Yes.**

A new contradiction entry **C5** has been added to `docs/whitepaper/contradiction.md` recording the precise wire-shape gap surfaced by this run:

> **C5. `TimeoutCertificate` wire shape carries no per-signer signature evidence.** The binary path currently cannot verify each signer's signature on an inbound `NewView` payload because `TimeoutCertificate` only carries `signers: Vec<ValidatorId>` and `high_qc: Option<QuorumCertificate<BlockIdT>>`. The Run 028 verification primitive (`verify_timeout_certificate_with_evidence`) takes the per-signer signed `TimeoutMsg` evidence as a separate argument, which is sound for locally-formed TCs but not for inbound TCs. Closing this requires a wire-shape change to add an evidence-bearing field; tracked as a separate run.

This is recorded as **OPEN — narrow** because:
- It does **not** weaken proposal/vote/QC verification (those are already enforced).
- It does **not** weaken `TimeoutMsg`-level verification (Run 028 covers that fully at the engine boundary).
- It only blocks **binary-path inbound `NewView`** signature verification until the wire change lands.

The existing C4 entry remains OPEN; Run 028 narrows the C4 sub-item "signature verification of `TimeoutMsg`/`TimeoutCertificate`" by adding the engine-level primitive but does NOT close it.

No other contradictions were introduced or invalidated by this run.

---

## 9. Exact immediate next action recommended

**Land the inbound binary-path wiring + the `TimeoutCertificate` evidence-bearing field together in a single follow-up run (proposed Run 029):**

1. Extend `TimeoutCertificate` in `crates/qbind-consensus/src/timeout.rs` with a `signed_timeouts: Vec<TimeoutMsg<BlockIdT>>` field. Populate it in `TimeoutAccumulator::maybe_tc_for`. Update existing `TimeoutCertificate::validate` to remain as-is (cheap voting-power-only check) and add a new `validate_with_signatures(...)` that delegates to `verify_timeout_certificate_with_evidence(self, &self.signed_timeouts, ...)`.
2. Thread `Arc<dyn SuiteAwareValidatorKeyProvider>` + `Arc<dyn ConsensusSigBackendRegistry>` + `ChainId` through `BinaryConsensusLoopIo` (or a new optional sibling `BinaryConsensusLoopVerifiers` struct, gated by `Option<...>` so the no-crypto LocalMesh / single-validator path stays bit-equivalent).
3. In `binary_consensus_loop.rs::process_inbound_msg` `Timeout` arm, call `verify_timeout_msg` **before** `engine.on_timeout_msg`. On error, increment a precise per-reason counter (mirroring the `view_timeout_engine_rejects` pattern already in the file).
4. In `process_inbound_msg` `NewView` arm, call `verify_timeout_certificate_with_evidence(&tc, &tc.signed_timeouts, ...)` **before** `engine.on_timeout_certificate`. On error, increment a precise per-reason counter.
5. Mirror the existing `validator_signer.rs` outbound signing pattern to sign locally-emitted `TimeoutMsg` over `timeout_signing_bytes_with_chain_id(...)` with the validator's signer; do not clone or expose private key material.
6. Add the new metrics surface (`inbound_timeouts_sig_ok`, `_sig_failed`, `_wrong_suite`, `_unknown_validator`, `_duplicate`, `inbound_new_views_sig_ok`, `_sig_failed`, `_quorum_failed`, `_high_qc_mismatch`, `_decode_failures`, `view_advances_due_to_verified_tc`, plus a per-suite latency entry).
7. Re-run the existing N=4 Required-mode B14 absent-leader recovery harness on the real binary and confirm: (a) committed_height/current_view advance under honest timeout/new-view traffic, (b) decode/engine reject/crypto-fail counters stay at zero during honest traffic, (c) negative injection (malformed Timeout/NewView, bad-signature, wrong-suite, unknown-validator, mixed-view, sub-quorum) increments rejection counters and never advances view, (d) proposal/vote/QC paths are bit-equivalent to Run 027, (e) snapshot-trigger paths from Run 027 remain bit-equivalent.
8. Produce `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_029.md` with the exact positive and negative results from (7).

Only after Run 029 lands cleanly should the C4 sub-item "signature verification of `TimeoutMsg` / `TimeoutCertificate`" be marked closed in `docs/whitepaper/contradiction.md`. Run 028 explicitly does not claim that closure.