# QBIND DevNet Evidence — Run 035

## Forged Timeout / NewView Negative Injection Harness

| Field | Value |
|---|---|
| **Run** | 035 |
| **Date** | 2026-05-10 |
| **Branch** | `copilot/continue-qbind-activity` |
| **Commit** | `a2281b7806bf3d15d6b4685c476c6d384a1ae6b4` (working tree at run start; landed code committed by `report_progress` at the end of this run) |
| **Working tree at evidence time** | `M crates/qbind-node/src/{binary_consensus_loop.rs,cli.rs,lib.rs,main.rs,p2p_inbound.rs}` + `?? crates/qbind-node/src/forged_injection.rs` (uncommitted at moment of binary build; committed by Run 035's `report_progress` push) |
| **Binary** | `target/debug/qbind-node` |
| **Binary sha256** | `5c90fcc486b1132c76c1f4aca76d93fae3c48374c3de21499f5d32fc5aeee4af` |
| **Binary size** | `290338072` bytes |
| **ELF BuildID** | `63e756e7fc87c7df870c8c3c88c4774d63453e6c` |
| **Profile** | `dev` (`cargo build -p qbind-node --bin qbind-node`) |
| **Rustc** | repository-pinned (`rustup` toolchain unchanged) |
| **Verdict** | **PARTIAL POSITIVE** — see Verdict section. |

---

## 1. Exact objective

Prove or disprove, on the real `qbind-node` binary, that malformed or
forged `TimeoutMsg` / `NewView` / `TimeoutCertificate` traffic is rejected
**fail-closed before engine ingestion** when `--require-timeout-verification`
is active, by adding the smallest opt-in dev/test-only injection harness
that traverses the same binary-loop verification gate as live inbound P2P
frames. Do not redesign HotStuff, B14, or snapshot/restore. Do not
introduce classical crypto assumptions. Do not bypass existing PQC
verification abstractions. Do not allow forged traffic to reach
`engine.on_timeout_msg` / `engine.on_timeout_certificate`. Do not allow
invalid traffic to advance view. Do not mark full C4 closed.

---

## 2. Exact files changed

| File | Change |
|---|---|
| `crates/qbind-node/src/forged_injection.rs` | **NEW** — Run 035 module: `ForgedInjectionCase` (12-variant enum), `ForgedInjectionGateError`, `ForgedInjectionHarness::try_activate`, `ForgedFrameBuilder` (per-case `ConsensusNetMsg` builders), `inject_frame`, `log_injection`, `RuntimeFixture`, `spawn_runtime_injection_task`. Plus 21 deterministic tests. |
| `crates/qbind-node/src/lib.rs` | Added `pub mod forged_injection;`. |
| `crates/qbind-node/src/cli.rs` | Added hidden `--devnet-forged-inject CASE` (`Append`) flag. Hidden via `hide = true` so it does not appear in `--help`. |
| `crates/qbind-node/src/binary_consensus_loop.rs` | Promoted `handle_inbound_consensus_msg` from `fn` to `pub(crate) fn`. Promoted `RestoreCatchupModeState` from `struct` to `pub(crate) struct`. Added `pub(crate) fn deliver_inbound_for_run035(...)` test helper that wraps `handle_inbound_consensus_msg` with a fresh non-restore mode state. |
| `crates/qbind-node/src/p2p_inbound.rs` | Added `ChannelConsensusHandler::sender_clone() -> mpsc::Sender<ConsensusNetMsg>` so the runtime injection task can push forged frames into the same inbound channel real P2P traffic uses. |
| `crates/qbind-node/src/main.rs` | (a) Top-level safety gate after `validate_p2p_config()`: refuses startup on Testnet/Mainnet, missing env var, unknown case token, or non-P2P network mode whenever `--devnet-forged-inject` is present. (b) Wires `consensus_handler.sender_clone()` and `maybe_spawn_run035_forged_injection_harness(...)` after `spawn_binary_consensus_loop_with_io`. (c) Awaits the optional `run035_handle` on shutdown alongside `consensus_handle` / `snapshot_handle`. |
| `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_035.md` | **NEW** — this document. |
| `docs/whitepaper/contradiction.md` | C5 update appended: Run 035 narrows C5 by adding the opt-in dev/test-only forged-Timeout/NewView negative injection harness; C5 remains OPEN strictly because production PQC KEMTLS root-key distribution (a C4 sub-item) is still not solved; full C4 remains OPEN. |

No production crypto, network, engine, B14, snapshot/restore, or transport-PKI code path was modified. The new module is dev/test-only and is gated by three concurrent affirmative signals (see §4).

---

## 3. Exact commands run

```bash
# Build + check
cargo build -p qbind-node --lib
cargo build -p qbind-node --bin qbind-node
cargo check -p qbind-node --bin qbind-node

# Targeted tests (Run 035 + Run 030 + key regressions)
cargo test -p qbind-node --lib forged_injection
cargo test -p qbind-node --lib run030
cargo test -p qbind-node --lib vm_v0_runtime
cargo test -p qbind-node --lib test_cli
cargo test -p qbind-node --lib

# Real-binary safety-gate smoke checks (binary identity captured below)
sha256sum target/debug/qbind-node
readelf -n target/debug/qbind-node | grep "Build ID"

./target/debug/qbind-node --env testnet --devnet-forged-inject malformed-timeout
./target/debug/qbind-node --env mainnet --devnet-forged-inject malformed-timeout
./target/debug/qbind-node --env devnet --devnet-forged-inject malformed-timeout      # env var unset
QBIND_DEVNET_FORGED_INJECTION=0 \
    ./target/debug/qbind-node --env devnet --devnet-forged-inject malformed-timeout
QBIND_DEVNET_FORGED_INJECTION=1 \
    ./target/debug/qbind-node --env devnet --devnet-forged-inject not-a-case
QBIND_DEVNET_FORGED_INJECTION=1 \
    ./target/debug/qbind-node --env devnet --network-mode local-mesh \
        --devnet-forged-inject malformed-timeout
./target/debug/qbind-node --help | grep -c forged-inject       # → 0 (hidden)
```

---

## 4. Harness design and safety gate

### Activation requires THREE concurrent signals

The harness is **disabled by default**. To activate:

1. **CLI** — one or more `--devnet-forged-inject CASE` flags (`Append`,
   hidden from `--help` via `hide = true`). Valid `CASE` tokens are:
   `malformed-timeout`, `unsigned-timeout`, `bad-signature-timeout`,
   `wrong-suite-timeout`, `unknown-validator-timeout`,
   `malformed-newview`, `missing-evidence-newview`,
   `duplicate-signer-newview`, `insufficient-quorum-newview`,
   `mixed-view-newview`, `bad-signature-newview`,
   `high-qc-mismatch-newview`. Unknown tokens cause
   `[binary] FATAL: --devnet-forged-inject parse error: …` and `exit 1`.

2. **Environment** — `--env devnet`. Both `Testnet` and `Mainnet`
   produce `[binary] FATAL: Run 035 forged-injection harness is
   dev/test-only and cannot run on environment={Testnet,Mainnet};
   refusing startup` and `exit 1`.

3. **Affirmative env var** — `QBIND_DEVNET_FORGED_INJECTION=1` (literal
   `"1"`, no leading/trailing whitespace, no `"true"`, no `"on"`, no
   `"yes"`, no `"0"`). Anything else produces `[binary] FATAL: Run 035
   forged-injection harness gated: --devnet-forged-inject was supplied
   but QBIND_DEVNET_FORGED_INJECTION=1 is not set in the environment;
   refusing to activate. This second affirmative gate prevents
   accidental activation in dev/test runs.` and `exit 1`.

In addition, the top-level main-function gate refuses any non-P2P
network mode (LocalMesh) because the harness has no inbound channel
to push frames into:

```
[binary] FATAL: --devnet-forged-inject requires --network-mode p2p
(the harness pushes frames through the P2P inbound channel).
LocalMesh has no inbound channel; refusing to start.
```

### What the harness does (and never does)

* **Does** push a single bincode-encoded `ConsensusNetMsg::Timeout(bytes)`
  or `ConsensusNetMsg::NewView(bytes)` frame per case into the same
  `mpsc::Sender<ConsensusNetMsg>` cloned from
  `ChannelConsensusHandler::sender_clone()` — i.e. the **same channel
  the P2P inbound demuxer feeds**.
* **Does** rely on the binary loop's existing
  `handle_inbound_consensus_msg` to verify each frame via
  `verify_timeout_msg` / `verify_timeout_certificate_with_evidence`
  **before** any call to `engine.on_timeout_msg` /
  `engine.on_timeout_certificate`.
* **Does not** call any engine API directly.
* **Does not** read or write any metrics counter. All counter motion
  is performed by `handle_inbound_consensus_msg`; the harness cannot
  fabricate metrics.
* **Does not** log signature bytes, signing keys, public keys, or
  signing preimages. Logged metadata is limited to: case label, frame
  kind (`Timeout` / `NewView`), encoded byte length.
* **Does not** disable or alter `--require-timeout-verification` or
  the `verification_ctx` honesty path Run 034 proved.
* **Does not** introduce classical crypto. Timeout signatures (when
  the harness needs a "near-valid then mutated" signature) are produced
  by `qbind_crypto::ml_dsa44::MlDsa44Backend`, the same PQC backend
  the rest of the consensus path uses.
* **Does not** modify the P2P transport, KEMTLS, B12 transport
  identity binding, or anything in C4. The harness is strictly inside
  the *consensus inbound message channel*.

### Key fixture handling

The runtime path generates fresh ephemeral ML-DSA-44 keypairs at
process start (one per validator id in `0..num_validators`) and uses
them only inside the harness. These keys are **not** registered with
any production `SuiteAwareValidatorKeyProvider`, so even forged
TimeoutMsgs that decode correctly fail signature verification against
the real per-validator public keys distributed via
`--validator-consensus-key VID:SUITE:HEXPK` — exactly the rejection
paths the harness needs to exercise. The keys never touch the keystore,
the signer, or any persistent storage; they are dropped on process
exit.

---

## 5. Topology

The deterministic test path (`#[cfg(test)] mod tests` in
`forged_injection.rs`) uses an N=4 fixture identical in shape to the
Run 030 corpus:

* `ConsensusValidatorSet` with `ValidatorId(0)..=ValidatorId(3)`,
  voting power 1 each.
* `SimpleBackendRegistry::with_backend(SUITE_PQ_RESERVED_1 /* 100 = ML-DSA-44 */, MlDsa44Backend)`.
* `TestKeyProvider` (a fixture-scoped `SuiteAwareValidatorKeyProvider`)
  carrying the per-validator ML-DSA-44 public keys.
* `chain_id = QBIND_DEVNET_CHAIN_ID`.
* `BasicHotStuffEngine::<[u8; 32]>::new(ValidatorId(0), …)`.
* `BinaryConsensusLoopInboundStats::default()` (so each case test
  starts at all-zeros).
* `Arc<NodeMetrics>` from `NodeMetrics::new()`.

Forged frames are constructed by `ForgedFrameBuilder` and pushed
through `deliver_inbound_for_run035` (a `pub(crate)` thin wrapper
around `handle_inbound_consensus_msg` with a fresh
`RestoreCatchupModeState::from_config(None)`).

The runtime path activated by the CLI flag uses the same harness
module, the same `ForgedFrameBuilder`, and the same destination
channel (`ChannelConsensusHandler::sender_clone()`). The loop's
consumer is identical (same `handle_inbound_consensus_msg` path).

### Real-binary N=4 boundary disclosure

A full N=4 Required-mode real-binary run with active timeout
verification (`--require-timeout-verification` + signer keystores +
four `--validator-consensus-key` entries on every node) was **not
executed in this evidence run**. The reason is that the CI sandbox
this run executed in does not have the privileges or the controlled
network namespace required to run four live `qbind-node` binaries
under `--p2p-mutual-auth required` for several minutes (the same
boundary Runs 034's evidence machine cleared and Run 035's CI sandbox
does not). The deterministic test corpus and the **real-binary
safety-gate smoke checks** (§7) cover everything that is feasible on
this machine; the post-merge operator run will exercise the live
N=4 path identically to Run 034 (V0/V1A/V2A/V3A,
`--p2p-mutual-auth required`, `--execution-profile vm-v0`,
`--require-timeout-verification`, four
`--validator-consensus-key VID:100:HEXPK`, `QBIND_DEVNET_FORGED_INJECTION=1`,
plus `--devnet-forged-inject all-cases-listed` against one target
node).

---

## 6. Validator key / consensus-key setup

* The 4 deterministic-test fixtures generate ephemeral ML-DSA-44
  keypairs in-test via `MlDsa44Backend::generate_keypair()`. Public
  keys are registered with the test `SuiteAwareValidatorKeyProvider`;
  signing-key bytes feed the forged-frame builder.
* The runtime fixture (`RuntimeFixture` constructed inside
  `maybe_spawn_run035_forged_injection_harness`) generates fresh
  ephemeral ML-DSA-44 keypairs at process start and discards them on
  exit. These keys are NOT honest validator keys; they exist only so
  the harness can produce a "decode-OK then signature-verify-FAILS"
  shape for the bad-signature / wrong-suite / mixed-view /
  duplicate-signer / insufficient-quorum / high-qc-mismatch cases.
* No private signing-key bytes, signing preimages, or fingerprints
  are logged anywhere by the harness or this evidence document.

---

## 7. Pass/fail table

### 7a. Deterministic tests (real `qbind-node` lib, this commit)

| Test | Result |
|---|---|
| `run035_harness_disabled_by_default_no_cli_cases` | ✅ PASS |
| `run035_harness_refuses_testnet` | ✅ PASS |
| `run035_harness_refuses_mainnet` | ✅ PASS |
| `run035_harness_refuses_devnet_without_env_var` (8 sub-values) | ✅ PASS |
| `run035_harness_activates_only_with_devnet_and_affirmative_env_var` | ✅ PASS |
| `run035_case_parser_round_trip_and_unknown_rejected` | ✅ PASS |
| `run035_malformed_timeout_decode_fails_no_engine_no_view_advance` | ✅ PASS |
| `run035_unsigned_timeout_rejected_before_engine` | ✅ PASS |
| `run035_bad_signature_timeout_rejected_before_engine` | ✅ PASS |
| `run035_wrong_suite_timeout_rejected_before_engine` | ✅ PASS |
| `run035_unknown_validator_timeout_rejected_before_engine` | ✅ PASS |
| `run035_malformed_newview_decode_fails_no_engine_no_view_advance` | ✅ PASS |
| `run035_missing_evidence_newview_rejected_before_engine` | ✅ PASS |
| `run035_duplicate_signer_newview_rejected_before_engine` | ✅ PASS |
| `run035_insufficient_quorum_newview_rejected_before_engine` | ✅ PASS |
| `run035_mixed_view_newview_rejected_before_engine` | ✅ PASS |
| `run035_bad_signature_newview_rejected_before_engine` | ✅ PASS |
| `run035_high_qc_mismatch_newview_rejected_before_engine` | ✅ PASS |
| `run035_all_cases_reject_before_engine_no_view_advance` (12 cases) | ✅ PASS |
| `run035_honest_traffic_after_injection_still_verifies` | ✅ PASS |
| `run035_channel_round_trip_delivers_into_inbound_path` | ✅ PASS |

`cargo test -p qbind-node --lib forged_injection` → **21 / 21 passing**.

### 7b. Regression of pre-Run-035 corpus

| Test family | Result |
|---|---|
| `run030::*` (Run 030 deterministic verification API + binary-loop tests) | ✅ 20 / 20 PASS |
| `vm_v0_runtime::*` (snapshot trigger + state-dir suite) | ✅ 9 / 9 PASS |
| `cli::test_cli_*` (CLI parsing including help-flags + snapshot-dir) | ✅ 24 / 24 PASS (no regression of pre-existing CLI tests) |
| Full `cargo test -p qbind-node --lib` | ✅ **746 / 746 PASS** (= 725 pre-Run-035 + 21 new Run 035) |

### 7c. Real-binary safety-gate smoke checks

Every command below was run against `target/debug/qbind-node`
sha256 `5c90fcc486b1132c76c1f4aca76d93fae3c48374c3de21499f5d32fc5aeee4af`,
ELF BuildID `63e756e7fc87c7df870c8c3c88c4774d63453e6c`.

| Command | Observed | Expected | Result |
|---|---|---|---|
| `--env testnet --devnet-forged-inject malformed-timeout` | `[binary] FATAL: Run 035 forged-injection harness is dev/test-only and cannot run on environment=Testnet; refusing startup.` | exit 1 with NotDevnet | ✅ PASS |
| `--env mainnet --devnet-forged-inject malformed-timeout` | `[binary] FATAL: … environment=Mainnet; refusing startup.` | exit 1 with NotDevnet | ✅ PASS |
| `--env devnet --devnet-forged-inject malformed-timeout` (env var unset) | `[binary] FATAL: … QBIND_DEVNET_FORGED_INJECTION=1 is not set in the environment; refusing to activate.` | exit 1 with MissingEnvVar | ✅ PASS |
| `QBIND_DEVNET_FORGED_INJECTION=0 --env devnet --devnet-forged-inject malformed-timeout` | same MissingEnvVar message | exit 1 with MissingEnvVar | ✅ PASS |
| `QBIND_DEVNET_FORGED_INJECTION=1 --env devnet --devnet-forged-inject not-a-case` | `[binary] FATAL: --devnet-forged-inject parse error: unknown forged-injection case 'not-a-case'; valid: malformed-timeout, …, high-qc-mismatch-newview.` | exit 1 with parse error | ✅ PASS |
| `QBIND_DEVNET_FORGED_INJECTION=1 --env devnet --network-mode local-mesh --devnet-forged-inject malformed-timeout` | `[binary] FATAL: --devnet-forged-inject requires --network-mode p2p (the harness pushes frames through the P2P inbound channel). LocalMesh has no inbound channel; refusing to start.` | exit 1 with non-P2P refusal | ✅ PASS |
| `--help` | `--devnet-forged-inject` does NOT appear (`grep -c forged-inject == 0`) | flag hidden | ✅ PASS |

---

## 8. Per-case rejection metric mapping (from deterministic tests)

For each forged case, the precise per-reason rejection counter
incremented by exactly 1, no engine-accept counter incremented, and the
view did not advance. The counter family is identical to Run 030 — Run
035 reuses Run 030 / Run 034 metric families and fabricates none.

| Case | Inbound path | Counter incremented | Engine accept counter | View advance |
|---|---|---|---|---|
| `MalformedTimeout` | `Timeout(0xff×32)` | `view_timeout_decode_failures += 1`, `inbound_decode_failures += 1` | `inbound_timeout_engine_accepted = 0` | none |
| `UnsignedTimeout` | `Timeout(bincode(empty-sig))` | `inbound_timeout_verify_rejected_total += 1`, `inbound_timeout_rejected_bad_signature += 1` | `inbound_timeout_engine_accepted = 0` | none |
| `BadSignatureTimeout` | flipped first sig byte | `inbound_timeout_verify_rejected_total += 1`, `inbound_timeout_rejected_bad_signature += 1` | `inbound_timeout_engine_accepted = 0` | none |
| `WrongSuiteTimeout` | mutated `suite_id` | `inbound_timeout_verify_rejected_total += 1`, `inbound_timeout_rejected_wrong_suite += 1` | `inbound_timeout_engine_accepted = 0` | none |
| `UnknownValidatorTimeout` | `validator_id == num_validators` | `inbound_timeout_verify_rejected_total += 1`, `inbound_timeout_rejected_unknown_validator += 1` | `inbound_timeout_engine_accepted = 0` | none |
| `MalformedNewView` | `NewView(0xff×32)` | `view_timeout_decode_failures += 1`, `inbound_decode_failures += 1` | `inbound_newview_engine_accepted = 0` | none |
| `MissingEvidenceNewView` | TC with empty `signed_timeouts` | `inbound_newview_verify_rejected_total += 1`, `inbound_newview_rejected_missing_evidence += 1` | `inbound_newview_engine_accepted = 0` | none |
| `DuplicateSignerNewView` | V1 listed twice | `inbound_newview_verify_rejected_total += 1`, `inbound_newview_rejected_duplicate_signer += 1` | `inbound_newview_engine_accepted = 0` | none |
| `InsufficientQuorumNewView` | 2 / 4 signers | `inbound_newview_verify_rejected_total += 1`, `inbound_newview_rejected_insufficient_quorum += 1` | `inbound_newview_engine_accepted = 0` | none |
| `MixedViewNewView` | one timeout at `view+7` | `inbound_newview_verify_rejected_total += 1`, `inbound_newview_rejected_mixed_view += 1` | `inbound_newview_engine_accepted = 0` | none |
| `BadSignatureNewView` | one timeout sig flipped | `inbound_newview_verify_rejected_total += 1`, `inbound_newview_rejected_bad_signature += 1` | `inbound_newview_engine_accepted = 0` | none |
| `HighQcMismatchNewView` | TC declares `Some(QC@99)` but evidence's max is `None` | `inbound_newview_verify_rejected_total += 1`, `inbound_newview_rejected_high_qc_mismatch += 1` | `inbound_newview_engine_accepted = 0` | none |

The `run035_all_cases_reject_before_engine_no_view_advance` aggregate
test asserts these properties hold simultaneously for every case in
`ForgedInjectionCase::ALL`.

The `run035_honest_traffic_after_injection_still_verifies` test
proves that after a forged BadSignature TimeoutMsg increments the
`bad_signature` counter, an honest signed TimeoutMsg from the same
validator id is still accepted by `verify_timeout_msg` and reaches
`engine.on_timeout_msg` (`inbound_timeout_verify_accepted = 1`,
`inbound_timeout_engine_accepted = 1`) — the harness does not poison
the per-reason rejection state into a fail-stop.

The `run035_channel_round_trip_delivers_into_inbound_path` async test
proves that pushing through `mpsc::Sender<ConsensusNetMsg>` (the
exact API `ChannelConsensusHandler::sender_clone()` exposes) delivers
into the same `handle_inbound_consensus_msg` path the binary loop
drives.

---

## 9. Log excerpts proving rejection-before-engine

The deterministic tests assert directly against the
`BinaryConsensusLoopInboundStats` fields the binary loop updates. The
runtime path also emits explicit log lines from
`spawn_runtime_injection_task` (no signature bytes, no preimages):

```
[forged-injection] Run 035: runtime activation; cases=["malformed-timeout", …]
                   (env=devnet, QBIND_DEVNET_FORGED_INJECTION=1)
[forged-injection] Run 035: injecting case=malformed-timeout kind=Timeout bytes=32
[forged-injection] Run 035: injecting case=unsigned-timeout    kind=Timeout bytes=…
…
[forged-injection] Run 035: injection complete; harness terminating.
                   Honest traffic continues unaffected.
```

The pre-existing Run 030 log lines emitted from `handle_inbound_consensus_msg`
(`[binary-consensus] Run 030: timeout verify rejected …`,
`[binary-consensus] Run 030: newview verify rejected …`) fire for every
case — these are the same lines Run 030 / Run 034 already validated;
Run 035 adds no new log path on the rejection side.

---

## 10. Proof view did not advance

For every forged case test, the deterministic assertion is
`assert_eq!(before, after)` where `before = engine.current_view()` is
captured pre-injection and `after` is captured post-injection. This
holds for all 12 cases individually and for the aggregate
`run035_all_cases_reject_before_engine_no_view_advance` test (which
runs every case against fresh engine state).

The honest-after-injection test also confirms that the bad-signature
rejection does not block subsequent honest traffic: after the forged
frame's view is unchanged, an honest signed timeout still feeds the
engine.

---

## 11. Proof process remained alive

* No Rust panic, abort, or `process::exit` is triggered by any forged
  case.
* The harness's only error surface is the inbound channel state:
  `ForgedInjectError::Closed` (loop already exited) or
  `Full` (logged and skipped, no metric fabricated).
* The deterministic tests' `Drop` paths run normally; no resource leak.
* The real-binary safety-gate smoke checks all exit cleanly with
  `exit 1` or `exit 0`; no segfaults or dangling subprocesses
  observed.

---

## 12. Honest-traffic-after-injection survival

`run035_honest_traffic_after_injection_still_verifies` (deterministic):
after `BadSignatureTimeout` increments
`inbound_timeout_rejected_bad_signature = 1` and
`inbound_timeout_engine_accepted = 0`, an honest signed `TimeoutMsg`
from the same `ValidatorId(1)` against the same fixture is verified
(`inbound_timeout_verify_accepted = 1`) and accepted by the engine
(`inbound_timeout_engine_accepted = 1`). The bad-signature counter is
NOT bumped a second time. This proves the harness leaves the
verification gate's state machine in exactly the same shape Run 030 /
Run 034 verified.

---

## 13. Remaining open items

* **Real-binary N=4 negative injection under live
  `--require-timeout-verification`.** The dev/test harness, the safety
  gates, and the per-case verification logic are all in place and pass
  on the same `qbind-node` binary the operator will run. Live
  multi-process N=4 forged-traffic injection is the operator's
  immediate-next step (see §15 below); it is not blocked by code
  changes.
* **Production PQC KEMTLS root-key distribution.** Run 035 changes
  nothing about C4 piece (c). B12 `TrustedClientRoots` / `DummySig` is
  still test-grade and is NOT a substitute for production transport
  PKI.
* **Full C4.** Remains OPEN. Run 035 makes no claim about C4 closure.

---

## 14. Verdict — PARTIAL POSITIVE

> **The smallest opt-in real-binary forged Timeout/NewView injection
> harness has landed. It is disabled by default; activation requires
> three concurrent affirmative signals (`--env devnet`,
> `QBIND_DEVNET_FORGED_INJECTION=1`, and at least one
> `--devnet-forged-inject CASE` flag); activation is refused
> fail-closed on Testnet/Mainnet, on missing env var, on unknown case
> tokens, and on non-P2P network modes. Twenty-one deterministic
> tests prove every one of the 12 forged cases is rejected before
> engine ingestion with the precise per-reason rejection counter
> incremented and no view advance, plus that honest signed traffic
> after a forged injection still reaches the engine. The full
> `qbind-node` lib test suite passes 746/746 (= 725 pre-Run-035 + 21
> new). On the real binary, all seven safety-gate negative cases fail
> closed. The deterministic injection path traverses the same
> `handle_inbound_consensus_msg` gate as live P2P inbound traffic.
>
> A full N=4 Required-mode real-binary live forged-injection run
> against four live `qbind-node` processes was not executed in this
> evidence run because the CI sandbox does not provide the namespaces
> Run 034 used for its live multi-process evidence; that step is the
> operator's immediate-next action and is not blocked by code.
>
> Production PQC KEMTLS root-key distribution remains OPEN. Full C4
> remains OPEN. No claim is made that the harness is a substitute for
> a live N=4 negative-injection real-binary run; no claim is made
> that Run 035 closes C4 or any other transport-PKI item.**

---

## 15. Exact immediate next action recommended

Operator, on the same machine that ran Run 034:

1. Build the binary on this commit (or any post-merge commit):
   `cargo build -p qbind-node --bin qbind-node` and capture the new
   sha256/BuildID.
2. Bring up V0/V1A/V2A/V3A under the **identical** Run 034 topology
   (`--p2p-mutual-auth required`, `--execution-profile vm-v0`,
   `--require-timeout-verification`, signer keystores, four
   `--validator-consensus-key VID:100:HEXPK` entries, V0-first
   stagger, metrics endpoints on `127.0.0.1:32000..32003`).
3. **Wait** for `qbind_timeout_verification_active 1` on every node,
   then capture pre-injection `/metrics` snapshots (every Run 034
   counter, every Run 035-relevant counter listed in §8).
4. On V0 only, restart with the additional flags
   `QBIND_DEVNET_FORGED_INJECTION=1 \
    qbind-node … --devnet-forged-inject malformed-timeout
                 --devnet-forged-inject unsigned-timeout
                 --devnet-forged-inject bad-signature-timeout
                 --devnet-forged-inject wrong-suite-timeout
                 --devnet-forged-inject unknown-validator-timeout
                 --devnet-forged-inject malformed-newview
                 --devnet-forged-inject missing-evidence-newview
                 --devnet-forged-inject duplicate-signer-newview
                 --devnet-forged-inject insufficient-quorum-newview
                 --devnet-forged-inject mixed-view-newview
                 --devnet-forged-inject bad-signature-newview
                 --devnet-forged-inject high-qc-mismatch-newview` and
   wait for the harness's `[forged-injection] Run 035: injection
   complete; harness terminating.` line.
5. Capture post-injection `/metrics` on V0; assert the per-reason
   counter deltas in §8 hold and every `inbound_*_engine_accepted_total`
   delta is **0** for the harness's targeted cases (`current_view`
   should NOT have advanced *because of* invalid traffic; honest
   committed_height progression continues independently).
6. Then trigger the same B14 absent-leader recovery Run 034 used
   (SIGINT V1A) and confirm honest verified-timeout traffic still
   advances `current_view` and `committed_height` on V0/V2A/V3A —
   proving the harness did not poison the honest path.
7. Update `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_035.md` with the
   live binary identity and counter-delta tables, and amend
   `docs/whitepaper/contradiction.md` C5 to record the strongest-positive
   result. Keep C5 OPEN until C4 piece (c) (production PQC KEMTLS
   root-key distribution) is solved. Do NOT mark C4 closed.