# QBIND DevNet Evidence — Run 142

**Subject**: Source/test wiring of v2 ratification + v2 authority-marker
validation into the **live inbound P2P peer-candidate `0x05`
validation-only receive path**, using the existing Run 130 v2 verifier
and the Run 132 `verify_marker_for_validation_only_v2` helper that the
local peer-candidate-check binary surface already exercises.

## Scope notice (mandatory per `task/RUN_142_TASK.txt`)

* **Run 142 is source/test wiring only.**
* **Live inbound `0x05` v2 validation-only support is now
  source/test covered** by the 16 new tests in
  `crates/qbind-node/tests/run_142_live_inbound_0x05_v2_validation_tests.rs`
  (all passing).
* **Release-binary live inbound `0x05` v2 evidence remains open for
  Run 143.**
* Peer-driven live trust-bundle apply **remains open**.
* Signing-key rotation/revocation lifecycle **remains open**.
* KMS / HSM authority-key custody **remains open**.
* MainNet governance attestation track **remains open**.
* Full C4 acceptance **remains open**.
* C5 acceptance **remains open**.

## What landed in Run 142

`task/RUN_142_TASK.txt` §§1–5 — implemented in:

* `crates/qbind-node/src/pqc_peer_candidate_wire.rs`
  * Added the optional `ratification_v2: Option<BundleSigningRatificationV2>`
    field to `LiveRatificationConfig`, mirroring the existing v1
    `ratification: Option<BundleSigningRatification>` slot. At most one
    of the two is `Some` in normal operation (the versioned sidecar
    loader at `pqc_ratification_input::load_versioned_ratification_from_path`
    dispatches to exactly one variant).
  * Inside `LivePeerCandidateWireDispatcher::dispatch_frame_from_peer_for_test`:
    * **Ambiguous v1+v2 fail-closed.** If the installed
      `LiveRatificationConfig` carries both `ratification` (v1) and
      `ratification_v2` (v2) and the Run 106 gate decision says invoke,
      the dispatcher rejects the frame **before** the inner validator
      runs, emits the `[run-142] live 0x05 v2 dispatch refused:
      ambiguous v1+v2 authority material` log, and runs the existing
      `maybe_propagate_after_validation` step — which suppresses
      rebroadcast because the outcome is `Rejected`. No marker write,
      no sequence write, no trust mutation, no session eviction.
    * **v2-only dispatch.** When `ratification_v2.is_some()` and v1 is
      `None`, the dispatcher bypasses the Run 109 v1
      `try_handle_frame_with_ratification` path (the v1 enforcer
      cannot consume a v2 sidecar) and runs the inner unguarded
      validator via `try_handle_frame`. Every Run 069 / Run 076
      structural / signing / sequence check still fires.
    * **v1-only dispatch.** Pre-Run-142 behaviour preserved verbatim.
    * After inner validation, the new
      `LivePeerCandidateWireDispatcher::maybe_reject_on_v2_marker_conflict`
      helper:
      1. Returns unchanged when the outcome is not `Validated`.
      2. Returns unchanged when no v2 ratification context is
         installed (v1 path / legacy path takes over).
      3. Runs the **Run 130** verifier
         (`qbind_ledger::verify_bundle_signing_key_ratification_v2`)
         against the operator's owned v2 sidecar. Any failure maps
         to `ValidationOnlyMarkerV2Error::V2VerifierFailure` and is
         rendered as `Rejected(ValidationFailed(MarkerConflict(...)))`
         so the downstream propagation gate suppresses rebroadcast
         automatically.
      4. If a `--data-dir`-derived `authority_marker_path` is
         configured, runs the **Run 132**
         `verify_marker_for_validation_only_v2` helper against the
         on-disk versioned marker. Wrong-domain, lower-sequence,
         same-sequence-different-digest, v1-after-v2 downgrade,
         corrupt-marker, and unsupported-marker-version conditions
         all map to the same `Rejected(MarkerConflict)` shape.
  * Wired the new helper **before** the existing Run 123 v1 marker
    check; the v1 check no-ops automatically when `ratification`
    (v1) is `None`, so the two surfaces are mutually exclusive
    per-frame.
  * `maybe_reject_on_v2_marker_conflict` performs zero disk writes
    (read-only `load_authority_state_versioned` only), zero
    `LivePqcTrustState` swaps, zero session evictions, zero
    sequence-file writes, zero reload-apply calls.

* `crates/qbind-node/src/main.rs`
  * Extended the `LiveRatificationConfig` construction in
    `run_p2p_node` (the live `0x05` dispatcher installation) to
    plumb `ctx_data.ratification_v2` (the Run 132 v2 sidecar field
    on `Run105ReloadCheckContextData`) into the new
    `LiveRatificationConfig::ratification_v2` slot. No new CLI
    flag; no new policy decision; the existing Run 106 gate already
    governs whether the v2 path runs.

* `crates/qbind-node/tests/run_142_live_inbound_0x05_v2_validation_tests.rs`
  * **16 new tests** covering the full A1–A4 + R1–R11 matrix from
    `task/RUN_142_TASK.txt`, plus an explicit local
    peer-candidate-check parity test that proves the
    `verify_marker_for_validation_only_v2` outcome matches the
    live `0x05` dispatcher outcome on identical fixtures.

* `crates/qbind-node/tests/run_109_pqc_peer_candidate_wire_live_ratification_tests.rs`
  * Existing test harness updated for the new
    `LiveRatificationConfig::ratification_v2` field (explicit
    `None` in the v1 helper to keep existing scenarios exercising
    the v1 path).

## What did NOT change in Run 142

* No new CLI flag (the existing operator-supplied
  `--p2p-trust-bundle-ratification` already accepts both v1 and v2
  sidecars via the versioned loader; the live `0x05` dispatcher
  consumes whichever variant the operator supplied).
* No metric family change (the existing
  `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters cover
  versioned outcomes; rejections from the v2 path increment the
  same `_rejected_total` counter the v1 path uses).
* No `LivePqcTrustState` swap on any v2 `0x05` validation path.
* No `pqc_trust_bundle_sequence.json` write.
* No `pqc_authority_state.json` write.
* No session eviction.
* No SIGHUP live-reload coupling.
* No fallback to `--p2p-trusted-root`.
* No peer-candidate wire-format change (the `0x05` envelope already
  carries a versioned payload; only dispatcher-side routing logic
  was added).
* No trust-bundle schema change.
* No ratification sidecar schema change.
* No v1 live inbound `0x05` regression — the existing Run 109/123
  v1 path is preserved bit-for-bit; the
  `run142_r9_v1_live_inbound_regression_unchanged` test pins this.

## Validation matrix

The new test file
`crates/qbind-node/tests/run_142_live_inbound_0x05_v2_validation_tests.rs`
covers:

| Test | Scenario |
|---|---|
| `run142_a1_valid_v2_candidate_accepted_validation_only` | Valid v2 candidate, no persisted marker; accepted; no mutation. |
| `run142_a2_idempotent_v2_marker_accepted_no_rewrite` | Pre-persisted v2 marker matches candidate; accepted; marker bytes unchanged. |
| `run142_a3_higher_sequence_v2_accepted_no_persist` | Persisted v2 seq=3, candidate seq=4; accepted; no persistence. |
| `run142_a4_v2_after_v1_migration_candidate_accepted` | Persisted v1 marker, v2 candidate at higher seq; accepted; v1 marker preserved. |
| `run142_r1_lower_sequence_v2_rejected` | Persisted v2 seq=5, candidate seq=2; rejected; no mutation; no propagation. |
| `run142_r2_same_sequence_different_digest_v2_rejected` | Equivocation rejection; no mutation; no propagation. |
| `run142_r3_bad_signature_v2_rejected` | Run 130 verifier failure mapped to `MarkerConflict`; no mutation. |
| `run142_r4_wrong_environment_v2_rejected` | Wrong-domain rejection; no mutation. |
| `run142_r5_wrong_chain_v2_rejected` | Wrong-domain rejection; no mutation. |
| `run142_r6_wrong_genesis_v2_rejected` | Wrong-domain rejection; no mutation. |
| `run142_r7_ambiguous_v1_plus_v2_fail_closed` | Both v1+v2 installed → fail-closed before validator runs; no mutation; no propagation. |
| `run142_r8_corrupted_local_marker_fail_closed` | Corrupt JSON on disk; fail-closed; bytes preserved. |
| `run142_r9_v1_live_inbound_regression_unchanged` | v1 sidecar still takes the Run 109 v1 path. |
| `run142_r10_no_sidecar_legacy_live_inbound_regression_unchanged` | DevNet without opt-in: unguarded legacy path unchanged. |
| `run142_r11_propagation_only_v2_interaction` | Three sub-cases: propagation disabled, propagation enabled with valid v2, propagation enabled with invalid v2. |
| `run142_local_peer_candidate_check_parity_accepts_and_rejects_match` | Same fixture accepted/rejected by both the local Run 132 surface and the live `0x05` dispatcher. |

Every test asserts the Run 142 negative invariants:

* `pqc_trust_bundle_sequence.json` absent or byte-identical pre/post.
* `pqc_authority_state.json` absent or byte-identical pre/post.
* No `LivePqcTrustState` swap (no apply pipeline exists on this surface).
* No session eviction.
* No reload-apply outcome.
* No SIGHUP outcome.
* No fallback to `--p2p-trusted-root`.

## Validation commands

```
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test -p qbind-node --test run_109_pqc_peer_candidate_wire_live_ratification_tests
cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests
cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests
cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test -p qbind-node --lib pqc_authority
```

All targeted tests pass on the Run 142 branch. The exact Run 132
validation-only target name from the task list
(`run_132_v2_validation_only_tests`) does not exist as a separate
integration test in this tree — the Run 132 v2 validation-only surface
is covered by the inline module tests under
`crates/qbind-node/src/pqc_authority_marker_acceptance.rs::tests::v2_validation_only`,
which are exercised by `cargo test -p qbind-node --lib pqc_authority`.

## Acceptance criteria (Run 142)

1. Live inbound `0x05` v2 candidates are validated with the same Run 130
   verifier + Run 132 marker-compare discipline as the local
   peer-candidate-check surface. ✅
2. Valid v2 candidates are accepted validation-only. ✅
3. Invalid v2 candidates are rejected fail-closed. ✅
4. No live trust mutation, sequence write, marker write, or session
   eviction occurs on any v2 `0x05` validation path. ✅
5. v1 and legacy `0x05` behaviour remains unchanged. ✅
6. Propagation-only behaviour, when touched, remains
   validation-before-rebroadcast and non-applying. ✅
7. No CLI / wire / schema / metric drift. ✅
8. Release-binary `0x05` v2 evidence is deferred to Run 143. ✅
9. `docs/whitepaper/contradiction.md` is updated. ✅
10. No full C4 or C5 closure is claimed. ✅
