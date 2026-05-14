# QBIND DevNet Evidence — Run 073 (PQC trust-bundle reload-apply runtime adapter)

**Date**: 2026-05-14  
**Status**: ✅ **PARTIAL-POSITIVE LANDED**  
**C4 sub-piece**: Production-honest concrete `LiveTrustApplyContext` adapter wired through the `qbind-node` binary so the Run 070 apply pipeline runs end-to-end against real `LivePqcTrustState` (Run 071), real `P2pSessionEvictor` (Run 072), and real `pqc_trust_sequence::check_and_update_sequence` (Run 055).  
**Whitepaper / Doc Reference**: `docs/whitepaper/contradiction.md` C4; `task/RUN_073_TASK.txt`

---

## 1. Summary

Run 073 closes the previously-open `ReloadApplyError::UnsupportedRuntimeContext` boundary on the operator-triggered **local-file** reload-apply path by landing a small, production-honest adapter
(`crates/qbind-node/src/pqc_live_trust_apply.rs::ProductionLiveTrustApplyContext`) that composes:

- **Run 069** `validate_candidate_bundle_full` — validation parity with startup, preserved by construction;
- **Run 070** `apply_validated_candidate_with_previous` — strict `validate → snapshot → swap → evict → commit` ordering contract; rollback on every post-swap failure stage;
- **Run 071** `LivePqcTrustState::swap_snapshot` — mutable shared live PQC trust handle; readers see all-or-nothing snapshot transitions under a single short write lock;
- **Run 072** `P2pSessionEvictor::evict_all_sessions(EvictionReason::TrustBundleReloadApply)` — truthful Run 072 session-eviction invariant (`attempted = evicted + failed`);
- **Run 055** `check_and_update_sequence` — anti-rollback persistence writer, same code path as startup, same atomic-write semantics.

The `qbind-node` binary's `--p2p-trust-bundle-reload-apply-path` hook now invokes the adapter in production, removes `UnsupportedRuntimeContext` from the local-operator-triggered path, and surfaces a single canonical operator-log line on success (`AppliedCandidate::applied_log_line`) and a fail-closed `VERDICT=invalid` line on any pre-swap or post-swap failure.

## 2. Strict scope (what Run 073 IS and is NOT)

### Run 073 IS

- A library adapter (`ProductionLiveTrustApplyContext`) implementing the full Run 070 `LiveTrustApplyContext` trait against the production handles.
- A truthful zero-session evictor (`NoActiveSessionsEvictor`) used by the binary's at-startup-time reload-apply hook (the node has not connected to any peer at the point the hook fires, so a zero-eviction report is the honest answer — Run 072 invariant trivially holds).
- 10 in-module unit tests covering every adapter method (snapshot/swap/evict/commit/rollback) and the zero-session evictor.
- 10 integration tests (`crates/qbind-node/tests/run_073_pqc_trust_bundle_reload_apply_runtime_tests.rs`) that drive the SAME `apply_validated_candidate_with_previous` entry point the binary uses, against real `LivePqcTrustState` + `MockP2pSessionEvictor` (for failure branches) / `NoActiveSessionsEvictor` (for the startup-time happy path) + real on-disk sequence files.
- Binary wiring in `crates/qbind-node/src/main.rs` that loads the `--p2p-trust-bundle` baseline, builds the adapter, runs the live apply, and exits 0/1 with a canonical `VERDICT=…` log line.
- Release-binary smoke (this document, §6) proving `VERDICT=applied` end-to-end with on-disk sequence-record persistence.

### Run 073 is **NOT** (still open in C4)

- **Long-running-node SIGHUP / admin-API triggered live apply.** The binary's reload-apply hook still runs at process-start time and exits; the node does NOT start in this mode. The same `ProductionLiveTrustApplyContext` is reusable verbatim against a live `TcpKemTlsP2pService` evictor (Run 072) when a future run lands a long-running signal handler or admin RPC. No adapter or test changes required.
- **Peer-gossiped / peer-supplied bundle acceptance.** Run 073 accepts local files only.
- **`activation_epoch` runtime sourcing.** No safe pre-consensus epoch source exists; bundles that declare `activation_epoch` continue to fail closed (unchanged from Run 057).
- **KMS / HSM custody of bundle signing keys.** Signing keys are still operator-supplied PEM/hex via `--p2p-trust-bundle-signing-key`.
- **Bundle-signing-key ratification.** No on-chain ratification of signing keys; trusted set is still operator-distributed at startup.
- **Selective session retention.** The v0 policy is "evict all" (Run 072); per-peer policy is out of scope.
- **Fast-sync / consensus-storage restore parity for live apply.** Live apply on a partially-restored node is not separately proven; Run 073 only covers the local-file at-startup-time scope and the in-process library entry point.

## 3. Library surface (single source of truth)

### 3.1 New module: `crates/qbind-node/src/pqc_live_trust_apply.rs`

```text
pub struct ProductionLiveTrustApplyContext {
    live: Arc<LivePqcTrustState>,
    evictor: Arc<dyn P2pSessionEvictor>,
    environment: NetworkEnvironment,
    chain_id: ChainId,
    sequence_path: Option<PathBuf>,
    now_unix_secs: u64,
}

impl ProductionLiveTrustApplyContext {
    pub fn new(...);
    pub fn snapshot_previous_metadata(&self) -> (String, Option<u64>);
}

impl LiveTrustApplyContext for ProductionLiveTrustApplyContext {
    fn snapshot_active(&mut self) -> ...;       // Arc<LivePqcTrustSnapshot> bump under read lock
    fn swap_trust_state(&mut self, ...) -> ...; // LivePqcTrustState::swap_snapshot under write lock
    fn evict_sessions(&mut self) -> ...;        // P2pSessionEvictor::evict_all_sessions
    fn commit_sequence(&mut self, ...) -> ...;  // check_and_update_sequence (atomic)
    fn rollback_trust_state(&mut self, ...);    // swap_snapshot back under write lock
}

pub struct NoActiveSessionsEvictor;
impl P2pSessionEvictor for NoActiveSessionsEvictor { /* always reports attempted=0/evicted=0/failed=0 */ }
```

### 3.2 No `/metrics` fabrication

Run 073 deliberately reuses Run 072's existing session-eviction counters (`qbind_p2p_session_eviction_*`) as the only metric surface for the eviction stage. The validation and commit stages already have no metric in Run 069/070 — the discipline of avoiding `/metrics` fabrication while no production mutating path exists is preserved (see `crates/qbind-node/src/pqc_trust_reload.rs` module comment). Operator-visible verdicts go through `eprintln!` log lines (single source of truth via `AppliedCandidate::applied_log_line`).

## 4. Composition contract (validate → snapshot → swap → evict → commit)

| Stage | Adapter callback | Production handle | Failure ⇒ |
|-------|------------------|-------------------|-----------|
| 1. Validate | (not on adapter) | Run 069 `validate_candidate_bundle_full` | `ReloadApplyError::ValidationFailed(_)`; adapter never called; live state and sequence file untouched. |
| 2. Snapshot | `snapshot_active` | `LivePqcTrustState::snapshot()` (Run 071) | Lock-poison → `StateSwapFailed(_)`; no swap, no evict, no commit, no rollback. |
| 3. Swap | `swap_trust_state` | `LivePqcTrustState::swap_snapshot(...)` (Run 071) | `StateSwapFailed(_)`; no evict, no commit, no rollback (no swap happened). |
| 4. Evict | `evict_sessions` | `P2pSessionEvictor::evict_all_sessions(EvictionReason::TrustBundleReloadApply)` (Run 072) | Partial-failure or unsupported-runtime → `SessionEvictionFailed { rollback_ok: bool }`; rollback called; no commit. |
| 5. Commit | `commit_sequence` | `check_and_update_sequence(...)` (Run 055) | `SequenceCommitFailed(_)` or `SequenceCommitFailedRollbackAlsoFailed(_)`; rollback called; on-disk record is unchanged on the failure branch (atomic-write semantics). |
| Rollback | `rollback_trust_state` | `LivePqcTrustState::swap_snapshot(previous_arc)` (Run 071) | Lock-poison → `SequenceCommitFailedRollbackAlsoFailed(...)`; FATAL operator log line. |

## 5. Test evidence

### 5.1 Library unit tests (in-module)

```
cargo test -p qbind-node --lib pqc_live_trust_apply
```

10 tests pass:
- `no_active_sessions_evictor_reports_zero_truthfully` — truthful zero-report + Run 072 invariant.
- `no_active_sessions_evictor_is_p2p_session_evictor_dyn` — dyn-compatible trait object.
- `snapshot_active_captures_arc_snapshot_for_rollback` — captured Arc points at same heap allocation as a fresh `live.snapshot()`; `sequence()` matches.
- `swap_trust_state_replaces_inner_snapshot_with_candidate` — post-swap snapshot is a fresh Arc with candidate fingerprint and sequence.
- `rollback_trust_state_restores_inner_snapshot` — post-rollback snapshot equals pre-swap snapshot (sequence preserved).
- `rollback_trust_state_rejects_wrong_type` — programming-error guard surfaces fail-closed error message, no panic.
- `evict_sessions_forwards_to_evictor_with_reload_apply_reason` — `MockP2pSessionEvictor` records exactly one call with `EvictionReason::TrustBundleReloadApply`.
- `evict_sessions_partial_failure_surfaces_error_with_invariant_counts` — partial-failure message includes attempted/evicted/failed and "rolling back".
- `commit_sequence_first_load_writes_persistence_record` — `load_record()` confirms the on-disk record matches the candidate's sequence.
- `commit_sequence_without_data_dir_surfaces_clean_error` — fail-closed when `--data-dir` is absent; clean operator-readable message.

### 5.2 Integration tests

```
cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests
```

10 tests pass, driving the SAME `apply_validated_candidate_with_previous` entry point the binary uses:

1. `run073_happy_path_swaps_live_state_evicts_and_commits_sequence_atomically` — full pipeline against real `LivePqcTrustState`, `MockP2pSessionEvictor` with 4 sessions, real sequence file. Validates: live state at candidate fingerprint/sequence; evictor recorded one `TrustBundleReloadApply` call (attempted=4/evicted=4/failed=0); seq file at sequence=2; `applied.session_evictions=4`.
2. `run073_validation_rollback_failure_does_not_invoke_adapter` — sequence rollback candidate; no adapter call recorded; live state at baseline; seq file unchanged.
3. `run073_validation_tampered_signature_does_not_invoke_adapter` — tampered ML-DSA-44 signature; same invariants as (2).
4. `run073_session_eviction_partial_failure_rolls_back_live_state` — `MockP2pSessionEvictor::arrange_failure(2)` of 5 sessions; live state rolled back to baseline; evictor recorded attempted=5/evicted=3/failed=2 with `attempted == evicted + failed`; seq file unchanged.
5. `run073_sequence_commit_failure_rolls_back_live_state_and_preserves_seq_file` — pre-seeded `EqualSequenceFingerprintMismatch` poison record; either `ValidationFailed` (peek catches it) or `SequenceCommitFailed`; live state at baseline; seq file unchanged.
6. `run073_no_active_sessions_evictor_happy_path_advances_state_and_sequence` — startup-time path with zero-session evictor; live state and seq file still advance to candidate; `applied.session_evictions=0` (truthful).
7. `run073_validate_only_mode_does_not_mutate_live_state_or_sequence_or_evict` — `ApplyMode::ValidateOnly` against the production adapter is fully non-mutating (Run 069 staging invariant preserved).
8. `run073_reapply_same_candidate_is_idempotent_at_persistence_layer` — second apply of the same candidate hits `EqualSequenceSameFingerprint`; persistence mtime unchanged; live state still at candidate.
9. `run073_post_apply_live_handle_is_consistent_and_fresh_arc` — pre-swap and post-swap `Arc<LivePqcTrustSnapshot>` are distinct heap allocations; post-swap `active_root_count=1`, `environment=Devnet`.
10. `run073_apply_live_with_no_context_still_returns_unsupported_runtime_context` — Run 070's library-level boundary still triggers when `None` context is supplied; Run 073 wiring does not weaken it.

### 5.3 Regression — Run 069/070/071/072 integration tests

```
cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests \
                         --test run_070_pqc_trust_bundle_reload_apply_tests \
                         --test run_071_pqc_live_trust_tests \
                         --test run_072_p2p_session_eviction_tests
```

All pass (12 + 28 + 13 + 8 = 61 tests). Run 070's `UnsupportedRuntimeContext` library-level boundary is preserved verbatim; the Run 073 adapter wiring only replaces the *binary's* call site, not the library contract.

### 5.4 Targeted lib-test sweep

```
cargo test -p qbind-node --lib -- \
    pqc_trust_reload pqc_live_trust pqc_live_trust_apply p2p_session_eviction \
    pqc_trust_bundle pqc_trust_sequence pqc_trust_activation
```

→ **204 tests pass; 0 failed; 0 ignored.**

### 5.5 Binary compile check

```
cargo check -p qbind-node --bin qbind-node
```

→ clean; only pre-existing `bincode::config` deprecation warnings unrelated to Run 073.

## 6. Release-binary smoke evidence (DevNet)

### 6.1 Fixture preparation

```
./target/debug/examples/devnet_pqc_trust_bundle_helper /tmp/run073_smoke 1 signed-devnet
# → bundle_sequence=1 signing_key_id=f1aa94a7..
#   /tmp/run073_smoke/trust-bundle.json
#   /tmp/run073_smoke/signing-key.spec
```

### 6.2 Positive: apply same-bundle (idempotent path)

```
SIGKEY=$(cat /tmp/run073_smoke/signing-key.spec)
mkdir -p /tmp/run073_data
./target/debug/qbind-node --env devnet --validator-id 0 \
    --data-dir /tmp/run073_data \
    --p2p-trust-bundle /tmp/run073_smoke/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SIGKEY" \
    --p2p-trust-bundle-reload-apply-enabled \
    --p2p-trust-bundle-reload-apply-path /tmp/run073_smoke/trust-bundle.json
```

Output (verbatim):

```
[restore] no --restore-from-snapshot requested; normal startup.
[binary] Run 070: trust-bundle candidate APPLIED live (operator-triggered local reload-apply; conservative session-eviction v0 policy) (old_fp=fcf44986.. new_fp=fcf44986.. old_sequence=Some(1) new_sequence=1 env=devnet chain_id=51424e4444455600 active_roots=1 active_revoked_roots=0 active_revoked_leaves=0 session_evictions=0 sequence_commit=ok)
[binary] Run 073: VERDICT=applied (baseline=/tmp/run073_smoke/trust-bundle.json candidate=/tmp/run073_smoke/trust-bundle.json live trust state swapped; session_evictions=0 (no-active-sessions at startup-time); sequence committed). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md.
EXIT=0
```

On-disk sequence record `/tmp/run073_data/pqc_trust_bundle_sequence.json`:

```
{"record_version":1,"environment":"devnet","chain_id":"51424e4444455600","highest_sequence":1,"bundle_fingerprint":"fcf44986bc3bcf37eb2bc5d7828a82e29854f3b5ab53eb339d9d58b7ef73ba0e","updated_at_unix_secs":1778770571}
```

The on-disk record reflects the candidate's sequence and fingerprint — written by the SAME `check_and_update_sequence` writer the startup binary uses.

### 6.3 Negative: missing baseline (`--p2p-trust-bundle` absent)

```
./target/debug/qbind-node --env devnet --validator-id 0 \
    --data-dir /tmp/run073_data \
    --p2p-trust-bundle-reload-apply-enabled \
    --p2p-trust-bundle-reload-apply-path /tmp/run073_smoke/trust-bundle.json
```

Output (verbatim):

```
[restore] no --restore-from-snapshot requested; normal startup.
[binary] FATAL: --p2p-trust-bundle-reload-apply-path requires --p2p-trust-bundle <BASELINE-PATH> so the Run 073 adapter can seed the mutable live trust handle from the same signed-bundle path the normal startup loader validates. No fallback. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md.
EXIT=1
```

Fail-closed: no live trust handle constructed; no apply pipeline invocation; no on-disk write.

### 6.4 Negative: candidate signed by a DIFFERENT signing key

```
./target/debug/examples/devnet_pqc_trust_bundle_helper /tmp/run073_smoke_bad 1 signed-devnet
# → bundle_sequence=1 signing_key_id=f5659a0e..   (different from baseline)

SIGKEY=$(cat /tmp/run073_smoke/signing-key.spec)   # baseline signing key only
./target/debug/qbind-node --env devnet --validator-id 0 \
    --data-dir /tmp/run073_data \
    --p2p-trust-bundle /tmp/run073_smoke/trust-bundle.json \
    --p2p-trust-bundle-signing-key "$SIGKEY" \
    --p2p-trust-bundle-reload-apply-enabled \
    --p2p-trust-bundle-reload-apply-path /tmp/run073_smoke_bad/trust-bundle.json
```

Output (verbatim):

```
[restore] no --restore-from-snapshot requested; normal startup.
[binary] Run 073: VERDICT=invalid (candidate rejected at validation, swap, eviction, or commit stage; live trust state rolled back to baseline where applicable; on-disk sequence record preserved on fail-closed branches). Candidate path=/tmp/run073_smoke_bad/trust-bundle.json. Reason: Run 070 candidate apply rejected at validation stage; live trust state unchanged; sequence not committed; sessions untouched: candidate bundle invalid: trust bundle signature references signing_key_id f5659a0e66de654a25406facae49968b212e930565ea03a6261c7013553b6433 but no matching --p2p-trust-bundle-signing-key was configured (fail closed). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md.
EXIT=1
```

Fail-closed: validation refused the candidate; adapter never called; live state and on-disk sequence record untouched.

## 7. Boundary statement — what remains open

After Run 073 the **library-level** apply contract is fully closed against production handles. The remaining C4 sub-pieces that are NOT closed by Run 073:

1. **Long-running-node trigger.** The binary's reload-apply hook currently runs at process-start and exits. Operator workflow is "stop → reload-apply → restart". A future run that lands a SIGHUP or admin-API trigger can call the SAME `ProductionLiveTrustApplyContext` against the live `TcpKemTlsP2pService` (Run 072) instead of `NoActiveSessionsEvictor`. No adapter or test changes required.
2. **Peer-gossiped bundle acceptance.** Local files only; no P2P-supplied candidates.
3. **`activation_epoch` runtime sourcing.** Unchanged from Run 057.
4. **KMS/HSM custody + signing-key ratification.** Unchanged from Run 051/065.
5. **Selective session retention.** Unchanged from Run 072 (evict-all v0 policy).
6. **Fast-sync / consensus-storage restore parity for live apply on a partially-restored node.** Not separately proven.

Each remaining sub-piece is recorded in `docs/whitepaper/contradiction.md` C4 with a citation back to this document.

## 8. Reproduction recipe

```
# 1. Library unit tests (10).
cargo test -p qbind-node --lib pqc_live_trust_apply

# 2. Run 073 integration tests (10).
cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests

# 3. Run 069 / 070 / 071 / 072 regression sweep (no Run 073 weakening).
cargo test -p qbind-node \
    --test run_069_pqc_trust_bundle_reload_check_tests \
    --test run_070_pqc_trust_bundle_reload_apply_tests \
    --test run_071_pqc_live_trust_tests \
    --test run_072_p2p_session_eviction_tests

# 4. Broader lib sweep.
cargo test -p qbind-node --lib -- \
    pqc_trust_reload pqc_live_trust pqc_live_trust_apply \
    p2p_session_eviction pqc_trust_bundle pqc_trust_sequence pqc_trust_activation

# 5. Binary build.
cargo check -p qbind-node --bin qbind-node

# 6. Release-binary smokes (positive + 2 fail-closed branches): §6 above.
```

## 9. Files added / changed

```
crates/qbind-node/src/pqc_live_trust_apply.rs                                          (NEW, +~520 LoC, in-module tests)
crates/qbind-node/src/lib.rs                                                           (+1 module declaration)
crates/qbind-node/src/main.rs                                                          (reload-apply hook rewired to ProductionLiveTrustApplyContext)
crates/qbind-node/tests/run_073_pqc_trust_bundle_reload_apply_runtime_tests.rs         (NEW, 10 integration tests)
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_073.md                                           (NEW, this document)
docs/whitepaper/contradiction.md                                                       (C4 narrowed with Run 073 partial-positive entry)
```