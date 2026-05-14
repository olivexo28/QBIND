# QBIND DevNet Evidence — Run 074 (long-running local operator-triggered live trust-bundle reload-apply trigger)

**Date**: 2026-05-14
**Status**: ✅ **PARTIAL-POSITIVE LANDED**
**C4 sub-piece**: Operator-triggered live trust-bundle reload-apply ON A RUNNING NODE via SIGHUP, against the live `LivePqcTrustState` (Run 071) + live `TcpKemTlsP2pService` session-evictor (Run 072) + on-disk anti-rollback sequence persistence (Run 055), composed through the Run 073 `ProductionLiveTrustApplyContext` adapter.
**Whitepaper / Doc Reference**: `docs/whitepaper/contradiction.md` C4; `task/RUN_074_TASK.txt`.

---

## 1. Summary

Run 074 closes the previously-deferred long-running-node trigger surface called out in the Run 073 evidence (`A future run that lands a long-running signal handler can call the same adapter on a running node without changing this surface`). Concretely, the `qbind-node` binary now installs — when explicitly armed via two hidden, required-together CLI flags — a SIGHUP signal-handler task that on each delivery:

1. Re-reads the operator-supplied candidate trust-bundle from a **local file** (no peer / no gossip input).
2. Validates the candidate through the SAME Run 069 `validate_candidate_bundle_full` entry point used at startup (parity by construction).
3. Drives the validated candidate through the SAME Run 070 `apply_validated_candidate_with_previous` pipeline, supplying the SAME Run 073 `ProductionLiveTrustApplyContext` against the **running node's live handles**:
   - Run 071 `LivePqcTrustState` shared with every handshake verifier (no second trust set, no parallel networking architecture);
   - Run 072 `TcpKemTlsP2pService` as `Arc<dyn P2pSessionEvictor>` (the truthful Run 072 invariant `attempted = evicted + failed` is preserved end-to-end);
   - Run 055 `check_and_update_sequence` atomic writer on the `--data-dir`-derived sequence file (the same file the startup hook reads/writes).
4. Surfaces a single canonical operator-log line per outcome (`Applied { evicted, new_sequence } | AlreadyInProgress | Invalid(reason) | Fatal(reason)`).
5. Bumps a dedicated Run 074 metric family on `/metrics` (`qbind_p2p_trust_bundle_live_reload_*`).

The node continues running after every outcome **except** `Fatal` (which signals graceful shutdown via the existing `shutdown_tx` watch channel — the only path that touches it).

## 2. Strict scope (what Run 074 IS and is NOT)

### Run 074 IS

- A long-running-node, **operator-triggered** SIGHUP signal-handler task in the production binary (`crates/qbind-node/src/main.rs::spawn_run074_live_reload_task`) that on each SIGHUP invokes:
- A library-level controller (`crates/qbind-node/src/pqc_live_trust_reload.rs::LiveReloadController`) that:
  - Holds `Arc<LivePqcTrustState>` + `Arc<dyn P2pSessionEvictor>` + `Arc<P2pMetrics>` + a clonable `LiveReloadConfig` (environment, chain_id, signing-key set, activation context, sequence-persistence path, optional local-leaf cert bytes);
  - Serializes concurrent triggers via an `Arc<AtomicBool>` "in progress" flag (CAS-only — no blocking; concurrent SIGHUPs while an apply is in flight surface `AlreadyInProgress` and never re-enter the pipeline);
  - On every trigger constructs a **fresh** `ProductionLiveTrustApplyContext` so each apply gets a faithful `now_unix_secs` and a fresh adapter — exactly mirroring the startup hook's per-process construction;
  - Returns a typed `LiveReloadOutcome { Applied(AppliedCandidate) | AlreadyInProgress | Invalid(ReloadApplyError) | Fatal(reason) }` (the `Fatal` arm is *only* reached when `ReloadApplyError::SequenceCommitFailedRollbackAlsoFailed` surfaces — i.e. the live trust state may be ahead of the on-disk sequence record — which the binary handler treats as a graceful-shutdown trigger).
- Two new hidden CLI flags (`--p2p-trust-bundle-live-reload-enabled`, `--p2p-trust-bundle-live-reload-path <PATH>`), required-together, refused without `--p2p-trust-bundle <BASELINE-PATH>` (the running node needs a baseline trust bundle to seed `LivePqcTrustState`).
- Six new `qbind_p2p_trust_bundle_live_reload_*` Prometheus counters / gauge on `P2pMetrics` (truthful; bumped only on real trigger paths; rendered once each on `/metrics`):
  - `qbind_p2p_trust_bundle_live_reload_trigger_total` — increments on every trigger entry (before the guard CAS);
  - `qbind_p2p_trust_bundle_live_reload_apply_success_total` — increments only on `LiveReloadOutcome::Applied`;
  - `qbind_p2p_trust_bundle_live_reload_apply_failure_total` — increments on `Invalid` AND on `Fatal`;
  - `qbind_p2p_trust_bundle_live_reload_already_in_progress_total` — increments only on `AlreadyInProgress`;
  - `qbind_p2p_trust_bundle_live_reload_sessions_evicted_total` — sum of `AppliedCandidate::session_evictions` across successful applies;
  - `qbind_p2p_trust_bundle_live_reload_last_applied_sequence` — gauge set to the last successfully-applied candidate's `sequence` (0 until the first success).
- 5 in-module unit tests + 10 cross-module integration tests in `crates/qbind-node/tests/run_074_pqc_trust_bundle_live_reload_tests.rs` (see § 5).

### Run 074 is **NOT**

- **Peer-supplied / gossiped bundle acceptance.** Local file only. The candidate is read by the same code that reads `--p2p-trust-bundle` at startup. Peer-driven distribution remains a future C4 piece.
- **Filesystem-watcher hot reload.** Operator must explicitly send `SIGHUP` to the running process. The handler does not watch the candidate path for inode changes.
- **Admin-API trigger.** No new HTTP/JSON-RPC surface is added. Only `SIGHUP`.
- **`activation_epoch` runtime sourcing.** The controller's `ActivationContext` is initialized to `height_only(0)` — the same height-only stance the startup `--p2p-trust-bundle` path uses today. A future run that lands a live height source can extend the `LiveReloadConfig` without changing the SIGHUP surface or its tests.
- **KMS / HSM custody, bundle-signing-key ratification, fast-sync restore replay, or per-environment trust-anchor operation.** None of those scope items are landed by Run 074; all remain OPEN under C4.
- **Selective session retention.** The v0 policy is "evict all on a successful apply" — inherited verbatim from Run 072. A future run can refine this without changing the SIGHUP surface.
- **Forced shutdown on non-fatal failures.** Validation refusal, sequence-rollback refusal, session-eviction partial failure, and sequence-commit failure with successful rollback are all **non-fatal** — the node continues running with the prior live trust state and the on-disk sequence record unchanged.

## 3. Code surfaces landed

- `crates/qbind-node/src/pqc_live_trust_reload.rs` *(new, 1100 lines)*:
  - `LiveReloadConfig` (cloneable; carries all per-apply inputs);
  - `LiveReloadController { live, evictor, metrics, config, in_progress: Arc<AtomicBool> }`;
  - `LiveReloadOutcome` with `log_line()`, `is_fatal()`, `is_already_in_progress()`;
  - `try_trigger() / try_trigger_with_now() / try_trigger_with_activation()` — same controller, three explicit entry points (SIGHUP handler uses `try_trigger()`; integration tests use the others for hermetic time/height control);
  - Test-only `__test_in_progress_swap` helper (gated behind `#[doc(hidden)]`; documented as test-only — production code MUST NOT touch it).
- `crates/qbind-node/src/cli.rs`:
  - `--p2p-trust-bundle-live-reload-enabled: bool` (hidden, default `false`);
  - `--p2p-trust-bundle-live-reload-path: Option<PathBuf>` (hidden).
- `crates/qbind-node/src/main.rs`:
  - Top-level CLI-validation block refusing partial-config shapes (path-without-enabled, enabled-without-path) AND refusing `--p2p-trust-bundle-live-reload-enabled` without `--p2p-trust-bundle <BASELINE-PATH>`;
  - In-`run_p2p_node` retention of an extra `Option<LivePqcTrustState>` clone for the SIGHUP task to share the same `Arc<RwLock<...>>` the listener-side handshake verifier reads from;
  - New `#[cfg(unix)] fn spawn_run074_live_reload_task(...)` helper that constructs the `LiveReloadController`, installs the `SignalKind::hangup()` signal, and runs the trigger loop on the existing shutdown watch channel;
  - `#[cfg(not(unix))]` fallback that logs the operator-actionable "trigger not supported on this platform" line and returns `None`.
- `crates/qbind-node/src/metrics.rs`:
  - Six new `live_reload_*` atomic fields on `P2pMetrics`;
  - Six new accessor methods + `format_metrics()` rendering;
  - One new test verifying each name renders exactly once.
- `crates/qbind-node/src/lib.rs`:
  - `pub mod pqc_live_trust_reload;` export.

## 4. Adversary contract (why Run 074 cannot be silently bypassed)

- **Operator confusion is refused at startup.** Supplying only `--p2p-trust-bundle-live-reload-path` without `--p2p-trust-bundle-live-reload-enabled` (or vice versa) exits with `FATAL` before any P2P listener / handshake / consensus loop starts. Verified on the release binary in § 6.
- **The trigger cannot fire without a baseline trust bundle.** `--p2p-trust-bundle-live-reload-enabled` without `--p2p-trust-bundle <BASELINE-PATH>` exits with `FATAL` at the same top-level boundary. There is no implicit fallback to `--p2p-trusted-root` (so an operator cannot bootstrap a live-reload-enabled node from a `--p2p-trusted-root`-only configuration and then sneak a bundle in at runtime).
- **Validation parity with startup is preserved by construction.** Every trigger calls `apply_validated_candidate_with_previous` with the SAME `ReloadCheckInputs` shape the startup hook uses — same signing-key set, same chain_id, same activation context, same sequence path, same local-leaf bytes. The Run 069/070 entry points perform all validation. The adapter has no validation of its own.
- **The atomic sequence writer is the only path that mutates the on-disk record.** A failed apply at any stage (validate / swap / evict / commit) leaves the seq file's bytes AND mtime unchanged (asserted in `run074_validation_rollback_failure_leaves_state_seq_evictor_unchanged`, `run074_validation_tampered_signature_leaves_state_seq_evictor_unchanged`, `run074_session_eviction_partial_failure_rolls_back_live_state`, and `run074_sequence_commit_failure_rolls_back_live_state_and_preserves_seq_file`).
- **Concurrent triggers are serialized in-process.** An `Arc<AtomicBool>` CAS guard rejects every second-or-later trigger as `AlreadyInProgress` for the full duration of an in-flight apply; the rejected trigger does not even enter the validation stage. Verified in `run074_already_in_progress_guard_rejects_concurrent_trigger_without_mutation` against a controller clone (same shared `Arc<AtomicBool>`).
- **The fatal branch is the only path that touches `shutdown_tx`.** Validation refusals, eviction partial failures, sequence-commit failures with successful rollback — none of those send to `shutdown_tx`. Only `SequenceCommitFailedRollbackAlsoFailed` (which means live trust state is potentially ahead of the on-disk record) triggers graceful shutdown so an operator can recover offline. The fatal branch is unreachable in normal operation against the production `swap_snapshot` writer.

## 5. Test evidence

### 5.1 New module unit tests (`pqc_live_trust_reload`)

`cargo test -p qbind-node --lib pqc_live_trust_reload`

```
running 5 tests
test pqc_live_trust_reload::tests::outcome_log_line_marks_each_branch_with_run_074_prefix ... ok
test pqc_live_trust_reload::tests::controller_is_clone_and_shares_in_progress_guard ... ok
test pqc_live_trust_reload::tests::trigger_with_nonexistent_candidate_path_returns_invalid_and_bumps_failure_counter ... ok
test pqc_live_trust_reload::tests::controller_construction_does_not_read_candidate_path ... ok
test pqc_live_trust_reload::tests::always_unsupported_evictor_surfaces_invalid_not_fatal ... ok

test result: ok. 5 passed; 0 failed; 0 ignored; 0 measured; 999 filtered out
```

### 5.2 New integration tests (`run_074_pqc_trust_bundle_live_reload_tests`)

`cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests`

```
running 10 tests
test run074_freshly_constructed_controller_has_no_side_effects ... ok
test run074_happy_path_trigger_swaps_state_evicts_and_commits_with_metrics_bumped ... ok
test run074_metric_family_renders_alongside_run_072_after_apply ... ok
test run074_already_in_progress_guard_rejects_concurrent_trigger_without_mutation ... ok
test run074_reapply_same_candidate_is_idempotent_and_metrics_remain_truthful ... ok
test run074_sequence_commit_failure_rolls_back_live_state_and_preserves_seq_file ... ok
test run074_try_trigger_with_activation_forwards_override_height ... ok
test run074_session_eviction_partial_failure_rolls_back_live_state ... ok
test run074_validation_rollback_failure_leaves_state_seq_evictor_unchanged ... ok
test run074_validation_tampered_signature_leaves_state_seq_evictor_unchanged ... ok

test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 5.3 Full regression suite from `task/RUN_074_TASK.txt`

| Suite | Result |
|---|---|
| `cargo test -p qbind-node --lib pqc_live_trust_apply` | **10 passed** |
| `cargo test -p qbind-node --lib pqc_trust_reload` | **5 passed** |
| `cargo test -p qbind-node --lib pqc_live_trust` | **26 passed** (Run 071 + Run 074 new module surfaced by partial-match) |
| `cargo test -p qbind-node --lib p2p_session_eviction` | **17 passed** |
| `cargo test -p qbind-node --lib pqc_trust_bundle` | **100 passed** |
| `cargo test -p qbind-node --lib pqc_trust_sequence` | **27 passed** |
| `cargo test -p qbind-node --lib pqc_trust_activation` | **34 passed** |
| `cargo test -p qbind-node --lib pqc_live_trust_reload` | **5 passed** *(new)* |
| `cargo test -p qbind-node --lib metrics` | **112 passed** (incl. 2 new Run 074 render-once) |
| `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests` | **12 passed** |
| `cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests` | **13 passed** |
| `cargo test -p qbind-node --test run_071_pqc_live_trust_tests` | **13 passed** |
| `cargo test -p qbind-node --test run_072_p2p_session_eviction_tests` | **8 passed** |
| `cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests` | **10 passed** |
| `cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests` | **10 passed** *(new)* |
| `cargo test -p qbind-node --test run_050_pqc_trust_bundle_tests` | **14 passed** |
| `cargo test -p qbind-node --test run_051_pqc_trust_bundle_signing_tests` | **13 passed** |
| `cargo test -p qbind-node --test run_052_pqc_leaf_revocation_tests` | **12 passed** |
| `cargo test -p qbind-node --test run_055_pqc_trust_bundle_sequence_tests` | **12 passed** |
| `cargo test -p qbind-node --test run_057_pqc_trust_bundle_activation_tests` | **12 passed** |
| `cargo test -p qbind-node --test run_061_pqc_local_leaf_self_check_tests` | **9 passed** |
| `cargo test -p qbind-node --test run_062_pqc_revocation_activation_tests` | **11 passed** |
| `cargo test -p qbind-node --test run_063_pqc_local_issuer_root_self_check_tests` | **8 passed** |
| `cargo test -p qbind-net --test run_052_leaf_revocation_handshake_tests` | **9 passed** |
| `cargo test -p qbind-node --test run_037_pqc_static_root_mutual_auth_tests` | **12 passed** |
| `cargo test -p qbind-node --test run_040_pqc_static_root_real_aead_tests` | **14 passed** |
| `cargo test -p qbind-node --test run_044_pqc_cert_verify_metrics_adapter_tests` | **10 passed** |
| `cargo test -p qbind-node --lib` *(full lib suite)* | **1004 passed** |
| `cargo test -p qbind-net --lib` | **17 passed** |
| `cargo test -p qbind-crypto --lib` | **68 passed** |
| `cargo build --release -p qbind-node --bin qbind-node --example devnet_pqc_trust_bundle_helper --example devnet_pqc_root_helper` | **OK** (release profile, 5 m 09 s) |

No tests were skipped, deleted, weakened, or `#[ignore]`-ed.

## 6. Release-binary smoke evidence

All three CLI top-level partial-config refusals on the **release** binary (`./target/release/qbind-node`):

```
$ ./target/release/qbind-node --p2p-trust-bundle-live-reload-enabled --env devnet
[restore] no --restore-from-snapshot requested; normal startup.
[binary] FATAL: --p2p-trust-bundle-live-reload-enabled requires --p2p-trust-bundle-live-reload-path <PATH> (the trigger needs a candidate path to re-read on each SIGHUP). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md.

$ ./target/release/qbind-node --p2p-trust-bundle-live-reload-path /tmp/x.json --env devnet
[restore] no --restore-from-snapshot requested; normal startup.
[binary] FATAL: --p2p-trust-bundle-live-reload-path requires --p2p-trust-bundle-live-reload-enabled. The Run 074 long-running-node live trust-bundle reload-apply trigger is disabled by default. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md.

$ ./target/release/qbind-node --p2p-trust-bundle-live-reload-enabled --p2p-trust-bundle-live-reload-path /tmp/x.json --env devnet
[restore] no --restore-from-snapshot requested; normal startup.
[binary] FATAL: --p2p-trust-bundle-live-reload-enabled requires --p2p-trust-bundle <BASELINE-PATH> (the long-running-node trigger needs a baseline to seed the live trust handle; no implicit fallback to --p2p-trusted-root is introduced). See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_074.md.
```

Both flags are hidden from `--help` (verified by `./target/release/qbind-node --help | grep -i live-reload` producing no output) — they exist as explicit operator-armed switches only, not as "advertised" surface.

## 7. Whitepaper contradiction narrowing record (C4)

Run 074 narrows C4 (`docs/whitepaper/contradiction.md`) by one piece:

- **NEW LANDED:** Operator-triggered live trust-bundle reload-apply ON A RUNNING NODE via SIGHUP, against real `LivePqcTrustState` + real `TcpKemTlsP2pService` evictor + real atomic sequence persistence, composing through the Run 073 production adapter. Concurrent triggers are serialized in-process. Fatal post-rollback-failure surfaces graceful shutdown. Disabled by default; hidden CLI flags; refused unless paired with `--p2p-trust-bundle <BASELINE-PATH>`.

What remains **OPEN under C4** (unchanged by Run 074):

- Peer-supplied / gossiped bundle acceptance (no `BundleAnnounce` / `BundleRequest` over the wire);
- `activation_epoch` runtime sourcing (the controller is constructed with `ActivationContext::height_only(0)` because the live binary does not currently expose a runtime height source through the apply pipeline);
- KMS / HSM custody for bundle-signing keys;
- Bundle-signing-key ratification ceremony / on-chain anchoring;
- Fast-sync restore replay of `TrustBundleRecord` (the snapshot path does not yet carry the trust-bundle sequence);
- Per-environment trust-anchor operation (root rotation cadence, escrow, key recovery);
- Selective session retention (Run 074 inherits the Run 072 v0 "evict all" policy verbatim);
- Filesystem-watcher hot reload / admin-API trigger surface (Run 074 ships SIGHUP only).

Each remaining piece is small enough to land in a single follow-up run without disturbing the Run 074 SIGHUP / `LiveReloadController` surface.