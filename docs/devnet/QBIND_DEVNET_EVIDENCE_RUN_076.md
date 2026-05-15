# QBIND DevNet Evidence — Run 076 (disabled-by-default peer/gossiped trust-bundle candidate validation boundary)

**Date**: 2026-05-15
**Status**: ✅ **PARTIAL-POSITIVE LANDED** (library-level only; production binary unchanged)
**C4 sub-piece**: Smallest defensible piece of the long-standing "peer-supplied / gossiped bundle acceptance remains C4-OPEN" Run 075 §10 residual — a **library-level, disabled-by-default, validation-only** peer-candidate path that reuses the Run 069 `validate_candidate_bundle_full` pipeline. Peer-driven live apply, peer/gossip propagation, admin-API / filesystem-watcher triggers, and every other peer-supplied surface remain explicitly OPEN.
**Whitepaper / Doc Reference**: `docs/whitepaper/contradiction.md` C4; `task/RUN_076_TASK.txt`.

---

## 1. Summary

Run 076 lands the safest possible foundation under the umbrella "peer-supplied / gossiped bundle acceptance" C4-OPEN sub-piece. Concretely, a new library module `crates/qbind-node/src/pqc_trust_peer_candidate.rs` defines a `PeerCandidateValidator` that:

1. Receives a bounded `PeerCandidateEnvelope` (max 256 KiB; declared length / fingerprint-prefix / chain-id / environment / domain tag / envelope version pre-checks);
2. Validates the candidate through the **same** Run 069 `validate_candidate_bundle_full` entry point used at startup, by the local reload-check, by the Run 073 process-start apply, and by the Run 074 SIGHUP live reload-apply;
3. Returns one of `Disabled | Oversize | RateLimited | DuplicateSuppressed | Validated | Rejected` — **every** outcome is non-mutating for live trust state, on-disk sequence persistence, and P2P / KEMTLS sessions;
4. **Never** applies the candidate. The module exposes no apply function. The validator holds no `LivePqcTrustState`, no `P2pSessionEvictor`, and no mutable sequence-file handle.

The default-constructed validator (`PeerCandidateValidator::disabled()`) returns `Disabled` on every call without touching the payload, performing crypto, or writing any scratch file. No CLI flag and no wire integration are introduced in this run — there is no production caller of the validator on the `qbind-node` binary. This is the strict "no behavior change unless enabled" boundary the task contract requires.

## 2. Strict scope (what Run 076 IS and is NOT)

### Run 076 IS

- A **library-level** validation surface for peer-supplied trust-bundle candidate bytes (`crates/qbind-node/src/pqc_trust_peer_candidate.rs`).
- A reuse-only path: every signature / structural / sequence / activation / revocation / chain-id / environment / self-check verdict is delegated to the existing Run 069 `validate_candidate_bundle_full`.
- A **non-mutation** boundary on every return path:
  - `LivePqcTrustState` is untouched (the validator holds no handle);
  - the on-disk sequence record is untouched (Run 055 `peek_sequence` is read-only);
  - no P2P / KEMTLS session is evicted (the validator holds no `P2pSessionEvictor`);
  - no peer broadcast / propagation happens (the validator is end-of-line);
  - the staged temp file is unlinked before `try_accept` returns.
- A **disabled-by-default** surface: `PeerCandidateConfig::enabled = false` is the default, and `PeerCandidateValidator::disabled()` returns `Disabled` without touching the payload.
- An **adversary-bounded** surface:
  - `MAX_PEER_CANDIDATE_BUNDLE_BYTES = 256 KiB` drops oversized payloads BEFORE any ML-DSA work;
  - `PeerCandidateRateLimiter` (fixed-window, no background timer) bounds the rate of expensive crypto;
  - `PeerCandidateDuplicateCache` (bounded LRU by 8-hex-char fingerprint prefix) prevents repeated expensive verification of identical bytes;
  - declared-length-vs-payload mismatch / declared-fingerprint-prefix mismatch / declared-sequence mismatch / unknown-domain-tag / unknown-envelope-version / wrong-environment / wrong-chain-id-hex / empty-payload are all rejected at the envelope layer BEFORE crypto.
- Seven new `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters on `P2pMetrics` (one per outcome variant plus the unconditional `received_total`). **There is no `_applied_total` family** — the validator never applies.
- Two new metrics unit tests (`peer_candidate_metrics_start_at_zero_and_record_outcomes_atomically`, `peer_candidate_metrics_render_once_in_format_metrics`).
- 16 new module unit tests + 16 new integration tests (`crates/qbind-node/tests/run_076_pqc_peer_candidate_validation_tests.rs`).

### Run 076 IS NOT

- **NOT** a peer-driven live apply path. The validator has no apply function; the live trust state is unreachable from this module.
- **NOT** a peer/gossip propagation surface. The validator does not re-broadcast; the candidate is end-of-line.
- **NOT** an admin-API trigger or a filesystem-watcher hot-reload trigger. Run 074's SIGHUP-only trigger surface is unchanged.
- **NOT** a CLI / wire change to the `qbind-node` binary. No new flag, no new network listener, no new gossip subscription, and no production caller of the validator. The strict "no behavior change unless enabled" boundary is enforced both by `enabled = false` AND by the absence of any production caller.
- **NOT** a change to startup trust-bundle validation, Run 069 reload-check, Run 070 apply contract, Run 071 `LivePqcTrustState`, Run 072 session-evictor, Run 073 `ProductionLiveTrustApplyContext`, or Run 074 `LiveReloadController` — all six are bit-for-bit unchanged.
- **NOT** `activation_epoch` runtime sourcing (still fails closed via the inherited loader).
- **NOT** KMS / HSM custody.
- **NOT** bundle-signing-key on-chain / in-binary ratification.
- **NOT** fast-sync / consensus-storage restore parity.
- **NOT** selective per-peer session retention.
- **NOT** the N-node MainNet release-binary peer-connection smoke.

## 3. Reused Run 069 entry point (no fork of validation logic)

`PeerCandidateValidator::try_accept` calls the same `crate::pqc_trust_reload::validate_candidate_bundle_full` that:

- startup uses (`TrustBundle::load_from_path_with_signing_keys_chain_id_and_activation` + Run 055 `check_and_update_sequence`);
- the Run 069 reload-check uses (validation-only via `validate_candidate_bundle`);
- the Run 070 apply contract uses (`apply_validated_candidate{,_with_previous}` calls it as the first stage);
- the Run 073 process-start apply uses (via `ProductionLiveTrustApplyContext`);
- the Run 074 SIGHUP live reload-apply uses (via `LiveReloadController::try_trigger*`).

This means any future hardening of the validation pipeline automatically applies to Run 076. No new structural / signature / sequence / activation / revocation logic is introduced.

## 4. Tests run

All commands run from repo root.

### 4.1 Module unit tests — 16/16 pass

```
cargo test -p qbind-node --lib pqc_trust_peer_candidate
```

Output (verbatim, tail):

```
running 16 tests
test pqc_trust_peer_candidate::tests::run076_config_default_is_disabled_by_default ... ok
test pqc_trust_peer_candidate::tests::run076_disabled_by_default ... ok
test pqc_trust_peer_candidate::tests::run076_duplicate_cache_capacity_at_least_one ... ok
test pqc_trust_peer_candidate::tests::run076_duplicate_cache_lru_evicts_oldest ... ok
test pqc_trust_peer_candidate::tests::run076_envelope_pre_check_rejects_unknown_version ... ok
test pqc_trust_peer_candidate::tests::run076_envelope_error_display_marks_pre_crypto_rejection_safely ... ok
test pqc_trust_peer_candidate::tests::run076_envelope_pre_check_rejects_declared_length_mismatch ... ok
test pqc_trust_peer_candidate::tests::run076_envelope_pre_check_rejects_wrong_chain_id ... ok
test pqc_trust_peer_candidate::tests::run076_envelope_pre_check_rejects_wrong_domain_tag ... ok
test pqc_trust_peer_candidate::tests::run076_envelope_pre_check_rejects_wrong_env ... ok
test pqc_trust_peer_candidate::tests::run076_is_lower_hex_strict ... ok
test pqc_trust_peer_candidate::tests::run076_max_size_is_bounded_and_drops_before_crypto ... ok
test pqc_trust_peer_candidate::tests::run076_outcome_helpers ... ok
test pqc_trust_peer_candidate::tests::run076_rate_limiter_admits_up_to_cap_then_blocks ... ok
test pqc_trust_peer_candidate::tests::run076_rate_limiter_zero_cap_always_blocks ... ok
test pqc_trust_peer_candidate::tests::run076_validated_log_line_marks_not_applied ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 1004 filtered out
```

### 4.2 Integration tests — 16/16 pass

```
cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests
```

Output (verbatim, tail):

```
running 16 tests
test run076_disabled_by_default_is_noop ... ok
test run076_declared_length_payload_mismatch_rejected ... ok
test run076_declared_sequence_mismatch_after_loader ... ok
test run076_declared_fingerprint_prefix_mismatch_after_loader ... ok
test run076_duplicate_suppression_skips_second_crypto ... ok
test run076_does_not_affect_run069_reload_check_path ... ok
test run076_oversize_candidate_dropped_pre_crypto_no_scratch ... ok
test run076_local_issuer_root_revoked_candidate_rejected ... ok
test run076_equal_sequence_different_fingerprint_rejected ... ok
test run076_local_revoked_leaf_candidate_rejected ... ok
test run076_tampered_signature_candidate_rejected_at_loader ... ok
test run076_rollback_candidate_rejected_by_read_only_peek ... ok
test run076_rate_limit_blocks_after_cap ... ok
test run076_wrong_environment_envelope_rejected_pre_crypto ... ok
test run076_valid_higher_sequence_candidate_validates_but_not_applied ... ok
test run076_wrong_chain_id_envelope_rejected_pre_crypto ... ok

test result: ok. 16 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 4.3 Metrics regression — 114/114 pass (includes the two new Run 076 metric tests)

```
cargo test -p qbind-node --lib metrics
```

```
test result: ok. 114 passed; 0 failed; 0 ignored; 0 measured; 908 filtered out
```

### 4.4 Run 069 reload-check regression — 12/12 pass

```
cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests
```

```
test result: ok. 12 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 4.5 Run 074 SIGHUP live-reload regression — 10/10 pass

```
cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests
```

```
test result: ok. 10 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### 4.6 No release-binary smoke recorded

Run 076 introduces NO production binary surface (no CLI flag, no wire path), so no release-binary smoke is applicable. The disabled-by-default validator is exercised end-to-end only by the test harness; the production binary's startup, reload-check, process-start apply, and SIGHUP live-reload paths are bit-for-bit unchanged.

## 5. Coverage matrix (per `task/RUN_076_TASK.txt`)

| # | Boundary | Test |
|---|---|---|
| 1 | Disabled-by-default → `Disabled` outcome; no scratch file written | `run076_disabled_by_default_is_noop`, `run076_disabled_by_default` |
| 2 | Valid candidate validates but is NOT applied; sequence file unchanged on success | `run076_valid_higher_sequence_candidate_validates_but_not_applied` |
| 3 | Tampered signature rejected at loader stage | `run076_tampered_signature_candidate_rejected_at_loader` |
| 4 | Wrong environment rejected BEFORE crypto | `run076_wrong_environment_envelope_rejected_pre_crypto`, `run076_envelope_pre_check_rejects_wrong_env` |
| 5 | Wrong chain id rejected BEFORE crypto | `run076_wrong_chain_id_envelope_rejected_pre_crypto`, `run076_envelope_pre_check_rejects_wrong_chain_id` |
| 6 | Rollback candidate rejected by read-only Run 055 peek | `run076_rollback_candidate_rejected_by_read_only_peek` |
| 7 | Equal-sequence different-fingerprint rejected as equivocation | `run076_equal_sequence_different_fingerprint_rejected` |
| 8 | Local revoked-leaf rejected via Run 061 self-check | `run076_local_revoked_leaf_candidate_rejected` |
| 9 | Local issuer-root revoked rejected via Run 063 self-check | `run076_local_issuer_root_revoked_candidate_rejected` |
| 10 | Oversize candidate dropped BEFORE crypto, no scratch file | `run076_oversize_candidate_dropped_pre_crypto_no_scratch`, `run076_max_size_is_bounded_and_drops_before_crypto` |
| 11 | Declared-length-vs-payload mismatch rejected at envelope | `run076_declared_length_payload_mismatch_rejected`, `run076_envelope_pre_check_rejects_declared_length_mismatch` |
| 12 | Declared-fingerprint-prefix mismatch rejected AFTER loader cross-check | `run076_declared_fingerprint_prefix_mismatch_after_loader` |
| 13 | Declared-sequence mismatch rejected AFTER loader cross-check | `run076_declared_sequence_mismatch_after_loader` |
| 14 | Duplicate-fingerprint suppression skips second crypto | `run076_duplicate_suppression_skips_second_crypto`, `run076_duplicate_cache_lru_evicts_oldest` |
| 15 | Rate limit blocks after `max_in_window` | `run076_rate_limit_blocks_after_cap`, `run076_rate_limiter_admits_up_to_cap_then_blocks` |
| 16 | Run 069 reload-check unaffected by Run 076 | `run076_does_not_affect_run069_reload_check_path` |
| 17 | Validated log-line marks "NOT applied / not propagated / sequence not persisted / live trust state unchanged / sessions untouched" | `run076_validated_log_line_marks_not_applied` |
| 18 | Metrics render once each; no `_applied_total` family | `peer_candidate_metrics_render_once_in_format_metrics` |
| 19 | Metrics atomic per-outcome bookkeeping; Run 074 apply counters untouched | `peer_candidate_metrics_start_at_zero_and_record_outcomes_atomically` |

## 6. Run 040 banner

Run 076 does not boot the binary, so a runtime Run 040 banner is not emitted. The Run 040 invariant is preserved transitively: every existing run's banner discipline (`dummy_kem_registered=false dummy_aead_registered=false`) is unchanged because Run 076 is library-only and the binary's startup banner code path is bit-for-bit unchanged.

## 7. Files changed

```
crates/qbind-node/src/lib.rs                                              # +13 lines: pub mod pqc_trust_peer_candidate + doc block
crates/qbind-node/src/pqc_trust_peer_candidate.rs                         # NEW module (validator + envelope + cache + rate-limiter + 16 unit tests)
crates/qbind-node/src/metrics.rs                                          # +Run 076 metric fields, accessors, recorders, format_metrics block, 2 unit tests
crates/qbind-node/tests/run_076_pqc_peer_candidate_validation_tests.rs    # NEW integration test (16 tests)
docs/whitepaper/contradiction.md                                          # +Run 076 narrowing block
docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_076.md                              # NEW (this file)
```

No `Cargo.toml` change. No new dependency. No production binary surface change.

## 8. Open items / what is NOT closed by Run 076

Full C4 still OPEN on, and explicitly NOT closed by, Run 076:

- **Peer-driven live apply.** Run 076 deliberately stops at validation — no apply path even exists on the validator. A future run would need to compose the validated `PeerCandidate` with the Run 070 `LiveTrustApplyContext` *under a separate review* and would need to handle the security-critical question of *which peers are authorized to trigger a live apply* (the validator alone cannot answer that).
- **Peer/gossip propagation.** Run 076 is end-of-line; no re-broadcast surface is introduced. A future run would need a gossip path with its own equivocation / rate / authority semantics.
- **Admin-API / filesystem-watcher hot-reload triggers.** Run 074's SIGHUP-only trigger surface is unchanged.
- **Production binary wire integration.** No CLI flag is introduced; the binary does not call the validator. A future run that lands a peer-supplied wire envelope would land its own CLI flag, its own top-level partial-config refusal, and its own release-binary smokes.
- `activation_epoch` runtime sourcing; KMS / HSM custody; on-chain signing-key ratification; fast-sync restore parity; per-environment trust-anchor operation; selective per-peer session retention; the N-node MainNet release-binary peer-connection smoke — all remain OPEN exactly as recorded by Runs 074/075.

## 9. Verdict

✅ **PARTIAL-POSITIVE LANDED**

- 16/16 module unit tests pass.
- 16/16 integration tests pass.
- 114/114 metrics lib tests pass.
- 12/12 Run 069 integration tests pass (unaffected).
- 10/10 Run 074 integration tests pass (unaffected).
- No new dependency, no production binary surface change, no `_applied_total` family.
- The smallest defensible piece of the peer-supplied / gossiped bundle acceptance C4-OPEN sub-piece is closed: peer-supplied bundle bytes can now be **parsed and validated** through the same Run 069 pipeline as every other trust-bundle entry point in the system, with strict adversary bounds, while live trust state, sequence persistence, and P2P sessions remain provably unchanged on every return path.