# QBIND DevNet Evidence — Run 077 (production-binary-facing, disabled-by-default peer-candidate validation local check mode)

**Date**: 2026-05-15
**Status**: ✅ **PARTIAL-POSITIVE LANDED** (binary surface exists; node is **not** started; **no** live trust apply; **no** sequence persistence write; **no** peer/network wire surface introduced)
**C4 sub-piece**: Smallest defensible piece under the long-standing "peer-supplied / gossiped bundle acceptance remains C4-OPEN" umbrella — a **production-binary-facing, disabled-by-default, validation-only** `qbind-node` CLI surface that exercises the Run 076 `PeerCandidateValidator` (which itself reuses the Run 069 `validate_candidate_bundle_full` pipeline). Peer-driven live apply, peer/gossip propagation, admin-API / filesystem-watcher triggers, and every other peer-supplied wire surface remain explicitly OPEN.
**Whitepaper / Doc Reference**: `docs/whitepaper/contradiction.md` C4; `task/RUN_077_TASK.txt`; `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_076.md`.

---

## 1. Summary

Run 076 landed the smallest defensible **library-level** peer-candidate validation surface and explicitly deferred the production binary surface to a future run. Run 077 closes that smallest defensible **binary** sub-piece, **without** introducing any peer/gossip wire surface, network listener, admin-API endpoint, or filesystem watcher, and **without** allowing a peer-supplied candidate to apply, propagate, or persist.

Concretely, two hidden required-together CLI flags now wire the Run 076 validator into the `qbind-node` release binary:

- `--p2p-trust-bundle-peer-candidate-validation-enabled` (bool, hidden, disabled by default)
- `--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>` (path, hidden)

When **both** flags are supplied, the binary:

1. Reads the local JSON `PeerCandidateEnvelope` fixture from `<ENVELOPE_PATH>`;
2. Constructs a `PeerCandidateValidator` with `enabled = true` for a single shot;
3. Calls the **same** Run 076 `try_accept` (which routes through the **same** Run 069 `validate_candidate_bundle_full`) against the parsed envelope;
4. Bumps the **same** seven Run 076 `qbind_p2p_pqc_trust_bundle_peer_candidate_*` Prometheus counters (no new metric family; no `_applied_total` family — none exists by design);
5. Prints the canonical `[binary] Run 077: VERDICT=... (NOT applied; not propagated; sequence not persisted; live trust state unchanged; sessions untouched) ...` operator-log line;
6. Exits — `0` only when the outcome is `Validated`; `1` on every fail-closed outcome (`Disabled` / `Oversize` / `RateLimited` / `DuplicateSuppressed` / `Rejected`) and on every partial-config / I/O / parse refusal.

The node does **not** start. No `LivePqcTrustState` is constructed. No `P2pSessionEvictor` is constructed. No `LiveReloadController` is spawned. No KEMTLS listener is bound. The on-disk anti-rollback sequence record (when `--data-dir` is supplied) is **never** modified — it is only consulted via the read-only Run 055 `peek_sequence` inherited from Run 069. The default value (`PeerCandidateValidator::disabled()`) of the Run 076 library is preserved for every other code path: the only place that flips `enabled = true` is the single-shot binary check helper, gated on the operator having explicitly armed both flags.

## 2. Strict scope (what Run 077 IS and is NOT)

### Run 077 IS

- A **production-binary-facing** validation surface for a **local** operator-supplied JSON envelope fixture. The fixture format is `serde_json::to_vec(&PeerCandidateEnvelope)` with `bundle_bytes` encoded as lowercase hex (Run 077 adds `serde::Serialize` / `serde::Deserialize` derives + a hex codec on the existing Run 076 envelope type).
- A reuse-only path:
  - `PeerCandidateValidator::try_accept` is Run 076's, bit-for-bit unchanged;
  - the inner pipeline is Run 069's `validate_candidate_bundle_full`, bit-for-bit unchanged;
  - the seven Prometheus counters are Run 076's, bit-for-bit unchanged;
  - the operator-log "not applied / not propagated / sequence not persisted / live trust state unchanged / sessions untouched" disclaimer is taken from Run 076's `ValidatedPeerCandidate::observed_log_line()` (single source of truth, reused).
- A **non-mutation** boundary on every return path (proven by integration tests below):
  - the on-disk sequence record under `--data-dir` is never modified;
  - no `LivePqcTrustState` is allocated or swapped;
  - no P2P / KEMTLS session is allocated, created, or evicted;
  - no peer broadcast / propagation happens;
  - the validator's staged temp file is unlinked before the binary exits.
- A **disabled-by-default** surface:
  - default behavior of the binary is unchanged for **every** existing CLI invocation that does not pass at least one of the two Run 077 flags;
  - typing only one of the two flags is a top-level partial-config refusal (`exit 1`) — exactly mirroring the Run 070 / Run 074 partial-config discipline.
- A **fail-closed** surface, reusing the Run 069 preconditions verbatim:
  - TestNet / MainNet require at least one `--p2p-trust-bundle-signing-key`;
  - TestNet / MainNet require `--data-dir` (so the candidate's sequence can be peeked against the persisted record);
  - `--p2p-leaf-cert` and `--p2p-leaf-cert-key` must be supplied together for the Run 061 / Run 063 self-checks;
  - no implicit fallback to `--p2p-trusted-root`;
  - no `DummySig` / `DummyKem` / `DummyAead` reactivation.
- An **operator-honest** metric surface:
  - the same seven existing `qbind_p2p_pqc_trust_bundle_peer_candidate_*` counters are bumped according to the outcome;
  - the `received_total` counter is bumped unconditionally on every successful envelope-fixture parse (truthful "we observed a candidate" signal);
  - the binary exits before `metrics::serve_metrics_http` is called, matching the Run 069 / Run 073 process-start hooks' discipline — these counters are not published over HTTP during Run 077, but the recording path is identical to the eventual wire-integration path.

### Run 077 is NOT

- **Not** peer-driven live apply. The validator type holds no live-state handle; there is no apply function to call.
- **Not** gossip propagation. The validator never re-broadcasts; the candidate is end-of-line.
- **Not** a peer / network wire surface. Run 077 introduces no new listener, no new dialer, no new gossip subscription, no new admin-API endpoint, and no filesystem watcher.
- **Not** an in-running-node hot reload. Run 074's SIGHUP trigger is unchanged; Run 077 adds no new long-running trigger surface. Run 077 exits before the node is constructed.
- **Not** a change to startup trust-bundle validation, Run 069 reload-check, Run 070 apply contract, Run 071 `LivePqcTrustState`, Run 072 session-evictor, Run 073 `ProductionLiveTrustApplyContext`, or Run 074 `LiveReloadController` — every entry point is bit-for-bit unchanged.
- **Not** `activation_epoch` runtime sourcing (unchanged from Run 057 — bundles that declare `activation_epoch` continue to fail closed via the inherited loader).
- **Not** KMS / HSM custody.
- **Not** bundle-signing-key on-chain / in-binary ratification.
- **Not** fast-sync / consensus-storage restore parity.
- **Not** selective per-peer session retention.
- **Not** the N-node MainNet release-binary peer-connection smoke.

## 3. Anchors

### 3.1 Code

- `crates/qbind-node/src/pqc_peer_candidate_binary.rs` — new module. Pure-function `run_local_check(Run077Inputs, &P2pMetrics) -> Run077Result`. Returns `Refused { reason }` for every partial-config / I/O / parse fail-closed condition; returns `Ran { outcome, verdict_line, observed_log_line }` for every reached `try_accept` outcome. `Run077Result::exit_code() -> i32` is `0` only for `Ran { outcome: PeerCandidateOutcome::Validated(_), .. }` and `1` for every other variant.
- `crates/qbind-node/src/pqc_trust_peer_candidate.rs` — `PeerCandidateEnvelope` now derives `serde::Serialize` / `serde::Deserialize`; `bundle_bytes` is serialised as a lowercase-hex string via a small internal `peer_candidate_bundle_bytes_hex` serde module (no new dependency; hex codec uses the same simple lowercase-only validation pattern as `pqc_trust_sequence`). All other fields use their existing `Serialize` / `Deserialize` impls. This is a fixture-format change only — Run 077 introduces no peer/gossip wire surface.
- `crates/qbind-node/src/cli.rs` — two new hidden args:
  - `--p2p-trust-bundle-peer-candidate-validation-enabled` (`bool`, `hide = true`);
  - `--p2p-trust-bundle-peer-candidate-check <PATH>` (`Option<PathBuf>`, `hide = true`).
- `crates/qbind-node/src/main.rs` — Run 077 hook positioned AFTER the Run 069 reload-check block (line ~341) and BEFORE the Run 073 process-start reload-apply block. Performs the top-level required-together partial-config refusal, parses signing keys, loads leaf credentials (when both leaf flags supplied), enforces the TestNet/MainNet data-dir + signing-key preconditions, builds a scratch directory under `--data-dir/run077-peer-candidate-scratch` (or `std::env::temp_dir()` on DevNet without `--data-dir`), assembles `Run077Inputs`, calls `run_local_check`, prints the verdict + observed log line + (on rejection) `outcome` debug payload, and exits with the deterministic exit code.
- `crates/qbind-node/src/lib.rs` — `pub mod pqc_peer_candidate_binary;` exposed alongside the existing `pub mod pqc_trust_peer_candidate;`.

### 3.2 Tests

#### 3.2.1 Module unit tests — `cargo test -p qbind-node --lib pqc_peer_candidate_binary` (11 tests, all pass)

- `run077_hook_active_returns_false_when_neither_flag_supplied`
- `run077_hook_active_returns_true_when_path_only`
- `run077_hook_active_returns_true_when_enabled_only`
- `run077_partial_config_path_without_enabled_flag_refuses`
- `run077_partial_config_enabled_without_path_refuses`
- `run077_refusal_exit_code_is_one`
- `run077_refusal_display_lines_are_log_safe`
- `run077_verdict_label_is_stable`
- `run077_verdict_log_line_is_validation_only_disclaimer`
- `run077_fixture_io_error_refuses_before_validator_constructed`
- `run077_fixture_parse_error_refuses_before_validator_constructed`

#### 3.2.2 Integration tests — `cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests` (12 tests, all pass)

- `run077_disabled_by_default_hook_is_inactive`
- `run077_partial_config_path_only_refuses_and_does_not_bump_metrics`
- `run077_partial_config_enabled_only_refuses_and_does_not_bump_metrics`
- `run077_fixture_io_error_refuses_before_validator`
- `run077_fixture_parse_error_refuses_before_validator`
- `run077_valid_candidate_validates_and_does_not_apply` — proves `Validated`, exit code 0, sequence file bit-for-bit unchanged, scratch file removed, `received_total` and `validated_total` each bumped by exactly 1, **no other** Run 076 counter bumped.
- `run077_oversize_candidate_dropped_pre_crypto_no_scratch` — proves a >256 KiB payload returns `Oversize`, exit 1, no scratch file written, `dropped_oversize_total` bumped.
- `run077_wrong_environment_envelope_rejected_pre_crypto` — proves the envelope environment cross-check fires BEFORE any crypto runs.
- `run077_wrong_chain_id_envelope_rejected_pre_crypto` — same, for chain-id.
- `run077_tampered_signature_rejected_at_loader` — proves loader-stage `BadSignature` surface still reaches the binary verdict.
- `run077_does_not_affect_run069_reload_check_path` — proves the Run 069 reload-check entry point continues to validate the SAME bundle cleanly AFTER a Run 077 check has seen it (no cross-mutation between the two paths).
- `run077_metrics_output_never_contains_applied_total_family` — explicit `format_metrics()` text assertion that `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` is **not** present and that no Run 074 trigger counter has been bumped by Run 077.

#### 3.2.3 Regression — every Run 069 / 070 / 072 / 073 / 074 / 076 test that existed before Run 077 continues to pass

- `cargo test -p qbind-node --lib pqc_trust_peer_candidate` → **16/16 pass** (Run 076 module unit tests).
- `cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests` → **16/16 pass** (Run 076 integration tests).
- `cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests` → **12/12 pass**.
- `cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests` → **13/13 pass**.
- `cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests` → **10/10 pass**.
- `cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests` → **10/10 pass**.
- `cargo test -p qbind-node --lib metrics` → **114/114 pass** (no new metric family, no displaced series).
- `cargo test -p qbind-node --lib pqc_trust` (broad filter) → **182/182 pass** (Run 050/051/055/057/061/062/063/065/069/070/071/072/073/074 trust-related lib coverage).
- `cargo build -p qbind-node --bin qbind-node` → succeeds.

## 4. Operator-facing CLI surface (hidden, evidence-only)

Both flags are `hide = true` in clap — `--help` does not list them. Only the operator who reads this evidence doc, `task/RUN_077_TASK.txt`, or `docs/whitepaper/contradiction.md` C4 will know they exist. This matches the hidden-flag discipline used for Runs 069 / 070 / 073 / 074.

```
--p2p-trust-bundle-peer-candidate-validation-enabled
    Boolean opt-in switch. Required when the path flag is supplied;
    refused (exit 1) when supplied alone.
--p2p-trust-bundle-peer-candidate-check <ENVELOPE_PATH>
    Local JSON `PeerCandidateEnvelope` fixture path. Required when the
    `--*-enabled` flag is supplied; refused (exit 1) when supplied
    alone.
```

Exit code contract:

- `0` — outcome is `PeerCandidateOutcome::Validated(_)`. The candidate passed every Run 069 / Run 076 check. The node was **not** started. The sequence record was **not** modified.
- `1` — every other outcome and every fail-closed refusal (partial-config, I/O, parse, signing-key parse, leaf-credential load, TestNet/MainNet missing data-dir or signing-key, scratch-dir creation failure, every `Rejected` / `Oversize` / `RateLimited` / `Disabled` / `DuplicateSuppressed`).

Stderr lines emitted (stable, parseable by smoke harnesses):

- On refusal: `[binary] FATAL: <reason display string>`.
- On reached validator with rejection: optional `[binary] Run 077: outcome detail: <Debug fmt of PeerCandidateOutcome>` followed by the canonical `[binary] Run 077: VERDICT=<label> (peer-candidate validation-only; NOT applied; not propagated; sequence not persisted; live trust state unchanged; sessions untouched). Envelope path=<path>. See docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_077.md.`
- On `Validated`: the Run 076 `observed_log_line()` is printed first (single source of truth), then the canonical Run 077 `VERDICT=validated` line.

## 5. Non-mutation / no-fallback proof

- The on-disk anti-rollback sequence file at `<data_dir>/pqc_trust_sequence` (when `--data-dir` is supplied) is **never** modified by the Run 077 path. Proven by `run077_valid_candidate_validates_and_does_not_apply`'s `assert_seq_file_unchanged` AFTER the success path, by `run077_oversize_candidate_dropped_pre_crypto_no_scratch`, by `run077_wrong_environment_envelope_rejected_pre_crypto`, and by `run077_tampered_signature_rejected_at_loader`. Mechanism: the validator only invokes `peek_sequence` (Run 055 read-only), never `check_and_update_sequence`.
- `LivePqcTrustState` is **never** constructed on the Run 077 path. The `Run077Inputs` struct holds no live-state handle, and the validator type itself holds no live-state handle (Run 076 invariant, unchanged).
- No P2P / KEMTLS session is allocated, created, or evicted. The Run 077 hook exits before the network-mode dispatch.
- No new `qbind_p2p_pqc_trust_bundle_peer_candidate_applied_total` series is introduced. Proven by `run077_metrics_output_never_contains_applied_total_family` and by Run 076's existing `peer_candidate_metrics_render_once_in_format_metrics` (still passing).
- No Run 044 / 050 / 051 / 055 / 057 / 069 / 070 / 071 / 072 / 073 / 074 / 076 series is displaced or duplicated.
- No `DummySig` / `DummyKem` / `DummyAead` fallback path is introduced or strengthened. Run 077 calls the same loader Run 069 calls.
- No `--p2p-trusted-root` fallback path is added.
- No private-key material is referenced by `PeerCandidateEnvelope` (Run 076 invariant, unchanged), by `Run077Inputs`, by `Run077Result`, by any Run 077 refusal-reason display string, or by the canonical Run 077 `VERDICT=...` log line. The hex codec for `bundle_bytes` is for the **public** candidate bytes only; signing-key secrets are loaded only via `--p2p-trust-bundle-signing-key` and never serialised by Run 077.
- No classical signatures are introduced anywhere on the Run 077 path.
- No admin-API / network surface is added.

## 6. What remains C4-OPEN

Run 077 narrows **only** the "local CLI check mode for the existing Run 076 validator" sub-piece. The umbrella C4-OPEN "peer-supplied / gossiped bundle acceptance" item still has the following residuals, all explicitly OUT-OF-SCOPE here:

- Peer-driven live apply (would require a `LivePqcTrustState` handle on the validator; out of scope).
- Peer / gossip propagation (would require a wire / gossip subscription; out of scope).
- Admin-API trigger (no admin-API endpoint exists on `qbind-node`; out of scope).
- Filesystem watcher hot-reload (Run 074 is SIGHUP-only by design; out of scope).
- `activation_epoch` runtime sourcing (Run 057 still defaults to no runtime epoch source).
- KMS / HSM custody for bundle-signing keys.
- On-chain / in-binary ratification of bundle-signing keys.
- Fast-sync restore parity with the trust-bundle anti-rollback record.
- Per-environment trust-anchor operation playbooks beyond the existing Run 075 prose.
- Selective per-peer session retention on apply.
- The N-node MainNet release-binary peer-connection smoke.

These all remain explicitly C4-OPEN under `docs/whitepaper/contradiction.md` C4.

## 7. Reproduction commands (DevNet)

```bash
# Module unit tests (11)
cargo test -p qbind-node --lib pqc_peer_candidate_binary

# Integration tests (12)
cargo test -p qbind-node --test run_077_binary_peer_candidate_check_tests

# Run 076 regression (16 + 16)
cargo test -p qbind-node --lib pqc_trust_peer_candidate
cargo test -p qbind-node --test run_076_pqc_peer_candidate_validation_tests

# Run 069 / 070 / 073 / 074 regression
cargo test -p qbind-node --test run_069_pqc_trust_bundle_reload_check_tests
cargo test -p qbind-node --test run_070_pqc_trust_bundle_reload_apply_tests
cargo test -p qbind-node --test run_073_pqc_trust_bundle_reload_apply_runtime_tests
cargo test -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests

# Metrics + broad trust-bundle regression
cargo test -p qbind-node --lib metrics
cargo test -p qbind-node --lib pqc_trust

# Binary build
cargo build -p qbind-node --bin qbind-node
```

All commands above were executed during Run 077 and pass on a clean tree.