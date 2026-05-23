# QBIND DevNet Evidence — Run 123

## Summary

Run 123 extends the authority anti-rollback marker system (Runs 117–121)
to the three **validation-only** surfaces that never persist marker state:

1. **Reload-check** (`--p2p-trust-bundle-reload-check`) — the `Run 069`
   non-mutating validation CLI mode.
2. **Peer-candidate-check** (`--p2p-trust-bundle-peer-candidate-check`) —
   the `Run 077` local envelope validation CLI mode.
3. **Live inbound `0x05`** — the `Run 109` ratification-aware wire
   dispatcher for peer-supplied candidate frames.

On all three surfaces the marker check:
- Runs AFTER ratification verification succeeds.
- Runs BEFORE the success verdict is emitted / rebroadcast eligibility.
- NEVER persists the marker file under any code path.
- Rejects on conflict / corruption / wrong-domain (fail-closed).
- Passes on no-prior-marker, idempotent, or upgrade-compatible.

For the live `0x05` surface specifically, a marker conflict changes the
validation outcome from `Validated` to `Rejected(MarkerConflict(...))`,
which the existing Run 088 propagation gating observes as a non-Validated
outcome — rebroadcast is automatically suppressed with no additional
propagation-layer change.

## Code Changes

| File | Change |
|------|--------|
| `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` | Added `ValidationOnlyMarkerError` enum, `ValidationOnlyMarkerAcceptReason` enum, `ValidationOnlyMarkerInputs` struct, `verify_marker_for_validation_only()` helper, `map_conflict_to_validation_only_error()` helper, 8 unit tests |
| `crates/qbind-node/src/pqc_trust_reload.rs` | Added `MarkerConflict(String)` variant to `ReloadCheckError` |
| `crates/qbind-node/src/pqc_peer_candidate_wire.rs` | Added `authority_marker_path: Option<PathBuf>` to `LivePeerCandidateWireDispatcherConfig` and `LivePeerCandidateWireDispatcher`; added `maybe_reject_on_marker_conflict()` method |
| `crates/qbind-node/src/main.rs` | Added `preflight_run_123_validation_only_marker_check()` binary-side helper; wired into reload-check and peer-candidate-check success paths; computed `authority_marker_path` for live dispatcher config |
| `crates/qbind-node/tests/run_079_*.rs` | Added `authority_marker_path: None` to test configs |
| `crates/qbind-node/tests/run_088_*.rs` | Added `authority_marker_path: None` to test configs |
| `crates/qbind-node/tests/run_109_*.rs` | Added `authority_marker_path: None` to test configs |

## Surfaces Wired

| Surface | Behaviour on marker conflict | Behaviour on no marker | Persists? |
|---------|------------------------------|------------------------|-----------|
| Reload-check CLI | `exit(1)` with typed error | Pass (first-seen) | Never |
| Peer-candidate-check CLI | `exit(1)` with typed error | Pass (first-seen) | Never |
| Live `0x05` inbound | `Rejected(MarkerConflict)` — propagation suppressed | Pass (first-seen) | Never |

## Skip Conditions (unchanged byte-for-byte from Run 119–121)

The validation-only helper returns `Ok(None)` (no marker enforcement) when:
- `--data-dir` is unset (DevNet-only convenience);
- The candidate is DevNet-unsigned (no signing key);
- `LegacyUnratifiedAccepted` (no ratified key to anchor a marker on);
- The candidate pre-load fails (deferred to the validation pipeline);
- The signing-key id is not in the configured set (deferred).

## Tests Landed

8 new unit tests in `pqc_authority_marker_acceptance::tests`:
- `run123_no_persisted_marker_passes_validation_only`
- `run123_idempotent_marker_passes_validation_only`
- `run123_upgrade_compatible_passes_validation_only`
- `run123_rollback_rejected_by_validation_only`
- `run123_corrupt_marker_rejected_by_validation_only`
- `run123_wrong_domain_rejected_by_validation_only`
- `run123_same_sequence_conflicting_hash_rejected`
- `run123_validation_only_never_persists_on_any_outcome`

## Regression

- `qbind-node --lib`: 1192 tests pass (was 1184 before Run 123; +8 new).
- `qbind-ledger --lib`: 231 tests pass (unchanged).
- `run_079_*`, `run_088_*`, `run_109_*`, `run_119_*` integration tests: all pass (unchanged).

## Invariants Preserved

Run 123 weakens no existing invariant:
- No Run 050–122 invariant changes.
- The reload-check surface still produces the same `VERDICT=valid` log on
  the accept path and the same `VERDICT=invalid` on any validation error.
- The peer-candidate-check surface still produces the same verdict lines.
- The live `0x05` surface still produces the same `Validated` / `Rejected`
  outcome types; propagation gating sees `Rejected` on marker conflict
  (identical to how it already sees `Rejected(RatificationRefused)` under
  Run 109).
- No mutating surface (startup, reload-apply, SIGHUP) is touched.
- Static production source-code anchors remain rejected.

## Explicit Non-Goals

Run 123 does NOT:
- Wire any new mutating-surface marker persistence.
- Modify the startup `--p2p-trust-bundle` path (Run 120).
- Modify the SIGHUP live-reload path (Run 121).
- Modify the reload-apply path (Run 119).
- Add release-binary evidence scenarios.
- Add `--allow-authority-state-reset` operator-recovery flag.
- Add per-key monotonic field schema bump.
- Claim C4 or C5 closure.