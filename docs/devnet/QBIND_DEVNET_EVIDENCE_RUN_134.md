# QBIND DevNet Evidence — Run 134

**Subject:** Wire v2 ratification into the process-start reload-apply **mutating** surface (accept-and-persist).
**Verdict:** **strongest-positive**
**Date:** 2026-05-25
**Task:** `task/RUN_134_TASK.txt`
**Type:** Implementation (mutating-surface wiring; v2 marker persistence after `commit_sequence`).

---

## 1. Scope summary

Run 134 wires the Run 130 v2 bundle-signing-key ratification verifier and the
Run 131 v2 authority marker primitives into the **process-start reload-apply**
mutating binary surface
(`--p2p-trust-bundle-reload-apply-path` + `--p2p-trust-bundle-reload-apply-enabled`).

Where Run 132 wired the validation-only surfaces (which never write marker
state), Run 134 wires the **only** v2 path that may mutate live trust state
*and* persist a v2 marker to disk after the trust-bundle `commit_sequence`
boundary. The pattern follows Run 118 / Run 119 verbatim:

```
  decide_marker_acceptance_v2  ─►  apply pipeline  ─►  persist v2 marker
        (no I/O write)               (Run 070)         (after commit_sequence)
```

Run 134 explicitly defers:

- **SIGHUP live-reload-apply v2 wiring** (Run 074 / Run 121 pattern) — deferred.
- **Snapshot/restore v2 marker wiring** (Run 124 pattern) — deferred.
- **`--p2p-trust-bundle` startup-acceptance v2 wiring** (Run 120 pattern) — deferred.
- **Release-binary evidence harness** — deferred to a follow-on run that
  mirrors Run 133's `scripts/devnet/run_133_*.sh` shape.
- **Signing-key rotation / revocation lifecycle plumbing** beyond what the
  Run 130 verifier and Run 131 derivation already enforce.

These deferrals match the same strict-scope discipline Run 132 / Run 133
used for v2.

---

## 2. Source changes

### 2.1 v2 atomic persister

File: `crates/qbind-node/src/pqc_authority_state.rs`

Added `persist_authority_state_v2_atomic(path, &PersistentAuthorityStateRecordV2)`
that mirrors `persist_authority_state_atomic` bit-for-bit (validate → serialise
→ `<path>.tmp` → `sync_all(tmp)` → `rename` → `sync_all(parent_dir)` on Unix).
The on-disk JSON keeps the same versioned discriminator
(`record_version` / `authority_schema_version`), so
`load_authority_state_versioned` / `parse_versioned_authority_state_record_bytes`
read it back as `PersistentAuthorityStateRecordVersioned::V2`.

This is the only place the Run 134 mutating-surface wiring touches disk
for v2 markers. Run 132 validation-only surfaces never call it.

### 2.2 v2 mutating-surface helpers

File: `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`

Added:

- `MutatingSurfaceMarkerV2Error` enum (10 variants):
  - `DerivationFailed(AuthorityStateDerivationV2Error)`
  - `LoadOrCorruption(AuthorityStateError)`
  - `PersistedDomainMismatch(AuthorityMarkerV2ComparisonOutcome)`
  - `LowerV2SequenceRefused { persisted_sequence, attempted_sequence }`
  - `SameSequenceConflictingDigest { sequence, persisted_digest, attempted_digest }`
  - `SameSequenceConflictingKeyOrAction { reason }`
  - `V1AfterV2Rejected` (defence-in-depth)
  - `UnsupportedMarkerVersion { reason }`
  - `Conflict(AuthorityMarkerV2ComparisonOutcome)` (catch-all)
  - `PersistFailure(AuthorityStateError)`
- `MarkerAcceptanceV2Inputs<'a>` struct: marker path + runtime trust-domain
  triple + verified v2 ratification + Run 130 verifier output + update-source
  tag + audit timestamp.
- `MarkerAcceptDecisionV2` (carries derived candidate + `should_persist` +
  `kind`) and `MarkerAcceptKindV2` (`FirstV2Write` | `Idempotent` |
  `UpgradeV2 { previous_sequence, new_sequence }` | `V2AfterV1Migration`).
- `decide_marker_acceptance_v2(inputs) -> Result<MarkerAcceptDecisionV2, MutatingSurfaceMarkerV2Error>`:
  derives the v2 candidate marker via Run 131
  `derive_authority_state_v2_from_ratification`, loads the persisted
  versioned marker via Run 131 `load_authority_state_versioned`, compares
  via Run 131 `compare_authority_marker_v2`, maps the outcome to a typed
  accept-or-reject. Performs **no** disk writes.
- `persist_accepted_v2_marker_after_commit_boundary(&decision) -> Result<(), MutatingSurfaceMarkerV2Error>`:
  no-op when `should_persist` is false (idempotent case); otherwise calls
  the new atomic v2 persister. The only write path for v2 markers in the
  Run 134 wiring.

### 2.3 Binary preflight helper + dispatch wiring

File: `crates/qbind-node/src/main.rs`

Added:

- `preflight_run_134_v2_marker_decision(runtime_env, runtime_chain_id, ctx_data, data_dir, updated_at_unix_secs)`:
  runs the Run 130 v2 verifier against the operator-supplied v2 sidecar
  carried in `Run105ReloadCheckContextData::ratification_v2`, then calls
  `decide_marker_acceptance_v2`. Returns `Ok(None)` when no v2 sidecar
  was supplied or `--data-dir` is unset, `Ok(Some(decision))` on accept,
  `Err(MutatingSurfaceMarkerV2Error)` on reject.

Modified the existing process-start reload-apply block to dispatch on the
v2 sidecar presence:

- **v2 sidecar present**: emit `[run-134] reload-apply v2 ratification path
  SELECTED`, call `preflight_run_134_v2_marker_decision`, then drive the
  Run 070 apply pipeline through `apply_validated_candidate_with_previous`
  **without** a v1 `RatificationEnforcementContext` (the v2 verifier
  already ran in the preflight). On `Ok(applied)`, call
  `persist_accepted_v2_marker_after_commit_boundary`. A persist failure
  AFTER successful apply is FATAL and surfaces operator-actionable text
  matching the Run 119 §D crash-window discipline (stale-by-one marker
  replayed as `UpgradeV2` on next accepted mutation per Run 131).
- **v1 sidecar (or no sidecar)**: existing Run 119 v1 path runs verbatim.

No change to CLI flag surfaces.

### 2.4 Tests

New: `crates/qbind-node/tests/run_134_reload_apply_v2_authority_marker_tests.rs`

Five scenarios using the deterministic `FakeLiveTrustApplyContext` from
Run 070/119 plus the Run 130 `v2_test_helpers::build_signed_ratification_v2`
helper:

1. **§C.1 clean v2 first-write** — decide_v2 → apply (Run 070 callback
   ordering preserved bit-for-bit) → persist_v2; on-disk marker is V2 with
   `latest_authority_domain_sequence=5`, `latest_lifecycle_action=Ratify`.
2. **§C.2 pre-persisted higher-sequence rollback** — persisted v2 at seq=7,
   candidate at seq=5. decide_v2 returns `LowerV2SequenceRefused { persisted_sequence: 7, attempted_sequence: 5 }`. No apply callback fires;
   on-disk bytes unchanged; sequence file never created.
3. **§C.3 swap-stage apply failure** — decide_v2 accepts, apply fails at
   `swap_trust_state`; the marker file is NEVER created because the
   orchestration skips persist on `Err`.
4. **§C.4 idempotent re-apply** — same candidate twice. Second decide_v2
   returns `Idempotent`, `should_persist=false`. persist_v2 is a strict
   no-op; file bytes byte-for-byte unchanged across the two persist calls.
5. **§C.5 v2-after-v1 migration** — pre-persist a real Run 119 v1 marker,
   then decide_v2 against the v2 candidate. Outcome classified as
   `V2AfterV1Migration` with `should_persist=true`. After persist_v2 the
   on-disk record loads back as `PersistentAuthorityStateRecordVersioned::V2`.

---

## 3. Tests run

```
$ cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
... 5 passed; 0 failed; 0 ignored ...

$ cargo test -p qbind-node --lib
... 1246 passed; 0 failed; 0 ignored ...

$ cargo test -p qbind-node \
    --test run_112_reload_apply_ratification_tests \
    --test run_114_sighup_live_reload_ratification_tests \
    --test run_119_authority_marker_acceptance_tests \
    --test run_121_sighup_authority_marker_tests \
    --test run_124_snapshot_restore_authority_marker_tests
... all green ...
```

No existing test required modification; the v1 path is bit-for-bit
unchanged.

---

## 4. What Run 134 does NOT change

- Run 119 v1 marker acceptance helpers / wiring — **unchanged**.
- Run 120 startup `--p2p-trust-bundle` v1 marker preflight — **unchanged** and
  v1-only. v2 startup wiring is deferred.
- Run 121 SIGHUP live-reload v1 marker wiring — **unchanged** and v1-only.
- Run 122 snapshot-restore v1 marker wiring — **unchanged** and v1-only.
- Run 123 / Run 132 validation-only surfaces (reload-check, peer-candidate-check)
  — **unchanged**; the new code path is only entered by the mutating
  reload-apply surface.
- CLI flag surface — **unchanged**.
- /metrics families — **unchanged** (the binary exits with `0`/`1` after this
  subcommand; `/metrics` is never bound on this path, per the Run 069/073
  module discipline).

---

## 5. Fail-closed guarantees

- The v2 helpers never silently turn a reject outcome into an accept.
- `decide_marker_acceptance_v2` performs zero disk writes — if the
  subsequent apply pipeline fails (validate / snapshot / swap / evict /
  commit), the marker file remains exactly as before.
- `persist_accepted_v2_marker_after_commit_boundary` is the only v2-write
  path in the Run 134 wiring, and it runs strictly AFTER `commit_sequence`.
  A mid-write crash leaves the on-disk marker stale-by-one (safely
  replayable per Run 118 §D / Run 131); a non-crash persist failure is
  FATAL and surfaces operatorially.
- MainNet behaviour: `--p2p-trust-bundle-reload-apply-path` requires
  `--data-dir`, the same precondition the v1 path enforces. The v2
  preflight returns `Ok(None)` when `--data-dir` is unset, matching the
  v1 path's DevNet-only convenience branch.

---

## 6. Cross-references

- Run 130 — v2 bundle-signing-key ratification verifier
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_130.md`).
- Run 131 — v2 authority marker primitives + monotonic comparison
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_131.md`).
- Run 132 — v2 validation-only surfaces (reload-check, peer-candidate-check)
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_132.md`).
- Run 118 §D — stale-by-one crash-window rule that Run 134 inherits
  verbatim for v2.
- Run 119 — v1 mutating-surface accept-and-persist helpers and wiring,
  whose shape Run 134 mirrors for v2.
- `docs/whitepaper/contradiction.md` C4 — bundle-signing-key ratification
  authority model.