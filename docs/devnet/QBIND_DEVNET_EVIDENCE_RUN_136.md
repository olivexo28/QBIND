# QBIND DevNet Evidence — Run 136

**Subject:** Wire v2 ratification into the **startup `--p2p-trust-bundle`** mutating surface (accept-and-persist).
**Verdict:** **strongest-positive**
**Date:** 2026-05-25
**Task:** `task/RUN_136_TASK.txt`
**Type:** Implementation (mutating-surface wiring; v2 marker persistence after `commit_sequence` on the startup binary surface).

---

## 1. Scope summary

Run 136 wires the Run 130 v2 bundle-signing-key ratification verifier and the
Run 131 v2 authority marker primitives into the **startup `--p2p-trust-bundle`**
mutating binary surface. This is the same `qbind-node` binary path that the
Run 105 / Run 106 startup gate and the Run 120 v1 marker preflight already
guard; Run 136 adds a v2 dispatch alongside the v1 path without touching
either of those existing flows.

Run 134 wired the v2 path into the **process-start reload-apply** mutating
surface (`--p2p-trust-bundle-reload-apply-path`). Run 136 is the strict twin
for the **startup `--p2p-trust-bundle`** mutating surface, applying the same
pattern verbatim:

```
  (skip v1 gate)                                            (after Run 055
   ↓                                                         commit_sequence
   verify_bundle_signing_key_ratification_v2                 succeeds)
   ↓                                                          ↓
   decide_marker_acceptance_v2  ─►  Run 055 sequence write ─► persist_v2
        (no I/O write)               (existing — unchanged)   (marker
                                                                writes
                                                                exactly
                                                                once)
```

The v1 startup gate (`apply_run_105_ratification_gate_at_startup`) cannot
parse a v2 sidecar (its loader is the Run 103 v1-only
`load_ratification_from_path`); Run 136 SKIPS that v1 gate on the v2 dispatch
branch because the Run 130 v2 verifier already runs inside the Run 136
preflight. The v1 startup gate continues to run unmodified for v1 sidecars
and for the no-sidecar legacy DevNet path.

Run 136 explicitly defers:

- **SIGHUP live-reload v2 wiring** (Run 074 / Run 121 pattern) — deferred.
- **Snapshot/restore v2 marker wiring** (Run 124 pattern) — deferred.
- **Release-binary evidence harness** — deferred to a follow-on run that
  mirrors Run 133's `scripts/devnet/run_133_*.sh` shape on the startup
  surface.
- **CLI flag surface changes** — none.

These deferrals match the same strict-scope discipline Run 132 / Run 133 /
Run 134 / Run 135 used for v2.

---

## 2. Source changes

### 2.1 Binary preflight helper

File: `crates/qbind-node/src/main.rs`

Added `preflight_run_136_v2_marker_decision_for_startup(runtime_env,
runtime_chain_id, ctx_data, data_dir, updated_at_unix_secs)`. The helper
composes:

1. The Run 130
   `qbind_ledger::verify_bundle_signing_key_ratification_v2` verifier
   against the operator-supplied v2 sidecar carried in
   `Run105ReloadCheckContextData::ratification_v2`. A verifier failure
   maps into `MutatingSurfaceMarkerV2Error::Conflict` so the operator
   sees a precise typed reason and the post-commit persist call never
   runs.
2. The Run 134 `decide_marker_acceptance_v2` helper, tagged with
   `AuthorityStateUpdateSource::StartupLoad` so the persisted audit
   field reflects the actual mutating surface.

The helper returns:

- `Ok(None)` when `data_dir` is unset (DevNet convenience; MainNet /
  TestNet are already FATAL-rejected on the startup `--p2p-trust-bundle`
  path when `--data-dir` is missing — see Run 055).
- `Ok(None)` when no v2 sidecar is present (caller-bug defence; the
  dispatcher in `main()` only calls this helper when
  `ctx_data.ratification_v2.is_some()`).
- `Ok(Some(decision))` on accept — caller MUST call
  `persist_accepted_v2_marker_after_commit_boundary` AFTER the Run 055
  `check_and_update_sequence` write succeeds.
- `Err(MutatingSurfaceMarkerV2Error)` on reject — caller MUST NOT write
  the Run 055 sequence record, MUST NOT merge any new bundle root into
  the live trust set, MUST NOT start P2P, and MUST surface the typed
  reason operatorially.

### 2.2 Startup dispatch wiring

File: `crates/qbind-node/src/main.rs`

Modified the existing startup `--p2p-trust-bundle` block (the
`startup_gate_decision.should_invoke()` arm) to dispatch on the v2 sidecar
presence carried in `Run105ReloadCheckContextData`:

- **v2 sidecar present:** emit `[run-136] startup --p2p-trust-bundle v2
  ratification path SELECTED`, SKIP
  `apply_run_105_ratification_gate_at_startup` (the v1-only gate cannot
  parse a v2 sidecar; the v2 verifier runs inside the Run 136 preflight),
  call `preflight_run_136_v2_marker_decision_for_startup`. On accept the
  resulting `MarkerAcceptDecisionV2` is held in
  `startup_marker_decision_v2: Option<MarkerAcceptDecisionV2>`. On reject
  the binary exits non-zero with an operator-actionable
  `[run-136] FATAL: ...` log line that names every guarantee the rejection
  preserves (no Run 055 sequence write, no bundle-root merge, no live
  trust mutation, no P2P startup, no marker write).
- **v1 sidecar (or no sidecar):** unchanged. The existing Run 105 gate
  runs, then the Run 120 v1 marker preflight runs, populating
  `startup_marker_decision: Option<MarkerAcceptDecision>`. The dispatch
  is mutually exclusive: exactly one of `startup_marker_decision` /
  `startup_marker_decision_v2` carries a decision after the gate body.

After the existing Run 055 `check_and_update_sequence` succeeds, the binary
runs the existing Run 120 v1 persist block AND a new Run 136 v2 persist
block. The two blocks are mutually exclusive by construction; both follow
the same shape:

```
if let Some(decision) = startup_marker_decision_v2.as_ref() {
    match persist_accepted_v2_marker_after_commit_boundary(decision) {
        Ok(()) => eprintln!("[run-136] v2 authority-marker persisted ..."),
        Err(e) => {
            eprintln!("[run-136] FATAL: v2 authority-marker persist failure ...");
            std::process::exit(1);
        }
    }
}
```

A persist failure AFTER successful Run 055 sequence write is FATAL and
surfaces operator-actionable text matching the Run 119 §D / Run 131
crash-window discipline (the on-disk v2 marker is stale-by-one and will
be re-derived on the next accepted mutation as an `UpgradeV2`).

No CLI flag changes. No new dependencies.

### 2.3 Tests

File: `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`

Added `tests::run136_v2_startup_tests` in-module test block with 8 cases
that mirror the Run 120 v1 startup matrix (`run_120_startup_*`) on the v2
path:

1. **§A.1 first v2 startup accepted** — `decide_v2` → simulated Run 055
   commit → `persist_v2`. On-disk record is V2 with
   `latest_authority_domain_sequence=1` and
   `last_update_source=StartupLoad`.
2. **§A.2 idempotent v2 startup** — same candidate twice across a
   simulated restart. Second `decide_v2` returns `Idempotent`,
   `should_persist=false`; the persist call is a strict no-op
   (file bytes byte-for-byte unchanged).
3. **§A.3 upgrade v2 startup** — pre-persist at sequence=1, restart with
   sequence=5. Outcome is `UpgradeV2 { previous_sequence: 1,
   new_sequence: 5 }`, persisted record advances.
4. **§A.4 lower v2 sequence at startup** — pre-persist at sequence=7,
   restart with sequence=3. `decide_v2` returns
   `LowerV2SequenceRefused { persisted_sequence: 7,
   attempted_sequence: 3 }`. No mutation; on-disk bytes unchanged.
5. **§A.5 same v2 sequence, different digest** — pre-persist
   `(seq=5, key_a)`, restart with `(seq=5, key_b)`. `decide_v2` rejects
   with `SameSequenceConflictingDigest` (or the equivalent
   `SameSequenceConflictingKeyOrAction` linkage variant). No mutation.
6. **§A.6 corrupt persisted marker** — `{ not valid json` on disk.
   `decide_v2` returns `LoadOrCorruption`; the garbage on disk is NOT
   auto-overwritten.
7. **§A.7 v2-after-v1 migration at startup** — pre-persist a Run 119 v1
   marker, then arrive at startup with a v2 sidecar at a higher
   sequence. `decide_v2` returns `V2AfterV1Migration`; after
   `persist_v2` the on-disk record loads as
   `PersistentAuthorityStateRecordVersioned::V2` with the
   `StartupLoad` audit tag.
8. **§A.8 dropped v2 decision** — decide accepts, drop without persist
   (simulates the Run 055 sequence-write `Err` arm). The marker file is
   NEVER created.

The Run 134 reload-apply integration tests
(`tests/run_134_reload_apply_v2_authority_marker_tests.rs`) cover the full
Run 070 callback ordering against `FakeLiveTrustApplyContext`; the
Run 136 in-module tests above focus on the marker decide/persist
contract that the startup binary wiring depends on. The startup wiring
inside `main()` is in turn a thin composition of those audited primitives
plus a v1/v2 dispatch on `Run105ReloadCheckContextData::ratification_v2`.

---

## 3. Tests run

```
$ cargo build -p qbind-node --lib
... Finished `dev` profile ...

$ cargo test -p qbind-node --lib pqc_authority_marker_acceptance::
... 51 passed; 0 failed; 0 ignored ...

$ cargo test -p qbind-node --lib
... 1254 passed; 0 failed; 0 ignored ...

$ cargo test -p qbind-node \
    --test run_105_ratification_enforcement_tests \
    --test run_106_ratification_policy_tests \
    --test run_112_reload_apply_ratification_tests \
    --test run_119_authority_marker_acceptance_tests \
    --test run_134_reload_apply_v2_authority_marker_tests
... all green ...
```

No existing test required modification; the v1 startup path is bit-for-bit
unchanged when the sidecar is v1 or absent, and the Run 134 reload-apply
v2 path is bit-for-bit unchanged.

---

## 4. What Run 136 does NOT change

- Run 119 v1 marker acceptance helpers / wiring — **unchanged**.
- Run 120 startup `--p2p-trust-bundle` v1 marker preflight — **unchanged**
  and still runs verbatim when the sidecar is v1 or absent.
- Run 121 SIGHUP live-reload v1 marker wiring — **unchanged** and v1-only.
- Run 122 snapshot-restore v1 marker wiring — **unchanged** and v1-only.
- Run 123 / Run 132 validation-only surfaces (reload-check,
  peer-candidate-check) — **unchanged**; the new code path is only entered
  by the mutating startup surface.
- Run 134 reload-apply v2 wiring — **unchanged**; Run 136 reuses the same
  `decide_marker_acceptance_v2` and
  `persist_accepted_v2_marker_after_commit_boundary` helpers with the
  `StartupLoad` audit tag.
- Run 105 / Run 106 v1 startup gate — **unchanged** structurally; the
  Run 136 dispatch only SKIPS the v1 gate on the v2 branch (the v2
  verifier runs inside the Run 136 preflight in its place).
- Run 055 trust-bundle sequence persistence — **unchanged**; the v2
  marker persist sits AFTER `check_and_update_sequence` exactly like the
  v1 marker persist.
- CLI flag surface — **unchanged**.
- /metrics families — **unchanged** (the new path emits operator-log
  lines only, no counters).

---

## 5. Fail-closed guarantees

- The Run 136 preflight performs ZERO disk writes; if the subsequent
  Run 055 sequence write fails, the marker file remains exactly as
  before and `startup_marker_decision_v2` is dropped without persist.
- `persist_accepted_v2_marker_after_commit_boundary` is the ONLY v2-write
  path in the Run 136 wiring, and it runs strictly AFTER
  `check_and_update_sequence`.
- A persist failure here is FATAL and surfaces operatorially. The
  trust-bundle sequence has already advanced; the on-disk v2 marker is
  stale-by-one, intentionally safe to replay as `UpgradeV2` on the next
  accepted v2 mutation per Run 118 §D / Run 131.
- MainNet / TestNet behaviour: the startup `--p2p-trust-bundle` path
  already requires `--data-dir` (Run 055 production-honest invariant).
  The Run 136 preflight returns `Ok(None)` when `--data-dir` is unset,
  matching the v1 startup path's DevNet-only convenience branch.
- v1/v2 mutual exclusion: exactly one of
  `startup_marker_decision` / `startup_marker_decision_v2` carries a
  decision after the gate body. There is no path on which both v1 and
  v2 markers are persisted in the same startup invocation.
- v1-after-v2 protection: the underlying `decide_marker_acceptance_v2`
  helper rejects a v1 candidate landing on a persisted v2 marker
  (`V1AfterV2Rejected`). Because Run 136 only routes v2 sidecars into
  the v2 decide helper, this is defence-in-depth at the helper layer;
  the dispatcher in `main()` chooses the helper by sidecar schema
  version.

---

## 6. Cross-references

- Run 105 / Run 106 — v1 bundle-signing-key ratification gate and
  per-environment policy
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_105.md`,
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_106.md`).
- Run 120 — v1 startup `--p2p-trust-bundle` authority-marker preflight
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_120.md`). The Run 136 dispatch
  preserves this code path bit-for-bit on the v1 / no-sidecar branch.
- Run 130 — v2 bundle-signing-key ratification verifier
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_130.md`).
- Run 131 — v2 authority marker primitives + monotonic comparison
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_131.md`).
- Run 132 — v2 validation-only surfaces (reload-check,
  peer-candidate-check)
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_132.md`).
- Run 134 — v2 reload-apply mutating-surface wiring
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_134.md`). Run 136 mirrors this
  exact shape on the startup surface.
- Run 118 §D / Run 131 — stale-by-one crash-window rule that Run 136
  inherits verbatim for v2 on the startup surface.
- `docs/whitepaper/contradiction.md` C4 — bundle-signing-key
  ratification and signed root distribution.
- `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
  §"Authority anti-rollback marker (Run 117–120, v2 Run 129–131,
  startup v2 Run 136)".