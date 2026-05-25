# QBIND DevNet Evidence — Run 138

**Subject**: Source/test wiring of v2 bundle-signing-key ratification and
v2 authority-marker discipline into the existing Run 074 SIGHUP live
trust-bundle reload mutating surface.

**Scope notice (mandatory per `task/RUN_138_TASK.txt`)**

* **Run 138 is source/test wiring only.**
* **No release-binary evidence was captured** in this run. Capture is
  deferred to Run 139.
* SIGHUP live-reload v2 source/test wiring (verifier + marker decision +
  post-commit persist) is now landed.
* Release-binary SIGHUP v2 evidence (PQC-aware `qbind-node` daemon
  driven by a real `kill -HUP <pid>` against a populated v2 sidecar
  plus `--authority-state-file` plus a generated post-Run-074 baseline)
  **remains open for Run 139**.
* Snapshot / restore v2 marker wiring **remains open**.
* Live inbound 0x05 v2 PQC trust-bundle frame validation **remains open**.
* Peer-driven live trust-bundle apply **remains open**.
* KMS / HSM authority-key custody **remains open**.
* MainNet governance attestation track **remains open**.
* Full C4 acceptance **remains open**.
* C5 acceptance **remains open**.

## What landed in Run 138

`task/RUN_138_TASK.txt` §§4–7 — implemented in:

* `crates/qbind-node/src/pqc_live_trust_reload.rs`
  * The SIGHUP reload controller (`LiveReloadController`) now peeks the
    ratification sidecar via the existing
    `load_versioned_ratification_from_path` (Run 114) helper. When the
    sidecar declares `schema_version=2`:
    1. A v2-scoped preflight
       (`preflight_sighup_v2_marker_decision`) runs the **existing**
       Run 130 v2 verifier
       (`verify_bundle_signing_key_ratification_v2`) **before any live
       mutation**. Verifier failures are mapped to
       `MutatingSurfaceMarkerV2Error::Conflict(MalformedOrUnsupportedMarkerRejected{..})`
       and surfaced as the new
       `LiveReloadOutcome::MarkerRejectedV2(_)` variant.
    2. The same Run 130/131 v2 marker decision used by the Run 134
       reload-apply path (`decide_marker_acceptance_v2`) runs **before
       any live mutation**, tagged with the existing
       `AuthorityStateUpdateSource::SighupReload` audit variant — no
       schema drift in `AuthorityStateUpdateSource`.
    3. On `Ok(accepted_decision)`, the SIGHUP apply pipeline runs the
       existing `apply_validated_candidate_with_previous` — the Run 070
       commit ordering is unchanged.
    4. Only on `Ok(applied)` is the v2 marker persisted via
       `persist_accepted_v2_marker_after_commit_boundary`. Persist
       failure surfaces as
       `LiveReloadOutcome::MarkerPersistFailureAfterCommitV2 { applied,
       marker_error }` with `is_fatal() == true` so the binary's SIGHUP
       task initiates graceful shutdown (mirrors the v1 Run 121 fatal
       shape).
  * v1 / no-ratification SIGHUP paths are byte-identical to Run 121 /
    Run 074. The only swap is the v1-only
    `load_ratification_from_path` (Run 114-era) for the versioned
    `load_versioned_ratification_from_path` (same module, same I/O
    fail-closed semantics).

* `crates/qbind-node/tests/run_138_sighup_v2_authority_marker_tests.rs`
  * 11 integration tests exercising the controller's
    `try_trigger_with_now` entry point — the same entry point the
    `qbind-node` binary's SIGHUP signal-handler task calls. Acceptance
    scenarios **A1–A4** and rejection scenarios **R1–R8** (R5 covered
    by orchestration shape and existing Run 074 commit-failure
    regression tests; explanation in the file's module doc-comment).

## Mutating-surface invariants

| Surface                         | Run | Path                  | Status   |
|---------------------------------|-----|-----------------------|----------|
| Startup `--p2p-trust-bundle`    | 119 | v1 marker             | landed   |
| Startup `--p2p-trust-bundle`    | 136 | v2 marker             | landed   |
| Reload-apply (in-process)       | 070 | v1 (no marker)        | landed   |
| Reload-apply (in-process)       | 134 | v2 marker             | landed   |
| **SIGHUP live trust-bundle reload** | 074 | v1 (no marker)    | landed   |
| **SIGHUP live trust-bundle reload** | 121 | v1 marker         | landed   |
| **SIGHUP live trust-bundle reload** | **138** | **v2 marker** | **landed (this run)** |
| Snapshot / restore              | —   | v2 marker             | open     |
| Live inbound 0x05 v2            | —   | v2 marker             | open     |
| Peer-driven apply               | —   | —                     | open     |

The Run 138 SIGHUP v2 path is gated on the operator having opted in to
both v2 ratification (by writing a `schema_version=2` sidecar at the
existing `ratification_sidecar_path`) and v2 authority-marker discipline
(by populating `--authority-state-file`, i.e.
`LiveReloadAuthorityMarkerConfig`). Either being absent preserves the
existing v1 / pre-Run-114 SIGHUP behaviour exactly.

## Validation commands executed (Run 138 session)

All commands run against this PR's worktree (`x86_64-unknown-linux-gnu`,
`rustc 1.x` per `rust-toolchain.toml`):

```
cargo build -p qbind-node --lib
cargo test  -p qbind-node --lib pqc_authority_marker_acceptance::
cargo test  -p qbind-node --test run_119_authority_marker_acceptance_tests
cargo test  -p qbind-node --test run_121_sighup_authority_marker_tests
cargo test  -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test  -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests
cargo test  -p qbind-node --test run_138_sighup_v2_authority_marker_tests
```

Results:

* `cargo build -p qbind-node --lib` — clean build, no warnings
  attributable to Run 138 changes.
* `pqc_authority_marker_acceptance::` — **51 passed / 0 failed** (Run
  119, Run 131, Run 136 v2-startup variants all green).
* `run_119_authority_marker_acceptance_tests` — **4 / 4 passed**.
* `run_121_sighup_authority_marker_tests` — **7 / 7 passed** (R7
  regression coverage: v1 SIGHUP unchanged).
* `run_134_reload_apply_v2_authority_marker_tests` — **5 / 5 passed**
  (v2 reload-apply path unchanged; Run 138 reuses the same v2 marker
  helpers).
* `run_074_pqc_trust_bundle_live_reload_tests` — **10 / 10 passed**
  (Run 070 / Run 074 commit-ordering invariants unchanged; covers the
  R5 commit-failure rollback case end-to-end).
* `run_138_sighup_v2_authority_marker_tests` — **11 / 11 passed**.

## Run 138 acceptance scenarios actually covered

| ID | Test                                                                    | Outcome |
|----|-------------------------------------------------------------------------|---------|
| A1 | `run138_a1_first_accepted_v2_sighup_creates_v2_marker`                  | pass    |
| A2 | `run138_a2_idempotent_v2_sighup_does_not_rewrite_marker`                | pass    |
| A3 | `run138_a3_higher_sequence_v2_sighup_advances_marker`                   | pass    |
| A4 | `run138_a4_v1_to_v2_sighup_migration_promotes_marker`                   | pass    |
| R1 | `run138_r1_lower_sequence_v2_sighup_refuses_pre_mutation`               | pass    |
| R2 | `run138_r2_same_sequence_different_digest_v2_sighup_refuses`            | pass    |
| R3 | `run138_r3_bad_signature_v2_sidecar_refuses_pre_mutation`               | pass    |
| R4 | `run138_r4_wrong_domain_v2_sidecar_refuses_pre_mutation`                | pass    |
| R5 | covered by Run 074 commit-failure regression + persist-only-on-`Ok` shape | pass  |
| R6 | `run138_r6_v2_marker_persist_failure_after_commit_is_fatal` (unix)      | pass    |
| R7 | `run138_r7_v1_sighup_sidecar_still_takes_v1_path`                       | pass    |
| R8 | `run138_r8_no_sidecar_devnet_sighup_writes_no_v2_marker`                | pass    |

## Drift audit

* No new `AuthorityStateUpdateSource` variants — Run 138 reuses
  `SighupReload`.
* No new CLI flags, no new metric names, no new wire-format fields,
  no new file-format fields, no new authority-marker schemas.
* The `LiveReloadOutcome` enum gains two **additive** variants
  (`MarkerRejectedV2`, `MarkerPersistFailureAfterCommitV2`) — both are
  internal to `qbind-node` and not part of any public protocol /
  wire / disk format.

## What this run does NOT prove

* Release-binary `qbind-node` SIGHUP-driven v2 evidence (PID-based
  signal delivery, real disk sidecar, real disk marker).
* That a snapshot/restore round-trip preserves the v2 marker.
* That a peer-delivered v2 trust-bundle is accepted via the live
  inbound 0x05 surface.
* Anything about KMS/HSM custody, MainNet governance, full C4, or C5.

All of the above remain explicit Run 139+ scope.
