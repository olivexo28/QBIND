# QBIND DevNet Evidence — Run 159

## Subject

Run 159: **source/test coverage** for the **v2 bundle-signing-key
lifecycle** transition machine — `ActivateInitial`, `Rotate`,
`Retire`, `Revoke`, `EmergencyRevoke` — together with the rejection
matrix for replay, stale-key, same-epoch / same-sequence
equivocation, and rollback. Run 159 implements the local
authority-state transition rules around the **existing** Run 130 v2
ratification / Run 131 v2 marker fields and adds typed pure
validation tests; it does **not** introduce a new wire format, a
new sidecar schema, or a new sequence-file schema, and it does
**not** capture any release-binary evidence.

## Verdict

**Run 159 is source/test signing-key lifecycle validation only.**
Planned rotation, retirement, revocation, and emergency revocation
each have explicit accepted/rejected behavior in
`crates/qbind-node/src/pqc_authority_lifecycle.rs`. Lower-sequence
rollback, same-sequence equivocation, wrong-environment / wrong-chain
/ wrong-genesis / wrong-authority-root, wrong-previous-key,
revoked-key reuse, retired-key reuse, malformed revoked metadata,
non-PQC suite, and unsupported lifecycle action are fail-closed
typed reject variants. Existing v2 marker comparison / apply
surfaces (Runs 134/136/138/150/152) are not weakened. DevNet/TestNet
peer-driven apply evidence from Runs 153 / 158 remains valid.
**MainNet remains refused for peer-driven apply.** Governance,
KMS/HSM, and validator-set rotation remain unimplemented. Full
**C4** is not closed; **C5** is not closed. Release-binary lifecycle
evidence is **deferred to Run 160**.

## Scope (strict)

Run 159 is bound by the following constraints, all enforced in the
patch:

* Source/test only.
* No release-binary evidence.
* No MainNet peer-driven apply enablement.
* No governance implementation.
* No KMS/HSM implementation.
* No validator-set rotation.
* No autonomous peer-driven apply.
* No automatic apply on receipt.
* No peer-majority authority.
* No new wire format.
* No trust-bundle schema change.
* No authority-marker schema change.
* No sequence-file schema change.
* No weakening of Runs 070, 130–158.
* No claim of full C4 / C5 closure.

## Source delta

Additive only:

* `crates/qbind-node/src/pqc_authority_lifecycle.rs` — new module
  exposing:
  * `LocalLifecycleAction { ActivateInitial, Rotate, Retire, Revoke, EmergencyRevoke }`;
  * `AuthorityTrustDomain` — the per-domain binding bundle (env,
    chain_id, genesis_hash, authority-root fingerprint+suite_id);
  * `AuthorityLifecycleTransitionOutcome` — typed accept/reject
    surface (initial accepted, rotation accepted, retirement
    accepted, revocation accepted, emergency revocation accepted,
    idempotent, lower-sequence rejected, same-sequence conflicting
    digest rejected, wrong-environment / wrong-chain / wrong-genesis
    / wrong-authority-root rejected, wrong-previous-key rejected,
    revoked-key-reuse rejected, retired-key-reuse rejected,
    unsupported-lifecycle-action rejected, malformed-revoked-metadata
    rejected, non-PQC suite rejected, structurally-malformed rejected,
    initial-after-persisted rejected, v1-persisted-v2-candidate-not-supported);
  * `validate_v2_lifecycle_transition(persisted, candidate, trust_domain)` —
    pure typed validator; performs no I/O; never mutates persisted
    bytes; never writes the sequence file; never touches a live
    trust bundle.
* `crates/qbind-node/src/lib.rs` — new `pub mod pqc_authority_lifecycle;`
  declaration with a Run 159 scope comment.

No existing module is modified.

The local sub-classification of the on-wire `Revoke` byte into
`Revoke / Retire / EmergencyRevoke` is realised purely as a Run 159
**local interpretation** of the existing optional lowercase-hex
`revoked_key_metadata` field (validated by
`PersistentAuthorityStateRecordV2::validate_structure`):

| sub-class           | first 2 hex chars (1 byte) of `revoked_key_metadata` |
| ------------------- | ---------------------------------------------------- |
| `Revoke`            | `01`                                                 |
| `Retire`            | `02`                                                 |
| `EmergencyRevoke`   | `03`                                                 |

The wire format and the on-disk marker schema are unchanged.

## Tests

`crates/qbind-node/tests/run_159_authority_signing_key_lifecycle_tests.rs`
covers the required matrix:

* **A1** initial active signing key accepted (no persisted marker; pure
  validator does not write).
* **A2** planned rotation accepted under correct previous-key binding
  and higher sequence.
* **A3** idempotent same-record acceptance (no mutation).
* **A4** retirement of a previous signing key accepted under higher
  sequence, audit-only (active key preserved).
* **A5** revocation accepted under higher sequence with well-formed
  metadata.
* **A6** emergency revocation accepted under higher sequence with
  emergency-prefixed metadata; still requires valid environment /
  chain / genesis / authority-root binding.
* **R1** lower-sequence lifecycle candidate rejected as rollback.
* **R2** same-sequence different digest rejected as equivocation.
* **R3** wrong environment rejected.
* **R4** wrong chain rejected.
* **R5** wrong genesis rejected.
* **R6** wrong authority root rejected.
* **R7** wrong previous-key fingerprint rejected.
* **R8** revoked-key reuse rejected.
* **R9** retired-key reuse rejected (no overlap window defined; Run
  159 always rejects retired-key reuse).
* **R10** emergency revocation replay rejected (same- or lower-sequence
  replay surfaces as `SameSequenceConflictingDigestRejected` or
  `LowerSequenceRejected`).
* **R11** malformed revoked metadata rejected (unknown sub-class
  prefix; sub-class minimum length).
* **R12** non-PQC signing-key suite rejected (active-key suite and
  authority-root suite).
* **R13** unsupported lifecycle action rejected (Rotate/Revoke with no
  prior marker; second-Ratify after persisted).
* **R14** candidate that re-binds a revoked key as the new active key
  rejected through the lifecycle validator.
* **R15** local marker bytes preserved on rejected transitions
  (validator borrows immutably; persisted record is bit-for-bit
  unchanged).
* **R16** Run 134/136/138/150/152 marker comparison behavior unchanged
  (Run 159 is additive; canonical preimage / digest semantics for
  v2 markers are untouched).
* **R17** DevNet and TestNet covered; MainNet pure validation may
  parse a MainNet-bound fixture but Run 159 does **not** wire MainNet
  peer-driven apply to this validator. Cross-domain (MainNet
  candidate vs DevNet trust domain) is rejected.

A v1-persisted / v2-candidate refusal test asserts that Run 159 does
**not** perform the v1→v2 migration; the existing Run 131
`migrate_authority_marker_v1_to_v2` primitive remains the
authoritative path for that case.

29 tests total, all passing under `cargo test -p qbind-node --test
run_159_authority_signing_key_lifecycle_tests`.

## Integration with existing reload-apply / SIGHUP / drain helpers

The Run 134 / 136 / 138 / 150 / 152 marker comparison helpers
(`compare_authority_marker_v2`, `prepare_v2_marker_for_acceptance`,
`decide_marker_acceptance_v2`,
`persist_accepted_v2_marker_after_commit_boundary`) **continue to
own** the mutating-surface accept-and-persist composition for the v2
marker. Run 159 explicitly does **not** rewire those helpers.

The Run 159 validator is intentionally a *typed pre-flight* surface
that future runs can compose into the marker-comparison pipeline once
the wire format carries explicit `Retire` / `EmergencyRevoke` action
bytes (a wire-format question that Run 159 deliberately defers). For
that reason, existing marker-comparison test suites remain green
without modification.

## Validation commands

The following commands were run on this branch and all completed
successfully:

* `cargo build -p qbind-node --lib` — clean.
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
  — 29 passed; 0 failed.
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
  — 16 passed; 0 failed.
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
  — 23 passed; 0 failed.
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
  — 19 passed; 0 failed.
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
  — 20 passed; 0 failed.
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
  — 16 passed; 0 failed.
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
  — 5 passed; 0 failed.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
  — 11 passed; 0 failed.
* `cargo test -p qbind-node --lib pqc_authority`
  — 148 passed; 0 failed.

Run 158's `cargo test -p qbind-node --lib` baseline remains green
under the Run 159 patch; the Run 159 patch is purely additive and
does not modify any pre-existing module.

## Out of scope (intentionally deferred)

* Release-binary evidence for the lifecycle path → **Run 160**.
* MainNet peer-driven apply enablement.
* Governance.
* KMS/HSM.
* Validator-set rotation.
* Wire-level encoding of `Retire` / `EmergencyRevoke` as distinct
  action bytes (the existing `Ratify / Rotate / Revoke` byte-set is
  preserved unchanged).
* Full **C4** closure.
* **C5** closure.
