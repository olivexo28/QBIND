# QBIND DevNet Evidence — Run 161

## Subject

Run 161: **source/test integration** wiring the Run 159 typed v2
bundle-signing-key lifecycle validator
(`crates/qbind-node/src/pqc_authority_lifecycle.rs`,
`validate_v2_lifecycle_transition`,
`classify_local_lifecycle_action`, `AuthorityTrustDomain`,
`LocalLifecycleAction`, `AuthorityLifecycleTransitionOutcome`) into
the **shared v2 marker-decision helper**
(`crates/qbind-node/src/pqc_authority_marker_acceptance.rs`,
`decide_marker_acceptance_v2`) used by:

1. Run 134 process-start reload-apply v2 marker path,
2. Run 136 startup `--p2p-trust-bundle` v2 marker path,
3. Run 138 SIGHUP live-reload v2 marker path,
4. Run 150 peer-driven apply drain marker decision,
5. Run 152 production drain `ProductionV2MarkerCoordinator`.

Run 161 is **source/test integration only**. It does **not** capture
release-binary lifecycle evidence — that is **deferred to Run 162**.
It does **not** modify wire format, marker schema, sequence-file
schema, or trust-bundle schema, and it does **not** weaken any
existing Run 070 or Run 130–160 acceptance / rejection behaviour.

## Verdict

**Run 161 wires the Run 159 lifecycle validator into the production
v2 marker-decision helper** so that lifecycle transitions become
enforceable on every existing v2 mutating surface (reload-apply,
startup, SIGHUP, peer-driven drain) and on every existing v2
validation-only surface (reload-check, peer-candidate-check, live
`0x05`) without disk writes. The Run 159 typed reject variants are
surfaced through the existing
`MutatingSurfaceMarkerV2Error` enum via a new
`LifecycleRejected(AuthorityLifecycleTransitionOutcome)` variant.
Existing v2 anti-rollback semantics (lower sequence, same-sequence
equivocation, wrong env/chain/genesis/authority-root, v1-after-v2,
malformed/unsupported markers) remain unchanged and continue to
report through the same precise error variants.

**MainNet remains refused** for peer-driven apply. **Governance,
KMS/HSM, and validator-set rotation remain unimplemented.** Full
**C4** is not closed; **C5** is not closed. Release-binary lifecycle
evidence is **deferred to Run 162**.

## Scope (strict)

Run 161 is bound by the following constraints, all enforced in the
patch:

* Source/test only.
* No release-binary harness in this run.
* No MainNet peer-driven apply enablement.
* No governance implementation.
* No KMS/HSM implementation.
* No validator-set rotation.
* No autonomous apply.
* No automatic apply on receipt.
* No peer-majority authority.
* No wire-format change (the on-wire
  `BundleSigningRatificationV2Action` byte set
  `Ratify (0)` / `Rotate (1)` / `Revoke (2)` is unchanged).
* No marker schema change (no new fields on
  `PersistentAuthorityStateRecordV2`).
* No sequence-file schema change.
* No trust-bundle schema change (no hard blocker found).
* Runs 070, 130–160 are **not** weakened.
* No claim of full **C4** or **C5** closure.

## Implementation summary

### Source wiring

The single integration point is the existing shared helper
`decide_marker_acceptance_v2`:

```text
verified v2 ratification
  → derive v2 candidate marker (Run 131)
  → load persisted versioned marker (Run 117/118/120)
  → compare v2 candidate vs persisted (Run 118/120, Run 134)
  → [Run 161] validate_v2_lifecycle_transition(persisted, candidate, trust_domain)
  → typed accept-or-reject decision (Run 134/161)
  → [caller performs Run 070 apply + Run 055 commit_sequence]
  → persist marker AFTER commit_sequence (Run 117/119/134)
```

Because Run 134/136/138/150/152 all call `decide_marker_acceptance_v2`
through this single helper, lifecycle validation reaches every
mutating surface without per-surface duplication and without any
new caller signature.

### Trust-domain binding

The integrated `AuthorityTrustDomain` is constructed from the
candidate's environment / chain id / genesis hash / authority root
fingerprint / authority root suite id. The candidate's environment,
chain id, and genesis hash are already cross-validated against the
runtime via Run 131 derivation; the candidate's authority root is
already cross-validated against the persisted marker via the Run
118/120 comparison. The lifecycle layer therefore enforces only the
**additional** lifecycle properties (PQC suite, lifecycle action
classification, previous-key linkage, revoked-key / retired-key
reuse, malformed metadata, emergency replay) without weakening the
existing trust-domain binding.

### Mandatory ordering (preserved bit-for-bit)

* `decide_marker_acceptance_v2` performs no disk writes.
* Lifecycle validation runs **before** any live trust mutation.
* Marker persistence remains strictly **after** Run 055 sequence
  commit via
  `persist_accepted_v2_marker_after_commit_boundary`.
* If lifecycle validation fails, Run 070 apply does **not** begin
  (the helper returns `Err`, the caller drops the unaccepted
  decision).
* If Run 070 apply fails before sequence commit, no marker persist.
* If marker persist fails after sequence commit, the existing
  fatal/operator-actionable behaviour is retained verbatim.

### Back-compat exceptions (R20)

Two Run 159 typed reject variants are passed through to the
existing comparison decision rather than escalated:

1. `InitialActivationAfterPersistedRejected` — Pre-Run-161 fixtures
   re-issue the wire byte `Ratify` on every accepted advancement
   (FirstWrite / Idempotent / HigherSequence). The existing v2
   marker schema's anti-rollback compare already enforces sequence
   monotonicity / digest equivocation safety on these
   `Ratify`-after-persisted advancements; treating them as a Run 159
   reject would weaken the very runs (134/136/138/150/152) Run 161
   is wiring lifecycle into.
2. `V1PersistedV2CandidateNotSupportedHere` — Run 131's explicit
   v1→v2 migration boundary. Run 159 deliberately does not validate
   v1→v2 transitions; the marker-decision layer continues to use
   the Run 131 outcome unchanged.

All other Run 159 reject variants are fail-closed and surface as
`MutatingSurfaceMarkerV2Error::LifecycleRejected(_)`.

## Tests

Source/test coverage lives in:

* `crates/qbind-node/tests/run_161_lifecycle_marker_integration_tests.rs`

29 tests cover the full A1–A9 acceptance and R1–R20 rejection
matrix:

* **A1** ActivateInitial accepted (no persisted marker).
* **A2** Rotate accepted on the reload-apply path.
* **A3** Rotate accepted on the startup path.
* **A4** Rotate accepted on the SIGHUP path.
* **A5** Rotate accepted through the Run 152
  `ProductionV2MarkerCoordinator` (peer-driven drain).
* **A6** Retire / **A7** Revoke / **A8** EmergencyRevoke routed
  through the integrated lifecycle validator (proving the wire-byte
  `Revoke` ratification reaches the Run 159 sub-class classifier in
  the marker-decision layer).
* **A9** Idempotent same-record acceptance (`should_persist=false`,
  no rewrite).
* **R1** Lower-sequence lifecycle candidate rejected before apply.
* **R2** Same-sequence different-digest equivocation rejected.
* **R3–R6** Wrong environment / chain / genesis / authority-root
  rejected.
* **R7** Wrong previous key rejected.
* **R8** Revoked-key reuse rejected.
* **R9** Retired-key reuse rejected (no overlap defined).
* **R10** Emergency revocation replay rejected.
* **R11** Malformed revoked metadata rejected.
* **R12** Non-PQC suite path is validator-routed.
* **R13** Unsupported lifecycle action byte pinned (wire enum is
  exactly `Ratify` / `Rotate` / `Revoke`).
* **R14** Corrupted local marker rejected fail-closed.
* **R15** Reload-apply lifecycle reject produces no Run 070 call
  and no marker write.
* **R16** Startup lifecycle reject produces no marker write.
* **R17** SIGHUP lifecycle reject produces no live trust swap, no
  eviction, no sequence write, and no marker write.
* **R18** Peer-driven drain lifecycle reject through the Run 152
  coordinator produces no apply, no swap, no eviction, no sequence
  write, and no marker write.
* **R19** Validation-only surfaces remain non-mutating (decide-and-
  drop leaves the on-disk marker bit-for-bit unchanged for both
  accept and reject cases).
* **R20** Existing `Ratify`-after-persisted advancements remain
  accepted as `UpgradeV2`.

## Regression coverage

The following pre-existing test targets remain green at the source
level:

* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests` — 29 tests.
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` — 5 tests.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests` — 11 tests.
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests` — 19 tests.
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests` — 23 tests.
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` — 16 tests.
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` — 20 tests.
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests` — 16 tests.
* `cargo test -p qbind-node --lib pqc_authority` — 148 tests.
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests` — 29 tests.

## Acceptance against the task acceptance criteria

1. **`validate_v2_lifecycle_transition` has production `src` call
   sites outside `pqc_authority_lifecycle.rs`** — yes, in
   `crates/qbind-node/src/pqc_authority_marker_acceptance.rs`
   (`decide_marker_acceptance_v2`).
2. **Lifecycle validation is composed into shared v2 marker
   decision/preflight paths** — yes, single integration point inside
   the shared helper used by Run 134/136/138/150/152.
3. **Startup, reload-apply, SIGHUP, and peer-driven drain paths are
   covered at source/test level** — yes, A2/A3/A4/A5 + R15/R16/R17/R18.
4. **Validation-only paths remain non-mutating** — yes, R19.
5. **Mutating paths still persist v2 marker only after sequence
   commit** — yes, the persist primitive is unchanged and only
   reachable via
   `persist_accepted_v2_marker_after_commit_boundary`.
6. **Lifecycle rejects prevent apply/mutation before Run 070
   starts** — yes, `decide_marker_acceptance_v2` returns `Err`
   before the orchestrator begins apply.
7. **Existing v2 anti-rollback behavior is not weakened** — yes;
   the comparison primitives and their reject variants are unchanged
   and are exercised end-to-end by the existing Run 134/136/138/150/152
   regression suites.
8. **MainNet remains refused** — yes; no MainNet apply path is
   enabled by Run 161.
9. **Governance/KMS-HSM/validator-set rotation remain open** — yes;
   no governance, KMS/HSM, or validator-set rotation surface is
   added.
10. **Docs defer release-binary lifecycle evidence to Run 162** —
    yes; this evidence file and the contradiction registry both
    state the deferral.
11. **No full C4 or C5 closure is claimed** — yes; both remain
    explicitly open.

## Out of scope (deferred)

* Release-binary lifecycle evidence — **Run 162**.
* MainNet peer-driven apply enablement — out of scope; remains
  refused by `PeerDrivenApplyPolicy::mainnet_attempted`.
* Governance for the lifecycle action set — open.
* KMS/HSM-bound authority signer — open.
* Validator-set rotation coupling — open.
* Full **C4** closure — open.
* **C5** closure — open.
