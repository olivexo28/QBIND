# QBIND DevNet Evidence — Run 162

## Subject

Run 162: **release-binary lifecycle enforcement evidence** for the
Run 159 typed v2 bundle-signing-key lifecycle validator
(`crates/qbind-node/src/pqc_authority_lifecycle.rs`,
`validate_v2_lifecycle_transition`,
`classify_local_lifecycle_action`, `AuthorityTrustDomain`,
`LocalLifecycleAction`, `AuthorityLifecycleTransitionOutcome`) now
that Run 161 has wired the validator into the **shared v2
marker-decision helper**
(`crates/qbind-node/src/pqc_authority_marker_acceptance.rs`,
`decide_marker_acceptance_v2`,
`MutatingSurfaceMarkerV2Error::LifecycleRejected`) used by:

1. Run 134 process-start reload-apply v2 marker path,
2. Run 136 startup `--p2p-trust-bundle` v2 marker path,
3. Run 138 SIGHUP live-reload v2 marker path,
4. Run 150 peer-driven apply drain marker decision,
5. Run 152 production drain `ProductionV2MarkerCoordinator`,
6. Run 132 reload-check / peer-candidate-check validation-only paths.

Run 162 is **release-binary evidence only**. It introduces no
production runtime source change. It does not modify wire format,
marker schema, sequence-file schema, peer-candidate envelope schema,
or trust-bundle schema, and it does not weaken any existing Run 070,
Run 055, or Run 130–161 acceptance / rejection behaviour.

## Verdict

**Run 162 captures release-binary lifecycle ENFORCEMENT evidence on
real `target/release/qbind-node`** through:

* a **validation-only** v2 marker-decision surface
  (`--p2p-trust-bundle-reload-check`), and
* a **mutating** v2 marker-decision surface
  (`--p2p-trust-bundle-reload-apply-path`).

Lifecycle accepts (`ActivateInitial`, `Rotate`, `Idempotent`) and
lifecycle rejects (`lower-sequence`, `same-sequence different-digest`,
`wrong environment`, `wrong chain`, `wrong genesis`, `corrupted local
marker`, and the PQC-verifier surrogate for `non-PQC suite`) are
observable on the real release binary; rejected candidates produce no
live trust swap, no session eviction, no Run 055 sequence write, no v2
marker write, no `.tmp` residue, no fallback to `--p2p-trusted-root`,
and no active `DummySig` / `DummyKem` / `DummyAead`. Mutating accepted
candidates preserve the `validate → snapshot → swap → evict_sessions →
commit_sequence` pipeline (Run 070) and persist the v2 marker strictly
**after** the Run 055 sequence commit (Run 134 §B.3 post-commit
boundary).

Run 162 **explicitly supersedes Run 160's "zero production caller"
partial-positive boundary**: a `grep -nE
'validate_v2_lifecycle_transition|LifecycleRejected'` over
`crates/qbind-node/src/**.rs` now returns hits in
`pqc_authority_marker_acceptance.rs` (where Run 161 added the
production call site and the matching typed-reject constructor), and
that helper is the one the release binary's reload-check / reload-apply
/ SIGHUP / startup / peer-driven drain paths invoke.

**MainNet remains refused** for peer-driven apply (cited from Run 151 /
Run 158 release-binary evidence; this harness does not enable MainNet
on any surface). **Governance, KMS/HSM, and validator-set rotation
remain unimplemented.** Full **C4** is **NOT** claimed; **C5** remains
**OPEN**.

## Scope (strict)

Run 162 is bound by the following constraints, all enforced in the
patch:

* Release-binary evidence only.
* Use real `target/release/qbind-node`.
* Use release-built helpers (`run_133_v2_validation_only_fixture_helper`
  + `run_160_authority_lifecycle_fixture_helper`) to mint lifecycle
  fixtures.
* No new production behavior; only a release-binary harness, an
  evidence archive, a canonical evidence report, and four narrow doc
  alignments.
* No MainNet apply enablement.
* No governance implementation.
* No KMS/HSM implementation.
* No validator-set rotation.
* No autonomous apply.
* No automatic apply on receipt.
* No peer-majority authority.
* No wire-format change (the on-wire `BundleSigningRatificationV2Action`
  byte set `Ratify=0` / `Rotate=1` / `Revoke=2` is unchanged).
* No marker schema change (`PersistentAuthorityStateRecordV2` fields
  unchanged).
* No sequence-file schema change.
* No trust-bundle schema change.
* Runs 070, 130–161 are **not** weakened.
* No claim of full **C4** or **C5** closure.

## Implementation summary

### Source delta

* **No production runtime source change.**
* Additive deliverables only:
  * `scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`
    — new release-binary harness;
  * `docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/`
    — new evidence archive (only `README.md` + `summary.txt` are
    tracked; everything else is `.gitignore`d, mirroring the
    Run 153 / 155 / 156 / 158 / 160 precedent);
  * `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_162.md` — this file;
  * narrow alignment updates to `docs/whitepaper/contradiction.md`,
    `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
    `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
    `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

### Why the release binary is now lifecycle-reachable

Run 161 wired `validate_v2_lifecycle_transition` into
`decide_marker_acceptance_v2`. Every existing v2 marker-decision call
site in the production binary therefore now exercises the lifecycle
validator on every accepted-or-rejected v2 ratification:

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

The Run 162 harness exercises the two simplest deterministic surfaces —
`--p2p-trust-bundle-reload-check` (Run 132 dispatch, validation-only)
and `--p2p-trust-bundle-reload-apply-path` (Run 134 dispatch,
mutating) — because (per the task's preferred minimal matrix) they are
easier to drive deterministically than long-running SIGHUP or live
`0x05`. The same `decide_marker_acceptance_v2` is the gate for SIGHUP
(Run 138), startup `--p2p-trust-bundle` (Run 136), peer-driven drain
(Run 150 / Run 152), and live inbound `0x05` (Run 142); Run 161
source/test coverage already proves those paths route through the same
helper at the source level.

### Reachability proof — Run 160 boundary explicitly superseded

The harness writes
`docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/reachability/src_grep.txt`
with the result of:

```text
grep -nE 'validate_v2_lifecycle_transition|LifecycleRejected' \
     crates/qbind-node/src/*.rs
```

The relevant production hits are:

```text
crates/qbind-node/src/pqc_authority_marker_acceptance.rs: ... LifecycleRejected ... // typed reject variant declared
crates/qbind-node/src/pqc_authority_marker_acceptance.rs: ... validate_v2_lifecycle_transition ... // production call site
```

These are **production callers** in the same module whose
`decide_marker_acceptance_v2` is invoked from `main.rs` (reload-apply
v2; startup `--p2p-trust-bundle` v2), `pqc_live_trust_reload.rs`
(SIGHUP v2), and `pqc_peer_candidate_apply.rs` (peer-driven drain v2).
Run 160's `call_graph/reachability.txt` recorded **zero** production
callers; Run 162 explicitly supersedes that boundary.

## Surfaces, scenarios, expected outcomes

### A. Validation-only `reload-check` (Run 132 dispatch)

| ID                                     | Lifecycle                    | Setup                                              | Expected stderr marker                                                                          | Mutation? |
|----------------------------------------|------------------------------|----------------------------------------------------|-------------------------------------------------------------------------------------------------|-----------|
| `A_A1_reload_check_initial_accept`     | A1 ActivateInitial accept    | v2 ratify@seq=1; no persisted marker               | `[run-132] reload-check v2 authority-marker check passed: no-persisted-marker-yet`              | NONE      |
| `A_A2_reload_check_rotate_accept`      | A2 Rotate accept             | v2 rotate@seq=2; persisted v2-seq=1                | `[run-132] reload-check v2 authority-marker check passed: v2 upgrade-compatible 1 -> 2`         | NONE      |
| `A_A6_reload_check_idempotent_accept`  | A6 Idempotent accept         | v2 ratify@seq=1; persisted v2-seq=1 (same digest)  | `[run-132] reload-check v2 authority-marker check passed: v2 idempotent`                        | NONE      |
| `A_R1_reload_check_lower_sequence`     | R1 lower-sequence reject     | v2 ratify@seq=1; persisted v2-seq=2                | `Run 132: v2 lower sequence refused`                                                            | NONE      |
| `A_R2_reload_check_equivocation`       | R2 same-seq different-digest | v2 ratify@seq=1 (rotated); persisted v2-seq=1      | `Run 132: v2 same-sequence different-digest refused`                                            | NONE      |
| `A_R3_reload_check_wrong_environment`  | R3 wrong environment         | v2 sidecar with wrong env field                    | `environment mismatch`                                                                          | NONE      |
| `A_R4_reload_check_wrong_chain`        | R4 wrong chain               | v2 sidecar with wrong chain id                     | `chain_id mismatch`                                                                             | NONE      |
| `A_R5_reload_check_wrong_genesis`      | R5 wrong genesis             | v2 sidecar with wrong genesis hash                 | `genesis_hash does not match runtime canonical genesis hash`                                    | NONE      |
| `A_R12_reload_check_bad_signature`     | R12 surrogate (PQC verifier) | v2 sidecar with tampered signature                 | `signature failed ML-DSA-44 PQC verification`                                                   | NONE      |

### B. Mutating `reload-apply` (Run 134 dispatch)

| ID                                     | Lifecycle                          | Setup                                            | Expected stderr marker                                                                                                                            | Mutation                                                                                  |
|----------------------------------------|------------------------------------|--------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|
| `B_A1_reload_apply_initial_accept`     | A1 ActivateInitial accept          | v2 ratify@seq=1; no persisted marker             | `[run-134] reload-apply v2 ratification path SELECTED` + `trust-bundle candidate APPLIED live` + `sequence_commit=ok` + `VERDICT=applied` + `[run-134] v2 authority-marker persisted ... candidate latest_authority_domain_sequence=1` | sequence advances to 1; v2 marker persisted POST-commit (record_version=2; latest_lifecycle_action=ratify) |
| `B_A2_reload_apply_rotate_accept`      | A2 Rotate accept                   | v2 rotate@seq=2; persisted v2-seq=1              | same SELECTED + APPLIED + commit_ok + applied + `... candidate latest_authority_domain_sequence=2`                                                | sequence advances 1→2; v2 marker persisted POST-commit (record_version=2; latest_lifecycle_action=rotate)  |
| `B_A6_reload_apply_idempotent_accept`  | A6 Idempotent accept (no rewrite)  | v2 ratify@seq=1; persisted v2-seq=1 (same)       | `[run-134] v2 authority-marker unchanged ... idempotent; no rewrite`                                                                              | sequence file present; v2 marker bytes byte-identical to seed                            |
| `B_R1_reload_apply_lower_sequence`     | R1 lower-sequence                  | v2 ratify@seq=1; persisted v2-seq=2              | `[run-134] FATAL: reload-apply refused by v2 authority-marker preflight` + `LowerV2SequenceRefused`                                              | NONE — pre-seeded v2-seq=2 marker preserved bit-for-bit; no sequence write               |
| `B_R2_reload_apply_equivocation`       | R2 same-seq different-digest       | v2 equivocation; persisted v2-seq=1              | `... preflight refused` + `SameSequenceConflicting`                                                                                                | NONE                                                                                      |
| `B_R3_reload_apply_wrong_environment`  | R3 wrong environment               | v2 sidecar wrong env                              | `... preflight refused` + `environment mismatch`                                                                                                   | NONE                                                                                      |
| `B_R12_reload_apply_bad_signature`     | R12 surrogate (PQC verifier)       | v2 sidecar tampered                               | `... preflight refused` + `signature failed ML-DSA-44 PQC verification`                                                                            | NONE                                                                                      |
| `B_R14_reload_apply_corrupted_marker`  | R14 corrupted local marker         | unparseable on-disk pqc_authority_state.json     | `FATAL`/`refused`/`failed to load`/`deserialize`                                                                                                   | NONE — corrupted marker bytes preserved bit-for-bit                                      |

For every mutating accept (B.A1, B.A2, B.A6) the harness asserts:

* lifecycle validation runs **before** any live trust mutation;
* Run 070 apply succeeds (`trust-bundle candidate APPLIED live`);
* Run 055 sequence commit succeeds (`sequence_commit=ok`);
* the v2 marker persists **strictly after** the sequence commit
  (`[run-134] v2 authority-marker persisted` follows `APPLIED live`);
* `record_version=2` is in the post-run marker JSON;
* `latest_authority_domain_sequence` matches the candidate sequence;
* `latest_lifecycle_action` matches the wire-byte action;
* marker SHA-256 before+after captured under `marker_hashes/`;
* sequence SHA-256 after captured under `sequence_hashes/`;
* the data-dir inventory is captured under `data_inventories/`;
* no `pqc_authority_state.json.tmp` sibling is left behind;
* no `Run 161: v2 authority-marker lifecycle transition rejected ...`
  line is emitted on the accept path.

For every reject scenario (validation-only or mutating) the harness
asserts:

* binary exits non-zero (rc=1);
* a precise marker / lifecycle rejection line is on stderr (one of
  the Run 132 `VERDICT=invalid` family, the Run 134 `FATAL: reload-
  apply refused by v2 authority-marker preflight`, or the Run 161
  `Run 161: v2 authority-marker lifecycle transition rejected by Run
  159 validator: ...`, depending on which decision the helper reaches
  first);
* no live trust swap (no `trust-bundle candidate APPLIED live`);
* no session eviction (no `session_evictions=N≥1`);
* no Run 055 sequence write (no `pqc_trust_bundle_sequence.json`);
* no v2 marker write (no `pqc_authority_state.json` created when none
  was seeded; pre-seeded marker bytes preserved bit-for-bit when one
  was);
* no `.tmp` residue;
* no `falling back to --p2p-trusted-root`;
* no `active DummySig` / `active DummyKem` / `active DummyAead`.

## Lifecycle actions remaining source/test-only on release binary today

These actions and reject cases are not directly representable through
the existing reload-check / reload-apply CLI surfaces because the
Run 159 lifecycle sub-class is encoded as the **first byte of
`revoked_key_metadata`** in the persisted v2 marker and there is no CLI
surface today to mint a sub-class-prefixed persisted marker via the
release binary alone. They remain covered by the Run 159 source/test
suite (`crates/qbind-node/tests/run_159_authority_signing_key_lifecycle_tests.rs`)
and by the Run 161 source/test integration suite
(`crates/qbind-node/tests/run_161_lifecycle_marker_integration_tests.rs`)
running on release-built test binaries:

* **A3 Retire accepted** — sub-class prefix `02` in the persisted
  marker. Cite Run 159 A3 + Run 161 A6.
* **A5 EmergencyRevoke accepted** — sub-class prefix `03`. Cite
  Run 159 A5 + Run 161 A8.
* **R6 wrong authority root rejected** — derived candidate
  authority-root fingerprint is a deterministic function of the
  baseline trust bundle's root; the existing fixture helper does not
  mint a wrong-root variant. Cite Run 159 R6 + Run 161 R6.
* **R7 wrong previous key rejected** — sub-class linkage on rotation;
  the persisted marker's `previous_authority_signing_key_fingerprint`
  field is decided at marker comparison time. Cite Run 159 R7 +
  Run 161 R7.
* **R8 revoked-key reuse rejected** — requires a sub-class-prefixed
  persisted marker. Cite Run 159 R8 + Run 161 R8.
* **R9 retired-key reuse rejected** — same. Cite Run 159 R9 + Run 161 R9.
* **R10 emergency revocation replay rejected** — same. Cite Run 159 R10 +
  Run 161 R10.
* **R11 malformed revoked metadata rejected** — same. Cite Run 159 R11 +
  Run 161 R11.
* **R12 non-PQC suite rejected** — Run 130 verifier rejects non-PQC
  suites earlier than the Run 159 lifecycle layer; the release-binary
  surrogate for R12 is the tampered-signature scenario which fails the
  ML-DSA-44 verification. Cite Run 159 R12 for the lifecycle-layer
  refusal of non-PQC suite ids.
* **R13 unsupported lifecycle action byte** — pinned at the wire-byte
  enum (`Ratify=0`, `Rotate=1`, `Revoke=2`); any unknown byte fails
  decode at the wire layer. No additional release-binary scenario is
  required.

The Run 162 reachability proof + the Run 161 wiring mean those
source/test results are now **claims about the production code path
the release binary actually executes**, not claims about a dead-code
module (which was the Run 160 boundary).

## R15: MainNet remains refused

This harness does **not** enable MainNet on any surface. MainNet
peer-driven apply refusal (`Run 151: FATAL`) is captured by Run 151's
release-binary harness and is **re-evidenced** by Run 158's positive
TestNet release-binary harness, which drives MainNet refusal
(`R2_mainnet_refused`) on the same `target/release/qbind-node` binary
type. Run 162 cites that prior evidence rather than duplicating it.

## Captured metadata

`docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/provenance.txt`
records:

* git commit hash;
* `rustc` / `cargo` versions;
* `target/release/qbind-node` SHA-256 + ELF Build ID;
* `target/release/examples/run_133_v2_validation_only_fixture_helper`
  SHA-256 + ELF Build ID;
* `target/release/examples/run_160_authority_lifecycle_fixture_helper`
  SHA-256 + ELF Build ID;
* the harness's `OUTDIR` and repo root.

`fixture_manifest.txt` records the SHA-256 of every minted fixture
file. `marker_hashes/`, `sequence_hashes/`, `data_inventories/`,
`exit_codes/`, `logs/`, `grep_summaries/`, and `reachability/`
contain the per-scenario captures defined above.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_160_authority_lifecycle_fixture_helper`
* `cargo build --release -p qbind-node --example run_133_v2_validation_only_fixture_helper`
* `bash scripts/devnet/run_162_authority_lifecycle_release_binary_enforcement.sh`
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests`
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

If any exact test name has been renamed by a future run, the operator
should locate the nearest existing target by the same Run NNN prefix
and capture the substitution in the harness's per-run logs.

## Documentation alignment

* `docs/whitepaper/contradiction.md` — Run 162 paragraph appended.
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_162.md` — this file.
* `docs/devnet/run_162_authority_lifecycle_release_binary_enforcement/{README.md,summary.txt,.gitignore}`
  — evidence archive (only `README.md` + `summary.txt` are tracked).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 162 entry:
  operators have **no new CLI surface** and **no new runtime
  behaviour**; the lifecycle validator is now exercisable on release
  binaries via the existing `--p2p-trust-bundle-reload-check` and
  `--p2p-trust-bundle-reload-apply-path` flags through
  `decide_marker_acceptance_v2`.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
  Run 162 entry: the six-phase fail-closed pipeline is **unchanged**;
  the lifecycle validator is now release-binary-reachable on the
  reload-check (validation-only) and reload-apply (mutating) v2
  marker-decision surfaces; SIGHUP / startup / peer-driven drain
  source/test coverage from Run 161 is now backed by release-binary
  evidence on the *same* helper.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 162
  entry: the authority model is **unchanged**; lifecycle transitions
  are now demonstrably enforceable through production v2
  marker-decision surfaces on real release binaries; MainNet remains
  refused unconditionally.

## Crosscheck against existing design / spec

Run 162 introduces no contradictions because:

1. The wire format, sidecar schema, marker schema, sequence-file
   schema, and peer-candidate envelope schema are all unchanged.
2. The Run 134 / 136 / 138 / 150 / 152 marker-comparison and
   accept-and-persist composition is preserved bit-for-bit; Run 161
   added the typed pre-mutation lifecycle gate inside the existing
   helper without changing any caller signature.
3. Run 070 apply ordering, Run 055 anti-rollback, Run 065 / Run 091
   activation gates, Run 076 / Run 079 / Run 088 envelope /
   propagation discipline, Run 109 / Run 123 v1 enforcement, Run 130
   / Run 131 v2 verifier and marker primitives, Run 132 / Run 142
   validation-only paths, Run 134 / Run 136 / Run 138 post-commit
   marker discipline, Run 140 / Run 141 snapshot / restore parity,
   the Run 144 safety specification's six-phase fail-closed pipeline,
   and the Run 145–158 staging / apply / drain / fixture surfaces
   are all untouched.
4. MainNet drain-once refusal, no autonomous peer-driven apply, no
   automatic apply on receipt, no peer-majority authority, no
   governance, no KMS / HSM, no validator-set rotation, and no
   static production MainNet anchor are all preserved.
5. DevNet evidence from Run 153, TestNet evidence from
   Runs 154 / 155 / 157 / 158, Run 159 source/test lifecycle
   coverage, Run 160's release-binary fixture-corpus boundary, and
   Run 161's source/test integration coverage all remain valid.
   Run 160's claim "the validator has zero production callers" is
   now historically superseded by Run 162; Run 160's release-binary
   fixture corpus + provenance + per-suite test outcomes are
   unchanged.

No contradictions or inconsistencies were found that required a new
entry in the contradiction registry beyond the standard Run 162
paragraph which records the boundary supersession.

## Acceptance against the task acceptance criteria

1. **Real release binaries exercise lifecycle validation through
   production v2 marker-decision surfaces** — yes; both
   `--p2p-trust-bundle-reload-check` (Run 132) and
   `--p2p-trust-bundle-reload-apply-path` (Run 134) route through
   `decide_marker_acceptance_v2`, which now invokes
   `validate_v2_lifecycle_transition` per Run 161.
2. **At least one validation-only and one mutating surface are
   covered** — yes; the harness drives the preferred minimal matrix
   (`reload-check` + `reload-apply`).
3. **Lifecycle accepts and rejects are visible in release-binary
   evidence** — yes; A1 / A2 / A6 accepts and R1 / R2 / R3 / R4 / R5
   / R12-surrogate / R14 rejects on the release binary.
4. **Rejected lifecycle candidates produce no mutation** — yes;
   `assert_no_mutation_validation` and `assert_no_mutation_apply`
   verify no sequence write, no marker write, no `.tmp` residue, no
   live trust swap, no session eviction, and no fallback.
5. **Mutating accepted candidates preserve sequence-before-marker
   ordering** — yes; the Run 134 `v2 authority-marker persisted`
   line is verified to follow the Run 070 `APPLIED live` and
   `sequence_commit=ok` lines on every accepted apply scenario.
6. **Run 160's zero-call-site boundary is explicitly superseded** —
   yes; the harness writes the supersession record in
   `reachability/reachability.txt` and asserts the production grep
   hits.
7. **MainNet remains refused** — yes; this harness does not enable
   MainNet on any surface, and the standard MainNet-refusal banner is
   excluded from the denylist match the same way it is in
   Run 153 / 155 / 156 / 158 / 160.
8. **Governance / KMS-HSM / validator-set rotation remain open** —
   yes; no governance, KMS / HSM, or validator-set rotation surface
   is added by Run 162.
9. **No full C4 or C5 closure is overclaimed** — yes; full **C4** is
   explicitly NOT claimed; **C5** remains explicitly OPEN.

## Out of scope (deferred)

* Sub-class-metadata-driven Retire / EmergencyRevoke release-binary
  acceptance evidence (and the corresponding R6–R11 rejection
  scenarios that depend on sub-class-prefixed persisted markers) —
  cited from Run 159 + Run 161 source/test coverage; would require a
  CLI or fixture surface to mint a sub-class-prefixed persisted
  marker and is not in the Run 162 minimal-matrix scope.
* MainNet peer-driven apply enablement — out of scope; remains
  refused by `PeerDrivenApplyPolicy::mainnet_attempted`.
* Governance for the lifecycle action set — open.
* KMS / HSM-bound authority signer — open.
* Validator-set rotation coupling — open.
* Full **C4** closure — open.
* **C5** closure — open.
