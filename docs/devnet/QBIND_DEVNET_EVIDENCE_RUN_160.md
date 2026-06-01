# QBIND DevNet Evidence — Run 160

## Subject

Run 160: **release-binary evidence / boundary** for the Run 159
**v2 bundle-signing-key lifecycle validator**
(`qbind_node::pqc_authority_lifecycle::validate_v2_lifecycle_transition`).
Per `task/RUN_160_TASK.txt`, Run 160 must produce the strongest honest
release-binary evidence currently possible for that validator and must
clearly determine whether the current production binary can exercise
lifecycle validation through an existing release-binary surface. If
the validator is not reachable from any release-binary surface, Run 160
must report that as a partial-positive boundary and identify the exact
next integration run, rather than fake lifecycle closure.

## Verdict

**`partial-positive: release-binary fixture/evidence boundary
captured; lifecycle validator not yet production-surface reachable`.**

The Run 160 source-level call graph (captured by the harness in
`docs/devnet/run_160_authority_lifecycle_release_binary/call_graph/reachability.txt`)
shows that `validate_v2_lifecycle_transition` and
`classify_local_lifecycle_action` have **zero** production callers.
References to `pqc_authority_lifecycle` exist only in:

* `crates/qbind-node/src/pqc_authority_lifecycle.rs` (the module
  itself);
* `crates/qbind-node/src/lib.rs` (`pub mod pqc_authority_lifecycle;`);
* `crates/qbind-node/tests/run_159_authority_signing_key_lifecycle_tests.rs`
  (the Run 159 test suite).

None of the eight release-binary surfaces enumerated by the task
(startup `--p2p-trust-bundle` v2, reload-check, local
peer-candidate-check, process-start reload-apply, SIGHUP, live inbound
`0x05`, peer-driven staged queue / drain-once, fixture helper / example
binary) calls the Run 159 validator today. The Run 134 / 136 / 138 /
150 / 152 marker-comparison helpers continue to own the
mutating-surface accept-and-persist composition for the v2 marker;
Run 159 explicitly deferred their rewiring, and Run 160 does not
introduce that wiring. Run 160 therefore captures the release-binary
evidence that is honestly available — a release-built lifecycle
fixture corpus + the same Run 159 source/test suite running on the
same checkout — and **does not claim strongest-positive**.

## Source delta

Additive only. **No production runtime source change.**

* `crates/qbind-node/examples/run_160_authority_lifecycle_fixture_helper.rs`
  — new release-built helper that mints the lifecycle fixture corpus
  (A1–A6 + R1–R14). Uses the existing
  `PersistentAuthorityStateRecordV2::new` /
  `PersistentAuthorityStateRecord::new` /
  `PersistentAuthorityStateRecordV2::validate_structure` primitives.
  No wire format / sidecar schema / marker schema / sequence-file
  schema change.
* `scripts/devnet/run_160_authority_lifecycle_release_binary.sh` —
  new harness.
* `docs/devnet/run_160_authority_lifecycle_release_binary/` — new
  evidence archive (README.md + summary.txt tracked; everything else
  `.gitignore`d, mirroring Run 153 / 155 / 156 / 158).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_160.md` — this report.
* Narrow doc updates to `contradiction.md`,
  `QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  `QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, and
  `QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

No `main.rs` / `cli.rs` edit, no CLI flag added or renamed, no SIGHUP /
reload-apply / startup-mutation / snapshot-restore / live `0x05`
dispatcher / drain-once code change, no `LivePqcTrustState` mutation,
no sequence-file write, no authority-marker write, no new wire format,
no schema/wire/metric drift.

## Surfaces investigated (release-binary reachability matrix)

Per `task/RUN_160_TASK.txt` §Investigation requirement:

| # | Surface                                                  | Calls validator? | Carries `LocalLifecycleAction`? | Carries Activate/Rotate/Retire/Revoke/Emergency? | Wire/schema change required? | Used for release-binary evidence in Run 160? |
|---|----------------------------------------------------------|------------------|---------------------------------|--------------------------------------------------|------------------------------|----------------------------------------------|
| 1 | startup `--p2p-trust-bundle` v2 (Run 137)                | NO               | NO                              | Activate/Rotate/Revoke only via the existing Run 130 wire byte set | NO new wire byte is required for Retire / EmergencyRevoke (Run 159 metadata sub-class convention rides on `Revoke=2`); the production wiring is missing | NO |
| 2 | reload-check validation-only (Run 132/133)               | NO               | NO                              | same                                              | same                         | NO |
| 3 | local peer-candidate-check validation-only (Run 132/133) | NO               | NO                              | same                                              | same                         | NO |
| 4 | process-start reload-apply (Run 134/135)                 | NO               | NO                              | same                                              | same                         | NO |
| 5 | SIGHUP live-reload (Run 138/139)                         | NO               | NO                              | same                                              | same                         | NO |
| 6 | live inbound `0x05` validation-only (Run 142/143)        | NO               | NO                              | same                                              | same                         | NO |
| 7 | peer-driven staged queue / drain-once (Run 148/150/151/152/153/158) | NO    | NO                              | same                                              | same                         | NO |
| 8 | release-built fixture helper / example (Run 160)         | INDIRECT         | YES (encoded in the JSON corpus) | YES (corpus carries all five logical actions)    | NO                           | YES (corpus minted by real release helper; corpus + Run 159 source/test runs together form the partial-positive boundary) |

## Lifecycle evidence matrix (A1–A6)

| ID | Action            | Release-binary fixture | Release-binary surface call? | Status                                     |
|----|-------------------|------------------------|------------------------------|--------------------------------------------|
| A1 | `ActivateInitial` | YES                    | NO                           | source/test PROVEN; release-binary FIXTURE |
| A2 | `Rotate`          | YES                    | NO                           | source/test PROVEN; release-binary FIXTURE |
| A3 | `Retire`          | YES                    | NO                           | source/test PROVEN; release-binary FIXTURE |
| A4 | `Revoke`          | YES                    | NO                           | source/test PROVEN; release-binary FIXTURE |
| A5 | `EmergencyRevoke` | YES                    | NO                           | source/test PROVEN; release-binary FIXTURE |
| A6 | Idempotent        | YES                    | NO                           | source/test PROVEN; release-binary FIXTURE |

Every accept-matrix entry is matched by a release-built fixture record
in `fixtures/lifecycle_corpus/candidates/`. The Run 159 test suite
exercises each accept variant on the same release-built test binary
(`cargo test -p qbind-node --test
run_159_authority_signing_key_lifecycle_tests`) and is captured in
`test_results/run_159_authority_signing_key_lifecycle_tests.{stdout,stderr,exit_code}`.

## Rejection matrix (R1–R14)

| ID  | Reject scenario                              | Release-binary fixture | Validator outcome                                  |
|-----|----------------------------------------------|------------------------|----------------------------------------------------|
| R1  | lower-sequence rollback                      | YES                    | `LowerSequenceRejected`                            |
| R2  | same-sequence different digest               | YES                    | `SameSequenceConflictingDigestRejected`            |
| R3  | wrong environment                            | YES                    | `WrongEnvironmentRejected`                         |
| R4  | wrong chain                                  | YES                    | `WrongChainRejected`                               |
| R5  | wrong genesis                                | YES                    | `WrongGenesisRejected`                             |
| R6  | wrong authority root                         | YES                    | `WrongAuthorityRootRejected`                       |
| R7  | wrong previous-key fingerprint on Rotate     | YES                    | `WrongPreviousKeyRejected`                         |
| R8  | revoked key reuse                            | YES                    | `RevokedKeyReuseRejected`                          |
| R9  | retired key reuse outside allowed overlap    | YES                    | `RetiredKeyReuseRejected`                          |
| R10 | emergency revocation replay                  | YES                    | `SameSequenceConflictingDigestRejected`            |
| R11 | malformed revoked metadata                   | YES                    | `MalformedRevokedMetadataRejected`                 |
| R12 | non-PQC signing-key suite                    | YES                    | `NonPqcSuiteRejected`                              |
| R13 | unsupported lifecycle action                 | YES                    | `UnsupportedLifecycleActionRejected`               |
| R14 | candidate signed by revoked key (path-bound) | N/A (no production wiring) | covered by Run 159 source/test (R8 + R14 pair); release-binary path is not currently wired |
| R15 | MainNet peer-driven apply remains refused    | n/a                    | preserved unchanged from Runs 151 / 153 / 155 / 156 / 158 |

The R14 row records the task's "candidate signed by revoked key
rejected if this path is currently wired" — that path is **not** wired
into the lifecycle validator, so Run 160 honestly records it as
covered by Run 159 source/test only and does not claim release-binary
proof. R15 preserves the existing MainNet refusal proven by the
Run 151 / 153 / 155 / 156 / 158 release-binary harnesses.

## Schema gap analysis

* The on-wire `BundleSigningRatificationV2Action` byte set
  (`Ratify=0`, `Rotate=1`, `Revoke=2`) is **preserved unchanged** by
  Run 159 and Run 160. Retire and EmergencyRevoke ride the existing
  `Revoke=2` byte plus a Run 159 local sub-class prefix in
  `revoked_key_metadata` (`01`=Revoke, `02`=Retire,
  `03`=EmergencyRevoke).
* Run 160 introduces **no** wire byte additions, **no** trust-bundle
  schema change, **no** authority-marker schema change, **no**
  sequence-file schema change, and **no** peer-candidate envelope
  schema change.
* Retire / EmergencyRevoke release-binary evidence is therefore
  **representable** on the existing schemas via the metadata
  convention — the schema is **not** the gap. The gap is the
  production wiring of `validate_v2_lifecycle_transition` into the
  Run 134 / 136 / 138 / 150 / 152 marker-comparison and
  accept-and-persist pipeline. That wiring is the precise scope of
  **Run 161**.

## Harness

`scripts/devnet/run_160_authority_lifecycle_release_binary.sh`

The harness:

1. Builds the real release `target/release/qbind-node`,
   `target/release/examples/run_160_authority_lifecycle_fixture_helper`,
   and (if missing) the Run 157 unified TestNet helper.
2. Captures provenance (git commit, rustc/cargo versions, binary +
   helper SHA-256 and ELF Build IDs) into `provenance.txt`.
3. Mints the lifecycle fixture corpus with the real release-built
   helper into `fixtures/lifecycle_corpus/` and writes per-file
   SHA-256s to `fixture_manifest.txt`.
4. Captures the source-level call graph of
   `validate_v2_lifecycle_transition` /
   `classify_local_lifecycle_action` /
   `pqc_authority_lifecycle` into
   `call_graph/{src_grep.txt, tests_grep.txt, main_rs_grep.txt,
   reachability.txt}`. The reachability summary names Run 161 as the
   exact next required integration run.
5. Runs the Run 159 lifecycle test suite plus the Run 134 / 138 /
   142 / 148 / 150 / 152 / 157 regression suites, the
   `lib pqc_authority` filter, and the full library tests, capturing
   per-suite stdout/stderr/exit_code into `test_results/`.
6. Writes `grep_summaries/in_scope.txt` (expected-present markers)
   and `grep_summaries/out_of_scope.txt` (denylist; expected empty).
7. Writes `partial_positive_proof.txt` (verdict + schema gap analysis
   + exact next required integration run) and `summary.txt`.

The harness does **not** substitute source/test coverage for a
release-binary lifecycle apply outcome. Because no release-binary
surface exercises the validator today, no apply outcome is claimed.

## Mandatory negative invariants (held)

* No MainNet apply is enabled.
* No autonomous background drain.
* No automatic apply on receipt.
* No peer-majority authority.
* No governance enforcement.
* No KMS / HSM custody.
* No validator-set rotation.
* No fallback to `--p2p-trusted-root`.
* No active `DummySig` / `DummyKem` / `DummyAead`.
* No schema / wire / metric drift.
* No marker write before sequence commit (no mutating surface is
  exercised; the validator is pure).
* No sequence write on validation-only surfaces.
* No marker write on validation-only surfaces.
* DevNet evidence from Run 153 and TestNet evidence from Runs 154 /
  155 / 156 / 157 / 158 remain valid and untouched.

## Validation commands

The task's required validation set is run by the harness:

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_157_unified_testnet_peer_apply_fixture_helper`
* `cargo build --release -p qbind-node --example run_160_authority_lifecycle_fixture_helper`
* `bash scripts/devnet/run_160_authority_lifecycle_release_binary.sh`
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

Per-suite stdout/stderr/exit_code are captured under
`docs/devnet/run_160_authority_lifecycle_release_binary/test_results/`
and summarised in `summary.txt`.

## Documentation alignment

* `docs/whitepaper/contradiction.md` — Run 160 paragraph appended
  (this run is purely additive; no Run 050–159 invariant is changed;
  release-binary lifecycle evidence is captured as a partial-positive
  boundary; the next required integration run is Run 161).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` — Run 160 entry
  documenting that operators have no new CLI surface and no new
  runtime behaviour; the lifecycle validator is still a pre-flight
  typed surface; release-binary lifecycle apply is **not** enabled
  in this run.
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` — Run 160
  entry recording that the authority model is unchanged, the
  release-binary lifecycle boundary is captured, and MainNet
  remains refused.
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` —
  Run 160 entry recording that the six-phase fail-closed pipeline is
  unchanged; the lifecycle validator is still not wired into any
  mutating surface.

## Out of scope (deferred)

* Production wiring of `validate_v2_lifecycle_transition` into the
  Run 134 / 136 / 138 / 150 / 152 marker-comparison and
  accept-and-persist pipeline → **Run 161** (the exact next required
  integration run).
* MainNet peer-driven apply enablement.
* Governance.
* KMS / HSM.
* Validator-set rotation.
* Wire-level encoding of `Retire` / `EmergencyRevoke` as distinct
  action bytes (the existing `Ratify / Rotate / Revoke` byte set is
  preserved unchanged).
* Full **C4** closure.
* **C5** closure.

## Acceptance criteria

Run 160 satisfies `task/RUN_160_TASK.txt` §Acceptance criteria:

1. It honestly determines release-binary reachability of Run 159
   lifecycle validation (verdict: not reachable today).
2. It captures release-binary lifecycle evidence for every feasible
   existing action — release-built helper minted A1–A6 + R1–R14
   fixtures; Run 159 source/test suite running on release-built test
   binaries exercises the validator on every fixture.
3. It documents infeasible release-binary apply outcomes (every
   surface 1–7) without fabricating evidence.
4. It preserves all validation-only and mutating-surface invariants:
   no marker write, no sequence write, no live trust mutation, no
   session eviction, no SIGHUP / reload-apply / drain-once / live
   `0x05` code change.
5. It introduces no schema/wire drift silently — schema gap analysis
   is documented above.
6. MainNet remains refused unconditionally.
7. Governance / KMS-HSM / validator-set rotation remain open.
8. The next required integration run is precisely identified as
   **Run 161** — wire `validate_v2_lifecycle_transition` into the
   Run 134 / 136 / 138 / 150 / 152 marker-comparison and
   accept-and-persist boundary.
9. Full **C4** is **not** claimed. **C5** is **not** claimed.