# Run 164 — Release-Binary Governance Authority Verifier Evidence / Boundary

## Scope

Run 164 produces the strongest **honest** release-binary evidence
currently possible for the Run 163 typed pure governance ratification
authority verifier
(`qbind_node::pqc_governance_authority::verify_governance_authority_proof`,
`qbind_node::pqc_governance_authority::validate_lifecycle_with_governance_authority`).
Per `task/RUN_164_TASK.txt`, Run 164 must **first determine** whether
the Run 163 verifier is reachable from any existing release-binary
production v2 surface and, if not, capture that fact as a
**partial-positive boundary** without fabricating production-surface
governance evidence.

The Run 164 source-level reachability proof (captured by the harness
in `reachability/src_grep.txt` and `reachability/reachability.txt`)
shows that `verify_governance_authority_proof`,
`validate_lifecycle_with_governance_authority`, and the
`pqc_governance_authority` module have **no production caller in
`crates/qbind-node/src/`** outside:

* `crates/qbind-node/src/pqc_governance_authority.rs` (the module
  itself, its module-level documentation, and the pure helper
  composing the Run 159 lifecycle validator with the Run 163 verifier);
* `crates/qbind-node/src/lib.rs` (the `pub mod
  pqc_governance_authority;` declaration only).

Test callers exist only in
`crates/qbind-node/tests/run_163_governance_authority_verifier_tests.rs`
(32 tests). None of the eight production release-binary v2 surfaces
enumerated by the task — startup `--p2p-trust-bundle` v2 (Run 137),
reload-check validation-only (Run 132/133), local peer-candidate-check
validation-only (Run 132/133), process-start reload-apply (Run
134/135/162), SIGHUP live-reload (Run 138/139), live inbound `0x05`
validation-only (Run 142/143), peer-driven staged queue / drain-once
(Run 148/150/151/152/153/158), and the lifecycle marker-decision path
from Run 161/162 — calls the Run 163 governance verifier today. The
Run 161 wiring of the Run 159 lifecycle validator into the shared v2
marker-decision helper
`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`
remains intact; Run 164 does **not** add a corresponding governance
wiring.

## Verdict

**`partial-positive: release-binary fixture/evidence boundary
captured; governance authority verifier not yet production-surface
reachable`.**

Run 164 does **not** claim strongest-positive. Run 164 does **not**
fabricate a production governance code-path. Run 164 captures the
release-binary evidence that is honestly available today:

1. A real release-built helper
   (`target/release/examples/run_164_governance_authority_fixture_helper`)
   mints the governance proof corpus covering the full task matrix:

   * **A1** GenesisBound Rotate accepted;
   * **A2** GenesisBound Revoke accepted;
   * **A3** GenesisBound EmergencyRevoke accepted;
   * **A4** EmergencyCouncil EmergencyRevoke accepted;
   * **A5** idempotent same proof / same candidate (verifier returns
     `AcceptedGenesisBound` — Run 163 does not surface a separate
     `AcceptedIdempotent` variant in this case; the lifecycle layer
     is responsible for that classification, and the combined helper
     `validate_lifecycle_with_governance_authority` does observe
     `AuthorityLifecycleTransitionOutcome::Idempotent { sequence: 2 }`
     paired with the governance accept, which is recorded under
     `combined_outcomes.txt`);
   * **R1** wrong environment;
   * **R2** wrong chain;
   * **R3** wrong genesis;
   * **R4** wrong authority root;
   * **R5** wrong lifecycle action (`Revoke` declared on a `Rotate`
     candidate);
   * **R6** wrong candidate digest;
   * **R7** wrong authority-domain sequence;
   * **R8** invalid issuer signature (signature byte mutated);
   * **R9** unsupported issuer suite (suite id `200`);
   * **R10** non-PQC issuer suite (`Ed25519` = 1);
   * **R11** threshold not met (`approvals=1, required=2, total=3`);
   * **R12** malformed proof (empty issuer signature);
   * **R13** stale lower-sequence replay
     (`proof_sequence=1, persisted_sequence=2`);
   * **R14** OnChainGovernance unsupported (fail-closed
     `UnsupportedOnChainGovernance`);
   * **R15** local operator config alone rejected (empty signature +
     empty authority root → typed `MalformedProof`; the
     `LocalOperatorConfigOnlyRejected` typed enum variant exists at
     the type level and is exercised by Run 163 R15 source/test
     coverage);
   * **R16** peer-majority rejected (constructed proof with empty
     signature → typed `MalformedProof`; the
     `PeerMajorityProofRejected` typed enum variant exists at the
     type level and is exercised by Run 163 R16 source/test
     coverage; the `GovernanceAuthorityClass` enum has no
     peer-majority variant by construction).

   Every record is built through the existing
   `PersistentAuthorityStateRecordV2::new` /
   `PersistentAuthorityStateRecordV2::validate_structure` primitives
   and the existing public Run 163 surface
   (`GovernanceAuthorityProof`, `fixture_issuer_signature`,
   `FixtureIssuerSignatureVerifier`, `GovernanceThreshold`,
   `verify_governance_authority_proof`,
   `validate_lifecycle_with_governance_authority`). No new wire
   format. No trust-bundle schema change. No authority-marker schema
   change. No sequence-file schema change. No peer-candidate
   envelope schema change.

2. The real `target/release/qbind-node` is built and its identity is
   recorded (sha256 + ELF Build ID) in `provenance.txt`. The harness
   verifies, by source grep, that this binary's production surfaces
   do **not** silently claim governance enforcement:
   `reachability/src_grep.txt` captures every hit of
   `verify_governance_authority_proof|validate_lifecycle_with_governance_authority|pqc_governance_authority`
   under `crates/qbind-node/src/`, and the harness fails closed if
   any hit lies outside `pqc_governance_authority.rs` (the module
   itself) or `lib.rs` (the `pub mod` declaration).

3. The release-built helper itself invokes
   `verify_governance_authority_proof` and
   `validate_lifecycle_with_governance_authority` on every scenario
   above, writing the actual typed outcome to
   `fixtures/scenarios/<id>/actual.txt` and the actual combined
   outcome to `fixtures/combined_outcomes.txt`. The harness then
   asserts that each scenario's actual outcome contains the expected
   typed-outcome class string from `fixtures/manifest.txt`; the
   per-scenario PASS/FAIL grid is captured in
   `scenario_assertions.txt` (PASS=21, FAIL=0). This is the
   strongest honest release-binary signal available today: a real
   release-built binary linking against and exercising the verifier
   on every feasible accept and reject scenario.

4. The Run 163 / 161 / 159 / 157 / 152 / 150 / 148 / 142 / 134 / 138
   regression suites and `cargo test -p qbind-node --lib
   pqc_authority` are run on the same checkout, with per-suite
   stdout/stderr/exit_code captured under `test_results/`. All
   eleven suites are green.

5. The harness writes `partial_positive_proof.txt` documenting the
   verdict, the schema-gap analysis (the existing v2 ratification
   wire fields are sufficient for `GenesisBound` and
   `EmergencyCouncil` per Run 163 module docs; `OnChainGovernance`
   remains deliberately fail-closed pending a future on-chain proof
   schema; the missing piece is the production call site, not the
   wire format), and the **exact next required integration run**:
   **Run 165 — compose `verify_governance_authority_proof` and
   `validate_lifecycle_with_governance_authority` into the existing
   shared v2 marker-decision helper
   `qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`**
   (or an immediately-upstream typed pre-flight gate) so the
   release-binary v2 surfaces (reload-apply, startup, SIGHUP,
   peer-driven drain, live `0x05`, reload-check,
   peer-candidate-check) exercise the governance verifier on every
   mutating and validation-only v2 decision, without changing the
   on-wire byte set or the v2 marker schema.

## Source delta

Additive only. **No production runtime source change.**

* `crates/qbind-node/examples/run_164_governance_authority_fixture_helper.rs`
  — new release-built helper (additive; automatic Cargo example
  registration; no production caller).
* `scripts/devnet/run_164_governance_authority_release_binary.sh` —
  new harness.
* `docs/devnet/run_164_governance_authority_release_binary/` — new
  evidence archive (`README.md` + `summary.txt` tracked; everything
  else is `.gitignore`d, mirroring Run 153 / 155 / 156 / 158 / 160 /
  162).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_164.md` — canonical
  evidence report.
* Narrow alignment updates to:
  * `docs/whitepaper/contradiction.md`,
  * `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
  * `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
  * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.

**No `main.rs` / `cli.rs` edit. No CLI flag added or renamed. No
SIGHUP / reload-apply / startup-mutation / snapshot-restore / live
`0x05` dispatcher / drain-once code path change. No
`LivePqcTrustState` mutation. No sequence-file write. No
authority-marker write. No new wire format. No schema/wire/metric
drift. No KMS / HSM. No governance execution implementation. No
on-chain governance integration. No validator-set rotation. No
MainNet enablement. No autonomous background drain. No automatic
apply on receipt. No peer-majority authority. No fallback to
`--p2p-trusted-root`. No active `DummySig` / `DummyKem` /
`DummyAead`.**

## Surfaces investigated (release-binary reachability matrix)

Per `task/RUN_164_TASK.txt` §Investigation requirement:

| # | Surface                                                | Calls `verify_governance_authority_proof`? | Calls `validate_lifecycle_with_governance_authority`? | Carries `GenesisBound`? | Carries `EmergencyCouncil`? | Carries `OnChainGovernance`? | Wire/schema change required? | Used for release-binary evidence in Run 164?         |
|---|--------------------------------------------------------|--------------------------------------------|-------------------------------------------------------|-------------------------|-----------------------------|------------------------------|------------------------------|------------------------------------------------------|
| 1 | startup `--p2p-trust-bundle` v2 (Run 137)              | No                                         | No                                                    | No                      | No                          | No                           | No (call site only)          | No — observed-no-claim invariant only                |
| 2 | reload-check validation-only (Run 132/133)             | No                                         | No                                                    | No                      | No                          | No                           | No (call site only)          | No — observed-no-claim invariant only                |
| 3 | local peer-candidate-check validation-only (Run 132)   | No                                         | No                                                    | No                      | No                          | No                           | No (call site only)          | No — observed-no-claim invariant only                |
| 4 | process-start reload-apply (Run 134/135/162)           | No                                         | No                                                    | No                      | No                          | No                           | No (call site only)          | No — observed-no-claim invariant only                |
| 5 | SIGHUP live-reload (Run 138/139)                       | No                                         | No                                                    | No                      | No                          | No                           | No (call site only)          | No — observed-no-claim invariant only                |
| 6 | live inbound `0x05` validation-only (Run 142/143)      | No                                         | No                                                    | No                      | No                          | No                           | No (call site only)          | No — observed-no-claim invariant only                |
| 7 | peer-driven staged queue / drain-once (Run 150–158)    | No                                         | No                                                    | No                      | No                          | No                           | No (call site only)          | No — observed-no-claim invariant only                |
| 8 | lifecycle marker-decision (Run 161/162)                | No                                         | No                                                    | No                      | No                          | No                           | No (call site only; Run 165) | No — observed-no-claim invariant only                |
| 9 | fixture helper / example binary path                   | **Yes**                                    | **Yes**                                               | **Yes**                 | **Yes**                     | **Yes** (fail-closed)        | No                           | **Yes** — A1–A5 / R1–R16 typed-outcome assertion     |

For surfaces 1–8 the harness asserts (i) absence of any source-level
call to `verify_governance_authority_proof` /
`validate_lifecycle_with_governance_authority` /
`pqc_governance_authority` outside the allowed module-itself + lib.rs
declaration locations, and (ii) the release-built `qbind-node` does
not silently claim governance enforcement. For surface 9 the harness
exercises the verifier through the release-built helper on the full
A1–A5 / R1–R16 corpus and asserts the expected typed outcome class
per scenario.

## Validation commands

The harness runs the following on this checkout:

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example
  run_164_governance_authority_fixture_helper`
* `bash scripts/devnet/run_164_governance_authority_release_binary.sh`
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests`
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

Each suite is captured under `test_results/<suite>.{stdout,stderr,exit}`.
All eleven suites are green on this checkout.

## Boundary statements

* Run 164 is **release-binary evidence/boundary only**.
* Run 164 does **not** enable MainNet peer-driven apply.
* Run 164 does **not** implement a governance execution engine.
* Run 164 does **not** integrate on-chain governance.
* Run 164 does **not** implement KMS / HSM custody.
* Run 164 does **not** implement validator-set rotation.
* Run 164 does **not** add an autonomous apply.
* Run 164 does **not** add an automatic apply on receipt.
* Run 164 does **not** introduce a peer-majority authority.
* Run 164 does **not** mutate any live trust state.
* Run 164 does **not** introduce a wire-format change.
* Run 164 does **not** introduce a marker / sequence-file /
  trust-bundle / peer-candidate-envelope schema change.
* Run 164 does **not** introduce a new metric family.
* Run 164 does **not** weaken Runs 050–163 invariants.
* Run 164 does **not** claim full **C4** closure.
* Run 164 does **not** claim **C5** closure.
* MainNet remains refused unconditionally for peer-driven apply
  (cited from Run 151 / Run 158 release-binary evidence).
* Run 162 release-binary lifecycle ENFORCEMENT evidence remains
  valid and untouched.
* OnChainGovernance remains explicitly fail-closed
  (`UnsupportedOnChainGovernance`); no on-chain proof format exists.

## Next required integration run

**Run 165 — compose `verify_governance_authority_proof` and
`validate_lifecycle_with_governance_authority` into the existing
shared v2 marker-decision helper
`qbind_node::pqc_authority_marker_acceptance::decide_marker_acceptance_v2`
(or an immediately-upstream typed pre-flight gate)** so the
release-binary v2 surfaces (reload-apply, startup, SIGHUP,
peer-driven drain, live `0x05`, reload-check, peer-candidate-check)
exercise the governance verifier on every mutating and
validation-only v2 decision, without changing the on-wire byte set
or the v2 marker schema. Run 166 is then the partner release-binary
ENFORCEMENT evidence run for Run 165 (as Run 162 was for Run 161).

## Archive contents

Tracked under git:

* `README.md` — this file;
* `summary.txt` — short verdict + acceptance/rejection summary;
* `.gitignore` — listing of generated artifacts that are reproduced
  by the harness and intentionally not tracked.

Reproduced by the harness (gitignored, mirroring the Run 153 / 155 /
156 / 158 / 160 / 162 evidence-archive precedent):

* `provenance.txt` — release-binary identities (sha256 + ELF Build
  ID) for `qbind-node` and the helper.
* `fixture_manifest.txt` — sha256 of every minted fixture file.
* `scenario_assertions.txt` — per-scenario expected/actual typed
  outcome PASS/FAIL grid.
* `negative_invariants.txt` — explicit negative-invariant assertions
  (no qbind-node started, no sequence/marker write, no live trust
  mutation, no p2p socket, no MainNet enablement).
* `partial_positive_proof.txt` — verdict + schema-gap analysis +
  next-required-integration-run identification.
* `logs/` — release-build logs and helper run log.
* `data/` — empty by construction (negative-invariant evidence).
* `fixtures/` — release-built helper output: manifest +
  expected/actual/combined outcomes + per-scenario candidate /
  proof / signature / trust domain / actual outcome.
* `exit_codes/` — exit codes of the build / helper / harness steps.
* `grep_summaries/` — out-of-scope denylist grep result
  (banner-excluded, must be empty).
* `reachability/` — source-level grep + reachability proof.
* `test_results/` — per-suite stdout / stderr / exit_code for each
  validation command run.