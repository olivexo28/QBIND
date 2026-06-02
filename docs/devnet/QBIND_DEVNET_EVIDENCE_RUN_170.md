# QBIND DevNet Evidence — Run 170

Run 170 is the **release-binary EVIDENCE** that the **Run 169 wiring** of
the **Run 167 typed governance-proof loader** into the **four
production v2 marker-decision preflight call sites** through the
**Run 169 shim**
(`pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load`)
is reachable and enforced from real release-built binaries linking the
same production marker-decision symbols `target/release/qbind-node`
links.

It is the release-binary counterpart to Run 169's source/test wiring
and the natural sequel to Run 168's helper-only proof-carrier
boundary. Run 170 carries no production source-code change beyond
what Run 167 / Run 169 already landed; it is documentation, harness,
and evidence-archive only.

This evidence file complements
`docs/devnet/run_170_governance_proof_production_surface_release_binary/README.md`
and is the canonical follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_168.md` (helper-only proof
carrier release-binary boundary) and
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_166.md` (release-binary
governance-gate enforcement).

## Scope

Per `task/RUN_170_TASK.txt`, Run 170 honestly proves on real release
binaries:

1. **A1 / A2 — pre-Run-167 no-proof v2 sidecars remain compatible**
   under `GovernanceProofPolicy::NotRequired` on real
   `target/release/qbind-node` `--p2p-trust-bundle-reload-check` and
   `--p2p-trust-bundle-reload-apply-path`. Both surfaces are now
   routed through the Run 169 shim. Backwards compatibility is
   evidenced end-to-end on the release binary.

2. **A3 / A7 / R1 / R2 / R5 / R7 / R8 / R9 / R10 / R15 / R16 —
   proof-carrying sidecars** are parsed by the **production** Run 167
   loader (now wired into all four production preflight call sites by
   Run 169) and the proof carrier round-trips through the production
   parse path. Valid proof-carrying GenesisBound `Rotate` sidecars are
   accepted by the Run 165 governance gate composed with the Run 169
   shim; absent / malformed / wrong-binding / invalid-signature /
   `OnChainGovernance` proofs fail closed. Evidence is captured
   through the Run 168 release-built helper which links the same
   production loader + gate symbols `target/release/qbind-node`
   links.

3. **R20 — MainNet peer-driven apply remains refused** regardless of
   any governance-proof carrier. The surface refusal is owned by the
   Run 130 environment policy and unchanged by Run 165 / Run 167 /
   Run 169.

Run 170 does **not**:

* enable MainNet peer-driven apply on any surface;
* introduce a governance execution engine, on-chain governance
  integration, KMS/HSM custody, or validator-set rotation;
* introduce any wire / marker / sequence / trust-bundle schema
  change beyond the additive Run 167 optional sibling field already
  landed;
* change the Run 169 production preflight call signatures;
* expose a release-binary CLI toggle for
  `GovernanceProofPolicy::RequiredForLifecycleSensitive` — that
  operator-control plumbing is intentionally NOT in Run 170 scope
  and is documented as deferred (see *Honest limitation*);
* weaken Runs 070, 130–169.

Run 170 does **not** close C4 or C5.

## Verdict

**`positive (release-binary boundary): the Run 169 shim
preflight_v2_marker_decision_with_governance_proof_load is referenced
from each of the four production v2 marker-decision preflight call
sites; the Run 167 loader and Run 169 versioned dispatcher are
referenced from main.rs and pqc_live_trust_reload.rs; old no-proof
sidecars continue to load and apply on real qbind-node through the
Run 169-wired preflights; the Run 168 release-built helper (replayed
on the current checkout) links the same production loader + gate
symbols and exercises the full A1–A7 / R1–R20 proof-carrying matrix;
MainNet peer-driven apply remains refused regardless of any
governance-proof carrier.`**

This supersedes the Run 168 helper-only proof-carrying boundary by
capturing the Run 169 source-level reachability proof on the same
release-binary checkout — the four production preflights now run
through the Run 169 shim, so a passing helper scenario that links the
same loader + gate symbols is honest release-binary evidence that the
production preflights enforce the same composition.

## Honest limitation (Run 170 strict scope)

The four production preflight call sites are wired by Run 169 to
invoke
`preflight_v2_marker_decision_with_governance_proof_load` with
`GovernanceProofPolicy::NotRequired` by default. Lifting the
release-binary CLI to expose a configurable
`RequiredForLifecycleSensitive` toggle would require a production
source change beyond the Run 170 strict scope and is intentionally
NOT in Run 170 scope. The full Required-policy proof-carrying matrix
is exercised through:

* the Run 168 release-built helper
  (`crates/qbind-node/examples/run_168_governance_proof_carrier_release_binary_helper.rs`,
  13 scenarios `H1`–`H13`) replayed against the current checkout —
  links the same production loader + Run 165 gate symbols
  `target/release/qbind-node` links;
* the Run 169 source/test integration suite
  (`crates/qbind-node/tests/run_169_governance_proof_loader_surface_integration_tests.rs`,
  39 tests) which directly exercises `Required` on every production
  preflight call site at the source level.

The release-binary CLI toggle for `Required` is documented as
deferred to a follow-up operator-control wiring run.

## Inheritance from prior runs

Run 170 inherits and does not weaken the boundaries already evidenced
by:

* Run 167 — typed governance-proof carrier surface, additive optional
  `governance_authority_proof` sibling, `GovernanceProofLoadStatus`,
  `GovernanceProofContext`, source-level matrix (47 tests);
* Run 169 — wiring of the Run 167 loader into all four production
  preflight call sites through the
  `preflight_v2_marker_decision_with_governance_proof_load` shim;
  `load_versioned_ratification_with_governance_proof_from_path`
  versioned dispatcher; production-surface integration suite
  (39 tests) covering A3 / A4 / A5 / A6 / R4 / R5 / R6 directly on
  the four production preflights at the source level;
* Run 165 — governance marker gate
  (`evaluate_governance_marker_gate`,
  `decide_v2_marker_acceptance_with_lifecycle_and_governance`,
  `GovernanceMarkerGate`,
  `GovernanceAuthorityVerificationOutcome`);
* Run 163 — governance authority verifier (32 tests) producing the
  precise typed reject variants
  (`WrongEnvironment`, `WrongChain`, `WrongGenesis`,
  `WrongAuthorityRoot`, `WrongLifecycleAction`, `WrongCandidateDigest`,
  `WrongAuthoritySequence`, `InvalidIssuerSignature`,
  `UnsupportedIssuerSuite`, `NonPqcSuiteRejected`,
  `NonPqcAuthorityRootSuiteRejected`, `ThresholdNotMet`,
  `ReplayRejected`, `UnsupportedOnChainGovernance`,
  `EmptyIssuerSignature`);
* Run 161 — lifecycle marker integration;
* Run 168 — release-binary helper-only proof-carrier evidence
  (13 scenarios `H1`–`H13`);
* Run 166 — release-binary governance-gate enforcement evidence;
* Run 164 — governance authority fixture helper;
* Run 133 — v2 validation-only fixture helper (no-proof corpus reused
  for A1 / A2 / R20);
* Run 070 — reload-apply ordering (sequence-before-marker);
* Run 055 — sequence commit boundary;
* Run 130 — environment policy MainNet apply refusal;
* Runs 050–162 — all prior trust-anchor / rotation / peer-driven apply
  invariants.

## Acceptance-criteria mapping (`task/RUN_170_TASK.txt`)

The task's acceptance-criteria block lists ten items. Each maps to a
specific harness scenario or evidence artefact:

| # | Acceptance criterion (paraphrased)                                                                                                                          | Evidence in Run 170                                                                                                                                                            |
|---|--------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | Run 167 production loader reachable from the four production v2 marker-decision call sites by source-level grep                                              | `reachability/src_grep.txt` + `reachability/reachability.txt`; `assert_grep` for `preflight_v2_marker_decision_with_governance_proof_load` at all four call sites              |
| 2 | Pre-Run-167 no-proof v2 sidecars remain accepted on real `target/release/qbind-node` reload-check / reload-apply under `NotRequired`                         | A1 / A2 scenarios; `marker_hashes/A2.{pre,post}.sha256`; `sequence_hashes/A2.{pre,post}.sha256`                                                                                |
| 3 | Valid proof-carrying GenesisBound Rotate sidecar accepted under `Required` policy through real production surfaces (or release-built helper of same symbols) | A3 helper-replay scenario; `helper_evidence/run_168_replay/scenarios/H1_*/`; cross-checked by the Run 169 production-surface integration suite (39 tests)                      |
| 4 | Idempotent re-presentation deterministically accepted; no marker mutation                                                                                    | A7 helper-replay scenario; pre/post marker SHA equality                                                                                                                        |
| 5 | Required-policy fail-close on absent / malformed / wrong-binding / invalid-signature / unsupported / empty-signature proofs                                  | R1, R2, R5, R7, R8, R9, R10, R15, R16 helper-replay scenarios; each with the precise typed error captured                                                                      |
| 6 | MainNet peer-driven apply remains refused regardless of any governance-proof carrier                                                                         | R20 scenario on real `target/release/qbind-node`; surface refusal owned by Run 130                                                                                             |
| 7 | No mutation on any rejected scenario; mutation-ordering invariants on accepted mutating scenarios                                                            | `negative_invariants.txt`; `assert_no_mutation_*` per scenario; pre/post marker SHA equality on every seeded reject                                                            |
| 8 | Denylist (no MainNet apply, no autonomous apply, no peer-majority authority, no on-chain claim, no KMS/HSM claim, no `--p2p-trusted-root` fallback, etc.)    | `grep_summaries/denylist.txt`; `assert_grep` for absence on every captured stdout/stderr                                                                                       |
| 9 | Cross-checks against the Run 169 + Run 167 + Run 165 + Run 163 + Run 161 + Run 159 + Run 157 + Run 152 + Run 150 + Run 148 + Run 142 + Run 138 + Run 134 suites + `pqc_authority` lib + full lib | `test_results/run_169..run_134_*.{out,err,exit}`; helper-replay scenarios H1–H13 also recorded |
| 10 | Provenance (release-binary identities, helper identities, git commit, rustc/cargo/uname)                                                                    | `provenance.txt`                                                                                                                                                                |

## Reachability — Run 168 boundary superseded

Run 168's `reachability/src_grep.txt` proved the Run 167 loader was
reachable from a release-built helper but the four production
preflight call sites still hard-coded
`GovernanceProofContext::Unavailable` on their direct call sites.
Run 169 replaced those hard-codes with the Run 169 shim. The Run 170
harness records this directly in `reachability/src_grep.txt` and
asserts via `assert_grep`:

* `crates/qbind-node/src/pqc_governance_proof_surface.rs` —
  `pub fn preflight_v2_marker_decision_with_governance_proof_load`.
* `crates/qbind-node/src/main.rs` —
  `preflight_v2_marker_decision_with_governance_proof_load` (twice:
  reload-apply preflight + startup `--p2p-trust-bundle` preflight).
* `crates/qbind-node/src/pqc_live_trust_reload.rs` —
  `preflight_v2_marker_decision_with_governance_proof_load` (SIGHUP
  preflight).
* `crates/qbind-node/src/pqc_peer_candidate_apply.rs` —
  `preflight_v2_marker_decision_with_governance_proof_load`
  (peer-driven coordinator).
* `crates/qbind-node/src/pqc_ratification_input.rs` —
  `pub fn load_v2_ratification_sidecar_with_governance_proof_from_path`,
  `pub fn load_versioned_ratification_with_governance_proof_from_path`,
  `VersionedRatificationSidecarWithGovernanceProof::{V1, V2}`.
* `crates/qbind-node/src/main.rs` and
  `crates/qbind-node/src/pqc_live_trust_reload.rs` —
  `load_versioned_ratification_with_governance_proof_from_path` is
  the entry the production preflights use to obtain the typed
  `GovernanceProofLoadStatus`.
* `crates/qbind-node/src/pqc_governance_proof_wire.rs` —
  `GovernanceProofLoadStatus::{Absent, Available, Malformed}` and
  `GovernanceProofLoadStatus::governance_proof_context(verifier)`.
* `crates/qbind-node/src/pqc_authority_marker_acceptance.rs` —
  `decide_v2_marker_acceptance_with_lifecycle_and_governance`.
* `crates/qbind-node/src/pqc_governance_authority.rs` —
  `evaluate_governance_marker_gate`,
  `GovernanceAuthorityVerificationOutcome`.

## Documentation requirements (per task)

Per the task's *Documentation requirements*, this evidence file
explicitly states:

* **Run 170 is release-binary production-surface evidence.** The
  Run 167 typed governance-proof loader is now reachable from each of
  the four production v2 marker-decision preflight call sites through
  the Run 169 shim; the Run 168 release-built helper replay exercises
  the proof-carrying matrix on the same loader + gate symbols
  `target/release/qbind-node` links; old no-proof sidecars continue
  to load and apply on real `qbind-node` through the Run 169-wired
  preflights.

* **No-proof sidecars are compatible under `NotRequired`.** A1 / A2
  on real `target/release/qbind-node` accept; sequence-before-marker
  preserved; no marker write on validation-only.

* **Required policy fails closed when proof absent.** R1 (Absent),
  R2 (Malformed → Unavailable), R16 (EmptyIssuerSignature →
  Malformed → Unavailable) all produce
  `GovernanceAuthorityRequiredButMissing(Rotate)`; seed marker bytes
  unchanged.

* **Valid proof-carrying sidecars are accepted through real
  production surfaces where lifecycle and anti-rollback pass.** A3 +
  A7 helper-replay; cross-checked at the source level by the Run 169
  production-surface integration suite (39 tests) directly driving
  the four production preflights under `Required`.

* **Invalid proof-carrying sidecars fail closed.** R5
  (`WrongAuthorityRoot`), R7 (`WrongLifecycleAction`),
  R8 (`WrongCandidateDigest`),
  R9 (`WrongAuthoritySequence`),
  R10 (`InvalidIssuerSignature`); each with the precise typed
  reject; no marker write.

* **`OnChainGovernance` is unsupported and fails closed at the
  verifier.** R15 helper-replay produces
  `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)`; the
  wire format intentionally permits round-tripping the
  `on-chain-governance` class so a future on-chain proof format can
  bind without a new wire-version bump; today the verifier fail-
  closes.

* **No MainNet apply.** R20 on real `target/release/qbind-node`;
  surface refusal owned by Run 130 environment policy and unchanged
  by Run 165 / Run 167 / Run 169.

* **Governance execution unimplemented.** Run 170 does not introduce
  one. The wire `governance_authority_proof` is verifier-only; the
  Run 169 shim composes loader → policy → gate; nothing executes
  governance.

* **On-chain governance integration unimplemented.** See R15.

* **KMS/HSM custody unimplemented.** Issuer keys are operator-managed
  symbols (Run 159 lifecycle); KMS/HSM is open.

* **Validator-set rotation unimplemented.** Open.

* **Full C4 closure remains open.** Run 170 narrows C4 by closing the
  release-binary boundary on the Run 169-wired preflights with the
  Run 167 governance-proof carrier under `NotRequired` (default) and
  evidencing `Required` through the Run 168 helper replay + Run 169
  source/test, but full C4 closure requires (a) the release-binary
  CLI toggle for `Required` (deferred), (b) governance execution,
  (c) on-chain integration, (d) KMS/HSM custody, (e) validator-set
  rotation.

* **C5 closure remains open.**

## Cross-checks

The Run 170 harness re-runs the following cargo test suites against
the same checkout (the harness records each as
`test_results/run_NNN_*.{out,err,exit}`):

* `run_169_governance_proof_loader_surface_integration_tests` (39
  tests) — production-surface wiring of the Run 167 loader through
  the Run 169 shim;
* `run_167_governance_proof_carrier_tests` (47 tests) — typed proof
  carrier matrix;
* `run_165_governance_marker_integration_tests` — governance marker
  gate;
* `run_163_governance_authority_verifier_tests` (32 tests) — typed
  reject matrix;
* `run_161_lifecycle_marker_integration_tests`;
* `run_159_authority_signing_key_lifecycle_tests`;
* `run_157_unified_testnet_fixture_universe_tests`;
* `run_152_binary_reachable_peer_drain_plumbing_tests`;
* `run_150_peer_driven_apply_drain_tests`;
* `run_148_peer_driven_apply_devnet_tests`;
* `run_142_live_inbound_0x05_v2_validation_tests`;
* `run_138_sighup_v2_authority_marker_tests`;
* `run_134_reload_apply_v2_authority_marker_tests`;
* `--lib pqc_authority` — library-level authority surface;
* `--lib` — full library suite for regression.

The Run 168 release-built helper replay is recorded under
`helper_evidence/run_168_replay/` with one subdirectory per scenario
(`H1` … `H13`). Each scenario captures the proof-carrying sidecar
JSON, its SHA-256, the helper stdout/stderr, the helper exit code,
the seed marker SHA-256 before and after, and the post-helper
data-dir inventory.

## Surfaces investigated

| #  | surface                                                  | reachable? | proof-carrier wiring used                                                | expected behaviour                                                                                          |
|----|----------------------------------------------------------|-----------|---------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------|
|  1 | real `qbind-node` `--p2p-trust-bundle-reload-check`      | yes (Run 169-wired) | no proof; loader returns `Absent`; shim → policy=NotRequired             | accept; no sequence write; no marker write                                                                  |
|  2 | real `qbind-node` `--p2p-trust-bundle-reload-apply-path` | yes (Run 169-wired) | no proof; loader returns `Absent`; shim → policy=NotRequired             | accept; sequence-before-marker preserved                                                                    |
|  3 | helper replay, proof-carrying GenesisBound Rotate        | yes        | proof present; loader returns `Available`; policy=Required                | gate accept (`UpgradeV2 1->2`); seed marker bytes unchanged                                                 |
|  4 | helper replay, idempotent re-presentation                | yes        | same loader + gate composition twice                                      | deterministic identical accept; no marker mutation                                                          |
|  5 | helper replay, no-proof Rotate under Required            | yes        | loader returns `Absent`; policy=Required                                  | `GovernanceAuthorityRequiredButMissing(Rotate)`; seed marker bytes unchanged                                |
|  6 | helper replay, malformed sibling under Required          | yes        | loader returns `Malformed(UnknownSchemaVersion)`; mapped to `Unavailable` | `GovernanceAuthorityRequiredButMissing(Rotate)`; seed marker bytes unchanged                                |
|  7 | helper replay, wrong authority root                      | yes        | loader returns `Available`; gate verifier rejects                         | `GovernanceAuthorityRejected(WrongAuthorityRoot)`; no marker write                                          |
|  8 | helper replay, wrong lifecycle action                    | yes        | loader returns `Available`; gate verifier rejects                         | `GovernanceAuthorityRejected(WrongLifecycleAction)`; no marker write                                        |
|  9 | helper replay, wrong candidate digest                    | yes        | loader returns `Available`; gate verifier rejects                         | `GovernanceAuthorityRejected(WrongCandidateDigest)`; no marker write                                        |
| 10 | helper replay, wrong authority sequence                  | yes        | loader returns `Available`; gate verifier rejects                         | `GovernanceAuthorityRejected(WrongAuthoritySequence)`; no marker write                                      |
| 11 | helper replay, invalid issuer signature                  | yes        | loader returns `Available`; gate verifier rejects                         | `GovernanceAuthorityRejected(InvalidIssuerSignature)`; no marker write                                      |
| 12 | helper replay, `OnChainGovernance` class                 | yes        | wire round-trip OK; gate verifier rejects                                 | `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)`; no marker write                                |
| 13 | helper replay, empty issuer signature                    | yes        | wire boundary rejects → `Malformed(EmptyIssuerSignature)` → `Unavailable` | `GovernanceAuthorityRequiredButMissing(Rotate)`; seed marker bytes unchanged                                |
| 14 | real `qbind-node` MainNet candidate                      | yes        | environment-policy refusal owns the boundary                              | refused regardless of any governance-proof carrier                                                          |

## Validation commands

See
`docs/devnet/run_170_governance_proof_production_surface_release_binary/README.md`
for the full reproduction command list. The harness lives at
`scripts/devnet/run_170_governance_proof_production_surface_release_binary.sh`.

## Out of scope (deferred)

* MainNet peer-driven apply enablement — remains refused;
* governance execution engine — remains unimplemented;
* on-chain governance integration — `OnChainGovernance` remains
  fail-closed at the verifier;
* KMS/HSM custody — remains unimplemented;
* validator-set rotation — remains open;
* autonomous / on-receipt / peer-majority apply — remains refused;
* full C4 closure — remains open;
* C5 closure — remains open;
* release-binary CLI toggle for
  `GovernanceProofPolicy::RequiredForLifecycleSensitive` —
  operator-control plumbing intentionally NOT in Run 170 scope; the
  full Required-policy proof-carrying matrix is exercised through
  the Run 168 release-built helper replay and the Run 169 source/test
  integration suite.
