# QBIND DevNet evidence — Run 186

**Title.** Source/test production OnChainGovernance verifier
boundary with explicit fail-closed MainNet policy.

**Status.** PASS (source/test, partial-positive). Run 186 introduces
a typed verifier-kind boundary that cleanly separates fixture
OnChainGovernance proof verification (DevNet/TestNet evidence-only)
from future real on-chain governance proof verification (declared
unavailable and fail-closed). The new boundary is additive over the
Run 178 typed verifier, the Run 180 surface wrappers, the Run 182
call-site wiring, the Run 184 payload-carrying sibling, and the
Run 185 release-binary payload evidence; it does not change any
existing wire, schema, marker, sequence, or trust-bundle format.
The default verifier kind is `Disabled` on every surface and every
proof. The fixture path is reachable only under the explicit
`FixtureSourceTest` kind, and it short-circuits to a typed
`FixtureProofRejectedAsMainNetProductionAuthority` whenever the
trust domain, candidate root, or proof environment is MainNet — so
a fixture proof can never masquerade as a production governance
authority. Both the `ProductionUnavailable` and the
`ProductionVerifierPlaceholder` kinds always return a typed
`ProductionVerifierUnavailable` (or
`MainNetProductionVerifierUnavailable` on MainNet), regardless of
proof material. Real on-chain governance proof verification,
governance execution, KMS/HSM custody, validator-set rotation,
bridge / light-client integration, autonomous apply, apply-on-receipt,
peer-majority authority, and the release-binary boundary for the
verifier kind itself all remain unimplemented. MainNet peer-driven
apply remains refused (Run 147 FATAL invariant). Full C4 and C5
remain **OPEN** invariants tracked by the contradiction ledger.

**Driving spec.** `task/RUN_186_TASK.txt`.

## 1. Strict scope

Run 186 is **source/test only**. It adds **only**:

* A new module
  [`pqc_onchain_governance_verifier`](
    ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
  defining:
  * `OnChainGovernanceVerifierKind` —
    `Disabled` / `FixtureSourceTest` / `ProductionUnavailable` /
    `ProductionVerifierPlaceholder`;
  * `OnChainGovernanceProofClass` — `Fixture` / `Production`,
    derived from the proof suite ID;
  * `OnChainGovernanceVerifierPolicy` carrying the kind plus the
    associated Run 178 proof policy that the fixture path forwards
    to;
  * `OnChainGovernanceVerifierBoundaryOutcome` — the typed surface
    of every boundary decision (accept-fixture, fixture-disabled,
    production-unavailable, production-unsupported,
    production-malformed, MainNet-production-unavailable,
    fixture-rejected-as-MainNet-production-authority, and
    Run 178-rejection forwarding);
  * the `OnChainGovernanceVerifier` trait plus four concrete
    verifiers — `DisabledOnChainGovernanceVerifier`,
    `FixtureSourceTestOnChainGovernanceVerifier`,
    `ProductionUnavailableOnChainGovernanceVerifier`, and
    `ProductionVerifierPlaceholderOnChainGovernanceVerifier`;
  * pure entry points
    `verify_fixture_onchain_governance_proof` and
    `verify_production_onchain_governance_proof`;
  * the boundary dispatcher
    `dispatch_onchain_governance_proof_through_verifier_boundary`;
  * the MainNet refusal helper
    `mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`;
  * the proof-class classifier
    `classify_onchain_governance_proof_class` and the
    `is_reserved_production_onchain_governance_proof_suite`
    predicate.
* Module registration at
  [`crates/qbind-node/src/lib.rs`](../../crates/qbind-node/src/lib.rs).
* A new integration test file
  [`tests/run_186_onchain_governance_production_verifier_boundary_tests.rs`](
    ../../crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs)
  covering the full A1–A7 acceptance matrix and the full R1–R29
  rejection matrix from `task/RUN_186_TASK.txt`, plus extras for
  proof-class separation, all four verifier traits, MainNet
  masquerade refusal, dispatcher determinism, and call-site
  reachability.

Run 186 does **not** add: any release-binary harness for the
verifier kind, any real on-chain governance proof verifier, any
governance execution engine, any KMS/HSM, any validator-set
rotation, any bridge / light-client integration, any
peer-majority authority, any autonomous or apply-on-receipt path,
any wire / schema / marker / sequence / trust-bundle change, any
MainNet peer-driven apply enablement, or any weakening of Runs 070
or 130–185. The release-binary boundary for the verifier kind is
explicitly deferred to Run 187.

## 2. Acceptance summary

The Run 186 acceptance matrix (A1–A7) and rejection matrix
(R1–R29) from the driving spec map 1:1 to integration tests in
[`run_186_onchain_governance_production_verifier_boundary_tests`](
  ../../crates/qbind-node/tests/run_186_onchain_governance_production_verifier_boundary_tests.rs).
All 44 tests pass. Highlights:

* **A1 / A2.** A fully-valid DevNet (resp. TestNet) fixture proof
  carried through the boundary under `FixtureSourceTest` kind +
  `AllowFixtureSourceTest` proof policy returns `AcceptedFixture`
  with the underlying Run 178 typed accept payload preserved.
* **A3 / A4.** The Run 185 reload-check / reload-apply fixture
  paths remain compatible — a boundary `AcceptedFixture` decision
  composes cleanly into the existing Run 180
  `reload_check_compose_onchain_governance_marker_decision`
  acceptance.
* **A5.** GenesisBound and EmergencyCouncil authority paths are
  not entered by the boundary at any kind.
* **A6.** Both production verifier kinds return
  `ProductionVerifierUnavailable` for any production-class proof.
* **A7.** The default kind `Disabled` refuses every proof.
* **R1–R29.** Disabled-kind refusal, fixture-as-MainNet refusal,
  production-class proofs on all environments, every Run 178 typed
  rejection (wrong env / chain / genesis / authority root /
  governance domain / proposal digest / proposal outcome /
  lifecycle action / candidate digest / authority sequence /
  expired / replayed / quorum / threshold / invalid bytes /
  unsupported suite / malformed / config-only / peer-majority /
  lifecycle invalid / production-verifier-unavailable / MainNet
  refusal / non-mutating / no-mutation-on-preflight) all surface
  through the boundary as typed rejection variants.

## 3. Honest limitations

Run 186 is purely a typed source/test boundary. It does not:

* Verify any real on-chain governance proof — the
  `ProductionVerifierPlaceholder` always fails closed.
* Execute any governance action.
* Provide any release-binary evidence; the release-binary boundary
  for the verifier kind is deferred to Run 187.
* Change any existing wire, schema, marker, sequence, or
  trust-bundle format.
* Enable MainNet peer-driven apply (still refused by Run 147).
* Implement KMS/HSM custody, validator-set rotation,
  bridge / light-client integration, autonomous apply, or
  apply-on-receipt.
* Close C4 or C5; both remain **OPEN** in the contradiction
  ledger.