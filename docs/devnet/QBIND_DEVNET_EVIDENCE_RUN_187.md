# QBIND DevNet evidence — Run 187

**Title.** Release-binary OnChainGovernance production verifier-boundary
evidence on real `target/release/qbind-node`. Closes the Run 186-deferred
release-binary boundary for the typed production OnChainGovernance
verifier surface added by `pqc_onchain_governance_verifier.rs`.

**Status.** PASS (release-binary, partial-positive) — the Run 186 typed
OnChainGovernance verifier-boundary contract is preserved end-to-end on
real `target/release/qbind-node`. The default
`OnChainGovernanceVerifierKind::Disabled` policy fails closed on every
production surface; the hidden `AllowFixtureSourceTest` selector arms a
DevNet/TestNet fixture-only verifier and does **not** enable any
production verifier; production-class OnChainGovernance proof
verification is fail-closed as `ProductionVerifierUnavailable` on
DevNet/TestNet and as `MainNetProductionVerifierUnavailable` on MainNet
under both `OnChainGovernanceVerifierKind::ProductionUnavailable` and
`OnChainGovernanceVerifierKind::ProductionVerifierPlaceholder`; a
fixture-class proof presented on MainNet under the `FixtureSourceTest`
verifier kind is rejected as the typed
`FixtureProofRejectedAsMainNetProductionAuthority`, explicitly
forbidding fixture-as-MainNet-production-authority; and the Run 147 /
148 / 152 FATAL MainNet peer-driven apply refusal invariant is
preserved unchanged with the selector armed AND a fully-valid MainNet
fixture proof carried through the Run 184 v2 sidecar additive sibling,
with the Run 186
`mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`
helper additionally encoding the rule at the typed verifier boundary
regardless of policy kind. The Run 185 release-binary fixture
accepted-proof reload-check / reload-apply paths remain compatible: a
real `target/release/qbind-node --p2p-trust-bundle-reload-check
<sidecar-with-sibling>
--p2p-trust-bundle-onchain-governance-fixture-allowed` invocation
continues to load the v2 sidecar through the production validation-
only path, extract the Run 184 sibling, parse the typed
`OnChainGovernanceProofWire`, invoke the Run 182 reload-check named
callsite entry, and reach the Run 186 typed verifier boundary at the
library layer (captured in release mode through the production library
symbols by the new Run 187 release-built helper) without any marker
write, sequence write, live trust swap, session eviction, or Run 070
call. Malformed sibling payloads (non-object, unknown schema-version,
empty required field, empty proof bytes) continue to fail closed at the
typed `OnChainGovernanceProofPayloadParseError` boundary *before* any
Run 186 verifier-boundary dispatch, surface-uniformly across every
Run 182 named callsite entry. The Run 186 release-binary boundary
previously deferred is now closed for the typed verifier-boundary
surface. Real on-chain governance proof verification, governance
execution, KMS/HSM custody, validator-set rotation, bridge /
light-client integration, autonomous apply, and apply-on-receipt all
remain unimplemented. Full **C4** and **C5** remain **OPEN**
invariants tracked by the contradiction ledger.

**Driving spec.** `task/RUN_187_TASK.txt`.

## 1. Strict scope

Run 187 closes the release-binary boundary that Run 186 explicitly
deferred. Run 186 introduced — at source/test level only — the typed
production OnChainGovernance verifier-boundary surface in
[`crates/qbind-node/src/pqc_onchain_governance_verifier.rs`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs):
the
[`OnChainGovernanceVerifierKind`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
enum (`Disabled` / `FixtureSourceTest` / `ProductionUnavailable` /
`ProductionVerifierPlaceholder`), the proof-class classifier
`classify_onchain_governance_proof_class` and the
`is_reserved_production_onchain_governance_proof_suite` predicate, the
typed boundary outcome
[`OnChainGovernanceVerifierBoundaryOutcome`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
(`AcceptedFixture` / `FixtureDisabled` / `ProductionVerifierUnavailable` /
`ProductionProofUnsupported` / `ProductionProofMalformed{reason}` /
`MainNetProductionVerifierUnavailable` /
`FixtureProofRejectedAsMainNetProductionAuthority` /
`Run178Rejection`), the
[`OnChainGovernanceVerifier`](
  ../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
trait with four concrete verifier modes
(`DisabledOnChainGovernanceVerifier`,
`FixtureSourceTestOnChainGovernanceVerifier`,
`ProductionUnavailableOnChainGovernanceVerifier`,
`ProductionVerifierPlaceholderOnChainGovernanceVerifier`), the pure
entry points `verify_fixture_onchain_governance_proof` /
`verify_production_onchain_governance_proof` and the dispatcher
`dispatch_onchain_governance_proof_through_verifier_boundary`, and the
explicit fail-closed MainNet refusal helper
`mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`.
Run 186 added 44 tests covering the A1–A7 / R1–R29 corpus and the
full lib suite is green; release-binary verifier-boundary evidence
is **this Run 187**.

Run 187 is **strictly release-binary boundary evidence** and adds
**only**:

* A new release-built example helper
  [`run_187_onchain_governance_verifier_boundary_release_binary_helper`](
    ../../crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs)
  that, in release mode and through the production library symbols,
  drives the dispatcher across all four
  `OnChainGovernanceVerifierKind` policy kinds against both
  fixture-class and production-class proofs across the A1–A8
  acceptance and R1–R29 rejection corpus, exercises the four
  concrete `OnChainGovernanceVerifier` trait impls' `kind()` and
  `verify(...)` surfaces, exercises the proof-class classifier and
  the reserved-production-suite predicate, exercises both pure
  entry points, exercises the MainNet refusal helper, and emits a
  typed-outcome table with bit-equality non-mutation evidence and
  determinism evidence. The helper exits non-zero if any scenario
  diverges from its expected typed outcome.
* A new release-binary harness
  [`scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh`](
    ../../scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh)
  that builds `target/release/qbind-node`, the Run 185
  payload-carrying helper (reused for sidecar minting), and the new
  Run 187 verifier-boundary helper; drives the release-binary
  acceptance / rejection matrix on real `target/release/qbind-node`
  (default-Disabled invariants, CLI selector arming, env selector
  arming across truthy/falsey variants, reload-check / reload-apply
  loading a Run 185 sidecar carrying the Run 184 sibling for
  Run 187 compatibility, malformed-sibling rejection, and MainNet
  refusal under armed selector AND fully-valid MainNet fixture
  proof); records source-reachability for every Run 186
  verifier-boundary symbol; records the denylist of forbidden
  tokens; records the no-mutation proof for every rejected
  scenario; records the mutation/no-mutation proof for accepted
  reload-check / reload-apply compatibility scenarios; and runs
  the full targeted regression slice in release mode.
* A canonical evidence archive
  [`docs/devnet/run_187_onchain_governance_verifier_boundary_release_binary/`](
    ./run_187_onchain_governance_verifier_boundary_release_binary/)
  tracking only `README.md`, `summary.txt`, and `.gitignore`; every
  per-run artifact (logs, exit codes, grep summaries, sidecars,
  reachability dumps, helper evidence trees, denylist verification,
  mutation/no-mutation proofs, regression test logs) is regenerated
  on every harness invocation and lives under `.gitignore`.
* This canonical evidence Markdown.
* Narrow append-only Run 187 update sections in the contradiction
  ledger and three protocol/runbook design docs.

Run 187 does **not**:

* introduce any production source change beyond what Run 186 already
  added at source/test level,
* bump any wire schema version,
* add any new metric / counter / log line beyond Run 180's
  pre-existing armed banner,
* change any default policy on any surface,
* enable MainNet peer-driven apply,
* implement any real on-chain proof verifier,
* implement governance execution / KMS-HSM / validator-set rotation,
* expose anything new on the public binary CLI `--help` surface (the
  Run 180 selector remains hidden via `clap(hide = true)`),
* claim closure of C4 or C5.

## 2. Acceptance summary

All A1–A8 acceptance scenarios and R1–R29 rejection scenarios listed
in `task/RUN_187_TASK.txt` are exercised either:

* on real `target/release/qbind-node` directly, by the
  Run 187 harness, for the scenarios that have a public binary
  surface (default-Disabled invariants, CLI/env selector arming,
  reload-check / reload-apply with a v2 sidecar carrying the
  Run 184 sibling for Run 187 compatibility, malformed-sibling
  rejection at reload-check, MainNet refusal under armed selector
  AND fully-valid MainNet fixture proof); or
* in release mode through the production library symbols
  `pqc_onchain_governance_verifier::*`, by the release-built
  Run 187 helper, for every typed verifier-boundary outcome across
  all four `OnChainGovernanceVerifierKind` policy kinds against
  both fixture-class and production-class proofs and across both
  DevNet/TestNet and MainNet trust domains, plus the four concrete
  `OnChainGovernanceVerifier` trait impls' `kind()` / `verify(...)`
  surfaces, the proof-class classifier, the reserved-production-
  suite predicate, both pure entry points, and the MainNet refusal
  helper — capturing the surfaces that have no end-to-end binary
  carrier in this tree (the honest limitation is recorded
  explicitly in `mutation_proof.txt` / `no_mutation_proof.txt`).

Run command (canonical):

```text
bash scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh
```

The harness is idempotent and regenerates every per-run artifact
under `docs/devnet/run_187_onchain_governance_verifier_boundary_release_binary/`
on every invocation. The canonical verdict line is written to
`docs/devnet/run_187_onchain_governance_verifier_boundary_release_binary/summary.txt`.

The release-built helpers (Run 185 payload-carrying corpus + Run 187
verifier-boundary corpus) each exit non-zero on any scenario divergence
from its expected typed outcome, so the `helper_summary.txt` files
under `helper_evidence/run_185/` and `helper_evidence/run_187/` are
the canonical machine-checkable verdicts for the in-process
release-mode coverage of the A1–A8 / R1–R29 corpus.

## 3. Honest limitations

* **Release-binary boundary only — no new production code.** Run 187
  ships no production source change; it only proves that the Run 186
  typed verifier-boundary surface is reachable in release mode on
  real `target/release/qbind-node` payload/context paths and that
  the typed boundary outcomes match the Run 186 source/test contract
  bit-identically.
* **Fixture OnChainGovernance remains DevNet/TestNet evidence-only.**
  Under `OnChainGovernanceVerifierKind::FixtureSourceTest` only
  fixture-class proofs are accepted, only on DevNet/TestNet, and
  only under the armed `AllowFixtureSourceTest` selector. A
  fixture-class proof presented on MainNet is rejected as the typed
  `FixtureProofRejectedAsMainNetProductionAuthority`. A
  production-class proof under `FixtureSourceTest` is rejected as
  `ProductionProofUnsupported`.
* **Production-class OnChainGovernance proof verification remains
  unavailable / fail-closed.** Both
  `OnChainGovernanceVerifierKind::ProductionUnavailable` and
  `OnChainGovernanceVerifierKind::ProductionVerifierPlaceholder`
  route production-class proofs to `ProductionVerifierUnavailable`
  on DevNet/TestNet and to `MainNetProductionVerifierUnavailable`
  on MainNet, encoding the honest unavailability of a real
  production OnChainGovernance proof verifier in this tree.
  Fixture-class proofs routed under either kind are rejected as
  `ProductionProofUnsupported`.
* **Fixture proof CANNOT satisfy MainNet production governance
  authority.** This is enforced at two layers in Run 186 / Run 187:
  (a) the typed `FixtureProofRejectedAsMainNetProductionAuthority`
  outcome from `verify_fixture_onchain_governance_proof` whenever
  the trust-domain environment is MainNet; and (b) the explicit
  `mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`
  helper which returns `true` for MainNet regardless of any
  boundary outcome.
* **Default Disabled preserved.** Carrying a fully-valid DevNet
  fixture proof through the Run 184 sibling has zero observable
  effect unless the hidden Run 180 `AllowFixtureSourceTest` selector
  is armed via the existing CLI flag
  (`--p2p-trust-bundle-onchain-governance-fixture-allowed`) or env
  var (`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
  with a truthy value), both of which remain hidden from
  `qbind-node --help` per Runs 180/181/183.
* **MainNet still refused.** The Run 182 peer-driven drain callsite
  entry continues to refuse MainNet peer-driven apply *before*
  invoking the underlying verifier (Run 147 FATAL invariant), and
  the Run 186 typed verifier boundary additionally encodes the
  rule via the `mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`
  helper. Even a fully-valid MainNet fixture proof carried through
  the Run 184 sibling cannot enable MainNet peer-driven apply.
* **Existing Run 185 fixture accepted-proof paths remain
  compatible.** The reload-check and reload-apply binary surfaces
  continue to behave exactly as in Run 185 with the Run 186
  verifier-boundary contract layered behind the Run 184 routing
  helpers; no marker write, no sequence write, no live trust swap,
  no session eviction, and no Run 070 call on the validation-only
  surface.
* **Malformed sibling fail-closed surface-uniformly.** When the
  optional sibling is structurally malformed (non-object,
  unknown schema, empty required field, empty proof bytes), every
  surface short-circuits to a typed
  `OnChainGovernanceProofPayloadParseError` *before* any verifier
  or marker decision runs, regardless of policy or
  verifier kind.
* **Reload-apply on a non-long-running qbind-node invocation
  honestly returns `UnsupportedRuntimeContext`.** Per Run 070, the
  Run 134 reload-apply path requires a runtime trust-context handle
  the binary does not have on a one-shot invocation; the matching
  accepted typed outcome through the Run 182 reload-apply named
  callsite entry under the Run 186 typed verifier boundary is
  captured in release mode through the same library symbols by the
  Run 187 helper corpus.
* **Production binary surfaces beyond reload-check / reload-apply.**
  The live `0x05` peer-candidate envelope and the peer-driven
  drain inbound payload may not yet carry the typed OnChainGovernance
  proof end-to-end on a real binary in this tree. Where they do not,
  Run 187 captures the source-reachability for the matching Run 182
  / Run 186 verifier-boundary symbols and records the boundary
  explicitly in `mutation_proof.txt`.
* **No real on-chain proof verifier.** Run 187 still carries proof
  *material* through the production payload/context paths and runs
  it through the Run 186 typed verifier boundary — it does not
  introduce any real on-chain governance proof verification.
* **No governance execution.** Accepting an `OnChainGovernance`
  fixture proof on the validation-only reload-check surface **does
  not** mutate authority state, **does not** enable MainNet apply,
  **does not** advance the validator set, and **does not** execute
  any governance action. The accepted outcome is observable only
  as the typed
  `OnChainGovernanceVerifierBoundaryOutcome::AcceptedFixture { decision }`
  through the Run 186 typed surface.
* **No KMS/HSM custody, no validator-set rotation, no autonomous
  apply, no apply-on-receipt, no peer-majority authority, no bridge /
  light-client integration.**
* **No schema/wire/metric drift.** Run 187 changes no schema, no
  wire, no metric, no counter, no log line, and does not bump any
  version. The Run 180 banner remains the only emitted token, only
  when the selector is armed.
* **C4 / C5 remain OPEN.** Run 187 does not claim closure of C4 or
  C5; both remain open invariants tracked by the contradiction
  ledger. Run 187 strictly closes the Run 186 release-binary
  boundary for the typed verifier-boundary surface.

## 4. Cross-references

* Driving spec: `task/RUN_187_TASK.txt`.
* Source/test predecessor: Run 186 (typed production OnChainGovernance
  verifier-boundary surface).
* Predecessor release-binary boundary runs: Run 181
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_181.md`), Run 183
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_183.md`), and Run 185
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_185.md`).
* Verifier source/test foundation: Run 178
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_178.md`) and the typed
  `OnChainGovernanceProofPolicy` selector wire-up Run 180
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_180.md`).
* Production call-site wrappers: Run 182
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_182.md`).
* Payload/carrier source/test: Run 184
  (`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_184.md`).
* Authority lifecycle invariants: Run 055 / 070 / 132 / 134 / 136 /
  138 / 142 / 147 / 148 / 150 / 152.
* Contradiction ledger: `docs/whitepaper/contradiction.md` (C4 / C5
  remain OPEN).
* Operational runbook update: `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
  (Run 187 update section).
* Peer-driven apply safety: `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`
  (Run 187 update section).
* Trust-anchor authority model: `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
  (Run 187 update section).