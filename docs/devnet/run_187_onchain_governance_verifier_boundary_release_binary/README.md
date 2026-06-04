# Run 187 — Release-binary OnChainGovernance production verifier-boundary evidence

## Scope

Closes the Run 186-deferred release-binary boundary for the
source/test production OnChainGovernance verifier-boundary layer
added by [`crates/qbind-node/src/pqc_onchain_governance_verifier.rs`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs).
Run 186 added the typed verifier-boundary surface:
[`OnChainGovernanceVerifierKind`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
(`Disabled` / `FixtureSourceTest` / `ProductionUnavailable` /
`ProductionVerifierPlaceholder`), the proof-class classifier
[`classify_onchain_governance_proof_class`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
+ `is_reserved_production_onchain_governance_proof_suite`, the typed
boundary outcome
[`OnChainGovernanceVerifierBoundaryOutcome`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
(`AcceptedFixture` / `FixtureDisabled` /
`ProductionVerifierUnavailable` / `ProductionProofUnsupported` /
`ProductionProofMalformed{reason}` /
`MainNetProductionVerifierUnavailable` /
`FixtureProofRejectedAsMainNetProductionAuthority` /
`Run178Rejection`), the
[`OnChainGovernanceVerifier`](
  ../../../crates/qbind-node/src/pqc_onchain_governance_verifier.rs)
trait with four concrete verifier modes
(`DisabledOnChainGovernanceVerifier`,
`FixtureSourceTestOnChainGovernanceVerifier`,
`ProductionUnavailableOnChainGovernanceVerifier`,
`ProductionVerifierPlaceholderOnChainGovernanceVerifier`), the pure
entry points `verify_fixture_onchain_governance_proof` /
`verify_production_onchain_governance_proof` and the dispatcher
`dispatch_onchain_governance_proof_through_verifier_boundary`, plus
the explicit fail-closed MainNet refusal helper
`mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`.
Run 186 is source/test only with 44 tests (A1–A7 / R1–R29) covering
the corpus and the full lib suite green; release-binary
verifier-boundary evidence is **this Run 187**.

Run 187 captures **release-binary** evidence that real
`target/release/qbind-node` preserves the Run 186 typed verifier-
boundary contract end-to-end:

* a real `target/release/qbind-node` invocation with the hidden
  `--p2p-trust-bundle-onchain-governance-fixture-allowed` selector
  engaged AND a v2 ratification sidecar carrying a typed Run 184
  `OnChainGovernanceProofWire` sibling reaches the Run 182
  `reload_check_callsite_onchain_governance_marker_decision` /
  `reload_apply_callsite_onchain_governance_marker_decision` named
  entries through the production `--p2p-trust-bundle-reload-check`
  and `--p2p-trust-bundle-reload-apply-path` payload/context paths,
  the Run 186 typed verifier boundary is reached at the library
  layer under `OnChainGovernanceVerifierKind::FixtureSourceTest`,
  and the matching fixture-accept outcome is observed without any
  marker write or sequence write (A1 / A2 / A3 / A4);
* the production default — neither flag nor env var truthy —
  emits no Run 180 banner, preserves the
  `OnChainGovernanceVerifierKind::Disabled` production default on
  every surface, and a Run 184 sibling carrying a fixture proof
  routes to the typed `FixtureDisabled` outcome at the verifier
  boundary instead of any verifier execution (A8 / R1);
* a Run 184 sibling carrying a production-class proof routes to the
  typed `ProductionVerifierUnavailable` outcome under
  `OnChainGovernanceVerifierKind::Disabled` /
  `ProductionUnavailable` / `ProductionVerifierPlaceholder` on
  DevNet/TestNet, encoding the honest unavailability of a real
  production OnChainGovernance proof verifier in this tree (A7 /
  R3 / R4 / R5);
* a fixture-class proof routed under
  `OnChainGovernanceVerifierKind::FixtureSourceTest` on MainNet
  routes to the typed
  `FixtureProofRejectedAsMainNetProductionAuthority` outcome,
  explicitly forbidding fixture-as-MainNet-production-authority
  (R2);
* malformed sibling bytes (non-object, unknown schema-version, empty
  required field, empty proof-bytes) are rejected as a typed
  `OnChainGovernanceProofPayloadParseError` *before* any verifier
  runs at all surfaces (R20 / R22), with no marker write, no
  sequence write, no live trust swap, no session eviction, and no
  Run 070 call;
* the Run 147 / 148 / 152 FATAL MainNet peer-driven apply refusal
  invariant survives unchanged with the selector armed AND a fully
  valid MainNet fixture proof carried through the Run 184 payload
  layer; the Run 186
  `mainnet_peer_driven_apply_remains_refused_under_verifier_boundary`
  helper additionally encodes the rule at the typed verifier
  boundary regardless of policy kind (R27);
* the release-built helpers — the Run 185
  `run_185_onchain_governance_payload_release_binary_helper` for
  payload/sidecar reachability and the new Run 187
  `run_187_onchain_governance_verifier_boundary_release_binary_helper`
  for the typed verifier-boundary corpus — exercise the Run 186
  A1–A8 / R1–R29 corpus end-to-end in **release mode** through the
  production library symbols `pqc_onchain_governance_verifier::*`.

## Strict scope (no production-source change)

Per `task/RUN_187_TASK.txt`:

* **Release-binary evidence only.** Run 187 introduces no new
  production module, no new production CLI flag, no new env knob,
  no new schema bump, no new wire shape, no new sidecar field, no
  new metric, and no new exit code beyond the Run 178 typed wire
  + Run 180 hidden selector + Run 184 additive optional
  `onchain_governance_proof` sidecar sibling + Run 186 typed
  verifier-boundary surface already in the tree. The only new
  files committed by Run 187 are this evidence archive, the
  harness shell script
  [`scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh`](
    ../../../scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh),
  the release-built helper example
  [`crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs`](
    ../../../crates/qbind-node/examples/run_187_onchain_governance_verifier_boundary_release_binary_helper.rs),
  the canonical evidence report
  [`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_187.md`](
    ../QBIND_DEVNET_EVIDENCE_RUN_187.md),
  and narrow append-only Run 187 update sections in the
  contradiction ledger and three protocol/runbook design docs.

* **Real `target/release/qbind-node`** is used for every binary
  scenario. Library-layer typed verifier-boundary outcomes are
  captured by the release-built helpers through the production
  library symbols.

* **No production source change.** No production-source line under
  `crates/` is modified by Run 187.

* **No MainNet peer-driven apply enablement.** The Run 147 / 148 /
  152 FATAL invariant is preserved.

* **No real on-chain governance execution.** No real on-chain
  governance proof verifier. No bridge / light-client integration.
  No KMS/HSM custody. No validator-set rotation. No autonomous
  apply. No apply-on-receipt. No peer-majority authority.

* **No schema/wire/metric drift.** The v2 ratification sidecar
  shape, the additive Run 184 `onchain_governance_proof` sibling,
  the v2 marker layout, the Run 055 sequence-file layout, the
  `qbind_ledger::BundleSigningRatificationV2` core schema, and
  every metric remain unchanged.

* **Runs 070, 130–186** are **not** weakened. Run 187 adds only
  release-binary evidence; the Run 186 typed boundary contract is
  preserved bit-identically.

* **Full C4 / C5 remain OPEN.** Run 187 does not claim closure of
  C4 (real on-chain governance proof verification + governance
  execution end-to-end) or C5 (real KMS/HSM + validator-set
  rotation + autonomous apply gates).

## Layout (tracked vs. generated)

This archive uses the same convention as Run 153 / 155 / 179 / 181 /
183 / 185:

* **Tracked in git** (committed):
  * `README.md` — this file.
  * `summary.txt` — committed placeholder; the harness rewrites it.
  * `.gitignore` — declares the generated subtrees below.

* **Generated by the harness** (gitignored, contain absolute paths
  and ephemeral data; reproducible from
  `scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh`):
  * `logs/` — per-scenario stdout/stderr.
  * `exit_codes/` — per-scenario `*.rc` files.
  * `helper_evidence/run_185/` — Run 185 helper output (reused for
    sidecar minting + payload-carrying compatibility evidence).
  * `helper_evidence/run_187/` — Run 187 helper output:
    `manifest.txt`, `expected_outcomes.txt`, `actual_outcomes.txt`,
    `verifier_kinds_table.txt`, `proof_class_table.txt`,
    `no_mutation_evidence.txt`, `determinism_evidence.txt`,
    `helper_summary.txt`, plus per-scenario subdirectories under
    `scenarios/`.
  * `sidecars/` — Run 185-minted v2 ratification JSON sidecars
    reused at the binary surface for Run 187 compatibility (A3 /
    A4) and MainNet refusal (R27).
  * `reachability/` — `source_reachability.txt`, the production
    grep proof for every Run 186 verifier-boundary symbol.
  * `test_results/` — captured `cargo test --release` logs for
    the targeted regression slice in `task/RUN_187_TASK.txt`.
  * `provenance.txt` — git commit / branch / status, rustc /
    cargo versions, host, qbind-node + helper SHA-256 + ELF
    Build IDs.
  * `fixture_manifest.txt` — per-sidecar SHA-256 manifest.
  * `negative_invariants.txt` — denylist proven empty.
  * `mutation_proof.txt` — accepted-compatibility scenario proof
    scaffold.
  * `no_mutation_proof.txt` — rejected-scenario non-mutation proof.

## Reproducibility

```
$ cargo build --release -p qbind-node --bin qbind-node
$ cargo build --release -p qbind-node --example \
    run_185_onchain_governance_payload_release_binary_helper
$ cargo build --release -p qbind-node --example \
    run_187_onchain_governance_verifier_boundary_release_binary_helper
$ bash scripts/devnet/run_187_onchain_governance_verifier_boundary_release_binary.sh
```

The harness is idempotent: it wipes and regenerates every gitignored
subtree above, then writes a fresh `summary.txt` with a canonical
PASS/FAIL verdict line (the verdict line is referenced verbatim by
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_187.md`).

## Honest limitations preserved

* No real on-chain governance proof verifier is wired in Run 187.
  Both `OnChainGovernanceVerifierKind::ProductionUnavailable` and
  `OnChainGovernanceVerifierKind::ProductionVerifierPlaceholder`
  route production-class proofs to the typed
  `ProductionVerifierUnavailable` outcome on DevNet/TestNet and to
  `MainNetProductionVerifierUnavailable` on MainNet, and route
  fixture-class proofs to `ProductionProofUnsupported` regardless
  of environment, encoding the honest unavailability of a real
  production verifier and explicitly forbidding
  fixture-as-MainNet-production-authority.

* Fixture OnChainGovernance proofs remain DevNet/TestNet
  evidence-only under
  `OnChainGovernanceVerifierKind::FixtureSourceTest`. A fixture
  proof presented as MainNet production authority is rejected as
  `FixtureProofRejectedAsMainNetProductionAuthority`.

* MainNet peer-driven apply remains refused at every surface (Run
  147 FATAL invariant), with the Run 186 typed verifier-boundary
  helper additionally encoding the rule.

* No governance execution, no KMS/HSM custody, no validator-set
  rotation, no autonomous apply, no apply-on-receipt, no
  peer-majority authority, no bridge / light-client integration,
  no schema/wire/metric drift.

* Full C4 and C5 remain OPEN. Run 187 is release-binary boundary
  evidence; it does not enable a real production verifier or a
  real governance execution engine.
