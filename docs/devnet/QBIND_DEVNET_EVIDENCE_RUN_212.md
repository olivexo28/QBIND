# QBIND DevNet evidence — Run 212

**Title.** Release-binary governance execution policy-boundary evidence.

**Status.** PASS (release-binary). Run 212 is the release-binary evidence run
for the Run 211 source/test governance **execution policy boundary**
([`crates/qbind-node/src/pqc_governance_execution_policy.rs`](
  ../../crates/qbind-node/src/pqc_governance_execution_policy.rs)).
It proves, on the **real** `target/release/qbind-node` plus a release-built
helper linking the production library symbols, that the Run 211 governance
execution policy boundary holds end-to-end in release mode: fixture governance
execution is accepted on DevNet/TestNet only under the explicit fixture policy;
the emergency council fixture is accepted only under the explicit emergency
fixture policy; production, on-chain, and MainNet governance execution remain
unavailable/fail-closed; the input/decision/transcript/policy digests are
deterministic and domain-bound; a lifecycle action is authorized only when the
action, candidate digest, and sequence all match; rejected cases produce no
mutation; and the MainNet peer-driven-apply refusal is preserved.

Run 212 is **release-binary evidence only**. It makes **no production source
change** (helper + harness + docs only). It does **not** implement a real
governance execution engine, a real on-chain governance proof verifier, a real
KMS/HSM backend, or a real RemoteSigner backend, and it implements no
validator-set rotation. Fixture governance execution is DevNet/TestNet
evidence-only and is refused on a MainNet trust domain; the production,
on-chain, and MainNet governance execution paths remain unavailable/fail-closed
regardless of inputs; the custody (Runs 188–193), RemoteSigner (Runs 194–202),
KMS/HSM (Runs 203–204), and custody-attestation (Runs 205–210) boundaries
remain separate, unchanged options; and MainNet peer-driven apply remains the
Run 147 / 148 / 152 FATAL refusal even when a fixture governance approval is
carried.

## Strict scope

* Release-binary evidence only; uses real `target/release/qbind-node`.
* Uses a release-built helper to drive the Run 211 governance execution policy
  corpus through the production library symbols.
* No production source change (none was required).
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No real KMS implementation; no real HSM implementation.
* No real RemoteSigner backend; no networked signer daemon.
* No production signing-key custody.
* No MainNet peer-driven apply enablement.
* No validator-set rotation; no autonomous apply; no apply on receipt; no
  peer-majority authority.
* No schema/wire change; no authority-marker / sequence-file / trust-bundle
  core schema change; no authority-lifecycle semantics change.
* Does not weaken Runs 070, 130–211; does not claim full C4 or C5 closure.

## Run 212 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_212_governance_execution_policy_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_212_governance_execution_policy_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_212_governance_execution_policy_release_binary.sh`](
    ../../scripts/devnet/run_212_governance_execution_policy_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_212_governance_execution_policy_release_binary/`](
    run_212_governance_execution_policy_release_binary/)
  (tracks `README.md`, `summary.txt`, `.gitignore`; all per-run artifacts
  are `.gitignore`d).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`](
      ../protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md)
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](
      ../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## What Run 212 proves

1. Fixture governance execution is accepted under the explicit fixture policy on
   DevNet/TestNet (evidence-only).
2. Emergency council fixture execution is accepted only under the explicit
   emergency fixture policy and is explicitly separate / non-production.
3. Production governance execution remains unavailable/fail-closed.
4. On-chain governance execution remains unavailable/fail-closed.
5. MainNet governance execution remains unavailable/fail-closed.
6. Governance input/decision/transcript/policy digests are deterministic and
   domain-bound.
7. Governance execution authorizes a lifecycle action only when the action,
   candidate digest, and sequence all match.
8. Validator-set rotation remains unsupported.
9. Rejected governance-execution cases produce no mutation.
10. MainNet peer-driven apply remains refused even with a fixture governance
    approval.
11. No real governance execution engine, on-chain proof verifier, KMS/HSM
    backend, RemoteSigner backend, or validator-set rotation is claimed.

## Release-binary surface invariants

The harness drives the real `target/release/qbind-node`. Run 211 is a pure
library boundary (no CLI flag and no env selector is added), so the binary
contract is that **no** surface exposes or enables governance execution:

* **S1** `--help` advertises no governance-execution surface, no production /
  MainNet governance enablement, no on-chain governance proof verifier, and no
  `run-211` / `run-212` token.
* **S2–S4** default DevNet / TestNet / MainNet `--print-genesis-hash` surface
  emits no governance-execution enablement banner and no MainNet peer-driven
  apply enablement claim.
* **S5** the Run 193 custody + Run 198 RemoteSigner + Run 209
  custody-attestation selectors armed together on DevNet stay
  governance-execution-silent.
* **S6** MainNet with the legacy selectors armed preserves the MainNet
  peer-driven apply refusal and emits no governance-execution enablement.
* **S7** the Run 180 governance on-chain fixture flag armed on DevNet produces
  no governance-execution drift (the fixture-proof banner explicitly states it
  never implements governance execution, an on-chain proof verifier, KMS/HSM,
  or validator-set rotation, and that MainNet remains refused).

> Honest limitation: the Run 211 governance execution policy boundary is
> consumed at the library/helper level; the release binary does not yet wire a
> governance execution evaluator into a long-running node runtime, so no
> production governance is enabled at the binary surface. The full
> input/decision/expectations → evaluator → outcome → peer-driven-guard chain is
> therefore proven in release mode through the production library symbols by the
> release-built helper.

## Release-helper corpus

The release-built helper
`run_212_governance_execution_policy_release_binary_helper` exercises the Run
211 corpus in **release mode through the production library symbols**
(`accepted`, `rejection`, `reachability` tables; all `verdict: PASS`,
73 checks total, 0 fail):

* **Accepted (A-corpus).** Fixture governance execution accepted under
  `FixtureGovernanceAllowed` for the initial-activation / rotate / retire /
  revoke / emergency-revoke lifecycle actions on DevNet and TestNet; emergency
  council fixture accepted under `EmergencyCouncilFixtureAllowed`; the typed
  outcome carries the matching input/decision/transcript digests.
* **Rejection (R-corpus).** Fixture governance rejected under
  `ProductionGovernanceRequired` / `MainnetGovernanceRequired`; emergency
  fixture rejected under `ProductionGovernanceRequired` /
  `MainnetGovernanceRequired`; production / on-chain / MainNet governance
  execution rejected as the typed unavailable outcome; class/policy mismatch,
  unknown class, wrong action / candidate-digest / authority-domain / sequence /
  quorum-threshold, expired decision, stale-or-replayed decision, malformed
  input / decision, unsupported governance-execution version, fixture-on-MainNet
  refusal, validator-set rotation unsupported, and policy-change action
  unsupported all rejected; rejection is pure (stable repeat results, no marker
  and no sequence write).
* **Reachability.** Input/decision/transcript/policy digests are byte-identical
  across repeats and domain-bound; the composition of
  `evaluate_governance_execution_with_peer_driven_guard` yields the typed
  `Accepted` / `Rejected` / `MainNetPeerDrivenApplyRefused` outcomes; the
  fail-closed helpers
  (`mainnet_peer_driven_apply_remains_refused_under_governance_execution`,
  `local_operator_cannot_satisfy_governance_execution`,
  `peer_majority_cannot_satisfy_governance_execution`,
  `validator_set_rotation_remains_unsupported`) return the expected fail-closed
  booleans; and MainNet peer-driven apply is refused even with a fixture
  governance approval.

## Source/release reachability proof

The harness records `grep` call-site proof under
`reachability/source_reachability.txt` for: the module
`pqc_governance_execution_policy`; the `GovernanceExecutionClass`,
`GovernanceExecutionPolicy`, and `GovernanceAction` enums; the
`GovernanceQuorumThreshold` quorum/threshold metadata; the
`GovernanceExecutionInput`, `GovernanceExecutionDecision`, and
`GovernanceExecutionExpectations` structs; the `input_digest`,
`decision_digest`, `governance_execution_transcript_digest`, and
`governance_execution_policy_digest` helpers; the `GovernanceExecutionEvaluator`
trait; the `FixtureGovernanceExecutionEvaluator`; the
`ProductionGovernanceExecutionEvaluator`,
`OnChainGovernanceExecutionEvaluator`, and
`MainnetGovernanceExecutionEvaluator` fail-closed evaluators; the
`evaluate_governance_execution_with_peer_driven_guard` peer-driven-guard
composition; and the fail-closed helpers. The module declaration in
`crates/qbind-node/src/lib.rs` is recorded under
`reachability/module_declaration.txt`.

## No-mutation / denylist proof

For every rejected governance-execution scenario the harness records
(`no_mutation_proof.txt`): no Run 070 apply call, no live trust swap, no
session eviction, no sequence write, no marker write, no `.tmp` residue, no
fallback to `--p2p-trusted-root`, and no active DummySig / DummyKem / DummyAead.
The Run 211 evaluators, digest helpers, peer-driven guard composition, and
fail-closed helpers are pure functions returning typed owned outcomes; a
Disabled / production / on-chain / MainNet governance policy fails closed
**before** any sequence/marker write, **before** any live trust swap, **before**
any session eviction, and **before** any Run 070 call. The denylist
(`negative_invariants.txt`) is proven empty across all captured logs for the
forbidden-claim corpus (no real governance execution engine active, no
production governance active, no MainNet governance enabled, no on-chain
governance proof verifier connected/active, no real KMS / HSM / RemoteSigner
backend, no custody attestation production active, no validator-set rotation
enabled, no schema/wire/metric drift, no MainNet peer-driven apply enabled, no
autonomous apply, no apply-on-receipt, no peer-majority authority).

## Validation commands

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_212_governance_execution_policy_release_binary_helper
bash scripts/devnet/run_212_governance_execution_policy_release_binary.sh
cargo test -p qbind-node --test run_211_governance_execution_policy_tests
cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests
cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests
cargo test -p qbind-node --test run_188_authority_custody_boundary_tests
cargo test -p qbind-node --test run_178_onchain_governance_proof_tests
cargo test -p qbind-node --test run_163_governance_authority_verifier_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

The harness additionally cross-checks the broader Run 134–211 regression target
set named in `task/RUN_212_TASK.txt` (recording any target absent from this
tree as `skipped(not-present)`), and writes the canonical
`docs/devnet/run_212_governance_execution_policy_release_binary/summary.txt`
verdict line. Observed result: the release node binary and Run 212 helper build
clean; the release helper reports `verdict: PASS` over its `accepted` /
`rejection` / `reachability` tables (73 checks, 0 fail); the S1–S7 real-binary
surface scenarios pass; the denylist is proven empty; and the regression
targets pass unchanged. (If a referenced test target name differs in a future
checkout, locate the nearest existing target and document the exact
command/result.)

## Why C4 / C5 remain OPEN

Run 212 only proves, in release mode, that the Run 211 governance execution
policy boundary resolves correctly, fails closed on production / on-chain /
MainNet policies and on malformed input, and authorizes a lifecycle action only
under an explicit fixture policy with a fully matching action / candidate digest
/ sequence. It implements no real governance execution engine, no real on-chain
governance proof verifier, no real KMS/HSM backend, no real RemoteSigner
backend, and no validator-set rotation; fixture governance execution remains
DevNet/TestNet evidence-only and is refused on MainNet; production / on-chain /
MainNet governance execution remains unavailable/fail-closed regardless of
inputs; the custody / KMS-HSM / RemoteSigner / custody-attestation / governance
proof paths remain compatible and unchanged; and MainNet peer-driven apply
remains the Run 147 / 148 / 152 FATAL refusal even with a fixture governance
approval. **Full C4 remains OPEN. C5 remains OPEN.**