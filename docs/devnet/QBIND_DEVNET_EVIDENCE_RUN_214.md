# QBIND DevNet evidence — Run 214

**Title.** Release-binary governance execution payload/carrying evidence.

**Status.** PASS (release-binary). Run 214 is the release-binary evidence run
for the Run 213 source/test governance **execution payload / carrying** and
production-context call-site wiring
([`crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs`](
  ../../crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs)).
It proves, on the **real** `target/release/qbind-node` plus a release-built
helper linking the production library symbols, that the Run 213 payload/carrying
boundary holds end-to-end in release mode: a legacy no-governance-execution
payload remains compatible under default `Disabled`; fixture governance
execution carried through the production-context routing helpers reaches the
Run 211 governance execution evaluator and is accepted on DevNet/TestNet only
under the explicit fixture policy; the emergency council fixture is accepted only
under the explicit emergency fixture policy; production, on-chain, and MainNet
governance execution material reaches the evaluator and remains
unavailable/fail-closed; malformed/invalid material fails closed; the
input/decision/transcript/policy digests are preserved through wire conversion
and remain deterministic and domain-bound; a carried lifecycle action is
authorized only when the action, candidate digest, and sequence all match;
rejected cases produce no mutation; and the MainNet peer-driven-apply refusal is
preserved.

Run 214 is **release-binary evidence only**. It makes **no production source
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
* Uses a release-built helper to mint governance-execution-carrying sidecars and
  drive the Run 213 payload/carrying corpus through the production library
  symbols.
* No production source change (none was required).
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No real KMS implementation; no real HSM implementation.
* No real RemoteSigner backend; no networked signer daemon.
* No production signing-key custody.
* No MainNet peer-driven apply enablement.
* No validator-set rotation; no autonomous apply; no apply on receipt; no
  peer-majority authority.
* No schema/wire change beyond Run 213's additive optional governance-execution
  sibling; no authority-marker / sequence-file / trust-bundle core schema
  change; no authority-lifecycle semantics change.
* Does not weaken Runs 070, 130–213; does not claim full C4 or C5 closure.

## Run 214 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_214_governance_execution_payload_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_214_governance_execution_payload_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_214_governance_execution_payload_release_binary.sh`](
    ../../scripts/devnet/run_214_governance_execution_payload_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_214_governance_execution_payload_release_binary/`](
    run_214_governance_execution_payload_release_binary/)
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

## What Run 214 proves

1. Legacy/no-governance-execution payloads remain compatible under default
   `Disabled` behavior.
2. Fixture governance execution material reaches production-context paths in
   release mode where policy allows (DevNet/TestNet evidence-only).
3. Production/on-chain/MainNet governance execution material reaches the
   evaluator and fails closed as unavailable.
4. Malformed/invalid governance execution material fails closed.
5. Governance input/decision/transcript/policy digests are preserved through
   wire conversion and remain deterministic and domain-bound.
6. A carried governance decision authorizes a lifecycle action only when the
   action, candidate digest, and sequence all match.
7. Validator-set rotation remains unsupported.
8. Rejected governance-execution-payload cases produce no mutation.
9. MainNet peer-driven apply remains refused even with a fixture governance
   approval.
10. No real governance execution engine, on-chain proof verifier, KMS/HSM
    backend, RemoteSigner backend, or validator-set rotation is claimed.

## Release-binary surface invariants

The harness drives the real `target/release/qbind-node`. Run 213 is a pure
library boundary (no CLI flag and no env selector is added), so the binary
contract is that **no** surface exposes or enables governance execution payload
carrying:

* **S1** `--help` advertises no governance-execution surface, no production /
  MainNet governance enablement, no on-chain governance proof verifier, and no
  `run-213` / `run-214` token.
* **S2–S4** default DevNet / TestNet / MainNet `--print-genesis-hash` surface
  emits no governance-execution enablement banner and no MainNet peer-driven
  apply enablement claim.
* **S5** the Run 193 custody + Run 198 RemoteSigner + Run 209
  custody-attestation selectors armed together on DevNet stay
  governance-execution-silent.
* **S6** MainNet with the legacy selectors armed preserves the MainNet
  peer-driven apply refusal and emits no governance-execution enablement.
* **S7** the Run 180 governance on-chain fixture flag armed on DevNet produces
  no governance-execution drift.

> Honest limitation: the Run 213 governance execution payload/carrying boundary
> is consumed at the library/helper level; the release binary does not yet wire a
> governance execution evaluator into a long-running node runtime, so no
> production governance is enabled at the binary surface. The full sidecar →
> optional `governance_execution` sibling → wire conversion → typed load status →
> per-surface routing helper → Run 211 evaluator → outcome → peer-driven-guard
> chain is therefore proven in release mode through the production library symbols
> by the release-built helper.

## Release-helper corpus

The release-built helper
`run_214_governance_execution_payload_release_binary_helper` exercises the Run
213 payload/carrying corpus in **release mode through the production library
symbols** (`accepted`, `rejection`, `reachability` tables; all `verdict: PASS`,
73 checks total, 0 fail):

* **Accepted (A1..A16).** A legacy no-governance-execution payload remains
  compatible under default `Disabled` (A1); DevNet/TestNet fixture governance
  execution carried through the reload-check and reload-apply contexts is
  accepted under the explicit fixture policy (A2..A4, A9); the input, decision,
  transcript, and policy digests are preserved through wire conversion (A5..A8);
  a carried lifecycle rotate/revoke action is authorized only when the carried
  decision authorizes that action with matching candidate digest and sequence
  (A10..A11); emergency revoke is accepted only under the explicit emergency
  fixture policy (A12); a combined lifecycle + governance proof +
  custody-attestation + fixture governance execution payload is accepted for the
  DevNet release-helper production-context path (A13); the GenesisBound /
  EmergencyCouncil / OnChainGovernance proof-carrier and the custody /
  RemoteSigner / KMS-HSM / custody-attestation paths remain compatible when the
  governance execution policy is `Disabled` (A14..A15); and production / on-chain
  / MainNet governance execution material reaches the evaluator and returns the
  typed unavailable outcome under a production-required policy (A16).
* **Rejection (R1..R40).** Governance execution material absent where the policy
  requires it (R1); malformed input / decision / combined payload (R2..R4);
  unsupported future schema version (R5); fixture rejected under
  `ProductionGovernanceRequired` / `MainnetGovernanceRequired` (R6..R8);
  production / on-chain / MainNet governance rejected as unavailable (R9..R11);
  unknown class (R12); wrong environment / chain / genesis / authority root /
  lifecycle action / candidate digest / authority-domain sequence / governance
  proof digest / on-chain proof digest / custody attestation digest / proposal id
  / decision id / effective epoch (R13..R25); expired and stale/replayed decision
  (R26..R27); insufficient quorum threshold (R28); emergency action not
  authorized (R29); validator-set rotation and policy-change action unsupported
  (R30..R31); local operator and peer majority cannot satisfy governance
  execution (R32..R33); governance-valid-but-lifecycle-mismatch and
  lifecycle-valid-but-governance-invalid (R34..R35); lifecycle + governance proof
  + custody valid but production governance execution unavailable (R36);
  validation-only rejection writes no marker and no sequence (R37); mutating
  rejection produces no Run 070 call, no live trust swap, no session eviction, no
  sequence write, and no marker write (R38); an invalid live `0x05`
  governance-execution candidate is not propagated, staged, or applied (R39); and
  MainNet peer-driven apply remains refused even with a fixture governance
  approval (R40).
* **Reachability.** The input/decision/transcript/policy digests are
  byte-identical across repeats and through round-trip wire conversion and remain
  domain-bound; the optional `governance_execution` sibling parses as `Absent`
  for a legacy sidecar, `Available` for a well-formed carrier, and `Malformed`
  for an invalid one; the seven per-surface routing helpers and the
  `evaluate_loaded_governance_execution{,_with_peer_driven_guard}` entry points
  yield the typed outcomes; and
  `mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying`
  refuses MainNet peer-driven apply even with a fixture governance approval.

## Source/release reachability proof

The harness records `grep` call-site proof under
`reachability/source_reachability.txt` for: the module
`pqc_governance_execution_payload_carrying`; the governance execution wire class
`GovernanceExecutionClassWire`; the governance execution action wire
`GovernanceExecutionActionWire`; the governance execution input wire
`GovernanceExecutionInputWire`; the governance execution decision wire
`GovernanceExecutionDecisionWire`; the governance execution payload wire
`GovernanceExecutionPayloadWire` and the `GovernanceExecutionParts`
reconstruction; the governance execution load status
`GovernanceExecutionLoadStatus`; the additive `governance_execution` sibling
field and schema-version constants; the
`parse_optional_governance_execution_sibling_from_json_value` parser and the
`load_v2_ratification_sidecar_with_governance_execution_from_{bytes,path}`
loaders; the `callsite_context_for_governance_execution` constructor; the seven
per-surface routing helpers
(`route_loaded_governance_execution_to_{reload_check,reload_apply,startup_p2p_trust_bundle,sighup,local_peer_candidate_check,live_inbound_0x05,peer_driven_drain}_callsite_decision`);
the Run 211 evaluator entry points `evaluate_loaded_governance_execution`,
`evaluate_loaded_governance_execution_with_peer_driven_guard`, and
`evaluate_governance_execution_policy`; and
`mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying`.
The module declaration in `crates/qbind-node/src/lib.rs` is recorded under
`reachability/module_declaration.txt`.

## No-mutation / denylist proof

For every rejected governance-execution-payload scenario the harness records
(`no_mutation_proof.txt`): no Run 070 apply call, no live trust swap, no
session eviction, no sequence write, no marker write, marker/sequence bytes
unchanged where present, no `.tmp` residue, no fallback to `--p2p-trusted-root`,
and no active DummySig / DummyKem / DummyAead. The Run 213 wire-conversion,
typed load status, the seven per-surface routing helpers, and the Run 211
evaluators are pure functions returning typed owned outcomes; a malformed /
required-but-absent / production / on-chain / MainNet governance execution
payload fails closed **before** any sequence/marker write, **before** any live
trust swap, **before** any session eviction, and **before** any Run 070 call.
For accepted fixture governance mutating compatibility scenarios the
`mutation_proof.txt` records that the governance-execution payload parse occurs
before the marker decision, governance execution evaluation and lifecycle /
governance-proof / custody / custody-attestation validation occur before any
apply/mutation, and the v2 marker persists strictly after the Run 055 sequence
commit. The denylist (`negative_invariants.txt`) is proven empty across all
captured logs for the forbidden-claim corpus (no real governance execution
engine active, no production governance active, no MainNet governance enabled,
no on-chain governance proof verifier connected/active, no real KMS / HSM /
RemoteSigner backend, no custody attestation production active, no validator-set
rotation enabled, no schema/wire/metric drift beyond Run 213's additive optional
governance-execution sibling, no MainNet peer-driven apply enabled, no
autonomous apply, no apply-on-receipt, no peer-majority authority).

## Validation commands

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_214_governance_execution_payload_release_binary_helper
bash scripts/devnet/run_214_governance_execution_payload_release_binary.sh
cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests
cargo test -p qbind-node --test run_211_governance_execution_policy_tests
cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests
cargo test -p qbind-node --test run_207_custody_attestation_payload_callsite_tests
cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests
cargo test -p qbind-node --test run_178_onchain_governance_proof_tests
cargo test -p qbind-node --test run_163_governance_authority_verifier_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

The harness additionally cross-checks the broader Run 134–213 regression target
set named in `task/RUN_214_TASK.txt` (recording any target absent from this
tree as `skipped(not-present)`), and writes the canonical
`docs/devnet/run_214_governance_execution_payload_release_binary/summary.txt`
verdict line. Observed result: the release node binary and Run 214 helper build
clean; the release helper reports `verdict: PASS` over its `accepted` /
`rejection` / `reachability` tables (73 checks, 0 fail); the S1–S7 real-binary
surface scenarios pass; the denylist is proven empty; and the regression
targets pass unchanged. (If a referenced test target name differs in a future
checkout, locate the nearest existing target and document the exact
command/result.)

## Why C4 / C5 remain OPEN

Run 214 only proves, in release mode, that the Run 213 governance execution
payload/carrying boundary carries input/decision material into the Run 211
evaluator correctly, preserves the digests through wire conversion, fails closed
on production / on-chain / MainNet policies, on malformed/required-but-absent
material, and on every wrong-binding mismatch, and authorizes a lifecycle action
only under an explicit fixture policy with a fully matching action / candidate
digest / sequence. It implements no real governance execution engine, no real
on-chain governance proof verifier, no real KMS/HSM backend, no real RemoteSigner
backend, and no validator-set rotation; fixture governance execution remains
DevNet/TestNet evidence-only and is refused on MainNet; production / on-chain /
MainNet governance execution remains unavailable/fail-closed regardless of
inputs; the custody / KMS-HSM / RemoteSigner / custody-attestation / governance
proof paths remain compatible and unchanged; and MainNet peer-driven apply
remains the Run 147 / 148 / 152 FATAL refusal even with a fixture governance
approval. **Full C4 remains OPEN. C5 remains OPEN.**
