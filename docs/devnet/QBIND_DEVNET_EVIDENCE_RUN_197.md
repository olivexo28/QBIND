# QBIND DevNet evidence — Run 197

**Title.** Release-binary RemoteSigner identity/request/response
attestation payload/carrying and production-context evidence.

**Status.** PASS (release-binary evidence). Run 197 captures
release-binary evidence that real `target/release/qbind-node` production
payload/context paths can carry RemoteSigner identity / request /
response attestation material and route it into the Run 194 RemoteSigner
boundary through the Run 196 production-context helpers
([`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`](
  ../../crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs)),
layered over the Run 194 RemoteSigner boundary
([`crates/qbind-node/src/pqc_remote_authority_signer.rs`](
  ../../crates/qbind-node/src/pqc_remote_authority_signer.rs)). Run 197
is **release-binary RemoteSigner payload/carrying evidence**; it makes no
production-source change (it adds a release example helper, a release
harness, and documentation only).

Run 197 does **not** implement a real RemoteSigner backend. Fixture
loopback RemoteSigner material remains DevNet/TestNet evidence-only;
production RemoteSigner material reaches the boundary and fails closed as
unavailable; malformed/invalid material fails closed; and MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal even when
fixture loopback RemoteSigner material is supplied.

## Strict scope

* Release-binary evidence only, on real `target/release/qbind-node`.
* No production-source change (helper + harness + docs only).
* No real RemoteSigner backend; no networked signer service.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema / wire / metric drift beyond Run 196's additive optional
  `remote_signer_attestation` sibling; no authority-marker / sequence-file
  / trust-bundle core schema change.
* Run 197 does not weaken any prior run (Runs 070, 130–196) and does not
  claim full C4 or C5 closure.

## Run 197 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_197_remote_signer_payload_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_197_remote_signer_payload_release_binary.sh`](
    ../../scripts/devnet/run_197_remote_signer_payload_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_197_remote_signer_payload_release_binary/`](
    run_197_remote_signer_payload_release_binary/) (tracked: `README.md`,
  `summary.txt`, `.gitignore`; all per-run artifacts are gitignored).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Release-binary surface evidence

Run 196 added NO new CLI flag and NO new env var — it is a pure library
boundary plus a strictly additive optional JSON sibling. The harness
therefore proves the existing Run 070 / 130–196 surfaces remain
RemoteSigner-silent on real `target/release/qbind-node`:

* **S1** — `qbind-node --help` advertises no RemoteSigner / KMS / HSM
  surface, no `remote_signer_attestation` field, and no
  governance-execution / validator-set-rotation claim.
* **S2–S4** — `--print-genesis-hash --env {devnet,testnet,mainnet}`
  emits no RemoteSigner enablement banner, no "RemoteSigner backend
  connected" / "RemoteSigner production active" claim, no KMS/HSM active
  claim, and no MainNet peer-driven apply enablement.
* **S5** — the Run 193 hidden custody policy selector
  (`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=devnet-local-allowed`)
  remains compatible with no RemoteSigner banner drift.
* **S6** — the governance fixture flag
  (`--p2p-trust-bundle-onchain-governance-fixture-allowed`) remains
  compatible with no RemoteSigner banner drift and no governance-execution
  claim.
* **S7** — even with the Run 193 selector set to
  `mainnet-production-custody-required` on `--env mainnet`, MainNet
  peer-driven apply remains the Run 147 FATAL refusal and no
  RemoteSigner / KMS / HSM enablement is emitted.

## Release-helper corpus evidence

The release-built helper exercises the Run 196 A1–A10 / R1–R34 corpus in
**release mode** through the production library symbols
`pqc_remote_signer_payload_carrying::*` layered over
`pqc_remote_authority_signer::*`, routing each loaded carrier through the
seven per-surface production-context routing helpers and asserting the
typed `RemoteSignerPayloadCarryingDecisionOutcome`:

* **Accepted (A1–A10):** legacy no-RemoteSigner bypass under the default
  `Disabled` policy (A1); DevNet/TestNet fixture loopback carried through
  reload-check / reload-apply / startup-p2p / sighup / local-peer-candidate
  contexts and accepted under the explicit `FixtureLoopbackAllowed`
  policy (A2–A4, A7); canonical-digest preservation through wire
  conversion (A5); custody-class `RemoteSigner` routing (A6); governance
  / other-custody compatibility under `Disabled` (A8–A9); and production
  RemoteSigner reaching the boundary and returning the typed unavailable
  outcome under a production-required policy (A10).
* **Rejected (R1–R34):** absent-where-required, malformed
  identity/request/response/combined attestation, fixture-rejected under
  production / mainnet-production required, production and
  mainnet-production rejected as unavailable, the full
  wrong-environment/chain/genesis/authority-root/custody-key/signing-key/
  lifecycle/candidate-digest/sequence/request-digest binding-mismatch
  family, stale/replayed request and response, expired attestation and
  response, unsupported suite, invalid/placeholder signature,
  local-operator-key and peer-majority cannot satisfy RemoteSigner,
  custody-invalid composition rejection, validation-only and
  mutating-preflight no-mutation, invalid live `0x05` material not
  propagated, and MainNet peer-driven apply refused even with fixture
  loopback material (R34).

The helper writes a per-table breakdown plus a `helper_summary.txt`
ending in the canonical `verdict: PASS` line, and exits non-zero if any
scenario does not match its expected typed outcome. The harness asserts
`verdict: PASS` before continuing.

## Source/release reachability

The harness records source-grep reachability under
`reachability/source_reachability.txt` for `pqc_remote_signer_payload_carrying`;
`RemoteSigner{Identity,Request,Response,Attestation}Wire`;
`RemoteSignerLoadStatus`; `remote_signer_attestation`; the seven
per-surface routing helpers; `validate_loaded_remote_signer`;
`validate_remote_signer`; `validate_remote_signer_for_custody_class`; and
`validate_lifecycle_governance_custody_and_remote_signer`.

## Mutation / no-mutation evidence

For every rejected RemoteSigner-payload scenario the helper proves no
mutation: the validation-only routing helpers (reload-check /
local-peer-candidate-check / live-inbound-0x05) are pure functions
returning typed outcomes, and the mutating-preflight helpers
(reload-apply / startup-p2p / sighup) short-circuit a malformed carrier
**before** the Run 194 verifier and therefore before any sequence/marker
write or Run 070 call. No Run 070 apply call, no live trust swap, no
session eviction, no sequence write, no marker write, no `.tmp` residue,
no fallback to `--p2p-trusted-root`, and no active DummySig / DummyKem /
DummyAead are produced (`no_mutation_proof.txt`,
`no_mutation_evidence.txt`, `determinism_evidence.txt`).

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
  --example run_197_remote_signer_payload_release_binary_helper
bash scripts/devnet/run_197_remote_signer_payload_release_binary.sh
```

The harness additionally runs the Run 196 / Run 194 / Run 192 / Run 190 /
Run 188 and the governance / lifecycle / peer-driven-apply regression
test targets from `task/RUN_197_TASK.txt`, plus
`cargo test -p qbind-node --lib pqc_authority`,
`--lib pqc_remote_signer_payload_carrying`, and `--lib`. Per-target exit
codes are captured under `exit_codes/` and summarised in `summary.txt`.
Targets absent from the tree are recorded as `skipped(not-present)`.

## Standing invariants (unchanged by Run 197)

* No real RemoteSigner backend is implemented.
* Fixture loopback RemoteSigner is DevNet/TestNet evidence-only.
* Production RemoteSigner remains unavailable / fail-closed.
* RemoteSigner payload/carrying evidence does not enable MainNet
  peer-driven apply.
* KMS / HSM remain unimplemented.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* Validator-set rotation remains open.
* Existing custody / governance proof paths remain compatible.
* Full C4 remains open.
* C5 remains open.