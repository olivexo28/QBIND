# QBIND DevNet evidence — Run 208

**Title.** Release-binary custody-attestation payload carrying and
production-context routing evidence.

**Status.** PASS (release-binary). Run 208 is the release-binary evidence
run for the Run 207 source/test custody-attestation payload/carrying and
production-context wiring
([`crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs`](
  ../../crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs)).
It proves, on the **real** `target/release/qbind-node` plus a release-built
helper linking the production library symbols, that real production
payload/context paths can carry custody-attestation material and route it
into the Run 205 custody-attestation verifier
([`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`](
  ../../crates/qbind-node/src/pqc_custody_attestation_verifier.rs))
through the Run 207 production-context helpers, while preserving the default
`CustodyAttestationPolicy::Disabled` behavior, legacy no-attestation payload
compatibility, and the MainNet peer-driven-apply refusal.

Run 208 is **release-binary evidence only**. It makes **no production source
change** (helper + harness + docs only). It does **not** implement a real
cloud-KMS attestation verifier, a real PKCS#11 attestation verifier, a real
HSM-vendor attestation verifier, a real KMS/HSM implementation, or a real
RemoteSigner backend. Fixture attestation is DevNet/TestNet evidence-only;
the production, cloud-KMS, PKCS#11, HSM-vendor, and RemoteSigner attestation
paths remain unavailable/fail-closed; the RemoteSigner path (Runs 194–202)
and the KMS/HSM backend path (Runs 203–204) remain separate, unchanged
backend-boundary options; and MainNet peer-driven apply remains the Run 147 /
148 / 152 FATAL refusal even when a fixture attestation is carried.

## Strict scope

* Release-binary evidence only; uses real `target/release/qbind-node`.
* Uses release-built helper(s) to mint custody-attestation-carrying
  sidecars / peer-candidate material.
* No production source change unless a tiny harness-only fix is required
  (none was required).
* No real cloud-KMS / PKCS#11 / HSM-vendor attestation verifier.
* No real KMS implementation; no real HSM implementation.
* No real RemoteSigner backend; no networked signer daemon.
* No production signing-key custody.
* No MainNet peer-driven apply enablement.
* No governance execution engine; no real on-chain proof verifier; no
  validator-set rotation; no autonomous apply; no apply on receipt; no
  peer-majority authority.
* No schema/wire change beyond Run 207's additive optional
  custody-attestation sibling; no authority-marker / sequence-file /
  trust-bundle core schema change; no authority-lifecycle semantics change.
* Does not weaken Runs 070, 130–207; does not claim full C4 or C5 closure.

## Run 208 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_208_custody_attestation_payload_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_208_custody_attestation_payload_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_208_custody_attestation_payload_release_binary.sh`](
    ../../scripts/devnet/run_208_custody_attestation_payload_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_208_custody_attestation_payload_release_binary/`](
    run_208_custody_attestation_payload_release_binary/)
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

## Release-binary surface invariants

The harness drives the real `target/release/qbind-node`:

* **S1** `--help` advertises no custody-attestation / KMS / HSM / cloud-KMS /
  PKCS#11 / RemoteSigner-backend surface, no `run-205`..`run-208` token, no
  governance-execution and no validator-set-rotation claim.
* **S2–S4** default DevNet / TestNet / MainNet `--print-genesis-hash` surface
  emits no custody-attestation enablement banner and no MainNet peer-driven
  apply enablement claim.
* **S5** Run 193 custody-policy selector armed on DevNet — no custody
  attestation / KMS-HSM / cloud-KMS / PKCS#11 enablement drift.
* **S6** Run 198 RemoteSigner-policy selector armed alongside the custody
  selector on DevNet — no enablement drift, no RemoteSigner backend connect.
* **S7** governance fixture flag armed on DevNet — no custody attestation
  drift, no governance-execution / on-chain-proof-verifier-active claim.
* **S8** MainNet with custody + RemoteSigner selectors armed — MainNet
  peer-driven apply refusal preserved (Run 147 FATAL invariant), no custody
  attestation / KMS-HSM / cloud-KMS / PKCS#11 / validator-set-rotation
  enablement.

## Release-helper corpus

The release-built helper
`run_208_custody_attestation_payload_release_binary_helper` exercises the
Run 207 payload/carrying corpus in **release mode through the production
library symbols** (`accepted`, `rejection`, `loader`, `determinism`,
`refusal_reachability` tables; all `verdict: PASS`):

* **A1** legacy no-attestation payload compatible under `Disabled`
  (`NoCustodyAttestationSupplied` bypass).
* **A2 / A3** DevNet / TestNet fixture attestation carried through the
  reload-check context (via the JSON sibling round-trip) and accepted under
  the explicit fixture policy.
* **A4** DevNet fixture attestation carried through the reload-apply context
  and accepted (`Accepted`).
* **A5–A8** evidence / input / transcript / provider-identity digests
  preserved through wire conversion.
* **A9** fixture attestation routes to the Run 205 verifier
  (`verify_loaded_custody_attestation` → `FixtureAttestationAccepted`) when
  material is present.
* **A10** combined lifecycle + custody + fixture attestation accepted via
  `validate_loaded_lifecycle_custody_and_attestation`.
* **A11–A13** fixture attestation composes with the Run 203 fixture KMS /
  HSM backend contexts and the Run 201 fixture RemoteSigner transport context
  (carried as opaque evidence fields).
* **A14** GenesisBound / EmergencyCouncil / OnChainGovernance proof behavior
  unchanged when attestation policy is `Disabled`.
* **A15** production attestation material reaches the verifier and returns a
  typed unavailable outcome under `ProductionAttestationRequired`.
* **R1** absent under a required policy rejected fail-closed
  (`CustodyAttestationRequiredButAbsent`).
* **R2–R5** malformed evidence / input / combined payload and an unsupported
  future schema version rejected fail-closed (`Malformed*`,
  `UnknownSchemaVersion`).
* **R6 / R7** fixture attestation rejected under
  `ProductionAttestationRequired` / `MainnetProductionAttestationRequired`.
* **R8–R14** RemoteSigner / KMS / HSM / cloud-KMS / PKCS#11 / production /
  MainNet production attestation rejected as unavailable.
* **R15** unknown attestation class rejected.
* **R16–R34** wrong environment / chain / genesis / authority-root /
  signing-key fingerprint / custody class / backend-provider-signer id /
  key id / suite / lifecycle action / candidate digest / authority-domain
  sequence / governance-proof / request / response / transcript digest /
  stale-or-replayed / expired / invalid-commitment rejected at the Run 205
  verifier.
* **R35 / R36** local operator and peer majority cannot satisfy a production
  attestation (reload-check and peer-driven-drain surfaces).
* **R37 / R38** attestation valid but custody metadata invalid
  (`LifecycleOrCustodyRejected`); custody valid but attestation invalid
  (`InvalidAttestationCommitment`).
* **R39** lifecycle + governance + custody valid but production attestation
  unavailable rejected overall on the reload-apply preflight.
* **R40 / R41** validation-only and mutating-preflight routing helpers are
  pure (stable repeat results; fixture carrier accepted with no mutation).
* **R42** invalid live `0x05` custody-attestation candidate is not
  propagated / staged / applied (malformed-payload fail-closed).
* **R43** MainNet peer-driven apply remains refused even with a fixture
  attestation (`MainNetPeerDrivenApplyRefused` +
  `mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying`).
* **loader** legacy v2 sidecar without sibling → `Absent`; sidecar with
  sibling → `Available` with matching parts; sidecar with malformed sibling →
  `Malformed` while the ratification still parses; canonical sibling field /
  schema version; absent when missing or explicitly null.
* **determinism** wire round-trip digests byte-identical across repeats and
  bound to the source evidence; routing outcome stable across repeats.
* **refusal_reachability** the MainNet-refusal helper returns `true` only on
  MainNet; all seven production surfaces reach the Run 205 verifier and
  accept the fixture carrier on DevNet.

## Source/release reachability proof

The harness records `grep` call-site proof under
`reachability/source_reachability.txt` for: the module
`pqc_custody_attestation_payload_carrying`; the wire types
`CustodyAttestationClassWire`, `CustodyAttestationEvidenceWire`,
`CustodyAttestationInputWire`, `CustodyAttestationPayloadWire`; the
`CustodyAttestationLoadStatus`; the additive sibling
`CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD` (`"custody_attestation"`); the
sibling parser and combined loader; the seven per-surface routing helpers;
and the Run 205 entry points `verify_custody_attestation`,
`validate_custody_metadata_and_attestation`, and
`validate_lifecycle_custody_and_attestation`.

## No-mutation / denylist proof

For every rejected custody-attestation-payload scenario the harness records
(`no_mutation_proof.txt`): no Run 070 apply call, no live trust swap, no
session eviction, no sequence write, no marker write, no `.tmp` residue, no
fallback to `--p2p-trusted-root`, and no active DummySig / DummyKem /
DummyAead. A malformed carrier short-circuits **before** the Run 205 verifier
and **before** any marker/sequence write, live trust swap, session eviction,
or Run 070 call. The denylist (`negative_invariants.txt`) is proven empty
across all captured logs for the forbidden-claim corpus (no MainNet apply, no
autonomous apply, no apply-on-receipt, no peer-majority authority, no real
KMS/HSM/cloud-KMS/PKCS#11/RemoteSigner backend or attestation-active claim,
no production custody attestation active, no governance execution, no real
on-chain governance proof, no validator-set rotation, no schema/wire/metric
drift, no marker-before-sequence, no marker/sequence write on
validation-only surfaces).

## Validation commands

```
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_208_custody_attestation_payload_release_binary_helper
bash scripts/devnet/run_208_custody_attestation_payload_release_binary.sh
cargo test -p qbind-node --test run_207_custody_attestation_payload_callsite_tests
cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests
cargo test -p qbind-node --test run_203_kms_hsm_backend_boundary_tests
cargo test -p qbind-node --test run_201_remote_signer_transport_boundary_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

The harness additionally cross-checks the broader Run 134–207 regression
target set named in `task/RUN_208_TASK.txt` (recording any target absent
from this tree as `skipped(not-present)`), and writes the canonical
`docs/devnet/run_208_custody_attestation_payload_release_binary/summary.txt`
verdict line. Observed result: the release node binary and Run 208 helper
build clean; the release helper reports `verdict: PASS` over its
`accepted` / `rejection` / `loader` / `determinism` / `refusal_reachability`
tables; the S1–S8 real-binary surface scenarios pass; the denylist is proven
empty; and the regression targets pass unchanged. (If a referenced test
target name differs in a future checkout, locate the nearest existing target
and document the exact command/result.)

## Why C4 / C5 remain OPEN

Run 208 only proves, in release mode, that the Run 207 typed
custody-attestation material can be carried through production
payload/context paths and routed into the Run 205 verifier. It implements no
real cloud-KMS / PKCS#11 / HSM-vendor attestation verifier, no real
RemoteSigner backend, no governance execution engine, no real on-chain proof
verifier, and no validator-set rotation; the fixture attestation remains
DevNet/TestNet evidence-only and is refused on MainNet; production
attestation remains unavailable/fail-closed; and MainNet peer-driven apply
remains the Run 147 / 148 / 152 FATAL refusal. **Full C4 remains OPEN; C5
remains OPEN.**