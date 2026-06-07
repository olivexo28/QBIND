# QBIND DevNet evidence — Run 206

**Title.** Release-binary custody attestation verifier boundary evidence.

**Status.** PASS (release-binary evidence). Run 206 captures
release-binary evidence that the real `target/release/qbind-node` keeps
every existing Run 070 / 130–205 surface custody-attestation-silent, and
that a release-built helper exercises the Run 205 production custody
attestation verifier skeleton
([`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`](
  ../../crates/qbind-node/src/pqc_custody_attestation_verifier.rs))
layered over the Run 188 authority-custody boundary
([`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../crates/qbind-node/src/pqc_authority_custody.rs)), the Run 203
KMS/HSM backend boundary
([`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`](
  ../../crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs)), and the
Run 201 RemoteSigner transport boundary, end-to-end in **release mode**
through the production library symbols. Run 206 is **release-binary
custody-attestation verifier-boundary evidence**; it makes no
production-source change (it adds a release example helper, a release
harness, and documentation only).

Run 206 does **not** implement a real cloud KMS attestation verifier, a
real PKCS#11 attestation verifier, or a real HSM vendor attestation
verifier. The fixture custody attestation verifier remains DevNet/TestNet
evidence-only and is refused on a MainNet trust domain; the production,
cloud-KMS, PKCS#11, HSM, and RemoteSigner attestation verifiers reach the
boundary and fail closed as unavailable; malformed/invalid attestation
material fails closed; the RemoteSigner and KMS/HSM paths (Runs 194–204)
remain backend-boundary only and unchanged; and MainNet peer-driven apply
remains the Run 147 / 148 / 152 FATAL refusal even with a fixture
attestation response.

## Strict scope

* Release-binary evidence only, on real `target/release/qbind-node`.
* Use a release-built helper to exercise the Run 205 custody attestation
  verifier boundary in release mode through the production library symbols.
* No production-source change (helper + harness + docs only).
* No real KMS / HSM / cloud KMS / PKCS#11 attestation verifier.
* No real RemoteSigner backend; no networked signer daemon; no
  production signing key custody.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema / wire / metric drift; no authority-marker / sequence-file /
  trust-bundle core schema change.
* Run 206 does not weaken any prior run (Runs 070, 130–205) and does not
  claim full C4 or C5 closure.

## Run 206 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_206_custody_attestation_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_206_custody_attestation_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_206_custody_attestation_release_binary.sh`](
    ../../scripts/devnet/run_206_custody_attestation_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_206_custody_attestation_release_binary/`](
    run_206_custody_attestation_release_binary/) (tracked:
  `README.md`, `summary.txt`, `.gitignore`; all per-run artifacts are
  gitignored).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`](../protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md)
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Release-binary surface evidence

Run 205 added a pure additive library module only — no CLI flag, no env
var, and no runtime banner. The surface contract is therefore that every
existing Run 070 / 130–205 surface stays custody-attestation-silent. The
harness proves on the real `target/release/qbind-node`:

* **S1** — `qbind-node --help` advertises no custody-attestation / KMS /
  HSM / cloud-KMS / PKCS#11 / RemoteSigner backend surface, and no
  governance-execution / validator-set-rotation claim.
* **S2–S4** — `--print-genesis-hash --env {devnet,testnet,mainnet}` emits
  no custody-attestation enablement banner, no "custody attestation
  active" / "production attestation active" / "KMS attestation active" /
  "HSM attestation active" / "PKCS#11 active" / "cloud KMS active" /
  "RemoteSigner backend connected" claim, and no MainNet peer-driven apply
  enablement.
* **S5** — the Run 193 hidden custody policy selector
  (`devnet-local-allowed`, env var) remains compatible with no custody
  attestation banner drift.
* **S6** — the Run 198 hidden RemoteSigner policy selector remains
  compatible alongside the custody selector (no banner drift), proving the
  RemoteSigner path stays separate.
* **S7** — the governance fixture flag remains compatible with no custody
  attestation banner drift and no governance-execution claim.
* **S8** — even with the custody selector and the RemoteSigner policy
  selector set to `mainnet-production-remote-signer-required` on
  `--env mainnet`, MainNet peer-driven apply remains the Run 147 FATAL
  refusal and no custody-attestation / KMS / HSM / cloud-KMS / PKCS#11
  enablement is emitted.

The real binary resolves `--print-genesis-hash` through the existing
genesis-hash path; the attestation *semantics* are proven by the
release-built helper below, which links the production library symbols.

## Release-helper corpus evidence

The release-built helper exercises the Run 205 A1–A15 / R1–R40 corpus in
**release mode** through the production library symbols
`pqc_custody_attestation_verifier::*` layered over
`pqc_authority_custody::*`, `pqc_authority_kms_hsm_backend::*`, and the
Run 201 RemoteSigner transport boundary. It registers six tables:

* **accepted (15):** A1/A2 fixture attestation accepted under the explicit
  fixture policy on DevNet/TestNet; A3–A6 evidence / input / transcript /
  provider-identity digests deterministic (and order-sensitive for the
  transcript) and domain-bound; A7 the evidence binds environment, chain,
  genesis, authority root, signing-key fingerprint, custody class,
  backend/signer id, key id, lifecycle action, candidate digest, and
  authority-domain sequence; A8 fixture attestation composes with the
  Run 188 custody metadata; A9/A10 fixture attestation composes with the
  Run 203 fixture KMS and fixture HSM backend evidence; A11 fixture
  attestation composes with the Run 201 fixture RemoteSigner transport
  evidence; A12–A14 the production, cloud-KMS, and PKCS#11 HSM attestation
  boundaries are callable and return the typed unavailable outcomes; A15 a
  `Disabled` attestation policy does not disturb GenesisBound /
  EmergencyCouncil / OnChainGovernance behaviour.
* **rejection (40):** the full R1–R40 family — disabled policy (R1);
  fixture-rejected under production / mainnet-production attestation
  policies (R2/R3); RemoteSigner / KMS / HSM / cloud-KMS / PKCS#11 HSM /
  production / MainNet production attestation unavailable (R4–R10);
  unknown attestation class rejected (R11); every binding-tuple mismatch —
  environment, chain, genesis, authority root, signing-key fingerprint,
  custody class, backend/provider/signer id, key id, suite, lifecycle
  action, candidate digest, authority-domain sequence, governance proof
  digest, request digest, response digest, transcript digest (R12–R27);
  stale/replayed (R28); expired (R29); malformed evidence (R30);
  unsupported version (R31); invalid commitment (R32); local-operator and
  peer-majority cannot satisfy production attestation (R33/R34);
  attestation-valid-but-custody-invalid (R35);
  custody-valid-but-attestation-invalid (R36);
  lifecycle/governance/custody valid but production attestation
  unavailable (R37); validation-only non-mutation (R38);
  mutating-preflight no-mutation (R39); and MainNet peer-driven apply
  refused even with fixture attestation (R40).
* **separation (5):** fixture attestation refused for MainNet;
  fixture-vs-production attestation are distinct; the production /
  cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation verifiers perform
  no I/O and fail closed on DevNet/TestNet; the trait object is mockable;
  and the default policy is `Disabled`.
* **composition (4):** the full
  `validate_custody_metadata_and_attestation` /
  `validate_lifecycle_custody_and_attestation` accepts the DevNet fixture
  composition over a routed custody class; rejects when the inner
  lifecycle/custody composition rejects; rejects when the attestation
  evidence is corrupt; and short-circuits to
  `MainNetPeerDrivenApplyRefused` for a MainNet peer-driven-apply
  preflight.
* **determinism (2):** repeated DevNet/TestNet scenarios yield identical
  typed outcomes and identical evidence / input / transcript /
  provider-identity digests.
* **refusal_helpers (3):** the named MainNet refusal helper (true on
  MainNet, false on DevNet/TestNet) plus the local-operator and
  peer-majority cannot-satisfy helpers.

The helper writes a per-table breakdown plus a `helper_summary.txt`
ending in the canonical `verdict: PASS` line, and exits non-zero if any
case does not match its expected typed outcome. The harness asserts
`verdict: PASS` before continuing. On this checkout the helper reports
**total_pass: 69, total_fail: 0, verdict: PASS**.

## Source/release reachability

The harness records source-grep reachability under
`reachability/source_reachability.txt` for
`pqc_custody_attestation_verifier`; `CustodyAttestationClass`;
`CustodyAttestationPolicy`; `CustodyAttestationEvidence`;
`CustodyAttestationInput`; the `CustodyAttestationVerifier` trait; the
fixture custody attestation verifier (`FixtureCustodyAttestationVerifier`);
the production / cloud-KMS / PKCS#11 / HSM / RemoteSigner unavailable
attestation verifiers (`ProductionAttestationVerifier` /
`CloudKmsAttestationVerifier` / `Pkcs11HsmAttestationVerifier` /
`HsmAttestationVerifier` / `RemoteSignerAttestationVerifier`); the
evidence / input / provider-identity digest helpers; the transcript
digest helper `attestation_transcript_digest`; the verifier
`verify_custody_attestation`; and the compositions
`validate_custody_metadata_and_attestation` /
`validate_lifecycle_custody_and_attestation`, layered over
`pqc_authority_custody`.

## Mutation / no-mutation evidence

For every rejected custody-attestation-boundary scenario the helper proves
no mutation: `verify_custody_attestation`,
`validate_custody_metadata_and_attestation`, and
`validate_lifecycle_custody_and_attestation` are pure functions returning
typed owned outcomes. R38 asserts every input is byte-identical after a
rejecting validation; R39 asserts the candidate is unchanged after a
mutating-preflight composition rejection. No Run 070 apply call, no live
trust swap, no session eviction, no sequence write, no marker write, no
`.tmp` residue, no fallback to `--p2p-trusted-root`, and no active
DummySig / DummyKem / DummyAead are produced (`no_mutation_proof.txt`).
The harness denylist (`negative_invariants.txt`) proves all forbidden
patterns empty across captured logs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
  --example run_206_custody_attestation_release_binary_helper
bash scripts/devnet/run_206_custody_attestation_release_binary.sh
```

The harness additionally runs the Run 205 / 203 / 201 / 198 / 196 / 194 /
192 / 190 / 188 and the governance / lifecycle / peer-driven-apply
regression test targets from `task/RUN_206_TASK.txt`, plus
`cargo test -p qbind-node --lib pqc_authority` and `--lib`. Per-target
exit codes are captured under `exit_codes/` and summarised in
`summary.txt`. Targets absent from the tree are recorded as
`skipped(not-present)`. On this checkout all listed targets completed with
`rc=0`.

## Acceptance summary

1. The release-built helper proves the Run 205 custody attestation
   verifier corpus (A1–A15 / R1–R40) in release mode. ✅
2. Real `target/release/qbind-node` confirms MainNet peer-driven apply
   remains refused. ✅
3. Fixture custody attestation remains DevNet/TestNet evidence-only. ✅
4. Production / cloud-KMS / PKCS#11 / HSM / RemoteSigner attestation
   remain unavailable / fail-closed. ✅
5. Evidence / input / transcript / provider-identity digests are
   deterministic and domain-bound. ✅
6. The attestation verifier composes with the Run 188 custody metadata. ✅
7. The attestation verifier composes with the Run 201 RemoteSigner
   transport and Run 203 KMS/HSM backend boundaries where feasible. ✅
8. Rejected custody-attestation cases produce no mutation. ✅
9. Existing custody / KMS-HSM / RemoteSigner / governance proof paths
   remain compatible. ✅
10. No real KMS/HSM attestation / RemoteSigner backend / governance
    execution / validator-set rotation claim is made. ✅
11. No full C4 or C5 closure is claimed. ✅

## Standing invariants (unchanged by Run 206)

* No real cloud KMS attestation verifier is implemented.
* No real PKCS#11 attestation verifier is implemented.
* No real HSM vendor attestation verifier is implemented.
* No real RemoteSigner backend is implemented.
* No real KMS/HSM backend is implemented.
* Fixture custody attestation is DevNet/TestNet evidence-only and is
  refused on a MainNet trust domain.
* Production custody attestation remains unavailable / fail-closed.
* The custody attestation verifier does not enable MainNet peer-driven
  apply.
* RemoteSigner and KMS/HSM remain backend-boundary only and unchanged.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* Validator-set rotation remains open.
* Existing custody / KMS-HSM / RemoteSigner / governance proof paths
  remain compatible.
* Full C4 remains open.
* C5 remains open.