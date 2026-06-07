# QBIND DevNet evidence — Run 204

**Title.** Release-binary KMS/HSM backend abstraction boundary evidence.

**Status.** PASS (release-binary evidence). Run 204 captures
release-binary evidence that the real `target/release/qbind-node` keeps
every existing Run 070 / 130–203 surface KMS/HSM-backend-silent, and that
a release-built helper exercises the Run 203 production KMS/HSM custody
backend abstraction boundary
([`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`](
  ../../crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs)) layered
over the Run 188 authority-custody boundary
([`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../crates/qbind-node/src/pqc_authority_custody.rs)) end-to-end in
**release mode** through the production library symbols. Run 204 is
**release-binary KMS/HSM backend-boundary evidence**; it makes no
production-source change (it adds a release example helper, a release
harness, and documentation only).

Run 204 does **not** implement a real KMS backend, a real HSM backend, a
cloud-KMS integration, or a PKCS#11 integration. The fixture KMS/HSM
backends remain DevNet/TestNet evidence-only and are refused on a MainNet
trust domain; the production, cloud-KMS, and PKCS#11 backends reach the
boundary and fail closed as unavailable; malformed/invalid backend
material fails closed; the RemoteSigner path (Runs 194–202) remains a
separate, unchanged custody option; and MainNet peer-driven apply remains
the Run 147 / 148 / 152 FATAL refusal even with a fixture KMS/HSM backend
response.

## Strict scope

* Release-binary evidence only, on real `target/release/qbind-node`.
* Use a release-built helper to exercise the Run 203 KMS/HSM backend
  boundary in release mode through the production library symbols.
* No production-source change (helper + harness + docs only).
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No real RemoteSigner backend; no networked signer daemon; no
  production signing key custody.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema / wire / metric drift; no authority-marker / sequence-file /
  trust-bundle core schema change.
* Run 204 does not weaken any prior run (Runs 070, 130–203) and does not
  claim full C4 or C5 closure.

## Run 204 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_204_kms_hsm_backend_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_204_kms_hsm_backend_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_204_kms_hsm_backend_release_binary.sh`](
    ../../scripts/devnet/run_204_kms_hsm_backend_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_204_kms_hsm_backend_release_binary/`](
    run_204_kms_hsm_backend_release_binary/) (tracked:
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

Run 203 added a pure additive library module only — no CLI flag, no env
var, and no runtime banner. The surface contract is therefore that every
existing Run 070 / 130–203 surface stays KMS/HSM-backend-silent. The
harness proves on the real `target/release/qbind-node`:

* **S1** — `qbind-node --help` advertises no KMS / HSM / cloud-KMS /
  PKCS#11 / RemoteSigner backend surface, and no governance-execution /
  validator-set-rotation claim.
* **S2–S4** — `--print-genesis-hash --env {devnet,testnet,mainnet}` emits
  no KMS/HSM backend enablement banner, no "KMS/HSM active" / "KMS
  enabled" / "HSM enabled" / "cloud KMS active" / "PKCS#11 active" /
  "RemoteSigner backend connected" claim, and no MainNet peer-driven apply
  enablement.
* **S5** — the Run 193 hidden custody policy selector
  (`devnet-local-allowed`, env var) remains compatible with no KMS/HSM
  backend banner drift.
* **S6** — the Run 198 hidden RemoteSigner policy selector remains
  compatible alongside the custody selector (no banner drift), proving the
  RemoteSigner path stays separate.
* **S7** — the governance fixture flag remains compatible with no KMS/HSM
  backend banner drift and no governance-execution claim.
* **S8** — even with the custody selector and the RemoteSigner policy
  selector set to `mainnet-production-remote-signer-required` on
  `--env mainnet`, MainNet peer-driven apply remains the Run 147 FATAL
  refusal and no KMS / HSM / cloud-KMS / PKCS#11 backend enablement is
  emitted.

The real binary resolves `--print-genesis-hash` through the existing
genesis-hash path; the backend *semantics* are proven by the
release-built helper below, which links the production library symbols.

## Release-helper corpus evidence

The release-built helper exercises the Run 203 A1–A15 / R1–R41 corpus in
**release mode** through the production library symbols
`pqc_authority_kms_hsm_backend::*` layered over
`pqc_authority_custody::*`. It registers six tables:

* **accepted (15):** A1–A4 fixture KMS and fixture HSM accepted under the
  matching fixture policy on DevNet/TestNet; A5–A8 identity / request /
  response / transcript digests deterministic and domain-bound (and
  order-sensitive for the transcript); A9 the request binds the full
  authority tuple (environment, chain, genesis, authority root, lifecycle
  action, candidate digest, authority-domain sequence, custody class, key
  id); A10 the response binds the request digest, backend id, provider id,
  key id, signature suite, response digest, and attestation digest; A11/A12
  the production KMS and production HSM backends are callable and return
  the typed unavailable outcomes; A13 the Run 188 custody validator remains
  compatible with the `Kms` / `Hsm` custody classes through the composition
  helper; A14 the RemoteSigner custody class is refused by the KMS/HSM
  router (RemoteSigner stays separate); A15 a `Disabled` backend policy
  does not disturb GenesisBound / EmergencyCouncil / OnChainGovernance
  behaviour.
* **rejection (41):** the full R1–R41 family — disabled policy;
  fixture-rejected under production-KMS / production-HSM /
  mainnet-production policies; production KMS / HSM, cloud KMS, PKCS#11
  HSM, and MainNet production custody unavailable; unknown backend
  rejected; every binding-tuple mismatch (environment, chain, genesis,
  authority root, key id, signing-key fingerprint, lifecycle action,
  candidate digest, authority-domain sequence); request / response /
  transcript digest mismatches; stale/replayed request / response; expired
  attestation / response; unsupported suite; invalid attestation /
  signature; malformed identity / request / response; local-operator and
  peer-majority cannot satisfy; backend-valid-but-custody-invalid (R35);
  custody-valid-but-backend-invalid (R36); lifecycle/governance/custody
  valid but production KMS / HSM unavailable (R37 / R38); validation-only
  non-mutation (R39); mutating-preflight no-mutation (R40); and MainNet
  peer-driven apply refused even with fixture KMS/HSM (R41).
* **separation (6):** fixture KMS/HSM backends refused for MainNet;
  fixture-vs-production backends are distinct; the production / cloud /
  PKCS#11 backends perform no I/O and fail closed on DevNet/TestNet; the
  custody-class router admits `Kms` / `Hsm` and rejects a non-KMS/HSM
  class; the trait object is mockable; and the default policy is
  `Disabled`.
* **composition (4):** the full
  `validate_lifecycle_governance_custody_and_backend` accepts the DevNet
  fixture composition over a routed custody class; rejects when the inner
  lifecycle/custody composition rejects; rejects when the backend response
  is corrupt (`BackendRejected`); and short-circuits to
  `MainNetPeerDrivenApplyRefused` for a MainNet peer-driven-apply
  preflight.
* **determinism (2):** repeated DevNet/TestNet scenarios yield identical
  typed outcomes and identical identity / request / response / transcript
  digests.
* **refusal_helpers (3):** the named MainNet refusal helper (true on
  MainNet, false on DevNet/TestNet) plus the local-operator and
  peer-majority cannot-satisfy helpers.

The helper writes a per-table breakdown plus a `helper_summary.txt`
ending in the canonical `verdict: PASS` line, and exits non-zero if any
case does not match its expected typed outcome. The harness asserts
`verdict: PASS` before continuing. On this checkout the helper reports
**total_pass: 71, total_fail: 0, verdict: PASS**.

## Source/release reachability

The harness records source-grep reachability under
`reachability/source_reachability.txt` for `pqc_authority_kms_hsm_backend`;
`BackendKind`; `BackendPolicy`; `BackendIdentity`; `BackendRequest`;
`BackendResponse`; the `AuthorityCustodyBackend` trait; the fixture
KMS/HSM backends (`FixtureKmsBackend` / `FixtureHsmBackend`); the
production / cloud / PKCS#11 unavailable backends (`ProductionKmsBackend`
/ `ProductionHsmBackend` / `CloudKmsBackend` / `Pkcs11HsmBackend`); the
identity / request / response digest helpers; `backend_transcript_digest`;
the verifier `verify_authority_custody_backend_response`; the
custody-class router `validate_backend_for_custody_class`; and the
composition `validate_lifecycle_governance_custody_and_backend`, layered
over `pqc_authority_custody`.

## Mutation / no-mutation evidence

For every rejected KMS/HSM backend-boundary scenario the helper proves no
mutation: `verify_authority_custody_backend_response`,
`validate_backend_for_custody_class`, and
`validate_lifecycle_governance_custody_and_backend` are pure functions
returning typed owned outcomes. R39 asserts every input is byte-identical
after a rejecting validation; R40 asserts the candidate is unchanged after
a mutating-preflight composition rejection. No Run 070 apply call, no live
trust swap, no session eviction, no sequence write, no marker write, no
`.tmp` residue, no fallback to `--p2p-trusted-root`, and no active
DummySig / DummyKem / DummyAead are produced (`no_mutation_proof.txt`).
The harness denylist (`negative_invariants.txt`) proves all forbidden
patterns empty across captured logs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
  --example run_204_kms_hsm_backend_release_binary_helper
bash scripts/devnet/run_204_kms_hsm_backend_release_binary.sh
```

The harness additionally runs the Run 203 / 201 / 198 / 196 / 194 / 192 /
190 / 188 and the governance / lifecycle / peer-driven-apply regression
test targets from `task/RUN_204_TASK.txt`, plus
`cargo test -p qbind-node --lib pqc_authority` and `--lib`. Per-target
exit codes are captured under `exit_codes/` and summarised in
`summary.txt`. Targets absent from the tree are recorded as
`skipped(not-present)`. On this checkout all listed targets completed with
`rc=0`.

## Acceptance summary

1. The release-built helper proves the Run 203 KMS/HSM backend corpus
   (A1–A15 / R1–R41) in release mode. ✅
2. Real `target/release/qbind-node` confirms MainNet peer-driven apply
   remains refused. ✅
3. Fixture KMS/HSM backends remain DevNet/TestNet evidence-only. ✅
4. Production KMS/HSM remain unavailable / fail-closed. ✅
5. Cloud KMS and PKCS#11 HSM remain unavailable / fail-closed. ✅
6. Backend identity / request / response / transcript digests are
   deterministic and domain-bound. ✅
7. The backend boundary composes with the Run 188 custody classes. ✅
8. The RemoteSigner path remains separate and unchanged. ✅
9. Rejected KMS/HSM backend-boundary cases produce no mutation. ✅
10. Existing custody / RemoteSigner / governance proof paths remain
    compatible. ✅
11. No real KMS/HSM / RemoteSigner backend / governance execution /
    validator-set rotation claim is made. ✅
12. No full C4 or C5 closure is claimed. ✅

## Standing invariants (unchanged by Run 204)

* No real KMS backend is implemented.
* No real HSM backend is implemented.
* No cloud KMS integration is implemented.
* No PKCS#11 integration is implemented.
* Fixture KMS/HSM is DevNet/TestNet evidence-only and is refused on a
  MainNet trust domain.
* Production KMS/HSM remain unavailable / fail-closed.
* The KMS/HSM boundary does not enable MainNet peer-driven apply.
* The RemoteSigner path remains separate and unchanged.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* Validator-set rotation remains open.
* Existing custody / RemoteSigner / governance proof paths remain
  compatible.
* Full C4 remains open.
* C5 remains open.
