# QBIND DevNet evidence — Run 205

**Title.** Source/test production custody attestation verifier skeleton.

**Status.** PASS (source/test only). Run 205 adds a typed production
custody attestation verifier skeleton: an attestation class, an
attestation policy, typed attestation evidence, a typed verifier input,
deterministic evidence/input/transcript/provider-identity digests, a
pure/mockable attestation verifier trait with a DevNet/TestNet fixture
verifier and fail-closed production/cloud/PKCS#11/HSM/RemoteSigner
verifiers, a typed outcome taxonomy, a pure verifier, and composition
helpers that layer the attestation boundary on top of the Run 188 custody
metadata validator while preserving the MainNet peer-driven-apply
refusal.

Run 205 does **not** implement a real cloud-KMS attestation verifier, a
real PKCS#11 attestation verifier, a real HSM vendor attestation
verifier, or a real RemoteSigner attestation verifier. The default
remains `CustodyAttestationPolicy::Disabled`. The fixture attestation is
DevNet/TestNet source/test only; the production, cloud-KMS, PKCS#11,
HSM-vendor, and RemoteSigner attestation paths remain
unavailable/fail-closed; the RemoteSigner path (Runs 194–202) and the
KMS/HSM backend path (Runs 203–204) remain separate, unchanged
backend-boundary options; and MainNet peer-driven apply remains the
Run 147 / 148 / 152 FATAL refusal even when a fixture attestation
verifies successfully.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 206).
* No real KMS implementation.
* No real HSM implementation.
* No real cloud KMS attestation verifier.
* No real PKCS#11 attestation verifier.
* No real HSM vendor attestation verifier.
* No real RemoteSigner backend; no networked signer daemon.
* No production signing-key custody.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No marker / sequence-file / trust-bundle core / authority-lifecycle
  semantics change.
* Run 205 does not weaken any prior run (Runs 070, 130–204) and does not
  claim full C4 or C5 closure.

## Run 205 deliverables

* Production source module:
  [`crates/qbind-node/src/pqc_custody_attestation_verifier.rs`](
    ../../crates/qbind-node/src/pqc_custody_attestation_verifier.rs).
* Module registration in
  [`crates/qbind-node/src/lib.rs`](../../crates/qbind-node/src/lib.rs).
* Focused test suite:
  [`crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs`](
    ../../crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs).
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

## Attestation verifier surface

The Run 205 module `pqc_custody_attestation_verifier` defines:

* **Attestation class** — `CustodyAttestationClass` enumerates
  `Disabled`, `FixtureAttestation`, `RemoteSignerAttestation`,
  `KmsAttestation`, `HsmAttestation`, `CloudKmsAttestationUnavailable`,
  `Pkcs11HsmAttestationUnavailable`, `ProductionAttestationUnavailable`,
  and `Unknown`, with `is_fixture` and `is_production_unavailable`
  helpers.
* **Attestation policy** — `CustodyAttestationPolicy` enumerates
  `Disabled` (default), `FixtureAttestationAllowed`,
  `RemoteSignerAttestationRequired`, `KmsAttestationRequired`,
  `HsmAttestationRequired`, `ProductionAttestationRequired`, and
  `MainnetProductionAttestationRequired`.
* **Attestation evidence** — `CustodyAttestationEvidence` binds the
  attestation class and schema version; the trust-domain environment,
  chain id, genesis hash, authority root fingerprint, and bundle-signing
  key fingerprint; the Run 188 custody class; the custody backend kind
  (where applicable); the backend / provider / signer id; the custody key
  id / key label; the suite id; the lifecycle action; the candidate
  digest; the authority-domain sequence; the optional governance proof
  digest; the optional bound Run 201 / Run 203 request / response /
  transcript digests; the attestation nonce; an optional issuance
  timestamp/epoch; an optional freshness/expiry window; and a placeholder
  evidence / certificate commitment.
* **Attestation verifier input** — `CustodyAttestationInput` carries the
  caller-supplied expectations (environment, chain id, genesis hash,
  authority root fingerprint, bundle-signing key fingerprint, custody
  class, backend/provider/signer id, custody key id, suite, lifecycle
  action, candidate digest, authority-domain sequence, optional
  governance/request/response/transcript digests, attestation nonce) plus
  a freshness/replay window (`replay_window_since_unix` /
  `replay_window_until_unix`) and the current timestamp/epoch
  (`now_unix`).
* **Deterministic digests** — domain-separated SHA3-256 digests:
  `CustodyAttestationEvidence::evidence_digest`,
  `CustodyAttestationInput::input_digest`, the free
  `attestation_transcript_digest(evidence_digest, input_digest)`, and the
  optional `CustodyAttestationEvidence::provider_identity_digest`.
* **Verifier trait / abstraction** — the pure / mockable
  `CustodyAttestationVerifier` trait (`class` +
  `verify_custody_attestation`). The DevNet/TestNet source/test-only
  `FixtureCustodyAttestationVerifier` delegates to the pure
  `verify_custody_attestation`, while `RemoteSignerAttestationVerifier`,
  `KmsAttestationVerifier`, `HsmAttestationVerifier`,
  `CloudKmsAttestationVerifier`, `Pkcs11HsmAttestationVerifier`, and
  `ProductionAttestationVerifier` are callable but fail closed as the
  matching unavailable outcome.
* **Typed outcomes** — `CustodyAttestationOutcome` distinguishes the
  fixture-attestation-accepted case from every reject case the task
  enumerates (attestation disabled; fixture rejected under
  production / mainnet-production policy; RemoteSigner, KMS, HSM, cloud
  KMS, PKCS#11 HSM, production, and MainNet production attestation
  unavailable; unknown attestation class rejected; attestation
  class/policy mismatch; fixture rejected for MainNet; wrong environment
  / chain / genesis / authority root / signing-key fingerprint / custody
  class / backend-provider-signer id / key id / suite / lifecycle action
  / candidate digest / authority-domain sequence; wrong governance proof
  / request / response / transcript digest; stale/replayed attestation;
  expired attestation; malformed evidence; unsupported version; invalid
  attestation commitment; local-operator / peer-majority cannot satisfy
  production attestation).

### New domain tags

Run 205 introduces four new domain tags, all under the existing `QBIND:`
prefix convention:

| constant | value |
|----------|-------|
| `CUSTODY_ATTESTATION_EVIDENCE_DOMAIN_TAG` | `QBIND:run205-custody-attestation-evidence:v1` |
| `CUSTODY_ATTESTATION_INPUT_DOMAIN_TAG` | `QBIND:run205-custody-attestation-input:v1` |
| `CUSTODY_ATTESTATION_TRANSCRIPT_DOMAIN_TAG` | `QBIND:run205-custody-attestation-transcript:v1` |
| `CUSTODY_ATTESTATION_PROVIDER_IDENTITY_DOMAIN_TAG` | `QBIND:run205-custody-attestation-provider-identity:v1` |

These are additive and collide with no other QBIND canonical digest. The
explicit `CUSTODY_ATTESTATION_INVALID_COMMITMENT_SENTINEL` constant drives
the source/test invalid-commitment rejection vector, and
`CUSTODY_ATTESTATION_SUPPORTED_VERSION` (1) drives the unsupported-version
rejection vector.

## Composition and fail-closed behavior

* The verifier `verify_custody_attestation` gates by policy first
  (Disabled and the production-required / mainnet-production policies fail
  closed before any binding check, distinguishing fixture vs
  production/cloud/PKCS#11 material), then — under the fixture-allowed
  policy — refuses any production/cloud/PKCS#11/RemoteSigner/unknown class
  as the matching typed unavailable/unknown outcome, enforces that the
  fixture class matches the fixture policy, refuses fixtures on a MainNet
  trust domain, and binds the evidence/input to the trust domain, the
  bundle-signing key fingerprint, the custody class, the
  backend/provider/signer id, the custody key id, the suite, the
  lifecycle action, the candidate digest, the next authority-domain
  sequence, the optional governance/request/response/transcript digests,
  the attestation commitment, the anti-replay nonce, the replay window,
  and the freshness/expiry window. Acceptance is only ever a fixture
  attestation under the `FixtureAttestationAllowed` policy on a
  DevNet/TestNet trust domain.
* `validate_custody_metadata_and_attestation` (and its grep-verifiable
  alias `validate_lifecycle_custody_and_attestation`) layers the
  attestation boundary on top of the Run 188
  `validate_lifecycle_governance_and_custody` composition. When
  `is_peer_driven_apply_preflight` is set and the trust domain is
  MainNet, it returns `MainNetPeerDrivenApplyRefused` **before**
  consulting custody or attestation — a fixture attestation can never
  enable a MainNet apply. The Run 188 custody layer is consulted first;
  if it rejects, the attestation verifier is not consulted
  (`LifecycleOrCustodyRejected`); if custody accepts but the attestation
  rejects, both are carried (`AttestationRejected`).
* The grep-verifiable helpers
  `local_operator_cannot_satisfy_production_attestation`,
  `peer_majority_cannot_satisfy_production_attestation`, and
  `mainnet_peer_driven_apply_remains_refused_under_attestation_boundary`
  encode the corresponding fail-closed rules.

The module is pure: every public function and trait method performs no
network or file I/O, writes no marker, writes no sequence, mutates no
live trust, evicts no sessions, and never invokes Run 070 apply.

## Tests added

[`crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs`](
  ../../crates/qbind-node/tests/run_205_custody_attestation_verifier_tests.rs)
covers the A1–A14 / R1–R40 matrix from `task/RUN_205_TASK.txt` (59
tests):

* **A1 / A2** — fixture attestation accepted under the explicit
  `FixtureAttestationAllowed` policy on DevNet and TestNet (including via
  the `FixtureCustodyAttestationVerifier` trait).
* **A3–A5** — deterministic, domain-bound evidence, input, and
  transcript digests.
* **A6** — the evidence binds the full authority tuple (environment,
  chain, genesis, authority root, signing-key fingerprint, custody class,
  backend/signer id, key id, lifecycle action, candidate digest,
  authority-domain sequence): mutating any bound field flips acceptance
  to a precise rejection.
* **A7** — the attestation verifier composes with the Run 188 custody
  metadata validator.
* **A8 / A9** — the attestation evidence composes with the Run 203
  fixture KMS and fixture HSM backend evidence (custody class + backend
  kind binding).
* **A10** — the attestation evidence composes with the Run 201
  RemoteSigner transport request/response/transcript digests as opaque
  evidence fields, while the RemoteSigner path stays a separate custody
  option.
* **A11 / A12 / A13** — the production, cloud-KMS, and PKCS#11 HSM
  attestation verifier boundaries are callable and return typed
  unavailable outcomes.
* **A14** — a `Disabled` attestation policy does not disturb GenesisBound
  / EmergencyCouncil / OnChainGovernance behavior.
* **R1–R40** — disabled-policy rejection; fixture rejected under
  production / mainnet-production policies; RemoteSigner, KMS, HSM, cloud
  KMS, PKCS#11 HSM, production, and MainNet production attestation
  unavailable; unknown class rejected; every binding-tuple mismatch
  (environment / chain / genesis / authority root / signing-key
  fingerprint / custody class / backend-provider-signer id / key id /
  suite / lifecycle action / candidate digest / authority-domain
  sequence); governance / request / response / transcript digest
  mismatches; stale/replayed and expired attestation; malformed evidence;
  unsupported version; invalid commitment; local-operator / peer-majority
  cannot satisfy production attestation; attestation valid but custody
  metadata invalid (R35); custody valid but attestation invalid (R36);
  lifecycle/governance/custody valid but production attestation
  unavailable (R37); validation-only and mutating-preflight rejection
  non-mutation (R38 / R39); and the MainNet peer-driven-apply refusal
  invariant with a fixture attestation (R40).
* Extras — fixture-vs-production attestation separation,
  provider-identity digest determinism, stable class/policy tags, and the
  production verifiers reporting their class.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests`
* `cargo test -p qbind-node --test run_203_kms_hsm_backend_boundary_tests`
* `cargo test -p qbind-node --test run_201_remote_signer_transport_boundary_tests`
* `cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`
* `cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests`
* `cargo test -p qbind-node --test run_194_remote_authority_signer_boundary_tests`
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests`
* `cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests`
* `cargo test -p qbind-node --test run_188_authority_custody_boundary_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`

All commands run on this checkout completed successfully, including:

* `run_205_custody_attestation_verifier_tests`: 59 passed.
* Prior-run regression suites (Runs 188 / 190 / 192 / 194 / 196 / 198 /
  201 / 203) remain green.
* Full `qbind-node` lib suite remains green.

## Acceptance summary

1. A typed custody attestation verifier skeleton exists
   (`pqc_custody_attestation_verifier`). ✅
2. Fixture attestation is DevNet/TestNet source-test only. ✅
3. Production / cloud / PKCS#11 / HSM vendor / RemoteSigner attestation
   remains unavailable/fail-closed. ✅
4. Evidence / input / transcript digests are deterministic and
   domain-bound. ✅
5. The attestation verifier composes with the Run 188 custody metadata. ✅
6. The attestation verifier composes with the Run 201 RemoteSigner
   transport and Run 203 KMS/HSM backend boundaries where feasible. ✅
7. Validation-only surfaces remain non-mutating. ✅
8. Mutating rejection paths produce no mutation. ✅
9. MainNet peer-driven apply remains refused. ✅
10. Release-binary custody-attestation verifier-boundary evidence is
    deferred to Run 206. ✅
11. No real KMS/HSM attestation / RemoteSigner backend / governance
    execution / validator-set rotation claim is made. ✅
12. No full C4 or C5 closure is claimed. ✅

## Deferred

* Release-binary custody-attestation verifier-boundary evidence:
  **Run 206**.
* Real cloud-KMS / PKCS#11 / HSM-vendor / RemoteSigner attestation
  verification remains unimplemented.
* Real KMS / HSM / cloud-KMS / PKCS#11 backend remains unimplemented.
* Real RemoteSigner backend / networked signer daemon remains
  unimplemented.
* Real on-chain governance proof verification remains unimplemented.
* Governance execution remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.