# QBIND DevNet evidence — Run 203

**Title.** Source/test KMS/HSM backend abstraction boundary.

**Status.** PASS (source/test only). Run 203 adds a typed,
provider-neutral KMS/HSM backend abstraction boundary for production
authority custody: a backend kind, a backend policy, a backend
identity/config, a backend request, a backend response, deterministic
identity/request/response/transcript digests, a pure/mockable backend
trait with DevNet/TestNet fixture backends and fail-closed
production/cloud/PKCS#11 backends, a typed outcome taxonomy, a pure
verifier, a custody-class router that composes the Run 188
`AuthorityCustodyClass::{Kms, Hsm}` classes, and a
lifecycle+governance+custody+backend composition helper.

Run 203 does **not** implement a real KMS backend, a real HSM backend, a
cloud-KMS integration, a PKCS#11 integration, a networked signer daemon,
or a real RemoteSigner backend. The default remains
`BackendPolicy::Disabled`. The fixture KMS/HSM backends are
DevNet/TestNet source/test only; the production, cloud-KMS, and PKCS#11
backends remain unavailable/fail-closed; the RemoteSigner path (Runs
194–202) remains a separate, unchanged custody option; and MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal even when
a fixture KMS/HSM backend returns a valid response.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 204).
* No real KMS implementation.
* No real HSM implementation.
* No cloud KMS integration.
* No PKCS#11 integration.
* No networked signer daemon; no real RemoteSigner backend.
* No production signing-key custody.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No marker / sequence-file / trust-bundle core / authority-lifecycle
  semantics change.
* Run 203 does not weaken any prior run (Runs 070, 130–202) and does not
  claim full C4 or C5 closure.

## Run 203 deliverables

* Production source module:
  [`crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs`](
    ../../crates/qbind-node/src/pqc_authority_kms_hsm_backend.rs).
* Module registration in
  [`crates/qbind-node/src/lib.rs`](../../crates/qbind-node/src/lib.rs).
* Focused test suite:
  [`crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs`](
    ../../crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs).
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

## Backend boundary surface

The Run 203 module `pqc_authority_kms_hsm_backend` defines:

* **Backend kind** — `BackendKind` enumerates `Disabled`, `FixtureKms`,
  `FixtureHsm`, `CloudKmsUnavailable`, `Pkcs11HsmUnavailable`,
  `ProductionKmsUnavailable`, `ProductionHsmUnavailable`, and `Unknown`,
  with `is_fixture`, `is_production_unavailable`, and `custody_class`
  helpers mapping each kind to the Run 188 `Kms` / `Hsm` custody class.
* **Backend policy** — `BackendPolicy` enumerates `Disabled` (default),
  `FixtureKmsAllowed`, `FixtureHsmAllowed`, `ProductionKmsRequired`,
  `ProductionHsmRequired`, and `MainnetProductionCustodyRequired`.
* **Backend identity / config** — `BackendIdentity` binds the backend id,
  provider id, key id / key label, authority root fingerprint,
  bundle-signing key fingerprint, environment, chain id, genesis hash,
  suite id, attestation / certificate digest placeholder, key usage
  policy, allowed lifecycle actions, and an optional freshness/expiry
  window.
* **Backend request** — `BackendRequest` binds the environment, chain id,
  genesis hash, authority root fingerprint, lifecycle action, candidate
  digest, authority-domain sequence, custody class, key id, signing-key
  fingerprints, an optional governance proof digest, the custody
  attestation digest, an anti-replay request nonce, and an optional
  request timestamp/epoch.
* **Backend response** — `BackendResponse` binds the backend kind, the
  echoed request digest, the backend id, provider id, key id, signature
  suite, a placeholder signature commitment, the attestation digest, an
  anti-replay response nonce, and an optional freshness/expiry window.
* **Deterministic digests** — domain-separated SHA3-256 digests:
  `BackendIdentity::identity_digest`, `BackendRequest::request_digest`,
  `BackendResponse::response_digest`, and the free
  `backend_transcript_digest(identity_digest, request_digest,
  response_digest)`.
* **Backend trait / abstraction** — the pure / mockable
  `AuthorityCustodyBackend` trait (`kind` + `identity` +
  `sign_authority_lifecycle_request`). DevNet/TestNet source/test-only
  `FixtureKmsBackend` / `FixtureHsmBackend` produce a deterministic,
  well-formed response that echoes the request digest, while
  `ProductionKmsBackend`, `ProductionHsmBackend`, `CloudKmsBackend`, and
  `Pkcs11HsmBackend` are callable but fail closed as
  `ProductionKmsUnavailable` / `ProductionHsmUnavailable` /
  `CloudKmsUnavailable` / `Pkcs11HsmUnavailable`. The pure verifier is
  `verify_authority_custody_backend_response`.
* **Typed outcomes** — `BackendOutcome` distinguishes the
  fixture-KMS-accepted and fixture-HSM-accepted cases from every reject
  case the task enumerates (backend disabled; fixture rejected under
  production / mainnet-production policy; production KMS / HSM, cloud KMS,
  PKCS#11 HSM, and MainNet production custody unavailable; unknown
  backend rejected; backend-kind/policy mismatch; fixture rejected for
  MainNet; wrong environment / chain / genesis / authority root / key id
  / signing-key fingerprint / lifecycle action / candidate digest /
  authority-domain sequence; wrong request / response / transcript
  digest; stale/replayed request / response; expired attestation /
  response; unsupported suite; invalid attestation / signature; malformed
  identity / request / response; local-operator / peer-majority cannot
  satisfy backend policy; not-KMS/HSM custody class).

### New domain tags

Run 203 introduces five new domain tags, all under the existing `QBIND:`
prefix convention:

| constant | value |
|----------|-------|
| `KMS_HSM_BACKEND_IDENTITY_DOMAIN_TAG` | `QBIND:run203-kms-hsm-backend-identity:v1` |
| `KMS_HSM_BACKEND_REQUEST_DOMAIN_TAG` | `QBIND:run203-kms-hsm-backend-request:v1` |
| `KMS_HSM_BACKEND_RESPONSE_DOMAIN_TAG` | `QBIND:run203-kms-hsm-backend-response:v1` |
| `KMS_HSM_BACKEND_TRANSCRIPT_DOMAIN_TAG` | `QBIND:run203-kms-hsm-backend-transcript:v1` |
| `KMS_HSM_BACKEND_FIXTURE_SIGNATURE_DOMAIN_TAG` | `QBIND:run203-kms-hsm-backend-fixture-signature:v1` |

These are additive and collide with no other QBIND canonical digest. The
explicit `KMS_HSM_BACKEND_INVALID_SIGNATURE_SENTINEL` and
`KMS_HSM_BACKEND_INVALID_ATTESTATION_SENTINEL` constants drive the
source/test invalid-signature and invalid-attestation rejection vectors.

## Composition and fail-closed behavior

* The verifier `verify_authority_custody_backend_response` gates by
  policy first (Disabled and the production-required / mainnet-production
  policies fail closed before any binding check, distinguishing fixture
  vs production/cloud/PKCS#11 material), then — under a fixture-allowed
  policy — refuses any production/cloud/PKCS#11/unknown response as the
  matching typed unavailable/unknown outcome, enforces that the fixture
  kind matches the fixture policy and the identity, refuses fixtures on a
  MainNet trust domain, and binds the identity/request/response to the
  trust domain, the key id, the signing-key fingerprint, the lifecycle
  action, the candidate digest, the next authority-domain sequence, the
  custody attestation digest, the request/response/transcript digests,
  the anti-replay nonces, the suite, the attestation/signature
  placeholders, and the identity/response freshness windows. Acceptance
  is only ever a fixture KMS/HSM response under the matching fixture
  policy on a DevNet/TestNet trust domain.
* `validate_backend_for_custody_class` dispatches `Kms` / `Hsm` to the
  verifier, refuses `LocalOperatorKey` / `FixtureLocalKey` as
  `LocalOperatorCannotSatisfyBackendPolicy`, and refuses every other
  class (including `RemoteSigner`) as `NotKmsHsmCustodyClass` — the
  RemoteSigner path (Runs 194–202) remains a separate custody option,
  not a replacement for KMS/HSM.
* `validate_lifecycle_governance_custody_and_backend` layers the KMS/HSM
  backend boundary on top of the Run 188
  `validate_lifecycle_governance_and_custody` composition. When
  `is_peer_driven_apply_preflight` is set and the trust domain is
  MainNet, it returns `MainNetPeerDrivenApplyRefused` **before**
  consulting custody or the backend — a fixture KMS/HSM backend can never
  enable a MainNet apply.
* The grep-verifiable helpers `local_operator_cannot_satisfy_backend_policy`,
  `peer_majority_cannot_satisfy_backend_policy`, and
  `mainnet_peer_driven_apply_remains_refused_under_kms_hsm_backend_boundary`
  encode the corresponding fail-closed rules.

The module is pure: every public function and trait method performs no
network or file I/O, writes no marker, writes no sequence, mutates no
live trust, evicts no sessions, and never invokes Run 070 apply.

## Tests added

[`crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs`](
  ../../crates/qbind-node/tests/run_203_kms_hsm_backend_boundary_tests.rs)
covers the A1–A15 / R1–R41 matrix from `task/RUN_203_TASK.txt` (60
tests):

* **A1–A4** — fixture KMS and fixture HSM accepted under the matching
  fixture policy on DevNet and TestNet.
* **A5–A8** — deterministic, domain-bound identity, request, response,
  and transcript digests.
* **A9 / A10** — the request binds the full authority tuple
  (environment, chain, genesis, authority root, lifecycle action,
  candidate digest, authority-domain sequence, custody class, key id),
  and the response binds the request digest, backend id, provider id,
  key id, signature suite, response digest, and attestation digest.
* **A11 / A12** — the production KMS and production HSM backends are
  callable and return typed unavailable outcomes.
* **A13** — the Run 188 custody validator remains compatible with the
  `Kms` / `Hsm` custody classes through the composition helper.
* **A14** — the RemoteSigner custody class is refused by the KMS/HSM
  router, proving the RemoteSigner path stays separate and unchanged.
* **A15** — a `Disabled` backend policy does not disturb GenesisBound /
  EmergencyCouncil / OnChainGovernance behavior.
* **R1–R41** — disabled-policy rejection; fixture rejected under
  production-KMS / production-HSM / mainnet-production policies;
  production KMS / HSM, cloud KMS, PKCS#11 HSM, and MainNet production
  custody unavailable; unknown backend rejected; every binding-tuple
  mismatch (environment / chain / genesis / authority root / key id /
  signing-key fingerprint / lifecycle action / candidate digest /
  authority-domain sequence); request / response / transcript digest
  mismatches; stale/replayed request / response; expired attestation /
  response; unsupported suite; invalid attestation / signature; malformed
  identity / request / response; local-operator / peer-majority cannot
  satisfy; backend valid but custody metadata invalid (R35); custody
  valid but backend response invalid (R36); lifecycle/governance/custody
  valid but production KMS / HSM unavailable (R37 / R38); validation-only
  and mutating rejection non-mutation (R39 / R40); and the MainNet
  peer-driven-apply refusal invariant with fixture KMS/HSM (R41).
* Extras — fixture-vs-production backend separation, fixture-kind/policy
  mismatch, and the cloud-KMS / PKCS#11 backend structs' callable
  fail-closed behavior.

## Validation commands

* `cargo build -p qbind-node --lib`
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

* `run_203_kms_hsm_backend_boundary_tests`: 60 passed.
* Prior-run regression suites (Runs 188 / 190 / 192 / 194 / 196 / 198 /
  201) remain green.
* `pqc_authority` lib self-tests: 164 passed; full `qbind-node` lib
  suite: 1328 passed.

## Acceptance summary

1. A typed KMS/HSM backend abstraction boundary exists
   (`pqc_authority_kms_hsm_backend`). ✅
2. Fixture KMS/HSM are DevNet/TestNet source-test only. ✅
3. Production KMS/HSM remain unavailable/fail-closed. ✅
4. Cloud KMS and PKCS#11 HSM are explicitly unavailable/fail-closed. ✅
5. Backend identity/request/response/transcript digests are
   deterministic and domain-bound. ✅
6. The backend boundary composes with the Run 188 custody classes. ✅
7. The RemoteSigner path remains separate and unchanged. ✅
8. Validation-only surfaces remain non-mutating. ✅
9. Mutating rejection paths produce no mutation. ✅
10. MainNet peer-driven apply remains refused. ✅
11. Release-binary KMS/HSM backend-boundary evidence is deferred to
    Run 204. ✅
12. No real KMS/HSM / RemoteSigner backend / governance execution /
    validator-set rotation claim is made. ✅
13. No full C4 or C5 closure is claimed. ✅

## Deferred

* Release-binary KMS/HSM backend-boundary evidence: **Run 204**.
* Real KMS / HSM / cloud-KMS / PKCS#11 backend remains unimplemented.
* Real RemoteSigner backend / networked signer daemon remains
  unimplemented.
* Real on-chain governance proof verification remains unimplemented.
* Governance execution remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.