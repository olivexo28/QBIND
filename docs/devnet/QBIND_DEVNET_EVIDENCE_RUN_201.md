# QBIND DevNet evidence — Run 201

**Title.** Source/test production RemoteSigner transport boundary.

**Status.** PASS (source/test only). Run 201 adds a typed
client/server-style RemoteSigner transport boundary: a transport
identity/endpoint config, a request envelope, a response envelope,
deterministic transcript-binding digests, authentication/identity
placeholders, a timeout/retry/error taxonomy, and fail-closed production
transport behavior for a future remote signer service. It composes with
the Run 194 RemoteSigner request/response types and (where feasible) the
Run 196 payload-carrying context.

Run 201 does **not** implement a real remote signer service, a networked
signer daemon, or any production signing-key custody. The default
remains `RemoteSignerPolicy::Disabled`. The fixture loopback transport is
DevNet/TestNet source/test only; the production transport remains
unavailable/fail-closed; and MainNet peer-driven apply remains the
Run 147 / 148 / 152 FATAL refusal even when the fixture loopback
transport returns a valid response.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 202).
* No real RemoteSigner backend; no networked signer daemon.
* No production signing-key custody.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No marker / sequence-file / trust-bundle core / authority-lifecycle
  semantics change.
* Run 201 does not weaken any prior run (Runs 070, 130–200) and does not
  claim full C4 or C5 closure.

## Run 201 deliverables

* Production source module:
  [`crates/qbind-node/src/pqc_remote_signer_transport.rs`](
    ../../crates/qbind-node/src/pqc_remote_signer_transport.rs).
* Module registration in
  [`crates/qbind-node/src/lib.rs`](../../crates/qbind-node/src/lib.rs).
* Focused test suite:
  [`crates/qbind-node/tests/run_201_remote_signer_transport_boundary_tests.rs`](
    ../../crates/qbind-node/tests/run_201_remote_signer_transport_boundary_tests.rs).
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

## Transport boundary surface

The Run 201 module `pqc_remote_signer_transport` defines:

* **Transport identity / endpoint config** —
  `RemoteSignerTransportConfig` binds the signer endpoint URI / abstract
  endpoint id, `signer_id`, `custody_key_id`,
  `authority_root_fingerprint`, `bundle_signing_key_fingerprint`,
  `environment`, `chain_id`, `genesis_hash`, `suite_id`, the
  `expected_signer_identity_digest`, an optional
  `transport_attestation_digest` placeholder, and a
  `TransportTimeoutRetryPolicy` (per-attempt timeout + max attempts).
* **Request envelope** — `RemoteSignerTransportRequestEnvelope` wraps the
  Run 194 `RemoteSignerRequest` and binds a protocol version, a domain
  tag, a request id / nonce, a timestamp/epoch, the trust-domain tuple,
  the custody key id, the expected signer id, the canonical request
  digest, the payload digest, and an anti-replay nonce.
* **Response envelope** — `RemoteSignerTransportResponseEnvelope` wraps
  the Run 194 `RemoteSignerResponse` and binds a protocol version, a
  domain tag, the request id echo, the signer id, custody key id, a
  response timestamp/expiry, the canonical response digest, the
  signature suite, a response commitment placeholder, and the transcript
  digest.
* **Transcript binding** — deterministic, domain-separated SHA3-256
  digests: `RemoteSignerTransportRequestEnvelope::envelope_digest`,
  `RemoteSignerTransportResponseEnvelope::envelope_digest`, and
  `transport_transcript_digest(request_envelope_digest,
  response_envelope_digest)`. The response envelope digest deliberately
  excludes its own `transcript_digest` field to avoid circularity. A
  helper `remote_signer_response_canonical_digest` provides the single
  canonical digest of a Run 194 response that the response envelope
  binds.
* **Transport trait / abstraction** — the pure / mockable
  `RemoteSignerTransport` trait (`config` + `call_remote_signer`) plus
  the free `send_remote_signer_request` helper. A DevNet/TestNet
  source/test-only `FixtureLoopbackRemoteSignerTransport` produces a
  deterministic well-formed response envelope (and can simulate
  timeout / retry-exhausted / invalid-attestation faults via
  `SimulatedTransportFault`), while `ProductionRemoteSignerTransport` is
  callable but fails closed as `ProductionTransportUnavailable` (or
  `MainNetProductionTransportUnavailable` on a MainNet config).
* **Typed outcomes** — `RemoteSignerTransportOutcome` distinguishes the
  fixture-accepted case from every reject case the task enumerates
  (transport disabled; fixture rejected under production /
  mainnet-production policy; production / MainNet-production unavailable;
  endpoint missing / malformed; wrong environment / chain / genesis /
  authority root / signer id / custody key id / signing-key fingerprint;
  wrong request id / request digest / response digest / transcript
  digest; stale/replayed request / response; timeout; retry exhausted;
  malformed request / response envelope; unsupported protocol version /
  suite; invalid transport attestation; local-operator /
  peer-majority cannot satisfy; RemoteSigner response invalid;
  not-RemoteSigner custody class).

### New domain tags

Run 201 introduces four new domain tags, all under the existing
`QBIND:` prefix convention:

| constant | value |
|----------|-------|
| `REMOTE_SIGNER_TRANSPORT_REQUEST_ENVELOPE_DOMAIN_TAG` | `QBIND:run201-remote-signer-transport-request-envelope:v1` |
| `REMOTE_SIGNER_TRANSPORT_RESPONSE_ENVELOPE_DOMAIN_TAG` | `QBIND:run201-remote-signer-transport-response-envelope:v1` |
| `REMOTE_SIGNER_TRANSPORT_TRANSCRIPT_DOMAIN_TAG` | `QBIND:run201-remote-signer-transport-transcript:v1` |
| `REMOTE_SIGNER_TRANSPORT_FIXTURE_COMMITMENT_DOMAIN_TAG` | `QBIND:run201-remote-signer-transport-fixture-commitment:v1` |

The response canonical digest helper uses
`QBIND:run201-remote-signer-response-canonical:v1`. These are additive
and collide with no other QBIND canonical digest.

## Composition and fail-closed behavior

* The verifier `validate_remote_signer_transport` gates by policy first
  (Disabled / production-required / mainnet-production-required fail
  closed before any binding check, distinguishing fixture vs production
  material), then binds the config and both envelopes to the trust
  domain and the signer/custody/signing-key identity, checks protocol
  version, request/response/transcript digests, anti-replay nonces, the
  response freshness window, the transport attestation, and the suite;
  it then **composes the Run 194 `validate_remote_signer`** over the
  wrapped request/response (R30) and finally binds the request/response
  transcript digest (R31). Acceptance is only ever a fixture loopback
  transport response under `FixtureLoopbackAllowed` on a DevNet/TestNet
  trust domain.
* `validate_lifecycle_custody_remote_signer_and_transport` layers the
  transport boundary on top of the Run 194
  `validate_lifecycle_governance_custody_and_remote_signer` composition.
  When `is_peer_driven_apply_preflight` is set and the trust domain is
  MainNet, it returns `MainNetPeerDrivenApplyRefused` **before**
  consulting custody, the remote signer, or the transport — the fixture
  loopback transport can never enable a MainNet apply (R35).
* `validate_remote_signer_transport_for_custody_class` refuses a
  `LocalOperatorKey` class as `LocalOperatorCannotSatisfyTransport`
  (R28) and every non-RemoteSigner class as
  `NotRemoteSignerCustodyClass`. The grep-verifiable helpers
  `local_operator_cannot_satisfy_remote_signer_transport`,
  `peer_majority_cannot_satisfy_remote_signer_transport`, and
  `mainnet_peer_driven_apply_remains_refused_under_remote_signer_transport_boundary`
  encode the corresponding fail-closed rules (R28, R29, R35).

The module is pure: every public function and trait method performs no
network or file I/O, writes no marker, writes no sequence, mutates no
live trust, evicts no sessions, and never invokes Run 070 apply.

## Tests added

[`crates/qbind-node/tests/run_201_remote_signer_transport_boundary_tests.rs`](
  ../../crates/qbind-node/tests/run_201_remote_signer_transport_boundary_tests.rs)
covers the A1–A10 / R1–R35 matrix from `task/RUN_201_TASK.txt` (58
tests):

* **A1–A10** — fixture loopback transport accepted on DevNet (A1) and
  TestNet (A2); deterministic request (A3), response (A4), and
  request/response transcript (A5) digests; the request envelope binds
  the full authority tuple (A6) and the response envelope binds request
  id, request digest, signer id, custody key id, response digest, and
  transcript digest (A7); the production transport is callable and
  returns a typed unavailable outcome (A8); Run 194 RemoteSigner
  validation remains compatible with the fixture transport response
  (A9); and the Run 194 GenesisBound behavior is unchanged when the
  transport policy is disabled (A10).
* **R1–R35** — disabled / production-required / mainnet-production-
  required rejections; production and MainNet-production unavailable;
  endpoint missing / malformed; every binding-tuple mismatch
  (environment / chain / genesis / authority root / signer id / custody
  key id / signing-key fingerprint); request id / request digest /
  response digest / transcript digest mismatches; stale/replayed
  request / response; timeout and retry-exhausted (via simulated
  transport faults); malformed request / response envelope; unsupported
  protocol version / suite; invalid transport attestation; local
  operator / peer majority cannot satisfy; transport valid but
  RemoteSigner response invalid (R30); RemoteSigner valid but transport
  transcript invalid (R31); lifecycle/governance/custody valid but
  production transport unavailable (R32); validation-only and mutating
  rejection non-mutation (R33, R34); and the MainNet peer-driven-apply
  refusal invariant with fixture loopback transport (R35).
* Extras — fixture-vs-production transport separation, the no-I/O
  guarantee for the production transport path, malformed-envelope
  fail-closed at the transport-call boundary, timeout/retry policy
  validation, trait-object mockability, and a full
  lifecycle+custody+remote-signer+transport composition accept.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_201_remote_signer_transport_boundary_tests`
* `cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests`
* `cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests`
* `cargo test -p qbind-node --test run_194_remote_authority_signer_boundary_tests`
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests`
* `cargo test -p qbind-node --test run_188_authority_custody_boundary_tests`
* `cargo test -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests`
* `cargo test -p qbind-node --lib pqc_remote_signer_transport`
* `cargo test -p qbind-node --lib pqc_authority`

All commands run on this checkout completed successfully, including:

* `run_201_remote_signer_transport_boundary_tests`: 58 passed.
* `pqc_remote_signer_transport` lib self-tests: 5 passed.
* Prior-run regression suites (Runs 188 / 192 / 194 / 196 / 198) remain
  green.

## Acceptance summary

1. A typed RemoteSigner transport boundary exists
   (`pqc_remote_signer_transport`). ✅
2. Request / response / transcript digests are deterministic and
   domain-bound. ✅
3. The fixture loopback transport is DevNet/TestNet source-test only. ✅
4. The production transport remains unavailable/fail-closed. ✅
5. The transport composes with the Run 194 RemoteSigner
   request/response. ✅
6. Local operator / peer majority cannot satisfy the transport policy. ✅
7. Validation-only surfaces remain non-mutating. ✅
8. Mutating rejection paths produce no mutation. ✅
9. MainNet peer-driven apply remains refused. ✅
10. Release-binary RemoteSigner transport-boundary evidence is deferred
    to Run 202. ✅
11. No real RemoteSigner backend / KMS / HSM / governance execution /
    validator-set rotation claim is made. ✅
12. No full C4 or C5 closure is claimed. ✅

## Deferred

* Release-binary RemoteSigner transport-boundary evidence: **Run 202**.
* Real RemoteSigner backend / networked signer daemon remains
  unimplemented.
* Real KMS / HSM / cloud-KMS / PKCS#11 backend remains unimplemented.
* Real on-chain governance proof verification remains unimplemented.
* Governance execution remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.