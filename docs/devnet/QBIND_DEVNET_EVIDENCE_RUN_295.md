# QBIND DevNet Evidence — Run 295

**Run 295 — Production KMS/HSM/cloud-KMS/PKCS#11 custody backend
(source/test implementation).**

## 1. Exact verdict

**PASS / source-test production KMS/HSM/cloud-KMS/PKCS#11 custody backend
implementation, release-binary evidence deferred to Run 296.**

Run 295 lands the first *real* production KMS/HSM custody backend client for the
authority/governance signing path: `ProductionKmsHsmCustodyBackend` drives the
existing Run 203 KMS/HSM backend boundary (`verify_authority_custody_backend_response`)
over an injected, mockable provider transport, builds deterministic domain-separated
request envelopes and request ids, enforces domain binding + request/response
correlation + backend transcript binding, applies a bounded attempt budget with a
typed provider error taxonomy, and fails closed on every unavailable / misconfigured
/ timeout / decode / malformed / oversized / mismatched / replayed path — with a
**default-Disabled** production policy that fails closed before any provider call
and **no** silent fixture/RemoteSigner/local-signing fallback under a production
policy. This is source/test only: the production binary is not wired to construct
the backend, no CLI flag is added, no raw local production signing key is loaded,
and MainNet is refused absent production authority criteria.

This run moves the **Real KMS/HSM/cloud-KMS/PKCS#11 custody backend** row from
**Red** to **Yellow / source-test implementation landed, release-binary evidence
pending Run 296**. This run does **not** claim release-binary evidence, does
**not** claim C4 closure, does **not** claim C5 closure, and does **not** claim
MainNet readiness. **Full C4 remains OPEN; C5 remains OPEN.**

## 2. Files changed

* `crates/qbind-node/src/pqc_production_kms_hsm_custody_backend.rs`
  (new source module — the real KMS/HSM custody backend client).
* `crates/qbind-node/src/lib.rs` (registers the module).
* `crates/qbind-node/tests/run_295_production_kms_hsm_custody_backend_tests.rs`
  (new test file, 89 integration tests; 6 additional inline unit tests live in
  the source module).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_295.md` (this report).
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` (matrix + status update:
  KMS/HSM custody backend row Red → Yellow).
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
  (Run 295 note).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 295 note).
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` (Run 295 note).
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 295 note).
* `docs/whitepaper/contradiction.md` (Run 295 entry).

## 3. Backend design summary

The new module defines a narrow, mockable provider transport trait
`KmsHsmCustodyProviderTransport` (`submit(request_env, attempt) -> Result<
ProductionCustodyResponse, ProductionCustodyError>`), and the real backend
`ProductionKmsHsmCustodyBackend<T: KmsHsmCustodyProviderTransport>` that is
generic over any transport implementation. The backend is genuinely real (not
fixture-only): it works over *any* transport, and its accept path composes the
existing Run 203 verifier `verify_authority_custody_backend_response` (28 binding
steps). Backend logic = deterministic request building, an attempt loop over the
transport, request/response correlation, backend transcript binding, and precise
outcome mapping.

Four transport implementations ship for composition tests:

* `FixtureKmsCustodyProvider` / `FixtureHsmCustodyProvider` — wrap the Run 203
  `FixtureKmsBackend` / `FixtureHsmBackend`, produce a deterministic fixture
  response envelope, and expose a `call_count()` for reachability assertions.
  Source/test only (DevNet/TestNet); refused on a MainNet trust domain by the
  verifier. Never a fallback under a production policy.
* `ProductionCustodyProviderStub` — represents the production cloud-KMS /
  PKCS#11-HSM / generic-KMS / generic-HSM provider paths. The path is *reachable*
  (the transport boundary is invoked, `call_count()` increments) but always fails
  closed with the configured error because no real provider config / module /
  session / key handle exists in Run 295.
* `MockKmsHsmCustodyTransport` — a programmable source/test transport for
  fault injection (timeout / unavailable / decode / malformed / oversized /
  tampered-envelope), with no real I/O.

`ProductionKmsHsmCustodyBackend` never loads a raw local production signing key,
never falls back to fixture/RemoteSigner/local signing under a production policy,
and never mutates any Run 070 / `LivePqcTrustState` / durable replay / settlement
state — every method returns a pure evidence value.

## 4. Provider taxonomy and policy model

Provider kinds (`ProductionCustodyProviderKind`): `Disabled` (default),
`FixtureKms`, `FixtureHsm`, `ProductionCloudKms`, `ProductionPkcs11Hsm`,
`ProductionGenericKms`, `ProductionGenericHsm`, `Unknown`. Each maps to a Run 203
`BackendKind` (production kinds map to the Run 203 `*Unavailable` sentinels) and
carries a custody class (`Kms` / `Hsm`) where applicable.

Policies (`ProductionKmsHsmCustodyBackendPolicy`, default `Disabled`): `Disabled`,
`FixtureKmsAllowed`, `FixtureHsmAllowed`, `ProductionCloudKmsRequired`,
`ProductionPkcs11HsmRequired`, `ProductionGenericKmsRequired`,
`ProductionGenericHsmRequired`, `MainnetProductionCustodyRequired`. Each maps to a
Run 203 `BackendPolicy` and declares its single allowed provider kind. The
default `Disabled` policy fails closed (`DisabledNoRequest`) before any request is
built or any provider invoked.

Request kinds (`ProductionCustodyRequestKind`): `AuthorityLifecycleSigning` and
`GovernanceExecutionSigning` are supported; `ValidatorSetRotation`, `PolicyChange`
and `OnChainGovernanceProofVerification` are explicitly unsupported and fail
closed at preflight (those rows remain Red — see §12).

The preflight gate ordering is: (1) Disabled → `DisabledNoRequest`; (2)
unsupported request kind → named refusal; (3) custody class not `Kms`/`Hsm` →
`RemoteSignerIsNotKmsHsmCustody` / `ProductionCustodyRejected`; (4) MainNet domain
gate (no provider call); (5) MainNet-required policy on non-MainNet → fail closed;
(6) structural well-formedness; (7) provider-kind ↔ policy match.

## 5. Request/response/transcript/domain binding

* `ProductionCustodyRequestSpec` binds the full authority-decision tuple
  (environment, chain, genesis, authority root, lifecycle action, candidate
  digest, authority-domain sequence, custody class, provider/key id, signing-key
  fingerprints, custody attestation digest, optional Run 291 durable replay record
  digest, request/response nonces, timestamp).
* `production_kms_hsm_custody_request_id(spec)` is a deterministic,
  domain-separated (`PRODUCTION_KMS_HSM_CUSTODY_REQUEST_ID_DOMAIN_TAG`) SHA3-256
  commitment over the typed spec — not random, not wall-clock. The response must
  echo it; a mismatch is `ProductionCustodyRequestIdMismatch`.
* `ProductionCustodyRequest` / `ProductionCustodyResponse` envelopes wrap the Run
  203 `BackendRequest` / `BackendResponse` and each expose a domain-separated
  `envelope_digest()`.
* The transcript digest chains the identity digest, request digest and response
  digest through the Run 203 `backend_transcript_digest`, then binds the protocol
  version, request id and optional durable replay record digest through
  `production_kms_hsm_custody_transcript_digest`. Domain binding is enforced by the
  composed Run 203 verifier (environment / chain / genesis / authority root /
  key id / signing-key / lifecycle action / candidate / sequence / nonces /
  request digest / response digest / transcript).

## 6. Accepted source/test evidence

Group A (15 tests) proves: the Disabled default policy is explicit and inert;
DevNet/TestNet fixture KMS and fixture HSM accept a valid request only under an
explicit fixture-allowed policy; a production provider request can be built
without any fixture fallback; the production cloud-KMS and PKCS#11-HSM provider
paths are reachable and fail closed as misconfigured without real config;
request id, response digest and transcript digest are deterministic; two
identical requests produce identical request/transcript digests; a valid fixture
response authorizes exactly the matching request; and the Run 203 provider-kind ↔
`BackendKind` mapping remains compatible.

## 7. Rejection/fail-closed evidence

Group B (36 tests) proves fail-closed on: Disabled (no request, no provider
call); MainNet identity; fixture KMS/HSM material for MainNet; RemoteSigner
material (cannot satisfy the KMS/HSM row); local-operator / fixture-local
material; wrong environment / chain / genesis / authority root / authority
sequence; wrong provider kind / key handle / signer identity; wrong request id /
transcript / candidate digest / authorized action; missing signature; missing
attestation; malformed response; oversized response; response replay from a prior
request; and every provider error (unavailable / timeout / decode / refused /
policy-rejected / unsupported provider / endpoint unavailable / unsupported
protocol version / attestation missing / attestation unavailable). Unsupported
request kinds (validator-set rotation, governance proof verification) fail closed.

## 8. MainNet refusal / authority policy evidence

Group C (10 tests) proves MainNet cannot be satisfied by fixture KMS, fixture
HSM, RemoteSigner-only evidence, local-operator material, or peer-majority
material; that a MainNet trust domain with the MainNet production policy fails
closed as `MainNetProductionCustodyUnavailable` with **no** provider call; that a
non-production policy on MainNet is `MainNetRefused`; that the MainNet production
policy on a non-MainNet domain also fails closed with no provider call; and that
the MainNet-unavailable path records no mutation.

## 9. Replay/recovery/idempotency evidence

Group E (7 tests) exercises `recover_custody_request_window`: no prior request →
`NoPriorRequest`; a byte-identical duplicate request is
`IdempotentReplayOfSameRequest`; the same request id with a different key handle,
different request transcript, or different response commitment each fail closed
(`ConflictingKeyHandleForSameId` / `ConflictingRequestForSameId` /
`ConflictingResponseForSameRequest`); different request ids are unrelated windows;
and idempotency is byte-identical only. The recovery window is represented as a
comparison of two submitted request/response pairs; it does **not** persist state
and does **not** claim any durable acceptance.

## 10. Non-mutation evidence

Group D (9 tests) proves every rejected path is non-mutating: the outcome type's
`is_non_mutating()` is invariantly true; a Disabled reject invokes no provider; a
domain-mismatch or wrong-key-handle reject during verify adds no further provider
call (exactly one submit during setup); the production-unavailable path records a
single reachable call only; and the named scope helpers assert no fallback, no raw
local key load, RemoteSigner-is-not-KMS/HSM, and non-mutation. No Run 070 call, no
`LivePqcTrustState` mutation, no trust swap, no session eviction, no trust-bundle
sequence write, no authority marker write, no durable replay overwrite, no
settlement, no external publication, no governance execution, no validator-set
rotation, no RemoteSigner fallback, and no raw local production signing key load
occurs on any path — the backend surfaces are pure evidence.

## 11. Tests run and results

* `cargo build -p qbind-node --lib` — **passes**.
* `cargo test -p qbind-node --test run_295_production_kms_hsm_custody_backend_tests`
  — **89 passed; 0 failed**.
* `cargo test -p qbind-node --lib pqc_production_kms_hsm_custody_backend` — 6
  inline unit tests **pass**.
* Full regression list (Run 293, 291, 290, 288, 286, 284, 282, 280, 278, 276,
  274, 272, 270, 268, 266, 264, 262, 260, 258, 256, 254, 252, 250, 248, 246, 244,
  242, 240, 238, 236, 234, 232, 230, 228, 226, 224) plus Run 203 / 201 / 194 / 188
  boundary tests and `cargo test -p qbind-node --lib` — see the "Tests run and
  results" section of the final response for the recorded per-binary totals.
* Substitution note: the task lists "Run 204" — there is no `run_204_*` test
  binary (Run 204 was the RemoteSigner release-binary evidence run). The closest
  present source/test boundary targets Run 201 (RemoteSigner transport) and Run
  203 (KMS/HSM backend), which are run instead.

## 12. C4/C5 matrix taxonomy status

* Production durable replay RocksDB backend — **Green** for release-binary-
  evidenced backend behavior only (unchanged).
* Real production RemoteSigner backend — **Green** for release-binary-evidenced
  backend behavior only (unchanged).
* Real KMS/HSM/cloud-KMS/PKCS#11 custody backend — **Yellow / source-test
  implementation landed, release-binary evidence pending Run 296** (this run).
* Real custody attestation verifier — **Red**.
* Real on-chain governance proof verifier — **Red**.
* Governance execution engine — **Red**.
* Validator-set rotation / authority-set synchronization — **Red**.
* MainNet authority rotation/revocation under production custody — **Red**.
* Production signing audit trail / crypto-agility activation / incident response —
  **Red**.
* Full MainNet release-binary evidence under production custody — **Red**.
* Full C4 remains **OPEN**. C5 remains **OPEN**.

## 13. Security scan results

* Secret scanning was run over the changed files; no secrets are present (the
  module uses only in-source deterministic fixture labels/digests, no keys or
  credentials).
* CodeQL: skipped because the CodeQL database was too large to build in the
  session environment. No CodeQL coverage is claimed for Run 295.

## 14. Honest limitations

* This is **source/test only**. Run 295 does **not** capture release-binary
  evidence; that is deferred to Run 296.
* No real cloud-KMS / PKCS#11-HSM provider is wired: the production provider paths
  are reachable but always fail closed as unavailable/misconfigured.
* The backend is not constructed by the production binary, no CLI flag is added,
  and no default runtime wiring is introduced.
* The recovery window is a pure comparison, not a persisted replay store; it makes
  no durable-acceptance claim.
* Custody attestation verification, on-chain governance proof verification,
  governance execution, and validator-set rotation are out of scope and remain
  Red.

## 15. C4/C5 status

Full C4 remains **OPEN**. C5 remains **OPEN**. This run advances exactly one
matrix row (KMS/HSM custody backend, Red → Yellow) and changes no other row.

## 16. Suggested Run 296 next step

Capture **release-binary evidence** for the Run 295 production KMS/HSM custody
backend: build the release binary, exercise the fixture-provider accept path and
the production-provider fail-closed paths end-to-end under a release-mode harness
(mirroring the Run 294 RemoteSigner release-binary shift-by-one pattern), and, on
positive evidence, move the KMS/HSM custody backend row from Yellow to Green
for release-binary-evidenced backend behavior only. C4/C5 remain OPEN.