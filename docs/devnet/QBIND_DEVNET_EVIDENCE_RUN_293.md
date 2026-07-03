# QBIND DevNet Evidence — Run 293

**Run 293 — Production RemoteSigner backend (source/test implementation).**

## 1. Exact verdict

**PASS / source-test production RemoteSigner backend implementation,
release-binary evidence deferred to Run 294.**

Run 293 lands the first *real* production RemoteSigner backend client for the
authority/governance signing path: `ProductionRemoteSignerBackend` drives the
existing Run 201 RemoteSigner transport boundary (which itself composes the Run
194 RemoteSigner payload/policy boundary) over an injected, mockable transport,
builds deterministic request envelopes, enforces domain binding + request/
response correlation + backend transcript binding, applies a bounded timeout/
retry budget with a typed transport error taxonomy, and fails closed on every
unavailable / malformed / mismatched / oversized / replayed path — with a
**default-Disabled** production policy that fails closed before any transport
call and **no** silent fixture/loopback/local-key fallback under a production
policy. This is source/test only: the production binary is not wired to
construct the backend, no CLI flag is added, and MainNet is refused absent
production authority criteria. **Full C4 remains OPEN; C5 remains OPEN.**

## 2. Files changed

* `crates/qbind-node/src/pqc_production_remote_signer_backend.rs`
  (new source module — the real RemoteSigner backend client).
* `crates/qbind-node/src/lib.rs` (registers the module).
* `crates/qbind-node/tests/run_293_production_remote_signer_backend_tests.rs`
  (new test file, 69 integration tests; 6 additional inline unit tests live in
  the source module).
* `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_293.md` (this report).
* `docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md` (matrix + status update:
  RemoteSigner backend row Red → Yellow).
* `docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`
  (Run 293 note).
* `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md` (Run 293 note).
* `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md` (Run 293 note).
* `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` (Run 293 note).
* `docs/whitepaper/contradiction.md` (Run 293 entry).

## 3. Backend design summary

The new module defines a narrow, mockable transport trait
`RemoteSignerBackendTransport` (`submit(request_env, attempt) -> Result<
ResponseEnvelope, ProductionRemoteSignerError>`), and the real backend
`ProductionRemoteSignerBackend<T: RemoteSignerBackendTransport>` that is generic
over any transport implementation. The backend is genuinely real (not
fixture-only): it works over *any* transport, and its accept path composes the
existing Run 201 verifier `validate_remote_signer_transport` (which composes the
Run 194 `validate_remote_signer`). Backend logic = deterministic request
building, a retry/timeout loop over the transport, request/response correlation,
backend transcript binding, and precise outcome mapping.

Two transport implementations ship for composition tests:

* `LoopbackRemoteSignerService<T>` — wraps the Run 201
  `FixtureLoopbackRemoteSignerTransport`, maps its transport outcome errors into
  the backend error taxonomy, and exposes a `call_count()` for reachability
  assertions. Used only for source/test evidence; it is never a fallback under
  a production policy.
* `MockRemoteSignerBackendTransport` — programmable (`always_fail` / `scripted`
  / `respond`) with a call counter, proving the backend surface is mockable and
  exercising the full transport error taxonomy without any real endpoint.

Policy selection is via `ProductionRemoteSignerBackendPolicy` whose `Default` is
`Disabled`. `Disabled` fails closed in `preflight_gate` **before** any transport
call (tests assert `call_count == 0`). The policy maps to the Run 194
`RemoteSignerPolicy` via `to_remote_signer_policy()`.

Supported request kinds: `AuthorityLifecycleSigning` and
`GovernanceExecutionSigning`. `ValidatorSetRotation`, `PolicyChange`, and
`OnChainGovernanceProofVerification` are refused up front (no transport call) as
`ValidatorSetRotationUnsupported` / `PolicyChangeUnsupported` /
`GovernanceVerifierUnavailable`, so Run 293 does not implement validator-set
rotation, policy-change signing, or on-chain governance proof verification.

## 4. Request / response / transcript / domain binding

* **Domain binding.** The request is bound to the `AuthorityTrustDomain`
  (environment, chain_id, genesis, authority-root fingerprint + suite) via the
  composed Run 194/201 verifiers; a wrong environment / chain / genesis / root
  fingerprint / suite fails closed with no accept.
* **Request id.** `production_remote_signer_request_id(spec)` is a SHA3-256
  domain-separated digest over the request spec fields — deterministic, never
  random and never wall-clock derived.
* **Request/response correlation.** The response envelope must echo the derived
  request id and the spec `response_nonce`; a mismatched echo or nonce fails
  closed (`RequestIdMismatch` / replay reject).
* **Transcript binding.** `production_remote_signer_backend_transcript_digest`
  binds the protocol version, request id, request/response envelope digests, the
  Run 201 transport transcript, and an optional
  `durable_replay_record_digest` (the Run 291 composition point). A wrong
  transcript fails closed.
* **Protocol version.** `PRODUCTION_REMOTE_SIGNER_BACKEND_PROTOCOL_VERSION` is
  bound into the request id and transcript; a wrong protocol version fails
  closed.

## 5. Accepted source/test evidence

Group A (`a01`–`a14`) drives the backend over the loopback service and the mock
transport with well-formed, correlated responses and asserts:

* accepted authority-lifecycle and governance-execution signing outcomes;
* deterministic request id / transcript digest across repeated builds;
* the accept path reaching the transport exactly once on the happy path;
* accept is evidence-only and does not authorize beyond the signer boundary.

## 6. Rejection / fail-closed evidence

Group B (`b01`–`b32`) asserts fail-closed on: unknown/unsupported request kind,
wrong signer identity, wrong request-id echo, wrong candidate digest, wrong
authorized action, wrong transcript digest, wrong protocol version, missing
response signature, malformed/oversized/decode-error response, signer
unavailable / refused / policy-rejected / attestation-unavailable, transport
endpoint-unavailable / connection-refused / timeout, unsupported-protocol
transport error, response from the wrong signer key, production-mode response
never accepted, unsupported kinds (validator-set rotation / policy change /
on-chain governance proof), malformed spec, and stale-nonce replay. Every reject
returns a non-accept outcome and performs no mutation.

## 7. MainNet refusal / authority policy evidence

Group C (`c01`–`c06`) asserts that MainNet cannot be satisfied by local operator
material, by the fixture loopback signer, or by a peer majority; that a
`MainnetProductionRequired` policy on MainNet is `MainNetProductionAuthorityUnavailable`;
that any other policy on MainNet is `MainNetRefused`; and that a production-
required policy on a non-MainNet environment is `RemoteSignerUnavailable` with no
fallback. All MainNet/authority gating happens in `preflight_gate` **before** any
transport call, and the production-unavailable path records no mutation.

## 8. Replay / recovery / idempotency evidence

Group E (`e01`–`e07`) asserts: no-prior-request recovery is a clean
no-op window; identical requests are idempotent over the deterministic request
id; the same request id with a different transcript or a different response
commitment fails closed; retry-then-success is idempotent across attempts; the
retry budget is bounded and exhaustion fails closed; and terminal (non-
retryable) errors are not retried. Group B `b32` covers stale-nonce replay
rejection.

## 9. Non-mutation evidence

Group D (`d01`–`d04`) asserts every reject is non-mutating, the scope helpers
hold, `Disabled` never touches the transport, and accept is evidence-only — not
authorizing beyond the signer. The backend does not call Run 070, does not
mutate `LivePqcTrustState`, and does not write trust-bundle sequence or
authority-marker files.

## 10. Tests run and results

* `cargo build -p qbind-node --lib` — **PASS** (clean; no warnings after
  removing the unused import).
* `cargo test -p qbind-node --test run_293_production_remote_signer_backend_tests`
  — **69 passed; 0 failed.**
* `cargo test -p qbind-node --lib` — **1371 passed; 0 failed** (includes the 6
  new inline unit tests and `--lib pqc_authority`).
* Regression corpus (all **PASS**):
  `run_291`, `run_290`, `run_288`, `run_286`, `run_284`, `run_282`, `run_280`,
  `run_278`, `run_276`, `run_274`, `run_272`, `run_270`, `run_268`, `run_266`,
  `run_264`, `run_262`, `run_260`, `run_258`, `run_256`, `run_254`, `run_252`,
  `run_250`, `run_248`, `run_246`, `run_244`, `run_242`, `run_240`, `run_238`,
  `run_236`, `run_234`, `run_232`, `run_230`, `run_228`, `run_226`, `run_224`.
* RemoteSigner boundary regressions `run_194`
  (remote-authority-signer boundary) and `run_201`
  (remote-signer-transport boundary) — **PASS.**

## 11. C4/C5 matrix taxonomy status

* Production durable replay RocksDB backend — **Green (for scope)** (Run
  291/292 release-binary-evidenced backend behavior only); **unchanged** by Run
  293.
* Real production RemoteSigner backend — **Red → Yellow** (Run 293 source/test
  implementation landed; release-binary evidence pending Run 294).
* Real KMS / HSM / cloud-KMS / PKCS#11 custody backend — **Red** (unchanged).
* Real custody attestation verifier — **Red** (unchanged).
* Real on-chain governance proof verifier — **Red** (unchanged).
* Governance execution engine — **Red** (unchanged).
* Validator-set rotation / authority-set synchronization — **Red** (unchanged).
* MainNet authority rotation/revocation under production custody — **Red**
  (unchanged).
* Production signing audit trail / crypto-agility activation / incident response
  — **Red** (unchanged).
* Full MainNet release-binary evidence under production custody — **Red**
  (unchanged).
* Full **C4 remains OPEN**; **C5 remains OPEN**.

## 12. Security scan results

* Secret scan over changed files — **clean** (no secrets; the backend derives
  ids/transcripts by SHA3-256 over public spec fields and never embeds keys).
* CodeQL — **attempted but did not complete**. CodeQL analysis over the Rust
  database was invoked but timed out / was skipped because the database size is
  too large, so it did **not** produce results. **No CodeQL coverage is
  claimed** for Run 293. Run 293 adds real backend code that derives
  ids/transcripts by SHA3-256 over public spec fields and never embeds keys;
  the honest CodeQL limitation is recorded here directly rather than deferred.

## 13. Honest limitations

* Run 293 is **source/test only**. It is **not** release-binary evidence;
  release-binary evidence is deferred to **Run 294**.
* Run 293 adds **no** default production runtime wiring and **no** public CLI
  flag; the backend is never constructed by the default binary.
* RemoteSigner is **not** enabled by default (`Disabled` fails closed).
* MainNet is **not** enabled.
* Run 293 does **not** implement KMS/HSM/cloud-KMS/PKCS#11 custody, custody
  attestation, on-chain governance proof verification, a governance execution
  engine, validator-set rotation, settlement, or external publication.
* The loopback/mock transports are test scaffolding only; under a production
  policy there is **no** fixture/loopback/local-key fallback.
* Run 293 does **not** weaken the Run 292 durable replay RocksDB Green-for-scope
  status.

## 14. C4/C5 status

Full **C4 remains OPEN.** **C5 remains OPEN.** The RemoteSigner backend row is
Yellow (source/test), not Green; no closure gate is claimed satisfied.

## 15. Suggested Run 294 next step

**Run 294 — release-binary evidence for the production RemoteSigner backend.**
Run 294 should build a real `target/release/qbind-node` plus a release-built
helper, exercise the Run 293 RemoteSigner backend in release mode, prove
request/response/transcript/domain binding, prove timeout/unavailable/malformed/
replay/wrong-domain fail-closed behavior, prove the default production binary
surfaces remain Disabled/silent (no CLI flag), prove MainNet remains refused
absent production authority criteria, and preserve Full C4 OPEN / C5 OPEN unless
every closure gate is actually satisfied.