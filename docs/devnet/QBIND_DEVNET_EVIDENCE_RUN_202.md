# QBIND DevNet evidence — Run 202

**Title.** Release-binary RemoteSigner transport boundary evidence.

**Status.** PASS (release-binary evidence). Run 202 captures
release-binary evidence that the real `target/release/qbind-node` keeps
every existing Run 070 / 130–201 surface RemoteSigner-transport-silent,
and that a release-built helper exercises the Run 201 production
RemoteSigner transport boundary
([`crates/qbind-node/src/pqc_remote_signer_transport.rs`](
  ../../crates/qbind-node/src/pqc_remote_signer_transport.rs)) layered
over the Run 194 RemoteSigner boundary
([`crates/qbind-node/src/pqc_remote_authority_signer.rs`](
  ../../crates/qbind-node/src/pqc_remote_authority_signer.rs)) end-to-end
in **release mode** through the production library symbols. Run 202 is
**release-binary RemoteSigner transport-boundary evidence**; it makes no
production-source change (it adds a release example helper, a release
harness, and documentation only).

Run 202 does **not** implement a real RemoteSigner backend or a
networked signer daemon. The fixture loopback transport remains
DevNet/TestNet evidence-only and is refused on a MainNet trust domain;
the production transport reaches the boundary and fails closed as
unavailable; malformed/invalid transport material fails closed; and
MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal
even with a fixture loopback transport response.

## Strict scope

* Release-binary evidence only, on real `target/release/qbind-node`.
* Use a release-built helper to exercise the Run 201 transport boundary
  in release mode through the production library symbols.
* No production-source change (helper + harness + docs only).
* No real RemoteSigner backend; no networked signer daemon; no
  production signing key custody.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No schema / wire / metric drift; no authority-marker / sequence-file /
  trust-bundle core schema change.
* Run 202 does not weaken any prior run (Runs 070, 130–201) and does not
  claim full C4 or C5 closure.

## Run 202 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_202_remote_signer_transport_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_202_remote_signer_transport_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_202_remote_signer_transport_release_binary.sh`](
    ../../scripts/devnet/run_202_remote_signer_transport_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_202_remote_signer_transport_release_binary/`](
    run_202_remote_signer_transport_release_binary/) (tracked:
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

Run 201 added a pure additive library module only — no CLI flag, no env
var, and no runtime banner. The surface contract is therefore that every
existing Run 070 / 130–201 surface stays RemoteSigner-transport-silent.
The harness proves on the real `target/release/qbind-node`:

* **S1** — `qbind-node --help` advertises no RemoteSigner transport /
  networked-signer-daemon / KMS / HSM surface, and no governance-execution
  / validator-set-rotation claim.
* **S2–S4** — `--print-genesis-hash --env {devnet,testnet,mainnet}` emits
  no RemoteSigner transport enablement banner, no "RemoteSigner backend
  connected" / "RemoteSigner transport active" / "networked signer daemon
  active" claim, no KMS/HSM active claim, and no MainNet peer-driven apply
  enablement.
* **S5** — the Run 198 hidden RemoteSigner policy selector
  (`fixture-loopback-allowed`, CLI flag + env var) remains compatible
  with no transport banner drift.
* **S6** — the Run 193 hidden custody policy selector remains compatible
  with the RemoteSigner selector (no banner drift).
* **S7** — the governance fixture flag remains compatible with no
  RemoteSigner transport banner drift and no governance-execution claim.
* **S8** — even with the RemoteSigner policy selector set to
  `mainnet-production-remote-signer-required` on `--env mainnet`, MainNet
  peer-driven apply remains the Run 147 FATAL refusal and no RemoteSigner
  transport / KMS / HSM enablement is emitted.

The real binary resolves `--print-genesis-hash` through the existing
genesis-hash path; the transport *semantics* are proven by the
release-built helper below, which links the production library symbols.

## Release-helper corpus evidence

The release-built helper exercises the Run 201 A1–A10 / R1–R35 corpus in
**release mode** through the production library symbols
`pqc_remote_signer_transport::*` layered over
`pqc_remote_authority_signer::*`. It registers six tables:

* **accepted (10):** A1/A2 fixture loopback transport accepted on
  DevNet/TestNet; A3/A4/A5 request / response / transcript envelope
  digests deterministic and domain-bound (and order-sensitive for the
  transcript); A6 the request binds the full authority tuple
  (environment, chain, genesis, authority root, signer id, custody key
  id, lifecycle action, candidate digest, authority-domain sequence) and
  its canonical request digest; A7 the response binds the request id,
  request/response canonical digests, and the transcript digest; A8 the
  production transport boundary is callable and returns the typed
  `ProductionTransportUnavailable` (directly and via
  `send_remote_signer_request`); A9 the Run 194 verifier accepts the
  wrapped fixture request/response; A10 a disabled transport policy fails
  closed without disturbing the Run 194 GenesisBound behaviour.
* **rejection (35):** the full R1–R35 family — disabled policy;
  fixture-rejected under production / mainnet-production required;
  production / MainNet-production unavailable; endpoint missing /
  malformed; every binding-tuple mismatch (environment, chain, genesis,
  authority root, signer id, custody key id, signing-key fingerprint);
  wrong request id / request digest / response digest / transcript
  digest; stale/replayed request / response; timeout; retry-exhausted;
  malformed request / response envelope; unsupported protocol version /
  suite; invalid transport attestation; local-operator and peer-majority
  cannot satisfy; transport-valid-but-RemoteSigner-invalid and
  RemoteSigner-valid-but-transcript-invalid; lifecycle/custody valid but
  production transport unavailable; validation-only non-mutation (R33);
  mutating-preflight no-mutation (R34); and MainNet peer-driven apply
  refused even with fixture loopback transport (R35).
* **separation (9):** fixture loopback transport refused for MainNet;
  fixture-vs-production transports are distinct; the production transport
  performs no I/O and fails closed on DevNet/TestNet; a malformed
  envelope fails closed before any response; the endpoint helper matches
  the validator decision; the custody-class router admits `RemoteSigner`
  and rejects a non-RemoteSigner class; the trait object is mockable; the
  default policy is `Disabled`; and a malformed timeout/retry policy
  fails the config well-formedness gate.
* **composition (4):** the full
  `validate_lifecycle_custody_remote_signer_and_transport` accepts the
  DevNet fixture composition; rejects when the inner composition accepts
  but the transport transcript is corrupt (`TransportRejected`); rejects
  the inner composition under a `Disabled` policy
  (`LifecycleCustodyOrRemoteSignerRejected`); and short-circuits to
  `MainNetPeerDrivenApplyRefused` for a MainNet peer-driven-apply
  preflight.
* **determinism (2):** repeated DevNet/TestNet scenarios yield identical
  typed outcomes and identical request / response / transcript digests.
* **refusal_helpers (3):** the named MainNet refusal helper (true on
  MainNet, false on DevNet/TestNet) plus the local-operator and
  peer-majority cannot-satisfy helpers.

The helper writes a per-table breakdown plus a `helper_summary.txt`
ending in the canonical `verdict: PASS` line, and exits non-zero if any
case does not match its expected typed outcome. The harness asserts
`verdict: PASS` before continuing. On this checkout the helper reports
**total_pass: 63, total_fail: 0, verdict: PASS**.

## Source/release reachability

The harness records source-grep reachability under
`reachability/source_reachability.txt` for `pqc_remote_signer_transport`;
`RemoteSignerTransportConfig`; `RemoteSignerTransportRequestEnvelope`;
`RemoteSignerTransportResponseEnvelope`; the `RemoteSignerTransport`
trait; `FixtureLoopbackRemoteSignerTransport`;
`ProductionRemoteSignerTransport`; the request/response envelope digest
helper (`envelope_digest`); the transcript digest helper
(`transport_transcript_digest`); `remote_signer_response_canonical_digest`;
`validate_remote_signer_transport`; and
`validate_lifecycle_custody_remote_signer_and_transport`, layered over
`pqc_remote_authority_signer`.

## Mutation / no-mutation evidence

For every rejected RemoteSigner transport-boundary scenario the helper
proves no mutation: `validate_remote_signer_transport` and
`validate_lifecycle_custody_remote_signer_and_transport` are pure
functions returning typed owned outcomes. R33 asserts every input is
byte-identical after a rejecting validation; R34 asserts the candidate is
unchanged after a `Disabled`-policy composition rejection. No Run 070
apply call, no live trust swap, no session eviction, no sequence write,
no marker write, no `.tmp` residue, no fallback to `--p2p-trusted-root`,
and no active DummySig / DummyKem / DummyAead are produced
(`no_mutation_proof.txt`). The harness denylist
(`negative_invariants.txt`) proves all 27 forbidden patterns empty across
captured logs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node \
  --example run_202_remote_signer_transport_release_binary_helper
bash scripts/devnet/run_202_remote_signer_transport_release_binary.sh
```

The harness additionally runs the Run 201 / 198 / 196 / 194 / 192 / 190 /
188 and the governance / lifecycle / peer-driven-apply regression test
targets from `task/RUN_202_TASK.txt`, plus
`cargo test -p qbind-node --lib pqc_authority`,
`--lib pqc_remote_signer_transport`, and `--lib`. Per-target exit codes
are captured under `exit_codes/` and summarised in `summary.txt`. Targets
absent from the tree are recorded as `skipped(not-present)`. On this
checkout all listed targets completed with `rc=0`.

## Acceptance summary

1. The release-built helper proves the Run 201 RemoteSigner transport
   corpus (A1–A10 / R1–R35) in release mode. ✅
2. Real `target/release/qbind-node` confirms MainNet peer-driven apply
   remains refused. ✅
3. Fixture loopback transport remains DevNet/TestNet evidence-only. ✅
4. Production transport remains unavailable / fail-closed. ✅
5. Request, response, and transcript digests are deterministic and
   domain-bound. ✅
6. The transport composes with the Run 194 RemoteSigner
   request/response. ✅
7. Rejected RemoteSigner transport-boundary cases produce no mutation. ✅
8. Existing custody / governance proof paths remain compatible. ✅
9. No real RemoteSigner backend / networked signer daemon / KMS / HSM /
   governance execution / validator-set rotation claim is made. ✅
10. No full C4 or C5 closure is claimed. ✅

## Standing invariants (unchanged by Run 202)

* No real RemoteSigner backend / networked signer daemon is implemented.
* The production transport remains unavailable / fail-closed.
* Fixture loopback transport is DevNet/TestNet evidence-only and is
  refused on a MainNet trust domain.
* No real KMS / HSM / cloud-KMS / PKCS#11 backend is implemented.
* RemoteSigner transport evidence does not enable MainNet peer-driven
  apply.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* Validator-set rotation remains open.
* Existing custody / governance proof paths remain compatible.
* Full C4 remains open.
* C5 remains open.
