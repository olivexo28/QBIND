# QBIND DevNet evidence — Run 194

**Title.** Source/test RemoteSigner production-custody interface
boundary for authority-lifecycle signing/custody.

**Status.** PASS (source/test). Run 194 replaces the vague Run 188
[`AuthorityCustodyClass::RemoteSigner`](../../crates/qbind-node/src/pqc_authority_custody.rs)
placeholder — which Runs 188 / 190 / 192 fail closed as
`RemoteSignerUnavailable` — with a precise, typed remote-signer
production-custody boundary that a later run can implement safely. The
new module
[`crates/qbind-node/src/pqc_remote_authority_signer.rs`](../../crates/qbind-node/src/pqc_remote_authority_signer.rs)
defines a typed remote-signer protocol (identity / request / response /
policy / outcome), a pure trait boundary with a DevNet/TestNet-only
fixture loopback signer and a fail-closed production signer, a pure
verifier, custody-class routing, and a pure composition helper layered
over the Run 188 lifecycle + governance + custody validator. The
default [`RemoteSignerPolicy::Disabled`](../../crates/qbind-node/src/pqc_remote_authority_signer.rs)
fails every request closed.

**Strict scope.**

* Source/test only. Release-binary RemoteSigner boundary evidence is
  deferred to **Run 195**.
* No real remote signer backend.
* No networked signer service.
* No real KMS implementation.
* No real HSM implementation.
* No cloud KMS integration.
* No PKCS#11 integration.
* No MainNet peer-driven apply enablement. The Run 147 / 148 / 152
  FATAL MainNet refusal remains intact even when a fixture loopback
  remote signer signs successfully.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority
  authority.
* No marker / sequence-file / trust-bundle core / wire / schema
  change. The additive remote-signer request/response types live
  entirely in the new source/test module and are not threaded into any
  production call site.
* Run 194 does not weaken any prior run (Runs 070, 130–193) and does
  not claim full C4 or C5 closure.

## Source surface added

New module:
[`crates/qbind-node/src/pqc_remote_authority_signer.rs`](
  ../../crates/qbind-node/src/pqc_remote_authority_signer.rs).

### Remote signer policy

[`RemoteSignerPolicy`](../../crates/qbind-node/src/pqc_remote_authority_signer.rs)
(`Default` is `Disabled`):

| variant                                  | tag                                       | behaviour                                        |
|------------------------------------------|-------------------------------------------|--------------------------------------------------|
| `Disabled`                               | `disabled`                                | refuses every request (default)                  |
| `FixtureLoopbackAllowed`                 | `fixture-loopback-allowed`                | DevNet/TestNet fixture loopback accepted         |
| `ProductionRemoteSignerRequired`         | `production-remote-signer-required`       | fails closed — no real backend                   |
| `MainnetProductionRemoteSignerRequired`  | `mainnet-production-remote-signer-required` | fails closed — no real backend, MainNet         |

### Typed protocol

* `RemoteSignerIdentity` — `signer_id`, `signer_public_identity`,
  `custody_key_id`, `authority_root_fingerprint`,
  `bundle_signing_key_fingerprint`, `environment`, `chain_id`,
  `genesis_hash`, `supported_suite_id`, `supported_lifecycle_actions`,
  `attestation_digest` (placeholder commitment), `freshness_unix` /
  `expires_at_unix`.
* `RemoteSignerRequest` — binds `environment`, `chain_id`,
  `genesis_hash`, `authority_root_fingerprint`, `lifecycle_action`,
  `candidate_digest`, `authority_domain_sequence`, active/new/revoked
  signing-key fingerprints, `governance_proof_digest`,
  `custody_attestation_digest`, `replay_nonce`,
  `request_timestamp_unix`. Exposes a deterministic, domain-separated
  SHA3-256 `canonical_digest`.
* `RemoteSignerResponse` — binds `request_digest`, `signer_id`,
  `custody_key_id`, `signature_suite_id`, placeholder
  `signature_commitment`, `response_nonce`, `freshness_unix` /
  `expires_at_unix`, and a `signer_mode` (`FixtureLoopback` /
  `Production`).
* `RemoteSignerExpectations` — caller-supplied binding expectations
  (lifecycle action, candidate digest, authority-domain sequence,
  custody key id, signing-key fingerprint, custody attestation digest,
  request/response anti-replay nonces, `now_unix`).

### Trait + implementations

* `RemoteAuthoritySigner` — pure trait boundary (`identity` + `sign`).
  No I/O.
* `FixtureLoopbackRemoteSigner` — **DevNet/TestNet source/test only.**
  Produces a deterministic, well-formed response echoing the request
  canonical digest. Never a real signer; rejected on MainNet by the
  verifier.
* `ProductionRemoteSigner` — callable but fails closed: `sign` always
  returns `RemoteSignerOutcome::ProductionRemoteSignerUnavailable`.

### Verifier, routing, composition

* `validate_remote_signer(identity, request, response, trust_domain,
  expected, policy) -> RemoteSignerOutcome` — pure, no-I/O verifier.
* `validate_remote_signer_for_custody_class(class, …)` — routes
  `AuthorityCustodyClass::RemoteSigner` into the boundary, refuses
  `LocalOperatorKey` as `LocalOperatorKeyCannotSatisfyRemoteSigner`,
  and refuses every other class as `NotRemoteSignerCustodyClass`.
* `custody_class_routes_to_remote_signer(class) -> bool` — `true` only
  for `RemoteSigner`.
* `validate_lifecycle_governance_custody_and_remote_signer(…)` — pure
  composition helper layered over the Run 188
  `validate_lifecycle_governance_and_custody`. Returns
  `Accepted` / `LifecycleOrCustodyRejected` / `RemoteSignerRejected` /
  `MainNetPeerDrivenApplyRefused`.
* Named refusal helpers:
  `mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`,
  `local_operator_key_cannot_satisfy_remote_signer`,
  `peer_majority_cannot_satisfy_remote_signer`.

The verifier and every helper are pure: no I/O, no marker write, no
sequence write, no live-trust swap, no session eviction, no Run 070
invocation.

## Tests added

[`crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs`](
  ../../crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs)
covers the full A1–A7 / R1–R31 matrix from `task/RUN_194_TASK.txt`:

* **A1–A7 accepted** — fixture loopback accepted on DevNet (A1) and
  TestNet (A2) under `FixtureLoopbackAllowed`; request/response bind
  the full `(environment, chain, genesis, authority root, lifecycle
  action, candidate digest, authority-domain sequence)` tuple via
  canonical-digest determinism (A3); `AuthorityCustodyClass::RemoteSigner`
  routes into the boundary (A4); combined lifecycle + governance +
  custody + fixture remote signer accepted on DevNet (A5); Disabled
  policy does not disturb governance classes (A6); the production
  remote signer is callable and returns the typed unavailable outcome
  (A7).
* **R1–R31 rejection** — Disabled (R1); fixture rejected under
  production-required (R2) and mainnet-production-required (R3);
  production unavailable (R4) and mainnet-production unavailable (R5);
  wrong environment / chain / genesis / authority root / custody key
  id / signing-key fingerprint / lifecycle action / candidate digest /
  authority-domain sequence / request digest (R6–R15);
  stale/replayed request (R16) and response (R17); expired attestation
  (R18) and response (R19); unsupported suite (R20); invalid signature
  (R21); malformed request (R22) and response (R23); local operator
  key cannot satisfy (R24); peer majority cannot satisfy (R25); remote
  signer valid but custody invalid (R26); custody valid but remote
  signer response invalid (R27); lifecycle + governance + custody
  valid but production remote signer unavailable (R28); MainNet
  peer-driven apply refused even with fixture loopback (R29);
  validation-only rejection non-mutating (R30); mutating-preflight
  rejection produces no mutation (R31).
* **Determinism / replay / separation** — request canonical digest is
  deterministic and field-sensitive; fixture-vs-production signer
  separation; fixture loopback response echoes the request digest;
  non-`RemoteSigner` custody classes do not route.

## Validation commands

* `cargo build -p qbind-node --lib`
* `cargo test -p qbind-node --test run_194_remote_authority_signer_boundary_tests`
* `cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests`
* `cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests`
* `cargo test -p qbind-node --test run_188_authority_custody_boundary_tests`
* `cargo test -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests`
* `cargo test -p qbind-node --test run_184_onchain_governance_payload_carrying_tests`
* `cargo test -p qbind-node --test run_182_onchain_governance_production_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_180_onchain_governance_marker_integration_tests`
* `cargo test -p qbind-node --test run_178_onchain_governance_proof_tests`
* `cargo test -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests`
* `cargo test -p qbind-node --test run_173_validation_only_governance_required_policy_tests`
* `cargo test -p qbind-node --test run_171_governance_required_policy_selector_tests`
* `cargo test -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests`
* `cargo test -p qbind-node --test run_167_governance_proof_carrier_tests`
* `cargo test -p qbind-node --test run_165_governance_marker_integration_tests`
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests`
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests`
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
* `cargo test -p qbind-node --lib pqc_authority`

All commands run on this checkout completed successfully. Representative
results:

* `run_194_remote_authority_signer_boundary_tests`: 44 passed.
* `run_192_authority_custody_policy_selector_tests`: 46 passed.
* `run_190_authority_custody_payload_callsite_tests`: 55 passed.
* `run_188_authority_custody_boundary_tests`: 48 passed.
* `run_186_onchain_governance_production_verifier_boundary_tests`: 44 passed.
* `run_184_onchain_governance_payload_carrying_tests`: 44 passed.
* `run_182_onchain_governance_production_callsite_wiring_tests`: 37 passed.
* `run_180_onchain_governance_marker_integration_tests`: 40 passed.
* `run_178_onchain_governance_proof_tests`: 46 passed.
* `run_176_live_0x05_governance_proof_carrier_tests`: 37 passed.
* `run_173_validation_only_governance_required_policy_tests`: 25 passed.
* `run_171_governance_required_policy_selector_tests`: 35 passed.
* `run_169_governance_proof_loader_surface_integration_tests`: 39 passed.
* `run_167_governance_proof_carrier_tests`: 47 passed.
* `run_165_governance_marker_integration_tests`: 31 passed.
* `run_163_governance_authority_verifier_tests`: 32 passed.
* `run_161_lifecycle_marker_integration_tests`: 29 passed.
* `run_159_authority_signing_key_lifecycle_tests`: 29 passed.
* `run_157_unified_testnet_fixture_universe_tests`: 16 passed.
* `run_152_binary_reachable_peer_drain_plumbing_tests`: 23 passed.
* `run_150_peer_driven_apply_drain_tests`: 19 passed.
* `run_148_peer_driven_apply_devnet_tests`: 20 passed.
* `run_142_live_inbound_0x05_v2_validation_tests`: 16 passed.
* `run_134_reload_apply_v2_authority_marker_tests`: 5 passed.
* `run_138_sighup_v2_authority_marker_tests`: 11 passed.
* `cargo test -p qbind-node --lib pqc_authority`: 164 passed.

## Acceptance summary

1. A typed RemoteSigner production-custody interface boundary exists
   (`pqc_remote_authority_signer.rs`). ✅
2. Fixture loopback RemoteSigner is DevNet/TestNet source-test only
   (accepted on DevNet/TestNet under `FixtureLoopbackAllowed`,
   rejected on MainNet — A1/A2 and R29 tests). ✅
3. Production RemoteSigner remains unavailable / fail-closed (A7, R4,
   R5, R28 tests). ✅
4. RemoteSigner request/response binding is deterministic and
   domain-bound (A3, canonical-digest determinism tests). ✅
5. RemoteSigner integrates with custody composition at source/test
   level (A4, A5 tests). ✅
6. Local operator key / peer majority cannot satisfy RemoteSigner
   policy (R24, R25 tests). ✅
7. Validation-only surfaces remain non-mutating (R30 test). ✅
8. Mutating rejection paths produce no mutation (R31 test). ✅
9. MainNet peer-driven apply remains refused (R29 test). ✅
10. Release-binary RemoteSigner boundary evidence deferred to
    Run 195. ✅
11. No real RemoteSigner / KMS / HSM / governance execution /
    validator-set rotation claim is made. ✅
12. No full C4 or C5 closure is claimed. ✅

## Deferred

* Release-binary RemoteSigner boundary evidence: **Run 195**.
* Real remote signer backend / networked signer service remains
  unimplemented.
* Real KMS / HSM / cloud-KMS / PKCS#11 backend remains unimplemented.
* Real on-chain governance proof verification remains unimplemented.
* Governance execution remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.