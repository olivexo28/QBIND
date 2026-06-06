# QBIND DevNet evidence — Run 196

**Title.** Source/test RemoteSigner identity/request/response attestation
payload/carrying and production-context wiring.

**Status.** PASS (source/test only). Run 196 adds source- and test-level
support for carrying RemoteSigner identity / request / response
attestation material through the production payload and production-context
paths, and routing it into the Run 194 lifecycle + governance + custody +
RemoteSigner composition. The carrier is an **additive, optional** JSON
sibling (`remote_signer_attestation`) on the v2 ratification sidecar,
mirroring the Run 190 authority-custody payload/carrying pattern. Run 196
adds NO new CLI flag and NO new env var; it is a pure library boundary.

Run 196 does NOT implement a real RemoteSigner backend. Fixture loopback
RemoteSigner material remains DevNet/TestNet source/test only; production
RemoteSigner material reaches the boundary and fails closed as
unavailable; malformed/invalid material fails closed; and MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal even when
fixture loopback RemoteSigner material is supplied.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 197).
* No real RemoteSigner backend; no networked signer service.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority authority.
* No marker / sequence-file / authority-marker / trust-bundle core /
  ratification-sidecar wire / schema change. The RemoteSigner attestation
  carrier is an additive optional JSON sibling only; legacy
  no-RemoteSigner payloads remain byte-compatible and parse as `Absent`.
* Run 196 does not weaken any prior run (Runs 070, 130–195) and does not
  claim full C4 or C5 closure.

## Run 196 deliverables

* Production source module:
  [`crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs`](
    ../../crates/qbind-node/src/pqc_remote_signer_payload_carrying.rs).
* Focused test suite:
  [`crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs`](
    ../../crates/qbind-node/tests/run_196_remote_signer_payload_callsite_tests.rs).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Source surface

`pqc_remote_signer_payload_carrying` provides:

* Wire types `RemoteSignerIdentityWire`, `RemoteSignerRequestWire`,
  `RemoteSignerResponseWire`, and the combined
  `RemoteSignerAttestationWire`, each with `to_*` / `from_*` converters
  to/from the Run 194 internal `pqc_remote_authority_signer` types.
  The wire carrier carries a `schema_version` that fails closed on any
  unsupported (future/unknown) value.
* `RemoteSignerLoadStatus { Absent, Available, Malformed }`, the
  fail-closed three-state load discipline matching Run 190.
* `parse_optional_remote_signer_attestation_sibling_from_json_value` —
  extracts the optional `remote_signer_attestation` sibling from a
  `serde_json::Value` **before** the strict v2 sidecar parse: absent →
  `Absent`; present-but-malformed → `Malformed` (fail closed);
  well-formed → `Available`.
* A combined v2-sidecar loader
  (`load_v2_ratification_sidecar_with_remote_signer_attestation_from_path`
  / `_from_bytes`) returning both the verified sidecar and the
  RemoteSigner load status.
* Seven per-surface production-context routing helpers —
  `reload_check`, `reload_apply`, `startup_p2p_trust_bundle`, `sighup`,
  `local_peer_candidate_check`, `live_inbound_0x05`, `peer_driven_drain`
  — each routing the loaded RemoteSigner material into the Run 194
  composition `validate_lifecycle_governance_custody_and_remote_signer`,
  short-circuiting on malformed material in front of the verifier, and
  preserving the MainNet peer-driven apply refusal.
* `route_remote_signer_attestation_for_custody_class` routing into the
  Run 194 `validate_remote_signer_for_custody_class`, and
  `validate_loaded_remote_signer` routing into `validate_remote_signer`.

## Test evidence

`cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests`
passes 58 tests, covering:

* Type-shape and serde round-trips; absent / null / non-object /
  malformed identity / malformed request / malformed response /
  unsupported-schema-version siblings all fail closed.
* Canonical digest determinism for the request binding.
* Combined loader on legacy (no-sibling → `Absent`) and carrying
  (sibling → `Available`) v2 sidecars.
* A1–A10 accept-path scenarios: legacy no-RemoteSigner bypass; fixture
  loopback reaching and passing the production-context path where policy
  allows; custody composition acceptance; validation-only non-mutation.
* R1–R34 reject-path scenarios: malformed/invalid material; fixture
  rejected under production / mainnet-production required; production and
  mainnet-production rejected as unavailable; local-operator-key and
  peer-majority cannot satisfy RemoteSigner; custody-invalid composition
  rejection; mutating-preflight produces no mutation; MainNet peer-driven
  apply refused even with fixture loopback RemoteSigner material.

## Standing invariants (unchanged by Run 196)

* No real RemoteSigner backend is implemented.
* Fixture loopback RemoteSigner remains DevNet/TestNet source/test only.
* Production RemoteSigner remains unavailable / fail-closed.
* RemoteSigner payload/carrying evidence is source/test only.
* MainNet peer-driven apply remains refused.
* KMS / HSM remain unimplemented.
* Governance execution remains unimplemented.
* Real on-chain proof verification remains unimplemented.
* Validator-set rotation remains open.
* Release-binary RemoteSigner payload/carrying evidence is deferred to
  Run 197.
* Full C4 remains open.
* C5 remains open.
