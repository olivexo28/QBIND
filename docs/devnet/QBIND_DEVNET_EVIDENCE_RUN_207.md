# QBIND DevNet evidence — Run 207

**Title.** Source/test custody-attestation payload carrying and production
preflight integration.

**Status.** PASS (source/test only). Run 207 makes the Run 205 typed
custody-attestation evidence/input reachable from production call-site
contexts by adding an additive, optional `custody_attestation` sibling on
the v2 ratification sidecar JSON, a wire/context representation that
converts into the Run 205 internal types, a typed load status, a pure
sibling-extraction parser, a combined v2 sidecar loader, a typed call-site
context, and seven per-surface routing helpers that drive the parsed
carrier into the Run 205 `verify_custody_attestation` /
`validate_custody_metadata_and_attestation` /
`validate_lifecycle_custody_and_attestation` boundary while preserving the
default `Disabled` policy, legacy no-attestation payload compatibility,
and the MainNet peer-driven-apply refusal.

Run 207 does **not** implement a real cloud-KMS attestation verifier, a
real PKCS#11 attestation verifier, a real HSM vendor attestation verifier,
or a real RemoteSigner backend. The default remains
`CustodyAttestationPolicy::Disabled`. The fixture attestation is
DevNet/TestNet source/test only; the production, cloud-KMS, PKCS#11,
HSM-vendor, and RemoteSigner attestation paths remain
unavailable/fail-closed; the RemoteSigner path (Runs 194–202) and the
KMS/HSM backend path (Runs 203–204) remain separate, unchanged
backend-boundary options; and MainNet peer-driven apply remains the
Run 147 / 148 / 152 FATAL refusal even when a fixture attestation is
carried and verifies successfully.

## Strict scope

* Source/test evidence only. No release-binary harness (deferred to
  Run 208).
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
* Additive, optional payload/context fields only. Legacy/no-attestation
  payload compatibility preserved.
* No authority-marker / sequence-file / trust-bundle core schema change;
  no authority-lifecycle semantics change.
* Run 207 does not weaken any prior run (Runs 070, 130–206) and does not
  claim full C4 or C5 closure.

## Run 207 deliverables

* Production source module:
  [`crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs`](
    ../../crates/qbind-node/src/pqc_custody_attestation_payload_carrying.rs).
* Module registration in
  [`crates/qbind-node/src/lib.rs`](../../crates/qbind-node/src/lib.rs).
* Focused test suite:
  [`crates/qbind-node/tests/run_207_custody_attestation_payload_callsite_tests.rs`](
    ../../crates/qbind-node/tests/run_207_custody_attestation_payload_callsite_tests.rs).
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

## Payload-carrying surface

The Run 207 module `pqc_custody_attestation_payload_carrying` defines:

* **Sibling field + schema version** —
  `CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD` (`"custody_attestation"`)
  and `CUSTODY_ATTESTATION_PAYLOAD_WIRE_SCHEMA_VERSION` (`1`). The sibling
  is strictly additive: a v2 sidecar without it parses exactly as before
  and yields `CustodyAttestationLoadStatus::Absent`.
* **Wire types** — `CustodyAttestationClassWire` (string-tagged mirror of
  the Run 205 `CustodyAttestationClass`), `CustodyAttestationEvidenceWire`,
  `CustodyAttestationInputWire`, and the combined
  `CustodyAttestationPayloadWire { schema_version, evidence, input }`.
  `to_parts` / `to_evidence` / `to_input` convert into the internal Run
  205 `CustodyAttestationEvidence` / `CustodyAttestationInput`; an unknown
  `schema_version` or an empty required field fails closed via
  `CustodyAttestationWireParseError`. The representation covers attestation
  class, policy context (via the active policy on the call-site context),
  environment, chain_id, genesis_hash, authority root fingerprint,
  bundle-signing key fingerprint, custody class, backend kind / provider
  id / signer id, custody key id / key label, suite id, lifecycle action,
  candidate digest, authority-domain sequence, governance proof digest,
  request digest, response digest, transcript digest, attestation nonce,
  issuance timestamp/epoch, freshness/expiry window, and the evidence /
  certificate / placeholder commitment.
* **Load status** — `CustodyAttestationLoadStatus::{Absent, Available,
  Malformed}` with `is_absent` / `is_available` / `is_malformed` /
  `as_parts` / `malformed_error`.
* **Parse error taxonomy** — `CustodyAttestationPayloadParseError::{Json,
  Wire}` separating JSON-shape failures from wire-form structural failures.
* **Sibling parser** —
  `parse_optional_custody_attestation_sibling_from_json_value` extracts the
  optional sibling from a generic `serde_json::Value`: absent/null →
  `Absent`; non-null but undecodable → `Malformed(Json)`; decodable but
  structurally invalid → `Malformed(Wire)`; otherwise `Available(parts)`.
* **Combined loader** —
  `load_v2_ratification_sidecar_with_custody_attestation_from_path` /
  `_from_bytes` return the typed `BundleSigningRatificationV2` together
  with the Run 207 load status, extracting the sibling **before** the
  strict v2 sidecar parse so a malformed sibling cannot poison the
  ratification.
* **Call-site context** — `CustodyAttestationCallsiteContext` bundling the
  in-process Run 188 custody attestation, the candidate / persisted v2
  records, the trust domain, the lifecycle / governance / custody / suite
  bindings, the Run 188 custody policy, the Run 205 attestation policy, and
  `now_unix`, with a `binds_mainnet` surface helper.
* **Routing outcome** —
  `CustodyAttestationPayloadCarryingDecisionOutcome::{MalformedCustodyAttestationPayload,
  CustodyAttestationRequiredButAbsent, NoCustodyAttestationSupplied,
  MainNetPeerDrivenApplyRefused, Callsite}` wrapping the Run 205
  `CustodyMetadataAttestationOutcome` for parsed/present carriers.
* **Seven per-surface routing helpers** — `route_loaded_custody_attestation_to_*_callsite_decision`
  for reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP,
  local peer-candidate-check, live inbound `0x05`, and peer-driven drain.
  A malformed carrier short-circuits BEFORE the verifier, BEFORE any
  sequence/marker write, BEFORE any live trust swap, BEFORE any session
  eviction, and BEFORE any Run 070 call. The peer-driven drain helper
  refuses MainNet unconditionally.
* **Reachability / fail-closed helpers** —
  `callsite_context_for_custody_attestation`,
  `verify_loaded_custody_attestation` (routes into Run 205
  `verify_custody_attestation`),
  `validate_loaded_lifecycle_custody_and_attestation` (routes into Run 205
  `validate_lifecycle_custody_and_attestation`), and
  `mainnet_peer_driven_apply_remains_refused_under_custody_attestation_payload_carrying`.

## Test corpus

`crates/qbind-node/tests/run_207_custody_attestation_payload_callsite_tests.rs`
(64 tests, all PASS) covers, where representable at the payload-carrying
layer:

* **A1** legacy no-attestation payload compatible under `Disabled`.
* **A2 / A3** DevNet / TestNet fixture attestation carried through
  reload-check and accepted under the explicit fixture policy.
* **A4** DevNet fixture attestation carried through reload-apply preflight.
* **A5–A8** evidence / input / transcript / provider-identity digests
  preserved through wire conversion.
* **A9** fixture attestation routes to the Run 205 verifier when present.
* **A10** combined lifecycle + custody + fixture attestation accepted for a
  DevNet production-context path.
* **A11–A13** fixture attestation composes with the Run 203 fixture KMS /
  HSM backend contexts and the Run 201 fixture RemoteSigner transport
  context (carried as opaque evidence fields).
* **A14** governance proof behavior unchanged when attestation policy is
  `Disabled`.
* **A15** production attestation material reaches the verifier and returns
  a typed unavailable outcome under a production-required policy.
* **R1** absent under a required policy rejected fail-closed.
* **R2–R5** malformed evidence / input / combined payload and an
  unsupported future schema version rejected fail-closed.
* **R6 / R7** fixture attestation rejected under
  `ProductionAttestationRequired` / `MainnetProductionAttestationRequired`.
* **R8–R14** RemoteSigner / KMS / HSM / cloud-KMS / PKCS#11 / production /
  MainNet production attestation rejected as unavailable.
* **R15** unknown attestation class rejected.
* **R16–R34** wrong environment / chain / genesis / authority-root /
  signing-key fingerprint / custody class / backend-provider-signer id /
  key id / suite / lifecycle action / candidate digest / authority-domain
  sequence / governance-proof / request / response / transcript digest /
  stale-or-replayed / expired / invalid-commitment rejected at the Run 205
  verifier.
* **R35 / R36** local operator and peer majority cannot satisfy a
  production attestation.
* **R37 / R38** attestation valid but custody invalid; custody valid but
  attestation invalid.
* **R39** lifecycle + governance + custody valid but production attestation
  unavailable rejected overall.
* **R40 / R41** validation-only and mutating-preflight routing helpers are
  pure (no mutation; stable results).
* **R42** invalid live `0x05` custody-attestation candidate is not
  propagated / staged / applied.
* **R43** MainNet peer-driven apply remains refused even with a fixture
  attestation.
* serde/loader compatibility: legacy v2 sidecar without sibling →
  `Absent`; sidecar with sibling → `Available`; sidecar with malformed
  sibling → `Malformed` while the ratification still parses.
* source reachability: all seven production surfaces reach the Run 205
  verifier on accept, and the reachability helpers reach
  `verify_custody_attestation` and
  `validate_lifecycle_custody_and_attestation` outside helper/example
  modules.

## Validation commands

```
cargo build -p qbind-node --lib
cargo test -p qbind-node --test run_207_custody_attestation_payload_callsite_tests
cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests
cargo test -p qbind-node --test run_203_kms_hsm_backend_boundary_tests
cargo test -p qbind-node --test run_201_remote_signer_transport_boundary_tests
cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests
cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests
cargo test -p qbind-node --lib pqc_authority
```

Observed results: `cargo build -p qbind-node --lib` succeeds; the Run 207
suite reports 64 passed / 0 failed; the Run 205 (59), Run 203 (60), Run 201
(58), Run 196 (58), and Run 190 (55) suites pass unchanged; and
`cargo test -p qbind-node --lib pqc_authority` reports 164 passed / 0
failed. (If a referenced test target name differs in a future checkout,
locate the nearest existing target and document the exact command/result.)

## Why C4 / C5 remain OPEN

Run 207 only carries the Run 205 typed custody-attestation material
through production payload/context paths at the source/test level. It
implements no real cloud-KMS / PKCS#11 / HSM-vendor attestation verifier,
no real RemoteSigner backend, no governance execution engine, no real
on-chain proof verifier, and no validator-set rotation; the fixture
attestation remains DevNet/TestNet evidence-only and is refused on MainNet;
production attestation remains unavailable/fail-closed; and MainNet
peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal.
Release-binary custody-attestation payload/carrying evidence is deferred to
**Run 208**. **Full C4 remains OPEN; C5 remains OPEN.**