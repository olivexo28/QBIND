# QBIND DevNet Evidence — Run 176

## Scope

Run 176 is **source/test governance-proof carrying for live inbound
`0x05` peer-candidate envelopes**.

It closes the live inbound `0x05` boundary documented by Run 173 A5:
the live `0x05` peer-candidate wire envelope can now carry an optional
governance authority proof, and the validation-only path can convert
that proof to the existing Run 167 `GovernanceProofLoadStatus` and
route it into the Run 173 / Run 169 / Run 165 governance gate via the
new Run 176 source-level shim.

Run 176 does **not** replace, weaken, or rewrite the Run 173 surface.
It adds a strictly additive optional carrier to the existing live
`0x05` wire envelope and a thin re-export shim for the live inbound
`0x05` validation-only boundary.

Release-binary live `0x05` proof-carrying evidence is **deferred to
Run 177**.

## Strict scope

* Source/test only. **No release-binary harness in this run.**
* No MainNet peer-driven apply enablement. MainNet peer-driven apply
  remains refused unconditionally at the upstream binary gate
  (Run 148/149/152 invariant), regardless of any validation-only
  outcome.
* No governance execution engine.
* No on-chain governance implementation. `OnChainGovernance` remains
  unsupported / fail-closed at the Run 163 verifier.
* No KMS/HSM implementation.
* No validator-set rotation.
* No autonomous apply, no automatic apply on receipt, no peer-
  majority authority.
* Additive optional field on the existing live `0x05` peer-candidate
  wire envelope (`PeerCandidateWireEnvelopeV1`). **No** marker /
  sequence-file / trust-bundle core / authority-marker / wire-frame /
  wire-domain-tag schema-breaking change. Old `0x05` envelopes
  continue to parse byte-for-byte and the JSON layout for the no-
  proof path is unchanged
  (`#[serde(default, skip_serializing_if = "Option::is_none")]`).
* Does not weaken Runs 070, 130–175.
* Does NOT claim full C4 closure.
* Does NOT claim C5 closure.

## What Run 176 changes

### Source

* `crates/qbind-node/src/pqc_peer_candidate_wire.rs`
  * `PeerCandidateWireEnvelopeV1` gains an optional
    `governance_authority_proof: Option<GovernanceAuthorityProofWire>`
    field.
  * `PeerCandidateWireEnvelopeV1::governance_proof_load_status()`
    reproduces the Run 167 sidecar loader semantics on the in-band
    carrier: `None → Absent`, well-formed → `Available`, structurally
    malformed → `Malformed`.
* `crates/qbind-node/src/pqc_governance_proof_surface.rs`
  * New library shim
    `preflight_live_inbound_0x05_validation_only_marker_check_with_governance_proof_carrier`
    — the single integration shim for the live inbound `0x05`
    validation-only path. It delegates to the existing Run 173
    validation-only shim
    `preflight_v2_validation_only_marker_check_with_governance_proof_load`
    (which delegates to the Run 169 mutating shim) so the entire Run
    165 / 163 / 167 governance composition is reachable by exact
    delegation. Validation-only callers MUST drop the returned
    decision rather than persisting.

### Tests

* `crates/qbind-node/tests/run_176_live_0x05_governance_proof_carrier_tests.rs`
  — 37 focused source/test cases covering serde-compat invariants,
  the A1–A7 acceptance matrix, the R1–R22 rejection matrix, and an
  explicit source-reachability test that proves the live-`0x05`
  carrier reaches the Run 165 governance gate via the Run 176 →
  Run 173 → Run 169 → Run 165 chain.

## Acceptance matrix (A1–A7)

| ID | What                                                     | Outcome |
| -- | -------------------------------------------------------- | ------- |
| A1 | Legacy no-proof live `0x05` envelope, NotRequired policy | ✅ accepted; no marker write |
| A2 | Proof-carrying Rotate, Required (default ctor) policy    | ✅ accepted; verifier accepts; no writes |
| A3 | Proof-carrying Rotate, CLI Required selector             | ✅ accepted; same as A2 via CLI selector |
| A4 | Proof-carrying Rotate, env Required selector             | ✅ accepted; same as A2 via env selector |
| A5 | Proof-carrying Revoke (where representable)              | ✅ proof reaches gate; lifecycle classifier routes per Run 161 metadata-prefix boundary |
| A6 | Proof-carrying EmergencyRevoke (where representable)     | ⚠️ V2 ratification has no `EmergencyRevoke` action variant; documented as not-yet-representable boundary |
| A7 | Idempotency of proof-carrying live `0x05` candidate      | ✅ deterministic and pure; no marker write |

### A5 / A6 boundary

* **A5 (Revoke).** Run 130 V2 wire ratification carries
  `revocation_reason` as a free-form string and the Run 159 derivation
  places the new key fingerprint in `revoked_key_metadata`. The Run
  161 lifecycle classifier requires the metadata to begin with one of
  three sub-class prefixes (`01`/`02`/`03`); end-to-end Revoke
  representability is therefore bounded by the existing Run 161
  metadata-prefix routing (see `run_161_lifecycle_marker_integration
  _tests::a7_revoke_routed_through_lifecycle_validator`). Run 176 A5
  asserts the proof-carrier reaches the Run 165 gate and the
  lifecycle-level reject (where it occurs) is the same boundary
  documented by Run 161 — independent of Run 176.
* **A6 (EmergencyRevoke).** `BundleSigningRatificationV2Action` only
  enumerates `Ratify`, `Rotate`, `Revoke`. There is no V2 wire-level
  `EmergencyRevoke` variant, so a proof-carrying EmergencyRevoke
  cannot today be transported on the live `0x05` envelope. The Run
  165 gate continues to model `LocalLifecycleAction::EmergencyRevoke`
  at the proof level (covered by Run 173 fixtures); only the V2
  ratification surface is the limiting factor.

## Rejection matrix (R1–R22)

R1–R10 cover proof-validity / context-binding rejects (no proof under
Required, malformed proof, invalid issuer signature, wrong
environment/chain/genesis/authority root, wrong lifecycle action,
wrong candidate digest, wrong authority domain sequence). R11–R12
cover unsupported / non-PQC issuer suite tampering. R13 covers
`OnChainGovernance` fail-closed (unsupported). R14–R15 cover
"local-operator-config cannot stand in" and "peer-majority cannot
stand in" — both must remain refused. R16 covers proof-valid /
lifecycle-invalid. R17 covers lifecycle-valid / proof-invalid. R18–
R20 cover "invalid proof-carrying candidate cannot propagate / stage
/ reach peer-driven drain" non-mutation. R21 covers "valid proof-
carrying candidate does not apply on receipt" — the Run 165 gate
acceptance is **not** an apply trigger. R22 covers "MainNet peer-
driven apply remains refused even with valid proof".

All R1–R22 cases produce typed errors and leave on-disk state
unchanged.

## Non-mutation invariant

The Run 176 validation-only shim writes no marker, writes no
sequence file, never invokes Run 070, never swaps live trust state,
never evicts sessions. Post-conditions are asserted on every accept
and reject case in the test file (seeded marker bytes preserved
verbatim; absent marker stays absent).

## What Run 176 does NOT do

* Does **not** add a release-binary harness — release-binary
  evidence for the live `0x05` proof-carrying boundary is deferred
  to Run 177.
* Does **not** enable MainNet peer-driven apply.
* Does **not** add a governance execution engine, on-chain
  governance, KMS/HSM, validator-set rotation, autonomous apply,
  apply-on-receipt, or peer-majority authority.
* Does **not** change any existing proof / marker / sequence-file /
  trust-bundle core / authority-marker / wire-frame / wire-domain-
  tag schema. Old `0x05` JSON parses byte-for-byte; new no-proof
  `0x05` JSON serialises identically to the pre-Run-176 form.
* Does **not** replace or rewrite the Run 167 sidecar loader; the
  in-band carrier complements (does not replace) the sidecar loader.
* Does **not** weaken Runs 070, 130–175.
* Does **not** claim full C4 or C5 closure — the closure of the
  live `0x05` boundary is one piece of the broader peer-driven trust
  bundle apply story.

## Source reachability

The test
`source_reachability_live_0x05_carrier_reaches_governance_gate`
demonstrates that a proof-carrying live `0x05` envelope's
`governance_proof_load_status()` is consumed by the Run 176 shim,
which delegates to Run 173, which delegates to Run 169, which
composes the Run 165 gate over the Run 163 verifier — the same chain
already exercised by Run 173 for sidecar-loaded proofs.

## Validation commands

```
cargo build -p qbind-node
cargo test -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests
cargo test -p qbind-node --test run_173_validation_only_governance_required_policy_tests
cargo test -p qbind-node --test run_171_governance_required_policy_selector_tests
cargo test -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests
cargo test -p qbind-node --test run_167_governance_proof_carrier_tests
cargo test -p qbind-node --test run_165_governance_marker_integration_tests
cargo test -p qbind-node --test run_163_governance_authority_verifier_tests
cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests
cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests
cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests
cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests
cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests
cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests
cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test -p qbind-node --test run_078_pqc_peer_candidate_wire_tests
cargo test -p qbind-node --test run_079_pqc_peer_candidate_wire_live_dispatch_tests
cargo test -p qbind-node --test run_088_pqc_peer_candidate_propagation_tests
cargo test -p qbind-node --test run_109_pqc_peer_candidate_wire_live_ratification_tests
cargo test -p qbind-node --test run_145_peer_candidate_staging_tests
cargo test -p qbind-node --test run_146_live_inbound_0x05_staging_hook_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

## Deferred

* Run 177 — release-binary evidence for the live `0x05` proof-
  carrying boundary (binary-reachable peer-driven drain plumbing
  with the in-band carrier under Required policy).