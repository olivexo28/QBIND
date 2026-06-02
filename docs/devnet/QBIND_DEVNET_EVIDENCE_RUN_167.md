# QBIND DevNet Evidence — Run 167

## Subject

Run 167: **source/test governance-proof carrying schema** for v2
authority / ratification sidecars.

Run 166 demonstrated, on a real `target/release/qbind-node`, that the
Run 165 governance gate (`GovernanceProofPolicy`,
`GovernanceProofContext`, `GovernanceMarkerGate`,
`evaluate_governance_marker_gate`,
`decide_v2_marker_acceptance_with_lifecycle_and_governance`) is
production-source reachable on the release binary, that
`GovernanceProofPolicy::NotRequired` is binary-compatible with existing
v2 wire material, and that `RequiredButMissing` / `GovernanceAuthorityRejected`
fail closed on the release-built helper. Run 166 also explicitly
identifies the next required run as the governance-proof carrying /
schema run — that is **Run 167**.

Run 167 introduces the smallest additive carrier that lets a v2
ratification sidecar transport a `GovernanceAuthorityProof` so that
existing production preflight surfaces can supply
`GovernanceProofContext::Available(...)` to the Run 165 gate via a
typed loader.

New/changed source surfaces:

* `crates/qbind-node/src/pqc_governance_proof_wire.rs` (new)
  * `GovernanceAuthorityProofWire` — wire-safe serde representation of
    every binding carried by the Run 163
    `GovernanceAuthorityProof`;
  * `GovernanceAuthorityClassWire` — wire-safe issuer-class enum
    (`genesis-bound`, `emergency-council`, `on-chain-governance`);
  * `GovernanceThresholdWire` — wire-safe threshold descriptor;
  * `GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION = 1` — explicit
    versioning so a future schema bump is a typed reject, not silent
    drift;
  * `GovernanceProofWireParseError` — typed parse errors
    (`Json`, `UnknownSchemaVersion`, `EmptyRequiredField`,
    `EmptyIssuerSignature`);
  * `GovernanceProofLoadStatus` — typed loader result
    (`Absent`, `Available(GovernanceAuthorityProof)`,
    `Malformed(GovernanceProofWireParseError)`);
  * `GovernanceProofLoadStatus::governance_proof_context(verifier)` —
    typed adapter into `GovernanceProofContext` for the Run 165 gate.
* `crates/qbind-node/src/pqc_ratification_input.rs`
  * `LoadedV2RatificationSidecar { ratification, governance_proof }`;
  * `load_v2_ratification_sidecar_with_governance_proof_from_path(path)`
    — additive sidecar loader that parses the optional
    `governance_authority_proof` JSON sibling field on the v2
    ratification sidecar and returns the typed load status. Existing
    `load_versioned_ratification_from_path` remains unchanged (Run 134 /
    Run 138 / Run 142 / Run 148 / Run 150 / Run 152 backwards
    compatibility).

Tests:
`crates/qbind-node/tests/run_167_governance_proof_carrier_tests.rs`.

## Strict scope

Run 167 is **source/test schema/carrying work only**. It does **not**:

* enable MainNet peer-driven apply (MainNet refusal remains intact even
  if a valid proof is supplied);
* implement a governance execution engine;
* implement on-chain governance integration —
  `GovernanceAuthorityClassWire::OnChainGovernance` round-trips through
  the wire carrier but is **explicitly fail-closed** at the Run 163
  verifier as `UnsupportedOnChainGovernance`;
* implement KMS/HSM custody;
* implement validator-set rotation;
* implement autonomous / on-receipt / peer-majority apply;
* change the v2 ratification, authority-marker, sequence-file, or
  trust-bundle wire formats — the
  `governance_authority_proof` field is an **additive optional sibling**
  on the v2 ratification sidecar JSON; sidecars without the field
  continue to parse exactly as they did before Run 167;
* weaken Run 070 reload-apply, Runs 130–166, or any prior acceptance
  evidence;
* include any release-binary harness — release-binary proof-carrying
  enforcement evidence is **deferred to Run 168**.

Run 167 does **not** close C4 or C5.

## Canonical bindings

The wire-carried governance proof binds to:

* environment;
* chain_id;
* genesis_hash;
* authority root fingerprint (and authority-root suite);
* lifecycle action (the local sub-classification: `ActivateInitial`,
  `Rotate`, `Retire`, `Revoke`, `EmergencyRevoke`);
* candidate v2 ratification digest;
* authority-domain sequence;
* active / new / revoked bundle-signing key fingerprint where applicable;
* issuer authority class;
* issuer signature suite;
* issuer signature.

The proof is **not** interpreted as:

* peer-majority authority (no peer-majority class is wire-representable);
* local operator config alone (an empty issuer signature is rejected at
  the wire boundary as `EmptyIssuerSignature`);
* MainNet apply authorization by itself (gate acceptance is independent
  of the surface MainNet refusal);
* KMS/HSM custody;
* on-chain governance execution proof
  (`OnChainGovernance` ⇒ `UnsupportedOnChainGovernance`).

## Source behaviour

1. The Run 167 sidecar loader returns one of:
   * `LoadedV2RatificationSidecar.governance_proof =
     GovernanceProofLoadStatus::Absent` when no
     `governance_authority_proof` sibling field is present (or it is
     JSON `null`);
   * `Available(GovernanceAuthorityProof)` when the sibling parses and
     converts cleanly into the typed Run 163 proof object;
   * `Malformed(GovernanceProofWireParseError)` when the sibling is
     present but unparseable / unsupported. The v2 ratification itself
     is still returned so the caller can fall through the gate; the gate
     fails closed under `RequiredForLifecycleSensitive` and is a no-op
     under `NotRequired`.
2. `GovernanceProofLoadStatus::governance_proof_context(verifier)`
   builds the `GovernanceProofContext` consumed by
   `evaluate_governance_marker_gate`. `Available` →
   `Supplied { proof, verifier }`; `Absent` and `Malformed` →
   `Unavailable` (fail-closed when the policy requires a proof).
3. Parsing performs **no marker write, no sequence write, no live trust
   swap, no session eviction**.

## Surface coverage

The Run 167 wire-carrier path supplies a `GovernanceProofContext` to
the same `evaluate_governance_marker_gate` entry point that every
existing production preflight surface already consumes. At source/test
level the test matrix exercises the wire-carrier path through:

1. reload-check validation-only;
2. reload-apply preflight;
3. startup `--p2p-trust-bundle` preflight;
4. SIGHUP live-reload preflight;
5. live inbound `0x05` / local peer-candidate validation-only;
6. peer-driven drain `ProductionV2MarkerCoordinator`.

Release-binary proof-carrying enforcement evidence on each surface is
deferred to Run 168.

## Accept matrix (A1–A9, source/test)

* **A1** sidecar without governance proof parses under `NotRequired` →
  `GovernanceMarkerGate::NotRequiredNoProof`.
* **A2** sidecar without governance proof under
  `RequiredForLifecycleSensitive` → `RequiredButMissing { action }`
  (fail-closed).
* **A3** wire carrier with valid `GenesisBound` Rotate proof → `Accepted(
  AcceptedGenesisBound { action: Rotate, .. })`.
* **A4** wire carrier with valid `GenesisBound` Revoke proof →
  `Accepted( AcceptedGenesisBound { action: Revoke, .. })`.
* **A5** wire carrier with valid `EmergencyCouncil` `EmergencyRevoke`
  proof → `Accepted( AcceptedEmergencyCouncil { .. })`.
* **A6** idempotent re-presentation of the same wire carrier → same
  accept (deterministic, non-mutating gate).
* **A7** valid proof-carrying sidecar through reload-check
  validation-only path: gate accepts, no sequence write, no marker
  write.
* **A8** valid proof-carrying sidecar through reload-apply preflight
  path: gate accepts, no mutation during preflight.
* **A9** valid proof-carrying sidecar reaches peer-driven drain
  `ProductionV2MarkerCoordinator` source path; MainNet enablement is
  **not** implied.

## Reject matrix (R1–R21, source/test)

* **R1** malformed governance proof → `Malformed(...)` → gate
  `RequiredButMissing { action }` under `RequiredForLifecycleSensitive`.
* **R2** wrong environment → `WrongEnvironment { .. }`.
* **R3** wrong chain → `WrongChain { .. }`.
* **R4** wrong genesis → `WrongGenesis { .. }`.
* **R5** wrong authority root → `WrongAuthorityRoot { .. }`.
* **R6** wrong lifecycle action → `WrongLifecycleAction { .. }`.
* **R7** wrong candidate digest → `WrongCandidateDigest { .. }`.
* **R8** wrong authority-domain sequence → `WrongAuthoritySequence { .. }`.
* **R9** invalid issuer signature → `InvalidIssuerSignature { .. }`.
* **R10** unsupported issuer suite → `UnsupportedIssuerSuite { suite_id }`.
* **R11** non-PQC suite → `NonPqcSuiteRejected { suite_id }`.
* **R12** threshold not met → `ThresholdNotMet { approvals, required }`.
* **R13** stale / replayed lower-sequence proof → `ReplayRejected { .. }`.
* **R14** `OnChainGovernance` class → `UnsupportedOnChainGovernance`
  (fail-closed unsupported).
* **R15** local operator config alone → cannot encode (empty
  `issuer_signature` rejected at the wire boundary as
  `EmptyIssuerSignature`).
* **R16** peer-majority / gossip count → cannot encode (no
  peer-majority class is wire-representable).
* **R17** proof valid but lifecycle invalid → reject (the gate composed
  with the lifecycle layer rejects on the broken-lifecycle side; the
  gate alone surfaces this through the persisted-sequence replay path).
* **R18** lifecycle valid but proof invalid → `InvalidIssuerSignature`
  (or the precise typed binding reject corresponding to the tampered
  field).
* **R19** proof valid but MainNet peer-driven apply still refused — gate
  accepts on a Mainnet candidate (gate is environment-agnostic), but the
  surface MainNet refusal is unchanged by Run 167 and continues to
  refuse MainNet peer-driven apply.
* **R20** old v2 sidecars (no `governance_authority_proof` sibling)
  remain valid under `NotRequired`.
* **R21** old v2 sidecars fail closed under
  `RequiredForLifecycleSensitive` for lifecycle-sensitive actions.

## Backwards-compatibility checks

The Run 167 carrier is strictly additive on the v2 ratification sidecar
JSON document and does **not** modify
`qbind_ledger::BundleSigningRatificationV2`. The existing `cargo test`
green-set is preserved:

* Run 134 reload-apply v2 marker tests — green.
* Run 138 SIGHUP v2 tests — green.
* Run 142 live inbound `0x05` v2 validation tests — green.
* Run 148 / 150 / 152 peer-driven apply tests — green.
* Run 161 lifecycle marker integration tests — green.
* Run 163 governance verifier tests — green.
* Run 165 governance marker integration tests — green.
* Run 166 evidence assumptions remain valid (governance gate is still
  production-source reachable; release-binary `NotRequired`
  compatibility is still proven; no MainNet peer-driven apply enabled).

## Known limitations / explicit non-goals

* **Run 168 deferral.** Release-binary proof-carrying evidence
  (the harness exercising the new sidecar carrier on a real
  `target/release/qbind-node`) is deferred to Run 168.
* **MainNet apply** remains refused. Run 167 does not change the
  surface MainNet refusal.
* **OnChainGovernance** remains unsupported / fail-closed
  (`UnsupportedOnChainGovernance`) until a real on-chain proof format is
  implemented.
* **Governance execution / on-chain proof** remains unimplemented.
* **KMS/HSM** remains unimplemented.
* **Validator-set rotation** remains open.
* **Full C4** remains open.
* **C5** remains open.

## Validation commands

```text
cargo build -p qbind-node --lib
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
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

All listed targets pass; the new
`run_167_governance_proof_carrier_tests` target reports 47 passing
tests covering the A1–A9 / R1–R21 matrix and the wire / loader /
context-adapter parse paths.
