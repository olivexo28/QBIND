# QBIND DevNet Evidence — Run 169

## Subject

Run 169: **source/test** integration of the Run 167 governance-proof
loader into the production v2 marker-decision callers. Release-binary
proof-carrying production-surface evidence is **deferred to Run 170**.

Run 167 introduced the typed v2-with-proof sidecar loader
(`load_v2_ratification_sidecar_with_governance_proof_from_path`) and the
[`GovernanceProofLoadStatus`] enum (`Absent` / `Available` / `Malformed`).
Run 168 produced release-binary evidence that a release-built helper
plus the real `target/release/qbind-node` enforce the Run 165
governance gate over proof-carrying v2 sidecars. Run 168 explicitly
left the follow-up:

> production marker-decision callers still need to consume the typed
> governance-proof loader instead of using `Unavailable`.

Run 169 closes that follow-up at the **source/test** level. It does
**not** add release-binary harness, does **not** enable MainNet
peer-driven apply, does **not** introduce KMS/HSM, does **not**
implement governance execution, and does **not** change any wire
schema.

## Strict scope

* Source/test only.
* No release-binary harness.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No on-chain governance implementation. `OnChainGovernance` remains
  unsupported / fail-closed.
* No KMS/HSM. The fixture verifier `fixture_issuer_signature_verifier`
  remains the only verifier wired into the production callers.
  Real-issuer-key verifier installation is deferred to Run 170+.
* No validator-set rotation.
* No autonomous apply.
* No automatic apply on receipt.
* No peer-majority authority.
* No new governance-proof schema beyond Run 167's optional sibling
  field.
* No marker schema change.
* No sequence-file schema change.
* No trust-bundle core schema change.
* No peer-candidate envelope schema change.
* Runs 070, 130–168 are not weakened.
* C4 and C5 remain open.

## Source delta

Single new library shim:

* `crates/qbind-node/src/pqc_governance_proof_surface.rs`
  — `preflight_v2_marker_decision_with_governance_proof_load(inputs,
  policy, &load_status, &dyn verifier)`. Maps a
  `GovernanceProofLoadStatus` to a `GovernanceProofContext` via the
  Run 167 documented mapping
  (`Available → Supplied`, `Absent | Malformed → Unavailable`) and
  delegates to the existing Run 165 helper
  `decide_v2_marker_acceptance_with_lifecycle_and_governance`. The
  shim is non-mutating: it never persists a marker. Persist remains
  the caller's responsibility after the Run 055 / Run 070
  sequence-commit boundary, via
  `persist_accepted_v2_marker_after_commit_boundary`.

Additive dispatcher in
`crates/qbind-node/src/pqc_ratification_input.rs`:

* `VersionedRatificationSidecarWithGovernanceProof::{V1, V2 { ratification, governance_proof }}`
* `load_versioned_ratification_with_governance_proof_from_path()` —
  delegates v2 envelopes to the Run 167 loader, v1 envelopes to the
  Run 132 v1 dispatcher unchanged. The `Absent | Available |
  Malformed` carrier shape is preserved unchanged.

Production callers updated to consume the new dispatcher and the new
shim:

* `crates/qbind-node/src/main.rs`
  * `Run105ReloadCheckContextData` carries a
    `governance_proof_load: GovernanceProofLoadStatus` field.
  * `build_run_105_reload_check_context` now uses
    `load_versioned_ratification_with_governance_proof_from_path` and
    propagates the typed load status downstream.
  * `preflight_run_134_v2_marker_decision` (reload-check / reload-apply
    Run 105 / Run 134) and
    `preflight_run_136_v2_marker_decision_for_startup`
    (`--p2p-trust-bundle` startup, Run 136) call the new shim with
    `fixture_issuer_signature_verifier()`,
    `GovernanceProofPolicy::NotRequired`, and the typed
    `governance_proof_load` from the Run 105 context.
* `crates/qbind-node/src/pqc_live_trust_reload.rs`
  * SIGHUP load site uses the new dispatcher.
  * `preflight_sighup_v2_marker_decision` (Run 138) takes
    `governance_proof_load: &GovernanceProofLoadStatus` and routes it
    through the shim.
* `crates/qbind-node/src/pqc_peer_candidate_apply.rs`
  * `ProductionV2MarkerCoordinator` carries
    `governance_proof_load: GovernanceProofLoadStatus` and
    `governance_policy: GovernanceProofPolicy` (defaults `Absent` /
    `NotRequired`, which preserves the Runs 148 / 150 / 152 semantics
    bit-for-bit).
  * `with_governance_proof_carrier(load, policy)` is the additive
    setter.
  * `decide_pre_apply` routes through the shim.

`OnChainGovernance` remains unsupported: the shim never short-circuits
the gate; it routes the load status into the gate, which already
returns `UnsupportedOnChainGovernance` for `OnChainGovernance` proofs
(Run 165). Run 169 does not change that. MainNet peer-driven apply
remains refused upstream of the coordinator: Run 169 does not change
environment gating in `pqc_peer_candidate_apply`.

## Source-reachability evidence (grep)

The four production marker-decision call sites that previously hard-
coded `GovernanceProofContext::Unavailable` now route through the
Run 167 loader instead. Confirm with:

```sh
# No remaining hard-coded Unavailable in the production preflight callers:
rg -n 'GovernanceProofContext::Unavailable' crates/qbind-node/src/main.rs \
  crates/qbind-node/src/pqc_live_trust_reload.rs \
  crates/qbind-node/src/pqc_peer_candidate_apply.rs

# All four production preflights now call the Run 169 shim:
rg -n 'preflight_v2_marker_decision_with_governance_proof_load' \
  crates/qbind-node/src/

# Run 167 loader is reachable from production callers (Run 105 / 134 /
# 136 / 138 / peer-driven coordinator):
rg -n 'load_versioned_ratification_with_governance_proof_from_path|load_v2_ratification_sidecar_with_governance_proof_from_path' \
  crates/qbind-node/src/
```

## Test surface

New: `crates/qbind-node/tests/run_169_governance_proof_loader_surface_integration_tests.rs`.

39 tests, all passing locally:

* **A1–A9 acceptance matrix**
  * A1 — old no-proof v2 sidecar accepted under `NotRequired`
    (back-compat).
  * A2 — reload-check valid Rotate proof under `RequiredForLifecycleSensitive`
    accepted, no marker write.
  * A3 — reload-apply valid Rotate proof accepted, no premature write.
  * A4 — startup `--p2p-trust-bundle` valid Rotate proof accepted, no
    premature write.
  * A5 — SIGHUP valid Rotate proof accepted, no premature write.
  * A6 — peer-driven coordinator valid Rotate proof accepted.
  * A7 — `Available` proof status reaches the gate as
    `GovernanceProofContext::Available` with the carrier's verifier.
  * A8 — `NotRequired` policy with `Absent` proof preserves bit-for-bit
    Runs 148 / 150 / 152 semantics.
  * A9 — proof-carrying sidecar with `EmergencyCouncil` class accepted
    when lifecycle is consistent.

* **R1–R25 rejection matrix** (all fail closed; no marker written;
  seeded prior marker bytes byte-for-byte unchanged on disk):
  * R1 — `RequiredForLifecycleSensitive` + absent proof on
    reload-check → `GovernanceAuthorityRequiredButMissing`.
  * R2 — same on reload-apply → no Run 070 call.
  * R3 — malformed proof → fails closed before mutation.
  * R4 — wrong environment.
  * R5 — wrong chain.
  * R6 — wrong genesis.
  * R7 — wrong authority root.
  * R8 — wrong lifecycle action.
  * R9 — wrong candidate digest.
  * R10 — wrong authority sequence.
  * R11 — invalid issuer signature.
  * R12 — unsupported issuer suite.
  * R13 — non-PQC suite.
  * R14 — threshold not met (when representable).
  * R15 — stale / replayed proof.
  * R16 — `OnChainGovernance` class — `UnsupportedOnChainGovernance`.
  * R17 — local operator config alone cannot be encoded as a proof.
  * R18 — peer majority gossip count cannot be encoded as a proof.
  * R20 — lifecycle valid but proof invalid → fails closed.
  * R21 — governance rejection on startup → no marker write.
  * R22 — governance rejection on SIGHUP → no mutation.
  * R23 — governance rejection on peer-driven drain → no mutation.

* Loader/dispatcher reachability tests confirm `V1` / `V2 no-proof` /
  `V2 with-proof` envelopes route to the correct
  `GovernanceProofLoadStatus` variant.

## Validation commands and results

All run on this branch from a clean checkout:

| Command | Result |
| --- | --- |
| `cargo build -p qbind-node --lib` | succeeded |
| `cargo test -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests` | 39 passed |
| `cargo test -p qbind-node --test run_167_governance_proof_carrier_tests` | 47 passed |
| `cargo test -p qbind-node --test run_165_governance_marker_integration_tests` | 23 passed |
| `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests` | 32 passed |
| `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests` | 29 passed |
| `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests` | 29 passed |
| `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests` | 16 passed |
| `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests` | 23 passed |
| `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests` | 19 passed |
| `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` | 20 passed |
| `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` | 16 passed |
| `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests` | 11 passed |
| `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` | 5 passed |
| `cargo test -p qbind-node --lib pqc_authority` | 148 passed |
| `cargo test -p qbind-node --lib` | 1282 passed |

## Invariants preserved

* No marker, sequence, or live-trust mutation occurs in the shim.
* Persist remains gated on the caller-owned Run 055 / Run 070
  sequence-commit boundary via
  `persist_accepted_v2_marker_after_commit_boundary`.
* Default policy in production callers remains `NotRequired`. Existing
  no-proof sidecars remain accepted under `NotRequired`.
* Default `ProductionV2MarkerCoordinator` semantics are bit-for-bit
  preserved (defaults `Absent` / `NotRequired`); Runs 148 / 150 / 152
  do not regress.
* MainNet peer-driven apply remains refused (environment gating
  upstream of the coordinator was not modified).
* `OnChainGovernance` remains unsupported / fail-closed.
* `Malformed` proof load deliberately maps to `Unavailable` so under
  `RequiredForLifecycleSensitive` it surfaces as
  `GovernanceAuthorityRequiredButMissing` (Run 167's documented fail-
  closed semantics).
* No schema drift: marker, sequence, trust-bundle, peer-candidate
  envelope, and governance-proof wire schema are unchanged from
  Run 167. Schema version of `GovernanceAuthorityProofWire` remains 1.

## Live inbound `0x05` path note

Run 169 does **not** extend the live-wire `LiveRatificationConfig` /
inbound `0x05` decode path (Run 142). Per Run 167, per-peer envelopes do
not carry the optional governance-proof sibling yet, so the existing
`Unavailable` context at that surface remains correct under
`NotRequired`. Lifting that to `RequiredForLifecycleSensitive` requires
a peer-candidate envelope schema extension and is explicitly deferred
to a later run; Run 169's strict scope forbids that envelope change.

## Deferred to Run 170 (and later)

* Release-binary production-surface proof-carrying evidence
  (`target/release/qbind-node` exercising the new shim end-to-end).
* Real-issuer-key verifier installation (replacing
  `fixture_issuer_signature_verifier` in production callers with a
  KMS/HSM-backed verifier).
* Per-peer envelope governance-proof carrier.
* Governance execution engine.
* On-chain governance implementation.
* Validator-set rotation.
* Autonomous apply / automatic apply on receipt.
* Peer-majority authority encoding.
* Full C4 closure.
* C5 closure.