# QBIND DevNet Evidence — Run 173

## Scope

Run 173 is **source/test validation-only Required-policy wiring**.

It wires the hidden Run 171 governance-proof Required-policy selector
(`--p2p-trust-bundle-governance-proof-required` /
`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1|true|yes|on`) into
the validation-only v2 surfaces so they can enforce
`GovernanceProofPolicy::RequiredForLifecycleSensitive` without ever
mutating on-disk state.

Run 173 closes the validation-only side of the Run 172 limitation:
Run 172 proved Required-policy on the **mutating** release-binary
surfaces (reload-apply, startup `--p2p-trust-bundle`, SIGHUP, peer-
driven apply) but the validation-only `--p2p-trust-bundle-reload-check`
path did not yet consult `governance_proof_policy_from_cli_or_env`.
Run 173 fixes that at the source/test level. Release-binary
validation-only Required-policy evidence is **deferred to Run 174**.

## Strict scope

* Source/test only. **No release-binary harness in this run.**
* No MainNet peer-driven apply enablement. MainNet peer-driven apply
  remains refused unconditionally at the upstream binary gate (Run
  148/149/152 invariant), regardless of any validation-only outcome.
* No governance execution engine.
* No on-chain governance implementation. `OnChainGovernance` remains
  unsupported / fail-closed at the Run 163 verifier.
* No KMS/HSM implementation.
* No validator-set rotation.
* No autonomous apply, no automatic apply on receipt, no peer-majority
  authority.
* No new proof / marker / sequence-file / trust-bundle core /
  peer-candidate envelope schema change.
* Does not weaken Runs 070, 130–172.
* Does NOT claim full C4 closure.
* Does NOT claim C5 closure.

## What Run 173 changes

### Source

* New library shim
  `qbind_node::pqc_governance_proof_surface::preflight_v2_validation_only_marker_check_with_governance_proof_load`
  — the single integration shim for validation-only callers. It
  delegates to the existing Run 169 mutating shim
  `preflight_v2_marker_decision_with_governance_proof_load` (same
  anti-rollback / lifecycle / governance gate composition); validation-
  only callers MUST drop the returned decision rather than persisting.
* `crates/qbind-node/src/main.rs` —
  `preflight_run_132_validation_only_v2_marker_check` now calls the
  new shim with the policy resolved by
  `governance_proof_policy_from_cli_or_env(ctx_data.governance_proof_required_selector)`
  and the typed `GovernanceProofLoadStatus` already carried by
  `Run105ReloadCheckContextData::governance_proof_load`. Both
  validation-only call sites for that function (the
  `--p2p-trust-bundle-reload-check` path and the local
  `--p2p-trust-bundle-peer-candidate-check` path) consume the same
  policy by construction.

### Tests

* `crates/qbind-node/tests/run_173_validation_only_governance_required_policy_tests.rs`
  — 25 focused source/test cases covering the A1–A6 acceptance
  matrix and R1–R18 rejection matrix from `task/RUN_173_TASK.txt`,
  plus an explicit source-reachability test.

## Acceptance matrix (A1–A6)

| ID | Surface                         | Selector          | Sidecar                         | Outcome |
| -- | ------------------------------- | ----------------- | ------------------------------- | ------- |
| A1 | reload-check                    | default (none)    | old, no proof                   | ✅ accepted; no marker / no sequence write |
| A2 | reload-check                    | CLI Required      | proof-carrying Rotate           | ✅ accepted; proof context Available; verifier accepts; no writes |
| A3 | reload-check                    | env Required      | proof-carrying Rotate           | ✅ accepted; same as A2 via env selector |
| A4 | local peer-candidate-check      | CLI Required      | proof-carrying Rotate           | ✅ accepted; validation-only; no mutation |
| A5 | live inbound `0x05`             | CLI Required      | proof-carrying Rotate (boundary) | ✅ shim accepts; **boundary documented below** |
| A6 | reload-check                    | env unset / false | (n/a)                           | ✅ NotRequired preserved |

### Live inbound `0x05` boundary (A5)

The current live inbound `0x05` peer-candidate validation surface
(`crates/qbind-node/src/pqc_peer_candidate_wire.rs`) calls
`qbind_node::pqc_authority_marker_acceptance::verify_marker_for_validation_only_v2`
directly. The on-the-wire peer-candidate envelope schema does **not**
carry a `governance_authority_proof` sibling field today, so a live
`0x05` peer-candidate cannot yet supply a typed
`GovernanceProofLoadStatus`. Run 173 documents this exact boundary
and defers the wire-envelope plumbing to a later run (the
peer-candidate envelope schema change is explicitly out of scope per
`task/RUN_173_TASK.txt`). The Run 173 shim itself is surface-agnostic
and accepts a valid `Available` proof for any caller; the only
remaining gap is the wire surface that does not yet thread proof
context through.

## Rejection matrix (R1–R18)

| ID | Selector | Proof Status                                             | Expected Error |
| -- | -------- | -------------------------------------------------------- | -- |
| R1 | CLI Req  | Absent (no proof)                                        | `GovernanceAuthorityRequiredButMissing` |
| R2 | env Req  | Absent (no proof)                                        | `GovernanceAuthorityRequiredButMissing` |
| R3 | Req      | Malformed                                                | `GovernanceAuthorityRequiredButMissing` (Run 167 mapping) |
| R4 | Req      | Available, invalid issuer signature                      | `GovernanceAuthorityRejected(InvalidIssuerSignature)` |
| R5 | Req      | Available, wrong environment                             | `GovernanceAuthorityRejected(...)` |
| R6 | Req      | Available, wrong chain                                   | `GovernanceAuthorityRejected(...)` |
| R7 | Req      | Available, wrong genesis                                 | `GovernanceAuthorityRejected(...)` |
| R8 | Req      | Available, wrong authority root                          | `GovernanceAuthorityRejected(...)` |
| R9 | Req      | Available, wrong lifecycle action                        | `GovernanceAuthorityRejected(...)` |
| R10 | Req      | Available, wrong candidate digest                        | `GovernanceAuthorityRejected(...)` |
| R11 | Req      | Available, wrong authority-domain sequence               | `GovernanceAuthorityRejected(...)` |
| R12 | Req      | Available, OnChainGovernance class                       | `GovernanceAuthorityRejected(UnsupportedOnChainGovernance)` |
| R13 | Req      | Local operator config alone (cannot stand in)            | shim has no operator-config carrier; Absent ⇒ RequiredButMissing |
| R14 | Req      | Peer-majority alone (cannot stand in)                    | shim has no peer-majority carrier; Absent ⇒ RequiredButMissing |
| R15 | Req      | Reject path                                              | no marker write; no sequence write |
| R16 | Req      | Reject path                                              | no live trust swap; no session eviction; no Run 070 call |
| R17 | (any)    | unrelated CLI flags                                      | selector is selector-input-driven only; cannot be flipped by accident |
| R18 | Req      | Available, valid (validation-only accepts)               | MainNet peer-driven apply remains refused upstream |

## Source-reachability evidence

The `source_reachability_validation_only_shim_reaches_governance_gate`
test pins the call chain at the source level:

1. `governance_proof_policy_from_cli_or_env(false)` →
   `GovernanceProofPolicy::NotRequired`. The validation-only shim
   accepts a no-proof sidecar — the gate observes `NotRequiredNoProof`.
2. `governance_proof_policy_from_cli_or_env(true)` →
   `GovernanceProofPolicy::RequiredForLifecycleSensitive`. The
   validation-only shim rejects a no-proof sidecar with
   `GovernanceAuthorityRequiredButMissing` — the gate observes
   `RequiredButMissing`.
3. `governance_proof_policy_from_cli_or_env(true)` +
   `GovernanceProofLoadStatus::Available(valid)` — the validation-only
   shim accepts; the Run 167 loader output reaches the Run 165 gate
   in the `Available` context.

The `--p2p-trust-bundle-reload-check` path captures the selector
into `Run105ReloadCheckContextData::governance_proof_required_selector`
at context-build time and resolves the active policy at preflight
time via `governance_proof_policy_from_cli_or_env`. The shared
validation-only helper `preflight_run_132_validation_only_v2_marker_check`
is the single library entry point both validation-only call sites
delegate to.

## Backwards compatibility

* Default selector (flag unset and env unset/falsey) →
  `GovernanceProofPolicy::NotRequired`. Old no-proof v2 sidecars
  remain bit-for-bit accepted on every validation-only surface.
* Run 167 carrier tests, Run 169 loader-surface integration tests,
  Run 171 selector tests, Run 172 release-binary mutating-surface
  evidence — all unchanged.
* `verify_marker_for_validation_only_v2` is unchanged at its
  signature; existing Run 142 / Run 154 / Run 157 callers see no
  change. Run 173 wires the governance gate **above** the existing
  validation-only marker check by routing through the new shim.

## Validation commands

```text
cargo build -p qbind-node --lib
cargo test  -p qbind-node --test run_173_validation_only_governance_required_policy_tests
cargo test  -p qbind-node --test run_171_governance_required_policy_selector_tests
cargo test  -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests
cargo test  -p qbind-node --test run_167_governance_proof_carrier_tests
cargo test  -p qbind-node --test run_165_governance_marker_integration_tests
cargo test  -p qbind-node --test run_163_governance_authority_verifier_tests
cargo test  -p qbind-node --test run_161_lifecycle_marker_integration_tests
cargo test  -p qbind-node --test run_159_authority_signing_key_lifecycle_tests
cargo test  -p qbind-node --test run_157_unified_testnet_fixture_universe_tests
cargo test  -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests
cargo test  -p qbind-node --test run_150_peer_driven_apply_drain_tests
cargo test  -p qbind-node --test run_148_peer_driven_apply_devnet_tests
cargo test  -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests
cargo test  -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test  -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test  -p qbind-node --lib pqc_authority
```

All commands pass on the Run 173 commit.

## Standing invariants (unchanged)

* MainNet peer-driven apply remains refused.
* `OnChainGovernance` remains unsupported / fail-closed.
* Governance execution remains unimplemented.
* KMS/HSM remains unimplemented.
* Validator-set rotation remains open.
* Full C4 remains open.
* C5 remains open.
* Release-binary validation-only Required-policy evidence is
  deferred to Run 174.
