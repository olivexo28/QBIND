# QBIND DevNet evidence — Run 178

**Title.** Source/test-only typed `OnChainGovernance` proof format and
fail-closed verifier boundary.

**Status.** PASS — source/test evidence captured (see test target
`crates/qbind-node/tests/run_178_onchain_governance_proof_tests.rs`,
46 / 46 tests passing). No release-binary evidence is captured in this
run.

**Driving spec.** `task/RUN_178_TASK.txt`.

## 1. Strict scope

Run 178 defines and implements a **typed, source/test-only**
`OnChainGovernance` proof format and a fail-closed pure verifier
boundary, so that `GovernanceAuthorityClass::OnChainGovernance` no
longer has only a generic unsupported outcome at source/test level.

Run 178 does **not**:

* enable MainNet peer-driven apply (Run 147 FATAL invariant continues to
  hold; the predicate
  `mainnet_peer_driven_apply_remains_refused` returns `true` for
  `Mainnet` regardless of any DevNet/TestNet fixture acceptance);
* implement a governance execution engine;
* implement real on-chain governance proof verification for MainNet —
  the Run 178 fixture suite
  (`ONCHAIN_GOVERNANCE_PROOF_SUITE_FIXTURE_MOCK_V1 = 0xA1`) is a
  deterministic mock commitment over the bound governance / lifecycle
  / sequence fields. The reserved suite id
  `ONCHAIN_GOVERNANCE_PROOF_SUITE_RESERVED_PRODUCTION = 0xA2` is **not**
  implemented and is rejected as `UnsupportedGovernanceProofSuite`;
* implement KMS/HSM custody;
* implement validator-set rotation;
* implement bridge / light-client integration;
* enable autonomous apply or apply-on-receipt;
* accept peer-majority / gossip count as an `OnChainGovernance` proof
  (the wire format intentionally cannot encode a peer-majority claim;
  any synthetic peer-gossip "proof" fails as `InvalidGovernanceProof`
  because its bytes will not equal the canonical fixture commitment);
* accept local operator config alone as an `OnChainGovernance` proof
  (under the default `OnChainGovernanceProofPolicy::Disabled` every
  proof is refused as `UnsupportedProductionOnChainGovernance`);
* change the v2 marker, sequence-file, or trust-bundle core schema.
  The wire surface is **additive only**: a new optional
  `OnChainGovernanceProofWire` carrier with
  `ONCHAIN_GOVERNANCE_PROOF_WIRE_SCHEMA_VERSION = 1`. Pre-Run-178
  Run 167–177 sidecars without this sibling continue to parse exactly
  as before.

Release-binary `OnChainGovernance` proof evidence is **deferred to
Run 179**. Full Whitepaper contradiction C4 and C5 closure remain
**open**.

## 2. Source delta

* `crates/qbind-node/src/pqc_onchain_governance_proof.rs` — **new**
  module. Defines:

  * `OnChainGovernanceProof` typed proof object with every binding
    required by the task: environment, chain_id, genesis_hash,
    authority_root_fingerprint (+ suite id), governance_domain_id,
    governance_epoch, proposal_id, proposal_digest, proposal_outcome,
    quorum, threshold, lifecycle_action, active /
    new / revoked bundle-signing key fingerprints,
    authority_domain_sequence, candidate_v2_digest, freshness window,
    unique_decision_id (replay nonce), proof_suite_id, proof_bytes;
  * `OnChainGovernanceProofPolicy::{Disabled, AllowFixtureSourceTest}`
    (default `Disabled`);
  * `OnChainGovernanceProofVerificationOutcome` enum with typed
    variants
    `AcceptedOnChainGovernanceFixture`,
    `UnsupportedProductionOnChainGovernance`,
    `MainNetProductionProofUnavailable`,
    `WrongEnvironment`, `WrongChain`, `WrongGenesis`,
    `WrongAuthorityRoot`, `WrongGovernanceDomain`,
    `WrongGovernanceEpoch`, `WrongProposalDigest`,
    `WrongProposalOutcome`, `WrongLifecycleAction`,
    `WrongCandidateDigest`, `WrongAuthoritySequence`,
    `ExpiredGovernanceProof`, `ReplayRejected`, `QuorumNotMet`,
    `ThresholdNotMet`, `UnsupportedGovernanceProofSuite`,
    `InvalidGovernanceProof`, `MalformedOnChainProof`,
    `LocalOperatorConfigOnlyRejected`, `PeerMajorityProofRejected`;
  * `verify_onchain_governance_proof` — pure verifier (no I/O,
    non-mutating, replay set is read-only);
  * `validate_lifecycle_with_onchain_governance_proof` — combined
    Run 159 lifecycle + Run 178 governance helper, also pure;
  * `OnChainGovernanceProofWire` — additive wire-safe carrier (serde
    derived, hex-encoded `proof_bytes`) with
    `OnChainGovernanceProofWireParseError` failing closed on unknown
    schema version, empty required fields, and empty proof bytes;
  * `mainnet_peer_driven_apply_remains_refused` — typed assertion
    helper used in tests to demonstrate MainNet refusal cannot be
    weakened by a DevNet/TestNet fixture acceptance.

* `crates/qbind-node/src/lib.rs` — module wired in (one-line `pub mod`
  with explanatory header).

* `crates/qbind-node/tests/run_178_onchain_governance_proof_tests.rs` —
  **new** test target. 46 tests covering A1–A7 + R1–R25 + proof-carrier
  parse compatibility + no-I/O guarantee + combined lifecycle purity +
  marker-decision source/test path + MainNet refusal helper.

The Run 163 `pqc_governance_authority.rs` source is **not** modified;
its existing `OnChainGovernance` class still returns
`UnsupportedOnChainGovernance` on the Run 163 verifier surface (R7
regression). Run 178 is parallel to that path.

The Run 167 `pqc_governance_proof_wire.rs` source is **not** modified;
old `GovernanceAuthorityProofWire` JSON sidecars are bit-for-bit
backwards-compatible (R24 regression).

## 3. Required scenarios — accepted

| ID | Scenario | Test |
|----|----------|------|
| A1 | DevNet fixture `OnChainGovernance` Rotate accepted | `a1_devnet_fixture_rotate_accepted` |
| A2 | TestNet fixture `OnChainGovernance` Rotate accepted | `a2_testnet_fixture_rotate_accepted` |
| A3 | DevNet fixture `OnChainGovernance` Revoke accepted | `a3_devnet_fixture_revoke_accepted` |
| A4 | TestNet fixture `OnChainGovernance` EmergencyRevoke accepted | `a4_testnet_fixture_emergency_revoke_accepted` |
| A5 | Combined lifecycle + governance accepted via `validate_lifecycle_with_onchain_governance_proof` | `a5_combined_lifecycle_with_onchain_governance_proof_accepted` |
| A6 | Proof-carrying sidecar wire round-trip + accept at source/test marker-decision level, no mutation | `a6_proof_carrying_sidecar_roundtrip_accepted_no_mutation` |
| A7 | Existing Run 163 GenesisBound + EmergencyCouncil + `UnsupportedOnChainGovernance` behavior unchanged | `a7_existing_genesis_bound_and_emergency_council_unchanged` |

## 4. Required scenarios — rejected

| ID | Scenario | Test |
|----|----------|------|
| R1  | Wrong environment | `r1_wrong_environment_rejected` |
| R2  | Wrong chain | `r2_wrong_chain_rejected` |
| R3  | Wrong genesis | `r3_wrong_genesis_rejected` |
| R4  | Wrong authority root | `r4_wrong_authority_root_rejected` |
| R5  | Wrong governance domain | `r5_wrong_governance_domain_rejected` |
| R6  | Wrong proposal digest / proposal id | `r6_wrong_proposal_digest_rejected` / `r6b_wrong_proposal_id_rejected_as_proposal_digest_mismatch` |
| R7  | Wrong proposal outcome | `r7_wrong_proposal_outcome_rejected` |
| R8  | Wrong lifecycle action | `r8_wrong_lifecycle_action_rejected` |
| R9  | Wrong candidate digest | `r9_wrong_candidate_digest_rejected` |
| R10 | Wrong authority-domain sequence | `r10_wrong_authority_sequence_rejected` |
| R11 | Expired governance proof (also too-early) | `r11_expired_governance_proof_rejected` / `r11b_too_early_governance_proof_rejected_as_expired_window` |
| R12 | Stale lower-sequence replay + duplicate `unique_decision_id` replay | `r12_stale_lower_sequence_replay_rejected` / `r12b_replayed_unique_decision_id_rejected` |
| R13 | Quorum not met | `r13_quorum_not_met_rejected` |
| R14 | Threshold not met | `r14_threshold_not_met_rejected` |
| R15 | Invalid governance proof bytes (commitment mismatch) | `r15_invalid_proof_bytes_rejected` |
| R16 | Unsupported governance proof suite (reserved production suite + arbitrary unknown id) | `r16_unsupported_proof_suite_rejected` / `r16b_unknown_proof_suite_rejected` |
| R17 | Malformed proof (empty field, empty proof bytes, malformed freshness window, non-PQC authority root suite) | `r17_*` |
| R18 | MainNet `OnChainGovernance` proof refused as `MainNetProductionProofUnavailable` | `r18_mainnet_proof_unavailable` |
| R19 | Local operator config alone refused under default `Disabled` policy | `r19_local_operator_config_alone_rejected_via_disabled_policy` |
| R20 | Peer-majority / gossip count refused via mock commitment mismatch | `r20_peer_majority_gossip_rejected_via_invalid_proof_bytes` |
| R21 | Proof valid but lifecycle invalid (rollback) | `r21_proof_valid_but_lifecycle_invalid_rejected` |
| R22 | Lifecycle valid but proof invalid (wrong proposal digest) | `r22_lifecycle_valid_but_proof_invalid_rejected` |
| R23 | DevNet fixture acceptance does NOT enable MainNet peer-driven apply | `r23_mainnet_peer_driven_apply_remains_refused_even_with_valid_devnet_proof` |
| R24 | Old Run 167 carriers without an `OnChainGovernance` sibling parse unchanged + Run 178 wire round-trips independently | `r24_old_run167_carrier_without_onchain_sibling_still_parses` / `r24b_run178_onchain_wire_roundtrips_independently` |
| R25 | Unsupported future schema version + empty required field + empty proof bytes all fail-closed at the wire boundary | `r25_*` |

## 5. Validation commands

* `cargo build -p qbind-node --lib` — clean.
* `cargo test -p qbind-node --test run_178_onchain_governance_proof_tests`
  → **46 / 46 ok**.
* `cargo test -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests`
  → 37 / 37 ok.
* `cargo test -p qbind-node --test run_173_validation_only_governance_required_policy_tests`
  → 25 / 25 ok.
* `cargo test -p qbind-node --test run_171_governance_required_policy_selector_tests`
  → 35 / 35 ok.
* `cargo test -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests`
  → 39 / 39 ok.
* `cargo test -p qbind-node --test run_167_governance_proof_carrier_tests`
  → 47 / 47 ok.
* `cargo test -p qbind-node --test run_165_governance_marker_integration_tests`
  → 31 / 31 ok.
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests`
  → 32 / 32 ok.
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests`
  → 29 / 29 ok.
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests`
  → 29 / 29 ok.
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests`
  → 16 / 16 ok.
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests`
  → 23 / 23 ok.
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests`
  → 19 / 19 ok.
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests`
  → 20 / 20 ok.
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests`
  → 16 / 16 ok.
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests`
  → 5 / 5 ok.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests`
  → 11 / 11 ok.
* `cargo test -p qbind-node --lib pqc_authority` → 148 / 148 ok.
* `cargo test -p qbind-node --lib` → 1282 / 1282 ok.

## 6. Acceptance — checked against task

1. `OnChainGovernance` proof material is representable at source/test
   level (typed `OnChainGovernanceProof`). ✓
2. Fixture DevNet/TestNet `OnChainGovernance` proofs can be accepted by
   a pure verifier (A1–A4). ✓
3. Wrong-domain, wrong-proposal, wrong-digest, expired, replayed,
   quorum/threshold failure, invalid-proof, malformed-proof, and
   unsupported-suite cases fail closed (R1–R17, R25). ✓
4. Existing GenesisBound and EmergencyCouncil governance proof behavior
   remains unchanged (A7, Run 163 regression suite). ✓
5. Proof-carrier compatibility remains intact (R24 — Run 167 carriers
   without the new sibling still parse; Run 178 wire round-trips). ✓
6. Combined lifecycle + `OnChainGovernance` decisions remain pure and
   non-mutating (`combined_decision_pure_and_non_mutating`). ✓
7. MainNet peer-driven apply remains refused even with a valid
   `OnChainGovernance` fixture proof (R18, R23). ✓
8. Docs defer release-binary `OnChainGovernance` evidence to Run 179
   (this document, plus
   `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`,
   `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`,
   `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`,
   `docs/whitepaper/contradiction.md`). ✓
9. No full C4 or C5 closure is claimed. ✓

## 7. Forward gaps explicitly NOT closed by Run 178

* Real on-chain governance proof verification for MainNet — deferred.
* Governance execution engine — deferred.
* KMS/HSM custody — deferred.
* Validator-set rotation — deferred.
* Release-binary `OnChainGovernance` proof evidence — deferred to
  Run 179.
* Bridge / light-client integration — deferred.
* Whitepaper C4 closure — open.
* Whitepaper C5 closure — open.
