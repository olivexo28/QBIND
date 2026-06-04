# QBIND DevNet evidence — Run 188

**Title.** Source/test KMS-HSM custody boundary for governance and
bundle-signing authority.

**Status.** PASS (source/test, partial-positive). Run 188 introduces a
typed authority-custody boundary that cleanly separates DevNet/TestNet
fixture and local-operator key material (evidence-only) from future
real KMS / HSM / remote-signer custody (declared unavailable and
fail-closed). The new boundary is purely additive over Runs 050–187:
it does not change any existing wire, schema, marker, sequence,
trust-bundle core, or governance-proof format, and it does not wire
custody validation into any mutating apply surface. The default
custody policy on every surface is `Disabled`, and every production
custody class (`RemoteSigner`, `Kms`, `Hsm`) fails closed at the
typed validator boundary because Run 188 deliberately ships no real
backend. Fixture / local-operator custody is reachable only under
the explicit `FixtureOnly` / `DevnetLocalAllowed` /
`TestnetLocalAllowed` policies and short-circuits to typed
`FixtureCustodyRejectedForMainNet` / `LocalCustodyRejectedForMainNet`
whenever the trust domain is MainNet — so a fixture / local-operator
key can never masquerade as MainNet production custody. Both
`ProductionCustodyRequired` and `MainnetProductionCustodyRequired`
policies always return a typed `ProductionCustodyUnavailable` /
`MainNetProductionCustodyUnavailable` (or, for production-class
placeholders, the more specific `KmsUnavailable` /
`HsmUnavailable` / `RemoteSignerUnavailable`) regardless of
attestation contents. Real KMS, HSM, cloud KMS, PKCS#11, remote
signer, on-chain governance proof verification, governance
execution, validator-set rotation, bridge / light-client integration,
autonomous apply, apply-on-receipt, peer-majority authority, and
the release-binary boundary for the custody kind itself all remain
unimplemented. MainNet peer-driven apply remains refused (Run 147
FATAL invariant). Full **C4** and **C5** remain **OPEN** invariants
tracked by the contradiction ledger. Release-binary custody-boundary
evidence is **deferred to Run 189**.

**Driving spec.** `task/RUN_188_TASK.txt`.

## 1. Strict scope

Run 188 is **source/test only**. It adds **only**:

* A new module
  [`pqc_authority_custody`](
    ../../crates/qbind-node/src/pqc_authority_custody.rs)
  defining:
  * `AuthorityCustodyClass` —
    `FixtureLocalKey` / `LocalOperatorKey` / `RemoteSigner` /
    `Kms` / `Hsm` / `Unknown`;
  * `AuthorityCustodyPolicy` —
    `Disabled` (default) / `FixtureOnly` / `DevnetLocalAllowed` /
    `TestnetLocalAllowed` / `ProductionCustodyRequired` /
    `MainnetProductionCustodyRequired`;
  * `AuthorityCustodyAttestation` — typed attestation binding to
    environment, chain id, genesis hash, authority-root fingerprint,
    bundle-signing-key fingerprint, governance authority class,
    lifecycle action, candidate digest, authority-domain sequence,
    custody class, custody key id, custody attestation digest, and
    optional freshness / expiry window;
  * `AuthorityCustodyValidationOutcome` — the typed surface of every
    custody decision (accept-fixture, accept-local-operator,
    production-custody-unavailable, kms / hsm / remote-signer
    unavailable, unknown-class-rejected, wrong-environment / chain /
    genesis / authority-root / signing-key-fingerprint /
    candidate-digest / authority-domain-sequence / lifecycle-action,
    custody-attestation missing / malformed / expired,
    custody-key-id mismatch, unsupported-custody-suite,
    fixture-rejected-for-MainNet, local-rejected-for-MainNet,
    MainNet-production-custody-unavailable, and the typed
    `PolicyRefusesCustodyClass` policy refusal);
  * the pure validator
    `validate_authority_custody_attestation`;
  * the typed combined helper
    `validate_lifecycle_governance_and_custody`, which calls Run 159
    `validate_v2_lifecycle_transition` first, then routes the
    accepted lifecycle through the Run 188 custody validator under
    the active policy and returns a typed
    `LifecycleGovernanceCustodyOutcome`
    (`Accepted` / `LifecycleRejected` / `CustodyRejected` /
    `MainNetPeerDrivenApplyRefused`);
  * three explicit grep-verifiable named helpers —
    `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
    `peer_majority_cannot_satisfy_custody`,
    `local_operator_config_alone_cannot_satisfy_mainnet_production_custody`
    — that encode, by symbol, three rules that Run 188 surfaces at
    the typed boundary regardless of any attestation contents.
* Source/test integration tests at
  [`crates/qbind-node/tests/run_188_authority_custody_boundary_tests.rs`](
    ../../crates/qbind-node/tests/run_188_authority_custody_boundary_tests.rs)
  covering the full A1–A8 / R1–R29 matrix from `task/RUN_188_TASK.txt`
  plus extras for fixture-vs-production custody separation,
  MainNet-fixture / MainNet-local masquerade refusal,
  KMS/HSM/remote-signer placeholder fail-closed under every policy,
  helper purity, deterministic re-evaluation, and short-circuit of
  custody under a rejected lifecycle (48 tests, all passing).

Run 188 adds **no**:

* Real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
* Real on-chain governance proof verifier.
* MainNet peer-driven apply enablement.
* Governance execution engine.
* Validator-set rotation.
* Autonomous apply or apply-on-receipt.
* Peer-majority authority.
* Marker, sequence-file, trust-bundle, wire, or metric drift.
* Selector / CLI flag / env var (Run 188 ships no operator-visible
  selector — the policy is supplied by the calling surface).

## 2. Acceptance summary

Acceptance scenarios A1–A8 and rejection scenarios R1–R29 are
captured in
[`crates/qbind-node/tests/run_188_authority_custody_boundary_tests.rs`](
  ../../crates/qbind-node/tests/run_188_authority_custody_boundary_tests.rs).

| Scenario | Tested by |
|----------|-----------|
| A1 DevNet fixture custody under `FixtureOnly` | `a1_devnet_fixture_custody_accepted_under_fixture_only_policy` |
| A2 TestNet fixture custody under `FixtureOnly` | `a2_testnet_fixture_custody_accepted_under_fixture_only_policy` |
| A3 DevNet local-operator under `DevnetLocalAllowed` | `a3_devnet_local_operator_accepted_under_devnet_local_policy` |
| A4 TestNet local-operator under `TestnetLocalAllowed` | `a4_testnet_local_operator_accepted_under_testnet_local_policy` |
| A5 GenesisBound / EmergencyCouncil unchanged when custody not required | `a5_genesisbound_and_emergencycouncil_paths_unchanged_when_custody_not_required` + `run_186_default_verifier_kind_remains_disabled_under_run_188` |
| A6 Combined lifecycle + governance + fixture custody DevNet | `a6_combined_lifecycle_governance_fixture_custody_accepted_devnet` |
| A7 Combined lifecycle + governance + local custody TestNet | `a7_combined_lifecycle_governance_local_custody_accepted_testnet` |
| A8 Production-custody boundary returns typed unavailable for KMS/HSM/RemoteSigner | `a8_production_custody_boundary_returns_typed_unavailable_for_each_placeholder` |
| R1 Fixture rejected under production custody policy | `r1_fixture_custody_rejected_under_production_custody_policy` |
| R2 Local-operator rejected under production custody policy | `r2_local_operator_custody_rejected_under_production_custody_policy` |
| R3 Fixture rejected for MainNet | `r3_fixture_custody_rejected_for_mainnet` |
| R4 Local-operator rejected for MainNet | `r4_local_operator_custody_rejected_for_mainnet` |
| R5 KMS placeholder rejected as unavailable | `r5_kms_placeholder_rejected_as_unavailable` + `devnet_local_policy_refuses_kms_placeholder_with_typed_unavailable` |
| R6 HSM placeholder rejected as unavailable | `r6_hsm_placeholder_rejected_as_unavailable` |
| R7 Remote signer placeholder rejected as unavailable | `r7_remote_signer_placeholder_rejected_as_unavailable` |
| R8 Unknown custody class rejected | `r8_unknown_custody_class_rejected` |
| R9 Wrong environment rejected | `r9_wrong_environment_rejected` |
| R10 Wrong chain rejected | `r10_wrong_chain_rejected` |
| R11 Wrong genesis rejected | `r11_wrong_genesis_rejected` |
| R12 Wrong authority root rejected | `r12_wrong_authority_root_rejected` |
| R13 Wrong signing-key fingerprint rejected | `r13_wrong_signing_key_fingerprint_rejected` |
| R14 Wrong candidate digest rejected | `r14_wrong_candidate_digest_rejected` |
| R15 Wrong authority-domain sequence rejected | `r15_wrong_authority_domain_sequence_rejected` |
| R16 Wrong lifecycle action rejected | `r16_wrong_lifecycle_action_rejected` |
| R17 Missing custody attestation rejected | `r17_missing_custody_attestation_rejected` |
| R18 Malformed custody attestation rejected | `r18_malformed_custody_attestation_rejected` + `r18b_malformed_when_only_one_of_freshness_expiry_set` |
| R19 Expired custody attestation rejected | `r19_expired_custody_attestation_rejected` |
| R20 Custody key id mismatch rejected | `r20_custody_key_id_mismatch_rejected` |
| R21 Unsupported custody suite rejected | `r21_unsupported_custody_suite_rejected` |
| R22 Custody valid but governance proof invalid | `r22_custody_valid_but_governance_proof_invalid_rejected` |
| R23 Governance proof valid but custody invalid | `r23_governance_proof_valid_but_custody_invalid_rejected` |
| R24 Lifecycle valid + governance valid + custody placeholder unavailable | `r24_lifecycle_valid_governance_valid_custody_placeholder_unavailable_rejected` |
| R25 MainNet peer-driven apply remains refused even if custody claims KMS | `r25_mainnet_peer_driven_apply_remains_refused_even_if_custody_claims_kms` |
| R26 Local operator config alone cannot satisfy MainNet production custody | `r26_local_operator_config_alone_cannot_satisfy_mainnet_production_custody` |
| R27 Peer majority / gossip count cannot satisfy custody | `r27_peer_majority_or_gossip_count_cannot_satisfy_custody` |
| R28 Validation-only rejection remains non-mutating | `r28_validation_only_rejection_remains_non_mutating` |
| R29 Mutating preflight rejection produces no Run 070 / live-trust / sequence / marker mutation | `r29_mutating_preflight_rejection_produces_no_run_070_call_and_no_persistence` |

Validation commands run at minimum:

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_188_authority_custody_boundary_tests` — PASS (48/48).
* `cargo test -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests` — PASS (44/44).
* `cargo test -p qbind-node --test run_184_onchain_governance_payload_carrying_tests` — PASS.
* `cargo test -p qbind-node --test run_182_onchain_governance_production_callsite_wiring_tests` — PASS.
* `cargo test -p qbind-node --test run_180_onchain_governance_marker_integration_tests` — PASS.
* `cargo test -p qbind-node --test run_178_onchain_governance_proof_tests` — PASS.
* `cargo test -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests` — PASS.
* `cargo test -p qbind-node --test run_173_validation_only_governance_required_policy_tests` — PASS.
* `cargo test -p qbind-node --test run_171_governance_required_policy_selector_tests` — PASS.
* `cargo test -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests` — PASS.
* `cargo test -p qbind-node --test run_167_governance_proof_carrier_tests` — PASS.
* `cargo test -p qbind-node --test run_165_governance_marker_integration_tests` — PASS.
* `cargo test -p qbind-node --test run_163_governance_authority_verifier_tests` — PASS.
* `cargo test -p qbind-node --test run_161_lifecycle_marker_integration_tests` — PASS.
* `cargo test -p qbind-node --test run_159_authority_signing_key_lifecycle_tests` — PASS.
* `cargo test -p qbind-node --test run_157_unified_testnet_fixture_universe_tests` — PASS.
* `cargo test -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests` — PASS.
* `cargo test -p qbind-node --test run_150_peer_driven_apply_drain_tests` — PASS.
* `cargo test -p qbind-node --test run_148_peer_driven_apply_devnet_tests` — PASS.
* `cargo test -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` — PASS.
* `cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` — PASS.
* `cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests` — PASS.
* `cargo test -p qbind-node --lib pqc_authority` — PASS (148/148).

## 3. Honest limitations

* **No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend
  is implemented.** Every `RemoteSigner`, `Kms`, and `Hsm` custody
  class fails closed at the typed Run 188 validator with a typed
  `RemoteSignerUnavailable` / `KmsUnavailable` / `HsmUnavailable`
  outcome, regardless of attestation contents or active policy. A
  future run that lands a real backend MUST extend the matching
  validator branch and cannot silently elevate any other variant.
* **Fixture / local-operator custody remains DevNet/TestNet
  evidence-only.** It is reachable only under the explicit
  `FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed`
  policies, and is rejected by symbol whenever the trust-domain
  environment is MainNet (`FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet`).
* **Fixture / local-operator custody cannot satisfy MainNet
  production custody.** The MainNet rejection layer is intentionally
  ahead of the policy gate so a misconfigured policy can never
  silently elevate fixture / local-operator material to MainNet
  production custody.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** regardless of custody outcome. The grep-verifiable
  helper
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`
  encodes the rule at the typed Run 188 boundary.
* **Governance execution remains unimplemented.** Run 188 does not
  call the Run 163 / 178 / 186 governance verifier itself; the
  composition helper takes the already-validated governance class
  from the calling surface. Real governance execution remains a
  separate future-run scope.
* **Real on-chain governance proof verification remains
  unimplemented.** Run 186's `OnChainGovernanceVerifierKind::Disabled`
  default is preserved on every surface; Run 188 adds no new
  proof-verifier path.
* **Validator-set rotation remains open.**
* **No release-binary custody-boundary evidence is captured by
  Run 188.** Release-binary custody-boundary evidence is **deferred
  to Run 189**.
* **Full C4 is NOT claimed by Run 188; C5 remains OPEN.**