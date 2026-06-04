# QBIND DevNet evidence — Run 190

**Title.** Source/test authority-custody metadata carrying and
production call-site wiring.

**Status.** PASS (source/test, partial-positive). Run 190 makes typed
authority-custody attestation metadata reach production payload /
context paths and the production v2 marker-decision preflight
composition, while preserving every prior invariant. The carrier is
purely additive: an optional `authority_custody_attestation` JSON
sibling on the v2 ratification sidecar, parsed before the strict v2
parse and converted into the Run 188 `AuthorityCustodyAttestation`.
Old no-custody payloads continue to parse byte-for-byte and run under
the default `AuthorityCustodyPolicy::Disabled`. Malformed custody
siblings fail closed at the typed payload boundary before any mutation
is considered. KMS / HSM / RemoteSigner production placeholders reach
the Run 188 validator and return the typed
`KmsUnavailable` / `HsmUnavailable` / `RemoteSignerUnavailable`
outcomes — Run 190 ships **no real KMS, HSM, cloud KMS, PKCS#11, or
remote-signer backend**. Fixture and local-operator custody remain
DevNet/TestNet evidence-only and short-circuit to typed
`FixtureCustodyRejectedForMainNet` /
`LocalCustodyRejectedForMainNet` whenever the trust-domain
environment is MainNet, so a misconfigured fixture / local policy can
never elevate fixture or local material to MainNet production
custody. MainNet peer-driven apply remains the Run 147 / 148 / 152
FATAL refusal regardless of any custody attestation contents,
including KMS / HSM placeholders. Real on-chain governance proof
verification, governance execution, validator-set rotation, bridge /
light-client integration, autonomous apply, apply-on-receipt, and
peer-majority authority all remain unimplemented. Full **C4** and
**C5** remain **OPEN** invariants tracked by the contradiction
ledger. Release-binary custody-metadata evidence is **deferred to
Run 191**.

**Driving spec.** `task/RUN_190_TASK.txt`.

## 1. Strict scope

Run 190 is **source/test only**. It adds **only**:

* A new module
  [`pqc_authority_custody_payload_carrying`](
    ../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
  defining:
  * `AuthorityCustodyClassWire` and `GovernanceAuthorityClassWire` —
    serde-tagged kebab-case mirrors of the Run 188 / Run 163 internal
    enums (the internal enums deliberately do not derive serde);
  * `AuthorityCustodyAttestationWire` — typed wire form bound to
    `schema_version = 1`, with explicit `to_attestation()` /
    `from_attestation()` conversion to the Run 188
    `AuthorityCustodyAttestation`;
  * `AuthorityCustodyPayloadParseError` — typed payload-level errors
    (`InvalidJson`, `EmptyRequiredField`,
    `UnsupportedSchemaVersion`, `InvalidEnumVariant`, …);
  * `AuthorityCustodyLoadStatus::{Absent, Available, Malformed}` —
    the typed sibling load status returned to every call site;
  * `extract_authority_custody_attestation_sibling` — the Run 167 /
    Run 184 sibling-extraction pattern, applied to the Run 167
    governance proof + Run 184 OnChainGovernance carriers; it removes
    the `authority_custody_attestation` field from the JSON object
    *before* the strict v2 sidecar is re-parsed, so a malformed
    custody sibling never poisons v2 parsing and does not affect the
    Run 167 / Run 184 sibling outcomes;
  * `load_v2_sidecar_with_governance_and_custody` — the combined
    Run 167 + Run 184 + Run 190 sidecar loader, returning the typed
    `BundleSigningRatificationV2`, the Run 167 governance-proof load
    status, the Run 184 OnChainGovernance load status, and the
    Run 190 custody load status, each independently typed;
  * `AuthorityCustodyCallsiteContext` — the production callsite
    context that pairs a typed (or absent / malformed) custody
    attestation with the active `AuthorityCustodyPolicy`, the
    expected lifecycle / governance-class / candidate-digest /
    authority-domain-sequence / custody-key-id, the trust-domain
    environment, and `now_unix`;
  * seven per-surface routing helpers — one each for reload-check,
    reload-apply preflight, startup `--p2p-trust-bundle` preflight,
    SIGHUP preflight, local peer-candidate-check, live inbound
    `0x05`, and the peer-driven drain coordinator — each driving the
    Run 188 lifecycle + governance + custody composition through the
    same typed boundary;
  * `AuthorityCustodyPayloadCarryingDecisionOutcome` — the typed
    surface of every Run 190 decision
    (`Accepted` / `MalformedPayload` /
    `RequiredButAbsent` / `NoCustodyAttestationSupplied` /
    `MainNetPeerDrivenApplyRefused` / `Callsite(...)`),
    plus `is_accept()` / `is_bypassed()` / `is_reject()` predicates;
  * grep-verifiable named helpers
    `mainnet_peer_driven_apply_remains_refused_under_run_190`,
    `peer_majority_cannot_satisfy_run_190_custody`, and
    `local_operator_config_alone_cannot_satisfy_mainnet_run_190_custody`
    that re-state, by symbol, that the Run 188 refusal layer is
    preserved at the Run 190 carrier boundary.
* Source/test integration tests at
  [`crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs`](
    ../../crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs)
  covering the full A1–A10 / R1–R32 matrix from
  `task/RUN_190_TASK.txt` plus serde / parse compatibility,
  unsupported-future-schema-version fail-closed, source-reachability
  invariants for `validate_authority_custody_attestation` and
  `validate_lifecycle_governance_and_custody` outside helper /
  example modules, and validation-only / mutating-rejection
  no-mutation invariants (55 tests, all passing).
* In-crate self-tests embedded in the new module exercising the wire
  conversion round-trips, sibling extraction, combined loader,
  callsite context routing, MainNet refusal short-circuit, and
  default `Disabled` policy fail-closed (10 tests, all passing).
* Module declaration in
  [`crates/qbind-node/src/lib.rs`](
    ../../crates/qbind-node/src/lib.rs)
  registering `pqc_authority_custody_payload_carrying` immediately
  after the Run 188 `pqc_authority_custody` module, so the new
  carrier sits beside its validator.

Run 190 adds **no**:

* Real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
* Real on-chain governance proof verifier.
* Governance execution engine.
* Validator-set rotation.
* MainNet peer-driven apply enablement.
* Autonomous apply or apply-on-receipt.
* Peer-majority authority.
* Authority-marker, sequence-file, trust-bundle core, wire, or
  metric drift.
* New operator-visible CLI flag, env var, or selector. The custody
  policy is supplied by the calling surface, default `Disabled`,
  exactly as in Run 188 / Run 189.
* Release-binary custody-metadata evidence (deferred to Run 191).

## 2. Acceptance summary

Acceptance scenarios A1–A10 and rejection scenarios R1–R32 are
captured in
[`crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs`](
  ../../crates/qbind-node/tests/run_190_authority_custody_payload_callsite_tests.rs).

| Scenario | Tested by |
|----------|-----------|
| A1 No-custody payload remains compatible under default Disabled | `a1_no_custody_payload_remains_compatible_under_default_disabled` |
| A2 DevNet fixture custody carried through reload-check | `a2_devnet_fixture_custody_carried_through_reload_check_accepted` |
| A3 TestNet fixture custody carried through reload-check | `a3_testnet_fixture_custody_carried_through_reload_check_accepted` |
| A4 DevNet local-operator under explicit DevNet local policy | `a4_devnet_local_operator_custody_accepted_under_devnet_local_policy` |
| A5 TestNet local-operator under explicit TestNet local policy | `a5_testnet_local_operator_custody_accepted_under_testnet_local_policy` |
| A6 DevNet fixture custody through reload-apply preflight | `a6_devnet_fixture_custody_carried_through_reload_apply_preflight_accepted` |
| A7 Combined lifecycle + governance + fixture custody DevNet | `a7_combined_lifecycle_governance_fixture_custody_accepted_devnet` |
| A8 Combined lifecycle + governance + local custody TestNet | `a8_combined_lifecycle_governance_local_custody_accepted_testnet` |
| A9 Governance proof paths compatible under custody Disabled | `a9_governance_proof_paths_compatible_under_custody_disabled` |
| A10 KMS/HSM/RemoteSigner placeholders reach validator unavailable | `a10_kms_hsm_remote_signer_placeholders_reach_validator_and_return_unavailable` |
| R1 Absent custody under required policy fail-closed | `r1_absent_custody_under_required_policy_fails_closed` |
| R2 Malformed custody payload rejected on every surface | `r2_malformed_custody_payload_rejected_on_every_surface` |
| R3 Fixture custody rejected under production custody required | `r3_fixture_custody_rejected_under_production_custody_required` |
| R4 Local-operator rejected under production custody required | `r4_local_operator_custody_rejected_under_production_custody_required` |
| R5 Fixture custody rejected for MainNet | `r5_fixture_custody_rejected_for_mainnet` |
| R6 Local-operator rejected for MainNet | `r6_local_operator_custody_rejected_for_mainnet` |
| R7 KMS placeholder rejected as unavailable | `r7_kms_placeholder_rejected_as_unavailable` |
| R8 HSM placeholder rejected as unavailable | `r8_hsm_placeholder_rejected_as_unavailable` |
| R9 Remote signer placeholder rejected as unavailable | `r9_remote_signer_placeholder_rejected_as_unavailable` |
| R10 Unknown custody class rejected | `r10_unknown_custody_class_rejected` |
| R11 Wrong environment rejected | `r11_wrong_environment_rejected` |
| R12 Wrong chain rejected | `r12_wrong_chain_rejected` |
| R13 Wrong genesis rejected | `r13_wrong_genesis_rejected` |
| R14 Wrong authority root rejected | `r14_wrong_authority_root_rejected` |
| R15 Wrong signing-key fingerprint rejected | `r15_wrong_signing_key_fingerprint_rejected` |
| R16 Wrong candidate digest rejected | `r16_wrong_candidate_digest_rejected` |
| R17 Wrong authority-domain sequence rejected | `r17_wrong_authority_domain_sequence_rejected` |
| R18 Wrong lifecycle action rejected | `r18_wrong_lifecycle_action_rejected` |
| R19 Missing custody attestation rejected | `r19_missing_custody_attestation_rejected` |
| R20 Malformed custody attestation rejected | `r20_malformed_custody_attestation_rejected` |
| R21 Expired custody attestation rejected | `r21_expired_custody_attestation_rejected` |
| R22 Custody key id mismatch rejected | `r22_custody_key_id_mismatch_rejected` |
| R23 Unsupported custody suite rejected | `r23_unsupported_custody_suite_rejected` |
| R24 Custody valid but governance class mismatch | `r24_custody_valid_but_governance_class_mismatch_rejected` |
| R25 Governance valid but custody invalid rejected | `r25_governance_valid_but_custody_invalid_rejected` |
| R26 Lifecycle+governance valid but custody placeholder unavailable | `r26_lifecycle_governance_valid_but_custody_placeholder_unavailable_rejected` |
| R27 Local-operator config alone cannot satisfy MainNet | `r27_local_operator_config_alone_cannot_satisfy_mainnet_production_custody` |
| R28 Peer majority cannot satisfy custody | `r28_peer_majority_cannot_satisfy_custody` |
| R29 Validation-only rejection is pure | `r29_validation_only_rejection_is_pure` |
| R30 Mutating rejection is pure | `r30_mutating_rejection_is_pure` |
| R31 Invalid live `0x05` custody is not staged or applied | `r31_invalid_live_0x05_custody_is_not_staged_or_applied` |
| R32 MainNet peer-driven apply refused even with KMS/HSM custody | `r32_mainnet_peer_driven_apply_refused_even_with_kms_hsm_custody` |

Validation commands run at minimum (all PASS):

* `cargo build -p qbind-node --lib` — PASS.
* `cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests` — PASS (55/55).
* `cargo test -p qbind-node --test run_188_authority_custody_boundary_tests` — PASS (48/48).
* `cargo test -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests` — PASS.
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
* `cargo test -p qbind-node --lib` — PASS (1310/1310).

## 3. Honest limitations

* **Run 190 is source/test only.** No release-binary custody-metadata
  harness is added; release-binary custody-metadata evidence is
  **deferred to Run 191**.
* **No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend
  is implemented.** The carrier wires the existing Run 188 typed
  validator into production call-site contexts; every `RemoteSigner`,
  `Kms`, and `Hsm` custody class still fails closed with the typed
  Run 188 unavailable variant, regardless of attestation contents,
  schema version, sibling shape, or active policy.
* **Fixture / local-operator custody remains DevNet/TestNet
  evidence-only.** It is reachable only under the explicit
  `FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed`
  policies, and is rejected by symbol whenever the trust-domain
  environment is MainNet.
* **Fixture / local-operator custody cannot satisfy MainNet
  production custody.** The MainNet rejection layer is intentionally
  ahead of the policy gate at the Run 190 carrier boundary, mirroring
  the Run 188 short-circuit.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal**, regardless of custody attestation contents (including
  KMS / HSM placeholders). The Run 190
  drain-coordinator routing helper layers the Run 152 MainNet check
  ahead of the validator and returns the typed
  `MainNetPeerDrivenApplyRefused` outcome.
* **Existing no-custody payloads remain byte / parse compatible.**
  Old v2 ratification sidecars without an `authority_custody_attestation`
  sibling parse through Run 167 / Run 184 / Run 190 unchanged; the
  Run 190 load status is `Absent` and the default `Disabled` policy
  short-circuits to `NoCustodyAttestationSupplied`, which is treated
  as a typed bypass (not an accept) so it cannot be confused with a
  successful custody validation.
* **Governance execution remains unimplemented.** Run 190 does not
  call any new governance verifier; it routes the already-validated
  Run 163 / 167 / 184 / 186 governance class into the Run 188
  composition helper.
* **Real on-chain governance proof verification remains
  unimplemented.** The Run 186 `OnChainGovernanceVerifierKind::Disabled`
  default is preserved.
* **Validator-set rotation remains open.**
* **Full C4 remains open.** **C5 remains open.**
* **No operator-visible custody selector is added at Run 190.**
  The active policy is supplied by the calling surface, default
  `AuthorityCustodyPolicy::Disabled` on every surface, identical to
  Run 188 / Run 189.
