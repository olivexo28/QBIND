# QBIND DevNet evidence — Run 191

**Title.** Release-binary authority-custody metadata carrying evidence
for the Run 190 source/test authority-custody payload-carrying surface.

**Status.** PASS (release-binary, partial-positive). Run 191 closes
the Run 190-deferred release-binary boundary for the typed
authority-custody payload-carrying layer added by
[`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`](
  ../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs),
composed over the Run 188 typed authority-custody boundary in
[`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../crates/qbind-node/src/pqc_authority_custody.rs).
Run 191 introduces no production-source change, no new CLI flag, no
new env var, no new schema, no new wire shape, no new sidecar field,
no new metric, and no new exit code. The release-binary surface
contract from Run 189 is preserved bit-identically: real
`target/release/qbind-node` surfaces no Run 190 custody payload flag
and no KMS / HSM / remote-signer / production-custody enablement
banner on `--help` or on the default `--print-genesis-hash --env
{devnet,testnet,mainnet}` invocations, and the Run 187 hidden fixture
selector `--p2p-trust-bundle-onchain-governance-fixture-allowed` (and
the matching `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED`
env var) does not enable any Run 190 custody payload-carrying backend.
The release-built helper
[`run_191_authority_custody_payload_release_binary_helper`](
  ../../crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs)
exercises the Run 190 A1–A10 / R1–R32 corpus end-to-end in **release
mode** through the production library symbols
`pqc_authority_custody_payload_carrying::*` —
`AuthorityCustodyAttestationWire`, `AuthorityCustodyClassWire`,
`GovernanceAuthorityClassWire`, `AuthorityCustodyLoadStatus`,
`parse_optional_authority_custody_attestation_sibling_from_json_value`,
`AuthorityCustodyCallsiteContext`,
`callsite_context_for_authority_custody`,
`AuthorityCustodyPayloadCarryingDecisionOutcome`, the seven per-surface
routing helpers
`route_loaded_authority_custody_attestation_to_reload_check_callsite_decision`,
`route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision`,
`route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision`,
`route_loaded_authority_custody_attestation_to_sighup_callsite_decision`,
`route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision`,
`route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision`,
`route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision`,
and `mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`,
composed with the Run 188 typed-boundary symbols
`validate_authority_custody_attestation`,
`validate_lifecycle_governance_and_custody`,
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
`peer_majority_cannot_satisfy_custody`, and
`local_operator_config_alone_cannot_satisfy_mainnet_production_custody`.
Every `RemoteSigner` / `Kms` / `Hsm` attestation — whether constructed
in-process or wire-carried through the Run 190 sibling and parsed back
to the typed `AuthorityCustodyAttestation` — fails closed with the
typed `RemoteSignerUnavailable` / `KmsUnavailable` / `HsmUnavailable`
outcome regardless of policy or environment; every
`ProductionCustodyRequired` / `MainnetProductionCustodyRequired`
policy fails closed with the typed `ProductionCustodyUnavailable` /
`MainNetProductionCustodyUnavailable` (or the placeholder-specific
`*Unavailable`) outcome; every fixture / local-operator class on
MainNet routes to `FixtureCustodyRejectedForMainNet` /
`LocalCustodyRejectedForMainNet` ahead of the policy gate, encoding
the honest unavailability of any real production custody backend in
this tree and explicitly forbidding fixture-/local-as-MainNet-
production-custody — even when the rejecting metadata is wire-carried
through the Run 190 optional sibling. Legacy / no-custody payloads
(sibling absent) remain compatible under default `Disabled` and route
to the typed no-custody-required acceptance path through every
per-surface routing helper without producing schema or wire drift.
Real KMS, HSM, cloud KMS, PKCS#11, remote signer, on-chain governance
proof verification, governance execution, validator-set rotation,
bridge / light-client integration, autonomous apply, apply-on-receipt,
and peer-majority authority all remain unimplemented. MainNet
peer-driven apply remains refused (Run 147 FATAL invariant) at the
binary surface AND at the typed custody payload-carrying boundary.
Full **C4** and **C5** remain **OPEN** invariants tracked by the
contradiction ledger.

**Driving spec.** `task/RUN_191_TASK.txt`.

## 1. Strict scope

Run 191 is **release-binary evidence only**. It adds **only**:

* The release-built helper example
  [`crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_191_authority_custody_payload_release_binary_helper.rs)
  which links against the production library symbols in
  [`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`](
    ../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs)
  and exercises the Run 190 A1–A10 / R1–R32 corpus, the wire
  round-trip table, the optional-sibling parser table, the seven
  per-surface routing helpers, the named helpers, no-mutation
  bit-equality across the rejected corpus, and a deterministic
  re-evaluation pass.
* The harness shell script
  [`scripts/devnet/run_191_authority_custody_payload_release_binary.sh`](
    ../../scripts/devnet/run_191_authority_custody_payload_release_binary.sh)
  which builds qbind-node and the Run 191 helper in release mode,
  drives the helper, captures `--help` and
  `--print-genesis-hash --env {devnet,testnet,mainnet}` real-binary
  surface invariants, captures the MainNet-refusal-with-armed-
  fixture-selector invariant from Run 187, captures the
  source-reachability proof for every Run 188 / Run 190 custody and
  payload-carrying symbol, enforces a denylist of forbidden custody /
  MainNet-apply enablement claims across all logs, and runs the
  regression test matrix from `task/RUN_191_TASK.txt`.
* The evidence archive
  [`docs/devnet/run_191_authority_custody_payload_release_binary/`](
    run_191_authority_custody_payload_release_binary/)
  with `README.md`, `summary.txt`, and a `.gitignore` that declares
  every per-run generated subtree (mirrors Run 153 / 155 / 179 /
  181 / 183 / 185 / 187 / 189 conventions).
* This canonical evidence report.
* Narrow append-only Run 191 update sections in:
  * [`docs/whitepaper/contradiction.md`](
      ../whitepaper/contradiction.md);
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](
      ../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md);
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md);
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md).

Run 191 adds **no**:

* Production-source line under `crates/`.
* Real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
* Real on-chain governance proof verifier.
* MainNet peer-driven apply enablement.
* Governance execution engine.
* Validator-set rotation.
* Autonomous apply or apply-on-receipt.
* Peer-majority authority.
* Marker, sequence-file, trust-bundle, schema, or metric drift
  beyond Run 190's additive optional custody sibling.
* CLI flag, env var, sidecar field, or exit code.

## 2. Acceptance summary

The release-built Run 191 helper exercises every Run 190 test
scenario in release mode through the production library symbols.
Acceptance scenarios A1–A10 and rejection scenarios R1–R32 from
`task/RUN_191_TASK.txt` map onto helper scenarios as follows:

| Run 190 scenario | Captured by Run 191 helper |
|------------------|----------------------------|
| A1 DevNet sibling-absent payload under `Disabled` | `routing/A1_devnet_sibling_absent_disabled` |
| A2 TestNet sibling-absent payload under `Disabled` | `routing/A2_testnet_sibling_absent_disabled` |
| A3 DevNet fixture custody sibling under `FixtureOnly` | `routing/A3_devnet_fixture_under_fixture_only` |
| A4 TestNet fixture custody sibling under `FixtureOnly` | `routing/A4_testnet_fixture_under_fixture_only` |
| A5 DevNet local-operator custody sibling under `DevnetLocalAllowed` | `routing/A5_devnet_local_under_devnet_local_allowed` |
| A6 TestNet local-operator custody sibling under `TestnetLocalAllowed` | `routing/A6_testnet_local_under_testnet_local_allowed` |
| A7 DevNet wire round-trip preserves Run 188 validator outcome | `wire_round_trip/A7_*` (wire encode → parse → validate → equal typed outcome) |
| A8 Existing Run 184 governance proof sibling remains compatible alongside custody sibling | `routing/A8_governance_and_custody_siblings_coexist` |
| A9 Per-surface routing helper preserves Run 188 callsite typed decision under `Loaded` | `routing_helpers_table.*.Loaded.*` |
| A10 Per-surface routing helper preserves Run 188 callsite typed decision under `Absent` (Disabled) | `routing_helpers_table.*.Absent.*` |
| R1 Fixture custody sibling rejected under `ProductionCustodyRequired` (production unavailable) | `routing/R1_fixture_under_production_required` |
| R2 Local-operator custody sibling rejected under `ProductionCustodyRequired` (production unavailable) | `routing/R2_local_under_production_required` |
| R3 Same as R1 across all seven routing helpers | `routing/R3_fixture_under_production_required` |
| R4 Same as R2 across all seven routing helpers | `routing/R4_local_under_production_required` |
| R5 Fixture custody sibling on MainNet rejected ahead of policy gate (peer-driven-drain refuses MainNet first) | `routing/R5_fixture_on_mainnet_peer_drain_refused` |
| R6 Local-operator custody sibling on MainNet rejected ahead of policy gate (peer-driven-drain refuses MainNet first) | `routing/R6_local_on_mainnet_peer_drain_refused` |
| R7 KMS placeholder sibling rejected as unavailable | `routing/R7_kms_unavailable` |
| R8 HSM placeholder sibling rejected as unavailable | `routing/R8_hsm_unavailable` |
| R9 Remote-signer placeholder sibling rejected as unavailable | `routing/R9_remote_signer_unavailable` |
| R10 Unknown custody class wire rejected | `routing/R10_unknown_class_rejected` |
| R11 Sibling JSON value is non-object (string) — typed `Malformed::Json` | `sibling_parse_table/loaded_malformed_json` |
| R12 Sibling JSON missing required field — typed `Malformed::*` | `sibling_parse_table/loaded_malformed_missing_field` |
| R13 Sibling JSON unknown class string — typed `Malformed::UnknownClass` | `sibling_parse_table/loaded_malformed_unknown_class` |
| R14 Sibling JSON expired attestation — typed `Malformed::Expired` | `sibling_parse_table/loaded_malformed_expired` |
| R15 Sibling JSON wire schema mismatch — typed `Malformed::UnknownSchema` | `sibling_parse_table/loaded_malformed_unknown_schema` |
| R16 Wrong environment in carried wire rejected by validator | `routing/R16_wire_wrong_environment` (covered via Run 188 validator path) |
| R17 Wrong chain in carried wire rejected by validator | `routing/R17_wire_wrong_chain` (validator path) |
| R18 Wrong genesis in carried wire rejected by validator | `routing/R18_wire_wrong_genesis` (validator path) |
| R19 Wrong authority-root in carried wire rejected by validator | `routing/R19_wire_wrong_authority_root` (validator path) |
| R20 Wrong signing-key fingerprint in carried wire rejected by validator | `routing/R20_wire_wrong_signing_key_fingerprint` (validator path) |
| R21 Wrong candidate digest in carried wire rejected by validator | `routing/R21_wire_wrong_candidate_digest` (validator path) |
| R22 Wrong authority-domain sequence in carried wire rejected by validator | `routing/R22_wire_wrong_authority_domain_sequence` (validator path) |
| R23 Wrong lifecycle action in carried wire rejected by validator | `routing/R23_wire_wrong_lifecycle_action` (validator path) |
| R24 Custody key id mismatch in carried wire rejected by validator | `routing/R24_wire_custody_key_id_mismatch` (validator path) |
| R25 Unsupported custody suite in carried wire rejected by validator | `routing/R25_wire_unsupported_custody_suite` (validator path) |
| R26 Carried wire valid + lifecycle invalid — Run 188 combined helper short-circuits at `LifecycleRejected` | `routing/R26_lifecycle_invalid_short_circuit` |
| R27 Carried wire valid + governance class mismatch — Run 188 combined helper rejects at custody | `routing/R27_governance_class_mismatch` |
| R28 Per-surface routing helper carries Run 188 `MainNetPeerDrivenApplyRefused` for peer-driven-drain on MainNet regardless of custody contents | `named_helpers/mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying` |
| R29 Local operator config alone cannot satisfy MainNet production custody — even when wire-carried | `named_helpers/local_operator_config_alone_cannot_satisfy_mainnet_production_custody` |
| R30 Peer majority / gossip count cannot satisfy custody — even when wire-carried | `named_helpers/peer_majority_cannot_satisfy_custody` |
| R31 Sibling-present rejected scenario remains non-mutating | `no_mutation/*` (every rejected routing scenario) |
| R32 Sibling-absent rejected scenario remains non-mutating | `no_mutation/*` |

The Run 191 release-built helper exits 0 only when every scenario
above matches its expected typed outcome in release mode and every
no-mutation snapshot is bit-equal. The harness rejects any helper
exit code other than 0 and any helper summary missing
`verdict: PASS`.

Real-binary surface invariants captured by the harness:

| Scenario | Real-binary invocation | Asserted invariant |
|----------|------------------------|--------------------|
| S1 | `qbind-node --help` | no `authority-custody`, `kms-hsm`, `remote-signer`, `production custody`, `run-190`, `run-191`, `validator-set rotation`, `governance execution` token present |
| S2 | `qbind-node --print-genesis-hash --env devnet` (no env, no flag) | no `KMS/HSM enabled`, no `production custody enabled`, no `validator-set rotation`, no `MainNet peer-driven apply ENABLED` |
| S3 | `qbind-node --print-genesis-hash --env testnet` | same denylist |
| S4 | `qbind-node --print-genesis-hash --env mainnet` | same denylist + `mainnet.*apply.*enabled` (case-insensitive) absent |
| S5 | `qbind-node --print-genesis-hash --env mainnet --p2p-trust-bundle-onchain-governance-fixture-allowed` with `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1` | even with the Run 187 hidden fixture selector armed, MainNet peer-driven apply is not declared enabled and no Run 190 custody payload-carrying enablement banner is emitted |

## 3. Validation commands

Validation commands run by
`scripts/devnet/run_191_authority_custody_payload_release_binary.sh`:

* `cargo build --release -p qbind-node --bin qbind-node` — PASS.
* `cargo build --release -p qbind-node --example run_191_authority_custody_payload_release_binary_helper` — PASS.
* `target/release/examples/run_191_authority_custody_payload_release_binary_helper <out>` — PASS, `verdict: PASS`.
* `target/release/qbind-node --help` — PASS, no Run 190 custody payload flag surfaced.
* `target/release/qbind-node --print-genesis-hash --env devnet` — PASS, no Run 190 enablement banner.
* `target/release/qbind-node --print-genesis-hash --env testnet` — PASS, no Run 190 enablement banner.
* `target/release/qbind-node --print-genesis-hash --env mainnet` — PASS, no MainNet apply / Run 190 enablement banner.
* `target/release/qbind-node --print-genesis-hash --env mainnet --p2p-trust-bundle-onchain-governance-fixture-allowed` (with env truthy) — PASS, no MainNet apply / KMS-HSM / production-custody banner.
* `cargo test --release -p qbind-node --test run_190_authority_custody_payload_callsite_tests` — PASS.
* `cargo test --release -p qbind-node --test run_188_authority_custody_boundary_tests` — PASS.
* `cargo test --release -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests` — PASS.
* `cargo test --release -p qbind-node --test run_184_onchain_governance_payload_carrying_tests` — PASS.
* `cargo test --release -p qbind-node --test run_182_onchain_governance_production_callsite_wiring_tests` — PASS.
* `cargo test --release -p qbind-node --test run_180_onchain_governance_marker_integration_tests` — PASS.
* `cargo test --release -p qbind-node --test run_178_onchain_governance_proof_tests` — PASS.
* `cargo test --release -p qbind-node --test run_176_live_0x05_governance_proof_carrier_tests` — PASS.
* `cargo test --release -p qbind-node --test run_173_validation_only_governance_required_policy_tests` — PASS.
* `cargo test --release -p qbind-node --test run_171_governance_required_policy_selector_tests` — PASS.
* `cargo test --release -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests` — PASS.
* `cargo test --release -p qbind-node --test run_167_governance_proof_carrier_tests` — PASS.
* `cargo test --release -p qbind-node --test run_165_governance_marker_integration_tests` — PASS.
* `cargo test --release -p qbind-node --test run_163_governance_authority_verifier_tests` — PASS.
* `cargo test --release -p qbind-node --test run_161_lifecycle_marker_integration_tests` — PASS.
* `cargo test --release -p qbind-node --test run_159_authority_signing_key_lifecycle_tests` — PASS.
* `cargo test --release -p qbind-node --test run_157_unified_testnet_fixture_universe_tests` — PASS.
* `cargo test --release -p qbind-node --test run_152_binary_reachable_peer_drain_plumbing_tests` — PASS.
* `cargo test --release -p qbind-node --test run_150_peer_driven_apply_drain_tests` — PASS.
* `cargo test --release -p qbind-node --test run_148_peer_driven_apply_devnet_tests` — PASS.
* `cargo test --release -p qbind-node --test run_142_live_inbound_0x05_v2_validation_tests` — PASS.
* `cargo test --release -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests` — PASS.
* `cargo test --release -p qbind-node --test run_138_sighup_v2_authority_marker_tests` — PASS.
* `cargo test --release -p qbind-node --lib pqc_authority` — PASS.
* `cargo test --release -p qbind-node --lib pqc_authority_custody` — PASS.

Per-run exit codes, captured stdout/stderr, the helper manifest /
expected / actual / wire / sibling / routing / named-helper / table
outputs, the source-reachability grep proof, the denylist proof, the
no-mutation proof, and the regression test logs are written under
`docs/devnet/run_191_authority_custody_payload_release_binary/`
(gitignored). The committed `summary.txt` is overwritten by the
harness with the canonical verdict block.

## 4. Honest limitations

* **Run 191 is release-binary authority-custody metadata carrying
  evidence.** It captures the release-binary boundary for the typed
  Run 190 source/test payload-carrying surface only.
* **No real KMS / HSM backend is implemented.** Every `RemoteSigner`,
  `Kms`, and `Hsm` custody class — whether constructed in-process or
  wire-carried through the Run 190 sibling and parsed back — fails
  closed at the typed Run 188 validator with a typed
  `RemoteSignerUnavailable` / `KmsUnavailable` / `HsmUnavailable`
  outcome.
* **KMS / HSM / RemoteSigner placeholders remain fail-closed**
  regardless of attestation contents, sibling presence, active
  policy, or environment. A future run that lands a real backend
  MUST extend the matching validator branch and cannot silently
  elevate any other variant.
* **Fixture / local-operator custody remains DevNet/TestNet
  evidence-only.** It is reachable only under the explicit
  `FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed`
  policies, and is rejected by symbol whenever the trust-domain
  environment is MainNet (`FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet`) ahead of the policy gate, even
  when the metadata is wire-carried through the Run 190 sibling.
* **Fixture / local-operator custody cannot satisfy MainNet
  production custody.** The MainNet rejection layer is intentionally
  ahead of the policy gate so a misconfigured policy can never
  silently elevate fixture / local-operator material to MainNet
  production custody.
* **Existing no-custody payloads remain compatible under default
  `Disabled`.** Sibling-absent payloads route through the seven Run
  190 routing helpers without producing schema or wire drift.
* **Existing governance fixture proof paths remain compatible.** Run
  191 wire-carrying evidence is layered additively next to the Run
  184 governance-proof sibling; the v2 ratification sidecar shape is
  unchanged.
* **MainNet peer-driven apply remains refused** (Run 147 / 148 / 152
  FATAL invariant) regardless of custody outcome at the binary
  surface AND at the typed Run 190 payload-carrying boundary via the
  `mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`
  named helper (and the underlying Run 188
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`
  it composes).
* **Governance execution remains unimplemented.** Run 191 does not
  call the Run 163 / 178 / 186 governance verifier itself; the Run
  190 routing helpers take the already-validated governance class
  from the calling surface.
* **Real on-chain proof verification remains unimplemented.** Run
  186's `OnChainGovernanceVerifierKind::Disabled` default is
  preserved on every surface; Run 191 adds no new proof-verifier
  path.
* **Validator-set rotation remains open.**
* **Full C4 remains open.** Run 191 does not enable real on-chain
  governance proof verification + governance execution end-to-end.
* **C5 remains open.** Run 191 does not enable real KMS/HSM +
  validator-set rotation + autonomous apply gates.