# QBIND DevNet evidence — Run 189

**Title.** Release-binary KMS/HSM authority-custody boundary evidence
for the Run 188 source/test authority-custody surface.

**Status.** PASS (release-binary, partial-positive). Run 189 closes
the Run 188-deferred release-binary boundary for the typed
authority-custody layer added by
[`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../crates/qbind-node/src/pqc_authority_custody.rs).
Run 189 introduces no production-source change, no new CLI flag, no
new env var, no new schema, no new wire shape, no new sidecar field,
no new metric, and no new exit code. The release-binary surface
contract from Run 187 is preserved bit-identically: real
`target/release/qbind-node` surfaces no Run 188 custody flag and no
KMS / HSM / remote-signer / production-custody enablement banner on
`--help` or on the default `--print-genesis-hash --env
{devnet,testnet,mainnet}` invocations, and the Run 187 hidden
fixture selector
`--p2p-trust-bundle-onchain-governance-fixture-allowed` (and the
matching
`QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED` env var)
does not enable any Run 188 custody backend. The release-built
helper
[`run_189_authority_custody_boundary_release_binary_helper`](
  ../../crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs)
exercises the Run 188 A1–A8 / R1–R29 corpus end-to-end in **release
mode** through the production library symbols
`pqc_authority_custody::*` —
`AuthorityCustodyClass`, `AuthorityCustodyPolicy`,
`AuthorityCustodyAttestation`, `AuthorityCustodyValidationOutcome`,
`LifecycleGovernanceCustodyOutcome`,
`validate_authority_custody_attestation`,
`validate_lifecycle_governance_and_custody`,
`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
`peer_majority_cannot_satisfy_custody`, and
`local_operator_config_alone_cannot_satisfy_mainnet_production_custody`.
Every `RemoteSigner` / `Kms` / `Hsm` attestation fails closed with the
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
production-custody. Real KMS, HSM, cloud KMS, PKCS#11, remote signer,
on-chain governance proof verification, governance execution,
validator-set rotation, bridge / light-client integration, autonomous
apply, apply-on-receipt, and peer-majority authority all remain
unimplemented. MainNet peer-driven apply remains refused (Run 147
FATAL invariant) at the binary surface AND at the typed custody
boundary. Full **C4** and **C5** remain **OPEN** invariants tracked
by the contradiction ledger.

**Driving spec.** `task/RUN_189_TASK.txt`.

## 1. Strict scope

Run 189 is **release-binary evidence only**. It adds **only**:

* The release-built helper example
  [`crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_189_authority_custody_boundary_release_binary_helper.rs)
  which links against the production library symbols in
  [`crates/qbind-node/src/pqc_authority_custody.rs`](
    ../../crates/qbind-node/src/pqc_authority_custody.rs)
  and exercises the Run 188 A1–A8 / R1–R29 corpus, the per-class /
  per-policy fail-closed table, the three named helpers, no-mutation
  bit-equality across the rejected corpus, and a deterministic
  re-evaluation pass.
* The harness shell script
  [`scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`](
    ../../scripts/devnet/run_189_authority_custody_boundary_release_binary.sh)
  which builds qbind-node and the Run 189 helper in release mode,
  drives the helper, captures `--help` and
  `--print-genesis-hash --env {devnet,testnet,mainnet}` real-binary
  surface invariants, captures the MainNet-refusal-with-armed-
  fixture-selector invariant from Run 187, captures the
  source-reachability proof for every Run 188 custody symbol,
  enforces a denylist of forbidden custody / MainNet-apply
  enablement claims across all logs, and runs the regression test
  matrix from `task/RUN_189_TASK.txt`.
* The evidence archive
  [`docs/devnet/run_189_authority_custody_boundary_release_binary/`](
    run_189_authority_custody_boundary_release_binary/)
  with `README.md`, `summary.txt`, and a `.gitignore` that declares
  every per-run generated subtree (mirrors Run 153 / 155 / 179 /
  181 / 183 / 185 / 187 conventions).
* This canonical evidence report.
* Narrow append-only Run 189 update sections in:
  * [`docs/whitepaper/contradiction.md`](
      ../whitepaper/contradiction.md);
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](
      ../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md);
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md);
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md).

Run 189 adds **no**:

* Production-source line under `crates/`.
* Real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
* Real on-chain governance proof verifier.
* MainNet peer-driven apply enablement.
* Governance execution engine.
* Validator-set rotation.
* Autonomous apply or apply-on-receipt.
* Peer-majority authority.
* Marker, sequence-file, trust-bundle, wire, schema, or metric drift.
* CLI flag, env var, sidecar field, or exit code.

## 2. Acceptance summary

The release-built Run 189 helper exercises every Run 188 test
scenario in release mode through the production library symbols.
Acceptance scenarios A1–A8 and rejection scenarios R1–R29 from
`task/RUN_189_TASK.txt` map onto helper scenarios as follows:

| Run 188 scenario | Captured by Run 189 helper |
|------------------|----------------------------|
| A1 DevNet fixture custody under `FixtureOnly` | `boundary/A1_devnet_fixture_under_fixture_only` |
| A2 TestNet fixture custody under `FixtureOnly` | `boundary/A2_testnet_fixture_under_fixture_only` |
| A3 DevNet local-operator under `DevnetLocalAllowed` | `boundary/A3_devnet_local_under_devnet_local_allowed` |
| A4 TestNet local-operator under `TestnetLocalAllowed` | `boundary/A4_testnet_local_under_testnet_local_allowed` |
| A5 GenesisBound / EmergencyCouncil paths preserved when custody not required | `boundary/A5_*` (custody policy `Disabled` accepts existing surfaces unchanged) |
| A6 Combined lifecycle + governance + fixture custody DevNet | `combo/A6_combined_lifecycle_governance_fixture_devnet` |
| A7 Combined lifecycle + governance + local custody TestNet | `combo/A7_combined_lifecycle_governance_local_testnet` |
| A8 Production-custody boundary returns typed unavailable for KMS/HSM/RemoteSigner | `boundary/A8_*` + `custody_class_table` placeholder fail-closed rows |
| R1 Fixture rejected under `ProductionCustodyRequired` | `boundary/R1_fixture_rejected_under_production_custody_required` |
| R2 Local-operator rejected under `ProductionCustodyRequired` | `boundary/R2_local_rejected_under_production_custody_required` |
| R3 Fixture rejected for MainNet | `boundary/R3_fixture_rejected_for_mainnet` |
| R4 Local-operator rejected for MainNet | `boundary/R4_local_rejected_for_mainnet` |
| R5 KMS placeholder rejected as unavailable | `boundary/R5_kms_unavailable` + `custody_class_table.Kms.*` |
| R6 HSM placeholder rejected as unavailable | `boundary/R6_hsm_unavailable` + `custody_class_table.Hsm.*` |
| R7 Remote signer placeholder rejected as unavailable | `boundary/R7_remote_signer_unavailable` + `custody_class_table.RemoteSigner.*` |
| R8 Unknown custody class rejected | `boundary/R8_unknown_class_rejected` |
| R9 Wrong environment rejected | `boundary/R9_wrong_environment` |
| R10 Wrong chain rejected | `boundary/R10_wrong_chain` |
| R11 Wrong genesis rejected | `boundary/R11_wrong_genesis` |
| R12 Wrong authority root rejected | `boundary/R12_wrong_authority_root` |
| R13 Wrong signing-key fingerprint rejected | `boundary/R13_wrong_signing_key_fingerprint` |
| R14 Wrong candidate digest rejected | `boundary/R14_wrong_candidate_digest` |
| R15 Wrong authority-domain sequence rejected | `boundary/R15_wrong_authority_domain_sequence` |
| R16 Wrong lifecycle action rejected | `boundary/R16_wrong_lifecycle_action` |
| R17 Missing custody attestation rejected | `boundary/R17_missing_custody_attestation` |
| R18 Malformed custody attestation rejected | `boundary/R18_malformed_custody_attestation` |
| R19 Expired custody attestation rejected | `boundary/R19_expired_custody_attestation` |
| R20 Custody key id mismatch rejected | `boundary/R20_custody_key_id_mismatch` |
| R21 Unsupported custody suite rejected | `boundary/R21_unsupported_custody_suite` |
| R22 Custody valid but governance proof invalid | `boundary/R22_governance_authority_class_mismatch` |
| R23 Governance proof valid but custody invalid | `combo/R23_governance_valid_but_custody_invalid` |
| R24 Lifecycle valid + governance valid + custody placeholder unavailable | `combo/R24_lifecycle_governance_valid_custody_placeholder_unavailable` |
| R25 MainNet peer-driven apply refused even if custody claims KMS | `named_helpers/mainnet_peer_driven_apply_remains_refused_under_custody_boundary` |
| R26 Local operator config alone cannot satisfy MainNet production custody | `named_helpers/local_operator_config_alone_cannot_satisfy_mainnet_production_custody` |
| R27 Peer majority / gossip count cannot satisfy custody | `named_helpers/peer_majority_cannot_satisfy_custody` |
| R28 Validation-only rejection remains non-mutating | `no_mutation/*` (every rejected boundary scenario) |
| R29 Mutating preflight rejection produces no Run 070 / live-trust / sequence / marker mutation | `no_mutation/*` + `combo/R28_R29_no_mutation_under_combined_helper` |

The Run 189 release-built helper exits 0 only when every scenario
above matches its expected typed outcome in release mode and every
no-mutation snapshot is bit-equal. The harness rejects any helper
exit code other than 0 and any helper summary missing
`verdict: PASS`.

Real-binary surface invariants captured by the harness:

| Scenario | Real-binary invocation | Asserted invariant |
|----------|------------------------|--------------------|
| S1 | `qbind-node --help` | no `authority-custody`, `kms-hsm`, `remote-signer`, `production custody`, `run-188`, `run-189`, `validator-set rotation`, `governance execution` token present |
| S2 | `qbind-node --print-genesis-hash --env devnet` (no env, no flag) | no `KMS/HSM enabled`, no `production custody enabled`, no `validator-set rotation`, no `MainNet peer-driven apply ENABLED` |
| S3 | `qbind-node --print-genesis-hash --env testnet` | same denylist |
| S4 | `qbind-node --print-genesis-hash --env mainnet` | same denylist + `mainnet.*apply.*enabled` (case-insensitive) absent |
| S5 | `qbind-node --print-genesis-hash --env mainnet --p2p-trust-bundle-onchain-governance-fixture-allowed` with `QBIND_P2P_TRUST_BUNDLE_ONCHAIN_GOVERNANCE_FIXTURE_ALLOWED=1` | even with the Run 187 hidden fixture selector armed, MainNet peer-driven apply is not declared enabled and no Run 188 custody enablement banner is emitted |

## 3. Validation commands

Validation commands run by
`scripts/devnet/run_189_authority_custody_boundary_release_binary.sh`:

* `cargo build --release -p qbind-node --bin qbind-node` — PASS.
* `cargo build --release -p qbind-node --example run_189_authority_custody_boundary_release_binary_helper` — PASS.
* `target/release/examples/run_189_authority_custody_boundary_release_binary_helper <out>` — PASS, `verdict: PASS`.
* `target/release/qbind-node --help` — PASS, no Run 188 custody flag surfaced.
* `target/release/qbind-node --print-genesis-hash --env devnet` — PASS, no Run 188 enablement banner.
* `target/release/qbind-node --print-genesis-hash --env testnet` — PASS, no Run 188 enablement banner.
* `target/release/qbind-node --print-genesis-hash --env mainnet` — PASS, no MainNet apply / Run 188 enablement banner.
* `target/release/qbind-node --print-genesis-hash --env mainnet --p2p-trust-bundle-onchain-governance-fixture-allowed` (with env truthy) — PASS, no MainNet apply / KMS-HSM / production-custody banner.
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
expected / actual / table outputs, the source-reachability grep
proof, the denylist proof, the no-mutation proof, and the regression
test logs are written under
`docs/devnet/run_189_authority_custody_boundary_release_binary/`
(gitignored). The committed `summary.txt` is overwritten by the
harness with the canonical verdict block.

## 4. Honest limitations

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
  `LocalCustodyRejectedForMainNet`) ahead of the policy gate.
* **Fixture / local-operator custody cannot satisfy MainNet
  production custody.** The MainNet rejection layer is intentionally
  ahead of the policy gate so a misconfigured policy can never
  silently elevate fixture / local-operator material to MainNet
  production custody.
* **MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
  refusal** regardless of custody outcome at the binary surface AND
  at the typed Run 188 boundary via the
  `mainnet_peer_driven_apply_remains_refused_under_custody_boundary`
  named helper.
* **Governance execution remains unimplemented.** Run 189 does not
  call the Run 163 / 178 / 186 governance verifier itself; the
  composition helper takes the already-validated governance class
  from the calling surface.
* **Real on-chain governance proof verification remains
  unimplemented.** Run 186's
  `OnChainGovernanceVerifierKind::Disabled` default is preserved on
  every surface; Run 189 adds no new proof-verifier path.
* **Validator-set rotation remains open.**
* **Existing Run 167 / 169 / 178 / 184 governance fixture paths
  remain compatible.** Run 189 makes no schema, wire, marker, or
  sidecar change.
* **No release-binary boundary for any real KMS / HSM / remote-
  signer backend is captured by Run 189.** Run 189 captures the
  release-binary boundary for the typed source/test custody surface
  only; landing a real backend is a future-run scope.
* **Full C4 is NOT claimed by Run 189; C5 remains OPEN.** Run 189
  does not enable real on-chain governance proof verification +
  governance execution end-to-end, and it does not enable real
  KMS/HSM + validator-set rotation + autonomous apply gates.
