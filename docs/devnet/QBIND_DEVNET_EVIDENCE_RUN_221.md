# QBIND DevNet evidence — Run 221

**Title.** Release-binary long-running governance-execution runtime-consumption evidence.

**Status.** PASS target (release-binary). Run 221 is the release-binary evidence run for the Run 220 source/test governance-execution runtime-**consumption** wiring (`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`). It closes the release-binary limitation Run 220 recorded: the resolved policy and the real governance-execution sidecar load status are now proven to be **consumed** by the Run 220 consumption layer (`GovernanceExecutionRuntimeConsumption` / `consume_surface` / `consume_surface_from_optional_sidecar_value` / `governance_execution_load_status_from_optional_sidecar_value`) on the real release binary and through a release-built helper using production library symbols.

## Scope and required statements

Run 221 proves with real `target/release/qbind-node` and a release-built helper that:

* Run 221 is release-binary long-running governance-execution runtime-consumption evidence;
* real binary paths consume the selected governance-execution policy where representable;
* real binary paths consume the real governance-execution sidecar status where representable;
* default remains `GovernanceExecutionPolicy::Disabled`;
* absent carrier under Disabled follows `ProceedLegacyBypass`;
* CLI/env precedence is preserved through runtime consumption;
* invalid selector values fail closed before mutation;
* fixture governance execution remains DevNet/TestNet evidence-only;
* emergency council fixture execution is explicit and non-production;
* production/on-chain/MainNet governance execution remains unavailable/fail-closed;
* live inbound `0x05` and peer-driven drain limitations are described honestly where still not fully representable;
* MainNet peer-driven apply remains refused;
* no real governance execution engine is implemented;
* no real on-chain governance proof verifier is implemented;
* no real KMS/HSM backend is implemented;
* no real RemoteSigner backend is implemented;
* validator-set rotation remains unsupported;
* existing custody/KMS-HSM/RemoteSigner/custody-attestation/governance proof paths remain compatible;
* full C4 remains open; C5 remains open.

## Deliverables

* Helper: `crates/qbind-node/examples/run_221_governance_execution_runtime_consumption_release_binary_helper.rs`.
* Harness: `scripts/devnet/run_221_governance_execution_runtime_consumption_release_binary.sh`.
* Evidence archive: `docs/devnet/run_221_governance_execution_runtime_consumption_release_binary/` (`README.md`, `summary.txt`, `.gitignore` tracked; generated artifacts ignored).
* Canonical report: this file.

## What is new versus Run 218 / Run 220

Run 218 exercised the Run 217 carrier `arm_surface` / the seven `preflight_*` methods and recorded the per-surface outcome, but at the long-running runtime call sites the outcome was **discarded** (`let _outcome = arming.arm_surface(..)`) and the load status was forced to `GovernanceExecutionLoadStatus::Absent`. Run 220 closed that gap at the source/test level by adding the consumption layer. Run 221 is the release-binary proof of that consumption layer: the release-built helper drives every scenario through `GovernanceExecutionRuntimeArmingConfig::consume_surface` / `consume_surface_from_optional_sidecar_value`, collapsing the Run 217 per-surface outcome into the typed `GovernanceExecutionRuntimeConsumption` three-way decision (`ProceedLegacyBypass` / `ProceedAccepted` / `FailClosed`) the production runtime call sites act on. On the real binary, the consumption helper `consume_run_220_governance_execution_runtime_outcome` in `main.rs` consumes the verdict at the reload-apply, startup `--p2p-trust-bundle`, reload-check, and local peer-candidate-check call sites (returning `Err` and failing closed before any mutation on `FailClosed`), and the SIGHUP runtime hook in `pqc_live_trust_reload.rs` consumes it on reload, routing the **real** sidecar load status via `governance_execution_load_status_from_optional_sidecar_value` instead of a forced `Absent`.

## Real-binary surface invariants

The harness drives the real release binary:

* `--help` hides `--p2p-trust-bundle-governance-execution-policy`.
* An invalid CLI selector value (`--p2p-trust-bundle-governance-execution-policy bogus`) and an invalid env selector value (`QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY=bogus-env-value`) both fail closed: the binary emits the Run 217 FATAL (`invalid governance-execution policy selector … No runtime config is armed; no preflight runs; no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call.`) and exits non-zero **before** the unrelated `--print-genesis-hash` requirement is evaluated, proving selector validation precedes runtime mutation and hence any consumption.
* Default DevNet/TestNet/MainNet surfaces and the CLI-selector, env-selector, CLI-over-env, MainNet armed selector, and legacy custody/RemoteSigner/custody-attestation compatibility scenarios emit no governance-execution, production-governance, MainNet-governance, on-chain-verifier, validator-set-rotation, KMS/HSM, RemoteSigner, autonomous-apply, apply-on-receipt, peer-majority, or MainNet peer-driven-apply enablement claim.

## Release-helper corpus

The helper records typed consumption tables under `helper_evidence/run_221/tables/`, all driven through `GovernanceExecutionRuntimeArmingConfig::consume_surface` / `consume_surface_from_optional_sidecar_value`:

* **Runtime-consumption selector:** A1 default Disabled + absent carrier consumes `ProceedLegacyBypass`; A2 default Disabled + absent carrier preserves the legacy bypass across all surfaces; A3 CLI `disabled` and A4 env `disabled` consume the bypass; A10 CLI-over-env precedence at the runtime config boundary; R1 invalid/empty CLI typed errors (no carrier constructed, hence no consumption); R2 invalid env typed error; R3 unrelated env stays Disabled and consumes the bypass; carrier/resolver parity for every canonical tag.
* **Accepted A5–A24:** CLI/env fixture acceptance consumes `ProceedAccepted` with the sidecar status read from the optional sidecar value (not a forced `Absent`); emergency-council fixture acceptance only for explicit emergency action; production/MainNet policies consume `FailClosed`; reload-check/reload-apply/startup/SIGHUP/local-peer-candidate/live-`0x05`/peer-driven-drain consumption of the selected policy and real sidecar status; DevNet drain consumes accept while MainNet drain consumes `FailClosed:MainNetPeerDrivenApplyRefused`; rotate/revoke authorization only with matching action/material/sequence; A20 `consume_surface == from_outcome(arm_surface)` for all seven surfaces (the outcome is consumed, not discarded); A21 a present sidecar resolves to `Available`, a `None` sidecar to `Absent`; A22/A23/A24 Run 210/199/193 selector compatibility notes.
* **Rejection R4–R28:** missing/malformed material consumed as `FailClosed`; fixture rejected under production/MainNet policies; unavailable production/on-chain/MainNet governance; wrong action/candidate-digest/sequence/proof-digest; expired/stale/quorum/emergency/validator-set/policy-change/local-operator/peer-majority failures; validation-only and mutating no-mutation purity (repeatable, equal decisions); invalid live `0x05` consumed as `FailClosed` (non-propagation); and MainNet peer-driven refusal even under `MainnetGovernanceRequired` with fixture approval.
* **Loader/reachability:** optional sidecar value → load status (`None`/legacy/`Available`/`Malformed`); schema constants; deterministic digests; all seven surfaces consumable through `consume_surface`; `consume_surface == from_outcome(arm_surface)`; the three-way decision partitions Proceed / FailClosed exactly across surfaces and policies; `from_outcome` classification of the three canonical outcomes; `fail_closed_reason` present on `FailClosed` and absent on proceed variants; the MainNet refusal helper.

## Required source/release reachability proof

The harness writes `reachability/source_reachability.txt`, `cli_flag_reachability.txt`, `runtime_hook_reachability.txt`, `no_discarded_outcome.txt`, and `no_forced_absent.txt` for:

* `pqc_governance_execution_runtime_arming`;
* `GovernanceExecutionRuntimeConsumption` / `ProceedLegacyBypass` / `ProceedAccepted` / `FailClosed`;
* `consume_surface` / `consume_surface_from_optional_sidecar_value`;
* `governance_execution_load_status_from_optional_sidecar_value`;
* the `main.rs` consumption helper (`consume_run_220_governance_execution_runtime_outcome`) at the reload-apply, startup `--p2p-trust-bundle`, reload-check, and local peer-candidate-check call sites consuming the verdict (`is_fail_closed` → `Err`), and the SIGHUP runtime hook in `pqc_live_trust_reload.rs` consuming it on reload;
* the real sidecar load derivation at the runtime hooks (no forced `Absent`);
* the absence of any discarded `let _outcome = arming.arm_surface(..)` statement at the production runtime call sites that claim consumption (`no_discarded_outcome.txt`);
* the absence of a forced `GovernanceExecutionLoadStatus::Absent` threaded into `consume_surface` at the runtime hooks (`no_forced_absent.txt`);
* production/on-chain/MainNet governance unavailable variants and the MainNet refusal helper.

The live inbound `0x05` runtime hook is representable only at the source/test level (the live runtime config does not yet thread a per-connection policy); this limitation is documented (A16/R27) and the consumption layer still routes the resolved policy and real sidecar status into the Run 213 live `0x05` routing helper so an invalid live candidate is consumed as `FailClosed` and not propagated, staged, or applied.

## Mutation/no-mutation and denylist

Rejected runtime-consumption scenarios consume a `FailClosed` decision that short-circuits the runtime call site **before** any mutation: no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, marker/sequence bytes unchanged where present, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active DummySig/DummyKem/DummyAead. Accepted fixture mutating compatibility remains ordered: selector resolution before runtime policy arming, arming before material parse (real sidecar status, not a forced `Absent`), parse before consumption, consumption (`consume_surface`) before the marker decision, governance/lifecycle/proof/custody checks before mutation, and Run 055 sequence commit before v2 marker persistence if a real mutating path is later exercised — a `ProceedAccepted` decision is the precondition for the existing ordered mutating path.

The denylist proves no MainNet apply, autonomous apply, apply-on-receipt, peer-majority authority, real governance execution claim, production governance active claim, MainNet governance enabled claim, real on-chain governance proof verifier claim, real KMS/HSM/RemoteSigner backend claim, custody-attestation production-active claim, validator-set rotation claim, fallback to `--p2p-trusted-root`, active DummySig/DummyKem/DummyAead, schema/wire/metric drift, marker-before-sequence, sequence write on validation-only surfaces, or marker write on validation-only surfaces.

## Captured metadata

The harness captures qbind-node and helper SHA-256 plus ELF Build ID, git commit, rustc/cargo versions, exact commands, stdout/stderr logs, per-scenario exit codes, governance-execution runtime-consumption policy values, fixture input/decision/payload paths and hashes, the runtime-consumption carrier inventory, marker/sequence no-mutation notes, data-dir inventories, and denylist grep results in the evidence archive. The regenerated `summary.txt` contains the observed SHA-256 and Build IDs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_221_governance_execution_runtime_consumption_release_binary_helper
bash scripts/devnet/run_221_governance_execution_runtime_consumption_release_binary.sh
cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests
cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests
cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests
cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests
cargo test -p qbind-node --test run_211_governance_execution_policy_tests
cargo test -p qbind-node --test run_209_custody_attestation_policy_selector_tests
cargo test -p qbind-node --test run_207_custody_attestation_payload_callsite_tests
cargo test -p qbind-node --test run_205_custody_attestation_verifier_tests
cargo test -p qbind-node --test run_203_kms_hsm_backend_boundary_tests
cargo test -p qbind-node --test run_201_remote_signer_transport_boundary_tests
cargo test -p qbind-node --test run_198_remote_signer_policy_selector_tests
cargo test -p qbind-node --test run_196_remote_signer_payload_callsite_tests
cargo test -p qbind-node --test run_194_remote_authority_signer_boundary_tests
cargo test -p qbind-node --test run_192_authority_custody_policy_selector_tests
cargo test -p qbind-node --test run_190_authority_custody_payload_callsite_tests
cargo test -p qbind-node --test run_188_authority_custody_boundary_tests
cargo test -p qbind-node --test run_186_onchain_governance_production_verifier_boundary_tests
cargo test -p qbind-node --test run_184_onchain_governance_payload_carrying_tests
cargo test -p qbind-node --test run_182_onchain_governance_production_callsite_wiring_tests
cargo test -p qbind-node --test run_180_onchain_governance_marker_integration_tests
cargo test -p qbind-node --test run_178_onchain_governance_proof_tests
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
cargo test -p qbind-node --test run_134_reload_apply_v2_authority_marker_tests
cargo test -p qbind-node --test run_138_sighup_v2_authority_marker_tests
cargo test -p qbind-node --lib pqc_authority
cargo test -p qbind-node --lib
```

## Why C4 / C5 remain OPEN

Run 221 is evidence-only. It adds no real governance execution engine, no real on-chain verifier, no KMS/HSM or RemoteSigner backend, no MainNet governance enablement, no validator-set rotation, no autonomous apply, no apply-on-receipt, no peer-majority authority, and no schema/wire/marker/sequence/trust-bundle change. The Run 220 consumption layer only collapses the Run 217 per-surface outcome into a typed decision the runtime call sites act on; it cannot make production/on-chain/MainNet governance available and cannot weaken MainNet peer-driven apply refusal. Fixture governance remains evidence-only and refused for MainNet production purposes. **Full C4 remains OPEN; C5 remains OPEN.**
