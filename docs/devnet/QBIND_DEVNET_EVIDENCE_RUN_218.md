# QBIND DevNet evidence — Run 218

**Title.** Release-binary governance execution runtime-arming evidence.

**Status.** PASS target (release-binary). Run 218 is the release-binary evidence run for the Run 217 source/test governance-execution runtime-arming wiring (`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`). It closes the release-binary limitation Run 216 recorded: the resolved policy is now proven to be **consumed by the Run 217 runtime-arming carrier** (`GovernanceExecutionRuntimeArmingConfig`) and routed into the production preflight contexts on the real release binary.

## Scope and required statements

Run 218 proves with real `target/release/qbind-node` and a release-built helper that:

* Run 218 is release-binary governance execution runtime-arming evidence;
* the hidden governance-execution selector is consumed by runtime preflight contexts through the Run 217 carrier;
* default remains `GovernanceExecutionPolicy::Disabled`;
* CLI/env precedence is preserved through runtime arming;
* invalid selector values fail closed before mutation;
* fixture governance execution remains DevNet/TestNet evidence-only;
* emergency council fixture execution is explicit and non-production;
* production/on-chain/MainNet governance execution remains unavailable/fail-closed;
* MainNet peer-driven apply remains refused;
* no real governance execution engine is implemented;
* no real on-chain governance proof verifier is implemented;
* no real KMS/HSM backend is implemented;
* no real RemoteSigner backend is implemented;
* validator-set rotation remains unsupported;
* existing custody/KMS-HSM/RemoteSigner/custody-attestation/governance proof paths remain compatible;
* full C4 remains open; C5 remains open.

## Deliverables

* Helper: `crates/qbind-node/examples/run_218_governance_execution_runtime_arming_release_binary_helper.rs`.
* Harness: `scripts/devnet/run_218_governance_execution_runtime_arming_release_binary.sh`.
* Evidence archive: `docs/devnet/run_218_governance_execution_runtime_arming_release_binary/` (`README.md`, `summary.txt`, `.gitignore` tracked; generated artifacts ignored).
* Canonical report: this file.

## What is new versus Run 216

Run 216 exercised the Run 215 selector resolver and the seven per-surface preflight wrappers **directly**. Run 218 resolves the selector through the Run 217 runtime-config carrier `GovernanceExecutionRuntimeArmingConfig::from_cli_or_env` and drives every preflight surface through that carrier (`arm_surface` / the seven `preflight_*` methods), proving the armed policy is the single value the long-running runtime config carries into each production preflight context. On the real binary, the carrier is constructed at the reload-apply, startup `--p2p-trust-bundle`, reload-check, SIGHUP, and local peer-candidate-check call sites in `main.rs`, and is embedded in `LiveReloadConfig::governance_execution_runtime_arming` (consumed by the SIGHUP runtime hook in `pqc_live_trust_reload.rs`).

## Real-binary surface invariants

The harness drives the real release binary:

* `--help` hides `--p2p-trust-bundle-governance-execution-policy`.
* An invalid selector value (`--p2p-trust-bundle-governance-execution-policy bogus`) fails closed: the binary emits the Run 217 FATAL (`invalid governance-execution policy selector … No runtime config is armed; no preflight runs; no marker write; no sequence write; no live trust swap; no session eviction; no Run 070 call.`) and exits non-zero **before** the unrelated `--print-genesis-hash` requirement is evaluated, proving selector validation precedes runtime mutation.
* Default DevNet/TestNet/MainNet surfaces and the CLI-selector, env-selector, CLI-over-env, MainNet armed selector, and legacy custody/RemoteSigner/custody-attestation compatibility scenarios emit no governance-execution, production-governance, MainNet-governance, on-chain-verifier, validator-set-rotation, KMS/HSM, RemoteSigner, autonomous-apply, apply-on-receipt, peer-majority, or MainNet peer-driven-apply enablement claim.

## Release-helper corpus

The helper records typed outcome tables under `helper_evidence/run_218/tables/`, all driven through `GovernanceExecutionRuntimeArmingConfig`:

* **Runtime-arming selector:** A1 default Disabled (carrier == `disabled()`); A2 CLI canonical tags reach arming; A3 env canonical tags reach arming; A9 CLI-over-env at the runtime config boundary; R1 invalid/empty CLI typed errors (no config constructed); R2 invalid env typed error (no config constructed); R3 unrelated env stays Disabled; carrier/resolver parity for every canonical tag.
* **Accepted A1–A22:** fixture DevNet/TestNet acceptance under explicit armed fixture policy across all seven surfaces; emergency-council fixture acceptance only for explicit emergency action; production/on-chain/MainNet unavailable outcomes; no-governance payload compatibility under Disabled arming; runtime-armed reload-check/reload-apply/startup/SIGHUP/local-peer-candidate/live-`0x05`/peer-driven-drain consumption of the selected policy; DevNet drain accepts while MainNet drain is refused; rotate/revoke authorization only with matching action/material/sequence; Run 210/199/193 selector compatibility notes.
* **Rejection R4–R28:** missing/malformed material; fixture rejected under production/MainNet policies; unavailable production/on-chain/MainNet governance; unknown class; wrong action/candidate-digest/sequence/proof-digest; expired/stale/quorum/emergency/validator-set/policy-change/local-operator/peer-majority failures; validation-only and mutating no-mutation purity; invalid live `0x05` non-propagation; and MainNet peer-driven refusal even under `MainnetGovernanceRequired` with fixture approval.
* **Loader/reachability:** sidecar sibling parsing, schema constants, deterministic digests, all seven surfaces reachable through `arm_surface`, per-method vs dispatch equivalence, and the MainNet refusal helper.

## Required source/release reachability proof

The harness writes `reachability/source_reachability.txt`, `cli_flag_reachability.txt`, and `runtime_hook_reachability.txt` for:

* `pqc_governance_execution_runtime_arming`;
* `GovernanceExecutionRuntimeArmingConfig` / `GovernanceExecutionRuntimeSurface`;
* `governance_execution_policy_from_cli_or_env`;
* `p2p_trust_bundle_governance_execution_policy` (CLI field);
* `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` (env);
* `LiveReloadConfig::governance_execution_runtime_arming`;
* `Run105ReloadCheckContextData` governance-execution policy field;
* the `main.rs` runtime hooks (`invoke_run_217_callsite_governance_execution_marker_decision`) at reload-apply, startup `--p2p-trust-bundle`, reload-check, and local peer-candidate-check call sites, and the SIGHUP runtime hook (`invoke_run_217_sighup_callsite_governance_execution_marker_decision`) in `pqc_live_trust_reload.rs`;
* the seven Run 215 governance-execution-policy preflight wrappers;
* Run 213 governance-execution payload routing helpers and Run 211 evaluator entry points;
* production/on-chain/MainNet governance unavailable variants and the MainNet refusal helper.

The live inbound `0x05` runtime hook is representable only at the source/test level (the live runtime config does not yet thread a per-connection policy); this limitation is documented (A16) and the carrier still routes the armed policy into the Run 213 live `0x05` routing helper so an invalid live candidate is not propagated, staged, or applied.

## Mutation/no-mutation and denylist

Rejected runtime-armed scenarios produce no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, marker/sequence bytes unchanged where present, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active DummySig/DummyKem/DummyAead. Accepted fixture mutating compatibility remains ordered: selector resolution before runtime policy arming, arming before material parse, parse before marker decision, governance/lifecycle/proof/custody checks before mutation, and Run 055 sequence commit before v2 marker persistence if a real mutating path is later exercised.

The denylist proves no MainNet apply, autonomous apply, apply-on-receipt, peer-majority authority, real governance execution claim, production governance active claim, MainNet governance enabled claim, real on-chain governance proof verifier claim, real KMS/HSM/RemoteSigner backend claim, custody-attestation production-active claim, validator-set rotation claim, fallback to `--p2p-trusted-root`, active DummySig/DummyKem/DummyAead, schema/wire/metric drift, marker-before-sequence, sequence write on validation-only surfaces, or marker write on validation-only surfaces.

## Captured metadata

The harness captures qbind-node and helper SHA-256 plus ELF Build ID, git commit, rustc/cargo versions, exact commands, stdout/stderr logs, per-scenario exit codes, governance execution runtime policy values, fixture input/decision/payload paths and hashes, marker/sequence no-mutation notes, data-dir inventories, and denylist grep results in the evidence archive. The regenerated `summary.txt` contains the observed SHA-256 and Build IDs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_218_governance_execution_runtime_arming_release_binary_helper
bash scripts/devnet/run_218_governance_execution_runtime_arming_release_binary.sh
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

Run 218 is evidence-only. It adds no real governance execution engine, no real on-chain verifier, no KMS/HSM or RemoteSigner backend, no MainNet governance enablement, no validator-set rotation, no autonomous apply, no apply-on-receipt, no peer-majority authority, and no schema/wire/marker/sequence/trust-bundle change. The Run 217 runtime-arming carrier only narrows what each preflight wrapper accepts; it cannot make production/on-chain/MainNet governance available and cannot weaken MainNet peer-driven apply refusal. Fixture governance remains evidence-only and refused for MainNet production purposes. **Full C4 remains OPEN; C5 remains OPEN.**