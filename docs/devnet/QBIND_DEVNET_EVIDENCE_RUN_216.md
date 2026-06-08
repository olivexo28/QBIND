# QBIND DevNet evidence — Run 216

**Title.** Release-binary governance execution policy-selector evidence.

**Status.** PASS target (release-binary). Run 216 is the release-binary evidence run for the Run 215 source/test hidden governance-execution policy selector (`crates/qbind-node/src/pqc_governance_execution_policy_surface.rs`). It mirrors Run 210's selector-release structure in the governance-execution domain.

## Scope and required statements

Run 216 proves with real `target/release/qbind-node` and a release-built helper that:

* default remains `GovernanceExecutionPolicy::Disabled`;
* hidden CLI/env selectors activate governance execution policies;
* CLI-over-env precedence is deterministic;
* invalid values fail closed;
* fixture governance execution remains DevNet/TestNet evidence-only;
* emergency council fixture execution is explicit and non-production;
* fixture governance cannot satisfy MainNet production governance execution;
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

* Helper: `crates/qbind-node/examples/run_216_governance_execution_policy_release_binary_helper.rs`.
* Harness: `scripts/devnet/run_216_governance_execution_policy_release_binary.sh`.
* Evidence archive: `docs/devnet/run_216_governance_execution_policy_release_binary/` (`README.md`, `summary.txt`, `.gitignore` tracked; generated artifacts ignored).
* Canonical report: this file.

## Real-binary surface invariants

The harness drives the real release binary:

* `--help` hides `--p2p-trust-bundle-governance-execution-policy`.
* Default DevNet/TestNet/MainNet surfaces emit no governance-execution, production-governance, MainNet-governance, on-chain-verifier, validator-set-rotation, KMS/HSM, RemoteSigner, autonomous-apply, apply-on-receipt, peer-majority, or MainNet peer-driven-apply enablement claim.
* CLI selector, env selector, CLI-over-env, invalid selector, MainNet armed selector, and legacy custody/RemoteSigner/custody-attestation selector compatibility scenarios are accepted at the binary surface without enabling production governance.

## Release-helper corpus

The helper records typed outcome tables under `helper_evidence/run_216/tables/`:

* **Selector:** A1 default Disabled; A2 CLI canonical tags; A3 env canonical tags; A9 CLI-over-env; R1 invalid/empty CLI typed errors; R2 invalid env typed error; R3 unrelated env does not enable policy.
* **Accepted A1–A16:** fixture DevNet/TestNet acceptance under explicit fixture policy, emergency-council fixture acceptance only for explicit emergency action, production/on-chain/MainNet unavailable outcomes, no-governance payload compatibility under Disabled, existing selector/path compatibility, rotate and revoke authorization only with matching action/material/sequence.
* **Rejection R1–R40:** invalid selectors, missing/malformed material, fixture rejected under production/MainNet policies, unavailable production/on-chain/MainNet governance, unknown class, wrong environment/chain/genesis/root/action/digests/proposal/decision/effective epoch, expired/stale/quorum/emergency/validator-set/policy-change/local-operator/peer-majority failures, validation-only and mutating no-mutation purity, invalid live `0x05` non-propagation, and MainNet peer-driven refusal.
* **Loader/reachability:** sidecar sibling parsing, schema constants, deterministic digests, all seven wrappers, and MainNet refusal helper.

## Required source/release reachability proof

The harness writes `reachability/source_reachability.txt` and `cli_flag_reachability.txt` for:

* `pqc_governance_execution_policy_surface`;
* `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY`;
* `p2p_trust_bundle_governance_execution_policy`;
* `governance_execution_policy_from_selector`;
* `governance_execution_policy_from_cli_or_env`;
* `governance_execution_policy_env_selector`;
* seven per-surface governance-execution-policy preflight wrappers;
* `GovernanceExecutionPolicy::{Disabled, FixtureGovernanceAllowed, EmergencyCouncilFixtureAllowed, ProductionGovernanceRequired, MainnetGovernanceRequired}`;
* Run 213 governance-execution payload routing helpers;
* production/on-chain/MainNet governance unavailable variants;
* MainNet governance refusal helper.

## Mutation/no-mutation and denylist

Rejected scenarios produce no Run 070 apply call, no live trust swap, no session eviction, no sequence write, no marker write, marker/sequence bytes unchanged where present, no `.tmp` residue, no fallback to `--p2p-trusted-root`, and no active DummySig/DummyKem/DummyAead. Accepted fixture mutating compatibility remains ordered: selector resolution before material parse, parse before marker decision, governance/lifecycle/proof/custody checks before mutation, and Run 055 sequence commit before v2 marker persistence if a real mutating path is later exercised.

The denylist proves no MainNet apply, autonomous apply, apply-on-receipt, peer-majority authority, real governance execution claim, production governance active claim, MainNet governance enabled claim, real on-chain governance proof verifier claim, real KMS/HSM/RemoteSigner backend claim, custody-attestation production-active claim, validator-set rotation claim, fallback to `--p2p-trusted-root`, active DummySig/DummyKem/DummyAead, schema/wire/metric drift, marker-before-sequence, sequence write on validation-only surfaces, or marker write on validation-only surfaces.

## Captured metadata

The harness captures qbind-node and helper SHA-256 plus ELF Build ID, git commit, rustc/cargo versions, exact commands, stdout/stderr logs, per-scenario exit codes, governance execution policy values, fixture input/decision/payload paths and hashes, marker/sequence no-mutation notes, data-dir inventories, and denylist grep results in the evidence archive. The regenerated `summary.txt` contains the observed SHA-256 and Build IDs.

## Validation commands

```bash
cargo build --release -p qbind-node --bin qbind-node
cargo build --release -p qbind-node --example run_216_governance_execution_policy_release_binary_helper
bash scripts/devnet/run_216_governance_execution_policy_release_binary.sh
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

Run 216 is evidence-only. It adds no real governance execution engine, no real on-chain verifier, no KMS/HSM or RemoteSigner backend, no MainNet governance enablement, no validator-set rotation, no autonomous apply, no apply-on-receipt, no peer-majority authority, and no schema/wire/marker/sequence/trust-bundle change. Fixture governance remains evidence-only and refused for MainNet production purposes. **Full C4 remains OPEN; C5 remains OPEN.**
