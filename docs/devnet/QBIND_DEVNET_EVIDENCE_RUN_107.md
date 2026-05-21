# QBIND DevNet Evidence — Run 107

**Task:** `task/RUN_107_TASK.txt` — ratification enforcement for the local peer-candidate check CLI.

**Verdict:** **partial-positive**. Source and focused integration-test proof landed for `--p2p-trust-bundle-peer-candidate-check`; release-binary smoke scenarios were not honestly produced in this run.

## Implemented surface

Run 107 wires the existing Run 105/106 bundle-signing-key ratification model into the local, validation-only peer-candidate check:

- `crates/qbind-node/src/pqc_trust_peer_candidate.rs`
  - adds `PeerCandidateValidator::try_accept_with_ratification(...)`;
  - preserves `PeerCandidateRuntimeContext` shape and does not touch live wire validation;
  - delegates to `validate_candidate_bundle_full_with_ratification(...)` only for the wrapper path.
- `crates/qbind-node/src/pqc_peer_candidate_binary.rs`
  - adds `run_local_check_with_ratification(...)` around the existing Run 077 local-check flow;
  - preserves `run_local_check(...)` for legacy/unratified DevNet behavior;
  - preserves non-mutation semantics: scratch file only, no sequence commit, no live state, no session eviction, no propagation.
- `crates/qbind-node/src/main.rs`
  - `--p2p-trust-bundle-peer-candidate-check` now calls `ratification_gate_decision(config.environment, opt_in)`;
  - MainNet/TestNet invoke ratification by default;
  - DevNet invokes only under `--p2p-trust-bundle-ratification-enforcement-enabled`;
  - the existing Run 105 sidecar flag `--p2p-trust-bundle-ratification <PATH>` and context builder are reused.

No peer-candidate wire format changed. No live dispatcher, propagation, reload-apply, SIGHUP, peer-driven apply, rotation, revocation, authority anti-rollback persistence, KMS/HSM, governance, or validator-set rotation was changed.

## Policy behavior

| Environment | Opt-in flag | Run 107 peer-candidate check decision |
|-------------|-------------|----------------------------------------|
| MainNet | absent or present | invoke ratification (`mainnet-default-strict`) |
| TestNet | absent or present | invoke ratification (`testnet-default-strict`) |
| DevNet | absent | skip ratification; preserve legacy local-check behavior |
| DevNet | present | invoke ratification (`devnet-operator-opt-in`) |

MainNet cannot use the DevNet skip branch because `ratification_gate_decision` never returns `Skip` for MainNet/TestNet.

## Test evidence

New focused test file:

- `crates/qbind-node/tests/run_107_peer_candidate_ratification_tests.rs`

Passing focused run:

```text
cargo test -p qbind-node --test run_107_peer_candidate_ratification_tests

running 6 tests
test run107_peer_candidate_policy_matches_run106 ... ok
test run107_devnet_without_opt_in_preserves_legacy_unratified_local_check ... ok
test run107_missing_ratification_rejects_mainnet_without_sequence_write ... ok
test run107_valid_mainnet_ratification_passes_and_does_not_write_sequence ... ok
test run107_bad_signature_wrong_chain_wrong_env_and_unsupported_suite_reject_precisely ... ok
test run107_unknown_transport_missing_and_malformed_authority_reject_precisely ... ok

test result: ok. 6 passed; 0 failed
```

Covered failures include missing ratification, bad signature, wrong chain, wrong environment, unknown authority root, transport root, missing authority key material, malformed authority key material, and unsupported suite. These surface through `PeerCandidateRejection::ValidationFailed(ReloadCheckError::RatificationRefused(...))`, preserving typed verifier reasons instead of collapsing to generic invalid-candidate errors.

## Non-mutation proof

Source-level invariants:

- The Run 107 wrapper only chooses between `validate_candidate_bundle_full(...)` and `validate_candidate_bundle_full_with_ratification(...)` inside the existing Run 076 validator.
- `validate_candidate_bundle_full_with_ratification(...)` first runs the same Run 069 validation pipeline, then calls the pure `qbind_ledger::enforce_bundle_signing_key_ratification(...)` gate.
- The local-check binary path exits before node startup and holds no `LivePqcTrustState`, no `P2pSessionEvictor`, no live reload controller, and no propagation handle.
- Sequence state is passed only to read-only peek logic; no `commit_sequence` / `check_and_update_sequence` path is reachable.

Test-level invariants:

- The valid MainNet ratification test asserts success and no sequence file creation.
- The missing-ratification MainNet rejection test asserts typed refusal and no sequence file creation.
- Existing Run 077 tests continue to cover scratch cleanup, metric family boundaries, wrong-env/wrong-chain envelope rejection, tampered signature rejection, and reload-check coexistence.

## Release-binary/process evidence

Release-binary smoke scenarios requested by `task/RUN_107_TASK.txt` were **not produced** in this run. A placeholder process log is recorded at:

- `docs/devnet/run_107_release_binary_smoke.log`

Because release-binary evidence is incomplete, this run is **partial-positive**, not positive or strongest-positive.

## Explicit non-claims

Run 107 does **not** implement live peer-candidate wire validation enforcement, propagation/rebroadcast enforcement, reload-apply enforcement, SIGHUP enforcement, signing-key rotation, signing-key revocation lifecycle, authority anti-rollback persistence, KMS/HSM custody, peer-driven live apply, governance, validator-set rotation, full C4 closure, or C5 closure.