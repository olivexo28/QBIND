# QBIND DevNet Evidence — Run 108

**Task:** `task/RUN_108_TASK.txt` — release-binary evidence closure for peer-candidate check ratification.

**Verdict:** **strongest-positive** for the local `--p2p-trust-bundle-peer-candidate-check` surface only.

Run 108 is evidence-first. No production runtime behavior changed. The only code addition is an evidence-only release fixture helper under `crates/qbind-node/examples/`, plus a DevNet evidence script under `scripts/devnet/`.

## Investigation summary

Existing helpers reused or mirrored:

- Genesis authority material: `qbind_ledger::{GenesisAuthorityConfig, GenesisAuthorityRoot, compute_canonical_genesis_hash}`.
- ML-DSA-44 authority/signing key generation: `qbind_crypto::MlDsa44Backend::generate_keypair`.
- Bundle-signing key IDs and bundle signatures: `qbind_node::pqc_trust_bundle::{derive_signing_key_id, sign_bundle_devnet_helper}`.
- Ratification sidecars: `qbind_ledger::bundle_signing_ratification::test_helpers::build_signed_ratification` through the existing `test-helpers` feature path used by integration tests.
- Trust bundles: `qbind_node::pqc_trust_bundle::TrustBundle`.
- Peer-candidate envelopes: `qbind_node::pqc_trust_peer_candidate::PeerCandidateEnvelope`.
- Expected genesis hash: release binary `--print-genesis-hash` semantics are equivalent to `format_genesis_hash(compute_canonical_genesis_hash(...))`; the helper writes the exact expected hash file used by the smoke matrix.
- Environment selection: release binary `--env mainnet|devnet` plus Run 106/107 `ratification_gate_decision` log labels.

Exact release-binary peer-candidate-check shape exercised:

```text
qbind-node \
  --env <mainnet|devnet> \
  --genesis-path <genesis.json> \
  --expect-genesis-hash <0x...> \
  --data-dir <scenario-data-dir> \
  --p2p-trust-bundle-signing-key <KEYID:100:PK> \
  --p2p-trust-bundle-peer-candidate-validation-enabled \
  --p2p-trust-bundle-peer-candidate-check <peer-candidate.json> \
  [--p2p-trust-bundle-ratification-enforcement-enabled] \
  [--p2p-trust-bundle-ratification <ratification.json>]
```

Non-mutation observability in check mode:

- Directly observed: no `pqc_trust_bundle_sequence.json` created under any scenario data dir.
- Directly observed: process emits Run 077 validation-only verdict and exits; no P2P transport, propagation, session eviction, reload-apply, SIGHUP, or apply markers appear.
- Source-level invariant: the local check path holds no live trust state, no session evictor, no propagation handle, and no apply context.
- Not directly observable: in-memory absence of a live trust mutation beyond logs/source shape, because the release-binary check exits before constructing the live node runtime. This is covered by source-level evidence and the no-startup log invariant.

Minimum release-binary failure markers identified and covered:

- Missing ratification: `RatificationRefused(Missing { ... })`.
- Bad signature: `RatificationRefused(Verifier(BadSignature))`.

Other typed failures remain covered by Run 107 tests: wrong chain, wrong environment, unknown authority root, transport root not allowed, missing/malformed authority key material, and unsupported suite.

## Release-binary evidence

Evidence directory:

- `docs/devnet/run_108_peer_candidate_check_ratification_release_binary_evidence/`

Script:

- `scripts/devnet/run_108_peer_candidate_check_ratification_release_binary.sh`

Fixture helper:

- `crates/qbind-node/examples/run_108_peer_candidate_ratification_fixture_helper.rs`

Summary artifact:

- `docs/devnet/run_108_peer_candidate_check_ratification_release_binary_evidence/summary.txt`

Release artifacts recorded by the script:

```text
qbind-node_sha256: ef55ebea525b434537384950273a927e83805116741f06af25440087d38b7b88
qbind-node_build_id: 665be0acb324902e25730d54a8ac917073bf0ec7
fixture-helper_sha256: fb7480d19b23b312414383aeead02f23b63f6be83d7b34b4c5f992ffadf21258
fixture-helper_build_id: f9cda9476d6aef03e4179baec279b8d2ecd8d57c
```

Scenario results:

| Scenario | Log prefix | Expected | Observed |
| --- | --- | --- | --- |
| 1. MainNet valid ratification passes | `scenario_1_mainnet_valid` | rc=0 | pass |
| 2. MainNet missing ratification rejects | `scenario_2_mainnet_missing` | rc=1 | pass |
| 3. MainNet bad ratification rejects | `scenario_3_mainnet_bad_signature` | rc=1 | pass |
| 4. DevNet no opt-in legacy behavior | `scenario_4_devnet_no_opt_in_legacy` | rc=0 | pass |
| 5a. DevNet opt-in valid ratification passes | `scenario_5a_devnet_opt_in_valid` | rc=0 | pass |
| 5b. DevNet opt-in missing ratification rejects | `scenario_5b_devnet_opt_in_missing` | rc=1 | pass |
| 5c. DevNet opt-in bad ratification rejects | `scenario_5c_devnet_opt_in_bad_signature` | rc=1 | pass |

Key observed markers:

- Scenario 1: `[run-102] OK`, `[run-107] ... INVOKED (policy=mainnet-default-strict, env=Mainnet)`, `VERDICT=validated`.
- Scenario 2: `RatificationRefused(Missing { environment: Mainnet, ... })`, `VERDICT=rejected`.
- Scenario 3: `RatificationRefused(Verifier(BadSignature))`, `VERDICT=rejected`.
- Scenario 4: `[run-107] ... SKIPPED (policy=devnet-no-operator-opt-in, env=Devnet)`, `VERDICT=validated`.
- Scenario 5a: `[run-107] ... INVOKED (policy=devnet-operator-opt-in, env=Devnet)`, `VERDICT=validated`.
- Scenario 5b: `RatificationRefused(Missing { environment: Devnet, ... })`, `VERDICT=rejected`.
- Scenario 5c: `RatificationRefused(Verifier(BadSignature))`, `VERDICT=rejected`.

Non-mutation checks: pass. The script asserts no sequence file creation and no node-startup/P2P/propagation/session-eviction/reload-apply markers for every scenario.

## Source-level evidence

Run 108 did not change production runtime paths. It did not alter:

- `crates/qbind-node/src/main.rs` peer-candidate check wiring;
- `crates/qbind-node/src/pqc_peer_candidate_binary.rs`;
- `crates/qbind-node/src/pqc_trust_peer_candidate.rs`;
- trust-bundle wire format;
- peer-candidate wire format;
- live dispatcher or propagation code.

The evidence helper only generates local JSON fixtures for the already-existing release-binary CLI. The script only runs release binaries and asserts logs, exit codes, and absence of mutation/startup indicators.

## Test evidence

Pre-change targeted regression run partially completed before stopping on a command-name typo:

- `cargo test -p qbind-node --test run_107_peer_candidate_ratification_tests` — pass, 6 tests.
- `cargo test -p qbind-node run106 --lib` — pass, 0 matching tests.
- `cargo test -p qbind-node run105 --lib` — pass, 0 matching tests.
- `cargo test -p qbind-ledger ratification --lib` — pass, 33 tests.
- `cargo test -p qbind-ledger authority --lib` — pass, 27 tests.
- `cargo test -p qbind-node peer_candidate --lib` — pass, 59 tests.
- The run then failed because `run_077_peer_candidate_binary_tests` is not a test target; the correct target is `run_077_binary_peer_candidate_check_tests`.

Final targeted regression results are recorded in the final response for this run.

## Explicit non-claims

Run 108 does **not** implement or change:

- live peer-candidate validation enforcement;
- propagation/rebroadcast enforcement;
- reload-apply enforcement;
- SIGHUP enforcement;
- trust-bundle wire format;
- peer-candidate wire format;
- peer-driven apply;
- KMS/HSM custody;
- signing-key rotation/revocation;
- authority anti-rollback persistence;
- full C4 closure;
- C5 closure.

Run 108 confirms only that the local release-binary peer-candidate check enforces Run 107 ratification policy as designed.
