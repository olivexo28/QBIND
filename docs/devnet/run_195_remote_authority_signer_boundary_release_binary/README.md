# Run 195 — Release-binary RemoteSigner production-custody boundary evidence

## Scope

Closes the Run 194-deferred release-binary boundary for the source/test
**RemoteSigner production-custody interface** added by
[`crates/qbind-node/src/pqc_remote_authority_signer.rs`](
  ../../../crates/qbind-node/src/pqc_remote_authority_signer.rs).
Run 194 added the typed RemoteSigner boundary on top of the Run 192 typed
authority-custody policy selector
[`crates/qbind-node/src/pqc_authority_custody_policy_surface.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody_policy_surface.rs),
the Run 190 typed authority-custody payload-carrying surface
[`crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody_payload_carrying.rs),
and the Run 188 typed authority-custody boundary
[`crates/qbind-node/src/pqc_authority_custody.rs`](
  ../../../crates/qbind-node/src/pqc_authority_custody.rs):

* `RemoteSignerPolicy::{Disabled, FixtureLoopbackAllowed,
  ProductionRemoteSignerRequired, MainnetProductionRemoteSignerRequired}`;
* `RemoteSignerIdentity`;
* `RemoteSignerRequest` with a deterministic domain-separated SHA3-256
  `canonical_digest` binding environment, chain, genesis, authority root,
  lifecycle action, candidate digest, and authority-domain sequence;
* `RemoteSignerResponse`;
* `RemoteSignerExpectations`;
* the pure `RemoteAuthoritySigner` trait;
* the DevNet/TestNet-only `FixtureLoopbackRemoteSigner`;
* the fail-closed `ProductionRemoteSigner`;
* the pure `validate_remote_signer` verifier;
* `validate_remote_signer_for_custody_class` (the
  `AuthorityCustodyClass::RemoteSigner` router);
* `validate_lifecycle_governance_custody_and_remote_signer` (the
  composition entry point);
* the named MainNet / local-operator / peer-majority refusal helpers
  (`mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`,
  `local_operator_key_cannot_satisfy_remote_signer`,
  `peer_majority_cannot_satisfy_remote_signer`).

Run 194 is source/test only with the A1–A7 / R1–R31 corpus
[`crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs`](
  ../../../crates/qbind-node/tests/run_194_remote_authority_signer_boundary_tests.rs)
all passing; release-binary RemoteSigner-boundary evidence is **this
Run 195**.

Run 195 captures **release-binary** evidence that real
`target/release/qbind-node` preserves the Run 194 typed RemoteSigner
production-custody boundary contract end-to-end:

* Run 194 added NO new CLI flag and NO new env var — it is a pure
  library boundary; `target/release/qbind-node --help` surfaces no
  RemoteSigner / KMS / HSM / governance-execution / validator-set-rotation
  enablement claim (S1);
* the default `--print-genesis-hash --env {devnet,testnet,mainnet}`
  invocations emit no RemoteSigner enablement banner and no MainNet
  peer-driven apply enablement claim (S2–S4);
* the Run 193 hidden authority-custody policy selector
  (`QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` /
  `--p2p-trust-bundle-authority-custody-policy`) remains compatible at
  the binary surface (S5);
* the governance fixture proof path
  (`--p2p-trust-bundle-onchain-governance-fixture-allowed`) remains
  compatible at the binary surface (S6);
* even with the Run 193 selector set to
  `mainnet-production-custody-required` and the governance fixture
  selector armed on MainNet startup, the binary still emits no MainNet
  peer-driven apply enablement claim, no RemoteSigner/KMS/HSM enablement
  banner, no governance execution claim, and no validator-set rotation
  claim — Run 147 / 148 / 152 FATAL invariant is preserved (S7);
* the release-built Run 195 helper
  [`run_195_remote_authority_signer_boundary_release_binary_helper`](
    ../../../crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs)
  exercises the Run 194 A1–A7 / R1–R31 RemoteSigner corpus end-to-end in
  **release mode** through the production library symbols
  `pqc_remote_authority_signer::*` — `RemoteSignerPolicy`,
  `RemoteSignerIdentity`, `RemoteSignerRequest`, `RemoteSignerResponse`,
  `RemoteSignerExpectations`, `RemoteAuthoritySigner`,
  `FixtureLoopbackRemoteSigner`, `ProductionRemoteSigner`,
  `validate_remote_signer`, `validate_remote_signer_for_custody_class`,
  `validate_lifecycle_governance_custody_and_remote_signer`, the named
  refusal helpers, and the deterministic `canonical_digest` entry
  points — layered above the Run 192 selector surface, the Run 190
  payload-carrying surface, and the Run 188 typed authority-custody
  boundary.

## Strict scope (from `task/RUN_195_TASK.txt`)

* Release-binary evidence only.
* Use real `target/release/qbind-node`.
* Use the release-built Run 195 helper to exercise the Run 194
  RemoteSigner boundary in release mode through production library
  symbols.
* No production-source change (harness-only tooling).
* No real RemoteSigner backend; no networked signer service.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution; no real on-chain proof verifier; no
  validator-set rotation; no autonomous apply; no apply-on-receipt;
  no peer-majority authority.
* No marker / sequence-file / trust-bundle / wire / metric drift.
* No new CLI flag, env var, schema bump, sidecar field, metric, or
  exit code.
* Do not weaken Runs 070, 130–194.
* Do not claim full C4 / C5 closure.

## Layout

Only `README.md`, `summary.txt`, and `.gitignore` are tracked in git.
All other artifacts are produced by the harness and contain absolute
paths and ephemeral data; they are listed in `.gitignore`.

* `summary.txt` — canonical verdict line emitted by the harness; the
  committed copy is a placeholder overwritten by every run.
* `logs/` — captured stdout/stderr for build / scenarios S1–S7 and
  helper invocation.
* `exit_codes/` — per-scenario exit codes for the harness.
* `helper_evidence/run_195/` — Run 195 release-helper output:
  scenario corpus (A1–A7 / R1–R31), canonical_digest table, policy-mode
  table, custody-routing table, composition table, refusal-helper table,
  no_mutation_evidence, determinism_evidence, helper_summary.txt.
* `reachability/source_reachability.txt` — `grep -RIn` evidence that
  every Run 194 / 192 / 190 / 188 typed symbol the helper exercises is
  wired in production source under `crates/qbind-node/src/`.
* `test_results/` — captured stdout/stderr for each cargo test target
  named in `task/RUN_195_TASK.txt` (skipped tests are recorded as
  `rc=skipped(not-present)`).
* `provenance.txt` — git commit, branch, rustc/cargo versions, host,
  binary SHA-256 + ELF Build ID for `target/release/qbind-node` and
  the Run 195 helper.
* `negative_invariants.txt` — denylist results.
* `mutation_proof.txt` — release-binary mutation reachability summary.
* `no_mutation_proof.txt` — non-mutation evidence for rejected
  RemoteSigner / custody / lifecycle / routing scenarios.

## Reproducing

```
bash scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh
```

The harness is idempotent: it wipes and regenerates everything under
this directory **except** `README.md`, `summary.txt`, and `.gitignore`.
The committed `summary.txt` is a placeholder and is overwritten by
every successful run.

## Honest limits

* Run 195 is release-binary RemoteSigner production-custody boundary
  evidence only;
* no real RemoteSigner backend is implemented and no networked signer
  service is wired;
* fixture loopback RemoteSigner is DevNet/TestNet evidence-only and
  cannot satisfy MainNet production RemoteSigner policy;
* production RemoteSigner remains unavailable/fail-closed under
  `ProductionRemoteSignerRequired` and
  `MainnetProductionRemoteSignerRequired` regardless of environment;
* RemoteSigner request/response binding is deterministic and
  domain-bound;
* local operator keys and peer-majority/gossip counts cannot satisfy
  RemoteSigner policy;
* RemoteSigner integrates with custody composition at the
  release-helper/library level only — RemoteSigner cannot enable
  MainNet peer-driven apply;
* MainNet peer-driven apply remains refused (Run 147 / 148 / 152 FATAL
  invariant) at every binary surface — including with the Run 193
  selector set to `mainnet-production-custody-required` and the
  governance fixture selector armed — and at the typed boundary via
  `mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`;
* KMS/HSM remain unimplemented (no cloud KMS, no PKCS#11);
* governance execution remains unimplemented; real on-chain proof
  verification remains unimplemented; validator-set rotation remains
  open;
* no autonomous apply / no apply-on-receipt / no peer-majority
  authority;
* existing custody/governance proof paths remain compatible;
* no schema/wire/metric drift in Run 195 (release-binary evidence
  only);
* full C4 remains OPEN; C5 remains OPEN.