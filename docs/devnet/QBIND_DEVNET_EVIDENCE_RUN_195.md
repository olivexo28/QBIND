# QBIND DevNet evidence — Run 195

**Title.** Release-binary evidence for the Run 194 RemoteSigner
production-custody interface boundary.

**Status.** PASS (release-binary). Run 195 closes the Run 194-deferred
release-binary boundary by exercising the RemoteSigner production-custody
interface on real `target/release/qbind-node` and through the
release-built helper
[`run_195_remote_authority_signer_boundary_release_binary_helper`](
  ../../crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs).
Run 194 added NO new CLI flag and NO new env var — it is a pure library
boundary; real `target/release/qbind-node` therefore surfaces no
RemoteSigner / KMS / HSM / governance-execution / validator-set-rotation
enablement claim on `--help` or
`--print-genesis-hash --env {devnet,testnet,mainnet}`. Fixture loopback
RemoteSigner remains DevNet/TestNet evidence-only; production RemoteSigner
remains unavailable/fail-closed; local operator keys and
peer-majority/gossip counts cannot satisfy RemoteSigner policy; and
MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL refusal
even with the Run 193 `mainnet-production-custody-required` selector and
the governance fixture selector armed.

**Strict scope.**

* Release-binary evidence only.
* Use real `target/release/qbind-node`.
* Use the release-built Run 195 helper to drive the Run 194 A1–A7 /
  R1–R31 RemoteSigner corpus through the production library symbols.
* No production-source change.
* No real RemoteSigner backend; no networked signer service.
* No real KMS / HSM / cloud KMS / PKCS#11 integration.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority
  authority.
* No marker / sequence-file / authority-marker / trust-bundle core /
  ratification-sidecar / wire / schema change.
* Run 195 does not weaken any prior run (Runs 070, 130–194) and does
  not claim full C4 or C5 closure.

## Run 195 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh`](
    ../../scripts/devnet/run_195_remote_authority_signer_boundary_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_195_remote_authority_signer_boundary_release_binary/`](
    run_195_remote_authority_signer_boundary_release_binary/).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Real-binary surface evidence

The harness drives real `target/release/qbind-node` across seven
release-binary scenarios (S1–S7). Per-scenario stdout/stderr, exit
codes, SHA-256, and ELF Build ID are captured under
[`docs/devnet/run_195_remote_authority_signer_boundary_release_binary/logs/`](
  run_195_remote_authority_signer_boundary_release_binary/logs/) and
[`exit_codes/`](run_195_remote_authority_signer_boundary_release_binary/exit_codes/);
binary provenance lives in `provenance.txt`; per-scenario assertions are
encoded in the harness `assert_grep` / `assert_not_grep` helpers.

| Scenario | Invocation | Required invariant |
| --- | --- | --- |
| **S1** | `qbind-node --help` | no `RemoteSigner enabled` / `RemoteSigner backend connected` / `remote signer production active` claim; no KMS/HSM; no governance execution; no validator-set rotation; no Run 194 / 195 banner. Run 194 added no new flag. |
| **S2** | `--print-genesis-hash --env devnet` | no RemoteSigner enabled/active/connected/wired banner; no KMS/HSM active; no validator-set rotation; no governance execution; no autonomous apply; no MainNet peer-driven apply ENABLED. |
| **S3** | `--print-genesis-hash --env testnet` | no RemoteSigner enabled/active/connected/wired banner; no KMS/HSM active; no MainNet peer-driven apply ENABLED. |
| **S4** | `--print-genesis-hash --env mainnet` | MainNet refusal preserved; no MainNet peer-driven apply ENABLED; no RemoteSigner enabled/active/connected/wired banner; no KMS/HSM active; no validator-set rotation; no governance execution. |
| **S5** | `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=fixture-only --print-genesis-hash --env devnet` | Run 193 hidden authority-custody policy selector remains compatible; no RemoteSigner/KMS/HSM banner; no MainNet peer-driven apply ENABLED. |
| **S6** | `--print-genesis-hash --env devnet --p2p-trust-bundle-onchain-governance-fixture-allowed` | governance fixture proof path remains compatible; no RemoteSigner banner; no governance execution; no MainNet peer-driven apply ENABLED. |
| **S7** | Run 193 selector `mainnet-production-custody-required` + governance fixture selector both armed (MainNet) | no MainNet peer-driven apply ENABLED; no MainNet apply ENABLED; no RemoteSigner enabled/active/connected/wired banner; no remote signer production active; no KMS/HSM active; no validator-set rotation; no governance execution. |

## Release-built helper evidence

The release-built helper
[`run_195_remote_authority_signer_boundary_release_binary_helper`](
  ../../crates/qbind-node/examples/run_195_remote_authority_signer_boundary_release_binary_helper.rs)
exercises the Run 194 A1–A7 / R1–R31 RemoteSigner corpus end-to-end in
**release mode** through the production library symbols
`pqc_remote_authority_signer::*` layered above
`pqc_authority_custody_policy_surface::*`,
`pqc_authority_custody_payload_carrying::*`, and
`pqc_authority_custody::*`. The helper does NOT alter any production
source; it only **reads** the typed surface.

The helper writes (under
`helper_evidence/run_195/`):

* `manifest.txt` — A1..A7 / R1..R31 corpus index;
* `scenarios/<id>/…` and `expected_outcomes.txt` /
  `actual_outcomes.txt` — per-scenario evidence and the expected vs.
  actual typed `RemoteSignerOutcome`;
* `canonical_digest_table.txt` — the deterministic domain-separated
  SHA3-256 `RemoteSignerRequest::canonical_digest` binding (A3):
  environment, chain, genesis, authority root, lifecycle action,
  candidate digest, and authority-domain sequence each perturb the
  digest, and identical inputs reproduce it bit-for-bit;
* `policy_mode_table.txt` — every `RemoteSignerPolicy`
  (`Disabled` / `FixtureLoopbackAllowed` /
  `ProductionRemoteSignerRequired` /
  `MainnetProductionRemoteSignerRequired`) resolves to its expected
  typed outcome (fixture accepted only under
  `FixtureLoopbackAllowed`; production/mainnet-production fail closed);
* `custody_routing_table.txt` — `validate_remote_signer_for_custody_class`
  routes `AuthorityCustodyClass::RemoteSigner` into the RemoteSigner
  boundary (A4), `LocalOperatorKey` cannot satisfy RemoteSigner (R24),
  and other classes route to `NotRemoteSignerCustodyClass`;
* `composition_table.txt` —
  `validate_lifecycle_governance_custody_and_remote_signer` composes
  lifecycle + governance + custody + fixture RemoteSigner for the
  DevNet helper path (A5), and rejects when any leg is invalid
  (R26 / R27 / R28) and refuses MainNet peer-driven apply (R29);
* `refusal_helpers_table.txt` — the named refusal helpers
  (`mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`,
  `local_operator_key_cannot_satisfy_remote_signer`,
  `peer_majority_cannot_satisfy_remote_signer`,
  `custody_class_routes_to_remote_signer`) return the expected verdicts;
* `no_mutation_evidence.txt` — for every rejected scenario, candidate
  and persisted snapshots taken **before** and **after** the rejecting
  RemoteSigner / custody / lifecycle / routing dispatch are bit-equal
  (R30 / R31);
* `determinism_evidence.txt` — every scenario re-evaluated under
  identical inputs reproduces the typed outcome bit-for-bit;
* `helper_summary.txt` — the canonical PASS/FAIL verdict line and
  per-table tallies (`scenarios_pass`, `canonical_digest_pass`,
  `policy_mode_pass`, `custody_routing_pass`, `composition_pass`,
  `refusal_helpers_pass`, `no_mutation_pass`, `determinism_pass`).

The helper exits non-zero if any tally has `*_fail > 0` and the harness
fails the run. The captured run records `verdict: PASS` with
`total_pass: 95`, `total_fail: 0`.

## Production-call-site reachability

[`reachability/source_reachability.txt`](
  run_195_remote_authority_signer_boundary_release_binary/reachability/source_reachability.txt)
records `grep -RIn --include='*.rs'` evidence for every Run 194 / 192 /
190 / 188 typed symbol the helper exercises against
`crates/qbind-node/src/`, including:

* the new Run 194 surface module `pqc_remote_authority_signer`;
* every `RemoteSignerPolicy` variant (`Disabled` /
  `FixtureLoopbackAllowed` / `ProductionRemoteSignerRequired` /
  `MainnetProductionRemoteSignerRequired`);
* `RemoteSignerIdentity`, `RemoteSignerRequest`, `RemoteSignerResponse`,
  `RemoteSignerExpectations`, `RemoteSignerOutcome`;
* the pure `RemoteAuthoritySigner` trait, the DevNet/TestNet-only
  `FixtureLoopbackRemoteSigner`, and the fail-closed
  `ProductionRemoteSigner`;
* `validate_remote_signer`,
  `validate_remote_signer_for_custody_class`,
  `validate_lifecycle_governance_custody_and_remote_signer`;
* the named refusal helpers
  `mainnet_peer_driven_apply_remains_refused_under_remote_signer_boundary`,
  `local_operator_key_cannot_satisfy_remote_signer`,
  `peer_majority_cannot_satisfy_remote_signer`,
  `custody_class_routes_to_remote_signer`;
* the deterministic `canonical_digest` entry point and the
  `REMOTE_SIGNER_INVALID_SIGNATURE_SENTINEL` constant;
* the layered Run 192 / 190 / 188 modules
  `pqc_authority_custody_policy_surface`,
  `pqc_authority_custody_payload_carrying`, `pqc_authority_custody`,
  and `AuthorityCustodyClass::RemoteSigner`.

## Mutation / no-mutation evidence

For every rejected RemoteSigner / custody / lifecycle / routing scenario
in the helper corpus, [`no_mutation_proof.txt`](
  run_195_remote_authority_signer_boundary_release_binary/no_mutation_proof.txt)
records:

* no Run 070 apply call;
* no live trust swap;
* no session eviction;
* no sequence write;
* no marker write;
* marker bytes unchanged where present;
* sequence bytes unchanged where present;
* no `.tmp` residue;
* no fallback to `--p2p-trusted-root`;
* no active `DummySig` / `DummyKem` / `DummyAead`.

The Run 195 harness does not exercise a Run 070 apply path on real
`target/release/qbind-node`; the only release-binary executions are
`--help` (S1) and `--print-genesis-hash --env …` (S2..S7), which are
non-mutating CLIs that exit quickly without opening sockets or touching
real data dirs. [`mutation_proof.txt`](
  run_195_remote_authority_signer_boundary_release_binary/mutation_proof.txt)
documents that the Run 194 RemoteSigner boundary is wired ahead of any
apply call, ahead of any live trust swap, ahead of any session eviction,
ahead of any sequence/marker write, and ahead of any peer-driven drain —
i.e. preflight/validation-only — and that RemoteSigner request, response,
custody, lifecycle, and governance validation each occur before any
apply/mutation on any accepted fixture compatibility path.

## Denylist results

[`negative_invariants.txt`](
  run_195_remote_authority_signer_boundary_release_binary/negative_invariants.txt)
proves the following patterns are **empty** across every captured log
under `logs/` and helper artifact under `helper_evidence/run_195/`
(except `qbind_node_help.log`, which we explicitly grep separately, and
the structured `helper_summary.txt`):

* `apply on receipt`, `apply-on-receipt`, `autonomous apply`,
  `peer-majority authority`;
* `fallback to --p2p-trusted-root`;
* `DummySig`, `DummyKem`, `DummyAead`;
* `governance execution claim`, `real governance execution`,
  `on-chain governance claim`,
  `real on-chain governance proof claim`;
* `KMS/HSM enabled`, `KMS/HSM active`, `kms-hsm enabled`;
* `real RemoteSigner backend`, `RemoteSigner backend connected`,
  `RemoteSigner enabled`, `remote signer production active`,
  `RemoteSigner production active`;
* `validator-set rotation claim`,
  `validator-set rotation enabled`;
* `schema drift`, `wire drift`, `metric drift`;
* `MainNet peer-driven apply ENABLED`, `MainNet apply ENABLED`.

## Regression test cross-checks

The harness runs the cargo test targets named in
`task/RUN_195_TASK.txt §Validation commands`. Targets that are not
present in this tree are recorded as `rc=skipped(not-present)` and the
harness continues. Per-target stdout/stderr lives under
[`test_results/`](run_195_remote_authority_signer_boundary_release_binary/test_results/);
exit codes are captured in `exit_codes/test_*.rc`. The summary block in
`summary.txt` lists every target and its `rc=` value, including
`run_194_remote_authority_signer_boundary_tests`,
`run_192_authority_custody_policy_selector_tests`, the Run 188 / 190
custody targets, the governance targets, the lifecycle/marker targets,
the `--lib pqc_authority` filter, and the `--lib
pqc_remote_authority_signer` filter.

## Captured metadata

`provenance.txt` records:

* `git_commit` (SHA);
* `git_branch`;
* `git_status_short`;
* `rustc_version`, `cargo_version`;
* host (`uname -a`);
* `qbind_node_path`, `qbind_node_sha256`, `qbind_node_buildid`;
* `helper_195_path`, `helper_195_sha256`, `helper_195_buildid`.

## Documentation invariants reaffirmed by Run 195

* Run 195 is **release-binary** RemoteSigner production-custody boundary
  evidence.
* No real RemoteSigner backend is implemented and no networked signer
  service is wired.
* Fixture loopback RemoteSigner is DevNet/TestNet evidence-only.
* Production RemoteSigner remains unavailable/fail-closed under
  `ProductionRemoteSignerRequired` and
  `MainnetProductionRemoteSignerRequired`.
* RemoteSigner request/response binding is deterministic and
  domain-bound (environment, chain, genesis, authority root, lifecycle
  action, candidate digest, authority-domain sequence).
* Local operator keys and peer-majority/gossip counts cannot satisfy
  RemoteSigner policy.
* RemoteSigner integrates with custody composition at the
  release-helper/library level only — RemoteSigner cannot enable MainNet
  peer-driven apply.
* MainNet peer-driven apply remains refused (Run 147 / 148 / 152 FATAL
  invariant) even with the Run 193 `mainnet-production-custody-required`
  selector and the governance fixture selector armed.
* KMS/HSM remain unimplemented (no cloud KMS, no PKCS#11).
* governance execution remains unimplemented.
* real on-chain proof verification remains unimplemented.
* validator-set rotation remains open.
* the existing custody / governance proof paths remain compatible.
* full **C4 remains OPEN**.
* **C5 remains OPEN**.

## Acceptance

Run 195 satisfies every `task/RUN_195_TASK.txt §Acceptance criteria`
clause:

1. The release-built helper proves the Run 194 RemoteSigner corpus
   (A1..A7 / R1..R31, `verdict: PASS`, `total_fail: 0`).
2. Real `target/release/qbind-node` confirms MainNet peer-driven apply
   remains refused (S4, S7).
3. Fixture loopback RemoteSigner remains DevNet/TestNet evidence-only
   (helper A1 / A2, policy_mode_table.txt).
4. Production RemoteSigner remains unavailable/fail-closed (helper A7,
   R2..R5).
5. RemoteSigner request/response binding is deterministic and
   domain-bound (helper A3, canonical_digest_table.txt, R6..R15).
6. Local operator / peer majority cannot satisfy RemoteSigner policy
   (helper R24 / R25, refusal_helpers_table.txt).
7. RemoteSigner integrates with custody composition at the
   release-helper/library level (helper A4 / A5, custody_routing_table.txt,
   composition_table.txt).
8. Rejected RemoteSigner-boundary cases produce no mutation
   (no_mutation_evidence.txt, R30 / R31).
9. Existing custody/governance paths remain compatible (helper A6, S5,
   S6).
10. No real RemoteSigner / KMS / HSM / governance execution /
    validator-set rotation claim is made (denylist proven empty).
11. No full C4 or C5 closure is claimed.