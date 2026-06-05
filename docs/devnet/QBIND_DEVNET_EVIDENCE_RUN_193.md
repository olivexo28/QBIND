# QBIND DevNet evidence — Run 193

**Title.** Release-binary evidence for the Run 192 hidden authority-
custody policy selector and the seven per-surface preflight wrappers.

**Status.** PASS (release-binary). Run 193 closes the Run 192-deferred
release-binary boundary by exercising the hidden authority-custody
policy selector and the per-surface preflight wrappers on real
`target/release/qbind-node` and through the release-built helper
[`run_193_authority_custody_policy_release_binary_helper`](
  ../../crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs).
The default
[`AuthorityCustodyPolicy::Disabled`](../../crates/qbind-node/src/pqc_authority_custody.rs)
is preserved bit-for-bit when neither CLI nor env selector is set;
the hidden CLI flag remains hidden from `--help`; CLI-over-env
precedence is deterministic at the binary surface; invalid selector
values fail closed; MainNet peer-driven apply remains the Run 147 /
148 / 152 FATAL refusal even with
`mainnet-production-custody-required` armed on env+CLI together with
the Run 187 hidden fixture selector.

**Strict scope.**

* Release-binary evidence only.
* Use real `target/release/qbind-node`.
* Use the release-built Run 193 helper to drive the Run 192 A1–A12 /
  R1–R29 selector + preflight corpus through the production library
  symbols.
* No production-source change.
* No real KMS / HSM / cloud KMS / PKCS#11 / remote-signer backend.
* No MainNet peer-driven apply enablement.
* No governance execution engine.
* No real on-chain proof verifier.
* No validator-set rotation.
* No autonomous apply / no apply on receipt / no peer-majority
  authority.
* No marker / sequence-file / authority-marker / trust-bundle core /
  ratification-sidecar / wire / schema change.
* Run 193 does not weaken any prior run (Runs 070, 130–192) and does
  not claim full C4 or C5 closure.

## Run 193 deliverables

* Release-binary helper:
  [`crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs`](
    ../../crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs).
* Release-binary harness:
  [`scripts/devnet/run_193_authority_custody_policy_release_binary.sh`](
    ../../scripts/devnet/run_193_authority_custody_policy_release_binary.sh).
* Evidence archive:
  [`docs/devnet/run_193_authority_custody_policy_release_binary/`](
    run_193_authority_custody_policy_release_binary/).
* Canonical evidence report (this file).
* Append-only updates in:
  * [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md)
  * [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md)
  * [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
      ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md)
  * [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
      ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md)

## Real-binary surface evidence

The harness drives real `target/release/qbind-node` across eight
release-binary scenarios (S1–S8). Per-scenario stdout/stderr,
exit codes, SHA-256, and ELF Build ID are captured under
[`docs/devnet/run_193_authority_custody_policy_release_binary/logs/`](
  run_193_authority_custody_policy_release_binary/logs/) and
[`exit_codes/`](run_193_authority_custody_policy_release_binary/exit_codes/);
binary provenance lives in `provenance.txt`; per-scenario assertions
are encoded in the harness `assert_grep` / `assert_not_grep` helpers.

| Scenario | Invocation | Required invariant |
| --- | --- | --- |
| **S1** | `qbind-node --help` | hidden flag `--p2p-trust-bundle-authority-custody-policy` is **NOT** advertised; no `(?i)authority.?custody`; no KMS/HSM; no remote-signer; no Run 188 / 191 / 192 / 193 banner. |
| **S2** | `--print-genesis-hash --env devnet` (no env, no CLI) | default `Disabled`; no KMS/HSM enabled; no production-custody enabled; no MainNet peer-driven apply ENABLED; no validator-set rotation; no autonomous apply. |
| **S3** | `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=fixture-only --print-genesis-hash --env devnet` | env selector activates the policy without drifting any banner. |
| **S4** | `--print-genesis-hash --env devnet --p2p-trust-bundle-authority-custody-policy devnet-local-allowed` | CLI selector activates the policy without drifting any banner. |
| **S5** | env=`fixture-only`, CLI=`disabled` (DevNet) | CLI-over-env precedence resolves to `Disabled` at the binary surface; no KMS/HSM enabled, no production-custody enabled, no MainNet peer-driven apply ENABLED. |
| **S6** | `--p2p-trust-bundle-authority-custody-policy garbage` (DevNet) | clap typed parser rejects the value (non-zero exit-code allowed); no MainNet apply / KMS/HSM / production-custody banner emitted. |
| **S7** | env=`mainnet-production-custody-required`, CLI=`mainnet-production-custody-required` (MainNet startup) | no MainNet peer-driven apply ENABLED; no MainNet apply ENABLED; no KMS/HSM enabled; no production-custody enabled; no remote-signer enabled; no validator-set rotation; no autonomous apply. |
| **S8** | Run 192 selector + Run 187 fixture selector both armed (MainNet) | no MainNet peer-driven apply ENABLED; no KMS/HSM / production-custody banner. |

## Release-built helper evidence

The release-built helper
[`run_193_authority_custody_policy_release_binary_helper`](
  ../../crates/qbind-node/examples/run_193_authority_custody_policy_release_binary_helper.rs)
exercises the Run 192 A1–A12 / R1–R29 selector + preflight wrapper
corpus end-to-end in **release mode** through the production library
symbols `pqc_authority_custody_policy_surface::*`,
`pqc_authority_custody_payload_carrying::*`, and
`pqc_authority_custody::*`. The helper does NOT alter any production
source; it only **reads** the typed surface.

The helper writes:

* `manifest.txt` — A1..A12 / R1..R29 corpus index;
* `scenarios/<id>/{note.txt, expected.txt, policy.txt, outcome.txt,
  determinism.txt, …}` — per-scenario evidence;
* `selector_parser_table.txt` — the typed parser table:
  every supported value resolves to the expected policy and every
  unsupported value resolves to
  `AuthorityCustodyPolicySelectorParseError::UnknownValue { value }`,
  with `Empty` covered by the empty-string case;
* `precedence_table.txt` — CLI-over-env precedence cases, including
  cli=Some + env=Some (CLI wins), cli=Some + env=None (CLI wins),
  cli=None + env=Some (env wins), cli=None + env=None (Disabled);
* `preflight_wrappers_table.txt` — the seven per-surface preflight
  wrappers (`reload_check`, `reload_apply`,
  `startup_p2p_trust_bundle`, `sighup`, `local_peer_candidate_check`,
  `live_inbound_0x05`, `peer_driven_drain`) each route the resolved
  policy into the matching Run 190 typed routing helper;
* `binding_mismatch_table.txt` — Run 188 typed binding-mismatch cases
  (wrong environment / chain / genesis / authority-root /
  signing-key fingerprint / candidate digest / authority-domain
  sequence / lifecycle action / expired attestation / custody
  key-id mismatch / unsupported custody suite / malformed payload)
  routed under every selectable policy with `FixtureOnly`;
* `no_mutation_evidence.txt` — for every rejected scenario, candidate
  and persisted snapshots taken **before** and **after** the
  rejecting selector / preflight / validator / routing dispatch are
  bit-equal;
* `determinism_evidence.txt` — every scenario re-evaluated under
  identical inputs reproduces the typed outcome bit-for-bit;
* `helper_summary.txt` — the canonical PASS/FAIL verdict line and
  per-table tallies (`scenarios_pass`, `parser_pass`,
  `precedence_pass`, `wrappers_pass`, `binding_mismatch_pass`,
  `no_mutation_pass`, `determinism_pass`).

The helper exits non-zero if any tally has `*_fail > 0` and the
harness fails the run.

## Production-call-site reachability

[`reachability/source_reachability.txt`](
  run_193_authority_custody_policy_release_binary/reachability/source_reachability.txt)
records `grep -RIn --include='*.rs'` evidence for every Run 192 / 190
/ 188 typed symbol the helper exercises against
`crates/qbind-node/src/`, including:

* the new Run 192 surface module
  `pqc_authority_custody_policy_surface`;
* `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY` and the public
  const `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY_ENV`;
* the hidden CLI field
  `p2p_trust_bundle_authority_custody_policy` in
  [`crates/qbind-node/src/cli.rs`](../../crates/qbind-node/src/cli.rs)
  (clap `hide = true`);
* `AuthorityCustodyPolicySelectorParseError` (`Empty` /
  `UnknownValue`);
* `authority_custody_policy_from_selector`,
  `authority_custody_policy_env_selector`,
  `authority_custody_policy_from_cli_or_env`;
* the seven `preflight_v2_marker_authority_custody_for_*` wrappers;
* every `AuthorityCustodyPolicy` variant
  (`Disabled` / `FixtureOnly` / `DevnetLocalAllowed` /
  `TestnetLocalAllowed` / `ProductionCustodyRequired` /
  `MainnetProductionCustodyRequired`);
* every `AuthorityCustodyClass` variant
  (`FixtureLocalKey` / `LocalOperatorKey` / `RemoteSigner` /
  `Kms` / `Hsm` / `Unknown`);
* `validate_authority_custody_attestation`,
  `validate_lifecycle_governance_and_custody`;
* the three named helpers
  (`mainnet_peer_driven_apply_remains_refused_under_custody_boundary`,
  `peer_majority_cannot_satisfy_custody`,
  `local_operator_config_alone_cannot_satisfy_mainnet_production_custody`);
* the Run 190 routing helpers
  `route_loaded_authority_custody_attestation_to_*_callsite_decision`,
  `parse_optional_authority_custody_attestation_sibling_from_json_value`,
  and `mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying`;
* the Run 190 typed payload-carrying types
  `AuthorityCustodyAttestationWire`, `AuthorityCustodyLoadStatus`,
  `AuthorityCustodyCallsiteContext`,
  `AuthorityCustodyPayloadCarryingDecisionOutcome`.

## Mutation / no-mutation evidence

For every rejected selector / preflight / validator / routing
scenario in the helper corpus, [`no_mutation_proof.txt`](
  run_193_authority_custody_policy_release_binary/no_mutation_proof.txt)
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

The Run 193 harness does not exercise a Run 070 apply path on real
`target/release/qbind-node`; the only release-binary executions are
`--help` (S1) and `--print-genesis-hash --env …` (S2..S8), which
are non-mutating CLIs that exit quickly without opening sockets or
touching real data dirs. [`mutation_proof.txt`](
  run_193_authority_custody_policy_release_binary/mutation_proof.txt)
documents that the Run 192 selector is wired ahead of any apply call,
ahead of any live trust swap, ahead of any session eviction, ahead of
any sequence/marker write, and ahead of any peer-driven drain — i.e.
preflight-only.

## Denylist results

[`negative_invariants.txt`](
  run_193_authority_custody_policy_release_binary/negative_invariants.txt)
proves the following patterns are **empty** across every captured
log under `logs/` and helper artifact under `helper_evidence/run_193/`
(except `qbind_node_help.log`, which we explicitly grep separately,
and the structured `helper_summary.txt`):

* `apply on receipt`, `apply-on-receipt`, `autonomous apply`,
  `peer-majority authority`;
* `fallback to --p2p-trusted-root`;
* `DummySig`, `DummyKem`, `DummyAead`;
* `governance execution claim`,
  `on-chain governance claim`,
  `real on-chain governance proof claim`;
* `KMS/HSM enabled`, `KMS/HSM active`, `kms-hsm enabled`;
* `remote signer enabled`, `remote signer production active`;
* `production custody enabled`,
  `production custody active`,
  `production custody wired`;
* `validator-set rotation claim`,
  `validator-set rotation enabled`;
* `schema drift`, `wire drift`, `metric drift`;
* `MainNet peer-driven apply ENABLED`, `MainNet apply ENABLED`.

## Regression test cross-checks

The harness runs the cargo test targets named in
`task/RUN_193_TASK.txt §Validation commands`. Targets that are not
present in this tree are recorded as `rc=skipped(not-present)` and the
harness continues. Per-target stdout/stderr lives under
[`test_results/`](run_193_authority_custody_policy_release_binary/test_results/);
exit codes are captured in `exit_codes/test_*.rc`. The summary block
in `summary.txt` lists every target and its `rc=` value.

## Captured metadata

`provenance.txt` records:

* `git_commit` (SHA);
* `git_branch`;
* `git_status_short`;
* `rustc_version`, `cargo_version`;
* host (`uname -a`);
* `qbind_node_path`, `qbind_node_sha256`, `qbind_node_buildid`;
* `helper_193_path`, `helper_193_sha256`, `helper_193_buildid`.

## Documentation invariants reaffirmed by Run 193

* Run 193 is **release-binary** authority-custody policy selector
  evidence.
* Default remains `AuthorityCustodyPolicy::Disabled`.
* The hidden CLI selector
  `--p2p-trust-bundle-authority-custody-policy <POLICY>` activates
  the typed `AuthorityCustodyPolicy` when set; clap `hide = true`
  keeps it out of normal `--help`.
* The env selector
  `QBIND_P2P_TRUST_BUNDLE_AUTHORITY_CUSTODY_POLICY=<POLICY>`
  activates the typed policy when set.
* CLI-over-env precedence is deterministic — at the typed boundary
  (helper precedence table) and at the binary surface (S5).
* Invalid selector values fail closed via
  `AuthorityCustodyPolicySelectorParseError`.
* Fixture / local-operator custody remains DevNet/TestNet
  evidence-only.
* Fixture / local custody cannot satisfy MainNet production custody
  (`FixtureCustodyRejectedForMainNet` /
  `LocalCustodyRejectedForMainNet`).
* `Kms` / `Hsm` / `RemoteSigner` placeholders remain fail-closed at
  the typed validator under every policy.
* MainNet peer-driven apply remains refused even with
  `mainnet-production-custody-required` and metadata claiming KMS /
  HSM, with or without the Run 187 fixture selector armed.
* No real KMS / HSM / cloud-KMS / PKCS#11 / remote-signer backend is
  implemented.
* governance execution remains unimplemented.
* real on-chain proof verification remains unimplemented.
* validator-set rotation remains open.
* the existing no-custody and governance fixture paths remain
  compatible; default Disabled accepts no-custody payloads exactly
  as in Run 190 / Run 191 / Run 192.
* full **C4 remains OPEN**.
* **C5 remains OPEN**.

## Acceptance

Run 193 satisfies every `task/RUN_193_TASK.txt §Acceptance criteria`
clause:

1. Real release binaries exercise the hidden authority-custody policy
   selector across S1..S8 and through the release-built helper.
2. Default `Disabled` is proven (S2, helper A1).
3. CLI selector and env selector both work (helper A2..A9, S3, S4).
4. CLI-over-env precedence is proven at the typed boundary (helper
   A10, precedence_table.txt) and at the binary surface (S5).
5. Invalid selector values fail closed (helper R1..R3, S6).
6. Valid DevNet/TestNet fixture/local custody metadata passes only
   where the selected policy allows (helper A4..A7, R4..R11).
7. KMS/HSM/RemoteSigner placeholders remain fail-closed (helper
   R12..R14, binding_mismatch_table.txt).
8. MainNet peer-driven apply remains refused even with
   `MainnetProductionCustodyRequired` and metadata claiming KMS/HSM
   (helper R29, S7, S8).
9. Rejected custody-policy cases produce no mutation
   (no_mutation_evidence.txt, R26, R27).
10. Existing governance proof paths remain compatible (helper A12,
    `--p2p-trust-bundle-onchain-governance-fixture-allowed` armed in
    S8).
11. No real KMS/HSM, governance execution, real on-chain proof, or
    validator-set rotation claim is made (denylist proven empty).
12. No full C4 or C5 closure is claimed.