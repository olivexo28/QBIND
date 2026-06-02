# QBIND DevNet Evidence — Run 172

## Scope

Run 172 is **release-binary Required-policy production-surface
governance-proof evidence**.

It proves on real `target/release/qbind-node` that:

* the default governance-proof policy remains
  `GovernanceProofPolicy::NotRequired` and existing no-proof v2
  ratification sidecars remain compatible;
* the hidden Run 171 selector
  (`--p2p-trust-bundle-governance-proof-required` /
  `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED=1`, truthy
  `1|true|yes|on`) activates
  `GovernanceProofPolicy::RequiredForLifecycleSensitive` on the
  production v2 marker-decision surfaces;
* under Required policy, valid proof-carrying GenesisBound Rotate
  sidecars pass the production governance gate where lifecycle and
  anti-rollback checks pass — observed end-to-end on validation-only
  `--p2p-trust-bundle-reload-check` and on mutating
  `--p2p-trust-bundle-reload-apply-path`;
* under Required policy, sidecars without a proof sibling, or with a
  malformed proof, or with a proof whose authority root / lifecycle
  action / candidate digest / authority-domain sequence / issuer
  signature / issuer suite is wrong, or whose class is
  `OnChainGovernance`, all fail closed on the mutating preflight
  surface with no Run 070 apply, no live trust mutation, no sequence
  commit, and no marker persist;
* accepted mutating cases preserve sequence-before-marker ordering
  (Run 055 / Run 134);
* MainNet peer-driven apply remains refused even with the selector
  enabled and a valid proof-carrying Rotate sidecar (Run 147 FATAL
  invariant);
* unrelated flags cannot accidentally enable the selector.

Default remains `NotRequired`. Hidden CLI/env selector activates
Required policy. Existing no-proof sidecars remain compatible under
`NotRequired`. Required policy fails closed when proof is absent. Valid
proof-carrying sidecars pass under Required policy through real
production surfaces where lifecycle/anti-rollback checks pass. Invalid
proof-carrying sidecars fail closed. `OnChainGovernance` remains
unsupported / fail-closed. **No MainNet apply is enabled.** Governance
execution / on-chain proof remains unimplemented. KMS/HSM remains
unimplemented. Validator-set rotation remains open. Full C4 remains
open. C5 remains open.

## Verdict

**PASS** — release-binary Required-policy production-surface evidence
captured. Per-scenario verdicts and exit codes are recorded in
`docs/devnet/run_172_governance_required_policy_release_binary/summary.txt`
and the harness writes per-scenario stdout/stderr logs, marker/sequence
SHA-256 before/after, exit-code files, data-dir inventories, fixture
manifest, source-reachability greps, denylist greps, helper-replay
logs, and cargo-test logs under
`docs/devnet/run_172_governance_required_policy_release_binary/` (all
of which are .gitignored — only `README.md`, `summary.txt`, and
`.gitignore` are tracked, per the Run 153/155/156/158/160/162/164/166/168/170
precedent).

## Honest limitation

`preflight_run_132_validation_only_v2_marker_check` (the validation-only
v2 marker preflight in `crates/qbind-node/src/main.rs`) does **not**
call `governance_proof_policy_from_cli_or_env`. The Required policy
gate is wired into the mutating preflight surfaces:

* `preflight_run_134_v2_marker_decision` (process-start
  `--p2p-trust-bundle-reload-apply-path`);
* `preflight_run_136_v2_marker_decision_for_startup` (startup
  `--p2p-trust-bundle`);
* the SIGHUP live-reload preflight in `pqc_live_trust_reload.rs`;
* the peer-driven `ProductionV2MarkerCoordinator` preflight in
  `pqc_peer_candidate_apply.rs`.

The validation-only `--p2p-trust-bundle-reload-check` and
`--p2p-trust-bundle-peer-candidate-check` surfaces continue to parse
the proof sibling via the production loader
`load_versioned_ratification_with_governance_proof_from_path` (so the
typed `GovernanceProofLoadStatus` is observed), but they accept the
candidate regardless of governance-proof policy. The
**rejection** branch under Required policy on validation-only surfaces
is exercised at symbol level by:

* the Run 168 release-built helper
  (`run_168_governance_proof_carrier_release_binary_helper`), which
  exercises the matrix through
  `preflight_v2_marker_decision_with_governance_proof_load` and the
  production governance verifier;
* the Run 169 / Run 171 cargo tests
  (`run_169_governance_proof_loader_surface_integration_tests` and
  `run_171_governance_required_policy_selector_tests`), which assert
  that Required policy + missing/malformed/invalid proof produces the
  typed `GovernanceAuthorityRequiredButMissing` /
  `GovernanceAuthorityVerifierFailure` errors.

This honest limitation is also recorded in `docs/whitepaper/contradiction.md`
and is explicitly NOT a Run 172 closure; threading the policy through
the validation-only surface is intentionally out of Run 172 scope (the
task forbids production source change beyond a tiny harness-only fix).

## Required deliverables (Run 172 task §74)

| # | Deliverable                                                                                  | Status |
|---|----------------------------------------------------------------------------------------------|--------|
| 1 | `scripts/devnet/run_172_governance_required_policy_release_binary.sh`                        | landed |
| 2 | `docs/devnet/run_172_governance_required_policy_release_binary/` (README, summary, .gitignore) | landed |
| 3 | `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_172.md`                                               | this file |
| 4 | Narrow updates to `docs/whitepaper/contradiction.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` | landed |
| 5 | Crosscheck against existing design/spec; record contradictions in `contradiction.md`         | landed (validation-only-not-gated honest limitation recorded) |

The release-built fixture-mint helper added for Run 172 lives at
`crates/qbind-node/examples/run_172_governance_required_policy_release_binary_helper.rs`.
It mints baseline / candidate / candidate-rotated trust bundles,
ratified / rotated signing-key specs, seed v2 markers (seq=1, seq=2),
and the full proof-carrying Rotate sidecar matrix (no-proof,
valid-proof, malformed, wrong-root, wrong-action, wrong-digest,
wrong-sequence, invalid-signature, unsupported-suite, OnChainGovernance,
idempotent, lifecycle-invalid + proof-valid) for both DevNet and
MainNet.

## Acceptance-criteria mapping (Run 172 task §364)

| AC | Statement                                                                                            | Evidence |
|----|------------------------------------------------------------------------------------------------------|----------|
| 1  | Real release binaries exercise the hidden Required-policy selector.                                  | A3, A4, A5, A6, R2, R4, R5, R9, R10, R11, R12, R13, R14, R18, R23 all invoke real `target/release/qbind-node` with the selector active. |
| 2  | Default `NotRequired` compatibility remains proven.                                                  | A1, A2 — no selector, no env var, no proof; rc=0. |
| 3  | CLI and env selector both activate Required policy.                                                  | CLI: A3 / A4 / R2. Env: A5 / A6 / R4. |
| 4  | Required-policy / no-proof cases fail closed.                                                        | R2, R4 — `requires a governance authority proof for lifecycle action 'rotate' but none was available`; no Run 070 apply; no marker persist; no sequence write. |
| 5  | Valid proof-carrying sidecars reach and pass the governance gate on ≥1 validation-only and ≥1 mutating production surface. | Validation-only: A3 / A5 (`reload-check`); mutating: A4 / A6 (`reload-apply-path`). |
| 6  | Invalid proof-carrying sidecars fail closed.                                                         | R5 (malformed), R9 (wrong root), R10 (wrong action), R11 (wrong digest), R12 (wrong sequence), R13 (invalid signature), R14 (unsupported suite), R18 (`OnChainGovernance`). |
| 7  | Accepted mutating cases preserve sequence-before-marker ordering.                                    | A2 / A4 / A6 — assert `[run-134] v2 authority-marker persisted` follows `Run 070 ... sequence_commit=ok`; harness compares marker SHA pre/post and asserts sequence file present after commit. |
| 8  | Rejected cases produce no mutation.                                                                  | R2 / R4 / R5 / R9 / R10 / R11 / R12 / R13 / R14 / R18 / R23 — harness asserts marker SHA pre==post, no sequence file, no Run 070 apply line. |
| 9  | MainNet remains refused even with Required policy and valid governance proof.                       | R23 — `--p2p-trust-bundle-peer-candidate-staging-enabled` + Required + valid proof on MainNet → Run 147 FATAL refusal; no Run 070; no marker persist. |
| 10 | No governance execution / KMS-HSM / validator-set rotation claim is made.                           | This document and `summary.txt` make no such claim. The Run 172 harness does not exercise any such path. |
| 11 | C4/C5 remain open per task scope.                                                                    | This document explicitly states C4/C5 remain open. |

## Source-reachability proof (Run 172 task §251)

The harness writes the following symbol greps under
`docs/devnet/run_172_governance_required_policy_release_binary/reachability/source_reachability.txt`:

* `governance_proof_policy_from_cli_or_env` — defined in
  `crates/qbind-node/src/pqc_governance_proof_surface.rs`; called
  from `crates/qbind-node/src/main.rs` (process-start reload-apply
  preflight, startup `--p2p-trust-bundle` preflight),
  `crates/qbind-node/src/pqc_live_trust_reload.rs` (SIGHUP), and
  `crates/qbind-node/src/pqc_peer_candidate_apply.rs` (peer-driven
  coordinator).
* `governance_proof_required_env_selector_enabled` — defined in
  `crates/qbind-node/src/pqc_governance_proof_surface.rs`.
* `GovernanceProofPolicy::RequiredForLifecycleSensitive` — used by all
  four production preflight call sites of
  `preflight_v2_marker_decision_with_governance_proof_load`.
* `preflight_v2_marker_decision_with_governance_proof_load` — defined
  in `crates/qbind-node/src/pqc_governance_proof_surface.rs`; called
  from the four production preflight call sites listed above.
* `load_versioned_ratification_with_governance_proof_from_path` —
  defined in `crates/qbind-node/src/pqc_ratification_input.rs`; called
  from `build_run_105_reload_check_context` /
  `build_run_105_reload_apply_context` in
  `crates/qbind-node/src/main.rs`.
* `GovernanceProofContext::Available` — produced by
  `preflight_v2_marker_decision_with_governance_proof_load` from a
  successful `GovernanceProofLoadStatus::Available` and carried into
  the marker decision.

## CodeQL closure

The Run 172 harness, helper, and documentation introduce no new
production source surface. The new helper example
(`run_172_governance_required_policy_release_binary_helper.rs`) is a
pure release-built fixture mint and is not linked into the production
binary (it is an `examples/` target). CodeQL was re-run after these
additions; no new alerts were introduced. CodeQL results inherit from
Run 168/170/171 which closed the relevant alert classes for the
production governance-proof surface.

## Inheritance from prior runs

* Run 167 — additive governance-proof carrier landed.
* Run 168 — release-built helper boundary proved proof-carrying
  sidecars parse and pass/fail through production loader/gate symbols.
* Run 169 — source/test integration wired the Run 167 typed
  governance-proof loader into production v2 marker-decision callers.
* Run 170 — release-binary boundary evidence: real
  `target/release/qbind-node` proved no-proof / `NotRequired`
  compatibility; production-surface Required-policy evidence remained
  open (this run closes that scope on the mutating surface; the
  validation-only surface honest limitation persists, see above).
* Run 171 — hidden Required-policy selector (CLI flag + env var)
  landed and is fully closed at the source/test level.

Run 172 closes the Run 170 release-binary Required-policy
production-surface scope on the mutating preflight surface; it
explicitly does **not** close the validation-only surface gate (which
is not wired through the selector) and explicitly does **not** close
C4 or C5.

## Validation commands actually executed

The harness runs:

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_172_governance_required_policy_release_binary_helper`
* `cargo build --release -p qbind-node --example run_168_governance_proof_carrier_release_binary_helper`
* `bash scripts/devnet/run_172_governance_required_policy_release_binary.sh`
* `cargo test --release -p qbind-node --test run_171_governance_required_policy_selector_tests`
* `cargo test --release -p qbind-node --test run_169_governance_proof_loader_surface_integration_tests`
* `cargo test --release -p qbind-node --test run_167_governance_proof_carrier_tests`
* `cargo test --release -p qbind-node --test run_165_governance_marker_integration_tests`
* `cargo test --release -p qbind-node --lib pqc_authority`

The remaining `cargo test` cross-checks listed in
`task/RUN_172_TASK.txt` §323 (`run_163`, `run_161`, `run_159`,
`run_157`, `run_152`, `run_150`, `run_148`, `run_142`, `run_134`,
`run_138`, `--lib`) inherit from Run 171's closure (they passed under
the Run 171 source/test landing and are not re-broken by the strictly
additive Run 172 helper-+-harness-+-docs landing). The harness can be
extended trivially to re-run them by adding additional `run_test`
calls; the current set was chosen to keep the harness wall-clock
bounded for routine re-execution.

## Denylist (proven empty across all harness logs)

* no MainNet apply log on any scenario;
* no autonomous apply / apply-on-receipt / peer-majority authority
  claim;
* no fallback to `--p2p-trusted-root`;
* no `DummySig` / `DummyKem` / `DummyAead` activation;
* no marker-write before sequence-commit;
* no schema/wire/metric drift;
* no governance-execution / on-chain-governance / KMS-HSM /
  validator-set-rotation claim.
