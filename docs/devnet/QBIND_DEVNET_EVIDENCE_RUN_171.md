# QBIND DevNet Evidence — Run 171

Run 171 is the **source/test SELECTOR WIRING** that introduces a
**hidden, explicit, disabled-by-default operator selector** for the
`GovernanceProofPolicy::RequiredForLifecycleSensitive` policy and
routes it through the four production v2 marker-decision preflight
contexts wired by Run 169 (`pqc_governance_proof_surface::preflight_v2_marker_decision_with_governance_proof_load`).

It is the natural sequel to Run 170. Run 170 evidenced — on real
release binaries — the Run 169 wiring of the Run 167 typed
governance-proof loader through the four production preflights under
the default `GovernanceProofPolicy::NotRequired`, and explicitly
declared as an *honest limitation* that lifting the binary to expose a
configurable `RequiredForLifecycleSensitive` toggle was operator-control
plumbing intentionally **deferred**. Run 171 lands exactly that
operator-control plumbing at the **source/test level only**.

Run 171 carries **no release-binary production-surface evidence**;
that is deferred to Run 172.

This evidence file is the canonical follow-up to
`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_170.md`.

## Scope

Per `task/RUN_171_TASK.txt`, Run 171 is **source/test selector wiring
only**:

* A **hidden** Required-policy selector exists:
  * CLI flag `--p2p-trust-bundle-governance-proof-required`
    (declared with `clap` `hide = true`, so it does not appear in
    `--help`);
  * environment variable
    `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED`;
  * recognized truthy values: `1`, `true`, `yes`, `on`
    (case-insensitive; any other value — including empty, `0`,
    `false` — leaves the selector disabled).
* The CLI flag and the environment variable are **OR-combined**:
  either source alone is sufficient to enable the Required policy.
* Selector helpers (in
  `crates/qbind-node/src/pqc_governance_proof_surface.rs`):
  * `governance_proof_required_env_selector_enabled`;
  * `governance_proof_policy_from_selector`;
  * `governance_proof_policy_from_cli_or_env`.
* The **default policy remains `GovernanceProofPolicy::NotRequired`**
  (flag unset and env var unset/falsey). Pre-Run-167 no-proof v2
  sidecars remain compatible exactly as before.
* The Required policy, when enabled, is routed through the Run 169
  shim across the production v2 marker-decision surfaces:
  * reload-check;
  * reload-apply;
  * startup `--p2p-trust-bundle`;
  * SIGHUP;
  * peer-driven `ProductionV2MarkerCoordinator`.
* `LiveReloadConfig.governance_proof_policy` is added and consumed by
  `preflight_sighup_v2_marker_decision`.

Under the Required policy at the source/test level:

* valid proof-carrying sidecars **pass**;
* missing / invalid proof sidecars **fail closed**;
* validation-only surfaces remain **non-mutating**;
* mutating surfaces still persist the marker **only after** the
  Run 055 / Run 070 sequence-commit boundary;
* **MainNet peer-driven apply remains refused** even with the
  Required policy enabled and a valid proof present — the refusal is
  owned by the Run 130 environment policy and is unchanged by
  Run 171.

Run 171 does **not**:

* enable MainNet peer-driven apply on any surface;
* change CLI behavior visible in `--help` (the flag is hidden) or any
  default behavior (default remains `NotRequired`);
* change any wire / marker / sequence / trust-bundle / metric schema
  or behavior;
* implement governance execution;
* implement on-chain governance (`OnChainGovernance` remains
  unsupported / fail-closed);
* implement KMS/HSM custody;
* implement validator-set rotation;
* claim full C4 or C5 closure.

`OnChainGovernance` remains unsupported / fail-closed. The fixture
issuer-signature verifier remains the only verifier wired into
production callers; real-issuer-key (KMS / HSM-backed) verifier
installation remains deferred. Validator-set rotation remains open.

## Verdict

**`positive (source/test selector wiring): a hidden,
disabled-by-default Required-policy selector
(--p2p-trust-bundle-governance-proof-required with clap hide=true, OR
the QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_PROOF_REQUIRED env var with
truthy values 1|true|yes|on) resolves through
governance_proof_policy_from_cli_or_env to
GovernanceProofPolicy::RequiredForLifecycleSensitive and is routed
through the Run 169 shim across all production v2 marker-decision
preflight contexts; default remains NotRequired so old no-proof v2
sidecars stay compatible; valid proof-carrying sidecars pass under
Required while missing/invalid proofs fail closed; validation-only
surfaces stay non-mutating; mutating surfaces persist the marker only
after the sequence-commit boundary; MainNet peer-driven apply remains
refused even with Required enabled and a valid proof.`**

Release-binary Required-policy production-surface evidence is
deferred to Run 172.

## Honest limitation (Run 171 strict scope)

Run 171 is **source/test only**. It adds the operator-control
selector and exercises the Required policy across the production
preflight contexts at the source/test level, but it does **not**
capture release-binary evidence of the Required policy on real
`target/release/qbind-node`. That release-binary Required-policy
production-surface evidence is **deferred to Run 172**.

Governance execution remains unimplemented; on-chain governance
remains unsupported / fail-closed; KMS/HSM custody remains
unimplemented; validator-set rotation remains open. Full C4 remains
open; C5 remains open.

## Validation results (already run)

* **Run 171 suite** — `crates/qbind-node/tests/run_171_governance_required_policy_selector_tests.rs`:
  **35/35 passed**.
* **Regression targets passed**:
  * `run_169`
  * `run_167`
  * `run_165`
  * `run_163`
  * `run_161`
  * `run_159`
  * `run_157`
  * `run_152`
  * `run_150`
  * `run_148`
  * `run_142`
  * `run_134`
  * `run_138`
  * `run_074`
  * `run_114`
  * `run_121`
* `cargo test -p qbind-node --lib`: **1282 passed**.
* `codeql_checker`: see *CodeQL closure* below.

## CodeQL closure

`codeql_checker` was run as part of Run 171 closure. Result recorded
here:

* **Result:** no security alerts attributable to Run 171 changes.
* No production behavior changes were introduced during closure
  (documentation + selector-wiring source/test only, already landed).

## Inheritance from prior runs

Run 171 inherits and does not weaken the boundaries already evidenced
by:

* Run 170 — release-binary evidence of the Run 169 production-surface
  governance-proof loader wiring under `NotRequired` (default);
* Run 169 — wiring of the Run 167 typed governance-proof loader into
  the four production preflight call sites through the
  `preflight_v2_marker_decision_with_governance_proof_load` shim;
* Run 167 — typed governance-proof carrier surface and source-level
  matrix;
* Run 165 — governance marker gate
  (`evaluate_governance_marker_gate`,
  `decide_v2_marker_acceptance_with_lifecycle_and_governance`);
* Run 163 — governance authority verifier and typed reject variants;
* Run 130 — environment policy MainNet apply refusal;
* Run 070 — reload-apply ordering (sequence-before-marker);
* Run 055 — sequence commit boundary;
* Runs 050–170 — all prior trust-anchor / rotation / peer-driven
  apply invariants.

## Acceptance-criteria mapping (`task/RUN_171_TASK.txt`)

| # | Acceptance criterion (paraphrased) | Evidence in Run 171 |
|---|------------------------------------|---------------------|
| 1 | `QBIND_DEVNET_EVIDENCE_RUN_171.md` exists and accurately reflects the run | This document |
| 2 | All four required docs have append-only Run 171 entries | `docs/whitepaper/contradiction.md`, `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`, `docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`, `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` |
| 3 | `codeql_checker` has been run and the result recorded | *CodeQL closure* section above |
| 4 | No production behavior changes introduced during closure | Closure is documentation-only; default remains `NotRequired`; flag stays hidden; no schema/wire/metric change |
| 5 | No full C4 or C5 closure claimed | *Honest limitation* section above; full C4 and C5 remain open |
