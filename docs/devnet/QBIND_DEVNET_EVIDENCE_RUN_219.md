# QBIND DevNet evidence — Run 219

**Title.** Governance execution runtime-surface gap audit and next-closure plan.

**Status.** Audit / spec / docs-only. Run 219 produces a source/docs audit
that maps every governance-execution runtime surface introduced by the Run
211–218 sequence, classifies each by evidence level, and selects the next
exact closure run sequence **from actual source inspection**. Run 219
implements **no new runtime behavior**, **no real governance execution
engine**, **no real on-chain governance proof verifier**, **no MainNet
enablement**, **no validator-set rotation**, and **no
KMS/HSM/RemoteSigner backend**. It makes **no production source, schema,
wire, marker, sequence, or trust-bundle change**.

## Scope and required statements

Run 219 records that:

* Run 219 is an **audit / spec run only**;
* **no new runtime behavior** is implemented;
* **no real governance execution engine** is implemented;
* **no real on-chain governance proof verifier** is implemented;
* fixture governance remains **DevNet/TestNet evidence-only**;
* the emergency council fixture remains **explicit and non-production**;
* production / on-chain / MainNet governance execution remains
  **unavailable / fail-closed**;
* **MainNet peer-driven apply remains refused**;
* **validator-set rotation remains unsupported**;
* KMS/HSM / RemoteSigner / custody-attestation remain **boundary-only**;
* **full C4 remains OPEN; C5 remains OPEN**.

## Deliverables

* Formal runtime-surface audit:
  [`docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md`](
    ../protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md).
* Canonical report: this file.
* Narrow doc updates:
  [`docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md`](
    ../protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md),
  [`docs/whitepaper/contradiction.md`](../whitepaper/contradiction.md),
  [`docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`](
    ../ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md),
  [`docs/protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md`](
    ../protocol/QBIND_PEER_DRIVEN_TRUST_BUNDLE_APPLY_SAFETY.md),
  [`docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`](
    ../protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md).

There is **no helper, no harness, and no release-binary archive** for Run
219 — none is required for an audit/spec run.

## What the audit inspected

The audit (see the companion document) classifies all relevant surfaces in
five groups:

* **Group A — selector and policy surfaces:**
  `pqc_governance_execution_policy_surface`,
  `governance_execution_policy_from_selector`,
  `governance_execution_policy_from_cli_or_env`, the CLI flag
  `--p2p-trust-bundle-governance-execution-policy`, and the env var
  `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY`.
* **Group B — runtime arming carrier:**
  `pqc_governance_execution_runtime_arming`,
  `GovernanceExecutionRuntimeArmingConfig`, `from_cli_or_env`,
  `arm_surface`, and the seven runtime/preflight wrappers.
* **Group C — payload / carrying:**
  `pqc_governance_execution_payload_carrying`, the optional
  `governance_execution` sidecar sibling, the combined v2 loader, and the
  seven callsite routing helpers.
* **Group D — runtime call sites:** reload-check, reload-apply, startup
  `--p2p-trust-bundle`, SIGHUP, local peer-candidate-check, live inbound
  `0x05`, and peer-driven drain.
* **Group E — compatibility surfaces:** governance proof policy selector
  (Runs 171/172), OnChainGovernance boundary (Runs 178–187), custody
  policy selector (Run 193), RemoteSigner policy selector (Run 199),
  custody-attestation policy selector (Run 210), KMS/HSM boundary (Runs
  203–204), and RemoteSigner transport boundary (Runs 201–202).

## Key findings

* **Group A (selectors):** fully wired and real-binary evidenced
  (Run 216/218). No further selector work required.
* **Group B (carrier):** partially wired. `from_cli_or_env` resolution is
  complete; the carrier is constructed on the live path and routes the
  armed policy into the preflight wrappers, but at every live call site
  the resolved outcome is **discarded** (`let _outcome = …`) and the
  payload load status is hard-coded `GovernanceExecutionLoadStatus::Absent`.
* **Group C (payload):** helper-evidenced and source/test complete, but
  **not consumed on the live path** — no long-running sidecar/connection
  format emits the `governance_execution` carrier today, so the live load
  status is always `Absent` (the same wire blocker as the Run 182
  on-chain governance hooks).
* **Group D (the seven runtime surfaces):**
  * reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP, and
    local peer-candidate-check are **partially wired** — a real
    long-running call site reaches the surface but the outcome is
    discarded and the carrier is `Absent`;
  * live inbound `0x05` and peer-driven drain are **helper-evidenced
    only** — no production call site invokes their preflight wrapper (the
    live `0x05` per-connection policy is not threaded; the real drain path
    `PeerDrivenDrainPolicy::try_drain_once` refuses MainNet independently
    and never calls `preflight_peer_driven_drain`).
* **Group E (compatibility):** every sibling surface is intentionally out
  of scope, independent, unchanged, and boundary-only or selector-only.

Across all seven runtime surfaces, rejection is non-mutating (no marker
write, no sequence write, no live trust swap, no session eviction, no Run
070 apply call) and **MainNet peer-driven apply remains refused**. The gap
is **consumption**, not safety: no surface yet reaches the
"real-binary long-running runtime + consumed" level.

## Required per-surface classification

| Runtime surface | Classification |
|---|---|
| reload-check | partially wired (also blocked by missing real governance engine) |
| reload-apply | partially wired (also blocked by missing real governance engine) |
| startup `--p2p-trust-bundle` | partially wired (also blocked by missing real governance engine) |
| SIGHUP | partially wired (also blocked by missing real governance engine) |
| local peer-candidate-check | partially wired (also blocked by missing real governance engine) |
| live inbound `0x05` | helper-evidenced only (per-connection policy not threaded) |
| peer-driven drain | helper-evidenced only (no production call site into the wrapper) |

## Decision: chosen next-run sequence

Because the audit confirms long-running runtime **consumption is
incomplete**, the chosen sequence is:

* **Run 220 — source/test long-running node governance-execution runtime
  consumption wiring.** Make the five reached surfaces consume the armed
  `GovernanceExecutionRuntimeArmingConfig` outcome on the long-running
  path instead of discarding it, and add real production call sites for
  the two helper-only surfaces where representable, keeping default
  `Disabled` bit-for-bit, failing closed on non-Disabled armed policies
  when the carrier is `Absent`, and keeping MainNet peer-driven apply
  refused.
* **Run 221 — release-binary long-running node governance-execution
  runtime consumption evidence.** Prove the Run 220 consumption on real
  `target/release/qbind-node` with the same invariants.

The alternate branch (Run 220 production governance execution evaluator
interface skeleton / Run 221 evaluator-boundary evidence) is **not**
selected, because the long-running runtime is not yet sufficiently wired.

These runs require **no** real governance engine, **no** real on-chain
verifier, **no** live `governance_execution` wire carrier, **no**
validator-set rotation, and **no** KMS/HSM/RemoteSigner backend; those
remain separate, later, explicitly scoped runs and the residual C4/C5
blockers.

## Contradiction crosscheck

The new and modified docs were crosschecked against the existing
design/spec (Runs 050–218 invariants and `contradiction.md`). **No new
contradiction is introduced** because Run 219 (i) is audit/spec/docs-only
and changes no production source, schema, wire, marker, sequence, or
trust-bundle semantics; (ii) reports the existing default-`Disabled`,
fail-closed, non-mutating, and MainNet-refused invariants without
weakening them; and (iii) selects a next-run sequence consistent with the
Run 218 honest limitation. The crosscheck result and the Run 219 entry are
recorded in `docs/whitepaper/contradiction.md`.

## Validation commands

```bash
grep -R "governance_execution_policy" crates/qbind-node/src crates/qbind-node/tests docs | head -200
grep -R "GovernanceExecutionRuntimeArmingConfig" crates/qbind-node/src crates/qbind-node/tests docs | head -200
grep -R "governance_execution" crates/qbind-node/src crates/qbind-node/tests docs | head -200
grep -R "Status as of Run 219" docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md
grep -R "Run 219" docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_219.md docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md docs/whitepaper/contradiction.md
cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests
cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests
cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests
cargo test -p qbind-node --test run_211_governance_execution_policy_tests
cargo test -p qbind-node --lib pqc_authority
```

## Observed results

| Command | Result |
|---|---|
| `grep -R "governance_execution_policy" …` | 326 matches |
| `grep -R "GovernanceExecutionRuntimeArmingConfig" …` | 54 matches |
| `grep -R "governance_execution" …` | 830 matches |
| `grep -R "Status as of Run 219" …CLOSURE_CRITERIA.md` | present |
| `grep -R "Run 219" …RUN_219.md …SURFACE_AUDIT.md contradiction.md` | present in all three |
| `cargo test … run_217_governance_execution_runtime_arming_tests` | ok. 45 passed; 0 failed |
| `cargo test … run_215_governance_execution_policy_selector_tests` | ok. 55 passed; 0 failed |
| `cargo test … run_213_governance_execution_payload_callsite_tests` | ok. 61 passed; 0 failed |
| `cargo test … run_211_governance_execution_policy_tests` | ok. 55 passed; 0 failed |
| `cargo test … --lib pqc_authority` | ok. 164 passed; 0 failed; 1181 filtered out |

All recorded results are PASS. Run 219 changes only documentation.

## Why C4 / C5 remain OPEN

Run 219 is audit/spec-only. It adds no real governance execution engine,
no real on-chain verifier, no KMS/HSM or RemoteSigner backend, no MainNet
governance enablement, no validator-set rotation, and no schema / wire /
marker / sequence / trust-bundle change. The audit confirms that the
long-running runtime consumes the armed policy only partially (five
surfaces reached but outcome discarded; two helper-only), and the chosen
Run 220/221 sequence wires consumption without making
production/on-chain/MainNet governance available and without weakening
MainNet peer-driven apply refusal. **Full C4 remains OPEN; C5 remains
OPEN.**