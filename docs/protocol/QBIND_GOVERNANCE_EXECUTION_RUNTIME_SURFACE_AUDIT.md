# QBIND Governance Execution Runtime Surface Audit

**Status as of Run 219:** Full **C4 remains OPEN**. **C5 remains OPEN**.

Run 219 is an **audit / spec / docs-only** run. It implements **no new
runtime behavior**, **no real governance execution engine**, **no real
on-chain governance proof verifier**, **no MainNet enablement**, **no
validator-set rotation**, and **no KMS/HSM/RemoteSigner backend**. It does
not touch production source, schema, wire, marker, sequence, or
trust-bundle semantics. Its sole purpose is to map every
governance-execution runtime surface that the Run 211–218 sequence
introduced, classify each surface by its current evidence level, and
choose — from actual source inspection rather than assumption — the next
exact closure run sequence.

This document is the formal companion to the canonical audit report
[`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_219.md`](
  ../devnet/QBIND_DEVNET_EVIDENCE_RUN_219.md).

## Run 220 update — consumption wiring landed (source/test)

Run 220 acts on the central Run 219 finding above. The long-running
runtime call sites no longer reach the armed surface while discarding the
decision: the four binary runtime hooks (reload-apply, startup,
reload-check, local-peer-candidate-check) and the SIGHUP runtime hook now
**consume** the selected `GovernanceExecutionPolicy` and the **real**
governance-execution sidecar load status. The previous
`let _outcome = arm_surface(...)` discard and the forced
`GovernanceExecutionLoadStatus::Absent` are removed on those surfaces; a
rejected verdict fails closed before any mutation. This is **source/test
only** — release-binary runtime-consumption evidence is deferred to
**Run 221**. Default remains `GovernanceExecutionPolicy::Disabled` and the
Run 214 no-governance-execution path is preserved bit-for-bit (Disabled +
absent carrier proceeds as a legacy bypass). Binary/SIGHUP candidate
metadata still lacks governance proposal/decision bindings, so a present
carrier at the binary surface reaches the Run 211 evaluator and fails
closed on the expectation mismatch; live inbound `0x05` and full positive
binary acceptance remain deferred to Run 221. No real governance execution
engine, on-chain proof verifier, KMS/HSM backend, RemoteSigner backend, or
validator-set rotation is implemented. MainNet peer-driven apply remains
refused. **Full C4 remains OPEN. C5 remains OPEN.** See
[`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_220.md`](
  ../devnet/QBIND_DEVNET_EVIDENCE_RUN_220.md).

## 1. Background and prior accepted state

* **Run 211** — source/test governance execution policy boundary
  (`crates/qbind-node/src/pqc_governance_execution_policy.rs`): the typed
  `GovernanceExecutionPolicy::{Disabled, FixtureGovernanceAllowed,
  EmergencyCouncilFixtureAllowed, ProductionGovernanceRequired,
  MainnetGovernanceRequired}` enum and the `evaluate_governance_execution_policy`
  evaluator.
* **Run 212** — release-binary policy-boundary evidence.
* **Run 213** — source/test governance-execution payload carrying and
  production-context wiring
  (`crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs`):
  the optional `governance_execution` sidecar sibling, the combined v2
  loader, and the seven `route_loaded_governance_execution_to_*_callsite_decision`
  routing helpers.
* **Run 214** — release-binary payload/carrying evidence.
* **Run 215** — source/test hidden governance-execution policy selector
  (`crates/qbind-node/src/pqc_governance_execution_policy_surface.rs`):
  the hidden CLI flag, env var, parsers, CLI/env resolver, and seven
  `preflight_v2_marker_governance_execution_for_*` wrappers.
* **Run 216** — release-binary policy-selector evidence.
* **Run 217** — source/test governance-execution runtime arming carrier
  (`crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs`):
  `GovernanceExecutionRuntimeArmingConfig`, `from_cli_or_env`,
  `arm_surface`, and the seven runtime preflight wrappers.
* **Run 218** — release-binary runtime-arming evidence.

**Run 218 honest limitation (the motivation for Run 219):** the release
binary parses the hidden selector and the helper/library runtime-arming
paths exercise it, but before real governance implementation work the
project needs an explicit audit of exactly which long-running node
surfaces truly **consume** governance-execution runtime policy and which
are still helper/library-evidence only.

## 2. Evidence-level taxonomy

Each surface below is classified by the highest evidence level it has
reached:

* **source/test** — exercised only by unit/integration tests and library
  callers.
* **release-helper** — additionally exercised by a release-built example
  helper (Run 212/214/216/218 helper corpus) against production library
  symbols.
* **real-binary startup/CLI** — additionally reachable on the real
  `target/release/qbind-node` at startup / CLI-parse time (flag hidden,
  selector parsed, fail-closed on invalid value).
* **real-binary long-running runtime** — additionally reached by a call
  site inside the long-running node code path (`main.rs::run_p2p_node`
  and the live reload / SIGHUP runtime in `pqc_live_trust_reload.rs`).
* **real-binary long-running runtime + consumed** — the surface is
  reached **and** the armed policy decision actually gates long-running
  node behavior (i.e. the outcome is consumed, not discarded).
* **not representable** — the surface cannot be expressed at the binary
  today because of a missing wire carrier or missing engine.

A surface can reach "real-binary long-running runtime" (the call site
executes on the live path) while still **not** being "consumed" (the
decision outcome is discarded and behavior is unchanged). This
distinction is the central finding of Run 219.

## 3. Classification axes (per task)

For every surface the table records:

* Surface name.
* Source file(s).
* Current evidence level (taxonomy in §2).
* Consumes selected `GovernanceExecutionPolicy`? (does the armed policy
  reach this surface).
* Can carry governance-execution payload material? (is a typed
  `governance_execution` carrier available at this surface, or is the
  load status forced to `Absent`).
* Rejection non-mutating? (no marker write, no sequence write, no live
  trust swap, no session eviction, no Run 070 apply call).
* MainNet peer-driven apply remains refused?
* Remaining blocker.
* Proposed next run if further work is needed.

## 4. Selector and policy surfaces (group A)

| Surface | Source file(s) | Evidence level | Consumes policy | Carries payload | Rejection non-mutating | MainNet apply refused | Remaining blocker | Proposed next run |
|---|---|---|---|---|---|---|---|---|
| `pqc_governance_execution_policy_surface` (module) | `crates/qbind-node/src/pqc_governance_execution_policy_surface.rs` | real-binary startup/CLI | Yes (produces it) | n/a (selector layer) | Yes | Yes | None for the selector itself | none |
| `governance_execution_policy_from_selector` | `pqc_governance_execution_policy_surface.rs:230` | release-helper + real-binary startup/CLI | Yes (parser) | n/a | Yes (pure parse) | Yes | None | none |
| `governance_execution_policy_from_cli_or_env` | `pqc_governance_execution_policy_surface.rs:298` | real-binary startup/CLI | Yes (CLI-over-env resolver) | n/a | Yes (pure parse) | Yes | None | none |
| CLI flag `--p2p-trust-bundle-governance-execution-policy` | `crates/qbind-node/src/cli.rs`, `crates/qbind-node/src/main.rs:425,544` | real-binary startup/CLI (hidden, fail-closed) | Yes (feeds resolver) | n/a | Yes | Yes | None | none |
| env var `QBIND_P2P_TRUST_BUNDLE_GOVERNANCE_EXECUTION_POLICY` | `pqc_governance_execution_policy_surface.rs` | real-binary startup/CLI | Yes (feeds resolver) | n/a | Yes | Yes | None | none |

**Finding (group A):** the selector/policy surfaces are **fully wired and
evidenced** on the real binary at startup/CLI-parse time (Run 216/218).
The hidden flag and env var resolve a `GovernanceExecutionPolicy` with
deterministic CLI-over-env precedence and fail closed on invalid values
before any runtime mutation. No further selector work is required.

## 5. Runtime arming carrier (group B)

| Surface | Source file(s) | Evidence level | Consumes policy | Carries payload | Rejection non-mutating | MainNet apply refused | Remaining blocker | Proposed next run |
|---|---|---|---|---|---|---|---|---|
| `pqc_governance_execution_runtime_arming` (module) | `crates/qbind-node/src/pqc_governance_execution_runtime_arming.rs` | real-binary long-running runtime (constructed; outcome discarded) | Yes | Carrier forced `Absent` at every live call site | Yes | Yes | Live sidecars carry no typed payload; outcome not consumed | Run 220 |
| `GovernanceExecutionRuntimeArmingConfig` | `pqc_governance_execution_runtime_arming.rs` | real-binary long-running runtime | Yes (holds the armed policy) | `Absent` at live call sites | Yes | Yes | Outcome discarded (`let _outcome = …`) | Run 220 |
| `from_cli_or_env` | `pqc_governance_execution_runtime_arming.rs` | real-binary startup/CLI + long-running runtime | Yes | n/a | Yes | Yes | None (resolution is complete) | none |
| `arm_surface` | `pqc_governance_execution_runtime_arming.rs:365` | real-binary long-running runtime (4 of 7 surfaces) | Yes | `Absent` | Yes | Yes | Outcome discarded; 2 surfaces unreached | Run 220 |
| 7 preflight wrappers `preflight_{reload_check,reload_apply,startup_p2p_trust_bundle,sighup,local_peer_candidate_check,live_inbound_0x05,peer_driven_drain}` | `pqc_governance_execution_runtime_arming.rs:234-347` | mixed — see §7 | Yes | `Absent` at live call sites | Yes | Yes | Outcome discarded; 2 wrappers reached only via helper/library | Run 220 |

**Finding (group B):** the runtime arming carrier is **partially wired**.
`from_cli_or_env` resolution is complete and real-binary evidenced; the
carrier is constructed on the live path and routes the armed policy into
the preflight wrappers, but at every live call site the resolved outcome
is **discarded** (`let _outcome = arming.arm_surface(…)` /
`let _outcome = arming.preflight_sighup(…)`) and the payload load status
is hard-coded to `GovernanceExecutionLoadStatus::Absent`. Under the
default `Disabled` policy this is a bit-for-bit no-op; under a non-Disabled
armed policy each wrapper fails closed as required-but-absent without
mutating. The carrier therefore **arms** but does not yet **gate**
long-running behavior.

## 6. Payload / carrying surfaces (group C)

| Surface | Source file(s) | Evidence level | Consumes policy | Carries payload | Rejection non-mutating | MainNet apply refused | Remaining blocker | Proposed next run |
|---|---|---|---|---|---|---|---|---|
| `pqc_governance_execution_payload_carrying` (module) | `crates/qbind-node/src/pqc_governance_execution_payload_carrying.rs` | release-helper + source/test | Yes (evaluator entry) | Yes (typed carrier exists) | Yes | Yes | No live sidecar emits the carrier | Run 220 |
| optional `governance_execution` sidecar sibling | `pqc_governance_execution_payload_carrying.rs:742` (`parse_optional_governance_execution_sibling_from_json_value`) | release-helper + source/test | Yes | Yes (parses when present) | Yes | Yes | Live reload sidecar formats do not include the sibling | Run 220 |
| combined v2 loader | `pqc_governance_execution_payload_carrying.rs:794,811` (`load_v2_ratification_sidecar_with_governance_execution_from_{path,bytes}`) | release-helper + source/test | Yes | Yes | Yes | Yes | Live load paths call the legacy loader, not this combined loader | Run 220 |
| 7 callsite routing helpers `route_loaded_governance_execution_to_*_callsite_decision` | `pqc_governance_execution_payload_carrying.rs:1090-1160` | release-helper + source/test; reached on live path with `Absent` carrier | Yes | Yes (when carrier present) | Yes | Yes | Reached only with `Absent` carrier from the arming wrappers | Run 220 |
| `mainnet_peer_driven_apply_remains_refused_under_governance_execution_payload_carrying` | `pqc_governance_execution_payload_carrying.rs:1193` | release-helper + source/test | n/a | n/a | Yes | Yes (proves refusal) | None (invariant holds) | none |

**Finding (group C):** the payload-carrying surfaces are
**helper-evidenced and source/test complete** but **not consumed on the
live path**: the typed `governance_execution` carrier and combined loader
exist and parse correctly when material is present, but no long-running
node sidecar/connection format emits the carrier today, so the live load
status is always `Absent`. This is the same wire blocker recorded for the
Run 182 on-chain governance hooks.

## 7. Runtime call sites — the seven surfaces (group D)

This is the decisive group. Each of the seven runtime surfaces is
classified by whether a **real long-running node call site** reaches it
and whether the resolved outcome is **consumed**.

| # | Surface | Live call site | Source file(s) | Evidence level | Consumes policy | Carries payload | Outcome consumed | Rejection non-mutating | MainNet apply refused | Classification |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | reload-check | `invoke_run_217_callsite_governance_execution_marker_decision(… ReloadCheck)` | `crates/qbind-node/src/main.rs:1789` | real-binary long-running runtime | Yes | `Absent` | **No** (`let _outcome`) | Yes | Yes | partially wired |
| 2 | reload-apply | `invoke_run_217_callsite_governance_execution_marker_decision(… ReloadApply)` | `main.rs:904`, `arm_surface` at `main.rs:1013` | real-binary long-running runtime | Yes | `Absent` | **No** (`let _outcome`) | Yes | Yes | partially wired |
| 3 | startup `--p2p-trust-bundle` | `invoke_run_217_callsite_governance_execution_marker_decision(… StartupP2pTrustBundle)` | `main.rs:1184` | real-binary long-running runtime | Yes | `Absent` | **No** (`let _outcome`) | Yes | Yes | partially wired |
| 4 | SIGHUP | `invoke_run_217_sighup_callsite_governance_execution_marker_decision` via `LiveReloadConfig::governance_execution_runtime_arming` | `crates/qbind-node/src/pqc_live_trust_reload.rs:1452,1536` | real-binary long-running runtime | Yes | `Absent` | **No** (`let _outcome`) | Yes | Yes | partially wired |
| 5 | local peer-candidate-check | `invoke_run_217_callsite_governance_execution_marker_decision(… LocalPeerCandidateCheck)` | `main.rs:3053` | real-binary long-running runtime | Yes | `Absent` | **No** (`let _outcome`) | Yes | Yes | partially wired |
| 6 | live inbound `0x05` | none (no production call site; only `arm_surface`/`preflight_live_inbound_0x05` from tests + helper) | `pqc_governance_execution_runtime_arming.rs:326` | release-helper + source/test | Yes (in helper/test) | `Absent` | **No** | Yes | Yes | helper-evidenced only |
| 7 | peer-driven drain | none (no production call site; the real drain path is `PeerDrivenDrainPolicy::try_drain_once`, which refuses MainNet independently and does not invoke `preflight_peer_driven_drain`) | `pqc_governance_execution_runtime_arming.rs:347`; drain path `crates/qbind-node/src/pqc_peer_candidate_drain.rs` | release-helper + source/test | Yes (in helper/test) | `Absent` | **No** | Yes | Yes | helper-evidenced only |

**Finding (group D):**

* **Surfaces 1–5 (reload-check, reload-apply, startup `--p2p-trust-bundle`,
  SIGHUP, local peer-candidate-check)** are **partially wired**: a real
  long-running node call site constructs the carrier and routes the armed
  policy into the preflight wrapper, but the resolved outcome is
  **discarded** and the payload carrier is `Absent`, so the decision does
  not yet gate live behavior. Under the default `Disabled` policy these
  paths are bit-for-bit unchanged.
* **Surfaces 6–7 (live inbound `0x05`, peer-driven drain)** are
  **helper-evidenced only**: no production call site invokes their
  preflight wrapper. The live inbound `0x05` runtime config does not
  thread a per-connection governance-execution policy (the documented Run
  215/217/218 limitation), and the real peer-driven drain path
  (`PeerDrivenDrainPolicy::try_drain_once`) refuses MainNet independently
  and never calls `preflight_peer_driven_drain`.

Across all seven surfaces the rejection paths are non-mutating and MainNet
peer-driven apply remains refused; the gap is **consumption**, not safety.

## 8. Compatibility surfaces (group E)

These sibling boundaries are independent of governance-execution arming.
Run 219 confirms they remain unchanged and compatible; none is consumed
by governance-execution runtime policy and none is modified.

| Surface | Origin runs | Source file(s) | Evidence level | Consumes gov-exec policy | Remaining blocker | Status |
|---|---|---|---|---|---|---|
| governance proof policy selector | Runs 171/172 | `crates/qbind-node/src/pqc_governance_proof_surface.rs` | real-binary startup/CLI (sibling selector) | No (independent) | Real on-chain verifier | independent / compatible |
| OnChainGovernance boundary | Runs 178–187 | `pqc_onchain_governance_proof.rs`, `pqc_onchain_governance_verifier.rs`, `pqc_onchain_governance_payload_carrying.rs`, `pqc_onchain_governance_callsite_wiring.rs` | release-helper + source/test (boundary only) | No | Real on-chain governance proof verifier | boundary-only |
| custody policy selector | Run 193 | `pqc_authority_custody_policy_surface.rs`, `pqc_authority_custody.rs` | real-binary startup/CLI (sibling selector) | No | Real production custody backend | independent / compatible |
| RemoteSigner policy selector | Run 199 | `pqc_remote_signer_policy_surface.rs` | real-binary startup/CLI (sibling selector) | No | Real RemoteSigner backend | independent / compatible |
| custody-attestation policy selector | Run 210 | `pqc_custody_attestation_policy_surface.rs`, `pqc_custody_attestation_verifier.rs` | real-binary startup/CLI (sibling selector) | No | Real attestation verifier | independent / compatible |
| KMS/HSM boundary | Runs 203–204 | `pqc_authority_kms_hsm_backend.rs` | release-helper + source/test (boundary only) | No | Real KMS/HSM backend | boundary-only |
| RemoteSigner transport boundary | Runs 201–202 | `pqc_remote_signer_transport.rs` | release-helper + source/test (boundary only) | No | Real RemoteSigner transport | boundary-only |

**Finding (group E):** every compatibility surface is **intentionally out
of scope** for governance-execution runtime consumption and remains
independent, unchanged, and boundary-only or selector-only. None is
weakened by the governance-execution arming carrier.

## 9. Required per-surface findings (the seven runtime surfaces)

Per the task, each of the seven runtime surfaces is explicitly classified
as one of: (1) fully wired and evidenced; (2) partially wired; (3)
helper-evidenced only; (4) intentionally out of scope; (5) blocked by
missing real governance engine.

1. **reload-check** — **(2) partially wired.** Live call site present;
   outcome discarded; carrier `Absent`. Also (5) blocked by missing real
   governance engine for any non-fixture consumption.
2. **reload-apply** — **(2) partially wired.** As above.
3. **startup `--p2p-trust-bundle`** — **(2) partially wired.** As above.
4. **SIGHUP** — **(2) partially wired.** As above.
5. **local peer-candidate-check** — **(2) partially wired.** As above.
6. **live inbound `0x05`** — **(3) helper-evidenced only.** No production
   call site; per-connection policy threading is the documented
   limitation. Also (5) blocked by missing real governance engine.
7. **peer-driven drain** — **(3) helper-evidenced only.** No production
   call site into the governance-execution wrapper; the real drain path
   refuses MainNet independently. Also (5) blocked by missing real
   governance engine.

**Consolidated finding:** the long-running runtime **consumption is
incomplete**. Five surfaces are partially wired (reached but outcome
discarded, carrier `Absent`); two surfaces are helper-evidenced only (no
production call site). The selector, resolver, carrier construction, and
all rejection/refusal safety invariants are complete and real-binary
evidenced, but no surface yet reaches the
"real-binary long-running runtime + consumed" level. Every compatibility
surface is out of scope and unchanged.

## 10. Decision: next exact closure run sequence

Because the audit confirms that long-running runtime **consumption is
incomplete** (no surface reaches "real-binary long-running runtime +
consumed"; five surfaces discard the outcome and two have no production
call site), the next closure sequence is:

* **Run 220 — source/test long-running node governance-execution runtime
  consumption wiring.** Make the five reached surfaces (reload-check,
  reload-apply, startup `--p2p-trust-bundle`, SIGHUP, local
  peer-candidate-check) **consume** the resolved
  `GovernanceExecutionRuntimeArmingConfig` outcome on the long-running
  path instead of discarding it, and add real production call sites for
  the two helper-only surfaces (live inbound `0x05`, peer-driven drain)
  where representable. Default `Disabled` must remain bit-for-bit
  unchanged; non-Disabled armed policies must fail closed without
  mutation when the carrier is `Absent`; MainNet peer-driven apply must
  remain refused. Source/test only.
* **Run 221 — release-binary long-running node governance-execution
  runtime consumption evidence.** Prove on real
  `target/release/qbind-node` that the consumed outcome gates the
  long-running path as wired in Run 220, with the same default-Disabled,
  fail-closed, and MainNet-refused invariants.

These two runs do **not** require a real governance execution engine, a
real on-chain proof verifier, a wire/schema change to add the
`governance_execution` carrier to live sidecars, validator-set rotation,
or any KMS/HSM/RemoteSigner backend. They wire **consumption of the armed
outcome** on the live path while preserving every existing safety
invariant. A real governance engine, a real on-chain verifier, and a live
`governance_execution` wire carrier remain separate, later, explicitly
scoped runs and are the residual blockers tracked under C4/C5.

(The alternate branch — "Run 220: production governance execution
evaluator interface skeleton; Run 221: release-binary evaluator-boundary
evidence" — is **not** selected, because the audit shows the long-running
runtime is **not** yet sufficiently wired: consumption is incomplete.)

## 11. Non-closure statements

* Run 219 is an **audit / spec run only**.
* **No new runtime behavior** is implemented.
* **No real governance execution engine** is implemented.
* **No real on-chain governance proof verifier** is implemented.
* Fixture governance remains **DevNet/TestNet evidence-only**.
* The emergency council fixture remains **explicit and non-production**.
* Production / on-chain / MainNet governance execution remains
  **unavailable / fail-closed**.
* **MainNet peer-driven apply remains refused.**
* **Validator-set rotation remains unsupported.**
* KMS/HSM / RemoteSigner / custody-attestation remain **boundary-only**.
* **Full C4 remains OPEN. C5 remains OPEN.**

## 12. Validation commands and results

Audit greps (counts over `crates/qbind-node/src`,
`crates/qbind-node/tests`, `docs`):

```bash
grep -R "governance_execution_policy" crates/qbind-node/src crates/qbind-node/tests docs | head -200   # 326 matches
grep -R "GovernanceExecutionRuntimeArmingConfig" crates/qbind-node/src crates/qbind-node/tests docs | head -200   # 54 matches
grep -R "governance_execution" crates/qbind-node/src crates/qbind-node/tests docs | head -200   # 830 matches
grep -R "Status as of Run 219" docs/protocol/QBIND_C4_C5_CLOSURE_CRITERIA.md   # present
grep -R "Run 219" docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_219.md docs/protocol/QBIND_GOVERNANCE_EXECUTION_RUNTIME_SURFACE_AUDIT.md docs/whitepaper/contradiction.md   # present in all three
```

Test targets (observed results):

```bash
cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests   # ok. 45 passed; 0 failed
cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests  # ok. 55 passed; 0 failed
cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests # ok. 61 passed; 0 failed
cargo test -p qbind-node --test run_211_governance_execution_policy_tests           # ok. 55 passed; 0 failed
cargo test -p qbind-node --lib pqc_authority                                        # ok. 164 passed; 0 failed; 1181 filtered out
```

All recorded results are PASS. Run 219 changes only documentation, so no
production build/test behavior is affected.