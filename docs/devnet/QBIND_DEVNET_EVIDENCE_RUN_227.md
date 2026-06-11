# QBIND DevNet evidence — Run 227

**Title.** Release-binary governance evaluator runtime call-site wiring evidence.

**Status.** PASS (release-binary). Run 227 is the release-binary evidence run
for the Run 226 governance evaluator runtime **call-site wiring**. Where
Run 226 proved at the source/test level that the representable Run 220
runtime call sites route through the Run 224 governance evaluator runtime
integration layer, Run 227 proves on real `target/release/qbind-node` plus a
release-built helper that the release-built code exposes and exercises the
Run 226 wiring entry points
(`wire_governance_evaluator_runtime_callsite` and
`wire_governance_evaluator_runtime_callsite_without_evaluator_context`), that
the representable runtime call sites consume the
`GovernanceEvaluatorRuntimeIntegrationOutcome` (the outcome is consumed, not
discarded), that the default Disabled legacy bypass is preserved, that a
present carrier without evaluator context fails closed, and that
production/on-chain/MainNet evaluators remain unavailable/fail-closed.

Run 227 is **release-binary evidence only**. It implements **no** real
governance execution engine, **no** real on-chain governance proof verifier,
**no** real KMS/HSM backend, **no** real RemoteSigner backend, **no** MainNet
governance enablement, and **no** validator-set rotation. It introduces no
production source behavior change.

## Strict scope

* Release-binary evidence only; real `target/release/qbind-node`.
* Release-built helper mints fixture/evaluator/payload material where needed.
* No production source behavior change.
* No real governance execution engine.
* No real on-chain governance proof verifier.
* No MainNet governance enablement.
* No MainNet peer-driven apply enablement.
* No validator-set rotation.
* No KMS/HSM backend implementation; no RemoteSigner backend
  implementation.
* No schema/wire/marker/sequence/trust-bundle change.
* Run 227 does not weaken any prior run (Runs 070, 130–226) and does not
  claim full C4 or C5 closure.

## Deliverables

* Release helper:
  `crates/qbind-node/examples/run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper.rs`
* Release harness:
  `scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh`
* Evidence archive:
  `docs/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary/`
  (tracks `README.md`, `summary.txt`, `.gitignore`; all other artifacts are
  regenerated and ignored).
* This canonical report.

## Release evidence

The release-built helper exercises the Run 226 call-site wiring symbols
through production library code over an A1–A23 accepted/compatible corpus and
an R1–R31 rejection corpus, plus a reachability corpus, all in release mode:

* the representable call sites consume the
  `GovernanceEvaluatorRuntimeIntegrationOutcome` (`Ok` for the proceed
  variants `ProceedLegacyBypass` / `ProceedMutate`, `Err` for the fail-closed
  variants `RuntimeConsumptionFailClosed` / `EvaluatorRejected` /
  `MainNetPeerDrivenApplyRefused`, carried by the typed
  `GovernanceEvaluatorRuntimeCallsiteFailClosed`);
* the call-site wiring outcome equals the underlying Run 224 integration
  outcome for the same context;
* the default Disabled-policy + absent-carrier **legacy bypass** is preserved
  (`Ok(ProceedLegacyBypass)`) at every wired call site, including the
  `without_evaluator_context` entry point for all governance execution
  runtime surfaces on DevNet;
* a present governance-execution carrier without evaluator context **fails
  closed** (reaches the unavailable production evaluator → `Err`);
* the production / on-chain / MainNet evaluator boundaries are reachable from
  the call-site wiring and return the typed unavailable / fail-closed
  `EvaluatorRejected` outcome;
* the fixture evaluator accepts only DevNet/TestNet decision sources, and the
  emergency-council fixture evaluator only an explicit emergency action;
* **MainNet peer-driven apply remains refused** even with a fixture evaluator
  approval (`Err`, `is_mainnet_peer_driven_apply_refused()` true);
* every `Err` rejection is non-mutating and never authorizes mutation.

The real `target/release/qbind-node` scenarios confirm the help output and
the default DevNet/TestNet/MainNet surfaces make no call-site wiring claims,
that a hidden governance-execution policy selector still parses, and that an
invalid governance-execution policy selector **fails closed before mutation**
(`no marker write; no sequence write; no live trust swap; no session
eviction; no Run 070 call`). Source and call-site reachability greps confirm
the Run 226 wiring symbols and the two wired call sites
(`main.rs::consume_run_220_governance_execution_runtime_outcome` and
`pqc_live_trust_reload.rs::consume_run_220_sighup_governance_execution_marker_decision`)
route through the integration layer. A 26-pattern denylist is proven empty
across the captured logs.

Captured metadata includes the helper and `qbind-node` SHA-256 + ELF Build
IDs, the git commit, rustc/cargo versions, exact commands, stdout/stderr
logs, per-scenario exit codes, call-site integration outcome values, and the
denylist grep results. See
`docs/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary/summary.txt`.

## Representability limitation (documented honestly)

The binary marker/candidate metadata cannot yet carry a governance
proposal/decision evaluator binding, so the **live inbound `0x05`** and
**peer-driven drain** surfaces are wired but their full positive evaluator
binding is not yet representable from the binary: only the Disabled +
absent-carrier legacy bypass is `Ok` at those binary call sites, and a
present carrier fails closed. Full positive `ProceedMutate` authorization
with a real proposal binding is exercised through the release-built helper,
which uses the same library symbols a future production call site would.

## Invariants restated

* Run 227 is release-binary governance evaluator runtime call-site wiring
  evidence.
* Representable runtime call sites route through the integration layer in
  release evidence.
* Default Disabled legacy bypass is preserved.
* Present carrier without evaluator context fails closed.
* Production/on-chain/MainNet evaluators remain unavailable/fail-closed.
* Fixture evaluator remains DevNet/TestNet evidence-only.
* Emergency fixture evaluator is explicit and non-production.
* Live inbound `0x05` and peer-driven drain limitations are documented
  honestly (full positive evaluator binding not yet representable from the
  binary).
* MainNet peer-driven apply remains refused.
* Validator-set rotation remains unsupported.
* No real governance engine or on-chain proof verifier is implemented.
* Existing Run 221, Run 223, and Run 225 release behaviour remains
  compatible.
* Full C4 remains OPEN.
* C5 remains OPEN.

## Validation commands

* `cargo build --release -p qbind-node --bin qbind-node`
* `cargo build --release -p qbind-node --example run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper`
* `bash scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh`
* `cargo test -p qbind-node --test run_226_governance_evaluator_runtime_callsite_wiring_tests`
* `cargo test -p qbind-node --test run_224_governance_evaluator_runtime_integration_tests`
* `cargo test -p qbind-node --test run_222_governance_execution_evaluator_tests`
* `cargo test -p qbind-node --test run_220_governance_execution_runtime_consumption_tests`
* `cargo test -p qbind-node --test run_217_governance_execution_runtime_arming_tests`
* `cargo test -p qbind-node --test run_215_governance_execution_policy_selector_tests`
* `cargo test -p qbind-node --test run_213_governance_execution_payload_callsite_tests`
* `cargo test -p qbind-node --test run_211_governance_execution_policy_tests`
* `cargo test -p qbind-node --lib pqc_authority`
* `cargo test -p qbind-node --lib`