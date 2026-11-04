# Run 227 — Release-binary governance evaluator runtime call-site wiring evidence

## Scope

Run 227 is the release-binary evidence run for the Run 226 source/test
governance evaluator runtime **call-site wiring** in
`crates/qbind-node/src/pqc_governance_execution_evaluator_runtime_integration.rs`:

* the call-site wiring entry points
  (`wire_governance_evaluator_runtime_callsite` and
  `wire_governance_evaluator_runtime_callsite_without_evaluator_context`);
* the typed `GovernanceEvaluatorRuntimeCallsiteFailClosed` carrier
  (`.surface`, `.outcome`, `.reason`,
  `.is_mainnet_peer_driven_apply_refused()`);
* the `Result<GovernanceEvaluatorRuntimeIntegrationOutcome,
  GovernanceEvaluatorRuntimeCallsiteFailClosed>` discipline
  (`Ok` for `ProceedLegacyBypass` / `ProceedMutate`; `Err` for
  `RuntimeConsumptionFailClosed` / `EvaluatorRejected` /
  `MainNetPeerDrivenApplyRefused`).

The call-site wiring routes the representable Run 220 runtime call sites
through the Run 224 integration layer:

* `consume_run_220_governance_execution_runtime_outcome` in `main.rs` routes
  reload-check, reload-apply, startup `--p2p-trust-bundle`, and local
  peer-candidate-check;
* `consume_run_220_sighup_governance_execution_marker_decision` in
  `pqc_live_trust_reload.rs` routes SIGHUP.

Where Run 226 proved the call-site wiring at the source/test level, Run 227
proves on real `target/release/qbind-node` plus a release-built helper
(`crates/qbind-node/examples/run_227_governance_evaluator_runtime_callsite_wiring_release_binary_helper.rs`,
driven by
`scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh`)
that the release-built code exposes and exercises the wiring:

* the representable call sites consume the
  `GovernanceEvaluatorRuntimeIntegrationOutcome` (the outcome is consumed,
  not discarded — `Ok`/`Err` is derived from the outcome's proceed/fail
  discipline);
* the default Disabled-policy + absent-carrier **legacy bypass** is preserved
  (`Ok(ProceedLegacyBypass)`, Run 214 compatibility) at every wired call site,
  including the `without_evaluator_context` entry point for all governance
  execution runtime surfaces on DevNet;
* a present governance-execution carrier without evaluator context **fails
  closed** (reaches the unavailable production evaluator → `Err`);
* the production / on-chain / MainNet evaluator boundaries are reachable from
  the call-site wiring and return the typed unavailable / fail-closed
  `EvaluatorRejected` outcome;
* the fixture evaluator accepts only DevNet/TestNet decision sources, and the
  emergency-council fixture evaluator only an explicit emergency action;
* **MainNet peer-driven apply remains refused** even with a fixture evaluator
  approval (`Err`, `is_mainnet_peer_driven_apply_refused()` true);
* every `Err` rejection is non-mutating (the wiring is a pure function over
  the integration layer) and never authorizes mutation;
* the call-site wiring outcome equals the underlying Run 224 integration
  outcome for the same context (A23 compatibility proof).

## Artifacts

This directory tracks only `README.md`, `summary.txt`, and `.gitignore`.
Everything else is regenerated and ignored:

```text
provenance.txt
logs/
data/
exit_codes/
helper_evidence/run_227/
reachability/
grep_summaries/
test_results/
negative_invariants.txt
mutation_proof.txt / no_mutation_proof.txt
```

## Reproduce

```bash
bash scripts/devnet/run_227_governance_evaluator_runtime_callsite_wiring_release_binary.sh
```

The harness regenerates artifacts and atomically replaces `summary.txt`.
Use an exclusive `OUTDIR`: one invocation/writer, including its children,
until all children have completed. Invocation IDs are not locks.

## Current-run regression verdict

Before any work, stderr identifies `run_id` and the summary is replaced with
that invocation's `verdict: INCOMPLETE`. All eight integration targets and
both library commands are required. Ordinary Cargo failures do not stop later
safely capturable commands; missing targets fail rather than skip.
Existing logs and numeric `.rc` files remain. The aggregation input is
`exit_codes/regression_results.tsv`: `run_id=<id>`, then the TSV header
`command_key`, `state`, `rc`, and exactly 10 rows. Keys are
`run227:test:<target>` and `run227:lib:<label>`; library labels are
`pqc_authority` and `lib_all`. States are `returned` with shell status 0-255,
or `missing_target` / `capture_error` with an empty status.

The harness validates identity, schema, exact inventory, uniqueness and
status-file consistency before incorporating records into the summary.
Complete nonzero/missing-target results yield `FAIL`; invalid/incomplete
records or I/O errors yield `INCOMPLETE`, taking precedence over failure.
Both exit nonzero. PASS requires every required result to be zero and
successful atomic summary publication, not human-readable PASS text alone.
Scenario/helper/denylist assertions remain separate. In particular S6's
expected invalid-selector rejection is not a regression failure.

Summary writes use checked same-directory temporary files and rename.
GNU coreutils `mv` with `-T` is required: `summary.txt` is an exact
destination, never a destination directory. Existing directories are refused
without removing their contents; a destination symlink is replaced itself
(its referent is untouched). Invalid final destinations cannot complete
successfully. Single-writer and crash-durability limitations are unchanged.
Initialization failure stops work and warns that any old summary is
untrusted. SIGINT/SIGTERM/SIGHUP trigger best-effort INCOMPLETE repair and
nonzero exit when Bash runs the handler; foreground commands can defer it.
The invoking supervisor must signal the process group, allow bounded cleanup,
contain survivors if needed, and reap children before OUTDIR reuse.
SIGKILL, host failure or unavailable storage may prevent repair. Atomic
visibility is not crash durability. Success requires matching invocation
identity, validated incorporated records, and parent/operator-observed normal
zero exit; a PASS file without that completion evidence is insufficient.

The isolated fixture command (from the repository root) is:

```bash
bash scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh /tmp/new-exclusive-fixture-evidence
```

It executes LF-normalized temporary copies with guarded stubs, not real
Cargo/node/helper binaries or the committed CRLF full release harness.
The fixture requires Linux subreaper support and a `/proc` PID/process-group
namespace matching Python and `killpg`; it refuses unsupported visibility
before cases launch. Cleanup is exception-safe and kernel group absence is
required before directory reuse/removal.
See [historical bounded evidence](https://github.com/olivexo28/QBIND/blob/6fdc0f0dcfc45c65037de3e53215121f5332689a/docs/security/evidence/a37-1-c2/README.md)
and [bounded review corrections](../../security/evidence/a37-1-c2-correction/README.md).

## Honest limitations

* The Run 226 call-site wiring routes the representable Run 220 runtime call
  sites (reload-check, reload-apply, startup `--p2p-trust-bundle`, SIGHUP,
  local peer-candidate-check) through the Run 224 integration layer. The
  binary marker / candidate metadata cannot yet carry a governance
  proposal/decision evaluator binding, so the **live inbound `0x05`** and
  **peer-driven drain** surfaces are wired but their full positive evaluator
  binding is not yet representable from the binary: only the
  `Disabled` + absent-carrier legacy bypass is `Ok` at those binary call
  sites, and a present carrier fails closed. Full positive `ProceedMutate`
  authorization with a real proposal binding is exercised through the
  release-built helper, which uses the same library symbols a future
  production call site would.
* The default Disabled legacy bypass is preserved bit-for-bit, so the Run 221
  runtime-consumption, Run 223 evaluator-interface, and Run 225
  integration-layer behaviour are unchanged.
* No real governance execution engine is implemented. Production / on-chain /
  MainNet evaluators are reachable but always return the typed unavailable /
  fail-closed outcome, regardless of the resolved policy.
* No real on-chain governance proof verifier is implemented.
* The fixture evaluator remains DevNet/TestNet evidence-only and is refused
  on a MainNet trust domain.
* The emergency-council fixture evaluator is explicit and non-production.
* The call-site wiring is pure: it performs no network or file I/O, writes no
  marker, writes no sequence, mutates no live trust, evicts no sessions, and
  never invokes Run 070 apply. Validation-only and mutating-surface rejection
  paths therefore perform no mutation, and the only mutation-authorizing
  outcome is the terminal `ProceedMutate`.
* No real KMS / HSM backend, no real RemoteSigner backend, and no production
  signing-key custody; KMS/HSM/RemoteSigner/custody-attestation remain
  boundary-only and unchanged.
* Validator-set rotation remains unsupported.
* MainNet peer-driven apply remains refused (Run 147 FATAL invariant) even
  with a fixture evaluator approval.
* Full C4 remains open. C5 remains open.