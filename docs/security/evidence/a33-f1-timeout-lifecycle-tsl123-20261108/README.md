# A33-F1 / E27 — TSL-1/2/3 test-only Timeout lifecycle corrections

**TSL-1/2/3 CORRECTION — INDEPENDENT REVIEW PENDING.**

## Provenance and scope

Repository: `olivexo28/QBIND`. The dedicated branch is
`test/a33-f1-timeout-signer-lifecycle`. The reviewed starting endpoint was
`c64aebc092b084d684a3a055a2f12eea2b9262cb`, tree
`a7d479276075395f5f46bddba88b3a2b6ccf234f`. Main remains
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`.

The corrected test/source producer is
`e9a7f22b2519072e908737ed2f8b2b2509b21876`, tree
`ec9f0a3ba970c7e656739fc2bcc7ff831740401d`, parent
`c64aebc092b084d684a3a055a2f12eea2b9262cb`. The five new/updated
test-only controls and the retained actual Timeout signer fixture are
inside `#[cfg(test)]` in
`crates/qbind-node/src/binary_consensus_loop.rs`. Production behavior,
guards, and authority are unchanged.

Source anchors in the corrected tree:

- Actual Timeout path and signer call: `binary_consensus_loop.rs:7563-7790`.
- Test-only state, separate request refusal and closure predicates:
  `:26402-26420`, `:26488-26574`.
- Function-completion/termination barrier: `:26856-26895`.
- TSL-1 preservation and overwrite-mutant control: `:27059-27126`;
  fresh pre-invocation refusal and TSL-3 barrier control: `:27128-27217`.
- TSL-2 tracked/omitted child controls and actual-path stale-admission
  mutant: `:27220-27354`.

The final evidence commit is separate from the source producer. This record
and its logs are stored separately from the prior
`a33-f1-timeout-lifecycle-20261108/` directory. That earlier directory's
ten original logs and `SHA256SUMS` remain unchanged and verifiable at their
producing revision.

## Corrections and controls

**TSL-1 — request refusal cannot overwrite prior outcome.** A denied
`acquire_effect_permit` now sets a separate request-refusal observation; it
does not replace the retained effect outcome. The focused control first
executes the actual Timeout path with the disposable-key
`LocalKeySigner` in error-after-invocation mode, preserving
`UnknownAfterInvocation`, one invocation and a generated-but-not-returned
signature. A later denied permit is recorded separately, and the same
`closure_safe` checker still refuses. A fresh revocation-before-permit
control reaches the actual wrapper but performs no underlying signer call:
outcome remains `NotInvoked`, refusal is separately recorded, and closure
is allowed only after the worker obligation is observed terminated.

The `denied_permit_overwrite_mutant` deliberately restores the reviewed
overwrite defect in a separate test owner after the same actual Unknown
fixture. The same checker then returns closure-safe, demonstrating the
sensitivity of the correction. The reviewer's source-derived
counterexample was not an executed test in the earlier revision; the new
control is the first executed reproduction in this record.

**TSL-2 — isolate omitted-child sensitivity.** In the tracked control, after
the modeled parent work ends and its executor obligation is retired, state
is exactly `outstanding=0`, `live_executors=1`, `live_children=1`, while the
independent physical count is `1`: the paused child is the sole live
executor and the same owner quiescence checker refuses. Only after child
release, thread join, and `child_terminated` observation does physical count
become `0` and the checker permit quiescence. In the separate omitted
handoff mutant, the parent is likewise gone and the child is independently
observed as the sole physical executor (`count=1`), but the same ledger-only
checker incorrectly returns quiescent. This intentionally exposes the
false-quiescence defect; the independent physical observation prevents
mistaking it for valid evidence. These tests establish no production thread
discovery.

**TSL-3 — function completion is not executor termination.** The spawned
worker records Timeout-function completion and signals a deterministic
barrier, then remains blocked before dropping its physical lease and
returning. With admission revoked and no unrelated work, at that barrier
the exact observations are `function_completed=true`,
`outstanding=1`, `live_executors=1`, physical count `1`; the same checker
refuses quiescence. Dropping the waiter receiver does not release or retire
the worker. The test releases the barrier, joins the worker, and only then
calls `worker_terminated`; physical count is then `0` and local quiescence
may be claimed. The separate error-after-invocation case remains
Unknown and closure-refused after local quiescence.

The earlier report's timing sentence is superseded: its worker dropped the
physical lease and retired the operation before sending completion and
returning, and its test did not pause in the function-complete/thread-live
interval. It did not establish that physical count remained nonzero until
join, nor did it show a protected effect after the earlier retirement
point.

The actual `maybe_emit_view_timeout_with_auth` call, existing F7
refusal-before-wrapper path, disposable fixture key, successful local
signature/verification/engine/publication path, and strengthened
stale-admission mutant are retained. The stale-admission mutant still
produces a real Timeout signature through the actual function after
revocation without a serialized permit; the same closure checker rejects
that unpermitted effect. A previously permitted effect may finish after
admission closes while its obligation remains owned.

## Executions

Environment: repository worktree; Rust `1.99.1`
(`58cf8f9c3 2026-10-13`), Cargo `1.99.1`
(`5f94df478 2026-08-27`), target
`x86_64-unknown-linux-gnu`, default workspace profile.
All final executions used source commit
`e9a7f22b2519072e908737ed2f8b2b2509b21876` and tree
`ec9f0a3ba970c7e656739fc2bcc7ff831740401d`.

| Selection | Result | Retained output |
|---|---|---|
| `cargo test -p qbind-node --lib a33_timeout_lifecycle -- --nocapture` | **Passed:** 5 passed, 0 failed, 0 ignored; 2,251 filtered; exit code 0. | `focused.log` |
| `cargo test -p qbind-node --lib run422_f7_retained_qc_local_timeout -- --nocapture` | **Passed:** 3 passed, 0 failed, 0 ignored; 2,253 filtered; exit code 0. | `local-timeout-regressions.log` |
| `cargo check -p qbind-node --lib` | **Passed**, existing warnings; exit code 0. | `production-library-check.log` |

The five focused test bodies are:

- `actual_timeout_guard_refusal_and_success_are_observed_end_to_end`
- `invoked_error_unknown_and_late_stage_failure_keep_signature_observations`
- `denied_permit_preserves_unknown_and_detects_overwrite_mutant`
- `revocation_order_and_cancelled_waiter_preserve_worker_ownership`
- `capacity_child_handoff_and_check_then_act_sensitivity`

The three direct regression bodies are:
`run422_f7_retained_qc_local_timeout_accepts_exact_lock_before_consumption`,
`run422_f7_retained_qc_local_timeout_refusal_preserves_signing_and_consumption_state`,
and
`run422_f7_retained_qc_local_timeout_formed_tc_is_rechecked_before_apply_and_publication`.
These are eight distinct bodies in the final selections, not eight newly
added tests. Cargo reports filtered counts, not ignored tests.

A pre-producer compile attempt during editing failed with an `E0308`
mutability mismatch in the new test call; the typo was corrected before the
source-producing commit. It did not execute any test body and is not part
of the final-source results. Its transient full output was not retained.
The final focused, regression, and library-check logs each include the full
command output and explicit exit code.

`SHA256SUMS` covers the three final-source execution logs. No live node,
deployment, operational key, network transport, HSM, power-loss,
cross-host, external-signer, global-exclusivity, production-fencing,
restart-safety, or participation-authority claim is made.

`cargo fmt --all -- --check` was also attempted and returned 1 with
formatter diffs across the workspace; no formatter wrote or changed files.
The CRLF-aware `git diff --check` passed. This workspace-wide formatter
result is not evidence about runtime behavior and is not used as a test
result.

**Remaining OPEN:** Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27.
Activation **DISABLED**; public DevNet **NO-GO**.
