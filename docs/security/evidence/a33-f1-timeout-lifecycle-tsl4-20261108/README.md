# A33-F1 / E27 — TSL-4 test-only Timeout lifecycle correction

**TSL-4 CORRECTION — INDEPENDENT REVIEW PENDING.**

## Provenance and scope

Repository: `olivexo28/QBIND`. Branch:
`test/a33-f1-timeout-signer-lifecycle`. Reviewed parent endpoint:
`f0941b3af4c68c20a2f3e17a2d37fb9d0b2f7ea8`, tree
`2844ca5077a54700b5df19a3da632b276101b2f1`. The final test/source
producer is `c3a1366e8b9d7ed4298474c576fbdc157ceefef3`, tree
`e72c3f6faac3e937522a680a22bcae3e12299848`, parent
`9763ecab2854b4d1996ca8b79c495926fb6c8b61`. `main` remains
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`.

The only source path changed is
`crates/qbind-node/src/binary_consensus_loop.rs`; all source changes are
inside the existing test-only `a33_timeout_lifecycle` module. Production
Timeout code, its guards, other tests, and authority are unchanged.

Final-tree anchors:

- Test-only bounded owner state and per-operation permit admission:
  `binary_consensus_loop.rs:26402-26532`.
- Sticky unresolved/unpermitted summaries and closure predicate:
  `:26536-26630`.
- Synchronous operation runner that allows reuse while admission stays open:
  `:26870-26915`.
- Same-owner Unknown-then-success sequence and overwrite sensitivity:
  `:27197-27340`.
- Prior-permit/later-unpermitted actual-path control and stale-permit
  sensitivity: `:27342-27478`.
- Actual production Timeout signer path remains at `:7563-7790`.

## TSL-4 correction

The owner permits at most one outstanding operation, but can be reused
sequentially while admission remains open. On each successful admission,
`permit_observed` and function-completion state are reset for that operation.
The one-bit `unresolved_effect_observed` and
`unpermitted_effect_observed` summaries remain sticky across all sequential
operations; a later signature return updates the latest `outcome` but cannot
clear prior uncertainty. The ordinary `closure_safe` checker requires both
sticky summaries to remain false and the observation accounting to remain
valid. Fixed-width invocation counters use checked increments; overflow
invalidates observations, which fails the closure check. The historical
`any_permit_observed` bit is diagnostic/test-mutant state only and does not
authorize later operations.

The first new control runs the actual Timeout signer path with a disposable
`LocalKeySigner`, returning `UnknownAfterInvocation`, then observes worker
termination with admission still open. It admits a second operation on the
same owner, exercises an actual successful Timeout signing path, observes
that worker's termination, revokes admission, and invokes the same
`closure_safe` checker. The second signature is returned and is the latest
outcome, but the earlier unresolved summary remains set and closure is
refused. A separate overwrite mutant clears that sticky summary after the
later actual success; the same checker then incorrectly returns true,
demonstrating sensitivity.

The second control first completes a real correctly permitted Timeout
signature and observes its worker termination. It admits another operation
on the same owner. The second `UnsafeCachedAdmission` signer caches open
admission, pauses, then admission is revoked before the signer proceeds.
The actual Timeout function invokes the disposable local signer and returns
a signature without acquiring a permit for this operation. With correct
admission reset, the per-operation permit bit is false, the sticky
unpermitted-effect summary is set at invocation, and the same checker
refuses closure despite the earlier valid permit.

The sensitivity mutant then deliberately uses an admission routine that
fails to reset `permit_observed`. The same actual second Timeout invocation
after revocation occurs; the stale permit bit makes invocation appear
permitted and the ordinary `closure_safe` checker returns true. This
demonstrates the per-operation association defect through the same checker,
not only through a separate model predicate.

Accounting remains bounded: at most one outstanding operation and two local
executors; request/effect history is represented by fixed-size booleans and
fixed-width counters. Executor ownership and function completion remain
distinct. The accepted ordering is preserved: a permit acquired before
revocation may finish while its worker remains owned. Admission closure by
itself does not establish quiescence. Existing TSL-1, TSL-2 and TSL-3
controls remain in the focused selection and passed again; this does not
expand or recharacterize their reviewed scenarios.

## Executions

Environment: repository worktree; Rust `1.99.1`
(`58cf8f9c3 2026-10-13`), Cargo `1.99.1`
(`5f94df478 2026-08-27`), target
`x86_64-unknown-linux-gnu`, default workspace profile. All final-source
commands ran at source producer
`c3a1366e8b9d7ed4298474c576fbdc157ceefef3`, tree
`e72c3f6faac3e937522a680a22bcae3e12299848`.

| Selection | Result | Retained output |
|---|---|---|
| `cargo test -p qbind-node --lib a33_timeout_lifecycle -- --nocapture` | **Passed:** 7 passed, 0 failed, 0 ignored; 2,251 filtered; exit code 0. | `focused.log` |
| `cargo test -p qbind-node --lib run422_f7_retained_qc_local_timeout -- --nocapture` | **Passed:** 3 passed, 0 failed, 0 ignored; 2,255 filtered; exit code 0. | `local-timeout-regressions.log` |
| `cargo check -p qbind-node --lib` | **Passed**, existing warnings; exit code 0. | `production-library-check.log` |

The seven focused bodies, each executed and passing in the final run, are:

- `actual_timeout_guard_refusal_and_success_are_observed_end_to_end`
- `denied_permit_preserves_unknown_and_detects_overwrite_mutant`
- `invoked_error_unknown_and_late_stage_failure_keep_signature_observations`
- `prior_permit_does_not_authorize_later_effect_and_detects_stale_permit_mutant`
- `revocation_order_and_cancelled_waiter_preserve_worker_ownership`
- `sequential_success_does_not_clear_unknown_and_detects_overwrite_mutant`
- `capacity_child_handoff_and_check_then_act_sensitivity`

The three directly affected pre-existing local-Timeout regression bodies
also passed:
`run422_f7_retained_qc_local_timeout_accepts_exact_lock_before_consumption`,
`run422_f7_retained_qc_local_timeout_refusal_preserves_signing_and_consumption_state`,
and
`run422_f7_retained_qc_local_timeout_formed_tc_is_rechecked_before_apply_and_publication`.
These are ten distinct bodies in the final selections, not ten newly added
tests. Cargo reports filtered counts, not ignored tests.

An earlier focused execution during this task, before the final
same-checker permit-mutant refinement, also passed 7/7; it is superseded by
the final-source execution and is not included in the retained final logs.
The prior TSL-1/2/3 evidence and historical manifests are preserved in
their original directories; this TSL-4 record and its logs are separate.
`SHA256SUMS` covers the three final-source execution logs.

No live node, deployment, operational key, network transport, HSM,
power-loss, cross-host, external-signer, production-fencing, restart-safety,
or participation-authority claim is made. The stale-admission and
stale-permit sequences are test mutants around the exercised local Timeout
path, not production behavior or a production vulnerability finding.

**Remaining OPEN:** Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27.
Activation **DISABLED**; public DevNet **NO-GO**.
