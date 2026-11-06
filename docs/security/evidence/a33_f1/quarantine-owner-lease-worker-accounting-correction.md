# Worker-loss accounting correction

**Status:** TEST-ONLY WORKER-ACCOUNTING CORRECTION — INDEPENDENT REVIEW
PENDING.

The source for W1 and W2 is the user-supplied review text in the task
request. No reviewer identity is inferred, and no claim is made that the
reviewer executed either counterexample or reran Rust tests.

## W1: ownership before first coordinator poll

The production shape of this test-support harness now constructs
`WorkerJoin` immediately after the worker spawn and before spawning the
coordinator. That guard is captured by the coordinator future, so destroying
the future before its first poll drops the guard, records the worker abort
request and classifies its result `NotObserved`. The coordinator-future
drop notifier is also constructed before `tokio::spawn` and captured by the
future; it independently reports future destruction even when the future's
body never begins. A separate atomic records whether the body was polled.
Worker future entry is separately recorded by the worker wrapper.

The pre-poll test checks, before yielding to the runtime, that the
coordinator body has not been polled and the worker body has not entered.
It then requests coordinator abort, awaits the actual coordinator
`JoinHandle` result, and checks coordinator destruction, worker abort
request, worker join observation (still false), and the unresolved
`NotObserved` classification separately. A worker-future drop notification
is awaited if worker entry was recorded; if the worker never entered, the
test does not require that signal. A future-drop notification is not a
worker join result, OS reclamation, or external-effect absence.

The test-only defective fixture intentionally captures the raw worker
handle and constructs `WorkerJoin` only inside the coordinator body. The
same `check_worker_loss_before_observation_boundary` checks loss-phase
classification and real protected admission. It rejects the defect because
no worker abort was accounted before first poll. The coordinator is
observably joined; test cleanup requests worker abort through a separate
test-only abort handle and observes the instrumented worker-future drop
signal, but the worker `JoinHandle` result remains unobserved. The
sensitivity test does not treat this cleanup request or drop signal as a
join.

The ordinary entered-coordinator success control checks both
`coordinator_future_polled` and `worker_future_entered`.

## W2: observed result before owner-state application

`WorkerResultDisposition` now distinguishes `Pending`, `NotObserved`,
`ObservedUnrecorded`, and `Recorded`. `worker_result_unobserved` remains a
separate observation bit; its being false is not taken to imply recording.
When the coordinator receives the actual worker `JoinHandle` result, it
sets `worker_join_observed` and `ObservedUnrecorded` before any further
await. It sets `Recorded` only after `apply_worker_join` updates the
owner-held snapshot. No separate recoverable result owner is introduced:
between join completion and application, the result exists only in the
coordinator future's local state. If that future is cancelled, the result is
dropped and remains classified as observed-but-unrecorded/unavailable.

A oneshot barrier pauses after the real join result is acquired and before
owner-state application. The cancellation control verifies the observed
join flag, `ObservedUnrecorded` disposition, no owner-recorded observation,
and no completed/application marker, then aborts and observes the
coordinator's actual join result. The phase-specific
`check_observed_unrecorded_boundary` verifies the lost coordinator state and
real protected-admission refusal without an admission-count increment.
This result-phase checker detects an injected, false `Recorded`
classification using the same lifecycle and admission checks.

The normal worker-success control checks `Recorded` only after the outcome
appears in owner state. The earlier loss-before-observation checker is
explicitly limited to `NotObserved`; it is not a general coordinator-loss
oracle.

## Verification

Focused command:

```text
cargo test -p qbind-node --test a33_f1_inprocess_owner_prototype_tests -- --nocapture
```

Final result: **28 passed, 0 failed, 0 ignored**. Directly affected
regression command:

```text
cargo test -p qbind-node --test a33_f1_quarantine_tokio_owner_lease_tests -- --nocapture
```

Final result: **12 passed, 0 failed, 0 ignored**. Exact outputs are
preserved in `quarantine-owner-lease-accounting-focused.log` and
`quarantine-owner-lease-accounting-regression.log`. Both omitted-guard and
false-classification sensitivity controls are expected rejections inside
passing tests, not separately executed failing child processes or security
passes.

The first full focused run reported **27 passed, 1 failed, 0 ignored** on
the same sensitivity test. An intermediate exact-filter diagnostic command,
`cargo test -p qbind-node --test a33_f1_inprocess_owner_prototype_tests false_recorded_classification_is_rejected_by_result_phase_checker -- --exact --nocapture`,
failed **0 passed, 1 failed, 27 filtered out**. That attempt invoked the
real admission check while the coordinator was deliberately paused but
before coordinator loss had been requested; the command then waited until
the admission watchdog. The control was corrected to request and observe
coordinator cancellation before checking admission, matching the required
loss phase. The exact-filter failed output is retained in
`quarantine-owner-lease-accounting-diagnostic-failure.log`; it is not
counted as a pass or as a security finding.

An initial `rustfmt --check` reported formatting diffs in the changed Rust
files; `rustfmt` was applied, and the final targeted check passed.

## Historical whitespace qualification

The prior worker-observation integrity entry's unqualified statement that
`git diff --check` passed did not cover all raw-log delivery bytes. The
reviewer reported terminal blank-line diagnostics for the preserved
worker-observation baseline, focused, and regression logs. Those three files
remain byte-for-byte unchanged from the parent revision (their current
SHA-256 digests match the parent blobs), and each ends with the original
two-LF Cargo-output terminator. They were not edited to silence diagnostics.

Independent checks for this correction found no trailing spaces or tabs in
the Rust source/test files or this evidence prose, and targeted `rustfmt
--check` passed. The new successful Cargo capture logs also retain the
normal terminal blank line; the failed diagnostic capture ends with one LF.
The complete delivery's ordinary whitespace check and its result are
recorded in the append-only integrity log, separately from the
blank-at-EOF-excluding check. No whitespace result is represented as clean
by rewriting historical or raw output.

## Scope and limits

The `StateReader` remains alive in the shutdown controls and retains its
command sender; no channel-closure conclusion is attributed to sender
absence. Admission checks are made through the existing test-only owner
method, and the admission counter is verified unchanged.

No P1/P2, substituted-snapshot, retirement, or previous worker-observation
acceptance was weakened or rewritten. This remains a test-support-only,
in-process prototype. It does not establish worker reclamation, independent
result recovery, production ownership, external-effect absence,
crash/runtime durability, startup enforcement, signer fencing, or network
delivery. A33-F1 / E27 and all other unresolved obligations remain **OPEN**;
activation **DISABLED**; public DevNet remains **NO-GO**.
