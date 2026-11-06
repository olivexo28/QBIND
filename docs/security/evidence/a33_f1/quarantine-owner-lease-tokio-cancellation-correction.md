# Test-only ownership cancellation correction

**Status:** TEST-ONLY OWNERSHIP CORRECTION — INDEPENDENT REVIEW PENDING.

This correction implements the two source-traced findings in the supplied
reviewer report. It does not identify a reviewer or claim the reviewer ran
tests.

## Handoff boundary

`HandoffOffer::accept_inner_with_loss` constructs the receiver's
`OperationOwner` before sending `AcceptHandoff`. The receiver future therefore
holds a loss-reporting guard while the coordinator processes acceptance and
places the reply in the oneshot channel. The initiator acknowledgment is
sent only after that reply send. Its meaning is limited to coordinator
acceptance while the receiver's guard already exists; it is not proof that
the receiver consumed the reply, constructed a long-lived handle, or remained
alive.

The coordinator's current-owner atomic changes from Initiator to Supervisor
only on successful acceptance. Dropping the initiator afterward cannot
revoke the Supervisor role. Dropping the Supervisor guard synchronously
changes the role to Lost and publishes refusal-closed state before attempting
the bounded `OwnerDropped` notification. Admission checks the current-owner
atomic as well as coordinator state, so a queued or failed loss notification
cannot leave a valid-looking mutation window. When the control queue is full,
the failed notification sets the existing control-overflow signal; admission
refuses with `CapacityUncertain`. A closed channel cannot restore authority:
the shared in-process role is already Lost, and the coordinator's absence is
itself fail-closed.

The acceptance-reply/cancellation test pauses the receiver after the
coordinator sends the reply but before the receiver completes `accept`, then
aborts and observes the receiver task. It verifies the owner-loss transition
and refuses supervisor admission. The sensitivity fixture disables the
loss-report guard and invokes the identical lifecycle check; the check
detects the defective trace as unexpectedly admitted. Separate controls
cover failed delivery, dropping an acquired owner, successful handoff, and
loss reporting when the bounded command queue is full.

## Coordinator join observation

`SupervisorTask::join` borrows the `JoinHandle` held in the task guard rather
than taking it into the waiter future. `abort_and_join` and the watchdog
post-abort wait use the same retained handle. If an observer is cancelled,
the `SupervisorTask` remains the identified handle owner; a later waiter can
observe the actual result. An abort request sets `coordinator_abort_requested`
and fail-closed supervisor state, but it does not set
`coordinator_join_observed`. Only polling the actual `JoinHandle` result
does so.

Deterministic tests hold the coordinator at a barrier, cancel an already
pending ordinary join waiter, and then perform a normal join. A separate
test cancels the abort-result waiter and later observes the cancelled task
result. The post-abort watchdog control returns `WatchdogUnresolved`, keeps
the join observer, and observes the actual cancellation afterward. The
detached-handle sensitivity fixture deliberately takes the JoinHandle out of
the guard; the same observer-ownership check rejects that state. Its guard
then requests abort on drop, but no JoinHandle remains to observe the result.
The final sensitivity state explicitly remains abort-requested,
supervisor-lost, and join-unobserved; it is not reported as successful
cleanup.

The test-only pause command waits without holding the snapshot mutex so
readers and loss-state publication remain observable at barriers.

## Verification

Exact focused command:

```text
cargo test -p qbind-node --test a33_f1_inprocess_owner_prototype_tests
```

Final raw output is preserved byte-for-byte in
`quarantine-owner-lease-tokio-cancellation-correction-raw.log`: exit 0,
**19 passed, 0 failed, 0 ignored**. The sensitivity tests are expected
rejections inside passing tests; no deliberately failing test is counted as
passing. Targeted formatting used:

```text
rustfmt --edition 2021 crates/qbind-node/tests/support/a33_f1_inprocess_owner.rs crates/qbind-node/tests/a33_f1_inprocess_owner_prototype_tests.rs
```

The supplied report was source review, not a runtime or production
reproduction. Intermediate test-only compilation/fixture corrections
occurred; one diagnostic run was stopped at its 20-second outer timeout
while investigating a state-locking barrier. The final focused run above
completed normally.

## Limits and scope

This is a non-wired, test-support-only, in-process component. Mock publication
is not filesystem or crash/power-loss durability. Tokio task abort/join does
not prove OS resource reclamation. The in-memory supervisor does not survive
process/runtime loss. No production consensus mutation, signer operation,
storage write, network action, startup classification, snapshot/restore
transition, callback, or outbound work is fenced. The accepted
substituted-snapshot test, prior retirement correction, and historical raw
logs are unchanged.

A33-F1 / E27 and all other unresolved obligations remain **OPEN**; activation
is **DISABLED**; public DevNet remains **NO-GO**.
