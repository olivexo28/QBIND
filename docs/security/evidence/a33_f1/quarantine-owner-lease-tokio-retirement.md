# A33-F1 / E27 Tokio operation retirement boundary

**TOKIO COMPLETION-RETIREMENT CORRECTION — INDEPENDENT REVIEW PENDING.**

The supplied reviewer report identified a source-derived test-harness gap:
once the successful application joined and cleanup completed, the same
authority still satisfied mutation admission. This was not an executed
probe. The correction is confined to the isolated Tokio harness; the
substituted-snapshot model test and accepted Unknown, publication-terminal,
abort, cleanup, and test-count controls remain unchanged.

## Retirement contract in the model

`operation_retired` is distinct from task termination, operation
cancellation, effect knowledge, and owner loss. On the successful path:

1. The application task performs a permitted modeled mutation and returns.
2. Its `JoinHandle` is observed as successfully completed. This records
   application-task completion only; it does not cancel the operation or
   transfer/lose the refusal owner.
3. `Tasks::cleanup` aborts and observes remaining tasks. The successful-path
   cleanup watcher is pending; its `JoinHandle` is observed cancelled.
4. The current refusal owner explicitly calls `retire_operation`.
   Retirement requires successful application-task completion, observed
   cleanup, an acknowledged publication, resolved known effects, and no
   operation cancellation. The owner remains the Initiator in this path.
5. The same authority is refused with `completed operation authority is
   retired`; the mutation count is unchanged.

Retirement closes mutation authority for that completed operation. It does
not set `operation_cancelled`, change owner to `Lost`, reopen participation,
or grant clear/resume authority. An accepted handoff remains governed by
its supervisor: initiator task completion does not imply cancellation or
retirement. The supervisor/current refusal owner remains responsible for
refusal and outcome observation until it explicitly retires or is observed
lost under the existing owner-loss path.

No one-mutation limit is modeled. The live-operation control has the same
acknowledged publication and known resolved work preconditions but has not
completed or retired; two successive modeled mutations are admitted.
Retirement, not mutation count, is the subsequent-mutation boundary.

After retirement the current owner can still record a late `Unknown`
outcome and publication uncertainty. These observations preserve closed
participation and cannot clear `operation_retired`; an uncertainty-to-
acknowledgment transition remains rejected, and further mutation is refused
for the retirement reason.

## Sensitivity control

`omitted_retirement_sensitivity_detects_post_completion_mutation` builds a
valid acknowledged/known-effect prefix, admits its first mutation, observes
application-task completion and cleanup, then deliberately omits
`retire_operation`. The shared post-completion refusal assertion fails with
the exact diagnostic `retirement check detected mutation admitted after
completion`; the counter shows the defective second mutation was admitted.
The test asserts that precise expected failure as a sensitivity control and
passes. It is not counted as a separately failing test.

The sensitivity was also run directly:

```text
cargo test -p qbind-node --test a33_f1_quarantine_tokio_owner_lease_tests omitted_retirement_sensitivity_detects_post_completion_mutation -- --exact --nocapture --test-threads=1
```

Result: **1 passed, 0 failed, 0 ignored, 11 filtered out**. Exact output is
preserved in
[`quarantine-owner-lease-tokio-retirement-sensitivity-raw.log`](quarantine-owner-lease-tokio-retirement-sensitivity-raw.log).
This passing test verifies that the deliberately defective trace is rejected
by the expected assertion; it is not itself a deliberately failing test.

## Verification

Exact focused command:

```text
cargo test -p qbind-node --test a33_f1_quarantine_tokio_owner_lease_tests -- --nocapture --test-threads=1
```

The target reports **12 passed, 0 failed, 0 ignored**. The sensitivity
control is included in the passing target. Exact output is preserved in
[`quarantine-owner-lease-tokio-retirement-raw.log`](quarantine-owner-lease-tokio-retirement-raw.log).
Targeted formatting command:

```text
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_quarantine_tokio_owner_lease_tests.rs
```

## Limits

This is only an in-process test model. Mocked publication is not filesystem
or crash/power-loss durability. Tokio task results do not prove OS resource
reclamation. An in-memory supervisor does not survive process/runtime loss.
No production signer, storage, snapshot, callback, or outbound work is
fenced. No production wiring, startup enforcement, recovery, clear/resume
authority, deployment, or activation assurance is established.

A33-F1 / E27 and remaining obligations remain **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.
