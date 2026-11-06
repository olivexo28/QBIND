# Test-only worker observation after coordinator loss

**Status:** TEST-ONLY WORKER-OBSERVATION INVESTIGATION — INDEPENDENT REVIEW
PENDING.

This investigation is confined to the non-wired in-process owner prototype.
The supplied reviewer report raised an outstanding-worker observation
question; no reviewer identity, reviewer-run tests, production failure, or
anonymous remote reachability is asserted.

## What remains observable

The worker `JoinHandle` is owned by `WorkerJoin` inside the coordinator
future. If that future is aborted or panics, dropping `WorkerJoin` records
that a worker abort was requested and marks its result unobserved, then
requests abort and drops the worker handle. The shared state remains closed
to protected-operation admission. Neither an abort request nor dropping a
handle establishes the worker's `JoinError` or proves absence of an external
effect.

The deterministic pre-effect control holds the worker before any mock
publication, aborts and joins the coordinator, and receives a test-only
notification that the worker future was dropped. It observes coordinator
abort requested and joined, worker abort requested, no worker result/join
observed, no publication or recorded effect, and fail-closed admission with
no counter increment. The shared worker status deliberately remains
`Running`: the worker `JoinHandle` result was discarded, and the drop
notification is only direct evidence that this instrumented future reached
its Rust drop path, not OS reclamation.

The post-publication control observes mock publication `Acknowledged`, then
holds a worker-produced `Known` result behind a barrier while the coordinator
panics. The coordinator panic result is observed; the worker's held result
is discarded as its future is dropped. No worker result or effect
observation is recorded by the owner, and admission remains refused. The
acknowledged mock publication is direct evidence of the synthetic effect;
it does not make the worker result available to another observer.

When the outer `SupervisorTask` guard is dropped, the test observes the
coordinator future's drop marker and worker-future drop marker, but there is
no coordinator JoinHandle observer and no worker JoinHandle observer.
Coordinator termination is therefore not represented as an observed join.
The owner remains closed. Each shutdown test retains its `StateReader`,
which itself retains a command sender; no channel-closure result is
attributed to those configurations.

In the normal control, the coordinator observes the worker's actual
`JoinHandle` result and then its own join result. The sensitivity control
clears the unobserved-result marker on the documented shutdown trace; the
same lifecycle checker rejects it specifically as
`WorkerResultNotMarkedUnobserved`. This expected detector rejection occurs
inside a passing test and is not a separate passing security test.

## Verification

The exact task-tip baseline `8521941968953a5149d7811616182acbd68e3bc0` was
checked out in a detached temporary worktree. The focused command was
`CARGO_TARGET_DIR=/workspaces/QBIND/olivexo28/QBIND/target cargo test -p qbind-node --test a33_f1_inprocess_owner_prototype_tests`:
**19 passed, 0 failed, 0 ignored**. Its raw output is preserved in
`quarantine-owner-lease-worker-observation-baseline.log`.

The current focused command
`cargo test -p qbind-node --test a33_f1_inprocess_owner_prototype_tests`
reports **24 passed, 0 failed, 0 ignored**. The directly affected regression
command
`cargo test -p qbind-node --test a33_f1_quarantine_tokio_owner_lease_tests`
reports **12 passed, 0 failed, 0 ignored**. Both raw outputs are preserved in
the corresponding `quarantine-owner-lease-worker-observation-*.log` files.
Targeted formatting passed with
`rustfmt --edition 2021 --check crates/qbind-node/tests/support/a33_f1_inprocess_owner.rs crates/qbind-node/tests/a33_f1_inprocess_owner_prototype_tests.rs`.
`git diff --check` also passed.

During implementation, one compile attempt failed because the test marker
clearer was on the wrong test-only handle and a `oneshot::Sender` was moved
from `Drop`; both were corrected. That intermediate diagnostic output was
not retained as a raw artifact. These compile errors are not test failures
and are not counted in the passing results.

## Limits

The prototype has no surviving worker-result observer after coordinator
loss; the best available state is a fail-closed owner plus an explicit
unobserved/unavailable result marker. The pre-effect test confirms only the
instrumented worker future's drop path. The post-effect test confirms only
the mock publication state and that the coordinator did not record its
worker result. No test establishes external-effect absence, worker
reclamation by the runtime or operating system, recovery of a discarded
handle, process/runtime-loss durability, or a production ownership rule.
This investigation adds no production work, startup gate, durable backend,
signer, network, real catch-up, recovery, or clear/resume implementation.

A33-F1 / E27 and all other unresolved obligations remain **OPEN**; activation
is **DISABLED**; public DevNet remains **NO-GO**.
