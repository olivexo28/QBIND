# A33-F1 / E27 test-only Tokio owner/lease lifecycle harness

**TOKIO OWNER/LEASE TESTS — INDEPENDENT REVIEW PENDING.**

## Scope and implementation

The isolated integration test
`crates/qbind-node/tests/a33_f1_quarantine_tokio_owner_lease_tests.rs`
uses synthetic state and a mock publisher. It is not wired to the consensus
engine, quarantine marker/backend, startup, CLI, signer, network, or a live
node. The state models refusal ownership, accepted handoff, operation
cancellation, publication visibility/acknowledgment/failure/uncertainty,
outstanding work, observed outcomes, and protected mutation admission.

Tokio tasks are spawned for the initiator, supervisor, mock publisher,
application, and independently owned external result. `mpsc` and `oneshot`
channels establish the test stages; no sleep decides whether a race occurred.
Join handles are observed. A three-second watchdog bounds waits; abort
helpers observe the `JoinHandle` result, and scenario cleanup aborts and
observes remaining tasks before asserting the scenario result. `Drop` only
requests abort as a fallback and is not represented as observed cleanup.

Seven focused tests cover:

- initiator cancellation before the supervisor accepts responsibility;
- accepted handoff followed by initiator task completion, with the
  supervisor observing outstanding work;
- operation cancellation after accepted handoff, preventing supervisor
  mutation while preserving the later observed outcome;
- mock publication completion before/after cancellation, failed and
  uncertain publication, and cancellation of a publisher blocked on a gate;
- supervisor recording a visible publication after the accepted initiator
  has ended, without granting mutation authority;
- observed supervisor abort followed by a late `Unknown` from a separately
  owned task, without reopening mutation;
- successful modeled application and ordinary cleanup without reopening;
- sensitivity rejection of unauthorized mutation, handoff before receiver
  acceptance, and reopening participation.

These are harness behavior tests, not proofs that a real owner/lease
mechanism is correct or integrated. The sensitivity test exercises the
model's deliberate refusal methods; it is not an external adversarial test
of production code.

## Verification result

The focused target reported **8 passed, 0 failed, 0 ignored**. Exact
commands and test names are in
[`quarantine-owner-lease-tokio-focused.log`](quarantine-owner-lease-tokio-focused.log).
The library build emitted eight existing dead-code warnings; the test target
emitted no warnings on the final run.

## Limits

- Mock publication is not filesystem, crash, or power-loss durability
  evidence.
- Tokio task abort and `JoinHandle` results do not prove OS resource
  reclamation or establish behavior under every runtime schedule.
- The in-memory supervisor does not survive process or runtime loss.
- The harness does not fence actual signer, storage, snapshot, callback, or
  outbound work, and does not establish an engine-wide production lease.
- It establishes no startup enforcement, signer exclusivity, currentness,
  durable marker, recovery, clear, resume, network delivery, deployment, or
  activation behavior.

A33-F1 / E27 and remaining obligations remain **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.
