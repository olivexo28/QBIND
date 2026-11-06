# A33-F1 / E27 non-wired in-process ownership component prototype

**Status: NON-WIRED OWNERSHIP COMPONENT PROTOTYPE — INDEPENDENT REVIEW
PENDING.** A33-F1 / E27 and all other unresolved obligations remain OPEN;
activation DISABLED; public DevNet NO-GO.

This prototype adds an integration-test-only support component in
`crates/qbind-node/tests/support/a33_f1_inprocess_owner.rs` and a focused
target in `crates/qbind-node/tests/a33_f1_inprocess_owner_prototype_tests.rs`.
It is not a library module and has no production caller. Its only modeled
"protected operation" is an in-memory admission counter.

## Containment contract

- One operation is represented by a bounded Tokio command channel, a
  supervisor task that owns and awaits the worker `JoinHandle`, and a
  refusal-only state snapshot. `StateReader` observes state without keeping
  the command channel open.
- A handoff offer does not transfer ownership. The supervisor command loop
  changes the recorded owner only after processing the receiver's explicit
  acceptance. If the receiver cannot acknowledge acceptance, the old owner
  is not treated as having transferred responsibility. Ending the initiating
  waiter after successful acceptance is distinct from cancelling the
  operation; the accepted supervisor remains responsible for result
  observation and refusal.
- Dropping the owner is not task completion. Worker completion, cancellation,
  and panic are recorded only from the actual worker `JoinHandle` result.
  Worker completion is separate from effect knowledge; `Unknown`, conflicting
  observations, and capacity uncertainty block admission.
- Command and observation capacities are bounded. A full command queue sets
  a fail-closed overflow flag and returns the attempted admission/outcome to
  its caller as a refusal. A full outcome store returns the unrecorded
  observation and permanently blocks admission. One observation slot is
  reserved for the worker result. Outcomes after retirement can be recorded
  if capacity remains, but cannot reopen participation.
- Publication is a one-attempt mock interface. Pending, visible,
  acknowledged, failed, and uncertain are distinct; a failed or uncertain
  attempt cannot be acknowledged later. Retry identity and retry semantics
  are outside this prototype.
- Explicit operation cancellation and terminal retirement both remain
  refusal-only. Retirement requires an observed completed worker, a known
  consistent outcome, and acknowledged publication. Neither transition
  grants clear, resume, or participation authority. The tests record late
  uncertain publication and Unknown outcome observations after retirement
  and confirm they cannot restore admission. A live operation is not
  restricted to one modeled mutation; the tested boundary is retirement.

## Focused tests

Exact command:

```text
cargo test -p qbind-node --test a33_f1_inprocess_owner_prototype_tests
```

The retained raw output reports **11 passed, 0 failed, 0 ignored**. The test
target covers pre-acceptance owner loss and refusal; accepted handoff with
initiator completion; operation cancellation after handoff; worker success,
cancellation, and panic; mock publication failure and uncertainty; late
Unknown and conflicting outcomes; outcome and command queue capacity
refusals; explicit retirement and live-operation admission; and supervisor
abort and panic with actual `JoinHandle` results observed.

Sensitivity controls preserve valid prefixes and check their intended
rejection reasons: receiver ownership cannot appear before explicit
acceptance; unobserved work refuses as `WorkerStillRunning`; reopening after
cancellation refuses as `OperationCancelled`; reopening after retirement
refuses as `OperationRetired`; and a malformed open-refusal snapshot is
rejected as `RefusalInvariant`. These are expected detector assertions
inside passing tests, not deliberately failing tests.

`rustfmt --edition 2021 --check` passed for both Rust files. Focused command
output and format output are retained in
`quarantine-owner-lease-component-prototype-focused.log` and
`quarantine-owner-lease-component-prototype-format.log`.
The raw Cargo stdout's terminal blank line is preserved; `git diff --check`
flags only that captured-output blank line, while the remaining staged diff
passes whitespace checking.

## Limits and remaining evidence

Mock publication is not filesystem, crash, or power-loss evidence. Tokio
abort requests and observed join results do not prove OS resource
reclamation. If the coordinator is aborted, its join result is observed and
the snapshot reports supervisor loss; if the runtime or process disappears,
the in-memory owner and state do not survive. No persistent record format,
filesystem path, initialization or currentness authority, generation fence,
signer exclusivity, production allow/clear/resume result, or recovery
authority is selected. No actual consensus mutation, signer operation,
storage write, network call, startup classification, restore transition, or
production callback is reachable through this component.

The tests do not establish crash durability, startup enforcement, actual
signer/storage/network fencing, deployment safety, or recovery. No live
node/network, operational signing, deployment, or activation was performed.
The previously accepted substituted-snapshot test and prior Tokio harness,
raw logs, and audit evidence remain unchanged.
