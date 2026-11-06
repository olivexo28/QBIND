# A33-F1 / E27 Tokio owner/lease harness correction

**TOKIO HARNESS CORRECTED — INDEPENDENT REVIEW PENDING.**

## Corrected model behavior

The integration test remains isolated and test-only. It does not modify or
wire production code, and the accepted substituted-snapshot model test was
not changed.

- Worker completion and effect knowledge are separate. `Outcome::Unknown`
  marks the worker complete but leaves the effect unresolved and blocks
  protected mutation. A separately established `Outcome::Observed`
  disposition permits the next modeled step when the publication, owner,
  cancellation, and pending-work conditions also pass.
- The model has one publication attempt and no retry semantics. A failed
  attempt is terminal; an uncertain attempt remains uncertain and terminal.
  Neither can be converted to acknowledgment. Known visibility precedes
  acknowledgment. Contradictory failure after acknowledgment downgrades the
  attempt to uncertainty, not permission.
- The owner-loss helper distinguishes abort request from observed
  termination. It requires the awaited `JoinHandle` result to be cancelled,
  then records task termination and transitions the owner to `Lost`.
  Completed-before-abort and unresolved join paths are not represented as a
  successful cancellation. A sensitivity control omits the loss transition
  after an observed supervisor abort and verifies mutation is refused.
- The ordinary-cleanup case no longer assigns latch values before checking
  them. It observes cleanup of a pending Tokio task, then verifies the
  existing refusal state remains closed. A faulted reopening is detected by
  the shared refusal validator.

New passing focused tests contain negative controls whose valid prefixes
are explicitly checked before asserting the intended refusal:

- `unknown_effect_blocks_mutation_but_known_disposition_allows_it` checks
  that `Unknown` blocks with `protected mutation blocked by unresolved
  external effect`; a duplicate known result is rejected. Its separate
  known-disposition branch admits exactly one mutation.
- `failed_and_uncertain_publication_attempts_cannot_become_acknowledged`
  checks valid pending/failure and pending/uncertainty prefixes, then rejects
  Failed → Acknowledged, Uncertain → Failed, and Uncertain → Acknowledged.
- `missing_owner_loss_transition_after_observed_task_abort_is_rejected`
  accepts the supervisor handoff prefix, observes an actual cancelled
  `JoinHandle`, injects the missing transition, and checks refusal before
  applying the proper loss transition.
- The existing sensitivity test injects an unauthorized reopen and checks
  the refusal validator reports `refusal latch reopened`.

These are deterministic in-process test assertions, not separate failing
security tests. The corrected target has no ignored or deliberately failing
tests; the negative controls are expected refusals within passing tests.

## Focused output discrepancy and verification

The previous committed
[`quarantine-owner-lease-tokio-focused.log`](quarantine-owner-lease-tokio-focused.log)
is preserved byte-for-byte. Its displayed `running 7 tests` disagreed with
its eight listed test names and eight-pass summary. An earlier captured raw
command output was available at `/tmp/a33-f1-tokio-owner-lease-tests.log`;
it reports **8 passed, 0 failed, 0 ignored**. Its bytes are preserved
verbatim in
[`quarantine-owner-lease-tokio-prior-raw.log`](quarantine-owner-lease-tokio-prior-raw.log),
not reconstructed from the old summary.

Corrected rerun commands:

```text
rustfmt --edition 2021 crates/qbind-node/tests/a33_f1_quarantine_tokio_owner_lease_tests.rs
rustfmt --edition 2021 --check crates/qbind-node/tests/a33_f1_quarantine_tokio_owner_lease_tests.rs
cargo test -p qbind-node --test a33_f1_quarantine_tokio_owner_lease_tests -- --nocapture --test-threads=1
```

The exact current captured command output, including compiler warnings, is
preserved in
[`quarantine-owner-lease-tokio-correction-raw.log`](quarantine-owner-lease-tokio-correction-raw.log).
It reports **11 passed, 0 failed, 0 ignored**. The build emitted eight
`qbind-node` library dead-code warnings; the test target emitted none. The
additional three tests are the controls listed above.

## Limits

Mocked publication is not filesystem or crash/power-loss durability.
Tokio task results do not prove OS resource reclamation. An in-memory
supervisor does not survive process/runtime loss. This harness does not
fence production signer, storage, snapshot, callback, or outbound work, and
does not establish startup enforcement, a durable marker, recovery,
clear/resume authority, deployment behavior, or activation.

A33-F1 / E27 and remaining obligations remain **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.
