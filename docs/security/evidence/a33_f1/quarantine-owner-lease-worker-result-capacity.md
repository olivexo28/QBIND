# Worker-result observation capacity boundary

**Status:** TEST-ONLY WORKER-RESULT CAPACITY INVESTIGATION — INDEPENDENT
REVIEW PENDING.

The scenario was supplied by the user. The user reports that the reviewer
inspected source and retained evidence but did not rerun Rust tests or the
full historical checksum verification. No reviewer identity or reviewer-run
counterexample is asserted, and the reported source shape is treated as an
investigation question rather than an assumed defect.

## Result semantics

`apply_worker_join` first marks the worker completed, then attempts to append
the exact returned observation if `state.observations.len() <
outcome_capacity`. At capacity it instead marks `outcome_overflow` and
shared overflow; it does not append the worker's returned value. After this
application, the coordinator sets `WorkerResultDisposition::Recorded`.
That state means the join result was applied to owner status/overflow state,
not that the raw observation was retained. In the full-capacity Known-value
case, the worker's exact returned observation is absent, `outcome_overflow`
is true, and `outcome_unknown` remains false. Overflow neither proves a
specific observation nor proves no effect. The admission path checks
overflow before known-effect state and returns `CapacityUncertain` without
incrementing `protected_admissions`.

The supported `RecordOutcome` route reserves one slot while the worker is
Running: it refuses when the observation count reaches
`outcome_capacity.saturating_sub(1)`. Therefore ordinary callers cannot
fill the observation vector to the configured capacity before the worker
join is processed. The full-capacity test deliberately uses a test-only
fixture to establish that defensive branch's precondition. It then uses a
barrier-held worker and the actual worker JoinHandle/result-application
path. It demonstrates branch behavior, not that normal API operations can
reach it.

A scoped search of the test-support tree found no consumer that interprets
`WorkerResultDisposition::Recorded` by itself as proof that the exact
observation is available. The enum is a harness observation and the
admission path uses `outcome_overflow`, `outcome_unknown`, and conflict
state. The meaning is now stated beside the enum; no classification change
was needed.

## Controls

`full_observation_capacity_applies_worker_overflow_without_retaining_value`
holds the worker at a oneshot barrier, seeds the configured two-slot
observation vector with repeated `Known(501)` values, and releases a worker
returning distinct `Known(599)`. It waits with the harness watchdog for the
actual join application, then checks:

- The owner retains exactly the two seeded values; `Known(599)` is absent.
- The worker JoinHandle result was observed; worker status is Completed and
  disposition is Recorded.
- `outcome_overflow` is true; `outcome_unknown` and `outcome_conflict` are
  false.
- The real `OperationOwner::admit_protected_operation` path returns
  `CapacityUncertain`; `protected_admissions` is unchanged.

The test calls the same capacity checker with an intentionally false
expectation that `Known(599)` was retained. The checker rejects that
expectation while still verifying the actual overflow refusal and unchanged
counter. This sensitivity is an expected assertion inside the passing
test, not a separately executed failing child or a separate security pass.

`available_observation_capacity_retains_distinct_worker_value` uses the
same worker barrier and a two-slot capacity with an initially empty
collection. The join result is retained as `Known(777)`, no overflow or
unknown flag is set, and the same checker observes successful admission and
the corresponding counter increment.

The StateReader remains alive in both controls and retains its command
sender. No behavior is attributed to channel closure. The worker and
coordinator tasks are owned by the harness; tests release the worker barrier,
wait for owner-state application with a bounded watchdog, drop the owner and
reader, and observe the coordinator JoinHandle result.

## Verification

Focused command:

```text
cargo test -p qbind-node --test a33_f1_inprocess_owner_prototype_tests -- --nocapture
```

Final raw output: **30 passed, 0 failed, 0 ignored**, retained in
`quarantine-owner-lease-worker-result-capacity-focused.log`.

Directly affected regression:

```text
cargo test -p qbind-node --test a33_f1_quarantine_tokio_owner_lease_tests -- --nocapture
```

Final raw output: **12 passed, 0 failed, 0 ignored**, retained in
`quarantine-owner-lease-worker-result-capacity-regression.log`. No
unsuccessful test or formatting attempts occurred in this investigation.
The prior worker-loss accounting focused run and regression also passed
before these additions; their raw files were not overwritten.

## Scope and limits

Only the test-support prototype, its tests, and append-only plan/evidence
change. No production capacity or result schema is selected. This does not
establish durable evidence, production worker reclamation, startup
enforcement, signer fencing, network delivery, or recovery. P1/P2,
substituted-snapshot, retirement, and prior worker-observation acceptances
remain in their previously reviewed scopes. A33-F1 / E27 remain **OPEN**;
activation **DISABLED**; public DevNet remains **NO-GO**.
