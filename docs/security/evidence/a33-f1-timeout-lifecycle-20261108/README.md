# A33-F1 / E27 — actual Timeout signer lifecycle observation

**TIMEOUT SIGNER LIFECYCLE SEAM — INDEPENDENT REVIEW PENDING.**

## Provenance and implementation

Repository: `olivexo28/QBIND`. The task branch
`test/a33-f1-timeout-signer-lifecycle` starts at reviewed documentation
commit `11601eb5d7a90b937dcbd40436c538e026e2d93b`, tree
`a707f2eb70f897480f27a697664e690866f07eed`, whose parent is
`22c5ebc551b8ed6568f667f1a7980a0fc115838c`. `main` remains
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`.

The test/source-producing history is:

- `1138013e230702e6b2a4126137eb16d38e150141`, tree
  `1e27480c38ce88576834b40669a8d7fb7662bd1c`, parent
  `11601eb5d7a90b937dcbd40436c538e026e2d93b`: initial test-only seam.
- `07be196f762288dcbf576810503ef8bdd3bbea8a`, tree
  `3bbc10fd7d37044f63b1fc40072ed1f089539f2d`, parent
  `1138013e230702e6b2a4126137eb16d38e150141`: strengthened
  check-then-act sensitivity control. All final-source executions below
  were run at this commit and tree.

The source change is limited to a nested test module in
`crates/qbind-node/src/binary_consensus_loop.rs` under its existing
`#[cfg(test)] mod tests`; the production `maybe_emit_view_timeout_with_auth`
and its guards are unchanged.

Source anchors in the final tree:

- Production Timeout entry and unchanged admission/F7 checks:
  `crates/qbind-node/src/binary_consensus_loop.rs:7563-7730`; the real
  `sign_timeout_with_chain_id` call, verification and downstream flow are
  at `:7731-7790`.
- Test-only owner/coordinator and observations:
  `:26402-26420`; the four test bodies are at `:26873`, `:26933`, `:27016`
  and `:27084`.

The test module admits one outstanding operation and at most two local
executors (worker plus child). Its mutex serializes revoke and the final
signing-effect permit. A pauseable `ValidatorSigner` records wrapper entry
separately from invocation of the actual `LocalKeySigner`; test-only fixture
keys are disposable. The real timeout-emission function constructs, signs,
verifies, ingests and sends the Timeout through a recording facade. Existing
F7 authorization refusal is exercised without bypass: its recorded wrapper
and underlying-signer counts remain zero.

## Results

Environment: `/workspaces/QBIND/olivexo28/QBIND`; Ubuntu 24.04; Rust
`rustc 1.99.1 (58cf8f9c3 2026-10-13)`, Cargo
`1.99.1 (5f94df478 2026-08-27)`; target
`x86_64-unknown-linux-gnu`; default workspace test profile
(`debug=0`, `strip=debuginfo`, `incremental=false`).

| Execution | Command | Result |
|---|---|---|
| Initial focused attempt (developmental, before correction) | `cargo test -p qbind-node --lib a33_timeout_lifecycle -- --nocapture` | **Failed:** 3 passed, 1 failed, 0 ignored. `capacity_child_handoff_and_check_then_act_sensitivity` exposed that the fixture had not closed admission before claiming local quiescence. The test was corrected to revoke before retiring the operation. Shell exit code was not separately captured in this retained log. Full output: `focused-initial-failure.log`. |
| Corrected focused and direct regression runs (developmental; before final sensitivity strengthening) | Same focused command; `cargo test -p qbind-node --lib run422_f7_retained_qc_local_timeout -- --nocapture` | **Passed:** focused 4/4 and regressions 3/3, zero ignored. These runs precede the final source commit and are retained only as developmental history: `focused-precommit-pass.log`, `focused-postcommit.log`, `regressions-precommit.log`, `regressions-postcommit.log`, `production-check.log`. |
| Final focused run at `07be196f...` / `3bbc10fd...` | `cargo test -p qbind-node --lib a33_timeout_lifecycle -- --nocapture` | **Passed:** 4 passed, 0 failed, 0 ignored; 2,251 filtered; exit code 0. Full output and exit code: `focused-final.log`. |
| Final direct regressions at `07be196f...` / `3bbc10fd...` | `cargo test -p qbind-node --lib run422_f7_retained_qc_local_timeout -- --nocapture` | **Passed:** 3 passed, 0 failed, 0 ignored; 2,252 filtered; exit code 0. Full output and exit code: `regressions-final.log`. |
| Final non-test library check at `07be196f...` / `3bbc10fd...` | `cargo check -p qbind-node --lib` | **Passed**, with existing unused/dead-code warnings; exit code 0. Full output and exit code: `production-check-final.log`. |

The four new test bodies, each passing in the final focused run, are:

- `actual_timeout_guard_refusal_and_success_are_observed_end_to_end`
- `invoked_error_unknown_and_late_stage_failure_keep_signature_observations`
- `revocation_order_and_cancelled_waiter_preserve_worker_ownership`
- `capacity_child_handoff_and_check_then_act_sensitivity`

The three existing local-Timeout regression bodies rerun in the final pass
are `run422_f7_retained_qc_local_timeout_accepts_exact_lock_before_consumption`,
`run422_f7_retained_qc_local_timeout_refusal_preserves_signing_and_consumption_state`
and
`run422_f7_retained_qc_local_timeout_formed_tc_is_rechecked_before_apply_and_publication`.
These are repeated executions of four new and three existing bodies, not
eighteen distinct tests. Cargo reports filtered counts, not ignored tests.

An earlier build attempt did not reach test execution because `bindgen`
could not locate `libclang.so` (Cargo exit 101); its complete output is
`initial-build-missing-libclang.log`. `libclang-dev` was installed, after
which the test and check commands completed. The failed test execution above
is retained separately and is not counted as passed evidence.

## What the controls observe

- The existing F7 refusal happens before `ValidatorSigner` wrapper entry;
  successful admission reaches the wrapper and underlying local signer.
- The signer-error case generates a disposable-key signature inside the
  signer but returns an error to the caller. The recorded effect remains
  Unknown after the synchronous Timeout function returns: local quiescence
  is true while the seam's closure-safe predicate is false. This earlier
  control did not establish termination of a separate worker thread.
- The corrupt-return control records signature bytes returned to the
  function, then observes the real verifier reject them before engine
  ingestion or publication. A successful-signature control observes engine
  timeout state and the actual Timeout facade call. The injected facade
  failure preserves the signature and engine-ingestion observations while
  reporting no successful publication.
- With revocation before permit, the actual function reaches the recording
  wrapper but the underlying signer is not called. With permit before
  revocation, the already-permitted signer returns late; dropping the
  completion receiver does not cancel the paused call. The earlier test
  observed a live executor while the signer was paused and zero after join,
  but did not observe the interval after the Timeout function completed and
  before the worker returned.
- A real child thread is held across the parent operation. Registered
  handoff prevents quiescence until child join; a deliberately omitted
  ledger handoff is detected by the separate test-harness physical-thread
  observation. The capacity control refuses both an additional operation
  and an additional child slot. Exhaustion and missing ownership refuse the
  seam's closure claim.
- The stale-check sensitivity control deliberately runs a cached-admission
  check/revoke/effect mutant through the real Timeout function and actual
  disposable-key `LocalKeySigner`, producing a signature after revocation.
  The seam records that effect but refuses its closure claim because no
  serialized permit was acquired. The ordinary serialized permit path
  refuses acquisition after revocation.

The child/thread registry is test instrumentation, not production discovery
of arbitrary threads. These tests do not establish external signer outcome,
worker coverage outside the exercised Timeout operation, durable Timeout
anti-equivocation, production coordinator wiring, power-loss durability,
cross-host exclusivity, HSM behavior, copied-state protection, restart
safety or participation authority. In particular, the fixture proves a
valid local signer-invocation path and a refused-before-signing path; it does
not make the lifecycle seam a production fence.

No live node, deployment, operational key or public network was used.
The reviewed A/B/C fencing decision and the separate refusal-only
classifier remain unchanged. No durable journal, recovery permission or
activation path is added.

Earlier developmental logs are retained unchanged and are not substituted
for final-source evidence. `SHA256SUMS` records checksums for every captured
`.log` file in this directory.

## TSL-1/2/3 correction

The follow-up record in
`docs/security/evidence/a33-f1-timeout-lifecycle-tsl123-20261108/README.md`
supersedes the original seam's state-retirement and timing claims. It adds
an actual error-after-invocation followed by denied-permit control, isolates
an omitted-child mutant with the child as the sole physical executor, and
places a deterministic barrier between Timeout-function completion and
worker termination. The original ten log files and this directory's
historical `SHA256SUMS` are unchanged; the corrective evidence is stored
separately.

**Remaining OPEN:** Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27.
Activation **DISABLED**; public DevNet **NO-GO**.
