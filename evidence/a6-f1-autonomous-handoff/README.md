# A6-F1 autonomous recovery of interrupted fatal-read handoff

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** This is a bounded follow-up
to the monitor-ownership correction, not closure of A6-F1 / OBL-AVL-4a /
E14. Those and all other remaining obligations stay **OPEN**; activation
**DISABLED**; public DevNet **NO-GO**.

## Entry, controlling input, and attribution

Entry verification found the clean existing task branch
`copilot/a6-f1-fatal-read-cleanup` at
`86f606382fbb3efe70b838e5b0d021211334283f`, tree
`99970b270acfb6323c0377314a46299de46ae086`. Local `main`, `origin/main`,
and remote `main` matched
`50bf93d8b1b6b0739cdce5e95334cd726af2386e`, tree
`dfe11db1e9b55de89df1a565b2df83cdba7d91c0`; the remote task ref matched
the expected starting tip. No prior commit was rewritten.

The controlling input remains
`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`, blob
`cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0`, SHA-256
`6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9`.
Anchors A:L17267-L17269 distinguish worker fatal delivery/backpressure,
application decode exits, and incomplete worker/socket cleanup;
A:L17271-L17279 retain the eviction/trust-reload boundary and bounded,
observable cleanup requirement; A:L17282 retains the disposition.
The register, remediation-plan history through section 22, and earlier
evidence are preserved. Current Run 072 tests below are transport regressions
on this producer, not a reconstruction or alteration of historical Run 072
evidence or its provenance.

The user supplied the independent-review finding that a monitor panic after
the reader observes a fatal error can leave the session active until external
cleanup. No reviewer identity was supplied for this follow-up; none is
inferred. The baseline reproduction and producer runs here were performed by
the authoring Copilot agent, not an independent reviewer. The original
ChatGPT source inspection and its narrower limits remain attributed in the
earlier evidence. Earlier author logs do not themselves embed producing
commit identities; their prior history-based associations are not upgraded
to self-identifying logs by this record.

## Baseline reproduction

An isolated detached worktree at the exact starting commit/tree received only
the retained `baseline-test.patch`. Its added loopback test pauses the actual
registered-session monitor after the fatal decode error and reader join,
then injects either the existing monitor panic or monitor cancellation.
Before any replacement, shutdown, or explicit cleanup, both subcases report:

```text
fatal_observed=true reader_join=completed monitor_finished=true active=1 retiring=0
```

The exact command was:

```sh
cargo test --manifest-path /tmp/qbind-a6-handoff-baseline/Cargo.toml --target-dir /workspaces/QBIND/olivexo28/QBIND/target --locked --offline -p qbind-node --lib baseline_interrupted_fatal_handoff_remains_active_without_external_cleanup -- --nocapture
```

`tests/baseline.log` embeds the baseline commit/tree, command, and exit status.
It reports **1 passed, 0 failed** because the test asserts the defect, for
both panic and cancellation; this is not a successful cleanup result.
Only after those assertions does the baseline test request explicit cleanup.
The isolated worktree was removed after verifying its diff matched the
retained patch checksum. No production baseline source or prior evidence
was changed. Injected panics/cancellations are test controls, not observed
production incidents.

## Producer and correction

Source/test producer: commit
`74b8a952e0d61b02a14f615e9c4153852dc61ba8`, tree
`9fca8d7869a35822f2983f63e340afc2658c307a`, parent
`86f606382fbb3efe70b838e5b0d021211334283f`.
`crates/qbind-node/src/p2p_tcp.rs` blob:
`2430abbb742aa698caa056d04009a33efa4f40de`.
All source anchors below refer to that producer.

The retirement owner now stores a supervisor handle/outcome in addition to
the monitor handle/outcome (`p2p_tcp.rs:386-407`). Registration starts both
tasks before active publication under the registry lock (`:1884-1960`).
The supervisor awaits the monitor through its shared, stored handle,
persisting the monitor result before clearing that handle (`:479-521`).
It distinguishes operation errors from monitor cancellation/panic.

On monitor cancellation/panic with a recorded terminal reader failure, the
supervisor moves the exact identity out of active service before its next
cancellable wait and attempts cleanup with the existing five-second bound
(`:1973-2020`). It never joins itself. The identity-checked registry
transition and count update remain under the registry lock (`:2119`);
reader/writer joins and channel-worker/socket cleanup are outside it.
`finish_registered` removes only the exact retained owner after independently
establishing cleanup (`:523-543`). Delayed old recovery cannot invalidate or
remove a newer session.

Reader/writer handles remain stored across cancellation and timeout
(`:416-455`). Explicit cleanup first observes the supervisor and original
monitor, then independently verifies task/worker cleanup (`:458-477`).
Persistent monitor/supervisor outcomes are not erased on retry, including
`OperationFailed`, `Cancelled`, and `Failed`. A stored cleanup-operation
error is retryable; a monitor JoinError alone does not establish cleanup.
An identity can be released after actual reader/writer and worker cleanup
has independently been established, while its retained diagnostic outcome
still records the earlier failure. A shutdown request or task abort is not
counted as a completed join.

### Deterministic controls and observed boundaries

`interrupted_fatal_handoff_autonomously_retires_and_retains_failed_cleanup`
(`:3397`) covers panic and cancellation after fatal reader completion but
before publication, with injected socket-shutdown operation failure.
Without replacement, shutdown, or `finish_and_wait` driving the initial
handoff, it waits for the supervisor to finish, verifies active count zero
and exact retained retirement ownership, and checks saved monitor failure
versus still-unobserved blocking-worker outcomes. Repeated cleanup remains
failed and owned; clearing the operation failure permits independently
observed joins and remote EOF on retry.

`interrupted_fatal_handoff_completes_without_external_cleanup_and_is_identity_checked`
(`:3481`) covers both injections without cleanup failure. It waits for
autonomous retirement without calling explicit cleanup, then separately
asserts reader/writer completion, blocking-worker completion, and remote EOF.
It registers a newer session and replays the actual old recovery route,
verifying unchanged new identity/count and delivery of a healthy heartbeat.

The retained lifecycle suite separately covers ordinary EOF and frame-decode
retirement without direct `finish_and_wait` (`:3160`, `:3187`), healthy,
idle-timeout and unrelated peers (`:3213`), pre-completion monitor
cancellation/reader ownership (`:3303`), panic versus replacement (`:3553`),
service drop (`:3617`), failed cleanup/replacement (`:3645`), cancelled
shutdown (`:3685`), eviction snapshots (`:3714`, `:4264`), queue-blocked
detection (`:3754`), join-failure/timeout retry (`:4063`), terminal shutdown,
and single-outbound-connection controls.

### Reference graph and service drop

While waiting, the supervisor strongly owns only the shared monitor slot
and its saved outcome; it holds a weak retirement reference. The monitor
strongly owns the task store but holds weak registry/retirement references.
There is no persistent idle
registry/retirement/supervisor/monitor ownership cycle. Fatal recovery
temporarily upgrades the retirement owner only for the bounded cleanup
attempt; timeout or return releases that reference, leaving unresolved
cleanup in the registry's retirement owner when the service remains alive.

The retained service-drop test confirms the registry and retirement owner
are released if the service is dropped without shutdown, then closes the
remote peer and confirms the task store is released. It does not show
worker/socket reclamation while the remote peer remains connected. In that
case, pending reader/monitor/supervisor tasks can remain detached until peer
closure or runtime teardown. Completing shutdown remains required for
cleanup assurance; weak ownership avoids an unbounded reference cycle, not
all detached work.

## Exact producer commands and results

The following raw logs embed producer commit/tree/source blob, exact command,
and exit status. Test output and existing compiler warnings are retained.
All commands exited zero; **96 tests passed, zero failed**.

| Log | Exact command | Result |
|---|---|---|
| `tests/peer-retirement.log` | `cargo test --locked --offline -p qbind-node --lib p2p_tcp::peer_retirement_tests -- --nocapture` | 34 passed |
| `tests/secure-channel.log` | `cargo test --locked --offline -p qbind-node --lib secure_channel::` | 16 passed; includes A5-F1 partial-frame and A11-F2 no-re-encryption/replay controls |
| `tests/transport-regressions.log` | `cargo test --locked --offline -p qbind-node --test b8_listener_identity_closure_and_dial_retry_tests --test run_072_p2p_session_eviction_tests --test run_074_pqc_trust_bundle_live_reload_tests --test run_418_authenticated_peer_consensus_sender_binding_tests --test run_418_newview_demux_chain_integration_tests` | B8 6, Run 072 8, Run 074 10, Run 418 sender binding 18 and demux 4 passed |
| `tests/cargo-check.log` | `cargo check --locked --offline -p qbind-node --lib` | passed with existing warnings |
| `tests/rustfmt.log` | `rustfmt --edition 2021 --config skip_children=true crates/qbind-node/src/p2p_tcp.rs --check` | passed |
| `tests/source-whitespace.log` | `git diff 86f606382fbb3efe70b838e5b0d021211334283f HEAD --check -- crates/qbind-node/src/p2p_tcp.rs` | passed; HEAD was the producer above |

### Discarded validation attempt

After running the isolated baseline with the shared Cargo target, an initial
attempt to validate the modified working source unexpectedly reused the
baseline executable. The lifecycle filter reported **33 passed** and
included the baseline-only test, rather than the two new controls.
`tests/discarded-stale-baseline-artifact.log` preserves that output; it has
no embedded producer identity and is **not producer validation**. No actual
test assertion failed in that attempt, but it did not test the intended
source. Updating the producing source timestamp forced recompilation;
the rebuilt precommit lifecycle suite passed 34/34. The separately
commit-pinned final lifecycle log above again passed 34/34 and contains both
new controls, not the baseline-only test. The removed baseline worktree
cannot subsequently rebuild over the accepted producer artifacts.

Source and prose whitespace checks pass. The full staged `git diff --cached
--check` exits 2 only for retained artifact bytes: a blank context line in
the baseline patch, the trailing space emitted by the command-printing
wrapper in six log headers, and the final blank line in the discarded raw
Cargo output. These artifacts are not normalized after checksumming.

### SHA-256 of retained artifacts

| Artifact | SHA-256 |
|---|---|
| `baseline-test.patch` | `fa60b80883d9e66aa5f746e5bff2843915a427b129ecdba2893ee337c9b8412e` |
| `tests/baseline.log` | `bb098c1c320397d5474357cf7f964c7315ec375eeb3ffb6112daaf30378f0c65` |
| `tests/discarded-stale-baseline-artifact.log` | `fb97509442c5a50d3bb2466738901e3497d8286351279472097f4e4924cdcf38` |
| `tests/peer-retirement.log` | `937dc492018e716205d4e13d7d7dd39024c99dc7cad9fe597df8d96c2602b5f7` |
| `tests/secure-channel.log` | `c66147498424b233791395c7027baec5bc5f075f25a92ff3aa0cfb6bb979e83b` |
| `tests/transport-regressions.log` | `09f9739916a1a97be14a8ba1b4af08914ff4dff7a9f6521dc36026ca0e23aba2` |
| `tests/cargo-check.log` | `4de5f0fc8cec9af00b193451ba9cb91ad0b544d9a644957f3c5ecebe281a1f8d` |
| `tests/rustfmt.log` | `68f9489beb9503d781075bb3428a4273de90a4f92db4e6b0fdd82122725257da` |
| `tests/source-whitespace.log` | `85b17afe34b166b71adf34b52d514eb767a2e76f8c8d2be1554252726ee95ef9` |

These are author-run local loopback controls, not independent review,
deployment evidence, or platform/runtime assurance.

## Explicitly retained limitations and gates

The new supervisor is not recursively supervised. Interruption of that
supervisor leaves its stored handle/outcome and the original monitor/task
handles available for later explicit cleanup, but autonomous recovery from
arbitrary supervisor failure or runtime teardown is not established.
Monitor interruption before a terminal reader failure is recorded is
outside the tested observed-failure handoff: the supervisor does not wait
for a future fatal after observing a monitor failure with no recorded
read failure. Panic controls exercise unwind behavior, not panic-abort.

Queue/downstream backpressure can still prevent a terminal error from
becoming observable. This work does not close that detection gap, broader
E14, complete eviction/trust-reload cleanup, cleanup of all displaced
sessions through every lifecycle route, global resource/exhaustion bounds,
OS socket reclamation, or platform/runtime assurance. Authentication and
crypto settings are unchanged. Already delivered messages and operations
already progressed cannot be retracted. Terminal shutdown fencing,
connection counts, eviction snapshot semantics, A5-F1 partial reads,
A11-F2 no replay, idle retry, and the outbound correction remain preserved.

No live network, deployment, operational signing, or activation was run.
Only the existing task branch is authorized for push; no PR, merge,
main update, or force-push. Independent review remains **PENDING**.
A6-F1 / OBL-AVL-4a / E14 and all other remaining obligations stay **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**.
