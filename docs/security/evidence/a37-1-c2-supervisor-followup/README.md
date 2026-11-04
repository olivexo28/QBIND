# A37.1-C2 / A38-iv watchdog-parent ownership follow-up

**IMPLEMENTED — VERIFICATION PENDING.** Independent post-correction review
**PENDING**. E07 / OBL-GOV-2 **OPEN**; activation **DISABLED**; public
DevNet **NO-GO**. This is a bounded implementation-review correction,
not a new canonical audit finding.

## Entry, independent review and reproduction

The user supplied independent review confirmed exact-destination publication,
the original correction's 32 checksums and 33-path manifest, and the validity
of its retained 120-invocation pass for the conditions actually tested.
That review separately reported an unchanged-function reproduction: a
KeyboardInterrupt during watchdog-parent waitpid polling left its worker
and inert surrogate group alive, UNSAFE_GROUPS empty, and allowed workspace
deletion. Reviewer-owned outer cleanup subsequently contained/reaped them.
This is reviewer reporting, not a local full-harness run or a claim that
the original 120 tested cases failed.

Required entry/pre-change commit:
`d494ce2af1dd522e8ec0fc14c36b02a19e50b209`, tree
`8449e9aa7683f68c113a1fb00b1491a0e6e75d5b`. Local HEAD, the existing
`copilot/audit-run216-227-regression-verdict-fix` branch and remote task
tip matched exactly; worktree was clean. Origin fetch/push identity was
`https://github.com/olivexo28/QBIND`. Protected remote main matched
`f36e59a5e2cebab6fdfd0365920ca3e1a09444ac`.

The local `reproduce.py` obtains that exact entry fixture with `git show`
and executes unchanged supervisor_negative/fixture_workspace functions with
an inert surrogate and sleeping child, injecting parent KeyboardInterrupt
only once both are live. `baseline/reproduction.json` retains observed
worker/group liveness, empty unsafe set, workspace deletion and independent
outer containment/reaping. It is an isolated function reproduction, not a
full harness invocation.

```bash
python3 docs/security/evidence/a37-1-c2-supervisor-followup/reproduce.py docs/security/evidence/a37-1-c2-supervisor-followup/baseline
```

Exit 0: defect reproduced; **outer rescue required**, explicitly not a
successful tested-watchdog cleanup.

## Ownership correction

The watchdog now acquires explicit parent ownership as part of worker
creation, with catchable signals blocked across fork/registration. The
worker establishes its own session before starting descendants. Negative
case harnesses create their own process groups **inside that session**,
rather than escaping into new sessions; guarded descendants inherit it.
This bounded fixture contract, not decoded control messages, determines
cleanup authority. Ordinary matrix case sessions are unchanged.

A finally-backed parent scope covers pipe setup/read, wait polling, message
parsing, evidence assertions, timeout and catchable interruption. A worker
pidfd protects direct-worker signaling; cleanup stops the launcher, scans
only its owned session using the validated Linux `/proc` boundary, kills
only its groups/worker and reaps only its observed owned PIDs. It confirms
worker reaping, no session members and kernel group absence before success.
It closes both pipe descriptors and the pidfd. Original failures survive;
cleanup errors are separately retained/noted. Unresolved quiescence marks
the unsafe set, prevents further cases and retains the workspace.

Linux subreaper support, pidfd APIs/kernel support, and matching visible
PID/process-group/session namespaces are required and checked before cases.
There is no claim of cleanup after SIGKILL, host failure or other
uncatchable termination. The fixture does not authorize arbitrary children
that deliberately escape its dedicated session or external process writers.
No production script changes, release execution or activation are involved.

## Focused parent-fault cases

`watchdog_cases.py` loads the actual fixture function definitions and
substitutes only an inert case body. It exercises interruption before and
after group announcement, pipe and wait errors, real catchable TERM/HUP,
malformed and incomplete messages, timeout and an intentionally unresolved
cleanup. Each has a separate bounded outer owner. Successful cleanup cases
require worker reaping, kernel/group/recorded-child absence and closed pipe/
pidfd descriptors, with workspace deletion only after quiescence.

The unresolved-cleanup case deliberately refuses containment with live
descendants, verifies original failure plus separate cleanup notes,
unsafe-state/workspace retention, and requires outer rescue. Its cleanup
result is **FAILED**, never counted as a tested-watchdog cleanup pass.
The outer owner removes that retained workspace only after its own
containment and independent quiescence verification.

`preliminary/` retains a calibration failure: redundant child-side closing
of the read descriptor caused early worker failure before descendants.
That duplicate close was removed. `preliminary-2/` retains eight passing
pre-pidfd inert calibrations, including the deliberately failed unresolved
cleanup. These are not producing-revision results or harness invocations.

## Historical evidence boundary

Both existing evidence directories remain byte-for-byte unchanged:
[original historical evidence](https://github.com/olivexo28/QBIND/blob/6fdc0f0dcfc45c65037de3e53215121f5332689a/docs/security/evidence/a37-1-c2/README.md)
and [first corrective evidence](https://github.com/olivexo28/QBIND/blob/d494ce2af1dd522e8ec0fc14c36b02a19e50b209/docs/security/evidence/a37-1-c2-correction/README.md).
Their checksum manifests describe those respective historical revisions;
neither is regenerated against changed current files. The historical
94-case and 120-invocation passes remain valid within documented tested
conditions; they did not exercise the newly reported parent-ownership gap.

Producing-revision verification, raw results, exact commands, identities,
checksums and final delivery manifest are recorded after the implementation/
test commit. Only isolated normalized fixtures and inert/guarded processes
are authorized. No real Cargo tests/builds, node/helper binaries, release
harnesses, live networking, deployment, signing or activation run.
