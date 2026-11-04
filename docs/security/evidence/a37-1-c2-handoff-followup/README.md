# A37.1-C2 / A38-iv creation-to-ownership handoff correction

**IMPLEMENTED — VERIFICATION PENDING.** Independent review **PENDING**.
E07 / OBL-GOV-2 **OPEN**; activation **DISABLED**; public DevNet **NO-GO**.
This is a bounded implementation-review correction, not a new audit finding.

## Entry and review boundary

Required entry `551e7cdd08eb01ce05914c4bba49562d8901b7ec`, tree
`85242ebdc73de44133a752886bccb6cd3456a261`: clean checkout, existing task
branch and remote task tip matched. Origin fetch/push identified
`https://github.com/olivexo28/QBIND`. Protected main matched
`f36e59a5e2cebab6fdfd0365920ca3e1a09444ac`.

The user supplied independent review reported a targeted probe of pinned
run_case/fixture_workspace: KeyboardInterrupt after Popen returned but before
owned_process entry leaked a live child, left UNSAFE_GROUPS empty and allowed
workspace deletion. Separate reviewer containment killed/reaped the child.
No separately retrieved review artifact or post-correction acceptance is
claimed. This was not a failure or rerun of the historical 120-invocation suite.

Local `reproduce.py` loads the unchanged entry functions with `git show`,
uses an inert Popen stand-in and injects at that exact handoff. Its
`baseline/reproduction.json` confirms the leak/deletion and required outer
rescue/reaping, not successful tested cleanup.

```bash
python3 docs/security/evidence/a37-1-c2-handoff-followup/reproduce.py docs/security/evidence/a37-1-c2-handoff-followup/baseline
```

Exit 0; isolated function reproduction, not a harness invocation.

## Correction

owned_process now accepts a command rather than an already-created process.
The Popen object is allocated inside its scope before initialization and
remains reachable in the enclosing try/finally if initialization or handoff
raises. Both ordinary run_case and the visibility probe use that creation
owner; there is no external Popen-to-owner handoff.

The single-threaded supervisor blocks INT/TERM/HUP while creating/registering
the process and installs raising handlers within its ownership scope.
A Python exec launcher restores the child's exact original signal mask
before exec of the actual isolated command; no preexec_fn is used. Parent
masks/handlers are restored after bounded cleanup. Original failures
survive; cleanup/evidence failures remain separately reported. Unresolved
quiescence marks unsafe state, refuses further creation/cases and retains
the workspace. Existing owned-group signaling/reaping and validated Linux
process-visibility/session/pidfd boundaries remain in force. No guarantee
is claimed for SIGKILL, host failure or other uncatchable termination.

## Focused boundary verification

`creation_cases.py` loads the actual fixture functions. A Popen initializer
stand-in retains the real exec launcher, creates a live inert child in the
requested owned group and injects a post-spawn initialization exception,
line-traced handoff KeyboardInterrupt, pending creation INT/TERM, or a mask
control. Both ordinary-case and visibility-probe entry routes are exercised.
Child and parent masks must equal the original mask.

A separate bounded outer owner checks cleanup/reaping and contains failures.
Actual workspace deletion is intercepted to require kernel group and
recorded-child absence first. Deliberately unresolved cleanup must preserve
the workspace, original failure and separate cleanup notes, refuse both
entry routes, and require outer rescue. Those rescues are recorded as
**failed tested cleanup**, never as passes.

Preliminary calibration is retained separately. The first attempt passed
four cases then timed out in its mask control because that inert ordinary
case entered the normal 30-second wait while the outer owner allowed ten
seconds. Outer containment rescued the child/tester; this is a failed
calibration, not a cleanup pass. The mask control was bounded explicitly
before ordinary case execution. The second calibration ran 12 cases:
ten successful cleanups and two deliberate unresolved failures/outer rescues.

All three historical evidence directories and both production scripts
remain byte-identical. Historical checksum references are pinned:
[original](https://github.com/olivexo28/QBIND/blob/6fdc0f0dcfc45c65037de3e53215121f5332689a/docs/security/evidence/a37-1-c2/README.md),
[publication/driver correction](https://github.com/olivexo28/QBIND/blob/d494ce2af1dd522e8ec0fc14c36b02a19e50b209/docs/security/evidence/a37-1-c2-correction/README.md),
[watchdog-parent follow-up](https://github.com/olivexo28/QBIND/blob/551e7cdd08eb01ce05914c4bba49562d8901b7ec/docs/security/evidence/a37-1-c2-supervisor-followup/README.md).
Their passes and limitations remain historical; their manifests are not
regenerated against changed current files.

Producing-revision outcomes, commands, identities and integrity records
follow after the implementation/test commit. Only isolated normalized
fixtures and inert/guarded processes are authorized; no real Cargo
builds/tests, nodes/helpers, full release harnesses, deployment, signing
or activation run.
