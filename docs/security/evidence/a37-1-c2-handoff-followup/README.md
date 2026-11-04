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
The first attempt's final raw row contains a worker-local provisional
`cleanup_pass: true`, but its outer status is null and outer_rescues is
nonempty. That provisional label is not accepted: the outer owner had
already intervened, so this row is a failed cleanup test. Raw bytes are
retained rather than relabeled as though the rescue had not occurred.

All three historical evidence directories and both production scripts
remain byte-identical. Historical checksum references are pinned:
[original](https://github.com/olivexo28/QBIND/blob/6fdc0f0dcfc45c65037de3e53215121f5332689a/docs/security/evidence/a37-1-c2/README.md),
[publication/driver correction](https://github.com/olivexo28/QBIND/blob/d494ce2af1dd522e8ec0fc14c36b02a19e50b209/docs/security/evidence/a37-1-c2-correction/README.md),
[watchdog-parent follow-up](https://github.com/olivexo28/QBIND/blob/551e7cdd08eb01ce05914c4bba49562d8901b7ec/docs/security/evidence/a37-1-c2-supervisor-followup/README.md).
Their passes and limitations remain historical; their manifests are not
regenerated against changed current files.

## Exact producing-revision execution

Implementation/test producer:
`b4669ab29ad31f82bb574800df4f5f21e8a1afb7`, tree
`9ded09b141ef96f307cacb6ee35e20dd9a672d82`, sole parent
`551e7cdd08eb01ce05914c4bba49562d8901b7ec`. The following evidence/
documentation commit changes no fixture or committed reproduction/test
bytes. Its final identity/tree/parent and remote equality are in the handoff.

After committing that exact producer, from repository root with `pipefail`:

```bash
bash scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh docs/security/evidence/a37-1-c2-handoff-followup/focused 2>&1 | tee docs/security/evidence/a37-1-c2-handoff-followup/focused.log
python3 docs/security/evidence/a37-1-c2-handoff-followup/creation_cases.py docs/security/evidence/a37-1-c2-handoff-followup/creation 2>&1 | tee docs/security/evidence/a37-1-c2-handoff-followup/creation.log
python3 docs/security/evidence/a37-1-c2-handoff-followup/masked_cases.py docs/security/evidence/a37-1-c2-handoff-followup/masked-creation-completed 2>&1 | tee docs/security/evidence/a37-1-c2-handoff-followup/masked-creation-completed.log
python3 docs/security/evidence/a37-1-c2-handoff-followup/validate.py
```

The full suite exited **0**, rerunning the existing **120 actual isolated
harness-copy invocations**: 110 matrix records plus all ten existing negative
controls. It attempted **2,033 guarded stub regression commands**, **zero
Rust tests**, and required **zero watchdog rescues**. The stdout footer
counts only normal matrix records (110); environment and negative records
establish the full 120. Seven guard calibrations and one visibility-probe
process are separate, not harness invocations.

The two completed inert creation commands each exited **0** as test drivers,
with 12 cases each: ten successful cleanups without outer rescue, plus two
deliberately unresolved cleanup failures requiring outer rescue. Across
these 24 cases, **20 tested cleanups passed** and **four deliberately failed
cleanups required rescue**; those rescues are not counted as passes.
Actual workspace deletion was checked for child/group absence before
removal on the 20 successful cases; reaping was independently checked.
The unresolved cases verified workspace retention, original failure/
separate cleanup notes and refusal of both reuse routes; their outer owners
removed retained directories only after containment. Parent/child masks
were restored in every completed case, including a nonempty inherited
SIGUSR1 mask in the supplemental command.

The first supplemental nonempty-mask attempt (`masked-creation/`) started
three inert cases: two passed, then a partial child-mask readiness file
caused JSONDecodeError. The owner cleaned that child without outer rescue,
but this incomplete test attempt is **not a passing verification run**.
`masked_cases.py` now observes complete JSON readiness before allowing the
unchanged producing test to proceed; it changes no ownership implementation
or producing test bytes. The completed retry is retained separately.

Actual counts for this follow-up: **120 full isolated harness-copy
invocations**, **17 pre-commit inert case attempts**, **27 producing-revision
inert case attempts** (24 in completed runs, three in the incomplete mask
attempt), and **one separate pinned historical function reproduction**.
These are not Rust tests and do not include prior historical suite counts.
The first calibration's unexpected timeout/rescue is retained as a failure,
separate from the deliberately unresolved cases.

Only isolated normalized fixtures and inert/guarded processes ran. No real
Cargo builds/tests, nodes/helpers, full release harnesses, live DevNet
networking, deployment, signing or activation ran. GitHub delivery operations
are separate from live DevNet networking. No uncatchable-termination cleanup
guarantee is claimed.

## Retained outcomes and integrity

`entry.json` records entry identities, review attribution and failed/completed
calibration commands. `baseline/reproduction.json` is the local unchanged-
function reproduction, distinct from reviewer reporting. `preliminary*`
and `masked-creation/` retain incomplete/calibration outcomes and errors,
not substitute producing-revision passes.

`focused/environment.json` binds producing commit/tree, fixture hash,
production raw/normalized identities, actual command and utility versions.
`focused/cases.json`, both `focused/raw/run-*.jsonl` files and `focused.log`
retain all matrix stdout/stderr, artifacts, fault/guard events and command
outcomes. `focused/supervisor-negative.jsonl` and
`focused/watchdog-ownership.jsonl` retain all ten existing negative controls,
cleanup/reaping, original errors, descriptor observations and independent
child/group absence checks.

`creation/` and `masked-creation-completed/` contain per-case live-child
identities, child masks, original errors, supervision cleanup/retention
records, observed deletion boundaries, independent reaping and outer rescue
results. Their `.log` transcripts and `results.json` files distinguish
successful tested cleanup from deliberate unresolved failures.

`validation.json` verifies exact producing fixture/test/reproducer bytes,
all three historical evidence directories unchanged, historical checksum
manifests at their respective revisions (16/32/147 entries), both production
scripts unchanged, plan bytes before section 14 unchanged (including protected
sections/inventories/register), permitted scope, modes/EOL/EOF preservation,
Bash/embedded/evidence Python syntax, CRLF-aware whitespace checks and
actual case counts/outcomes. It is generated while HEAD is the producer.

`MANIFEST.tsv` gives changed-path old/new modes and complete blob IDs relative
to the required entry, excluding only itself and `SHA256SUMS` for non-circular
hashing. Their two final entries are supplied in the handoff. `SHA256SUMS`
covers every changed file except itself. Neither historical manifest is
regenerated. From repository root:

```bash
python3 docs/security/evidence/a37-1-c2-handoff-followup/seal.py --check
sha256sum -c docs/security/evidence/a37-1-c2-handoff-followup/SHA256SUMS
```

The checksum manifest's own blob/SHA-256 and final remote equality are
reported in the handoff.
