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
of the read descriptor caused early worker failure before descendants;
the outer calibration then reported missing identity evidence. That duplicate
close was removed. `preliminary-2/` retains eight pre-pidfd inert calibrations:
seven successful cleanups and one deliberately failed unresolved cleanup
with outer rescue. These are not producing-revision results or harness
invocations.

## Historical evidence boundary

Both existing evidence directories remain byte-for-byte unchanged:
[original historical evidence](https://github.com/olivexo28/QBIND/blob/6fdc0f0dcfc45c65037de3e53215121f5332689a/docs/security/evidence/a37-1-c2/README.md)
and [first corrective evidence](https://github.com/olivexo28/QBIND/blob/d494ce2af1dd522e8ec0fc14c36b02a19e50b209/docs/security/evidence/a37-1-c2-correction/README.md).
Their checksum manifests describe those respective historical revisions;
neither is regenerated against changed current files. The historical
94-case and 120-invocation passes remain valid within documented tested
conditions; they did not exercise the newly reported parent-ownership gap.

## Exact producing-revision verification

Implementation/test producing commit:
`e02047003a3ac5d099a12268dda5fb210ef69902`, tree
`7323a8e2faaf69361559b6cac6c675abfc8b0789`, sole parent
`d494ce2af1dd522e8ec0fc14c36b02a19e50b209`. The commands below ran
after that commit. The following evidence/documentation commit changes no
fixture or committed test/reproduction script bytes; its own identity/tree/
parent and remote equality are reported in the delivery handoff.

From repository root, each captured command used `set -o pipefail`:

```bash
bash scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh docs/security/evidence/a37-1-c2-supervisor-followup/focused 2>&1 | tee docs/security/evidence/a37-1-c2-supervisor-followup/focused.log
python3 docs/security/evidence/a37-1-c2-supervisor-followup/watchdog_cases.py docs/security/evidence/a37-1-c2-supervisor-followup/parent-cases 2>&1 | tee docs/security/evidence/a37-1-c2-supervisor-followup/parent-cases.log
python3 docs/security/evidence/a37-1-c2-supervisor-followup/observe_deletion.py docs/security/evidence/a37-1-c2-supervisor-followup/deletion-boundary 2>&1 | tee docs/security/evidence/a37-1-c2-supervisor-followup/deletion-boundary.log
python3 docs/security/evidence/a37-1-c2-supervisor-followup/check_refusal.py docs/security/evidence/a37-1-c2-supervisor-followup/unsafe-refusal 2>&1 | tee docs/security/evidence/a37-1-c2-supervisor-followup/unsafe-refusal.log
python3 docs/security/evidence/a37-1-c2-supervisor-followup/validate.py
```

The full suite exited **0**: **120 actual isolated harness-copy invocations**
(110 matrix records plus all ten existing supervisor-negative controls),
**2,033 guarded stub regression command attempts**, **zero Rust tests**.
The historical 110 matrix case identities are exactly retained; all ten
supervisor controls have zero watchdog rescue, independent group/child
absence and new parent-ownership cleanup/descriptor evidence. The stdout
footer's 110 counter covers only normal matrix records; environment and
negative records account for the full 120. Seven guard-calibration probes
and one visibility-probe process are not harness invocations.

Both inert parent-fault commands exited **0** as test drivers. Each ran
ten isolated function cases: **nine successful tested-watchdog cleanups**
with **zero outer rescues**, plus **one intentionally unresolved cleanup
failure**, correctly retained as **FAILED**, with unsafe-state/workspace
retention and required outer rescue. Across these two executions there
were 20 inert cases: **18 successful cleanups**, **two deliberately failed
cleanups/two outer rescues**. Those rescues are not reclassified as successful
cleanup. The second execution used `observe_deletion.py` to intercept each
actual workspace deletion independently; all **ten deletion boundaries**
verified worker/group/recorded-child absence before `rmtree`, including the
outer removal of the deliberately retained workspace only after containment.
The actual producing fixture functions and committed inert-case script
were unchanged; the observer adds checks, not replacement ownership logic.
The separate unsafe-state check exited 0, proving both case/watchdog entry
routes refuse before any pipe, fork or Popen launch (zero such attempts).

Pre-commit calibration ran nine worker cases: one early failure without
surrogate launch, then eight inert cases (seven successful cleanups and one
deliberate unresolved failure/outer rescue). The separate historical local
reproduction ran one inert surrogate and required outer containment. None
of these are full harness-copy or Rust invocations; the current follow-up's
only full-harness-copy invocations are the authoritative **120**.

Only isolated normalized fixtures and inert/guarded processes ran. No real
Cargo tests/builds, node/helper binaries, full release harnesses, live DevNet
networking, deployment, signing or activation ran. GitHub repository delivery
operations are separate from live DevNet networking. Linux pidfd/session
requirements intentionally narrow the supported fixture environment; no
cleanup guarantees are asserted for uncatchable termination or session-
escaping arbitrary descendants.

## Retained raw evidence and integrity

`entry.json` retains exact starting identity, clean branch/remote checks and
the user-supplied independent-review reference. `baseline/reproduction.json`
is the local unchanged-function reproduction, distinct from reviewer reporting.
`preliminary.log`, `preliminary/`, `preliminary-2.log` and `preliminary-2/`
retain the pre-commit calibrations and failure history.

`focused/environment.json` binds producing commit/tree, fixture hash,
production raw/normalized identities, actual command and utility/environment
versions. `focused/cases.json`, both `focused/raw/run-*.jsonl` files and
`focused.log` retain all matrix invocations, stdout/stderr, artifacts and
guarded command outcomes. `focused/supervisor-negative.jsonl` retains the ten
existing controls' raw records, original errors, driver cleanup, independent
child/group checks and logs. `focused/watchdog-ownership.jsonl` adds the ten
parent-side worker/session cleanup, reaping, descriptor and message records.

`parent-cases/` and `deletion-boundary/` retain per-case side-channel owned
worker/session/group/child identities, expected original errors, separate
cleanup notes, descriptor lists, workspace-retention/deletion observations,
raw ownership logs, and aggregate results including outer rescue status.
Their `.log` transcripts and `deletion-boundary-deletion.jsonl` retain exact
outcomes and actual deletion-boundary observations. Workspace paths refer
to now-quiescent removed temporary directories, not persistent evidence.
`unsafe-refusal/results.json` and `unsafe-refusal.log` retain the
zero-launch refusal checks performed by `check_refusal.py`.

`validation.json` records exact producer/parent/tree and unchanged fixture/
committed test identities, both historical directories byte-identical,
historical manifests verified at their respective revisions (16 and 32
entries), unchanged production scripts, protected plan prefix before
section 14 (including 6/8/11/12/13 and inventories/register), permitted scope,
modes/EOL/EOF preservation, Bash/embedded/evidence Python syntax, CRLF-aware
whitespace, case identity/count assertions, actual parent outcomes and
relative documentation links. It was generated while HEAD was the producer.

`MANIFEST.tsv` lists every changed path's old/new mode and complete blob IDs
relative to the required entry, excluding only itself and `SHA256SUMS` to
avoid self-reference. Their final two entries are supplied in the handoff.
`SHA256SUMS` covers every changed file except itself. `seal.py` generates
and verifies those artifacts; neither historical manifest is rewritten.

```bash
python3 docs/security/evidence/a37-1-c2-supervisor-followup/seal.py --check
sha256sum -c docs/security/evidence/a37-1-c2-supervisor-followup/SHA256SUMS
```

The checksum manifest's own blob/SHA-256 and final remote equality are
reported in the handoff without circular/self-referential hashing.
