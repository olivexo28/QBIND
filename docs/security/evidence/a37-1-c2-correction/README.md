# A37.1-C2 / A38-iv bounded implementation-review corrections

**IMPLEMENTED — VERIFICATION PENDING.** Independent post-correction review
is **PENDING**. E07 / OBL-GOV-2 remain **OPEN**; activation **DISABLED**;
public DevNet **NO-GO**. These are bounded review corrections, not new
canonical audit findings or real Rust/release/runtime verification.

## Entry and historical evidence

Required entry: `6fdc0f0dcfc45c65037de3e53215121f5332689a`, tree
`b43769723cbe2b0319ad0b3166e8bcfe14fec5d3`. The initial clean checkout
was on protected main, `f36e59a5e2cebab6fdfd0365920ca3e1a09444ac`.
Origin identified `https://github.com/olivexo28/QBIND`; the remote task
branch matched the required entry. The existing remote branch was fetched
and continued at that exact commit/tree, with a clean checkout.

The [historical 94-case evidence](https://github.com/olivexo28/QBIND/blob/6fdc0f0dcfc45c65037de3e53215121f5332689a/docs/security/evidence/a37-1-c2/README.md)
and every file in that historical evidence directory remain byte-for-byte
unchanged. Its checksum manifest describes that historical revision, not
the corrected live sources. It must not be regenerated against this tree.
The historical pass did not cover directory destination interpretation or
exceptions between process creation and cleanup; an empty `/proc` group scan
was also insufficient to establish kernel group absence. No claim is made
that the reviewer's namespace mismatch occurred in the original Copilot run.

## Bounded reproductions

`reproduce.py` obtains source with `git show` at the required entry.
It extracts each actual `publish_incomplete` function, normalizing only
CRLF to LF, and executes two regular-file controls and four directory /
directory-symlink cases. All six returned zero; the four negative cases
left the destination as a directory and moved the temporary summary inside.

The unchanged historical driver function was invoked with an inert Popen
surrogate that created a wrong phase marker and sleeping child. Its assertion
escaped with the group alive and no driver cleanup call. A distinct outer
owner killed/reaped the reproduction's processes before temporary teardown.
This rescue demonstrates the historical defect; it is not a corrected
cleanup pass. Raw outcomes are in `baseline-completed/reproduction.json`.

Command:

```bash
python3 docs/security/evidence/a37-1-c2-correction/reproduce.py docs/security/evidence/a37-1-c2-correction/baseline-completed
```

An earlier collector attempt failed before launching the surrogate:
its global Popen replacement intercepted a `git show` call (`KeyError:
'env'`). The source read was moved before that replacement. `entry.json`
records the failed command/error; that attempt emitted no raw result file
and is not counted as a completed reproduction. Six publication invocations
had occurred before that collector error; six more occurred in the completed
run.

## Correction and environment boundary

Both startup/repair and final publishers now use GNU coreutils `mv -fT`.
This is exact-destination replacement: real directories cause nonzero
initialization failure before work, or nonzero final completion, without
removing directories/contents. Symlinks (including directory symlinks)
are replaced themselves by the intended regular summary; referents remain
unchanged. Same-directory temporary publication, exclusive single writer,
best-effort signal repair and atomic visibility rather than crash durability
are unchanged. GNU `mv -T` is an explicit platform requirement.

Every process creation in the case driver is immediately owned by a
`finally`-backed context. Assertions, missing/malformed marker reads,
evidence-read errors and unexpected `BaseException` paths all run bounded
cleanup. The original error is retained; cleanup errors are separately
recorded/noted. Unsafe cleanup stops further cases and retains the workspace
rather than deleting/reusing directories that children might still write.

Linux subreaper support and matching `/proc`/Python/killpg PID and process
group visibility are required. Self visibility and a separate owned-group
probe are validated before cases launch; a false-empty scan is tested as an
unsupported preflight condition. Containment uses kernel `killpg`, never
an empty scan as authority. Success requires kernel group absence, no
visible group members, and child reaping. Reaping is restricted to the
owned group, not arbitrary children of the shared environment.

New actual-script cases cover regular files, file symlinks, directories
and directory symlinks at startup and final publication, for both harnesses.
The guarded mv wrapper dispatches the real GNU utility with the actual
arguments, including after-PASS signal cases. Final conflicts are created
at the actual publication boundary; assertions check the intended failure,
normal completion, destination type, untouched referents/contents, work
reachability and absence of nested temporary summaries.

Five supervisor negative cases per harness cover a live phase assertion,
missing marker, malformed marker, failed evidence read and exceptional
driver termination. A distinct watchdog observes the tested driver and
independently checks kernel group and recorded-child absence. Any outer
rescue is a failed test, never a pass.

## Verification records

`preliminary.log` and `preliminary/` retain pre-commit calibration.
The first calibration reached the directory-symlink case and exposed a
fixture expectation error: GNU `mv -T` replaces that link itself, as allowed
by the specified policy, rather than refusing it. The fixture assertions
were corrected to require a regular summary and untouched target.
This is not counted as producing-revision verification.

The [implementation/test producing revision](https://github.com/olivexo28/QBIND/commit/763efbbbf1141d5be264ce2fa73b10763287bb27)
is `763efbbbf1141d5be264ce2fa73b10763287bb27`, tree
`9a2756852685c34ff7c631ce0845175ae1b047fd`, sole parent the required entry
`6fdc0f0dcfc45c65037de3e53215121f5332689a`. The following evidence/documentation
commit changes no production script or fixture bytes. Its final identity,
tree, parentage and remote equality are reported in the delivery handoff.

After committing that exact producing revision, from repository root:

```bash
set -o pipefail
bash scripts/devnet/tests/run_216_227_regression_verdict_fixture.sh docs/security/evidence/a37-1-c2-correction/focused 2>&1 | tee docs/security/evidence/a37-1-c2-correction/focused.log
python3 docs/security/evidence/a37-1-c2-correction/check_owner_errors.py docs/security/evidence/a37-1-c2-correction/owner-errors 2>&1 | tee docs/security/evidence/a37-1-c2-correction/owner-errors.log
python3 docs/security/evidence/a37-1-c2-correction/validate.py
```

All commands exited **0**. The authoritative suite made **120 actual
isolated harness invocations**: **110 normal matrix cases** (four pinned
pre-original-implementation baseline controls/reproductions at
`f36e59a5e2cebab6fdfd0365920ca3e1a09444ac`, 106 corrected candidate cases),
plus **10 supervised negative invocations**. This reruns all **94 original
case identities** and adds **16 destination cases** and **10 supervisor
negatives**. The stdout footer's legacy `110` counter covers normal matrix
records only; the ten negative invocation lines and
`environment.json:total_harness_invocations=120` account for the complete
suite. These are **not Rust tests**: **2,033 guarded stub regression
command attempts**, comprising 2,023 matrix attempts and ten negative-path
attempts. No real Cargo builds/tests or node/helper binaries ran.

All 120 owned groups were contained/reaped; all ten independent watchdog
checks passed with **zero rescues**. The suite also made one separate
visibility-probe process launch and seven guard calibration probes, neither
counted as harness invocations. Two separate ownership-error process checks
passed: original exceptions survived a deliberately reported cleanup error
and a failed supervision-evidence write; the former retained its workspace
until independent kernel/group absence verification permitted cleanup.
No independent rescue was needed in either check.

Pre-commit calibration made **51 additional harness invocations**, attempting
1,444 guarded regression commands before its fixture-expectation assertion.
Thus this correction task executed **171 full isolated harness-copy
invocations**, not 171 Rust tests. Separately, the baseline collector made
12 extracted publisher-function invocations across its two attempts and
one inert historical-driver surrogate invocation. The original historical
94-case pass is not added to these current-task invocation counts.

Only isolated LF-normalized script copies and guarded stubs execute.
No real Cargo builds/tests, nodes, helpers, full release harnesses, live
networking, deployment, signing or activation ran. Repository fetch/identity/
push operations are separate GitHub delivery operations, not live DevNet
networking.

## Retained evidence and integrity

`entry.json` retains entry/repository checks, branch continuation and the
failed/completed collector commands. `baseline-completed/reproduction.json`
contains extracted publisher commands, directory outcomes and the historical
supervisor leak/outer-containment record. `preliminary/` and `preliminary.log`
are explicitly non-authoritative calibration, including its failed assertion.

`focused/environment.json` binds producing commit/tree, source blobs,
raw/normalized hashes, utility versions, invocation command, environment and
process-visibility checks. `focused/cases.json`, `focused/raw/run-216.jsonl`
and `focused/raw/run-227.jsonl` retain matrix results, stdout/stderr, guarded
commands, actual faults, summary contents and per-command artifacts.
`focused/supervisor-negative.jsonl` retains the ten independent watchdog
records, original errors, cleanup/reaping, owned child IDs and raw logs.
`focused/supervision.json` retains case/probe cleanup observations (forked
negative workers additionally retain their own observations in their result
records). `focused.log` is the authoritative transcript.

`owner-errors/results.json`, `owner-errors/supervision.json` and
`owner-errors.log` retain the two separate error-preservation checks;
`owner-errors/not-a-directory` is the intentional evidence-write blocker.
`check_owner_errors.py` loads the unchanged producing fixture ownership
functions, not a substitute cleanup implementation.

`validation.json` records exact producing source identities, all historical
evidence bytes unchanged, all 16 historical manifest entries verified
against the required historical revision, protected plan bytes before
section 14 unchanged (including sections 8/12/13), exact two-flag-only
production changes, all original 94 cases rerun, permitted-path scope,
unchanged modes/EOL/EOF conventions, LF syntax, embedded/evidence Python
syntax, CRLF-aware whitespace checks and local documentation targets.
`validate.py` is the retained verification command. It was run before
the evidence-only publication commit, while HEAD was the producing revision.

`MANIFEST.tsv` gives changed-path old/new modes and complete blob IDs
relative to the required entry, excluding only itself and `SHA256SUMS` to
avoid self-reference. Their two final manifest entries are supplied in the
delivery handoff, completing the changed-path manifest.
`SHA256SUMS` covers every changed file, including `MANIFEST.tsv`, excluding
only itself. Run from repository root:

```bash
sha256sum -c docs/security/evidence/a37-1-c2-correction/SHA256SUMS
python3 docs/security/evidence/a37-1-c2-correction/seal.py --check
```

Its own blob and SHA-256 identity are reported in the delivery handoff;
there is no circular hashing or regeneration of the historical manifest.
`seal.py` generated these two artifacts after final evidence validation;
its `--check` form verifies the complete non-self-referential content.
