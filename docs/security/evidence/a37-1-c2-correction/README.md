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
'env'`). The source read was moved before that replacement. The partial
`baseline/historical-driver` metadata is retained, not counted as a
completed reproduction. Six publication invocations had occurred before
that collector error; six more occurred in the completed run.

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

The authoritative producing-revision suite, identities, counts, checksums
and delivery manifest are recorded after the implementation/test commit.
Only isolated LF-normalized script copies and guarded stubs execute.
No real Cargo builds/tests, nodes, helpers, full release harnesses, live
networking, deployment, signing or activation are permitted or claimed.
