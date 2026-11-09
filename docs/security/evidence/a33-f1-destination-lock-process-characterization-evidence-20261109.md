# QBIND — Separate-process destination-lock characterization

**AUTHOR-RUN, TEST-ONLY CHARACTERIZATION. NOT HOSTED CI OR AN INDEPENDENT
OBSERVATION. NO PRODUCTION STARTUP WAS RUN.**

## Pinned inputs and tested source

| Input | Revision |
|---|---|
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed contract | `docs/candidate-b-existing-destination-authorization-contract`, commit `1afcc51e152c1b1760f2beac1cbfaec5a02f79a1`, tree `23a8008a347224b617137558e4a6248397890153` |
| Process-characterization source commit | `cf39f7f9d64de956f37bf020576a1e65845a8358` |
| Process-characterization source tree | `cd749fee49b59786ef3cc6e68c9ea19f4553cd40` |
| Characterization test-file blob | `689e343b515ed3f6d8fcd906d46094efbddb9619` |

Both new process-level commands ran against this exact source commit/tree.
The prior one-process controls and their historical logs were preserved and
not rerun. Evidence is committed separately; the test file, manifests,
lockfile and other build inputs were verified unchanged after the commands.

The child processes invoke only the existing
`qbind_node::restore_completion::acquire_destination_lock` API. A unique
`tempfile` root contains the destination, result markers, and all lock-file
path changes. Child PIDs are checked against the parent and each other.
Workers publish a result only after the acquisition attempt and then block
on parent stdin while retaining any successful lock guard. The parent
observes the result, verifies that both processes remain alive during the
overlap, and then releases them. Coordination uses result files and bounded
10-second waits. Short polling intervals only check for those explicit
markers or process exits; no fixed delay is used to infer a lock outcome.

### Identity observation

The API keeps the lock descriptor private, and this test does **not** inspect
or `fstat` those private descriptors. It observes path entries using Unix
`symlink_metadata` (`device`, `inode`) before/after acquisition:

- same-object case: metadata for the unchanged `restore.lock` path;
- replacement case: metadata for the renamed original entry and the
  replacement `restore.lock` entry, checked to be distinct.

The lock outcome comes from the API result returned in each child process.
The metadata establishes which regular-file objects the fixture paths named;
it is not direct descriptor inspection or a portable object-identity claim.

## Environment

- OS: Linux, `x86_64`; kernel string `Linux adc-sandbox 6.12.8+ #1 SMP Thu Jul 30 23:01:31 UTC 2026 x86_64 GNU/Linux`.
- Worktree and fixture filesystem: ext4 mounted at `/`, `rw,relatime`.
- Rust: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Cargo: `cargo 1.99.0 (5f94df478 2026-08-27)`.
- Cargo build output used the worktree-local `target/` directory.
- Run timestamp: `2026-11-09T07:53:19+00:00`.

## Commands, exit codes, and test counts

Complete stdout/stderr is retained in the two adjacent `.txt` files.

| Purpose | Exact command | Exit code | Test result |
|---|---|---:|---|
| Focused process-level controls | `cargo test -p qbind-node --test a33_f1_destination_lock_characterization_tests separate_processes_ -- --nocapture` | 0 | 2 passed, 0 failed, 0 ignored, 3 filtered out |
| Compile-only check | `cargo test -p qbind-node --test a33_f1_destination_lock_characterization_tests --no-run` | 0 | Target compiled; executable produced; no tests executed by this command |

Full logs:

- `a33-f1-destination-lock-process-focused-output-20261109.txt`
- `a33-f1-destination-lock-process-compile-output-20261109.txt`

SHA-256:

- Focused output: `73f8fb3a84926bf3832ecb40daa59fb1d40ba05567ebc38a70d2bc0484223208`
- Compile-only output: `8cbb2afaa273527ce596695ac5d57139c5cd37a2199dc3761db0e14ccd866344`

The compiler emitted existing dead-code warnings from `qbind-consensus`
and `qbind-node`; no compile or test error occurred. These are author-run
results, not hosted CI or an independent observation.

## Actual process-level observations

Test pass counts above are separate from these observations. The worker
process IDs and path metadata were printed by the focused run.

1. **Unchanged lock path / same object:** first worker PID `14692` acquired
   the lock and remained held. Separate worker PID `14696` called the same
   API through the unchanged path and returned `contended`. The two
   processes were distinct and overlapped; the path still named metadata
   object `(device=65040, inode=131202)`.
2. **Controlled replacement:** first worker PID `14693` retained the lock
   while the fixture renamed its lock path and created a distinct regular
   file at `restore.lock`. The original entry metadata was
   `(device=65040, inode=139250)` and the replacement entry metadata was
   `(device=65040, inode=139525)`. Separate worker PID `14698` called the
   existing API through the replacement path and returned `acquired`. Both
   worker processes remained alive at observation, so both calls held their
   returned lock guards simultaneously in this Linux/ext4 run.

The fixture observed identities only through path metadata, not through the
API's private lock descriptors. The API result plus both workers' held
guards and verified process overlap supports the stated observation for
this run; it does not establish a general process or platform guarantee.

Both temporary roots, `/tmp/.tmpJxLWWm` and `/tmp/.tmp6I7jc6`, were
explicitly removed by the tests and checked absent afterward. An inability
to establish a worker result, distinct process IDs, object identity, or
overlap fails the relevant test setup; no result would be inferred in that
case.

## Limits and status

These are platform-specific observations of two bounded fixture cases.
They do not authenticate the destination or its authority; establish
Candidate B enforcement; prove destination-to-backend binding; or establish
fencing, recovery, behavior under uncooperative writers, or safety of either
observed outcome. Independent destination authority, backend binding,
fencing and recovery, and the broader feasibility blocker remain open.

No production startup, operational keys, live signer, or node was used.
CB-1 and CB-FIXTURE-1 retain their accepted scopes. A23-F1 and A33-F1 / E27
remain OPEN; activation remains DISABLED; public DevNet remains NO-GO.
