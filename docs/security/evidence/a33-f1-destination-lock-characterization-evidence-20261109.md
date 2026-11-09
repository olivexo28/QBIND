# QBIND — Current destination-lock characterization evidence

**AUTHOR-RUN, TEST-ONLY CHARACTERIZATION. NOT HOSTED CI OR AN INDEPENDENT
OBSERVATION. NO PRODUCTION STARTUP WAS RUN.**

## Pinned inputs and scope

| Input | Revision |
|---|---|
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed contract | `docs/candidate-b-existing-destination-authorization-contract`, commit `1afcc51e152c1b1760f2beac1cbfaec5a02f79a1`, tree `23a8008a347224b617137558e4a6248397890153` |
| Test source commit used for both commands | `f8caff93a17ed88dbf61a9503e9b632d989f38d7` |
| Test source tree used for both commands | `cf36a4f2e5b21911d885a3c646cb4c7e4ecd2108` |
| Test source blob | `7354f2ee486ba2817cab0665d9434afc481e6b69` |

Only the existing `acquire_destination_lock` API was exercised, from two
separate opens in one process. Tests used `tempfile`-created roots and the
fixed child paths `data/restore.lock` and `data/retained-original-lock`.
The fixture code verifies that the destination remains under the canonical
temporary root and uses `symlink_metadata` to observe regular-file identities.
No production startup, external process, filesystem attack, operational key,
signer, node, or real QBIND data directory was used. The only namespace
change was the explicitly authorized rename and replacement inside the
test-created temporary fixture.

## Environment

- OS: Linux, `x86_64`; kernel string `Linux adc-sandbox 6.12.8+ #1 SMP Thu Jul 30 23:01:31 UTC 2026 x86_64 GNU/Linux`.
- Filesystem containing the worktree and `/tmp` fixture roots: ext4, mounted at `/`, `rw,relatime`.
- Rust: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`.
- Cargo: `cargo 1.99.0 (5f94df478 2026-08-27)`.
- Temporary build output: the worktree-local Cargo `target/` directory; no manifest, lockfile, dependency, or production source changed.

## Commands and results

The complete stdout/stderr output from each command is retained beside this
report. Each command exited `0`.

| Purpose | Exact command | Exit | Result |
|---|---|---:|---|
| Focused characterization | `cargo test -p qbind-node --test a33_f1_destination_lock_characterization_tests -- --nocapture` | 0 | 2 passed, 0 failed, 0 ignored |
| Compile-only check | `cargo test -p qbind-node --test a33_f1_destination_lock_characterization_tests --no-run` | 0 | Target compiled; executable produced; tests not run by this command |

Full logs:

- `a33-f1-destination-lock-characterization-focused-output-20261109.txt`
- `a33-f1-destination-lock-characterization-compile-output-20261109.txt`

SHA-256:

- Focused output: `1841a491e37099fa762fb28e32072ebe97ff4b9b1910b97fa27f73f3bd63c3e7`
- Compile-only output: `c4251e037770468e69deda8dad1f0c06612c25b15eb752fa1dc29a12b24622cc`

The compiler emitted existing dead-code warnings from `qbind-consensus` and
`qbind-node`; neither command reported a build or test error. The focused
result is the author-run result, not hosted CI and not an independent rerun.

## Actual observations

The test prints Unix file identities as `(device, inode)` obtained from
`symlink_metadata`; these are platform-specific observations, not portable
identities or an authenticated destination claim.

1. **Same lock object:** first acquisition remained held. The second API call
   was a separate open in the same process, observed the same object
   `(device=65040, inode=131202)`, and returned **contended**.
2. **Controlled lock-path replacement:** while the first lock remained held,
   its path was renamed within the temporary destination and a regular-file
   replacement was created at `restore.lock`. The original remained
   `(device=65040, inode=131203)` and the replacement was distinct,
   `(device=65040, inode=139250)`. A second same-process open through the
   existing API **succeeded**; both returned lock handles were held
   simultaneously during the observation.

The test does not use sleeps or timing-based polling. In the replacement
case it verifies that the old object remains at the renamed in-root path,
that the replacement path has a different identity, and that both
acquisitions overlap while the first handle is live. It does not exercise
separate processes and makes no process-level claim.

Both temporary roots were explicitly dropped and checked absent. The
observed roots `/tmp/.tmpTDyk9O` and `/tmp/.tmpNAEAFB` were subsequently
checked absent as well.

## Limits and status

These observations characterize only this Linux/ext4 test environment and
the current API's behavior for these isolated operations. They do not prove
that any outcome is safe, authenticate a destination or its authority,
establish Candidate B enforcement, bind later backend opens to a destination,
or address uncooperative writers, ownership/recovery, or crash behavior.
Independent destination authority, backend binding, recovery, and the broader
feasibility blocker remain OPEN.

CB-1 and CB-FIXTURE-1 remain within their accepted scopes. A23-F1 and
A33-F1 / E27 remain OPEN; activation remains DISABLED; public DevNet remains
NO-GO.
