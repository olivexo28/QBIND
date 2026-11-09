# A33-F1 — Non-UTF-8 alias COMPLETE-guard-to-storage characterization

**AUTHOR-RUN, TEST-ONLY OBSERVATION.** This bounded test called QBIND's
actual `evaluate_ordinary_startup` guard and, only after an allowing result,
separately called the existing account-storage API. It did not run node
startup, exercise a filesystem race, use operational keys, or establish
destination authority, backend confinement, race resistance, or Candidate B
enforcement.

## Pins, source, and scope

| Item | Value |
|---|---|
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed characterization branch | `test/candidate-b-nonutf8-alias-ancestor-characterization` |
| Reviewed endpoint | `5588d45a0388638d315e32b67dd753cd9f368ecc`, tree `102e038096b06089f0262c2de3e9b26a67d6a087` |
| Test branch | `test/candidate-b-nonutf8-complete-guard-storage` |
| Source commit at final test run | `7af0d66578ea3e538f24dde3e67b0895ee2766cd`, tree `9d714c32e82bde478485b3a5d9ed712b7e41092f`, parent `01c7dc1dc09e9777b5870c928370ad023e40821c` |
| Test source Git blob at final run | `02b325f98c603b0654a473bd7418748242b4f053` |
| Cargo.lock SHA-256 | `70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf` |

The test source was committed before the final test and compile-only run. Its
first committed version was `01c7dc1dc09e9777b5870c928370ad023e40821c`
(tree `51b28ef5e9cd136976dace27165bbbba76a8b260`). Initial focused and
compile-only attempts found two Rust E0382 moved-value errors in the new
test. The test helper was changed to borrow its marker values in follow-up
source commit `7af0d66578ea3e538f24dde3e67b0895ee2766cd` before final runs.
The first-attempt complete output is retained, but its shell exit code was
not captured in the session record; the final attempts and their exit codes
are recorded below.

Only the new integration test and these evidence files are added relative to
the reviewed endpoint and expected main. The previously accepted tests and
historical findings were not modified or rerun.

The test exercises the actual guard at
`crates/qbind-node/src/restore_completion.rs:988` and its `ProceedComplete`,
`RefuseForeign`, and `RefuseMissingState` decisions
(`:914`, `:988-1017`). It constructs and publishes synthetic COMPLETE
records using the constructors and publication entry point at
`crates/qbind-node/src/restore_completion.rs:213-238` and `:647-655`, then
calls `RocksDbAccountState::open_existing` at
`crates/qbind-ledger/src/execution.rs:1441`. Test implementation is at
`crates/qbind-node/tests/candidate_b_nonutf8_complete_guard_storage_tests.rs:74-185`
and `:188-287`.

## Environment and dependencies

- OS/kernel/architecture: Linux `6.12.8+`, x86_64.
- Filesystem: ext4 on `/dev/vdb`, mounted at `/`; the unique test fixture,
temporary directory, and isolated Cargo target were under `/tmp` on this
filesystem.
- Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`,
  `cargo 1.99.1 (5f94df478 2026-08-27)`.
- Lock-resolved packages: `rocksdb 0.22.0`, `librocksdb-sys
  0.16.0+8.10.0`, `clap 4.5.56`, and `clap_builder 4.5.56`.
- Cargo used locally cached archives and extracted source under
  `/usr/local/cargo/registry/{cache,src}/index.crates.io-1949cf8c6b5b557f/`.
  The cached RocksDB archive SHA-256
  `6bd13e55d6d7b8cd0ea569161127567cd587676c99f4472f779a0279aa60a7a7`
  and librocksdb-sys archive SHA-256
  `ce3d60bc059831dc1c83903fb45c103f75db65c5a7bf22272764d9cc683e348c`
  match their `Cargo.lock` checksums. This does not claim independent
  byte-for-byte equivalence with an upstream tag or another published
  artifact.

The isolated run root was
`/tmp/qbind-nonutf8-complete-guard.S9CkTy`; both `TMPDIR` and
`CARGO_TARGET_DIR` were placed below it. The test's `TempDir` fixtures were
under its `tmp` subdirectory. A post-run check found no fixture residue
under `tmp`. The isolated Cargo target and captured logs were kept there
until the complete outputs were copied into this evidence set.

## Author-run observations (distinct from test counts)

On this Unix/ext4 fixture, the symlink creation succeeded. The non-UTF-8
alias component bytes were `616c6961732dff` (`alias-\xFF`); the fixture
verified that its canonical target equaled the intended in-root UTF-8
destination before the guard call. The synthetic COMPLETE record named that
canonical destination. The raw alias data directory and its lossy spelling
were distinct paths, and the two account database fixtures had different
synthetic markers.

The actual call `evaluate_ordinary_startup(raw_alias)` returned
`ProceedComplete`. The subsequent storage API call was therefore made, and
`RocksDbAccountState::open_existing(database_path(raw_alias))` returned
`Ok`; the marker read was nonce `8738` (`0x2222`), balance `48059`
(`0xbbbb`), matching the fixture placed at the lossy-spelling database.
The intended UTF-8 destination database contained the distinct marker
nonce `4369` (`0x1111`), balance `43690` (`0xaaaa`). Thus this test observed
the actual COMPLETE guard permit the raw alias and the subsequent API return
the lossy-path fixture's marker.

The marker value identifies which fixture data the API returned; this test
did not inspect a private RocksDB descriptor. Directory-entry listings
before and after the call are recorded in the complete output, but are not
represented as direct descriptor identity. The guard and storage API were
called separately by the test. This does not show that an ordinary CLI/node
invocation reaches this sequence, or that it is an exploitable attack.

The UTF-8 positive control returned `ProceedComplete` and read its marker.
The foreign-record control returned `RefuseForeign`; missing and empty
required-state controls returned `RefuseMissingState`. In all three
refusal cases, the harness asserted that its conditional storage closure
was not called. These controls characterize the guard's decision and this
test harness, not a node startup route.

The focused command reported 2 tests passed, 0 failed. That count is
separate from the observations above and is not their evidentiary basis.

## Commands, exit codes, and complete outputs

The focused run used:

```text
TMPDIR=/tmp/qbind-nonutf8-complete-guard.S9CkTy/tmp \
CARGO_TARGET_DIR=/tmp/qbind-nonutf8-complete-guard.S9CkTy/target \
cargo test --locked -p qbind-node --test candidate_b_nonutf8_complete_guard_storage_tests -- --nocapture
exit code: 0
```

The compile-only check used:

```text
TMPDIR=/tmp/qbind-nonutf8-complete-guard.S9CkTy/tmp \
CARGO_TARGET_DIR=/tmp/qbind-nonutf8-complete-guard.S9CkTy/target \
cargo test --locked -p qbind-node --test candidate_b_nonutf8_complete_guard_storage_tests --no-run
exit code: 0
```

The complete final stdout/stderr from those commands is preserved in:

- `a33-f1-nonutf8-complete-guard-storage-focused-output.txt`
- `a33-f1-nonutf8-complete-guard-storage-compile-output.txt`

The complete initial failed build outputs are also retained:

- `a33-f1-nonutf8-complete-guard-storage-initial-focused-failure.txt`
- `a33-f1-nonutf8-complete-guard-storage-initial-compile-failure.txt`

`rustfmt --edition 2021 --check
crates/qbind-node/tests/candidate_b_nonutf8_complete_guard_storage_tests.rs`
and `git diff --check` succeeded before source commit. The final source blob
and Cargo.lock identity are recorded above; the evidence files do not change
test/build inputs.

No behavior outside this bounded, author-run test observation is claimed.
The earlier no-replacement-database finding, CB-1, and CB-FIXTURE-1 retain
their accepted scopes. A23-F1 and A33-F1 / E27 remain OPEN; activation
remains DISABLED; public DevNet remains NO-GO.
