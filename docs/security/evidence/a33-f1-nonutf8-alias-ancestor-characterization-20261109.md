# A33-F1 — Non-UTF-8 alias and account ancestor characterization

**AUTHOR-RUN, TEST-ONLY OBSERVATION.** This characterization called two
existing QBIND APIs in isolated temporary fixtures. It did not run node
startup, exercise the COMPLETE guard, use operational keys, exercise a
filesystem race, or establish destination authority, race resistance, or
Candidate B enforcement.

## Pins and scope

| Item | Value |
|---|---|
| Expected main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed earlier characterization branch | `test/candidate-b-account-storage-path-characterization` |
| Reviewed endpoint | `318dcdec38ebaa4322e75a036f170d30287a524e`, tree `8cbcb65bce00dfc1f5648e6d1490b413d880a829` |
| Parent/source base for this run | `318dcdec38ebaa4322e75a036f170d30287a524e`, tree `8cbcb65bce00dfc1f5648e6d1490b413d880a829` |
| Test source Git blob at run | `7c8d507842cf0578c0def29705dcfa0f908ecc8c` |
| Cargo.lock Git blob / SHA-256 | `8f19cdd29d9923e04d600669fea26acd93b6d73c` / `70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf` |

This adds a separate integration test and evidence only. The previous
account-storage characterization source and historical evidence were not
modified or rerun. The new test invokes `DestinationId::canonicalize`
directly (`crates/qbind-node/src/restore_completion.rs:153-173`) and
`RocksDbAccountState::open_existing` directly
(`crates/qbind-ledger/src/execution.rs:1423-1445`).

## Environment and dependencies

- OS/kernel/architecture: Linux `6.12.8+`, x86_64.
- Filesystem: ext4 on `/dev/vdb`, mounted at `/`; the unique fixture and
  isolated Cargo target were under `/tmp` on this filesystem.
- Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`,
  `cargo 1.99.0 (5f94df478 2026-08-27)`.
- Lock-resolved packages: `rocksdb 0.22.0`, `librocksdb-sys
  0.16.0+8.10.0`, `clap 4.5.56`, and `clap_builder 4.5.56`.
- Cargo used locally cached crate archives/source in
  `/usr/local/cargo/registry/{cache,src}/index.crates.io-1949cf8c6b5b557f/`.
  The cached RocksDB archive SHA-256
  `6bd13e55d6d7b8cd0ea569161127567cd587676c99f4472f779a0279aa60a7a7`
  and librocksdb-sys archive SHA-256
  `ce3d60bc059831dc1c83903fb45c103f75db65c5a7bf22272764d9cc683e348c`
  match their `Cargo.lock` checksums. This does not independently establish
  byte-for-byte equivalence with an upstream tag or another published
  artifact.

The unique run root was
`/tmp/qbind-nonutf8-alias-ancestor.XDITga`; both `TMPDIR` and
`CARGO_TARGET_DIR` were placed below it. Each test created its own
`tempfile` fixture beneath that `TMPDIR`.

## Observations (separate from test counts)

The focused command printed and asserted both results; complete raw output is
retained at
`a33-f1-nonutf8-alias-ancestor-focused-output-20261109.txt`. The command
reported **2 passed, 0 failed**. That count is not itself evidence for the
printed API outcomes.

1. **Non-UTF-8 symlink spelling.** On this Unix/ext4 fixture, symlink
   creation succeeded. The alias component bytes were `616c6961732dff`
   (`alias-\xFF`); the symlink target was the existing in-root UTF-8 path
   `utf8-destination`. Before calling `DestinationId::canonicalize`, the
   test resolved the alias and verified that its canonical target exactly
   equaled the intended target and remained beneath the fixture root. The
   API returned `Ok` with that canonical UTF-8 target string. Thus this
   observation records the canonical target, not the original alias
   spelling, as the `DestinationId` value.
2. **Account database beneath a non-UTF-8 ancestor.** The raw ancestor
   bytes were `616e636573746f722dff` (`ancestor-\xFF`); the lossy ancestor
   bytes were `616e636573746f72efbfbd` (`ancestor-�`). Both account database
   leaves were the fixed UTF-8 `state_vm_v0` component and both full paths
   were distinct and inside the fixture. The test created a real synthetic
   database at the lossy-ancestor path, wrote and flushed nonce `13398`,
   balance `30874`, then dropped the setup handle. Before the observed
   open, the raw-path database was absent and the lossy-path database
   existed. `open_existing(raw_ancestor/state_vm_v0)` returned `Ok`; its API
   read back the lossy database's marker values. Afterward, the raw
   ancestor/database directories existed but the raw database directory was
   empty; the lossy path still contained the RocksDB files. The marker read
   is the evidence identifying which fixture data the API returned. No
   private RocksDB descriptor was inspected, so this is not a direct
   descriptor identity observation.

These are platform-specific direct-API results, not node-route results.
They do not exercise whether the ordinary startup absent-RTR branch admits
such a path, nor the COMPLETE guard, and they do not demonstrate
exploitability or race resistance. The accepted no-replacement-database
finding and earlier direct-API observations remain within their existing
scopes.

## Commands, exit codes, and retained output

The focused command ran with
`TMPDIR=/tmp/qbind-nonutf8-alias-ancestor.XDITga/tmp` and
`CARGO_TARGET_DIR=/tmp/qbind-nonutf8-alias-ancestor.XDITga/target`:

```text
cargo test --locked -p qbind-node --test candidate_b_nonutf8_alias_ancestor_characterization_tests -- --nocapture
exit code: 0
```

The compile-only command used the same isolated environment:

```text
cargo test --locked -p qbind-node --test candidate_b_nonutf8_alias_ancestor_characterization_tests --no-run
exit code: 0
```

Complete stdout/stderr from those commands is preserved in:

- `a33-f1-nonutf8-alias-ancestor-focused-output-20261109.txt`
- `a33-f1-nonutf8-alias-ancestor-compile-output-20261109.txt`

The focused build completed in 12m17s and emitted existing dead-code
warnings from `qbind-consensus` and `qbind-node`; no test warning or failure
was reported. The compile-only command completed successfully. Formatting
and `git diff --check` also completed successfully.

The `tempfile` fixtures cleaned up; a post-run check found no entries under
the run's `TMPDIR`. The isolated Cargo target was removed after the complete
logs had been copied into this evidence set. The test source Git blob was
checked again before commit to ensure the test/build input did not change
after execution.

No behavior outside these two bounded API observations is claimed.
Destination-binding feasibility and route questions remain OPEN. Preserve
CB-1 and CB-FIXTURE-1 within their accepted scopes; A23-F1 and A33-F1 / E27
remain OPEN; activation remains DISABLED; public DevNet remains NO-GO.
