# A33-F1 — Account-storage direct-API path characterization

**AUTHOR-RUN, TEST-ONLY OBSERVATION.** No node startup, production route,
filesystem race, operational key, provisioning, or deployment was exercised.
This direct-API result does not authenticate a destination or establish
Candidate B enforcement.

## Pins and scope

| Item | Value |
|---|---|
| Reviewed main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed storage-contract branch | `docs/candidate-b-storage-first-effect-path-encoding` |
| Reviewed contract endpoint | `d03e6d73585ffa5a2e08bd1454af81cdc1acd8e5`, tree `0cd9d4c985e470b5b32649a919455d2df4736b8b` |
| Source base for this run | `d03e6d73585ffa5a2e08bd1454af81cdc1acd8e5`, tree `0cd9d4c985e470b5b32649a919455d2df4736b8b` |
| Test source SHA-1 blob at run | `284a07c3c75153c37c2705e7a8de8ad7c924df44` |
| Cargo.lock Git blob / SHA-256 | `8f19cdd29d9923e04d600669fea26acd93b6d73c` / `70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf` |

Only the new integration test and this evidence document are in scope.
The test calls `RocksDbAccountState::open_existing` directly
(`crates/qbind-ledger/src/execution.rs:1423-1445`) and uses
`RocksDbAccountState::open` only to create synthetic fixture databases. It
does not run QBIND startup. The existing no-replacement-database finding
remains accepted within its prior scope.

## Environment and dependency inputs

- OS/kernel and architecture: Linux `6.12.8+`, x86_64.
- Filesystem: ext4 on `/dev/vdb`, mounted at `/`; the unique test root and
  isolated build target were under `/tmp` on that filesystem.
- Toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`,
  `cargo 1.99.0 (5f94df478 2026-08-27)`.
- Locked dependency versions: `rocksdb 0.22.0` and
  `librocksdb-sys 0.16.0+8.10.0`.
- Cargo used locally cached crate archives and extracted source under
  `/usr/local/cargo/registry/{cache,src}/index.crates.io-1949cf8c6b5b557f/`.
  The local archive SHA-256 values matched the respective Cargo.lock package
  checksums: rocksdb `6bd13e55d6d7b8cd0ea569161127567cd587676c99f4472f779a0279aa60a7a7`;
  librocksdb-sys `ce3d60bc059831dc1c83903fb45c103f75db65c5a7bf22272764d9cc683e348c`.
  This verifies the cached archives against this lockfile, not against the
  upstream rust-rocksdb tag or any independently obtained published
  archive. No byte-for-byte tag/archive equivalence is claimed.

Both `CARGO_TARGET_DIR` and `TMPDIR` were set under the unique run root
`/tmp/qbind-account-storage-path.vSm0QM`. The test's `tempfile` fixtures
were created below that `TMPDIR`, with separate unique roots for the two
controls. No fixture path was outside the run root.

## Observations

The focused run completed **2 tests passed, 0 failed**. These are author-run
observations on the environment above, not independent or hosted-CI results.

1. **Missing existing-only path:** the target began absent. The API returned
   the logged `Err` because `CURRENT` was absent. Afterward the path and its
   parent directories existed and contained `LOCK` and `LOG`; the observed
   listing contained no `CURRENT`, `IDENTITY`, `MANIFEST-*`, or `OPTIONS-*`.
   This is directory and diagnostic/lock-file effect, distinct from
   initializing an openable database. The positive control created a
   database inside the same fixture, released its setup handle, then opened
   it existing-only and read back nonce `4660`, balance `22136`.
2. **Non-UTF-8 path:** Unix path-byte construction succeeded. Raw name
   `db-\xFF` had bytes `64622dff`; its distinct lossy-converted name
   `db-�` had bytes `64622defbfbd`. A real synthetic database with nonce
   `9029`, balance `26505` was created at the lossy path; its setup handle
   was dropped. Before the observed call, the raw path did not exist and the
   lossy path did. `open_existing(raw_path)` returned `Ok`, and the API read
   back the synthetic marker values. Afterward, the raw path existed as an
   empty directory while the lossy path still contained the database files.
   The marker read identifies the data returned by the direct API call as
   the lossy-path fixture's data. The test did not inspect a private file
   descriptor; path listings alone are not presented as descriptor
   identity.

The non-UTF-8 result is consistent with the inspected wrapper's separate
Rust-path directory creation and lossy C-path conversion. It is an
observation of this locally locked build and platform, not proof of
ordinary-startup reachability, general cross-platform behavior, or an
attack. The earlier upstream-source qualification remains: the published
crate archive and author-local registry were not independently verified
byte-for-byte against the upstream tag.

The `tempfile` fixtures were removed by `TempDir` cleanup; the post-run check
found no entries under the run's `TMPDIR`. The isolated Cargo target was
removed after preserving the complete output below.

## Commands and exit codes

The focused command ran with `TMPDIR=/tmp/qbind-account-storage-path.vSm0QM/tmp`
and `CARGO_TARGET_DIR=/tmp/qbind-account-storage-path.vSm0QM/target`:

```text
cargo test --locked -p qbind-ledger --test candidate_b_account_storage_path_characterization_tests -- --nocapture
exit code: 0
```

The compile-only command used the same isolated environment:

```text
cargo test --locked -p qbind-ledger --test candidate_b_account_storage_path_characterization_tests --no-run
exit code: 0
```

`cargo tree --locked --offline -p qbind-ledger -i rocksdb` also exited `0`
and resolved `rocksdb v0.22.0` under `qbind-ledger`. Formatting and
`git diff --check` completed successfully.

The dependency-tree output was:

```text
rocksdb v0.22.0
└── qbind-ledger v0.1.0 (/workspaces/QBIND/olivexo28/QBIND/crates/qbind-ledger)
```

## Complete focused output

```text
Finished `test` profile [unoptimized] target(s) in 0.20s
     Running tests/candidate_b_account_storage_path_characterization_tests.rs (/tmp/qbind-account-storage-path.vSm0QM/target/debug/deps/candidate_b_account_storage_path_characterization_tests-30568d0b39780e32)

running 2 tests
fixture root: "/tmp/qbind-account-storage-path.vSm0QM/tmp/.tmpnzOrDO"
missing target: "missing/state_vm_v0"
fixture root: "/tmp/qbind-account-storage-path.vSm0QM/tmp/.tmp3SOttZ"
raw name debug: "db-\xFF"
missing target exists before call: false
tree before missing-path call:
raw name bytes: 64622dff
lossy name debug: "db-�"
lossy name bytes: 64622defbfbd
missing-path API result: Err(storage I/O error: Invalid argument: /tmp/qbind-account-storage-path.vSm0QM/tmp/.tmpnzOrDO/missing/state_vm_v0/CURRENT: does not exist (create_if_missing is false))
missing target exists after call: true
tree after missing-path call:
  dir "missing"
  dir "missing/state_vm_v0"
  file "missing/state_vm_v0/LOCK"
  file "missing/state_vm_v0/LOG"
lossy-path setup handle released before observed open: true
path states before observed open: raw_exists=false lossy_exists=true
tree before non-UTF-8 API call:
  dir "db-�"
  file "db-�/000008.log"
  file "db-�/000009.sst"
  file "db-�/CURRENT"
  file "db-�/IDENTITY"
  file "db-�/LOCK"
  file "db-�/LOG"
  file "db-�/MANIFEST-000005"
  file "db-�/OPTIONS-000007"
valid control setup handle released before existing-only open: true
non-UTF-8 API result: Ok; marker nonce=9029 balance=26505
path states after observed open: raw_exists=true lossy_exists=true
tree after non-UTF-8 API call:
  dir "db-�"
  file "db-�/000009.sst"
  file "db-�/000012.log"
  file "db-�/CURRENT"
  file "db-�/IDENTITY"
  file "db-�/LOCK"
  file "db-�/LOG"
  file "db-�/LOG.old.1794213218257251"
  file "db-�/MANIFEST-000013"
  file "db-�/OPTIONS-000007"
  file "db-�/OPTIONS-000015"
  dir "db-\xFF"
test existing_only_non_utf8_path_and_lossy_database_control ... ok
valid-database API result: Ok; marker nonce=4660 balance=22136
tree after valid-database control:
  dir "missing"
  dir "missing/state_vm_v0"
  file "missing/state_vm_v0/LOCK"
  file "missing/state_vm_v0/LOG"
  dir "valid_db"
  file "valid_db/000009.sst"
  file "valid_db/000012.log"
  file "valid_db/CURRENT"
  file "valid_db/IDENTITY"
  file "valid_db/LOCK"
  file "valid_db/LOG"
  file "valid_db/LOG.old.1794213218285096"
  file "valid_db/MANIFEST-000013"
  file "valid_db/OPTIONS-000007"
  file "valid_db/OPTIONS-000015"
test existing_only_missing_path_effects_and_database_control ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.12s
```

## Complete compile-only output

```text
Finished `test` profile [unoptimized] target(s) in 0.10s
  Executable tests/candidate_b_account_storage_path_characterization_tests.rs (/tmp/qbind-account-storage-path.vSm0QM/target/debug/deps/candidate_b_account_storage_path_characterization_tests-30568d0b39780e32)
```

These observations do not establish ordinary node-route input delivery,
namespace-race resistance, destination authentication, backend confinement,
or Candidate B enforcement. They do not broaden or reopen the accepted
no-replacement-database finding. Destination-binding feasibility and
route-design questions remain **OPEN**. CB-1 and CB-FIXTURE-1 retain their
accepted scopes; A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO.
