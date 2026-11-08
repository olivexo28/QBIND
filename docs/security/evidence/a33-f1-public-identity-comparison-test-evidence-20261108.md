# A33-F1 — test-only public identity comparison evidence

**ISOLATED TEST-ONLY SLICE.** This evidence does not establish a production
identity authority or authorize startup, signing, participation, recovery or
restart. Activation remains **DISABLED**; public DevNet remains **NO-GO**.
A33-F1 / E27 and other recorded obligations remain **OPEN**.

## Source and evidence provenance

The original test/build inputs are source commit
`8794b8b1f45ee3518de6ec30335fa03570c11a72`, tree
`b61e532cd5633a3a85d06f6c2de825b83f81b935`, parent
`e9e92b29c128daeaeb7dd11477f9661146e6aa27`. The complete original focused-test
output, including command, source commit/tree, test count, exit code and
compiler warnings, is retained in
[`a33-f1-public-identity-comparison-focused-output-20261108.txt`](a33-f1-public-identity-comparison-focused-output-20261108.txt).
The complete compile-only output and exit code are retained in
[`a33-f1-public-identity-comparison-compile-output-20261108.txt`](a33-f1-public-identity-comparison-compile-output-20261108.txt).

The follow-up test/build inputs are source commit
`677e393aca41b9a604137730f3786e6952cc157f`, tree
`7e3a9679e4dfc2e9e926f64154bcf80044d13de1`, parent
`97e1f72c67346306ceeec43aeaa9fd760874b58d`. The complete follow-up focused
and compile-only outputs, including commands, source provenance, test count,
exit codes and compiler warnings, are retained in
[`a33-f1-public-identity-comparison-followup-focused-output-20261108.txt`](a33-f1-public-identity-comparison-followup-focused-output-20261108.txt)
and
[`a33-f1-public-identity-comparison-followup-compile-output-20261108.txt`](a33-f1-public-identity-comparison-followup-compile-output-20261108.txt).
This evidence update changes only this note and those two output files; the
test source, manifests, lockfile and other build inputs are unchanged from
the follow-up source commit. The evidence commit/tree are recorded by Git
metadata, not substituted for the source revision used in the runs.

The wrapper-sensitivity correction test/build inputs are source commit
`8df5c5be68ef14fc690d08b4d315b6146ad2d4e2`, tree
`eb561ae5dca1a287f375ccabba873334f8898c28`, parent
`754dde408d2dd15750b4d404c9ccee786fb14118`. Complete focused and compile-only
outputs, including commands, source provenance, test count, exit codes and
compiler warnings, are retained in
[`a33-f1-public-identity-comparison-wrapper-focused-output-20261108.txt`](a33-f1-public-identity-comparison-wrapper-focused-output-20261108.txt)
and
[`a33-f1-public-identity-comparison-wrapper-compile-output-20261108.txt`](a33-f1-public-identity-comparison-wrapper-compile-output-20261108.txt).
This evidence update changes only this note and those two output files; test
source and build inputs remain unchanged from the correction source commit.

## Helpers and synthetic boundary

The integration test is
[`crates/qbind-node/tests/public_first_identity_comparison_tests.rs`](../../../crates/qbind-node/tests/public_first_identity_comparison_tests.rs).
It calls these existing read-only source helpers from pinned main commit
[`810a6759ef1e3ddb42c9a0f09f78502dc4655276`](https://github.com/olivexo28/QBIND/tree/810a6759ef1e3ddb42c9a0f09f78502dc4655276):

- `DestinationId::canonicalize` at
  [`restore_completion.rs:153-179`](https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-node/src/restore_completion.rs#L153-L179)
  supplies the observed canonicalized UTF-8 destination path. The path and
  expected value are disposable synthetic fixtures; this helper does not
  establish filesystem-incarnation identity or race resistance.
- `compute_canonical_genesis_hash` at
  [`genesis.rs:1576-1621`](https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L1576-L1621)
  and `verify_boot_time_genesis` at
  [`genesis.rs:1797-1855`](https://github.com/olivexo28/QBIND/blob/810a6759ef1e3ddb42c9a0f09f78502dc4655276/crates/qbind-ledger/src/genesis.rs#L1797-L1855)
  operate on one owned parse in the fixture. The test compares the full hash
  with its synthetic retained boot hash and refuses a missing or mismatched
  retained value. This is a test-profile choice only; it does not select a
  production policy for `None` or embedded genesis.

The expected association and its “authenticated” status are explicit
**synthetic fixtures**. The comparison covers seven identity fields; the
synthetic public key is 64 bytes. It does not create or inspect founder
credentials, trust roots, provisioning, a signer or signing history. No
operational key is accessed and no production node is run.

Temporary fixture creation is outside the comparison path: `tempfile::TempDir`
creates disposable directories, test setup writes/reads synthetic genesis
JSON and a malformed JSON fixture, and RAII cleanup removes them. A missing
genesis path exercises the actual read-error branch. Ambiguous source
resolution is simulated because the existing helpers do not return an
ambiguous-association category.

## Controls exercised

- Matching synthetic association returns only the test comparator’s `Match`
  enum; there are no startup, signer, participation, recovery or restart
  capability values.
- Each of environment, numeric chain ID, full genesis hash, destination,
  validator ID, suite ID and complete public key is varied independently for
  missing, unavailable and mismatch evidence.
- The full-key negative control changes a byte after the shared first four
  bytes, demonstrating equal short display prefixes but unequal full key
  bytes.
- Absent and explicitly untrusted expected associations refuse. A test-only
  bypass of the expected-association trust guard makes the untrusted case
  match, invalidating that negative control.
- Actual missing-path and malformed-JSON helper errors are refused before the
  comparator. Ambiguous acquisition is an explicitly simulated error. A
  test-only bypass of the acquisition guard makes each negative case match.
- Per-field bypass controls demonstrate that bypassing each field’s missing,
  unavailable or equality check changes its corresponding negative case to
  `Match`. A separate positive control prevents an always-refuse comparator
  from passing.
- Missing retained external-genesis hash and hash mismatch refuse in this
  synthetic test profile. The genesis fields/hash derive from one owned parse.
- A matching synthetic local-record fixture cannot replace missing or
  untrusted expected authority. A test-only fallback mutation makes those
  negative cases match.
- Actual canonical-destination and same-parse genesis helper results are
  compared against a fixed synthetic expected association. A matching fixture
  is positive; a separately canonicalized destination and a separately
  parsed, valid genesis (verified against its own retained hash) mismatch the
  unchanged expected tuple through `acquire_against_expected(..., false)`,
  returning the specific `DestinationId` and `GenesisHash` mismatches.
  Calling that same wrapper with `bypass=true` on each same changed observation
  discards the acquired identity and returns `Match`, making each negative
  assertion sensitive to the wrapper improperly discarding acquired values.
- The runtime environment and numeric chain ID are explicit synthetic inputs;
  numeric chain ID uses `NetworkEnvironment::chain_id()`, not inference from
  the genesis textual chain name.
- In the helper-connected path, the observed destination string comes from
  `DestinationId::canonicalize`; parsed genesis text and full canonical hash
  come from one read and owned parse, with the hash checked against the
  supplied retained fixture hash. The fixed expected association is a
  separately constructed, explicitly synthetic fixture: its destination is
  independently canonicalized from the expected fixture path and its genesis
  hash comes from the expected `GenesisConfig`. Environment/numeric chain,
  validator ID, suite, and 64-byte public key are synthetic inputs, not
  signer observations. The change to genesis timestamp retains the same
  textual chain name and passes validation against its own hash; comparison
  against the unchanged expected association rejects the changed full hash.

There is no orchestration-order claim, so there are no protected-effect
callbacks in this test. It does not test CLI startup ordering or claim refusal
blocks real startup effects. Any future orchestration claim requires observable
protected-effect callbacks and a sensitive bypass control.

## Checks

Follow-up commands run at source commit
`677e393aca41b9a604137730f3786e6952cc157f`, tree
`7e3a9679e4dfc2e9e926f64154bcf80044d13de1`:

| Command | Result |
|---|---|
| `cargo test -p qbind-node --test public_first_identity_comparison_tests -- --nocapture` | Exit 0; **10 passed, 0 failed**. Complete output retained in the follow-up focused output file. |
| `cargo test -p qbind-node --test public_first_identity_comparison_tests --no-run` | Exit 0; test executable compiled. Complete output retained in the follow-up compile output file. |
| `rustfmt --edition 2021 --check crates/qbind-node/tests/public_first_identity_comparison_tests.rs` | Exit 0. |
| `git diff --check` | Exit 0. |

The earlier source commit's **8 passed** focused run and compile-only check
remain documented above and their historical raw output files are unchanged.

For the wrapper-sensitivity correction, at source commit
`8df5c5be68ef14fc690d08b4d315b6146ad2d4e2`, tree
`eb561ae5dca1a287f375ccabba873334f8898c28`:

| Command | Result |
|---|---|
| `cargo test -p qbind-node --test public_first_identity_comparison_tests -- --nocapture` | Exit 0; **10 passed, 0 failed**. Complete output retained in the wrapper focused output file. |
| `cargo test -p qbind-node --test public_first_identity_comparison_tests --no-run` | Exit 0; test executable compiled. Complete output retained in the wrapper compile output file. |
| `rustfmt --edition 2021 --check crates/qbind-node/tests/public_first_identity_comparison_tests.rs` | Exit 0. |
| `git diff --check` | Exit 0. |

The initial focused compile attempt failed before reaching this test because
the environment lacked `libclang` required by `zstd-sys`; after installing
that build dependency, the focused test and compile-only check above passed.
Warnings in the retained successful logs are existing unused-code warnings in
workspace crates, not test failures.

## Limitations

The result does not prove authenticated real provisioning, production CLI
ordering/enforcement, namespace-race resistance, filesystem-incarnation
identity, durable intent, signing-history currentness, signer fencing or
exclusivity, recovery authority, restart safety, or any permission to proceed
or sign. It does not modify signed formats, production source, manifests or
historical raw logs. Prior scoped acceptances and the closed PR #11 transfer
investigation remain unchanged.
