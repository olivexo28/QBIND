# QBIND — Path-encoding refusal test-only baseline

**TEST-ONLY BASELINE — NOT A PRODUCTION CHANGE OR APPROVAL.** This evidence
records current behavior for the proposed path-encoding refusal contract.
It does not implement that contract, select an error API, or authorize
startup, provisioning, operational keys, or deployment.

The test calls real account and consensus storage APIs with synthetic
temporary fixtures. It separately exercises the public execution adapter.
It does not start a node or establish normal-startup reachability. Results
are specific to the source, dependencies, operating system, and filesystem
recorded here. The prior no-replacement-database finding, CB-1,
CB-FIXTURE-1, and guard-to-storage characterization retain their accepted
scopes. A23-F1 and A33-F1 / E27 remain OPEN; activation remains DISABLED;
public DevNet remains NO-GO.

## Pinned source and scope

| Item | Identity |
|---|---|
| Pinned main | `aa382fa28b2d3e97e6203d47fa8231b5f2269741`, tree `f1a7d40993bfefbe18635bd637a100ad5527d875` |
| Reviewed proposal endpoint | `094f51204ead638204a83ff00085dc289400b087`, tree `3e159f7c836de131c506dc591a97538d3a6130b3` |
| Final test source at compile and focused run | `4df65b037d1172adbb93bdfa4ee7ae7648254c97`, tree `9f17651793d9b0840465913d96ae7233a52ba875`, parent `272e473e5ecd6ba892283d889b522eead044e40a` |
| Test source blob at final run | `crates/qbind-node/tests/candidate_b_storage_path_encoding_baseline_tests.rs`: `2f5ea014c21b8a696ded00c52001c806d755c12c` |
| Proposal and contract matrix | [`a33-f1-storage-path-encoding-refusal-proposal-20261109.md`](a33-f1-storage-path-encoding-refusal-proposal-20261109.md) at `094f51204ead638204a83ff00085dc289400b087` |
| Earlier guard-to-storage characterization | `4ca2839796e27b8384ff6b4b12e21ab9d3b2fccf`; its author-run results and limitations are not rerun or broadened here |

The test branch adds the test source to the reviewed proposal endpoint.
Its complete comparison against main also includes inherited proposal
specifications, tests, and evidence; the test-only slice must not be
described as the entire main-relative package.

## Commands, inputs, and retained outputs

Commands ran from the repository root. The isolated run root was
`/tmp/qbind-storage-path-encoding-baseline.esJwsk`; `TMPDIR` was
`$ROOT/tmp`, and `CARGO_TARGET_DIR` was `$ROOT/target`. The source was
committed before each recorded compile or focused run.

| Source at command | Command | Result |
|---|---|---|
| `d0e90e1621aeb0a9ee5e34c001d03de5af63cfc3`, tree `352a09debf5ac4b27b6db6e700ef188b0d758542`, test blob `cd476964ed80411cfda199da390e6603d5493c9e` | `CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_storage_path_encoding_baseline_tests --no-run` | Exit 0; initial compile-only check. Full output: [`initial compile`](candidate-b-path-encoding-baseline-initial-compile-20261109.txt), SHA-256 `4489227a57cf6dce9380cb1a6510988dc03db6e1415f5f139a464933dbf26c66`. |
| `a018d95b73aafd87528a6403d133bdb4ec320277`, tree `f7b0a507c96f3d61b9ec24af4e35f84744ceaa9f`, test blob `2a5f2d7341a2daaf799d9bc7ea2ba4be2d586ed0` | Same compile-only command | Exit 0. Full output: [`pre-adapter compile`](candidate-b-path-encoding-baseline-pre-adapter-compile-20261109.txt), SHA-256 `598203fe58c3b2aef7d531aad160ba77b1a115c8b7bb69faab29bcaadae859ff`. |
| `a018d95b73aafd87528a6403d133bdb4ec320277` | `CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_storage_path_encoding_baseline_tests -- --nocapture` | Exit 101; 1 passed, 3 failed. These were observed path-contract baseline failures. Full output: [`pre-adapter focused run`](candidate-b-path-encoding-baseline-pre-adapter-focused-20261109.txt), SHA-256 `fea53ec5b0e411e8a450c89ba60fbb9ee175bad8f77da049d1920cb535f209f5`. |
| `272e473e5ecd6ba892283d889b522eead044e40a`, tree `5a6a6ec63b7ca055bbc1c2299c4bf7454ef812ad`, test blob `60a998971d7e0a6dcdb9568d29a750451edc4f4f` | Same compile-only command | Exit 101; the new adapter control passed `VmV0ExecutionEngine`, which does not implement the required `ExecutionEngine` trait. This is a compilation failure, not a test result. Full output: [`adapter compile failure`](candidate-b-path-encoding-baseline-adapter-compile-failure-20261109.txt), SHA-256 `721ae31722d2783cca61898636ef98f2164f04a30145630aefa24a172e68b0aa`. |
| Final source `4df65b037d1172adbb93bdfa4ee7ae7648254c97` | Same compile-only command | Exit 0. The adapter fixture was corrected to supply `NonceExecutionEngine` while selecting the VM-v0 profile. Full output: [`final compile`](candidate-b-path-encoding-baseline-final-compile-20261109.txt), SHA-256 `7598d0cf34ef358d9eb0a931087495d6053cf805a7d9ba6b3ca23161d82cc60c`. |
| Final source `4df65b037d1172adbb93bdfa4ee7ae7648254c97` | `CARGO_TARGET_DIR="$ROOT/target" TMPDIR="$ROOT/tmp" cargo test --locked -p qbind-node --test candidate_b_storage_path_encoding_baseline_tests -- --nocapture` | Exit 101; **2 passed, 3 failed, 0 ignored**. Failures are contract assertion failures against unchanged production APIs, not compilation or infrastructure failures. Full output: [`final focused run`](candidate-b-path-encoding-baseline-final-focused-20261109.txt), SHA-256 `2313532201cbdb11be9e0ad84588de3c8e833ad49049d7ad6c1a0a8a3aac83ee`. |

The final test-source compile and focused run used the same committed source
and build inputs. The source file and `Cargo.lock` were unchanged afterward.
The workspace Cargo.lock SHA-256 was
`70aec07f6e1eb8ea3e98634acefdd92bf9f9ea03929d2821e3cc04c75bb1baaf`.
The initial and intermediate logs are retained to distinguish compile
successes, the adapter compile failure, and the earlier focused baseline;
they are not substituted for the final run.

## Environment and dependency observations

- Observed platform: Linux `x86_64`, kernel `6.12.8+`; the isolated run root
  was on `/dev/vdb`, filesystem `ext4`.
- Observed toolchain: `rustc 1.99.1 (58cf8f9c3 2026-10-13)`,
  `cargo 1.99.1 (5f94df478 2026-08-27)`.
- `cargo tree --locked -p qbind-node -i rocksdb` resolved `rocksdb v0.22.0`
  through `qbind-ledger` and `qbind-node`. The lockfile records
  `librocksdb-sys 0.16.0+8.10.0`. The cached archive checksum was reported
  to match the lockfile; independent identity of the archive against the
  upstream tag or publisher was not established.
- Fixtures used `tempfile` roots under the isolated `TMPDIR`. Unix-only
  tests constructed an ancestor containing byte `0xff`; the tests were
  run on Linux/ext4. No cross-platform result is established.

## Actual API observations

The test uses the real `RocksDbAccountState::open`,
`RocksDbAccountState::open_existing`, and `RocksDbConsensusStorage::open`
interfaces described in the pinned proposal. Markers distinguish a raw
path from its lossy UTF-8 spelling. Setup database handles were dropped
before observed opens. Raw path bytes, fixture paths, marker values,
results, and filesystem entries are emitted in the retained focused logs.

| Control | Final focused-run observation |
|---|---|
| Account create with invalid UTF-8 in an ancestor | API returned `Err`; raw ancestor and `state_vm_v0` directory existed afterward. The lossy-spelling directory remained absent, and no lossy-path marker was found. The test failed its proposed refusal-before-effects assertion. |
| Account existing-only open with invalid UTF-8 in an ancestor | API returned `Ok` and read the distinguishable lossy-path marker (nonce `29555`, balance `42148`). The raw ancestor/database appeared, and lossy database entries changed. The test failed its proposed refusal assertion. |
| Consensus open with invalid UTF-8 in an ancestor | API returned `Ok` and read the lossy-fixture epoch `0x12345678`. The raw ancestor/database appeared, and lossy database entries changed. The test failed its proposed refusal assertion. |
| Representable UTF-8 account create/existing-only and consensus reopen | Positive controls passed and returned the written markers. |
| Ordinary storage errors | Existing-only on an empty directory and account/consensus open beneath a regular-file parent returned errors as expected. |
| Execution adapter configured with a persistent path blocked by a regular file | The actual public `SingleThreadExecutionService` VM-v0 adapter logged persistent-open failure and fallback to in-memory; one transaction was applied. With no persistent path explicitly selected, the in-memory control also applied one transaction. |

The final focused run's 2 passing tests are the adapter control and the
representable/ordinary-error controls. Its 3 failing tests are the account
create, account existing-only, and consensus non-representable-path
contract assertions. In particular, account-create returning an error
does not satisfy the proposed contract: its raw-path ancestor and database
directory were already created. Because this is a normal Cargo integration
test target, the intentional baseline assertions also make the crate's
default test discovery fail until separately reviewed; this branch is not
integration-ready. The recorded execution used only the focused target
command above, not the full crate suite.

The direct API observations do **not** prove the exact captured path passed
to `DB::open`, prove that a wrapper call was or was not made, or prove that
the proposed refusal boundary precedes all private backend effects.
Filesystem listings and returned markers are observable evidence, not
wrapper-call instrumentation. A future implementation needs a test seam
or equivalent direct evidence for same-captured-path identity and
pre-wrapper refusal. No production instrumentation was added.

The adapter control establishes behavior only for the public adapter call
made by this test. It does not show that the ordinary P2P startup route
reaches this adapter. No node was started and no startup-ordering control
was run; the earlier protected-effect boundary remains a separate future
test requirement.

## Future evidence gaps and limitations

The test is a baseline against unchanged production behavior, not a
conformance pass or integration-ready suite. It establishes no production
path-representability refusal, distinguished error variant, exact wrapper
call boundary, startup ordering, ordinary-node reachability, or policy
against silent fallback after a required persistent open fails. It does
not test Windows or other filesystems, embedded NUL, namespace/symlink
races, destination authentication, object binding, ownership, fencing,
recovery, or Candidate B enforcement.

Future test-only work, after separate authorization and any required
implementation seam, should retain the raw/lossy marker controls and
assert the proposed API result, exact captured-path identity, and
pre-wrapper effect boundary for account create, account existing-only, and
consensus open. A separate instrumented startup test would need to prove
the scoped ordinary-P2P refusal precedes its selected first protected
effect. Adapter tests should separately assert that a requested persistent
store failure refuses and that explicitly selected in-memory operation
continues. These controls are **FUTURE / NOT EXECUTED**; no synthetic
recorder or model is presented as production evidence.

The observed account and consensus effects are for these actual API calls
and this particular dependency build/platform. Any claim about other
platforms, actual node orchestration, RocksDB's private wrapper call
sequence, or a production correction needs separate evidence.
