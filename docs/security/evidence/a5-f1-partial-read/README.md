# A5-F1 / OBL-AVL-3a bounded author evidence

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** A5-F1 / OBL-AVL-3a and E11
remain **OPEN** to their remaining extent, as do A11-F2 / OBL-TRN-3,
E19, E07 and OBL-GOV-2. Activation **DISABLED**; public DevNet **NO-GO**.

## Exact identities and changed source paths

Repository: `https://github.com/olivexo28/QBIND`.
Task branch: `copilot/audit-a5-f1-partial-read`.
Required baseline/sole implementation parent:
`4629c8d14323afd86d45d2f6786f46db4f074a59`, tree
`5bcf469421d0d0232f603bb41788e694b6326d83`.
Baseline raw parent: `5815346afcdd70323dad2bae1d01bf46c132cf81`.
Implementation/test producing commit:
`cbfaa4150465f3e3c3dfb45ee7887d961f087d36`, tree
`69ab5828fde0d07f043e5169968c70e129f66e7f`.

| Producer path | Git blob | Change |
|---|---|---|
| `crates/qbind-node/src/secure_channel.rs` | `7026a8e66c02254b8454bdf750a12c70a1c6d377` | Whole-frame counting, fatal original-cause wrapping and shared invalidation/shutdown; async error-detail preservation without releasing invalidated buffered plaintext |
| `crates/qbind-node/src/secure_channel/partial_read_tests.rs` | `213725a75fd9546ca73f3d4a823c4004022a403a` | Six focused deterministic receive tests |
| `crates/qbind-node/src/secure_channel/encrypted_write_tests.rs` | `efd8bc5fdc2e34877739b5340ec2e25cca632180` | Share the private real-AEAD fixture; adapt partial-output peer EOF assertion to require fatal wrapping with original EOF and invalidation; preserve all seven send tests |
| `crates/qbind-net/src/framed_io.rs` | `23559a10508a222e704145bd809c2864b3d50ccb` | Document stateless transport reader's progress/retry caller obligation; no framing algorithm or limit change |

[Producer source](https://github.com/olivexo28/QBIND/blob/cbfaa4150465f3e3c3dfb45ee7887d961f087d36/crates/qbind-node/src/secure_channel.rs)
and [receive tests](https://github.com/olivexo28/QBIND/blob/cbfaa4150465f3e3c3dfb45ee7887d961f087d36/crates/qbind-node/src/secure_channel/partial_read_tests.rs)
are pinned to the producing revision, not this later documentation.
`producer.txt` records empty worktree status before validation, exact
commit/tree/parent, all four blobs/modes, toolchain/kernel, origin and
remote-main advertisement. The task branch did not yet exist remotely.

The later evidence/documentation commit changes only this new evidence
directory and appends sections 16-17 to the plan. Its own commit/tree/
parent and manifest blob are reported at delivery rather than embedded
self-referentially. The historical audit register, old evidence files,
all earlier plan bytes and other protected files remain unchanged.

## Producer-pinned validation

All commands below ran at the clean implementation producer, with
unchanged tracked files. Logs contain producer identity, exact command,
raw combined stdout/stderr and exit status. Watchdogs bound command
execution; they are not application-timeout or platform claims.

| Log | Exact command | Actual result |
|---|---|---|
| `focused.log` | `timeout 240s cargo test --locked --offline -p qbind-node --lib secure_channel:: -- --test-threads=1` | 13 passed: 6 new receive, all 7 encrypted-write; 2172 unrelated filtered out |
| `node-regressions.log` | `timeout 300s cargo test --locked --offline -p qbind-node --test secure_channel_smoke_tests --test secure_channel_async_refactor_tests --test t139_real_pqc_kemtls_two_node_tests --test kemtls_encrypted_transport_tests --test peer_manager_roundtrip_tests --test peer_manager_consensus_roundtrip_tests -- --test-threads=1` | 30 passed: 2 smoke, 3 async-refactor, 8 real-PQC, 11 encrypted-transport, 4 peer roundtrip, 2 peer consensus |
| `framing-regressions.log` | `timeout 240s cargo test --locked --offline -p qbind-net --test framed_io_tests --test full_channel_roundtrip_tests -- --test-threads=1` | 22 framing + 4 roundtrip passed |
| `production-check.log` | `timeout 300s cargo check --locked --offline -p qbind-node -p qbind-remote-signer --lib --bins` | Passed without test seams |
| `format-whitespace.log` | `rustfmt --edition 2021 --check --config skip_children=true crates/qbind-net/src/framed_io.rs crates/qbind-node/src/secure_channel.rs crates/qbind-node/src/secure_channel/encrypted_write_tests.rs crates/qbind-node/src/secure_channel/partial_read_tests.rs` | Passed |
| `format-whitespace.log` | `git diff --check 4629c8d14323afd86d45d2f6786f46db4f074a59 HEAD` | Passed |

All six validation commands exited **0**. **69 selected Rust tests passed,
0 failed, 0 ignored**. Existing warnings are included, not suppressed or
represented as a warning-free build. This is not full-workspace,
release-artifact, deployed-binary or independent execution evidence.

## What the six receive tests measure

| Test | Bounded observation |
|---|---|
| `idle_timeouts_retry_same_session_with_real_aead_and_interrupted` | Both timeout kinds at zero consumption, both directions, no shutdown/open, same session accepts two consecutive valid frames and reverse traffic; normal Interrupted handling |
| `partial_header_header_only_and_body_failures_latch_both_directions` | Both directions; exact budgets 1/4 (partial header), 5 (header complete, no body), 7 (partial body); WouldBlock/TimedOut/EOF/reset; both shutdown outcomes; original causes and byte counts retained under fatal outer kind, no decrypt/open or further send seal; no subsequent guarded reads; live peer traffic after injected shutdown failure still cannot reach local AEAD |
| `actual_reader_retries_idle_then_reports_partial_error_and_terminates` | Real production reader loop; both timeout kinds; zero progress followed by complete valid frame and controlled EOF on the same session; budgets 2/5/7 produce one fatal error carrying original cause and close the reader queue; worker completion observed within a five-second test watchdog, with queue capacity available |
| `spawned_owned_cloned_and_independent_shared_handles_refuse_partial_reads` | Actual spawned owned/shared workers, clones, independent shared wrappers and late shared wrapper; synchronous shared guard; both shutdown outcomes; async fatal classification/refusal, no AEAD open |
| `counted_framing_keeps_limit_and_does_not_read_past_frame` | Framing-only cursor control: accept exact 16 MiB ciphertext with trailing sentinel unread; reject limit + 1 after consuming only five header bytes |
| `real_aead_full_ciphertext_at_limit` | Both directions successfully transfer/decrypt a real-AEAD frame with exactly 16 MiB ciphertext (plaintext limit minus 16-byte tag); sending/receiving run concurrently on local loopback |

The fault reader performs real socket reads capped by a deterministic
budget and then injects exactly one chosen error (or returns zero for
EOF). The counting adapter, framer, channel, latch and workers are
production logic. The fault reader overrides `read_exact` to panic:
the passing tests prove the adapter uses its own default `read_exact`
through counted `read`, not an uncounted underlying override.
There is no production feature flag or operational bypass.

The fixture uses real ML-KEM-768 and counted real
ChaCha20-Poly1305, shared with the A11-F2 tests. Certificate signature
verification is dummy and fixture mutual authentication is disabled;
this is not production identity-admission evidence. The open count
remains zero for incomplete frames; the unentered `decrypt_app`/session
open path is also where receive counters advance. Idle retry success
additionally checks receive-counter synchronization. Existing framing/
dummy-crypto controls are distinct from these real-AEAD controls.

## Preparation attempts, not clean-producer evidence

These are raw outputs from **uncommitted precursors** based on the
required baseline; exact dirty-source trees were not recorded. They are
retained for transparency, not attributed to the producer commit or
counted again in the 69 tests.

| Log | Actual command / outcome |
|---|---|
| `preparation.log` | `timeout 240s cargo test --locked --offline -p qbind-node --lib secure_channel:: -- --test-threads=1`; exit 101: `sha3` missing from local Cargo cache, no tests ran |
| `preparation-online.log` | `timeout 600s cargo test --locked -p qbind-node --lib secure_channel:: -- --test-threads=1`; exit 101: dependencies restored, build failed because bindgen could not find `libclang.so`; no tests ran |
| `dependency-install.log` | `timeout 240s apt-get update -qq` then `timeout 240s apt-get install -y -qq libclang-dev`; exit 0; apt reported an unrelated Chrome-index DNS warning, required libclang installed |
| `preparation-retry.log` | `timeout 600s cargo test --locked --offline -p qbind-node --lib secure_channel:: -- --test-threads=1`; exit 101: 12 passed, 1 failed. Historical send test expected bare peer EOF after partial output; corrected to require the new fatal partial-read wrapper with original EOF, not weakened into acceptance of arbitrary errors |
| `preparation-final.log` | `timeout 240s cargo test --locked --offline -p qbind-node --lib secure_channel:: -- --test-threads=1`; exit 0: 13 passed before implementation commit |

No manifests/lockfile changed. Independent attempts to retrieve official
Rust `Read` documentation (web fetch and `timeout 30s curl -fLsS
https://doc.rust-lang.org/std/io/trait.Read.html`) failed DNS resolution;
curl exited 6. Reasoning uses the supplied `Read` contract and actual
counting-path controls, not a claimed successful fresh fetch.

## Historical A11-F2 review and integrity

Plan section 16 records the **supplied bounded independent source and
retained-evidence review** at the required baseline: implementation and
all 11 checksums checked; author's logs report 46 selected tests;
reviewer did not rerun them because Cargo was unavailable. No real
binary/runtime/deployment or broad lifecycle assurance follows.

`a11-baseline-checksums.log` is this author's additional check of those
11 entries on a `git archive` extraction of the exact baseline, all OK.
The baseline manifest also covers source and plan files which this task
intentionally updates. Verify the old manifest **at the old baseline**,
not against later source/plan bytes. Old retained files remain unchanged.

## Compatibility, limits and retained-file integrity

See [plan section 17](../../QBIND_AUDIT_REMEDIATION_PLAN.md#17-a5-f1--obl-avl-3a-bounded-receive-side-partial-frame-correction)
for the supplied review's limited scope and the author's separate
caller inventory. Zero-progress timeout kinds remain unchanged;
partial-frame failures now return fatal `Io(InvalidData)` with original
I/O error/byte-count details. Async readers and peer-manager filters no
longer retry these errors. The daemon ends the session; the client maps
partial response failure to SignerUnavailable/transport, not Timeout.
No public error variants/signatures changed. Send-once/no-re-encryption
and shared invalidation guarantees remain intact.

The local latch does not prove complete cleanup. Queue backpressure,
idle independent writers, existing mutex/timeouts/setup behavior, raw
socket access, task joining/cancellation, registry removal, OS shutdown/
delivery and owner/key cleanup remain outside the bounded result.
Already completed operations cannot be retracted. Tests do not establish
platform-wide timeout mappings, live-network behavior or production
authentication. No external peers, live DevNet, deployment, signing,
activation, PR, merge or main push.

`SHA256SUMS` covers the four producer source files, appended plan, this
README and all retained logs/producer record, with repository-relative
paths. It excludes itself. From the repository root run
`sha256sum -c docs/security/evidence/a5-f1-partial-read/SHA256SUMS`.
The final delivery tree supplies the manifest's own Git blob identity.

## Delivery whitespace observation

The initial evidence commit was
`abb545ffeca8126e945237ba709554c7554c51ed`, tree
`00dbdb03da3afd6448c25a8aace7328b14675bdd`, sole parent the implementation
producer. A subsequent full-delivery
`git diff --check 4629c8d14323afd86d45d2f6786f46db4f074a59 abb545ffeca8126e945237ba709554c7554c51ed`
exited **2**, flagging raw log whitespace (including original apt CR
line endings and a Cargo output blank line at EOF). The combined
verification output is retained as `delivery-whitespace-attempt.log`.
It had already verified all 18 manifest entries; the failed whitespace
check stopped that compound verification before its remote/worktree
checks. No source or prose formatting issue was reported.

Raw logs are deliberately not normalized, rewritten or hidden via a
repository attribute. The final source/document check excludes only
`docs/security/evidence/a5-f1-partial-read/*.log`; checksum verification
still covers every retained log. This later documentation-only record
does not change the test-producing source or reattribute any test
results. Remote equality, protected bytes and clean-worktree checks are
rerun separately at delivery.
