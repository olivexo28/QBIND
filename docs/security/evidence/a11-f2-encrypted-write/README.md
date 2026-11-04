# A11-F2 / OBL-TRN-3 author evidence

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** A11-F2 / OBL-TRN-3 and E19
remain **OPEN** pending independent review and their remaining obligations.
E07 / OBL-GOV-2 remain **OPEN** to their remaining extent. Activation is
**DISABLED**; public DevNet is **NO-GO**.

## Revision identity and scope

| Identity | Exact value |
|---|---|
| Repository | `https://github.com/olivexo28/QBIND` |
| Required baseline / implementation parent | `cb03d25e9c4c06046ff95eda70c089e94cea7577` |
| Required baseline tree | `eace7e8db1374b2f4a37bca6af8ec3d210af6856` |
| Implementation/test producing commit | `5815346afcdd70323dad2bae1d01bf46c132cf81` |
| Implementation/test producing tree | `861a94a19c218b66e30f1a5b8bf0e8ba2a4844ca` |
| Task branch | `copilot/audit-a11-f2-encrypted-write-retry` |
| Production source Git blob | `7dd0b3969ef5e712429e2b6a37e66f9dca5742b5` |
| Focused test Git blob | `d8b33faa6116ae46aa9c200de3d66f08f790d9dd` |

The implementation commit has exactly two changed paths:

* [Production source at the producing revision](https://github.com/olivexo28/QBIND/blob/5815346afcdd70323dad2bae1d01bf46c132cf81/crates/qbind-node/src/secure_channel.rs):
  session latch/constructor initialization at lines 221-250;
  guarded send, shutdown, receive and status at lines 425-490;
  async shared latch, worker single-send, application guards and status at
  lines 637-960.
* [Focused real-AEAD tests at the producing revision](https://github.com/olivexo28/QBIND/blob/5815346afcdd70323dad2bae1d01bf46c132cf81/crates/qbind-node/src/secure_channel/encrypted_write_tests.rs):
  counted real AEAD at lines 15-63; loopback handshake fixture at lines
  81-150; controlled write/flush/shutdown seam at lines 155-226; seven
  tests at lines 244-475.

These are author-generated results, not independent review evidence.
The clean producing checkout was recorded before running the commands;
all retained runs used that implementation commit with unchanged tracked
files. Logs were generated outside the repository and copied here after
the runs. This README, logs, checksum manifest and appended plan section
are later evidence/documentation, **not** files present in the producing
tree. They do not claim their own containing commit as the test producer.
The final evidence commit/tree/parent and all delivery blob identities
are reported separately at delivery, avoiding self-referential identities.

See [remediation plan section 15](../../QBIND_AUDIT_REMEDIATION_PLAN.md#15-a11-f2--obl-trn-3-bounded-encrypted-send-correction)
for the exact source-review scope, compatibility impacts and lifecycle
residuals. Earlier audit register rows and evidence were preserved.

## Commands and raw retained results

`producer.txt` records the UTC observation, commit/tree/parent, empty
initial worktree status, source/test blob identities, toolchain, kernel,
origin and remote-main advertisement. The task branch did not yet exist
remotely at this producing observation; its final publication/equality
check is a separate delivery observation.

Each `.log` contains the exact command, producing revision, combined raw
stdout/stderr (including warnings), and actual exit status. `timeout 180s`
is an outer test/build watchdog, not a transport timeout claim. Commands
ran from the repository root with default features.

| Log | Actual command | Result |
|---|---|---|
| `focused.log` | `timeout 180s cargo test --locked --offline -p qbind-node --lib secure_channel::encrypted_write_tests -- --test-threads=1` | 7 passed; 0 failed; 2172 unrelated tests filtered out |
| `node-regressions.log` | `timeout 180s cargo test --locked --offline -p qbind-node --test secure_channel_smoke_tests --test secure_channel_async_refactor_tests --test t139_real_pqc_kemtls_two_node_tests -- --test-threads=1` | 3 async-refactor, 2 smoke, 8 real-PQC transport tests passed; 0 failed |
| `framing-regressions.log` | `timeout 180s cargo test --locked --offline -p qbind-net --test framed_io_tests --test full_channel_roundtrip_tests -- --test-threads=1` | 22 framing and 4 roundtrip tests passed; 0 failed |
| `production-check.log` | `timeout 180s cargo check --locked --offline -p qbind-node -p qbind-remote-signer --lib --bins` | Passed, default production source with no test seam |
| `formatting.log` | `rustfmt --edition 2021 --check --config skip_children=true crates/qbind-node/src/secure_channel.rs crates/qbind-node/src/secure_channel/encrypted_write_tests.rs` | Passed |
| `whitespace.log` | `git diff --check cb03d25e9c4c06046ff95eda70c089e94cea7577 HEAD` | Passed at implementation HEAD |

All six commands exited **0**. Total: **46 selected Rust tests passed**.
No tests were ignored in these selections. Existing unrelated compiler
warnings are retained, not represented as a warning-free build. This is
not a full-workspace test run, release-artifact validation or deployment.

Preparation before the producing commit: the initial test build failed
because bindgen could not find `libclang.so`; no tests ran in that attempt.
`libclang-dev` was installed after that missing-dependency failure, then
development tests/builds passed. Apt reported an unrelated Chrome-index
DNS warning; the needed package installed successfully. Dependencies were
downloaded during preparation; the revision-pinned Cargo commands above
all used `--locked --offline`. No dependency manifests or lockfile were
changed. This environment repair is not a correction to repository code.

## What the seven focused tests establish

| Test | Bounded observation |
|---|---|
| `real_aead_full_send_receive_both_directions` | Actual KEMTLS constructors, real ML-KEM-768 and real ChaCha20-Poly1305; two full messages/decryptions in each direction; c2s/s2c counter 0 then 1 |
| `sync_zero_partial_flush_and_shutdown_failures_both_directions` | Both directions: zero-byte WouldBlock, seven bytes then WouldBlock/broken-pipe, write-zero, full ciphertext then timeout/other flush failure; original error, one seal, subsequent send/receive refusal and owned-wrapper refusal; shutdown attempt counted; successful local shutdown yields EOF after incomplete output |
| `encryption_error_also_latches_before_any_write` | Counter/seal attempt then injected encryption error; zero writes, one shutdown attempt, permanent application refusal even when shutdown is injected to fail |
| `production_workers_propagate_error_drop_queued_send_and_terminate_reader` | Actual writer executes once, returns original error and drops second queued completion without encryption; actual reader observes the latch, reports fatal refusal and exits with notification-queue capacity available; both directions, including shutdown failure |
| `async_clones_and_independent_shared_workers_refuse_failed_session` | Actual spawned workers, async failure propagation, cloned and independently constructed shared wrappers (including one constructed after failure), synchronous shared handle all refuse; both directions |
| `owned_async_worker_returns_original_error_and_clone_refuses` | Owned `try_new` route, actual spawned writer, zero-byte WouldBlock returned instead of replay; clone refuses subsequent application use |
| `queued_plaintext_is_not_released_after_invalidation` | Real decrypted plaintext queued behind the async receive mutex; receive polled pending before invalidation, then resumed after invalidation; both pending receive and fresh receive reject the buffered plaintext |

The counted AEAD delegates to the real ChaCha20-Poly1305 implementation;
it is not dummy encryption. The injected seal-error control performs the
real seal and then returns an error. Certificate signature verification
is a dummy fixture; mutual auth is disabled in this fixture only. Tests
are not evidence of production certificate admission. The existing
framing/roundtrip dummy-crypto controls are distinct from the focused
real-AEAD suite and the existing real-PQC transport regression suite.

The write seam wraps a real loopback socket and passes controlled
prefixes through the same production `write_transport_frame`. With a
seven-byte limit it passes seven actual frame bytes, then injects the
selected error. Flush controls pass all ciphertext then inject failure:
the peer successfully decrypts it, yet the sender still receives failure.
No test assumes WouldBlock proves zero progress. The shutdown-failure
seam refuses OS shutdown and leaves the socket live; the peer can send a
valid real-AEAD message, but the invalidated local receive never reaches
decryption. No test-only fault path exists in a production build.

## Limits and retained-file integrity

The guarantee is a monotonic local application-session refusal after a
send error, before any subsequent encryption/read on that session. It is
not message delivery acknowledgement, automatic reconnect/replay, or
complete socket/reader/task/registry cleanup. In-flight operations which
linearized before invalidation and higher-layer deliveries already
completed cannot be retracted. Raw socket access remains outside guarded
application APIs. Reader queue backpressure, a reader holding the shared
mutex, idle independent shared writers, task joining, registry removal,
receive-side partial-read retry, OS shutdown/delivery behavior and
platform-wide timing remain separate limitations described in the plan.
A send error is returned by the synchronous/async channel send API;
higher-layer enqueue-only/best-effort peer APIs retain their existing
semantics, not delivery acknowledgement or retroactive enqueue failure.
A reader termination test with room in its queue is not proof of
termination under arbitrary backpressure.

No live DevNet, external peers, real multi-node deployment, signing,
activation or network-wide outcome was exercised. A11-F1 is not fixed.
Independent post-implementation review is **PENDING**.

`SHA256SUMS` covers the source, tests, appended plan, this README and every
raw evidence log/producer record, using repository-relative paths.
The manifest excludes itself to avoid self-reference. Verify from the
repository root with `sha256sum -c
docs/security/evidence/a11-f2-encrypted-write/SHA256SUMS`. The final
delivery Git tree supplies the manifest's own blob identity.
