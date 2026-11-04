# A6-F1 / OBL-AVL-4a bounded implementation evidence

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** A6-F1 / OBL-AVL-4a and
E14 remain **OPEN** to their remaining extent. A5-F1 / E11, A11-F2 /
E19, E07 and OBL-GOV-2 remain **OPEN** to their remaining extent.
Activation **DISABLED**; public DevNet **NO-GO**.

## Entry, scope and source review

Repository: `https://github.com/olivexo28/QBIND`.
Required baseline and `origin/main`: commit
`64ce7131340a861d8b33063f430dfc0beab531b3`, tree
`612512d8ac47bce6f587c028836b631d84da3275`. The checkout was clean,
no applicable `AGENTS.md` was found, and the task branch
`copilot/audit-a6-f1-displaced-peer-cleanup` did not exist before it was
created from the baseline.

The supplied independent review was checked against the baseline
registration, channel and caller paths. Replacement dropped the old
`NodeId` map entry without retaining it; dropping async task handles
detached their tasks. Blocking reader/writer workers had separate
ownership, and the socket mutex could be held by blocked I/O. The
independent shutdown capability therefore must not acquire that mutex,
and its successful call cannot stand in for observing either async-loop
or blocking-worker completion. Inbound registry identity and
authenticated consensus origin are distinct checks; neither identity
nor authentication/consensus-origin gates changed. No contradiction
with the supplied review was found. The supplied review did not
reproduce live resource exhaustion or establish a consensus effect.

## Producing revisions and source identity

Implementation commit `0bba1ebb4d73d52073c0891b97491d59874bc911`,
tree `ba2dd48e0d5ff01105ea2773097b70c9983a7865`, is a direct child of
the required baseline. Follow-up test commits
`731be6398dbc687bd421ac49b334bfca1a088655` (tree
`c310eae4a1fed6623468fad99fc95c5c7d54e741`) and
`b4020969dcc5c3fbeebed44a357163fed0baaf1b` (tree
`e10bcf27a37fbac86c8e310479880205ffb19e18`) are direct children in
that order. The final validation producer is the latter; its parent is
`731be6398dbc687bd421ac49b334bfca1a088655`. `producer.txt` records the
final producer/tree/parent. A subsequent documentation-only source
comment commit is `7f91712c5596bc846b6cf2299282e1cb9cad4d2c`, tree
`0c59e5269af3e31d8764998b1b161a7c3b5582ce`, parent
`b4020969dcc5c3fbeebed44a357163fed0baaf1b`; it changes no runtime
behavior or test outcome, so validation remains pinned to `b402096`.
The code/test producer changes these paths:

| Path | Producer blob | Commit-pinned source |
|---|---|---|
| `crates/qbind-node/src/p2p_tcp.rs` | `c13461e01238ec87a4156324e51c58c8efe9bd04` | [p2p_tcp.rs](https://github.com/olivexo28/QBIND/blob/731be6398dbc687bd421ac49b334bfca1a088655/crates/qbind-node/src/p2p_tcp.rs) |
| `crates/qbind-node/src/secure_channel.rs` | `59cf3769ed4c6e11462ec2da5dd92c03e12945bf` | [secure_channel.rs](https://github.com/olivexo28/QBIND/blob/b4020969dcc5c3fbeebed44a357163fed0baaf1b/crates/qbind-node/src/secure_channel.rs) |
| `crates/qbind-node/src/secure_channel/encrypted_write_tests.rs` | `3f9956f2a0f0a9184f6cdd883207711ffc1453ef` | [encrypted_write_tests.rs](https://github.com/olivexo28/QBIND/blob/b4020969dcc5c3fbeebed44a357163fed0baaf1b/crates/qbind-node/src/secure_channel/encrypted_write_tests.rs) |
| `crates/qbind-node/src/p2p_session_eviction.rs` | `b7d49cfa8ea5e32078e327bec739bdd1a278791d` | [p2p_session_eviction.rs](https://github.com/olivexo28/QBIND/blob/b4020969dcc5c3fbeebed44a357163fed0baaf1b/crates/qbind-node/src/p2p_session_eviction.rs) |

`peer_retirement.log`, `secure-channel-regressions.log`,
`eviction-trust-reload-regressions.log`, `production-check.log` and
`formatting-whitespace.log` each record the exact command, final
producer ID, raw combined output and exit status. `producer.txt` records
the immutable producer identity. Their SHA-256 checksums:

| Evidence file | SHA-256 |
|---|---|
| `producer.txt` | `349e4f990a21deb7fcfd46c3b4b18b59e7bf62a14302b18e3be5cd22f85d25d2` |
| `peer-retirement.log` | `925ae8a27490c2bf0d739426663f7137e342e42aed220cc89bb6123f6fdb4aa7` |
| `secure-channel-regressions.log` | `29bc98e4f53a7f731569c99ece6acab81126a3e8de1901e701acb0ca663e9190` |
| `eviction-trust-reload-regressions.log` | `494d7b5d3056e096abe51f1c98e20e1c8269ff33e65a3803b5ab03027e4374d3` |
| `production-check.log` | `3d5b3a83be0e86906deabf60aab83ab4e252a7e1fbf5aa987bb6562b1461eb68` |
| `formatting-whitespace.log` | `7e61be703a9e70c9f02f473d645c42e04b1ab68a5e35f4cbfae9a612c1626fbb` |

## Ownership contract and observed behavior

Every active peer has a session-specific retirement owner retaining the
guarded channel, async peer-loop join handles, blocking-worker join
handles, and an independent `TcpStream` clone for shutdown. The
registry tracks active, retiring and registering entries by exact
`NodeId`; concurrent same-identity registrations are refused while the
reservation is held, and only one cleanup owner can remain for one
identity. The new session's insertion in the active registry is the
linearization point, after old-session shutdown and loop/worker
completion are observed. Waits happen outside the registry lock.

Retirement invalidates application sends/receives and signals both
loops, calls `Shutdown::Both` through the independent handle, then joins
async loops and blocking workers. A five-second watchdog bounds each
attempt. Shutdown, abort, task completion, blocking-worker completion
and owner/socket-handle drop remain distinct. If the socket capability
cannot be created, the channel is refused before workers start. If
shutdown fails, replacement returns an error and the old owner stays in
the retiring map; repeated candidates cannot allocate new channel
workers for that identity. A later retry can finish it; a permanent
failure keeps that one owner and blocks the identity.

| Focused control | Actual observation |
|---|---|
| `replacement_retires_only_displaced_session_and_preserves_new_and_other_peers` | Idle displaced peer observed EOF; a send completed before replacement and was received; post-replacement sender clones refuse; the distinct peer and replacement each deliver a real-AEAD heartbeat; late completion through the old owner leaves the replacement session ID intact. |
| `active_read_and_queued_inbound_work_are_interrupted_without_replay` | Inbound queue backpressure leaves read work in flight; outbound sends are queued while the read side is blocked; replacement terminates the old read and writer paths, observes old-peer EOF, refuses later cloned sends, and drops the last registry-owned retirement owner. Progressed outbound frames may arrive before EOF; queued work is not replayed. |
| `concurrent_replacement_is_refused_while_owned_cleanup_is_in_progress` | A held task-join lock deterministically keeps the first registration in progress; the second candidate is refused; after the first succeeds, a late completion from the old owner cannot change the active session. |
| `failed_shutdown_remains_tracked_and_blocks_replacement_until_retry_succeeds` | Injected shutdown failure returns refusal, leaves exactly one old owner in `retiring`, preserves a distinct peer, and refuses repeated candidates; a later successful retry cleans up before replacement. |
| `async_wrapper_refuses_when_shutdown_capability_creation_fails` | Injected independent-handle creation failure returns an error before worker spawn; the peer observes local channel drop as EOF. |
| `shared_async_wrapper_fails_closed_without_shutdown_capability` | The legacy infallible shared constructor returns a non-established wrapper with no workers; sends refuse, retirement surfaces the missing capability, and dropping the wrapper releases its owned channel. |

These are deterministic local loopback controls. The pair fixture uses
real ML-KEM-768 and real ChaCha20-Poly1305 for session traffic, but its
certificate-signature verifier is a test-only dummy. Registry tests use
synthetic `NodeId`s and `None` consensus origins; they do not simulate
production identity authentication. No replay or delivery acknowledgement
is added. An already-progressed send, encrypted nonce, or message already
forwarded to application code cannot be retracted.

## Validation results

At the final producer:

| Exact command | Result |
|---|---|
| `timeout 180s cargo test --locked --offline -p qbind-node --lib peer_retirement_tests -- --test-threads=1` | 4 passed, 0 failed |
| `timeout 240s cargo test --locked --offline -p qbind-node --lib secure_channel:: -- --test-threads=1` | 15 passed, 0 failed; includes the existing A5-F1 receive and A11-F2 encrypted-write controls |
| `timeout 300s cargo test --locked --offline -p qbind-node --test run_072_p2p_session_eviction_tests --test run_074_pqc_trust_bundle_live_reload_tests -- --test-threads=1` | Run 072: 8 passed; Run 074: 10 passed |
| `timeout 300s cargo check --locked --offline -p qbind-node --lib` | Passed with existing compiler warnings |
| `rustfmt --edition 2021 --check --config skip_children=true crates/qbind-node/src/secure_channel.rs crates/qbind-node/src/secure_channel/encrypted_write_tests.rs crates/qbind-node/src/p2p_tcp.rs` plus `git -c core.whitespace=cr-at-eol diff --check 64ce7131340a861d8b33063f430dfc0beab531b3 HEAD` | Passed |

The test fixtures and controls do not establish platform-wide shutdown
timing, OS-wide reclamation, registered-session fatal-read cleanup,
eviction cleanup absent a later replacement/shutdown, live trust-reload
cleanup, full-workspace assurance or deployment behavior. Run 072/074
preserve their report/controller results but are not evidence that the
retained blocking workers or sockets were cleaned up by the synchronous
eviction call. E14 remains open.

### Preparation failures and historical A5-F1 record

During implementation, an initial test build found a missing field in a
test-only struct literal; the first filtered run executed zero tests
because the test module had been placed inside a function; and an early
replacement test exposed non-idempotent repeated shutdown returning
`NotConnected`. Each was corrected before the final producer and the
final focused tests pass. An initial generic whitespace check also
treated existing CRLF source lines as trailing whitespace; the retained
final check uses `core.whitespace=cr-at-eol`. These failures are not
hidden or represented as producer results.

The previous bounded A5-F1 review independently verified **19
checksums** and reported **69 selected tests in the author's logs**. The
reviewer did **not** rerun Rust tests because Cargo was unavailable.
That review is distinct from this task's author-run tests. The documented
A5-F1 raw-log whitespace limitation remains: an earlier full-delivery
`git diff --check` failed on preserved raw logs (including apt CR line
endings and Cargo's blank output line); see the section 17 record and
[`../a5-f1-partial-read/README.md`](../a5-f1-partial-read/README.md).

## Remaining scope and gates

The registry handoff does not resolve registered-session read-failure,
eviction or trust-reload cleanup in full. A permanent capability or
worker failure leaves the bounded per-identity owner retained and
refuses further replacement; retry and service shutdown are the only
implemented recovery opportunities. Sender clones cannot progress
through the retired writer loop, but in-flight operations may already
have progressed and are not retractable. No live DevNet, external peer,
real signing, deployment or activation was run. The audit register was
not changed. A6-F1 / OBL-AVL-4a and E14 remain open; A5-F1 / E11,
A11-F2 / E19, E07 and OBL-GOV-2 remain open to their remaining extent.
Activation remains **DISABLED**; public DevNet remains **NO-GO**.
