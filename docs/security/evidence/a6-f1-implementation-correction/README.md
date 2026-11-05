# A6-F1 bounded implementation-review correction

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** These are corrections to
implementation-review issues, not new canonical audit findings. A6-F1 /
OBL-AVL-4a and E14 remain **OPEN** to their remaining extent, as do
A5-F1 / E11, A11-F2 / E19, E07 and OBL-GOV-2. Activation **DISABLED**;
public DevNet **NO-GO**.

## Entry and immutable producer

Repository `olivexo28/QBIND`; existing branch
`copilot/audit-a6-f1-displaced-peer-cleanup`; clean starting checkout,
HEAD and advertised task tip `cbb774d438361f5787eced49b546cc886e90b59c`,
tree `50b951aa69df198323c1699539c2db0a8c949294`. Remote `main` was
`64ce7131340a861d8b33063f430dfc0beab531b3`. No applicable repository
`AGENTS.md` was found. No previous commit was overwritten.

Correction/test producer:
`e2e7bca7da935f1ecf46f83ba5abac2fc14857d3`, tree
`a4f87173d1e8da13e80fb1789cbc9fc767d419d6`, sole parent
`cbb774d438361f5787eced49b546cc886e90b59c`.
`producer.txt` records its exact identities, modes, blobs and toolchain.
Validation had no tracked source changes; the new correction evidence
directory was untracked and subsequently committed separately.

| Producer path | Mode | Blob |
|---|---|---|
| `crates/qbind-node/src/p2p_tcp.rs` | `100644` | `1546d018e8c5fd4fc94533ca22a10fd2453f73df` |
| `crates/qbind-node/src/secure_channel.rs` | `100755` | `f06a31986f01a8527a4f4af8fb5547d8cf150ff3` |
| `crates/qbind-node/src/secure_channel/encrypted_write_tests.rs` | `100644` | `0d7e0ee8032a280730ce0472cf7aa2f9c6dcee4b` |

[Peer ownership and tests](https://github.com/olivexo28/QBIND/blob/e2e7bca7da935f1ecf46f83ba5abac2fc14857d3/crates/qbind-node/src/p2p_tcp.rs),
[channel outcomes](https://github.com/olivexo28/QBIND/blob/e2e7bca7da935f1ecf46f83ba5abac2fc14857d3/crates/qbind-node/src/secure_channel.rs),
and [blocking-worker probes](https://github.com/olivexo28/QBIND/blob/e2e7bca7da935f1ecf46f83ba5abac2fc14857d3/crates/qbind-node/src/secure_channel/encrypted_write_tests.rs)
are pinned to that producer.

## Independent review and starting-revision reproduction

The supplied independent review inspected source and retained evidence,
but did not run Rust probes because Cargo was unavailable. Its three
issues are confirmed to their stated bounded mechanisms: join failures
could be lost across a later cancelled await, shutdown could drain away
ownership while registration published a new session, and unlocked
counter increments/resets could race registry changes. The original
4 + 15 + 8 + 10 author-run results remain valid for their tested
conditions; they did not exercise these schedules.

`baseline-probes.patch` adds only two deterministic test functions and a
test import to an isolated checkout of the required starting revision.
The production retirement functions are unchanged in that checkout.
The probes first retire real-AEAD loopback workers, replace their owned
join handles with controlled async/blocking tasks, force the first task
to panic, and keep the second pending while the finish future times out.
Both probes failed when retry returned `Ok(())` instead of preserving
the earlier panic. `baseline-outcome-reproduction.log` records **0
passed, 2 failed, exit 101** with the original panic and false-success
assertions. The first timeout variant fails before the cancellation
variant runs at this baseline; cancellation coverage is producer-side.

Exact baseline command (from the isolated starting checkout, with the
test-only patch applied):

```sh
CARGO_TARGET_DIR=/workspaces/QBIND/olivexo28/QBIND/target timeout 240s cargo test --locked --offline -p qbind-node --lib join_failure_survives -- --test-threads=1
```

The isolated worktree was removed after reproducing the bug. The patch
and raw log are retained here, not in the historical evidence directory.
Shutdown/count issues are recorded as source-review mechanisms with
producer-side barrier controls; no unrun baseline runtime reproduction
is claimed for those races. `precursor-compile-failure.log` retains a
pre-commit compilation failure (moved config and error formatting);
a subsequent guard-lifetime/`Send` compilation issue was also corrected
before producer validation. Neither is a final producer failure.

## Corrected contracts

**Observed outcomes:** both retirement functions persist each task's
completed/cancelled/failed join outcome before removing its handle and
before another await. A pending handle remains owned on timeout or
future cancellation. An observed panic stays visible on retry and
prevents successful replacement. An async-loop cancellation outcome is
accepted as observed termination for eviction compatibility, but is not
socket/worker completion. Cancellation of a blocking task is a cleanup
failure. No abort or timeout is silently counted as completed I/O.

**Terminal shutdown:** under the peer-registry lock, shutdown sets a
permanent registration fence, transfers active owners into `retiring`,
and updates the active-entry count to zero. It does not take retiring
owners out of the registry while waiting, nor reinsert them on failure.
Success removes only the identical `Arc` owner. Cleanup failure,
timeout, or cancellation leaves unfinished ownership intact.

Candidates waiting for admission have no application workers and have
an independently held socket-shutdown clone retained by their
registration reservation. Shutdown requests closure of these sockets;
reservations remain tracked until the registration future observes the
fence or is dropped. Worker construction and active publication occur
under one registry guard with no intervening await, so shutdown sees
either a reserved raw candidate or a fully owned active session.

Inbound and outbound established handshakes also retain their
independent socket clone and blocking join in the registry. Outbound
TCP connect uses Tokio's cancellable connect before starting the owned
blocking handshake; KEMTLS validation and verified-origin checks are
unchanged. The listener owns inbound async handlers in a `JoinSet`,
including handlers not yet polled, and aborts/observes them on shutdown.
Unfinished listener/dial handles and handshake workers remain owned
across interrupted shutdown attempts. A later shutdown retries cleanup,
but never reopens registration. **Restart requires a new service
instance**; this is an intentional compatibility change.

**Counter:** `connections_current` measures active registry entries,
not open sockets, authenticated consensus origins, pending handshakes,
reservations, or retiring sessions. Every active-map mutation and its
atomic count store happen under the same registry write lock. A count
read is an instantaneous snapshot, not a combined registry/metrics
transaction. Source search found this transport counter distinct from
`metrics::P2pMetrics`' similarly named gauge; no Prometheus wiring to
this transport counter is claimed.

**Eviction remains snapshot-based:** it does not set the terminal
fence. Only the snapshot's entries are evicted; later-admitted peers
remain active and contribute to the count. Existing report semantics
remain active-registry removal/async abort request, not verified socket
reclamation. Same-identity admission still waits for its specific
retiring owner; unrelated peers are unaffected.

## Producer-pinned verification

Each positive log records producer/tree, exact command, raw combined
output and exit status. All commands below exited **0**.

| Log / command | Result |
|---|---|
| `lifecycle.log`: `timeout 240s cargo test --locked --offline -p qbind-node --lib peer_retirement_tests -- --test-threads=1` | 15 passed, including all original 4 replacement controls |
| `secure-channel.log`: `timeout 240s cargo test --locked --offline -p qbind-node --lib secure_channel:: -- --test-threads=1` | 16 passed, including all original 15 A5-F1/A11-F2/capability controls |
| `compatibility.log`: `timeout 360s cargo test --locked --offline -p qbind-node --test run_072_p2p_session_eviction_tests --test run_074_pqc_trust_bundle_live_reload_tests --test b8_listener_identity_closure_and_dial_retry_tests --test run_418_authenticated_peer_consensus_sender_binding_tests -- --test-threads=1` | Run 072: 8; Run 074: 10; B8: 6; Run 418: 18 passed |
| `production-check.log`: `timeout 300s cargo check --locked --offline -p qbind-node --lib` | Passed with existing warnings |
| `format-whitespace.log`: `rustfmt --edition 2021 --check --config skip_children=true crates/qbind-node/src/p2p_tcp.rs crates/qbind-node/src/secure_channel.rs crates/qbind-node/src/secure_channel/encrypted_write_tests.rs` and `git diff --check cbb774d438361f5787eced49b546cc886e90b59c HEAD` | Passed at producer |

**73 selected tests passed**, no failures/ignored tests. This is author
execution, not independent post-correction acceptance. The new tests
cover timeout and dropped-future retries for failed peer/blocking joins,
replacement refusal after persisted failures, shutdown interrupted
during owned cleanup, reserved and already-published candidates,
successful inbound handshakes with old-session cleanup failure/retry,
blocked inbound handshake through the actual listener, cancelled
outbound handshake ownership, counter publication before a delayed
caller return, and admission after eviction's snapshot.

Scheduling barriers are private `cfg(test)` controls; forced panics
use owned test task handles, not production cryptographic failures.
Applicable channel/handshake traffic uses real ML-KEM-768 and
ChaCha20-Poly1305 over loopback, with a dummy certificate verifier and
synthetic routing identities. The raw blocked-handshake controls send
no valid handshake and establish ownership/EOF, not AEAD acceptance.
Already-progressed sends and already-forwarded application messages
cannot be retracted; no replay or acknowledgement was introduced.

## Integrity, residuals and gates

`integrity.log` verifies all **7 historical A6-F1 evidence files
byte-for-byte**, with SHA-256s, and the original plan bytes before this
append. `verify.py` checks the preserved plan prefix, old evidence,
producer blobs, logs and `SHA256SUMS`; run
`python3 docs/security/evidence/a6-f1-implementation-correction/verify.py`
from the repository root. `documentation-integrity.log` retains the
documentation checks. The full staged whitespace check exits **2**
because `baseline-probes.patch` lines 4 and 10 are unchanged blank
context lines represented by a single space. The patch is preserved
verbatim; source/prose-only staged checks pass. Raw failure logs remain
raw; source/prose whitespace checks are distinct from raw evidence.
No historical evidence, audit register, or preceding plan text changes.
The earlier A5-F1 bounded-review record still means 19 checksums
verified, 69 tests reported in author logs, no Rust rerun by the reviewer
because Cargo was unavailable, and its raw-log whitespace limitation
preserved.

Shutdown's unit return still cannot certify OS socket reclamation; it
logs incomplete cleanup and retains its owners. An observed panic or
permanent capability/worker failure may leave one identity blocked;
retry cannot erase it. Pending reservations can outlive a shutdown
return until their async futures resume or are dropped, but remain
tracked, socket-shutdown-requested and fenced from worker publication.
Global admission/resource caps, registered-session fatal-read cleanup,
full eviction/live trust-reload completion, non-loopback OS timing,
upper-layer delivery and deployment assurance remain outside this
bounded correction. No live DevNet, external peers, real signing,
deployment or activation was performed. **IMPLEMENTED — INDEPENDENT
REVIEW PENDING**; all listed obligations remain open and operational
gates remain unchanged.
