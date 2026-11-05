# A6-F1 monitor and retirement ownership correction

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** This evidence covers only the
monitor/task-ownership review correction on the existing
`copilot/a6-f1-fatal-read-cleanup` branch. A6-F1 / OBL-AVL-4a / E14 and all
other remaining obligations remain **OPEN**; activation **DISABLED**; public
DevNet **NO-GO**.

## Entry, inputs, and review limits

At entry, the task branch was clean at
`40938fb25b82823d699731a95d42f5d2b0931a5d`, tree
`9bf91ac24f75f64cd2add05f49bb7cc35c925fab`. Local and remote `main` both
matched the protected commit
`50bf93d8b1b6b0739cdce5e95334cd726af2386e`, tree
`dfe11db1e9b55de89df1a565b2df83cdba7d91c0`.

The controlling input remains
`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`, blob
`cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0`, SHA-256
`6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9`.
Applicable anchors remain A:L17267-L17269, A:L17271-L17279, and A:L17282.
The prior remediation-plan sections 18-21 and prior evidence were preserved;
the audit register is unchanged.

At the starting tip, `PeerRetirement::finish_and_wait` cleared its monitor
handle at `p2p_tcp.rs:430-436` before returning a `JoinError`, while
`monitor_peer_reader` removed the reader handle from shared ownership at
`p2p_tcp.rs:1822-1830` before awaiting it. This confirms the reported
ownership gap by source inspection. No separate monitor-cancellation
runtime reproduction was run on the starting revision. The earlier baseline
EOF reproduction in section 21 demonstrates the stale active-entry condition,
not this monitor cancellation finding.

The existing author logs under
`evidence/a6-f1-fatal-read-cleanup/tests/` are retained unchanged. Their
contents do not embed a producing commit identity; section 21 associates
them with the earlier source producer by repository history, not by an
identity in the logs. They are not represented here as newly rerun or
independently reviewed.

## Correction and ownership boundaries

The reader and writer `JoinHandle`s remain inside a shared
`Arc<Mutex<PeerLoopTasks>>`; the monitor awaits the reader through its stored
handle and does not `take()` it first. Cancellation or timeout drops only the
borrow/lock guard, leaving the handle in its owner. `finish` records observed
join outcomes before removing handles and refuses success if reader or writer
completion has no handle or recorded outcome. Monitor outcomes
(`Completed`, retryable `OperationFailed`, `Cancelled`, and `Failed`) are
recorded before the monitor handle is cleared and are not overwritten on
retry. Cleanup operation errors remain separately retryable; task and monitor
failures stay observable rather than being converted to success by losing
their handles.

`finish_and_wait` independently verifies cleanup before removing the exact
retiring owner. Active-to-retiring changes and connection-count updates stay
under the registry write lock; task joins and socket/worker cleanup occur
outside it. Replacement remains refused while cleanup is unresolved. The
terminal shutdown fence, identity-checked retirement, eviction snapshot
semantics, one-connection outbound correction, authentication and crypto
settings, A5-F1 partial-frame behavior, A11-F2 no-replay behavior, and
zero-progress idle timeout retry behavior are preserved.

Test-only controls pause the actual monitor after it reaches the reader join
and inject a panic after the reader join but before retirement publication.
These are deterministic **test injections**, not observed production
incidents. The EOF and frame-decode tests wait for autonomous registry
retirement and do not call `finish_and_wait` themselves. Other controls cover
repeated cleanup and refused replacement while a shutdown operation fails,
monitor panic racing replacement, shutdown and eviction races, queue-blocked
detection, healthy and unrelated peers, task/worker outcomes, and socket
closure.

### Service drop without shutdown

While waiting for the reader, the monitor strongly owns the shared task store
but holds only weak references to the registry and retirement record; this
avoids a persistent registry/retirement/monitor ownership cycle. Once a fatal
read is observed, it temporarily upgrades those weak references and bounds its
cleanup attempt by `PEER_RETIREMENT_TIMEOUT`. If the service is dropped before
shutdown completes, the registry and retirement owner can disappear while
the monitor is still waiting. Such a monitor cannot publish retirement or
join through a vanished owner. If the remote peer remains connected, the
reader/monitor may remain detached until the peer closes or the runtime ends.
The test drops the service without shutdown, verifies the registry and owner
are released, then closes the peer and verifies the task store is released.
It does **not** establish worker/socket reclamation when the peer remains
connected or prove OS-level cleanup. Callers must still complete shutdown
when cleanup assurance is required.

Fatal errors that are not observable because a secure-channel queue or
downstream consumer is blocked remain a separate limitation. Already
delivered messages and operations already progressed cannot be retracted.

## Producer and verification

Source/test producer: commit
`d62eecc306d545cfb945f640de0f727e2624f923`, tree
`134a661d1fc314bed6fdd417a427726875d95a01`, parent
`40938fb25b82823d699731a95d42f5d2b0931a5d`. The changed source blob is
`p2p_tcp.rs` =
`876c08fd34411e7c7d0a091a7c88bd4d6bed46a8`. The raw test logs do not
themselves embed that commit identity; this record pins the commands and
checksums to the producer by contemporaneous repository state.

| Exact command | Result | Raw-output SHA-256 |
|---|---:|---|
| `cargo test --locked --offline -p qbind-node --lib p2p_tcp::peer_retirement_tests -- --nocapture` | 32 passed, 0 failed | `c7522eb4da87e659793dee70749a2c2ba7062a15c333bd9b2a8d44f197d91330` |
| `cargo test --locked --offline -p qbind-node --lib secure_channel::` | 16 passed, 0 failed | `f83d1d6703b5dd91e5c3647ac70b0a794d19e0123a262378b97c4776ffbc69a6` |
| `cargo test --locked --offline -p qbind-node --test b8_listener_identity_closure_and_dial_retry_tests` | 6 passed, 0 failed | `80a138006d0c3ce377a9abde0eff96eb237c1bf45e2bb21e5b9ff9b17c755518` |
| `cargo test --locked --offline -p qbind-node --test run_072_p2p_session_eviction_tests` | 8 passed, 0 failed | `bbdfad4a1580b0fbd3ad2cc3aa65ae42942e47e3fd2be6f95892e1d5acf3f411` |
| `cargo test --locked --offline -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests` | 10 passed, 0 failed | `ed46fd863ac58fd920bbc6db2ca99cb1e034be4796aa25e1bb0930752f44c95a` |
| `cargo test --locked --offline -p qbind-node --test run_418_authenticated_peer_consensus_sender_binding_tests` | 18 passed, 0 failed | `0ef50b7e52486c2e3c551acf908fc99a4e6ada420562d8b4c57f4d17e6172876` |
| `cargo test --locked --offline -p qbind-node --test run_418_newview_demux_chain_integration_tests` | 4 passed, 0 failed | `dde80a4dcebf3914a6755094d212130c89e7934de79879ad946a6628e0d66145` |
| `cargo check --locked --offline -p qbind-node --lib` | passed with existing warnings | `5ec3fece6258e5b73d20d222b4308a1e4a739de2c9f85aeedd3297e3f7f07595` |

Targeted formatting passed:
`rustfmt --edition 2021 --config skip_children=true crates/qbind-node/src/p2p_tcp.rs --check`.
`git diff --check -- crates/qbind-node/src/p2p_tcp.rs` passed with empty
output (SHA-256 of empty output:
`e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`).
The staged `git diff --cached --check` reports one extra blank line at EOF
in each of seven raw Cargo test logs; these outputs are preserved byte-for-byte
for their recorded checksums. The source and prose whitespace checks pass.

An intermediate run of the lifecycle command reported 31 passed and one
failed: the new code initially treated an eviction-requested writer-task
cancellation as a loop failure. The cancellation outcome remains recorded,
but an observed, requested eviction cancellation is not misclassified as a
fatal loop failure; all task and channel-worker joins are still required.
The captured intermediate output is
`tests/peer-retirement-tests-intermediate-failure.log`, SHA-256
`8a0f1641419a886b48b30126f2e250bdf430f8a0d6080170a1a5abe3002e39c1`.
Final lifecycle output is separately retained and checksummed above.

These are author-run local tests, not independent review, runtime assurance,
or deployment evidence.

## Remaining open scope

Broader E14, complete eviction/trust-reload cleanup, cleanup of all displaced
sessions through every lifecycle route, blocked-queue detection before the
error becomes observable, OS-level socket reclamation, platform/runtime
assurance, and global admission/exhaustion bounds remain open. No live
network, deployment, operational signing, or activation was run. Independent
review remains **PENDING**; A6-F1 / OBL-AVL-4a / E14 and all other remaining
obligations remain **OPEN**; activation **DISABLED**; public DevNet **NO-GO**.
