# A6-F1 / OBL-AVL-4a / E14 registered fatal-read cleanup

**IMPLEMENTED — INDEPENDENT REVIEW PENDING.** This evidence covers only
registered sessions whose read loop actually observes a terminal channel-read
or frame-decode failure. A6-F1 / OBL-AVL-4a / E14 and all other remaining
obligations remain **OPEN**. Activation remains **DISABLED**; public DevNet
remains **NO-GO**.

## Input, entry and pre-implementation review

Entry was `olivexo28/QBIND`, clean `main` at
`50bf93d8b1b6b0739cdce5e95334cd726af2386e`, tree
`dfe11db1e9b55de89df1a565b2df83cdba7d91c0`; local and `origin/main` matched.
The task branch `copilot/a6-f1-fatal-read-cleanup` was created from that
commit. The audit register remains unchanged.

The controlling audit input at entry was
`Audit/QBIND_SECURITY_FINDINGS_REGISTER.md`, Git blob
`cd81efdbaf2bfb45e00dc3c60db3ea4f523adfa0`, 5,509,470 bytes, SHA-256
`6e68d3d05964f9a6dc0384ffda2bb53d81d7da97ffb786ce84f4bd5a4360c0d9`.
Relevant exact audit anchors are A:L17267-L17269 (fatal worker delivery,
app read-loop exits, and registered cleanup); A:L17271-L17279 (A6-F1
eviction/trust-reload scope, required outcome, and E14 evidence requirements);
and A:L17282 (supersession and retained disposition). The coordination plan
at entry was blob `e7f3dbb91903e76cfe5daa147cc3a454279d795a`;
sections 18, 19, and 20 (then lines 3653, 3813, and 3956 onward) were read
in full. They require accurate outcome boundaries, preserved history, and
no claim that an abort request completes worker/socket cleanup.

The supplied independent pre-implementation source review is attributed to
**ChatGPT**, as reported in the task: at the expected main it inspected
`p2p_tcp.rs` and found that the read loop returns on observed receive or
frame-decode errors while active registry ownership retains retirement
handles. That supports the selected bounded correction. It was source
inspection, not runtime reproduction or review of the full audit register.
The implementer separately verified the relevant A6-F1 disposition and
sections 18-20 before changing code. No independent post-implementation
review is claimed.

## Correction and boundary

The read loop now records only terminal `recv` and frame-decode failures.
A tracked monitor task, owned by that session's retirement record, observes
the read-loop join without making the read loop join itself. Under the
registry write lock it moves the exact matching `Arc<PeerRetirement>` from
`active` to `retiring` and updates `connections_current`; outside that lock it
drops outbound senders and requests bounded cleanup. It removes the retiring
owner only after the join/worker cleanup succeeds. Timeout, cancellation, or
cleanup failure leaves the owner available for shutdown/replacement retry.
Replacement and late-failure races compare exact ownership, so an old session
cannot remove a newer one. Existing terminal shutdown fencing, one-connection
outbound behavior, eviction snapshot/report behavior, auth and crypto settings
are unchanged.

An idle healthy connection does not time out: zero-progress socket timeouts
remain retries. Existing A5-F1 partial-frame behavior and A11-F2
no-re-encryption/no-replay controls remain in the secure-channel suite.
Already-delivered messages and operations already progressed cannot be
retracted.

Fatal errors that are not yet observable because the secure-channel worker is
blocked delivering an error to its bounded queue, or because the P2P read loop
is blocked forwarding to a full downstream queue, remain a **separate
limitation**. A dedicated test confirms no removal is claimed while the
downstream consumer blocks; cleanup begins after the queue drains and the
terminal read is observed.

## Baseline reproduction

On an isolated detached worktree at the exact starting commit, a test-only
loopback control registered a session, dropped the peer, waited for the
registered read task to finish, then asserted that the old active entry and
count were still present. No production source was changed in that worktree.
The observed output was `Read error: ... UnexpectedEof`; the test passed with
active entry/count still `1`. This establishes the stale-entry behavior for
that local EOF schedule, not resource exhaustion or deployment impact.

Command:

```text
cargo test --manifest-path /tmp/qbind-a6-baseline/Cargo.toml --target-dir /workspaces/QBIND/olivexo28/QBIND/target --locked --offline -p qbind-node --lib baseline_observed_eof_leaves_registered_session_active -- --nocapture
```

Result: **1 passed, 0 failed**. Raw output is
`tests/baseline.log`, SHA-256
`281b4576cc3746a9a627031ecd7e48ab6818237f6dee8732deb78bbf99e33407`.
The isolated worktree was removed.

## Producing revision and verification

Final source/test producer: commit
`e53765832fadff1a1dff0188ac1268d572fddd1b`, tree
`d8ddef30300c9900ec756c4d6a507bb88c43d702`, parent
`23a9e7badce2bdbf8b3116485ece0767126a3e0a` (itself directly from the
starting commit). Source blobs are `p2p_tcp.rs` =
`43a50d2c163f9763d4f4762e485bc4c47658b4b8` and `secure_channel.rs` =
`c62fec8b37f96cfcfa1ac13645f0a57a1b84eff7`.

| Exact command | Result | Raw-output SHA-256 |
|---|---:|---|
| `cargo test --locked --offline -p qbind-node --lib p2p_tcp::peer_retirement_tests` | 29 passed, 0 failed | final: `e5a30f1f308173597db1531ca9a7f91186b8a27929f99ccf755d7c494e51d3a4`; initial passing run: `cf4617ccd12ae513fc4ad5d4d72ae8c55f7923895a563a0bb34953c6b113433c` |
| `cargo test --locked --offline -p qbind-node --lib secure_channel::` | 16 passed, 0 failed | `919a1a0a97f213f011254ccac80261795aa51a97edfb186011cc8aa3c63bf87e` |
| `cargo test --locked --offline -p qbind-node --test b8_listener_identity_closure_and_dial_retry_tests` | 6 passed, 0 failed | `db7413f4c7635d4c692f227b258a0e6b6180ba356dc20c8ff8be2862c36481de` |
| `cargo test --locked --offline -p qbind-node --test run_072_p2p_session_eviction_tests` | 8 passed, 0 failed | `0b982a2af873a63bf9b40d057ca4321cac0e8d77d71e8031d01c0272f59f1874` |
| `cargo test --locked --offline -p qbind-node --test run_074_pqc_trust_bundle_live_reload_tests` | 10 passed, 0 failed | `beee6cb65ce983857e5d8659624b465037fed2f718bb1f1157082b177dd14b89` |
| `cargo test --locked --offline -p qbind-node --test run_418_authenticated_peer_consensus_sender_binding_tests` | 18 passed, 0 failed | `7682ac39e666c55a8d16005f0ee8213ba3f99da07713da08a3f0a91f7e1bed38` |
| `cargo test --locked --offline -p qbind-node --test run_418_newview_demux_chain_integration_tests` | 4 passed, 0 failed | `a6b395d8312941c5bfb16eb69246998c714d2f76304afdc8f9734b3cb218304f` |
| `cargo check --locked --offline -p qbind-node --lib` | passed; existing warnings | `a5065703da94043e911c79acd75fed8b94a3d1c2257450da33a954ae23f3e846` |
| `rustfmt --edition 2021 --config skip_children=true --check crates/qbind-node/src/p2p_tcp.rs crates/qbind-node/src/secure_channel.rs` | passed | empty output, SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `git diff --check` (producer sources) | passed | empty output, SHA-256 `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |

The final lifecycle controls separately observe active count, read-loop join,
blocking-reader and blocking-writer outcomes, cleanup-owner retention, and
remote EOF on the decode-failure path. They include observed EOF and
frame-decode failure; healthy idle and unrelated-peer controls; old failure
versus replacement; fatal-read races with shutdown and eviction; retained
cleanup failure and retry; and queue-blocked detection remaining unclaimed.
The secure-channel tests exercise zero-progress idle timeout retry,
A5-F1 partial-read failure, and A11-F2 encrypted-write no-replay behavior.
These are author-run local tests, not independent review.

## Failed checks and evidence qualifications

The initial offline baseline build lacked cached `sha3`; retrying with Cargo
network resolution then failed because `bindgen` could not find `libclang.so`.
After installing `libclang-dev`, the offline build and all listed checks
completed. A first producer test compile caught a test-only mutability error;
it was corrected before the final 29-test run.

`cargo fmt --all -- --check` was also attempted and failed on existing
formatting differences outside this task, including `qbind-consensus` and
`peer_consensus_binding.rs`; changed source files pass the pinned targeted
rustfmt check. A full staged `git diff --check` reports trailing blank lines
at EOF in preserved raw Cargo logs. Those logs are intentionally kept
unmodified; the source-only whitespace check passes. The log files preserve
compiler warnings and command output, not deployment assurance.

## Remaining open scope

This correction does not establish full eviction completion or truthful
trust-reload success for every session, displaced-session reload cleanup,
OS-level socket reclamation, platform/runtime timing, resource-exhaustion
thresholds, or global admission bounds. It does not cover blocked queue
detection until the failure becomes observable. Existing eviction remains a
snapshot operation whose report does not certify task, worker, or socket
completion; the terminal shutdown fence remains terminal. No live network,
DevNet, deployment, operational signing, or activation was run. Broader E14,
A6-F1 / OBL-AVL-4a, and all other remaining obligations stay **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**.
