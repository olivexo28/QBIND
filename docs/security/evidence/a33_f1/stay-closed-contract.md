# A33-F1 / E27 stay-closed catch-up quarantine: pre-implementation contract

**DESIGN ONLY — INDEPENDENT REVIEW PENDING.** This is a proposed implementation boundary, not code, production authorization, or evidence of durability. It supplements the existing A33-F1 / A17-F1 records and the v3 quarantine proposal. The task branch still contains the earlier unmerged eviction-walk implementation. A33-F1 / E27 and all other unresolved obligations remain **OPEN**; activation is **DISABLED** and public DevNet is **NO-GO**.

## Authority, source and scope

The project owner authorized preparation of a stay-closed contract with a dedicated synced marker, an early startup refusal, and explicit in-flight ownership and unknown outcomes. The approved direction refuses catch-up replacement of an existing ID until separately reviewed, refuses a new item when a safe slot cannot be obtained, and does not resume participation while partial effects are unresolved. This direction is not approval of a storage backend, currentness authority, reconciliation procedure, implementation or activation.

Repository `olivexo28/QBIND`; entry branch `copilot/a33-f1-bounded-eviction` at `c07099b229563e7acd8a6253e3e6d28b309261d0`, tree `30fcd8b2fe1e25f2576b11fd6b17da2692544b33`. GitHub main was `c9aaef40b045e896ddfa8b01bad230f6b680715e`. The independent source-level feasibility inspection was against main; this branch's earlier consensus changes are not on main. GitHub refs were read remotely; a remote branch has no inspectable local worktree, so no local worktree state is asserted.

Relevant source anchors, pinned to main:

* `crates/qbind-node/src/binary_consensus_loop.rs:8437-8534`: the response handler directly applies catch-up. An error may follow earlier effects; its existing no-mutation comment is not a valid response-level guarantee.
* `crates/qbind-node/src/binary_consensus_loop.rs:350-390,3109-3195`: consensus storage is optional, and the loop dispatches engine work and subsequent effects. The catch-up handler currently has no dedicated marker argument.
* `crates/qbind-node/src/storage.rs:142-242,1042-1080`: existing synced epoch/WAL operations are epoch-scoped precedents, not a catch-up marker interface. The in-memory backend is non-durable.
* `crates/qbind-node/src/restore_completion.rs:23-33,581-710`: restore publication has a specified file/rename/directory-sync profile and stage-aware failures; it is not a catch-up record or proof of this contract.
* `crates/qbind-node/src/main.rs:2492-2527,5003,5039-5043,5150-5168,5420-5446,8101-8110`: the destination lock precedes the optional metrics server, whereas the ordinary restore guard and ordinary consensus-store open occur after metrics spawn. P2P signer preflight precedes `builder.build()`. These are candidate ordering landmarks, not proof that all CLI/startup paths are covered.
* `crates/qbind-node/src/signing_reservation_journal.rs:1-25` and `binary_consensus_loop.rs:3130-3146`: the Proposal/Vote journal disclaims anti-rollback and is not wired into the production loop; Timeout is a separate signing surface.
* `crates/qbind-node/src/consensus_net_p2p.rs:298-365` and `p2p_tcp.rs:2988-3010`: facade calls and `try_send` do not establish peer delivery or a complete drain.

The audit register remains authoritative and unchanged. Source inspection does not establish configured binary behavior, process-crash safety, OS/device power-loss behavior, authenticated catch-up or live-network effects.

## Safety invariant and allowed scope

In the intended participating-node scope, a catch-up item must not produce engine, signing, or externally visible consensus effects, or related storage effects other than the required intent and guard records, unless (1) the applicable operation barrier has prevented new conflicting admissions and accounted for previously admitted work, and (2) a dedicated `Applying` intent has been durably acknowledged under the selected, validated storage profile. An unresolved intent, uncertain mutation, interrupted operation, or unverified startup state keeps participation refused. A later acknowledgement, restart, timeout or local checksum alone cannot clear this state.

This first slice has **no automatic clear or resume**. A complete catch-up response is not, by itself, a durable complete safety checkpoint. If a pre-mutation no-effect result is provable, its effect on future eligibility still requires a separately reviewed clear transition. The conservative implementation may therefore sacrifice liveness and leave a node stopped indefinitely. No previously committed prefix is rolled back by assertion; work already progressed or delivered cannot be recalled.

No rule here makes the configured block limit global: it addresses the catch-up path only. Existing-ID refusal and new-ID capacity decisions remain subject to exclusive engine ownership, checked arithmetic, non-mutating classification and the separate A17-F1 authentication boundary. Do not enable catch-up or use logical QC validation as signature authentication.

## Dedicated synced marker interface: required contract

The actual API and backend are unresolved. Any implementation must expose a **dedicated, versioned catch-up quarantine namespace** and typed results. It must not repurpose `meta:current_epoch`, the epoch-transition marker, the snapshot restore-transaction record, or a generic `flush_epoch_durable` call as evidence that a different record is durable.

The minimum abstract operations are:

1. **Read and classify:** distinguish a valid supported record, absent record, corrupt/truncated/foreign record, unsupported version and I/O failure. Every non-proven state must refuse participating startup. Preserve diagnostic evidence; do not silently recreate, delete or downgrade it.
2. **Synchronously publish intent:** serialize and persist an `Applying` record before the first possible catch-up mutation. Bind an exact store/chain identity and transaction generation, starting anchor/view/lock and response identity to the extent the separately reviewed schema permits. A checksum is corruption detection, not authenticity, freshness or exclusive signer ownership.
3. **Record outcome and uncertainty:** persist completed-prefix/current-item effect status and independently observed in-flight domains; a failed or uncertain write/sync leaves the transaction unresolved. A durable record of intent does not make volatile engine changes durable.
4. **Startup inspection:** read the same authoritative record before the participating startup gate opens. Missing, foreign, incomplete, corrupt, unsupported or unreadable state must not be treated as clean. Fresh-store initialization and legacy migration require a separately reviewed baseline procedure; absence is not proof of freshness.

The implementation must specify atomicity, concurrent-writer serialization, exact write/flush ordering, and whether a failed operation might nevertheless have published bytes. Each backend must declare its real guarantees; no default may turn an unsynced or in-memory write into a claimed durable success. `--data-dir` absent, no consensus-store handle, read-only storage, unavailable sync, or an unsupported platform must refuse affected catch-up and participating startup; do not fall back to a volatile flag or silently create a clean history. Administrative/read-only CLI exceptions, if any, require an explicit separately reviewed command classification and must not start the node, mutate guarded state or sign.

The durability claim must name the WAL/filesystem/device and crash model. Process-kill tests, mocked failures and a successful API call do not establish power-loss durability; independently authorized storage and crash evidence is required. A stale but internally consistent copy can roll back both record and state; no local-only marker proves currentness or fences a second signer.

## Startup refusal: required ordering

For every participating ordinary and restore startup, determine the data-directory/store identity without opening listeners, initializing an operational signer or running consensus, acquire the applicable destination ownership, then classify the dedicated marker. Refuse before starting the optional metrics HTTP server **when it is enabled**, before P2P construction/listen/dial, signer loading or preflight, consensus engine/task/timers, snapshotter and other stateful node services. A diagnostic output that does not open a network endpoint may be permitted only by an explicit command matrix.

The current ordinary restore guard at `main.rs:5039` is too late to serve unchanged as the proposed before-networking gate: metrics is spawned at `:5003`, and requested restore has an earlier materialization path. The destination-lock area is a possible insertion landmark, not an approved implementation location. Inspect all exits and side effects before choosing it, including `identity`, genesis/validation-only commands, requested restore, LocalMesh, P2P, optional metrics, and storage-opening CLI modes. Do not assume that every CLI is a participating node or that an existing CLI is automatically safe to exempt. If relevant ordering cannot be proved, refuse that participating path.

Opening storage may itself create paths or initialize schema; distinguish read-existing classification from fresh creation. If early marker inspection requires opening RocksDB, avoid double opens/locks and prove the same checked handle and identity are carried to the mutation path. Do not let existing restore locks imply cross-copy signer fencing. Establish the gate before the signer, network and consensus surfaces are initialized; any narrower exception must be explicit and separately reviewed.

## Barrier and in-flight ownership

The binary loop's mutable engine ownership provides a serialization point for that loop only; it is not a process-wide fence for asynchronous network workers, signing backends, snapshots or storage callbacks. The design must inventory every participating producer and give each admitted operation an owner, admission point and completion observation. Close admission and establish an exclusive catch-up barrier before the first mutation; ensure the durable intent has been acknowledged before allowing that mutation. Specify ordering for operations admitted before the barrier, including callbacks that may produce new work. No registry lock or other global lock may be held across unbounded worker joins.

Track at least: signer request admission, reservation, key invocation, signer completion and durable journal result; storage submission, completion and sync acknowledgement; engine callbacks and snapshot/reconfiguration effects; serialization, enqueue, transport worker completion and any available delivery acknowledgement. A cancellation request or timeout is not completion. A result already accepted by a signer or enqueued/sent may still take effect; preserve its exact known outcome or `Unknown`. A facade `Ok` or absence of a log cannot prove delivery or non-delivery. Failure to observe, drain, fence or durably record any required domain keeps the node quarantined; no timeout, local flag or operator acknowledgement turns `Unknown` into no effect.

The no-effect claim is per domain: current engine item, completed response prefix, signer/reservation, durable storage, outbound/network, and other callbacks/snapshots. The intent record itself is a durable effect even if engine admission is refused. Avoid a single blanket `no mutation` result. The contract does not require an impossible network delivery proof when none exists: it requires reporting uncertainty and withholding clear/resume.

## Review and verification matrix — proposed, not executed

| Boundary | Required evidence before a bounded implementation may be accepted |
|---|---|
| Marker write | Controlled write, sync, readback and error-stage tests; failure before/after publication; absent storage/data-dir; unsupported backend. Verify no catch-up mutation on a failed or uncertain pre-intent operation. |
| Crash ordering | Inject failure before intent, after intent, around each eviction/insertion/vote/QC/lock/commit, outcome and any clear. Startup must refuse when effects are uncertain. Child-process crash and power-loss tests require separately scoped authorization and a pinned durability profile. |
| Startup paths | Actual binary-path ordering controls for ordinary/restore, LocalMesh/P2P, enabled/disabled metrics and relevant CLI modes. Assert refusal before the first configured listener, signer preflight and consensus/snapshot task; include missing/corrupt/foreign marker and absent store. |
| In-flight work | Barrier-controlled fake signer, reservation, storage and outbound workers at each admission/completion boundary. Assert no new work crosses the gate; retain observed results or `Unknown`; timeout/abort is not completion. |
| Retained copy | Restore a synthetic older but internally valid marker and state; model two copies of one signer. No local checksum or lockfile may authorize either copy to resume. Any real signer, external authority or operational data requires separate authorization. |
| Engine compatibility | Existing-ID refusal; new-ID pressure below/at/above max and zero; valid acyclic eviction; cycle/missing ancestry; exact partial-prefix/current-item and evidence accounting. Preserve prior A33-F1 witnesses and the other open findings. |

## Implementation blockers and handoff

Before implementation, resolve and independently review marker format and store identity, migration/fresh-store classification, durability profile and error semantics, startup/CLI coverage, the all-producer operation barrier and completion interfaces, and exact effect-report representation. Before *clearing* quarantine, separately decide and verify trusted currentness, rollback/copy handling, exclusive signing, reconciliation/clear authority and safety-state continuity. These latter authorities are not selected by this stay-closed design. If a safe barrier, durable ordering or startup refusal cannot be established for a path, that path remains refused; do not report a partial prototype as complete node enforcement.

No tests, builds, live nodes, process-crash experiments, operational signing or deployment were run for this documentation task. Prior author evidence and its limitations remain unchanged. Independent pre-implementation contract review and all operational gates remain pending.
