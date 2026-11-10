# Cursor non-entanglement source/use-path audit and finality/input handoff

## Status and provenance

**DOCUMENTATION ONLY — INDEPENDENT REVIEW REQUIRED.** This is a pinned-source
audit and candidate specification. It authorizes no implementation, migration,
experiment, startup, integration, signing, recovery, activation or DevNet
action. The candidate execution cursor is not implemented in the reviewed
source endpoint.

**OWNER DECISION (already approved for specification only):** a distinct
execution-applied cursor identifies the exact finalized input prefix applied
to account state and must commit atomically with required state and
completion. It is not finality proof, an anti-rollback anchor, or authority
for consensus, signing, recovery or activation. Consensus safety state and
the signing-reservation journal remain under their existing authority.
Whether consensus may advance while execution is behind and any lag policy
remain OPEN. This document does not ask the owner to approve the distinct
cursor direction again.

**Pinned refs verified before this work:** `main`
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`; reviewed branch
`docs/distinct-execution-cursor-handoff` at
`b559658a0042d4b495ad8c22fb50f08ef9dd7223`, tree
`9377587a80ee87b33ac74a4cc4d9032661180556`, parent
`2211d0f67f682ac11189995d9839b040128ba506`. Reviewed cursor specification:
`docs/security/evidence/distinct-execution-cursor-finality-handoff-nonentanglement-20261110.md`,
blob `dd42b95cf0ef4403088e4e4f17ac79d801996e68`.

Use the labels precisely:

- **SOURCE FACT**: behavior or interface directly observed in that pinned
  source, including its scope and route.
- **OWNER DECISION**: the decision above; it is not implementation evidence.
- **CANDIDATE REQUIREMENT**: behavior a future reviewed design must enforce.
- **OPEN / BLOCKED**: evidence, authority or policy is missing. A design
  constraint is not proof of implementation.

All proposed tests, builds, runtime traces and other validation are
**FUTURE / NOT AUTHORIZED / NOT EXECUTED**.

## 1. Source/use-path inventory

### Execution-side progress candidates

| Source and route | Observed producer → representation → consumer | Scope and limits |
|---|---|---|
| `crates/qbind-node/src/execution_adapter.rs:169-203,230-242,295-366` | `QbindBlock::new` takes `view` from `proposal.header.height`; its `block_id` is the proposal's `payload_hash`. The synchronous `InMemoryExecutionAdapter` has a `current_height` field, starts it at zero, and updates it only after successful per-transaction execution. `ExecutionAdapter::current_height()` exposes that non-durable value. | This is an in-memory adapter; it is not the proposed cursor or finality proof. Workspace search found the accessor calls in tests, not a production consensus/signing/recovery/activation call site. |
| `execution_adapter.rs:1049-1077,1088-1120,1286-1374` | The async worker initializes a private local `current_height = 0`. Its NonceOnly worker updates it on successful execution; the VM-v0 worker attempts `flush_state`, logs a flush error, then updates local height regardless. The value is used in the worker shutdown log. | The async `AsyncExecutionService` does not expose this local variable as a durable position. It resets on worker start and cannot establish persistence, exact prefix or successful flush. |
| `execution_adapter.rs:452-475,1492-1510` | `submit_block` uses `try_send`; `Ok(())` means successfully enqueued, with `QueueFull` / `ShuttingDown` errors. | Queue admission only. It is not execution completion or acknowledgement. |
| `crates/qbind-node/src/hotstuff_node_sim.rs:3028-3129` | On a newly committed block in this simulator/harness route, proposal transaction bytes are decoded in order, but malformed/short items are logged and skipped; a `QbindBlock` is then passed to async `submit_block` if configured or to synchronous execution otherwise. | This proves neither a general production caller nor exact-input completion. A cursor handoff must reject any malformed or skipped entry, rather than acknowledge the filtered vector. The wrapper's `payload_hash` / `header.height` fields do not by themselves establish stable finalized identity. |
| `crates/qbind-node/src/ledger_bridge.rs:1-20,73-123`; `crates/qbind-ledger/src/apply.rs:59-162`; `crates/qbind-node/src/commit_index.rs:1-12,90-145` | The in-memory node/ledger harness drains consensus `NodeCommittedBlock`s and applies them to `InMemoryLedger`; its `tip_height` and the node `CommitIndex` track committed blocks in memory. `CommitIndex` describes itself as a consensus-level index. | These are in-memory/test-harness paths, not a persistent account-state execution cursor. The ledger view consumes consensus commits; no path back to consensus authority or signing was observed. |
| `crates/qbind-node/src/evm_commit.rs:170-260,281-385` | The EVM bridge may load `current_height` from its own latest EVM snapshot, applies a `NodeCommittedBlock` and supplied `evm_txs`, sets its height and result cache, then stores/prunes an EVM snapshot. `apply_committed_block` is `#[cfg(feature = "default")]`. | This is a separate EVM state/result route; the method receives transactions separately from the proposal and updates in-memory state/height before snapshot storage can return an error. Workspace source search found the implementation and test call sites, but no production-source caller; downstream use is unverified. It cannot serve as the candidate cursor or entitlement proof. |
| `crates/qbind-node/src/node_config.rs:5271-5291`; `crates/qbind-ledger/src/execution.rs:1130-1141,1258-1285,1380-1483` | VM account values are accessed through per-account state methods; inspected getters may map missing/error to default and setter paths do not carry a durable block position. | No durable execution-prefix position or reviewed atomic membership/state/completion interface is established here. An absent/default account value is not cursor evidence. |

Workspace searches in `crates/` for the candidate identifiers
`execution_cursor`, `execution_applied`, `AppliedCursor` and
`ExecutionPosition` returned no source matches at the reviewed endpoint.
This is bounded search evidence, not proof against generic scalar aliases,
generated/macro-expanded code, unsearched workspace components, other
feature configurations or downstream users.

### Consensus safety and finality routes

| Route | Current source flow | Condition and implication |
|---|---|---|
| Simulator durable restart | `hotstuff_node_sim.rs:2038-2147` reads `ConsensusStorage::get_last_committed`, loads the corresponding block and QC/embedded QC, constructs a locked QC and calls `initialize_from_restart`. `storage.rs:929-959` reads/writes `meta:last_committed`. The simulator commit path updates this key at `hotstuff_node_sim.rs:3219`. | This is the inspected simulator/storage restart route. It derives consensus height, committed block and lock from consensus records, not an execution cursor. It is not evidence that the production binary has a corresponding persisted committed-tip path. |
| Engine restart primitive | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:2598-2618` seeds committed block/height, optional lock and `current_view = committed_height + 1`; `hotstuff_state_engine.rs:1991-2017` stores committed tip and lock. | The method is a consensus authority path. Any future cursor-derived input here would repurpose E as consensus recovery/safety authority and is prohibited. |
| Binary snapshot baseline | `crates/qbind-node/src/main.rs:2888-2900` maps a successful restore outcome's `StateSnapshotMeta.height/block_hash` to `RestoreBaseline`. `main.rs:5512-5530,8502-8504` threads it to the binary consensus configuration. `binary_consensus_loop.rs:2840-2855` calls `initialize_from_snapshot_baseline`; `basic_hotstuff_engine.rs:2620-2685` sets committed height and `current_view = snapshot_height + 1`; `hotstuff_state_engine.rs:2019-2085` inserts a synthetic committed baseline with no QC history. | This route is active when `--restore-from-snapshot` yields a restore outcome. Engine comments say it does not restore QC, vote history or pre-snapshot block history. It still seeds the committed monotonicity floor/current view, so using E as `StateSnapshotMeta.height` would indirectly affect later consensus proposals/commit/finality. |
| Consensus catch-up and observations | `binary_consensus_loop.rs:2330-2350,8380-8600` uses engine `committed_height()` and committed block for request/response bounds, proposal deferral and catch-up exit; `binary_consensus_loop.rs:8620-8655` derives `SnapshotAnchor` from engine committed height/block. | These are engine/consensus-derived positions. A cursor or diagnostic derived from it must not be fed back as the consensus position. Route-specific P2P behavior is configuration-dependent; no execution cursor is read in these inspected paths. |
| Proposal/vote/finality engine | The binary loop drives `BasicHotStuffEngine` and supplies proposal/vote actions through its consensus code; restart/baseline methods above seed engine state. | No execution cursor exists at this endpoint. The audit did not execute a feature/build matrix or prove every call edge; the complete consensus safety/finality graph remains a future implementation proof obligation. |

### Snapshot/restore and the two verified indirect channels

**Channel A — snapshot height → `RestoreBaseline` → consensus baseline.**

1. `record_engine_progress` obtains `engine.committed_height()` and
   `engine.committed_block()` and creates a `SnapshotAnchor`
   (`binary_consensus_loop.rs:8620-8655`).
2. The binary snapshot trigger passes that anchor to
   `VmV0RuntimeState::create_snapshot`
   (`main.rs:9348-9355`; runtime call site and periodic route are
   `binary_consensus_loop.rs:9167-9255`).
3. `vm_v0_runtime.rs:174-245` copies current VM state through
   `StateSnapshotter` and writes `StateSnapshotMeta.height` and `block_hash`
   from the consensus anchor (`qbind-ledger/src/state_snapshot.rs:91-187`).
   No execution cursor/current-height check is present in the inspected
   snapshot call path.
4. On a requested restore, `main.rs:2450-2485` validates/materializes the
   snapshot and `main.rs:2888-2900` converts its metadata fields to
   `RestoreBaseline`; the binary then calls
   `initialize_from_snapshot_baseline` as above.

**Source fact:** snapshot metadata position comes from consensus, while its
copied account image is not checked against a persisted execution-applied
prefix in this path. This does not prove that the copied image is actually
behind; it proves the inspected path does not establish equality. If E were
stored in the existing `height` field, restore would turn it into consensus
committed height/view.

**Channel B — restore baseline height → `ActivationContext.current_height`.**

- Ordinary startup trust-bundle loading uses
  `restore_baseline.snapshot_height` or zero to build
  `ActivationContext.current_height` before the consensus loop starts
  (`main.rs:6570-6611`; activation policy accepts this value at
  `pqc_trust_activation.rs:193-225,353-425`).
- CLI `--p2p-trust-bundle-reload-check`,
  `--p2p-trust-bundle-peer-candidate-check` and
  `--p2p-trust-bundle-reload-apply-path` similarly derive the activation
  height from the baseline or zero (`main.rs:3012-3036,3415-3439,
  4382-4406`); the reload-apply baseline bundle uses that same value at
  `main.rs:4447-4449`.
- Other trust-bundle routes are different: marker preflights construct
  `current_height: None` (`main.rs:668-669,1641-1642`), some dispatcher and
  reload builders use `height_only(0)` (`main.rs:7816-7817,8278-8280,
  9094-9103`), and a SIGHUP trigger supplies `Some(0)`
  (`main.rs:9220-9222`). Thus not every activation/reload route uses
  `RestoreBaseline`, but these differences do not authorize a future cursor
  to enter any `ActivationContext`.

### Signing history and recovery routes

| Authority | Current flow and condition | Non-entanglement consequence |
|---|---|---|
| Signing position/journal | `SigningPosition` is keyed by validator, network/genesis, message kind and `originating_view` (`signing_reservation_journal.rs:150-195`). Guarded Proposal/Vote signing constructs it from the originating consensus action and reserves it before signing (`binary_consensus_loop.rs:4733-4761,5162-5185`). The journal is persisted through the consensus storage adapter under its own namespace (`storage.rs:1456-1535`). | E must never supply or alter `originating_view`, the journal key/binding, a reservation, retained-result lookup or signer gate. The source position is consensus-action-originated; no execution cursor is read. |
| Signing journal restart/recovery | `SigningReservationJournal::reserve_for_sign` re-reads the record and fails closed on store errors/corruption; a recovered signed record requires an explicit durability acknowledgement before retained resend, and a reserved record does not yield a fresh continuation (`signing_reservation_journal.rs:2630-2695`, with the recovered-ack barrier around 4070-4120). | This is signing-history recovery only, not general execution recovery or E authority. It remains under existing signing rules. |
| Snapshot restore authority | The requested restore route checks snapshot authority markers before materialization when its canonical genesis context is available; marker failure refuses the requested restore (`main.rs:2450-2485`; `snapshot_restore.rs:760-806`). The baseline itself still comes from `meta.height/block_hash`. | Snapshot authority-marker checks do not prove an execution input prefix or authorize signing/consensus recovery from E. Missing authority context has route-specific fail-closed behavior; it is not replaced by E. |
| Restore transaction record | `restore_completion.rs:1-27,193-280` defines local INTENT/COMPLETE bookkeeping and an advisory destination lock; the module explicitly says the record is not an external authority, checkpoint authentication or anti-rollback witness. | It may gate ordinary startup for an interrupted restore, but it does not establish E, finality or recovery authority. Do not treat cursor presence as permission to clear or bypass restore gates. |
| Consensus restart | The simulator reads `last_committed` and block/QC records as above; the snapshot-baseline route seeds only a synthetic committed prefix. | An execution cursor cannot choose a restart baseline, owner, rollback direction, lock/QC, or return-to-service state. Recovery remains separately authorized and independently evidenced. |

## 2. Non-entanglement matrix

The current source has no implemented cursor. The first column records
observed current routes, not E flows. The future constraints are design
requirements, not claims that an implementation satisfies them.

| Current producer / transformation / consumer | Observed status | Future cursor prohibition and required evidence |
|---|---|---|
| Worker/account progress → consensus committed tip, lock, view, vote or finality | No direct production-source use of `ExecutionAdapter::current_height` or async worker-local height was found in the workspace search. Consensus restart/baseline routes instead consume consensus storage or `RestoreBaseline`. Search did find simulator submission from a consensus commit into execution. | Keep E in a separately typed execution domain. It must not be convertible/aliased to consensus height, view, block ID, lock, vote or committed tip; never write it to `last_committed`. Audit all engine constructors, safety decisions, callbacks, caches, P2P/catch-up, CLI and restart paths. Test prohibited direct and indirect flows. |
| Consensus `SnapshotAnchor` → `StateSnapshotMeta.height` → `RestoreBaseline` → engine baseline | This is an actual current consensus-derived chain, and the engine uses the baseline as committed-height/view floor. The snapshot's copied state prefix is not tied to an execution position by this path. | Do not put E in `SnapshotAnchor.height`, `StateSnapshotMeta.height`, `RestoreBaseline.snapshot_height`, or an equivalent scalar. Snapshot/restore needs distinct authenticated position fields and a separately reviewed relation; until then exact-prefix restore is BLOCKED. |
| `RestoreBaseline.snapshot_height` → `ActivationContext.current_height` → trust bundle activation/reload decisions | Actual on startup and three CLI trust-bundle paths, with additional baseline reuse; other routes use None/0. | No E may populate baseline or current height, directly or through snapshots, fallback/defaults, cache or callback. Audit every startup and CLI route; runtime trace must establish activation's true source. |
| Consensus action `originating_view` → `SigningPosition` → journal reservation/recovered result → signer | Actual Proposal/Vote signing path uses captured consensus action view; journal recovery is separately bound to that key. | E must not seed a signing position, change signing authority, trigger signature reuse, clear/repair a journal or establish history continuity. Require type/data-flow audit of every signer path and restart/recovery test under all production features. |
| Snapshot/restore or restore-transaction state → recovery decision | Existing mechanisms inspect a requested snapshot, local authority marker and local restore transaction record; none supplies execution-prefix proof. | E cannot authorize selection, rollback, migration, fence release or recovery. Recovery authority, currentness, first-use enrollment and evidence must be separately authenticated; ordinary gates must remain in force during restricted inspection. |
| EVM bridge's snapshot height/result cache → caller | Separate EVM route accepts a committed block and caller-supplied EVM transaction vector; no production-source caller found. | Do not infer native state cursor, exact proposal input completion or receipt entitlement from EVM height/cache. Any future result must be bound to the same reviewed operation/unit and authorized entitlement. |
| Generic scalar/cache/API/metrics/snapshot field derived from E | No such E exists in the source endpoint; exact identifier search had no matches. | Preserve an opaque type and provenance at each serialization/API boundary. No integer cast, alias, callback, cache, migration field, metric or snapshot metadata may make E consumable as C, signer position, recovery authority or activation height. Audit macros/generated code and downstream consumers. |

### Design-level separation argument — conditional only

A distinct E can be specified without redefining consensus safety only if
the future interface preserves this separation:

1. An execution-domain owner creates and atomically updates an opaque
   `ExecutionAppliedPosition` together with the account membership/values,
   operation identity, exact executed input order/count, acknowledgement
   and entitled completion.
2. Consensus APIs continue to accept only consensus-authorized positions and
   proof; signer APIs continue to accept only captured consensus
   `originating_view` and signing-domain identity. No `From`/cast or
   untyped scalar adapter bridges E into those types.
3. Snapshot metadata and restore APIs carry separate typed consensus and
   execution positions if both are needed. Existing `height` fields are not
   silently redefined. Restore baseline continues to require independently
   authenticated consensus authority.
4. Activation receives only its separately approved currentness sources.
   Recovery inspection can read E but cannot promote, roll back, authorize,
   release a fence, sign or resume service based on E alone.
5. Access controls/fencing apply at every shared-state backend boundary,
   not only at a worker mutex or API. No alternate process, stale handle,
   cache, migration utility or raw store handle bypasses the boundary.

Those are design constraints, not evidence that actual QBIND interfaces
provide such a separation. The current snapshot-height channels are concrete
ways a future scalar cursor could become entangled if placed in existing
metadata. Therefore implementation entry is **BLOCKED** until actual source,
build and runtime use-proof shows every direct and indirect route is separated.

## 3. Candidate finality-to-execution handoff

This is a candidate contract only; no such typed handoff exists in the
inspected source.

### Authenticated handoff contents

An immutable input to execution must bind:

- independently authenticated finalized decision subject and its consensus
  history/context;
- deployment, genesis, chain and backend/state namespace;
- authoritative predecessor consensus position and predecessor E;
- authorized ruleset/schema/version and its applicability at this decision;
- exact authenticated canonical proposal/input bytes;
- ordered decoded transaction sequence, count, and exact sequence actually
  passed to execution;
- resulting account values **and membership**;
- stable operation/commit identity and relation to that state;
- acknowledgement plus every entitled completion outcome, with unresolved
  fields unavailable or retained pending owner decision.

No height, local worker counter, `last_committed`, payload hash, snapshot
directory, balance equality or queue response substitutes for these
bindings.

### Validation and publication sequence

1. **Authenticate finality independently.** Verify evidence against the
   authorized consensus history/policy and currentness context. Bind it to
   one finalized subject, deployment/genesis and ruleset. An execution worker
   or account store cannot self-assert finality.
2. **Verify predecessor continuity and association.** Independently verify
   deployment/backend association and the authoritative predecessor
   consensus/execution positions. A missing, stale, conflicting or
   unavailable predecessor refuses before ordinary state mutation.
3. **Bind exact proposal bytes and inputs.** Decode every ordered transaction;
   reject malformed/trailing data, missing transactions, parser skips,
   reordering, duplication, count mismatch or any substitution. Preserve
   exact byte sequence and decoded order. Compare proposal transaction count
   with the exact executed input count. Any failure refuses before state
   mutation, cursor advancement or state-dependent completion. The current
   simulator's skip behavior is not acceptable for this handoff.
4. **Establish operation identity.** Bind the semantic decision subject,
   deployment/backend, chain/genesis, predecessor and new positions,
   authorized ruleset/schema, exact executed order/count, and the eventual
   state/completion unit. Proof representation alone must not create a
   conflicting operation ID if it is validly equivalent under a later
   approved policy.
5. **Execute under a fenced state generation.** Use only the validated
   handoff and a coherent predecessor account membership/value state. Keep
   every input in exact order. Retain transaction outcomes as specified,
   without treating a failed transaction as proof that the block did not
   commit.
6. **Commit one reviewed unit.** Atomically bind all required account values
   and membership; E; operation/commit identity; exact input order/count;
   acknowledgement; and each entitled outcome. No required field may be
   silently omitted. A failed/unknown write or commit leaves completion
   unavailable and ordinary access gated.
7. **Acknowledge/retry by operation identity.** Return an acknowledgement
   only after proving the whole committed unit and applicable authentication/
   currentness. It means committed execution under applicable rules, not that
   every transaction succeeded. A duplicate retry retrieves only the same
   operation's retained result. Missing, pruned, conflicting or uncertain
   completion is unknown/unavailable; do not fabricate success or blindly
   re-execute.

### QC and equivalent proof representations

`qbind-wire/src/consensus.rs:915-950` includes the proposal's embedded QC
bytes and ordered transaction bytes in the canonical proposal body; the
signing/canonicalization paths authenticate that exact body. Separately
supplied external finality evidence is not authenticated merely because it
accompanies the proposal. The handoff must distinguish (a) the decision
subject, (b) QC bytes embedded in the proposal and (c) external proof.

Under a future approved policy, a different independently valid proof
representation for the same decision subject must not manufacture a
conflicting operation identity solely because the proof bytes differ. That
requires re-verification or authenticated reusable verification evidence,
including subject, policy/version, deployment/context and currentness/
revocation. A changed embedded QC changes the signed proposal body; it is
not automatically equivalent. No applicable QBIND route or equivalence/
currentness policy is established.

The six identity bindings remain **OPEN**:

1. finality and exact decision subject;
2. exact authenticated input bytes and executed sequence/count;
3. position continuity and predecessor;
4. deployment/genesis/backend association;
5. authorized ruleset/schema/history;
6. operation/commit identity tied to state, membership, acknowledgement and
   entitled outcomes in the same unit.

Native post-quantum integrity/authentication is fixed. Construction, trust
roots/authority, parameters, composition and demonstrated end-to-end
security remain **OPEN**.

## 4. Lag, migration and recovery boundaries

| Condition | Candidate required behavior | Current status |
|---|---|---|
| E missing at first use or source account state not linked to exact finalized prefix | No default-zero enrollment, state-dependent read, execution completion or acknowledgement. Require independently authenticated first-use evidence. | No persistent E or enrollment authority found. |
| Finality, currentness, ruleset, predecessor, deployment/backend or exact inputs missing/conflicting | Do not execute/publish E or acknowledge; state-dependent completion is unavailable. | Six bindings and native-PQ construction are OPEN. |
| Consensus ahead of E | E identifies only the prefix actually applied. Refuse operations that require newer execution state. Whether consensus may advance and what lag/liveness rule applies is OPEN; no equality-to-C policy selected. | No current E/C comparison or lag gate. |
| Execution write/flush/commit result uncertain | Keep ordinary state-dependent access and acknowledgement gated; status is unknown/unavailable. Do not infer success from balances, worker height, later flush or matching snapshot. Do not blindly replay. | The inspected VM worker logs a flush failure and still updates its local height; it does not produce a durable completion ack. |
| Restart, stale owner, retained handle, other process, migration or rollback | Gate ordinary readers/writers/workers; use restricted independently authenticated inspection only. Fence at the actual backend/write boundary; a mutex/advisory lock alone is not sufficient. Conflicting or uncertain cutover remains quarantined. | No cursor fence/cutover protocol. Restore lock/RTR scopes are local restore bookkeeping; they do not prove general multi-process cursor ownership. |
| Recovery evidence/currentness missing | Inspection may report unknown; it cannot authorize rollback, forward recovery, fence release, node participation or signing. | Independent recovery authority, first-use enrollment, currentness and signing-history continuity remain OPEN. VM-state recovery alone does not authorize signing or participation. |

The full inventory of operations depending on account execution state is not
established by these source paths. Candidate gates must inventory ordinary
account reads/writes/flushes, worker claims, EVM/RPC result retrieval, caches,
snapshot/restore, retries, callbacks and any signing/participation operation
whose policy depends on VM state. No claim is made that current QBIND gates
these operations on E.

Migration/cutover is **BLOCKED**: source account state has not been tied to
an exact finalized ordered input prefix. Do not substitute `last_committed`,
balances, `ExecutionAdapter::current_height`, async worker-local height, EVM
snapshot height or an absent marker. Future cutover needs independently
authenticated source provenance, backend/deployment association, a safe
quiescence boundary, stale-owner and retained-handle fencing, one-authority
publication, interrupted-cutover behavior, rollback authority and recovery
evidence. None is authorized or performed here.

## 5. Evidence, limitations and decision

| Category | Finding |
|---|---|
| **Source-supported** | No execution cursor authority/interface exists at the reviewed endpoint. Current worker, EVM, in-memory ledger and consensus positions are distinct mechanisms with different persistence and route scope. Snapshot anchor derives from engine committed position; snapshot metadata height becomes `RestoreBaseline`, which seeds consensus height/view. The baseline height also flows into `ActivationContext.current_height` on startup and selected CLI trust-bundle routes. Signing journal position is captured from consensus action view; journal recovery is separately position-bound. |
| **Owner-approved** | Distinct execution-applied cursor, atomic binding to required state/completion, no use as finality/rollback/consensus/signing/recovery/activation authority. Consensus lag is not decided. |
| **Candidate requirement** | Typed finality/exact-input handoff, stable semantic operation identity, atomic state/membership/E/completion unit, exact order/count, refusal on binding failure, unavailable on uncertain commit, and strict no-flow into prohibited domains. |
| **Unverified / OPEN** | Exhaustive production callers and state-dependent operations; complete call graph across all features/macros and downstream code; exact snapshot state prefix; full consensus binary persistence/restart equivalence; applicable external finality/QC equivalence and currentness route; six identity bindings; native-PQ construction and roots; storage atomicity/durability; migration/fencing; recovery authority; lag/liveness policy. |
| **Design verdict** | A conceptual type/data-domain separation is specifiable, but the reviewed source does not implement it. Current snapshot metadata provides concrete indirect channels that could entangle a future cursor. Non-entanglement is therefore **BLOCKED for implementation entry**, not proven for any implementation and not proven impossible as a design. |

Before any later implementation entry, independent review needs:

- a complete production caller/use-path inventory including all features,
  macros/generated code, startup/CLI, APIs, callbacks and downstream
  integration;
- typed-interface and data-flow evidence that E cannot reach consensus
  committed tip/lock/view/vote/finality, signing position/authorization,
  snapshot-derived consensus baseline, recovery authority or activation;
- exact snapshot state-prefix and separate consensus-position semantics;
- independently authenticated finality/input and all six binding evidence;
- backend atomic-commit, durability, shared-state fencing, migration and
  recovery evidence under explicitly approved threat/crash models;
- future negative tests and runtime traces demonstrating fail-closed
  behavior, including the two snapshot/restore and restore/activation
  channels and every bypass path.

All such tests, builds, runtime observations and experiments are
**FUTURE / NOT AUTHORIZED / NOT EXECUTED**. The earlier 5/5 capability run
remains author evidence only for its limited characterization; it does not
prove joint atomicity, cursor separation or power-loss safety.

### Smallest next owner decision

Do not revisit approval of the distinct cursor direction. The smallest
remaining decision is to identify which independently authenticated finality
authority and artifact are eligible to supply the future handoff, including
what defines the semantic decision subject for equivalent-proof review.
Evidence needed before that decision is an independent inventory of available
finality inputs and their currentness/context; it need not select a key,
cryptographic construction, storage mechanism, retention period, lag policy
or recovery authority.

## 6. Pinned paths and inherited scope

Principal reviewed paths (line ranges refer to the pinned source endpoint):

- `crates/qbind-node/src/execution_adapter.rs` (169-203, 230-242,
  295-366, 452-475, 1049-1120, 1286-1374, 1492-1510).
- `crates/qbind-node/src/hotstuff_node_sim.rs` (2038-2147, 3028-3129,
  3219).
- `crates/qbind-node/src/evm_commit.rs` (170-260, 281-385);
  `crates/qbind-node/src/ledger_bridge.rs` (1-20, 73-123);
  `crates/qbind-ledger/src/apply.rs` (59-162);
  `crates/qbind-node/src/commit_index.rs` (1-12, 90-145).
- `crates/qbind-node/src/storage.rs` (929-959, 1456-1535);
  `crates/qbind-node/src/production_consensus_storage.rs` (353-375).
- `crates/qbind-consensus/src/basic_hotstuff_engine.rs` (2598-2685);
  `crates/qbind-consensus/src/hotstuff_state_engine.rs` (1991-2085).
- `crates/qbind-node/src/binary_consensus_loop.rs` (2330-2350,
  2840-2855, 8380-8655, 9167-9255).
- `crates/qbind-node/src/main.rs` (2450-2485, 2888-2900, 3012-3036,
  3415-3439, 4382-4449, 5512-5530, 6570-6611, 8502-8504,
  9348-9355).
- `crates/qbind-node/src/vm_v0_runtime.rs` (174-245);
  `crates/qbind-ledger/src/state_snapshot.rs` (91-187);
  `crates/qbind-node/src/snapshot_restore.rs` (760-806).
- `crates/qbind-node/src/pqc_trust_activation.rs` (57-69, 193-225,
  353-425); `crates/qbind-node/src/restore_completion.rs` (1-27,
  193-280).
- `crates/qbind-node/src/signing_reservation_journal.rs` (150-195,
  2630-2695, 4070-4120); `crates/qbind-wire/src/consensus.rs` (915-950).
- Reviewed cursor specification:
  `docs/security/evidence/distinct-execution-cursor-finality-handoff-nonentanglement-20261110.md`,
  blob `dd42b95cf0ef4403088e4e4f17ac79d801996e68`.

The reviewed cursor endpoint inherits 51 changed paths versus pinned
`main`. This manifest is the pinned `git diff --name-status main
b559658a0042d4b495ad8c22fb50f08ef9dd7223`:

```text
A crates/qbind-ledger/src/checked_arithmetic_oracle_tests.rs
M crates/qbind-ledger/src/parallel_exec.rs
A crates/qbind-ledger/tests/atomic_block_retained_completion_capability.rs
A crates/qbind-ledger/tests/gas_disabled_recipient_overflow_characterization.rs
A crates/qbind-ledger/tests/sequential_direct_stage_b_overflow_characterization.rs
M crates/qbind-node/src/execution_adapter.rs
M crates/qbind-node/src/lib.rs
M crates/qbind-node/tests/t155_async_execution_integration_tests.rs
M crates/qbind-node/tests/t157_parallel_execution_integration_tests.rs
M crates/qbind-node/tests/t160_devnet_cluster_harness.rs
M crates/qbind-node/tests/t163_vm_v0_integration_tests.rs
M crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs
M crates/qbind-node/tests/t177_vm_v0_pipeline_proptests.rs
M crates/qbind-node/tests/t179_gas_pipeline_proptests.rs
M crates/qbind-node/tests/t221_dag_coupling_cluster_tests.rs
M crates/qbind-node/tests/t222_consensus_chaos_harness.rs
M crates/qbind-node/tests/t238_multi_region_latency_harness.rs
A docs/security/evidence/atomic-block-retained-completion-capability-experiment-20261109.md
A docs/security/evidence/caller-completion-actual-store-failure-contract-20261109.md
A docs/security/evidence/candidate-durable-execution-recovery-protocol-20261109.md
A docs/security/evidence/checked-arithmetic-oracle-baseline-20261109.md
A docs/security/evidence/checked-arithmetic-oracle-debug-20261109.txt
A docs/security/evidence/checked-arithmetic-oracle-nontest-build-20261109.txt
A docs/security/evidence/checked-arithmetic-oracle-release-20261109.txt
A docs/security/evidence/checked-arithmetic-owner-followup-debug-20261109.txt
A docs/security/evidence/checked-arithmetic-owner-followup-release-20261109.txt
A docs/security/evidence/checked-arithmetic-owner-test-contract-20261109.md
A docs/security/evidence/checked-arithmetic-owner-test-contract-followup-20261109.md
A docs/security/evidence/distinct-execution-cursor-finality-handoff-nonentanglement-20261110.md
A docs/security/evidence/future-submitter-acknowledgement-atomic-commit-design-20261109.md
A docs/security/evidence/gas-disabled-arithmetic-compatibility-transition-assessment-20261109.md
A docs/security/evidence/gas-disabled-arithmetic-refusal-contract-proposal-20261109.md
A docs/security/evidence/gas-disabled-recipient-overflow-characterization-20261109.md
A docs/security/evidence/gas-disabled-recipient-overflow-debug-20261109.txt
A docs/security/evidence/gas-disabled-recipient-overflow-release-20261109.txt
A docs/security/evidence/option-a-execution-position-consolidation-assessment-20261109.md
A docs/security/evidence/required-persistence-adapter-unit-output-20261109.txt
A docs/security/evidence/required-persistence-refusal-candidate-20261109.md
A docs/security/evidence/required-persistence-shared-state-check-output-20261109.txt
A docs/security/evidence/required-persistence-shared-state-correction-20261109.md
A docs/security/evidence/required-persistence-shared-state-t166-output-20261109.txt
A docs/security/evidence/required-persistence-shared-state-unit-output-20261109.txt
A docs/security/evidence/required-persistence-t166-initial-duplicate-open-output-20261109.txt
A docs/security/evidence/required-persistence-t166-smoke-output-20261109.txt
A docs/security/evidence/required-persistence-test-check-output-20261109.txt
A docs/security/evidence/sequential-direct-stage-b-overflow-characterization-20261109.md
A docs/security/evidence/sequential-direct-stage-b-overflow-debug-20261109.txt
A docs/security/evidence/sequential-direct-stage-b-overflow-release-20261109.txt
A docs/security/evidence/shared-state-blocker-controls-20261109.md
A docs/security/evidence/shared-state-blocker-controls-output-20261109.txt
A docs/security/evidence/worker-write-failure-backend-reuse-decision-brief-20261109.md
```

The only new path versus reviewed cursor endpoint
`b559658a0042d4b495ad8c22fb50f08ef9dd7223` is:

```text
A docs/security/evidence/cursor-nonentanglement-source-use-path-audit-20261110.md
```

Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**.
Recipient overflow, A23-F1 and A33-F1 / E27 remain **OPEN**; activation
remains **DISABLED**; public DevNet remains **NO-GO**. Preserve all prior
scoped dispositions.
