# Distinct execution-applied cursor: finality handoff and non-entanglement

## Status, owner decision and evidence boundary

**DOCUMENTATION ONLY / SPECIFICATION CANDIDATE FOR INDEPENDENT REVIEW.**
The owner selected a distinct execution-applied cursor as a candidate whose
purpose is to identify the exact finalized input prefix applied to account
state and commit that position atomically with state and completion. This is
not an implementation or feasibility approval. No implementation, migration,
experiment, startup, integration, recovery, signing, activation or DevNet
action is authorized.

The cursor is not finality evidence, anti-rollback protection, or authority
for signing, consensus participation, recovery or activation. Consensus
`last_committed`, committed tip/lock, block/QC history and the
signing-reservation journal remain under their existing authority and must
not be repurposed.

**OWNER REQUIREMENT:** the reviewed atomic unit binds account values and
membership; authenticated execution position; stable operation identity;
exact executed transaction order and count; acknowledgement; and every
entitled outcome. Unknown fields are explicitly unavailable or retained
pending owner decision. The future submitter acknowledgement means committed
execution under applicable rules, not that every transaction succeeded.

This assessment is pinned to source endpoint
`2211d0f67f682ac11189995d9839b040128ba506`, tree
`84bc01224e64df11809621dd6775a16cb43f593d`, parent
`35ba53e62a7dd9e157821d78d2087a8f3c812e69`; pinned `main` is
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`. The reviewed Option A
assessment is
`docs/security/evidence/option-a-execution-position-consolidation-assessment-20261109.md`,
blob `6d60b089d15dece962f87c656d739e842501bd29`. Its source boundary and
unknowns are preserved here, not promoted to proof.

Labels: **SOURCE FACT** is observed in pinned source; **OWNER DECISION** is
the decision stated above; **CANDIDATE CONTRACT** is a required future
interface or behavior; **OPEN** is missing policy/evidence; **BLOCKED** means
the relevant operation must refuse until the open condition is resolved.
Every validation below is **FUTURE / NOT AUTHORIZED / NOT EXECUTED**.

## 1. Pinned source and authority map

| Surface | Pinned source fact | Boundary for the proposed cursor |
|---|---|---|
| VM account state | `RocksDbAccountState` opens the VM state at `<data_dir>/state_vm_v0`; the persistent API is per-account get/put/flush. Its read maps missing, malformed and I/O-error results to a default; `AccountStateUpdater::set_account_state` returns no error (`crates/qbind-node/src/node_config.rs:5271-5291`; `crates/qbind-node/src/vm_v0_runtime.rs:58-141`; `crates/qbind-ledger/src/execution.rs:1130-1141,1258-1285,1380-1483`). | No durable execution cursor or fallible membership-aware block transaction exists in this interface. The candidate must not treat default state as proof that an account is absent or that state is healthy. |
| Worker progress and queue | Async `submit_block(QbindBlock)` reports enqueue, queue-full or shutdown; worker progress is initialized in a local `current_height`. The VM worker attempts a flush, logs an error if it fails, then updates that local height (`crates/qbind-node/src/execution_adapter.rs:460-505,1049-1067,1315-1382,1492-1525`). | Queue admission and local height do not establish an applied prefix. No cursor-aware acknowledgement or restart lookup exists. |
| Simulator handoff/decode | The inspected `hotstuff_node_sim.rs` commit callback converts proposal transactions to `QbindTransaction`; malformed encodings are logged and skipped, then a `QbindBlock` is submitted or synchronously applied (`crates/qbind-node/src/hotstuff_node_sim.rs:3028-3125`). | This simulator/harness route is not proof of an ordinary production caller. Its skip-on-decode-error behavior cannot satisfy exact-input binding: a future handoff must refuse on any missing/malformed item and must reconcile proposal count, canonical bytes, decoded count and executed count. |
| Consensus tip and safety state | `ConsensusStorage` stores `meta:last_committed`, block/QC records and epoch metadata in its own DB at `<data_dir>/consensus`; the VM account DB is separate. The simulator writes block, QC and `last_committed` through separate calls. Restart loads the committed block and QC and seeds `HotStuffStateEngine` committed tip/lock and `BasicHotStuffEngine` view (`crates/qbind-node/src/storage.rs:168-224,719-754,929-1025`; `crates/qbind-node/src/production_consensus_storage.rs:353-375`; `crates/qbind-node/src/hotstuff_node_sim.rs:2020-2150,3198-3222`; `crates/qbind-consensus/src/hotstuff_state_engine.rs:1991-2020`; `crates/qbind-consensus/src/basic_hotstuff_engine.rs:2598-2610`). | Consensus `last_committed` is safety/restart state, not the proposed execution cursor. It remains at its current authority. No source establishes an atomic account-state/consensus-position commit. |
| Consensus-derived reads | Binary consensus uses `engine.committed_height()` and committed block for restore-catch-up requests, peer response checks, proposal deferral and catch-up exit; it publishes consensus committed anchors from the engine (`crates/qbind-node/src/binary_consensus_loop.rs:2330-2350,8380-8600,8630-8655`). | These are consensus uses. The execution cursor must not feed, replace or indirectly derive these heights or block IDs. |
| Snapshot and restore | Snapshot creation uses a `SnapshotAnchor` whose height/block ID comes from the consensus engine and writes those as `StateSnapshotMeta.height/block_hash` while copying VM state (`binary_consensus_loop.rs:8638-8655,9168-9255`; `crates/qbind-node/src/vm_v0_runtime.rs:15-32,174-260`; `crates/qbind-ledger/src/state_snapshot.rs:91-135`). Restore translates `StateSnapshotMeta.height/block_hash` into `RestoreBaseline`, and the binary seeds `initialize_from_snapshot_baseline` (`crates/qbind-node/src/main.rs:2878-2905`; `crates/qbind-node/src/binary_consensus_loop.rs:2840-2855`; `crates/qbind-consensus/src/basic_hotstuff_engine.rs:2620-2685`). | Snapshot position is indirectly a consensus restart baseline. Current source does not establish that the account image copied for a consensus anchor has executed exactly through that anchor. A future cursor must not be put into this `height` field and thereby seed consensus safety. The snapshot/state-prefix relation is OPEN. |
| Trust activation | Pre-consensus `ActivationContext.current_height` is sourced from `restore_baseline.snapshot_height` or zero, per comments and binary setup (`crates/qbind-node/src/pqc_trust_activation.rs:55-75,185-230`; `crates/qbind-node/src/main.rs:6570-6610`, with analogous validation/reload call sites at 3012-3035,3415-3438,4382-4405). | This is an activation input, not an execution cursor consumer. The cursor must not flow into activation height, currentness, bundle acceptance or activation. The existing activation policy is not proof of cursor safety. |
| Signing position/history | `SigningPosition` is keyed by validator, network/genesis, message kind and originating consensus view (`crates/qbind-node/src/signing_reservation_journal.rs:150-195`). The Proposal/Vote signing paths construct positions from the originating consensus view (`crates/qbind-node/src/binary_consensus_loop.rs:4708-4755,5148-5190`). The journal uses the consensus storage backend under a separate namespace and is explicitly not signing authorization or an anti-rollback anchor (`signing_reservation_journal.rs:1-37`; `crates/qbind-node/src/storage.rs:1456-1535`). | The cursor must never supply or alter `SigningPosition`, reserve/retrieve a signature, authorize signer use, or establish recovery/history continuity. The journal and its authority remain unchanged. |
| Proposal representation | Canonical signed proposal body contains header fields, embedded QC bytes and length-prefixed ordered transaction bytes (`crates/qbind-wire/src/consensus.rs:915-950`). | External finality evidence is not authenticated merely by accompanying the signed proposal. A proposal/QC object or cursor value is not by itself finality proof. |

These are inspected paths, not a complete production call graph. In
particular, the source does not establish the full set of production
execution-service callers or all downstream account-state, snapshot, EVM,
RPC/P2P and recovery consumers. Their existence, absence and dependencies
remain unverified until separately inventoried.

## 2. Candidate cursor and finality/input handoff

### 2.1 Distinct semantic position

**CANDIDATE CONTRACT:** define an execution-applied position `E` as the
authenticated stable decision subject and exact input prefix already applied
to the associated account membership/value state. It is distinct from
consensus committed position `C`:

- `C` remains the consensus engine/storage position used by commit, lock,
  view, catch-up, consensus restart and any consensus safety rule.
- `E` advances only when the corresponding operation's account state and
  completion commit together. It may be behind `C`; this task does not approve
  consensus advancing while that happens or select an allowed-lag policy.
- `E` is not proof that the decision was finalized, a vote/signing position,
  a trust activation height, an anti-rollback anchor or a recovery credential.
- Any `C-E` diagnostic is meaningful only after both positions are
  authenticated and shown comparable under the same deployment/history. It
  may report status or trigger refusal under a separately approved policy;
  it may not authorize consensus, signing, activation or recovery.

No integer-only interchange with consensus height/view is permitted by the
candidate contract. Exact representation and wire/storage encoding remain
unselected. Any conversion or projection has to name its authority, purpose
and proof, and cannot erase the distinction between `C` and `E`.

### 2.2 Candidate handoff contract

The proposed boundary is a typed, immutable **verified finalized execution
input** followed by one execution-domain commit. It is not an existing QBIND
interface:

1. **Independent finality authority** authenticates the exact decision
   subject under the authorized consensus history and policy. It supplies
   evidence and verification context to the handoff; the execution store
   cannot self-certify its cursor.
2. **Handoff validation** binds deployment/genesis and chain, predecessor
   consensus/execution positions, full parent and decision subject, authorized
   ruleset/schema/transition, and currentness. It checks finality evidence
   and relation to the proposal under the approved policy.
3. **Exact-input validation** checks the canonical proposal and its
   transaction count; binds exact ordered byte strings to the decoding
   results and to the transactions actually executed. It refuses any parser
   skip, malformed/trailing data, count mismatch, substitution or
   noncanonical representation. The current simulator's skip-on-decode-error
   path must not be reused as a successful handoff.
4. **Operation identity** is stable for the semantic decision and binds the
   deployment/backend, chain/genesis, full predecessor and new position,
   subject, exact executed order/count, authorized ruleset/schema, and
   commit/result relation. Its definition does not choose an encoding or
   cryptographic construction.
5. **Execution** consumes only that validated handoff and a coherent
   prior account state/membership generation. The execution domain retains
   exact input order/count and any entitled outcomes with the same commit
   identity. It atomically publishes state/membership, `E`, operation/commit
   identity, acknowledgement and entitled outcomes. It does not update `C`
   or signing history.
6. **Acknowledgement** is available only after the complete unit and
   authentication/currentness are established. It asserts committed
   execution under applicable rules, not success of every transaction.
   Missing/unresolved fields are retained pending owner decision or reported
   explicitly unavailable. An error/unknown commit does not create an
   acknowledgement and does not authorize re-execution.

### 2.3 Six identity bindings and proof equivalence

All six bindings remain **OPEN**; including data in a record is not proof
that it was verified:

| Binding | Required future check |
|---|---|
| 1. Finality | Authorized, independently authenticated evidence finalizes the exact stable decision subject under current consensus policy/history. |
| 2. Exact inputs | Exact canonical transaction bytes, actual decoded/executed sequence and count match the authenticated proposal/decision. |
| 3. Position continuity | Full predecessor and authoritative consensus/execution positions are current and contiguous under the approved rules; conflicts refuse. |
| 4. Deployment/backend association | Independent evidence binds chain/genesis, deployment and actual backend/state namespace, including replacement and migration. |
| 5. Ruleset/history | Independently authorized execution/schema version and transitions are valid at the decision position and supported by the executing binary. |
| 6. Commit/completion | Operation identity, state values/membership, `E`, exact inputs, acknowledgement and entitled outcomes are bound in the same reviewed durable unit. |

**SOURCE FACT:** proposal-embedded QC bytes are in the canonical signed
proposal body with ordered transactions; external finality evidence is not
covered by that signature merely because it is presented with the proposal.
Different embedded QC bytes change the signed body. Consequently the future
policy must distinguish:

- the authenticated proposal/decision subject;
- QC bytes embedded in that proposal; and
- any separately supplied external finality proof.

An alternate valid, policy-authorized equivalent proof representation must
not manufacture a conflicting operation identity solely because its bytes
differ. The policy must independently reverify it or authorize reuse through
an authenticated verification record bound to subject, policy/version,
deployment, context and currentness/revocation. Different embedded QC bytes
do not automatically prove equivalent proposal subjects; that relationship
must be checked. No current applicable route, equivalence policy or
currentness mechanism is claimed.

Native post-quantum integrity/authentication is a fixed requirement.
Construction, parameters, roots, authority, composition and demonstrated
end-to-end security remain **OPEN**. Hashing or classical authentication alone
does not satisfy it.

## 3. Non-entanglement use-proof matrix

This matrix is a **proof obligation only**. It describes desired uses and
prohibitions; it does not prove that any future or current implementation
enforces them. Any unlisted production consumer discovered later must be
added and reviewed before implementation entry.

| Proposed producer/reader/derived value | Authority and operation it may depend on; permitted scope | Direct/indirect flows prohibited | Evidence required to establish the prohibition |
|---|---|---|---|
| **P1. Initial enrollment producer** | Only independently authenticated genesis/initial-state evidence or separately authorized migration evidence proving the exact account membership/value prefix and backend association. May write initial `E` only in the same atomic unit as that state and its identity. | No default `E=0` from absent key, empty directory, `create_if_missing`, `last_committed`, height, balances, snapshot filename or local operator configuration. No authority to start consensus, signing or recovery. | Enrollment authority and evidence schema; source/target namespace binding; negative tests for missing, copied, rolled-back and conflicting stores; source/audit review proving no fallback initialization path. |
| **P2. Commit producer (sole steady-state writer)** | Verified finalized input + exact-input validation + authorized ruleset + prior `E` + execution-domain fence. May advance `E` only atomically with complete account values/membership, stable operation/commit identity, exact executed order/count, ack and outcomes. | No direct write from consensus `last_committed`, worker-local `current_height`, queue admission, `SnapshotAnchor`, parser-skipped proposal, later flush, matching balance or unverified caller ID. No write to consensus `last_committed`, QC, lock, vote or signing journal. | Source/call-graph proving one writer API and no raw-store bypass; type/data-flow review; fault/refusal tests showing invalid or uncertain input leaves `E` unchanged and no ack; backend proof of atomic unit. |
| **R1. Next-operation admission/predecessor check** | Current `E` and authenticated finality/input handoff for exactly its successor; may accept only the operation whose authenticated predecessor matches `E`. Queueing remains separate from admission/commit. | No advancing/guessing `E` from consensus height, skipping a position, reconstructing missing history, or treating a block's arrival as finalized. No signing/participation permission from a “caught up” value. | Typed API/call graph; negative controls for gaps, duplicates, same-height conflicts, stale proofs and altered transaction count; verify refusal occurs before state mutation. |
| **R2. Account-state reads, cache and state-dependent APIs** | May read a coherent committed state generation only with authenticated association to its `E`; cached values carry/invalidate with that generation. A caller requiring a newer or otherwise established prefix must be refused/unavailable when `E` is unknown or insufficient. | No default-on-error/missing state served as established state; no stale cache after commit; no inferring `E` from returned values; no state read through clones/handles that bypasses gate. The cursor cannot make a state-dependent caller current to `C`. | Inventory every public/private reader, clone, cache, runtime, EVM/RPC/P2P and raw handle. Static call/data-flow audit plus bypass tests for missing/corrupt state, stale cache, lag and alternate handles. Current complete consumer inventory is unavailable. |
| **R3. Acknowledgement and retry reader** | Same operation ID, authenticated position, exact order/count and retained completion in the atomic unit. May return the original completion only after verifying the whole unit/currentness. | `E` alone, success counters, balances, or a duplicate request cannot synthesize acknowledgement or per-transaction success. No blind re-execution when result is absent, pruned, conflicting or unknown. | Exact schema/API test matrix for committed success including failed transactions, unknown/unavailable and missing fields; prove retrieval is operation-bound and independent of proof-byte-only differences under approved equivalence policy. |
| **R4. Snapshot, restore, replay and migration readers** | Restricted inspection may read `E` and compare it with separately authenticated consensus/finality history and state manifest. Snapshot can claim a prefix only if its state is proven to equal that prefix. Restore/cutover requires separate authority and explicit position semantics. | `E` must not flow through `SnapshotAnchor` or `StateSnapshotMeta.height` into `RestoreBaseline`, `initialize_from_snapshot_baseline`, committed tip/current view, trust activation, or catch-up. Do not equate state snapshot height with consensus height without proof. | Trace snapshot production, metadata, restore, replay and every startup configuration. Require dual-position/authority review if schemas are changed; mismatch/gap tests; audit no cursor-derived value reaches consensus baseline or activation. Current state/snapshot prefix equivalence is unestablished. |
| **R5. Status/metrics/lag derivation** | May expose distinctly labeled `execution_applied_position` and, only when comparable, diagnostic `C-E` status. May trigger a fail-closed refusal under a separately approved policy. | No alias to consensus `committed_height`, `current_view`, `committed_anchor`, activation height, signer view or “finalized” metric. No threshold/lag limit is chosen here. | Metric/API schema review and serialization/call-graph audit; tests that updates cannot mutate consensus or signing inputs; prove missing/mismatched positions report unavailable rather than a numeric default. |
| **R6. Restricted recovery inspection** | Separately authorized, read-only verifier may inspect `E`, unit records and proof/currentness evidence to report committed/prepared/conflicting/unknown status. It may not resolve authority by itself. | No cursor-only recovery authorization, rollback anchor, owner election, abort/roll-forward, fence release, normal read/write access, node startup, signer activation or participation. | Independent recovery authority/evidence specification; nonmutating inspection semantics; access-control/bypass and restart tests; separate signing-history continuity review. All remain OPEN. |
| **Forbidden consensus consumer: `last_committed` / tip / lock / view** | Consensus authority and authenticated consensus history only. | No direct E read or indirect conversion via account state, snapshot, cache, migration, replay, callback, metrics or API may set `ConsensusStorage.last_committed`, `committed_block`, `committed_height`, `locked_qc`, `current_view` or commit/finality decisions. | Repository-wide call graph and symbol/data-flow proof across feature/build modes; API types that prevent interchange; negative tests on restart, proposal/vote/catch-up and snapshot-baseline routes; runtime attestation of actual read sources. |
| **Forbidden consensus participation/finality consumer** | Existing consensus engine, validator rules, authenticated QC/history and independent consensus policy only. | No E-derived “caught up” status, P2P catch-up anchor/exit, proposal deferral/admission, quorum/finality or epoch/ruleset transition authorization. If a path depends on VM state and that dependency is unestablished, refuse that path; do not make E its authorizer. | Audit `binary_consensus_loop`, engine callbacks, P2P, epoch and governance transitions; prove inputs trace only to approved consensus sources; targeted prohibited-flow and bypass tests. |
| **Forbidden signing-reservation consumer** | Existing signing domain and consensus `originating_view`, message kind, validator and network/genesis identity. | No E or E-derived height/view may construct `SigningPosition`, alter journal keys/bindings, reserve/retrieve a signature, clear a reservation or authorize signing. Never move or merge signing records as cursor migration. | Source/type/data-flow audit of every signer/journal call site; tests showing E changes cannot alter canonical signing position or journal outcomes; inspect built production artifact/runtime data source. Signing-history continuity remains a separate OPEN requirement. |
| **Forbidden activation/currentness consumer** | Existing independently approved trust/activation authority and its reviewed current-height/epoch sources. | No direct/indirect E flow into `ActivationContext`, trust-bundle validation/reload/apply, key or ruleset activation, or any freshness/revocation decision. Snapshot metadata must not become a covert E-to-activation bridge. | Audit startup, CLI validation/reload/apply, restore and activation calls; assert exact source provenance in tests/runtime traces; prove no E-derived snapshot field is consumed by activation. |

### Direct and indirect flow review

The following chains are explicit **prohibitions**, not claims that current
QBIND already has the cursor:

1. `E -> SnapshotAnchor.height -> StateSnapshotMeta.height ->
   RestoreBaseline.snapshot_height -> initialize_from_snapshot_baseline ->
   HotStuff committed_height/current_view`. The current restore path maps
   snapshot metadata height into a consensus baseline. Any future snapshot
   design must carry distinct authenticated execution and consensus positions
   or block restore until their relation is independently established. This
   assessment selects neither.
2. `E -> snapshot/restore height -> ActivationContext.current_height ->
   trust-bundle activation/reload`. The inspected pre-consensus path currently
   uses snapshot baseline height or zero; E must not influence that input.
3. `E -> committed_anchor / metrics -> snapshot trigger or P2P catch-up`,
   including `RestoreCatchupRequest`, proposal-deferral and catch-up-exit
   predicates. Those positions are derived from the consensus engine today.
4. `E -> current_view/originating_view -> SigningPosition ->
   signing-reservation journal -> signer`. The journal position remains
   consensus-originated and independently governed.
5. `E -> storage `meta:last_committed`/block/QC -> restart loader ->
   committed tip/lock/view`. This would repurpose consensus state and is
   prohibited.
6. `E -> recovery status -> fence release/return-to-service`, or
   `E -> enrollment/currentness/revocation -> trust or participation`.
   Cursor integrity is not an external anti-rollback or recovery authority.
7. Any renamed scalar, cache entry, snapshot filename, callback field,
   telemetry projection or API response carrying E must retain its distinct
   type/meaning and cannot be reinterpreted as a consensus height by a
   downstream consumer.

The current snapshot trigger is keyed to a consensus `SnapshotAnchor` and
copies VM account state. The inspected path has no execution-cursor check.
Because asynchronous execution and consensus progress are distinct, equality
between that anchor and the state prefix is not established by this source.
Until a separately reviewed snapshot/restore contract proves the relation,
snapshot operations that require an exact state position must refuse or mark
the position unavailable; do not infer equality or use E as a consensus
baseline. Continuously requiring `E == C` is not selected.

## 4. Lag, refusal and failure states

Let `C` denote the independently authenticated consensus position and `E`
the candidate account-state execution prefix. These are not interchangeable.
No allowed lag value or liveness policy is selected.

| Observation | Candidate response |
|---|---|
| First use; no authenticated initial state/cursor record | `UNENROLLED`; ordinary state reads, execution, acknowledgement, signing/participation that depends on state, and activation refuse. Missing key/empty DB is not genesis proof. |
| `C` and finality evidence unavailable, stale or not bound to exact inputs | No cursor advance or acknowledgement. State-dependent reads that require that decision remain unavailable. Signing/participation cannot use E to bypass consensus policy. |
| `C` is ahead of a valid established `E` | `E` describes only its applied prefix. No acknowledgement or state read claiming the newer prefix. A separately authorized catch-up execution may be considered only after exact next-input verification; this task does not authorize or decide it. Whether consensus may advance while lag exists is OPEN for separate safety/liveness review. |
| `E` unknown, behind by an unknown amount, or source state cannot be tied to E | Close state-dependent reads, writes, execution result, acknowledgement and operations depending on current execution state. Do not infer the gap from balances, height, queue length or snapshots. |
| `E` conflicts with authenticated history, is ahead of C without approved proof, has a predecessor gap, or duplicate position has a different subject/input/ruleset | Quarantine; no overwrite, rollback, acknowledgement or re-execution. Require separate authorized inspection. |
| Proposal/input parser skips malformed transaction or count/order differs | Refuse before effects; no cursor advance/ack. This is required because the inspected simulator decoder currently logs and skips malformed entries (`hotstuff_node_sim.rs:3038-3115`). |
| Execution write/flush or atomic commit returns error/unknown | Keep ordinary access gated; report unknown/unavailable. Do not use the local worker height, later flush or matching state to claim commit. Do not re-execute blindly. |
| Crash before failure marker, during commit, or after commit before response | Start gated. Resolve only by restricted inspection of the prepared/committed operation and complete unit. Without proof, status remains unknown/unavailable and no acknowledgement is fabricated. |
| Consensus/signing operation appears state-dependent while E is unknown/behind | Refuse that dependent operation pending a separately approved policy and proven state. Do not use E to authorize the operation or change the consensus/signing position. The full current dependency inventory is unavailable. |
| Snapshot or restore position relation unknown | Do not label copied account state as matching consensus `C` or feed E into `RestoreBaseline`/activation. Refuse or mark unavailable under the later approved contract. |

Whether asynchronous consensus may keep advancing while E lags, what
operations are allowed during catch-up, and whether any liveness policy uses a
bound remain **OPEN**. A policy requiring E always equal C is not chosen and
needs its own safety/liveness review.

## 5. Atomic unit, enrollment and migration blockers

The candidate commit includes all account values and membership, E and its
authenticated predecessor, stable operation/commit identity, exact executed
input order/count, acknowledgement and entitled outcomes. Required result
references and target bytes must share the same reviewed unit. E alone is not
an atomic primitive, fencing token or durable write.

**Migration/cutover is BLOCKED.** The current persistent account path has no
execution cursor; worker height is process-local and may advance after a
flush error; consensus `last_committed` seeds consensus safety and cannot
substitute for the account applied prefix. No available source evidence ties
the existing account image to an exact finalized ordered input prefix.

Future requirements (not operations authorized here):

- Initial enrollment must independently authenticate deployment/genesis,
  backend instance, account values **and membership**, ruleset/schema and
  exact initial execution prefix. Do not assign zero or infer from absent
  metadata.
- Migration source and target identity, snapshot contents, prefix evidence,
  cursor and completion must be independently associated and authenticated.
  Existing-only restore openers do not provide this migration authority.
- Before cutover, quiesce/join workers and fence every process, retained
  handle, alias, old binary, maintenance path, reader, writer and flusher.
  A mutex, worker claim or advisory lock alone is insufficient; enforce the
  fence at the backend/write boundary and provide platform evidence.
- Cutover publishes exactly one current generation. Competing source/target,
  interrupted cutover, missing evidence or uncertain decision means both
  paths remain gated. No automatic fallback or choosing the “higher” cursor.
- Rollback is allowed only with separate authority and proof that no
  post-cutover committed execution would be lost. Otherwise quarantine and
  separately authorize forward recovery.
- Currentness, stale-owner revocation, external anti-rollback, recovery
  authority and signing-history continuity remain OPEN. E cannot establish
  any of them.

## 6. Evidence matrix and feasibility decision

| Classification | Current statement | Evidence needed before any implementation entry |
|---|---|---|
| **Established source facts** | Account DB and consensus DB are separate; account API has per-key operations and no durable execution cursor; worker progress is local; `last_committed` restores consensus tip/lock; signer history has its own records under the consensus store; snapshot/restore and activation have indirect consensus-height paths; simulator decode can skip invalid transactions. | Pinned source and complete caller/use-path audit across production binaries, features, startup, callbacks, snapshots, caches, APIs and direct storage access. Existing source statements do not prove future gates. |
| **Owner decisions** | Distinct execution-applied cursor; no repurposing of consensus safety or signing-history authorities; required atomic unit and future submitter acknowledgement semantics. | Confirm any unresolved semantics of position tuple, first-use authority and lag/catch-up policy. No mechanism is chosen by this specification. |
| **Candidate requirements** | One producer: atomic execution commit. Readers use E only for the exact applied prefix, duplicate/result lookup and fail-closed gating. Restricted inspection cannot authorize return to service. | Reviewed typed API/data-flow boundary, backend atomicity/durability contract, membership semantics, no-bypass fencing and identity-bound result retrieval. |
| **OPEN identity/trust prerequisites** | Six identity bindings; proof equivalence/reverification/currentness; native post-quantum construction; external deployment/backend and ruleset authority. | Independent authority evidence and security review. Valid equivalent proofs must preserve stable semantic identity; no current route/policy is claimed. |
| **OPEN non-entanglement proof** | Design matrix says where E may and may not flow. It is not implementation proof. Snapshot height currently feeds consensus restore baseline and trust activation; signer position is consensus-view based. | Source and dependency/call graph plus taint/type review proving no direct/indirect E flow into consensus safety/finality, `last_committed`, signing, recovery or activation. Review every build/configuration and generated/runtime call path. |
| **BLOCKED migration** | Source account image cannot currently be tied to exact finalized applied prefix; there is no persisted E. | Authenticated source-prefix proof, enrollment authority, state/membership manifest, old-writer fencing, cutover/rollback evidence and recovery review. |
| **FUTURE validation** | No tests, builds, runtime traces or experiments are performed or authorized here. Earlier 5/5 capability evidence remains author evidence for its limited characterization only, not joint atomicity or power-loss safety. | **FUTURE / NOT AUTHORIZED / NOT EXECUTED:** source/call-graph audit; type/API compile checks; positive/negative exact-input and identity tests; direct/indirect prohibited-flow bypass tests; lag/unknown/startup/snapshot/activation/signing separation tests; feature/build matrix; runtime traces showing actual sources and fail-closed outcomes; backend, migration, fencing and separately scoped process/OS/power-loss evidence. Each needs later separate approval. |

### Feasibility verdict

- **Cursor definition:** a distinct execution-applied cursor is a coherent
  candidate specification, not an existing source interface.
- **Non-entanglement:** **OPEN/BLOCKED.** It is plausible only as a distinct
  cursor that leaves `last_committed`, committed tip/lock, QC history and
  signing journal untouched. The source does not yet prove exhaustive
  non-entanglement. Moving or aliasing current consensus position is outside
  this candidate and needs separate review.
- **Finality/input handoff:** **OPEN/BLOCKED.** The inspected service accepts
  `QbindBlock`, and the simulator can skip malformed encodings. No reviewed
  typed handoff proves all six bindings or exact executed inputs.
- **Atomicity/migration:** **BLOCKED.** Current two-store paths have no joint
  commit and current account state lacks a durable cursor; source-prefix
  migration evidence is absent.
- **Implementation feasibility overall:** **UNPROVEN, not proven impossible.**
  Required evidence includes the use-proof, an exact finality/input interface,
  a reviewed single transaction domain and migration/recovery boundary.

## 7. Smallest next owner decision

Confirm that the authoritative value is a distinct, potentially lagging
execution-applied prefix, and explicitly exclude consensus `last_committed`,
HotStuff lock/view, signing position, recovery authority and activation
context. Then commission a reviewed source/use-path proof and finality/input
handoff specification before deciding whether any later implementation or
validation work is warranted. This is the next decision only; no production
mechanism, lag policy, backend, key, wire format, retention period or
recovery authority is selected.

## 8. Pinned sources and inherited scope

Pinned source endpoint and reviewed assessment are stated at the top.
Principal source paths and ranges:

- `crates/qbind-node/src/execution_adapter.rs` (232-242, 460-505,
  1049-1067, 1315-1382, 1492-1525).
- `crates/qbind-node/src/hotstuff_node_sim.rs` (2020-2150, 3028-3125,
  3198-3222).
- `crates/qbind-node/src/storage.rs` (168-224, 719-754, 929-1025,
  1456-1535).
- `crates/qbind-consensus/src/hotstuff_state_engine.rs` (291-450,
  1991-2020); `crates/qbind-consensus/src/basic_hotstuff_engine.rs`
  (2598-2685).
- `crates/qbind-node/src/signing_reservation_journal.rs` (1-37, 150-195);
  `crates/qbind-node/src/binary_consensus_loop.rs` (2330-2350,
  8380-8655, 9168-9255).
- `crates/qbind-node/src/main.rs` (2878-2905, 3012-3035, 3415-3438,
  4382-4405, 6570-6610); `crates/qbind-node/src/pqc_trust_activation.rs`
  (55-75, 185-230); `crates/qbind-node/src/snapshot_restore.rs`
  (230-335).
- `crates/qbind-ledger/src/execution.rs` (1130-1141, 1258-1285,
  1380-1483); `crates/qbind-ledger/src/state_snapshot.rs` (91-135).
- `crates/qbind-node/src/node_config.rs` (5271-5291);
  `crates/qbind-node/src/vm_v0_runtime.rs` (15-32, 174-260);
  `crates/qbind-node/src/production_consensus_storage.rs` (353-375);
  `crates/qbind-node/src/commit_index.rs` (1-140);
  `crates/qbind-wire/src/consensus.rs` (915-950).
- Reviewed assessment:
  `docs/security/evidence/option-a-execution-position-consolidation-assessment-20261109.md`,
  blob `6d60b089d15dece962f87c656d739e842501bd29`.
- Reviewed atomic-commit design:
  `docs/security/evidence/future-submitter-acknowledgement-atomic-commit-design-20261109.md`,
  blob `03415268e14818eac314f99903a77cf4bea33d86`.

The assessment endpoint inherited 50 changed paths versus pinned `main`.
The verified inherited manifest is:

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

The sole additional path versus `2211d0f67f682ac11189995d9839b040128ba506`
is:

```text
A docs/security/evidence/distinct-execution-cursor-finality-handoff-nonentanglement-20261110.md
```

Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**.
Recipient overflow, A23-F1 and A33-F1 / E27 remain **OPEN**; the six identity
bindings and native post-quantum construction remain **OPEN**; activation
remains **DISABLED**; public DevNet remains **NO-GO**. Preserve all prior
scoped dispositions. The independent reviewer maintains the carry-forward
record.
