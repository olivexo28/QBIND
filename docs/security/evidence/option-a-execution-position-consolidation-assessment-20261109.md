# Option A: execution-position consolidation assessment

## Status and scope

**DOCUMENTATION ONLY / SPECIFICATION AND FEASIBILITY ASSESSMENT.** The owner
selected Option A as a direction to investigate, not as a feasibility verdict
or storage-mechanism decision. No implementation, migration, experiment,
startup, integration, signing, recovery, activation or DevNet action is
authorized by this assessment. All proposed evidence is **FUTURE / NOT
AUTHORIZED / NOT EXECUTED**.

The assessment uses source pinned to design endpoint
`35ba53e62a7dd9e157821d78d2087a8f3c812e69` (tree
`23a724090315ee4ca10df62afc44b4aedd62de3b`), whose parent is
`9b3cec9a850c53afababe17b2adc949631af48af`; pinned `main` is
`aa382fa28b2d3e97e6203d47fa8231b5f2269741`. The reviewed Option A/B design
is `docs/security/evidence/future-submitter-acknowledgement-atomic-commit-design-20261109.md`,
blob `03415268e14818eac314f99903a77cf4bea33d86`.

Labels: **SOURCE FACT** is what the pinned code exposes; **OWNER DECISION**
is the supplied direction or requirement; **CANDIDATE REQUIREMENT** is a
property a later design must satisfy; **ASSUMPTION** is not demonstrated;
**OPEN/BLOCKED** means the needed authority, evidence or decision is absent.

## 1. First question: which position?

### Source and authority map

| Name in this assessment | Pinned source fact | Authority and limitation |
|---|---|---|
| Execution-adapter `current_height` | `ExecutionAdapter::current_height` is an API accessor. `InMemoryExecutionAdapter` stores it in a field initialized to 0 and updates it only after synchronous block execution succeeds (`crates/qbind-node/src/execution_adapter.rs:232-242, 302-368`). | **In-memory execution progress**, not durable state position and not proof of finality. |
| Async worker `current_height` | The worker initializes a local variable to 0 on each worker loop. Its VM-v0 path executes transactions, attempts a state flush, logs flush failure, then assigns the task block height (`execution_adapter.rs:1049-1067, 1315-1382`). | **Process-local progress only.** It is not a restartable account-state cursor; advancing it after a failed flush is not durable commit evidence. |
| Async block input | `submit_block(QbindBlock)` returns enqueue, queue-full or shutdown. The worker claim and operation mutex are process-local. The inspected `hotstuff_node_sim.rs` path dispatches a committed proposal/decoded transactions to this service and later removes transactions from the mempool; no durable completion is returned (`execution_adapter.rs:460-505, 1492-1525; hotstuff_node_sim.rs:3110-3222`). | Queue admission and a local worker claim do not establish durable execution or a finality-authenticated execution cursor. This simulator/harness route does not establish that an ordinary production caller uses the same path. The inspected dispatch contains a proposal and decoded transactions; no explicit verified-finality handoff/result type is established. |
| Consensus `last_committed` | `ConsensusStorage` exposes `put/get_last_committed`, block and QC operations, and epoch methods. Production opens a `RocksDbConsensusStorage` at `<data_dir>/consensus`; the VM account runtime opens `RocksDbAccountState` at `<data_dir>/state_vm_v0` (`storage.rs:168-224, 719-754, 929-1025; node_config.rs:5271-5291; production_consensus_storage.rs:353-375; vm_v0_runtime.rs:58-90`). The inspected simulator persists block, then QC, then `last_committed` using separate calls (`hotstuff_node_sim.rs:3198-3222`). | **Persisted consensus commit metadata** in a store separate from accounts. The ordinary `last_committed` put is a separate DB write; a consensus epoch `WriteBatch` is atomic only within the consensus DB (`storage.rs:1110-1160`). Neither establishes joint account/position atomicity or a power-loss contract. |
| Consensus engine tip and lock | `HotStuffStateEngine` holds `committed_block`, `committed_height`, `locked_qc`, vote/lock state in engine memory. Restart loads `last_committed`, its block and QC, chooses a conservative lock and calls `initialize_from_restart`; the engine sets the committed tip and next view (`hotstuff_state_engine.rs:291-450, 1991-2020; basic_hotstuff_engine.rs:2548-2610; hotstuff_node_sim.rs:2020-2150`). | **Consensus safety/restart state.** `last_committed` is not a disposable execution watermark: the inspected restart path uses it to seed the safety engine and reconstruct a lock. This assessment does not authorize moving or redefining it. |
| Consensus commit index | `CommitIndex` is an in-memory height-to-commit map and enforces monotonicity/conflict checks (`commit_index.rs:1-140`). | An additional node-level **in-memory consensus index**, not durable execution progress. |
| Signing history | The signing journal is explicitly a signing-reservation journal, not signing authorization or an anti-rollback anchor; its module says it is not wired to production activation (`signing_reservation_journal.rs:1-37`). Its `SigningJournalStorage for RocksDbConsensusStorage` reads/writes records in that same DB under a separate namespace and has synced write operations (`storage.rs:1456-1535`; key prefix and record definitions in `signing_reservation_journal.rs:44-59`). | **Separate signing-history state and failure domain**, not an authority to sign. Relocating/replacing the consensus DB or treating its records as execution metadata would risk coupling this history. It must remain untouched and separately governed. |
| Proposal representation | Canonical signed proposal body includes header fields, embedded QC bytes and length-prefixed ordered transactions (`qbind-wire/src/consensus.rs:915-950`). | Does not by itself establish external finality evidence, execution correctness, or currentness. |

**SOURCE FACT:** the inspected persistent VM account interface has no durable
block/execution-position method. Reads collapse missing account, decode
failure and I/O error to a default value; the updater's setter has no error
return (`qbind-ledger/src/execution.rs:1130-1141, 1258-1285, 1380-1483`).
The worker's `current_height` is reset on worker start, while account writes,
flush and in-memory progress are separate operations. Source therefore does
not establish what finalized position a given persistent account image
represents.

### Authority-separation verdict

**Verdict: OPEN / BLOCKED, not proven impossible and not proven safe.**

There is a plausible architectural distinction, but it is not yet a source-
established interface:

- Keep consensus `meta:last_committed`, block/QC history, engine committed
  tip/lock and signing journal in the existing consensus authority.
- Define a **new execution-applied position** in the account transaction
  domain. It means "this exact authenticated finalized decision and ordered
  input set was executed into this account state", not "HotStuff committed
  through this height" and not "this validator may sign or participate".
- Permit this execution cursor to lag consensus progress while work is
  queued. Require authenticated, contiguous catch-up from the exact previous
  execution cursor. Never feed the execution cursor into HotStuff lock,
  vote/view, finality, signer reservation, or activation decisions.

This separation is a **candidate definition**, not a behavior established by
QBIND. The source does not establish (a) an authoritative durable execution
cursor; (b) a typed verified-finality/input handoff from the consensus
decision to a persistent executor; (c) the full set of production consumers
of height/progress; or (d) a proof that no execution-position value is used
to authorize consensus safety or signing/recovery. The async submitter API
accepts a `QbindBlock` and reports admission only. An owner must confirm that
the desired authoritative position is this distinct execution-applied cursor.
If the owner instead means the existing consensus `last_committed` position,
moving it is outside this option as specified and would require separate
consensus-safety review; do not silently reinterpret it.

## 2. Option A candidate boundary and interface

**OWNER REQUIREMENT:** one transaction domain must atomically bind:

1. Account values **and membership** (including absent, present-default,
   created and deleted accounts).
2. Authenticated authoritative execution position and predecessor.
3. Stable operation/commit identity.
4. Exact transaction bytes actually executed, their order and count (or a
   complete integrity-bound representation whose required bytes are also
   available within this reviewed unit).
5. The block acknowledgement and every caller-entitled outcome.

**CANDIDATE DOMAIN:** the future VM execution-state domain could own an
`ExecutionCommitStore` interface with typed fallible snapshot reads, a
durable prepare/intent operation, a staged account-membership/value view,
`commit_block(unit)` and authenticated lookup/inspection by stable operation
identity and execution position. This is a conceptual interface only; no
backend or primitive is selected. It must not be a wrapper that performs
independent per-account writes and then separately updates a cursor.

The boundary must define snapshot/conflict semantics, membership and deletion
representation, canonical encoding/size bounds, retention, versioning,
commit identity, and typed outcomes for committed, definitely-not-committed,
unknown and unavailable. A commit success may be reported only after the
backend's reviewed contract establishes the complete unit. The account store's
current defaulting read and void-returning updater need replacement or a
separate fallible staging layer; worker write failures must reach the operation
result rather than be silently dropped.

No single-database batch is assumed to meet this contract. A database's
atomic visibility and configured durability are distinct; a primitive must be
reviewed for the actual unit, API version/options, error cases and failure
model. Current account `put`/`flush` plus the existing consensus `last_committed`
write do not provide this boundary.

### Preconditions and authority sources

| Precondition / binding | Candidate evidence source | Current status |
|---|---|---|
| 1. Authenticated finality for stable decision subject | Consensus authority under an owner-authorized finality policy; must identify the exact finalized subject and evidence. | **OPEN.** Existing commit callback follows `new_commits`, but no executor-facing verified-finality contract or recovery-grade authenticated evidence is established. |
| 2. Exact executed inputs | Verified canonical proposal/input bytes, exact decode result and ordered count passed to executor; commit unit retains bytes or an integrity-bound available manifest. | **OPEN.** Proposal canonical body includes embedded QC and transactions, but current async API accepts decoded `QbindBlock`; equality and durable binding are not established. |
| 3. Position and predecessor continuity | Consensus-finalized subject plus account-domain execution cursor; independently check exact predecessor and contiguous execution policy. | **OPEN.** No durable VM execution cursor exists in the inspected interface. Need owner decision whether execution may lag and how skipped/replayed decisions are handled. |
| 4. Deployment/backend association | Independently authenticated deployment and state-instance identity, path/namespace binding, enrollment and replacement history. | **OPEN.** A configured directory or local metadata alone is not independent authentication. |
| 5. Authorized ruleset and transition history | Independently authorized execution-ruleset/schema history at the decision position; supported by the exact executor binary. | **OPEN.** No such proof is supplied by a local configuration flag or by execution height. |
| 6. Durable commit/completion binding | Same reviewed transaction unit contains state/membership, execution position, identity, exact order/count and acknowledgement/outcomes. | **UNPROVEN.** The two current stores expose no joint API. |
| Native post-quantum integrity/authentication | Owner-approved native trust construction covering authority evidence, operation/commit record and retrieval. | Requirement fixed; construction, parameters, roots, composition and demonstrated security remain **OPEN**. |

For alternate finality representations, the operation identity must be based
on the stable authenticated decision subject or an owner-approved deterministic
equivalence/selection rule, not unexamined proof bytes. Reverify each proof or
reuse a durable authenticated equivalence record only when policy version,
subject, deployment, context, revocation and currentness are re-established.
Different bytes alone must not create a conflict. Invalid, unauthorized,
wrong-subject, non-equivalent, stale or unavailable evidence refuses or yields
unavailable. The signed proposal's embedded QC bytes are covered by its
canonical body; external finality evidence is not thereby covered. No
applicable QBIND route or equivalence/currentness policy is claimed.

## 3. Candidate execution, commit and acknowledgement

Every step is a **CANDIDATE REQUIREMENT / UNIMPLEMENTED**.

1. **Start gated and establish ownership.** Independently authenticate the
   target backend/deployment, currentness, prior execution cursor and fencing
   generation. Keep ordinary reads/writes, flushes and worker claims refused
   until inspection finishes. No first-use inference from missing DB keys.
2. **Admit authenticated work.** Validate all six bindings, exact finalized
   proposal/input relation, authorized ruleset and predecessor. Admission or
   queue acceptance remains distinct from execution/commit.
3. **Resolve duplicate first.** Look up the stable operation identity and
   execution position. Return the original retained result only if the
   complete unit and currentness are authenticated. Prepared/unknown/conflicting
   work remains gated; absence is not evidence that it never ran.
4. **Durable preparation.** Record operation identity, exact input/order/count,
   predecessor, ruleset/schema and backend/fence identity before any effect
   can escape. If preparation is uncertain, do not execute; inspect under the
   restricted recovery path. Alternatively, a transaction primitive may prove
   staged effects cannot become visible absent its atomic decision, but that
   proof must cover crash before any post-failure marker could be written.
5. **Execute in isolation.** Read a coherent membership-aware snapshot and
   compute writes and ordered outcomes in an isolated candidate state. Keep
   worker errors distinct from VM transaction failures. Do not mutate
   published per-account keys during calculation. An error in any state
   access or write invalidates or quarantines the candidate unless definite
   no-publication is established.
6. **Validate and commit once.** Recheck fence and predecessor; validate
   identity, membership, exact executed order/count and outcome completeness.
   The one transaction publishes all values/membership, execution position,
   operation/commit identity, input binding, acknowledgement and every
   entitled outcome. The linearization point and durability semantics must be
   documented for the selected backend. No live height/cache/result is exposed
   as committed before this point.
7. **Acknowledge/retrieve.** Only after durable commit is established and the
   same operation's entire required record is authenticated/retrievable may
   the future submitter receive an operation/position-bound acknowledgement.
   It means committed execution under applicable rules, **not** that every
   transaction succeeded. Entitled failures/results remain ordered and bound
   to the same unit. EVM receipts and all other callers' durable outcome
   entitlements remain OPEN; unresolved fields stay unavailable or retained
   pending decision.
8. **Unknown or lost response.** Commit return errors/timeouts, missing result
   fields or an unresolvable identity produce unknown/unavailable and closed
   ordinary access. Do not infer success from balances, height, a later flush
   or queue admission. Do not fabricate an acknowledgement or blindly
   re-execute.

## 4. Migration-safety requirements - design only

**SOURCE FACT:** current VM account writes do not carry a durable block cursor;
the worker's local height is reset on worker startup. Consensus `last_committed`
is persisted separately, is used to restore HotStuff's committed tip and
locked QC, and cannot be assumed to equal the account state's applied-through
position. Async enqueue and worker execution/flush are distinct. Therefore a
copy of current balances plus `last_committed` does not prove a consistent
execution snapshot.

The existing VM runtime has both a create-if-missing opener and an
existing-only opener for a separately admitted `COMPLETE` restore transaction
(`vm_v0_runtime.rs:58-141`). That restore-specific boundary is not a general
execution-position migration, authenticated source/target association or
authority to cut over.

| Migration state / interruption | Required candidate behavior |
|---|---|
| Source identification | Independently bind source VM DB, consensus DB, deployment/chain, schema/ruleset and versions. Preserve provenance for block/QC history and signing records. If source authority or namespace is ambiguous, refuse migration. |
| Quiescing | Close submit, execution, account reads/writes and flush paths; stop and join workers; fence every old process/handle and maintenance route. A process mutex, worker claim or advisory lock alone is insufficient. Require platform/backend evidence that no stale writer can mutate source or target. |
| Snapshot and position proof | Capture account values **and membership** from a coherent source snapshot. Derive target execution position only from authenticated complete history or separately authorized enrollment evidence. Because no persisted execution cursor exists, if source state cannot be tied to a precise finalized input prefix, the cutover is **BLOCKED**; do not substitute consensus `last_committed`, balance matching or local worker height. |
| Target staging | Copy/import into an isolated target namespace with an authenticated manifest binding source/target identities, contents/membership, chosen execution cursor, schema/ruleset, finality/input history and migration generation. Independently validate the manifest and target before admission. No production path is wired by this document. |
| Cutover | Publish a single authenticated cutover decision under an enforceable fence; admit only the target generation. Keep existing consensus DB, `last_committed`, block/QC history and signing journal under their existing authority. No dual writing or simultaneous active source/target. |
| Interrupted or uncertain cutover | Gate both generations. Recovery must authenticate whether cutover was committed and prove exactly one authorized current backend. If it cannot, result is unavailable; no automatic fallback to the old copy. |
| Rollback request | Permit only if evidence proves no execution/commit occurred on the target after cutover and authority/currentness is preserved; otherwise rollback would discard committed effects. Prefer a separately authorized forward recovery. No rollback procedure or authority is selected. |
| Missing evidence or competing authorities | Quarantine. Preserve both copies and evidence; do not choose newest timestamp, highest height, directory name or matching balances. Independently authorized recovery and first-use enrollment remain OPEN. |

Changing the execution backend namespace/path also requires proving that
old binaries cannot reopen the prior state and that retained RocksDB handles,
renamed directories, mount aliases, snapshots and maintenance tools are fenced.
The deployment/backend association must bind the actual storage instance, not
only a path string. A new execution cursor must not be allowed to seed
`BasicHotStuffEngine::initialize_from_restart`, consensus lock/view, signing
journal position or validator participation.

## 5. Crash and recovery boundaries

| Failure model | What a later claim would require |
|---|---|
| Process crash | Backend transaction recovery and intent ordering establish old-or-new visibility after process death. Clean close/reopen is weaker evidence than abrupt process termination. Resolve the same operation before retry; ordinary service starts gated. |
| OS crash | Prove WAL/write synchronization and ordering across metadata, data and any filesystem namespace operations. Process-crash results do not prove kernel/page-cache loss safety. |
| Power loss | Identify exact backend/native build and options, filesystem/mount, kernel, controller/device caches, flush/barrier behavior and power-loss protection. Prove the selected durability contract under those assumptions. Do not generalize a successful flush or restart. |

Preparation must be durable before any externally visible effect, or the
selected transaction must prove no partial effect is visible before commit.
If a process dies before a failure marker can be written, the earlier durable
intent or transaction recovery record must still force inspection/refusal.
If preparation itself is ambiguous, execution does not begin. A commit error
or durability-barrier failure is unknown unless the primitive plus authenticated
inspection resolves the entire unit.

Restart first opens only a restricted inspection path while ordinary reads,
writes, flushes, workers, signing and participation remain refused. Inspection
may authenticate and read bounded metadata, verify records/currentness,
compare source and target manifests, and determine whether a migration/commit
decision exists. It must not create/repair the DB, mutate records, compact or
flush, release a worker claim, sign, initialize the node for participation,
or expose state through a normal read API. If the backend cannot support
nonmutating restricted inspection, that is another feasibility blocker.

Recovery authority, currentness/revocation, first-use enrollment, ownership
fencing, abort/roll-forward authorization and signing-history continuity
remain OPEN. VM-state recovery alone does not authorize Proposal/Vote
signing, consensus participation or service activation.

## 6. Option B and hybrid fallback

| Choice | Boundary and additional work | Principal cost/blocker |
|---|---|---|
| **Option B: preserve consensus position as authoritative** | Coordinate account/membership/result store with the consensus DB holding `meta:last_committed`, if the owner determines that exact consensus position must be part of the execution unit. Add durable prepare/participant versions, one authenticated coordinator decision, generation-aware reads, all-path fencing and restart reconciliation. Keep signing-journal records in their separate namespace and preserve their authority. | Consensus `last_committed` is used in engine safety restart. Publishing it independently from account state is unsafe for this requirement; gating every reader and safely resolving partial prepares/commits is unproven. More coordination, latency and fail-closed unavailability. No evidence makes every possible coordinator impossible. |
| **Hybrid: distinct execution cursor in account domain** | Leave consensus finality, `last_committed`, block/QC and signing-history authorities unchanged; add the candidate execution-applied cursor atomically with account state and completion. A verified finality/input handoff maps consensus decisions to cursor increments; consensus may be ahead while async execution catches up. | Likely the least entangling route, but the needed verified handoff, identity, separate-cursor semantics and no-consumer/use proof are absent. If the owner requires "execution position" to equal the consensus committed tip, this hybrid does not meet that meaning. |
| **A shown unsafe/infeasible?** | Not established. | Current interfaces fail the joint guarantee; that is not proof against redesigned storage. If separate execution cursor cannot be authorized or complete finality evidence cannot be delivered, A remains blocked and B needs separate specification/review. |

Option B/hybrid must define a single linearization point, prove no reader can
observe a mixed generation, and keep ordinary access blocked during partial
states. Cross-store success calls, local locks, markers or later flushes are
not substitutes. Coordinator loss may require indefinite unavailability to
preserve safety. No protocol, migration or fallback is selected.

## 7. Decision and evidence matrix

| Classification | Current statement | Required before implementation entry |
|---|---|---|
| **Established source facts** | Async submit is admission-only; worker height is local; account values are per-key in a separate DB; consensus `last_committed` is persisted in the consensus DB and used to reconstruct committed tip/lock; signing journal shares that DB through a separate key namespace; no inspected joint account/position API exists. | Full production/downstream caller and read/write/flush/worker/startup route inventory pinned to an approved endpoint. |
| **Owner-approved** | Investigate Option A only; no implementation/migration/experiment authorization. Joint unit includes account values/membership, authenticated execution position, operation identity, exact order/count, acknowledgement and entitled outcomes. Do not alter consensus safety or signing authority implicitly. | Owner confirms semantic definition of execution-applied cursor versus consensus committed tip and whether async lag is permitted. |
| **Candidate requirements** | Add separate execution cursor and one transaction domain, with explicit gates and acknowledgement/retry semantics. Keep consensus and signing authority unchanged. | Reviewed storage and execution interfaces; every state read/write including membership and errors covered; typed verified-input handoff; old-or-new visibility and failure contract. |
| **Assumptions** | Consensus-finalized decisions can be independently authenticated and mapped in order to execution tasks; stale writers can be fenced; target/source association can be authenticated; selected store can durably publish the entire unit. | Evidence for each assumption from the selected backend, platform and trust/authority design. No assumption may be inferred from local config, worker mutex, or balance/height agreement. |
| **OPEN/BLOCKED authority separation** | No durable execution cursor or explicit verified-finality execution handoff; `last_committed` is safety restart state, not shown to be movable. No exhaustive proof that execution progress is never used in other safety/signing/recovery routes. | Owner decision on separate cursor semantics; call graph/use proof; interface and recovery proof that cursor cannot authorize or seed consensus/signing state. |
| **OPEN/BLOCKED Option A** | Feasibility is unproven, not impossible. Current two-store path does not satisfy the unit. Migration cannot establish source state position from current durable metadata alone. | Backend primitive/API and durability semantics; migration provenance and source-prefix proof; independent deployment association; all six identity bindings; post-quantum construction; fencing; restricted recovery and crash evidence. |
| **Future validation** | Earlier 5/5 run remains author evidence for its limited synthetic characterization only; no joint atomicity or power-loss proof. | Every proposed test, fault injection, process/OS/power-loss assessment, migration rehearsal or capability experiment is **FUTURE / NOT AUTHORIZED / NOT EXECUTED** and requires separate owner approval. |

### Feasibility verdict

- **Can a separate execution-position authority be specified without moving
  consensus safety/signing authority?** Plausible as a new, distinct
  execution-applied cursor, but **OPEN/BLOCKED** until the owner confirms the
  semantics and source/use-path proof establishes non-entanglement. Moving
  existing consensus `last_committed` is not authorized and would require
  separate consensus review.
- **Does current QBIND meet Option A?** **No.** The existing account and
  consensus/position stores have no joint commit API, and execution progress
  is not durably recorded in the inspected worker interface.
- **Is Option A unsafe or impossible in every redesign?** **Not established.**
  A distinct cursor plus an authenticated input handoff may be feasible, but
  the owner decision, evidence and migration boundary are absent.
- **Does Option B solve this today?** **No.** It is only a fallback design
  direction and needs its own coordinator, fencing, recovery and availability
  proof.

## 8. Next owner decisions

1. Confirm whether the required execution position is a new applied-through
   cursor distinct from consensus `last_committed`; decide whether it may lag
   the consensus tip and how contiguous catch-up is defined.
2. Decide which authority can attest finality, exact inputs, ruleset and
   deployment/backend association to the execution service without granting
   it consensus safety or signing authority.
3. Decide migration enrollment/authority and what evidence can establish the
   old account state's exact execution prefix when no durable cursor exists.
4. Decide completion fields/retention for the future submitter; all other
   durable outcome entitlements, including EVM receipts, remain OPEN.
5. Decide availability/failure-model expectations and recovery authority.
   Select neither backend nor fencing primitive in this document.
6. If A is later shown infeasible or owner rejects the distinct cursor,
   authorize a separate B/hybrid specification; this assessment does not
   authorize its implementation or an experiment.

## 9. Pinned source and inherited status

Primary pinned QBIND paths inspected:

- `crates/qbind-node/src/execution_adapter.rs` (232-242, 302-368, 460-505,
  1049-1067, 1315-1382, 1492-1525).
- `crates/qbind-node/src/hotstuff_node_sim.rs` (2020-2150, 3110-3222).
- `crates/qbind-node/src/storage.rs` (168-224, 719-754, 929-1025,
  1110-1160, 1456-1535).
- `crates/qbind-consensus/src/hotstuff_state_engine.rs` (291-450,
  1991-2020); `crates/qbind-consensus/src/basic_hotstuff_engine.rs`
  (2548-2610).
- `crates/qbind-node/src/signing_reservation_journal.rs` (1-59);
  `crates/qbind-node/src/commit_index.rs` (1-140);
  `crates/qbind-node/src/startup_validation.rs` (681-711).
- `crates/qbind-ledger/src/execution.rs` (1130-1141, 1258-1285,
  1380-1483); `crates/qbind-node/src/node_config.rs` (5271-5291);
  `crates/qbind-node/src/vm_v0_runtime.rs` (58-90, 100-141);
  `crates/qbind-node/src/production_consensus_storage.rs` (353-375);
  `crates/qbind-wire/src/consensus.rs` (915-950).

Reviewed specification paths:

- `docs/security/evidence/future-submitter-acknowledgement-atomic-commit-design-20261109.md`,
  especially sections 2-9, blob `03415268e14818eac314f99903a77cf4bea33d86`.
- `docs/security/evidence/caller-completion-actual-store-failure-contract-20261109.md`,
  blob `5644b132d591b5402ce21b7b75a27f68c911b599`.
- `docs/security/evidence/candidate-durable-execution-recovery-protocol-20261109.md`,
  blob `e48d199a8544faa353036e0127cc7e874339689d`.
- `docs/security/evidence/atomic-block-retained-completion-capability-experiment-20261109.md`,
  blob `1b4d45b1543f38963c109803bd1eeed148a2b5f2`.

The reviewed design endpoint differs from pinned main in 49 inherited paths.
The exact inherited manifest is:

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

The current assessment adds exactly one path versus
`35ba53e62a7dd9e157821d78d2087a8f3c812e69`:

```text
A docs/security/evidence/option-a-execution-position-consolidation-assessment-20261109.md
```

Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**.
Recipient overflow, A23-F1 and A33-F1 / E27 remain **OPEN**; activation
remains **DISABLED**; public DevNet remains **NO-GO**. Preserve prior scoped
dispositions. The independent reviewer maintains the carry-forward record.
