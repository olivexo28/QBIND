# Caller completion and actual-store failure contract

## Status and scope

The owner selected **atomic block publication with retained completion** as
the primary candidate. The reviewed capability experiment did not establish
the required joint durable commit; production implementation entry remains
**BLOCKED**. This document proposes a caller-completion and failure contract
for independent review. It does not authorize implementation, select a
backend or cross-store protocol, or establish that a current QBIND route
provides the proposed guarantees.

The reviewed refs were `main` at
`aa382fa28b2d3e97e6203d47fa8231b5f2269741` and
`test/atomic-block-retained-completion-capability` at
`257d0c265578e328aae272864cd36dad9e1a1d4b`. The source and evidence pins
below refer to that reviewed endpoint.

The owner decision recorded in this revision sets a **specification
direction**: define a durable block acknowledgement and retain ordered
transaction outcomes wherever an identified caller is entitled to them.
It does not establish that acknowledgement-only is sufficient, authorize
implementation, or provide an attributed message URL or timestamp.

## Pinned source and reviewed evidence

At commit `257d0c265578e328aae272864cd36dad9e1a1d4b`, tree
`3c1d263e776dd576b44055800fd00f129c414da9`:

- `crates/qbind-ledger/src/execution.rs`, blob
  `fe78bed4bddc5f00aa0ea2c8a464050106d84093`:
  `AccountStateUpdater` (1137–1141); `PersistentAccountState`
  (1250–1285); `RocksDbAccountState` (1380–1483); transaction result
  `VmV0TxResult` (1913 onward); `VmV0ExecutionEngine::execute_block`
  (2508–2522).
- `crates/qbind-node/src/execution_adapter.rs`, blob
  `13adcb22f3317485c47ed019daf019599193e721`:
  `ExecutionAdapter::apply_block` (238 onward); `AsyncExecutionService`
  (460–478); `PersistentVmV0State` and process-local worker claim
  (495–505); worker result, flush, and height handling (1315–1382);
  `submit_block` implementation (1492 onward).
- `crates/qbind-node/src/evm_commit.rs`, blob
  `263e0d680e31e235b13170714f2f5797f73d4bd2`: public
  `EvmCommitResult`, `apply_committed_block` return, in-memory
  `get_commit_result`, snapshot-retention field and pruning (126–150,
  182–188, 286–288, 295–297, 321–378).
- `crates/qbind-node/src/lib.rs`, blob
  `b2a477139d62e8b90c65decbca01edf3de0be42e`: `BlockApplyOutcome` and
  `Node::apply_block` result path (2525–2534, 2595–2640).
- `crates/qbind-runtime/src/lib.rs`: `BlockExecutionResult` contains one
  `TxApplyResult` per transaction (102 onward), blob
  `2dc36ab3369d408c927ae71fed8372c9dc4dc47f`.
- `crates/qbind-runtime/src/execution_engine.rs`: runtime `TxReceipt`
  fields (152 onward), including success, gas, logs, contract address,
  output and error, blob `fe57150ea6ab1ffbf99cd6172839ad9411728c4a`.
- `crates/qbind-ledger/src/parallel_exec.rs`, blob
  `9791f74b5c54655796edb823743c98d98817b33c`: Stage B account lookup
  materialization and export (425–477).
- `crates/qbind-node/src/hotstuff_node_sim.rs`, blob
  `85d6dc22fc2b7b11ffd9b08181fc7623fff02c97`: simulator dispatch to
  async/sync execution and mempool removal (3127–3190).
- `crates/qbind-node/src/node_config.rs`, blob
  `f95376764ce5cc6d8ccd42567d134e3aa8dac207`: VM-v0 path
  `<data_dir>/state_vm_v0` (5271–5277) and consensus path
  `<data_dir>/consensus` (5279 onward).
- `crates/qbind-node/src/vm_v0_runtime.rs`, blob
  `0762478b16847ffaee3b06536cd5d5f23e0aca14`: VM-v0 database opener
  (58–90).
- `crates/qbind-node/src/production_consensus_storage.rs`, blob
  `636ef998eb51354f6794de0620b2e2149b6c0739`: production consensus
  database opening (353–375).
- `crates/qbind-node/src/storage.rs`, blob
  `9a78a55ce75b2e9e5a7107eb478d1da2ebc215f0`: `ConsensusStorage`
  committed-position and epoch methods (168–224), epoch transition method
  (293–315), and implementation (929–1110).
- `crates/qbind-wire/src/consensus.rs`, blob
  `5a60b7a1aed1bfb93a78817224e11f89276e5868`: signed proposal canonical
  body, embedded QC and ordered transactions (915–950).
- `docs/security/evidence/candidate-durable-execution-recovery-protocol-20261109.md`,
  blob `e48d199a8544faa353036e0127cc7e874339689d`: identity and six OPEN
  bindings (3.1–3.3), publication and completion (4.2–4.4), recovery and
  owner decisions (5, 10).
- `docs/security/evidence/atomic-block-retained-completion-capability-experiment-20261109.md`,
  blob `1b4d45b1543f38963c109803bd1eeed148a2b5f2`: bounded test scope,
  observations and limits (status, “Failure model”, and “Future verification
  plan”).

## 1. Caller completion: source facts and missing decision

### Existing interfaces and observations

The inventory distinguishes internal computation, synchronous API returns,
queue submission, and observed source consumers. Repository-local tests and
harnesses are evidence of exercised API shapes, not evidence that external
callers are entitled to durable fields.

| Identified caller or surface | Interface and what it submits/receives | What source establishes about entitlement |
|---|---|---|
| VM-v0 execution engine and worker | `VmV0ExecutionEngine::execute_block` accepts state and ordered transactions and returns ordered `Vec<VmV0TxResult>`; the inspected production-like call site is the async worker, and tests/harnesses also call the engine directly. Each result has success/error and gas/fee fields. | The function return gives its immediate caller execution outcomes. The worker consumes them for metrics; test/harness consumers are not external caller entitlements. No downstream production consumer or durable retention requirement for each field was established. |
| Generic synchronous adapter caller | `ExecutionAdapter::apply_block(&QbindBlock)` returns `Result<(), ExecutionAdapterError>`; `current_height` is separately queryable. The implementation stops at first transaction execution error. | Its declared API returns success/error, not per-transaction results, durable acknowledgement, or an identity-bound completion. The simulator logs adapter errors and continues its commit callback. |
| Async service submitter | `AsyncExecutionService::submit_block(QbindBlock)` returns queue-admission `Result<(), AsyncExecError>`; `queue_len` is approximate. | `Ok(())` establishes enqueue only; queue-full and shutdown are admission outcomes. It says nothing about eventual execution or durable completion. |
| VM-v0 worker and metrics consumer | Worker executes ordered transactions, consumes results for success/error metrics, attempts `flush_state`, logs flush failure, then advances local height. Stage B may materialize missing accounts in its temporary state and exports changed state back through setters. | Worker-local use establishes that results affect metrics, not that those metrics or results are a durable caller response. It returns no completion handle/result to submitters. The setter/cache updates, Stage B state materialization/export, adapter publication and backend writes/flush are distinct. |
| HotStuff simulator commit callback | Submits a committed `QbindBlock` to async service, or calls synchronous adapter; after this dispatch it removes committed transactions from the selected mempool. Queue-full is fail-stop; shutdown logs and continues without execution; sync adapter failure is logged and does not fail the commit callback. | This caller observes admission or `Result<(), ExecutionAdapterError>`, not durable completion. Mempool removal is not evidence that a result was delivered to a transaction submitter. This is simulator behavior, not proof about an ordinary P2P route. |
| `Node::apply_block` API caller | Returns `BlockApplyOutcome` with height, round, block ID, `BlockExecutionResult` (one success/failure outcome per transaction), and vote decision. | The API exposes ordered transaction outcomes to its caller, but this local execute-and-return path does not establish durable commit or a persistent retry result. No production external consumer entitlement is established by its signature alone. |
| EVM bridge API and callers | `apply_committed_block` returns `EvmCommitResult` with receipts, state/transaction/receipts roots and total gas; `get_commit_result(height)` looks up the separate in-memory `committed_roots` map. EVM receipts expose success, gas, cumulative gas, effective gas price, logs, contract address, output and error. | Tests inspect the returned and retained values. The configured/default `retention` value is used by snapshot pruning, not by `get_commit_result`; in the inspected `evm_commit.rs`, no eviction from `committed_roots` is shown. That file does not establish durable result storage or restart retrieval. In the inspected implementation, current height and the in-memory result map update before snapshot persistence; storage failure can return an error after those in-memory updates. No production caller or entitlement/expiry contract was established. |
| Repository integration tests/harnesses | Tests submit blocks, poll queue drain/metrics, or directly inspect execution results/receipts. | These are test consumers, not production caller commitments. They confirm results are used in some harnesses but do not determine the external completion schema. |

This is a bounded repository-source inventory. It does not identify every
downstream crate, application, RPC, ordinary P2P route, operator integration,
or external consumer. A type being public/exported or fields existing in a
result is not proof that a particular caller is entitled to those fields.
No ordinary P2P completion response or end-to-end caller path was established
by the inspected call sites.

**Owner direction and remaining API decision:** specify a durable block
acknowledgement plus ordered transaction outcomes for each identified caller
whose entitlement is established. Do not retain fields no identified caller
is entitled to. Until the inventory is completed with downstream/API owners,
the entitlement for `Node::apply_block`, EVM bridge consumers, RPC/P2P
consumers, and any uninspected downstream user remains unresolved. For an
unresolved caller or field, either preserve it pending the entitlement
decision or explicitly report it unavailable; never silently omit it.
Acknowledgement-only sufficiency is not established.

### Owner-approved working caller classification

The owner-approved working classification below records a specification
direction only. It distinguishes current source behavior from a possible
future contract; it does not establish entitlement, durable completion,
production wiring, or approval of a completion mechanism.

| Caller/interface | Current source behavior | Working future direction and unresolved entitlement |
|---|---|---|
| Synchronous execution adapter | Preserve the current immediate `Ok(())`-if-all-succeed / first-error return semantics. Do not silently replace a required error with generic success. | A future persistent completion contract is separate from the current immediate return. Durable-result entitlement remains OPEN. |
| Asynchronous service submitter | `submit_block` reports queue admission, queue-full, or shutdown; it does not report execution or durable completion. | Keep admission distinct from execution and durable completion. The future direction is “a durable block acknowledgement as specified, if and when separately approved.” No durable acknowledgement mechanism is approved or implemented. Outcome entitlement remains OPEN. |
| `Node::apply_block` | Preserve the current immediate ordered per-transaction results in `BlockApplyOutcome`; they are not durable completion. | Future durable-result entitlement remains OPEN. |
| `LedgerApply` / `NodeLedgerHarness` | Preserve the inspected in-memory ledger success/error semantics and harness propagation. The current harness does not return a durable acknowledgement. | Do not invent a durable acknowledgement for the current harness. A persistent consumer or contract requires separate identification and decision. |
| EVM bridge consumer | Preserve the exposed immediate `EvmCommitResult` and `get_commit_result` behavior and reviewed limitations. Snapshot retention is distinct from the separate in-memory `committed_roots` map; that map does not establish durable restart retrieval. | Durable receipt-retrieval entitlement remains OPEN pending identification of an actual consumer and its required fields. |

For any future persistent caller whose entitlement is established, the
acknowledgement and every entitled outcome must bind to the same reviewed
atomic consistency unit, operation identity, and exact transaction order and
count. Unknown or unresolved fields remain explicitly unavailable or
retained pending the owner's decision; they must not be silently omitted.
Acknowledgement-only sufficiency for all callers is not established.

This classification is based on a repository-local, non-exhaustive
inventory. It does not establish caller entitlement, production wiring,
durable completion, atomic-commit feasibility, or a complete caller set.
No retention period, wire format, storage mechanism, production ruleset,
recovery procedure, or operational authority is selected. All future
durable-result entitlements remain OPEN. CCI-1 and CCI-2 remain CLOSED
within their reviewed inventory scopes; CCI-3 remains optional and
non-blocking. CCC-1 and CCC-2 remain within their documentation scopes.
The six identity bindings remain OPEN, the native post-quantum requirement
remains fixed, and prior scoped findings are preserved.

### Smallest proposed completion record

Subject to the caller inventory, propose a versioned, authenticated **block
completion record** keyed by stable operation identity and authoritative
position. Its exact encoding, integrity primitive, authentication authority,
and field widths are unresolved. The logical schema is:

| Record component | Proposed content and semantics | Current derivability |
|---|---|---|
| Schema and policy context | Record version, execution/ruleset version and state schema; deployment/backend association. | Required context is identified in the recovery protocol; encoding and allowed versions are OPEN. |
| Operation and position binding | Stable operation ID; exact prior and new authoritative positions; chain/epoch/height/parent and deployment association as required by the approved identity. | Six verified identity bindings remain OPEN; current block ID alone is insufficient. |
| Block acknowledgement | Terminal assertion that this block’s execution was committed under the applicable rules. It is distinct from queue admission and from global failure to establish commit. **It does not assert that every transaction succeeded.** | The semantics are this specification direction; no QBIND durable acknowledgement exists. |
| Ordered-input binding | Exact executed transaction order and count, bound to the same operation identity. Could refer to the authenticated canonical operation data if its availability/integrity are established. | Required binding is OPEN. Hash/encoding, storage location and maximum transaction count/bytes are not chosen. |
| Ordered transaction outcomes | One outcome per executed transaction in exact input order, with index/order relation and count. Retain only fields established as caller-entitled; for unresolved entitlements, retain pending decision or explicitly mark unavailable. | Caller inventory is incomplete. No caller/field entitlement or field encoding can be inferred solely from internal types. |
| State/commit integrity | Authenticated relation to final account values and membership and the authoritative position within the same atomic commit. | Joint durable commit is BLOCKED / UNPROVEN. Native post-quantum integrity/authentication is required but its construction is OPEN. |

For callers whose entitlement is established, the outcome subrecord must
match their API contract:

- **VM-v0 direct result consumers:** if identified as entitled, preserve
  ordered `success`, typed `error`, `gas_used`, `fee_paid`, `fee_burned` and
  `fee_to_proposer` values where applicable. Which downstream consumers
  require which fields and the canonical error encoding remain unresolved.
- **`Node::apply_block` callers:** its current `BlockExecutionResult`
  distinguishes per-transaction `Success` and `Failed(ExecutionError)`.
  Durable retention is not implied by this in-memory return; any identified
  caller entitled to replay/retrieval needs that ordered result and an
  owner-defined encoding.
- **EVM bridge callers:** if any identified caller is entitled to receipts,
  applicable fields include success, gas and cumulative gas, effective gas
  price, logs, contract address, output, and execution error. Their presence
  in `EvmCommitResult` and in-memory height map does not prove a durable
  entitlement; no maximum log/output sizes or persistent receipt policy is
  established.
- **Async submitters and simulator commit callback:** current submitter
  receives queue admission only. A future durable API must distinguish
  admission from a terminal acknowledgement and, where entitled, outcomes.
  The current source does not identify a transaction-originating caller that
  receives these worker results.

A committed block may contain failed transaction outcomes; that is distinct
from a storage or protocol failure to establish that the block’s commit
occurred. A durable acknowledgement is returned only when the atomic commit
is established, even if some or all transaction outcomes are failures under
the applicable execution rules. A commit-level unknown/unavailable result
must not be encoded as a committed block acknowledgement.

Do not treat a digest or success bit as a replacement for entitled details.
An unresolved field must be retained pending the entitlement decision or
reported unavailable, not silently omitted. Every retained outcome must be
bound to the same atomic commit and operation identity as the acknowledgement,
and to the exact executed input order and count. The specific schema encoding,
canonical error types, optional-field rules, size bounds, transaction count
limit, and response transport remain OPEN.

### Retention proposal and limits

The following are proposed lifecycle bounds, not selected numeric durations
or byte limits. The owner must set each bound from caller retry semantics,
recovery/audit obligations, maximum transaction/result sizes, storage budget,
and an authenticated supersession/currentness policy. No field may be pruned
while its caller entitlement or recovery requirement remains active.

| Field class | Proposed minimum retention | Limit needed before implementation |
|---|---|---|
| Block acknowledgement and operation/position key | Keep throughout the approved idempotent retry window and until the operation is no longer needed for authoritative recovery or conflict detection. An expired record must not cause re-execution if the position may already have committed. | Retry window, recovery horizon, expiration semantics, and whether a compact tombstone remains after payload pruning are OPEN. |
| Caller-entitled ordered outcomes | Keep each required outcome for at least that caller’s approved retrieval/retry window. The outcome bytes must be committed in the same reviewed atomic consistency unit as account values/membership, position, operation identity and acknowledgement. A logical reference is permitted only when both the reference and its target outcome data are included in that same consistency unit. | Per-caller window, response/API contract, size cap, and behavior on retention exhaustion are OPEN. Independently writing/committing required outcomes or their references is not authorized by this specification, even if authenticated and retrievable; a broader scheme needs a new owner decision and safety proof. |
| Outcome fields with unresolved entitlement | Preserve pending entitlement review or explicitly return unavailable to affected callers; do not silently omit or prune. | Owner must complete downstream inventory and decide whether each field is retained or unavailable before claiming the associated API contract. |
| Schema, ruleset, identity and integrity metadata | Retain alongside every acknowledgement/outcome that depends on it, for at least the longest retention period of those records; do not delete the decoder/policy context while dependent records exist. | Version support, migration/deprecation and metadata compaction rules are OPEN. |
| State/result reference and integrity/authentication evidence | Any reference for required outcome data must point to bytes co-committed with that reference in the same reviewed atomic consistency unit. Keep the logical reference and its verification context with the acknowledgement for the full promised lifetime; if the same-boundary data cannot be retrieved or validated, report unavailable. | Storage location within the boundary, access controls, cryptographic constructions/keys, key rotation, and integrity verification schedule are OPEN. Independently stored/committed required data or references are not permitted absent a new owner decision and safety proof. |
| Maximum record size and aggregate storage | Refuse or mark unavailable before acknowledging if a required record cannot be stored within the approved bound; do not truncate required fields. | Maximum transactions/block, bytes per transaction, error/log/output sizes, total per-block outcomes, database limits and backpressure policy are OPEN. |

No concrete numeric retention or size limit can be derived from the inspected
caller APIs. In `crates/qbind-node/src/evm_commit.rs` at the pinned blob
`263e0d680e31e235b13170714f2f5797f73d4bd2`, the configured/default 256-block
window is used to prune persisted snapshots. `get_commit_result` separately
reads the in-memory `committed_roots` map; the inspected file shows no map
eviction, but it does not establish durable storage or retrieval after
restart. Neither behavior is an approved durable retention period or
evidence for the VM-v0 contract. A logical result reference is acceptable
only if both reference and target data belong to the same reviewed atomic
consistency unit; authenticated bytes written or committed independently do
not satisfy this specification.

The record’s encoding, integrity primitive, authentication authority,
native post-quantum construction and parameters, and storage schema are
**not selected**. Native post-quantum integrity/authentication is fixed for
the acknowledgement and retained outcomes. Ordinary classical hashes,
database checksums, or a reference without authenticated availability cannot
substitute for that requirement. When any required record is missing,
corrupt, stale, conflicting, unauthenticated, expired under an approved
policy, or unavailable, the response is **unknown/unavailable**, not
success. It must not trigger blind re-execution.

## 2. Actual stores and proposed consistency unit

### Existing QBIND boundary

The VM-v0 account database is opened at `<data_dir>/state_vm_v0`; the
production consensus database is opened separately at `<data_dir>/consensus`.
The VM account backend uses one RocksDB instance and account-key records;
the account key’s presence represents a stored account, while a missing key
is read as default state. `PersistentAccountState` exposes per-account get,
put and flush; it has no account-membership enumeration or block commit API.
Its read interface also maps storage/read or decode errors to default state,
so that interface alone cannot distinguish absent membership from failed or
malformed stored state.

For state-path interpretation, keep these operations distinct: Stage B may
materialize absent accounts into a temporary snapshot and export state;
transaction setter calls update the updater/cache; adapter publication moves
worker results into its shared state; durable backend effects are separate
storage writes/flushes. None of those boundaries alone establishes that
membership and account values were published atomically with position and
completion.

The separate `ConsensusStorage` API owns committed block ID and epoch
metadata. It exposes independent position writes and a same-consensus-store
epoch-transition batch. That batch does not include VM account data,
operation identity, or completion. The reviewed source and experiment
establish no single QBIND transaction boundary spanning the account DB and
consensus DB.

### Required atomic unit (owner requirement)

The proposed unit is one externally authoritative publication of all of:

1. final VM account values and explicit account membership/presence changes;
2. authenticated authoritative execution position, including predecessor;
3. stable operation identity and its validated context; and
4. caller-required retained completion bound to that operation and position.

All ordinary readers and writers must observe either the previous complete
unit or the new complete unit. No caller may receive a durable-success
response unless the approved contract establishes the complete unit and
completion. A one-database batch over synthetic keys only tests a backend
capability in that one database; it cannot establish the required guarantee
while actual QBIND stores remain separate.

### Candidate directions (not selected)

- **Single transaction boundary:** redesign/relocate the authoritative
  account state, position, identity and completion into one supported
  transactional boundary. The selected engine and its atomic visibility,
  error, recovery and durability semantics would need independent evidence.
- **Cross-store protocol:** define a durable coordinator/prepare/commit
  protocol across the actual stores, with explicit state transitions,
  fencing and authenticated recovery inspection. It is adequate only if it
  proves externally atomic publication and safely resolves every partial or
  ambiguous state under the approved failure model. A sequence of successful
  per-store writes, a later flush, an advisory/process-local lock, or a
  marker alone is not that proof.

Neither direction is chosen or demonstrated. The experiment’s partial-state
control is a characterization of two sequential writes with an injected
failure between them; it does not show that every possible coordinated
redesign is incapable of satisfying the contract.

## 3. Failure model and refusal outcomes

The failure model must be selected per backend and deployment before a
durable guarantee is claimed. Current source inspection does not establish
the chosen WAL policy, synchronous write options for the joint unit,
filesystem persistence behavior, storage-device cache/flush behavior,
cross-process fencing, or recovery authority.

| Event | Required proposed behavior |
|---|---|
| Failure/crash before preparation | Perform no externally visible effects. If finality, operation identity, prior position, backend association, current ruleset, or the pre-effect prepared record cannot be authenticated and established, refuse and remain gated. Absence of a marker must not be interpreted as a fresh valid history without authenticated enrollment evidence. |
| Failure while writing account state/membership | Treat an error as potentially partial or unknown unless the chosen backend contract proves no effect. Do not write/acknowledge position or completion independently. Close ordinary access and inspect only through the approved recovery path. A partial write is possible, not established for every failure. |
| Failure while writing position/identity/completion | If earlier account writes may have taken effect, state may be partial or unknown; it is not established to be partial in every such case. Do not expose it as committed or roll forward by guess. Gate ordinary access and use authenticated, fenced recovery evidence or retain unknown/unavailable status. |
| Failure during a cross-store coordinator step | A coordinator error, partial prepare, partial commit, timeout or lost return is unknown unless the protocol’s durable decision record and all participants resolve the same operation. Keep the gate closed; no blind retry. |
| Unknown commit outcome or lost response | Return explicit **unknown** to the caller. Do not infer success from balances, visible account values, in-memory height, an independently stored position, a later flush, or a missing error response. Do not re-execute. Retry may query the same stable operation ID and return its retained result only after the entire atomic unit and caller-required completion are independently established. |
| Process crash and restart | Restart in a closed/gated state until authenticated inspection resolves prepared/committed/partial status, authoritative position and result. A normal process-reopen test is not evidence about power loss. Missing, malformed or conflicting evidence requires refusal/unavailability. |
| OS crash, power loss, or arbitrary storage failure | Claim durability only under independently reviewed settings and assumptions for the actual backend/WAL, synchronization calls, filesystem, mount configuration, device write cache/flush behavior and hardware. A killed process or clean reopen cannot establish these properties. If that evidence is absent, any uncertain outcome remains unknown/unavailable. |
| Missing/corrupt/stale/conflicting position or completion | Refuse success and normal service. Do not synthesize defaults, choose one conflicting copy, infer from balances, or advance from height alone. Preserve evidence and keep outcome unavailable pending authorized recovery. |
| Recovery evidence unavailable or authority compromised/lost | Keep the backend quarantined/unavailable. No local self-authorization, configuration change or validator/bundle-signing capability may authorize recovery. Who can resolve it and under what independent evidence remains OPEN. |

The reviewed experiment’s five passing tests are author evidence only for:
the synthetic one-database clean-reopen control, deliberate partial state
across two sequential writes, and modeled synthetic proof/completion
behavior. They did not inject a real ambiguous database response or
mid-commit error; did not run process crash/restart; and did not establish
cross-store atomicity, authenticated identity, power-loss behavior, or a
production finality policy. Do not rerun or broaden those results here.

## 4. Identity, access gates and recovery dependencies

### Six identity bindings remain OPEN

The operation and completion must eventually be shown to bind all six
requirements recorded in the reviewed protocol:

1. authenticated finality for the exact stable decision subject;
2. exact ordered transaction bytes actually decoded/executed;
3. authoritative position and predecessor continuity;
4. independently authenticated deployment/backend association;
5. authorized ruleset and transition history; and
6. operation identity and required completion bound to durable state and
   position in the same consistency unit.

Height, payload hash, a current consensus block ID, or a completion record
alone is not a substitute. The canonical signed proposal body contains the
embedded QC bytes and ordered transaction bytes; external evidence is not
authenticated merely because it is presented with that proposal.

The native post-quantum protection requirement for identity and commit records
is fixed. Actual constructions, parameters, roots, evidence and demonstrated
end-to-end properties remain OPEN. Keep association/recovery verification
authority separate from validator signing and bundle-signing authority.

A valid, policy-authorized equivalent finality proof for the same stable
subject must be independently reverified or accepted under an owner-approved
equivalence/reuse policy and its currentness requirements. Different proof
bytes alone do not define a different operation. Invalid, unauthorized,
wrong-subject, non-equivalent, stale, conflicting or unavailable proof
evidence must produce the future policy’s refusal/unavailable result. No
current QBIND route accepting alternate proofs is established; no production
equivalence or reuse policy is selected.

### Required gates and authority questions

Before any effect, require gates for ordinary account reads/writes/flushes,
worker claims, cached/shared state, restart/startup, all other writers and
maintenance paths. Recovery inspection must be a restricted, read-only path
that cannot accidentally start execution, signing, proposal/vote
participation, or normal service. A process-local mutex, worker flag, or
advisory lock does not establish fencing against other processes, stale
handles, aliases or uncooperative writers.

Recovery will need independently authenticated evidence sufficient to bind
the exact deployment/backend instance; finalized history and operation
identity; prior and candidate positions; state membership and values;
authorized ruleset; retained completion; and the status/currentness of any
superseding or revoking transition. It must also establish that one fenced
owner controls the backend and that no stale writer can mutate it.

The trust roots, authority, provisioning, currentness/revocation source,
fencing primitive, evidence format, enrollment and recovery transitions, and
who may authorize abort/roll-forward or service return are unresolved owner
decisions. No operational key, authority or recovery procedure is selected.
If authority or current evidence is unavailable or compromised, refuse and
remain gated.

## 5. Decision matrix

| Classification | Current statement |
|---|---|
| **Established source facts** | VM account values and position use separate DB paths and interfaces; account persistence is per-key put/flush; consensus storage separately exposes committed ID/epoch; ledger execution has ordered transaction result values; async submit returns queue admission; the inspected async worker does not return durable completion to its submitter. |
| **Owner-approved requirements** | Atomic block publication with retained completion is the primary candidate; specify a durable block acknowledgement plus ordered transaction outcomes wherever an identified caller is entitled to them; do not retain fields no identified caller is entitled to; unresolved entitlements are retained pending decision or reported unavailable; all state values/membership, authoritative position, stable identity and caller-required completion share the consistency unit; unresolved outcomes remain unknown/unavailable; native post-quantum trust is fixed. |
| **Proposed contract** | A versioned, authenticated operation-bound acknowledgement and per-caller ordered outcomes; explicit separation of admission/execution/durable completion; gate ordinary access on any partial or ambiguous state; refuse rather than infer or blindly retry. |
| **Unresolved owner/API decisions** | Complete caller inventory including downstream consumers and routes; which caller requires which outcome fields; response endpoint/correlation/idempotency; exact durable schema and encoding; per-field retention/expiry and size limits; terminal transaction failure semantics; stable identity encoding and proof equivalence/currentness policy; recovery authority and evidence. |
| **Feasibility blockers** | No inspected joint account-plus-position-plus-identity-plus-completion API; cross-store atomic visibility and unknown-outcome resolution unproven; backend/WAL/sync/filesystem/hardware assumptions not approved; complete fencing, authenticated current history, recovery gate and authority not established. |

## 6. Future evidence plan

**FUTURE / NOT AUTHORIZED / NOT EXECUTED:** no additional experiment or test
is authorized by this specification. Any later capability investigation
requires separate approval and must exercise the selected contract against
the actual QBIND account and authoritative-position boundaries, or a
separately approved redesign that demonstrably places them in one consistency
unit. A single-database batch control is not a substitute. Every control
listed below is **FUTURE / NOT EXECUTED**:

At minimum, later evidence must include:

- completed caller/API inventory and schema tests that distinguish queue
  admission, execution result, durable acknowledgement, and caller-visible
  response; verify a committed block acknowledgement does not imply all
  transactions succeeded;
- per-caller ordered-outcome tests for success/error and only the applicable
  gas/fee/receipt fields, including count/order and explicit behavior for
  unresolved or missing fields; test size-limit/backpressure without silent
  truncation;
- retention/expiry and integrity tests for every field over approved caller
  and recovery windows; verify any logical reference and its target
  completion bytes are in the same actual atomic consistency unit, and that
  no required outcome or reference is independently written/committed. Test
  unavailable references and required-record pruning refusal;
- exact selected backend/dependency, API, configuration, WAL and sync
  semantics, source provenance, filesystem/device assumptions, and a stated
  failure model;
- positive commit and retrieval of account values and membership, position,
  operation identity and the owner-approved completion together;
- failures at every preparation, account-store, position-store,
  coordinator, completion and acknowledgement boundary, including ambiguous
  return and lost response; independently verify old-or-new external
  visibility and same-operation recovery, otherwise require unknown;
- restart inspection with missing, corrupt, stale, conflicting and
  unavailable records; restricted recovery and normal-access gating;
- adversarial field-binding and same-checker bypass controls for all six
  identity bindings, proof validity/equivalence/currentness, backend
  association, and retained result retrieval;
- retry through a second valid authorized equivalent proof must retrieve
  the same acknowledgement and required ordered outcomes, while refusing
  invalid, wrong-subject, unauthorized, non-equivalent, stale, conflicting
  or unavailable evidence. The test must not treat proof-byte difference
  alone as a conflict;
- independent multiprocess/stale-owner fencing controls;
- process-crash/reopen evidence only for that failure class, and separate
  appropriately scoped OS-crash/power-loss evidence if those guarantees are
  claimed. Process crash must never be reported as power-loss evidence; and
- real provisioning, storage, runtime and operational evidence for any
  claim about authority, currentness, post-quantum trust or recovery.

These controls are not authorized by this specification and must not be used
to imply that the earlier single-database batch characterization established
the required actual-store joint guarantee.

Deterministic reconstruction remains an unselected alternative. It would
require authenticated and sufficiently complete replay history, the
applicable versioned ruleset, adequate prior state, and evidence of exact
reconstruction of every caller-required result. Persistent block storage or
a snapshot alone does not establish those conditions.

Required-persistence remains **NOT ACCEPTED / NOT INTEGRATION-READY**.
Recipient overflow, A23-F1 and A33-F1 / E27 remain OPEN; activation remains
DISABLED; public DevNet remains NO-GO. DER-1-TM-2 remains closed within its
documentation scope; DER-2 and DER-3 remain passed within their documentation
scopes. The arithmetic baseline remains red. No earlier scoped finding is
expanded, replaced, or authorized by this proposal.
