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

| Surface | Established source behavior | What it does not establish |
|---|---|---|
| VM transaction and block execution | `execute_tx` returns a `VmV0TxResult`; `execute_block` returns results in transaction order. The result has success/error and gas/fee fields, including `fee_burned` and `fee_to_proposer` when applicable. | It does not durably retain results or define a retry/retrieval API. |
| Synchronous `ExecutionAdapter` | `apply_block` returns `Result<(), ExecutionAdapterError>` and `current_height`; this generic adapter stops at its first execution error. | It does not return a block completion record or transaction result vector. It is not proof of durable publication. |
| Async `AsyncExecutionService` | `submit_block` is nonblocking and returns `Ok(())` for successful queue admission, or queue-full/shutting-down errors. `queue_len` is approximate. | `Ok(())` is not execution completion, durable commit, result availability, or acknowledgement of a specific completed operation. |
| VM-v0 async worker | Executes the block, consumes per-transaction results for metrics, logs a flush failure, and advances in-memory height after the flush attempt. | The worker does not return its `VmV0TxResult` vector or a durable result to the submitting caller. The current observed ordering does not establish a safe durable-completion boundary. |
| Simulator caller | On async `Ok(())`, the commit callback continues. It handles queue full as a fail-stop and logs shutdown while continuing without execution. It then removes committed transactions from mempool. The sync fallback logs `apply_block` failure and does not fail the consensus commit. | The simulator’s callback does not wait for or retrieve an execution completion. This is source evidence about that caller, not proof of every production caller’s contract. |

Thus the checked interfaces establish neither a general caller entitlement
to only an acknowledgement nor an entitlement to receipts, gas, fees, or
other per-transaction data. In particular, transaction result values exist,
but their presence in an internal return type does not itself make them a
caller-facing or durable API.

**Required owner/API decision (OPEN):** name each caller and its contract for
queue admission, execution rejection, block execution outcome, durable
completion, and retry/retrieval. Decide whether callers need only a durable
operation/position acknowledgement or also ordered transaction results
(including the applicable error, gas, fee, and receipt fields), and define
their retention and expiry. Until resolved, no implementation may silently
drop result fields or represent enqueue as successful durable completion.

### Smallest proposed completion record

Subject to that decision, the narrowest candidate is a versioned,
authenticated **block completion record** keyed by a stable operation ID and
the authoritative new position. At minimum it would contain:

- record schema/version and execution ruleset/schema identifiers;
- deployment/backend association identifier;
- stable operation ID and the exact prior and new authoritative positions;
- terminal committed execution status, distinct from queue admission and
  transaction-level success/failure;
- an integrity/authentication binding to the same committed account values,
  membership and position; and
- either the complete caller-required ordered result data, or a reference
  whose retrieval is itself authenticated, durable and guaranteed to resolve
  the exact same result.

A digest or success bit alone is insufficient if a caller is entitled to
transaction details. If the owner/API establishes that callers need only
an idempotent durable block acknowledgement, the retained completion may be
smaller, but must still identify the operation, position, terminal outcome
and schema. If ordered receipts/results are required, persist those values
or an equivalently durable, authenticated representation atomically; do not
reconstruct or discard them by assumption.

The record’s encoding, integrity primitive, authentication authority,
native post-quantum construction and parameters, storage schema, retention
period, expiration, and treatment of deprecation are **not selected**. The
fixed project requirement is native post-quantum protection; ordinary
classical hashes or database checksums cannot substitute for authenticated
identity/commit protection. When a record is missing, corrupt, stale,
conflicting, unauthenticated, expired under an unresolved policy, or
unavailable, the response is **unknown/unavailable**, not success. It must
not trigger blind re-execution.

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
| Failure while writing account state/membership | Treat an error as potentially partial/unknown unless the chosen backend contract proves no effect. Do not write/acknowledge position or completion independently. Close ordinary access and inspect only through the approved recovery path. |
| Failure while writing position/identity/completion | If accounts may already have changed, the system is in a partial state: do not expose it as committed or roll forward by guess. Refuse normal reads/writes/execution; use authenticated, fenced recovery evidence or retain unknown/unavailable status. |
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
| **Owner-approved requirements** | Atomic block publication with retained completion is the primary candidate; all state values/membership, authoritative position, stable identity and caller-required completion must share the consistency unit; unresolved outcomes remain unknown/unavailable; native post-quantum trust is fixed. |
| **Proposed contract** | A versioned, authenticated operation-bound completion record; explicit separation of admission/execution/durable completion; gate ordinary access on any partial or ambiguous state; refuse rather than infer or blindly retry. |
| **Unresolved owner/API decisions** | Which callers require which outcome; acknowledgment versus receipt/result fields; endpoint and correlation/idempotency mechanism; durable completion schema and retention/expiry; terminal transaction failure semantics; stable identity encoding and proof equivalence/currentness policy; recovery authority and evidence. |
| **Feasibility blockers** | No inspected joint account-plus-position-plus-identity-plus-completion API; cross-store atomic visibility and unknown-outcome resolution unproven; backend/WAL/sync/filesystem/hardware assumptions not approved; complete fencing, authenticated current history, recovery gate and authority not established. |

## 6. Future evidence plan

**FUTURE / NOT AUTHORIZED / NOT EXECUTED:** no additional experiment or test
is authorized by this specification. Any later capability investigation
requires separate approval and must exercise the selected contract against
the actual QBIND account and authoritative-position boundaries, or a
separately approved redesign that demonstrably places them in one consistency
unit. A single-database batch control is not a substitute.

At minimum, later evidence must include:

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
- independent multiprocess/stale-owner fencing controls;
- process-crash/reopen evidence only for that failure class, and separate
  appropriately scoped OS-crash/power-loss evidence if those guarantees are
  claimed. Process crash must never be reported as power-loss evidence; and
- real provisioning, storage, runtime and operational evidence for any
  claim about authority, currentness, post-quantum trust or recovery.

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
