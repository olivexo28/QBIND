# Candidate Durable Execution and Recovery Protocol

**Status:** Candidate for independent review only. This is not an approved
production design, operating procedure, implementation authorization, or
activation decision. It selects no operational keys, trust root, signer,
cryptographic suite, storage primitive, provisioning process, recovery
authority, or currentness mechanism.

The required-persistence candidate remains **NOT ACCEPTED /
NOT INTEGRATION-READY**. Recipient overflow, A23-F1, and A33-F1 / E27 remain
OPEN. Activation remains DISABLED; public DevNet remains NO-GO.

## 1. Basis, terminology, and evidence boundary

### Pinned basis

- Main: `aa382fa28b2d3e97e6203d47fa8231b5f2269741`
- Reviewed requirements branch:
  `docs/worker-write-atomic-recovery-spec`
- Reviewed requirements endpoint:
  `79f178956706333b68cd83a9b46ad6f41563d4cd`
- Requirements endpoint tree:
  `cfe86b20f649016f669ca8b88650b47b2b56a920`
- Requirements document:
  `docs/security/evidence/worker-write-failure-backend-reuse-decision-brief-20261109.md`
- Requirements-document blob at the reviewed endpoint:
  `eab79df2d99fc0eaba0643b96292bc80ea727df0`
- Supplemental source endpoint reviewed by that document:
  `2fdc30da4174a6b131c10c3e14091a5bea9a766f`
- Supplemental source tree:
  `3bb8f6529b04eca2241ae5d01988cf862be74ae7`
- Relevant pinned blobs at the supplemental source endpoint:
  - `crates/qbind-node/src/execution_adapter.rs`:
    `13adcb22f3317485c47ed019daf019599193e721`
  - `crates/qbind-ledger/src/parallel_exec.rs`:
    `9791f74b5c54655796edb823743c98d98817b33c`
  - `crates/qbind-ledger/src/execution.rs`:
    `fe78bed4bddc5f00aa0ea2c8a464050106d84093`

In this document **Source fact** means behavior visible in those pinned
sources; **Candidate requirement** means a property a later design would
need; **Assumption** means a condition on which the candidate depends but
which has not been demonstrated; **Owner decision** means a policy choice
that remains for the owner. None of the candidate requirements should be
read as an existing guarantee.

The earlier evidence is bounded: the worker controls used injected failures
and a controlled panic, not a real RocksDB write failure, power loss, durable
corruption, or recovery. The supplemental Stage B source review is not an
execution experiment. This protocol adds no empirical evidence.

## 2. Candidate protocol at a glance

The candidate treats each finalized execution decision as one uniquely
identified operation. It gates all access to a backend until its identity,
current committed position, and recovery status have been checked. Before
running transaction effects, it durably records an operation-specific
prepared state. It then computes a complete candidate state, including
account-key membership, off to the side. One atomic publication boundary
would expose the new account state, its membership semantics, a commit
record, and the new authoritative execution position together. Any
unresolved outcome closes the gate and requires separately authorized
recovery; absence of a marker is never interpreted as proof that no attempt
occurred.

This sequence is conditional on a storage primitive that provides the
required atomic visibility and durability, and on an enforceable fence over
all access paths. Neither primitive is established by the inspected
repository. If the selected backend cannot provide them, or the authorized
history needed to resolve ambiguity is unavailable, the candidate must
refuse execution and service rather than approximate the guarantee.

Proposed backend states:

| State | Meaning | Ordinary access |
|---|---|---|
| `UNENROLLED` | No independently authenticated deployment/backend association has been accepted. | Refuse reads that disclose VM state, writes, execution, and service startup. |
| `READY(position)` | An enrolled backend has a reconciled committed position and no unresolved operation. | Admit only the fenced executor and explicitly authorized read interfaces. |
| `PREPARED(operation)` | An operation-specific durable intent exists; publication is not yet resolved. | Refuse new work and ordinary reads/writes; recovery-only inspection may proceed. |
| `COMMITTED(position)` | The atomic publication record and state correspond to a committed execution position. | Return to `READY` only after commit durability and required evidence checks. |
| `QUARANTINED(reason, operation?)` | A failure, conflict, failed check, or unknown outcome prevents safe admission. | Refuse ordinary access and reuse. |
| `RECOVERY_PENDING` | Recovery authority/evidence is being checked or the result remains uncertain. | Keep ordinary gate closed. |

These are conceptual states, not a proposed durable format. Persisting them
in a file, RocksDB key, or separate database would introduce ordering and
atomicity questions; no format is selected.

## 3. Bind execution to an authoritative finalized decision

### 3.1 Proposed operation identity

Before effects, construct a domain-separated `ExecutionOperationId` from a
canonical encoding of at least:

- a unique deployment identity and backend/state-instance identity;
- the wire chain ID, consensus epoch, finalized block height and round;
- the full parent block ID and the prior committed operation/position;
- the digest of the complete finalized consensus proposal and its
  authenticated finalization evidence;
- the exact ordered transaction byte strings to be executed, including their
  count and unambiguous length boundaries;
- the applicable execution profile/ruleset identifier and version;
- any transition metadata that changes interpretation of the block; and
- an identifier for the required state schema and canonical account-key
  membership semantics.

The candidate additionally computes a deterministic digest of the complete
candidate post-state (sorted account keys, explicit presence/absence semantics,
and canonical values) and places that digest in the commit metadata. This is
for consistency checking, not by itself proof that the state is correct or
authentic. Hash algorithm, domain encoding, collision assumptions, signing
scheme, and whether a post-quantum construction is required are unresolved.
No cryptographic assumption here is implicitly post-quantum.

Height plus payload hash is insufficient as a unique execution identity.
Distinct parents, transaction ordering, rulesets, deployments, or prior
outcomes could otherwise be conflated. The current consensus engine's
`derive_block_id_from_header` constructs its 32-byte identifier from proposer,
view, and only the first 16 bytes of the parent ID; it does not bind transaction
payload, epoch, chain ID, or QC contents
(`crates/qbind-consensus/src/basic_hotstuff_engine.rs:3875-3889` at the
supplemental endpoint). The wire proposal canonical body includes multiple
header fields, QC bytes, and ordered length-prefixed transactions
(`crates/qbind-wire/src/consensus.rs:915-950` at that endpoint), but a
canonical signed proposal is not, without further checks, proof of
finalization, a correct execution, or deployment currentness.

### 3.2 Required verified bindings versus identity fields

The identity fields above are proposed data, not verified bindings. Before
the candidate may proceed, a later implementation and review would need to
establish all of the following:

1. **Finality:** independently verify evidence that the exact proposal was
   finalized under the authorized consensus history. A proposal signature or
   QC-shaped object alone must not be treated as finality unless the
   applicable consensus contract proves that implication.
2. **Exact inputs:** validate the proposal's full canonical encoding and
   bind the transaction bytes actually decoded/executed, in order, to that
   finalized proposal. Verify transaction count and every relevant payload
   commitment; refuse missing, conflicting, malformed, or non-canonical
   evidence. Do not substitute locally supplied transactions for committed
   bytes.
3. **Position continuity:** verify that the finalized decision extends the
   exact prior committed position, with contiguous/order rules required by
   the applicable consensus history. A same-height conflict, parent mismatch,
   missing prior position, or non-identical duplicate is a refusal.
4. **Deployment and backend:** authenticate the association between the
   finalized history, chain/deployment identity, backend instance, and
   configured path/namespace. Locally editable configuration alone cannot
   establish this binding.
5. **Ruleset:** obtain the execution ruleset/version from an independently
   authorized transition/history, not merely a command-line flag or local
   configuration. Verify that the exact ruleset is permitted at this
   position and that the binary supports it.
6. **Commit identity:** place the operation ID and prior/new positions in the
   same atomic commit boundary as the state. Verify its relation to the exact
   prepared operation before acknowledging completion.

No inspected interface currently supplies this complete verified binding.
The consensus block ID is not a suitable substitute, and the async service
accepts a `QbindBlock` and reports queue admission rather than a verified,
durable execution result (`execution_adapter.rs:475, 1492-1518` at the
supplemental endpoint).

### 3.3 Duplicate work and uncertain predecessor

- If an exact operation ID is already committed and its authenticated commit
  record and state digest verify, return the recorded completion result
  without re-executing.
- If an operation ID is present as prepared, pending, quarantined, or has an
  uncertain prior commit, do not rerun it. Gate service and resolve it using
  recovery evidence.
- If the same position is presented with different input, parent, ruleset,
  deployment association, or operation ID, refuse and quarantine as a
  conflict.
- If no authoritative prior position can be established, do not infer one
  from a directory, account balances, current height in memory, or a missing
  database key. Require authenticated enrollment or recovery evidence.
- If duplicate identity retention has been pruned, refuse rather than infer
  that the operation was never committed. Retention and checkpoint rules are
  owner decisions.

## 4. Consistency, completion, and durability boundary

### 4.1 Candidate atomic unit

The candidate publication unit is one finalized block operation and includes:

1. all account values after applying the operation;
2. the exact account membership/presence representation, including any
   created, deleted, or explicitly default-valued accounts;
3. the operation ID, prior position, new authoritative execution position,
   and ruleset/schema identifiers;
4. the complete post-state digest and enough commit metadata to correlate
   retries and determine the committed operation; and
5. any durable recovery state needed to show that this operation is no
   longer pending.

These must become visible together or the backend must remain gated. If
account state and execution position are updated in separate stores, a
transaction spanning those stores or an independently proved equivalent
protocol is required. Cache updates and externally visible receipts must not
be presented as committed before this boundary.

### 4.2 Candidate execution and publication sequence

1. **Gate and validate.** Acquire the backend's exclusive fence, close
   ordinary access, and validate enrollment, currentness, prior committed
   position, ruleset, and finalized inputs. Any mismatch refuses before
   mutation.
2. **Prepare durably.** Persist an operation-specific prepared record linked
   to the prior committed position and exact operation ID. Wait for the
   selected durability barrier and verify its outcome. Do not begin account
   effects if preparation is absent or uncertain. If its result is ambiguous,
   keep the gate closed and inspect through the recovery path.
3. **Compute isolated candidate.** Execute from a coherent snapshot of the
   committed state under the selected ruleset. Capture write failures as
   typed errors; a VM transaction rejection is distinct from a backend error.
   Do not expose partial staged values. This requires an execution API that
   propagates updater failure instead of the current void-returning
   `AccountStateUpdater` (`execution.rs:1138-1145`).
4. **Check candidate.** Validate operation identity, exact transaction order,
   state membership and value changes, deterministic post-state digest, and
   resource limits. A calculation failure leaves the backend prepared or
   quarantined; it is not silently converted to a successful block result.
5. **Atomic publish.** Atomically publish account values and membership,
   commit identity, prior/new position, state digest, and resolved operation
   status. The atomic operation must provide documented visibility and
   durability semantics under the chosen failure model.
6. **Confirm before acknowledge.** Establish that commit is durable according
   to the chosen contract, update or invalidate caches, then publish the
   block-correlated completion acknowledgement and success metrics. Queue
   admission remains a separate response. If completion delivery is lost
   after commit, a retry reads the exact committed operation record and does
   not re-execute.
7. **Release gate.** Only after commit resolution and cache/publication
   consistency checks may the backend return to `READY`.

### 4.3 Candidate primitive and feasibility blocker

One possible implementation is a single embedded-database atomic batch that
contains every changed account/membership key and the position/commit record,
with a documented synchronous durability setting. Another is a transactional
storage engine with a commit identity and equivalent atomicity/durability
contract. These are alternatives, not selected mechanisms. A separate
prepared journal is acceptable only if its ordering, crash semantics,
integrity, and relationship to the state commit are established.

**Feasibility blocker:** At the pinned source, `RocksDbAccountState` writes
accounts with individual `DB::put` calls and implements flush with
`DB::flush`; the shown open options only enable create-if-missing
(`crates/qbind-ledger/src/execution.rs:1380-1483` at the supplemental
endpoint). No inspected source establishes a batch spanning account state
and authoritative position, a synchronous WAL/durability contract, or the
crash behavior of a proposed commit-record protocol. A generic batch name,
successful return, later flush, matching balances, or a local marker alone
does not prove durable atomic publication. Until a selected engine/version,
configuration, API, error semantics, and failure model are reviewed and
verified, this protocol cannot claim the required guarantee and must not be
implemented as though the blocker were solved.

### 4.4 Error, lost response, flush, and crash behavior

| Event | Candidate handling |
|---|---|
| Transaction calculation or validation failure before prepare | No state effect; report the typed refusal. If reads can materialize membership, use a read path that does not mutate or include that behavior in the isolated candidate rather than touching committed state. |
| Worker write fails while building isolated candidate | Discard the isolated candidate only if it is proven not to have changed published state. Preserve the error; gate and quarantine if any effect may have escaped. |
| Prepare write fails or returns ambiguously | Do not execute. Keep gate closed. Recovery-only inspection must determine whether the exact prepared record exists; unreadable/conflicting evidence means refusal. |
| Crash after confirmed prepare but before computation | Restart sees unresolved `PREPARED`; no ordinary service. Recovery may safely abort only if authenticated history and storage evidence prove no publication occurred and protocol defines abort. Otherwise it remains unresolved. |
| Crash during atomic publication | Restart remains gated. If the storage primitive proves all-or-none durable commit and authoritative evidence identifies the result, resolve as committed or uncommitted. If not, feasibility blocker: no inference. |
| Commit returns error, times out, or response is lost | Treat as unknown, not failure. Do not retry execution, acknowledge success, advance service position, or release fence until commit identity and state are independently reconciled. |
| Commit returns success but durability barrier fails | Success is not acknowledged as durable. Gate and quarantine; a later flush cannot retroactively establish the original boundary without a specified recovery proof. |
| Crash after durable commit but before cache update/acknowledgement | On restart, revalidate commit identity, position, state digest and external finalized history; rebuild cache only after checks. Retry returns the stored completion, not a second execution. |
| Cache publication fails or differs | Keep service gated; durable state may be committed, but cache is not authoritative. Rebuild only from verified committed state and report completion according to the owner-approved contract. |
| Metrics or receipt delivery fails | Do not roll back committed state. Reconstruct only from durable commit metadata if that output is part of the specified contract; otherwise report delivery as separate and possibly unknown. |

Transaction calculations, worker-write failure, visibility, durability,
cache/receipts/metrics, and acknowledgements are separate contracts. A
durable state commit does not automatically make in-memory metrics or a
remote receipt atomic with the database.

## 5. First use, quarantine, and recovery

### 5.1 First enrollment

First use must not infer an empty valid chain from a missing database,
default account values, an empty directory, or `create_if_missing`. It begins
in `UNENROLLED` and remains inaccessible until an owner-approved enrollment
process has independently authenticated:

- the deployment and backend identity and their association;
- the initial authoritative consensus/execution position or genesis
  decision;
- the initial ruleset and account-state schema;
- the current authority and status of any prior/superseding transition; and
- the authority permitted to approve this enrollment.

Enrollment evidence must be bound to the exact backend namespace and
provisioned through a channel independent of the local host/configuration and
not dependent on one unauthenticated delivery channel. Authority, trust-root
custody, key enrollment, signatures, format, independent channel, and
currentness source are unresolved owner decisions. There is no enrollment
procedure approved here.

### 5.2 Normal operation

For each operation, the `READY -> PREPARED -> COMMITTED -> READY` sequence
above applies. Exactly one fenced owner may execute against a backend at a
time. New operations cannot overlap an unresolved operation. Read-only
inspection is restricted to interfaces explicitly permitted by the access
policy; consensus, signing, proposal/vote participation, and service startup
are not authorized merely because VM state can be read or recovered.

### 5.3 Quarantine and restart

On any write error, uncertain commit, failed durability barrier, worker
panic/loss, unexpected membership/state discrepancy, invalid position, or
loss of fencing, close the gate and transition to `QUARANTINED` or
`RECOVERY_PENDING`. Do not rely on an error handler to write the first
failure marker after effects begin.

**Required pre-effect invariant:** before the first potentially persistent
effect, a block-correlated prepared intent must be durably established, or
the selected atomic protocol must make it impossible for an effect to become
visible without an equally durable authoritative operation identity. If the
prepare result is ambiguous, effects do not begin. If the process crashes
before a failure marker can be written, the earlier prepare state must still
cause restart refusal. If the storage backend cannot establish this invariant,
the design is infeasible under the stated crash model.

At restart, the normal service must not open the backend for work and then
inspect it. A recovery-only path first acquires the required fence, leaves
ordinary read/write/flush/worker/consensus access disabled, and inspects
durable state. Recovery inspection may use a separate read-only handle or an
offline snapshot, but either approach must be demonstrated not to create,
repair, compact, mutate, or silently default missing/corrupt state. If the
database API necessarily opens writable or may mutate state on inspection,
that is another feasibility blocker until a safe inspection method is
established.

### 5.4 Recovery assessment and return to service

Recovery is a separately authorized state transition, not automatic startup
behavior. It requires independently authenticated and current evidence that
binds:

- deployment/backend identity and the precise prior and candidate positions;
- the finalized consensus decision and exact ordered inputs;
- the applicable ruleset and schema;
- whether the exact operation committed, did not commit, or remains unknown;
- the expected complete account membership and values (or a trusted
  checkpoint plus sufficient authenticated history to recompute them); and
- authority of the actor/system approving the recovery transition.

The recovery authority must be independent of the affected local backend and
its configuration. A valid old authorization may have been superseded;
currentness and anti-replay require a separately trusted mechanism. Missing,
unavailable, stale, corrupt, unauthenticated, contradictory, or
deployment-mismatched evidence means **refuse service and reuse**. An
unresolved commit is not converted into rollback by choosing to replay, and a
matching balance is not proof of complete history.

If evidence proves the operation committed, recovery may propose restoring
the verified committed boundary and rebuilding derived cache state. If it
proves no effects escaped and the protocol defines an authenticated abort,
recovery may propose returning to the prior position. If the state is partial
or evidence cannot decide, do not automatically repair, roll forward, roll
back, or resume. Require a separately approved and evidenced recovery path.

VM-state recovery does not itself authorize validator signing, proposal/vote
participation, bundle signing, or any other external action. Those require
their own authority, history, signer-control, and continuity checks. No
recovery keys, provisioning process, authority, role separation mechanism,
cryptographic suite, or return-to-service decision is selected here.

## 6. Fencing threat model

### 6.1 Threats considered

The candidate must account for accidental and adversarial overlap from:

- two workers or service objects in one process;
- stale worker handles retained across shutdown, panic, timeout, or recovery;
- a second process opening the same backend;
- another process using a path alias, hard link, mount alias, or copied
  backend;
- an operator or maintenance tool reading/writing/compacting the backend
  during execution or recovery;
- restored snapshots or replacement directories that appear to have the
  same logical identity but different contents;
- filesystem namespace changes, symlink/path substitution, permissions
  changes, or host restart;
- an external writer that ignores the application's lock; and
- a compromised local host/configuration or a compromised single delivery
  channel.

This candidate does not assume that a malicious host can be defeated by an
in-process protocol. If the threat model includes an administrator or kernel
that can replace both data and trust evidence, an independent machine or
authority must detect/reject that substitution; otherwise recovery has a
feasibility blocker.

### 6.2 Candidate gates and limits

| Access surface | Candidate control required | What it does not prove |
|---|---|---|
| Worker/service construction | Process-local ownership plus a backend-scoped, crash-releasing exclusive lease with a fencing generation checked on every operation. | The current `worker_claimed` atomic is process-local; it does not fence another process or stale external handles. |
| Reads | Route all reads through a gate-aware handle; deny ordinary account reads while prepared/quarantined. Use a distinct recovery-only read interface. | A submission queue gate does not stop public or retained read handles. |
| Writes, delete, prune, repair | Enforce the same backend lease/generation at the storage boundary, not just in the VM adapter; maintenance paths must participate. | An advisory lock is ineffective against an uncooperative writer unless every writer is required and technically constrained to honor it. |
| Flush/commit | Require current fence token and operation ID; prevent stale owners from committing after takeover. | A mutex or lock file does not revoke a handle that already passed an earlier check unless the backend checks fencing at commit. |
| Startup/restart | Gate startup before opening writable handles; inspect authenticated backend identity/status and acquire a fresh fence before service. | A missing marker or successful database open does not prove the backend is enrolled/current/consistent. |
| Recovery | Exclusive recovery lease, ordinary access disabled, authenticated evidence verified outside the affected mutable state, and a new fencing generation on authorized return. | A local recovery flag or a signature verified only against local mutable configuration is not independent authority. |
| Path/namespace | Resolve and bind canonical backend identity to a protected namespace; prevent aliases/replacement for the lifetime of the lease. | Path string equality alone does not establish object identity, and local ACLs do not fence a privileged host actor. |

Candidate fencing mechanisms include an OS lock with mandatory participation,
a database-enforced lease/generation, or an external coordinator issuing
fencing tokens. These alternatives have different failure modes; no one is
selected. A lock must define crash release, split-brain behavior, generation
monotonicity, namespace identity, and how the actual storage mutation rejects
stale generations. Merely adding an advisory lock, process mutex, boolean
claim, or startup check is not sufficient.

**Fencing feasibility blocker:** the inspected adapter uses a process-local
atomic `worker_claimed` value and serialized operations within its shared
handle (`execution_adapter.rs:495-505, 651-655` at the supplemental
endpoint). No inspected source establishes cross-process fencing, revocation
of retained handles, mandatory cooperation by external writers, or authority
over path aliases and host administrators. If the deployment cannot enforce
the selected backend/OS/namespace fencing assumptions, it must refuse
execution and recovery rather than claim exclusive ownership.

## 7. Stage B: distinct state and write observations

The following are separate quantities and must not be conflated:

1. **Account values:** nonce/balance values visible for account IDs.
2. **Account membership:** which account IDs are actually present in a map or
   persisted keyspace, including default-valued accounts.
3. **Read-triggered materialization:** Stage B's `get_account_lock` creates
   a default entry when an account was absent; `to_in_memory` exports every
   entry (`parallel_exec.rs:426-477` at the supplemental endpoint). Thus a
   read can change working/final-map membership without a transaction setter.
4. **Transaction setter calls:** calls made by the transaction engine to its
   `AccountStateUpdater`; these count only that engine boundary.
5. **Adapter snapshot publication:** for the Stage B adapter route, touched
   accounts are extracted into a snapshot, `execute_block_stage_b` produces a
   final state, and `apply_state_changes` sends final entries through the
   updater (`execution_adapter.rs:125-160, 1320-1360` at that endpoint).
   This is a separate publication loop and may call setters even when an
   internal getter materialized membership.
6. **Durable backend effects:** successful persistent operations, their
   visibility/durability, and state after an independently reopened backend.
   Neither a setter-call count nor a returned in-memory result proves this.

The absent-sender scenario is a source-derived possibility, not an executed
observation. The current adapter's Stage B branch additionally depends on its
configuration and transaction-count selection; direct Stage B API evidence
would not establish adapter route selection or publication. Future evidence
must record initial/working/final/persisted membership and values, internal
setter calls, adapter publication entries/calls, route selection, and durable
reopen state independently.

## 8. Failure-state matrix

All rows below are candidate behavior and unresolved design work. The
evidence/recovery column does not imply that the required mechanism exists.

| Boundary and precondition | Action | Error/crash/ambiguous result | Required gate | Evidence needed before recovery | Unresolved decision/blocker |
|---|---|---|---|---|---|
| First enrollment; backend not yet trusted | Authenticate deployment, backend, initial position, schema, ruleset, and authority. | Missing/conflicting evidence, crash midway, substituted directory. | Remain `UNENROLLED`; no ordinary backend access. | Independently authenticated enrollment and currentness proof bound to backend identity. | Root custody, authority, format, provisioning, path/object binding. |
| Fence acquisition; backend is `READY` | Obtain exclusive fencing generation before opening/using mutable handles. | Stale owner, second process, coordinator/OS error, crash during lease. | Deny reads/writes/work until ownership is unambiguous. | Valid current fence and proof prior owner cannot commit. | Cross-process primitive, stale-handle rejection, namespace and OS assumptions. |
| Consensus decision/input binding; fence held | Verify finalized decision, ordered transaction bytes, deployment, prior position, ruleset. | QC/history missing, body mismatch, conflicting position, replay. | Reject operation before prepare/effects. | Verified finality/current history and exact canonical input binding. | Consensus authority, history completeness, ruleset-transition/replay policy. |
| Durable prepare; inputs verified | Persist `PREPARED(operation, prior_position)` and required integrity/currentness evidence. | Error or timeout may mean present or absent; crash before marker. | No effects until prepare is proven durable; ambiguous prepare remains gated. | Recovery-only read of exact operation record plus authenticated history. | Atomic/durable prepare primitive; proves crash-before-marker has no effects. |
| Isolated calculation; prepared | Read coherent snapshot and compute candidate state. | Worker panic, read error hidden by API, absent-account materialization, arithmetic refusal. | Keep committed state inaccessible to ordinary work; no partial candidate publication. | Exact input/ruleset and proof published state was not mutated; membership audit. | Error-bearing read/write API, coherent snapshot, Stage B membership contract. |
| Atomic commit; candidate validated | Atomically publish account values/membership, operation record, state digest, and new position. | Commit error, timeout, process crash, partial write if primitive is not atomic. | `PREPARED`/quarantine gate; no retry or next operation. | Selected engine's documented commit semantics plus authenticated external position and state/history reconciliation. | **Feasibility blocker:** atomic visibility/durability of state plus metadata not established in source. |
| Durability barrier; commit possibly visible | Establish required durability before success ack. | Flush error, lost response, power loss; commit may be durable or not. | Mark outcome unknown; gate service. | Backend-specific durable commit identity after reopen and selected failure-model evidence. | Sync semantics and power-loss guarantees for selected engine/filesystem. |
| Cache and ack; commit proven | Rebuild/update cache then send block-correlated result. | Cache mismatch, process crash, caller response loss. | No second execution; maintain committed identity; gate if cache uncertain. | Durable commit record, verified state digest, prior result identity. | Cache derivation, completion API, receipt/metric replay semantics. |
| Restart with unresolved status | Inspect under exclusive recovery-only access before normal open. | Missing/corrupt marker, DB open error, stale history, conflicting authority. | Refuse all ordinary reads/writes and service startup. | Authenticated current status, full commit/history evidence, state recomputation or trusted checkpoint. | Read-only/non-mutating inspection primitive; external history/currentness source. |
| Recovery authorization | Assess whether committed, safely abortable, or indeterminate. | Authority unavailable/compromised; evidence replayed or self-authorized. | Remain quarantined on any uncertainty. | Independent authorization bound to exact transition and backend; freshness/replay protection. | Recovery authority, roles, auth/currentness mechanism, recovery procedure. |
| Return to service | Install verified state, position, and new fence generation. | Crash during restoration, stale handle survives, concurrent writer appears. | Keep gate closed until all readers/writers fenced and post-check succeeds. | Independent post-recovery audit and verified current authority. | Fencing enforcement and independent operational evidence. |

## 9. Future validation plan

Every control below is **FUTURE / NOT EXECUTED**. Synthetic injection is useful
for control-flow sensitivity only; it does not establish RocksDB, OS,
filesystem, power-loss, or operational behavior.

| Control | FUTURE / NOT EXECUTED target | Evidence class and limit |
|---|---|---|
| Identity-binding sensitivity | Mutate deployment, chain, epoch, height, parent, QC/finality evidence, transaction order/bytes, ruleset, prior position, and state ID independently; require rejection. | Synthetic canonical-input controls do not establish the external finality or authority. |
| Duplicate/replay sensitivity | Replay exact committed operation, exact prepared operation, stale prior transition, same-height conflict, altered transaction order, and missing history. | Must verify duplicate returns stored outcome without re-execution; replay tests do not establish production currentness. |
| Arithmetic/error propagation | Once a production candidate is separately authorized, assert test-only arithmetic expectations and storage-error precedence at sequential and Stage B boundaries. | Owner-approved arithmetic expectations are test-only. Retained author-run debug and release baselines each report 38 passed / 9 failed / exit 101. The isolated-result self-transfer control remains FUTURE / NOT EXECUTED; the oracle is not treated as trusted. |
| Worker-write sensitivity | Inject failure before effect, after possible effect, between account updates, during prepared write, commit, and durability barrier; assert typed result and gate state. | Injection is not a real backend failure or proof of crash durability. |
| Stage B observation | Record values and membership before/after absent sender/recipient reads, Stage B execution, adapter route and publication, and durable reopen. | The absent-sender materialization example is source-derived and has not been executed. Direct Stage B does not prove adapter route or backend publication. |
| Concurrency/fencing | Race two services/processes, stale handles, shutdown/recovery, path aliases, maintenance tools, and a writer that ignores advisory locking. | Requires the actual selected fencing primitive and environment; a same-process mutex test is insufficient. |
| Process-crash boundaries | Terminate at each prepare/commit/cache/ack boundary and reopen from a fresh process. | Process termination is not power-loss testing and does not by itself prove storage durability. |
| Backend failure and power loss | Exercise selected backend's real error paths and controlled crash/power-loss model; validate atomic all-or-none state plus position after reopen. | Requires actual storage/configuration and documented environment; synthetic errors are separate evidence. |
| Recovery authority/currentness | Test valid, stale, replayed, missing, conflicting, compromised-channel, unauthorized, and unavailable evidence, with refusal on uncertainty. | Requires separately provisioned owner-approved authority; no test boolean substitutes. |
| Full end-to-end route | Demonstrate configured adapter route, worker completion, atomic publication, cache, service read/write gates, restart, and recovery against intended deployment configuration. | Requires future integration and operational evidence; no current route coverage is claimed. |

The smallest future sequence is: (1) resolve owner decisions and feasibility
blockers; (2) review a typed interface and canonical identity contract;
(3) test identity/replay and sensitivity controls synthetically;
(4) validate the selected storage atomicity and fencing primitives in
isolation; (5) exercise full adapter/worker and Stage B route controls;
(6) perform process-crash/reopen and backend-specific durability tests; and
(7) obtain independent operational review before any activation decision.
Passing arithmetic tests alone is not evidence of storage safety,
transition-compatibility, history completeness, or production readiness.

## 10. Open owner decisions and preserved dispositions

Before implementation, the owner and independent reviewers must decide:

1. Which source is authoritative for finalized consensus history, deployment
   identity, current ruleset, execution position, and recovery authorization?
2. What finality evidence must be verified, and how is complete historical
   continuity established after pruning, restore, conflict, or outage?
3. What identity encoding, hash/signature suite, trust roots, currentness and
   replay protections are acceptable? Which are classical assumptions and
   whether post-quantum properties are required remain explicit decisions.
4. Which database/transaction primitive and failure model provide atomic,
   durable account-plus-position publication and inspectable unknown outcomes?
5. How are account presence, default-valued entries, deletion, and Stage B
   read materialization represented and committed?
6. Which OS/backend/namespace mechanism fences all processes and stale
   handles, including maintenance and recovery tools?
7. Who may enroll, quarantine, assess recovery, authorize abort/roll-forward,
   and return a backend to service, using what independently authenticated
   current evidence?
8. Which mixed-version execution, ruleset transition, replay, and historical
   re-execution rules apply, and what happens when history is unavailable?
9. What completion result does a caller receive for queue admission,
   execution rejection, definite storage failure, unknown commit, and
   durable success? How are receipts and metrics reconstructed?
10. Which validator signing, proposal/vote participation, bundle signing,
    and signer-continuity gates remain separate from VM recovery?

The owner-approved arithmetic expectations remain test-only. The retained
test baseline remains author-run evidence, not a production contract. The
isolated-result self-transfer control remains unexecuted. Worker-write
propagation, durable atomicity, recovery authority, authenticated history,
mixed-version/replay behavior, and route coverage remain OPEN.

Prior ATOM-1/M18, CB-1, CB-FIXTURE-1, no-replacement-database,
consensus-oracle, and RPC dispositions retain only their reviewed scopes.
This document changes none of them. The required-persistence candidate
remains NOT ACCEPTED / NOT INTEGRATION-READY; recipient overflow, A23-F1,
and A33-F1 / E27 remain OPEN; activation remains DISABLED; public DevNet
remains NO-GO.

## Scope and limits

This candidate protocol is a new documentation proposal for independent
review. It does not modify production or test code or historical evidence.
All proposed controls are FUTURE / NOT EXECUTED. No tests or node were run;
no operational keys, provisioning, PR, merge, deployment, or activation were
used.

The atomic account-plus-position primitive, durable pre-effect preparation,
safe recovery-only inspection, global fencing, independently authenticated
current history, and recovery authority are feasibility blockers until
selected and demonstrated. No candidate stage authorizes execution,
recovery, signing, participation, or return to service.
