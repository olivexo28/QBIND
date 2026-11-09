# Worker Write Failure and Backend Reuse: Specification Requirements

**Status:** Decision support only. No production policy or recovery authority
is selected here. The required-persistence candidate remains **NOT ACCEPTED /
NOT INTEGRATION-READY**. Activation remains DISABLED; public DevNet remains
NO-GO.

## Pinned basis

- Reviewed controls branch: `test/shared-state-blocker-controls`
- Reviewed endpoint: `25cd872cd7c6b63b83279dd92ebcc0d7f052c0ea`
- Endpoint tree: `f1ed269cffd7c86d95dfd124523a2c3c2b1de04c`
- Expected main: `aa382fa28b2d3e97e6203d47fa8231b5f2269741`
- Underlying shared-state correction: `6a127fff955de04e3636b6e12b6c2e7e400bc37a`
- Test-control source commit: `6d212fe563bc47a43fba5d3fdf9a365aa387aa73`
- Test-control `execution_adapter.rs` blob: `13adcb22f3317485c47ed019daf019599193e721`
- Reviewed controls and limitations: `docs/security/evidence/shared-state-blocker-controls-20261109.md`
  at the reviewed endpoint; retained output hash
  `9418254723df3e169bfc614c28d264a9917dfb41e4e7df20d2156ed209973005`.

The line references below refer to the pinned endpoint. The controls remain
test-instrumented author-run observations: no actual RocksDB put failure,
durable corruption, rollback, or safe recovery was established. The prior
RPC-1/2 controls retain only their documented partial dispositions and
scheduling limits; this brief does not reopen or strengthen them.

The supplemental source review is pinned to
`test/checked-arithmetic-owner-contract-followup` at
`2fdc30da4174a6b131c10c3e14091a5bea9a766f`, tree
`3bb8f6529b04eca2241ae5d01988cf862be74ae7`. Its source blobs are:

- `crates/qbind-node/src/execution_adapter.rs`:
  `13adcb22f3317485c47ed019daf019599193e721`
- `crates/qbind-ledger/src/parallel_exec.rs`:
  `9791f74b5c54655796edb823743c98d98817b33c`
- `crates/qbind-ledger/src/execution.rs`:
  `fe78bed4bddc5f00aa0ea2c8a464050106d84093`
- Earlier decision brief at that endpoint:
  `86381214217deb92311402adf621cd348f0b3d30`

The additional behavior and line references are pinned to this supplemental
endpoint. It is not a new execution experiment and does not upgrade the
earlier injected controls into real storage-failure or crash-recovery
evidence.

## Decision at issue

The current worker adapts `PersistentVmV0State` to the void-returning
`AccountStateUpdater` and silently ignores a failed put
(`crates/qbind-node/src/execution_adapter.rs:621-675`). The worker then derives
success counts and block metrics from VM transaction results, while flush
failure is logged and execution continues (`:1361-1400`). The public
`AsyncExecutionService::submit_block` result only describes queue admission
(`:475`, `:1492-1518`).

The reviewed test injected an error before the worker's RocksDB put and observed
transaction and block success metrics despite unchanged account values. In a
separate control, a real sender put was followed by an injected panic before
the recipient update; joining the panicked worker released the claim and
allowed a new service claim. That observed partial state and reuse are not
evidence of durable corruption or safe recovery
(`shared-state-blocker-controls-20261109.md`, “Focused controls and observed
outcomes”). The public put control instead performed a successful RocksDB put
and overrode its result afterward; it demonstrates an ambiguous post-effect
error and cache behavior, not a real storage failure.

Two design directions are compared below as proposals only. This expanded
document remains decision support, not an approved production design or
operating procedure.

## Required properties for a future specification

The following are design requirements and decision prompts, not selected
mechanisms. Neither direction below is authorized by this document.

### Observable worker-write failure

At the pinned endpoint, the ledger-facing `AccountStateUpdater` setter returns
no result (`crates/qbind-ledger/src/execution.rs:1138-1145`). The persistent
worker adapter drops the result from `put_worker_account_state` and updates
the cache only on success
(`crates/qbind-node/src/execution_adapter.rs:628-640, 668-670`). The worker
then derives transaction and block metrics from VM results and logs flush
errors while proceeding (`:1361-1400`). `submit_block` returns after queue
admission rather than block completion (`:1492-1518`). Thus the current public
return value is not evidence that execution or persistence succeeded.

A future design must carry a typed storage/execution outcome across each
boundary: transaction mutation, block execution, worker completion, caller
observation, and service health. It must distinguish VM rejection from
storage failure, definite non-effect from possible/unknown effect, and queue
admission from completed publication. A block-correlated completion identity
must survive a lost response so retry does not silently execute the same
block twice. The first failed or ambiguous result must not be overwritten by
a later successful setter, flush, or block. These requirements do not choose
error types, APIs, or retry policy.

### State, membership, and publication are different observations

Transaction-level setter-call counts are not a complete state-change
observation. `StageBPerAccountState::get` obtains an account lock that creates
a default entry when the account is absent, and `to_in_memory` exports every
entry (`crates/qbind-ledger/src/parallel_exec.rs:426-477`). The adapter
extracts touched sender/recipient accounts into a snapshot, executes Stage B,
and applies every final snapshot entry through its updater
(`crates/qbind-node/src/execution_adapter.rs:125-160, 1320-1360`). An absent
account may therefore become present in the Stage B working/final maps
without an explicit transaction-level setter for that lookup; adapter
publication is a further boundary. Whether a default-valued account is
semantically absent or materialized is an unresolved state-format/API
decision.

Future evidence must report separately: (1) account values and membership in
the initial, working, and final maps; (2) transaction-engine setter calls;
(3) adapter snapshot entries submitted to the underlying updater; and
(4) durable backend state after reopen. A zero count at one layer does not
prove zero work or no account materialization at another. A Stage B result or
final in-memory state alone does not establish adapter selection, service
publication, storage success, or durability.

### Atomic publication and unknown outcomes

If atomic publication is selected, the proposed consistency unit must include
the account-state changes and an authoritative execution position sufficient
to identify which block is committed. It must also decide how account
membership/materialization and any durable block identity or completion
record participate. Publishing state and advancing execution position in
separate, independently visible operations leaves a crash window in which
they disagree. Cache state must not be presented as committed ahead of the
durable boundary, and callers must not be told success before that boundary
is established.

A commit call that reports an error, times out, or loses its response may
have committed. Its result is **unknown**, not automatically failure or
success. The service must gate further execution and reuse until a
block-identity-based, independently trusted resolution establishes the
outcome. A later flush or matching account values alone cannot resolve the
identity or prove the complete state transition. The exact commit primitive,
identity, read-back evidence, cache ordering, and caller protocol remain
unselected.

### Crash-safe quarantine requires a pre-effect gate

A quarantine marker written only after detecting a failed write cannot by
itself protect against a crash before that marker is durably written. If
account effects can occur while the durable record still appears healthy,
restart may admit a state whose last attempted block is unknown. A process-
local flag, a worker join, a missing marker, or a marker write attempted
after the failure does not close this gap.

Any future restart-safe proposal must explain a fail-closed protocol for the
entire interval before the first state effect, through commit or uncertainty:

1. Establish exclusive ownership and close access to the backend until its
   durable status has been checked. The gate must cover every relevant
   reader, writer, worker, alternate service instance, and startup path—not
   merely `submit_block` or an in-memory ownership flag.
2. Before allowing effects, durably establish a block-correlated
   in-progress/prepared state (or an equivalent atomic protocol) tied to the
   backend and prior authoritative execution position. If recording that
   state has an ambiguous result, keep the gate closed and resolve it before
   proceeding.
3. Publish account state, account membership semantics, and the new
   authoritative execution position under the selected atomic boundary, or
   leave a durable unresolved state that startup must refuse to serve.
4. On restart, admit access only after authenticated evidence proves a
   consistent committed boundary and current authority. Missing, stale,
   corrupt, unreadable, conflicting, or unauthenticated status is not a
   healthy default; refuse service and reuse.

This sequence is a set of required questions, not a claim that the
repository has such a gate or protocol. A design must specify how it handles
crash before/while preparing, after preparation but before effects, between
effects if they are not atomic, during commit, after commit before response,
and while recording the outcome. It must also prevent access through open
handles or other processes during recovery. If no mechanism can establish
that all access is gated and the last durable boundary is authoritative,
recovery must remain unavailable rather than infer rollback or commit.

Recovery must be authorized by a source independent of the possibly
compromised backend, its local configuration, and any single delivery
channel. Evidence must bind the deployment/backend identity, the affected
execution boundary, and the state/history being accepted; it must be
authenticated, current under a separately established currentness rule, and
protected against replay or substitution. The authority, authentication
scheme, currentness source, recovery evidence format, operator roles,
provisioning, and transition process are all unresolved. Association-
verification authority must remain separate from validator signing and
bundle-signing authority.

### Authority, replay, and signing-history limits

Authenticating a stored anchor or association proves, at most, that the
presented object was authorized by the trust source under its stated
assumptions. It does not show that the object is current, has not been
superseded, or represents complete history. Currentness requires a separate
authenticated mechanism and trust assumption; absent or unavailable
currentness evidence requires refusal. A valid older transition may be
replayed unless transition ordering, freshness, and rollback resistance are
independently established.

Even a current authenticated association does not establish the complete
validator signing history, exclusive signer control, or absence of
equivocation. Recovery authority, canonical execution history, validator
signing authority, and bundle-signing authority are distinct roles and
evidence domains. The design must not use a recovery signature as proof of
signing-history completeness or let association verification authorize
validator/bundle signing. Trust-root custody, classical versus post-quantum
assumptions, transition replay, historical reconciliation, and signer
continuity remain open; this document selects no cryptographic suite or
authority.

## A. Stage a block and publish through an atomic commit boundary

### Proposed unit and scope

The natural candidate unit is a single submitted VM-v0 block: account state
changes for all of its transactions, plus whatever execution position and
block-completion metadata are needed to identify the committed block. A
successful boundary would make the block's state and its durable completion
position appear together; failed or interrupted publication must not expose a
partially applied block as committed.

The present code does not define or persist that complete unit:

- `VmV0ExecutionEngine::execute_tx` writes sender state and then recipient
  state separately (`crates/qbind-ledger/src/execution.rs:2147-2198`); blocks
  iterate transactions in order and return a vector of `VmV0TxResult`
  (`:2508-2522`). Gas-aware paths can also update sender, recipient and
  proposer accounts (`:2224-2500`).
- Stage B computes against an `InMemoryAccountState` snapshot, then copies
  final entries back with repeated updater calls
  (`crates/qbind-node/src/execution_adapter.rs:149-157, 1320-1360`).
  Those calls are not one persistent transaction.
- The worker updates in-memory `current_height`, queue-length and execution
  metrics, logs transaction errors, and may flush the state
  (`:1305-1400`). These process-local values, metrics, logs and any receipts
  delivered elsewhere are not automatically included in a database atomic
  commit.
- `submit_block` admits work to a queue; there is no per-block completion
  receipt or durable association between queue admission and the worker's
  eventual state publication (`:475, 1492-1518`). No external signing effect
  is part of the inspected account-state transaction, and a database commit
  cannot make validator signing, bundle signing, or other external effects
  atomic with account state.

Therefore “atomic block” must be defined by the owner: at minimum account
mutations and an authoritative execution position; cache publication and any
durable block metadata must be ordered consistently with that boundary.
Transient counters, logs, queue state and external effects need explicit
semantics, rather than a claim that one database transaction covers them.

### Error and ambiguity handling

A proposed result-bearing updater and block executor would have to distinguish
VM transaction rejection from state-storage failure. A block-scoped outcome
must correlate to the submitted block (and not merely its height if duplicate
or competing submissions are possible), and reach the caller through a
per-block completion interface or an explicitly designed service-health
contract.

A put failure before staging/publication could be reported as a failed block
only if no relevant effect escaped the stage. A commit error may be ambiguous:
the storage engine might have applied the atomic batch even though the caller
did not receive success. In that case the result must say “outcome unknown”
unless an independently specified read-back/commit marker establishes the
boundary. A later successful flush cannot rewrite an earlier failed or
ambiguous commit into success. Flush itself is not a substitute for atomic
publication.

### Panic, worker loss, and restart

Before commit, panic or timeout should leave staged data unpublished, if
staging is isolated and has no external effects. During or after commit, a
worker panic, lost response or process crash may leave publication outcome
unknown. Admission of subsequent blocks and ownership transfer cannot rely on
thread termination alone; they require resolution of the commit identity and
the authoritative execution position.

For restart safety, either the atomic commit boundary itself must durably
include sufficient execution identity to determine whether the block committed,
or a separate durable protocol must order a prepared/committed marker with the
state change. Its crash windows, replay rules, torn/corrupt metadata behavior
and consistency with the storage engine must be demonstrated. A memory-only
“failed” flag or service claim does not survive process restart. If current
commit status cannot be authenticated, refuse admission/reuse until reviewed
recovery; do not infer commit or rollback.

### Dependencies and trade-offs

This direction likely needs result-bearing mutation and execution interfaces
in `crates/qbind-ledger/src/execution.rs`, changes to the persistent state
implementation and cache publication, plus worker block-completion and
admission changes in `crates/qbind-node/src/execution_adapter.rs`. Public
traits and execution result types affect in-repository and downstream
implementations/callers; the public `AccountStateUpdater` inventory is not
complete beyond this checkout. RocksDB atomicity and crash durability
properties must be verified for the exact operations/options used; a generic
batch API alone does not include cache memory, metrics, receipts or external
signer behavior.

Staging consumes additional memory or storage and adds commit work; serial
block publication can constrain throughput. Atomicity improves the clarity
of state outcomes but cannot remove the “commit may have succeeded, response
was lost” ambiguity without a durable, queryable identity protocol.

## B. Allow partial effects, surface failure, and keep backend unavailable

### Proposed unit and scope

This direction explicitly treats a write or execution failure as potentially
partial. The affected unit is the backend's execution history from a known
last-good boundary through the failed/unknown block. Account values, in-memory
cache, transaction results, execution position and flush status can diverge;
the observed panic control already showed the database sender value advanced
while cache remained at its previous value and recipient remained absent.

The backend must be marked unavailable after a write error, failed/ambiguous
commit or flush, worker panic/loss, or a timeout/missing completion whose
work may still be running. That is a proposed fail-closed admission policy,
not an existing behavior. It does not undo earlier puts or establish the
correct next state.

### Error and quarantine handling

The adapter needs an error-bearing mutation path and a block-correlated
completion outcome that distinguishes definite error from unknown effect.
The first failure must not be discarded by a later successful write, flush, or
block: preserve the first failing/ambiguous boundary and its identity. The
worker must stop accepting/processing later work for that backend until its
status is resolved. Queue admission success cannot be described as execution
success.

The current `Drop` path joins and then clears `worker_claimed` even when join
returns a panic (`crates/qbind-node/src/execution_adapter.rs:1540-1563`).
Keeping a backend unavailable therefore requires more than changing this
in-memory boolean: it needs ownership semantics for normal shutdown, panic,
lost handle, timeout and process restart. If the worker cannot be proven
terminated, do not release its live-process ownership. If it is terminated,
that proves only the thread ended—not that writes were absent or state is
consistent.

### Restart and authorized recovery

An in-memory quarantine flag prevents only same-process reuse. Restart-safe
refusal needs a durable, crash-consistent record tied to the exact backend,
execution identity and affected block/position. The record's ordering relative
to attempted writes matters: a crash can occur before recording quarantine,
between quarantine and writes, during writes, after a write but before a
completion record, or while recording the outcome. Every such window needs
evidence; writing a marker after the failure is not sufficient if the process
can crash first.

When persistent currentness evidence is absent, contradictory, unreadable or
unauthenticated, startup must not treat a missing marker as “healthy.”
The owner must define an independent recovery authority and evidence adequate
to reconcile canonical block history with durable state. Until that is
approved and verified, refuse service/reuse. No authority, durable format,
marker, recovery procedure or API is selected by this brief.

### Dependencies and trade-offs

Likely changes include the public `AccountStateUpdater` contract and every
implementation, transaction/block execution error types, adapter per-block
completion and service admission, backend ownership and durable health
metadata, startup checks, and recovery tooling. The internal
`CachedPersistentAccountState` also updates its cache before discarding
`put_account_state` failure (`crates/qbind-ledger/src/execution.rs:1806-1813`);
this pre-existing behavior is not fixed by only changing the adapter.

Fail-closed quarantine is a smaller state-mutation redesign than transactional
block publication, but it can reduce availability for the entire backend
until an authorized decision. It does not provide rollback, atomic receipts,
or repair. Persistent quarantine introduces storage-format, crash-ordering,
and backward-compatibility requirements. An in-memory flag alone is not
restart-safe.

## Cross-cutting decisions and proposed next slice

Neither direction is implementable as a narrowly scoped adapter-only change
while preserving the current void-returning ledger contract and asynchronous
fire-and-forget completion boundary. Both require coordinated ledger and
adapter API work and downstream caller review. Owners should decide, before
implementation:

1. Is block-level atomic publication required, or are partial effects
   acceptable with fail-closed quarantine?
2. What is the block identity and authoritative execution-position evidence
   used to resolve retries, duplicate submissions and ambiguous commits?
3. What outcomes must callers observe, and does the service expose per-block
   completion, terminal health, or both?
4. Which failures stop later work, and what process-restart behavior is
   required when the worker or response is lost?
5. Who can authorize recovery, what evidence is sufficient, and what happens
   if it is unavailable or conflicts with stored state?
6. Which database guarantees and crash-consistency assumptions are accepted,
   and which effects (cache, receipts, metrics, logs, external signing) remain
   outside that transaction?

**Proposed smallest defensible next step:** owner decision plus a reviewed
interface/failure-state design that covers both the ledger mutation result and
the async block outcome before production changes. Then choose one direction
for an isolated candidate. If the owner selects A, first prove the exact
storage transaction boundary and cache/metadata publication order. If B is
selected, first approve a restart-safe quarantine and recovery authority;
do not ship a process-local flag as the safety boundary. This recommendation
does not select either design.

## Future verification matrix

Every item below is **FUTURE / NOT EXECUTED**. Injected failures, process-crash
experiments and operational/production evidence are separate evidence classes.

| Control | FUTURE / NOT EXECUTED evidence target | Evidence class and limit |
|---|---|---|
| Put failure before any effect | Exercise the real persistent worker and public completion path; assert identifiable failure and admission policy. | Injected adapter/storage-result failure is synthetic control, not an OS/RocksDB failure. |
| Error after possible effect | Cause a real or controlled ambiguous returned result after a write; query durable block identity and require `unknown` until verified. | Injected post-call error demonstrates ambiguity only; actual storage error requires backend-specific test evidence. |
| Multi-account / multi-transaction partial effects | Fail the recipient update after sender update and a later transaction after an earlier transaction; assert either atomic absence or explicit partial state plus refusal. | Synthetic failure injection; no rollback claim without the selected transaction mechanism. |
| Commit and flush outcomes | Fail before commit, during/after commit, and during flush; correlate each outcome to a block and preserve earlier errors across later successful flushes. | Backend-injected errors are distinct from process-crash durability tests. |
| Panic and worker loss | Panic before first write, between account writes, after commit, and after commit before response; observe join result, completion, admission, and ownership separately. | Controlled panic does not model process termination or durable recovery. |
| Timeout / missing response | Hold work beyond a deadline, lose the waiter/response, then prove no overlapping execution or unsafe release while the original work can continue. | Bounded scheduling control; cancellation is not termination proof. |
| Cache consistency | Compare cache, reopened database state, committed block identity, and transaction receipts after each injected/ambiguous failure. | Same-process reads alone do not prove durable state. |
| Ownership and reuse | Attempt competing service construction during active work, shutdown, join, panic, timeout and after restart; require release only at the selected safe boundary. | In-process join tests are not restart or recovery evidence. |
| Restart and crash windows | Use controlled process-crash/power-loss testing around every durable marker/state ordering boundary; reopen and refuse or reconcile exactly as approved. | Separate crash experiment; filesystem/VM behavior and storage configuration must be recorded. |
| Crash before failure/quarantine marker | Crash before the error handler can persist a failure marker, including while preparing the block and while resolving an ambiguous prepare; prove the startup gate cannot treat an unrecorded attempted operation as healthy. | FUTURE / NOT EXECUTED. Must test the selected durable pre-effect protocol and actual reopen path; an injected post-error marker does not cover this window. |
| Gated access and restart | Attempt every configured read/write/service path through startup, recovery, alternate handles and competing processes while state is unresolved; require refusal until authenticated resolution. | FUTURE / NOT EXECUTED. An in-process boolean or one service's queue gate is insufficient evidence of system-wide exclusion. |
| Account membership and adapter publication | Record account-key membership and values before/after touched-account extraction, Stage B get/set/final-state export, adapter selection and each updater publication; reopen the persistent backend and compare. | FUTURE / NOT EXECUTED. Must distinguish read materialization, transaction setter calls, adapter writes and durable entries. |
| Authorized recovery | With independently provisioned and authenticated recovery authority, test valid, stale, conflicting, missing and unauthorized evidence; refuse absent/ambiguous authority. | Requires owner-approved authority and real provisioning; not simulated by a test boolean. |
| Production readiness | Verify the actual configured storage, startup path, external effects and operating procedure, with independently reviewed evidence. | Operational evidence; unit tests do not establish deployment behavior. |

Existing RPC-1 and RPC-2 controls remain as previously scoped; their lock
observation, scheduling and join sequencing do not establish transactionality,
restart safety, or recovery. The RPC-3/RPC-4 controls likewise remain
characterization, not proof of real write failure or safe reuse.

## Scope and status

This supplemental slice changes only this existing document relative to
`2fdc30da4174a6b131c10c3e14091a5bea9a766f`; it does not create another copy
or alter the earlier controls and historical evidence. The full branch scope
relative to main includes this single-document update plus all inherited
changes from the checked-arithmetic follow-up; exact branch, commit, tree,
parent, and path counts are reported with the independent-review delivery.

No source or test files, historical raw logs, or operational state were
changed. No tests were run. All proposed verification matrix items remain
FUTURE / NOT EXECUTED. No operational keys, live node, provisioning, PR,
merge or deployment were used. No database mechanism, consistency unit
implementation, production API, gate, durable quarantine format, recovery
authority, authentication scheme, currentness mechanism, replay policy, or
signing-history/continuity procedure is approved here. Storage-error
propagation, destination/path authority, startup ordering, worker shutdown,
durability and recovery remain OPEN. The required-persistence candidate
remains NOT ACCEPTED / NOT INTEGRATION-READY; recipient overflow and A23-F1
and A33-F1 / E27 remain OPEN; activation remains DISABLED; public DevNet
remains NO-GO.
