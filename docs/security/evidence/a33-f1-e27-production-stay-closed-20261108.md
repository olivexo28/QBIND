# A33-F1 / E27: production stay-closed boundary and next slice

**PRODUCTION STAY-CLOSED NEXT SLICE — INDEPENDENT REVIEW PENDING.**
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**. Activation remains
**DISABLED**; public DevNet remains **NO-GO**. This is source/design and
documentation only, not implementation, recovery or integration approval.
The [local fencing clarification](#local-owner-and-worker-contract--fencing-clarification)
below supersedes ambiguous fencing language in this historical proposal.

## Identity and provenance

Repository `olivexo28/QBIND`; preflight HEAD, local `main`, remote-tracking
`origin/main` and direct remote `refs/heads/main` were
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`. The starting branch was
`main`; index, tracked worktree and untracked-file status were clean. No
applicable `AGENTS.md` was found in the repository or its ancestor directories.
The dedicated branch is `docs/a33-f1-e27-stay-closed-next-slice`. The complete
intended changed-path list relative to the baseline consists solely of this
file. The commit and tree of the delivered branch are reported separately
after commit; a commit cannot contain its own identity.

Source anchors below are pinned to the baseline. `M` denotes
[`crates/qbind-node/src/main.rs`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs),
`B` denotes
[`crates/qbind-node/src/binary_consensus_loop.rs`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs),
and `E` denotes
[`crates/qbind-consensus/src/basic_hotstuff_engine.rs`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-consensus/src/basic_hotstuff_engine.rs).
Ranges identify evidence, not a claim that every external caller or deployment
is known.

The user-supplied direction is accepted: unresolved partial catch-up stays
closed across restart, with no automatic clear or resume. Earlier bounded
PASSED/CLOSED decisions and test-only model acceptances remain as recorded;
they are not reopened or expanded. The separate, available
[recovery/resume carry-forward](https://github.com/olivexo28/QBIND/blob/7fcb3b96dd4263dc60f1d81871c541ddb4210631/docs/security/evidence/recovery-resume-inventory-20261107/README.md)
is pinned to its own branch and source baseline `9bf0eb43e4e3c601d02d3886d220b0abeb3a103e`,
not presented as part of this main tree or as independent production
acceptance. Its sections 3, 5 and 7 distinguish local ownership and
uncertain effects from recovery authority; section 8 retains the supplied
PASS WITH LIMITATIONS on the scoped inventory corrections. No reviewer
identity or unavailable raw review is inferred. Any later unprovided
carry-forward or model acceptance cannot be independently checked here.

## Current production boundary

| Surface | Baseline source and bounded consequence |
|---|---|
| Inbound response | [B:7379-7440](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L7379-L7440): after sender binding and receipt accounting, every non-empty response is rejected; every empty response is counted as ignored and returns. Binding failures return earlier. These are dispatch containments, after decoding, not durable quarantine or universal engine fencing. The optional no-gate compatibility path is not authenticated binding. |
| Callable import | [E:3946-4047](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3946-L4047): public `apply_restore_catchup_blocks` validates each item, then registers it and replays logical QC signers before validating the next. Registration, vote accumulation, QC/lock/commit and eviction-related effects may precede a later error; successful completion can advance view. It verifies logical quorum shape, not constituent endorsement signatures. No rollback is implied. [B:8466-8567](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L8466-L8567) contains the compiled direct helper and its stale-anchor and error behavior, but current inbound response dispatch does not call it. Source search found no other non-test workspace call of the importer; its public API does not exclude external library callers. |
| Mode and leader | [B:2308-2425](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L2308-L2425), [B:3124-3306](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L3124-L3306), [B:3662-3770](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L3662-L3770): mode is in memory, initialized from the current invocation's baseline. It suppresses local timeout, defers only selected proposals and controls requests; it does not stop `engine.try_propose()` before action admission, caching or logical self-vote. The no-I/O tick branch is separate. Restart without a restore baseline does not reconstruct an unresolved catch-up state from this mode. |
| Other engine and output | [B:6576-6681](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L6576-L6681), [B:6959-7335](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L6959-L7335): proposal/vote and eligible Timeout/NewView handling are distinct routes. [B:3160-3210](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L3160-L3210) shows post-inbound snapshots, epoch transitions and persistence; ticks also trigger snapshots. Catch-up requests and response exports can publish; cached proposals/votes can be re-emitted. A guard only at import or response receipt would miss these paths. |
| Signing | [M:8673-8708](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L8673-L8708), [B:4376-4469](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L4376-L4469), [B:4956-5035](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L4956-L5035): production selects Required and has no PV authority/current snapshot or journal wired; guarded Proposal/Vote routes refuse missing admission/journal. This neither reverses prior engine mutation nor fences Timeout signing ([B:7601-7740](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L7601-L7740)), external signers, other processes, or all future routes. An invoked signer with a timed-out/cancelled result may still have signed. |
| Startup and local ownership | [M:2503-2552](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2503-L2552) holds a destination advisory lock for participating data-directory startup; stateless starts lack it. Requested snapshot restore applies before ordinary startup's RTR check ([M:2783-2852](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2783-L2852), [M:5034-5124](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5034-L5124)). RTR `INTENT`/`COMPLETE` tracks snapshot materialization, not catch-up or signing history; ordinary startup permits absent RTR. The separate reset path obtains its own lock before reset effects ([M:2215-2247](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2215-L2247)). The local lock is not a cross-host signer lease. |

The node's startup/lifecycle owner, holding destination ownership across the
entire participating lifetime, is the candidate owner of a durable unresolved
state; the binary consensus loop is the serial engine owner and must consume
that decision before scheduling effects. Neither `RestoreCatchupModeState`
nor a peer response is that owner. P2P security preflight is before
`builder.build()` and the latter precedes consensus spawn
([M:8120-8140](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L8120-L8140),
[M:8704-8708](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L8704-L8708)).
Checking only at spawn is too late for earlier restore and reset effects.

## One recommended follow-on slice: sticky refusal boundary

Implement a **node-owned, durable unresolved-attempt latch plus startup
refusal**, without a recovery importer, automatic clear, or participation
grant. Keep both existing dispatch returns unchanged. The slice prepares a
safe boundary for a future attempt; it does **not** make the current
unreachable importer reachable. In particular, ordinary rejected network
responses must not create persistent markers or let a peer permanently
disable a node. With current dispatch there is no production catch-up import
attempt to latch, so the slice is not evidence that an actual partial import
has been quarantined.

1. Under a held destination-ownership domain, a node-owned attempt entry
   must durably publish a sticky `unresolved` intent **before** the first
   possible catch-up protected effect: engine registration/vote, state or
   evidence publication, signing, or any worker permitted to perform one.
   Record a version, destination/domain identity, unique attempt identity,
   operation kind and starting anchor/context sufficient to distinguish
   attempts and diagnose the interruption; these values are bookkeeping,
   not proof of authenticity, finality or freshness. No peer-controlled
   claim may itself authorize an attempt. Do not select a concrete storage
   backend in this record.
2. For this slice the entry **refuses application even after a successful
   intent write**; it must not call `E::apply_restore_catchup_blocks`, the
   response helper's import branch, or any replacement importer. This keeps
   legacy logical-QC input from becoming authority. First close admission to
   new participation, then publish intent before relying on a drain/fence
   of already admitted work. A successful durable intent is deliberately
   sticky even when no mutation follows. If safe quiescence cannot be
   established, refuse the attempt without importing and preserve uncertainty.
   A later implementation proposing mutation requires a separate reviewed
   change.
3. On startup, classify the catch-up record under destination ownership
   **before** requested restore materialization, reset effects, starting
   listeners/dials, consensus loop, signer-capable work or publication from
   affected state. The normal check belongs immediately after acquisition at
   M:2515, before restore dispatch; the separate reset path requires its own
   check after M:2240 and before reset effects, or must refuse while the
   classification cannot be made. Do not rely on the later ordinary RTR
   guard. Unresolved, corrupt, foreign, unsupported, unreadable, ambiguous or
   unclassifiable state is a non-zero, diagnostic refusal. Do not let a
   snapshot restore, reset, restart, timeout, empty response, successful local
   operation or matching height clear it. Account for all other state-mutating
   or signer-capable CLI/startup exits before asserting complete coverage.
4. An acknowledged unresolved record remains unresolved after process death.
   If publication/barrier fails or its outcome is uncertain, no importer or
   new participation starts; classify the observed durable result on next
   start, and refuse if it cannot prove the safe classification. A failed
   publication cannot itself guarantee durable evidence of in-flight work;
   absence is safe only under the separate provisioning and signing-history
   assumptions below. An error after
   any attempted effect is not proof of rollback: retain/report known effects
   and unknown outcomes and remain closed. No success-shaped default,
   catch-and-continue, or implicit cleanup is permitted.

**Fencing contract.** For a running owner, establish a linearization point
that prevents admission before intent/effects and invalidates queued work;
then account for already-running work before treating the fence as effective.
The gate must cover both `run_binary_consensus_loop_with_io` select branches:
leader `try_propose`, inbound Proposal/Vote and Timeout/NewView delivery,
local timeout, catch-up request/response export, caches and re-emission,
forwarding, periodic/signal snapshot publication, reconfiguration/epoch
persistence and any downstream workers derived from this engine. Diagnostics
and bounded refusal metrics may continue, provided they cannot publish
recovered state or participation messages. Drop or invalidate queued inbound
and outbound actions, and reject late results against the same ownership
generation immediately before the final effect; do not assume closing a
channel cancels already dequeued work. Inspect actual transport queue/send
and snapshot worker lifetimes during implementation: already published bytes
cannot be recalled, and the node must not report a complete fence until
in-flight effects are resolved or explicitly classified uncertain.

Proposal/Vote reservation guards and Timeout signing are separate final effect
boundaries. Fence before signer invocation and before publishing returned
signatures; a late response from an invoked signer is uncertain, not proof of
no signature. A local gate cannot revoke an HSM call or another host's access.
The slice must refuse an attempt if its required local quiescence cannot be
proven; global signer exclusivity, copied destinations, rollback and
out-of-process signing remain assumptions/dependencies, not coverage claims.
The standalone public engine API is outside the node owner's enforcement:
do not describe this as a universal library or signer fence. Any future node
caller must go through the owner; require a caller inventory and a
non-bypass control before changing dispatch.

**Errors and observability.** Use distinguishable refusal reasons for
unresolved, unknown/invalid, ownership unavailable, intent publication
failure/uncertainty and in-flight work not quiesced. Emit an actionable
startup fatal diagnostic without secrets, a nonzero process outcome, and a
bounded runtime counter/status for an attempted transition. Neither a counter
nor an intent is a recovery receipt. Existing dispatch accounting must remain
unchanged. Pre-effect rejection must leave protected engine/state/signature
effects absent; after a started effect, report acknowledged, partial and
uncertain outcomes separately, not as unchanged or successfully recovered.

## Decisions and acceptance controls before implementation

The accepted stay-closed rule is not up for reapproval. Reviewers must decide
the following implementation dependencies rather than silently choose them:

* **Durability and identity:** supported filesystem/database and actual
  crash/barrier semantics, atomic publication/read rules, record schema,
  destination binding, and scope of one exclusive owner. Existing RTR
  publication and `restore.lock` are local precedents, not a selected backend
  or global fence. Failed rename/directory sync may have published despite an
  error. Power-loss, copied-directory and hostile rollback guarantees require
  their own evidence.
* **Absence and rollout:** a newly absent latch cannot prove that an older
  binary or copied destination never suffered partial effects. Choose a
  reviewed provisioning/migration classification or refuse unclassifiable
  destinations; do not treat absence, RTR COMPLETE, a fresh process, or
  successful snapshot restore as proof of clean catch-up history. Define
  stateless/no-data-dir behavior and reset/CLI coverage before participation.
* **Concurrency and signing:** define the actual quiescence barrier, delivery
  and ownership-generation checks, outstanding signer result treatment, and
  whether signer/transport workers can be controlled or must cause refusal.
  Cross-process/host or HSM exclusivity and rollback resistance need a
  separately established authority; local advisory locking alone is not it.
* **Entry and UX:** define who may request a local attempt, exact attempted
  operation identity, safe refusal diagnostics, and how to prevent arbitrary
  peers from creating a sticky denial. No supported clear procedure is
  selected. An owner may later review one separately; it is not part of this
  slice. No cryptographic proof route, currentness service or recovery backend
  is chosen here.

Focused controls for the **future implementation, not executed here**:

* **Positive and dispatch:** an explicitly provisioned known-clean destination
  starts under the documented assumptions; ordinary pre-effect rejected
  empty/non-empty dispatches retain their exact counters and create no latch.
  A controlled local attempt durably records one unresolved identity and
  returns the exact refusal without invoking the importer, signing, or
  publishing a consensus action. Test the actual startup/owner entry points,
  not only a state-machine mock.
* **Negative and sensitivity:** inject unavailable/contended ownership,
  absent-but-unclassified, corrupt, truncated, unsupported, foreign, stale or
  unreadable records and failures at each write/barrier. Assert the exact
  error, nonzero outcome and no pre-effect protected mutation; show a
  deliberate omitted/late guard is detected by the same state and output
  oracle. Cover requested restore, ordinary startup, reset, stateless mode,
  both loop I/O configurations and all relevant CLI exits. Keep existing
  bounded containments unchanged.
* **Crash/restart:** terminate a child before intent, during staging, after
  publication/before acknowledgement, after durable acknowledgement and
  after each controlled attempted effect; restart a fresh process against the
  same owned destination without restore flags. Assert observed records,
  exact refusals and no participation. Include failure/uncertain directory
  synchronization and partial-prefix/error fixtures, and distinguish known
  pre-effect failure from unknown outcome. Process-kill tests alone do not
  prove power-loss durability or resistance to rollback/copy.
* **Queued/in-flight:** use barriers and recording facades/signers to pause
  work before and after the fence: leader actions, inbound messages, cached
  re-emission, timeout signing, snapshot/epoch publication, queued transport
  and late signer/worker completion. Verify no new protected effect after
  the established fence; pre-fence or already-invoked effects must be
  observed/drained or reported uncertain, never asserted undone. Include
  competing local owners and stale-generation rejection; do not turn those
  tests into a claim of global exclusivity.

The refusal-only direction has a real liveness cost: honest suffixes are
already refused, empty responses cannot clear mode, and a restored node can
remain in mode indefinitely, attempting eligible requests, deferring
selected proposals and suppressing local timeouts. A sticky unresolved record
can additionally block future startup indefinitely. This is intentional
availability loss, not an automatic recovery route or proof all other engine
work currently stops. A cluster with insufficient remaining voting power may
stop making progress; no deployment impact is measured here.

## Reused evidence and remaining scope

* [A17 integration](a17-f1-integration/README.md) and
  [corrected controls](a17-f1-test-controls/README.md), plus
  [empty-response implementation](empty-restore-response/implementation-20261107/README.md),
  document scoped dispatch controls and their historical author executions.
  They do not prove durable quarantine, all engine/signer paths or production
  recovery. The [voting-ancestry record](voting_ancestry/README.md) documents
  its own bounded correction and fixtures, not a catch-up authority.
* The separate carry-forward's
  [P1 provider model](https://github.com/olivexo28/QBIND/blob/7fcb3b96dd4263dc60f1d81871c541ddb4210631/docs/security/evidence/recovery-resume-inventory-20261107/p1-provider-model-implementation/README.md),
  [fixture correction and handoff](https://github.com/olivexo28/QBIND/blob/7fcb3b96dd4263dc60f1d81871c541ddb4210631/docs/security/evidence/recovery-resume-inventory-20261107/p1-provider-verifier-handoff/README.md),
  and [composition ordering](https://github.com/olivexo28/QBIND/blob/7fcb3b96dd4263dc60f1d81871c541ddb4210631/docs/security/evidence/recovery-resume-inventory-20261107/p1-composition-resource-ordering/README.md)
  provide test-only lease, lifetime, refusal-order and sensitivity precedents.
  Their recorded scoped acceptances are preserved. Simulated currentness and
  a synthetic signature are not production provenance, quorum finality,
  durable application, signer fencing or resume authority.
* The integrated [application-frame evidence](application-frame-scoped-candidate-20261108/README.md)
  and [transport-frame evidence](../../devnet/evidence/transport_frame_checked_endpoint/README.md)
  retain their revision-specific results and limitations. Checked endpoint
  arithmetic is present in `p2p_tcp.rs:190-215` and
  `qbind-net/src/transport.rs:47-67`. Native 32-bit execution was not
  established by those records; neither correction supplies nested decode
  resource bounds, quarantine or recovery.

New execution in this task consists of Git preflight/ref inspection and
source/document reads, followed by documentation/scope checks and branch
publication. No unchanged tests, builds, node, network experiment, deployment,
operational signing, activation, PR or merge is run. Existing audit register,
remediation plan, source and historical evidence bytes are not modified.

After the proposed slice, authenticated recovered prefix/finality, trusted
currentness, signing-history continuity, global fencing, anti-rollback,
resource bounds, safe reconciliation and any separately authorized
clear/resume remain OPEN. A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain OPEN;
activation DISABLED; public DevNet NO-GO. This proposal is neither public
DevNet nor integration approval.

## Local owner and worker contract — fencing clarification

**LOCAL STAY-CLOSED FENCING CONTRACT — INDEPENDENT REVIEW PENDING.**
The user supplied independent **PASS WITH LIMITATIONS** for the reviewed
proposal's documentation and direction; it is not acceptance of a
production quarantine or an implementation-ready contract. Earlier scoped
acceptances are unchanged; no reviewer identity or raw review artifact is
asserted. This addendum is a concrete proposed local contract, not implemented
enforcement, and still needs independent review and the decisions below.

Continuation preflight: direct remote `main` and local `main` at
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`; direct remote and local
`docs/a33-f1-e27-stay-closed-next-slice`, starting HEAD and reviewed parent
`f0c516a755c155d409c3655f50ba04a63aa98ad8`, tree
`d41db469bef858062b4f63feaa460e9c90ee2281`. Checkout was already on that
branch; index, tracked worktree and untracked status were clean. Remote is
`olivexo28/QBIND`; no applicable `AGENTS.md` was found. This continuation
changes only this file, preserving the original text as historical evidence.

### Controlling clarification: three independent observations

The earlier sentence in **Fencing contract**, “must not report a complete
fence until in-flight effects are resolved or explicitly classified
uncertain”, is **superseded**: classification as uncertain alone does not
establish a fence. The earlier acceptance-control phrase “observed/drained
or reported uncertain” likewise means effect accounting, **not an
alternative to the required quiescence barrier**. The rule below controls
all readings of the original proposal.

* **A — admission closed:** the local owner has atomically stopped granting
  new protected-work admissions and recorded revocation of the active
  generation. This does not imply pre-existing work has stopped.
* **B — effect outcome unknown:** an already admitted operation may have
  invoked a signer, sent bytes or attempted a write without an authoritative
  result. Record `Unknown` against that operation and retain the unresolved
  state; neither record proves no effect occurred or that a worker stopped.
* **C — local quiescence proven:** A holds, every previously admitted
  operation and descendant capable of a covered local effect is accounted
  for, and the barrier has positively established that none can subsequently
  initiate or complete a covered **local** effect. No queue, worker,
  active effect permit or local callback capable of the covered effect
  remains. This statement is scoped to the inventoried local boundary.

A and B can hold while C is false, e.g. a signer call is still executing.
A and C can later hold while B remains true, e.g. a local worker has
terminated and no local publication can follow, but the remote signer's
result is still unknown. C does not prove that the external signer has
stopped, that no signature exists, or that delivered bytes were retracted.
Already published bytes cannot be recalled. Closing a channel, requesting
cancellation, timing out, dropping a future/handle, a counter increment, or
writing `Unknown` is not a join, drain, effect acknowledgement or proof of
physical cancellation. If C cannot be proven, the barrier remains incomplete
and participation stays refused. If C is proven but B persists, remain
unresolved and refused; C is not permission to clear or resume.

### Proposed local owner protocol

The candidate node lifecycle owner owns destination ownership, admission,
revocation and a complete outstanding-operation ledger; the engine loop and
workers are subordinate, not independent sources of authority. This is
proposed wiring: today's restore-mode flag, transport queues, snapshot tasks
and signer do not implement it. A ledger entry has an owner-incarnation and
non-reused generation, operation identity, effect class, ownership/liveness
state and a **separate** effect outcome (`not invoked`, acknowledged,
partial or unknown). Exhaustion, duplicate identity, failed bookkeeping,
owner loss or missing handoff refuses; `Unknown` must never be treated as
`not invoked`. Bounds and durable representation remain undecided.

1. **Admission linearization.** A single local coordinator serializes
   `admit`, `revoke`, effect-permit reservation and operation/child handoff.
   `admit(G)` atomically checks owner live and admission open for G and
   registers an outstanding operation **before** its work is queued or
   executed. No protected work exists without a ledger owner. Queue transfer,
   fan-out, callback and dequeue either atomically transfer ownership to a
   tracked child/worker or retain the parent until all descendants terminate;
   failed handoff cannot erase ownership. Untrusted peer response refusal is
   not an attempt and creates no durable latch.
2. **Revocation.** Under the same serialization boundary `revoke(G)` closes
   admission and invalidates G. That atomic change is A's linearization point.
   Cancellation requests and dropping queued work may assist draining, but
   entries retire only on positive completion or positively proven
   non-execution, including tracked descendants. A discarded queue entry
   requires proof it was never concurrently dequeued; otherwise it stays
   outstanding. No new generation may reopen participation in this slice.
3. **Final-effect interleaving.** A worker's earlier generation check is
   advisory only. Immediately at each protected effect, it must acquire an
   effect permit by atomically checking G and the live ledger entry under the
   **same** coordinator as revocation. If revoke linearizes first, permit
   acquisition fails and no effect is attempted. If the permit linearizes
   first, the operation remains explicitly owned as in flight until the
   effect and all locally capable continuations complete; revocation can
   close new admission but cannot declare C meanwhile. The physical effect
   may occur after A and before C. No unprotected check-then-act gap or
   untracked child is allowed. A stale result cannot acquire a new permit
   for publication; retain its actual effect outcome independently.
4. **Barrier.** After closing A, durably publish the unresolved intent
   before any new catch-up protected effect and before relying on a
   completed drain. Await positive, identity-bound worker termination and
   child/queue ownership discharge, and completion of each locally capable
   effect permit. Only the coordinator's atomic observation of A plus an
   empty live-operation/permit set and verified termination of inventoried
   local executors establishes C. A join acknowledgement is useful only if
   its contract covers the actual executor and all descendants; absence of a
   join handle is not proof. For executors that can outlive their waiter,
   including blocking tasks, retain and observe the actual executor or leave
   C false. Unknown external effects remain B after local completion.

The coordinator must not hold its mutex across blocking I/O, signer calls,
network sends or joins: reserve an owned in-flight permit under it, release
it, perform the effect, then account for completion under it. A stalled
worker can therefore stall C indefinitely rather than deadlocking the
coordinator, though an external call or leaked child can still prevent
quiescence indefinitely. Permit release must not be automatic merely because
a waiter is cancelled or unwinds; termination and ownership of the actual
executor and descendants must be established. Diagnostics, counters and
unresolved-record writes are not a substitute for these observations.

For comparison, a single local actor could serialize admission, revocation
and **all** effects in one executor, with a tracked barrier behind all
already admitted work. It avoids shared-memory races only if every descendant
and final effect truly runs within that actor or is tracked through a
handoff; network writers, blocking snapshot tasks and external signers break
that assumption unless integrated. Waiting inside an actor for a callback
that requires that same actor can deadlock. A mutex held across a final
blocking/external call also serializes revocation, but can block revocation
forever and introduces reentrancy/deadlock risks; it does not cancel external
effects. The permit-plus-ledger protocol above is the recommended bounded
local design for review, not a selection of a persistence backend or a claim
that present source already provides this serialization.

### Source boundaries, ordering and remaining dependencies

The pinned [B:3124-3306](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L3124-L3306)
and [B:3373-3454](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L3373-L3454)
show both select/tick paths. [B:9239-9254](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L9239-L9254)
spawns a fire-and-forget periodic task and an inner `spawn_blocking`;
[M:9255-9355](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L9255-L9355)
has a separate signal snapshot path. A future owner must track the actual
blocking executor and publication, not just its async waiter.
[TCP:3000-3017](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/p2p_tcp.rs#L3000-L3017)
enqueues per peer via `try_send`; [TCP:2324-2399](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/p2p_tcp.rs#L2324-L2399)
has separate writers which dequeue and send. Queue acceptance is not
physical send completion. Inventories and handoffs must cover transport,
snapshot, cached re-emission, local engine mutations, epoch persistence and
all Proposal/Vote/Timeout signer and publication routes. Existing
`ValidatorSigner` is a shared trait with synchronous signer methods
([validator_signer.rs:144-200](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/validator_signer.rs#L144-L200));
the interface does not establish external cancellation or exclusivity. An
already invoked call returning late must update its retained outcome, never
re-enable a stale result for broadcast. A local executor's verified
termination can establish C locally even if an external call's outcome
remains B, but only when no covered local continuation can still publish.
It cannot establish global signer quiescence.

For assessed normal data-directory startup: acquire the destination lock,
then classify the catch-up record **before** canonical consensus storage
open, requested restore materialization, services, signer-capable work or
participation ([M:2503-2552](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2503-L2552),
[M:2617-2630](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2617-L2630)).
For the distinct reset path, classify after its own lock and before reset
effects ([M:2215-2247](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2215-L2247)).
The existing lock acquisition can create the directory/lock file; the
proposed order is not a claim of zero filesystem setup effects before
classification. Other early CLI exits and stateless/no-data-dir operation are
not fully assessed: enumerate and gate or refuse them before claiming
coverage. Current early RTR checks and its COMPLETE state are not catch-up
classification.

During an explicitly authorized local attempt, acquire/retain ownership,
close admission A, durably publish sticky intent, and establish C before
any future catch-up mutation could be considered. In this slice the importer
remains disabled even after C. Intent failure or uncertain durability closes
the current process, but cannot by itself prove a durable marker exists after
a crash; a fresh startup must refuse if safe classification cannot be
established. Empty/non-empty response dispatch remains ignore/refuse and
cannot create the marker. Unknown, owner loss, missing child accounting,
unproven quiescence or ambiguous classification require continued refusal.
No automatic clear or resume exists.

Before implementation, separately decide bounded schema/read and ledger
limits, supported durable barriers and uncertain writes, destination identity,
legacy provisioning/migration and absent-record classification, crash ownership
and all CLI/stateless paths. Establish separately any cross-process/host or
HSM exclusivity, copied-store protection, anti-rollback and external outcome
reconciliation; neither the local `restore.lock` nor the journal's
per-backend domain ([signing_reservation_journal.rs:1329-1345](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/signing_reservation_journal.rs#L1329-L1345))
provides these properties. No recovery authority, storage backend or
clearance policy is selected. Previously accepted P1 provider/lease and
composition controls cited above are single-threaded test-only precedents,
not enforcement of this local concurrent protocol or production currentness.

### Focused acceptance controls — FUTURE / NOT EXECUTED

Each control must assert authoritative owner/worker and protected-effect
state separately from diagnostic text and counters. Use real boundary
entrypoints, deterministic barriers and recording fakes, not timing alone:

| Interleaving | Required observation and bounded proof |
|---|---|
| Admitted worker paused; close admission | A true, worker owned/outstanding, C false; new admission refused. Release the worker and observe actual termination before C. Proves admission closure is not worker cancellation, not global fencing. |
| Check G, revoke, attempt final effect | Pause after a preliminary check; revoke wins coordinator; effect permit refused and recording sink unchanged. Reverse order: permit wins, revoke closes A but C stays false until owned effect and child finish. Proves local serialization, not rollback of an earlier effect. |
| Signer invoked, late/unknown result | Pause inside an invoked signer; A true and C false while its local executor can still act. On late return record actual result and reject stale publication; if executor terminates with outcome unknown, assert C only after all local continuations terminate and B remains. Proves no stale local publication, not external no-signature or HSM cancellation. |
| Unknown recorded while worker runs | Assert B true and A true while the live ledger/permit keeps C false; closing channel or dropping waiter alone does not change this. Proves refusal accounting is not a barrier. |
| Local completion, external effect unknown | Positively observe actual executor and descendants terminated; assert A and C true, B still true, unresolved record and participation refusal retained. Proves local liveness/effect-outcome separation, not external resolution. |
| Quiescent with no new admission | Account for every queued/dequeued child, final permit and executor; assert C only after all discharge, and reject all later admissions/stale callbacks. Exercise transport and blocking snapshot handoffs. Proves only inventoried local coverage, not recall of sent bytes or global signer fencing. |
| Owner loss and restart | Kill/restart around close, intent write/ack and effect handoffs under a fresh owner; an absent unprovisioned, corrupt, unreadable or ambiguous classification refuses before assessed storage/restore/reset/participation effects. Distinguish known pre-effect from uncertain publication; no inferred rollback. Proves tested process-crash ordering only, not power-loss durability or anti-rollback. |
| Sensitivity | Deliberately omit the final permit barrier and separately omit tracking a previously admitted child; the same oracle must observe post-revoke effect or premature C and fail. Restore correct paths and assert non-vacuous positives. Proves the controls detect those mutants, not all possible bypasses. |

No Rust tests or builds were rerun, no node or operational signer was run,
and no source/test, Cargo file, audit register or prior evidence bytes were
changed. This continuation performs only source/ref inspection, documentation
checks and branch publication. All controls above are **FUTURE / NOT
EXECUTED**. Transport, A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain
**OPEN**; activation **DISABLED**; public DevNet **NO-GO**.
