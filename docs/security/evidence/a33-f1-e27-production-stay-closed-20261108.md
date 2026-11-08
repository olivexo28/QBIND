# A33-F1 / E27: production stay-closed boundary and next slice

**PRODUCTION STAY-CLOSED NEXT SLICE — INDEPENDENT REVIEW PENDING.**
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**. Activation remains
**DISABLED**; public DevNet remains **NO-GO**. This is source/design and
documentation only, not implementation, recovery or integration approval.

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
