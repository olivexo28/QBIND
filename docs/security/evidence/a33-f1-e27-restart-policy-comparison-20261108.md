# A33-F1 / E27: restart-policy comparison and next slice

**RESTART-POLICY COMPARISON — INDEPENDENT REVIEW PENDING.** No operating
policy, production format, backend, provisioning procedure, integration,
recovery or participation authority is approved by this task. Transport,
A17-F1 / RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**; activation remains
**DISABLED**; public DevNet remains **NO-GO**.

Preflight: repository `olivexo28/QBIND`; local and direct remote `main`
`0d1b56515c52abe2862064027d1a9f103fef5a0c`, tree
`b3e8914e6ff234afd80fd29b58470c43f2b08009`; current and direct remote
`docs/a33-f1-e27-stay-closed-next-slice` parent
`ebd65c6e0afa0ed3c2ceb2aaf1e302803bfa2e88`, tree
`6bd18dc668aff9313f85d97839485bb1b9012b0f`. Checkout, index and untracked
status were clean; no applicable `AGENTS.md` was found. This continuation
adds only this file. Final commit/tree are reported after commit.

The [one-shot candidate](a33-f1-e27-durable-intent-contract-20261108.md)
and accepted [A/B/C and permit/revocation clarification](a33-f1-e27-production-stay-closed-20261108.md#local-owner-and-worker-contract--fencing-clarification)
are preserved unchanged. Unresolved or ambiguous partial work stays closed;
no automatic clear or resume is proposed. All new acceptance controls below
are **FUTURE / NOT EXECUTED**.

## What main and existing evidence establish

Pinned source at main `0d1b56515c52abe2862064027d1a9f103fef5a0c`:

* Actual response dispatch rejects bound non-empty responses and ignores
  empties before the helper ([`binary_consensus_loop.rs:7398-7440`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L7398-L7440)).
  The public sequential importer remains callable and can retain effects
  before a later error ([`basic_hotstuff_engine.rs:3954-4047`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-consensus/src/basic_hotstuff_engine.rs#L3954-L4047)).
  A rejected ordinary peer response must not create persistent refusal.
* Startup takes a local destination lock, but stateless starts lack one;
  requested restore can open storage before the later ordinary RTR check
  ([`main.rs:2503-2552`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2503-L2552),
  [`:2617-2630`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2617-L2630),
  [`:5034-5065`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L5034-L5065)).
  Reset has a separate lock/early path
  ([`main.rs:2222-2267`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L2222-L2267)).
  Other CLI, stateless and alternate entry paths need inventory. A proposed
  guard must run under the relevant ownership and before protected effects.
* RTR provides a bounded read and a local file-sync/rename/directory-sync
  precedent ([`restore_completion.rs:455-571`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L455-L571),
  [`:641-718`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/restore_completion.rs#L641-L718)).
  Its staging is **path-based**, with create/truncate; it is not the
  candidate's exclusive directory-relative backend. RTR COMPLETE and its
  checksum are not catch-up or signing-history evidence.
* The loop can mutate locally and spawn periodic snapshot work before any
  proposed stay-closed owner exists
  ([`binary_consensus_loop.rs:3224-3309`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L3224-L3309),
  [`:9239-9254`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/binary_consensus_loop.rs#L9239-L9254)).
  Transport queues and sends separately
  ([`p2p_tcp.rs:3000-3017`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/p2p_tcp.rs#L3000-L3017),
  [`:2324-2399`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/p2p_tcp.rs#L2324-L2399)).
  Production has no active Proposal/Vote authority or journal wired
  ([`main.rs:8680-8707`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/main.rs#L8680-L8707)).
  The journal's shared ownership is per backend instance, not cross-copy or
  cross-host ([`signing_reservation_journal.rs:1329-1345`](https://github.com/olivexo28/QBIND/blob/0d1b56515c52abe2862064027d1a9f103fef5a0c/crates/qbind-node/src/signing_reservation_journal.rs#L1329-L1345)).
* The prior record's **4222-byte maximum valid encoding**, **4223-byte
  probe**, and **256-slot volatile ledger** are proposed, unapproved design
  values. The ledger is not crash-recoverable detailed evidence. The
  separately cited P1 models exercise synthetic provider/lease and
  single-threaded ordering; their scoped acceptances are not production
  enforcement, a restart certificate, durable history or signer fencing.
  Successful decoding is never startup authorization.

## Two policy candidates

### A — one-shot sticky refusal

After independently provisioned `PROVISIONED_CLEAN`, and only under held
destination ownership, acknowledge durable `ACTIVE_UNRESOLVED` **before**
any covered protected run. A local attempt can publish
`ATTEMPT_UNRESOLVED` after admission closure; no importer is enabled. Both
states are sticky, including after clean shutdown or a provably no-effect
attempt. A later startup, including reset, refuses. An ordinary rejected
peer response does not write a marker.

Before active publication, provisioned clean may be eligible to try the
transition; absence, legacy, invalid, foreign, unreadable or staging
ambiguity refuses. During publication, before acknowledgement no covered
work may start. A pre-replacement failure can leave old clean plus staging;
an uncertain rename or sync can leave either final and must not be reported
as rollback. A staged artifact refuses. If a later startup observes clean
with no staging, retry is only justified under the proposed filesystem
durability/non-rollback assumptions and independent provisioning history,
and only because no work could precede acknowledged active. After
acknowledged active, crash or clean exit must leave startup closed under
those assumptions; if a copied or rolled-back clean record is accepted, the
assumption has been violated and the local marker cannot detect it.

Previously admitted work remains owned after A closes admission, and may
finish before C. Unknown effects remain unknown; local quiescence does not
prove that an external signer stopped or produced no signature. The sticky
marker refuses after restart even if local work completed. Local lock,
canonical path, checksum and the proposed volatile ledger do not prove
global exclusivity, authenticity, freshness, anti-rollback or a complete
signing history. Copied, foreign, legacy and unclassifiable destinations
refuse unless independently established prerequisites exist; a copy or
rollback at the same path may be indistinguishable and is outside the local
guarantee. This is safe only within explicitly reviewed assumptions, and can
make routine restarts impossible, reducing available voting power and possibly
halting quorum.

### B — restart after a sealed, fully accounted ordinary run

This is a **conditional design**, not a selected journal, service, authority,
backend or clear policy. It applies only to a run in which **no catch-up
attempt was admitted and no unresolved or ambiguous partial work occurred**.
It does not clear an `ATTEMPT_UNRESOLVED`, an unknown outcome or an
interrupted run. A merely error-free exit or `CLEAN` byte string is not a
certificate. B requires its own independently reviewed active-run and closure
state machine; it does not reinterpret or automatically clear A's sticky
`ACTIVE_UNRESOLVED` record. Neither A's proposed format nor any upgrade or
migration from A to B is selected here.

One concrete candidate lifecycle:

1. A separately authorized, non-rollbackable owner/fencing service grants
   one run generation bound to chain/genesis, exact destination/provision
   identity, validator/signer identity and a current fence. It must prevent a
   second owner or stale signer capability from causing covered effects.
   The exact authority, service, proof and trust roots are **unselected**.
2. Before each protected effect, an independently durable journal records
   the operation, generation, signer position and intended effect; after
   completion it records the actual result and all required state/lock/
   signing-history updates and barriers. Coverage includes descendants,
   snapshot/epoch publication, transport and every signer call; a signed
   outcome is recorded even if it is never broadcast. Missing, incomplete,
   reserved, cancelled, late or uncertain outcomes remain unresolved. The
   256-slot volatile model cannot supply this history after a crash.
3. For an orderly no-catch-up completion, close admission A, retain all
   permits and children until C is positively proven, and reconcile every
   journal position and protected store. Do not equate C with an external
   signer's outcome: obtain authoritative completion or proof of non-invocation
   and retire/fence the signer capability so no late external effect remains
   possible. Any Unknown, partial operation, untracked work, failed barrier,
   loss of owner or stale fence prevents completion.
4. Only then may the **separate authority** conditionally issue a durable,
   monotonic `RUN_CLOSED` seal for that exact run, journal frontier, state
   identity, signer/fence and no-catch-up-attempt assertion. It must
   atomically prevent old-generation reuse and remain current across copies
   and rollback. Publish a local reference using a reviewed durable
   mechanism. A restart may proceed to *independent admission checks* only
   if it can verify the exact seal, complete journal/state correspondence,
   current ownership/fence and no later generation, and atomically acquire
   a new generation. This does not itself authorize recovery or voting.

Before durable run-start publication, only the previous verified closure may
remain; no work under a new generation can have started. An issued but
unacknowledged start/lease is ambiguous unless the external authority can
classify and fence it; otherwise refuse. During an active run or after crash
before a valid closure, refuse even if no visible effect occurred. While
closing, a crash before journal durability, C, signer retirement or the
conditional seal refuses; no partial closure may be promoted. A crash after
authority seal but before local publication, or after a local rename but
before sync acknowledgement, requires fresh independent authority/journal
classification; missing, stale, mismatched or ambiguous data refuses.
An observed seal must be verified as durably committed/current by that
authority, not inferred from a local rename or process exit. If its
independently verified committed closure exists but the local reference is
missing, this candidate **refuses**, rather than inventing a repair path.
Only a fully matching, current closed run can qualify for ordinary restart.

This could preserve availability across an orderly, fully accounted run;
crashes, uncertainty, unavailable authority and all catch-up attempts
remain closed. A checksum, height, empty directory, operator assertion,
local journal revision or copied seal does not establish currentness. The
service must detect stale/copy/rollback or refuse, and protect the actual
signer, not merely the node process. The journal's data and finality,
external fencing semantics, secure provisioning, identity binding,
durability and cross-store atomic correspondence need independent design and
evidence. None is established by main or the test models. Loss of that
service or inability to reconcile can block restarts and quorum indefinitely.

## Owner decision and recommended boundary

| Choice | Consequence for initial public DevNet | Evidence or decision needed |
|---|---|---|
| A: one-shot | Simpler refusal-oriented local boundary, but a normal restart is unavailable after the first covered run; loss of enough nodes can halt quorum. It is not protection against copied or rolled-back state. | Approve the availability cost, provisioning, stable local ownership and filesystem assumptions; verify actual startup/worker coverage and crash behavior. No public DevNet approval follows from selecting it. |
| B: sealed ordinary-run restart | Potentially allows restart after a fully accounted non-catch-up run, at the cost of a new durable journal, external current/fenced signer authority and cross-store correspondence. Crashes, Unknown and catch-up attempts stay closed. | Select and independently review those mechanisms, their trust roots, no-late-effect semantics and failure modes; obtain production and multi-owner evidence. They are not currently available by implication. |
| Keep activation disabled while deciding | No unsupported authority is assumed; public DevNet remains NO-GO and unavailable. | Owner must decide whether A's liveness cost is acceptable or commission B's prerequisites; neither choice is approved here. |

**Recommendation:** for initial public DevNet, retain disabled/no-go rather
than assume B. If an owner later chooses an initial implementation, A is the
more conservative refusal-only direction under its explicitly limited local
assumptions, with the stated severe availability cost; it is not approved
by this recommendation and does not resolve global fencing. Do not activate
either option until the relevant authority and release prerequisites are
independently established.

### Smallest policy-neutral implementation slice to review next

Implement a **standalone refusal-only classification boundary** in the node
library, without startup wiring, file access or production participation
changes. Its input is a typed caller-supplied observation (`Absent`,
`Unavailable`, `Invalid`, `Foreign`, `Ambiguous`, `ProvisionedClean`,
`ActiveUnresolved`, `AttemptUnresolved`); it returns a typed refusal for
**every** variant, including `ProvisionedClean` as
`NoStartupAuthority`. No branch returns a capability, performs I/O,
creates a marker, clears state or interprets a checksum as authority. The
API explicitly distinguishes observed data from verified evidence and
cannot be used as a positive admission gate. Naming and exact placement in
`qbind-node` are implementation choices; no format/backend or B authority is
selected.

Future focused unit controls should exhaustively cover each variant, assert
the exact refusal and no success-shaped value, and use a fake caller to
show that no downstream effect is invoked on any result. This narrowly
implementable, independently reviewable primitive advances a common
fail-closed vocabulary for both policy directions; it is **not** an actual
startup guard, durable latch, worker fence, recovery or a fix of A33-F1.
Before any real caller is wired, separately review the actual input
provenance, record bounds, ownership, startup placement, effect and worker
coverage, provisioning, and the owner-selected policy. The existing dispatch
stays unchanged. If a meaningful production guard rather than an isolated
primitive is required next, it cannot honestly be specified without choosing
those unresolved dependencies.

## Future acceptance controls

All rows are **FUTURE / NOT EXECUTED**. Assert persistent state, actual
effect/worker/signer observations and refusal separately from counters or
logs.

| Scenario | Candidate A | Candidate B |
|---|---|---|
| Clean shutdown after covered work | Next fresh process refuses on active marker. | Restart qualifies only after journal barriers, C, signer retirement, authoritative current seal and all independent admission checks; exit alone proves none. |
| No-effect completion | Active/attempt marker remains sticky; no automatic clear. | A fully accounted ordinary run with no admitted catch-up attempt may seal; an admitted attempt or uncertain no-effect claim refuses. |
| Interrupted write / acknowledgement | Inject staging, file sync, rename and directory-sync failures; preserve actual observed bytes and ambiguity, never assume rollback. | Inject each start, journal, signer fence, seal and local-reference boundary; missing or uncertain evidence refuses. |
| Crash and restart | Kill before and after active acknowledgement and work admission; prove no pre-ack effect and post-ack restart refusal under tested assumptions. | Crash at each run/close stage; active or unsealed run refuses; verify that a committed seal is independently current and matches exact journal/state. |
| Late signer / worker | A remains closed; C only after proven local termination, with external outcome independently Unknown if necessary. | Unknown or a capability capable of a late effect blocks seal; exercise stale owner and delayed signer after purported close. |
| Missing, legacy, copied or rollback | Absent/unclassified refuses; copy/rollback at identical local identity may be undetectable and requires separate controls/assumptions, not a local success claim. | Legacy/missing refuses; demonstrate external authority rejects copied/stale/rolled-back generation and fails closed on authority loss. |
| Ledger capacity / untracked child | Exhaust the proposed bound before new effects, retain previously admitted work and keep refusal; sensitivity mutant must detect premature C. | Durable accounting capacity must be reserved before effects; exhaustion, missing descendant or incomplete journal blocks seal and restart. |
| Process-kill vs power loss | Process-kill checks ordering only; filesystem/power-loss guarantees require separate platform-specific evidence. | Same, plus independent durability and consistency of journal and external authority; no process-kill test proves those guarantees. |

New execution here consists only of source/ref inspection, documentation
checks and branch publication. No Rust tests, node, deployment or
operational signing are run; source, tests, audit register and historical
evidence remain unchanged. No PR or merge is created. Transport, A17-F1 /
RS1-F7, RS1 and A33-F1 / E27 remain **OPEN**; activation **DISABLED**;
public DevNet **NO-GO**.
