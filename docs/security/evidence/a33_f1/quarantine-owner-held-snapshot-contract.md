# A33-F1 / E27 owner-held starting-anchor snapshot contract

**SNAPSHOT CONTRACT PROPOSED — INDEPENDENT REVIEW PENDING.**

This documentation-only proposal supplements the
[committed-anchor proposal](quarantine-committed-anchor-proposal.md), the
[stay-closed contract](stay-closed-contract.md), and the capacity inventory.
It does not implement a snapshot API, intent publisher, quarantine backend,
gate, or recovery mechanism. The earlier **PASS WITH LIMITATIONS** filesystem
prototype review is the user-supplied review recorded in the capacity
inventory; the reviewer identity and raw review artifact were not supplied,
and those prototype tests were not independently rerun here. The user also
reported that the independent reviewer could not retrieve the node-handler
source range. The handler range was inspected directly for this proposal
(details below); no reviewer identity or artifact is inferred.

## Entry and pinned source

Repository `olivexo28/QBIND`; branch
`copilot/a33-f1-bounded-eviction`; starting task tip
`35b10e210ba9c8db8ef61546aab9eb96f4438e08`; protected local and remote main
`c9aaef40b045e896ddfa8b01bad230f6b680715e`. Worktree and index were clean
at entry. Source references below are at the starting task tip.

### Actual owner, call path, and handler behavior

`crates/qbind-node/src/binary_consensus_loop.rs:2806-2817` constructs the
`BasicHotStuffEngine<[u8; 32]>` as a local mutable value inside
`run_binary_consensus_loop_with_io`. Its inbound select arm at
`:3112-3155` synchronously calls
`handle_inbound_consensus_msg(&mut engine, ...)`; the inbound response arm
at `:7393-7411` first binds the declared responder to the authenticated
transport origin, increments the received counter, and calls the response
handler. The handler at `:8437-8538` is verified source, not a reconstruction:

* The self-responder guard returns first (`:8444-8446`). For a non-self,
  empty response, it captures the peer's reported committed height and
  calls `evaluate_restore_mode_transition` before any local committed-anchor
  comparison (`:8448-8461`). That updates restore-mode peer-progress state
  and metrics; it does not call the engine catch-up method. Thus an empty
  response is not a no-op on all loop state, and it currently can advance
  restore-mode exit tracking.
* Only a nonempty response reaches the exact local
  `request_from_height`/`request_from_block_id` comparison (`:8462-8483`).
  A mismatch increments rejection stats and still evaluates peer progress
  (`:8470-8482`) without applying engine blocks.
* For a matching nonempty response, the handler converts the supplied
  vectors and synchronously calls `engine.apply_restore_catchup_blocks`
  (`:8485-8506`). Success updates counters/logging and evaluates the mode
  transition (`:8507-8524`). The error arm (`:8525-8535`) claims rejected
  input did not mutate the engine, but that is not a response-wide guarantee:
  the engine registers each item before replaying its signers and can retain
  prior-item effects or partial current-item vote effects before a later
  error (`crates/qbind-consensus/src/basic_hotstuff_engine.rs:3948-4050`).
  There is no response rollback.
* After the inbound handler returns, the loop updates metrics, may schedule
  a periodic snapshot, runs reconfiguration handling, and persists an epoch
  transition (`binary_consensus_loop.rs:3156-3210`). These are additional
  effects, not automatically fenced by an engine-only snapshot.

The direct response-handler source range that the supplied reviewer could
not retrieve was therefore inspected and is cited above. This verifies the
current code path only; it does not verify a built binary, configured
deployment, all startup paths, or any production quarantine.

### Anchor values and limits of current state

`HotStuffStateEngine` stores `committed_block: Option<BlockIdT>` and
`committed_height: Option<u64>` separately (`crates/qbind-consensus/src/
hotstuff_state_engine.rs:291-299`); the binary block ID is `[u8; 32]`.
`BasicHotStuffEngine` separately exposes `current_view() -> u64`,
`committed_block()`, `committed_height()`, and `locked_qc()` as distinct
accessors (`basic_hotstuff_engine.rs:2223-2225,2421-2427,2548-2550`).
There is no typed atomic snapshot accessor or engine generation number.

* Fresh engine construction can have no committed block or height.
  `apply_restore_catchup_blocks` returns immediately for an empty slice, but
  requires both anchor parts for a nonempty slice
  (`basic_hotstuff_engine.rs:3948-3969`). For a mutating intent, the pair
  must be either both present or the operation refuses; a one-sided pair is
  inconsistent. Both absent does not establish a fresh store or permit
  catch-up.
* Restart initialization records the supplied block ID and height and an
  optional lock but does not restore the block tree or committed-block view
  (`hotstuff_state_engine.rs:1958-2005`). The binary wrapper sets current
  view to `committed_height.saturating_add(1)`
  (`basic_hotstuff_engine.rs:2598-2612`). This is the current restart
  convention, not a general equality between height and view.
* Snapshot-baseline initialization receives an opaque snapshot block
  identifier and height; the binary wrapper supplies height as the synthetic
  block's view and sets current view to height plus one, saturating
  (`hotstuff_state_engine.rs:2021-2088`,
  `basic_hotstuff_engine.rs:2630-2688`). The source explicitly does not
  claim that the snapshot identifier is the pre-snapshot consensus block ID.
  A matching ID/height tuple from this path is therefore not, by itself,
  proof of an independently validated consensus block or database object.
* A normal committed entry contains independent block ID, view, and height,
  but the engine has no dedicated committed-view field; the commit log is
  bounded and is not restored on restart
  (`hotstuff_state_engine.rs:79-85,1213-1223,1958-2005`). The historical
  committed-block view remains a separate value. It must be `Unknown`
  unless obtained from a source with reviewed provenance; current view,
  committed height, and locked-QC view must never substitute for it.
* The lock is `None` or a QC with a block ID and view. Absence is a valid
  explicitly observed snapshot value; it is not an implicit zero QC.
  Presence does not establish correspondence to the committed anchor, chain,
  store, or a verified certificate without the separately selected checks.
  Do not invent an ordering/equality rule among lock view, current view,
  committed height, and committed-block view.

The engine catches up from its own committed ID/height. The response handler
compares those values exactly with the response request anchor
(`binary_consensus_loop.rs:8462-8483`); the engine then checks sequential
height, parent ID, its catch-up-specific `height == view`, expected proposer,
derived ID, and logical QC membership/quorum (`basic_hotstuff_engine.rs:
3960-4017`). These checks establish only the stated local/source conditions.
An independent store/chain binding and a validated block at the anchor
require separate authorities and evidence. If unavailable, those facts stay
`Unknown`, and the operation remains refused. Sender binding is not
authentication of every embedded logical signer claim; the separate A17-F1
boundary is not discharged here.

## Candidate contract

### Snapshot value and validation

For review, the immutable value is:

```rust
struct StartingAnchorSnapshot {
    committed: Option<CommittedAnchor>, // all-or-none pair
    current_view: u64,                   // engine current view, never an alias
    lock: Option<LockAnchor>,            // explicit observed absence is valid
    // Historical committed-block view is intentionally not inferred here.
}

struct CommittedAnchor {
    block_id: [u8; 32],
    height: u64,
}

struct LockAnchor {
    block_id: [u8; 32],
    view: u64,
}
```

This is a candidate Rust shape, not an existing source type. `Option` on the
pair encodes only both-present or both-absent; it cannot encode a half-pair.
A future snapshot implementation must refuse a mutating catch-up if the pair
is absent, if source access observes only one component, or if an independent
validation finds disagreement. `current_view` is captured in the same owner
critical section but is not a substitute anchor and no universal
`current_view == height`, `height + 1`, or lock-view relation is imposed.
Overflow/next-height viability must be checked by the operation contract,
not inferred from a saturating value.

When available under a separately reviewed provenance rule, an independent
block/store check must compare the exact ID and height to the intended
destination's validated anchor. Bind the response's request ID/height to
that same pair before publishing intent. A store identity must identify the
actual object used by the later protected operation; matching local metadata
alone does not prove pathname/object continuity or currentness. The current
snapshot-baseline opaque identifier is not upgraded into a consensus block
identity by this proposal. Missing validated block, chain/store binding,
response binding, or consistent restart provenance is `Unknown` and refuses.

The snapshot does not contain historical committed-block view. That value is
diagnostic or a possible future recovery input only, unless a separate
reviewed invariant requires it for safety. It must never be reconstructed
from current view, height, lock view, or peer data. If needed and unavailable
(including restart with no retained block tree/commit entry), it remains
`Unknown`; no recovery or reopening follows.

### Owner, linearization point, and publication interval

The current engine owner is the single `run_binary_consensus_loop_with_io`
task and its local mutable `engine`; the inbound arm dispatches one handler
synchronously before selecting another inbound message or leader tick. That
is a serialization point for this loop only. It is not a process-wide
admission barrier and does not fence storage handles, signer work, snapshots,
callbacks, outbound workers, or already queued messages.

Proposed order for a future response:

1. Authenticate/bind the transport sender. Acquire the engine-owner lease
   before reading any state used for a mutating decision; close admission for
   operations that can mutate this engine, including ticks, while this
   transaction owns it. Route empty and stale responses through their
   separately specified non-application path rather than treating them as a
   successful snapshot.
2. Under that exclusive owner, capture and validate the snapshot, require a
   nonempty response for a mutating intent, compare its request anchor to the
   snapshot, and bind it to an operation ID, full response identity, and
   chain/store identity. Resolve or conservatively classify previously
   admitted work in every separately protected domain; unresolved work is
   `Unknown` and blocks the operation.
3. Keep the same exclusive owner/admission lease through publication and
   acknowledgement of the `Applying` intent and bound evidence. No await,
   callback, re-entry, queue dispatch, or tick may mutate the engine in this
   interval. After the acknowledgement, re-read the snapshot under the same
   owner and require exact equality before the first catch-up mutation.
   The acknowledgement means only what a future separately approved backend
   guarantees; this document selects no format or durability profile.
4. On exact revalidation, apply synchronously while retaining the owner.
   Record each known effect and Unknown outcome; do not assume error means
   no mutation. Continue the stay-closed rule until a separate reviewed
   mechanism determines otherwise.

The exclusive lease across publication is the proposed coherence mechanism;
revalidation under that still-held lease is defense in depth, not a way to
accept a stale snapshot after releasing ownership. If implementation cannot
hold the owner lease over asynchronous publication, it needs a reviewed
generation/token mechanism that detects all intervening mutations, including
ABA-equivalent anchor values, before applying. Current engine APIs provide
neither an owner lease for storage publication nor a generation counter.
Comparing only the tuple after releasing ownership is insufficient.

This lease must not be represented as fencing non-engine producers.
Implementation must separately close/drain or fence each signer, storage,
snapshot, callback, and outbound domain, and record late/unknown results.
The inventory and lifetime bounds for those domains remain unresolved in
the capacity inventory. A result already admitted, reserved, invoked,
enqueued, or delivered cannot be presumed cancelled.

### Cancellation, failure, and stale state

Before any engine mutation, failure to snapshot, validate identity/anchor,
publish intent, acknowledge publication, or revalidate leaves the
transaction closed and refuses the response. Publication failure may mean
old bytes, new visible bytes, malformed/unreadable state, or uncertain
visibility; do not infer unchanged storage. No later effect may use a
failed/uncertain publication as permission.

Cancellation at any ownership handoff is not a successful no-effect proof.
The durable intent attempt may have become visible, and independently
admitted work may still complete. The owner must retain the barrier or
transfer it to a supervisor that cannot admit participation, classify the
intent/outcomes as `Unknown` when not proven, and remain refused on restart.
The current loop has no quarantine transaction object, cancellation-safe
owner lease, durable publisher, startup refusal gate, or handoff protocol.
If cancellation can drop the only barrier and leave a participating
continuation, this contract cannot be implemented safely until that missing
mechanism is designed and reviewed.

After the first engine mutation, any catch-up error, cancellation, process
restart, or evidence-write uncertainty preserves all known effects and marks
the rest `Unknown`; it does not roll back earlier items or votes. The
original starting snapshot is immutable evidence and must not be overwritten
by the later engine tuple. Any later observed tuple is a separate outcome
observation. A successful snapshot or matching local identity grants no
reset, participation, clear, resume, or currentness authority.

### Empty and stale responses

The verified empty-response path currently skips anchor comparison and engine
application, but updates peer-progress/restore-mode state from the responder's
reported height. Under this proposal, an empty response does not create an
`Applying` engine-mutation intent solely because the vector is empty.
However, it is not treated as a no-effect proof and cannot clear quarantine,
authorize participation, or advance a future quarantine state machine.
Quarantined operation must suppress its ability to exit restore mode until a
separately reviewed gate covers that state transition. The existing handler
has no such gate; its empty-response behavior is not a production quarantine
implementation.

Likewise, a nonempty stale-anchor response currently updates peer-progress
tracking even though it does not invoke engine catch-up. A future gate must
classify and separately authorize that mode-tracker mutation. This proposal
does not convert peer-reported height into a trusted local anchor.

## Candidate API sketch (not implemented)

The sketch shows ownership shape and result distinctions only. It is not a
selected async-trait signature, format, backend, or complete error enum:

```rust
async fn apply_response_under_owner(
    owner: &mut ConsensusOwner,
    response: RestoreCatchupResponse,
    bindings: OperationBindings,
    publisher: &dyn ApplyingIntentPublisher,
) -> Result<ApplyOutcome, Refusal> {
    let _lease = owner.close_engine_admission().await?;
    let start = owner.engine().starting_anchor_snapshot()?;
    let validated = validate_snapshot_response_and_store(&start, &response, &bindings)?;
    let intent = ApplyingIntent::bind(validated, &response, &bindings)?;
    publisher.publish_and_ack(&intent).await.map_err(Refusal::Uncertain)?;
    if owner.engine().starting_anchor_snapshot()? != start {
        return Err(Refusal::AnchorChanged);
    }
    owner.engine_mut_under_lease().apply_restore_catchup_blocks(/* validated */)
}
```

Required invariants for any eventual API:

* Snapshot fields are copied atomically from one engine owner; committed ID
  and height are both present or absent; no separately-read field can be
  mixed across owner generations.
* Mutating application requires both committed fields, a current-view
  observation, explicit lock present/absent, exact response-anchor match,
  and separately approved store/chain/block validation. Mismatch, absence,
  unsupported provenance, or ambiguity refuses.
* The intent binds operation, complete response identity, chain/store
  identity, starting snapshot, and evidence revision. `Applying` must be
  acknowledged before the first mutation. No local identity match is
  authorization.
* The engine lease remains exclusive across publication and revalidation.
  All other effect domains need separate admission/completion controls.
* Cancellation, publication uncertainty, stale/replaced ownership, effect
  error, or evidence loss cannot produce an allow-shaped success. Outcomes
  preserve known and Unknown effects; no automatic clear/resume exists.
* The historical committed-block view is absent from this snapshot type and
  stays `Unknown` unless separately and authoritatively supplied.

## Acceptance matrix — all cases proposed and unexecuted

| Proposed case | Observable result and responsible owner |
|---|---|
| Fresh engine: both committed fields absent, nonempty response | Snapshot may report absent pair for diagnosis; owner refuses before publishing an applicable intent or mutating. Absence is not a clean/fresh-store proof. |
| Exactly one committed field present or source getter disagreement | Typed inconsistent-snapshot refusal; no intent-dependent mutation. Snapshot owner must make this impossible or report it. |
| No lock in one coherent snapshot | Explicit `lock: None` is captured and bound; accepted only if all other anchor/identity checks pass. No zero/default QC is fabricated. |
| Lock present but validator/chain/committed relationship cannot be established | Keep exact observed block ID/view, classify validation `Unknown`, refuse; consensus owner cannot infer correspondence. |
| Restart initialization with block ID/height but no retained tree or committed view | Capture the pair and current view only with reviewed restart provenance; committed-block view remains `Unknown`. If validated anchor/store binding is absent, refuse. |
| Snapshot baseline using opaque hash and `height` as synthetic view | Preserve opaque identity provenance; do not claim consensus-ID equivalence or recover committed-block view. Refuse if required identity validation cannot establish the pair. |
| ID/height disagrees with store-validated block or response anchor | Typed mismatch refusal before publication/effects; store/response validator owns comparison. |
| State changes while intent publication is pending | Exclusive lease should make engine mutation impossible; adversarial test attempts re-entry/tick and expects blocked/rejected admission. If state changes despite lease, revalidation fails and remains closed. |
| Snapshot captured, lease released before publisher completes | Negative control: reject this API design, even if tuple later compares equal; an ABA change is not excluded by tuple equality. |
| Cancellation before lease acquisition, after lease, during publication, after acknowledgement, or at mutation handoff | No participation continuation; intent/effect state is absent only when proven, otherwise `Unknown`; owner/supervisor retains refusal. Test each handoff and require no lost barrier. |
| Publisher reports failure before/after visible replacement or uncertain acknowledgement | Remain refused; observed bytes may be old/new/malformed/unreadable. No “unchanged” assumption or engine mutation. |
| Nonempty response reaches engine; later item or signer replay errors after earlier effects | Original snapshot remains immutable; retain exact known prefix/current effects and `Unknown` remainder; remain closed. Engine owner plus evidence owner report outcome. |
| Empty non-self response with peer height at/below local height | No engine snapshot/apply intent; existing handler's restore-mode progress/exit state is observed. Quarantine gate must prevent that observation from clearing/refusing state or authorizing participation. |
| Empty response with peer height above local height; self response; sender-binding failure | Verify each distinct early return: no catch-up engine application; peer-progress update only for authenticated non-self empty case. Inbound owner records/gates mode state separately. |
| Stale nonempty response anchor | No engine catch-up application; peer-reported progress currently updates transition tracking. Future quarantine must gate that side effect and retain response as stale, not current anchor. |
| Late signer/storage/snapshot/callback/outbound work while engine lease is held | Engine serialization alone is insufficient. Domain owner must report completion or `Unknown`; test that no external result is discarded and no clear follows. |
| Restart with `Applying` evidence missing, stale, malformed, unavailable, or mismatched | Startup remains refused; evidence reader/owner classifies typed refusal. No reconstruction from current view, height, lock view, or peer report. |
| Matching chain/store local identity but copied/rolled-back store or uncertain object continuity | No authorization; currentness/anti-rollback/exclusive signer ownership remain unresolved. Store authority reports `Unknown`; node stays closed. |
| Historical committed-block view missing after restart or commit-log eviction | Remains `Unknown`; never substitutes another scalar. If a reviewed future recovery needs it, recovery remains unavailable. |

These are implementation-facing proposals only. No Rust tests, builds,
filesystem/crash tests, CLI checks, node execution, signing, or network
operations were run for this record.

## Unresolved implementation blockers

Before implementation, independently review: the API/owner object that
serializes all engine mutations; a cancellation-safe lease/handoff that
cannot be lost on task cancellation; the persistent intent publisher and
acknowledgement meaning; exact operation/response/chain/store identity
derivation and binding to the same actual data object; independent
committed-anchor validation for restart and snapshot-baseline cases; lock
validity/provenance; how queued/already-admitted work and non-engine
producers are fenced or reported; and the separate gate for empty/stale
response restore-mode transitions. Historical committed-block view is not
available uniformly and remains unresolved for any recovery needing it.

No persistent format, initialization/migration procedure, currentness or
anti-rollback authority, signer exclusivity, filesystem durability profile,
complete startup coverage, clear/resume authority, or production allow state
is selected. A33-F1 / E27 and all remaining obligations remain **OPEN**;
activation **DISABLED**; public DevNet **NO-GO**.

## User-supplied review correction — tuple and sender-binding limits

This append-only correction records the user-supplied review report; no
reviewer identity or raw artifact was provided. It supersedes any broader
interpretation of tuple revalidation or sender binding above.

**Tuple revalidation is not an event-history fence.** Equality between the
captured and re-read `(committed ID, committed height, current view, lock)`
detects a changed tuple at those two observations only. It cannot detect all
intervening mutations, including an ABA transition back to equal values or
changes outside those fields. Therefore the proposed continuous exclusive
engine lease is the invariant that excludes engine mutations during
publication; revalidation is only a defensive changed-tuple check. If the
lease is lost, dropped, cancelled, or uncertain, the owner state becomes
Lost/Unknown and mutation remains refused even when the tuple compares equal.
A separate monotonic generation/fencing mechanism could be reviewed as an
alternative, but is neither specified nor selected here and would require
atomic admission/revocation, coverage of every relevant mutation, and
overflow refusal. No production fence is claimed.

**Sender binding has three distinct source modes.** The handler calls
`bind_sender` for the self-declared response sender
(`crates/qbind-node/src/binary_consensus_loop.rs:7393-7410`). The closure
defined in `handle_inbound_consensus_msg` (`:6097-6160`) delegates to
`PeerConsensusBindingGate::authorize(origin, claimed)` when a gate is
installed. With `binding_gate == None`, the explicit fallback is
`Ok(claimed)`; the source comment identifies that path as test-only
(`:6061-6090`). Tests also directly call
`handle_restore_catchup_response` (`:10078-10091,10175-10188`), bypassing
the inbound binding closure entirely. This inspection distinguishes the
installed-gate route, the no-gate test-only route, and direct handler tests;
it does not establish an unauthenticated production route or prove which
configuration any built deployment uses. The supplied reviewer’s source
retrieval limitation is acknowledged; the citations here are from direct
inspection at the pinned task tip.

The test-only owner/lease lifecycle task adds controls for dropped-lease
reopening, pre-acceptance transfer, ABA tuple equality, and late/duplicate
completion clearing. All are model evidence only; they do not prove Rust
task cancellation semantics, production scheduling, durable publication,
filesystem behavior, or external-domain fencing.
