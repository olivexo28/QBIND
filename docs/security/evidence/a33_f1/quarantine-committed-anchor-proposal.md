# A33-F1 / E27 committed-anchor decision proposal

**COMMITTED-ANCHOR PROPOSAL — INDEPENDENT REVIEW PENDING.**

This append-only source investigation proposes an anchor representation for
the stay-closed catch-up quarantine. It does not implement a backend, codec,
gate, test, or recovery path. It supplements the prior
[backend contract](quarantine-backend-contract-proposal.md) and its
[user-supplied review correction](quarantine-backend-contract-review-correction.md);
neither historical document is rewritten. The prior **PASS WITH LIMITATIONS**
filesystem-prototype review remains only as the user-supplied report recorded
in [the capacity inventory](capacity-inventory.md): reviewer identity and raw
artifact were not supplied, and it was not independently rerun here.

## Pinned source facts

The inspection is at branch tip
`3a56674277fc7be992c81a235652dcd27a72fc15`; protected main remains
`c9aaef40b045e896ddfa8b01bad230f6b680715e`.

* `crates/qbind-consensus/src/hotstuff_state_engine.rs:291-299,425-440`
  stores `committed_block: Option<BlockIdT>` and
  `committed_height: Option<u64>` separately. Both start as `None`.
  `BasicHotStuffEngine`'s binary specialization uses `[u8; 32]` block IDs.
* `hotstuff_state_engine.rs:79-85` defines `CommittedEntry` with three
  independent fields: `block_id: BlockIdT`, `view: u64`, and `height: u64`.
  The state engine's commit path at `1830-1925` finds grandparent `g_id`,
  `g_view`, and `g_height`, applies monotonicity checks, then updates the
  committed block and height and appends all three values to the commit log.
  It does not maintain a separate `committed_view` field.
* Commit-log view is not a reliable always-available committed-view source.
  The log is explicitly a bounded observability/debugging history; old
  entries are drained above `ConsensusLimitsConfig::max_commit_log_entries`
  (`hotstuff_state_engine.rs:1213-1223`, default 8192 in
  `vote_accumulator.rs:55-68,108-126`). Initialization from restart sets
  committed block/height and optional lock, but does not populate the commit
  log (`hotstuff_state_engine.rs:1958-2005`). The generic snapshot baseline
  accepts committed view and height separately and stores them on a
  synthetic `BlockNode` (`hotstuff_state_engine.rs:2021-2088`); the binary
  wrapper accepts only snapshot height and deliberately passes that as both
  view and height (`basic_hotstuff_engine.rs:2630-2688`). The snapshot
  block hash is documented as an opaque parent identifier, not necessarily
  the pre-snapshot consensus block ID.
* `BlockNode` has separate `view` and `height` fields
  (`crates/qbind-consensus/src/block_state.rs:21-45`). `BasicHotStuffEngine`
  exposes `current_view() -> u64`, while `committed_height() -> Option<u64>`,
  `committed_block() -> Option<&BlockIdT>`, and `locked_qc() -> Option<&QC>`
  are separate accessors (`basic_hotstuff_engine.rs:2223-2225,2421-2427,
  2548-2550`). A lock QC separately carries its block ID and QC view.
  The engine's *current view* is not the committed block's view and is not
  interchangeable with committed height or lock view.
* The binary catch-up handler checks the response's `request_from_height`
  and `request_from_block_id` against current committed height and ID before
  applying (`crates/qbind-node/src/binary_consensus_loop.rs:8437-8478`).
  Response blocks separately carry `height` and `view`
  (`crates/qbind-node/src/p2p.rs:185-218`); the engine requires contiguous
  height, parent equality, and for this path `height == view`, then checks
  proposer, derived block ID and QC before registering and replaying votes
  (`basic_hotstuff_engine.rs:3948-4025`). This is a catch-up input invariant,
  not a general equality invariant for every engine state or persisted
  committed block.
* Each accepted catch-up item is registered before its signers are replayed.
  `on_vote` may form a QC; `on_qc` updates the lock, and the 3-chain path may
  update committed block/height (`hotstuff_state_engine.rs:1694-1805,
  1830-1925`). Earlier items and partial current-item vote effects can
  remain if a later error occurs. The function can also advance engine
  `current_view` after a valid suffix (`basic_hotstuff_engine.rs:4023-4049`).
  There is no response-wide rollback.
* `ConsensusStorage` persists `meta:last_committed` as only a block ID
  (`crates/qbind-node/src/storage.rs:168-173,358,929-970`). It does not
  persist a committed height or committed view in that key. The simulation
  restart loader obtains height from the stored block header and reconstructs
  a lock from a stored or embedded QC, using QC height as view
  (`crates/qbind-node/src/hotstuff_node_sim.rs:2049-2148`). This is a
  separate reconstruction path, not an atomic persisted anchor triple or a
  general proof of committed-block view.

### Availability at an intent boundary

On the current binary-loop catch-up route, the mutable engine exposes the
committed ID and height as optional values, the current view as a `u64`, and
the lock QC as optional. A nonempty catch-up suffix cannot proceed without
both committed ID and height: the engine returns `MissingLocalAnchor` if
either is absent (`basic_hotstuff_engine.rs:3954-3969`). Empty responses
return before that engine precondition. A well-formed intent for a mutating
suffix must therefore refuse if either committed-anchor component is absent.
The current view is representable at the boundary, but its value alone does
not prove that startup established a valid committed anchor.

The in-memory commit routine updates committed ID and height together within
one mutable call, but the public API exposes separate option getters and
there is no typed atomic `CommittedAnchor` snapshot. An implementation must
read/validate the tuple under the exclusive engine owner before the first
catch-up effect; independent asynchronous producers, database state, or
callbacks are not fenced merely by these getters. During catch-up the tuple,
lock, commit log and current view may advance. They are *starting* values,
not the eventual outcome. A storage error, restart reconstruction, absent
block, bounded-log eviction or mismatch with request/persisted identity can
make a later observation stale, incomplete or inconsistent.

## Stay-closed requirement versus diagnosis and recovery

The accepted stay-closed contract requires a durable `Applying` intent before
the first possible catch-up mutation, bound to the exact store/chain and
transaction, and requires unresolved/uncertain state to keep participation
refused. The prior storage candidate calls for the exact starting committed
anchor, view, lock identity and response identity. This is an intent-time
observation requirement; it does not authorize recovery or clear.

For that narrow invariant, the candidate latch must retain, or bind to
revision-matched durable evidence containing:

1. the starting committed block ID **and** committed height (or an explicit
   absent/invalid indication that refuses the operation);
2. the starting engine `current_view`, explicitly distinguished from
   committed block view and lock QC view; and
3. the starting lock's full block ID and QC view when a lock exists, with an
   explicit absence flag otherwise.

These values let a future owner bind the intent to its immediate consensus
starting state and refuse on absence/mismatch. They do not prove persistent
database equality, freshness, currentness, ancestry, or signer exclusivity.
The stay-closed decision does not require the historical view of the
committed block if its only action is to remain closed. That committed-block
view, complete QC/certificate material, intermediate commit sequence, full
response/effect history, and persisted-vs-memory reconciliation are
diagnostic or possible future recovery inputs. No future recovery is approved.
If any such required recovery fact exists only in unavailable evidence, it
is **Unknown** and recovery remains refused; it must not be inferred from
height, current view, lock view, block ID, or a peer's reported height.

The prior source has no always-present committed-block view in the engine's
restart state. If independent review decides the latch itself must retain
that distinct value, source work must first define how it is authoritatively
obtained for restart, snapshot baseline, ordinary commits, and bounded-log
eviction; missing or inconsistent results must refuse. Do not silently use
`view = height` outside the specific binary baseline/catch-up paths that
document that convention.

## Candidate comparison and recommendation

| Candidate | What remains observable if evidence is lost | Disposition |
|---|---|---|
| Block ID + one scalar | If scalar is committed height, start height and ID can be compared but starting engine current view is lost. If scalar is current view or committed-block view, the committed height needed by the catch-up request/engine anchor is lost. A single scalar cannot serve these distinct source values without an approved invariant that current source does not establish. | Insufficient for the reviewed starting anchor/view/lock boundary. Refuse rather than infer the missing value. |
| Block ID + committed height + committed-block view | Captures the triple only if committed-block view was authoritatively available at intent. Current engine has no dedicated committed-view field; the bounded commit log can be empty, absent after restart, or evicted. If view is missing, the latch cannot claim the full triple. This still does not capture the engine's distinct current view unless that is explicitly substituted and named. | Not supportable as a universally available committed triple from current source. Requires a reviewed accessor/reconstruction rule and may require another scalar for current view. |
| Smaller latch anchor plus separately bound evidence | Latch can retain block ID+height and evidence revision/digest; engine current view and any committed-block view live in evidence. If that evidence is unavailable, stale or mismatched after restart, the extra facts are Unknown and no reconciliation/recovery is allowed. The stay-closed latch still refuses; it cannot safely resume. | Viable only if independent review accepts evidence as mandatory for the full intent tuple and accepts permanent refusal on evidence loss. Evidence availability/capacity is unresolved. |
| Block ID + committed height + engine current view in latch | The intent retains both catch-up anchor values and the actual engine view at the boundary. If the optional block/height pair is incomplete or invalid, intent refuses. The committed-block view remains diagnostic/recovery-only evidence; losing it does not permit recovery or opening the gate. | **Preferred source-backed candidate for review**, conditional on a future typed, coherent anchor snapshot under exclusive engine ownership. It does not claim that current source already supplies that atomic API or any persistence/currentness guarantee. |

Recommendation: review the fourth representation. It gives distinct names
to the source's committed block ID, committed height, and current engine
view rather than asserting that committed view equals height. Preserve
locked QC block ID/view separately as the existing candidate intends. Before
an implementation can use it, the consensus owner must approve a single
snapshot contract that verifies `committed_block` and `committed_height`
are both present for a mutating catch-up, captures `current_view` and lock
under the same mutable owner, and refuses inconsistencies. Source currently
updates the committed ID/height pair together but lacks such a named
snapshot method and does not provide an always-available committed-block
view. If review requires that latter view for stay-closed safety rather than
only later diagnosis/recovery, this recommendation is blocked pending a
source-backed retrieval contract.

### Conditional candidate layout

Starting from the prior 416-byte candidate, define `224..232` as
`starting_committed_height: u64`, insert
`232..240` as `starting_engine_current_view: u64`, then shift all original
fields after offset 232 by 8 bytes. The earlier conditional 424-byte
arithmetic is now attached to this explicit choice; it is **not** a
production format or limit.

| Offset | Width | Candidate field |
|---|---:|---|
| 0..224 | 224 | Prior fixed envelope, flags/revisions, identity fields and committed block ID |
| 224..232 | 8 | Starting committed height |
| 232..240 | 8 | Starting engine `current_view` |
| 240..272 | 32 | Starting locked-QC block ID |
| 272..280 | 8 | Starting locked-QC view |
| 280..312 | 32 | Bound response identity digest |
| 312..320 | 8 | Sticky known-effect bitmap |
| 320..328 | 8 | Sticky unresolved-domain bitmap |
| 328..336 | 8 | Sticky conflict-domain bitmap |
| 336..344 | 8 | Completed-prefix count |
| 344..352 | 8 | Current-item index/sentinel |
| 352..384 | 32 | Evidence-object identity digest |
| 384..392 | 8 | Referenced evidence revision |
| 392..424 | 32 | Integrity digest over candidate bytes 0..392 |

Checked total: `224 + 8 + 8 + 32 + 8 + 32 + 3*8 + 8 + 8 + 32 + 8 + 32 = 424` bytes. The earlier v1 candidate requires all state-flag bits after bit 6 to be zero, so these assignments require a revised candidate version: assign bit 7 to `committed_anchor_present` (block ID and height are present together) and bit 8 to `lock_present`; keep bit 0 `closed` required. The versioned integrity domain must also be reviewed for the revised format. A missing anchor is not admitted for mutating catch-up. A missing lock is permitted only when the owner observed `locked_qc == None` in the same snapshot. A production encoding must define and validate these combinations and recalculate envelope/checksum coverage if additional flags do not fit. The `u64` values remain full-width and all arithmetic/conversions must be checked. `416` and `424` bytes are both unapproved candidates.

## Proposed acceptance matrix — not executed

| Case | Expected future result |
|---|---|
| Missing committed block or height on nonempty catch-up intent | Refuse before effects; encode absence only as diagnostic closed state if separately permitted |
| Current view exists but committed pair absent | Do not treat current view as an anchor; refuse |
| ID/height mismatch against request anchor, held store, or independently validated block | Refuse/uncertain; never infer height or view from ID |
| Committed-block view unavailable because restart omitted the block tree or commit log is empty/evicted | For the recommended intent tuple, use separately captured current view; mark committed-block view unknown. If later recovery requires it, remain refused |
| Partial catch-up commits or advances lock/current view before a later error | Keep original intent tuple immutable; record each known effect/current tuple or Unknown in bound evidence; no rollback assertion and remain closed |
| Evidence absent, stale, corrupt, inaccessible or revision-mismatched | `Absent`, malformed/read failure, or `Uncertain`; no recovery or reopening |
| Restart from ID-only metadata plus reconstructed height/QC | Verify the selected tuple only under a reviewed binding rule; missing/mismatched components remain Unknown and closed |
| Mismatched chain/store identity or copied matching store | Current interface refuses differing store/chain strings; copied/matching IDs do not prove currentness; future typed identity checks remain unimplemented |
| Empty catch-up response | No engine application occurs in the handler; any decision to persist an operation intent for an empty response is unresolved and must not imply clean state |

All rows are proposed and **unexecuted**. No Rust, backend, filesystem,
restart, CLI, node, signer or network tests were run for this investigation.

## Remaining decisions

Independent review must decide whether the latch needs committed-block view
for the stay-closed decision or only for a separately authorized recovery
procedure; approve or reject the `block ID + committed height + engine
current_view` tuple; specify a coherent owner-held snapshot API and validity
rules; define optional-anchor flag semantics; and decide whether missing
committed-block view may remain Unknown indefinitely. Evidence bounds,
identity authority, initialization/migration, RocksDB object continuity,
durability profile, currentness, anti-rollback, signer exclusivity, and
clear/resume authority remain unresolved. The 416- and 424-byte candidates
remain unapproved. A33-F1 / E27 and all other unresolved obligations remain
**OPEN**; activation **DISABLED**; public DevNet **NO-GO**.
