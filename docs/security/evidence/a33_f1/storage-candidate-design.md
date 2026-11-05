# A33-F1 / E27 storage candidate and implementation acceptance matrix

**STORAGE DESIGN PROPOSED — INDEPENDENT REVIEW PENDING.**
All format, backend, path, API and durability choices below are **PROPOSED**,
not approved or implemented. A33-F1 / E27 and all other unresolved obligations
remain **OPEN**; activation **DISABLED**; public DevNet **NO-GO**.

## 1. Inputs, attribution and evidence boundary

Inspected task commit `cbb66b1fe63d37909718e27a037b973dc6009508`, tree
`1d5922681ece5ff90d0ad9b858c2ced2d18bf33d`, on
`copilot/a33-f1-bounded-eviction`. Repository, branch, tip/tree, clean worktree
and staging, remote task and local/remote main were verified before editing.
Protected main was `c9aaef40b045e896ddfa8b01bad230f6b680715e`; no
fast-forward was needed. Source anchors below refer to the inspected task
commit, not an assertion that its earlier changes are on main.

The owner supplied an independent review accepting the Phase 1 interface
as a pre-implementation boundary. The owner also supplied a source/evidence
review of the 19-test correction; it did **not independently rerun Rust
tests**. These are **user-supplied review observations**, not reviews
performed here. No reviewer identity or raw review artifact was supplied;
neither is invented. No production backend approval is inferred. The earlier
33-test review's Cargo-unavailable limitation remains historical evidence;
it is not evidence that the present reviewer ran the 19 tests.

Controlling inputs, preserved unchanged:
[stay-closed contract](stay-closed-contract.md),
[interface evidence](store-interface-evidence.txt) and
[active-operation rejection correction](store-interface-rejection-evidence.txt).
The prior author-reported 19-pass result is not new validation of this design.

## 2. Source-supported facts (F), not candidate guarantees

| ID | Inspected source anchor | Observed fact |
|---|---|---|
| F1 | `crates/qbind-node/src/storage.rs:719-766` | Backend owns a RocksDB handle; ordinary `open` sets `create_if_missing(true)` and uses one default column family. It is not read-existing inspection. |
| F2 | `crates/qbind-node/src/storage.rs:1042-1080,1332-1342` | Epoch uses `put_opt` with `set_sync(true)` and `flush_wal(true)`; signing namespace documents mechanism versus unproved power-loss behavior. These are precedents, not a quarantine namespace or acknowledgement. |
| F3 | `crates/qbind-node/src/production_consensus_storage.rs:302-318,391-444` | Lifecycle carries an `Arc<RocksDbConsensusStorage>`; opening creates the parent, opens the database and performs schema/epoch checks. It is not a no-create inspection API. |
| F4 | `crates/qbind-node/src/main.rs:2492-2527,2603-2630,5150-5178` | Startup creates the data directory and acquires destination ownership; requested restore pre-opens consensus storage and later reuses the same handle. Ordinary startup opens it later. |
| F5 | `crates/qbind-node/src/main.rs:4991-5008,5039-5043,5420-5446,5491-5522,8101-8110` | Optional metrics spawn precedes ordinary restore guard and storage open. Storage handles reach runtime paths. P2P security preflight precedes builder construction. This is not exhaustive CLI/startup coverage. |
| F6 | `crates/qbind-node/src/restore_completion.rs:480-577` | Existing restore reader checks the opened object, refuses special files, uses Unix no-follow/nonblocking flags and bounded reads. It distinguishes absence from read/decode errors. |
| F7 | `crates/qbind-node/src/restore_completion.rs:583-735,800-900` | Restore publication distinguishes before/after rename errors, syncs file then parent directory; a held local advisory lock has limited scope. Not a quarantine marker or cross-copy signer fence. |
| F8 | `crates/qbind-node/src/binary_consensus_loop.rs:8437-8538` | Catch-up handler directly calls engine, logs/counts results and evaluates restore-mode transitions on success/empty/stale responses. Its error no-mutation comment is not response-level evidence. |
| F9 | `crates/qbind-consensus/src/basic_hotstuff_engine.rs:3954-4050` | Catch-up registers then replays votes per item, with fallible vote processing after insertion; earlier prefix can remain. Final view advancement occurs after the loop. No response rollback or marker parameter exists. |
| F10 | `crates/qbind-consensus/tests/a33_f1_quarantine_store_interface_tests.rs:202-222,367-422` | Corrected fake interface separates unrecorded rejection from unresolved publication, recognizes active ownership and latches before fallible checks. This is model behavior, not storage/node implementation. |

No identified target file was unavailable. The reads were bounded to relevant
surfaces; all CLI exits, OS/RocksDB internals, device behavior, snapshot export
coverage and alternate service entrypoints were **not exhaustively inspected**.
No binary, process, restart, storage crash, live network or signing ran here.

## 3. Candidate comparison and recommendation

| Property | Dedicated RocksDB namespace | Dedicated external marker |
|---|---|---|
| Proposed location | Dedicated `quarantine:catchup:*` keys in `<data_dir>/consensus`, never epoch/signing keys | `<data_dir>/catchup-quarantine/marker`, separate from `restore-transaction` and database |
| Binding/serialization | Can share exact DB `Arc` and a dedicated ownership domain; sync write batch could combine record/revision. Plain `get`/`put` is not compare-and-swap. | Must bind external record to the exact DB identity and pinned handle; local owner serializes read/check/replace. Two-store consistency requires explicit ordering, not assumed atomicity. |
| Inspection | Existing opener creates and lifecycle may write schema; needs new read-existing path. RocksDB open may perform recovery/filesystem work even with creation disabled. Read-only open then reopen creates a handle gap. | Can classify marker before opening DB, without creating it; regular-file bounded reads have local prior art (F6). Missing marker never admits startup. |
| Publication | WAL-enabled `sync=true` plus documented backend profile; errors may have visible bytes. Must not borrow epoch flush acknowledgement. | Temp file sync, same-directory rename, directory sync, stage-aware errors. No DB open needed to see unresolved intent at restart. |
| Restore/copy | Database-only copies may carry marker but omit state/signing history; cannot prove freshness | Database-only copy can omit marker: absence refuses. Paired copies can both be stale: validity still refuses. |
| Main cost | Early DB ownership/recovery, no-create inspection and namespace isolation changes | Separate-store binding, safe directory-relative operations and publication implementation |

**Recommendation (PROPOSED): external marker**, because quarantine can be
observed before a potentially creating/recovering database open and before
listeners. It also exposes a restart refusal even if DB opening fails.
Neither current backend meets the complete boundary unchanged. The external
candidate is an implementation target only after identity, initialization,
bounded format and storage-profile review. It does not sidestep those blockers.
The RocksDB alternative remains viable if a reviewed existing-only opening
and continuous ownership design is established; it is not selected here.

## 4. Proposed concrete boundary and record

Dedicated non-blanket trait, not an extension/default on `ConsensusStorage`:

```rust,ignore
trait CatchupQuarantineStore {
    fn inspect_existing(&self) -> Result<Inspection, InspectFailure>;
    fn publish_applying(
        &mut self, owner: &ActiveCatchupOwner, expected: Revision,
        intent: &ValidatedIntent,
    ) -> Result<IntentAck, IntentFailure>;
    fn record_outcome(
        &mut self, owner: &mut ActiveCatchupOwner, ack: &IntentAck,
        expected: Revision, update: &OutcomeUpdate,
    ) -> Result<OutcomeAck, RecordFailure>;
}
```

Types, names and signatures are proposed, not compiled implementation.
`ActiveCatchupOwner` owns the closed-admission latch, effect registry,
retained rejected inputs and exact checked-store binding. Its private token
is issued only through separately reviewed admission/barrier construction;
no public token deserialization or forged boolean barrier is sufficient.
`IntentAck` acknowledges only the exact intent publication under one named
storage profile, not startup eligibility, engine persistence or signer safety.
`OutcomeAck` covers only one outcome revision. Neither clears quarantine.

Proposed binding is `(chain/genesis identity, local store ID, store incarnation,
operation ID, writer session, revision, predecessor revision)`. Include exact
starting committed anchor, view, lock identity, request/response identity and
the evidence inventory used by catch-up. Do not equate equal block IDs with
equal contents, QC or evidence. The operation retains distinct completed
prefix, current-item, signer/reservation, storage, callbacks/snapshot/epoch,
enqueue/worker and delivery observations. A checksum detects accidental
corruption only; it authenticates none of these claims.

Proposed envelope: dedicated magic/tag, format version, checked lengths,
binding, Applying state and cumulative outcome evidence, followed by checksum.
Strictly reject unknown versions/tags, trailing bytes, truncation, duplicate
conflicting fields, arithmetic overflow and over-limit input; never truncate.
**Proposed storage-only ceiling: 64 KiB** per final record and per staged
publication, checked during reads with one detection byte and before encoding.
This is not a protocol limit or approval to drop evidence. Before approval,
derive whether the full supported bounded response/effect inventory fits;
if not, revise/review the design or refuse before admission, not after silently
discarding effects. Count limits and complete byte layout/checksum choice
remain format-review dependencies; prototype's 4/16 limits are not inherited.

The store ID/incarnation must also exist in dedicated consensus-DB metadata
and be read from the exact handle under destination ownership. **That metadata
does not exist as this quarantine binding today.** Its allocation, initialization,
copy/restore behavior and validation require review. Session and operation IDs
must be non-reused under a reviewed allocation rule; no randomness/crypto
authority is selected here. A copied ID is a copied label, not copy detection.

## 5. Existing-only inspection, ownership and handle continuity

Proposed inspection opens an already-existing data directory and marker
directory without `create_dir_all`, schema initialization, repair, truncation
or promotion of temporary files. Use held directory handles and relative,
no-follow regular-file operations with checked bounds; F6 is a precedent,
not proof that existing absolute-path helpers close all parent-path races.
Absent store/directory/record, special files, corrupt/unsupported/unreadable
state all refuse participating admission. Do not invoke F1/F3 for classification.
Inspecting a valid local Applying or outcome record **also refuses**.

A separate proposed ownership acquisition holds destination ownership
through startup, restore and runtime; it is not part of read-only inspection.
If acquisition would create a missing lock/directory, do not call it
initialization: refuse or use the separately authorized baseline workflow.
Use one lock ordering: destination ownership, quarantine owner, DB ownership;
do not hold the quarantine mutex across worker joins. The process-wide barrier
must close admissions/drain before entering the short publication lock.

After admissible baseline handling (not selected here), open the existing
consensus DB once with creation disabled, inspect IDs/schema without repairs,
and package the exact `Arc`, identity and held directory/lock handles in a
non-rebindable `CheckedCatchupStore`. Pass this object to the engine owner,
marker publisher, snapshot/storage callbacks and catch-up handler; no path
lookup/reopen or caller-supplied identity substitution at mutation time.
Requested restore must carry this same binding through precheck/materialize/
persist, preserving F4's single-handle pattern without its creating behavior.
If restore would replace the bound DB/store, stop; explicit rebind/migration
rules are required rather than continuing with a stale marker.

Expected-revision comparison and publication occur under the same owner.
Stale revision, overflow, changed owner/handle/store or lost lock refuse.
The recognized active operation latches before these errors. Foreign requests
cannot change another operation's record/latch; their caller owns its own
failure/evidence and must not continue effects. Local locks cover cooperating
processes at this destination only, not copies, hostile writers or a shared signer.

## 6. Proposed ordering and failure semantics

1. Establish reviewed admission prerequisites and inventory participants.
   Close new admissions; observe completion/fencing of in-flight signer,
   callback, snapshot, storage and outbound work. Cancellation/enqueue/timeout
   are not completion or delivery. Unknown stays closed; progressed effects
   cannot be retracted. No worker join under the record lock.
2. Freeze exact anchor/view/retained-state and checked-store binding. Preflight
   input sizes/capacity/existing-ID rules without mutating engine state.
   The all-producer barrier and intent acknowledgement are separate requirements.
3. Under owner/revision serialization, publish Applying before the first
   possible catch-up mutation: exclusive temp creation inside held marker
   directory, bounded full write, temp-file sync, atomic same-directory rename,
   marker-directory sync. A newly initialized directory would additionally
   need parent sync under a separately reviewed initialization path.
4. Issue `IntentAck` only after all required sync acknowledgements and exact
   scope validation. If any stage fails, issue no acknowledgement and perform
   no catch-up mutation. Readback is diagnostic, never a substitute for sync.
5. Apply only under the held engine/barrier/store ownership. Refuse existing
   IDs and unavailable safe slots before insertion/vote replay under the
   separately approved containment contract; preserve protected ancestry.
   Registration, vote replay, QC/lock/commit and view effects need real typed
   reports: F9 cannot currently supply this contract. No response rollback.
6. On entering outcome recording for the legitimate active operation, latch
   further mutation **before any fallible validation**, as the corrected model
   does. Merge sticky known effects/conflicts and prefix/current-item evidence.
   Publish next revision using the same full sync sequence. A valid-prefix
   refusal reports the prefix and any current effects; no blanket no-effect.
7. Oversized/unsupported/revision/ownership failures return typed
   `RejectedUnrecorded` with the original input still owned by the active
   operation. It retains payload/failure and remains closed; no truncation
   or claimed persistent Unknown. Failed publication returns
   `PublicationUnresolved` with volatile observations separately scoped.
   A retry may record evidence, but cannot restore mutation authority.
8. Complete/no-effect/empty/stale responses, timeout, late completion and
   restart do not clear quarantine or exit restore mode. Existing F8 transition
   calls require future gating; this document does not modify them.

Before-rename errors may retain the prior final record only when the stage
is actually established. After rename but failed directory sync means new
bytes may be visible with unacknowledged durability; no success token, no
assertion of prior-record retention. Interrupted writes/ambiguous completion
remain unresolved. Temporary artifacts are diagnostic only, never automatic
repair/completion evidence. On restart classify observable final bytes and
refuse, regardless of whether a prior process received acknowledgement.
An acknowledged Applying intent protects the restart boundary even if later
rejected/outcome evidence was only in memory; it does not recover lost evidence.

## 7. Durability, crash models and startup consequences

**Proposed profile P1, unverified:** supported Unix local filesystem; same-
filesystem atomic rename; acknowledged regular-file sync persists bytes;
acknowledged directory sync persists name replacement; OS/device honors flush
and ordering through the declared storage stack. Specify OS/kernel, filesystem,
mount options, block device/controller/cache and virtualization settings before
any claim. Refuse unsupported sync/storage profiles, read-only media and I/O
errors; no volatile fallback. Space exhaustion is a failed publication, not
permission to mutate.

| Failure model | What P1 could support after validation | Not established |
|---|---|---|
| Ordinary process crash | Final record classification; missing/partial/intent/outcome refuses restart | No recovery of caller-held effects lost before outcome; no signer continuity |
| Power loss | Only ordering/durability under named verified P1 stack and fault evidence | Process-kill tests do not establish this |
| Corrupt/truncated/absent records | Bounded refusal and preserved diagnostics | Authenticity, repair, fresh-history inference |
| Older internally valid directory copy | Local record is readable but participation still refused | Currentness/anti-rollback |
| Two copies with same signing identity | Each local owner can serialize its own writes | Global exclusivity/fencing |

Before actual participating startup, classify quarantine **before enabled
metrics listener**, operational signer loading/preflight, P2P construction,
engine/timers/snapshot tasks and requested-restore materialization. F4/F5
currently do not implement this order. Move classification ahead of existing
creating operations; do not merely add a check after F3. Restore's RTR COMPLETE
or epoch parity cannot override quarantine. Ordinary and requested restore,
LocalMesh/P2P, optional metrics, no-data-dir and validation/apply CLI exits need
a reviewed mode matrix. Read-only diagnostics may be allowed only without
listeners/signing/guarded mutation; no implicit exemptions. Preserve existing
RUN 422 guards rather than replacing them with this marker.

Fresh data-dir and legacy nonempty DB without marker both refuse under this
candidate. A separately reviewed baseline initialization/migration procedure
must define chain/store identities, signing history, locks and durable ordering.
No automatic baseline, deletion of marker, operator acknowledgement or restore
is a clear procedure. In this stay-closed slice valid records still refuse
restart participation: indefinite stop is an explicit liveness cost.

## 8. Implementation acceptance matrix (NOT executed)

All rows require source review plus the named test layer before implementation
acceptance. Unit/fake tests alone cannot satisfy filesystem/binary rows.

| Failpoint/location | Input | Expected observable state | Required test layer |
|---|---|---|---|
| Existing-only directory/store open | Missing data-dir/DB/marker | Typed absence/refusal; no directories, schema, repaired DB or marker created | Filesystem integration, binary modes |
| Inspect final open/read/decode | Corrupt/truncated/unsupported/foreign/unreadable/oversized; symlink/FIFO | Bounded refusal, no blocking special-file open or rewrite/truncation | Codec unit + Unix filesystem |
| Inspect valid record | Applying/outcome/Complete local copy | Readable diagnostic only; no participation/currentness claim | Unit + startup binary |
| Owner acquire | Two cooperating writers, either order | One owner; other typed contention, no replaced evidence | Real multi-process local-lock plan |
| Owner/revision compare | Stale revision/overflow | Active owner latched; old evidence intact, rejected input unrecorded | Unit + backend integration |
| Binding at handoff | Different DB Arc/store/incarnation, renamed parent/path | Refusal before mutation; no path-based rebind | Identity/handle integration + filesystem |
| Temp open/write | Permission/ENOSPC/short write/error | No intent acknowledgement/mutation; diagnostic temp may exist | Backend failpoint integration |
| Temp sync | Bytes written then sync fails | No acknowledgement; unresolved, no engine effect | Backend failpoint integration |
| Rename | Failure before established replacement | Prior final only if known; no acknowledgement | Filesystem failpoint |
| Post-rename directory sync | New bytes visible, sync error/unknown | No token; visibility not durability, prior retention not asserted | Filesystem failpoint + reopen |
| Intent acknowledgement return | Completion lost/timeout | Unknown result; no catch-up until actual scoped ack; restart refuses | Owner unit + authorized process plan |
| After acknowledged intent | Kill before first engine mutation | Applying survives under tested process model; restart refuses before services | Separately authorized process/binary |
| Barrier | Outstanding signer/storage/callback/outbound work | Intent alone insufficient; no mutation; unknown domain retained | Deterministic workers + actual node integration |
| Engine slot admission | Full/above/zero capacity, protected/indeterminate ancestry | Refusal before insertion/votes; no unsafe eviction; exact evidence accounting | Engine/retention integration |
| After first accepted item | Valid prefix then refusal | Prefix retained; rejected/partial item separate, mode stays closed | Engine + actual handler |
| Inside vote replay | Error after insertion or some votes | Report known insertion/votes, possible QC/lock/commit; no rollback assertion | Engine failpoints + node propagation |
| Outcome validate | Known effect plus oversized/unsupported input | Active operation latched before error; full caller payload unrecorded, no truncation | Corrected model + backend-owner tests |
| Foreign recording request | Token for other store/op/writer/revision | No change to victim operation/evidence; caller handles own refusal | Unit + owner integration |
| Outcome sync/publication | Failure/uncertainty/visible-before-error | Volatile effects retained; no OutcomeAck or durable-Unknown claim | Backend failpoints + node counters/logs |
| Outcome merge/retry | Repeated/backward/contradictory/Unknown update | Known prefix/effects sticky; conflict separate; no gate restoration | Unit/property tests + backend integration |
| Restart after outcome | Complete/no-effect/partial/absent/corrupt | Stay closed before metrics/signer/P2P; no response-mode exit | CLI matrix + authorized process plan |
| Snapshot restore/copy | RTR COMPLETE, DB replacement or stale paired copy | No quarantine bypass/rebind/currentness inference | Restore integration; process plan |
| Copied concurrent stores | Same signing identity, two valid markers | Local locks not exclusivity; neither gains restart admission | Synthetic controls; real signer work separately authorized |
| Power interruption | Every write/sync/rename boundary on named stack | Only profile-specific ordered persistence claim after evidence | Separately authorized storage/power-fault plan |

## 9. Decisions and acceptance gates

**Needed to implement stay-closed recording:** approve candidate location/API;
exact bounded encoding/profile inventory and checksum; allocation and DB
metadata binding for chain/store/incarnation/session/operation identities;
non-creating open and continuous handle/directory ownership; local serialization
and revision behavior; durability P1/backend error contract; initialization/
migration; complete startup/CLI/restore ordering; all-producer barrier and
typed engine effect reports; retention of unrecorded inputs/errors and bounded
diagnostics/counters. Candidate acceptance requires matrix evidence, not merely
matching the fake model. No acceptance gate is waived by this recommendation.

**Later, separately necessary before clear/resume:** independently trusted
currentness/anti-rollback evidence; exclusive signer ownership across copies;
reconciliation of anchor/view/retry position, retained blocks/votes/evidence,
lock/commit and signing history; recovery/clear authority and observed barrier
completion. Alternatives remain external trusted checkpoint/currentness,
independently fenced signer service or separately reviewed recovery procedure;
none is selected or approved. A local marker, generation match, checksum,
restart or operator acknowledgement proves none of these.

This design selects no clear authority, enables no catch-up and closes no
authentication, A17-F1, global-capacity, RUN 422 evidence or deployment obligation.
No production/test source was changed or Rust tests rerun for this document.
See [design checks and hashes](storage-candidate-checks.txt) for executed
documentation-only checks; all acceptance matrix experiments remain **NOT RUN**.
