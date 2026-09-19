# QBIND Snapshot-Restore Completion Contract

Status: `D7D7_RESTORE_COMPLETION_CONTRACT=DEFINED-NOT-IMPLEMENTED`

Scope: **documentation-only.** This document defines an implementation-ready
protocol for containing interrupted snapshot restores. It adds **no** production
code, tests, storage schema, journal, CLI flag, recovery command, cleanup, or
activation change. Defining this contract does **not** establish operational
protection; the safety boundary exists only once the bounded successor task in
§10 is implemented and validated.

This document is the authoritative contract for restore completion. The existing
protocol documents
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` and
`docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` carry only
concise successor references to it; they are not superseded on any other subject.

Retained posture (unchanged by this document; see §11):

* `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`
* `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`
* `GENESIS_AUTHORITY_ACTIVATION=DISABLED`
* `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`
* `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
* `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`

---

## 1. Provenance and object availability (actual checkout)

* Actual working branch: `copilot/run-422-d7-d7`.
* Actual `HEAD` at authoring: `1babc12216f29bf02a44742a56996acb8d691a3f`
  (parent `36f179469753e85b24a51cc2b116e3f959e549fd`).
* This is a shallow, single-branch clone (`git rev-list --count HEAD` = 2). The
  D7-D6 provenance named in the task — accepted branch `copilot/run-422-d7-d6`,
  accepted revision `9d9723e09b65381bba5f784d0cd10b1d2455c6ea`, and D6 test
  checkpoint `0099517183bfe842e0a8c04ddd179c44c285934a` — are **not resolvable as
  git objects** here (`git cat-file -t` → "could not get object info" for both).
  `36f179469753e85b24a51cc2b116e3f959e549fd` remains separately identified as the
  previously reported base / build-source reference; it is **not** relabeled as
  the test-implementation checkpoint. No branch was renamed and no ancestry was
  manufactured. Missing objects do **not** establish missing implementation: the
  D5/D6 behavior this contract builds on is present in this worktree and cited by
  file and line throughout.

---

## 2. The failure window this contract must close (source-backed)

D6 characterized a real, deterministic interruption window. Read from
`crates/qbind-node/src/snapshot_restore.rs` and
`crates/qbind-node/src/main.rs`, the restore effects occur in this order:

1. `main.rs` (restore path, ~L2553) opens the canonical `<data_dir>/consensus`
   storage EARLY (`open_production_consensus_storage`) and runs the D5
   pre-materialization epoch-compatibility precheck
   (`evaluate_restore_epoch_compatibility`, a fresh LIVE `get_current_epoch`
   read; `production_consensus_storage.rs:535`).
2. On PERMIT, `materialize_validated_snapshot`
   (`snapshot_restore.rs:613`) creates `<data_dir>/state_vm_v0` when absent and
   **copies** the snapshot account state into it (`copy_dir_recursive`,
   `snapshot_restore.rs:652`), THEN
3. calls `write_restore_marker` (`snapshot_restore.rs:715`), which OPENS
   `RESTORED_FROM_SNAPSHOT.json` with
   `OpenOptions::create(true).append(true).open(path)` (`:746`) and appends one
   JSON audit line via `write_all` — **no `flush`, no `sync_all`, no directory
   fsync.**
4. Only AFTER a successful restore outcome does `main.rs` (~L4920) run Run 097
   `persist_restored_snapshot_epoch` (`production_consensus_storage.rs:619`),
   which calls `put_current_epoch` (`storage.rs:912`) via `self.db.put(...)` —
   RocksDB **default write options (no `WriteOptions::set_sync`)**.

D6's `d7d6_*` cases obstruct step 3 by making the marker path a directory: the
copy in step 2 succeeds, the marker open fails (`M_MARKER_OPEN_FAIL = "cannot
open marker file"`), the process exits 1 **before** step 4, and the snapshot
epoch is never persisted
(`crates/qbind-node/tests/run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`,
`produce_and_verify_marker_obstructed_failure`, `d7d6_a/b/c`). Then:

* An ordinary **no-flag** restart over that destination reaches the consensus
  loop with `restore_baseline=false` — it never inspects the account-state
  directory for an interrupted restore (`d7d6_b`, `main.rs` `Ok(None)` branch at
  ~L2660; the ordinary-startup path has no restore-marker check).
* A **with-flag** retry is refused by `RestoreError::TargetStateNotEmpty`
  (`snapshot_restore.rs:638`; `d7d6_c`, `M_TARGET_NOT_EMPTY`).

**Central requirement.** Ordinary startup must not admit a tracked, interrupted
restore as completed. Completion must cover account-state installation, the
required audit recording, and the required epoch persistence. The existing audit
marker is **not** sufficient completion evidence: it is written in step 3, before
Run 097 (step 4), so a marker present on disk does not prove the epoch was
persisted. Writing the same marker earlier would not close the window either.

---

## 3. Reuse inventory (actual callers, trust, persistence, reuse limits)

Each mechanism below was read in the actual checkout. A name that merely sounds
applicable (a governance replay record, or the RocksDB epoch-transition marker)
is **not** treated as a restore transaction.

| Mechanism | Location | What it does | Trust / persistence | Reuse limit for restore completion |
|---|---|---|---|---|
| Restore validation | `snapshot_restore.rs:597` `validate_snapshot_for_restore` → `qbind_ledger::validate_snapshot_dir` | Checks layout + chain-id, returns validated `StateSnapshotMeta` | Read-only; no durability role | Reuse as the single validated-meta source bound to the transaction record. |
| Materialization | `snapshot_restore.rs:613` `materialize_validated_snapshot`, `copy_dir_recursive` `:669` | create_dir_all + recursive file copy into `state_vm_v0`; refuse non-empty target `:638` | Plain `std::fs::copy`; **no fsync of files or dir** | Copy is the first destination mutation; the intent record must precede it. Copy is not durable without added sync. |
| Audit marker write | `snapshot_restore.rs:715` `write_restore_marker` | Append one JSON line; `create+append+write_all` `:746` | **No `flush`/`sync_all`** | May be treated as a human-auditable receipt only. **Not** completion evidence. |
| Outcome handling | `snapshot_restore.rs` `RestoreOutcome`; `main.rs` `restore_result` match ~L2658 | `Ok(Some)` → baseline; `Err` → `exit(1)` | In-memory; process-scoped | Reuse the `Err`→fail-closed convention; add completion-record write on the success arm. |
| D5 epoch compatibility | `production_consensus_storage.rs:535` `evaluate_restore_epoch_compatibility` | Fresh LIVE `get_current_epoch`; `RestoreEpochInconsistent` on `m≠n`, `PersistAfterMaterialization` on `None` | Live read; fail-closed on read error (`EpochProbeFailed`) | Reuse verbatim as the epoch gate; do **not** duplicate its decision. |
| Run 097 persistence | `production_consensus_storage.rs:619` `persist_restored_snapshot_epoch` → `put_current_epoch` `storage.rs:912` | Writes `meta:current_epoch` big-endian, checksum-wrapped, via `self.db.put` | **RocksDB default (async) write**; API success ≠ power-loss durability | Reuse as the epoch effect; completion must not be recorded until this effect satisfies the chosen durability profile (§5). |
| Atomic epoch-transition batch | `storage.rs:361` `EpochTransitionBatch`, `EpochTransitionMarker` `:350`; `check_for_incomplete_epoch_transition` `:1087` | M16 governance epoch boundary: WriteBatch + start/clear marker; startup fail-closed if marker present | RocksDB WriteBatch atomicity within the consensus DB only | **Not a restore transaction.** Do not conflate; it covers consensus epoch boundaries inside one DB, not the cross-artifact restore. Its start/clear-marker pattern is a *design reference* only. |
| Storage observation (D7-C1) | `consensus_storage_observation.rs` `observe_consensus_storage` | Read-only startup classification: `NoStorageHandle` / `PresentNoCommittedEpoch` / `CommittedEpoch(n)` | Read-only; never authorizes | Reuse as the startup epoch-state reader; a persisted epoch is evidence, not authority. |
| Snapshot staging / checkpoint | `qbind_ledger` `StateSnapshotter` (T215) RocksDB checkpoint; snapshot dir `meta.json` + `state/` | Point-in-time source; `meta.epoch` optional | Source-side only | Source of the validated meta and `state/` bytes; not a destination durability mechanism. |
| Startup incomplete-op check | `main.rs` Run 093 open + `check_for_incomplete_epoch_transition`; D5 CLI-exit refusal ~L2511 | Detects incomplete epoch transition; refuses restore + CLI-exit combos | Consensus-DB-scoped | No equivalent check exists for interrupted **restore**; that is the gap this contract fills. |
| Fault-injection / restart tests | `run_422_d7d3_..._tests.rs` (`DrainedChild`, `observe_then_terminate`, `ordinary_localmesh_args`, `produce_and_verify_marker_obstructed_failure`) | Child-process release-binary restarts; marker obstruction via directory sentinel | Deterministic local-I/O only | Reuse fixtures/runner for future tests; these are **not** process-kill or power-loss evidence. |

**Trust boundary reminder (from the inventory).** A consensus RocksDB handle
locks only the `<data_dir>/consensus` database (RocksDB `LOCK`). It does **not**
lock `state_vm_v0`, the restore marker, or a future transaction record. No
existing lock covers the whole restore/startup operation or the whole
destination.

---

## 4. Protocol: the smallest coherent restore-transaction state machine

The contract introduces one durable **restore-transaction record** (RTR) distinct
from the account-state directory, the audit marker, and the consensus epoch key.
The RTR is the single source of truth for "is there a tracked restore, and is it
complete?" It is intentionally minimal.

### 4.1 Association fields (bound before the first destination mutation)

The RTR is created and made durable **before** `copy_dir_recursive` runs, and
records:

* `destination_id` — canonical absolute `data_dir` (and `state_vm_v0` subpath),
  so a completion record cannot authorize a different destination.
* `snapshot_meta_digest` — a digest over the SAME validated `StateSnapshotMeta`
  (`height`, `block_hash`, `chain_id`, `created_at_unix_ms`, and `epoch` as an
  explicit `Option`) returned by `validate_snapshot_for_restore`, so the record
  is bound to one validated snapshot identity.
* `attempt_nonce` — a per-attempt unique value, so a completion record from an
  earlier attempt cannot authorize a later attempt.
* `expected_epoch` — the snapshot `meta.epoch` (`Option<u64>`), preserving the
  `None` vs `Some(0)` distinction (missing epoch ≠ epoch zero).

### 4.2 Persistent states and their meaning

| State | Meaning | Set when |
|---|---|---|
| *(absent)* | No tracked restore at this destination. | Fresh destination, or never-restored legacy directory. |
| `INTENT` | A restore attempt is in progress; the destination may be partially mutated. | Durably written before any account-state copy. |
| `COMPLETE` | All required restore effects (account-state install, required audit record, required epoch persistence) satisfied the durability contract (§5) for THIS attempt and destination. | Durably written only after every required effect is durable. |

There is no other terminal success state. An `INTENT` record that is never
upgraded to `COMPLETE` denotes an interrupted restore.

### 4.3 What permits account-state installation

Account-state installation (the `copy_dir_recursive` into `state_vm_v0`) is
permitted only after: snapshot validation passed; the D5 authority-marker check
passed; the D5 epoch-compatibility precheck PERMITTED; and the `INTENT` RTR is
durable. This preserves the existing pre-materialization gates and adds the
intent gate ahead of the first mutation.

### 4.4 What constitutes completion

Completion (`COMPLETE`) requires, for the same `attempt_nonce` and
`destination_id`:

1. account state installed into `state_vm_v0`;
2. the required audit record written; and
3. the required epoch effect performed — either `put_current_epoch` succeeded for
   a `Some(n)` snapshot into a present-no-committed-epoch destination, or the
   epoch was already consistent, or the snapshot legitimately carries no epoch
   (`None`) — each having met the durability profile of §5.

Only after (1)–(3) are durable is `COMPLETE` written and made durable. Publishing
`COMPLETE` before any required effect is durable is prohibited (§10).

### 4.5 Startup decisions

Ordinary startup (no flag) and requested-restore startup both consult the RTR
before using the affected account state or starting services that could act on
it:

| RTR at destination | Ordinary (no-flag) startup | Requested-restore (with-flag) startup |
|---|---|---|
| absent + empty `state_vm_v0` | Proceed (fresh). | Proceed with restore. |
| absent + non-empty `state_vm_v0` (untracked/legacy) | **Refuse — investigate** (cannot prove clean; §5.5). | Existing `TargetStateNotEmpty` refusal. |
| `INTENT` (interrupted) | **Refuse — fail-closed, investigate.** Must not admit as completed. | **Refuse** the occupied destination; operator must clear/replace before retry (no auto-cleanup). |
| `COMPLETE` for this destination + matching snapshot identity | Proceed; the restored state is admitted. | Idempotent: recognized as already-restored; do not re-copy. |
| `COMPLETE` but destination/nonce/snapshot mismatch | **Refuse** — a stale/foreign completion must not authorize this destination. | **Refuse.** |
| corrupt / unreadable / malformed / unsupported-version RTR | **Refuse — fail-closed, investigate.** | **Refuse.** |

Epoch reconciliation with the RTR at startup preserves the D5 semantics:

* Missing epoch stays distinct from epoch zero.
* A `COMPLETE` historical restore is **not** current-authority freshness; a
  legitimately larger live committed epoch (normal epoch advancement after a
  completed restore) must not be mistaken for an incomplete old restore merely
  because it differs from the recorded `expected_epoch`. The RTR gates
  *completion*, not *freshness*; anti-rollback remains out of scope.

### 4.6 Automatic recovery

Automatic recovery (auto-clean of a partial `state_vm_v0`, auto-retry, or
auto-repair of a corrupt RTR) is **excluded** from the first implementation. The
first implementation only detects and refuses; an operator investigates and acts.

---

## 5. Trust model, ownership, and compatibility

These are stated separately and must not be collapsed.

### 5.1 Ordinary I/O-error handling

Any read/write/open error on the RTR, account state, or epoch surface is
fail-closed (non-zero exit), as the existing restore path already does for its
own errors (`RestoreError::Io`, `main.rs` `exit(1)`). No silent degradation.

### 5.2 Process termination

An abrupt process exit (signal/panic) between `INTENT` and `COMPLETE` leaves an
`INTENT` record and possibly a partial `state_vm_v0`. Startup refuses (§4.5). This
is the D6 window and is fully addressable with deterministic, ordered writes
plus fsync of the RTR before the copy.

### 5.3 Host / power failure

Power loss can lose writes that returned success but were not fsync'd — this is
exactly why `put_current_epoch`'s default RocksDB `put` (`storage.rs:912`) and
`write_restore_marker`'s un-synced append (`snapshot_restore.rs:746`) cannot be
claimed power-loss durable today. The chosen first-implementation profile
(§5.6) MUST specify explicit fsync points, or must **not** claim power-loss
durability. A filesystem rename does **not** make account storage, consensus
storage, and audit data one atomic transaction; no such claim is made.

### 5.4 Malicious deletion / replacement / rollback of the directory

Out of scope for the first implementation. An adversary who can delete or replace
`data_dir` (including the RTR) can erase evidence of an attempt. Restore
completion is necessary evidence for the ordinary-startup boundary, **not** proof
of consensus recovery, signing-state continuity, authorization, or rollback
resistance. `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED` remains.

### 5.5 Ownership and competing processes

No existing lock covers the entire restore/startup operation and destination; the
consensus RocksDB `LOCK` covers only `<data_dir>/consensus`. The first
implementation MUST take an explicit exclusive destination-scoped lock (e.g. an
`O_CREAT|O_EXCL` lock file, or an advertised advisory lock over `data_dir`)
around intent→install→complete and around the startup RTR inspection, and MUST
assume a second writer can exist rather than assuming it cannot. Absence of a new
RTR cannot retrospectively prove a legacy directory is clean.

### 5.6 Explicit filesystem / storage assumptions (first-implementation profile)

* Target: a POSIX filesystem where `fsync(file)` + `fsync(parent dir)` orders and
  persists a create/rename, and RocksDB `WriteOptions::set_sync(true)` persists a
  put before returning.
* The RTR write path: write to a temp file, `fsync` it, atomically `rename` into
  place, then `fsync` the parent directory — a durable, single-file atomic
  publish for each RTR state transition.
* The epoch effect: `put_current_epoch` under this profile MUST use a synced
  write (or an explicit flush) before `COMPLETE`; otherwise `COMPLETE` may not be
  claimed power-loss durable.
* Unsupported guarantees (cross-artifact atomicity, network filesystems, storage
  that reorders fsync) remain **unclaimed**.

### 5.7 Compatibility / migration decision (explicit)

* A tracked destination is one bearing an RTR. Existing destinations have **no**
  RTR (D3–D6 layouts, legacy `RESTORED_FROM_SNAPSHOT.json`, D4/D6 partial
  layouts).
* Decision: an untracked **non-empty** `state_vm_v0` is treated as
  **unproven** — ordinary startup refuses and requires operator action (a legacy
  audit marker does not upgrade it to `COMPLETE`; absence of an RTR cannot prove
  it clean). An untracked **empty/fresh** destination proceeds.
* **Unresolved prerequisite:** whether existing operational deployments already
  hold non-empty untracked `state_vm_v0` directories that would now be refused,
  and whether a one-time operator-attested "adopt as complete" step is required.
  This must be resolved before enabling the ordinary-startup refusal in
  production. No automatic cleanup or approval bypass is invented here.

### 5.8 D5 protections preserved and bypass inventory

Preserve D5's restore/CLI incompatibility (`main.rs` ~L2511 refusal of
restore + `cli_storage_exit_mode_active`), live-read epoch semantics
(`evaluate_restore_epoch_compatibility`), authority-marker checks
(`restore_from_snapshot_with_authority_marker_check`,
`AuthorityContextMissing` for legacy no-context + existing marker), and
fail-closed defaults. Entrypoints that could bypass the proposed startup guard
and MUST be inventoried by the implementation:

* `snapshot_restore::restore_from_snapshot` /
  `restore_from_snapshot_with_authority_marker_check` (library primitives usable
  by tests/tools without the RTR gate).
* `apply_snapshot_restore_if_requested` legacy no-context entrypoint.
* Any CLI-exit mode that opens `<data_dir>/consensus` (Run 098) before normal
  startup.
* Direct operator manipulation of `state_vm_v0` / the marker outside the binary.

---

## 6. Failure matrix

Durability claims below assume the §5.6 profile; where the profile is not yet
implemented, the "evidence" column names what is required to validate the claim.

| Interruption point | Durable artifacts | Allowed startup behavior | Retry behavior | Evidence to validate |
|---|---|---|---|---|
| Before intent recording | none | Fresh: proceed | With-flag: proceed | Deterministic I/O test (fresh control). |
| During intent create / sync | partial/temp RTR only (no `INTENT` published) | Treat as absent → fresh proceed only if `state_vm_v0` empty; else refuse | With-flag: proceed if empty | Process-kill test around RTR publish + `fsync`. |
| During account-state copy/stage | `INTENT` + partial `state_vm_v0` | **Refuse — investigate** | With-flag: refuse occupied | Process-kill test (kill mid-copy); D6-style directory obstruction. |
| During install (rename/finalize of copied state) | `INTENT` + possibly-complete state | **Refuse — investigate** | With-flag: refuse occupied | Process-kill test at finalize boundary. |
| During audit append (incl. partial line) | `INTENT` + partial marker | **Refuse** (marker is not completion evidence) | With-flag: refuse occupied | D6 `d7d6_*` marker-obstruction reuse. |
| Before required epoch persist | `INTENT` (+ state, marker) | **Refuse** | With-flag: refuse occupied | The exact D6 window (`d7d6_a/b/c`). |
| During epoch persist | `INTENT`; epoch possibly written un-synced | **Refuse** | With-flag: refuse occupied | Power-loss evidence for the epoch synced write. |
| After epoch persist, before `COMPLETE` | `INTENT` + all effects present | **Refuse** (not yet `COMPLETE`) | With-flag: refuse occupied | Process-kill test between persist and `COMPLETE`. |
| During `COMPLETE` write / sync | `INTENT` or torn `COMPLETE` | **Refuse** unless `COMPLETE` fully durable | With-flag: refuse occupied | Atomic-publish (temp+fsync+rename+dir-fsync) test. |
| After `COMPLETE`, before normal startup | `COMPLETE` (matching dest/nonce/snapshot) | **Proceed**; admit restored state | With-flag: idempotent (no re-copy) | `d7d5_b`-style compatible-restore + subsequent startup. |

---

## 7. Future acceptance tests (reuse existing fixtures and runner)

Reuse `run_422_d7d3_binary_snapshot_restore_characterization_tests.rs`
(`DrainedChild`, `observe_then_terminate`, `ordinary_localmesh_args`,
`produce_and_verify_marker_obstructed_failure`, marker sentinels). Distinguish
deterministic I/O tests, process-kill tests, and power-loss evidence — one does
**not** establish another.

Deterministic I/O tests:

* D6's actual marker-directory obstruction (`d7d6_a`) now leaves `INTENT`; assert
  the RTR is `INTENT`, not `COMPLETE`.
* Ordinary no-flag restart after an interrupted tracked restore (extend `d7d6_b`):
  assert startup **refuses** instead of reaching the consensus loop.
* Requested-restore retry over the tracked incomplete destination (extend
  `d7d6_c`): assert refusal (occupied / `INTENT`).
* Successful completion then startup: assert `COMPLETE` published, then a
  subsequent no-flag startup proceeds and admits the state (`d7d5_b` control).
* Epoch matrix: missing (`None`) vs zero (`Some(0)`) vs matching vs conflicting
  (`d7d3_b`, `d7d3_c`, D5 conflict controls) with RTR present.
* Corrupt / stale / mismatched RTR (wrong `destination_id`, wrong `attempt_nonce`,
  truncated/garbage record, unsupported version): assert fail-closed refusal.
* Legacy / untracked non-empty destination: assert refusal; untracked empty:
  assert proceed.

Process-kill tests (SIGKILL at each §6 boundary): assert only `absent` or
`INTENT` or fully-durable `COMPLETE` are ever observed — never a torn `COMPLETE`.

Competing-process ownership: two concurrent restore/startup processes over one
`data_dir` — assert the destination lock serializes them and the loser refuses.

Power-loss evidence: for every durability boundary the §5.6 profile claims
(RTR atomic publish, synced epoch write), capture explicit power-loss / fsync
evidence. Absent that evidence, the corresponding durability claim stays
unproven; a green deterministic test does not substitute for it.

---

## 8. Contradiction-ledger reconciliation

`docs/whitepaper/contradiction.md` C4 is `OPEN — partial` and lists B3 (VM-v0
state restore) and B5 (restore-aware consensus start) among its partial items.
This contract is documentation-only and defines, not implements, restore
completion; it therefore does **not** change C4's status and requires **no**
ledger rewrite. The ledger already reflects C4/C5 open and the restore path as
partial, which is consistent with `DEFINED-NOT-IMPLEMENTED`. No unrelated history
is touched. Reconciliation is required only when the §10 successor task lands and
establishes an actual boundary; at that point the ledger's B3 sub-item should
reference this contract.

---

## 9. Unresolved decisions (implementation readiness pending)

1. **Legacy adoption (§5.7):** whether existing non-empty untracked `state_vm_v0`
   directories require a one-time operator-attested adoption before the
   ordinary-startup refusal is enabled in production. Until resolved, the
   ordinary-startup refusal cannot be enabled without an operational break.
2. **Power-loss durability profile (§5.6):** the synced-write / atomic-publish
   profile is specified but not yet backed by power-loss evidence; `COMPLETE`
   may not claim power-loss durability until that evidence exists.
3. **Destination lock mechanism (§5.5):** the concrete exclusive-lock primitive
   (lock file vs advisory lock) and its cross-platform behavior must be chosen.

Because decisions (1)–(3) remain open, operational protection is **pending**; the
status is `DEFINED-NOT-IMPLEMENTED` (not `IMPLEMENTED`), and would be `PARTIAL`
only if the protocol itself were incomplete — it is complete, but its enabling
prerequisites are unresolved.

---

## 10. The single bounded successor implementation task

**Task (one, bounded): introduce the durable restore-transaction record (RTR) and
the ordinary-startup restore-completion guard.**

* Entrypoints / smallest file set:
  * `crates/qbind-node/src/snapshot_restore.rs` — write `INTENT` (durable) before
    `copy_dir_recursive`; upgrade to `COMPLETE` only after account-state install,
    audit record, and the epoch effect are durable; keep the `Err`→fail-closed
    contract.
  * `crates/qbind-node/src/main.rs` — on both the ordinary (no-flag) and
    requested-restore startup paths, inspect the RTR before using `state_vm_v0`
    or starting consensus services (the current no-flag `Ok(None)` branch at
    ~L2660 gains an RTR check); wire the existing D5 epoch precheck and Run 097
    persistence into the RTR transitions.
  * `crates/qbind-node/src/production_consensus_storage.rs` — reuse
    `evaluate_restore_epoch_compatibility` / `persist_restored_snapshot_epoch`
    unchanged in decision, but perform the epoch effect under the synced-write
    profile before `COMPLETE`.
* Required new persistent state (only where reuse is insufficient): the RTR
  itself (a single atomically-published file at the destination with the §4.1
  fields and a schema version). Reuse validated `StateSnapshotMeta`, the D5 epoch
  gate, and the D7-C1 observation reader; do **not** reuse the M16
  `EpochTransitionMarker` for this purpose.
* Complete safety boundary the implementation must establish: ordinary startup
  refuses any tracked interrupted (`INTENT`), corrupt, mismatched, or foreign
  restore, and any untracked non-empty destination; it admits only a `COMPLETE`
  RTR matching this destination, `attempt_nonce`, and validated snapshot identity;
  all transitions are serialized by a destination-scoped exclusive lock;
  `COMPLETE` is never published before every required effect is durable.
* Keep separate (do NOT fold in): automatic repair/cleanup of partial
  destinations, anti-rollback, signing-state continuity, and broader recovery
  lifecycle. Do not split the task so it can publish `COMPLETE` before required
  effects are complete.

This successor task is blocked on the §9 unresolved decisions for its production
*enablement*; the code boundary itself is implementable and testable behind the
existing fail-closed defaults.

---

## 11. Retained posture

This document changes none of the following, which remain as recorded:

* `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`
* `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`
* `GENESIS_AUTHORITY_ACTIVATION=DISABLED`
* `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`
* `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
* `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`

C4/C5 stay open. No readiness promotion, production signing enablement, or Run 423
work is implied. Restore completion, once implemented, is necessary evidence for
the ordinary-startup boundary only — not proof of consensus recovery, signing
continuity, authorization, or rollback resistance.