# QBIND Snapshot-Restore Completion Contract

Status: `D7D7_RESTORE_COMPLETION_CONTRACT=DEFINED-NOT-IMPLEMENTED`

Scope: **documentation-only.** This document defines a complete but
**not-yet-implemented** protocol for containing interrupted snapshot restores. It
adds **no** production code, tests, storage schema, journal, CLI flag, recovery
command, cleanup, or activation change. The earlier "implementation-ready" claim
is **withdrawn**: the protocol choices below are resolved, but no code exists and
no durability test has been executed, so this is `DEFINED-NOT-IMPLEMENTED`, not
implemented. Defining this contract does **not** establish operational
protection; the safety boundary exists only once the bounded successor task in
§10 is implemented and validated (§9 separates resolved protocol choices from the
remaining implementation and durability-evidence obligations).

This document is the authoritative contract for restore completion. The existing
protocol documents
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md` and
`docs/protocol/QBIND_GENESIS_AUTHORITY_ENGINE_QC_INTEGRATION_AUDIT.md` carry only
concise successor references to it; they are not superseded on any other subject.

**Correction note (D7-D7 review PARTIAL → three fixes, applied in place).** A later
review found three material contract inconsistencies, now corrected in the operative
text rather than merely appended: **(A)** the durability sequence (§5.9, §4.3) rejects
an occupied destination **before** publishing `INTENT`, so a rejected restore over an
ordinary populated directory leaves no interrupted-restore record; **(B)** crash
decisions (§6, §5.9) are stated from the observable final record under the atomic
temp→sync→rename publication model, replacing the old "`INTENT` or torn `COMPLETE` /
refuse unless fully durable" row; and **(C)** active-attempt binding is separated from
ordinary restart (§4.5, §4.8, §6, §10) — historical `snapshot_meta_digest`/`attempt_nonce`
are provenance on the no-flag path, compared only during an active attempt that holds
those values. The accepted decisions of §3-§10 are otherwise unchanged.

Retained posture (unchanged by this document; see §11):

* `D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE`
* `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`
* `GENESIS_AUTHORITY_ACTIVATION=DISABLED`
* `PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`
* `CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED`
* `SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO`

---

## 1. Provenance and object availability (actual checkout)

* This D7-D7 correction pass ran on actual branch
  `copilot/copilotrun-422-d7-d7-again` with starting HEAD
  `79dd28eaf01924d13008e8b0c013a2924fac00ec` and a clean worktree. The reviewed
  revision `bc0bc2541f53492d19aae1a6c7848381e2c1ac36` is **not resolvable as a git
  object** in this checkout (`git cat-file -t` → "could not get object info"); the
  present worktree content corresponds to the reviewed contract but no ancestry is
  manufactured. Corrections A-C below are committed on this branch (no PR, rename,
  force-push, or history rewrite).
* Actual working branch (earlier draft pass): `copilot/run-422-d7-d7-again`.
* Prior on-branch commits before this correction pass: `a3d82382` (parent
  `1babc12216f29bf02a44742a56996acb8d691a3f`) — the reviewed draft (review
  disposition PARTIAL). The review-named draft revision
  `b8333f33b422e273f439983e269d577637655b8f` is **not resolvable as a git object**
  in this checkout (`git cat-file -t` → "could not get object info"); missing
  objects do not establish missing source and no ancestry is manufactured. This
  pass corrects the reviewed draft in place on the same branch.
* This is a shallow, single-branch clone. The
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
* `snapshot_meta_digest` — a digest over the **entire** validated
  `StateSnapshotMeta` returned by `validate_snapshot_for_restore`, using the
  canonical encoding of §4.8: `height`, `block_hash`, `chain_id`,
  `created_at_unix_ms`, `epoch` (explicit `Option`), **and** the two authority
  fields `authority_state` and `authority_state_v2`
  (`crates/qbind-ledger/src/state_snapshot.rs:169,187`, each an explicit
  `Option`). Binding all metadata — not only the first five fields — keeps the
  identity claim equal to the whole validated meta. This digest is a bounded
  **identity** binding only: it is **not** authentication of checkpoint contents,
  proof the state has not advanced, or current authorization, and it does **not**
  replace the independent D5 authority-marker checks (§5.8), which continue to run
  unchanged.
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
permitted only after, in order: snapshot validation passed; the D5 authority-marker
check passed; the D5 epoch-compatibility precheck PERMITTED; the non-writing
destination-eligibility (occupied-target) check passed; and only then the `INTENT`
RTR is made durable. The eligibility check precedes intent so a rejected restore
over an occupied destination never creates an `INTENT`; this preserves the existing
pre-materialization gates and adds the intent gate ahead of the first mutation.

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
| absent + empty `state_vm_v0` | Proceed (fresh node). | Proceed with restore. |
| absent + non-empty `state_vm_v0` (ordinary node / untracked legacy) | **Proceed** — this is the ordinary steady state (an ordinary node writes `state_vm_v0` via `vm_v0_runtime.rs:70`); startup is unchanged from pre-RTR behavior (§4.7, §5.7). | Existing `TargetStateNotEmpty` refusal (cannot restore over occupied state). |
| `INTENT` (interrupted tracked restore) | **Refuse — fail-closed, investigate.** Must not admit as completed. | **Refuse** the occupied destination; operator must clear/replace before retry (no auto-cleanup). |
| `COMPLETE` for this destination, `state_vm_v0` present | Proceed; the restored state is admitted after validating the record format and that the recorded `destination_id` matches the actual destination and `state_vm_v0` is present. No fresh snapshot or nonce exists on this path, so none is compared; the historical `snapshot_meta_digest`/`attempt_nonce` are provenance only (§4.8). No re-copy, no epoch re-write (§4.6.1). | **Refuse** — the destination is occupied by a completed restore; no idempotent-success route (operator clears/replaces before any retry). A new snapshot/nonce would exist here, but it is **not** used to manufacture an idempotent match. |
| `COMPLETE` present but `state_vm_v0` missing/unreadable | **Refuse — fail-closed, investigate;** do **not** recreate restored state (§4.8.1). | **Refuse.** |
| `COMPLETE` whose recorded `destination_id` does not match this destination (foreign/stale) | **Refuse** — a foreign completion must not authorize this destination. (Nonce/snapshot are provenance, not compared on the no-flag path; §4.8.) | **Refuse.** |
| corrupt / unreadable / malformed / unsupported-version RTR | **Refuse — fail-closed, investigate.** | **Refuse.** |

The comparison inputs, their sources, and the phase in which each applies are
specified in §4.8; the ordinary no-flag restart supplies no new snapshot and no
new nonce, so on that path the only RTR question is `INTENT` (refuse) vs
`COMPLETE`/absent (proceed) — no field is compared against itself as a match.

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

### 4.6.1 A historical `COMPLETE` never re-applies

A `COMPLETE` RTR admits the already-restored `state_vm_v0`; it MUST NOT trigger a
re-copy of account state or a re-write of the consensus epoch. After a completed
restore the node advances normally, and the live committed epoch may legitimately
exceed the recorded `expected_epoch`. The RTR gates *completion*, never
*freshness*: a larger live epoch is normal progress, not an incomplete old
restore, and a historical `COMPLETE` must never roll a progressed node back to the
recorded baseline or epoch. Ordinary startup after a completed restore remains
subject to every other startup and recovery requirement (D5 gates, schema check,
incomplete-epoch-transition check); the RTR adds the interrupted-restore refusal
and nothing else.

### 4.7 Lifecycle transition table (one coherent lifecycle)

The RTR is written **only** by the restore path. Ordinary node operation opens and
writes `<data_dir>/state_vm_v0` through the VM-v0 runtime
(`VmV0RuntimeState::open_from_config` → `RocksDbAccountState::open`,
`crates/qbind-node/src/vm_v0_runtime.rs:70`) and **never** creates an RTR.
Therefore RTR-*absence* means "no tracked restore" — the ordinary lifecycle — and
a legitimate fresh node that has written account data is distinguished from an
interrupted restore by the **`INTENT` record the restore path publishes before it
mutates**, not by whether `state_vm_v0` is non-empty.

| Step | Action | `state_vm_v0` | RTR state | Next ordinary (no-flag) startup |
|---|---|---|---|---|
| Ordinary 1 | Fresh startup, no restore | empty → created | *(absent)* | Proceed (fresh). |
| Ordinary 2 | Normal initialization + account-state writes | non-empty | *(absent)* | Proceed (ordinary). |
| Ordinary 3 | Subsequent ordinary restart | non-empty | *(absent)* | Proceed (ordinary) — **not** mistaken for an interrupted restore. |
| Restore-OK 1 | Requested restore: validate + D5 gates pass, publish intent | empty | `INTENT` (durable) | (mid-attempt) Refuse if seen. |
| Restore-OK 2 | Copy state, sync, audit, epoch effect all durable | non-empty | `INTENT` | Refuse if seen. |
| Restore-OK 3 | Publish completion | non-empty | `COMPLETE` | Proceed; admit restored state (§4.6.1). |
| Restore-OK 4 | Subsequent ordinary restart | non-empty | `COMPLETE` | Proceed; admit (no re-copy/re-epoch). |
| Restore-INT 1 | Requested restore: intent published | empty/partial | `INTENT` | — |
| Restore-INT 2 | Crash during copy/audit/epoch (the D6 window) | partial/complete | `INTENT` (never upgraded) | **Refuse — fail-closed, investigate.** |

The essential distinction (Ordinary 3 vs Restore-INT 2) is carried entirely by the
`INTENT` record. Existing initialization/provenance mechanisms were inspected: the
VM-v0 runtime opener, the audit marker (`snapshot_restore.rs:715`), and the
consensus epoch key all fail to distinguish these cases (§2 shows the marker is
written mid-restore and the no-flag path never inspects the destination). The
**minimal missing mechanism** is exactly the durable `INTENT`/`COMPLETE` RTR;
ordinary initialization needs **no** new record because ordinary startup is
unchanged (it proceeds), and only restores are tracked. Restores performed
*before* this contract exists left no RTR and are therefore indistinguishable from
ordinary state; the contract closes the window for restores performed **under** it
and makes no retroactive claim about pre-contract restores (§5.7).

### 4.8 Association and comparison inputs (per claimed rejection)

Every rejection names exactly which values are compared, where each comes from,
which source is trusted, and in which phase the comparison occurs. Two phases
exist: a **requested restore** (with `--restore-from-snapshot`, which supplies a
fresh snapshot argument and a freshly generated `attempt_nonce`) and an **ordinary
restart** (no flag; no newly supplied snapshot and no new nonce).

| Rejection | Value A (source) | Value B (source) | Trusted source | Phase |
|---|---|---|---|---|
| Foreign destination | `RTR.destination_id` (the on-disk RTR) | canonicalized live `data_dir`/`state_vm_v0` path (this process's config + filesystem) | the live canonical path | both phases |
| Stale attempt | `RTR.attempt_nonce` (on-disk RTR) | the nonce freshly generated for **this** requested attempt (this process) | this process's fresh nonce | **requested restore only** — an ordinary restart has no new nonce, so the RTR nonce is **not** compared against itself as a match |
| Wrong snapshot | `RTR.snapshot_meta_digest` (on-disk RTR) | digest of the freshly validated `StateSnapshotMeta` of the snapshot supplied to **this** requested restore (`validate_snapshot_for_restore`) | neither is an external authority; the equality only asserts same-snapshot-identity for the requested restore | **requested restore only** — an ordinary restart supplies no snapshot, so no digest comparison occurs |
| Inconsistent epoch | `snapshot meta.epoch` (validated meta) vs live `get_current_epoch` (consensus DB) — the authoritative D5 comparison | `RTR.expected_epoch` is informational only (records what the completed restore installed) | the **live consensus-DB epoch** (D5); `RTR.expected_epoch` is **not** trusted as an anti-rollback witness | requested restore (D5 precheck) and completion recording |

**Trust of the RTR.** The RTR is trusted only as *this node's own local record of
its own restore attempts at this destination*, under the destination-lock
ownership of §5.5 and the fail-closed / non-adversarial assumptions of §5.1–§5.4.
It is **not** an external authority and **not** an anti-rollback or freshness
witness; no such witness is invented to justify it. Where a value cannot be an
independent match (the ordinary-restart nonce/digest), the claim is narrowed
accordingly above.

#### 4.8.1 Record format, nonce, and invalid-record behavior

* **Version:** a leading `u32` schema-version field; an unknown/unsupported
  version is an invalid record → **refuse** (never auto-upgrade).
* **Bounded representation:** a fixed maximum record size (small, e.g. a few KiB);
  over-size, trailing bytes, or truncation ⇒ invalid → **refuse**.
* **Canonical metadata encoding / digest:** the `snapshot_meta_digest` is computed
  over a canonical encoding of the whole validated `StateSnapshotMeta` —
  deterministic field order, fixed-width big-endian integers, explicit `Option`
  tags, and the `authority_state` / `authority_state_v2` fields — hashed with the
  `sha3` digest already vendored in `crates/qbind-node/Cargo.toml` (no new crypto
  dependency; distinct from the CRC-style `wrap_checksummed` envelope used for
  storage values). Equal digests assert equal validated metadata only (§4.1).
* **Nonce semantics:** `attempt_nonce` is a per-attempt unique value drawn from the
  OS RNG at restore start, stored in `INTENT` and copied verbatim into `COMPLETE`;
  it binds a `COMPLETE` to the specific attempt that produced it, so an old
  `COMPLETE` cannot authorize a later attempt.
* **Invalid-record behavior:** any parse, version, size, or field-length error is
  fail-closed → **refuse**; the first implementation never repairs a record.

A `COMPLETE` RTR whose required destination state (`state_vm_v0`) is missing,
empty, or unreadable is treated as inconsistent and **refused** on both paths;
the node does **not** silently recreate the missing restored state.

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

### 5.5 Ownership and competing processes (one chosen mechanism)

No existing lock covers the entire restore/startup operation and destination; the
consensus RocksDB `LOCK` covers only `<data_dir>/consensus`. This contract selects
**one** concrete mechanism (not "lock file or advisory lock"):

* **Mechanism:** a **kernel-managed advisory exclusive lock** taken with
  `flock(LOCK_EX | LOCK_NB)` on an open file descriptor of a dedicated lock file
  `<data_dir>/restore.lock` (created with the destination, never deleted as a
  signalling act). The lock is the kernel lock on that open fd, not the mere
  presence of the file.
* **Acquisition:** before any decision that authorizes a protected effect — i.e.
  before snapshot validation / the D5 gates on the restore path, and before the
  startup RTR inspection that could admit `state_vm_v0` on either path.
* **Coverage and lifetime:** acquired once at process start and **held for the
  whole process lifetime**, covering validation, mutation, completion, and all
  subsequent state use. There is no mid-operation release and therefore no
  hand-off race.
* **Competing process:** a second process's `LOCK_NB` acquisition fails with
  `EWOULDBLOCK`; that process **refuses** (fail-closed) rather than proceeding.
* **Process death:** the kernel **auto-releases** the advisory lock when the fd is
  closed or the process dies, so there is **no stale lock file to reap** and no
  presence-based crash policy. (A presence-based `O_CREAT|O_EXCL` lock file is
  explicitly **rejected** here precisely because it would require a separate,
  riskier stale-lock reclamation policy after a crash.)
* **Stable identity:** the lock object is `<data_dir>/restore.lock` under the
  canonicalized destination path; the same canonical path yields the same lock.

A second writer is assumed to exist and is serialized by this lock; the loser
refuses. Absence of a new RTR cannot retrospectively prove a legacy directory is
clean, and the lock does **not** protect against non-participating tools or
malicious directory manipulation (§5.4, §5.5.1).

#### 5.5.1 Participating entrypoints and read-only limits

The lock protects only **participating** entrypoints, which MUST all acquire it:
the release-binary restore path and ordinary-startup path (`main.rs`), and the
library primitives `snapshot_restore::restore_from_snapshot` /
`restore_from_snapshot_with_authority_marker_check` when invoked by a
participating binary. Explicit limits:

* Read-only inspection (`observe_consensus_storage`, tooling that only reads) is a
  permitted exception and takes no exclusive lock; it must not mutate.
* `cfg(test)` and direct library callers that invoke the primitives without the
  guard are **unprotected by construction**; this contract makes **no** claim of
  protection against arbitrary non-participating tools, external processes, or an
  adversary manipulating `data_dir` directly (that is §5.4, out of scope).

### 5.6 Explicit filesystem / storage assumptions (first-implementation profile)

* Target: a POSIX filesystem where `fsync(file)` + `fsync(parent dir)` orders and
  persists a create/rename, and RocksDB `WriteOptions::set_sync(true)` persists a
  put before returning.
* The RTR write path: write to a temp file, `fsync` it, atomically `rename` into
  place, then `fsync` the parent directory — a durable, single-file atomic
  publish for each RTR state transition.
* The epoch effect: `put_current_epoch` under this profile MUST use a synced
  write (or an explicit durability barrier) before `COMPLETE`; otherwise
  `COMPLETE` may not be claimed power-loss durable. **This requires a storage-
  interface change:** the current `ConsensusStorage` trait
  (`crates/qbind-node/src/storage.rs:142`, `put_current_epoch` at `:188`/`:912`)
  writes via RocksDB default `self.db.put` and exposes **no** synced-write or
  flush method, so the existing three-file plan cannot provide this durability
  operation with its present APIs. The successor task (§10) MUST add a synced
  epoch effect to the trait (e.g. a `put_current_epoch_synced` or a
  `flush_epoch_durable` barrier) implemented on `RocksDbConsensusStorage` with
  `WriteOptions::set_sync(true)` / `flush_wal(true)` and on
  `InMemoryConsensusStorage`.
* Unsupported guarantees (cross-artifact atomicity, network filesystems, storage
  that reorders fsync) remain **unclaimed**.

### 5.7 Compatibility / migration decision (explicit)

* A tracked destination is one bearing an RTR. Existing destinations have **no**
  RTR (D3–D6 layouts, legacy `RESTORED_FROM_SNAPSHOT.json`, D4/D6 partial
  layouts), exactly like an ordinary node that has only ever written
  `state_vm_v0` through normal operation.
* **Explicit first-profile legacy policy (chosen, not deferred):** an untracked
  destination — RTR **absent** — is treated as the **ordinary lifecycle**, and
  ordinary (no-flag) startup **proceeds** whether `state_vm_v0` is empty or
  non-empty, exactly as it does today (§4.7). The RTR mechanism *adds*
  interrupted-restore detection via a lingering `INTENT`; it does **not**
  retroactively refuse untracked state, because untracked non-empty state is the
  normal steady state of every ordinary and every pre-contract node. No operator
  "adopt as complete" step, automatic cleanup, or approval bypass is required or
  invented.
* **Scope honesty:** because a pre-contract interrupted restore left no RTR, it is
  indistinguishable from ordinary state and is admitted. The contract closes the
  D6 window for restores performed **under** it (which publish `INTENT` before
  mutating) and makes **no** retroactive claim about restores that predate it.
* The **requested-restore** (with-flag) path is unchanged for occupied
  destinations: an untracked non-empty `state_vm_v0` still hits the existing
  `TargetStateNotEmpty` refusal.

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

### 5.9 Complete durability ordering (ordered sequence)

The restore path performs the following in order. Steps 0.a–0.c are **permitted
preparatory effects** (creating a directory, a lock object, or opening consensus
storage); the **first protected restore mutation** is the account-state copy
(step 3). Intent (step 2) is published before the first *protected* mutation and
only after step 1 has established — without writing anything — that the existing RTR
state, the D5 gates, and destination occupancy all permit installation. The contract
does **not** claim intent precedes *every* destination mutation, because the lock
file and directory-create in step 0 necessarily precede it; it does require that
occupied-target refusal occurs **before** any `INTENT` is created or replaced, so a
rejected restore over an ordinary populated directory can never leave a persistent
startup-refusing record.

0. **Preparatory (permitted before intent).**
   a. Canonicalize the destination; create `data_dir` if absent.
   b. Create/open `<data_dir>/restore.lock` and acquire `flock(LOCK_EX|LOCK_NB)`
      (§5.5). On `EWOULDBLOCK`, refuse.
   c. Open `<data_dir>/consensus` (`open_production_consensus_storage`) for the D5
      reads. Opening storage is preparatory, not a protected restore mutation.
1. **Ownership, precondition, and eligibility checks (no protected mutation, no
   RTR write).** Performed in this order, with D5 precedence preserved:
   a. Lock held (§5.5).
   b. **Inspect existing RTR state and enforce its refusal rules** (§4.5): a
      tracked `INTENT` (interrupted), a `COMPLETE` occupying the destination, or a
      corrupt/foreign/unsupported record refuses the requested restore here; a new
      attempt never overwrites or replaces an existing RTR.
   c. Snapshot validation (`validate_snapshot_for_restore`); D5 authority-marker
      check; D5 epoch-compatibility precheck
      (`evaluate_restore_epoch_compatibility`, a fresh live `get_current_epoch`)
      must PERMIT. Any failure ⇒ refuse.
   d. **Non-writing destination-eligibility check.** Read `state_vm_v0` and refuse
      an occupied target (`TargetStateNotEmpty`) — the same read-only occupancy test
      the copy step performs (`snapshot_restore.rs:627-638`), factored ahead of
      intent so it is reused rather than duplicated with a divergent occupancy
      policy. This check writes nothing.
   The valid snapshot and compatible epochs of (c) ensure no other gate masks the
   occupancy check of (d). Any failure at (a)–(d) refuses **before** any RTR is
   created or replaced, so a rejected request against an ordinary populated
   destination leaves no `INTENT` and no interrupted-restore record.
2. **Durable intent publication.** Only after step 1 establishes eligibility, write
   the `INTENT` RTR (§4.1 fields, version, nonce) via temp-file → `fsync` file →
   atomic `rename` → `fsync` parent dir. Only after this is durable may a protected
   mutation begin. Once a genuine attempt has durably published `INTENT`, a
   subsequent failure retains the fail-closed record — no automatic rollback or
   deletion (§4.6).
3. **Account-state copy / installation.** `copy_dir_recursive` into `state_vm_v0`
   (`snapshot_restore.rs:652`). The copy path re-applies the same occupied-target
   guard defensively, but the authoritative occupancy refusal already occurred at
   step 1(d), before intent.
4. **File and directory synchronization.** `fsync` every copied file, `fsync` the
   `state_vm_v0` directory, and `fsync` the parent of every newly created path
   (including `state_vm_v0` itself when first created).
5. **Audit-record append and its durability.** Append the marker line
   (`write_restore_marker`, `snapshot_restore.rs:715/746`) **and then**
   `flush` + `sync_all` the file and `fsync` its parent directory — the current
   append is un-synced (`:746`) and MUST gain these barriers.
6. **Consensus-epoch effect and its durability.** Perform the epoch effect per the
   outcome matrix below, under the synced-write / durability barrier of §5.6
   (which requires the §10 storage-interface change).
7. **Completion-record publication.** Write the `COMPLETE` RTR (same
   `attempt_nonce`/`destination_id`) via temp → `fsync` → `rename` → dir-`fsync`,
   only after steps 3–6 are durable. Publishing `COMPLETE` before any required
   effect is durable is prohibited.
8. **Admission to subsequent state use.** Only after `COMPLETE` is durable does the
   node open `state_vm_v0` for use and start consensus services.

**Epoch-outcome matrix** (verbs from `evaluate_restore_epoch_compatibility` /
`persist_restored_snapshot_epoch`, `production_consensus_storage.rs:535/619`):

| Snapshot epoch | Live committed epoch | Effect at step 6 | Durability barrier before `COMPLETE` |
|---|---|---|---|
| `None` (missing) | (not read) | `NoEpochToPersist` — **no coercion to zero**, no write | none required; record `expected_epoch=None` |
| `Some(n)` | `None` (present, none committed) | `PersistAfterMaterialization` — write `n` | synced put of `n` (new API) |
| `Some(n)` | `Some(n)` (already matching) | `AlreadyConsistent` — no value change | an **explicit durability barrier** (synced flush of the epoch surface); a successful *read* does **not** prove the value was fsync'd, so the barrier is still required |
| `Some(n)` | `Some(m)`, m ≠ n (conflict) | `RestoreEpochInconsistent` — **refuse** | n/a (refuse) |
| `Some(n)` | read/write/sync failure | `EpochProbeFailed` / I/O error — **refuse** | n/a (refuse) |

Startup decides from **observable on-disk records** only (the single final RTR +
`state_vm_v0` presence + live epoch). Separate what the **writer** must synchronize
from what a **restarting reader** can observe:

* **Writer obligations (§5.9):** before continuing past each step the writer fsyncs
  the copied state, the audit file, and the epoch effect, and publishes each RTR
  atomically (temp → `fsync` → `rename` → dir-`fsync`). A valid `COMPLETE` can be
  published **only** after every prerequisite effect has satisfied its durability
  barrier, because `COMPLETE` publication is the last step (step 7) and is gated on
  steps 3–6 being durable under the selected writer model.
* **Reader observations (startup):** the reader validates the single final record
  actually present; it cannot know whether the previous process received its final
  `fsync` acknowledgment, so it never substitutes that unknowable fact for an
  on-disk observation.

Decisions from the observable final record, under the §5.6 filesystem/storage
assumptions:

* **Valid final `INTENT`:** refuse (interrupted; a pre-`fsync`-loss `INTENT` and a
  genuinely interrupted `INTENT` are indistinguishable and treated identically).
* **Valid final `COMPLETE`:** apply the defined completion-record, destination, and
  required-state checks (§4.5, §4.8); proceed only if they pass.
* **Temporary artifacts** (a staged temp RTR not yet atomically renamed): never
  promoted into completion evidence; their presence does not override the final
  record.
* **Malformed, unsupported, corrupt, or unreadable final record:** refuse
  (fail-closed; kept separate from the normal atomic-publish outcomes).
* **No final record during an interrupted initial intent publication:** use the
  absent-record policy (§4.7), justified by the invariant that protected restore
  mutations cannot begin before durable intent (§5.9 step 2).

For replacement of an already-durable `INTENT` with `COMPLETE` (step 7), a valid old
record (`INTENT`) present with no valid new record ⇒ refuse; a valid new record
(`COMPLETE`) atomically published ⇒ proceed under the checks above. Because
publication is atomic (temp → `rename`), a torn final record is **not** the normal
result of the chosen mechanism; a torn/partial `COMPLETE` is never a valid
`COMPLETE`, and any unexpected corruption of the final record is the separate
fail-closed case above. If restart admission itself requires a durability barrier on
an observed record before acting on it, that operation (e.g. an `fsync` of the RTR
directory on open) and its fail-closed error handling are specified directly, rather
than substituting an unknowable claim about the previous process's acknowledgment.
Finally, these are **specified durability assumptions**, not validated guarantees:
SIGKILL/process-kill tests exercise the interruption ordering and observed-record
behavior but do **not** establish power-loss durability or reveal historical `fsync`
acknowledgments, which remain a separate evidence obligation (§7, §9).

---

## 6. Failure matrix

Durability claims below assume the §5.6 profile; where the profile is not yet
implemented, the "evidence" column names what is required to validate the claim.

| Interruption point | Durable artifacts | Allowed startup behavior | Retry behavior | Evidence to validate |
|---|---|---|---|---|
| Before intent recording | none | Fresh: proceed | With-flag: proceed | Deterministic I/O test (fresh control). |
| During intent create / sync | partial/temp RTR only (no `INTENT` published) | Treat as **absent** → ordinary proceed (empty = fresh, non-empty = ordinary; §4.7) | With-flag: proceed if `state_vm_v0` empty; else `TargetStateNotEmpty` | Process-kill test around RTR publish + `fsync`. |
| During account-state copy/stage | `INTENT` + partial `state_vm_v0` | **Refuse — investigate** | With-flag: refuse occupied | Process-kill test (kill mid-copy); D6-style directory obstruction. |
| During install (rename/finalize of copied state) | `INTENT` + possibly-complete state | **Refuse — investigate** | With-flag: refuse occupied | Process-kill test at finalize boundary. |
| During audit append (incl. partial line) | `INTENT` + partial marker | **Refuse** (marker is not completion evidence) | With-flag: refuse occupied | D6 `d7d6_*` marker-obstruction reuse. |
| Before required epoch persist | `INTENT` (+ state, marker) | **Refuse** | With-flag: refuse occupied | The exact D6 window (`d7d6_a/b/c`). |
| During epoch persist | `INTENT`; epoch possibly written un-synced | **Refuse** | With-flag: refuse occupied | Power-loss evidence for the epoch synced write. |
| After epoch persist, before `COMPLETE` | `INTENT` + all effects present | **Refuse** (not yet `COMPLETE`) | With-flag: refuse occupied | Process-kill test between persist and `COMPLETE`. |
| During `COMPLETE` write / sync | final record is still the durable `INTENT` (temp `COMPLETE` not yet atomically renamed) **or** a fully published `COMPLETE` | `INTENT` observed ⇒ **refuse**; a valid published `COMPLETE` ⇒ **proceed** (apply §4.5/§4.8 checks); a temp/torn `COMPLETE` artifact is never promoted; unexpected corruption ⇒ refuse | With-flag: refuse occupied | Atomic-publish (temp+fsync+rename+dir-fsync) + process-kill test. |
| After `COMPLETE`, before normal startup | valid published `COMPLETE` (recorded `destination_id` matches; `state_vm_v0` present) | **Proceed**; admit restored state (no re-copy, no epoch re-write). No fresh snapshot/nonce exists to compare; historical digest/nonce are provenance (§4.8) | With-flag: **refuse** occupied (no idempotent-success route) | `d7d5_b`-style compatible-restore + subsequent startup. |

Every row decides from the **observable final record** only, per the observable-state
decision list in §5.9: temporary artifacts are never promoted into completion
evidence, and a malformed or corrupt final record is the separate fail-closed case.

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
* **Occupied-target refusal before intent (Correction A):** begin with an ordinary
  non-empty `state_vm_v0`, **no** RTR, and a known account sentinel; supply a valid
  snapshot with compatible epochs so no other gate masks the occupancy check. Assert
  the requested restore refuses with the occupied-target reason
  (`TargetStateNotEmpty`); the account sentinel, logical epoch, audit marker, and
  RTR status are unchanged; the RTR remains **absent**; and a subsequent ordinary
  no-flag startup still proceeds under the ordinary lifecycle (§4.7).
* Epoch matrix: missing (`None`) vs zero (`Some(0)`) vs matching vs conflicting
  (`d7d3_b`, `d7d3_c`, D5 conflict controls) with RTR present.
* Corrupt / stale / mismatched RTR: a wrong `destination_id` (both phases), a
  truncated/garbage record, or an unsupported version ⇒ fail-closed refusal. A
  "wrong `attempt_nonce`" test must name an **active-attempt** comparison that can
  actually occur — the durable `INTENT`/`COMPLETE` of an in-progress attempt versus
  the validated snapshot metadata and attempt nonce that attempt holds — and must
  **not** invent an expected nonce for an ordinary restart, which supplies none
  (§4.8).
* **Normal-node restart** (ordinary node: non-empty `state_vm_v0`, RTR **absent**):
  assert ordinary startup **proceeds** and is **not** treated as an interrupted
  restore (the §4.7 Ordinary-3 case). Untracked empty: assert proceed (fresh).
* **Requested retry over a `COMPLETE` destination:** assert with-flag restore is
  **refused** (occupied) — no idempotent-success route (§4.5).
* **`COMPLETE` with missing `state_vm_v0`:** assert fail-closed refusal and that no
  state is recreated (§4.8.1).

Process-kill tests (SIGKILL at each §6 boundary): assert only `absent`, a valid
final `INTENT`, or a fully-durable valid `COMPLETE` is ever admitted — a torn or
temporary `COMPLETE` artifact is never promoted into completion evidence. These
tests establish observed interruption behavior; they do **not** prove power-loss
durability or reveal historical `fsync` acknowledgments.

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

## 9. Resolved protocol choices and remaining obligations

Following the review, the essential **protocol choices are resolved** (so design
acceptance is not blocked):

1. **Initialization / legacy lifecycle (§4.7, §5.7):** RTR-absence is the ordinary
   lifecycle; ordinary startup proceeds over untracked empty or non-empty
   `state_vm_v0`; interrupted tracked restores are caught by a lingering `INTENT`.
   No operator adoption step is required.
2. **Record identity (§4.1, §4.8):** the digest binds the whole validated
   `StateSnapshotMeta` including `authority_state`/`authority_state_v2`, with a
   versioned, bounded record, defined nonce semantics, and fail-closed
   invalid-record behavior; the digest is an identity binding, not authentication.
3. **Destination lock (§5.5):** a single chosen mechanism — kernel-managed advisory
   `flock(LOCK_EX|LOCK_NB)` on `<data_dir>/restore.lock`, held for the process
   lifetime, auto-released on death.
4. **Durability ordering (§5.9):** a complete ordered sequence with all epoch
   outcomes and preparatory-vs-protected distinction.

**Remaining implementation and durability-evidence obligations** (future work,
which do **not** block design acceptance):

* **Storage-interface change (§5.6, §10):** the synced epoch effect is not exposed
  by the current `ConsensusStorage` API and must be added.
* **Unimplemented code:** the RTR, the startup guard, and the lock are specified
  but not written.
* **Power-loss durability evidence (§5.6, §7):** the synced-write / atomic-publish
  profile is specified but not yet backed by power-loss evidence; `COMPLETE` may
  not be claimed power-loss durable until that evidence exists. SIGKILL tests do
  not substitute for it.

Because the protocol choices are resolved but no code or durability evidence
exists, operational protection is **pending**; the
status is `DEFINED-NOT-IMPLEMENTED` (not `IMPLEMENTED`), and would be `PARTIAL`
only if a protocol choice (lock, initialization/legacy, identity, or durability
ordering) were still unresolved — none is. What remains is implementation and
durability evidence, which are future obligations, not open protocol choices.

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
  * `crates/qbind-node/src/storage.rs` — **required interface change:** add a
    synced epoch effect to the `ConsensusStorage` trait (`:142`, `:188`) — a
    `put_current_epoch_synced` or a `flush_epoch_durable` barrier — implemented on
    `RocksDbConsensusStorage` (`WriteOptions::set_sync(true)` / `flush_wal(true)`)
    and on `InMemoryConsensusStorage`. The present three-file plan cannot provide
    the §5.9 step-6 durability with existing APIs.
* Required new persistent state (only where reuse is insufficient): the RTR
  itself (a single atomically-published file at the destination with the §4.1
  fields and a schema version), plus `<data_dir>/restore.lock` for the §5.5
  advisory lock. Reuse validated `StateSnapshotMeta`, the D5 epoch gate, and the
  D7-C1 observation reader; do **not** reuse the M16 `EpochTransitionMarker` for
  this purpose.
* Complete safety boundary the implementation must establish: every participating
  entrypoint (§5.5.1) acquires the `flock(LOCK_EX|LOCK_NB)` destination lock before
  any authorizing decision; the occupied-target eligibility check runs **before** any
  `INTENT` is created or replaced (§5.9 step 1, §4.3); ordinary startup refuses any
  tracked interrupted (`INTENT`), corrupt, mismatched, foreign, or missing-state
  `COMPLETE`, while proceeding over untracked (ordinary/legacy) destinations; a
  requested restore is refused over any occupied (`INTENT` or `COMPLETE`) destination
  with **no** idempotent-success route; a `COMPLETE` never re-copies state or
  re-writes the epoch (§4.6.1); and `COMPLETE` is never published before every
  required effect is durable (§5.9). Admission and binding differ by phase:

  * **During an active restore attempt**, the durable `INTENT` and its subsequent
    `COMPLETE` are bound to the validated snapshot metadata (the whole
    `StateSnapshotMeta`, both authority fields included; §4.1) and the attempt nonce
    that the attempt holds; wrong-nonce/wrong-snapshot comparisons occur only here,
    against those held values (§4.8).
  * **On ordinary restart**, admission requires a valid, supported, bounded
    `COMPLETE` record whose recorded `destination_id` matches the actual destination
    and whose `state_vm_v0` is present, plus the applicable startup checks. It does
    **not** require equality with a freshly supplied snapshot or nonce (neither
    exists); the historical `snapshot_meta_digest`/`attempt_nonce` are provenance
    fields, not independent freshness or authorization evidence, and the epoch/baseline
    are never rewritten from the historical record (§4.6.1, §4.8).
* No new enablement flag and no implied bypass "behind existing fail-closed
  defaults": the guard is always-on for participating entrypoints; it introduces
  no opt-out.
* Keep separate (do NOT fold in): automatic repair/cleanup of partial
  destinations, anti-rollback, signing-state continuity, and broader recovery
  lifecycle. Do not split the task so it can publish `COMPLETE` before required
  effects are complete.

The code boundary is implementable and testable behind the existing fail-closed
defaults; the remaining §9 obligations are the storage-interface change,
implementation, and power-loss evidence — not open protocol choices.

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