# QBIND Consensus-Recovery / Signing-History Correspondence Contract

**Run:** 422 D7-D11
**Status:** Source audit and protocol definition only. No Rust, test, dependency,
storage key/schema, CLI flag, configuration, workflow, wire-format,
signing-preimage, or activation change is made or proposed for implementation in
this phase. This document *defines* the recovery-admission and
consensus/signing-history correspondence requirements that must hold after an
ordinary restart or a snapshot restoration **before signing may resume**; it does
**not** implement them, does not enable signing, and does not move any readiness
item to Green.

```
D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE          (preserved, not reopened)
D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE (preserved)
D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED          (preserved, not reopened)
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE      (preserved, not reopened)
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

## 0. Ownership and relationship to the continuity contract

This contract is the **authoritative owner** of the *recovery-admission* and the
*consensus-state ↔ signing-history correspondence* requirements: what observable
evidence must exist, and what comparisons must succeed, after an ordinary restart
or a snapshot restoration before a validator may resume signing Proposals / Votes.

`docs/protocol/QBIND_PROPOSAL_VOTE_SIGNING_STATE_CONTINUITY_CONTRACT.md`
(hereafter **the continuity contract**) remains the single authoritative owner of
the **signing-reservation journal** itself — the durable-before-sign invariant, the
conflict rule, the record/state machine, retry/pruning, and the anti-rollback
anchor question. This contract does **not** restate or redefine that journal
specification; it references it and specifies only how the journal's *recovered*
state must be made to correspond with *recovered consensus safety state* before
signing. Where the continuity contract already names a recovery or correspondence
requirement (its §5, §5.2, §5.3, §6.7), those statements remain operative and are
cross-referenced here rather than duplicated; this document supplies the fuller,
source-anchored admission ordering and the per-comparison correspondence table.
No operative statement in the continuity contract is contradicted; the only
reconciliation applied there is the addition of cross-references naming this
contract as the owner of the recovery/correspondence surface.

This contract elaborates requirement **(C) signing / consensus-state continuity**
only (the three-part split **(A) activation authorization**, **(B) current-authority
freshness**, **(C) continuity** is owned by
`docs/protocol/QBIND_PROPOSAL_VOTE_AUTHORITY_LIFECYCLE_CONTRACT.md`). It never
establishes (A) or (B), and no correspondence match defined here authorizes signing.

**Unresolved dependencies (stated up front):**

* **Consensus-lock recovery: UNMET PREREQUISITE.** Neither production recovery
  entrypoint reconstructs the HotStuff `locked_qc` required to enforce the
  safe-vote rule for *future* views on the production snapshot-baseline path, and
  no recovery entrypoint carries an uncommitted-vote / per-view
  anti-equivocation record (§3, §4-Q2, continuity §5.3). A committed height, an
  epoch, or a single valid QC does **not** restore the lock.
* **Signing-history correspondence: NO MECHANISM EXISTS.** Production never opens a
  signing-reservation journal (§3, §4-Q3). There is therefore no local reader that
  compares recovered consensus state against retained signing obligations; the
  comparison inputs this contract specifies do not yet exist in the production
  recovery path.
* **Durable anti-rollback anchor: UNRESOLVED.** No repository mechanism supplies an
  authenticated, rollback-resistant, freshness-bearing commitment outside the
  attacker's rollback domain (continuity §6). A whole-copy rollback is locally
  indistinguishable (§5).
* Design completion of this contract establishes **no** implemented recovery
  protection. C4/C5 remain OPEN. No activation, readiness promotion, or Run 423
  work is authorized or implied.

---

## 1. Inspected revision and reachability inventory

Inspected against the **actual supplied worktree**, not the SHAs the task recites.
This D7-D11 contract was subsequently **corrected** (Corrections A–D below) against
the same worktree source; the source line locators are unchanged because the
correction pass altered only documentation.

* **Working branch (actual):** `copilot/copilotcopilotcopilotrun-422-documentation-only-co`
  (`git branch --show-current`). Used **unchanged**; no rename, rebase,
  force-push, or history rewrite. (An earlier revision of this contract recorded a
  shorter branch string; the branch actually carrying this work is the one named
  here and is used as-is.)
* **Source revision for line locators (full SHA):**
  `5435d22b917d1d078c94b633b18bd28d5802c1a3` (`update`). All Rust source line
  references below are taken against this revision. The D7-D11 documentation that
  this correction pass edits was committed on top of it (`80baf08…`, `update`),
  which changed **only** the three authorized documents; no tracked Rust source
  changed, so every source locator below remains valid against the current
  worktree. The correction pass begins from that documentation commit with a clean
  worktree.
* **Shallow, single-branch clone.** `git rev-list --count HEAD` = 2; only this
  branch is present. Other branches and older history are not fetched.
* **Reference objects named by the task:**
  * Accepted D10 final revision `3d7155eddc09f7071d1af277208a070695aabd66` and the
    reviewed revision `515b531a321163c1e20458c4ccb9fc963863b54a`: **objects absent**
    from this shallow clone (`git cat-file -t` → *could not get object info*); not in
    local ancestry; not referenced by any tracked file.
  * Reported task branch
    `copilot/copilotrun-422-documentation-only-consolidation`: the **actual**
    branch carrying this work is
    `copilot/copilotcopilotcopilotrun-422-documentation-only-co` (used unchanged).
* **Ancestry to an absent object is not manufactured.** For the absent D10 final
  revision, correspondence is asserted only against the *content* of the current
  worktree (the D10 journal/engine/process implementation and its evidence,
  recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` and the continuity
  contract), not against a claimed commit chain. Reachability of reference objects
  is reported here **separately** from content correspondence.
* **Absence findings are scoped to the paths actually inspected** (below). No claim
  is made about paths outside this checkout.

### 1.1 Source references anchoring this contract (worktree HEAD `5435d22`)

All line numbers are against the inspected `5435d22` worktree and are provided as
locators; the symbols, not the exact line numbers, are authoritative. Inspect
current source rather than trusting a line number.

* Engine recovery and safe-vote rule,
  `crates/qbind-consensus/src/basic_hotstuff_engine.rs`:
  * `voted_in_view` (field, ~L317), `proposed_in_view`, `timeout_emitted_in_view`,
    `advance_view` (~L1000), `on_leader_step` (~L1434), `ingest_proposal`
    (~L1720), `on_vote_event` (~L1867), `on_timeout_certificate`
    (lock update when `tc.high_qc.view > locked_qc.view`, ~L2175).
  * `initialize_from_restart` (~L1134): sets committed id/height and `locked_qc`
    from parameters, `current_view = committed_height + 1`, and **resets**
    `voted_in_view = false`.
  * `initialize_from_snapshot_baseline` (~L1201): sets committed id/height,
    `current_view = snapshot_height + 1`, inserts a synthetic baseline block, and
    recovers **no** `locked_qc` (remains `None`).
* Lock / block state, `crates/qbind-consensus/src/hotstuff_state_engine.rs`:
  `locked_qc` (field, ~L173), `set_locked_qc` (~L1144),
  `is_safe_to_vote_on_block` (~L1312, the safe-vote/lock predicate),
  `initialize_from_restart` (~L1190), `initialize_from_snapshot_baseline`
  (~L1254), and the fresh `blocks` map / `vote_accumulator` on recovery.
  `verified_justification` evidence is **non-serialized** and is never restored
  (left `None` after restart/restore).
* **Harness restart**, `crates/qbind-node/src/hotstuff_node_sim.rs`:
  `load_persisted_state` (~L2035, **test-oriented harness**): schema-compat check,
  `get_last_committed`, `get_block`, `get_qc`, and the embedded `block.qc`, then a
  logical lock that the source *comments* call **conservative** — chosen as the
  higher-view of the separately-stored QC and the embedded QC — passed to
  `initialize_from_restart`. **No** QC signature or wire re-verification is
  performed on load; the stored QC is assumed trusted. This reader has **no
  production-startup caller**: the production binary startup path (`main.rs`)
  does **not** invoke `load_persisted_state` (it references neither that method
  nor `AsyncNodeRunner`; see §7A correction). A *compiled* (non-test) wrapper
  does exist — `AsyncNodeRunner::load_persisted_state`
  (`crates/qbind-node/src/async_runner.rs` ~L506) simply delegates to
  `self.harness.load_persisted_state()` — but a compiled harness wrapper is
  **not** evidence that the production binary startup path invokes recovery;
  nothing in `main.rs` constructs an `AsyncNodeRunner` or calls it. Its lock
  reconstruction and whether that lock is *sufficient* for recovery are examined
  in Correction B (§2.1); this audit does **not** establish that the
  reconstructed lock preserves every pre-crash voting restriction — indeed Run
  422 D7-D12 exhibits a concrete case where it does **not** (a candidate whose
  ancestry extends neither locked block is rejected under a stronger advanced
  pre-restart lock and accepted under the lower reconstructed lock; see the D12
  evidence section of the devnet record).
* **Production ordinary startup / restoration**, consensus-loop engine
  construction in `crates/qbind-node/src/binary_consensus_loop.rs` and the
  `main.rs` driver:
  * **Production ordinary startup builds a fresh engine.** The binary consensus
    loop constructs `BasicHotStuffEngine::new(local_validator_id, validators)`
    (~L2492) with no committed-state, lock, or journal input. It does **not** call
    `load_persisted_state` and does **not** restore committed blocks, a
    `locked_qc`, or any signing-journal state into the engine.
  * **Production requested restoration applies a snapshot baseline only.** When —
    and only when — a restore was requested, `main.rs` translates the restore
    outcome into a `RestoreBaseline { snapshot_height, snapshot_block_id }`
    (`main.rs` ~L2865) and the loop conditionally calls
    `engine.initialize_from_snapshot_baseline(snapshot_block_id, snapshot_height)`
    (~L2517). That initializer sets committed id/height from the snapshot meta,
    `current_view = snapshot_height + 1`, inserts a synthetic baseline block, and
    recovers **no** `locked_qc`. The snapshot `block_hash` is reused as an **opaque
    baseline / parent identifier** in the engine's block tree (so documented at
    `main.rs` ~L2860–2864); it is **not** equated with an authenticated historical
    consensus block id, and no pre-snapshot QC / vote history is reconstructed.
  * **Production storage opening is observation, not state restoration.** The
    `main.rs` restore/startup path performs destination-lock acquire (Run 422
    D7-D8), pre-materialization epoch-conflict check
    (`evaluate_restore_epoch_compatibility`, Run 422 D7-D5),
    `apply_guarded_snapshot_restore` (materialization + RTR `Intent`),
    `open_production_consensus_storage` (Run 093) with its schema /
    incomplete-epoch-transition checks, `persist_restored_snapshot_epoch_durable`
    + RTR `Complete` publication (Run 097), then `spawn_binary_consensus_loop`.
    These schema/incomplete-transition/epoch checks and the stored-epoch
    observation **do not themselves restore** committed blocks, a lock, or
    journal state into the engine — they establish storage availability and
    observe a persisted epoch value only. **No signing-reservation journal is
    opened or wired anywhere in production `main.rs`.**
* Guarded signing routes, `crates/qbind-node/src/binary_consensus_loop.rs`:
  `ConsensusVerificationPolicy` (`Required` default / test-only
  `LocalFixtureUnsigned`), `guarded_sign_proposal_for_broadcast`,
  `guarded_sign_vote_for_broadcast` (context → signer → wire-chain → **journal
  availability** fail-closed → required-admission → reserved signing),
  `forward_actions_to_facade`, `do_leader_tick`,
  `maybe_reemit_on_late_peer_connect`. Production wires `current_auth = None` and
  `journal = None`; under `Required` every outbound action is rejected at
  admission before the signing stage.
* Consensus storage, `crates/qbind-node/src/storage.rs`: `trait ConsensusStorage`
  with `get_current_epoch`, `put_current_epoch_synced`, `flush_epoch_durable`,
  `apply_epoch_transition_atomic`, `check_for_incomplete_epoch_transition`,
  `verify_epoch_consistency_on_startup`; block/QC/last-committed/epoch keys; and
  the signing-namespace APIs `get_signing_record`, `put_signing_record_synced`,
  `get_signing_metadata` / `put_signing_metadata_synced`,
  `put_signing_record_and_metadata_synced`, `for_each_signing_namespace_entry`,
  `signing_ownership_domain`.
* Production consensus storage,
  `crates/qbind-node/src/production_consensus_storage.rs`:
  `open_production_consensus_storage`, `ConsensusStorageState`
  (`NoConsensusStorage` / `PresentNoCommittedEpoch` / `CommittedEpoch(u64)`),
  `evaluate_restore_epoch_compatibility`, `RestoreEpochInconsistent`,
  `persist_restored_snapshot_epoch`.
* Restore completion, `crates/qbind-node/src/restore_completion.rs`:
  `RestoreTransactionRecord` (`RtrState::Intent` / `Complete`),
  `snapshot_meta_digest` (SHA3-256 over `StateSnapshotMeta`), advisory
  `restore.lock` flock, strict fail-closed decode. The `COMPLETE` record proves
  only that *this restore attempt's* effects passed their durability barriers; it
  is **not** an anti-rollback or freshness witness and does not prove
  consensus-lock recovery or signing-history freshness.
* Signing-reservation journal,
  `crates/qbind-node/src/signing_reservation_journal.rs`:
  `SigningReservationJournal::{initialize, open}`, `SigningRecordStage`
  (`Reserved` / `Signed`), `ReservationOutcome`
  (`FreshlyReserved` / `ExactRetryRetained` / `Conflict` / `PotentiallySigned` /
  `Exhausted`), `reserve_for_sign` / `consume_for_signing` / `record_signed_result`,
  `SigningOwnershipDomain` (one `Mutex` + process-unique token per backend
  instance; in-process only), `SigningJournalMetadata` (persistent
  `max_reserved_positions` / `reserved_positions` count), and the bounded
  `RecoveredAckCache` (`MAX_RECOVERED_ACK_ENTRIES = 128`, FIFO eviction). On
  reopen it **never** auto-initializes, repairs, deletes, overwrites, resets
  counters, or migrates history; it is fail-closed on missing/legacy/corrupt
  metadata or records; it provides **no** durable anti-rollback or freshness
  property.
* Prior characterization reused as evidence, not re-derived:
  `crates/qbind-node/tests/run_422_d7d2_signing_state_recovery_tests.rs` (D7-D2),
  the D7-D3/D4/D5/D6 binary restore characterizations, and the D10 journal /
  engine / process tests.

---

## 2. Source-backed recovery inventory

Distinguish **exact restoration** (the recovered value is the pre-crash value),
**reconstruction** (a value derived from durable inputs whose *recovery
sufficiency is a separate obligation* — it is **not** assumed to be a safe
lower/weaker bound merely because a source comment calls it "conservative";
see §2.1), **fixture input** (supplied only by a test/harness, not production),
and **unsupported assumption** (no durable channel exists). "Reachability" names
whether the recovery consumer runs in the **production** binary path or only in a
**harness**/test. Three production boundaries are kept distinct: (a) **production
ordinary startup**, which builds a *fresh* engine and restores nothing; (b)
**production requested restoration**, which applies only
`initialize_from_snapshot_baseline` from the supplied snapshot baseline (no lock);
and (c) **production storage opening**, whose schema/epoch checks *observe* stored
values without restoring committed blocks, a lock, or journal state into the
engine.

| State or obligation | Producer / update point | Persistence & durability | Recovery consumer | Verification performed | Prod / harness reachability | Gap |
|---|---|---|---|---|---|---|
| Committed block id | `on_commit` / engine commit; `storage.put_last_committed` | `meta:last_committed`, checksummed | **Harness restart:** `load_persisted_state` → `initialize_from_restart`. **Production requested restore:** `initialize_from_snapshot_baseline` sets committed id from the snapshot meta's opaque `block_hash` | Schema-compat only; decode/checksum | **Harness** restart; **production** snapshot baseline. **Production ordinary startup restores nothing (fresh engine)** | Exact restoration of a *committed id* only (harness); snapshot path carries an opaque baseline id, not an authenticated historical block id |
| Committed height | `block.header.height` of committed block | Embedded in persisted block / snapshot meta | Harness `load_persisted_state` reads `block.header.height`; snapshot from `meta.height` | Decode only | **Harness** restart; **production** snapshot baseline (not ordinary startup) | Exact, but a height is **not** a lock (§4-Q2) |
| `locked_qc` (lock) | `set_locked_qc` on TC / 3-chain progress | Persisted QC (`q:<id>`) and/or embedded `block.qc` | **Harness restart:** `load_persisted_state` picks higher-view of stored/embedded QC → `initialize_from_restart`. **Production snapshot:** `initialize_from_snapshot_baseline` recovers **none**. **Production ordinary startup:** fresh engine, no lock | **No** signature/wire re-verification on load; assumed trusted | Restart reconstruction = **harness only**; production (snapshot and ordinary) recovers no lock | Harness reconstruction's **recovery sufficiency is NOT established by this audit** (§2.1); **absent** on every production path — lock recovery UNMET |
| Uncommitted vote / per-view latch (`voted_in_view`) | Set during `ingest_proposal` vote emission | **Not persisted** | None — reset to `false` on both initializers | — | Lost on every restart/restore | **Unsupported assumption**: no durable channel (D7-D2) |
| Non-committed block tree, `vote_accumulator` | Engine runtime | **Not persisted** | Rebuilt as new proposals/votes arrive | — | Both paths start fresh | In-flight consensus work lost (safe by design, but not a lock) |
| `verified_justification` evidence (D7-C3F) | `on_verified_proposal_event` | **Non-serialized** | Never restored (`None`) | — | Both paths | Evidence must be re-verified on re-admission |
| Current epoch | `apply_epoch_transition_atomic` / restore persist | `meta:current_epoch`, synced; incomplete-transition marker | `open_production_consensus_storage` → `verify_epoch_consistency_on_startup`, `get_current_epoch` | Incomplete-transition marker check; fail-closed | **Production storage opening** (observation) | Exact restoration / observation; coarse — epoch is **not** a lock and **not** a signing-history commitment (continuity §6.3), and observing it does not restore engine state |
| Restore completeness (RTR) | `apply_guarded_snapshot_restore` → `Intent`; Run 097 → `Complete` | `RESTORE_TRANSACTION.rtr`, SHA3-256, fsync + dir fsync; advisory lock | `main.rs` restore path reads/validates RTR | Strict fail-closed decode; digest = integrity only | **Production** (D7-D8) | `COMPLETE` proves *this attempt's* durability only; **not** lock recovery / signing freshness / anti-rollback |
| Signing reservation (`Reserved`) | `reserve_for_sign` before signer | `sig:…` record, synced, checksummed | `journal.open` + `for_each_signing_namespace_entry` | Decode/checksum; accounting vs metadata; fail-closed | **Harness/test only** — not opened in production | No production reader; recovered `Reserved` ⇒ potentially-signed (continuity §5.2) |
| Signing result (`Signed`) | `record_signed_result` after signer | `sig:…` (+signature) + metadata, atomic synced | `journal.open`; `RecoveredAckCache` for exact resend | Decode/checksum; ack barrier; exact-record binding | **Harness/test only** | No production reader; exact reuse retains D10 ack/verify/authorization |
| Journal metadata (limit / count) | `initialize` then atomic advance with each **new reservation** | `sig:meta:v1`, synced, checksummed | `journal.open` accounting validation | Count ≤ limit; version; fail-closed | **Harness/test only** | No production reader; `reserved_positions` advances once per new reservation, not on result publication / ack (§5.1 X2, Correction D) |
| Signing exclusivity (ownership) | `SigningOwnershipDomain` per backend instance | **In-process only** (process-unique token) | Re-created per process open | One `Mutex` serializes supported handles over **one** backend | In-process | Separate directories/hosts each hold their **own** domain; exclusivity does **not** span copies/hosts (continuity §4.2; §7 R10) |
| Timeout / NewView dependency | `on_timeout_certificate` updates `locked_qc` | Lock persisted only via QC, as above | Same as `locked_qc` | As above | As above | Timeout/NewView compatibility is an explicit unmigrated dependency |

**Reading of the inventory.** Production recovery establishes *committed state*
(only when a restore is requested, from the snapshot baseline) and *observes a
coarse epoch* exactly; **production ordinary startup restores nothing and builds a
fresh engine**. A lock is reconstructed **only on the harness restart path** and
that reconstruction's recovery sufficiency is **not established by this audit**
(§2.1); **no** production path recovers a lock, **no** path recovers an
uncommitted-vote record, and production opens **no** signing journal at all. The
correspondence this contract requires therefore has, today, **no production
comparison inputs on the signing side** and an **incomplete safety-state input**
on the consensus side.

### 2.1 The limits of lock reconstruction (Correction B)

The harness `load_persisted_state` reconstruction and the source comments that call
it "conservative" (`hotstuff_node_sim.rs` ~L2088–2090, ~L2114, ~L2123) do **not**
establish that the reconstructed lock preserves every pre-crash voting restriction.
A comment is not a proof. The relevant predicate is
`HotStuffStateEngine::is_safe_to_vote_on_block` (`hotstuff_state_engine.rs`
~L1312), which admits a vote for a candidate block when **any** of:

1. there is no `locked_qc` (returns `true`); or
2. the candidate's `justify_qc.view >= locked_qc.view` (the HotStuff liveness
   condition — a *view comparison*, independent of ancestry); or
3. walking the candidate's registered ancestors reaches `locked_qc.block_id`
   (the candidate extends the locked block).

Lock updates advance `locked_qc` on **every** higher-view QC the engine forms,
**before** any three-chain commit is attempted, and also on
`on_timeout_certificate` when `tc.high_qc.view > locked_qc.view`. Concretely,
`HotStuffStateEngine::on_qc` (`hotstuff_state_engine.rs` ~L995) sets
`locked_qc = Some(qc)` whenever `qc.view > existing.view` and only **then**
calls `try_commit_with_qc` (the three-chain rule). Lock advancement therefore
does **not** require a successful three-chain commit: a QC formed via `on_vote`
raises the lock even when no block is committed. Run 422 D7-D12 exercises this
directly — `d7d12_precrash_lock_advances_via_on_vote_without_a_commit` drives a
quorum through `on_vote`, observes `locked_qc.view` advance, and asserts
`committed_height() == None` (see the D12 evidence section of the devnet
record). The harness `load_persisted_state`, by contrast, selects from the
*committed* block's separately-stored QC and its embedded `block.qc` the
higher-view of the two. Neither of those is guaranteed to equal the pre-crash
`locked_qc`, which may have advanced to a **strictly higher view** via a
timeout certificate or a later QC that the committed block does not
embed. The reconstructed lock can therefore be **lower-view** than the pre-crash
lock.

**Source-level reasoning promoted to executed predicate evidence (Run 422
D7-D12, corrected). Still a predicate result, not a demonstrated network-level
attack.** Run 422 D7-D12 realizes this relationship against actual engine/reader
state as **one coherent fixture sequence** over a single surviving committed
baseline, rather than assumed view numbers. A first harness loads the
committed-height-7 fixture (reconstructed lock `(0x77…, view 7)`); **that same
engine's** lock is then advanced to `(0xB0,20, view 20)` through the real
`on_vote` → `on_qc` transition (using the single-validator harness quorum),
leaving the committed baseline unchanged; a fresh harness over the **same**
storage reconstructs `(0x77…, view 7)`. The two locks differ in **both** block id
and view. The same candidate — ancestry extending **neither** locked block,
`justify_qc.view` = 15 — is evaluated under each. Applying the implemented
condition (2) above:

* Under the **advanced pre-restart** lock (block `0xB0,20` / view 20):
  `15 >= 20` is false, and the ancestor walk does not reach the locked block ⇒
  the candidate **fails** the safe-vote predicate.
* Under the **reconstructed** lock (block `0x77…` / view 7): `15 >= 7` is true ⇒
  the candidate **passes** the safe-vote predicate.

The narrowed, demonstrated statement is therefore: *this candidate, whose
ancestry extends neither locked block, is rejected under the advanced
pre-restart lock and accepted under the reconstructed lock.* This is a measured
`is_safe_to_vote_on_block` outcome
(`d7d12_candidate_rejected_by_precrash_lock_accepted_by_reconstructed_lock`), not
an assumption, and it is **not** a global claim that the reconstructed lock
enlarges the whole permitted voting set: the predicate checks ancestry **as well
as** view, so a lower view with a different locked block does not by itself prove
global set inclusion. The example view numbers quoted previously (10/15/20)
remain illustrative; the executed case uses 7/15/20. A predicate result
establishes **no** emitted vote, **no** signing, **no** facade handoff, **no**
network transmission, and **no** production attack (task §3); other admission,
leader, view, latch, and verified-justification checks still gate any real vote.

**Proof obligation.** Labeling a reconstruction "conservative" does not discharge
safety. For resumption to be safe, either (i) the reconstructed state must be shown
to **preserve the required safety restrictions** (so the permitted voting set does
not grow relative to the pre-crash lock), or (ii) an **independently justified
protocol recovery rule** must establish why resuming from the reconstructed lock is
safe. A QC's validity alone does **not** identify it as the sufficient recovery
lock: being a valid certificate for the committed block is necessary but not
sufficient to show it equals or dominates the pre-crash lock. Pending one of these,
the current harness behavior is labeled **reconstruction whose recovery sufficiency
is NOT established by this audit**, and the "safe/conservative" phrasing is not
treated as a proven guarantee anywhere in this contract.

---

## 3. Safety invariants and explicit trust assumptions

**Invariants the recovery path must preserve (derived from the implemented
consensus rules, not invented):**

* **INV-R1 (fail-closed recovery).** If any required safety evidence is missing,
  malformed, inconsistent, or unavailable, signing does **not** resume. Absence is
  never read as "unused" or "current".
* **INV-R2 (lock before future votes).** Signing may resume only after a
  `locked_qc` sufficient to enforce `is_safe_to_vote_on_block` for future views is
  recovered **and** its recovery sufficiency is established — i.e. a reconstructed
  lock must be shown to **preserve the required safety restrictions** (the
  permitted voting set does not grow relative to the pre-crash lock) or an
  **independently justified protocol recovery rule** must establish why resumption
  is safe (§2.1) — **and** any in-flight signing reservations are present. A
  high-water mark, an epoch, or a single valid QC alone does **not** restore the
  lock, and the harness "conservative" reconstruction's sufficiency is **not**
  established by this audit (continuity §5.3, §6.7).
* **INV-R3 (recovered reservation is potentially-signed).** A recovered `Reserved`
  position with no usable retained result is treated as **potentially signed**: no
  automatic release, no automatic re-signing (continuity §5.2 row 4; D10 preserved).
* **INV-R4 (exact reuse retains D10 obligations).** Reuse of a retained `Signed`
  result is an exact resend only, and still requires D10's acknowledgement,
  record/binding verification, and current-authorization revalidation.
* **INV-R5 (no silent repair).** Recovery performs no automatic journal
  initialization, repair, deletion, overwrite, counter reset, or history migration
  (journal source; continuity §9).
* **INV-R6 (preserve conflict identity and view semantics).** Recovery must not
  introduce a new signing-position namespace or discard obligations to permit
  progress; originating-action view semantics, per-kind field checks, and the
  existing conflict identity (continuity §3.2) are preserved across recovery.
* **INV-R7 (observable-state crash decisions).** Every recovery decision is keyed
  to observable durable state; no decision relies on knowing an unrecorded crash
  location.
* **INV-R8 (local check ≠ activation).** A successful local recovery/correspondence
  check is **not** production activation authorization, authority freshness (B), or
  activation authorization (A).

**Trust assumptions made explicit:**

* **T-FS (filesystem/storage).** `fsync(file)` and `fsync(parent dir)` are honored
  and order/persist writes and renames; there is no silent device rollback. This is
  the stated supported profile (restore-completion §5.6); it is **not** empirical
  power-loss durability.
* **T-INTEG (integrity only).** CRC32 (journal/epoch records) and SHA3-256 (RTR
  digest) provide corruption detection and record-to-input **association** only.
  They are **not** message authentication, authorization, or freshness, and do not
  detect an adversary who rewrites a whole internally-consistent copy.
* **T-TRUST-STORAGE (QC trust on load).** Recovery consumers treat already-persisted
  QCs as trusted and do **not** re-verify their signatures on load. Any future
  design that weakens this assumption must state the re-verification it adds.
* **T-DOMAIN (rollback domain).** Resisting restoration of an older copy requires
  appropriately trusted state/evidence **outside the attacker's rollback domain**
  (a protected local mechanism or a remote witness — neither selected). A
  whole-copy rollback inside that domain is **locally indistinguishable** from a
  valid older state (continuity §6).

---

## 4. The five safety questions, separated

The task's five questions are kept explicitly distinct. Each names what the
recovered evidence can and cannot establish.

1. **Local non-equivocation — can an existing signing position acquire a conflicting
   decision?** Addressed by the D10 journal *when opened*: a recovered position's
   conflict identity is preserved and a conflicting binding at the same originating
   position is REFUSED (continuity §3.2, §5.2). **Scope limit:** this is per-position
   and local; it does not answer Q2, Q3, Q4, or Q5, and in production the journal is
   not opened at all.
2. **Consensus safety after recovery — do future decisions preserve the engine's
   actual locking / safe-vote rule?** **UNMET on every production path** (no
   `locked_qc` recovered on the snapshot-baseline path and none on ordinary
   startup) and, on the **harness** restart path, only *reconstructed* with a
   sufficiency that this audit does **not** establish (§2.1: the reconstructed lock
   can be lower-view than the pre-crash lock, admitting at least one candidate —
   whose ancestry extends neither locked block — that the advanced pre-restart
   lock refused; §2.1 does not establish any whole-set enlargement).
   No uncommitted-vote latch is recovered anywhere (D7-D2). This is the INV-R2
   prerequisite and is **independent** of Q1.
3. **History correspondence — are the restored consensus/account state and the
   retained signing obligations compatible?** **No mechanism exists**: production
   opens no journal, so there is no reader that compares recovered consensus state
   with retained signing obligations. This contract specifies the required
   comparisons (§5); they are not yet implemented.
4. **Freshness and exclusivity — is the local state current, and does this validator
   key have another active copy?** **UNRESOLVED.** No authenticated, rollback-
   resistant freshness anchor exists (continuity §6.6); ownership exclusivity is
   in-process only and does not span copies/hosts (continuity §4.2).
5. **Authorization — is the node currently permitted to sign?** Owned by the
   authority lifecycle contract ((A) activation + (B) freshness). No correspondence
   match here grants it; production already fails closed at admission
   (`current_auth = None` under `Required`).

D10 demonstrably addresses a bounded subset of Q1. It does **not** independently
resolve Q2–Q5. This contract does not assume that a latest journal view, a
committed height, epoch equality, or a single valid QC alone restores the required
lock or establishes correspondence.

---

## 5. Correspondence contract

For each proposed comparison: the two values, their **exact data representation**,
their actual **source**, the recovery **phase**, the **relation** being checked,
the integrity/authentication/freshness assumptions, the **limited conclusion**
available, what remains unproven, and the behavior on a missing / malformed /
inconsistent / unavailable input. **No comparison invents an input that an ordinary
restart does not possess, a record compared with itself is never treated as
independent evidence, and no structural match implies full recovery
compatibility.**

### 5.0 Classification of each item (Correction C)

Each X-item is first classified by *what kind of check it is*, because several are
not defined correspondence predicates today:

* **(a) Existing structural / internal-consistency check** — compares two values
  the opened journal already holds; establishes self-consistency only, never
  freshness or history compatibility. (**X2**.)
* **(b) Operation-specific check requiring independently supplied inputs** — can
  only run when a trusted, independently obtained input (a canonical message /
  domain, or an actual candidate decision with its trusted context) is supplied;
  the stored record alone is insufficient. (**X3**, **X5**.)
* **(c) Unresolved recovery-safety predicate requiring missing evidence** — the
  intended relation is not yet defined and/or the required recovered state is not
  present (no lock on production paths; no reconstructed ancestry); numerical
  relations are observations, not a correspondence verdict. (**X1**, **X4**.)
* **(d) Freshness / exclusivity requirement outside local detection** — depends on
  trusted evidence outside the rollback domain; no local comparison resolves it.
  (The §5.2 whole-copy / copied-key scenarios; partly **X6**.)

### 5.1 Comparison table

| # | Class | Value A (representation) | Value B (representation) | Source & phase | Relation checked | Integrity / auth / freshness | Limited conclusion | Remains unproven | On missing / malformed / inconsistent / unavailable |
|---|---|---|---|---|---|---|---|---|---|
| X1 | (c) unresolved predicate | Recovered `locked_qc` (logical QC: `block_id`, `view`) | Committed block id (`[u8;32]`) / the recovered block tree | Engine recovery; harness restart only (no lock on any production path) | **The intended relation must be stated explicitly** — identity (`locked_qc.block_id == committed_id`), ancestry (committed id is an ancestor of the locked block in the registered tree), or another justified condition. It is **not** a defined predicate today, and the recovered block tree does **not** restore ancestry it did not re-register | Integrity: checksum on persisted QC; auth: **assumed trusted on load** (T-TRUST-STORAGE); freshness: none | At most, that a reconstructed lock is *anchored in* recovered committed state — **not** a correspondence verdict | That the lock equals or dominates the **pre-crash** lock (§2.1); that the tree contains the ancestry the relation would require; every production path has no lock to compare | Refuse to sign (INV-R2); no synthesis of a lock from height/epoch; no assumption of unrestored ancestry |
| X2 | (a) structural | Journal metadata `reserved_positions` (`u64`) | Count of decodable `sig:` records (`usize`) | `journal.open` accounting (both from the **same** store) | Equality of the persisted count and the record count | Integrity: CRC32; auth/freshness: none | Internal journal self-consistency only | Latestness; this is a record-vs-itself check, **not** independent freshness evidence | `AccountingInconsistent` → fail-closed; no repair/reset |
| X3 | (b) operation-specific | A `SigningDecisionRecord`: readable `position` (`validator_id`, `network_genesis`, `kind`, `originating_view`), `stage`, optional `retained_signature`; plus an **opaque** `BindingDigest` (`[u8;32]`) | Independently obtained canonical message/domain evidence for that position | Journal records vs an independently supplied canonical preimage/domain | The **readable** `position` fields may be compared to recovered identity/kind/view; the `BindingDigest` is a one-way SHA3 over the prepared preimage + `authorized_epoch`/`suite_id`/versions/`authority_commitment`/`block_id` and does **not** expose those fields for decoding — a further comparison requires **recomputing** the digest from independently obtained canonical evidence and checking equality | Integrity: checksum; auth: pinned-identity (A/B) is a **separate** obligation; freshness: none | That the retained record's *position* names the same validator/network/kind/view as recovered state; a digest match (only if the canonical inputs are independently supplied) that the prepared decision binds those exact inputs | Epoch/key/authority/block/message cannot be **reconstructed from the digest**; caller-supplied claims are **not** trusted provenance; current authorization; freshness | Refuse in both cases, but record the finding precisely: a **digest mismatch** (independent canonical evidence supplied and it does not match) is **demonstrated non-correspondence**, whereas **absent independent evidence** (no canonical preimage/domain obtained, so the digest cannot be recomputed) is **unavailable evidence** — an *undetermined* comparison, not a proof of non-correspondence. Either requires refusal; neither ever mints a new namespace (INV-R6) |
| X4 | (c) unresolved predicate | Highest retained signing position (`originating_view` of a `Reserved`/`Signed`) | Recovered consensus view / committed height (`u64`) | Journal vs engine recovery | A **numerical** relation (position view vs recovered height/view) — **recorded only as an observation** | Integrity: checksum; freshness: none | Only the raw numerical relation. A journal position **above** the committed frontier can be ordinary uncommitted work; a maximum view cannot establish branch compatibility, complete history, or stale restoration | That either side is current; branch/history compatibility; that the restore is not a same-epoch older copy. Missing evidence stays **unavailable/unestablished** | If required recovery-safety evidence is unestablished, refuse (not because the number "matched" but because safety is not shown) |
| X5 | (b) operation-specific | Recovered `Signed` record (`position`, `BindingDigest`, retained `signature`) | The **actual candidate decision** and its trusted context at that position | D10 exact-reuse path | Exact-reuse eligibility: the candidate decision, rebuilt from trusted context, binds to the same position+digest as the retained result | Integrity: checksum; auth: D10 verification + current-authorization revalidation (INV-R4) | Eligibility for an **exact resend** of that one result — **only** when the candidate decision and its trusted context are supplied | A stored signature + digest **alone do not reconstruct** the candidate decision; authorization/freshness beyond D10's local scope | Refuse reuse; retain the obligation; never re-sign |
| X6 | (b)/(d) active-restore only | RTR `snapshot_meta_digest` (`[u8;32]`) | `StateSnapshotMeta` of the restored input (the **validated snapshot metadata**, available during an **active restore**) | Restore completion (D7-D8) — **active restoration only** | Association of the restored effects with *that* snapshot meta, for attempt binding | Integrity: SHA3-256 association; auth/freshness: **none** (T-INTEG) | During an **active restore**, that the restored effects correspond to *that* snapshot meta | That *that* snapshot is the **latest** authorized state (rollback not detected). An **ordinary restart** need not retain or receive the original snapshot input, so this binding is simply **unavailable** then — its absence is **not** a failure (preserve D8 historical-COMPLETE; §5.3) | Strict fail-closed decode during an active restore; `Invalid` ⇒ refuse. Absent on an ordinary restart ⇒ **not required** |

### 5.2 The specific scenarios the task requires addressed

* **Newer journal retained while older state is restored in the same epoch.** Epoch
  equality does **not** prove freshness. The X4 numerical relation (a retained
  position view at or above the restored frontier) is **only an observation**: it
  can equally be ordinary uncommitted work, so it does **not** by itself establish
  stale restoration. Signing is refused at the covered positions because the
  **required recovery-safety evidence is unestablished**, not because the number
  proves staleness; refusal persists until trusted out-of-domain state resolves
  latestness (continuity §5.2 row 10). Distinguish D10's **per-position** conflict
  refusal (a conflicting binding at one recovered position is refused) from this
  **broader** requirement to refuse *new* signing whenever the required recovery
  safety is unestablished, even where no per-position conflict exists.
* **Newer consensus state retained while journal state is lost or reverted.** A lost
  `Reserved`/`Signed` record relative to newer recovered consensus state is the
  first-use-vs-lost-state ambiguity (continuity §5.1): an empty/older journal must
  **not** be read as "never signed". Refuse (fail-closed) pending trusted evidence.
* **Restoring an internally-consistent older copy of the entire directory.** A
  whole-copy rollback in which every local reference (including the journal and RTR)
  was restored together is **locally indistinguishable** from a valid older state.
  The local reader cannot recognize it; detection depends on appropriately trusted
  evidence outside the specified rollback domain (continuity §6.1/§6.6). This
  contract does **not** claim the local reader detects it and does **not** select an
  anchor.
* **Missing journal metadata vs genuinely authorized first initialization.** A
  missing-metadata/established-records state is `LegacyRecordsWithoutMetadata` /
  `NotInitialized` → fail-closed; it is never auto-adopted. Distinguishing a
  legitimate first initialization from a lost/rolled-back journal requires an
  activation gate (A), not a local inference. This prohibition on silent
  **repair / history replacement** (no auto-init, delete, overwrite, counter reset,
  or migration; INV-R5) is distinct from D10's **permitted** behavior of
  re-acknowledging a **byte-identical** existing record through a fresh synced
  write (an idempotent re-publication of the same retained result, never a content
  change). The accepted D10 uncertainty handling and exact-reuse rules are
  preserved unchanged.
* **Copied validator keys or directories on another host.** `SigningOwnershipDomain`
  is **per backend instance**: supported handles over **one** backend share a single
  in-process coordination domain, but separate directories/hosts each hold their
  **own** domain. Two instances with the same key on separate copies therefore do
  **not** share ownership and are **not** mutually detected locally. The unmet
  requirement is **cross-copy exclusivity** (a fence spanning copies/hosts); local
  ownership does **not** provide or enforce it, and depends on the same unresolved
  out-of-domain evidence (continuity §4.2 / §5.2 row 13).

Checksums and untrusted digests provide integrity/association only; they do not
establish authorization or freshness. Whole-copy rollback remains outside local
detection and is documented as a limitation, not a solved comparison.

---

## 6. Proposed recovery-admission ordering

A proposed admission sequence using existing boundaries where possible. Each stage
names **existing implementation** vs **missing mechanism**. The stages are kept
distinct so that a success at an early stage never short-circuits a later
prerequisite, and so that a local check never becomes production activation.

| Stage | Action | Existing boundary | Missing mechanism | Fail-closed on |
|---|---|---|---|---|
| S1 | Open storage and read state | `open_production_consensus_storage`; `ConsensusStorageState` | — | Schema incompat, incomplete-epoch marker, decode error |
| S2 | Validate / reconstruct consensus safety state | `load_persisted_state` (harness) / `initialize_from_restart`; `initialize_from_snapshot_baseline` | **Production lock recovery** (snapshot path recovers none); **uncommitted-vote recovery** (none anywhere) | Lock not reconstructable; required safety state absent (INV-R2) |
| S3 | Open and validate the established journal | `journal.open`; `for_each_signing_namespace_entry`; metadata accounting | **Production journal open/wiring** (not opened in production today) | `NotInitialized` / `LegacyRecordsWithoutMetadata` / `AccountingInconsistent` / corrupt record |
| S4 | Establish required correspondence | §5 comparisons (X1–X6) | **The X1–X6 predicates *and* their required evidence** — not merely an absent reader. Even a correspondence reader cannot establish correspondence without: X1's resolved pre-crash-vs-reconstructed lock safety predicate (today **unmet** — D7-D12 shows the reconstructed lock can be strictly lower and admit a vote the pre-crash lock refused); X3/X5's **independently-obtained** canonical message/domain evidence and an actual candidate decision (the retained `BindingDigest` cannot be decoded back into its inputs); and the pinned-identity (A/B) and freshness (S5) obligations, which S4 does not discharge | Any §5 non-correspondence; stale-restore indication; **absent independent evidence** (unavailable evidence ≠ demonstrated non-correspondence, but either fails closed) |
| S5 | Establish authorization (A), freshness (B), exclusivity | Authority lifecycle contract; admission gate (`current_auth`) | **Anchor** (freshness/anti-rollback); **cross-host exclusivity** | Missing/invalid authorization; no freshness anchor |
| S6 | Invoke a signer | `guarded_sign_{proposal,vote}_for_broadcast` → reserved signing | — (gated by S1–S5) | Any prior stage unmet |
| S7 | Reuse a retained signature | D10 exact-reuse (`ExactRetryRetained`) | — | Failed D10 verification/ack/authorization (INV-R4) |
| S8 | Hand an action to the facade | `confirm_outbound_before_effect` → facade | — | Confirmation failure (effect suppressed, obligation retained) |

**Ordering rules preserved:**

* **S6 (fresh signing) and S7 (retained reuse) are alternative branches, not a
  sequence.** After the applicable S1–S5 prerequisites, a **fresh** operation
  follows D10's acknowledged reservation, one-use continuation, frozen-operation
  revalidation, signer invocation, checked result publication, and pre-effect
  confirmation. A **retained-result** branch performs the required
  acknowledgement / record-and-binding verification / frozen-operation
  revalidation and pre-effect confirmation with **zero new signer calls** — it
  resends the one retained result and never invokes the signer.
* **The persistent position count advances only on a new reservation.**
  `reserve_for_sign` advances `reserved_positions` by exactly one and writes the
  `Reserved` record + metadata in a single atomic synced write; a `Reserved` and
  its later `Signed` record occupy the **same** position **once**
  (`record_signed_result` overwrites in place at the same key). Result publication
  and recovery acknowledgement do **not** create another position or re-advance
  the count.
* Recovered `Reserved` records remain **potentially signed**: no automatic release
  or re-signing (INV-R3).
* Exact retained-result reuse retains D10's acknowledgement, verification, and
  authorization requirements, and the original-ticket / bound-context / selected-
  signer binding and post-storage revalidation are preserved intact (INV-R4).
* Missing or inconsistent required safety evidence prevents signing (INV-R1/R2).
* No automatic journal initialization, repair, deletion, overwrite, counter reset,
  or history migration occurs during recovery; this is distinct from D10's
  permitted re-acknowledgement of a **byte-identical** record (INV-R5).
* **D8 `COMPLETE` admission is not proof of consensus-lock recovery or signing-history
  freshness.** S2–S5 remain required after a `COMPLETE` restore.
* Crash decisions are based on observable durable state only (INV-R7).
* A successful S1–S4 local recovery check does **not** become production activation
  authorization (INV-R8); S5 remains independent and unmet.

---

## 7. Observable-state failure matrix

Every row is keyed to observable durable state; no row relies on knowing an
unrecorded crash location. Rows marked *(continuity §5.2)* restate an existing
continuity-contract decision for the recovery surface rather than re-deriving it.

| # | Observable durable state | Permitted | Refused | Supporting assumption |
|---|---|---|---|---|
| R1 | Ordinary restart; committed state + reconstructed lock + consistent journal | Resume after S2–S5 satisfied **and** lock-sufficiency established | Signing before lock-sufficiency + correspondence established | Harness restart *reconstructs* a lock whose sufficiency is **not** established by this audit; production paths reconstruct none (§2.1, INV-R2) |
| R2 | Snapshot-baseline recovery; **no** `locked_qc` recovered | Nothing (sign) | All future votes until lock established | Snapshot path recovers no lock (§2) |
| R3 | Recovered `Reserved`, no usable retained result | Retain reservation | Re-sign; release | Potentially signed (INV-R3) |
| R4 | Recovered `Signed` with ack'd retained result | Exact resend after D10 reuse checks, **zero new signer calls** | Re-sign; resend without D10 checks | INV-R4; fresh vs reuse are alternative branches *(continuity §5.2 row 5/6)* |
| R5 | Same-epoch older snapshot + newer journal records | Refuse at covered positions | Signing from stale restored state; **treating the X4 numerical relation as a correspondence match or stale-state verdict** | Refusal is because required recovery safety is unestablished, not because the number "matched"; epoch equality is not freshness (§5.2; X4 observation) *(continuity §5.2 row 10)* |
| R6 | Newer consensus state + lost/older journal | Refuse (fail-closed) | Assuming "never signed" | First-use-vs-lost ambiguity (continuity §5.1) |
| R7 | Internally-consistent whole-directory older copy | Refuse pending out-of-domain evidence | Trusting the restored copy as current | Locally indistinguishable (T-DOMAIN) |
| R8 | Missing / malformed / inconsistent journal or safety state | Refuse (fail-closed) | Auto-init / repair / adopt | INV-R1/R5 (distinct from byte-identical re-acknowledgement) |
| R9 | Missing journal metadata with established records | Refuse (`LegacyRecordsWithoutMetadata`) | Auto-adopt as authorized first init | Needs activation gate, not local inference |
| R10 | Two instances, same validator key / copied directory | At most one holds in-process exclusivity **over one backend** | Both signing; **assuming local ownership enforces cross-copy exclusivity** | Separate copies hold separate ownership domains; **cross-copy exclusivity is UNMET** and not provided locally (continuity §4.2) |
| R11 | Committed-state-only recovery (control) | Resume once S2–S5 met | Treating committed recovery as lock/freshness proof | Committed height is not a lock (§4-Q2) |
| R12 | Later-view decision that would violate the pre-crash lock though it avoids same-position equivocation | Refuse under the recovered/required lock | Signing because no same-position conflict exists | Lock rule, not only non-equivocation (INV-R2/R6; §2.1 example) |

**No structural match implies full recovery compatibility.** A numerical or
record-vs-itself relation (X2, X4) is an observation only; correspondence requires
the operation-specific evidence (X3, X5) or the unresolved safety predicate (X1,
X4) to be independently established.

---

## 8. Future acceptance matrix — not executed here

Future tests only; **no row is a current PASS.** Each names an entrypoint,
artifacts, observable result, the expected refusal/admission boundary, and an
evidence level. Evidence levels are kept separate: *unit/model → real-storage
restart → process-death → release-binary → power-loss → adversarial*. Process
termination is not power-loss evidence; an isolated test signer is not configured
production authority; a CodeQL scope skip is not a security pass.

| # | Scenario | Entrypoint | Artifacts | Observable result | Expected boundary | Evidence level |
|---|---|---|---|---|---|---|
| F1 | Ordinary restart, all required state intact | Recovery parent over real storage | Recovered engine + journal | Resume only after S2–S5 | ADMIT after correspondence | real-storage restart |
| F2 | Recovery after an uncommitted signing decision | Reserve then process-death, reopen | `Reserved` record | Potentially-signed; refuse re-sign | REFUSE (INV-R3) | process-death |
| F3 | Reserved-only recovery; retained-`Signed` exact reuse | Reopen journal | `Reserved` / ack'd `Signed` | Refuse re-sign / exact resend only | REFUSE / ADMIT-RESEND | real-storage + process-death |
| F4 | Same-epoch older snapshot + newer journal | Restore older snapshot, keep journal | Snapshot + `sig:` records | Refuse at covered positions (X4 relation is an **observation**, not a match) | REFUSE because safety unestablished (not because the number matched) | real-storage |
| F5 | Missing / corrupt / inconsistent journal or safety state | Corrupt record / omit metadata / drop lock input | Malformed store | Fail-closed | REFUSE (INV-R1) | unit/model + real-storage |
| F6 | Whole-directory rollback; copied-key | Restore whole older copy; run two copies | Internally-consistent old copy / two keys | Local reader cannot distinguish; refuse on correspondence/exclusivity gap | REFUSE / documented indistinguishability | adversarial (needs out-of-domain anchor) |
| F7 | Harness reconstruction vs production paths | `load_persisted_state` vs `initialize_from_snapshot_baseline` vs fresh ordinary startup | Reconstructed vs absent lock | Harness reconstructs (sufficiency unestablished); production snapshot + ordinary startup recover none | Distinguish paths; REFUSE on production paths | real-storage + release-binary |
| F8 | Lower-view reconstructed lock admits a candidate the advanced pre-restart lock refused (§2.1 example) | Reconstructed lock vs advanced pre-restart lock, future vote | Lock inputs at two identities (block id + view) + candidate with `justify_qc.view` between them, ancestry extending neither locked block | That candidate passes under the reconstructed lock yet fails under the advanced pre-restart lock (narrow; not a whole-set enlargement claim) | REFUSE until lock-sufficiency established (INV-R2/R6) | unit/model |
| F9 | Committed-state recovery control | Normal committed recovery | Committed block + QC | Resume once S2–S5 met | ADMIT (control) | real-storage |
| F10 | Power-loss durability of recovery decisions | Power-cut harness | Durable store | Decisions survive power loss | boundary TBD | power-loss |

---

## 9. Existing vs missing mechanisms, and unresolved prerequisites

**Existing (reusable) mechanisms:**

* Committed-state and (harness-only) lock reconstruction on the **harness** restart
  path (`load_persisted_state` → `initialize_from_restart`), whose recovery
  sufficiency is **not** established by this audit (§2.1).
* Epoch durability and incomplete-transition fail-closed checks
  (`open_production_consensus_storage`, `verify_epoch_consistency_on_startup`).
* Restore-completion containment and its strict fail-closed RTR
  (`restore_completion.rs`, D7-D8).
* The D10 signing-reservation journal's open/validation, fail-closed recovery,
  recovered-`Reserved` = potentially-signed behavior, exact `Signed` reuse, bounded
  recovery-ack cache, and in-process ownership exclusivity.
* Guarded signing routes that already fail closed on a missing journal and on a
  missing current-authorization snapshot.

**Missing prerequisites (not implemented here):**

* **Production lock recovery** on the snapshot-baseline path, and **uncommitted-vote
  / per-view** recovery on all paths (INV-R2; D7-D2).
* **Production journal open/wiring** — the journal is not opened in production, so
  every §5 comparison lacks its signing-side input (Q3).
* **Defined correspondence predicates and their inputs** — X1 and X4 are
  **unresolved predicates** (undefined intended relation / missing recovered
  state), and X3/X5 require independently supplied canonical evidence or an actual
  candidate decision; a correspondence reader that performs X1–X6 (S4) cannot be
  built meaningfully until these are resolved and the journal is opened in
  production.
* **A freshness / anti-rollback anchor** and **cross-copy / cross-host exclusivity**
  (Q4; continuity §6).
* **Authorization (A) + current-authority freshness (B)** wiring (S5; lifecycle contract).

**Unresolved trust assumptions:** T-TRUST-STORAGE (QCs trusted on load without
re-verification), T-DOMAIN (whole-copy rollback locally indistinguishable), and
T-INTEG (checksums/digests are integrity/association only). None are resolved by
this contract.

---

## 10. The single bounded successor task

**Exactly one** smallest justified successor, based on the corrected findings.

**Withdrawal of the previously-proposed observer.** An earlier revision proposed a
read-only *correspondence observer* that would "implement X1–X6 and report an
overall `match / non-correspondence`" from the recovered inputs. That proposal is
**withdrawn**: §5 shows that today X1 and X4 are **unresolved predicates** (no
production lock; undefined intended relation; no restored ancestry), X3 and X5 are
**operation-specific** checks that require independently supplied canonical
evidence or an actual candidate decision the stored record cannot reconstruct, and
X6 binds only during an active restore. An observer cannot produce a *meaningful
overall* correspondence verdict from inputs that do not exist, and a
"non-authorizing" label does **not** compensate for unavailable inputs or undefined
predicates. Proposing it would manufacture a successful-looking comparison.

**Replacement successor (D7-D12 candidate): a bounded source+test characterization
of the existing lock reconstruction and recovery-input loss, using existing
engine/storage interfaces — no new reader, persistence format, freshness interface,
or recovery architecture.**

* **Precise unanswered question.** On the **harness** restart path, can the lock
  reconstructed by `load_persisted_state` be **strictly lower-view** (and a
  different block id) than the pre-crash `locked_qc` (because the pre-crash lock
  advanced via a timeout certificate or later three-chain progress not embedded
  in the committed block), and does that lower reconstruction **admit at least one
  specific candidate** — whose ancestry extends neither locked block — that the
  advanced pre-restart lock refused under `is_safe_to_vote_on_block` (the §2.1
  example)? This is the concrete, bounded form of the Q2 lock-sufficiency gap; it
  is **not** a claim about the whole admitted set.
* **Why this, and whether existing tests already cover it.** D7-D2
  (`run_422_d7d2_signing_state_recovery_tests.rs`) characterizes the
  **uncommitted-vote latch** loss and that the snapshot baseline carries **no**
  lock. Its committed-state recovery control (`committed_state_recovery_control`,
  the `d7d2_c_*` cases) already drives the **real** reader `load_persisted_state`
  and asserts that it recovers the committed baseline **and a QC-derived lock**
  (`locked_qc.view == committed QC height`) from a persisted committed-state
  fixture — that reconstruction is **established prior coverage**, not something
  D12 re-establishes. What D7-D2 did **not** do is compare that reconstructed
  lock against a **stronger pre-crash lock** evaluated with the **same**
  candidate. D7-D12 adds exactly that comparison as **one coherent sequence**: it
  loads a common committed baseline into a first harness, **advances that same
  engine's** lock through the real `on_vote` → QC → `on_qc` transition (using the
  single-validator harness quorum, committed baseline unchanged), evaluates a
  candidate under it, then discards that harness and recovers the baseline lock
  from the **same** surviving storage and evaluates the **same** candidate —
  showing the candidate is **rejected under the advanced pre-restart lock and
  accepted under the reconstructed lock** (both complete lock identities
  reported; plus below-both / at-least-both / unchanged-lock controls). This
  successor is therefore the next missing evidence, not a duplicate, and is
  strictly narrower than a generic anchor (Q4) or a production lock-recovery
  redesign (Q2 implementation).
* **Mechanisms reused (only existing interfaces):** `load_persisted_state` →
  `initialize_from_restart`, the engine's `locked_qc()` accessor and
  `is_safe_to_vote_on_block`, `HotStuffStateEngine::{register_block, on_vote}`,
  `initialize_from_snapshot_baseline`, `observe_consensus_storage`, and the
  storage `put_*`/`get_*` readers and writers — composed in **tests only**,
  asserting both complete lock identities (block id **and** view) and the narrow
  per-candidate predicate consequence (passes/fails), not a whole-set
  enlargement.
  **Isolated fixture setup through the existing storage APIs** (e.g.
  `put_block` / `put_qc` / `put_last_committed` to lay down the surviving
  committed-state fixture, and post-recovery `register_block` of
  explicitly test-supplied candidate/ancestry inputs) is **authorized and
  necessary** — these are test fixture writes, **not** production recovery
  writes and **not** recovery repair. **Excluded:** production wiring, a new
  module, a new reader/persistence format, signer calls, and any recovery-repair
  write.
* **Evidence required for a *safety* conclusion (not produced here):** a proof or
  construction that the reconstructed lock preserves the required restrictions, or
  an independently justified recovery rule (§2.1 proof obligation). The successor
  **characterizes** the gap; it does **not** claim to close it.
* **Explicit exclusions:** the freshness/anti-rollback anchor (continuity §6.6),
  whole-copy/cross-host rollback detection, a production lock-recovery redesign,
  Timeout/NewView migration, opening or wiring a journal in the production signing
  path, any new reader / persistence format / freshness interface / recovery
  architecture, enabling signing, and any activation/readiness change. The
  characterization is **non-authorizing** and reports a bounded observation only.

The successor **has now been executed** as Run 422 D7-D12 (tests +
documentation only); its results, controls, limitations, and exact commands are
recorded in the D12 evidence section of the devnet record
(`docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`). The *safety* conclusion
(§2.1 proof obligation) remains **not** produced: D12 characterizes the gap and
does **not** close it.

---

## 11. Validation performed and retained posture

### 11.1 Checks actually performed (documentation-only)

* **Corrections A–D applied by re-inspection, not restatement.** Correction A
  re-traced the production vs harness recovery boundaries
  (`binary_consensus_loop.rs` fresh `BasicHotStuffEngine::new`; conditional
  `initialize_from_snapshot_baseline`; `main.rs` opaque `block_hash` baseline;
  storage-opening observation). Correction B re-read `is_safe_to_vote_on_block`
  and the harness lock selection and recorded the view-comparison example and proof
  obligation (§2.1). Correction C reclassified X1–X6 and read
  `SigningDecisionRecord` / `BindingDigest` to bound what X3/X5 can read. Correction
  D re-read `reserve_for_sign` / `record_signed_result` / `SigningOwnershipDomain`
  for the position-count, fresh-vs-reuse, and ownership-scope statements.
* Source symbols and call order were re-traced against the `5435d22` source
  (engine recovery, harness `load_persisted_state`, production `main.rs` startup /
  restore, the binary consensus loop engine construction, guarded signing routes,
  storage / production-storage recovery readers, `restore_completion.rs`, and
  `signing_reservation_journal.rs`). Line numbers are locators; symbols are
  authoritative.
* Reference-object reachability was checked with `git cat-file -t`: the accepted
  D10 final `3d7155e…` **and** the reviewed revision `515b531a…` are **absent** from
  this shallow clone and are reported separately from content correspondence;
  ancestry to them is not manufactured.
* Cross-document consistency was checked against the continuity contract (§5, §5.2,
  §5.3, §6 — including the narrow recovery-claim correction to its §5.3 made so it
  no longer calls the harness reconstruction unqualifiedly "conservative"), the
  authority lifecycle contract, the snapshot-restore completion contract, and the
  genesis authority / QC integration audit (inspected read-only).
  `docs/whitepaper/contradiction.md` was inspected read-only; C4/C5 posture is
  unchanged and no ledger edit was made.
* Markdown structure, relative links, and table well-formedness in the changed
  files were reviewed. EOL (CRLF) and the existing no-final-newline EOF convention
  are preserved to match sibling documents.
* No Cargo tests, Clippy, or release rebuild were executed — none are required for
  this documentation-only correction. No historical result is relabelled; fresh
  tool outcomes are recorded literally and separately in
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. A skip, an unavailable
  reviewer, or a "no comments" wrapper does **not** establish completed security
  analysis. The §2.1 reasoning example and the §8/§10 future tests are labeled as
  reasoning / not-yet-executed; no new execution evidence is claimed.

### 11.2 Scoped verdict and retained posture

The corrected contract defines the recovery-admission requirements, the available
evidence, the missing prerequisites, and the unresolved proof obligations (lock
sufficiency, §2.1; the undefined X1/X4 predicates and the operation-specific
X3/X5 inputs, §5) **without** asserting any unsupported safety guarantee. On that
basis — not merely because all sections exist — design completion of this contract
establishes **no** implemented recovery protection, and the token is:

```
D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED
```

Preserved unchanged (not reopened):

```
D7D10_LOCAL_SIGNING_RESERVATION=CODE-AND-STORAGE-TEST-POSITIVE
D7D10_CORRECTION_F_ENGINE_PROGRESS_AND_CHILD_RECOVERY=CODE-AND-PROCESS-TEST-POSITIVE
D7D9_SIGNING_STATE_CONTINUITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7D8_RESTORE_COMPLETION_CONTAINMENT=CODE-AND-RELEASE-TEST-POSITIVE
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. No production signing enablement, readiness promotion, or
Run 423 work is authorized or implied by this contract.