# QBIND Consensus-Recovery / Signing-History Correspondence Contract

**Run:** 422 D7-D11 (extended by D7-D13 — consensus safety-state durability, § 12; D7-D14 — recoverable safety-record design, § 13)
**Status:** Source audit and protocol definition only. No Rust, test, dependency,
storage key/schema, CLI flag, configuration, workflow, wire-format,
signing-preimage, or activation change is made or proposed for implementation in
this phase. This document *defines* the recovery-admission and
consensus/signing-history correspondence requirements that must hold after an
ordinary restart or a snapshot restoration **before signing may resume**; it does
**not** implement them, does not enable signing, and does not move any readiness
item to Green.

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED            (RUN 422 D7-D14; see § 13)
D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED   (RUN 422 D7-D13; see § 12)
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
| Current epoch | `apply_epoch_transition_atomic` / restore persist | `meta:current_epoch`; incomplete-transition marker. `apply_epoch_transition_atomic` writes the epoch in an **unsynced** `WriteBatch` (`db.write`, no `set_sync`) — atomic among co-located keys, **not** a durability barrier; only the D7-D8 restore-completion path uses the **explicit synced** epoch operation/barrier (`put_current_epoch_synced` / `flush_epoch_durable`) | `open_production_consensus_storage` → `verify_epoch_consistency_on_startup`, `get_current_epoch` | Incomplete-transition marker check; fail-closed | **Production storage opening** (observation) | Exact restoration / observation; coarse — epoch is **not** a lock and **not** a signing-history commitment (continuity §6.3), and observing it does not restore engine state |
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

**Successor status (RUN 422 D7-D13).** This D12 successor is now a **historical
completion**; the single smallest justified *next* successor — a bounded source +
test characterization that the in-memory lock raise has **no durability channel**
today — is defined in § 12.7, which is the authoritative owner of the D13
requirements. No second competing successor is proposed.

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

---

## 12. RUN 422 D7-D13 — Consensus safety-state durability and recovery-ordering contract

This section extends this recovery contract — its **authoritative owner** — with
the **durability boundary for the consensus safety restriction itself** (the
HotStuff lock and its supporting QC/TC evidence) relative to dependent signing,
and the ordering obligations that follow. It is **documentation-only**: no Rust,
test, dependency, storage key/schema, persistence format, wire format, CLI flag,
configuration, workflow, signing-preimage, or activation change is made or
proposed for implementation here. No competing contract is created; the
continuity contract receives only cross-references and a scope reconciliation.

```
D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
```

**What D13 adds beyond D11.** D11 (§5–§7) owns recovery-admission *ordering* and
the *correspondence* table; the continuity contract §4.1 owns the
durable-before-sign boundary for the signing **reservation**. D13 adds the
distinct, **earlier** boundary: *when the in-memory safety restriction changes,
when its supporting material must become durable, which dependent operations must
block before that point, and how a future implementation must bind a signed
decision to the safety state that justified it.* Every statement below is
labelled **implemented behavior**, **proposed requirement**, or **unresolved
proof/trust obligation**. Nothing here enables signing, moves a readiness item to
Green, or authorizes Run 423 work.

### 12.1 Source-backed safety-state transition inventory

Line numbers are locators against the inspected worktree; the **symbols** are
authoritative. "Durability obligation" is a **proposed requirement**, not an
implemented write.

| State / transition | Actual source / caller | Safety use | Current persistence / recovery | Proposed durability obligation | Limitation |
|---|---|---|---|---|---|
| QC formation → lock raise | `HotStuffStateEngine::on_vote` (`hotstuff_state_engine.rs` ~L952) → private `on_qc` (~L995) — reached from the `BasicHotStuffEngine` entrypoints `on_vote_event` (~L1867) / `ingest_proposal`'s `self.state.on_vote` (~L1817); `on_qc` sets `locked_qc = Some(qc.clone())` at ~L1004 when `qc.view > existing.view`, **before** `try_commit_with_qc` (~L1013). (`on_vote` is the `HotStuffStateEngine` method; `on_vote_event` is the distinct `BasicHotStuffEngine` method — they are **not** one combined symbol) | Raises the lock enforcing `is_safe_to_vote_on_block` for future views | **In-memory only** at this point. A QC becomes *stored* only when separately written (`q:<id>`) or embedded in a later committed block (`put_block`/`put_qc`/`put_last_committed`) — but those are **ordinary `db.put` writes with no `WriteOptions::set_sync`**, so storing a QC or a committed block persists bytes **without** establishing the required **acknowledged sync** durability barrier (§12.5) | Before any signing that relies on the raised restriction, the supporting QC must be durable **and** recoverable *as the lock* | **Implemented:** the raise is immediate and **not** itself persisted. A lock advanced via `on_vote` **without** a commit has **no** durability channel; recovery reconstructs only the committed-embedded/stored QC (D12) |
| TC lock update | `BasicHotStuffEngine::on_timeout_certificate` (`basic_hotstuff_engine.rs` ~L2162) → `set_locked_qc(tc.high_qc)` when `tc.high_qc.view > locked_qc.view`, **before** the `current_view` advance | Lock inherited into the new view | TC is **not** persisted as a lock input; only its embedded QC, if later stored | Same as the QC row: a TC-derived raise needs a durable, recoverable supporting QC | Timeout/NewView durability is **unmigrated** (explicit gate) |
| Lock replacement mechanism | `set_locked_qc` (~L1144) **assigns directly** (`self.locked_qc = Some(qc)` ~L1145) with **no** view check inside the setter | The write point of the restriction | — | — | The strictly-higher-`view` guard is enforced by the **callers** (`on_qc` ~L1000; `on_timeout_certificate` when `tc.high_qc.view > locked_qc.view`), **not** by the setter. A higher view is **not** the same claim as exact lock identity (§2.1) |
| Safe-vote predicate | `is_safe_to_vote_on_block` (~L1312): admits when (no lock) **or** `justify_qc.view >= locked_qc.view` **or** the ancestor walk reaches `locked_qc.block_id` | **The actual restriction** — classify: *enforces a restriction* | Evaluated against the live/recovered lock + registered tree | The recovered state must preserve this predicate for future views (§12.2) | A view comparison and an ancestry comparison are **different** claims |
| Per-view vote latch | `voted_in_view` (`basic_hotstuff_engine.rs` field ~L317; **reset** in both initializers ~L1148/§2) | Per-view anti-equivocation | **Not persisted**; lost on every restart/restore (D7-D2) | A future per-view/uncommitted-vote record (not designed here) | No durable channel exists today |
| Originating action view | `on_leader_step` (~L1434) captures `view = self.current_view` at ~L1443 and sets `header.height = view` / `round = view` at ~L1503–1504; `ingest_proposal` reads `view = proposal.header.height` (~L1732). `current_view` advances separately (`advance_view` ~L1000) | The action binds to its **construction** view, not a later `current_view` | The wire message carries the construction view immutably; the engine may advance afterward | A future implementation must associate the signed decision with the safety state in force **at that route's own decision/eligibility point** (not a later transition produced while processing the same event) (§12.3) | **Implemented:** action types carry only header fields; they do **not** carry the lock/evidence that justified the decision |
| Committed id/height + lock on recovery | `initialize_from_restart` (~L1134 basic / ~L1190 state); `initialize_from_snapshot_baseline` (~L1201 basic / ~L1254 state, recovers **no** `locked_qc`) | Committed baseline; harness-only lock reconstruction | Reuse §2 inventory | Reuse §2/§2.1 (lock-sufficiency unestablished; absent on production paths) | Cross-ref §2.1; D12 |
| Verified-justification evidence | `verified_justification` (non-serialized; never restored, `None`) | Supports **verification**, not the restriction | Not persisted | Must be **re-verified** on re-admission | Cross-ref §1.1 |
| Signing-reservation durability | `reserve_for_sign` writes `Reserved` + metadata in **one atomic synced write** before the signer; `record_signed_result` overwrites in place; `reserved_positions` advances **only** on a new reservation | Durable-before-sign linearization (continuity §4.1 step 4) | `sig:` namespace, synced, checksummed (harness/test only; not opened in production) | The §12.3 safety-state frontier must precede this reservation | Cross-ref continuity §4.1 / §9; D10 preserved |

**Field classification (not every in-memory field is equally safety-critical).**

* **Enforce a safety restriction:** `locked_qc` (block id **and** view) and the
  per-view `voted_in_view` latch (per-view non-equivocation). These gate whether a
  vote is permitted.
* **Support verification / ancestry:** the QC/TC certificate bytes, the
  validator/authority + network/genesis context needed to interpret them, the
  registered block tree / ancestry walked by the predicate, and
  `verified_justification`. These let the restriction be *checked*, but are not the
  restriction.
* **Support scheduling / liveness:** `current_view`, `proposed_in_view`,
  `timeout_emitted_in_view`, `vote_accumulator`. These drive progress, not a safety
  restriction — with the one qualification that `current_view` must not be reset in
  a way that **relaxes** the restriction (§12.2); a high `current_view` is **not**
  itself a lock.

### 12.2 Protected safety state and the preservation requirement

**Minimal logical contents** for the proposed recovery profile, each justified by
an actual consumer:

* **Lock block id *and* lock view** (`locked_qc` identity). Consumer:
  `is_safe_to_vote_on_block` — the ancestor walk uses the **block id**, the
  liveness condition uses the **view**. Exact identity and a higher view are
  **different** claims.
* **The certificate / evidence supporting the lock** (the QC, or the TC plus its
  `high_qc`). Consumer: the trust-on-load assumption (T-TRUST-STORAGE) or any
  future recovery re-verification. A block-id/view pair **alone** restores neither
  verification evidence nor ancestry.
* **Network/genesis and validator/authority context.** Consumer: interpreting the
  QC signer set and threshold; without it the certificate is uninterpretable.
* **Committed-state association.** Consumer: anchoring the lock in recovered
  committed state (§5 X1).
* **Required block/header/ancestry material.** Consumer: the ancestor walk. The
  **locked block identity + view** must be present **at startup**; candidate
  ancestry may be **supplied and checked per candidate**. Missing candidate
  ancestry must **never** become assumed ancestry.
* **View material needed to avoid an unjustified reset.** `current_view` must not
  be lowered into a range that relaxes the restriction; but a view value alone is
  not a lock.
* **Relationship to outstanding D10 signing obligations.** A recovered `Reserved`
  is potentially-signed (INV-R3); the lock profile neither releases nor discharges
  it.

**Preservation rule (stated as a recovery decision, not a pre-crash comparison).**
A restarted process **cannot** observe the pre-crash lock, so the resume rule must
**not** be phrased as a runtime comparison against it. Two distinct things are kept
separate:

* **Runtime resume decision (what a recovered process may evaluate).** Signing may
  resume only when the recovered **durable** safety state is self-consistent and,
  **for each evaluated candidate**, establishes `is_safe_to_vote_on_block` from
  observable recovered inputs alone — the recovered lock identity + view, its
  supporting certificate/context, and the **per-candidate** ancestry supplied and
  checked. The decision is made against **what is durably present**, never against a
  remembered volatile value.
* **Design-level proof obligation (what the chosen recovery rule must satisfy once,
  off-line).** The rule by which that durable state is produced/reconstructed must be
  shown — as a design argument, not a per-restart check — to preserve the pre-crash
  restriction. This is the §2.1 obligation and it is discharged **by one of two
  relations**, not by a numeric "dominance":
    * **(i) Exact lock restoration** — the durable state restores the **same** locked
      block identity and view established by the last transition that became
      **effective** (durable and acknowledged) pre-crash. This is the **selected**
      profile (§12.3 selection; profile (a)). It is **not** claimed to be the *only*
      reachable observable outcome: a transition whose supporting record reached
      storage **before** the former caller received the durability acknowledgement or
      installed it in memory can **survive** the crash (§12.3 surviving-write case).
      Recovery is therefore defined over the **observable durable record** — restore
      the last effective lock, or complete a valid surviving published transition —
      never over a remembered volatile value or an assumed acknowledgement; or
    * **(ii) An alternative restriction-preservation relation** — an independently
      justified recovery rule proving that the reconstructed lock admits **no**
      candidate the pre-crash lock would have refused. This relation is evaluated
      per candidate against **supplied** evidence (the candidate's `justify_qc` and
      registered ancestry); where that evidence is absent the candidate is refused
      (candidate-scoped), and where the relation itself is unproven signing is
      refused generally.

None of the following is sufficient **by itself**: committed height; current
epoch; highest journal position; a valid QC; a higher lock view; D8 `COMPLETE`; a
checksum or digest. A higher lock **view** is **not** automatically a stronger
restriction, and block identity carries **no** numerical "dominance"; "higher means
safer" and "conservative" are **not** accepted as a rule. Between (i) and (ii) this
pass **selects (i)** — exact restoration from a durable, recoverable
safety-restriction record (the §12.3 profile (a)) — because the existing
committed-QC reconstruction has the **demonstrated D12 gap** (it can admit a
candidate the pre-crash lock refused) and relation (ii) has **no** supplied
construction or preservation proof. The selection and its justification are recorded
in §12.7. It fixes the recovery **rule**; no safety-state persistence interface
exists today, so the overall design remains **DEFINED-NOT-IMPLEMENTED** (§12.8) and
the single remaining successor is the implementation-design of that record (§12.7).

**Absence classification** — whether an absence blocks startup, signing generally,
or only the affected candidate:

* Missing **lock identity + view** at startup → blocks signing **generally** (and
  the future-vote path) until established (INV-R2).
* Missing **supporting certificate / context** → blocks signing **generally**
  (the lock cannot be interpreted or verified).
* Missing **candidate ancestry** → blocks **only the affected candidate** (refuse
  that candidate; never assume the ancestry).

Do **not** require retaining the entire block tree: the profile needs the locked
block identity + view, the supporting certificate/context, and **per-candidate**
ancestry as supplied. Conversely, a block-id/view pair alone does **not** restore
verification evidence or history.

### 12.3 The durability boundary before dependent signing (protected frontier)

**Selected ordinary-crash profile (a) — recoverable safety-restriction record
(conservative; PROPOSED, not current behavior).** This pass **selects** this profile
(§12.2 relation (i); §12.7) as the frontier rule: an effective lock transition is
backed by a **durable, recoverable safety-restriction record** (lock identity + view
and its supporting QC/TC evidence and context), rather than relying on the
committed-QC reconstruction that carries the demonstrated D12 gap. A lock transition
is treated in two stages:

* **pending** — the engine has computed a higher-view QC/TC but its supporting
  material is **not yet** durable and acknowledged;
* **effective** — the supporting material is durable and acknowledged, and only
  then is the raised restriction treated as **installed** for admitting dependent
  signing.

Under this profile **no signing decision may depend on a pending transition**:
while a transition is pending, the reserve/sign/retain/confirm steps for any
decision that relies on the newly raised restriction remain **blocked**. The
**linearization point** is the **acknowledged-durable** publication of the record and
its supporting evidence; at that point the raised restriction becomes **irrevocable**
and only then may dependent signing proceed. A recovered process never reconstructs
or compares against a remembered volatile pending transition; it decides from the
**durable record alone** (§12.2 runtime rule).

**Two crash sub-cases, decided by observable inputs (not by the volatile label).**
The labels *pending* / *effective* exist only inside the live process; a restarted
process **cannot** observe them, nor whether the former caller received the write
acknowledgement or installed the transition in memory. It observes only the
**surviving durable record**. Two sub-cases follow:

* **Crash before any supporting record is durable.** Nothing of the new transition
  survives; no dependent signature was admitted (it was blocked); recovery resumes
  from the last **effective** (durable) lock with no lost obligation. *This* is the
  case the earlier draft described.
* **Crash after some or all of the record reached storage, before the
  acknowledgement or in-memory install.** A (possibly partial) record **survives**.
  Renaming the transition "pending" does **not** prove its record may be discarded:
  if a **valid, complete** supporting record survived, recovery **completes** that
  published transition (treats it as effective); an **incomplete, malformed, or
  mismatched** publication is **refused** (frontier not reached). The decision is
  made from the record's observable completeness, never from an assumed
  acknowledgement — a readable byte is **not** an acknowledged write (INV-R7).

Because exact pre-crash restoration is therefore **not** the only reachable outcome,
the surviving-write schedule and compact matrix below define recovery for every
observable case, and §12.5's D13 rows are reconciled to them.

**This is a proposed design, not current behavior.** Current engine mutation is
**immediate**: `on_qc` (~L1004) and `on_timeout_certificate`'s `set_locked_qc`
install the raise in memory with **no** staging and **no** durable write. The
profile does **not** claim the engine already stages transitions.

**Missing integration boundary (named).** There is today **no** integration point
between the engine's in-memory lock mutation (`on_qc` / `set_locked_qc`) and a
durable safety-record write, and **no** "pending vs effective" gate on dependent
signing. Supplying that boundary is a **proposed requirement**, not an existing
mechanism; **which production rule supplies it is now selected — profile (a), a
recoverable safety-restriction record (§12.7)** — but the record's implementation
design and the persistence interface do **not** exist yet (§12.5), so the boundary
remains proposed, not implemented.

**Per-route ordering (source-backed; replaces a single uniform sequence).** "Durable"
means an acknowledged barrier, not a readable byte. Each production route has its
**own** decision/eligibility point, and the state present when a message object is
**constructed** is not necessarily the state that **justified** the decision:

* **`BasicHotStuffEngine::ingest_proposal` (~L1720).** Decision point:
  `is_safe_to_vote_on_block` at ~L1810, evaluated against the lock **before** the
  self-vote. It **then** ingests the local self-vote (`self.state.on_vote` ~L1817),
  which **may form a QC and raise the lock**, and **only afterward** constructs the
  outgoing `Vote` (~L1829). The vote object can therefore reflect a higher lock than
  the one that justified it. A self-vote-generated QC **must not** retroactively
  justify that same vote.
* **`BasicHotStuffEngine::on_leader_step` (~L1434).** Decision point: parent /
  justification selected from `locked_qc()` (~L1450–1461) and the `Proposal`
  constructed (~L1498) **before** the self-vote (`self.state.on_vote` ~L1538). The
  returned actions (proposal + vote) may therefore **span an internal lock/view
  transition** generated while processing the step.
* **Externally received vote/QC processing (`on_vote_event` ~L1867).** A received
  vote may form a QC and raise the lock; any emitted action binds to the originating
  view, not to the post-QC lock.
* **`on_timeout_certificate` (~L2162).** `set_locked_qc(tc.high_qc)` raises the lock
  **before** the `current_view` advance; a later view value must not relabel an
  earlier action.
* **D10 fresh signing vs retained reuse.** Fresh signing (S6): reserve
  (`reserve_for_sign` synced, continuity §4.1 step 4) → sign (`signer.sign_*`) →
  retain (`record_signed_result` synced; `result_acked` only after the
  acknowledgement) → confirm (`confirm_outbound_before_effect`; a later confirmation
  cannot undo a completed signature). Retained reuse (S7): resend the one retained
  `Signed` with **zero** new signer calls. Both branches require the §12.2/§12.3
  safety-state prerequisites **before** external signing or reuse.

**Proposed association with the justifying decision point.** For every route a
future implementation must bind the signed decision to: its **originating action
view** and the **exact decision inputs** (candidate block id, `justify_qc`,
ancestry); the **safety state and evidence used for that decision** (the lock in
force at the decision point, not a later one); **any later lock transition generated
while processing it** (recorded as such, never used to re-justify the decision); and
the **durability prerequisites** (the protected frontier) before external signing or
reuse. **Absent today:** action/operation representations carry **only** header
fields and do **not** carry the lock/evidence that justified the decision; no such
binding exists and none is introduced in this pass.

**Protected frontier.** Before any dependent signing (reserve onward) that relies on
a **newly raised** restriction, that restriction's supporting material must be
**durable and recoverable as the lock**; the **protected frontier** is the
acknowledged-durable point of that material, and the reserve/sign/retain/confirm
steps for a decision justified by the raised restriction remain **blocked** before
it. Today there is **no dedicated, acknowledged safety-state durability channel**: a
lock is only **incidentally** recoverable by reconstruction from committed state (a
committed block's embedded/stored QC, itself written by ordinary `db.put` without a
sync barrier), so a lock raised via `on_vote`/TC **without** a commit has no such
incidental persistence and is lost on recovery (D12). A volatile observation that **no** admitted signing decision depends on does
not require its own persistence, but under the profile it is simply never treated as
effective, so it cannot **relax** the restriction on recovery (§2.1).

**Write failure / uncertain acknowledgement.** On a write failure or an uncertain
acknowledgement of the supporting material, dependent signing does **not** proceed
(fail-closed); a successful **read** of bytes is **never** treated as acknowledged
persistence (INV-R7).

**Surviving-write / lost-acknowledgement case (the schedule §5 requires closed).**
Consider the concrete schedule under profile (a):

1. The effective lock is **L0**.
2. The engine computes a transition toward **L1**.
3. Some or all of the proposed L1 record and its supporting evidence reach storage.
4. The process crashes **before** receiving the write acknowledgement, or before
   installing L1 in memory.
5. A fresh process reads the surviving records.

The restarted process **cannot** observe whether the former caller received an
acknowledgement; it observes only durable records. Exact restoration of the
pre-crash **effective** lock is therefore **not** the only reachable outcome — a
valid surviving L1 publication may be present — and any statement to the contrary
is corrected here. A **readable** valid record is **not** evidence that a previous
acknowledgement was received; conversely, loss of acknowledgement knowledge is
**not** proof the write never persisted. Recovery is decided from the observable
inputs below (the illustrative schedule above is kept **separate** from these
recovery inputs):

| # | Observable input (profile (a)) | Decision |
|---|---|---|
| SW-1 | No new authoritative L1 record; prior established L0 state valid | Resume from **L0** after S2–S5 and the frontier (no new transition to complete) |
| SW-2 | Incomplete, malformed, or mismatched L1 publication | **Refuse** the transition (frontier not reached); fail-closed (INV-R7). The refusal blocks **both** protected signing **and** retained-result reuse that would depend on L1. "Keep L0" means **preserve the existing durable evidence**, not permission to fall back to L0 and **continue signing**; do **not** delete, repair, overwrite, or discard the problematic publication to regain progress. (SW-1's valid-prior-state case is unaffected — absence of a new transition is **not** corrupt or missing required established state.) All shared recovery / authorization / freshness / exclusivity / D10 gates stay intact |
| SW-3 | Valid, complete surviving L1 record, **no** process-local acknowledgement knowledge | **Complete** the published transition as effective **only after** the recovery durability operation below confirms it; until then, dependent signing stays blocked |
| SW-4 | Recovery durability operation **succeeds** | L1 is effective; dependent signing may proceed through the remaining gates |
| SW-5 | Recovery durability operation **fails or remains uncertain** | **Refuse** (fail-closed); do **not** treat the readable L1 bytes as effective |
| SW-6 | Valid safety state, **no** new D10 reservation recorded | **Not** itself unsafe (D13-12/G8): proceed to the remaining checks; synthesize no reservation |
| SW-7 | Recovered D10 `Reserved` | Potentially-signed (INV-R3); **refuse** re-sign |
| SW-8 | Recovered D10 `Signed` | Exact resend only, **zero** new signer calls (INV-R4) |

**Recovery durability operation (PROPOSED; interface does not exist today).**
Completing a surviving L1 (SW-3→SW-4) requires a **safety-state durability operation**:
a synced (acknowledged) re-publication of the L1 safety-restriction record and its
supporting evidence, whose **protected effect** is that L1 is treated as effective
only after the acknowledged barrier. Its **failure behavior** is fail-closed (SW-5):
on error or uncertainty, L1 is not admitted and signing does not proceed. **No such
safety-state API exists today** — it must **not** silently reuse the epoch-specific
(`put_current_epoch_synced`, `flush_epoch_durable`) or D10 journal-specific synced
APIs, which keep their own contracts (§12.5). A plain **read** of the surviving bytes
is **not** this operation.

**Originating-action semantics (proposed integration requirement, source-backed).**

* Actions **may be constructed before the engine advances** (`on_leader_step`
  builds the proposal with the view captured at L1443; `advance_view`/timeout
  change `current_view` independently).
* A returned action **must not be relabeled** using a later `current_view`; the
  wire `header.height`/`round` are fixed at construction (L1503–1504).
* A later safety-state snapshot **must not retroactively authorize** an earlier
  decision.
* **How a future implementation would bind the decision to its justifying safety
  state:** carry, alongside the reserved position, the **originating view** and a
  reference to the lock/evidence in force **at that route's decision point** (the
  lock that justified the vote/proposal, **not** a later self-vote-generated
  transition), and revalidate that at the durable reservation — **not** re-derive it
  from `current_view`.
* This is a **proposed** requirement. Current action types carry **only** header
  fields; they do **not** already bind the justifying lock/evidence, and no claim
  is made that they do.

**Latency / throughput (qualitative).** The durability barrier can add a wait
before dependent signing. Batching is permissible **only if** the required
acknowledgement still **precedes** the protected effect; any optimization that
would weaken the accepted preservation requirement is **excluded** pending
justification. No performance figures are given (none measured).

### 12.4 Integration with D10 (semantics unchanged)

The §12.2 preservation rule and the §12.3 protected frontier sit **before** D10's
reservation (continuity §4.1 step 4). D10's accepted properties are **preserved
unchanged**: the canonical signing-position identity; prepared-preimage binding;
one-use operation-bound continuation; backend-shared ownership over supported
handles; the frozen ticket/context/signer; post-storage authorization
revalidation; checked result publication; exact retained-result verification and
recovery acknowledgement; recovered `Reserved` treated as potentially-signed;
uncertain publication suppressing delivery; and no release/reset to regain
progress.

**Fresh signing vs retained reuse are separate branches.**

* **Fresh signing (S6):** the §12.2 preservation rule and the §12.3 durability
  boundary are **prerequisites** to the reservation and signer, in addition to
  D10's own acknowledged reservation and revalidation.
* **Retained reuse (S7):** resends the one retained `Signed` result with **zero
  new signer calls** — but it does **not** bypass recovery admission. The
  fresh-signing rule is **not** automatically sufficient for resend, and resend is
  still gated by the §12.2/§12.3 prerequisites and D10's acknowledgement /
  record-and-binding verification / current-authorization revalidation (INV-R4).

**BindingDigest limitation.** The journal's opaque `BindingDigest` cannot
reconstruct a canonical message, authority context, or block history (§5 X3). Any
comparison needs **additional** inputs: an **independently obtained** canonical
preimage/domain **and** the pinned validator/authority context (trusted source:
the authority-lifecycle (A/B) obligations and the genesis identity) — **not** the
digest and **not** caller-supplied claims. The withdrawn generic "correspondence
observer" is **not** reintroduced, and no global match is manufactured from
unavailable evidence.

### 12.5 Storage, initialization, uncertainty, and recovery decisions

**Prefer existing mechanisms.** Synced writes (`put_*_synced`,
`flush_epoch_durable`), the atomic-batch model (`apply_epoch_transition_atomic`),
and the block/QC writers (`put_block`/`put_qc`/`put_last_committed`) are the
reuse surface. **Concrete missing interface:** there is **no** production API that
durably records *the safety restriction currently in force* as a recoverable
record **distinct from** a committed-embedded QC; today the lock is reconstructed
from committed state only on the harness path and **not at all** on production
paths. A signing-scoped safety record would be **new** (it is **not** claimed to
exist).

**Storage atomicity vs durability (source-verified; they are different
properties).**

| Operation | Atomicity scope | Requested durability semantics | Current caller / use | Applicability / missing interface |
|---|---|---|---|---|
| `put_block` / `put_qc` / `put_last_committed` (`storage.rs` ~L815/~L874/~L929) | Single key each (`db.put`); **separate** ordered ops, not one transaction | **Ordinary write** — no `WriteOptions::set_sync`; the `Ok(())` return is **not** an acknowledged synchronous durability barrier | Commit-path block / QC / last-committed persistence | Reusable for the bytes, but ordering three separate puts is **not** a cross-artifact atomic transaction and gives **no** durability barrier |
| `apply_epoch_transition_atomic` (`storage.rs` ~L1110) | Same-database `WriteBatch` (block + QC + last_committed + epoch + marker-delete) via `db.write` | **Atomic batch only** — its `db.write` (~L1163) does **not** request sync; atomicity ≠ durability barrier | Epoch transition | Atomic **among co-located keys in one DB**; data outside the batch is **not** covered |
| `put_current_epoch_synced` (`storage.rs` ~L1042) | Single key (`put_opt`) | **Synced** — `WriteOptions::set_sync(true)`; acknowledged barrier over the epoch key | D8 restore-completion epoch | An actual durability barrier — epoch key only |
| `flush_epoch_durable` (`storage.rs` ~L1071) | WAL (`flush_wal(true)`) | **Durability barrier** over previously-written epoch surface; no value change | D8 "already consistent" outcome | Barrier only; epoch surface only |
| D10 `reserve_for_sign` / `record_signed_result` | Single synced record + metadata write | **Synced**, acknowledged (`result_acked` only after ack) | Signing reservation / result (harness/test; **not** opened in production) | Explicitly synced; the §12.3 safety-state frontier must precede these |
| **Durable safety-restriction record** (lock + supporting QC/context) | — | — | — | **No such interface exists** — would be new, with its own atomicity + ordering relative to D10 writes |

An **atomic batch** and a **durability barrier** are different properties, and
**ordered separate operations are not a cross-artifact atomic transaction**. The
epoch-specific (`put_current_epoch_synced`, `flush_epoch_durable`) and D10
signing-journal APIs keep their **own** contracts; their existence does **not**
establish a safety-state persistence API. If required supporting data lives
**outside** one atomic batch, the necessary publication/recovery protocol must be
**specified as a proposed requirement** or the case marked
**unsupported/unresolved**; ordering alone is **not** claimed to provide atomicity.

**Field roles (engine guards vs durable protection).** The in-engine
proposal/vote guards — `voted_in_view` (per-view anti-equivocation) and
`proposed_in_view` (per-view leader dedup) — provide **real in-process** protection,
but it is **volatile**: both are reset in every initializer and lost on
restart/restore (D7-D2). D10's durable reservation is the **durable** protection at
the signing boundary. Neither is "irrelevant" to safety; they protect at different
layers. This section does **not** prescribe duplicating the same fact in two stores
without a stated justification — any proposed safety record persists the **lock**
restriction, not a re-copy of D10's reservation.

Requirements for such a (future, not-designed-here) record: bounded/versioned
record + evidence; canonical interpretation + context binding; **atomicity** among
a safety record and its required supporting QC/context (a same-database **atomic
batch** where co-located; where they **cannot** be co-located, a **specified
publication/recovery protocol** that makes partial publication detectable and
recoverable — ordered separate writes are **not** a cross-artifact atomic
transaction and do **not** satisfy this requirement); ordering so
the safety record is durable **before** the dependent D10 reservation/result
writes; single-writer ownership with no assumed concurrent updater; explicit
**first initialization** versus **opening established** state; **fail-closed** on
malformed / missing / unsupported / inconsistent state and on write-before-error /
uncertain acknowledgement; and retention/pruning **only after** the safety
obligation is discharged. A local record revision or counter is **bookkeeping, not
an anti-rollback anchor.** No transaction framework, second journal, authority
registry, or freshness service is invented to state these requirements.

**Observable-state recovery matrix (D13 safety-state frontier).** Each row is
keyed to observable durable state; none infers an unrecorded crash location or a
lost acknowledgement from readable bytes.

| # | Observable durable state | Decision |
|---|---|---|
| D13-1 | Valid required safety state + consistent established journal | Resume after S2–S5 **and** the §12.3 durability boundary is met |
| D13-2 | Missing required safety state, existing journal | **Refuse** (INV-R1/R2) |
| D13-3 | Safety state present but journal missing / unusable | **Refuse** (fail-closed) |
| D13-4 | Incomplete safety-record / supporting-evidence publication | **Refuse** (frontier not reached) |
| D13-5 | Write-outcome uncertainty — attributed by phase (not a former caller's lost acknowledgement) | A **live** operation that observes its **own** failed or uncertain write fails closed **then** and admits no dependent signing. A **restarted** process cannot observe whether a former caller received an acknowledgement, so it does **not** refuse on that unobservable basis; it decides only from observable inputs — recovered record validity/completeness (D13-4/D13-13) and the outcome of its **own** current recovery durability operation (D13-14 success / D13-15 fail-or-uncertain; §12.3 SW-3…SW-5). A readable byte is **not** an acknowledged write (INV-R7) |
| D13-6 | Recovered `Reserved` | Potentially-signed; **refuse** re-sign (INV-R3) |
| D13-7 | Retained `Signed` | Exact resend only, **zero** new signer calls (INV-R4) |
| D13-8 | Safety state **ahead of** the committed baseline | Being ahead is **not** itself a refusal reason — a valid durable lock ahead of committed state can be legitimate uncommitted work (exactly the state this contract preserves). Distinguish: (a) **validated** safety state with the required correspondence established → **may proceed** to the remaining checks; (b) **missing evidence** needed to establish correspondence → **refuse** because the evidence is **unavailable** (not because of a numeric relation; §5 X4); (c) **demonstrated inconsistency** → **refuse**. An unavailable comparison may require refusal, but the reason is the **unavailable evidence**, never a number "matching" |
| D13-9 | Same-epoch older snapshot | **Refuse** (epoch equality ≠ freshness; §5.2) |
| D13-10 | Internally consistent whole-copy rollback | **Locally indistinguishable**; refuse pending out-of-domain evidence (T-DOMAIN) |
| D13-11 | Historical D8 `COMPLETE` with later legitimate progress | `COMPLETE` must **not** reapply old epoch/baseline; S2–S5 still required |
| D13-12 | Valid durable safety state + established journal, but **no** new reservation recorded (crash after safety persistence, before reserving) | **Not** itself an unsafe observable condition. The recovered safety state and established journal are both available; under the selected local ordinary-crash model the operation **may proceed** to the remaining checks (S2–S5, the §12.3 frontier, and D10's reservation/conflict gates). No reservation is synthesized; D10's reservation/conflict rules and all independent authorization/freshness gates are preserved |
| D13-13 | Valid, complete surviving **new** safety record, **no** process-local acknowledgement knowledge (crash after the record reached storage, before ack/install; §12.3 SW-3) | **Complete** the published transition **only after** the recovery durability operation confirms it; until then dependent signing stays **blocked**. A readable record is **not** a received acknowledgement, and exact pre-crash restoration is **not** assumed to be the only outcome |
| D13-14 | Recovery durability operation **succeeds** (§12.3 SW-4) | The surviving transition is **effective**; proceed through the remaining gates |
| D13-15 | Recovery durability operation **fails or remains uncertain** (§12.3 SW-5) | **Refuse** (fail-closed); never treat readable bytes as effective (INV-R7) |

**Lost acknowledgement vs observable records (separate these).** A restarted
process **cannot** directly observe that a former caller lost an acknowledgement; it
observes only durable records. Four conditions are kept distinct: **live in-process
uncertainty** (only meaningful before the crash); **recovered valid records**;
**absent or malformed records**; and **inconsistent supporting evidence**. Readable
valid state does **not** prove an earlier acknowledgement, and a successful **read**
is **not** acknowledged persistence (INV-R7). If recovery requires an **additional
durability operation** (e.g. a synced re-publication after an uncertain write), its
required semantics and whether the interface exists must be **named** — a read alone
is **not** that operation — and it must be performed, not assumed.

**Common gates for every "may proceed" / "resume" row.** Each admitting row above is
additionally gated by the shared recovery/authorization prerequisites: the S2–S5
sequence (validated safety state → established journal → required correspondence →
authorization (A) / freshness (B) / exclusivity), the §12.3 protected frontier, and
the INV invariants. **Fresh signing and retained reuse remain alternative
branches:** a recovered **retained `Signed`** permits only the exact reuse allowed
by D10 — **zero** new signer calls plus all applicable recovery checks — while a
recovered **`Reserved`** remains **potentially signed** (INV-R3). No automatic
repair, initialization, deletion, history replacement, or reservation release is
introduced by any row.

### 12.6 Trust and scope boundaries (stated separately)

* **Accidental corruption detection** — CRC32/SHA3-256 (T-INTEG): integrity /
  association only.
* **Cryptographic certificate verification** — **separate**; **not** performed on
  load today (T-TRUST-STORAGE). A logical QC with an **empty signer list** is
  **not** retained authentication evidence. If the profile requires recovery-time
  verification, it requires the **certificate bytes + trusted validator/authority
  context**, not comments or fixture acceptance.
* **Local storage integrity assumptions** — T-FS (fsync honored; no silent device
  rollback); the supported profile, not empirical power-loss durability.
* **Current authorization (A)** and **current-authority freshness (B)** — owned by
  the authority-lifecycle contract; no correspondence/durability check here grants
  them.
* **Ordinary crash consistency** — the **only** property the §12.3 boundary
  provides.
* **Whole-copy rollback resistance** — **UNMET** (T-DOMAIN; locally
  indistinguishable).
* **Copied-key / cross-host exclusivity** — **UNMET**; ownership is in-process over
  one backend only (§5.2; §7 R10).

Timeout/TC paths are **inventoried** (they affect locks) but **not** redesigned;
Timeout/NewView compatibility is **not** claimed solved — it remains an explicit
gate. First-use ambiguity stays explicit: a genuinely new directory and a
lost/rolled-back state can be **locally indistinguishable**, and this is **not**
resolved by silently initializing missing established state. No local checksum,
digest, synced write, or ownership mutex establishes whole-copy freshness or
cross-host exclusivity. D8 restore completion remains **separate** from consensus
safety and signing-history correspondence.

**Contradiction ledger (read-only).** `docs/whitepaper/contradiction.md` was
inspected read-only; the relevant remaining contradiction — durable anti-rollback
**NOT-established** and C4/C5 **OPEN** — is **unchanged** by this section, and no
edit was made to it.

### 12.7 Future acceptance matrix (not executed) and one successor

Future tests only; **no row is a current PASS.** Evidence levels are kept
separate: *unit/model → real-storage → process-death → release-binary →
power-loss*. Process termination is not power-loss; an isolated signer is not
configured production authority.

| # | Scenario | Expected boundary | Evidence level |
|---|---|---|---|
| G1 | The accepted D12 candidate restriction across the proposed recovery path | REFUSE until lock-sufficiency + frontier established | unit/model + real-storage |
| G2 | Unchanged-lock preservation (no raise since last durable point) | ADMIT after S2–S5 (control) | real-storage |
| G3 | Lock **identity** vs **view-only** comparison | REFUSE a view-only "match"; require identity + restriction | unit/model |
| G4 | Missing required ancestry / evidence | REFUSE (candidate-scoped vs general per §12.2) | unit/model + real-storage |
| G5 | QC-derived lock-update durability | REFUSE dependent signing before the supporting QC is durable | real-storage |
| G6 | TC-derived lock-update durability | REFUSE dependent signing before the supporting QC is durable | real-storage |
| G7 | Recovery at a surviving-write / pre-barrier boundary (crash before the safety-state durability barrier was acknowledged) | Decide from observable inputs, not from an unobservable former acknowledgement: incomplete / malformed / mismatched / unavailable required publication → REFUSE; a valid surviving publication grants **no** protected use before the required **current** recovery durability barrier; that barrier **succeeds** → proceed only through the remaining S2–S5 / frontier / D10 prerequisites; the barrier **fails or remains uncertain** → REFUSE (fail-closed). A valid safety state with no new reservation is **not** inherently unsafe (preserve G8 / D10). An illustrative crash location may frame the test schedule but must **not** become an input to the restarted process | process-death |
| G8 | Interruption **after** safety persistence but **before** a new reservation | **ADMIT** to the remaining checks — this interruption is **not** itself unsafe; the durable safety state + established journal are available and the operation proceeds to S2–S5 / D10 gates (no reservation synthesized) | process-death |
| G9 | Interruption **after** reservation and after possible signing | Recovered `Reserved` = potentially-signed; REFUSE re-sign | process-death |
| G10 | Retained-result reuse without a new signature | ADMIT exact resend only (D10 checks); zero signer calls | real-storage + process-death |
| G11 | Missing / corrupt established state | REFUSE (fail-closed) | unit/model + real-storage |
| G12 | Unchanged D10 conflict obligations across the frontier | REFUSE a conflicting binding at the same position | unit/model |
| G13 | Ordinary restart vs snapshot restore | Distinguish paths; REFUSE where no lock is recovered | real-storage + release-binary |
| G14 | Rollback cases that remain locally undetectable | Document indistinguishability; REFUSE on the correspondence/exclusivity gap | adversarial (needs out-of-domain anchor) |

**Historical completion note (replacing the §10 D12 successor).** The §10
successor — the bounded source+test characterization comparing the
`load_persisted_state` reconstruction against a stronger pre-crash lock with the
same candidate — **has been completed** as Run 422 D7-D12 (tests + documentation
only). Its results, controls, and limitations are recorded in the D12 evidence
section of `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`; the §2.1 *safety*
proof obligation remains **not** discharged. D12 already **executes** the sequence
*lock advancement without commitment → unchanged stored baseline → reconstruction of
the older lock* and also retains the distinct standalone no-commit test
(`committed_height() == None`); re-proposing that sequence would therefore be a
**duplicate** and is **not** the successor below.

**Frontier decision — RESOLVED in this pass (profile (a) selected).** The §12.2/§12.3
frontier rule is **no longer open**: this pass **selects profile (a)** — a durable,
recoverable **safety-restriction record** persisted at each **effective** lock raise,
carrying the lock identity + view and its supporting QC/TC evidence and context, with
a stated atomicity + ordering rule relative to D10's reservation/result writes. It is
selected over the relation-(ii) reconstruction rule (profile (b)) for two reasons:
(1) the existing committed-QC reconstruction has the **demonstrated D12 gap** — it can
be strictly lower-view and admit a candidate the pre-crash lock refused; and (2)
relation (ii) is admissible **only** with an actual construction, required inputs, and
a preservation argument, and **none** is supplied (a higher view, a valid QC, a
committed height, an epoch, or a checksum is **not** that argument). Profile (a)
closes the gap by making the effective restriction **itself** recoverable rather than
inferring it from committed state. The selection fixes the recovery **rule**; it does
**not** implement it (no such API exists today — §12.5), so the scoped token stays
**DEFINED-NOT-IMPLEMENTED**.

* **Selected profile (a) — record contents and obligations (design level).**
  * **Publication unit:** the safety-restriction record (lock block id + view)
    **plus** its supporting certificate (the QC, or the TC and its `high_qc`) and the
    network/genesis + validator/authority context needed to interpret it; a
    block-id/view pair alone is insufficient (§12.2).
  * **Atomicity:** the record and its required supporting evidence must be published
    atomically where co-located (a same-database atomic batch); where they cannot be
    co-located, a **specified publication/recovery protocol** must make a partial
    publication detectable and recoverable — ordered separate writes do **not**
    satisfy atomicity (§12.5).
  * **Ordering:** the safety record is durable (acknowledged) **before** the
    dependent D10 reservation/result writes and before any signer call (§12.3
    protected frontier; continuity §4.1).
  * **Recovery:** decided from observable durable records only (the §12.3
    surviving-write matrix and the §12.5 D13 rows), with the PROPOSED safety-state
    durability operation completing a valid surviving transition and fail-closing on
    failure/uncertainty.
  * **Not fixed here:** the concrete logical record layout, the non-co-located
    cross-artifact protocol, the first-initialization-vs-open semantics, and the
    retention/pruning rule — these are the single successor below. Profile (a) also
    does **not** discharge the independent anti-rollback anchor (continuity §6.6).

**Exactly one justified successor (unstarted): specify profile (a)'s record at
implementation-design granularity.** With the frontier *rule* selected, the one
genuinely remaining design gap is turning profile (a) into an implementation-ready
logical specification — **still documentation-only**, no code.

* **Question / missing mechanism.** Define, for the selected safety-restriction
  record: the **logical record layout** (bounded/versioned fields + evidence
  binding); the **cross-artifact publication/recovery protocol** for the case where
  the record and its supporting QC/context cannot share one atomic batch (making
  partial publication detectable), or mark that case **unsupported**; the explicit
  **first initialization vs opening established** semantics; and the
  **retention/pruning** rule (only after the safety obligation is discharged). No
  safety-state persistence API exists today (§12.5).
* **Why it is distinct.** It neither re-opens the (a)/(b) choice (resolved here) nor
  re-runs the D12 characterization (completed); it specifies the record whose *rule*
  is now fixed.
* **Anticipated files / evidence level.** The three authorized documents only
  (design/specification); **no** code, **no** promoted acceptance row, **no**
  unit/model execution.
* **Prerequisites.** This §12.7 selection; the §12.1 inventory; the §12.5
  atomicity-vs-durability table; continuity §4.1/§6.6.
* **Strict exclusions.** No implementation; no new module/reader/persistence
  format/freshness interface; no signer calls; no recovery-repair write; no
  **anchor selection**; no new characterization tests; no activation/readiness
  change. Local ordinary-crash consistency stays **separate** from whole-copy
  rollback resistance; the independent **anti-rollback anchor remains unresolved**
  and is **not** part of this successor.

**Material decision status (updated).** The (a)/(b) choice — a dedicated recoverable
safety record at each lock raise versus an independently justified reconstruction
rule — was the material decision; it is now **made: (a)** (justified above). What
remains is the implementation-design specification named as the single successor and
the **separate**, still-unresolved anti-rollback **anchor** (continuity §6.6), which
profile (a) does **not** discharge. The §12.2/§12.3 **frontier-rule disposition is
RESOLVED**; the record remains **DEFINED-NOT-IMPLEMENTED** because no persistence
interface exists yet, so the design is **not** implementation-ready and no activation
is permitted.

### 12.8 Validation performed and retained posture

* **Source re-traced against the checkout** (symbols authoritative; line numbers
  are locators): `on_qc` sets `locked_qc` at ~L1004 **before** `try_commit_with_qc`
  at ~L1013; `on_leader_step` captures the view at ~L1443 and fixes
  `header.height`/`round` at ~L1503–1504; `is_safe_to_vote_on_block` (~L1312);
  `on_timeout_certificate` `set_locked_qc` before the view advance;
  `initialize_from_restart` / `initialize_from_snapshot_baseline`;
  `reserve_for_sign` / `record_signed_result` ordering.
* **Provenance (this frontier-resolution pass).** Actual branch
  `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotc-again` (the task's
  reported branch `copilot/copilotcopilotcopilotcopilotcopilotcopilotcopilotr`
  differs; the **actual** branch is used **unchanged** — no
  rename/rebase/force-push/history rewrite). Starting HEAD
  `fd6a167b99bfe1ce511c10f0be2c1f9eefba5118`; clean worktree before this pass. The
  task's reviewed revision `9b56dc04ae5d989afef6fee6cdf1ddf172867652` **is** available
  here (fetched on demand): `git cat-file -t` → `commit`, and its tree content is
  **identical** to the starting worktree (`git diff --stat 9b56dc04 HEAD` empty), yet
  it is **not** an ancestor of HEAD (`git merge-base --is-ancestor` fails). Content
  correspondence is therefore reported **separately** from ancestry, and ancestry is
  **not** manufactured from content equality. The final pushed SHA is the last commit
  on the branch (recorded in the devnet D13 entry).
* **Cross-document consistency** checked against D10/D11/D12 (this contract) and
  the continuity contract (§4.1, §5.3, §6), which receives only a cross-reference /
  scope reconciliation. `docs/whitepaper/contradiction.md` inspected read-only; no
  edit. CRLF line endings and the existing no-final-newline EOF convention are
  preserved; `task/warning.txt` and unrelated work are untouched.
* **Tooling.** Available review/security tooling was attempted once; the literal
  outcome is recorded in the D13 evidence section of
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. No Cargo/Clippy/release
  rebuild was run to produce new counts; no historical tool outcome is relabelled
  as a fresh execution.

On that basis — not merely because the sections exist — this section **defines**,
and does **not** implement, the consensus safety-state durability and
recovery-ordering requirements as a coherent, source-backed scoped contract. The
**frontier-rule decision is now RESOLVED**: profile (a) (a recoverable
safety-restriction record) is **selected and justified** (§12.2/§12.7), the
surviving-write / lost-acknowledgement case is closed by observable inputs
(§12.3/§12.5), the decision binding is per-route (not construction-time), and the
storage atomicity/durability/publication requirements are mutually consistent — so
the frontier **design** is coherent. What remains is **implementation** (no
safety-state persistence interface exists — §12.5) plus the implementation-design
specification named as the single successor (§12.7) and the **separate**,
still-unresolved anti-rollback **anchor**; the scoped-contract token below therefore
stays DEFINED-NOT-IMPLEMENTED and is **not** a claim of implemented protection,
empirical durability, independent approval, or activation:

```
D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
```

Preserved unchanged (not reopened):

```
D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. No production signing enablement, wiring, activation, readiness
promotion, or Run 423 / D14 work is authorized or implied by this section.

## 13. RUN 422 D7-D14 — Recoverable consensus safety record (profile (a) implementation-design specification)

This section is the **single §12.7 successor**, executed as **documentation-only**
design. It turns the D13-**selected** profile (a) — a durable, recoverable
**safety-restriction record** published at each *effective* lock raise — into an
implementation-ready **logical** specification: the record contents, the
publish/open/read/recover operations, the ownership/concurrency rules, the engine
and D10 binding, and the retention/capacity policy. It does **not** re-open the
(a)/(b) choice (resolved in §12.7) and does **not** repeat D12. No Rust, test,
dependency, actual storage key/schema, concrete serialized persistence/wire format,
signing preimage, CLI, configuration, workflow, production wiring, or activation
change is made or proposed for implementation. Logical types and interface
contracts are proposed in prose/pseudocode only; the concrete byte framing (magic,
offsets, encodings) is deliberately **left to the implementation successor** (§13.9).

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED
```

**What D14 adds beyond D13.** §12 fixed the frontier **rule** (when the restriction
must be durable, which dependent operations block, how recovery decides from
observable inputs). §13 fixes the **record and its operations** at component level:
exactly one supported storage/publication arrangement, the bounded field set with a
named consumer for every field, the distinct initialize/open/read/publish/
re-acknowledge operations with their uncertainty behavior, the ownership rules that
serialize them, the per-route engine/D10 binding, and the retention/capacity policy.
Every statement is labelled **implemented behavior**, **proposed requirement**, or
**unresolved proof/trust obligation**. Nothing here enables signing, moves a
readiness item to Green, discharges the anti-rollback anchor, or authorizes Run 423.

### 13.1 The one bounded supported profile (and the five excluded properties)

**Supported arrangement (initial profile — PROPOSED).** The safety-restriction
record **and all of its required persisted supporting material** (the lock identity +
view, the supporting QC — or TC and its `high_qc` — and the network/genesis +
validator/authority context identifier) live **co-located in the one canonical
consensus database** (the same RocksDB instance that already holds blocks/QCs/epoch
state) and are made visible in **one atomic publication unit**. The publication unit
is a **single same-database `WriteBatch`** (the atomicity model of
`apply_epoch_transition_atomic`, `storage.rs` ~L1110) committed with
`WriteOptions::set_sync(true)` — i.e. one `db.write(batch, sync)` that is **both**
atomic over its keys **and** an acknowledged durability barrier. The **atomic-plus-sync
pattern already exists**: D10's `put_signing_record_and_metadata_synced`
(`storage.rs` ~L1417) commits a multi-key `WriteBatch` with `WriteOptions::set_sync(true)`
via `db.write_opt(batch, &write_opts)` — atomic over its keys **and** `fsync`-acknowledged
in one call. (`apply_epoch_transition_atomic`'s `db.write` ~L1163 is atomic but not
synced, and `put_current_epoch_synced` ~L1042 is synced but epoch-only; the combined
pattern is **not** absent — D10 already demonstrates it.) What does **not** exist today
is a **safety-state-specific** interface built on that pattern, with the
safety-record **validation and single-writer ownership** integration (§13.5); supplying
**that** interface is the **proposed requirement**. The safety record must **not** be
routed through the epoch API or the D10 signing API — it reuses the atomic-plus-sync
**pattern** on its own keys, not those APIs.

**Explicitly unsupported in the initial profile.** **Non-co-located** publication —
the record in one store and its required supporting evidence/context in another, or
split across two atomic units — is **unsupported**. A cross-store arrangement would
require a cross-artifact publication/recovery protocol making partial publication
detectable and recoverable; no such protocol is essential to the single-database
deployment, so **none is invented** here (no distributed-transaction framework, no
second journal, no two-phase commit). If a future deployment genuinely cannot
co-locate, that protocol must be specified then, or the arrangement stays
unsupported; this is stated, not silently assumed away.

**Local writer / ownership and storage assumptions (stated).**

* **Single local writer.** Exactly one process on one host owns the canonical
  database and performs all safety-record writes; there is **no** assumed concurrent
  external updater. Multiple in-process handles are serialized by the owner (§13.5).
* **Filesystem / storage (T-FS, reused).** `fsync` is honoured and the device does
  **not** silently roll back acknowledged writes; this is the **supported profile
  assumption**, not an empirical power-loss or anti-rollback claim. Whole-copy
  rollback and copied-database reuse are **out of scope** (below).

**Six properties distinguished; only the first three belong to this record.**

| # | Property | In this record? | Where it lives |
|---|---|---|---|
| 1 | **Atomic visibility** — the record and its supporting evidence become visible together or not at all | **Yes** | The single-`WriteBatch` publication unit (§13.5) |
| 2 | **Acknowledged durability** — a returned success means an `fsync`-acknowledged barrier, not merely a readable byte | **Yes** | `set_sync(true)` on the batch write (§13.5); INV-R7 |
| 3 | **Validation of record contents and transition eligibility** — structural decode + bounds + association + safe-vote eligibility | **Yes** | Read/validate + publish operations (§13.4/§13.5) |
| 4 | **Authorization and current-authority freshness** (A/B) | **No** | Authority-lifecycle contract; never granted here |
| 5 | **Whole-copy rollback resistance** | **No** | Anti-rollback anchor — UNRESOLVED (continuity §6; T-DOMAIN) |
| 6 | **Cross-host / copied-key exclusivity** | **No** | In-process ownership only; UNMET (§5.2; §7 R10) |

Properties 4–6 remain **separate prerequisites**. This component establishes 1–3
and **nothing** about 4–6; local atomicity/durability/validation do **not** imply
authorization, freshness, rollback resistance, or exclusivity.

### 13.2 Logical record and evidence field table

The proposed record is a bounded, versioned logical structure named (for this
specification) the **`SafetyRestrictionRecord`**. "Stored directly" means the bytes
live in the record; "obtained independently" means the record holds only a reference
or identifier that is checked against a **separately trusted** source, never trusted
from the record's own claim. "Logical type" is prose; no concrete encoding is fixed.

| Field (logical type) | Producer / source | Consumer | Bound & validation rule | Stored directly / obtained independently | Proves / does **not** prove |
|---|---|---|---|---|---|
| `persistence_format_version` (`u16`) | This component's writer | Read/open structural gate | Must equal a supported constant, checked **before** any further decode; unsupported → refuse (no migration) | Stored directly | Proves which layout to decode. **Distinct** from the wire-message version and the signing-domain/preimage version and from D10's `SIGNING_RECORD_FORMAT_VERSION` / `SIGNING_METADATA_FORMAT_VERSION` (`signing_reservation_journal.rs` ~L52/~L92, both `u16=1`). Does **not** prove authenticity, authority, or freshness |
| `network_genesis_id` + `authority_context_ref` (genesis identity + authorized-epoch validator-set descriptor) | Boot-time **pinned** genesis identity (`ExpectedGenesisIdentity::load_pinned`, `genesis_authority_record_correspondence.rs`) and the authorized-epoch validator set | Certificate **interpretation** (signer set / threshold) and the **context-binding** check | Must **match** the independently pinned runtime context; mismatch → refuse (`ValidationPolicyMismatch`-style, reusing the C3B correspondence shape) | **Obtained independently** — the record stores an identifier that is compared to the pinned context; the pinned context is **not** taken from the record | Proves which validator set/threshold would interpret the QC. Does **not** prove the certificate is authentic, nor that the authority is current/authorized (A/B separate). A snapshot-baseline identifier is **not** automatically an authenticated historical block id |
| `lock_block_id` (`[u8;32]`) + `lock_view` (`u64`) | Engine `locked_qc` identity at the **effective** transition (`on_qc` ~L1004 / `set_locked_qc` via `on_timeout_certificate` ~L2162) | `is_safe_to_vote_on_block` (~L1312): the ancestor walk uses the **id**, the liveness test uses the **view** | 32-byte id; `view` ≤ a checked maximum; `view` **strictly greater** than the predecessor record's `view` (bookkeeping monotonicity, **not** anti-rollback) | Stored directly | Proves the **restriction identity + view** to enforce. Does **not** prove candidate ancestry is present, nor that the lock is verified or fresh. A higher **view** is **not** a stronger restriction and block id carries **no** numeric "dominance" (§2.1) |
| `supporting_certificate` (**wire** `QuorumCertificate`, `qbind_wire::consensus::QuorumCertificate` — the form carrying `signer_bitmap` + `signatures` + `suite_id`) | Engine evidence (`on_qc`'s `qc`; for a TC-derived raise, the `high_qc` **in wire form**) | Structural threshold observation + the association check; recovery-time **signature verification** only if wired (stage 2) | Signer-bitmap length ≤ `MAX_BITMAP_LEN` (=8192); `signatures.len()` ≤ `MAX_SIGNATURE_COUNT` (=`u16::MAX`); per-signature length ≤ `MAX_SIGNATURE_LEN` (=`u16::MAX`); threshold `ceil(2W/3)` recomputed in `u128` (reuse `qc_verify_domain` bounds + constants, D7-C3D) | Stored directly | Proves the **evidence that justified** the raise exists and is structurally bounded. The **logical** `QuorumCertificate` (`qc.rs`: `block_id`/`view`/`signers` only) **cannot** be stored here because it carries **no** cryptographic material; the **wire** form is required so stage-2 verification is even possible. A certificate with an **empty signer list** fails the structural threshold (`ceil(2W/3) ≥ 1`) and is refused **without** cryptography; full signature verification against the trusted validator context is a **separate** stage (T-TRUST-STORAGE), not performed on load today. **TC support (stated honestly):** only a TC whose `high_qc` is available **in wire form** is recovery-verifiable via the supporting QC; there is **no** wire `TimeoutCertificate` type and **no** TC/`signed_timeouts` domain verifier today, so a TC whose only form is **logical** is **not** recovery-verifiable — that case is a **material design gap** (§13.9), **not** invented evidence |
| `evidence_lock_binding` (SHA3-256 digest over {`lock_block_id`,`lock_view`, `supporting_certificate`, `authority_context_ref`}) | Writer at publication (reuse `BindingDigest`/`Sha3_256`, `signing_reservation_journal.rs` ~L221) | Read/validate: **recompute and compare** | 32-byte; recomputed digest must equal the stored digest from the **re-derived** inputs | Stored directly (digest); its **inputs** are re-derived, not trusted from the digest | Proves the stored certificate/context **corresponds** to the stored lock (integrity/association). Does **not** reconstruct the committed bytes or trusted context, and is **not** authentication, authorization, or freshness (a digest ≠ a signature; §5 X3) |
| `committed_state_assoc` (committed block id + height anchor) | Engine committed baseline at the transition | Anchoring the lock in **recovered committed state** (§5 X1) | **Comparison relation (explicit):** the stored anchor `(id, height)` must name a block that is **present in the recovered committed history** at that height (equal id at the anchored height), with `height` via checked arithmetic; the recovered committed baseline **may legitimately be at or beyond** the anchor height (committed progress since the last lock publication is **expected and allowed**), but the anchored block must still be on the recovered committed chain; if the anchor block is **absent** from recovered committed state or the height is **inconsistent**, the comparison **cannot be established** → **refuse** | **Obtained independently** — compared against recovered committed state; stored as a reference | Proves the lock's **relation to the committed baseline**. Does **not** prove ancestry of arbitrary candidates (that is per-candidate, below), and a later committed height does **not** by itself invalidate the anchor |
| `publication_revision` (`u64`, monotonic) + optional `predecessor_ref` | Writer (single-writer counter) | Ownership **stale-work fencing** (§13.5) and open's **authoritative-record selection** | Strictly increasing under the single writer; checked arithmetic; wrap → **refuse** (no silent reuse) | Stored directly | Proves **ordering among this host's own publications** (local bookkeeping). Does **not** prove whole-copy freshness or anti-rollback — a local revision/counter is **not** an anchor (§12.5; continuity §6.3) |
| `integrity_checksum` (CRC32 over the record payload) | Writer (reuse `compute_crc32` / `signing_journal_crc32`, `storage.rs` ~L531/~L545) | Read: **accidental-corruption** detection | 4-byte; recomputed checksum must match | Stored directly | Proves **accidental-corruption** detection (T-INTEG). Does **not** prove authenticity or authorization (a CRC is **not** a MAC) |
| `bounds_metadata` (declared lengths / counts for the variable-length members) | Writer | Read decode gate | **Concrete bounds, not “fixed maxima”:** `signer_bitmap.len()` ≤ `MAX_BITMAP_LEN` (8192); `signatures.len()` ≤ `MAX_SIGNATURE_COUNT` (`u16::MAX`=65535); per-signature ≤ `MAX_SIGNATURE_LEN` (`u16::MAX`=65535); `lock_block_id`/`committed id`/digests fixed at 32 bytes; `lock_view`/`publication_revision` are `u64` with **checked** increments (wrap → refuse); total record size ≤ a declared `MAX_SAFETY_RECORD_BYTES` constant **to be fixed by the successor**. The purely structural worst case is dominated by `MAX_AGGREGATE_SIGNATURE_BYTES = MAX_SIGNATURE_COUNT × MAX_SIGNATURE_LEN` (≈ 4.29 GB) — **not a safe allocation target**; the **real** deployment cap is derived from the authorized validator-set size `W` (`signatures.len()` ≤ `W`, aggregate bytes ≤ `W ×` per-signature cap), checked against the pinned context. All offset/length arithmetic is **checked** (no wrap) | Stored directly | Proves the record is **structurally bounded** so decode cannot over-read. Does **not** prove any semantic property. The u16×u16 product is an honest **allocation-bound limitation**, not a usable buffer size |

**Per-candidate ancestry is deliberately NOT a stored field.** The record stores the
**locked block identity + view** (required at startup) and the committed-state
anchor; it does **not** retain the entire block tree. The ancestry walked by
`is_safe_to_vote_on_block` is **supplied and checked per candidate** at evaluation
(the candidate's `justify_qc` and registered ancestry). **Missing candidate ancestry
→ refuse that candidate only**; it must **never** become assumed ancestry (§12.2).

**No field is stored "because it exists in memory."** Each row above names an actual
recovery or validation consumer. Fields with no recovery/validation consumer (e.g.
`current_view`, scheduling counters, the volatile `voted_in_view` latch) are **not**
in this record; `voted_in_view` remains lost on restart (D7-D2) and is **not**
reconstructed by this component.

### 13.3 Source-representation tracing and the four separated checks

**Four checks are distinct and must not be conflated.** The record design keeps these
as separate stages; passing an earlier stage never implies a later one, and an
explicitly **unverified** result **must not** silently satisfy a prerequisite that
requires a **verified** one:

1. **Structural decoding (structural observation)** — `persistence_format_version` +
   `bounds_metadata` + `integrity_checksum` (CRC32) + the **structural threshold
   observation** of the certificate (signer-count / bitmap bounds and `ceil(2W/3) ≥ 1`).
   Detects unsupported layout / oversize / accidental corruption, and refuses an
   **empty-signer** certificate **structurally** — zero signers cannot meet the
   threshold, so this needs **no** cryptography. Proves **nothing** about signature
   authenticity or authority.
2. **Evidence verification (verified evidence)** — verifying the **wire**
   `supporting_certificate`'s **signatures** against the trusted validator context (the
   D7-C3D `verify_quorum_certificate_with_domain` shape, which consumes the **wire** QC).
   **Separate**; **not** performed on load today (T-TRUST-STORAGE). It is **not**
   satisfied by a present-but-unverified certificate, a CRC, a digest, or a comment; the
   empty-signer certificate refused at stage 1 could never reach a verified result.
3. **Context binding (context / association validation)** — `network_genesis_id` /
   `authority_context_ref` match the **independently pinned** genesis + validator
   context; and `evidence_lock_binding` recomputes. Proves association/interpretability,
   **not** authenticity.
4. **Current authorization (A) / current-authority freshness (B)** — owned by the
   authority-lifecycle contract; **never** granted by any check here, however many of
   stages 1–3 pass.

**Durability acknowledgement and eligibility are two further, distinct levels.** The
O4/O5 `fsync`-acknowledged **durability** barrier is an existence/persistence result
(the bytes are durable), **not** a verification result: O5's “effective” outcome is a
**durability** acknowledgement of an already-validated record, **never** an
authentication result. **Eligibility for protected recovery** then still requires the
stage-2 verified evidence and the stage-4 current authorization. Consequently an
explicitly **unverified** stored certificate (stage 2 not run) is carried as
**unverified** and must **not** be treated downstream as if it satisfied a
verified-evidence prerequisite, no matter how many of stages 1, 3, and the durability
barrier passed.

**Source-representation facts carried from §2.1/§12.6 (so the record cannot
over-claim).**

* A certificate with **empty signer material** is **not** authenticated certificate
  evidence and is refused **structurally at stage 1** (zero signers cannot meet
  `ceil(2W/3) ≥ 1`), before any stage-2 cryptography.
* The **logical** QC (`qc.rs`: `block_id`/`view`/`signers`) carries **no** signatures;
  only the **wire** QC can be stage-2 verified, so the wire form is what is persisted.
* A **digest** (`evidence_lock_binding`, `BindingDigest`) does **not** reconstruct
  the bytes or the trusted context it commits to; it only re-compares them.
* A **snapshot baseline identifier** is **not** automatically an authenticated
  historical block identifier; `committed_state_assoc` is checked against recovered
  committed state, not trusted as authenticated history.
* **Candidate ancestry** is supplied and checked **per candidate**; the record does
  **not** silently assume restoration of the whole block tree.

**Named missing integration obligations (where a current producer does not supply a
required input, use is refused — no input is invented).**

* **Engine → safety-record writer boundary.** There is **no** integration point today
  between the in-memory lock mutation (`on_qc` / `set_locked_qc`, immediate, unstaged)
  and a durable safety-record write. Supplying it is a **proposed requirement**.
* **Recovery-time certificate verification.** Stage 2 is **not** wired on any load
  path today; requiring it on recovery is a proposed obligation, and until it is
  supplied the certificate is treated as **unverified** (trust-on-load, T-TRUST-STORAGE).
* **Decision→evidence binding.** Action/operation types carry **only** header fields
  and do **not** carry the lock/evidence that justified a decision (§12.3); binding
  them is a proposed requirement (§13.6), not an existing capability.
* **The safety-scoped synced-atomic publication interface** (§13.1) does **not** exist,
  although the underlying **atomic-plus-sync pattern does** (D10's
  `put_signing_record_and_metadata_synced`, `storage.rs` ~L1417). The missing element is
  the **safety-state-specific** interface with its validation/ownership integration; it
  must **not** be routed through the epoch-only synced API or the D10 journal's API.

### 13.4 Distinct logical operations (initialize / open / read-validate / publish / re-acknowledge)

Five operations are kept **distinct**. For each: **inputs**, **preconditions**,
**allowed writes**, **success**, **failure**, and **uncertainty behavior** (all
**proposed**; no operation exists today). None performs automatic adoption, repair,
reset, or migration.

**(O1) Explicit first initialization — `initialize_safety_store`.**
* *Inputs:* the external initialization prerequisite (the pinned genesis/validator
  context) and an explicit "first-use" intent; **no** fabricated QC, epoch, or
  authorization.
* *Preconditions:* the target slot holds **genuinely no** established safety state
  (not merely an empty directory — see below). Any existing unrelated / partial /
  legacy / malformed / unsupported state → **refuse** (no overwrite).
* *Allowed writes:* the initialization metadata **and**, atomically with it, an
  explicit initial **record** — **always** the `BootstrapNoLock` variant at first
  initialization (below) — in **one** atomic unit. The “metadata but no record” option
  is **removed**: this component uses the **one coherent layout** in which initialized
  metadata is **never** written without an associated record (resolving the prior O1/
  invariant conflict). So the metadata and the initial record can never diverge.
* *Success:* an established, openable store with no admitted signing.
* *Failure:* refuse on any pre-existing or unsupported state; no partial store left
  claimed as initialized.
* *Uncertainty:* if the initializing write returns an error but **may have
  survived**, the operation reports uncertainty and does **not** assume success; a
  later explicit **open** (O2) decides from the observable durable state, and a second
  `initialize` is **refused** if any established state is observed (no duplicate init
  over a survived write).

**(O2) Opening established state — `open_safety_store`.**
* *Inputs:* the store handle and the pinned context.
* *Preconditions:* an established store is expected.
* *Allowed writes:* **none** (open is read-only; it may run the recovery durability
  operation O5 only as its own explicitly-named step, never a silent repair).
* *Success:* an in-memory authoritative state (the selected record + its validated
  evidence/context) and the expected `publication_revision`.
* *Failure:* **genuine absence** of any established state when established state was
  expected → **refuse** (do **not** initialize; INV-R1/R2). Malformed / partial /
  unsupported / inconsistent → **refuse** (fail-closed). An empty directory is **not**
  equated with an unused validator (first-use ambiguity stays explicit).
* *Uncertainty:* open never infers a lost acknowledgement from readable bytes; it
  decides from observable records only, invoking O3/O5.

**(O3) Reading / validating the authoritative publication — `read_authoritative`.**
* *Inputs:* the durable bytes.
* *Preconditions:* a candidate record is present.
* *Allowed writes:* **none**.
* *Success:* a structurally-decoded, bounds-checked, CRC-valid, **structurally
  threshold-observed** (non-empty signer set), association-bound record (stages 1 and 3
  of §13.3). Stage 2 signature verification runs **only** if recovery verification is
  wired; when it does not run, the record is returned explicitly flagged **unverified**
  and must **not** satisfy any verified-evidence prerequisite downstream.
* *Failure:* any stage-1 failure (including an **empty-signer** certificate, refused
  **structurally**) or any stage-3 association/context failure → **refuse** (frontier
  not reached).
* *Uncertainty:* a readable byte is **not** an acknowledged write (INV-R7); validity
  of bytes is **not** evidence a former acknowledgement was received; an **unverified**
  result is **not** upgraded to verified by being durable or association-bound.

**(O4) Publishing an eligible transition — `publish_transition`.** (Detailed in §13.5.)
* *Inputs:* the engine's computed higher-view lock + its supporting certificate +
  the pinned context + the expected current `publication_revision`.
* *Preconditions:* transition **eligibility validated** (the raise is strictly higher
  view than the current effective record and the evidence/context validate); the
  expected revision matches (stale work fenced).
* *Allowed writes:* exactly one atomic synced publication unit (§13.1).
* *Success:* the new record is **acknowledged-durable**; only then is it **effective**
  and installed in memory, admitting dependent work.
* *Failure:* validation failure → no write. Write failure → fail-closed, not effective.
* *Uncertainty:* uncertain acknowledgement → **not** effective; dependent signing
  stays blocked until O2/O5 re-establish state.

**(O5) Re-acknowledging an identical recovered publication — `reacknowledge_recovered`.** (Detailed in §13.5.)
* *Inputs:* the **complete** recovered publication (the whole O3-validated record and
  all of its supporting material), the **independently supplied** pinned context, and
  the **expected `publication_revision`**. No process-local acknowledgement knowledge is
  an input.
* *Preconditions:* O3 validated the surviving record; the owner holds the
  serialization boundary that protects re-publication (below); the expected revision is
  supplied.
* *Allowed writes:* a **synced re-publication of the identical validated bytes** — the
  recovery durability operation. It must **not** alter, repair, or rewrite content: it
  does **not** change the `publication_revision`, the initialization/bootstrap state,
  the association fields, or any supporting material. Identity is established by
  comparing the **complete authoritative content** (the whole re-serialized validated
  record and its supporting material) against the **currently stored publication**,
  under the owner/serialization boundary, **before** re-acknowledging. This is a
  **complete-content** comparison, **not** an equivalence to matching
  `integrity_checksum` + `evidence_lock_binding`: the CRC32 covers only accidental
  corruption and the SHA3-256 `evidence_lock_binding` covers only the selected bound
  fields, so **neither, nor both together, establishes complete publication identity**.
  The checksum and the binding are retained as **additional** corruption/association
  checks over their own inputs; no new cryptographic construction is introduced.
* *Refusal:* refuse on **stale** input (the stored current revision no longer matches
  the expected revision — e.g. a newer publication exists) or on any content
  **mismatch** between the recovered and the currently stored publication.
* *No-overwrite-of-newer:* because the comparison and the re-publication both occur
  under the single owner boundary against the **currently stored** publication and the
  expected revision, a **newer** publication cannot be overwritten by an older recovered
  one in the window **between** the comparison and the re-publication.
* *Success:* the surviving transition becomes **effective** (SW-4 / D13-14) only after
  O5's own synced durability acknowledgement.
* *Failure / uncertainty:* a **failed or uncertain** durability acknowledgement returns
  **failure** — **refuse** (SW-5 / D13-15); never treat readable bytes as effective.

**Edge cases addressed explicitly.**

* **Genuine absence vs missing established state.** O1 requires genuine absence; O2
  refuses on missing-but-expected state. The two are different operations and are
  **not** collapsed; an empty directory is not treated as an unused validator.
* **Existing unrelated / partial / legacy / malformed / unsupported state.** All →
  **refuse** (O1 refuses to overwrite; O2/O3 refuse to adopt). No migration.
* **Duplicate initialization.** A second O1 over any observable established state →
  **refuse**.
* **Initialization whose write survives despite a returned error.** O1 reports
  uncertainty; O2 decides from the survived durable state; a repeat O1 is refused.
* **Explicit open after an uncertain init.** O2 reads what durably survived and either
  opens it (if valid/complete) or refuses (if partial/malformed) — it never
  auto-initializes to "fix" the uncertainty.
* **Initialization metadata and its atomic association.** The init metadata is written
  **atomically with** the initial record (one unit) so a reader can never see metadata
  claiming "initialized" without the associated record, or vice versa.

**Coherent initialization layout — two explicit variants (resolves the O1/invariant
conflict).** An established store always holds metadata **and** exactly one record, in
one of **two** explicit variants; there is no third “metadata-only” shape:

* **`BootstrapNoLock` variant** (a validator that has legitimately not yet locked).
  * *Required fields:* `persistence_format_version`, the `network_genesis_id` +
    `authority_context_ref` (matched against the pinned context), an explicit
    bootstrap discriminant, `publication_revision` = the **initial** revision, and
    `integrity_checksum` + `bounds_metadata`.
  * *Absent fields:* `lock_block_id` / `lock_view`, `supporting_certificate`,
    `evidence_lock_binding`, and `committed_state_assoc` are **absent by variant** (not
    zeroed-and-claimed): the decoder requires them to be absent for this variant and
    present for `Locked`.
* **`Locked` variant** (an effective lock has been published).
  * *Required fields:* **all** §13.2 fields, including `lock_block_id` / `lock_view`,
    the wire `supporting_certificate`, `evidence_lock_binding`, and
    `committed_state_assoc`.
  * *Absent fields:* none; a missing required field → **refuse** (stage 1).

**Revision rules.** `publication_revision` starts at a fixed **initial** value in
`BootstrapNoLock` and is a `u64` incremented by **checked** arithmetic on every O4
publication; **exhaustion** (wrap) → **refuse** (no silent reuse), never a reset.

**First transition to a legitimate view-zero lock (no fabricated predecessor).** The
first `Locked` publication raises from `BootstrapNoLock` to a genuine view-zero (or
first legitimate) lock using the engine's **actual** first `locked_qc` and its wire
supporting certificate; the component **fabricates no** predecessor QC, epoch, or
authorization to “justify” the first lock. The monotonic-`view` rule applies from the
bootstrap baseline (the first lock's `view` is simply the first stored lock view; there
is no synthetic prior lock to out-rank).

**O2/O3/O5 for both variants.** O2 opens either variant from durable state; O3
validates the **variant-correct** field set (absent fields required absent for
`BootstrapNoLock`, all present for `Locked`); O5 re-acknowledges either variant by the
**complete-content** comparison of §13.4 (it preserves the variant and its revision and
repairs nothing). A `BootstrapNoLock` store admits **no** dependent signing until a
`Locked` record is effective.

**Duplicate and survived-but-unacknowledged initialization.** A second O1 over **any**
observable established state (either variant) → **refuse**. An initialization whose
write **survived** despite a returned error is decided by a later O2 from the durable
state (open the survived valid record, or refuse if partial/malformed); O1 is **not**
re-run to “fix” it.

**Missing / partial / malformed / unsupported / inconsistent established state.**
Missing-but-expected established state → O2 **refuses** (no auto-init); partial /
malformed / unsupported-version / variant-inconsistent (e.g. a `Locked` discriminant
with an absent `lock_block_id`, or a `BootstrapNoLock` discriminant carrying lock
fields) → **refuse** (fail-closed). These stay **distinct** from a valid
`BootstrapNoLock` state and from a valid prior `Locked` publication.

**Absence is scoped to this component's owned state.** “Genuine absence” (O1's
precondition) means **no established safety record in this component's own owned
namespace** — **not** that the whole consensus DB or unrelated namespaces are empty; an
empty directory is **not** an unused validator. The external initialization
prerequisite (the pinned genesis/validator context) must be present; representing
no-lock **does not** establish that production first use is legitimate (that is A/B,
separate). `initialize` and `open` stay **separate**; there is **no** automatic
adoption, repair, reset, or migration, and local absence plus a pinned context does
**not** prove a validator has never operated or authorize production first use.

### 13.5 Publication, recovery, durability contract, and ownership/concurrency

**Publication unit and exact durability contract.** The publication unit is the
single same-database `WriteBatch` of §13.1, committed with `set_sync(true)`. The
**durability contract** is: the publication returns success **only after** an
`fsync`-acknowledged barrier over the whole unit; a returned success is the
**acknowledged-durable** boundary and **only then** is the transition **effective**.
Ordinary `db.put` writes (`put_block`/`put_qc`/`put_last_committed`) and unsynced
batches (`apply_epoch_transition_atomic`'s `db.write`) do **not** implement this
contract — they persist bytes without the acknowledged barrier (§12.5). The ordering
of the one publication operation is:

1. **Validation before publication** — transition eligibility (strictly-higher view;
   evidence + context validate; expected `publication_revision` matches). Failure →
   no write.
2. **Atomic publication** — the record **and** its required supporting material
   (certificate + context reference) in **one** `WriteBatch`.
3. **Acknowledged-durable boundary** — `set_sync(true)`; success ⇒ barrier reached.
4. **In-memory installation** — only after (3) is the raised restriction installed as
   **effective**.
5. **Admission of dependent work** — dependent signing (D10 reserve onward) and
   retained-result reuse are admitted **only after** (4).

**Failure / store-then-error / uncertain acknowledgement.** Failure **before** the
write → nothing published, not effective. **Store-then-error** (bytes reached
storage but the caller got an error) or **uncertain acknowledgement** → the live
caller fails **closed then** and admits no dependent work; a **restarted** process
later decides from the **surviving record** via O2/O3/O5, never from the former
caller's (unobservable) acknowledgement. A readable byte is **not** an acknowledged
write (INV-R7).

**Recovery from valid / missing / incomplete / malformed / mismatched state.**
Recovery decides **only** from observable durable records (the §12.3 surviving-write
matrix SW-1…SW-8 and the §12.5 rows D13-1…D13-15, which remain authoritative):

* **Valid, complete surviving record, no ack knowledge** → O5 (recovery durability
  operation); effective **only after** O5 succeeds (SW-3→SW-4 / D13-13→D13-14).
* **Missing** required safety state (but established journal) → refuse (D13-2).
* **Incomplete / malformed** publication → refuse (D13-4; frontier not reached).
* **Mismatched** (e.g. evidence/lock association fails, or context mismatch) → refuse.
* **No new transition, valid prior state** → resume from the last effective record
  after the shared gates (SW-1).

**The recovery operation does not silently repair.** O5 **republishes identical
validated bytes** and establishes identity by a **complete-content comparison** of the
whole recovered publication against the **currently stored** publication under the
owner boundary before re-acknowledging; it never edits, truncates, or "fixes" content,
and it does **not** change the revision, initialization state, association fields, or
supporting material. The `integrity_checksum` and `evidence_lock_binding` are retained
as **additional** corruption/association checks over their own inputs only — matching
them is **not** equivalent to byte-for-byte publication identity (a CRC detects
corruption; the binding covers selected fields; neither establishes complete identity).
If complete identity cannot be established, or the stored current revision no longer
matches the expected revision (a newer publication exists), O5 **refuses** — it does
not synthesize a corrected record and does not overwrite a newer publication.

**The surviving-write case is preserved (D13).** Recovery **cannot** use knowledge of
whether a former caller received an acknowledgement; a valid surviving publication is
**completed** through O5's fresh recovery durability operation, and loss of
acknowledgement knowledge is **not** proof the write failed.

**Ownership across supported handles.**

* **Who serializes.** A single in-process **safety-record owner** serializes
  transition-eligibility validation, publication (O4), recovery re-acknowledgement
  (O5), and in-memory installation. It is a **new** coordinator; this specification
  does **not** claim an existing engine lock, storage mutex, or D10 `reserved_positions`
  owner already coordinates it — it may **reuse** the backend-shared single-writer
  **pattern** (the D10 ownership shape) without reusing its instance.
* **Expected-record / revision check.** Every O4/O5 carries the **expected current
  `publication_revision`**; the owner refuses if the durable/in-memory current revision
  differs, so a stale handle cannot publish or re-acknowledge against an unexpected base.
* **Preventing stale overwrite.** Because publication requires strictly-greater view
  **and** the matching expected revision under the single writer, stale work cannot
  overwrite or re-acknowledge an **older** publication over a **newer** one.
* **After an uncertain write.** Until state is re-established (via O2/O3/O5), the owner
  admits **no** dependent signing; the in-memory "effective" state is not advanced on
  an uncertain write.
* **After process death and a fresh open.** O2 rebuilds the in-memory authoritative
  state and `publication_revision` from the durable record; nothing volatile
  (`voted_in_view`, pending/effective labels) survives, and the pending/effective
  distinction is re-derived **only** from the durable record.

**Local ownership does not fence other hosts.** Single-writer ownership coordinates
one backend on one host; it does **not** fence a **copied** database or signing key on
another host (property 6, UNMET). No local checksum, digest, synced write, revision
counter, or mutex establishes whole-copy freshness or cross-host exclusivity.

### 13.6 Engine decision binding and D10 integration

Decision timing is **per route**; the state present when a message object is
**constructed** is not necessarily the state that **justified** the decision (§12.3).
The table names, for each route, the decision/eligibility point, the required
safety-state prerequisite, and the **proposed missing interface** (all binding is a
**proposed requirement**; current action types carry **only** header fields).

| Event / operation | Decision / eligibility point (source) | Safety-state prerequisite (profile (a)) | Proposed missing interface |
|---|---|---|---|
| **Inbound `Proposal` processing** | `ingest_proposal` (~L1720): `is_safe_to_vote_on_block` (~L1810) against the lock **before** the self-vote | The effective record in force **at ~L1810** must be durable; bind the decision to **that** lock/evidence, not a later one | A decision→record reference carried with the admitted work; none today |
| **Leader `Proposal` + self-`Vote`** | `on_leader_step` (~L1434): parent/justification from `locked_qc()` (~L1450–1461), `Proposal` built (~L1498) **before** self-vote (~L1538) | Bind to the lock at the step's decision point; a self-vote-generated QC/raise is recorded **separately** and must **not** re-justify the same proposal/vote | Same binding interface; plus "later transition recorded separately" |
| **Received `Vote` / QC-driven lock transition** | `on_vote_event` (~L1867): a received vote may form a QC and raise the lock | Any emitted action binds to its **originating** view, not the post-QC lock | Binding; **never** use a self-vote-generated QC to retroactively justify that same vote |
| **TC-driven lock transition** | `on_timeout_certificate` (~L2162): `set_locked_qc(tc.high_qc)` **before** the `current_view` advance | A TC-derived raise needs a durable, recoverable supporting QC before dependent signing | Binding; a later `current_view` must not relabel an earlier action |
| **Fresh D10 signing (S6)** | Continuity §4.1 step 4 reservation, **after** the §13.5 frontier | The effective record (and O5 if recovering) must be durable **before** `reserve_for_sign` and the signer | Ordering hook placing the safety-record barrier before D10's reservation |
| **Retained-result reuse (S7)** | Resend the one retained `Signed`, **zero** new signer calls | Still gated by the §12.2/§12.3 prerequisites **and** D10's acknowledgement / record-binding / current-authorization revalidation | The same prerequisite gate; reuse is **not** automatically sufficient |

**Prepared-decision policy across an L0→L1 transition (stated explicitly, not left to
scheduling).** A decision prepared under effective lock **L0** when an **L1**
transition is pending or becomes effective before external signing/reuse is handled
by **defined checks**, not an unstated assumption. The L0 eligibility inputs the
decision needs are **not** re-read from disk after replacement and are **not**
reconstructable from D10's records (D10's `BindingDigest` is an opaque one-way digest
over the preimage/position; it does **not** carry L0's `lock_block_id`/`lock_view` or
supporting certificate — §13.2, `signing_reservation_journal.rs` ~L190/~L281). They are
therefore captured **at decision time** as a **bounded, immutable in-memory evidence
reference** (the L0 lock identity+view and the supporting-evidence/context reference
the check used), carried with the prepared operation for **its own lifetime only** and
never written as a second disk generation (§13.7):

* **Within the same event (self-vote-generated L1).** The decision's L0 eligibility
  check is the one captured at decision time against the **then-effective L0** record;
  the L1 raise produced while processing the event is recorded **separately** and the
  decision stays bound to **L0**; L1 **must not** retroactively justify it. If the
  decision was not valid under that captured L0 eligibility, it is **rejected** (not
  rescued by L1). No failure here authorizes a **fallback** signing under L0.
* **Across events (an externally-driven L1 became effective before signing/reuse).**
  The prepared L0 decision is **blocked** until revalidated; the captured L0 in-memory
  evidence is used only to identify the **exact** prepared candidate, **not** to
  authorize it under L0. It is **permitted only if** re-checking `is_safe_to_vote_on_block`
  for that **exact** candidate against the now-effective **L1** durable record (and the
  supplied per-candidate ancestry) passes; otherwise it is **rejected**. Preference is
  **explicit serialization and conservative refusal** over any concurrency machinery.
* **Pending or uncertain publication of L1.** While the L1 publication is pending or its
  acknowledgement is uncertain, the prepared work stays **blocked** and admits **no**
  dependent signing until O2/O3/O5 re-establish a durable effective record; no partial
  or uncertain L1 relabels or releases the protected work.
* **Across process death.** The bounded in-memory L0 evidence and every prepared
  operation are **volatile** and are **not** reconstructed on restart (`voted_in_view`
  is likewise lost, D7-D2); only the single durable authoritative record survives. A
  prepared decision not yet durably reserved under D10 is simply **not** reconstructed —
  it is re-derived from scratch under the recovered effective record (conservative
  refusal), never resurrected under a stale L0.

**Why authoritative-record replacement is safe under this lifecycle.** Replacing the
single durable record with an acknowledged L1 successor never strands an outstanding
consumer that needed L0's **disk** bytes: an outstanding prepared decision either
carries its own captured **in-memory** L0 evidence (used for identity, then
revalidated against L1 or rejected) or, if it did not survive, is not reconstructed at
all. No outstanding consumer reads the superseded L0 disk record, so retaining exactly
one authoritative disk generation is consistent with §13.6. This **local**
replacement/retention safety is **separate** from the unresolved anti-rollback anchor
(a newer local record is not whole-copy freshness; §13.9), and **no** D10 record is
read, replaced, or pruned by this lifecycle.

**D10 preserved (unchanged).** The §13 prerequisites sit **before** D10's reservation;
D10's accepted properties are preserved: canonical position identity and
prepared-preimage binding; the original frozen ticket/context/signer; post-storage
authorization revalidation; durable reservation **before** signing; one-use checked
continuation and publication; a recovered `Reserved` remains **potentially signed**
(INV-R3); exact retained reuse invokes **no** signer and retains its
acknowledgement/verification checks (INV-R4); and **no** conflict obligation is
released by a safety-state transition.

**Ordering sufficiency (why not one transaction spanning safety + D10).** A **single**
atomic transaction spanning the safety publication and the D10 writes is **not**
required, because the two have an **ordering** relation, not a joint-atomicity one:
for every supported crash state the safety record is durable **before** D10's
reservation, so (i) crash **before the atomic storage publication completes** ⇒ nothing
stored, no effective transition, no admitted D10 reservation (nothing to reconcile);
(i′) crash **after the atomic publication but before/at the acknowledgement** ⇒ a
**complete successor may be durably stored** while the live caller observed no success
— this is **not** “nothing to reconcile”: it leaves no effective transition and no
admitted D10 reservation for the live caller, but a restarted process must run **O3/O5**
against the observed record (complete → O5; incomplete/malformed → refuse) and must not
assume the predecessor remained stored; (ii) crash **after** the safety barrier,
**before** the reservation ⇒ valid safety state with no new reservation,
which is **not** unsafe (D13-12 / G8) — recovery proceeds to D10's own gates and
synthesizes no reservation; (iii) crash **after** the reservation ⇒ D10's own
durable-before-sign invariant governs (recovered `Reserved` = potentially signed).
Because each crash state is independently recoverable from the two ordered barriers,
the extra complexity of a spanning transaction is **not** justified within scope.

### 13.7 Retention, replacement, and capacity

**Concrete bounded policy (initial profile): retain exactly one authoritative
record; pruning disabled.**

* **One authoritative record, not multiple generations.** The component retains the
  single current **effective** `SafetyRestrictionRecord` (plus, transiently during
  O4, the in-progress publication until it is acknowledged or discarded). Recovery
  needs only the **current** effective record and its supporting evidence/context, so
  no superseded **disk** generation is kept. An outstanding **prepared** decision that
  still needs its originating L0 eligibility does **not** read a superseded L0 disk
  record and is **not** satisfied by D10's records (D10's `BindingDigest` cannot
  reconstruct L0's lock/evidence — §13.6): it carries a **bounded, immutable in-memory
  L0 evidence reference** for its own lifetime only (§13.6), which is volatile and not
  reconstructed across restart. This keeps a single authoritative **disk** generation
  while still handling outstanding consumers; it adds **no** unbounded second journal
  and leaves D10's own records untouched.
* **When replacement is safe (storage publication vs caller acknowledgement vs
  in-memory install, kept distinct).** A new record **replaces** the current one only
  via a successful O4, whose stages are **separate**: (1) validated eligibility; (2)
  **atomic storage publication** of the successor (the single `WriteBatch` — atomic
  over its keys); (3) a **durability acknowledgement** that the live caller may or may
  not observe; (4) **in-memory installation** admitting dependent work, reached only
  when the caller observes success. Because step (2) is atomic, a crash during
  replacement leaves either the intact predecessor **or** a **complete successor**,
  never a torn mix — and a complete successor **can** be the durable outcome **even
  when the original caller received an error or died before observing success** (step
  (3)/(4) did not complete for that caller). The design therefore does **not** claim
  the predecessor **necessarily remains stored** after an uncertain replacement; a
  restarted process decides from the **observed** durable state via O2/O3/O5 and does
  **not** discard, repair, or overwrite a possibly-published successor.
* **Deletion / pruning — disabled.** Because a safe prune would require a defined
  **discharge condition** with observable inputs, and the only honest discharge here
  ("the superseded safety obligation is fully discharged") cannot be reduced to
  observable local inputs **without** the unresolved anti-rollback anchor, **pruning
  is disabled** in the initial profile. The component does **not** use "prune after
  the obligation is discharged" as an undefined rule, and it does **not** introduce an
  unbounded second journal of historical records.
* **At capacity.** Since only one authoritative record is retained, steady-state size
  is **bounded by construction**. If an implementation-level bound (e.g. a maximum
  record size from §13.2's `bounds_metadata`) is exceeded, publication **fails closed**
  (the transition is refused; the prior effective record is preserved) rather than
  silently truncating or dropping evidence.
* **Restart preserves capacity and retention obligations.** O2 rebuilds exactly the
  one authoritative record and its revision; no retained-generation bookkeeping needs
  reconstruction because none exists. The bounded single-record invariant holds
  identically across restart.
* **D10 records are never pruned here.** This component does **not** prune, rewrite,
  or modify D10 signing records as part of retention; D10 retains its own policy
  (continuity §9).

### 13.8 Invariants and future acceptance matrix (not executed)

**Invariant argument (concise).** (INV-D14-1) A transition is **effective** only
after the §13.5 acknowledged-durable barrier; dependent signing/reuse is admitted
only against an effective record (atomic visibility + acknowledged durability).
(INV-D14-2) The record is usable only after structural decode + bounds + CRC
(stage 1) and association/context binding (stage 3) pass; evidence verification
(stage 2) and authorization (stage 4) are **separate** and never implied.
(INV-D14-3) Recovery decides only from observable durable records; a readable byte is
never an acknowledged write, and a valid surviving transition is completed only via
O5's fresh barrier. (INV-D14-4) Single-writer ownership with an expected-revision
check prevents a stale handle from overwriting or re-acknowledging a newer record with
an older one. (INV-D14-5) Exactly one authoritative **disk** generation is retained;
replacement's **storage publication is atomic** (a crash leaves the intact predecessor
or a complete successor), **separate** from the caller-observed acknowledgement and the
in-memory install — so a complete successor may be durable even when the caller
observed no success, and the predecessor is **not** assumed to remain stored after an
uncertain replacement; outstanding prepared L0 consumers are served by bounded
in-memory evidence (§13.6); pruning is disabled; D10 records are untouched.
(INV-D14-6) No operation performs automatic adoption, repair, reset, or migration, and
none fabricates a QC/epoch/authorization. **No row below is an executed PASS.**

| # | Scenario | Observable inputs | Allowed / refused behavior | Protected effect | Evidence level eventually required |
|---|---|---|---|---|---|
| H1 | D12 advanced-lock recovery across profile (a) | Durable record vs reconstructed committed-QC | REFUSE the D12 candidate until the effective record + frontier establish the lock | No vote the pre-crash lock refused | unit/model + real-storage |
| H2 | First `initialize` on genuine absence | Empty/absent established state + explicit intent + pinned context | ADMIT O1 (bootstrap/no-lock representable); no signing | Established, openable store | unit/model + real-storage |
| H3 | `open` on missing-but-expected state | Absent record where established expected | REFUSE (no auto-init) | No fabricated state | unit/model |
| H4 | Duplicate `initialize` / uncertain-init survival | Survived init bytes + a second O1 | REFUSE second O1; O2 opens the survived valid state | No duplicate/overwrite | process-death |
| H5 | Valid lock/evidence/context association | Complete record, CRC+binding match, context pinned | ADMIT read/validate (stages 1,3) | Interpretable record | unit/model + real-storage |
| H6 | Invalid association / context mismatch / empty-signer QC; unverified-but-durable certificate | Mismatched binding or empty signer list; or a present certificate with stage 2 not wired | Empty-signer → REFUSE **structurally** (stage 1 threshold); association/context mismatch → REFUSE (stage 3); present-but-unverified → carried **unverified**, never satisfying a verified prerequisite | No unverified adoption; no unverified result treated as verified | unit/model |
| H7 | Size limits / checked arithmetic / unsupported version / corruption | Oversize, wrap, bad version, bad CRC | REFUSE at structural decode | No over-read / no migration | unit/model |
| H8 | Atomic publication; partial outcome vs complete-but-unacknowledged successor | A torn/partial record **or** a complete successor whose acknowledgement the caller never observed (“uncertain bytes” is **not** a stored format) | Torn/partial → REFUSE (frontier not reached); complete successor → O5 re-acknowledges; live uncertain result → fail-closed and block dependent work | No torn record admitted; a complete successor is neither discarded nor overwritten | real-storage + process-death |
| H9 | Crash before acknowledgement or in-memory install | Surviving (possibly partial) record, no ack knowledge | Decide from observable record: complete→O5; else REFUSE | No effect from an unacknowledged write | process-death |
| H10 | Successful recovery re-acknowledgement | Valid complete surviving record + O5 success | ADMIT; transition effective | Effective only after O5 barrier | process-death |
| H11 | Failed recovery re-acknowledgement | Valid record + O5 failure/uncertainty | REFUSE (fail-closed) | No effect from readable bytes | process-death |
| H12 | Competing handles / stale publication attempt | Two handles, mismatched expected revision | REFUSE the stale O4/O5 | No older-over-newer overwrite | unit/model + real-storage |
| H13 | Prepared L0 decision across an L1 transition | L0 decision + effective L1 record + candidate ancestry | Self-vote L1: bound to L0 / REJECT if invalid under L0; external L1: BLOCK then PERMIT only if revalidation passes, else REJECT | No retroactive justification | unit/model + process-death |
| H14 | Fresh signing vs exact retained reuse | S6 vs S7 recovery state | Fresh: full prerequisites then reserve/sign; reuse: exact resend, zero signer calls, D10 checks | D10 semantics preserved | real-storage + process-death |
| H15 | Preservation of D10 conflicts across the frontier | Conflicting binding at one position | REFUSE (no conflict released by a safety transition) | D10 conflict invariant intact | unit/model |
| H16 | Capacity / replacement / disabled pruning | Oversize record; successful replacement; complete-but-unacknowledged successor; prune request | Oversize→fail-closed (prior record preserved); replacement's **storage publication is atomic** and **separate** from the caller-observed acknowledgement (a complete successor may be durable even if the caller saw no success; predecessor not assumed retained); prune→disabled | Bounded single-disk-generation invariant | unit/model + real-storage |
| H17 | Ordinary restart vs requested snapshot restore | Restart (record present) vs restore (no lock recovered) | Distinguish paths; REFUSE where no durable effective record is recovered | No unlocked resume above a baseline | real-storage + release-binary |
| H18 | Explicitly unsupported arrangement | Non-co-located record/evidence split | REFUSE (unsupported in initial profile) | No partial cross-store publication | unit/model |
| H19 | Complete identity change **outside** `evidence_lock_binding` | A field outside the digest's inputs differs between recovered and stored bytes, CRC and recomputed digest both still match | O5 **refuses** (complete-content comparison detects it; CRC+binding do **not**) | No non-identical re-acknowledgement | unit/model + process-death |
| H20 | Stale O5 against a newer publication | A recovered older record + a newer stored publication (expected revision no longer current) | O5 **refuses** (no older-over-newer overwrite between comparison and re-publication) | Newer publication preserved | unit/model + real-storage |
| H21 | Certificate/lock mismatch despite valid CRC and recomputed digest | Certificate fields do not semantically correspond to the lock id/view, yet CRC and digest recompute | REFUSE (semantic association, not a recomputed hash, is required) | No false semantic correspondence | unit/model |
| H22 | Verified vs unverified evidence outcome | Present certificate, stage 2 not wired, used where a verified prerequisite is required | Carry **unverified**; REFUSE to treat it as satisfying a verified prerequisite | No unverified-as-verified | unit/model |
| H23 | Committed-state comparison failure | Anchor block absent from recovered committed chain, or height inconsistent | REFUSE (comparison cannot be established); legitimate committed progress since the lock is **allowed** | No lock admitted off the committed chain | unit/model + real-storage |

Evidence levels are kept **separate**: *unit/model → real-storage → process-death →
release-binary → power-loss / production-authority*. Process termination is **not**
power-loss; an isolated writer is **not** configured production authority.

### 13.9 Existing vs missing, resolved vs unresolved, the single successor, and verdict

**Existing mechanisms reused (patterns, not instances).** The **atomic-plus-sync**
publication pattern — a multi-key `WriteBatch` committed with `WriteOptions::set_sync(true)`
— **already exists** in D10's `put_signing_record_and_metadata_synced` (`storage.rs`
~L1417); same-database `WriteBatch` atomicity (`apply_epoch_transition_atomic`) and the
epoch-only `set_sync(true)` barrier (`put_current_epoch_synced`, `flush_epoch_durable`)
are the narrower precedents; CRC32 corruption detection (`compute_crc32` /
`signing_journal_crc32`); SHA3-256 association binding (`BindingDigest`); distinct `u16`
persistence-format versioning (the D10 record/metadata version precedent); bounded
**wire**-QC verification shape (`qc_verify_domain`, D7-C3D); pinned genesis/validator
correspondence (`genesis_authority_record_correspondence`, C3A/C3B); the backend-shared
single-writer ownership **shape** (D10).

**Missing implementation (named).** **Not** the atomic-plus-sync primitive (D10 already
combines them) but a **safety-state-specific** publication interface built on it with
the safety-record **validation and single-writer ownership** integration — not routed
through the epoch or D10 APIs; the safety-record reader/validator (O3) and recovery
durability operation (O5); the engine→writer integration boundary and the
decision→evidence binding; recovery-time certificate verification wiring (stage 2); and
a **wire**-form TC verifier (no wire `TimeoutCertificate` type / `signed_timeouts`
verifier exists, so logical-only TC evidence is not recovery-verifiable — a **material
design gap**, §13.2). **None** of these exists today.

**Resolved design choices (this pass).** One supported co-located single-database
profile with a single synced-atomic publication unit (non-co-located **unsupported**);
the bounded versioned field set (concrete bounds, not "fixed maxima") with a named
consumer per field; the five distinct operations and their uncertainty behavior; the
**two explicit initialization variants** (`BootstrapNoLock` / `Locked`) in one coherent
layout (no metadata-without-record); recovery decided from observable durable records
with a **complete-content**, non-repairing re-acknowledgement (O5 identity is not a
CRC+binding equivalence); single-writer ownership with an
expected-revision fence; per-route decision binding and the explicit L0→L1
prepared-decision policy; D10 preserved via **ordering**, not a spanning transaction;
and **one authoritative record with pruning disabled and fail-closed capacity**.

**Material unresolved issues (kept separate, out of this component).** The durable
**anti-rollback anchor** (continuity §6.6) is **UNRESOLVED**; profile (a) does **not**
discharge it, and pruning is disabled **because** a safe discharge condition depends on
it. Whole-copy rollback resistance (property 5) and cross-host/copied-key exclusivity
(property 6) remain **UNMET**. Recovery-time certificate verification (stage 2) is a
named integration obligation, **not** wired. These are prerequisites tracked elsewhere,
not gaps in the record **design**.

**One material record-design gap is named honestly (TC recovery-verifiability).** For a
**TC-derived** lock raise, recovery-time verification requires the supporting QC in
**wire** form; there is **no** wire `TimeoutCertificate` type and **no**
`signed_timeouts` domain verifier today (§13.2). The implementation successor must
**resolve** this precise obligation — either persist the TC's `high_qc` in wire form as
the verifiable supporting QC, or declare TC-derived locks **recovery-unverifiable** and
**refuse** them on the protected recovery path — and must **not** invent TC signatures
or a verifier. The QC-derived path is fully specified; only this TC sub-case is an open
design choice for the successor.

**Exactly one bounded, unstarted successor.** *Implement and unit/real-storage-test the
co-located single-database `SafetyRestrictionRecord` publish/open/read-validate/
re-acknowledge operations behind a disabled-by-default, non-production-wired interface*
— the O1…O5 operations and the synced-atomic publication unit, with the §13.8 H-matrix
as its target cases, **without** engine integration, signer calls, anchor selection,
activation, or readiness change. This successor neither re-opens the (a)/(b) choice
(resolved, §12.7) nor repeats D12; it builds the **storage component** whose logical
design §13 fixes, and it must **resolve the named TC recovery-verifiability design
obligation** above (persist the wire `high_qc`, or refuse TC-derived locks on recovery)
before that sub-case is implemented. It is **not** full production integration and does **not** authorize
it: engine/decision binding, recovery-time certificate verification, the anti-rollback
anchor, and activation remain **separate** later work, each gated independently.

**Validation and verdict.** The §13 design makes concrete component-level choices
(not merely "bounded/atomic/validated"), names a consumer for every field, separates
the four checks, decides recovery from observable inputs, preserves D10 and the D13
surviving-write case, and states its exclusions. The QC-derived record design is
complete; **one** record-design obligation is named and left to the successor (TC
recovery-verifiability, above), and the anti-rollback anchor / rollback resistance /
cross-host exclusivity / stage-2 wiring remain **separate** prerequisites explicitly
out of scope. This pass therefore reports a coherent specified component design, with a
single named open sub-case, implemented by nothing:

```
D7D14_CONSENSUS_SAFETY_RECORD_DESIGN=DEFINED-NOT-IMPLEMENTED
```

Preserved unchanged (not reopened):

```
D7D13_CONSENSUS_SAFETY_STATE_DURABILITY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7D11_CONSENSUS_RECOVERY_SIGNING_HISTORY_CONTRACT=DEFINED-NOT-IMPLEMENTED
D7_STATUS=PARTIAL-CODE-TEST / PRODUCTION-LIFECYCLE-UNAVAILABLE
DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED
GENESIS_AUTHORITY_ACTIVATION=DISABLED
PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED
CONFIGURED_AUTHORITY_RELEASE_BINARY_EVIDENCE=NOT-YET-CAPTURED
SECURITY_POSTURE=RS1-OPEN / PUBLIC-DEVNET-NO-GO
```

C4/C5 remain OPEN. No production signing enablement, anchor selection, readiness
promotion, D15 implementation, or Run 423 work is authorized or implied by this
section.