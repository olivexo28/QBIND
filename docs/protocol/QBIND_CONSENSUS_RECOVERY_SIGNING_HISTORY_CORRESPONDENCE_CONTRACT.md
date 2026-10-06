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

**Implementation availability (Run 422 D7-D14).** The design verdict above is preserved as **historical**: it records that this contract pass implemented nothing. An **isolated, disabled-by-default** implementation successor now exists as the `qbind_node::safety_record_store` component (source + scoped acceptance tests under `crates/qbind-node`), implementing the §13.2A encoding/bounded decode, the §13.3A validation (P1–P4 with wire-`height` view binding and the optional explicit `height == round` profile choice; TA1–TA8; evidence carried **unverified**), the §13.4/§13.5 O1–O5 operations under one shared serialization domain with expected-revision fencing and byte-for-byte O5 re-acknowledgement, the §13.2A/§13.7A bounds (measured `size_of::<RetainedGeneration>() = 336 B ≤ 384`), and the accepted H-subset (H2–H12, H16, H18–H25, H26, H27, H30) with unit, real-RocksDB, and child-process evidence. The component is **never** constructed on any production startup/consensus/signing path (backend policy defaults to `Disabled`, MainNet refused), so the still-missing **production integration** — engine/prepared-decision wiring, recovery-time signature verification (stage 2), durable anti-rollback, and activation — remains **unimplemented** and the operative integration posture is unchanged. The operative component status is:

```
D7D14_STORAGE_COMPONENT=IMPLEMENTED-ISOLATED
```

**Correction (Run 422 D7-D14 code-and-test correction pass).** The
`IMPLEMENTED-ISOLATED` token above is **withdrawn** as unsupported and is
**superseded** by `PARTIAL-IMPLEMENTATION`. The reviewed object
(`8f6d332db7eca35f14a2a3160dca9fa1b3eea494`) was a **partial** implementation
whose claimed acceptance subset was **not** established: the shared serialization
domain was an empty value that did not block dependent publication after an
ambiguous/uncertain write; O3/O4/O5 did not enforce the pinned-context /
established-state prerequisite independently of a caller voluntarily invoking
`open` (a foreign-context handle could read/publish); the raw write/inject
bypasses were unrestricted `pub fn`; and several H-row test names did not exercise
the row meaning they claimed. This correction pass closes the shared-uncertainty,
foreign-context, and raw-bypass gaps (with regressions) but does **not** complete
the full accepted subset (opaque validated-publication type, allocation-admission
wiring into O1–O5, the retained `evidence_lock_binding`, the record-level high-QC
encoder discriminant, bounded legacy-namespace classification, the full H-matrix
rename/remap, and coordinated deterministic crash coverage remain outstanding).
The operative component status is therefore:

```
D7D14_STORAGE_COMPONENT=PARTIAL-IMPLEMENTATION
D7D14_STORAGE_ACCEPTANCE=INCOMPLETE
```

**Correction (Run 422 D7-D14 — complete allocation admission at the binding /
backend-read / namespace boundaries, reviewed object
`92d95e4c6448e592b1eca6714bbd288aa825f127`; supersedes the broad "every dependent
allocation/copy" phrasing of the immediately following entry).** The prior entry
claimed structural admission was "moved ahead of **every** dependent component-owned
variable-size allocation/copy." That phrasing was an **overclaim**: three
component-owned allocation/copy paths still ran before any bound. This pass closes
them (with regressions) and does **not** weaken any obligation: **(a)** the public
`compute_evidence_lock_binding` helper is now a **context-checking entry point** — it
runs the single `admit_supporting_evidence` path **before** allocating/encoding the
evidence `cert` scratch, so a direct caller can no longer bypass admission (the
thread-local evidence-encode counter is **0** on an over-bound refusal, **≥ 1** on a
valid call); **(b)** backend `read_checksummed` now reads through `db.get_pinned` — a
borrowed, backend-internal view — and enforces the applicable record-size bound
(record: `MAX_SAFETY_RECORD_BYTES`; metadata: the fixed `2+32+8` bound) on that view
**before** taking the single component-owned copy, refusing an over-bound payload with
`Oversize`; **(c)** `first_unrecognized_safety_key` now scans with a raw iterator that
reads only **borrowed keys** (never materializing values) and returns only the
offending key's **byte length**, so namespace classification copies **zero**
application-owned key/value bytes while remaining bounded by work (`MAX_SCAN = 64`) and
by application-owned bytes. The evidence-encode instrumentation comment now states its
exact, single measurement scope. Admission now precedes these specific
component-owned variable-size allocations/copies; this is **not** a claim that the full
**operational** peak is enforced through the real O1–O5 objects (that remains blocker
(1) below). **Still outstanding (plural blockers):** (1) §13.7A operational
allocation-admission wiring into the real O1–O5 objects/lifetimes with measured
peak/lifetime enforcement and the complete retained-field inventory; (2) §7
deterministic crash coverage (uncertain-init, pre-effectiveness publish, failed/
uncertain O5, complete-content divergence, locked-with-no-commit) with hooks at the
actual boundaries; (3) full §6 original-H-matrix mapping corrections (H12 competing
handles, H21 reuse of `h8_p1_p2_binding_enforced`, H26 real-storage adversarial TC,
H3/H10 crediting/removals); and (4) the independent CodeQL / Code Review security gate.
The default release node build (exit 0) and the production non-wiring audit are
captured this pass; a release build establishes build compatibility, **not**
running-node recovery acceptance. The operative component status therefore **remains**
`D7D14_STORAGE_COMPONENT=PARTIAL-IMPLEMENTATION` /
`D7D14_STORAGE_ACCEPTANCE=INCOMPLETE`.

**Correction (Run 422 D7-D14 — admission-before-allocation / backend-bound
recovery tokens pass, supersedes the "named blocker" framing of the prior D7-D14
entry below).** This pass implements a further part of the accepted subset and does
**not** weaken any obligation; all prior closures below remain in force. Closed this
pass (with regressions): **(a) structural admission is moved ahead of every dependent
component-owned variable-size allocation/copy** — O4 (`publish_locked`) and
`make_locked_qc` now call the single `admit_supporting_evidence` path **before**
`compute_evidence_lock_binding` allocates its evidence `Vec`/encodes the certificate,
so an oversize field (e.g. a 9-byte signature under `S_sig = 8`, or oversized nested
TC signer/timeout/timeout-signature counts) is refused **before** the binding/encode
allocation, not merely before the database write; a test-only thread-local
instrumentation counter incremented at the exact evidence-encode/copy site proves the
counter is still **zero** after a refused operation and non-zero after a valid
publication; **(b) recovery tokens are bound to their originating backend** — the
opaque `ValidatedRecord` now additionally carries a process-local
`recovery_backend_incarnation`; only a successful **O3** (`read_validate`) on an
established backend grants it, O5 (`reacknowledge`) refuses a token whose incarnation
does not match the backend being recovered, and public standalone `validate_decoded`
and the `bootstrap_validated` helper mint **no** O5 recovery capability — so a token
from store A is refused by store B even when pinned context, revision, and publication
bytes are byte-identical, a reopened backend requires a fresh O3 token, and handles
sharing the same backend incarnation may use it. The earlier claim that **operational
allocation-admission wiring was the *sole* remaining blocker is withdrawn.** Partial
§13.7A progress: `RetainedGeneration` now carries `evidence_lock_binding` (charged via
the existing retained-size bound), but the accountant is **still standalone/synthetic**
and is **not** yet driven from the real O1–O5 objects/lifetimes. **Concrete remaining
blockers (not a single blocker):** (1) §13.7A operational allocation-admission wiring
into the real O1–O5 objects/lifetimes with measured peak/lifetime enforcement and the
complete retained-field inventory; (2) §7 deterministic crash coverage for
uncertain-initialization and failed/uncertain-O5 child phases with a pre-install hook
at the actual effectiveness transition and specific termination-outcome verification;
(3) full §6 original-H-matrix reconciliation in the evidence attachment; and (4) the
blocked release build, production non-wiring audit, and security tooling (CodeQL /
independent review) evidence at this revision. The operative component status therefore
**remains** `D7D14_STORAGE_COMPONENT=PARTIAL-IMPLEMENTATION` /
`D7D14_STORAGE_ACCEPTANCE=INCOMPLETE`.

**Correction (Run 422 D7-D14 — recovery lifecycle / opaque publication / unified
admission / TC+namespace pass, corrects `0f258734f1466488c41be814bc76162021c8a948`).**
This pass implements a further tranche of the accepted subset and **tightens** the
implementation to match this contract's §13.4/§13.5 obligations; it does **not**
weaken any obligation. Closed this pass (with regressions): the effectiveness latch
now initializes **not-effective on every open** (a reopened established store carries
**no inherited acknowledgement**; dependent O4 is blocked until an acknowledged O1 or a
successful O5 per §12.3 SW-3→SW-5 / INV-R7) — the earlier evidence-log claim that "a
reopened backend starts clear" satisfies recovery is **withdrawn**; raw
publication/recovery-clearing bypasses are removed (`SerializationDomain` is
non-constructible, `publish_atomic`/`lock_domain` are crate-internal,
`clear_recovery_requirement` is deleted, effectiveness transitions only through the
enforced O1/O4/O5 paths); established-state prerequisites (presence, structure,
**record-revision == metadata-revision**, pinned context) are enforced centrally and
O4 validates its authoritative predecessor; `ValidatedRecord` is **opaque** with a
decoded↔encoded correspondence check and an origin-context binding, so unrelated bytes
cannot acquire validated status and O5 compares the complete original bytes
byte-for-byte; one **structural-admission** path refuses oversize fields (e.g. a 9-byte
signature under `S_sig = 8`) **before** publication; the record-level high-QC presence
discriminant is encoded/charged and the TA1–TA8 identifiers are reconciled (TA2 by
view+block_id only; TA1 byte-identical copy; TA8 unrun); and O1 performs **bounded**
`safetyrec:` namespace classification refusing unknown/legacy/partial keys without
migration/repair. **Still outstanding (the named blocker):** §13.7A **operational
allocation-admission wiring into the real O1–O5 objects/lifetimes** — the accountant
remains standalone/synthetic and `RetainedGeneration` still omits `evidence_lock_binding`
and the other complete-wrapper retained fields, so the operational peak-memory ceiling
is not yet enforced through actual operations. The operative component status therefore
**remains**:

```
D7D14_STORAGE_COMPONENT=PARTIAL-IMPLEMENTATION
D7D14_STORAGE_ACCEPTANCE=INCOMPLETE
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
| `supporting_certificate` — a **discriminated evidence** field with **two** representations (resolving the prior wire-QC-only contradiction, D7-D14): a **`QcDerived`** representation storing the **wire** `QuorumCertificate` (`qbind_wire::consensus::QuorumCertificate` — the form carrying `height`/`round`/`epoch`/`chain_id`/`block_id` + `signer_bitmap` + `signatures` + `suite_id`); **or** a **`TcDerived`** representation storing the TC's **logical** `high_qc` (`qc.rs`: `block_id`/`view`/`signers` only, **no** signatures) **plus** the retained serialized `TimeoutCertificate` (`timeout.rs` ~L232: `signed_timeouts: Vec<TimeoutMsg>`) whose timeout quorum (`two_thirds_vp`) justified the raise (§13.3A) | Engine evidence — for a **QC-derived** raise the inbound **wire** `justify_qc` (available at the proposal boundary; cf. C3F `VerifiedQuorumCertificate`); for a **TC-derived** raise the TC's `high_qc` is **logical-only** (no constituent signatures are carried by the TC on any path), so it is persisted as **unverified** supporting material (§13.3A) | Structural threshold observation + the §13.3A **semantic association** predicates; recovery-time **signature verification** only if wired (stage 2) | Signer-bitmap length ≤ `MAX_BITMAP_LEN` (=8192); `signatures.len()` ≤ `MAX_SIGNATURE_COUNT` (=`u16::MAX`); per-signature length ≤ `MAX_SIGNATURE_LEN` (=`u16::MAX`); threshold `ceil(2W/3)` recomputed in `u128` (reuse `qc_verify_domain` bounds + constants, D7-C3D) | Stored directly | Proves the **evidence that justified** the raise exists and is structurally bounded. For the **`QcDerived`** representation the **wire** `QuorumCertificate` is required (the **logical** `QuorumCertificate` (`qc.rs`: `block_id`/`view`/`signers` only) carries **no** cryptographic material and could never reach a stage-2 verified result). For the **`TcDerived`** representation **no** wire `high_qc` is available on any path, so the record stores the **logical** `high_qc` (identity-only) and the retained `TimeoutCertificate`; it is **stage-2-unverifiable from TC inputs**, carried **unverified** (§13.3A), and the **wire-only** predicates (signer-bitmap/signature-count/per-signature bounds and stage-2 signature verification) are **inapplicable** to it — replaced, where a comparison is still needed, by the logical `high_qc` **identity** predicates (P1/P2 on `high_qc.block_id`/`high_qc.view`) and the retained TC's own timeout-quorum observation. No logical QC is upgraded to a wire QC and no signatures are fabricated; the **wire** form remains what makes stage-2 verification even possible for `QcDerived`. A certificate with an **empty signer list** fails the structural threshold (`ceil(2W/3) ≥ 1`) and is refused **without** cryptography; full signature verification against the trusted validator context is a **separate** stage (T-TRUST-STORAGE), not performed on load today. **TC support (corrected source inventory, D7-D14):** a TC/`signed_timeouts` evidence verifier **does exist and is wired** — `verify_timeout_certificate_with_evidence` (`timeout_verify.rs` ~L350) runs over `tc.signed_timeouts` on every inbound `NewView` **before** `engine.on_timeout_certificate` (`binary_consensus_loop.rs` ~L6892), and the **serialized** `TimeoutCertificate` (`timeout.rs` ~L232, carrying `signed_timeouts: Vec<TimeoutMsg>`) is a real decoded type. That verifier checks the **timeout** signatures, membership/quorum (`two_thirds_vp`), and the **derived `high_qc` identity** (`high_qc_eq`: `view` + `block_id` only, ~L435); it does **not** cryptographically verify the **constituent votes** inside the TC's logical `high_qc`, and it is **not** a persisted-record recovery verifier (and establishes nothing about D14 record recovery, current authority, anti-rollback, or production readiness). The absence of a dedicated **`qbind-wire`** `TimeoutCertificate` type does **not** mean no serialized TC or verifier exists. **Selected evidence rule (§13.3A):** a TC-derived raise carries its `high_qc` only in **logical** form, so its supporting evidence is **not stage-2 wire-QC verifiable** from TC inputs; the lock **restriction** (`lock_block_id`+`lock_view`) is still persisted and enforced, but the record is carried **unverified** and must refuse any verified-evidence prerequisite. No signatures are invented, no logical QC is upgraded to a wire QC, and no verifier is added |
| `evidence_lock_binding` (SHA3-256 digest over {`lock_block_id`,`lock_view`, `supporting_certificate`, `authority_context_ref`}) | Writer at publication (reuse `BindingDigest`/`Sha3_256`, `signing_reservation_journal.rs` ~L221) | Read/validate: **recompute and compare** | 32-byte; recomputed digest must equal the stored digest from the **re-derived** inputs | Stored directly (digest); its **inputs** are re-derived, not trusted from the digest | Proves the stored fields were **published together and are internally un-tampered** relative to the stored digest (integrity/co-publication). Does **not** prove **semantic correspondence**: recomputing the digest does **not** establish that the certificate's own `block_id`/`height` equal `lock_block_id`/`lock_view` (the engine reads `height`, not `round`, as the view), nor that `chain_id`/`epoch`/`suite_id` match the pinned context — those are the **explicit stage-3 predicates** (§13.3A), which a valid CRC and a recomputed digest **do not** substitute for (H21). Does **not** reconstruct the committed bytes or trusted context, and is **not** authentication, authorization, or freshness (a digest ≠ a signature; §5 X3) |
| `committed_state_assoc` (committed block id + height anchor) **— present only in the `Locked`-with-committed-anchor sub-case; absent by variant in `BootstrapNoLock` and `Locked`-with-no-commit** | Engine committed baseline at the transition (**may be genuinely `None`** — a lock can advance via `on_qc` with no three-chain commit: `run_422_d7d2_signing_state_recovery_tests::d7d12_precrash_lock_advances_via_on_vote_without_a_commit`) | Anchoring the lock in **recovered committed state** (§5 X1), when an anchor exists | **Comparison relation (explicit, when present):** the stored anchor `(id, height)` must name a block that is **present in the recovered committed history** at that height (equal id at the anchored height), with `height` via checked arithmetic; the recovered committed baseline **may legitimately be at or beyond** the anchor height (committed progress since the last lock publication is **expected and allowed**), but the anchored block must still be on the recovered committed chain; if the anchor block is **absent** from recovered committed state or the height is **inconsistent**, the comparison **cannot be established** → **refuse**. **When absent by variant** (`Locked`-with-no-commit / `BootstrapNoLock`): the anchor predicate is **skipped** (there is nothing to anchor) — the absence is an **explicit discriminant**, **never** a coerced height-zero or a manufactured committed block, and it is **distinct** from a missing/corrupt anchor on a variant that requires one | **Obtained independently** — compared against recovered committed state; stored as a reference (or **absent by variant**) | Proves the lock's **relation to the committed baseline** when one exists. A genuine **no-commit** lock proves a legitimately uncommitted restriction, **not** a committed anchor. Does **not** prove ancestry of arbitrary candidates (per-candidate, below), and a later committed height does **not** by itself invalidate a present anchor |
| `publication_revision` (`u64`, monotonic) + optional `predecessor_ref` | Writer (single-writer counter) | Ownership **stale-work fencing** (§13.5) and open's **authoritative-record selection** | Strictly increasing under the single writer; checked arithmetic; wrap → **refuse** (no silent reuse) | Stored directly | Proves **ordering among this host's own publications** (local bookkeeping). Does **not** prove whole-copy freshness or anti-rollback — a local revision/counter is **not** an anchor (§12.5; continuity §6.3) |
| `integrity_checksum` (CRC32 over the record payload) | Writer (reuse `compute_crc32` / `signing_journal_crc32`, `storage.rs` ~L531/~L545) | Read: **accidental-corruption** detection | 4-byte; recomputed checksum must match | Stored directly | Proves **accidental-corruption** detection (T-INTEG). Does **not** prove authenticity or authorization (a CRC is **not** a MAC) |
| `bounds_metadata` (declared lengths / counts for the variable-length members) | Writer | Read decode gate | **Concrete bounds, not “fixed maxima”:** `signer_bitmap.len()` ≤ `MAX_BITMAP_LEN` (8192); `signatures.len()` ≤ `MAX_SIGNATURE_COUNT` (`u16::MAX`=65535); per-signature ≤ `MAX_SIGNATURE_LEN` (`u16::MAX`=65535); `lock_block_id`/`committed id`/digests fixed at 32 bytes; `lock_view`/`publication_revision` are `u64` with **checked** increments (wrap → refuse); total record size ≤ a declared `MAX_SAFETY_RECORD_BYTES`, **fixed here as a checked formula over hard-bounded parameters (every width enumerated in the § 13.2A field tables, with actual-length and worst-case stated separately)** (not deferred): the authoritative serialized caps are the **§ 13.2A(f) named caps** `MAX_QC_BYTES` and `MAX_TC_BYTES`, with `MAX_SAFETY_RECORD_BYTES = max(MAX_QC_BYTES, MAX_TC_BYTES)` (checked `u128`); this cell **references** those names and does **not** restate a divergent formula. For the `QcDerived` variant the authoritative cap resolves at the initial profile `C = 2` to **`MAX_QC_BYTES = 269 + B_span + N × (2 + S_sig)`** (§ 13.2A(f): `FIXED_OVERHEAD 153 + anchor 40 + predecessor 8 + QC_FIXED 64 + bitmap-length-prefix 2 + signatures-count-prefix 2 + B_span + N × (2 + S_sig)`), where **`N`** = the pinned authorized-epoch **validator/member count** (so the signature **count** `signatures.len()` ≤ `N`; `N` is a *count*, not voting power), **`B_span`** = the signer-**bitmap identifier span** in bytes, which is `ceil(N/8)` **only under an explicitly established dense-index profile** (members indexed contiguously `0..N-1`) and is otherwise bounded by the **identifier-span bound `qc_verify_domain` already demonstrates** — `MAX_BITMAP_LEN` = 8192 bytes, i.e. the span needed to represent any set bit up to `u16::MAX` (`qc_verify_domain.rs` ~L163, ~L752) — because **sparse / non-dense member identifiers** within the representable span make `ceil(N/8)` insufficient, **`S_sig`** = the pinned signature-suite's per-signature byte length (individual-signature bound; aggregate signature bytes ≤ `N × S_sig`), with the four quantities — **validator count `N`**, **bitmap identifier span `B_span`**, **signature count (`≤ N`)**, and **signature bytes (`≤ N × S_sig`)** — kept explicitly distinct from each other and from **voting power `W`**. For the **`TcDerived`** variant there is **no** wire signer-bitmap or signature vector; its serialized members are the record's **own** logical `high_qc` **and** the retained serialized `TimeoutCertificate` (which carries its **own** second `high_qc`), so the cap is a checked sum over **explicit encoded terms** (not in-memory `size_of` used as a serialization width): **`MAX_TC_BYTES`** (§ 13.2A(f)) `= FIXED_OVERHEAD + [40 + 8]_{anchor+pred} + REC_HIGH_QC + TC_VIEW + TC_TIMEOUT_VIEW + TC_HIGH_QC + TC_SIGNERS + SIGNED_TIMEOUTS` — where **`D_ev` is not re-added** because the evidence discriminant is already one of the always-present rows summed into `FIXED_OVERHEAD = 153` (adding it again would double-count). The **identifier width** `W_id` = the **encoded** width of a `ValidatorId` — a `u64`, **8 bytes** (`ids.rs` ~L29; a compact profile may instead encode a `u16` `validator_index` per `ids.rs` ~L11, but the persisted **logical** form uses the 8-byte id), bounded to `N` distinct members; `C` = the profile's fixed **length/count-prefix** width, **concretely `2` bytes** (`u16`) in the initial profile (§ 13.2A(a), allowed {2,4}, pinned before decode, never read from the record); `D_ev`/`D` = a **1-byte** (`u8`) evidence/`Option`/variant **discriminant**. **All widths are enumerated row-by-row in the § 13.2A field tables; this cell summarizes them.** The retained `TimeoutCertificate` (`timeout.rs` ~L232) also contributes its **two fixed `u64` fields** — **`TC_VIEW`** = `8` (`view`, ~L235) and **`TC_TIMEOUT_VIEW`** = `8` (`timeout_view`, ~L246), **counted explicitly** (previously omitted). **Both `high_qc` copies are charged once each, not shared:** **`REC_HIGH_QC`** = `D + 32 + 8 + (C + N × W_id)` is the **record-level** logical `high_qc` (discriminant + `block_id` 32 + `view` 8 + its **nested** `signers` id list ≤ `N × W_id`), and **`TC_HIGH_QC`** = `D + 32 + 8 + (C + N × W_id)` is the retained `TimeoutCertificate`'s **own** `high_qc` (`timeout.rs` ~L238, identical shape); the two are **distinct serialized occurrences, each counted exactly once**, and the selected rule **requires them byte-identical** (`REC_HIGH_QC`'s `(block_id, view, signers)` == `TimeoutCertificate.high_qc`; §13.3A P1/P2/TA1 compare that **one** identity) — a mismatch → **refuse**, and **neither** copy is silently dropped. The remaining variable terms are: **`TC_SIGNERS`** = `C + N × W_id` (the TC's **own** `signers: Vec<ValidatorId>`, `timeout.rs` ~L241, ≤ `N`); **`SIGNED_TIMEOUTS`** = `C + N × T_msg` (the `signed_timeouts` **count** ≤ `N` entries, `timeout.rs` ~L244), where **`T_msg`** is itself a checked per-entry sum — **not** one pinned `TimeoutMsg` length — over each timeout's fields: `T_msg = 8 (view) + W_id (validator_id) + 1 (suite_id: u8) + (C + S_sig) (signature length prefix + signature bytes ≤ the suite's per-signature length) + D (high_qc discriminant) + [ 32 + 8 + (C + N × W_id) ] (its **optional** `high_qc`: `block_id` 32 + `view` 8 + **nested** `signers` ≤ `N × W_id`, included only when the discriminant is set) + `F` framing (**= 0**, no extra per-message framing, § 13.2A)`. Here `S_sig` bounds **one signature**, **not** the whole `TimeoutMsg`, and the per-entry `suite_id: u8` (`timeout.rs` ~L82) is counted **explicitly** (previously omitted). Every `C`/`D` length/count prefix and discriminant is counted explicitly; and **`FIXED_OVERHEAD`** = the summed fixed-size common rows **derived mechanically in § 13.2A(b) to `153` bytes** (`persistence_format_version` 2 + the four 32-byte ids/digests + `network_genesis_id`/`authority_context_ref` context fields + `lock_view`/`publication_revision` at 8 each + `integrity_checksum` 4 + the always-present evidence/anchor/predecessor discriminants + `F = 0` framing), **not** an unexplained constant. The **quorum** relation `ceil(2W/3)` over total **voting power `W`** is validated separately (threshold observation) and is a *power* sum, kept **distinct** from the *count* `N` that bounds bytes. Every term is summed with **checked** `u128`/`usize` arithmetic; any overflow, or a declared length/count exceeding its term, → **refuse before any application-owned allocation or copy** of the variable-length members. The bound's **source** is the pinned authorized-epoch context (`N`, `S_sig`, `W`), enforced by the reader against the pinned context. The purely structural ceiling `MAX_AGGREGATE_SIGNATURE_BYTES = MAX_SIGNATURE_COUNT × MAX_SIGNATURE_LEN` (≈ 4.29 GB) is retained **only** as the over-read guard — an honest **allocation-bound limitation**, not a buffer size and not the applied cap. The formula bounds **this component's** serialized record; it does **not** bound the storage backend's own internal allocations (that limitation is retained honestly). All offset/length arithmetic is **checked** (no wrap) | Stored directly | Proves the record is **structurally bounded** so decode cannot over-read. Does **not** prove any semantic property. The u16×u16 product is an honest **allocation-bound limitation**, not a usable buffer size |

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

### 13.2A Proposed serialized persistence profile — explicit field, prefix, and contribution tables (Correction 1, D7-D14)

This subsection **replaces** the prior ambiguous inline descriptions of `C`,
"per-message framing," and `FIXED_OVERHEAD` with mechanical tables. It specifies a
**proposed persistence encoding** for the `SafetyRestrictionRecord`, **distinct from**
the existing `qbind-wire` wire encoding (`consensus.rs` ~L304 `WireEncode for
QuorumCertificate`) and from every signing preimage (`timeout.rs`
`timeout_signing_bytes_with_chain_id` ~L155; the Proposal/Vote signing-domain v2
preimage). **No** implementation, wire format, or signing preimage is changed here;
these rows describe only how a future on-disk record *would* be framed so the size
bound derives from named rows rather than an unexplained constant. `MAX_SAFETY_RECORD_BYTES`
is the **serialized** cap (an encoded byte buffer); decoded in-memory footprint is a
**separate** charge accounted in §13.7A, never inferred from this serialized length.

**(a) Profile parameters — fixed before any encode/decode, validated against the pinned
authorized-epoch context, and never accepted as policy from an untrusted record.**

| Parameter | Meaning | Concrete width / initial profile value | Allowed range | Validation rule (reader) |
|---|---|---|---|---|
| `C` | Width of **every** length/count prefix in this profile | **2 bytes** (`u16` prefix), matching the wire encoding's `u16` prefixes (`consensus.rs` ~L316/~L321/~L324) | Fixed element of {`2` (`u16`), `4` (`u32`)}, chosen at profile instantiation; initial profile = **2** | Every count/length this prefixes is independently bounded (≤ `N`, ≤ `MAX_BITMAP_LEN`, ≤ `S_sig`), so a value needing more than `C` bytes → **refuse**. `C` is a pinned constant, **not** read from the record |
| `W_id` | **Encoded** width of a `ValidatorId` | **8 bytes** (`u64`, `ids.rs` ~L29) | Fixed `8` for the logical form (a compact profile may encode a `u16` `validator_index`, `ids.rs` ~L11, but the persisted logical form is 8) | Fixed by profile; distinct from the **in-memory** `size_of::<ValidatorId>()` charged in §13.7A |
| `D` | Width of a `1`-byte discriminant/`Option`/variant tag | **1 byte** (`u8`) | Fixed `1` | Tag must decode to a defined variant; unknown tag → **refuse** (no coercion of `None`) |
| `S_sig` | Pinned signature-suite **per-signature** byte length | Suite constant (e.g. ML-DSA-44); bounds **one** signature, **not** a whole message | `1 ..= MAX_SIGNATURE_LEN` (`u16::MAX` = 65535) | A declared per-signature length `>` the pinned `S_sig` → **refuse** |
| `N` | Pinned authorized-epoch validator/member **count** (a count, not voting power `W`) | Context constant | `1 ..= MAX_SIGNATURE_COUNT` (`u16::MAX` = 65535) | A declared count (signatures, signers, `signed_timeouts`) `>` pinned `N` → **refuse** |
| `F` | **Extra per-record framing** beyond the counted prefixes/discriminants (magic/envelope/trailer) | **0 bytes — stated explicitly: this profile adds no extra framing** (unlike the wire encoding, there is no leading `MSG_TYPE_QC` byte; every structural byte is a named row below) | Fixed `0` | n/a (nothing to validate; no uncounted bytes exist) |

`B_span` (bitmap span in bytes) = `ceil(N/8)` **only** under an explicitly established
**dense-index** profile (members indexed contiguously `0..N-1`); otherwise it is bounded
by the identifier-span bound `qc_verify_domain` already demonstrates, `MAX_BITMAP_LEN`
= `8192` (`qc_verify_domain.rs` ~L163/~L752), because sparse/non-dense identifiers make
`ceil(N/8)` insufficient.

**(b) Common record fields (present in every variant) — these rows sum to `FIXED_OVERHEAD`.**

| Field (owning scope) | Encoded width / formula | Presence | Max count/length | Prefix/discriminant contribution | Named contribution |
|---|---|---|---|---|---|
| `persistence_format_version` (`u16`) | `2` | always | 1 value | none | `+2` |
| `network_genesis_id` (`[u8;32]`) | `32` | always | fixed 32 | none | `+32` |
| `authority_context_ref` (32-byte descriptor digest) | `32` | always | fixed 32 | none | `+32` |
| `lock_block_id` (`[u8;32]`) | `32` | always | fixed 32 | none | `+32` |
| `lock_view` (`u64`) | `8` | always | 1 value | none | `+8` |
| `evidence_lock_binding` (SHA3-256) | `32` | always | fixed 32 | none | `+32` |
| `publication_revision` (`u64`) | `8` | always | 1 value | none | `+8` |
| `integrity_checksum` (CRC32) | `4` | always | fixed 4 | none | `+4` |
| evidence discriminant `D_ev` | `D = 1` | always | 1 tag | `QcDerived` vs `TcDerived` | `+1` |
| committed-anchor presence discriminant `D_ca` | `D = 1` | always | 1 tag | gates the anchor payload in (d) | `+1` |
| predecessor presence discriminant `D_pred` | `D = 1` | always | 1 tag | gates `predecessor_ref` in (d) | `+1` |
| per-record framing `F` | `0` | always | — | **explicit zero** | `+0` |

**`FIXED_OVERHEAD` = 2 + 32 + 32 + 32 + 8 + 32 + 8 + 4 + 1 + 1 + 1 + 0 = `153` bytes**
— derived **mechanically** from the named rows above, **not** an unexplained constant.

**(c) Committed-anchor and predecessor-reference representations (present-only payloads,
gated by their always-present discriminants in (b)).**

| Field (owning scope) | Encoded width / formula | Presence condition | Max count/length | Prefix/discriminant | Named contribution |
|---|---|---|---|---|---|
| `committed_state_assoc` = committed `block_id` (`[u8;32]`) + `height` (`u64`) | `32 + 8 = 40` | only when `D_ca` set (`Locked`-with-committed-anchor) | fixed 40 | discriminant counted in (b) | `+40` when present, else `+0` |
| `predecessor_ref` (`u64` revision) | `8` | only when `D_pred` set | 1 value | discriminant counted in (b) | `+8` when present, else `+0` |

**(d) `QcDerived` supporting certificate (the stored wire `QuorumCertificate`,
`consensus.rs` ~L282) — fixed members, then every count/length prefix and the per-signature
prefix charged in the variable part.**

| Field (owning variant) | Encoded width / formula | Presence | Max count/length | Prefix/discriminant | Named contribution |
|---|---|---|---|---|---|
| `version` (`u8`) | `1` | `QcDerived` | 1 | none | `+1` |
| `chain_id` (`u32`) | `4` | `QcDerived` | 1 | none | `+4` |
| `epoch` (`u64`) | `8` | `QcDerived` | 1 | none | `+8` |
| `height` (`u64`) | `8` | `QcDerived` | 1 | none | `+8` |
| `round` (`u64`) | `8` | `QcDerived` | 1 | none | `+8` |
| `step` (`u8`) | `1` | `QcDerived` | 1 | none | `+1` |
| `block_id` (`[u8;32]`) | `32` | `QcDerived` | fixed 32 | none | `+32` |
| `suite_id` (`u16`) | `2` | `QcDerived` | 1 | none | `+2` |
| **`QC_FIXED` subtotal** | `1+4+8+8+8+1+32+2 = 64` | — | — | — | **`+64`** |
| `signer_bitmap` outer length prefix | `C = 2` | `QcDerived` | prefix | **count/length prefix** | `+C` |
| `signer_bitmap` bytes | `B_span` | `QcDerived` | ≤ `ceil(N/8)` (dense) else ≤ `MAX_BITMAP_LEN` (8192) | — | `+B_span` |
| `signatures` outer count prefix | `C = 2` | `QcDerived` | prefix | **outer count prefix** | `+C` |
| per-signature length prefix × count | `C` per entry | `QcDerived` | ≤ `N` entries | **per-entry prefix — NOT fixed overhead** | `+ N × C` |
| per-signature bytes × count | ≤ `S_sig` per entry | `QcDerived` | ≤ `N` entries | — | `+ N × S_sig` |

`QcDerived` variable part `QC_VAR = C + B_span + C + N × (C + S_sig)` — the outer bitmap
prefix, the bitmap span, the outer signature count, and, for **each** of the ≤ `N`
signatures, **its own length prefix `C` plus ≤ `S_sig` bytes**. The per-entry `C` is
multiplied by the count and is therefore **variable, never folded into `FIXED_OVERHEAD`**.

**(e) `TcDerived` supporting evidence (the record-level **logical** `high_qc` plus the
retained serialized `TimeoutCertificate`, `timeout.rs` ~L232). Both `high_qc` copies are
charged **once each** and the selected rule requires them byte-identical.**

| Field (owning variant / nesting) | Encoded width / formula | Presence | Max count/length | Prefix/discriminant | Named contribution |
|---|---|---|---|---|---|
| record-level `high_qc` discriminant | `D = 1` | `TcDerived` | 1 tag | Option/variant tag | `+D` |
| record-level `high_qc.block_id` (`[u8;32]`) | `32` | when set | fixed 32 | none | `+32` |
| record-level `high_qc.view` (`u64`) | `8` | when set | 1 | none | `+8` |
| record-level `high_qc.signers` count prefix + ids | `C + N × W_id` | when set | ≤ `N` ids | **count prefix** | `+ C + N × W_id` |
| **`REC_HIGH_QC` subtotal** | `D + 32 + 8 + (C + N × W_id)` | — | — | — | **record-level copy #1** |
| `TimeoutCertificate.view` (`u64`, ~L235) | `8` | `TcDerived` | 1 | none | **`TC_VIEW` = +8** |
| `TimeoutCertificate.timeout_view` (`u64`, ~L246) | `8` | `TcDerived` | 1 | none | **`TC_TIMEOUT_VIEW` = +8** |
| `TimeoutCertificate.high_qc` (Option, ~L238) | `D + [32 + 8 + (C + N × W_id)]` | discriminant always; payload when set | ≤ `N` ids | Option tag | **`TC_HIGH_QC`** — copy #2, **byte-identical to copy #1** or **refuse** |
| `TimeoutCertificate.signers` (`Vec<ValidatorId>`, ~L241) | `C + N × W_id` | `TcDerived` | ≤ `N` | **count prefix** | **`TC_SIGNERS`** |
| `TimeoutCertificate.signed_timeouts` (`Vec<TimeoutMsg>`, ~L244) | `C + Σ T_msg` over ≤ `N` entries | `TcDerived` | ≤ `N` entries | **outer count prefix** | **`SIGNED_TIMEOUTS`** |

Per-entry `T_msg` (one `TimeoutMsg`, `timeout.rs` ~L72) — **not** one pinned length:

| `TimeoutMsg` field | Encoded width / formula | Presence | Prefix/discriminant | Named contribution |
|---|---|---|---|---|
| `view` (`u64`, ~L75) | `8` | always | none | `+8` |
| `high_qc` (Option, ~L78) | `D + [32 + 8 + (C + N × W_id)]` | discriminant always; payload when set | Option tag | `+D (+ nested high_qc when set)` |
| `validator_id` (`ValidatorId`, ~L80) | `W_id = 8` | always | none | `+8` |
| `suite_id` (`u8`, ~L82) | `1` | always | none | `+1` **(previously omitted)** |
| `signature` (`Vec<u8>`, ~L84) | `C + ≤ S_sig` | always | **length prefix** | `+ C + S_sig` |
| per-entry framing | `F = 0` | always | **explicit zero** | `+0` |

Worst-case `T_msg = 8 + (D + 32 + 8 + C + N × W_id) + W_id + 1 + (C + S_sig) + 0`.

**(f) Actual-length and worst-case totals (stated separately; every stored byte appears
exactly once).**

* **Actual length** uses the record's **real** present discriminants and **real** counts
  (`k ≤ N` signatures/signers, real signature lengths `s_i ≤ S_sig`, optional members
  present only when their discriminant is set). No parameter is inflated to its maximum.
* **Worst case** substitutes `N` for every count, `S_sig` for every signature, and treats
  every optional discriminant as **set** (all payloads present):
  * `QcDerived` — **named cap `MAX_QC_BYTES`**: `MAX_QC_BYTES = FIXED_OVERHEAD + [40 + 8]_{anchor+pred} + QC_FIXED + QC_VAR` where `QC_FIXED = 64` and `QC_VAR = C + B_span + C + N × (C + S_sig)`. **Resolving the initial profile `C = 2` against the (b)/(c)/(d) rows** (`FIXED_OVERHEAD = 153`, anchor `40`, predecessor `8`, `QC_FIXED = 64`, bitmap-length prefix `2`, signatures-count prefix `2`): `MAX_QC_BYTES = 153 + 40 + 8 + 64 + 2 + B_span + 2 + N × (2 + S_sig)` = **`269 + B_span + N × (2 + S_sig)`**. This is the worst case with **both** optional payloads present; the actual-length form uses the record's real present discriminants and real counts.
  * `TcDerived` — **named cap `MAX_TC_BYTES`**: `MAX_TC_BYTES = FIXED_OVERHEAD + [40 + 8]_{anchor+pred} + REC_HIGH_QC + TC_VIEW + TC_TIMEOUT_VIEW + TC_HIGH_QC + TC_SIGNERS + SIGNED_TIMEOUTS`, with `SIGNED_TIMEOUTS = C + N × T_msg`. The `N × (N × W_id)` nested-`high_qc` signer term inside `SIGNED_TIMEOUTS` is the `O(N²)` worst case and is charged explicitly. **`D_ev` is NOT added here**: the evidence discriminant is already one of the always-present `(b)` rows summed into `FIXED_OVERHEAD = 153`, so adding it again would double-count it. Every other term is a `(b)/(c)/(e)` row counted exactly once.
  * **Authoritative cap each reader enforces.** `MAX_SAFETY_RECORD_BYTES` is the **checked maximum across variants**, `MAX_SAFETY_RECORD_BYTES = max(MAX_QC_BYTES, MAX_TC_BYTES)`, computed in checked `u128`. A reader that has already decoded the evidence discriminant enforces the **variant-specific** cap (`MAX_QC_BYTES` for `QcDerived`, `MAX_TC_BYTES` for `TcDerived`); a pre-discriminant size gate (e.g. the encoded-buffer admission in §13.7) enforces the cross-variant `MAX_SAFETY_RECORD_BYTES`. These are the **only** operative serialized caps; §13.2 `bounds_metadata`, INV-D14-7, H26, and the continuity-contract summary **reference these names** rather than restating a formula.

Every `C` and `D` is a named row; the only byte not attributable to a row is `F = 0`.
All sums are **checked** `u128`/`usize`; any overflow, or a declared length/count
exceeding its term, → **refuse before any application-owned allocation or copy** of the
variable-length members. The purely structural ceiling `MAX_AGGREGATE_SIGNATURE_BYTES =
MAX_SIGNATURE_COUNT × MAX_SIGNATURE_LEN` (≈ 4.29 GB) is retained **only** as the over-read
guard — an honest **allocation-bound limitation**, not a buffer size and not the applied
cap. This formula bounds **this component's** serialized record; it does **not** bound the
storage backend's own internal allocations (that limitation is retained honestly).

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
3. **Context binding and semantic association (context / association validation)** —
   the **explicit predicates of §13.3A**: `network_genesis_id` / `authority_context_ref`
   match the **independently pinned** genesis + validator context, **and** the
   certificate's own fields **semantically correspond to the lock** —
   `supporting_certificate.block_id == lock_block_id`,
   `supporting_certificate.height == lock_view` (the engine's `height`→view interpretation, **not** a `round`→view
   interpretation), and the certificate's `chain_id`/`epoch`/`suite_id` match the pinned
   context. The `evidence_lock_binding` recompute is an **integrity / co-publication**
   check over the writer's own inputs and is **not** one of these semantic predicates: a
   valid CRC and a recomputed digest **do not** substitute for them (H21). Proves
   association/interpretability, **not** authenticity.
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
  The existing TC evidence verifier `verify_timeout_certificate_with_evidence`
  (`timeout_verify.rs` ~L350) is a **NewView-time** gate over `tc.signed_timeouts`, **not**
  a persisted-record recovery verifier, and it does not verify the TC `high_qc`'s
  constituent votes (§13.3A); recovery-time stage-2 wire-QC verification remains the
  named obligation for the QC-derived path.
* **Decision→evidence binding.** Action/operation types carry **only** header fields
  and do **not** carry the lock/evidence that justified a decision (§12.3); binding
  them is a proposed requirement (§13.6), not an existing capability.
* **The safety-scoped synced-atomic publication interface** (§13.1) does **not** exist,
  although the underlying **atomic-plus-sync pattern does** (D10's
  `put_signing_record_and_metadata_synced`, `storage.rs` ~L1417). The missing element is
  the **safety-state-specific** interface with its validation/ownership integration; it
  must **not** be routed through the epoch-only synced API or the D10 journal's API.

### 13.3A Semantic association predicates and the selected TC-derived evidence rule

**Every required association names Value A, an independent Value B, the exact predicate,
the phase, the failure/unavailable behavior, and what a match proves (and leaves
unproven).** These predicates are traced to the **actual** wire↔logical conversion, not
inferred from field names: `qc_verify_domain` reconstructs each `Vote` from the wire QC's
**own** `epoch`/`height`/`round`/`chain_id`/`block_id` (`qc_verify_domain.rs` ~L976), and
`basic_hotstuff` sets `header.round = current_view` (`basic_hotstuff_engine.rs` ~L1180). **But the lock's logical view is NOT sourced from the wire QC's `round`:**
the engine's wire→logical QC conversion reads the certificate's **`height`** into the logical
QC **view** — `QuorumCertificate::new(wire_qc.block_id, wire_qc.height, vec![])` (`basic_hotstuff_engine.rs` ~L1771, the legacy `ingest_proposal` path) and `QuorumCertificate::new(evidence.certificate().block_id, evidence.certificate().height, …)` (`hotstuff_state_engine.rs` ~L866, the verified `register_block_with_verified_justification` path) — so `locked_qc.view` / `lock_view` is sourced from the certificate's **`height`**, **not** its `round` (the logical `QuorumCertificate.view` field, `qc.rs` ~L33, is populated from the wire `height`). The emitter happens to set `height == round == view` for **locally-originated** messages (`basic_hotstuff_engine.rs` ~L1503/~L1522/~L1557), but that equality is an **emitter property**, **not** an input-boundary guarantee: at a general input boundary `height` and `round` may differ and the engine uses **`height`**. The wire QC has **no** `view` field.

| # | Association | Value A (source) | Value B (independent source) | Predicate | Phase | Failure / unavailable input | Match proves / leaves unproven |
|---|---|---|---|---|---|---|---|
| P1 | **Block identity** | `supporting_certificate.block_id` (wire QC `Hash32`, the certificate's own field) | `lock_block_id` (record `[u8;32]`, from engine `locked_qc` identity) | byte-equal | Stage 3 (O3 read-validate) | mismatch, or certificate missing → **refuse** | Proves the certificate certifies the **locked block**. Leaves unproven: certificate authenticity (stage 2) and current authority (stage 4) |
| P2 | **View interpretation** | `supporting_certificate.height` (wire QC `u64`; the field the engine reads into the logical QC **view** — `QuorumCertificate::new(…, wire_qc.height, …)` at `basic_hotstuff_engine.rs` ~L1771 and `…, evidence.certificate().height, …` at `hotstuff_state_engine.rs` ~L866) | `lock_view` (record `u64`, from `locked_qc.view`) | `height` equals `lock_view` (the engine's `height`→view interpretation; the wire `round` is **not** read as the view) | Stage 3 (O3) | mismatch → **refuse**; a certificate with `height != lock_view` is rejected **even if** its `round == lock_view` | Proves the certificate's **height-encoded view** equals the restriction view. Leaves unproven: liveness/safety of any candidate beyond that view, and that `height == round` (the latter is an **additional** eligibility check, below, not established by P2) |
| P3 | **Committed anchor** (only when `committed_state_assoc` is present) | stored `committed_state_assoc` `(id, height)` and `supporting_certificate.height` | the **recovered committed-history** block id at that height (supplied to O3, §13.4) | anchored `(id, height)` is present on the recovered committed chain (equal id at that height); recovered baseline may be **≥** the anchor height | Stage 3 (O3), **requires the recovered-committed-state input** | anchor absent / height inconsistent / **recovered committed history not supplied** → **refuse** (comparison cannot be established). For a `Locked`-with-no-commit record there is **no** anchor and this predicate is **skipped**, not faked | Proves the lock's **relation to committed state**. Leaves unproven: per-candidate ancestry (checked per candidate) |
| P4 | **Context / domain** | `supporting_certificate.chain_id` + `epoch` + `suite_id` (wire QC fields) | the pinned `network_genesis_id` + `authority_context_ref` (`ExpectedGenesisIdentity::load_pinned`) | match the independently pinned context | Stage 3 (O3) | mismatch → **refuse** (`ValidationPolicyMismatch`-style) | Proves **which** validator set/threshold/suite interprets the QC. Leaves unproven: authenticity and current authority |

A valid **CRC32** (`integrity_checksum`) and a recomputed **SHA3-256**
(`evidence_lock_binding`) are retained as corruption / co-publication checks over their
**own** inputs and are **not** a substitute for P1–P4 (that substitution is exactly the
H21 defect): the binding commits to the lock and certificate as opaque byte blobs and
proves they were written together un-tampered, **not** that the certificate's internal
`block_id`/`round`/context fields semantically equal the lock's. P1–P4 are therefore
checked **explicitly** at stage 3, on the certificate's **own** decoded fields, against
**independent** sources. **Additional `height == round` eligibility check (PROPOSED, with source/scope).** P2 binds only `height == lock_view`, because `height` is the field the engine actually reads into the logical view. If the supported persistence profile additionally wants to require `height == round` on a stored certificate, that is an **explicit additional eligibility predicate**, **not** an existing verifier guarantee: `verify_quorum_certificate_with_domain` reconstructs each `Vote` from the QC's **own** `height` **and** `round` verbatim (`qc_verify_domain.rs` ~L976) and so binds a signature to whatever pair the certificate carries — it does **not** check `height == round`. The equality is **sourced** only from the **emitter**, which sets `header.height == header.round == current_view` for locally-originated proposals/QCs (`basic_hotstuff_engine.rs` ~L1503/~L1522/~L1557), mirrored by the continuity contract's message-admission refusal (`height != view` **or** `round != view`, continuity § 3 field table). Its **scope** is therefore the locally-originated-message boundary, not a property the stored-record verifier can assume; a profile that adopts it must enforce it as its own stage-3 predicate (`height == round`, refuse otherwise) and state that it rejects certificates where the two diverge. **Proposed acceptance counterexample (`height != round`; design case, not an executed test).** A future stored certificate carries `height = Hh`, `round = Rr` with `Hh != Rr`, `block_id == lock_block_id`, and `Hh == lock_view`. P2 (`height == lock_view`) **accepts** the view binding because the engine's logical view is `Hh`; a certificate instead carrying `round == lock_view` but `height != lock_view` is **rejected by P2** (it binds `height`, not `round`). If — and only if — the profile has adopted the additional `height == round` predicate, that predicate **additionally rejects** the `Hh != Rr` certificate at stage 3; without that predicate the record is admitted on the `height`-encoded view alone. This is labelled a **proposed acceptance case**, not an executed result.

**TC-derived semantic-association predicates (explicit, separately named).** For a
`TcDerived` record the following checks link, by distinct names, the **recovered logical
lock** (`lock_block_id`/`lock_view`), the **retained `TimeoutCertificate.high_qc`**, and
the **high-QC selection derived from the retained `signed_timeouts`**. They are traced to
`timeout.rs`, `timeout_verify.rs`, and the engine consumer; none invents a rule.

| # | Association | Value A (source) | Value B (independent source) | Predicate | Phase | Failure / unavailable input | Proves / leaves unproven |
|---|---|---|---|---|---|---|---|
| TA1 | **Lock ↔ TC `high_qc` identity** | recovered lock `(lock_block_id, lock_view)` (engine `locked_qc` identity, set from `tc.high_qc` by `on_timeout_certificate` — `set_locked_qc(tc_high_qc.clone())`, `basic_hotstuff_engine.rs` ~L2185) | retained `TimeoutCertificate.high_qc` `(block_id, view)` (`timeout.rs` ~L238) | `high_qc.block_id == lock_block_id` **and** `high_qc.view == lock_view` (byte/number equal) | Stage 3 (O3) | `high_qc` absent with a present lock, or mismatch → **refuse** (a TC with no `high_qc` cannot justify a lock) | Proves the retained TC's `high_qc` is the lock's justification; the record's **own** logical `high_qc` copy (`REC_HIGH_QC`, §13.2) is **required byte-identical** to this `TimeoutCertificate.high_qc` (both copies charged once, §13.2) and a mismatch → **refuse** (neither silently dropped). Leaves unproven: the `high_qc`'s own constituent-vote authenticity (not carried) |
| TA2 | **TC `high_qc` ↔ derived max over `signed_timeouts`** | `tc.high_qc` identity | `select_max_high_qc(tc.signed_timeouts)` — the deterministic maximum-by-`view` `high_qc` over the retained evidence (`timeout.rs` ~L410; `verify_timeout_certificate_with_evidence` step 5, `timeout_verify.rs` ~L419) | `high_qc_eq`: `None == None`, else `view` **and** `block_id` equal (`timeout_verify.rs` ~L435) | Stage 3 (O3) | mismatch → **refuse** (`HighQcMismatch`) | See the absent/equal-view/inconsistent-identity handling below. Proves `tc.high_qc` is the max-view `high_qc` the retained timeouts carry. Leaves unproven: a canonical choice among conflicting equal-view `high_qc`s |
| TA3 | **Signer uniqueness** | `tc.signers` | the `signed_timeouts` `validator_id` multiset | no duplicate `ValidatorId` in `tc.signers` (step 1b, `timeout_verify.rs` ~L371) **and** none in evidence (step 1c ~L382) | Stage 3 (O3) | duplicate → **refuse** (`DuplicateSigner`) | Proves each signer is counted once. Leaves unproven: membership/power (TA4/TA7) |
| TA4 | **Authorized signer membership** | each `tc.signers` id and each `signed_timeouts.validator_id` | the **pinned** authorized-epoch validator set (`ExpectedGenesisIdentity::load_pinned`) | every id is a set member (`verify_timeout_msg` ~L252 `UnknownValidator`; `TimeoutCertificate::validate` ~L364 `NonMemberSigner`) | Stage 3 (O3) | non-member → **refuse** | Proves only authorized members contributed. Leaves unproven: that the member is the **current** authority (stage 4) |
| TA5 | **Signer-set correspondence** | `tc.signers` (as a set) | the `signed_timeouts` `validator_id` set | the evidence set is a **permutation** of `tc.signers` — no extras, no missing, equal cardinality (step 1c, `timeout_verify.rs` ~L385–L391) | Stage 3 (O3) | mismatch → **refuse** (`EvidenceMismatch`) | Proves the claimed signer set equals the evidence's actual signers |
| TA6 | **Timeout-view consistency** | each `signed_timeouts` entry's `view` | `tc.timeout_view` | every entry `view == tc.timeout_view` (step 2, `timeout_verify.rs` ~L396) | Stage 3 (O3) | mismatch → **refuse** (`MixedView`) | Proves all evidence timeouts are for the one view the TC certifies |
| TA7 | **Quorum-weight accounting (power, not count; not authentication)** | accumulated **voting power** of the **claimed** signer set `tc.signers` (summed from each member's `voting_power` by the **logical** `TimeoutCertificate::validate`, `timeout.rs` ~L362–L376, over the claimed signers — **no** signatures are checked at this stage) | `validators.two_thirds_vp()` | accumulated power ≥ `two_thirds_vp()` (`timeout.rs` ~L380–L386; mirrored by `verify_timeout_certificate_with_evidence` step 4, `timeout_verify.rs` ~L411) | Stage 3 (O3) | below threshold → **refuse** (`InsufficientQuorum`) | With TA3 (uniqueness), TA4 (membership), and TA5 (signer-set correspondence), membership/uniqueness/correspondence and power summation establish the **quorum weight of the claimed signer set** — the power sum `W` kept **distinct** from the signer **count** `N` (entries in `tc.signers`); a count quorum is **never** substituted for a power quorum. They do **not** authenticate **timeout participation**: that requires successful **per-entry timeout-signature verification** against the trusted context (`verify_timeout_msg` inside `verify_timeout_certificate_with_evidence`, `timeout_verify.rs` ~L238/~L404 — the separate cryptographic stage, TA8). Even authenticated timeouts do **not** authenticate the logical `high_qc`'s **constituent votes** (not carried). Leaves unproven: timeout-signature authenticity (separate stage) and the `high_qc`'s own QC-threshold (observed separately) |

**Absent high-QCs, equal-view candidates, and inconsistent identities (TA2, as the code
actually behaves).** `select_max_high_qc` **skips** every `signed_timeouts` entry whose
`high_qc` is `None` (`timeout.rs` ~L419); if **all** entries are `None` the derived max is
`None`, so `tc.high_qc` must also be `None` or TA2 refuses. Among present candidates it keeps
the **first-encountered** candidate at the maximum view (**strict** `qc.view > max_view`,
`timeout.rs` ~L420), so selection among **equal-view** candidates is **iteration-order
dependent** and the existing code does **not** compare `block_id` to break the tie. Two
equal-view entries carrying **different** `block_id`s are therefore **not** detected or
rejected by `select_max_high_qc`; whichever iterates first becomes the derived max and
`tc.high_qc` must equal exactly that. This is a **recorded limitation**, **not** an invented
tie-break: the design does **not** attribute a deterministic equal-view tie-break to the
existing code, and a deployment that needs equal-view determinism must add one **explicitly**
and label it; until then a `TcDerived` record whose evidence holds conflicting equal-view
`high_qc`s is admitted only on the first-seen selection (never silently “corrected”).

**Structural/semantic vs cryptographic separation (TA8).** TA1–TA2 and TA5–TA6 are
**structural/semantic identity and set** checks; TA3 (no-duplicate), TA4 (membership) and
TA7 (power) are the **logical** validations `TimeoutCertificate::validate` performs with
**no** signatures (`timeout.rs` ~L353); the **timeout signature** cryptography is a
**separate** per-entry check by `verify_timeout_msg` (suite + preimage + signature,
`timeout_verify.rs` ~L238) inside `verify_timeout_certificate_with_evidence`. A valid
`integrity_checksum` (CRC32), a recomputed `evidence_lock_binding` (SHA3-256), or lock
fields that merely match **do not** admit TC evidence: they are corruption/co-publication
checks over opaque bytes and are **not** a substitute for TA1–TA7 (the H21 defect applied to
TC evidence). Unrelated TC evidence carrying a valid CRC/digest is **refused** at TA1/TA2/TA5.

**Engine-consumer note (what the live engine actually does).** The live
`on_timeout_certificate` (`basic_hotstuff_engine.rs` ~L2162) calls **only** `tc.validate()`
(the logical TA3/TA4/TA7 over `tc.signers`, ~L2167) and then raises the lock directly from
`tc.high_qc` when `tc_high_qc.view > locked.view` (**strict**, ~L2177–L2185); it does
**not** itself invoke `verify_timeout_certificate_with_evidence` (TA2/TA5/TA6 and the
timeout-signature cryptography), which runs **earlier** at the inbound `NewView` boundary
(`binary_consensus_loop.rs` ~L6892). The D14 **recovery** design therefore specifies
TA1–TA8 as the stored-record checks the successor performs at O3; it does **not** claim the
engine's in-memory lock raise already performs them. Recovery **never** satisfies a
verified-evidence prerequisite from TA1–TA8 alone — the timeout signatures authenticate the
**timeouts**, not the `high_qc`'s constituent votes — so a `TcDerived` record stays
**unverified** by the selected rule below.

**Selected TC-derived evidence rule.** For a **TC-derived** lock raise the TC carries its
`high_qc` only in **logical** form (`timeout.rs`: `high_qc: Option<QuorumCertificate>`
with `block_id`/`view`/`signers` and **no** constituent signatures), on **every** path —
the inbound `NewView` `TimeoutCertificate` and each `signed_timeouts` entry carry logical
`high_qc`s. `verify_timeout_certificate_with_evidence` authenticates the **timeout**
signatures and matches the derived `high_qc` **identity** (`view`+`block_id`), but it does
**not** authenticate the `high_qc`'s **constituent votes**; there is thus **no** wire-form
`high_qc` with signer bitmap + signatures available to persist for a TC-derived raise.
The selected rule is therefore: **persisting and enforcing the lock restriction**
(`lock_block_id`+`lock_view`) does **not** require verified
wire-QC supporting material and is **allowed** for a TC-derived raise; but reaching
**stage-2 verified evidence** does require an independently available **wire** `high_qc`,
which TC inputs do **not** supply, so a TC-derived record is carried **unverified** and
**must refuse** any verified-evidence prerequisite on the protected recovery path. This is
a **selected** rule, not invented evidence: no signatures are fabricated, no logical QC is
upgraded to a wire QC, and no verifier is added. **Persisting/enforcing a lock restriction is not claimed to "only narrow voting":** `is_safe_to_vote_on_block` (`basic_hotstuff_engine.rs` ~L1312) depends on **both** the lock **view** and the candidate's **block ancestry** relative to `lock_block_id`, so replacing one effective lock with another does **not** in general preserve a subset of the previously eligible candidates (a different `lock_block_id` can make previously-ineligible candidates eligible and vice-versa). The record therefore persists and enforces the restriction without asserting monotone narrowing. It keeps **persisting a lock restriction**
distinct from **authenticating or replaying the entire TC-driven view-change event**
(the latter would require the constituent-vote cryptography the TC does not carry). The
only implementation choice left to the successor is **mechanical**: if a future wire path
ever carries the `high_qc` with its constituent signatures, that wire form becomes the
stage-2-verifiable `supporting_certificate`; until then TC-derived locks stay
restriction-only / unverified by this selected rule (§13.9). **O3/O4/O5 for each representation.** O3 decodes and validates the **variant-correct** evidence: for `QcDerived` it runs stages 1 and 3 on the wire QC (bitmap/signature bounds, threshold observation, P1/P2/P4 on the wire fields) and stage 2 only if wired; for `TcDerived` the wire-only structural bounds are **inapplicable**, so it validates the logical `high_qc` **identity** (P1 `high_qc.block_id == lock_block_id`, P2 `high_qc.view == lock_view`), observes the retained TC's timeout quorum, binds context (P4) from the pinned context (the logical `high_qc` carries **no** `chain_id`/`epoch`/`suite_id`, so P4's Value A is the record's own `authority_context_ref`, not the certificate), and returns the record **explicitly unverified** — it must **not** satisfy a verified-evidence prerequisite. O4 publishes either representation through the one synced-atomic unit; a `TcDerived` record is **effective** as a durable **restriction** but never admits a verified-evidence-dependent use. O5 re-acknowledges by the **complete-content** comparison of §13.4/§13.5, which spans the **evidence discriminant and its variant-specific supporting material** (the wire-QC bytes for `QcDerived`; the logical `high_qc` + the retained `TimeoutCertificate` bytes for `TcDerived`): a discriminant difference, a differing retained TC, or any other content divergence → **refuse**; and O5 still refuses a **stale** publication (expected revision no longer current) so an older recovered record of **either** representation cannot overwrite a newer stored one.

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
* *Inputs:* the durable bytes **and the independent inputs every validation needs** —
  the **pinned genesis/validator context** (`ExpectedGenesisIdentity::load_pinned`, for
  the stage-3 context and semantic predicates P1–P4) and, **only** when the candidate is
  a `Locked`-with-committed-anchor record, the **recovered committed-history baseline**
  (a read-only **committed-history relation** that, given an `(id, height)` anchor, answers whether that id is the committed block at that height on the recovered chain —   a **PROPOSED** interface, **not** an existing production service; opening the consensus DB does **not** itself supply it. **No existing method realizes this relation.** The nearest existing code, the **harness** `load_persisted_state` (`hotstuff_node_sim.rs` ~L2035), only **loads the last committed block and its associated QCs** (`get_last_committed` → `get_block` → `get_qc`/embedded `block.qc`, reconstructing a QC-derived lock) for the **D12 harness restart** path; it does **not** answer arbitrary older-anchor membership — it establishes **nothing** about whether a given `(id, height)` is the committed block at an **older** height in recovered committed history. The committed-history relation therefore remains **explicitly proposed and independently supplied**; if it is unavailable the dependent comparison (P3) **cannot succeed** and O3 refuses) for the
  `committed_state_assoc` comparison (P3). O3 performs **no** comparison against an input
  it was not given: if a required independent input is **unavailable** (pinned context, or
  recovered committed history for an anchored record), the dependent predicate **cannot be
  established → refuse**. The durable bytes **alone** are **not** sufficient inputs. This
  does **not** claim ordinary production startup reconstructs committed/lock history: ordinary production startup constructs a **fresh** `BasicHotStuffEngine::new` (`binary_consensus_loop.rs` ~L2493) that restores **nothing**; a **requested restore** may supply `initialize_from_snapshot_baseline` (a committed baseline only, **no** lock); and the **harness** `load_persisted_state` (D12) is the only path that
  reconstructs committed state + a QC-derived lock (D7-D2). The P3 committed-history input must therefore be **independently supplied** to O3 (and labelled **proposed** where no production producer exists), with its consistency assumption stated — the supplied relation reflects the **same** recovered committed chain the reader opened, read-only and internally consistent — and bounded by the lookup's own cost (a single `(id, height)` membership check, no unbounded scan); a `BootstrapNoLock` or
  `Locked`-with-no-commit record supplies **no** anchor and P3 is **skipped**, not faked.
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
  comparing the **complete authoritative content** (the whole **retained original validated
  publication** — the complete O3-validated encoded record retained verbatim in `ENC_INPUT` and
  kept live through O5, § 13.7A(c.5) — and its supporting material) against the **currently stored
  publication** (read back as operand 2),
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
* **`Locked` variant** (an effective lock has been published) — in **two** explicit
  committed sub-cases distinguished by a discriminant, **never** by coercing `None`. **Orthogonally, every `Locked` record also carries an evidence discriminant** — **`QcDerived`** (the wire `supporting_certificate`, stage-2-verifiable) **or** **`TcDerived`** (the logical `high_qc` identity + the retained `TimeoutCertificate`, carried **unverified**; the wire-only signer-bitmap/signature-count/per-signature bounds and the stage-2 signature verification are **inapplicable** and are replaced by the `high_qc` identity predicates P1/P2 and the TC's own timeout-quorum observation) — so a **TC-derived raise is representable without a wire QC** (§13.2/§13.3A), resolving the earlier wire-QC-only contradiction. The two discriminants are independent (either committed sub-case may be `QcDerived` or `TcDerived`):
  * **`Locked`-with-committed-anchor.** *Required fields:* **all** §13.2 fields, including
    `lock_block_id` / `lock_view`, the `supporting_certificate` evidence (in its **`QcDerived`** wire-QC **or** **`TcDerived`** logical-`high_qc`+retained-`TimeoutCertificate` representation per the evidence discriminant above),
    `evidence_lock_binding`, **and** `committed_state_assoc`. *Absent fields:* none; a
    missing required field → **refuse** (stage 1).
  * **`Locked`-with-no-commit.** *Required fields:* all of the above **except**
    `committed_state_assoc`, plus an explicit **no-commit discriminant**. *Absent by
    variant:* `committed_state_assoc` — because a lock can legitimately advance through
    `on_qc` with **no** committed baseline (`committed_height`/`committed_block` both
    `None`:
    `run_422_d7d2_signing_state_recovery_tests::d7d12_precrash_lock_advances_via_on_vote_without_a_commit`).
    The decoder **requires** `committed_state_assoc` **absent** here and **present** in
    the committed-anchor sub-case; it is **not** zeroed-and-claimed and **not** coerced to
    height zero, and a manufactured committed block is **never** synthesized. P3 is
    **skipped** for this sub-case (nothing to anchor), which stays **distinct** from a
    missing/corrupt anchor on a record that requires one (→ refuse).

**Revision rules.** `publication_revision` starts at a fixed **initial** value in
`BootstrapNoLock` and is a `u64` incremented by **checked** arithmetic on every O4
publication; **exhaustion** (wrap) → **refuse** (no silent reuse), never a reset.

**Non-circular bootstrap → first-QC → first-lock path (no genesis QC, no assumed
external certificate).** `BootstrapNoLock` is a **durably established no-lock restriction
state** — explicitly **distinct** from *missing* established state (O2 refuses the latter,
opens the former). Its role is **candidate eligibility**, **not** signing authorization:
under `is_safe_to_vote_on_block` (`basic_hotstuff_engine.rs` ~L1312) a **no-lock** state
imposes **no** lock-ancestry refusal, so first-view candidates are **eligible** on the
lock axis (subject to the **separate** A/B authorization, which `BootstrapNoLock` never
grants). The path is therefore non-circular: legitimate bootstrap (an established
`BootstrapNoLock` record) → the engine votes on the first proposal under the no-lock
eligibility **and** independent A/B authorization → that vote forms the **first real QC**
→ `on_qc` sets the first `locked_qc` → O4 publishes the **first `Locked` record** from
that genuine QC. No genesis QC is fabricated, no external initial certificate is silently
assumed, and no production first-use legitimacy is established (A/B remain separate). The
**first `Locked` publication** raises from `BootstrapNoLock` to a genuine **view-zero** (or
first legitimate) lock using the engine's **actual** first `locked_qc` and its wire
supporting certificate (which may be the committed-anchor or the no-commit sub-case). The
monotonic-`view` rule applies from the bootstrap baseline (the first lock's `view` is
simply the first stored lock view; there is no synthetic prior lock to out-rank).

**O2/O3/O5 for both variants.** O2 opens either variant from durable state; O3
validates the **variant-correct** field set (absent fields required absent for
`BootstrapNoLock`, all present for `Locked`); O5 re-acknowledges either variant by the
**complete-content** comparison of §13.4 (it preserves the variant and its revision and
repairs nothing). A `BootstrapNoLock` store admits no **lock-dependent protected
recovery/reuse** (there is no effective lock to depend on), but this is **not** the
circular prohibition "no signing until a `Locked` record exists": see the non-circular
bootstrap path below — the **first** QC that produces the first `Locked` record is itself
formed by legitimate bootstrap voting under the **no-lock** state, not blocked on a
pre-existing lock.

**Duplicate and survived-but-unacknowledged initialization.** A second O1 over **any**
observable established state (either variant) → **refuse**. An initialization whose
write **survived** despite a returned error is decided by a later O2 from the durable
state (open the survived valid record, or refuse if partial/malformed); O1 is **not**
re-run to “fix” it.

**Missing / partial / malformed / unsupported / inconsistent established state.**
Missing-but-expected established state → O2 **refuses** (no auto-init); partial /
malformed / unsupported-version / variant-inconsistent (e.g. a `Locked` discriminant
with an absent `lock_block_id`; a `BootstrapNoLock` discriminant carrying lock fields; a
`Locked`-with-committed-anchor discriminant with an absent `committed_state_assoc`; or a
`Locked`-with-no-commit discriminant **carrying** a `committed_state_assoc`) → **refuse**
(fail-closed). These stay **distinct** from a valid `BootstrapNoLock` state, a valid
`Locked`-with-no-commit record (a legitimate uncommitted lock), and a valid
`Locked`-with-committed-anchor publication; a **legitimate absence of a committed
baseline** is **never** conflated with **missing/corrupt** established state.

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
| **TC-driven lock transition** | `on_timeout_certificate` (~L2162): `set_locked_qc(tc.high_qc)` **before** the `current_view` advance | A TC-derived raise must make its **lock restriction** durable before dependent signing; its `high_qc` is **logical-only**, so the record is carried **unverified** under the selected §13.3A rule (restriction enforced, no verified-evidence prerequisite satisfied) | Binding; a later `current_view` must not relabel an earlier action |
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
  O4, the in-progress publication — in two **distinct** sub-phases: an **unpublished
  preparation** buffer that exists only **before** the `WriteBatch` is submitted and can
  be dropped without having touched storage; and, once submitted, a **possibly-published**
  state whose durable outcome is uncertain and that a restarted process resolves via
  O2/O3/O5 — it is **not** simply "discarded", because a complete successor may already be
  durable). Recovery
  needs only the **current** effective record and its supporting evidence/context, so
  no superseded **disk** generation is kept. An outstanding **prepared** decision that
  still needs its originating L0 eligibility does **not** read a superseded L0 disk
  record and is **not** satisfied by D10's records (D10's `BindingDigest` cannot
  reconstruct L0's lock/evidence — §13.6): it carries a **bounded, immutable in-memory
  L0 evidence reference** for its own lifetime only (§13.6), which is volatile and not
  reconstructed across restart. This keeps a single authoritative **disk** generation
  while still handling outstanding consumers; it adds **no** unbounded second journal
  and leaves D10's own records untouched.
* **Retained L0-evidence capacity (explicit, bounded).** The in-memory L0 evidence is
  bounded on every axis so it cannot grow without limit:
  * **Maximum outstanding count.** At most `MAX_OUTSTANDING_PREPARED_L0` prepared
    decisions may hold captured L0 evidence at once. **Concrete supported limit: `MAX_OUTSTANDING_PREPARED_L0 = 2`**, bounded by
    the engine's in-flight decisions — **its defined input:** the engine advances **one** current view at a time and prepares at most **one proposal + one
    self-vote** for that view before advancing (`on_leader_step` prepares then self-votes; `ingest_proposal` self-votes once per view under the `voted_in_view` guard); a deployment pipelining more in-flight decisions must raise the constant **explicitly**, not leave it unbounded. A preparation that would exceed it is **refused**
    (conservative refusal), and the refusal **never** evicts or discards evidence held by
    an **already-admitted** operation and **never** releases a D10 conflict obligation.
  * **Per-operation retained bytes and the generation it pins.** Each entry holds the **identity** fields
    (`lock_block_id` 32 + `lock_view` 8) plus a **shared reference** (an `Arc`-style
    handle) to the validated evidence/context **generation effective at its decision time** — **not** necessarily the current authoritative record's
    evidence/context — **not** a second copy of the certificate. After an O4 replacement advances the effective record from generation `G_k` to `G_{k+1}`, an outstanding operation that captured `G_k` still **pins `G_k` alive** through its `Arc`: the `Arc` avoids copying but does **not** eliminate the allocation it keeps alive (cf. `VerifiedQuorumCertificate::retained_byte_size`, which charges shared `Arc` evidence **once to its canonical owner**, `qc_verify_domain.rs` ~L607). Each entry's **owned** retained
    memory is therefore the fixed identity bytes + the `Arc` **handle pointer word** (`8` B — **not** the shared control block, which is the generation-owned `ARC_CTRL` charged **once per generation** to the generation's canonical owner, § 13.7A(c.6)), a small constant independent of certificate size; the **pinned evidence/context generation** is charged **separately**, once per distinct generation (below).
  * **Aggregate retained bytes and the separate retained-memory cap (distinct-allocation accounting).**
    The serialized-record cap `MAX_SAFETY_RECORD_BYTES` (§ 13.2) bounds a record's **on-disk
    encoded** length and is **not** a bound on a **decoded generation's in-memory** footprint; the
    two are stated as **separate limits** and the retained charge is **not** asserted to be ≤
    `MAX_SAFETY_RECORD_BYTES`. A decoded generation's retained memory is charged by a
    per-generation accounting `retained_generation_bytes` covering: the **decoded objects and
    descriptors** (the owned struct value, including inline `Vec` pointer/len/capacity triples);
    **vector capacities and their backing allocations** (charged at `capacity()`, not `len()`); the
    **signer arrays and signature buffers** (each signer vector's `capacity() × W_id` and each
    signature buffer's `capacity()`); **owned context allocations** (the pinned genesis/authority
    context the generation owns); and **shared allocation / control-block overhead** (each `Arc`'s
    control block). This **follows the existing** `VerifiedQuorumCertificate::retained_byte_size`
    **accounting precedent** (`qc_verify_domain.rs` ~L618: struct `size_of` + bitmap `capacity()` +
    outer-vector descriptor storage + each signature `capacity()` + signer-vector `capacity() ×
    size_of::<ValidatorId>()`, with checked arithmetic, charging a shared `Arc` **once to its
    canonical owner** and deliberately excluding process-wide allocator bookkeeping) — but that
    method is a **`VerifiedQuorumCertificate`** accessor, **not** an already-implemented
    safety-record accounting service; the successor must supply the record-level
    `retained_generation_bytes` modelled on it.
  * **Ownership scope and shared-once counting.** Each distinct allocation is counted **once**
    within a stated **ownership scope**: a generation's heap is owned by that generation and charged
    to it once, no matter how many outstanding operations hold an `Arc` to it; a per-operation entry
    owns only its **identity bytes** (`lock_block_id` 32 + `lock_view` 8) and its **`Arc` handle
    pointer word** (`8` B — the shared control block is **not** owned per entry; it is the
    generation-owned `ARC_CTRL`, charged **once per generation**, § 13.7A(c.6)), a small constant independent of certificate size. Operations
    that captured **different** generations across an O4 replacement charge **each** such generation;
    a **superseded** generation `G_k` is counted until its **last** outstanding `Arc` is released (at
    that operation's end-of-lifetime), and is only then collectible. The accounting **scope** spans
    the **current authoritative record** and every **superseded generation** still pinned by an
    outstanding operation — at most `(MAX_OUTSTANDING_PREPARED_L0 + 1)` **distinct** generations;
    this is **not** once per outstanding operation.
  * **Separate limits and the encoded-vs-decoded buffer taxonomy (no decoded bound inferred from a serialized length).** Three caps are stated distinctly and are **not** interchangeable: (1) the **serialized-record** cap `MAX_SAFETY_RECORD_BYTES` (§ 13.2) bounds **only an encoded byte buffer** of that enforced capacity (on-disk / in-flight **encoded** length); (2) a **retained-generation** cap `MAX_RETAINED_GENERATION_BYTES` bounds a single **decoded** generation's `retained_generation_bytes`; (3) an **aggregate / peak** cap `MAX_AGGREGATE_RETAINED_BYTES` bounds the coexisting peak. **A decoded candidate/preparation object's in-memory footprint is NOT bounded by `MAX_SAFETY_RECORD_BYTES`** — that cap applies only where the allocation is explicitly an **encoded byte buffer with that enforced capacity**. The distinct allocation kinds are therefore charged **separately**: **(i) encoded input/output byte buffers** — the candidate's **encoded** decode-input bytes and the in-flight **publication/encoding** bytes, each a real byte buffer **bounded by `MAX_SAFETY_RECORD_BYTES`**; **(ii) the decoded candidate object** and its backing allocations — a **decoded generation** bounded by `MAX_RETAINED_GENERATION_BYTES`, **not** the serialized cap; **(iii) the current authoritative decoded generation**; **(iv) superseded generations** still pinned by outstanding decisions; **(v) preparation-owned decoded objects**; **(vi) capacity-normalization overlap** (below); **(vii) publication-owned encoded buffers**; and **(viii) bounded validation scratch** — each counted **once** within its stated ownership scope (a generation's heap charged once no matter how many `Arc` holders; a shared control block charged once to its designated owner; shared context neither omitted nor double-charged).
  * **`MAX_RETAINED_GENERATION_BYTES` (checked formula over bounded profile parameters, with the variant-specific per-allocation tables in § 13.7A).** A single decoded generation's charge is **variant-specific** — the **checked `u128` maximum** across the two variants' explicit per-allocation totals: `MAX_RETAINED_GENERATION_BYTES = checked_max(MAX_QC_GENERATION_BYTES, MAX_TC_GENERATION_BYTES)`, where each per-variant total is the explicit checked `u128` **sum of every § 13.7A allocation row** for that variant (the named totals `MAX_QC_GENERATION_BYTES` and `MAX_TC_GENERATION_BYTES` are derived mechanically in § 13.7A(c)). **The earlier incomplete `GEN_STRUCT + SIGNERS_CAP + SIG_TERMS + CTX_OWNED + ARC_CTRL` sum is superseded** — it buried the `signatures` **outer descriptor-array** backing inside `SIG_TERMS` and, for `TcDerived`, omitted the record-level/TC/nested `high_qc` signer backings, the `signed_timeouts` backing, the per-entry timeout-signature buffers, and the `O(N²)` nested-signer term; **every** such allocation is now charged in the variant-specific allocation tables in § 13.7A, which enumerate, per allocation, its **owner**, **element type and in-memory element size**, **maximum admitted capacity**, **charged bytes**, whether descriptors are **inline or in an outer backing allocation**, and **sharing/lifetime**. The terms are **decoded** backing allocations charged at `capacity()`, not `len()`: `GEN_STRUCT` is the decoded struct value including inline `Vec` pointer/len/capacity descriptors; `SIGNERS_CAP` is the signer-vector backing `N ×` `size_of::<ValidatorId>()`; `SIG_TERMS` is `N × S_sig` for `QcDerived` (signature buffers) and, for `TcDerived`, the retained `TimeoutCertificate`'s decoded vectors (its `signers`, and each of ≤ `N` `signed_timeouts` entries' own signature ≤ `S_sig` plus optional nested `high_qc` signer vector — the `O(N²)` term); `CTX_OWNED` is the pinned genesis/authority context bytes the generation owns; and `ARC_CTRL` is the shared-allocation overhead (strong/weak counter header **plus** required layout padding, **not** the value) charged **once to its canonical owner** — the complete target-profile charge of § 13.7A(c.6), not a bare 16-byte-header assumption (modelled on `VerifiedQuorumCertificate::retained_byte_size`, `qc_verify_domain.rs` ~L618). `N`, `S_sig`, and each framing constant are the **pinned authorized-epoch** profile parameters, **fixed before use**; these are **decoded capacities** (and **in-memory** `size_of`), never the **serialized** widths of § 13.2A. Any overflow → **refuse**.
  * **`MAX_AGGREGATE_RETAINED_BYTES` (checked peak with finite multiplicity).** The aggregate cap is a **checked `u128`** peak over explicit, bounded multiplicities: `MAX_AGGREGATE_RETAINED_BYTES ≥ ((1 + MAX_CONCURRENT_CANDIDATES) × Arc-handle + MAX_OUTSTANDING_PREPARED_L0 × (identity + Arc-handle)) + ((MAX_OUTSTANDING_PREPARED_L0 + 1 + MAX_CONCURRENT_CANDIDATES) × MAX_RETAINED_GENERATION_BYTES) + (MAX_CONCURRENT_CANDIDATES × CAPNORM_OVERLAP) + ((MAX_CONCURRENT_CANDIDATES + 2 × MAX_CONCURRENT_PUBLICATIONS) × MAX_SAFETY_RECORD_BYTES) + VALIDATION_SCRATCH`. The **holder term** charges every **owning `Arc` handle** exactly once from a **bounded holder inventory** (§ 13.7A(c.6)): the **current-authoritative** holder (`1`) and each **candidate** holder (`MAX_CONCURRENT_CANDIDATES`) contribute **one `Arc`-handle pointer word** (`8` B) each, and each **outstanding prepared-operation** holder (`MAX_OUTSTANDING_PREPARED_L0`) contributes its **identity bytes** (`40` B) **plus** one `Arc`-handle pointer word; a **superseded** generation is pinned **directly by the prepared-operation handle** that captured it, **not** by a separate slot, so it adds **no** extra handle. The shared control block is **not** in this term — it is the generation-owned `ARC_CTRL`, charged **once per distinct generation** (§ 13.7A(c.6)), never per handle. The `(MAX_OUTSTANDING_PREPARED_L0 + 1 + MAX_CONCURRENT_CANDIDATES)` term charges the **current** generation, every **pinned superseded** generation, **and the candidate generation being decoded** — the candidate is included **in addition to** current/pinned whenever they coexist during O3. The encoded term charges the **three** separately-owned encoded byte buffers under the conservative three-buffer model (§ 13.7B) — the candidate **input** (`× MAX_CONCURRENT_CANDIDATES`) plus the successor **encoding** and in-flight **publication** buffers (`2 × MAX_CONCURRENT_PUBLICATIONS`), each ≤ `MAX_SAFETY_RECORD_BYTES` (so **3** record-sized buffers under the initial `1`/`1` limits). **`MAX_CONCURRENT_CANDIDATES`**, **`MAX_CONCURRENT_PUBLICATIONS`**, and `MAX_OUTSTANDING_PREPARED_L0` are **proposed component limits** (concrete initial profile: **1**, **1**, **2**), **not** claims about existing engine enforcement; they give the peak a **finite** multiplicity (without them the multiplicity would be unbounded). A deployment pipelining more concurrency must raise them **explicitly**.
  * **Capacity-normalization overlap (both allocations charged at peak; no exact-capacity assumption).** Decoded generation vectors are **capacity-normalized** on admission so `capacity()` cannot exceed the `len()`-derived term by more than a fixed `CAPNORM_SLACK`. If normalization **reallocates** a vector while its **original** allocation remains live, **both** are charged at peak — that is the `CAPNORM_OVERLAP` term (bounded by one `MAX_RETAINED_GENERATION_BYTES` per concurrent candidate). A `shrink_to_fit`/shrink is **not** assumed to yield exact capacity; the bound uses either the explicit `CAPNORM_SLACK` or a bounded allocation representation, never an assumed exact shrink.
  * **`CAPNORM_SLACK` — concrete bounded profile parameter (elements per vector, converted to bytes; explicit multiplicity).** `CAPNORM_SLACK` is defined in **elements**, not bytes: it is the maximum number of **spare element slots** a capacity-normalized growable backing may retain beyond its `len()` after admission (`capacity() ≤ len() + CAPNORM_SLACK`). **Initial profile value `CAPNORM_SLACK = 0` elements** (admission normalizes to an exact bounded representation; a non-zero value is permitted only if a deployment documents it). It applies to **each** decoded growable backing a generation owns — for `QcDerived`: the `signer_bitmap` backing, the `signatures` outer descriptor array, and **each** per-signature buffer (≤ `N` of them); for `TcDerived`: the record-level `high_qc.signers` backing, the `TimeoutCertificate.signers` backing, the optional TC `high_qc.signers` backing, the `signed_timeouts` outer descriptor array, **each** per-entry `signature` buffer, and **each** per-entry nested `high_qc.signers` backing. Its **byte** contribution per vector is `CAPNORM_SLACK × size_of::<element>()`, and its **multiplicity** per generation is the count of such vectors, which is itself bounded: `O(N)` flat vectors plus the `O(N)` per-entry buffers and `O(N)` per-entry nested-signer backings, so the total slack bytes charged into a variant's generation total are bounded with **named per-variant coefficients** (no unspecified `c₁`/`c₂`): for `QcDerived`, `≤ CAPNORM_SLACK × (N + 25)` bytes (one `u8` `signer_bitmap` backing at `1` B/elt + one `signatures` descriptor array at `24` B/elt + ≤ `N` per-signature `u8` buffers at `1` B/elt); for `TcDerived`, `≤ CAPNORM_SLACK × (9·N + 24 + size_of::<TimeoutMsg>())` bytes (three `ValidatorId` signer backings at `8` B/elt + one `signed_timeouts` backing at `size_of::<TimeoutMsg>()` B/elt + ≤ `N` per-entry `u8` signature buffers at `1` B/elt + ≤ `N` per-entry nested `ValidatorId` signer backings at `8` B/elt) — finite, and **0** under the initial profile `CAPNORM_SLACK = 0`. Validation rule: a decoded vector whose `capacity()` exceeds `len() + CAPNORM_SLACK` after normalization → **refuse** (no silent over-capacity retention). This slack is the only capacity excess admitted; it is charged, never assumed away by `shrink_to_fit`.
  * **Allocation admission sequence (check before allocate; a post-allocation check is not prevention).** Allocations are admitted in this order: **(1)** validate profile parameters and declared shapes (version, discriminants, declared counts/lengths vs pinned `N`/`S_sig`); **(2)** compute **conservative** charges for the proposed allocations and their coexistence (the peak terms above) in checked `u128`; **(3)** **check available capacity against each cap before performing the allocations those checks protect**; **(4)** allocate **only within** the admitted bounds; **(5)** validate the **actual** capacities/charges and retain **only** admissible objects, refusing/dropping any that exceed their charge. Step (5)'s post-allocation capacity check is a **confirmation**, **not** the prevention of step (4)'s allocation — prevention is **step (3)**, performed **before** allocation; a post-allocation check **never** justifies an allocation that could not be pre-admitted.
  * **Refusal at capacity.** An operation that would exceed **any** of the three caps is **refused** (conservative refusal); the refusal **preserves** established evidence, every outstanding operation's evidence, and D10 conflict obligations — it **never** evicts or discards an **already-admitted** operation's evidence and **never** releases a D10 conflict obligation. This adds **no** new cache, journal, or production memory-accounting framework; it reuses the bounded in-memory structures only.
  * **Acquisition / release.** Captured **at decision time** (when
    `is_safe_to_vote_on_block` is evaluated); released when the prepared operation is
    signed/reused, rejected, or abandoned — i.e. at the end of its own lifetime.
  * **Process death.** All L0 evidence is **volatile** and is **not** reconstructed on
    restart; nothing is leaked across restart and only the single durable record survives.
  This reuses the existing bounded field types (simple bounded in-memory structures); it
  is **not** a cache and **not** a generation journal.
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
* **Deletion / pruning — disabled (what it does and does not mean, with exactly one
  authoritative disk generation).** Four operations are **distinct** and must not be
  conflated:
  * **Authoritative replacement** (a successful O4 overwriting the one record with a
    higher-view successor) is **allowed** — that is how the frontier advances and is
    **not** pruning; it does **not** require the anti-rollback anchor (its local safety is
    argued in §13.6, separate from the anchor).
  * **Deletion / reset of required state** (erasing or zeroing the one authoritative
    record so a validator resumes with **no** durable restriction) is **never** performed
    — it would drop a safety restriction.
  * **Release of volatile evidence** (freeing an entry of in-memory L0 evidence at the
    end of a prepared operation's lifetime) is **allowed** and routine — it is in-memory
    lifetime management, **not** disk pruning, and likewise does **not** require the
    anchor.
  * **D10-history pruning** is governed by D10's own policy and is **untouched** here.

  "Pruning disabled" means specifically the **third kind of pruning** — accumulating and
  later **deleting superseded historical safety generations** — is not done, because a
  safe discharge condition ("the superseded safety obligation is fully discharged") cannot
  be reduced to observable local inputs **without** the unresolved anti-rollback anchor.
  With exactly one authoritative disk generation there is **no** historical generation to
  prune in the first place; the component does **not** use "prune after the obligation is
  discharged" as an undefined rule and introduces **no** unbounded second journal.
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

### 13.7A Decoded-generation allocation tables (Correction 2, D7-D14)

These tables **replace** the incomplete `GEN_STRUCT + SIGNERS_CAP + SIG_TERMS`
description with a **per-allocation, variant-specific** accounting of one decoded
generation's `retained_generation_bytes`. Every row is a **decoded in-memory**
allocation charged at `capacity()` (not `len()`); none is a serialized width. The
**encoded** `ValidatorId` width (`W_id = 8`, § 13.2A) is **distinct** from the
**in-memory** `size_of::<ValidatorId>()` (the newtype wraps a single `u64`, so it is
also `8`, but the two are conceptually and dimensionally different — a serialized byte
count vs a Rust type size); likewise a `Vec<T>` contributes an **inline** 3-word
descriptor (`ptr`/`len`/`cap`, `24` bytes on a 64-bit target) **plus** an **outer
backing** allocation of `capacity() × size_of::<T>()`. Capacities are `≤` the pinned
`N`/`S_sig` (+ a fixed `CAPNORM_SLACK` **elements** per vector, § 13.7; initial profile
`CAPNORM_SLACK = 0`). Any overflow → **refuse**.

**(a) `QcDerived` decoded generation (the decoded wire `QuorumCertificate`,
`consensus.rs` ~L282).**

| Allocation (owner) | Element type / in-memory element size | Max admitted capacity | Charged bytes | Inline or outer backing | Sharing / lifetime |
|---|---|---|---|---|---|
| `GEN_STRUCT` — decoded struct value | fixed scalars (`version`/`chain_id`/`epoch`/`height`/`round`/`step`/`block_id`/`suite_id`) **+ 2 inline `Vec` descriptors** (`signer_bitmap: Vec<u8>`, `signatures: Vec<Vec<u8>>`); each descriptor `24` B | 1 struct | `GEN_STRUCT = size_of::<RetainedGeneration>()` — **single whole-enum constant**, identical in both variants, ≤ `GEN_STRUCT_MAX = 384` B (§ 13.7A(c); the embedded-QC scalars **+** its 2 inline `Vec` descriptors named here are **already included once** within it — **not** the `size_of::<QuorumCertificate>()` inner-arm footprint) | **inline** | generation; charged once per generation |
| `SIGNERS_CAP` — `signer_bitmap` backing | `u8` / `1` B | ≤ `B_span` (dense `ceil(N/8)`, else `MAX_BITMAP_LEN` 8192) | `capacity() × 1` ≤ `B_span` | **outer backing** | generation |
| `signatures` outer backing (descriptor array) | `Vec<u8>` descriptor / `24` B | ≤ `N` | `capacity() × 24` ≤ `N × 24` | **outer backing** | generation |
| `SIG_TERMS` — per-signature buffers | `u8` / `1` B | ≤ `N` buffers, each cap ≤ `S_sig` | `Σ capacity()` ≤ `N × S_sig` | **outer backing** (one allocation per signature) | generation |
| `CTX_OWNED` — pinned context bytes the generation owns | `u8` / `1` B | **0 under the initial profile** (the generation **references** the pinned context via a 32-byte descriptor counted inline in `GEN_STRUCT`, not a copy), else ≤ `CTX_MAX` | `0` initial, else `≤ CTX_MAX` (§ 13.7A(c)) | **outer backing** | generation; owned, not shared |
| `ARC_CTRL` — shared-allocation overhead (strong/weak counter header **+ required layout padding**, **not** the value) | `2 × size_of::<AtomicUsize>()` header + header→value & final layout padding | 1 shared allocation | `ARC_CTRL ≤ ARC_CTRL_MAX` — **proposed** target-profile charge (`= 16` B header + `0` B padding on the 64-bit profile), counted **once to the canonical owner**; external `Arc` handle pointer words are charged to their **holders**, not here | **outer backing** (shared-allocation header + required padding; the value portion is `GEN_STRUCT`) | shared across `Arc` holders; released with last holder (see the § 13.7A(c) Arc ownership / alignment table) |

**(b) `TcDerived` decoded generation (the record-level logical `high_qc` plus the
retained `TimeoutCertificate`, `timeout.rs` ~L232).**

| Allocation (owner) | Element type / in-memory element size | Max admitted capacity | Charged bytes | Inline or outer backing | Sharing / lifetime |
|---|---|---|---|---|---|
| `GEN_STRUCT` — decoded struct value | record-level `high_qc` (inline `block_id` 32, `view` 8, `signers: Vec` descriptor 24) **+** `TimeoutCertificate` struct (`view` 8, `timeout_view` 8, `high_qc: Option<QC>` inline, `signers: Vec` descriptor 24, `signed_timeouts: Vec` descriptor 24) | 1 struct | `GEN_STRUCT = size_of::<RetainedGeneration>()` — **same single whole-enum constant** as the QcDerived row, ≤ `GEN_STRUCT_MAX = 384` B (§ 13.7A(c); the record-level `high_qc` **+** `TimeoutCertificate` inline members named here are **already included once** within it) | **inline** | generation |
| record-level `high_qc.signers` backing | `ValidatorId` / `size_of::<ValidatorId>() = 8` B | ≤ `N` | `capacity() × 8` ≤ `N × 8` | **outer backing** | generation |
| `TimeoutCertificate.signers` backing | `ValidatorId` / `8` B | ≤ `N` | ≤ `N × 8` | **outer backing** | generation |
| `TimeoutCertificate.high_qc.signers` backing (optional) | `ValidatorId` / `8` B | ≤ `N` (when `high_qc` present) | ≤ `N × 8` | **outer backing** | generation |
| `signed_timeouts` outer backing (descriptor/struct array) | `TimeoutMsg` / `size_of::<TimeoutMsg>()` (inline `view` 8, `high_qc: Option<QC>`, `validator_id` 8, `suite_id` 1, `signature: Vec` descriptor 24) | ≤ `N` entries | `capacity() × size_of::<TimeoutMsg>()` | **outer backing** | generation |
| per-entry `signature` buffers | `u8` / `1` B | ≤ `N` buffers, each ≤ `S_sig` | `Σ capacity()` ≤ `N × S_sig` | **outer backing** (one per entry) | generation |
| per-entry nested `high_qc.signers` backing | `ValidatorId` / `8` B | ≤ `N` entries × ≤ `N` ids | ≤ `N × (N × 8)` = **`8N²` (O(N²) term, charged explicitly)** | **outer backing** (one per entry) | generation |
| `CTX_OWNED` — pinned context bytes owned | `u8` / `1` B | **0 under the initial profile** (32-byte descriptor counted inline in `GEN_STRUCT`), else ≤ `CTX_MAX` | `0` initial, else `≤ CTX_MAX` (§ 13.7A(c)) | **outer backing** | generation; owned, not shared |
| `ARC_CTRL` — shared-allocation overhead (strong/weak counter header **+ required layout padding**, **not** the value) | `2 × size_of::<AtomicUsize>()` header + header→value & final layout padding | 1 shared allocation | `ARC_CTRL ≤ ARC_CTRL_MAX` — **proposed** target-profile charge (`= 16` B header + `0` B padding on the 64-bit profile), counted **once to the canonical owner**; external `Arc` handle pointer words are charged to their **holders**, not here | **outer backing** (shared-allocation header + required padding; the value portion is `GEN_STRUCT`) | shared; released with last holder (see the § 13.7A(c) Arc ownership / alignment table) |

In both variants `GEN_STRUCT` is the **single whole-enum constant** `size_of::<RetainedGeneration>()` (§ 13.7A(c)) — **identical** across variants and **not** a per-variant sum of the inline struct rows; it already **includes once** the **inline** struct members (including each
`Vec`'s 3-word descriptor), and the `*_CAP`/`SIG_TERMS` rows are the **outer backing**
allocations. A generation's heap is charged **once** regardless of how many `Arc`
holders reference it; the shared-allocation overhead `ARC_CTRL` (counter header + required layout padding, **not** the value; § 13.7A(c.6)) is charged **once to its designated
owner** (never double-charged, never omitted), and external `Arc` handle pointer words are charged to their holders. These decoded charges feed
`MAX_RETAINED_GENERATION_BYTES` and, with the multiplicities of § 13.7, the aggregate
peak `MAX_AGGREGATE_RETAINED_BYTES` — **never** bounded by the serialized
`MAX_SAFETY_RECORD_BYTES` (§ 13.2A).

### 13.7A(c) Complete-wrapper representation and named per-variant generation totals (Correction 1, D7-D14)

The operative single-generation charge is the **checked maximum across variants** of two
**named totals**, each the explicit checked `u128` **sum of every § 13.7A allocation row** for
its variant; this **replaces** the incomplete `GEN_STRUCT + SIGNERS_CAP + SIG_TERMS + CTX_OWNED
+ ARC_CTRL` sum (§ 13.7). Every term below has a **measurable bound** (an in-memory
`size_of` expression or a pinned-profile capacity) and a **validation requirement** (checked
`u128` sum; a term, or a backing `capacity()`, exceeding its bound → **refuse**).

**Proposed complete generation representation (`RetainedGeneration`).** One decoded generation
is a **wrapper**, not merely the embedded certificate. Its inline value holds: **(i)** the
common record identity/bookkeeping fields (`lock_block_id` `[u8;32]`, `lock_view` `u64`,
`publication_revision` `u64`, the evidence/anchor/predecessor discriminants) and optional inline
payloads; **(ii)** the **evidence-variant** storage — a discriminated enum holding, for
`QcDerived`, the decoded **wire** `QuorumCertificate` inline struct (its scalars **plus** its two
inline `Vec` descriptors `signer_bitmap: Vec<u8>` and `signatures: Vec<Vec<u8>>`), or, for
`TcDerived`, the record-level logical `high_qc` inline struct **plus** the `TimeoutCertificate`
inline struct (each with its own inline `Vec` descriptors); **(iii)** a **context reference** —
a 32-byte authority-context descriptor the generation references (ownership optional); and
**(iv)** placement **inside** a single shared `Arc<RetainedGeneration>` allocation whose strong/weak counter header and **required layout padding** are the `ARC_CTRL` overhead (§ 13.7A(c) Arc ownership / alignment table): the **external** `Arc` handle (pointer word) that references the value is held by the **bounded holder inventory** — the **current-authoritative** slot, each **candidate** holder, and each **prepared-operation** holder (a prepared-operation handle is what pins a **superseded** generation; there is **no** separate pinned-superseded slot) — charged to those holders, and is **not** owned inside the value — the generation does **not** own its external sharing handle.

**Charge the complete wrapper (which inline fields are already included — not double-counted).**
`GEN_STRUCT` is the **single** whole-enum constant `size_of::<RetainedGeneration>()` — **invariant
across the active variant** (see the Rust-layout correction below) — and **already includes**,
counted **once**: every embedded-certificate **scalar** field, every embedded
**inline `Vec` descriptor** (`ptr`/`len`/`cap`, `24` B each — e.g. the wire QC's `signer_bitmap`
and `signatures` descriptors; the TC's `signers`/`signed_timeouts` descriptors), the common
identity fields, and the 32-byte context-reference descriptor (the value carries **no** self-pointer or `Arc` handle word — it is the payload placed **inside** the shared `Arc` allocation, whose header/padding are the separate `ARC_CTRL` overhead). These inline
members are **not** re-counted in the backing rows; only the **outer backing** allocations
(bitmap bytes, signatures descriptor array, per-signature buffers, signer-id backings,
`signed_timeouts` backing, owned context bytes, the `ARC_CTRL` shared-allocation overhead) are added separately.
**Native alignment/padding** inflates `size_of` above the sum of field widths and is **distinct**
from the § 13.2A **serialized** widths.

**Rust-layout correction (complete-wrapper `size_of`, D7-D14).** `size_of::<RetainedGeneration>()`
is a **single compile-time constant** fixed by the chosen representation on its supported
target; it does **not** vary with the active variant and does **not** shrink when a smaller
inner payload is active — the enum occupies the **whole** chosen layout for **every** variant
and never collapses to one arm. This whole-enum invariance is a property of the selected
representation measured on its target profile, **not** a generic native-layout sizing formula
or a stable language guarantee. The earlier per-arm reading `GEN_STRUCT_QC = size_of::<RetainedGeneration>()`
`≤ 256` B (QcDerived arm) vs `GEN_STRUCT_TC = size_of::<RetainedGeneration>()` `≤ 384` B
(TcDerived arm) is therefore **withdrawn as a layout error**: the `≤ 256` figure mislabeled the
**inner QcDerived payload-arm** footprint as the whole-enum footprint, but a decoded `QcDerived`
generation still occupies the full enum (the larger TcDerived arm plus tag/padding). The
corrected accounting charges **one** inline wrapper term `GEN_STRUCT = size_of::<RetainedGeneration>()`,
**identical in both variant totals**, bounded by a **single proposed** ceiling `GEN_STRUCT_MAX = 384` B on
a 64-bit target (the larger TcDerived arm: common ≤ `136` + record-level `high_qc` inline `64` +
`TimeoutCertificate` inline struct incl. its `Vec` descriptors ≤ `184`) — a **proposed, unexecuted** value, **not** a stable guarantee about the Rust enum layout — with a **single proposed, unexecuted**
`const` assertion `size_of::<RetainedGeneration>() ≤ GEN_STRUCT_MAX` (a compile-time refusal the implementation **would** carry; it is **not** asserted to have been compiled or executed in this
documentation-only pass). The eventual implementation must **measure and enforce the complete chosen representation**
`size_of::<RetainedGeneration>()` on its supported target; measuring a smaller inner variant
payload (`size_of::<QcGenerationArm>()` / `size_of::<TcGenerationArm>()`) does **not** license a
smaller charge for the **unchanged whole-enum allocation**, which does not shrink to one arm. Because the operative cap is
`checked_max(MAX_QC_GENERATION_BYTES, MAX_TC_GENERATION_BYTES)`, substituting the single `384`-B
whole-enum constant into **both** totals **raises the QcDerived inline-wrapper term** by up to `128` B over the **withdrawn** `256`-B arm reading (the TcDerived total already used `384`, so it is unchanged); whether that leaves
`MAX_RETAINED_GENERATION_BYTES` **unchanged** depends on the **pinned-profile** backing-allocation rows of the two variants — it is **not** asserted to remain TcDerived-dominated (that dominance is **withdrawn as unsupported**; see the D7-D14 dominance-claim correction entry). Independent of the inline term, the backing-allocation totals,
serialized formulas, scratch representations, three-buffer peak, and corrected QC attribution are
all **preserved**.

**`CTX_OWNED` (bounded explicitly).** Under the **initial profile** the generation **references**
the pinned context by the 32-byte descriptor already counted inline in `GEN_STRUCT`, so the
separately-**owned** context backing is **`CTX_OWNED = 0` B**. If a deployment copies the context,
it is bounded by `CTX_MAX` — a **pinned descriptor-length constant** fixed before use (a declared
profile maximum, validated by the reader); a copy exceeding `CTX_MAX` → **refuse**. This is a
concrete bound, not "bounded by the descriptor".

**`ARC_CTRL` (complete shared-allocation overhead, bounded explicitly).** `ARC_CTRL` is the **non-value** overhead of the one shared `Arc<RetainedGeneration>` allocation: the strong/weak counter **header** `2 × size_of::<AtomicUsize>()`, **plus** the **header→value alignment padding** that places the value at `align_of::<RetainedGeneration>()`, **plus** any **required final layout padding** that rounds the value up to a multiple of the allocation's alignment. On the 64-bit target profile the header is `16` B, and because `align_of::<RetainedGeneration>()` (≤ `8`, its largest field being a `u64`/pointer) divides both the `16`-B header and `size_of::<RetainedGeneration>()`, both padding terms evaluate to `0` B, so `ARC_CTRL = 16` B **on that profile** — but this is a **proposed implementation obligation computed per target profile**, bounded by a pinned `ARC_CTRL_MAX`, **not** a stable guarantee about `std::sync::Arc` internals. It is charged **once** to the canonical owner (never per `Arc` holder, never omitted); the value itself is charged separately as `GEN_STRUCT`, and external `Arc` handle pointer words are charged to their holders (§ 13.7A(c) Arc ownership / alignment table). The **required alignment/layout padding above is part of `ARC_CTRL` and is NOT dismissed as allocator rounding**; only the allocator's rounding of the whole block up to a size class is **excluded** (and that exclusion is stated — see honesty note), which is a **distinct** quantity.

**(c.1) `MAX_QC_GENERATION_BYTES` — every § 13.7A(a) row summed (checked `u128`):**

| Named term | § 13.7A(a) row | Measurable bound |
|---|---|---|
| `GEN_STRUCT_QC` | decoded struct value (inline wrapper) | `size_of::<RetainedGeneration>()` ≤ `GEN_STRUCT_MAX = 384` B (single whole-enum constant — **not** a `256`-B QC-only arm size; see the Rust-layout correction) |
| `SIGNERS_CAP` | `signer_bitmap` backing | `capacity() × 1` ≤ `B_span` |
| `SIG_VEC_BACKING` | `signatures` outer descriptor array | `capacity() × 24` ≤ `N × 24` |
| `SIG_TERMS` | per-signature `u8` buffers (≤ `N`) | `Σ capacity()` ≤ `N × S_sig` |
| `DECODED_SIGNERS` | retained decoded signer array | **`0` — none retained** (the wire QC carries `signer_bitmap` + `signatures`, **not** a decoded `Vec<ValidatorId>`) |
| `CTX_OWNED` | owned context bytes | `0` initial, else ≤ `CTX_MAX` |
| `ARC_CTRL` | shared-allocation overhead (counter header + required layout padding, not the value) | `ARC_CTRL ≤ ARC_CTRL_MAX` (proposed; `= 16` B header + `0` B padding on the 64-bit profile) |
| `CAPNORM_SLACK_QC` | permitted capacity slack | `0` initial, else ≤ `CAPNORM_SLACK × (N + 25)` (§ 13.7) |

`MAX_QC_GENERATION_BYTES = GEN_STRUCT_QC + SIGNERS_CAP + SIG_VEC_BACKING + SIG_TERMS +
DECODED_SIGNERS + CTX_OWNED + ARC_CTRL + CAPNORM_SLACK_QC` (checked `u128`; overflow →
**refuse**).

**(c.2) `MAX_TC_GENERATION_BYTES` — every § 13.7A(b) row summed (checked `u128`):**

| Named term | § 13.7A(b) row | Measurable bound |
|---|---|---|
| `GEN_STRUCT_TC` | decoded struct value (inline wrapper) | `size_of::<RetainedGeneration>()` ≤ `GEN_STRUCT_MAX = 384` B (same single whole-enum constant as `GEN_STRUCT_QC`) |
| `REC_HIGH_QC_SIGNERS` | record-level `high_qc.signers` backing | `capacity() × 8` ≤ `N × 8` |
| `TC_SIGNERS` | `TimeoutCertificate.signers` backing | ≤ `N × 8` |
| `TC_HIGH_QC_SIGNERS` | `TimeoutCertificate.high_qc.signers` backing (optional) | ≤ `N × 8` (when present) |
| `SIGNED_TIMEOUTS_BACKING` | `signed_timeouts` outer backing | `capacity() × size_of::<TimeoutMsg>()` ≤ `N × size_of::<TimeoutMsg>()` |
| `TIMEOUT_SIG_BUFFERS` | per-entry `signature` `u8` buffers (≤ `N`) | `Σ capacity()` ≤ `N × S_sig` |
| `NESTED_HIGH_QC_SIGNERS` | per-entry nested `high_qc.signers` backings | ≤ `N × (N × 8)` = **`8N²`** (O(N²), explicit) |
| `CTX_OWNED` | owned context bytes | `0` initial, else ≤ `CTX_MAX` |
| `ARC_CTRL` | shared-allocation overhead (counter header + required layout padding, not the value) | `ARC_CTRL ≤ ARC_CTRL_MAX` (proposed; `= 16` B header + `0` B padding on the 64-bit profile) |
| `CAPNORM_SLACK_TC` | permitted capacity slack | `0` initial, else ≤ `CAPNORM_SLACK × (9·N + 24 + size_of::<TimeoutMsg>())` (§ 13.7) |

`MAX_TC_GENERATION_BYTES = GEN_STRUCT_TC + REC_HIGH_QC_SIGNERS + TC_SIGNERS + TC_HIGH_QC_SIGNERS
+ SIGNED_TIMEOUTS_BACKING + TIMEOUT_SIG_BUFFERS + NESTED_HIGH_QC_SIGNERS + CTX_OWNED + ARC_CTRL
+ CAPNORM_SLACK_TC` (checked `u128`; overflow → **refuse**). The `8N²` nested-signer term is
charged **explicitly**, never approximated away.

**(c.3) Operative single-generation cap.** `MAX_RETAINED_GENERATION_BYTES =
checked_max(MAX_QC_GENERATION_BYTES, MAX_TC_GENERATION_BYTES)` (checked `u128`). Each § 13.7A
row maps to exactly one named term above, so **every allocation row contributes** to its
variant total and none is counted twice. The two inline-wrapper terms are the **same** single
whole-enum constant — `GEN_STRUCT_QC = GEN_STRUCT_TC = size_of::<RetainedGeneration>() ≤
GEN_STRUCT_MAX = 384` B — so the variants differ **only** in their backing-allocation rows, so
the operative `checked_max` is decided by those backing rows at the **pinned profile**; the earlier
claim that it remains **TcDerived-dominated** and that the cap is **unchanged** by the
Rust-layout correction is **withdrawn as unsupported** (raising the QcDerived inline term to the
uniform `384` constant can raise `MAX_QC_GENERATION_BYTES`, and no proof was given that the
TcDerived total exceeds it by the required margin). **Honest scope:** these are **application-owned**
charges; allocator rounding and storage-backend-internal allocations are **excluded** and that
exclusion is stated — this is **not** a process-RSS bound. This total feeds the aggregate peak
`MAX_AGGREGATE_RETAINED_BYTES` (§ 13.7 / § 13.7B) and is **never** bounded by the serialized
`MAX_SAFETY_RECORD_BYTES` (§ 13.2A).

**(c.4) Retained-field inventory — post-validation treatment and ownership.** Each common
serialized field (§ 13.2 / § 13.2A) is assigned exactly one post-validation treatment —
**retained inline** (counted once inside the single whole-enum `GEN_STRUCT =
size_of::<RetainedGeneration>()`), **retained through a named owner**, or **discarded after
validation** — with its consumer and its allocation charge. Inline charges are **already
included once** in `GEN_STRUCT` and are **not** re-added as backing rows. No absent value is
manufactured: an absent field is represented **only** by its presence discriminant, never by a
coerced zero or a synthesized block. Bootstrap/no-commit distinctions are preserved exactly as
in § 13.2 / § 13.4.

| Field | Post-validation treatment | Consumer / reason | Owner | Allocation charge |
|---|---|---|---|---|
| `persistence_format_version` (`u16`) | **Discarded from the decoded generation after validation** — the layout gate is checked **before** decode and selects the decoder; it has **no** post-decode consumer in `RetainedGeneration`, yet its exact bytes survive in the **retained encoded publication** (c.5), which supplies O5's whole-publication comparison | structural decode/open gate (§ 13.2) | none retained — validated then dropped; it is **not** a field of `RetainedGeneration` | `0` B (transient decode-time scalar; not in `GEN_STRUCT`) |
| `network_genesis_id` (`[u8;32]`) | **Discarded from the decoded generation after validation** — the record's copy is **compared** to the independently pinned genesis identity, which is the authority, and is not retained as truth in the decoded generation; its exact bytes nonetheless survive in the **retained encoded publication** (c.5) for O5's whole-publication comparison | context interpretation / binding (P4), compared vs the pinned identity | the **pinned** `ExpectedGenesisIdentity` (external, obtained-independently), **not** the generation | `0` B in the generation (the pinned identity is charged outside § 13.7A) |
| `authority_context_ref` (32-byte descriptor) | **Retained inline** as a 32-byte reference descriptor (the owned context bytes, if any, are a separate backing) | P4 context binding and an input re-derived for the `evidence_lock_binding` recompute; part of the O5 complete-content span | **generation** holds the 32-byte descriptor inline; the full pinned context is owned **externally** | `32` B inside `GEN_STRUCT`; owned-copy bytes are `CTX_OWNED` (`0` initial, else ≤ `CTX_MAX`) via the named owner |
| `lock_block_id` (`[u8;32]`) + `lock_view` (`u64`) | **Retained inline** — the enforced restriction identity + view | `is_safe_to_vote_on_block` — the `id` drives the ancestor walk, the `view` the liveness test | **generation** (inline) | `32 + 8 = 40` B inside `GEN_STRUCT` |
| `evidence_lock_binding` (32-byte SHA3-256 digest) | **Retained inline** — recomputed and compared at validation; its **inputs are re-derived**, never trusted from the digest | integrity / co-publication recompute; part of the O5 complete-content span (digest ≠ semantic correspondence) | **generation** (inline digest); inputs re-derived | `32` B inside `GEN_STRUCT` |
| `committed_state_assoc` (committed `block_id` 32 + `height` 8) **+ presence discriminant** | **Present sub-case** (`Locked`-with-committed-anchor): retained inline (`40` B) plus its 1-byte discriminant, compared vs recovered committed history (P3). **Absent by variant** (`BootstrapNoLock`, `Locked`-with-no-commit): **only the discriminant** is retained and P3 is **skipped** — the absence is an explicit discriminant, **never** a coerced height-zero or a manufactured committed block | P3 committed-anchor comparison vs recovered committed state, **when present** | **generation** (inline when present); the presence discriminant is always inline | `D (1) + [40 when present, else 0]` B inside `GEN_STRUCT`; **no** value charged or manufactured when absent |
| `publication_revision` (`u64`, monotonic) | **Retained inline** — local ordering bookkeeping | ownership stale-work fencing and open's authoritative-record selection (§ 13.5) | **generation** (inline) | `8` B inside `GEN_STRUCT` |
| `predecessor_ref` (optional reference) **+ presence discriminant** | **Retained inline when present** (a reference, not a copied predecessor) plus its 1-byte discriminant; **absent** → the discriminant only, no manufactured predecessor | authoritative-record selection / ordering among this host's own publications | **generation** (inline); the referenced predecessor is **not** copied in | `D (1) + [ref width when present, else 0]` B inside `GEN_STRUCT` |
| `integrity_checksum` (CRC32, `4` B) | **Discarded from the decoded generation after validation** — recomputed and compared for accidental-corruption detection at decode; **no** post-decode consumer in `RetainedGeneration`, yet its exact bytes survive in the **retained encoded publication** (c.5), which is kept live through O5 and supplies O5's whole-publication comparison | accidental-corruption detection (T-INTEG) at decode | none retained in the decoded generation (validated then dropped) | `0` B in `GEN_STRUCT` (transient decode-time scalar) |
| `initialization` discriminant (bootstrap / established) and `evidence` discriminant (`QcDerived` / `TcDerived`) | **Retained inline** (1 byte each) — they drive variant decode and O5's **variant-correct** comparison and preserve the bootstrap/no-commit distinctions | variant selection; bootstrap/no-commit preservation; O5 discriminant comparison (a discriminant difference → refuse) | **generation** (inline) | `D (1)` B each inside `GEN_STRUCT` (already summed once into the whole-enum constant; not re-counted) |

Every inline row above is one of the members **already included once** in `GEN_STRUCT =
size_of::<RetainedGeneration>()` (§ 13.7A(c)); the inventory does **not** add a new charge, it
**attributes** the single wrapper constant field-by-field and names which fields are owned
elsewhere or discarded. This replaces any bare pointer to a non-existent inventory: the
complete-wrapper definition of § 13.7A(c) is **this** table plus the backing rows of § 13.7A(a)/(b).

**(c.5) How O5 obtains the whole publication for the byte-for-byte comparison.** O5 re-acknowledges
by a **whole-publication byte-for-byte** comparison (§ 13.4 / § 13.5); **digest equality is
insufficient** (an auxiliary 32-byte digest MAY be computed as a fast-reject but **never** replaces
the full comparison — H19). O5 compares the **identical validated publication** — the complete
O3-validated encoded record **including** its framing/version/genesis/checksum bytes, all
discriminants, lengths, ordering, and supporting evidence — against the currently stored
publication. It obtains **both** operands from **already-budgeted encoded buffers**, **not** by
reconstructing the bytes from the decoded fields (which have dropped the framing/integrity bytes)
and **not** by retaining a second copy inside the generation:

* **Operand 1 — the retained original validated bytes (source / owner / capacity / lifetime).**
  The **original, complete O3-validated encoded publication** is retained **verbatim** in the
  candidate **encoded input buffer** (`ENC_INPUT`, § 13.7B) — the **same** `≤ MAX_SAFETY_RECORD_BYTES`
  byte buffer whose bytes O3 decoded and validated — and is **kept live through O5** (it is **not**
  released after decode). Owner: the single in-flight candidate/publication operation under the
  single-owner serialization boundary (§ 13.5); capacity bound: `≤ MAX_SAFETY_RECORD_BYTES`;
  lifetime: O3 admission → O5 completion. Because these are the exact validated bytes, every field
  the (c.4) inventory marks **discarded from the decoded generation** (`persistence_format_version`,
  `network_genesis_id`, `integrity_checksum`) still survives **here**, in the retained encoded
  publication, and is **never re-synthesized as truth** from the decoded fields.
* **Operand 2 — the currently stored comparison operand.** O5 obtains the second operand by
  **reading back the currently stored publication** from storage into a **publication-side**
  encoded buffer (§ 13.7B), `≤ MAX_SAFETY_RECORD_BYTES`, under the **expected-revision** check and
  the single-owner boundary. A **stale** publication (expected revision no longer current) is
  **refused** so an older recovered record of either representation cannot overwrite a newer stored
  one.
* **Charging (no new term) and release.** Both operands and the re-publication copy are charged by
  the **existing § 13.7B three-buffer model**: operand 1 is the candidate **input** term
  (`× MAX_CONCURRENT_CANDIDATES`); the read-back operand 2 and the re-publication copy are the two
  **publication-side** terms (encoding + publication, `2 × MAX_CONCURRENT_PUBLICATIONS`). **No** new
  retained copy and **no** fourth record-sized buffer are added. The read-back buffer is released at
  the end of the comparison; the retained `ENC_INPUT` operand and the re-publication buffer are
  released only **after** O5's **successful durability acknowledgement** and the identical
  re-publication.
* **Byte-for-byte identity and re-publication.** The comparison spans the **whole publication** —
  the evidence discriminant and its variant-specific supporting material (the wire-QC bytes for
  `QcDerived`; the logical `high_qc` plus the retained `TimeoutCertificate` bytes for `TcDerived`)
  **together with** all framing/version/genesis/checksum/length/ordering bytes: any discriminant
  difference, a differing retained TC, or **any** other byte divergence → **refuse**. On
  **complete** equality O5 **republishes exactly the retained validated bytes** — a **verbatim**
  write of operand 1, with **no** re-encode, repair, normalization, or content change — and the
  transition is **effective only after** O5's successful durability acknowledgement.

**(c.6) Arc ownership and alignment.** The one decoded generation lives in a **single shared
`Arc<RetainedGeneration>` allocation**. The table below separates the **value** (charged by
`GEN_STRUCT`) from the **shared-allocation overhead** (`ARC_CTRL`) and from the **external handles**
(charged to their holders), so nothing is double-counted and no required padding is dismissed as
allocator rounding. The generation does **not** own its external sharing handle. The **holders** are a **single bounded inventory** of actual owning handles — the **current-authoritative** holder (`1`), the **candidate** holders (`MAX_CONCURRENT_CANDIDATES`), and the **outstanding prepared-operation** holders (`MAX_OUTSTANDING_PREPARED_L0`); a **superseded** generation is pinned **directly by the prepared-operation handle** that captured it, **not** by a separate slot or a new registry. Each handle is charged **once** to its holder; each generation value and its backing allocations are charged **once per distinct generation**; the shared-allocation overhead `ARC_CTRL` is charged **once per allocation**; moves and borrows create **no** additional owning handle (any admitted clone has a **bounded** multiplicity already counted in the inventory).

| Object / allocation | Owner | Lifetime | Charge | Sharing rule |
|---|---|---|---|---|
| `RetainedGeneration` **value** (the decoded wrapper placed inside the shared allocation) | the shared `Arc<RetainedGeneration>` allocation | decode-admit → **last strong-handle** drop (the value is dropped when the last **strong** handle drops) | `GEN_STRUCT = size_of::<RetainedGeneration>()` ≤ `GEN_STRUCT_MAX = 384` B (proposed; the single whole-enum constant, charged **once**) | one value per generation; shared **by reference**, never copied per holder |
| **Shared allocation** containing that value (`Arc<RetainedGeneration>` heap block) | the first producer allocates it; it is conceptually owned by the Arc's shared ownership | reclaimed when the last **strong *and* weak** handle drops — outstanding `Weak` handles can keep the **backing allocation** alive after the value is dropped; the **initial profile excludes external `Weak` handles** (no weak-reference subsystem is requested), so with no outstanding `Weak` the allocation is reclaimed with the last **strong** handle | value portion = `GEN_STRUCT`; non-value overhead = `ARC_CTRL` (rows below); charged **once to the canonical owner** | a **single** allocation shared across all handles |
| **External `Arc` handles** (the bounded holder inventory — pointer words in the **current-authoritative**, **candidate**, and **prepared-operation** slots; a prepared-operation handle is what pins a **superseded** generation, so there is **no separate pinned-superseded slot**) | each **holding slot** | each handle's own lifetime (per holder) | `size_of::<*const ()>() = 8` B pointer word **per handle**, charged to the **holder** (the holder term `(1 + MAX_CONCURRENT_CANDIDATES) × Arc-handle + MAX_OUTSTANDING_PREPARED_L0 × (identity + Arc-handle)`, § 13.7 / § 13.7B) | a clone bumps the strong count; it does **not** duplicate the value or the header |
| **Strong/weak counter header** (`strong: AtomicUsize`, `weak: AtomicUsize`) | the shared allocation | allocation lifetime | `2 × size_of::<AtomicUsize>()` (`= 16` B on the 64-bit profile) — part of `ARC_CTRL` | one header per allocation; charged **once to the canonical owner** |
| **Header→value alignment padding** (pads so the value begins at `align_of::<RetainedGeneration>()`) | the shared allocation | allocation lifetime | `pad(2 × size_of::<AtomicUsize>() → align_of::<RetainedGeneration>())` — part of `ARC_CTRL`; `0` B on the 64-bit profile (value align `8` divides the `16`-B header) | once per allocation; **required layout padding, NOT allocator rounding** |
| **Required final layout padding** within the requested allocation (rounds the whole layout up to a multiple of the allocation's alignment) | the shared allocation | allocation lifetime | `pad(header + padding + value → alloc align)` — part of `ARC_CTRL`; `0` B when `size_of::<RetainedGeneration>()` is a multiple of its alignment | once per allocation; **required layout padding, NOT allocator size-class rounding (which is excluded)** |

`ARC_CTRL` = (counter header) + (header→value alignment padding) + (required final layout padding) =
the **complete non-value overhead** of the single shared allocation, charged **once** to the
canonical owner. On the 64-bit target profile it evaluates to `16` B (header) `+ 0 + 0`, but the
charge is a **proposed implementation obligation computed per target profile** and bounded by a
pinned `ARC_CTRL_MAX` — **not** a stable guarantee about `std::sync::Arc` internals. The bare
`16`-byte-header assumption is therefore **replaced** by this complete charge that covers the
required layout padding. The allocator's rounding of the whole block up to a size class remains
**outside** the stated accounting scope (honestly excluded); it is **distinct** from — and must not
be conflated with — the required alignment/layout padding charged above.

### 13.7B O3/O4/O5 phase / coexistence table and derived peak (Correction 3, D7-D14)

This subsection makes the **coexistence** of the §13.7/§13.7A allocations explicit per
operational phase, bounds the two previously-unbounded terms (`VALIDATION_SCRATCH`,
preparation-owned objects), and **derives** the single conservative peak formula
`MAX_AGGREGATE_RETAINED_BYTES` (§13.7) from the table rather than asserting it. It adds
**no** production memory-accounting framework, cache, or journal; it is a finite model of
which bounded in-memory objects are simultaneously live. The proposed concurrency limits
of §13.7 are preserved unchanged: `MAX_OUTSTANDING_PREPARED_L0 = 2`,
`MAX_CONCURRENT_CANDIDATES = 1`, `MAX_CONCURRENT_PUBLICATIONS = 1`. "Charged" = a distinct
owned allocation counted in the peak; "alias" = a reference to an already-charged owner
with **no** additional copy admitted in the selected profile.

**Decoded-generation multiplicity** `G = MAX_OUTSTANDING_PREPARED_L0 + 1 = 3` distinct
generations may be pinned at once (current + every superseded generation still held by an
outstanding prepared decision); the candidate under O3 is **one more**, charged in
addition.

| Allocation kind (owner) | O3 decode/validate candidate | O4 publish + install | O5 re-acknowledge / re-publish | Charge in selected profile |
|---|---|---|---|---|
| Current authoritative generation | live | live | live | charged (1 of `G`) `× MAX_RETAINED_GENERATION_BYTES` |
| Superseded pinned generations | live (`≤ G−1`) | live | live | charged (rest of `G`) |
| Candidate generation (decoded) | **live** (being decoded) | live (being installed) | not decoded (comparison is content-level) | `+1 × MAX_RETAINED_GENERATION_BYTES` |
| Preparation-owned decoded objects | **alias** to candidate/current `Arc` | alias | alias | **aliased — no extra copy** (profile excludes preparation copying) |
| Normalization old + new allocations | both live during reallocation | — | — | `CAPNORM_OVERLAP` (≤ `MAX_CONCURRENT_CANDIDATES × MAX_RETAINED_GENERATION_BYTES`) |
| Encoded **input** buffer (candidate) = retained validated publication (`ENC_INPUT`, operand 1) | **live** (decode input) | **retained** (kept live as O5 operand 1) | **live** — the retained original validated bytes (operand 1) | charged `≤ MAX_SAFETY_RECORD_BYTES` |
| Encoding buffer (successor serialization) | — | **live** | live (read-back of stored publication, operand 2) | charged separately `≤ MAX_SAFETY_RECORD_BYTES` |
| Publication buffer (in-flight write) | — | **live** | live (verbatim re-publication of operand 1) | charged separately `≤ MAX_SAFETY_RECORD_BYTES` |
| O5 comparison / re-publication buffers | — | — | **live** (operand 1 retained `ENC_INPUT` + read-back of the stored publication + verbatim re-publication) | O5 reuses the **same three** `≤ MAX_SAFETY_RECORD_BYTES` encoded kinds — the retained **input** (operand 1), the **read-back** of the currently stored publication (operand 2), and the **re-publication** write — adding **no** new kind; **all three** are charged in the peak |
| Validation scratch | **live** | — | live | `VALIDATION_SCRATCH` (bounded below) |

**Preparation-owned objects (decision made and documented).** Preparation does **not** own
a separate decoded copy: it **aliases** the already-charged candidate/current generation via
its `Arc` handle (a per-operation entry owns only its identity bytes + `Arc` handle, §13.7).
No additional preparation copy is admitted in the selected profile; a deployment that
introduces a real preparation copy must charge it explicitly and raise the multiplicity.

**Encoding vs publication (decision made and documented).** The candidate **encoded input**
buffer, the successor **encoding** buffer, and the in-flight **publication** buffer are
treated as **three separate** owned allocations and **all three** charged (each
`≤ MAX_SAFETY_RECORD_BYTES`); none is assumed to alias another. This is the **conservative
three-buffer model** — separate ownership is the selected representation, so **no**
aliasing/release rule is claimed and no two-buffer peak is asserted. O5's two comparison operands — the retained validated **input** (operand 1) and the **read-back**
of the currently stored publication — and its **verbatim re-publication** reuse these **same three**
encoded kinds (there is **no** re-encode), so O5 introduces
**no** additional encoded kind; the peak charges `MAX_CONCURRENT_CANDIDATES` input buffers +
`2 × MAX_CONCURRENT_PUBLICATIONS` (encoding + publication) buffers = **3** under the initial
`1`/`1` limits.

**`VALIDATION_SCRATCH` — explicit finite bound.** Validation scratch is the transient
structure used while checking a candidate, bounded as a checked `u128` sum, multiplicity
**1** (not pipelined across candidates in the initial profile):
`VALIDATION_SCRATCH = UNIQ_SET + ASSOC_MAP + CMP_SPAN`, each a **concrete** bounded
representation (multiplicity **1** — not pipelined across candidates in the initial
profile; inline descriptor **and** outer backing both charged): **`UNIQ_SET`** is the
signer/member **uniqueness/membership** check represented as a **sorted `Vec<ValidatorId>`**
of ≤ `N` ids (no hashing), charged `24` B inline descriptor **+** `≤ N × size_of::<ValidatorId>()`
= `24 + N × 8` B backing (capacity ≤ `N`); **`ASSOC_MAP`** is the
TC-association/`signed_timeouts`↔`signers` correspondence represented as a
**`Vec<(ValidatorId, u32)>`** of ≤ `N` entries, charged `24` B inline descriptor **+**
`≤ N × size_of::<(ValidatorId, u32)>()` = `24 + N × 16` B backing (capacity ≤ `N`); and
**`CMP_SPAN`** is the **whole-publication** byte-for-byte comparison performed **over the two
already-charged encoded operands** — the retained original validated publication (`ENC_INPUT`,
operand 1) and the read-back of the currently stored publication (operand 2, § 13.7A(c.5)) — so it
**owns no separate buffer** and adds **no** fourth record-sized allocation (`CMP_SPAN = 0` extra
bytes). **O5 retains the accepted complete-content
identity requirement**: an optional 32-byte digest MAY be computed as an **auxiliary**
fast-reject, but it **never replaces** the full byte-for-byte comparison — `CMP_SPAN` is the
**complete** span, not a digest-only equality. Each component is finite and tied to the
pinned `N` and the serialized cap; a scratch structure that would exceed its term →
**refuse** before allocating it. `VALIDATION_SCRATCH` owns no generation heap and aliases none.

**Derived conservative peak (from the table, not asserted).** Taking the **union** of the
simultaneously-live rows across O3/O4/O5 (each phase is dominated by this union) gives the
single peak already stated in §13.7:

`MAX_AGGREGATE_RETAINED_BYTES ≥ ((1 + MAX_CONCURRENT_CANDIDATES) × Arc-handle + MAX_OUTSTANDING_PREPARED_L0 × (identity + Arc-handle)) + ((MAX_OUTSTANDING_PREPARED_L0 + 1 + MAX_CONCURRENT_CANDIDATES) × MAX_RETAINED_GENERATION_BYTES) + (MAX_CONCURRENT_CANDIDATES × CAPNORM_OVERLAP) + ((MAX_CONCURRENT_CANDIDATES + 2 × MAX_CONCURRENT_PUBLICATIONS) × MAX_SAFETY_RECORD_BYTES) + VALIDATION_SCRATCH`.

Here the **holder term** `((1 + MAX_CONCURRENT_CANDIDATES) × Arc-handle + MAX_OUTSTANDING_PREPARED_L0 × (identity + Arc-handle))`
charges each **owning handle once** — the current-authoritative holder and each candidate holder
one `8`-B `Arc`-handle pointer word, each prepared-operation holder its `40`-B identity **plus** one
pointer word — with **superseded** generations pinned **by the prepared-operation handles** (no
separate slot) and the shared control block charged **once per generation** as `ARC_CTRL`
(§ 13.7A(c.6)), not in this term; the `(G + MAX_CONCURRENT_CANDIDATES)` generation term covers the current + pinned +
candidate decoded-generation rows; `CAPNORM_OVERLAP` covers the normalization old/new row;
the `(MAX_CONCURRENT_CANDIDATES + 2 × MAX_CONCURRENT_PUBLICATIONS) × MAX_SAFETY_RECORD_BYTES`
term covers the **three** separately-charged encoded buffers — the candidate **input**
(`× MAX_CONCURRENT_CANDIDATES`) plus the **encoding** and **publication** buffers
(`2 × MAX_CONCURRENT_PUBLICATIONS`), i.e. **3** under the initial `1`/`1` limits (O5 reuses
these three kinds, adding no term); and `VALIDATION_SCRATCH` is the bound
above. The peak is **conservative** (it sums the union rather than taking a per-phase
maximum) and **finite** because every multiplicity is a pinned, bounded profile constant.
This is an **application-owned allocation charge**, honestly **not** a process-RSS bound:
allocator and backend-internal overhead are excluded and that exclusion is stated, not
hidden. Admission (§13.7 steps 1–3) checks these **conservative charges before** the
protected allocations; the step-5 post-allocation check only **confirms** admitted bounds.
A capacity refusal **preserves** established evidence, every outstanding operation's
evidence, and D10 conflict obligations (§13.7), and is kept **separate** from any future
decision-lifecycle integration.

### 13.8 Invariants and future acceptance matrix (not executed)

**Invariant argument (concise).** (INV-D14-1) A transition is **effective** only
after the §13.5 acknowledged-durable barrier; dependent signing/reuse is admitted
only against an effective record (atomic visibility + acknowledged durability).
(INV-D14-2) The record is usable only after structural decode + bounds + CRC
(stage 1) and the **explicit semantic/association predicates** P1–P4 (stage 3, §13.3A:
certificate `block_id`/**`height`** equal `lock_block_id`/`lock_view` (the engine reads the wire **`height`** into the logical view; `round` is **not** the view carrier), context matches the
pinned runtime, and — when present — the committed anchor is on the recovered chain)
pass; a valid CRC and a recomputed `evidence_lock_binding` are integrity/co-publication
checks and do **not** substitute for P1–P4. Evidence verification (stage 2) and
authorization (stage 4) are **separate** and never implied; a TC-derived lock, whose
`high_qc` is logical-only, is carried **unverified** (§13.3A) while its restriction is
still enforced.
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
none fabricates a QC/epoch/authorization. (INV-D14-7) The serialized record is bounded by
the **checked `MAX_SAFETY_RECORD_BYTES` formula** over the pinned parameters — the **§ 13.2A(f) named caps**, for `QcDerived` `MAX_QC_BYTES = 269 + B_span + N × (2 + S_sig)` at `C = 2` (with `B_span = ceil(N/8)` only under a dense-index profile, else the `MAX_BITMAP_LEN` identifier-span bound), for `TcDerived` `MAX_TC_BYTES = FIXED_OVERHEAD + [40 + 8]_{anchor+pred} + REC_HIGH_QC + TC_VIEW + TC_TIMEOUT_VIEW + TC_HIGH_QC + TC_SIGNERS + SIGNED_TIMEOUTS` (`D_ev` **not** re-added — already in `FIXED_OVERHEAD = 153`) (the **record-level** logical `high_qc` **and** the retained `TimeoutCertificate`'s **own** `high_qc` — **both** copies charged once and required byte-identical — the TC's `view` and `timeout_view` (8 each), the TC's own signer list, and the `signed_timeouts` count with each timeout's fields including `suite_id: u8`/signer id/signature/framing/optional nested `high_qc` signer list — all discriminants and length/count prefixes counted, § 13.2)
(§13.2 `bounds_metadata`), enforced **before** application-owned allocation/copy; the
serialized-record cap is kept **distinct** from the **decoded-generation in-memory** charge,
which has its **own** separate caps — a per-generation `retained_generation_bytes` bound
(`MAX_RETAINED_GENERATION_BYTES`) and an aggregate/peak bound (`MAX_AGGREGATE_RETAINED_BYTES`)
covering the coexisting peak of the current, pinned-superseded, **and candidate** decoded generations (each a **decoded** charge ≤ `MAX_RETAINED_GENERATION_BYTES`, **not** the serialized cap) plus the bounded **encoded** byte buffers (candidate decode-input, encoding, and in-flight publication, each ≤ `MAX_SAFETY_RECORD_BYTES`) — so **no** decoded-memory bound is inferred from a serialized length, and the decoded charge is **not** asserted to be ≤ `MAX_SAFETY_RECORD_BYTES`; the retained
in-memory L0 evidence is bounded on count, per-operation, per-generation, and aggregate/peak
axes with **refusal at capacity** that never evicts an admitted operation's evidence or
releases a D10 conflict obligation (§13.7). (INV-D14-8) `BootstrapNoLock` is a durable **no-lock
restriction state** distinct from missing state; it does not authorize signing, and the
**first** QC-backed `Locked` record is reached non-circularly via bootstrap voting under
the no-lock eligibility plus separate A/B authorization; a `Locked`-with-no-commit record
is an explicit discriminant (no coerced height-zero, no manufactured committed block).
**No row below is an executed PASS.**

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
| H24 | `Locked`-with-no-commit lock recovery | A valid `Locked` record with the **no-commit discriminant** (`committed_state_assoc` absent by variant), `committed_height`/`committed_block` genuinely `None` | ADMIT (P3 **skipped**, nothing to anchor); a `Locked`-with-no-commit discriminant **carrying** an anchor, or a committed-anchor discriminant **missing** one, → REFUSE | Legitimate uncommitted lock enforced; no coerced height-zero / manufactured block | unit/model + process-death |
| H25 | **Storage-level** bootstrap → first `Locked` transition | Established `BootstrapNoLock` record + **clearly-labelled supplied** first-lock evidence (a fixture `locked_qc`+wire certificate, **not** engine voting) + pinned context | ADMIT O4 publishing the first `Locked` from the supplied evidence over the no-lock baseline (monotonic from the bootstrap view); REFUSE if the supplied evidence fails stages 1/3 | First `Locked` representable at the **storage** layer from supplied evidence | unit/model + real-storage |
| H25e | **Real-engine** bootstrap voting → first-QC formation (engine integration, **not storage-only**) | Running `BasicHotStuffEngine` voting on the first proposal under no-lock eligibility + separate A/B, forming the first real QC → `on_qc` → O4 | ADMIT the end-to-end bootstrap→first-QC→first-`Locked`; this is an **engine-integration** scenario, excluded from the storage-only successor subset | First lock reached without a fabricated genesis QC | real-storage + release-binary |
| H26 | **Record-size cap** (storage-only) | A record whose declared lengths exceed the checked `MAX_SAFETY_RECORD_BYTES` — the **§ 13.2A(f) named caps**, `MAX_QC_BYTES = 269 + B_span + N × (2 + S_sig)` (`C = 2`) for `QcDerived` (with `B_span = ceil(N/8)` only under a dense-index profile, else `MAX_BITMAP_LEN`), or `MAX_TC_BYTES = FIXED_OVERHEAD + [40 + 8]_{anchor+pred} + REC_HIGH_QC + TC_VIEW + TC_TIMEOUT_VIEW + TC_HIGH_QC + TC_SIGNERS + SIGNED_TIMEOUTS` for `TcDerived` (both `high_qc` copies required byte-identical, the TC `view`/`timeout_view`, each timeout's `suite_id: u8`; `D_ev` **not** re-added, § 13.2A) | Oversize → REFUSE **before** any application-owned allocation/copy (prior record preserved) | Bounded serialized record for **both** evidence variants | unit/model + real-storage |
| H26l | **Retained-L0 lifecycle / capacity** (requires **decision integration**, not storage-only) | An `MAX_OUTSTANDING_PREPARED_L0 + 1`-th prepared decision capturing L0 evidence | Over-capacity preparation → REFUSE **without** evicting an admitted operation's evidence or releasing a D10 conflict | Bounded in-memory L0 evidence | unit/model + process-death |
| H27 | TC-derived lock: logical-only `high_qc` | A TC-derived raise whose `high_qc` is logical-only (no constituent signatures on any path) | PERSIST + ENFORCE the lock restriction; carry **unverified** (stage 2 unmet); REFUSE to satisfy any verified-evidence prerequisite; **no** fabricated signatures/verifier | Restriction enforced; view-change event **not** falsely authenticated | unit/model |
| H28 | Shared references to **one** generation (design case, **decision integration**) | Multiple outstanding prepared decisions sharing **one** `Arc` to the same evidence generation | Charge that generation's record-level `retained_generation_bytes` (modelled on `VerifiedQuorumCertificate::retained_byte_size`) **once**, plus each operation's owned identity + `Arc`-handle bytes | Distinct-allocation accounting (once per generation) | unit/model + process-death |
| H29 | References retaining **different** generations across replacement (design case, **decision integration**) | An outstanding op pins superseded `G_k` while O4 installs `G_{k+1}` as authoritative | Charge **both** `G_k` (pinned by the outstanding `Arc`) and `G_{k+1}` (current) via `retained_generation_bytes`; `G_k` collectible only when its last `Arc` is released | Superseded generations counted until released | unit/model + process-death |
| H30 | QC `height`/`round` disagreement (design case, storage-only) | A stored `QcDerived` certificate with `height = Hh`, `round = Rr`, `Hh != Rr`, `block_id == lock_block_id` | P2 binds `height == lock_view`: ADMIT the view binding when `Hh == lock_view` (REJECT a certificate that instead matches only `round`); if the **additional `height == round` eligibility predicate** is adopted, **additionally** REFUSE the `Hh != Rr` certificate | View sourced from `height`, not `round`; `height==round` is a separate eligibility check | unit/model |

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
decision→evidence binding; and recovery-time **wire-QC** certificate verification wiring
(stage 2) on the load path. **None** of these exists today. A TC/`signed_timeouts`
evidence verifier **does** already exist (`verify_timeout_certificate_with_evidence`,
`timeout_verify.rs` ~L350, wired inbound at `binary_consensus_loop.rs` ~L6892 over
`tc.signed_timeouts`), but it is a **NewView-time** gate that authenticates timeout
signatures + quorum + `high_qc` **identity**, **not** a persisted-record recovery verifier
and **not** a verifier of the `high_qc`'s constituent votes; so the selected TC-derived
evidence rule (§13.3A) persists/enforces the restriction while carrying it **unverified** —
no wire-form TC verifier is invented.

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
**one authoritative record with pruning disabled and fail-closed capacity**; the
**explicit semantic association predicates** P1–P4 with independent inputs (§13.3A, so a
CRC/digest is never mistaken for semantic correspondence); every O1–O5 comparison given
its **real independent inputs** (O3 receives the pinned context and, for anchored records, the independently-supplied **proposed** committed-history relation — **not** an existing production service; ordinary production startup builds a **fresh** engine and reconstructs none, so P3's input is supplied/harness-only); the **corrected QC-view mapping** (the engine reads the certificate's **`height`** into the logical view, so P2 binds `height == lock_view`; `round` is **not** the view carrier); the **checked `MAX_SAFETY_RECORD_BYTES` formula** over
`N`/`S_sig`/`W` and the **bounded retained-L0-evidence** policy (§13.2/§13.7); the
**non-circular bootstrap → first-QC → first-`Locked`** path and the **`Locked`-with-no-commit**
representation (§13.3A/§13.4); and the **selected TC-derived evidence rule** (§13.3A:
restriction persisted/enforced, evidence carried unverified).

**Material unresolved issues (kept separate, out of this component).** The durable
**anti-rollback anchor** (continuity §6.6) is **UNRESOLVED**; profile (a) does **not**
discharge it, and pruning is disabled **because** a safe discharge condition depends on
it. Whole-copy rollback resistance (property 5) and cross-host/copied-key exclusivity
(property 6) remain **UNMET**. Recovery-time certificate verification (stage 2) is a
named integration obligation, **not** wired. These are prerequisites tracked elsewhere,
not gaps in the record **design**.

**TC-derived evidence — selected, not left open (source-grounded).** The earlier claim
that "no TC/`signed_timeouts` verifier exists" is **corrected**: the verifier exists and is
wired (above, §13.3A). Because that verifier does **not** authenticate the `high_qc`'s
constituent votes and the TC carries its `high_qc` only in **logical** form on every path,
no wire-form `high_qc` is available to persist for a TC-derived raise. The **design rule
is therefore selected** (not deferred): a TC-derived lock's **restriction** is
persisted/enforced, while its evidence is carried **unverified**
and may **not** satisfy any verified-evidence prerequisite — keeping *persisting a
restriction* distinct from *authenticating/replaying the whole TC-driven view-change
event*. The only element left to the successor is **mechanical implementation** (honor the
unverified carry; and, **if** a future wire path ever carries the `high_qc` with its
constituent signatures, verify that wire form at stage 2), **not** an unresolved design
choice. The QC-derived path is fully specified, including P1–P4, bounds, and the no-commit
representation. **One named, bounded profile choice (does not block readiness):** whether to adopt the **additional `height == round` eligibility predicate** (§13.3A). P2 binds the view on the certificate's **`height`** (the field the engine reads), which is authoritative and complete on its own; requiring `height == round` as well is an optional stage-3 predicate a deployment may add, sourced only from the emitter/message-admission equality, not a verifier guarantee. Leaving it to the profile keeps the storage design coherent; it is a labelled choice, not an unresolved gap, and implementation readiness remains **unestablished** regardless (DEFINED-NOT-IMPLEMENTED).

**Exactly one bounded, unstarted successor.** *Implement and unit/real-storage-test the
co-located single-database `SafetyRestrictionRecord` publish/open/read-validate/
re-acknowledge operations behind a disabled-by-default, non-production-wired interface*
— the O1…O5 operations and the synced-atomic publication unit, with the §13.8 H-matrix
as its target cases, **without** engine integration, signer calls, anchor selection,
activation, or readiness change. **All material component-design choices are resolved**
(evidence rule, semantic predicates, bounds, bootstrap/no-commit, retention/capacity), so
the successor is a **storage-component implementation with an explicit acceptance subset**:
the O1…O5 operations and the synced-atomic publication unit, accepted against the §13.8
H-matrix rows **H2–H12, H16, H18–H25, H26, H27, H30** (initialize/open/read-validate/publish/
re-acknowledge, bounds/capacity, semantic predicates, no-commit, bootstrap, stale-O5, and
the TC unverified-carry, the record-size cap for both variants, and the `height`/`round` view-source case) — **excluding** the engine-/decision-integration rows (H1/H13/H14/H15/H17/**H25e**/**H26l**/**H28**/**H29**,
which need engine/decision binding, signer calls, or release-binary evidence). This
successor neither re-opens the (a)/(b) choice (resolved, §12.7) nor repeats D12; it builds
the **storage component** whose logical design §13 fixes. It is **not** full production
integration and does **not** authorize it: engine/decision binding, recovery-time wire-QC
certificate verification, the anti-rollback anchor, and activation remain **separate**
later work, each gated independently.

**Validation and verdict.** The §13 design makes concrete component-level choices
(not merely "bounded/atomic/validated"), names a consumer for every field, separates
the four checks, decides recovery from observable inputs, preserves D10 and the D13
surviving-write case, and states its exclusions. The record design — **including** the
semantic predicates (P1–P4), the independent O1–O5 inputs, the checked size cap and
retained-L0 bounds, the bootstrap/no-commit representations, and the **selected**
TC-derived evidence rule — is **complete at the component-design level**; no material
record-design choice is left unresolved. The anti-rollback anchor / whole-copy rollback
resistance / cross-host exclusivity / recovery-time stage-2 wire-QC wiring remain
**separate** prerequisites explicitly out of scope — prerequisites, not design gaps. This
pass therefore reports a coherent, fully specified component design, implemented by
nothing:

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

### 13.7C Operational enforcement wiring (final revision, D7-D14)

> **OPERATIVE CORRECTION (D7-D14, supersedes the claims in this subsection).** The statements below
> that the §13.7/§13.7A/§13.7B accounting is *"enforced through the real O1–O5 operations"*, that
> *"reservation precedes allocation"* for O1/O3/O4/O5, and that the `rec=811` / `gen=1104` /
> `2·gen+3·rec=4641` / `cap=7772` figures are *"measured"* confirmation, are **withdrawn as
> unsupported** and preserved only as historical text. Actual allocations remain outside the
> reservations (O1 existing-state/refusal reads, O2 `load_established`, O3 simultaneously-live
> decoded/re-encode/binding scratch, O4 live predecessor+candidate clones, O5 `load_established`
> decoded generation + envelopes); `AllocationAccountant::current`/`peak` sum admitted charges and do
> **not** inspect real `Vec` capacities, so those figures are **calculated profile/reservation
> quantities, not measured operational memory**; and the operational retained proof is
> `ValidatedRecord`, not the synthetic `RetainedGeneration` the layout assertion measures. The one
> correction landed this pass is sharing the pinned context behind `Arc` so cloning an owner handle no
> longer copies the validator vector into an unaccounted buffer (task §4). The operative verdict is
> restored to `D7D14_STORAGE_COMPONENT=PARTIAL-IMPLEMENTATION` /
> `D7D14_STORAGE_ACCEPTANCE=INCOMPLETE`; see the operative correction section of
> `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` for the full withdrawn-claim list and remaining
> blockers.

This subsection records that the §13.7 / §13.7A / §13.7B accounting — previously a **defined model**
exercised only by standalone arithmetic helpers (`AllocationAccountant`, `generation_charge`) — is now
**enforced through the real O1–O5 operations** of the isolated `safety_record_store` component. **No
bound, ownership requirement, recovery semantic, or evidence level defined above is weakened**; this is
an implementation note, not a contract change.

- **Shared, cross-handle budget.** A single `SharedAccountant` is owned by each `SafetyBackend`; every
  attached handle / clone shares it (the inner `Arc` is cloned, never re-created), so attaching another
  handle cannot open an independent budget that bypasses `MAX_AGGREGATE_RETAINED_BYTES`. The ceiling is
  **bound** from the pinned context at `attach`; a divergent/foreign-context ceiling is refused.
- **Reservation precedes allocation.** O1 (bootstrap buffer), O3 (retained holder + validation
  read-back scratch), O4 (the §13.7B working set `2·gen + 3·rec`), and O5 (stored read-back) each admit
  their conservative charge **before** the matching allocation/copy, via an RAII reservation that
  releases on **every** exit (success, refusal, error, uncertainty, drop). A capacity refusal is a
  **pre-write** refusal that preserves established evidence and admitted holders.
- **Charged once per ownership scope; distinct live allocations charged separately.** The retained O3
  proof owns its holder charge for the proof's lifetime; a copy must take a **separate** charge
  (`try_clone`), so repeated cloning / repeated O3 cannot mint unbounded uncharged holders. The O5
  complete-content comparison adds **no** uncharged fourth record-sized buffer (the retained operand is
  charged once by its O3 holder; O5 reserves only the single read-back).
- **Measured confirmation.** For the reference pinned context (N=4, S_sig=8) the measured values are
  `rec = 811`, `gen = 1104`, retained-holder `rec+gen = 1915`, O4 working set `2·gen + 3·rec = 4641`,
  and `MAX_AGGREGATE_RETAINED_BYTES = 7772`; regressions assert the **post-allocation** `current` / peak
  against the ceiling, confirming the admitted charge (not merely a pre-check). Serialized record size,
  retained-generation charge, aggregate simultaneous application-owned charge, and process RSS remain
  distinct statements; backend-internal and allocator exclusions are unchanged and do not exclude
  component-owned vectors, copies, or retained buffers.

The authoritative row-by-row H-subset mapping, crash-boundary table, and literal validation outcomes for
this revision are recorded in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md` (final-revision section).
Recovered evidence remains **`Unverified`**: durability neither authenticates signatures nor establishes
anti-rollback. `DURABLE_ANTI_ROLLBACK=NOT-ESTABLISHED`, `GENESIS_AUTHORITY_ACTIVATION=DISABLED`,
`PRODUCTION_WIRE_CHAIN_ID_BEHAVIOR=UNCHANGED`, and the open C4/C5 / RS1 posture are all unchanged; this
subsection authorizes no production integration, signing, verifier wiring, anti-rollback, activation,
D15, or Run 423 work.