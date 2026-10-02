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

* **Working branch (actual):** `copilot/copilotcopilotrun-422-documentation-only-consolida`
  (`git branch --show-current`). Used **unchanged**; no rename, rebase,
  force-push, or history rewrite.
* **Starting worktree HEAD (actual, full SHA):**
  `5435d22b917d1d078c94b633b18bd28d5802c1a3` (`update`). Worktree clean before
  this documentation pass. This is the revision all source line references below
  are taken against.
* **Shallow, single-branch clone.** `git rev-list --count HEAD` = 2; only this
  branch is present. Other branches and older history are not fetched.
* **Reference objects named by the task:**
  * Accepted D10 final revision `3d7155eddc09f7071d1af277208a070695aabd66`:
    **object absent** from this shallow clone (`git cat-file -t` → *could not get
    object info*); not in local ancestry; not referenced by any tracked file.
  * Reported task branch
    `copilot/copilotrun-422-documentation-only-consolidation`: the **actual**
    branch carrying this work is
    `copilot/copilotcopilotrun-422-documentation-only-consolida` (used unchanged).
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
* Harness recovery, `crates/qbind-node/src/hotstuff_node_sim.rs`:
  `load_persisted_state` (~L2035, **test-oriented harness**): schema-compat check,
  `get_last_committed`, `get_block`, `get_qc`, and the embedded `block.qc`, then a
  **conservative lock** chosen as the higher-view of the separately-stored QC and
  the embedded QC, passed to `initialize_from_restart`. **No** QC signature or
  wire re-verification is performed on load; the stored QC is assumed trusted.
* Production startup / restoration, `crates/qbind-node/src/main.rs`:
  destination-lock acquire (Run 422 D7-D8), pre-materialization epoch-conflict
  check (`evaluate_restore_epoch_compatibility`, Run 422 D7-D5),
  `apply_guarded_snapshot_restore` (materialization + RTR `Intent`),
  `open_production_consensus_storage` (Run 093), `persist_restored_snapshot_epoch_durable`
  + RTR `Complete` publication (Run 097), then `spawn_binary_consensus_loop`. **No
  signing-reservation journal is opened or wired anywhere in production
  `main.rs`.**
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
**conservative reconstruction** (a safe lower/weaker value derived from durable
inputs), **fixture input** (supplied only by a test/harness, not production), and
**unsupported assumption** (no durable channel exists). "Reachability" names
whether the recovery consumer runs in the **production** binary path or only in a
**harness**/test.

| State or obligation | Producer / update point | Persistence & durability | Recovery consumer | Verification performed | Prod / harness reachability | Gap |
|---|---|---|---|---|---|---|
| Committed block id | `on_commit` / engine commit; `storage.put_last_committed` | `meta:last_committed`, checksummed | `load_persisted_state` → `initialize_from_restart`; snapshot sets from meta | Schema-compat only; decode/checksum | Production restart (via harness wrapper) **and** snapshot baseline | Exact restoration of *committed* id only |
| Committed height | `block.header.height` of committed block | Embedded in persisted block | `load_persisted_state` reads `block.header.height`; snapshot from meta | Decode only | Production + snapshot | Exact, but a height is **not** a lock (§4-Q2) |
| `locked_qc` (lock) | `set_locked_qc` on TC / 3-chain progress | Persisted QC (`q:<id>`) and/or embedded `block.qc` | **Restart:** `load_persisted_state` picks higher-view of stored/embedded QC → `initialize_from_restart`. **Snapshot:** `initialize_from_snapshot_baseline` recovers **none** | **No** signature/wire re-verification on load; assumed trusted | Restart path = **harness** reconstruction; snapshot path = **production**, recovers no lock | **Conservative** on restart; **absent** on snapshot baseline — lock recovery UNMET |
| Uncommitted vote / per-view latch (`voted_in_view`) | Set during `ingest_proposal` vote emission | **Not persisted** | None — reset to `false` on both recovery paths | — | Lost on every restart/restore | **Unsupported assumption**: no durable channel (D7-D2) |
| Non-committed block tree, `vote_accumulator` | Engine runtime | **Not persisted** | Rebuilt as new proposals/votes arrive | — | Both paths start fresh | In-flight consensus work lost (safe by design, but not a lock) |
| `verified_justification` evidence (D7-C3F) | `on_verified_proposal_event` | **Non-serialized** | Never restored (`None`) | — | Both paths | Evidence must be re-verified on re-admission |
| Current epoch | `apply_epoch_transition_atomic` / restore persist | `meta:current_epoch`, synced; incomplete-transition marker | `open_production_consensus_storage` → `verify_epoch_consistency_on_startup`, `get_current_epoch` | Incomplete-transition marker check; fail-closed | **Production** | Exact restoration; coarse — epoch is **not** a signing-history commitment (continuity §6.3) |
| Restore completeness (RTR) | `apply_guarded_snapshot_restore` → `Intent`; Run 097 → `Complete` | `RESTORE_TRANSACTION.rtr`, SHA3-256, fsync + dir fsync; advisory lock | `main.rs` restore path reads/validates RTR | Strict fail-closed decode; digest = integrity only | **Production** (D7-D8) | `COMPLETE` proves *this attempt's* durability only; **not** lock recovery / signing freshness / anti-rollback |
| Signing reservation (`Reserved`) | `reserve_for_sign` before signer | `sig:…` record, synced, checksummed | `journal.open` + `for_each_signing_namespace_entry` | Decode/checksum; accounting vs metadata; fail-closed | **Harness/test only** — not opened in production | No production reader; recovered `Reserved` ⇒ potentially-signed (continuity §5.2) |
| Signing result (`Signed`) | `record_signed_result` after signer | `sig:…` (+signature) + metadata, atomic synced | `journal.open`; `RecoveredAckCache` for exact resend | Decode/checksum; ack barrier; exact-record binding | **Harness/test only** | No production reader; exact reuse retains D10 ack/verify/authorization |
| Journal metadata (limit / count) | `initialize` then atomic advance with each signed result | `sig:meta:v1`, synced, checksummed | `journal.open` accounting validation | Count ≤ limit; version; fail-closed | **Harness/test only** | No production reader; `AccountingInconsistent` fail-closed |
| Signing exclusivity (ownership) | `SigningOwnershipDomain` per backend instance | **In-process only** (process-unique token) | Re-created per process open | One `Mutex` serializes supported handles | In-process | Does **not** span processes/hosts/copies (continuity §4.2) |
| Timeout / NewView dependency | `on_timeout_certificate` updates `locked_qc` | Lock persisted only via QC, as above | Same as `locked_qc` | As above | As above | Timeout/NewView compatibility is an explicit unmigrated dependency |

**Reading of the inventory.** Production recovery establishes *committed state* and
a *coarse epoch* exactly, reconstructs a *conservative* lock **only on the harness
restart path**, recovers **no** lock on the production snapshot-baseline path,
recovers **no** uncommitted-vote record on any path, and opens **no** signing
journal at all in production. The correspondence this contract requires therefore
has, today, **no production comparison inputs on the signing side** and an
**incomplete safety-state input** on the consensus side.

---

## 3. Safety invariants and explicit trust assumptions

**Invariants the recovery path must preserve (derived from the implemented
consensus rules, not invented):**

* **INV-R1 (fail-closed recovery).** If any required safety evidence is missing,
  malformed, inconsistent, or unavailable, signing does **not** resume. Absence is
  never read as "unused" or "current".
* **INV-R2 (lock before future votes).** Signing may resume only after the
  `locked_qc` sufficient to enforce `is_safe_to_vote_on_block` for future views is
  recovered or conservatively reconstructed from durable inputs, **and** any
  in-flight signing reservations are present. A high-water mark, an epoch, or a
  single valid QC alone does **not** restore the lock (continuity §5.3, §6.7).
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
   actual locking / safe-vote rule?** **UNMET on the production snapshot-baseline
   path** (no `locked_qc` recovered) and **conservatively reconstructed only in the
   harness** restart path; no uncommitted-vote latch is recovered anywhere (D7-D2).
   This is the INV-R2 prerequisite and is **independent** of Q1.
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

For each proposed comparison: the two values, their actual source and recovery
phase, the integrity/authentication/freshness assumptions, what a match
establishes, what remains unproven, and the behavior on a missing / malformed /
inconsistent / unavailable input. **No comparison invents an input that an ordinary
restart does not possess, and a record compared with itself is never treated as
independent evidence.**

### 5.1 Comparison table

| # | Value A | Value B | Source & phase | Integrity / auth / freshness | A match establishes | Remains unproven | On missing / malformed / inconsistent / unavailable |
|---|---|---|---|---|---|---|---|
| X1 | Recovered `locked_qc` block id | Committed block id / recovered chain | Engine recovery (conservative restart; **none** on snapshot) | Integrity: checksum on persisted QC; auth: **assumed trusted on load** (T-TRUST-STORAGE); freshness: none | The reconstructed lock is anchored in recovered committed state | That the lock equals the **pre-crash** lock; snapshot path has no lock to compare | Refuse to sign (INV-R2); no synthesis of a lock from height/epoch |
| X2 | Journal metadata `reserved_positions` count | Count of decodable `sig:` records | `journal.open` accounting (both from the **same** store) | Integrity: CRC32; auth/freshness: none | Internal journal self-consistency only | Latestness; this is a record-vs-itself check, **not** independent freshness evidence | `AccountingInconsistent` → fail-closed; no repair/reset |
| X3 | Recovered signing records' bound epoch/network/key | Recovered consensus authority epoch/network/key | Journal records vs recovered authority/epoch | Integrity: checksum; auth: pinned-identity check is a **separate** obligation (A/B); freshness: none | The retained obligations name the same validator/network/epoch as recovered state | Current authorization; freshness; that the snapshot is not an older copy | Refuse; mismatch is treated as non-correspondence, never a new namespace (INV-R6) |
| X4 | Highest signing position retained (`Reserved`/`Signed`) | Recovered consensus view / committed height | Journal vs engine recovery | Integrity: checksum; freshness: none | Whether retained obligations sit at/above the recovered consensus frontier (the compatibility question) | That either side is current; a same-epoch older snapshot can satisfy height yet be stale | If retained obligations exceed what recovered state can safely support, refuse (potentially-stale restore) |
| X5 | Recovered `Signed` retained result | Canonical decision at that position | D10 exact-reuse path | Integrity: checksum; auth: D10 verification + current-authorization revalidation (INV-R4) | Eligibility for an **exact resend** of that one result | Authorization/freshness beyond D10's local scope | Refuse reuse; retain the obligation; never re-sign |
| X6 | RTR `snapshot_meta_digest` | `StateSnapshotMeta` of the restored input | Restore completion (D7-D8) | Integrity: SHA3-256 association; auth/freshness: **none** (T-INTEG) | The restored effects correspond to *that* snapshot meta | That *that* snapshot is the **latest** authorized state (rollback not detected) | Strict fail-closed decode; `Invalid` ⇒ refuse |

### 5.2 The specific scenarios the task requires addressed

* **Newer journal retained while older state is restored in the same epoch.** Epoch
  equality does **not** prove freshness. The test is **correspondence** (X4), not
  epoch inequality: if the retained signing records already cover positions at or
  above the restored consensus frontier, signing is refused at those positions until
  trusted out-of-domain state resolves latestness (continuity §5.2 row 10).
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
  activation gate (A), not a local inference.
* **Copied validator keys or directories on another host.** In-process ownership
  exclusivity does not span copies/hosts; two instances with the same key are not
  mutually detected locally (continuity §4.2 / §5.2 row 13). Exclusivity depends on
  the same unresolved out-of-domain evidence.

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
| S4 | Establish required correspondence | §5 comparisons (X1–X6) | **The correspondence reader itself** (no production component performs X1–X6) | Any §5 non-correspondence; stale-restore indication |
| S5 | Establish authorization (A), freshness (B), exclusivity | Authority lifecycle contract; admission gate (`current_auth`) | **Anchor** (freshness/anti-rollback); **cross-host exclusivity** | Missing/invalid authorization; no freshness anchor |
| S6 | Invoke a signer | `guarded_sign_{proposal,vote}_for_broadcast` → reserved signing | — (gated by S1–S5) | Any prior stage unmet |
| S7 | Reuse a retained signature | D10 exact-reuse (`ExactRetryRetained`) | — | Failed D10 verification/ack/authorization (INV-R4) |
| S8 | Hand an action to the facade | `confirm_outbound_before_effect` → facade | — | Confirmation failure (effect suppressed, obligation retained) |

**Ordering rules preserved:**

* Recovered `Reserved` records remain **potentially signed**: no automatic release
  or re-signing (INV-R3).
* Exact retained-result reuse retains D10's acknowledgement, verification, and
  authorization requirements (INV-R4).
* Missing or inconsistent required safety evidence prevents signing (INV-R1/R2).
* No automatic journal initialization, repair, deletion, overwrite, counter reset,
  or history migration occurs during recovery (INV-R5).
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
| R1 | Ordinary restart; committed state + reconstructable lock + consistent journal | Resume after S2–S5 satisfied | Signing before lock + correspondence established | Harness restart reconstructs a conservative lock; production snapshot path does not (INV-R2) |
| R2 | Snapshot-baseline recovery; **no** `locked_qc` recovered | Nothing (sign) | All future votes until lock established | Snapshot path recovers no lock (§2) |
| R3 | Recovered `Reserved`, no usable retained result | Retain reservation | Re-sign; release | Potentially signed (INV-R3) |
| R4 | Recovered `Signed` with ack'd retained result | Exact resend after D10 reuse checks | Re-sign; resend without D10 checks | INV-R4; *(continuity §5.2 row 5/6)* |
| R5 | Same-epoch older snapshot + newer journal records | Refuse at covered positions | Signing from stale restored state | Correspondence (X4), not epoch equality *(continuity §5.2 row 10)* |
| R6 | Newer consensus state + lost/older journal | Refuse (fail-closed) | Assuming "never signed" | First-use-vs-lost ambiguity (continuity §5.1) |
| R7 | Internally-consistent whole-directory older copy | Refuse pending out-of-domain evidence | Trusting the restored copy as current | Locally indistinguishable (T-DOMAIN) |
| R8 | Missing / malformed / inconsistent journal or safety state | Refuse (fail-closed) | Auto-init / repair / adopt | INV-R1/R5 |
| R9 | Missing journal metadata with established records | Refuse (`LegacyRecordsWithoutMetadata`) | Auto-adopt as authorized first init | Needs activation gate, not local inference |
| R10 | Two instances, same validator key / copied directory | At most one holds in-process exclusivity | Both signing; assuming local detection | Exclusivity does not span hosts (continuity §4.2) |
| R11 | Committed-state-only recovery (control) | Resume once S2–S5 met | Treating committed recovery as lock/freshness proof | Committed height is not a lock (§4-Q2) |
| R12 | Later-view decision that would violate the pre-crash lock though it avoids same-position equivocation | Refuse under the recovered/required lock | Signing because no same-position conflict exists | Lock rule, not only non-equivocation (INV-R2/R6) |

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
| F4 | Same-epoch older snapshot + newer journal | Restore older snapshot, keep journal | Snapshot + `sig:` records | Refuse at covered positions | REFUSE (X4) | real-storage |
| F5 | Missing / corrupt / inconsistent journal or safety state | Corrupt record / omit metadata / drop lock input | Malformed store | Fail-closed | REFUSE (INV-R1) | unit/model + real-storage |
| F6 | Whole-directory rollback; copied-key | Restore whole older copy; run two copies | Internally-consistent old copy / two keys | Local reader cannot distinguish; refuse on correspondence/exclusivity gap | REFUSE / documented indistinguishability | adversarial (needs out-of-domain anchor) |
| F7 | Harness reconstruction vs production snapshot path | `load_persisted_state` vs `initialize_from_snapshot_baseline` | Reconstructed vs absent lock | Harness reconstructs; production recovers none | Distinguish paths; REFUSE on production path | real-storage + release-binary |
| F8 | Later-view decision violating the pre-crash lock | Recovered lock vs future vote | Lock input + future proposal | Refuse despite no same-position conflict | REFUSE (INV-R2/R6, F12-style) | unit/model |
| F9 | Committed-state recovery control | Normal committed recovery | Committed block + QC | Resume once S2–S5 met | ADMIT (control) | real-storage |
| F10 | Power-loss durability of recovery decisions | Power-cut harness | Durable store | Decisions survive power loss | boundary TBD | power-loss |

---

## 9. Existing vs missing mechanisms, and unresolved prerequisites

**Existing (reusable) mechanisms:**

* Committed-state and conservative-lock reconstruction on the **harness** restart
  path (`load_persisted_state` → `initialize_from_restart`).
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
* **The correspondence reader** that performs X1–X6 (S4).
* **A freshness / anti-rollback anchor** and **cross-host exclusivity** (Q4; continuity §6).
* **Authorization (A) + current-authority freshness (B)** wiring (S5; lifecycle contract).

**Unresolved trust assumptions:** T-TRUST-STORAGE (QCs trusted on load without
re-verification), T-DOMAIN (whole-copy rollback locally indistinguishable), and
T-INTEG (checksums/digests are integrity/association only). None are resolved by
this contract.

---

## 10. The single bounded successor task

**Exactly one** smallest justified successor. It must address the **next missing
prerequisite** demonstrated above — not a generic freshness module or production
wiring chosen without that demonstration.

**Successor (D7-D12 candidate): a non-authorizing, read-only recovery
*correspondence observer* — source + tests only.**

* **Why this and not something else.** §2 shows production recovers committed state
  and an epoch but opens no journal and (on the snapshot path) recovers no lock.
  Before any anchor (Q4) or authorization wiring (Q5) can matter, the system needs a
  component that can *read* recovered consensus safety state and an *opened* journal
  and *report* whether they correspond (X1–X6), fail-closed, **without** signing or
  authorizing. This is the smallest step that makes Q3 observable and is a strict
  prerequisite for S4; a freshness anchor (Q4) is premature because there is nothing
  yet consuming correspondence, and production lock recovery (Q2) is a distinct,
  separately-scoped consensus change.
* **Extends / reuses:** the existing `journal.open` + `for_each_signing_namespace_entry`
  readers, `ConsensusStorageState` / `open_production_consensus_storage`
  observation, and the engine recovery outputs (`locked_qc`, committed height) —
  composed in a new **read-only** observer that returns a typed
  correspondence result (match / non-correspondence / input-unavailable) and
  **never** writes, signs, initializes, repairs, or authorizes.
* **Proposed tests:** the §8 rows reachable without an anchor — F1 (intact), F2/F3
  (reserved/retained), F4 (same-epoch older snapshot), F5 (missing/corrupt), F9
  (committed control), and F7's path distinction — asserting fail-closed outcomes
  and zero writes/zero signer calls.
* **Explicit exclusions:** the freshness/anti-rollback anchor (continuity §6.6),
  whole-copy/cross-host rollback detection, production lock-recovery redesign,
  Timeout/NewView migration, opening a journal in the production signing path,
  enabling signing, and any activation/readiness change. The observer is
  **non-authorizing** and reports correspondence only; it must never be called
  rollback protection, freshness, or authorization.

The successor **implementation is not begun** in this task.

---

## 11. Validation performed and retained posture

### 11.1 Checks actually performed (documentation-only)

* Source symbols and call order were re-traced against the `5435d22` worktree
  (engine recovery, harness `load_persisted_state`, production `main.rs` startup /
  restore, guarded signing routes, storage / production-storage recovery readers,
  `restore_completion.rs`, and `signing_reservation_journal.rs`). Line numbers are
  locators; symbols are authoritative.
* Reference-object reachability was checked with `git cat-file -t`: the accepted
  D10 final `3d7155e…` is **absent** from this shallow clone and is reported
  separately from content correspondence; ancestry to it is not manufactured.
* Cross-document consistency was checked against the continuity contract (§5, §5.2,
  §5.3, §6), the authority lifecycle contract, the snapshot-restore completion
  contract, and the genesis authority / QC integration audit (inspected read-only).
* Markdown structure, relative links, and table well-formedness in the changed
  files were reviewed. EOL (CRLF) and the existing no-final-newline EOF convention
  are preserved to match sibling documents.
* No Cargo tests, Clippy, or release rebuild were executed — none are required for
  this documentation-only phase. No historical result is relabelled; fresh tool
  outcomes (if any) are recorded literally and separately in
  `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_422_D7.md`. A skip, an unavailable
  reviewer, or a "no comments" wrapper does **not** establish completed security
  analysis.

### 11.2 Scoped verdict and retained posture

Design completion of this contract establishes **no** implemented recovery
protection. If the required contract is complete, the token is:

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