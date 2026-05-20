# QBIND DevNet Evidence — Run 095

**Objective:** Implement the smallest production-honest binary-path
wiring that detects canonical committed reconfiguration blocks on the
real `qbind-node` binary consensus path and triggers
`BasicHotStuffEngine::transition_to_epoch(...)` so the Run 094
persistence hook can fire on real epoch transitions (per
`task/RUN_095_TASK.txt`). The wiring must use only the existing
canonical reconfig representation (`BlockHeader.payload_kind ==
PAYLOAD_KIND_RECONFIG` + `next_epoch`), invoke only the existing
engine epoch-transition machinery (no redesign of HotStuff commit
rules, epoch semantics, or validator-set rotation), persist the
**actual** committed reconfig block ID through Run 094 (no zero
fallback for real transitions), preserve Run 091/092
`CurrentEpochUnavailable` trust-bundle activation behaviour, and
fail-close on malformed / non-monotonic / engine-rejected transitions.

**Verdict:** **partial positive.** Run 095 lands every source-level
binary-path piece called out by the task. Release-binary Scenario 2
("real committed reconfig transition") cannot be honestly produced
today because the existing binary-path leader code
(`BasicHotStuffEngine::try_propose` in
`crates/qbind-consensus/src/basic_hotstuff_engine.rs:1189..1205`)
hard-codes `payload_kind: PAYLOAD_KIND_NORMAL` and `next_epoch: 0`
into every emitted proposal, and there is no runtime governance /
peer-injection path on the production binary today that would
introduce a canonical `PAYLOAD_KIND_RECONFIG` proposal into the
binary consensus loop. That residual piece is the separately-tracked
open C4 item "peer-driven live apply" listed in
`task/RUN_095_TASK.txt` §"Current state" and is **explicitly out of
scope** for Run 095 per `task/RUN_095_TASK.txt` §"Strict non-goals"
("Do not redesign HotStuff commit rules, epoch semantics, or
validator-set rotation"). Run 095 must therefore not fabricate a
binary-path reconfig commit just to satisfy Scenario 2 — that is the
`negative`-verdict trigger listed in `task/RUN_095_TASK.txt`
§"Expected verdicts" ("implementation invents synthetic epoch" /
"uses height/view/time as epoch").

Run 095 makes **zero** change to
`pqc_trust_activation::ActivationContext`, to `StateSnapshotMeta`, to
the trust-bundle wire format, to peer propagation, to KEMTLS
handshake, to any CLI flag, to any metric family, to any third-party
dependency, and to validator-set rotation. Run 091/092
`CurrentEpochUnavailable` fail-closed activation behaviour is
unchanged. Every existing `ActivationContext { current_epoch: None,
.. }` construction site remains. The Run 093 production
`ConsensusStorage` opening surface and the Run 094 persistence trigger
are both preserved; Run 095 only narrows the Run 094 persistence
helper signature so the `reconfig_block_id` it persists is the
**actual** committed reconfig block ID (not a silent zero fallback)
on real transitions.

---

## 1. Files changed

```
crates/qbind-node/src/binary_consensus_loop.rs
  + pub struct BinaryReconfigDetector
  + pub fn maybe_transition_epoch_from_committed_block(...)
  + pub enum ReconfigTransitionError { NonMonotonicTargetEpoch, EngineRejected }
  + pub enum EpochPersistenceFailureSource { StorageWrite, MissingReconfigBlockId }
  ~ pub fn maybe_persist_engine_epoch_transition(
        engine, storage, last_persisted_epoch,
        reconfig_block_id: Option<[u8; 32]>          // <— new, fail-closed
    ) -> Result<bool, EpochPersistenceFailed>
  ~ pub struct EpochPersistenceFailed { ..., source: EpochPersistenceFailureSource }
  ~ do_leader_tick(...) — observes BroadcastProposal and records the
                          canonical reconfig header into the detector
  ~ handle_inbound_consensus_msg(...) — observes inbound BlockProposal
                                        and records the canonical reconfig
                                        header into the detector
  ~ binary loop main body — instantiates one BinaryReconfigDetector seeded
    with engine.commit_log().len() at loop start; on every tick path that
    may advance commits calls maybe_transition_epoch_from_committed_block
    before maybe_persist_engine_epoch_transition; threads the detector's
    latest_reconfig_block_id() into the Run 094 persistence call; tracks
    reconfig_transition_failed alongside epoch_persistence_failed in the
    loop-exit summary.

crates/qbind-node/tests/run_095_binary_path_reconfig_detection_tests.rs   (new)
crates/qbind-node/tests/run_094_binary_path_epoch_transition_persistence_tests.rs
  ~ updated to pass an explicit reconfig_block_id (4-arg helper).

docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_095.md   (new)
docs/whitepaper/contradiction.md               (narrowed)
docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md  (one operator-facing line)
```

No other files in the repository were touched. No dependency was
added, removed, or version-bumped. No CLI flag, metric family, or
wire-format byte was changed.

---

## 2. Reconfig detection path (`BlockHeader.payload_kind ==
PAYLOAD_KIND_RECONFIG` + `next_epoch`)

Run 095 uses the **existing** canonical wire-level reconfiguration
representation already present in
`crates/qbind-wire/src/consensus.rs:555..585`:

```rust
pub struct BlockHeader {
    ...
    /// Payload kind indicator (T102.1).
    /// Use `PAYLOAD_KIND_NORMAL` (0) for normal blocks.
    /// Use `PAYLOAD_KIND_RECONFIG` (1) for reconfiguration blocks.
    pub payload_kind: u8,
    /// The next epoch to transition to (T102.1).
    /// Only meaningful when `payload_kind == PAYLOAD_KIND_RECONFIG`.
    pub next_epoch: u64,
    ...
}
```

No new schema is invented. The two existing canonical header fields
(`payload_kind`, `next_epoch`) are the **only** values the Run 095
detector reads.

The detector is a small per-loop struct
(`BinaryReconfigDetector`) in
`crates/qbind-node/src/binary_consensus_loop.rs` that:

* **Caches header metadata at observation time.** Every proposal the
  binary loop has visibility into is recorded via
  `record_observed_proposal(&BlockProposal)`. The cache key is the
  canonical binary-path block ID derived by
  `BlockStore::compute_block_id` — which uses
  `(proposer_index, height, parent_block_id)` and matches the
  engine's internal `derive_block_id_from_header` exactly. The cache
  value is the `(payload_kind, next_epoch)` tuple lifted directly
  from `proposal.header`.
* **Observation points** are the two places the binary loop already
  sees `BlockProposal` values: leader-emitted proposals (the
  `ConsensusEngineAction::BroadcastProposal(p)` arm of
  `do_leader_tick`) and inbound proposals (the
  `ConsensusNetMsg::Proposal(p)` decode site in
  `handle_inbound_consensus_msg` — recorded *before*
  `engine.on_proposal_event` so that even rejected-but-decoded
  proposals contribute their header to the cache, matching the
  engine's own block tree which inserts on `on_proposal_event`).

---

## 3. Engine epoch transition trigger

After every tick path that may have advanced `engine.commit_log()`
(both inbound-IO branch and ticker branch in the loop's
`tokio::select!` — three call sites total), the loop calls:

```rust
maybe_transition_epoch_from_committed_block(&mut engine, &mut detector)?
```

This helper:

1. Walks `engine.commit_log()[detector.next_commit_index..]` for newly
   committed entries.
2. For each entry, looks up its block ID in `detector.header_cache`.
   * If absent — block was never observed as a proposal on this loop
     (e.g. snapshot-restored anchor); treated as no-op (normal-block
     semantics). The cursor advances so the entry is not re-scanned.
   * If `payload_kind == PAYLOAD_KIND_NORMAL` — ordinary block,
     no-op, advance cursor.
   * If `payload_kind == PAYLOAD_KIND_RECONFIG` — canonical
     committed reconfig block. Continue to step 3.
3. Validates `header.next_epoch > engine.current_epoch()` (strict
   monotonicity pre-check). On failure: return
   `ReconfigTransitionError::NonMonotonicTargetEpoch { ... }` and
   leave `next_commit_index` pinned at the offending entry so the
   failure is reproducible. The cursor does NOT advance — the
   binary loop fails closed.
4. Calls the **existing** engine machinery:

   ```rust
   engine.transition_to_epoch(
       EpochId::new(header.next_epoch),
       engine.validators().clone(),
   )
   ```

   This is the same
   `BasicHotStuffEngine::transition_to_epoch(...)` already used by
   the engine since T102 (see
   `crates/qbind-consensus/src/basic_hotstuff_engine.rs:618..654`),
   which enforces strict sequential (`current_epoch + 1`)
   monotonicity via `EpochTransitionError::NonSequentialEpoch`. Any
   such rejection is wrapped as
   `ReconfigTransitionError::EngineRejected { source, .. }`,
   surfacing the underlying engine error verbatim. Run 095 does NOT
   redesign HotStuff commit rules, epoch semantics, or
   validator-set rotation — the same validator set is threaded
   across the boundary (validator-set rotation remains the
   separately-tracked C4 item "peer-driven live apply").
5. On success, records the canonical committed reconfig block ID
   into `detector.latest_reconfig_block_id`. The cursor advances.

---

## 4. Reconfig block ID handoff (no zero fallback for real
   transitions)

Per `task/RUN_095_TASK.txt` §"D. Correct reconfig_block_id", Run 095
narrows the Run 094 persistence helper's signature so the
`reconfig_block_id` it persists is the **actual** committed reconfig
block ID:

```rust
pub fn maybe_persist_engine_epoch_transition(
    engine: &BasicHotStuffEngine<[u8; 32]>,
    storage: &Arc<dyn ConsensusStorage>,
    last_persisted_epoch: &mut u64,
    reconfig_block_id: Option<[u8; 32]>,           // <— new
) -> Result<bool, EpochPersistenceFailed>;
```

Semantics:

* If `engine.current_epoch() <= *last_persisted_epoch` — no advance,
  no write, return `Ok(false)`. `reconfig_block_id` is *not*
  consulted on idle ticks (no spurious writes).
* If the engine has advanced and `reconfig_block_id` is
  `Some(committed_id)` — write through
  `apply_epoch_transition_atomic(EpochTransitionBatch::new(target,
  previous, committed_id))`. Same Run 094 atomic-recovery semantics.
* If the engine has advanced and `reconfig_block_id` is `None` — the
  helper **refuses to persist** and returns
  `EpochPersistenceFailed { source: EpochPersistenceFailureSource::
  MissingReconfigBlockId, .. }`. `last_persisted_epoch` is left
  unchanged. The binary loop logs `FATAL`, records
  `epoch_persistence_failed=true` in the loop-exit summary, and
  breaks out. There is **no** silent zero fallback for a real
  transition.

The loop wires the detector and the persistence helper together so
that the actual committed reconfig block ID is always passed when a
real transition has occurred:

```rust
// inside both tokio::select! arms
maybe_transition_epoch_from_committed_block(&mut engine, &mut reconfig_detector)?;
if let Some(storage) = cfg.consensus_storage.as_ref() {
    maybe_persist_engine_epoch_transition(
        &engine,
        storage,
        &mut last_persisted_epoch,
        reconfig_detector.latest_reconfig_block_id(),   // <— actual ID
    )?;
}
```

---

## 5. Failure behaviour (fail closed)

Run 095 introduces two typed error surfaces; both are surfaced as
`eprintln!("[binary-consensus] FATAL: …")` and break out of the loop:

* `ReconfigTransitionError::NonMonotonicTargetEpoch { committed_block_id,
  current_epoch, next_epoch }` — committed reconfig block carries
  `next_epoch == 0` or any value `<= current_epoch`. Engine epoch is
  **not** advanced; Run 094 persistence is **not** called.
* `ReconfigTransitionError::EngineRejected { committed_block_id,
  next_epoch, source: EpochTransitionError }` — the existing engine
  epoch-transition machinery rejected the transition (typically
  `NonSequentialEpoch`). Engine epoch is **not** advanced; Run 094
  persistence is **not** called. The underlying engine error is
  preserved verbatim for operator log correlation.
* `EpochPersistenceFailureSource::MissingReconfigBlockId` —
  canonical engine epoch advanced but no committed reconfig block
  ID is available. Persistence is **refused**;
  `last_persisted_epoch` is unchanged; loop fails closed.

The loop-exit summary now reports both
`epoch_persistence_failed={bool}` (Run 094) and
`reconfig_transition_failed={bool}` (Run 095) so operators can
correlate against engine logs.

---

## 6. Trust-bundle activation isolation

Run 095 makes zero change to `pqc_trust_activation::ActivationContext`
or to any of its construction sites. Every production
`ActivationContext` continues to be constructed with
`current_epoch: None`, including the binary-path activation site
audited by Run 091/092. Run 091/092 `CurrentEpochUnavailable`
fail-closed activation behaviour is unchanged. Fresh genesis remains
`PresentNoCommittedEpoch`; it is **not** epoch 0.

`grep -n 'ActivationContext' crates -r --include='*.rs'` against
`HEAD` shows every production call site still passes
`current_epoch: None`. The Run 094 evidence document's matrix of
sites is unchanged by Run 095.

---

## 7. What was proven

### 7.1 Source-level proof

* Canonical reconfig representation is reused as-is. The detector
  reads only `BlockHeader.payload_kind` and `BlockHeader.next_epoch`
  via `record_observed_proposal`; no new schema is invented. See
  `crates/qbind-node/src/binary_consensus_loop.rs` ::
  `BinaryReconfigDetector::record_observed_proposal`.
* Engine epoch transition is delegated to the existing
  `BasicHotStuffEngine::transition_to_epoch(...)` machinery. No
  HotStuff commit rules, epoch semantics, or validator-set rotation
  are redesigned. See
  `crates/qbind-node/src/binary_consensus_loop.rs` ::
  `maybe_transition_epoch_from_committed_block`.
* The persisted `reconfig_block_id` is the actual committed block ID
  pulled from `engine.commit_log()`; zero fallback is unreachable on
  the real binary path because `latest_reconfig_block_id()` is
  `Some(committed_id)` whenever the engine epoch has advanced via
  the detector (no other code path advances the engine epoch on the
  binary loop).
* Trust-bundle activation isolation is preserved. The detector and
  persistence helper never touch `ActivationContext`. Run 091/092
  fail-closed behaviour is preserved.

### 7.2 Unit / integration test proof

`crates/qbind-node/tests/run_095_binary_path_reconfig_detection_tests.rs`
adds 11 tests, all passing:

```
test run_095_detector_fresh_state ... ok
test run_095_detector_record_observed_proposal_caches_headers ... ok
test run_095_no_commits_no_observations_no_transition ... ok
test run_095_observed_but_not_committed_no_transition ... ok
test run_095_persistence_refuses_zero_fallback_for_real_transition ... ok
test run_095_persistence_succeeds_with_supplied_block_id ... ok
test run_095_persistence_no_advance_no_persistence_even_without_block_id ... ok
test run_095_non_monotonic_target_epoch_display_string ... ok
test run_095_engine_rejected_display_string ... ok
test run_095_normal_committed_blocks_do_not_trigger_transition ... ok
test run_095_engine_enforces_sequential_epoch_monotonicity ... ok

test result: ok. 11 passed; 0 failed; 0 ignored
```

Regression suites called out in `task/RUN_095_TASK.txt` §"C.
Regression tests" — all passing on this branch:

```
run_091_pqc_trust_bundle_activation_epoch_tests           4 passed
run_093_production_consensus_storage_lifecycle_tests     15 passed
run_094_binary_path_epoch_transition_persistence_tests    7 passed
run_095_binary_path_reconfig_detection_tests             11 passed
epoch_persistence_tests                                  13 passed
epoch_startup_validation_tests                            8 passed
binary_path_b1_b2_b4_tests                                4 passed
b5_restore_aware_consensus_start_tests                    4 passed
c4_b6_p2p_binary_path_interconnect_tests                  5 passed
single_node_epoch_transition_tests                        3 passed
t133_mldsa44_epoch_transition_tests                      12 passed
qbind-node --lib                                       1070 passed
```

The `m16_epoch_transition_hardening_tests` test target has 4
pre-existing compile errors (`set_inject_write_failure`,
`clear_epoch_transition_marker`) against the
`RocksDbConsensusStorage` API at `HEAD` of `main` — these predate
Run 095 (they are inherited from the Run 094 parent commit, as
documented in `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_094.md` §"What
was proven"). Run 095 does not introduce them and does not undertake
to fix them (out of scope).

### 7.3 Release-binary evidence proof

Release-binary **Scenario 1** ("fresh startup remains no-epoch") and
**Scenario 5** ("activation unchanged") and **Scenario 4** ("ordinary
block no-op") are unchanged from Run 094 evidence: the same binary
behaviour is preserved verbatim by Run 095 (Run 095 only adds the
*detection* layer; the Run 094 `PresentNoCommittedEpoch` /
fail-closed activation / ordinary-block no-op behaviour is preserved
unchanged).

Release-binary **Scenario 2** ("real committed reconfig transition")
and **Scenario 3** ("restart proof following Scenario 2") cannot be
honestly produced on the production binary today because the
existing binary-path leader code
(`BasicHotStuffEngine::try_propose` in
`crates/qbind-consensus/src/basic_hotstuff_engine.rs:1189..1205`)
hard-codes `payload_kind: PAYLOAD_KIND_NORMAL` and `next_epoch: 0`
into every emitted proposal, and there is no runtime governance or
peer-injection path on the production binary today that would
introduce a canonical `PAYLOAD_KIND_RECONFIG` proposal into the
binary consensus loop. The committed `commit_log()` therefore
contains only normal blocks on a real binary run — which is exactly
the behaviour Run 095's negative-regression unit test
`run_095_normal_committed_blocks_do_not_trigger_transition`
exercises end-to-end.

This blocker is the separately-tracked open C4 item "peer-driven
live apply" listed in `task/RUN_095_TASK.txt` §"Current state". It
is explicitly **out of scope** for Run 095 per the task's strict
non-goals ("Do not redesign HotStuff commit rules, epoch semantics,
or validator-set rotation"). Per `task/RUN_095_TASK.txt`
§"Release-binary evidence" final paragraph:

> If release-binary Scenario 2 cannot be honestly produced because
> no production binary mechanism exists yet to inject or create a
> canonical reconfig block, return **partial-positive** and document
> the exact blocker. Do not fake it.

Run 095 returns **partial-positive** for that reason.

---

## 8. What was NOT changed

* No change to `pqc_trust_activation::ActivationContext`.
* No change to any production `ActivationContext` construction site —
  every site still passes `current_epoch: None`.
* No synthetic epoch source. The Run 094 persistence trigger remains
  exclusively `engine.current_epoch()`; the Run 095 transition
  trigger remains exclusively a canonical
  `PAYLOAD_KIND_RECONFIG`-marked entry in `engine.commit_log()`.
* No wall-clock epoch.
* No height-derived or view-derived epoch (the engine's
  `transition_to_epoch` enforces strict sequential `current_epoch +
  1` monotonicity; Run 095 surfaces — not redesigns — that rule).
* No zero fallback for real transitions (the new
  `MissingReconfigBlockId` error makes zero fallback unreachable on
  the live path).
* No snapshot redesign.
* No fast-sync redesign.
* No validator-set rotation redesign.
* No change to `StateSnapshotMeta`, to the trust-bundle wire format,
  to peer propagation, to KEMTLS handshake, to any CLI flag, to any
  metric family, or to any third-party dependency.
* Run 091/092 `CurrentEpochUnavailable` fail-closed behaviour is
  preserved verbatim.
* Fresh genesis remains `PresentNoCommittedEpoch`; it is **not**
  epoch 0.