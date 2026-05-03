# QBIND Whitepaper Contradictions and Undocumented Behaviors

**Version**: 1.2  
**Date**: 2026-05-03  
**Status**: Active Tracking Document

This document tracks contradictions between the whitepaper (`docs/whitepaper/QBIND_WHITEPAPER.md`) and the actual implementation, as well as behaviors that are implemented but not documented.

---

## Contradictions

### C1. O3–O5 Offense Penalties Not Implemented

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M9/M11)** |
| **Whitepaper Reference** | Section 8.10, Section 12.2 |
| **Code Location** | `crates/qbind-consensus/src/slashing/mod.rs:2218-2240` (PenaltyEngineConfig defaults), `crates/qbind-consensus/src/slashing/mod.rs:2523-2540` (apply_penalty_if_needed O3-O5 handling) |
| **Evidence** | O3-O5 penalties are now fully implemented and enforced: O3 (Invalid Vote): 300 bps (3%) slash + 3 epoch jail; O4 (Censorship): 200 bps (2%) slash + 2 epoch jail; O5 (Availability): 100 bps (1%) slash + 1 epoch jail. Mode matrix: `EnforceCritical`/`EnforceAll` applies penalties for all O1-O5 offenses. |
| **Tests** | `crates/qbind-node/tests/m11_slashing_penalty_o3_o5_tests.rs` (21 tests) |

### C2. No Minimum Stake Requirement

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M2.1-M2.4)** |
| **Whitepaper Reference** | Section 8.1, Section 12.2, Section 18 |
| **Code Location** | `crates/qbind-system/src/validator_program.rs:130-132` (registration-time enforcement), `crates/qbind-consensus/src/validator_set.rs:116-178` (epoch-boundary filtering via `build_validator_set_with_stake_filter()`), `crates/qbind-node/src/hotstuff_node_sim.rs:936-987` (`with_stake_filtering_epoch_state_provider()`) |
| **Evidence** | Minimum stake is now enforced at both registration and epoch boundary. `min_validator_stake` enforced via `ExecutionContext.min_validator_stake` at registration. `StakeFilteringEpochStateProvider` excludes validators with `stake < min_validator_stake` at epoch transitions. Fail-closed: if all validators excluded, epoch transition fails. |
| **Tests** | `crates/qbind-consensus/tests/validator_set_tests.rs`, `crates/qbind-consensus/tests/m2_2_stake_filter_epoch_transition_tests.rs`, `crates/qbind-node/tests/m2_3_stake_filtering_node_integration_tests.rs`, `crates/qbind-node/tests/m2_4_production_stake_filtering_tests.rs` |

### C4. Production `qbind-node` Binary Does Not Boot a Fully Operating Node

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN — partial** (B1, B2, **B3 (VM-v0 state restore)** landed; multi-validator P2P binary-path interconnect still outstanding) |
| **Whitepaper / Doc Reference** | `docs/devnet/QBIND_DEVNET_OPERATIONAL_GUIDE.md` §7–§8 (node bring-up, observability), `docs/ops/QBIND_MONITORING_AND_ALERTING_BASELINE.md` §4 (signal classes A/C/D/E/F), `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` §C1–C5 (recoverability, restore proofs), `docs/release/QBIND_MAINNET_READINESS_CHECKLIST.md` (operability and observability gates) |
| **Code Location** | `crates/qbind-node/src/main.rs` — `run_local_mesh_node` and `run_p2p_node` spawn `binary_consensus_loop::spawn_binary_consensus_loop` (drives `BasicHotStuffEngine` on a tokio interval) and `metrics_http::spawn_metrics_http_server_with_crypto` (gated by `QBIND_METRICS_HTTP_ADDR` via `MetricsHttpConfig::from_env`); `main.rs` now also calls `snapshot_restore::apply_snapshot_restore_if_requested` before consensus startup. `crates/qbind-node/src/binary_consensus_loop.rs` (B1 wiring). `crates/qbind-node/src/snapshot_restore.rs` (**new, B3** — validates the existing `meta.json + state/` `StateSnapshotter` format via `validate_snapshot_dir`, materializes the RocksDB checkpoint into `<data_dir>/state_vm_v0`, and writes an append-only `RESTORED_FROM_SNAPSHOT.json` audit marker). `crates/qbind-node/src/cli.rs` — `--restore-from-snapshot <PATH>` plumbed into `FastSyncConfig`. `crates/qbind-ledger/src/state_snapshot.rs` (existing snapshot creation + validation; reused, not re-implemented). |
| **Description** | The canonical operations docs presume an operable validator binary that, on startup: (a) runs the consensus loop and produces/commits blocks, (b) exposes a Prometheus-compatible `/metrics` endpoint, and (c) supports recovery from a state snapshot. **All three are now satisfied at the binary level for the single-validator binary path.** B1 + B2 landed earlier; **B3 lands the smallest honest restore-from-snapshot startup path**: when `--restore-from-snapshot <PATH>` is passed, the binary validates the snapshot via the existing `validate_snapshot_dir` (chain-id, layout, height) and materializes the RocksDB checkpoint into the configured `<data_dir>/state_vm_v0` before consensus starts. Failures (missing path, wrong chain id, missing `meta.json` / `state/`, populated target state dir, missing `--data-dir`) cause a non-zero exit with a precise reason; no silent degradation. Multi-validator P2P consensus interconnect (routing inbound P2P consensus messages back into the engine's `on_proposal_event`/`on_vote_event`) is **still** not wired at the binary level; multi-validator P2P bring-up continues to rely on `NodeHotstuffHarness`-style integration tests. B3 is scoped to **VM-v0 account state** (the format `StateSnapshotter` produces); restoring non–VM-v0 substate (e.g. consensus storage at `<data_dir>/consensus`) is out of scope and not silently faked. |
| **Impact** | Further reduced — DevNet readiness work and DevNet Evidence Run 003 (restore-then-observe) can now run honestly against the binary path. Backup/recovery drills can produce real restore evidence shaped against `docs/ops/QBIND_BACKUP_AND_RECOVERY_BASELINE.md` §C1–C5 for the VM-v0 state. Full multi-node P2P validator clusters via the binary remain blocked on the consensus-net binary-path interconnect. Protocol-correctness claims continue to be test-evidenced. |
| **Remaining (EXE-1 → EXE-2 follow-up)** | • ✅ B1 — `BasicHotStuffEngine` driver wired into `run_local_mesh_node` and `run_p2p_node` via `binary_consensus_loop`. • ✅ B2 — `metrics_http::spawn_metrics_http_server_with_crypto` spawned from the binary path, gated on `QBIND_METRICS_HTTP_ADDR`. • ✅ **B3** — `--restore-from-snapshot <path>` ingestion at startup, reusing the existing `StateSnapshotter` (`meta.json + state/`) format; regression-tested by `crates/qbind-node/tests/b3_snapshot_restore_tests.rs`. Drill-script wiring for template-shaped restore evidence is tracked separately under DevNet Evidence Run 003. • ⚠️ Wire P2P inbound consensus events into the engine driver from the binary path (the existing `P2pNodeBuilder` + `P2pConsensusNetwork` already exist; the routing into `on_proposal_event`/`on_vote_event` from the binary remains tracked under EXE-2). • ⚠️ Extend restore beyond VM-v0 substate if/when other substores grow snapshot semantics — not currently produced by `StateSnapshotter`. |
| **Tracking** | Recorded by `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md` §6.1–§6.3, §9 (B1, B2, B3) as the top three execution blockers exposed by EXE-1. B1 + B2 closed by `crates/qbind-node/src/binary_consensus_loop.rs` + `crates/qbind-node/src/main.rs` (regression-tested by `crates/qbind-node/tests/binary_path_b1_b2_b4_tests.rs`). **B3 closed** by `crates/qbind-node/src/snapshot_restore.rs` + `--restore-from-snapshot` CLI flag in `crates/qbind-node/src/cli.rs` + restore call in `crates/qbind-node/src/main.rs` (regression-tested by `crates/qbind-node/tests/b3_snapshot_restore_tests.rs`). |

### C3. Reporter Rewards Not Implemented

| Field | Value |
|-------|-------|
| **Status** | ⚠️ **OPEN** |
| **Whitepaper Reference** | Section 12.2 (Slashing Model), Section 12.2.3 (Reporter Incentives) |
| **Code Location** | `crates/qbind-types/src/state_governance.rs:52` (`reporter_reward_bps` field) |
| **Description** | `reporter_reward_bps` parameter exists in `ParamRegistry` but no code distributes rewards. Evidence reporting has no incentive mechanism. Whitepaper Section 12.2.3 now explicitly documents this as future work. |
| **Impact** | Low-Medium - No monetary incentive; however reporting is hardened and abuse-resistant (M15). |
| **M15 Mitigation** | Evidence ingestion hardened with 8-step verification ordering: (1) Reporter validation, (2) Size bounds, (3) Per-block cap, (4) Deduplication, (5) Structure validation, (6) Age bounds, (7) Future height check, (8) Cryptographic verification (expensive - last). Config: `require_validator_reporter=true`, `per_block_evidence_cap=10`, `max_evidence_age_blocks=100K`, size limits per offense type. See `crates/qbind-consensus/src/slashing/mod.rs` (`HardenedEvidenceIngestionEngine`). |
| **M20 Documentation** | Whitepaper Section 12.2.3 "Reporter Incentives (Future Work)" added. Explicitly states: no on-chain reporter rewards currently; slashing is purely punitive; any future reward model must build on M15 hardened evidence pipeline. |
| **Remaining** | • Wire `reporter_reward_bps` to slashing engine reward distribution • Add reward transfer in penalty application path • Design and implement tokenomics for reporter incentives |

---

## Undocumented Implementation Details

### 1. In-Memory Slashing Ledger (T230)

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M1/M19)** |
| **Implementation** | `crates/qbind-ledger/src/slashing_ledger.rs:713-1466` (`RocksDbSlashingLedger`) |
| **Evidence** | Persistent slashing ledger implemented via `RocksDbSlashingLedger`. Provides restart-safe persistence for validator slashing state, evidence records, and penalty history. Atomic updates via `apply_slashing_update_atomic()` using RocksDB `WriteBatch` (M1.2). Failure injection tests verify atomicity (M1.3). **M19**: Added `verify_slashing_consistency_on_startup()` for fail-closed corruption detection, explicit consensus-critical vs non-critical classification in docs, and comprehensive M19 test suite. Whitepaper Section 16.8 updated with full persistence model. |
| **Tests** | `crates/qbind-node/tests/m1_slashing_persistence_tests.rs`, `crates/qbind-ledger/tests/slashing_ledger_tests.rs`, `crates/qbind-node/tests/m19_slashing_persistence_canonicalization_tests.rs` |

### 2. Vote History Memory Limits

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M20)** |
| **Implementation** | `crates/qbind-consensus/src/hotstuff_state_engine.rs:107-122` (`votes_by_view`, eviction tracking) |
| **Whitepaper Reference** | Section 8.4.1 (Vote History Retention) |
| **Description** | The vote history (`votes_by_view` HashMap) is bounded with memory limits and eviction (`evict_votes_by_view_if_needed()`). Whitepaper Section 8.4.1 now documents that equivocation detection is best-effort over a sliding window and very old views may no longer be checked. |
| **Security Impact** | Protocol safety unchanged (locking rule and QC formation guarantee safety independent of historical vote tracking). Very old double-votes may not be slashable if their view has been evicted—acceptable trade-off to prevent unbounded memory growth. |

### 3. CRC-32 Checksum for Storage Integrity

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M20)** |
| **Implementation** | `crates/qbind-node/src/storage.rs:256-336` (`compute_crc32()`, `wrap_checksummed()`, `unwrap_checksummed()`) |
| **Whitepaper Reference** | Section 10.5.1 (Storage Integrity Checksums) |
| **Description** | Storage uses CRC-32 checksums (IEEE 802.3 polynomial) for integrity detection. Whitepaper Section 10.5.1 now documents that checksums detect bit-rot and accidental corruption but are non-cryptographic; adversarial tampering must be handled at higher layers (signatures, QCs, consensus verification). |

### 4. Epoch Transition Write Ordering

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M12, M16)** |
| **Implementation** | `crates/qbind-node/src/storage.rs`, Whitepaper Section 18.4.3 |
| **Evidence** | Epoch transition write ordering and persistence semantics formally specified in Whitepaper Section 18 "Validator Set Transition and Epoch Boundary Semantics" (M12). Section 18.4.3 defines persistence ordering: storage commits before in-memory state update. **M16**: Crash-window elimination now proven by 14 tests with failure injection. All epoch-boundary writes (block, QC, last_committed, epoch) commit atomically via RocksDB WriteBatch. `EpochTransitionMarker` detects incomplete transitions on startup with fail-closed behavior. |

### 5. Key Rotation Grace Period Semantics

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M20)** |
| **Implementation** | `crates/qbind-consensus/src/key_rotation.rs:238-298` |
| **Whitepaper Reference** | Section 9.8 (Key Rotation Semantics) |
| **Description** | Key rotation uses an epoch-aligned grace period where both old and new keys are valid during transition. Whitepaper Section 9.8 now documents: (1) partial-epoch rotations not supported, (2) both keys valid for grace epoch, (3) security trade-off of simpler reasoning vs. slower key turnover. |

### 6. DAG Mempool Batch Priority

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M20)** |
| **Implementation** | `crates/qbind-node/src/dag_mempool.rs`, `crates/qbind-node/src/mempool.rs` |
| **Whitepaper Reference** | Section 7.1.1 (Mempool Ordering Semantics) |
| **Description** | Mempool priority uses `arrival_id` which differs per node. Whitepaper Section 7.1.1 now documents: (1) batch selection deterministic per node but depends on local arrival order, (2) transaction ordering within blocks is proposer-determined, not globally canonical, (3) consensus safety unaffected—economic fairness (block inclusion) is proposer-local. |

### 7. Timeout Exponential Backoff Parameters

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M20)** |
| **Implementation** | `crates/qbind-consensus/src/pacemaker.rs:74-109` (`TimeoutPacemakerConfig` with `timeout_multiplier: 2.0`, `max_timeout: 30s`) |
| **Whitepaper Reference** | Section 17.3.1 (Exponential Backoff Parameters) |
| **Description** | The timeout pacemaker uses configurable exponential backoff. Whitepaper Section 17.3.1 now documents: (1) default multiplier 2.0× and max timeout 30 seconds, (2) parameters are environment-tunable, (3) must remain bounded and deterministic for safety and cross-node consistency. |

### 8. Evidence Signature Verification Not Performed

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M9/M11)** |
| **Implementation** | `crates/qbind-consensus/src/slashing/mod.rs:579-594` (`verify_ml_dsa_44_signature()`), lines 664-682 (O1 verification), 762-769 (O2 verification), 860-865 (O3 verification), 945-951 (O4 verification) |
| **Evidence** | Cryptographic signature verification IS implemented for all offense types. `verify_ml_dsa_44_signature()` performs ML-DSA-44 signature verification on evidence payloads. O1 verifies both block signatures; O2 verifies header signature invalidity; O3 verifies vote signature; O4 verifies certificate signatures. Deterministic verification with fail-closed behavior on non-verifiable evidence. |

### 9. Governance Slashing Parameters Not Connected

| Field | Value |
|-------|-------|
| **Status** | ✅ **RESOLVED (M14)** |
| **Implementation** | `crates/qbind-types/src/state_governance.rs:44-117` (`SlashingPenaltySchedule` struct with O1-O5 parameters), `crates/qbind-consensus/src/slashing/mod.rs:2260-2370` (`PenaltyEngineConfig::from_governance_schedule()`, `GovernanceSlashingSchedule` type) |
| **Whitepaper Reference** | Section 11 (Governance) |
| **Description** | `ParamRegistry` now contains a canonical `SlashingPenaltySchedule` with all O1-O5 penalty parameters. `PenaltyEngineConfig::from_governance_schedule()` creates engine configurations directly from governance state. Slashing parameters are governed and upgradeable with epoch-boundary activation semantics. |
| **Evidence** | M14 implementation: (1) `SlashingPenaltySchedule` stores slash_bps and jail_epochs for O1-O5 plus activation_epoch, (2) `GovernanceSlashingSchedule` provides interface between types crate and consensus crate, (3) `PenaltyEngineConfig::from_governance_schedule()` constructs configs deterministically, (4) DevNet allows fallback defaults; TestNet/MainNet require schedule presence (fail-closed). |
| **Tests** | `crates/qbind-node/tests/m14_governance_slashing_params_tests.rs` (15 tests): deterministic schedule load (A1-A3), epoch-boundary activation (B1-B3), fail-closed behavior (C1-C5), O1-O5 regression (D1-D4). |

### 10. Stake Synchronization Gap

| Field | Value |
|-------|-------|
| **Status** | ✅ **PARTIAL (M13)** |
| **Implementation** | `crates/qbind-types/src/state_validator.rs:31-102` (`ValidatorRecord` with canonical fields), `crates/qbind-ledger/src/slashing_ledger.rs:1-50` (M13 documentation) |
| **Evidence** | Canonical economic state unified (M13). `ValidatorRecord.stake` and `ValidatorRecord.jailed_until_epoch` are the single source of truth. `ValidatorSlashingState` mirrors but is documented as non-authoritative. Eligibility predicates (`ValidatorRecord::is_eligible_at_epoch()`) read from canonical fields. |
| **Tests** | `crates/qbind-node/tests/m13_economic_state_unification_tests.rs` (12 tests) |
| **Remaining** | • Full architectural unification (single-write path for slashing penalties to both `ValidatorRecord` and `ValidatorSlashingState`) |

---

## Summary

| Category | Count | Items |
|----------|-------|-------|
| **RESOLVED** | 12 | C1, C2, Item 1, Item 2 (M20), Item 3 (M20), Item 4, Item 5 (M20), Item 6 (M20), Item 7 (M20), Item 8, Item 9 (M14), Item 10 (partial) |
| **OPEN** | 2 | C3, C4 |

**High-Risk Open Items**: C4 (Production binary does not yet boot a fully operating node) — DevNet readiness items B1, B2, and B3 have all landed; multi-validator P2P binary-path interconnect remains the residual blocker for full multi-node clusters via the binary. Protocol-correctness claims remain unaffected (those are test-evidenced).

**Medium-Risk Open Items**:
- C3 (Reporter Rewards): No economic incentive for evidence reporting. Whitepaper Section 12.2.3 documents this as future work; M15 hardened evidence pipeline is the baseline for any future reward implementation.

---

## Update History

| Date | Change | Author |
|------|--------|--------|
| 2026-02-11 | Initial document created during state audit | Audit |
| 2026-02-11 | Added C1-C3 contradictions, items 8-10 undocumented details from validator economics audit | Audit |
| 2026-02-15 | M12: Added formal validator set transition spec (Section 18). Items 4 (Epoch Transition Write Ordering) now documented in Section 18.4.3. C2 (Minimum Stake) partially addressed by M2 epoch-boundary filtering; registration-time validation still pending. | M12 |
| 2026-02-15 | M13: Canonical economic state unified. Item 10 (Stake Synchronization Gap) partially mitigated - canonical source defined (`ValidatorRecord.stake`, `ValidatorRecord.jailed_until_epoch`). `ValidatorSlashingState` documented as mirror. 12 restart safety tests added. | M13 |
| 2026-02-15 | M13.1: Full reconciliation pass. Updated all entries with Status/Evidence fields. Verified: C1 RESOLVED (M9/M11 O3-O5 penalties implemented), C2 RESOLVED (M2 minimum stake enforced), Item 1 RESOLVED (M1 RocksDbSlashingLedger), Item 8 RESOLVED (signature verification implemented). Updated line references and test citations. | M13.1 |
| 2026-02-15 | M14: Governance slashing parameters wired into penalty engine. Item 9 RESOLVED. `SlashingPenaltySchedule` added to `ParamRegistry` with O1-O5 penalty parameters + activation_epoch. `PenaltyEngineConfig::from_governance_schedule()` provides deterministic config from governance state. DevNet allows fallback; TestNet/MainNet fail-closed on missing schedule. 15 M14 tests added. | M14 |
| 2026-02-15 | M16: Epoch transition hardening completed. Item 4 updated with crash-window elimination. `EpochTransitionBatch` and `apply_epoch_transition_atomic()` implement atomic RocksDB WriteBatch for all epoch-boundary writes. `EpochTransitionMarker` detects incomplete transitions on startup. 14 M16 tests added with failure injection. Spec Gap 2.6 in QBIND_PROTOCOL_REPORT.md now Mitigated. | M16 |
| 2026-02-15 | M17: Formal slashing penalty schedule added to whitepaper. Section 12.2 updated with: (1) O1-O5 penalty table (offense, evidence type, verification rule, slash bps, jail epochs), (2) governance/activation semantics paragraphs (SlashingPenaltySchedule in ParamRegistry, epoch-boundary activation, fail-closed behavior). Protocol Report Spec Gap 2.5 status changed to "✅ Mitigated (spec added M17)", risk level reduced from Medium to Low. C3 (Reporter Rewards) remains OPEN unchanged. | M17 |
| 2026-02-16 | M19: Slashing state persistence and canonicalization hardening. Item 1 updated to M1/M19 RESOLVED with `verify_slashing_consistency_on_startup()` for fail-closed corruption detection. Whitepaper Section 16.8 updated with full persistence model (consensus-critical vs non-critical classification, atomic update guarantees, fail-closed behavior). `SlashingStateCorrupt` error variant added. `ValidatorSlashingState` documentation enhanced with M19 NON-AUTHORITATIVE warnings. Protocol Report section 3.15 added. 8 M19 tests added. | M19 |
| 2026-02-16 | M20: Documentation hardening milestone (no Rust changes). Closed Items 2, 3, 5, 6, 7. Whitepaper updates: Section 8.4.1 (vote history retention), Section 10.5.1 (CRC-32 checksums), Section 9.8 (key rotation semantics), Section 7.1.1 (mempool ordering), Section 17.3.1 (timeout backoff parameters), Section 12.2.3 (reporter incentives - future work). C3 remains OPEN by design—no tokenomics yet; updated with M15 hardening reference and new whitepaper note. | M20 |
| 2026-05-03 | EXE-1: Repo/code↔doc alignment audit. Added C4 (Production `qbind-node` binary does not boot a fully operating node) — covers binary lacking consensus driver, `/metrics` HTTP not spawned by binary, and missing restore-from-snapshot path. Recorded as the top three execution blockers (B1/B2/B3) in `docs/protocol/QBIND_REPO_CODE_DOC_ALIGNMENT_AUDIT.md`. Protocol-correctness items remain unchanged; gap is at the binary/operability layer. | EXE-1 |
| 2026-05-03 | B3: Restore-from-snapshot startup path landed in `qbind-node`. New `crates/qbind-node/src/snapshot_restore.rs` validates a snapshot via the existing `validate_snapshot_dir` (T215 `meta.json + state/` format), refuses to overwrite a populated `<data_dir>/state_vm_v0`, copies the RocksDB checkpoint into place, and writes a `RESTORED_FROM_SNAPSHOT.json` audit marker; `--restore-from-snapshot <PATH>` CLI flag wired in `crates/qbind-node/src/cli.rs`; `main.rs` calls the restore path before consensus startup and exits non-zero with a precise reason on any failure. Regression-tested by `crates/qbind-node/tests/b3_snapshot_restore_tests.rs` (10 tests, including a restore-then-reopen-and-observe proof). C4 status updated: B1+B2+B3 all landed; multi-validator P2P binary-path interconnect remains the residual sub-item. | B3 |

---

*This document should be updated whenever a contradiction is discovered between the whitepaper and implementation, or when significant undocumented behaviors are identified.*