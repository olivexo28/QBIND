# QBIND DevNet Evidence — Run 128

**Subject:** Release-binary evidence for Run 127 offline authority-state reset CLI behavior.  
**Verdict:** **strongest-positive**  
**Date:** 2026-05-24  
**Task:** `task/RUN_128_TASK.txt`  
**Type:** Release-binary evidence + docs sync.

---

## 1. Exact verdict

**strongest-positive.**

Run 128 is evidence-focused and proves on a real release binary that:

- DevNet reset succeeds with valid inputs and writes marker + audit;
- MainNet local reset refuses by default;
- missing/bad ratification, wrong genesis hash, corrupt marker, missing audit flag, and wrong-chain/wrong-environment ratification all refuse;
- refusal paths do not write or mutate marker bytes;
- reset path exits before normal startup surfaces.

No production runtime code was changed.

---

## 2. What changed

- Added harness script:
  - `scripts/devnet/run_128_authority_state_reset_release_binary.sh`
- Added release-binary evidence document:
  - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_128.md`
- Added release-binary archive (deterministic path):
  - `docs/devnet/run_128_authority_state_reset_release_binary/`
- Updated docs:
  - `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
  - `docs/ops/QBIND_PQC_TRUST_LIFECYCLE_RUNBOOK.md`
  - `docs/whitepaper/contradiction.md`

**Runtime bug fixes:** none.  
**Production runtime source changes (`crates/**/src/**`):** none.

---

## 3. What was proven

### 3.1 Release-binary/process evidence

Harness: `scripts/devnet/run_128_authority_state_reset_release_binary.sh`  
Binary: `target/release/qbind-node` (sha256/build-id recorded in archive summary)

| Scenario | Result | Proof highlights |
|---|---|---|
| 1. DevNet valid reset | **PASS** | `rc=0`; marker written; audit written; marker JSON equals `audit.new_marker_record`; no startup markers |
| 2. MainNet local reset | **PASS** | `rc=1`; refusal `MainNetLocalResetUnsupported`; marker absent/unchanged; refusal audit written |
| 3. Missing ratification | **PASS** | `rc=1`; refusal `MissingRatification`; marker unchanged; refusal audit written |
| 4. Bad ratification | **PASS** | `rc=1`; refusal `RatificationEnforcementFailed`; marker unchanged; refusal audit written |
| 5. Wrong expected genesis hash | **PASS** | `rc=1`; refusal `GenesisHashMismatch`; marker unchanged; refusal audit written |
| 6. Corrupt existing marker | **PASS** | `rc=1`; refusal `ExistingMarkerCorrupt`; marker sha256 before==after; no auto-repair |
| 7. Missing audit output flag | **PASS** | `rc=1`; refusal `AuditOutputMissing`; marker unchanged; no normal startup markers |
| 8a. Wrong chain ratification | **PASS** | `rc=1`; refusal `RatificationEnforcementFailed` (chain mismatch); marker unchanged |
| 8b. Wrong environment ratification | **PASS** | `rc=1`; refusal `RatificationEnforcementFailed` (environment mismatch); marker unchanged |

**No-marker-write-on-refusal invariant:** proven across all refusal scenarios via per-scenario marker SHA before/after capture in `summary.txt` and `logs/*.marker_sha_*`.

**No-normal-startup invariant:** proven by per-scenario stderr assertion that no P2P/consensus/metrics/SIGHUP/reload/peer-candidate startup markers appear.

### 3.2 Source-level evidence

- Reset path still early-exits before normal startup:
  - `crates/qbind-node/src/main.rs` (Run 127 early-exit branch)
- Refusal stable IDs and audit schema unchanged:
  - `crates/qbind-node/src/pqc_authority_state_reset.rs`
- CLI remains hidden operator ceremony flags only:
  - `crates/qbind-node/src/cli.rs`

No new runtime behavior was introduced by Run 128.

### 3.3 Test evidence

Captured in: `docs/devnet/run_128_authority_state_reset_release_binary/tests/`

- `run127_reset_cli_source_tests_lib_only`: **pass**
- `run125_snapshot_restore_tests`: **pass**
- `run124_snapshot_restore_authority_marker_tests`: **pass**
- `run123_validation_only_marker_tests_lib_only`: **pass**
- `run119_mutating_marker_tests`: **pass**
- `run120_mutating_marker_tests_lib_only`: **pass**
- `run121_mutating_marker_tests`: **pass**
- `run117_118_authority_state_tests_lib`: **pass**
- `run103_ratification_tests`: **pass**
- `run104_ratification_tests`: **pass**
- `qbind_node_lib`: **pass**
- `qbind_ledger_lib`: **pass**
- `qbind_crypto_lib`: **pass**

Known pre-existing issue (not introduced by Run 128):

- `run127_reset_cli_source_tests_known_preexisting_fail` (`cargo test -p qbind-node run127_`) fails because `m16_epoch_transition_hardening_tests` references missing methods (`set_inject_write_failure`, `clear_epoch_transition_marker`) on `RocksDbConsensusStorage`. Error is captured in:
  - `docs/devnet/run_128_authority_state_reset_release_binary/tests/run127_reset_cli_source_tests_known_preexisting_fail.stderr.log`

---

## 4. What was not changed

- No MainNet governance artifact support.
- No trust-bundle wire format change.
- No peer-candidate wire format change.
- No peer-driven apply.
- No KMS/HSM custody changes.
- No signing-key rotation/revocation lifecycle implementation.
- No authority monotonic schema (ratification v2) implementation.
- No full C4 closure claim.
- No C5 closure claim.

---

## 5. Contradictions or inconsistencies

Cross-checked with Runs 100–127 docs and current source surfaces:

- Run 100/101/102/103/104 authority+genesis+ratification model: consistent.
- Runs 105–115 ratification enforcement semantics: consistent.
- Runs 117–125 authority-marker and restore invariants: consistent.
- Run 126 reset specification and Run 127 implementation boundaries: consistent.
- `docs/whitepaper/contradiction.md`, protocol doc, runbook: synchronized for Run 128.

No new contradiction found.

---

## 6. Evidence references

- Evidence document:
  - `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_128.md`
- Archive directory:
  - `docs/devnet/run_128_authority_state_reset_release_binary/`
- Summary:
  - `docs/devnet/run_128_authority_state_reset_release_binary/summary.txt`
- Per-scenario logs and exit codes:
  - `docs/devnet/run_128_authority_state_reset_release_binary/logs/`
- Per-scenario audits:
  - `docs/devnet/run_128_authority_state_reset_release_binary/audits/`
- Test matrix summary + logs:
  - `docs/devnet/run_128_authority_state_reset_release_binary/tests/test_matrix_summary.txt`

Scenario command shape is fully encoded in:

- `scripts/devnet/run_128_authority_state_reset_release_binary.sh`

---

## 7. Residual risks and next recommended run

### Residual risks

- MainNet governance recovery artifact verification remains unimplemented (intentionally).
- Signing-key rotation/revocation lifecycle remains open.
- Per-key monotonic ratification schema (v2) remains open.
- One unrelated/pre-existing qbind-node broad-filter test compile issue remains (`m16_epoch_transition_hardening_tests`).

### Next recommended run

Proceed to the ratification-v2/per-key monotonic authority sequence design+implementation track (Run 129+) while preserving Run 128 proven invariants: MainNet local reset refusal, strict refusal typing, no marker write on refusal, and offline-only reset behavior.

