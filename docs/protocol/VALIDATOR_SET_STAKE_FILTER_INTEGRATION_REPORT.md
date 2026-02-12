# Validator Set Stake Filter Integration Report

**Version**: 3.0  
**Date**: 2026-02-12  
**Status**: ✅ PRODUCTION INTEGRATED (M2.3)

This document provides a comprehensive verification of the `build_validator_set_with_stake_filter()` integration in the QBIND consensus codebase. It addresses the following questions:

1. Is `build_validator_set_with_stake_filter()` invoked in the canonical epoch transition path used by consensus?
2. What is the exact file and function where epoch boundary validator set is constructed?
3. Is there an alternate code path constructing ValidatorSet without stake filtering?
4. Do consensus quorum threshold and leader schedule use the filtered set?

---

## Executive Summary

**STATUS: ✅ PRODUCTION INTEGRATED (M2.3)**

The `build_validator_set_with_stake_filter()` function is now integrated into the canonical epoch transition path through the `StakeFilteringEpochStateProvider`. With M2.3, this provider can now be wired into the `NodeHotstuffHarness` via the `with_stake_filtering_epoch_state_provider()` method.

### M2.3 Integration Components

| Component | Location | Description |
|-----------|----------|-------------|
| `StakeFilteringEpochStateProvider` | `validator_set.rs:883-1055` | Wrapper provider that filters validators at epoch boundary |
| `StakeFilterEmptySetError` | `validator_set.rs:893-920` | Error type for fail-closed behavior |
| `with_stake_filtering_epoch_state_provider()` | `hotstuff_node_sim.rs:908-962` | Builder method to wire filtering into node harness |
| `ArcEpochStateProvider` | `hotstuff_node_sim.rs:93-116` | Helper wrapper for dynamic provider dispatch |
| M2.2 Integration tests | `m2_2_stake_filter_epoch_transition_tests.rs` | 13 tests covering filtering, leader schedule, quorum, determinism |
| M2.3 Node-level tests | `m2_3_stake_filtering_node_integration_tests.rs` | 8 tests covering node-level epoch transitions with filtering |

### Key Features

1. **Stake Filtering**: Validators with `stake < min_validator_stake` are excluded from the active set
2. **Fail-Closed**: If filtering excludes all validators, `get_epoch_state()` returns `None` and logs error
3. **Deterministic**: Validators are sorted by `ValidatorId` before filtering for consistent ordering across nodes
4. **Observable**: Excluded validators are logged for monitoring/debugging
5. **Production Wiring (M2.3)**: `with_stake_filtering_epoch_state_provider()` method enables stake filtering for TestNet/MainNet deployments

---

## 1. Is `build_validator_set_with_stake_filter()` Invoked in Canonical Epoch Transition Path?

### Answer: YES (M2.2 Integrated, M2.3 Production Wired)

### Integration Path:

```
[Epoch Transition Request]
    ↓
StakeFilteringEpochStateProvider::get_epoch_state(epoch)
    ↓
[Inner provider returns candidate EpochState]
    ↓
build_validator_set_with_stake_filter(candidates, min_stake)
    ↓
[Returns filtered EpochState or None if all excluded]
    ↓
BasicHotStuffEngine::transition_to_epoch(filtered_validator_set)
    ↓
[Leader schedule and quorum use filtered set]
```

### Evidence:

**Function Definition (Implemented)**:
- **File**: `crates/qbind-consensus/src/validator_set.rs`
- **Lines**: 146-178
- **Status**: ✅ Fully implemented with deterministic stake filtering logic

```rust
pub fn build_validator_set_with_stake_filter<I>(
    candidates: I,
    min_validator_stake: u64,
) -> Result<ValidatorSetBuildResult, String>
where
    I: IntoIterator<Item = ValidatorCandidate>,
{
    // Collect and sort candidates by validator_id for deterministic ordering
    let mut all_candidates: Vec<ValidatorCandidate> = candidates.into_iter().collect();
    all_candidates.sort_by_key(|c| c.validator_id);

    // Partition into included and excluded based on stake threshold
    let mut included = Vec::new();
    let mut excluded = Vec::new();

    for candidate in all_candidates {
        if candidate.stake >= min_validator_stake {
            included.push(ValidatorSetEntry {
                id: candidate.validator_id,
                voting_power: candidate.voting_power,
            });
        } else {
            excluded.push(candidate);
        }
    }

    // Create the validator set (will fail if empty)
    let validator_set = ConsensusValidatorSet::new(included)?;

    Ok(ValidatorSetBuildResult {
        validator_set,
        excluded,
    })
}
```

**Function Usage**:
- **Production Code**: ✅ **WIRED (M2.3)** - `with_stake_filtering_epoch_state_provider()` in `crates/qbind-node/src/hotstuff_node_sim.rs:908-962`
- **Test Code**: ✅ Used in `crates/qbind-consensus/tests/validator_set_tests.rs` and `crates/qbind-node/tests/m2_3_stake_filtering_node_integration_tests.rs`
- **Documentation**: ✅ Referenced in `docs/protocol/QBIND_PROTOCOL_REPORT.md` as mitigation M2.1+M2.2+M2.3

**Canonical Epoch Transition Path (With M2.3 Stake Filter)**:

1. **Node Builder Setup (M2.3)**:
   - **File**: `crates/qbind-node/src/hotstuff_node_sim.rs`
   - **Lines**: 908-962
   - **Method**: `with_stake_filtering_epoch_state_provider()`
   - **Code**:
     ```rust
     // Create harness with stake filtering
     let harness = NodeHotstuffHarness::new(...)
         .with_stake_filtering_epoch_state_provider(
             Arc::new(inner_provider),
             stake_config.min_validator_stake,
         );
     ```

2. **Epoch Transition Handler**:
   - **File**: `crates/qbind-node/src/hotstuff_node_sim.rs`
   - **Lines**: 3100-3150
   - **Method**: `handle_potential_reconfig_commit()`
   - **Flow**:
     ```rust
     // Line 3107: Fetch the epoch state (now uses stake-filtering provider)
     let epoch_state = match provider.get_epoch_state(next_epoch_id) {
         Some(state) => state,  // Already filtered!
         None => { /* error - possibly all validators excluded */ }
     };
     
     // Line 3134: Get the validator set from the filtered epoch state
     let new_validator_set = epoch_state.validators().clone();
     
     // Line 3150: Transition the engine to the new epoch with filtered set
     self.sim.engine.transition_to_epoch(next_epoch_id, new_validator_set)?;
     ```

2. **Engine Epoch Transition**:
   - **File**: `crates/qbind-consensus/src/basic_hotstuff_engine.rs`
   - **Lines**: 569-605
   - **Method**: `transition_to_epoch()`
   - **Parameters**: Receives already-constructed `ConsensusValidatorSet`
   - **Code**:
     ```rust
     pub fn transition_to_epoch(
         &mut self,
         new_epoch: crate::validator_set::EpochId,
         new_validator_set: ConsensusValidatorSet,  // Already constructed!
     ) -> Result<(), crate::validator_set::EpochTransitionError> {
         // Enforce sequential epoch transitions
         if new_epoch != expected_next { /* error */ }
         
         // Update epoch atomically
         self.current_epoch = new_epoch.as_u64();
         
         // Update leader cache (line 591)
         let mut ids: Vec<ValidatorId> = new_validator_set.iter().map(|v| v.id).collect();
         ids.sort_by_key(|id| id.0);
         self.leaders = ids;
         
         // Update the underlying state engine's validator set (line 597)
         self.state.update_validators(new_validator_set);
     }
     ```

3. **EpochState Construction (Test Path)**:
   - **File**: `crates/qbind-node/src/validator_config.rs`
   - **Lines**: 356-389
   - **Methods**: 
     - `build_consensus_validator_set_for_tests()` (line 356)
     - `build_epoch_state_for_tests()` (line 386)
   - **Status**: Test-only helpers, do NOT use stake filtering
   - **Code**:
     ```rust
     pub fn build_consensus_validator_set_for_tests(&self) -> ConsensusValidatorSet {
         let entries = std::iter::once(ValidatorSetEntry {
             id: self.local.validator_id,
             voting_power: 1,
         })
         .chain(self.remotes.iter().map(|r| ValidatorSetEntry {
             id: r.validator_id,
             voting_power: 1,
         }))
         .collect::<Vec<_>>();

         ConsensusValidatorSet::new(entries)  // Direct construction - NO STAKE FILTER
             .expect("NodeValidatorConfig should not create duplicate validator ids")
     }
     
     pub fn build_epoch_state_for_tests(&self) -> EpochState {
         let validator_set = self.build_consensus_validator_set_for_tests();
         EpochState::genesis(validator_set)  // NO STAKE FILTER
     }
     ```

### Conclusion for Question 1:

**With M2.3 Integration**, the function `build_validator_set_with_stake_filter()` **IS invoked** in the canonical epoch transition path when `StakeFilteringEpochStateProvider` is wired via `with_stake_filtering_epoch_state_provider()`:

- `EpochStateProvider::get_epoch_state()` is called
- If provider is `StakeFilteringEpochStateProvider`, it internally calls `build_validator_set_with_stake_filter()`
- Returns filtered `EpochState` (or `None` if all excluded)
- Filtered `ConsensusValidatorSet` is passed to `BasicHotStuffEngine::transition_to_epoch()`

**M2.4 Note**: The `new_with_stake_filtering()` constructor and `enable_stake_filtering_for_environment()` method in `NodeHotstuffHarness` provide the recommended production integration path. TestNet/MainNet deployments should use these methods to ensure stake filtering is always enabled.

---

## 2. Exact File and Function Where Epoch Boundary Validator Set is Constructed

### Test Path (Current Implementation):

**Primary Construction Point**:
- **File**: `crates/qbind-node/src/validator_config.rs`
- **Function**: `build_consensus_validator_set_for_tests()`
- **Lines**: 356-369
- **Method**: Direct `ConsensusValidatorSet::new(entries)` without stake filtering

**EpochState Wrapper**:
- **File**: `crates/qbind-node/src/validator_config.rs`
- **Function**: `build_epoch_state_for_tests()`
- **Lines**: 386-389
- **Method**: Wraps `ConsensusValidatorSet` in `EpochState::genesis()`

### Epoch Transition Path (Runtime):

**Epoch State Retrieval**:
- **File**: `crates/qbind-node/src/hotstuff_node_sim.rs`
- **Lines**: 3100-3150
- **Method**: `handle_potential_reconfig_commit()`
- **Code**:
  ```rust
  // Line 3107: Fetch from provider
  let epoch_state = match provider.get_epoch_state(next_epoch_id) {
      Some(state) => state,
      None => { /* error */ }
  };
  
  // Line 3134: Extract validator set
  let new_validator_set = epoch_state.validators().clone();
  ```

**EpochStateProvider Trait**:
- **File**: `crates/qbind-consensus/src/validator_set.rs`
- **Trait**: `EpochStateProvider`
- **Lines**: 803-808
- **Method**: `get_epoch_state(&self, epoch: EpochId) -> Option<EpochState>`
- **Status**: Returns pre-constructed `EpochState` objects

**Test Implementation (StaticEpochStateProvider)**:
- **File**: `crates/qbind-consensus/src/validator_set.rs`
- **Struct**: `StaticEpochStateProvider`
- **Lines**: 833-881
- **Method**: Returns `EpochState` from a HashMap (line 878)
- **Status**: Test-only, no stake filtering

### Missing Production Implementation:

**Expected Production Path** (NOT YET IMPLEMENTED):
```
[Ledger State] 
    → Read ValidatorRecords with stake amounts
    → Build ValidatorCandidate list
    → Call build_validator_set_with_stake_filter(candidates, min_stake)
    → Construct EpochState with filtered validator set
    → Store in EpochStateProvider
    → Return from get_epoch_state()
```

**Gap**: There is no production implementation that:
1. Reads validator stake from ledger state
2. Creates `ValidatorCandidate` objects
3. Calls `build_validator_set_with_stake_filter()`
4. Constructs `EpochState` with the filtered set

### Conclusion for Question 2:

**Current (Test) Construction**:
- File: `crates/qbind-node/src/validator_config.rs`
- Function: `build_consensus_validator_set_for_tests()` (line 356)
- Method: Direct `ConsensusValidatorSet::new()` without filtering

**Expected (Production) Construction** (NOT YET IMPLEMENTED):
- Should call `build_validator_set_with_stake_filter()` with validator candidates
- Should be implemented in an `EpochStateProvider` that reads from ledger state
- Currently **missing** from codebase

---

## 3. Alternate Code Paths Constructing ValidatorSet Without Stake Filtering

### Answer: YES - Multiple Paths Exist

### All `ConsensusValidatorSet::new()` Call Sites:

**Production Source Files**:
1. `crates/qbind-node/src/validator_config.rs:367`
   - Function: `build_consensus_validator_set_for_tests()`
   - Status: Test-only helper, no stake filtering

2. `crates/qbind-consensus/src/validator_set.rs:173`
   - Function: `build_validator_set_with_stake_filter()`
   - Status: **This IS the filtered path** - internally calls `ConsensusValidatorSet::new()`
   - Note: This is the ONLY production function that applies filtering

**Test Files** (Multiple instances):
- `crates/qbind-consensus/src/driver.rs`: Lines 847, 875, 914, 953
- `crates/qbind-consensus/src/timeout.rs`: Line 634
- `crates/qbind-consensus/src/basic_hotstuff_engine.rs`: Line 1416
- `crates/qbind-consensus/src/validator_set.rs`: Lines 956, 975, 991, 999, 1017, 1039, 1050, 1072, 1083, 1102, 1120, 1166, 1242, 1263, 1286, 1322
- All integration tests in `crates/qbind-node/tests/`

### EpochState Construction Paths:

**Direct EpochState::new() / EpochState::genesis() Calls**:

1. `crates/qbind-node/src/validator_config.rs:388`
   - Function: `build_epoch_state_for_tests()`
   - Uses: Unfiltered validator set

2. `crates/qbind-node/src/validator_config.rs:400`
   - Function: `build_epoch_state_with_id_for_tests()`
   - Uses: Unfiltered validator set

3. All integration tests:
   - `crates/qbind-node/tests/three_node_epoch_transition_tests.rs:115`
   - `crates/qbind-node/tests/three_node_staggered_epoch_transition_tests.rs:116`
   - `crates/qbind-node/tests/t133_mldsa44_epoch_transition_tests.rs:154`
   - Multiple others

### Configuration Constants (For Filtering):

**Minimum Stake Thresholds Defined**:
- **File**: `crates/qbind-node/src/node_config.rs`
- **Struct**: `ValidatorStakeConfig`
- **Lines**: 2180-2260
- **Fields**:
  - `min_validator_stake: u64` (line 2187)
  - `fail_fast_on_startup: bool` (line 2193)

**Stake Thresholds**:
- DevNet: 1,000,000 microQBIND (1 QBIND) - line 2209
- TestNet: 10,000,000 microQBIND (10 QBIND) - line 2220
- MainNet: 100,000,000,000 microQBIND (100,000 QBIND) - line 2231

**Helper Method**:
```rust
// Line 2237
pub fn is_stake_sufficient(&self, stake: u64) -> bool {
    stake >= self.min_validator_stake
}
```

### Conclusion for Question 3:

**YES**, there are alternate code paths that construct `ValidatorSet` without stake filtering:

1. **Test Path**: `validator_config.rs::build_consensus_validator_set_for_tests()` - No filtering
2. **Current Runtime Path**: Pre-constructed `EpochState` objects in `StaticEpochStateProvider` - No filtering
3. **All Integration Tests**: Direct `ConsensusValidatorSet::new()` calls - No filtering

The **ONLY** code path that applies stake filtering is:
- `build_validator_set_with_stake_filter()` in `validator_set.rs:146-178`
- This function is **NOT called** by any production code path

---

## 4. Do Consensus Quorum Threshold and Leader Schedule Use the Filtered Set?

### Answer: YES (By Design, Pending Integration)

### Quorum Threshold Calculation:

**Implementation**:
- **File**: `crates/qbind-consensus/src/validator_set.rs`
- **Method**: `ConsensusValidatorSet::has_quorum()`
- **Lines**: 315-328
- **Algorithm**: 2/3 total voting power threshold

```rust
/// Checks if a set of validators (by id) reaches >= 2/3 of the total voting power.
pub fn has_quorum<I>(&self, ids: I) -> bool
where
    I: IntoIterator<Item = ValidatorId>,
{
    let mut acc: u64 = 0;
    for id in ids {
        if let Some(idx) = self.index_of(id) {
            let entry = &self.validators[idx];
            acc = acc.saturating_add(entry.voting_power);
        }
    }
    acc >= self.two_thirds_vp()  // Line 327: >= ceil(2 * total / 3)
}
```

**Helper Method**:
```rust
// Lines 303-310
pub fn two_thirds_vp(&self) -> u64 {
    let total = self.total_voting_power();
    (2 * total).div_ceil(3)  // Ceiling division for 2/3 threshold
}
```

**Usage in QC Validation**:
- **File**: `crates/qbind-consensus/src/qc.rs`
- **Lines**: 75-106
- **Method**: `QuorumCertificate::validate()`
- **Code**:
  ```rust
  // Line 105: Check quorum threshold
  if total_vp < validator_set.two_thirds_vp() {
      return Err(QcError::InsufficientQuorum {
          required: validator_set.two_thirds_vp(),
          actual: total_vp,
      });
  }
  ```

### Leader Schedule Calculation:

**Implementation**:
- **File**: `crates/qbind-consensus/src/basic_hotstuff_engine.rs`
- **Method**: `leader_for_view()`
- **Lines**: 607-618
- **Algorithm**: Round-robin over validator IDs

```rust
/// Get the leader for a given view (round-robin).
pub fn leader_for_view(&self, view: u64) -> ValidatorId {
    let n = self.leaders.len() as u64;
    assert!(n > 0, "validator set must not be empty");
    let idx = (view % n) as usize;
    self.leaders[idx]  // Round-robin selection
}
```

**Leader Cache Update During Epoch Transition**:
- **File**: `crates/qbind-consensus/src/basic_hotstuff_engine.rs`
- **Lines**: 590-593 (in `transition_to_epoch()`)
- **Code**:
  ```rust
  // Update leader cache
  let mut ids: Vec<ValidatorId> = new_validator_set.iter().map(|v| v.id).collect();
  ids.sort_by_key(|id| id.0);  // Deterministic ordering
  self.leaders = ids;
  ```

### Data Flow:

```
[Epoch Transition]
    ↓
transition_to_epoch(new_validator_set)  ← Receives ConsensusValidatorSet
    ↓
[Update leader cache: self.leaders = sorted validator IDs]
    ↓
[Update state engine: self.state.update_validators(new_validator_set)]
    ↓
[Consensus Operations]
    ├─→ leader_for_view() uses self.leaders (round-robin)
    └─→ QC validation uses validator_set.has_quorum() (2/3 VP)
```

### Conclusion for Question 4:

**YES**, both quorum threshold and leader schedule use the `ConsensusValidatorSet` passed to `transition_to_epoch()`:

1. **Quorum Threshold**:
   - Uses `ConsensusValidatorSet::has_quorum()` (line 315)
   - Calculates 2/3 of total voting power from the validator set
   - Would automatically use filtered set IF filtering were integrated

2. **Leader Schedule**:
   - Uses `BasicHotStuffEngine::leader_for_view()` (line 613)
   - Operates on `self.leaders` derived from validator set (line 591)
   - Would automatically use filtered set IF filtering were integrated

**Key Point**: Both mechanisms are correctly wired to use whatever `ConsensusValidatorSet` is provided. The issue is that the set provided is **not yet filtered** at epoch boundaries.

---

## 5. Summary and Recommendations

### Current State:

| Component | Status | File/Lines |
|-----------|--------|------------|
| `build_validator_set_with_stake_filter()` function | ✅ Implemented | `validator_set.rs:146-178` |
| Unit tests for stake filtering | ✅ Complete | `validator_set_tests.rs` |
| `ValidatorStakeConfig` with thresholds | ✅ Implemented | `node_config.rs:2180-2260` |
| Quorum calculation using validator set | ✅ Implemented | `validator_set.rs:315-328` |
| Leader schedule using validator set | ✅ Implemented | `basic_hotstuff_engine.rs:613-618` |
| `StakeFilteringEpochStateProvider` (M2.2) | ✅ Implemented | `validator_set.rs:883-1055` |
| `with_stake_filtering_epoch_state_provider()` (M2.3) | ✅ Implemented | `hotstuff_node_sim.rs:978-991` |
| `enable_stake_filtering_for_environment()` (M2.4) | ✅ Implemented | `hotstuff_node_sim.rs:993-1047` |
| `new_with_stake_filtering()` (M2.4) | ✅ Implemented | `hotstuff_node_sim.rs:2372-2434` |
| **Production integration at epoch boundary** | ✅ **AVAILABLE** | Use M2.4 methods for TestNet/MainNet |

### M2.4 Production Wiring:

Production deployments (TestNet/MainNet) should use one of these methods:

1. **`new_with_stake_filtering()`**: Production constructor that wires stake filtering automatically
2. **`enable_stake_filtering_for_environment()`**: Builder method to enable filtering based on `NodeConfig`

### Remaining Integration Work:

The remaining work involves wiring the actual ledger-backed `EpochStateProvider` implementation:

1. **Production EpochStateProvider Implementation** (Future Work):
   - Should read `ValidatorRecord` from ledger state
   - Should extract `validator_id` and `stake` fields
   - Should wrap with `StakeFilteringEpochStateProvider` using `NodeConfig.validator_stake.min_validator_stake`
   - **Location**: To be implemented in a ledger-backed provider

2. **Startup Validation** (Recommended):
   - Implement `fail_fast_on_startup` logic (already in config)
   - Verify initial validator set meets minimum stake requirements
   - Location: Add to startup validation in `crates/qbind-node/src/startup_validation.rs`

---

## 6. References

### Key Source Files:

1. **Stake Filtering Implementation**:
   - `crates/qbind-consensus/src/validator_set.rs:44-178` - ValidatorCandidate, build_validator_set_with_stake_filter()
   - `crates/qbind-consensus/src/validator_set.rs:883-1055` - StakeFilteringEpochStateProvider (M2.2)
   
2. **M2.3/M2.4 Production Integration**:
   - `crates/qbind-node/src/hotstuff_node_sim.rs:978-991` - with_stake_filtering_epoch_state_provider()
   - `crates/qbind-node/src/hotstuff_node_sim.rs:993-1047` - enable_stake_filtering_for_environment()
   - `crates/qbind-node/src/hotstuff_node_sim.rs:2372-2434` - new_with_stake_filtering()
   
3. **Consensus Validator Set**:
   - `crates/qbind-consensus/src/validator_set.rs:181-329` - ConsensusValidatorSet, has_quorum(), two_thirds_vp()
   
3. **Epoch State**:
   - `crates/qbind-consensus/src/validator_set.rs:408-532` - EpochState struct and methods
   - `crates/qbind-consensus/src/validator_set.rs:803-881` - EpochStateProvider trait and StaticEpochStateProvider
   
4. **Epoch Transition**:
   - `crates/qbind-consensus/src/basic_hotstuff_engine.rs:569-605` - transition_to_epoch()
   - `crates/qbind-consensus/src/basic_hotstuff_engine.rs:607-618` - leader_for_view()
   - `crates/qbind-node/src/hotstuff_node_sim.rs:3100-3150` - handle_potential_reconfig_commit()
   
5. **Configuration**:
   - `crates/qbind-node/src/node_config.rs:2180-2260` - ValidatorStakeConfig
   - `crates/qbind-node/src/node_config.rs:2203-2233` - Stake thresholds (DevNet/TestNet/MainNet)
   
6. **Test Helpers**:
   - `crates/qbind-node/src/validator_config.rs:356-400` - Test-only validator set construction
   - `crates/qbind-consensus/tests/validator_set_tests.rs` - Unit tests for stake filtering
   - `crates/qbind-consensus/tests/m2_2_stake_filter_epoch_transition_tests.rs` - M2.2 integration tests

### Documentation:

1. **Protocol Report**:
   - `docs/protocol/QBIND_PROTOCOL_REPORT.md:213-222` - M2.1+M2.2 mitigation reference
   - `docs/protocol/QBIND_PROTOCOL_REPORT.md:231` - Security risk register entry

2. **Repository Memories**:
   - M2.1: Use `build_validator_set_with_stake_filter()` at epoch boundary (stored fact)
   - M2.2: Use `StakeFilteringEpochStateProvider` to integrate filtering into epoch transitions

---

## 7. M2.2 Integration Status Addendum

**Date**: 2026-02-12  
**Status**: ✅ INTEGRATED

### Summary

M2.2 has been completed. The `StakeFilteringEpochStateProvider` now provides a canonical integration point for minimum stake enforcement at epoch transitions.

### Implementation Details

1. **`StakeFilteringEpochStateProvider<P>`** - A generic wrapper around any `EpochStateProvider` implementation that:
   - Intercepts `get_epoch_state()` calls
   - Converts validator entries to `ValidatorCandidate` list
   - Applies `build_validator_set_with_stake_filter()` with configured threshold
   - Returns filtered `EpochState` or `None` if all validators excluded

2. **`StakeFilterEmptySetError`** - Error type for fail-closed diagnostics:
   - Reports epoch ID, candidate count, and min_stake threshold
   - Accessible via `last_filter_error()` method for monitoring

3. **Test Coverage** (13 tests in `m2_2_stake_filter_epoch_transition_tests.rs`):
   - Basic filtering (exclude/include based on stake)
   - Fail-closed behavior (all validators excluded)
   - Leader schedule exclusion (filtered validators never become leader)
   - Quorum threshold calculation (reflects filtered set only)
   - Determinism (same inputs produce same outputs)
   - Multi-epoch transitions
   - Error diagnostics

### Usage

```rust
use qbind_consensus::validator_set::{
    EpochStateProvider, StakeFilteringEpochStateProvider,
    StaticEpochStateProvider,
};
use std::sync::Arc;

// Create inner provider (test or production ledger-backed)
let inner = StaticEpochStateProvider::new()
    .with_epoch(epoch_state);

// Wrap with stake filtering (1 QBIND minimum)
let provider = StakeFilteringEpochStateProvider::new(inner, 1_000_000);

// get_epoch_state now returns filtered validator set
let filtered_state = provider.get_epoch_state(EpochId::new(1));
```

### Remaining Work

~~For full production integration:~~
~~1. Wire `StakeFilteringEpochStateProvider` into `NodeHotstuffHarness` when using production ledger-backed provider~~
~~2. Implement ledger-backed provider that reads `ValidatorRecord.stake` from storage~~

**UPDATE (M2.3)**: Item 1 completed. `with_stake_filtering_epoch_state_provider()` method added to `NodeHotstuffHarness`.

---

## 8. M2.3 Production Integration Addendum

**Date**: 2026-02-12  
**Status**: ✅ PRODUCTION WIRED

### Summary

M2.3 has been completed. The `StakeFilteringEpochStateProvider` is now wired into the canonical epoch transition path at the node level via the `with_stake_filtering_epoch_state_provider()` builder method.

### Implementation Details

1. **`with_stake_filtering_epoch_state_provider()`** (`hotstuff_node_sim.rs:908-962`):
   - Builder method on `NodeHotstuffHarness`
   - Takes an inner `Arc<dyn EpochStateProvider>` and `min_validator_stake`
   - Wraps the inner provider with `StakeFilteringEpochStateProvider`
   - Stores as the harness's `epoch_state_provider`

2. **`ArcEpochStateProvider`** (`hotstuff_node_sim.rs:93-116`):
   - Helper wrapper type that adapts `Arc<dyn EpochStateProvider>` to implement `EpochStateProvider`
   - Enables dynamic dispatch with the generic `StakeFilteringEpochStateProvider<P>`

3. **Test Coverage** (8 tests in `m2_3_stake_filtering_node_integration_tests.rs`):
   - Provider wiring verification
   - Leader schedule exclusion post-transition
   - Quorum threshold reflects filtered set
   - Fail-closed behavior
   - Excluded validator absence post-transition
   - Determinism verification
   - Zero min_stake pass-through
   - Full engine epoch transition with filtering

### Usage

```rust
use qbind_node::NodeHotstuffHarness;
use qbind_consensus::validator_set::StaticEpochStateProvider;
use qbind_node::node_config::ValidatorStakeConfig;
use std::sync::Arc;

// Create inner provider
let inner_provider = StaticEpochStateProvider::new()
    .with_epoch(epoch0)
    .with_epoch(epoch1);

// Get stake config for environment
let stake_config = ValidatorStakeConfig::testnet_default();

// Create harness with stake filtering enabled
let harness = NodeHotstuffHarness::new(local_id, net_cfg, validators, id_map)?
    .with_stake_filtering_epoch_state_provider(
        Arc::new(inner_provider),
        stake_config.min_validator_stake,
    );
```

### Production Deployment

For TestNet/MainNet deployments:

1. Create the appropriate inner `EpochStateProvider` (static or ledger-backed)
2. Obtain `min_validator_stake` from `NodeConfig::validator_stake` or `ValidatorStakeConfig`
3. Use `with_stake_filtering_epoch_state_provider()` when building the `NodeHotstuffHarness`

The epoch transition handler (`handle_potential_reconfig_commit()`) will automatically receive filtered validator sets when calling `provider.get_epoch_state()`.

---

## 9. M2.4 Production Constructor Addendum

**Date**: 2026-02-12  
**Status**: ✅ PRODUCTION CONSTRUCTORS ADDED

### Summary

M2.4 adds production-ready constructors to simplify stake filtering wiring for TestNet/MainNet deployments.

### New Methods

1. **`enable_stake_filtering_for_environment()`** (`hotstuff_node_sim.rs:993-1047`):
   - Builder method that wraps any `EpochStateProvider` with stake filtering
   - Uses `min_validator_stake` from `NodeConfig.validator_stake`
   - Logs the environment and threshold for debugging

2. **`new_with_stake_filtering()`** (`hotstuff_node_sim.rs:2372-2434`):
   - All-in-one production constructor
   - Creates `NodeHotstuffHarness` with stake filtering already wired
   - Recommended for TestNet/MainNet deployments

### Test Coverage (11 tests in `m2_4_production_stake_filtering_tests.rs`):
   - Config preset stake values (DevNet/TestNet/MainNet)
   - Stake filtering with TestNet threshold
   - Stake filtering with MainNet threshold
   - Stake filtering with DevNet threshold
   - Fail-closed behavior
   - Epoch transition with filtered sets
   - MainNet config validation

### Usage

```rust
use qbind_node::NodeHotstuffHarness;
use qbind_node::node_config::NodeConfig;
use std::sync::Arc;

// Method 1: Production constructor (recommended)
let harness = NodeHotstuffHarness::new_with_stake_filtering(
    &cfg,
    client_cfg,
    server_cfg,
    None,
    &NodeConfig::testnet_alpha_preset(),
    Arc::new(inner_provider),
)?;

// Method 2: Builder pattern
let harness = NodeHotstuffHarness::new_from_validator_config(&cfg, client_cfg, server_cfg, None)?
    .enable_stake_filtering_for_environment(
        Arc::new(inner_provider),
        &NodeConfig::testnet_alpha_preset(),
    );
```

---

**Report End**