# Validator Set Stake Filter Integration - Quick Reference

**Investigation Date**: 2026-02-12  
**Full Report**: `docs/protocol/VALIDATOR_SET_STAKE_FILTER_INTEGRATION_REPORT.md`

## Quick Answers

### 1. Is `build_validator_set_with_stake_filter()` invoked in canonical epoch transition path?

**❌ NO** - Function exists but is NOT called in production code.

- **Function Location**: `crates/qbind-consensus/src/validator_set.rs:146-178`
- **Current Usage**: Only in unit tests
- **Production Path**: Uses pre-constructed validator sets without filtering

### 2. Where is epoch boundary validator set constructed?

**Test Path** (current implementation):
- File: `crates/qbind-node/src/validator_config.rs`
- Function: `build_consensus_validator_set_for_tests()` (line 356)
- Method: Direct `ConsensusValidatorSet::new()` - NO filtering

**Runtime Path**:
- File: `crates/qbind-node/src/hotstuff_node_sim.rs`
- Lines: 3107-3150
- Retrieves from `EpochStateProvider.get_epoch_state()` - NO filtering

**Missing**: Production implementation that reads validator stakes and applies filtering

### 3. Are there alternate paths without stake filtering?

**✅ YES** - Multiple paths exist without filtering:

1. Test helpers in `validator_config.rs:356-400`
2. All integration tests
3. Current `EpochStateProvider` implementations

**Only filtered path**: `build_validator_set_with_stake_filter()` - NOT called in production

### 4. Do consensus quorum and leader schedule use the validator set?

**✅ YES** - Both correctly use `ConsensusValidatorSet`:

- **Quorum**: `ConsensusValidatorSet::has_quorum()` at `validator_set.rs:315`
  - Uses 2/3 total voting power threshold
- **Leader Schedule**: `BasicHotStuffEngine::leader_for_view()` at `basic_hotstuff_engine.rs:613`
  - Uses round-robin over sorted validator IDs

**Note**: Both would automatically use filtered set IF filtering were integrated

## Key File Locations

| Component | File | Lines |
|-----------|------|-------|
| Stake filter function | `crates/qbind-consensus/src/validator_set.rs` | 146-178 |
| Epoch transition handler | `crates/qbind-node/src/hotstuff_node_sim.rs` | 3100-3150 |
| Engine epoch transition | `crates/qbind-consensus/src/basic_hotstuff_engine.rs` | 569-605 |
| Quorum calculation | `crates/qbind-consensus/src/validator_set.rs` | 315-328 |
| Leader schedule | `crates/qbind-consensus/src/basic_hotstuff_engine.rs` | 607-618 |
| Stake config | `crates/qbind-node/src/node_config.rs` | 2180-2260 |

## Status Summary

| Component | Status |
|-----------|--------|
| `build_validator_set_with_stake_filter()` | ✅ Implemented |
| Unit tests | ✅ Complete |
| Stake config (thresholds) | ✅ Implemented |
| Quorum using validator set | ✅ Implemented |
| Leader schedule using validator set | ✅ Implemented |
| **Production integration** | ❌ **MISSING** |

## Gap: Missing Production Integration

**What's Missing**:
- Production `EpochStateProvider` that reads validator stakes from ledger
- Conversion of ledger `ValidatorRecord` to `ValidatorCandidate` list
- Call to `build_validator_set_with_stake_filter()` at epoch boundary
- Integration between ledger state and epoch state construction

**What Exists**:
- Filtering function with tests
- Configuration with stake thresholds
- Consensus mechanisms ready to use filtered sets

## Next Steps (Recommendations)

1. Implement production `EpochStateProvider` that:
   - Reads `ValidatorRecord.stake` from ledger
   - Creates `ValidatorCandidate` objects
   - Calls `build_validator_set_with_stake_filter()`
   - Returns `EpochState` with filtered validator set

2. Add integration test for stake-filtered epoch transitions

3. Update documentation to reflect integration status

See full report for detailed analysis and code examples.