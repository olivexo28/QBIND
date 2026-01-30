# QBIND Ignored Tests Audit

**Document Version**: 1.0  
**Last Updated**: 2026-01-30  
**Purpose**: Comprehensive audit of all ignored tests in the QBIND PQC L1 blockchain codebase

---

## Executive Summary

This document catalogs all tests marked with `#[ignore]` in the QBIND codebase. These tests are excluded from regular CI runs but remain valuable for manual performance evaluation, load testing, and future feature validation.

**Total Ignored Tests**: 10

**Categories**:
- **Performance/Load Tests**: 9 tests
- **Unimplemented Features**: 1 test

---

## 1. Performance & Load Tests (9 tests)

These tests are ignored because they:
- Execute for extended periods (30-120+ seconds)
- Generate high system load with thousands of transactions
- Are designed for manual benchmarking and TPS measurement
- Would significantly slow down CI pipelines

### 1.1 DevNet Performance Tests

#### Test: `tps_benchmark_canonical`
- **File**: `crates/qbind-node/tests/t154_devnet_tps_harness.rs`
- **Line**: 446
- **Purpose**: Full DevNet TPS benchmark with canonical configuration
- **Configuration**:
  - Validators: 4
  - Mempool size: Configurable
  - Transaction volume: High (thousands)
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test t154_devnet_tps_harness \
    tps_benchmark_canonical -- --ignored --nocapture
  ```
- **Expected Duration**: 60+ seconds
- **Metrics Tracked**: TPS, latency, commit rate, mempool pressure

---

#### Test: `devnet_cluster_soak_fifo_mempool`
- **File**: `crates/qbind-node/tests/t160_devnet_cluster_harness.rs`
- **Line**: 1220
- **Purpose**: DevNet soak test with FIFO mempool under sustained load
- **Configuration**:
  - Validators: 4
  - Mempool: FIFO (non-DAG)
  - Transactions: 5,000
  - Senders: 100 concurrent
  - Send concurrency: 8
  - Max duration: 30 seconds
  - Payload size: 64 bytes
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test t160_devnet_cluster_harness \
    devnet_cluster_soak_fifo_mempool -- --ignored --nocapture
  ```
- **Expected Duration**: 30-60 seconds
- **Success Criteria**:
  - Duration > 0
  - Transactions committed or rejected > 0
  - No crashes or deadlocks

---

#### Test: `devnet_cluster_smoke_dag_mempool`
- **File**: `crates/qbind-node/tests/t160_devnet_cluster_harness.rs`
- **Line**: 1256
- **Purpose**: DevNet smoke test with DAG mempool batching
- **Configuration**:
  - Validators: 4
  - Mempool: DAG (batched)
  - Transactions: 1,000
  - Max txs per block: 500
  - Mempool size: 5,000
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test t160_devnet_cluster_harness \
    devnet_cluster_smoke_dag_mempool -- --ignored --nocapture
  ```
- **Expected Duration**: 20-40 seconds
- **Validation Points**:
  - DAG batch formation
  - Transaction ordering
  - Commit consistency

---

### 1.2 DAG Availability Tests

#### Test: `test_multi_node_cluster_smoke`
- **File**: `crates/qbind-node/tests/t165_dag_availability_integration_tests.rs`
- **Line**: 186
- **Purpose**: Multi-validator DAG availability cluster smoke test
- **Scenario**:
  1. One validator creates a batch
  2. All validators receive the batch
  3. All validators exchange acknowledgments (acks)
  4. All validators form availability certificates
- **Configuration**:
  - Validators: 4
  - Quorum size: 3 (2f+1)
  - DAG availability: Enabled
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test t165_dag_availability_integration_tests \
    test_multi_node_cluster_smoke -- --ignored --nocapture
  ```
- **Expected Duration**: 10-30 seconds
- **Key Metrics**:
  - Acks accepted
  - Certificates formed
  - Batch propagation time

---

### 1.3 TestNet Alpha Performance Tests

#### Test: `test_testnet_alpha_cluster_dag_availability_smoke`
- **File**: `crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs`
- **Line**: 1578
- **Purpose**: TestNet Alpha cluster with DAG mempool and availability certificates
- **Features Tested**:
  - DAG mempool batch creation
  - Availability certificate quorum formation
  - VM state consistency across validators
  - Gas enforcement integration
- **Configuration**:
  - Profile: TestNet Alpha (gas-aware)
  - DAG mempool: Enabled
  - DAG availability: Enabled
  - Timeout: 30 seconds
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness \
    test_testnet_alpha_cluster_dag_availability_smoke -- --ignored --nocapture
  ```
- **Expected Duration**: 30-45 seconds
- **Validation**: VM state must be consistent across all validators

---

#### Test: `test_testnet_alpha_cluster_dag_metrics_integration`
- **File**: `crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs`
- **Line**: 1652
- **Purpose**: Verify DAG availability metrics are tracked correctly
- **Metrics Validated**:
  - `qbind_dag_batch_acks_total{result="accepted"}` > 0
  - `qbind_dag_batch_certs_total` > 0 (when certs form)
  - `qbind_dag_batch_certs_pending` >= 0
- **Configuration**:
  - DAG mempool: Enabled
  - DAG availability: Enabled
  - Transactions: 5
  - Timeout: 20 seconds
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness \
    test_testnet_alpha_cluster_dag_metrics_integration -- --ignored --nocapture
  ```
- **Expected Duration**: 20-30 seconds

---

#### Test: `test_testnet_alpha_tps_scenario_heavy`
- **File**: `crates/qbind-node/tests/t166_testnet_alpha_cluster_harness.rs`
- **Line**: 1730
- **Purpose**: Heavy TPS soak test for TestNet Alpha profile
- **Configuration**:
  - Validators: 4
  - Senders: 20 concurrent
  - Transactions per sender: 50
  - Total transactions: 1,000
  - Initial balance: 10,000,000 (to cover gas fees)
  - Timeout: 60 seconds
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness \
    test_testnet_alpha_tps_scenario_heavy -- --ignored --nocapture
  ```
- **Expected Duration**: 60-90 seconds
- **Metrics Captured**: Per-node TPS, total throughput, latency distribution

---

### 1.4 Consensus Soak Tests

#### Test: `three_node_extended_soak_high_target`
- **File**: `crates/qbind-node/tests/three_node_soak_tests.rs`
- **Line**: 289
- **Purpose**: Extended HotStuff consensus soak test with high target height
- **Configuration**:
  - Nodes: 3
  - Max steps: 10,000
  - Target height: 500
  - Tick interval: 50ms
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test three_node_soak_tests \
    three_node_extended_soak_high_target -- --ignored
  ```
- **Expected Duration**: 60-120 seconds
- **Success Criteria**:
  - Final height >= 500
  - All nodes agree on committed state
  - QCs formed correctly

---

#### Test: `three_node_extended_soak_small_limits_high_target`
- **File**: `crates/qbind-node/tests/three_node_soak_tests.rs`
- **Line**: 322
- **Purpose**: Soak test with memory pressure (small commit log limits)
- **Configuration**:
  - Nodes: 3
  - Max steps: 15,000
  - Target height: 500
  - Commit log limit: Small (triggers eviction)
  - Block store limit: Small
- **Run Command**:
  ```bash
  cargo test -p qbind-node --test three_node_soak_tests \
    three_node_extended_soak_small_limits_high_target -- --ignored
  ```
- **Expected Duration**: 90-180 seconds
- **Validation Points**:
  - Memory eviction works correctly
  - No corruption under memory pressure
  - Consensus remains safe

---

## 2. Unimplemented Features (1 test)

### Test: `driver_commit_notification_with_bounded_log`
- **File**: `crates/qbind-consensus/tests/commit_log_memory_limits_tests.rs`
- **Line**: 291
- **Status**: ❌ **BLOCKED** - Waiting for trait implementation
- **Reason Ignored**: `HotStuffStateEngine` does not implement the `HasCommitLog` trait
- **Context**: 
  - T123 (bounded commit logs) was implemented without requiring this trait
  - Test preserved for future implementation
  - Not critical for current functionality
- **Future Work**: 
  - Implement `HasCommitLog` trait for `HotStuffStateEngine`
  - Enable test after trait implementation
  - Verify driver commit notifications work with bounded logs
- **Estimated Effort**: Medium (trait implementation + validation)

---

## 3. Running Ignored Tests

### Run All Ignored Tests
```bash
cargo test --all --all-features -- --ignored --nocapture
```

### Run Specific Test File
```bash
cargo test -p qbind-node --test <test_file_name> -- --ignored --nocapture
```

### Run Specific Test
```bash
cargo test -p qbind-node --test <test_file_name> <test_name> -- --ignored --nocapture
```

### Examples
```bash
# Run all DevNet cluster tests
cargo test -p qbind-node --test t160_devnet_cluster_harness -- --ignored --nocapture

# Run all three-node soak tests
cargo test -p qbind-node --test three_node_soak_tests -- --ignored --nocapture

# Run all TestNet Alpha heavy tests
cargo test -p qbind-node --test t166_testnet_alpha_cluster_harness -- --ignored --nocapture
```

---

## 4. Test Maintenance Guidelines

### When to Review Ignored Tests

1. **Before Major Releases**: Run all ignored tests to validate performance
2. **After Performance Optimizations**: Verify improvements with load tests
3. **Quarterly**: Review and update test configurations
4. **After Architecture Changes**: Ensure tests still reflect system behavior

### Adding New Ignored Tests

When adding a new performance/load test:

1. **Document the test** in this file with:
   - Purpose and scenario
   - Configuration parameters
   - Expected duration
   - Success criteria
   - Run command

2. **Add appropriate comment** in test file:
   ```rust
   /// <Description of what the test does>
   ///
   /// This test is ignored by default because <reason>.
   ///
   /// Run with: `cargo test -p <package> --test <file> <name> -- --ignored --nocapture`
   #[test]
   #[ignore]
   fn test_name() {
       // ...
   }
   ```

3. **Update this audit file** with the new entry

### Removing Ignored Tests

Before removing an ignored test:

1. Verify it's truly obsolete (not just inconvenient)
2. Document why it was removed in git commit
3. Update this audit file
4. Consider if test should be rewritten rather than removed

---

## 5. CI/CD Integration

### Current CI Behavior
- **Regular CI**: Runs all non-ignored tests (~2000+ tests)
- **Ignored tests**: Skipped automatically
- **Duration**: ~5 minutes with `-j 1`

### Nightly/Weekly CI (Recommended)
Consider adding a nightly or weekly CI job that:
- Runs all ignored performance tests
- Captures metrics and TPS data
- Alerts on performance regressions
- Stores historical performance data

### Example GitHub Actions Config
```yaml
name: Performance Tests (Ignored)
on:
  schedule:
    - cron: '0 2 * * 0'  # Weekly, Sundays at 2 AM
  workflow_dispatch:  # Manual trigger

jobs:
  performance-tests:
    runs-on: ubuntu-latest
    timeout-minutes: 180
    steps:
      - uses: actions/checkout@v3
      - uses: actions-rust-lang/setup-rust-toolchain@v1
      - name: Run ignored tests
        run: cargo test --all --all-features -- --ignored --nocapture
      - name: Archive performance metrics
        uses: actions/upload-artifact@v3
        with:
          name: performance-results
          path: target/performance-*.json
```

---

## 6. Performance Baselines

### Expected TPS (Approximate)

| Test | Configuration | Expected TPS | Notes |
|------|--------------|--------------|-------|
| tps_benchmark_canonical | 4 validators, FIFO | 500-2000 | Baseline DevNet |
| devnet_cluster_soak_fifo_mempool | 4 validators, 5k txs | 300-1500 | With signature verification |
| devnet_cluster_smoke_dag_mempool | 4 validators, DAG | 400-1800 | Batched execution |
| test_testnet_alpha_tps_scenario_heavy | 4 validators, gas-aware | 200-1000 | Gas enforcement overhead |

*Note: Actual TPS depends on hardware, network conditions, and system load*

### Performance Regression Thresholds

Alert if:
- TPS drops > 20% from baseline
- Latency increases > 30% from baseline
- Memory usage increases > 50% from baseline
- Any test timeout or failure

---

## 7. Known Issues & Limitations

### Current Limitations

1. **KEMTLS Test Failure**: `three_node_kemtls_hotstuff_full_consensus` occasionally fails with handshake timeout
   - Tracked separately (not ignored, but flaky)
   - Related to non-blocking I/O timing
   - Does not affect production (PlainTCP mode stable)

2. **Test Duration Variability**: Load tests may vary ±30% in duration based on:
   - CPU load
   - Memory availability
   - Background processes
   - File system performance

3. **Metrics Accuracy**: Single-node tests may show lower ack/cert metrics
   - Expected behavior for simplified test scenarios
   - Full multi-node clusters show realistic metrics

### Future Improvements

- [ ] Add automated performance regression detection
- [ ] Implement historical TPS tracking
- [ ] Create performance dashboard
- [ ] Add memory profiling to soak tests
- [ ] Implement `HasCommitLog` trait for consensus tests
- [ ] Add TestNet Beta load tests (when profile is ready)

---

## 8. Contact & Ownership

**Maintainers**: QBIND Core Team  
**Last Audit**: 2026-01-30  
**Next Review**: 2026-04-30 (Quarterly)

For questions about ignored tests or to request performance test runs, contact the development team or open a GitHub issue with label `testing/performance`.

---

## Appendix A: Quick Reference Table

| Test Name | File | Category | Duration | Priority |
|-----------|------|----------|----------|----------|
| driver_commit_notification_with_bounded_log | commit_log_memory_limits_tests.rs | Unimplemented | N/A | Low |
| tps_benchmark_canonical | t154_devnet_tps_harness.rs | Performance | 60s | High |
| devnet_cluster_soak_fifo_mempool | t160_devnet_cluster_harness.rs | Load Test | 30-60s | High |
| devnet_cluster_smoke_dag_mempool | t160_devnet_cluster_harness.rs | Load Test | 20-40s | High |
| test_multi_node_cluster_smoke | t165_dag_availability_integration_tests.rs | Integration | 10-30s | Medium |
| test_testnet_alpha_cluster_dag_availability_smoke | t166_testnet_alpha_cluster_harness.rs | Integration | 30-45s | Medium |
| test_testnet_alpha_cluster_dag_metrics_integration | t166_testnet_alpha_cluster_harness.rs | Metrics | 20-30s | Medium |
| test_testnet_alpha_tps_scenario_heavy | t166_testnet_alpha_cluster_harness.rs | Performance | 60-90s | High |
| three_node_extended_soak_high_target | three_node_soak_tests.rs | Soak Test | 60-120s | Medium |
| three_node_extended_soak_small_limits_high_target | three_node_soak_tests.rs | Soak Test | 90-180s | Medium |

---

**End of Document**
