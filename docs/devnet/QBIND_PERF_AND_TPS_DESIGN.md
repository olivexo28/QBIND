# QBIND Performance & TPS Testing Design

**Task**: T234  
**Status**: Design + Implementation Complete  
**Date**: 2026-02-10

---

## 1. Scope & Motivation

### 1.1 Goals

This document describes the philosophy and architecture of performance testing in QBIND, with a focus on:

- **PQC-first performance evaluation**: Real ML-DSA-44 signatures in end-to-end tests
- **Realistic workload simulation**: Multi-sender, realistic transaction patterns
- **Repeatable measurements**: Deterministic harness with controlled load generation
- **Safety over raw throughput**: Correctness and determinism are prioritized over maximum TPS

### 1.2 Performance Testing Philosophy

QBIND's performance testing strategy follows a **defense-in-depth** approach:

1. **Microbenchmarks** (T198): Measure individual PQC operations in isolation
2. **Stage B Correctness** (T223): Verify parallel execution determinism over long runs
3. **End-to-End Harness** (T234): Measure realistic TPS and latency with full protocol stack

This layered strategy ensures:
- PQC costs are understood at the primitive level
- Parallel execution correctness is proven before performance tuning
- E2E measurements capture real-world protocol overhead

### 1.3 Relationship to Other Performance Work

| Task | Focus | Scope | Evidence Type |
| :--- | :--- | :--- | :--- |
| **T198** | PQC cost benchmarking | ML-DSA-44 sign/verify microbenchmarks | Unit-level primitive costs |
| **T223** | Stage B correctness | Long-run determinism over randomized workloads | Correctness proof (no perf claims) |
| **T234** | E2E performance | Realistic TPS/latency with full protocol stack | End-to-end throughput/latency |

**Key Distinction**: T223 focuses on **correctness** (Stage B = sequential), while T234 focuses on **performance** (how fast can we go?).

---

## 2. Performance Harness Architecture (T234)

### 2.1 Design Overview

The T234 harness is an **in-process cluster test** that:

1. Spins up N validators (3–4 for DevNet/Beta profiles)
2. Generates sender accounts with real ML-DSA-44 keypairs
3. Drives controlled load (configurable TPS rate)
4. Tracks submission → commit latency for each transaction
5. Computes metrics: effective TPS, p50/p90/p99 latency, rejection rate

### 2.2 Core Components

#### PerfHarnessConfig

Configures the test run:

```rust
pub struct PerfHarnessConfig {
    pub num_validators: usize,        // Cluster size (3-4)
    pub stage_b_enabled: bool,         // Enable Stage B parallel execution
    pub target_tps: u32,               // Nominal send rate
    pub run_duration_secs: u32,        // Test duration
    pub num_senders: u32,              // Concurrent sender accounts
    pub max_in_flight: u32,            // Per-sender outstanding tx cap
    pub seed: u64,                     // RNG seed for reproducibility
}
```

**Profiles**:
- **DevNet**: 3 validators, Stage B off, moderate TPS (~200)
- **Beta**: 4 validators, Stage B on, higher TPS (~500)

#### PerfHarnessResult

Captures run results:

```rust
pub struct PerfHarnessResult {
    pub total_submitted: u64,
    pub total_committed: u64,
    pub total_rejected: u64,
    pub p50_latency_ms: f64,
    pub p90_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub avg_tps: f64,
    pub max_in_flight_observed: u32,
    pub stage_b_enabled: bool,
    pub actual_duration_secs: f64,
}
```

### 2.3 Real ML-DSA-44 Signatures

The harness uses **real PQC signatures**, not mocks:

- Each sender account generates a fresh ML-DSA-44 keypair via `MlDsa44Backend::generate_keypair()`
- Transactions are signed with `tx.sign(&secret_key)`
- Signature verification happens in the normal consensus path

This ensures measured TPS and latency reflect real-world PQC costs.

### 2.4 Load Generation & Rate Control

The harness generates load in a controlled manner:

1. **Target TPS** determines the nominal send rate
2. **In-flight limit** prevents overwhelming the mempool
3. **Rate limiter** spaces out submissions evenly over the run
4. **Random sender selection** simulates realistic multi-user workload
5. **Random recipients** create realistic transfer patterns

### 2.5 Latency Tracking

For each transaction:
- **Submission timestamp** recorded when tx enters mempool
- **Commit timestamp** recorded when block containing tx is committed
- **Latency** = commit_time - submit_time

Latencies are sorted and percentiles computed (p50/p90/p99).

---

## 3. Test Scenarios (T234)

### 3.1 Test Suite

| Test | Purpose | Assertions |
| :--- | :--- | :--- |
| `test_pqc_perf_smoke_stage_b_off` | Basic sanity with Stage B off | committed > 0, avg_tps > 0, latencies finite |
| `test_pqc_perf_smoke_stage_b_on` | Basic sanity with Stage B on | Stage B metrics show usage, mismatch = 0 |
| `test_pqc_perf_latency_distribution` | Latency distribution sanity | p90 ≥ p50, p99 ≥ p90, p99 < 10s |
| `test_pqc_perf_reproducibility_with_seed` | Determinism check | Same seed → same submission/commit counts |
| `test_pqc_perf_metrics_snapshot_includes_stage_b_and_mempool` | Metrics presence | Stage B and mempool metric keys present |
| `test_pqc_perf_beta_profile_end_to_end` (ignored) | Higher-load Beta profile | Same assertions, longer run |

### 3.2 CI vs Manual Runs

- **CI**: Short smoke tests (5-10s runs) for every PR
- **Manual**: Longer Beta profile runs (30-60s) for pre-release validation

---

## 4. Metrics & Observability

### 4.1 Harness Metrics

The harness exports:

- **Throughput**: `avg_tps` (committed txs per second)
- **Latency**: p50, p90, p99 latency in milliseconds
- **Rejection rate**: `total_rejected / total_submitted`
- **In-flight tracking**: `max_in_flight_observed` for capacity planning

### 4.2 Integration with Existing Metrics

The harness consumes existing metrics:

| Metric Family | Usage in T234 |
| :--- | :--- |
| `qbind_execution_stage_b_blocks_total{mode=...}` | Verify Stage B usage when enabled |
| `qbind_execution_stage_b_mismatch_total` | Assert mismatch = 0 |
| `qbind_mempool_txs_total{...}` | Verify mempool activity |
| `qbind_mempool_tx_rejected_rate_limit_total{...}` | Track DoS limit rejections |

### 4.3 Structured Logging

The harness emits a **JSON summary line** after each run:

```json
{"stage_b_enabled":true,"total_submitted":1000,"total_committed":980,"total_rejected":20,"avg_tps":98.00,"p50_latency_ms":125.34,"p90_latency_ms":234.56,"p99_latency_ms":456.78,"max_in_flight":15,"duration_secs":10.00}
```

This enables:
- Automated performance regression detection in CI
- Long-term performance trend tracking
- Comparison across different configurations

---

## 5. Extending the Harness

### 5.1 Future Enhancements

The T234 harness is designed to be extended for future work:

| Enhancement | Description | Complexity |
| :--- | :--- | :--- |
| **Bigger clusters** | Test with 7, 10, or 21 validators | Low |
| **WAN latency** | Simulate geographic distribution with network delay injection | Medium |
| **HSM in the loop** | Wire in real HSM remote signer for key path testing | Medium |
| **DAG mempool impact** | Measure DAG vs FIFO throughput differences | Low |
| **Multi-machine harness** | Distributed test cluster across multiple hosts | High |
| **External load generator** | Drive load from separate process/machine | Medium |

### 5.2 How to Add a New Profile

To add a new performance profile:

1. Define a new `PerfHarnessConfig` preset in `t234_pqc_end_to_end_perf_tests.rs`:
   ```rust
   impl PerfHarnessConfig {
       pub fn my_new_profile() -> Self {
           Self {
               num_validators: 7,
               stage_b_enabled: true,
               target_tps: 1000,
               run_duration_secs: 30,
               num_senders: 100,
               max_in_flight: 50,
               seed: 42,
           }
       }
   }
   ```

2. Add a test case:
   ```rust
   #[test]
   #[ignore]
   fn test_pqc_perf_my_new_profile() {
       let config = PerfHarnessConfig::my_new_profile();
       let result = run_perf_harness(&config).expect("Harness failed");
       assert!(result.avg_tps > 0.0);
       result.print_summary();
   }
   ```

3. Run manually:
   ```bash
   cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests \
     test_pqc_perf_my_new_profile -- --ignored --nocapture
   ```

---

## 6. Performance Expectations & Targets

### 6.1 No Hard TPS Target for MainNet v0

QBIND MainNet v0 **does not specify a minimum TPS target**. Instead:

- **Safety & correctness first**: All validators must agree on state
- **Deployment-dependent throughput**: Actual TPS depends on:
  - Validator count (more validators = more signature verification)
  - Hardware specs (CPU cores, NVMe performance)
  - Network latency (geographic distribution)
  - Stage B configuration (parallel vs sequential)

### 6.2 Reference Performance Characteristics

Based on T234 testing, reference characteristics (subject to hardware):

| Configuration | Expected TPS Range | Notes |
| :--- | :--- | :--- |
| 3 validators, local cluster, Stage B off | 100–300 TPS | DevNet reference |
| 4 validators, local cluster, Stage B on | 300–800 TPS | Beta reference |
| 7 validators, WAN-like latency, Stage B on | 100–400 TPS | Realistic MainNet estimate |

**Important**: These are **reference ranges**, not guarantees. Operators should run T234 on their hardware to establish baseline expectations.

### 6.3 Latency Expectations

For typical configurations:

- **p50 latency**: 100–500 ms (1–5 blocks at 100ms block time)
- **p90 latency**: 200–1000 ms (2–10 blocks)
- **p99 latency**: 500–5000 ms (5–50 blocks)

Higher latencies may occur under:
- Heavy load (near mempool capacity)
- View changes (leader failure)
- Network partitions or high packet loss

---

## 7. Running the Harness

### 7.1 Quick Start

```bash
# Run all T234 tests (short smoke tests, CI-friendly)
cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests

# Run with detailed output
cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests -- --nocapture

# Run a specific profile
cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests \
  test_pqc_perf_smoke_stage_b_on -- --nocapture
```

### 7.2 Running Beta Profile (Longer Duration)

```bash
# Ignored by default; must be run explicitly
cargo test -p qbind-node --test t234_pqc_end_to_end_perf_tests \
  test_pqc_perf_beta_profile_end_to_end -- --ignored --nocapture
```

### 7.3 Pre-Release Checklist

Before MainNet launch or major release:

1. **Run Beta profile** on representative hardware
2. **Compare results** to previous baseline
3. **Verify Stage B** shows non-zero parallel usage and zero mismatches
4. **Check rejection rate** is low (< 5%)
5. **Confirm latencies** are within acceptable bounds for your deployment

See [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) §4.4 for operational procedures.

---

## 8. References

- **T234 Implementation**: `crates/qbind-node/tests/t234_pqc_end_to_end_perf_tests.rs`
- **T223 Stage B Soak**: `crates/qbind-node/tests/t223_stage_b_soak_harness.rs`
- **T198 PQC Benchmarks**: See task spec for microbenchmark details
- **MainNet Spec**: [QBIND_MAINNET_V0_SPEC.md](../mainnet/QBIND_MAINNET_V0_SPEC.md) §2.6
- **MainNet Audit**: [QBIND_MAINNET_AUDIT_SKELETON.md](../mainnet/QBIND_MAINNET_AUDIT_SKELETON.md) §4.1
- **MainNet Runbook**: [QBIND_MAINNET_RUNBOOK.md](../ops/QBIND_MAINNET_RUNBOOK.md) §4.4

---

## 9. Maintenance & Updates

This document should be updated when:

- New performance profiles are added
- Harness architecture changes significantly
- Performance characteristics are measured on new hardware
- MainNet performance targets are established

**Last Updated**: 2026-02-10 (T234 implementation)
