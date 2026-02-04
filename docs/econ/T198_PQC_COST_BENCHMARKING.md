# T198: PQC Cost Benchmarking Harness & Monetary Parameter Calibration

## Overview

This document describes the PQC (Post-Quantum Cryptography) cost benchmarking harness introduced in T198. The harness measures the real computational, bandwidth, and storage costs of QBIND's PQC stack (ML-DSA-44, DAG certificates) and provides guidance for calibrating the `MonetaryEngineConfig` premium parameters.

## Purpose

The T198 harness answers these questions with real data:

1. **How expensive are ML-DSA-44 signatures?**
   - Per keygen, per sign, per verify
   - Operations per second
   - Impact on block processing time

2. **How expensive are DAG certificates?**
   - CPU cost for 2f+1 signature verification
   - Bandwidth cost for certificate wire format
   - Scaling with committee size

3. **What are the PQC premiums for monetary policy calibration?**
   - `β_compute`: CPU overhead vs classical signatures
   - `β_bandwidth`: Signature/key size overhead
   - `β_storage`: Key storage overhead

## Running the Benchmarks

### Quick Start

All T198 benchmarks are marked `#[ignore]` so they don't run in CI by default. Run them locally with:

```bash
# Run all T198 benchmarks
cargo test -p qbind-crypto t198_ -- --ignored --nocapture

# Run specific benchmark
cargo test -p qbind-crypto t198_microbench_mldsa44_verify_typical -- --ignored --nocapture

# Run size report only
cargo test -p qbind-crypto t198_pqc_size_report -- --ignored --nocapture
```

### Available Benchmarks

| Benchmark | Description |
|-----------|-------------|
| `t198_microbench_mldsa44_keygen` | Keypair generation throughput |
| `t198_microbench_mldsa44_sign_typical` | Signing with 256-byte payloads |
| `t198_microbench_mldsa44_sign_large` | Signing with 4KB payloads |
| `t198_microbench_mldsa44_verify_typical` | Verification with 256-byte payloads |
| `t198_microbench_mldsa44_verify_large` | Verification with 4KB payloads |
| `t198_microbench_dag_certificate_verify` | Certificate verification (various quorum sizes) |
| `t198_pqc_size_report` | Key and signature size analysis |
| `t198_pqc_premium_calibration_helper` | Calibration formula reference |
| `t198_throughput_regression_baseline` | Baseline for regression detection |

### Output Format

Each benchmark prints human-readable results:

```
=== T198 ML-DSA-44 Verify Benchmark (Typical Payload) ===
Iterations: 1000, Message size: 256 bytes
Results:
  Total time:    1234 ms
  Avg per op:    1234 us
  Throughput:    810.5 verifies/sec

Block-level extrapolation (at current throughput):
  100 txs/block: 123.4 ms verify time
  500 txs/block: 617.0 ms verify time
  1000 txs/block: 1234.0 ms verify time
  5000 txs/block: 6170.0 ms verify time
```

## PQC Premium Calibration

### Understanding the Premiums

The `MonetaryEngineConfig` (T195) includes three PQC premium factors:

```rust
pub struct MonetaryEngineConfig {
    /// PQC compute premium (β_compute): higher CPU cost for ML-DSA-44 verification.
    /// Typical range: 0.20–0.35
    pub pqc_premium_compute: f64,

    /// PQC bandwidth premium (β_bandwidth): larger signature sizes.
    /// Typical range: 0.10–0.20
    pub pqc_premium_bandwidth: f64,

    /// PQC storage premium (β_storage): larger keys and state.
    /// Typical range: 0.05–0.10
    pub pqc_premium_storage: f64,
    // ...
}
```

These premiums adjust the inflation target rate to account for the additional costs of operating a PQC chain:

```
effective_r_target = r_target_base * (1 + β_compute + β_bandwidth + β_storage)
```

### Calibration Formulas

#### β_compute (CPU Overhead)

```
β_compute = (ml_dsa44_verify_us - ecdsa_verify_us) / ecdsa_verify_us
```

Reference values:
- Typical ECDSA (secp256k1) verify: 50-100 μs
- Typical ML-DSA-44 verify: 200-500 μs
- Resulting β_compute: 0.20 - 0.35

#### β_bandwidth (Bandwidth Premium Factor)

The raw size ratio formula:
```
raw_ratio = (ml_dsa44_sig_size - ecdsa_sig_size) / ecdsa_sig_size
```

Reference values:
- ECDSA signature: 64 bytes
- ML-DSA-44 signature: 2,420 bytes
- Raw size ratio: ~37.8x larger

**Important**: The raw ratio (~36.8 overhead) is too large to use directly as an inflation adjustment. The β_bandwidth premium is a **moderated policy multiplier** that captures the marginal cost impact on validator economics after accounting for:
- Economies of scale in bandwidth costs
- Batching and compression efficiencies
- Network-level amortization

Suggested β_bandwidth: 0.10 - 0.20

#### β_storage (Storage Premium Factor)

The raw size ratio formula:
```
raw_ratio = (ml_dsa44_pk_size - ecdsa_pk_size) / ecdsa_pk_size
```

Reference values:
- ECDSA public key: 33 bytes (compressed)
- ML-DSA-44 public key: 1,312 bytes
- Raw size ratio: ~39.8x larger

**Important**: Like β_bandwidth, the β_storage premium is a **moderated policy multiplier**, not the raw size ratio. It captures the marginal cost impact after accounting for:
- SSD/storage cost amortization
- State pruning efficiencies
- Account churn rates

Suggested β_storage: 0.05 - 0.10

### Recommended Process

1. **Run baseline on target hardware:**
   ```bash
   cargo test -p qbind-crypto t198_throughput_regression_baseline -- --ignored --nocapture
   ```

2. **Compare with classical baseline:**
   - Measure ECDSA verify time on same hardware (if available)
   - Or use reference values: 50-100 μs for secp256k1

3. **Calculate premiums:**
   ```
   β_compute = (your_verify_us - 75) / 75  # Using 75μs as baseline
   β_bandwidth = 0.15  # Fixed based on protocol overhead ratio
   β_storage = 0.08    # Fixed based on state growth ratio
   ```

4. **Apply to MonetaryEngineConfig:**
   ```rust
   MonetaryEngineConfig {
       pqc_premium_compute: 0.30,   // Adjust based on step 3
       pqc_premium_bandwidth: 0.15,
       pqc_premium_storage: 0.08,
       // ...
   }
   ```

## Size Reference

### ML-DSA-44 Sizes

| Component | Size (bytes) | Size (KB) |
|-----------|-------------|-----------|
| Public key | 1,312 | 1.28 |
| Secret key | 2,560 | 2.50 |
| Signature | 2,420 | 2.36 |

### BatchCertificate Sizes (v1, no aggregation)

| Quorum Size | Estimated Size | Notes |
|-------------|----------------|-------|
| 3 (n=4) | 7.3 KB | Small DevNet |
| 5 (n=7) | 12.2 KB | Medium TestNet |
| 7 (n=10) | 17.0 KB | Standard |
| 15 (n=21) | 36.4 KB | Large network |
| 67 (n=100) | 162.3 KB | Very large |

### Per-Transaction Overhead

| Block Size | PQC Signature Overhead |
|------------|----------------------|
| 100 txs | 237 KB |
| 500 txs | 1.18 MB |
| 1000 txs | 2.37 MB |
| 5000 txs | 11.8 MB |

## Integration with Monetary Policy

### How Premiums Affect Inflation

The PQC premiums are **moderated policy multipliers** that adjust the inflation target to compensate validators for PQC-related costs. The multiplier is applied additively:

```
pqc_mult = 1.0 + β_compute + β_bandwidth + β_storage
         = 1.0 + 0.30 + 0.15 + 0.10
         = 1.55

effective_r_target = r_target_base * pqc_mult
                   = 0.05 * 1.55
                   = 0.0775 (7.75%)
```

**Note**: The premium values (0.30, 0.15, 0.10) are not raw overhead ratios. They are calibrated to capture the marginal cost impact on validator economics while avoiding excessive inflation. The raw size ratios (~37-40x for PQC vs ECDSA) would result in unreasonably high inflation if used directly.

This compensates validators for the additional PQC costs.

### Phase-Specific Impacts

| Phase | Base Target | With PQC Premium (1.55x) |
|-------|-------------|-------------------------|
| Bootstrap | 5% | 7.75% |
| Transition | 4% | 6.20% |
| Mature | 3% | 4.65% |

## Future Work

1. **Signature Aggregation**: When PQ aggregate schemes mature, BatchCertificate sizes will decrease significantly.

2. **Hardware Acceleration**: ML-DSA-44 performance varies with hardware; SIMD optimizations may improve throughput.

3. **Adaptive Premiums**: Future governance may adjust premiums based on observed network costs.

## Related Documents

- [QBIND_MONETARY_POLICY_DESIGN.md](QBIND_MONETARY_POLICY_DESIGN.md) - T194 monetary policy design
- T195: MonetaryEngineConfig and inflation calculation
- T196: Monetary telemetry and observability
- T197: MonetaryMode and seigniorage wiring