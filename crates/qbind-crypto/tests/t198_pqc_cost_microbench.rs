//! T198: PQC Cost Benchmarking Harness
//!
//! This module provides microbenchmarks to quantify the real cost of the QBIND PQC stack:
//! - ML-DSA-44 keygen / sign / verify throughput
//! - Signature and key sizes
//!
//! These benchmarks help calibrate the PQC premium parameters (β_compute, β_bandwidth, β_storage)
//! in `MonetaryEngineConfig` (T195/T196/T197).
//!
//! ## Running Benchmarks
//!
//! All benchmarks are marked `#[ignore]` so they don't run in CI by default.
//! To run locally:
//!
//! ```sh
//! # Run all T198 benchmarks
//! cargo test -p qbind-crypto t198_ -- --ignored --nocapture
//!
//! # Run a specific benchmark
//! cargo test -p qbind-crypto t198_microbench_mldsa44_verify -- --ignored --nocapture
//! ```
//!
//! ## Output Format
//!
//! Each benchmark prints:
//! - Operations per second (ops/sec)
//! - Microseconds per operation (us/op)
//! - Total time and iteration count
//!
//! ## Size Reports
//!
//! The size report test prints:
//! - ML-DSA-44 public key, secret key, and signature sizes
//! - Estimated certificate size for various quorum sizes

use std::time::Instant;

use qbind_crypto::{
    ml_dsa44::MlDsa44Backend, ConsensusSigVerifier, ML_DSA_44_PUBLIC_KEY_SIZE,
    ML_DSA_44_SECRET_KEY_SIZE, ML_DSA_44_SIGNATURE_SIZE,
};

// ============================================================================
// Benchmark Configuration
// ============================================================================

/// Number of iterations for keygen benchmarks (keygen is slow).
const KEYGEN_ITERATIONS: usize = 100;

/// Number of iterations for sign benchmarks.
const SIGN_ITERATIONS: usize = 1_000;

/// Number of iterations for verify benchmarks.
const VERIFY_ITERATIONS: usize = 1_000;

/// Number of iterations for batch certificate verify simulation.
const CERT_VERIFY_ITERATIONS: usize = 100;

/// Typical message size for vote/proposal payloads (bytes).
const TYPICAL_MESSAGE_SIZE: usize = 256;

/// Larger message size for block proposal payloads (bytes).
const LARGE_MESSAGE_SIZE: usize = 4096;

// ============================================================================
// ML-DSA-44 Keygen Benchmark
// ============================================================================

/// Benchmark ML-DSA-44 keypair generation throughput.
///
/// Measures:
/// - Total time for N keygen operations
/// - Operations per second
/// - Microseconds per operation
#[test]
#[ignore]
fn t198_microbench_mldsa44_keygen() {
    println!("\n=== T198 ML-DSA-44 Keygen Benchmark ===");
    println!("Iterations: {}", KEYGEN_ITERATIONS);

    // Warmup: single keygen
    let _ = MlDsa44Backend::generate_keypair().expect("warmup keygen");

    let start = Instant::now();

    for _ in 0..KEYGEN_ITERATIONS {
        let _ = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    }

    let elapsed = start.elapsed();
    let total_ms = elapsed.as_millis();
    let avg_us = elapsed.as_micros() / KEYGEN_ITERATIONS as u128;
    let ops_per_sec = KEYGEN_ITERATIONS as f64 / elapsed.as_secs_f64();

    println!("Results:");
    println!("  Total time:    {} ms", total_ms);
    println!("  Avg per op:    {} us", avg_us);
    println!("  Throughput:    {:.2} ops/sec", ops_per_sec);
    println!(
        "  Keypairs/sec:  {:.2} (for validator rotation planning)",
        ops_per_sec
    );
}

// ============================================================================
// ML-DSA-44 Sign Benchmark
// ============================================================================

/// Benchmark ML-DSA-44 signing throughput with typical message size.
///
/// Measures:
/// - Total time for N sign operations
/// - Operations per second
/// - Microseconds per operation
#[test]
#[ignore]
fn t198_microbench_mldsa44_sign_typical() {
    println!("\n=== T198 ML-DSA-44 Sign Benchmark (Typical Payload) ===");
    println!(
        "Iterations: {}, Message size: {} bytes",
        SIGN_ITERATIONS, TYPICAL_MESSAGE_SIZE
    );

    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = vec![0xABu8; TYPICAL_MESSAGE_SIZE];

    // Warmup
    let _ = MlDsa44Backend::sign(&sk, &message).expect("warmup sign");

    let start = Instant::now();

    for _ in 0..SIGN_ITERATIONS {
        let _ = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");
    }

    let elapsed = start.elapsed();
    let total_ms = elapsed.as_millis();
    let avg_us = elapsed.as_micros() / SIGN_ITERATIONS as u128;
    let ops_per_sec = SIGN_ITERATIONS as f64 / elapsed.as_secs_f64();

    println!("Results:");
    println!("  Total time:    {} ms", total_ms);
    println!("  Avg per op:    {} us", avg_us);
    println!("  Throughput:    {:.2} signs/sec", ops_per_sec);
}

/// Benchmark ML-DSA-44 signing throughput with large message size.
#[test]
#[ignore]
fn t198_microbench_mldsa44_sign_large() {
    println!("\n=== T198 ML-DSA-44 Sign Benchmark (Large Payload) ===");
    println!(
        "Iterations: {}, Message size: {} bytes",
        SIGN_ITERATIONS, LARGE_MESSAGE_SIZE
    );

    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = vec![0xCDu8; LARGE_MESSAGE_SIZE];

    // Warmup
    let _ = MlDsa44Backend::sign(&sk, &message).expect("warmup sign");

    let start = Instant::now();

    for _ in 0..SIGN_ITERATIONS {
        let _ = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");
    }

    let elapsed = start.elapsed();
    let total_ms = elapsed.as_millis();
    let avg_us = elapsed.as_micros() / SIGN_ITERATIONS as u128;
    let ops_per_sec = SIGN_ITERATIONS as f64 / elapsed.as_secs_f64();

    println!("Results:");
    println!("  Total time:    {} ms", total_ms);
    println!("  Avg per op:    {} us", avg_us);
    println!("  Throughput:    {:.2} signs/sec", ops_per_sec);
}

// ============================================================================
// ML-DSA-44 Verify Benchmark
// ============================================================================

/// Benchmark ML-DSA-44 verification throughput with typical message size.
///
/// Measures:
/// - Total time for N verify operations
/// - Operations per second
/// - Microseconds per operation
/// - Extrapolated verifies per block (at various block sizes)
#[test]
#[ignore]
fn t198_microbench_mldsa44_verify_typical() {
    println!("\n=== T198 ML-DSA-44 Verify Benchmark (Typical Payload) ===");
    println!(
        "Iterations: {}, Message size: {} bytes",
        VERIFY_ITERATIONS, TYPICAL_MESSAGE_SIZE
    );

    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = vec![0xEFu8; TYPICAL_MESSAGE_SIZE];
    let signature = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");
    let backend = MlDsa44Backend::new();

    // Warmup
    backend
        .verify_vote(1, &pk, &message, &signature)
        .expect("warmup verify");

    let start = Instant::now();

    for _ in 0..VERIFY_ITERATIONS {
        backend
            .verify_vote(1, &pk, &message, &signature)
            .expect("verification should succeed");
    }

    let elapsed = start.elapsed();
    let total_ms = elapsed.as_millis();
    let avg_us = elapsed.as_micros() / VERIFY_ITERATIONS as u128;
    let ops_per_sec = VERIFY_ITERATIONS as f64 / elapsed.as_secs_f64();

    println!("Results:");
    println!("  Total time:    {} ms", total_ms);
    println!("  Avg per op:    {} us", avg_us);
    println!("  Throughput:    {:.2} verifies/sec", ops_per_sec);

    // Extrapolate to block-level
    println!("\nBlock-level extrapolation (at current throughput):");
    for txs_per_block in [100, 500, 1000, 5000] {
        let verify_time_ms = (txs_per_block as f64 * avg_us as f64) / 1000.0;
        println!(
            "  {} txs/block: {:.2} ms verify time",
            txs_per_block, verify_time_ms
        );
    }
}

/// Benchmark ML-DSA-44 verification throughput with large message size.
#[test]
#[ignore]
fn t198_microbench_mldsa44_verify_large() {
    println!("\n=== T198 ML-DSA-44 Verify Benchmark (Large Payload) ===");
    println!(
        "Iterations: {}, Message size: {} bytes",
        VERIFY_ITERATIONS, LARGE_MESSAGE_SIZE
    );

    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = vec![0x12u8; LARGE_MESSAGE_SIZE];
    let signature = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");
    let backend = MlDsa44Backend::new();

    // Warmup
    backend
        .verify_vote(1, &pk, &message, &signature)
        .expect("warmup verify");

    let start = Instant::now();

    for _ in 0..VERIFY_ITERATIONS {
        backend
            .verify_vote(1, &pk, &message, &signature)
            .expect("verification should succeed");
    }

    let elapsed = start.elapsed();
    let total_ms = elapsed.as_millis();
    let avg_us = elapsed.as_micros() / VERIFY_ITERATIONS as u128;
    let ops_per_sec = VERIFY_ITERATIONS as f64 / elapsed.as_secs_f64();

    println!("Results:");
    println!("  Total time:    {} ms", total_ms);
    println!("  Avg per op:    {} us", avg_us);
    println!("  Throughput:    {:.2} verifies/sec", ops_per_sec);
}

// ============================================================================
// Batch Certificate Verify Benchmark (Simulated)
// ============================================================================

/// Benchmark batch certificate verification (simulated 2f+1 signatures).
///
/// A BatchCertificate with 2f+1 validators requires verifying 2f+1 ML-DSA-44
/// signatures. This benchmark simulates that workload for various committee sizes.
///
/// For n=4 validators: 2f+1 = 3 signatures (f=1)
/// For n=7 validators: 2f+1 = 5 signatures (f=2)
/// For n=10 validators: 2f+1 = 7 signatures (f=3)
/// For n=100 validators: 2f+1 = 67 signatures (f=33)
#[test]
#[ignore]
fn t198_microbench_dag_certificate_verify() {
    println!("\n=== T198 DAG Certificate Verify Benchmark ===");
    println!(
        "Iterations per config: {}, Message size: {} bytes",
        CERT_VERIFY_ITERATIONS, TYPICAL_MESSAGE_SIZE
    );

    // Simulate batch acknowledgment preimage (batch_ref + validator_id + view_hint)
    // ~56 bytes typical
    let ack_preimage_size = 56;
    let message = vec![0x77u8; ack_preimage_size];
    let backend = MlDsa44Backend::new();

    // Test configurations: (n_validators, quorum_size, description)
    let configs: Vec<(usize, usize, &str)> = vec![
        (4, 3, "small committee (n=4, 2f+1=3)"),
        (7, 5, "medium committee (n=7, 2f+1=5)"),
        (10, 7, "standard committee (n=10, 2f+1=7)"),
        (21, 15, "large committee (n=21, 2f+1=15)"),
        (100, 67, "very large committee (n=100, 2f+1=67)"),
    ];

    for (n_validators, quorum_size, description) in configs {
        println!("\n--- {} ---", description);

        // Generate quorum_size keypairs and signatures
        let mut validators: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(quorum_size);
        let mut signatures: Vec<Vec<u8>> = Vec::with_capacity(quorum_size);

        for _ in 0..quorum_size {
            let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
            let sig = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");
            validators.push((pk, sk));
            signatures.push(sig);
        }

        // Warmup: verify all signatures once
        for (i, (pk, _)) in validators.iter().enumerate() {
            backend
                .verify_vote(i as u64, pk, &message, &signatures[i])
                .expect("warmup verify");
        }

        // Benchmark: verify all quorum signatures CERT_VERIFY_ITERATIONS times
        let start = Instant::now();

        for _ in 0..CERT_VERIFY_ITERATIONS {
            for (i, (pk, _)) in validators.iter().enumerate() {
                backend
                    .verify_vote(i as u64, pk, &message, &signatures[i])
                    .expect("verification should succeed");
            }
        }

        let elapsed = start.elapsed();
        let total_verifies = CERT_VERIFY_ITERATIONS * quorum_size;
        let total_ms = elapsed.as_millis();
        let avg_us_per_cert = elapsed.as_micros() / CERT_VERIFY_ITERATIONS as u128;
        let avg_us_per_verify = elapsed.as_micros() / total_verifies as u128;
        let certs_per_sec = CERT_VERIFY_ITERATIONS as f64 / elapsed.as_secs_f64();

        println!("Results:");
        println!("  Committee size:        {}", n_validators);
        println!("  Quorum size:           {}", quorum_size);
        println!("  Total verifies:        {}", total_verifies);
        println!("  Total time:            {} ms", total_ms);
        println!("  Avg per certificate:   {} us", avg_us_per_cert);
        println!("  Avg per single verify: {} us", avg_us_per_verify);
        println!("  Certificate throughput: {:.2} certs/sec", certs_per_sec);

        // Estimate certificate wire size (without signature aggregation)
        // batch_ref (40) + view (8) + signers (quorum * 8) + signatures (quorum * 2420)
        let cert_overhead = 40 + 8 + (quorum_size * 8);
        let cert_with_sigs = cert_overhead + (quorum_size * ML_DSA_44_SIGNATURE_SIZE);
        println!(
            "  Est. cert size (w/ sigs): {} bytes ({:.1} KB)",
            cert_with_sigs,
            cert_with_sigs as f64 / 1024.0
        );
    }
}

// ============================================================================
// PQC Size Report
// ============================================================================

/// Report sizes of PQC primitives for bandwidth/storage cost estimation.
///
/// This helps calibrate β_bandwidth and β_storage in MonetaryEngineConfig.
#[test]
#[ignore]
fn t198_pqc_size_report() {
    println!("\n=== T198 PQC Size Report ===");

    // ML-DSA-44 sizes (compile-time constants)
    println!("\nML-DSA-44 Key/Signature Sizes:");
    println!(
        "  Public key:    {} bytes ({:.1} KB)",
        ML_DSA_44_PUBLIC_KEY_SIZE,
        ML_DSA_44_PUBLIC_KEY_SIZE as f64 / 1024.0
    );
    println!(
        "  Secret key:    {} bytes ({:.2} KB)",
        ML_DSA_44_SECRET_KEY_SIZE,
        ML_DSA_44_SECRET_KEY_SIZE as f64 / 1024.0
    );
    println!(
        "  Signature:     {} bytes ({:.2} KB)",
        ML_DSA_44_SIGNATURE_SIZE,
        ML_DSA_44_SIGNATURE_SIZE as f64 / 1024.0
    );

    // Verify runtime matches constants
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen should succeed");
    let message = [0u8; 64];
    let signature = MlDsa44Backend::sign(&sk, &message).expect("signing should succeed");

    println!("\nRuntime verification:");
    println!(
        "  Generated PK:  {} bytes (expected {})",
        pk.len(),
        ML_DSA_44_PUBLIC_KEY_SIZE
    );
    println!(
        "  Generated SK:  {} bytes (expected {})",
        sk.len(),
        ML_DSA_44_SECRET_KEY_SIZE
    );
    println!(
        "  Generated sig: {} bytes (expected {})",
        signature.len(),
        ML_DSA_44_SIGNATURE_SIZE
    );

    assert_eq!(pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
    assert_eq!(sk.len(), ML_DSA_44_SECRET_KEY_SIZE);
    assert_eq!(signature.len(), ML_DSA_44_SIGNATURE_SIZE);

    // Comparison with classical ECDSA (for context)
    println!("\nComparison with classical ECDSA (secp256k1):");
    let ecdsa_pk_size = 33; // compressed
    let ecdsa_sig_size = 64;
    println!("  ECDSA public key:  {} bytes", ecdsa_pk_size);
    println!("  ECDSA signature:   {} bytes", ecdsa_sig_size);
    println!(
        "  ML-DSA-44 PK premium: {:.1}x larger",
        ML_DSA_44_PUBLIC_KEY_SIZE as f64 / ecdsa_pk_size as f64
    );
    println!(
        "  ML-DSA-44 sig premium: {:.1}x larger",
        ML_DSA_44_SIGNATURE_SIZE as f64 / ecdsa_sig_size as f64
    );

    // BatchCertificate size estimates
    println!("\nBatchCertificate size estimates (v1, no aggregation):");
    println!(
        "  Base overhead (batch_ref + view + length): {} bytes",
        40 + 8 + 4
    );

    for quorum_size in [3, 5, 7, 15, 67] {
        // signers (quorum * 8) + signatures (quorum * 2420)
        let signers_size = quorum_size * 8;
        let signatures_size = quorum_size * ML_DSA_44_SIGNATURE_SIZE;
        let total = 52 + signers_size + signatures_size;
        println!(
            "  quorum={:3}: {} bytes ({:.1} KB) - {} sigs",
            quorum_size,
            total,
            total as f64 / 1024.0,
            quorum_size
        );
    }

    // Transaction overhead estimate
    println!("\nPer-transaction PQC overhead:");
    println!(
        "  Signature overhead: {} bytes",
        ML_DSA_44_SIGNATURE_SIZE
    );
    println!(
        "  For 1000 txs/block: {} KB additional",
        (1000 * ML_DSA_44_SIGNATURE_SIZE) / 1024
    );
    println!(
        "  For 5000 txs/block: {} KB additional",
        (5000 * ML_DSA_44_SIGNATURE_SIZE) / 1024
    );
}

// ============================================================================
// PQC Premium Calibration Helper
// ============================================================================

/// Report suggested PQC premium values based on benchmark results.
///
/// This test provides a framework for operators to calculate suggested
/// β_compute, β_bandwidth, and β_storage values based on their hardware.
///
/// The actual calibration should be done by operators running the full
/// benchmark suite on their target hardware.
#[test]
#[ignore]
fn t198_pqc_premium_calibration_helper() {
    println!("\n=== T198 PQC Premium Calibration Helper ===");

    println!("\nThis helper provides a framework for calibrating PQC premiums.");
    println!("Run the full benchmark suite on your target hardware, then use");
    println!("these formulas to calculate suggested premium values:\n");

    // Compute premium (β_compute)
    println!("β_compute (CPU overhead for verification):");
    println!("  Formula: (ml_dsa44_verify_us - ecdsa_verify_us) / ecdsa_verify_us");
    println!("  Typical ECDSA verify: ~50-100 us");
    println!("  Typical ML-DSA-44 verify: ~200-500 us (see benchmark results)");
    println!("  Expected range: 0.20 - 0.35\n");

    // Bandwidth premium (β_bandwidth)
    println!("β_bandwidth (signature size overhead):");
    println!(
        "  Formula: (ml_dsa44_sig_size - ecdsa_sig_size) / ecdsa_sig_size"
    );
    println!("  ECDSA signature: 64 bytes");
    println!(
        "  ML-DSA-44 signature: {} bytes",
        ML_DSA_44_SIGNATURE_SIZE
    );
    let bandwidth_ratio = ML_DSA_44_SIGNATURE_SIZE as f64 / 64.0;
    println!("  Size ratio: {:.1}x", bandwidth_ratio);
    println!("  Suggested β_bandwidth: 0.10 - 0.20\n");

    // Storage premium (β_storage)
    println!("β_storage (key storage overhead):");
    println!("  Formula: (ml_dsa44_pk_size - ecdsa_pk_size) / ecdsa_pk_size");
    println!("  ECDSA public key: 33 bytes (compressed)");
    println!("  ML-DSA-44 public key: {} bytes", ML_DSA_44_PUBLIC_KEY_SIZE);
    let storage_ratio = ML_DSA_44_PUBLIC_KEY_SIZE as f64 / 33.0;
    println!("  Size ratio: {:.1}x", storage_ratio);
    println!("  Suggested β_storage: 0.05 - 0.10\n");

    // Example MonetaryEngineConfig setup
    println!("Example MonetaryEngineConfig premium values:");
    println!("```rust");
    println!("MonetaryEngineConfig {{");
    println!("    pqc_premium_compute: 0.30,   // Policy multiplier (not raw overhead ratio)");
    println!("    pqc_premium_bandwidth: 0.15, // Policy multiplier (not raw size ratio)");
    println!("    pqc_premium_storage: 0.10,   // Policy multiplier (not raw size ratio)");
    println!("    // ... other fields ...");
    println!("}}");
    println!("```\n");

    println!("Note: These are moderated policy multipliers, NOT the raw overhead ratios.");
    println!("The raw ratios (37.8x for signatures, 39.8x for keys) are too large to use");
    println!("directly as inflation adjustments. The premiums capture the marginal cost");
    println!("impact on validator economics after accounting for economies of scale.");
    println!("\nRun benchmarks on your hardware and adjust based on actual measurements");
    println!("vs. classical alternatives and network economics.");
}

// ============================================================================
// Throughput Regression Baseline
// ============================================================================

/// Establish baseline throughput for regression detection.
///
/// This test runs a fixed workload and reports results that can be compared
/// across runs to detect performance regressions.
#[test]
#[ignore]
fn t198_throughput_regression_baseline() {
    println!("\n=== T198 Throughput Regression Baseline ===");

    let iterations = 500;
    let message = vec![0xAAu8; TYPICAL_MESSAGE_SIZE];
    let backend = MlDsa44Backend::new();

    // Keygen baseline
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = MlDsa44Backend::generate_keypair().expect("keygen");
    }
    let keygen_elapsed = start.elapsed();
    let keygen_ops_sec = iterations as f64 / keygen_elapsed.as_secs_f64();

    // Sign baseline
    let (_, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = MlDsa44Backend::sign(&sk, &message).expect("sign");
    }
    let sign_elapsed = start.elapsed();
    let sign_ops_sec = iterations as f64 / sign_elapsed.as_secs_f64();

    // Verify baseline
    let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
    let sig = MlDsa44Backend::sign(&sk, &message).expect("sign");
    let start = Instant::now();
    for _ in 0..iterations {
        backend.verify_vote(1, &pk, &message, &sig).expect("verify");
    }
    let verify_elapsed = start.elapsed();
    let verify_ops_sec = iterations as f64 / verify_elapsed.as_secs_f64();

    println!("Baseline results (iterations={}):", iterations);
    println!("  Keygen:  {:.1} ops/sec", keygen_ops_sec);
    println!("  Sign:    {:.1} ops/sec", sign_ops_sec);
    println!("  Verify:  {:.1} ops/sec", verify_ops_sec);

    // Compute derived metrics
    let verify_us = verify_elapsed.as_micros() as f64 / iterations as f64;
    let block_1000_ms = (1000.0 * verify_us) / 1000.0;
    let block_5000_ms = (5000.0 * verify_us) / 1000.0;

    println!("\nDerived metrics:");
    println!("  Verify latency: {:.1} us/op", verify_us);
    println!("  1000-tx block verify time: {:.1} ms", block_1000_ms);
    println!("  5000-tx block verify time: {:.1} ms", block_5000_ms);

    // Output in machine-readable format
    println!("\n--- Machine-readable baseline ---");
    println!("KEYGEN_OPS_SEC={:.1}", keygen_ops_sec);
    println!("SIGN_OPS_SEC={:.1}", sign_ops_sec);
    println!("VERIFY_OPS_SEC={:.1}", verify_ops_sec);
    println!("VERIFY_US_PER_OP={:.1}", verify_us);
}