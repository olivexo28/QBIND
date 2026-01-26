# T146 PQC Microbench Audit

## What is measured
- ML-DSA-44 keygen/sign/verify loops via tests in crates/qbind-crypto/tests/t146_pqc_microbench_mldsa44_tests.rs
- ML-KEM-768 keygen/encaps/decaps loops via tests in crates/qbind-crypto/tests/t146_pqc_microbench_mlkem768_tests.rs
- Iteration counts are fixed at 100 to keep runtime under a couple of seconds per test

## How to run
- cargo test -p qbind-crypto --test t146_pqc_microbench_mldsa44_tests -- --nocapture
- cargo test -p qbind-crypto --test t146_pqc_microbench_mlkem768_tests -- --nocapture
- Run on a relatively quiet machine for more stable timing output; no timing assertions are enforced

## How to interpret results
- Numbers are rough and machine-dependent; treat them as order-of-magnitude guidance, not stable benchmarks
- Compare relative costs: ML-DSA-44 sign vs verify, and ML-KEM-768 encaps vs decaps
- Think in terms of millis per block for HotStuff when using ML-DSA-44, and handshake overhead for ML-KEM-768
- Protocol behavior does not depend on these numbers; they inform operator tuning and future soak/pacemaker design

## Risks and bottlenecks
- ML-DSA-44 sign/verify likely dominate the HotStuff critical path (as noted in earlier PQC backend audits)
- ML-KEM-768 cost matters mainly for connection storms and KEMTLS handshakes
- Future tasks: feed these measurements into the 3-node PQC soak plan and timeout configuration work

## Notes
- Referenced audit docs T131_PQC_BACKEND_AUDIT, T134_MLKEM_BACKEND_AUDIT, and T135_MLKEM_KEMTLS_AUDIT were not present in this repository snapshot; nothing was changed in protocol or production code paths for this task

## T146 Test Fixes (2026-01-25)

### Summary
The T146 PQC microbench tests and soak_harness have been verified and fixed to compile and pass clippy cleanly.

### Changes made

**T146 ML-KEM-768 microbench tests** (`crates/qbind-crypto/tests/t146_pqc_microbench_mlkem768_tests.rs`):
- The test file already had the correct `KemSuite` trait import (`use qbind_crypto::KemSuite;`)
- No type inference issues were present; the tests compile and run correctly
- All 3 tests pass: keygen, encaps, decaps microbenchmarks

**T146 ML-DSA-44 microbench tests** (`crates/qbind-crypto/tests/t146_pqc_microbench_mldsa44_tests.rs`):
- Tests were already correctly implemented
- All 3 tests pass: keygen, sign, verify microbenchmarks

**Soak harness** (`crates/qbind-node/tests/soak_harness.rs`):
- Fixed clippy `clone_on_copy` warnings by replacing `.clone()` with Copy semantics for `ConsensusLimitsConfig`:
  - Line 404: Changed `custom_limits.clone()` to `*custom_limits`
  - Line 420: Removed unnecessary `.clone()` call on `limits` (Copy type)
- The `rate_limit_drops` and `view_lag` fields already had `#[allow(dead_code)]` annotations

### Validation results
- `cargo fmt --all`: ✓ No formatting changes needed
- `cargo test -p qbind-crypto --test t146_pqc_microbench_mldsa44_tests -- --nocapture`: ✓ 3 tests passed
- `cargo test -p qbind-crypto --test t146_pqc_microbench_mlkem768_tests -- --nocapture`: ✓ 3 tests passed
- `cargo test --all --all-features -j 1`: ✓ All workspace tests pass
- `cargo clippy -p qbind-crypto --test t146_pqc_microbench_* -- -D warnings`: ✓ Clean
- `cargo clippy -p qbind-node --test soak_harness -- -D warnings`: ✓ Clean

Note: There are pre-existing clippy warnings in other test files (not part of T146 scope) that were not modified per the task scope.
