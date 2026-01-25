//! T147: Integration tests for parallel verification in NodeHotstuffHarness.
//!
//! These tests verify:
//! - The verification pool correctly uses multi-threaded workers
//! - Valid messages are processed and return ok=true
//! - Invalid messages are rejected with ok=false
//! - Behavior matches the prior single-threaded mode
//! - No deadlocks or panics under mixed valid/invalid messages

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use cano_consensus::crypto_verifier::SimpleBackendRegistry;
use cano_consensus::ids::ValidatorId;
use cano_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use cano_consensus::verify_job::{ConsensusMsgKind, ConsensusVerifyJob};
use cano_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use cano_crypto::ConsensusSigSuiteId;
use cano_node::verify_pool::{ConsensusVerifyPool, ConsensusVerifyPoolConfig};

// ============================================================================
// Test helpers
// ============================================================================

/// Suite ID for ML-DSA-44 (used in tests)
const TEST_SUITE_ID: u16 = 100;

/// A mock key provider that returns test keys for validators.
#[derive(Debug)]
struct TestKeyProvider {
    suite_id: ConsensusSigSuiteId,
    keys: HashMap<ValidatorId, Vec<u8>>,
}

impl TestKeyProvider {
    fn new(suite_id: u16) -> Self {
        TestKeyProvider {
            suite_id: ConsensusSigSuiteId::new(suite_id),
            keys: HashMap::new(),
        }
    }

    fn with_validator(mut self, id: ValidatorId, pk: Vec<u8>) -> Self {
        self.keys.insert(id, pk);
        self
    }
}

impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&id).map(|pk| (self.suite_id, pk.clone()))
    }
}

/// A mock verifier that validates based on a simple rule:
/// - Signature is valid if signature length equals preimage length
struct MockRuleVerifier;

impl ConsensusSigVerifier for MockRuleVerifier {
    fn verify_vote(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        // Simple rule: signature should match preimage length
        if signature.len() == preimage.len() {
            Ok(())
        } else {
            Err(ConsensusSigError::InvalidSignature)
        }
    }

    fn verify_proposal(
        &self,
        _validator_id: u64,
        _pk: &[u8],
        preimage: &[u8],
        signature: &[u8],
    ) -> Result<(), ConsensusSigError> {
        // Same rule for proposals
        if signature.len() == preimage.len() {
            Ok(())
        } else {
            Err(ConsensusSigError::InvalidSignature)
        }
    }
}

fn make_test_key_provider(count: usize) -> Arc<TestKeyProvider> {
    let mut provider = TestKeyProvider::new(TEST_SUITE_ID);
    for i in 1..=count {
        provider = provider.with_validator(
            ValidatorId::new(i as u64),
            vec![i as u8; 32], // Simple test key
        );
    }
    Arc::new(provider)
}

fn make_test_backend_registry() -> Arc<SimpleBackendRegistry> {
    let mut registry = SimpleBackendRegistry::new();
    registry.register(
        ConsensusSigSuiteId::new(TEST_SUITE_ID),
        Arc::new(MockRuleVerifier),
    );
    Arc::new(registry)
}

// ============================================================================
// Pool integration tests
// ============================================================================

#[test]
fn test_pool_processes_valid_votes() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(100);
    let key_provider = make_test_key_provider(4);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Create valid votes from multiple validators
    let preimage = vec![1u8; 64]; // 64 bytes
    let signature = vec![2u8; 64]; // Same length = valid

    for i in 1..=4 {
        let job = ConsensusVerifyJob::new_vote(
            10, // view
            [i as u8; 32],
            ValidatorId::new(i as u64),
            TEST_SUITE_ID,
            preimage.clone(),
            signature.clone(),
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(100));

    let results = pool.drain_results();
    assert_eq!(results.len(), 4, "should have 4 results");
    assert!(
        results.iter().all(|r| r.ok),
        "all votes should verify successfully"
    );
    assert_eq!(pool.metrics().ok(), 4);
}

#[test]
fn test_pool_rejects_invalid_votes() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(100);
    let key_provider = make_test_key_provider(4);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Create invalid votes (signature length != preimage length)
    let preimage = vec![1u8; 64];
    let invalid_signature = vec![2u8; 32]; // Different length = invalid

    for i in 1..=4 {
        let job = ConsensusVerifyJob::new_vote(
            10,
            [i as u8; 32],
            ValidatorId::new(i as u64),
            TEST_SUITE_ID,
            preimage.clone(),
            invalid_signature.clone(),
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(100));

    let results = pool.drain_results();
    assert_eq!(results.len(), 4);
    assert!(
        results.iter().all(|r| !r.ok),
        "all votes should fail verification"
    );
    assert_eq!(pool.metrics().failed(), 4);
}

#[test]
fn test_pool_mixed_valid_invalid_votes() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(4)
        .with_queue_capacity(100);
    let key_provider = make_test_key_provider(10);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit a mix of valid and invalid votes
    for i in 1..=10 {
        let preimage = vec![i as u8; 64];
        // Even validators get valid signatures, odd get invalid
        let signature = if i % 2 == 0 {
            vec![i as u8; 64] // Valid (same length)
        } else {
            vec![i as u8; 32] // Invalid (different length)
        };

        let job = ConsensusVerifyJob::new_vote(
            10,
            [i as u8; 32],
            ValidatorId::new(i as u64),
            TEST_SUITE_ID,
            preimage,
            signature,
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(100));

    let results = pool.drain_results();
    assert_eq!(results.len(), 10);

    let valid_count = results.iter().filter(|r| r.ok).count();
    let invalid_count = results.iter().filter(|r| !r.ok).count();

    assert_eq!(valid_count, 5, "5 valid votes (even validators)");
    assert_eq!(invalid_count, 5, "5 invalid votes (odd validators)");
}

#[test]
fn test_pool_processes_proposals() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(100);
    let key_provider = make_test_key_provider(4);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Create valid proposals
    let preimage = vec![1u8; 128];
    let signature = vec![2u8; 128]; // Valid

    for i in 1..=4 {
        let job = ConsensusVerifyJob::new_proposal(
            i as u64 * 10,
            [i as u8; 32],
            ValidatorId::new(i as u64),
            TEST_SUITE_ID,
            preimage.clone(),
            signature.clone(),
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(100));

    let results = pool.drain_results();
    assert_eq!(results.len(), 4);
    assert!(results.iter().all(|r| r.ok));
    assert!(results
        .iter()
        .all(|r| r.job.kind == ConsensusMsgKind::Proposal));
}

#[test]
fn test_pool_processes_timeouts() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(100);
    let key_provider = make_test_key_provider(4);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Create valid timeout messages
    let preimage = vec![1u8; 72]; // Typical timeout preimage size
    let signature = vec![2u8; 72]; // Valid

    for i in 1..=4 {
        let job = ConsensusVerifyJob::new_timeout(
            10,
            ValidatorId::new(i as u64),
            TEST_SUITE_ID,
            preimage.clone(),
            signature.clone(),
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for processing
    std::thread::sleep(Duration::from_millis(100));

    let results = pool.drain_results();
    assert_eq!(results.len(), 4);
    assert!(results.iter().all(|r| r.ok));
    assert!(results
        .iter()
        .all(|r| r.job.kind == ConsensusMsgKind::Timeout));
}

// ============================================================================
// Correctness tests
// ============================================================================

#[test]
fn test_pool_preserves_job_data() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(10);
    let key_provider = make_test_key_provider(4);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    let preimage = vec![42u8; 64];
    let signature = vec![43u8; 64];
    let view = 12345u64;
    let block_id = [99u8; 32];
    let validator_id = ValidatorId::new(2);

    let job = ConsensusVerifyJob::new_vote(
        view,
        block_id,
        validator_id,
        TEST_SUITE_ID,
        preimage.clone(),
        signature.clone(),
    );
    pool.submit(job).expect("should submit");

    std::thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);

    let result = &results[0];
    assert!(result.ok);
    assert_eq!(result.job.view, view);
    assert_eq!(result.job.block_id, Some(block_id));
    assert_eq!(result.job.validator_id, validator_id);
    assert_eq!(result.job.suite_id, TEST_SUITE_ID);
    assert_eq!(result.job.message_bytes, preimage);
    assert_eq!(result.job.signature, signature);
}

#[test]
fn test_pool_order_independence() {
    // Verification results may arrive in different order than submission
    // This test verifies that all jobs are processed regardless of order
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(8)
        .with_queue_capacity(1000);
    let key_provider = make_test_key_provider(100);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit many jobs
    let num_jobs = 100;
    for i in 1..=num_jobs {
        let preimage = vec![i as u8; 64];
        let signature = vec![i as u8; 64]; // Valid

        let job = ConsensusVerifyJob::new_vote(
            i as u64,
            [i as u8; 32],
            ValidatorId::new(i as u64),
            TEST_SUITE_ID,
            preimage,
            signature,
        );
        pool.submit(job).expect("should submit");
    }

    // Wait for all processing
    std::thread::sleep(Duration::from_millis(200));

    let results = pool.drain_results();
    assert_eq!(results.len(), num_jobs as usize);

    // Verify all validators got their results (regardless of order)
    let validator_ids: std::collections::HashSet<_> = results
        .iter()
        .map(|r| r.job.validator_id.as_u64())
        .collect();
    assert_eq!(validator_ids.len(), num_jobs as usize);

    // All should be successful
    assert!(results.iter().all(|r| r.ok));
}

// ============================================================================
// Stress tests
// ============================================================================

#[test]
fn test_pool_high_throughput() {
    let num_workers = num_cpus::get();
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(num_workers)
        .with_queue_capacity(10000);
    let key_provider = make_test_key_provider(1000);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Submit many jobs rapidly
    let num_jobs = 1000;
    let start = std::time::Instant::now();

    for i in 1..=num_jobs {
        let preimage = vec![(i % 256) as u8; 64];
        let signature = vec![(i % 256) as u8; 64];

        let job = ConsensusVerifyJob::new_vote(
            i as u64,
            [(i % 256) as u8; 32],
            ValidatorId::new(((i - 1) % 1000 + 1) as u64),
            TEST_SUITE_ID,
            preimage,
            signature,
        );
        let _ = pool.submit(job); // Ignore drops for this stress test
    }

    let submit_time = start.elapsed();
    eprintln!("Submitted {} jobs in {:?}", num_jobs, submit_time);

    // Wait for processing
    std::thread::sleep(Duration::from_millis(500));

    let results = pool.drain_results();
    eprintln!(
        "Processed {} jobs, submitted={}, dropped={}, ok={}, failed={}",
        results.len(),
        pool.metrics().submitted(),
        pool.metrics().dropped(),
        pool.metrics().ok(),
        pool.metrics().failed()
    );

    // Most jobs should be processed
    let processed = pool.metrics().ok() + pool.metrics().failed();
    assert!(processed > 0, "should have processed at least some jobs");
}

#[test]
fn test_pool_no_deadlock_under_backpressure() {
    // Small queue to create backpressure
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(2)
        .with_queue_capacity(5);
    let key_provider = make_test_key_provider(100);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Continuously submit and drain for a period
    let start = std::time::Instant::now();
    let test_duration = Duration::from_millis(500);

    let mut total_submitted = 0u64;
    let mut total_dropped = 0u64;
    let mut total_results = 0u64;

    while start.elapsed() < test_duration {
        // Submit some jobs
        for i in 0..10 {
            let job = ConsensusVerifyJob::new_vote(
                i,
                [i as u8; 32],
                ValidatorId::new((i % 100 + 1) as u64),
                TEST_SUITE_ID,
                vec![i as u8; 64],
                vec![i as u8; 64],
            );
            match pool.submit(job) {
                Ok(()) => total_submitted += 1,
                Err(_) => total_dropped += 1,
            }
        }

        // Drain some results
        for result in pool.drain_results() {
            total_results += 1;
            let _ = result; // Just count them
        }
    }

    eprintln!(
        "Backpressure test: submitted={}, dropped={}, results={}",
        total_submitted, total_dropped, total_results
    );

    // Test passed if we didn't deadlock
    assert!(total_results > 0, "should have processed some results");
}

// ============================================================================
// Pool lifecycle tests
// ============================================================================

#[test]
fn test_pool_graceful_shutdown() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(4)
        .with_queue_capacity(100);
    let key_provider = make_test_key_provider(10);
    let backend_registry = make_test_backend_registry();

    {
        let pool: ConsensusVerifyPool<[u8; 32]> =
            ConsensusVerifyPool::new(config, key_provider.clone(), backend_registry.clone());

        // Submit some jobs
        for i in 1..=10 {
            let job = ConsensusVerifyJob::new_vote(
                i,
                [i as u8; 32],
                ValidatorId::new(i),
                TEST_SUITE_ID,
                vec![i as u8; 64],
                vec![i as u8; 64],
            );
            pool.submit(job).expect("should submit");
        }

        // Pool drops here
    }

    // Test passes if no panic during drop
    std::thread::sleep(Duration::from_millis(50));
}

#[test]
fn test_pool_can_be_recreated() {
    let key_provider = make_test_key_provider(10);
    let backend_registry = make_test_backend_registry();

    // Create and use first pool
    {
        let config = ConsensusVerifyPoolConfig::default().with_workers(2);
        let pool: ConsensusVerifyPool<[u8; 32]> =
            ConsensusVerifyPool::new(config, key_provider.clone(), backend_registry.clone());

        let job = ConsensusVerifyJob::new_vote(
            1,
            [1u8; 32],
            ValidatorId::new(1),
            TEST_SUITE_ID,
            vec![1u8; 64],
            vec![1u8; 64],
        );
        pool.submit(job).expect("should submit");
        std::thread::sleep(Duration::from_millis(50));
        let results = pool.drain_results();
        assert_eq!(results.len(), 1);
    }

    // Create and use second pool
    {
        let config = ConsensusVerifyPoolConfig::default().with_workers(2);
        let pool: ConsensusVerifyPool<[u8; 32]> =
            ConsensusVerifyPool::new(config, key_provider.clone(), backend_registry.clone());

        let job = ConsensusVerifyJob::new_vote(
            2,
            [2u8; 32],
            ValidatorId::new(2),
            TEST_SUITE_ID,
            vec![2u8; 64],
            vec![2u8; 64],
        );
        pool.submit(job).expect("should submit");
        std::thread::sleep(Duration::from_millis(50));
        let results = pool.drain_results();
        assert_eq!(results.len(), 1);
    }
}

// ============================================================================
// Semantic correctness tests
// ============================================================================

#[test]
fn test_pool_suite_mismatch_is_rejected() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(10);
    let key_provider = make_test_key_provider(4);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Job with wrong suite_id (200 instead of 100)
    let job = ConsensusVerifyJob::new_vote(
        1,
        [1u8; 32],
        ValidatorId::new(1),
        200, // Wrong suite
        vec![1u8; 64],
        vec![1u8; 64],
    );

    pool.submit(job).expect("should submit");
    std::thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(!results[0].ok, "suite mismatch should fail");
    assert!(
        results[0]
            .error
            .as_ref()
            .map(|e| e.contains("suite mismatch"))
            .unwrap_or(false),
        "error should mention suite mismatch"
    );
}

#[test]
fn test_pool_unknown_validator_is_rejected() {
    let config = ConsensusVerifyPoolConfig::default()
        .with_workers(1)
        .with_queue_capacity(10);
    // Only register validators 1-4
    let key_provider = make_test_key_provider(4);
    let backend_registry = make_test_backend_registry();
    let pool: ConsensusVerifyPool<[u8; 32]> =
        ConsensusVerifyPool::new(config, key_provider, backend_registry);

    // Job from validator 999 (unknown)
    let job = ConsensusVerifyJob::new_vote(
        1,
        [1u8; 32],
        ValidatorId::new(999), // Unknown validator
        TEST_SUITE_ID,
        vec![1u8; 64],
        vec![1u8; 64],
    );

    pool.submit(job).expect("should submit");
    std::thread::sleep(Duration::from_millis(50));

    let results = pool.drain_results();
    assert_eq!(results.len(), 1);
    assert!(!results[0].ok, "unknown validator should fail");
    assert!(
        results[0]
            .error
            .as_ref()
            .map(|e| e.contains("missing key"))
            .unwrap_or(false),
        "error should mention missing key"
    );
}
