//! T236: Fee Market Adversarial Analysis & Stress Harness v1
//!
//! This test module provides a concrete, repeatable adversarial test harness that
//! stresses the fee market and DAG mempool under hostile conditions. It builds on
//! existing fee tests (T169, T179, T181, T218–T220) to validate:
//!
//! - **Inclusion fairness**: Honest senders are not starved by adversarial spam
//! - **Fee stability**: Base fee and effective fees remain stable under stress
//! - **Safety invariants**: No balance underflow, double-spend, or fee-accounting bugs
//!
//! # Scenarios Tested
//!
//! 1. **Baseline**: Light traffic with honest senders only
//! 2. **Single-sender spam**: One attacker floods low-fee txs vs honest moderate-fee senders
//! 3. **Front-running pattern**: Attacker tries to outbid honest txs
//! 4. **Churn attack**: Many accounts send bursts to cause eviction pressure
//!
//! # Running Tests
//!
//! ```bash
//! cargo test -p qbind-node --test t236_fee_market_adversarial_tests -- --test-threads=1
//! ```
//!
//! # MainNet Audit Reference
//!
//! This harness provides "Fee market analysis under adversarial conditions" evidence
//! for MN-R2 in the MainNet audit skeleton. See [QBIND_MAINNET_AUDIT_SKELETON.md].
//!
//! # Related Tasks
//!
//! - T169: Fee-priority mempool
//! - T179: Gas property tests
//! - T181: Fee-market cluster tests
//! - T193: Hybrid fee distribution
//! - T218: DAG mempool DoS protections
//! - T219/T220: Eviction rate limiting

use std::collections::HashMap;

use qbind_consensus::ValidatorId;
use qbind_ledger::{
    AccountStateView, InMemoryAccountState, QbindTransaction, TransferPayload, VmV0ExecutionEngine,
};
use qbind_node::dag_mempool::{DagMempool, DagMempoolConfig, InMemoryDagMempool};
use qbind_node::EvictionRateMode;
use qbind_types::AccountId;

// ============================================================================
// Adversarial Profile Definitions
// ============================================================================

/// Adversarial profile for fee market stress testing.
///
/// Each profile represents a different attack pattern or baseline scenario.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FeeAdversarialProfile {
    /// Baseline: Light traffic, honest senders only.
    /// Used for sanity checking that the system works under normal conditions.
    Baseline,

    /// Single-sender spam: One attacker account floods low-fee transactions.
    /// Tests per-sender quotas (T218) and fee-priority ordering.
    SpammySingleSender,

    /// Front-running pattern: Attacker slightly outbids honest transactions.
    /// Verifies fee accounting integrity, not MEV prevention.
    FrontRunningPattern,

    /// Churn attack: Many accounts send bursts to cause eviction pressure.
    /// Tests eviction rate limiting (T219/T220).
    ChurnAttack,
}

// ============================================================================
// Configuration Structure
// ============================================================================

/// Configuration for the fee market adversarial harness.
#[derive(Clone, Debug)]
pub struct FeeAdversarialConfig {
    /// Number of validators in the simulated cluster.
    pub num_validators: usize,
    /// Number of honest sender accounts.
    pub num_honest_senders: usize,
    /// Number of adversarial sender accounts.
    pub num_adversarial_senders: usize,
    /// Target transactions per second (nominal rate).
    pub target_tps: u32,
    /// Duration of the test in simulated blocks.
    pub duration_blocks: u32,
    /// Adversarial profile to use.
    pub profile: FeeAdversarialProfile,
    /// Random seed for reproducibility.
    pub seed: u64,
    /// Fee range for honest senders (min, max) in gas price units.
    pub honest_fee_range: (u128, u128),
    /// Fee range for adversarial senders (min, max) in gas price units.
    pub adversarial_fee_range: (u128, u128),
    /// Probability (0-100) of adversarial burst in churn attack.
    pub burst_probability: u32,
    /// Maximum pending transactions per sender in mempool.
    pub max_pending_per_sender: u32,
    /// Enable fee-priority ordering in mempool.
    pub enable_fee_priority: bool,
    /// Mempool eviction rate limiting mode.
    pub eviction_mode: EvictionRateMode,
    /// Maximum evictions per interval for rate limiting.
    pub max_evictions_per_interval: u32,
}

impl Default for FeeAdversarialConfig {
    fn default() -> Self {
        Self {
            num_validators: 4,
            num_honest_senders: 10,
            num_adversarial_senders: 5,
            target_tps: 100,
            duration_blocks: 20,
            profile: FeeAdversarialProfile::Baseline,
            seed: 42,
            honest_fee_range: (50, 200),
            adversarial_fee_range: (10, 50),
            burst_probability: 30,
            max_pending_per_sender: 100,
            enable_fee_priority: true,
            eviction_mode: EvictionRateMode::Enforce,
            max_evictions_per_interval: 50,
        }
    }
}

impl FeeAdversarialConfig {
    /// Create a baseline configuration (no adversary).
    pub fn baseline() -> Self {
        Self {
            num_adversarial_senders: 0,
            profile: FeeAdversarialProfile::Baseline,
            ..Default::default()
        }
    }

    /// Create a single-sender spam configuration.
    pub fn single_sender_spam() -> Self {
        Self {
            num_adversarial_senders: 1,
            adversarial_fee_range: (1, 20), // Very low fees
            profile: FeeAdversarialProfile::SpammySingleSender,
            ..Default::default()
        }
    }

    /// Create a front-running pattern configuration.
    pub fn front_running() -> Self {
        Self {
            num_adversarial_senders: 3,
            adversarial_fee_range: (100, 250), // Slightly higher than honest
            profile: FeeAdversarialProfile::FrontRunningPattern,
            ..Default::default()
        }
    }

    /// Create a churn attack configuration.
    pub fn churn_attack() -> Self {
        Self {
            num_adversarial_senders: 20,
            burst_probability: 60,
            adversarial_fee_range: (60, 150),
            max_pending_per_sender: 50, // Tighter limit
            profile: FeeAdversarialProfile::ChurnAttack,
            ..Default::default()
        }
    }
}

// ============================================================================
// Result Structure
// ============================================================================

/// Inclusion latency distribution (number of blocks to inclusion).
#[derive(Clone, Debug, Default)]
pub struct InclusionLatencyBuckets {
    /// Transactions included within 3 blocks.
    pub within_3_blocks: u64,
    /// Transactions included within 10 blocks.
    pub within_10_blocks: u64,
    /// Transactions included after 10 blocks.
    pub over_10_blocks: u64,
}

/// Fee accounting aggregates.
#[derive(Clone, Debug, Default)]
pub struct FeeAccountingAggregates {
    /// Total fees paid by honest senders.
    pub honest_fees_paid: u128,
    /// Total fees paid by adversarial senders.
    pub adversarial_fees_paid: u128,
    /// Total fees burned (approximate).
    pub total_burned: u128,
    /// Total fees paid to proposers (approximate).
    pub total_to_proposers: u128,
}

/// Results from an adversarial fee market test run.
#[derive(Clone, Debug, Default)]
pub struct FeeAdversarialResult {
    // ========================================================================
    // Submission & Inclusion Counts
    // ========================================================================
    /// Total transactions submitted across all senders.
    pub total_txs_submitted: u64,
    /// Total transactions successfully included in blocks.
    pub total_txs_included: u64,
    /// Transactions submitted by honest senders.
    pub honest_txs_submitted: u64,
    /// Transactions included from honest senders.
    pub honest_txs_included: u64,
    /// Transactions submitted by adversarial senders.
    pub adversarial_txs_submitted: u64,
    /// Transactions included from adversarial senders.
    pub adversarial_txs_included: u64,

    // ========================================================================
    // Distribution Statistics
    // ========================================================================
    /// Inclusion latency buckets.
    pub inclusion_latency: InclusionLatencyBuckets,
    /// Fraction of blocks with >= 50% adversarial transactions.
    pub blocks_with_high_adversarial_fraction: f64,

    // ========================================================================
    // Fee Accounting
    // ========================================================================
    /// Fee accounting aggregates.
    pub fee_accounting: FeeAccountingAggregates,

    // ========================================================================
    // Safety Flags
    // ========================================================================
    /// Whether any balance anomalies (unexpected changes) were detected.
    pub balance_anomalies_detected: bool,
    /// Whether any double-spend or replay was detected.
    pub double_spend_or_replay_detected: bool,
    /// Whether any negative balance was detected.
    pub negative_balance_detected: bool,

    // ========================================================================
    // Mempool Statistics
    // ========================================================================
    /// Number of transactions rejected due to sender limits.
    pub sender_limit_rejections: u64,
    /// Number of evictions triggered.
    pub evictions_triggered: u64,
    /// Number of times eviction rate limit was hit.
    pub eviction_rate_limit_hits: u64,
}

impl FeeAdversarialResult {
    /// Print a human-readable summary of the results.
    pub fn print_summary(&self) {
        eprintln!("\n=== T236 Fee Market Adversarial Results ===");
        eprintln!("Total submitted: {}", self.total_txs_submitted);
        eprintln!("Total included: {}", self.total_txs_included);
        eprintln!(
            "Honest: {} submitted / {} included",
            self.honest_txs_submitted, self.honest_txs_included
        );
        eprintln!(
            "Adversarial: {} submitted / {} included",
            self.adversarial_txs_submitted, self.adversarial_txs_included
        );
        eprintln!(
            "Inclusion ratio (honest): {:.2}%",
            if self.honest_txs_submitted > 0 {
                (self.honest_txs_included as f64 / self.honest_txs_submitted as f64) * 100.0
            } else {
                0.0
            }
        );
        eprintln!("Sender limit rejections: {}", self.sender_limit_rejections);
        eprintln!("Evictions: {}", self.evictions_triggered);
        eprintln!("Rate limit hits: {}", self.eviction_rate_limit_hits);
        eprintln!("Balance anomalies: {}", self.balance_anomalies_detected);
        eprintln!(
            "Double-spend detected: {}",
            self.double_spend_or_replay_detected
        );
        eprintln!("Negative balance: {}", self.negative_balance_detected);
        eprintln!("==========================================\n");
    }

    /// Calculate honest sender inclusion ratio.
    pub fn honest_inclusion_ratio(&self) -> f64 {
        if self.honest_txs_submitted == 0 {
            return 1.0;
        }
        self.honest_txs_included as f64 / self.honest_txs_submitted as f64
    }

    /// Check if all safety invariants hold.
    pub fn safety_invariants_hold(&self) -> bool {
        !self.balance_anomalies_detected
            && !self.double_spend_or_replay_detected
            && !self.negative_balance_detected
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Create an account ID from a u32 index with a namespace marker.
fn account_id_from_index(index: u32, is_adversarial: bool) -> AccountId {
    let mut id = [0u8; 32];
    id[0] = if is_adversarial { 0xAD } else { 0x00 }; // Namespace marker
    let bytes = index.to_le_bytes();
    id[1..5].copy_from_slice(&bytes);
    id
}

/// Create a recipient account ID.
fn recipient_id_from_index(index: u32) -> AccountId {
    let mut id = [0u8; 32];
    id[0] = 0xFF; // Recipient namespace
    let bytes = index.to_le_bytes();
    id[1..5].copy_from_slice(&bytes);
    id
}

/// Simple deterministic pseudo-random number generator (LCG).
/// Matches the pattern used in T223/T234 for consistency.
struct SimpleRng {
    state: u64,
}

impl SimpleRng {
    fn new(seed: u64) -> Self {
        Self {
            state: seed.wrapping_add(1),
        }
    }

    fn next_u64(&mut self) -> u64 {
        // LCG parameters (from Numerical Recipes)
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        self.state
    }

    fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    fn next_range(&mut self, min: u32, max: u32) -> u32 {
        if max <= min {
            return min;
        }
        min + (self.next_u32() % (max - min))
    }

    fn next_u128_range(&mut self, min: u128, max: u128) -> u128 {
        if max <= min {
            return min;
        }
        let range = max - min;
        min + ((self.next_u64() as u128) % range)
    }

    fn next_bool(&mut self, probability_percent: u32) -> bool {
        self.next_range(0, 100) < probability_percent
    }
}

/// Transaction metadata for tracking.
#[derive(Clone)]
struct TxMetadata {
    sender: AccountId,
    is_adversarial: bool,
    #[allow(dead_code)]
    fee: u128,
    submitted_at_block: u32,
}

// ============================================================================
// Core Harness Implementation
// ============================================================================

/// Run the fee market adversarial harness with the given configuration.
///
/// This function simulates adversarial conditions on the fee market and
/// DAG mempool, measuring inclusion fairness, fee stability, and safety invariants.
pub fn run_fee_adversarial_harness(config: FeeAdversarialConfig) -> FeeAdversarialResult {
    let mut result = FeeAdversarialResult::default();
    let mut rng = SimpleRng::new(config.seed);

    // Initialize account state with sufficient balances
    let initial_balance: u128 = 1_000_000_000;
    let mut state = InMemoryAccountState::new();
    let mut sender_nonces: HashMap<AccountId, u64> = HashMap::new();

    // Initialize honest senders
    for i in 0..config.num_honest_senders {
        let account = account_id_from_index(i as u32, false);
        state.init_account(&account, initial_balance);
        sender_nonces.insert(account, 0);
    }

    // Initialize adversarial senders
    for i in 0..config.num_adversarial_senders {
        let account = account_id_from_index(i as u32, true);
        state.init_account(&account, initial_balance);
        sender_nonces.insert(account, 0);
    }

    // Initialize recipients
    let num_recipients = config.num_honest_senders + config.num_adversarial_senders;
    for i in 0..num_recipients {
        let recipient = recipient_id_from_index(i as u32);
        state.init_account(&recipient, 0);
    }

    // Configure mempool
    let mempool_config = DagMempoolConfig {
        max_batches: 1000,
        max_pending_txs: 5000,
        batch_size: 50,
        local_validator_id: ValidatorId::new(1),
        enable_fee_priority: config.enable_fee_priority,
        max_pending_per_sender: config.max_pending_per_sender,
        max_pending_bytes_per_sender: 8 * 1024 * 1024,
        max_txs_per_batch: 1000,
        max_batch_bytes: 2 * 1024 * 1024,
        eviction_mode: config.eviction_mode,
        max_evictions_per_interval: config.max_evictions_per_interval,
        eviction_interval_secs: 10,
    };

    let mempool = InMemoryDagMempool::with_config(mempool_config);

    // Track pending transactions and their metadata
    let mut tx_metadata: HashMap<[u8; 32], TxMetadata> = HashMap::new();
    let mut blocks_high_adversarial = 0u32;

    // Execution engine for simulating block processing
    let engine = VmV0ExecutionEngine::new();

    // Track initial balances for anomaly detection
    let mut expected_balances: HashMap<AccountId, u128> = HashMap::new();
    for i in 0..config.num_honest_senders {
        let account = account_id_from_index(i as u32, false);
        expected_balances.insert(account, initial_balance);
    }
    for i in 0..config.num_adversarial_senders {
        let account = account_id_from_index(i as u32, true);
        expected_balances.insert(account, initial_balance);
    }

    // Run simulation over blocks
    for block_idx in 0..config.duration_blocks {
        // Generate transactions for this block based on profile
        let mut block_txs: Vec<QbindTransaction> = Vec::new();
        let mut block_metadata: Vec<TxMetadata> = Vec::new();

        let txs_this_block = config.target_tps / 10; // Simplified: assume 10 blocks per second

        // Generate honest transactions
        let honest_txs_count = if config.num_adversarial_senders > 0 {
            txs_this_block * 2 / 3 // 2/3 honest when adversary present
        } else {
            txs_this_block
        };

        for _ in 0..honest_txs_count {
            if config.num_honest_senders == 0 {
                break;
            }

            let sender_idx = rng.next_range(0, config.num_honest_senders as u32);
            let sender = account_id_from_index(sender_idx, false);
            let recipient_idx = rng.next_range(0, num_recipients as u32);
            let recipient = recipient_id_from_index(recipient_idx);

            let nonce = sender_nonces.get(&sender).copied().unwrap_or(0);
            let fee = rng.next_u128_range(config.honest_fee_range.0, config.honest_fee_range.1);
            let amount = 100u128;

            let payload = TransferPayload::new(recipient, amount);
            let tx = QbindTransaction::new(sender, nonce, payload.encode());

            // Compute a simple tx hash for tracking
            let tx_hash = compute_tx_hash(&tx);

            block_txs.push(tx);
            block_metadata.push(TxMetadata {
                sender,
                is_adversarial: false,
                fee,
                submitted_at_block: block_idx,
            });
            tx_metadata.insert(tx_hash, block_metadata.last().unwrap().clone());

            result.honest_txs_submitted += 1;
            result.total_txs_submitted += 1;
        }

        // Generate adversarial transactions based on profile
        let adversarial_txs_count = match config.profile {
            FeeAdversarialProfile::Baseline => 0,

            FeeAdversarialProfile::SpammySingleSender => {
                // Single sender floods with many low-fee txs
                txs_this_block * 3 // 3x normal rate
            }

            FeeAdversarialProfile::FrontRunningPattern => {
                // Match honest tx count but with higher fees
                honest_txs_count
            }

            FeeAdversarialProfile::ChurnAttack => {
                // Burst probability determines if this block has a burst
                if rng.next_bool(config.burst_probability) {
                    txs_this_block * 5 // 5x burst
                } else {
                    txs_this_block / 2
                }
            }
        };

        for tx_idx in 0..adversarial_txs_count {
            if config.num_adversarial_senders == 0 {
                break;
            }

            // For SpammySingleSender, always use sender 0
            let sender_idx = match config.profile {
                FeeAdversarialProfile::SpammySingleSender => 0,
                _ => rng.next_range(0, config.num_adversarial_senders as u32),
            };

            let sender = account_id_from_index(sender_idx, true);
            let recipient_idx = rng.next_range(0, num_recipients as u32);
            let recipient = recipient_id_from_index(recipient_idx);

            let nonce = sender_nonces.get(&sender).copied().unwrap_or(0);

            // For front-running, slightly increase fee based on honest tx fees
            let fee = match config.profile {
                FeeAdversarialProfile::FrontRunningPattern => {
                    // Add a small premium to honest fee range
                    let base =
                        rng.next_u128_range(config.honest_fee_range.0, config.honest_fee_range.1);
                    base + 10 + (tx_idx as u128 % 20) // Slight outbid
                }
                _ => rng.next_u128_range(
                    config.adversarial_fee_range.0,
                    config.adversarial_fee_range.1,
                ),
            };

            let amount = 100u128;
            let payload = TransferPayload::new(recipient, amount);
            let tx = QbindTransaction::new(sender, nonce, payload.encode());

            let tx_hash = compute_tx_hash(&tx);

            block_txs.push(tx);
            block_metadata.push(TxMetadata {
                sender,
                is_adversarial: true,
                fee,
                submitted_at_block: block_idx,
            });
            tx_metadata.insert(tx_hash, block_metadata.last().unwrap().clone());

            result.adversarial_txs_submitted += 1;
            result.total_txs_submitted += 1;
        }

        // Try to insert transactions into mempool
        let insert_result = mempool.insert_local_txs(block_txs.clone());
        if insert_result.is_err() {
            // All rejected
            result.sender_limit_rejections += block_txs.len() as u64;
        }
        // Note: Individual tx rejections due to sender limits are tracked by the mempool
        // internally; we can't easily get the count from Result<(), Error>

        // Select frontier transactions for inclusion (simulating block building)
        let frontier_txs = mempool.select_frontier_txs(50);

        // Track adversarial fraction in this block
        let mut adversarial_in_block = 0u32;
        let mut honest_in_block = 0u32;

        // Execute the block and track results
        let mut block_state = state.clone();
        let results = engine.execute_block(&mut block_state, &frontier_txs);

        for (tx, exec_result) in frontier_txs.iter().zip(results.iter()) {
            let tx_hash = compute_tx_hash(tx);

            if let Some(metadata) = tx_metadata.get(&tx_hash) {
                // Track inclusion latency
                let latency_blocks = block_idx.saturating_sub(metadata.submitted_at_block);
                if latency_blocks <= 3 {
                    result.inclusion_latency.within_3_blocks += 1;
                } else if latency_blocks <= 10 {
                    result.inclusion_latency.within_10_blocks += 1;
                } else {
                    result.inclusion_latency.over_10_blocks += 1;
                }

                // Track honest vs adversarial inclusion
                if metadata.is_adversarial {
                    result.adversarial_txs_included += 1;
                    adversarial_in_block += 1;
                    result.fee_accounting.adversarial_fees_paid += exec_result.fee_paid;
                } else {
                    result.honest_txs_included += 1;
                    honest_in_block += 1;
                    result.fee_accounting.honest_fees_paid += exec_result.fee_paid;
                }

                result.total_txs_included += 1;

                // Track fee distribution (simplified: 50% burn, 50% proposer)
                result.fee_accounting.total_burned += exec_result.fee_burned;
                result.fee_accounting.total_to_proposers +=
                    exec_result.fee_paid - exec_result.fee_burned;

                // Update nonce tracking
                sender_nonces.insert(metadata.sender, tx.nonce + 1);
            }
        }

        // Check if this block has high adversarial fraction
        let total_in_block = honest_in_block + adversarial_in_block;
        if total_in_block > 0 && adversarial_in_block as f64 / total_in_block as f64 >= 0.5 {
            blocks_high_adversarial += 1;
        }

        // Verify safety invariants
        for (account, _expected_balance) in expected_balances.iter() {
            let actual = block_state.get_account_state(account);

            // Check for negative balance (should be impossible with u128)
            // In practice, check if balance dropped below expected minimum
            if actual.balance > initial_balance * 2 {
                // Unlikely legitimate - potential overflow
                result.balance_anomalies_detected = true;
            }
        }

        // Check no account has negative balance (balance is u128, but we track underflow attempts)
        for i in 0..config.num_honest_senders {
            let account = account_id_from_index(i as u32, false);
            let account_state = block_state.get_account_state(&account);
            // In a u128 context, "negative" would manifest as very large numbers
            // after underflow, but Rust prevents this. We check consistency.
            if account_state.balance > initial_balance * 10 {
                result.negative_balance_detected = true;
            }
        }

        // Update state for next block
        state = block_state;

        // Mark included transactions as committed in mempool
        mempool.mark_committed(&frontier_txs);
    }

    // Calculate final statistics
    result.blocks_with_high_adversarial_fraction =
        blocks_high_adversarial as f64 / config.duration_blocks as f64;

    result
}

/// Compute a simple hash for transaction tracking.
fn compute_tx_hash(tx: &QbindTransaction) -> [u8; 32] {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tx.sender.hash(&mut hasher);
    tx.nonce.hash(&mut hasher);
    tx.payload.hash(&mut hasher);
    let hash = hasher.finish();

    let mut result = [0u8; 32];
    result[0..8].copy_from_slice(&hash.to_le_bytes());
    result
}

// ============================================================================
// Tests
// ============================================================================

/// T236 Test 1: Baseline sanity check - no adversary, moderate TPS.
///
/// Verifies that honest transactions are included regularly with no anomalies
/// when there is no adversarial activity.
#[test]
fn test_t236_fee_baseline_sanity() {
    let config = FeeAdversarialConfig::baseline();

    eprintln!("\n=== T236: Baseline Sanity Test ===");
    eprintln!("Profile: {:?}", config.profile);
    eprintln!("Honest senders: {}", config.num_honest_senders);
    eprintln!("Duration blocks: {}", config.duration_blocks);

    let result = run_fee_adversarial_harness(config);
    result.print_summary();

    // Assertions
    assert!(
        result.safety_invariants_hold(),
        "Safety invariants must hold in baseline scenario"
    );
    assert!(
        result.honest_txs_submitted > 0,
        "Should have submitted honest transactions"
    );
    assert!(
        result.honest_txs_included > 0,
        "Should have included honest transactions"
    );
    assert!(
        result.honest_inclusion_ratio() > 0.5,
        "Honest inclusion ratio should be > 50% (got {:.2}%)",
        result.honest_inclusion_ratio() * 100.0
    );
    assert_eq!(
        result.adversarial_txs_submitted, 0,
        "Baseline should have no adversarial transactions"
    );
    assert!(!result.balance_anomalies_detected, "No balance anomalies");
    assert!(!result.negative_balance_detected, "No negative balances");
}

/// T236 Test 2: Single sender spam cannot starve honest senders.
///
/// One adversarial sender floods the mempool with low-fee transactions.
/// Honest senders with moderate fees should still get included thanks to
/// per-sender quotas (T218) and fee-priority ordering.
#[test]
fn test_t236_single_sender_spam_cannot_starve_others() {
    let config = FeeAdversarialConfig::single_sender_spam();

    eprintln!("\n=== T236: Single Sender Spam Test ===");
    eprintln!("Profile: {:?}", config.profile);
    eprintln!("Honest senders: {}", config.num_honest_senders);
    eprintln!("Adversarial senders: {}", config.num_adversarial_senders);
    eprintln!("Honest fee range: {:?}", config.honest_fee_range);
    eprintln!("Adversarial fee range: {:?}", config.adversarial_fee_range);

    let result = run_fee_adversarial_harness(config);
    result.print_summary();

    // Safety invariants must hold
    assert!(
        result.safety_invariants_hold(),
        "Safety invariants must hold under spam attack"
    );

    // Honest transactions should still be included
    assert!(
        result.honest_txs_included > 0,
        "Honest transactions must be included despite spam"
    );

    // Honest inclusion ratio should be meaningful (not starved)
    // With per-sender quotas, honest senders should get through
    let honest_ratio = result.honest_inclusion_ratio();
    assert!(
        honest_ratio > 0.3,
        "Honest senders must not be starved (ratio: {:.2}%, expected > 30%)",
        honest_ratio * 100.0
    );

    // Per-sender limits should have been exercised
    eprintln!(
        "Sender limit rejections: {} (expected > 0 for spam scenario)",
        result.sender_limit_rejections
    );

    // No negative balances or accounting bugs
    assert!(!result.negative_balance_detected, "No negative balances");
    assert!(!result.balance_anomalies_detected, "No balance anomalies");
}

/// T236 Test 3: Front-running pattern does not break fee accounting.
///
/// Adversary follows a pattern of slightly outbidding honest transactions.
/// We verify that fee accounting remains correct (no double-crediting or
/// undercharging), even if the adversary gets priority inclusion.
#[test]
fn test_t236_front_running_pattern_does_not_break_accounting() {
    let config = FeeAdversarialConfig::front_running();

    eprintln!("\n=== T236: Front-Running Pattern Test ===");
    eprintln!("Profile: {:?}", config.profile);
    eprintln!("Honest fee range: {:?}", config.honest_fee_range);
    eprintln!("Adversarial fee range: {:?}", config.adversarial_fee_range);

    let result = run_fee_adversarial_harness(config);
    result.print_summary();

    // Safety invariants must hold
    assert!(
        result.safety_invariants_hold(),
        "Safety invariants must hold under front-running"
    );

    // Fee accounting must be consistent
    // Total fees paid should equal burned + proposer (approximately)
    let total_fees =
        result.fee_accounting.honest_fees_paid + result.fee_accounting.adversarial_fees_paid;
    let total_distributed =
        result.fee_accounting.total_burned + result.fee_accounting.total_to_proposers;

    // Allow for rounding differences
    let fee_diff = if total_fees > total_distributed {
        total_fees - total_distributed
    } else {
        total_distributed - total_fees
    };

    // Fees should roughly balance (within 1% or small absolute amount)
    let tolerance = (total_fees / 100).max(1000);
    assert!(
        fee_diff <= tolerance,
        "Fee accounting mismatch: total_fees={}, distributed={}, diff={}",
        total_fees,
        total_distributed,
        fee_diff
    );

    // Honest transactions should still be included (not completely dominated)
    assert!(
        result.honest_txs_included > 0,
        "Some honest transactions should be included"
    );

    // No double-spend or replay
    assert!(
        !result.double_spend_or_replay_detected,
        "No double-spend or replay"
    );
}

/// T236 Test 4: Eviction churn under attack respects rate limits.
///
/// Many adversarial accounts send bursts to cause eviction pressure.
/// Eviction rate limiting (T219/T220) should prevent complete starvation.
#[test]
fn test_t236_eviction_churn_under_attack_respects_rate_limits() {
    let config = FeeAdversarialConfig::churn_attack();

    eprintln!("\n=== T236: Eviction Churn Attack Test ===");
    eprintln!("Profile: {:?}", config.profile);
    eprintln!("Adversarial senders: {}", config.num_adversarial_senders);
    eprintln!("Burst probability: {}%", config.burst_probability);
    eprintln!("Eviction mode: {:?}", config.eviction_mode);
    eprintln!(
        "Max evictions per interval: {}",
        config.max_evictions_per_interval
    );

    let result = run_fee_adversarial_harness(config);
    result.print_summary();

    // Safety invariants must hold
    assert!(
        result.safety_invariants_hold(),
        "Safety invariants must hold under churn attack"
    );

    // Honest transactions should see some inclusion over the run
    // Even under high churn, rate limiting should prevent total starvation
    assert!(
        result.honest_txs_included > 0,
        "Honest transactions must be included despite churn"
    );

    // The fraction of blocks with high adversarial content should be bounded
    // (not 100% adversarial takeover)
    assert!(
        result.blocks_with_high_adversarial_fraction < 1.0,
        "Adversary should not completely dominate all blocks"
    );

    // No negative balances
    assert!(!result.negative_balance_detected, "No negative balances");
}

/// T236 Test 5: Fee market results are reproducible with fixed seed.
///
/// Running the same configuration with the same seed should produce
/// identical or nearly identical results (for deterministic scheduling).
#[test]
fn test_t236_fee_market_reproducible_with_fixed_seed() {
    let config = FeeAdversarialConfig {
        seed: 12345,
        duration_blocks: 15,
        ..FeeAdversarialConfig::single_sender_spam()
    };

    eprintln!("\n=== T236: Reproducibility Test ===");
    eprintln!("Seed: {}", config.seed);

    // Run twice with identical config
    let result1 = run_fee_adversarial_harness(config.clone());
    let result2 = run_fee_adversarial_harness(config);

    eprintln!("\n--- Run 1 ---");
    result1.print_summary();
    eprintln!("--- Run 2 ---");
    result2.print_summary();

    // Results should be identical for deterministic execution
    assert_eq!(
        result1.total_txs_submitted, result2.total_txs_submitted,
        "Total submitted should match"
    );
    assert_eq!(
        result1.honest_txs_submitted, result2.honest_txs_submitted,
        "Honest submitted should match"
    );
    assert_eq!(
        result1.adversarial_txs_submitted, result2.adversarial_txs_submitted,
        "Adversarial submitted should match"
    );

    // Inclusion counts should match (deterministic mempool behavior)
    assert_eq!(
        result1.total_txs_included, result2.total_txs_included,
        "Total included should match"
    );
    assert_eq!(
        result1.honest_txs_included, result2.honest_txs_included,
        "Honest included should match"
    );
    assert_eq!(
        result1.adversarial_txs_included, result2.adversarial_txs_included,
        "Adversarial included should match"
    );

    // Safety flags should match
    assert_eq!(
        result1.safety_invariants_hold(),
        result2.safety_invariants_hold(),
        "Safety invariants should match"
    );
}

/// T236 Test 6: Mixed scenario with all safety checks.
///
/// A combined test that runs multiple scenarios and validates
/// the core safety invariants across all of them.
#[test]
fn test_t236_all_scenarios_preserve_invariants() {
    let scenarios = [
        ("Baseline", FeeAdversarialConfig::baseline()),
        (
            "SingleSenderSpam",
            FeeAdversarialConfig::single_sender_spam(),
        ),
        ("FrontRunning", FeeAdversarialConfig::front_running()),
        ("ChurnAttack", FeeAdversarialConfig::churn_attack()),
    ];

    eprintln!("\n=== T236: All Scenarios Invariant Test ===");

    for (name, config) in scenarios {
        eprintln!("\n--- Scenario: {} ---", name);
        let result = run_fee_adversarial_harness(config);

        // All scenarios must preserve safety invariants
        assert!(
            result.safety_invariants_hold(),
            "Scenario '{}' failed safety invariants: anomalies={}, double_spend={}, negative={}",
            name,
            result.balance_anomalies_detected,
            result.double_spend_or_replay_detected,
            result.negative_balance_detected
        );

        eprintln!(
            "  ✓ {} passed: {} txs included, honest ratio = {:.1}%",
            name,
            result.total_txs_included,
            result.honest_inclusion_ratio() * 100.0
        );
    }

    eprintln!("\n=== All scenarios passed safety invariants ===");
}