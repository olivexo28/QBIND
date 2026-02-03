//! Tests for T117: Strict Validator Context Enforcement in HotStuff Driver.
//!
//! These tests verify that:
//! 1. Node wiring uses strict mode (with ValidatorContext)
//! 2. Permissive mode is only available for tests via explicit helper
//! 3. There is no silent fallback to permissive behavior
//!
//! The key invariant is: production code MUST use `new_strict()` or
//! `with_validators()`, while tests MAY use `for_tests_permissive_validators()`.

use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_consensus::{
    ConsensusEngineAction, ConsensusEngineDriver, ConsensusNetworkEvent, HotStuffDriver,
    HotStuffState, MockConsensusNetwork, ValidatorContext, ValidatorId,
};
use qbind_wire::consensus::{BlockHeader, BlockProposal, Vote};

// ============================================================================
// Test helpers
// ============================================================================

/// Create a dummy Vote for testing.
fn make_dummy_vote(height: u64, round: u64) -> Vote {
    Vote {
        version: 1,
        chain_id: 1,
        epoch: 0,
        height,
        round,
        step: 0,
        block_id: [0u8; 32],
        validator_index: 0,
        suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
        signature: vec![],
    }
}

/// Create a dummy BlockProposal for testing.
fn make_dummy_proposal(height: u64, round: u64) -> BlockProposal {
    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height,
            round,
            parent_block_id: [0u8; 32],
            payload_hash: [0u8; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 0,
            timestamp: 0,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![],
        signature: vec![],
    }
}

/// Create a validator set with three validators for testing.
fn make_test_validator_set() -> ConsensusValidatorSet {
    let validators = vec![
        ValidatorSetEntry {
            id: ValidatorId::new(1),
            voting_power: 10,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(2),
            voting_power: 20,
        },
        ValidatorSetEntry {
            id: ValidatorId::new(3),
            voting_power: 30,
        },
    ];
    ConsensusValidatorSet::new(validators).unwrap()
}

// ============================================================================
// Section 1: Node wiring uses strict mode
// ============================================================================

/// Test that `new_strict()` creates a driver in strict mode.
///
/// The driver should have `is_strict_mode() == true` and should enforce
/// membership checks for incoming votes and proposals.
#[test]
fn t117_new_strict_creates_strict_mode_driver() {
    let engine = HotStuffState::new_at_height(1);
    let validator_set = make_test_validator_set();
    let ctx = ValidatorContext::new(validator_set);

    let driver: HotStuffDriver<HotStuffState, [u8; 32]> = HotStuffDriver::new_strict(engine, ctx);

    // The driver should be in strict mode
    assert!(
        driver.is_strict_mode(),
        "new_strict() should create a driver in strict mode"
    );

    // The driver should have a validator context
    assert!(
        driver.validators().is_some(),
        "new_strict() driver should have validator context"
    );
}

/// Test that `with_validators()` (alias for `new_strict`) creates strict mode.
///
/// This is the constructor currently used by NodeHotstuffHarness, so it must
/// produce a strict-mode driver.
#[test]
fn t117_with_validators_creates_strict_mode_driver() {
    let engine = HotStuffState::new_at_height(1);
    let validator_set = make_test_validator_set();
    let ctx = ValidatorContext::new(validator_set);

    let driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::with_validators(engine, ctx);

    // The driver should be in strict mode
    assert!(
        driver.is_strict_mode(),
        "with_validators() should create a driver in strict mode"
    );

    // The driver should have a validator context
    assert!(
        driver.validators().is_some(),
        "with_validators() driver should have validator context"
    );
}

/// Test that strict-mode driver rejects votes from unknown validators.
///
/// When using `new_strict()`, votes from validators not in the context
/// should be rejected (counted in `rejected_votes()`).
#[test]
fn t117_strict_mode_rejects_vote_from_unknown_validator() {
    let engine = HotStuffState::new_at_height(1);
    let validator_set = make_test_validator_set(); // Contains validators 1, 2, 3
    let ctx = ValidatorContext::new(validator_set);

    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new_strict(engine, ctx);
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a vote from validator 999 (NOT in the set)
    let vote = make_dummy_vote(1, 0);
    let event = ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(999),
        vote,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Vote should be rejected
    assert_eq!(
        driver.votes_received(),
        0,
        "Unknown validator vote should not be counted as received"
    );
    assert_eq!(
        driver.rejected_votes(),
        1,
        "Unknown validator vote should be rejected"
    );
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

/// Test that strict-mode driver accepts votes from known validators.
#[test]
fn t117_strict_mode_accepts_vote_from_known_validator() {
    let engine = HotStuffState::new_at_height(1);
    let validator_set = make_test_validator_set(); // Contains validators 1, 2, 3
    let ctx = ValidatorContext::new(validator_set);

    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new_strict(engine, ctx);
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a vote from validator 2 (IN the set)
    let vote = make_dummy_vote(1, 0);
    let event = ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(2),
        vote,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Vote should be accepted
    assert_eq!(
        driver.votes_received(),
        1,
        "Known validator vote should be counted"
    );
    assert_eq!(
        driver.rejected_votes(),
        0,
        "Known validator vote should not be rejected"
    );
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

/// Test that strict-mode driver rejects proposals from unknown validators.
#[test]
fn t117_strict_mode_rejects_proposal_from_unknown_validator() {
    let engine = HotStuffState::new_at_height(1);
    let validator_set = make_test_validator_set();
    let ctx = ValidatorContext::new(validator_set);

    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new_strict(engine, ctx);
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a proposal from validator 999 (NOT in the set)
    let proposal = make_dummy_proposal(1, 0);
    let event = ConsensusNetworkEvent::IncomingProposal {
        from: ValidatorId::new(999),
        proposal,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Proposal should be rejected
    assert_eq!(driver.proposals_received(), 0);
    assert_eq!(driver.rejected_proposals(), 1);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

/// Test that strict-mode driver accepts proposals from known validators.
#[test]
fn t117_strict_mode_accepts_proposal_from_known_validator() {
    let engine = HotStuffState::new_at_height(1);
    let validator_set = make_test_validator_set();
    let ctx = ValidatorContext::new(validator_set);

    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new_strict(engine, ctx);
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a proposal from validator 1 (IN the set)
    let proposal = make_dummy_proposal(1, 0);
    let event = ConsensusNetworkEvent::IncomingProposal {
        from: ValidatorId::new(1),
        proposal,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Proposal should be accepted
    assert_eq!(driver.proposals_received(), 1);
    assert_eq!(driver.rejected_proposals(), 0);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

// ============================================================================
// Section 2: Permissive helper is test-only and works as expected
// ============================================================================

/// Test that `for_tests_permissive_validators()` creates a driver in permissive mode.
///
/// This helper is TEST-ONLY (marked with #[doc(hidden)] and clearly named with
/// `for_tests_` prefix) and creates a driver that accepts all validators
/// regardless of membership.
#[test]
fn t117_permissive_helper_creates_permissive_mode_driver() {
    let engine = HotStuffState::new_at_height(1);

    let driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine);

    // The driver should NOT be in strict mode
    assert!(
        !driver.is_strict_mode(),
        "for_tests_permissive_validators() should create permissive mode"
    );

    // The driver should have NO validator context
    assert!(
        driver.validators().is_none(),
        "permissive driver should have no validator context"
    );
}

/// Test that permissive-mode driver accepts votes from any validator.
///
/// This is the key behavior we want for test helpers: bypass membership checks.
#[test]
fn t117_permissive_mode_accepts_vote_from_any_validator() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine);
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a vote from validator 999999 (would be unknown in any real set)
    let vote = make_dummy_vote(1, 0);
    let event = ConsensusNetworkEvent::IncomingVote {
        from: ValidatorId::new(999999),
        vote,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Vote should be accepted (permissive mode)
    assert_eq!(
        driver.votes_received(),
        1,
        "Permissive mode should accept any vote"
    );
    assert_eq!(
        driver.rejected_votes(),
        0,
        "Permissive mode should not reject any votes"
    );
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

/// Test that permissive-mode driver accepts proposals from any validator.
#[test]
fn t117_permissive_mode_accepts_proposal_from_any_validator() {
    let engine = HotStuffState::new_at_height(1);
    let mut driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine);
    let mut net: MockConsensusNetwork<ValidatorId> = MockConsensusNetwork::new();

    // Send a proposal from validator 888888
    let proposal = make_dummy_proposal(1, 0);
    let event = ConsensusNetworkEvent::IncomingProposal {
        from: ValidatorId::new(888888),
        proposal,
    };

    let actions = driver.step(&mut net, Some(event)).unwrap();

    // Proposal should be accepted (permissive mode)
    assert_eq!(
        driver.proposals_received(),
        1,
        "Permissive mode should accept any proposal"
    );
    assert_eq!(driver.rejected_proposals(), 0);
    assert_eq!(actions.len(), 1);
    assert!(matches!(actions[0], ConsensusEngineAction::Noop));
}

// ============================================================================
// Section 3: Mode detection and consistency
// ============================================================================

/// Test that `is_strict_mode()` correctly reflects the driver's mode.
#[test]
fn t117_is_strict_mode_reflects_actual_mode() {
    // Strict mode
    let engine1 = HotStuffState::new_at_height(1);
    let ctx = ValidatorContext::new(make_test_validator_set());
    let strict_driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new_strict(engine1, ctx);
    assert!(strict_driver.is_strict_mode());

    // Permissive mode
    let engine2 = HotStuffState::new_at_height(1);
    let permissive_driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine2);
    assert!(!permissive_driver.is_strict_mode());
}

/// Test that both constructors produce drivers with correct initial counters.
#[test]
fn t117_both_constructors_have_zero_counters() {
    // Strict mode
    let engine1 = HotStuffState::new_at_height(1);
    let ctx = ValidatorContext::new(make_test_validator_set());
    let strict_driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new_strict(engine1, ctx);
    assert_eq!(strict_driver.votes_received(), 0);
    assert_eq!(strict_driver.proposals_received(), 0);
    assert_eq!(strict_driver.rejected_votes(), 0);
    assert_eq!(strict_driver.rejected_proposals(), 0);

    // Permissive mode
    let engine2 = HotStuffState::new_at_height(1);
    let permissive_driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine2);
    assert_eq!(permissive_driver.votes_received(), 0);
    assert_eq!(permissive_driver.proposals_received(), 0);
    assert_eq!(permissive_driver.rejected_votes(), 0);
    assert_eq!(permissive_driver.rejected_proposals(), 0);
}

// ============================================================================
// Section 4: Verifier attachment works in both modes
// ============================================================================

/// Test that verifiers can be attached to strict-mode drivers.
#[test]
fn t117_strict_mode_supports_verifier_attachment() {
    use qbind_consensus::NoopConsensusVerifier;
    use std::sync::Arc;

    let engine = HotStuffState::new_at_height(1);
    let ctx = ValidatorContext::new(make_test_validator_set());

    let driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::new_strict(engine, ctx).with_verifier(Arc::new(NoopConsensusVerifier));

    assert!(driver.is_strict_mode());
}

/// Test that verifiers can be attached to permissive-mode drivers.
#[test]
fn t117_permissive_mode_supports_verifier_attachment() {
    use qbind_consensus::NoopConsensusVerifier;
    use std::sync::Arc;

    let engine = HotStuffState::new_at_height(1);

    let driver: HotStuffDriver<HotStuffState, [u8; 32]> =
        HotStuffDriver::for_tests_permissive_validators(engine)
            .with_verifier(Arc::new(NoopConsensusVerifier));

    assert!(!driver.is_strict_mode());
}

// ============================================================================
// Documentation tests (compile-time checks)
// ============================================================================

/// This test documents the contract for node wiring code.
///
/// The NodeHotstuffHarness (in qbind-node) MUST use `with_validators()` or
/// `new_strict()` to ensure strict mode. This is enforced by:
/// 1. `new()` is deprecated and generates warnings
/// 2. `for_tests_permissive_validators()` is clearly named with `for_tests_` prefix
///    and marked with `#[doc(hidden)]` to discourage production use
///
/// # Node wiring pattern (enforced by T117):
///
/// ```ignore
/// // CORRECT: Node code uses with_validators (strict mode)
/// let vctx = ValidatorContext::new(consensus_validators);
/// let driver = HotStuffDriver::with_validators(engine, vctx);
/// assert!(driver.is_strict_mode());
/// ```
///
/// # Test helper pattern (allowed in tests only):
///
/// ```ignore
/// // ONLY IN TESTS: Use explicit permissive helper
/// let driver = HotStuffDriver::for_tests_permissive_validators(engine);
/// assert!(!driver.is_strict_mode());
/// ```
#[test]
fn t117_documentation_contract_test() {
    // This test just documents the contract - actual enforcement is via:
    // 1. #[deprecated] on new() which generates compiler warnings
    // 2. Clear `for_tests_` naming prefix that makes misuse obvious in code review
    // 3. #[doc(hidden)] which hides the function from documentation

    // The key invariant:
    // - The `for_tests_permissive_validators()` function name makes it obvious
    //   when it's being misused in production code
    // - Code review should catch any use of this function outside test code
    // - Production code should use new_strict() or with_validators()

    // This test passes if it compiles, which proves the helper is available in tests
    let engine = HotStuffState::new_at_height(1);
    let _driver =
        HotStuffDriver::<HotStuffState, [u8; 32]>::for_tests_permissive_validators(engine);
}
