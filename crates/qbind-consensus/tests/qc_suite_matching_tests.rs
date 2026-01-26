//! T115: QC suite matching tests.
//!
//! These tests verify that:
//! - QC with correct suite (matching epoch suite) is accepted.
//! - QC with wrong suite (not matching epoch suite) is rejected with clear error.
//! - The `ensure_qc_suite_matches_epoch()` helper works correctly.
//!
//! # Test Organization
//!
//! - Tests for the `ensure_qc_suite_matches_epoch()` helper function.
//! - Tests for the `QcSuiteMismatch` error variant.
//! - Tests proving no panics occur during QC suite validation.

use qbind_consensus::verify::{ensure_qc_suite_matches_epoch, VerificationError};
use qbind_crypto::consensus_sig::SUITE_TOY_SHA3;
use qbind_crypto::suite_catalog::{SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2};
use qbind_crypto::ConsensusSigSuiteId;

// ============================================================================
// T115: QC Suite Matching Helper Tests
// ============================================================================

/// Test that ensure_qc_suite_matches_epoch returns Ok when suites match.
#[test]
fn qc_suite_matches_epoch_returns_ok() {
    let qc_suite = SUITE_TOY_SHA3;
    let epoch_suite = SUITE_TOY_SHA3;

    let result = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
    assert!(result.is_ok(), "Matching suites should return Ok");
}

/// Test that ensure_qc_suite_matches_epoch returns Ok for matching PQ suites.
#[test]
fn qc_suite_matches_epoch_pq_suite_returns_ok() {
    let qc_suite = SUITE_PQ_RESERVED_1;
    let epoch_suite = SUITE_PQ_RESERVED_1;

    let result = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
    assert!(result.is_ok(), "Matching PQ suites should return Ok");
}

/// Test that ensure_qc_suite_matches_epoch returns error when suites differ.
#[test]
fn qc_suite_mismatch_returns_error() {
    let qc_suite = SUITE_TOY_SHA3;
    let epoch_suite = SUITE_PQ_RESERVED_1;

    let result = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
    match result {
        Err(VerificationError::QcSuiteMismatch {
            qc_suite: qs,
            epoch_suite: es,
        }) => {
            assert_eq!(qs, SUITE_TOY_SHA3);
            assert_eq!(es, SUITE_PQ_RESERVED_1);
        }
        other => panic!("Expected QcSuiteMismatch, got {:?}", other),
    }
}

/// Test that ensure_qc_suite_matches_epoch returns error when PQ suites differ.
#[test]
fn qc_suite_mismatch_different_pq_suites() {
    let qc_suite = SUITE_PQ_RESERVED_1;
    let epoch_suite = SUITE_PQ_RESERVED_2;

    let result = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
    match result {
        Err(VerificationError::QcSuiteMismatch {
            qc_suite: qs,
            epoch_suite: es,
        }) => {
            assert_eq!(qs, SUITE_PQ_RESERVED_1);
            assert_eq!(es, SUITE_PQ_RESERVED_2);
        }
        other => panic!("Expected QcSuiteMismatch, got {:?}", other),
    }
}

/// Test that ensure_qc_suite_matches_epoch works with arbitrary suite IDs.
#[test]
fn qc_suite_mismatch_arbitrary_suite_ids() {
    let qc_suite = ConsensusSigSuiteId::new(12345);
    let epoch_suite = ConsensusSigSuiteId::new(54321);

    let result = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
    match result {
        Err(VerificationError::QcSuiteMismatch {
            qc_suite: qs,
            epoch_suite: es,
        }) => {
            assert_eq!(qs.as_u16(), 12345);
            assert_eq!(es.as_u16(), 54321);
        }
        other => panic!("Expected QcSuiteMismatch, got {:?}", other),
    }
}

// ============================================================================
// T115: QcSuiteMismatch Error Display Tests
// ============================================================================

/// Test that QcSuiteMismatch error has descriptive Display output.
#[test]
fn qc_suite_mismatch_error_display() {
    let err = VerificationError::QcSuiteMismatch {
        qc_suite: ConsensusSigSuiteId::new(999),
        epoch_suite: SUITE_TOY_SHA3,
    };

    let display_str = format!("{}", err);
    assert!(
        display_str.contains("QC suite mismatch"),
        "Should mention QC suite mismatch: {}",
        display_str
    );
    assert!(
        display_str.contains("999") || display_str.contains("suite_999"),
        "Should mention QC suite: {}",
        display_str
    );
    assert!(
        display_str.contains("0") || display_str.contains("suite_0"),
        "Should mention epoch suite: {}",
        display_str
    );
}

/// Test that QcSuiteMismatch error includes both suite IDs in the message.
#[test]
fn qc_suite_mismatch_error_includes_both_suites() {
    let err = VerificationError::QcSuiteMismatch {
        qc_suite: SUITE_PQ_RESERVED_1,
        epoch_suite: SUITE_PQ_RESERVED_2,
    };

    let display_str = format!("{}", err);
    // The suite IDs are 100 and 101 respectively
    assert!(
        display_str.contains("100") || display_str.contains("suite_100"),
        "Should mention QC suite ID 100: {}",
        display_str
    );
    assert!(
        display_str.contains("101") || display_str.contains("suite_101"),
        "Should mention epoch suite ID 101: {}",
        display_str
    );
}

// ============================================================================
// T115: No Panic Tests
// ============================================================================

/// Test that QC suite mismatch check does not panic with edge case suite IDs.
#[test]
fn qc_suite_check_does_not_panic_min_values() {
    let qc_suite = ConsensusSigSuiteId::new(0);
    let epoch_suite = ConsensusSigSuiteId::new(1);

    // Should not panic
    let _ = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
}

/// Test that QC suite mismatch check does not panic with max u16 values.
#[test]
fn qc_suite_check_does_not_panic_max_values() {
    let qc_suite = ConsensusSigSuiteId::new(u16::MAX);
    let epoch_suite = ConsensusSigSuiteId::new(u16::MAX - 1);

    // Should not panic
    let result = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
    assert!(result.is_err(), "Different suites should return error");
}

/// Test that QC suite mismatch check does not panic with same max values.
#[test]
fn qc_suite_check_does_not_panic_same_max_values() {
    let qc_suite = ConsensusSigSuiteId::new(u16::MAX);
    let epoch_suite = ConsensusSigSuiteId::new(u16::MAX);

    // Should not panic
    let result = ensure_qc_suite_matches_epoch(qc_suite, epoch_suite);
    assert!(result.is_ok(), "Same suites should return Ok");
}

// ============================================================================
// T115: VerificationError Variant Tests
// ============================================================================

/// Test that QcSuiteMismatch implements PartialEq correctly.
#[test]
fn qc_suite_mismatch_eq() {
    let err1 = VerificationError::QcSuiteMismatch {
        qc_suite: SUITE_TOY_SHA3,
        epoch_suite: SUITE_PQ_RESERVED_1,
    };
    let err2 = VerificationError::QcSuiteMismatch {
        qc_suite: SUITE_TOY_SHA3,
        epoch_suite: SUITE_PQ_RESERVED_1,
    };
    let err3 = VerificationError::QcSuiteMismatch {
        qc_suite: SUITE_PQ_RESERVED_1,
        epoch_suite: SUITE_TOY_SHA3,
    };

    assert_eq!(err1, err2, "Same errors should be equal");
    assert_ne!(err1, err3, "Different errors should not be equal");
}

/// Test that QcSuiteMismatch implements Clone correctly.
#[test]
fn qc_suite_mismatch_clone() {
    let err = VerificationError::QcSuiteMismatch {
        qc_suite: SUITE_TOY_SHA3,
        epoch_suite: SUITE_PQ_RESERVED_1,
    };
    let cloned = err.clone();
    assert_eq!(err, cloned, "Cloned error should equal original");
}

/// Test that QcSuiteMismatch implements Debug correctly.
#[test]
fn qc_suite_mismatch_debug() {
    let err = VerificationError::QcSuiteMismatch {
        qc_suite: SUITE_TOY_SHA3,
        epoch_suite: SUITE_PQ_RESERVED_1,
    };
    let debug_str = format!("{:?}", err);
    assert!(
        debug_str.contains("QcSuiteMismatch"),
        "Debug should include variant name: {}",
        debug_str
    );
}

// ============================================================================
// T115: Correct Suite Path Tests
// ============================================================================

/// Test the correct-suite path works with SUITE_TOY_SHA3.
#[test]
fn correct_suite_path_toy_sha3() {
    let result = ensure_qc_suite_matches_epoch(SUITE_TOY_SHA3, SUITE_TOY_SHA3);
    assert!(result.is_ok(), "Same SUITE_TOY_SHA3 should succeed");
}

/// Test the correct-suite path works with SUITE_PQ_RESERVED_1.
#[test]
fn correct_suite_path_pq_reserved_1() {
    let result = ensure_qc_suite_matches_epoch(SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_1);
    assert!(result.is_ok(), "Same SUITE_PQ_RESERVED_1 should succeed");
}

/// Test the correct-suite path works with SUITE_PQ_RESERVED_2.
#[test]
fn correct_suite_path_pq_reserved_2() {
    let result = ensure_qc_suite_matches_epoch(SUITE_PQ_RESERVED_2, SUITE_PQ_RESERVED_2);
    assert!(result.is_ok(), "Same SUITE_PQ_RESERVED_2 should succeed");
}

/// Test that calling the helper multiple times in sequence doesn't cause issues.
#[test]
fn multiple_qc_suite_checks_sequential() {
    // All these should succeed
    assert!(ensure_qc_suite_matches_epoch(SUITE_TOY_SHA3, SUITE_TOY_SHA3).is_ok());
    assert!(ensure_qc_suite_matches_epoch(SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_1).is_ok());
    assert!(ensure_qc_suite_matches_epoch(SUITE_PQ_RESERVED_2, SUITE_PQ_RESERVED_2).is_ok());

    // These should fail
    assert!(ensure_qc_suite_matches_epoch(SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1).is_err());
    assert!(ensure_qc_suite_matches_epoch(SUITE_PQ_RESERVED_1, SUITE_TOY_SHA3).is_err());
    assert!(ensure_qc_suite_matches_epoch(SUITE_PQ_RESERVED_1, SUITE_PQ_RESERVED_2).is_err());
}
