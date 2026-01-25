//! Consensus Signature Suite Catalog
//!
//! This module provides a central catalog of known consensus signature suites,
//! including metadata, lookup APIs, and guardrails for ensuring catalog consistency.
//!
//! # Design
//!
//! The catalog defines:
//! - Canonical suite IDs and their metadata (name, PQ-ness, toy vs production, security level)
//! - Lookup functions to map `ConsensusSigSuiteId` → metadata
//! - Guardrails to ensure no duplicate IDs and proper suite categorization
//!
//! # Suite Registry
//!
//! Currently defined suites:
//! - `SUITE_TOY_SHA3` (ID 0): Test-only SHA3-based suite, NOT FOR PRODUCTION
//! - `SUITE_PQ_RESERVED_1` (ID 100): Reserved for future ML-DSA-44 backend (T111+)
//! - `SUITE_PQ_RESERVED_2` (ID 101): Reserved for future ML-DSA-87 backend (T111+)
//! - `SUITE_PQ_RESERVED_3` (ID 102): Reserved for future SPHINCS+-128s backend (T111+)
//!
//! # Future Work
//!
//! Real PQ signature implementations will be added in T111+ tasks. This module
//! provides the structural foundation without any actual cryptographic backends.

use crate::consensus_sig::{ConsensusSigSuiteId, SUITE_TOY_SHA3};

// ============================================================================
// Reserved PQ Suite IDs
// ============================================================================

/// Reserved suite ID for future ML-DSA-44 (Dilithium2) backend.
///
/// This suite is intended for post-quantum signature verification using
/// the ML-DSA-44 algorithm (FIPS 204). The backend is implemented in
/// `cano_crypto::ml_dsa44::MlDsa44Backend`.
///
/// **IMPLEMENTED** (T131) - real ML-DSA-44 backend available.
pub const SUITE_PQ_RESERVED_1: ConsensusSigSuiteId = ConsensusSigSuiteId(100);

/// Reserved suite ID for future ML-DSA-87 (Dilithium5) backend.
///
/// This suite is intended for post-quantum signature verification using
/// the ML-DSA-87 algorithm (FIPS 204). The actual backend will be implemented
/// in T111+ tasks.
///
/// **NOT YET IMPLEMENTED** - placeholder for future PQ backend.
pub const SUITE_PQ_RESERVED_2: ConsensusSigSuiteId = ConsensusSigSuiteId(101);

/// Reserved suite ID for future SPHINCS+-128s backend.
///
/// This suite is intended for post-quantum signature verification using
/// the SPHINCS+-128s algorithm. The actual backend will be implemented
/// in T111+ tasks.
///
/// **NOT YET IMPLEMENTED** - placeholder for future PQ backend.
pub const SUITE_PQ_RESERVED_3: ConsensusSigSuiteId = ConsensusSigSuiteId(102);

// ============================================================================
// Suite Metadata
// ============================================================================

/// Metadata describing a consensus signature suite.
///
/// This struct provides information about a signature suite including its
/// name, whether it's post-quantum, whether it's a toy/test suite, and
/// its approximate security level.
///
/// # Fields
///
/// - `id`: The unique identifier for this suite
/// - `name`: Human-readable name for the suite
/// - `is_pq`: Whether this suite uses post-quantum cryptography
/// - `is_toy`: Whether this suite is for testing only (NOT FOR PRODUCTION)
/// - `security_bits`: Approximate classical security level (None for toy suites)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsensusSigSuiteInfo {
    /// The unique identifier for this suite.
    pub id: ConsensusSigSuiteId,
    /// Human-readable name for the suite.
    pub name: &'static str,
    /// Whether this suite uses post-quantum cryptography.
    pub is_pq: bool,
    /// Whether this suite is for testing only (NOT FOR PRODUCTION).
    pub is_toy: bool,
    /// Approximate classical security level in bits.
    /// `None` for toy suites, `Some(n)` where n >= 128 for production suites.
    pub security_bits: Option<u16>,
}

// ============================================================================
// Static Catalog
// ============================================================================

/// Static catalog of all known consensus signature suites.
///
/// This catalog is the authoritative source for suite metadata. It includes:
/// - The toy SHA3 suite for testing
/// - Reserved PQ suites for future implementation
///
/// # Invariants
///
/// The catalog maintains the following invariants (enforced by tests):
/// - No duplicate suite IDs
/// - At most one toy suite
/// - PQ suites have `is_pq == true` and `is_toy == false`
/// - PQ suites have `security_bits.is_some()` with value >= 128
/// - Toy suites have `security_bits == None`
pub const KNOWN_CONSENSUS_SIG_SUITES: &[ConsensusSigSuiteInfo] = &[
    // Toy suite for testing - NOT FOR PRODUCTION
    ConsensusSigSuiteInfo {
        id: SUITE_TOY_SHA3,
        name: "toy-sha3",
        is_pq: false,
        is_toy: true,
        security_bits: None,
    },
    // Reserved PQ suite: ML-DSA-44 (Dilithium2)
    // Implemented in T131 - real backend available
    ConsensusSigSuiteInfo {
        id: SUITE_PQ_RESERVED_1,
        name: "ml-dsa-44",
        is_pq: true,
        is_toy: false,
        security_bits: Some(128), // NIST Level 1 (128-bit classical security)
    },
    // Reserved PQ suite: ML-DSA-87 (Dilithium5)
    // Placeholder for T111+ - backend not yet implemented
    ConsensusSigSuiteInfo {
        id: SUITE_PQ_RESERVED_2,
        name: "ml-dsa-87-reserved",
        is_pq: true,
        is_toy: false,
        security_bits: Some(256), // NIST Level 5 (256-bit classical security)
    },
    // Reserved PQ suite: SPHINCS+-128s
    // Placeholder for T111+ - backend not yet implemented
    ConsensusSigSuiteInfo {
        id: SUITE_PQ_RESERVED_3,
        name: "sphincs-plus-128s-reserved",
        is_pq: true,
        is_toy: false,
        security_bits: Some(128), // NIST Level 1 (128-bit classical security)
    },
];

// ============================================================================
// Lookup Functions
// ============================================================================

/// Find a suite by its ID.
///
/// Returns `Some(&ConsensusSigSuiteInfo)` if the suite is known, or `None` if
/// the suite ID is not in the catalog.
///
/// # Examples
///
/// ```
/// use cano_crypto::{SUITE_TOY_SHA3, suite_catalog::find_suite};
///
/// let info = find_suite(SUITE_TOY_SHA3).unwrap();
/// assert_eq!(info.name, "toy-sha3");
/// assert!(info.is_toy);
/// ```
pub fn find_suite(id: ConsensusSigSuiteId) -> Option<&'static ConsensusSigSuiteInfo> {
    KNOWN_CONSENSUS_SIG_SUITES.iter().find(|info| info.id == id)
}

/// Get all known suites.
///
/// Returns a slice containing metadata for all suites in the catalog.
///
/// # Examples
///
/// ```
/// use cano_crypto::suite_catalog::all_suites;
///
/// let suites = all_suites();
/// assert!(!suites.is_empty());
/// ```
pub fn all_suites() -> &'static [ConsensusSigSuiteInfo] {
    KNOWN_CONSENSUS_SIG_SUITES
}

/// Check if a suite ID is known.
///
/// Returns `true` if the suite ID is in the catalog, `false` otherwise.
///
/// # Examples
///
/// ```
/// use cano_crypto::{ConsensusSigSuiteId, SUITE_TOY_SHA3, suite_catalog::is_known_suite};
///
/// assert!(is_known_suite(SUITE_TOY_SHA3));
/// assert!(!is_known_suite(ConsensusSigSuiteId::new(65535)));
/// ```
pub fn is_known_suite(id: ConsensusSigSuiteId) -> bool {
    find_suite(id).is_some()
}

/// Get the human-readable name of a suite.
///
/// Returns the suite name if known, or `"unknown-suite"` if the suite ID
/// is not in the catalog.
///
/// # Examples
///
/// ```
/// use cano_crypto::{ConsensusSigSuiteId, SUITE_TOY_SHA3, suite_catalog::suite_name};
///
/// assert_eq!(suite_name(SUITE_TOY_SHA3), "toy-sha3");
/// assert_eq!(suite_name(ConsensusSigSuiteId::new(65535)), "unknown-suite");
/// ```
pub fn suite_name(id: ConsensusSigSuiteId) -> &'static str {
    find_suite(id)
        .map(|info| info.name)
        .unwrap_or("unknown-suite")
}

/// Get the effective security bits for a suite.
///
/// Returns the security bits for known suites, treating `None` as 0.
/// For unknown suites, returns 0.
///
/// This is useful for comparing suite security levels where unknown
/// or toy suites should be treated as having minimal security.
///
/// # Examples
///
/// ```
/// use cano_crypto::{SUITE_TOY_SHA3, SUITE_PQ_RESERVED_1, suite_catalog::effective_security_bits};
///
/// assert_eq!(effective_security_bits(SUITE_TOY_SHA3), 0); // None → 0
/// assert_eq!(effective_security_bits(SUITE_PQ_RESERVED_1), 128); // Some(128) → 128
/// ```
pub fn effective_security_bits(id: ConsensusSigSuiteId) -> u16 {
    find_suite(id)
        .and_then(|info| info.security_bits)
        .unwrap_or(0)
}

// ============================================================================
// Catalog Validation
// ============================================================================

/// Validate the suite catalog for consistency.
///
/// This function checks that the catalog maintains all required invariants:
/// - No duplicate suite IDs
/// - At most one toy suite
/// - PQ suites have `is_pq == true` and `is_toy == false`
/// - PQ suites have `security_bits >= Some(128)`
/// - Toy suites have `security_bits == None`
///
/// # Returns
///
/// `Ok(())` if all invariants hold, `Err(String)` with a description of the
/// first violated invariant.
///
/// # Note
///
/// This function is primarily intended for use in tests to ensure catalog
/// consistency is maintained as new suites are added.
pub fn validate_suite_catalog() -> Result<(), String> {
    use std::collections::HashSet;

    let suites = all_suites();

    // Check for duplicate IDs
    let mut seen_ids = HashSet::new();
    for info in suites {
        if !seen_ids.insert(info.id) {
            return Err(format!("duplicate suite ID: {} ({})", info.id, info.name));
        }
    }

    // Check for at most one toy suite
    let toy_count = suites.iter().filter(|info| info.is_toy).count();
    if toy_count > 1 {
        return Err(format!(
            "multiple toy suites found: expected at most 1, found {}",
            toy_count
        ));
    }

    // Validate each suite's properties
    for info in suites {
        if info.is_toy {
            // Toy suites should not be PQ
            if info.is_pq {
                return Err(format!(
                    "toy suite '{}' is marked as PQ, which is inconsistent",
                    info.name
                ));
            }
            // Toy suites should not have security_bits
            if info.security_bits.is_some() {
                return Err(format!(
                    "toy suite '{}' has security_bits set, expected None",
                    info.name
                ));
            }
        } else {
            // Non-toy suites that are PQ should have proper security_bits
            if info.is_pq {
                match info.security_bits {
                    None => {
                        return Err(format!(
                            "PQ suite '{}' has no security_bits, expected Some(n) where n >= 128",
                            info.name
                        ));
                    }
                    Some(bits) if bits < 128 => {
                        return Err(format!(
                            "PQ suite '{}' has security_bits={}, expected >= 128",
                            info.name, bits
                        ));
                    }
                    Some(_) => {} // Valid
                }
            }
        }
    }

    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------------------
    // Catalog invariant tests
    // ------------------------------------------------------------------------

    /// Test that the catalog validation passes.
    #[test]
    fn catalog_validation_passes() {
        let result = validate_suite_catalog();
        assert!(result.is_ok(), "Catalog validation failed: {:?}", result);
    }

    /// Test that there are no duplicate suite IDs.
    #[test]
    fn no_duplicate_suite_ids() {
        use std::collections::HashSet;
        let mut ids = HashSet::new();
        for info in all_suites() {
            assert!(
                ids.insert(info.id),
                "duplicate suite ID found: {} ({})",
                info.id,
                info.name
            );
        }
    }

    /// Test that exactly one toy suite is present.
    #[test]
    fn exactly_one_toy_suite() {
        let toy_suites: Vec<_> = all_suites().iter().filter(|info| info.is_toy).collect();
        assert_eq!(
            toy_suites.len(),
            1,
            "expected exactly 1 toy suite, found {}",
            toy_suites.len()
        );
        assert_eq!(toy_suites[0].id, SUITE_TOY_SHA3);
        assert_eq!(toy_suites[0].name, "toy-sha3");
    }

    /// Test that PQ suites have correct properties.
    #[test]
    fn pq_suites_have_correct_properties() {
        let pq_suites: Vec<_> = all_suites().iter().filter(|info| info.is_pq).collect();
        assert!(
            pq_suites.len() >= 2,
            "expected at least 2 PQ suites, found {}",
            pq_suites.len()
        );

        for info in pq_suites {
            assert!(
                info.is_pq,
                "suite '{}' should have is_pq == true",
                info.name
            );
            assert!(
                !info.is_toy,
                "PQ suite '{}' should have is_toy == false",
                info.name
            );
            assert!(
                info.security_bits.is_some(),
                "PQ suite '{}' should have security_bits.is_some()",
                info.name
            );
            let bits = info.security_bits.unwrap();
            assert!(
                bits >= 128,
                "PQ suite '{}' should have security_bits >= 128, got {}",
                info.name,
                bits
            );
        }
    }

    // ------------------------------------------------------------------------
    // Lookup behavior tests
    // ------------------------------------------------------------------------

    /// Test find_suite for SUITE_TOY_SHA3.
    #[test]
    fn find_suite_toy_sha3() {
        let info = find_suite(SUITE_TOY_SHA3);
        assert!(info.is_some(), "SUITE_TOY_SHA3 should be found");
        let info = info.unwrap();
        assert_eq!(info.name, "toy-sha3");
        assert!(info.is_toy);
        assert!(!info.is_pq);
        assert_eq!(info.security_bits, None);
    }

    /// Test find_suite for reserved PQ suite 1 (ML-DSA-44).
    #[test]
    fn find_suite_pq_reserved_1() {
        let info = find_suite(SUITE_PQ_RESERVED_1);
        assert!(info.is_some(), "SUITE_PQ_RESERVED_1 should be found");
        let info = info.unwrap();
        assert_eq!(info.name, "ml-dsa-44");
        assert!(info.is_pq);
        assert!(!info.is_toy);
        assert_eq!(info.security_bits, Some(128));
    }

    /// Test find_suite for reserved PQ suite 2 (ML-DSA-87).
    #[test]
    fn find_suite_pq_reserved_2() {
        let info = find_suite(SUITE_PQ_RESERVED_2);
        assert!(info.is_some(), "SUITE_PQ_RESERVED_2 should be found");
        let info = info.unwrap();
        assert_eq!(info.name, "ml-dsa-87-reserved");
        assert!(info.is_pq);
        assert!(!info.is_toy);
        assert_eq!(info.security_bits, Some(256));
    }

    /// Test find_suite for reserved PQ suite 3 (SPHINCS+-128s).
    #[test]
    fn find_suite_pq_reserved_3() {
        let info = find_suite(SUITE_PQ_RESERVED_3);
        assert!(info.is_some(), "SUITE_PQ_RESERVED_3 should be found");
        let info = info.unwrap();
        assert_eq!(info.name, "sphincs-plus-128s-reserved");
        assert!(info.is_pq);
        assert!(!info.is_toy);
        assert_eq!(info.security_bits, Some(128));
    }

    // ------------------------------------------------------------------------
    // Unknown suite tests
    // ------------------------------------------------------------------------

    /// Test that an unknown suite ID returns None from find_suite.
    #[test]
    fn unknown_suite_returns_none() {
        let unknown_id = ConsensusSigSuiteId::new(65535);
        assert!(
            find_suite(unknown_id).is_none(),
            "unknown suite ID should return None"
        );
    }

    /// Test that suite_name returns "unknown-suite" for unknown IDs.
    #[test]
    fn unknown_suite_name() {
        let unknown_id = ConsensusSigSuiteId::new(65535);
        assert_eq!(
            suite_name(unknown_id),
            "unknown-suite",
            "unknown suite should return 'unknown-suite'"
        );
    }

    /// Test is_known_suite for known and unknown suites.
    #[test]
    fn is_known_suite_behavior() {
        assert!(is_known_suite(SUITE_TOY_SHA3));
        assert!(is_known_suite(SUITE_PQ_RESERVED_1));
        assert!(is_known_suite(SUITE_PQ_RESERVED_2));
        assert!(is_known_suite(SUITE_PQ_RESERVED_3));
        assert!(!is_known_suite(ConsensusSigSuiteId::new(65535)));
        assert!(!is_known_suite(ConsensusSigSuiteId::new(999)));
    }

    // ------------------------------------------------------------------------
    // All suites tests
    // ------------------------------------------------------------------------

    /// Test that all_suites returns a non-empty slice.
    #[test]
    fn all_suites_non_empty() {
        let suites = all_suites();
        assert!(
            !suites.is_empty(),
            "all_suites() should return non-empty slice"
        );
        assert!(
            suites.len() >= 4,
            "expected at least 4 suites (1 toy + 3 PQ reserved), found {}",
            suites.len()
        );
    }

    /// Test that every ID in all_suites passes is_known_suite.
    #[test]
    fn all_suites_ids_are_known() {
        for info in all_suites() {
            assert!(
                is_known_suite(info.id),
                "suite '{}' (id={}) should be known",
                info.name,
                info.id
            );
        }
    }

    /// Test that suite_name returns correct names for all known suites.
    #[test]
    fn suite_name_for_all_known_suites() {
        for info in all_suites() {
            assert_eq!(
                suite_name(info.id),
                info.name,
                "suite_name({}) should return '{}'",
                info.id,
                info.name
            );
        }
    }

    // ------------------------------------------------------------------------
    // ConsensusSigSuiteInfo tests
    // ------------------------------------------------------------------------

    /// Test that ConsensusSigSuiteInfo implements Debug.
    #[test]
    fn suite_info_debug() {
        let info = find_suite(SUITE_TOY_SHA3).unwrap();
        let debug_str = format!("{:?}", info);
        assert!(debug_str.contains("toy-sha3"));
        assert!(debug_str.contains("is_toy: true"));
    }

    /// Test that ConsensusSigSuiteInfo implements Clone and Copy.
    #[test]
    fn suite_info_clone_copy() {
        let info = find_suite(SUITE_TOY_SHA3).unwrap();
        let cloned = info.clone();
        let copied: ConsensusSigSuiteInfo = *info;
        assert_eq!(cloned, copied);
        assert_eq!(cloned.id, info.id);
    }

    /// Test that ConsensusSigSuiteInfo implements Eq.
    #[test]
    fn suite_info_equality() {
        let info1 = find_suite(SUITE_TOY_SHA3).unwrap();
        let info2 = find_suite(SUITE_TOY_SHA3).unwrap();
        let info3 = find_suite(SUITE_PQ_RESERVED_1).unwrap();
        assert_eq!(info1, info2);
        assert_ne!(info1, info3);
    }
}
