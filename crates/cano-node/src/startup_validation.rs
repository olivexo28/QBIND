//! Startup-time validation for consensus suites, backends, and storage.
//!
//! This module provides `ConsensusStartupValidator`, a helper that validates
//! at node startup that:
//!
//! 1. For every consensus-signing key known to governance, there is a corresponding
//!    registered `ConsensusSigVerifier` backend for its `ConsensusSigSuiteId`.
//!
//! 2. If there is persisted last-committed state in storage (block + QC), their
//!    suite_id values also have registered backends and are decodable.
//!
//! 3. (T111) All configured validator suites satisfy the `SuitePolicy`:
//!    - Are known (exist in `KNOWN_CONSENSUS_SIG_SUITES`)
//!    - Are not toy suites when running under a "prod" policy
//!    - Satisfy a minimum security level in bits, where configured
//!
//! # Usage
//!
//! ```ignore
//! use std::sync::Arc;
//! use cano_node::startup_validation::{ConsensusStartupValidator, SuitePolicy};
//!
//! let validator = ConsensusStartupValidator::new(
//!     governance,
//!     backend_registry,
//!     storage,
//! ).with_suite_policy(SuitePolicy::prod_default());
//!
//! // Call validate() before starting the consensus loop
//! validator.validate()?;
//! ```
//!
//! # Design Notes
//!
//! - This is a T82.1 task component, building on T79-T82.
//! - T111 adds `SuitePolicy` for startup-only enforcement (no runtime changes).
//! - We do NOT enforce wire vs governance suite equality here (that's T83).
//! - The goal is clear, early failure on misconfiguration with good error messages.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use cano_consensus::crypto_verifier::ConsensusSigBackendRegistry;
use cano_consensus::governed_key_registry::ConsensusKeyGovernance;
use cano_crypto::ConsensusSigSuiteId;

use crate::storage::{ConsensusStorage, StorageError};

// ============================================================================
// StartupValidationError
// ============================================================================

/// Error type for startup validation failures.
///
/// This is a non-leaky error type that does not expose secrets or low-level
/// internal implementation details. It provides clear error messages for
/// operator diagnosis.
#[derive(Debug)]
pub enum StartupValidationError {
    /// No backend is registered for the specified consensus signature suite.
    ///
    /// This indicates a misconfiguration: governance references a suite ID
    /// for which no backend has been registered.
    MissingBackendForSuite(ConsensusSigSuiteId),

    /// Multiple suites are missing backends.
    ///
    /// This aggregates multiple `MissingBackendForSuite` errors into a single
    /// error for clearer diagnostics.
    MissingBackendsForSuites(Vec<ConsensusSigSuiteId>),

    /// Storage is inconsistent or corrupted.
    ///
    /// This indicates that persisted state could not be loaded or decoded.
    /// The string contains a human-readable explanation.
    StorageInconsistent(String),

    /// Error accessing governance data.
    ///
    /// This indicates a problem querying the governance system for validator
    /// keys. The string contains a human-readable explanation.
    GovernanceError(String),

    /// A validator in the epoch has no consensus key registered in governance.
    ///
    /// This indicates a mismatch between the epoch's validator set and the
    /// governance key registry.
    MissingKeyForValidator(cano_consensus::ids::ValidatorId),

    /// A validator's consensus key uses an unknown signature suite.
    ///
    /// This indicates a mismatch between the suite used by governance and
    /// the registered backends.
    UnknownSuiteForValidator {
        validator_id: cano_consensus::ids::ValidatorId,
        suite_id: u16,
    },

    /// Governance has a key for a validator not in the epoch.
    ///
    /// This indicates a mismatch between the epoch's validator set and
    /// governance - there are "stray" keys that don't correspond to any
    /// validator in the current epoch.
    StrayGovernanceKey(cano_consensus::ids::ValidatorId),

    /// A validator's consensus key uses a toy suite which is not allowed
    /// under the current suite policy.
    ///
    /// This indicates that the validator is using a test-only suite (like
    /// SUITE_TOY_SHA3) in a production context where toy suites are disallowed.
    ToySuiteNotAllowed {
        validator_id: cano_consensus::ids::ValidatorId,
        suite_id: u16,
        suite_name: &'static str,
    },

    /// A validator's consensus key uses a suite with insufficient security bits.
    ///
    /// This indicates that the suite's security level (in bits) is below the
    /// minimum required by the current suite policy.
    InsufficientSecurityBits {
        validator_id: cano_consensus::ids::ValidatorId,
        suite_id: u16,
        suite_name: &'static str,
        actual_bits: Option<u16>,
        required_bits: u16,
    },

    /// The epoch contains validators using different consensus signature suites.
    ///
    /// This indicates that the epoch's validator set does not share a single
    /// consensus signature suite. For now, each epoch must be single-suite
    /// for consensus signatures, and this invariant is enforced at startup.
    ///
    /// (T115: Single-suite-per-epoch policy)
    MixedSuitesInEpoch {
        epoch_id: cano_consensus::validator_set::EpochId,
        suites: Vec<ConsensusSigSuiteId>,
    },

    /// Attempted to downgrade to a weaker signature suite across epochs.
    ///
    /// This indicates that epoch N+1 uses a suite with lower effective security
    /// than epoch N, which is not allowed under the current policy.
    ///
    /// (T124: Cross-epoch suite downgrade protection)
    SuiteDowngradeAcrossEpochs {
        from_epoch: cano_consensus::validator_set::EpochId,
        to_epoch: cano_consensus::validator_set::EpochId,
        from_suite: ConsensusSigSuiteId,
        to_suite: ConsensusSigSuiteId,
    },

    /// Other validation error.
    ///
    /// Catch-all for errors that don't fit the other categories.
    Other(String),
}

impl fmt::Display for StartupValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StartupValidationError::MissingBackendForSuite(suite_id) => {
                write!(
                    f,
                    "no consensus signature backend registered for suite {}; \
                     node must be reconfigured or code updated before starting",
                    suite_id
                )
            }
            StartupValidationError::MissingBackendsForSuites(suite_ids) => {
                let suites: Vec<String> = suite_ids.iter().map(|s| s.to_string()).collect();
                write!(
                    f,
                    "no consensus signature backends registered for suites [{}]; \
                     governance references these suites but no backends are available; \
                     node must be reconfigured or code updated before starting",
                    suites.join(", ")
                )
            }
            StartupValidationError::StorageInconsistent(msg) => {
                write!(
                    f,
                    "persisted storage is inconsistent or corrupted: {}; \
                     check storage integrity or clear storage to start fresh",
                    msg
                )
            }
            StartupValidationError::GovernanceError(msg) => {
                write!(f, "error accessing governance data: {}", msg)
            }
            StartupValidationError::MissingKeyForValidator(validator_id) => {
                write!(
                    f,
                    "validator {:?} in epoch has no consensus key registered in governance; \
                     ensure all epoch validators have governance keys configured",
                    validator_id
                )
            }
            StartupValidationError::UnknownSuiteForValidator {
                validator_id,
                suite_id,
            } => {
                write!(
                    f,
                    "validator {:?} uses unknown signature suite {}; \
                     ensure all required backends are registered",
                    validator_id, suite_id
                )
            }
            StartupValidationError::StrayGovernanceKey(validator_id) => {
                write!(
                    f,
                    "governance has a key for validator {:?} which is not in the current epoch; \
                     check epoch configuration for consistency with governance",
                    validator_id
                )
            }
            StartupValidationError::ToySuiteNotAllowed {
                validator_id,
                suite_id,
                suite_name,
            } => {
                write!(
                    f,
                    "validator {:?} uses toy suite {} ('{}') which is not allowed under \
                     the current production policy; use a production-grade suite",
                    validator_id, suite_id, suite_name
                )
            }
            StartupValidationError::InsufficientSecurityBits {
                validator_id,
                suite_id,
                suite_name,
                actual_bits,
                required_bits,
            } => match actual_bits {
                Some(bits) => write!(
                    f,
                    "validator {:?} uses suite {} ('{}') with {} security bits, \
                         but at least {} bits are required by policy",
                    validator_id, suite_id, suite_name, bits, required_bits
                ),
                None => write!(
                    f,
                    "validator {:?} uses suite {} ('{}') with unknown security level, \
                         but at least {} bits are required by policy",
                    validator_id, suite_id, suite_name, required_bits
                ),
            },
            StartupValidationError::MixedSuitesInEpoch { epoch_id, suites } => {
                let suite_strs: Vec<String> = suites.iter().map(|s| s.to_string()).collect();
                write!(
                    f,
                    "epoch {:?} contains validators using multiple signature suites [{}]; \
                     each epoch must use a single consensus signature suite",
                    epoch_id,
                    suite_strs.join(", ")
                )
            }
            StartupValidationError::SuiteDowngradeAcrossEpochs {
                from_epoch,
                to_epoch,
                from_suite,
                to_suite,
            } => {
                write!(
                    f,
                    "suite downgrade detected from epoch {} to {}: {} → {}; \
                     cross-epoch suite monotonicity requires equal or stronger security",
                    from_epoch, to_epoch, from_suite, to_suite
                )
            }
            StartupValidationError::Other(msg) => {
                write!(f, "startup validation error: {}", msg)
            }
        }
    }
}

impl std::error::Error for StartupValidationError {}

impl From<StorageError> for StartupValidationError {
    fn from(err: StorageError) -> Self {
        StartupValidationError::StorageInconsistent(err.to_string())
    }
}

// ============================================================================
// SuitePolicy (T111)
// ============================================================================

/// Policy configuration for suite validation at startup.
///
/// This type controls which signature suites are allowed when validating
/// consensus keys at node startup. It provides two common configurations:
///
/// - `dev_default()`: Permissive policy for development/testing. Allows toy
///   suites like `SUITE_TOY_SHA3` and has no minimum security requirement.
///
/// - `prod_default()`: Strict policy for production/testnet. Disallows toy
///   suites and requires a minimum of 128-bit security.
///
/// # Examples
///
/// ```ignore
/// use cano_node::startup_validation::SuitePolicy;
///
/// // For development: allow toy suites
/// let dev_policy = SuitePolicy::dev_default();
/// assert!(dev_policy.allow_toy);
///
/// // For production: disallow toy suites, require 128-bit security
/// let prod_policy = SuitePolicy::prod_default();
/// assert!(!prod_policy.allow_toy);
/// assert_eq!(prod_policy.min_security_bits, Some(128));
/// ```
///
/// # Design Note (T111)
///
/// This policy is purely startup/config-time enforcement. It does NOT affect
/// runtime signature verification behavior. The goal is to catch misconfigurations
/// early with clear error messages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SuitePolicy {
    /// Whether to allow toy/test-only suites (like `SUITE_TOY_SHA3`).
    ///
    /// When `false`, any validator using a toy suite will fail validation.
    pub allow_toy: bool,

    /// Minimum required security level in bits.
    ///
    /// If `Some(n)`, suites with `security_bits < n` (or `security_bits == None`
    /// for non-toy suites) will fail validation.
    ///
    /// If `None`, no minimum security requirement is enforced.
    pub min_security_bits: Option<u16>,
}

impl SuitePolicy {
    /// Create a development/test-friendly policy.
    ///
    /// This policy:
    /// - Allows toy suites (for testing)
    /// - Has no minimum security requirement
    ///
    /// Use this for devnet, local testing, and CI tests.
    pub fn dev_default() -> Self {
        SuitePolicy {
            allow_toy: true,
            min_security_bits: None,
        }
    }

    /// Create a production-grade policy.
    ///
    /// This policy:
    /// - Disallows toy suites (test-only suites are rejected)
    /// - Requires at least 128-bit security
    ///
    /// Use this for testnet and mainnet deployments.
    pub fn prod_default() -> Self {
        SuitePolicy {
            allow_toy: false,
            min_security_bits: Some(128),
        }
    }

    /// Create a custom policy with a specific minimum security requirement.
    ///
    /// # Arguments
    ///
    /// * `allow_toy` - Whether to allow toy suites.
    /// * `min_security_bits` - Minimum required security level in bits.
    pub fn new(allow_toy: bool, min_security_bits: Option<u16>) -> Self {
        SuitePolicy {
            allow_toy,
            min_security_bits,
        }
    }

    /// Builder method to set the minimum security bits.
    pub fn with_min_security_bits(mut self, bits: u16) -> Self {
        self.min_security_bits = Some(bits);
        self
    }

    /// Check if a transition from one suite to another is allowed under this policy.
    ///
    /// This implements the cross-epoch suite monotonicity rule:
    /// - Moving from weaker → stronger (or equal) is allowed.
    /// - Moving from stronger → weaker is rejected.
    /// - Moving from/to a toy suite is only allowed in dev policy; in prod policy it must be rejected.
    /// - Unknown suites are treated as having 0 security bits.
    ///
    /// # Arguments
    ///
    /// * `from_suite` - The suite ID used in the earlier epoch.
    /// * `to_suite` - The suite ID proposed for the later epoch.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the transition is allowed.
    /// * `Err(StartupValidationError::SuiteDowngradeAcrossEpochs)` if the transition is a downgrade.
    pub fn check_transition_allowed(
        &self,
        from_suite: ConsensusSigSuiteId,
        to_suite: ConsensusSigSuiteId,
    ) -> Result<(), StartupValidationError> {
        use cano_crypto::suite_catalog::{effective_security_bits, find_suite};

        // If suites are equal, transition is always allowed
        if from_suite == to_suite {
            return Ok(());
        }

        let from_info = find_suite(from_suite);
        let to_info = find_suite(to_suite);

        // Check toy suite restrictions
        if !self.allow_toy {
            if let Some(info) = from_info {
                if info.is_toy {
                    return Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
                        from_epoch: cano_consensus::validator_set::EpochId::new(0), // placeholder, will be filled by caller
                        to_epoch: cano_consensus::validator_set::EpochId::new(0),
                        from_suite,
                        to_suite,
                    });
                }
            }
            if let Some(info) = to_info {
                if info.is_toy {
                    return Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
                        from_epoch: cano_consensus::validator_set::EpochId::new(0), // placeholder, will be filled by caller
                        to_epoch: cano_consensus::validator_set::EpochId::new(0),
                        from_suite,
                        to_suite,
                    });
                }
            }
        }

        // In dev policy, allow transitions involving toy suites regardless of security bits
        if self.allow_toy {
            if let Some(info) = from_info {
                if info.is_toy {
                    // From toy suite: always allowed in dev
                    return Ok(());
                }
            }
            if let Some(info) = to_info {
                if info.is_toy {
                    // To toy suite: always allowed in dev
                    return Ok(());
                }
            }
        }

        // Compare effective security bits
        let from_bits = effective_security_bits(from_suite);
        let to_bits = effective_security_bits(to_suite);

        if to_bits >= from_bits {
            // Equal or stronger security: allowed
            Ok(())
        } else {
            // Weaker security: rejected
            Err(StartupValidationError::SuiteDowngradeAcrossEpochs {
                from_epoch: cano_consensus::validator_set::EpochId::new(0), // placeholder, will be filled by caller
                to_epoch: cano_consensus::validator_set::EpochId::new(0),
                from_suite,
                to_suite,
            })
        }
    }
}

impl Default for SuitePolicy {
    /// Default policy is `dev_default()` to avoid breaking existing tests.
    fn default() -> Self {
        SuitePolicy::dev_default()
    }
}

// ============================================================================
// ValidatorEnumerator trait
// ============================================================================

/// Trait for enumerating validators known to governance.
///
/// This trait extends `ConsensusKeyGovernance` to provide iteration over
/// all validators for which consensus keys are configured. This is needed
/// for startup validation to check that all governance-configured suites
/// have registered backends.
///
/// # Implementation Notes
///
/// For this task, it's acceptable to validate only the primary validator set
/// used by consensus. Future extensions may add more comprehensive enumeration.
pub trait ValidatorEnumerator: ConsensusKeyGovernance {
    /// Returns a list of validator IDs for which consensus keys are configured.
    ///
    /// This does not need to be exhaustive of all possible validators; it should
    /// include at least the active consensus validator set.
    fn list_validators(&self) -> Vec<u64>;
}

// ============================================================================
// ConsensusStartupValidator
// ============================================================================

/// Startup-time validator for consensus configuration consistency.
///
/// This struct validates at node startup that:
/// 1. All suite IDs referenced by governance have registered backends.
/// 2. Persisted state (if any) is readable and uses configured suites.
/// 3. (T111) All configured suites satisfy the `SuitePolicy`.
///
/// # Type Parameters
///
/// * `CG` - The governance type implementing both `ConsensusKeyGovernance`
///   and `ValidatorEnumerator`.
/// * `BR` - The backend registry type implementing `ConsensusSigBackendRegistry`.
/// * `CS` - The storage type implementing `ConsensusStorage`.
///
/// # Example
///
/// ```ignore
/// let validator = ConsensusStartupValidator::new(
///     governance.clone(),
///     backend_registry.clone(),
///     storage.clone(),
/// ).with_suite_policy(SuitePolicy::prod_default());
///
/// match validator.validate() {
///     Ok(()) => {
///         // Proceed with consensus startup
///     }
///     Err(e) => {
///         eprintln!("Startup validation failed: {}", e);
///         std::process::exit(1);
///     }
/// }
/// ```
pub struct ConsensusStartupValidator<CG, BR, CS: ?Sized> {
    governance: Arc<CG>,
    backend_registry: Arc<BR>,
    storage: Arc<CS>,
    suite_policy: SuitePolicy,
}

impl<CG, BR, CS: ?Sized> ConsensusStartupValidator<CG, BR, CS>
where
    CG: ValidatorEnumerator + Send + Sync,
    BR: ConsensusSigBackendRegistry + Send + Sync,
    CS: ConsensusStorage + Send + Sync,
{
    /// Create a new startup validator with default (dev) suite policy.
    ///
    /// # Arguments
    ///
    /// * `governance` - Governance implementation for looking up validator keys.
    /// * `backend_registry` - Registry mapping suite IDs to verifier backends.
    /// * `storage` - Storage backend for persisted consensus state.
    ///
    /// # Note
    ///
    /// The default suite policy is `SuitePolicy::dev_default()`, which allows
    /// toy suites. For production use, call `.with_suite_policy(SuitePolicy::prod_default())`.
    pub fn new(governance: Arc<CG>, backend_registry: Arc<BR>, storage: Arc<CS>) -> Self {
        ConsensusStartupValidator {
            governance,
            backend_registry,
            storage,
            suite_policy: SuitePolicy::dev_default(),
        }
    }

    /// Set the suite policy for validation.
    ///
    /// # Arguments
    ///
    /// * `policy` - The suite policy to use for validation.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let validator = ConsensusStartupValidator::new(
    ///     governance.clone(),
    ///     backend_registry.clone(),
    ///     storage.clone(),
    /// ).with_suite_policy(SuitePolicy::prod_default());
    /// ```
    pub fn with_suite_policy(mut self, policy: SuitePolicy) -> Self {
        self.suite_policy = policy;
        self
    }

    /// Get a reference to the current suite policy.
    pub fn suite_policy(&self) -> &SuitePolicy {
        &self.suite_policy
    }

    /// Validate the consensus configuration at startup.
    ///
    /// This method performs the following checks:
    ///
    /// 1. **Governance → Backends**: For each validator known to governance,
    ///    verify that the suite ID of their consensus key has a registered
    ///    backend in the backend registry.
    ///
    /// 2. **Storage → Backends**: If persisted state exists (last committed
    ///    block + QC), verify that their suite_id values have registered
    ///    backends and the data is decodable.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all checks pass.
    /// * `Err(StartupValidationError)` if any check fails.
    ///
    /// # Failure Modes
    ///
    /// * `MissingBackendForSuite` / `MissingBackendsForSuites`: A suite ID
    ///   referenced by governance has no registered backend.
    /// * `StorageInconsistent`: Persisted state is corrupted or uses an
    ///   unknown suite ID.
    pub fn validate(&self) -> Result<(), StartupValidationError> {
        // Step 1: Validate governance suites ↔ backends
        self.validate_governance_suites()?;

        // Step 2: Validate persisted state ↔ backends
        self.validate_persisted_state()?;

        Ok(())
    }

    /// Validate that all suite IDs referenced by governance have registered backends.
    fn validate_governance_suites(&self) -> Result<(), StartupValidationError> {
        let validator_ids = self.governance.list_validators();
        let mut missing_suites: HashSet<ConsensusSigSuiteId> = HashSet::new();

        for validator_id in validator_ids {
            if let Some((suite_id, _pk)) = self.governance.get_consensus_key(validator_id) {
                // Check if backend exists for this suite
                if self.backend_registry.get_backend(suite_id).is_none() {
                    missing_suites.insert(suite_id);
                }
            }
            // If get_consensus_key returns None, that's a governance issue,
            // but we don't treat it as a backend-missing error.
        }

        if missing_suites.is_empty() {
            Ok(())
        } else if missing_suites.len() == 1 {
            let suite_id = missing_suites.into_iter().next().unwrap();
            // Log clear error message
            eprintln!(
                "[startup_validation] ERROR: governance references suite {} \
                 but no consensus signature backend is registered for it",
                suite_id
            );
            Err(StartupValidationError::MissingBackendForSuite(suite_id))
        } else {
            let suites: Vec<ConsensusSigSuiteId> = missing_suites.into_iter().collect();
            // Log clear error message
            eprintln!(
                "[startup_validation] ERROR: governance references suites {:?} \
                 but no consensus signature backends are registered for them",
                suites.iter().map(|s| s.to_string()).collect::<Vec<_>>()
            );
            Err(StartupValidationError::MissingBackendsForSuites(suites))
        }
    }

    /// Validate that persisted state uses configured suites and is readable.
    fn validate_persisted_state(&self) -> Result<(), StartupValidationError> {
        // Check for last committed block
        let last_committed = self.storage.get_last_committed()?;

        let block_id = match last_committed {
            Some(id) => id,
            None => {
                // Fresh node - no persisted state to validate
                eprintln!("[startup_validation] No persisted state found - starting as fresh node");
                return Ok(());
            }
        };

        eprintln!(
            "[startup_validation] Found persisted state: last_committed={:?}",
            &block_id[..8]
        );

        // Load the block
        let block = self.storage.get_block(&block_id)?.ok_or_else(|| {
            StartupValidationError::StorageInconsistent(format!(
                "last_committed block_id {:?} not found in storage",
                &block_id[..8]
            ))
        })?;

        // Check block's suite_id has a backend
        let block_suite_id = ConsensusSigSuiteId::new(block.header.suite_id);
        if self.backend_registry.get_backend(block_suite_id).is_none() {
            eprintln!(
                "[startup_validation] ERROR: persisted block at height {} uses suite {} \
                 but no backend is registered for it",
                block.header.height, block_suite_id
            );
            return Err(StartupValidationError::MissingBackendForSuite(
                block_suite_id,
            ));
        }

        eprintln!(
            "[startup_validation] Validated block: height={}, suite_id={}",
            block.header.height, block_suite_id
        );

        // Load and validate the QC (if stored)
        if let Some(qc) = self.storage.get_qc(&block_id)? {
            let qc_suite_id = ConsensusSigSuiteId::new(qc.suite_id);
            if self.backend_registry.get_backend(qc_suite_id).is_none() {
                eprintln!(
                    "[startup_validation] ERROR: persisted QC at height {} uses suite {} \
                     but no backend is registered for it",
                    qc.height, qc_suite_id
                );
                return Err(StartupValidationError::MissingBackendForSuite(qc_suite_id));
            }

            eprintln!(
                "[startup_validation] Validated QC: height={}, suite_id={}",
                qc.height, qc_suite_id
            );
        }

        // Also check embedded QC in block if present
        if let Some(ref embedded_qc) = block.qc {
            let embedded_qc_suite_id = ConsensusSigSuiteId::new(embedded_qc.suite_id);
            if self
                .backend_registry
                .get_backend(embedded_qc_suite_id)
                .is_none()
            {
                eprintln!(
                    "[startup_validation] ERROR: embedded QC in persisted block uses suite {} \
                     but no backend is registered for it",
                    embedded_qc_suite_id
                );
                return Err(StartupValidationError::MissingBackendForSuite(
                    embedded_qc_suite_id,
                ));
            }

            eprintln!(
                "[startup_validation] Validated embedded QC: height={}, suite_id={}",
                embedded_qc.height, embedded_qc_suite_id
            );
        }

        Ok(())
    }

    /// Validate the epoch state against governance and backend registry.
    ///
    /// This method performs epoch-aware validation:
    /// 1. Every validator in the epoch has a governance-backed consensus key.
    /// 2. Every governance key uses a suite with a registered backend.
    /// 3. (T111) Every suite satisfies the current `SuitePolicy`.
    /// 4. (Optional) No stray keys exist in governance for non-epoch validators.
    ///
    /// # Arguments
    ///
    /// * `epoch_state` - The epoch state to validate.
    /// * `check_stray_keys` - If true, also check for governance keys that don't
    ///   correspond to any validator in the epoch.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if validation passes.
    /// * `Err(StartupValidationError)` if validation fails.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let epoch_state = EpochState::genesis(validator_set);
    ///
    /// let validator = ConsensusStartupValidator::new(
    ///     governance.clone(),
    ///     backend_registry.clone(),
    ///     storage.clone(),
    /// ).with_suite_policy(SuitePolicy::prod_default());
    ///
    /// // Validate epoch (with stray key check)
    /// validator.validate_epoch(&epoch_state, true)?;
    /// ```
    pub fn validate_epoch(
        &self,
        epoch_state: &cano_consensus::validator_set::EpochState,
        check_stray_keys: bool,
    ) -> Result<(), StartupValidationError> {
        // Create a suite checker using the backend registry
        let is_known_suite = |suite_id: cano_crypto::ConsensusSigSuiteId| {
            self.backend_registry.get_backend(suite_id).is_some()
        };

        // Validate epoch validators against governance
        if check_stray_keys {
            let gov_validator_ids = self.governance.list_validators();
            epoch_state
                .validate_with_governance_strict(
                    self.governance.as_ref(),
                    &gov_validator_ids,
                    is_known_suite,
                )
                .map_err(|e| Self::convert_epoch_error(e))?;
        } else {
            epoch_state
                .validate_with_governance(self.governance.as_ref(), is_known_suite)
                .map_err(|e| Self::convert_epoch_error(e))?;
        }

        // T115: Enforce single-suite-per-epoch invariant.
        // Collect all unique suite IDs used by validators in this epoch.
        let mut suite_ids_in_epoch: std::collections::HashSet<ConsensusSigSuiteId> =
            std::collections::HashSet::new();
        for entry in epoch_state.iter() {
            if let Some((suite_id, _pk)) = self.governance.get_consensus_key(entry.id.as_u64()) {
                suite_ids_in_epoch.insert(suite_id);
            }
        }
        // If more than one suite ID is present, reject the epoch.
        if suite_ids_in_epoch.len() > 1 {
            let suites: Vec<ConsensusSigSuiteId> = suite_ids_in_epoch.into_iter().collect();
            eprintln!(
                "[startup_validation] ERROR: epoch {:?} has mixed suites {:?}; \
                 single-suite-per-epoch invariant violated",
                epoch_state.epoch_id(),
                suites.iter().map(|s| s.to_string()).collect::<Vec<_>>()
            );
            return Err(StartupValidationError::MixedSuitesInEpoch {
                epoch_id: epoch_state.epoch_id(),
                suites,
            });
        }

        // T111: Validate each validator's suite against the policy
        for entry in epoch_state.iter() {
            let validator_id = entry.id;
            if let Some((suite_id, _pk)) = self.governance.get_consensus_key(validator_id.as_u64())
            {
                self.validate_suite_for_validator(validator_id, suite_id)?;
            }
        }

        eprintln!(
            "[startup_validation] Epoch {} validation passed: {} validators (policy: {:?})",
            epoch_state.epoch_id(),
            epoch_state.len(),
            self.suite_policy
        );

        Ok(())
    }

    /// Validate a single validator's suite against the current policy.
    ///
    /// This method checks that:
    /// 1. The suite is known (exists in `KNOWN_CONSENSUS_SIG_SUITES`).
    /// 2. The suite is not a toy suite if the policy disallows them.
    /// 3. The suite has sufficient security bits if the policy requires a minimum.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator whose suite is being validated.
    /// * `suite_id` - The consensus signature suite ID used by the validator.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if the suite passes all policy checks.
    /// * `Err(StartupValidationError)` if any check fails.
    fn validate_suite_for_validator(
        &self,
        validator_id: cano_consensus::ids::ValidatorId,
        suite_id: ConsensusSigSuiteId,
    ) -> Result<(), StartupValidationError> {
        use cano_crypto::suite_catalog::{find_suite, suite_name};

        // Look up the suite in the catalog
        let suite_info = match find_suite(suite_id) {
            Some(info) => info,
            None => {
                eprintln!(
                    "[startup_validation] ERROR: validator {:?} uses unknown suite {}",
                    validator_id, suite_id
                );
                return Err(StartupValidationError::UnknownSuiteForValidator {
                    validator_id,
                    suite_id: suite_id.as_u16(),
                });
            }
        };

        // Check toy suite policy
        if !self.suite_policy.allow_toy && suite_info.is_toy {
            eprintln!(
                "[startup_validation] ERROR: validator {:?} uses toy suite {} ('{}') \
                 which is not allowed under production policy",
                validator_id, suite_id, suite_info.name
            );
            return Err(StartupValidationError::ToySuiteNotAllowed {
                validator_id,
                suite_id: suite_id.as_u16(),
                suite_name: suite_info.name,
            });
        }

        // Check minimum security bits
        if let Some(required_bits) = self.suite_policy.min_security_bits {
            match suite_info.security_bits {
                Some(actual_bits) if actual_bits >= required_bits => {
                    // Suite meets minimum security requirement
                }
                Some(actual_bits) => {
                    eprintln!(
                        "[startup_validation] ERROR: validator {:?} uses suite {} ('{}') \
                         with {} security bits, but {} bits required",
                        validator_id, suite_id, suite_info.name, actual_bits, required_bits
                    );
                    return Err(StartupValidationError::InsufficientSecurityBits {
                        validator_id,
                        suite_id: suite_id.as_u16(),
                        suite_name: suite_info.name,
                        actual_bits: Some(actual_bits),
                        required_bits,
                    });
                }
                None if !suite_info.is_toy => {
                    // Non-toy suite with no security_bits: fail conservatively
                    eprintln!(
                        "[startup_validation] ERROR: validator {:?} uses suite {} ('{}') \
                         with unknown security level, but {} bits required",
                        validator_id, suite_id, suite_info.name, required_bits
                    );
                    return Err(StartupValidationError::InsufficientSecurityBits {
                        validator_id,
                        suite_id: suite_id.as_u16(),
                        suite_name: suite_info.name,
                        actual_bits: None,
                        required_bits,
                    });
                }
                None => {
                    // Toy suite with no security_bits: already handled by allow_toy check
                    // If we're here, allow_toy must be true, so we skip the security check
                }
            }
        }

        // Use suite_name to avoid unused warning (it's used for the catalog lookup)
        let _ = suite_name;

        Ok(())
    }

    /// Convert an EpochValidationError to a StartupValidationError.
    fn convert_epoch_error(
        err: cano_consensus::validator_set::EpochValidationError,
    ) -> StartupValidationError {
        use cano_consensus::validator_set::EpochValidationError;

        match err {
            EpochValidationError::MissingKey(id) => {
                eprintln!(
                    "[startup_validation] ERROR: validator {:?} in epoch has no consensus key",
                    id
                );
                StartupValidationError::MissingKeyForValidator(id)
            }
            EpochValidationError::UnknownSuite {
                validator_id,
                suite_id,
            } => {
                eprintln!(
                    "[startup_validation] ERROR: validator {:?} uses unknown suite {}",
                    validator_id, suite_id
                );
                StartupValidationError::UnknownSuiteForValidator {
                    validator_id,
                    suite_id,
                }
            }
            EpochValidationError::StrayKey(id) => {
                eprintln!(
                    "[startup_validation] ERROR: governance has key for validator {:?} not in epoch",
                    id
                );
                StartupValidationError::StrayGovernanceKey(id)
            }
            EpochValidationError::Other(msg) => {
                eprintln!(
                    "[startup_validation] ERROR: epoch validation failed: {}",
                    msg
                );
                StartupValidationError::Other(msg)
            }
        }
    }

    /// Full validation including epoch state.
    ///
    /// This method combines the existing validation with epoch validation:
    /// 1. Validate governance suites have registered backends.
    /// 2. Validate persisted state uses registered suites.
    /// 3. Validate epoch state against governance.
    ///
    /// # Arguments
    ///
    /// * `epoch_state` - The epoch state to validate.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all validation passes.
    /// * `Err(StartupValidationError)` if any validation fails.
    pub fn validate_with_epoch(
        &self,
        epoch_state: &cano_consensus::validator_set::EpochState,
    ) -> Result<(), StartupValidationError> {
        // Step 1: Original validation (governance suites + persisted state)
        self.validate()?;

        // Step 2: Epoch validation (with stray key check)
        self.validate_epoch(epoch_state, true)?;

        Ok(())
    }

    /// Validate cross-epoch suite monotonicity for a sequence of epochs.
    ///
    /// This method validates that epoch N+1 does not use a weaker suite than epoch N
    /// under the current policy. It enforces the "no downgrade across epochs" rule.
    ///
    /// # Arguments
    ///
    /// * `epochs` - An ordered sequence of epoch states (earliest to latest).
    /// * `metrics` - Optional metrics for recording suite transitions.
    ///
    /// # Returns
    ///
    /// * `Ok(())` if all transitions are allowed (equal or stronger security).
    /// * `Err(StartupValidationError::SuiteDowngradeAcrossEpochs)` if any transition
    ///   is a downgrade.
    ///
    /// # Notes
    ///
    /// - Single epoch or empty sequence: validation succeeds trivially.
    /// - Gapped epoch IDs: validation proceeds based on the order provided.
    /// - Unknown suites are treated as having 0 security bits.
    pub fn validate_epoch_sequence(
        &self,
        epochs: &[cano_consensus::validator_set::EpochState],
        metrics: Option<&crate::metrics::SuiteTransitionMetrics>,
    ) -> Result<(), StartupValidationError> {
        use cano_crypto::suite_catalog::{effective_security_bits, suite_name};

        if epochs.len() <= 1 {
            // Single epoch or empty sequence: nothing to compare
            return Ok(());
        }

        // Helper to get the suite ID for an epoch
        let get_epoch_suite =
            |epoch: &cano_consensus::validator_set::EpochState| -> Option<ConsensusSigSuiteId> {
                let mut suite_ids = std::collections::HashSet::new();
                for entry in epoch.iter() {
                    if let Some((suite_id, _pk)) =
                        self.governance.get_consensus_key(entry.id.as_u64())
                    {
                        suite_ids.insert(suite_id);
                    }
                }
                // According to T115, epochs should be single-suite, so we expect at most one
                if suite_ids.len() == 1 {
                    suite_ids.into_iter().next()
                } else {
                    // Mixed suites or no validators with keys
                    None
                }
            };

        // Iterate through adjacent pairs
        for i in 0..epochs.len() - 1 {
            let epoch_n = &epochs[i];
            let epoch_n1 = &epochs[i + 1];

            let from_epoch_id = epoch_n.epoch_id();
            let to_epoch_id = epoch_n1.epoch_id();

            let from_suite = match get_epoch_suite(epoch_n) {
                Some(suite) => suite,
                None => {
                    // Couldn't determine suite for epoch N
                    // This might happen if epoch has no validators or mixed suites
                    // We'll skip validation for this pair
                    continue;
                }
            };

            let to_suite = match get_epoch_suite(epoch_n1) {
                Some(suite) => suite,
                None => {
                    // Couldn't determine suite for epoch N+1
                    continue;
                }
            };

            // Check if transition is allowed
            if let Err(mut err) = self
                .suite_policy
                .check_transition_allowed(from_suite, to_suite)
            {
                // Fill in the epoch IDs in the error
                if let StartupValidationError::SuiteDowngradeAcrossEpochs {
                    ref mut from_epoch,
                    ref mut to_epoch,
                    ..
                } = err
                {
                    *from_epoch = from_epoch_id;
                    *to_epoch = to_epoch_id;
                }

                // Log the downgrade attempt
                let from_bits = effective_security_bits(from_suite);
                let to_bits = effective_security_bits(to_suite);
                let from_name = suite_name(from_suite);
                let to_name = suite_name(to_suite);

                eprintln!(
                    "[startup_validation] ERROR: Suite downgrade detected from epoch {} to {}: \
                     {} ({} bits) → {} ({} bits)",
                    from_epoch_id, to_epoch_id, from_name, from_bits, to_name, to_bits
                );

                // Record rejected transition in metrics
                if let Some(m) = metrics {
                    m.record_rejected();
                }

                return Err(err);
            }

            // Record allowed transition in metrics (if suites differ)
            if from_suite != to_suite {
                if let Some(m) = metrics {
                    m.record_ok();
                }

                // Log allowed transition
                let from_bits = effective_security_bits(from_suite);
                let to_bits = effective_security_bits(to_suite);
                let from_name = suite_name(from_suite);
                let to_name = suite_name(to_suite);

                eprintln!(
                    "[startup_validation] INFO: Suite transition from epoch {} to {}: \
                     {} ({} bits) → {} ({} bits) - allowed",
                    from_epoch_id, to_epoch_id, from_name, from_bits, to_name, to_bits
                );
            }
        }

        Ok(())
    }
}

impl<CG, BR, CS: ?Sized> std::fmt::Debug for ConsensusStartupValidator<CG, BR, CS> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConsensusStartupValidator")
            .field("governance", &"<ValidatorEnumerator>")
            .field("backend_registry", &"<ConsensusSigBackendRegistry>")
            .field("storage", &"<ConsensusStorage>")
            .finish()
    }
}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    //! Unit tests for ConsensusStartupValidator.
    //!
    //! These tests use in-src #[cfg(test)] because they need to access
    //! internal test helpers and validate private implementation details.
    //!
    //! More comprehensive integration tests are in tests/startup_validation_tests.rs.

    use super::*;

    #[test]
    fn startup_validation_error_display_missing_backend() {
        let err = StartupValidationError::MissingBackendForSuite(ConsensusSigSuiteId::new(42));
        let msg = err.to_string();
        assert!(msg.contains("suite_42"));
        assert!(msg.contains("no consensus signature backend registered"));
    }

    #[test]
    fn startup_validation_error_display_multiple_missing() {
        let err = StartupValidationError::MissingBackendsForSuites(vec![
            ConsensusSigSuiteId::new(1),
            ConsensusSigSuiteId::new(2),
        ]);
        let msg = err.to_string();
        assert!(msg.contains("suite_1"));
        assert!(msg.contains("suite_2"));
        assert!(msg.contains("governance references these suites"));
    }

    #[test]
    fn startup_validation_error_display_storage_inconsistent() {
        let err = StartupValidationError::StorageInconsistent("block not found".to_string());
        let msg = err.to_string();
        assert!(msg.contains("block not found"));
        assert!(msg.contains("inconsistent or corrupted"));
    }

    #[test]
    fn startup_validation_error_display_missing_key_for_validator() {
        use cano_consensus::ids::ValidatorId;
        let err = StartupValidationError::MissingKeyForValidator(ValidatorId::new(42));
        let msg = err.to_string();
        assert!(msg.contains("42"));
        assert!(msg.contains("no consensus key"));
    }

    #[test]
    fn startup_validation_error_display_unknown_suite_for_validator() {
        use cano_consensus::ids::ValidatorId;
        let err = StartupValidationError::UnknownSuiteForValidator {
            validator_id: ValidatorId::new(5),
            suite_id: 99,
        };
        let msg = err.to_string();
        assert!(msg.contains("5"));
        assert!(msg.contains("99"));
        assert!(msg.contains("unknown signature suite"));
    }

    #[test]
    fn startup_validation_error_display_stray_governance_key() {
        use cano_consensus::ids::ValidatorId;
        let err = StartupValidationError::StrayGovernanceKey(ValidatorId::new(100));
        let msg = err.to_string();
        assert!(msg.contains("100"));
        assert!(msg.contains("not in the current epoch"));
    }
}
