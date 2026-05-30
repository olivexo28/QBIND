//! Run 159 — typed pure transition validator for the v2 bundle-signing-key
//! lifecycle.
//!
//! Scope: source/test only. Run 159 does not enable MainNet peer-driven
//! apply, governance, KMS/HSM, or validator-set rotation. No release-binary
//! evidence is captured in this run; release-binary lifecycle evidence is
//! deferred to Run 160.
//!
//! ## Lifecycle actions pinned by Run 159
//!
//! The on-wire `BundleSigningRatificationV2Action` byte (Run 130) encodes
//! only `Ratify (0)`, `Rotate (1)`, `Revoke (2)`. Run 159 does **not**
//! introduce a new wire format; it pins these three wire bytes onto the
//! five logical lifecycle actions required by the local authority-state
//! machine:
//!
//! | local action       | wire action | persisted shape & metadata convention |
//! | ------------------ | ----------- | ------------------------------------- |
//! | `ActivateInitial`  | `Ratify`    | persisted marker is `None` (genesis-bound first activation) |
//! | `Rotate`           | `Rotate`    | candidate carries `previous_bundle_signing_key_fingerprint == persisted.active` |
//! | `Retire`           | `Revoke`    | `revoked_key_metadata` first 2 hex chars (1 byte) = `02` |
//! | `Revoke`           | `Revoke`    | `revoked_key_metadata` first 2 hex chars (1 byte) = `01` |
//! | `EmergencyRevoke`  | `Revoke`    | `revoked_key_metadata` first 2 hex chars (1 byte) = `03` |
//!
//! The metadata sub-class prefix is a **local interpretation** of the
//! existing optional lowercase-hex `revoked_key_metadata` field validated
//! by [`PersistentAuthorityStateRecordV2::validate_structure`]. No new
//! wire schema, no new sequence-file schema, no trust-bundle schema
//! change, and no authority-marker schema change is introduced.
//!
//! ## Bindings
//!
//! Every accepted lifecycle transition is bound to:
//!
//! * environment;
//! * chain_id;
//! * genesis_hash;
//! * authority_root_fingerprint and authority_root_suite_id;
//! * active bundle-signing key fingerprint and suite_id;
//! * authority-domain sequence (strictly monotonic for non-idempotent
//!   transitions; same sequence + identical record is idempotent; same
//!   sequence + different digest/binding is rejected as equivocation);
//! * the on-wire lifecycle action byte and its local sub-class.
//!
//! ## Pure / typed
//!
//! [`validate_v2_lifecycle_transition`] performs **no I/O**, never writes
//! the sequence file, never mutates a live trust bundle, and preserves
//! local marker bytes on every rejected transition (the caller still owns
//! the persisted bytes — the validator does not touch them). All
//! mutating-surface composition continues to flow through the existing
//! Run 134 / 136 / 138 / 150 / 152 helpers; Run 159 only adds typed
//! pre-flight transition validation that those helpers may consult or
//! reuse in future runs.

use serde::{Deserialize, Serialize};

use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_ledger::bundle_signing_ratification::BundleSigningRatificationV2Action;

/// PQC suite ID required for Run 159 lifecycle transitions
/// (mirrors `qbind_ledger::GENESIS_AUTHORITY_SUITE_ML_DSA_44`).
pub const PQC_LIFECYCLE_SUITE_ML_DSA_44: u8 = 100;

/// Returns `true` iff `suite_id` is one of the PQC suite IDs accepted
/// by the Run 159 lifecycle validator.
pub fn is_pqc_lifecycle_suite(suite_id: u8) -> bool {
    suite_id == PQC_LIFECYCLE_SUITE_ML_DSA_44
}

/// Run 159 metadata sub-class prefix — standard revocation.
pub const REVOKED_METADATA_PREFIX_REVOKE: &str = "01";
/// Run 159 metadata sub-class prefix — retirement (no emergency semantics).
pub const REVOKED_METADATA_PREFIX_RETIRE: &str = "02";
/// Run 159 metadata sub-class prefix — emergency revocation.
pub const REVOKED_METADATA_PREFIX_EMERGENCY: &str = "03";

/// Local sub-classification of v2 lifecycle actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LocalLifecycleAction {
    ActivateInitial,
    Rotate,
    Retire,
    Revoke,
    EmergencyRevoke,
}

impl LocalLifecycleAction {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::ActivateInitial => "activate-initial",
            Self::Rotate => "rotate",
            Self::Retire => "retire",
            Self::Revoke => "revoke",
            Self::EmergencyRevoke => "emergency-revoke",
        }
    }
}

/// Authority trust domain that every lifecycle transition is bound to.
///
/// The fields mirror the binding required by the Run 130 v2 verifier and
/// the Run 131/134/136/138/150/152 marker comparison primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityTrustDomain {
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,
}

impl AuthorityTrustDomain {
    pub fn new(
        environment: TrustBundleEnvironment,
        chain_id: impl Into<String>,
        genesis_hash: impl Into<String>,
        authority_root_fingerprint: impl Into<String>,
        authority_root_suite_id: u8,
    ) -> Self {
        Self {
            environment,
            chain_id: chain_id.into(),
            genesis_hash: genesis_hash.into(),
            authority_root_fingerprint: authority_root_fingerprint.into(),
            authority_root_suite_id,
        }
    }
}

/// Typed outcome of [`validate_v2_lifecycle_transition`].
///
/// Reject variants carry the data required to emit a precise operator
/// log line. The caller MUST NOT advance authority state on any reject
/// variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityLifecycleTransitionOutcome {
    InitialActivationAccepted,
    RotationAccepted {
        previous_sequence: u64,
        new_sequence: u64,
        retired_predecessor_fingerprint: String,
    },
    RetirementAccepted {
        retired_key_fingerprint: String,
        previous_sequence: u64,
        new_sequence: u64,
    },
    RevocationAccepted {
        revoked_key_fingerprint: String,
        previous_sequence: u64,
        new_sequence: u64,
    },
    EmergencyRevocationAccepted {
        revoked_key_fingerprint: String,
        previous_sequence: u64,
        new_sequence: u64,
    },
    Idempotent {
        sequence: u64,
    },
    LowerSequenceRejected {
        persisted_sequence: u64,
        candidate_sequence: u64,
    },
    SameSequenceConflictingDigestRejected {
        sequence: u64,
        persisted_digest: String,
        candidate_digest: String,
    },
    WrongEnvironmentRejected {
        expected_environment: TrustBundleEnvironment,
        candidate_environment: TrustBundleEnvironment,
    },
    WrongChainRejected {
        expected_chain_id: String,
        candidate_chain_id: String,
    },
    WrongGenesisRejected {
        expected_genesis_hash: String,
        candidate_genesis_hash: String,
    },
    WrongAuthorityRootRejected {
        expected_authority_root: String,
        candidate_authority_root: String,
    },
    WrongPreviousKeyRejected {
        persisted_active_key: String,
        candidate_previous_key: String,
    },
    RevokedKeyReuseRejected {
        revoked_key_fingerprint: String,
    },
    RetiredKeyReuseRejected {
        retired_key_fingerprint: String,
    },
    UnsupportedLifecycleActionRejected {
        reason: String,
    },
    MalformedRevokedMetadataRejected {
        reason: String,
    },
    NonPqcSuiteRejected {
        suite_id: u8,
        field: &'static str,
    },
    StructurallyMalformedRejected {
        reason: String,
    },
    InitialActivationAfterPersistedRejected,
    V1PersistedV2CandidateNotSupportedHere,
}

impl AuthorityLifecycleTransitionOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::InitialActivationAccepted
                | Self::RotationAccepted { .. }
                | Self::RetirementAccepted { .. }
                | Self::RevocationAccepted { .. }
                | Self::EmergencyRevocationAccepted { .. }
                | Self::Idempotent { .. }
        )
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Classify a candidate v2 marker into its local lifecycle action.
///
/// Errors are returned as fully-formed [`AuthorityLifecycleTransitionOutcome`]
/// reject variants so the caller can return them directly.
pub fn classify_local_lifecycle_action(
    persisted_v2: Option<&PersistentAuthorityStateRecordV2>,
    candidate: &PersistentAuthorityStateRecordV2,
) -> Result<LocalLifecycleAction, AuthorityLifecycleTransitionOutcome> {
    match candidate.latest_lifecycle_action {
        BundleSigningRatificationV2Action::Ratify => {
            if persisted_v2.is_some() {
                return Err(AuthorityLifecycleTransitionOutcome::InitialActivationAfterPersistedRejected);
            }
            Ok(LocalLifecycleAction::ActivateInitial)
        }
        BundleSigningRatificationV2Action::Rotate => Ok(LocalLifecycleAction::Rotate),
        BundleSigningRatificationV2Action::Revoke => {
            let metadata = candidate.revoked_key_metadata.as_ref().ok_or_else(|| {
                AuthorityLifecycleTransitionOutcome::MalformedRevokedMetadataRejected {
                    reason: "v2 revoke marker requires revoked_key_metadata".to_string(),
                }
            })?;
            if metadata.len() < 2 {
                return Err(
                    AuthorityLifecycleTransitionOutcome::MalformedRevokedMetadataRejected {
                        reason: "revoked_key_metadata too short to carry sub-class prefix"
                            .to_string(),
                    },
                );
            }
            let prefix = &metadata[..2];
            match prefix {
                REVOKED_METADATA_PREFIX_REVOKE => Ok(LocalLifecycleAction::Revoke),
                REVOKED_METADATA_PREFIX_RETIRE => Ok(LocalLifecycleAction::Retire),
                REVOKED_METADATA_PREFIX_EMERGENCY => Ok(LocalLifecycleAction::EmergencyRevoke),
                other => Err(
                    AuthorityLifecycleTransitionOutcome::MalformedRevokedMetadataRejected {
                        reason: format!(
                            "unknown lifecycle sub-class prefix '{}' (expected {} / {} / {})",
                            other,
                            REVOKED_METADATA_PREFIX_REVOKE,
                            REVOKED_METADATA_PREFIX_RETIRE,
                            REVOKED_METADATA_PREFIX_EMERGENCY,
                        ),
                    },
                ),
            }
        }
    }
}

/// Pure typed v2 lifecycle transition validator.
///
/// Performs no I/O. Never mutates the persisted record. Local marker
/// bytes are preserved on every reject variant — the validator does not
/// touch the persisted file at all.
pub fn validate_v2_lifecycle_transition(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
) -> AuthorityLifecycleTransitionOutcome {
    use AuthorityLifecycleTransitionOutcome as O;

    if let Err(e) = candidate.validate_structure() {
        return O::StructurallyMalformedRejected {
            reason: e.to_string(),
        };
    }

    // ---- Trust-domain binding ----------------------------------------------
    if candidate.environment != trust_domain.environment {
        return O::WrongEnvironmentRejected {
            expected_environment: trust_domain.environment,
            candidate_environment: candidate.environment,
        };
    }
    if candidate.chain_id != trust_domain.chain_id {
        return O::WrongChainRejected {
            expected_chain_id: trust_domain.chain_id.clone(),
            candidate_chain_id: candidate.chain_id.clone(),
        };
    }
    if candidate.genesis_hash != trust_domain.genesis_hash {
        return O::WrongGenesisRejected {
            expected_genesis_hash: trust_domain.genesis_hash.clone(),
            candidate_genesis_hash: candidate.genesis_hash.clone(),
        };
    }
    if candidate.authority_root_fingerprint != trust_domain.authority_root_fingerprint {
        return O::WrongAuthorityRootRejected {
            expected_authority_root: trust_domain.authority_root_fingerprint.clone(),
            candidate_authority_root: candidate.authority_root_fingerprint.clone(),
        };
    }
    if candidate.authority_root_suite_id != trust_domain.authority_root_suite_id {
        return O::WrongAuthorityRootRejected {
            expected_authority_root: trust_domain.authority_root_fingerprint.clone(),
            candidate_authority_root: candidate.authority_root_fingerprint.clone(),
        };
    }

    // ---- PQC suite enforcement ---------------------------------------------
    if !is_pqc_lifecycle_suite(candidate.authority_root_suite_id) {
        return O::NonPqcSuiteRejected {
            suite_id: candidate.authority_root_suite_id,
            field: "authority_root_suite_id",
        };
    }
    if !is_pqc_lifecycle_suite(candidate.active_bundle_signing_key_suite_id) {
        return O::NonPqcSuiteRejected {
            suite_id: candidate.active_bundle_signing_key_suite_id,
            field: "active_bundle_signing_key_suite_id",
        };
    }

    // ---- Resolve the persisted marker --------------------------------------
    let persisted_v2 = match persisted {
        None => None,
        Some(PersistentAuthorityStateRecordVersioned::V2(v)) => {
            if let Err(e) = v.validate_structure() {
                return O::StructurallyMalformedRejected {
                    reason: format!("persisted v2 marker malformed: {}", e),
                };
            }
            Some(v)
        }
        Some(PersistentAuthorityStateRecordVersioned::V1(_)) => {
            // Run 159 explicitly does not perform v1->v2 lifecycle migration;
            // the existing Run 131 `migrate_authority_marker_v1_to_v2`
            // primitive remains the authoritative path for that case.
            return O::V1PersistedV2CandidateNotSupportedHere;
        }
    };

    // ---- Idempotency short-circuit -----------------------------------------
    // A bit-for-bit identical re-presentation of the persisted v2 record is
    // accepted as idempotent regardless of the local sub-class (this also
    // lets a re-applied initial Ratify pass through cleanly).
    if let Some(prev) = persisted_v2 {
        if candidate == prev {
            return O::Idempotent {
                sequence: prev.latest_authority_domain_sequence,
            };
        }
    }

    // ---- Local sub-classification ------------------------------------------
    let action = match classify_local_lifecycle_action(persisted_v2, candidate) {
        Ok(a) => a,
        Err(rej) => return rej,
    };

    match (persisted_v2, action) {
        // ===== No prior marker =============================================
        (None, LocalLifecycleAction::ActivateInitial) => O::InitialActivationAccepted,
        (None, _) => O::UnsupportedLifecycleActionRejected {
            reason: format!(
                "lifecycle action '{}' requires a persisted authority marker; only ActivateInitial is permitted at first-write",
                action.tag()
            ),
        },

        // ===== Prior marker present ========================================
        (Some(prev), action) => {
            if candidate.latest_authority_domain_sequence < prev.latest_authority_domain_sequence {
                return O::LowerSequenceRejected {
                    persisted_sequence: prev.latest_authority_domain_sequence,
                    candidate_sequence: candidate.latest_authority_domain_sequence,
                };
            }
            if candidate.latest_authority_domain_sequence == prev.latest_authority_domain_sequence
            {
                // Idempotency was already short-circuited above; reaching this
                // arm with equal sequence means the records differ in some
                // binding field — that is an equivocation.
                return O::SameSequenceConflictingDigestRejected {
                    sequence: prev.latest_authority_domain_sequence,
                    persisted_digest: prev.latest_ratification_v2_digest.clone(),
                    candidate_digest: candidate.latest_ratification_v2_digest.clone(),
                };
            }

            // Strictly higher sequence — apply per-action rules.
            match action {
                LocalLifecycleAction::ActivateInitial => O::UnsupportedLifecycleActionRejected {
                    reason: "ActivateInitial is only valid when no prior marker exists".into(),
                },
                LocalLifecycleAction::Rotate => {
                    let cand_prev_key =
                        match candidate.previous_bundle_signing_key_fingerprint.as_ref() {
                            Some(p) => p,
                            None => {
                                return O::WrongPreviousKeyRejected {
                                    persisted_active_key: prev
                                        .active_bundle_signing_key_fingerprint
                                        .clone(),
                                    candidate_previous_key: String::new(),
                                };
                            }
                        };
                    if cand_prev_key != &prev.active_bundle_signing_key_fingerprint {
                        return O::WrongPreviousKeyRejected {
                            persisted_active_key: prev
                                .active_bundle_signing_key_fingerprint
                                .clone(),
                            candidate_previous_key: cand_prev_key.clone(),
                        };
                    }
                    if let Some(rej) = check_active_key_not_revoked_or_retired(prev, candidate) {
                        return rej;
                    }
                    O::RotationAccepted {
                        previous_sequence: prev.latest_authority_domain_sequence,
                        new_sequence: candidate.latest_authority_domain_sequence,
                        retired_predecessor_fingerprint: prev
                            .active_bundle_signing_key_fingerprint
                            .clone(),
                    }
                }
                LocalLifecycleAction::Retire => {
                    if candidate.active_bundle_signing_key_fingerprint
                        != prev.active_bundle_signing_key_fingerprint
                    {
                        return O::UnsupportedLifecycleActionRejected {
                            reason:
                                "Retire must preserve the persisted active key (audit-only transition)"
                                    .into(),
                        };
                    }
                    let retired_fp = retired_or_revoked_target_fp(candidate);
                    O::RetirementAccepted {
                        retired_key_fingerprint: retired_fp,
                        previous_sequence: prev.latest_authority_domain_sequence,
                        new_sequence: candidate.latest_authority_domain_sequence,
                    }
                }
                LocalLifecycleAction::Revoke => {
                    if let Some(rej) = check_active_key_not_revoked_or_retired(prev, candidate) {
                        return rej;
                    }
                    let revoked_fp = retired_or_revoked_target_fp(candidate);
                    O::RevocationAccepted {
                        revoked_key_fingerprint: revoked_fp,
                        previous_sequence: prev.latest_authority_domain_sequence,
                        new_sequence: candidate.latest_authority_domain_sequence,
                    }
                }
                LocalLifecycleAction::EmergencyRevoke => {
                    if let Some(rej) = check_active_key_not_revoked_or_retired(prev, candidate) {
                        return rej;
                    }
                    let revoked_fp = retired_or_revoked_target_fp(candidate);
                    O::EmergencyRevocationAccepted {
                        revoked_key_fingerprint: revoked_fp,
                        previous_sequence: prev.latest_authority_domain_sequence,
                        new_sequence: candidate.latest_authority_domain_sequence,
                    }
                }
            }
        }
    }
}

/// Extract the revoked/retired target fingerprint from the metadata field
/// (everything after the 2-character sub-class prefix).
fn retired_or_revoked_target_fp(candidate: &PersistentAuthorityStateRecordV2) -> String {
    candidate
        .revoked_key_metadata
        .as_ref()
        .and_then(|m| m.get(2..))
        .unwrap_or("")
        .to_string()
}

fn metadata_subclass_prefix(record: &PersistentAuthorityStateRecordV2) -> Option<&str> {
    record
        .revoked_key_metadata
        .as_ref()
        .and_then(|m| m.get(..2))
}

/// If the persisted state shows the candidate's prospective active key
/// has already been revoked or retired, reject reuse.
fn check_active_key_not_revoked_or_retired(
    prev: &PersistentAuthorityStateRecordV2,
    candidate: &PersistentAuthorityStateRecordV2,
) -> Option<AuthorityLifecycleTransitionOutcome> {
    if prev.latest_lifecycle_action != BundleSigningRatificationV2Action::Revoke {
        return None;
    }
    let target = retired_or_revoked_target_fp(prev);
    if target.is_empty() || target != candidate.active_bundle_signing_key_fingerprint {
        return None;
    }
    let prefix = metadata_subclass_prefix(prev).unwrap_or("");
    Some(if prefix == REVOKED_METADATA_PREFIX_RETIRE {
        AuthorityLifecycleTransitionOutcome::RetiredKeyReuseRejected {
            retired_key_fingerprint: target,
        }
    } else {
        AuthorityLifecycleTransitionOutcome::RevokedKeyReuseRejected {
            revoked_key_fingerprint: target,
        }
    })
}