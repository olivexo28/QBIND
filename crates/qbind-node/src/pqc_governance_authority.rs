//! Run 163 — typed pure governance ratification authority verifier for v2
//! bundle-signing-key lifecycle transitions.
//!
//! ## Strict scope
//!
//! Source/test only. Run 163 does **not**:
//!
//! * enable MainNet peer-driven apply,
//! * implement a governance execution engine,
//! * implement on-chain governance integration,
//! * implement KMS/HSM custody,
//! * implement validator-set rotation,
//! * mutate any live trust state,
//! * write a v2 marker, sequence file, or trust bundle,
//! * accept peer-majority / gossip-count as an authority proof,
//! * accept local operator config alone as a MainNet authority proof.
//!
//! Release-binary governance verifier evidence is **deferred to Run 164**.
//!
//! ## Module purpose
//!
//! This module defines and validates the local proof object that, in a
//! future run, can authorize MainNet/TestNet governance-controlled
//! bundle-signing-key lifecycle transitions. The verifier is **pure and
//! non-mutating**: it performs no I/O, never reads or writes a sequence
//! file, never touches the persisted v2 marker, and never mutates a live
//! trust bundle. It only inspects the candidate v2 record, the local
//! governance authority proof, and the expected trust domain, returning a
//! typed [`GovernanceAuthorityVerificationOutcome`].
//!
//! ## Authority classes
//!
//! The verifier models three authority classes:
//!
//! 1. [`GovernanceAuthorityClass::GenesisBound`] — proof chains to a
//!    genesis-bound bundle-signing authority root. Valid for DevNet/
//!    TestNet fixtures, future MainNet-compatible, but does **not**
//!    enable MainNet apply.
//! 2. [`GovernanceAuthorityClass::EmergencyCouncil`] — proof represents
//!    emergency revocation authority. Must be domain-bound and must NOT
//!    bypass signature, genesis, chain, environment, or sequence checks.
//! 3. [`GovernanceAuthorityClass::OnChainGovernance`] — placeholder. No
//!    on-chain proof format exists yet, so this class is **explicitly
//!    fail-closed** as [`GovernanceAuthorityVerificationOutcome::
//!    UnsupportedOnChainGovernance`].
//!
//! ## Proof shape
//!
//! [`GovernanceAuthorityProof`] carries every binding required by the
//! Run 130 v2 verifier and the Run 159 lifecycle validator, plus an
//! issuer-side authority class, suite ID, signature byte string, and an
//! optional governance threshold descriptor. The signature itself is
//! verified through a typed [`GovernanceIssuerSignatureVerifier`] hook
//! so that source/test fixtures can supply a deterministic checker
//! today and a real PQC signature verifier in a future run **without**
//! changing the verifier's typed surface or its outcome enum.
//!
//! Run 163 does **not** introduce a new wire format. The fields of
//! [`GovernanceAuthorityProof`] are sufficient to represent the genesis-
//! bound and emergency-council classes; the on-chain governance class is
//! deliberately fail-closed pending an explicit on-chain proof schema in
//! a future run. If a future run determines that the existing v2
//! ratification proof fields are insufficient, that run is the one that
//! must extend the wire format — Run 163 does not silently invent a
//! schema.
//!
//! ## Integration boundary
//!
//! Run 163 is **NOT** wired into mutating apply surfaces. The pure
//! integration helper [`validate_lifecycle_with_governance_authority`]
//! composes the Run 159 lifecycle validator with the governance
//! authority verifier into a single non-mutating typed decision. It
//! performs no I/O, writes no marker, writes no sequence, and mutates
//! no live trust state.

use crate::pqc_authority_lifecycle::{
    is_pqc_lifecycle_suite, validate_v2_lifecycle_transition,
    AuthorityLifecycleTransitionOutcome, AuthorityTrustDomain, LocalLifecycleAction,
    PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;
use qbind_ledger::bundle_signing_ratification::BundleSigningRatificationV2Action;

/// Issuer authority class carried by a [`GovernanceAuthorityProof`].
///
/// The class declares which trust model the proof claims membership in;
/// the verifier still enforces every binding (environment, chain,
/// genesis, authority root, lifecycle action, candidate digest, sequence,
/// signature, suite) regardless of the declared class. The class only
/// shapes the accept variant returned on success and gates which
/// lifecycle actions are permissible for that class (for example,
/// [`GovernanceAuthorityClass::EmergencyCouncil`] only authorizes
/// `EmergencyRevoke`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceAuthorityClass {
    /// Proof chains to a genesis-bound bundle-signing authority root.
    /// Valid for DevNet/TestNet fixtures and future MainNet-compatible.
    /// Does **not** enable MainNet apply.
    GenesisBound,
    /// Proof represents emergency revocation authority. Domain-bound;
    /// must not bypass signature, genesis, chain, environment, or
    /// sequence checks.
    EmergencyCouncil,
    /// Placeholder for on-chain governance proofs. No proof format
    /// exists yet; the verifier rejects with
    /// [`GovernanceAuthorityVerificationOutcome::UnsupportedOnChainGovernance`].
    OnChainGovernance,
}

impl GovernanceAuthorityClass {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::GenesisBound => "genesis-bound",
            Self::EmergencyCouncil => "emergency-council",
            Self::OnChainGovernance => "on-chain-governance",
        }
    }
}

/// PQC issuer suite IDs accepted by Run 163.
///
/// Mirrors [`PQC_LIFECYCLE_SUITE_ML_DSA_44`]. Any other suite ID is
/// rejected as either non-PQC or unsupported.
pub const PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44: u8 = PQC_LIFECYCLE_SUITE_ML_DSA_44;

/// Returns `true` iff `suite_id` is the single PQC issuer suite Run 163
/// accepts as a governance-authority issuer signature suite.
pub fn is_pqc_governance_issuer_suite(suite_id: u8) -> bool {
    suite_id == PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44
}

/// A small, well-known set of non-PQC suite IDs the verifier explicitly
/// rejects with [`GovernanceAuthorityVerificationOutcome::NonPqcSuiteRejected`]
/// instead of the more generic
/// [`GovernanceAuthorityVerificationOutcome::UnsupportedIssuerSuite`].
///
/// These values match the legacy non-PQC tags used elsewhere in the
/// codebase for rejection-test fixtures (`Ed25519`, `Secp256k1`,
/// `RsaPss`). Source/test only — there is no live non-PQC verifier.
const NON_PQC_SUITE_IDS: &[u8] = &[1, 2, 3];

fn is_known_non_pqc_suite(suite_id: u8) -> bool {
    NON_PQC_SUITE_IDS.contains(&suite_id)
}

/// Optional governance threshold descriptor.
///
/// Run 163 source/test only. Threshold metadata is representable as
/// `(approvals, required, total)` where `approvals >= required` is the
/// minimum representable accept condition. If the threshold descriptor
/// is `None` the verifier does not enforce a threshold (genesis-bound
/// single-issuer fixtures); if it is `Some`, the verifier rejects with
/// [`GovernanceAuthorityVerificationOutcome::ThresholdNotMet`] when the
/// threshold is unmet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceThreshold {
    pub approvals: u32,
    pub required: u32,
    pub total: u32,
}

impl GovernanceThreshold {
    pub fn new(approvals: u32, required: u32, total: u32) -> Self {
        Self {
            approvals,
            required,
            total,
        }
    }

    /// Structural validation. The threshold is well-formed iff
    /// `required >= 1`, `total >= required`, and `approvals <= total`.
    pub fn is_well_formed(&self) -> bool {
        self.required >= 1 && self.total >= self.required && self.approvals <= self.total
    }

    pub fn is_met(&self) -> bool {
        self.is_well_formed() && self.approvals >= self.required
    }
}

/// Local proof object that, in a future run, can authorize MainNet/
/// TestNet governance-controlled bundle-signing-key lifecycle
/// transitions.
///
/// The proof carries:
///
/// * the trust-domain binding fields (environment, chain_id,
///   genesis_hash, authority root fingerprint and suite);
/// * the lifecycle action this proof authorizes (the local
///   sub-classification, NOT just the on-wire action byte);
/// * the active / new / revoked bundle-signing key fingerprints;
/// * the authority-domain sequence the proof targets;
/// * the candidate v2 record digest the proof binds to;
/// * the issuer authority class, signature suite, and signature bytes;
/// * an optional [`GovernanceThreshold`] descriptor.
///
/// The verifier requires every binding to match the candidate v2
/// record AND the expected trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceAuthorityProof {
    // ---- Trust-domain binding -----------------------------------------
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,

    // ---- Lifecycle action binding -------------------------------------
    pub lifecycle_action: LocalLifecycleAction,

    // ---- Key binding --------------------------------------------------
    /// Active bundle-signing key fingerprint after this transition.
    pub active_bundle_signing_key_fingerprint: String,
    /// Optional new bundle-signing key fingerprint introduced by this
    /// transition (rotate/activate-initial). For revoke-class actions
    /// the new key is unchanged from `active_bundle_signing_key_fingerprint`.
    pub new_bundle_signing_key_fingerprint: Option<String>,
    /// Optional revoked / retired key fingerprint.
    pub revoked_bundle_signing_key_fingerprint: Option<String>,

    // ---- Sequence + digest binding ------------------------------------
    pub authority_domain_sequence: u64,
    pub candidate_v2_digest: String,

    // ---- Issuer binding -----------------------------------------------
    pub issuer_authority_class: GovernanceAuthorityClass,
    pub issuer_signature_suite_id: u8,
    pub issuer_signature: Vec<u8>,

    // ---- Optional threshold metadata ----------------------------------
    pub threshold: Option<GovernanceThreshold>,
}

/// Hook used to verify the issuer signature byte string carried by a
/// [`GovernanceAuthorityProof`].
///
/// Source/test only. The hook is **pure** — it MUST NOT perform I/O.
/// Returning `Ok(())` means the byte string is a valid issuer signature
/// over the candidate digest under the expected authority root for the
/// declared issuer authority class; returning `Err(reason)` means the
/// signature is invalid or malformed and the verifier rejects with
/// [`GovernanceAuthorityVerificationOutcome::InvalidIssuerSignature`].
///
/// Run 163 source/test fixtures supply
/// [`fixture_issuer_signature_verifier`]. A future run will replace
/// this hook with a real PQC signature verifier without changing the
/// verifier surface.
pub trait GovernanceIssuerSignatureVerifier {
    fn verify_issuer_signature(
        &self,
        proof: &GovernanceAuthorityProof,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<(), String>;
}

/// Source/test fixture issuer-signature verifier.
///
/// Accepts the proof iff the signature byte string is the deterministic
/// concatenation of:
///
/// `b"qbind-run163-gov:"` || class_tag || b":" || authority_root_fingerprint ||
/// b":" || candidate_v2_digest || b":" || authority_domain_sequence (big-endian u64)
///
/// This gives the test matrix a deterministic accept/reject signal that
/// is bound to authority root, candidate digest, and sequence — so a
/// stale lower-sequence signature is rejected by the signature check
/// alone (R13), and a wrong-root or wrong-digest signature is rejected
/// by the signature check independently of the binding checks (R4, R6,
/// R8).
pub struct FixtureIssuerSignatureVerifier;

impl FixtureIssuerSignatureVerifier {
    pub fn expected_signature_bytes(
        class: GovernanceAuthorityClass,
        authority_root_fingerprint: &str,
        candidate_v2_digest: &str,
        authority_domain_sequence: u64,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(b"qbind-run163-gov:");
        out.extend_from_slice(class.tag().as_bytes());
        out.extend_from_slice(b":");
        out.extend_from_slice(authority_root_fingerprint.as_bytes());
        out.extend_from_slice(b":");
        out.extend_from_slice(candidate_v2_digest.as_bytes());
        out.extend_from_slice(b":");
        out.extend_from_slice(&authority_domain_sequence.to_be_bytes());
        out
    }
}

impl GovernanceIssuerSignatureVerifier for FixtureIssuerSignatureVerifier {
    fn verify_issuer_signature(
        &self,
        proof: &GovernanceAuthorityProof,
        trust_domain: &AuthorityTrustDomain,
    ) -> Result<(), String> {
        let expected = Self::expected_signature_bytes(
            proof.issuer_authority_class,
            &trust_domain.authority_root_fingerprint,
            &proof.candidate_v2_digest,
            proof.authority_domain_sequence,
        );
        if proof.issuer_signature == expected {
            Ok(())
        } else {
            Err("fixture issuer signature does not match canonical bytes".to_string())
        }
    }
}

/// Convenience constructor for a fixture issuer-signature byte string.
pub fn fixture_issuer_signature(
    class: GovernanceAuthorityClass,
    authority_root_fingerprint: &str,
    candidate_v2_digest: &str,
    authority_domain_sequence: u64,
) -> Vec<u8> {
    FixtureIssuerSignatureVerifier::expected_signature_bytes(
        class,
        authority_root_fingerprint,
        candidate_v2_digest,
        authority_domain_sequence,
    )
}

/// Construct a [`FixtureIssuerSignatureVerifier`].
pub fn fixture_issuer_signature_verifier() -> FixtureIssuerSignatureVerifier {
    FixtureIssuerSignatureVerifier
}

/// Typed outcome of [`verify_governance_authority_proof`].
///
/// Reject variants carry the data required to render a precise operator
/// log line. The caller MUST NOT mutate authority state on any reject
/// variant. Acceptance does NOT enable MainNet peer-driven apply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceAuthorityVerificationOutcome {
    /// Genesis-bound proof accepted for the declared lifecycle action
    /// (`ActivateInitial`, `Rotate`, `Retire`, `Revoke`, or
    /// `EmergencyRevoke` if the genesis-bound model authorizes it).
    AcceptedGenesisBound {
        action: LocalLifecycleAction,
        authority_domain_sequence: u64,
    },
    /// Emergency-council proof accepted. Run 163 only authorizes
    /// `EmergencyRevoke` for this class.
    AcceptedEmergencyCouncil {
        authority_domain_sequence: u64,
    },
    /// Bit-for-bit identical re-presentation of an already-accepted
    /// proof against an already-accepted candidate at the same sequence.
    /// Replay-safe (idempotent), distinct from
    /// [`Self::ReplayRejected`] which fires for a stale lower-sequence
    /// proof landing on a higher persisted sequence.
    AcceptedIdempotent {
        authority_domain_sequence: u64,
    },

    /// Placeholder on-chain governance class — no proof format exists.
    UnsupportedOnChainGovernance,

    // ---- Domain-binding rejects ----------------------------------------
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        candidate: TrustBundleEnvironment,
    },
    WrongChain {
        expected: String,
        candidate: String,
    },
    WrongGenesis {
        expected: String,
        candidate: String,
    },
    WrongAuthorityRoot {
        expected: String,
        candidate: String,
    },

    // ---- Action / digest / sequence rejects ----------------------------
    WrongLifecycleAction {
        expected: LocalLifecycleAction,
        candidate: LocalLifecycleAction,
    },
    /// Authority class does not authorize the declared lifecycle action
    /// (e.g. EmergencyCouncil declaring Rotate).
    AuthorityClassDoesNotAuthorizeAction {
        class: GovernanceAuthorityClass,
        action: LocalLifecycleAction,
    },
    WrongCandidateDigest {
        expected: String,
        candidate: String,
    },
    WrongAuthoritySequence {
        expected: u64,
        candidate: u64,
    },
    /// Stale / replayed lower-sequence proof landing on a higher
    /// persisted sequence (R13). Distinct from
    /// [`Self::AcceptedIdempotent`].
    ReplayRejected {
        persisted_sequence: u64,
        proof_sequence: u64,
    },

    // ---- Signature / suite rejects -------------------------------------
    InvalidIssuerSignature {
        reason: String,
    },
    UnsupportedIssuerSuite {
        suite_id: u8,
    },
    NonPqcSuiteRejected {
        suite_id: u8,
    },
    /// Proof's `authority_root_suite_id` is not a PQC suite. Distinct
    /// from `NonPqcSuiteRejected` on the issuer signature suite.
    NonPqcAuthorityRootSuiteRejected {
        suite_id: u8,
    },

    // ---- Threshold rejects ---------------------------------------------
    ThresholdNotMet {
        approvals: u32,
        required: u32,
    },

    // ---- Structural rejects --------------------------------------------
    MalformedProof {
        reason: String,
    },

    // ---- Explicit non-authority rejects --------------------------------
    /// Local operator config alone is rejected as a MainNet authority
    /// proof (R15). This variant exists so a caller that hands the
    /// verifier a synthetic "operator-config" proof (no issuer
    /// signature, no class) gets a precise typed reject instead of a
    /// generic structural error.
    LocalOperatorConfigOnlyRejected,
    /// Peer-majority / gossip count is rejected as an authority proof
    /// (R16).
    PeerMajorityProofRejected,
}

impl GovernanceAuthorityVerificationOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedGenesisBound { .. }
                | Self::AcceptedEmergencyCouncil { .. }
                | Self::AcceptedIdempotent { .. }
        )
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Typed combined decision returned by
/// [`validate_lifecycle_with_governance_authority`].
///
/// Both the lifecycle outcome AND the governance outcome must be accepts
/// for [`Self::Accepted`]. Otherwise the helper returns the precise
/// typed rejection from whichever surface refused the candidate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CombinedLifecycleGovernanceOutcome {
    Accepted {
        lifecycle: AuthorityLifecycleTransitionOutcome,
        governance: GovernanceAuthorityVerificationOutcome,
    },
    LifecycleRejected(AuthorityLifecycleTransitionOutcome),
    GovernanceRejected {
        lifecycle: AuthorityLifecycleTransitionOutcome,
        governance: GovernanceAuthorityVerificationOutcome,
    },
}

impl CombinedLifecycleGovernanceOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Pure typed governance ratification authority verifier.
///
/// Performs no I/O. Never mutates persisted state. Verifies every
/// binding (environment, chain, genesis, authority root, lifecycle
/// action, candidate digest, sequence, signature, suite, threshold)
/// against the candidate v2 record and the expected trust domain.
///
/// Acceptance does **not** imply MainNet peer-driven apply enablement.
pub fn verify_governance_authority_proof<V: GovernanceIssuerSignatureVerifier + ?Sized>(
    proof: &GovernanceAuthorityProof,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    persisted_sequence: Option<u64>,
    signature_verifier: &V,
) -> GovernanceAuthorityVerificationOutcome {
    use GovernanceAuthorityVerificationOutcome as O;

    // ---- Class gate: on-chain governance is fail-closed ----------------
    if proof.issuer_authority_class == GovernanceAuthorityClass::OnChainGovernance {
        return O::UnsupportedOnChainGovernance;
    }

    // ---- Structural well-formedness ------------------------------------
    if proof.chain_id.is_empty()
        || proof.genesis_hash.is_empty()
        || proof.authority_root_fingerprint.is_empty()
        || proof.active_bundle_signing_key_fingerprint.is_empty()
        || proof.candidate_v2_digest.is_empty()
    {
        return O::MalformedProof {
            reason: "governance authority proof has empty required field".to_string(),
        };
    }
    if proof.issuer_signature.is_empty() {
        return O::MalformedProof {
            reason: "governance authority proof carries empty issuer signature".to_string(),
        };
    }

    // ---- Suite enforcement (issuer signature suite) --------------------
    if is_known_non_pqc_suite(proof.issuer_signature_suite_id) {
        return O::NonPqcSuiteRejected {
            suite_id: proof.issuer_signature_suite_id,
        };
    }
    if !is_pqc_governance_issuer_suite(proof.issuer_signature_suite_id) {
        return O::UnsupportedIssuerSuite {
            suite_id: proof.issuer_signature_suite_id,
        };
    }

    // ---- Suite enforcement (authority root suite) ----------------------
    if !is_pqc_lifecycle_suite(proof.authority_root_suite_id) {
        return O::NonPqcAuthorityRootSuiteRejected {
            suite_id: proof.authority_root_suite_id,
        };
    }

    // ---- Trust-domain binding (proof against expected domain) ----------
    if proof.environment != trust_domain.environment {
        return O::WrongEnvironment {
            expected: trust_domain.environment,
            candidate: proof.environment,
        };
    }
    if proof.chain_id != trust_domain.chain_id {
        return O::WrongChain {
            expected: trust_domain.chain_id.clone(),
            candidate: proof.chain_id.clone(),
        };
    }
    if proof.genesis_hash != trust_domain.genesis_hash {
        return O::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            candidate: proof.genesis_hash.clone(),
        };
    }
    if proof.authority_root_fingerprint != trust_domain.authority_root_fingerprint
        || proof.authority_root_suite_id != trust_domain.authority_root_suite_id
    {
        return O::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            candidate: proof.authority_root_fingerprint.clone(),
        };
    }

    // ---- Trust-domain binding (candidate against expected domain) ------
    //
    // The candidate v2 record must also match the expected trust domain
    // — otherwise a proof bound to (env=Devnet, chain=X) could authorize
    // a candidate with (env=Devnet, chain=Y), which would defeat the
    // whole point of binding.
    if candidate.environment != trust_domain.environment {
        return O::WrongEnvironment {
            expected: trust_domain.environment,
            candidate: candidate.environment,
        };
    }
    if candidate.chain_id != trust_domain.chain_id {
        return O::WrongChain {
            expected: trust_domain.chain_id.clone(),
            candidate: candidate.chain_id.clone(),
        };
    }
    if candidate.genesis_hash != trust_domain.genesis_hash {
        return O::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            candidate: candidate.genesis_hash.clone(),
        };
    }
    if candidate.authority_root_fingerprint != trust_domain.authority_root_fingerprint {
        return O::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            candidate: candidate.authority_root_fingerprint.clone(),
        };
    }

    // ---- Candidate-digest binding --------------------------------------
    if proof.candidate_v2_digest != candidate.latest_ratification_v2_digest {
        return O::WrongCandidateDigest {
            expected: candidate.latest_ratification_v2_digest.clone(),
            candidate: proof.candidate_v2_digest.clone(),
        };
    }

    // ---- Authority-domain sequence binding -----------------------------
    if proof.authority_domain_sequence != candidate.latest_authority_domain_sequence {
        return O::WrongAuthoritySequence {
            expected: candidate.latest_authority_domain_sequence,
            candidate: proof.authority_domain_sequence,
        };
    }
    // Stale-lower-sequence replay: persisted sequence is strictly higher
    // than the proof's claimed sequence. The Run 159 lifecycle validator
    // also rejects this on the candidate side, but we surface a precise
    // typed `ReplayRejected` here so callers can distinguish governance-
    // proof replay from candidate-marker rollback.
    if let Some(prev_seq) = persisted_sequence {
        if proof.authority_domain_sequence < prev_seq {
            return O::ReplayRejected {
                persisted_sequence: prev_seq,
                proof_sequence: proof.authority_domain_sequence,
            };
        }
    }

    // ---- Lifecycle-action binding --------------------------------------
    let candidate_action_class = match classify_candidate_lifecycle_action(candidate) {
        Ok(a) => a,
        Err(reason) => return O::MalformedProof { reason },
    };
    if proof.lifecycle_action != candidate_action_class {
        return O::WrongLifecycleAction {
            expected: candidate_action_class,
            candidate: proof.lifecycle_action,
        };
    }

    // ---- Authority-class / lifecycle-action gating ---------------------
    match proof.issuer_authority_class {
        GovernanceAuthorityClass::GenesisBound => {
            // Genesis-bound authority may authorize any of the five
            // lifecycle actions (Rotate, Revoke, EmergencyRevoke,
            // ActivateInitial, Retire) in the source/test model.
        }
        GovernanceAuthorityClass::EmergencyCouncil => {
            if proof.lifecycle_action != LocalLifecycleAction::EmergencyRevoke {
                return O::AuthorityClassDoesNotAuthorizeAction {
                    class: proof.issuer_authority_class,
                    action: proof.lifecycle_action,
                };
            }
        }
        GovernanceAuthorityClass::OnChainGovernance => {
            // Already short-circuited above.
            return O::UnsupportedOnChainGovernance;
        }
    }

    // ---- Key binding (active / new / revoked) --------------------------
    if proof.active_bundle_signing_key_fingerprint
        != candidate.active_bundle_signing_key_fingerprint
    {
        return O::MalformedProof {
            reason: "proof active key fingerprint does not match candidate".to_string(),
        };
    }
    match proof.lifecycle_action {
        LocalLifecycleAction::Rotate => {
            // For rotate, the proof's `new` key must equal the candidate
            // active key, and its `revoked` key (predecessor) must equal
            // the candidate's previous-key fingerprint.
            let cand_prev = candidate
                .previous_bundle_signing_key_fingerprint
                .as_deref()
                .unwrap_or("");
            if let Some(new_fp) = proof.new_bundle_signing_key_fingerprint.as_deref() {
                if new_fp != candidate.active_bundle_signing_key_fingerprint {
                    return O::MalformedProof {
                        reason: "rotate proof new key does not match candidate active key"
                            .to_string(),
                    };
                }
            }
            if let Some(rev_fp) = proof.revoked_bundle_signing_key_fingerprint.as_deref() {
                if rev_fp != cand_prev {
                    return O::MalformedProof {
                        reason: "rotate proof revoked key does not match candidate previous key"
                            .to_string(),
                    };
                }
            }
        }
        LocalLifecycleAction::Retire
        | LocalLifecycleAction::Revoke
        | LocalLifecycleAction::EmergencyRevoke => {
            // For revoke-class actions, the proof's `revoked` key must
            // match the candidate's revoked target (everything after
            // the 2-character sub-class metadata prefix).
            let target = candidate
                .revoked_key_metadata
                .as_deref()
                .and_then(|m| m.get(2..))
                .unwrap_or("");
            if let Some(rev_fp) = proof.revoked_bundle_signing_key_fingerprint.as_deref() {
                if rev_fp != target {
                    return O::MalformedProof {
                        reason: "revoke-class proof revoked key does not match candidate metadata"
                            .to_string(),
                    };
                }
            }
        }
        LocalLifecycleAction::ActivateInitial => {
            // No predecessor binding to verify.
        }
    }

    // ---- Threshold (if representable) ----------------------------------
    if let Some(threshold) = proof.threshold.as_ref() {
        if !threshold.is_well_formed() {
            return O::MalformedProof {
                reason: format!(
                    "governance threshold malformed: approvals={} required={} total={}",
                    threshold.approvals, threshold.required, threshold.total
                ),
            };
        }
        if !threshold.is_met() {
            return O::ThresholdNotMet {
                approvals: threshold.approvals,
                required: threshold.required,
            };
        }
    }

    // ---- Issuer signature ---------------------------------------------
    if let Err(reason) = signature_verifier.verify_issuer_signature(proof, trust_domain) {
        return O::InvalidIssuerSignature { reason };
    }

    // ---- Accept --------------------------------------------------------
    match proof.issuer_authority_class {
        GovernanceAuthorityClass::GenesisBound => O::AcceptedGenesisBound {
            action: proof.lifecycle_action,
            authority_domain_sequence: proof.authority_domain_sequence,
        },
        GovernanceAuthorityClass::EmergencyCouncil => O::AcceptedEmergencyCouncil {
            authority_domain_sequence: proof.authority_domain_sequence,
        },
        GovernanceAuthorityClass::OnChainGovernance => O::UnsupportedOnChainGovernance,
    }
}

/// Pure non-mutating helper that composes:
///
/// * the Run 159 typed v2 lifecycle validator
///   ([`validate_v2_lifecycle_transition`]), and
/// * the Run 163 typed governance authority verifier
///   ([`verify_governance_authority_proof`]),
///
/// into a single typed [`CombinedLifecycleGovernanceOutcome`].
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no
/// live trust state. Run 163 explicitly does **not** wire this helper
/// into mutating apply surfaces — it is a pure decision aid only.
pub fn validate_lifecycle_with_governance_authority<V: GovernanceIssuerSignatureVerifier>(
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    candidate: &PersistentAuthorityStateRecordV2,
    proof: &GovernanceAuthorityProof,
    trust_domain: &AuthorityTrustDomain,
    signature_verifier: &V,
) -> CombinedLifecycleGovernanceOutcome {
    let lifecycle = validate_v2_lifecycle_transition(persisted, candidate, trust_domain);
    if lifecycle.is_reject() {
        return CombinedLifecycleGovernanceOutcome::LifecycleRejected(lifecycle);
    }

    let persisted_sequence = match persisted {
        Some(PersistentAuthorityStateRecordVersioned::V2(v)) => {
            Some(v.latest_authority_domain_sequence)
        }
        _ => None,
    };

    let governance = verify_governance_authority_proof(
        proof,
        candidate,
        trust_domain,
        persisted_sequence,
        signature_verifier,
    );
    if governance.is_reject() {
        return CombinedLifecycleGovernanceOutcome::GovernanceRejected {
            lifecycle,
            governance,
        };
    }

    CombinedLifecycleGovernanceOutcome::Accepted {
        lifecycle,
        governance,
    }
}

/// Map a candidate v2 record's on-wire action byte (and revocation
/// metadata sub-class) into a [`LocalLifecycleAction`]. This is a thin
/// re-classification used by [`verify_governance_authority_proof`] to
/// compare the proof's declared `lifecycle_action` against the
/// candidate's encoded lifecycle action without consulting persisted
/// state.
///
/// Run 165 makes this public so the marker-decision layer can determine
/// — without re-deriving any state — whether a candidate's lifecycle
/// action is governance-sensitive and therefore requires a governance
/// authority proof under the active [`GovernanceProofPolicy`].
pub fn classify_candidate_lifecycle_action(
    candidate: &PersistentAuthorityStateRecordV2,
) -> Result<LocalLifecycleAction, String> {
    match candidate.latest_lifecycle_action {
        BundleSigningRatificationV2Action::Ratify => Ok(LocalLifecycleAction::ActivateInitial),
        BundleSigningRatificationV2Action::Rotate => Ok(LocalLifecycleAction::Rotate),
        BundleSigningRatificationV2Action::Revoke => {
            let metadata = candidate.revoked_key_metadata.as_deref().ok_or_else(|| {
                "v2 revoke marker requires revoked_key_metadata sub-class prefix".to_string()
            })?;
            if metadata.len() < 2 {
                return Err(
                    "revoked_key_metadata too short to carry sub-class prefix".to_string()
                );
            }
            match &metadata[..2] {
                "01" => Ok(LocalLifecycleAction::Revoke),
                "02" => Ok(LocalLifecycleAction::Retire),
                "03" => Ok(LocalLifecycleAction::EmergencyRevoke),
                other => Err(format!(
                    "unknown lifecycle sub-class prefix '{}' (expected 01/02/03)",
                    other
                )),
            }
        }
    }
}
// ===========================================================================
// Run 165 — governance-aware marker-decision policy + gate
// ===========================================================================
//
// Run 165 wires the Run 163 governance authority verifier into the v2
// lifecycle / marker-decision path so governance authority checks become
// production-source reachable before lifecycle-sensitive marker decisions
// are accepted.
//
// Strict scope (unchanged from Runs 159/161/162/163/164):
//
// * source/test integration only — release-binary governance enforcement
//   evidence is deferred to Run 166;
// * accepting a governance proof does NOT enable MainNet peer-driven apply
//   and does NOT bypass any existing environment gate;
// * no governance execution engine, no on-chain governance, no KMS/HSM,
//   no validator-set rotation, no wire/marker/sequence/trust-bundle schema
//   change.
//
// ## Documented schema-carrying gap
//
// The current v2 ratification / authority-marker wire material does NOT
// carry governance authority proof fields. Run 165 deliberately does NOT
// invent a schema to smuggle proof bytes through the existing wire format.
// Instead, a surface that cannot obtain a proof supplies
// [`GovernanceProofContext::Unavailable`]; under a policy that requires a
// proof for the candidate's lifecycle action the gate fails closed with
// [`GovernanceMarkerGate::RequiredButMissing`]. A future run that defines
// an actual proof-carrying schema (or supplies a proof out-of-band) passes
// [`GovernanceProofContext::Supplied`].

/// Run 165 — which lifecycle actions require a governance authority proof.
///
/// The default production wiring for Run 165 is [`Self::NotRequired`]:
/// governance verification is composed into the marker-decision path and
/// is exercised whenever a proof is supplied, but a *missing* proof does
/// not by itself refuse a transition. This preserves the existing
/// DevNet/TestNet peer-driven apply evidence (Runs 148/150/152/153/158),
/// which has no governance-proof fixtures yet, and defers release-binary
/// governance enforcement to Run 166.
///
/// [`Self::RequiredForLifecycleSensitive`] is the fail-closed policy the
/// Run 165 test matrix uses to prove that missing/invalid governance
/// proofs reject lifecycle-sensitive transitions (`Rotate`, `Retire`,
/// `Revoke`, `EmergencyRevoke`). `ActivateInitial` remains governance-
/// optional under both policies (genesis-bound first activation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GovernanceProofPolicy {
    /// Governance proof optional for every action. A supplied proof is
    /// still verified; an absent proof does not refuse the transition.
    NotRequired,
    /// `Rotate` / `Retire` / `Revoke` / `EmergencyRevoke` require a valid
    /// governance authority proof. `ActivateInitial` remains optional.
    RequiredForLifecycleSensitive,
}

impl GovernanceProofPolicy {
    /// Returns `true` iff this policy requires a governance authority
    /// proof for `action`.
    pub fn requires_proof_for(self, action: LocalLifecycleAction) -> bool {
        match self {
            Self::NotRequired => false,
            Self::RequiredForLifecycleSensitive => matches!(
                action,
                LocalLifecycleAction::Rotate
                    | LocalLifecycleAction::Retire
                    | LocalLifecycleAction::Revoke
                    | LocalLifecycleAction::EmergencyRevoke
            ),
        }
    }
}

/// Run 165 — governance proof context handed to the marker-decision path.
///
/// The verifier reference is a trait object so the marker-decision layer
/// stays non-generic; the trait is object-safe and `dyn Trait` itself
/// implements [`GovernanceIssuerSignatureVerifier`], so the existing
/// generic [`verify_governance_authority_proof`] accepts it unchanged.
pub enum GovernanceProofContext<'a> {
    /// No governance proof is available to the calling surface. Today the
    /// v2 ratification / marker wire material does NOT carry governance
    /// proof fields (documented schema gap). Under a policy that requires
    /// a proof for the candidate's lifecycle action this fails closed.
    Unavailable,
    /// A governance proof is supplied (source/test fixture path, or a
    /// future run that carries proof material out-of-band).
    Supplied {
        proof: &'a GovernanceAuthorityProof,
        verifier: &'a dyn GovernanceIssuerSignatureVerifier,
    },
}

/// Run 165 — typed outcome of [`evaluate_governance_marker_gate`].
///
/// Pure / non-mutating. The caller MUST NOT begin Run 070 apply, mutate
/// live trust, evict sessions, write a sequence, or persist a marker on
/// any non-accept variant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceMarkerGate {
    /// Policy does not require a proof for this action and none was
    /// supplied. The governance layer is a no-op for this decision; the
    /// existing anti-rollback + lifecycle decision stands unchanged.
    NotRequiredNoProof,
    /// A governance proof was supplied and accepted by
    /// [`verify_governance_authority_proof`].
    Accepted(GovernanceAuthorityVerificationOutcome),
    /// Policy requires a governance proof for this lifecycle action but
    /// none was available (documented wire schema gap). Fail closed.
    RequiredButMissing { action: LocalLifecycleAction },
    /// A governance proof was supplied but rejected. Carries the precise
    /// typed verifier outcome for the operator log line. Fail closed.
    Rejected(GovernanceAuthorityVerificationOutcome),
}

impl GovernanceMarkerGate {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::NotRequiredNoProof | Self::Accepted(_))
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 165 — pure governance gate over an already-derived candidate.
///
/// Performs **no I/O**. Writes no marker, no sequence, mutates no live
/// trust state, evicts no sessions. Determines the candidate's lifecycle
/// action, then:
///
/// * if a proof is supplied, verifies it via
///   [`verify_governance_authority_proof`] and returns
///   [`GovernanceMarkerGate::Accepted`] / [`GovernanceMarkerGate::Rejected`];
/// * if no proof is supplied, returns
///   [`GovernanceMarkerGate::RequiredButMissing`] when `policy` requires a
///   proof for the action, else [`GovernanceMarkerGate::NotRequiredNoProof`].
///
/// Acceptance does **not** imply MainNet peer-driven apply enablement.
pub fn evaluate_governance_marker_gate(
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    persisted_sequence: Option<u64>,
    policy: GovernanceProofPolicy,
    context: GovernanceProofContext<'_>,
) -> GovernanceMarkerGate {
    let action = match classify_candidate_lifecycle_action(candidate) {
        Ok(a) => a,
        Err(reason) => {
            return GovernanceMarkerGate::Rejected(
                GovernanceAuthorityVerificationOutcome::MalformedProof { reason },
            );
        }
    };

    match context {
        GovernanceProofContext::Supplied { proof, verifier } => {
            let outcome = verify_governance_authority_proof(
                proof,
                candidate,
                trust_domain,
                persisted_sequence,
                verifier,
            );
            if outcome.is_accept() {
                GovernanceMarkerGate::Accepted(outcome)
            } else {
                GovernanceMarkerGate::Rejected(outcome)
            }
        }
        GovernanceProofContext::Unavailable => {
            if policy.requires_proof_for(action) {
                GovernanceMarkerGate::RequiredButMissing { action }
            } else {
                GovernanceMarkerGate::NotRequiredNoProof
            }
        }
    }
}