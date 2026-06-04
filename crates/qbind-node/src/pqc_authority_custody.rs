//! Run 188 — source/test KMS/HSM custody boundary for bundle-signing
//! authority and governance authority operations.
//!
//! Source/test only. Run 188 does **not** wire a real KMS, HSM, cloud
//! KMS, PKCS#11, or remote-signer backend; nor does it enable MainNet
//! peer-driven apply, real on-chain governance proof verification,
//! governance execution, or validator-set rotation. The boundary
//! introduced here is intentionally narrow:
//!
//! * Distinguish, by typed symbol, custody material that is acceptable
//!   only as DevNet/TestNet evidence (`FixtureLocalKey`,
//!   `LocalOperatorKey`) from custody material that *would* satisfy
//!   future production custody (`RemoteSigner` / `Kms` / `Hsm`) once
//!   real backends land.
//! * Make the absence of those production backends the typed default
//!   on every surface — every production-class custody class fails
//!   closed as "unavailable" until a future run replaces it with a
//!   real implementation.
//! * Bind every custody decision to the same `(environment, chain_id,
//!   genesis_hash, authority_root_fingerprint, signing_key_fingerprint,
//!   governance_authority_class, lifecycle_action, candidate_digest,
//!   authority_domain_sequence, custody_class, custody_key_id,
//!   custody_attestation_digest, freshness/expiry)` tuple that the Run
//!   159 / 163 / 178 / 186 verifiers already enforce, so a custody
//!   acceptance can never claim authority over a different lifecycle
//!   transition or a different trust domain.
//! * Refuse, by symbol, every attempt to satisfy MainNet production
//!   custody with fixture or local-operator material — even if the
//!   custody attestation is otherwise structurally valid for the
//!   declared trust domain.
//! * Refuse, by symbol, every attempt to satisfy custody by gossip,
//!   peer majority, or peer-driven apply count.
//!
//! Release-binary custody-boundary evidence is **deferred to Run
//! 189**. Real KMS/HSM/remote-signer backends, real on-chain
//! governance proof verification, governance execution, validator-set
//! rotation, autonomous apply, apply-on-receipt, and peer-majority
//! authority all remain unimplemented. MainNet peer-driven apply
//! remains the Run 147 / 148 / 152 FATAL refusal regardless of
//! custody outcome.
//!
//! The module is pure: every public function performs no I/O, writes
//! no marker, writes no sequence, mutates no live trust, evicts no
//! sessions, and never invokes Run 070 apply.

use crate::pqc_authority_lifecycle::{
    validate_v2_lifecycle_transition, AuthorityLifecycleTransitionOutcome, AuthorityTrustDomain,
    LocalLifecycleAction, PQC_LIFECYCLE_SUITE_ML_DSA_44,
};
use crate::pqc_authority_state::{PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Custody class
// ===========================================================================

/// Run 188 — typed enumeration of authority-custody classes.
///
/// The variants are intentionally disjoint so a calling surface can
/// distinguish, by symbol, "fixture key material" from "local
/// operator key material" from each of the three future production
/// custody backends, plus an explicit `Unknown` reject bucket for any
/// suite-id / class-id combination that does not match a known
/// variant.
///
/// Run 188 does **not** wire a real implementation for any production
/// variant — `RemoteSigner`, `Kms`, and `Hsm` are placeholder symbols
/// only; the validator fails them closed as "unavailable". Future
/// runs that land a real backend MUST extend the matching validator
/// branch and cannot silently elevate any other variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AuthorityCustodyClass {
    /// DevNet/TestNet fixture key material baked into the source/test
    /// corpus. Acceptable only under an explicit fixture policy.
    /// Must NOT satisfy MainNet production custody.
    FixtureLocalKey,
    /// Explicit local-operator key material (e.g. an operator-supplied
    /// signing key that is held on the local machine, not in a real
    /// KMS / HSM / remote signer). DevNet/TestNet may use it where
    /// already allowed by policy. Must NOT satisfy MainNet production
    /// custody.
    LocalOperatorKey,
    /// Placeholder for a real authenticated remote signer protocol.
    /// Run 188 fails this closed as "unavailable" because no real
    /// remote-signer protocol is wired.
    RemoteSigner,
    /// Placeholder for a real Key-Management-Service backend. Run 188
    /// fails this closed as "unavailable".
    Kms,
    /// Placeholder for a real Hardware-Security-Module backend. Run
    /// 188 fails this closed as "unavailable".
    Hsm,
    /// Unknown / unsupported custody class. Always fail-closed.
    Unknown,
}

impl AuthorityCustodyClass {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::FixtureLocalKey => "fixture-local-key",
            Self::LocalOperatorKey => "local-operator-key",
            Self::RemoteSigner => "remote-signer",
            Self::Kms => "kms",
            Self::Hsm => "hsm",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` iff this custody class is local fixture / local
    /// operator material that MUST NOT satisfy MainNet production
    /// custody.
    pub const fn is_local_only(self) -> bool {
        matches!(self, Self::FixtureLocalKey | Self::LocalOperatorKey)
    }

    /// Returns `true` iff this custody class is a production-class
    /// placeholder (RemoteSigner / Kms / Hsm) that Run 188 fails
    /// closed as "unavailable".
    pub const fn is_production_placeholder(self) -> bool {
        matches!(self, Self::RemoteSigner | Self::Kms | Self::Hsm)
    }
}

// ===========================================================================
// Custody policy
// ===========================================================================

/// Run 188 — typed custody policy.
///
/// The policy is an explicit gate selected by the calling surface.
/// `FixtureOnly` is reserved for DevNet/TestNet fixture-only test
/// vectors; `DevnetLocalAllowed` and `TestnetLocalAllowed` permit
/// local-operator custody for the matching environment;
/// `ProductionCustodyRequired` and `MainnetProductionCustodyRequired`
/// REQUIRE a real production custody backend — and Run 188's
/// validator fails them closed because no such backend exists yet.
///
/// `Disabled` is the default fail-closed policy that refuses every
/// custody class regardless of attestation contents, preserving
/// Run 050–187 conservative defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum AuthorityCustodyPolicy {
    /// Default. Refuses every custody class. Used by every production
    /// surface unless a more specific policy is explicitly set.
    #[default]
    Disabled,
    /// Source/test fixture-only policy. Accepts `FixtureLocalKey`
    /// only, on DevNet or TestNet trust domains.
    FixtureOnly,
    /// DevNet local policy. Accepts `FixtureLocalKey` and
    /// `LocalOperatorKey` on a DevNet trust domain.
    DevnetLocalAllowed,
    /// TestNet local policy. Accepts `FixtureLocalKey` and
    /// `LocalOperatorKey` on a TestNet trust domain.
    TestnetLocalAllowed,
    /// Production custody required (DevNet/TestNet bring-up of a real
    /// backend). Run 188 fails closed because no real backend is
    /// implemented.
    ProductionCustodyRequired,
    /// MainNet production custody required. Run 188 fails closed for
    /// every custody class — fixture/local material is rejected as
    /// non-production custody, and every production placeholder is
    /// rejected as unavailable. MainNet peer-driven apply also remains
    /// the Run 147 FATAL refusal regardless of this policy.
    MainnetProductionCustodyRequired,
}

impl AuthorityCustodyPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureOnly => "fixture-only",
            Self::DevnetLocalAllowed => "devnet-local-allowed",
            Self::TestnetLocalAllowed => "testnet-local-allowed",
            Self::ProductionCustodyRequired => "production-custody-required",
            Self::MainnetProductionCustodyRequired => "mainnet-production-custody-required",
        }
    }

    /// Returns `true` iff this policy requires production custody
    /// (and therefore Run 188 fails closed for every custody class).
    pub const fn requires_production_custody(self) -> bool {
        matches!(
            self,
            Self::ProductionCustodyRequired | Self::MainnetProductionCustodyRequired
        )
    }

    /// Returns `true` iff this policy allows fixture-class custody
    /// (DevNet/TestNet evidence-only).
    pub const fn allows_fixture(self) -> bool {
        matches!(
            self,
            Self::FixtureOnly | Self::DevnetLocalAllowed | Self::TestnetLocalAllowed
        )
    }

    /// Returns `true` iff this policy allows local-operator custody
    /// for the environment indicated by the policy variant.
    pub const fn allows_local_operator(self) -> bool {
        matches!(
            self,
            Self::DevnetLocalAllowed | Self::TestnetLocalAllowed
        )
    }
}

// ===========================================================================
// Custody attestation
// ===========================================================================

/// Run 188 — typed custody attestation.
///
/// Pure data. The fields mirror the full Run 159 / 163 / 178 / 186
/// binding tuple plus the custody-class-specific fields required to
/// distinguish "this attestation belongs to *this* custody class with
/// *this* key id over *this* lifecycle transition" from any other
/// authority decision. Every field is enforced by
/// [`validate_authority_custody_attestation`].
///
/// `custody_attestation_digest` is the placeholder commitment a
/// future production backend will replace with a real attestation
/// signature / quote / wrapped key. Run 188 only enforces presence
/// and non-emptiness; it does not interpret the bytes.
///
/// `freshness_unix` and `expires_at_unix` are optional: when both are
/// present, the validator enforces `freshness_unix <= now_unix <
/// expires_at_unix`; when absent the attestation is treated as not
/// time-bound (acceptable for fixtures only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCustodyAttestation {
    /// Custody class declared by this attestation.
    pub custody_class: AuthorityCustodyClass,
    /// Stable, opaque identifier of the custody-held key.
    pub custody_key_id: String,
    /// Custody suite identifier (placeholder; only the Run 159 PQC
    /// signing suite is currently accepted).
    pub custody_suite_id: u8,
    /// Placeholder commitment / wrapped attestation bytes. Must be
    /// non-empty.
    pub custody_attestation_digest: String,
    /// Optional freshness lower bound (UNIX seconds).
    pub freshness_unix: Option<u64>,
    /// Optional expiry upper bound (UNIX seconds, exclusive).
    pub expires_at_unix: Option<u64>,
    /// Bound trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Bound trust-domain chain id.
    pub chain_id: String,
    /// Bound trust-domain genesis hash.
    pub genesis_hash: String,
    /// Bound trust-domain authority root fingerprint.
    pub authority_root_fingerprint: String,
    /// Bound bundle-signing key fingerprint.
    pub bundle_signing_key_fingerprint: String,
    /// Bound governance authority class.
    pub governance_authority_class: GovernanceAuthorityClass,
    /// Bound lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// Bound candidate digest (next persistent authority record digest).
    pub candidate_digest: String,
    /// Bound authority-domain sequence (next sequence number this
    /// custody attestation authorizes).
    pub authority_domain_sequence: u64,
}

// ===========================================================================
// Validation outcome
// ===========================================================================

/// Run 188 — typed outcome of [`validate_authority_custody_attestation`].
///
/// Reject variants are precise so each can be distinguished from any
/// other in tests and operator log lines without pattern-matching
/// the inner attestation. Acceptance is **always** of a fixture-class
/// or local-operator-class attestation under the matching DevNet /
/// TestNet policy — production-class attestations are refused
/// regardless of contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityCustodyValidationOutcome {
    /// DevNet/TestNet fixture custody accepted under explicit
    /// `FixtureOnly` / `DevnetLocalAllowed` / `TestnetLocalAllowed`
    /// policy. Acceptance is evidence-only; no MainNet apply, no
    /// governance execution, no mutation.
    AcceptedFixtureCustody {
        custody_key_id: String,
        environment: TrustBundleEnvironment,
    },
    /// DevNet/TestNet local-operator custody accepted under explicit
    /// `DevnetLocalAllowed` / `TestnetLocalAllowed` policy.
    AcceptedLocalOperatorCustody {
        custody_key_id: String,
        environment: TrustBundleEnvironment,
    },
    /// The active policy requires production custody (either
    /// `ProductionCustodyRequired` or
    /// `MainnetProductionCustodyRequired`). Run 188 has no real
    /// production custody backend; every such request fails closed
    /// here.
    ProductionCustodyUnavailable {
        policy: AuthorityCustodyPolicy,
    },
    /// `RemoteSigner` placeholder routed through the validator. Run
    /// 188 has no real remote-signer protocol; the placeholder fails
    /// closed.
    RemoteSignerUnavailable,
    /// `Kms` placeholder routed through the validator. Run 188 has no
    /// real KMS backend.
    KmsUnavailable,
    /// `Hsm` placeholder routed through the validator. Run 188 has no
    /// real HSM backend.
    HsmUnavailable,
    /// Custody class is `Unknown`. Always fail-closed.
    UnknownCustodyClassRejected,
    /// Trust-domain environment does not match the attestation.
    WrongEnvironment {
        expected: TrustBundleEnvironment,
        attested: TrustBundleEnvironment,
    },
    /// Trust-domain chain id does not match the attestation.
    WrongChain {
        expected: String,
        attested: String,
    },
    /// Trust-domain genesis hash does not match the attestation.
    WrongGenesis {
        expected: String,
        attested: String,
    },
    /// Trust-domain authority root fingerprint does not match the
    /// attestation.
    WrongAuthorityRoot {
        expected: String,
        attested: String,
    },
    /// Bundle-signing key fingerprint does not match the candidate.
    WrongSigningKeyFingerprint {
        expected: String,
        attested: String,
    },
    /// Candidate digest does not match the attestation.
    WrongCandidateDigest {
        expected: String,
        attested: String,
    },
    /// Authority-domain sequence does not match the expected next
    /// sequence.
    WrongAuthorityDomainSequence {
        expected: u64,
        attested: u64,
    },
    /// Lifecycle action does not match the attestation.
    WrongLifecycleAction {
        expected: LocalLifecycleAction,
        attested: LocalLifecycleAction,
    },
    /// Custody attestation digest is missing (empty).
    CustodyAttestationMissing,
    /// Custody attestation is malformed (e.g. empty key id).
    CustodyAttestationMalformed { reason: String },
    /// Custody attestation has expired (now_unix is at or past
    /// `expires_at_unix`, or before `freshness_unix`).
    CustodyAttestationExpired { now_unix: u64 },
    /// Declared custody key id mismatched the persisted candidate
    /// expectation.
    CustodyKeyIdMismatch {
        expected: String,
        attested: String,
    },
    /// Custody suite id is not the Run 159 PQC suite — or any other
    /// recognized custody suite.
    UnsupportedCustodySuite { suite_id: u8 },
    /// Fixture custody rejected because the active policy is
    /// `MainnetProductionCustodyRequired` (or the trust domain is
    /// MainNet).
    FixtureCustodyRejectedForMainNet,
    /// Local-operator custody rejected because the active policy is
    /// `MainnetProductionCustodyRequired` (or the trust domain is
    /// MainNet).
    LocalCustodyRejectedForMainNet,
    /// MainNet production custody is unavailable. Distinct from
    /// [`Self::ProductionCustodyUnavailable`] so the calling surface
    /// can log a precise "MainNet production custody unavailable"
    /// line that is layered ahead of the Run 147 / 148 / 152 FATAL
    /// peer-driven-apply refusal.
    MainNetProductionCustodyUnavailable,
    /// The active custody policy refuses this custody class, even
    /// though every binding field matches. Used when a fixture
    /// attestation is presented under
    /// `ProductionCustodyRequired` (DevNet/TestNet bring-up), or a
    /// local-operator attestation is presented under `FixtureOnly`,
    /// or any custody class is presented under `Disabled`.
    PolicyRefusesCustodyClass {
        policy: AuthorityCustodyPolicy,
        class: AuthorityCustodyClass,
    },
}

impl AuthorityCustodyValidationOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(
            self,
            Self::AcceptedFixtureCustody { .. } | Self::AcceptedLocalOperatorCustody { .. }
        )
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }

    /// Returns `true` iff this outcome represents an "unavailable
    /// production custody" rejection (regardless of fixture vs.
    /// MainNet vs. placeholder source).
    pub fn is_production_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionCustodyUnavailable { .. }
                | Self::MainNetProductionCustodyUnavailable
                | Self::RemoteSignerUnavailable
                | Self::KmsUnavailable
                | Self::HsmUnavailable
        )
    }

    /// Returns `true` iff this outcome is a MainNet-specific custody
    /// refusal.
    pub fn is_mainnet_refusal(&self) -> bool {
        matches!(
            self,
            Self::FixtureCustodyRejectedForMainNet
                | Self::LocalCustodyRejectedForMainNet
                | Self::MainNetProductionCustodyUnavailable
        )
    }
}

// ===========================================================================
// Custody validator
// ===========================================================================

/// Run 188 — pure typed custody validator.
///
/// Performs no I/O. Writes no marker. Writes no sequence. Mutates no
/// live trust. Evicts no sessions. Never invokes Run 070.
///
/// The validator binds every custody decision to:
///
/// * the [`AuthorityTrustDomain`] (environment / chain_id /
///   genesis_hash / authority root fingerprint);
/// * the bundle-signing key fingerprint of the persisted candidate;
/// * the governance authority class;
/// * the lifecycle action;
/// * the candidate digest;
/// * the next authority-domain sequence;
/// * the declared custody class, custody key id, custody attestation
///   digest, and freshness/expiry window.
///
/// `expected_custody_key_id` is the value the calling surface
/// expects to see — typically derived from the persisted candidate
/// metadata; when `None` the key-id binding is not enforced (used by
/// helpers that only need the policy / placeholder fail-closed
/// shape).
#[allow(clippy::too_many_arguments)]
pub fn validate_authority_custody_attestation(
    attestation: &AuthorityCustodyAttestation,
    candidate: &PersistentAuthorityStateRecordV2,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    policy: AuthorityCustodyPolicy,
    now_unix: u64,
) -> AuthorityCustodyValidationOutcome {
    // 1. Trust-domain environment.
    if attestation.environment != trust_domain.environment
        || candidate.environment != trust_domain.environment
    {
        return AuthorityCustodyValidationOutcome::WrongEnvironment {
            expected: trust_domain.environment,
            attested: attestation.environment,
        };
    }

    // 2. Trust-domain chain.
    if attestation.chain_id != trust_domain.chain_id || candidate.chain_id != trust_domain.chain_id
    {
        return AuthorityCustodyValidationOutcome::WrongChain {
            expected: trust_domain.chain_id.clone(),
            attested: attestation.chain_id.clone(),
        };
    }

    // 3. Trust-domain genesis.
    if attestation.genesis_hash != trust_domain.genesis_hash
        || candidate.genesis_hash != trust_domain.genesis_hash
    {
        return AuthorityCustodyValidationOutcome::WrongGenesis {
            expected: trust_domain.genesis_hash.clone(),
            attested: attestation.genesis_hash.clone(),
        };
    }

    // 4. Authority root fingerprint binding.
    if attestation.authority_root_fingerprint != trust_domain.authority_root_fingerprint {
        return AuthorityCustodyValidationOutcome::WrongAuthorityRoot {
            expected: trust_domain.authority_root_fingerprint.clone(),
            attested: attestation.authority_root_fingerprint.clone(),
        };
    }

    // 5. Bundle-signing key fingerprint binding.
    if attestation.bundle_signing_key_fingerprint != candidate.active_bundle_signing_key_fingerprint {
        return AuthorityCustodyValidationOutcome::WrongSigningKeyFingerprint {
            expected: candidate.active_bundle_signing_key_fingerprint.clone(),
            attested: attestation.bundle_signing_key_fingerprint.clone(),
        };
    }

    // 6. Candidate digest binding.
    if attestation.candidate_digest != expected_candidate_digest {
        return AuthorityCustodyValidationOutcome::WrongCandidateDigest {
            expected: expected_candidate_digest.to_string(),
            attested: attestation.candidate_digest.clone(),
        };
    }

    // 7. Authority-domain sequence binding.
    if attestation.authority_domain_sequence != expected_authority_domain_sequence {
        return AuthorityCustodyValidationOutcome::WrongAuthorityDomainSequence {
            expected: expected_authority_domain_sequence,
            attested: attestation.authority_domain_sequence,
        };
    }

    // 8. Lifecycle action binding.
    if attestation.lifecycle_action != expected_lifecycle_action {
        return AuthorityCustodyValidationOutcome::WrongLifecycleAction {
            expected: expected_lifecycle_action,
            attested: attestation.lifecycle_action,
        };
    }

    // 9. Governance authority class binding (treated like lifecycle
    //    action for the purposes of typed reject — reuses the typed
    //    "wrong lifecycle action" surface only when it matters; here
    //    we surface it via a malformed-attestation reject because
    //    Run 188 does not carry a separate "wrong governance
    //    authority class" outcome, matching Run 186 boundary shape).
    if attestation.governance_authority_class != expected_governance_authority_class {
        return AuthorityCustodyValidationOutcome::CustodyAttestationMalformed {
            reason: format!(
                "governance authority class mismatch: expected {}, attested {}",
                expected_governance_authority_class.tag(),
                attestation.governance_authority_class.tag()
            ),
        };
    }

    // 10. Custody attestation digest presence + non-emptiness.
    if attestation.custody_attestation_digest.is_empty() {
        return AuthorityCustodyValidationOutcome::CustodyAttestationMissing;
    }

    // 11. Custody key id presence (malformed if empty).
    if attestation.custody_key_id.is_empty() {
        return AuthorityCustodyValidationOutcome::CustodyAttestationMalformed {
            reason: "custody_key_id is empty".to_string(),
        };
    }

    // 12. Custody key id binding (when expected).
    if let Some(expected_key_id) = expected_custody_key_id {
        if attestation.custody_key_id != expected_key_id {
            return AuthorityCustodyValidationOutcome::CustodyKeyIdMismatch {
                expected: expected_key_id.to_string(),
                attested: attestation.custody_key_id.clone(),
            };
        }
    }

    // 13. Custody suite acceptance — Run 188 only accepts the Run 159
    //     PQC signing suite as a custody suite. Any other id is
    //     rejected as `UnsupportedCustodySuite`.
    if attestation.custody_suite_id != PQC_LIFECYCLE_SUITE_ML_DSA_44 {
        return AuthorityCustodyValidationOutcome::UnsupportedCustodySuite {
            suite_id: attestation.custody_suite_id,
        };
    }

    // 14. Freshness / expiry window (when present).
    if let (Some(freshness_unix), Some(expires_at_unix)) =
        (attestation.freshness_unix, attestation.expires_at_unix)
    {
        if expires_at_unix <= freshness_unix {
            return AuthorityCustodyValidationOutcome::CustodyAttestationMalformed {
                reason: "expires_at_unix must be strictly greater than freshness_unix"
                    .to_string(),
            };
        }
        if now_unix < freshness_unix || now_unix >= expires_at_unix {
            return AuthorityCustodyValidationOutcome::CustodyAttestationExpired { now_unix };
        }
    } else if attestation.freshness_unix.is_some() != attestation.expires_at_unix.is_some() {
        return AuthorityCustodyValidationOutcome::CustodyAttestationMalformed {
            reason: "freshness_unix and expires_at_unix must both be set or both be unset"
                .to_string(),
        };
    }

    // 15. Custody class + policy decision. The order matters: the
    //     production-class placeholders fail closed BEFORE the policy
    //     gate so a "RemoteSigner" attestation under
    //     `DevnetLocalAllowed` is still surfaced as
    //     `RemoteSignerUnavailable`, not as
    //     `PolicyRefusesCustodyClass`. Likewise, `Unknown` is
    //     refused before anything else custody-class-specific.
    match attestation.custody_class {
        AuthorityCustodyClass::Unknown => {
            return AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected;
        }
        AuthorityCustodyClass::RemoteSigner => {
            return AuthorityCustodyValidationOutcome::RemoteSignerUnavailable;
        }
        AuthorityCustodyClass::Kms => {
            return AuthorityCustodyValidationOutcome::KmsUnavailable;
        }
        AuthorityCustodyClass::Hsm => {
            return AuthorityCustodyValidationOutcome::HsmUnavailable;
        }
        AuthorityCustodyClass::FixtureLocalKey | AuthorityCustodyClass::LocalOperatorKey => {}
    }

    // 16. MainNet trust domain — fixture/local custody is rejected by
    //     symbol regardless of policy. This layer is intentionally
    //     ahead of the policy gate so a misconfigured policy can
    //     never silently elevate fixture/local custody to MainNet.
    if trust_domain.environment == TrustBundleEnvironment::Mainnet {
        return match attestation.custody_class {
            AuthorityCustodyClass::FixtureLocalKey => {
                AuthorityCustodyValidationOutcome::FixtureCustodyRejectedForMainNet
            }
            AuthorityCustodyClass::LocalOperatorKey => {
                AuthorityCustodyValidationOutcome::LocalCustodyRejectedForMainNet
            }
            // Other classes were already returned above.
            _ => AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected,
        };
    }

    // 17. Production-custody policies refuse fixture/local custody by
    //     symbol — Run 188 has no real backend, so the typed surface
    //     is the explicit "production custody unavailable" or, on
    //     MainNet, the matching MainNet-specific reject.
    if policy.requires_production_custody() {
        return match policy {
            AuthorityCustodyPolicy::MainnetProductionCustodyRequired => {
                AuthorityCustodyValidationOutcome::MainNetProductionCustodyUnavailable
            }
            AuthorityCustodyPolicy::ProductionCustodyRequired => {
                AuthorityCustodyValidationOutcome::ProductionCustodyUnavailable { policy }
            }
            _ => unreachable!("requires_production_custody covers only the two production policies"),
        };
    }

    // 18. Policy-class compatibility (DevNet/TestNet only beyond this
    //     point).
    match (policy, attestation.custody_class, trust_domain.environment) {
        (
            AuthorityCustodyPolicy::FixtureOnly,
            AuthorityCustodyClass::FixtureLocalKey,
            TrustBundleEnvironment::Devnet | TrustBundleEnvironment::Testnet,
        ) => AuthorityCustodyValidationOutcome::AcceptedFixtureCustody {
            custody_key_id: attestation.custody_key_id.clone(),
            environment: trust_domain.environment,
        },
        (
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            AuthorityCustodyClass::FixtureLocalKey,
            TrustBundleEnvironment::Devnet,
        )
        | (
            AuthorityCustodyPolicy::TestnetLocalAllowed,
            AuthorityCustodyClass::FixtureLocalKey,
            TrustBundleEnvironment::Testnet,
        ) => AuthorityCustodyValidationOutcome::AcceptedFixtureCustody {
            custody_key_id: attestation.custody_key_id.clone(),
            environment: trust_domain.environment,
        },
        (
            AuthorityCustodyPolicy::DevnetLocalAllowed,
            AuthorityCustodyClass::LocalOperatorKey,
            TrustBundleEnvironment::Devnet,
        )
        | (
            AuthorityCustodyPolicy::TestnetLocalAllowed,
            AuthorityCustodyClass::LocalOperatorKey,
            TrustBundleEnvironment::Testnet,
        ) => AuthorityCustodyValidationOutcome::AcceptedLocalOperatorCustody {
            custody_key_id: attestation.custody_key_id.clone(),
            environment: trust_domain.environment,
        },
        (policy, class, _) => AuthorityCustodyValidationOutcome::PolicyRefusesCustodyClass {
            policy,
            class,
        },
    }
}

// ===========================================================================
// Combined lifecycle + governance + custody helper
// ===========================================================================

/// Run 188 — typed combined decision for a lifecycle + governance +
/// custody preflight.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleGovernanceCustodyOutcome {
    /// The lifecycle transition validates AND the custody attestation
    /// validates under the active policy. Carries both the typed
    /// lifecycle outcome and the typed custody outcome. **Acceptance
    /// is evidence-only.** It does not enable MainNet apply, does
    /// not perform a Run 070 call, does not write a marker, does not
    /// burn a sequence number, does not swap live trust, and does
    /// not evict sessions.
    Accepted {
        lifecycle_outcome: AuthorityLifecycleTransitionOutcome,
        custody_outcome: AuthorityCustodyValidationOutcome,
    },
    /// The lifecycle transition rejected. Carries the typed
    /// lifecycle reject. Custody validation was not attempted.
    LifecycleRejected(AuthorityLifecycleTransitionOutcome),
    /// The lifecycle transition validated but custody validation
    /// rejected. Carries the typed custody reject AND the accepted
    /// lifecycle outcome so the operator log line can record
    /// "lifecycle valid + custody invalid".
    CustodyRejected {
        lifecycle_outcome: AuthorityLifecycleTransitionOutcome,
        custody_outcome: AuthorityCustodyValidationOutcome,
    },
    /// MainNet trust domain — peer-driven apply remains the Run 147 /
    /// 148 / 152 FATAL refusal regardless of custody outcome. This
    /// variant is surfaced when the calling surface explicitly
    /// requests a MainNet peer-driven-apply preflight.
    MainNetPeerDrivenApplyRefused,
}

impl LifecycleGovernanceCustodyOutcome {
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::Accepted { .. })
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept()
    }
}

/// Run 188 — pure composition helper.
///
/// Calls Run 159 lifecycle validation, then (if accepted) calls the
/// Run 188 custody validator under the active policy, and returns a
/// typed combined decision. Performs no I/O, writes no marker, writes
/// no sequence, mutates no live trust, evicts no sessions, never
/// invokes Run 070.
///
/// `expected_governance_authority_class` is supplied by the calling
/// surface (e.g. `GenesisBound` for a routine rotation; a future run
/// may pass `OnChainGovernance` once the Run 178+ proof verifier
/// surface delivers a typed accepted-class decision). Run 188 does
/// not call the Run 163 / 178 / 186 governance verifier itself —
/// the calling surface is expected to thread the already-validated
/// governance class in. This keeps the helper pure and avoids
/// duplicating Run 178 / 186 binding checks.
#[allow(clippy::too_many_arguments)]
pub fn validate_lifecycle_governance_and_custody(
    custody_attestation: &AuthorityCustodyAttestation,
    candidate: &PersistentAuthorityStateRecordV2,
    persisted: Option<&PersistentAuthorityStateRecordVersioned>,
    trust_domain: &AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&str>,
    policy: AuthorityCustodyPolicy,
    now_unix: u64,
) -> LifecycleGovernanceCustodyOutcome {
    let lifecycle_outcome = validate_v2_lifecycle_transition(persisted, candidate, trust_domain);
    if lifecycle_outcome.is_reject() {
        return LifecycleGovernanceCustodyOutcome::LifecycleRejected(lifecycle_outcome);
    }

    let custody_outcome = validate_authority_custody_attestation(
        custody_attestation,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        policy,
        now_unix,
    );

    if custody_outcome.is_accept() {
        LifecycleGovernanceCustodyOutcome::Accepted {
            lifecycle_outcome,
            custody_outcome,
        }
    } else {
        LifecycleGovernanceCustodyOutcome::CustodyRejected {
            lifecycle_outcome,
            custody_outcome,
        }
    }
}

/// Run 188 — explicit fail-closed helper.
///
/// Returns `true` iff the trust-domain environment is MainNet. The
/// helper encodes, at the typed Run 188 boundary, the rule that
/// MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
/// refusal regardless of any custody attestation contents. The
/// helper is pure data — it never reads custody material.
pub fn mainnet_peer_driven_apply_remains_refused_under_custody_boundary(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 188 — explicit fail-closed helper.
///
/// Returns `true` iff peer-majority / gossip count *cannot* satisfy
/// custody. Run 188 always returns `true`: custody is a per-key
/// authority decision and is never satisfiable by counting peers.
/// Provided as a grep-verifiable named symbol so a future operator
/// log can record the rule explicitly.
pub fn peer_majority_cannot_satisfy_custody() -> bool {
    true
}

/// Run 188 — explicit fail-closed helper.
///
/// Returns `true` iff local operator config alone cannot satisfy
/// MainNet production custody. Run 188 always returns `true`. The
/// helper is grep-verifiable for an operator-log line.
pub fn local_operator_config_alone_cannot_satisfy_mainnet_production_custody() -> bool {
    true
}
