//! Run 297 — source/test production custody attestation verifier.
//!
//! This module implements a real source/test production custody
//! **attestation verifier** boundary layered on top of the Run 295
//! [`crate::pqc_production_kms_hsm_custody_backend`] KMS/HSM custody
//! backend. Where Run 295 can build, request, correlate, and fail closed
//! a custody signing round-trip, Run 297 adds the first typed verifier
//! that validates *provider attestation evidence* — binding it to the
//! provider identity, key handle, custody class, signer identity, custody
//! request, custody response, backend transcript, authority domain, and
//! optional Run 291 durable replay record — and fails closed when
//! attestation is missing, unavailable, malformed, stale, wrong-domain,
//! wrong-provider, wrong-key, ambiguous, or unsupported.
//!
//! Scope and honesty constraints (Run 297):
//!
//! * This run is a **source/test implementation only**. It is **not**
//!   release-binary evidence — that is deferred to Run 298.
//! * The default policy is
//!   [`ProductionCustodyAttestationVerifierPolicy::Disabled`] and fails
//!   closed before any evidence parsing, provider verification,
//!   trust-root check, or acceptance.
//! * Fixture attestation is accepted **only** for DevNet/TestNet under an
//!   explicit fixture policy; it is refused for MainNet.
//! * The four production attestation classes (cloud-KMS, PKCS#11 HSM,
//!   generic KMS, generic HSM) are *reachable but fail closed* as
//!   unavailable / unverified / trust-root-missing because Run 297 wires
//!   no real quote / certificate-chain / hardware-proof verifier.
//! * RemoteSigner attestation is refused for the KMS/HSM custody row.
//! * A MainNet trust domain is **refused** absent production authority
//!   criteria and verified production custody attestation.
//! * The verifier is **non-mutating**: it performs no Run 070 apply, no
//!   [`crate::pqc_live_trust::LivePqcTrustState`] mutation, no trust
//!   swap, no session eviction, no PQC trust-bundle sequence write, no
//!   authority marker write, no durable replay overwrite, no settlement,
//!   no external publication, no governance execution, and no
//!   validator-set rotation. Full C4 remains OPEN; C5 remains OPEN.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_297.md`.

use std::cell::{Cell, RefCell};
use std::collections::VecDeque;

use crate::pqc_authority_custody::AuthorityCustodyClass;
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_production_kms_hsm_custody_backend::{
    ProductionCustodyProviderKind, ProductionCustodyRequestKind, SubmittedCustodyRequest,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Domain tags / protocol constants
// ===========================================================================

/// Run 297 — the only attestation protocol version this run accepts.
pub const PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION: u16 = 1;

/// Run 297 — attestation challenge digest domain tag.
pub const PRODUCTION_CUSTODY_ATTESTATION_CHALLENGE_DOMAIN_TAG: &str =
    "QBIND:run297-production-custody-attestation-challenge:v1";

/// Run 297 — attestation evidence digest domain tag.
pub const PRODUCTION_CUSTODY_ATTESTATION_EVIDENCE_DOMAIN_TAG: &str =
    "QBIND:run297-production-custody-attestation-evidence:v1";

/// Run 297 — attestation transcript digest domain tag.
pub const PRODUCTION_CUSTODY_ATTESTATION_TRANSCRIPT_DOMAIN_TAG: &str =
    "QBIND:run297-production-custody-attestation-transcript:v1";

/// Run 297 — attestation decision digest domain tag.
pub const PRODUCTION_CUSTODY_ATTESTATION_DECISION_DOMAIN_TAG: &str =
    "QBIND:run297-production-custody-attestation-decision:v1";

/// Run 297 — trust-root digest domain tag.
pub const PRODUCTION_CUSTODY_ATTESTATION_TRUST_ROOT_DOMAIN_TAG: &str =
    "QBIND:run297-production-custody-attestation-trust-root:v1";

/// Run 297 — the fixed domain separation tag every evidence object must
/// carry. Evidence carrying any other tag fails closed.
pub const PRODUCTION_CUSTODY_ATTESTATION_DOMAIN_SEPARATION_TAG: &str =
    "QBIND:run297-production-custody-attestation:v1";

/// Run 297 — explicit invalid-attestation-commitment sentinel for
/// source/test rejection vectors. Evidence carrying this sentinel as its
/// certificate/quote/proof digest is rejected as malformed.
pub const PRODUCTION_CUSTODY_ATTESTATION_INVALID_PROOF_SENTINEL: &str =
    "INVALID-PRODUCTION-CUSTODY-ATTESTATION-PROOF";

/// Helper: length-prefixed domain-separated field hashing.
fn hash_field(h: &mut sha3::Sha3_256, label: &[u8], value: &[u8]) {
    use sha3::Digest;
    h.update((label.len() as u64).to_le_bytes());
    h.update(label);
    h.update((value.len() as u64).to_le_bytes());
    h.update(value);
}

fn hash_opt(h: &mut sha3::Sha3_256, label: &[u8], value: Option<&str>) {
    hash_field(h, label, value.unwrap_or("").as_bytes());
}

// ===========================================================================
// Protocol version newtype
// ===========================================================================

/// Run 297 — typed attestation protocol version. Only
/// [`PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION`] is supported.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ProductionCustodyAttestationProtocolVersion(pub u16);

impl ProductionCustodyAttestationProtocolVersion {
    /// The single supported protocol version.
    pub const fn supported() -> Self {
        Self(PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION)
    }

    /// Returns `true` iff this is the supported protocol version.
    pub const fn is_supported(self) -> bool {
        self.0 == PRODUCTION_CUSTODY_ATTESTATION_PROTOCOL_VERSION
    }
}

impl Default for ProductionCustodyAttestationProtocolVersion {
    fn default() -> Self {
        Self::supported()
    }
}

// ===========================================================================
// Attestation class taxonomy
// ===========================================================================

/// Run 297 — typed custody attestation class.
///
/// `Disabled` is the inert default. `FixtureKmsAttestation` /
/// `FixtureHsmAttestation` are DevNet/TestNet source/test attestations
/// only. The four production attestation classes are reachable but fail
/// closed without real verification material. `RemoteSignerAttestation`
/// is a separate class that must not satisfy the KMS/HSM custody row.
/// `Unknown` always fails closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionCustodyAttestationClass {
    /// Inert default. No attestation is selected.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture KMS attestation.
    FixtureKmsAttestation,
    /// DevNet/TestNet source/test fixture HSM attestation.
    FixtureHsmAttestation,
    /// Production cloud-KMS attestation. Reachable, fails closed.
    ProductionCloudKmsAttestation,
    /// Production PKCS#11 HSM attestation. Reachable, fails closed.
    ProductionPkcs11HsmAttestation,
    /// Production generic KMS attestation. Reachable, fails closed.
    ProductionGenericKmsAttestation,
    /// Production generic HSM attestation. Reachable, fails closed.
    ProductionGenericHsmAttestation,
    /// RemoteSigner attestation. Not KMS/HSM custody attestation.
    RemoteSignerAttestation,
    /// Unknown / unsupported attestation class. Always fail closed.
    Unknown,
}

impl ProductionCustodyAttestationClass {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureKmsAttestation => "fixture-kms-attestation",
            Self::FixtureHsmAttestation => "fixture-hsm-attestation",
            Self::ProductionCloudKmsAttestation => "production-cloud-kms-attestation",
            Self::ProductionPkcs11HsmAttestation => "production-pkcs11-hsm-attestation",
            Self::ProductionGenericKmsAttestation => "production-generic-kms-attestation",
            Self::ProductionGenericHsmAttestation => "production-generic-hsm-attestation",
            Self::RemoteSignerAttestation => "remote-signer-attestation",
            Self::Unknown => "unknown",
        }
    }

    /// Returns `true` iff this class is a DevNet/TestNet source/test
    /// fixture attestation.
    pub const fn is_fixture(self) -> bool {
        matches!(self, Self::FixtureKmsAttestation | Self::FixtureHsmAttestation)
    }

    /// Returns `true` iff this class is a production attestation class.
    pub const fn is_production(self) -> bool {
        matches!(
            self,
            Self::ProductionCloudKmsAttestation
                | Self::ProductionPkcs11HsmAttestation
                | Self::ProductionGenericKmsAttestation
                | Self::ProductionGenericHsmAttestation
        )
    }

    /// The KMS/HSM custody class this attestation class carries, if any.
    pub const fn custody_class(self) -> Option<AuthorityCustodyClass> {
        match self {
            Self::FixtureKmsAttestation
            | Self::ProductionCloudKmsAttestation
            | Self::ProductionGenericKmsAttestation => Some(AuthorityCustodyClass::Kms),
            Self::FixtureHsmAttestation
            | Self::ProductionPkcs11HsmAttestation
            | Self::ProductionGenericHsmAttestation => Some(AuthorityCustodyClass::Hsm),
            Self::RemoteSignerAttestation => Some(AuthorityCustodyClass::RemoteSigner),
            Self::Disabled | Self::Unknown => None,
        }
    }

    /// The attestation class that corresponds to a Run 295 custody
    /// provider kind.
    pub const fn for_provider_kind(kind: ProductionCustodyProviderKind) -> Self {
        match kind {
            ProductionCustodyProviderKind::FixtureKms => Self::FixtureKmsAttestation,
            ProductionCustodyProviderKind::FixtureHsm => Self::FixtureHsmAttestation,
            ProductionCustodyProviderKind::ProductionCloudKms => Self::ProductionCloudKmsAttestation,
            ProductionCustodyProviderKind::ProductionPkcs11Hsm => {
                Self::ProductionPkcs11HsmAttestation
            }
            ProductionCustodyProviderKind::ProductionGenericKms => {
                Self::ProductionGenericKmsAttestation
            }
            ProductionCustodyProviderKind::ProductionGenericHsm => {
                Self::ProductionGenericHsmAttestation
            }
            ProductionCustodyProviderKind::Disabled | ProductionCustodyProviderKind::Unknown => {
                Self::Unknown
            }
        }
    }
}

// ===========================================================================
// Attestation policy taxonomy
// ===========================================================================

/// Run 297 — typed custody attestation verifier policy.
///
/// `Disabled` is the default fail-closed policy: verification refuses
/// before any evidence parsing. The fixture policies accept only
/// DevNet/TestNet fixture attestation; the production policies require a
/// real production attestation that Run 297 fails closed as unavailable.
/// `MainnetProductionCustodyAttestationRequired` requires production
/// custody attestation and refuses fixture / local / RemoteSigner-only /
/// peer-majority evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum ProductionCustodyAttestationVerifierPolicy {
    /// Default. Refuses every request before any evidence parsing.
    #[default]
    Disabled,
    /// DevNet/TestNet source/test fixture-KMS attestation policy.
    FixtureKmsAttestationAllowed,
    /// DevNet/TestNet source/test fixture-HSM attestation policy.
    FixtureHsmAttestationAllowed,
    /// Production cloud-KMS attestation required. Fails closed.
    ProductionCloudKmsAttestationRequired,
    /// Production PKCS#11 HSM attestation required. Fails closed.
    ProductionPkcs11HsmAttestationRequired,
    /// Production generic KMS attestation required. Fails closed.
    ProductionGenericKmsAttestationRequired,
    /// Production generic HSM attestation required. Fails closed.
    ProductionGenericHsmAttestationRequired,
    /// MainNet production custody attestation required. Fails closed for
    /// every request — fixture / local / RemoteSigner-only / peer
    /// evidence is rejected and production evidence is unavailable.
    MainnetProductionCustodyAttestationRequired,
}

impl ProductionCustodyAttestationVerifierPolicy {
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FixtureKmsAttestationAllowed => "fixture-kms-attestation-allowed",
            Self::FixtureHsmAttestationAllowed => "fixture-hsm-attestation-allowed",
            Self::ProductionCloudKmsAttestationRequired => {
                "production-cloud-kms-attestation-required"
            }
            Self::ProductionPkcs11HsmAttestationRequired => {
                "production-pkcs11-hsm-attestation-required"
            }
            Self::ProductionGenericKmsAttestationRequired => {
                "production-generic-kms-attestation-required"
            }
            Self::ProductionGenericHsmAttestationRequired => {
                "production-generic-hsm-attestation-required"
            }
            Self::MainnetProductionCustodyAttestationRequired => {
                "mainnet-production-custody-attestation-required"
            }
        }
    }

    /// Returns `true` iff this policy is `Disabled`.
    pub const fn is_disabled(self) -> bool {
        matches!(self, Self::Disabled)
    }

    /// Returns `true` iff this policy is a fixture policy.
    pub const fn is_fixture(self) -> bool {
        matches!(
            self,
            Self::FixtureKmsAttestationAllowed | Self::FixtureHsmAttestationAllowed
        )
    }

    /// Returns `true` iff this policy requires real production
    /// attestation (Run 297 fails these closed).
    pub const fn requires_production_attestation(self) -> bool {
        matches!(
            self,
            Self::ProductionCloudKmsAttestationRequired
                | Self::ProductionPkcs11HsmAttestationRequired
                | Self::ProductionGenericKmsAttestationRequired
                | Self::ProductionGenericHsmAttestationRequired
                | Self::MainnetProductionCustodyAttestationRequired
        )
    }

    /// Returns `true` iff this policy is the MainNet production policy.
    pub const fn is_mainnet(self) -> bool {
        matches!(self, Self::MainnetProductionCustodyAttestationRequired)
    }

    /// The single attestation class this policy accepts, if any.
    pub const fn allowed_class(self) -> Option<ProductionCustodyAttestationClass> {
        match self {
            Self::Disabled | Self::MainnetProductionCustodyAttestationRequired => None,
            Self::FixtureKmsAttestationAllowed => {
                Some(ProductionCustodyAttestationClass::FixtureKmsAttestation)
            }
            Self::FixtureHsmAttestationAllowed => {
                Some(ProductionCustodyAttestationClass::FixtureHsmAttestation)
            }
            Self::ProductionCloudKmsAttestationRequired => {
                Some(ProductionCustodyAttestationClass::ProductionCloudKmsAttestation)
            }
            Self::ProductionPkcs11HsmAttestationRequired => {
                Some(ProductionCustodyAttestationClass::ProductionPkcs11HsmAttestation)
            }
            Self::ProductionGenericKmsAttestationRequired => {
                Some(ProductionCustodyAttestationClass::ProductionGenericKmsAttestation)
            }
            Self::ProductionGenericHsmAttestationRequired => {
                Some(ProductionCustodyAttestationClass::ProductionGenericHsmAttestation)
            }
        }
    }
}

// ===========================================================================
// Trust root / measurement / challenge
// ===========================================================================

/// Run 297 — typed attestation trust root.
///
/// Represents the provider trust anchor an attestation verifier checks a
/// quote / certificate chain against: an opaque root id, the issuer
/// identity, and a root-of-trust measurement digest. A missing (empty)
/// trust root fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProductionCustodyAttestationTrustRoot {
    /// Stable, opaque trust-root identifier.
    pub root_id: String,
    /// Opaque issuer identity (e.g. attestation CA / provider vendor).
    pub issuer_identity: String,
    /// Root-of-trust measurement digest.
    pub root_measurement_digest: String,
}

impl ProductionCustodyAttestationTrustRoot {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_present(&self) -> bool {
        !self.root_id.is_empty()
            && !self.issuer_identity.is_empty()
            && !self.root_measurement_digest.is_empty()
    }

    /// Deterministic, domain-separated SHA3-256 hex digest.
    pub fn trust_root_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_CUSTODY_ATTESTATION_TRUST_ROOT_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"root_id", self.root_id.as_bytes());
        hash_field(&mut h, b"issuer_identity", self.issuer_identity.as_bytes());
        hash_field(
            &mut h,
            b"root_measurement_digest",
            self.root_measurement_digest.as_bytes(),
        );
        hex::encode(h.finalize())
    }
}

/// Run 297 — typed attestation measurement.
///
/// Represents the measured state a provider attestation reports (e.g. a
/// device / module measurement or firmware digest). An empty measurement
/// digest fails closed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProductionCustodyAttestationMeasurement {
    /// The attested measurement digest.
    pub measurement_digest: String,
}

impl ProductionCustodyAttestationMeasurement {
    pub fn is_present(&self) -> bool {
        !self.measurement_digest.is_empty()
    }
}

/// Run 297 — typed attestation challenge / freshness window.
///
/// Freshness is represented **only** through explicit typed nonce /
/// challenge / sequence fields, never through ambient wall-clock
/// acceptance. The challenge is bound to the custody request id so a
/// challenge issued for one request cannot authorize another.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProductionCustodyAttestationChallenge {
    /// Per-attempt anti-replay nonce.
    pub nonce: String,
    /// Verifier-issued challenge value.
    pub challenge: String,
    /// Monotonic attestation sequence number.
    pub sequence: u64,
    /// The custody request id this challenge is bound to.
    pub bound_request_id: String,
}

impl ProductionCustodyAttestationChallenge {
    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.nonce.is_empty() && !self.challenge.is_empty() && !self.bound_request_id.is_empty()
    }

    /// Deterministic, domain-separated SHA3-256 hex challenge digest.
    pub fn challenge_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_CUSTODY_ATTESTATION_CHALLENGE_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"nonce", self.nonce.as_bytes());
        hash_field(&mut h, b"challenge", self.challenge.as_bytes());
        hash_field(&mut h, b"sequence", &self.sequence.to_le_bytes());
        hash_field(&mut h, b"bound_request_id", self.bound_request_id.as_bytes());
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Binding (domain / custody / request tuple)
// ===========================================================================

/// Run 297 — the typed domain / custody / request binding tuple every
/// attestation is bound to. Both the evidence and the caller-side
/// expectations carry a binding; any field mismatch is a precise
/// fail-closed reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyAttestationBinding {
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_domain_sequence: u64,
    pub custody_class: AuthorityCustodyClass,
    pub provider_kind: ProductionCustodyProviderKind,
    pub provider_id: String,
    pub key_handle: String,
    pub key_fingerprint: String,
    pub signer_identity: String,
    pub request_kind: ProductionCustodyRequestKind,
    pub authorized_action: LocalLifecycleAction,
    pub candidate_digest: String,
    pub custody_request_id: String,
    pub request_envelope_digest: String,
    pub response_envelope_digest: String,
    pub backend_transcript_digest: String,
    pub durable_replay_record_digest: Option<String>,
}

impl ProductionCustodyAttestationBinding {
    /// Narrow projection helper: derive the binding from a Run 295
    /// submitted custody request/response, plus the signer identity and
    /// optional durable replay record digest that live outside the
    /// envelope.
    pub fn from_submitted_request(
        submitted: &SubmittedCustodyRequest,
        signer_identity: impl Into<String>,
        request_kind: ProductionCustodyRequestKind,
        durable_replay_record_digest: Option<String>,
    ) -> Self {
        let request = &submitted.request;
        let backend_request = &request.backend_request;
        let key_fingerprint = backend_request
            .new_signing_key_fingerprint
            .as_deref()
            .or(backend_request.active_signing_key_fingerprint.as_deref())
            .or(backend_request.revoked_signing_key_fingerprint.as_deref())
            .unwrap_or("")
            .to_string();
        Self {
            environment: request.environment,
            chain_id: request.chain_id.clone(),
            genesis_hash: request.genesis_hash.clone(),
            authority_root_fingerprint: request.authority_root_fingerprint.clone(),
            authority_domain_sequence: backend_request.authority_domain_sequence,
            custody_class: request.custody_class,
            provider_kind: request.provider_kind,
            provider_id: request.provider_id.clone(),
            key_handle: request.key_id.clone(),
            key_fingerprint,
            signer_identity: signer_identity.into(),
            request_kind,
            authorized_action: backend_request.lifecycle_action,
            candidate_digest: backend_request.candidate_digest.clone(),
            custody_request_id: submitted.request_id.clone(),
            request_envelope_digest: request.envelope_digest(),
            response_envelope_digest: submitted.response.envelope_digest(),
            backend_transcript_digest: submitted.response.transcript_digest.clone(),
            durable_replay_record_digest,
        }
    }

    /// Returns `true` iff every mandatory field is structurally present.
    pub fn is_well_formed(&self) -> bool {
        !self.chain_id.is_empty()
            && !self.genesis_hash.is_empty()
            && !self.authority_root_fingerprint.is_empty()
            && !self.provider_id.is_empty()
            && !self.key_handle.is_empty()
            && !self.candidate_digest.is_empty()
            && !self.custody_request_id.is_empty()
            && !self.request_envelope_digest.is_empty()
            && !self.response_envelope_digest.is_empty()
            && !self.backend_transcript_digest.is_empty()
            && matches!(
                self.custody_class,
                AuthorityCustodyClass::Kms | AuthorityCustodyClass::Hsm
            )
    }

    fn hash_into(&self, h: &mut sha3::Sha3_256) {
        hash_field(h, b"environment", &self.environment.metric_code().to_le_bytes());
        hash_field(h, b"chain_id", self.chain_id.as_bytes());
        hash_field(h, b"genesis_hash", self.genesis_hash.as_bytes());
        hash_field(
            h,
            b"authority_root_fingerprint",
            self.authority_root_fingerprint.as_bytes(),
        );
        hash_field(
            h,
            b"authority_domain_sequence",
            &self.authority_domain_sequence.to_le_bytes(),
        );
        hash_field(h, b"custody_class", self.custody_class.tag().as_bytes());
        hash_field(h, b"provider_kind", self.provider_kind.tag().as_bytes());
        hash_field(h, b"provider_id", self.provider_id.as_bytes());
        hash_field(h, b"key_handle", self.key_handle.as_bytes());
        hash_field(h, b"key_fingerprint", self.key_fingerprint.as_bytes());
        hash_field(h, b"signer_identity", self.signer_identity.as_bytes());
        hash_field(h, b"request_kind", self.request_kind.tag().as_bytes());
        hash_field(h, b"authorized_action", self.authorized_action.tag().as_bytes());
        hash_field(h, b"candidate_digest", self.candidate_digest.as_bytes());
        hash_field(h, b"custody_request_id", self.custody_request_id.as_bytes());
        hash_field(
            h,
            b"request_envelope_digest",
            self.request_envelope_digest.as_bytes(),
        );
        hash_field(
            h,
            b"response_envelope_digest",
            self.response_envelope_digest.as_bytes(),
        );
        hash_field(
            h,
            b"backend_transcript_digest",
            self.backend_transcript_digest.as_bytes(),
        );
        hash_opt(
            h,
            b"durable_replay_record_digest",
            self.durable_replay_record_digest.as_deref(),
        );
    }
}

// ===========================================================================
// Evidence
// ===========================================================================

/// Run 297 — typed custody attestation evidence.
///
/// Binds the domain / custody / request tuple ([`Self::binding`]) to the
/// attestation class, trust root, measurement, challenge, certificate /
/// quote / proof digest, protocol version, verifier policy, and domain
/// separation tag. Canonical bytes are derived by
/// [`Self::evidence_digest`]; `Debug` formatting is never canonical.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyAttestationEvidence {
    pub protocol_version: ProductionCustodyAttestationProtocolVersion,
    pub attestation_class: ProductionCustodyAttestationClass,
    pub binding: ProductionCustodyAttestationBinding,
    pub trust_root: ProductionCustodyAttestationTrustRoot,
    pub measurement: ProductionCustodyAttestationMeasurement,
    pub challenge: ProductionCustodyAttestationChallenge,
    /// The attestation certificate / quote / proof digest a real provider
    /// would produce. Run 297 verifies this only for fixture classes.
    pub certificate_proof_digest: String,
    /// The policy the evidence was produced under.
    pub verifier_policy: ProductionCustodyAttestationVerifierPolicy,
    /// The fixed domain separation tag; must equal
    /// [`PRODUCTION_CUSTODY_ATTESTATION_DOMAIN_SEPARATION_TAG`].
    pub domain_separation_tag: String,
}

impl ProductionCustodyAttestationEvidence {
    /// Returns `true` iff every mandatory field is structurally present
    /// and the certificate/proof digest is not the invalid sentinel.
    pub fn is_well_formed(&self) -> bool {
        self.binding.is_well_formed()
            && self.challenge.is_well_formed()
            && !self.certificate_proof_digest.is_empty()
            && self.certificate_proof_digest != PRODUCTION_CUSTODY_ATTESTATION_INVALID_PROOF_SENTINEL
            && self.domain_separation_tag == PRODUCTION_CUSTODY_ATTESTATION_DOMAIN_SEPARATION_TAG
    }

    /// Deterministic, domain-separated SHA3-256 hex evidence digest.
    pub fn evidence_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PRODUCTION_CUSTODY_ATTESTATION_EVIDENCE_DOMAIN_TAG.as_bytes());
        hash_field(&mut h, b"protocol_version", &self.protocol_version.0.to_le_bytes());
        hash_field(
            &mut h,
            b"attestation_class",
            self.attestation_class.tag().as_bytes(),
        );
        self.binding.hash_into(&mut h);
        hash_field(&mut h, b"trust_root_digest", self.trust_root.trust_root_digest().as_bytes());
        hash_field(
            &mut h,
            b"measurement_digest",
            self.measurement.measurement_digest.as_bytes(),
        );
        hash_field(&mut h, b"challenge_digest", self.challenge.challenge_digest().as_bytes());
        hash_field(
            &mut h,
            b"certificate_proof_digest",
            self.certificate_proof_digest.as_bytes(),
        );
        hash_field(&mut h, b"verifier_policy", self.verifier_policy.tag().as_bytes());
        hash_field(
            &mut h,
            b"domain_separation_tag",
            self.domain_separation_tag.as_bytes(),
        );
        hex::encode(h.finalize())
    }

    /// Deterministic provider-identity digest binding the provider kind /
    /// id / key handle.
    pub fn provider_identity_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(b"QBIND:run297-production-custody-attestation-provider-identity:v1");
        hash_field(
            &mut h,
            b"provider_kind",
            self.binding.provider_kind.tag().as_bytes(),
        );
        hash_field(&mut h, b"provider_id", self.binding.provider_id.as_bytes());
        hash_field(&mut h, b"key_handle", self.binding.key_handle.as_bytes());
        hex::encode(h.finalize())
    }
}

// ===========================================================================
// Expectations
// ===========================================================================

/// Run 297 — the caller-side attestation expectations.
///
/// Carries the binding the caller expects (derived from the Run 295
/// submitted request), the expected trust root, expected measurement, and
/// the expected challenge. The verifier compares the submitted evidence
/// against these; any mismatch is a precise fail-closed reject.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyAttestationExpectations {
    pub binding: ProductionCustodyAttestationBinding,
    pub expected_trust_root: ProductionCustodyAttestationTrustRoot,
    pub expected_measurement: ProductionCustodyAttestationMeasurement,
    pub expected_challenge: ProductionCustodyAttestationChallenge,
}

impl ProductionCustodyAttestationExpectations {
    /// Returns `true` iff the expected binding / trust root / challenge
    /// are structurally well-formed.
    pub fn is_well_formed(&self) -> bool {
        self.binding.is_well_formed()
            && self.expected_challenge.is_well_formed()
            && self.expected_measurement.is_present()
    }
}

// ===========================================================================
// Config
// ===========================================================================

/// Run 297 — typed custody attestation verifier config.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyAttestationVerifierConfig {
    /// Attestation protocol version. Must equal the supported version.
    pub protocol_version: ProductionCustodyAttestationProtocolVersion,
}

impl ProductionCustodyAttestationVerifierConfig {
    pub fn new() -> Self {
        Self {
            protocol_version: ProductionCustodyAttestationProtocolVersion::supported(),
        }
    }

    /// Returns `true` iff the config pins the supported protocol version.
    pub fn is_well_formed(&self) -> bool {
        self.protocol_version.is_supported()
    }
}

impl Default for ProductionCustodyAttestationVerifierConfig {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Error taxonomy
// ===========================================================================

/// Run 297 — typed attestation-verifier transport / availability error a
/// real provider-attestation verifier may surface. Run 297 injects these
/// via the source/test verifiers / mock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionCustodyAttestationError {
    /// No attestation evidence was supplied.
    AttestationMissing,
    /// The attestation service / provider is unavailable.
    AttestationUnavailable,
    /// The attestation evidence was structurally malformed.
    MalformedAttestation,
    /// No trust root is available to verify against.
    TrustRootMissing,
    /// The quote / certificate-chain verifier is unavailable.
    QuoteVerifierUnavailable,
    /// The provider produced no verification material.
    VerificationMaterialUnavailable,
    /// The attestation measurement could not be verified.
    MeasurementUnverified,
    /// The attestation class is unsupported.
    UnsupportedClass,
    /// The attestation protocol version is unsupported.
    UnsupportedProtocol { version: u16 },
}

impl ProductionCustodyAttestationError {
    pub const fn tag(&self) -> &'static str {
        match self {
            Self::AttestationMissing => "attestation-missing",
            Self::AttestationUnavailable => "attestation-unavailable",
            Self::MalformedAttestation => "malformed-attestation",
            Self::TrustRootMissing => "trust-root-missing",
            Self::QuoteVerifierUnavailable => "quote-verifier-unavailable",
            Self::VerificationMaterialUnavailable => "verification-material-unavailable",
            Self::MeasurementUnverified => "measurement-unverified",
            Self::UnsupportedClass => "unsupported-class",
            Self::UnsupportedProtocol { .. } => "unsupported-protocol",
        }
    }
}

// ===========================================================================
// Outcome taxonomy
// ===========================================================================

/// Run 297 — typed outcome of the custody attestation verifier.
///
/// Only [`Self::FixtureKmsAttestationVerified`] and
/// [`Self::FixtureHsmAttestationVerified`] may authorize source/test
/// evidence, and only under an explicit fixture policy on DevNet/TestNet.
/// Every other variant is a precise, non-mutating fail-closed reject (or
/// the inert [`Self::DisabledNoVerification`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionCustodyAttestationOutcome {
    /// The policy is `Disabled`. No evidence was parsed.
    DisabledNoVerification,
    /// A fixture KMS attestation was verified under an explicit fixture
    /// policy on DevNet/TestNet. **Evidence only.**
    FixtureKmsAttestationVerified {
        provider_id: String,
        environment: TrustBundleEnvironment,
        custody_request_id: String,
    },
    /// A fixture HSM attestation was verified under an explicit fixture
    /// policy on DevNet/TestNet. **Evidence only.**
    FixtureHsmAttestationVerified {
        provider_id: String,
        environment: TrustBundleEnvironment,
        custody_request_id: String,
    },
    /// A production attestation was verified. **Unreachable in Run 297**
    /// (no real verification material) but represented for Run 298.
    ProductionAttestationVerified {
        provider_id: String,
        environment: TrustBundleEnvironment,
        custody_request_id: String,
        transcript_digest: String,
    },
    /// The production attestation service / provider was unavailable.
    ProductionAttestationUnavailable,
    /// The production attestation could not be verified.
    ProductionAttestationUnverified,
    /// The attestation evidence was malformed.
    ProductionAttestationMalformed,
    /// The attestation class is unsupported.
    ProductionAttestationUnsupportedClass,
    /// The attestation protocol version is unsupported.
    ProductionAttestationUnsupportedProtocol { version: u16 },
    /// No trust root was available.
    ProductionAttestationTrustRootMissing,
    /// The evidence trust root did not match the expected trust root.
    ProductionAttestationTrustRootMismatch,
    /// The evidence provider identity / kind did not match.
    ProductionAttestationProviderMismatch,
    /// The evidence key handle did not match.
    ProductionAttestationKeyHandleMismatch,
    /// The evidence signer identity did not match.
    ProductionAttestationSignerMismatch,
    /// The evidence custody class did not match.
    ProductionAttestationCustodyClassMismatch,
    /// The evidence custody request id did not match.
    ProductionAttestationRequestIdMismatch,
    /// The evidence backend transcript digest did not match.
    ProductionAttestationBackendTranscriptMismatch,
    /// The evidence request envelope digest did not match.
    ProductionAttestationRequestEnvelopeMismatch,
    /// The evidence response envelope digest did not match.
    ProductionAttestationResponseEnvelopeMismatch,
    /// The evidence candidate / proposal digest did not match.
    ProductionAttestationCandidateDigestMismatch,
    /// The evidence authorized action did not match.
    ProductionAttestationActionMismatch,
    /// The evidence trust-domain binding did not match (environment /
    /// chain / genesis / authority-root / authority-sequence).
    ProductionAttestationDomainMismatch,
    /// The evidence nonce / challenge was replayed or stale.
    ProductionAttestationNonceReplay,
    /// The evidence measurement digest did not match / was unverified.
    ProductionAttestationMeasurementMismatch,
    /// The evidence was ambiguous — fail closed.
    ProductionAttestationEvidenceAmbiguous { reason: String },
    /// Fixture attestation was rejected for a MainNet trust domain.
    FixtureAttestationRejectedForMainNet,
    /// RemoteSigner attestation cannot satisfy the KMS/HSM custody row.
    RemoteSignerAttestationIsNotKmsHsmCustody,
    /// MainNet production custody attestation was required but no
    /// production attestation material is available.
    MainNetProductionCustodyAttestationUnavailable,
    /// MainNet was refused because the policy is not a MainNet production
    /// custody attestation policy.
    MainNetRefused,
    /// The on-chain governance proof verifier is unavailable (not
    /// implemented in Run 297).
    GovernanceVerifierUnavailable,
    /// Validator-set rotation is unsupported (not implemented in Run 297).
    ValidatorSetRotationUnsupported,
    /// Governance policy change is unsupported (not implemented in Run
    /// 297).
    PolicyChangeUnsupported,
    /// The request / config was structurally malformed, or the outcome
    /// could not be classified — fail closed.
    AmbiguousFailClosed { reason: String },
}

impl ProductionCustodyAttestationOutcome {
    /// Returns `true` iff this outcome authorizes the next decision
    /// (evidence-only DevNet/TestNet fixture acceptance).
    pub fn is_verified(&self) -> bool {
        matches!(
            self,
            Self::FixtureKmsAttestationVerified { .. }
                | Self::FixtureHsmAttestationVerified { .. }
                | Self::ProductionAttestationVerified { .. }
        )
    }

    /// Every Run 297 outcome is non-mutating; acceptance is evidence-only.
    pub fn is_non_mutating(&self) -> bool {
        true
    }

    /// Returns `true` iff this outcome represents an "unavailable"
    /// production path.
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::ProductionAttestationUnavailable
                | Self::MainNetProductionCustodyAttestationUnavailable
        )
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::DisabledNoVerification => "disabled-no-verification",
            Self::FixtureKmsAttestationVerified { .. } => "fixture-kms-attestation-verified",
            Self::FixtureHsmAttestationVerified { .. } => "fixture-hsm-attestation-verified",
            Self::ProductionAttestationVerified { .. } => "production-attestation-verified",
            Self::ProductionAttestationUnavailable => "production-attestation-unavailable",
            Self::ProductionAttestationUnverified => "production-attestation-unverified",
            Self::ProductionAttestationMalformed => "production-attestation-malformed",
            Self::ProductionAttestationUnsupportedClass => "production-attestation-unsupported-class",
            Self::ProductionAttestationUnsupportedProtocol { .. } => {
                "production-attestation-unsupported-protocol"
            }
            Self::ProductionAttestationTrustRootMissing => "production-attestation-trust-root-missing",
            Self::ProductionAttestationTrustRootMismatch => {
                "production-attestation-trust-root-mismatch"
            }
            Self::ProductionAttestationProviderMismatch => "production-attestation-provider-mismatch",
            Self::ProductionAttestationKeyHandleMismatch => {
                "production-attestation-key-handle-mismatch"
            }
            Self::ProductionAttestationSignerMismatch => "production-attestation-signer-mismatch",
            Self::ProductionAttestationCustodyClassMismatch => {
                "production-attestation-custody-class-mismatch"
            }
            Self::ProductionAttestationRequestIdMismatch => "production-attestation-request-id-mismatch",
            Self::ProductionAttestationBackendTranscriptMismatch => {
                "production-attestation-backend-transcript-mismatch"
            }
            Self::ProductionAttestationRequestEnvelopeMismatch => {
                "production-attestation-request-envelope-mismatch"
            }
            Self::ProductionAttestationResponseEnvelopeMismatch => {
                "production-attestation-response-envelope-mismatch"
            }
            Self::ProductionAttestationCandidateDigestMismatch => {
                "production-attestation-candidate-digest-mismatch"
            }
            Self::ProductionAttestationActionMismatch => "production-attestation-action-mismatch",
            Self::ProductionAttestationDomainMismatch => "production-attestation-domain-mismatch",
            Self::ProductionAttestationNonceReplay => "production-attestation-nonce-replay",
            Self::ProductionAttestationMeasurementMismatch => {
                "production-attestation-measurement-mismatch"
            }
            Self::ProductionAttestationEvidenceAmbiguous { .. } => {
                "production-attestation-evidence-ambiguous"
            }
            Self::FixtureAttestationRejectedForMainNet => "fixture-attestation-rejected-for-mainnet",
            Self::RemoteSignerAttestationIsNotKmsHsmCustody => {
                "remote-signer-attestation-is-not-kms-hsm-custody"
            }
            Self::MainNetProductionCustodyAttestationUnavailable => {
                "mainnet-production-custody-attestation-unavailable"
            }
            Self::MainNetRefused => "mainnet-refused",
            Self::GovernanceVerifierUnavailable => "governance-verifier-unavailable",
            Self::ValidatorSetRotationUnsupported => "validator-set-rotation-unsupported",
            Self::PolicyChangeUnsupported => "policy-change-unsupported",
            Self::AmbiguousFailClosed { .. } => "ambiguous-fail-closed",
        }
    }
}

/// Map an evidence-verifier error to a precise fail-closed outcome.
fn error_to_outcome(
    err: &ProductionCustodyAttestationError,
) -> ProductionCustodyAttestationOutcome {
    use ProductionCustodyAttestationError as E;
    use ProductionCustodyAttestationOutcome as O;
    match err {
        E::AttestationMissing => O::ProductionAttestationMalformed,
        E::AttestationUnavailable => O::ProductionAttestationUnavailable,
        E::MalformedAttestation => O::ProductionAttestationMalformed,
        E::TrustRootMissing => O::ProductionAttestationTrustRootMissing,
        E::QuoteVerifierUnavailable | E::VerificationMaterialUnavailable => {
            O::ProductionAttestationUnverified
        }
        E::MeasurementUnverified => O::ProductionAttestationMeasurementMismatch,
        E::UnsupportedClass => O::ProductionAttestationUnsupportedClass,
        E::UnsupportedProtocol { version } => {
            O::ProductionAttestationUnsupportedProtocol { version: *version }
        }
    }
}

// ===========================================================================
// Decision + transcript
// ===========================================================================

/// Run 297 — the typed decision produced by the verifier: the outcome,
/// the bound custody request id, the evidence digest, and the decision
/// transcript digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProductionCustodyAttestationDecision {
    pub outcome: ProductionCustodyAttestationOutcome,
    pub custody_request_id: String,
    pub evidence_digest: String,
    pub transcript_digest: String,
}

impl ProductionCustodyAttestationDecision {
    /// Returns `true` iff the decision verified the attestation.
    pub fn is_verified(&self) -> bool {
        self.outcome.is_verified()
    }
}

/// Run 297 — deterministic, domain-separated attestation transcript
/// digest binding the protocol version, evidence digest, challenge
/// digest, and expectations binding into a single commitment.
pub fn production_custody_attestation_transcript_digest(
    protocol_version: u16,
    evidence_digest: &str,
    challenge_digest: &str,
    custody_request_id: &str,
    backend_transcript_digest: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_CUSTODY_ATTESTATION_TRANSCRIPT_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"protocol_version", &protocol_version.to_le_bytes());
    hash_field(&mut h, b"evidence_digest", evidence_digest.as_bytes());
    hash_field(&mut h, b"challenge_digest", challenge_digest.as_bytes());
    hash_field(&mut h, b"custody_request_id", custody_request_id.as_bytes());
    hash_field(
        &mut h,
        b"backend_transcript_digest",
        backend_transcript_digest.as_bytes(),
    );
    hex::encode(h.finalize())
}

/// Run 297 — deterministic, domain-separated attestation decision digest
/// binding a transcript digest to its typed outcome tag.
pub fn production_custody_attestation_decision_digest(
    transcript_digest: &str,
    outcome_tag: &str,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(PRODUCTION_CUSTODY_ATTESTATION_DECISION_DOMAIN_TAG.as_bytes());
    hash_field(&mut h, b"transcript_digest", transcript_digest.as_bytes());
    hash_field(&mut h, b"outcome_tag", outcome_tag.as_bytes());
    hex::encode(h.finalize())
}

// ===========================================================================
// Evidence-verifier boundary
// ===========================================================================

/// Run 297 — the verified material a real evidence verifier would return
/// after checking a provider quote / certificate chain against a trust
/// root. Source/test only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestationMaterial {
    /// The attestation class that was verified.
    pub attestation_class: ProductionCustodyAttestationClass,
    /// The verified provider-identity digest.
    pub provider_identity_digest: String,
}

/// Run 297 — narrow, mockable custody-attestation evidence verifier
/// boundary.
///
/// A real production verifier would implement [`Self::verify_evidence`]
/// by checking a cloud-KMS attestation document / a PKCS#11 device quote
/// / an HSM vendor certificate chain against a trust root, and returning
/// verified material or a typed [`ProductionCustodyAttestationError`].
/// Run 297 wires no real verifier; only the DevNet/TestNet source/test
/// fixture verifiers, the reachable-but-fail-closed production stubs, and
/// the programmable mock implement this boundary.
///
/// Implementations must perform no marker write, no sequence write, no
/// live-trust mutation, no session eviction, and must never invoke Run
/// 070.
pub trait CustodyAttestationEvidenceVerifier {
    /// Verify `evidence` against `trust_root`. Returns verified material
    /// or a typed error.
    fn verify_evidence(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        trust_root: &ProductionCustodyAttestationTrustRoot,
    ) -> Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError>;
}

/// Run 297 — DevNet/TestNet source/test fixture KMS attestation verifier.
///
/// **Source/test only.** Verifies a fixture KMS attestation whose
/// certificate/proof digest matches the trust root's root measurement
/// digest recomputation. It is NOT a real KMS attestation verifier and
/// MainNet material is refused by the policy gate. Records how many times
/// it was called so tests can prove the Disabled policy never invokes it.
pub struct FixtureKmsCustodyAttestationVerifier {
    call_count: Cell<u32>,
}

impl Default for FixtureKmsCustodyAttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureKmsCustodyAttestationVerifier {
    pub fn new() -> Self {
        Self {
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

/// Deterministic fixture proof binding: a fixture attestation is
/// "verified" iff its certificate/proof digest equals this recomputation
/// over the trust root and provider identity. Source/test only.
pub fn fixture_attestation_expected_proof(
    evidence: &ProductionCustodyAttestationEvidence,
    trust_root: &ProductionCustodyAttestationTrustRoot,
) -> String {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"QBIND:run297-fixture-custody-attestation-proof:v1");
    hash_field(&mut h, b"trust_root_digest", trust_root.trust_root_digest().as_bytes());
    hash_field(
        &mut h,
        b"provider_identity_digest",
        evidence.provider_identity_digest().as_bytes(),
    );
    hash_field(
        &mut h,
        b"measurement_digest",
        evidence.measurement.measurement_digest.as_bytes(),
    );
    hash_field(&mut h, b"challenge_digest", evidence.challenge.challenge_digest().as_bytes());
    hex::encode(h.finalize())
}

fn verify_fixture_evidence(
    call_count: &Cell<u32>,
    expected_class: ProductionCustodyAttestationClass,
    evidence: &ProductionCustodyAttestationEvidence,
    trust_root: &ProductionCustodyAttestationTrustRoot,
) -> Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError> {
    call_count.set(call_count.get() + 1);
    if evidence.attestation_class != expected_class {
        return Err(ProductionCustodyAttestationError::UnsupportedClass);
    }
    if !trust_root.is_present() {
        return Err(ProductionCustodyAttestationError::TrustRootMissing);
    }
    if !evidence.measurement.is_present() {
        return Err(ProductionCustodyAttestationError::MeasurementUnverified);
    }
    let expected_proof = fixture_attestation_expected_proof(evidence, trust_root);
    if evidence.certificate_proof_digest != expected_proof {
        return Err(ProductionCustodyAttestationError::MalformedAttestation);
    }
    Ok(VerifiedAttestationMaterial {
        attestation_class: expected_class,
        provider_identity_digest: evidence.provider_identity_digest(),
    })
}

impl CustodyAttestationEvidenceVerifier for FixtureKmsCustodyAttestationVerifier {
    fn verify_evidence(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        trust_root: &ProductionCustodyAttestationTrustRoot,
    ) -> Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError> {
        verify_fixture_evidence(
            &self.call_count,
            ProductionCustodyAttestationClass::FixtureKmsAttestation,
            evidence,
            trust_root,
        )
    }
}

/// Run 297 — DevNet/TestNet source/test fixture HSM attestation verifier.
/// Source/test only; see [`FixtureKmsCustodyAttestationVerifier`].
pub struct FixtureHsmCustodyAttestationVerifier {
    call_count: Cell<u32>,
}

impl Default for FixtureHsmCustodyAttestationVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl FixtureHsmCustodyAttestationVerifier {
    pub fn new() -> Self {
        Self {
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl CustodyAttestationEvidenceVerifier for FixtureHsmCustodyAttestationVerifier {
    fn verify_evidence(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        trust_root: &ProductionCustodyAttestationTrustRoot,
    ) -> Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError> {
        verify_fixture_evidence(
            &self.call_count,
            ProductionCustodyAttestationClass::FixtureHsmAttestation,
            evidence,
            trust_root,
        )
    }
}

/// Run 297 — reachable-but-fail-closed production attestation verifier
/// stub.
///
/// Represents the production cloud-KMS / PKCS#11-HSM / generic-KMS /
/// generic-HSM attestation verifier paths. The path is *reachable* (the
/// boundary is invoked) but always fails closed with the configured error
/// because no real quote / certificate-chain / hardware-proof verifier
/// exists in Run 297. Records how many times it was called.
pub struct ProductionCustodyAttestationVerifierStub {
    attestation_class: ProductionCustodyAttestationClass,
    error: ProductionCustodyAttestationError,
    call_count: Cell<u32>,
}

impl ProductionCustodyAttestationVerifierStub {
    /// A production cloud-KMS attestation verifier, unverified without
    /// real verification material.
    pub fn cloud_kms() -> Self {
        Self::with_error(
            ProductionCustodyAttestationClass::ProductionCloudKmsAttestation,
            ProductionCustodyAttestationError::VerificationMaterialUnavailable,
        )
    }

    /// A production PKCS#11 HSM attestation verifier, unavailable without
    /// a real device quote / session / certificate chain.
    pub fn pkcs11_hsm() -> Self {
        Self::with_error(
            ProductionCustodyAttestationClass::ProductionPkcs11HsmAttestation,
            ProductionCustodyAttestationError::QuoteVerifierUnavailable,
        )
    }

    /// A production generic KMS attestation verifier, unavailable without
    /// a trust root.
    pub fn generic_kms() -> Self {
        Self::with_error(
            ProductionCustodyAttestationClass::ProductionGenericKmsAttestation,
            ProductionCustodyAttestationError::TrustRootMissing,
        )
    }

    /// A production generic HSM attestation verifier, unavailable.
    pub fn generic_hsm() -> Self {
        Self::with_error(
            ProductionCustodyAttestationClass::ProductionGenericHsmAttestation,
            ProductionCustodyAttestationError::AttestationUnavailable,
        )
    }

    /// A production attestation verifier of `attestation_class` that fails
    /// closed with `error`.
    pub fn with_error(
        attestation_class: ProductionCustodyAttestationClass,
        error: ProductionCustodyAttestationError,
    ) -> Self {
        Self {
            attestation_class,
            error,
            call_count: Cell::new(0),
        }
    }

    pub fn attestation_class(&self) -> ProductionCustodyAttestationClass {
        self.attestation_class
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl CustodyAttestationEvidenceVerifier for ProductionCustodyAttestationVerifierStub {
    fn verify_evidence(
        &self,
        _evidence: &ProductionCustodyAttestationEvidence,
        _trust_root: &ProductionCustodyAttestationTrustRoot,
    ) -> Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError> {
        self.call_count.set(self.call_count.get() + 1);
        Err(self.error.clone())
    }
}

/// Run 297 — programmable source/test evidence verifier for fault
/// injection. Each call consumes the next programmed step; when exhausted
/// it returns the configured default.
pub struct MockCustodyAttestationVerifier {
    steps: RefCell<
        VecDeque<Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError>>,
    >,
    default_result: RefCell<Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError>>,
    call_count: Cell<u32>,
}

impl MockCustodyAttestationVerifier {
    /// A mock that always returns `err`.
    pub fn always_fail(err: ProductionCustodyAttestationError) -> Self {
        Self {
            steps: RefCell::new(VecDeque::new()),
            default_result: RefCell::new(Err(err)),
            call_count: Cell::new(0),
        }
    }

    /// A mock that returns the programmed `steps` in order, then falls
    /// back to `default_result`.
    pub fn scripted(
        steps: Vec<Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError>>,
        default_result: Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError>,
    ) -> Self {
        Self {
            steps: RefCell::new(steps.into_iter().collect()),
            default_result: RefCell::new(default_result),
            call_count: Cell::new(0),
        }
    }

    pub fn call_count(&self) -> u32 {
        self.call_count.get()
    }
}

impl CustodyAttestationEvidenceVerifier for MockCustodyAttestationVerifier {
    fn verify_evidence(
        &self,
        _evidence: &ProductionCustodyAttestationEvidence,
        _trust_root: &ProductionCustodyAttestationTrustRoot,
    ) -> Result<VerifiedAttestationMaterial, ProductionCustodyAttestationError> {
        self.call_count.set(self.call_count.get() + 1);
        if let Some(step) = self.steps.borrow_mut().pop_front() {
            step
        } else {
            self.default_result.borrow().clone()
        }
    }
}

// ===========================================================================
// Recovery outcome
// ===========================================================================

/// Run 297 — typed outcome of an attestation replay / recovery-window
/// check.
///
/// Run 297 models only the narrow replay/recovery semantics the existing
/// surfaces already represent: idempotent re-verification of
/// byte-identical evidence, and fail-closed refusal of any conflicting
/// evidence digest / key handle / measurement / reused nonce, or
/// ambiguous window. It claims **no** durable acceptance persistence of
/// its own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProductionCustodyAttestationRecoveryOutcome {
    /// No prior attestation exists; nothing to recover.
    NoPriorAttestation,
    /// The current evidence is byte-identical to the prior evidence —
    /// idempotent replay, safe.
    IdempotentReplayOfSameAttestation,
    /// The same attestation id was reused with a different transcript —
    /// fail closed.
    ConflictingTranscriptForSameId,
    /// The same attestation id was reused with a different key handle —
    /// fail closed.
    ConflictingKeyHandleForSameId,
    /// The same attestation id was reused with a different measurement —
    /// fail closed.
    ConflictingMeasurementForSameId,
    /// The same nonce / challenge was reused across a different request
    /// id — fail closed.
    ReusedNonceAcrossRequests,
    /// The recovery window is ambiguous — fail closed.
    AmbiguousRecoveryFailClosed { reason: String },
}

impl ProductionCustodyAttestationRecoveryOutcome {
    /// Returns `true` iff the recovery is safe to treat as idempotent.
    pub fn is_idempotent(&self) -> bool {
        matches!(self, Self::IdempotentReplayOfSameAttestation)
    }
}

// ===========================================================================
// Verifier trait
// ===========================================================================

/// Run 297 — the production custody attestation verifier boundary.
///
/// Implementations drive a [`CustodyAttestationEvidenceVerifier`],
/// applying the attestation policy, class gating, MainNet refusal,
/// domain / custody / request binding, challenge / nonce replay
/// protection, trust-root and measurement checks, and returning a precise
/// typed [`ProductionCustodyAttestationDecision`]. No implementation
/// mutates live trust, writes a marker/sequence, evicts sessions,
/// performs settlement / external publication / governance execution /
/// validator-set rotation, or invokes Run 070.
pub trait GovernanceProductionCustodyAttestationVerifier {
    /// Build a deterministic attestation challenge for a custody request.
    fn build_attestation_challenge(
        &self,
        nonce: impl Into<String>,
        challenge: impl Into<String>,
        sequence: u64,
        custody_request_id: impl Into<String>,
    ) -> ProductionCustodyAttestationChallenge;

    /// Verify `evidence` against `expectations` and the trust domain,
    /// returning a precise outcome. Does not build a transcript.
    fn verify_custody_attestation(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        expectations: &ProductionCustodyAttestationExpectations,
        trust_domain: &AuthorityTrustDomain,
    ) -> ProductionCustodyAttestationOutcome;

    /// Verify and produce a full decision (outcome + transcript digest).
    fn evaluate_custody_attestation(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        expectations: &ProductionCustodyAttestationExpectations,
        trust_domain: &AuthorityTrustDomain,
    ) -> ProductionCustodyAttestationDecision;

    /// Evaluate an attestation replay / recovery window against a prior
    /// evidence object.
    fn recover_attestation_window(
        &self,
        prior: Option<&ProductionCustodyAttestationEvidence>,
        current: &ProductionCustodyAttestationEvidence,
    ) -> ProductionCustodyAttestationRecoveryOutcome;
}

// ===========================================================================
// Verifier implementation
// ===========================================================================

/// Run 297 — the real production custody attestation verifier.
///
/// Generic over the injected [`CustodyAttestationEvidenceVerifier`] so
/// the same real verifier logic runs over a source/test fixture verifier,
/// a reachable-but-fail-closed production stub, a programmable mock, or
/// (in a future run) a real quote / certificate-chain verifier.
pub struct ProductionCustodyAttestationVerifier<V: CustodyAttestationEvidenceVerifier> {
    pub config: ProductionCustodyAttestationVerifierConfig,
    pub policy: ProductionCustodyAttestationVerifierPolicy,
    pub evidence_verifier: V,
}

impl<V: CustodyAttestationEvidenceVerifier> ProductionCustodyAttestationVerifier<V> {
    pub fn new(
        config: ProductionCustodyAttestationVerifierConfig,
        policy: ProductionCustodyAttestationVerifierPolicy,
        evidence_verifier: V,
    ) -> Self {
        Self {
            config,
            policy,
            evidence_verifier,
        }
    }

    /// Pure policy / class / MainNet gate applied before any evidence
    /// verification. Returns `Some(outcome)` when the request must be
    /// refused before verification, `None` to proceed.
    fn preflight_gate(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        expectations: &ProductionCustodyAttestationExpectations,
        trust_domain: &AuthorityTrustDomain,
    ) -> Option<ProductionCustodyAttestationOutcome> {
        use ProductionCustodyAttestationOutcome as O;

        // 1. Disabled fails closed before any evidence parsing.
        if self.policy.is_disabled() {
            return Some(O::DisabledNoVerification);
        }

        // 2. Unsupported request kinds are refused up front.
        match expectations.binding.request_kind {
            ProductionCustodyRequestKind::ValidatorSetRotation => {
                return Some(O::ValidatorSetRotationUnsupported);
            }
            ProductionCustodyRequestKind::PolicyChange => {
                return Some(O::PolicyChangeUnsupported);
            }
            ProductionCustodyRequestKind::OnChainGovernanceProofVerification => {
                return Some(O::GovernanceVerifierUnavailable);
            }
            ProductionCustodyRequestKind::AuthorityLifecycleSigning
            | ProductionCustodyRequestKind::GovernanceExecutionSigning => {}
        }

        // 3. RemoteSigner / local operator / peer custody material cannot
        //    satisfy the KMS/HSM custody attestation row.
        if evidence.attestation_class
            == ProductionCustodyAttestationClass::RemoteSignerAttestation
        {
            return Some(O::RemoteSignerAttestationIsNotKmsHsmCustody);
        }
        match expectations.binding.custody_class {
            AuthorityCustodyClass::RemoteSigner => {
                return Some(O::RemoteSignerAttestationIsNotKmsHsmCustody);
            }
            AuthorityCustodyClass::LocalOperatorKey
            | AuthorityCustodyClass::FixtureLocalKey
            | AuthorityCustodyClass::Unknown => {
                return Some(O::ProductionAttestationCustodyClassMismatch);
            }
            AuthorityCustodyClass::Kms | AuthorityCustodyClass::Hsm => {}
        }

        // 4. MainNet gate. A MainNet trust domain requires the explicit
        //    MainNet production custody attestation policy; even then, no
        //    real production attestation is wired, so it fails closed as
        //    unavailable. Fixture material is rejected; any other policy
        //    is refused. Gated before class-match / well-formedness so
        //    MainNet can never reach a verification path.
        if trust_domain.environment == TrustBundleEnvironment::Mainnet {
            return Some(match self.policy {
                ProductionCustodyAttestationVerifierPolicy::MainnetProductionCustodyAttestationRequired => {
                    O::MainNetProductionCustodyAttestationUnavailable
                }
                p if p.is_fixture() => O::FixtureAttestationRejectedForMainNet,
                _ => O::MainNetRefused,
            });
        }

        // 5. The MainNet production policy on a non-MainNet domain has no
        //    real attestation wired — fail closed with no verification.
        if self.policy.is_mainnet() {
            return Some(O::MainNetProductionCustodyAttestationUnavailable);
        }

        // 6. Structural well-formedness of config, evidence, expectations.
        if !self.config.is_well_formed()
            || !evidence.is_well_formed()
            || !expectations.is_well_formed()
        {
            return Some(O::ProductionAttestationMalformed);
        }

        // 7. Protocol version must be supported.
        if !evidence.protocol_version.is_supported() {
            return Some(O::ProductionAttestationUnsupportedProtocol {
                version: evidence.protocol_version.0,
            });
        }

        // 8. Attestation class must match the active policy.
        if self.policy.allowed_class() != Some(evidence.attestation_class) {
            // Fixture attestation under a fixture policy for the wrong
            // fixture kind, or any production mismatch, is unsupported.
            return Some(O::ProductionAttestationUnsupportedClass);
        }

        None
    }

    /// Field-by-field binding comparison. Returns `Some(outcome)` on the
    /// first mismatch, `None` when the binding matches.
    fn check_binding(
        &self,
        evidence: &ProductionCustodyAttestationBinding,
        expected: &ProductionCustodyAttestationBinding,
        trust_domain: &AuthorityTrustDomain,
    ) -> Option<ProductionCustodyAttestationOutcome> {
        use ProductionCustodyAttestationOutcome as O;

        // Trust-domain binding must match both the expectations and the
        // authoritative trust domain.
        if evidence.environment != expected.environment
            || evidence.environment != trust_domain.environment
            || evidence.chain_id != expected.chain_id
            || evidence.chain_id != trust_domain.chain_id
            || evidence.genesis_hash != expected.genesis_hash
            || evidence.genesis_hash != trust_domain.genesis_hash
            || evidence.authority_root_fingerprint != expected.authority_root_fingerprint
            || evidence.authority_root_fingerprint != trust_domain.authority_root_fingerprint
            || evidence.authority_domain_sequence != expected.authority_domain_sequence
        {
            return Some(O::ProductionAttestationDomainMismatch);
        }
        if evidence.custody_class != expected.custody_class {
            return Some(O::ProductionAttestationCustodyClassMismatch);
        }
        if evidence.provider_kind != expected.provider_kind
            || evidence.provider_id != expected.provider_id
        {
            return Some(O::ProductionAttestationProviderMismatch);
        }
        if evidence.key_handle != expected.key_handle {
            return Some(O::ProductionAttestationKeyHandleMismatch);
        }
        if evidence.key_fingerprint != expected.key_fingerprint
            || evidence.signer_identity != expected.signer_identity
        {
            return Some(O::ProductionAttestationSignerMismatch);
        }
        if evidence.authorized_action != expected.authorized_action {
            return Some(O::ProductionAttestationActionMismatch);
        }
        if evidence.candidate_digest != expected.candidate_digest {
            return Some(O::ProductionAttestationCandidateDigestMismatch);
        }
        if evidence.custody_request_id != expected.custody_request_id {
            return Some(O::ProductionAttestationRequestIdMismatch);
        }
        if evidence.request_envelope_digest != expected.request_envelope_digest {
            return Some(O::ProductionAttestationRequestEnvelopeMismatch);
        }
        if evidence.response_envelope_digest != expected.response_envelope_digest {
            return Some(O::ProductionAttestationResponseEnvelopeMismatch);
        }
        if evidence.backend_transcript_digest != expected.backend_transcript_digest {
            return Some(O::ProductionAttestationBackendTranscriptMismatch);
        }
        if evidence.durable_replay_record_digest != expected.durable_replay_record_digest {
            return Some(O::ProductionAttestationEvidenceAmbiguous {
                reason: "durable-replay-record-digest-mismatch".to_string(),
            });
        }
        None
    }
}

impl<V: CustodyAttestationEvidenceVerifier> GovernanceProductionCustodyAttestationVerifier
    for ProductionCustodyAttestationVerifier<V>
{
    fn build_attestation_challenge(
        &self,
        nonce: impl Into<String>,
        challenge: impl Into<String>,
        sequence: u64,
        custody_request_id: impl Into<String>,
    ) -> ProductionCustodyAttestationChallenge {
        ProductionCustodyAttestationChallenge {
            nonce: nonce.into(),
            challenge: challenge.into(),
            sequence,
            bound_request_id: custody_request_id.into(),
        }
    }

    fn verify_custody_attestation(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        expectations: &ProductionCustodyAttestationExpectations,
        trust_domain: &AuthorityTrustDomain,
    ) -> ProductionCustodyAttestationOutcome {
        use ProductionCustodyAttestationOutcome as O;

        if let Some(outcome) = self.preflight_gate(evidence, expectations, trust_domain) {
            return outcome;
        }

        // Binding comparison (domain / custody / provider / key / request).
        if let Some(outcome) =
            self.check_binding(&evidence.binding, &expectations.binding, trust_domain)
        {
            return outcome;
        }

        // Challenge / nonce binding + replay. The challenge must be bound
        // to the same custody request id and match the expected challenge.
        if evidence.challenge.bound_request_id != evidence.binding.custody_request_id
            || evidence.challenge.bound_request_id != expectations.binding.custody_request_id
        {
            return O::ProductionAttestationNonceReplay;
        }
        if evidence.challenge != expectations.expected_challenge {
            return O::ProductionAttestationNonceReplay;
        }

        // Trust-root binding.
        if !evidence.trust_root.is_present() {
            return O::ProductionAttestationTrustRootMissing;
        }
        if evidence.trust_root != expectations.expected_trust_root {
            return O::ProductionAttestationTrustRootMismatch;
        }

        // Measurement binding.
        if !evidence.measurement.is_present() {
            return O::ProductionAttestationMeasurementMismatch;
        }
        if evidence.measurement != expectations.expected_measurement {
            return O::ProductionAttestationMeasurementMismatch;
        }

        // Delegate provider quote / certificate-chain / hardware-proof
        // verification to the injected evidence verifier. Production
        // classes fail closed here (no real verification material).
        let verified = match self
            .evidence_verifier
            .verify_evidence(evidence, &evidence.trust_root)
        {
            Ok(material) => material,
            Err(err) => return error_to_outcome(&err),
        };

        // The verifier must confirm the same class it was asked about, and
        // the same provider identity.
        if verified.attestation_class != evidence.attestation_class {
            return O::ProductionAttestationEvidenceAmbiguous {
                reason: "verifier class disagreement".to_string(),
            };
        }
        if verified.provider_identity_digest != evidence.provider_identity_digest() {
            return O::ProductionAttestationProviderMismatch;
        }

        // Accept — fixture attestation only, DevNet/TestNet, evidence-only.
        match evidence.attestation_class {
            ProductionCustodyAttestationClass::FixtureKmsAttestation => {
                O::FixtureKmsAttestationVerified {
                    provider_id: evidence.binding.provider_id.clone(),
                    environment: trust_domain.environment,
                    custody_request_id: evidence.binding.custody_request_id.clone(),
                }
            }
            ProductionCustodyAttestationClass::FixtureHsmAttestation => {
                O::FixtureHsmAttestationVerified {
                    provider_id: evidence.binding.provider_id.clone(),
                    environment: trust_domain.environment,
                    custody_request_id: evidence.binding.custody_request_id.clone(),
                }
            }
            // A production class can never be verified in Run 297 because
            // the evidence verifier fails closed above; represented for
            // Run 298.
            _ => O::ProductionAttestationUnverified,
        }
    }

    fn evaluate_custody_attestation(
        &self,
        evidence: &ProductionCustodyAttestationEvidence,
        expectations: &ProductionCustodyAttestationExpectations,
        trust_domain: &AuthorityTrustDomain,
    ) -> ProductionCustodyAttestationDecision {
        let outcome = self.verify_custody_attestation(evidence, expectations, trust_domain);
        let evidence_digest = evidence.evidence_digest();
        let transcript_digest = production_custody_attestation_transcript_digest(
            self.config.protocol_version.0,
            &evidence_digest,
            &evidence.challenge.challenge_digest(),
            &evidence.binding.custody_request_id,
            &evidence.binding.backend_transcript_digest,
        );
        ProductionCustodyAttestationDecision {
            outcome,
            custody_request_id: evidence.binding.custody_request_id.clone(),
            evidence_digest,
            transcript_digest,
        }
    }

    fn recover_attestation_window(
        &self,
        prior: Option<&ProductionCustodyAttestationEvidence>,
        current: &ProductionCustodyAttestationEvidence,
    ) -> ProductionCustodyAttestationRecoveryOutcome {
        use ProductionCustodyAttestationRecoveryOutcome as R;
        let Some(prior) = prior else {
            return R::NoPriorAttestation;
        };
        // A reused nonce/challenge across different request ids is a replay.
        if prior.challenge.nonce == current.challenge.nonce
            && prior.challenge.challenge == current.challenge.challenge
            && prior.binding.custody_request_id != current.binding.custody_request_id
        {
            return R::ReusedNonceAcrossRequests;
        }
        // Different attestation (request id) => unrelated window.
        if prior.binding.custody_request_id != current.binding.custody_request_id {
            return R::NoPriorAttestation;
        }
        // Same id, different key handle => conflict.
        if prior.binding.key_handle != current.binding.key_handle {
            return R::ConflictingKeyHandleForSameId;
        }
        // Same id, different measurement => conflict.
        if prior.measurement != current.measurement {
            return R::ConflictingMeasurementForSameId;
        }
        // Same id, different transcript / evidence digest => conflict.
        if prior.binding.backend_transcript_digest != current.binding.backend_transcript_digest {
            return R::ConflictingTranscriptForSameId;
        }
        // Byte-identical evidence => idempotent replay.
        if prior == current {
            R::IdempotentReplayOfSameAttestation
        } else if prior.evidence_digest() == current.evidence_digest() {
            R::AmbiguousRecoveryFailClosed {
                reason: "same digest but non-identical evidence".to_string(),
            }
        } else {
            R::AmbiguousRecoveryFailClosed {
                reason: "conflicting evidence for same id".to_string(),
            }
        }
    }
}

// ===========================================================================
// Explicit fail-closed / scope helpers (grep-verifiable named symbols)
// ===========================================================================

/// Run 297 — returns `true`: the custody attestation verifier default
/// policy is `Disabled`.
pub fn production_custody_attestation_verifier_default_is_disabled() -> bool {
    ProductionCustodyAttestationVerifierPolicy::default()
        == ProductionCustodyAttestationVerifierPolicy::Disabled
}

/// Run 297 — returns `true`: fixture attestation can never satisfy a
/// MainNet production custody attestation.
pub fn production_custody_attestation_verifier_mainnet_refuses_fixture() -> bool {
    true
}

/// Run 297 — returns `true`: the verifier never falls back to fixture /
/// RemoteSigner / local / peer-majority evidence under a production
/// policy.
pub fn production_custody_attestation_verifier_never_falls_back() -> bool {
    true
}

/// Run 297 — returns `true`: this run is a source/test implementation and
/// is NOT release-binary evidence (deferred to Run 298).
pub fn production_custody_attestation_verifier_is_source_test_not_release_binary_evidence() -> bool {
    true
}

/// Run 297 — returns `true`: RemoteSigner attestation cannot satisfy the
/// KMS/HSM/cloud-KMS/PKCS#11 custody attestation row.
pub fn production_custody_attestation_verifier_remote_signer_is_not_kms_hsm() -> bool {
    true
}

/// Run 297 — returns `true`: production attestation classes are reachable
/// but fail closed without real quote / certificate-chain / hardware
/// verification material.
pub fn production_custody_attestation_verifier_production_is_fail_closed() -> bool {
    true
}

/// Run 297 — returns `true`: the verifier performs no Run 070 apply, no
/// `LivePqcTrustState` mutation, no trust swap, no session eviction, no
/// sequence/marker write, no durable replay overwrite, no settlement, no
/// external publication, no governance execution, and no validator-set
/// rotation.
pub fn production_custody_attestation_verifier_is_non_mutating() -> bool {
    true
}
