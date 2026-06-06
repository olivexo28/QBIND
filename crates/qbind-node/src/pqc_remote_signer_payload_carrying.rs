//! Run 196 — source/test RemoteSigner attestation payload carrying and
//! production-context custody composition wiring.
//!
//! ## Strict scope (Run 196)
//!
//! * **Source/test only.** Run 196 does **not** capture release-binary
//!   evidence; release-binary RemoteSigner payload/carrying evidence is
//!   deferred to **Run 197**.
//! * **No real RemoteSigner backend.** No networked signer service, no
//!   real KMS, no real HSM, no cloud-KMS integration, no PKCS#11
//!   integration. The Run 194 [`ProductionRemoteSigner`] remains
//!   callable but fails closed as
//!   [`RemoteSignerOutcome::ProductionRemoteSignerUnavailable`].
//! * **No MainNet peer-driven apply enablement.** The
//!   Run 147/148/152 MainNet refusal at the peer-driven apply surface
//!   remains intact even with a fully-valid DevNet/TestNet fixture
//!   loopback RemoteSigner attestation carried through this Run 196
//!   payload layer.
//! * **No governance execution engine, no real on-chain proof
//!   verifier, no validator-set rotation, no autonomous apply / apply
//!   on receipt / peer-majority authority.**
//! * **No marker / sequence-file / authority-marker / trust-bundle
//!   core schema change.** The carrier is a strictly additive,
//!   optional sibling on the existing v2 ratification sidecar JSON
//!   alongside the Run 167 `governance_authority_proof`, Run 184
//!   `onchain_governance_proof`, and Run 190
//!   `authority_custody_attestation` siblings: legacy
//!   no-RemoteSigner payloads continue to parse and to be accepted
//!   under the default [`RemoteSignerPolicy::Disabled`] policy
//!   bit-for-bit.
//!
//! Run 196 does **not** weaken any prior run (Runs 070, 130–195) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! Before Run 196 the Run 194 typed [`RemoteSignerIdentity`],
//! [`RemoteSignerRequest`], and [`RemoteSignerResponse`] could only
//! reach the Run 194 boundary via in-process source/test construction:
//! every production payload/context delivered the call-site context
//! with no RemoteSigner material, and neither
//! [`validate_remote_signer`] nor
//! [`validate_lifecycle_governance_custody_and_remote_signer`] was ever
//! reached from a production call site.
//!
//! Run 196 closes that gap at the source/test level by adding:
//!
//! 1. An **additive optional sibling field** —
//!    [`REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD`] — on the same
//!    v2 ratification sidecar JSON document already used by the Run 167
//!    / Run 184 / Run 190 siblings.
//! 2. A wire/context representation —
//!    [`RemoteSignerAttestationWire`] (combining
//!    [`RemoteSignerIdentityWire`], [`RemoteSignerRequestWire`], and
//!    [`RemoteSignerResponseWire`]) — with an explicit `schema_version`
//!    plus a string-tagged [`RemoteSignerModeWire`]. The wire form
//!    converts into the internal Run 194 types via
//!    [`RemoteSignerAttestationWire::to_parts`]; an unknown
//!    `schema_version` or an empty required field fails closed.
//! 3. A typed [`RemoteSignerLoadStatus`] (`Absent` / `Available` /
//!    `Malformed`) parallel to the Run 190
//!    [`crate::pqc_authority_custody_payload_carrying::AuthorityCustodyLoadStatus`].
//! 4. A typed [`RemoteSignerAttestationPayloadParseError`] separating
//!    JSON-shape failures from wire-form structural failures.
//! 5. A pure
//!    [`parse_optional_remote_signer_attestation_sibling_from_json_value`]
//!    helper that extracts the optional sibling from a generic
//!    `serde_json::Value` envelope.
//! 6. A combined v2 sidecar loader
//!    [`load_v2_ratification_sidecar_with_remote_signer_attestation_from_path`]
//!    (and bytes variant) that returns the typed
//!    [`qbind_ledger::BundleSigningRatificationV2`] together with BOTH
//!    the Run 190 [`AuthorityCustodyLoadStatus`] AND the Run 196
//!    [`RemoteSignerLoadStatus`].
//! 7. A typed [`RemoteSignerCallsiteContext`] — the natural production
//!    call-site inputs already available at every Run 194 RemoteSigner
//!    decision (the in-process Run 188 custody attestation, the
//!    candidate / persisted v2 records, the trust domain, the custody
//!    policy, the RemoteSigner expectations, and the RemoteSigner
//!    policy).
//! 8. Seven typed per-surface routing helpers
//!    ([`route_loaded_remote_signer_attestation_to_*_callsite_decision`])
//!    binding a parsed [`RemoteSignerLoadStatus`] to the seven
//!    production v2 marker-decision surfaces (reload-check / reload-
//!    apply / startup `--p2p-trust-bundle` / SIGHUP / local
//!    peer-candidate-check / live inbound `0x05` / peer-driven drain)
//!    with:
//!      * a typed
//!        [`RemoteSignerPayloadCarryingDecisionOutcome::MalformedRemoteSignerAttestationPayload`]
//!        variant placed *in front of* the Run 194 boundary so a
//!        malformed carrier fails closed BEFORE the verifier is
//!        invoked, BEFORE any sequence/marker write, BEFORE any live
//!        trust swap, BEFORE any session eviction, and BEFORE any Run
//!        070 call;
//!      * a typed
//!        [`RemoteSignerPayloadCarryingDecisionOutcome::RemoteSignerRequiredButAbsent`]
//!        variant when the active RemoteSigner policy requires material
//!        and the carrier is absent;
//!      * a typed
//!        [`RemoteSignerPayloadCarryingDecisionOutcome::NoRemoteSignerSupplied`]
//!        bypass variant when the active RemoteSigner policy is
//!        `Disabled` and the carrier is absent — the legacy
//!        no-RemoteSigner payload compatibility variant;
//!      * a typed
//!        [`RemoteSignerPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
//!        variant on the peer-driven drain surface that fires *before*
//!        the verifier regardless of RemoteSigner-attestation contents,
//!        mirroring the Run 147 / 148 / 152 MainNet refusal;
//!      * an inner Run 194
//!        [`LifecycleCustodyRemoteSignerOutcome`] for every parsed,
//!        present carrier.
//!
//! ## Pure / non-mutating
//!
//! The loaders perform read-only file I/O. The routing helpers perform
//! no I/O. No marker write, no sequence write, no live trust swap, no
//! session eviction, no Run 070 call.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pqc_authority_custody::{
    AuthorityCustodyAttestation, AuthorityCustodyClass, AuthorityCustodyPolicy,
};
use crate::pqc_authority_custody_payload_carrying::{
    parse_optional_authority_custody_attestation_sibling_from_json_value, AuthorityCustodyLoadStatus,
};
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_ratification_input::VersionedRatificationInputError;
use crate::pqc_remote_authority_signer::{
    validate_lifecycle_governance_custody_and_remote_signer, validate_remote_signer,
    validate_remote_signer_for_custody_class, LifecycleCustodyRemoteSignerOutcome,
    RemoteSignerExpectations, RemoteSignerIdentity, RemoteSignerMode, RemoteSignerOutcome,
    RemoteSignerPolicy, RemoteSignerRequest, RemoteSignerResponse,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Sibling field name + schema version
// ===========================================================================

/// JSON sibling field name carrying the Run 196 optional
/// [`RemoteSignerAttestationWire`] on the v2 ratification sidecar
/// envelope.
///
/// The field is strictly additive: legacy sidecars without this
/// sibling parse exactly as before and yield
/// [`RemoteSignerLoadStatus::Absent`].
pub const REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD: &str = "remote_signer_attestation";

/// Run 196 — wire schema version for the additive optional
/// [`RemoteSignerAttestationWire`] sibling. Versioning is additive: a
/// future run extending the wire shape MUST bump this constant. Run 196
/// rejects unknown versions with
/// [`RemoteSignerAttestationWireParseError::UnknownSchemaVersion`].
pub const REMOTE_SIGNER_ATTESTATION_WIRE_SCHEMA_VERSION: u32 = 1;

// ===========================================================================
// Wire-tagged signer mode
// ===========================================================================

/// Run 196 — wire-tagged form of [`RemoteSignerMode`].
///
/// The Run 194 [`RemoteSignerMode`] does not derive `Serialize` /
/// `Deserialize` (it is an internal symbol), so Run 196 mirrors it as
/// a string-tagged wire enum and converts in
/// [`RemoteSignerResponseWire::to_response`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RemoteSignerModeWire {
    FixtureLoopback,
    Production,
}

impl RemoteSignerModeWire {
    pub const fn to_mode(self) -> RemoteSignerMode {
        match self {
            Self::FixtureLoopback => RemoteSignerMode::FixtureLoopback,
            Self::Production => RemoteSignerMode::Production,
        }
    }

    pub const fn from_mode(m: RemoteSignerMode) -> Self {
        match m {
            RemoteSignerMode::FixtureLoopback => Self::FixtureLoopback,
            RemoteSignerMode::Production => Self::Production,
        }
    }
}

// ===========================================================================
// Wire forms
// ===========================================================================

/// Run 196 — wire-safe encoding of [`RemoteSignerIdentity`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSignerIdentityWire {
    pub signer_id: String,
    pub signer_public_identity: String,
    pub custody_key_id: String,
    pub authority_root_fingerprint: String,
    pub bundle_signing_key_fingerprint: String,
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub supported_suite_id: u8,
    pub supported_lifecycle_actions: Vec<LocalLifecycleAction>,
    pub attestation_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
}

impl RemoteSignerIdentityWire {
    /// Convert into the internal Run 194 [`RemoteSignerIdentity`].
    /// Fails closed when any required string field is empty.
    pub fn to_identity(
        &self,
    ) -> Result<RemoteSignerIdentity, RemoteSignerAttestationWireParseError> {
        if self.signer_id.is_empty()
            || self.signer_public_identity.is_empty()
            || self.custody_key_id.is_empty()
            || self.authority_root_fingerprint.is_empty()
            || self.bundle_signing_key_fingerprint.is_empty()
            || self.chain_id.is_empty()
            || self.genesis_hash.is_empty()
            || self.attestation_digest.is_empty()
        {
            return Err(RemoteSignerAttestationWireParseError::EmptyRequiredField {
                part: "identity",
            });
        }
        Ok(RemoteSignerIdentity {
            signer_id: self.signer_id.clone(),
            signer_public_identity: self.signer_public_identity.clone(),
            custody_key_id: self.custody_key_id.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            bundle_signing_key_fingerprint: self.bundle_signing_key_fingerprint.clone(),
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            supported_suite_id: self.supported_suite_id,
            supported_lifecycle_actions: self.supported_lifecycle_actions.clone(),
            attestation_digest: self.attestation_digest.clone(),
            freshness_unix: self.freshness_unix,
            expires_at_unix: self.expires_at_unix,
        })
    }

    /// Source/test helper: build a wire form from an in-process
    /// [`RemoteSignerIdentity`].
    pub fn from_identity(i: &RemoteSignerIdentity) -> Self {
        Self {
            signer_id: i.signer_id.clone(),
            signer_public_identity: i.signer_public_identity.clone(),
            custody_key_id: i.custody_key_id.clone(),
            authority_root_fingerprint: i.authority_root_fingerprint.clone(),
            bundle_signing_key_fingerprint: i.bundle_signing_key_fingerprint.clone(),
            environment: i.environment,
            chain_id: i.chain_id.clone(),
            genesis_hash: i.genesis_hash.clone(),
            supported_suite_id: i.supported_suite_id,
            supported_lifecycle_actions: i.supported_lifecycle_actions.clone(),
            attestation_digest: i.attestation_digest.clone(),
            freshness_unix: i.freshness_unix,
            expires_at_unix: i.expires_at_unix,
        }
    }
}

/// Run 196 — wire-safe encoding of [`RemoteSignerRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSignerRequestWire {
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub lifecycle_action: LocalLifecycleAction,
    pub candidate_digest: String,
    pub authority_domain_sequence: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub active_signing_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_signing_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_signing_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_proof_digest: Option<String>,
    pub custody_attestation_digest: String,
    pub replay_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_timestamp_unix: Option<u64>,
}

impl RemoteSignerRequestWire {
    /// Convert into the internal Run 194 [`RemoteSignerRequest`]. Fails
    /// closed when any mandatory field is empty.
    pub fn to_request(&self) -> Result<RemoteSignerRequest, RemoteSignerAttestationWireParseError> {
        let request = RemoteSignerRequest {
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            lifecycle_action: self.lifecycle_action,
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            active_signing_key_fingerprint: self.active_signing_key_fingerprint.clone(),
            new_signing_key_fingerprint: self.new_signing_key_fingerprint.clone(),
            revoked_signing_key_fingerprint: self.revoked_signing_key_fingerprint.clone(),
            governance_proof_digest: self.governance_proof_digest.clone(),
            custody_attestation_digest: self.custody_attestation_digest.clone(),
            replay_nonce: self.replay_nonce.clone(),
            request_timestamp_unix: self.request_timestamp_unix,
        };
        if !request.is_well_formed() {
            return Err(RemoteSignerAttestationWireParseError::EmptyRequiredField {
                part: "request",
            });
        }
        Ok(request)
    }

    /// Source/test helper: build a wire form from an in-process
    /// [`RemoteSignerRequest`].
    pub fn from_request(r: &RemoteSignerRequest) -> Self {
        Self {
            environment: r.environment,
            chain_id: r.chain_id.clone(),
            genesis_hash: r.genesis_hash.clone(),
            authority_root_fingerprint: r.authority_root_fingerprint.clone(),
            lifecycle_action: r.lifecycle_action,
            candidate_digest: r.candidate_digest.clone(),
            authority_domain_sequence: r.authority_domain_sequence,
            active_signing_key_fingerprint: r.active_signing_key_fingerprint.clone(),
            new_signing_key_fingerprint: r.new_signing_key_fingerprint.clone(),
            revoked_signing_key_fingerprint: r.revoked_signing_key_fingerprint.clone(),
            governance_proof_digest: r.governance_proof_digest.clone(),
            custody_attestation_digest: r.custody_attestation_digest.clone(),
            replay_nonce: r.replay_nonce.clone(),
            request_timestamp_unix: r.request_timestamp_unix,
        }
    }
}

/// Run 196 — wire-safe encoding of [`RemoteSignerResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSignerResponseWire {
    pub request_digest: String,
    pub signer_id: String,
    pub custody_key_id: String,
    pub signature_suite_id: u8,
    pub signature_commitment: String,
    pub response_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,
    pub signer_mode: RemoteSignerModeWire,
}

impl RemoteSignerResponseWire {
    /// Convert into the internal Run 194 [`RemoteSignerResponse`]. Fails
    /// closed when any mandatory field is empty.
    pub fn to_response(
        &self,
    ) -> Result<RemoteSignerResponse, RemoteSignerAttestationWireParseError> {
        let response = RemoteSignerResponse {
            request_digest: self.request_digest.clone(),
            signer_id: self.signer_id.clone(),
            custody_key_id: self.custody_key_id.clone(),
            signature_suite_id: self.signature_suite_id,
            signature_commitment: self.signature_commitment.clone(),
            response_nonce: self.response_nonce.clone(),
            freshness_unix: self.freshness_unix,
            expires_at_unix: self.expires_at_unix,
            signer_mode: self.signer_mode.to_mode(),
        };
        if !response.is_well_formed() {
            return Err(RemoteSignerAttestationWireParseError::EmptyRequiredField {
                part: "response",
            });
        }
        Ok(response)
    }

    /// Source/test helper: build a wire form from an in-process
    /// [`RemoteSignerResponse`].
    pub fn from_response(r: &RemoteSignerResponse) -> Self {
        Self {
            request_digest: r.request_digest.clone(),
            signer_id: r.signer_id.clone(),
            custody_key_id: r.custody_key_id.clone(),
            signature_suite_id: r.signature_suite_id,
            signature_commitment: r.signature_commitment.clone(),
            response_nonce: r.response_nonce.clone(),
            freshness_unix: r.freshness_unix,
            expires_at_unix: r.expires_at_unix,
            signer_mode: RemoteSignerModeWire::from_mode(r.signer_mode),
        }
    }
}

/// Run 196 — combined additive wire-form RemoteSigner attestation
/// carried as an optional sibling on the v2 ratification sidecar JSON.
///
/// Bundles the [`RemoteSignerIdentityWire`], [`RemoteSignerRequestWire`],
/// and [`RemoteSignerResponseWire`] behind a single `schema_version`.
/// Old sidecars (Runs 167–195) that do not carry this sibling continue
/// to parse and validate exactly as before — the sibling is extracted
/// from the surrounding `serde_json::Value` and is absent when missing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSignerAttestationWire {
    pub schema_version: u32,
    pub identity: RemoteSignerIdentityWire,
    pub request: RemoteSignerRequestWire,
    pub response: RemoteSignerResponseWire,
}

impl RemoteSignerAttestationWire {
    /// Convert the Run 196 combined wire form into the internal Run 194
    /// [`RemoteSignerAttestationParts`].
    ///
    /// Fails closed when:
    ///
    /// * the `schema_version` is not the one Run 196 supports
    ///   ([`REMOTE_SIGNER_ATTESTATION_WIRE_SCHEMA_VERSION`]);
    /// * any required string field of the identity / request / response
    ///   is empty.
    ///
    /// The conversion does not interpret the placeholder signature /
    /// attestation bytes — all trust-domain / lifecycle / custody /
    /// sequence / candidate-digest / suite / freshness / replay checks
    /// are deferred to the Run 194 verifier.
    pub fn to_parts(
        &self,
    ) -> Result<RemoteSignerAttestationParts, RemoteSignerAttestationWireParseError> {
        if self.schema_version != REMOTE_SIGNER_ATTESTATION_WIRE_SCHEMA_VERSION {
            return Err(RemoteSignerAttestationWireParseError::UnknownSchemaVersion {
                got: self.schema_version,
                expected: REMOTE_SIGNER_ATTESTATION_WIRE_SCHEMA_VERSION,
            });
        }
        let identity = self.identity.to_identity()?;
        let request = self.request.to_request()?;
        let response = self.response.to_response()?;
        Ok(RemoteSignerAttestationParts {
            identity,
            request,
            response,
        })
    }

    /// Source/test helper: build a Run 196 combined wire form from
    /// in-process Run 194 parts.
    pub fn from_parts(
        identity: &RemoteSignerIdentity,
        request: &RemoteSignerRequest,
        response: &RemoteSignerResponse,
    ) -> Self {
        Self {
            schema_version: REMOTE_SIGNER_ATTESTATION_WIRE_SCHEMA_VERSION,
            identity: RemoteSignerIdentityWire::from_identity(identity),
            request: RemoteSignerRequestWire::from_request(request),
            response: RemoteSignerResponseWire::from_response(response),
        }
    }
}

/// Run 196 — the internal Run 194 RemoteSigner parts produced by
/// converting a well-formed [`RemoteSignerAttestationWire`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSignerAttestationParts {
    pub identity: RemoteSignerIdentity,
    pub request: RemoteSignerRequest,
    pub response: RemoteSignerResponse,
}

// ===========================================================================
// Typed wire-form parse error
// ===========================================================================

/// Run 196 — typed wire-form parse error emitted by
/// [`RemoteSignerAttestationWire::to_parts`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignerAttestationWireParseError {
    /// The wire form's `schema_version` is not the one Run 196 supports.
    UnknownSchemaVersion { got: u32, expected: u32 },
    /// A required string field of the named part (`identity` /
    /// `request` / `response`) was empty.
    EmptyRequiredField { part: &'static str },
}

impl std::fmt::Display for RemoteSignerAttestationWireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchemaVersion { got, expected } => write!(
                f,
                "[run-196] unsupported remote_signer_attestation schema_version={} (expected {}). Fail closed.",
                got, expected
            ),
            Self::EmptyRequiredField { part } => write!(
                f,
                "[run-196] remote_signer_attestation {} has an empty required field. Fail closed.",
                part
            ),
        }
    }
}

impl std::error::Error for RemoteSignerAttestationWireParseError {}

// ===========================================================================
// Typed payload-level parse error
// ===========================================================================

/// Run 196 — typed parse error emitted at the payload/sibling boundary
/// when a `remote_signer_attestation` sibling is present but cannot be
/// converted into typed Run 194 parts.
///
/// Distinct from [`RemoteSignerAttestationWireParseError`] so that
/// JSON-shape failures (payload-level) are kept separate from wire-form
/// structural failures (Run 196 schema-level). Both map to a single
/// [`RemoteSignerPayloadCarryingDecisionOutcome::MalformedRemoteSignerAttestationPayload`]
/// variant at the call-site routing helpers and never to a partially
/// parsed attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignerAttestationPayloadParseError {
    /// JSON decoding of the optional `remote_signer_attestation`
    /// sibling field failed.
    Json { error: String },
    /// The sibling decoded as a [`RemoteSignerAttestationWire`] but the
    /// wire form failed structural validation (unknown schema_version,
    /// empty required field).
    Wire(RemoteSignerAttestationWireParseError),
}

impl std::fmt::Display for RemoteSignerAttestationPayloadParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { error } => write!(
                f,
                "[run-196] failed to JSON-decode optional `{}` sibling: {}. Fail closed.",
                REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD, error
            ),
            Self::Wire(e) => write!(f, "[run-196] {}", e),
        }
    }
}

impl std::error::Error for RemoteSignerAttestationPayloadParseError {}

impl From<RemoteSignerAttestationWireParseError> for RemoteSignerAttestationPayloadParseError {
    fn from(e: RemoteSignerAttestationWireParseError) -> Self {
        Self::Wire(e)
    }
}

// ===========================================================================
// Typed load status
// ===========================================================================

/// Run 196 — typed load status of the optional
/// [`RemoteSignerAttestationWire`] sibling on the v2 ratification
/// sidecar JSON / `0x05` peer-candidate envelope.
///
/// Pure data; carries no live trust state and triggers no I/O on
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignerLoadStatus {
    /// The carrier carried no `remote_signer_attestation` sibling
    /// field. Backwards-compatible with all pre-Run-196 v2 sidecars
    /// and live envelopes — a no-RemoteSigner payload remains accepted
    /// under the default [`RemoteSignerPolicy::Disabled`] policy.
    Absent,
    /// The carrier carried a well-formed wire attestation which was
    /// structurally converted into the typed Run 194 parts. The parts
    /// have NOT yet been validated against trust-domain / lifecycle /
    /// custody / replay / freshness bindings — validation is performed
    /// by the Run 196 per-surface routing helpers which delegate to the
    /// Run 194 verifier.
    Available(RemoteSignerAttestationParts),
    /// The carrier carried a `remote_signer_attestation` sibling field
    /// that failed to decode at the JSON layer or failed wire
    /// structural validation. Always fails closed at the Run 196
    /// per-surface routing helpers.
    Malformed(RemoteSignerAttestationPayloadParseError),
}

impl RemoteSignerLoadStatus {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed(_))
    }

    /// Borrow the typed parts when the carrier was well-formed. `None`
    /// for `Absent` and `Malformed`.
    pub fn as_parts(&self) -> Option<&RemoteSignerAttestationParts> {
        match self {
            Self::Available(p) => Some(p),
            Self::Absent | Self::Malformed(_) => None,
        }
    }

    /// Return the typed parse error when the carrier was malformed.
    pub fn malformed_error(&self) -> Option<&RemoteSignerAttestationPayloadParseError> {
        match self {
            Self::Malformed(e) => Some(e),
            Self::Absent | Self::Available(_) => None,
        }
    }
}

// ===========================================================================
// Sibling parsing
// ===========================================================================

/// Run 196 — pure parse helper that extracts the optional
/// `remote_signer_attestation` sibling from a generic JSON value and
/// returns a typed [`RemoteSignerLoadStatus`].
///
/// Behaviour:
///
/// * `value` has no `remote_signer_attestation` field, or the field is
///   `null`: returns [`RemoteSignerLoadStatus::Absent`].
/// * `value` has a non-null `remote_signer_attestation` field that
///   fails to decode as [`RemoteSignerAttestationWire`]: returns
///   [`RemoteSignerLoadStatus::Malformed`] carrying a
///   [`RemoteSignerAttestationPayloadParseError::Json`].
/// * `value` has a well-formed wire object but
///   [`RemoteSignerAttestationWire::to_parts`] rejects it (unknown
///   schema version, empty required field): returns
///   [`RemoteSignerLoadStatus::Malformed`] carrying the wire parse
///   error.
/// * Otherwise: returns [`RemoteSignerLoadStatus::Available`] with the
///   typed Run 194 parts.
///
/// Pure — does not mutate `value` and performs no I/O.
pub fn parse_optional_remote_signer_attestation_sibling_from_json_value(
    value: &Value,
) -> RemoteSignerLoadStatus {
    let sibling = value.get(REMOTE_SIGNER_ATTESTATION_PAYLOAD_SIBLING_FIELD);
    match sibling {
        None => RemoteSignerLoadStatus::Absent,
        Some(Value::Null) => RemoteSignerLoadStatus::Absent,
        Some(raw) => match serde_json::from_value::<RemoteSignerAttestationWire>(raw.clone()) {
            Ok(wire) => match wire.to_parts() {
                Ok(parts) => RemoteSignerLoadStatus::Available(parts),
                Err(e) => RemoteSignerLoadStatus::Malformed(
                    RemoteSignerAttestationPayloadParseError::Wire(e),
                ),
            },
            Err(e) => RemoteSignerLoadStatus::Malformed(
                RemoteSignerAttestationPayloadParseError::Json {
                    error: e.to_string(),
                },
            ),
        },
    }
}

// ===========================================================================
// Combined v2 sidecar loader (Run 190 custody + Run 196 RemoteSigner)
// ===========================================================================

/// Run 196 — typed result of loading a v2 ratification sidecar together
/// with the Run 190 [`AuthorityCustodyAttestationWire`] sibling and the
/// Run 196 [`RemoteSignerAttestationWire`] sibling.
///
/// Strictly additive over the Run 190 combined sidecar: pre-Run-196
/// sidecars yield [`RemoteSignerLoadStatus::Absent`] in the new field
/// and continue to expose the existing Run 190 custody load status
/// unchanged.
#[derive(Debug, Clone)]
pub struct LoadedV2RatificationSidecarWithRemoteSignerAttestation {
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    pub authority_custody_attestation: AuthorityCustodyLoadStatus,
    pub remote_signer_attestation: RemoteSignerLoadStatus,
}

/// Run 196 — load a v2 ratification sidecar JSON file and additionally
/// attempt to parse the Run 190 `authority_custody_attestation` sibling
/// and the Run 196 `remote_signer_attestation` sibling.
///
/// Both optional sibling fields are **strictly additive**. A v2 sidecar
/// without them continues to parse as before and yields the
/// corresponding `Absent` load status. A sibling that fails to
/// deserialise into its wire form, or that fails wire-form structural
/// validation, yields the corresponding `Malformed` load status
/// independently. The v2 ratification itself is still returned so the
/// caller can fall through the policy/gate pipeline.
///
/// No file write, no marker write, no sequence write, no live trust
/// swap, no session eviction, no Run 070 call.
pub fn load_v2_ratification_sidecar_with_remote_signer_attestation_from_path(
    path: &Path,
) -> Result<
    LoadedV2RatificationSidecarWithRemoteSignerAttestation,
    VersionedRatificationInputError,
> {
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes(&bytes, path)
}

/// Run 196 — bytes-form variant of
/// [`load_v2_ratification_sidecar_with_remote_signer_attestation_from_path`].
///
/// Used by validation-only / live-inbound surfaces that already hold
/// the JSON envelope in memory. The `path_for_diagnostics` argument is
/// only used to populate typed [`VersionedRatificationInputError`]
/// variants — it does NOT trigger any file access on this code path.
pub fn load_v2_ratification_sidecar_with_remote_signer_attestation_from_bytes(
    bytes: &[u8],
    path_for_diagnostics: &Path,
) -> Result<
    LoadedV2RatificationSidecarWithRemoteSignerAttestation,
    VersionedRatificationInputError,
> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| VersionedRatificationInputError::JsonParse {
            path: path_for_diagnostics.to_path_buf(),
            error: e.to_string(),
        })?;

    let version_value = value.get("schema_version").or_else(|| value.get("version"));
    let version_int = match version_value.and_then(|v| v.as_u64()) {
        Some(v) => v as u32,
        None => {
            return Err(VersionedRatificationInputError::UnknownSchemaVersion {
                path: path_for_diagnostics.to_path_buf(),
                got: version_value.cloned(),
            });
        }
    };
    if version_int != 2 {
        return Err(VersionedRatificationInputError::MalformedSidecar {
            path: path_for_diagnostics.to_path_buf(),
            schema_version: version_int,
            error: format!(
                "Run 196 remote-signer-attestation carrier requires v2 sidecar (got schema_version={})",
                version_int
            ),
        });
    }

    // Extract optional siblings BEFORE re-parsing into the typed
    // ratification, so neither sibling can poison the v2 parse and so
    // each sibling produces its own typed load status independently.
    let authority_custody_attestation =
        parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
    let remote_signer_attestation =
        parse_optional_remote_signer_attestation_sibling_from_json_value(&value);

    let ratification: qbind_ledger::BundleSigningRatificationV2 = serde_json::from_value(value)
        .map_err(|e| VersionedRatificationInputError::MalformedSidecar {
            path: path_for_diagnostics.to_path_buf(),
            schema_version: 2,
            error: e.to_string(),
        })?;

    Ok(LoadedV2RatificationSidecarWithRemoteSignerAttestation {
        ratification,
        authority_custody_attestation,
        remote_signer_attestation,
    })
}

// ===========================================================================
// Wire-encoding helper for the additive sibling
// ===========================================================================

/// Run 196 — additive optional sibling shape used to produce a v2
/// ratification sidecar JSON document that carries a
/// [`RemoteSignerAttestationWire`] (and optionally the Run 190 custody
/// sibling) alongside the typed
/// [`qbind_ledger::BundleSigningRatificationV2`].
///
/// Source/test helper. Production paths continue to write the
/// `BundleSigningRatificationV2` directly when no RemoteSigner material
/// is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RatificationSidecarWithRemoteSignerAttestationWire {
    #[serde(flatten)]
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer_attestation: Option<RemoteSignerAttestationWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_custody_attestation: Option<
        crate::pqc_authority_custody_payload_carrying::AuthorityCustodyAttestationWire,
    >,
}

// ===========================================================================
// Call-site context
// ===========================================================================

/// Run 196 — typed bundle of the natural production call-site inputs
/// required to drive a Run 194 lifecycle + governance + custody +
/// RemoteSigner preflight at any of the seven production v2
/// marker-decision surfaces.
///
/// Every field is borrowed; the struct is purely a typed argument
/// bundle and never mutates any input. Constructing it is free of I/O.
#[derive(Debug)]
pub struct RemoteSignerCallsiteContext<'a> {
    /// In-process Run 188 custody attestation already resolved by the
    /// calling surface (e.g. via the Run 190 custody carrier). The
    /// Run 194 composition validates this under `custody_policy` before
    /// consulting the RemoteSigner.
    pub custody_attestation: &'a AuthorityCustodyAttestation,
    /// Persisted v2 record when the call site has one in hand.
    pub persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    /// Candidate v2 record being preflighted by the call site.
    pub candidate: &'a PersistentAuthorityStateRecordV2,
    /// Active trust domain at the call site.
    pub trust_domain: &'a AuthorityTrustDomain,
    /// Expected governance authority class binding for the Run 188
    /// validator.
    pub expected_governance_authority_class: GovernanceAuthorityClass,
    /// Expected lifecycle action binding.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected candidate digest binding.
    pub expected_candidate_digest: &'a str,
    /// Expected next authority-domain sequence binding.
    pub expected_authority_domain_sequence: u64,
    /// Optional expected custody key id binding.
    pub expected_custody_key_id: Option<&'a str>,
    /// Active Run 188 [`AuthorityCustodyPolicy`].
    pub custody_policy: AuthorityCustodyPolicy,
    /// Run 194 RemoteSigner verifier expectations (per-attempt nonces,
    /// expected signing-key fingerprint, candidate digest, sequence,
    /// custody key id, custody attestation digest, now_unix).
    pub remote_signer_expected: &'a RemoteSignerExpectations,
    /// Active Run 194 [`RemoteSignerPolicy`]. Default in production is
    /// [`RemoteSignerPolicy::Disabled`].
    pub remote_signer_policy: RemoteSignerPolicy,
    /// Wall-clock seconds-since-epoch.
    pub now_unix: u64,
}

impl<'a> RemoteSignerCallsiteContext<'a> {
    /// Run 196 — pure surface-level MainNet refusal helper. Returns
    /// `true` iff the candidate, the trust domain, or any carried
    /// RemoteSigner part binds MainNet. Used by the peer-driven drain
    /// routing helper before the verifier is invoked, mirroring the
    /// Run 152 MainNet peer-driven-apply refusal.
    pub fn binds_mainnet(&self, parts: Option<&RemoteSignerAttestationParts>) -> bool {
        self.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || self.candidate.environment == TrustBundleEnvironment::Mainnet
            || parts
                .map(|p| {
                    p.identity.environment == TrustBundleEnvironment::Mainnet
                        || p.request.environment == TrustBundleEnvironment::Mainnet
                })
                .unwrap_or(false)
    }
}

// ===========================================================================
// Routing into Run 194 validation
// ===========================================================================

/// Run 196 — typed outcome of routing a Run 196
/// [`RemoteSignerLoadStatus`] through any of the seven production v2
/// marker-decision surfaces.
///
/// Adds typed variants in front of the Run 194
/// [`LifecycleCustodyRemoteSignerOutcome`]:
///
/// * [`Self::MalformedRemoteSignerAttestationPayload`] — the carrier
///   sibling was present but malformed at the JSON or wire-structural
///   level. Always fail-closed regardless of policy. The Run 194
///   verifier is NOT invoked.
/// * [`Self::RemoteSignerRequiredButAbsent`] — the active RemoteSigner
///   policy requires material (every non-`Disabled` policy) and the
///   carrier sibling is absent. Always fail-closed.
/// * [`Self::NoRemoteSignerSupplied`] — the carrier sibling is absent
///   and the active RemoteSigner policy is
///   [`RemoteSignerPolicy::Disabled`]. Legacy no-RemoteSigner payload
///   compatibility variant; the calling surface continues with its
///   pre-Run-196 path. The Run 194 verifier is NOT invoked.
/// * [`Self::MainNetPeerDrivenApplyRefused`] — the peer-driven drain
///   surface refuses MainNet unconditionally regardless of
///   RemoteSigner-attestation contents.
/// * [`Self::Callsite`] — wraps the Run 194
///   [`LifecycleCustodyRemoteSignerOutcome`] for every parsed, present
///   carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteSignerPayloadCarryingDecisionOutcome {
    /// The carrier sibling was present but malformed. Fail closed
    /// before any Run 194 validation, before any sequence/marker write,
    /// before any live trust swap, before any session eviction, before
    /// any Run 070 call.
    MalformedRemoteSignerAttestationPayload(RemoteSignerAttestationPayloadParseError),
    /// The active RemoteSigner policy requires material and the carrier
    /// sibling is absent. Fail closed.
    RemoteSignerRequiredButAbsent { policy: RemoteSignerPolicy },
    /// The carrier sibling is absent and the active RemoteSigner policy
    /// is `Disabled`. Legacy no-RemoteSigner payload compatibility.
    NoRemoteSignerSupplied,
    /// MainNet peer-driven apply remains the Run 147 / 148 / 152 FATAL
    /// refusal regardless of RemoteSigner-attestation contents. Surfaced
    /// only by the peer-driven drain routing helper.
    MainNetPeerDrivenApplyRefused,
    /// The carrier sibling parsed and the Run 194 composition was
    /// invoked. Carries the typed Run 194 combined lifecycle +
    /// governance + custody + RemoteSigner outcome.
    Callsite(LifecycleCustodyRemoteSignerOutcome),
}

impl RemoteSignerPayloadCarryingDecisionOutcome {
    pub fn is_accept(&self) -> bool {
        match self {
            Self::Callsite(o) => o.is_accept(),
            _ => false,
        }
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !self.is_bypassed()
    }

    /// `true` iff the policy was `Disabled` and the carrier was absent —
    /// the legacy no-RemoteSigner-payload bypass variant.
    pub fn is_bypassed(&self) -> bool {
        matches!(self, Self::NoRemoteSignerSupplied)
    }

    pub fn is_malformed_payload(&self) -> bool {
        matches!(self, Self::MalformedRemoteSignerAttestationPayload(_))
    }

    pub fn is_required_but_absent(&self) -> bool {
        matches!(self, Self::RemoteSignerRequiredButAbsent { .. })
    }

    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// Borrow the inner Run 194 outcome, if any.
    pub fn callsite_outcome(&self) -> Option<&LifecycleCustodyRemoteSignerOutcome> {
        match self {
            Self::Callsite(o) => Some(o),
            _ => None,
        }
    }
}

/// Internal — short-circuit a malformed-carrier load status into the
/// Run 196 fail-closed outcome. `Absent` and `Available` return `None`,
/// in which case the caller continues per-surface.
fn malformed_payload_shortcircuit(
    loaded: &RemoteSignerLoadStatus,
) -> Option<RemoteSignerPayloadCarryingDecisionOutcome> {
    match loaded {
        RemoteSignerLoadStatus::Malformed(e) => Some(
            RemoteSignerPayloadCarryingDecisionOutcome::MalformedRemoteSignerAttestationPayload(
                e.clone(),
            ),
        ),
        RemoteSignerLoadStatus::Absent | RemoteSignerLoadStatus::Available(_) => None,
    }
}

/// Internal — handle the absent-carrier case under the active
/// RemoteSigner policy. Returns `None` only when the carrier is
/// `Available`.
fn absent_or_available_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> Option<RemoteSignerPayloadCarryingDecisionOutcome> {
    match loaded {
        RemoteSignerLoadStatus::Absent => match ctx.remote_signer_policy {
            RemoteSignerPolicy::Disabled => {
                Some(RemoteSignerPayloadCarryingDecisionOutcome::NoRemoteSignerSupplied)
            }
            other => Some(
                RemoteSignerPayloadCarryingDecisionOutcome::RemoteSignerRequiredButAbsent {
                    policy: other,
                },
            ),
        },
        RemoteSignerLoadStatus::Available(_) => None,
        // Already short-circuited by [`malformed_payload_shortcircuit`].
        RemoteSignerLoadStatus::Malformed(_) => None,
    }
}

/// Internal — invoke the Run 194 lifecycle + governance + custody +
/// RemoteSigner composition with the call-site context inputs.
fn run_194_validate(
    ctx: &RemoteSignerCallsiteContext<'_>,
    parts: &RemoteSignerAttestationParts,
    is_peer_driven_apply_preflight: bool,
) -> LifecycleCustodyRemoteSignerOutcome {
    validate_lifecycle_governance_custody_and_remote_signer(
        ctx.custody_attestation,
        ctx.candidate,
        ctx.persisted,
        ctx.trust_domain,
        ctx.expected_governance_authority_class,
        ctx.expected_lifecycle_action,
        ctx.expected_candidate_digest,
        ctx.expected_authority_domain_sequence,
        ctx.expected_custody_key_id,
        ctx.custody_policy,
        &parts.identity,
        &parts.request,
        &parts.response,
        ctx.remote_signer_expected,
        ctx.remote_signer_policy,
        ctx.now_unix,
        is_peer_driven_apply_preflight,
    )
}

/// Internal — generic per-surface routing entry shared by every
/// non-`peer_driven_drain` surface.
fn route_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
    is_peer_driven_apply_preflight: bool,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    if let Some(short) = malformed_payload_shortcircuit(loaded) {
        return short;
    }
    if let Some(short) = absent_or_available_decision(ctx, loaded) {
        return short;
    }
    let parts = match loaded {
        RemoteSignerLoadStatus::Available(p) => p,
        // Unreachable: short-circuited above.
        _ => unreachable!("malformed_payload_shortcircuit / absent_or_available_decision handled"),
    };
    RemoteSignerPayloadCarryingDecisionOutcome::Callsite(run_194_validate(
        ctx,
        parts,
        is_peer_driven_apply_preflight,
    ))
}

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] through the
/// `--p2p-trust-bundle-reload-check` validation-only call-site.
/// Validation-only mutation contract: the caller MUST drop the returned
/// outcome and MUST NOT persist a marker, advance the bundle-signing
/// sequence, swap live trust state, evict sessions, or invoke Run 070.
pub fn route_loaded_remote_signer_attestation_to_reload_check_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] through the
/// `--p2p-trust-bundle-reload-apply-*` mutating-preflight call-site. A
/// malformed carrier short-circuits before the verifier is invoked,
/// before any sequence/marker write, and before any Run 070 call.
pub fn route_loaded_remote_signer_attestation_to_reload_apply_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] through the
/// startup `--p2p-trust-bundle` mutating-preflight call-site.
pub fn route_loaded_remote_signer_attestation_to_startup_p2p_trust_bundle_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] through the
/// SIGHUP live trust-bundle reload mutating-preflight call-site.
pub fn route_loaded_remote_signer_attestation_to_sighup_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] through the local
/// `--p2p-trust-bundle-peer-candidate-check` validation-only call-site.
pub fn route_loaded_remote_signer_attestation_to_local_peer_candidate_check_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] through the live
/// inbound `0x05` peer-candidate validation-only call-site. An invalid
/// live `0x05` RemoteSigner-attestation candidate (malformed payload,
/// absent under non-`Disabled` policy, or rejected by the Run 194
/// verifier) is **not propagated, staged, or applied** — the rejection
/// short-circuits at this routing helper before any staging path is
/// reached.
pub fn route_loaded_remote_signer_attestation_to_live_inbound_0x05_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded, false)
}

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] through the
/// Run 150 peer-driven apply drain coordinator preflight call-site.
///
/// **Surface-level MainNet refusal.** Even if the active
/// [`RemoteSignerPolicy`] is `FixtureLoopbackAllowed` and a fully-valid
/// fixture loopback RemoteSigner attestation is supplied, this entry
/// refuses MainNet peer-driven apply unconditionally and returns
/// [`RemoteSignerPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
/// before the verifier is invoked, mirroring the Run 152 MainNet
/// refusal at the calling surface. Non-MainNet candidates fall through
/// to the shared composition with the peer-driven-apply preflight flag
/// set so the Run 194 composition layers its own MainNet refusal.
pub fn route_loaded_remote_signer_attestation_to_peer_driven_drain_callsite_decision(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerPayloadCarryingDecisionOutcome {
    if ctx.binds_mainnet(loaded.as_parts()) {
        return RemoteSignerPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused;
    }
    route_callsite_decision(ctx, loaded, true)
}

// ===========================================================================
// Custody-class routing convenience
// ===========================================================================

/// Run 196 — route a parsed [`RemoteSignerLoadStatus`] into the Run 194
/// [`validate_remote_signer_for_custody_class`] boundary for the given
/// custody class.
///
/// When the carrier is `Available` and the custody class is
/// `RemoteSigner`, the typed parts are dispatched to the Run 194 remote
/// signer verifier. A `LocalOperatorKey` custody class is refused as
/// [`RemoteSignerOutcome::LocalOperatorKeyCannotSatisfyRemoteSigner`];
/// every other class is refused as
/// [`RemoteSignerOutcome::NotRemoteSignerCustodyClass`]. An absent or
/// malformed carrier is reported via the typed
/// [`RemoteSignerOutcome::MalformedResponse`] reason so this helper
/// always yields a typed Run 194 outcome.
pub fn route_remote_signer_attestation_for_custody_class(
    custody_class: AuthorityCustodyClass,
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> RemoteSignerOutcome {
    match loaded {
        RemoteSignerLoadStatus::Available(parts) => validate_remote_signer_for_custody_class(
            custody_class,
            &parts.identity,
            &parts.request,
            &parts.response,
            ctx.trust_domain,
            ctx.remote_signer_expected,
            ctx.remote_signer_policy,
        ),
        RemoteSignerLoadStatus::Absent => RemoteSignerOutcome::MalformedResponse {
            reason: "remote_signer_attestation carrier absent for custody-class routing"
                .to_string(),
        },
        RemoteSignerLoadStatus::Malformed(e) => RemoteSignerOutcome::MalformedResponse {
            reason: e.to_string(),
        },
    }
}

// ===========================================================================
// Convenience constructor + fail-closed helper
// ===========================================================================

/// Run 196 — convenience constructor mirroring the Run 190
/// `callsite_context_for_authority_custody` helper. Builds a
/// [`RemoteSignerCallsiteContext`] from the natural production call-site
/// inputs the preflight already has in hand.
#[allow(clippy::too_many_arguments)]
pub fn callsite_context_for_remote_signer<'a>(
    custody_attestation: &'a AuthorityCustodyAttestation,
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    trust_domain: &'a AuthorityTrustDomain,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &'a str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&'a str>,
    custody_policy: AuthorityCustodyPolicy,
    remote_signer_expected: &'a RemoteSignerExpectations,
    remote_signer_policy: RemoteSignerPolicy,
    now_unix: u64,
) -> RemoteSignerCallsiteContext<'a> {
    RemoteSignerCallsiteContext {
        custody_attestation,
        persisted,
        candidate,
        trust_domain,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        custody_policy,
        remote_signer_expected,
        remote_signer_policy,
        now_unix,
    }
}

/// Run 196 — explicit fail-closed helper mirroring the Run 190 / Run 194
/// helpers. Returns `true` iff the trust-domain environment is MainNet.
/// Pure data — never reads RemoteSigner material.
pub fn mainnet_peer_driven_apply_remains_refused_under_remote_signer_payload_carrying(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

/// Run 196 — grep-verifiable reachability helper. Routes the carried
/// RemoteSigner parts directly into the Run 194 [`validate_remote_signer`]
/// verifier (without the Run 188 custody composition). Returns `None`
/// when the carrier is not `Available`.
pub fn validate_loaded_remote_signer(
    ctx: &RemoteSignerCallsiteContext<'_>,
    loaded: &RemoteSignerLoadStatus,
) -> Option<RemoteSignerOutcome> {
    loaded.as_parts().map(|parts| {
        validate_remote_signer(
            &parts.identity,
            &parts.request,
            &parts.response,
            ctx.trust_domain,
            ctx.remote_signer_expected,
            ctx.remote_signer_policy,
        )
    })
}