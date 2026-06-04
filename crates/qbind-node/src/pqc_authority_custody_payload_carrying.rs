//! Run 190 — source/test authority-custody metadata carrying and
//! production call-site wiring.
//!
//! ## Strict scope (Run 190)
//!
//! * **Source/test only.** Run 190 does **not** capture release-binary
//!   evidence; release-binary custody-metadata evidence is deferred to
//!   **Run 191**.
//! * **No real KMS/HSM/cloud-KMS/PKCS#11/remote-signer backend.**
//!   `RemoteSigner`, `Kms`, and `Hsm` continue to fail closed as
//!   "unavailable" via the Run 188 validator.
//! * **No MainNet peer-driven apply enablement.** The
//!   Run 147/148/152 MainNet refusal at the peer-driven apply surface
//!   remains intact even with a fully-valid DevNet/TestNet fixture or
//!   local-operator custody attestation carried through this Run 190
//!   payload layer.
//! * **No governance execution engine.**
//! * **No real on-chain proof verifier.**
//! * **No validator-set rotation.**
//! * **No autonomous apply / no apply on receipt / no peer-majority
//!   authority.**
//! * **No marker / sequence-file / authority-marker / trust-bundle
//!   core schema change.** The carrier is a strictly additive,
//!   optional sibling on the existing v2 ratification sidecar JSON
//!   alongside the Run 167 `governance_authority_proof` and Run 184
//!   `onchain_governance_proof` siblings: legacy no-custody payloads
//!   continue to parse and to be accepted under the default
//!   [`AuthorityCustodyPolicy::Disabled`] policy bit-for-bit.
//!
//! Run 190 does **not** weaken any prior run (Runs 070, 130–189) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! Before Run 190 the Run 188 typed [`AuthorityCustodyAttestation`]
//! could only reach the Run 188 validator via in-process source/test
//! construction: every production payload/context delivered the call-
//! site context with no custody material and the Run 188 validator was
//! never reached from a production call site.
//!
//! Run 190 closes that gap at the source/test level by adding:
//!
//! 1. An **additive optional sibling field** —
//!    [`AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD`] — on the
//!    same v2 ratification sidecar JSON document already used by the
//!    Run 167 `governance_authority_proof` and Run 184
//!    `onchain_governance_proof` siblings.
//! 2. A wire/context representation —
//!    [`AuthorityCustodyAttestationWire`] — with explicit
//!    `schema_version` plus typed string-tagged enums for the custody
//!    class and governance authority class. The wire form converts
//!    into the internal Run 188 [`AuthorityCustodyAttestation`] via
//!    [`AuthorityCustodyAttestationWire::to_attestation`]; an unknown
//!    `schema_version` or empty required field fails closed.
//! 3. A typed [`AuthorityCustodyLoadStatus`] (`Absent` / `Available`
//!    / `Malformed`) parallel to the Run 167
//!    [`crate::pqc_governance_proof_wire::GovernanceProofLoadStatus`]
//!    and Run 184
//!    [`crate::pqc_onchain_governance_payload_carrying::OnChainGovernanceProofLoadStatus`].
//! 4. A typed
//!    [`AuthorityCustodyAttestationPayloadParseError`] separating
//!    JSON-shape failures from wire-form structural failures.
//! 5. A pure [`parse_optional_authority_custody_attestation_sibling_from_json_value`]
//!    helper that extracts the optional sibling from a generic
//!    `serde_json::Value` envelope.
//! 6. A combined v2 sidecar loader
//!    [`load_v2_ratification_sidecar_with_authority_custody_attestation_from_path`]
//!    (and bytes variant) that returns BOTH the typed
//!    [`qbind_ledger::BundleSigningRatificationV2`] AND the typed
//!    Run 190 [`AuthorityCustodyLoadStatus`] alongside the existing
//!    Run 167 / Run 184 carriers. The same parse helper is reused by
//!    the live inbound `0x05` peer-candidate envelope path so the
//!    live-wire surface can extend its existing optional-sibling
//!    envelope without a new schema.
//! 7. A typed [`AuthorityCustodyCallsiteContext`] — the natural
//!    production call-site inputs already available at every Run 188
//!    custody decision.
//! 8. Seven typed per-surface routing helpers
//!    ([`route_loaded_authority_custody_attestation_to_*_callsite_decision`])
//!    that bind a parsed [`AuthorityCustodyLoadStatus`] to the seven
//!    production v2 marker-decision surfaces (reload-check / reload-
//!    apply / startup `--p2p-trust-bundle` / SIGHUP / local
//!    peer-candidate-check / live inbound `0x05` / peer-driven drain)
//!    with:
//!      * a typed
//!        [`AuthorityCustodyPayloadCarryingDecisionOutcome::MalformedAuthorityCustodyAttestationPayload`]
//!        variant placed *in front of* the Run 188 validator so a
//!        malformed carrier fails closed BEFORE the validator is
//!        invoked, BEFORE any sequence/marker write, BEFORE any live
//!        trust swap, BEFORE any session eviction, and BEFORE any Run
//!        070 call;
//!      * a typed
//!        [`AuthorityCustodyPayloadCarryingDecisionOutcome::CustodyAttestationRequiredButAbsent`]
//!        variant when the active policy requires custody and the
//!        carrier is absent;
//!      * a typed
//!        [`AuthorityCustodyPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied`]
//!        bypass variant when the active policy is `Disabled` and the
//!        carrier is absent — this is the legacy no-custody payload
//!        compatibility variant;
//!      * a typed
//!        [`AuthorityCustodyPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
//!        variant on the peer-driven drain surface that fires *before*
//!        the validator regardless of custody-attestation contents,
//!        mirroring the Run 147 / 148 / 152 MainNet refusal;
//!      * an inner Run 188
//!        [`LifecycleGovernanceCustodyOutcome`] that already enumerates
//!        accepted / lifecycle-rejected / custody-rejected /
//!        MainNet-peer-driven-apply-refused.
//!
//! ## Pure / non-mutating
//!
//! The loaders perform read-only file I/O. The routing helpers do not
//! perform any I/O. No marker write, no sequence write, no live trust
//! swap, no session eviction, no Run 070 call. Mutating callers
//! (reload-apply / startup `--p2p-trust-bundle` / SIGHUP /
//! peer-driven drain) remain responsible for honoring the existing
//! `commit_sequence` → `persist_accepted_v2_marker_after_commit_boundary`
//! sequence-before-marker ordering AFTER Run 190 acceptance.
//!
//! ## Wire compatibility
//!
//! * Existing Run 167 / Run 184 v2 sidecars (with or without the
//!   `governance_authority_proof` or `onchain_governance_proof`
//!   siblings) continue to parse exactly as before Run 190 — the new
//!   `authority_custody_attestation` sibling is `#[serde(default)]`-
//!   equivalent (extracted from the surrounding `serde_json::Value`
//!   and absent if missing).
//! * A v2 sidecar carrying any combination of the Run 167, Run 184,
//!   and Run 190 siblings parses into the corresponding typed
//!   objects independently.
//! * A malformed Run 190 sibling does not poison the v2 ratification
//!   parse: the loader still returns the typed
//!   [`qbind_ledger::BundleSigningRatificationV2`] together with a
//!   typed [`AuthorityCustodyLoadStatus::Malformed`] status, so the
//!   call-site routing helper can emit a typed fail-closed
//!   [`AuthorityCustodyPayloadCarryingDecisionOutcome::MalformedAuthorityCustodyAttestationPayload`]
//!   without losing the underlying ratification or its existing
//!   Run 167 / Run 184 carriers.
//! * Unknown `schema_version` values fail closed at the wire-form
//!   layer (`UnknownSchemaVersion`) — a future schema bump cannot be
//!   silently accepted by Run 190 source code.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pqc_authority_custody::{
    validate_lifecycle_governance_and_custody, AuthorityCustodyAttestation, AuthorityCustodyClass,
    AuthorityCustodyPolicy, LifecycleGovernanceCustodyOutcome,
};
use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, LocalLifecycleAction};
use crate::pqc_authority_state::{
    PersistentAuthorityStateRecordV2, PersistentAuthorityStateRecordVersioned,
};
use crate::pqc_governance_authority::GovernanceAuthorityClass;
use crate::pqc_governance_proof_wire::{GovernanceAuthorityProofWire, GovernanceProofLoadStatus};
use crate::pqc_onchain_governance_payload_carrying::{
    parse_optional_onchain_governance_proof_sibling_from_json_value,
    OnChainGovernanceProofLoadStatus,
};
use crate::pqc_onchain_governance_proof::OnChainGovernanceProofWire;
use crate::pqc_ratification_input::VersionedRatificationInputError;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

// ===========================================================================
// Sibling field name + schema version
// ===========================================================================

/// JSON sibling field name carrying the Run 190 optional
/// [`AuthorityCustodyAttestationWire`] on the v2 ratification sidecar
/// envelope.
///
/// The field is strictly additive: legacy sidecars without this
/// sibling parse exactly as before and yield
/// [`AuthorityCustodyLoadStatus::Absent`].
pub const AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD: &str =
    "authority_custody_attestation";

/// Run 190 — wire schema version for the additive optional
/// [`AuthorityCustodyAttestationWire`] sibling. Versioning is additive:
/// a future run extending the wire shape MUST bump this constant.
/// Run 190 rejects unknown versions with
/// [`AuthorityCustodyAttestationWireParseError::UnknownSchemaVersion`].
pub const AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION: u32 = 1;

// ===========================================================================
// Wire-tagged enums
// ===========================================================================

/// Run 190 — wire-tagged form of [`AuthorityCustodyClass`].
///
/// Run 188's [`AuthorityCustodyClass`] does not derive `Serialize` /
/// `Deserialize` (it is an internal symbol), so Run 190 mirrors it as
/// a string-tagged wire enum and converts in
/// [`AuthorityCustodyAttestationWire::to_attestation`]. Unknown tag
/// values map to [`AuthorityCustodyClass::Unknown`] which the Run 188
/// validator already rejects as
/// [`AuthorityCustodyValidationOutcome::UnknownCustodyClassRejected`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityCustodyClassWire {
    FixtureLocalKey,
    LocalOperatorKey,
    RemoteSigner,
    Kms,
    Hsm,
    Unknown,
}

impl AuthorityCustodyClassWire {
    pub const fn to_class(self) -> AuthorityCustodyClass {
        match self {
            Self::FixtureLocalKey => AuthorityCustodyClass::FixtureLocalKey,
            Self::LocalOperatorKey => AuthorityCustodyClass::LocalOperatorKey,
            Self::RemoteSigner => AuthorityCustodyClass::RemoteSigner,
            Self::Kms => AuthorityCustodyClass::Kms,
            Self::Hsm => AuthorityCustodyClass::Hsm,
            Self::Unknown => AuthorityCustodyClass::Unknown,
        }
    }

    pub const fn from_class(c: AuthorityCustodyClass) -> Self {
        match c {
            AuthorityCustodyClass::FixtureLocalKey => Self::FixtureLocalKey,
            AuthorityCustodyClass::LocalOperatorKey => Self::LocalOperatorKey,
            AuthorityCustodyClass::RemoteSigner => Self::RemoteSigner,
            AuthorityCustodyClass::Kms => Self::Kms,
            AuthorityCustodyClass::Hsm => Self::Hsm,
            AuthorityCustodyClass::Unknown => Self::Unknown,
        }
    }
}

/// Run 190 — wire-tagged form of [`GovernanceAuthorityClass`].
///
/// Mirrors Run 163's `GovernanceAuthorityClass` as a string-tagged
/// wire enum (the internal symbol does not derive `Serialize` /
/// `Deserialize`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GovernanceAuthorityClassWire {
    GenesisBound,
    EmergencyCouncil,
    OnChainGovernance,
}

impl GovernanceAuthorityClassWire {
    pub const fn to_class(self) -> GovernanceAuthorityClass {
        match self {
            Self::GenesisBound => GovernanceAuthorityClass::GenesisBound,
            Self::EmergencyCouncil => GovernanceAuthorityClass::EmergencyCouncil,
            Self::OnChainGovernance => GovernanceAuthorityClass::OnChainGovernance,
        }
    }

    pub const fn from_class(c: GovernanceAuthorityClass) -> Self {
        match c {
            GovernanceAuthorityClass::GenesisBound => Self::GenesisBound,
            GovernanceAuthorityClass::EmergencyCouncil => Self::EmergencyCouncil,
            GovernanceAuthorityClass::OnChainGovernance => Self::OnChainGovernance,
        }
    }
}

// ===========================================================================
// Wire form
// ===========================================================================

/// Run 190 — wire-safe encoding of [`AuthorityCustodyAttestation`].
///
/// Carried as an additional optional sibling field on the Run 167 /
/// Run 184 governance-proof-carrying v2 ratification sidecar JSON.
/// Old sidecars (Runs 167–189) that do not carry this sibling
/// continue to parse and validate exactly as before — the sibling is
/// `#[serde(default)]`-equivalent at the Run 190 sibling extractor
/// level.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityCustodyAttestationWire {
    pub schema_version: u32,

    pub custody_class: AuthorityCustodyClassWire,
    pub custody_key_id: String,
    pub custody_suite_id: u8,
    pub custody_attestation_digest: String,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub freshness_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_unix: Option<u64>,

    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub bundle_signing_key_fingerprint: String,

    pub governance_authority_class: GovernanceAuthorityClassWire,
    pub lifecycle_action: LocalLifecycleAction,
    pub candidate_digest: String,
    pub authority_domain_sequence: u64,
}

impl AuthorityCustodyAttestationWire {
    /// Convert the Run 190 wire form into the internal Run 188
    /// [`AuthorityCustodyAttestation`].
    ///
    /// Fails closed when:
    ///
    /// * the `schema_version` is not the one Run 190 supports
    ///   ([`AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION`]);
    /// * any required string field is empty.
    ///
    /// The conversion does not interpret the
    /// `custody_attestation_digest` bytes — it only enforces presence.
    /// All trust-domain / lifecycle / governance / sequence /
    /// candidate-digest / custody-key-id / suite-id / freshness checks
    /// are deferred to the Run 188 validator.
    pub fn to_attestation(
        &self,
    ) -> Result<AuthorityCustodyAttestation, AuthorityCustodyAttestationWireParseError> {
        if self.schema_version != AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION {
            return Err(AuthorityCustodyAttestationWireParseError::UnknownSchemaVersion {
                got: self.schema_version,
                expected: AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION,
            });
        }
        if self.custody_key_id.is_empty()
            || self.custody_attestation_digest.is_empty()
            || self.chain_id.is_empty()
            || self.genesis_hash.is_empty()
            || self.authority_root_fingerprint.is_empty()
            || self.bundle_signing_key_fingerprint.is_empty()
            || self.candidate_digest.is_empty()
        {
            return Err(AuthorityCustodyAttestationWireParseError::EmptyRequiredField);
        }
        Ok(AuthorityCustodyAttestation {
            custody_class: self.custody_class.to_class(),
            custody_key_id: self.custody_key_id.clone(),
            custody_suite_id: self.custody_suite_id,
            custody_attestation_digest: self.custody_attestation_digest.clone(),
            freshness_unix: self.freshness_unix,
            expires_at_unix: self.expires_at_unix,
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            bundle_signing_key_fingerprint: self.bundle_signing_key_fingerprint.clone(),
            governance_authority_class: self.governance_authority_class.to_class(),
            lifecycle_action: self.lifecycle_action,
            candidate_digest: self.candidate_digest.clone(),
            authority_domain_sequence: self.authority_domain_sequence,
        })
    }

    /// Build a Run 190 wire form from an in-process Run 188
    /// [`AuthorityCustodyAttestation`]. Source/test helper.
    pub fn from_attestation(a: &AuthorityCustodyAttestation) -> Self {
        Self {
            schema_version: AUTHORITY_CUSTODY_ATTESTATION_WIRE_SCHEMA_VERSION,
            custody_class: AuthorityCustodyClassWire::from_class(a.custody_class),
            custody_key_id: a.custody_key_id.clone(),
            custody_suite_id: a.custody_suite_id,
            custody_attestation_digest: a.custody_attestation_digest.clone(),
            freshness_unix: a.freshness_unix,
            expires_at_unix: a.expires_at_unix,
            environment: a.environment,
            chain_id: a.chain_id.clone(),
            genesis_hash: a.genesis_hash.clone(),
            authority_root_fingerprint: a.authority_root_fingerprint.clone(),
            bundle_signing_key_fingerprint: a.bundle_signing_key_fingerprint.clone(),
            governance_authority_class: GovernanceAuthorityClassWire::from_class(
                a.governance_authority_class,
            ),
            lifecycle_action: a.lifecycle_action,
            candidate_digest: a.candidate_digest.clone(),
            authority_domain_sequence: a.authority_domain_sequence,
        }
    }
}

// ===========================================================================
// Typed wire-form parse error
// ===========================================================================

/// Run 190 — typed wire-form parse error emitted by
/// [`AuthorityCustodyAttestationWire::to_attestation`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityCustodyAttestationWireParseError {
    /// The wire form's `schema_version` is not the one Run 190
    /// supports.
    UnknownSchemaVersion { got: u32, expected: u32 },
    /// One of the required string fields was empty.
    EmptyRequiredField,
}

impl std::fmt::Display for AuthorityCustodyAttestationWireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownSchemaVersion { got, expected } => write!(
                f,
                "[run-190] unsupported authority_custody_attestation schema_version={} (expected {}). Fail closed.",
                got, expected
            ),
            Self::EmptyRequiredField => write!(
                f,
                "[run-190] authority_custody_attestation has an empty required field. Fail closed."
            ),
        }
    }
}

impl std::error::Error for AuthorityCustodyAttestationWireParseError {}

// ===========================================================================
// Typed payload-level parse error
// ===========================================================================

/// Run 190 — typed parse error emitted at the payload/sibling
/// boundary when an `authority_custody_attestation` sibling is present
/// but cannot be converted into a typed
/// [`AuthorityCustodyAttestation`].
///
/// Distinct from [`AuthorityCustodyAttestationWireParseError`] so that
/// JSON-shape failures (which are payload-level) are kept separate
/// from wire-form structural failures (which are Run 190 schema-
/// level). Both map to a single
/// [`AuthorityCustodyPayloadCarryingDecisionOutcome::MalformedAuthorityCustodyAttestationPayload`]
/// variant at the call-site routing helpers and never to a partially
/// parsed attestation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityCustodyAttestationPayloadParseError {
    /// JSON decoding of the optional `authority_custody_attestation`
    /// sibling field failed.
    Json { error: String },
    /// The sibling decoded as an [`AuthorityCustodyAttestationWire`]
    /// but the wire form failed structural validation (unknown
    /// schema_version, empty required field).
    Wire(AuthorityCustodyAttestationWireParseError),
}

impl std::fmt::Display for AuthorityCustodyAttestationPayloadParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { error } => write!(
                f,
                "[run-190] failed to JSON-decode optional `{}` sibling: {}. Fail closed.",
                AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD, error
            ),
            Self::Wire(e) => write!(f, "[run-190] {}", e),
        }
    }
}

impl std::error::Error for AuthorityCustodyAttestationPayloadParseError {}

impl From<AuthorityCustodyAttestationWireParseError>
    for AuthorityCustodyAttestationPayloadParseError
{
    fn from(e: AuthorityCustodyAttestationWireParseError) -> Self {
        Self::Wire(e)
    }
}

// ===========================================================================
// Typed load status
// ===========================================================================

/// Run 190 — typed load status of the optional
/// [`AuthorityCustodyAttestationWire`] sibling on the v2 ratification
/// sidecar JSON / `0x05` peer-candidate envelope.
///
/// Pure data; carries no live trust state and triggers no I/O on
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityCustodyLoadStatus {
    /// The carrier carried no `authority_custody_attestation` sibling
    /// field. Backwards-compatible with all pre-Run-190 v2 sidecars
    /// and live envelopes — a no-custody payload remains accepted
    /// under the default [`AuthorityCustodyPolicy::Disabled`] policy.
    Absent,
    /// The carrier carried a well-formed wire attestation which was
    /// structurally converted into a typed Run 188
    /// [`AuthorityCustodyAttestation`]. The attestation has NOT yet
    /// been validated against trust-domain / lifecycle / governance /
    /// custody bindings — validation is performed by the Run 190
    /// per-surface routing helpers which delegate to the Run 188
    /// validator.
    Available(AuthorityCustodyAttestation),
    /// The carrier carried an `authority_custody_attestation` sibling
    /// field that failed to decode at the JSON layer or failed wire
    /// structural validation. Always fails closed at the Run 190
    /// per-surface routing helpers.
    Malformed(AuthorityCustodyAttestationPayloadParseError),
}

impl AuthorityCustodyLoadStatus {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed(_))
    }

    /// Borrow the typed [`AuthorityCustodyAttestation`] when the
    /// carrier was well-formed. `None` for `Absent` and `Malformed`.
    pub fn as_attestation(&self) -> Option<&AuthorityCustodyAttestation> {
        match self {
            Self::Available(a) => Some(a),
            Self::Absent | Self::Malformed(_) => None,
        }
    }

    /// Return the typed parse error when the carrier was malformed.
    pub fn malformed_error(&self) -> Option<&AuthorityCustodyAttestationPayloadParseError> {
        match self {
            Self::Malformed(e) => Some(e),
            Self::Absent | Self::Available(_) => None,
        }
    }
}

// ===========================================================================
// Sibling parsing
// ===========================================================================

/// Run 190 — pure parse helper that extracts the optional
/// `authority_custody_attestation` sibling from a generic JSON value
/// and returns a typed [`AuthorityCustodyLoadStatus`].
///
/// Behaviour:
///
/// * `value` has no `authority_custody_attestation` field, or the
///   field is `null`: returns [`AuthorityCustodyLoadStatus::Absent`].
/// * `value` has a non-null `authority_custody_attestation` field
///   that fails to decode as [`AuthorityCustodyAttestationWire`]:
///   returns [`AuthorityCustodyLoadStatus::Malformed`] carrying a
///   [`AuthorityCustodyAttestationPayloadParseError::Json`].
/// * `value` has a well-formed wire object but
///   [`AuthorityCustodyAttestationWire::to_attestation`] rejects it
///   (unknown schema version, empty required field): returns
///   [`AuthorityCustodyLoadStatus::Malformed`] carrying the wire
///   parse error.
/// * Otherwise: returns [`AuthorityCustodyLoadStatus::Available`]
///   with the typed Run 188 attestation.
///
/// Pure — does not mutate `value` and performs no I/O.
pub fn parse_optional_authority_custody_attestation_sibling_from_json_value(
    value: &Value,
) -> AuthorityCustodyLoadStatus {
    let sibling = value.get(AUTHORITY_CUSTODY_ATTESTATION_PAYLOAD_SIBLING_FIELD);
    match sibling {
        None => AuthorityCustodyLoadStatus::Absent,
        Some(Value::Null) => AuthorityCustodyLoadStatus::Absent,
        Some(raw) => match serde_json::from_value::<AuthorityCustodyAttestationWire>(raw.clone()) {
            Ok(wire) => match wire.to_attestation() {
                Ok(a) => AuthorityCustodyLoadStatus::Available(a),
                Err(e) => AuthorityCustodyLoadStatus::Malformed(
                    AuthorityCustodyAttestationPayloadParseError::Wire(e),
                ),
            },
            Err(e) => AuthorityCustodyLoadStatus::Malformed(
                AuthorityCustodyAttestationPayloadParseError::Json {
                    error: e.to_string(),
                },
            ),
        },
    }
}

// ===========================================================================
// Combined v2 sidecar loader (Run 167 + Run 184 + Run 190)
// ===========================================================================

/// Run 190 — typed result of loading a v2 ratification sidecar
/// together with all three optional carrier siblings: Run 167
/// [`GovernanceAuthorityProofWire`], Run 184
/// [`OnChainGovernanceProofWire`], and Run 190
/// [`AuthorityCustodyAttestationWire`].
///
/// Strictly additive over the Run 184 combined sidecar: pre-Run-190
/// sidecars yield [`AuthorityCustodyLoadStatus::Absent`] in the new
/// field and continue to expose the existing Run 167 / Run 184 load
/// statuses unchanged.
#[derive(Debug, Clone)]
pub struct LoadedV2RatificationSidecarWithAuthorityCustodyAttestation {
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    pub governance_proof: GovernanceProofLoadStatus,
    pub onchain_governance_proof: OnChainGovernanceProofLoadStatus,
    pub authority_custody_attestation: AuthorityCustodyLoadStatus,
}

/// Run 190 — load a v2 ratification sidecar JSON file and additionally
/// attempt to parse all three optional sibling fields:
///
/// * Run 167 `governance_authority_proof`
/// * Run 184 `onchain_governance_proof`
/// * Run 190 `authority_custody_attestation`
///
/// All three optional sibling fields are **strictly additive**. A v2
/// sidecar without any of them continues to parse as before and
/// yields the corresponding `Absent` load status for each missing
/// sibling.
///
/// A sibling that fails to deserialise into its wire form, or that
/// fails wire-form structural validation, yields the corresponding
/// `Malformed` load status independently of the other siblings. The
/// v2 ratification itself is still returned so the caller can fall
/// through the policy/gate pipeline.
///
/// A v1 sidecar at this path is rejected with
/// [`VersionedRatificationInputError::MalformedSidecar`] because all
/// three carriers are v2-only by design.
///
/// No file write, no marker write, no sequence write, no live trust
/// swap, no session eviction, no Run 070 call.
pub fn load_v2_ratification_sidecar_with_authority_custody_attestation_from_path(
    path: &Path,
) -> Result<
    LoadedV2RatificationSidecarWithAuthorityCustodyAttestation,
    VersionedRatificationInputError,
> {
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    load_v2_ratification_sidecar_with_authority_custody_attestation_from_bytes(&bytes, path)
}

/// Run 190 — bytes-form variant of
/// [`load_v2_ratification_sidecar_with_authority_custody_attestation_from_path`].
///
/// Used by validation-only / live-inbound surfaces that already hold
/// the JSON envelope in memory and do not need to reread the local
/// file. The `path_for_diagnostics` argument is only used to populate
/// typed [`VersionedRatificationInputError`] variants — it does NOT
/// trigger any file access on this code path.
pub fn load_v2_ratification_sidecar_with_authority_custody_attestation_from_bytes(
    bytes: &[u8],
    path_for_diagnostics: &Path,
) -> Result<
    LoadedV2RatificationSidecarWithAuthorityCustodyAttestation,
    VersionedRatificationInputError,
> {
    let value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(|e| VersionedRatificationInputError::JsonParse {
            path: path_for_diagnostics.to_path_buf(),
            error: e.to_string(),
        })?;

    let version_value = value
        .get("schema_version")
        .or_else(|| value.get("version"));
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
                "Run 190 authority-custody-attestation carrier requires v2 sidecar (got schema_version={})",
                version_int
            ),
        });
    }

    // Extract optional siblings BEFORE re-parsing into the typed
    // ratification, so neither sibling can poison the v2 parse and so
    // each sibling produces its own typed load status independently.
    let governance_proof = parse_optional_governance_authority_proof_sibling(&value);
    let onchain_governance_proof =
        parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
    let authority_custody_attestation =
        parse_optional_authority_custody_attestation_sibling_from_json_value(&value);

    let ratification: qbind_ledger::BundleSigningRatificationV2 = serde_json::from_value(value)
        .map_err(|e| VersionedRatificationInputError::MalformedSidecar {
            path: path_for_diagnostics.to_path_buf(),
            schema_version: 2,
            error: e.to_string(),
        })?;

    Ok(LoadedV2RatificationSidecarWithAuthorityCustodyAttestation {
        ratification,
        governance_proof,
        onchain_governance_proof,
        authority_custody_attestation,
    })
}

/// Run 190 internal helper — extract the Run 167
/// `governance_authority_proof` sibling from a generic JSON value and
/// return a typed [`GovernanceProofLoadStatus`]. Mirrors the Run 184
/// helper of the same shape; kept private here so the Run 190
/// combined loader does not have to re-read the file.
fn parse_optional_governance_authority_proof_sibling(value: &Value) -> GovernanceProofLoadStatus {
    use crate::pqc_governance_proof_wire::GovernanceProofWireParseError;
    let sibling = value.get("governance_authority_proof");
    match sibling {
        None => GovernanceProofLoadStatus::Absent,
        Some(Value::Null) => GovernanceProofLoadStatus::Absent,
        Some(raw) => match serde_json::from_value::<GovernanceAuthorityProofWire>(raw.clone()) {
            Ok(wire) => match wire.to_governance_authority_proof() {
                Ok(proof) => GovernanceProofLoadStatus::Available(proof),
                Err(e) => GovernanceProofLoadStatus::Malformed(e),
            },
            Err(e) => GovernanceProofLoadStatus::Malformed(GovernanceProofWireParseError::Json {
                error: e.to_string(),
            }),
        },
    }
}

// ===========================================================================
// Wire-encoding helper for the additive sibling
// ===========================================================================

/// Run 190 — additive optional sibling shape used to produce a v2
/// ratification sidecar JSON document that carries an
/// [`AuthorityCustodyAttestationWire`] alongside the typed
/// [`qbind_ledger::BundleSigningRatificationV2`] (and optionally the
/// Run 167 / Run 184 siblings).
///
/// Source/test helper. Production paths continue to write the
/// `BundleSigningRatificationV2` directly when no custody is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RatificationSidecarWithAuthorityCustodyAttestationWire {
    #[serde(flatten)]
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authority_custody_attestation: Option<AuthorityCustodyAttestationWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onchain_governance_proof: Option<OnChainGovernanceProofWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_authority_proof: Option<GovernanceAuthorityProofWire>,
}

// ===========================================================================
// Call-site context
// ===========================================================================

/// Run 190 — typed bundle of the natural production call-site inputs
/// required to drive a Run 188 lifecycle + governance + custody
/// preflight at any of the seven production v2 marker-decision
/// surfaces.
///
/// Every field is borrowed; the struct is purely a typed argument
/// bundle and never mutates any input. Constructing it is free of I/O.
#[derive(Debug)]
pub struct AuthorityCustodyCallsiteContext<'a> {
    /// Persisted v2 record (the on-disk authority marker state) when
    /// the call site has one in hand. `None` for `ActivateInitial`
    /// and for surfaces called before the marker exists on disk.
    pub persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    /// Candidate v2 record being preflighted by the call site.
    pub candidate: &'a PersistentAuthorityStateRecordV2,
    /// Active trust domain (env / chain / genesis / authority root /
    /// suite) at the call site.
    pub trust_domain: &'a AuthorityTrustDomain,
    /// Active Run 188 [`AuthorityCustodyPolicy`] resolved by the
    /// calling surface. Default in production is
    /// [`AuthorityCustodyPolicy::Disabled`]; explicit fixture / DevNet
    /// / TestNet local-operator policies are available only in
    /// tests / internal contexts; production-required policies fail
    /// closed for KMS / HSM / RemoteSigner placeholders via the
    /// Run 188 validator.
    pub policy: AuthorityCustodyPolicy,
    /// Expected governance authority class binding for the Run 188
    /// validator (e.g. `GenesisBound` for a routine rotation; a
    /// future run may pass `OnChainGovernance` once the Run 178+
    /// proof verifier surface delivers a typed accepted-class
    /// decision).
    pub expected_governance_authority_class: GovernanceAuthorityClass,
    /// Expected lifecycle action binding for the Run 188 validator.
    pub expected_lifecycle_action: LocalLifecycleAction,
    /// Expected candidate digest binding for the Run 188 validator.
    pub expected_candidate_digest: &'a str,
    /// Expected next authority-domain sequence binding.
    pub expected_authority_domain_sequence: u64,
    /// Optional expected custody key id binding. `None` skips key-id
    /// enforcement (used by helpers that only need the policy /
    /// placeholder fail-closed shape).
    pub expected_custody_key_id: Option<&'a str>,
    /// Wall-clock seconds-since-epoch used by the freshness binding.
    pub now_unix: u64,
}

impl<'a> AuthorityCustodyCallsiteContext<'a> {
    /// Run 190 — pure surface-level MainNet refusal helper. Returns
    /// `true` iff the candidate, the trust domain, or the attestation
    /// binds MainNet. Used by [`route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision`]
    /// before the validator is even invoked, mirroring the Run 152
    /// MainNet peer-driven-apply refusal at the calling surface.
    pub fn binds_mainnet(&self, attestation: Option<&AuthorityCustodyAttestation>) -> bool {
        self.trust_domain.environment == TrustBundleEnvironment::Mainnet
            || self.candidate.environment == TrustBundleEnvironment::Mainnet
            || attestation
                .map(|a| a.environment == TrustBundleEnvironment::Mainnet)
                .unwrap_or(false)
    }
}

// ===========================================================================
// Routing into Run 188 validation
// ===========================================================================

/// Run 190 — typed outcome of routing a Run 190
/// [`AuthorityCustodyLoadStatus`] through any of the seven production
/// v2 marker-decision surfaces.
///
/// Adds three typed variants in front of the Run 188
/// [`LifecycleGovernanceCustodyOutcome`]:
///
/// * [`Self::MalformedAuthorityCustodyAttestationPayload`] — the
///   carrier sibling was present but malformed at the JSON or wire-
///   structural level. Always fail-closed regardless of policy. The
///   Run 188 validator is NOT invoked.
/// * [`Self::CustodyAttestationRequiredButAbsent`] — the active
///   policy requires custody (every non-`Disabled` policy) and the
///   carrier sibling is absent. Always fail-closed.
/// * [`Self::NoCustodyAttestationSupplied`] — the carrier sibling is
///   absent and the active policy is
///   [`AuthorityCustodyPolicy::Disabled`]. Legacy no-custody payload
///   compatibility variant; the calling surface continues with its
///   pre-Run-190 path. The Run 188 validator is NOT invoked.
/// * [`Self::MainNetPeerDrivenApplyRefused`] — the peer-driven drain
///   surface refuses MainNet unconditionally regardless of custody-
///   attestation contents.
/// * [`Self::Callsite`] — wraps the Run 188
///   [`LifecycleGovernanceCustodyOutcome`] for every other case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityCustodyPayloadCarryingDecisionOutcome {
    /// The carrier sibling was present but malformed. Fail closed
    /// before any Run 188 validation, before any sequence/marker
    /// write, before any live trust swap, before any session
    /// eviction, before any Run 070 call.
    MalformedAuthorityCustodyAttestationPayload(AuthorityCustodyAttestationPayloadParseError),
    /// The active policy requires custody and the carrier sibling is
    /// absent. Fail closed.
    CustodyAttestationRequiredButAbsent { policy: AuthorityCustodyPolicy },
    /// The carrier sibling is absent and the active policy is
    /// `Disabled`. Legacy no-custody payload compatibility.
    NoCustodyAttestationSupplied,
    /// MainNet peer-driven apply remains the Run 147 / 148 / 152
    /// FATAL refusal regardless of custody-attestation contents.
    /// Surfaced only by the peer-driven drain routing helper.
    MainNetPeerDrivenApplyRefused,
    /// The carrier sibling parsed and the Run 188 validator was
    /// invoked. Carries the typed Run 188 combined lifecycle +
    /// governance + custody outcome.
    Callsite(LifecycleGovernanceCustodyOutcome),
}

impl AuthorityCustodyPayloadCarryingDecisionOutcome {
    pub fn is_accept(&self) -> bool {
        match self {
            Self::Callsite(o) => o.is_accept(),
            _ => false,
        }
    }

    pub fn is_reject(&self) -> bool {
        !self.is_accept() && !self.is_bypassed()
    }

    /// `true` iff the policy was `Disabled` and the carrier was
    /// absent — the legacy no-custody-payload bypass variant.
    pub fn is_bypassed(&self) -> bool {
        matches!(self, Self::NoCustodyAttestationSupplied)
    }

    pub fn is_malformed_payload(&self) -> bool {
        matches!(self, Self::MalformedAuthorityCustodyAttestationPayload(_))
    }

    pub fn is_required_but_absent(&self) -> bool {
        matches!(self, Self::CustodyAttestationRequiredButAbsent { .. })
    }

    pub fn is_mainnet_peer_driven_apply_refused(&self) -> bool {
        matches!(self, Self::MainNetPeerDrivenApplyRefused)
    }

    /// Borrow the inner Run 188 outcome, if any.
    pub fn callsite_outcome(&self) -> Option<&LifecycleGovernanceCustodyOutcome> {
        match self {
            Self::Callsite(o) => Some(o),
            _ => None,
        }
    }
}

/// Internal — short-circuit a malformed-carrier load status into the
/// Run 190 fail-closed outcome. `Absent` and `Available` return
/// `None`, in which case the caller continues per-surface.
fn malformed_payload_shortcircuit(
    loaded: &AuthorityCustodyLoadStatus,
) -> Option<AuthorityCustodyPayloadCarryingDecisionOutcome> {
    match loaded {
        AuthorityCustodyLoadStatus::Malformed(e) => Some(
            AuthorityCustodyPayloadCarryingDecisionOutcome::MalformedAuthorityCustodyAttestationPayload(
                e.clone(),
            ),
        ),
        AuthorityCustodyLoadStatus::Absent | AuthorityCustodyLoadStatus::Available(_) => None,
    }
}

/// Internal — handle the absent-carrier case under the active policy.
/// Returns `None` only when the carrier is `Available`.
fn absent_or_available_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> Option<AuthorityCustodyPayloadCarryingDecisionOutcome> {
    match loaded {
        AuthorityCustodyLoadStatus::Absent => match ctx.policy {
            AuthorityCustodyPolicy::Disabled => Some(
                AuthorityCustodyPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied,
            ),
            other => Some(
                AuthorityCustodyPayloadCarryingDecisionOutcome::CustodyAttestationRequiredButAbsent {
                    policy: other,
                },
            ),
        },
        AuthorityCustodyLoadStatus::Available(_) => None,
        AuthorityCustodyLoadStatus::Malformed(_) => {
            // Already short-circuited by [`malformed_payload_shortcircuit`].
            None
        }
    }
}

/// Internal — invoke the Run 188 lifecycle + governance + custody
/// validator with the call-site context inputs. Pre-condition:
/// `attestation` is the parsed Run 188 attestation extracted from a
/// well-formed Run 190 carrier.
fn run_188_validate(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    attestation: &AuthorityCustodyAttestation,
) -> LifecycleGovernanceCustodyOutcome {
    validate_lifecycle_governance_and_custody(
        attestation,
        ctx.candidate,
        ctx.persisted,
        ctx.trust_domain,
        ctx.expected_governance_authority_class,
        ctx.expected_lifecycle_action,
        ctx.expected_candidate_digest,
        ctx.expected_authority_domain_sequence,
        ctx.expected_custody_key_id,
        ctx.policy,
        ctx.now_unix,
    )
}

/// Internal — generic per-surface routing entry shared by every
/// non-`peer_driven_drain` surface. The peer-driven drain routing
/// helper layers the surface-level MainNet refusal in front of this
/// shared composition.
fn route_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    if let Some(short) = malformed_payload_shortcircuit(loaded) {
        return short;
    }
    if let Some(short) = absent_or_available_decision(ctx, loaded) {
        return short;
    }
    let attestation = match loaded {
        AuthorityCustodyLoadStatus::Available(a) => a,
        // Unreachable: short-circuited above.
        _ => unreachable!("malformed_payload_shortcircuit / absent_or_available_decision handled"),
    };
    AuthorityCustodyPayloadCarryingDecisionOutcome::Callsite(run_188_validate(ctx, attestation))
}

/// Run 190 — route a parsed [`AuthorityCustodyLoadStatus`] through
/// the `--p2p-trust-bundle-reload-check` validation-only call-site.
/// Validation-only mutation contract: the caller MUST drop the
/// returned outcome and MUST NOT persist a marker, advance the
/// bundle-signing sequence, swap live trust state, evict sessions, or
/// invoke Run 070.
pub fn route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 190 — route a parsed [`AuthorityCustodyLoadStatus`] through
/// the `--p2p-trust-bundle-reload-apply-*` mutating-preflight call-
/// site. A malformed carrier short-circuits before the validator is
/// invoked, before any sequence/marker write, and before any Run 070
/// call. Mutating callers continue to honor sequence-before-marker
/// ordering after acceptance.
pub fn route_loaded_authority_custody_attestation_to_reload_apply_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 190 — route a parsed [`AuthorityCustodyLoadStatus`] through
/// the startup `--p2p-trust-bundle` mutating-preflight call-site.
/// Same mutation contract as the reload-apply routing helper.
pub fn route_loaded_authority_custody_attestation_to_startup_p2p_trust_bundle_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 190 — route a parsed [`AuthorityCustodyLoadStatus`] through
/// the SIGHUP live trust-bundle reload mutating-preflight call-site.
/// Same mutation contract as the reload-apply routing helper.
pub fn route_loaded_authority_custody_attestation_to_sighup_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 190 — route a parsed [`AuthorityCustodyLoadStatus`] through
/// the local `--p2p-trust-bundle-peer-candidate-check` validation-only
/// call-site. Validation-only mutation contract identical to the
/// reload-check routing helper.
pub fn route_loaded_authority_custody_attestation_to_local_peer_candidate_check_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 190 — route a parsed [`AuthorityCustodyLoadStatus`] through
/// the live inbound `0x05` peer-candidate validation-only call-site.
/// An invalid live `0x05` custody-metadata candidate (malformed
/// payload, absent under non-`Disabled` policy, MainNet binding under
/// fixture/local custody, or rejected by the Run 188 validator) is
/// **not propagated, staged, or applied** — the rejection short-
/// circuits at this routing helper before any staging path is reached.
pub fn route_loaded_authority_custody_attestation_to_live_inbound_0x05_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    route_callsite_decision(ctx, loaded)
}

/// Run 190 — route a parsed [`AuthorityCustodyLoadStatus`] through
/// the Run 150 peer-driven apply drain coordinator
/// (`ProductionV2MarkerCoordinator`) preflight call-site.
///
/// **Surface-level MainNet refusal.** Even if the active
/// [`AuthorityCustodyPolicy`] is `DevnetLocalAllowed` or
/// `TestnetLocalAllowed` and a fully-valid fixture / local-operator
/// custody attestation is supplied, this entry refuses MainNet peer-
/// driven apply unconditionally and returns
/// [`AuthorityCustodyPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused`]
/// before the validator is invoked, mirroring the Run 152 MainNet
/// refusal at the calling surface. The same refusal fires when the
/// custody attestation itself claims `Kms` / `Hsm` / `RemoteSigner` —
/// MainNet peer-driven apply remains refused regardless of custody
/// class. Non-MainNet candidates fall through to the shared
/// composition.
pub fn route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
    ctx: &AuthorityCustodyCallsiteContext<'_>,
    loaded: &AuthorityCustodyLoadStatus,
) -> AuthorityCustodyPayloadCarryingDecisionOutcome {
    if ctx.binds_mainnet(loaded.as_attestation()) {
        return AuthorityCustodyPayloadCarryingDecisionOutcome::MainNetPeerDrivenApplyRefused;
    }
    route_callsite_decision(ctx, loaded)
}

// ===========================================================================
// Optional convenience — build a callsite context from a loaded carrier
// ===========================================================================

/// Run 190 — convenience constructor mirroring the Run 184
/// [`callsite_context_with_loaded_onchain_governance_proof`] helper.
/// Builds an [`AuthorityCustodyCallsiteContext`] from the natural
/// production call-site inputs the preflight already has in hand. The
/// loaded carrier is *not* embedded in the context — it is passed
/// alongside the context to the per-surface routing helpers so the
/// carrier shape (`Absent` / `Available` / `Malformed`) is visible
/// at the routing boundary.
#[allow(clippy::too_many_arguments)]
pub fn callsite_context_for_authority_custody<'a>(
    persisted: Option<&'a PersistentAuthorityStateRecordVersioned>,
    candidate: &'a PersistentAuthorityStateRecordV2,
    trust_domain: &'a AuthorityTrustDomain,
    policy: AuthorityCustodyPolicy,
    expected_governance_authority_class: GovernanceAuthorityClass,
    expected_lifecycle_action: LocalLifecycleAction,
    expected_candidate_digest: &'a str,
    expected_authority_domain_sequence: u64,
    expected_custody_key_id: Option<&'a str>,
    now_unix: u64,
) -> AuthorityCustodyCallsiteContext<'a> {
    AuthorityCustodyCallsiteContext {
        persisted,
        candidate,
        trust_domain,
        policy,
        expected_governance_authority_class,
        expected_lifecycle_action,
        expected_candidate_digest,
        expected_authority_domain_sequence,
        expected_custody_key_id,
        now_unix,
    }
}

/// Run 190 — explicit fail-closed helper mirroring the Run 188
/// helper. Returns `true` iff the trust-domain environment is
/// MainNet. Pure data — never reads custody material.
pub fn mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying(
    environment: TrustBundleEnvironment,
) -> bool {
    environment == TrustBundleEnvironment::Mainnet
}

// ===========================================================================
// In-crate self-tests (smoke-level — full A1-A10 / R1-R32 coverage
// lives in `tests/run_190_authority_custody_payload_callsite_tests.rs`).
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_authority_custody::AuthorityCustodyAttestation;
    use crate::pqc_authority_custody::AuthorityCustodyValidationOutcome;
    use crate::pqc_authority_lifecycle::PQC_LIFECYCLE_SUITE_ML_DSA_44;
    use crate::pqc_authority_state::{
        AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    };
    use qbind_ledger::BundleSigningRatificationV2Action;

    const KEY_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const KEY_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const ROOT_FP: &str = "1111111111111111111111111111111111111111";
    const CHAIN_ID: &str = "0000000000000001";
    const GENESIS_HASH: &str =
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const DIGEST_2: &str =
        "2222222222222222222222222222222222222222222222222222222222222222";
    const CUSTODY_ATTEST_DIGEST: &str = "custody-att-digest-190";
    const CUSTODY_KEY_ID: &str = "custody-key-id-190";
    const NOW: u64 = 1_700_000_000;
    const FRESH: u64 = 1_699_999_900;
    const EXPIRES: u64 = 1_700_001_000;

    fn devnet_domain() -> AuthorityTrustDomain {
        AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            CHAIN_ID,
            GENESIS_HASH,
            ROOT_FP,
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
        )
    }

    fn devnet_candidate() -> PersistentAuthorityStateRecordV2 {
        PersistentAuthorityStateRecordV2::new(
            CHAIN_ID.to_string(),
            TrustBundleEnvironment::Devnet,
            GENESIS_HASH.to_string(),
            ROOT_FP.to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            KEY_B.to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(KEY_A.to_string()),
            DIGEST_2.to_string(),
            None,
            AuthorityStateUpdateSource::TestOrFixture,
            NOW,
        )
    }

    fn devnet_persisted() -> PersistentAuthorityStateRecordVersioned {
        PersistentAuthorityStateRecordVersioned::V2(PersistentAuthorityStateRecordV2::new(
            CHAIN_ID.to_string(),
            TrustBundleEnvironment::Devnet,
            GENESIS_HASH.to_string(),
            ROOT_FP.to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            KEY_A.to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            1,
            BundleSigningRatificationV2Action::Ratify,
            None,
            "1111111111111111111111111111111111111111111111111111111111111111".to_string(),
            None,
            AuthorityStateUpdateSource::TestOrFixture,
            NOW,
        ))
    }

    fn good_fixture_attestation(env: TrustBundleEnvironment) -> AuthorityCustodyAttestation {
        AuthorityCustodyAttestation {
            custody_class: AuthorityCustodyClass::FixtureLocalKey,
            custody_key_id: CUSTODY_KEY_ID.to_string(),
            custody_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
            custody_attestation_digest: CUSTODY_ATTEST_DIGEST.to_string(),
            freshness_unix: Some(FRESH),
            expires_at_unix: Some(EXPIRES),
            environment: env,
            chain_id: CHAIN_ID.to_string(),
            genesis_hash: GENESIS_HASH.to_string(),
            authority_root_fingerprint: ROOT_FP.to_string(),
            bundle_signing_key_fingerprint: KEY_B.to_string(),
            governance_authority_class: GovernanceAuthorityClass::GenesisBound,
            lifecycle_action: LocalLifecycleAction::Rotate,
            candidate_digest: DIGEST_2.to_string(),
            authority_domain_sequence: 2,
        }
    }

    #[test]
    fn absent_sibling_yields_absent_load_status() {
        let value = serde_json::json!({"unrelated": 1});
        let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
        assert!(s.is_absent());
        assert!(s.as_attestation().is_none());
    }

    #[test]
    fn null_sibling_yields_absent_load_status() {
        let value = serde_json::json!({"authority_custody_attestation": null});
        let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
        assert!(s.is_absent());
    }

    #[test]
    fn malformed_json_sibling_yields_malformed_load_status() {
        let value = serde_json::json!({"authority_custody_attestation": "not-an-object"});
        let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
        assert!(s.is_malformed());
        assert!(matches!(
            s.malformed_error().unwrap(),
            AuthorityCustodyAttestationPayloadParseError::Json { .. }
        ));
    }

    #[test]
    fn unsupported_schema_version_yields_malformed_load_status() {
        let mut wire = AuthorityCustodyAttestationWire::from_attestation(
            &good_fixture_attestation(TrustBundleEnvironment::Devnet),
        );
        wire.schema_version = 999;
        let value =
            serde_json::json!({ "authority_custody_attestation": serde_json::to_value(&wire).unwrap() });
        let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
        assert!(s.is_malformed());
        assert!(matches!(
            s.malformed_error().unwrap(),
            AuthorityCustodyAttestationPayloadParseError::Wire(
                AuthorityCustodyAttestationWireParseError::UnknownSchemaVersion { .. }
            )
        ));
    }

    #[test]
    fn well_formed_wire_round_trips_to_attestation() {
        let att = good_fixture_attestation(TrustBundleEnvironment::Devnet);
        let wire = AuthorityCustodyAttestationWire::from_attestation(&att);
        let value =
            serde_json::json!({ "authority_custody_attestation": serde_json::to_value(&wire).unwrap() });
        let s = parse_optional_authority_custody_attestation_sibling_from_json_value(&value);
        assert!(s.is_available());
        assert_eq!(s.as_attestation().unwrap(), &att);
    }

    #[test]
    fn malformed_payload_short_circuits_to_typed_fail_closed() {
        let candidate = devnet_candidate();
        let domain = devnet_domain();
        let loaded = AuthorityCustodyLoadStatus::Malformed(
            AuthorityCustodyAttestationPayloadParseError::Json {
                error: "synthetic".to_string(),
            },
        );
        let ctx = callsite_context_for_authority_custody(
            None,
            &candidate,
            &domain,
            AuthorityCustodyPolicy::FixtureOnly,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            NOW,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                &ctx, &loaded,
            );
        assert!(outcome.is_malformed_payload());
        assert!(outcome.is_reject());
        assert!(!outcome.is_accept());
        assert!(!outcome.is_bypassed());
    }

    #[test]
    fn absent_payload_under_default_disabled_policy_is_bypassed() {
        let candidate = devnet_candidate();
        let domain = devnet_domain();
        let loaded = AuthorityCustodyLoadStatus::Absent;
        let ctx = callsite_context_for_authority_custody(
            None,
            &candidate,
            &domain,
            AuthorityCustodyPolicy::Disabled,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            NOW,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                &ctx, &loaded,
            );
        assert_eq!(
            outcome,
            AuthorityCustodyPayloadCarryingDecisionOutcome::NoCustodyAttestationSupplied
        );
        assert!(outcome.is_bypassed());
        assert!(!outcome.is_accept());
        assert!(!outcome.is_reject());
    }

    #[test]
    fn absent_payload_under_required_policy_fails_closed() {
        let candidate = devnet_candidate();
        let domain = devnet_domain();
        let loaded = AuthorityCustodyLoadStatus::Absent;
        let ctx = callsite_context_for_authority_custody(
            None,
            &candidate,
            &domain,
            AuthorityCustodyPolicy::FixtureOnly,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            NOW,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                &ctx, &loaded,
            );
        assert!(outcome.is_required_but_absent());
        assert!(outcome.is_reject());
    }

    #[test]
    fn peer_driven_drain_refuses_mainnet_before_validation() {
        let candidate = PersistentAuthorityStateRecordV2::new(
            CHAIN_ID.to_string(),
            TrustBundleEnvironment::Mainnet,
            GENESIS_HASH.to_string(),
            ROOT_FP.to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            KEY_B.to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some(KEY_A.to_string()),
            DIGEST_2.to_string(),
            None,
            AuthorityStateUpdateSource::TestOrFixture,
            NOW,
        );
        let mainnet_domain = AuthorityTrustDomain::new(
            TrustBundleEnvironment::Mainnet,
            CHAIN_ID,
            GENESIS_HASH,
            ROOT_FP,
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
        );
        let mut att = good_fixture_attestation(TrustBundleEnvironment::Mainnet);
        att.custody_class = AuthorityCustodyClass::Kms;
        let loaded = AuthorityCustodyLoadStatus::Available(att);
        let ctx = callsite_context_for_authority_custody(
            None,
            &candidate,
            &mainnet_domain,
            AuthorityCustodyPolicy::FixtureOnly,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            NOW,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_peer_driven_drain_callsite_decision(
                &ctx, &loaded,
            );
        assert!(outcome.is_mainnet_peer_driven_apply_refused());
        assert!(outcome.is_reject());
        assert!(mainnet_peer_driven_apply_remains_refused_under_custody_payload_carrying(
            TrustBundleEnvironment::Mainnet
        ));
    }

    #[test]
    fn fixture_attestation_under_devnet_fixture_policy_accepts() {
        let candidate = devnet_candidate();
        let domain = devnet_domain();
        let persisted = devnet_persisted();
        let att = good_fixture_attestation(TrustBundleEnvironment::Devnet);
        let loaded = AuthorityCustodyLoadStatus::Available(att);
        let ctx = callsite_context_for_authority_custody(
            Some(&persisted),
            &candidate,
            &domain,
            AuthorityCustodyPolicy::FixtureOnly,
            GovernanceAuthorityClass::GenesisBound,
            LocalLifecycleAction::Rotate,
            DIGEST_2,
            2,
            Some(CUSTODY_KEY_ID),
            NOW,
        );
        let outcome =
            route_loaded_authority_custody_attestation_to_reload_check_callsite_decision(
                &ctx, &loaded,
            );
        assert!(outcome.is_accept());
        match outcome {
            AuthorityCustodyPayloadCarryingDecisionOutcome::Callsite(
                LifecycleGovernanceCustodyOutcome::Accepted { custody_outcome, .. },
            ) => {
                assert!(matches!(
                    custody_outcome,
                    AuthorityCustodyValidationOutcome::AcceptedFixtureCustody { .. }
                ));
            }
            other => panic!("expected accepted fixture custody, got {:?}", other),
        }
    }
}
