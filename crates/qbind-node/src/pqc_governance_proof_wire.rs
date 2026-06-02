//! Run 167 — additive, versioned wire-safe governance-proof carrier for v2
//! authority / ratification sidecars.
//!
//! ## Strict scope
//!
//! Source/test only. Run 167 does **not**:
//!
//! * enable MainNet peer-driven apply,
//! * implement a governance execution engine,
//! * implement on-chain governance integration,
//! * implement KMS/HSM custody,
//! * implement validator-set rotation,
//! * accept peer-majority / gossip-count as an authority proof,
//! * accept local operator config alone as a MainNet authority proof,
//! * change the v2 ratification, authority-marker, sequence-file, or
//!   trust-bundle wire formats.
//!
//! Release-binary proof-carrying enforcement evidence is **deferred to Run 168**.
//!
//! ## Design
//!
//! Run 167 adds a wire-safe, serde-derived [`GovernanceAuthorityProofWire`]
//! that mirrors every binding carried by the Run 163
//! [`crate::pqc_governance_authority::GovernanceAuthorityProof`]:
//!
//! * environment, chain_id, genesis_hash;
//! * authority_root_fingerprint + authority_root_suite_id;
//! * lifecycle_action (the local sub-classification);
//! * candidate_v2_digest;
//! * authority_domain_sequence;
//! * active / new / revoked bundle-signing key fingerprint where applicable;
//! * issuer authority class, signature suite, and signature bytes;
//! * optional [`GovernanceThresholdWire`] descriptor.
//!
//! The wire object is embedded **only** as an optional sibling field on the
//! v2 ratification sidecar JSON document. The existing
//! [`qbind_ledger::BundleSigningRatificationV2`] struct is **not** modified
//! — sidecars without the optional sibling field continue to parse
//! unchanged (backwards compatibility). The sibling is parsed by the
//! Run 167 sidecar loader [`crate::pqc_ratification_input::
//! load_v2_ratification_sidecar_with_governance_proof_from_path`] and
//! converted into the typed Run 163 proof object.
//!
//! ## Non-authority encodings explicitly rejected
//!
//! The wire format intentionally cannot encode:
//!
//! * peer-majority / gossip count as an authority proof (R16);
//! * local operator config alone as a MainNet authority proof (R15);
//! * an OnChainGovernance proof — that class fails closed in Run 163 and
//!   remains unsupported (R14).
//!
//! ## No mutation
//!
//! Parsing a wire proof performs **no I/O beyond the original sidecar
//! file read**, writes no marker, writes no sequence, and mutates no live
//! trust state. Acceptance does **not** enable MainNet peer-driven apply.

use serde::{Deserialize, Serialize};

use crate::pqc_authority_lifecycle::LocalLifecycleAction;
use crate::pqc_governance_authority::{
    GovernanceAuthorityClass, GovernanceAuthorityProof, GovernanceIssuerSignatureVerifier,
    GovernanceProofContext, GovernanceThreshold,
};
use crate::pqc_trust_bundle::TrustBundleEnvironment;

/// Wire-safe encoding of the issuer authority class.
///
/// Mirrors [`GovernanceAuthorityClass`]. Serialized as a stable lowercase
/// kebab-case tag (`"genesis-bound"`, `"emergency-council"`,
/// `"on-chain-governance"`).
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

    pub const fn from_class(class: GovernanceAuthorityClass) -> Self {
        match class {
            GovernanceAuthorityClass::GenesisBound => Self::GenesisBound,
            GovernanceAuthorityClass::EmergencyCouncil => Self::EmergencyCouncil,
            GovernanceAuthorityClass::OnChainGovernance => Self::OnChainGovernance,
        }
    }
}

/// Wire-safe encoding of [`GovernanceThreshold`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceThresholdWire {
    pub approvals: u32,
    pub required: u32,
    pub total: u32,
}

impl GovernanceThresholdWire {
    pub fn to_threshold(&self) -> GovernanceThreshold {
        GovernanceThreshold::new(self.approvals, self.required, self.total)
    }

    pub fn from_threshold(t: &GovernanceThreshold) -> Self {
        Self {
            approvals: t.approvals,
            required: t.required,
            total: t.total,
        }
    }
}

/// Schema version for the Run 167 wire governance proof carrier.
///
/// Versioning is additive: a future run that extends the wire shape MUST
/// bump this constant. The Run 167 loader rejects unknown schema
/// versions with [`GovernanceProofWireParseError::UnknownSchemaVersion`].
pub const GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION: u32 = 1;

/// Wire-safe governance authority proof carrier.
///
/// Embedded on the v2 ratification sidecar JSON as an optional sibling
/// field `governance_authority_proof`. Parsed by the Run 167 sidecar
/// loader and converted into the typed Run 163
/// [`GovernanceAuthorityProof`] for use with the Run 165 governance
/// gate.
///
/// Run 167 does **not** mutate any persisted state during parsing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceAuthorityProofWire {
    /// Wire schema version. MUST equal
    /// [`GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION`].
    pub schema_version: u32,

    // ---- Trust-domain binding -----------------------------------------
    pub environment: TrustBundleEnvironment,
    pub chain_id: String,
    pub genesis_hash: String,
    pub authority_root_fingerprint: String,
    pub authority_root_suite_id: u8,

    // ---- Lifecycle binding --------------------------------------------
    pub lifecycle_action: LocalLifecycleAction,

    // ---- Key binding --------------------------------------------------
    pub active_bundle_signing_key_fingerprint: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub new_bundle_signing_key_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_bundle_signing_key_fingerprint: Option<String>,

    // ---- Sequence + digest binding ------------------------------------
    pub authority_domain_sequence: u64,
    pub candidate_v2_digest: String,

    // ---- Issuer binding -----------------------------------------------
    pub issuer_authority_class: GovernanceAuthorityClassWire,
    pub issuer_signature_suite_id: u8,
    /// Issuer signature byte string. Carried as lowercase hex on the
    /// wire to keep the JSON document stable across serializers.
    #[serde(with = "hex_bytes")]
    pub issuer_signature: Vec<u8>,

    // ---- Optional threshold metadata ----------------------------------
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<GovernanceThresholdWire>,
}

impl GovernanceAuthorityProofWire {
    /// Convert this wire object into a typed Run 163
    /// [`GovernanceAuthorityProof`].
    ///
    /// Performs only structural validation (schema version, non-empty
    /// required fields, hex-decodable signature). Crypto / chain /
    /// environment / genesis / authority-root / digest / sequence /
    /// signature / suite / threshold checks are performed by the Run 163
    /// verifier, not here.
    pub fn to_governance_authority_proof(
        &self,
    ) -> Result<GovernanceAuthorityProof, GovernanceProofWireParseError> {
        if self.schema_version != GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION {
            return Err(GovernanceProofWireParseError::UnknownSchemaVersion {
                got: self.schema_version,
                expected: GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION,
            });
        }
        if self.chain_id.is_empty()
            || self.genesis_hash.is_empty()
            || self.authority_root_fingerprint.is_empty()
            || self.active_bundle_signing_key_fingerprint.is_empty()
            || self.candidate_v2_digest.is_empty()
        {
            return Err(GovernanceProofWireParseError::EmptyRequiredField);
        }
        if self.issuer_signature.is_empty() {
            return Err(GovernanceProofWireParseError::EmptyIssuerSignature);
        }
        Ok(GovernanceAuthorityProof {
            environment: self.environment,
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash.clone(),
            authority_root_fingerprint: self.authority_root_fingerprint.clone(),
            authority_root_suite_id: self.authority_root_suite_id,
            lifecycle_action: self.lifecycle_action,
            active_bundle_signing_key_fingerprint: self
                .active_bundle_signing_key_fingerprint
                .clone(),
            new_bundle_signing_key_fingerprint: self.new_bundle_signing_key_fingerprint.clone(),
            revoked_bundle_signing_key_fingerprint: self
                .revoked_bundle_signing_key_fingerprint
                .clone(),
            authority_domain_sequence: self.authority_domain_sequence,
            candidate_v2_digest: self.candidate_v2_digest.clone(),
            issuer_authority_class: self.issuer_authority_class.to_class(),
            issuer_signature_suite_id: self.issuer_signature_suite_id,
            issuer_signature: self.issuer_signature.clone(),
            threshold: self.threshold.as_ref().map(|t| t.to_threshold()),
        })
    }

    /// Build a wire object from a typed Run 163
    /// [`GovernanceAuthorityProof`]. Source/test helper used by the
    /// Run 167 fixture matrix.
    pub fn from_governance_authority_proof(p: &GovernanceAuthorityProof) -> Self {
        Self {
            schema_version: GOVERNANCE_AUTHORITY_PROOF_WIRE_SCHEMA_VERSION,
            environment: p.environment,
            chain_id: p.chain_id.clone(),
            genesis_hash: p.genesis_hash.clone(),
            authority_root_fingerprint: p.authority_root_fingerprint.clone(),
            authority_root_suite_id: p.authority_root_suite_id,
            lifecycle_action: p.lifecycle_action,
            active_bundle_signing_key_fingerprint: p
                .active_bundle_signing_key_fingerprint
                .clone(),
            new_bundle_signing_key_fingerprint: p.new_bundle_signing_key_fingerprint.clone(),
            revoked_bundle_signing_key_fingerprint: p
                .revoked_bundle_signing_key_fingerprint
                .clone(),
            authority_domain_sequence: p.authority_domain_sequence,
            candidate_v2_digest: p.candidate_v2_digest.clone(),
            issuer_authority_class: GovernanceAuthorityClassWire::from_class(
                p.issuer_authority_class,
            ),
            issuer_signature_suite_id: p.issuer_signature_suite_id,
            issuer_signature: p.issuer_signature.clone(),
            threshold: p
                .threshold
                .as_ref()
                .map(GovernanceThresholdWire::from_threshold),
        }
    }
}

/// Typed parse errors emitted when a wire governance proof carrier is
/// malformed or carries an unsupported schema version.
///
/// Every variant fails closed at the sidecar loader boundary — the
/// loader never returns a partially-parsed proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceProofWireParseError {
    /// JSON decoding of the optional `governance_authority_proof`
    /// sibling field failed.
    Json { error: String },
    /// The wire schema version is not supported by this build.
    UnknownSchemaVersion { got: u32, expected: u32 },
    /// At least one structurally-required field (chain_id, genesis_hash,
    /// authority_root_fingerprint, active key fingerprint, candidate
    /// digest) is empty.
    EmptyRequiredField,
    /// The issuer signature byte string is empty after hex decode.
    EmptyIssuerSignature,
}

impl std::fmt::Display for GovernanceProofWireParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { error } => write!(
                f,
                "[run-167] failed to parse governance_authority_proof JSON: {}. \
                 Fail closed.",
                error
            ),
            Self::UnknownSchemaVersion { got, expected } => write!(
                f,
                "[run-167] unsupported governance_authority_proof schema_version={} \
                 (expected {}). Fail closed.",
                got, expected
            ),
            Self::EmptyRequiredField => write!(
                f,
                "[run-167] governance_authority_proof has an empty required field. \
                 Fail closed."
            ),
            Self::EmptyIssuerSignature => write!(
                f,
                "[run-167] governance_authority_proof has empty issuer_signature. \
                 Fail closed."
            ),
        }
    }
}

impl std::error::Error for GovernanceProofWireParseError {}

/// Status of an optional governance-proof carrier on a v2 ratification
/// sidecar, after the Run 167 loader has attempted to parse it.
///
/// Pure data; carries no live trust state and triggers no I/O on
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GovernanceProofLoadStatus {
    /// The sidecar carried no `governance_authority_proof` sibling field.
    /// Backwards-compatible with all pre-Run-167 v2 sidecars.
    Absent,
    /// The sidecar carried a well-formed wire proof which was structurally
    /// converted into a typed Run 163 [`GovernanceAuthorityProof`]. The
    /// proof has NOT yet been verified — verification is performed by
    /// [`crate::pqc_governance_authority::evaluate_governance_marker_gate`]
    /// against the candidate v2 record and the expected trust domain.
    Available(GovernanceAuthorityProof),
    /// The sidecar carried a `governance_authority_proof` sibling field
    /// that failed to parse. Fail-closed under any policy that requires
    /// a proof for the candidate's lifecycle action.
    Malformed(GovernanceProofWireParseError),
}

impl GovernanceProofLoadStatus {
    /// Build a [`GovernanceProofContext`] for the Run 165 governance gate.
    ///
    /// * [`Self::Available`] → [`GovernanceProofContext::Supplied`] with
    ///   the supplied verifier.
    /// * [`Self::Absent`] / [`Self::Malformed`] →
    ///   [`GovernanceProofContext::Unavailable`].
    ///
    /// `Malformed` deliberately maps to `Unavailable` rather than
    /// `Supplied` so that the gate fails closed under a
    /// `RequiredForLifecycleSensitive` policy. A future run that wants
    /// to surface a richer "malformed-proof present" reject can extend
    /// the gate; Run 167 keeps the surface minimal.
    pub fn governance_proof_context<'a>(
        &'a self,
        verifier: &'a dyn GovernanceIssuerSignatureVerifier,
    ) -> GovernanceProofContext<'a> {
        match self {
            Self::Available(proof) => GovernanceProofContext::Supplied { proof, verifier },
            Self::Absent | Self::Malformed(_) => GovernanceProofContext::Unavailable,
        }
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed(_))
    }
}

mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut out, "{:02x}", b);
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom(
                "[run-167] issuer_signature hex string has odd length",
            ));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = decode_nibble(bytes[i]).map_err(serde::de::Error::custom)?;
            let lo = decode_nibble(bytes[i + 1]).map_err(serde::de::Error::custom)?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }

    fn decode_nibble(b: u8) -> Result<u8, &'static str> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(10 + b - b'a'),
            b'A'..=b'F' => Ok(10 + b - b'A'),
            _ => Err("[run-167] issuer_signature contains non-hex byte"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_governance_authority::{
        fixture_issuer_signature, GovernanceAuthorityClass, GovernanceThreshold,
        PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
    };
    use crate::pqc_authority_lifecycle::PQC_LIFECYCLE_SUITE_ML_DSA_44;

    fn proof_fixture() -> GovernanceAuthorityProof {
        let root_fp = "1111111111111111111111111111111111111111";
        let digest = "2222222222222222222222222222222222222222222222222222222222222222";
        let sig = fixture_issuer_signature(
            GovernanceAuthorityClass::GenesisBound,
            root_fp,
            digest,
            7,
        );
        GovernanceAuthorityProof {
            environment: TrustBundleEnvironment::Devnet,
            chain_id: "0000000000000001".to_string(),
            genesis_hash: "a".repeat(64),
            authority_root_fingerprint: root_fp.to_string(),
            authority_root_suite_id: PQC_LIFECYCLE_SUITE_ML_DSA_44,
            lifecycle_action: LocalLifecycleAction::Rotate,
            active_bundle_signing_key_fingerprint: "b".repeat(40),
            new_bundle_signing_key_fingerprint: Some("b".repeat(40)),
            revoked_bundle_signing_key_fingerprint: Some("a".repeat(40)),
            authority_domain_sequence: 7,
            candidate_v2_digest: digest.to_string(),
            issuer_authority_class: GovernanceAuthorityClass::GenesisBound,
            issuer_signature_suite_id: PQC_GOVERNANCE_ISSUER_SUITE_ML_DSA_44,
            issuer_signature: sig,
            threshold: Some(GovernanceThreshold::new(2, 2, 3)),
        }
    }

    #[test]
    fn wire_roundtrips_through_json_and_back_to_proof() {
        let p = proof_fixture();
        let wire = GovernanceAuthorityProofWire::from_governance_authority_proof(&p);
        let json = serde_json::to_vec(&wire).unwrap();
        let decoded: GovernanceAuthorityProofWire = serde_json::from_slice(&json).unwrap();
        assert_eq!(wire, decoded);
        let p_back = decoded.to_governance_authority_proof().unwrap();
        assert_eq!(p, p_back);
    }

    #[test]
    fn wire_unknown_schema_version_is_rejected() {
        let mut wire = GovernanceAuthorityProofWire::from_governance_authority_proof(
            &proof_fixture(),
        );
        wire.schema_version = 99;
        let err = wire.to_governance_authority_proof().unwrap_err();
        assert!(matches!(
            err,
            GovernanceProofWireParseError::UnknownSchemaVersion { got: 99, expected: 1 }
        ));
    }

    #[test]
    fn wire_empty_required_field_is_rejected() {
        let mut wire = GovernanceAuthorityProofWire::from_governance_authority_proof(
            &proof_fixture(),
        );
        wire.chain_id.clear();
        let err = wire.to_governance_authority_proof().unwrap_err();
        assert!(matches!(err, GovernanceProofWireParseError::EmptyRequiredField));
    }

    #[test]
    fn wire_empty_issuer_signature_is_rejected() {
        let mut wire = GovernanceAuthorityProofWire::from_governance_authority_proof(
            &proof_fixture(),
        );
        wire.issuer_signature.clear();
        let err = wire.to_governance_authority_proof().unwrap_err();
        assert!(matches!(err, GovernanceProofWireParseError::EmptyIssuerSignature));
    }

    #[test]
    fn wire_class_tag_serialization_is_kebab_case() {
        let s = serde_json::to_string(&GovernanceAuthorityClassWire::GenesisBound).unwrap();
        assert_eq!(s, "\"genesis-bound\"");
        let s = serde_json::to_string(&GovernanceAuthorityClassWire::EmergencyCouncil).unwrap();
        assert_eq!(s, "\"emergency-council\"");
        let s = serde_json::to_string(&GovernanceAuthorityClassWire::OnChainGovernance)
            .unwrap();
        assert_eq!(s, "\"on-chain-governance\"");
    }
}