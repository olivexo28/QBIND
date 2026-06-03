//! Run 184 — source/test OnChainGovernance proof-carrying production
//! payload/context layer.
//!
//! ## Strict scope (Run 184)
//!
//! * **Source/test only.** Run 184 does **not** capture release-binary
//!   evidence; release-binary `OnChainGovernance` accepted-proof
//!   evidence is deferred to **Run 185**.
//! * **Hidden DevNet/TestNet fixture policy only.** The default
//!   production policy remains
//!   [`crate::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy::Disabled`].
//! * **No MainNet peer-driven apply enablement.** The
//!   Run 147/Run 148/Run 152 MainNet refusal at the peer-driven apply
//!   surface remains intact even with a fully-valid DevNet fixture
//!   proof carried through this Run 184 payload layer and the Run 180
//!   selector enabled.
//! * **No governance execution engine.**
//! * **No real on-chain proof verifier.**
//! * **No bridge / light-client integration.**
//! * **No KMS/HSM custody implementation.**
//! * **No validator-set rotation.**
//! * **No autonomous apply / no automatic apply on receipt /
//!   no peer-majority authority.**
//! * **No marker / sequence-file / trust-bundle core schema change.**
//!   The carrier is a strictly additive, optional sibling on the
//!   existing v2 ratification sidecar JSON (alongside the Run 167
//!   `governance_authority_proof` sibling): legacy no-proof payloads
//!   continue to parse and to be accepted under the default
//!   `Disabled` / `NotRequired` policy bit-for-bit.
//!
//! Run 184 does **not** weaken any prior run (Runs 070, 130–183) and
//! does **not** claim full C4 or C5 closure.
//!
//! ## What this module adds
//!
//! Before Run 184 the Run 178 typed [`OnChainGovernanceProof`] could
//! reach the Run 182 production call-site entries only via in-process
//! source/test construction: every production wire/sidecar/payload
//! delivered the call-site context with `proof: None` and the Run 180
//! wrappers short-circuited to
//! [`OnChainGovernanceMarkerDecisionOutcome::NoOnChainGovernanceProofSupplied`].
//!
//! Run 184 closes that gap at the source/test level by adding:
//!
//! 1. An **additive optional sibling field** —
//!    [`ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD`] — on the same
//!    v2 ratification sidecar JSON document already used by the
//!    Run 167 governance proof carrier
//!    (`governance_authority_proof`). The Run 184 sibling reuses the
//!    Run 178 [`OnChainGovernanceProofWire`] schema verbatim.
//! 2. A typed [`OnChainGovernanceProofLoadStatus`] (`Absent` /
//!    `Available` / `Malformed`) parallel to the Run 167
//!    [`crate::pqc_governance_proof_wire::GovernanceProofLoadStatus`].
//! 3. Pure, non-mutating loaders that parse the v2 sidecar JSON from
//!    a path / bytes / `serde_json::Value` envelope and return both
//!    the typed [`qbind_ledger::BundleSigningRatificationV2`] AND the
//!    typed Run 184 [`OnChainGovernanceProofLoadStatus`]. The same
//!    parse helper (`parse_optional_onchain_governance_proof_sibling_from_json_value`)
//!    is reused by the live inbound `0x05` peer-candidate envelope
//!    path so the live-wire surface can extend its existing optional
//!    sibling without a new schema.
//! 4. Production-context routing helpers —
//!    [`route_loaded_onchain_governance_proof_to_*_callsite_decision`]
//!    — that bind a parsed [`OnChainGovernanceProofLoadStatus`] to
//!    the Run 182 per-surface call-site entries (reload-check /
//!    reload-apply / startup `--p2p-trust-bundle` / SIGHUP / local
//!    peer-candidate-check / live inbound `0x05` / peer-driven drain)
//!    with a typed
//!    [`OnChainGovernancePayloadCarryingDecisionOutcome::MalformedOnChainGovernanceProofPayload`]
//!    variant placed *in front of* the Run 182 outcome so a malformed
//!    carrier fails closed BEFORE any verifier is invoked, BEFORE any
//!    sequence/marker write, BEFORE any live trust swap, BEFORE any
//!    session eviction, and BEFORE any Run 070 call.
//!
//! ## Pure / non-mutating
//!
//! The loaders perform read-only file I/O. The routing helpers do not
//! perform any I/O. No marker write, no sequence write, no live trust
//! swap, no session eviction, no Run 070 call. Replay protection is
//! supplied by the caller as a reference to an in-memory replay-id
//! set; the helpers never extend that set.
//!
//! ## Wire compatibility
//!
//! * Existing Run 167 v2 sidecars (with or without
//!   `governance_authority_proof`) continue to parse exactly as before
//!   Run 184 — the new `onchain_governance_proof` sibling is
//!   `#[serde(default)]`-equivalent (extracted from the surrounding
//!   `serde_json::Value` and absent if missing).
//! * A v2 sidecar carrying both Run 167 and Run 184 siblings parses
//!   into both typed objects.
//! * A malformed Run 184 sibling does not poison the v2 ratification
//!   parse: the loader still returns the typed
//!   [`qbind_ledger::BundleSigningRatificationV2`] together with a
//!   typed
//!   [`OnChainGovernanceProofLoadStatus::Malformed`] status, so the
//!   call-site routing helper can emit a typed fail-closed
//!   [`OnChainGovernancePayloadCarryingDecisionOutcome::MalformedOnChainGovernanceProofPayload`]
//!   without losing the underlying ratification or its existing
//!   Run 167 carrier.

use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::pqc_governance_proof_wire::{GovernanceAuthorityProofWire, GovernanceProofLoadStatus};
use crate::pqc_onchain_governance_callsite_wiring::{
    live_inbound_0x05_callsite_onchain_governance_marker_decision,
    local_peer_candidate_check_callsite_onchain_governance_marker_decision,
    peer_driven_drain_callsite_onchain_governance_marker_decision,
    reload_apply_callsite_onchain_governance_marker_decision,
    reload_check_callsite_onchain_governance_marker_decision,
    sighup_callsite_onchain_governance_marker_decision,
    startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision,
    OnChainGovernanceCallsiteContext,
};
use crate::pqc_onchain_governance_proof::{
    OnChainGovernanceProof, OnChainGovernanceProofWire, OnChainGovernanceProofWireParseError,
    OnChainGovernanceReplaySet,
};
use crate::pqc_onchain_governance_proof_surface::OnChainGovernanceMarkerDecisionOutcome;
use crate::pqc_ratification_input::VersionedRatificationInputError;

// ===========================================================================
// Sibling field name
// ===========================================================================

/// JSON sibling field name carrying the Run 184 optional
/// [`OnChainGovernanceProofWire`] on the v2 ratification sidecar
/// envelope.
///
/// The field is strictly additive: legacy sidecars without this
/// sibling parse exactly as before and yield
/// [`OnChainGovernanceProofLoadStatus::Absent`].
pub const ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD: &str = "onchain_governance_proof";

// ===========================================================================
// Typed payload-level parse error
// ===========================================================================

/// Run 184 — typed parse error emitted at the payload/sibling boundary
/// when an `onchain_governance_proof` sibling is present but cannot be
/// converted into a typed [`OnChainGovernanceProof`].
///
/// Distinct from [`OnChainGovernanceProofWireParseError`] so that JSON
/// shape failures (which are payload-level) are kept separate from the
/// wire-form structural failures (which are Run 178 schema-level).
/// Both map to a single
/// [`OnChainGovernancePayloadCarryingDecisionOutcome::MalformedOnChainGovernanceProofPayload`]
/// variant at the call-site routing helpers and never to a partially
/// parsed proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainGovernanceProofPayloadParseError {
    /// JSON decoding of the optional `onchain_governance_proof`
    /// sibling field failed.
    Json { error: String },
    /// The sibling decoded as an [`OnChainGovernanceProofWire`] but
    /// the wire form failed structural validation (unknown schema
    /// version, empty required field, empty proof bytes).
    Wire(OnChainGovernanceProofWireParseError),
}

impl std::fmt::Display for OnChainGovernanceProofPayloadParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Json { error } => write!(
                f,
                "[run-184] failed to JSON-decode optional `{}` sibling: {}. Fail closed.",
                ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD, error
            ),
            Self::Wire(e) => write!(f, "[run-184] {}", e),
        }
    }
}

impl std::error::Error for OnChainGovernanceProofPayloadParseError {}

impl From<OnChainGovernanceProofWireParseError> for OnChainGovernanceProofPayloadParseError {
    fn from(e: OnChainGovernanceProofWireParseError) -> Self {
        Self::Wire(e)
    }
}

// ===========================================================================
// Typed load status
// ===========================================================================

/// Run 184 — typed load status of the optional
/// [`OnChainGovernanceProofWire`] sibling on the v2 ratification
/// sidecar JSON / `0x05` peer-candidate envelope.
///
/// Pure data; carries no live trust state and triggers no I/O on
/// construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainGovernanceProofLoadStatus {
    /// The carrier carried no `onchain_governance_proof` sibling
    /// field. Backwards-compatible with all pre-Run-184 v2 sidecars
    /// and live envelopes — a no-proof payload remains accepted under
    /// the default `Disabled` / `NotRequired` policy.
    Absent,
    /// The carrier carried a well-formed wire proof which was
    /// structurally converted into a typed Run 178
    /// [`OnChainGovernanceProof`]. The proof has NOT yet been
    /// verified against trust-domain / lifecycle / governance / proof
    /// bindings — verification is performed by the Run 182 call-site
    /// entries which delegate to the Run 180 wrappers and the Run 178
    /// verifier.
    Available(OnChainGovernanceProof),
    /// The carrier carried an `onchain_governance_proof` sibling
    /// field that failed to decode at the JSON layer or failed wire
    /// structural validation. Always fails closed at the Run 182
    /// call-site routing helpers.
    Malformed(OnChainGovernanceProofPayloadParseError),
}

impl OnChainGovernanceProofLoadStatus {
    pub fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }

    pub fn is_available(&self) -> bool {
        matches!(self, Self::Available(_))
    }

    pub fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed(_))
    }

    /// Return a borrowed reference to the typed
    /// [`OnChainGovernanceProof`] when the carrier was well-formed.
    /// `None` for `Absent` and `Malformed`.
    ///
    /// This is the exact value passed as the `proof: Option<&'a
    /// OnChainGovernanceProof>` field of the Run 182
    /// [`OnChainGovernanceCallsiteContext`].
    pub fn as_proof(&self) -> Option<&OnChainGovernanceProof> {
        match self {
            Self::Available(p) => Some(p),
            Self::Absent | Self::Malformed(_) => None,
        }
    }

    /// Return the typed parse error when the carrier was malformed.
    pub fn malformed_error(&self) -> Option<&OnChainGovernanceProofPayloadParseError> {
        match self {
            Self::Malformed(e) => Some(e),
            Self::Absent | Self::Available(_) => None,
        }
    }
}

// ===========================================================================
// Sibling parsing
// ===========================================================================

/// Run 184 — pure parse helper that extracts the optional
/// `onchain_governance_proof` sibling from a generic JSON value and
/// returns a typed [`OnChainGovernanceProofLoadStatus`].
///
/// Behaviour:
///
/// * `value` has no `onchain_governance_proof` field, or the field is
///   `null`: returns [`OnChainGovernanceProofLoadStatus::Absent`].
/// * `value` has a non-null `onchain_governance_proof` field that
///   fails to decode as [`OnChainGovernanceProofWire`]: returns
///   [`OnChainGovernanceProofLoadStatus::Malformed`] carrying a
///   [`OnChainGovernanceProofPayloadParseError::Json`].
/// * `value` has a well-formed wire object but
///   [`OnChainGovernanceProofWire::to_proof`] rejects it (unknown
///   schema version, empty required field, empty proof bytes):
///   returns [`OnChainGovernanceProofLoadStatus::Malformed`] carrying
///   the wire parse error.
/// * Otherwise: returns
///   [`OnChainGovernanceProofLoadStatus::Available`] with the typed
///   Run 178 proof.
///
/// Pure — does not mutate `value` and performs no I/O.
pub fn parse_optional_onchain_governance_proof_sibling_from_json_value(
    value: &Value,
) -> OnChainGovernanceProofLoadStatus {
    let sibling = value.get(ONCHAIN_GOVERNANCE_PROOF_PAYLOAD_SIBLING_FIELD);
    match sibling {
        None => OnChainGovernanceProofLoadStatus::Absent,
        Some(Value::Null) => OnChainGovernanceProofLoadStatus::Absent,
        Some(raw) => match serde_json::from_value::<OnChainGovernanceProofWire>(raw.clone()) {
            Ok(wire) => match wire.to_proof() {
                Ok(p) => OnChainGovernanceProofLoadStatus::Available(p),
                Err(e) => {
                    OnChainGovernanceProofLoadStatus::Malformed(
                        OnChainGovernanceProofPayloadParseError::Wire(e),
                    )
                }
            },
            Err(e) => OnChainGovernanceProofLoadStatus::Malformed(
                OnChainGovernanceProofPayloadParseError::Json {
                    error: e.to_string(),
                },
            ),
        },
    }
}

// ===========================================================================
// Combined v2 sidecar loader (Run 167 + Run 184)
// ===========================================================================

/// Run 184 — typed result of loading a v2 ratification sidecar
/// together with both the optional Run 167
/// [`GovernanceAuthorityProofWire`] sibling and the optional Run 184
/// [`OnChainGovernanceProofWire`] sibling.
///
/// Strictly additive over
/// [`crate::pqc_ratification_input::LoadedV2RatificationSidecar`]:
/// pre-Run-184 v2 sidecars yield
/// [`OnChainGovernanceProofLoadStatus::Absent`] in the new field and
/// continue to expose the existing
/// [`GovernanceProofLoadStatus`] in the `governance_proof` field.
#[derive(Debug, Clone)]
pub struct LoadedV2RatificationSidecarWithOnChainGovernanceProof {
    /// The fully-parsed v2 ratification sidecar (typed
    /// [`qbind_ledger::BundleSigningRatificationV2`]).
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    /// Run 167 — optional governance authority proof carrier.
    pub governance_proof: GovernanceProofLoadStatus,
    /// Run 184 — optional OnChainGovernance proof carrier.
    pub onchain_governance_proof: OnChainGovernanceProofLoadStatus,
}

/// Run 184 — load a v2 ratification sidecar JSON file and additionally
/// attempt to parse BOTH its optional Run 167
/// [`GovernanceAuthorityProofWire`] sibling field
/// (`governance_authority_proof`) and its optional Run 184
/// [`OnChainGovernanceProofWire`] sibling field
/// (`onchain_governance_proof`).
///
/// # Behaviour
///
/// * Both optional sibling fields are **strictly additive**. A v2
///   sidecar without either field continues to parse as before and
///   yields the corresponding `Absent` load status.
/// * A sibling that fails to deserialise into its wire form, or that
///   fails wire-form structural validation, yields the corresponding
///   `Malformed` load status. The v2 ratification itself is still
///   returned so the caller can fall through the policy/gate
///   pipeline.
/// * A v1 sidecar at this path is rejected with
///   [`VersionedRatificationInputError::MalformedSidecar`] because
///   both Run 167 and Run 184 carriers are v2-only by design.
/// * No file write, no marker write, no sequence write, no live trust
///   swap, no session eviction, no Run 070 call.
pub fn load_v2_ratification_sidecar_with_onchain_governance_proof_from_path(
    path: &Path,
) -> Result<LoadedV2RatificationSidecarWithOnChainGovernanceProof, VersionedRatificationInputError>
{
    let bytes = std::fs::read(path).map_err(|error| VersionedRatificationInputError::Io {
        path: path.to_path_buf(),
        error,
    })?;
    load_v2_ratification_sidecar_with_onchain_governance_proof_from_bytes(&bytes, path)
}

/// Run 184 — bytes-form variant of
/// [`load_v2_ratification_sidecar_with_onchain_governance_proof_from_path`].
///
/// Used by validation-only / live-inbound surfaces that already hold
/// the JSON envelope in memory and do not need to reread the local
/// file. The `path_for_diagnostics` argument is only used to populate
/// typed [`VersionedRatificationInputError`] variants — it does NOT
/// trigger any file access on this code path.
pub fn load_v2_ratification_sidecar_with_onchain_governance_proof_from_bytes(
    bytes: &[u8],
    path_for_diagnostics: &Path,
) -> Result<LoadedV2RatificationSidecarWithOnChainGovernanceProof, VersionedRatificationInputError>
{
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
                "Run 184 OnChainGovernance-proof carrier requires v2 sidecar (got schema_version={})",
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

    let ratification: qbind_ledger::BundleSigningRatificationV2 = serde_json::from_value(value)
        .map_err(|e| VersionedRatificationInputError::MalformedSidecar {
            path: path_for_diagnostics.to_path_buf(),
            schema_version: 2,
            error: e.to_string(),
        })?;

    Ok(LoadedV2RatificationSidecarWithOnChainGovernanceProof {
        ratification,
        governance_proof,
        onchain_governance_proof,
    })
}

/// Run 184 internal helper — extract the Run 167
/// `governance_authority_proof` sibling from a generic JSON value and
/// return a typed [`GovernanceProofLoadStatus`].
///
/// Single-source-of-truth mirror of the extraction logic already
/// present in
/// [`crate::pqc_ratification_input::load_v2_ratification_sidecar_with_governance_proof_from_path`];
/// kept private here so the Run 184 combined loader does not have to
/// re-read the file.
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

/// Run 184 — additive optional sibling shape used to produce a v2
/// ratification sidecar JSON document that carries an
/// [`OnChainGovernanceProofWire`] alongside the typed
/// [`qbind_ledger::BundleSigningRatificationV2`].
///
/// Source/test helper. The struct is purely a JSON-construction
/// convenience: it merges the `BundleSigningRatificationV2` fields
/// with an `onchain_governance_proof` sibling. Production paths
/// continue to write the `BundleSigningRatificationV2` directly when
/// no proof is carried.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct V2RatificationSidecarWithOnChainGovernanceProofWire {
    #[serde(flatten)]
    pub ratification: qbind_ledger::BundleSigningRatificationV2,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onchain_governance_proof: Option<OnChainGovernanceProofWire>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_authority_proof: Option<GovernanceAuthorityProofWire>,
}

// ===========================================================================
// Routing into the Run 182 call-site entries
// ===========================================================================

/// Run 184 — typed outcome of routing a Run 184
/// [`OnChainGovernanceProofLoadStatus`] through any of the seven
/// Run 182 per-surface call-site entries.
///
/// Adds the typed
/// [`OnChainGovernancePayloadCarryingDecisionOutcome::MalformedOnChainGovernanceProofPayload`]
/// variant *in front of* the Run 182
/// [`OnChainGovernanceMarkerDecisionOutcome`] so a malformed payload
/// fails closed BEFORE any verifier is invoked, BEFORE any sequence /
/// marker write, BEFORE any live trust swap, BEFORE any session
/// eviction, and BEFORE any Run 070 call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OnChainGovernancePayloadCarryingDecisionOutcome {
    /// The carrier sibling was present but malformed at the JSON or
    /// wire-structural level. Always fail-closed regardless of
    /// `OnChainGovernanceProofPolicy`. The Run 178 verifier was NOT
    /// invoked.
    MalformedOnChainGovernanceProofPayload(OnChainGovernanceProofPayloadParseError),
    /// The carrier was absent or well-formed; the decision is the
    /// Run 182 call-site outcome (which already enumerates
    /// `Disabled`, `NoOnChainGovernanceProofSupplied`,
    /// `MainNetRefused`, `Accepted`, `Rejected`).
    Callsite(OnChainGovernanceMarkerDecisionOutcome),
}

impl OnChainGovernancePayloadCarryingDecisionOutcome {
    pub fn is_accept(&self) -> bool {
        match self {
            Self::Callsite(o) => o.is_accept(),
            Self::MalformedOnChainGovernanceProofPayload(_) => false,
        }
    }

    pub fn is_reject(&self) -> bool {
        match self {
            Self::MalformedOnChainGovernanceProofPayload(_) => true,
            Self::Callsite(o) => o.is_reject(),
        }
    }

    /// `true` for the Run 184 malformed-payload reject *and* for the
    /// Run 182 reject variants (`MainNetRefused`, `Rejected`).
    pub fn is_fail_closed(&self) -> bool {
        self.is_reject()
    }

    /// `true` iff the underlying Run 182 path was bypassed because
    /// the policy is `Disabled` or no proof was supplied. Returns
    /// `false` for the Run 184 malformed variant.
    pub fn is_bypassed(&self) -> bool {
        match self {
            Self::Callsite(o) => o.is_bypassed(),
            Self::MalformedOnChainGovernanceProofPayload(_) => false,
        }
    }

    pub fn is_malformed_payload(&self) -> bool {
        matches!(self, Self::MalformedOnChainGovernanceProofPayload(_))
    }

    /// Borrow the inner Run 182 outcome, if any.
    pub fn callsite_outcome(&self) -> Option<&OnChainGovernanceMarkerDecisionOutcome> {
        match self {
            Self::Callsite(o) => Some(o),
            Self::MalformedOnChainGovernanceProofPayload(_) => None,
        }
    }
}

/// Build an [`OnChainGovernanceCallsiteContext`] borrowing its proof
/// field from a typed Run 184
/// [`OnChainGovernanceProofLoadStatus::Available`]. The other fields
/// are the natural Run 182 call-site context inputs the production
/// preflight already has in hand.
///
/// `Absent` and `Malformed` load statuses produce a context with
/// `proof: None`, mirroring exactly what the existing production
/// callers already pass today. Routing helpers then layer Run 184
/// malformed-payload short-circuits in front of the Run 182 path.
#[allow(clippy::too_many_arguments)]
pub fn callsite_context_with_loaded_onchain_governance_proof<
    'a,
    R: OnChainGovernanceReplaySet + ?Sized,
>(
    persisted: Option<&'a crate::pqc_authority_state::PersistentAuthorityStateRecordVersioned>,
    candidate: &'a crate::pqc_authority_state::PersistentAuthorityStateRecordV2,
    loaded: &'a OnChainGovernanceProofLoadStatus,
    trust_domain: &'a crate::pqc_authority_lifecycle::AuthorityTrustDomain,
    policy: crate::pqc_onchain_governance_proof::OnChainGovernanceProofPolicy,
    expected_governance_domain_id: &'a str,
    expected_governance_epoch: u64,
    expected_proposal_id: &'a str,
    expected_proposal_digest: &'a str,
    now_unix: u64,
    replay_set: &'a R,
) -> OnChainGovernanceCallsiteContext<'a, R> {
    OnChainGovernanceCallsiteContext {
        persisted,
        candidate,
        proof: loaded.as_proof(),
        trust_domain,
        policy,
        expected_governance_domain_id,
        expected_governance_epoch,
        expected_proposal_id,
        expected_proposal_digest,
        now_unix,
        replay_set,
    }
}

/// Internal — short-circuit a malformed-carrier load status into the
/// Run 184 fail-closed outcome. `Absent` and `Available` return
/// `None`, in which case the caller should invoke the Run 182
/// call-site entry.
fn malformed_payload_shortcircuit(
    loaded: &OnChainGovernanceProofLoadStatus,
) -> Option<OnChainGovernancePayloadCarryingDecisionOutcome> {
    match loaded {
        OnChainGovernanceProofLoadStatus::Malformed(e) => Some(
            OnChainGovernancePayloadCarryingDecisionOutcome::MalformedOnChainGovernanceProofPayload(
                e.clone(),
            ),
        ),
        OnChainGovernanceProofLoadStatus::Absent
        | OnChainGovernanceProofLoadStatus::Available(_) => None,
    }
}

macro_rules! define_route_callsite {
    ($(#[$meta:meta])* $name:ident => $entry:ident) => {
        $(#[$meta])*
        pub fn $name<R: OnChainGovernanceReplaySet + ?Sized>(
            ctx: &OnChainGovernanceCallsiteContext<'_, R>,
            loaded: &OnChainGovernanceProofLoadStatus,
        ) -> OnChainGovernancePayloadCarryingDecisionOutcome {
            if let Some(short) = malformed_payload_shortcircuit(loaded) {
                return short;
            }
            OnChainGovernancePayloadCarryingDecisionOutcome::Callsite($entry(ctx))
        }
    };
}

define_route_callsite!(
    /// Run 184 — route a parsed [`OnChainGovernanceProofLoadStatus`]
    /// through the Run 182 reload-check validation-only call-site
    /// entry. A malformed carrier short-circuits to
    /// [`OnChainGovernancePayloadCarryingDecisionOutcome::MalformedOnChainGovernanceProofPayload`]
    /// before the verifier is invoked. Validation-only mutation
    /// contract is preserved: the caller MUST drop the returned
    /// outcome and MUST NOT persist a marker, advance the bundle-
    /// signing sequence, swap live trust state, evict sessions, or
    /// invoke Run 070.
    route_loaded_onchain_governance_proof_to_reload_check_callsite_decision
        => reload_check_callsite_onchain_governance_marker_decision
);

define_route_callsite!(
    /// Run 184 — route a parsed [`OnChainGovernanceProofLoadStatus`]
    /// through the Run 182 reload-apply mutating-preflight call-site
    /// entry. A malformed carrier short-circuits to
    /// [`OnChainGovernancePayloadCarryingDecisionOutcome::MalformedOnChainGovernanceProofPayload`]
    /// before the verifier is invoked, before any sequence/marker
    /// write, and before any Run 070 call. Mutating callers continue
    /// to honor sequence-before-marker ordering after acceptance.
    route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision
        => reload_apply_callsite_onchain_governance_marker_decision
);

define_route_callsite!(
    /// Run 184 — route a parsed [`OnChainGovernanceProofLoadStatus`]
    /// through the Run 182 startup `--p2p-trust-bundle` mutating-
    /// preflight call-site entry. Same mutation contract as
    /// [`route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision`].
    route_loaded_onchain_governance_proof_to_startup_p2p_trust_bundle_callsite_decision
        => startup_p2p_trust_bundle_callsite_onchain_governance_marker_decision
);

define_route_callsite!(
    /// Run 184 — route a parsed [`OnChainGovernanceProofLoadStatus`]
    /// through the Run 182 SIGHUP live trust-bundle reload mutating-
    /// preflight call-site entry. Same mutation contract as
    /// [`route_loaded_onchain_governance_proof_to_reload_apply_callsite_decision`].
    route_loaded_onchain_governance_proof_to_sighup_callsite_decision
        => sighup_callsite_onchain_governance_marker_decision
);

define_route_callsite!(
    /// Run 184 — route a parsed [`OnChainGovernanceProofLoadStatus`]
    /// through the Run 182 local peer-candidate-check validation-only
    /// call-site entry. Validation-only mutation contract identical
    /// to
    /// [`route_loaded_onchain_governance_proof_to_reload_check_callsite_decision`].
    route_loaded_onchain_governance_proof_to_local_peer_candidate_check_callsite_decision
        => local_peer_candidate_check_callsite_onchain_governance_marker_decision
);

define_route_callsite!(
    /// Run 184 — route a parsed [`OnChainGovernanceProofLoadStatus`]
    /// through the Run 182 live inbound `0x05` peer-candidate
    /// validation-only call-site entry. An invalid `0x05`
    /// OnChainGovernance proof candidate (malformed payload OR
    /// rejected by the verifier) is **not propagated, staged, or
    /// applied** — the rejection short-circuits at this routing
    /// helper before any staging path is reached.
    route_loaded_onchain_governance_proof_to_live_inbound_0x05_callsite_decision
        => live_inbound_0x05_callsite_onchain_governance_marker_decision
);

define_route_callsite!(
    /// Run 184 — route a parsed [`OnChainGovernanceProofLoadStatus`]
    /// through the Run 182 peer-driven drain coordinator
    /// (`ProductionV2MarkerCoordinator`) preflight call-site entry.
    /// The Run 182 entry already layers a surface-level MainNet
    /// refusal before invoking the verifier; a malformed carrier
    /// fails closed first regardless of MainNet binding.
    route_loaded_onchain_governance_proof_to_peer_driven_drain_callsite_decision
        => peer_driven_drain_callsite_onchain_governance_marker_decision
);

// ===========================================================================
// In-crate self-tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_authority_lifecycle::{AuthorityTrustDomain, PQC_LIFECYCLE_SUITE_ML_DSA_44};
    use crate::pqc_authority_state::{
        AuthorityStateUpdateSource, PersistentAuthorityStateRecordV2,
    };
    use crate::pqc_onchain_governance_proof::{
        EmptyOnChainGovernanceReplaySet, OnChainGovernanceProofPolicy,
    };
    use crate::pqc_trust_bundle::TrustBundleEnvironment;
    use qbind_ledger::BundleSigningRatificationV2Action;

    fn devnet_domain() -> AuthorityTrustDomain {
        AuthorityTrustDomain::new(
            TrustBundleEnvironment::Devnet,
            "0000000000000001",
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "1111111111111111111111111111111111111111",
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
        )
    }

    fn devnet_candidate() -> PersistentAuthorityStateRecordV2 {
        PersistentAuthorityStateRecordV2::new(
            "0000000000000001".to_string(),
            TrustBundleEnvironment::Devnet,
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
            "1111111111111111111111111111111111111111".to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_string(),
            PQC_LIFECYCLE_SUITE_ML_DSA_44,
            2,
            BundleSigningRatificationV2Action::Rotate,
            Some("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()),
            "2222222222222222222222222222222222222222222222222222222222222222".to_string(),
            None,
            AuthorityStateUpdateSource::TestOrFixture,
            1_700_000_000,
        )
    }

    #[test]
    fn absent_sibling_yields_absent_load_status() {
        let value = serde_json::json!({"unrelated": 1});
        let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
        assert!(matches!(s, OnChainGovernanceProofLoadStatus::Absent));
        assert!(s.is_absent());
        assert!(s.as_proof().is_none());
    }

    #[test]
    fn null_sibling_yields_absent_load_status() {
        let value = serde_json::json!({"onchain_governance_proof": null});
        let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
        assert!(s.is_absent());
    }

    #[test]
    fn malformed_json_sibling_yields_malformed_load_status() {
        let value = serde_json::json!({"onchain_governance_proof": "not-an-object"});
        let s = parse_optional_onchain_governance_proof_sibling_from_json_value(&value);
        assert!(s.is_malformed());
        assert!(matches!(
            s.malformed_error().unwrap(),
            OnChainGovernanceProofPayloadParseError::Json { .. }
        ));
    }

    #[test]
    fn malformed_payload_short_circuits_to_typed_fail_closed() {
        let candidate = devnet_candidate();
        let domain = devnet_domain();
        let replay = EmptyOnChainGovernanceReplaySet;
        let loaded = OnChainGovernanceProofLoadStatus::Malformed(
            OnChainGovernanceProofPayloadParseError::Json {
                error: "synthetic".to_string(),
            },
        );
        let ctx = callsite_context_with_loaded_onchain_governance_proof(
            None,
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::AllowFixtureSourceTest,
            "qbind-onchain-gov-1",
            1,
            "prop-001",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            1_700_000_000,
            &replay,
        );
        let outcome = route_loaded_onchain_governance_proof_to_reload_check_callsite_decision(
            &ctx, &loaded,
        );
        assert!(outcome.is_malformed_payload());
        assert!(outcome.is_reject());
        assert!(!outcome.is_accept());
        assert!(!outcome.is_bypassed());
    }

    #[test]
    fn absent_payload_routes_through_run_182_and_reports_disabled_under_default_policy() {
        let candidate = devnet_candidate();
        let domain = devnet_domain();
        let replay = EmptyOnChainGovernanceReplaySet;
        let loaded = OnChainGovernanceProofLoadStatus::Absent;
        let ctx = callsite_context_with_loaded_onchain_governance_proof(
            None,
            &candidate,
            &loaded,
            &domain,
            OnChainGovernanceProofPolicy::Disabled,
            "qbind-onchain-gov-1",
            1,
            "prop-001",
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            1_700_000_000,
            &replay,
        );
        let outcome = route_loaded_onchain_governance_proof_to_reload_check_callsite_decision(
            &ctx, &loaded,
        );
        assert_eq!(
            outcome,
            OnChainGovernancePayloadCarryingDecisionOutcome::Callsite(
                OnChainGovernanceMarkerDecisionOutcome::PolicyDisabled
            )
        );
    }
}
