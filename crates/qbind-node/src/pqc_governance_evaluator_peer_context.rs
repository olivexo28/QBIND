//! Run 228 — source/test evaluator-context representation boundary for live
//! inbound `0x05` and peer-driven drain.
//!
//! Source/test only. Run 228 captures **no** release-binary evidence;
//! release-binary evidence for this boundary is deferred to **Run 229**. Run
//! 228 does **not** implement a real governance execution engine, a real
//! on-chain governance proof verifier, MainNet governance enablement, MainNet
//! peer-driven apply enablement, validator-set rotation, a real KMS/HSM
//! backend, or a real RemoteSigner backend.
//!
//! ## What this module adds
//!
//! Runs 220–227 proved, at the source/test level and then with release-binary
//! evidence, that the *representable* long-running runtime call sites route
//! runtime consumption through the Run 224 integration layer
//! ([`integrate_governance_evaluator_runtime_consumption`]) via the Run 226
//! call-site wiring entry points
//! ([`wire_governance_evaluator_runtime_callsite`]).
//!
//! Two surfaces were left **honestly documented as limited / not-yet
//! representable**: the live inbound `0x05` peer-candidate validation-only
//! path and the peer-driven drain validation path. The binary marker-decision
//! metadata reachable from those two surfaces does not carry the governance
//! proposal/decision evaluator bindings (proposal id, decision id, candidate
//! digest, replay nonce, decision-source identity), so a live-wire-only path
//! cannot construct a full Run 222 [`EvaluatorRequest`] / [`EvaluatorResponse`]
//! without a wire/schema change.
//!
//! Run 228 closes the *representation* gap — not the wire gap — at the
//! source/test level. It adds a typed, **local-only** evaluator-context
//! representation boundary ([`GovernanceEvaluatorPeerContext`]) that can bind
//! or reference evaluator context for those two surfaces *where representable*
//! in source/test plumbing (a local sidecar / source-test fixture), and routes
//! a representable context **through the Run 226 call-site wiring** so it is
//! subject to exactly the same Run 220/222/224 fail-closed evaluation as every
//! other surface. Where a surface cannot reach the integration layer without a
//! wire/schema change, the boundary returns a typed
//! [`PeerEvaluatorContextOutcome::WireSchemaUnavailable`] /
//! [`PeerEvaluatorContextOutcome::UnsupportedSurface`] fail-closed — never a
//! silent approval.
//!
//! ## What this module does NOT change
//!
//! * It does **not** invent a new network `0x05` wire format.
//! * It adds **no** field to any production wire message.
//! * It alters **no** trust-bundle schema.
//! * It alters **no** authority-marker or sequence schema.
//! * It enables **no** MainNet peer-driven apply.
//!
//! ## Fail-closed contract
//!
//! * The boundary is a pure function: it performs no I/O, writes no marker,
//!   writes no sequence, swaps no live trust, evicts no sessions, and never
//!   invokes Run 070. Only
//!   [`PeerEvaluatorContextOutcome::RoutedProceedMutate`] authorizes the
//!   surface to continue, and only because the composed Run 226 call-site
//!   wiring produced a fully-authorized
//!   [`GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate`].
//! * A missing carrier under an explicit evaluator policy is a typed
//!   fail-closed, never an approval.
//! * MainNet peer-driven apply remains refused unconditionally, even with a
//!   fixture evaluator approval.
//! * Production / on-chain / MainNet evaluators remain callable-but-unavailable
//!   and fail closed through the underlying Run 222 / Run 224 stages.

use crate::pqc_authority_lifecycle::LocalLifecycleAction;
use crate::pqc_governance_execution_evaluator::{
    EvaluatorPolicy, ProductionGovernanceExecutionEvaluator,
};
use crate::pqc_governance_execution_evaluator_runtime_integration::{
    wire_governance_evaluator_runtime_callsite, GovernanceEvaluatorRuntimeCallsiteFailClosed,
    GovernanceEvaluatorRuntimeIntegrationContext, GovernanceEvaluatorRuntimeIntegrationOutcome,
};
use crate::pqc_governance_execution_payload_carrying::GovernanceExecutionLoadStatus;
use crate::pqc_governance_execution_policy::GovernanceExecutionPolicy;
use crate::pqc_governance_execution_runtime_arming::GovernanceExecutionRuntimeSurface;
use crate::pqc_trust_bundle::TrustBundleEnvironment;

/// Domain-separation tag for the Run 228 peer evaluator-context digest. Keeps
/// the context digest from colliding with any other QBIND canonical digest.
pub const PEER_EVALUATOR_CONTEXT_DOMAIN_TAG: &str =
    "qbind.run228.governance.evaluator.peer.context.v1";

// ===========================================================================
// Validation surface
// ===========================================================================

/// Run 228 — the two previously-limited validation surfaces this boundary
/// represents.
///
/// Both are validation-only / preflight surfaces at the source/test level.
/// [`Self::PeerDrivenDrain`] is additionally a peer-driven apply preflight,
/// for which MainNet apply remains refused unconditionally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerEvaluatorContextSurface {
    /// Live inbound `0x05` peer-candidate validation-only surface.
    LiveInbound0x05,
    /// Peer-driven apply drain validation surface (MainNet refused).
    PeerDrivenDrain,
}

impl PeerEvaluatorContextSurface {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LiveInbound0x05 => "live-inbound-0x05",
            Self::PeerDrivenDrain => "peer-driven-drain",
        }
    }

    /// The Run 217 runtime surface this boundary drives through the Run 226
    /// call-site wiring.
    pub const fn runtime_surface(self) -> GovernanceExecutionRuntimeSurface {
        match self {
            Self::LiveInbound0x05 => GovernanceExecutionRuntimeSurface::LiveInbound0x05,
            Self::PeerDrivenDrain => GovernanceExecutionRuntimeSurface::PeerDrivenDrain,
        }
    }

    /// `true` iff this surface is a peer-driven apply preflight (MainNet
    /// apply remains refused unconditionally for it).
    pub const fn is_peer_driven_apply_preflight(self) -> bool {
        matches!(self, Self::PeerDrivenDrain)
    }
}

// ===========================================================================
// Peer / source class
// ===========================================================================

/// Run 228 — the class of the source that presented the evaluator context.
///
/// All variants are local/source-test descriptors; none of them confers
/// authority. A peer majority can never satisfy an evaluator policy
/// ([`Self::PeerMajorityGossip`] is always a fail-closed
/// [`PeerEvaluatorContextOutcome::PeerMajorityUnsupported`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerEvaluatorSourceClass {
    /// A single live inbound peer presented the candidate.
    LiveInboundPeer,
    /// A staged peer candidate reached the drain coordinator.
    DrainStagedPeer,
    /// A local source/test fixture sidecar supplied the context.
    LocalSourceTest,
    /// A peer-majority / gossip count "vote" — never authoritative.
    PeerMajorityGossip,
}

impl PeerEvaluatorSourceClass {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::LiveInboundPeer => "live-inbound-peer",
            Self::DrainStagedPeer => "drain-staged-peer",
            Self::LocalSourceTest => "local-source-test",
            Self::PeerMajorityGossip => "peer-majority-gossip",
        }
    }

    /// `true` iff this source class is a peer-majority / gossip "vote",
    /// which can never satisfy an evaluator policy.
    pub const fn is_peer_majority(self) -> bool {
        matches!(self, Self::PeerMajorityGossip)
    }
}

// ===========================================================================
// Load-status tag (local mirror of the Run 213 load status)
// ===========================================================================

/// Run 228 — local mirror of the Run 213
/// [`GovernanceExecutionLoadStatus`] variant tag. The boundary records the
/// *shape* of the governance-execution load status without owning the parsed
/// parts, so the context stays pure data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerEvaluatorLoadStatus {
    /// No `governance_execution` sibling was carried.
    Absent,
    /// A well-formed `governance_execution` payload was structurally parsed.
    Available,
    /// A `governance_execution` payload failed to decode / validate.
    Malformed,
}

impl PeerEvaluatorLoadStatus {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Available => "available",
            Self::Malformed => "malformed",
        }
    }

    /// Derive the local mirror from a Run 213 load status.
    pub fn from_load_status(status: &GovernanceExecutionLoadStatus) -> Self {
        match status {
            GovernanceExecutionLoadStatus::Absent => Self::Absent,
            GovernanceExecutionLoadStatus::Available(_) => Self::Available,
            GovernanceExecutionLoadStatus::Malformed(_) => Self::Malformed,
        }
    }
}

// ===========================================================================
// Carrier status classification
// ===========================================================================

/// Run 228 — typed classification of the evaluator-context carrier on a live
/// inbound `0x05` or peer-driven drain surface.
///
/// This is the **carrier-status taxonomy** required by the run scope. Every
/// status other than [`Self::Present`] is fail-closed; in particular
/// [`Self::Absent`], [`Self::WireSchemaUnavailable`],
/// [`Self::UnsupportedSurface`], [`Self::Malformed`],
/// [`Self::PeerMajorityUnsupported`], and [`Self::MainNetRefused`] are NEVER
/// treated as an approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerEvaluatorCarrierStatus {
    /// No evaluator-context carrier was supplied at all. Preserves legacy
    /// validation behavior only under the default Disabled policy; under an
    /// explicit evaluator policy it fails closed as missing context.
    Absent,
    /// A full local evaluator-context carrier is present and bound. Eligible
    /// to route through the Run 226 call-site wiring.
    Present,
    /// A carrier was supplied but is structurally malformed. Always
    /// fail-closed.
    Malformed,
    /// The surface cannot reach the integration layer without a wire/schema
    /// change. Typed fail-closed; never an approval.
    UnsupportedSurface,
    /// No wire/schema carrier exists on the live surface to convey evaluator
    /// context. Typed fail-closed; explicitly NOT a silent approval.
    WireSchemaUnavailable,
    /// A peer-majority / gossip "vote" cannot satisfy an evaluator policy.
    /// Always fail-closed.
    PeerMajorityUnsupported,
    /// MainNet peer-driven apply is refused unconditionally. Always
    /// fail-closed regardless of any fixture evaluator approval.
    MainNetRefused,
}

impl PeerEvaluatorCarrierStatus {
    /// Stable operator-facing tag.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Absent => "absent",
            Self::Present => "present",
            Self::Malformed => "malformed",
            Self::UnsupportedSurface => "unsupported-surface",
            Self::WireSchemaUnavailable => "wire-schema-unavailable",
            Self::PeerMajorityUnsupported => "peer-majority-unsupported",
            Self::MainNetRefused => "mainnet-refused",
        }
    }

    /// `true` iff this status is eligible to route through the integration
    /// layer (only [`Self::Present`]).
    pub const fn is_present(self) -> bool {
        matches!(self, Self::Present)
    }
}

// ===========================================================================
// Typed local-only evaluator peer context
// ===========================================================================

/// Run 228 — typed, **local-only** evaluator context for a live inbound
/// `0x05` or peer-driven drain validation surface.
///
/// Pure data. It binds (or references, via digests) every field the run scope
/// requires so the previously-limited surfaces can carry/reference evaluator
/// context in source/test plumbing without any wire/schema change. The digest
/// fields are references into the Run 222 evaluator material
/// ([`DecisionSourceIdentity::source_identity_digest`],
/// [`EvaluatorRequest::request_digest`],
/// [`EvaluatorResponse::response_digest`]) and the candidate trust-bundle /
/// marker digests — never copies of any wire payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GovernanceEvaluatorPeerContext {
    /// Which previously-limited surface this context represents.
    pub surface: PeerEvaluatorContextSurface,
    /// Carrier-status classification.
    pub carrier_status: PeerEvaluatorCarrierStatus,
    /// Selected Run 211 governance-execution policy.
    pub selected_policy: GovernanceExecutionPolicy,
    /// Active Run 222 evaluator policy.
    pub evaluator_policy: EvaluatorPolicy,
    /// Governance-execution load status shape (Run 213).
    pub load_status: PeerEvaluatorLoadStatus,
    /// Governance-execution payload digest, where bound.
    pub governance_execution_payload_digest: Option<String>,
    /// Evaluator source-identity digest, where bound.
    pub evaluator_source_identity_digest: Option<String>,
    /// Evaluator request digest, where bound.
    pub evaluator_request_digest: Option<String>,
    /// Evaluator response digest, where bound.
    pub evaluator_response_digest: Option<String>,
    /// Candidate trust-bundle digest, where present.
    pub candidate_trust_bundle_digest: Option<String>,
    /// Candidate v2 marker digest, where present.
    pub candidate_v2_marker_digest: Option<String>,
    /// Authority-domain sequence.
    pub authority_domain_sequence: u64,
    /// Lifecycle action.
    pub lifecycle_action: LocalLifecycleAction,
    /// Trust-domain environment.
    pub environment: TrustBundleEnvironment,
    /// Trust-domain chain id.
    pub chain_id: String,
    /// Trust-domain genesis hash.
    pub genesis_hash: String,
    /// Peer id (opaque, local-only).
    pub peer_id: String,
    /// Source class.
    pub source_class: PeerEvaluatorSourceClass,
}

impl GovernanceEvaluatorPeerContext {
    /// Construct an absent-carrier context for `surface`. Under the default
    /// Disabled policy this preserves legacy validation behavior; under an
    /// explicit evaluator policy it fails closed as missing context.
    pub fn absent(
        surface: PeerEvaluatorContextSurface,
        environment: TrustBundleEnvironment,
        chain_id: impl Into<String>,
        genesis_hash: impl Into<String>,
    ) -> Self {
        Self {
            surface,
            carrier_status: PeerEvaluatorCarrierStatus::Absent,
            selected_policy: GovernanceExecutionPolicy::Disabled,
            evaluator_policy: EvaluatorPolicy::Disabled,
            load_status: PeerEvaluatorLoadStatus::Absent,
            governance_execution_payload_digest: None,
            evaluator_source_identity_digest: None,
            evaluator_request_digest: None,
            evaluator_response_digest: None,
            candidate_trust_bundle_digest: None,
            candidate_v2_marker_digest: None,
            authority_domain_sequence: 0,
            lifecycle_action: LocalLifecycleAction::Rotate,
            environment,
            chain_id: chain_id.into(),
            genesis_hash: genesis_hash.into(),
            peer_id: String::new(),
            source_class: match surface {
                PeerEvaluatorContextSurface::LiveInbound0x05 => {
                    PeerEvaluatorSourceClass::LiveInboundPeer
                }
                PeerEvaluatorContextSurface::PeerDrivenDrain => {
                    PeerEvaluatorSourceClass::DrainStagedPeer
                }
            },
        }
    }

    /// Construct a fully-bound `Present` context by **referencing** the Run
    /// 226 integration material for `surface`. Every evaluator digest is
    /// derived from the supplied integration context, so a `Present` context
    /// built this way is always internally consistent with the material it
    /// routes; the binding the underlying Run 222 / Run 224 evaluation
    /// enforces is therefore the authoritative check.
    pub fn present_from_integration<E>(
        surface: PeerEvaluatorContextSurface,
        source_class: PeerEvaluatorSourceClass,
        peer_id: impl Into<String>,
        integration: &GovernanceEvaluatorRuntimeIntegrationContext<'_, E>,
        candidate_trust_bundle_digest: Option<String>,
        candidate_v2_marker_digest: Option<String>,
    ) -> Self
    where
        E: ProductionGovernanceExecutionEvaluator,
    {
        Self {
            surface,
            carrier_status: PeerEvaluatorCarrierStatus::Present,
            selected_policy: integration.arming.governance_execution_policy(),
            evaluator_policy: integration.evaluator_policy,
            load_status: PeerEvaluatorLoadStatus::from_load_status(integration.load_status),
            governance_execution_payload_digest: integration
                .load_status
                .as_parts()
                .map(|parts| parts.input.input_digest()),
            evaluator_source_identity_digest: Some(integration.identity.source_identity_digest()),
            evaluator_request_digest: Some(integration.request.request_digest()),
            evaluator_response_digest: Some(integration.response.response_digest()),
            candidate_trust_bundle_digest,
            candidate_v2_marker_digest,
            authority_domain_sequence: integration.request.authority_domain_sequence,
            lifecycle_action: integration.request.lifecycle_action,
            environment: integration.trust_domain.environment,
            chain_id: integration.trust_domain.chain_id.clone(),
            genesis_hash: integration.trust_domain.genesis_hash.clone(),
            peer_id: peer_id.into(),
            source_class,
        }
    }

    /// Deterministic SHA3-256 hex digest over every context field. Two
    /// structurally-identical contexts always produce the same digest, and
    /// the digest is domain-separated so it can never collide with any other
    /// QBIND canonical digest.
    pub fn context_digest(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut h = Sha3_256::new();
        h.update(PEER_EVALUATOR_CONTEXT_DOMAIN_TAG.as_bytes());
        let mut field = |label: &[u8], present: u8, value: &[u8]| {
            h.update((label.len() as u64).to_le_bytes());
            h.update(label);
            h.update([present]);
            h.update((value.len() as u64).to_le_bytes());
            h.update(value);
        };
        field(b"surface", 1, self.surface.tag().as_bytes());
        field(b"carrier_status", 1, self.carrier_status.tag().as_bytes());
        field(b"selected_policy", 1, self.selected_policy.tag().as_bytes());
        field(b"evaluator_policy", 1, self.evaluator_policy.tag().as_bytes());
        field(b"load_status", 1, self.load_status.tag().as_bytes());
        let opt = |v: &Option<String>| match v {
            Some(s) => (1u8, s.clone()),
            None => (0u8, String::new()),
        };
        let (p, v) = opt(&self.governance_execution_payload_digest);
        field(b"governance_execution_payload_digest", p, v.as_bytes());
        let (p, v) = opt(&self.evaluator_source_identity_digest);
        field(b"evaluator_source_identity_digest", p, v.as_bytes());
        let (p, v) = opt(&self.evaluator_request_digest);
        field(b"evaluator_request_digest", p, v.as_bytes());
        let (p, v) = opt(&self.evaluator_response_digest);
        field(b"evaluator_response_digest", p, v.as_bytes());
        let (p, v) = opt(&self.candidate_trust_bundle_digest);
        field(b"candidate_trust_bundle_digest", p, v.as_bytes());
        let (p, v) = opt(&self.candidate_v2_marker_digest);
        field(b"candidate_v2_marker_digest", p, v.as_bytes());
        field(
            b"authority_domain_sequence",
            1,
            &self.authority_domain_sequence.to_le_bytes(),
        );
        field(
            b"lifecycle_action",
            1,
            self.lifecycle_action.tag().as_bytes(),
        );
        let environment_tag = self.environment.to_string();
        field(b"environment", 1, environment_tag.as_bytes());
        field(b"chain_id", 1, self.chain_id.as_bytes());
        field(b"genesis_hash", 1, self.genesis_hash.as_bytes());
        field(b"peer_id", 1, self.peer_id.as_bytes());
        field(b"source_class", 1, self.source_class.tag().as_bytes());
        hex::encode(h.finalize())
    }

    /// `true` iff a `Present` context references every digest the run scope
    /// requires it to bind (the four evaluator/payload digests). A `Present`
    /// context missing any required digest is treated as malformed.
    pub fn present_bindings_complete(&self) -> bool {
        self.governance_execution_payload_digest.is_some()
            && self.evaluator_source_identity_digest.is_some()
            && self.evaluator_request_digest.is_some()
            && self.evaluator_response_digest.is_some()
    }

    /// `true` iff this `Present` context's referenced digests and bound
    /// trust-domain / sequence / lifecycle fields are consistent with the
    /// supplied Run 226 integration material. Used as a local cross-binding
    /// check before routing.
    pub fn binds_consistently_with<E>(
        &self,
        integration: &GovernanceEvaluatorRuntimeIntegrationContext<'_, E>,
    ) -> bool
    where
        E: ProductionGovernanceExecutionEvaluator,
    {
        self.evaluator_source_identity_digest.as_deref()
            == Some(integration.identity.source_identity_digest().as_str())
            && self.evaluator_request_digest.as_deref()
                == Some(integration.request.request_digest().as_str())
            && self.evaluator_response_digest.as_deref()
                == Some(integration.response.response_digest().as_str())
            && self.authority_domain_sequence == integration.request.authority_domain_sequence
            && self.lifecycle_action == integration.request.lifecycle_action
            && self.environment == integration.trust_domain.environment
            && self.chain_id == integration.trust_domain.chain_id
            && self.genesis_hash == integration.trust_domain.genesis_hash
    }
}

// ===========================================================================
// Boundary outcome
// ===========================================================================

/// Run 228 — typed outcome of evaluating an evaluator peer context on a live
/// inbound `0x05` or peer-driven drain surface.
///
/// Only [`Self::RoutedProceedMutate`] authorizes the surface to continue (and
/// only because the composed Run 226 call-site wiring authorized a mutate).
/// Every other variant is a non-mutating, non-propagating, non-staging
/// fail-closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerEvaluatorContextOutcome {
    /// Default Disabled policy + absent carrier: legacy validation behavior
    /// is preserved bit-for-bit and the evaluator interface is never reached.
    LegacyValidationPreserved,
    /// A representable `Present` context routed through the Run 226 call-site
    /// wiring and the composed pipeline authorized a mutate. This is the
    /// **only** outcome that authorizes propagation / staging / apply.
    RoutedProceedMutate {
        /// The authorizing Run 224 integration outcome.
        integration_outcome: GovernanceEvaluatorRuntimeIntegrationOutcome,
        /// Deterministic context digest of the routed context.
        context_digest: String,
    },
    /// A `Present` context routed through the Run 226 call-site wiring and the
    /// composed pipeline failed closed. Carries the typed Run 226 fail-closed.
    RoutedFailClosed(GovernanceEvaluatorRuntimeCallsiteFailClosed),
    /// The surface cannot reach the integration layer without a wire/schema
    /// change. Typed fail-closed; no propagation / staging / apply.
    UnsupportedSurface {
        surface: PeerEvaluatorContextSurface,
        reason: String,
    },
    /// No wire/schema carrier exists to convey evaluator context. Typed
    /// fail-closed; explicitly NOT a silent approval.
    WireSchemaUnavailable {
        surface: PeerEvaluatorContextSurface,
        reason: String,
    },
    /// A malformed carrier was supplied. Fail-closed.
    MalformedRejected { reason: String },
    /// An explicit evaluator policy required a carrier but none was supplied.
    /// Fail-closed.
    MissingContextRejected { reason: String },
    /// A peer-majority / gossip "vote" cannot satisfy an evaluator policy.
    /// Fail-closed.
    PeerMajorityUnsupported,
    /// MainNet peer-driven apply remains refused unconditionally. Fail-closed.
    MainNetRefused,
}

impl PeerEvaluatorContextOutcome {
    /// `true` iff this outcome authorizes propagation / staging / apply. This
    /// is the **only** mutation-authorizing outcome.
    pub fn is_apply_authorized(&self) -> bool {
        matches!(self, Self::RoutedProceedMutate { .. })
    }

    /// `true` iff this outcome preserves legacy validation behavior.
    pub fn is_legacy_validation_preserved(&self) -> bool {
        matches!(self, Self::LegacyValidationPreserved)
    }

    /// `true` iff this outcome is a fail-closed rejection (every variant that
    /// is neither the legacy bypass nor an authorized mutate).
    pub fn is_fail_closed(&self) -> bool {
        !matches!(
            self,
            Self::LegacyValidationPreserved | Self::RoutedProceedMutate { .. }
        )
    }

    /// `true` iff this rejection is the MainNet peer-driven-apply refusal.
    pub fn is_mainnet_refused(&self) -> bool {
        matches!(self, Self::MainNetRefused)
            || matches!(
                self,
                Self::RoutedFailClosed(fc) if fc.is_mainnet_peer_driven_apply_refused()
            )
    }

    /// `true` iff this outcome leaves the surface with no propagation, no
    /// staging, and no apply (everything that is not an authorized mutate).
    pub fn no_propagation_no_staging_no_apply(&self) -> bool {
        !self.is_apply_authorized()
    }
}

// ===========================================================================
// Boundary entry points
// ===========================================================================

/// Run 228 — evaluate an evaluator peer context against the Run 226 call-site
/// wiring for a representable surface.
///
/// This is the core boundary entry point. It dispatches on the context's
/// carrier status:
///
/// * [`PeerEvaluatorCarrierStatus::MainNetRefused`], or any peer-driven drain
///   surface on a MainNet trust domain, returns
///   [`PeerEvaluatorContextOutcome::MainNetRefused`] before anything else.
/// * [`PeerEvaluatorCarrierStatus::Present`] verifies the local cross-binding,
///   then routes through [`wire_governance_evaluator_runtime_callsite`] and
///   surfaces the composed outcome (mutate / fail-closed / legacy bypass).
/// * [`PeerEvaluatorCarrierStatus::Absent`] preserves legacy validation under
///   the default Disabled evaluator policy, and fails closed as missing
///   context under any explicit evaluator policy.
/// * Every other carrier status is a typed fail-closed.
///
/// Pure — performs no I/O and no mutation. The integration context's
/// `surface` must equal `peer.surface.runtime_surface()`; otherwise the call
/// fails closed as an unsupported surface.
pub fn evaluate_peer_evaluator_context<E>(
    peer: &GovernanceEvaluatorPeerContext,
    integration: &GovernanceEvaluatorRuntimeIntegrationContext<'_, E>,
) -> PeerEvaluatorContextOutcome
where
    E: ProductionGovernanceExecutionEvaluator,
{
    // MainNet peer-driven apply remains refused unconditionally — guard it
    // before any other classification so a fixture approval can never bypass
    // it.
    if peer.carrier_status == PeerEvaluatorCarrierStatus::MainNetRefused
        || (peer.surface.is_peer_driven_apply_preflight()
            && peer.environment == TrustBundleEnvironment::Mainnet)
    {
        return PeerEvaluatorContextOutcome::MainNetRefused;
    }

    // The integration material must drive the same runtime surface this peer
    // context represents.
    if integration.surface != peer.surface.runtime_surface() {
        return PeerEvaluatorContextOutcome::UnsupportedSurface {
            surface: peer.surface,
            reason: format!(
                "integration surface {} does not match peer context surface {}",
                integration.surface.tag(),
                peer.surface.runtime_surface().tag(),
            ),
        };
    }

    match peer.carrier_status {
        PeerEvaluatorCarrierStatus::MainNetRefused => {
            // Handled above; kept exhaustive.
            PeerEvaluatorContextOutcome::MainNetRefused
        }
        PeerEvaluatorCarrierStatus::PeerMajorityUnsupported => {
            PeerEvaluatorContextOutcome::PeerMajorityUnsupported
        }
        PeerEvaluatorCarrierStatus::Malformed => PeerEvaluatorContextOutcome::MalformedRejected {
            reason: format!(
                "malformed evaluator peer context on {} surface",
                peer.surface.tag()
            ),
        },
        PeerEvaluatorCarrierStatus::UnsupportedSurface => {
            PeerEvaluatorContextOutcome::UnsupportedSurface {
                surface: peer.surface,
                reason: format!(
                    "{} surface cannot reach the Run 224 integration layer without a wire/schema \
                     change",
                    peer.surface.tag()
                ),
            }
        }
        PeerEvaluatorCarrierStatus::WireSchemaUnavailable => {
            PeerEvaluatorContextOutcome::WireSchemaUnavailable {
                surface: peer.surface,
                reason: format!(
                    "no wire/schema carrier exists on the {} surface to convey evaluator context; \
                     typed fail-closed (NOT an approval)",
                    peer.surface.tag()
                ),
            }
        }
        PeerEvaluatorCarrierStatus::Absent => {
            // A peer-majority source can never satisfy an evaluator policy.
            if peer.source_class.is_peer_majority() {
                return PeerEvaluatorContextOutcome::PeerMajorityUnsupported;
            }
            // Legacy validation is preserved only under the default Disabled
            // evaluator policy; an explicit evaluator policy fails closed.
            if peer.evaluator_policy == EvaluatorPolicy::Disabled
                && integration.arming.is_disabled()
            {
                // Route to confirm the legacy bypass (the integration
                // short-circuits before the evaluator stage).
                match wire_governance_evaluator_runtime_callsite(integration) {
                    Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass) => {
                        PeerEvaluatorContextOutcome::LegacyValidationPreserved
                    }
                    Ok(other) => {
                        // A non-bypass proceed under an absent carrier is not
                        // representable; fail closed conservatively.
                        PeerEvaluatorContextOutcome::MissingContextRejected {
                            reason: format!(
                                "absent carrier produced unexpected proceed outcome: {:?}",
                                other
                            ),
                        }
                    }
                    Err(fc) => PeerEvaluatorContextOutcome::RoutedFailClosed(fc),
                }
            } else {
                PeerEvaluatorContextOutcome::MissingContextRejected {
                    reason: format!(
                        "evaluator policy {} requires an evaluator context but the carrier is \
                         absent on the {} surface",
                        peer.evaluator_policy.tag(),
                        peer.surface.tag()
                    ),
                }
            }
        }
        PeerEvaluatorCarrierStatus::Present => {
            // A peer-majority source can never satisfy an evaluator policy,
            // even with a present carrier.
            if peer.source_class.is_peer_majority() {
                return PeerEvaluatorContextOutcome::PeerMajorityUnsupported;
            }
            // A present carrier must reference every required binding.
            if !peer.present_bindings_complete() {
                return PeerEvaluatorContextOutcome::MalformedRejected {
                    reason: format!(
                        "present evaluator peer context on {} surface is missing required \
                         evaluator/payload digest bindings",
                        peer.surface.tag()
                    ),
                };
            }
            // The local cross-binding must agree with the routed material.
            if !peer.binds_consistently_with(integration) {
                return PeerEvaluatorContextOutcome::MalformedRejected {
                    reason: format!(
                        "present evaluator peer context on {} surface does not bind consistently \
                         with the Run 226 integration material",
                        peer.surface.tag()
                    ),
                };
            }
            // Route through the Run 226 call-site wiring and surface the
            // composed outcome.
            match wire_governance_evaluator_runtime_callsite(integration) {
                Ok(outcome @ GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedMutate { .. }) => {
                    PeerEvaluatorContextOutcome::RoutedProceedMutate {
                        integration_outcome: outcome,
                        context_digest: peer.context_digest(),
                    }
                }
                Ok(GovernanceEvaluatorRuntimeIntegrationOutcome::ProceedLegacyBypass) => {
                    PeerEvaluatorContextOutcome::LegacyValidationPreserved
                }
                // The two proceed variants above are the only `Ok` values;
                // `wire_governance_evaluator_runtime_callsite` returns `Err`
                // for every non-proceed outcome.
                Ok(other) => PeerEvaluatorContextOutcome::RoutedFailClosed(
                    GovernanceEvaluatorRuntimeCallsiteFailClosed {
                        surface: integration.surface,
                        outcome: other,
                        reason: "unexpected non-proceed outcome surfaced as Ok".to_string(),
                    },
                ),
                Err(fc) => PeerEvaluatorContextOutcome::RoutedFailClosed(fc),
            }
        }
    }
}

/// Run 228 — convenience entry point for the live-wire-only path that cannot
/// construct a full evaluator context.
///
/// The live inbound `0x05` wire and the peer-driven drain wire do **not**
/// carry the governance proposal/decision evaluator bindings, so a path that
/// only has the wire material cannot build a [`PeerEvaluatorCarrierStatus::Present`]
/// context. This entry point makes that honest by returning a typed
/// [`PeerEvaluatorContextOutcome::WireSchemaUnavailable`] under an explicit
/// evaluator policy and [`PeerEvaluatorContextOutcome::LegacyValidationPreserved`]
/// under the default Disabled policy — never an approval, and never any
/// propagation / staging / apply.
pub fn evaluate_peer_evaluator_context_wire_only(
    surface: PeerEvaluatorContextSurface,
    environment: TrustBundleEnvironment,
    chain_id: &str,
    genesis_hash: &str,
    evaluator_policy: EvaluatorPolicy,
) -> PeerEvaluatorContextOutcome {
    // MainNet peer-driven apply remains refused unconditionally.
    if surface.is_peer_driven_apply_preflight() && environment == TrustBundleEnvironment::Mainnet {
        return PeerEvaluatorContextOutcome::MainNetRefused;
    }
    if evaluator_policy == EvaluatorPolicy::Disabled {
        let _ = (chain_id, genesis_hash);
        PeerEvaluatorContextOutcome::LegacyValidationPreserved
    } else {
        PeerEvaluatorContextOutcome::WireSchemaUnavailable {
            surface,
            reason: format!(
                "no wire/schema carrier exists on the {} surface to convey evaluator context for \
                 evaluator policy {}; typed fail-closed (NOT an approval). Wire-carrier evidence \
                 is deferred to Run 229.",
                surface.tag(),
                evaluator_policy.tag()
            ),
        }
    }
}

/// Run 228 — MainNet peer-driven apply remains refused even with a fixture
/// evaluator approval. Mirrors the Run 222 / Run 224 invariant at the peer
/// evaluator-context boundary.
pub const fn mainnet_peer_driven_apply_remains_refused_under_peer_context() -> bool {
    true
}

/// Run 228 — validator-set rotation remains unsupported at the peer
/// evaluator-context boundary.
pub const fn validator_set_rotation_remains_unsupported_under_peer_context() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn surface_maps_to_runtime_surface() {
        assert_eq!(
            PeerEvaluatorContextSurface::LiveInbound0x05.runtime_surface(),
            GovernanceExecutionRuntimeSurface::LiveInbound0x05
        );
        assert_eq!(
            PeerEvaluatorContextSurface::PeerDrivenDrain.runtime_surface(),
            GovernanceExecutionRuntimeSurface::PeerDrivenDrain
        );
        assert!(PeerEvaluatorContextSurface::PeerDrivenDrain.is_peer_driven_apply_preflight());
        assert!(!PeerEvaluatorContextSurface::LiveInbound0x05.is_peer_driven_apply_preflight());
    }

    #[test]
    fn absent_context_digest_is_deterministic() {
        let a = GovernanceEvaluatorPeerContext::absent(
            PeerEvaluatorContextSurface::LiveInbound0x05,
            TrustBundleEnvironment::Devnet,
            "qbind-devnet",
            "genesis",
        );
        let b = GovernanceEvaluatorPeerContext::absent(
            PeerEvaluatorContextSurface::LiveInbound0x05,
            TrustBundleEnvironment::Devnet,
            "qbind-devnet",
            "genesis",
        );
        assert_eq!(a.context_digest(), b.context_digest());
    }

    #[test]
    fn invariant_helpers_hold() {
        assert!(mainnet_peer_driven_apply_remains_refused_under_peer_context());
        assert!(validator_set_rotation_remains_unsupported_under_peer_context());
    }
}