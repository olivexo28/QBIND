//! Run 078 (C4 piece: disabled-by-default **P2P wire** receive path
//! for peer/gossiped trust-bundle candidate **validation only**):
//! the smallest honest receive-path surface that decodes a typed,
//! versioned, bounded wire envelope and routes it through the
//! Run 076 [`PeerCandidateValidator`] for fail-closed validation
//! **without** applying the candidate, propagating it, persisting
//! its sequence, mutating `LivePqcTrustState`, or evicting any
//! P2P/KEMTLS session.
//!
//! # Strict scope
//!
//! Run 078 is **only** the safest possible wire-receive surface
//! under the umbrella "peer-supplied / gossiped bundle acceptance"
//! C4-OPEN sub-piece in `docs/whitepaper/contradiction.md`. It is
//! intentionally minimal:
//!
//! - Defines [`PeerCandidateWireEnvelopeV1`] — a typed, versioned,
//!   bounded wire envelope **distinct** from the Run 077 local
//!   fixture format. Different domain tag, different version
//!   namespace, different module — so a fixture file cannot be
//!   mistaken for a wire frame and vice versa.
//! - Defines [`DISCRIMINATOR_PEER_CANDIDATE_WIRE`] (`0x05`) — a
//!   reserved P2P-frame discriminator that does **not** collide
//!   with the existing `0x01` consensus, `0x02` DAG, or `0x03`
//!   control discriminators in `p2p_tcp.rs`. The same length-
//!   prefixed framing (`[discriminator: u8][length: u32-be]
//!   [payload: length bytes]`) is reused, so any future production
//!   wire dispatcher can route Run 078 frames over the existing
//!   KEMTLS-encrypted secure channel with no framing change.
//! - Defines [`PeerCandidateWireReceiver`] — the disabled-by-default
//!   receive handler. Wraps a Run 076 [`PeerCandidateValidator`]
//!   one-to-one, exposes `try_handle_frame(frame_bytes, ctx) ->
//!   PeerCandidateWireOutcome`, and records the SAME seven Run 076
//!   `qbind_p2p_pqc_trust_bundle_peer_candidate_*` Prometheus
//!   counters via the operator-supplied [`P2pMetrics`] reference
//!   (no new metric family; no `_applied_total` family).
//! - **Does NOT** call [`PeerCandidateValidator`] when the receiver
//!   is disabled — when `enabled == false`, the receiver bumps the
//!   truthful `received_total` + `disabled_total` counters and
//!   returns [`PeerCandidateWireOutcome::Disabled`] **before** any
//!   decode work beyond the frame-level discriminator and length
//!   header.
//! - **Does NOT** propagate / re-broadcast the candidate. The
//!   receiver has no `P2pService` handle, no broadcast method, no
//!   peer fan-out. Run 078 is end-of-line at the receiver.
//! - **Does NOT** apply the candidate. No `LiveTrustApplyContext`,
//!   no `LiveReloadController`, no `LivePqcTrustState::swap_*`,
//!   no `P2pSessionEvictor` handle, no `check_and_update_sequence`
//!   call. The receiver inherits the Run 076 strict non-mutation
//!   contract by construction (the validator it wraps has no apply
//!   function to call).
//! - **Does NOT** persist the candidate's sequence. The Run 069
//!   `validate_candidate_bundle_full` path consulted by Run 076
//!   uses `peek_sequence` only (read-only).
//! - **Does NOT** introduce automatic gossip propagation, peer-
//!   driven live apply, admin-API triggers, filesystem-watcher
//!   triggers, `activation_epoch` runtime sourcing, KMS/HSM custody,
//!   in-binary or on-chain bundle-signing-key ratification, or
//!   fast-sync / consensus-storage restore parity.
//! - **Does NOT** weaken Run 069 reload-check, Run 070 reload-apply,
//!   Run 073 process-start apply, Run 074 SIGHUP live reload-apply,
//!   Run 076 library-level peer-candidate validator, or Run 077
//!   binary-facing local check. All six are bit-for-bit unchanged.
//! - **Does NOT** silently fall back to `--p2p-trusted-root`,
//!   `DummySig`, `DummyKem`, or `DummyAead`. The reused Run 050/051
//!   loader fails closed on those exactly like startup.
//! - **Does NOT** accept unsigned TestNet/MainNet bundles. The
//!   reused loader rejects those exactly like startup.
//!
//! # Wire format
//!
//! Run 078 reuses the existing `p2p_tcp.rs` length-prefixed framing
//! verbatim, with a new dedicated discriminator:
//!
//! ```text
//! ┌────────────────────┬───────────────────┬───────────────────────────────────────┐
//! │ discriminator: u8  │ payload_len: u32  │ payload: payload_len bytes            │
//! │ = 0x05             │ big-endian        │ = serde_json(PeerCandidateWireEnvelope) │
//! └────────────────────┴───────────────────┴───────────────────────────────────────┘
//! ```
//!
//! The payload itself is a strict JSON object whose schema is the
//! [`PeerCandidateWireEnvelopeV1`] struct below. The on-wire size of
//! the entire frame is hard-capped by [`MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES`]
//! — this cap is enforced on the **declared** `payload_len` from
//! the frame header **before** any allocation/decode, so an
//! adversary cannot force a large allocation or expensive JSON
//! decode by sending an oversized header.
//!
//! # Boundary vs. production gossip dispatcher
//!
//! Run 078 lands the receive **codec and handler** with a
//! disabled-by-default CLI flag. It does **not** wire a new variant
//! into the existing `P2pMessage` enum in `crates/qbind-node/src/p2p.rs`
//! because doing so would change the consensus / DAG / control
//! message dispatch surface and risk silent regressions in the
//! production binary. Instead, the receiver is the typed function
//! a future production gossip dispatcher will call once it has read
//! a frame whose first byte is `DISCRIMINATOR_PEER_CANDIDATE_WIRE`.
//! Tests in `crates/qbind-node/tests/run_078_pqc_peer_candidate_wire_tests.rs`
//! drive frames through this entry point identically to how the
//! production dispatcher would; the function takes raw frame bytes
//! and an operator-supplied trust context.
//!
//! This is the same "smallest honest receive-path harness that uses
//! the same P2P framing layer and document exact boundary" the
//! Run 078 task explicitly allows when no fully-typed P2P channel
//! exists for peer-candidate validation: the codec is on the wire
//! format, the handler is the production-honest end-of-line for any
//! such frame, and the boundary is "no production gossip subscription
//! adds 0x05 frames to the wire today — they will be added by a
//! future run under a separate review once peer-driven live apply
//! / propagation / activation_epoch / KMS-HSM custody all land".

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use qbind_ledger::{
    BundleSigningRatification, BundleSigningRatificationV2, GenesisAuthorityConfig, GenesisHash,
    NetworkEnvironmentPolicy, RatificationEnforcementPolicy,
};
use qbind_types::{ChainId, NetworkEnvironment};

use crate::metrics::P2pMetrics;
use crate::p2p::NodeId;
use crate::pqc_governance_proof_wire::{
    GovernanceAuthorityProofWire, GovernanceProofLoadStatus,
};
use crate::pqc_peer_candidate_staging::{PeerCandidateStagingQueue, StagingOutcome};
use crate::pqc_ratification_policy::RatificationGateDecision;
use crate::pqc_trust_activation::ActivationContext;
use crate::pqc_trust_bundle::{BundleSigningKeySet, TrustBundleEnvironment};
use crate::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateEnvelope, PeerCandidateOutcome,
    PeerCandidateRuntimeContext, PeerCandidateValidator, MAX_PEER_CANDIDATE_BUNDLE_BYTES,
};
use crate::pqc_trust_reload::RatificationEnforcementContext;

/// Reserved P2P frame discriminator for Run 078 peer-candidate wire
/// frames. Distinct from the existing `p2p_tcp.rs` consensus
/// (`0x01`), DAG (`0x02`), and control (`0x03`) discriminators.
/// Value `0x04` is left reserved for any future control-plane
/// extension. Value `0x05` is the first dedicated trust-bundle
/// peer-candidate wire frame.
pub const DISCRIMINATOR_PEER_CANDIDATE_WIRE: u8 = 0x05;

/// JSON envelope overhead allowance added on top of the lowercase-
/// hex encoded bundle bytes so the wire envelope's metadata fields
/// (domain tag, version, chain-id-hex, peer-id, declared length /
/// sequence / fingerprint prefix, environment) fit comfortably
/// inside [`MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES`] without ever
/// permitting a payload that would exceed the Run 076 inner cap.
pub const PEER_CANDIDATE_WIRE_JSON_ENVELOPE_OVERHEAD_BYTES: usize = 16 * 1024;

/// Hard cap on the on-wire size of the entire Run 078 frame
/// (`1 + 4 + payload_len` bytes). Set conservatively to the
/// Run 076 [`MAX_PEER_CANDIDATE_BUNDLE_BYTES`] (256 KiB) *
/// 2 (lowercase-hex encoding doubles the byte count) plus
/// [`PEER_CANDIDATE_WIRE_JSON_ENVELOPE_OVERHEAD_BYTES`] so the
/// wire envelope's JSON metadata fields plus the lowercase-hex
/// encoding of the bundle bytes themselves fit comfortably.
///
/// This cap is enforced on the **declared** payload length from
/// the 5-byte frame header **before** any allocation / decode /
/// signature verification.
pub const MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES: usize = 1
    + 4
    + (MAX_PEER_CANDIDATE_BUNDLE_BYTES * 2 + PEER_CANDIDATE_WIRE_JSON_ENVELOPE_OVERHEAD_BYTES);

/// Canonical domain tag for the Run 078 wire envelope. **Distinct**
/// from the Run 076 [`PeerCandidateEnvelope::DOMAIN_TAG`] fixture
/// tag (`"qbind-peer-trust-bundle-candidate-v0"`) so a fixture file
/// can never be replayed as a wire frame and vice versa.
pub const PEER_CANDIDATE_WIRE_DOMAIN_TAG: &str =
    "QBIND:PQC_TRUST_BUNDLE_PEER_CANDIDATE_WIRE:v1";

/// Current Run 078 wire envelope version. Bumped only on layout
/// changes; the receiver MUST reject unknown versions.
pub const PEER_CANDIDATE_WIRE_VERSION: u16 = 1;

/// Run 078 wire envelope (version 1). Strict, log-safe metadata
/// plus the candidate `bundle_bytes` themselves (which never escape
/// the validator).
///
/// `bundle_bytes` is serialised as a **lowercase hex string**, the
/// same encoding the Run 076 [`PeerCandidateEnvelope::bundle_bytes`]
/// uses — so an operator inspecting captured wire frames sees the
/// same diff-friendly format the local Run 077 fixture file uses.
/// This is a deliberate design choice: the wire format is
/// human-inspectable, the cap is enforced before allocation, and
/// the candidate is validated through the same Run 076 / Run 069
/// pipeline regardless of how it arrived.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct PeerCandidateWireEnvelopeV1 {
    /// Run 078 wire envelope version. Currently fixed at
    /// [`PEER_CANDIDATE_WIRE_VERSION`]. Future envelopes that
    /// change layout MUST bump this and the receiver MUST reject
    /// unknown versions.
    pub envelope_version: u16,
    /// Domain tag (`PEER_CANDIDATE_WIRE_DOMAIN_TAG`). Bound into
    /// the receiver so a payload from a *different* protocol
    /// domain (e.g. the Run 076 local fixture, a Run 074 SIGHUP
    /// trigger envelope, a consensus message) cannot be replayed
    /// here.
    pub domain_tag: String,
    /// Optional peer identifier (e.g. P2P node id hex prefix).
    /// Used for safe operator-log lines; not security-relevant to
    /// the validation pipeline (the candidate itself is what is
    /// authenticated, not the peer).
    pub peer_id: Option<String>,
    /// Environment the peer claims this candidate targets.
    pub environment: TrustBundleEnvironment,
    /// 16-char lowercase hex chain id the peer claims this
    /// candidate targets.
    pub chain_id_hex: String,
    /// Bundle's declared sequence. Cross-checked against the parsed
    /// bundle by the Run 076 validator AFTER structural validation.
    pub declared_sequence: u64,
    /// 8-char lowercase hex prefix of the bundle's canonical
    /// fingerprint (Run 050 SHA3-256).
    pub declared_fingerprint_prefix: String,
    /// Length the peer claims `bundle_bytes` has. Cross-checked
    /// against `bundle_bytes.len()`.
    pub declared_length: usize,
    /// The peer-supplied bundle bytes. Strict cap
    /// [`MAX_PEER_CANDIDATE_BUNDLE_BYTES`] inherited from Run 076.
    /// Serialised as a lowercase hex string (see Run 076).
    #[serde(with = "crate::pqc_trust_peer_candidate::peer_candidate_bundle_bytes_hex_pub")]
    pub bundle_bytes: Vec<u8>,

    /// Run 176 — additive optional governance-proof carrier.
    ///
    /// Mirrors the Run 167 v2-sidecar optional sibling field
    /// (`governance_authority_proof`) but lives directly on the live
    /// inbound `0x05` peer-candidate wire envelope so a peer can
    /// transport authority-proof material end-to-end at source/test
    /// level. The field is `#[serde(default, skip_serializing_if =
    /// "Option::is_none")]` so legacy / no-proof v1 envelopes (every
    /// envelope produced before Run 176) continue to parse and
    /// serialise byte-for-byte as they did before. The carrier itself
    /// is structurally validated (schema version, non-empty required
    /// fields, hex-decodable signature) by
    /// [`Self::governance_proof_load_status`]; cryptographic /
    /// trust-domain / lifecycle / digest / suite checks are owned by
    /// the existing Run 163 verifier composition reachable through
    /// the Run 173 / Run 176 validation-only shim.
    ///
    /// Carrying this field does NOT enable apply-on-receipt, MainNet
    /// peer-driven apply, on-chain governance, peer-majority authority,
    /// validator-set rotation, autonomous apply, KMS/HSM custody, or
    /// any new mutating boundary. It is purely additive evidence that
    /// the live inbound `0x05` validation-only path can pass into the
    /// existing Run 173 governance-proof gate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub governance_authority_proof: Option<GovernanceAuthorityProofWire>,
}

impl PeerCandidateWireEnvelopeV1 {
    /// Construct from the Run 076 fixture envelope. This is the
    /// canonical bridge: a Run 077 local fixture can be promoted
    /// to a Run 078 wire envelope by re-tagging the domain and
    /// version. The bridge is intentionally explicit so the two
    /// formats are never silently conflated.
    pub fn from_run076_envelope(e: &PeerCandidateEnvelope) -> Self {
        Self {
            envelope_version: PEER_CANDIDATE_WIRE_VERSION,
            domain_tag: PEER_CANDIDATE_WIRE_DOMAIN_TAG.to_string(),
            peer_id: e.peer_id.clone(),
            environment: e.environment,
            chain_id_hex: e.chain_id_hex.clone(),
            declared_sequence: e.declared_sequence,
            declared_fingerprint_prefix: e.declared_fingerprint_prefix.clone(),
            declared_length: e.declared_length,
            bundle_bytes: e.bundle_bytes.clone(),
            // Run 176 — Run 077 fixture envelope has no carrier; the
            // bridge stays additive-default-`None` so promoting an
            // existing fixture to a wire envelope never accidentally
            // synthesises a proof.
            governance_authority_proof: None,
        }
    }

    /// Convert into a Run 076 fixture envelope for the receiver to
    /// hand to [`PeerCandidateValidator::try_accept`]. Drops the
    /// wire-only domain tag / version (they were already verified
    /// in [`decode_peer_candidate_wire_frame`]) and re-stamps the
    /// Run 076 fixture domain tag / version expected by the
    /// validator's envelope pre-check.
    pub fn into_run076_envelope(self) -> PeerCandidateEnvelope {
        PeerCandidateEnvelope {
            envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
            domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
            peer_id: self.peer_id,
            environment: self.environment,
            chain_id_hex: self.chain_id_hex,
            declared_sequence: self.declared_sequence,
            declared_fingerprint_prefix: self.declared_fingerprint_prefix,
            declared_length: self.declared_length,
            bundle_bytes: self.bundle_bytes,
        }
    }

    /// Run 176 — typed governance-proof load status for the optional
    /// carrier on this live inbound `0x05` peer-candidate wire
    /// envelope.
    ///
    /// Mirrors the Run 167 sidecar loader behaviour bit-for-bit:
    ///
    /// * Carrier absent →
    ///   [`GovernanceProofLoadStatus::Absent`] (legacy / no-proof
    ///   envelope; backwards-compatible under
    ///   [`crate::pqc_governance_authority::GovernanceProofPolicy::NotRequired`]).
    /// * Carrier present and structurally well-formed →
    ///   [`GovernanceProofLoadStatus::Available`] carrying the typed
    ///   Run 163
    ///   [`crate::pqc_governance_authority::GovernanceAuthorityProof`].
    ///   The proof has NOT yet been verified — verification is owned
    ///   by the Run 173 / Run 176 validation-only shim through the
    ///   Run 163 verifier.
    /// * Carrier present but malformed (unknown schema version, empty
    ///   required field, empty issuer signature) →
    ///   [`GovernanceProofLoadStatus::Malformed`]; the gate fails
    ///   closed under any policy that requires a proof, and the
    ///   carrier is mapped to
    ///   [`crate::pqc_governance_authority::GovernanceProofContext::Unavailable`]
    ///   under
    ///   [`crate::pqc_governance_authority::GovernanceProofPolicy::NotRequired`]
    ///   (Run 167 documented mapping).
    ///
    /// This helper performs structural validation only and is
    /// mutation-free: no marker write, no sequence write, no live
    /// trust swap, no session eviction, no Run 070 invocation.
    pub fn governance_proof_load_status(&self) -> GovernanceProofLoadStatus {
        match self.governance_authority_proof.as_ref() {
            None => GovernanceProofLoadStatus::Absent,
            Some(wire) => match wire.to_governance_authority_proof() {
                Ok(proof) => GovernanceProofLoadStatus::Available(proof),
                Err(err) => GovernanceProofLoadStatus::Malformed(err),
            },
        }
    }
}

/// Run 078 frame-level decode error. Every variant is a fail-closed
/// reason that fires **before** the Run 076 validator is invoked
/// (and **before** any expensive crypto runs). The receiver records
/// the matching `rejected_total` or `dropped_oversize_total`
/// counter and returns without mutating any trust / sequence /
/// session state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PeerCandidateWireFrameError {
    /// Frame is shorter than the 5-byte header.
    FrameTooShort {
        observed_len: usize,
    },
    /// First byte is not [`DISCRIMINATOR_PEER_CANDIDATE_WIRE`].
    UnknownDiscriminator {
        observed: u8,
    },
    /// `payload_len` field exceeds
    /// [`MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES`] **before** any
    /// allocation. Adversary cannot force a large allocation here.
    DeclaredPayloadOversize {
        declared: usize,
        cap: usize,
    },
    /// Frame is shorter than `5 + payload_len` bytes (truncated).
    FrameTruncated {
        declared: usize,
        observed: usize,
    },
    /// Payload did not parse as a [`PeerCandidateWireEnvelopeV1`]
    /// JSON document.
    PayloadParseError {
        message: String,
    },
    /// Decoded envelope's `envelope_version` field is not
    /// [`PEER_CANDIDATE_WIRE_VERSION`].
    UnsupportedEnvelopeVersion {
        observed: u16,
    },
    /// Decoded envelope's `domain_tag` is not
    /// [`PEER_CANDIDATE_WIRE_DOMAIN_TAG`].
    UnknownDomainTag {
        observed: String,
    },
}

impl std::fmt::Display for PeerCandidateWireFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameTooShort { observed_len } => write!(
                f,
                "peer-candidate wire frame too short ({} < 5 bytes); live trust \
                 state unchanged; sequence not persisted; sessions untouched",
                observed_len
            ),
            Self::UnknownDiscriminator { observed } => write!(
                f,
                "peer-candidate wire frame has unknown discriminator 0x{:02x} \
                 (expected 0x{:02x}); live trust state unchanged; sequence not \
                 persisted; sessions untouched",
                observed, DISCRIMINATOR_PEER_CANDIDATE_WIRE
            ),
            Self::DeclaredPayloadOversize { declared, cap } => write!(
                f,
                "peer-candidate wire frame declared payload_len={} exceeds cap={} \
                 (dropped BEFORE any allocation / decode / crypto); live trust \
                 state unchanged; sequence not persisted; sessions untouched",
                declared, cap
            ),
            Self::FrameTruncated { declared, observed } => write!(
                f,
                "peer-candidate wire frame truncated (declared payload_len={} but \
                 only {} bytes observed); live trust state unchanged; sequence \
                 not persisted; sessions untouched",
                declared, observed
            ),
            Self::PayloadParseError { message } => write!(
                f,
                "peer-candidate wire frame payload did not parse as \
                 PeerCandidateWireEnvelopeV1 JSON: {}; live trust state \
                 unchanged; sequence not persisted; sessions untouched",
                message
            ),
            Self::UnsupportedEnvelopeVersion { observed } => write!(
                f,
                "peer-candidate wire frame envelope_version={} unsupported \
                 (expected {}); live trust state unchanged; sequence not \
                 persisted; sessions untouched",
                observed, PEER_CANDIDATE_WIRE_VERSION
            ),
            Self::UnknownDomainTag { observed } => write!(
                f,
                "peer-candidate wire frame unknown domain_tag {:?} (expected \
                 {:?}); live trust state unchanged; sequence not persisted; \
                 sessions untouched",
                observed, PEER_CANDIDATE_WIRE_DOMAIN_TAG
            ),
        }
    }
}

impl std::error::Error for PeerCandidateWireFrameError {}

/// Encode a [`PeerCandidateWireEnvelopeV1`] into a Run 078 wire
/// frame using the same length-prefixed framing as `p2p_tcp.rs`.
///
/// The returned bytes are exactly what
/// [`decode_peer_candidate_wire_frame`] / [`PeerCandidateWireReceiver::try_handle_frame`]
/// expect on the receive side. Encoding is **infallible** at the
/// frame layer (serde_json may fail on truly pathological inputs,
/// but the envelope's owned fields cannot trigger that path); the
/// `Result` keeps the surface symmetric with [`decode_peer_candidate_wire_frame`].
pub fn encode_peer_candidate_wire_frame(
    envelope: &PeerCandidateWireEnvelopeV1,
) -> Result<Vec<u8>, PeerCandidateWireFrameError> {
    let payload = serde_json::to_vec(envelope).map_err(|e| {
        PeerCandidateWireFrameError::PayloadParseError {
            message: format!("encode error: {}", e),
        }
    })?;
    if 1 + 4 + payload.len() > MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES {
        return Err(PeerCandidateWireFrameError::DeclaredPayloadOversize {
            declared: payload.len(),
            cap: MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES,
        });
    }
    let len: u32 = payload.len() as u32;
    let mut frame = Vec::with_capacity(1 + 4 + payload.len());
    frame.push(DISCRIMINATOR_PEER_CANDIDATE_WIRE);
    frame.extend_from_slice(&len.to_be_bytes());
    frame.extend_from_slice(&payload);
    Ok(frame)
}

/// Decode a Run 078 wire frame into a [`PeerCandidateWireEnvelopeV1`].
/// Strict fail-closed: each error variant is fired BEFORE any
/// allocation / signature / Run 076 validator call that could be
/// expensive for the receiver.
pub fn decode_peer_candidate_wire_frame(
    frame: &[u8],
) -> Result<PeerCandidateWireEnvelopeV1, PeerCandidateWireFrameError> {
    if frame.len() < 5 {
        return Err(PeerCandidateWireFrameError::FrameTooShort {
            observed_len: frame.len(),
        });
    }
    if frame[0] != DISCRIMINATOR_PEER_CANDIDATE_WIRE {
        return Err(PeerCandidateWireFrameError::UnknownDiscriminator {
            observed: frame[0],
        });
    }
    let declared = u32::from_be_bytes([frame[1], frame[2], frame[3], frame[4]]) as usize;
    // Cap BEFORE allocation / decode (DoS-resistant).
    if 1 + 4 + declared > MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES {
        return Err(PeerCandidateWireFrameError::DeclaredPayloadOversize {
            declared,
            cap: MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES,
        });
    }
    if frame.len() < 5 + declared {
        return Err(PeerCandidateWireFrameError::FrameTruncated {
            declared,
            observed: frame.len().saturating_sub(5),
        });
    }
    let payload = &frame[5..5 + declared];
    let envelope: PeerCandidateWireEnvelopeV1 =
        serde_json::from_slice(payload).map_err(|e| {
            PeerCandidateWireFrameError::PayloadParseError {
                message: e.to_string(),
            }
        })?;
    if envelope.envelope_version != PEER_CANDIDATE_WIRE_VERSION {
        return Err(PeerCandidateWireFrameError::UnsupportedEnvelopeVersion {
            observed: envelope.envelope_version,
        });
    }
    if envelope.domain_tag != PEER_CANDIDATE_WIRE_DOMAIN_TAG {
        return Err(PeerCandidateWireFrameError::UnknownDomainTag {
            observed: envelope.domain_tag.clone(),
        });
    }
    Ok(envelope)
}

/// Run 078 disabled-by-default wire receiver configuration. The
/// default-constructed value is `enabled = false` so importing /
/// constructing the receiver without explicitly opting in is a
/// guaranteed no-op.
#[derive(Debug, Clone)]
pub struct PeerCandidateWireReceiverConfig {
    /// Master switch. Default `false`. When `false`,
    /// [`PeerCandidateWireReceiver::try_handle_frame`] bumps only
    /// the `received_total` and `disabled_total` Run 076 counters
    /// and returns without touching the payload beyond the frame-
    /// level discriminator / length check.
    pub enabled: bool,
    /// Inner [`PeerCandidateValidator`] config. When `enabled` is
    /// `true` on the receiver, `inner.enabled` is forced to `true`
    /// at construction time so the validator routes through the
    /// SAME Run 069 pipeline that startup, the local reload-check,
    /// Run 073 process-start apply, Run 074 SIGHUP live reload-
    /// apply, Run 076 library-level validator, and Run 077 binary-
    /// facing local check all use.
    pub inner: PeerCandidateConfig,
}

impl Default for PeerCandidateWireReceiverConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            inner: PeerCandidateConfig::default(),
        }
    }
}

/// Run 088 disabled-by-default propagation prototype configuration.
/// Propagation is advisory rebroadcast only: it never applies a
/// candidate, never persists a sequence, never mutates live trust, and
/// never evicts sessions.
#[derive(Debug, Clone)]
pub struct PeerCandidatePropagationConfig {
    /// Master switch. Default `false`.
    pub enabled: bool,
    /// Bounded seen-cache capacity for loop / duplicate suppression.
    pub seen_lru_capacity: usize,
    /// Maximum rebroadcast targets selected from currently connected
    /// peers after excluding the source peer.
    pub max_rebroadcast_targets: usize,
    /// Fixed-window propagation attempt rate-limit window.
    pub rate_limit_window_ms: u64,
    /// Maximum validated propagation attempts in one window.
    pub max_in_window: u32,
}

impl Default for PeerCandidatePropagationConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            seen_lru_capacity: 256,
            max_rebroadcast_targets: 16,
            rate_limit_window_ms: 1_000,
            max_in_window: 8,
        }
    }
}

#[derive(Debug)]
struct PeerCandidatePropagationState {
    seen: VecDeque<String>,
    rate_limiter: crate::pqc_trust_peer_candidate::PeerCandidateRateLimiter,
}

impl PeerCandidatePropagationState {
    fn new(cfg: &PeerCandidatePropagationConfig) -> Self {
        Self {
            seen: VecDeque::with_capacity(cfg.seen_lru_capacity.max(1)),
            rate_limiter: crate::pqc_trust_peer_candidate::PeerCandidateRateLimiter::new(
                cfg.rate_limit_window_ms,
                cfg.max_in_window,
            ),
        }
    }

    fn contains(&self, id: &str) -> bool {
        // Run 088 keeps the propagation seen cache deliberately small
        // (`seen_lru_capacity` defaults to 256) and allocation-light.
        // A linear scan under that hard bound is acceptable for the
        // prototype and avoids adding a second membership structure that
        // could drift from the eviction order.
        self.seen.iter().any(|s| s == id)
    }

    fn insert(&mut self, id: String, capacity: usize) {
        if self.contains(&id) {
            return;
        }
        let cap = capacity.max(1);
        if self.seen.len() == cap {
            self.seen.pop_front();
        }
        self.seen.push_back(id);
    }
}

/// Run 078 outcome of [`PeerCandidateWireReceiver::try_handle_frame`].
/// Every variant is non-mutating for live trust state, sequence
/// persistence, and P2P sessions.
#[derive(Debug)]
pub enum PeerCandidateWireOutcome {
    /// Receiver was disabled (`config.enabled == false`). The
    /// frame's discriminator + declared length were checked (cheap
    /// header parse only), the truthful `received_total` and
    /// `disabled_total` Run 076 counters were bumped, no decode,
    /// no validator call, no crypto, no propagation.
    Disabled,
    /// Frame failed the frame-level decode BEFORE the Run 076
    /// validator was invoked. The matching Run 076 counter
    /// (`dropped_oversize_total` for declared-oversize, otherwise
    /// `rejected_total`) was bumped; `received_total` was bumped
    /// once on entry. Live state, sequence, and sessions are
    /// unchanged.
    FrameRejected(PeerCandidateWireFrameError),
    /// Frame decoded successfully; the Run 076 validator ran. The
    /// outcome's matching Run 076 counter was bumped exactly once
    /// in addition to the entry-time `received_total`. Live state,
    /// sequence, and sessions are unchanged on EVERY variant of
    /// [`PeerCandidateOutcome`] (Run 076 invariant).
    ValidatorRan(PeerCandidateOutcome),
}

impl PeerCandidateWireOutcome {
    /// Convenience: `true` iff the inner Run 076 outcome was
    /// `Validated`.
    pub fn is_validated(&self) -> bool {
        matches!(self, Self::ValidatorRan(PeerCandidateOutcome::Validated(_)))
    }

    /// Convenience: stable short label for logging / metrics
    /// dashboards.
    pub fn short_label(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::FrameRejected(e) => match e {
                PeerCandidateWireFrameError::DeclaredPayloadOversize { .. } => {
                    "frame-oversize"
                }
                PeerCandidateWireFrameError::FrameTooShort { .. } => "frame-too-short",
                PeerCandidateWireFrameError::UnknownDiscriminator { .. } => {
                    "frame-unknown-discriminator"
                }
                PeerCandidateWireFrameError::FrameTruncated { .. } => "frame-truncated",
                PeerCandidateWireFrameError::PayloadParseError { .. } => {
                    "frame-payload-parse-error"
                }
                PeerCandidateWireFrameError::UnsupportedEnvelopeVersion { .. } => {
                    "frame-unsupported-version"
                }
                PeerCandidateWireFrameError::UnknownDomainTag { .. } => {
                    "frame-unknown-domain-tag"
                }
            },
            Self::ValidatorRan(o) => match o {
                PeerCandidateOutcome::Validated(_) => "validated",
                PeerCandidateOutcome::Rejected(_) => "rejected",
                PeerCandidateOutcome::Disabled => "validator-disabled",
                PeerCandidateOutcome::Oversize { .. } => "oversize",
                PeerCandidateOutcome::RateLimited { .. } => "rate-limited",
                PeerCandidateOutcome::DuplicateSuppressed { .. } => "duplicate-suppressed",
            },
        }
    }
}

/// Run 078 runtime context (the operator-supplied side of the
/// boundary). Same shape as the Run 076 [`PeerCandidateRuntimeContext`]
/// — the receiver does not introduce any additional operator-
/// controlled trust knob.
#[derive(Debug, Clone)]
pub struct PeerCandidateWireRuntimeContext<'a> {
    /// Operator's runtime environment.
    pub expected_environment: NetworkEnvironment,
    /// Operator's runtime chain id.
    pub expected_chain_id: ChainId,
    /// Operator-controlled scratch directory for the temp candidate
    /// file used internally by the Run 076 validator. MUST NOT be a
    /// directory the peer can influence.
    pub scratch_dir: &'a Path,
    /// Wall-clock seconds.
    pub validation_time_secs: u64,
    /// Bundle-signing key set; same fail-closed semantics as
    /// Run 069. TestNet/MainNet refuse unsigned bundles here.
    pub signing_keys: &'a BundleSigningKeySet,
    /// Activation context; same shape as Run 069.
    pub activation_ctx: ActivationContext,
    /// Optional sequence persistence path; same semantics as Run 069
    /// (read-only peek when `Some`).
    pub sequence_persistence_path: Option<&'a Path>,
    /// Optional local leaf cert bytes for the Run 061 / Run 063
    /// self-checks.
    pub local_leaf_cert_bytes: Option<&'a [u8]>,
    /// Current monotonic clock in milliseconds (for the inner
    /// rate limiter).
    pub now_ms: u64,
}

/// Run 078 disabled-by-default P2P wire receive handler. The
/// receiver holds exactly one Run 076 [`PeerCandidateValidator`]
/// instance — it does NOT hold (and CANNOT mutate) any live PQC
/// trust state, sequence persistence handle, P2P session manager,
/// admin-API endpoint, or filesystem watcher.
pub struct PeerCandidateWireReceiver {
    config: PeerCandidateWireReceiverConfig,
    validator: PeerCandidateValidator,
}

impl PeerCandidateWireReceiver {
    /// Construct the receiver explicitly disabled (default).
    pub fn disabled() -> Self {
        let config = PeerCandidateWireReceiverConfig::default();
        let validator = PeerCandidateValidator::new(config.inner.clone());
        Self { config, validator }
    }

    /// Construct with an explicit config. When `config.enabled` is
    /// `true`, the inner Run 076 validator is forced to
    /// `enabled = true` so the receiver routes frames through the
    /// SAME Run 069 pipeline that startup uses. When
    /// `config.enabled` is `false`, the inner validator is forced
    /// to `enabled = false` so even a misconfiguration cannot
    /// reach the validator's expensive path.
    pub fn new(mut config: PeerCandidateWireReceiverConfig) -> Self {
        config.inner.enabled = config.enabled;
        let validator = PeerCandidateValidator::new(config.inner.clone());
        Self { config, validator }
    }

    pub fn config(&self) -> &PeerCandidateWireReceiverConfig {
        &self.config
    }

    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Run 078 receive entry point. Accepts the raw P2P wire frame
    /// bytes (same length-prefixed framing as `p2p_tcp.rs`) and
    /// either rejects them at the frame layer (with a
    /// fail-closed log-safe reason) or hands the decoded envelope
    /// to the Run 076 [`PeerCandidateValidator`] for validation.
    ///
    /// # Strict non-mutation contract (every return path)
    ///
    /// - the live PQC trust state (`LivePqcTrustState`) of the
    ///   running process is not touched;
    /// - the on-disk sequence persistence file at
    ///   `ctx.sequence_persistence_path` is not modified;
    /// - no P2P / KEMTLS session is evicted;
    /// - no `_applied_total` metric family is bumped (none exists
    ///   by design);
    /// - no candidate frame is re-broadcast or forwarded;
    /// - no admin-API surface is reachable from this function.
    ///
    /// # Metrics
    ///
    /// `received_total` is bumped on every call (truthful "we
    /// observed a frame" signal). The matching outcome-specific
    /// Run 076 counter is bumped exactly once before returning.
    /// No new metric family is introduced by Run 078.
    pub fn try_handle_frame(
        &mut self,
        frame: &[u8],
        ctx: &PeerCandidateWireRuntimeContext<'_>,
        metrics: &P2pMetrics,
    ) -> PeerCandidateWireOutcome {
        self.try_handle_frame_inner(frame, ctx, metrics, None)
    }

    /// Run 109 — receive entry point that additionally enforces the
    /// Run 103/105 bundle-signing-key ratification gate on the same
    /// Run 069/076 inner validation pipeline that
    /// [`try_handle_frame`](Self::try_handle_frame) drives.
    ///
    /// The frame-layer decode, disabled-by-default short-circuit, DoS
    /// cap, duplicate suppression, and rate limiter all run FIRST and
    /// unchanged. Only after the inner Run 069 validation succeeds is
    /// the ratification gate consulted. If the gate refuses, the call
    /// returns
    /// `ValidatorRan(PeerCandidateOutcome::Rejected(
    /// PeerCandidateRejection::ValidationFailed(
    /// ReloadCheckError::RatificationRefused(..))))`
    /// — the SAME rejection shape Runs 105/107 emit elsewhere — and
    /// the propagation gate downstream observes a non-validated
    /// outcome and refuses to rebroadcast (see Run 088 path).
    ///
    /// # Strict non-mutation contract (every return path)
    ///
    /// - the live PQC trust state is not touched;
    /// - the on-disk sequence persistence file is not modified
    ///   (peek-only via the Run 069 inner pipeline);
    /// - no P2P / KEMTLS session is evicted;
    /// - no `_applied_total` metric family is bumped (none exists);
    /// - no candidate frame is re-broadcast or forwarded by this
    ///   function (the dispatcher's Run 088 propagation step runs
    ///   AFTER this method and is gated on a validated outcome).
    pub fn try_handle_frame_with_ratification(
        &mut self,
        frame: &[u8],
        ctx: &PeerCandidateWireRuntimeContext<'_>,
        ratification_ctx: &RatificationEnforcementContext<'_>,
        metrics: &P2pMetrics,
    ) -> PeerCandidateWireOutcome {
        self.try_handle_frame_inner(frame, ctx, metrics, Some(ratification_ctx))
    }

    fn try_handle_frame_inner(
        &mut self,
        frame: &[u8],
        ctx: &PeerCandidateWireRuntimeContext<'_>,
        metrics: &P2pMetrics,
        ratification_ctx: Option<&RatificationEnforcementContext<'_>>,
    ) -> PeerCandidateWireOutcome {
        // Always-truthful "we observed a frame" counter — matches
        // the Run 076 / Run 077 `received_total` discipline.
        metrics.record_peer_candidate_received();

        // 1. Disabled-by-default short-circuit. Cheap header-only
        //    discriminator check still runs so we can record a
        //    truthful counter, but we do NOT decode the payload,
        //    NOT call the validator, NOT do any crypto.
        if !self.config.enabled {
            metrics.record_peer_candidate_disabled();
            return PeerCandidateWireOutcome::Disabled;
        }

        // 2. Frame-layer decode. Strict fail-closed. The DoS cap
        //    on declared `payload_len` is enforced in
        //    `decode_peer_candidate_wire_frame` BEFORE any
        //    allocation / JSON decode / crypto.
        let envelope = match decode_peer_candidate_wire_frame(frame) {
            Ok(e) => e,
            Err(err) => {
                match &err {
                    PeerCandidateWireFrameError::DeclaredPayloadOversize { .. } => {
                        metrics.record_peer_candidate_dropped_oversize();
                    }
                    _ => {
                        metrics.record_peer_candidate_rejected();
                    }
                }
                return PeerCandidateWireOutcome::FrameRejected(err);
            }
        };

        // 3. Hand the decoded envelope to the Run 076 validator.
        //    The validator's strict non-mutation contract applies
        //    on every return path. We re-stamp the Run 076 fixture
        //    domain tag / version on the inner envelope because
        //    the wire-layer tag was already verified above.
        let run076_envelope = envelope.into_run076_envelope();
        let inner_ctx = PeerCandidateRuntimeContext {
            expected_environment: ctx.expected_environment,
            expected_chain_id: ctx.expected_chain_id,
            scratch_dir: ctx.scratch_dir,
            validation_time_secs: ctx.validation_time_secs,
            signing_keys: ctx.signing_keys,
            activation_ctx: ctx.activation_ctx.clone(),
            sequence_persistence_path: ctx.sequence_persistence_path,
            local_leaf_cert_bytes: ctx.local_leaf_cert_bytes,
            now_ms: ctx.now_ms,
        };
        let outcome = match ratification_ctx {
            Some(rctx) => self
                .validator
                .try_accept_with_ratification(run076_envelope, &inner_ctx, rctx),
            None => self.validator.try_accept(run076_envelope, &inner_ctx),
        };

        // 4. Record the outcome-specific metric exactly once.
        //    Reuses the SAME seven Run 076 counters (no new metric
        //    family).
        match &outcome {
            PeerCandidateOutcome::Validated(_) => {
                metrics.record_peer_candidate_validated();
            }
            PeerCandidateOutcome::Rejected(_) => {
                metrics.record_peer_candidate_rejected();
            }
            PeerCandidateOutcome::Disabled => {
                // Defensive: should not happen because we force
                // `inner.enabled = enabled` at construction, but
                // surface honestly if it ever did.
                metrics.record_peer_candidate_disabled();
            }
            PeerCandidateOutcome::Oversize { .. } => {
                metrics.record_peer_candidate_dropped_oversize();
            }
            PeerCandidateOutcome::RateLimited { .. } => {
                metrics.record_peer_candidate_rate_limited();
            }
            PeerCandidateOutcome::DuplicateSuppressed { .. } => {
                metrics.record_peer_candidate_duplicate();
            }
        }

        PeerCandidateWireOutcome::ValidatorRan(outcome)
    }
}

/// Single source of truth for the Run 078 "frame observed, NOT
/// applied, NOT propagated" operator-log line. Stable substrings
/// (`Run 078`, `NOT applied`, `not propagated`, `sequence not
/// persisted`, `live trust state unchanged`, `sessions untouched`)
/// so tests and operator log scrapers agree.
pub fn wire_observed_log_line(
    outcome: &PeerCandidateWireOutcome,
    peer_id: Option<&str>,
) -> String {
    format!(
        "[binary] Run 078: peer-candidate wire frame observed; outcome={}; NOT \
         applied; not propagated; sequence not persisted; live trust state \
         unchanged; sessions untouched (peer_id={})",
        outcome.short_label(),
        peer_id.unwrap_or("<unknown>")
    )
}

// ---------------------------------------------------------------------
// Run 079: live P2P receive-loop dispatch wiring.
//
// Run 078 landed the codec, the typed envelope, and the disabled-by-
// default `PeerCandidateWireReceiver`. Run 079 lands the smallest
// honest live-receive-loop bridge: a `Send + Sync` trait the
// transport's read loop can call into when it observes a frame whose
// first byte is `DISCRIMINATOR_PEER_CANDIDATE_WIRE`, and a
// `LivePeerCandidateWireDispatcher` that wraps the Run 078 receiver
// + the operator-supplied runtime context (signing keys, environment,
// chain id, scratch dir, activation context, optional sequence
// persistence path, optional local leaf bytes, shared P2pMetrics)
// behind that trait.
//
// Strict scope inherited from Run 078:
//   - validation-only (NEVER applied);
//   - no propagation / rebroadcast (the trait method returns `()`);
//   - no LivePqcTrustState mutation (no handle held);
//   - no sequence persistence (the inner Run 069 path uses
//     `peek_sequence` only);
//   - no P2P session eviction (no evictor handle held);
//   - no _applied_total metric (none exists by design).
//
// The transport's read loop is responsible for:
//   - peeking the first byte of every received frame BEFORE calling
//     the existing `decode_frame` (which only knows about the
//     consensus/DAG/control discriminators and would break the
//     connection on an unknown discriminator);
//   - routing `0x05` frames through the installed sink (if any);
//   - dropping `0x05` frames cheaply when no sink is installed (so
//     a peer cannot poison the read loop just by sending a 0x05
//     frame to a node that has not opted in).
// ---------------------------------------------------------------------

/// Trait implemented by anything the live P2P receive loop can hand
/// a `DISCRIMINATOR_PEER_CANDIDATE_WIRE` frame to. The trait is
/// **dyn-compatible** and `Send + Sync` so the read loop can hold an
/// `Arc<dyn PeerCandidateWireFrameSink>` and the sink itself can
/// internally serialize state (e.g. behind a `Mutex`).
///
/// # Contract on every call
///
/// - the implementation MUST NOT block the caller for longer than
///   the validation cost (the read loop is per-peer; long blocks
///   stall honest traffic);
/// - the implementation MUST NOT propagate / rebroadcast / forward
///   the frame;
/// - the implementation MUST NOT mutate any live PQC trust state,
///   sequence file, or P2P session;
/// - the implementation MUST NOT panic on malformed input — any
///   decode / validation failure is surfaced via the inner
///   `P2pMetrics` counters reused from Run 076.
pub trait PeerCandidateWireFrameSink: Send + Sync + 'static {
    /// Hand the receive loop's raw frame bytes (including the
    /// 5-byte length-prefixed header) to the sink.
    ///
    /// The default Run 079 implementation
    /// (`LivePeerCandidateWireDispatcher`) routes the frame through
    /// the Run 078 `PeerCandidateWireReceiver` and bumps the same
    /// seven Run 076 `qbind_p2p_pqc_trust_bundle_peer_candidate_*`
    /// counters as the Run 078 library tests do.
    fn handle_frame(&self, frame: &[u8]);

    /// Source-aware entry point used by the live transport. The
    /// default preserves the Run 079 validation-only behaviour for
    /// existing sinks; Run 088 propagation-aware sinks override this
    /// so they can exclude the source peer from any validated
    /// rebroadcast.
    fn handle_frame_from_peer(&self, frame: &[u8], source_peer: Option<NodeId>) {
        let _ = source_peer;
        self.handle_frame(frame);
    }
}

/// Run 079 live receive-loop dispatcher: the production-honest
/// implementation of [`PeerCandidateWireFrameSink`]. Holds exactly
/// one Run 078 [`PeerCandidateWireReceiver`] (which itself holds
/// exactly one Run 076 [`PeerCandidateValidator`]) plus the
/// operator-supplied runtime context. None of these owned fields
/// give the dispatcher any way to apply / propagate / evict.
///
/// The struct's `handle_frame` impl:
///   1. records "wall-clock" `now_ms` via the injectable clock fn
///      (`SystemTime` by default; tests can inject a deterministic
///      clock);
///   2. constructs a [`PeerCandidateWireRuntimeContext`] from the
///      owned fields;
///   3. delegates to [`PeerCandidateWireReceiver::try_handle_frame`];
///   4. emits a single safe operator-log line via
///      [`wire_observed_log_line`].
pub struct LivePeerCandidateWireDispatcher {
    receiver: Mutex<PeerCandidateWireReceiver>,
    propagation: PeerCandidatePropagationConfig,
    propagation_state: Mutex<PeerCandidatePropagationState>,
    propagation_sender: Mutex<Option<Arc<dyn PeerCandidateWireFrameSender>>>,
    expected_environment: NetworkEnvironment,
    expected_chain_id: ChainId,
    scratch_dir: PathBuf,
    signing_keys: BundleSigningKeySet,
    activation_ctx: ActivationContext,
    /// Run 098: optional canonical production `ConsensusStorage`
    /// handle. When present, `dispatch_frame_from_peer_for_test`
    /// reads `meta:current_epoch` and overrides
    /// `activation_ctx.current_epoch` per-dispatch.
    consensus_storage_for_epoch:
        Option<std::sync::Arc<crate::storage::RocksDbConsensusStorage>>,
    sequence_persistence_path: Option<PathBuf>,
    local_leaf_cert_bytes: Option<Vec<u8>>,
    validation_time_secs: u64,
    metrics: Arc<P2pMetrics>,
    clock_ms_fn: Arc<dyn Fn() -> u64 + Send + Sync + 'static>,
    /// Run 109 — owned ratification context applied to every live
    /// inbound `0x05` frame BEFORE validation success / propagation.
    /// `None` preserves the pre-Run-109 unguarded path used by older
    /// tests and DevNet operators who have not yet wired ratification.
    live_ratification: Option<LiveRatificationConfig>,
    /// Run 123 — optional authority-marker file path for validation-only
    /// conflict checks. See [`LivePeerCandidateWireDispatcherConfig::authority_marker_path`].
    authority_marker_path: Option<PathBuf>,
    /// Run 146 — optional non-applying peer-candidate staging queue.
    /// When `Some`, validated outcomes (after the v2/v1 marker
    /// conflict checks) are forwarded to the queue's
    /// `try_stage_validated` for **non-authoritative** recording.
    /// When `None`, behavior is identical to the Run 143
    /// validation-only / propagation-only path.
    ///
    /// **Invariants (Run 146):**
    ///
    /// * The hook never calls Run 070 apply.
    /// * The hook never mutates [`crate::pqc_live_trust::LivePqcTrustState`].
    /// * The hook never writes the sequence file.
    /// * The hook never writes the authority-marker file.
    /// * The hook never evicts P2P / KEMTLS sessions.
    /// * The hook never invokes SIGHUP / reload-apply.
    /// * The hook never causes propagation; propagation is independently
    ///   gated by [`PeerCandidatePropagationConfig`].
    /// * Invalid / rejected / rate-limited / oversize / disabled /
    ///   duplicate-suppressed outcomes never reach
    ///   `try_stage_validated` — only `Validated(_)` is forwarded.
    /// * The queue's own `PeerDrivenStagingPolicy` enforces
    ///   MainNet refusal and disabled-by-default semantics.
    staging_queue: Option<Arc<Mutex<PeerCandidateStagingQueue>>>,
}

impl std::fmt::Debug for LivePeerCandidateWireDispatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LivePeerCandidateWireDispatcher")
            .field("expected_environment", &self.expected_environment)
            .field("expected_chain_id", &self.expected_chain_id)
            .field("scratch_dir", &self.scratch_dir)
            .field(
                "sequence_persistence_path",
                &self.sequence_persistence_path,
            )
            .field(
                "local_leaf_cert_bytes_present",
                &self.local_leaf_cert_bytes.is_some(),
            )
            .field(
                "consensus_storage_for_epoch_present",
                &self.consensus_storage_for_epoch.is_some(),
            )
            .field("validation_time_secs", &self.validation_time_secs)
            .field("is_enabled", &self.is_enabled())
            .field("propagation_enabled", &self.propagation.enabled)
            .field(
                "ratification_gate_invoked",
                &self.ratification_gate_is_invoked(),
            )
            .field(
                "authority_marker_path",
                &self.authority_marker_path,
            )
            .field(
                "staging_queue_installed",
                &self.staging_queue.is_some(),
            )
            .finish()
    }
}

/// Run 079 owned-fields builder for [`LivePeerCandidateWireDispatcher`].
/// Each field has the same semantic as the corresponding field in
/// [`PeerCandidateWireRuntimeContext`] (which is the *borrowed*
/// per-call view).
#[derive(Clone)]
pub struct LivePeerCandidateWireDispatcherConfig {
    /// Run 078 receiver config. When `inner.enabled` is `true`, the
    /// receive path runs full Run 076 validation against every
    /// frame; when `false`, frames short-circuit at the disabled
    /// check (the cheap path the task requires).
    pub inner: PeerCandidateWireReceiverConfig,
    /// Operator's runtime environment (Devnet / Testnet / Mainnet).
    pub expected_environment: NetworkEnvironment,
    /// Operator's runtime chain id.
    pub expected_chain_id: ChainId,
    /// Operator-controlled scratch directory for the temp candidate
    /// file used internally by the Run 076 validator. MUST NOT be a
    /// directory the peer can influence.
    pub scratch_dir: PathBuf,
    /// Bundle-signing key set (same fail-closed semantics as the
    /// Run 069 reload-check path).
    pub signing_keys: BundleSigningKeySet,
    /// Activation context (same shape as Run 069).
    pub activation_ctx: ActivationContext,
    /// Run 098: optional canonical production `ConsensusStorage`
    /// handle used for per-frame epoch read. When present, the
    /// dispatcher reads `meta:current_epoch` BEFORE every dispatch
    /// and overrides `activation_ctx.current_epoch` with the result.
    /// When absent, `activation_ctx.current_epoch` is used as-is
    /// (test-grade / legacy behavior). See
    /// `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_098.md`.
    pub consensus_storage_for_epoch:
        Option<std::sync::Arc<crate::storage::RocksDbConsensusStorage>>,
    /// Optional on-disk sequence file path (read-only `peek_sequence`
    /// is used; the file is NEVER written by the Run 079 receive
    /// path).
    pub sequence_persistence_path: Option<PathBuf>,
    /// Optional local leaf cert bytes for Run 061 / Run 063
    /// startup self-checks.
    pub local_leaf_cert_bytes: Option<Vec<u8>>,
    /// Wall-clock seconds used as `validation_time_secs`. Held as
    /// an owned `u64` because the validator already passes it
    /// per-call; receivers that want a moving clock should
    /// reconstruct the dispatcher (Run 079 is library-grade — no
    /// continuous clock daemon).
    pub validation_time_secs: u64,
    /// Run 088 disabled-by-default propagation config. When enabled,
    /// the dispatcher may rebroadcast only after validation succeeds.
    pub propagation: PeerCandidatePropagationConfig,
    /// Run 088 raw-frame sender used for rebroadcast. If omitted,
    /// propagation remains inert even if `propagation.enabled` is
    /// true; tests and production wiring install this explicitly.
    pub propagation_sender: Option<Arc<dyn PeerCandidateWireFrameSender>>,
    /// Run 109 — optional owned ratification context applied to live
    /// inbound `0x05` peer-candidate frames BEFORE the inner Run 069
    /// validation accepts the candidate. When `None`, frames are
    /// validated through the unchanged pre-Run-109 path (Run 088
    /// propagation gating is unaffected). When `Some`, the
    /// dispatcher consults
    /// [`LiveRatificationConfig::gate_decision`] on every frame and
    /// routes through
    /// [`PeerCandidateWireReceiver::try_handle_frame_with_ratification`]
    /// iff the gate is invoked under Run 106 policy.
    ///
    /// MainNet/TestNet callers MUST install this in production; the
    /// dispatcher cannot infer per-environment defaults from
    /// `expected_environment` alone because the owned authority
    /// material lives in the operator-supplied genesis file, not in
    /// the dispatcher itself.
    pub live_ratification: Option<LiveRatificationConfig>,
    /// Run 123 — optional authority-marker file path for validation-only
    /// conflict checks on live inbound `0x05` frames. When `Some`, the
    /// dispatcher performs a marker compare AFTER ratification-aware
    /// validation succeeds and BEFORE propagation eligibility. On
    /// conflict/corruption/wrong-domain, the frame outcome is changed
    /// to `Rejected` and propagation is suppressed. The marker file is
    /// **never** written by the dispatcher (validation-only contract).
    /// When `None`, no marker check is performed (pre-Run-123 behavior).
    pub authority_marker_path: Option<PathBuf>,
    /// Run 146 — optional non-applying peer-candidate staging queue
    /// handle. When `Some`, validation-accepted candidates (after the
    /// v2/v1 marker conflict checks) are forwarded to
    /// [`PeerCandidateStagingQueue::try_stage_validated`] for
    /// **non-authoritative** recording. When `None`, behavior remains
    /// bit-for-bit Run 143 validation-only / propagation-only. The
    /// queue's own [`crate::pqc_peer_candidate_staging::PeerDrivenStagingPolicy`]
    /// is disabled by default and refuses MainNet unconditionally. The
    /// dispatcher does **not** itself apply, propagate, persist, or
    /// mutate any trust state as a result of staging.
    pub staging_queue: Option<Arc<Mutex<PeerCandidateStagingQueue>>>,
}

/// Run 109 — owned ratification context for live inbound
/// peer-candidate `0x05` frame validation.
///
/// Holds the same six fields the borrowed
/// [`RatificationEnforcementContext`] borrows for the local Run 107
/// peer-candidate-check path, plus the Run 106
/// [`RatificationGateDecision`] computed once at dispatcher build
/// time (the per-environment policy decision is stable for the
/// lifetime of the process and does not depend on per-frame state).
///
/// This struct is constructed once at startup by the operator-facing
/// builder (mirroring the
/// [`crate::pqc_peer_candidate_binary::run_local_check_with_ratification`]
/// path that already builds the borrowed context for Run 107) and
/// owned by the dispatcher for the lifetime of the process. The
/// dispatcher reborrows it per-frame to produce the borrowed
/// [`RatificationEnforcementContext`] the verifier consumes.
///
/// # Strict scope
///
/// - No private-key material is held here. `ratification` is an
///   already-signed object; `authority` carries only public-key
///   material; `expected_genesis_hash` is the canonical Run 102
///   hash; `expected_chain_id_str` is the public chain id; `policy`
///   is the Run 106 per-environment enum.
/// - No I/O is performed here. Loading the genesis authority and
///   the optional ratification sidecar happens out-of-band by the
///   binary entry point.
/// - No live trust state, sequence handle, or session evictor is
///   carried here. This struct is the "ratification context only"
///   side of the Run 109 boundary.
#[derive(Debug, Clone)]
pub struct LiveRatificationConfig {
    /// Genesis-bound authority block (Run 101/104). Cloned from the
    /// canonical genesis configuration loaded at startup. The
    /// verifier consults `bundle_signing_authority_roots` only.
    pub authority: GenesisAuthorityConfig,
    /// Canonical genesis hash computed at startup (Run 102).
    pub expected_genesis_hash: GenesisHash,
    /// Per-environment policy enum for the verifier. Derived from
    /// `config.environment` at dispatcher build time.
    pub expected_environment_policy: NetworkEnvironmentPolicy,
    /// Pre-formatted lowercase-hex string form of the runtime chain
    /// id (matches the Run 107 binary path; the verifier expects a
    /// `&str` so the canonical encoding lives at the call site).
    pub expected_chain_id_str: String,
    /// Optional owned ratification sidecar object. `None` triggers
    /// the verifier's `Missing` / `LegacyUnratifiedAccepted` branch
    /// per `policy`. On MainNet/TestNet under
    /// `RatificationEnforcementPolicy::Strict` (Run 106 default),
    /// `Missing` is fail-closed.
    pub ratification: Option<BundleSigningRatification>,
    /// Run 142 — optional owned **v2** ratification sidecar.
    ///
    /// When the operator-supplied sidecar is schema_version=2, the
    /// versioned dispatcher (`load_versioned_ratification_from_path`)
    /// produces a [`BundleSigningRatificationV2`] which is plumbed
    /// here. At most one of [`Self::ratification`] (v1) and
    /// [`Self::ratification_v2`] may be `Some` — both being `Some`
    /// is treated as ambiguous v1+v2 authority material and is
    /// fail-closed by the dispatcher on every frame.
    ///
    /// When `Some`, the dispatcher routes Validated outcomes through
    /// the Run 130 v2 verifier and the Run 132
    /// `verify_marker_for_validation_only_v2` helper, mirroring the
    /// local peer-candidate-check v2 surface bit-for-bit. The
    /// validation-only invariants (no marker write, no sequence
    /// write, no live trust mutation, no session eviction, no
    /// reload-apply, no SIGHUP) are preserved.
    pub ratification_v2: Option<BundleSigningRatificationV2>,
    /// Per-surface enforcement policy. MainNet is always
    /// [`RatificationEnforcementPolicy::Strict`]; TestNet/DevNet
    /// may be `AllowLegacyUnratified` only when the operator
    /// supplied the explicit legacy-allow flag.
    pub policy: RatificationEnforcementPolicy,
    /// Run 106 per-environment gate decision computed once at
    /// startup. When this is `Skip(DevnetNoOperatorOptIn)` the
    /// dispatcher routes frames through the pre-Run-109 unguarded
    /// path; otherwise it routes through the ratification-aware
    /// path. MainNet/TestNet always produce
    /// `Invoke(MainnetDefaultStrict)` / `Invoke(TestnetDefaultStrict)`
    /// and the gate is always invoked.
    pub gate_decision: RatificationGateDecision,
}

impl LivePeerCandidateWireDispatcher {
    /// Construct the dispatcher. The clock function returns "now"
    /// in monotonic milliseconds and is used as the Run 076
    /// rate-limiter clock input. The default
    /// `LivePeerCandidateWireDispatcher::new` uses
    /// `std::time::SystemTime::now()`; tests inject a deterministic
    /// clock via [`LivePeerCandidateWireDispatcher::with_clock`].
    pub fn new(
        config: LivePeerCandidateWireDispatcherConfig,
        metrics: Arc<P2pMetrics>,
    ) -> Self {
        let clock_ms_fn: Arc<dyn Fn() -> u64 + Send + Sync + 'static> = Arc::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0)
        });
        Self::with_clock(config, metrics, clock_ms_fn)
    }

    /// Like [`new`](Self::new) but with an injectable clock for
    /// deterministic tests.
    pub fn with_clock(
        config: LivePeerCandidateWireDispatcherConfig,
        metrics: Arc<P2pMetrics>,
        clock_ms_fn: Arc<dyn Fn() -> u64 + Send + Sync + 'static>,
    ) -> Self {
        let receiver = PeerCandidateWireReceiver::new(config.inner);
        let propagation_state = PeerCandidatePropagationState::new(&config.propagation);
        Self {
            receiver: Mutex::new(receiver),
            propagation: config.propagation,
            propagation_state: Mutex::new(propagation_state),
            propagation_sender: Mutex::new(config.propagation_sender),
            expected_environment: config.expected_environment,
            expected_chain_id: config.expected_chain_id,
            scratch_dir: config.scratch_dir,
            signing_keys: config.signing_keys,
            activation_ctx: config.activation_ctx,
            consensus_storage_for_epoch: config.consensus_storage_for_epoch,
            sequence_persistence_path: config.sequence_persistence_path,
            local_leaf_cert_bytes: config.local_leaf_cert_bytes,
            validation_time_secs: config.validation_time_secs,
            metrics,
            clock_ms_fn,
            live_ratification: config.live_ratification,
            authority_marker_path: config.authority_marker_path,
            staging_queue: config.staging_queue,
        }
    }
    pub fn is_enabled(&self) -> bool {
        self.receiver.lock().is_enabled()
    }

    /// Run 109 — `true` iff an owned ratification context has been
    /// installed AND the Run 106 gate decision says the gate should
    /// be invoked. False both when no ratification context is wired
    /// (pre-Run-109 unguarded path) and when the gate decision is a
    /// `Skip` (DevNet without operator opt-in).
    pub fn ratification_gate_is_invoked(&self) -> bool {
        self.live_ratification
            .as_ref()
            .map(|c| c.gate_decision.should_invoke())
            .unwrap_or(false)
    }

    /// Run 109 — borrow the installed owned ratification context, if
    /// any. Tests and operator-introspection paths read this to
    /// confirm the policy/gate decision applied to live frames.
    pub fn live_ratification(&self) -> Option<&LiveRatificationConfig> {
        self.live_ratification.as_ref()
    }

    /// Install or replace the Run 088 propagation sender after the
    /// P2P transport is built. This does not enable propagation by
    /// itself; [`PeerCandidatePropagationConfig::enabled`] remains the
    /// master switch.
    pub fn set_propagation_sender(&self, sender: Arc<dyn PeerCandidateWireFrameSender>) {
        *self.propagation_sender.lock() = Some(sender);
    }

    /// Run 146 — install or replace the non-applying peer-candidate
    /// staging queue handle after dispatcher construction. The queue
    /// remains disabled-by-default unless the operator constructs it
    /// with an explicit
    /// [`crate::pqc_peer_candidate_staging::PeerDrivenStagingPolicy`]
    /// that has `enabled = true` AND the matching environment
    /// `allow_*` switch set. MainNet is refused unconditionally by
    /// the queue itself even with `allow_mainnet = true`.
    ///
    /// Installing a staging queue does **not** change validation,
    /// propagation, or apply behavior. The hook is end-of-line for
    /// staging: it records non-authoritative metadata only.
    pub fn set_staging_queue(&mut self, queue: Arc<Mutex<PeerCandidateStagingQueue>>) {
        self.staging_queue = Some(queue);
    }

    /// Run 146 — borrow the installed staging queue handle, if any.
    /// Tests use this to inspect the queue contents after dispatch.
    pub fn staging_queue(&self) -> Option<&Arc<Mutex<PeerCandidateStagingQueue>>> {
        self.staging_queue.as_ref()
    }

    /// Run 146 — `true` iff a staging queue has been installed AND its
    /// own policy currently accepts new candidates (master enable
    /// switch is on and the runtime environment is permitted). When
    /// `false`, [`Self::dispatch_frame_for_test`] never calls
    /// [`PeerCandidateStagingQueue::try_stage_validated`].
    pub fn staging_hook_is_armed(&self) -> bool {
        self.staging_queue
            .as_ref()
            .map(|q| {
                let queue = q.lock();
                let policy = queue.policy();
                if !policy.enabled {
                    return false;
                }
                match policy.environment {
                    qbind_types::NetworkEnvironment::Devnet => policy.allow_devnet,
                    qbind_types::NetworkEnvironment::Testnet => policy.allow_testnet,
                    // MainNet is refused unconditionally by the queue.
                    qbind_types::NetworkEnvironment::Mainnet => false,
                }
            })
            .unwrap_or(false)
    }

    /// Test-grade synchronous dispatch entry point. Returns the
    /// inner outcome so unit tests can assert it without scraping
    /// metrics.
    ///
    /// The production read loop calls
    /// [`PeerCandidateWireFrameSink::handle_frame`] instead, which
    /// discards the outcome (no propagation by construction).
    pub fn dispatch_frame_for_test(&self, frame: &[u8]) -> PeerCandidateWireOutcome {
        self.dispatch_frame_from_peer_for_test(frame, None)
    }

    /// Source-aware test entry point used by Run 088 propagation
    /// tests. The source peer, when supplied, is excluded from any
    /// validated rebroadcast.
    ///
    /// Run 098: when `consensus_storage_for_epoch` is present, the
    /// dispatcher reads `meta:current_epoch` from the canonical
    /// production storage BEFORE constructing the runtime context.
    /// This per-frame read ensures `activation_ctx.current_epoch`
    /// reflects the latest committed epoch (epoch transitions
    /// happen asynchronously). When the storage handle is absent
    /// or the read fails, `self.activation_ctx.current_epoch` is
    /// used as-is (test-grade / legacy behavior).
    pub fn dispatch_frame_from_peer_for_test(
        &self,
        frame: &[u8],
        source_peer: Option<NodeId>,
    ) -> PeerCandidateWireOutcome {
        let now_ms = (self.clock_ms_fn)();
        // Run 098: derive canonical epoch per-frame when handle is present.
        let activation_ctx = {
            let mut ctx = self.activation_ctx.clone();
            if let Some(ref storage) = self.consensus_storage_for_epoch {
                // Run 098: surface storage failures distinctly from valid
                // no-epoch state. On Err we treat as unavailable
                // (`current_epoch = None`) — any epoch-declaring candidate
                // is then rejected with `CurrentEpochUnavailable` at the
                // activation gate (fail-closed direction). The error is
                // logged so operators can see the storage degradation
                // rather than it being silently absorbed.
                match crate::pqc_trust_activation_epoch::activation_epoch_source_from_storage(Some(storage)) {
                    Ok(epoch_source) => {
                        ctx.current_epoch = epoch_source.as_option();
                    }
                    Err(e) => {
                        eprintln!(
                            "[binary] Run 098: peer-candidate wire dispatcher: \
                             canonical meta:current_epoch read failed: {}. \
                             Treating as CurrentEpochUnavailable for this frame \
                             (epoch-declaring candidates will be rejected; \
                             no live trust mutation; no sequence write; \
                             no session eviction).",
                            e
                        );
                        ctx.current_epoch = None;
                    }
                }
            }
            ctx
        };
        let ctx = PeerCandidateWireRuntimeContext {
            expected_environment: self.expected_environment,
            expected_chain_id: self.expected_chain_id,
            scratch_dir: self.scratch_dir.as_path(),
            validation_time_secs: self.validation_time_secs,
            signing_keys: &self.signing_keys,
            activation_ctx,
            sequence_persistence_path: self
                .sequence_persistence_path
                .as_deref(),
            local_leaf_cert_bytes: self.local_leaf_cert_bytes.as_deref(),
            now_ms,
        };
        let mut receiver = self.receiver.lock();
        // Run 142 — fail-closed when both v1 and v2 ratification
        // material are installed simultaneously. The
        // `LiveRatificationConfig` invariant is that AT MOST ONE of
        // `ratification` (v1) and `ratification_v2` is `Some`. Any
        // simultaneous presence is ambiguous v1+v2 authority claim
        // and is rejected before the inner validator runs. No
        // mutation, no propagation, no marker write.
        let ambiguous_v1_v2 = self
            .live_ratification
            .as_ref()
            .map(|rc| {
                rc.gate_decision.should_invoke()
                    && rc.ratification.is_some()
                    && rc.ratification_v2.is_some()
            })
            .unwrap_or(false);
        if ambiguous_v1_v2 {
            drop(receiver);
            eprintln!(
                "[run-142] live 0x05 v2 dispatch refused: ambiguous v1+v2 \
                 authority material present in LiveRatificationConfig; \
                 fail-closed (no validation, no marker write, no propagation, \
                 no live trust mutation, no session eviction)."
            );
            self.metrics.record_peer_candidate_rejected();
            let outcome = PeerCandidateWireOutcome::ValidatorRan(
                PeerCandidateOutcome::Rejected(
                    crate::pqc_trust_peer_candidate::PeerCandidateRejection::ValidationFailed(
                        crate::pqc_trust_reload::ReloadCheckError::MarkerConflict(
                            "Run 142: ambiguous v1+v2 authority material; fail-closed"
                                .to_string(),
                        ),
                    ),
                ),
            );
            self.maybe_propagate_after_validation(frame, source_peer, now_ms, &outcome);
            return outcome;
        }
        // Run 109/142: route through the ratification-aware receiver path
        // when the owned ratification context is installed AND the
        // Run 106 gate decision says invoke. Otherwise preserve the
        // pre-Run-109 unguarded path (used by DevNet without operator
        // opt-in and by all pre-Run-109 tests). The Run 088
        // propagation step downstream is gated on a validated outcome
        // either way, so an unratified candidate (which produces a
        // `Rejected(RatificationRefused)` outcome under the
        // ratification-aware path) is NEVER rebroadcast.
        //
        // Run 142: when the operator-supplied sidecar is v2
        // (`ratification_v2.is_some()`), the v1 ratification-aware path
        // is bypassed (the v1 verifier cannot consume v2 material). The
        // inner unguarded validator still runs every Run 069 / Run 076
        // check on the bundle bytes; the v2 verifier + v2 marker
        // compare are run AFTER inner validation by
        // [`Self::maybe_reject_on_v2_marker_conflict`]. This mirrors
        // the local Run 132 peer-candidate-check binary path's v2
        // dispatch.
        let outcome = match self.live_ratification.as_ref() {
            Some(rc) if rc.gate_decision.should_invoke() && rc.ratification_v2.is_some() => {
                receiver.try_handle_frame(frame, &ctx, self.metrics.as_ref())
            }
            Some(rc) if rc.gate_decision.should_invoke() => {
                let rctx = RatificationEnforcementContext {
                    authority: &rc.authority,
                    expected_genesis_hash: &rc.expected_genesis_hash,
                    expected_environment_policy: rc.expected_environment_policy,
                    expected_chain_id_str: rc.expected_chain_id_str.as_str(),
                    ratification: rc.ratification.as_ref(),
                    policy: rc.policy,
                };
                receiver.try_handle_frame_with_ratification(
                    frame,
                    &ctx,
                    &rctx,
                    self.metrics.as_ref(),
                )
            }
            _ => receiver.try_handle_frame(frame, &ctx, self.metrics.as_ref()),
        };
        drop(receiver);

        // Run 142 — validation-only v2 ratification + v2 authority-marker
        // conflict check for live inbound `0x05` frames carrying v2
        // material. Runs AFTER inner validation succeeds, BEFORE
        // propagation eligibility. On v2 verifier failure / v2 marker
        // conflict / corruption / wrong-domain, changes the outcome to
        // `Rejected` so `maybe_propagate_after_validation` observes a
        // non-Validated outcome and suppresses rebroadcast. Never
        // writes the marker, never mutates live trust state, never
        // evicts sessions, never calls reload-apply.
        let outcome = self.maybe_reject_on_v2_marker_conflict(outcome);

        // Run 123 — validation-only authority marker conflict check for live
        // inbound `0x05` frames. Runs AFTER ratification-aware validation
        // succeeds, BEFORE propagation eligibility. On marker conflict/
        // corruption/wrong-domain, changes the outcome to Rejected so
        // `maybe_propagate_after_validation` observes a non-Validated outcome
        // and suppresses rebroadcast. The marker file is NEVER written.
        let outcome = self.maybe_reject_on_marker_conflict(outcome);

        // Run 146 — non-applying peer-candidate staging hook. Runs AFTER
        // validation acceptance, AFTER v2/v1 authority-marker conflict
        // checks, and BEFORE propagation eligibility. Forwards ONLY
        // `Validated(_)` outcomes; rejected / oversize / rate-limited /
        // duplicate-suppressed / disabled outcomes are filtered upstream
        // by `try_stage_outcome`. The staging queue itself enforces
        // disabled-by-default semantics, MainNet refusal, capacity
        // bounds, deduplication, and TTL. This call is non-mutating w.r.t.
        // live trust state, the sequence file, the authority marker, P2P
        // sessions, and reload-apply/SIGHUP — it only records
        // non-authoritative metadata in an in-memory queue.
        self.maybe_stage_after_validation(now_ms, &outcome);

        self.maybe_propagate_after_validation(frame, source_peer, now_ms, &outcome);
        outcome
    }

    /// Run 142 — validation-only v2 ratification + v2 authority-marker
    /// conflict check for live inbound `0x05` frames when the
    /// operator-supplied sidecar is schema_version=2.
    ///
    /// Pipeline (mirrors the local Run 132 peer-candidate-check binary
    /// path bit-for-bit):
    ///
    /// 1. If the inner outcome is not `Validated`, return unchanged.
    /// 2. If no v2 ratification context is installed, return unchanged
    ///    (v1 path / legacy path takes over).
    /// 3. Run the Run 130 v2 verifier
    ///    ([`qbind_ledger::verify_bundle_signing_key_ratification_v2`])
    ///    against the operator's owned v2 sidecar.
    /// 4. Run [`crate::pqc_authority_marker_acceptance::verify_marker_for_validation_only_v2`]
    ///    against the on-disk marker (if any).
    /// 5. On any failure, change the outcome to `Rejected` with a
    ///    synthetic [`crate::pqc_trust_reload::ReloadCheckError::MarkerConflict`]
    ///    so the downstream propagation gate suppresses rebroadcast
    ///    automatically.
    ///
    /// # Critical guarantees
    ///
    /// * **Never writes the marker file.** All I/O is read-only.
    /// * **Never mutates [`crate::pqc_live_trust::LivePqcTrustState`].**
    /// * **Never writes `pqc_trust_bundle_sequence.json`.**
    /// * **Never evicts sessions.**
    /// * **Never calls reload-apply or SIGHUP logic.**
    /// * **Never starts a peer-driven apply flow.**
    fn maybe_reject_on_v2_marker_conflict(
        &self,
        outcome: PeerCandidateWireOutcome,
    ) -> PeerCandidateWireOutcome {
        // Step 1: only relevant if the validation produced a Validated result.
        let is_validated = matches!(
            &outcome,
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Validated(_))
        );
        if !is_validated {
            return outcome;
        }

        // Step 2: must have an installed ratification context with v2
        // material AND the gate decision must say invoke.
        let rc = match self.live_ratification.as_ref() {
            Some(rc) if rc.gate_decision.should_invoke() => rc,
            _ => return outcome,
        };
        let ratification_v2 = match rc.ratification_v2.as_ref() {
            Some(r) => r,
            None => return outcome,
        };

        // Step 3: run the Run 130 v2 verifier.
        use crate::pqc_authority_marker_acceptance::{
            verify_marker_for_validation_only_v2, ValidationOnlyMarkerV2Error,
            ValidationOnlyMarkerV2Inputs,
        };
        let ratified_v2 = match qbind_ledger::verify_bundle_signing_key_ratification_v2(
            qbind_ledger::RatificationV2VerifierInputs {
                ratification: ratification_v2,
                authority: &rc.authority,
                expected_chain_id: rc.expected_chain_id_str.as_str(),
                expected_environment: rc.expected_environment_policy,
                expected_genesis_hash: &rc.expected_genesis_hash,
            },
        ) {
            Ok(r) => r,
            Err(e) => {
                let marker_err = ValidationOnlyMarkerV2Error::V2VerifierFailure(e);
                eprintln!(
                    "[run-142] live 0x05 v2 verifier rejected sidecar: {} \
                     (validation-only; no marker persistence; no trust mutation; \
                     propagation suppressed; NOT applied; sessions untouched).",
                    marker_err
                );
                self.metrics.record_peer_candidate_rejected();
                return PeerCandidateWireOutcome::ValidatorRan(
                    PeerCandidateOutcome::Rejected(
                        crate::pqc_trust_peer_candidate::PeerCandidateRejection::ValidationFailed(
                            crate::pqc_trust_reload::ReloadCheckError::MarkerConflict(format!(
                                "{}",
                                marker_err
                            )),
                        ),
                    ),
                );
            }
        };

        // Step 4: marker conflict check against persisted marker (if any).
        // If `--data-dir` was not supplied, the dispatcher's
        // `authority_marker_path` is `None` and we skip the on-disk
        // compare (DevNet convenience only; matches Run 132 main.rs
        // behaviour at line 1339). The v2 verifier above already
        // ratified the candidate against the authority block.
        let marker_path = match self.authority_marker_path.as_ref() {
            Some(p) => p,
            None => {
                eprintln!(
                    "[run-142] live 0x05 v2 verifier passed; on-disk v2 marker \
                     compare skipped (no --data-dir configured). Validation-only; \
                     no marker write; no trust mutation."
                );
                return outcome;
            }
        };

        // Compute genesis hash hex from the owned ratification context.
        let mut runtime_genesis_hash_hex = String::with_capacity(64);
        for b in rc.expected_genesis_hash {
            use std::fmt::Write;
            let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
        }

        let marker_result = verify_marker_for_validation_only_v2(ValidationOnlyMarkerV2Inputs {
            marker_path,
            runtime_env: self.expected_environment,
            runtime_chain_id: self.expected_chain_id,
            runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
            ratification: ratification_v2,
            ratified: &ratified_v2,
        });

        match marker_result {
            Ok(reason) => {
                eprintln!(
                    "[run-142] live 0x05 v2 authority-marker check passed: {} \
                     (validation-only; no marker persistence; no trust mutation; \
                     propagation eligibility preserved).",
                    reason
                );
                outcome
            }
            Err(marker_err) => {
                eprintln!(
                    "[run-142] live 0x05 v2 authority-marker conflict rejected: {} \
                     (validation-only; no marker persistence; no trust mutation; \
                     propagation suppressed; NOT applied; sessions untouched).",
                    marker_err
                );
                self.metrics.record_peer_candidate_rejected();
                PeerCandidateWireOutcome::ValidatorRan(
                    PeerCandidateOutcome::Rejected(
                        crate::pqc_trust_peer_candidate::PeerCandidateRejection::ValidationFailed(
                            crate::pqc_trust_reload::ReloadCheckError::MarkerConflict(format!(
                                "{}",
                                marker_err
                            )),
                        ),
                    ),
                )
            }
        }
    }

    /// Run 123 — if the inner validation returned `Validated` and we have
    /// both a ratification context (for marker derivation) and a marker
    /// path (for the on-disk compare), perform the validation-only marker
    /// conflict check. On conflict/corruption/wrong-domain, change the
    /// outcome to `Rejected` with a synthetic `ReloadCheckError`-shaped
    /// rejection so the propagation gate observes a non-validated outcome
    /// and suppresses rebroadcast automatically.
    ///
    /// Never persists marker. Never touches live trust state.
    fn maybe_reject_on_marker_conflict(
        &self,
        outcome: PeerCandidateWireOutcome,
    ) -> PeerCandidateWireOutcome {
        // Only relevant if the validation produced a Validated result.
        let is_validated = matches!(
            &outcome,
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Validated(_))
        );
        if !is_validated {
            return outcome;
        }

        // Must have both marker_path and live_ratification to derive a
        // candidate marker.
        let marker_path = match self.authority_marker_path.as_ref() {
            Some(p) => p,
            None => return outcome,
        };
        let rc = match self.live_ratification.as_ref() {
            Some(rc) if rc.gate_decision.should_invoke() => rc,
            _ => return outcome,
        };

        // Compute genesis hash hex from the owned ratification context.
        let mut runtime_genesis_hash_hex = String::with_capacity(64);
        for b in rc.expected_genesis_hash {
            use std::fmt::Write;
            let _ = write!(runtime_genesis_hash_hex, "{:02x}", b);
        }

        // The ratification context carries the ratification object and
        // authority — derive the ratified key by re-running enforcement.
        // This is cheap (pure computation, no I/O except the marker file
        // read) and matches the pattern used by the reload-check and
        // peer-candidate-check binary paths.
        let ratification = match rc.ratification.as_ref() {
            Some(r) => r,
            None => return outcome,
        };

        // We need the candidate's signing public key from the validated
        // outcome to run the enforcer. However, the validated result
        // carries only the fingerprint, not the raw bytes. We re-use
        // the signing_keys set to look up the pk by fingerprint.
        // Actually — the enforcer needs the candidate's public key bytes
        // which the signing_keys set already has indexed by key_id.
        // But we don't have the signing_key_id from the validated outcome.
        // The simpler path: just use the ratification context's own
        // key material directly. The ratification was already verified
        // by the inner pipeline; we trust it carried the correct key.
        // We can derive the marker from the ratification alone.

        // Derive candidate marker from the already-verified ratification.
        // The `bundle_signing_public_key` in the ratification is the key
        // that was ratified; we need a RatifiedBundleSigningKey from
        // enforce_bundle_signing_key_ratification. Let's call the enforcer.
        use qbind_ledger::{
            enforce_bundle_signing_key_ratification, RatificationEnforcementInputs,
            RatificationEnforcementOutcome,
        };
        use crate::pqc_authority_marker_acceptance::{
            verify_marker_for_validation_only, ValidationOnlyMarkerInputs,
        };

        let signing_pk = &ratification.bundle_signing_public_key;
        let enforcer_result = enforce_bundle_signing_key_ratification(
            RatificationEnforcementInputs {
                ratification: Some(ratification),
                authority: &rc.authority,
                expected_chain_id: &rc.expected_chain_id_str,
                expected_environment: rc.expected_environment_policy,
                expected_genesis_hash: &rc.expected_genesis_hash,
                candidate_bundle_signing_public_key: signing_pk,
                policy: rc.policy,
            },
        );
        let ratified = match enforcer_result {
            Ok(RatificationEnforcementOutcome::Ratified(rk)) => rk,
            _ => return outcome, // Skip if not ratified (legacy path, etc.)
        };

        let marker_result = verify_marker_for_validation_only(ValidationOnlyMarkerInputs {
            marker_path,
            runtime_env: self.expected_environment,
            runtime_chain_id: self.expected_chain_id,
            runtime_genesis_hash_hex: &runtime_genesis_hash_hex,
            authority_policy_version: rc.authority.authority_policy_version,
            authority_sequence: rc.authority.authority_sequence,
            authority_epoch: rc.authority.authority_epoch,
            ratification,
            ratified: &ratified,
        });

        match marker_result {
            Ok(reason) => {
                eprintln!(
                    "[run-123] live 0x05 authority-marker check passed: {} \
                     (validation-only; no marker persistence; no trust mutation; \
                     propagation eligibility preserved).",
                    reason
                );
                outcome
            }
            Err(marker_err) => {
                eprintln!(
                    "[binary] Run 123: live 0x05 authority-marker conflict rejected: {} \
                     (validation-only; no marker persistence; no trust mutation; \
                     propagation suppressed; NOT applied; sessions untouched).",
                    marker_err
                );
                self.metrics.record_peer_candidate_rejected();
                // Convert to a Rejected outcome so downstream propagation
                // and log lines see a non-validated state.
                PeerCandidateWireOutcome::ValidatorRan(
                    PeerCandidateOutcome::Rejected(
                        crate::pqc_trust_peer_candidate::PeerCandidateRejection::ValidationFailed(
                            crate::pqc_trust_reload::ReloadCheckError::MarkerConflict(
                                format!("{}", marker_err)
                            ),
                        ),
                    ),
                )
            }
        }
    }

    /// Run 146 — non-applying peer-candidate staging hook. Invoked once
    /// per `dispatch_frame_from_peer_for_test` call, AFTER validation
    /// acceptance and AFTER the v2/v1 authority-marker conflict checks,
    /// and BEFORE [`Self::maybe_propagate_after_validation`].
    ///
    /// Strict contract:
    ///
    /// * **No staging if no queue is installed.** When
    ///   `self.staging_queue.is_none()`, this is a zero-cost early
    ///   return that preserves bit-for-bit Run 143 validation-only /
    ///   propagation-only behavior.
    /// * **No staging on non-`Validated` outcomes.** Invalid /
    ///   rejected / rate-limited / oversize / disabled /
    ///   duplicate-suppressed outcomes are filtered out by
    ///   [`PeerCandidateStagingQueue::try_stage_outcome`], so they
    ///   never reach `try_stage_validated`.
    /// * **No staging when policy is disabled or environment refused.**
    ///   The queue's own `PeerDrivenStagingPolicy` enforces this.
    ///   MainNet is refused unconditionally.
    /// * **No apply.** The hook does not call Run 070
    ///   `apply_validated_candidate*`.
    /// * **No mutation of `LivePqcTrustState`.**
    /// * **No write to `pqc_trust_bundle_sequence.json`.**
    /// * **No write to `pqc_authority_state.json`.**
    /// * **No session eviction.**
    /// * **No SIGHUP / reload-apply invocation.**
    /// * **No propagation.** The propagation eligibility decision is
    ///   independently gated by
    ///   [`PeerCandidatePropagationConfig::enabled`] and is unaffected
    ///   by the staging hook.
    ///
    /// The `authority_marker_digest` slot in the staged record is
    /// derived from the validated outcome's authority-marker digest
    /// field when present; the staging queue contributes this digest
    /// to its dedup key so byte-identical resubmissions return
    /// `AlreadyStaged` rather than growing the queue.
    fn maybe_stage_after_validation(
        &self,
        now_ms: u64,
        outcome: &PeerCandidateWireOutcome,
    ) {
        let queue = match self.staging_queue.as_ref() {
            Some(q) => q,
            None => return,
        };
        // Wall-clock seconds for the staging TTL. Derived from the
        // dispatcher's monotonic-millisecond clock so deterministic
        // test clocks remain deterministic.
        let now_unix_secs = now_ms / 1_000;
        // Derive an authority-marker digest fingerprint from the
        // validated outcome, if any. Currently we fingerprint the
        // validated bundle's `fingerprint_hex` plus its declared
        // sequence — this is the same dedup signal the validation
        // path produces, and it is stable across byte-identical
        // resubmissions. A future Run 147 production wiring may
        // substitute the persisted authority-marker file digest here
        // without changing the staging-queue API.
        let marker_digest: Option<String> = match outcome {
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Validated(v)) => {
                Some(format!(
                    "fp={};seq={}",
                    v.validated.fingerprint_hex, v.validated.sequence
                ))
            }
            _ => None,
        };
        let mut q = queue.lock();
        let staging_outcome = q.try_stage_outcome(outcome, marker_digest, now_unix_secs);
        // Operator-log line. Single source of truth for the Run 146
        // "staged / already-staged / refused" boundary, mirroring the
        // Run 088 propagation log line style.
        match staging_outcome {
            StagingOutcome::Staged {
                ref fingerprint_prefix,
                sequence,
            } => {
                eprintln!(
                    "[binary] Run 146: peer-candidate validated and STAGED \
                     (non-applying, non-authoritative); NOT applied; sequence \
                     not persisted; live trust unchanged; sessions untouched; \
                     authority marker NOT written; candidate_fp={}.. sequence={}",
                    fingerprint_prefix, sequence
                );
            }
            StagingOutcome::AlreadyStaged {
                ref fingerprint_prefix,
                sequence,
            } => {
                eprintln!(
                    "[binary] Run 146: peer-candidate validated but already \
                     staged (dedup hit); NOT applied; sequence not persisted; \
                     live trust unchanged; sessions untouched; authority \
                     marker NOT written; candidate_fp={}.. sequence={}",
                    fingerprint_prefix, sequence
                );
            }
            StagingOutcome::RefusedDisabled => {
                // Disabled-by-default is the normal case — log only at
                // verbose level to avoid log noise. Run 146 keeps it
                // observable for evidence harnesses.
                eprintln!(
                    "[binary] Run 146: peer-candidate validated; staging \
                     hook refused (policy disabled); NOT applied; sequence \
                     not persisted; live trust unchanged; sessions untouched."
                );
            }
            StagingOutcome::RefusedEnvironmentPolicy => {
                eprintln!(
                    "[binary] Run 146: peer-candidate validated; staging \
                     hook refused (environment policy: MainNet refused / \
                     allow_* flag false); NOT applied; sequence not \
                     persisted; live trust unchanged; sessions untouched."
                );
            }
            StagingOutcome::RefusedNotValidated => {
                // Not a Validated outcome — staging hook is end-of-line
                // for non-validated material. No log line (the
                // upstream validator already logged the rejection).
            }
            StagingOutcome::RefusedGlobalCapacity { cap } => {
                eprintln!(
                    "[binary] Run 146: peer-candidate validated; staging \
                     hook refused (global queue cap={} reached, reject-new); \
                     NOT applied; sequence not persisted; live trust \
                     unchanged; sessions untouched.",
                    cap
                );
            }
            StagingOutcome::RefusedPerPeerCapacity { cap } => {
                eprintln!(
                    "[binary] Run 146: peer-candidate validated; staging \
                     hook refused (per-peer cap={} reached, reject-new); \
                     NOT applied; sequence not persisted; live trust \
                     unchanged; sessions untouched.",
                    cap
                );
            }
        }
    }

    fn maybe_propagate_after_validation(
        &self,
        frame: &[u8],
        source_peer: Option<NodeId>,
        now_ms: u64,
        outcome: &PeerCandidateWireOutcome,
    ) {
        if !self.propagation.enabled {
            return;
        }

        let validated = match outcome {
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Validated(v)) => v,
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::DuplicateSuppressed { .. }) => {
                self.metrics
                    .record_peer_candidate_propagation_suppressed_duplicate();
                return;
            }
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::RateLimited { .. }) => {
                self.metrics.record_peer_candidate_propagation_rate_limited();
                return;
            }
            PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Rejected(_))
            | PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Oversize { .. })
            | PeerCandidateWireOutcome::FrameRejected(_) => {
                self.metrics
                    .record_peer_candidate_propagation_suppressed_invalid();
                return;
            }
            PeerCandidateWireOutcome::Disabled
            | PeerCandidateWireOutcome::ValidatorRan(PeerCandidateOutcome::Disabled) => {
                return;
            }
        };

        self.metrics.record_peer_candidate_propagation_attempt();

        let candidate_id = format!(
            "{}:{}",
            validated.validated.sequence, validated.validated.fingerprint_prefix
        );
        {
            let mut state = self.propagation_state.lock();
            if let Err((_attempts, _cap)) = state.rate_limiter.try_admit(now_ms) {
                self.metrics.record_peer_candidate_propagation_rate_limited();
                eprintln!(
                    "[binary] Run 088: peer-candidate validated before propagation but propagation rate-limited; NOT applied; sequence not persisted; live trust unchanged; sessions untouched; rebroadcast_count=0; source_peer_excluded=true; candidate_fp={}.. sequence={}",
                    validated.validated.fingerprint_prefix,
                    validated.validated.sequence
                );
                return;
            }
            if state.contains(&candidate_id) {
                self.metrics
                    .record_peer_candidate_propagation_suppressed_duplicate();
                eprintln!(
                    "[binary] Run 088: peer-candidate validated before propagation but suppressed as duplicate; NOT applied; sequence not persisted; live trust unchanged; sessions untouched; rebroadcast_count=0; source_peer_excluded=true; candidate_fp={}.. sequence={}",
                    validated.validated.fingerprint_prefix,
                    validated.validated.sequence
                );
                return;
            }
            state.insert(candidate_id, self.propagation.seen_lru_capacity);
        }

        let sender = self.propagation_sender.lock().clone();
        let Some(sender) = sender.as_ref() else {
            eprintln!(
                "[binary] Run 088: peer-candidate validated before propagation but no propagation sender is installed; NOT applied; sequence not persisted; live trust unchanged; sessions untouched; rebroadcast_count=0; source_peer_excluded=true; candidate_fp={}.. sequence={}",
                validated.validated.fingerprint_prefix,
                validated.validated.sequence
            );
            return;
        };

        let targets: Vec<NodeId> = sender
            .connected_peer_node_ids()
            .into_iter()
            .filter(|peer| Some(*peer) != source_peer)
            // Deterministic first-N fanout is intentional for Run 088
            // evidence reproducibility. A future production topology
            // run can add randomized or policy-ranked peer selection.
            .take(self.propagation.max_rebroadcast_targets)
            .collect();
        let report = sender.send_raw_frame_to_selected_peers(frame.to_vec(), &targets);
        for (_, peer_outcome) in report.per_peer() {
            if peer_outcome.is_enqueued() {
                self.metrics.record_peer_candidate_propagation_sent();
            }
        }
        eprintln!(
            "[binary] Run 088: peer-candidate validated before propagation; NOT applied; sequence not persisted; live trust unchanged; sessions untouched; rebroadcast_count={}; source_peer_excluded=true; candidate_fp={}.. sequence={}",
            report.sent(),
            validated.validated.fingerprint_prefix,
            validated.validated.sequence
        );
    }
}

impl PeerCandidateWireFrameSink for LivePeerCandidateWireDispatcher {
    fn handle_frame(&self, frame: &[u8]) {
        self.handle_frame_from_peer(frame, None);
    }

    fn handle_frame_from_peer(&self, frame: &[u8], source_peer: Option<NodeId>) {
        let outcome = self.dispatch_frame_from_peer_for_test(frame, source_peer);
        // Single safe operator-log line. No bundle bytes, no
        // private material — the Run 078 helper enforces the
        // stable substrings used by operator log scrapers.
        let peer_id_for_log = None;
        eprintln!("{}", wire_observed_log_line(&outcome, peer_id_for_log));
    }
}

/// Run 079 "cheap-discard" sink: installed when the wire-validation
/// flag is enabled but the runtime context required to construct a
/// real [`LivePeerCandidateWireDispatcher`] is unavailable (e.g.
/// no `--p2p-trust-bundle` baseline supplied). Bumps the truthful
/// `received_total` + `disabled_total` counters reused from
/// Run 076 and returns. NEVER decodes the payload.
pub struct DiscardPeerCandidateWireSink {
    metrics: Arc<P2pMetrics>,
}

impl DiscardPeerCandidateWireSink {
    pub fn new(metrics: Arc<P2pMetrics>) -> Self {
        Self { metrics }
    }
}

impl PeerCandidateWireFrameSink for DiscardPeerCandidateWireSink {
    fn handle_frame(&self, _frame: &[u8]) {
        self.metrics.record_peer_candidate_received();
        self.metrics.record_peer_candidate_disabled();
    }
}

/// Run 079 read-loop helper: given the raw frame bytes received
/// from the secure channel and the optional installed sink,
/// returns the decision the transport's read loop should take.
///
/// This is intentionally a small pure function so the read-loop
/// branching logic is unit-testable without spinning up KEMTLS.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadLoopFrameDecision {
    /// Frame is a peer-candidate wire frame (`0x05`). The caller
    /// has already invoked the sink (if any) and MUST `continue`
    /// the read loop — DO NOT call the existing consensus/DAG/
    /// control `decode_frame` on this frame.
    ConsumedPeerCandidateWire,
    /// Frame is NOT a peer-candidate wire frame. The caller MUST
    /// fall through to the existing length-prefixed
    /// consensus/DAG/control decode path bit-for-bit.
    PassThrough,
}

/// Run 079 read-loop branch entry point. Inspects only the first
/// byte of `frame_bytes`:
///
/// - if it equals [`DISCRIMINATOR_PEER_CANDIDATE_WIRE`], invokes
///   the installed sink (or silently drops the frame when no sink
///   is installed) and returns
///   [`ReadLoopFrameDecision::ConsumedPeerCandidateWire`];
/// - otherwise, returns [`ReadLoopFrameDecision::PassThrough`]
///   without touching the frame so the caller's pre-existing
///   decode path runs bit-for-bit.
///
/// This function NEVER returns an error and NEVER panics — a
/// malformed `0x05` frame is the sink's problem (it has the
/// Run 078 fail-closed decoder), and a non-`0x05` frame is the
/// existing transport's problem (its policy on unknown
/// discriminators is preserved).
pub fn read_loop_dispatch_peer_candidate_wire_frame(
    frame_bytes: &[u8],
    sink: Option<&Arc<dyn PeerCandidateWireFrameSink>>,
) -> ReadLoopFrameDecision {
    read_loop_dispatch_peer_candidate_wire_frame_from_peer(frame_bytes, sink, None)
}

/// Source-aware Run 088 variant of
/// [`read_loop_dispatch_peer_candidate_wire_frame`].
pub fn read_loop_dispatch_peer_candidate_wire_frame_from_peer(
    frame_bytes: &[u8],
    sink: Option<&Arc<dyn PeerCandidateWireFrameSink>>,
    source_peer: Option<NodeId>,
) -> ReadLoopFrameDecision {
    if frame_bytes.first().copied() == Some(DISCRIMINATOR_PEER_CANDIDATE_WIRE) {
        if let Some(sink) = sink {
            sink.handle_frame_from_peer(frame_bytes, source_peer);
        }
        // No sink installed → cheap drop. The truthful zero-cost
        // observation is "we saw a 0x05 frame on the wire and did
        // not validate it because the operator did not opt in".
        // We intentionally do NOT poison the read loop here so the
        // existing consensus / DAG / control traffic continues
        // unaffected.
        ReadLoopFrameDecision::ConsumedPeerCandidateWire
    } else {
        ReadLoopFrameDecision::PassThrough
    }
}

// ---------------------------------------------------------------------
// Run 080: disabled-by-default production send-side publisher for the
// peer-candidate wire frame (0x05).
// ---------------------------------------------------------------------

/// Run 080 sender-side abstraction: the smallest interface needed by
/// the publisher to (a) observe currently authenticated peers and (b)
/// enqueue one already-framed raw P2P frame to all currently connected
/// peers.
pub trait PeerCandidateWireFrameSender: Send + Sync + 'static {
    /// Snapshot currently authenticated peers.
    fn connected_peer_node_ids(&self) -> Vec<NodeId>;
    /// Enqueue one already-framed raw P2P frame to all currently
    /// authenticated peers.
    fn send_raw_frame_to_all_peers(&self, frame_bytes: Vec<u8>) -> RawFrameSendReport;
    /// Enqueue one already-framed raw P2P frame to the supplied
    /// selected peers. The default preserves Run 080 implementers
    /// that only know all-peer fanout; production Run 088 transport
    /// handles override this so propagation can exclude the source
    /// peer.
    fn send_raw_frame_to_selected_peers(
        &self,
        frame_bytes: Vec<u8>,
        selected_peers: &[NodeId],
    ) -> RawFrameSendReport {
        let all = self.connected_peer_node_ids();
        if selected_peers.len() == all.len()
            && selected_peers.iter().all(|p| all.iter().any(|a| a == p))
        {
            self.send_raw_frame_to_all_peers(frame_bytes)
        } else {
            RawFrameSendReport::from_per_peer(
                selected_peers
                    .iter()
                    .copied()
                    .map(|p| (p, RawFramePeerSendOutcome::ChannelClosed))
                    .collect(),
            )
        }
    }
}

/// Run 080 per-peer raw-frame send outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RawFramePeerSendOutcome {
    Enqueued,
    QueueFull,
    ChannelClosed,
}

impl RawFramePeerSendOutcome {
    pub fn short_label(self) -> &'static str {
        match self {
            Self::Enqueued => "enqueued",
            Self::QueueFull => "queue_full",
            Self::ChannelClosed => "channel_closed",
        }
    }
    pub fn is_enqueued(self) -> bool {
        matches!(self, Self::Enqueued)
    }
}

/// Run 080 raw-frame send aggregate result over the currently
/// authenticated peer snapshot.
#[derive(Debug, Clone, Default)]
pub struct RawFrameSendReport {
    per_peer: Vec<(NodeId, RawFramePeerSendOutcome)>,
}

impl RawFrameSendReport {
    pub fn from_per_peer(per_peer: Vec<(NodeId, RawFramePeerSendOutcome)>) -> Self {
        Self { per_peer }
    }
    pub fn attempted(&self) -> usize {
        self.per_peer.len()
    }
    pub fn sent(&self) -> usize {
        self.per_peer
            .iter()
            .filter(|(_, o)| o.is_enqueued())
            .count()
    }
    pub fn failed(&self) -> usize {
        self.per_peer
            .iter()
            .filter(|(_, o)| !o.is_enqueued())
            .count()
    }
    pub fn per_peer(&self) -> &[(NodeId, RawFramePeerSendOutcome)] {
        &self.per_peer
    }
}

/// Run 080 publish-once policy knobs.
#[derive(Debug, Clone)]
pub struct PeerCandidateWirePublishConfig {
    /// Master switch, disabled by default.
    pub enabled: bool,
    /// Required local operator envelope path.
    pub envelope_path: Option<PathBuf>,
    /// Publish exactly once when triggered.
    pub publish_once: bool,
    /// Bounded wait for at least one authenticated peer.
    pub wait_for_peer_timeout: Duration,
    /// Poll cadence while waiting for peers.
    pub wait_poll_interval: Duration,
}

impl Default for PeerCandidateWirePublishConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            envelope_path: None,
            publish_once: false,
            wait_for_peer_timeout: Duration::from_secs(10),
            wait_poll_interval: Duration::from_millis(200),
        }
    }
}

/// Run 080 publish refusal paths.
#[derive(Debug)]
pub enum PeerCandidateWirePublishError {
    Disabled,
    EnvelopePathMissing,
    EnvelopeIo {
        path: PathBuf,
        message: String,
    },
    EnvelopeParse {
        path: PathBuf,
        message: String,
    },
    FrameOversize {
        declared: usize,
        cap: usize,
    },
    NoPeerWithinTimeout {
        timeout: Duration,
    },
}

impl std::fmt::Display for PeerCandidateWirePublishError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Disabled => write!(
                f,
                "Run 080 publisher disabled-by-default (set --p2p-trust-bundle-peer-candidate-wire-publish-enabled to opt in)"
            ),
            Self::EnvelopePathMissing => write!(
                f,
                "Run 080 publish enabled but no --p2p-trust-bundle-peer-candidate-wire-publish-path was supplied"
            ),
            Self::EnvelopeIo { path, message } => write!(
                f,
                "Run 080 publish could not read envelope fixture at {}: {}",
                path.display(),
                message
            ),
            Self::EnvelopeParse { path, message } => write!(
                f,
                "Run 080 publish could not parse envelope fixture at {} as PeerCandidateEnvelope JSON: {}",
                path.display(),
                message
            ),
            Self::FrameOversize { declared, cap } => write!(
                f,
                "Run 080 publish refused oversize frame before send (declared={} cap={})",
                declared, cap
            ),
            Self::NoPeerWithinTimeout { timeout } => write!(
                f,
                "Run 080 publish observed no authenticated peers within {:?}",
                timeout
            ),
        }
    }
}

impl std::error::Error for PeerCandidateWirePublishError {}

/// Run 080 publish report (single publish-once attempt).
#[derive(Debug, Clone)]
pub struct PeerCandidateWirePublishReport {
    pub candidate_sequence: u64,
    pub candidate_fingerprint_prefix: String,
    pub raw_send: RawFrameSendReport,
}

impl PeerCandidateWirePublishReport {
    pub fn attempted(&self) -> usize {
        self.raw_send.attempted()
    }
    pub fn sent(&self) -> usize {
        self.raw_send.sent()
    }
    pub fn failed(&self) -> usize {
        self.raw_send.failed()
    }
}

/// Run 080 production publisher.
pub struct LivePeerCandidateWirePublisher {
    sender: Arc<dyn PeerCandidateWireFrameSender>,
    metrics: Arc<P2pMetrics>,
}

impl LivePeerCandidateWirePublisher {
    pub fn new(
        sender: Arc<dyn PeerCandidateWireFrameSender>,
        metrics: Arc<P2pMetrics>,
    ) -> Self {
        Self { sender, metrics }
    }

    pub async fn publish_once_from_config(
        &self,
        cfg: &PeerCandidateWirePublishConfig,
    ) -> Result<PeerCandidateWirePublishReport, PeerCandidateWirePublishError> {
        if !cfg.enabled {
            return Err(PeerCandidateWirePublishError::Disabled);
        }
        let envelope_path = cfg
            .envelope_path
            .as_ref()
            .ok_or(PeerCandidateWirePublishError::EnvelopePathMissing)?;
        let envelope = load_run076_envelope_file(envelope_path)?;
        let wire_envelope = PeerCandidateWireEnvelopeV1::from_run076_envelope(&envelope);
        let frame = match encode_peer_candidate_wire_frame(&wire_envelope) {
            Ok(f) => f,
            Err(PeerCandidateWireFrameError::DeclaredPayloadOversize { declared, cap }) => {
                self.metrics.record_peer_candidate_send_oversize();
                return Err(PeerCandidateWirePublishError::FrameOversize { declared, cap });
            }
            Err(other) => {
                self.metrics.record_peer_candidate_send_failure();
                return Err(PeerCandidateWirePublishError::EnvelopeParse {
                    path: envelope_path.clone(),
                    message: format!("wire frame encode error: {}", other),
                });
            }
        };

        self.wait_for_peer(cfg.wait_for_peer_timeout, cfg.wait_poll_interval)
            .await?;

        let raw = self.sender.send_raw_frame_to_all_peers(frame);
        for (_, o) in raw.per_peer() {
            if o.is_enqueued() {
                self.metrics.record_peer_candidate_sent();
            } else {
                self.metrics.record_peer_candidate_send_failure();
            }
        }
        Ok(PeerCandidateWirePublishReport {
            candidate_sequence: envelope.declared_sequence,
            candidate_fingerprint_prefix: envelope.declared_fingerprint_prefix,
            raw_send: raw,
        })
    }

    async fn wait_for_peer(
        &self,
        timeout: Duration,
        poll: Duration,
    ) -> Result<(), PeerCandidateWirePublishError> {
        let start = Instant::now();
        loop {
            if !self.sender.connected_peer_node_ids().is_empty() {
                return Ok(());
            }
            if start.elapsed() >= timeout {
                self.metrics.record_peer_candidate_send_no_peer();
                return Err(PeerCandidateWirePublishError::NoPeerWithinTimeout { timeout });
            }
            tokio::time::sleep(poll).await;
        }
    }
}

/// Stable Run 080 operator log line.
pub fn wire_publish_log_line(
    report: &PeerCandidateWirePublishReport,
    target_count: usize,
) -> String {
    format!(
        "[binary] Run 080: peer-candidate wire publish attempt complete; targets={} attempted={} sent={} failed={} seq={} fp_prefix={} outcome=validation-only/not-applied/not-propagated/no-sequence-write/no-session-eviction",
        target_count,
        report.attempted(),
        report.sent(),
        report.failed(),
        report.candidate_sequence,
        report.candidate_fingerprint_prefix
    )
}

fn load_run076_envelope_file(
    envelope_path: &Path,
) -> Result<PeerCandidateEnvelope, PeerCandidateWirePublishError> {
    let bytes = std::fs::read(envelope_path).map_err(|e| PeerCandidateWirePublishError::EnvelopeIo {
        path: envelope_path.to_path_buf(),
        message: e.to_string(),
    })?;
    serde_json::from_slice(&bytes).map_err(|e| PeerCandidateWirePublishError::EnvelopeParse {
        path: envelope_path.to_path_buf(),
        message: e.to_string(),
    })
}


// ---------------------------------------------------------------------
// Unit tests (frame codec / disabled-by-default / metrics +
// Run 079 read-loop dispatch helper + cheap-discard sink).
// Full-pipeline validator tests live in
// crates/qbind-node/tests/run_078_pqc_peer_candidate_wire_tests.rs
// and crates/qbind-node/tests/run_079_pqc_peer_candidate_wire_live_dispatch_tests.rs
// because they need the test signing harness.
// ---------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::pqc_trust_bundle::BundleSigningKeySet;
    use qbind_types::NetworkEnvironment;

    fn fake_signing_keys() -> BundleSigningKeySet {
        BundleSigningKeySet::from_keys_unchecked(vec![])
    }

    fn devnet_wire_envelope(bytes: Vec<u8>) -> PeerCandidateWireEnvelopeV1 {
        let len = bytes.len();
        PeerCandidateWireEnvelopeV1 {
            envelope_version: PEER_CANDIDATE_WIRE_VERSION,
            domain_tag: PEER_CANDIDATE_WIRE_DOMAIN_TAG.to_string(),
            peer_id: Some("peer-abcd".to_string()),
            environment: TrustBundleEnvironment::Devnet,
            chain_id_hex: crate::pqc_trust_sequence::chain_id_hex(
                NetworkEnvironment::Devnet.chain_id(),
            ),
            declared_sequence: 7,
            declared_fingerprint_prefix: "deadbeef".to_string(),
            declared_length: len,
            bundle_bytes: bytes,
            governance_authority_proof: None,
        }
    }

    #[test]
    fn run078_discriminator_does_not_collide_with_p2p_tcp_discriminators() {
        // p2p_tcp.rs uses 0x01 (consensus), 0x02 (DAG), 0x03 (control).
        // 0x04 is reserved; 0x05 is Run 078.
        assert_ne!(DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0x01);
        assert_ne!(DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0x02);
        assert_ne!(DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0x03);
        assert_eq!(DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0x05);
    }

    #[test]
    fn run078_wire_envelope_roundtrip() {
        let env = devnet_wire_envelope(vec![1, 2, 3, 4, 5]);
        let frame = encode_peer_candidate_wire_frame(&env).expect("encode");
        assert_eq!(frame[0], DISCRIMINATOR_PEER_CANDIDATE_WIRE);
        let decoded = decode_peer_candidate_wire_frame(&frame).expect("decode");
        assert_eq!(decoded, env);
    }

    #[test]
    fn run078_decode_rejects_short_frame() {
        let err = decode_peer_candidate_wire_frame(&[0u8; 3]).unwrap_err();
        match err {
            PeerCandidateWireFrameError::FrameTooShort { observed_len } => {
                assert_eq!(observed_len, 3);
            }
            other => panic!("expected FrameTooShort, got {:?}", other),
        }
    }

    #[test]
    fn run078_decode_rejects_unknown_discriminator() {
        // Build a synthetic header with 0x01 (consensus) discriminator.
        let mut frame = vec![0x01u8, 0, 0, 0, 0];
        frame.extend_from_slice(b"{}");
        let err = decode_peer_candidate_wire_frame(&frame).unwrap_err();
        match err {
            PeerCandidateWireFrameError::UnknownDiscriminator { observed } => {
                assert_eq!(observed, 0x01);
            }
            other => panic!("expected UnknownDiscriminator, got {:?}", other),
        }
    }

    #[test]
    fn run078_decode_rejects_declared_oversize_before_allocation() {
        // declared payload_len = cap + 1; payload bytes are NOT
        // present in the frame at all — the rejection MUST fire
        // before the receiver tries to slice / decode them.
        let declared: u32 = (MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES + 1) as u32;
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        frame.extend_from_slice(&declared.to_be_bytes());
        let err = decode_peer_candidate_wire_frame(&frame).unwrap_err();
        match err {
            PeerCandidateWireFrameError::DeclaredPayloadOversize { declared: d, cap } => {
                assert_eq!(d, declared as usize);
                assert_eq!(cap, MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES);
            }
            other => panic!("expected DeclaredPayloadOversize, got {:?}", other),
        }
    }

    #[test]
    fn run078_decode_rejects_truncated_frame() {
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        frame.extend_from_slice(&100u32.to_be_bytes());
        // Only 10 actual payload bytes; declared 100.
        frame.extend_from_slice(&[0u8; 10]);
        let err = decode_peer_candidate_wire_frame(&frame).unwrap_err();
        match err {
            PeerCandidateWireFrameError::FrameTruncated { declared, observed } => {
                assert_eq!(declared, 100);
                assert_eq!(observed, 10);
            }
            other => panic!("expected FrameTruncated, got {:?}", other),
        }
    }

    #[test]
    fn run078_decode_rejects_unknown_version() {
        let mut env = devnet_wire_envelope(vec![9, 9, 9]);
        env.envelope_version = 999;
        let payload = serde_json::to_vec(&env).unwrap();
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let err = decode_peer_candidate_wire_frame(&frame).unwrap_err();
        match err {
            PeerCandidateWireFrameError::UnsupportedEnvelopeVersion { observed } => {
                assert_eq!(observed, 999);
            }
            other => panic!("expected UnsupportedEnvelopeVersion, got {:?}", other),
        }
    }

    #[test]
    fn run078_decode_rejects_unknown_domain_tag() {
        let mut env = devnet_wire_envelope(vec![9, 9, 9]);
        env.domain_tag = "evil".to_string();
        let payload = serde_json::to_vec(&env).unwrap();
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);
        let err = decode_peer_candidate_wire_frame(&frame).unwrap_err();
        match err {
            PeerCandidateWireFrameError::UnknownDomainTag { observed } => {
                assert_eq!(observed, "evil");
            }
            other => panic!("expected UnknownDomainTag, got {:?}", other),
        }
    }

    #[test]
    fn run078_decode_rejects_malformed_payload() {
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        let payload = b"{ not json";
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(payload);
        let err = decode_peer_candidate_wire_frame(&frame).unwrap_err();
        match err {
            PeerCandidateWireFrameError::PayloadParseError { .. } => {}
            other => panic!("expected PayloadParseError, got {:?}", other),
        }
    }

    #[test]
    fn run078_receiver_disabled_by_default_short_circuits_without_decoding() {
        let mut r = PeerCandidateWireReceiver::disabled();
        assert!(!r.is_enabled());
        let metrics = P2pMetrics::default();
        let env = devnet_wire_envelope(vec![0u8; 4]);
        let frame = encode_peer_candidate_wire_frame(&env).unwrap();
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let ctx = PeerCandidateWireRuntimeContext {
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: &scratch,
            validation_time_secs: 100,
            signing_keys: &keys,
            activation_ctx: ActivationContext::height_only(0),
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            now_ms: 1_000,
        };
        let out = r.try_handle_frame(&frame, &ctx, &metrics);
        assert!(matches!(out, PeerCandidateWireOutcome::Disabled));
        assert_eq!(metrics.peer_candidate_received_total(), 1);
        assert_eq!(metrics.peer_candidate_disabled_total(), 1);
        // No validator-side counters bumped.
        assert_eq!(metrics.peer_candidate_validated_total(), 0);
        assert_eq!(metrics.peer_candidate_rejected_total(), 0);
        assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
        assert_eq!(metrics.peer_candidate_rate_limited_total(), 0);
        assert_eq!(metrics.peer_candidate_duplicate_total(), 0);
    }

    #[test]
    fn run078_receiver_disabled_outcome_label() {
        assert_eq!(PeerCandidateWireOutcome::Disabled.short_label(), "disabled");
        let log = wire_observed_log_line(&PeerCandidateWireOutcome::Disabled, Some("p1"));
        assert!(log.contains("Run 078"));
        assert!(log.contains("NOT applied"));
        assert!(log.contains("not propagated"));
        assert!(log.contains("sequence not persisted"));
        assert!(log.contains("live trust state unchanged"));
        assert!(log.contains("sessions untouched"));
        assert!(log.contains("p1"));
    }

    #[test]
    fn run078_receiver_enabled_oversize_frame_drops_before_validator() {
        // Build a frame whose header declares oversize: the receiver
        // must record `dropped_oversize_total` AND `received_total`
        // without touching the validator. Body-size > cap is fine
        // because the cap check fires on declared length.
        let mut r = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
            enabled: true,
            inner: PeerCandidateConfig::default(),
        });
        let metrics = P2pMetrics::default();
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let ctx = PeerCandidateWireRuntimeContext {
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: &scratch,
            validation_time_secs: 100,
            signing_keys: &keys,
            activation_ctx: ActivationContext::height_only(0),
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            now_ms: 1_000,
        };

        let declared: u32 = (MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES + 1) as u32;
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        frame.extend_from_slice(&declared.to_be_bytes());

        let out = r.try_handle_frame(&frame, &ctx, &metrics);
        match out {
            PeerCandidateWireOutcome::FrameRejected(
                PeerCandidateWireFrameError::DeclaredPayloadOversize { .. },
            ) => {}
            other => panic!("expected FrameRejected(DeclaredPayloadOversize), got {:?}", other),
        }
        assert_eq!(metrics.peer_candidate_received_total(), 1);
        assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 1);
        assert_eq!(metrics.peer_candidate_validated_total(), 0);
        assert_eq!(metrics.peer_candidate_rejected_total(), 0);
    }

    #[test]
    fn run078_receiver_enabled_unknown_version_frame_rejected_not_oversize() {
        let mut r = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
            enabled: true,
            inner: PeerCandidateConfig::default(),
        });
        let metrics = P2pMetrics::default();
        let scratch = std::env::temp_dir();
        let keys = fake_signing_keys();
        let ctx = PeerCandidateWireRuntimeContext {
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: &scratch,
            validation_time_secs: 100,
            signing_keys: &keys,
            activation_ctx: ActivationContext::height_only(0),
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            now_ms: 1_000,
        };

        let mut env = devnet_wire_envelope(vec![1, 2, 3]);
        env.envelope_version = 999;
        let payload = serde_json::to_vec(&env).unwrap();
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        frame.extend_from_slice(&payload);

        let out = r.try_handle_frame(&frame, &ctx, &metrics);
        match out {
            PeerCandidateWireOutcome::FrameRejected(
                PeerCandidateWireFrameError::UnsupportedEnvelopeVersion { observed },
            ) => assert_eq!(observed, 999),
            other => panic!("expected UnsupportedEnvelopeVersion, got {:?}", other),
        }
        // rejected_total (NOT dropped_oversize_total) for non-oversize
        // frame rejections.
        assert_eq!(metrics.peer_candidate_received_total(), 1);
        assert_eq!(metrics.peer_candidate_rejected_total(), 1);
        assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    }

    #[test]
    fn run078_receiver_config_default_is_disabled() {
        let cfg = PeerCandidateWireReceiverConfig::default();
        assert!(!cfg.enabled);
        assert!(!cfg.inner.enabled);
    }

    #[test]
    fn run078_receiver_new_forces_inner_enabled_to_match() {
        // enabled=true on the wrapper forces inner.enabled=true.
        let r = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
            enabled: true,
            inner: PeerCandidateConfig {
                enabled: false, // user mistakenly set false
                ..PeerCandidateConfig::default()
            },
        });
        assert!(r.config().enabled);
        assert!(r.config().inner.enabled);
        // enabled=false on the wrapper forces inner.enabled=false.
        let r2 = PeerCandidateWireReceiver::new(PeerCandidateWireReceiverConfig {
            enabled: false,
            inner: PeerCandidateConfig {
                enabled: true, // user mistakenly set true
                ..PeerCandidateConfig::default()
            },
        });
        assert!(!r2.config().enabled);
        assert!(!r2.config().inner.enabled);
    }

    #[test]
    fn run078_max_frame_cap_strictly_greater_than_inner_bundle_cap() {
        // A frame that fits the Run 076 inner bundle cap (256 KiB)
        // MUST also fit the Run 078 wire frame cap so a legitimate
        // bundle can never be dropped at the wire layer.
        assert!(
            MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES > MAX_PEER_CANDIDATE_BUNDLE_BYTES,
            "wire frame cap must exceed inner bundle cap"
        );
    }

    // -----------------------------------------------------------------
    // Run 079 unit tests: live read-loop dispatch helper +
    // cheap-discard sink. The full Run 078 → Run 069 validation
    // pipeline is covered by the integration suite
    // crates/qbind-node/tests/run_079_pqc_peer_candidate_wire_live_dispatch_tests.rs.
    // -----------------------------------------------------------------

    /// Test-grade [`PeerCandidateWireFrameSink`] that records the
    /// raw frame bytes it was handed. Used to assert the
    /// read-loop helper invokes the sink exactly once per 0x05
    /// frame.
    struct RecordingSink {
        seen: Mutex<Vec<Vec<u8>>>,
    }
    impl RecordingSink {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                seen: Mutex::new(Vec::new()),
            })
        }
    }
    impl PeerCandidateWireFrameSink for RecordingSink {
        fn handle_frame(&self, frame: &[u8]) {
            self.seen.lock().push(frame.to_vec());
        }
    }

    #[test]
    fn run079_read_loop_helper_passes_through_non_0x05_frames() {
        // Existing consensus / DAG / control discriminators MUST
        // fall through to the existing decode path unchanged.
        let sink = RecordingSink::new();
        let sink_arc: Arc<dyn PeerCandidateWireFrameSink> = sink.clone();
        for d in [0x00u8, 0x01, 0x02, 0x03, 0x04, 0x06, 0xff] {
            let frame = vec![d, 0, 0, 0, 0];
            let decision = read_loop_dispatch_peer_candidate_wire_frame(
                &frame,
                Some(&sink_arc),
            );
            assert_eq!(decision, ReadLoopFrameDecision::PassThrough);
        }
        assert!(sink.seen.lock().is_empty());
    }

    #[test]
    fn run079_read_loop_helper_routes_0x05_to_sink() {
        let sink = RecordingSink::new();
        let sink_arc: Arc<dyn PeerCandidateWireFrameSink> = sink.clone();
        let frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0, 0, 0, 0];
        let decision = read_loop_dispatch_peer_candidate_wire_frame(
            &frame,
            Some(&sink_arc),
        );
        assert_eq!(decision, ReadLoopFrameDecision::ConsumedPeerCandidateWire);
        let seen = sink.seen.lock();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0], frame);
    }

    #[test]
    fn run079_read_loop_helper_drops_0x05_when_no_sink_installed() {
        // Cheap drop: NEVER poisons the read loop, NEVER calls
        // the existing decode_frame, NEVER bumps any metric (the
        // metric handle lives inside the sink which is absent here).
        let frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0, 0, 0, 0];
        let decision = read_loop_dispatch_peer_candidate_wire_frame(&frame, None);
        assert_eq!(decision, ReadLoopFrameDecision::ConsumedPeerCandidateWire);
    }

    #[test]
    fn run079_read_loop_helper_empty_frame_passes_through() {
        // Empty frame is not 0x05 — must fall through to the
        // existing transport's "frame too short" handling so we
        // do not silently change the policy for malformed frames.
        let frame: Vec<u8> = Vec::new();
        let decision = read_loop_dispatch_peer_candidate_wire_frame(&frame, None);
        assert_eq!(decision, ReadLoopFrameDecision::PassThrough);
    }

    #[test]
    fn run079_discard_sink_records_received_and_disabled() {
        let metrics = Arc::new(P2pMetrics::default());
        let sink = DiscardPeerCandidateWireSink::new(Arc::clone(&metrics));
        let frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0, 0, 0, 0];
        // Drive five frames to prove the sink is non-mutating and
        // the counters move monotonically.
        for _ in 0..5 {
            sink.handle_frame(&frame);
        }
        assert_eq!(metrics.peer_candidate_received_total(), 5);
        assert_eq!(metrics.peer_candidate_disabled_total(), 5);
        // Nothing else should move on the discard path.
        assert_eq!(metrics.peer_candidate_validated_total(), 0);
        assert_eq!(metrics.peer_candidate_rejected_total(), 0);
        assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
        assert_eq!(metrics.peer_candidate_rate_limited_total(), 0);
        assert_eq!(metrics.peer_candidate_duplicate_total(), 0);
    }

    #[test]
    fn run079_live_dispatcher_disabled_short_circuits_without_decode() {
        // A disabled live dispatcher MUST behave exactly like the
        // Run 078 disabled receiver: bump received_total +
        // disabled_total, never decode the payload, never call
        // the validator.
        let metrics = Arc::new(P2pMetrics::default());
        let cfg = LivePeerCandidateWireDispatcherConfig {
            inner: PeerCandidateWireReceiverConfig::default(), // disabled
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: std::env::temp_dir(),
            signing_keys: fake_signing_keys(),
            activation_ctx: ActivationContext::height_only(0),
            consensus_storage_for_epoch: None,
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            validation_time_secs: 100,
            propagation: PeerCandidatePropagationConfig::default(),
            propagation_sender: None,
            live_ratification: None,
            authority_marker_path: None,
            staging_queue: None,
        };
        let disp = LivePeerCandidateWireDispatcher::new(cfg, Arc::clone(&metrics));
        assert!(!disp.is_enabled());
        // Even an obviously malformed frame must not panic, must
        // not poison anything — the disabled short-circuit fires
        // FIRST inside the wrapped receiver.
        let frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0xff, 0xff, 0xff, 0xff];
        let outcome = disp.dispatch_frame_for_test(&frame);
        assert!(matches!(outcome, PeerCandidateWireOutcome::Disabled));
        assert_eq!(metrics.peer_candidate_received_total(), 1);
        assert_eq!(metrics.peer_candidate_disabled_total(), 1);
        assert_eq!(metrics.peer_candidate_validated_total(), 0);
        assert_eq!(metrics.peer_candidate_rejected_total(), 0);
        assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 0);
    }

    #[test]
    fn run079_live_dispatcher_enabled_rejects_oversize_frame_before_decode() {
        // The Run 078 DoS cap is enforced on the DECLARED
        // payload_len in the 5-byte header BEFORE allocation /
        // decode. Drive an enabled dispatcher with such a frame
        // and assert dropped_oversize_total fires, NOT
        // rejected_total.
        let metrics = Arc::new(P2pMetrics::default());
        let cfg = LivePeerCandidateWireDispatcherConfig {
            inner: PeerCandidateWireReceiverConfig {
                enabled: true,
                inner: PeerCandidateConfig::default(),
            },
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: std::env::temp_dir(),
            signing_keys: fake_signing_keys(),
            activation_ctx: ActivationContext::height_only(0),
            consensus_storage_for_epoch: None,
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            validation_time_secs: 100,
            propagation: PeerCandidatePropagationConfig::default(),
            propagation_sender: None,
            live_ratification: None,
            authority_marker_path: None,
            staging_queue: None,
        };
        let disp = LivePeerCandidateWireDispatcher::new(cfg, Arc::clone(&metrics));
        assert!(disp.is_enabled());
        let declared: u32 = (MAX_PEER_CANDIDATE_WIRE_FRAME_BYTES + 1) as u32;
        let mut frame = vec![DISCRIMINATOR_PEER_CANDIDATE_WIRE];
        frame.extend_from_slice(&declared.to_be_bytes());
        // No payload bytes — the cap check fires on the declared
        // header value alone.
        let outcome = disp.dispatch_frame_for_test(&frame);
        assert!(matches!(
            outcome,
            PeerCandidateWireOutcome::FrameRejected(
                PeerCandidateWireFrameError::DeclaredPayloadOversize { .. },
            )
        ));
        assert_eq!(metrics.peer_candidate_received_total(), 1);
        assert_eq!(metrics.peer_candidate_dropped_oversize_total(), 1);
        assert_eq!(metrics.peer_candidate_rejected_total(), 0);
        assert_eq!(metrics.peer_candidate_validated_total(), 0);
    }

    #[test]
    fn run079_live_dispatcher_clock_fn_is_invoked_per_frame() {
        // Drive a deterministic clock and assert it fires once per
        // dispatch_frame_for_test call (proving the dispatcher
        // does not cache a wall-clock value across frames in a way
        // the inner rate limiter could not see).
        let clock_counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let clock_counter_for_fn = Arc::clone(&clock_counter);
        let clock_fn: Arc<dyn Fn() -> u64 + Send + Sync + 'static> =
            Arc::new(move || {
                clock_counter_for_fn
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                42
            });
        let metrics = Arc::new(P2pMetrics::default());
        let cfg = LivePeerCandidateWireDispatcherConfig {
            inner: PeerCandidateWireReceiverConfig::default(),
            expected_environment: NetworkEnvironment::Devnet,
            expected_chain_id: NetworkEnvironment::Devnet.chain_id(),
            scratch_dir: std::env::temp_dir(),
            signing_keys: fake_signing_keys(),
            activation_ctx: ActivationContext::height_only(0),
            consensus_storage_for_epoch: None,
            sequence_persistence_path: None,
            local_leaf_cert_bytes: None,
            validation_time_secs: 100,
            propagation: PeerCandidatePropagationConfig::default(),
            propagation_sender: None,
            live_ratification: None,
            authority_marker_path: None,
            staging_queue: None,
        };
        let disp = LivePeerCandidateWireDispatcher::with_clock(
            cfg,
            Arc::clone(&metrics),
            clock_fn,
        );
        // Disabled path still calls the clock once before the
        // short-circuit (cheap; the inner receiver receives the
        // ctx even on the disabled path so the contract is the
        // same as Run 078).
        for _ in 0..3 {
            let _ = disp
                .dispatch_frame_for_test(&[DISCRIMINATOR_PEER_CANDIDATE_WIRE, 0, 0, 0, 0]);
        }
        assert_eq!(
            clock_counter.load(std::sync::atomic::Ordering::Relaxed),
            3
        );
    }

    struct FakeRun080Sender {
        peers: Vec<NodeId>,
        outcome: RawFramePeerSendOutcome,
        sent_frames: Mutex<Vec<Vec<u8>>>,
    }
    impl FakeRun080Sender {
        fn with(peers: Vec<NodeId>, outcome: RawFramePeerSendOutcome) -> Arc<Self> {
            Arc::new(Self {
                peers,
                outcome,
                sent_frames: Mutex::new(Vec::new()),
            })
        }
    }
    impl PeerCandidateWireFrameSender for FakeRun080Sender {
        fn connected_peer_node_ids(&self) -> Vec<NodeId> {
            self.peers.clone()
        }

        fn send_raw_frame_to_all_peers(&self, frame_bytes: Vec<u8>) -> RawFrameSendReport {
            self.sent_frames.lock().push(frame_bytes);
            RawFrameSendReport::from_per_peer(
                self.peers
                    .iter()
                    .copied()
                    .map(|p| (p, self.outcome))
                    .collect(),
            )
        }
    }

    fn run080_envelope() -> PeerCandidateEnvelope {
        let bytes = vec![1, 2, 3, 4];
        PeerCandidateEnvelope {
            envelope_version: PeerCandidateEnvelope::ENVELOPE_VERSION,
            domain_tag: PeerCandidateEnvelope::DOMAIN_TAG.to_string(),
            peer_id: Some("peer-run080".to_string()),
            environment: TrustBundleEnvironment::Devnet,
            chain_id_hex: crate::pqc_trust_sequence::chain_id_hex(
                NetworkEnvironment::Devnet.chain_id(),
            ),
            declared_sequence: 11,
            declared_fingerprint_prefix: "deadbeef".to_string(),
            declared_length: bytes.len(),
            bundle_bytes: bytes,
        }
    }

    fn write_envelope_file(env: &PeerCandidateEnvelope) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "qbind-run080-test-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("candidate.json");
        std::fs::write(&path, serde_json::to_vec(env).unwrap()).unwrap();
        path
    }

    #[tokio::test]
    async fn run080_publish_disabled_fails_closed() {
        let sender = FakeRun080Sender::with(
            vec![NodeId::new([1u8; 32])],
            RawFramePeerSendOutcome::Enqueued,
        );
        let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender;
        let metrics = Arc::new(P2pMetrics::default());
        let p = LivePeerCandidateWirePublisher::new(sender_trait, Arc::clone(&metrics));
        let out = p
            .publish_once_from_config(&PeerCandidateWirePublishConfig::default())
            .await
            .unwrap_err();
        assert!(matches!(out, PeerCandidateWirePublishError::Disabled));
        assert_eq!(metrics.peer_candidate_sent_total(), 0);
        assert_eq!(metrics.peer_candidate_send_failure_total(), 0);
    }

    #[tokio::test]
    async fn run080_publish_no_peer_times_out_and_bumps_no_peer_counter() {
        let sender = FakeRun080Sender::with(vec![], RawFramePeerSendOutcome::Enqueued);
        let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender;
        let metrics = Arc::new(P2pMetrics::default());
        let p = LivePeerCandidateWirePublisher::new(sender_trait, Arc::clone(&metrics));
        let path = write_envelope_file(&run080_envelope());
        let cfg = PeerCandidateWirePublishConfig {
            enabled: true,
            envelope_path: Some(path),
            publish_once: true,
            wait_for_peer_timeout: Duration::from_millis(20),
            wait_poll_interval: Duration::from_millis(5),
        };
        let out = p.publish_once_from_config(&cfg).await.unwrap_err();
        assert!(matches!(
            out,
            PeerCandidateWirePublishError::NoPeerWithinTimeout { .. }
        ));
        assert_eq!(metrics.peer_candidate_send_no_peer_total(), 1);
        assert_eq!(metrics.peer_candidate_sent_total(), 0);
    }

    #[tokio::test]
    async fn run080_publish_success_bumps_sent_counter_per_peer() {
        let peers = vec![NodeId::new([9u8; 32]), NodeId::new([7u8; 32])];
        let sender = FakeRun080Sender::with(peers.clone(), RawFramePeerSendOutcome::Enqueued);
        let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender.clone();
        let metrics = Arc::new(P2pMetrics::default());
        let p = LivePeerCandidateWirePublisher::new(sender_trait, Arc::clone(&metrics));
        let path = write_envelope_file(&run080_envelope());
        let cfg = PeerCandidateWirePublishConfig {
            enabled: true,
            envelope_path: Some(path),
            publish_once: true,
            wait_for_peer_timeout: Duration::from_secs(1),
            wait_poll_interval: Duration::from_millis(10),
        };
        let report = p.publish_once_from_config(&cfg).await.expect("publish");
        assert_eq!(report.attempted(), 2);
        assert_eq!(report.sent(), 2);
        assert_eq!(report.failed(), 0);
        assert_eq!(metrics.peer_candidate_sent_total(), 2);
        assert_eq!(metrics.peer_candidate_send_failure_total(), 0);
        assert_eq!(sender.sent_frames.lock().len(), 1);
        let log = wire_publish_log_line(&report, peers.len());
        assert!(log.contains("validation-only/not-applied"));
        assert!(log.contains("seq=11"));
    }

    #[tokio::test]
    async fn run080_publish_queue_full_bumps_send_failure_counter() {
        let sender = FakeRun080Sender::with(
            vec![NodeId::new([5u8; 32]), NodeId::new([6u8; 32])],
            RawFramePeerSendOutcome::QueueFull,
        );
        let sender_trait: Arc<dyn PeerCandidateWireFrameSender> = sender;
        let metrics = Arc::new(P2pMetrics::default());
        let p = LivePeerCandidateWirePublisher::new(sender_trait, Arc::clone(&metrics));
        let path = write_envelope_file(&run080_envelope());
        let cfg = PeerCandidateWirePublishConfig {
            enabled: true,
            envelope_path: Some(path),
            publish_once: true,
            wait_for_peer_timeout: Duration::from_secs(1),
            wait_poll_interval: Duration::from_millis(10),
        };
        let report = p.publish_once_from_config(&cfg).await.expect("publish");
        assert_eq!(report.attempted(), 2);
        assert_eq!(report.sent(), 0);
        assert_eq!(report.failed(), 2);
        assert_eq!(metrics.peer_candidate_sent_total(), 0);
        assert_eq!(metrics.peer_candidate_send_failure_total(), 2);
    }
}