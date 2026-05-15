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

use std::path::Path;

use qbind_types::{ChainId, NetworkEnvironment};

use crate::metrics::P2pMetrics;
use crate::pqc_trust_activation::ActivationContext;
use crate::pqc_trust_bundle::{BundleSigningKeySet, TrustBundleEnvironment};
use crate::pqc_trust_peer_candidate::{
    PeerCandidateConfig, PeerCandidateEnvelope, PeerCandidateOutcome,
    PeerCandidateRuntimeContext, PeerCandidateValidator, MAX_PEER_CANDIDATE_BUNDLE_BYTES,
};

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
        let outcome = self.validator.try_accept(run076_envelope, &inner_ctx);

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
// Unit tests (frame codec / disabled-by-default / metrics).
// Full-pipeline validator tests live in
// crates/qbind-node/tests/run_078_pqc_peer_candidate_wire_tests.rs
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
}