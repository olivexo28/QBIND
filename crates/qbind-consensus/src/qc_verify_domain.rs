//! Run 422 D7-C3D — pure, dormant D6-compatible QuorumCertificate verification.
//!
//! # Purpose
//!
//! [`verify_quorum_certificate_with_domain`] verifies the constituent `Vote`
//! signatures and the aggregate voting power of a **wire**
//! [`QuorumCertificate`](qbind_wire::consensus::QuorumCertificate) under an
//! explicitly supplied D6 signing domain
//! ([`ProposalVoteSigningDomainV2`]). It reuses — never re-implements — the
//! existing D6 machinery:
//!
//! * [`verify_vote_msg_with_domain`](crate::proposal_vote_verify::verify_vote_msg_with_domain)
//!   for every per-signer cryptographic check (so the signed input is exactly
//!   `ProposalVoteSigningDomainV2::vote_preimage`, never the legacy
//!   `vote_digest`);
//! * [`ConsensusValidatorSet`] for membership + voting power;
//! * [`SuiteAwareValidatorKeyProvider`] for the governed `(suite, pk)`;
//! * [`ConsensusSigBackendRegistry`] for suite → backend dispatch.
//!
//! # Trust model
//!
//! The **entire QC is untrusted**: it may be directly constructed as well as
//! wire-decoded, so shape and resource bounds are validated before any
//! expensive work. The **trusted** inputs are the caller-supplied `domain`,
//! `authorized_epoch`, `validators` (membership), `key_provider`, and
//! `backend_registry`. They must describe a coherent, stable verification
//! context for the duration of the call; this module does not solve concurrent
//! provider mutation or persistent freshness.
//!
//! Success establishes **signature-and-quorum validity relative to those
//! trusted inputs only**. It does **not** establish that the inputs came from
//! official genesis, that the authority is current, or that activation is
//! permitted. The returned [`VerifiedQuorumCertificate`] is deliberately
//! **non-authorizing** and offers **no** conversion to any current-authority
//! owner, snapshot, ticket, signer, activation state, or production
//! verification capability.
//!
//! # Signer-index semantics (matches D6)
//!
//! The D6 primitive derives the signer identity from the wire index as
//! `ValidatorId::new(vote.validator_index as u64)`. This module preserves that
//! exactly: **bitmap bit `i` reconstructs wire `validator_index = i` and
//! identifies `ValidatorId(i)`**, subject to checked representability and a
//! trusted membership lookup. Membership-vector *position* is never substituted
//! for `ValidatorId`; ids are never reordered, renumbered, truncated, or
//! wrapped. Because a bitmap cannot repeat a bit, every signer id is distinct.
//!
//! # Size bounds (all validated before any clone or cryptographic work)
//!
//! The structural preflight is **complete before the cryptographic loop**: no
//! signature buffer is cloned and **no backend is invoked** until every one of
//! the following holds, so an oversized late signature (or an unrepresentable
//! count) rejects before *any* backend call.
//!
//! * **Signature-count representability.** The wire QC encodes
//!   `signatures.len()` as a `u16` (`sig_count`), so at most
//!   [`MAX_SIGNATURE_COUNT`] (`u16::MAX == 65535`) signatures are encodable.
//!   `signatures.len() > MAX_SIGNATURE_COUNT` is rejected with a bounded typed
//!   error **before any crypto or signer-result allocation**. Note the three
//!   distinct quantities: the maximum *validator index* is `65535` (still
//!   valid); the number of *representable indices* is `65536` (`0..=65535`);
//!   and the maximum *encodable signature count* is `65535`. An 8192-byte
//!   bitmap alone does **not** enforce the count limit — a full 8192-byte
//!   bitmap has `65536` set bits, one more than the encodable count — so the
//!   count is bounded explicitly rather than inferred from the bitmap.
//! * **Global bitmap length.** `signer_bitmap.len() <= `[`MAX_BITMAP_LEN`]
//!   (8192 bytes). Any bit in a longer bitmap could imply a
//!   `validator_index > u16::MAX`, so the cap bounds work and guarantees every
//!   set bit maps to a representable u16 index.
//! * **Membership-relative bitmap span.** `signer_bitmap.len()` must not exceed
//!   the trusted membership's **identifier span** — the number of bytes needed
//!   to represent bit indices `0..=max_id` where `max_id` is the largest
//!   representable `ValidatorId` in the trusted set (`(max_id / 8) + 1` bytes;
//!   `0` for an empty set). This uses the *identifier span*, never
//!   `validators.len()`, so sparse and reordered memberships remain valid. Any
//!   byte beyond that span — **including zero padding** — is rejected
//!   ([`QcDomainVerifyError::BitmapBeyondMembershipSpan`]). Set bits for unknown
//!   members that fall *within* the span continue to reject at the membership
//!   check. Because every `max_id <= u16::MAX`, the span is always
//!   `<= MAX_BITMAP_LEN`.
//! * `popcount(bitmap) == signatures.len()` is required; `collect_signers`
//!   builds the temporary ascending-bit-order signer vector that this
//!   correspondence is checked against. That temporary vector is bounded by the
//!   bitmap capacity — before correspondence succeeds it can hold up to `65536`
//!   entries (a full 8192-byte bitmap's popcount), and only after successful
//!   correspondence is it bounded by [`MAX_SIGNATURE_COUNT`]. The per-signature
//!   and aggregate size checks below therefore run *after* this temporary
//!   allocation; they precede only the signature-buffer clone and any backend
//!   invocation, not every allocation.
//! * **Per-signature size.** Each signature length ≤ [`MAX_SIGNATURE_LEN`] (the
//!   wire u16 length bound), validated for *every* signature before the crypto
//!   loop.
//! * **Checked aggregate size.** The sum of all constituent signature byte
//!   lengths is accumulated with checked arithmetic
//!   ([`checked_aggregate_signature_bytes`]) and must not exceed the documented
//!   acceptance bound [`MAX_AGGREGATE_SIGNATURE_BYTES`]
//!   (`MAX_SIGNATURE_COUNT * MAX_SIGNATURE_LEN`). This is the structural worst
//!   case implied purely by the two wire field widths (a `u16` count of
//!   `u16`-length signatures); it is the dormant verifier's own acceptance
//!   bound and is **deliberately distinct** from transport limits such as
//!   `qbind_wire::net::MAX_NET_MESSAGE_BYTES`. Establishing it does not change
//!   transport policy.
//! * The only per-signer allocation is a single clone of that signer's
//!   signature into the reconstructed `Vote` (bounded by `MAX_SIGNATURE_LEN`);
//!   all sizes above are validated *before* that clone and before any
//!   cryptographic work.
//!
//! This is **not** a complete transport-level DoS audit.
//!
//! # Quorum arithmetic
//!
//! The total voting power `W` is **recomputed with checked arithmetic** from
//! the trusted membership (the cached total uses saturating accumulation and
//! `two_thirds_vp()` computes `2 * total` in `u64`, neither of which may be
//! trusted blindly). `W` must be positive and representable. The threshold is
//! the existing mathematical `ceil(2W/3)` computed with wide (`u128`)
//! arithmetic — the **checked equivalent** of
//! [`ConsensusValidatorSet::two_thirds_vp`] that avoids its `2 * total` u64
//! overflow. Preserving this `ceil(2W/3)` policy is **compatibility behavior**,
//! not a new proof of safety under arbitrary weighted fault assumptions.
//!
//! Every declared signature is verified: the function never returns success
//! upon merely reaching quorum while leaving additional claimed signatures
//! unchecked. A QC with a valid quorum followed by an invalid extra signature
//! is rejected.
//!
//! # Dormancy
//!
//! Run 422 D7-C3E added a single, conditional binary caller: the inbound
//! `Proposal` arm of `qbind-node`'s `handle_inbound_consensus_msg`. Under the
//! `Required` verification policy, with a bound current-authorization snapshot
//! and a Proposal carrying `Some(qc)`, the handler invokes
//! [`verify_quorum_certificate_with_domain`] to admit the PRESENT embedded wire
//! QC BEFORE any inbound Proposal effect (restore-deferral accounting,
//! delivery, reconfiguration observation, engine mutation/view advancement, or
//! the immediate outbound handoff). The trusted inputs are drawn from that same
//! admitted snapshot; the returned [`VerifiedQuorumCertificate`] remains
//! **non-authorizing** and is not retained beyond the synchronous handler call.
//!
//! This module remains **uncalled** by production node startup, the engine's
//! own QC formation/adoption, cache, storage, and activation paths. Genesis
//! authority activation stays DISABLED, so no release binary constructs the
//! bound snapshot that reaches this caller; the conditional caller is therefore
//! exercised by tests. Aside from that C3E admission gate, the C3D rules,
//! D6 bytes, wire encodings, and legacy verification are unchanged.

use qbind_crypto::ConsensusSigSuiteId;
use qbind_wire::consensus::{QuorumCertificate as WireQuorumCertificate, Vote};
use qbind_wire::pv_signing_domain::ProposalVoteSigningDomainV2;

use crate::crypto_verifier::ConsensusSigBackendRegistry;
use crate::ids::ValidatorId;
use crate::key_registry::SuiteAwareValidatorKeyProvider;
use crate::proposal_vote_verify::{verify_vote_msg_with_domain, ProposalVoteVerifyError};
use crate::validator_set::ConsensusValidatorSet;

/// Maximum accepted `signer_bitmap` length, in bytes.
///
/// `8192 * 8 == 65536` bits, so the highest representable bit index is `65535`
/// (`byte 8191`, `bit 7`), which is exactly `u16::MAX`. A bitmap no longer than
/// this therefore can never imply a `validator_index` that the u16 wire field
/// cannot represent, and the bound also caps the per-call scanning work.
pub const MAX_BITMAP_LEN: usize = 8192;

/// Maximum accepted length of any single constituent signature, in bytes.
///
/// This is the wire length bound: on the wire each signature is `u16`
/// length-prefixed, so it can never exceed `u16::MAX`. A directly constructed
/// (non-wire) QC is held to the same bound.
pub const MAX_SIGNATURE_LEN: usize = u16::MAX as usize;

/// Maximum accepted number of constituent signatures in a QC.
///
/// The wire `QuorumCertificate` encodes `signatures.len()` as a `u16`
/// (`sig_count`), so a QC carrying more than `u16::MAX == 65535` signatures is
/// **not encodable** — the encoder would panic on the narrowing conversion.
/// This dormant verifier therefore rejects `signatures.len() > 65535` with a
/// bounded typed error *before* any cryptographic work or signer-result
/// allocation, rather than relying on that downstream panic and without
/// changing the wire format or encoder to accommodate an oversized count.
///
/// This is distinct from the number of *representable validator indices*
/// (`65536`, i.e. `0..=65535`) and from the *maximum validator index* (`65535`,
/// which remains valid): a full 8192-byte bitmap has `65536` set bits, one more
/// than the maximum encodable signature count.
pub const MAX_SIGNATURE_COUNT: usize = u16::MAX as usize;

/// Documented aggregate acceptance bound for the combined byte length of all
/// constituent signatures: [`MAX_SIGNATURE_COUNT`] × [`MAX_SIGNATURE_LEN`].
///
/// This is the structural worst case implied purely by the two wire field
/// widths — at most `65535` signatures, each at most `65535` bytes. It is the
/// dormant verifier's *own* acceptance bound, enforced with checked arithmetic
/// before any cryptographic work, and is **deliberately distinct** from
/// transport-layer limits such as `qbind_wire::net::MAX_NET_MESSAGE_BYTES`
/// (1 MiB). Establishing it here does not change transport policy and is not a
/// complete DoS audit.
pub const MAX_AGGREGATE_SIGNATURE_BYTES: usize = MAX_SIGNATURE_COUNT * MAX_SIGNATURE_LEN;

/// Maximum diagnostic length retained from a backend error string.
const MAX_BACKEND_MSG_LEN: usize = 96;

/// Bounded, typed rejection taxonomy for
/// [`verify_quorum_certificate_with_domain`].
///
/// Outward diagnostics are deliberately bounded: no variant embeds a whole
/// certificate, signature array, key bytes, or an unbounded backend string.
/// [`QcDomainVerifyError::BackendError`] carries only a truncated message
/// produced by our own suite backends (never wire input).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QcDomainVerifyError {
    /// The QC's wire `chain_id` disagrees with the trusted domain's validated
    /// `expected_wire_chain_id`. Checked before any cryptographic work; the QC
    /// is never rewritten.
    WireChainMismatch {
        /// The wire `chain_id` the domain requires authentic QCs to carry.
        expected: u32,
        /// The wire `chain_id` actually carried by the QC.
        actual: u32,
    },
    /// The QC's `epoch` disagrees with the independently supplied authorized
    /// epoch. Checked before any cryptographic work.
    EpochMismatch {
        /// The trusted authorized epoch.
        expected: u64,
        /// The epoch actually carried by the QC.
        actual: u64,
    },
    /// The trusted membership has a non-positive (zero) total voting power.
    ZeroTotalVotingPower,
    /// The trusted membership's total voting power overflows `u64` under
    /// checked accumulation (the cached total silently saturates).
    TotalVotingPowerOverflow,
    /// The trusted membership contains a `ValidatorId` the u16 wire
    /// `validator_index` field cannot represent (`> u16::MAX`). For this
    /// bounded phase such a membership is rejected outright.
    MembershipIdNotRepresentable(ValidatorId),
    /// The `signer_bitmap` is longer than [`MAX_BITMAP_LEN`].
    BitmapTooLong {
        /// The actual bitmap length in bytes.
        len: usize,
        /// The maximum accepted bitmap length in bytes.
        max: usize,
    },
    /// The `signer_bitmap` extends beyond the trusted membership's identifier
    /// span — the byte span required to represent bit indices `0..=max_id` for
    /// the largest representable `ValidatorId` in the trusted set. Any byte
    /// past that span (including trailing zero padding) is rejected.
    BitmapBeyondMembershipSpan {
        /// The actual bitmap length in bytes.
        len: usize,
        /// The maximum bitmap length permitted by the membership span, in
        /// bytes.
        allowed: usize,
    },
    /// `signatures.len()` exceeds [`MAX_SIGNATURE_COUNT`] (`u16::MAX`), so the
    /// wire `sig_count` field cannot represent it. Checked before any crypto or
    /// signer-result allocation.
    SignatureCountNotRepresentable {
        /// The number of declared signatures.
        count: usize,
        /// The maximum encodable signature count.
        max: usize,
    },
    /// The checked aggregate byte length of all constituent signatures exceeds
    /// [`MAX_AGGREGATE_SIGNATURE_BYTES`], or the checked summation overflowed
    /// `usize`. Checked before any cryptographic work.
    AggregateSignatureBytesTooLarge {
        /// The accumulated aggregate byte length at the point of rejection
        /// (saturated to `usize::MAX` if the checked summation overflowed).
        aggregate: usize,
        /// The documented aggregate acceptance bound.
        max: usize,
    },
    /// A set bit implies a `validator_index` greater than `u16::MAX`.
    SignerIndexNotRepresentable {
        /// The offending bit index.
        index: u32,
    },
    /// `popcount(signer_bitmap)` does not equal `signatures.len()`.
    SignatureCountMismatch {
        /// The number of set bits in the bitmap.
        popcount: usize,
        /// The number of supplied signatures.
        signatures: usize,
    },
    /// A signer's signature field is empty (unsigned).
    MissingSignature(ValidatorId),
    /// A signer's signature exceeds [`MAX_SIGNATURE_LEN`].
    MalformedSignature(ValidatorId),
    /// A set bit maps to a `ValidatorId` that is not a member of the trusted
    /// set.
    UnknownSigner(ValidatorId),
    /// The reconstructed signer index did not match the associated D6 signer
    /// identity. Not reachable through the public entrypoint (the two are
    /// derived from the same bit) but retained as an explicit fail-closed
    /// guard.
    SignerAssociation(ValidatorId),
    /// No governed public key is registered for a signer.
    MissingKey(ValidatorId),
    /// The QC's single wire `suite_id` does not match a signer's governed
    /// suite.
    SuiteMismatch {
        /// The signer.
        validator_id: ValidatorId,
        /// The suite id carried by the QC on the wire.
        wire_suite: ConsensusSigSuiteId,
        /// The governance-configured suite for this signer.
        governance_suite: ConsensusSigSuiteId,
    },
    /// No registered/allowed backend exists for a signer's governed suite.
    UnsupportedBackend {
        /// The signer.
        validator_id: ValidatorId,
        /// The governance-configured suite for this signer.
        governance_suite: ConsensusSigSuiteId,
    },
    /// A signer's signature did not verify against the governed key over the
    /// recomputed D6 preimage.
    InvalidSignature(ValidatorId),
    /// A suite backend returned an error other than invalid/malformed
    /// signature. The message is bounded and produced by our own backend.
    BackendError(ValidatorId, String),
    /// The verified voting power did not reach the `ceil(2W/3)` threshold.
    InsufficientVotingPower {
        /// The verified accumulated voting power.
        have: u64,
        /// The required `ceil(2W/3)` threshold.
        need: u64,
    },
    /// Accumulating a verified signer's voting power overflowed. This is
    /// unreachable given the checked, representable total-power precondition
    /// (the signer subset weight can never exceed the validated total), but is
    /// retained as an explicit checked-arithmetic guard rather than a silent
    /// saturation.
    VerifiedPowerOverflow,
}

impl std::fmt::Display for QcDomainVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            QcDomainVerifyError::WireChainMismatch { expected, actual } => write!(
                f,
                "QC wire chain_id mismatch: expected={}, actual={}",
                expected, actual
            ),
            QcDomainVerifyError::EpochMismatch { expected, actual } => write!(
                f,
                "QC epoch mismatch: expected={}, actual={}",
                expected, actual
            ),
            QcDomainVerifyError::ZeroTotalVotingPower => {
                write!(f, "trusted membership total voting power is zero")
            }
            QcDomainVerifyError::TotalVotingPowerOverflow => {
                write!(f, "trusted membership total voting power overflows u64")
            }
            QcDomainVerifyError::MembershipIdNotRepresentable(id) => {
                write!(f, "membership id not representable as u16 index: {:?}", id)
            }
            QcDomainVerifyError::BitmapTooLong { len, max } => {
                write!(f, "signer_bitmap too long: len={}, max={}", len, max)
            }
            QcDomainVerifyError::BitmapBeyondMembershipSpan { len, allowed } => write!(
                f,
                "signer_bitmap extends beyond membership span: len={}, allowed={}",
                len, allowed
            ),
            QcDomainVerifyError::SignatureCountNotRepresentable { count, max } => write!(
                f,
                "signature count not representable as u16: count={}, max={}",
                count, max
            ),
            QcDomainVerifyError::AggregateSignatureBytesTooLarge { aggregate, max } => write!(
                f,
                "aggregate signature bytes too large: aggregate={}, max={}",
                aggregate, max
            ),
            QcDomainVerifyError::SignerIndexNotRepresentable { index } => {
                write!(f, "signer index not representable as u16: {}", index)
            }
            QcDomainVerifyError::SignatureCountMismatch {
                popcount,
                signatures,
            } => write!(
                f,
                "signature count mismatch: popcount={}, signatures={}",
                popcount, signatures
            ),
            QcDomainVerifyError::MissingSignature(id) => {
                write!(f, "missing signature for signer: {:?}", id)
            }
            QcDomainVerifyError::MalformedSignature(id) => {
                write!(f, "malformed signature for signer: {:?}", id)
            }
            QcDomainVerifyError::UnknownSigner(id) => {
                write!(f, "unknown signer: {:?}", id)
            }
            QcDomainVerifyError::SignerAssociation(id) => {
                write!(f, "signer association error: {:?}", id)
            }
            QcDomainVerifyError::MissingKey(id) => {
                write!(f, "missing key for signer: {:?}", id)
            }
            QcDomainVerifyError::SuiteMismatch {
                validator_id,
                wire_suite,
                governance_suite,
            } => write!(
                f,
                "suite mismatch for signer {:?}: wire={}, governance={}",
                validator_id, wire_suite, governance_suite
            ),
            QcDomainVerifyError::UnsupportedBackend {
                validator_id,
                governance_suite,
            } => write!(
                f,
                "unsupported backend for signer {:?}: governance_suite={}",
                validator_id, governance_suite
            ),
            QcDomainVerifyError::InvalidSignature(id) => {
                write!(f, "invalid signature from signer: {:?}", id)
            }
            QcDomainVerifyError::BackendError(id, msg) => {
                write!(f, "backend error for signer {:?}: {}", id, msg)
            }
            QcDomainVerifyError::InsufficientVotingPower { have, need } => {
                write!(f, "insufficient voting power: have={}, need={}", have, need)
            }
            QcDomainVerifyError::VerifiedPowerOverflow => {
                write!(f, "verified voting power accumulation overflowed")
            }
        }
    }
}

impl std::error::Error for QcDomainVerifyError {}

impl QcDomainVerifyError {
    /// Map a per-signer D6 verification failure to the QC taxonomy, tagging the
    /// signer being processed. The `signer` argument is the bit-derived signer
    /// identity so the outward error stays attributable and bounded.
    fn from_pv(signer: ValidatorId, e: ProposalVoteVerifyError) -> Self {
        match e {
            // Not reachable via the public entrypoint (claimed == message
            // signer by construction), but mapped explicitly rather than
            // panicking.
            ProposalVoteVerifyError::SignerMismatch { .. } => {
                QcDomainVerifyError::SignerAssociation(signer)
            }
            ProposalVoteVerifyError::UnknownValidator(id) => QcDomainVerifyError::UnknownSigner(id),
            ProposalVoteVerifyError::MissingSignature(id) => {
                QcDomainVerifyError::MissingSignature(id)
            }
            ProposalVoteVerifyError::MissingKey(id) => QcDomainVerifyError::MissingKey(id),
            ProposalVoteVerifyError::UnsupportedSuite {
                validator_id,
                governance_suite,
            } => QcDomainVerifyError::UnsupportedBackend {
                validator_id,
                governance_suite,
            },
            ProposalVoteVerifyError::SuiteMismatch {
                validator_id,
                wire_suite,
                governance_suite,
            } => QcDomainVerifyError::SuiteMismatch {
                validator_id,
                wire_suite,
                governance_suite,
            },
            ProposalVoteVerifyError::InvalidSignature(id) => {
                QcDomainVerifyError::InvalidSignature(id)
            }
            // The per-vote wire chain_id equals the QC's (already domain-checked)
            // chain_id, so this should not fire; mapped explicitly regardless.
            ProposalVoteVerifyError::WireChainMismatch {
                expected_wire_chain_id,
                actual_wire_chain_id,
                ..
            } => QcDomainVerifyError::WireChainMismatch {
                expected: expected_wire_chain_id,
                actual: actual_wire_chain_id,
            },
            ProposalVoteVerifyError::MalformedSignature(id) => {
                QcDomainVerifyError::MalformedSignature(id)
            }
            ProposalVoteVerifyError::BackendError(id, msg) => {
                QcDomainVerifyError::BackendError(id, truncate_backend_msg(&msg))
            }
        }
    }
}

/// Truncate a backend diagnostic string to a bounded length so error
/// Display/Debug can never grow without bound.
fn truncate_backend_msg(msg: &str) -> String {
    if msg.len() <= MAX_BACKEND_MSG_LEN {
        return msg.to_string();
    }
    let mut end = MAX_BACKEND_MSG_LEN;
    while end > 0 && !msg.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = msg[..end].to_string();
    out.push('…');
    out
}

/// Attributable, **non-authorizing** evidence produced by a successful
/// [`verify_quorum_certificate_with_domain`] call.
///
/// The verified certificate is stored as an **owned clone**, so the evidence
/// can never silently refer to a different, subsequently mutated certificate.
/// All fields are private with read-only accessors; there is no public
/// constructor, no public mutable field, and no `Deserialize` — the only way to
/// obtain one is a successful verification.
///
/// This type deliberately provides **no** conversion to a current-authorization
/// owner, snapshot, ticket, signer, activation state, or production
/// verification capability. It records signature-and-quorum validity relative
/// to the trusted inputs *at the instant of the call only*; it does not solve
/// concurrent provider mutation or persistent freshness.
#[derive(Clone)]
pub struct VerifiedQuorumCertificate {
    certificate: WireQuorumCertificate,
    signers: Vec<ValidatorId>,
    verified_voting_power: u64,
    threshold: u64,
    expected_wire_chain_id: u32,
    authorized_epoch: u64,
    domain: ProposalVoteSigningDomainV2,
}

impl VerifiedQuorumCertificate {
    /// The verified certificate (owned clone of the input QC).
    pub fn certificate(&self) -> &WireQuorumCertificate {
        &self.certificate
    }

    /// The distinct signer identities whose signatures verified, in ascending
    /// bit order.
    pub fn signers(&self) -> &[ValidatorId] {
        &self.signers
    }

    /// The verified accumulated voting power.
    pub fn verified_voting_power(&self) -> u64 {
        self.verified_voting_power
    }

    /// The `ceil(2W/3)` threshold this certificate met.
    pub fn threshold(&self) -> u64 {
        self.threshold
    }

    /// The trusted expected wire `chain_id` the certificate was verified
    /// against.
    pub fn expected_wire_chain_id(&self) -> u32 {
        self.expected_wire_chain_id
    }

    /// The trusted authorized epoch the certificate was verified against.
    pub fn authorized_epoch(&self) -> u64 {
        self.authorized_epoch
    }

    /// The trusted signing domain the certificate was verified against.
    pub fn domain(&self) -> &ProposalVoteSigningDomainV2 {
        &self.domain
    }

    /// Run 422 D7-C3F: the number of bytes this evidence conservatively
    /// occupies when retained by an engine's block tree, for **checked**
    /// retention-budget accounting.
    ///
    /// Existing block-count limits alone are **not** an adequate byte bound:
    /// each retained certificate carries variable-length constituent signature
    /// buffers, a signer bitmap and a signer-identity vector, all heap
    /// allocated. This method charges, with fully **checked** arithmetic (so an
    /// unrepresentable total is rejected rather than silently saturated into an
    /// admissible value):
    ///
    /// * the owned [`VerifiedQuorumCertificate`] value itself
    ///   (`size_of::<VerifiedQuorumCertificate>()`). This already includes the
    ///   *inline* `Vec` descriptors (pointer/len/capacity triples) for the
    ///   bitmap, the outer signatures vector and the signer vector, plus every
    ///   inline scalar field and the fully-inline
    ///   [`ProposalVoteSigningDomainV2`] (which owns no heap allocation). Those
    ///   inline descriptors are therefore **not** re-added below, avoiding
    ///   double counting;
    /// * the signer bitmap's allocated heap buffer (its `capacity()`);
    /// * the outer signatures vector's allocated descriptor storage — the
    ///   `capacity()` backing `Vec<u8>` handles, each `size_of::<Vec<u8>>()`
    ///   bytes — which is the heap the outer vector points at, distinct from
    ///   its inline descriptor counted in the struct size;
    /// * each constituent signature buffer's allocated `capacity()`;
    /// * the signer-identity vector's allocated heap buffer
    ///   (`capacity() * size_of::<ValidatorId>()`).
    ///
    /// Deliberately **outside** this accounting model:
    ///
    /// * process-wide allocator bookkeeping and per-allocation bucket rounding
    ///   (the real resident set is `>=` this charge; the charge is a
    ///   conservative accounting bound, not an allocator audit);
    /// * externally retained `Arc` clones of this evidence — the value is
    ///   charged exactly once to the block that owns the canonical handle and is
    ///   never multiplied by the number of outstanding `Arc` handles.
    ///
    /// # Errors
    ///
    /// Returns [`RetainedByteSizeError::Unrepresentable`] if any intermediate
    /// or the final total overflows `u64`. The verifier's own
    /// [`MAX_AGGREGATE_SIGNATURE_BYTES`] and bitmap bounds keep every realistic
    /// certificate far below `u64::MAX`, so this is a defensive invariant, not
    /// an expected outcome.
    pub fn retained_byte_size(&self) -> Result<u64, RetainedByteSizeError> {
        use std::mem::size_of;

        // The owned struct value, including all inline scalars and the inline
        // Vec descriptors for the bitmap, outer signatures vector and signer
        // vector. Heap buffers reachable through those descriptors are added
        // below; their inline descriptors are NOT re-added.
        let mut bytes: u64 = size_of::<VerifiedQuorumCertificate>() as u64;

        // Signer bitmap heap buffer (allocated capacity, not just length).
        bytes = checked_add_u64(bytes, usize_to_u64(self.certificate.signer_bitmap.capacity())?)?;

        // Outer signatures vector: allocated descriptor storage for `capacity`
        // `Vec<u8>` handles.
        let sig_descriptor_bytes = checked_mul_u64(
            usize_to_u64(self.certificate.signatures.capacity())?,
            size_of::<Vec<u8>>() as u64,
        )?;
        bytes = checked_add_u64(bytes, sig_descriptor_bytes)?;

        // Each constituent signature buffer's allocated capacity.
        for sig in &self.certificate.signatures {
            bytes = checked_add_u64(bytes, usize_to_u64(sig.capacity())?)?;
        }

        // Signer-identity vector heap buffer (allocated capacity).
        let signer_bytes = checked_mul_u64(
            usize_to_u64(self.signers.capacity())?,
            size_of::<ValidatorId>() as u64,
        )?;
        bytes = checked_add_u64(bytes, signer_bytes)?;

        Ok(bytes)
    }
}

/// Run 422 D7-C3F: failure of a **checked** retained-byte charge computation.
///
/// Carries no certificate material — only the fact that the charge is not
/// representable as a `u64` (and therefore the accounting invariant cannot be
/// upheld). Callers must reject the retention explicitly rather than admit an
/// unrepresentable total.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetainedByteSizeError {
    /// An intermediate or the final retained-byte total overflowed `u64`.
    Unrepresentable,
}

impl std::fmt::Display for RetainedByteSizeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RetainedByteSizeError::Unrepresentable => {
                write!(f, "retained-evidence byte charge is not representable as u64")
            }
        }
    }
}

impl std::error::Error for RetainedByteSizeError {}

/// Checked `usize -> u64` conversion (infallible on 64-bit targets; kept
/// checked so 128-bit or future targets cannot silently truncate).
#[inline]
fn usize_to_u64(v: usize) -> Result<u64, RetainedByteSizeError> {
    u64::try_from(v).map_err(|_| RetainedByteSizeError::Unrepresentable)
}

#[inline]
fn checked_add_u64(a: u64, b: u64) -> Result<u64, RetainedByteSizeError> {
    a.checked_add(b).ok_or(RetainedByteSizeError::Unrepresentable)
}

#[inline]
fn checked_mul_u64(a: u64, b: u64) -> Result<u64, RetainedByteSizeError> {
    a.checked_mul(b).ok_or(RetainedByteSizeError::Unrepresentable)
}

impl std::fmt::Debug for VerifiedQuorumCertificate {
    /// Bounded debug output: summarizes counts and context without dumping the
    /// whole certificate, its signature bytes, or any key material.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerifiedQuorumCertificate")
            .field("signer_count", &self.signers.len())
            .field("verified_voting_power", &self.verified_voting_power)
            .field("threshold", &self.threshold)
            .field("expected_wire_chain_id", &self.expected_wire_chain_id)
            .field("authorized_epoch", &self.authorized_epoch)
            .field("qc_height", &self.certificate.height)
            .field("qc_round", &self.certificate.round)
            .field("qc_epoch", &self.certificate.epoch)
            .finish()
    }
}

/// Checked membership bounds recomputed from the trusted validator set.
struct MembershipBounds {
    /// The positive, representable total voting power `W`.
    total_voting_power: u64,
    /// The maximum accepted `signer_bitmap` length, in bytes, implied by the
    /// membership's identifier span: the byte span required to represent bit
    /// indices `0..=max_id`. `0` for an empty set.
    max_bitmap_bytes: usize,
}

/// Recompute the trusted membership's total voting power with checked
/// arithmetic, validate every id is representable as a u16 wire index, and
/// derive the membership identifier span (in bytes) for the bitmap bound.
///
/// Returns the positive, representable total `W` and the membership-relative
/// bitmap byte span. This deliberately does **not** trust the set's cached
/// (saturating) total or `two_thirds_vp()`'s `2 * total` u64 arithmetic, and
/// uses the *identifier span* (largest `ValidatorId`), never `validators.len()`,
/// so sparse and reordered memberships remain valid.
fn validate_membership_bounds(
    validators: &ConsensusValidatorSet,
) -> Result<MembershipBounds, QcDomainVerifyError> {
    let mut total: u64 = 0;
    let mut max_id: Option<u64> = None;
    for entry in validators.iter() {
        let id = entry.id.as_u64();
        if id > u16::MAX as u64 {
            return Err(QcDomainVerifyError::MembershipIdNotRepresentable(entry.id));
        }
        max_id = Some(match max_id {
            Some(m) => m.max(id),
            None => id,
        });
        total = total
            .checked_add(entry.voting_power)
            .ok_or(QcDomainVerifyError::TotalVotingPowerOverflow)?;
    }
    if total == 0 {
        return Err(QcDomainVerifyError::ZeroTotalVotingPower);
    }
    // Byte span needed to represent bit indices 0..=max_id. Since every id is
    // <= u16::MAX (65535), this is <= 8192 == MAX_BITMAP_LEN. Empty set -> 0.
    let max_bitmap_bytes = match max_id {
        Some(m) => (m as usize / 8) + 1,
        None => 0,
    };
    Ok(MembershipBounds {
        total_voting_power: total,
        max_bitmap_bytes,
    })
}

/// Accumulate the aggregate byte length of all constituent signatures with
/// checked arithmetic and validate it against [`MAX_AGGREGATE_SIGNATURE_BYTES`].
///
/// This is pure allocation arithmetic — it never allocates or clones signature
/// buffers — so its acceptance/rejection boundary can be exercised directly
/// without multi-gigabyte test allocations. A checked-add overflow is reported
/// as [`QcDomainVerifyError::AggregateSignatureBytesTooLarge`] with the
/// aggregate saturated to `usize::MAX`.
pub fn checked_aggregate_signature_bytes<I>(sig_lens: I) -> Result<usize, QcDomainVerifyError>
where
    I: IntoIterator<Item = usize>,
{
    let mut aggregate: usize = 0;
    for len in sig_lens {
        aggregate = aggregate.checked_add(len).ok_or(
            QcDomainVerifyError::AggregateSignatureBytesTooLarge {
                aggregate: usize::MAX,
                max: MAX_AGGREGATE_SIGNATURE_BYTES,
            },
        )?;
        if aggregate > MAX_AGGREGATE_SIGNATURE_BYTES {
            return Err(QcDomainVerifyError::AggregateSignatureBytesTooLarge {
                aggregate,
                max: MAX_AGGREGATE_SIGNATURE_BYTES,
            });
        }
    }
    Ok(aggregate)
}

/// Collect the signer identities implied by the set bits of a validated bitmap,
/// in ascending-bit order. Bit `i` -> wire `validator_index = i` ->
/// `ValidatorId(i)`, matching D6. Each index is checked representable as a u16
/// (fail-closed), though the prior bitmap-length bounds already guarantee it.
///
/// The returned length equals `popcount(bitmap)`.
fn collect_signers(bitmap: &[u8]) -> Result<Vec<ValidatorId>, QcDomainVerifyError> {
    let mut signers: Vec<ValidatorId> = Vec::new();
    for (byte_index, byte) in bitmap.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        for bit in 0..8u32 {
            if (byte & (1u8 << bit)) == 0 {
                continue;
            }
            let index_u32 = (byte_index as u32) * 8 + bit;
            if index_u32 > u16::MAX as u32 {
                return Err(QcDomainVerifyError::SignerIndexNotRepresentable { index: index_u32 });
            }
            signers.push(ValidatorId::new(index_u32 as u64));
        }
    }
    Ok(signers)
}

/// Compute the `ceil(2W/3)` quorum threshold using wide (`u128`) arithmetic.
///
/// This is the checked equivalent of [`ConsensusValidatorSet::two_thirds_vp`]:
/// it computes the identical mathematical value while avoiding that helper's
/// `2 * total` u64 overflow. Because `ceil(2W/3) <= W <= u64::MAX`, the result
/// always fits `u64`.
fn checked_two_thirds(total: u64) -> u64 {
    let t = total as u128;
    let need = (2 * t).div_ceil(3);
    // ceil(2W/3) <= W <= u64::MAX, so the cast never truncates.
    debug_assert!(need <= u64::MAX as u128);
    need as u64
}

/// Verify the constituent `Vote` signatures and aggregate voting power of a
/// wire [`QuorumCertificate`](qbind_wire::consensus::QuorumCertificate) under a
/// trusted D6 signing `domain`.
///
/// See the module documentation for the full contract. In order:
///
/// 1. `qc.chain_id == domain.expected_wire_chain_id()` (else
///    [`QcDomainVerifyError::WireChainMismatch`], before crypto).
/// 2. `qc.epoch == authorized_epoch` (else [`QcDomainVerifyError::EpochMismatch`],
///    before crypto).
/// 3. Checked, representable, positive total voting power `W`, and the
///    membership identifier span used to bound the bitmap.
/// 4. Complete structural preflight, **all before the cryptographic loop and any
///    signature clone**: signature-count representability
///    (`signatures.len() <= MAX_SIGNATURE_COUNT`), global bitmap length
///    (`<= MAX_BITMAP_LEN`), membership-relative bitmap span, every set bit
///    representable as a u16 index, `popcount(bitmap) == signatures.len()`,
///    every individual signature length (`<= MAX_SIGNATURE_LEN`), and the
///    checked aggregate signature-byte bound (`MAX_AGGREGATE_SIGNATURE_BYTES`).
///    An oversized late signature (or an unrepresentable count) therefore
///    rejects before *any* backend invocation.
/// 5. For each set bit in ascending order (associating signatures in the same
///    order): reconstruct the `Vote` from the QC's *actual* fields plus the
///    bit-derived index and its signature and verify via
///    [`verify_vote_msg_with_domain`]. Accumulate the signer's voting power once
///    (checked).
/// 6. Require `accumulated >= ceil(2W/3)`.
///
/// Every declared signature is verified even after quorum is reached. On any
/// failure no partial [`VerifiedQuorumCertificate`] is produced.
pub fn verify_quorum_certificate_with_domain<K, B>(
    qc: &WireQuorumCertificate,
    domain: &ProposalVoteSigningDomainV2,
    authorized_epoch: u64,
    validators: &ConsensusValidatorSet,
    key_provider: &K,
    backend_registry: &B,
) -> Result<VerifiedQuorumCertificate, QcDomainVerifyError>
where
    K: SuiteAwareValidatorKeyProvider + ?Sized,
    B: ConsensusSigBackendRegistry + ?Sized,
{
    // Step 1: domain wire-chain gate (before any crypto or buffer clone).
    let expected_wire_chain_id = domain.expected_wire_chain_id();
    if qc.chain_id != expected_wire_chain_id {
        return Err(QcDomainVerifyError::WireChainMismatch {
            expected: expected_wire_chain_id,
            actual: qc.chain_id,
        });
    }

    // Step 2: epoch gate (before any crypto or buffer clone).
    if qc.epoch != authorized_epoch {
        return Err(QcDomainVerifyError::EpochMismatch {
            expected: authorized_epoch,
            actual: qc.epoch,
        });
    }

    // Step 3: checked, representable, positive total voting power, plus the
    // membership identifier span used to bound the bitmap.
    let bounds = validate_membership_bounds(validators)?;
    let total_voting_power = bounds.total_voting_power;
    let threshold = checked_two_thirds(total_voting_power);

    // Step 4a: signature-count representability. The wire `sig_count` is a u16,
    // so reject an unrepresentable count BEFORE any crypto or signer-result
    // allocation. (An 8192-byte bitmap could imply 65536 set bits; the count
    // bound is enforced explicitly rather than inferred from the bitmap.)
    if qc.signatures.len() > MAX_SIGNATURE_COUNT {
        return Err(QcDomainVerifyError::SignatureCountNotRepresentable {
            count: qc.signatures.len(),
            max: MAX_SIGNATURE_COUNT,
        });
    }

    // Step 4b: global bitmap length bound (bounds work and guarantees
    // representable indices).
    if qc.signer_bitmap.len() > MAX_BITMAP_LEN {
        return Err(QcDomainVerifyError::BitmapTooLong {
            len: qc.signer_bitmap.len(),
            max: MAX_BITMAP_LEN,
        });
    }

    // Step 4c: membership-relative bitmap span. Reject any byte beyond the
    // trusted identifier span, INCLUDING trailing zero padding. Uses the
    // identifier span (largest ValidatorId), never validators.len(), so sparse
    // and reordered memberships remain valid.
    if qc.signer_bitmap.len() > bounds.max_bitmap_bytes {
        return Err(QcDomainVerifyError::BitmapBeyondMembershipSpan {
            len: qc.signer_bitmap.len(),
            allowed: bounds.max_bitmap_bytes,
        });
    }

    // Step 4d: collect_signers materializes the ascending-bit-order signer
    // vector, then popcount(bitmap) == signatures.len() is checked against it.
    // The temporary vector is bounded by the bitmap's capacity: before this
    // correspondence succeeds it can hold up to 65536 entries (a full 8192-byte
    // bitmap's popcount, one more than MAX_SIGNATURE_COUNT). Only after the
    // correspondence succeeds is it bounded by MAX_SIGNATURE_COUNT, because the
    // count was already checked representable and popcount must equal it.
    let signers = collect_signers(&qc.signer_bitmap)?;
    if signers.len() != qc.signatures.len() {
        return Err(QcDomainVerifyError::SignatureCountMismatch {
            popcount: signers.len(),
            signatures: qc.signatures.len(),
        });
    }

    // Step 4e: complete per-signature size validation BEFORE any clone or
    // cryptographic work. Signatures associate with set bits in ascending-bit
    // order, so signers[k] owns signatures[k]; an oversized signature at ANY
    // position (including after quorum would be reached) rejects here — before
    // any backend invocation. (Empty signatures are left to the reused D6
    // MissingSignature check for a precise diagnostic.)
    for (signer, signature) in signers.iter().zip(qc.signatures.iter()) {
        if signature.len() > MAX_SIGNATURE_LEN {
            return Err(QcDomainVerifyError::MalformedSignature(*signer));
        }
    }

    // Step 4f: checked aggregate signature-byte bound (allocation arithmetic).
    let _aggregate_bytes =
        checked_aggregate_signature_bytes(qc.signatures.iter().map(|s| s.len()))?;

    // Step 5: verify each declared signature, associating signatures with set
    // bits in ascending-bit order. ALL signatures are verified — quorum is
    // checked only after the loop, so an invalid extra signature still rejects.
    let mut accumulated: u64 = 0;

    for (signer, signature) in signers.iter().zip(qc.signatures.iter()) {
        let signer = *signer;
        // Bit → wire validator_index, matching D6's
        // ValidatorId::new(vote.validator_index as u64). The bitmap bounds
        // guarantee this fits u16.
        let validator_index = signer.as_u64() as u16;

        // Reconstruct the Vote from the QC's ACTUAL fields — never
        // substituting trusted values to make a signature pass — plus the
        // bit-derived signer index and its associated signature.
        let vote = Vote {
            version: qc.version,
            chain_id: qc.chain_id,
            epoch: qc.epoch,
            height: qc.height,
            round: qc.round,
            step: qc.step,
            block_id: qc.block_id,
            validator_index,
            suite_id: qc.suite_id,
            signature: signature.clone(),
        };

        // Reuse the D6 message-bound Vote verifier: membership, missing
        // signature, governed key, suite match (QC suite vs governed
        // suite), backend dispatch, and the cryptographic check over the
        // recomputed v2 preimage. `claimed == signer` by construction.
        verify_vote_msg_with_domain(
            &vote,
            signer,
            validators,
            key_provider,
            backend_registry,
            domain,
        )
        .map_err(|e| QcDomainVerifyError::from_pv(signer, e))?;

        // Accumulate this verified signer's voting power exactly once, by
        // ValidatorId lookup and checked arithmetic. Membership was proven
        // by the successful verify above; a present index is therefore
        // expected, but the lookup stays fail-closed.
        let idx = validators
            .index_of(signer)
            .ok_or(QcDomainVerifyError::UnknownSigner(signer))?;
        let entry = validators
            .get(idx)
            .ok_or(QcDomainVerifyError::UnknownSigner(signer))?;
        accumulated = accumulated
            .checked_add(entry.voting_power)
            .ok_or(QcDomainVerifyError::VerifiedPowerOverflow)?;
    }

    // Step 6: quorum. ceil(2W/3) preserved (compatibility behavior).
    if accumulated < threshold {
        return Err(QcDomainVerifyError::InsufficientVotingPower {
            have: accumulated,
            need: threshold,
        });
    }

    Ok(VerifiedQuorumCertificate {
        certificate: qc.clone(),
        signers,
        verified_voting_power: accumulated,
        threshold,
        expected_wire_chain_id,
        authorized_epoch,
        domain: domain.clone(),
    })
}