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
//! # Size bounds
//!
//! * Bitmap length ≤ [`MAX_BITMAP_LEN`] (8192 bytes). Any bit in a longer
//!   bitmap could imply a `validator_index > u16::MAX` (unrepresentable by the
//!   wire field), so the cap simultaneously bounds work and guarantees every
//!   set bit maps to a representable u16 index.
//! * `popcount(bitmap) == signatures.len()` is required; signatures are
//!   associated with set bits in ascending-bit order.
//! * Each signature length ≤ [`MAX_SIGNATURE_LEN`] (the wire u16 length bound).
//! * The only per-signer allocation is a single clone of that signer's
//!   signature into the reconstructed `Vote` (bounded by `MAX_SIGNATURE_LEN`);
//!   sizes are validated *before* that clone and before any cryptographic work.
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
//! This module is **uncalled** by the production engine, node startup,
//! handlers, cache, storage, and activation paths. Its only callers are tests.

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

/// Recompute the trusted membership's total voting power with checked
/// arithmetic and validate every id is representable as a u16 wire index.
///
/// Returns the positive, representable total `W`. This deliberately does **not**
/// trust the set's cached (saturating) total or `two_thirds_vp()`'s `2 * total`
/// u64 arithmetic.
fn validate_total_voting_power(
    validators: &ConsensusValidatorSet,
) -> Result<u64, QcDomainVerifyError> {
    let mut total: u64 = 0;
    for entry in validators.iter() {
        if entry.id.as_u64() > u16::MAX as u64 {
            return Err(QcDomainVerifyError::MembershipIdNotRepresentable(entry.id));
        }
        total = total
            .checked_add(entry.voting_power)
            .ok_or(QcDomainVerifyError::TotalVotingPowerOverflow)?;
    }
    if total == 0 {
        return Err(QcDomainVerifyError::ZeroTotalVotingPower);
    }
    Ok(total)
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
/// 3. Checked, representable, positive total voting power `W`.
/// 4. Structural bounds: `bitmap.len() <= MAX_BITMAP_LEN`, every set bit
///    representable as a u16 index, `popcount(bitmap) == signatures.len()`.
/// 5. For each set bit in ascending order (associating signatures in the same
///    order): reconstruct the `Vote` from the QC's *actual* fields plus the
///    bit-derived index and its signature, validate the signature length, and
///    verify via [`verify_vote_msg_with_domain`]. Accumulate the signer's
///    voting power once (checked).
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

    // Step 3: checked, representable, positive total voting power.
    let total_voting_power = validate_total_voting_power(validators)?;
    let threshold = checked_two_thirds(total_voting_power);

    // Step 4a: bitmap length bound (bounds work and guarantees representable
    // indices).
    if qc.signer_bitmap.len() > MAX_BITMAP_LEN {
        return Err(QcDomainVerifyError::BitmapTooLong {
            len: qc.signer_bitmap.len(),
            max: MAX_BITMAP_LEN,
        });
    }

    // Step 4b: popcount(bitmap) == signatures.len().
    let popcount: usize = qc
        .signer_bitmap
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum();
    if popcount != qc.signatures.len() {
        return Err(QcDomainVerifyError::SignatureCountMismatch {
            popcount,
            signatures: qc.signatures.len(),
        });
    }

    // Step 5: verify each declared signature, associating signatures with set
    // bits in ascending-bit order. ALL signatures are verified — quorum is
    // checked only after the loop, so an invalid extra signature still rejects.
    let mut signers: Vec<ValidatorId> = Vec::with_capacity(popcount);
    let mut accumulated: u64 = 0;
    let mut sig_iter = qc.signatures.iter();

    for (byte_index, byte) in qc.signer_bitmap.iter().enumerate() {
        if *byte == 0 {
            continue;
        }
        for bit in 0..8u32 {
            if (byte & (1u8 << bit)) == 0 {
                continue;
            }
            // Bit → wire validator_index, matching D6's
            // ValidatorId::new(vote.validator_index as u64). The MAX_BITMAP_LEN
            // cap guarantees this fits u16, but the check is explicit and
            // fail-closed rather than a narrowing cast.
            let index_u32 = (byte_index as u32) * 8 + bit;
            if index_u32 > u16::MAX as u32 {
                return Err(QcDomainVerifyError::SignerIndexNotRepresentable { index: index_u32 });
            }
            let validator_index = index_u32 as u16;
            let signer = ValidatorId::new(index_u32 as u64);

            // Ascending-order signature association.
            let signature = sig_iter
                .next()
                .ok_or(QcDomainVerifyError::SignatureCountMismatch {
                    popcount,
                    signatures: qc.signatures.len(),
                })?;

            // Validate signature size BEFORE cloning it into the Vote or doing
            // cryptographic work. (Empty signatures are left to the reused D6
            // MissingSignature check for a precise diagnostic.)
            if signature.len() > MAX_SIGNATURE_LEN {
                return Err(QcDomainVerifyError::MalformedSignature(signer));
            }

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

            signers.push(signer);
        }
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