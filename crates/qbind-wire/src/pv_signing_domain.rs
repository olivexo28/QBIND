//! Run 422 D6 — versioned Proposal/Vote signing-domain isolation.
//!
//! # Purpose
//!
//! This module defines an **explicitly versioned** signing preimage
//! ([`ProposalVoteSigningDomainV2`]) for HotStuff `BlockProposal` and `Vote`
//! traffic that cryptographically binds a signature to the intended network
//! and accepted-authority snapshot. A signature produced for one domain must
//! not authenticate the same message under another domain even when:
//!
//! * the same signing key is reused,
//! * the validator index is unchanged,
//! * the message payload and wire `chain_id` are unchanged,
//! * two runtime chain IDs share the same legacy textual scope (both "UNK"),
//! * two networks share the same runtime [`ChainId`] but have different
//!   accepted genesis identities.
//!
//! This is achieved by prepending a typed, immutable domain header to the
//! **same** canonical body bytes the legacy v1 preimage signs
//! ([`BlockProposal::canonical_body`] / [`Vote::canonical_body`]). No second
//! hash implementation, signature backend, suite, or wire format is
//! introduced — the domain object only controls the *bytes handed to the
//! existing signer/verifier*.
//!
//! # Relationship to the legacy v1 preimage
//!
//! The historical v1 preimage is `domain_prefix(chain_id, kind) || body`,
//! where `domain_prefix` derives a short textual scope ("DEV"/"TST"/"MAIN"/
//! "UNK") from the runtime [`ChainId`]. Two distinct custom chain IDs both map
//! to "UNK", so v1 gives them the *same* domain prefix. Whether that alone
//! allows a cross-chain replay also depends on the signed body (the body
//! embeds the wire `chain_id`); but v1 provides no binding at all to the
//! accepted genesis identity or to the accepted consensus-authority snapshot.
//! The v2 domain closes both gaps by binding the full 64-bit runtime
//! [`ChainId`], the accepted 32-byte genesis identity, and a 32-byte consensus
//! authority commitment.
//!
//! # Byte layout (v2)
//!
//! ```text
//! offset  field                     width  encoding
//! ------  ------------------------  -----  -------------------------------
//! 0       domain_tag                17     ASCII "QBIND:PVDOMAIN:v2"
//! 17      signing_format_version    1      u8, MUST be 2
//! 18      message_family            1      u8, 1 = Proposal, 2 = Vote
//! 19      runtime_chain_id          8      u64, big-endian (full ChainId)
//! 27      expected_wire_chain_id    4      u32, big-endian
//! 31      genesis_identity          32     raw bytes (accepted genesis hash)
//! 63      authority_commitment      32     raw bytes (authority snapshot)
//! 95      body_len                  8      u64, big-endian
//! 103     body                      N      canonical_body() of the message
//! ```
//!
//! Every variable-length field is length-prefixed and every fixed field has a
//! fixed width, so the encoding is unambiguous (no concatenation ambiguity).
//! Integers in the *domain header* are big-endian; the appended `body` is the
//! unchanged little-endian v1 field encoding.
//!
//! # What is bound, and how the genesis string identity is covered
//!
//! * **Signing-format version** — the literal `2` byte; a verifier for this
//!   format rejects any other value ([`ProposalVoteSigningFormat::from_u8`]).
//! * **Message family** — Proposal vs Vote, so a Proposal signature can never
//!   authenticate a Vote (and vice versa).
//! * **Full runtime ChainId** — the entire 64-bit value, never truncated to
//!   the 32-bit wire field and never derived from an incoming message.
//! * **Accepted canonical genesis identity** — the boot-verified genesis hash.
//! * **Consensus authority commitment** — identifies the intended
//!   membership/key/suite snapshot. In this repository the commitment produced
//!   by the genesis-bound consensus loader
//!   (`qbind-node::genesis_consensus_authority`) already folds in the genesis
//!   `chain_id` **string**, the genesis hash, and every validator's
//!   `(index, suite, public key)`. Binding that commitment therefore also
//!   binds the genesis chain-name/string identity cryptographically. The
//!   [`genesis_identity`](ProposalVoteSigningDomainV2::genesis_identity) field
//!   binds the genesis hash *directly and explicitly* in addition, so the
//!   binding does not depend solely on how the commitment was computed.
//!
//! A commitment included in a signature identifies the *intended* authority
//! snapshot. It does **not** prove that snapshot is current or authorized for
//! a later epoch — authority freshness/lifetime (D7) is out of scope here.

use crate::consensus::{BlockProposal, Vote};
use crate::io::{put_bytes, put_u8};
use qbind_types::ChainId;

/// ASCII domain tag prefixing every v2 Proposal/Vote signing preimage.
///
/// Distinct from the legacy `QBIND:<SCOPE>:PROPOSAL:v1` / `:VOTE:v1` tags, so
/// a v2 preimage can never collide with a v1 preimage for any input.
pub const PV_SIGNING_DOMAIN_V2_TAG: &[u8] = b"QBIND:PVDOMAIN:v2";

/// The single supported signing-format version for this module.
pub const PV_SIGNING_FORMAT_VERSION_V2: u8 = 2;

/// Explicit signing-format version selector.
///
/// The signing format version is deliberately **separate** from the
/// cryptographic suite id: choosing a suite never changes the format, and
/// choosing a format never changes the suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProposalVoteSigningFormat {
    /// Versioned domain that binds runtime chain id + genesis identity +
    /// authority commitment (this module).
    V2,
}

impl ProposalVoteSigningFormat {
    /// Numeric on-the-wire version byte for this format.
    pub const fn version_byte(self) -> u8 {
        match self {
            ProposalVoteSigningFormat::V2 => PV_SIGNING_FORMAT_VERSION_V2,
        }
    }

    /// Parse a signing-format version byte, rejecting unsupported versions
    /// explicitly. There is **no** fallback to another version.
    pub fn from_u8(v: u8) -> Result<Self, PvSigningDomainError> {
        match v {
            PV_SIGNING_FORMAT_VERSION_V2 => Ok(ProposalVoteSigningFormat::V2),
            other => Err(PvSigningDomainError::UnsupportedVersion(other)),
        }
    }
}

/// Which consensus message family a domain/preimage is bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProposalVoteMessageFamily {
    /// A `BlockProposal`.
    Proposal,
    /// A `Vote`.
    Vote,
}

impl ProposalVoteMessageFamily {
    /// Fixed byte tag for this message family (1 = Proposal, 2 = Vote).
    pub const fn tag(self) -> u8 {
        match self {
            ProposalVoteMessageFamily::Proposal => 1,
            ProposalVoteMessageFamily::Vote => 2,
        }
    }
}

/// Errors from constructing or parsing a versioned Proposal/Vote domain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PvSigningDomainError {
    /// The accepted genesis identity was all-zero. A domain must never default
    /// a missing genesis identity to zeros (or to DevNet).
    ZeroGenesisIdentity,
    /// The consensus authority commitment was all-zero. A domain must never
    /// default a missing authority commitment to zeros.
    ZeroAuthorityCommitment,
    /// A signing-format version byte other than a supported one was seen.
    UnsupportedVersion(u8),
}

impl std::fmt::Display for PvSigningDomainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PvSigningDomainError::ZeroGenesisIdentity => {
                write!(f, "genesis identity must not be all-zero")
            }
            PvSigningDomainError::ZeroAuthorityCommitment => {
                write!(f, "authority commitment must not be all-zero")
            }
            PvSigningDomainError::UnsupportedVersion(v) => {
                write!(f, "unsupported Proposal/Vote signing-format version: {}", v)
            }
        }
    }
}

impl std::error::Error for PvSigningDomainError {}

/// Immutable, validated versioned Proposal/Vote signing domain (v2).
///
/// Construct with [`ProposalVoteSigningDomainV2::try_new`], which rejects an
/// all-zero genesis identity or authority commitment. All fields are private
/// and immutable after construction: the domain a node signs/verifies under is
/// selected from trusted configuration/validated authority, never from
/// attacker-controlled wire data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalVoteSigningDomainV2 {
    runtime_chain_id: ChainId,
    expected_wire_chain_id: u32,
    genesis_identity: [u8; 32],
    authority_commitment: [u8; 32],
}

impl ProposalVoteSigningDomainV2 {
    /// Construct a validated v2 signing domain.
    ///
    /// * `runtime_chain_id` — the full 64-bit runtime chain id of the accepted
    ///   network.
    /// * `expected_wire_chain_id` — the wire `chain_id` (u32) that authentic
    ///   messages on this network must carry. This is trusted configuration:
    ///   it is **not** derived from any incoming message. The runtime→wire
    ///   chain-id relationship is not resolved by a validated mapping in this
    ///   repository, so callers must supply it explicitly; production activation
    ///   remains unavailable until that mapping exists (D7/downstream).
    /// * `genesis_identity` — the accepted canonical genesis hash. Must be
    ///   non-zero.
    /// * `authority_commitment` — the accepted consensus-authority snapshot
    ///   commitment. Must be non-zero.
    pub fn try_new(
        runtime_chain_id: ChainId,
        expected_wire_chain_id: u32,
        genesis_identity: [u8; 32],
        authority_commitment: [u8; 32],
    ) -> Result<Self, PvSigningDomainError> {
        if genesis_identity == [0u8; 32] {
            return Err(PvSigningDomainError::ZeroGenesisIdentity);
        }
        if authority_commitment == [0u8; 32] {
            return Err(PvSigningDomainError::ZeroAuthorityCommitment);
        }
        Ok(Self {
            runtime_chain_id,
            expected_wire_chain_id,
            genesis_identity,
            authority_commitment,
        })
    }

    /// The full runtime chain id bound by this domain.
    pub fn runtime_chain_id(&self) -> ChainId {
        self.runtime_chain_id
    }

    /// The expected wire `chain_id` (u32) authentic messages must carry.
    pub fn expected_wire_chain_id(&self) -> u32 {
        self.expected_wire_chain_id
    }

    /// The accepted canonical genesis identity bound by this domain.
    pub fn genesis_identity(&self) -> &[u8; 32] {
        &self.genesis_identity
    }

    /// The accepted consensus-authority commitment bound by this domain.
    pub fn authority_commitment(&self) -> &[u8; 32] {
        &self.authority_commitment
    }

    /// The signing-format version this domain uses.
    pub const fn format(&self) -> ProposalVoteSigningFormat {
        ProposalVoteSigningFormat::V2
    }

    /// Build the v2 signing preimage for a `BlockProposal`.
    ///
    /// Binds the `Proposal` message family plus this domain's chain/genesis/
    /// authority identity to the proposal's canonical body.
    pub fn proposal_preimage(&self, proposal: &BlockProposal) -> Vec<u8> {
        self.build_preimage(
            ProposalVoteMessageFamily::Proposal,
            &proposal.canonical_body(),
        )
    }

    /// Build the v2 signing preimage for a `Vote`.
    ///
    /// Binds the `Vote` message family plus this domain's chain/genesis/
    /// authority identity to the vote's canonical body.
    pub fn vote_preimage(&self, vote: &Vote) -> Vec<u8> {
        self.build_preimage(ProposalVoteMessageFamily::Vote, &vote.canonical_body())
    }

    /// Core preimage assembly shared by proposal and vote. See the module
    /// docs for the exact byte layout.
    fn build_preimage(&self, family: ProposalVoteMessageFamily, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            PV_SIGNING_DOMAIN_V2_TAG.len() + 1 + 1 + 8 + 4 + 32 + 32 + 8 + body.len(),
        );
        // Fixed domain tag.
        put_bytes(&mut out, PV_SIGNING_DOMAIN_V2_TAG);
        // Explicit signing-format version.
        put_u8(&mut out, PV_SIGNING_FORMAT_VERSION_V2);
        // Message family.
        put_u8(&mut out, family.tag());
        // Full 64-bit runtime chain id (big-endian). Never truncated.
        out.extend_from_slice(&self.runtime_chain_id.as_u64().to_be_bytes());
        // Expected wire chain id (big-endian).
        out.extend_from_slice(&self.expected_wire_chain_id.to_be_bytes());
        // Accepted genesis identity.
        put_bytes(&mut out, &self.genesis_identity);
        // Accepted authority commitment.
        put_bytes(&mut out, &self.authority_commitment);
        // Length-framed canonical body.
        out.extend_from_slice(&(body.len() as u64).to_be_bytes());
        put_bytes(&mut out, body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::{BlockHeader, BlockProposal, Vote};

    fn dummy_domain(
        runtime: u64,
        wire: u32,
        genesis: [u8; 32],
        commitment: [u8; 32],
    ) -> ProposalVoteSigningDomainV2 {
        ProposalVoteSigningDomainV2::try_new(ChainId(runtime), wire, genesis, commitment)
            .expect("valid domain")
    }

    fn header() -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: 7,
            epoch: 0,
            height: 3,
            round: 3,
            parent_block_id: [1u8; 32],
            payload_hash: [2u8; 32],
            proposer_index: 4,
            suite_id: 100,
            tx_count: 0,
            timestamp: 0,
            payload_kind: 0,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        }
    }

    fn proposal() -> BlockProposal {
        BlockProposal {
            header: header(),
            qc: None,
            txs: vec![],
            signature: vec![],
        }
    }

    fn vote() -> Vote {
        Vote {
            version: 1,
            chain_id: 7,
            epoch: 0,
            height: 3,
            round: 3,
            step: 0,
            block_id: [5u8; 32],
            validator_index: 4,
            suite_id: 100,
            signature: vec![],
        }
    }

    #[test]
    fn try_new_rejects_zero_genesis_identity() {
        let e = ProposalVoteSigningDomainV2::try_new(ChainId(1), 7, [0u8; 32], [9u8; 32])
            .expect_err("must reject zero genesis");
        assert_eq!(e, PvSigningDomainError::ZeroGenesisIdentity);
    }

    #[test]
    fn try_new_rejects_zero_authority_commitment() {
        let e = ProposalVoteSigningDomainV2::try_new(ChainId(1), 7, [9u8; 32], [0u8; 32])
            .expect_err("must reject zero commitment");
        assert_eq!(e, PvSigningDomainError::ZeroAuthorityCommitment);
    }

    #[test]
    fn unsupported_version_is_rejected_no_fallback() {
        assert_eq!(
            ProposalVoteSigningFormat::from_u8(2).unwrap(),
            ProposalVoteSigningFormat::V2
        );
        assert_eq!(
            ProposalVoteSigningFormat::from_u8(1),
            Err(PvSigningDomainError::UnsupportedVersion(1))
        );
        assert_eq!(
            ProposalVoteSigningFormat::from_u8(3),
            Err(PvSigningDomainError::UnsupportedVersion(3))
        );
    }

    #[test]
    fn preimage_starts_with_v2_tag_and_version() {
        let d = dummy_domain(1, 7, [1u8; 32], [2u8; 32]);
        let pre = d.proposal_preimage(&proposal());
        assert!(pre.starts_with(PV_SIGNING_DOMAIN_V2_TAG));
        assert_eq!(
            pre[PV_SIGNING_DOMAIN_V2_TAG.len()],
            PV_SIGNING_FORMAT_VERSION_V2
        );
        // family byte follows the version byte.
        assert_eq!(pre[PV_SIGNING_DOMAIN_V2_TAG.len() + 1], 1); // Proposal
        let pre_v = d.vote_preimage(&vote());
        assert_eq!(pre_v[PV_SIGNING_DOMAIN_V2_TAG.len() + 1], 2); // Vote
    }

    #[test]
    fn family_isolation_proposal_ne_vote() {
        // Even if a Proposal and a Vote happened to have identical bodies, the
        // family byte differs, so the preimages differ.
        let d = dummy_domain(1, 7, [1u8; 32], [2u8; 32]);
        let p = d.proposal_preimage(&proposal());
        let v = d.vote_preimage(&vote());
        assert_ne!(p, v);
    }

    #[test]
    fn different_full_runtime_chain_id_changes_preimage_same_legacy_scope() {
        // Two custom chain IDs that both map to legacy "UNK" produce IDENTICAL
        // v1 prefixes but DISTINCT v2 preimages.
        let g = [3u8; 32];
        let c = [4u8; 32];
        let d1 = dummy_domain(0xAAAA_0000_0000_0001, 7, g, c);
        let d2 = dummy_domain(0xBBBB_0000_0000_0002, 7, g, c);
        let v = vote();
        // v1 legacy prefixes collide ("UNK").
        assert_eq!(
            qbind_types::domain::chain_scope(d1.runtime_chain_id()),
            "UNK"
        );
        assert_eq!(
            qbind_types::domain::chain_scope(d2.runtime_chain_id()),
            "UNK"
        );
        // v2 preimages differ because the full 64-bit chain id is bound.
        assert_ne!(d1.vote_preimage(&v), d2.vote_preimage(&v));
    }

    #[test]
    fn different_genesis_identity_changes_preimage() {
        let c = [4u8; 32];
        let d1 = dummy_domain(9, 7, [1u8; 32], c);
        let d2 = dummy_domain(9, 7, [2u8; 32], c);
        let v = vote();
        assert_ne!(d1.vote_preimage(&v), d2.vote_preimage(&v));
    }

    #[test]
    fn different_authority_commitment_changes_preimage() {
        let g = [1u8; 32];
        let d1 = dummy_domain(9, 7, g, [4u8; 32]);
        let d2 = dummy_domain(9, 7, g, [5u8; 32]);
        let v = vote();
        assert_ne!(d1.vote_preimage(&v), d2.vote_preimage(&v));
    }

    #[test]
    fn v2_preimage_ends_with_canonical_body() {
        // The v2 preimage embeds exactly the same canonical body the v1
        // preimage signs (framed), proving no divergent field re-encoding.
        let d = dummy_domain(9, 7, [1u8; 32], [2u8; 32]);
        let v = vote();
        let body = v.canonical_body();
        let pre = d.vote_preimage(&v);
        assert!(pre.ends_with(&body));
    }
}
