//! Domain separation helpers for QBIND signing preimages (T159).
//!
//! This module provides a centralized, chain-aware domain-separation scheme for all
//! signed objects in QBIND. By including the chain ID in all signing preimages,
//! we prevent cross-chain replay attacks between DevNet, TestNet, and MainNet.
//!
//! # Domain Tag Format
//!
//! All domain tags follow the format:
//!
//! ```text
//! QBIND:<SCOPE>:<KIND>:v1
//! ```
//!
//! Where:
//! - `SCOPE` is derived from the chain ID: "DEV", "TST", "MAIN", or "UNK" (unknown)
//! - `KIND` identifies the type of signed object (e.g., "TX", "BATCH", "VOTE")
//! - `v1` is the version number (for future format changes)
//!
//! # Examples
//!
//! ```text
//! QBIND:DEV:TX:v1       - User transaction on DevNet
//! QBIND:TST:BATCH:v1    - DAG batch on TestNet
//! QBIND:MAIN:VOTE:v1    - Consensus vote on MainNet
//! QBIND:DEV:PROPOSAL:v1 - Block proposal on DevNet
//! QBIND:DEV:TIMEOUT:v1  - Timeout message on DevNet
//! QBIND:DEV:NEWVIEW:v1  - NewView message on DevNet
//! ```
//!
//! # Security Properties
//!
//! - **Cross-chain isolation**: Signatures created on one chain cannot be verified
//!   on another chain because the domain tag includes the chain scope.
//! - **Type isolation**: Signatures for one object type cannot be confused with
//!   another type because the kind is part of the domain tag.
//! - **Version isolation**: Future format changes can use a new version number
//!   without breaking existing signatures.
//!
//! # Usage
//!
//! All signing preimage functions should use `domain_prefix()` to obtain the
//! appropriate domain tag bytes:
//!
//! ```rust,ignore
//! use qbind_types::domain::{domain_prefix, DomainKind};
//! use qbind_types::ChainId;
//!
//! fn signing_preimage(chain_id: ChainId, ...) -> Vec<u8> {
//!     let mut preimage = domain_prefix(chain_id, DomainKind::UserTx);
//!     // ... append other fields ...
//!     preimage
//! }
//! ```

use crate::{ChainId, QBIND_DEVNET_CHAIN_ID, QBIND_MAINNET_CHAIN_ID, QBIND_TESTNET_CHAIN_ID};

/// The types of signed objects in QBIND.
///
/// Each variant corresponds to a specific signed object type, which determines
/// the "kind" portion of the domain tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DomainKind {
    /// User transaction signing preimage.
    ///
    /// Domain tag: `QBIND:<SCOPE>:TX:v1`
    UserTx,

    /// DAG mempool batch signing preimage.
    ///
    /// Domain tag: `QBIND:<SCOPE>:BATCH:v1`
    Batch,

    /// Consensus vote signing preimage.
    ///
    /// Domain tag: `QBIND:<SCOPE>:VOTE:v1`
    Vote,

    /// Block proposal signing preimage.
    ///
    /// Domain tag: `QBIND:<SCOPE>:PROPOSAL:v1`
    Proposal,

    /// Timeout message signing preimage.
    ///
    /// Domain tag: `QBIND:<SCOPE>:TIMEOUT:v1`
    Timeout,

    /// NewView/pacemaker message signing preimage.
    ///
    /// Domain tag: `QBIND:<SCOPE>:NEWVIEW:v1`
    NewView,

    /// Batch acknowledgment signing preimage (T165).
    ///
    /// Domain tag: `QBIND:<SCOPE>:BATCH_ACK:v1`
    BatchAck,
}

impl DomainKind {
    /// Get the kind string for this domain type.
    ///
    /// This is the middle portion of the domain tag (e.g., "TX", "BATCH", "VOTE").
    pub const fn kind_str(&self) -> &'static str {
        match self {
            DomainKind::UserTx => "TX",
            DomainKind::Batch => "BATCH",
            DomainKind::Vote => "VOTE",
            DomainKind::Proposal => "PROPOSAL",
            DomainKind::Timeout => "TIMEOUT",
            DomainKind::NewView => "NEWVIEW",
            DomainKind::BatchAck => "BATCH_ACK",
        }
    }
}

/// Get the chain scope string from a ChainId.
///
/// Returns:
/// - "DEV" for QBIND_DEVNET_CHAIN_ID
/// - "TST" for QBIND_TESTNET_CHAIN_ID
/// - "MAIN" for QBIND_MAINNET_CHAIN_ID
/// - "UNK" for any unknown chain ID
///
/// # Note
///
/// Unknown chain IDs are intentionally supported to allow custom/private networks
/// to use the same domain-separation scheme. However, the "UNK" scope provides
/// weaker isolation guarantees since different unknown chains will share the
/// same scope prefix.
pub fn chain_scope(chain_id: ChainId) -> &'static str {
    if chain_id == QBIND_DEVNET_CHAIN_ID {
        "DEV"
    } else if chain_id == QBIND_TESTNET_CHAIN_ID {
        "TST"
    } else if chain_id == QBIND_MAINNET_CHAIN_ID {
        "MAIN"
    } else {
        "UNK"
    }
}

/// Compute the domain-separation prefix for a signing preimage.
///
/// This function returns the byte sequence that should be prepended to all
/// signing preimages to ensure domain separation.
///
/// # Format
///
/// ```text
/// QBIND:<SCOPE>:<KIND>:v1
/// ```
///
/// # Arguments
///
/// - `chain_id`: The chain ID for determining the scope prefix
/// - `kind`: The type of signed object
///
/// # Returns
///
/// A byte vector containing the domain tag.
///
/// # Examples
///
/// ```rust,ignore
/// use qbind_types::domain::{domain_prefix, DomainKind};
/// use qbind_types::QBIND_DEVNET_CHAIN_ID;
///
/// let prefix = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::UserTx);
/// assert_eq!(prefix, b"QBIND:DEV:TX:v1");
///
/// let prefix = domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::Vote);
/// assert_eq!(prefix, b"QBIND:TST:VOTE:v1");
/// ```
pub fn domain_prefix(chain_id: ChainId, kind: DomainKind) -> Vec<u8> {
    let scope = chain_scope(chain_id);
    let kind_str = kind.kind_str();
    format!("QBIND:{}:{}:v1", scope, kind_str).into_bytes()
}

// ============================================================================
// Legacy domain tags (for documentation/reference)
// ============================================================================

/// Legacy domain tag for user transactions.
///
/// **DEPRECATED**: Use `domain_prefix(chain_id, DomainKind::UserTx)` instead.
///
/// This constant is provided for documentation purposes and to help identify
/// where legacy tags were used. New code should always use `domain_prefix()`.
pub const LEGACY_TX_DOMAIN_TAG: &[u8] = b"QBIND:TX:v1";

/// Legacy domain tag for DAG batches.
///
/// **DEPRECATED**: Use `domain_prefix(chain_id, DomainKind::Batch)` instead.
pub const LEGACY_BATCH_DOMAIN_TAG: &[u8] = b"QBIND:BATCH:v1";

/// Legacy domain tag for consensus votes.
///
/// **DEPRECATED**: Use `domain_prefix(chain_id, DomainKind::Vote)` instead.
pub const LEGACY_VOTE_DOMAIN_TAG: &[u8] = b"QBIND:VOTE:v1";

/// Legacy domain tag for block proposals.
///
/// **DEPRECATED**: Use `domain_prefix(chain_id, DomainKind::Proposal)` instead.
pub const LEGACY_PROPOSAL_DOMAIN_TAG: &[u8] = b"QBIND:PROPOSAL:v1";

/// Legacy domain separator for timeout messages.
///
/// **DEPRECATED**: Use `domain_prefix(chain_id, DomainKind::Timeout)` instead.
pub const LEGACY_TIMEOUT_DOMAIN_TAG: &[u8] = b"QBIND_TIMEOUT_V1";

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_scope() {
        assert_eq!(chain_scope(QBIND_DEVNET_CHAIN_ID), "DEV");
        assert_eq!(chain_scope(QBIND_TESTNET_CHAIN_ID), "TST");
        assert_eq!(chain_scope(QBIND_MAINNET_CHAIN_ID), "MAIN");
        assert_eq!(chain_scope(ChainId(0)), "UNK");
        assert_eq!(chain_scope(ChainId(123456789)), "UNK");
    }

    #[test]
    fn test_domain_prefix_devnet() {
        assert_eq!(
            domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::UserTx),
            b"QBIND:DEV:TX:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Batch),
            b"QBIND:DEV:BATCH:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Vote),
            b"QBIND:DEV:VOTE:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Proposal),
            b"QBIND:DEV:PROPOSAL:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Timeout),
            b"QBIND:DEV:TIMEOUT:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::NewView),
            b"QBIND:DEV:NEWVIEW:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::BatchAck),
            b"QBIND:DEV:BATCH_ACK:v1"
        );
    }

    #[test]
    fn test_domain_prefix_testnet() {
        assert_eq!(
            domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::UserTx),
            b"QBIND:TST:TX:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::Batch),
            b"QBIND:TST:BATCH:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::Vote),
            b"QBIND:TST:VOTE:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::BatchAck),
            b"QBIND:TST:BATCH_ACK:v1"
        );
    }

    #[test]
    fn test_domain_prefix_mainnet() {
        assert_eq!(
            domain_prefix(QBIND_MAINNET_CHAIN_ID, DomainKind::UserTx),
            b"QBIND:MAIN:TX:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_MAINNET_CHAIN_ID, DomainKind::Batch),
            b"QBIND:MAIN:BATCH:v1"
        );
        assert_eq!(
            domain_prefix(QBIND_MAINNET_CHAIN_ID, DomainKind::Vote),
            b"QBIND:MAIN:VOTE:v1"
        );
    }

    #[test]
    fn test_domain_prefix_unknown() {
        assert_eq!(
            domain_prefix(ChainId(0), DomainKind::UserTx),
            b"QBIND:UNK:TX:v1"
        );
        assert_eq!(
            domain_prefix(ChainId(12345), DomainKind::Vote),
            b"QBIND:UNK:VOTE:v1"
        );
    }

    #[test]
    fn test_different_chains_different_prefixes() {
        // Critical security test: Different chains must produce different prefixes
        let devnet_tx = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::UserTx);
        let testnet_tx = domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::UserTx);
        let mainnet_tx = domain_prefix(QBIND_MAINNET_CHAIN_ID, DomainKind::UserTx);

        assert_ne!(devnet_tx, testnet_tx);
        assert_ne!(devnet_tx, mainnet_tx);
        assert_ne!(testnet_tx, mainnet_tx);

        // Same for other domain kinds
        let devnet_vote = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Vote);
        let testnet_vote = domain_prefix(QBIND_TESTNET_CHAIN_ID, DomainKind::Vote);

        assert_ne!(devnet_vote, testnet_vote);
    }

    #[test]
    fn test_different_kinds_different_prefixes() {
        // Different domain kinds must produce different prefixes
        let tx = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::UserTx);
        let batch = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Batch);
        let vote = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Vote);
        let proposal = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Proposal);
        let timeout = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::Timeout);
        let newview = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::NewView);
        let batch_ack = domain_prefix(QBIND_DEVNET_CHAIN_ID, DomainKind::BatchAck);

        // All must be unique
        let prefixes = vec![tx, batch, vote, proposal, timeout, newview, batch_ack];
        for i in 0..prefixes.len() {
            for j in (i + 1)..prefixes.len() {
                assert_ne!(
                    prefixes[i], prefixes[j],
                    "Domain prefixes {:?} and {:?} should be different",
                    prefixes[i], prefixes[j]
                );
            }
        }
    }
}
