//! Canonical block structure and types for QBIND blockchain.
//!
//! This module defines the core block types introduced in T151:
//! - `QbindBlockHeader`: Block header with parent hash, state/tx/receipt roots
//! - `QbindBlockBody`: Block body containing transactions
//! - `QbindBlock`: Complete block combining header and body
//!
//! ## Root Calculation
//!
//! For T151, roots are calculated using simple Merkle tree over hashes:
//! - `tx_root`: Merkle root over `hash(tx)` for each transaction
//! - `receipts_root`: Merkle root over `hash(receipt)` for each receipt
//! - `state_root`: Placeholder deterministic hash over state (temporary)
//!
//! A proper Merkle Patricia Trie or Verkle tree will be introduced in a later task.

use crate::execution_engine::TxReceipt;
use crate::qbind_tx::QbindTx;

/// 32-byte hash type used for block hashes and roots.
pub type H256 = [u8; 32];

/// The zero hash (32 zero bytes).
pub const ZERO_H256: H256 = [0u8; 32];

/// Validator ID for block proposer (temporary simplified type).
/// In the full system, this comes from qbind-consensus::ids::ValidatorId.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct BlockProposerId(pub u64);

impl BlockProposerId {
    /// Create a new proposer ID.
    pub fn new(id: u64) -> Self {
        BlockProposerId(id)
    }

    /// Get the raw ID value.
    pub fn as_u64(&self) -> u64 {
        self.0
    }
}

impl From<u64> for BlockProposerId {
    fn from(id: u64) -> Self {
        BlockProposerId(id)
    }
}

/// Block header containing metadata and Merkle roots.
///
/// The header captures all data needed to verify block integrity
/// and chain linkage without the full transaction data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QbindBlockHeader {
    /// Hash of the parent block's header.
    pub parent_hash: H256,

    /// Root of the state trie after executing this block.
    ///
    /// NOTE: For T151, this is a placeholder hash computed by hashing
    /// a canonical serialization of the in-memory state. A proper
    /// Merkle Patricia Trie will be introduced in a later task.
    pub state_root: H256,

    /// Merkle root over the transaction list.
    ///
    /// Computed as `merkle_root([hash(tx) for tx in transactions])`.
    pub tx_root: H256,

    /// Merkle root over the receipt list.
    ///
    /// Computed as `merkle_root([hash(receipt) for receipt in receipts])`.
    pub receipts_root: H256,

    /// Block number (height) in the chain.
    pub number: u64,

    /// Block timestamp in seconds since Unix epoch.
    ///
    /// This value comes from consensus and is NOT derived from wall clock time.
    pub timestamp: u64,

    /// Validator ID of the block proposer.
    pub proposer_id: BlockProposerId,
    // Future fields (commented for reference):
    // pub base_fee: u128,
    // pub prev_randao: H256,
    // pub extra_data: Vec<u8>,
}

impl QbindBlockHeader {
    /// Create a new block header.
    pub fn new(
        parent_hash: H256,
        state_root: H256,
        tx_root: H256,
        receipts_root: H256,
        number: u64,
        timestamp: u64,
        proposer_id: BlockProposerId,
    ) -> Self {
        QbindBlockHeader {
            parent_hash,
            state_root,
            tx_root,
            receipts_root,
            number,
            timestamp,
            proposer_id,
        }
    }

    /// Create a genesis block header (block 0).
    pub fn genesis(state_root: H256, timestamp: u64, proposer_id: BlockProposerId) -> Self {
        QbindBlockHeader {
            parent_hash: ZERO_H256,
            state_root,
            tx_root: ZERO_H256, // Empty merkle root for no transactions
            receipts_root: ZERO_H256,
            number: 0,
            timestamp,
            proposer_id,
        }
    }

    /// Check if any of the roots are non-zero (need verification).
    pub fn has_roots(&self) -> bool {
        self.state_root != ZERO_H256 || self.tx_root != ZERO_H256 || self.receipts_root != ZERO_H256
    }
}

/// Block body containing the list of transactions.
#[derive(Clone, Debug, Default)]
pub struct QbindBlockBody {
    /// List of transactions in the block.
    pub transactions: Vec<QbindTx>,
}

impl QbindBlockBody {
    /// Create a new block body with the given transactions.
    pub fn new(transactions: Vec<QbindTx>) -> Self {
        QbindBlockBody { transactions }
    }

    /// Create an empty block body.
    pub fn empty() -> Self {
        QbindBlockBody {
            transactions: Vec::new(),
        }
    }

    /// Get the number of transactions.
    pub fn tx_count(&self) -> usize {
        self.transactions.len()
    }
}

/// A complete QBIND block with header and body.
///
/// This is the full block structure that gets:
/// - Proposed by leaders during consensus
/// - Verified by followers
/// - Committed to the ledger after finalization
#[derive(Clone, Debug)]
pub struct QbindBlock {
    /// Block header with roots and metadata.
    pub header: QbindBlockHeader,

    /// Block body with transactions.
    pub body: QbindBlockBody,
}

impl QbindBlock {
    /// Create a new block with the given header and body.
    pub fn new(header: QbindBlockHeader, body: QbindBlockBody) -> Self {
        QbindBlock { header, body }
    }

    /// Create a genesis block with the given initial state root.
    pub fn genesis(state_root: H256, timestamp: u64, proposer_id: BlockProposerId) -> Self {
        QbindBlock {
            header: QbindBlockHeader::genesis(state_root, timestamp, proposer_id),
            body: QbindBlockBody::empty(),
        }
    }

    /// Get the block number.
    pub fn number(&self) -> u64 {
        self.header.number
    }

    /// Get the block timestamp.
    pub fn timestamp(&self) -> u64 {
        self.header.timestamp
    }

    /// Get the transaction count.
    pub fn tx_count(&self) -> usize {
        self.body.tx_count()
    }
}

// ============================================================================
// Hashing utilities
// ============================================================================

/// Hash a QBIND transaction for Merkle tree inclusion.
///
/// The serialization format is:
/// - from (20 bytes)
/// - to_flag (1 byte: 0 = None, 1 = Some)
/// - to (20 bytes if Some)
/// - nonce (8 bytes, big-endian)
/// - gas_limit (8 bytes, big-endian)
/// - max_fee_per_gas (16 bytes, big-endian)
/// - max_priority_fee_per_gas (16 bytes, big-endian)
/// - value (32 bytes, big-endian)
/// - data_len (4 bytes, big-endian)
/// - data (variable)
///
/// This serialization is stable and must not change to maintain root compatibility.
pub fn hash_qbind_tx(tx: &QbindTx) -> H256 {
    let mut preimage = Vec::with_capacity(128);

    // from (20 bytes)
    preimage.extend_from_slice(tx.from.as_bytes());

    // to_flag + to
    match &tx.to {
        Some(addr) => {
            preimage.push(1);
            preimage.extend_from_slice(addr.as_bytes());
        }
        None => {
            preimage.push(0);
        }
    }

    // nonce (8 bytes)
    preimage.extend_from_slice(&tx.nonce.to_be_bytes());

    // gas_limit (8 bytes)
    preimage.extend_from_slice(&tx.gas_limit.to_be_bytes());

    // max_fee_per_gas (16 bytes)
    preimage.extend_from_slice(&tx.max_fee_per_gas.to_be_bytes());

    // max_priority_fee_per_gas (16 bytes)
    preimage.extend_from_slice(&tx.max_priority_fee_per_gas.to_be_bytes());

    // value (32 bytes)
    preimage.extend_from_slice(tx.value.as_bytes());

    // data_len (4 bytes)
    preimage.extend_from_slice(&(tx.data.len() as u32).to_be_bytes());

    // data
    preimage.extend_from_slice(&tx.data);

    qbind_hash::sha3_256(&preimage)
}

/// Hash a transaction receipt for Merkle tree inclusion.
///
/// The serialization format is:
/// - success (1 byte: 0 = false, 1 = true)
/// - gas_used (8 bytes, big-endian)
/// - cumulative_gas_used (8 bytes, big-endian)
/// - logs_count (4 bytes, big-endian)
/// - for each log:
///   - address (20 bytes)
///   - topics_count (4 bytes)
///   - for each topic: (32 bytes)
///   - data_len (4 bytes)
///   - data (variable)
/// - contract_address_flag (1 byte)
/// - contract_address (20 bytes if Some)
/// - output_len (4 bytes)
/// - output (variable)
///
/// This serialization is stable and must not change to maintain root compatibility.
pub fn hash_receipt(receipt: &TxReceipt) -> H256 {
    let mut preimage = Vec::with_capacity(256);

    // success
    preimage.push(if receipt.success { 1 } else { 0 });

    // gas_used
    preimage.extend_from_slice(&receipt.gas_used.to_be_bytes());

    // cumulative_gas_used
    preimage.extend_from_slice(&receipt.cumulative_gas_used.to_be_bytes());

    // logs
    preimage.extend_from_slice(&(receipt.logs.len() as u32).to_be_bytes());
    for log in &receipt.logs {
        preimage.extend_from_slice(log.address.as_bytes());
        preimage.extend_from_slice(&(log.topics.len() as u32).to_be_bytes());
        for topic in &log.topics {
            preimage.extend_from_slice(topic.as_bytes());
        }
        preimage.extend_from_slice(&(log.data.len() as u32).to_be_bytes());
        preimage.extend_from_slice(&log.data);
    }

    // contract_address
    match &receipt.contract_address {
        Some(addr) => {
            preimage.push(1);
            preimage.extend_from_slice(addr.as_bytes());
        }
        None => {
            preimage.push(0);
        }
    }

    // output
    preimage.extend_from_slice(&(receipt.output.len() as u32).to_be_bytes());
    preimage.extend_from_slice(&receipt.output);

    qbind_hash::sha3_256(&preimage)
}

/// Compute a simple Merkle root over a list of hashes.
///
/// For an empty list, returns ZERO_H256.
/// For a single element, returns that element's hash.
/// For multiple elements, builds a binary Merkle tree.
///
/// If the number of elements is not a power of two, the last element
/// is duplicated to fill the tree level.
///
/// ## Implementation Note
///
/// This is a simplified binary Merkle tree that differs from Ethereum's
/// RLP-encoded Merkle Patricia Trie:
///
/// - Uses SHA3-256 instead of Keccak-256
/// - Simple binary tree instead of Patricia trie
/// - Odd-length lists use duplication instead of path encoding
///
/// This is intentional for T151. A proper MPT will be introduced in a
/// later task for full Ethereum compatibility where needed.
///
/// ## Complexity
///
/// O(n) time and space where n is the number of hashes.
pub fn merkle_root(hashes: &[H256]) -> H256 {
    if hashes.is_empty() {
        return ZERO_H256;
    }

    if hashes.len() == 1 {
        return hashes[0];
    }

    // Build tree bottom-up
    let mut current_level: Vec<H256> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity(current_level.len().div_ceil(2));

        for chunk in current_level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] }; // duplicate if odd

            // Combine: H(left || right)
            let mut combined = [0u8; 64];
            combined[..32].copy_from_slice(&left);
            combined[32..].copy_from_slice(&right);
            next_level.push(qbind_hash::sha3_256(&combined));
        }

        current_level = next_level;
    }

    current_level[0]
}

/// Compute the transactions root from a block body.
pub fn compute_tx_root(body: &QbindBlockBody) -> H256 {
    let tx_hashes: Vec<H256> = body.transactions.iter().map(hash_qbind_tx).collect();
    merkle_root(&tx_hashes)
}

/// Compute the receipts root from execution receipts.
pub fn compute_receipts_root(receipts: &[TxReceipt]) -> H256 {
    let receipt_hashes: Vec<H256> = receipts.iter().map(hash_receipt).collect();
    merkle_root(&receipt_hashes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm_types::{Address, U256};

    fn make_test_addr(byte: u8) -> Address {
        let mut bytes = [0u8; 20];
        bytes[19] = byte;
        Address::from_bytes(bytes)
    }

    #[test]
    fn test_empty_merkle_root() {
        let empty: Vec<H256> = vec![];
        assert_eq!(merkle_root(&empty), ZERO_H256);
    }

    #[test]
    fn test_single_merkle_root() {
        let hash = [1u8; 32];
        assert_eq!(merkle_root(&[hash]), hash);
    }

    #[test]
    fn test_two_merkle_root() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let root = merkle_root(&[h1, h2]);

        // Verify it's deterministic
        let root2 = merkle_root(&[h1, h2]);
        assert_eq!(root, root2);

        // Verify changing order changes root
        let root_swapped = merkle_root(&[h2, h1]);
        assert_ne!(root, root_swapped);
    }

    #[test]
    fn test_hash_qbind_tx_determinism() {
        let tx = QbindTx::transfer(
            make_test_addr(1),
            make_test_addr(2),
            U256::from_u64(1000),
            0,
        );

        let hash1 = hash_qbind_tx(&tx);
        let hash2 = hash_qbind_tx(&tx);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_hash_receipt_determinism() {
        let receipt = TxReceipt::success(21000, 21000, vec![], vec![]);

        let hash1 = hash_receipt(&receipt);
        let hash2 = hash_receipt(&receipt);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_block_header_creation() {
        let header = QbindBlockHeader::new(
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
            [4u8; 32],
            1,
            1704067200,
            BlockProposerId::new(0),
        );

        assert_eq!(header.number, 1);
        assert!(header.has_roots());
    }

    #[test]
    fn test_genesis_block() {
        let genesis = QbindBlock::genesis([0u8; 32], 1704067200, BlockProposerId::new(0));

        assert_eq!(genesis.number(), 0);
        assert_eq!(genesis.header.parent_hash, ZERO_H256);
        assert_eq!(genesis.tx_count(), 0);
    }

    #[test]
    fn test_compute_tx_root() {
        let tx1 = QbindTx::transfer(make_test_addr(1), make_test_addr(2), U256::from_u64(100), 0);
        let tx2 = QbindTx::transfer(make_test_addr(3), make_test_addr(4), U256::from_u64(200), 0);

        let body = QbindBlockBody::new(vec![tx1.clone(), tx2.clone()]);
        let root = compute_tx_root(&body);

        // Verify determinism
        let body2 = QbindBlockBody::new(vec![tx1, tx2]);
        let root2 = compute_tx_root(&body2);
        assert_eq!(root, root2);
    }

    #[test]
    fn test_empty_body_tx_root() {
        let body = QbindBlockBody::empty();
        let root = compute_tx_root(&body);
        assert_eq!(root, ZERO_H256);
    }
}