use crate::error::WireError;
use crate::io::{
    get_bytes, get_u16, get_u32, get_u64, get_u8, len_to_u16, len_to_u32, put_bytes, put_u16,
    put_u32, put_u64, put_u8, WireDecode, WireEncode,
};
use qbind_types::Hash32;

pub const MSG_TYPE_VOTE: u8 = 0x01;
pub const MSG_TYPE_QC: u8 = 0x02;
pub const MSG_TYPE_BLOCK_PROPOSAL: u8 = 0x03;

/// Default suite ID for consensus signatures.
/// This is SUITE_TOY_SHA3 (0) - a test-only SHA3-based signature suite.
/// Centralized here so it's easy to change when real PQ suites are added.
///
/// **NOT FOR PRODUCTION** - this is only for testing the verification pipeline.
pub const DEFAULT_CONSENSUS_SUITE_ID: u16 = 0;

/// Vote message wire structure:
/// msg_type:        u8    // 0x01
/// version:         u8    // 0x01
/// chain_id:        u32
/// epoch:           u64   // epoch number (T101)
/// height:          u64
/// round:           u64
/// step:            u8    // 0 = Prevote, 1 = Precommit
/// block_id:        [u8;32]
/// validator_index: u16
/// suite_id:        u16   // consensus signature suite identifier
/// signature:       Vec<u8> (length given by sig_len field)
///
/// # Wire Format Change (T81)
///
/// The `reserved` field has been replaced with `suite_id` to carry the
/// consensus signature suite identifier. This enables cryptographic agility
/// for multi-suite support (e.g., classical vs post-quantum signatures).
///
/// # Wire Format Change (T101)
///
/// Added `epoch` field to carry the epoch number. This enables epoch-aware
/// consensus and allows nodes to reject messages from the wrong epoch.
///
/// **Backwards Compatibility**: This is a devnet-only wire format change.
/// Old messages without explicit suite_id or epoch are not supported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vote {
    pub version: u8,
    pub chain_id: u32,
    /// The epoch number this vote belongs to.
    /// Nodes will reject votes from a different epoch.
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    pub step: u8,
    pub block_id: Hash32,
    pub validator_index: u16,
    /// Consensus signature suite identifier.
    /// Use `DEFAULT_CONSENSUS_SUITE_ID` for the default toy SHA3 suite.
    pub suite_id: u16,
    pub signature: Vec<u8>,
}

impl WireEncode for Vote {
    fn encode(&self, out: &mut Vec<u8>) {
        // msg_type + version
        put_u8(out, MSG_TYPE_VOTE);
        put_u8(out, self.version);
        // fixed fields
        put_u32(out, self.chain_id);
        put_u64(out, self.epoch);
        put_u64(out, self.height);
        put_u64(out, self.round);
        put_u8(out, self.step);
        put_bytes(out, &self.block_id);
        put_u16(out, self.validator_index);
        put_u16(out, self.suite_id);
        // sig length + sig bytes
        let sig_len = self.signature.len();
        let sig_len_u16 = len_to_u16(sig_len);
        put_u16(out, sig_len_u16);
        put_bytes(out, &self.signature);
    }
}

impl WireDecode for Vote {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_VOTE {
            return Err(WireError::InvalidValue("unexpected msg_type for Vote"));
        }
        let version = get_u8(input)?;
        let chain_id = get_u32(input)?;
        let epoch = get_u64(input)?;
        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let step = get_u8(input)?;
        let block_id_bytes = get_bytes(input, 32)?;
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(block_id_bytes);
        let validator_index = get_u16(input)?;
        let suite_id = get_u16(input)?;
        let sig_len = get_u16(input)? as usize;
        let sig_bytes = get_bytes(input, sig_len)?.to_vec();
        Ok(Vote {
            version,
            chain_id,
            epoch,
            height,
            round,
            step,
            block_id,
            validator_index,
            suite_id,
            signature: sig_bytes,
        })
    }
}

/// Domain separator for Vote signing preimages.
/// Changing this is a consensus-breaking change.
pub const VOTE_DOMAIN_TAG: &[u8] = b"QBIND:VOTE:v1";

impl Vote {
    /// Return the canonical preimage bytes to be signed for this vote
    /// (excluding the signature field itself).
    ///
    /// # Preimage Layout (v1)
    ///
    /// The preimage is constructed as follows (all integers are little-endian):
    ///
    /// ```text
    /// domain_tag:      "QBIND:VOTE:v1" (12 bytes)
    /// version:         u8
    /// chain_id:        u32
    /// epoch:           u64
    /// height:          u64
    /// round:           u64
    /// step:            u8
    /// block_id:        [u8; 32]
    /// validator_index: u16
    /// suite_id:        u16
    /// ```
    ///
    /// Note: The signature field is NOT included in the preimage.
    ///
    /// # Wire Format Change (T101)
    ///
    /// Added `epoch` to the preimage. This ensures that votes from different
    /// epochs cannot be replayed, as the epoch is part of what's signed.
    ///
    /// # Stability
    ///
    /// Changing this layout is a consensus-breaking change and must be versioned
    /// (hence "v1" in the domain tag). Any future layout changes should use a
    /// new domain tag (e.g., "QBIND:VOTE:v2").
    pub fn signing_preimage(&self) -> Vec<u8> {
        // Capacity hint: domain_tag(12) + version(1) + chain_id(4) + epoch(8) + height(8) + round(8) +
        //               step(1) + block_id(32) + validator_index(2) + suite_id(2) = 78 bytes
        let mut out =
            Vec::with_capacity(VOTE_DOMAIN_TAG.len() + 1 + 4 + 8 + 8 + 8 + 1 + 32 + 2 + 2);
        // Domain separator
        put_bytes(&mut out, VOTE_DOMAIN_TAG);
        // Vote fields (excluding signature)
        put_u8(&mut out, self.version);
        put_u32(&mut out, self.chain_id);
        put_u64(&mut out, self.epoch);
        put_u64(&mut out, self.height);
        put_u64(&mut out, self.round);
        put_u8(&mut out, self.step);
        put_bytes(&mut out, &self.block_id);
        put_u16(&mut out, self.validator_index);
        put_u16(&mut out, self.suite_id);
        out
    }
}

/// QuorumCertificate:
/// msg_type:      u8   // 0x02
/// version:       u8
/// chain_id:      u32
/// epoch:         u64  // epoch number (T101)
/// height:        u64
/// round:         u64
/// step:          u8
/// block_id:      [u8;32]
/// suite_id:      u16   // consensus signature suite identifier
/// bitmap_len:    u16
/// signer_bitmap: [u8; bitmap_len]
/// sig_count:     u16
/// signatures:    sequence of (u16 len, bytes[len])
///
/// # Wire Format Change (T81)
///
/// Added `suite_id` field to carry the consensus signature suite identifier.
/// This enables cryptographic agility for multi-suite support.
///
/// For now, a single `suite_id` is used for all signers in the QC. This is
/// acceptable because all validators currently use the same suite (SUITE_TOY_SHA3).
/// Future tasks may extend this to support per-validator suite IDs if needed
/// for live suite rotation.
///
/// # Wire Format Change (T101)
///
/// Added `epoch` field to carry the epoch number. This ensures that QCs
/// from different epochs cannot be replayed or mixed.
///
/// **Backwards Compatibility**: This is a devnet-only wire format change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QuorumCertificate {
    pub version: u8,
    pub chain_id: u32,
    /// The epoch number this QC belongs to.
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    pub step: u8,
    pub block_id: Hash32,
    /// Consensus signature suite identifier for all signers in this QC.
    /// Use `DEFAULT_CONSENSUS_SUITE_ID` for the default toy SHA3 suite.
    ///
    /// # Design Note
    ///
    /// A single suite_id per QC assumes all validators use the same suite.
    /// This is acceptable for the current devnet phase. Future tasks may
    /// need to extend this to per-signer suite IDs for live suite rotation.
    pub suite_id: u16,
    pub signer_bitmap: Vec<u8>,
    pub signatures: Vec<Vec<u8>>,
}

impl WireEncode for QuorumCertificate {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, MSG_TYPE_QC);
        put_u8(out, self.version);
        put_u32(out, self.chain_id);
        put_u64(out, self.epoch);
        put_u64(out, self.height);
        put_u64(out, self.round);
        put_u8(out, self.step);
        put_bytes(out, &self.block_id);
        put_u16(out, self.suite_id);
        // bitmap_len + signer_bitmap
        let bitmap_len = len_to_u16(self.signer_bitmap.len());
        put_u16(out, bitmap_len);
        put_bytes(out, &self.signer_bitmap);
        // sig_count + signatures
        let sig_count = len_to_u16(self.signatures.len());
        put_u16(out, sig_count);
        for sig in &self.signatures {
            let sig_len = len_to_u16(sig.len());
            put_u16(out, sig_len);
            put_bytes(out, sig);
        }
    }
}

impl WireDecode for QuorumCertificate {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_QC {
            return Err(WireError::InvalidValue(
                "unexpected msg_type for QuorumCertificate",
            ));
        }
        let version = get_u8(input)?;
        let chain_id = get_u32(input)?;
        let epoch = get_u64(input)?;
        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let step = get_u8(input)?;
        let block_id_bytes = get_bytes(input, 32)?;
        let mut block_id = [0u8; 32];
        block_id.copy_from_slice(block_id_bytes);
        let suite_id = get_u16(input)?;
        let bitmap_len = get_u16(input)? as usize;
        let signer_bitmap = get_bytes(input, bitmap_len)?.to_vec();
        let sig_count = get_u16(input)? as usize;
        let mut signatures = Vec::with_capacity(sig_count);
        for _ in 0..sig_count {
            let sig_len = get_u16(input)? as usize;
            let sig = get_bytes(input, sig_len)?.to_vec();
            signatures.push(sig);
        }
        Ok(QuorumCertificate {
            version,
            chain_id,
            epoch,
            height,
            round,
            step,
            block_id,
            suite_id,
            signer_bitmap,
            signatures,
        })
    }
}

/// Payload kind constants for block classification.
pub const PAYLOAD_KIND_NORMAL: u8 = 0;
pub const PAYLOAD_KIND_RECONFIG: u8 = 1;

/// BlockHeader (without embedded QC):
/// msg_type:       u8   // 0x03
/// version:        u8
/// chain_id:       u32
/// epoch:          u64  // epoch number (T101)
/// height:         u64
/// round:          u64
/// parent_block_id:Hash32
/// payload_hash:   Hash32
/// proposer_index: u16
/// suite_id:       u16  // consensus signature suite identifier for proposer's signature
/// tx_count:       u32
/// timestamp:      u64
/// payload_kind:   u8   // 0 = Normal, 1 = Reconfig (T102.1)
/// next_epoch:     u64  // only meaningful if payload_kind == Reconfig (T102.1)
/// qc_len:         u32   // length in bytes of QC encoding that follows
///
/// # Wire Format Change (T81)
///
/// The `reserved` field has been replaced with `suite_id` to carry the
/// proposer's consensus signature suite identifier.
///
/// # Wire Format Change (T101)
///
/// Added `epoch` field to carry the epoch number. This ensures that
/// proposals from different epochs cannot be mixed.
///
/// # Wire Format Change (T102.1)
///
/// Added `payload_kind` (u8) and `next_epoch` (u64) fields to carry reconfig
/// information. When `payload_kind == PAYLOAD_KIND_RECONFIG`, the `next_epoch`
/// field indicates the epoch to transition to when this block commits.
/// When `payload_kind == PAYLOAD_KIND_NORMAL`, `next_epoch` is ignored (set to 0).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockHeader {
    pub version: u8,
    pub chain_id: u32,
    /// The epoch number this block belongs to.
    pub epoch: u64,
    pub height: u64,
    pub round: u64,
    pub parent_block_id: Hash32,
    pub payload_hash: Hash32,
    pub proposer_index: u16,
    /// Consensus signature suite identifier for the proposer's signature.
    /// Use `DEFAULT_CONSENSUS_SUITE_ID` for the default toy SHA3 suite.
    pub suite_id: u16,
    pub tx_count: u32,
    pub timestamp: u64,
    /// Payload kind indicator (T102.1).
    /// Use `PAYLOAD_KIND_NORMAL` (0) for normal blocks.
    /// Use `PAYLOAD_KIND_RECONFIG` (1) for reconfiguration blocks.
    pub payload_kind: u8,
    /// The next epoch to transition to (T102.1).
    /// Only meaningful when `payload_kind == PAYLOAD_KIND_RECONFIG`.
    /// Set to 0 for normal blocks.
    pub next_epoch: u64,
}

/// BlockProposal wire structure:
/// msg_type:        u8    // 0x03
/// version:         u8
/// chain_id:        u32
/// epoch:           u64   // epoch number (T101)
/// height:          u64
/// round:           u64
/// parent_block_id: [u8;32]
/// payload_hash:    [u8;32]
/// proposer_index:  u16
/// suite_id:        u16   // consensus signature suite identifier
/// tx_count:        u32
/// timestamp:       u64
/// payload_kind:    u8    // 0 = Normal, 1 = Reconfig (T102.1)
/// next_epoch:      u64   // epoch to transition to if reconfig (T102.1)
/// qc_len:          u32   // length in bytes of QC encoding that follows
/// qc_bytes:        [u8; qc_len]
/// txs:             sequence of (u32 len, bytes[len])
/// sig_len:         u16
/// signature:       [u8; sig_len]
///
/// # Wire Format Change (T81)
///
/// Added `suite_id` field (replacing `reserved`) to carry the consensus
/// signature suite identifier for the proposer's signature.
///
/// # Wire Format Change (T101)
///
/// Added `epoch` field to carry the epoch number.
///
/// # Wire Format Change (T102.1)
///
/// Added `payload_kind` (u8) and `next_epoch` (u64) fields to carry reconfig
/// information. This enables marking blocks as epoch-change blocks.
///
/// **Backwards Compatibility**: This is a devnet-only wire format change.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockProposal {
    pub header: BlockHeader,
    pub qc: Option<QuorumCertificate>,
    /// raw transactions as encoded blobs; in later tasks we will parse them as qbind-wire::tx::Transaction.
    pub txs: Vec<Vec<u8>>,
    /// Opaque signature bytes over a canonical encoding of this proposal.
    pub signature: Vec<u8>,
}

impl WireEncode for BlockProposal {
    fn encode(&self, out: &mut Vec<u8>) {
        // First, encode QC into a temp buffer to get its length
        let qc_bytes = if let Some(ref qc) = self.qc {
            let mut qc_buf = Vec::new();
            qc.encode(&mut qc_buf);
            qc_buf
        } else {
            Vec::new()
        };
        let qc_len = len_to_u32(qc_bytes.len());

        // Now encode the header fields
        put_u8(out, MSG_TYPE_BLOCK_PROPOSAL);
        put_u8(out, self.header.version);
        put_u32(out, self.header.chain_id);
        put_u64(out, self.header.epoch);
        put_u64(out, self.header.height);
        put_u64(out, self.header.round);
        put_bytes(out, &self.header.parent_block_id);
        put_bytes(out, &self.header.payload_hash);
        put_u16(out, self.header.proposer_index);
        put_u16(out, self.header.suite_id);
        put_u32(out, self.header.tx_count);
        put_u64(out, self.header.timestamp);
        // T102.1: Encode payload_kind and next_epoch
        put_u8(out, self.header.payload_kind);
        put_u64(out, self.header.next_epoch);
        put_u32(out, qc_len);

        // Append QC bytes
        put_bytes(out, &qc_bytes);

        // Append each tx as u32 len + bytes
        for tx in &self.txs {
            let tx_len = len_to_u32(tx.len());
            put_u32(out, tx_len);
            put_bytes(out, tx);
        }

        // Append signature (length-prefixed with u16, consistent with Vote.signature)
        // u16 is sufficient for PQ signatures like ML-DSA (~3KB) up to 64KB max.
        let sig_len = len_to_u16(self.signature.len());
        put_u16(out, sig_len);
        put_bytes(out, &self.signature);
    }
}

impl WireDecode for BlockProposal {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let msg_type = get_u8(input)?;
        if msg_type != MSG_TYPE_BLOCK_PROPOSAL {
            return Err(WireError::InvalidValue(
                "unexpected msg_type for BlockProposal",
            ));
        }
        let version = get_u8(input)?;
        let chain_id = get_u32(input)?;
        let epoch = get_u64(input)?;
        let height = get_u64(input)?;
        let round = get_u64(input)?;
        let parent_block_id_bytes = get_bytes(input, 32)?;
        let mut parent_block_id = [0u8; 32];
        parent_block_id.copy_from_slice(parent_block_id_bytes);
        let payload_hash_bytes = get_bytes(input, 32)?;
        let mut payload_hash = [0u8; 32];
        payload_hash.copy_from_slice(payload_hash_bytes);
        let proposer_index = get_u16(input)?;
        let suite_id = get_u16(input)?;
        let tx_count = get_u32(input)?;
        let timestamp = get_u64(input)?;
        // T102.1: Decode payload_kind and next_epoch
        let payload_kind = get_u8(input)?;
        let next_epoch = get_u64(input)?;
        let qc_len = get_u32(input)? as usize;

        let qc = if qc_len > 0 {
            let qc_bytes = get_bytes(input, qc_len)?;
            let mut qc_input = qc_bytes;
            Some(QuorumCertificate::decode(&mut qc_input)?)
        } else {
            None
        };

        let mut txs = Vec::with_capacity(tx_count as usize);
        for _ in 0..tx_count {
            let tx_len = get_u32(input)? as usize;
            let tx_bytes = get_bytes(input, tx_len)?.to_vec();
            txs.push(tx_bytes);
        }

        // Read signature (length-prefixed with u16)
        let sig_len = get_u16(input)? as usize;
        let sig_bytes = get_bytes(input, sig_len)?.to_vec();

        Ok(BlockProposal {
            header: BlockHeader {
                version,
                chain_id,
                epoch,
                height,
                round,
                parent_block_id,
                payload_hash,
                proposer_index,
                suite_id,
                tx_count,
                timestamp,
                payload_kind,
                next_epoch,
            },
            qc,
            txs,
            signature: sig_bytes,
        })
    }
}

/// Domain separator for BlockProposal signing preimages.
/// Changing this is a consensus-breaking change.
pub const PROPOSAL_DOMAIN_TAG: &[u8] = b"QBIND:PROPOSAL:v1";

impl BlockProposal {
    /// Return the canonical preimage bytes to be signed for this proposal
    /// (excluding the signature field itself).
    ///
    /// # Preimage Layout (v1)
    ///
    /// The preimage is constructed as follows (all integers are little-endian):
    ///
    /// ```text
    /// domain_tag:       "QBIND:PROPOSAL:v1" (16 bytes)
    /// version:          u8
    /// chain_id:         u32
    /// epoch:            u64
    /// height:           u64
    /// round:            u64
    /// parent_block_id:  [u8; 32]
    /// payload_hash:     [u8; 32]
    /// proposer_index:   u16
    /// suite_id:         u16
    /// tx_count:         u32
    /// timestamp:        u64
    /// payload_kind:     u8           (T102.1)
    /// next_epoch:       u64          (T102.1)
    /// qc_len:           u32
    /// qc_bytes:         [u8; qc_len]  (full WireEncode of QC if present)
    /// txs:              sequence of (u32 len, bytes[len])
    /// ```
    ///
    /// Note: The signature field is NOT included in the preimage.
    ///
    /// # Wire Format Change (T101)
    ///
    /// Added `epoch` to the preimage. This ensures that proposals from different
    /// epochs cannot be replayed, as the epoch is part of what's signed.
    ///
    /// # Wire Format Change (T102.1)
    ///
    /// Added `payload_kind` and `next_epoch` to the preimage. This ensures that
    /// the reconfig payload is signed and cannot be altered after proposal.
    ///
    /// # Stability
    ///
    /// Changing this layout is a consensus-breaking change and must be versioned
    /// (hence "v1" in the domain tag). Any future layout changes should use a
    /// new domain tag (e.g., "QBIND:PROPOSAL:v2").
    pub fn signing_preimage(&self) -> Vec<u8> {
        // Encode QC into a temp buffer to get its length
        let qc_bytes = if let Some(ref qc) = self.qc {
            let mut qc_buf = Vec::new();
            qc.encode(&mut qc_buf);
            qc_buf
        } else {
            Vec::new()
        };
        let qc_len = len_to_u32(qc_bytes.len());

        let mut out = Vec::new();

        // Domain separator
        put_bytes(&mut out, PROPOSAL_DOMAIN_TAG);

        // Header fields
        put_u8(&mut out, self.header.version);
        put_u32(&mut out, self.header.chain_id);
        put_u64(&mut out, self.header.epoch);
        put_u64(&mut out, self.header.height);
        put_u64(&mut out, self.header.round);
        put_bytes(&mut out, &self.header.parent_block_id);
        put_bytes(&mut out, &self.header.payload_hash);
        put_u16(&mut out, self.header.proposer_index);
        put_u16(&mut out, self.header.suite_id);
        put_u32(&mut out, self.header.tx_count);
        put_u64(&mut out, self.header.timestamp);
        // T102.1: Include payload_kind and next_epoch in preimage
        put_u8(&mut out, self.header.payload_kind);
        put_u64(&mut out, self.header.next_epoch);

        // QC (length-prefixed)
        put_u32(&mut out, qc_len);
        put_bytes(&mut out, &qc_bytes);

        // Transactions (each length-prefixed with u32)
        for tx in &self.txs {
            let tx_len = len_to_u32(tx.len());
            put_u32(&mut out, tx_len);
            put_bytes(&mut out, tx);
        }

        // NOTE: signature is NOT included
        out
    }
}
