use crate::hash::sha3_256_tagged;
use cano_types::Hash32;
use cano_wire::consensus::Vote;
use cano_wire::io::{put_bytes, put_u16, put_u32, put_u64, put_u8};

/// Compute the canonical vote digest:
/// H("CANO:VOTE" || chain_id || height || round || step || block_id || validator_index || suite_id)
pub fn vote_digest(vote: &Vote) -> Hash32 {
    let mut out = Vec::new();

    put_u32(&mut out, vote.chain_id);
    put_u64(&mut out, vote.height);
    put_u64(&mut out, vote.round);
    put_u8(&mut out, vote.step);
    put_bytes(&mut out, &vote.block_id);
    put_u16(&mut out, vote.validator_index);
    put_u16(&mut out, vote.suite_id);

    sha3_256_tagged("CANO:VOTE", &out)
}
