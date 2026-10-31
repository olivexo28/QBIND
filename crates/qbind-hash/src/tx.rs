use crate::hash::sha3_256_tagged;
use qbind_types::Hash32;
use qbind_wire::io::{len_to_u16, len_to_u32, put_bytes, put_u16, put_u32, put_u64, put_u8};
use qbind_wire::tx::{Transaction, TxAccountMeta};
use sha3::{Digest, Sha3_256};

const TX_DOMAIN_TAG: &[u8; 8] = b"QBIND:TX";

/// Compute the canonical TxSignBody preimage according to the wire spec.
/// This does NOT include msg_type or auths[].
pub fn tx_sign_body_preimage(tx: &Transaction) -> Vec<u8> {
    let mut out = Vec::new();

    // version
    put_u8(&mut out, tx.version);
    // chain_id
    put_u32(&mut out, tx.chain_id);
    // payer
    put_bytes(&mut out, &tx.payer);
    // nonce
    put_u64(&mut out, tx.nonce);
    // fee_limit
    put_u64(&mut out, tx.fee_limit);

    // accounts
    let account_count = tx.accounts.len();
    let account_count_u16 = len_to_u16(account_count);
    put_u16(&mut out, account_count_u16);
    for meta in &tx.accounts {
        encode_account_meta(&mut out, meta);
    }

    // program_id
    put_bytes(&mut out, &tx.program_id);

    // call_data
    let call_len = tx.call_data.len();
    let call_len_u32 = len_to_u32(call_len);
    put_u32(&mut out, call_len_u32);
    put_bytes(&mut out, &tx.call_data);

    out
}

/// Helper: encode TxAccountMeta in the same order as its wire format.
fn encode_account_meta(out: &mut Vec<u8>, meta: &TxAccountMeta) {
    put_bytes(out, &meta.account_id);
    put_u8(out, meta.flags);
    put_u8(out, meta.access_hint);
    put_bytes(out, &meta.reserved0);
}

/// Canonical tx_digest = SHA3-256("QBIND:TX" || TxSignBody).
pub fn tx_digest(tx: &Transaction) -> Hash32 {
    let preimage = tx_sign_body_preimage(tx);
    sha3_256_tagged("QBIND:TX", &preimage)
}

/// A fixed-size refusal category for checked native transaction digesting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TxDigestError {
    AccountCountTooLarge,
    CallDataLengthTooLarge,
    LengthOverflow,
}

impl core::fmt::Display for TxDigestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::AccountCountTooLarge => "transaction account count exceeds u16",
            Self::CallDataLengthTooLarge => "transaction call-data length exceeds u32",
            Self::LengthOverflow => "transaction signed-body length overflow",
        };
        f.write_str(message)
    }
}

impl std::error::Error for TxDigestError {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckedTxLengths {
    account_count: u16,
    call_data_length: u32,
    body_length: u64,
    stream_length: u64,
}

fn checked_tx_lengths(
    account_count: u64,
    call_data_length: u64,
) -> Result<CheckedTxLengths, TxDigestError> {
    let account_count =
        u16::try_from(account_count).map_err(|_| TxDigestError::AccountCountTooLarge)?;
    let call_data_length =
        u32::try_from(call_data_length).map_err(|_| TxDigestError::CallDataLengthTooLarge)?;

    let account_bytes = u64::from(account_count)
        .checked_mul(36)
        .ok_or(TxDigestError::LengthOverflow)?;
    let body_length = 91u64
        .checked_add(account_bytes)
        .and_then(|length| length.checked_add(u64::from(call_data_length)))
        .ok_or(TxDigestError::LengthOverflow)?;
    let stream_length = u64::try_from(TX_DOMAIN_TAG.len())
        .ok()
        .and_then(|tag_length| body_length.checked_add(tag_length))
        .ok_or(TxDigestError::LengthOverflow)?;

    Ok(CheckedTxLengths {
        account_count,
        call_data_length,
        body_length,
        stream_length,
    })
}

/// Compute the canonical transaction digest without materializing its signing body.
///
/// The hash state and helper scalars are constant-size. Hashing work is
/// O(accounts.len() + call_data.len()); the caller-owned transaction storage
/// and allocations made by any separate test oracle are excluded. The signed
/// body is 91 + 36 * account_count + call_data_length bytes, plus the 8-byte
/// domain tag in the hashed stream. Type-size observations do not establish a
/// compiler stack-frame or physical-memory bound.
pub fn try_tx_digest_streaming(tx: &Transaction) -> Result<Hash32, TxDigestError> {
    let account_count =
        u64::try_from(tx.accounts.len()).map_err(|_| TxDigestError::AccountCountTooLarge)?;
    let call_data_length =
        u64::try_from(tx.call_data.len()).map_err(|_| TxDigestError::CallDataLengthTooLarge)?;
    let lengths = checked_tx_lengths(account_count, call_data_length)?;

    let mut hasher = Sha3_256::new();
    hasher.update(TX_DOMAIN_TAG);
    hasher.update([tx.version]);
    hasher.update(tx.chain_id.to_le_bytes());
    hasher.update(tx.payer);
    hasher.update(tx.nonce.to_le_bytes());
    hasher.update(tx.fee_limit.to_le_bytes());
    hasher.update(lengths.account_count.to_le_bytes());
    for meta in &tx.accounts {
        hasher.update(meta.account_id);
        hasher.update([meta.flags]);
        hasher.update([meta.access_hint]);
        hasher.update(meta.reserved0);
    }
    hasher.update(tx.program_id);
    hasher.update(lengths.call_data_length.to_le_bytes());
    hasher.update(&tx.call_data);

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    debug_assert_eq!(
        lengths.body_length.checked_add(8),
        Some(lengths.stream_length)
    );
    Ok(out)
}

#[cfg(test)]
mod run422_native_tx_streaming_scalar_tests {
    use super::{checked_tx_lengths, TxDigestError};

    #[test]
    fn run422_native_tx_streaming_scalar_wire_limits_and_exact_lengths() {
        let max_accounts = u64::from(u16::MAX);
        let max_call_data = u64::from(u32::MAX);
        let lengths = checked_tx_lengths(max_accounts, max_call_data).unwrap();
        assert_eq!(lengths.account_count, u16::MAX);
        assert_eq!(lengths.call_data_length, u32::MAX);
        assert_eq!(lengths.body_length, 4_297_326_646);
        assert_eq!(lengths.stream_length, 4_297_326_654);

        assert_eq!(
            checked_tx_lengths(max_accounts + 1, 0),
            Err(TxDigestError::AccountCountTooLarge)
        );
        assert_eq!(
            checked_tx_lengths(0, max_call_data + 1),
            Err(TxDigestError::CallDataLengthTooLarge)
        );
    }

    #[test]
    fn run422_native_tx_streaming_scalar_lengths_at_account_and_data_limits() {
        assert_eq!(
            checked_tx_lengths(u64::from(u16::MAX), 0)
                .unwrap()
                .body_length,
            2_359_351
        );
        assert_eq!(
            checked_tx_lengths(0, u64::from(u32::MAX))
                .unwrap()
                .body_length,
            4_294_967_386
        );
    }
}
