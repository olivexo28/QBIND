use std::sync::Arc;

use qbind_crypto::CryptoProvider;
use qbind_hash::tx::{try_tx_digest_streaming, TxDigestError};
use qbind_serde::keyset::{parse_stored_keyset, StoredKeysetLimits, StoredKeysetParseError};
use qbind_serde::StateError;
use qbind_types::{Hash32, KEYSET_PROGRAM_ID};
use qbind_wire::tx::{Transaction, TxAuth};

use crate::store::AccountStore;
use crate::ExecutionError;

/// Verify all TxAuth entries on a Transaction against on-chain keyset accounts.
///
/// For each TxAuth:
///  - interpret auth.account_index as an index into tx.accounts
///  - use that account's account_id as the keyset AccountId
///  - load the corresponding account from AccountStore
///  - require the returned ID, keyset-program owner and non-executable metadata
///  - decode KeysetAccount from account.data via qbind-serde
///  - require stored version 1 and zero header/entry reserved bytes
///  - require a nonzero threshold, then select the first matching suite_id entry
///  - require that selected entry's individual weight to meet the threshold
///  - use CryptoProvider to fetch a SignatureSuite and verify the signature
///  - reject an empty authentication vector before digest, store, or crypto work
///  - structurally cover every signed bit-0 signer declaration by its exact index,
///    and reject authentication entries targeting unmarked accounts before that work
///
/// This conservative compatibility restriction is not full weighted authorization:
/// weights are never aggregated, repeated proofs add no weight, and a later
/// matching key cannot replace the first. Every supplied TxAuth is independently
/// processed in order, even after an earlier proof meets its own threshold.
/// Canonical duplicate/alias consistency and common-state semantics remain
/// unresolved. Repeated account IDs do not cover other indices. These declarations
/// are transaction-supplied; programs still need independent authority rules.
pub fn verify_transaction_auth<S: AccountStore>(
    store: &mut S,
    crypto: Arc<dyn CryptoProvider>,
    tx: &Transaction,
) -> Result<(), ExecutionError> {
    if tx.auths.is_empty() {
        return Err(ExecutionError::InvalidCallData(
            "transaction requires at least one authentication entry",
        ));
    }

    if u16::try_from(tx.accounts.len()).is_err() {
        return Err(ExecutionError::InvalidCallData(
            "transaction account count exceeds wire limit",
        ));
    }
    if u16::try_from(tx.auths.len()).is_err() {
        return Err(ExecutionError::InvalidCallData(
            "transaction authentication count exceeds wire limit",
        ));
    }

    // 8192 bytes of allocation-free index coverage, derived from the u16 count
    // limit. This bounds only the bitmap, not the verifier or physical memory.
    let mut covered = [0u8; (u16::MAX as usize + 1) / 8];
    for auth in &tx.auths {
        let index = usize::from(auth.account_index);
        let meta = tx
            .accounts
            .get(index)
            .ok_or(ExecutionError::InvalidCallData(
                "auth.account_index out of range",
            ))?;
        if meta.flags & 1 == 0 {
            return Err(ExecutionError::InvalidCallData(
                "authentication account is not a required signer",
            ));
        }
        covered[index / 8] |= 1 << (index % 8);
    }
    for (index, meta) in tx.accounts.iter().enumerate() {
        if meta.flags & 1 != 0 && covered[index / 8] & (1 << (index % 8)) == 0 {
            return Err(ExecutionError::InvalidCallData(
                "required signer authentication missing",
            ));
        }
    }

    let digest = try_tx_digest_streaming(tx).map_err(|error| {
        ExecutionError::InvalidCallData(match error {
            TxDigestError::AccountCountTooLarge => "transaction account count exceeds wire limit",
            TxDigestError::CallDataLengthTooLarge => {
                "transaction call-data length exceeds wire limit"
            }
            TxDigestError::LengthOverflow => "transaction signed-body length overflow",
        })
    })?;

    for auth in &tx.auths {
        verify_single_auth(store, crypto.as_ref(), tx, auth, &digest)?;
    }

    Ok(())
}

fn verify_single_auth<S: AccountStore>(
    store: &mut S,
    crypto: &dyn CryptoProvider,
    tx: &Transaction,
    auth: &TxAuth,
    digest: &Hash32,
) -> Result<(), ExecutionError> {
    // 1) Resolve account_index into tx.accounts.
    let account_index = auth.account_index as usize;
    if account_index >= tx.accounts.len() {
        return Err(ExecutionError::InvalidCallData(
            "auth.account_index out of range",
        ));
    }
    let meta = &tx.accounts[account_index];
    let keyset_id = meta.account_id;

    // 2) Load once; missing-account behavior remains unchanged.
    let account = store
        .get(&keyset_id)
        .ok_or(ExecutionError::AccountNotFound)?;

    // 3) Admit only the requested account's keyset-owned, non-executable response.
    if account.id != keyset_id {
        return Err(ExecutionError::InvalidCallData(
            "keyset account id mismatch",
        ));
    }
    if account.header.owner != KEYSET_PROGRAM_ID {
        return Err(ExecutionError::AccountOwnerMismatch);
    }
    if account.header.is_executable {
        return Err(ExecutionError::InvalidCallData(
            "keyset account is executable",
        ));
    }

    // These limits preserve the existing u16 framing without adding operational caps.
    let keyset = parse_stored_keyset(
        &account.data,
        StoredKeysetLimits {
            max_encoded_bytes: account.data.len(),
            max_entries: usize::from(u16::MAX),
            max_key_bytes: usize::from(u16::MAX),
            max_total_key_bytes: account.data.len(),
        },
    )
    .map_err(|error| match error {
        StoredKeysetParseError::Malformed(StateError::InvalidValue(
            "trailing stored keyset bytes",
        )) => ExecutionError::SerializationError("trailing bytes in KeysetAccount account"),
        _ => ExecutionError::SerializationError("decode KeysetAccount"),
    })?;

    // Native-auth compatibility admission, after complete framing validation.
    if keyset.version() != 1 {
        return Err(ExecutionError::InvalidCallData(
            "unsupported keyset account version",
        ));
    }
    if keyset.reserved0() != [0; 3] || keyset.reserved1() != [0; 4] {
        return Err(ExecutionError::InvalidCallData(
            "nonzero keyset account reserved bytes",
        ));
    }
    for entry in keyset.entries() {
        if entry.reserved0 != [0; 1] {
            return Err(ExecutionError::InvalidCallData(
                "nonzero keyset entry reserved bytes",
            ));
        }
    }

    let threshold = keyset.threshold();
    if threshold == 0 {
        return Err(ExecutionError::InvalidCallData("keyset threshold is zero"));
    }

    // 4) Find the first KeysetEntry with matching suite_id.
    let suite_id = auth.suite_id;
    let maybe_entry = keyset.entries().find(|e| e.suite_id == suite_id);
    let entry = match maybe_entry {
        Some(e) => e,
        None => {
            return Err(ExecutionError::InvalidCallData(
                "no key in keyset for given suite_id",
            ));
        }
    };

    if entry.weight < threshold {
        return Err(ExecutionError::InvalidCallData(
            "selected key weight below keyset threshold",
        ));
    }

    // 5) Obtain SignatureSuite from CryptoProvider.
    let suite = crypto
        .signature_suite(suite_id)
        .ok_or(ExecutionError::CryptoError("signature suite not found"))?;
    if suite.suite_id() != auth.suite_id {
        return Err(ExecutionError::CryptoError("signature suite id mismatch"));
    }

    // 6) Extract signature bytes from TxAuth.
    let sig_bytes: &[u8] = &auth.signature;
    let pk_bytes: &[u8] = entry.pubkey_bytes;

    // 7) Verify using the suite.
    suite
        .verify(pk_bytes, digest, sig_bytes)
        .map_err(|_| ExecutionError::CryptoError("signature verification failed"))?;

    Ok(())
}
