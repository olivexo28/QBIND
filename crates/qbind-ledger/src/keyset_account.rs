//! Unused native account-read prerequisite; not keyset or authorization validation.
//!
//! The store's bounded-read contract supplies one coherent account read, not a
//! transaction-wide snapshot, freshness after return, rollback protection, or
//! persistent-store guarantees. Successful metadata admission says nothing about
//! keyset encoding, version/reserved-field policy, canonical keys, reachable
//! thresholds, signatures, or transaction authorization.

use crate::store::BoundedReadError;
use crate::{Account, AccountStore};
use qbind_types::{AccountId, KEYSET_PROGRAM_ID};

/// Fixed-size refusal categories; no account contents or input-derived text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeysetAccountReadError {
    Unsupported,
    Oversized,
    Backend,
    MissingAccount,
    AccountIdMismatch,
    OwnerMismatch,
    Executable,
}

/// Read once through `get_bounded`, then check identity, owner and executability.
///
/// `max_data_bytes` is an explicit logical data-length limit, not a protocol cap,
/// default policy, Vec-capacity, allocator, stack, or physical-memory bound.
/// Spare capacity is allowed. The defensive post-read length check detects a
/// violated backend postcondition; it cannot undo an oversized allocation already
/// performed by a faulty backend.
///
/// The helper performs only constant-size metadata checks, with no additional
/// heap allocation, data-body scan, parsing, crypto, cloning, fallback or mutation.
/// Backend materialization is separate. On success the same plain owned Account
/// is moved out, preserving its buffer, full header and ID independently of the
/// store. Lamports, rent_epoch, reserved header bytes and data are uninterpreted.
pub fn read_keyset_owned_account_bounded(
    store: &dyn AccountStore,
    requested_id: &AccountId,
    max_data_bytes: usize,
) -> Result<Account, KeysetAccountReadError> {
    use KeysetAccountReadError as Error;

    let account = store
        .get_bounded(requested_id, max_data_bytes)
        .map_err(|error| match error {
            BoundedReadError::Unsupported => Error::Unsupported,
            BoundedReadError::Oversized => Error::Oversized,
            BoundedReadError::Backend => Error::Backend,
        })?
        .ok_or(Error::MissingAccount)?;

    if account.data.len() > max_data_bytes {
        return Err(Error::Oversized);
    }
    if account.id != *requested_id {
        return Err(Error::AccountIdMismatch);
    }
    if account.header.owner != KEYSET_PROGRAM_ID {
        return Err(Error::OwnerMismatch);
    }
    if account.header.is_executable {
        return Err(Error::Executable);
    }
    Ok(account)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyset_validation::{
        analyze_stored_keyset_semantics, KeysetSemanticAnalysisError, KeysetSemanticAnalysisSummary,
    };
    use crate::{AccountHeader, ExecutionError, InMemoryAccountStore};
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::{MlDsa44SignatureSuite, StaticCryptoProvider};
    use qbind_serde::keyset::{parse_stored_keyset, StoredKeysetLimits, StoredKeysetParseError};
    use qbind_serde::{StateEncode, StateError};
    use qbind_types::{KeysetAccount, KeysetEntry};
    use std::cell::{Cell, RefCell};
    use std::sync::Arc;

    const ID: AccountId = [0x19; 32];

    fn account(data: Vec<u8>) -> Account {
        Account {
            id: ID,
            header: AccountHeader {
                owner: KEYSET_PROGRAM_ID,
                lamports: 0x0102_0304_0506_0708,
                is_executable: false,
                rent_epoch: 0x1112_1314_1516_1718,
                reserved: [0xA5; 8],
            },
            data,
        }
    }

    #[derive(Default)]
    struct Calls {
        bounded: Cell<usize>,
        requested: Cell<Option<(AccountId, usize)>>,
        get: Cell<usize>,
        put: Cell<usize>,
        delete: Cell<usize>,
    }

    impl Calls {
        fn record_bounded(&self, id: &AccountId, limit: usize) {
            self.bounded.set(self.bounded.get() + 1);
            self.requested.set(Some((*id, limit)));
        }

        fn assert_no_legacy_or_mutation(&self) {
            assert_eq!(self.get.get(), 0);
            assert_eq!(self.put.get(), 0);
            assert_eq!(self.delete.get(), 0);
        }

        fn assert_once(&self, id: &AccountId, limit: usize) {
            assert_eq!(self.bounded.get(), 1);
            assert_eq!(self.requested.get(), Some((*id, limit)));
            self.assert_no_legacy_or_mutation();
        }
    }

    #[derive(Default)]
    struct LegacyOnlyStore {
        calls: Calls,
    }

    impl AccountStore for LegacyOnlyStore {
        fn get(&self, _id: &AccountId) -> Option<Account> {
            self.calls.get.set(self.calls.get.get() + 1);
            panic!("legacy get must never be invoked");
        }

        fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
            self.calls.put.set(self.calls.put.get() + 1);
            panic!("put must never be invoked");
        }

        fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
            self.calls.delete.set(self.calls.delete.get() + 1);
            panic!("delete must never be invoked");
        }
    }

    struct DefaultReadWitness {
        legacy: LegacyOnlyStore,
    }

    impl AccountStore for DefaultReadWitness {
        fn get_bounded(
            &self,
            id: &AccountId,
            limit: usize,
        ) -> Result<Option<Account>, BoundedReadError> {
            self.legacy.calls.record_bounded(id, limit);
            self.legacy.get_bounded(id, limit)
        }

        fn get(&self, id: &AccountId) -> Option<Account> {
            self.legacy.get(id)
        }

        fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
            self.legacy.put(account)
        }

        fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
            self.legacy.delete(id)
        }
    }

    struct HandoffStore {
        legacy: LegacyOnlyStore,
        response: RefCell<Option<Result<Option<Account>, BoundedReadError>>>,
    }

    impl HandoffStore {
        fn new(response: Result<Option<Account>, BoundedReadError>) -> Self {
            Self {
                legacy: LegacyOnlyStore::default(),
                response: RefCell::new(Some(response)),
            }
        }
    }

    impl AccountStore for HandoffStore {
        fn get_bounded(
            &self,
            id: &AccountId,
            limit: usize,
        ) -> Result<Option<Account>, BoundedReadError> {
            self.legacy.calls.record_bounded(id, limit);
            self.response.borrow_mut().take().expect("one handoff only")
        }

        fn get(&self, id: &AccountId) -> Option<Account> {
            self.legacy.get(id)
        }

        fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
            self.legacy.put(account)
        }

        fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
            self.legacy.delete(id)
        }
    }

    fn assert_response(
        response: Result<Option<Account>, BoundedReadError>,
        limit: usize,
        expected: KeysetAccountReadError,
    ) {
        let store = HandoffStore::new(response);
        assert_eq!(
            read_keyset_owned_account_bounded(&store, &ID, limit),
            Err(expected)
        );
        store.legacy.calls.assert_once(&ID, limit);
        assert!(store.response.borrow().is_none());
    }

    fn assert_valid_control(limit: usize) {
        let store = HandoffStore::new(Ok(Some(account(vec![1, 2, 3]))));
        assert_eq!(
            read_keyset_owned_account_bounded(&store, &ID, limit),
            Ok(account(vec![1, 2, 3]))
        );
        store.legacy.calls.assert_once(&ID, limit);
    }

    #[test]
    fn run422_keyset_account_read_real_store_exact_limit_and_one_below() {
        let expected = account(vec![0xD3; 7]);
        let mut store = InMemoryAccountStore::new();
        store.put(expected.clone()).unwrap();
        assert_eq!(
            read_keyset_owned_account_bounded(&store, &ID, 7),
            Ok(expected.clone())
        );
        assert_eq!(
            read_keyset_owned_account_bounded(&store, &ID, 6),
            Err(KeysetAccountReadError::Oversized)
        );
        assert_eq!(
            read_keyset_owned_account_bounded(&store, &ID, 7),
            Ok(expected)
        );
    }

    #[test]
    fn run422_keyset_account_read_real_store_missing() {
        let store = InMemoryAccountStore::new();
        assert_eq!(
            read_keyset_owned_account_bounded(&store, &ID, 0),
            Err(KeysetAccountReadError::MissingAccount)
        );
    }

    #[test]
    fn run422_keyset_account_read_zero_limit_metadata_is_not_encoding() {
        let mut store = InMemoryAccountStore::new();
        store.put(account(Vec::new())).unwrap();
        let returned = read_keyset_owned_account_bounded(&store, &ID, 0).unwrap();
        assert_eq!(returned, account(Vec::new()));
        let parsed = parse_stored_keyset(
            &returned.data,
            StoredKeysetLimits {
                max_encoded_bytes: 0,
                max_entries: 0,
                max_key_bytes: 0,
                max_total_key_bytes: 0,
            },
        );
        assert_eq!(
            parsed.unwrap_err(),
            StoredKeysetParseError::Malformed(StateError::UnexpectedEof)
        );
    }

    #[test]
    fn run422_keyset_account_read_actual_default_unsupported_no_fallback() {
        let store = LegacyOnlyStore::default();
        assert_eq!(
            read_keyset_owned_account_bounded(&store, &ID, 23),
            Err(KeysetAccountReadError::Unsupported)
        );
        store.calls.assert_no_legacy_or_mutation();

        let witnessed = DefaultReadWitness {
            legacy: LegacyOnlyStore::default(),
        };
        assert_eq!(
            read_keyset_owned_account_bounded(&witnessed, &ID, 23),
            Err(KeysetAccountReadError::Unsupported)
        );
        witnessed.legacy.calls.assert_once(&ID, 23);
    }

    #[test]
    fn run422_keyset_account_read_bounded_errors_and_missing_are_distinct_once() {
        for (backend_error, expected) in [
            (
                BoundedReadError::Unsupported,
                KeysetAccountReadError::Unsupported,
            ),
            (
                BoundedReadError::Oversized,
                KeysetAccountReadError::Oversized,
            ),
            (BoundedReadError::Backend, KeysetAccountReadError::Backend),
        ] {
            assert_response(Err(backend_error), 3, expected);
        }
        assert_response(Ok(None), 3, KeysetAccountReadError::MissingAccount);
    }

    #[test]
    fn run422_keyset_account_read_wrong_returned_id_single_fault() {
        assert_valid_control(3);
        let mut returned = account(vec![1, 2, 3]);
        returned.id = [0x20; 32];
        assert_response(
            Ok(Some(returned)),
            3,
            KeysetAccountReadError::AccountIdMismatch,
        );
    }

    #[test]
    fn run422_keyset_account_read_wrong_owner_single_fault() {
        assert_valid_control(3);
        let mut returned = account(vec![1, 2, 3]);
        returned.header.owner = [0x20; 32];
        assert_response(Ok(Some(returned)), 3, KeysetAccountReadError::OwnerMismatch);
    }

    #[test]
    fn run422_keyset_account_read_executable_single_fault() {
        assert_valid_control(3);
        let mut returned = account(vec![1, 2, 3]);
        returned.header.is_executable = true;
        assert_response(Ok(Some(returned)), 3, KeysetAccountReadError::Executable);
    }

    #[test]
    fn run422_keyset_account_read_faulty_backend_post_read_oversized() {
        assert_valid_control(3);
        // This allocation precedes the helper; refusal cannot undo it.
        assert_response(
            Ok(Some(account(vec![1, 2, 3, 4]))),
            3,
            KeysetAccountReadError::Oversized,
        );
    }

    #[test]
    fn run422_keyset_account_read_move_preserves_buffer_after_store_destruction() {
        let (returned, pointer, length, capacity, header, id) = {
            let mut data = Vec::with_capacity(64);
            data.extend_from_slice(&[9, 8, 7, 6, 5]);
            let prebuilt = account(data);
            let witness = (
                prebuilt.data.as_ptr(),
                prebuilt.data.len(),
                prebuilt.data.capacity(),
                prebuilt.header.clone(),
                prebuilt.id,
            );
            assert!(witness.2 > witness.1);
            let store = HandoffStore::new(Ok(Some(prebuilt)));
            let returned = read_keyset_owned_account_bounded(&store, &ID, witness.1).unwrap();
            store.legacy.calls.assert_once(&ID, witness.1);
            assert!(store.response.borrow().is_none());
            (
                returned, witness.0, witness.1, witness.2, witness.3, witness.4,
            )
        };
        assert_eq!(returned.data.as_ptr(), pointer);
        assert_eq!(returned.data.len(), length);
        assert_eq!(returned.data.capacity(), capacity);
        assert_eq!(returned.header, header);
        assert_eq!(returned.id, id);
        assert_eq!(returned.data, [9, 8, 7, 6, 5]);
        assert_ne!(returned.header.lamports, 0);
        assert_ne!(returned.header.rent_epoch, 0);
        assert_eq!(returned.header.reserved, [0xA5; 8]);
    }

    #[test]
    fn run422_keyset_account_read_composes_borrowed_parser_and_slice2c_semantics() {
        let (first_key, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (second_key, _) = MlDsa44Backend::generate_keypair().unwrap();
        let key_len = first_key.len();
        assert_eq!(second_key.len(), key_len);
        let state = KeysetAccount {
            version: 1,
            reserved0: [0; 3],
            threshold: 8,
            entry_count: 2,
            reserved1: [0; 4],
            entries: vec![
                KeysetEntry {
                    suite_id: 100,
                    weight: 3,
                    reserved0: [0],
                    pubkey_len: u16::try_from(key_len).unwrap(),
                    pubkey_bytes: first_key,
                },
                KeysetEntry {
                    suite_id: 100,
                    weight: 5,
                    reserved0: [0],
                    pubkey_len: u16::try_from(key_len).unwrap(),
                    pubkey_bytes: second_key,
                },
            ],
        };
        let mut data = Vec::new();
        state.encode_state(&mut data);
        let limit = data.len();
        let store = HandoffStore::new(Ok(Some(account(data))));
        let returned = read_keyset_owned_account_bounded(&store, &ID, limit).unwrap();
        store.legacy.calls.assert_once(&ID, limit);

        let view = parse_stored_keyset(
            &returned.data,
            StoredKeysetLimits {
                max_encoded_bytes: limit,
                max_entries: 2,
                max_key_bytes: key_len,
                max_total_key_bytes: 2 * key_len,
            },
        )
        .expect("framing only, separate from metadata admission");
        assert_eq!(view.encoded_bytes().as_ptr(), returned.data.as_ptr());
        for (index, entry) in view.entries().enumerate() {
            let offset = 12 + index * (6 + key_len) + 6;
            assert_eq!(
                entry.pubkey_bytes.as_ptr(),
                returned.data[offset..].as_ptr()
            );
            assert_eq!(entry.pubkey_bytes, state.entries[index].pubkey_bytes);
        }

        let provider = StaticCryptoProvider::new()
            .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100)));
        assert_eq!(
            analyze_stored_keyset_semantics::<2>(view, &provider, 2, 64),
            Ok(KeysetSemanticAnalysisSummary {
                encoded_entry_count: 2,
                distinct_canonical_identity_count: 2,
                total_distinct_key_weight: 8,
                attainable_weight: 8,
                minimum_distinct_key_proofs: 2,
            })
        );
        assert_eq!(
            analyze_stored_keyset_semantics::<2>(view, &provider, 1, 64),
            Err(KeysetSemanticAnalysisError::ThresholdUnreachable)
        );
        // No transaction, proof or signature authorization is performed here.
    }
}
