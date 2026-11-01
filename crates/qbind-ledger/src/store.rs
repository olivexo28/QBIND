use crate::account::Account;
use crate::ExecutionError;
use qbind_types::AccountId;
use std::collections::HashMap;

/// Fixed-size failure categories for bounded account reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BoundedReadError {
    /// The store does not implement a coherent bounded read.
    Unsupported,
    /// The account data exceeds the caller-supplied logical byte budget.
    Oversized,
    /// The backend could not materialize the admitted account.
    Backend,
}

/// Abstract account storage used by the execution engine.
/// Implementations can be in-memory (for tests) or persistent (for nodes).
pub trait AccountStore {
    /// Fetch an account by its AccountId.
    fn get(&self, id: &AccountId) -> Option<Account>;

    /// Fetch an account only if its data length is within `max_data_bytes`.
    ///
    /// Implementations must check the limit and materialize the returned
    /// account from one coherent read/version. The default intentionally does
    /// not fall back to `get`, since that could allocate an unbounded copy.
    fn get_bounded(
        &self,
        _id: &AccountId,
        _max_data_bytes: usize,
    ) -> Result<Option<Account>, BoundedReadError> {
        Err(BoundedReadError::Unsupported)
    }

    /// Insert or replace an account.
    fn put(&mut self, account: Account) -> Result<(), ExecutionError>;

    /// Remove an account.
    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError>;
}

/// Simple in-memory HashMap-backed account store for tests and local execution.
pub struct InMemoryAccountStore {
    inner: HashMap<AccountId, Account>,
}

impl InMemoryAccountStore {
    pub fn new() -> Self {
        Self {
            inner: HashMap::new(),
        }
    }

    /// Model-scoped support only. Validate all invariants before taking inputs.
    ///
    /// std::collections::HashMap::capacity documents the number of elements
    /// the map can hold without reallocating. Admit len + ALL creates against
    /// that current capacity, ignoring possible later deletion space. Creates
    /// run first; unique replacements cannot increase len and deletes reduce it.
    /// Keys are [u8;32], the hasher is std RandomState, and Accounts contain only
    /// scalar headers and Vec<u8>. There are no user Hash/Eq/Drop implementations.
    /// No guarantee covers arbitrary panic, allocator abort, or process failure.
    pub(crate) fn publish_native_fixture_batch<const W: usize>(
        &mut self,
        effects: &mut [Option<crate::native_staged_effects::FixtureEffect>; W],
        limits: crate::native_staged_effects::FixtureStageLimits,
        eligible: bool,
    ) -> Result<
        crate::native_staged_effects::FixturePublicationSummary,
        crate::native_staged_effects::FixtureStageRefusal,
    > {
        use crate::native_staged_effects::{
            check_account, checked_capacity, checked_result_counts, FixtureEffect,
            FixturePublicationSummary, FixtureStageRefusal as Error,
        };
        #[cfg(test)]
        NATIVE_FIXTURE_OBSERVER.with(|c| c.set((c.get().0.saturating_add(1), c.get().1)));

        if !eligible {
            return Err(Error::Poisoned);
        }
        if limits.max_operations > W
            || limits.max_data_len > limits.max_account_capacity
            || limits.max_account_capacity > limits.max_aggregate_capacity
        {
            return Err(Error::OperationCapacity);
        }
        let mut summary = FixturePublicationSummary {
            operations: 0,
            creates: 0,
            replaces: 0,
            deletes: 0,
            retained_capacity: 0,
            resulting_accounts: 0,
        };
        for (index, effect) in effects.iter().enumerate() {
            let Some(effect) = effect else { continue };
            summary.operations = summary
                .operations
                .checked_add(1)
                .ok_or(Error::ArithmeticOverflow)?;
            if summary.operations > limits.max_operations {
                return Err(Error::OperationCapacity);
            }
            if effects
                .iter()
                .take(index)
                .flatten()
                .any(|e| e.target() == effect.target())
            {
                return Err(Error::DuplicateTarget);
            }
            if let Some(account) = effect.account() {
                check_account(effect.target(), account, limits)?;
                summary.retained_capacity = checked_capacity(
                    summary.retained_capacity,
                    account.data.capacity(),
                    limits.max_aggregate_capacity,
                )?;
            }
            let exists = self.inner.contains_key(effect.target());
            match effect {
                FixtureEffect::Create(_, _) => {
                    if exists {
                        return Err(Error::CreateExisting);
                    }
                    summary.creates = summary
                        .creates
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                }
                FixtureEffect::Replace(_, _) => {
                    if !exists {
                        return Err(Error::ReplaceMissing);
                    }
                    summary.replaces = summary
                        .replaces
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                }
                FixtureEffect::Delete(_) => {
                    if !exists {
                        return Err(Error::DeleteMissing);
                    }
                    summary.deletes = summary
                        .deletes
                        .checked_add(1)
                        .ok_or(Error::ArithmeticOverflow)?;
                }
            }
        }
        let (peak, result) =
            checked_result_counts(self.inner.len(), summary.creates, summary.deletes)?;
        summary.resulting_accounts = result;
        if peak > self.inner.capacity() {
            return Err(Error::MapCapacity);
        }

        // From here onward: admitted moves only, no fallible work or validation.
        for slot in effects.iter_mut() {
            if matches!(slot, Some(FixtureEffect::Create(_, _))) {
                if let Some(FixtureEffect::Create(id, account)) = slot.take() {
                    self.inner.insert(id, account);
                    #[cfg(test)]
                    observe_native_fixture_mutation();
                }
            }
        }
        for slot in effects.iter_mut() {
            match slot.take() {
                Some(FixtureEffect::Replace(id, account)) => {
                    self.inner.insert(id, account);
                    #[cfg(test)]
                    observe_native_fixture_mutation();
                }
                Some(FixtureEffect::Delete(id)) => {
                    self.inner.remove(&id);
                    #[cfg(test)]
                    observe_native_fixture_mutation();
                }
                _ => {}
            }
        }
        Ok(summary)
    }
}

#[cfg(test)]
thread_local! {
    static NATIVE_FIXTURE_OBSERVER: std::cell::Cell<(usize, usize)> =
        const { std::cell::Cell::new((0, 0)) };
}

#[cfg(test)]
fn observe_native_fixture_mutation() {
    NATIVE_FIXTURE_OBSERVER.with(|c| c.set((c.get().0, c.get().1.saturating_add(1))));
}

#[cfg(test)]
mod run422_native_staged_effects_tests {
    use super::*;
    use crate::native_staged_effects::{
        FixtureEffect as Op, FixtureStageLimits, FixtureStageRefusal as Error,
    };
    use std::cell::Cell;

    fn limits(n: usize) -> FixtureStageLimits {
        FixtureStageLimits {
            max_operations: n,
            max_data_len: 8,
            max_account_capacity: 8,
            max_aggregate_capacity: n.max(1) * 8,
        }
    }
    fn account(id: u8) -> Account {
        Account::new([id; 32], [7; 32], 42, vec![id; 4])
    }
    fn reset() {
        NATIVE_FIXTURE_OBSERVER.with(|c| c.set((0, 0)));
    }
    fn counts() -> (usize, usize) {
        NATIVE_FIXTURE_OBSERVER.with(Cell::get)
    }

    #[test]
    fn run422_native_staged_effects_actual_capacity_boundary() {
        let mut store = InMemoryAccountStore::new();
        // Provision before the attempt; use the real resulting capacity.
        store.inner.reserve(8);
        let capacity = store.inner.capacity();
        assert!(capacity > 0 && capacity < 200);
        for id in 0..capacity - 1 {
            store.put(account(id as u8)).unwrap();
        }
        let mut exact = [Some(Op::Create([200; 32], account(200)))];
        let pointer = exact[0].as_ref().unwrap().account().unwrap().data.as_ptr();
        reset();
        let result = store
            .publish_native_fixture_batch(&mut exact, limits(1), true)
            .unwrap();
        assert_eq!(result.resulting_accounts, capacity);
        assert_eq!(store.inner.capacity(), capacity);
        assert_eq!(store.inner.get(&[200; 32]).unwrap().data.as_ptr(), pointer);
        assert_eq!(counts(), (1, 1));

        let before_len = store.inner.len();
        let mut refused = [
            Some(Op::Create([201; 32], account(201))),
            Some(Op::Delete([0; 32])),
        ];
        let pointer = refused[0]
            .as_ref()
            .unwrap()
            .account()
            .unwrap()
            .data
            .as_ptr();
        reset();
        assert_eq!(
            store.publish_native_fixture_batch(&mut refused, limits(2), true),
            Err(Error::MapCapacity)
        );
        assert_eq!(counts(), (1, 0));
        assert_eq!(store.inner.len(), before_len);
        for id in 0..capacity - 1 {
            assert_eq!(store.inner.get(&[id as u8; 32]), Some(&account(id as u8)));
        }
        assert_eq!(store.inner.get(&[200; 32]), Some(&account(200)));
        assert_eq!(
            refused[0]
                .as_ref()
                .unwrap()
                .account()
                .unwrap()
                .data
                .as_ptr(),
            pointer
        );
        assert_eq!(store.inner.capacity(), capacity);

        store.inner.reserve(1); // fresh fixture provisioning outside publication
        assert!(store.inner.capacity() > capacity);
        reset();
        let result = store
            .publish_native_fixture_batch(&mut refused, limits(2), true)
            .unwrap();
        assert_eq!(result.operations, 2);
        assert_eq!(counts(), (1, 2));
        assert!(store.inner.contains_key(&[201; 32]));
        assert!(!store.inner.contains_key(&[0; 32]));
    }

    #[test]
    fn run422_native_staged_effects_helper_prevalidates_without_consuming() {
        let mut store = InMemoryAccountStore::new();
        store.inner.reserve(8);
        let original = account(1);
        store.put(original.clone()).unwrap();
        let cases = [
            (Some(Op::Create([1; 32], account(1))), Error::CreateExisting),
            (
                Some(Op::Replace([2; 32], account(2))),
                Error::ReplaceMissing,
            ),
            (Some(Op::Delete([2; 32])), Error::DeleteMissing),
            (
                Some(Op::Replace([1; 32], account(2))),
                Error::AccountIdMismatch,
            ),
            (Some(Op::Delete([3; 32])), Error::DuplicateTarget),
            (
                Some(Op::Create(
                    [4; 32],
                    Account::new([4; 32], [7; 32], 0, vec![0; 9]),
                )),
                Error::LogicalLength,
            ),
        ];
        for (bad, expected) in cases {
            let mut effects = [Some(Op::Create([3; 32], account(3))), bad];
            let pointer = effects[0]
                .as_ref()
                .unwrap()
                .account()
                .unwrap()
                .data
                .as_ptr();
            reset();
            assert_eq!(
                store.publish_native_fixture_batch(&mut effects, limits(2), true),
                Err(expected)
            );
            assert_eq!(counts(), (1, 0));
            assert_eq!(store.inner.len(), 1);
            assert_eq!(store.inner.get(&original.id), Some(&original));
            assert_eq!(
                effects[0]
                    .as_ref()
                    .unwrap()
                    .account()
                    .unwrap()
                    .data
                    .as_ptr(),
                pointer
            );
        }
        let mut data = Vec::with_capacity(9);
        data.push(1);
        let mut effects = [Some(Op::Create(
            [3; 32],
            Account::new([3; 32], [7; 32], 0, data),
        ))];
        reset();
        assert_eq!(
            store.publish_native_fixture_batch(&mut effects, limits(1), true),
            Err(Error::AccountCapacity)
        );
        assert_eq!(counts(), (1, 0));
        assert!(effects[0].is_some());
        assert_eq!(store.inner.get(&original.id), Some(&original));
    }

    #[test]
    fn run422_native_staged_effects_helper_bounds_and_poison() {
        let mut store = InMemoryAccountStore::new();
        store.inner.reserve(4);
        let mut effects = [
            Some(Op::Create([1; 32], account(1))),
            Some(Op::Create([2; 32], account(2))),
        ];
        for (limits, eligible, expected) in [
            (limits(2), false, Error::Poisoned),
            (limits(1), true, Error::OperationCapacity),
            (
                FixtureStageLimits {
                    max_aggregate_capacity: 7,
                    max_account_capacity: 4,
                    ..limits(2)
                },
                true,
                Error::OperationCapacity,
            ),
            (
                FixtureStageLimits {
                    max_data_len: 4,
                    max_account_capacity: 4,
                    max_aggregate_capacity: 7,
                    ..limits(2)
                },
                true,
                Error::AggregateCapacity,
            ),
        ] {
            reset();
            assert_eq!(
                store.publish_native_fixture_batch(&mut effects, limits, eligible),
                Err(expected)
            );
            assert_eq!(counts(), (1, 0));
            assert!(store.inner.is_empty());
            assert!(effects.iter().all(Option::is_some));
        }
        reset();
        let summary = store
            .publish_native_fixture_batch(&mut effects, limits(2), true)
            .unwrap();
        assert_eq!(summary.retained_capacity, 8);
        assert_eq!(counts(), (1, 2));
    }

    #[test]
    fn run422_native_staged_effects_private_multi_effect_moves_and_headers() {
        let mut store = InMemoryAccountStore::new();
        store.inner.reserve(8);
        let originals = [account(1), account(2), account(3)];
        for a in &originals {
            store.put(a.clone()).unwrap();
        }
        let create = account(4);
        let mut replace = account(1);
        replace.header.owner = [99; 32];
        replace.header.lamports = 100;
        replace.header.is_executable = true;
        replace.header.rent_epoch = 101;
        replace.header.reserved = [9; 8];
        replace.data = vec![9; 8];
        let pointers = (create.data.as_ptr(), replace.data.as_ptr());
        let capacities = (create.data.capacity(), replace.data.capacity());
        let expected = (create.clone(), replace.clone());
        let mut effects = [
            Some(Op::Replace([1; 32], replace)),
            Some(Op::Delete([2; 32])),
            Some(Op::Create([4; 32], create)),
        ];
        let original_capacity = store.inner.capacity();
        reset();
        let summary = store
            .publish_native_fixture_batch(&mut effects, limits(3), true)
            .unwrap();
        assert_eq!(counts(), (1, 3));
        assert_eq!(
            (
                summary.operations,
                summary.creates,
                summary.replaces,
                summary.deletes
            ),
            (3, 1, 1, 1)
        );
        assert_eq!(store.inner.len(), 3);
        assert_eq!(store.inner.capacity(), original_capacity);
        let create = store.inner.get(&[4; 32]).unwrap();
        let replace = store.inner.get(&[1; 32]).unwrap();
        assert_eq!(create, &expected.0);
        assert_eq!(replace, &expected.1);
        assert_eq!((create.data.as_ptr(), replace.data.as_ptr()), pointers);
        assert_eq!(
            (create.data.capacity(), replace.data.capacity()),
            capacities
        );
        assert_eq!(store.inner.get(&[3; 32]), Some(&originals[2]));
        assert!(!store.inner.contains_key(&[2; 32]));
        assert!(effects.iter().all(Option::is_none));
    }

    #[test]
    fn run422_native_staged_effects_capacity_refusal_consumes_session_fresh_begin_succeeds() {
        use crate::native_admission_context::{
            FixtureBinding, FixtureProfileStatus, PrototypePolicy,
        };
        use crate::native_staged_effects::{FixtureSelection, NativeStagedEffects};
        use crate::native_tx_proof::NativeTransactionProofLimits;
        use qbind_crypto::ml_dsa44::MlDsa44Backend;
        use qbind_crypto::{ml_dsa_44_sign_digest, MlDsa44SignatureSuite, StaticCryptoProvider};
        use qbind_hash::tx::try_tx_digest_streaming;
        use qbind_serde::keyset::StoredKeysetLimits;
        use qbind_serde::StateEncode;
        use qbind_types::{KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
        use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
        use std::sync::Arc;

        let (public, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let keyset = KeysetAccount {
            version: 1,
            reserved0: [0; 3],
            threshold: 1,
            entry_count: 1,
            reserved1: [0; 4],
            entries: vec![KeysetEntry {
                suite_id: 100,
                weight: 1,
                reserved0: [0],
                pubkey_len: 1312,
                pubkey_bytes: public,
            }],
        };
        let mut data = Vec::new();
        keyset.encode_state(&mut data);
        let key_account = Account::new([1; 32], KEYSET_PROGRAM_ID, 0, data);
        let mut store = InMemoryAccountStore::new();
        store.put(key_account.clone()).unwrap();
        let capacity = store.inner.capacity();
        assert!(capacity < 200);
        for id in 2..=capacity {
            store.put(account(id as u8)).unwrap();
        }
        assert_eq!(store.inner.len(), capacity);
        let provider = StaticCryptoProvider::new()
            .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100)));
        let binding = FixtureBinding {
            chain_id: 1,
            execution_pre_state: [4; 32],
            provider_identity: [5; 32],
            policy: PrototypePolicy {
                identity: [6; 32],
                version: 1,
                limits: NativeTransactionProofLimits {
                    max_required_signer_indices: 1,
                    max_keyset_account_count: 1,
                    max_authentication_proof_count: 1,
                    max_signature_bytes: 2420,
                    max_aggregate_signature_bytes: 2420,
                    stored_keyset: StoredKeysetLimits {
                        max_encoded_bytes: 2048,
                        max_entries: 1,
                        max_key_bytes: 1312,
                        max_total_key_bytes: 1312,
                    },
                    max_algorithm_parameter_identifier_bytes: 128,
                },
            },
        };
        let mut tx = Transaction {
            version: 1,
            chain_id: 1,
            payer: [2; 32],
            nonce: 1,
            fee_limit: 0,
            accounts: vec![TxAccountMeta {
                account_id: [1; 32],
                flags: 1,
                access_hint: 0,
                reserved0: [0; 2],
            }],
            program_id: [3; 32],
            call_data: vec![],
            auths: vec![],
        };
        let signature =
            ml_dsa_44_sign_digest(&secret, &try_tx_digest_streaming(&tx).unwrap()).unwrap();
        tx.auths.push(TxAuth {
            account_index: 0,
            suite_id: 100,
            reserved: 0,
            signature,
        });
        reset();
        let mut s = NativeStagedEffects::<1, 1, 1, 1>::begin_for_fixture(
            &mut store,
            &tx,
            Some(FixtureSelection::new_for_fixture(
                &provider,
                binding,
                FixtureProfileStatus::Active,
            )),
            Some(binding),
            limits(1),
        )
        .ok()
        .unwrap();
        s.create_for_fixture([200; 32], account(200)).unwrap();
        assert_eq!(s.publish_for_fixture(), Err(Error::MapCapacity));
        assert_eq!(counts(), (1, 0));
        assert_eq!(store.inner.len(), capacity);
        assert_eq!(store.inner.capacity(), capacity);
        assert_eq!(store.inner.get(&[1; 32]), Some(&key_account));
        for id in 2..=capacity {
            assert_eq!(store.inner.get(&[id as u8; 32]), Some(&account(id as u8)));
        }
        assert!(!store.inner.contains_key(&[200; 32]));

        store.inner.reserve(1); // provisioning after release, not in publication
        assert!(store.inner.capacity() > capacity);
        reset();
        let mut s = NativeStagedEffects::<1, 1, 1, 1>::begin_for_fixture(
            &mut store,
            &tx,
            Some(FixtureSelection::new_for_fixture(
                &provider,
                binding,
                FixtureProfileStatus::Active,
            )),
            Some(binding),
            limits(1),
        )
        .ok()
        .unwrap();
        let offered = account(200);
        let pointer = offered.data.as_ptr();
        s.create_for_fixture([200; 32], offered).unwrap();
        s.publish_for_fixture().unwrap();
        assert_eq!(counts(), (1, 1));
        assert_eq!(store.inner.get(&[200; 32]).unwrap().data.as_ptr(), pointer);
        assert_eq!(store.inner.len(), capacity + 1);
        assert_eq!(store.inner.get(&[1; 32]), Some(&key_account));
    }
}

impl Default for InMemoryAccountStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod run422_native_keyset_create_model {
    use super::*;
    use crate::native_keyset_create_model::observation;
    use crate::native_staged_effects::FixtureStageRefusal;

    // The same genuine composition fixtures also execute as integration tests.
    mod fixture {
        use crate as qbind_ledger;
        include!("../tests/run_422_native_keyset_create_model_tests.rs");
    }

    #[test]
    fn actual_composition_preparation_entry_boundaries() {
        use crate::native_keyset_create_model::KeysetCreateModelError;
        for case in 0..8 {
            let mut f = fixture::Fixture::new();
            let mut config = fixture::config();
            match case {
                0 => f.tx.program_id = [0; 32],
                1 => config.staging.max_operations = 2,
                2 => f.tx.auths[0].signature[0] ^= 1,
                3 => f.tx.auths.clear(),
                4 => {
                    f.tx.accounts[0].account_id = fixture::TARGET;
                    f.resign(true);
                }
                5 => {
                    f.tx.call_data.push(0);
                    f.resign(false);
                }
                6 => {
                    f.tx.call_data[34..36].copy_from_slice(&0u16.to_le_bytes());
                    f.resign(false);
                }
                _ => config.preparation.max_stored_data_bytes = 1329,
            }
            observation::reset();
            let error = match fixture::Model::begin_for_fixture(
                &mut f.store,
                &f.tx,
                Some(fixture::selection(&f.provider)),
                Some(fixture::binding()),
                config,
            ) {
                Ok(_) => panic!("expected refusal"),
                Err(error) => error,
            };
            let entries = usize::from(case >= 5);
            assert_eq!(observation::get(), (entries, 0, 0, 0));
            assert_eq!(
                matches!(error, KeysetCreateModelError::Preparation(_)),
                case >= 5
            );
            f.preserved();
            assert!(!f.store.inner.contains_key(&fixture::TARGET));
            if case >= 5 {
                assert_eq!(f.provider.work().2, 1);
            }
        }
    }

    #[test]
    fn actual_composition_capacity_retry_and_allocation_movement() {
        let mut f = fixture::Fixture::new();
        let capacity = f.store.inner.capacity();
        assert!(capacity >= 3 && capacity < 200);
        let fillers = capacity - f.store.inner.len() - 1;
        for id in 0..fillers {
            f.store
                .put(Account::new([100 + id as u8; 32], [7; 32], 42, vec![9; 4]))
                .unwrap();
        }
        observation::reset();
        let m = f.begin().unwrap();
        let (entries, pointer, length, allocated) = observation::get();
        assert_eq!(entries, 1);
        assert_eq!(length, 1330);
        assert!(allocated >= length);
        assert_ne!(pointer, 0);
        let summary = m.publish_for_fixture().unwrap();
        assert_eq!(summary.resulting_accounts, capacity);
        let actual = f.store.inner.get(&fixture::TARGET).unwrap();
        assert_eq!(
            (
                actual.data.as_ptr() as usize,
                actual.data.len(),
                actual.data.capacity()
            ),
            (pointer, length, allocated)
        );
        assert_eq!(actual, &f.expected);
        assert_eq!(f.store.inner.capacity(), capacity);
        f.preserved();
        for id in 0..fillers {
            assert_eq!(
                f.store.inner.get(&[100 + id as u8; 32]),
                Some(&Account::new([100 + id as u8; 32], [7; 32], 42, vec![9; 4]))
            );
        }
        println!("exact map capacity={capacity}; prepared len={length} actual capacity={allocated}; pointer moved to private map");

        f.tx.call_data[2..34].copy_from_slice(&[20; 32]);
        // Re-sign the actual changed body via the shared genuine fixture helper.
        f.resign(false);
        observation::reset();
        let work = f.provider.work();
        assert_eq!(
            f.begin().unwrap().publish_for_fixture(),
            Err(FixtureStageRefusal::MapCapacity)
        );
        assert_eq!(observation::get().0, 1);
        assert_eq!(f.store.inner.len(), capacity);
        f.preserved();
        assert_eq!(f.store.inner.get(&fixture::TARGET), Some(&f.expected));
        assert!(!f.store.inner.contains_key(&[20; 32]));
        for id in 0..fillers {
            assert_eq!(
                f.store.inner.get(&[100 + id as u8; 32]),
                Some(&Account::new([100 + id as u8; 32], [7; 32], 42, vec![9; 4]))
            );
        }
        assert_eq!(f.store.inner.capacity(), capacity);
        assert!(f.provider.work().2 > work.2);
        f.store.inner.reserve(1); // Only after consuming refusal released exclusivity.
        let provisioned = f.store.inner.capacity();
        assert!(provisioned > capacity);
        let work = f.provider.work();
        let m = f.begin().unwrap();
        let (_, pointer, length, allocated) = observation::get();
        assert_eq!(observation::get().0, 2);
        m.publish_for_fixture().unwrap();
        let actual = f.store.inner.get(&[20; 32]).unwrap();
        assert_eq!(
            (
                actual.data.as_ptr() as usize,
                actual.data.len(),
                actual.data.capacity()
            ),
            (pointer, length, allocated)
        );
        assert!(f.provider.work().2 > work.2);
        f.preserved();
        assert_eq!(f.store.inner.get(&fixture::TARGET), Some(&f.expected));
        assert_eq!(f.store.inner.len(), capacity + 1);
        for id in 0..fillers {
            assert_eq!(
                f.store.inner.get(&[100 + id as u8; 32]),
                Some(&Account::new([100 + id as u8; 32], [7; 32], 42, vec![9; 4]))
            );
        }
        println!("insufficient map capacity={capacity}; outside-attempt provisioned={provisioned}; fresh proofs/preparation repeated");
    }
}

impl AccountStore for InMemoryAccountStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.inner.get(id).cloned()
    }

    fn get_bounded(
        &self,
        id: &AccountId,
        max_data_bytes: usize,
    ) -> Result<Option<Account>, BoundedReadError> {
        let Some(account) = self.inner.get(id) else {
            return Ok(None);
        };
        if account.data.len() > max_data_bytes {
            return Err(BoundedReadError::Oversized);
        }

        materialize_account(account).map(Some)
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.inner.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.inner.remove(id);
        Ok(())
    }
}

fn materialize_account(account: &Account) -> Result<Account, BoundedReadError> {
    #[cfg(test)]
    observe_materialization_boundary(account.data.len());

    let mut data = Vec::new();
    data.try_reserve_exact(account.data.len())
        .map_err(|_| BoundedReadError::Backend)?;
    data.extend_from_slice(&account.data);

    Ok(Account {
        id: account.id,
        header: account.header.clone(),
        data,
    })
}

#[cfg(test)]
thread_local! {
    static MATERIALIZATION_OBSERVER: std::cell::Cell<(usize, usize)> =
        std::cell::Cell::new((0, 0));
}

#[cfg(test)]
fn observe_materialization_boundary(requested_data_len: usize) {
    MATERIALIZATION_OBSERVER.with(|observer| {
        let (calls, _) = observer.get();
        observer.set((calls + 1, requested_data_len));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::AccountHeader;
    use std::cell::Cell;

    fn account(id_byte: u8, data: Vec<u8>) -> Account {
        Account {
            id: [id_byte; 32],
            header: AccountHeader {
                owner: [id_byte.wrapping_add(1); 32],
                lamports: 0x0102_0304_0506_0708,
                is_executable: true,
                rent_epoch: 0x1112_1314_1516_1718,
                reserved: [id_byte.wrapping_add(2); 8],
            },
            data,
        }
    }

    fn observed_materializations() -> (usize, usize) {
        MATERIALIZATION_OBSERVER.with(Cell::get)
    }

    fn reset_materialization_observer() {
        MATERIALIZATION_OBSERVER.with(|observer| observer.set((0, 0)));
    }

    struct LegacyOnlyStore {
        get_calls: Cell<usize>,
        put_calls: Cell<usize>,
        delete_calls: Cell<usize>,
    }

    impl AccountStore for LegacyOnlyStore {
        fn get(&self, _id: &AccountId) -> Option<Account> {
            self.get_calls.set(self.get_calls.get() + 1);
            None
        }

        fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
            self.put_calls.set(self.put_calls.get() + 1);
            Ok(())
        }

        fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
            self.delete_calls.set(self.delete_calls.get() + 1);
            Ok(())
        }
    }

    #[test]
    fn run422_bounded_account_read_default_is_unsupported_without_legacy_calls() {
        let mut store = LegacyOnlyStore {
            get_calls: Cell::new(0),
            put_calls: Cell::new(0),
            delete_calls: Cell::new(0),
        };
        let id = [1; 32];

        assert_eq!(store.get(&id), None);
        store.put(account(1, vec![])).unwrap();
        store.delete(&id).unwrap();
        assert_eq!(store.get_calls.get(), 1);
        assert_eq!(store.put_calls.get(), 1);
        assert_eq!(store.delete_calls.get(), 1);

        store.get_calls.set(0);
        store.put_calls.set(0);
        store.delete_calls.set(0);
        let object_safe_store: &dyn AccountStore = &store;
        assert_eq!(
            object_safe_store.get_bounded(&id, 0),
            Err(BoundedReadError::Unsupported)
        );
        assert_eq!(store.get_calls.get(), 0);
        assert_eq!(store.put_calls.get(), 0);
        assert_eq!(store.delete_calls.get(), 0);
    }

    #[test]
    fn run422_bounded_account_read_missing_and_zero_budget_semantics() {
        let store = InMemoryAccountStore::new();
        assert_eq!(store.get_bounded(&[9; 32], 0), Ok(None));
        assert_eq!(store.get(&[9; 32]), None);

        let mut store = store;
        let empty = account(2, Vec::new());
        store.put(empty.clone()).unwrap();
        assert_eq!(store.get_bounded(&empty.id, 0), Ok(Some(empty.clone())));
        assert_eq!(store.get(&empty.id), Some(empty));
    }

    #[test]
    fn run422_bounded_account_read_exact_limit_preserves_complete_account() {
        let mut store = InMemoryAccountStore::new();
        let expected = account(3, vec![0xA5; 12]);
        let id = expected.id;
        store.put(expected.clone()).unwrap();

        let result = store.get_bounded(&id, expected.data.len()).unwrap();
        assert_eq!(result, Some(expected.clone()));
        assert_eq!(store.get(&id), Some(expected));
    }

    #[test]
    fn run422_bounded_account_read_one_byte_over_limit_refuses() {
        let mut store = InMemoryAccountStore::new();
        let stored = account(4, vec![0x5A; 13]);
        let id = stored.id;
        store.put(stored.clone()).unwrap();

        assert_eq!(store.get_bounded(&id, 12), Err(BoundedReadError::Oversized));
        assert_eq!(store.get_bounded(&id, 0), Err(BoundedReadError::Oversized));
        assert_eq!(store.get(&id), Some(stored));
    }

    #[test]
    fn run422_bounded_account_read_ignores_source_spare_capacity() {
        let mut source_data = Vec::with_capacity(16 * 1024);
        source_data.extend_from_slice(b"bounded-data");
        let source_capacity = source_data.capacity();
        let expected_len = source_data.len();
        let mut store = InMemoryAccountStore::new();
        let stored = account(5, source_data);
        let id = stored.id;
        store.put(stored).unwrap();

        let result = store
            .get_bounded(&id, expected_len)
            .unwrap()
            .expect("stored account");
        assert_eq!(result.data.len(), expected_len);
        assert!(result.data.capacity() >= expected_len);
        assert!(result.data.capacity() < source_capacity);
        assert_eq!(result, store.get(&id).unwrap());
    }

    #[test]
    fn run422_bounded_account_read_returns_independent_owned_data() {
        let mut store = InMemoryAccountStore::new();
        let original = account(6, vec![1, 2, 3, 4]);
        let id = original.id;
        store.put(original.clone()).unwrap();

        let mut result = store.get_bounded(&id, 4).unwrap().unwrap();
        result.data[0] = 0xFF;
        result.header.reserved[0] = 0xEE;
        drop(result);

        assert_eq!(store.get(&id), Some(original));
    }

    #[test]
    fn run422_bounded_account_read_observes_refusal_before_materialization() {
        reset_materialization_observer();
        let mut store = InMemoryAccountStore::new();
        let stored = account(7, vec![0xCC; 32]);
        let id = stored.id;
        store.put(stored.clone()).unwrap();

        assert_eq!(store.get_bounded(&id, 31), Err(BoundedReadError::Oversized));
        assert_eq!(observed_materializations(), (0, 0));
        assert_eq!(store.get(&id), Some(stored.clone()));

        let returned = store.get_bounded(&id, 32).unwrap().unwrap();
        assert_eq!(returned, stored);
        assert_eq!(observed_materializations(), (1, 32));
        assert_eq!(store.get(&id), Some(stored));
    }

    #[test]
    fn run422_bounded_account_read_supported_through_trait_object() {
        let mut store = InMemoryAccountStore::new();
        let expected = account(8, vec![0x42; 5]);
        let id = expected.id;
        store.put(expected.clone()).unwrap();

        let object_safe_store: &dyn AccountStore = &store;
        assert_eq!(
            object_safe_store.get_bounded(&id, 5),
            Ok(Some(expected.clone()))
        );
        assert_eq!(store.get(&id), Some(expected));
    }
}
