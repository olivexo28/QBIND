//! Unused, trusted fixture effect plan; never native program authority.
//!
//! One exclusive concrete store borrow spans fresh proof evaluation, staging
//! and consuming publication/cancellation. Provider stability and fixture label
//! provenance remain trusted assumptions. No persistent MVCC, crash durability,
//! restart safety or rollback after arbitrary publication panic is implemented.
//! All caller-supplied limits are UNAPPROVED; there are no defaults.
//!
//! Valid release permits normal caller mutation:
//! ```
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::{AccountStore, InMemoryAccountStore};
//! use qbind_ledger::native_admission_context::{FixtureBinding, FixtureProfileStatus};
//! use qbind_ledger::native_staged_effects::{
//!     FixtureSelection, FixtureStageLimits, NativeStagedEffects,
//! };
//! use qbind_wire::tx::Transaction;
//! fn example(store: &mut InMemoryAccountStore, tx: &mut Transaction,
//!            provider: &dyn CryptoProvider, binding: FixtureBinding) {
//!     let selected = FixtureSelection::new_for_fixture(provider, binding, FixtureProfileStatus::Active);
//!     if let Ok(session) = NativeStagedEffects::<8,8,16,3>::begin_for_fixture(
//!         store, tx, Some(selected), Some(binding),
//!         FixtureStageLimits { max_operations: 3, max_data_len: 8,
//!             max_account_capacity: 8, max_aggregate_capacity: 24 }) {
//!         session.cancel();
//!     }
//!     store.delete(&[0;32]).unwrap();
//!     tx.auths.clear();
//! }
//! ```
//! An external writer cannot run while the session remains usable:
//! ```compile_fail,E0499
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::{AccountStore, InMemoryAccountStore};
//! use qbind_ledger::native_admission_context::{FixtureBinding, FixtureProfileStatus};
//! use qbind_ledger::native_staged_effects::{FixtureSelection, FixtureStageLimits, NativeStagedEffects};
//! use qbind_wire::tx::Transaction;
//! fn example(store: &mut InMemoryAccountStore, tx: &Transaction, p: &dyn CryptoProvider,
//!            b: FixtureBinding, limits: FixtureStageLimits) {
//!     let s = NativeStagedEffects::<8,8,16,3>::begin_for_fixture(store, tx,
//!         Some(FixtureSelection::new_for_fixture(p,b,FixtureProfileStatus::Active)),Some(b),limits).unwrap();
//!     store.delete(&[0;32]).unwrap();
//!     s.cancel();
//! }
//! ```
//! Complete proof bytes cannot change:
//! ```compile_fail,E0502
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_admission_context::{FixtureBinding, FixtureProfileStatus};
//! use qbind_ledger::native_staged_effects::{FixtureSelection, FixtureStageLimits, NativeStagedEffects};
//! use qbind_wire::tx::Transaction;
//! fn example(store: &mut InMemoryAccountStore, tx: &mut Transaction, p: &dyn CryptoProvider,
//!            b: FixtureBinding, limits: FixtureStageLimits) {
//!     let s = NativeStagedEffects::<8,8,16,3>::begin_for_fixture(store, tx,
//!         Some(FixtureSelection::new_for_fixture(p,b,FixtureProfileStatus::Active)),Some(b),limits).unwrap();
//!     tx.auths.clear();
//!     s.cancel();
//! }
//! ```
//! Publication and cancellation consume the session:
//! ```compile_fail,E0502
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_admission_context::{FixtureBinding, FixtureProfileStatus};
//! use qbind_ledger::native_staged_effects::{FixtureSelection, FixtureStageLimits, NativeStagedEffects};
//! use qbind_wire::tx::Transaction;
//! fn example(store: &mut InMemoryAccountStore, tx: &mut Transaction, p: &dyn CryptoProvider,
//!            b: FixtureBinding, limits: FixtureStageLimits) {
//!     let s = NativeStagedEffects::<8,8,16,3>::begin_for_fixture(store, tx,
//!         Some(FixtureSelection::new_for_fixture(p,b,FixtureProfileStatus::Active)),Some(b),limits).unwrap();
//!     tx.call_data.clear();
//!     let _ = s.publish_for_fixture();
//! }
//! ```
//! The selected provider owner cannot be replaced/destroyed:
//! ```compile_fail,E0505
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_admission_context::{FixtureBinding, FixtureProfileStatus};
//! use qbind_ledger::native_staged_effects::{FixtureSelection, FixtureStageLimits, NativeStagedEffects};
//! use qbind_wire::tx::Transaction;
//! fn example(store: &mut InMemoryAccountStore, tx: &Transaction, p: Box<dyn CryptoProvider>,
//!            b: FixtureBinding, limits: FixtureStageLimits) {
//!     let s = NativeStagedEffects::<8,8,16,3>::begin_for_fixture(store, tx,
//!         Some(FixtureSelection::new_for_fixture(&*p,b,FixtureProfileStatus::Active)),Some(b),limits).unwrap();
//!     drop(p);
//!     s.cancel();
//! }
//! ```
//! Session inputs are private, not a caller-rebindable capability:
//! ```compile_fail,E0616
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_staged_effects::NativeStagedEffects;
//! fn example(mut s: NativeStagedEffects<'_,8,8,16,3>, other: &mut InMemoryAccountStore) {
//!     s.store = other;
//!     s.cancel();
//! }
//! ```
//! ```compile_fail,E0616
//! use qbind_ledger::native_staged_effects::{NativeStagedEffects, FixtureSelection};
//! fn example<'a>(mut s: NativeStagedEffects<'a,8,8,16,3>, selected: FixtureSelection<'a>) {
//!     s._selected = selected;
//!     s.cancel();
//! }
//! ```
//! ```compile_fail,E0382
//! use qbind_ledger::native_staged_effects::NativeStagedEffects;
//! fn example(s: NativeStagedEffects<'_,8,8,16,3>) {
//!     let _ = s.publish_for_fixture();
//!     s.cancel();
//! }
//! ```
//! ```compile_fail,E0382
//! use qbind_ledger::native_staged_effects::NativeStagedEffects;
//! fn example(s: NativeStagedEffects<'_,8,8,16,3>) {
//!     s.cancel();
//!     let _ = s.publish_for_fixture();
//! }
//! ```

use crate::native_admission_context::{
    FixtureBinding, FixtureProfileStatus, NativeAdmissionContext, NativeAdmissionContextError,
    PrototypeFixture,
};
use crate::native_tx_proof::NativeTransactionProofError;
use crate::{Account, InMemoryAccountStore};
use qbind_crypto::CryptoProvider;
use qbind_types::AccountId;
use qbind_wire::tx::Transaction;

/// Trusted selected inputs, separate from the requested binding.
pub struct FixtureSelection<'a> {
    provider: &'a dyn CryptoProvider,
    binding: FixtureBinding,
    status: FixtureProfileStatus,
}

impl<'a> FixtureSelection<'a> {
    pub fn new_for_fixture(
        provider: &'a dyn CryptoProvider,
        binding: FixtureBinding,
        status: FixtureProfileStatus,
    ) -> Self {
        Self {
            provider,
            binding,
            status,
        }
    }
}

/// Independent fixture limits, not the native proof candidate profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureStageLimits {
    pub max_operations: usize,
    pub max_data_len: usize,
    pub max_account_capacity: usize,
    pub max_aggregate_capacity: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixtureBeginError {
    StageConfiguration,
    Context(NativeAdmissionContextError),
    Proof(NativeTransactionProofError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureStageRefusal {
    Poisoned,
    OperationCapacity,
    DuplicateTarget,
    AccountIdMismatch,
    LogicalLength,
    AccountCapacity,
    AggregateCapacity,
    ArithmeticOverflow,
    CreateExisting,
    ReplaceMissing,
    DeleteMissing,
    /// Local model inability, never a consensus transaction-failure receipt.
    MapCapacity,
}

/// On rejected create/replace the original allocation remains caller-owned.
#[derive(Debug)]
pub struct FixtureAccountRefusal {
    pub reason: FixtureStageRefusal,
    pub account: Account,
}

/// Fixed diagnostic counts only: no durability or authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixturePublicationSummary {
    pub operations: usize,
    pub creates: usize,
    pub replaces: usize,
    pub deletes: usize,
    pub retained_capacity: usize,
    pub resulting_accounts: usize,
}

pub(crate) enum FixtureEffect {
    Create(AccountId, Account),
    Replace(AccountId, Account),
    Delete(AccountId),
}

impl FixtureEffect {
    pub(crate) fn target(&self) -> &AccountId {
        match self {
            Self::Create(id, _) | Self::Replace(id, _) | Self::Delete(id) => id,
        }
    }

    pub(crate) fn account(&self) -> Option<&Account> {
        match self {
            Self::Create(_, a) | Self::Replace(_, a) => Some(a),
            Self::Delete(_) => None,
        }
    }
}

pub(crate) fn checked_capacity(
    retained: usize,
    offered: usize,
    limit: usize,
) -> Result<usize, FixtureStageRefusal> {
    let total = retained
        .checked_add(offered)
        .ok_or(FixtureStageRefusal::ArithmeticOverflow)?;
    if total > limit {
        return Err(FixtureStageRefusal::AggregateCapacity);
    }
    Ok(total)
}

pub(crate) fn check_account(
    target: &AccountId,
    account: &Account,
    limits: FixtureStageLimits,
) -> Result<(), FixtureStageRefusal> {
    if target != &account.id {
        return Err(FixtureStageRefusal::AccountIdMismatch);
    }
    if account.data.len() > limits.max_data_len {
        return Err(FixtureStageRefusal::LogicalLength);
    }
    if account.data.capacity() > limits.max_account_capacity {
        return Err(FixtureStageRefusal::AccountCapacity);
    }
    Ok(())
}

pub(crate) fn checked_result_counts(
    len: usize,
    creates: usize,
    deletes: usize,
) -> Result<(usize, usize), FixtureStageRefusal> {
    let peak = len
        .checked_add(creates)
        .ok_or(FixtureStageRefusal::ArithmeticOverflow)?;
    let result = peak
        .checked_sub(deletes)
        .ok_or(FixtureStageRefusal::ArithmeticOverflow)?;
    Ok((peak, result))
}

/// Private bounded stage; no read-your-writes, dispatch, rebinding or authority API.
pub struct NativeStagedEffects<'a, const G: usize, const P: usize, const E: usize, const W: usize> {
    store: &'a mut InMemoryAccountStore,
    _transaction: &'a Transaction,
    _selected: FixtureSelection<'a>,
    limits: FixtureStageLimits,
    effects: [Option<FixtureEffect>; W],
    operations: usize,
    retained_capacity: usize,
    poisoned: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::native_admission_context::PrototypePolicy;
    use crate::native_tx_proof::NativeTransactionProofLimits;
    use crate::AccountStore;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::{ml_dsa_44_sign_digest, MlDsa44SignatureSuite, StaticCryptoProvider};
    use qbind_hash::tx::try_tx_digest_streaming;
    use qbind_serde::keyset::StoredKeysetLimits;
    use qbind_serde::StateEncode;
    use qbind_types::{KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
    use qbind_wire::tx::{TxAccountMeta, TxAuth};
    use std::mem::size_of;
    use std::sync::Arc;

    #[test]
    fn run422_native_staged_effects_private_stage_preservation_and_copied_selection() {
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
        let original = Account::new([1; 32], KEYSET_PROGRAM_ID, 0, data);
        let mut store = InMemoryAccountStore::new();
        store.put(original.clone()).unwrap();
        let provider = StaticCryptoProvider::new()
            .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100)));
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
            reserved0: 0,
            signature,
        });
        let mut binding = FixtureBinding {
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
        let selected_binding = binding;
        let mut s = NativeStagedEffects::<1, 1, 1, 2>::begin_for_fixture(
            &mut store,
            &tx,
            Some(FixtureSelection::new_for_fixture(
                &provider,
                binding,
                FixtureProfileStatus::Active,
            )),
            Some(binding),
            FixtureStageLimits {
                max_operations: 2,
                max_data_len: 4,
                max_account_capacity: 4,
                max_aggregate_capacity: 8,
            },
        )
        .ok()
        .unwrap();
        binding.policy.version = 2;
        assert_ne!(binding, selected_binding);
        assert_eq!(s._selected.binding, selected_binding);
        let offered = Account::new([20; 32], [9; 32], 10, vec![7; 4]);
        let pointer = offered.data.as_ptr();
        s.create_for_fixture([20; 32], offered).unwrap();
        assert_eq!(s.store.get(&original.id), Some(original.clone()));
        assert_eq!(s.store.get(&[20; 32]), None);
        assert_eq!(s.operations, 1);
        assert_eq!(s.retained_capacity, 4);
        assert_eq!(
            s.effects
                .iter()
                .flatten()
                .next()
                .unwrap()
                .account()
                .unwrap()
                .data
                .as_ptr(),
            pointer
        );
        let candidate = Account::new([21; 32], [9; 32], 10, vec![8; 4]);
        let candidate_pointer = candidate.data.as_ptr();
        let refusal = s.create_for_fixture([20; 32], candidate).unwrap_err();
        assert_eq!(refusal.account.data.as_ptr(), candidate_pointer);
        assert_eq!(s.operations, 1);
        assert_eq!(s.retained_capacity, 4);
        assert_eq!(s.effects.iter().flatten().count(), 1);
        assert_eq!(
            s.effects
                .iter()
                .flatten()
                .next()
                .unwrap()
                .account()
                .unwrap()
                .data
                .as_ptr(),
            pointer
        );
        assert_eq!(s.publish_for_fixture(), Err(FixtureStageRefusal::Poisoned));
        assert_eq!(store.get(&original.id), Some(original));
        assert_eq!(store.get(&[20; 32]), None);
    }

    #[test]
    fn run422_native_staged_effects_scalar_overflow_and_layouts() {
        assert_eq!(
            checked_capacity(usize::MAX, 1, usize::MAX),
            Err(FixtureStageRefusal::ArithmeticOverflow)
        );
        assert_eq!(checked_capacity(4, 4, 8), Ok(8));
        assert_eq!(
            checked_capacity(4, 5, 8),
            Err(FixtureStageRefusal::AggregateCapacity)
        );
        assert_eq!(
            checked_result_counts(usize::MAX, 1, 0),
            Err(FixtureStageRefusal::ArithmeticOverflow)
        );
        assert_eq!(
            checked_result_counts(0, 0, 1),
            Err(FixtureStageRefusal::ArithmeticOverflow)
        );
        println!("layout session W=0/1/3={}/{}/{} operation={} option_operation={} summary={} stage_error={} offered_error={} begin_error={} selection={} limits={}",
            size_of::<NativeStagedEffects<8,8,16,0>>(),
            size_of::<NativeStagedEffects<8,8,16,1>>(),
            size_of::<NativeStagedEffects<8,8,16,3>>(),
            size_of::<FixtureEffect>(), size_of::<Option<FixtureEffect>>(),
            size_of::<FixturePublicationSummary>(), size_of::<FixtureStageRefusal>(),
            size_of::<FixtureAccountRefusal>(), size_of::<FixtureBeginError>(),
            size_of::<FixtureSelection>(), size_of::<FixtureStageLimits>());
        assert_eq!(
            size_of::<NativeStagedEffects<8, 8, 16, 3>>()
                - size_of::<NativeStagedEffects<8, 8, 16, 0>>(),
            3 * size_of::<Option<FixtureEffect>>()
        );
    }
}

impl<'a, const G: usize, const P: usize, const E: usize, const W: usize>
    NativeStagedEffects<'a, G, P, E, W>
{
    /// Acquires exclusivity before constructing the temporary read context.
    /// Failure returns no usable session and never changes the store.
    pub fn begin_for_fixture(
        store: &'a mut InMemoryAccountStore,
        transaction: &'a Transaction,
        selected: Option<FixtureSelection<'a>>,
        requested: Option<FixtureBinding>,
        limits: FixtureStageLimits,
    ) -> Result<Self, FixtureBeginError> {
        if limits.max_operations > W
            || limits.max_data_len > limits.max_account_capacity
            || limits.max_account_capacity > limits.max_aggregate_capacity
        {
            return Err(FixtureBeginError::StageConfiguration);
        }
        {
            let fixture = selected.as_ref().map(|s| {
                PrototypeFixture::new_for_fixture(&*store, s.provider, s.binding, s.status)
            });
            let context = NativeAdmissionContext::<G, P, E>::new_for_fixture(
                fixture.as_ref(),
                requested,
                transaction,
            )
            .map_err(FixtureBeginError::Context)?;
            context.evaluate().map_err(FixtureBeginError::Proof)?;
            context.cancel();
        }
        let selected = selected.ok_or(FixtureBeginError::Context(
            NativeAdmissionContextError::UnavailableFixture,
        ))?;
        Ok(Self {
            store,
            _transaction: transaction,
            _selected: selected,
            limits,
            effects: std::array::from_fn(|_| None),
            operations: 0,
            retained_capacity: 0,
            poisoned: false,
        })
    }

    fn admit_slot(
        &mut self,
        target: &AccountId,
        account: Option<&Account>,
    ) -> Result<&mut Option<FixtureEffect>, FixtureStageRefusal> {
        let checked = (|| {
            if self.poisoned {
                return Err(FixtureStageRefusal::Poisoned);
            }
            let count = self
                .operations
                .checked_add(1)
                .ok_or(FixtureStageRefusal::ArithmeticOverflow)?;
            if count > self.limits.max_operations || count > W {
                return Err(FixtureStageRefusal::OperationCapacity);
            }
            if self.effects.iter().flatten().any(|e| e.target() == target) {
                return Err(FixtureStageRefusal::DuplicateTarget);
            }
            let capacity = if let Some(a) = account {
                check_account(target, a, self.limits)?;
                a.data.capacity()
            } else {
                0
            };
            let total = checked_capacity(
                self.retained_capacity,
                capacity,
                self.limits.max_aggregate_capacity,
            )?;
            Ok((count, total))
        })();
        let (count, total) = match checked {
            Ok(values) => values,
            Err(reason) => {
                self.poisoned = true;
                return Err(reason);
            }
        };
        if let Some(slot) = self.effects.iter_mut().find(|e| e.is_none()) {
            self.operations = count;
            self.retained_capacity = total;
            Ok(slot)
        } else {
            self.poisoned = true;
            Err(FixtureStageRefusal::OperationCapacity)
        }
    }

    pub fn create_for_fixture(
        &mut self,
        target: AccountId,
        account: Account,
    ) -> Result<(), FixtureAccountRefusal> {
        let slot = match self.admit_slot(&target, Some(&account)) {
            Ok(slot) => slot,
            Err(reason) => return Err(FixtureAccountRefusal { reason, account }),
        };
        *slot = Some(FixtureEffect::Create(target, account));
        Ok(())
    }

    pub fn replace_for_fixture(
        &mut self,
        target: AccountId,
        account: Account,
    ) -> Result<(), FixtureAccountRefusal> {
        let slot = match self.admit_slot(&target, Some(&account)) {
            Ok(slot) => slot,
            Err(reason) => return Err(FixtureAccountRefusal { reason, account }),
        };
        *slot = Some(FixtureEffect::Replace(target, account));
        Ok(())
    }

    pub fn delete_for_fixture(&mut self, target: AccountId) -> Result<(), FixtureStageRefusal> {
        let slot = self.admit_slot(&target, None)?;
        *slot = Some(FixtureEffect::Delete(target));
        Ok(())
    }

    /// Consumes on either outcome. Refusal drops stage-owned accounts only.
    pub fn publish_for_fixture(mut self) -> Result<FixturePublicationSummary, FixtureStageRefusal> {
        self.store
            .publish_native_fixture_batch(&mut self.effects, self.limits, !self.poisoned)
    }

    /// Discards stage-owned effects; caller store/transaction/provider survive.
    pub fn cancel(self) {}
}
