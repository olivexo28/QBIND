//! Isolated, unused native diagnostic read context; not execution authority.
//!
//! The concrete store's private map and safe immutable borrow pin in-memory
//! reads. A generic `AccountStore` borrow promises only per-account coherence
//! and could switch generations between reads. No persistent/backend snapshot,
//! chain authority, freshness, staging, commit or recovery is established here.
//! Execution-position and policy provenance are trusted fixture inputs only.
//! Provider semantic stability is a separate trusted assumption: borrowing a
//! trait object does not prove immutable canonical or verification semantics.
//! Every numerical limit remains UNAPPROVED.
//!
//! Valid construction and release (fixture inputs, not approved policy):
//! ```
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::{AccountStore, InMemoryAccountStore};
//! use qbind_ledger::native_admission_context::{
//!     FixtureBinding, FixtureProfileStatus, NativeAdmissionContext, PrototypeFixture,
//! };
//! use qbind_wire::tx::Transaction;
//! fn example(store: &mut InMemoryAccountStore, tx: &mut Transaction,
//!            provider: &dyn CryptoProvider, binding: FixtureBinding) {
//!     let fixture = PrototypeFixture::new_for_fixture(
//!         store, provider, binding, FixtureProfileStatus::Active);
//!     let context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
//!         Some(&fixture), Some(binding), tx).unwrap();
//!     let _diagnostic = context.evaluate();
//!     context.cancel();
//!     store.delete(&[0; 32]).unwrap();
//!     tx.auths.clear();
//! }
//! ```
//!
//! The borrow must remain immutable through the last context use:
//! ```compile_fail,E0502
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::{AccountStore, InMemoryAccountStore};
//! use qbind_ledger::native_admission_context::{
//!     FixtureBinding, FixtureProfileStatus, NativeAdmissionContext, PrototypeFixture,
//! };
//! use qbind_wire::tx::Transaction;
//! fn example(store: &mut InMemoryAccountStore, tx: &Transaction,
//!            provider: &dyn CryptoProvider, binding: FixtureBinding) {
//!     let fixture = PrototypeFixture::new_for_fixture(
//!         store, provider, binding, FixtureProfileStatus::Active);
//!     let context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
//!         Some(&fixture), Some(binding), tx).unwrap();
//!     store.delete(&[0; 32]).unwrap();
//!     let _ = context.evaluate();
//! }
//! ```
//! ```compile_fail,E0502
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_admission_context::{
//!     FixtureBinding, FixtureProfileStatus, NativeAdmissionContext, PrototypeFixture,
//! };
//! use qbind_wire::tx::Transaction;
//! fn example(store: &InMemoryAccountStore, tx: &mut Transaction,
//!            provider: &dyn CryptoProvider, binding: FixtureBinding) {
//!     let fixture = PrototypeFixture::new_for_fixture(
//!         store, provider, binding, FixtureProfileStatus::Active);
//!     let context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
//!         Some(&fixture), Some(binding), tx).unwrap();
//!     tx.auths.clear();
//!     let _ = context.evaluate();
//! }
//! ```
//!
//! A required owner cannot be destroyed while the context remains usable:
//! ```compile_fail,E0597
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_admission_context::{
//!     FixtureBinding, FixtureProfileStatus, NativeAdmissionContext, PrototypeFixture,
//! };
//! use qbind_wire::tx::Transaction;
//! fn example(tx: &Transaction, provider: &dyn CryptoProvider, binding: FixtureBinding) {
//!     let context;
//!     {
//!         let store = InMemoryAccountStore::new();
//!         let fixture = PrototypeFixture::new_for_fixture(
//!             &store, provider, binding, FixtureProfileStatus::Active);
//!         context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
//!             Some(&fixture), Some(binding), tx).unwrap();
//!     }
//!     let _ = context.evaluate();
//! }
//! ```
//!
//! The generic switching-store surface is not supported:
//! ```compile_fail,E0308
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::AccountStore;
//! use qbind_ledger::native_admission_context::{
//!     FixtureBinding, FixtureProfileStatus, PrototypeFixture,
//! };
//! fn example(store: &dyn AccountStore, provider: &dyn CryptoProvider,
//!            binding: FixtureBinding) {
//!     let _ = PrototypeFixture::new_for_fixture(
//!         store, provider, binding, FixtureProfileStatus::Active);
//! }
//! ```
//!
//! Consuming cancellation leaves no reusable context:
//! ```compile_fail,E0382
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_admission_context::{
//!     FixtureBinding, FixtureProfileStatus, NativeAdmissionContext, PrototypeFixture,
//! };
//! use qbind_wire::tx::Transaction;
//! fn example(store: &InMemoryAccountStore, tx: &Transaction,
//!            provider: &dyn CryptoProvider, binding: FixtureBinding) {
//!     let fixture = PrototypeFixture::new_for_fixture(
//!         store, provider, binding, FixtureProfileStatus::Active);
//!     let context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
//!         Some(&fixture), Some(binding), tx).unwrap();
//!     context.cancel();
//!     let _ = context.evaluate();
//! }
//! ```

use crate::native_tx_proof::{
    evaluate_native_transaction_proofs, NativeTransactionProofError, NativeTransactionProofLimits,
    NativeTransactionProofSummary,
};
use crate::store::{AccountStore, BoundedReadError, InMemoryAccountStore};
use crate::{Account, ExecutionError};
use qbind_crypto::CryptoProvider;
use qbind_types::AccountId;
use qbind_wire::tx::Transaction;

#[cfg(test)]
thread_local! {
    static TEST_ENTRIES: std::cell::Cell<(usize, usize)> = const { std::cell::Cell::new((0, 0)) };
}

/// Explicit fixture policy, never an approved/authorized capability or default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrototypePolicy {
    pub identity: [u8; 32],
    pub version: u32,
    pub limits: NativeTransactionProofLimits,
}

/// Fixed-size fixture labels. These do not authenticate state or a provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FixtureBinding {
    pub chain_id: u32,
    pub execution_pre_state: [u8; 32],
    pub policy: PrototypePolicy,
    pub provider_identity: [u8; 32],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FixtureProfileStatus {
    Active,
    Inactive,
    Unavailable,
}

/// Trusted fixture source, separate from the presented/requested binding.
/// Its labels and active selection are fixture assertions, not chain provenance.
pub struct PrototypeFixture<'a> {
    store: &'a InMemoryAccountStore,
    provider: &'a dyn CryptoProvider,
    binding: FixtureBinding,
    status: FixtureProfileStatus,
}

impl<'a> PrototypeFixture<'a> {
    pub fn new_for_fixture(
        store: &'a InMemoryAccountStore,
        provider: &'a dyn CryptoProvider,
        binding: FixtureBinding,
        status: FixtureProfileStatus,
    ) -> Self {
        Self {
            store,
            provider,
            binding,
            status,
        }
    }
}

/// Context unavailability/configuration only; not an invalid-transaction receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeAdmissionContextError {
    MissingBinding,
    UnavailableFixture,
    UnavailableSelection,
    ChainMismatch,
    ExecutionPreStateMismatch,
    UnknownProfile,
    InactiveProfile,
    ProfileMismatch,
    ProviderMismatch,
    GroupWorkspaceUnsupported,
    ProofWorkspaceUnsupported,
    EntryWorkspaceUnsupported,
}

/// Fixed-size diagnostic context, not a transferable authorization capability.
/// No Clone/Copy, serialization,
/// execution, insertion, reservation, commit or rebinding API.
///
/// The complete transaction, concrete store and selected provider are borrowed
/// until the last use/drop/cancel. The fixture binding is copied once; changing
/// caller-owned labels afterward cannot change this context's selected policy.
/// Success counts are neither cached nor turned into an execution token.
pub struct NativeAdmissionContext<'a, const G: usize, const P: usize, const E: usize> {
    transaction: &'a Transaction,
    store: ReadOnlyStore<'a>,
    provider: &'a dyn CryptoProvider,
    binding: FixtureBinding,
    #[cfg(test)]
    evaluator_calls: std::cell::Cell<usize>,
}

impl<'a, const G: usize, const P: usize, const E: usize> NativeAdmissionContext<'a, G, P, E> {
    /// Select only from the supplied trusted fixture; no work on accounts or
    /// providers, body/proof cloning, snapshot allocation, or fallback.
    pub fn new_for_fixture(
        fixture: Option<&PrototypeFixture<'a>>,
        requested: Option<FixtureBinding>,
        transaction: &'a Transaction,
    ) -> Result<Self, NativeAdmissionContextError> {
        use NativeAdmissionContextError as Error;
        let requested = requested.ok_or(Error::MissingBinding)?;
        let fixture = fixture.ok_or(Error::UnavailableFixture)?;
        if fixture.status == FixtureProfileStatus::Unavailable {
            return Err(Error::UnavailableSelection);
        }
        let selected = fixture.binding;
        if requested.chain_id != selected.chain_id || transaction.chain_id != selected.chain_id {
            return Err(Error::ChainMismatch);
        }
        if requested.execution_pre_state != selected.execution_pre_state {
            return Err(Error::ExecutionPreStateMismatch);
        }
        if requested.policy.identity != selected.policy.identity {
            return Err(Error::UnknownProfile);
        }
        if fixture.status == FixtureProfileStatus::Inactive {
            return Err(Error::InactiveProfile);
        }
        if requested.policy != selected.policy {
            return Err(Error::ProfileMismatch);
        }
        if requested.provider_identity != selected.provider_identity {
            return Err(Error::ProviderMismatch);
        }
        let limits = selected.policy.limits;
        if limits.max_keyset_account_count > G {
            return Err(Error::GroupWorkspaceUnsupported);
        }
        if limits.max_authentication_proof_count > P {
            return Err(Error::ProofWorkspaceUnsupported);
        }
        if limits.stored_keyset.max_entries > E {
            return Err(Error::EntryWorkspaceUnsupported);
        }
        Ok(Self {
            transaction,
            store: ReadOnlyStore {
                inner: fixture.store,
                #[cfg(test)]
                bounded_reads: std::cell::Cell::new(0),
                #[cfg(test)]
                injected_backend_failure: false,
            },
            provider: fixture.provider,
            binding: selected,
            #[cfg(test)]
            evaluator_calls: std::cell::Cell::new(0),
        })
    }

    /// Fresh diagnostic evaluation of the original complete transaction.
    /// Backend/crypto failures retain the existing helper's exact typed detail;
    /// this result is not classified as a consensus receipt or execution right.
    pub fn evaluate(&self) -> Result<NativeTransactionProofSummary, NativeTransactionProofError> {
        #[cfg(test)]
        {
            self.evaluator_calls.set(self.evaluator_calls.get() + 1);
            TEST_ENTRIES.with(|entries| {
                let (evaluations, reads) = entries.get();
                entries.set((evaluations + 1, reads));
            });
        }
        evaluate_native_transaction_proofs::<G, P, E>(
            self.transaction,
            &self.store,
            self.provider,
            self.binding.policy.limits,
        )
    }

    /// End this context's borrows only. No implicit evaluation or state effects;
    /// caller-owned transaction, store and provider are not destroyed.
    pub fn cancel(self) {}
}

struct ReadOnlyStore<'a> {
    inner: &'a InMemoryAccountStore,
    #[cfg(test)]
    bounded_reads: std::cell::Cell<usize>,
    #[cfg(test)]
    injected_backend_failure: bool,
}

impl AccountStore for ReadOnlyStore<'_> {
    fn get(&self, _: &AccountId) -> Option<Account> {
        panic!("isolated native context forbids unbounded legacy reads")
    }

    fn get_bounded(
        &self,
        id: &AccountId,
        max_data_bytes: usize,
    ) -> Result<Option<Account>, BoundedReadError> {
        #[cfg(test)]
        {
            self.bounded_reads.set(self.bounded_reads.get() + 1);
            TEST_ENTRIES.with(|entries| {
                let (evaluations, reads) = entries.get();
                entries.set((evaluations, reads + 1));
            });
            if self.injected_backend_failure {
                return Err(BoundedReadError::Backend);
            }
        }

        #[cfg(test)]
        mod tests {
            use super::*;
            use crate::keyset_account::KeysetAccountReadError;
            use qbind_crypto::ml_dsa44::MlDsa44Backend;
            use qbind_crypto::{
                ml_dsa_44_sign_digest, MlDsa44SignatureSuite, StaticCryptoProvider,
            };
            use qbind_hash::tx::try_tx_digest_streaming;
            use qbind_serde::keyset::StoredKeysetLimits;
            use qbind_serde::StateEncode;
            use qbind_types::{KeysetAccount, KeysetEntry, KEYSET_PROGRAM_ID};
            use qbind_wire::tx::{TxAccountMeta, TxAuth};
            use std::sync::Arc;

            fn binding() -> FixtureBinding {
                FixtureBinding {
                    chain_id: 1,
                    execution_pre_state: [0; 32],
                    policy: PrototypePolicy {
                        identity: [0x42; 32],
                        version: 1,
                        limits: NativeTransactionProofLimits {
                            max_required_signer_indices: 8,
                            max_keyset_account_count: 8,
                            max_authentication_proof_count: 8,
                            max_signature_bytes: 8_192,
                            max_aggregate_signature_bytes: 65_536,
                            stored_keyset: StoredKeysetLimits {
                                max_encoded_bytes: 65_536,
                                max_entries: 16,
                                max_key_bytes: 4_096,
                                max_total_key_bytes: 65_536,
                            },
                            max_algorithm_parameter_identifier_bytes: 128,
                        },
                    },
                    provider_identity: [0x44; 32],
                }
            }

            fn transaction() -> Transaction {
                Transaction {
                    version: 1,
                    chain_id: 1,
                    payer: [0; 32],
                    nonce: 0,
                    fee_limit: 0,
                    accounts: vec![TxAccountMeta {
                        account_id: [1; 32],
                        flags: 1,
                        access_hint: 0,
                        reserved0: [0; 2],
                    }],
                    program_id: [0; 32],
                    call_data: vec![],
                    auths: vec![TxAuth {
                        account_index: 0,
                        suite_id: 100,
                        reserved: 0,
                        signature: vec![1],
                    }],
                }
            }

            fn entries() -> (usize, usize) {
                TEST_ENTRIES.with(std::cell::Cell::get)
            }

            #[test]
            fn run422_native_admission_context_early_refusals_have_zero_helper_entries() {
                use NativeAdmissionContextError as Error;
                let store = InMemoryAccountStore::new();
                let provider = StaticCryptoProvider::new();
                let tx = transaction();
                let selected = binding();
                let active = PrototypeFixture::new_for_fixture(
                    &store,
                    &provider,
                    selected,
                    FixtureProfileStatus::Active,
                );
                let unavailable = PrototypeFixture::new_for_fixture(
                    &store,
                    &provider,
                    selected,
                    FixtureProfileStatus::Unavailable,
                );
                let inactive = PrototypeFixture::new_for_fixture(
                    &store,
                    &provider,
                    selected,
                    FixtureProfileStatus::Inactive,
                );
                let mut wrong_chain = selected;
                wrong_chain.chain_id = 2;
                let mut wrong_state = selected;
                wrong_state.execution_pre_state = [2; 32];
                let mut unknown = selected;
                unknown.policy.identity = [2; 32];
                let mut wrong_profile = selected;
                wrong_profile.policy.version = 2;
                let mut wrong_limits = selected;
                wrong_limits.policy.limits.max_signature_bytes = 1;
                let mut wrong_provider = selected;
                wrong_provider.provider_identity = [2; 32];
                TEST_ENTRIES.with(|entries| entries.set((0, 0)));
                for (source, requested, expected) in [
                    (Some(&active), None, Error::MissingBinding),
                    (None, Some(selected), Error::UnavailableFixture),
                    (
                        Some(&unavailable),
                        Some(selected),
                        Error::UnavailableSelection,
                    ),
                    (Some(&inactive), Some(selected), Error::InactiveProfile),
                    (Some(&active), Some(wrong_chain), Error::ChainMismatch),
                    (
                        Some(&active),
                        Some(wrong_state),
                        Error::ExecutionPreStateMismatch,
                    ),
                    (Some(&active), Some(unknown), Error::UnknownProfile),
                    (Some(&active), Some(wrong_profile), Error::ProfileMismatch),
                    (Some(&active), Some(wrong_limits), Error::ProfileMismatch),
                    (Some(&active), Some(wrong_provider), Error::ProviderMismatch),
                ] {
                    assert!(matches!(
                        NativeAdmissionContext::<8, 8, 16>::new_for_fixture(source, requested, &tx),
                        Err(error) if error == expected
                    ));
                    assert_eq!(entries(), (0, 0));
                    assert_eq!(store.get(&[1; 32]), None);
                }
                assert!(matches!(
                    NativeAdmissionContext::<1, 8, 16>::new_for_fixture(
                        Some(&active),
                        Some(selected),
                        &tx
                    ),
                    Err(Error::GroupWorkspaceUnsupported)
                ));
                assert!(matches!(
                    NativeAdmissionContext::<8, 1, 16>::new_for_fixture(
                        Some(&active),
                        Some(selected),
                        &tx
                    ),
                    Err(Error::ProofWorkspaceUnsupported)
                ));
                assert!(matches!(
                    NativeAdmissionContext::<8, 8, 1>::new_for_fixture(
                        Some(&active),
                        Some(selected),
                        &tx
                    ),
                    Err(Error::EntryWorkspaceUnsupported)
                ));
                assert_eq!(entries(), (0, 0));
                let context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
                    Some(&active),
                    Some(selected),
                    &tx,
                )
                .unwrap();
                assert_eq!(entries(), (0, 0));
                assert_eq!(
                    context.evaluate(),
                    Err(NativeTransactionProofError::AccountRead(
                        KeysetAccountReadError::MissingAccount
                    ))
                );
                assert_eq!(entries(), (1, 1));
                assert_eq!(context.evaluator_calls.get(), 1);
                assert_eq!(context.store.bounded_reads.get(), 1);
                context.cancel();
                assert_eq!(entries(), (1, 1));
            }

            #[test]
            fn run422_native_admission_context_injected_backend_refusal_then_fresh_genuine_success()
            {
                let (public, secret) = MlDsa44Backend::generate_keypair().unwrap();
                let state = KeysetAccount {
                    version: 1,
                    reserved0: [0; 3],
                    threshold: 1,
                    entry_count: 1,
                    reserved1: [0; 4],
                    entries: vec![KeysetEntry {
                        suite_id: 100,
                        weight: 1,
                        reserved0: [0],
                        pubkey_len: u16::try_from(public.len()).unwrap(),
                        pubkey_bytes: public,
                    }],
                };
                let mut data = Vec::new();
                state.encode_state(&mut data);
                let account = Account::new([1; 32], KEYSET_PROGRAM_ID, 0, data);
                let mut store = InMemoryAccountStore::new();
                store.put(account.clone()).unwrap();
                let mut tx = transaction();
                tx.auths[0].signature =
                    ml_dsa_44_sign_digest(&secret, &try_tx_digest_streaming(&tx).unwrap()).unwrap();
                let original = tx.clone();
                let provider = StaticCryptoProvider::new()
                    .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(100)));
                let fixture = PrototypeFixture::new_for_fixture(
                    &store,
                    &provider,
                    binding(),
                    FixtureProfileStatus::Active,
                );
                let mut context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
                    Some(&fixture),
                    Some(binding()),
                    &tx,
                )
                .unwrap();
                // Private helper-level injection, not a genuine backend allocation fault.
                context.store.injected_backend_failure = true;
                assert_eq!(
                    context.evaluate(),
                    Err(NativeTransactionProofError::AccountRead(
                        KeysetAccountReadError::Backend
                    ))
                );
                assert_eq!(context.store.bounded_reads.get(), 1);
                assert_eq!(store.get(&account.id), Some(account.clone()));
                assert_eq!(tx, original);
                context.cancel();
                let fresh = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
                    Some(&fixture),
                    Some(binding()),
                    &tx,
                )
                .unwrap();
                assert_eq!(
                    fresh.evaluate(),
                    Ok(NativeTransactionProofSummary {
                        required_signer_index_count: 1,
                        distinct_keyset_account_count: 1,
                        evaluated_authentication_proof_count: 1,
                    })
                );
                assert_eq!(fresh.store.bounded_reads.get(), 1);
                assert_eq!(fresh.evaluator_calls.get(), 1);
                assert_eq!(store.get(&account.id), Some(account.clone()));
                assert_eq!(tx, original);
                drop(fresh);
                store.put(account).unwrap();
            }

            #[test]
            fn run422_native_admission_context_adapter_has_no_legacy_or_write_surface() {
                let mut store = InMemoryAccountStore::new();
                let account = Account::new([1; 32], KEYSET_PROGRAM_ID, 7, vec![1, 2, 3]);
                store.put(account.clone()).unwrap();
                let provider = StaticCryptoProvider::new();
                let tx = transaction();
                let fixture = PrototypeFixture::new_for_fixture(
                    &store,
                    &provider,
                    binding(),
                    FixtureProfileStatus::Active,
                );
                let mut context = NativeAdmissionContext::<8, 8, 16>::new_for_fixture(
                    Some(&fixture),
                    Some(binding()),
                    &tx,
                )
                .unwrap();
                assert!(matches!(
                    context.store.put(account.clone()),
                    Err(ExecutionError::ProgramError(
                        "isolated native context is read-only"
                    ))
                ));
                assert!(matches!(
                    context.store.delete(&account.id),
                    Err(ExecutionError::ProgramError(
                        "isolated native context is read-only"
                    ))
                ));
                assert!(
                    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| context
                        .store
                        .get(&account.id)))
                    .is_err()
                );
                assert_eq!(
                    context.evaluate(),
                    Err(NativeTransactionProofError::KeysetParse(
                        qbind_serde::keyset::StoredKeysetParseError::Malformed(
                            qbind_serde::StateError::UnexpectedEof
                        )
                    ))
                );
                assert_eq!(context.store.bounded_reads.get(), 1);
                assert_eq!(store.get(&account.id), Some(account.clone()));
                context.cancel();
                store.delete(&account.id).unwrap();
                assert_eq!(store.get(&account.id), None);
                println!(
                    "cfg_test_context={} cfg_test_adapter={} adapter_genuine_read_count=1",
                    std::mem::size_of::<NativeAdmissionContext<'_, 8, 8, 16>>(),
                    std::mem::size_of::<ReadOnlyStore<'_>>(),
                );
            }
        }
        self.inner.get_bounded(id, max_data_bytes)
    }

    fn put(&mut self, _: Account) -> Result<(), ExecutionError> {
        Err(ExecutionError::ProgramError(
            "isolated native context is read-only",
        ))
    }

    fn delete(&mut self, _: &AccountId) -> Result<(), ExecutionError> {
        Err(ExecutionError::ProgramError(
            "isolated native context is read-only",
        ))
    }
}
