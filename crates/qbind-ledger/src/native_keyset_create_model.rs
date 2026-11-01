//! Unused transaction-bound keyset-create composition for trusted fixtures.
//!
//! All configuration is UNAPPROVED fixture input, not authenticated authority.
//! Proof success establishes no creator, payer, program, nonce, fee, replay or
//! bootstrap policy. One concrete exclusive store borrow spans fresh proofs,
//! preparation, staging and consuming publication/cancellation.
//!
//! Proof workspace ends before preparation; the empty one-slot session remains
//! live. The unchanged preparer's semantic workspace ends before destination
//! reservation. Its logical output bound and requested reservation do NOT bound
//! actual Vec capacity before allocation. Staging checks actual capacity only
//! after that transient owner exists. One Account allocation moves into stage
//! and then map; caller transaction/provider and existing store allocations live
//! throughout. This is normal-error atomicity only, not arbitrary-panic rollback,
//! crash durability, restart safety, persistent isolation or transaction receipts.
//!
//! Valid release permits both store and complete transaction mutation:
//! ```
//! use qbind_crypto::CryptoProvider;
//! use qbind_ledger::{AccountStore, InMemoryAccountStore};
//! use qbind_ledger::native_keyset_create_model::{NativeKeysetCreateModel, KeysetCreateFixtureConfig, KeysetCreateFixtureSelection};
//! use qbind_ledger::native_admission_context::FixtureBinding;
//! use qbind_wire::tx::Transaction;
//! fn example(s: &mut InMemoryAccountStore, t: &mut Transaction,
//!            p: Option<KeysetCreateFixtureSelection<'_>>, b: Option<FixtureBinding>,
//!            c: KeysetCreateFixtureConfig) {
//!     if let Ok(m) = NativeKeysetCreateModel::<8,8,16>::begin_for_fixture(s,t,p,b,c) {
//!         m.cancel();
//!     }
//!     s.delete(&[0;32]).unwrap();
//!     t.auths.clear();
//! }
//! ```
//! ```compile_fail,E0499
//! use qbind_ledger::{AccountStore, InMemoryAccountStore};
//! use qbind_ledger::native_keyset_create_model::{NativeKeysetCreateModel, KeysetCreateFixtureConfig};
//! use qbind_wire::tx::Transaction;
//! fn example(s: &mut InMemoryAccountStore, t: &Transaction, c: KeysetCreateFixtureConfig) {
//!     let m = NativeKeysetCreateModel::<8,8,16>::begin_for_fixture(s,t,None,None,c).unwrap();
//!     s.delete(&[0;32]).unwrap();
//!     m.cancel();
//! }
//! ```
//! ```compile_fail,E0502
//! use qbind_ledger::InMemoryAccountStore;
//! use qbind_ledger::native_keyset_create_model::{NativeKeysetCreateModel, KeysetCreateFixtureConfig};
//! use qbind_wire::tx::Transaction;
//! fn example(s: &mut InMemoryAccountStore, t: &mut Transaction, c: KeysetCreateFixtureConfig) {
//!     let m = NativeKeysetCreateModel::<8,8,16>::begin_for_fixture(s,t,None,None,c).unwrap();
//!     t.auths.clear();
//!     m.cancel();
//! }
//! ```
//! ```compile_fail,E0616
//! use qbind_ledger::native_keyset_create_model::NativeKeysetCreateModel;
//! fn example(m: NativeKeysetCreateModel<'_,8,8,16>) {
//!     let _ = m.session;
//! }
//! ```
//! ```compile_fail,E0382
//! use qbind_ledger::native_keyset_create_model::NativeKeysetCreateModel;
//! fn example(m: NativeKeysetCreateModel<'_,8,8,16>) {
//!     let _ = m.publish_for_fixture();
//!     m.cancel();
//! }
//! ```
//! ```compile_fail,E0382
//! use qbind_ledger::native_keyset_create_model::NativeKeysetCreateModel;
//! fn example(m: NativeKeysetCreateModel<'_,8,8,16>) {
//!     m.cancel();
//!     let _ = m.publish_for_fixture();
//! }
//! ```

use crate::keyset_create::{
    prepare_keyset_account_bounded, KeysetCreatePreparationError, KeysetCreatePreparationLimits,
};
use crate::native_admission_context::{FixtureBinding, FixtureProfileStatus};
use crate::native_staged_effects::{
    FixtureBeginError, FixturePublicationSummary, FixtureSelection, FixtureStageLimits,
    FixtureStageRefusal, NativeStagedEffects,
};
use crate::InMemoryAccountStore;
use qbind_crypto::CryptoProvider;
use qbind_types::KEYSET_PROGRAM_ID;
use qbind_wire::tx::Transaction;

/// Selected fixture inputs, deliberately separate from requested native binding.
pub struct KeysetCreateFixtureSelection<'a> {
    provider: &'a dyn CryptoProvider,
    binding: FixtureBinding,
    status: FixtureProfileStatus,
}

impl<'a> KeysetCreateFixtureSelection<'a> {
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

/// Explicit trusted configuration with no defaults or activation mechanism.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KeysetCreateFixtureConfig {
    pub preparation: KeysetCreatePreparationLimits,
    pub staging: FixtureStageLimits,
}

/// Fixed-size diagnostics; a refused internally prepared owner never escapes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeysetCreateModelError {
    WrongProgram,
    Configuration,
    Admission(FixtureBeginError),
    Preparation(KeysetCreatePreparationError),
    Staging(FixtureStageRefusal),
}

/// Exactly one create; no inner extraction, arbitrary staging or read API.
pub struct NativeKeysetCreateModel<'a, const G: usize, const P: usize, const E: usize> {
    session: NativeStagedEffects<'a, G, P, E, 1>,
}

impl<'a, const G: usize, const P: usize, const E: usize> NativeKeysetCreateModel<'a, G, P, E> {
    pub fn begin_for_fixture(
        store: &'a mut InMemoryAccountStore,
        transaction: &'a Transaction,
        selected: Option<KeysetCreateFixtureSelection<'a>>,
        requested: Option<FixtureBinding>,
        config: KeysetCreateFixtureConfig,
    ) -> Result<Self, KeysetCreateModelError> {
        if transaction.program_id != KEYSET_PROGRAM_ID {
            return Err(KeysetCreateModelError::WrongProgram);
        }
        let p = config.preparation;
        let s = config.staging;
        if p.create_keyset.max_entries > E
            || s.max_operations != 1
            || p.max_stored_data_bytes > s.max_data_len
            || s.max_data_len > s.max_account_capacity
            || s.max_account_capacity > s.max_aggregate_capacity
        {
            return Err(KeysetCreateModelError::Configuration);
        }
        // Keep the very same provider reference for both existing primitives.
        let provider = selected.as_ref().map(|selection| selection.provider);
        let selected = selected.map(|selection| {
            FixtureSelection::new_for_fixture(
                selection.provider,
                selection.binding,
                selection.status,
            )
        });
        let mut session =
            NativeStagedEffects::begin_for_fixture(store, transaction, selected, requested, s)
                .map_err(KeysetCreateModelError::Admission)?;
        // Successful session construction guarantees selection presence.
        let provider = provider.expect("staged admission requires selected fixture");
        #[cfg(test)]
        observation::enter_preparation();
        let account =
            prepare_keyset_account_bounded::<E>(transaction.call_data.as_slice(), provider, p)
                .map_err(KeysetCreateModelError::Preparation)?;
        #[cfg(test)]
        observation::prepared(&account);
        let id = account.id;
        if let Err(refusal) = session.create_for_fixture(id, account) {
            let reason = refusal.reason;
            drop(refusal.account);
            return Err(KeysetCreateModelError::Staging(reason));
        }
        Ok(Self { session })
    }

    /// No new inputs; complete existing batch preflight precedes all mutation.
    /// MapCapacity is local inability, not a consensus invalid-transaction receipt.
    pub fn publish_for_fixture(self) -> Result<FixturePublicationSummary, FixtureStageRefusal> {
        self.session.publish_for_fixture()
    }

    pub fn cancel(self) {
        self.session.cancel();
    }
}

#[cfg(test)]
pub(crate) mod observation {
    use crate::Account;
    use std::cell::Cell;

    thread_local! {
        static VALUE: Cell<(usize, usize, usize, usize)> = const { Cell::new((0,0,0,0)) };
    }

    pub(crate) fn reset() {
        VALUE.with(|v| v.set((0, 0, 0, 0)));
    }
    pub(crate) fn get() -> (usize, usize, usize, usize) {
        VALUE.with(Cell::get)
    }
    pub(super) fn enter_preparation() {
        VALUE.with(|v| v.set((v.get().0 + 1, 0, 0, 0)));
    }
    pub(super) fn prepared(account: &Account) {
        VALUE.with(|v| {
            v.set((
                v.get().0,
                account.data.as_ptr() as usize,
                account.data.len(),
                account.data.capacity(),
            ))
        });
    }
}
