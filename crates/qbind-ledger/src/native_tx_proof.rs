//! Isolated composition of bounded native transaction proof evaluation.
//!
//! This evaluator is additive and unused by production authorization. Success
//! means only that every supplied proof verifies against the separately read
//! keyset for its resolved account ID and this transaction digest under the
//! supplied provider and limits. It does not establish a common transaction
//! state snapshot, current authority, policy admission, or permission to run.
//!
//! Groups are traversed in first-occurrence order among signer-marked account
//! indices; proofs within each group retain their original transaction order.
//! Coverage is exact-index based even when several indices resolve to one ID.
//! Each group has an independent threshold and distinct-key weight set.
//!
//! If group k has m_k required indices, p_k supplied proofs, and r_k minimum
//! distinct-key proofs required by its stored keyset, exact-index coverage gives
//! p_k >= m_k and successful per-keyset reachability with max_proof_count=p_k
//! gives p_k >= r_k. With B equal to the admitted transaction proof budget,
//! global preflight establishes sum(p_k)=auths.len()<=B. Thus a successful call
//! satisfies sum(max(m_k,r_k)) <= sum(p_k) <= B. No second read or semantic pass
//! is done to expose r_k, and actual signatures and thresholds must still pass.
//!
//! Work includes full metadata/auth preflight, O(accounts * groups) exact ID
//! grouping, O(auths * groups) group proof counting, then one bounded read and
//! borrowed parse per group. Proof gathering rescans all auths once per group;
//! keyset descriptor/canonical work follows the existing per-keyset helper,
//! including at most sum(p_k * e_k) signature-verification calls for e_k
//! entries in group k. The checked streaming digest costs
//! O(91 + 36*accounts.len() + call_data.len()).
//!
//! Workspace arrays are allocation-free. The caller-owned Transaction predates
//! this call. Logical data limits do not bound Vec capacity, allocator overhead,
//! backend/crypto internals, stack frames, or process memory. Each bounded read
//! is coherent only for that account; several reads do not imply one shared
//! state version. Earlier group work is not rolled back if a later group refuses.

use crate::keyset_account::{read_keyset_owned_account_bounded, KeysetAccountReadError};
use crate::keyset_proof::{
    evaluate_stored_keyset_proofs, KeysetProofEvaluationError, KeysetProofEvaluationLimits,
    KeysetSignatureProof,
};
use crate::store::AccountStore;
use qbind_crypto::CryptoProvider;
use qbind_hash::tx::{try_tx_digest_streaming, TxDigestError};
use qbind_serde::keyset::{parse_stored_keyset, StoredKeysetLimits, StoredKeysetParseError};
use qbind_types::AccountId;
use qbind_wire::tx::Transaction;

/// Explicit per-call admission limits. These are caller inputs, not policy
/// approval or defaults. Keyset framing limits apply independently to each
/// account; signature aggregation applies across the complete transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTransactionProofLimits {
    pub max_required_signer_indices: usize,
    pub max_keyset_account_count: usize,
    pub max_authentication_proof_count: usize,
    pub max_signature_bytes: usize,
    pub max_aggregate_signature_bytes: usize,
    pub stored_keyset: StoredKeysetLimits,
    pub max_algorithm_parameter_identifier_bytes: usize,
}

/// Fixed-size structural and workspace refusal categories.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NativeTransactionProofStructureError {
    EmptyAuths,
    AccountCountWireLimit,
    AuthCountWireLimit,
    CallDataWireLimit,
    SignatureLengthWireLimit,
    RequiredSignerCountLimit,
    KeysetAccountCountLimit,
    AuthenticationProofCountLimit,
    SignatureByteLimit,
    AggregateSignatureByteOverflow,
    AggregateSignatureByteLimit,
    AuthIndexOutOfRange,
    AuthTargetsUnmarkedAccount,
    MissingRequiredSignerAuth,
    GroupWorkspaceCapacity,
    ProofWorkspaceCapacity,
    EntryWorkspaceCapacity,
    GroupAssignmentMismatch,
}

/// Fixed-size errors. No transaction bytes, key material, signature, account,
/// or input-derived diagnostic string is retained.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NativeTransactionProofError {
    Structure(NativeTransactionProofStructureError),
    Digest(TxDigestError),
    AccountRead(KeysetAccountReadError),
    KeysetParse(StoredKeysetParseError),
    KeysetProof(KeysetProofEvaluationError),
}

/// Diagnostic-only result; it carries no authority or execution capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NativeTransactionProofSummary {
    pub required_signer_index_count: usize,
    pub distinct_keyset_account_count: usize,
    pub evaluated_authentication_proof_count: usize,
}

fn check_wire_lengths(
    account_count: usize,
    auth_count: usize,
    call_data_len: usize,
) -> Result<(), NativeTransactionProofError> {
    use NativeTransactionProofStructureError as Error;

    if u16::try_from(account_count).is_err() {
        return Err(NativeTransactionProofError::Structure(
            Error::AccountCountWireLimit,
        ));
    }
    if u16::try_from(auth_count).is_err() {
        return Err(NativeTransactionProofError::Structure(
            Error::AuthCountWireLimit,
        ));
    }
    if u32::try_from(call_data_len).is_err() {
        return Err(NativeTransactionProofError::Structure(
            Error::CallDataWireLimit,
        ));
    }
    Ok(())
}

fn check_signature_wire_length(signature_len: usize) -> Result<(), NativeTransactionProofError> {
    if u16::try_from(signature_len).is_err() {
        return Err(NativeTransactionProofError::Structure(
            NativeTransactionProofStructureError::SignatureLengthWireLimit,
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct GroupMetadata {
    account_id: AccountId,
    required_index_count: usize,
    proof_count: usize,
}

struct TransactionPreflight<const G: usize> {
    groups: [Option<GroupMetadata>; G],
    group_count: usize,
    required_signer_index_count: usize,
    authentication_proof_count: usize,
}

struct BorrowedProofWorkspace<'tx, const P: usize> {
    proofs: [KeysetSignatureProof<'tx>; P],
}

/// Check the complete transaction structure and compute the deterministic
/// account-ID groups before hashing, store access, or provider activity.
fn preflight<const G: usize, const P: usize>(
    tx: &Transaction,
    limits: NativeTransactionProofLimits,
) -> Result<TransactionPreflight<G>, NativeTransactionProofError> {
    use NativeTransactionProofStructureError as Error;

    if tx.auths.is_empty() {
        return Err(NativeTransactionProofError::Structure(Error::EmptyAuths));
    }
    check_wire_lengths(tx.accounts.len(), tx.auths.len(), tx.call_data.len())?;
    if tx.auths.len() > limits.max_authentication_proof_count {
        return Err(NativeTransactionProofError::Structure(
            Error::AuthenticationProofCountLimit,
        ));
    }

    // The full representable u16 account-index space is covered without heap
    // allocation; this is 8192 bytes and is released when preflight returns.
    let mut covered = [0u8; (u16::MAX as usize + 1) / 8];
    let mut aggregate_signature_bytes = 0usize;
    for auth in &tx.auths {
        check_signature_wire_length(auth.signature.len())?;
        if auth.signature.len() > limits.max_signature_bytes {
            return Err(NativeTransactionProofError::Structure(
                Error::SignatureByteLimit,
            ));
        }
        aggregate_signature_bytes = aggregate_signature_bytes
            .checked_add(auth.signature.len())
            .ok_or(NativeTransactionProofError::Structure(
                Error::AggregateSignatureByteOverflow,
            ))?;
        if aggregate_signature_bytes > limits.max_aggregate_signature_bytes {
            return Err(NativeTransactionProofError::Structure(
                Error::AggregateSignatureByteLimit,
            ));
        }

        let index = usize::from(auth.account_index);
        let meta = tx
            .accounts
            .get(index)
            .ok_or(NativeTransactionProofError::Structure(
                Error::AuthIndexOutOfRange,
            ))?;
        if meta.flags & 1 == 0 {
            return Err(NativeTransactionProofError::Structure(
                Error::AuthTargetsUnmarkedAccount,
            ));
        }
        covered[index / 8] |= 1 << (index % 8);
    }

    let mut groups: [Option<GroupMetadata>; G] = [None; G];
    let mut group_count = 0usize;
    let mut required_signer_index_count = 0usize;
    for (index, meta) in tx.accounts.iter().enumerate() {
        if meta.flags & 1 == 0 {
            continue;
        }
        required_signer_index_count = required_signer_index_count.checked_add(1).ok_or(
            NativeTransactionProofError::Structure(Error::RequiredSignerCountLimit),
        )?;
        if required_signer_index_count > limits.max_required_signer_indices {
            return Err(NativeTransactionProofError::Structure(
                Error::RequiredSignerCountLimit,
            ));
        }
        if covered[index / 8] & (1 << (index % 8)) == 0 {
            return Err(NativeTransactionProofError::Structure(
                Error::MissingRequiredSignerAuth,
            ));
        }

        let account_id = meta.account_id;
        let existing = groups[..group_count]
            .iter()
            .position(|group| group.is_some_and(|group| group.account_id == account_id));
        if let Some(group_index) = existing {
            let group = groups.get_mut(group_index).and_then(Option::as_mut).ok_or(
                NativeTransactionProofError::Structure(Error::GroupWorkspaceCapacity),
            )?;
            group.required_index_count = group.required_index_count.checked_add(1).ok_or(
                NativeTransactionProofError::Structure(Error::RequiredSignerCountLimit),
            )?;
        } else {
            if group_count >= limits.max_keyset_account_count {
                return Err(NativeTransactionProofError::Structure(
                    Error::KeysetAccountCountLimit,
                ));
            }
            if group_count >= G {
                return Err(NativeTransactionProofError::Structure(
                    Error::GroupWorkspaceCapacity,
                ));
            }
            groups[group_count] = Some(GroupMetadata {
                account_id,
                required_index_count: 1,
                proof_count: 0,
            });
            group_count += 1;
        }
    }

    // Assign every structurally valid proof to exactly one full-ID group.
    // This traversal preserves the original transaction auth order per group.
    for auth in &tx.auths {
        let account_id = tx.accounts[usize::from(auth.account_index)].account_id;
        let group_index = groups[..group_count]
            .iter()
            .position(|group| group.is_some_and(|group| group.account_id == account_id))
            .ok_or(NativeTransactionProofError::Structure(
                Error::GroupWorkspaceCapacity,
            ))?;
        let group = groups.get_mut(group_index).and_then(Option::as_mut).ok_or(
            NativeTransactionProofError::Structure(Error::GroupWorkspaceCapacity),
        )?;
        group.proof_count =
            group
                .proof_count
                .checked_add(1)
                .ok_or(NativeTransactionProofError::Structure(
                    Error::AuthenticationProofCountLimit,
                ))?;
        if group.proof_count > P {
            return Err(NativeTransactionProofError::Structure(
                Error::ProofWorkspaceCapacity,
            ));
        }
    }
    if groups[..group_count]
        .iter()
        .flatten()
        .any(|group| group.proof_count < group.required_index_count)
    {
        return Err(NativeTransactionProofError::Structure(
            Error::GroupAssignmentMismatch,
        ));
    }

    Ok(TransactionPreflight {
        groups,
        group_count,
        required_signer_index_count,
        authentication_proof_count: tx.auths.len(),
    })
}

/// Evaluate every transaction authentication proof using isolated per-account
/// keyset checks. `G`, `P`, and `E` are trusted caller-selected implementation
/// capacities, not approved protocol or production limits.
pub fn evaluate_native_transaction_proofs<const G: usize, const P: usize, const E: usize>(
    tx: &Transaction,
    store: &dyn AccountStore,
    provider: &dyn CryptoProvider,
    limits: NativeTransactionProofLimits,
) -> Result<NativeTransactionProofSummary, NativeTransactionProofError> {
    use NativeTransactionProofStructureError as StructureError;

    let preflight = preflight::<G, P>(tx, limits)?;
    let digest = try_tx_digest_streaming(tx).map_err(NativeTransactionProofError::Digest)?;
    let mut proof_workspace = BorrowedProofWorkspace {
        proofs: [KeysetSignatureProof {
            suite_id: 0,
            signature_bytes: &[],
        }; P],
    };

    for group_index in 0..preflight.group_count {
        let group = preflight.groups[group_index].ok_or(NativeTransactionProofError::Structure(
            StructureError::GroupWorkspaceCapacity,
        ))?;
        {
            // This lexical scope bounds the evaluator's newly returned Account
            // to one group. The parser and descriptors borrow its data; they
            // are gone before the next bounded read begins.
            let account = read_keyset_owned_account_bounded(
                store,
                &group.account_id,
                limits.stored_keyset.max_encoded_bytes,
            )
            .map_err(NativeTransactionProofError::AccountRead)?;
            let keyset = parse_stored_keyset(&account.data, limits.stored_keyset)
                .map_err(NativeTransactionProofError::KeysetParse)?;
            if usize::from(keyset.entry_count()) > E {
                return Err(NativeTransactionProofError::Structure(
                    StructureError::EntryWorkspaceCapacity,
                ));
            }

            let mut proof_count = 0usize;
            for auth in &tx.auths {
                let account_id = tx.accounts[usize::from(auth.account_index)].account_id;
                if account_id == group.account_id {
                    if proof_count >= P {
                        return Err(NativeTransactionProofError::Structure(
                            StructureError::ProofWorkspaceCapacity,
                        ));
                    }
                    proof_workspace.proofs[proof_count] = KeysetSignatureProof {
                        suite_id: auth.suite_id,
                        signature_bytes: &auth.signature,
                    };
                    proof_count += 1;
                }
            }
            if proof_count != group.proof_count {
                return Err(NativeTransactionProofError::Structure(
                    StructureError::AuthenticationProofCountLimit,
                ));
            }
            evaluate_stored_keyset_proofs::<E>(
                keyset,
                provider,
                &digest,
                &proof_workspace.proofs[..proof_count],
                KeysetProofEvaluationLimits {
                    max_proof_count: proof_count,
                    max_signature_bytes: limits.max_signature_bytes,
                    // The transaction-wide aggregate is already admitted in
                    // preflight; using that same ceiling here cannot weaken it.
                    max_aggregate_signature_bytes: limits.max_aggregate_signature_bytes,
                    max_algorithm_parameter_identifier_bytes: limits
                        .max_algorithm_parameter_identifier_bytes,
                },
            )
            .map_err(NativeTransactionProofError::KeysetProof)?;
        }
        for proof in &mut proof_workspace.proofs[..group.proof_count] {
            *proof = KeysetSignatureProof {
                suite_id: 0,
                signature_bytes: &[],
            };
        }
    }

    Ok(NativeTransactionProofSummary {
        required_signer_index_count: preflight.required_signer_index_count,
        distinct_keyset_account_count: preflight.group_count,
        evaluated_authentication_proof_count: preflight.authentication_proof_count,
    })
}

#[cfg(test)]
mod run422_native_tx_proof_tests {
    use super::*;
    use crate::store::BoundedReadError;
    use crate::{Account, AccountHeader, ExecutionError};
    use qbind_crypto::error::CryptoError;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
    use qbind_crypto::{
        AeadSuite, CryptoProvider, KemSuite, MlDsa44SignatureSuite, StaticCryptoProvider,
    };
    use qbind_hash::tx::try_tx_digest_streaming;
    use qbind_types::{AccountId, Hash32, KEYSET_PROGRAM_ID};
    use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    const SUITE: u8 = 100;

    #[derive(Default)]
    struct Calls {
        lookups: AtomicUsize,
        descriptors: AtomicUsize,
        verifications: AtomicUsize,
    }

    struct CountedSuite {
        inner: MlDsa44SignatureSuite,
        calls: Arc<Calls>,
    }

    impl SignatureSuite for CountedSuite {
        fn suite_id(&self) -> u8 {
            self.inner.suite_id()
        }

        fn public_key_len(&self) -> usize {
            self.inner.public_key_len()
        }

        fn signature_len(&self) -> usize {
            self.inner.signature_len()
        }

        fn verify(&self, key: &[u8], digest: &Hash32, signature: &[u8]) -> Result<(), CryptoError> {
            self.calls.verifications.fetch_add(1, Ordering::SeqCst);
            self.inner.verify(key, digest, signature)
        }

        fn canonical_key_descriptor<'a>(
            &self,
            key: &'a [u8],
        ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
            self.calls.descriptors.fetch_add(1, Ordering::SeqCst);
            self.inner.canonical_key_descriptor(key)
        }
    }

    #[derive(Clone, Copy)]
    enum SyntheticVerifyMode {
        AcceptAll,
        BackendFailure,
    }

    struct SyntheticSuite {
        mode: SyntheticVerifyMode,
        calls: Arc<Calls>,
    }

    impl SignatureSuite for SyntheticSuite {
        fn suite_id(&self) -> u8 {
            7
        }

        fn public_key_len(&self) -> usize {
            0
        }

        fn signature_len(&self) -> usize {
            0
        }

        fn verify(
            &self,
            _key: &[u8],
            _digest: &Hash32,
            _signature: &[u8],
        ) -> Result<(), CryptoError> {
            self.calls.verifications.fetch_add(1, Ordering::SeqCst);
            match self.mode {
                SyntheticVerifyMode::AcceptAll => Ok(()),
                SyntheticVerifyMode::BackendFailure => {
                    Err(CryptoError::InternalError("synthetic backend failure"))
                }
            }
        }

        fn canonical_key_descriptor<'a>(
            &self,
            key: &'a [u8],
        ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
            self.calls.descriptors.fetch_add(1, Ordering::SeqCst);
            Ok(CanonicalKeyDescriptor {
                algorithm_id: b"synthetic-algorithm",
                parameter_id: b"synthetic-parameters",
                public_key_encoding: key,
            })
        }
    }

    struct CountedProvider {
        inner: StaticCryptoProvider,
        calls: Arc<Calls>,
    }

    impl CountedProvider {
        fn mldsa(calls: Arc<Calls>) -> Self {
            let suite = CountedSuite {
                inner: MlDsa44SignatureSuite::new(SUITE),
                calls: Arc::clone(&calls),
            };
            Self::with_suite(Arc::new(suite), calls)
        }

        fn with_suite(suite: Arc<dyn SignatureSuite>, calls: Arc<Calls>) -> Self {
            Self {
                inner: StaticCryptoProvider::new().with_signature_suite(suite),
                calls,
            }
        }

        fn no_suites(calls: Arc<Calls>) -> Self {
            Self {
                inner: StaticCryptoProvider::new(),
                calls,
            }
        }
    }

    impl CryptoProvider for CountedProvider {
        fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
            self.calls.lookups.fetch_add(1, Ordering::SeqCst);
            self.inner.signature_suite(suite_id)
        }

        fn kem_suite(&self, suite_id: u8) -> Option<&dyn KemSuite> {
            self.inner.kem_suite(suite_id)
        }

        fn aead_suite(&self, suite_id: u8) -> Option<&dyn AeadSuite> {
            self.inner.aead_suite(suite_id)
        }
    }

    #[derive(Default)]
    struct RecordingStore {
        accounts: Vec<Account>,
        reads: RefCell<Vec<(AccountId, usize)>>,
        legacy_gets: Cell<usize>,
        puts: Cell<usize>,
        deletes: Cell<usize>,
        read_error: Option<BoundedReadError>,
        response_override: Option<Account>,
    }

    impl AccountStore for RecordingStore {
        fn get(&self, _id: &AccountId) -> Option<Account> {
            self.legacy_gets.set(self.legacy_gets.get() + 1);
            None
        }

        fn get_bounded(
            &self,
            id: &AccountId,
            max_data_bytes: usize,
        ) -> Result<Option<Account>, BoundedReadError> {
            self.reads.borrow_mut().push((*id, max_data_bytes));
            if let Some(error) = self.read_error {
                return Err(error);
            }
            let account = self
                .response_override
                .as_ref()
                .or_else(|| self.accounts.iter().find(|account| account.id == *id));
            let Some(account) = account else {
                return Ok(None);
            };
            if account.data.len() > max_data_bytes {
                return Err(BoundedReadError::Oversized);
            }
            Ok(Some(account.clone()))
        }

        fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
            self.puts.set(self.puts.get() + 1);
            panic!("native transaction proof evaluation must not write accounts");
        }

        fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
            self.deletes.set(self.deletes.get() + 1);
            panic!("native transaction proof evaluation must not delete accounts");
        }
    }

    #[derive(Default)]
    struct DefaultUnsupportedStore {
        legacy_gets: Cell<usize>,
        puts: Cell<usize>,
        deletes: Cell<usize>,
    }

    impl AccountStore for DefaultUnsupportedStore {
        fn get(&self, _id: &AccountId) -> Option<Account> {
            self.legacy_gets.set(self.legacy_gets.get() + 1);
            None
        }

        fn put(&mut self, _account: Account) -> Result<(), ExecutionError> {
            self.puts.set(self.puts.get() + 1);
            Ok(())
        }

        fn delete(&mut self, _id: &AccountId) -> Result<(), ExecutionError> {
            self.deletes.set(self.deletes.get() + 1);
            Ok(())
        }
    }

    fn limits(proofs: usize) -> NativeTransactionProofLimits {
        NativeTransactionProofLimits {
            max_required_signer_indices: 16,
            max_keyset_account_count: 8,
            max_authentication_proof_count: proofs,
            max_signature_bytes: 3000,
            max_aggregate_signature_bytes: proofs.saturating_mul(3000),
            stored_keyset: StoredKeysetLimits {
                max_encoded_bytes: 32 * 1024,
                max_entries: 16,
                max_key_bytes: 4096,
                max_total_key_bytes: 16 * 4096,
            },
            max_algorithm_parameter_identifier_bytes: 64,
        }
    }

    fn metadata(account_id: AccountId, signer: bool) -> TxAccountMeta {
        TxAccountMeta {
            account_id,
            flags: u8::from(signer),
            access_hint: 0,
            reserved0: [0; 2],
        }
    }

    fn transaction(account_ids: &[(AccountId, bool)]) -> Transaction {
        Transaction {
            version: 1,
            chain_id: 7,
            payer: [0x41; 32],
            nonce: 8,
            fee_limit: 99,
            accounts: account_ids
                .iter()
                .map(|(id, signer)| metadata(*id, *signer))
                .collect(),
            program_id: [0x51; 32],
            call_data: vec![1, 3, 3, 7],
            auths: Vec::new(),
        }
    }

    fn auth(index: u16, signature: Vec<u8>) -> TxAuth {
        auth_with_suite(index, SUITE, signature)
    }

    fn auth_with_suite(index: u16, suite_id: u8, signature: Vec<u8>) -> TxAuth {
        TxAuth {
            account_index: index,
            suite_id,
            reserved: 0,
            signature,
        }
    }

    fn keyset(threshold: u16, entries: &[(u16, &[u8])]) -> Vec<u8> {
        keyset_with_suite(threshold, SUITE, entries)
    }

    fn keyset_with_suite(threshold: u16, suite_id: u8, entries: &[(u16, &[u8])]) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&[1, 0, 0, 0]);
        bytes.extend_from_slice(&threshold.to_le_bytes());
        bytes.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        bytes.extend_from_slice(&[0; 4]);
        for (weight, key) in entries {
            bytes.push(suite_id);
            bytes.extend_from_slice(&weight.to_le_bytes());
            bytes.push(0);
            bytes.extend_from_slice(&(key.len() as u16).to_le_bytes());
            bytes.extend_from_slice(key);
        }
        bytes
    }

    fn keyset_account(id: AccountId, data: Vec<u8>) -> Account {
        Account {
            id,
            header: AccountHeader {
                owner: KEYSET_PROGRAM_ID,
                lamports: 19,
                is_executable: false,
                rent_epoch: 7,
                reserved: [0xA5; 8],
            },
            data,
        }
    }

    fn with_auths(mut tx: Transaction, signatures: &[(u16, Vec<u8>)]) -> Transaction {
        tx.auths = signatures
            .iter()
            .map(|(index, signature)| auth(*index, signature.clone()))
            .collect();
        tx
    }

    fn sign(secret: &[u8], tx: &Transaction) -> Vec<u8> {
        MlDsa44Backend::sign(secret, &try_tx_digest_streaming(tx).unwrap()).unwrap()
    }

    fn reset(calls: &Calls) {
        calls.lookups.store(0, Ordering::SeqCst);
        calls.descriptors.store(0, Ordering::SeqCst);
        calls.verifications.store(0, Ordering::SeqCst);
    }

    fn assert_no_external_work(store: &RecordingStore, calls: &Calls) {
        assert!(store.reads.borrow().is_empty());
        assert_eq!(store.legacy_gets.get(), 0);
        assert_eq!(store.puts.get(), 0);
        assert_eq!(store.deletes.get(), 0);
        assert_eq!(calls.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(calls.descriptors.load(Ordering::SeqCst), 0);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_native_tx_proof_composes_interleaved_repeated_ids_once_each() {
        let (key_a, secret_a) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b1, secret_b1) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b2, secret_b2) = MlDsa44Backend::generate_keypair().unwrap();
        let id_a = [0xA1; 32];
        let id_b = [0xB2; 32];
        let tx_body = transaction(&[(id_a, true), (id_b, true), (id_a, true)]);
        let signature_a = sign(&secret_a, &tx_body);
        let signature_b1 = sign(&secret_b1, &tx_body);
        let signature_b2 = sign(&secret_b2, &tx_body);
        let mut tx = tx_body;
        // Interleave groups and repeat A at another exact signer index.
        tx.auths = vec![
            auth(1, signature_b1),
            auth(2, signature_a.clone()),
            auth(1, signature_b2),
            auth(0, signature_a),
        ];
        let original = tx.clone();
        let account_a = keyset_account(id_a, keyset(1, &[(1, &key_a)]));
        let account_b = keyset_account(id_b, keyset(2, &[(1, &key_b1), (1, &key_b2)]));
        let max_a = account_a.data.len();
        let max_b = account_b.data.len();
        let store = RecordingStore {
            accounts: vec![account_a, account_b],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        let mut exact_limits = limits(4);
        exact_limits.max_required_signer_indices = 3;
        exact_limits.max_keyset_account_count = 2;
        exact_limits.max_signature_bytes = 2420;
        exact_limits.max_aggregate_signature_bytes = 4 * 2420;
        exact_limits.stored_keyset.max_encoded_bytes = max_a.max(max_b);
        exact_limits.stored_keyset.max_entries = 2;
        exact_limits.stored_keyset.max_key_bytes = 1312;
        exact_limits.stored_keyset.max_total_key_bytes = 2 * 1312;
        exact_limits.max_algorithm_parameter_identifier_bytes = 16;
        let result =
            evaluate_native_transaction_proofs::<2, 2, 2>(&tx, &store, &provider, exact_limits)
                .unwrap();
        assert_eq!(
            result,
            NativeTransactionProofSummary {
                required_signer_index_count: 3,
                distinct_keyset_account_count: 2,
                evaluated_authentication_proof_count: 4,
            }
        );
        let bound = max_a.max(max_b);
        assert_eq!(&*store.reads.borrow(), &[(id_a, bound), (id_b, bound)]);
        assert_eq!(store.legacy_gets.get(), 0);
        assert_eq!(store.puts.get(), 0);
        assert_eq!(store.deletes.get(), 0);
        assert_eq!(calls.lookups.load(Ordering::SeqCst), 3);
        assert_eq!(calls.descriptors.load(Ordering::SeqCst), 3);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 6);
        assert_eq!(tx, original);
    }

    #[test]
    fn run422_native_tx_proof_requires_distinct_weight_within_each_group() {
        let (key_a, secret_a) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, secret_b) = MlDsa44Backend::generate_keypair().unwrap();
        let id = [0xA3; 32];
        let tx_body = transaction(&[(id, true)]);
        let signature_a = sign(&secret_a, &tx_body);
        let signature_b = sign(&secret_b, &tx_body);
        let mut tx = tx_body;
        tx.auths = vec![auth(0, signature_b), auth(0, signature_a)];
        let store = RecordingStore {
            accounts: vec![keyset_account(id, keyset(2, &[(1, &key_a), (1, &key_b)]))],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 2>(&tx, &store, &provider, limits(2),)
                .unwrap()
                .evaluated_authentication_proof_count,
            2
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 4);
    }

    #[test]
    fn run422_native_tx_proof_preflight_refusals_make_no_external_calls() {
        let id = [0xC1; 32];
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        let empty = transaction(&[(id, true)]);
        let store = RecordingStore::default();
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&empty, &store, &provider, limits(1),),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::EmptyAuths
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut out_of_range = transaction(&[(id, true)]);
        out_of_range.auths.push(auth(1, vec![]));
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(
                &out_of_range,
                &store,
                &provider,
                limits(1),
            ),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::AuthIndexOutOfRange
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut unmarked = transaction(&[(id, false)]);
        unmarked.auths.push(auth(0, vec![]));
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&unmarked, &store, &provider, limits(1),),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::AuthTargetsUnmarkedAccount
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut missing_duplicate_id = transaction(&[(id, true), (id, true)]);
        missing_duplicate_id.auths.push(auth(0, vec![]));
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(
                &missing_duplicate_id,
                &store,
                &provider,
                limits(1),
            ),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::MissingRequiredSignerAuth
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut extra_repeat = transaction(&[(id, true), (id, true)]);
        extra_repeat.auths = vec![auth(0, vec![]), auth(0, vec![])];
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 1>(
                &extra_repeat,
                &store,
                &provider,
                limits(2),
            ),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::MissingRequiredSignerAuth
            ))
        );
        assert_no_external_work(&store, &calls);
    }

    #[test]
    fn run422_native_tx_proof_wire_length_scalar_controls_are_fallible() {
        use NativeTransactionProofStructureError as Structure;

        assert_eq!(
            check_wire_lengths(
                usize::from(u16::MAX),
                usize::from(u16::MAX),
                u32::MAX as usize
            ),
            Ok(())
        );
        assert_eq!(
            check_wire_lengths(usize::from(u16::MAX) + 1, 0, 0),
            Err(NativeTransactionProofError::Structure(
                Structure::AccountCountWireLimit
            ))
        );
        assert_eq!(
            check_wire_lengths(0, usize::from(u16::MAX) + 1, 0),
            Err(NativeTransactionProofError::Structure(
                Structure::AuthCountWireLimit
            ))
        );
        assert_eq!(
            check_wire_lengths(0, 0, (u32::MAX as usize) + 1),
            Err(NativeTransactionProofError::Structure(
                Structure::CallDataWireLimit
            ))
        );
        assert_eq!(check_signature_wire_length(usize::from(u16::MAX)), Ok(()));
        assert_eq!(
            check_signature_wire_length(usize::from(u16::MAX) + 1),
            Err(NativeTransactionProofError::Structure(
                Structure::SignatureLengthWireLimit
            ))
        );
    }

    #[test]
    fn run422_native_tx_proof_global_and_workspace_budgets_are_preflighted() {
        let id_a = [0xD1; 32];
        let id_b = [0xD2; 32];
        let tx = with_auths(
            transaction(&[(id_a, true), (id_b, true)]),
            &[(0, vec![1]), (1, vec![2])],
        );
        let store = RecordingStore::default();
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));
        let mut too_many = limits(2);
        too_many.max_authentication_proof_count = 1;
        assert_eq!(
            evaluate_native_transaction_proofs::<2, 2, 1>(&tx, &store, &provider, too_many),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::AuthenticationProofCountLimit
            ))
        );
        assert_no_external_work(&store, &calls);

        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 1>(&tx, &store, &provider, limits(2),),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::GroupWorkspaceCapacity
            ))
        );
        assert_no_external_work(&store, &calls);

        assert_eq!(
            evaluate_native_transaction_proofs::<0, 2, 1>(&tx, &store, &provider, limits(2)),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::GroupWorkspaceCapacity
            ))
        );
        assert_no_external_work(&store, &calls);

        assert_eq!(
            evaluate_native_transaction_proofs::<2, 0, 1>(&tx, &store, &provider, limits(2),),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::ProofWorkspaceCapacity
            ))
        );
        assert_no_external_work(&store, &calls);

        let group_with_two_proofs = with_auths(
            transaction(&[(id_a, true), (id_b, true)]),
            &[(0, vec![1]), (0, vec![2]), (1, vec![3])],
        );
        assert_eq!(
            evaluate_native_transaction_proofs::<2, 1, 1>(
                &group_with_two_proofs,
                &store,
                &provider,
                limits(3),
            ),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::ProofWorkspaceCapacity
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut signature_limits = limits(2);
        signature_limits.max_signature_bytes = 0;
        assert_eq!(
            evaluate_native_transaction_proofs::<2, 2, 1>(&tx, &store, &provider, signature_limits,),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::SignatureByteLimit
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut group_limit = limits(2);
        group_limit.max_keyset_account_count = 1;
        assert_eq!(
            evaluate_native_transaction_proofs::<2, 2, 1>(&tx, &store, &provider, group_limit),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::KeysetAccountCountLimit
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut signer_limit = limits(2);
        signer_limit.max_required_signer_indices = 1;
        assert_eq!(
            evaluate_native_transaction_proofs::<2, 2, 1>(&tx, &store, &provider, signer_limit),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::RequiredSignerCountLimit
            ))
        );
        assert_no_external_work(&store, &calls);

        let mut aggregate_limit = limits(2);
        aggregate_limit.max_signature_bytes = 1;
        aggregate_limit.max_aggregate_signature_bytes = 1;
        assert_eq!(
            evaluate_native_transaction_proofs::<2, 2, 1>(&tx, &store, &provider, aggregate_limit,),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::AggregateSignatureByteLimit
            ))
        );
        assert_no_external_work(&store, &calls);
    }

    #[test]
    fn run422_native_tx_proof_thresholds_cannot_borrow_between_groups() {
        let (key_a, secret_a) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, secret_b) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_c, secret_c) = MlDsa44Backend::generate_keypair().unwrap();
        let id_a = [0xE1; 32];
        let id_b = [0xE2; 32];
        let tx_body = transaction(&[(id_a, true), (id_b, true)]);
        let signature_a = sign(&secret_a, &tx_body);
        let signature_b = sign(&secret_b, &tx_body);
        let signature_c = sign(&secret_c, &tx_body);
        let mut tx = tx_body;
        // Group B has extra valid weight; it cannot satisfy A's threshold.
        tx.auths = vec![
            auth(0, signature_a),
            auth(1, signature_b),
            auth(1, signature_c),
        ];
        let store = RecordingStore {
            accounts: vec![
                keyset_account(id_a, keyset(2, &[(1, &key_a), (1, &key_c)])),
                keyset_account(id_b, keyset(1, &[(1, &key_b), (1, &key_c)])),
            ],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        assert_eq!(
            evaluate_native_transaction_proofs::<2, 3, 2>(&tx, &store, &provider, limits(3),),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::ThresholdUnreachable
            ))
        );
        assert_eq!(store.reads.borrow().len(), 1);
        assert_eq!(tx.accounts.len(), 2);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_native_tx_proof_later_group_refusal_follows_earlier_success() {
        let (key_a, secret_a) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b1, _secret_b1) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b2, _secret_b2) = MlDsa44Backend::generate_keypair().unwrap();
        let id_a = [0xE2; 32];
        let id_b = [0xE3; 32];
        let tx_body = transaction(&[(id_a, true), (id_b, true)]);
        let signature_a = sign(&secret_a, &tx_body);
        let mut tx = tx_body;
        // A succeeds; B's actual proof count cannot reach its two-key threshold.
        tx.auths = vec![auth(0, signature_a), auth(1, vec![0x42; 2420])];
        let original = tx.clone();
        let account_a = keyset_account(id_a, keyset(1, &[(1, &key_a)]));
        let account_b = keyset_account(id_b, keyset(2, &[(1, &key_b1), (1, &key_b2)]));
        let store = RecordingStore {
            accounts: vec![account_a, account_b],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        assert_eq!(
            evaluate_native_transaction_proofs::<2, 1, 2>(&tx, &store, &provider, limits(2)),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::ThresholdUnreachable
            ))
        );
        let bound = limits(2).stored_keyset.max_encoded_bytes;
        assert_eq!(&*store.reads.borrow(), &[(id_a, bound), (id_b, bound)]);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 1);
        assert_eq!(tx, original);
    }

    #[test]
    fn run422_native_tx_proof_counts_same_canonical_key_per_group() {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let id_a = [0xE4; 32];
        let id_b = [0xE5; 32];
        let tx_body = transaction(&[(id_a, true), (id_b, true)]);
        let signature = sign(&secret, &tx_body);
        let mut tx = tx_body;
        tx.auths = vec![auth(0, signature.clone()), auth(1, signature)];
        let store = RecordingStore {
            accounts: vec![
                keyset_account(id_a, keyset(2, &[(2, &key)])),
                keyset_account(id_b, keyset(5, &[(5, &key)])),
            ],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        assert_eq!(
            evaluate_native_transaction_proofs::<2, 1, 1>(&tx, &store, &provider, limits(2)),
            Ok(NativeTransactionProofSummary {
                required_signer_index_count: 2,
                distinct_keyset_account_count: 2,
                evaluated_authentication_proof_count: 2,
            })
        );
        assert_eq!(store.reads.borrow().len(), 2);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn run422_native_tx_proof_repeated_index_proofs_do_not_multiply_weight() {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let id = [0xE3; 32];
        let tx_body = transaction(&[(id, true), (id, true)]);
        let signature = sign(&secret, &tx_body);
        let mut tx = tx_body;
        tx.auths = vec![
            auth(0, signature.clone()),
            auth(0, signature.clone()),
            auth(1, signature),
        ];
        let store = RecordingStore {
            accounts: vec![keyset_account(id, keyset(2, &[(1, &key)]))],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        assert_eq!(
            evaluate_native_transaction_proofs::<1, 3, 1>(&tx, &store, &provider, limits(3),),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::ThresholdUnreachable
            ))
        );
        assert_eq!(store.reads.borrow().len(), 1);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_native_tx_proof_late_invalid_extra_proof_is_still_verified() {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let id = [0xE4; 32];
        let tx_body = transaction(&[(id, true)]);
        let signature = sign(&secret, &tx_body);
        let mut invalid = signature.clone();
        invalid[0] ^= 0x80;
        let mut tx = tx_body;
        tx.auths = vec![auth(0, signature), auth(0, invalid)];
        let original = tx.clone();
        let account = keyset_account(id, keyset(1, &[(1, &key)]));
        let store = RecordingStore {
            accounts: vec![account],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 1>(&tx, &store, &provider, limits(2),),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::InvalidProof
            ))
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 2);
        assert_eq!(
            &*store.reads.borrow(),
            &[(id, limits(2).stored_keyset.max_encoded_bytes)]
        );
        assert_eq!(tx, original);
    }

    #[test]
    fn run422_native_tx_proof_rejects_body_digest_and_bad_signature() {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let id = [0xE5; 32];
        let body = transaction(&[(id, true)]);
        let signature = sign(&secret, &body);
        let mut tx = body.clone();
        tx.auths.push(auth(0, signature.clone()));
        tx.call_data[0] ^= 1;
        let store = RecordingStore {
            accounts: vec![keyset_account(id, keyset(1, &[(1, &key)]))],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &store, &provider, limits(1),),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::InvalidProof
            ))
        );
        assert_eq!(tx.call_data[0], body.call_data[0] ^ 1);

        let mut malformed = body;
        malformed.auths.push(auth(0, vec![]));
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&malformed, &store, &provider, limits(1),),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::InvalidProof
            ))
        );
    }

    #[test]
    fn run422_native_tx_proof_bounded_read_and_parser_refusals_are_typed() {
        let (key, _secret) = MlDsa44Backend::generate_keypair().unwrap();
        let id = [0xE6; 32];
        let tx = with_auths(transaction(&[(id, true)]), &[(0, vec![0x42; 2420])]);
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        let unsupported = DefaultUnsupportedStore::default();
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &unsupported, &provider, limits(1),),
            Err(NativeTransactionProofError::AccountRead(
                KeysetAccountReadError::Unsupported
            ))
        );
        assert_eq!(unsupported.legacy_gets.get(), 0);
        assert_eq!(unsupported.puts.get(), 0);
        assert_eq!(unsupported.deletes.get(), 0);
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);

        let missing = RecordingStore::default();
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &missing, &provider, limits(1),),
            Err(NativeTransactionProofError::AccountRead(
                KeysetAccountReadError::MissingAccount
            ))
        );
        assert_eq!(
            &*missing.reads.borrow(),
            &[(id, limits(1).stored_keyset.max_encoded_bytes)]
        );

        let backend = RecordingStore {
            read_error: Some(BoundedReadError::Backend),
            ..RecordingStore::default()
        };
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &backend, &provider, limits(1),),
            Err(NativeTransactionProofError::AccountRead(
                KeysetAccountReadError::Backend
            ))
        );

        let mut configured = limits(1);
        configured.stored_keyset.max_encoded_bytes = 1;
        let oversized = RecordingStore {
            accounts: vec![keyset_account(id, keyset(1, &[(1, &key)]))],
            ..RecordingStore::default()
        };
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &oversized, &provider, configured,),
            Err(NativeTransactionProofError::AccountRead(
                KeysetAccountReadError::Oversized
            ))
        );

        let malformed = RecordingStore {
            accounts: vec![keyset_account(id, vec![1, 2, 3])],
            ..RecordingStore::default()
        };
        assert!(matches!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &malformed, &provider, limits(1),),
            Err(NativeTransactionProofError::KeysetParse(
                StoredKeysetParseError::Malformed(_)
            ))
        ));

        let too_many_entries = RecordingStore {
            accounts: vec![keyset_account(id, keyset(1, &[(1, &key), (1, &key)]))],
            ..RecordingStore::default()
        };
        let mut entry_limits = limits(1);
        entry_limits.stored_keyset.max_entries = 1;
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(
                &tx,
                &too_many_entries,
                &provider,
                entry_limits,
            ),
            Err(NativeTransactionProofError::KeysetParse(
                StoredKeysetParseError::EntryCountLimit
            ))
        );

        for (max_key_bytes, max_total_key_bytes, expected) in [
            (0, 2 * key.len(), StoredKeysetParseError::PerKeyBytesLimit),
            (
                key.len(),
                key.len() - 1,
                StoredKeysetParseError::AggregateKeyBytesLimit,
            ),
        ] {
            let mut parser_limits = limits(1);
            parser_limits.stored_keyset.max_entries = 2;
            parser_limits.stored_keyset.max_key_bytes = max_key_bytes;
            parser_limits.stored_keyset.max_total_key_bytes = max_total_key_bytes;
            assert_eq!(
                evaluate_native_transaction_proofs::<1, 1, 2>(
                    &tx,
                    &too_many_entries,
                    &provider,
                    parser_limits,
                ),
                Err(NativeTransactionProofError::KeysetParse(expected))
            );
        }

        let trailing = RecordingStore {
            accounts: vec![keyset_account(id, {
                let mut bytes = keyset(1, &[(1, &key)]);
                bytes.push(0xAA);
                bytes
            })],
            ..RecordingStore::default()
        };
        assert!(matches!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &trailing, &provider, limits(1),),
            Err(NativeTransactionProofError::KeysetParse(
                StoredKeysetParseError::Malformed(_)
            ))
        ));

        let mut capacity_limits = limits(1);
        capacity_limits.stored_keyset.max_entries = 2;
        let capacity_calls = Arc::new(Calls::default());
        let capacity_provider = CountedProvider::mldsa(Arc::clone(&capacity_calls));
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(
                &tx,
                &too_many_entries,
                &capacity_provider,
                capacity_limits,
            ),
            Err(NativeTransactionProofError::Structure(
                NativeTransactionProofStructureError::EntryWorkspaceCapacity
            ))
        );
        assert_eq!(capacity_calls.lookups.load(Ordering::SeqCst), 0);
        assert_eq!(capacity_calls.descriptors.load(Ordering::SeqCst), 0);
        assert_eq!(capacity_calls.verifications.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn run422_native_tx_proof_checks_account_metadata_before_provider_work() {
        let id = [0xE7; 32];
        let tx = with_auths(transaction(&[(id, true)]), &[(0, vec![0x42; 2420])]);
        let account = keyset_account(id, keyset(1, &[(1, &[0x55])]));
        let mut wrong_owner = account.clone();
        wrong_owner.header.owner = [0; 32];
        let wrong_id = RecordingStore {
            response_override: Some(Account {
                id: [0x99; 32],
                ..account.clone()
            }),
            ..RecordingStore::default()
        };
        let owner_store = RecordingStore {
            response_override: Some(wrong_owner),
            ..RecordingStore::default()
        };
        let mut executable = account;
        executable.header.is_executable = true;
        let executable_store = RecordingStore {
            response_override: Some(executable),
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::mldsa(Arc::clone(&calls));

        for (store, expected) in [
            (&wrong_id, KeysetAccountReadError::AccountIdMismatch),
            (&owner_store, KeysetAccountReadError::OwnerMismatch),
            (&executable_store, KeysetAccountReadError::Executable),
        ] {
            assert_eq!(
                evaluate_native_transaction_proofs::<1, 1, 1>(&tx, store, &provider, limits(1),),
                Err(NativeTransactionProofError::AccountRead(expected))
            );
            assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);
            reset(&calls);
        }
    }

    #[test]
    fn run422_native_tx_proof_unsupported_suite_and_body_change_refuse() {
        let id = [0xE8; 32];
        let (key, _secret) = MlDsa44Backend::generate_keypair().unwrap();
        let mut tx = with_auths(transaction(&[(id, true)]), &[(0, vec![0x42; 2420])]);
        let store = RecordingStore {
            accounts: vec![keyset_account(id, keyset(1, &[(1, &key)]))],
            ..RecordingStore::default()
        };
        let calls = Arc::new(Calls::default());
        let provider = CountedProvider::no_suites(Arc::clone(&calls));
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(&tx, &store, &provider, limits(1),),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::SuiteNotFound
            ))
        );
        assert_eq!(calls.verifications.load(Ordering::SeqCst), 0);

        tx.auths[0].suite_id = SUITE.wrapping_add(1);
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(
                &tx,
                &store,
                &CountedProvider::mldsa(Arc::new(Calls::default())),
                limits(1),
            ),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::NoMatchingSuiteEntry
            ))
        );
    }

    #[test]
    fn run422_native_tx_proof_synthetic_defensive_ambiguity_and_backend_controls() {
        // These synthetic suites exercise defensive control flow only; they are
        // not cryptographic security controls or positive signature evidence.
        let id = [0xE8; 32];
        let body = transaction(&[(id, true)]);
        let ambiguous_tx = {
            let mut tx = body.clone();
            tx.auths.push(auth_with_suite(0, 7, vec![1]));
            tx
        };
        let ambiguous_store = RecordingStore {
            accounts: vec![keyset_account(
                id,
                keyset_with_suite(1, 7, &[(1, &[1]), (1, &[2])]),
            )],
            ..RecordingStore::default()
        };
        let ambiguous_calls = Arc::new(Calls::default());
        let ambiguous_provider = CountedProvider::with_suite(
            Arc::new(SyntheticSuite {
                mode: SyntheticVerifyMode::AcceptAll,
                calls: Arc::clone(&ambiguous_calls),
            }),
            Arc::clone(&ambiguous_calls),
        );
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 2>(
                &ambiguous_tx,
                &ambiguous_store,
                &ambiguous_provider,
                limits(1),
            ),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::AmbiguousProof
            ))
        );
        assert_eq!(ambiguous_calls.verifications.load(Ordering::SeqCst), 2);

        let backend_store = RecordingStore {
            accounts: vec![keyset_account(id, keyset_with_suite(1, 7, &[(1, &[3])]))],
            ..RecordingStore::default()
        };
        let backend_calls = Arc::new(Calls::default());
        let backend_provider = CountedProvider::with_suite(
            Arc::new(SyntheticSuite {
                mode: SyntheticVerifyMode::BackendFailure,
                calls: Arc::clone(&backend_calls),
            }),
            Arc::clone(&backend_calls),
        );
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 1, 1>(
                &ambiguous_tx,
                &backend_store,
                &backend_provider,
                limits(1),
            ),
            Err(NativeTransactionProofError::KeysetProof(
                KeysetProofEvaluationError::VerificationFailure
            ))
        );
        assert_eq!(backend_calls.verifications.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn run422_native_tx_proof_auth_order_permutation_preserves_acceptance() {
        let (key, secret) = MlDsa44Backend::generate_keypair().unwrap();
        let id = [0xE9; 32];
        let tx_body = transaction(&[(id, true)]);
        let signature_a = sign(&secret, &tx_body);
        let signature_b = sign(&secret, &tx_body);
        let mut tx_a = tx_body.clone();
        tx_a.auths = vec![auth(0, signature_a.clone()), auth(0, signature_b.clone())];
        let mut tx_b = tx_body;
        tx_b.auths = vec![auth(0, signature_b), auth(0, signature_a)];
        let store = RecordingStore {
            accounts: vec![keyset_account(id, keyset(1, &[(1, &key)]))],
            ..RecordingStore::default()
        };
        let provider = CountedProvider::mldsa(Arc::new(Calls::default()));
        let expected = NativeTransactionProofSummary {
            required_signer_index_count: 1,
            distinct_keyset_account_count: 1,
            evaluated_authentication_proof_count: 2,
        };
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 1>(&tx_a, &store, &provider, limits(2),),
            Ok(expected)
        );
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 1>(&tx_b, &store, &provider, limits(2),),
            Ok(expected)
        );
    }

    #[test]
    fn run422_native_tx_proof_keyset_entry_order_permutation_preserves_result() {
        let (key_a, secret_a) = MlDsa44Backend::generate_keypair().unwrap();
        let (key_b, secret_b) = MlDsa44Backend::generate_keypair().unwrap();
        let id = [0xEA; 32];
        let tx_body = transaction(&[(id, true)]);
        let signature_a = sign(&secret_a, &tx_body);
        let signature_b = sign(&secret_b, &tx_body);
        let mut tx = tx_body;
        tx.auths = vec![auth(0, signature_a), auth(0, signature_b)];
        let forward = RecordingStore {
            accounts: vec![keyset_account(id, keyset(2, &[(1, &key_a), (1, &key_b)]))],
            ..RecordingStore::default()
        };
        let reversed = RecordingStore {
            accounts: vec![keyset_account(id, keyset(2, &[(1, &key_b), (1, &key_a)]))],
            ..RecordingStore::default()
        };
        let provider = CountedProvider::mldsa(Arc::new(Calls::default()));
        let expected = NativeTransactionProofSummary {
            required_signer_index_count: 1,
            distinct_keyset_account_count: 1,
            evaluated_authentication_proof_count: 2,
        };
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 2>(&tx, &forward, &provider, limits(2),),
            Ok(expected)
        );
        assert_eq!(
            evaluate_native_transaction_proofs::<1, 2, 2>(&tx, &reversed, &provider, limits(2),),
            Ok(expected)
        );
    }

    #[test]
    fn run422_native_tx_proof_reports_compiler_object_sizes() {
        use core::mem::size_of;

        eprintln!(
            "native transaction proof object bytes: coverage={} preflight<G=2>={} proof_workspace<P=2>={} proof_workspace<P=4>={} group={} proof={} limits={} summary={} error={} keyset_view={} account={}",
            size_of::<[u8; (u16::MAX as usize + 1) / 8]>(),
            size_of::<TransactionPreflight<2>>(),
            size_of::<BorrowedProofWorkspace<'static, 2>>(),
            size_of::<BorrowedProofWorkspace<'static, 4>>(),
            size_of::<GroupMetadata>(),
            size_of::<KeysetSignatureProof<'static>>(),
            size_of::<NativeTransactionProofLimits>(),
            size_of::<NativeTransactionProofSummary>(),
            size_of::<NativeTransactionProofError>(),
            size_of::<qbind_serde::keyset::StoredKeysetView<'static>>(),
            size_of::<Account>(),
        );
    }
}
