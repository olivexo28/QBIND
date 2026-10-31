use std::sync::Arc;

use qbind_crypto::{ml_dsa_44_sign_digest, MlDsa44SignatureSuite, StaticCryptoProvider};
use qbind_ledger::{Account, AccountStore, ExecutionError, InMemoryAccountStore};
use qbind_runtime::TxExecutor;
use qbind_serde::StateDecode;
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_types::{AccountId, KeysetAccount, KeysetEntry, ProgramId};
use qbind_wire::io::WireEncode;
use qbind_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const AUTH_SUITE_ID: u8 = 100;
const AUTH_KEYSET_ID: AccountId = [0xA0; 32];

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn dummy_program_id(byte: u8) -> ProgramId {
    [byte; 32]
}

struct AuthFixture {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl AuthFixture {
    fn new(store: &mut InMemoryAccountStore) -> Self {
        let (public_key, secret_key) =
            qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
        let entry = KeysetEntry {
            suite_id: AUTH_SUITE_ID,
            weight: 1,
            reserved0: [0; 1],
            pubkey_len: public_key.len() as u16,
            pubkey_bytes: public_key.clone(),
        };
        let keyset = KeysetAccount {
            version: 1,
            reserved0: [0; 3],
            threshold: 1,
            entry_count: 1,
            reserved1: [0; 4],
            entries: vec![entry],
        };
        let mut data = Vec::new();
        qbind_serde::StateEncode::encode_state(&keyset, &mut data);
        store
            .put(Account::new(AUTH_KEYSET_ID, KEYSET_PROGRAM_ID, 0, data))
            .expect("seed existing test keyset");
        Self {
            public_key,
            secret_key,
        }
    }

    fn crypto(&self) -> Arc<dyn qbind_crypto::CryptoProvider> {
        Arc::new(
            StaticCryptoProvider::new()
                .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(AUTH_SUITE_ID))),
        )
    }

    fn authenticate(&self, tx: &mut Transaction) {
        tx.accounts.insert(
            0,
            TxAccountMeta {
                account_id: AUTH_KEYSET_ID,
                flags: 1,
                access_hint: 0,
                reserved0: [0; 2],
            },
        );
        tx.auths = vec![TxAuth {
            account_index: 0,
            suite_id: AUTH_SUITE_ID,
            reserved: 0,
            signature: Vec::new(),
        }];
        let digest = qbind_hash::tx::tx_digest(tx);
        tx.auths[0].signature =
            ml_dsa_44_sign_digest(&self.secret_key, &digest).expect("sign canonical tx_digest");
    }
}

fn build_keyset_create_tx(target_id: AccountId, auth: &AuthFixture) -> Transaction {
    let entries = vec![WireKeyEntry {
        suite_id: AUTH_SUITE_ID,
        weight: 100,
        pubkey_bytes: auth.public_key.clone(),
    }];

    let call = CreateKeysetCall {
        version: 1,
        target_id,
        threshold: 50,
        entries,
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_KEYSET_CREATE);

    // The target remains distinct from the existing keyset used for authentication.
    let accounts = vec![TxAccountMeta {
        account_id: target_id,
        flags: 0b0000_0010,
        access_hint: 0,
        reserved0: [0u8; 2],
    }];

    let mut tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts,
        program_id: KEYSET_PROGRAM_ID,
        call_data,
        auths: Vec::new(),
    };
    auth.authenticate(&mut tx);
    tx
}

#[test]
fn executor_runs_keyset_create_end_to_end() {
    let mut store = InMemoryAccountStore::new();
    let auth = AuthFixture::new(&mut store);
    let crypto = auth.crypto();
    let executor: TxExecutor<InMemoryAccountStore> = TxExecutor::new();

    let keyset_id = dummy_account_id(0xEE);
    let tx = build_keyset_create_tx(keyset_id, &auth);
    assert_ne!(keyset_id, AUTH_KEYSET_ID);

    executor
        .execute_transaction(&mut store, crypto, &tx)
        .expect("execute_transaction should succeed");

    // Check that the keyset account now exists and decodes correctly.
    let stored = store.get(&keyset_id).expect("keyset account should exist");
    assert_eq!(stored.id, keyset_id);
    assert_eq!(stored.header.owner, KEYSET_PROGRAM_ID);

    let mut slice: &[u8] = &stored.data;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode keyset account");
    assert!(slice.is_empty());

    assert_eq!(decoded.threshold, 50);
    assert_eq!(decoded.entries.len(), 1);
    assert_eq!(decoded.entries[0].suite_id, AUTH_SUITE_ID);
    assert_eq!(decoded.entries[0].weight, 100);
    assert_eq!(decoded.entries[0].pubkey_bytes, auth.public_key);
}

#[test]
fn executor_unknown_program_id_fails() {
    let mut store = InMemoryAccountStore::new();
    let auth = AuthFixture::new(&mut store);
    let crypto = auth.crypto();
    let executor: TxExecutor<InMemoryAccountStore> = TxExecutor::new();

    let mut tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: Vec::new(),
        program_id: dummy_program_id(0xFF), // unknown
        call_data: Vec::new(),
        auths: Vec::new(),
    };
    auth.authenticate(&mut tx);

    let err = executor
        .execute_transaction(&mut store, crypto, &tx)
        .expect_err("must fail");
    match err {
        ExecutionError::ProgramError(msg) => {
            assert!(msg.contains("unknown program_id"));
        }
        other => panic!("unexpected error: {:?}", other),
    }
}

#[test]
fn executor_rejects_empty_auth_before_keyset_program_changes_state() {
    let mut store = InMemoryAccountStore::new();
    let auth = AuthFixture::new(&mut store);
    let crypto = auth.crypto();
    let executor: TxExecutor<InMemoryAccountStore> = TxExecutor::new();
    let target_id = dummy_account_id(0xEE);
    let mut tx = build_keyset_create_tx(target_id, &auth);
    tx.auths.clear();

    let tx_witness = tx.clone();
    let account_witness = [store.get(&AUTH_KEYSET_ID), store.get(&target_id)];
    let err = executor
        .execute_transaction(&mut store, crypto, &tx)
        .expect_err("empty-auth keyset create must fail before execution");

    assert!(matches!(
        err,
        ExecutionError::InvalidCallData("transaction requires at least one authentication entry")
    ));
    assert!(tx == tx_witness, "refusal changed the complete transaction");
    let account_state_after = [store.get(&AUTH_KEYSET_ID), store.get(&target_id)];
    assert!(
        account_state_after == account_witness,
        "refusal changed the complete account witness"
    );
}
