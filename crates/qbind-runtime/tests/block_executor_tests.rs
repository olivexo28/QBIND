use std::sync::Arc;

use qbind_crypto::{ml_dsa_44_sign_digest, MlDsa44SignatureSuite, StaticCryptoProvider};
use qbind_ledger::{Account, AccountStore, ExecutionError, InMemoryAccountStore};
use qbind_runtime::{BlockExecutor, TxApplyResult};
use qbind_serde::StateDecode;
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_system::validator_program::VALIDATOR_PROGRAM_ID;
use qbind_types::{AccountId, KeysetAccount, KeysetEntry};
use qbind_wire::io::WireEncode;
use qbind_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const AUTH_SUITE_ID: u8 = 100;
const AUTH_KEYSET_ID: AccountId = [0xA0; 32];

fn dummy_account_id(byte: u8) -> AccountId {
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
        let keyset = KeysetAccount {
            version: 1,
            reserved0: [0; 3],
            threshold: 1,
            entry_count: 1,
            reserved1: [0; 4],
            entries: vec![KeysetEntry {
                suite_id: AUTH_SUITE_ID,
                weight: 1,
                reserved0: [0; 1],
                pubkey_len: public_key.len() as u16,
                pubkey_bytes: public_key.clone(),
            }],
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

    fn unsigned(&self, mut tx: Transaction) -> Transaction {
        self.authenticate(&mut tx);
        tx.auths.clear();
        tx
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

fn build_invalid_validator_tx(auth: &AuthFixture) -> Transaction {
    let mut tx = Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x02),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: Vec::new(),
        program_id: VALIDATOR_PROGRAM_ID,
        call_data: vec![0xFF],
        auths: Vec::new(),
    };
    auth.authenticate(&mut tx);
    tx
}

#[test]
fn block_executor_applies_multiple_txs_and_reports_results() {
    let mut store = InMemoryAccountStore::new();
    let auth = AuthFixture::new(&mut store);
    let crypto = auth.crypto();
    let executor: BlockExecutor<InMemoryAccountStore> = BlockExecutor::new();

    let keyset_id = dummy_account_id(0xEE);
    let tx1 = build_keyset_create_tx(keyset_id, &auth);
    let tx2 = build_invalid_validator_tx(&auth);

    let result = executor.execute_block(&mut store, crypto, &[tx1, tx2]);

    assert_eq!(result.tx_results.len(), 2);
    assert!(matches!(result.tx_results[0], TxApplyResult::Success));
    assert!(matches!(result.tx_results[1], TxApplyResult::Failed(_)));
    assert!(!result.all_succeeded());

    // Check that state from the successful tx is present.
    let stored = store.get(&keyset_id).expect("keyset account must exist");
    assert_eq!(stored.header.owner, KEYSET_PROGRAM_ID);

    let mut slice: &[u8] = &stored.data;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode KeysetAccount");
    assert!(slice.is_empty());
    assert_eq!(decoded.entries.len(), 1);
}

#[test]
fn block_executor_all_successes_sets_all_succeeded_true() {
    let mut store = InMemoryAccountStore::new();
    let auth = AuthFixture::new(&mut store);
    let crypto = auth.crypto();
    let executor: BlockExecutor<InMemoryAccountStore> = BlockExecutor::new();

    let keyset_id1 = dummy_account_id(0xA1);
    let keyset_id2 = dummy_account_id(0xA2);

    let tx1 = build_keyset_create_tx(keyset_id1, &auth);
    let tx2 = build_keyset_create_tx(keyset_id2, &auth);

    let result = executor.execute_block(&mut store, crypto, &[tx1, tx2]);

    assert_eq!(result.tx_results.len(), 2);
    assert!(result.all_succeeded());
    assert!(matches!(result.tx_results[0], TxApplyResult::Success));
    assert!(matches!(result.tx_results[1], TxApplyResult::Success));

    assert!(store.get(&keyset_id1).is_some());
    assert!(store.get(&keyset_id2).is_some());
}

#[test]
fn block_executor_refuses_unsigned_effects_and_keeps_sequential_positive_result() {
    let mut store = InMemoryAccountStore::new();
    let auth = AuthFixture::new(&mut store);
    let crypto = auth.crypto();
    let executor: BlockExecutor<InMemoryAccountStore> = BlockExecutor::new();
    let refused_target = dummy_account_id(0xB1);
    let accepted_target = dummy_account_id(0xB2);
    let unsigned = auth.unsigned(build_keyset_create_tx(refused_target, &auth));
    let accepted = build_keyset_create_tx(accepted_target, &auth);
    let txs = [unsigned, accepted];
    let tx_witnesses = txs.clone();
    let account_witness = [
        store.get(&AUTH_KEYSET_ID),
        store.get(&refused_target),
        store.get(&accepted_target),
    ];

    let result = executor.execute_block(&mut store, crypto, &txs);

    assert!(
        txs == tx_witnesses,
        "block executor changed the complete transaction witnesses"
    );
    assert_eq!(txs.len(), result.tx_results.len());
    assert!(matches!(
        result.tx_results[0],
        TxApplyResult::Failed(ExecutionError::InvalidCallData(
            "transaction requires at least one authentication entry"
        ))
    ));
    assert!(matches!(result.tx_results[1], TxApplyResult::Success));
    let account_state_after = [
        store.get(&AUTH_KEYSET_ID),
        store.get(&refused_target),
        store.get(&accepted_target),
    ];
    assert!(
        account_state_after[0] == account_witness[0]
            && account_state_after[1] == account_witness[1]
            && account_witness[2].is_none()
            && account_state_after[2]
                .as_ref()
                .is_some_and(|account| account.header.owner == KEYSET_PROGRAM_ID),
        "block execution account witnesses disagree with the sequential result"
    );
}
