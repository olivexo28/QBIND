use std::sync::Arc;

use qbind_consensus::{
    BlockVerifyConfig, ConsensusNodeError, ConsensusVerifyError, HotStuffState, ValidatorInfo,
    ValidatorSet, VoteDecision,
};
use qbind_crypto::{
    ml_dsa_44_sign_digest, AeadSuite, CryptoError, CryptoProvider, KemSuite, MlDsa44SignatureSuite,
    SignatureSuite,
};
use qbind_ledger::{Account, AccountStore, ExecutionError, InMemoryAccountStore};
use qbind_node::{Node, NodeError};
use qbind_serde::StateDecode;
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_types::{AccountId, Hash32, KeysetAccount, KeysetEntry};
use qbind_wire::consensus::{BlockHeader, BlockProposal};
use qbind_wire::io::WireEncode;
use qbind_wire::keyset::{CreateKeysetCall, WireKeyEntry, OP_KEYSET_CREATE};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const AUTH_SUITE_ID: u8 = 100;
const AUTH_KEYSET_ID: AccountId = [0xA0; 32];

fn dummy_account_id(b: u8) -> AccountId {
    [b; 32]
}

/// Test-only structural control for the consensus harness; not transaction-auth evidence.
struct AcceptAllSignatureSuite;

impl SignatureSuite for AcceptAllSignatureSuite {
    fn suite_id(&self) -> u8 {
        1
    }

    fn public_key_len(&self) -> usize {
        0
    }

    fn signature_len(&self) -> usize {
        0
    }

    fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// Test provider: suite 1 is structural-only consensus harness control; suite 100
/// uses the production ML-DSA-44 adapter for native transaction authentication.
struct TestCryptoProvider {
    sig_suite: AcceptAllSignatureSuite,
    tx_auth_suite: MlDsa44SignatureSuite,
}

impl TestCryptoProvider {
    fn new() -> Self {
        Self {
            sig_suite: AcceptAllSignatureSuite,
            tx_auth_suite: MlDsa44SignatureSuite::new(AUTH_SUITE_ID),
        }
    }
}

impl CryptoProvider for TestCryptoProvider {
    fn signature_suite(&self, suite_id: u8) -> Option<&dyn SignatureSuite> {
        match suite_id {
            1 => Some(&self.sig_suite),
            AUTH_SUITE_ID => Some(&self.tx_auth_suite),
            _ => None,
        }
    }

    fn kem_suite(&self, _suite_id: u8) -> Option<&dyn KemSuite> {
        None
    }

    fn aead_suite(&self, _suite_id: u8) -> Option<&dyn AeadSuite> {
        None
    }
}

fn test_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(TestCryptoProvider::new())
}

struct AuthFixture {
    public_key: Vec<u8>,
    secret_key: Vec<u8>,
}

impl AuthFixture {
    fn new() -> Self {
        let (public_key, secret_key) =
            qbind_crypto::ml_dsa44::MlDsa44Backend::generate_keypair().expect("ML-DSA-44 keygen");
        Self {
            public_key,
            secret_key,
        }
    }

    fn seed(&self, store: &mut InMemoryAccountStore) {
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
                pubkey_len: self.public_key.len() as u16,
                pubkey_bytes: self.public_key.clone(),
            }],
        };
        let mut data = Vec::new();
        qbind_serde::StateEncode::encode_state(&keyset, &mut data);
        store
            .put(Account::new(AUTH_KEYSET_ID, KEYSET_PROGRAM_ID, 0, data))
            .expect("seed existing test keyset");
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

fn small_validator_set() -> ValidatorSet {
    ValidatorSet {
        validators: vec![ValidatorInfo {
            validator_id: 0,
            suite_id: 1,
            consensus_pk: vec![0],
            voting_power: 1,
        }],
        qc_threshold: 1,
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
        flags: 0b0000_0011, // signer + writable
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

fn build_proposal_with_txs(txs: &[Transaction]) -> BlockProposal {
    // Encode each tx into a blob.
    let mut tx_blobs = Vec::with_capacity(txs.len());
    for tx in txs {
        let mut buf = Vec::new();
        tx.encode(&mut buf);
        tx_blobs.push(buf);
    }

    BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 10,
            round: 0,
            parent_block_id: [0xCD; 32],
            payload_hash: [0xAB; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: tx_blobs.len() as u32,
            timestamp: 1234567890,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: tx_blobs,
        signature: vec![],
    }
}

#[test]
fn node_applies_block_and_executes_transactions() {
    let vs = small_validator_set();
    let auth = AuthFixture::new();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();
    auth.seed(&mut store);

    let keyset_id = dummy_account_id(0xEE);
    let tx = build_keyset_create_tx(keyset_id, &auth);
    let proposal = build_proposal_with_txs(&[tx]);

    let outcome = node
        .apply_block(&mut store, &proposal)
        .expect("block apply should succeed");

    assert_eq!(outcome.height, 10);
    assert_eq!(outcome.round, 0);
    assert_eq!(outcome.block_id, [0xAB; 32]);
    assert!(outcome.exec_result.all_succeeded());
    assert!(matches!(
        outcome.vote_decision,
        VoteDecision::ShouldVote {
            height: 10,
            round: 0
        }
    ));

    // Check that the keyset account was created.
    let stored = store.get(&keyset_id).expect("keyset account should exist");
    assert_eq!(stored.header.owner, KEYSET_PROGRAM_ID);

    let mut slice: &[u8] = &stored.data;
    let decoded = KeysetAccount::decode_state(&mut slice).expect("decode KeysetAccount");
    assert!(slice.is_empty());
    assert_eq!(decoded.entries.len(), 1);
}

#[test]
fn node_returns_block_outcome_when_native_transaction_auth_fails() {
    let vs = small_validator_set();
    let auth = AuthFixture::new();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };
    let hs = HotStuffState::new_at_height(10);
    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);
    let mut store = InMemoryAccountStore::new();
    auth.seed(&mut store);

    let target_id = dummy_account_id(0xE1);
    let mut tx = build_keyset_create_tx(target_id, &auth);
    tx.auths.clear();
    let account_witness = [store.get(&AUTH_KEYSET_ID), store.get(&target_id)];
    let proposal = build_proposal_with_txs(&[tx]);
    let proposal_witness = proposal.clone();

    let outcome = node
        .apply_block(&mut store, &proposal)
        .expect("block decoding/application outcome should be returned");

    assert!(
        proposal == proposal_witness,
        "node path changed the complete proposal witness"
    );
    assert_eq!(outcome.exec_result.tx_results.len(), 1);
    assert!(matches!(
        outcome.exec_result.tx_results[0],
        qbind_runtime::TxApplyResult::Failed(ExecutionError::InvalidCallData(
            "transaction requires at least one authentication entry"
        ))
    ));
    let account_state_after = [store.get(&AUTH_KEYSET_ID), store.get(&target_id)];
    assert!(
        account_state_after == account_witness,
        "empty-auth transaction changed the complete account witness"
    );
}

#[test]
fn node_rejects_block_when_tx_count_exceeds_max() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    // Very small max_tx_count to trigger overflow
    let cfg = BlockVerifyConfig { max_tx_count: 1 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();

    // Create proposal with 2 txs, exceeding max_tx_count of 1
    let keyset_id1 = dummy_account_id(0xA1);
    let keyset_id2 = dummy_account_id(0xA2);
    let auth = AuthFixture::new();
    let tx1 = build_keyset_create_tx(keyset_id1, &auth);
    let tx2 = build_keyset_create_tx(keyset_id2, &auth);
    let proposal = build_proposal_with_txs(&[tx1, tx2]);

    let result = node.apply_block(&mut store, &proposal);

    // Should fail with consensus verification error for TxCountOverflow
    assert!(result.is_err());
    match result.unwrap_err() {
        NodeError::Consensus(ConsensusNodeError::Verify(ConsensusVerifyError::TxCountOverflow)) => {
            // expected
        }
        other => panic!("expected TxCountOverflow error, got {:?}", other),
    }

    // Ensure store was not modified
    assert!(store.get(&keyset_id1).is_none());
    assert!(store.get(&keyset_id2).is_none());
}

#[test]
fn node_rejects_block_with_malformed_tx_blob() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();

    // Create a proposal with a malformed tx blob
    let malformed_blob = vec![0xFF, 0xFF, 0xFF]; // garbage bytes

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 10,
            round: 0,
            parent_block_id: [0xCD; 32],
            payload_hash: [0xAB; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 1,
            timestamp: 1234567890,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![malformed_blob],
        signature: vec![],
    };

    let result = node.apply_block(&mut store, &proposal);

    // Should fail with wire decoding error
    assert!(result.is_err());
    match result.unwrap_err() {
        NodeError::Wire(msg) => {
            assert!(
                msg.contains("failed to decode transaction"),
                "expected decode failure, got: {}",
                msg
            );
        }
        other => panic!("expected Wire error, got {:?}", other),
    }
}

#[test]
fn node_rejects_block_with_extra_bytes_after_tx() {
    let vs = small_validator_set();
    let crypto = test_crypto();
    let cfg = BlockVerifyConfig { max_tx_count: 1024 };
    let hs = HotStuffState::new_at_height(10);

    let mut node: Node<InMemoryAccountStore> = Node::new(vs, hs, cfg, crypto);

    let mut store = InMemoryAccountStore::new();

    // Create a valid tx, then append extra bytes
    let keyset_id = dummy_account_id(0xEE);
    let auth = AuthFixture::new();
    let tx = build_keyset_create_tx(keyset_id, &auth);
    let mut blob = Vec::new();
    tx.encode(&mut blob);
    blob.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]); // extra bytes

    let proposal = BlockProposal {
        header: BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 10,
            round: 0,
            parent_block_id: [0xCD; 32],
            payload_hash: [0xAB; 32],
            proposer_index: 0,
            suite_id: qbind_wire::DEFAULT_CONSENSUS_SUITE_ID,
            tx_count: 1,
            timestamp: 1234567890,
            payload_kind: qbind_wire::PAYLOAD_KIND_NORMAL,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        },
        qc: None,
        txs: vec![blob],
        signature: vec![],
    };

    let result = node.apply_block(&mut store, &proposal);

    // Should fail with wire decoding error about extra bytes
    assert!(result.is_err());
    match result.unwrap_err() {
        NodeError::Wire(msg) => {
            assert!(
                msg.contains("extra bytes"),
                "expected extra bytes error, got: {}",
                msg
            );
        }
        other => panic!("expected Wire error, got {:?}", other),
    }
}
