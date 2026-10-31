use qbind_hash::tx::{try_tx_digest_streaming, TxDigestError};
use qbind_hash::{tx_digest, tx_sign_body_preimage};
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};
use sha3::{Digest, Sha3_256};

fn make_test_transaction() -> Transaction {
    Transaction {
        version: 1,
        chain_id: 42,
        payer: [1; 32],
        nonce: 7,
        fee_limit: 1000,
        accounts: vec![TxAccountMeta {
            account_id: [0x22; 32],
            flags: 0b00000011,       // is_signer + is_writable
            access_hint: 0b00000011, // may_read + may_write
            reserved0: [0, 0],
        }],
        program_id: [0x44; 32],
        call_data: vec![0xAA, 0xBB],
        auths: vec![],
    }
}

#[test]
fn tx_sign_body_preimage_is_stable() {
    let tx = make_test_transaction();
    let preimage1 = tx_sign_body_preimage(&tx);
    let preimage2 = tx_sign_body_preimage(&tx);
    assert_eq!(preimage1, preimage2);
}

#[test]
fn tx_digest_is_stable() {
    let tx = make_test_transaction();
    let digest1 = tx_digest(&tx);
    let digest2 = tx_digest(&tx);
    assert_eq!(digest1, digest2);
}

#[test]
fn tx_digest_changes_with_nonce() {
    let tx1 = make_test_transaction();
    let mut tx2 = make_test_transaction();
    tx2.nonce = 8;

    let digest1 = tx_digest(&tx1);
    let digest2 = tx_digest(&tx2);
    assert_ne!(digest1, digest2);
}

#[test]
fn tx_digest_ignores_auths() {
    let tx1 = make_test_transaction();
    let mut tx2 = make_test_transaction();
    tx2.auths = vec![TxAuth {
        account_index: 0,
        suite_id: 1,
        reserved: 0,
        signature: vec![0xCC, 0xDD, 0xEE],
    }];

    // Digest should be the same since auths are NOT part of the sign body
    let digest1 = tx_digest(&tx1);
    let digest2 = tx_digest(&tx2);
    assert_eq!(digest1, digest2);
}

fn run422_transaction() -> Transaction {
    Transaction {
        version: 0x7b,
        chain_id: 0x1234_5678,
        payer: std::array::from_fn(|index| index as u8),
        nonce: 0x0102_0304_0506_0708,
        fee_limit: 0x1122_3344_5566_7788,
        accounts: vec![
            TxAccountMeta {
                account_id: std::array::from_fn(|index| 0xa0 + index as u8),
                flags: 0x91,
                access_hint: 0x42,
                reserved0: [0xfe, 0x7d],
            },
            TxAccountMeta {
                account_id: std::array::from_fn(|index| 0x20 + index as u8),
                flags: 0x35,
                access_hint: 0xc6,
                reserved0: [0x81, 0x02],
            },
        ],
        program_id: std::array::from_fn(|index| 0x80 + index as u8),
        call_data: vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0x7f, 0x80],
        auths: Vec::new(),
    }
}

fn assert_matches_legacy_oracle(tx: &Transaction) {
    let preimage = tx_sign_body_preimage(tx);
    let mut hasher = Sha3_256::new();
    hasher.update(b"QBIND:TX");
    hasher.update(&preimage);
    let independent_preimage_digest: [u8; 32] = hasher.finalize().into();
    assert_eq!(try_tx_digest_streaming(tx).unwrap(), tx_digest(tx));
    assert_eq!(
        try_tx_digest_streaming(tx).unwrap(),
        independent_preimage_digest
    );
}

#[test]
fn run422_native_tx_streaming_exact_legacy_and_independent_preimage_equivalence() {
    let mut tx = run422_transaction();
    let original = tx.clone();
    assert_matches_legacy_oracle(&tx);
    tx.accounts[0].flags ^= 0x08;
    tx.call_data.extend_from_slice(&[0x11, 0x22, 0x33]);
    assert_matches_legacy_oracle(&tx);
    assert_eq!(tx, {
        let mut expected = original;
        expected.accounts[0].flags ^= 0x08;
        expected.call_data.extend_from_slice(&[0x11, 0x22, 0x33]);
        expected
    });
}

#[test]
fn run422_native_tx_streaming_known_answer_vector() {
    let tx = run422_transaction();
    let digest = try_tx_digest_streaming(&tx).unwrap();
    let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
    assert_eq!(
        hex,
        "5a36873207138c6e4da783aee0bd6d07e7b0c5e46dd96117aa832b31049ed61a"
    );
    assert_matches_legacy_oracle(&tx);
}

#[test]
fn run422_native_tx_streaming_every_signed_field_affects_digest() {
    let base = run422_transaction();
    let base_digest = try_tx_digest_streaming(&base).unwrap();

    let mut changed = Vec::new();
    let mut tx = base.clone();
    tx.version ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.chain_id ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.payer[0] ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.nonce ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.fee_limit ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.accounts[0].account_id[0] ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.accounts[0].flags ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.accounts[0].access_hint ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.accounts[0].reserved0[0] ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.accounts[0].reserved0[1] ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.accounts.swap(0, 1);
    changed.push(tx);
    let mut tx = base.clone();
    tx.accounts.pop();
    changed.push(tx);
    let mut tx = base.clone();
    tx.program_id[0] ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.call_data[0] ^= 1;
    changed.push(tx);
    let mut tx = base.clone();
    tx.call_data.push(0);
    changed.push(tx);

    for changed_tx in changed {
        assert_ne!(try_tx_digest_streaming(&changed_tx).unwrap(), base_digest);
        assert_matches_legacy_oracle(&changed_tx);
    }
}

#[test]
fn run422_native_tx_streaming_empty_fields_and_sha3_block_boundaries() {
    let mut tx = run422_transaction();
    tx.accounts.clear();
    tx.call_data.clear();
    tx.auths.clear();
    let original = tx.clone();
    let empty_digest = try_tx_digest_streaming(&tx).unwrap();
    assert_matches_legacy_oracle(&tx);
    assert_eq!(tx, original);

    for (call_length, absorbed_length) in [(36, 135), (37, 136), (38, 137), (4097, 4196)] {
        tx.call_data = (0..call_length).map(|index| (index % 251) as u8).collect();
        assert_eq!(99 + tx.call_data.len(), absorbed_length);
        assert_matches_legacy_oracle(&tx);
    }
    assert_ne!(empty_digest, try_tx_digest_streaming(&tx).unwrap());
}

#[test]
fn run422_native_tx_streaming_authentication_is_excluded_without_validation() {
    let mut tx = run422_transaction();
    tx.accounts.clear();
    tx.call_data.clear();
    let original_digest = try_tx_digest_streaming(&tx).unwrap();
    assert!(tx.auths.is_empty());

    let auth_a = TxAuth {
        account_index: u16::MAX,
        suite_id: 0xfe,
        reserved: 0xa5,
        signature: vec![0xff, 0x00, 0x80],
    };
    let auth_b = TxAuth {
        account_index: 42,
        suite_id: 0,
        reserved: 0xff,
        signature: vec![1, 2, 3, 4],
    };
    tx.auths = vec![auth_a.clone(), auth_b.clone()];
    assert_eq!(try_tx_digest_streaming(&tx).unwrap(), original_digest);
    tx.auths.reverse();
    assert_eq!(try_tx_digest_streaming(&tx).unwrap(), original_digest);
    tx.auths[0].signature.push(5);
    tx.auths[0].account_index = 0;
    tx.auths[0].suite_id ^= 0xff;
    tx.auths[0].reserved ^= 0xff;
    assert_eq!(try_tx_digest_streaming(&tx).unwrap(), original_digest);
    tx.auths.pop();
    assert_eq!(try_tx_digest_streaming(&tx).unwrap(), original_digest);
    tx.auths.clear();
    assert_eq!(try_tx_digest_streaming(&tx).unwrap(), original_digest);
}

#[test]
fn run422_native_tx_streaming_accepts_maximum_account_count_and_preserves_input() {
    let mut tx = run422_transaction();
    tx.accounts = (0..u16::MAX)
        .map(|index| TxAccountMeta {
            account_id: [index as u8; 32],
            flags: index as u8,
            access_hint: (index >> 8) as u8,
            reserved0: [0x5a, 0xa5],
        })
        .collect();
    tx.call_data.clear();
    let original = tx.clone();

    let digest = try_tx_digest_streaming(&tx).unwrap();
    assert_eq!(digest, try_tx_digest_streaming(&tx).unwrap());
    assert_eq!(tx, original);
}

#[test]
fn run422_native_tx_streaming_public_account_overflow_refuses_without_mutation() {
    let mut tx = run422_transaction();
    tx.accounts = (0..=u16::MAX)
        .map(|index| TxAccountMeta {
            account_id: [index as u8; 32],
            flags: index as u8,
            access_hint: (index >> 8) as u8,
            reserved0: [0x3c, 0xc3],
        })
        .collect();
    tx.auths = vec![TxAuth {
        account_index: u16::MAX,
        suite_id: 0xf1,
        reserved: 0x9d,
        signature: vec![0, 0xff, 0x80, 0x7f],
    }];
    let original = tx.clone();

    assert_eq!(
        try_tx_digest_streaming(&tx),
        Err(TxDigestError::AccountCountTooLarge)
    );
    assert_eq!(tx, original);
}

#[test]
fn run422_native_tx_streaming_repeated_success_preserves_complete_transaction() {
    let mut tx = run422_transaction();
    tx.auths = vec![TxAuth {
        account_index: u16::MAX,
        suite_id: 0xfe,
        reserved: 0xa5,
        signature: vec![0x00, 0xff, 0x80, 0x7f],
    }];
    let original = tx.clone();
    let first = try_tx_digest_streaming(&tx).unwrap();
    let second = try_tx_digest_streaming(&tx).unwrap();
    assert_eq!(first, second);
    assert_eq!(tx, original);
}
