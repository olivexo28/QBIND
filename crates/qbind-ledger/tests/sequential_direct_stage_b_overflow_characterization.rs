//! Direct synthetic API observations, not an approved arithmetic contract.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

use qbind_ledger::{
    execute_block_stage_b, AccountState, AccountStateUpdater, AccountStateView,
    InMemoryAccountState, QbindTransaction, TransferPayload, VmV0Error, VmV0ExecutionEngine,
};

const ACCOUNTS: [[u8; 32]; 4] = [[0x11; 32], [0x22; 32], [0x33; 32], [0x44; 32]];

fn snapshot(state: &InMemoryAccountState) -> Vec<AccountState> {
    ACCOUNTS
        .iter()
        .map(|account| state.get_account_state(account))
        .collect()
}

fn fixture(
    recipient_balance: u128,
    first_nonce: u64,
) -> (InMemoryAccountState, Vec<QbindTransaction>) {
    let mut state = InMemoryAccountState::new();
    for (account, value) in ACCOUNTS.iter().zip([
        AccountState::new(4, 100),
        AccountState::new(9, recipient_balance),
        AccountState::new(2, 50),
        AccountState::new(7, 20),
    ]) {
        state.set_account_state(account, value);
    }
    let txs = vec![
        QbindTransaction::new(
            ACCOUNTS[0],
            first_nonce,
            TransferPayload::new(ACCOUNTS[1], 1).encode(),
        ),
        QbindTransaction::new(
            ACCOUNTS[2],
            2,
            TransferPayload::new(ACCOUNTS[3], 3).encode(),
        ),
    ];
    (state, txs)
}

fn overflow_message(payload: &(dyn Any + Send)) -> &str {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .expect("unexpected non-string panic");
    assert_eq!(message, "attempt to add with overflow", "unexpected panic");
    message
}

fn characterize(label: &str, recipient_balance: u128, nonce: u64) {
    assert!(cfg!(panic = "unwind"), "unsupported: requires unwind");
    let overflow_checks =
        match catch_unwind(|| std::hint::black_box(u128::MAX) + std::hint::black_box(1u128)) {
            Ok(value) => {
                assert_eq!(value, 0);
                false
            }
            Err(payload) => {
                overflow_message(payload.as_ref());
                true
            }
        };
    println!(
        "case={label} debug_assertions={} panic_unwind={} overflow_checks_observed={overflow_checks}",
        cfg!(debug_assertions),
        cfg!(panic = "unwind")
    );
    let (initial, txs) = fixture(recipient_balance, nonce);
    println!("initial={:?} transactions={txs:?}", snapshot(&initial));
    let engine = VmV0ExecutionEngine::new();
    assert!(!engine.is_gas_enabled());
    let mut sequential_state = initial.clone();
    let sequential = catch_unwind(AssertUnwindSafe(|| {
        engine.execute_block(&mut sequential_state, &txs)
    }));
    match &sequential {
        Ok(results) => println!(
            "path=sequential outcome=returned results={results:?} final={:?}",
            snapshot(&sequential_state)
        ),
        Err(payload) => println!(
            "path=sequential outcome=panic message={:?} results=unavailable caller_owned_state={:?}",
            overflow_message(payload.as_ref()),
            snapshot(&sequential_state)
        ),
    }

    // A dedicated pool bounds worker ownership; install completes before pool drop.
    let pool = rayon::ThreadPoolBuilder::new()
        .num_threads(2)
        .build()
        .expect("Rayon pool creation failed");
    let stage_b = catch_unwind(AssertUnwindSafe(|| {
        pool.install(|| execute_block_stage_b(&txs, &initial))
    }));
    drop(pool);
    match &stage_b {
        Ok((results, state, stats)) => println!(
            "path=direct_stage_b outcome=returned results={results:?} final={:?} stats={stats:?}",
            snapshot(state)
        ),
        Err(payload) => println!(
            "path=direct_stage_b outcome=panic message={:?} results=unavailable final_state=unavailable",
            overflow_message(payload.as_ref())
        ),
    }
    assert_eq!(
        snapshot(&initial),
        snapshot(&fixture(recipient_balance, nonce).0)
    );

    let is_overflow_case = nonce == 4 && recipient_balance == u128::MAX;
    if is_overflow_case && overflow_checks {
        let payload = sequential.expect_err("sequential must expose checked overflow");
        overflow_message(payload.as_ref());
        assert_eq!(
            snapshot(&sequential_state),
            vec![
                AccountState::new(5, 99),
                AccountState::new(9, u128::MAX),
                AccountState::new(2, 50),
                AccountState::new(7, 20),
            ]
        );
        let payload = stage_b.expect_err("direct Stage B must expose checked overflow");
        overflow_message(payload.as_ref());
        println!("comparison=both_panicked stage_b_internal_state_not_observable");
        return;
    }

    let sequential_results = sequential.expect("unexpected sequential panic");
    let (stage_b_results, stage_b_state, stats) = stage_b.expect("unexpected Stage B panic");
    assert_eq!(stats.tx_count, 2);
    for (path, results, state) in [
        ("sequential", sequential_results, &sequential_state),
        ("direct_stage_b", stage_b_results, &stage_b_state),
    ] {
        assert_eq!(results.len(), 2, "{path}");
        assert!(results[1].success && results[1].error.is_none(), "{path}");
        let first = if nonce == 3 {
            assert!(!results[0].success, "{path}");
            assert_eq!(
                results[0].error,
                Some(VmV0Error::NonceMismatch {
                    expected: 4,
                    got: 3
                }),
                "{path}"
            );
            vec![
                AccountState::new(4, 100),
                AccountState::new(9, recipient_balance),
            ]
        } else {
            assert!(results[0].success && results[0].error.is_none(), "{path}");
            let credit = if is_overflow_case {
                0
            } else {
                recipient_balance + 1
            };
            vec![AccountState::new(5, 99), AccountState::new(9, credit)]
        };
        let mut expected = first;
        expected.extend([AccountState::new(3, 47), AccountState::new(7, 23)]);
        assert_eq!(snapshot(state), expected, "{path}");
    }
    println!("comparison=independent_oracles_passed");
}

#[test]
fn two_transaction_recipient_overflow() {
    characterize("overflow", u128::MAX, 4);
}

#[test]
fn two_transaction_positive_control() {
    characterize("positive", 20, 4);
}

#[test]
fn nonce_refusal_with_separate_success_control() {
    characterize("nonce_refusal", u128::MAX, 3);
}
