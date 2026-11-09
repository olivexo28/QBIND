//! Synthetic in-memory characterization, not an approved overflow policy.

use std::any::Any;
use std::panic::{catch_unwind, AssertUnwindSafe};

use qbind_ledger::{
    AccountState, AccountStateUpdater, AccountStateView, InMemoryAccountState, QbindTransaction,
    TransferPayload, VmV0Error, VmV0ExecutionEngine,
};

fn fixture(recipient_balance: u128) -> (InMemoryAccountState, [u8; 32], [u8; 32]) {
    let sender = [0x31; 32];
    let recipient = [0x42; 32];
    assert_ne!(sender, recipient);
    let mut state = InMemoryAccountState::new();
    state.set_account_state(&sender, AccountState::new(4, 100));
    state.set_account_state(&recipient, AccountState::new(9, recipient_balance));
    (state, sender, recipient)
}

fn panic_message(payload: &(dyn Any + Send)) -> &str {
    if let Some(message) = payload.downcast_ref::<&str>() {
        message
    } else if let Some(message) = payload.downcast_ref::<String>() {
        message.as_str()
    } else {
        panic!("unexpected non-string panic payload");
    }
}

#[test]
fn recipient_overflow_observes_partial_sender_update_and_panic_or_wrap() {
    assert!(cfg!(panic = "unwind"), "this harness requires unwind");
    let engine = VmV0ExecutionEngine::new();
    assert!(!engine.is_gas_enabled());
    // Measure arithmetic behavior in this build independently of its profile name.
    let arithmetic = catch_unwind(|| std::hint::black_box(u128::MAX) + std::hint::black_box(1u128));
    let overflow_checks_observed = match arithmetic {
        Ok(value) => {
            assert_eq!(value, 0);
            false
        }
        Err(payload) => {
            assert_eq!(
                panic_message(payload.as_ref()),
                "attempt to add with overflow"
            );
            true
        }
    };
    let (mut state, sender, recipient) = fixture(u128::MAX);
    let tx = QbindTransaction::new(sender, 4, TransferPayload::new(recipient, 1).encode());
    let outcome = catch_unwind(AssertUnwindSafe(|| engine.execute_tx(&mut state, &tx)));
    let sender_after = state.get_account_state(&sender);
    let recipient_after = state.get_account_state(&recipient);
    println!(
        "gas_enabled={} debug_assertions={} panic_unwind={} arithmetic_overflow_checks_observed={} sender_after={sender_after:?} recipient_after={recipient_after:?}",
        engine.is_gas_enabled(),
        cfg!(debug_assertions),
        cfg!(panic = "unwind"),
        overflow_checks_observed,
    );
    assert_eq!(sender_after, AccountState::new(5, 99));
    match outcome {
        Err(payload) => {
            let message = panic_message(payload.as_ref());
            println!("engine_outcome=panic message={message:?}");
            assert!(overflow_checks_observed);
            assert_eq!(message, "attempt to add with overflow");
            assert_eq!(recipient_after, AccountState::new(9, u128::MAX));
        }
        Ok(result) => {
            println!("engine_outcome=returned result={result:?}");
            assert!(!overflow_checks_observed);
            assert!(result.success);
            assert!(result.error.is_none());
            assert_eq!(recipient_after, AccountState::new(9, 0));
        }
    }
}

#[test]
fn positive_control_returns_success_and_updates_both_accounts() {
    let engine = VmV0ExecutionEngine::new();
    assert!(!engine.is_gas_enabled());
    let (mut state, sender, recipient) = fixture(20);
    let tx = QbindTransaction::new(sender, 4, TransferPayload::new(recipient, 1).encode());
    let result = engine.execute_tx(&mut state, &tx);
    let sender_after = state.get_account_state(&sender);
    let recipient_after = state.get_account_state(&recipient);
    println!("positive result={result:?} sender_after={sender_after:?} recipient_after={recipient_after:?}");
    assert!(result.success);
    assert!(result.error.is_none());
    assert_eq!(sender_after, AccountState::new(5, 99));
    assert_eq!(recipient_after, AccountState::new(9, 21));
}

#[test]
fn nonce_refusal_control_returns_error_without_mutating_either_account() {
    let engine = VmV0ExecutionEngine::new();
    assert!(!engine.is_gas_enabled());
    let (mut state, sender, recipient) = fixture(u128::MAX);
    let tx = QbindTransaction::new(sender, 3, TransferPayload::new(recipient, 1).encode());
    let result = engine.execute_tx(&mut state, &tx);
    let sender_after = state.get_account_state(&sender);
    let recipient_after = state.get_account_state(&recipient);
    println!("validation_refusal result={result:?} sender_after={sender_after:?} recipient_after={recipient_after:?}");
    assert!(!result.success);
    assert_eq!(
        result.error,
        Some(VmV0Error::NonceMismatch {
            expected: 4,
            got: 3,
        })
    );
    assert_eq!(sender_after, AccountState::new(4, 100));
    assert_eq!(recipient_after, AccountState::new(9, u128::MAX));
}
