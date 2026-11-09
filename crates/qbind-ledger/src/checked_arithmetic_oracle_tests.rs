//! Proposed test assumptions; current production arithmetic is intentionally not corrected.
//! A test-contract decision does not authorize production behavior, transition, activation or deployment.

use super::{execute_block_stage_b, execute_tx_on_stage_b_state, StageBPerAccountState};
use crate::{
    AccountState, AccountStateUpdater, AccountStateView, InMemoryAccountState, QbindTransaction,
    TransferPayload, VmV0Error, VmV0ExecutionEngine, VmV0TxResult,
};
use std::panic::{catch_unwind, AssertUnwindSafe};

const A: [u8; 32] = [0x51; 32];
const B: [u8; 32] = [0x62; 32];

#[derive(Clone, Debug)]
struct Case {
    sender: AccountState,
    recipient: Option<AccountState>,
    amount: u128,
    nonce: u64,
    alias: bool,
    malformed: bool,
    error: Option<VmV0Error>,
}

impl Case {
    fn normal() -> Self {
        Self {
            sender: AccountState::new(4, 100),
            recipient: Some(AccountState::new(9, 20)),
            amount: 1,
            nonce: 4,
            alias: false,
            malformed: false,
            error: None,
        }
    }

    fn fixture(&self) -> (InMemoryAccountState, QbindTransaction) {
        let mut state = InMemoryAccountState::new();
        state.set_account_state(&A, self.sender.clone());
        if !self.alias {
            if let Some(recipient) = &self.recipient {
                state.set_account_state(&B, recipient.clone());
            }
        }
        let payload = if self.malformed {
            vec![0xff]
        } else {
            TransferPayload::new(if self.alias { A } else { B }, self.amount).encode()
        };
        (state, QbindTransaction::new(A, self.nonce, payload))
    }

    fn expected(&self) -> Observation {
        let (mut state, _) = self.fixture();
        let mut writes = Vec::new();
        let result = if let Some(error) = &self.error {
            VmV0TxResult::failure(error.clone())
        } else {
            let sender =
                AccountState::new(self.sender.nonce + 1, self.sender.balance - self.amount);
            writes.push((A, sender.clone()));
            state.set_account_state(&A, sender.clone());
            let recipient_id = if self.alias { A } else { B };
            let previous = state.get_account_state(&recipient_id);
            let recipient = AccountState::new(previous.nonce, previous.balance + self.amount);
            writes.push((recipient_id, recipient.clone()));
            state.set_account_state(&recipient_id, recipient);
            VmV0TxResult::success()
        };
        Observation {
            result: Some(result),
            panic: None,
            state: Some(entries(&state)),
            writes: Some(writes),
        }
    }
}

type Entries = Vec<([u8; 32], AccountState)>;

fn entries(state: &InMemoryAccountState) -> Entries {
    let mut values: Entries = state
        .iter()
        .map(|(id, value)| (*id, value.clone()))
        .collect();
    values.sort_by_key(|(id, _)| *id);
    values
}

#[derive(Debug)]
struct Observation {
    result: Option<VmV0TxResult>,
    panic: Option<String>,
    state: Option<Entries>,
    writes: Option<Entries>,
}

fn outcome(result: std::thread::Result<VmV0TxResult>) -> (Option<VmV0TxResult>, Option<String>) {
    match result {
        Ok(result) => (Some(result), None),
        Err(payload) => {
            let message = payload
                .downcast_ref::<&str>()
                .map(|s| s.to_string())
                .or_else(|| payload.downcast_ref::<String>().cloned())
                .unwrap_or_else(|| "<non-string panic>".into());
            (None, Some(message))
        }
    }
}

struct ObservingState {
    state: InMemoryAccountState,
    writes: Entries,
}

impl AccountStateView for ObservingState {
    fn get_account_state(&self, id: &[u8; 32]) -> AccountState {
        self.state.get_account_state(id)
    }
}

impl AccountStateUpdater for ObservingState {
    fn set_account_state(&mut self, id: &[u8; 32], state: AccountState) {
        self.writes.push((*id, state.clone()));
        self.state.set_account_state(id, state);
    }
}

fn observe(case: &Case, path: &str) -> Observation {
    assert!(cfg!(panic = "unwind"), "unsupported panic strategy");
    let (state, tx) = case.fixture();
    match path {
        "sequential_transaction" => {
            let mut observed = ObservingState {
                state,
                writes: Vec::new(),
            };
            let engine = VmV0ExecutionEngine::new();
            assert!(!engine.is_gas_enabled());
            let (result, panic) = outcome(catch_unwind(AssertUnwindSafe(|| {
                engine.execute_tx(&mut observed, &tx)
            })));
            Observation {
                result,
                panic,
                state: Some(entries(&observed.state)),
                writes: Some(observed.writes),
            }
        }
        "stage_b_internal_transaction" => {
            let observed = StageBPerAccountState::from_in_memory(&state);
            let (result, panic) = outcome(catch_unwind(AssertUnwindSafe(|| {
                execute_tx_on_stage_b_state(&observed, &tx)
            })));
            let writes = observed.oracle_writes.lock().unwrap().clone();
            Observation {
                result,
                panic,
                state: Some(entries(&observed.to_in_memory())),
                writes: Some(writes),
            }
        }
        "direct_stage_b_api" => {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(2)
                .build()
                .expect("pool creation");
            let returned = catch_unwind(AssertUnwindSafe(|| {
                pool.install(|| execute_block_stage_b(&[tx], &state))
            }));
            drop(pool);
            match returned {
                Ok((mut results, state, stats)) => {
                    assert_eq!(results.len(), 1);
                    println!("direct_stage_b_stats={stats:?}");
                    Observation {
                        result: Some(results.remove(0)),
                        panic: None,
                        state: Some(entries(&state)),
                        writes: None,
                    }
                }
                Err(payload) => {
                    let (_, panic) = outcome(Err(payload));
                    Observation {
                        result: None,
                        panic,
                        state: None,
                        writes: None,
                    }
                }
            }
        }
        _ => panic!("unknown path"),
    }
}

fn oracle(case: &Case, actual: &Observation, require_writes: bool) -> Result<(), String> {
    let expected = case.expected();
    let mut failures = Vec::new();
    if actual.panic.is_some() {
        failures.push("panic is not arithmetic refusal");
    }
    match (&actual.result, &expected.result) {
        (Some(actual), Some(expected))
            if actual.success == expected.success && actual.error == expected.error => {}
        _ => failures.push("wrong result/error/precedence"),
    }
    if actual.state != expected.state {
        failures.push("wrong account values or membership");
    }
    if require_writes && actual.writes != expected.writes {
        failures.push("wrong transaction updater calls/order/values");
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

fn run(case: Case, path: &str) {
    let actual = observe(&case, path);
    println!(
        "path={path} debug_assertions={} unwind={} case={case:?} observed={actual:?}",
        cfg!(debug_assertions),
        cfg!(panic = "unwind")
    );
    let result = oracle(&case, &actual, path != "direct_stage_b_api");
    assert!(
        result.is_ok(),
        "CONFORMANCE FAILURE: {}",
        result.unwrap_err()
    );
}

macro_rules! cases {
    ($name:ident, $case:expr) => {
        mod $name {
            use super::*;
            #[test]
            fn sequential_transaction() {
                run($case, "sequential_transaction");
            }
            #[test]
            fn stage_b_internal_transaction() {
                run($case, "stage_b_internal_transaction");
            }
            #[test]
            fn direct_stage_b_api() {
                run($case, "direct_stage_b_api");
            }
        }
    };
}

fn nonce_overflow() -> Case {
    Case {
        sender: AccountState::new(u64::MAX, 100),
        nonce: u64::MAX,
        error: Some(VmV0Error::ArithmeticOverflow {
            operation: "nonce increment",
        }),
        ..Case::normal()
    }
}

fn recipient_overflow() -> Case {
    Case {
        recipient: Some(AccountState::new(9, u128::MAX)),
        error: Some(VmV0Error::ArithmeticOverflow {
            operation: "recipient balance increment",
        }),
        ..Case::normal()
    }
}

cases!(nonce_increment_overflow, nonce_overflow());
cases!(recipient_balance_overflow, recipient_overflow());
cases!(
    simultaneous_overflow,
    Case {
        recipient: Some(AccountState::new(9, u128::MAX)),
        ..nonce_overflow()
    }
);
cases!(
    malformed_precedence,
    Case {
        malformed: true,
        nonce: 0,
        amount: 101,
        error: Some(VmV0Error::MalformedPayload),
        ..nonce_overflow()
    }
);
cases!(
    nonce_precedence,
    Case {
        nonce: 3,
        amount: 101,
        error: Some(VmV0Error::NonceMismatch {
            expected: 4,
            got: 3
        }),
        ..recipient_overflow()
    }
);
cases!(
    balance_precedence,
    Case {
        amount: 101,
        error: Some(VmV0Error::InsufficientBalance {
            balance: 100,
            needed: 101
        }),
        ..nonce_overflow()
    }
);
cases!(
    maximum_self_transfer,
    Case {
        alias: true,
        sender: AccountState::new(4, u128::MAX),
        ..Case::normal()
    }
);
cases!(
    ordinary_self_transfer,
    Case {
        alias: true,
        ..Case::normal()
    }
);
cases!(
    self_transfer_balance_refusal,
    Case {
        alias: true,
        amount: 101,
        error: Some(VmV0Error::InsufficientBalance {
            balance: 100,
            needed: 101
        }),
        ..Case::normal()
    }
);
cases!(
    zero_existing_recipient,
    Case {
        amount: 0,
        recipient: Some(AccountState::new(9, u128::MAX)),
        ..Case::normal()
    }
);
cases!(
    zero_absent_recipient,
    Case {
        amount: 0,
        recipient: None,
        ..Case::normal()
    }
);
cases!(
    zero_self_transfer,
    Case {
        alias: true,
        amount: 0,
        ..Case::normal()
    }
);
cases!(
    valid_boundary,
    Case {
        sender: AccountState::new(u64::MAX - 1, u128::MAX),
        nonce: u64::MAX - 1,
        recipient: Some(AccountState::new(9, u128::MAX - 1)),
        ..Case::normal()
    }
);
cases!(
    maximum_amount,
    Case {
        sender: AccountState::new(4, u128::MAX),
        amount: u128::MAX,
        recipient: None,
        ..Case::normal()
    }
);
cases!(ordinary_transfer, Case::normal());

#[test]
fn runtime_build_probe() {
    assert!(cfg!(panic = "unwind"));
    let result = catch_unwind(|| std::hint::black_box(u128::MAX) + std::hint::black_box(1u128));
    match result {
        Ok(value) => {
            assert_eq!(value, 0);
            println!(
                "overflow_probe=wrapped debug_assertions={}",
                cfg!(debug_assertions)
            );
        }
        Err(payload) => {
            let (_, message) = outcome(Err(payload));
            assert_eq!(message.as_deref(), Some("attempt to add with overflow"));
            println!(
                "overflow_probe=panicked debug_assertions={}",
                cfg!(debug_assertions)
            );
        }
    }
}

#[test]
fn same_oracle_rejects_synthetic_bypass_and_reordering_controls() {
    let case = recipient_overflow();
    let mut changed = case.expected();
    assert!(oracle(&case, &changed, true).is_ok());
    changed.result = Some(VmV0TxResult::success());
    assert!(
        oracle(&case, &changed, true).is_err(),
        "unchecked-success bypass escaped"
    );
    let mut changed = case.expected();
    changed.writes = Some(vec![(A, case.sender.clone())]);
    assert!(
        oracle(&case, &changed, true).is_err(),
        "single-write nonempty trace with unchanged final state escaped"
    );
    let both = Case {
        recipient: Some(AccountState::new(9, u128::MAX)),
        ..nonce_overflow()
    };
    let mut changed = both.expected();
    changed.result = case.expected().result;
    assert!(
        oracle(&both, &changed, true).is_err(),
        "arithmetic reordering escaped"
    );
    let precedence = Case {
        amount: 101,
        error: Some(VmV0Error::InsufficientBalance {
            balance: 100,
            needed: 101,
        }),
        ..nonce_overflow()
    };
    let mut changed = precedence.expected();
    changed.result = nonce_overflow().expected().result;
    assert!(
        oracle(&precedence, &changed, true).is_err(),
        "validation reordering escaped"
    );
    let alias = Case {
        alias: true,
        ..Case::normal()
    };
    let mut changed = alias.expected();
    changed.writes.as_mut().unwrap().remove(0);
    assert!(
        oracle(&alias, &changed, true).is_err(),
        "single-write alias escaped"
    );
    let zero = Case {
        amount: 0,
        recipient: None,
        ..Case::normal()
    };
    let mut changed = zero.expected();
    changed.state.as_mut().unwrap().retain(|(id, _)| *id != B);
    assert!(
        oracle(&zero, &changed, true).is_err(),
        "missing materialization escaped"
    );
    println!("synthetic same-oracle controls rejected: unchecked success, single-write nonempty trace with unchanged final state, arithmetic/validation reordering, one-write alias, missing materialization");
}
