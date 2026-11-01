use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use qbind_crypto::{CryptoProvider, StaticCryptoProvider};
use qbind_ledger::{Account, AccountStore, ExecutionContext, ExecutionError, Program};
use qbind_serde::StateEncode;
use qbind_system::governance_program::{
    GOVERNANCE_PROGRAM_ID, LAUNCH_CHECKLIST_ACCOUNT_ID, PARAM_REGISTRY_ACCOUNT_ID,
    SUITE_REGISTRY_ACCOUNT_ID,
};
use qbind_system::GovernanceProgram;
use qbind_types::{
    AccountId, Hash32, LaunchChecklist, MainnetStatus, ParamRegistry, ProgramId, SecurityCategory,
    SuiteEntry, SuiteFamily, SuiteRegistry, SuiteStatus, SuiteTier,
};
use qbind_wire::gov::{
    GovSetMainnetStatusCall, GovUpdateLaunchChecklistCall, GovUpdateParamRegistryCall,
    GovUpdateSuiteStatusCall, OP_GOV_SET_MAINNET_STATUS, OP_GOV_UPDATE_LAUNCH_CHECKLIST,
    OP_GOV_UPDATE_PARAM_REGISTRY, OP_GOV_UPDATE_SUITE_STATUS,
};
use qbind_wire::io::WireEncode;
use qbind_wire::tx::Transaction;

fn zero_hash() -> Hash32 {
    [0u8; 32]
}

fn dummy_account_id(byte: u8) -> AccountId {
    [byte; 32]
}

fn empty_crypto() -> Arc<dyn CryptoProvider> {
    Arc::new(StaticCryptoProvider::new())
}

fn base_tx(program_id: ProgramId, call_data: Vec<u8>) -> Transaction {
    Transaction {
        version: 1,
        chain_id: 1,
        payer: dummy_account_id(0x01),
        nonce: 1,
        fee_limit: 1_000_000,
        accounts: Vec::new(), // not enforced yet
        program_id,
        call_data,
        auths: Vec::new(),
    }
}

#[derive(Default, Debug, PartialEq, Eq)]
struct StoreEvents {
    reads: Vec<AccountId>,
    writes: Vec<AccountId>,
    deletes: Vec<AccountId>,
}

#[derive(Default)]
struct WitnessStore {
    accounts: HashMap<AccountId, Account>,
    events: RefCell<StoreEvents>,
}

impl WitnessStore {
    fn clear_events(&mut self) {
        *self.events.get_mut() = StoreEvents::default();
    }

    fn take_events(&mut self) -> StoreEvents {
        std::mem::take(self.events.get_mut())
    }
}

impl AccountStore for WitnessStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.events.borrow_mut().reads.push(*id);
        self.accounts.get(id).cloned()
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.events.get_mut().writes.push(account.id);
        self.accounts.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.events.get_mut().deletes.push(*id);
        self.accounts.remove(id);
        Ok(())
    }
}

fn assert_direct_refusal(store: &mut WitnessStore, tx: &Transaction) {
    let before = store.accounts.clone();
    store.clear_events();
    let result = {
        let mut ctx = ExecutionContext::new(store, empty_crypto());
        GovernanceProgram::new().execute(&mut ctx, tx)
    };
    match result {
        Err(ExecutionError::ProgramError("native governance authority unavailable")) => {}
        other => panic!("expected native governance authority refusal, got {other:?}"),
    }
    assert_eq!(store.accounts, before);
    assert_eq!(store.take_events(), StoreEvents::default());
}

#[test]
fn gov_update_suite_status_refuses_without_reading_target() {
    // Prepare a SuiteRegistry account with two entries.
    let e1 = SuiteEntry {
        suite_id: 0x01,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat3,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };
    let e2 = SuiteEntry {
        suite_id: 0x02,
        family: SuiteFamily::Lattice,
        category: SecurityCategory::Cat5,
        tier: SuiteTier::Core,
        status: SuiteStatus::Active,
        reserved0: [0u8; 3],
        params_hash: zero_hash(),
        ext_len: 0,
        ext_bytes: Vec::new(),
    };
    let registry = SuiteRegistry {
        version: 1,
        reserved0: [0u8; 3],
        suite_count: 2,
        reserved1: 0,
        suites: vec![e1, e2],
    };

    let mut data = Vec::new();
    registry.encode_state(&mut data);

    let suite_account = Account::new(SUITE_REGISTRY_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = WitnessStore::default();
    store.put(suite_account).unwrap();

    // Build call to set suite_id 0x01 to Disabled (2).
    let call = GovUpdateSuiteStatusCall {
        version: 1,
        suite_id: 0x01,
        new_status: 2, // Disabled
        proposal_id: 42,
        eta_height: 1000,
    };
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_UPDATE_SUITE_STATUS);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    assert_direct_refusal(&mut store, &tx);
}

#[test]
fn gov_update_param_registry_refuses_without_reading_target() {
    // Prepare ParamRegistry account.
    let params = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 10,
        slash_bps_precommit: 20,
        reporter_reward_bps: 5,
        reserved1: 0,
        min_validator_stake: 0,
        slashing_schedule: None,
    };

    let mut data = Vec::new();
    params.encode_state(&mut data);
    let param_account = Account::new(PARAM_REGISTRY_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = WitnessStore::default();
    store.put(param_account).unwrap();

    let call = GovUpdateParamRegistryCall {
        version: 1,
        proposal_id: 7,
        eta_height: 2000,
        slash_bps_prevote: 100,
        slash_bps_precommit: 200,
        reporter_reward_bps: 50,
    };
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_UPDATE_PARAM_REGISTRY);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    assert_direct_refusal(&mut store, &tx);
}

#[test]
fn gov_update_launch_checklist_refuses_without_reading_target() {
    // Prepare LaunchChecklist account with defaults.
    let checklist = LaunchChecklist {
        version: 1,
        reserved0: [0u8; 3],
        devnet_ok: false,
        testnet_ok: false,
        perf_ok: false,
        adversarial_ok: false,
        crypto_audit_ok: false,
        proto_audit_ok: false,
        spec_ok: false,
        reserved1: 0,
        devnet_report_hash: zero_hash(),
        testnet_report_hash: zero_hash(),
        perf_report_hash: zero_hash(),
        adversarial_report_hash: zero_hash(),
        crypto_audit_hash: zero_hash(),
        proto_audit_hash: zero_hash(),
        spec_hash: zero_hash(),
    };

    let mut data = Vec::new();
    checklist.encode_state(&mut data);
    let checklist_account =
        Account::new(LAUNCH_CHECKLIST_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = WitnessStore::default();
    store.put(checklist_account).unwrap();

    let call = GovUpdateLaunchChecklistCall {
        version: 1,
        proposal_id: 9,
        eta_height: 3000,
        devnet_ok: true,
        testnet_ok: true,
        perf_ok: true,
        adversarial_ok: false,
        crypto_audit_ok: true,
        proto_audit_ok: false,
        spec_ok: true,
        devnet_report_hash: [1u8; 32],
        testnet_report_hash: [2u8; 32],
        perf_report_hash: [3u8; 32],
        adversarial_report_hash: [4u8; 32],
        crypto_audit_hash: [5u8; 32],
        proto_audit_hash: [6u8; 32],
        spec_hash: [7u8; 32],
    };

    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_UPDATE_LAUNCH_CHECKLIST);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    assert_direct_refusal(&mut store, &tx);
}

#[test]
fn gov_set_mainnet_status_refuses_without_reading_target() {
    // Prepare ParamRegistry with PreGenesis.
    let params = ParamRegistry {
        version: 1,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0u8; 6],
        slash_bps_prevote: 10,
        slash_bps_precommit: 20,
        reporter_reward_bps: 5,
        reserved1: 0,
        min_validator_stake: 0,
        slashing_schedule: None,
    };
    let mut data = Vec::new();
    params.encode_state(&mut data);
    let param_account = Account::new(PARAM_REGISTRY_ACCOUNT_ID, GOVERNANCE_PROGRAM_ID, 0, data);

    let mut store = WitnessStore::default();
    store.put(param_account).unwrap();

    let call = GovSetMainnetStatusCall {
        version: 1,
        new_status: MainnetStatus::Ready,
        proposal_id: 11,
        eta_height: 4000,
    };
    let mut call_data = Vec::new();
    call.encode(&mut call_data);
    assert_eq!(call_data[0], OP_GOV_SET_MAINNET_STATUS);

    let tx = base_tx(GOVERNANCE_PROGRAM_ID, call_data);
    assert_direct_refusal(&mut store, &tx);
}

#[test]
fn direct_program_wrong_id_refuses_before_any_store_access() {
    let mut store = WitnessStore::default();
    store
        .put(Account::new(
            dummy_account_id(0xDD),
            dummy_account_id(0xEE),
            7,
            vec![1, 2, 3],
        ))
        .unwrap();
    store.clear_events();
    let before = store.accounts.clone();
    let tx = base_tx(dummy_account_id(0xFF), Vec::new());
    let result = {
        let mut ctx = ExecutionContext::new(&mut store, empty_crypto());
        GovernanceProgram::new().execute(&mut ctx, &tx)
    };
    match result {
        Err(ExecutionError::ProgramError("program_id mismatch for GovernanceProgram")) => {}
        other => panic!("expected wrong program id refusal, got {other:?}"),
    }
    assert_eq!(store.accounts, before);
    assert_eq!(store.take_events(), StoreEvents::default());
}
