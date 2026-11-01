use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use qbind_crypto::error::CryptoError;
use qbind_crypto::ml_dsa44::MlDsa44Backend;
use qbind_crypto::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_crypto::{
    ml_dsa_44_sign_digest, CryptoProvider, MlDsa44SignatureSuite, StaticCryptoProvider,
};
use qbind_hash::tx::tx_digest;
use qbind_ledger::{Account, AccountStore, ExecutionError};
use qbind_runtime::TxExecutor;
use qbind_serde::{StateDecode, StateEncode};
use qbind_system::governance_program::{
    GOVERNANCE_PROGRAM_ID, LAUNCH_CHECKLIST_ACCOUNT_ID, PARAM_REGISTRY_ACCOUNT_ID,
    SAFETY_COUNCIL_KEYSET_ACCOUNT_ID, SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS, SUITE_REGISTRY_ACCOUNT_ID,
};
use qbind_system::keyset_program::KEYSET_PROGRAM_ID;
use qbind_types::{
    AccountId, Hash32, KeysetAccount, KeysetEntry, LaunchChecklist, MainnetStatus, ParamRegistry,
    SafetyCouncilKeyAccount, SafetyCouncilKeyset, SecurityCategory, SuiteEntry, SuiteFamily,
    SuiteRegistry, SuiteStatus, SuiteTier,
};
use qbind_wire::gov::{
    GovSetMainnetStatusCall, GovUpdateLaunchChecklistCall, GovUpdateParamRegistryCall,
    GovUpdateSuiteStatusCall, OP_GOV_SET_MAINNET_STATUS, OP_GOV_UPDATE_LAUNCH_CHECKLIST,
    OP_GOV_UPDATE_PARAM_REGISTRY, OP_GOV_UPDATE_SUITE_STATUS,
};
use qbind_wire::io::WireEncode;
use qbind_wire::tx::{Transaction, TxAccountMeta, TxAuth};

const AUTH_ID: AccountId = [0xC0; 32];
const SENTINEL_ID: AccountId = [0xD0; 32];
const PAYER_ID: AccountId = [0xE0; 32];
const SUITE_ID: u8 = 100;
static COUNCIL_PUBLIC_KEYS: OnceLock<Vec<Vec<u8>>> = OnceLock::new();

#[derive(Clone, Copy, Debug)]
enum Operation {
    SuiteStatus,
    ParamRegistry,
    LaunchChecklist,
    MainnetStatus,
}

impl Operation {
    const ALL: [Self; 4] = [
        Self::SuiteStatus,
        Self::ParamRegistry,
        Self::LaunchChecklist,
        Self::MainnetStatus,
    ];

    fn target(self) -> AccountId {
        match self {
            Self::SuiteStatus => SUITE_REGISTRY_ACCOUNT_ID,
            Self::ParamRegistry | Self::MainnetStatus => PARAM_REGISTRY_ACCOUNT_ID,
            Self::LaunchChecklist => LAUNCH_CHECKLIST_ACCOUNT_ID,
        }
    }

    fn encoded_call(self) -> Vec<u8> {
        let mut bytes = Vec::new();
        match self {
            Self::SuiteStatus => GovUpdateSuiteStatusCall {
                version: 1,
                suite_id: 0x03,
                new_status: 2,
                proposal_id: 77,
                eta_height: 9_876,
            }
            .encode(&mut bytes),
            Self::ParamRegistry => GovUpdateParamRegistryCall {
                version: 1,
                proposal_id: 77,
                eta_height: 9_876,
                slash_bps_prevote: 101,
                slash_bps_precommit: 202,
                reporter_reward_bps: 303,
            }
            .encode(&mut bytes),
            Self::LaunchChecklist => GovUpdateLaunchChecklistCall {
                version: 1,
                proposal_id: 77,
                eta_height: 9_876,
                devnet_ok: true,
                testnet_ok: false,
                perf_ok: true,
                adversarial_ok: false,
                crypto_audit_ok: true,
                proto_audit_ok: false,
                spec_ok: true,
                devnet_report_hash: [0x11; 32],
                testnet_report_hash: [0x22; 32],
                perf_report_hash: [0x33; 32],
                adversarial_report_hash: [0x44; 32],
                crypto_audit_hash: [0x55; 32],
                proto_audit_hash: [0x66; 32],
                spec_hash: [0x77; 32],
            }
            .encode(&mut bytes),
            Self::MainnetStatus => GovSetMainnetStatusCall {
                version: 1,
                new_status: MainnetStatus::Ready,
                proposal_id: 77,
                eta_height: 9_876,
            }
            .encode(&mut bytes),
        }
        let expected_opcode = match self {
            Self::SuiteStatus => OP_GOV_UPDATE_SUITE_STATUS,
            Self::ParamRegistry => OP_GOV_UPDATE_PARAM_REGISTRY,
            Self::LaunchChecklist => OP_GOV_UPDATE_LAUNCH_CHECKLIST,
            Self::MainnetStatus => OP_GOV_SET_MAINNET_STATUS,
        };
        assert_eq!(bytes.first(), Some(&expected_opcode));
        bytes
    }

    fn proposal_offset(self) -> usize {
        match self {
            Self::SuiteStatus => 8,
            Self::ParamRegistry | Self::LaunchChecklist | Self::MainnetStatus => 4,
        }
    }

    fn eta_offset(self) -> usize {
        self.proposal_offset() + 8
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
    reads: RefCell<Vec<AccountId>>,
    writes: Vec<AccountId>,
    deletes: Vec<AccountId>,
}

impl WitnessStore {
    fn seed(&mut self, account: Account) {
        self.accounts.insert(account.id, account);
    }

    fn clear_events(&mut self) {
        self.reads.borrow_mut().clear();
        self.writes.clear();
        self.deletes.clear();
    }

    fn take_events(&mut self) -> StoreEvents {
        StoreEvents {
            reads: std::mem::take(&mut *self.reads.borrow_mut()),
            writes: std::mem::take(&mut self.writes),
            deletes: std::mem::take(&mut self.deletes),
        }
    }

    fn complete_state(&self) -> HashMap<AccountId, Account> {
        self.accounts.clone()
    }
}

impl AccountStore for WitnessStore {
    fn get(&self, id: &AccountId) -> Option<Account> {
        self.reads.borrow_mut().push(*id);
        self.accounts.get(id).cloned()
    }

    fn put(&mut self, account: Account) -> Result<(), ExecutionError> {
        self.writes.push(account.id);
        self.accounts.insert(account.id, account);
        Ok(())
    }

    fn delete(&mut self, id: &AccountId) -> Result<(), ExecutionError> {
        self.deletes.push(*id);
        self.accounts.remove(id);
        Ok(())
    }
}

struct CountedSuite {
    inner: MlDsa44SignatureSuite,
    verifications: Arc<AtomicUsize>,
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

    fn canonical_key_descriptor<'a>(
        &self,
        key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        self.inner.canonical_key_descriptor(key)
    }

    fn verify(&self, key: &[u8], digest: &Hash32, signature: &[u8]) -> Result<(), CryptoError> {
        self.verifications.fetch_add(1, Ordering::SeqCst);
        self.inner.verify(key, digest, signature)
    }
}

struct Fixture {
    store: WitnessStore,
    original_state: HashMap<AccountId, Account>,
    transaction: Transaction,
    secret: Vec<u8>,
    crypto: Arc<dyn CryptoProvider>,
    verifications: Arc<AtomicUsize>,
    executor: TxExecutor<WitnessStore>,
}

impl Fixture {
    fn new(operation: Operation) -> Self {
        let (public_key, secret) = MlDsa44Backend::generate_keypair().expect("genuine ML-DSA-44");
        let keyset = KeysetAccount {
            version: 1,
            reserved0: [0; 3],
            threshold: 1,
            entry_count: 1,
            reserved1: [0; 4],
            entries: vec![KeysetEntry {
                suite_id: SUITE_ID,
                weight: 1,
                reserved0: [0],
                pubkey_len: u16::try_from(public_key.len()).unwrap(),
                pubkey_bytes: public_key,
            }],
        };
        let mut keyset_data = Vec::new();
        keyset.encode_state(&mut keyset_data);
        let signer = Account::new(AUTH_ID, KEYSET_PROGRAM_ID, 0, keyset_data);

        let mut store = WitnessStore::default();
        store.seed(signer);
        store.seed(target_account(operation));
        store.seed(sentinel_account());

        let council = SafetyCouncilKeyset {
            version: 1,
            threshold: 5,
            member_count: 7,
            reserved0: 0,
            members: SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS.to_vec(),
        };
        let mut council_data = Vec::new();
        council.encode_state(&mut council_data);
        store.seed(Account::new(
            SAFETY_COUNCIL_KEYSET_ACCOUNT_ID,
            GOVERNANCE_PROGRAM_ID,
            0,
            council_data,
        ));
        let council_public_keys = COUNCIL_PUBLIC_KEYS.get_or_init(|| {
            (0..7)
                .map(|_| {
                    MlDsa44Backend::generate_keypair()
                        .expect("genuine council fixture key generation")
                        .0
                })
                .collect()
        });
        for (id, public_key) in SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS
            .into_iter()
            .zip(council_public_keys)
        {
            let member = SafetyCouncilKeyAccount {
                version: 1,
                suite_id: SUITE_ID,
                reserved0: [0; 2],
                pk_bytes: public_key.clone(),
            };
            let mut data = Vec::new();
            member.encode_state(&mut data);
            store.seed(Account::new(id, GOVERNANCE_PROGRAM_ID, 0, data));
        }

        let accounts = std::iter::once(TxAccountMeta {
            account_id: AUTH_ID,
            flags: 1,
            access_hint: 0,
            reserved0: [0; 2],
        })
        .chain(std::iter::once(TxAccountMeta {
            account_id: operation.target(),
            flags: 2,
            access_hint: 0,
            reserved0: [0; 2],
        }))
        .chain(std::iter::once(TxAccountMeta {
            account_id: SENTINEL_ID,
            flags: 0,
            access_hint: 0,
            reserved0: [0; 2],
        }))
        .chain(std::iter::once(TxAccountMeta {
            account_id: SAFETY_COUNCIL_KEYSET_ACCOUNT_ID,
            flags: 0,
            access_hint: 0,
            reserved0: [0; 2],
        }))
        .chain(
            SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS
                .into_iter()
                .map(|account_id| TxAccountMeta {
                    account_id,
                    flags: 0,
                    access_hint: 0,
                    reserved0: [0; 2],
                }),
        )
        .collect();
        let mut transaction = Transaction {
            version: 1,
            chain_id: 1,
            payer: PAYER_ID,
            nonce: 42,
            fee_limit: 100_000,
            accounts,
            program_id: GOVERNANCE_PROGRAM_ID,
            call_data: operation.encoded_call(),
            auths: Vec::new(),
        };
        sign(&mut transaction, &secret);

        let verifications = Arc::new(AtomicUsize::new(0));
        let crypto: Arc<dyn CryptoProvider> = Arc::new(
            StaticCryptoProvider::new().with_signature_suite(Arc::new(CountedSuite {
                inner: MlDsa44SignatureSuite::new(SUITE_ID),
                verifications: Arc::clone(&verifications),
            })),
        );
        store.clear_events();
        let original_state = store.complete_state();
        Self {
            store,
            original_state,
            transaction,
            secret,
            crypto,
            verifications,
            executor: TxExecutor::new(),
        }
    }

    fn verify_count(&self) -> usize {
        self.verifications.load(Ordering::SeqCst)
    }

    fn execute(&mut self, tx: &Transaction) -> Result<(), ExecutionError> {
        self.executor
            .execute_transaction(&mut self.store, Arc::clone(&self.crypto), tx)
    }

    fn expected_state_after(&self, operation: Operation) -> HashMap<AccountId, Account> {
        let mut expected = self.original_state.clone();
        expected.insert(operation.target(), expected_target(operation));
        expected
    }

    fn assert_success(&mut self, operation: Operation, tx: &Transaction) -> StoreEvents {
        let tx_before = tx.clone();
        let wire_before = transaction_bytes(tx);
        let before_verifications = self.verify_count();
        self.store.clear_events();
        self.execute(tx).expect("genuine executor control succeeds");
        let events = self.store.take_events();
        assert_eq!(
            events.reads,
            vec![AUTH_ID, operation.target()],
            "only transaction signer keyset and fixed operation target are read"
        );
        assert_eq!(events.writes, vec![operation.target()]);
        assert!(events.deletes.is_empty());
        assert_eq!(self.verify_count(), before_verifications + 1);
        assert_eq!(self.store.accounts, self.expected_state_after(operation));
        assert_eq!(*tx, tx_before);
        assert_eq!(transaction_bytes(tx), wire_before);
        assert!(!events.reads.contains(&SAFETY_COUNCIL_KEYSET_ACCOUNT_ID));
        assert!(SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS
            .iter()
            .all(|id| !events.reads.contains(id)));
        assert!(!events.reads.contains(&PAYER_ID));
        events
    }

    fn assert_refusal(
        &mut self,
        tx: &Transaction,
        expected_error: ExecutionError,
        expected_reads: Vec<AccountId>,
        expected_verification_delta: usize,
    ) {
        let tx_before = tx.clone();
        let wire_before = transaction_bytes(tx);
        let state_before = self.store.complete_state();
        let before_verifications = self.verify_count();
        self.store.clear_events();
        assert_execution_error(self.execute(tx).unwrap_err(), expected_error);
        let events = self.store.take_events();
        assert_eq!(events.reads, expected_reads);
        assert!(events.writes.is_empty());
        assert!(events.deletes.is_empty());
        assert_eq!(
            self.verify_count(),
            before_verifications + expected_verification_delta
        );
        assert_eq!(self.store.accounts, state_before);
        assert_eq!(*tx, tx_before);
        assert_eq!(transaction_bytes(tx), wire_before);
    }
}

fn assert_execution_error(actual: ExecutionError, expected: ExecutionError) {
    match (actual, expected) {
        (ExecutionError::InvalidCallData(actual), ExecutionError::InvalidCallData(expected))
        | (ExecutionError::CryptoError(actual), ExecutionError::CryptoError(expected))
        | (ExecutionError::ProgramError(actual), ExecutionError::ProgramError(expected)) => {
            assert_eq!(actual, expected)
        }
        (actual, expected) => panic!("error category mismatch: {actual:?} != {expected:?}"),
    }
}

fn sign(tx: &mut Transaction, secret: &[u8]) {
    tx.auths = vec![TxAuth {
        account_index: 0,
        suite_id: SUITE_ID,
        reserved: 0,
        signature: Vec::new(),
    }];
    tx.auths[0].signature = ml_dsa_44_sign_digest(secret, &tx_digest(tx)).expect("sign body");
}

fn transaction_bytes(tx: &Transaction) -> Vec<u8> {
    let mut bytes = Vec::new();
    tx.encode(&mut bytes);
    bytes
}

fn encode_state<T: StateEncode>(state: &T) -> Vec<u8> {
    let mut bytes = Vec::new();
    state.encode_state(&mut bytes);
    bytes
}

fn decode_state<T: StateDecode>(data: &[u8]) -> T {
    let mut input = data;
    let state = T::decode_state(&mut input).expect("fixture state decodes");
    assert!(input.is_empty(), "fixture state has no trailing bytes");
    state
}

fn target_account(operation: Operation) -> Account {
    let data = match operation {
        Operation::SuiteStatus => encode_state(&initial_suite_registry()),
        Operation::ParamRegistry | Operation::MainnetStatus => encode_state(&initial_params()),
        Operation::LaunchChecklist => encode_state(&initial_checklist()),
    };
    let mut account = Account::new(operation.target(), GOVERNANCE_PROGRAM_ID, 51, data);
    account.header.rent_epoch = 29;
    account.header.reserved = [0xA5; 8];
    account
}

fn sentinel_account() -> Account {
    let mut account = Account::new(SENTINEL_ID, [0x66; 32], 808, vec![0x5A; 19]);
    account.header.is_executable = true;
    account.header.rent_epoch = 909;
    account.header.reserved = [0x3C; 8];
    account
}

fn initial_suite_registry() -> SuiteRegistry {
    SuiteRegistry {
        version: 4,
        reserved0: [1, 2, 3],
        suite_count: 2,
        reserved1: 0x1234,
        suites: vec![
            SuiteEntry {
                suite_id: 0x03,
                family: SuiteFamily::Lattice,
                category: SecurityCategory::Cat1,
                tier: SuiteTier::Experimental,
                status: SuiteStatus::Active,
                reserved0: [4, 5, 6],
                params_hash: [7; 32],
                ext_len: 3,
                ext_bytes: vec![8, 9, 10],
            },
            SuiteEntry {
                suite_id: 0x04,
                family: SuiteFamily::HashBased,
                category: SecurityCategory::Cat5,
                tier: SuiteTier::Core,
                status: SuiteStatus::Legacy,
                reserved0: [11, 12, 13],
                params_hash: [14; 32],
                ext_len: 2,
                ext_bytes: vec![15, 16],
            },
        ],
    }
}

fn initial_params() -> ParamRegistry {
    ParamRegistry {
        version: 3,
        mainnet_status: MainnetStatus::PreGenesis,
        reserved0: [0xA1; 6],
        slash_bps_prevote: 10,
        slash_bps_precommit: 20,
        reporter_reward_bps: 30,
        reserved1: 40,
        min_validator_stake: 50_000,
        slashing_schedule: None,
    }
}

fn initial_checklist() -> LaunchChecklist {
    LaunchChecklist {
        version: 2,
        reserved0: [0xB1; 3],
        devnet_ok: false,
        testnet_ok: true,
        perf_ok: false,
        adversarial_ok: true,
        crypto_audit_ok: false,
        proto_audit_ok: true,
        spec_ok: false,
        reserved1: 0xC1,
        devnet_report_hash: [1; 32],
        testnet_report_hash: [2; 32],
        perf_report_hash: [3; 32],
        adversarial_report_hash: [4; 32],
        crypto_audit_hash: [5; 32],
        proto_audit_hash: [6; 32],
        spec_hash: [7; 32],
    }
}

fn expected_target(operation: Operation) -> Account {
    let mut expected = target_account(operation);
    expected.data = match operation {
        Operation::SuiteStatus => {
            let mut state: SuiteRegistry = decode_state(&expected.data);
            state
                .suites
                .iter_mut()
                .find(|suite| suite.suite_id == 0x03)
                .unwrap()
                .status = SuiteStatus::Disabled;
            encode_state(&state)
        }
        Operation::ParamRegistry => {
            let mut state: ParamRegistry = decode_state(&expected.data);
            state.slash_bps_prevote = 101;
            state.slash_bps_precommit = 202;
            state.reporter_reward_bps = 303;
            encode_state(&state)
        }
        Operation::LaunchChecklist => {
            let mut state: LaunchChecklist = decode_state(&expected.data);
            state.devnet_ok = true;
            state.testnet_ok = false;
            state.perf_ok = true;
            state.adversarial_ok = false;
            state.crypto_audit_ok = true;
            state.proto_audit_ok = false;
            state.spec_ok = true;
            state.devnet_report_hash = [0x11; 32];
            state.testnet_report_hash = [0x22; 32];
            state.perf_report_hash = [0x33; 32];
            state.adversarial_report_hash = [0x44; 32];
            state.crypto_audit_hash = [0x55; 32];
            state.proto_audit_hash = [0x66; 32];
            state.spec_hash = [0x77; 32];
            encode_state(&state)
        }
        Operation::MainnetStatus => {
            let mut state: ParamRegistry = decode_state(&expected.data);
            state.mainnet_status = MainnetStatus::Ready;
            encode_state(&state)
        }
    };
    expected
}

#[test]
fn all_four_native_governance_operations_execute_through_tx_executor() {
    for operation in Operation::ALL {
        let mut fixture = Fixture::new(operation);
        assert_ne!(AUTH_ID, operation.target());
        assert_ne!(AUTH_ID, SAFETY_COUNCIL_KEYSET_ACCOUNT_ID);
        assert!(SAFETY_COUNCIL_MEMBER_ACCOUNT_IDS
            .iter()
            .all(|id| AUTH_ID != *id));
        let tx = fixture.transaction.clone();
        fixture.assert_success(operation, &tx);
        let updated = &fixture.store.accounts[&operation.target()];
        assert_eq!(updated, &expected_target(operation));

        match operation {
            Operation::SuiteStatus => {
                let stored: SuiteRegistry = decode_state(&updated.data);
                assert_eq!(stored.suites[0].status, SuiteStatus::Disabled);
                assert_eq!(stored.suites[1], initial_suite_registry().suites[1]);
            }
            Operation::ParamRegistry => {
                let stored: ParamRegistry = decode_state(&updated.data);
                assert_eq!(
                    (
                        stored.slash_bps_prevote,
                        stored.slash_bps_precommit,
                        stored.reporter_reward_bps,
                        stored.mainnet_status
                    ),
                    (101, 202, 303, MainnetStatus::PreGenesis)
                );
            }
            Operation::LaunchChecklist => {
                let stored: LaunchChecklist = decode_state(&updated.data);
                assert!(stored.devnet_ok);
                assert!(!stored.testnet_ok);
                assert_eq!(stored.devnet_report_hash, [0x11; 32]);
                assert_eq!(stored.spec_hash, [0x77; 32]);
            }
            Operation::MainnetStatus => {
                let stored: ParamRegistry = decode_state(&updated.data);
                assert_eq!(stored.mainnet_status, MainnetStatus::Ready);
                assert_eq!(stored.slash_bps_prevote, initial_params().slash_bps_prevote);
            }
        }
    }
}

#[test]
fn each_operation_authentication_refusal_is_exact_and_recoverable() {
    for operation in Operation::ALL {
        let mut fixture = Fixture::new(operation);
        let valid = fixture.transaction.clone();
        let mut no_auth = valid.clone();
        no_auth.auths.clear();
        fixture.assert_refusal(
            &no_auth,
            ExecutionError::InvalidCallData(
                "transaction requires at least one authentication entry",
            ),
            vec![],
            0,
        );
        fixture.assert_success(operation, &valid);

        let mut tampered_fixture = Fixture::new(operation);
        let valid = tampered_fixture.transaction.clone();
        let mut tampered = valid.clone();
        tampered.auths[0].signature[100] ^= 0x80;
        tampered_fixture.assert_refusal(
            &tampered,
            ExecutionError::CryptoError("signature verification failed"),
            vec![AUTH_ID],
            1,
        );
        tampered_fixture.assert_success(operation, &valid);
    }
}

#[test]
fn signed_malformed_calls_and_unsupported_dispatch_refuse_before_effects() {
    for operation in Operation::ALL {
        let mut fixture = Fixture::new(operation);
        let mut malformed = fixture.transaction.clone();
        malformed.call_data.pop();
        sign(&mut malformed, &fixture.secret);
        let handler_error = match operation {
            Operation::SuiteStatus => {
                ExecutionError::InvalidCallData("invalid GovUpdateSuiteStatusCall")
            }
            Operation::ParamRegistry => {
                ExecutionError::InvalidCallData("invalid GovUpdateParamRegistryCall")
            }
            Operation::LaunchChecklist => {
                ExecutionError::InvalidCallData("invalid GovUpdateLaunchChecklistCall")
            }
            Operation::MainnetStatus => {
                ExecutionError::InvalidCallData("invalid GovSetMainnetStatusCall")
            }
        };
        fixture.assert_refusal(&malformed, handler_error, vec![AUTH_ID], 1);
        let valid = fixture.transaction.clone();
        fixture.assert_success(operation, &valid);
    }

    let mut fixture = Fixture::new(Operation::SuiteStatus);
    let mut unsupported = fixture.transaction.clone();
    unsupported.call_data[0] = 0xFF;
    sign(&mut unsupported, &fixture.secret);
    fixture.assert_refusal(
        &unsupported,
        ExecutionError::ProgramError("unsupported governance opcode"),
        vec![AUTH_ID],
        1,
    );
    let valid = fixture.transaction.clone();
    fixture.assert_success(Operation::SuiteStatus, &valid);

    let mut fixture = Fixture::new(Operation::SuiteStatus);
    let mut invalid_status = fixture.transaction.clone();
    invalid_status.call_data[3] = 0xFF;
    sign(&mut invalid_status, &fixture.secret);
    fixture.assert_refusal(
        &invalid_status,
        ExecutionError::InvalidCallData("invalid SuiteStatus"),
        vec![AUTH_ID, SUITE_REGISTRY_ACCOUNT_ID],
        1,
    );
    let valid = fixture.transaction.clone();
    fixture.assert_success(Operation::SuiteStatus, &valid);
}

#[test]
fn proposal_id_and_eta_are_signed_but_not_admission_inputs() {
    for operation in Operation::ALL {
        for offset in [operation.proposal_offset(), operation.eta_offset()] {
            let mut fixture = Fixture::new(operation);
            let original = fixture.transaction.clone();
            let mut altered = original.clone();
            altered.call_data[offset] ^= 0x40;
            assert_ne!(tx_digest(&original), tx_digest(&altered));
            fixture.assert_refusal(
                &altered,
                ExecutionError::CryptoError("signature verification failed"),
                vec![AUTH_ID],
                1,
            );
        }

        for (offset, value) in [
            (operation.proposal_offset(), u64::MAX),
            (operation.eta_offset(), 0),
        ] {
            let mut fixture = Fixture::new(operation);
            let mut resubmitted = fixture.transaction.clone();
            resubmitted.call_data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
            sign(&mut resubmitted, &fixture.secret);
            fixture.assert_success(operation, &resubmitted);
            assert_eq!(
                fixture.store.accounts[&operation.target()],
                expected_target(operation),
                "proposal/ETA values do not change the handler's stored result"
            );
        }
    }
}

#[test]
fn identical_complete_signed_transaction_is_accepted_twice() {
    let operation = Operation::ParamRegistry;
    let mut fixture = Fixture::new(operation);
    let tx = fixture.transaction.clone();
    let bytes = transaction_bytes(&tx);

    assert_eq!(fixture.verify_count(), 0);

    let first_events = fixture.assert_success(operation, &tx);
    assert_eq!(fixture.verify_count(), 1);
    assert_eq!(first_events.writes, vec![operation.target()]);
    assert_eq!(first_events.deletes, Vec::<AccountId>::new());
    let after_first = fixture.store.complete_state();

    let second_events = fixture.assert_success(operation, &tx);
    assert_eq!(fixture.verify_count(), 2);
    assert_eq!(second_events.writes, vec![operation.target()]);
    assert_eq!(second_events.deletes, Vec::<AccountId>::new());
    let after_second = fixture.store.complete_state();
    assert_eq!(
        after_second, after_first,
        "setter's second logical state is unchanged"
    );
    assert_eq!(transaction_bytes(&tx), bytes);
}
