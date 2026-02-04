pub mod account;
pub mod apply;
pub mod auth;
pub mod context;
pub mod error;
pub mod execution;
pub mod execution_gas;
pub mod monetary_engine;
pub mod parallel_exec;
pub mod program;
pub mod store;

pub use account::{Account, AccountHeader};
pub use auth::verify_transaction_auth;
pub use context::ExecutionContext;
pub use error::ExecutionError;
pub use program::Program;
pub use store::{AccountStore, InMemoryAccountStore};

pub use apply::{InMemoryLedger, LedgerApply, LedgerBlockInfo, LedgerError};

// T150: Execution layer exports
pub use execution::{
    get_account_nonce, set_account_nonce, ExecutionEngine, ExecutionEngineError, ExecutionEvent,
    ExecutionOutcome, InMemoryState, NonceExecutionEngine, QbindTransaction, StateUpdater,
    StateView, TxVerifyError, UserPublicKey, UserSignature, NONCE_KEY_PREFIX, TX_DOMAIN_TAG,
    USER_ML_DSA_44_SUITE_ID,
};

// T157: Stage A parallel execution exports
pub use execution::{
    ParallelExecConfig, ParallelExecStats, SenderPartitionedNonceExecutor, TxReceipt,
};

// T163: VM v0 state model and execution engine exports
pub use execution::{
    AccountState, AccountStateUpdater, AccountStateView, InMemoryAccountState, TransferPayload,
    VmV0BlockStats, VmV0Error, VmV0ExecutionEngine, VmV0TxResult, TRANSFER_PAYLOAD_SIZE,
};

// T164: Persistent account state exports
pub use execution::{
    CachedPersistentAccountState, PersistentAccountState, RocksDbAccountState, StorageError,
};

// T168: Gas accounting and fee model exports
// T193: Fee distribution policy exports
pub use execution_gas::{
    compute_gas_for_vm_v0_tx, decode_transfer_payload, gas_for_standard_transfer,
    gas_for_transfer_v0, ExecutionGasConfig, FeeDistributionPolicy, GasComputeResult,
    TransferPayloadDecoded, TransferPayloadV1, VmGasError, BLOCK_GAS_LIMIT_DEFAULT,
    BPS_100_PERCENT, DEFAULT_V0_GAS_LIMIT, GAS_BASE_TX, GAS_PER_ACCOUNT_READ,
    GAS_PER_ACCOUNT_WRITE, GAS_PER_BYTE_PAYLOAD, MINIMUM_GAS_LIMIT, TRANSFER_PAYLOAD_V1_SIZE,
};

// T171: Stage B parallel execution skeleton exports
pub use parallel_exec::{
    build_conflict_graph, build_parallel_schedule, extract_all_read_write_sets,
    extract_read_write_set, ConflictGraph, ParallelSchedule, TxIndex, TxReadWriteSet,
};

// T186: Stage B production parallel execution exports
pub use parallel_exec::{execute_block_stage_b, StageBExecStats};

// T195: Monetary Engine v1 exports
pub use monetary_engine::{
    compute_monetary_decision, MonetaryDecision, MonetaryEngineConfig, MonetaryInputs,
    MonetaryPhase, PhaseParameters, PhaseTransitionRecommendation,
};