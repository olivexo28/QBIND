pub mod account;
pub mod apply;
pub mod auth;
pub mod context;
pub mod error;
pub mod execution;
pub mod execution_gas;
pub mod monetary_engine;
pub mod monetary_state;
pub mod parallel_exec;
pub mod program;
pub mod state_pruning;
pub mod state_snapshot;
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

// T197: Monetary Seigniorage exports
pub use monetary_engine::{
    compute_seigniorage_split, parse_monetary_mode, MonetaryAccounts, MonetaryMode,
    SeigniorageAccounting, SeigniorageSplit, SEIGNIORAGE_SPLIT_MAINNET_DEFAULT,
    VALID_MONETARY_MODES,
};

// T199: Monetary Epoch State exports
#[allow(deprecated)]
pub use monetary_state::{
    compute_epoch_state, compute_smoothed_annual_fee_revenue, epoch_for_height, is_epoch_boundary,
    MonetaryEpochInputs, MonetaryEpochState, DEFAULT_BLOCKS_PER_EPOCH, DEFAULT_EPOCHS_PER_YEAR,
};

// T202: EMA Fee Smoothing exports
pub use monetary_state::{compute_ema_fee_revenue, ema_step};

// T203: Rate-of-Change Limiting exports
pub use monetary_state::clamp_inflation_rate_change;

// T204: Phase Transition Logic exports
pub use monetary_state::{
    compute_fee_coverage_ratio_bps, compute_phase_transition, compute_stake_ratio_bps,
    PhaseTransitionOutcome, PhaseTransitionReason, EPOCHS_PER_YEAR_10_MIN, EPOCH_MATURE_START,
    EPOCH_TRANSITION_START, FEE_COVERAGE_BOOTSTRAP_TO_TRANSITION_BPS,
    FEE_COVERAGE_TRANSITION_TO_MATURE_BPS, STAKE_RATIO_BOOTSTRAP_TO_TRANSITION_BPS,
    STAKE_RATIO_TRANSITION_TO_MATURE_BPS,
};

// T200: Epoch Issuance & Validator Reward Distribution exports
pub use monetary_state::{
    compute_epoch_issuance, compute_validator_rewards, ValidatorReward,
    ValidatorRewardDistribution, ValidatorStake, MAINNET_EPOCHS_PER_YEAR,
};

// T201: Seigniorage Application & Routing exports
pub use monetary_state::{
    apply_seigniorage_balances, compute_epoch_seigniorage, process_epoch_seigniorage,
    SeigniorageApplicationResult, SeigniorageStateMutator, SEIGNIORAGE_SPLIT_MAINNET_T201,
};

// T208: State Pruning exports
pub use state_pruning::{PruneStats, StatePruner};

// T215: State Snapshot exports
pub use state_snapshot::{
    validate_snapshot_dir, SnapshotStats, SnapshotValidationResult, StateSnapshotError,
    StateSnapshotMeta, StateSnapshotter,
};