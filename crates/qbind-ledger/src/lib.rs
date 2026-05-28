pub mod account;
pub mod apply;
pub mod auth;
pub mod bundle_signing_ratification;
pub mod context;
pub mod error;
pub mod execution;
pub mod execution_gas;
pub mod genesis;
pub mod monetary_engine;
pub mod monetary_state;
pub mod parallel_exec;
pub mod program;
pub mod slashing_ledger;
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

// Run 117: Authority-state snapshot metadata exports (additive carrier
// for the persistent authority anti-rollback marker; restore wiring is
// staged for Run 118).
pub use state_snapshot::AuthorityStateSnapshotMeta;

// Run 140: Authority-state v2 snapshot metadata exports (additive carrier
// for v2 anti-rollback markers in snapshots; restore wiring is staged for
// source/test only — release-binary harness deferred to Run 141).
pub use state_snapshot::AuthorityStateSnapshotMetaV2;

// T230: Slashing Ledger exports
// M1: Persistent RocksDB-backed slashing ledger
// M1.2: Atomic persistence for slashing updates
pub use slashing_ledger::{
    EpochNumber, InMemorySlashingLedger, RocksDbSlashingLedger, SlashingLedger,
    SlashingLedgerError, SlashingRecord, SlashingUpdateBatch, StakeAmount, ValidatorLedgerId,
    ValidatorSlashingState,
};

// T232: Genesis & Launch State exports
pub use genesis::{
    GenesisAllocation, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
    GenesisValidationError, GenesisValidator,
};

// T233: Genesis Hash Commitment exports
pub use genesis::{
    compute_genesis_hash_bytes, format_genesis_hash, parse_genesis_hash, ChainMeta, ChainMetaError,
    GenesisHash,
};

// Run 101: Genesis Authority + Canonical Hash + Boot-Time Verification exports
pub use genesis::{
    compute_canonical_genesis_hash, verify_boot_time_genesis, BootGenesisVerification,
    BootGenesisVerificationError, GenesisAuthorityConfig, GenesisAuthorityRoot,
    GenesisAuthorityRootKind, GenesisAuthoritySuiteId, GenesisAuthorityValidationError,
    NetworkEnvironmentPolicy, CANONICAL_GENESIS_HASH_DOMAIN_V1,
    GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX, GENESIS_AUTHORITY_FINGERPRINT_MIN_HEX_DEVNET,
    GENESIS_AUTHORITY_FINGERPRINT_MIN_HEX_PROD, GENESIS_AUTHORITY_POLICY_VERSION_RUN_101,
    GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};

// Run 104: Genesis-Bound Authority Key Material Registry exports
pub use genesis::{
    authority_public_key_fingerprint, GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN,
    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES, GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN,
};

// Run 103: Minimal Bundle-Signing-Key Ratification Verifier exports
pub use bundle_signing_ratification::{
    canonical_ratification_digest, canonical_ratification_preimage, classify_authority_root_kind,
    pqc_public_key_fingerprint, verify_bundle_signing_key_ratification, BundleSigningRatification,
    RatificationEnvironment, RatificationFailure, RatificationVerifierInputs,
    RatifiedBundleSigningKey, BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1,
    BUNDLE_SIGNING_RATIFICATION_VERSION_V1,
};

// Run 130: Ratification v2 primitive exports.
pub use bundle_signing_ratification::{
    canonical_ratification_v2_digest, verify_bundle_signing_key_ratification_v2,
    BundleSigningRatificationV2, BundleSigningRatificationV2Action, RatificationV2Failure,
    RatificationV2VerifierInputs, RatifiedBundleSigningKeyV2,
    BUNDLE_SIGNING_RATIFICATION_DOMAIN_V2, BUNDLE_SIGNING_RATIFICATION_VERSION_V2,
};

// Run 105: Non-mutating ratification enforcement layer exports.
pub use bundle_signing_ratification::{
    enforce_bundle_signing_key_ratification, RatificationEnforcementFailure,
    RatificationEnforcementInputs, RatificationEnforcementOutcome, RatificationEnforcementPolicy,
};
