pub mod account;
pub mod apply;
pub mod auth;
pub mod context;
pub mod error;
pub mod execution;
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
    VmV0Error, VmV0ExecutionEngine, VmV0TxResult, TRANSFER_PAYLOAD_SIZE,
};

// T164: Persistent account state exports
pub use execution::{
    CachedPersistentAccountState, PersistentAccountState, RocksDbAccountState, StorageError,
};
