//! Slashing Ledger trait and implementations (T230, M1).
//!
//! This module provides the `SlashingLedger` trait that abstracts validator stake
//! and jailing state management for the slashing system. It enables the slashing
//! backend in `qbind-consensus` to apply penalties without knowing implementation
//! details of the staking/validator registry.
//!
//! # Design (T230)
//!
//! Following the existing `AccountStore` pattern in this crate, we provide:
//! - `SlashingLedger` trait: Minimal interface for slashing operations
//! - `InMemorySlashingLedger`: HashMap-backed implementation for tests
//! - `RocksDbSlashingLedger`: Persistent RocksDB-backed implementation (M1)
//!
//! # Persistent Slashing Ledger (M1)
//!
//! The `RocksDbSlashingLedger` provides restart-safe persistence for:
//! - Per-validator slashing state (jailed_until_epoch, burned_amount_total, etc.)
//! - Evidence deduplication markers to prevent replay/double-penalty
//! - Slashing records for audit purposes
//!
//! ## Key Prefix Scheme
//!
//! ```text
//! slash:val:<validator_id>:state     -> ValidatorSlashingState (serialized JSON)
//! slash:evidence:<dedup_key>         -> u8(1) marker for seen evidence
//! slash:record:<validator_id>:<seq>  -> SlashingRecord (serialized JSON)
//! slash:meta:record_seq              -> u64 global sequence counter
//! ```
//!
//! # Future Work
//!
//! - On-chain slashing evidence transactions
//! - Governance transactions for parameter adjustments

use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Path;

/// Unique identifier for a validator in the slashing ledger.
///
/// This is a u64 that matches the ValidatorId used in qbind-consensus.
pub type ValidatorLedgerId = u64;

/// Amount of stake in native units (e.g., microQBIND).
pub type StakeAmount = u64;

/// Epoch number for jail expiration.
pub type EpochNumber = u64;

/// Validator state tracked by the slashing ledger.
#[derive(Clone, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ValidatorSlashingState {
    /// Current stake amount.
    pub stake: StakeAmount,
    /// Epoch at which the validator will be unjailed (None = not jailed).
    pub jailed_until_epoch: Option<EpochNumber>,
    /// Total stake slashed (cumulative, for audit purposes).
    pub total_slashed: StakeAmount,
    /// Number of times this validator has been jailed.
    pub jail_count: u32,
    /// Last offense epoch (for repeat offense detection, optional).
    #[serde(default)]
    pub last_offense_epoch: Option<EpochNumber>,
}

/// Slashing record persisted in the ledger for audit/CLI inspection.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SlashingRecord {
    /// The validator that was slashed.
    pub validator_id: ValidatorLedgerId,
    /// The offense kind (as string for serialization).
    pub offense_kind: String,
    /// Amount of stake burned.
    pub slashed_amount: StakeAmount,
    /// Whether the validator was jailed.
    pub jailed: bool,
    /// Epoch at which the validator will be unjailed (if jailed).
    pub jailed_until_epoch: Option<EpochNumber>,
    /// Block height at which the slashing occurred.
    pub height: u64,
    /// View at which the slashing occurred.
    pub view: u64,
    /// Epoch at which the slashing occurred.
    pub epoch: u64,
}

/// Error type for slashing ledger operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SlashingLedgerError {
    /// Validator not found in the registry.
    ValidatorNotFound(ValidatorLedgerId),
    /// Insufficient stake to slash.
    InsufficientStake {
        validator_id: ValidatorLedgerId,
        required_bps: u16,
        available_stake: StakeAmount,
    },
    /// Validator already jailed.
    AlreadyJailed(ValidatorLedgerId),
    /// Storage error.
    StorageError(String),
    /// Other error.
    Other(String),
}

impl std::fmt::Display for SlashingLedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SlashingLedgerError::ValidatorNotFound(id) => {
                write!(f, "validator {} not found", id)
            }
            SlashingLedgerError::InsufficientStake {
                validator_id,
                required_bps,
                available_stake,
            } => {
                write!(
                    f,
                    "validator {} has insufficient stake ({}) for {} bps slash",
                    validator_id, available_stake, required_bps
                )
            }
            SlashingLedgerError::AlreadyJailed(id) => {
                write!(f, "validator {} is already jailed", id)
            }
            SlashingLedgerError::StorageError(msg) => write!(f, "storage error: {}", msg),
            SlashingLedgerError::Other(msg) => write!(f, "slashing ledger error: {}", msg),
        }
    }
}

impl std::error::Error for SlashingLedgerError {}

/// Abstract slashing ledger trait (T230).
///
/// This trait provides the minimal operations needed by the slashing backend
/// to apply penalties. Implementations can be in-memory (for tests) or
/// persistent (for nodes).
///
/// # Design Notes
///
/// The trait is designed to be:
/// - Minimal: Only exposes what the slashing backend needs
/// - Testable: In-memory implementation for unit tests
/// - Extensible: Future persistent implementations can add state commits
pub trait SlashingLedger {
    /// Get a validator's current slashing state.
    fn get_validator_state(
        &self,
        validator_id: ValidatorLedgerId,
    ) -> Option<ValidatorSlashingState>;

    /// Get a validator's current stake.
    fn get_stake(&self, validator_id: ValidatorLedgerId) -> Option<StakeAmount>;

    /// Reduce a validator's stake by a percentage (basis points).
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to slash
    /// * `slash_bps` - Slash percentage in basis points (1 bps = 0.01%)
    ///
    /// # Returns
    ///
    /// The amount of stake actually burned.
    fn slash_stake(
        &mut self,
        validator_id: ValidatorLedgerId,
        slash_bps: u16,
    ) -> Result<StakeAmount, SlashingLedgerError>;

    /// Mark a validator as jailed until a specific epoch.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to jail
    /// * `until_epoch` - The epoch at which the validator will be unjailed
    ///
    /// # Returns
    ///
    /// The epoch at which the validator will be unjailed.
    fn jail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
        until_epoch: EpochNumber,
    ) -> Result<EpochNumber, SlashingLedgerError>;

    /// Check if a validator is currently jailed.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to check
    /// * `current_epoch` - The current epoch (for comparing against jail expiration)
    fn is_jailed(&self, validator_id: ValidatorLedgerId, current_epoch: EpochNumber) -> bool;

    /// Clear a validator's jail status (for unjailing at epoch boundary).
    fn unjail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
    ) -> Result<(), SlashingLedgerError>;

    /// Store a slashing record for audit purposes.
    fn store_slashing_record(&mut self, record: SlashingRecord) -> Result<(), SlashingLedgerError>;

    /// Get all slashing records for a validator.
    fn get_slashing_records(&self, validator_id: ValidatorLedgerId) -> Vec<SlashingRecord>;

    /// Get all slashing records in the ledger.
    fn get_all_slashing_records(&self) -> Vec<SlashingRecord>;
}

// ============================================================================
// In-Memory Implementation
// ============================================================================

/// In-memory slashing ledger for tests (T230).
///
/// Tracks per-validator stake and jail status in memory.
/// Used by unit tests and integration harnesses.
#[derive(Debug, Default)]
pub struct InMemorySlashingLedger {
    /// Per-validator slashing state.
    validator_states: HashMap<ValidatorLedgerId, ValidatorSlashingState>,
    /// All slashing records (for audit purposes).
    records: Vec<SlashingRecord>,
}

impl InMemorySlashingLedger {
    /// Create a new empty in-memory slashing ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create an in-memory ledger with initial validator stakes.
    ///
    /// # Arguments
    ///
    /// * `initial_stakes` - Iterator of (validator_id, stake) pairs
    pub fn with_stakes(
        initial_stakes: impl IntoIterator<Item = (ValidatorLedgerId, StakeAmount)>,
    ) -> Self {
        let validator_states: HashMap<_, _> = initial_stakes
            .into_iter()
            .map(|(id, stake)| {
                (
                    id,
                    ValidatorSlashingState {
                        stake,
                        jailed_until_epoch: None,
                        total_slashed: 0,
                        jail_count: 0,
                        last_offense_epoch: None,
                    },
                )
            })
            .collect();
        Self {
            validator_states,
            records: Vec::new(),
        }
    }

    /// Set a validator's stake (for testing).
    pub fn set_stake(&mut self, validator_id: ValidatorLedgerId, stake: StakeAmount) {
        self.validator_states.entry(validator_id).or_default().stake = stake;
    }

    /// Get the number of validators tracked.
    pub fn validator_count(&self) -> usize {
        self.validator_states.len()
    }

    /// Get total stake across all validators.
    pub fn total_stake(&self) -> StakeAmount {
        self.validator_states.values().map(|s| s.stake).sum()
    }

    /// Get total amount slashed across all validators.
    pub fn total_slashed(&self) -> StakeAmount {
        self.validator_states
            .values()
            .map(|s| s.total_slashed)
            .sum()
    }
}

impl SlashingLedger for InMemorySlashingLedger {
    fn get_validator_state(
        &self,
        validator_id: ValidatorLedgerId,
    ) -> Option<ValidatorSlashingState> {
        self.validator_states.get(&validator_id).cloned()
    }

    fn get_stake(&self, validator_id: ValidatorLedgerId) -> Option<StakeAmount> {
        self.validator_states.get(&validator_id).map(|s| s.stake)
    }

    fn slash_stake(
        &mut self,
        validator_id: ValidatorLedgerId,
        slash_bps: u16,
    ) -> Result<StakeAmount, SlashingLedgerError> {
        let state = self
            .validator_states
            .get_mut(&validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        // Calculate slash amount: stake * slash_bps / 10000
        let slash_amount = (state.stake as u128 * u128::from(slash_bps) / 10000) as u64;

        // Apply slash
        state.stake = state.stake.saturating_sub(slash_amount);
        state.total_slashed += slash_amount;

        eprintln!(
            "[SLASHING_LEDGER] Slashed {} from validator {} ({} bps), remaining stake: {}",
            slash_amount, validator_id, slash_bps, state.stake
        );

        Ok(slash_amount)
    }

    fn jail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
        until_epoch: EpochNumber,
    ) -> Result<EpochNumber, SlashingLedgerError> {
        let state = self
            .validator_states
            .get_mut(&validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        // Update jail status (extend if already jailed to a later epoch)
        let current_jail = state.jailed_until_epoch.unwrap_or(0);
        if until_epoch > current_jail {
            state.jailed_until_epoch = Some(until_epoch);
            state.jail_count += 1;
            eprintln!(
                "[SLASHING_LEDGER] Jailed validator {} until epoch {} (jail count: {})",
                validator_id, until_epoch, state.jail_count
            );
        }

        Ok(until_epoch)
    }

    fn is_jailed(&self, validator_id: ValidatorLedgerId, current_epoch: EpochNumber) -> bool {
        self.validator_states
            .get(&validator_id)
            .and_then(|s| s.jailed_until_epoch)
            .map(|until| current_epoch < until)
            .unwrap_or(false)
    }

    fn unjail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
    ) -> Result<(), SlashingLedgerError> {
        let state = self
            .validator_states
            .get_mut(&validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        state.jailed_until_epoch = None;
        eprintln!("[SLASHING_LEDGER] Unjailed validator {}", validator_id);

        Ok(())
    }

    fn store_slashing_record(&mut self, record: SlashingRecord) -> Result<(), SlashingLedgerError> {
        self.records.push(record);
        Ok(())
    }

    fn get_slashing_records(&self, validator_id: ValidatorLedgerId) -> Vec<SlashingRecord> {
        self.records
            .iter()
            .filter(|r| r.validator_id == validator_id)
            .cloned()
            .collect()
    }

    fn get_all_slashing_records(&self) -> Vec<SlashingRecord> {
        self.records.clone()
    }
}

// ============================================================================
// RocksDB Persistent Implementation (M1)
// ============================================================================

/// RocksDB error wrapper for consistent error handling.
#[derive(Debug)]
pub struct RocksDbError(String);

impl std::fmt::Display for RocksDbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RocksDB error: {}", self.0)
    }
}

impl std::error::Error for RocksDbError {}

impl From<rocksdb::Error> for RocksDbError {
    fn from(e: rocksdb::Error) -> Self {
        RocksDbError(e.to_string())
    }
}

/// Key prefix for validator slashing state.
const VALIDATOR_STATE_PREFIX: &[u8] = b"slash:val:";

/// Key prefix for evidence deduplication markers.
const EVIDENCE_DEDUP_PREFIX: &[u8] = b"slash:evidence:";

/// Key prefix for slashing records.
const RECORD_PREFIX: &[u8] = b"slash:record:";

/// Key for record sequence counter metadata.
const RECORD_SEQ_KEY: &[u8] = b"slash:meta:record_seq";

/// Persistent RocksDB-backed slashing ledger (M1).
///
/// Provides restart-safe persistence for:
/// - Per-validator slashing state (stake, jailed_until_epoch, total_slashed, jail_count, last_offense_epoch)
/// - Evidence deduplication markers to prevent replay/double-penalty
/// - Slashing records for audit purposes
///
/// ## Key Schema
///
/// ```text
/// slash:val:<validator_id>:state     -> ValidatorSlashingState (JSON)
/// slash:evidence:<dedup_key_hash>    -> u8(1) marker
/// slash:record:<validator_id>:<seq>  -> SlashingRecord (JSON)
/// slash:meta:record_seq              -> u64 (global sequence counter, big-endian)
/// ```
///
/// ## Thread Safety
///
/// The underlying RocksDB instance is thread-safe, but the `SlashingLedger` trait
/// requires mutable access for write operations, so this struct is typically used
/// with external synchronization.
///
/// # Example
///
/// ```rust,ignore
/// use qbind_ledger::RocksDbSlashingLedger;
/// use std::path::Path;
///
/// let ledger = RocksDbSlashingLedger::open(Path::new("/data/slashing_ledger"))?;
///
/// // Initialize a validator
/// ledger.initialize_validator(1, 1_000_000)?;
///
/// // Slash the validator
/// let slashed = ledger.slash_stake(1, 750)?; // 7.5% slash
/// ```
pub struct RocksDbSlashingLedger {
    /// The underlying RocksDB instance.
    db: rocksdb::DB,
    /// In-memory cache of seen evidence for fast deduplication checks.
    /// Populated on startup from the database.
    seen_evidence_cache: HashSet<String>,
}

impl std::fmt::Debug for RocksDbSlashingLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RocksDbSlashingLedger")
            .field("path", &self.db.path())
            .field("seen_evidence_count", &self.seen_evidence_cache.len())
            .finish()
    }
}

impl RocksDbSlashingLedger {
    /// Open or create a RocksDB-backed slashing ledger at the given path.
    ///
    /// On open, loads the evidence deduplication markers into memory for fast lookups.
    ///
    /// # Arguments
    ///
    /// * `path` - Path to the database directory.
    ///
    /// # Errors
    ///
    /// Returns `SlashingLedgerError::StorageError` if the database cannot be opened.
    ///
    /// # Example
    ///
    /// ```rust,ignore
    /// use qbind_ledger::RocksDbSlashingLedger;
    /// use std::path::Path;
    ///
    /// let ledger = RocksDbSlashingLedger::open(Path::new("/data/slashing_ledger"))?;
    /// ```
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self, SlashingLedgerError> {
        let mut opts = rocksdb::Options::default();
        opts.create_if_missing(true);

        let db = rocksdb::DB::open(&opts, path)
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

        // Load existing evidence markers into cache
        let seen_evidence_cache = Self::load_evidence_cache(&db)?;

        eprintln!(
            "[SLASHING_LEDGER] RocksDB opened, loaded {} evidence markers",
            seen_evidence_cache.len()
        );

        Ok(Self {
            db,
            seen_evidence_cache,
        })
    }

    /// Load evidence deduplication markers from the database into memory.
    fn load_evidence_cache(db: &rocksdb::DB) -> Result<HashSet<String>, SlashingLedgerError> {
        let mut cache = HashSet::new();
        let iter = db.prefix_iterator(EVIDENCE_DEDUP_PREFIX);

        for item in iter {
            match item {
                Ok((key, _value)) => {
                    // Extract the dedup key from the full key
                    if key.starts_with(EVIDENCE_DEDUP_PREFIX) {
                        let dedup_key = &key[EVIDENCE_DEDUP_PREFIX.len()..];
                        if let Ok(s) = std::str::from_utf8(dedup_key) {
                            cache.insert(s.to_string());
                        }
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[SLASHING_LEDGER] Warning: error reading evidence cache: {}",
                        e
                    );
                }
            }
        }

        Ok(cache)
    }

    /// Build the key for a validator's slashing state.
    fn validator_state_key(validator_id: ValidatorLedgerId) -> Vec<u8> {
        let mut key = Vec::with_capacity(VALIDATOR_STATE_PREFIX.len() + 8 + 6);
        key.extend_from_slice(VALIDATOR_STATE_PREFIX);
        key.extend_from_slice(&validator_id.to_be_bytes());
        key.extend_from_slice(b":state");
        key
    }

    /// Build the key for an evidence deduplication marker.
    fn evidence_dedup_key(dedup_key: &str) -> Vec<u8> {
        let mut key = Vec::with_capacity(EVIDENCE_DEDUP_PREFIX.len() + dedup_key.len());
        key.extend_from_slice(EVIDENCE_DEDUP_PREFIX);
        key.extend_from_slice(dedup_key.as_bytes());
        key
    }

    /// Build the key for a slashing record.
    fn record_key(validator_id: ValidatorLedgerId, seq: u64) -> Vec<u8> {
        let mut key = Vec::with_capacity(RECORD_PREFIX.len() + 8 + 1 + 8);
        key.extend_from_slice(RECORD_PREFIX);
        key.extend_from_slice(&validator_id.to_be_bytes());
        key.push(b':');
        key.extend_from_slice(&seq.to_be_bytes());
        key
    }

    /// Get the next record sequence number.
    fn next_record_seq(&self) -> Result<u64, SlashingLedgerError> {
        let current = match self.db.get(RECORD_SEQ_KEY) {
            Ok(Some(bytes)) => {
                if bytes.len() != 8 {
                    return Err(SlashingLedgerError::StorageError(
                        "invalid record_seq length".to_string(),
                    ));
                }
                let arr: [u8; 8] = bytes[..].try_into().unwrap();
                u64::from_be_bytes(arr)
            }
            Ok(None) => 0,
            Err(e) => return Err(SlashingLedgerError::StorageError(e.to_string())),
        };

        let next = current.saturating_add(1);
        self.db
            .put(RECORD_SEQ_KEY, next.to_be_bytes())
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

        Ok(current)
    }

    /// Initialize a validator with a given stake.
    ///
    /// This is used to set up a new validator in the ledger. If the validator
    /// already exists, this updates their stake.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator to initialize.
    /// * `stake` - The initial stake amount.
    ///
    /// # Errors
    ///
    /// Returns `SlashingLedgerError::StorageError` on database errors.
    pub fn initialize_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
        stake: StakeAmount,
    ) -> Result<(), SlashingLedgerError> {
        let key = Self::validator_state_key(validator_id);
        let mut state = self.get_validator_state(validator_id).unwrap_or_default();
        state.stake = stake;

        let json = serde_json::to_vec(&state)
            .map_err(|e| SlashingLedgerError::StorageError(format!("JSON encode error: {}", e)))?;

        self.db
            .put(&key, json)
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

        Ok(())
    }

    /// Set a validator's stake directly (for testing or initialization).
    pub fn set_stake(
        &mut self,
        validator_id: ValidatorLedgerId,
        stake: StakeAmount,
    ) -> Result<(), SlashingLedgerError> {
        self.initialize_validator(validator_id, stake)
    }

    /// Check if evidence with the given deduplication key has been seen.
    ///
    /// Uses the in-memory cache for fast lookups.
    pub fn is_evidence_seen(&self, dedup_key: &str) -> bool {
        self.seen_evidence_cache.contains(dedup_key)
    }

    /// Mark evidence as seen to prevent replay/double-penalty.
    ///
    /// # Arguments
    ///
    /// * `dedup_key` - A string key uniquely identifying the evidence
    ///   (typically: `"{validator_id}:{offense}:{height}:{view}"`)
    ///
    /// # Errors
    ///
    /// Returns `SlashingLedgerError::StorageError` on database errors.
    pub fn mark_evidence_seen(&mut self, dedup_key: &str) -> Result<(), SlashingLedgerError> {
        // Already seen? Skip
        if self.seen_evidence_cache.contains(dedup_key) {
            return Ok(());
        }

        let key = Self::evidence_dedup_key(dedup_key);
        self.db
            .put(&key, &[1u8])
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

        self.seen_evidence_cache.insert(dedup_key.to_string());

        Ok(())
    }

    /// Format a deduplication key from evidence components.
    ///
    /// # Arguments
    ///
    /// * `validator_id` - The validator ID.
    /// * `offense_kind` - The offense type string.
    /// * `height` - The block height.
    /// * `view` - The view number.
    ///
    /// # Returns
    ///
    /// A string key in the format: `"{validator_id}:{offense}:{height}:{view}"`
    pub fn format_dedup_key(
        validator_id: ValidatorLedgerId,
        offense_kind: &str,
        height: u64,
        view: u64,
    ) -> String {
        format!("{}:{}:{}:{}", validator_id, offense_kind, height, view)
    }

    /// Get the number of validators tracked.
    pub fn validator_count(&self) -> usize {
        let iter = self.db.prefix_iterator(VALIDATOR_STATE_PREFIX);
        iter.count()
    }

    /// Get total stake across all validators.
    pub fn total_stake(&self) -> StakeAmount {
        let iter = self.db.prefix_iterator(VALIDATOR_STATE_PREFIX);
        let mut total: StakeAmount = 0;

        for item in iter {
            if let Ok((_, value)) = item {
                if let Ok(state) = serde_json::from_slice::<ValidatorSlashingState>(&value) {
                    total = total.saturating_add(state.stake);
                }
            }
        }

        total
    }

    /// Get total amount slashed across all validators.
    pub fn total_slashed(&self) -> StakeAmount {
        let iter = self.db.prefix_iterator(VALIDATOR_STATE_PREFIX);
        let mut total: StakeAmount = 0;

        for item in iter {
            if let Ok((_, value)) = item {
                if let Ok(state) = serde_json::from_slice::<ValidatorSlashingState>(&value) {
                    total = total.saturating_add(state.total_slashed);
                }
            }
        }

        total
    }

    /// Flush pending writes to disk.
    ///
    /// # Errors
    ///
    /// Returns `SlashingLedgerError::StorageError` on flush failure.
    pub fn flush(&self) -> Result<(), SlashingLedgerError> {
        self.db
            .flush()
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))
    }
}

impl SlashingLedger for RocksDbSlashingLedger {
    fn get_validator_state(
        &self,
        validator_id: ValidatorLedgerId,
    ) -> Option<ValidatorSlashingState> {
        let key = Self::validator_state_key(validator_id);

        match self.db.get(&key) {
            Ok(Some(value)) => serde_json::from_slice(&value).ok(),
            Ok(None) => None,
            Err(e) => {
                eprintln!(
                    "[SLASHING_LEDGER] Error reading validator state {}: {}",
                    validator_id, e
                );
                None
            }
        }
    }

    fn get_stake(&self, validator_id: ValidatorLedgerId) -> Option<StakeAmount> {
        self.get_validator_state(validator_id).map(|s| s.stake)
    }

    fn slash_stake(
        &mut self,
        validator_id: ValidatorLedgerId,
        slash_bps: u16,
    ) -> Result<StakeAmount, SlashingLedgerError> {
        let key = Self::validator_state_key(validator_id);

        let mut state = self
            .get_validator_state(validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        // Calculate slash amount: stake * slash_bps / 10000
        let slash_amount = (state.stake as u128 * u128::from(slash_bps) / 10000) as u64;

        // Apply slash
        state.stake = state.stake.saturating_sub(slash_amount);
        state.total_slashed += slash_amount;

        // Persist updated state
        let json = serde_json::to_vec(&state)
            .map_err(|e| SlashingLedgerError::StorageError(format!("JSON encode error: {}", e)))?;

        self.db
            .put(&key, json)
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

        eprintln!(
            "[SLASHING_LEDGER] Slashed {} from validator {} ({} bps), remaining stake: {}",
            slash_amount, validator_id, slash_bps, state.stake
        );

        Ok(slash_amount)
    }

    fn jail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
        until_epoch: EpochNumber,
    ) -> Result<EpochNumber, SlashingLedgerError> {
        let key = Self::validator_state_key(validator_id);

        let mut state = self
            .get_validator_state(validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        // Update jail status (extend if already jailed to a later epoch)
        let current_jail = state.jailed_until_epoch.unwrap_or(0);
        if until_epoch > current_jail {
            state.jailed_until_epoch = Some(until_epoch);
            state.jail_count += 1;

            // Persist updated state
            let json = serde_json::to_vec(&state).map_err(|e| {
                SlashingLedgerError::StorageError(format!("JSON encode error: {}", e))
            })?;

            self.db
                .put(&key, json)
                .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

            eprintln!(
                "[SLASHING_LEDGER] Jailed validator {} until epoch {} (jail count: {})",
                validator_id, until_epoch, state.jail_count
            );
        }

        Ok(until_epoch)
    }

    fn is_jailed(&self, validator_id: ValidatorLedgerId, current_epoch: EpochNumber) -> bool {
        self.get_validator_state(validator_id)
            .and_then(|s| s.jailed_until_epoch)
            .map(|until| current_epoch < until)
            .unwrap_or(false)
    }

    fn unjail_validator(
        &mut self,
        validator_id: ValidatorLedgerId,
    ) -> Result<(), SlashingLedgerError> {
        let key = Self::validator_state_key(validator_id);

        let mut state = self
            .get_validator_state(validator_id)
            .ok_or(SlashingLedgerError::ValidatorNotFound(validator_id))?;

        state.jailed_until_epoch = None;

        // Persist updated state
        let json = serde_json::to_vec(&state)
            .map_err(|e| SlashingLedgerError::StorageError(format!("JSON encode error: {}", e)))?;

        self.db
            .put(&key, json)
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

        eprintln!("[SLASHING_LEDGER] Unjailed validator {}", validator_id);

        Ok(())
    }

    fn store_slashing_record(&mut self, record: SlashingRecord) -> Result<(), SlashingLedgerError> {
        let seq = self.next_record_seq()?;
        let key = Self::record_key(record.validator_id, seq);

        let json = serde_json::to_vec(&record)
            .map_err(|e| SlashingLedgerError::StorageError(format!("JSON encode error: {}", e)))?;

        self.db
            .put(&key, json)
            .map_err(|e| SlashingLedgerError::StorageError(e.to_string()))?;

        Ok(())
    }

    fn get_slashing_records(&self, validator_id: ValidatorLedgerId) -> Vec<SlashingRecord> {
        let prefix = {
            let mut p = Vec::with_capacity(RECORD_PREFIX.len() + 8 + 1);
            p.extend_from_slice(RECORD_PREFIX);
            p.extend_from_slice(&validator_id.to_be_bytes());
            p.push(b':');
            p
        };

        let mut records = Vec::new();
        let iter = self.db.prefix_iterator(&prefix);

        for item in iter {
            match item {
                Ok((key, value)) => {
                    // Ensure key still matches our prefix (RocksDB prefix iterator may overshoot)
                    if !key.starts_with(&prefix) {
                        break;
                    }
                    if let Ok(record) = serde_json::from_slice::<SlashingRecord>(&value) {
                        records.push(record);
                    }
                }
                Err(e) => {
                    eprintln!(
                        "[SLASHING_LEDGER] Error reading record for validator {}: {}",
                        validator_id, e
                    );
                    break;
                }
            }
        }

        records
    }

    fn get_all_slashing_records(&self) -> Vec<SlashingRecord> {
        let mut records = Vec::new();
        let iter = self.db.prefix_iterator(RECORD_PREFIX);

        for item in iter {
            match item {
                Ok((key, value)) => {
                    if !key.starts_with(RECORD_PREFIX) {
                        break;
                    }
                    if let Ok(record) = serde_json::from_slice::<SlashingRecord>(&value) {
                        records.push(record);
                    }
                }
                Err(e) => {
                    eprintln!("[SLASHING_LEDGER] Error reading records: {}", e);
                    break;
                }
            }
        }

        records
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_in_memory_slashing_ledger_basic() {
        let mut ledger =
            InMemorySlashingLedger::with_stakes(vec![(1, 100_000), (2, 200_000), (3, 50_000)]);

        // Verify initial state
        assert_eq!(ledger.get_stake(1), Some(100_000));
        assert_eq!(ledger.get_stake(2), Some(200_000));
        assert_eq!(ledger.get_stake(3), Some(50_000));
        assert_eq!(ledger.get_stake(999), None);

        // Slash validator 1 by 750 bps (7.5%)
        let slashed = ledger.slash_stake(1, 750).unwrap();
        assert_eq!(slashed, 7_500); // 100_000 * 750 / 10000 = 7500
        assert_eq!(ledger.get_stake(1), Some(92_500));

        // Verify total slashed
        assert_eq!(ledger.total_slashed(), 7_500);
    }

    #[test]
    fn test_in_memory_slashing_ledger_jail() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000), (2, 200_000)]);

        // Jail validator 1 until epoch 10
        let until = ledger.jail_validator(1, 10).unwrap();
        assert_eq!(until, 10);

        // Check jail status at various epochs
        assert!(ledger.is_jailed(1, 5)); // Before epoch 10
        assert!(ledger.is_jailed(1, 9)); // Still before epoch 10
        assert!(!ledger.is_jailed(1, 10)); // At epoch 10, no longer jailed
        assert!(!ledger.is_jailed(1, 15)); // After epoch 10

        // Validator 2 should not be jailed
        assert!(!ledger.is_jailed(2, 5));

        // Extend jail period
        ledger.jail_validator(1, 20).unwrap();
        assert!(ledger.is_jailed(1, 15)); // Now jailed until 20
        assert!(!ledger.is_jailed(1, 25)); // After epoch 20

        // Verify jail count
        let state = ledger.get_validator_state(1).unwrap();
        assert_eq!(state.jail_count, 2);
    }

    #[test]
    fn test_in_memory_slashing_ledger_unjail() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);

        // Jail and then unjail
        ledger.jail_validator(1, 100).unwrap();
        assert!(ledger.is_jailed(1, 50));

        ledger.unjail_validator(1).unwrap();
        assert!(!ledger.is_jailed(1, 50));
    }

    #[test]
    fn test_in_memory_slashing_ledger_records() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000), (2, 200_000)]);

        // Store some slashing records
        let record1 = SlashingRecord {
            validator_id: 1,
            offense_kind: "O1_double_sign".to_string(),
            slashed_amount: 7_500,
            jailed: true,
            jailed_until_epoch: Some(10),
            height: 1000,
            view: 100,
            epoch: 5,
        };
        let record2 = SlashingRecord {
            validator_id: 2,
            offense_kind: "O2_invalid_proposer_sig".to_string(),
            slashed_amount: 10_000,
            jailed: false,
            jailed_until_epoch: None,
            height: 2000,
            view: 200,
            epoch: 6,
        };

        ledger.store_slashing_record(record1.clone()).unwrap();
        ledger.store_slashing_record(record2.clone()).unwrap();

        // Get records for validator 1
        let records_1 = ledger.get_slashing_records(1);
        assert_eq!(records_1.len(), 1);
        assert_eq!(records_1[0], record1);

        // Get all records
        let all_records = ledger.get_all_slashing_records();
        assert_eq!(all_records.len(), 2);
    }

    #[test]
    fn test_in_memory_slashing_ledger_validator_not_found() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);

        // Try to slash unknown validator
        let result = ledger.slash_stake(999, 100);
        assert!(matches!(
            result,
            Err(SlashingLedgerError::ValidatorNotFound(999))
        ));

        // Try to jail unknown validator
        let result = ledger.jail_validator(999, 10);
        assert!(matches!(
            result,
            Err(SlashingLedgerError::ValidatorNotFound(999))
        ));
    }

    #[test]
    fn test_in_memory_slashing_ledger_zero_slash() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100)]);

        // Slash 0 bps should result in 0 slashed
        let slashed = ledger.slash_stake(1, 0).unwrap();
        assert_eq!(slashed, 0);
        assert_eq!(ledger.get_stake(1), Some(100));
    }

    #[test]
    fn test_in_memory_slashing_ledger_full_slash() {
        let mut ledger = InMemorySlashingLedger::with_stakes(vec![(1, 100_000)]);

        // Slash 100% (10000 bps)
        let slashed = ledger.slash_stake(1, 10000).unwrap();
        assert_eq!(slashed, 100_000);
        assert_eq!(ledger.get_stake(1), Some(0));

        // Subsequent slashes should return 0
        let slashed2 = ledger.slash_stake(1, 750).unwrap();
        assert_eq!(slashed2, 0);
    }

    // ============================================================================
    // RocksDbSlashingLedger Tests (M1)
    // ============================================================================

    #[test]
    fn test_rocksdb_slashing_ledger_basic() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        // Initialize validators with stakes
        ledger.initialize_validator(1, 100_000).unwrap();
        ledger.initialize_validator(2, 200_000).unwrap();
        ledger.initialize_validator(3, 50_000).unwrap();

        // Verify initial state
        assert_eq!(ledger.get_stake(1), Some(100_000));
        assert_eq!(ledger.get_stake(2), Some(200_000));
        assert_eq!(ledger.get_stake(3), Some(50_000));
        assert_eq!(ledger.get_stake(999), None);

        // Slash validator 1 by 750 bps (7.5%)
        let slashed = ledger.slash_stake(1, 750).unwrap();
        assert_eq!(slashed, 7_500); // 100_000 * 750 / 10000 = 7500
        assert_eq!(ledger.get_stake(1), Some(92_500));

        // Verify total slashed
        assert_eq!(ledger.total_slashed(), 7_500);
    }

    #[test]
    fn test_rocksdb_slashing_ledger_jail() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        ledger.initialize_validator(1, 100_000).unwrap();
        ledger.initialize_validator(2, 200_000).unwrap();

        // Jail validator 1 until epoch 10
        let until = ledger.jail_validator(1, 10).unwrap();
        assert_eq!(until, 10);

        // Check jail status at various epochs
        assert!(ledger.is_jailed(1, 5)); // Before epoch 10
        assert!(ledger.is_jailed(1, 9)); // Still before epoch 10
        assert!(!ledger.is_jailed(1, 10)); // At epoch 10, no longer jailed
        assert!(!ledger.is_jailed(1, 15)); // After epoch 10

        // Validator 2 should not be jailed
        assert!(!ledger.is_jailed(2, 5));

        // Extend jail period
        ledger.jail_validator(1, 20).unwrap();
        assert!(ledger.is_jailed(1, 15)); // Now jailed until 20
        assert!(!ledger.is_jailed(1, 25)); // After epoch 20

        // Verify jail count
        let state = ledger.get_validator_state(1).unwrap();
        assert_eq!(state.jail_count, 2);
    }

    #[test]
    fn test_rocksdb_slashing_ledger_unjail() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        ledger.initialize_validator(1, 100_000).unwrap();

        // Jail and then unjail
        ledger.jail_validator(1, 100).unwrap();
        assert!(ledger.is_jailed(1, 50));

        ledger.unjail_validator(1).unwrap();
        assert!(!ledger.is_jailed(1, 50));
    }

    #[test]
    fn test_rocksdb_slashing_ledger_records() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        ledger.initialize_validator(1, 100_000).unwrap();
        ledger.initialize_validator(2, 200_000).unwrap();

        // Store some slashing records
        let record1 = SlashingRecord {
            validator_id: 1,
            offense_kind: "O1_double_sign".to_string(),
            slashed_amount: 7_500,
            jailed: true,
            jailed_until_epoch: Some(10),
            height: 1000,
            view: 100,
            epoch: 5,
        };
        let record2 = SlashingRecord {
            validator_id: 2,
            offense_kind: "O2_invalid_proposer_sig".to_string(),
            slashed_amount: 10_000,
            jailed: false,
            jailed_until_epoch: None,
            height: 2000,
            view: 200,
            epoch: 6,
        };

        ledger.store_slashing_record(record1.clone()).unwrap();
        ledger.store_slashing_record(record2.clone()).unwrap();

        // Get records for validator 1
        let records_1 = ledger.get_slashing_records(1);
        assert_eq!(records_1.len(), 1);
        assert_eq!(records_1[0], record1);

        // Get all records
        let all_records = ledger.get_all_slashing_records();
        assert_eq!(all_records.len(), 2);
    }

    #[test]
    fn test_rocksdb_slashing_ledger_validator_not_found() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        ledger.initialize_validator(1, 100_000).unwrap();

        // Try to slash unknown validator
        let result = ledger.slash_stake(999, 100);
        assert!(matches!(
            result,
            Err(SlashingLedgerError::ValidatorNotFound(999))
        ));

        // Try to jail unknown validator
        let result = ledger.jail_validator(999, 10);
        assert!(matches!(
            result,
            Err(SlashingLedgerError::ValidatorNotFound(999))
        ));
    }

    #[test]
    fn test_rocksdb_slashing_ledger_persistence() {
        let temp_dir = tempfile::tempdir().unwrap();

        // Write data in first session
        {
            let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();
            ledger.initialize_validator(1, 1_000_000).unwrap();
            ledger.initialize_validator(2, 2_000_000).unwrap();

            // Slash validator 1
            ledger.slash_stake(1, 750).unwrap();

            // Jail validator 2
            ledger.jail_validator(2, 100).unwrap();

            // Store a record
            let record = SlashingRecord {
                validator_id: 1,
                offense_kind: "O1_double_sign".to_string(),
                slashed_amount: 75_000,
                jailed: false,
                jailed_until_epoch: None,
                height: 500,
                view: 50,
                epoch: 10,
            };
            ledger.store_slashing_record(record).unwrap();

            // Mark evidence as seen
            let dedup_key = RocksDbSlashingLedger::format_dedup_key(1, "O1_double_sign", 500, 50);
            ledger.mark_evidence_seen(&dedup_key).unwrap();

            ledger.flush().unwrap();
        }

        // Reopen and verify data persisted
        {
            let ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

            // Check validator 1 state (slashed)
            let state1 = ledger.get_validator_state(1).unwrap();
            assert_eq!(state1.stake, 925_000); // 1M - 75K
            assert_eq!(state1.total_slashed, 75_000);

            // Check validator 2 state (jailed)
            let state2 = ledger.get_validator_state(2).unwrap();
            assert_eq!(state2.stake, 2_000_000);
            assert!(state2.jailed_until_epoch.is_some());
            assert_eq!(state2.jailed_until_epoch.unwrap(), 100);

            // Check record persisted
            let records = ledger.get_slashing_records(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].slashed_amount, 75_000);

            // Check evidence dedup marker persisted (loaded into cache)
            let dedup_key = RocksDbSlashingLedger::format_dedup_key(1, "O1_double_sign", 500, 50);
            assert!(ledger.is_evidence_seen(&dedup_key));

            // Check unknown evidence not seen
            let unknown_key =
                RocksDbSlashingLedger::format_dedup_key(999, "O1_double_sign", 999, 999);
            assert!(!ledger.is_evidence_seen(&unknown_key));
        }
    }

    #[test]
    fn test_rocksdb_slashing_ledger_evidence_dedup() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        let dedup_key = "1:O1_double_sign:100:50";

        // Initially not seen
        assert!(!ledger.is_evidence_seen(dedup_key));

        // Mark as seen
        ledger.mark_evidence_seen(dedup_key).unwrap();
        assert!(ledger.is_evidence_seen(dedup_key));

        // Mark again (should be no-op)
        ledger.mark_evidence_seen(dedup_key).unwrap();
        assert!(ledger.is_evidence_seen(dedup_key));
    }

    #[test]
    fn test_rocksdb_slashing_ledger_full_slash() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        ledger.initialize_validator(1, 100_000).unwrap();

        // Slash 100% (10000 bps)
        let slashed = ledger.slash_stake(1, 10000).unwrap();
        assert_eq!(slashed, 100_000);
        assert_eq!(ledger.get_stake(1), Some(0));

        // Subsequent slashes should return 0
        let slashed2 = ledger.slash_stake(1, 750).unwrap();
        assert_eq!(slashed2, 0);
    }

    #[test]
    fn test_rocksdb_slashing_ledger_last_offense_epoch() {
        let temp_dir = tempfile::tempdir().unwrap();
        let mut ledger = RocksDbSlashingLedger::open(temp_dir.path()).unwrap();

        ledger.initialize_validator(1, 100_000).unwrap();

        // Get initial state
        let state = ledger.get_validator_state(1).unwrap();
        assert!(state.last_offense_epoch.is_none());

        // The last_offense_epoch field is available for tracking (can be updated via
        // direct state modification if needed in future - for now it's tracked in records)
    }
}
