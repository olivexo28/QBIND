//! T232: Genesis & Launch State Specification v0
//!
//! This module defines the genesis state model for QBIND, including:
//! - Genesis configuration schema (JSON/TOML compatible)
//! - Rust types for genesis state validation
//! - Invariant checking for initial token supply, allocations, validators, council
//!
//! # Design Goals
//!
//! 1. **Auditable**: Clear schema with documented constraints
//! 2. **Replayable**: Deterministic genesis state from config
//! 3. **Validated**: Strong invariants checked at parse time
//!
//! # Schema Overview
//!
//! ```json
//! {
//!   "chain_id": "qbind-mainnet-v0",
//!   "genesis_time_unix_ms": 1738000000000,
//!   "allocations": [...],
//!   "validators": [...],
//!   "council": { "members": [...], "threshold": 2 },
//!   "monetary": { ... },
//!   "extra": {}
//! }
//! ```
//!
//! # Validation Rules
//!
//! - All allocation amounts must be > 0
//! - No duplicate addresses in allocations
//! - Validator count must be >= 1
//! - Council threshold must be <= member count and > 0
//! - Total supply (sum of allocations) must be > 0
//!
//! See: `docs/consensus/QBIND_GENESIS_AND_LAUNCH_DESIGN.md` for detailed design.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::MonetaryEngineConfig;

// ============================================================================
// Genesis Allocation
// ============================================================================

/// An initial token allocation in the genesis state.
///
/// Represents tokens assigned to an address at genesis, optionally with
/// lockup restrictions.
///
/// # Fields
///
/// - `address`: The recipient address (32-byte hex string)
/// - `amount`: Token amount in base units (must be > 0)
/// - `memo`: Optional human-readable description (e.g., "Foundation allocation")
/// - `lockup_until_unix_ms`: Optional lockup expiry timestamp (tokens frozen until this time)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAllocation {
    /// Recipient address (32-byte hex string, e.g., "0x123...abc").
    pub address: String,

    /// Token amount in base units (smallest denomination).
    /// Must be > 0.
    pub amount: u128,

    /// Optional human-readable memo for this allocation.
    /// Used for audit trails and documentation (e.g., "Early contributor", "Treasury").
    #[serde(default)]
    pub memo: Option<String>,

    /// Optional lockup expiry timestamp (Unix milliseconds).
    /// If set, tokens cannot be transferred until this time.
    /// If None, tokens are immediately liquid.
    #[serde(default)]
    pub lockup_until_unix_ms: Option<u64>,
}

impl GenesisAllocation {
    /// Create a new unlocked allocation.
    pub fn new(address: impl Into<String>, amount: u128) -> Self {
        Self {
            address: address.into(),
            amount,
            memo: None,
            lockup_until_unix_ms: None,
        }
    }

    /// Create a new allocation with lockup.
    pub fn with_lockup(
        address: impl Into<String>,
        amount: u128,
        lockup_until_unix_ms: u64,
    ) -> Self {
        Self {
            address: address.into(),
            amount,
            memo: None,
            lockup_until_unix_ms: Some(lockup_until_unix_ms),
        }
    }

    /// Create a new allocation with memo.
    pub fn with_memo(address: impl Into<String>, amount: u128, memo: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            amount,
            memo: Some(memo.into()),
            lockup_until_unix_ms: None,
        }
    }
}

// ============================================================================
// Genesis Validator
// ============================================================================

/// An initial validator in the genesis state.
///
/// Represents a validator in the initial validator set, including their
/// PQC public key material and initial stake.
///
/// # PQC Key Material
///
/// The `pqc_public_key` field contains the ML-DSA-44 public key encoded
/// as a hex string. This key is used for consensus signing and verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisValidator {
    /// Validator address (32-byte hex string).
    pub address: String,

    /// PQC public key (ML-DSA-44) as hex string.
    /// This is the validator's signing key for consensus operations.
    pub pqc_public_key: String,

    /// Initial stake amount in base units.
    /// Must be > 0 for active validators.
    pub stake: u128,

    /// Optional human-readable name or identifier.
    #[serde(default)]
    pub name: Option<String>,

    /// Optional validator metadata (e.g., website, contact info).
    #[serde(default)]
    pub metadata: Option<String>,
}

impl GenesisValidator {
    /// Create a new genesis validator.
    pub fn new(address: impl Into<String>, pqc_public_key: impl Into<String>, stake: u128) -> Self {
        Self {
            address: address.into(),
            pqc_public_key: pqc_public_key.into(),
            stake,
            name: None,
            metadata: None,
        }
    }

    /// Create a genesis validator with name.
    pub fn with_name(
        address: impl Into<String>,
        pqc_public_key: impl Into<String>,
        stake: u128,
        name: impl Into<String>,
    ) -> Self {
        Self {
            address: address.into(),
            pqc_public_key: pqc_public_key.into(),
            stake,
            name: Some(name.into()),
            metadata: None,
        }
    }
}

// ============================================================================
// Genesis Council Configuration
// ============================================================================

/// Configuration for the initial governance council.
///
/// The council is a multisig body that can authorize protocol upgrades
/// and emergency actions. The threshold specifies the minimum number
/// of council member signatures required for authorization.
///
/// # Invariants
///
/// - `threshold` must be > 0
/// - `threshold` must be <= members.len()
/// - All member addresses must be distinct
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisCouncilConfig {
    /// Council member addresses (32-byte hex strings).
    /// Each member can sign council proposals.
    pub members: Vec<String>,

    /// Minimum signatures required for council authorization.
    /// Must be > 0 and <= members.len().
    pub threshold: u32,
}

impl GenesisCouncilConfig {
    /// Create a new council configuration.
    pub fn new(members: Vec<String>, threshold: u32) -> Self {
        Self { members, threshold }
    }

    /// Validate the council configuration.
    ///
    /// Returns `Err` if:
    /// - threshold is 0
    /// - threshold > members.len()
    /// - members contains duplicates
    pub fn validate(&self) -> Result<(), GenesisValidationError> {
        // Check threshold bounds
        if self.threshold == 0 {
            return Err(GenesisValidationError::CouncilThresholdZero);
        }
        if self.threshold as usize > self.members.len() {
            return Err(GenesisValidationError::CouncilThresholdTooHigh {
                threshold: self.threshold,
                member_count: self.members.len(),
            });
        }

        // Check for duplicate members
        let mut seen = HashSet::new();
        for member in &self.members {
            if !seen.insert(member.clone()) {
                return Err(GenesisValidationError::DuplicateCouncilMember {
                    address: member.clone(),
                });
            }
        }

        Ok(())
    }
}

// ============================================================================
// Run 101: Genesis Authority Fields
// ============================================================================
//
// These types add an *additive*, backward-compatible authority surface to the
// genesis configuration as the first implementation step after Run 100's
// `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md` design.
//
// Scope (Run 101): represent and **hash-bind** the initial production
// PQC transport / bundle-signing-authority roots and authority-policy
// metadata. **Not consumed** for live bundle-signing-key ratification — that
// is Run 102+. See `docs/whitepaper/contradiction.md` Run 101 update for the
// explicit non-claims.
//
// Design decisions (mirroring Run 100 spec §5, §6, §7):
//   * additive: existing DevNet genesis without `authority` continues to
//     parse and validate, but MainNet/TestNet refuse missing/empty roots.
//   * MainNet must NOT come from source-code static constants — only from a
//     genesis file bound by `compute_canonical_genesis_hash`.
//   * authority fields participate in the canonical genesis hash (domain
//     `QBIND:GENESIS:v1`) so any change to roots, policy version, or
//     authority sequence produces a different hash.

/// Suite identifier for a PQC trust-anchor key (ML-DSA-44 = 100).
///
/// Stored as a raw `u8` to mirror the on-wire suite-id encoding already used
/// throughout `qbind-net` / `qbind-crypto`. The set of accepted values for
/// MainNet is intentionally narrow and is enforced by
/// [`GenesisAuthorityRoot::validate`].
pub type GenesisAuthoritySuiteId = u8;

/// Suite-id constant for ML-DSA-44 PQC signature keys.
///
/// This mirrors the `100` value used by `qbind-types::SuiteId::MlDsa44` /
/// `qbind_types::genesis_suite_registry` and the Run 050+ trust-bundle
/// signer suite. The genesis authority layer accepts only this suite for
/// MainNet (Run 100 spec §5.3, §7.3).
pub const GENESIS_AUTHORITY_SUITE_ML_DSA_44: GenesisAuthoritySuiteId = 100;

/// Minimum allowed length (in raw bytes) for a hex-encoded authority-root
/// key fingerprint.
///
/// Run 101 stores fingerprints as hex strings (consistent with the existing
/// `GenesisValidator::pqc_public_key` representation). A 32-byte SHA3-256
/// fingerprint is 64 hex characters; we accept anything from 32 hex
/// characters (16 bytes, e.g. truncated key id) up to a full PQC public key
/// (~5KB hex). MainNet enforces the 64-hex (32-byte) minimum.
pub const GENESIS_AUTHORITY_FINGERPRINT_MIN_HEX_DEVNET: usize = 32;

/// MainNet/TestNet minimum hex length for an authority-root fingerprint
/// (32 raw bytes = 64 hex characters). Equal to a SHA3-256 digest length.
pub const GENESIS_AUTHORITY_FINGERPRINT_MIN_HEX_PROD: usize = 64;

/// Hex-string upper bound for a single authority root entry (safety guard
/// against accidental multi-megabyte blobs in a genesis file).
pub const GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX: usize = 16 * 1024;

/// Current authority-policy schema version. Run 101 = `1`. Future runs that
/// extend the authority surface MUST bump this constant and document the
/// migration in `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`.
pub const GENESIS_AUTHORITY_POLICY_VERSION_RUN_101: u32 = 1;

/// One entry in the initial PQC trust-anchor / bundle-signing-authority root
/// set, as expressed in the genesis configuration file.
///
/// Run 101 only hash-binds these entries — they are **not** yet consumed by
/// the in-binary ratification verifier (that lands in Run 102). Each entry
/// is intentionally minimal:
///
/// * `suite_id` — PQC suite identifier (must be `ML-DSA-44 = 100` on MainNet).
/// * `key_fingerprint` — lowercase hex of either the full PQC public key
///   bytes or the SHA3-256 fingerprint of the key (operators choose, but
///   MainNet requires ≥ 64 hex chars = 32 raw bytes).
/// * `label` — operator-facing identifier (e.g. `"foundation-root-1"`).
///   Must be non-empty; included in the canonical hash; never used for
///   trust decisions.
/// * `not_before_epoch` — optional epoch at which this root becomes valid;
///   reserved for Run 102+. When `Some`, the value is hash-bound but not
///   enforced by Run 101.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAuthorityRoot {
    /// PQC suite identifier. MainNet MUST be `100` (ML-DSA-44).
    pub suite_id: GenesisAuthoritySuiteId,

    /// Lowercase hex fingerprint or full public key.
    pub key_fingerprint: String,

    /// Operator-facing label. Non-empty; hash-bound; not used for trust.
    pub label: String,

    /// Reserved for Run 102+ activation gating. Hash-bound only.
    #[serde(default)]
    pub not_before_epoch: Option<u64>,
}

impl GenesisAuthorityRoot {
    /// Construct a new authority root entry. Performs no validation.
    pub fn new(
        suite_id: GenesisAuthoritySuiteId,
        key_fingerprint: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        Self {
            suite_id,
            key_fingerprint: key_fingerprint.into(),
            label: label.into(),
            not_before_epoch: None,
        }
    }

    /// Validate this root against the per-environment policy.
    ///
    /// MainNet/TestNet rules:
    ///   * `suite_id` must equal `GENESIS_AUTHORITY_SUITE_ML_DSA_44`.
    ///   * `key_fingerprint` must be valid lowercase hex (no `0x` prefix),
    ///     length in `[64, GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX]`,
    ///     even length.
    ///   * `label` must be non-empty.
    ///
    /// DevNet relaxes the suite-id and fingerprint-length checks to allow
    /// helper-generated short fingerprints in legacy local tests.
    pub fn validate(
        &self,
        env: NetworkEnvironmentPolicy,
        kind: GenesisAuthorityRootKind,
    ) -> Result<(), GenesisAuthorityValidationError> {
        if self.label.is_empty() {
            return Err(GenesisAuthorityValidationError::EmptyLabel { kind });
        }
        let hex = &self.key_fingerprint;
        if hex.is_empty() {
            return Err(GenesisAuthorityValidationError::EmptyFingerprint {
                kind,
                label: self.label.clone(),
            });
        }
        if hex.len() % 2 != 0 {
            return Err(GenesisAuthorityValidationError::MalformedFingerprint {
                kind,
                label: self.label.clone(),
                reason: "hex length must be even".into(),
            });
        }
        if hex.len() > GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX {
            return Err(GenesisAuthorityValidationError::MalformedFingerprint {
                kind,
                label: self.label.clone(),
                reason: format!(
                    "hex length {} exceeds maximum {}",
                    hex.len(),
                    GENESIS_AUTHORITY_FINGERPRINT_MAX_HEX
                ),
            });
        }
        if !hex
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
        {
            return Err(GenesisAuthorityValidationError::MalformedFingerprint {
                kind,
                label: self.label.clone(),
                reason: "fingerprint must be lowercase hex without 0x prefix".into(),
            });
        }
        let min_hex = match env {
            NetworkEnvironmentPolicy::Devnet => GENESIS_AUTHORITY_FINGERPRINT_MIN_HEX_DEVNET,
            NetworkEnvironmentPolicy::Testnet | NetworkEnvironmentPolicy::Mainnet => {
                GENESIS_AUTHORITY_FINGERPRINT_MIN_HEX_PROD
            }
        };
        if hex.len() < min_hex {
            return Err(GenesisAuthorityValidationError::MalformedFingerprint {
                kind,
                label: self.label.clone(),
                reason: format!(
                    "hex length {} below minimum {} for environment {:?}",
                    hex.len(),
                    min_hex,
                    env
                ),
            });
        }
        match env {
            NetworkEnvironmentPolicy::Mainnet | NetworkEnvironmentPolicy::Testnet => {
                if self.suite_id != GENESIS_AUTHORITY_SUITE_ML_DSA_44 {
                    return Err(GenesisAuthorityValidationError::UnsupportedSuite {
                        kind,
                        label: self.label.clone(),
                        suite_id: self.suite_id,
                    });
                }
            }
            NetworkEnvironmentPolicy::Devnet => { /* permissive */ }
        }
        Ok(())
    }
}

/// Discriminator for error messages: which kind of root we are validating.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GenesisAuthorityRootKind {
    /// `authority.pqc_transport_roots[..]`
    Transport,
    /// `authority.bundle_signing_authority_roots[..]`
    BundleSigning,
}

impl std::fmt::Display for GenesisAuthorityRootKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisAuthorityRootKind::Transport => write!(f, "pqc_transport_root"),
            GenesisAuthorityRootKind::BundleSigning => write!(f, "bundle_signing_authority_root"),
        }
    }
}

/// Minimal per-environment policy enum used by Run 101 genesis validation.
///
/// This is a local mirror of `qbind_types::NetworkEnvironment` to avoid
/// pulling `qbind-types` into `qbind-ledger`'s public API surface for the
/// authority validator. Callers in `qbind-node` map their
/// `NetworkEnvironment` to this enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NetworkEnvironmentPolicy {
    /// Development network — permissive.
    Devnet,
    /// Public test network — production-shape rules except where explicitly
    /// relaxed (see `validate_for_environment`).
    Testnet,
    /// Production main network — strictest fail-closed rules.
    Mainnet,
}

impl NetworkEnvironmentPolicy {
    /// ASCII scope tag used as part of the canonical genesis-hash
    /// domain-separator (matches `qbind_types::NetworkEnvironment::scope`).
    pub const fn scope(&self) -> &'static str {
        match self {
            NetworkEnvironmentPolicy::Devnet => "DEV",
            NetworkEnvironmentPolicy::Testnet => "TST",
            NetworkEnvironmentPolicy::Mainnet => "MAIN",
        }
    }
}

/// Genesis authority configuration block (Run 101).
///
/// Additive, hash-bound, and validated per environment. Not yet consumed by
/// any live ratification verifier — that is Run 102+ scope (see Run 100
/// spec §5 / §8 / §13 and `docs/whitepaper/contradiction.md` Run 101 update).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenesisAuthorityConfig {
    /// Authority-policy schema version. Run 101 = `1`. MainNet/TestNet
    /// refuse `0` and refuse any value greater than this binary's known
    /// maximum (currently `1`).
    pub authority_policy_version: u32,

    /// Monotonic authority-sequence anchor for Run 102+ anti-rollback. Run
    /// 101 hash-binds this value but does NOT persist it (no
    /// `<data_dir>/pqc_authority_state.json` yet).
    #[serde(default)]
    pub authority_sequence: u64,

    /// Optional authority-activation epoch. Hash-bound only in Run 101.
    #[serde(default)]
    pub authority_epoch: Option<u64>,

    /// Initial PQC transport trust anchors (e.g. KEMTLS leaf-cert issuers).
    /// Run 101 only hash-binds these entries; consumption by the transport
    /// layer remains a Run 102+ topic.
    #[serde(default)]
    pub pqc_transport_roots: Vec<GenesisAuthorityRoot>,

    /// Initial bundle-signing-authority roots. Run 101 only hash-binds; the
    /// in-binary ratification verifier lands in Run 102.
    pub bundle_signing_authority_roots: Vec<GenesisAuthorityRoot>,
}

impl GenesisAuthorityConfig {
    /// Construct an authority block with the current Run 101 policy version.
    pub fn new(bundle_signing_authority_roots: Vec<GenesisAuthorityRoot>) -> Self {
        Self {
            authority_policy_version: GENESIS_AUTHORITY_POLICY_VERSION_RUN_101,
            authority_sequence: 0,
            authority_epoch: None,
            pqc_transport_roots: Vec::new(),
            bundle_signing_authority_roots,
        }
    }

    /// Validate this authority block against the per-environment policy.
    ///
    /// MainNet rules (fail-closed):
    ///   * `authority_policy_version` in `[1, GENESIS_AUTHORITY_POLICY_VERSION_RUN_101]`.
    ///   * `bundle_signing_authority_roots` non-empty.
    ///   * Every root validates per `GenesisAuthorityRoot::validate(Mainnet, _)`.
    ///   * No duplicate `(suite_id, key_fingerprint)` pairs across the
    ///     combined transport + bundle-signing sets.
    ///
    /// TestNet rules: identical to MainNet except that an empty
    /// `pqc_transport_roots` is allowed (Run 101 does not yet wire transport
    /// roots).
    ///
    /// DevNet rules: permissive — empty sets are allowed, but if entries
    /// are present they must still pass the relaxed per-root validation.
    pub fn validate_for_environment(
        &self,
        env: NetworkEnvironmentPolicy,
    ) -> Result<(), GenesisAuthorityValidationError> {
        if self.authority_policy_version == 0 {
            return Err(GenesisAuthorityValidationError::InvalidPolicyVersion {
                got: self.authority_policy_version,
                max_supported: GENESIS_AUTHORITY_POLICY_VERSION_RUN_101,
            });
        }
        if self.authority_policy_version > GENESIS_AUTHORITY_POLICY_VERSION_RUN_101 {
            return Err(GenesisAuthorityValidationError::InvalidPolicyVersion {
                got: self.authority_policy_version,
                max_supported: GENESIS_AUTHORITY_POLICY_VERSION_RUN_101,
            });
        }

        // MainNet & TestNet require a non-empty bundle-signing root set.
        // DevNet is permissive (legacy local tests).
        if matches!(
            env,
            NetworkEnvironmentPolicy::Mainnet | NetworkEnvironmentPolicy::Testnet
        ) && self.bundle_signing_authority_roots.is_empty()
        {
            return Err(GenesisAuthorityValidationError::EmptyBundleSigningRoots);
        }

        for root in &self.pqc_transport_roots {
            root.validate(env, GenesisAuthorityRootKind::Transport)?;
        }
        for root in &self.bundle_signing_authority_roots {
            root.validate(env, GenesisAuthorityRootKind::BundleSigning)?;
        }

        // Reject duplicate (suite_id, key_fingerprint) pairs across the
        // combined set. Duplicates would silently inflate the authority
        // surface and are never intended.
        let mut seen = HashSet::new();
        for root in self
            .pqc_transport_roots
            .iter()
            .chain(self.bundle_signing_authority_roots.iter())
        {
            let key = (root.suite_id, root.key_fingerprint.as_str());
            if !seen.insert(key) {
                return Err(GenesisAuthorityValidationError::DuplicateAuthorityRoot {
                    suite_id: root.suite_id,
                    key_fingerprint: root.key_fingerprint.clone(),
                });
            }
        }

        Ok(())
    }
}

/// Errors returned by [`GenesisAuthorityConfig::validate_for_environment`]
/// and [`GenesisAuthorityRoot::validate`].
///
/// All variants produce operator-facing messages with the precise reason —
/// no vague "invalid config" errors. Mirrors the precision required by the
/// Run 101 task ("logging / operator error messages" section).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisAuthorityValidationError {
    /// `authority` block is absent and required by the current environment.
    Missing { env: NetworkEnvironmentPolicy },

    /// `authority_policy_version` is zero or beyond this binary's max.
    InvalidPolicyVersion { got: u32, max_supported: u32 },

    /// MainNet/TestNet requires at least one bundle-signing root.
    EmptyBundleSigningRoots,

    /// Authority root entry has an empty `label`.
    EmptyLabel { kind: GenesisAuthorityRootKind },

    /// Authority root entry has an empty hex `key_fingerprint`.
    EmptyFingerprint {
        kind: GenesisAuthorityRootKind,
        label: String,
    },

    /// Authority root entry has a malformed hex `key_fingerprint`.
    MalformedFingerprint {
        kind: GenesisAuthorityRootKind,
        label: String,
        reason: String,
    },

    /// Authority root entry uses a suite not allowed by environment policy.
    UnsupportedSuite {
        kind: GenesisAuthorityRootKind,
        label: String,
        suite_id: GenesisAuthoritySuiteId,
    },

    /// Duplicate `(suite_id, key_fingerprint)` across the combined root set.
    DuplicateAuthorityRoot {
        suite_id: GenesisAuthoritySuiteId,
        key_fingerprint: String,
    },

    /// The genesis `chain_id` does not match the runtime environment scope.
    ChainEnvironmentMismatch {
        chain_id: String,
        env: NetworkEnvironmentPolicy,
    },
}

impl std::fmt::Display for GenesisAuthorityValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisAuthorityValidationError::Missing { env } => write!(
                f,
                "genesis authority block is required for environment {:?} but is missing",
                env
            ),
            GenesisAuthorityValidationError::InvalidPolicyVersion { got, max_supported } => write!(
                f,
                "genesis authority_policy_version {} invalid: must be in 1..={}",
                got, max_supported
            ),
            GenesisAuthorityValidationError::EmptyBundleSigningRoots => write!(
                f,
                "genesis bundle_signing_authority_roots must be non-empty for MainNet/TestNet"
            ),
            GenesisAuthorityValidationError::EmptyLabel { kind } => {
                write!(f, "genesis {} has empty label", kind)
            }
            GenesisAuthorityValidationError::EmptyFingerprint { kind, label } => write!(
                f,
                "genesis {} '{}' has empty key_fingerprint",
                kind, label
            ),
            GenesisAuthorityValidationError::MalformedFingerprint {
                kind,
                label,
                reason,
            } => write!(
                f,
                "genesis {} '{}' has malformed key_fingerprint: {}",
                kind, label, reason
            ),
            GenesisAuthorityValidationError::UnsupportedSuite {
                kind,
                label,
                suite_id,
            } => write!(
                f,
                "genesis {} '{}' uses unsupported suite_id {} (MainNet/TestNet require ML-DSA-44 = {})",
                kind, label, suite_id, GENESIS_AUTHORITY_SUITE_ML_DSA_44
            ),
            GenesisAuthorityValidationError::DuplicateAuthorityRoot {
                suite_id,
                key_fingerprint,
            } => write!(
                f,
                "genesis authority duplicate root: suite_id={} key_fingerprint={}",
                suite_id, key_fingerprint
            ),
            GenesisAuthorityValidationError::ChainEnvironmentMismatch { chain_id, env } => write!(
                f,
                "genesis chain_id '{}' does not match runtime environment {:?}",
                chain_id, env
            ),
        }
    }
}

impl std::error::Error for GenesisAuthorityValidationError {}

// ============================================================================
// Genesis Monetary Configuration
// ============================================================================

/// Monetary engine configuration for genesis.
///
/// This wraps the `MonetaryEngineConfig` from the monetary engine module
/// and adds genesis-specific validation.
///
/// # Initial Parameters
///
/// The genesis monetary config establishes the initial monetary policy:
/// - PQC premiums for compute, bandwidth, and storage
/// - Phase-specific parameters (Bootstrap, Transition, Mature)
/// - Alpha fee offset factor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisMonetaryConfig {
    /// PQC compute premium (β_compute): higher CPU cost for ML-DSA-44 verification.
    /// Typical range: 0.20–0.35.
    pub pqc_premium_compute: f64,

    /// PQC bandwidth premium (β_bandwidth): larger signature sizes.
    /// Typical range: 0.10–0.20.
    pub pqc_premium_bandwidth: f64,

    /// PQC storage premium (β_storage): larger state footprint.
    /// Typical range: 0.05–0.15.
    pub pqc_premium_storage: f64,

    /// Bootstrap phase: target annual inflation rate.
    pub bootstrap_r_target_annual: f64,

    /// Bootstrap phase: inflation floor (typically 0.0).
    pub bootstrap_inflation_floor_annual: f64,

    /// Bootstrap phase: maximum annual inflation cap.
    pub bootstrap_max_annual_inflation_cap: f64,

    /// Bootstrap phase: EMA lambda in basis points.
    pub bootstrap_ema_lambda_bps: u16,

    /// Bootstrap phase: max Δr per epoch in basis points.
    pub bootstrap_max_delta_r_per_epoch_bps: u32,

    /// Transition phase: target annual inflation rate.
    pub transition_r_target_annual: f64,

    /// Transition phase: inflation floor (typically 0.0).
    pub transition_inflation_floor_annual: f64,

    /// Transition phase: maximum annual inflation cap.
    pub transition_max_annual_inflation_cap: f64,

    /// Transition phase: EMA lambda in basis points.
    pub transition_ema_lambda_bps: u16,

    /// Transition phase: max Δr per epoch in basis points.
    pub transition_max_delta_r_per_epoch_bps: u32,

    /// Mature phase: target annual inflation rate.
    pub mature_r_target_annual: f64,

    /// Mature phase: inflation floor (typically > 0).
    pub mature_inflation_floor_annual: f64,

    /// Mature phase: maximum annual inflation cap.
    pub mature_max_annual_inflation_cap: f64,

    /// Mature phase: EMA lambda in basis points.
    pub mature_ema_lambda_bps: u16,

    /// Mature phase: max Δr per epoch in basis points.
    pub mature_max_delta_r_per_epoch_bps: u32,

    /// Alpha fee offset factor (typically 1.0).
    pub alpha_fee_offset: f64,
}

impl GenesisMonetaryConfig {
    /// Create a genesis monetary config from a MonetaryEngineConfig.
    pub fn from_engine_config(config: &MonetaryEngineConfig) -> Self {
        Self {
            pqc_premium_compute: config.pqc_premium_compute,
            pqc_premium_bandwidth: config.pqc_premium_bandwidth,
            pqc_premium_storage: config.pqc_premium_storage,
            bootstrap_r_target_annual: config.bootstrap.r_target_annual,
            bootstrap_inflation_floor_annual: config.bootstrap.inflation_floor_annual,
            bootstrap_max_annual_inflation_cap: config.bootstrap.max_annual_inflation_cap,
            bootstrap_ema_lambda_bps: config.bootstrap.ema_lambda_bps,
            bootstrap_max_delta_r_per_epoch_bps: config.bootstrap.max_delta_r_inf_per_epoch_bps,
            transition_r_target_annual: config.transition.r_target_annual,
            transition_inflation_floor_annual: config.transition.inflation_floor_annual,
            transition_max_annual_inflation_cap: config.transition.max_annual_inflation_cap,
            transition_ema_lambda_bps: config.transition.ema_lambda_bps,
            transition_max_delta_r_per_epoch_bps: config.transition.max_delta_r_inf_per_epoch_bps,
            mature_r_target_annual: config.mature.r_target_annual,
            mature_inflation_floor_annual: config.mature.inflation_floor_annual,
            mature_max_annual_inflation_cap: config.mature.max_annual_inflation_cap,
            mature_ema_lambda_bps: config.mature.ema_lambda_bps,
            mature_max_delta_r_per_epoch_bps: config.mature.max_delta_r_inf_per_epoch_bps,
            alpha_fee_offset: config.alpha_fee_offset,
        }
    }

    /// Convert to a MonetaryEngineConfig.
    pub fn to_engine_config(&self) -> MonetaryEngineConfig {
        use crate::PhaseParameters;

        MonetaryEngineConfig {
            pqc_premium_compute: self.pqc_premium_compute,
            pqc_premium_bandwidth: self.pqc_premium_bandwidth,
            pqc_premium_storage: self.pqc_premium_storage,
            bootstrap: PhaseParameters {
                r_target_annual: self.bootstrap_r_target_annual,
                inflation_floor_annual: self.bootstrap_inflation_floor_annual,
                fee_smoothing_half_life_days: 30.0, // Default value
                max_annual_inflation_cap: self.bootstrap_max_annual_inflation_cap,
                ema_lambda_bps: self.bootstrap_ema_lambda_bps,
                max_delta_r_inf_per_epoch_bps: self.bootstrap_max_delta_r_per_epoch_bps,
            },
            transition: PhaseParameters {
                r_target_annual: self.transition_r_target_annual,
                inflation_floor_annual: self.transition_inflation_floor_annual,
                fee_smoothing_half_life_days: 60.0, // Default value
                max_annual_inflation_cap: self.transition_max_annual_inflation_cap,
                ema_lambda_bps: self.transition_ema_lambda_bps,
                max_delta_r_inf_per_epoch_bps: self.transition_max_delta_r_per_epoch_bps,
            },
            mature: PhaseParameters {
                r_target_annual: self.mature_r_target_annual,
                inflation_floor_annual: self.mature_inflation_floor_annual,
                fee_smoothing_half_life_days: 90.0, // Default value
                max_annual_inflation_cap: self.mature_max_annual_inflation_cap,
                ema_lambda_bps: self.mature_ema_lambda_bps,
                max_delta_r_inf_per_epoch_bps: self.mature_max_delta_r_per_epoch_bps,
            },
            alpha_fee_offset: self.alpha_fee_offset,
        }
    }

    /// Create a default MainNet monetary configuration.
    pub fn mainnet_default() -> Self {
        Self {
            pqc_premium_compute: 0.30,
            pqc_premium_bandwidth: 0.15,
            pqc_premium_storage: 0.10,
            bootstrap_r_target_annual: 0.05,
            bootstrap_inflation_floor_annual: 0.0,
            bootstrap_max_annual_inflation_cap: 0.12,
            bootstrap_ema_lambda_bps: 700,
            bootstrap_max_delta_r_per_epoch_bps: 25,
            transition_r_target_annual: 0.04,
            transition_inflation_floor_annual: 0.0,
            transition_max_annual_inflation_cap: 0.10,
            transition_ema_lambda_bps: 300,
            transition_max_delta_r_per_epoch_bps: 10,
            mature_r_target_annual: 0.03,
            mature_inflation_floor_annual: 0.01,
            mature_max_annual_inflation_cap: 0.08,
            mature_ema_lambda_bps: 150,
            mature_max_delta_r_per_epoch_bps: 5,
            alpha_fee_offset: 1.0,
        }
    }
}

// ============================================================================
// Top-Level Genesis Configuration
// ============================================================================

/// Top-level genesis configuration for QBIND.
///
/// This is the canonical schema for `genesis.json`. It defines:
/// - Chain identity (chain_id, genesis_time)
/// - Initial token allocations
/// - Initial validator set
/// - Initial governance council
/// - Initial monetary parameters
///
/// # Validation
///
/// Call `validate()` after parsing to check all invariants:
/// - All allocations have amount > 0
/// - No duplicate addresses in allocations
/// - At least one validator
/// - Council threshold is valid
/// - Total supply > 0
///
/// # Example (JSON)
///
/// ```json
/// {
///   "chain_id": "qbind-mainnet-v0",
///   "genesis_time_unix_ms": 1738000000000,
///   "allocations": [
///     { "address": "0x123...", "amount": 1000000000, "memo": "Foundation" }
///   ],
///   "validators": [
///     { "address": "0xabc...", "pqc_public_key": "...", "stake": 100000 }
///   ],
///   "council": { "members": ["0x111...", "0x222...", "0x333..."], "threshold": 2 },
///   "monetary": { ... }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    /// Chain identifier (e.g., "qbind-mainnet-v0", "qbind-testnet-beta").
    ///
    /// This value MUST match the chain_id used by all nodes on the network.
    /// It is embedded in all domain-separated signatures to prevent cross-chain replay.
    pub chain_id: String,

    /// Genesis timestamp (Unix milliseconds).
    ///
    /// The canonical start time of the blockchain. All nodes MUST agree on this value.
    /// Used for time-based lockup validation and historical reference.
    pub genesis_time_unix_ms: u64,

    /// Initial token allocations.
    ///
    /// Defines the initial token distribution at genesis. The sum of all amounts
    /// is the total initial supply.
    pub allocations: Vec<GenesisAllocation>,

    /// Initial validator set.
    ///
    /// Defines the validators that can participate in consensus from genesis.
    /// Must contain at least one validator.
    pub validators: Vec<GenesisValidator>,

    /// Initial governance council configuration.
    ///
    /// Defines the multisig council for protocol upgrades and emergency actions.
    pub council: GenesisCouncilConfig,

    /// Initial monetary engine parameters.
    ///
    /// Defines the starting monetary policy parameters (inflation targets, premiums, etc.).
    pub monetary: GenesisMonetaryConfig,

    /// Reserved for future extensions.
    ///
    /// Additional fields can be stored here without breaking schema compatibility.
    /// This allows adding new genesis features without changing the core schema.
    #[serde(default)]
    pub extra: serde_json::Value,

    /// Run 101: optional genesis authority block.
    ///
    /// **Additive and backward-compatible:** existing DevNet/test genesis
    /// JSON files without this field continue to parse cleanly.
    /// MainNet/TestNet require `authority` to be present and validated by
    /// [`GenesisConfig::validate_for_environment`].
    ///
    /// The authority block is included in the canonical genesis hash
    /// (see [`compute_canonical_genesis_hash`]). Any change to the authority
    /// roots, policy version, sequence, or epoch produces a different hash.
    ///
    /// Not yet consumed by any live ratification verifier — see
    /// `docs/whitepaper/contradiction.md` Run 101 update for the explicit
    /// non-claims.
    #[serde(default)]
    pub authority: Option<GenesisAuthorityConfig>,
}

impl GenesisConfig {
    /// Create a new genesis configuration.
    pub fn new(
        chain_id: impl Into<String>,
        genesis_time_unix_ms: u64,
        allocations: Vec<GenesisAllocation>,
        validators: Vec<GenesisValidator>,
        council: GenesisCouncilConfig,
        monetary: GenesisMonetaryConfig,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis_time_unix_ms,
            allocations,
            validators,
            council,
            monetary,
            extra: serde_json::Value::Null,
            authority: None,
        }
    }

    /// Validate the genesis configuration.
    ///
    /// Checks all invariants:
    /// - All allocations have amount > 0
    /// - No duplicate addresses in allocations
    /// - At least one validator
    /// - Council threshold is valid
    /// - Total supply > 0
    /// - Chain ID is non-empty
    ///
    /// Returns `Err(GenesisValidationError)` if any invariant is violated.
    pub fn validate(&self) -> Result<(), GenesisValidationError> {
        // Check chain_id is non-empty
        if self.chain_id.is_empty() {
            return Err(GenesisValidationError::EmptyChainId);
        }

        // Check allocations
        if self.allocations.is_empty() {
            return Err(GenesisValidationError::NoAllocations);
        }

        let mut seen_addresses = HashSet::new();
        let mut total_supply: u128 = 0;

        for alloc in &self.allocations {
            // Check amount > 0
            if alloc.amount == 0 {
                return Err(GenesisValidationError::ZeroAllocationAmount {
                    address: alloc.address.clone(),
                });
            }

            // Check for empty address
            if alloc.address.is_empty() {
                return Err(GenesisValidationError::EmptyAddress);
            }

            // Check for duplicate addresses
            if !seen_addresses.insert(alloc.address.clone()) {
                return Err(GenesisValidationError::DuplicateAllocationAddress {
                    address: alloc.address.clone(),
                });
            }

            // Accumulate total supply (check for overflow)
            total_supply = total_supply
                .checked_add(alloc.amount)
                .ok_or(GenesisValidationError::TotalSupplyOverflow)?;
        }

        // Check total supply > 0 (implied by non-empty allocations with amount > 0)
        if total_supply == 0 {
            return Err(GenesisValidationError::ZeroTotalSupply);
        }

        // Check validators
        if self.validators.is_empty() {
            return Err(GenesisValidationError::NoValidators);
        }

        // Check validator addresses are distinct and non-empty
        let mut validator_addresses = HashSet::new();
        for validator in &self.validators {
            if validator.address.is_empty() {
                return Err(GenesisValidationError::EmptyAddress);
            }
            if validator.pqc_public_key.is_empty() {
                return Err(GenesisValidationError::EmptyValidatorPqcKey {
                    address: validator.address.clone(),
                });
            }
            if !validator_addresses.insert(validator.address.clone()) {
                return Err(GenesisValidationError::DuplicateValidatorAddress {
                    address: validator.address.clone(),
                });
            }
        }

        // Validate council configuration
        self.council.validate()?;

        Ok(())
    }

    /// Compute the total initial supply from allocations.
    pub fn total_supply(&self) -> u128 {
        self.allocations.iter().map(|a| a.amount).sum()
    }

    /// Get the number of initial validators.
    pub fn validator_count(&self) -> usize {
        self.validators.len()
    }

    /// Get the number of council members.
    pub fn council_member_count(&self) -> usize {
        self.council.members.len()
    }

    /// Run 101: per-environment genesis validation.
    ///
    /// In addition to all checks performed by [`Self::validate`]:
    ///   * MainNet/TestNet require [`Self::authority`] to be present and
    ///     valid per [`GenesisAuthorityConfig::validate_for_environment`].
    ///   * DevNet allows a missing `authority` block (legacy local tests),
    ///     but if present it must still pass relaxed validation.
    ///
    /// Note: this method does NOT check the runtime-vs-genesis chain_id
    /// match — that is handled at the boot-time layer by
    /// [`verify_boot_time_genesis`].
    pub fn validate_for_environment(
        &self,
        env: NetworkEnvironmentPolicy,
    ) -> Result<(), GenesisValidationError> {
        self.validate()?;
        match (&self.authority, env) {
            (None, NetworkEnvironmentPolicy::Mainnet)
            | (None, NetworkEnvironmentPolicy::Testnet) => {
                return Err(GenesisValidationError::AuthorityValidationFailed(
                    GenesisAuthorityValidationError::Missing { env },
                ));
            }
            (None, NetworkEnvironmentPolicy::Devnet) => {
                // DevNet legacy: tolerated, but caller should log a
                // non-production banner. See Run 101 evidence Scenario 1.
            }
            (Some(authority), _) => {
                authority
                    .validate_for_environment(env)
                    .map_err(GenesisValidationError::AuthorityValidationFailed)?;
            }
        }
        Ok(())
    }
}

// ============================================================================
// Run 101: Canonical Genesis Hash (domain "QBIND:GENESIS:v1")
// ============================================================================

/// Canonical genesis-hash domain-separation tag.
///
/// Mirrors the project-wide tag style used by `qbind-hash::net` /
/// `qbind-hash::tx` / `qbind-hash::consensus` (`b"QBIND:<SCOPE>:v<N>"`).
pub const CANONICAL_GENESIS_HASH_DOMAIN_V1: &[u8] = b"QBIND:GENESIS:v1";

/// Run 101: compute the canonical, deterministic, domain-separated genesis
/// hash over the structured [`GenesisConfig`].
///
/// **Differs from [`compute_genesis_hash_bytes`]:** that function hashes the
/// exact bytes of the genesis JSON file (T233 behaviour, kept for backward
/// compatibility with `--expect-genesis-hash`). The canonical hash here is
/// computed over the *structured* configuration with explicit framing and
/// domain separation, so it is stable across whitespace / map-ordering
/// differences in the source JSON.
///
/// Both hashes coexist in Run 101: the file-bytes hash continues to back
/// `--expect-genesis-hash`, and the canonical hash is the value that
/// Run 102+ ratification objects will bind to.
///
/// # Encoding
///
/// ```text
/// SHA3-256(
///     "QBIND:GENESIS:v1"
///   || u32_be(env_scope_len)    || env_scope_bytes
///   || u32_be(chain_id_len)     || chain_id_bytes
///   || u64_be(genesis_time_unix_ms)
///   || u32_be(allocation_count) || allocations_canonical_bytes
///   || u32_be(validator_count)  || validators_canonical_bytes
///   || u32_be(council_threshold)|| council_canonical_bytes
///   || monetary_canonical_bytes
///   || authority_canonical_bytes  // empty framed block if authority is None
/// )
/// ```
///
/// All variable-length strings are length-prefixed with a big-endian `u32`
/// length followed by the raw UTF-8 bytes. Sub-blocks (each allocation /
/// validator / council member / authority root) are similarly framed and
/// emitted in declaration order (not sorted) — this preserves operator
/// intent and is deterministic because the JSON-to-struct decode preserves
/// `Vec` order.
///
/// Optional fields are framed with a single `0` or `1` discriminator byte
/// so that `None` and `Some("")` never collide.
///
/// The `extra` field is hashed via `serde_json::to_vec` of the *value* (not
/// the raw substring of the source JSON). Operators who set `extra` MUST
/// supply canonical JSON values — strings, numbers, booleans, ordered
/// arrays, and `serde_json::Map` (which is `BTreeMap` here in `qbind-ledger`'s
/// build of `serde_json` with the `preserve_order` feature **disabled**;
/// see `Cargo.toml`). For Run 101 / DevNet the `extra` field is `Null` in
/// practice.
pub fn compute_canonical_genesis_hash(
    config: &GenesisConfig,
    env: NetworkEnvironmentPolicy,
) -> GenesisHash {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    buf.extend_from_slice(CANONICAL_GENESIS_HASH_DOMAIN_V1);
    encode_length_prefixed_str(&mut buf, env.scope());
    encode_length_prefixed_str(&mut buf, &config.chain_id);
    buf.extend_from_slice(&config.genesis_time_unix_ms.to_be_bytes());

    encode_u32_be(&mut buf, config.allocations.len() as u32);
    for alloc in &config.allocations {
        encode_length_prefixed_str(&mut buf, &alloc.address);
        buf.extend_from_slice(&alloc.amount.to_be_bytes());
        encode_optional_str(&mut buf, alloc.memo.as_deref());
        encode_optional_u64(&mut buf, alloc.lockup_until_unix_ms);
    }

    encode_u32_be(&mut buf, config.validators.len() as u32);
    for validator in &config.validators {
        encode_length_prefixed_str(&mut buf, &validator.address);
        encode_length_prefixed_str(&mut buf, &validator.pqc_public_key);
        buf.extend_from_slice(&validator.stake.to_be_bytes());
        encode_optional_str(&mut buf, validator.name.as_deref());
        encode_optional_str(&mut buf, validator.metadata.as_deref());
    }

    encode_u32_be(&mut buf, config.council.threshold);
    encode_u32_be(&mut buf, config.council.members.len() as u32);
    for member in &config.council.members {
        encode_length_prefixed_str(&mut buf, member);
    }

    // Monetary config is hashed via its serde_json canonical bytes. This is
    // deterministic across runs because `qbind-ledger` depends on
    // `serde_json` without the `preserve_order` feature, and
    // `GenesisMonetaryConfig` is a fixed-shape struct with primitive fields
    // only. We frame with a length prefix so the boundary is unambiguous.
    let monetary_bytes = serde_json::to_vec(&config.monetary)
        .expect("GenesisMonetaryConfig must always serialize to JSON");
    encode_u32_be(&mut buf, monetary_bytes.len() as u32);
    buf.extend_from_slice(&monetary_bytes);

    encode_authority_block(&mut buf, config.authority.as_ref());

    qbind_hash::sha3_256(&buf)
}

fn encode_u32_be(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

fn encode_length_prefixed_str(buf: &mut Vec<u8>, s: &str) {
    let bytes = s.as_bytes();
    encode_u32_be(buf, bytes.len() as u32);
    buf.extend_from_slice(bytes);
}

fn encode_optional_str(buf: &mut Vec<u8>, s: Option<&str>) {
    match s {
        None => buf.push(0u8),
        Some(s) => {
            buf.push(1u8);
            encode_length_prefixed_str(buf, s);
        }
    }
}

fn encode_optional_u64(buf: &mut Vec<u8>, v: Option<u64>) {
    match v {
        None => buf.push(0u8),
        Some(v) => {
            buf.push(1u8);
            buf.extend_from_slice(&v.to_be_bytes());
        }
    }
}

fn encode_authority_block(buf: &mut Vec<u8>, authority: Option<&GenesisAuthorityConfig>) {
    match authority {
        None => buf.push(0u8),
        Some(authority) => {
            buf.push(1u8);
            encode_u32_be(buf, authority.authority_policy_version);
            buf.extend_from_slice(&authority.authority_sequence.to_be_bytes());
            encode_optional_u64(buf, authority.authority_epoch);
            encode_u32_be(buf, authority.pqc_transport_roots.len() as u32);
            for root in &authority.pqc_transport_roots {
                encode_authority_root(buf, root);
            }
            encode_u32_be(
                buf,
                authority.bundle_signing_authority_roots.len() as u32,
            );
            for root in &authority.bundle_signing_authority_roots {
                encode_authority_root(buf, root);
            }
        }
    }
}

fn encode_authority_root(buf: &mut Vec<u8>, root: &GenesisAuthorityRoot) {
    buf.push(root.suite_id);
    encode_length_prefixed_str(buf, &root.key_fingerprint);
    encode_length_prefixed_str(buf, &root.label);
    encode_optional_u64(buf, root.not_before_epoch);
}

// ============================================================================
// Run 101: Boot-time Genesis Hash / Authority Verification
// ============================================================================

/// Errors returned by [`verify_boot_time_genesis`].
///
/// Distinct, precise variants so that operator log messages can pinpoint the
/// failure cause without resorting to vague "invalid config" output (per the
/// Run 101 task "logging / operator error messages" requirement).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootGenesisVerificationError {
    /// `expected_canonical_hash` is required for this environment and was
    /// not supplied (MainNet always, TestNet by policy).
    ExpectedCanonicalHashMissing { env: NetworkEnvironmentPolicy },

    /// Supplied `expected_canonical_hash` did not match the computed value.
    CanonicalHashMismatch {
        env: NetworkEnvironmentPolicy,
        expected: GenesisHash,
        actual: GenesisHash,
    },

    /// Structural genesis validation (env-aware) failed.
    GenesisValidationFailed(GenesisValidationError),

    /// Authority validation failed.
    AuthorityValidationFailed(GenesisAuthorityValidationError),

    /// The genesis `chain_id` does not match the runtime environment.
    ChainEnvironmentMismatch {
        chain_id: String,
        env: NetworkEnvironmentPolicy,
    },
}

impl std::fmt::Display for BootGenesisVerificationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BootGenesisVerificationError::ExpectedCanonicalHashMissing { env } => write!(
                f,
                "expected canonical genesis hash is required for environment {:?} but was not provided",
                env
            ),
            BootGenesisVerificationError::CanonicalHashMismatch {
                env,
                expected,
                actual,
            } => write!(
                f,
                "canonical genesis hash mismatch on environment {:?}: expected {} actual {}",
                env,
                format_genesis_hash(expected),
                format_genesis_hash(actual)
            ),
            BootGenesisVerificationError::GenesisValidationFailed(e) => {
                write!(f, "genesis validation failed: {}", e)
            }
            BootGenesisVerificationError::AuthorityValidationFailed(e) => {
                write!(f, "genesis authority validation failed: {}", e)
            }
            BootGenesisVerificationError::ChainEnvironmentMismatch { chain_id, env } => write!(
                f,
                "genesis chain_id '{}' does not match runtime environment {:?}",
                chain_id, env
            ),
        }
    }
}

impl std::error::Error for BootGenesisVerificationError {}

/// Result of a boot-time genesis verification call. On success this carries
/// the computed canonical hash so callers (e.g. `qbind-node` startup) can
/// log it and persist it alongside the file-bytes [`ChainMeta`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BootGenesisVerification {
    /// The canonical hash that was computed and (when applicable) matched.
    pub canonical_hash: GenesisHash,
}

/// Run 101: boot-time genesis-hash + authority verification.
///
/// Performs, in order:
///   1. structural validation via [`GenesisConfig::validate_for_environment`];
///   2. chain_id / environment binding check (substring match of the
///      environment scope in the chain id, see below);
///   3. canonical hash computation;
///   4. expected-hash comparison per environment policy.
///
/// Environment policy:
///
/// | env     | authority required | expected hash required | chain_id check |
/// |---------|--------------------|------------------------|----------------|
/// | DevNet  | optional (legacy)  | optional               | best-effort    |
/// | TestNet | required           | strongly required if `expected_canonical_hash.is_some()` (Run 101 does not yet force the CLI flag; documented as partial-positive) | required |
/// | MainNet | required           | required (fail-closed) | required       |
///
/// The chain_id check is a substring match of the environment's lowercase
/// scope token (`"devnet"` / `"testnet"` / `"mainnet"`) against
/// `config.chain_id.to_lowercase()`. This mirrors the existing
/// `qbind-mainnet-v0` / `qbind-testnet-beta` chain-id convention used by
/// `QBIND_DEVNET_CHAIN_ID` / `QBIND_TESTNET_CHAIN_ID` /
/// `QBIND_MAINNET_CHAIN_ID` in `qbind-types::primitives`. It is intentionally
/// loose for DevNet (best-effort warning only via the returned error) and
/// strict for MainNet/TestNet.
///
/// On any failure this function returns the most specific error variant —
/// no silent "continue with default authority" path exists.
pub fn verify_boot_time_genesis(
    env: NetworkEnvironmentPolicy,
    config: &GenesisConfig,
    expected_canonical_hash: Option<&GenesisHash>,
) -> Result<BootGenesisVerification, BootGenesisVerificationError> {
    // 1. Structural + per-env validation.
    config
        .validate_for_environment(env)
        .map_err(|e| match e {
            GenesisValidationError::AuthorityValidationFailed(a) => {
                BootGenesisVerificationError::AuthorityValidationFailed(a)
            }
            other => BootGenesisVerificationError::GenesisValidationFailed(other),
        })?;

    // 2. chain_id / environment binding check.
    if matches!(
        env,
        NetworkEnvironmentPolicy::Mainnet | NetworkEnvironmentPolicy::Testnet
    ) {
        let needle = match env {
            NetworkEnvironmentPolicy::Mainnet => "mainnet",
            NetworkEnvironmentPolicy::Testnet => "testnet",
            NetworkEnvironmentPolicy::Devnet => unreachable!(),
        };
        if !config.chain_id.to_lowercase().contains(needle) {
            return Err(BootGenesisVerificationError::ChainEnvironmentMismatch {
                chain_id: config.chain_id.clone(),
                env,
            });
        }
    }

    // 3. Canonical hash computation.
    let canonical_hash = compute_canonical_genesis_hash(config, env);

    // 4. Expected-hash comparison per environment policy.
    match (env, expected_canonical_hash) {
        (NetworkEnvironmentPolicy::Mainnet, None) => {
            return Err(BootGenesisVerificationError::ExpectedCanonicalHashMissing { env });
        }
        (_, Some(expected)) => {
            if expected != &canonical_hash {
                return Err(BootGenesisVerificationError::CanonicalHashMismatch {
                    env,
                    expected: *expected,
                    actual: canonical_hash,
                });
            }
        }
        // TestNet without explicit expected hash: documented partial-positive
        // (Run 101 does not yet force the CLI flag on TestNet — see
        // `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_101.md` and the runbook).
        (NetworkEnvironmentPolicy::Testnet, None) => { /* allowed for now */ }
        // DevNet without expected hash: explicitly non-production allowed.
        (NetworkEnvironmentPolicy::Devnet, None) => { /* allowed */ }
    }

    Ok(BootGenesisVerification { canonical_hash })
}

// ============================================================================
// Genesis Validation Errors
// ============================================================================

/// Error type for genesis configuration validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisValidationError {
    /// Chain ID is empty.
    EmptyChainId,

    /// No allocations defined in genesis.
    NoAllocations,

    /// An allocation has zero amount.
    ZeroAllocationAmount { address: String },

    /// An address is empty.
    EmptyAddress,

    /// Duplicate address in allocations.
    DuplicateAllocationAddress { address: String },

    /// Total supply would overflow u128.
    TotalSupplyOverflow,

    /// Total supply is zero.
    ZeroTotalSupply,

    /// No validators defined in genesis.
    NoValidators,

    /// Duplicate validator address.
    DuplicateValidatorAddress { address: String },

    /// Validator has empty PQC public key.
    EmptyValidatorPqcKey { address: String },

    /// Council threshold is zero.
    CouncilThresholdZero,

    /// Council threshold exceeds member count.
    CouncilThresholdTooHigh { threshold: u32, member_count: usize },

    /// Duplicate council member address.
    DuplicateCouncilMember { address: String },

    /// Run 101: authority block validation failed (additive).
    AuthorityValidationFailed(GenesisAuthorityValidationError),
}

impl std::fmt::Display for GenesisValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GenesisValidationError::EmptyChainId => {
                write!(f, "chain_id must be non-empty")
            }
            GenesisValidationError::NoAllocations => {
                write!(f, "genesis must have at least one allocation")
            }
            GenesisValidationError::ZeroAllocationAmount { address } => {
                write!(f, "allocation for {} has zero amount", address)
            }
            GenesisValidationError::EmptyAddress => {
                write!(f, "address must be non-empty")
            }
            GenesisValidationError::DuplicateAllocationAddress { address } => {
                write!(f, "duplicate allocation address: {}", address)
            }
            GenesisValidationError::TotalSupplyOverflow => {
                write!(f, "total supply would overflow u128")
            }
            GenesisValidationError::ZeroTotalSupply => {
                write!(f, "total supply must be > 0")
            }
            GenesisValidationError::NoValidators => {
                write!(f, "genesis must have at least one validator")
            }
            GenesisValidationError::DuplicateValidatorAddress { address } => {
                write!(f, "duplicate validator address: {}", address)
            }
            GenesisValidationError::EmptyValidatorPqcKey { address } => {
                write!(f, "validator {} has empty PQC public key", address)
            }
            GenesisValidationError::CouncilThresholdZero => {
                write!(f, "council threshold must be > 0")
            }
            GenesisValidationError::CouncilThresholdTooHigh {
                threshold,
                member_count,
            } => {
                write!(
                    f,
                    "council threshold {} exceeds member count {}",
                    threshold, member_count
                )
            }
            GenesisValidationError::DuplicateCouncilMember { address } => {
                write!(f, "duplicate council member: {}", address)
            }
            GenesisValidationError::AuthorityValidationFailed(e) => {
                write!(f, "authority validation failed: {}", e)
            }
        }
    }
}

impl std::error::Error for GenesisValidationError {}

// ============================================================================
// T233: Genesis Hash Commitment Types
// ============================================================================

/// Type alias for a genesis hash (SHA3-256, 32 bytes).
///
/// This hash is computed over the exact bytes of the genesis JSON file,
/// with NO normalization, whitespace stripping, or key reordering.
///
/// # Canonical Definition
///
/// ```text
/// genesis_hash = SHA3-256(genesis_json_bytes)
/// ```
///
/// Where `genesis_json_bytes` is the exact file content as distributed.
pub type GenesisHash = [u8; 32];

/// Compute the canonical SHA3-256 genesis hash over raw bytes.
///
/// This function computes the SHA3-256 hash of the given bytes deterministically.
/// The bytes should be the exact content of the genesis JSON file.
///
/// # Important
///
/// - NO JSON normalization is applied
/// - NO whitespace stripping or key reordering
/// - The hash is computed over the exact file bytes as distributed
///
/// # Example
///
/// ```rust
/// use qbind_ledger::compute_genesis_hash_bytes;
///
/// let genesis_json = br#"{"chain_id": "qbind-mainnet-v0"}"#;
/// let hash = compute_genesis_hash_bytes(genesis_json);
/// assert_eq!(hash.len(), 32);
/// ```
pub fn compute_genesis_hash_bytes(bytes: &[u8]) -> GenesisHash {
    qbind_hash::sha3_256(bytes)
}

/// Format a genesis hash as a hex string with 0x prefix.
///
/// # Example
///
/// ```rust
/// use qbind_ledger::{compute_genesis_hash_bytes, format_genesis_hash};
///
/// let hash = compute_genesis_hash_bytes(b"test");
/// let hex = format_genesis_hash(&hash);
/// assert!(hex.starts_with("0x"));
/// assert_eq!(hex.len(), 66); // 0x + 64 hex chars
/// ```
pub fn format_genesis_hash(hash: &GenesisHash) -> String {
    let hex: String = hash.iter().map(|b| format!("{:02x}", b)).collect();
    format!("0x{}", hex)
}

/// Parse a genesis hash from a hex string (with or without 0x prefix).
///
/// # Arguments
///
/// * `hex_str` - A 64-character hex string, optionally prefixed with "0x"
///
/// # Returns
///
/// * `Ok(GenesisHash)` - The parsed 32-byte hash
/// * `Err(String)` - Error message if parsing fails
///
/// # Example
///
/// ```rust
/// use qbind_ledger::parse_genesis_hash;
///
/// // With 0x prefix
/// let hash1 = parse_genesis_hash(&format!("0x{}", "ab".repeat(32)));
/// assert!(hash1.is_ok());
///
/// // Without prefix
/// let hash2 = parse_genesis_hash(&"cd".repeat(32));
/// assert!(hash2.is_ok());
///
/// // Invalid length
/// let hash3 = parse_genesis_hash("0x1234");
/// assert!(hash3.is_err());
/// ```
pub fn parse_genesis_hash(hex_str: &str) -> Result<GenesisHash, String> {
    // Strip optional 0x prefix
    let hex = hex_str.strip_prefix("0x").unwrap_or(hex_str);

    // Check length (must be 64 hex chars for 32 bytes)
    if hex.len() != 64 {
        return Err(format!(
            "invalid genesis hash length: expected 64 hex characters, got {}",
            hex.len()
        ));
    }

    // Parse hex string to bytes
    let mut hash = [0u8; 32];
    for i in 0..32 {
        let byte_str = &hex[i * 2..i * 2 + 2];
        hash[i] = u8::from_str_radix(byte_str, 16)
            .map_err(|e| format!("invalid hex character at position {}: {}", i * 2, e))?;
    }

    Ok(hash)
}

// ============================================================================
// T233: Chain Metadata Types
// ============================================================================

/// Chain metadata stored during genesis application.
///
/// This structure captures the essential identity of a chain and is persisted
/// at height 0 when the genesis state is applied. It serves as a commitment
/// that can be verified by operators and auditors.
///
/// # Fields
///
/// - `chain_id`: The human-readable chain identifier (e.g., "qbind-mainnet-v0")
/// - `genesis_hash`: The SHA3-256 hash of the genesis JSON file bytes
///
/// # Usage
///
/// The `ChainMeta` is computed and stored during genesis application:
/// 1. Load genesis JSON file as raw bytes
/// 2. Compute `genesis_hash = SHA3-256(bytes)`
/// 3. Parse genesis config to extract `chain_id`
/// 4. Persist `ChainMeta { chain_id, genesis_hash }` as part of height 0 state
///
/// # Verification
///
/// Operators verify chain identity by:
/// 1. Computing the hash of their local genesis file
/// 2. Comparing against the stored `ChainMeta.genesis_hash`
/// 3. Using `--expect-genesis-hash` flag to fail fast on mismatch
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ChainMeta {
    /// Chain identifier from the genesis configuration.
    pub chain_id: String,

    /// SHA3-256 hash of the exact genesis JSON file bytes.
    pub genesis_hash: GenesisHash,
}

impl ChainMeta {
    /// Create a new ChainMeta.
    pub fn new(chain_id: impl Into<String>, genesis_hash: GenesisHash) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis_hash,
        }
    }

    /// Get the genesis hash as a hex string with 0x prefix.
    pub fn genesis_hash_hex(&self) -> String {
        format_genesis_hash(&self.genesis_hash)
    }
}

/// Errors that can occur when storing or loading chain metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainMetaError {
    /// Chain metadata already exists (attempted duplicate store).
    AlreadyExists,

    /// Chain metadata not found.
    NotFound,

    /// Serialization/deserialization error.
    SerializationError(String),

    /// Storage backend error.
    StorageError(String),
}

impl std::fmt::Display for ChainMetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ChainMetaError::AlreadyExists => {
                write!(f, "chain metadata already exists (cannot re-apply genesis)")
            }
            ChainMetaError::NotFound => {
                write!(f, "chain metadata not found")
            }
            ChainMetaError::SerializationError(msg) => {
                write!(f, "chain metadata serialization error: {}", msg)
            }
            ChainMetaError::StorageError(msg) => {
                write!(f, "chain metadata storage error: {}", msg)
            }
        }
    }
}

impl std::error::Error for ChainMetaError {}

// ============================================================================
// Unit Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn test_monetary_config() -> GenesisMonetaryConfig {
        GenesisMonetaryConfig::mainnet_default()
    }

    fn valid_genesis_config() -> GenesisConfig {
        GenesisConfig::new(
            "qbind-testnet-v0",
            1738000000000,
            vec![
                GenesisAllocation::new("0x1111111111111111111111111111111111111111", 1_000_000),
                GenesisAllocation::new("0x2222222222222222222222222222222222222222", 2_000_000),
            ],
            vec![
                GenesisValidator::new(
                    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "pqc_key_validator_1",
                    100_000,
                ),
                GenesisValidator::new(
                    "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "pqc_key_validator_2",
                    200_000,
                ),
            ],
            GenesisCouncilConfig::new(
                vec![
                    "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                    "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                ],
                2,
            ),
            test_monetary_config(),
        )
    }

    #[test]
    fn test_genesis_valid_basic() {
        let config = valid_genesis_config();
        assert!(config.validate().is_ok());
        assert_eq!(config.total_supply(), 3_000_000);
        assert_eq!(config.validator_count(), 2);
        assert_eq!(config.council_member_count(), 3);
    }

    #[test]
    fn test_genesis_rejects_empty_chain_id() {
        let mut config = valid_genesis_config();
        config.chain_id = "".to_string();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::EmptyChainId)
        ));
    }

    #[test]
    fn test_genesis_rejects_zero_allocation() {
        let mut config = valid_genesis_config();
        config.allocations[0].amount = 0;
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::ZeroAllocationAmount { .. })
        ));
    }

    #[test]
    fn test_genesis_rejects_duplicate_allocation_address() {
        let mut config = valid_genesis_config();
        config.allocations[1].address = config.allocations[0].address.clone();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::DuplicateAllocationAddress { .. })
        ));
    }

    #[test]
    fn test_genesis_rejects_no_validators() {
        let mut config = valid_genesis_config();
        config.validators.clear();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::NoValidators)
        ));
    }

    #[test]
    fn test_genesis_rejects_duplicate_validator_address() {
        let mut config = valid_genesis_config();
        config.validators[1].address = config.validators[0].address.clone();
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::DuplicateValidatorAddress { .. })
        ));
    }

    #[test]
    fn test_genesis_rejects_council_threshold_zero() {
        let mut config = valid_genesis_config();
        config.council.threshold = 0;
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::CouncilThresholdZero)
        ));
    }

    #[test]
    fn test_genesis_rejects_council_threshold_too_high() {
        let mut config = valid_genesis_config();
        config.council.threshold = 10; // Only 3 members
        assert!(matches!(
            config.validate(),
            Err(GenesisValidationError::CouncilThresholdTooHigh { .. })
        ));
    }

    #[test]
    fn test_genesis_monetary_config_roundtrip() {
        use crate::MonetaryEngineConfig;

        // Create an engine config
        let engine_config = MonetaryEngineConfig {
            pqc_premium_compute: 0.30,
            pqc_premium_bandwidth: 0.15,
            pqc_premium_storage: 0.10,
            bootstrap: crate::PhaseParameters {
                r_target_annual: 0.05,
                inflation_floor_annual: 0.0,
                fee_smoothing_half_life_days: 30.0,
                max_annual_inflation_cap: 0.12,
                ema_lambda_bps: 700,
                max_delta_r_inf_per_epoch_bps: 25,
            },
            transition: crate::PhaseParameters {
                r_target_annual: 0.04,
                inflation_floor_annual: 0.0,
                fee_smoothing_half_life_days: 60.0,
                max_annual_inflation_cap: 0.10,
                ema_lambda_bps: 300,
                max_delta_r_inf_per_epoch_bps: 10,
            },
            mature: crate::PhaseParameters {
                r_target_annual: 0.03,
                inflation_floor_annual: 0.01,
                fee_smoothing_half_life_days: 90.0,
                max_annual_inflation_cap: 0.08,
                ema_lambda_bps: 150,
                max_delta_r_inf_per_epoch_bps: 5,
            },
            alpha_fee_offset: 1.0,
        };

        // Convert to genesis config
        let genesis_monetary = GenesisMonetaryConfig::from_engine_config(&engine_config);

        // Convert back
        let roundtrip = genesis_monetary.to_engine_config();

        // Check key fields match
        assert_eq!(
            roundtrip.pqc_premium_compute,
            engine_config.pqc_premium_compute
        );
        assert_eq!(
            roundtrip.bootstrap.r_target_annual,
            engine_config.bootstrap.r_target_annual
        );
        assert_eq!(
            roundtrip.mature.inflation_floor_annual,
            engine_config.mature.inflation_floor_annual
        );
    }

    #[test]
    fn test_allocation_constructors() {
        let alloc1 = GenesisAllocation::new("0x1234", 1000);
        assert_eq!(alloc1.amount, 1000);
        assert!(alloc1.lockup_until_unix_ms.is_none());
        assert!(alloc1.memo.is_none());

        let alloc2 = GenesisAllocation::with_lockup("0x1234", 1000, 1800000000000);
        assert_eq!(alloc2.lockup_until_unix_ms, Some(1800000000000));

        let alloc3 = GenesisAllocation::with_memo("0x1234", 1000, "Foundation");
        assert_eq!(alloc3.memo, Some("Foundation".to_string()));
    }

    #[test]
    fn test_validator_constructors() {
        let v1 = GenesisValidator::new("0xabc", "pqc_key_1", 10000);
        assert!(v1.name.is_none());

        let v2 = GenesisValidator::with_name("0xabc", "pqc_key_1", 10000, "Validator One");
        assert_eq!(v2.name, Some("Validator One".to_string()));
    }

    // ========================================================================
    // Run 101: Genesis Authority + Canonical Hash + Boot-Time Verification
    // ========================================================================

    fn ml_dsa_44_fingerprint(seed: u8) -> String {
        // 64 hex chars = 32 raw bytes; matches MainNet minimum.
        let byte_hex = format!("{:02x}", seed);
        byte_hex.repeat(32)
    }

    fn authority_root(seed: u8, label: &str) -> GenesisAuthorityRoot {
        GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            ml_dsa_44_fingerprint(seed),
            label,
        )
    }

    fn mainnet_authority() -> GenesisAuthorityConfig {
        let mut auth = GenesisAuthorityConfig::new(vec![
            authority_root(0xab, "foundation-bundle-signer-1"),
        ]);
        auth.pqc_transport_roots = vec![authority_root(0xcd, "foundation-transport-1")];
        auth
    }

    fn mainnet_genesis_config() -> GenesisConfig {
        let mut cfg = valid_genesis_config();
        cfg.chain_id = "qbind-mainnet-v0".to_string();
        cfg.authority = Some(mainnet_authority());
        cfg
    }

    fn devnet_genesis_config_no_authority() -> GenesisConfig {
        let mut cfg = valid_genesis_config();
        cfg.chain_id = "qbind-devnet-v0".to_string();
        cfg.authority = None;
        cfg
    }

    // ---- Authority validation ----

    #[test]
    fn test_authority_mainnet_requires_present() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority = None;
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::Missing { .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_empty_bundle_signing_roots() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority.as_mut().unwrap().bundle_signing_authority_roots = vec![];
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::EmptyBundleSigningRoots
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_unsupported_suite() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority.as_mut().unwrap().bundle_signing_authority_roots[0].suite_id = 1;
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::UnsupportedSuite { suite_id: 1, .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_malformed_fingerprint_short() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority.as_mut().unwrap().bundle_signing_authority_roots[0].key_fingerprint =
            "ab".repeat(8); // 16 hex chars
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::MalformedFingerprint { .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_malformed_fingerprint_non_hex() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority.as_mut().unwrap().bundle_signing_authority_roots[0].key_fingerprint =
            "zz".repeat(32);
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::MalformedFingerprint { .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_empty_label() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority.as_mut().unwrap().bundle_signing_authority_roots[0].label = String::new();
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::EmptyLabel { .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_duplicate_roots() {
        let mut cfg = mainnet_genesis_config();
        let dup = cfg.authority.as_ref().unwrap().bundle_signing_authority_roots[0].clone();
        cfg.authority
            .as_mut()
            .unwrap()
            .bundle_signing_authority_roots
            .push(dup);
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::DuplicateAuthorityRoot { .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_invalid_policy_version() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority.as_mut().unwrap().authority_policy_version = 0;
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::InvalidPolicyVersion { got: 0, .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_rejects_policy_version_too_new() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority.as_mut().unwrap().authority_policy_version = u32::MAX;
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::InvalidPolicyVersion { .. }
            )
        ));
    }

    #[test]
    fn test_authority_devnet_allows_missing() {
        let cfg = devnet_genesis_config_no_authority();
        cfg.validate_for_environment(NetworkEnvironmentPolicy::Devnet)
            .expect("devnet must allow missing authority for legacy local tests");
    }

    #[test]
    fn test_authority_testnet_requires_present() {
        let mut cfg = mainnet_genesis_config();
        cfg.chain_id = "qbind-testnet-beta".to_string();
        cfg.authority = None;
        let err = cfg
            .validate_for_environment(NetworkEnvironmentPolicy::Testnet)
            .unwrap_err();
        assert!(matches!(
            err,
            GenesisValidationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::Missing { .. }
            )
        ));
    }

    #[test]
    fn test_authority_mainnet_accepts_valid() {
        let cfg = mainnet_genesis_config();
        cfg.validate_for_environment(NetworkEnvironmentPolicy::Mainnet)
            .expect("valid mainnet genesis with authority must pass");
    }

    // ---- Canonical hash ----

    #[test]
    fn test_canonical_hash_is_deterministic() {
        let cfg = mainnet_genesis_config();
        let h1 = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let h2 = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_canonical_hash_differs_on_chain_id() {
        let mut a = mainnet_genesis_config();
        let b = a.clone();
        a.chain_id = "qbind-mainnet-v1".to_string();
        let ha = compute_canonical_genesis_hash(&a, NetworkEnvironmentPolicy::Mainnet);
        let hb = compute_canonical_genesis_hash(&b, NetworkEnvironmentPolicy::Mainnet);
        assert_ne!(ha, hb);
    }

    #[test]
    fn test_canonical_hash_differs_on_environment() {
        let cfg = mainnet_genesis_config();
        let main_h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let test_h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Testnet);
        let dev_h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Devnet);
        assert_ne!(main_h, test_h);
        assert_ne!(test_h, dev_h);
        assert_ne!(main_h, dev_h);
    }

    #[test]
    fn test_canonical_hash_differs_on_authority_change() {
        let cfg = mainnet_genesis_config();
        let h_before = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut cfg2 = cfg.clone();
        cfg2.authority
            .as_mut()
            .unwrap()
            .bundle_signing_authority_roots[0]
            .key_fingerprint = ml_dsa_44_fingerprint(0xee);
        let h_after = compute_canonical_genesis_hash(&cfg2, NetworkEnvironmentPolicy::Mainnet);
        assert_ne!(h_before, h_after);
    }

    #[test]
    fn test_canonical_hash_differs_on_authority_policy_version_change() {
        let cfg = mainnet_genesis_config();
        let h_before = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut cfg2 = cfg.clone();
        // Bump to the maximum supported version (still valid).
        cfg2.authority.as_mut().unwrap().authority_policy_version =
            GENESIS_AUTHORITY_POLICY_VERSION_RUN_101;
        // Mutate authority_sequence instead to ensure a hash difference even
        // if the policy version is already at max.
        cfg2.authority.as_mut().unwrap().authority_sequence += 1;
        let h_after = compute_canonical_genesis_hash(&cfg2, NetworkEnvironmentPolicy::Mainnet);
        assert_ne!(h_before, h_after);
    }

    #[test]
    fn test_canonical_hash_differs_on_validator_change() {
        let cfg = mainnet_genesis_config();
        let h_before = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut cfg2 = cfg.clone();
        cfg2.validators[0].stake += 1;
        let h_after = compute_canonical_genesis_hash(&cfg2, NetworkEnvironmentPolicy::Mainnet);
        assert_ne!(h_before, h_after);
    }

    #[test]
    fn test_canonical_hash_differs_on_allocation_change() {
        let cfg = mainnet_genesis_config();
        let h_before = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut cfg2 = cfg.clone();
        cfg2.allocations[0].amount += 1;
        let h_after = compute_canonical_genesis_hash(&cfg2, NetworkEnvironmentPolicy::Mainnet);
        assert_ne!(h_before, h_after);
    }

    #[test]
    fn test_canonical_hash_distinguishes_none_vs_empty_authority() {
        // No-authority and empty-authority must hash differently because the
        // authority block is framed with a discriminator byte.
        let mut cfg_none = devnet_genesis_config_no_authority();
        let mut cfg_empty = cfg_none.clone();
        cfg_empty.authority = Some(GenesisAuthorityConfig::new(vec![]));
        cfg_none.authority = None;
        let h_none = compute_canonical_genesis_hash(&cfg_none, NetworkEnvironmentPolicy::Devnet);
        let h_empty = compute_canonical_genesis_hash(&cfg_empty, NetworkEnvironmentPolicy::Devnet);
        assert_ne!(h_none, h_empty);
    }

    // ---- Boot-time verification ----

    #[test]
    fn test_boot_mainnet_requires_expected_hash() {
        let cfg = mainnet_genesis_config();
        let err =
            verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, None).unwrap_err();
        assert!(matches!(
            err,
            BootGenesisVerificationError::ExpectedCanonicalHashMissing {
                env: NetworkEnvironmentPolicy::Mainnet
            }
        ));
    }

    #[test]
    fn test_boot_mainnet_accepts_matching_hash() {
        let cfg = mainnet_genesis_config();
        let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let v = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&h))
            .expect("matching hash must succeed");
        assert_eq!(v.canonical_hash, h);
    }

    #[test]
    fn test_boot_mainnet_rejects_mismatched_hash() {
        let cfg = mainnet_genesis_config();
        let wrong = [0u8; 32];
        let err =
            verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&wrong))
                .unwrap_err();
        assert!(matches!(
            err,
            BootGenesisVerificationError::CanonicalHashMismatch { .. }
        ));
    }

    #[test]
    fn test_boot_mainnet_rejects_missing_authority_before_hash() {
        let mut cfg = mainnet_genesis_config();
        cfg.authority = None;
        // Even when the operator supplies *some* expected hash, missing
        // authority must surface as an authority error (fail-closed before
        // any hash compare).
        let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let err = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&h))
            .unwrap_err();
        assert!(matches!(
            err,
            BootGenesisVerificationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::Missing { .. }
            )
        ));
    }

    #[test]
    fn test_boot_mainnet_rejects_wrong_chain_id() {
        let mut cfg = mainnet_genesis_config();
        cfg.chain_id = "qbind-testnet-v0".to_string();
        let h = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let err = verify_boot_time_genesis(NetworkEnvironmentPolicy::Mainnet, &cfg, Some(&h))
            .unwrap_err();
        assert!(matches!(
            err,
            BootGenesisVerificationError::ChainEnvironmentMismatch { .. }
        ));
    }

    #[test]
    fn test_boot_devnet_allows_missing_hash_and_authority() {
        let cfg = devnet_genesis_config_no_authority();
        let v = verify_boot_time_genesis(NetworkEnvironmentPolicy::Devnet, &cfg, None)
            .expect("devnet legacy path must remain usable");
        // Hash is still deterministic and exposed.
        assert_eq!(
            v.canonical_hash,
            compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Devnet)
        );
    }

    #[test]
    fn test_boot_testnet_allows_missing_hash_with_authority_present() {
        let mut cfg = mainnet_genesis_config();
        cfg.chain_id = "qbind-testnet-beta".to_string();
        verify_boot_time_genesis(NetworkEnvironmentPolicy::Testnet, &cfg, None)
            .expect("testnet without expected hash but valid authority should pass (Run 101 partial-positive)");
    }

    #[test]
    fn test_boot_testnet_rejects_missing_authority() {
        let mut cfg = mainnet_genesis_config();
        cfg.chain_id = "qbind-testnet-beta".to_string();
        cfg.authority = None;
        let err = verify_boot_time_genesis(NetworkEnvironmentPolicy::Testnet, &cfg, None)
            .unwrap_err();
        assert!(matches!(
            err,
            BootGenesisVerificationError::AuthorityValidationFailed(
                GenesisAuthorityValidationError::Missing { .. }
            )
        ));
    }

    #[test]
    fn test_backward_compat_legacy_json_without_authority_parses() {
        // A genesis JSON written before Run 101 (no `authority` key) must
        // still deserialize cleanly.
        let json = serde_json::json!({
            "chain_id": "qbind-devnet-v0",
            "genesis_time_unix_ms": 1738000000000u64,
            "allocations": [{
                "address": "0x1111111111111111111111111111111111111111",
                "amount": 1_000_000u128.to_string().parse::<u128>().unwrap(),
            }],
            "validators": [{
                "address": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "pqc_public_key": "pqc_key_1",
                "stake": 100_000u128,
            }],
            "council": {
                "members": ["0xcccccccccccccccccccccccccccccccccccccccc"],
                "threshold": 1u32,
            },
            "monetary": serde_json::to_value(test_monetary_config()).unwrap(),
        });
        let cfg: GenesisConfig = serde_json::from_value(json).expect("legacy JSON must parse");
        assert!(cfg.authority.is_none());
        cfg.validate_for_environment(NetworkEnvironmentPolicy::Devnet)
            .expect("legacy DevNet genesis must remain valid");
    }
}