//! Run 422 D7-C2 — bounded, **non-authorizing** correspondence between an
//! independently pinned genesis-derived expected identity, a separately
//! supplied, explicitly **untrusted** authority-record description, and a D7-C1
//! storage observation.
//!
//! # What this module establishes
//!
//! It answers exactly one bounded question: *do the fields actually compared in
//! an untrusted [`ClaimedAuthorityRecord`] correspond, field for field, to an
//! [`ExpectedGenesisIdentity`] that was constructed independently from a pinned,
//! boot-validated genesis file, and to an explicitly observed C1 storage
//! epoch?* A [`GenesisRecordCorrespondence`] is returned **only** when every
//! compared field matches.
//!
//! # What this module does NOT establish (stated explicitly)
//!
//! A successful [`GenesisRecordCorrespondence`] is **correspondence-only**. It
//! does **not**:
//!
//! - authenticate a persisted authority record (the record is an in-memory,
//!   untrusted description, never read from RocksDB by this module);
//! - prove the record and the observed epoch came from the same database
//!   (storage/record **co-origin is not established**);
//! - establish current authority, freshness, or activation authorization;
//! - prevent rollback or provide any durable anti-rollback evidence.
//!
//! A matching record plus `CommittedEpoch(0)` **never** becomes
//! [`crate::genesis_consensus_authority::LocalAuthorizationState::Established`],
//! a `CurrentAuthorizationOwner`, an `AuthorizedProposalVoteSnapshot`, an
//! `AuthorizationTicket`, or a signing capability. This type is deliberately
//! kept structurally separate from every authorization API and exposes no
//! conversion into one.
//!
//! # Trust source of every compared field
//!
//! | Field | Source of the *expected* value |
//! | --- | --- |
//! | chain id label | independently pinned genesis validation |
//! | canonical genesis hash | independently pinned genesis validation (against the required pin) |
//! | authority commitment | derived from the pinned validated snapshot |
//! | validator membership / index | derived from the pinned validated snapshot |
//! | per-validator suite / key bytes / voting power | derived from the pinned validated snapshot |
//! | founding epoch | the genesis-static founding epoch constant |
//! | observed epoch | the C1 storage observation (storage evidence only) |
//!
//! Every field carried by the [`ClaimedAuthorityRecord`] is *claimed* by the
//! untrusted record and is only ever accepted when it equals the independently
//! established expected value. The record's own `commitment` is never trusted as
//! a substitute for comparing the full membership contents: a record that leaves
//! an unchanged commitment but alters a validator's key/suite/weight is rejected
//! by the per-member comparison.
//!
//! Production limitation: the runtime → wire `chain_id` mapping and live
//! Proposal/Vote activation authorization are unavailable in production. This
//! checker never fills them from the record being checked and never claims they
//! were validated.

use std::collections::HashSet;
use std::path::Path;

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
use qbind_crypto::ConsensusSigSuiteId;
use qbind_ledger::{verify_boot_time_genesis, GenesisHash, NetworkEnvironmentPolicy};
use qbind_types::{
    resolve_network_wire_alias, ChainId, NetworkEnvironment, NetworkWireAlias,
    NetworkWireAliasMismatch,
};

use crate::consensus_storage_observation::{
    ConsensusStorageObservation, ConsensusStorageObservationError,
};
use crate::genesis_consensus_authority::{
    build_genesis_consensus_authority, GenesisConsensusAuthority, GenesisConsensusAuthorityError,
    MAX_GENESIS_CONSENSUS_VALIDATORS,
};
use crate::pqc_boot_genesis::{load_external_genesis, map_environment};
use crate::signer_loader::public_key_fingerprint;
use crate::timeout_verification_bridge::SUPPORTED_TIMEOUT_SUITE_ID;

// ============================================================================
// Independently pinned, validated expected identity
// ============================================================================

/// An independently pinned, validated genesis-derived expected identity.
///
/// Immutable with **private** fields and **no** unchecked public constructor or
/// setter. The only way to obtain one is [`Self::load_pinned`], which:
///
/// 1. requires an independently supplied expected genesis hash (the *pin*);
/// 2. reads the genesis file exactly **once** into an owned snapshot;
/// 3. uses the existing boot-time validation + canonical hashing against that
///    required pin (via [`verify_boot_time_genesis`], after a single
///    [`load_external_genesis`] read);
/// 4. derives membership and consensus key material from that **same** validated
///    snapshot;
/// 5. copies the necessary immutable values into this object.
///
/// The pin must be supplied by the caller from an independent source (e.g. an
/// original fixture / operator-pinned `--expect-genesis-hash`). It is **never**
/// taken from the untrusted record and **never** silently calculated from the
/// file being accepted: [`verify_boot_time_genesis`] receives the pin as the
/// required `expected_genesis_hash`, so a file whose canonical hash
/// disagrees is rejected rather than accepted.
pub struct ExpectedGenesisIdentity {
    /// The validated, immutable genesis-bound authority snapshot. Built once
    /// from the pinned, boot-validated genesis; the single source of every
    /// expected field. Held privately so the expected identity cannot be
    /// mutated or reconstructed from untrusted claims.
    authority: GenesisConsensusAuthority,
    /// Run 422 D7-C3B — the exact [`NetworkEnvironmentPolicy`] that was used to
    /// boot-validate this identity (and, crucially, that scoped the canonical
    /// genesis hash the pin was compared against).
    ///
    /// Private and immutable: it is recorded only by the successful
    /// [`Self::load_pinned`] construction and never altered afterwards. There is
    /// no public constructor, setter, or default that can fabricate a validation
    /// policy, so a stored policy always reflects the policy under which this
    /// identity actually passed pinned validation. It is the trust anchor for
    /// [`Self::check_network_correspondence`], which refuses to relabel an
    /// already-validated identity under a different environment policy.
    validation_policy: NetworkEnvironmentPolicy,
}

impl std::fmt::Debug for ExpectedGenesisIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExpectedGenesisIdentity")
            .field("chain_id", &self.authority.chain_id)
            .field("genesis_fp", &public_key_fingerprint(&self.authority.genesis_hash))
            .field("validator_count", &self.authority.validator_count)
            .field("founding_epoch", &self.authority.authorized_epoch())
            .field("validation_policy", &self.validation_policy)
            .finish()
    }
}

impl ExpectedGenesisIdentity {
    /// Construct the expected identity from a pinned, boot-validated genesis
    /// file.
    ///
    /// `expected_genesis_hash` is the **required** independent pin. The genesis
    /// file at `genesis_path` is read **once** into an owned snapshot and fully
    /// re-validated against that pin with the existing boot-time validation +
    /// canonical hashing ([`verify_boot_time_genesis`]); membership and key
    /// material are then derived from that **same** validated snapshot
    /// ([`build_genesis_consensus_authority`]). `local_validator_id` is
    /// `ValidatorId(0)`, which is always in range for a non-empty genesis; it is
    /// a per-node role only and never participates in the authority identity.
    ///
    /// The pin is supplied to [`verify_boot_time_genesis`] as the required
    /// expected hash, so a file whose canonical identity disagrees with the pin
    /// fails closed rather than being accepted. The pin is therefore never taken
    /// from the untrusted record and never silently calculated from (and
    /// accepted for) the file. Only one file read occurs; identity and key
    /// material are never sourced from separate reads.
    pub fn load_pinned(
        genesis_path: &Path,
        env_policy: NetworkEnvironmentPolicy,
        expected_genesis_hash: &GenesisHash,
    ) -> Result<Self, ExpectedGenesisIdentityError> {
        // 1. Single owned read of the external genesis snapshot.
        let genesis = load_external_genesis(genesis_path).map_err(|e| {
            ExpectedGenesisIdentityError::GenesisReloadFailed {
                detail: e.to_string(),
            }
        })?;

        // 2. Existing boot-time validation + canonical hashing AGAINST the
        //    required pin. Passing `Some(pin)` makes verification fail closed
        //    unless the file's canonical identity equals the pin.
        let canonical_hash =
            verify_boot_time_genesis(env_policy, &genesis, Some(expected_genesis_hash))
                .map_err(|e| ExpectedGenesisIdentityError::GenesisRevalidationFailed {
                    detail: e.to_string(),
                })?
                .canonical_hash;

        // 3. Derive membership + key material from the SAME validated snapshot.
        let authority =
            build_genesis_consensus_authority(&genesis, &canonical_hash, ValidatorId::new(0))
                .map_err(ExpectedGenesisIdentityError::Authority)?;

        // 4. Retain the exact policy that scoped this successful validation. The
        //    canonical hash the pin was compared against already binds
        //    `env_policy.scope()`, so recording the policy here keeps the
        //    environment provenance attached to the validated identity.
        Ok(Self {
            authority,
            validation_policy: env_policy,
        })
    }

    /// The chain identity label established by pinned genesis validation.
    pub fn chain_id(&self) -> &str {
        &self.authority.chain_id
    }

    /// The canonical genesis hash established against the required pin.
    pub fn genesis_hash(&self) -> &GenesisHash {
        &self.authority.genesis_hash
    }

    /// The genesis-authority commitment derived from the validated snapshot.
    pub fn authority_commitment(&self) -> &[u8; 32] {
        &self.authority.commitment
    }

    /// The committed validator count.
    pub fn validator_count(&self) -> usize {
        self.authority.validator_count
    }

    /// The single founding epoch this genesis-static identity is valid for.
    pub fn founding_epoch(&self) -> u64 {
        self.authority.authorized_epoch()
    }

    /// The exact [`NetworkEnvironmentPolicy`] under which this identity was
    /// pin-validated. This is the retained provenance checked by
    /// [`Self::check_network_correspondence`].
    pub fn validation_policy(&self) -> NetworkEnvironmentPolicy {
        self.validation_policy
    }

    /// Run 422 D7-C3B — establish a **dormant, non-authorizing** static
    /// correspondence between this pin-validated genesis identity, the selected
    /// standard [`NetworkEnvironment`], the supplied full-width runtime
    /// [`ChainId`], and the C3A wire alias.
    ///
    /// The operation, in order:
    ///
    /// 1. maps `selected_environment` to a [`NetworkEnvironmentPolicy`] via the
    ///    existing [`map_environment`] and compares it against the policy this
    ///    identity was *actually* validated under. A mismatch is rejected
    ///    ([`GenesisNetworkCorrespondenceError::ValidationPolicyMismatch`]) —
    ///    changing the environment/runtime pair can never relabel an
    ///    already-validated identity;
    /// 2. resolves the wire alias through the existing
    ///    [`resolve_network_wire_alias`] (C3A), which independently re-checks the
    ///    supplied full-width runtime ID against
    ///    [`NetworkEnvironment::chain_id`]; a runtime mismatch is surfaced as
    ///    [`GenesisNetworkCorrespondenceError::RuntimeMismatch`] (the reused C3A
    ///    error) with no truncation or fallback;
    /// 3. only when both checks pass, returns a [`GenesisNetworkCorrespondence`]
    ///    that *borrows* this validated identity immutably, so the alias stays
    ///    attached to the same validated genesis hash and authority commitment.
    ///
    /// The runtime ID is never inferred from the genesis `chain_id` label; it is
    /// checked exclusively through C3A against the environment's authoritative
    /// runtime constant. The result establishes **static correspondence only**:
    /// it is not current authority, activation permission, freshness, storage
    /// provenance, rollback resistance, or a signing capability, and there is no
    /// conversion from it into any authorization type.
    pub fn check_network_correspondence(
        &self,
        selected_environment: NetworkEnvironment,
        supplied_runtime: ChainId,
    ) -> Result<GenesisNetworkCorrespondence<'_>, GenesisNetworkCorrespondenceError> {
        // 1. Retained validation policy vs the selected environment's policy.
        let selected_policy = map_environment(selected_environment);
        if selected_policy != self.validation_policy {
            return Err(GenesisNetworkCorrespondenceError::ValidationPolicyMismatch {
                validated_policy: self.validation_policy,
                selected_environment,
                selected_policy,
            });
        }

        // 2. Wire alias obtained through the existing C3A resolver, which also
        //    re-checks the full-width runtime ID. We never accept an
        //    independently supplied raw alias.
        let wire_alias = resolve_network_wire_alias(selected_environment, supplied_runtime)
            .map_err(GenesisNetworkCorrespondenceError::RuntimeMismatch)?;

        // 3. Attach the alias to the same validated identity via an immutable
        //    borrow. No identity field is taken from a separately supplied
        //    caller value.
        Ok(GenesisNetworkCorrespondence {
            identity: self,
            environment: selected_environment,
            runtime: supplied_runtime,
            wire_alias,
        })
    }
}

// ============================================================================
// Run 422 D7-C3B — pinned genesis ⇄ standard network correspondence
// ============================================================================

/// A dormant, **non-authorizing** static correspondence between a pin-validated
/// [`ExpectedGenesisIdentity`] and a standard network mapping.
///
/// It is produced **only** by [`ExpectedGenesisIdentity::check_network_correspondence`]
/// after both the retained-validation-policy check and the C3A runtime/wire
/// resolution succeed. All fields are **private** and the value borrows the
/// validated identity immutably, so it can never be constructed from
/// independently supplied identity fields and never outlives the identity it
/// refers to.
///
/// # What it establishes
///
/// That the selected [`NetworkEnvironment`] matches the environment policy this
/// genesis was validated under, that the supplied full-width runtime
/// [`ChainId`] is the authoritative runtime for that environment (checked by
/// C3A), and the resulting dormant [`NetworkWireAlias`] — all attached to the
/// original validated genesis hash and authority commitment.
///
/// # What it does NOT establish (stated explicitly)
///
/// It is **not** current authority, activation permission, freshness, storage
/// provenance, rollback resistance, or a signing capability. It exposes only
/// read-only inspection accessors and offers **no** conversion into
/// `LocalAuthorizationState::Established`, a `CurrentAuthorizationOwner`, an
/// `AuthorizedProposalVoteSnapshot`, an `AuthorizationTicket`, a
/// `ProposalVoteSigningDomainV2`, or any signer / activated verification
/// context. It also does not prove the operator obtained the correct official
/// genesis pin, and it never chooses an official genesis or asserts uniqueness
/// across forks.
#[derive(Clone, Copy)]
pub struct GenesisNetworkCorrespondence<'a> {
    /// The pin-validated identity this correspondence refers to. Borrowed
    /// immutably; the alias therefore stays attached to the exact validated
    /// genesis hash / authority commitment.
    identity: &'a ExpectedGenesisIdentity,
    /// The selected standard environment (already confirmed to equal the
    /// identity's retained validation policy scope).
    environment: NetworkEnvironment,
    /// The supplied full-width runtime ID (already confirmed by C3A to equal
    /// `environment.chain_id()`).
    runtime: ChainId,
    /// The dormant C3A wire alias for that environment.
    wire_alias: NetworkWireAlias,
}

impl std::fmt::Debug for GenesisNetworkCorrespondence<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenesisNetworkCorrespondence")
            .field("environment", &self.environment)
            .field("runtime", &self.runtime)
            .field("wire_alias", &self.wire_alias)
            .field("genesis_fp", &public_key_fingerprint(self.identity.genesis_hash()))
            .field("validation_policy", &self.identity.validation_policy())
            .finish()
    }
}

impl<'a> GenesisNetworkCorrespondence<'a> {
    /// The selected standard environment for this correspondence.
    pub fn environment(&self) -> NetworkEnvironment {
        self.environment
    }

    /// The full-width runtime [`ChainId`] confirmed for this environment.
    pub fn runtime_chain_id(&self) -> ChainId {
        self.runtime
    }

    /// The dormant C3A wire alias resolved for this environment.
    pub fn wire_alias(&self) -> NetworkWireAlias {
        self.wire_alias
    }

    /// The environment policy under which the underlying identity was
    /// pin-validated (always the policy scope of [`Self::environment`]).
    pub fn validation_policy(&self) -> NetworkEnvironmentPolicy {
        self.identity.validation_policy()
    }

    /// The original validated canonical genesis hash the alias is attached to.
    pub fn genesis_hash(&self) -> &GenesisHash {
        self.identity.genesis_hash()
    }

    /// The original validated authority commitment the alias is attached to.
    pub fn authority_commitment(&self) -> &[u8; 32] {
        self.identity.authority_commitment()
    }

    /// The chain identity label of the underlying validated genesis.
    pub fn chain_id(&self) -> &str {
        self.identity.chain_id()
    }

    /// The committed validator count of the underlying validated identity.
    pub fn validator_count(&self) -> usize {
        self.identity.validator_count()
    }

    /// The founding epoch of the underlying validated identity.
    pub fn founding_epoch(&self) -> u64 {
        self.identity.founding_epoch()
    }

    /// An immutable borrow of the underlying validated identity.
    pub fn identity(&self) -> &'a ExpectedGenesisIdentity {
        self.identity
    }
}

/// Fail-closed reasons a pinned genesis identity does not correspond to a
/// selected standard network mapping.
///
/// Both variants carry only **bounded, non-secret** metadata (environment /
/// policy enums and numeric runtime IDs). Neither `Display` nor `Debug` copies
/// or prints genesis labels, file contents, paths, or key material.
#[derive(Debug)]
pub enum GenesisNetworkCorrespondenceError {
    /// The selected environment's policy differs from the policy the identity
    /// was pin-validated under. Rejecting this prevents relabelling an
    /// already-validated identity under a different environment.
    ValidationPolicyMismatch {
        /// The policy the identity was actually validated under.
        validated_policy: NetworkEnvironmentPolicy,
        /// The environment selected by the caller.
        selected_environment: NetworkEnvironment,
        /// The policy the selected environment maps to.
        selected_policy: NetworkEnvironmentPolicy,
    },
    /// The supplied full-width runtime ID did not match the selected
    /// environment's authoritative runtime. This reuses the C3A mismatch error
    /// verbatim (bounded: environment enum + two numeric [`ChainId`] values).
    RuntimeMismatch(NetworkWireAliasMismatch),
}

impl std::fmt::Display for GenesisNetworkCorrespondenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationPolicyMismatch {
                validated_policy,
                selected_environment,
                selected_policy,
            } => write!(
                f,
                "genesis network correspondence: validation-policy mismatch \
                 (validated under {validated_policy:?}, selected {selected_environment} \
                 mapping to {selected_policy:?})"
            ),
            Self::RuntimeMismatch(e) => write!(
                f,
                "genesis network correspondence: runtime-id mismatch ({e})"
            ),
        }
    }
}

impl std::error::Error for GenesisNetworkCorrespondenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::ValidationPolicyMismatch { .. } => None,
            Self::RuntimeMismatch(e) => Some(e),
        }
    }
}

/// Fail-closed reasons the pinned expected identity could not be constructed.
#[derive(Debug)]
pub enum ExpectedGenesisIdentityError {
    /// The genesis file could not be read/parsed into the single owned
    /// snapshot. Carries the boot-genesis loader's message.
    GenesisReloadFailed { detail: String },
    /// Boot-time re-validation of the reread snapshot (structural + authority +
    /// chain_id + required-pin compare) failed. Carries the verifier's message
    /// verbatim; a pin mismatch surfaces here.
    GenesisRevalidationFailed { detail: String },
    /// The genesis-committed authority itself was rejected (empty/oversized set,
    /// malformed/duplicate key, out-of-range local id, ...).
    Authority(GenesisConsensusAuthorityError),
}

impl std::fmt::Display for ExpectedGenesisIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenesisReloadFailed { detail } => write!(
                f,
                "expected genesis identity: could not read/parse the genesis snapshot: {detail}"
            ),
            Self::GenesisRevalidationFailed { detail } => write!(
                f,
                "expected genesis identity: re-validation against the required pin failed: {detail}"
            ),
            Self::Authority(e) => write!(
                f,
                "expected genesis identity: genesis-committed authority rejected: {e}"
            ),
        }
    }
}

impl std::error::Error for ExpectedGenesisIdentityError {}

// ============================================================================
// Claimed (untrusted) authority-record description
// ============================================================================

/// One validator entry inside an untrusted [`ClaimedAuthorityRecord`].
///
/// Every field is *claimed* by the untrusted record. It is accepted only when it
/// equals the independently established expected value for the same
/// genesis-index position.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedValidatorRecord {
    /// The genesis membership index the record claims for this validator. It is
    /// compared against the canonical genesis-index position; a record whose
    /// declared index does not equal its position is rejected as non-canonical.
    pub index: u64,
    /// The claimed voting power. Compared against the committed (equal) voting
    /// power; a record cannot silently reinterpret a balance/stake as weight.
    pub voting_power: u64,
    /// The claimed consensus signature suite.
    pub suite: ConsensusSigSuiteId,
    /// The claimed complete consensus public-key bytes.
    pub public_key: Vec<u8>,
}

/// An explicitly **untrusted**, bounded, in-memory authority-record description.
///
/// This introduces **no** new database key, storage schema, file format, CLI
/// argument, or production reader/writer. It is a pure in-memory value the
/// caller supplies to the correspondence checker. In tests it is a hand-built
/// fixture, **never** a record read from RocksDB.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimedAuthorityRecord {
    /// Claimed chain identity label.
    pub chain_id: String,
    /// Claimed canonical genesis hash.
    pub genesis_hash: GenesisHash,
    /// Claimed genesis-authority commitment. Never trusted as a substitute for
    /// comparing the full membership contents.
    pub authority_commitment: [u8; 32],
    /// Claimed epoch. Compared against both the expected founding epoch and the
    /// C1 observed epoch.
    pub claimed_epoch: u64,
    /// Claimed validator membership, in canonical genesis-index order.
    pub validators: Vec<ClaimedValidatorRecord>,
}

// ============================================================================
// Correspondence result (correspondence-only; NOT authorization)
// ============================================================================

/// A successful **correspondence-only** result.
///
/// Named and documented so it can never be confused with authorization. It
/// records the fields that were compared and matched, and it always reports the
/// three things it does **not** establish (see the accessor methods below).
/// There is deliberately no method that converts this value into any
/// authorization state, owner, snapshot, ticket, or signing capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenesisRecordCorrespondence {
    chain_id: String,
    genesis_fingerprint: String,
    commitment_fingerprint: String,
    validator_count: usize,
    corresponded_epoch: u64,
}

impl GenesisRecordCorrespondence {
    /// The chain identity label that corresponded.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Short fingerprint of the genesis hash that corresponded.
    pub fn genesis_fingerprint(&self) -> &str {
        &self.genesis_fingerprint
    }

    /// Short fingerprint of the authority commitment that corresponded.
    pub fn commitment_fingerprint(&self) -> &str {
        &self.commitment_fingerprint
    }

    /// The validator count that corresponded.
    pub fn validator_count(&self) -> usize {
        self.validator_count
    }

    /// The epoch (founding epoch 0) that corresponded across the record and the
    /// C1 storage observation. Storage evidence only.
    pub fn corresponded_epoch(&self) -> u64 {
        self.corresponded_epoch
    }

    /// Correspondence-only invariant: storage/record **co-origin is not
    /// established**. Always `false`. A matching hash / commitment and a
    /// successful epoch read do not prove the record and the database share an
    /// origin.
    pub fn storage_record_coorigin_established(&self) -> bool {
        false
    }

    /// Correspondence-only invariant: activation authorization is **not
    /// established**. Always `false`.
    pub fn activation_authorization_established(&self) -> bool {
        false
    }

    /// Correspondence-only invariant: current authorization / freshness is
    /// **unavailable**. Always `false`.
    pub fn current_authorization_available(&self) -> bool {
        false
    }
}

// ============================================================================
// Correspondence errors
// ============================================================================

/// Fail-closed reasons the untrusted record does not correspond to the pinned
/// expected identity (and observed epoch). Every variant is a bounded,
/// non-secret diagnostic; none carries private key material.
#[derive(Debug)]
pub enum RecordCorrespondenceError {
    /// No authority record was supplied. Missing information stays explicit and
    /// is never filled with a default.
    MissingRecord,
    /// The claimed chain identity label differs from the expected one. Only the
    /// bounded byte lengths of the expected and claimed labels are retained: the
    /// untrusted claimed label is **never** cloned, formatted, hashed, or
    /// otherwise copied into the error, so neither `Display` nor derived `Debug`
    /// can reproduce an unbounded label. A length-incompatible claimed label is
    /// rejected before any per-byte comparison; only equal-length labels are
    /// compared byte-for-byte, and an ordinary same-length mismatch is still
    /// rejected here (with `expected_len == claimed_len`).
    ChainIdMismatch { expected_len: usize, claimed_len: usize },
    /// The claimed canonical genesis hash differs from the pinned expected one.
    GenesisHashMismatch {
        expected_fingerprint: String,
        claimed_fingerprint: String,
    },
    /// The claimed authority commitment differs from the expected one.
    AuthorityCommitmentMismatch {
        expected_fingerprint: String,
        claimed_fingerprint: String,
    },
    /// The claimed membership count differs from the committed one.
    MembershipCountMismatch { expected: usize, claimed: usize },
    /// The claimed membership exceeds the existing hard bound before any
    /// per-entry work.
    TooManyClaimedValidators { count: usize, max: usize },
    /// A claimed validator's declared index is not its canonical position; the
    /// record is reordered / has missing / extra entries and is not silently
    /// repaired.
    NonCanonicalMembership {
        position: usize,
        declared_index: u64,
    },
    /// Two claimed validators share the same complete public key (ambiguous
    /// signing identity).
    DuplicateClaimedKey {
        first_position: usize,
        duplicate_position: usize,
        fingerprint: String,
    },
    /// A claimed validator's public key is not exactly the required ML-DSA-44
    /// size.
    ClaimedKeyLengthInvalid {
        position: usize,
        got: usize,
        expected: usize,
    },
    /// A claimed validator uses an unsupported signature suite.
    UnsupportedSuite {
        position: usize,
        claimed_suite: ConsensusSigSuiteId,
        supported_suite: ConsensusSigSuiteId,
    },
    /// A claimed validator's suite differs from the expected suite at the same
    /// genesis-index position.
    ValidatorSuiteMismatch {
        position: usize,
        expected: ConsensusSigSuiteId,
        claimed: ConsensusSigSuiteId,
    },
    /// A claimed validator's public-key bytes differ from the expected ones at
    /// the same genesis-index position.
    ValidatorKeyMismatch {
        position: usize,
        expected_fingerprint: String,
        claimed_fingerprint: String,
    },
    /// A claimed validator's voting power differs from the committed (equal)
    /// weight at the same genesis-index position.
    ValidatorVotingPowerMismatch {
        position: usize,
        expected: u64,
        claimed: u64,
    },
    /// The expected identity is internally missing key material for a committed
    /// index (should be unreachable for a validated snapshot). Surfaced rather
    /// than silently skipped.
    ExpectedKeyUnavailable { position: usize },
    /// The claimed epoch is not the expected founding epoch.
    ClaimedEpochNotFounding {
        claimed_epoch: u64,
        founding_epoch: u64,
    },
    /// The C1 storage observation reported an explicit error; it stays an error
    /// rather than producing a correspondence. The original error is preserved.
    StorageObservationError(ConsensusStorageObservationError),
    /// The C1 observation found no storage handle. Absent storage stays
    /// explicit.
    StorageHandleAbsent,
    /// The C1 observation found storage with no committed epoch. A missing epoch
    /// is never coerced to zero.
    StorageCommittedEpochAbsent,
    /// The claimed epoch and the C1 observed committed epoch disagree.
    RecordStorageEpochMismatch {
        claimed_epoch: u64,
        storage_epoch: u64,
    },
}

impl std::fmt::Display for RecordCorrespondenceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRecord => write!(
                f,
                "no authority record supplied; correspondence cannot be established"
            ),
            Self::ChainIdMismatch { expected_len, claimed_len } => write!(
                f,
                "claimed chain id (byte length {claimed_len}) does not equal the pinned expected \
                 chain id (byte length {expected_len})"
            ),
            Self::GenesisHashMismatch {
                expected_fingerprint,
                claimed_fingerprint,
            } => write!(
                f,
                "claimed genesis identity (fp={claimed_fingerprint}) does not equal the pinned \
                 expected identity (fp={expected_fingerprint})"
            ),
            Self::AuthorityCommitmentMismatch {
                expected_fingerprint,
                claimed_fingerprint,
            } => write!(
                f,
                "claimed authority commitment (fp={claimed_fingerprint}) does not equal the \
                 expected commitment (fp={expected_fingerprint})"
            ),
            Self::MembershipCountMismatch { expected, claimed } => write!(
                f,
                "claimed membership count ({claimed}) does not equal the committed count \
                 ({expected})"
            ),
            Self::TooManyClaimedValidators { count, max } => write!(
                f,
                "claimed membership carries {count} validators, exceeding the maximum of {max}"
            ),
            Self::NonCanonicalMembership {
                position,
                declared_index,
            } => write!(
                f,
                "claimed validator at position {position} declares non-canonical index \
                 {declared_index}"
            ),
            Self::DuplicateClaimedKey {
                first_position,
                duplicate_position,
                fingerprint,
            } => write!(
                f,
                "claimed validators at positions {first_position} and {duplicate_position} share \
                 the same public key (fingerprint {fingerprint}); ambiguous signing identity"
            ),
            Self::ClaimedKeyLengthInvalid {
                position,
                got,
                expected,
            } => write!(
                f,
                "claimed validator at position {position} has a {got}-byte public key; ML-DSA-44 \
                 requires exactly {expected}"
            ),
            Self::UnsupportedSuite {
                position,
                claimed_suite,
                supported_suite,
            } => write!(
                f,
                "claimed validator at position {position} uses unsupported suite {claimed_suite}; \
                 only {supported_suite} is supported"
            ),
            Self::ValidatorSuiteMismatch {
                position,
                expected,
                claimed,
            } => write!(
                f,
                "claimed validator at position {position} suite ({claimed}) does not equal the \
                 expected suite ({expected})"
            ),
            Self::ValidatorKeyMismatch {
                position,
                expected_fingerprint,
                claimed_fingerprint,
            } => write!(
                f,
                "claimed validator at position {position} key (fp={claimed_fingerprint}) does not \
                 equal the expected key (fp={expected_fingerprint})"
            ),
            Self::ValidatorVotingPowerMismatch {
                position,
                expected,
                claimed,
            } => write!(
                f,
                "claimed validator at position {position} voting power ({claimed}) does not equal \
                 the committed weight ({expected})"
            ),
            Self::ExpectedKeyUnavailable { position } => write!(
                f,
                "expected identity is missing key material for committed index {position}"
            ),
            Self::ClaimedEpochNotFounding {
                claimed_epoch,
                founding_epoch,
            } => write!(
                f,
                "claimed epoch ({claimed_epoch}) is not the genesis-static founding epoch \
                 ({founding_epoch})"
            ),
            Self::StorageObservationError(e) => write!(
                f,
                "C1 storage observation error; correspondence not established: {e}"
            ),
            Self::StorageHandleAbsent => write!(
                f,
                "C1 storage observation reports no storage handle; observed epoch unavailable"
            ),
            Self::StorageCommittedEpochAbsent => write!(
                f,
                "C1 storage observation reports storage without a committed epoch; a missing epoch \
                 is never inferred as zero"
            ),
            Self::RecordStorageEpochMismatch {
                claimed_epoch,
                storage_epoch,
            } => write!(
                f,
                "claimed epoch ({claimed_epoch}) does not equal the C1 observed committed epoch \
                 ({storage_epoch})"
            ),
        }
    }
}

impl std::error::Error for RecordCorrespondenceError {}

// ============================================================================
// The correspondence checker
// ============================================================================

/// Compare, field for field, an untrusted [`ClaimedAuthorityRecord`] against a
/// pinned [`ExpectedGenesisIdentity`] and a D7-C1 storage observation.
///
/// Returns [`GenesisRecordCorrespondence`] **only** when every compared field
/// matches. This is a bounded, **non-authorizing** comparison: it establishes
/// only that the compared fields correspond, and its result is never a signing
/// capability, owner, snapshot, ticket, or established authorization state (see
/// the module and [`GenesisRecordCorrespondence`] docs).
///
/// `record` is [`Option`]: a missing record stays an explicit
/// [`RecordCorrespondenceError::MissingRecord`], never a default. `storage` is
/// the exact [`crate::consensus_storage_observation::observe_consensus_storage`]
/// result; a C1 error, absent handle, or absent committed epoch each surface as
/// their own distinct rejection and are never turned into a zero epoch or a
/// success.
///
/// Comparisons (genesis-static scope):
///
/// 1. record presence;
/// 2. chain identity label;
/// 3. canonical genesis identity;
/// 4. existing genesis-authority commitment;
/// 5. membership count and hard bound;
/// 6. complete validator membership using genesis-index identity semantics,
///    with deterministic ordering, duplicate/malformed/unsupported-suite
///    rejection, and per-validator voting power / suite / complete key bytes;
/// 7. claimed epoch vs the expected founding epoch;
/// 8. C1 observation (error / absent handle / absent epoch);
/// 9. claimed epoch vs the C1 observed committed epoch.
pub fn check_genesis_record_correspondence(
    expected: &ExpectedGenesisIdentity,
    record: Option<&ClaimedAuthorityRecord>,
    storage: Result<ConsensusStorageObservation, ConsensusStorageObservationError>,
) -> Result<GenesisRecordCorrespondence, RecordCorrespondenceError> {
    // 1. record presence — missing information stays explicit.
    let record = record.ok_or(RecordCorrespondenceError::MissingRecord)?;

    // 2. chain identity label. Reject an oversized or length-incompatible
    //    claimed label BEFORE cloning, formatting, hashing, or otherwise copying
    //    the complete untrusted label. The expected label was independently
    //    established by pinned genesis validation, so its byte length is the
    //    applicable bound: a claimed label of a different byte length cannot
    //    match and is rejected immediately (short-circuiting before any per-byte
    //    comparison of the untrusted bytes). Only an equal-length label is then
    //    compared byte-for-byte; an ordinary same-length mismatch is still
    //    rejected. Either way, no full copy/fingerprint of the claimed label is
    //    taken — only the two byte lengths are retained as bounded metadata.
    if record.chain_id.len() != expected.chain_id().len()
        || record.chain_id != expected.chain_id()
    {
        return Err(RecordCorrespondenceError::ChainIdMismatch {
            expected_len: expected.chain_id().len(),
            claimed_len: record.chain_id.len(),
        });
    }

    // 3. canonical genesis identity.
    if &record.genesis_hash != expected.genesis_hash() {
        return Err(RecordCorrespondenceError::GenesisHashMismatch {
            expected_fingerprint: public_key_fingerprint(expected.genesis_hash()),
            claimed_fingerprint: public_key_fingerprint(&record.genesis_hash),
        });
    }

    // 4. existing genesis-authority commitment.
    if &record.authority_commitment != expected.authority_commitment() {
        return Err(RecordCorrespondenceError::AuthorityCommitmentMismatch {
            expected_fingerprint: fp_hex(expected.authority_commitment()),
            claimed_fingerprint: fp_hex(&record.authority_commitment),
        });
    }

    // 5. membership count and hard bound. The commitment matching above is NOT
    //    treated as sufficient: the full contents are still compared below.
    if record.validators.len() > MAX_GENESIS_CONSENSUS_VALIDATORS {
        return Err(RecordCorrespondenceError::TooManyClaimedValidators {
            count: record.validators.len(),
            max: MAX_GENESIS_CONSENSUS_VALIDATORS,
        });
    }
    if record.validators.len() != expected.validator_count() {
        return Err(RecordCorrespondenceError::MembershipCountMismatch {
            expected: expected.validator_count(),
            claimed: record.validators.len(),
        });
    }

    // 6. complete validator membership, genesis-index identity semantics.
    let mut seen_keys: HashSet<&Vec<u8>> = HashSet::with_capacity(record.validators.len());
    let mut first_key_pos: std::collections::HashMap<&Vec<u8>, usize> =
        std::collections::HashMap::with_capacity(record.validators.len());
    for (position, claimed) in record.validators.iter().enumerate() {
        // Deterministic ordering: declared index must equal canonical position.
        if claimed.index != position as u64 {
            return Err(RecordCorrespondenceError::NonCanonicalMembership {
                position,
                declared_index: claimed.index,
            });
        }

        // Bounds: exact ML-DSA-44 key size.
        if claimed.public_key.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(RecordCorrespondenceError::ClaimedKeyLengthInvalid {
                position,
                got: claimed.public_key.len(),
                expected: ML_DSA_44_PUBLIC_KEY_SIZE,
            });
        }

        // Unsupported suite (before comparing to expected suite).
        if claimed.suite != SUPPORTED_TIMEOUT_SUITE_ID {
            return Err(RecordCorrespondenceError::UnsupportedSuite {
                position,
                claimed_suite: claimed.suite,
                supported_suite: SUPPORTED_TIMEOUT_SUITE_ID,
            });
        }

        // Duplicate complete public key (ambiguous signing identity).
        if !seen_keys.insert(&claimed.public_key) {
            let first = *first_key_pos.get(&claimed.public_key).unwrap_or(&position);
            return Err(RecordCorrespondenceError::DuplicateClaimedKey {
                first_position: first,
                duplicate_position: position,
                fingerprint: public_key_fingerprint(&claimed.public_key),
            });
        }
        first_key_pos.insert(&claimed.public_key, position);

        // Expected values at the same genesis-index position.
        let expected_id = ValidatorId::new(position as u64);
        let expected_entry = expected
            .authority
            .validators
            .get(position)
            .ok_or(RecordCorrespondenceError::ExpectedKeyUnavailable { position })?;
        let (expected_suite, expected_key) = expected
            .authority
            .key_provider
            .get_suite_and_key(expected_id)
            .ok_or(RecordCorrespondenceError::ExpectedKeyUnavailable { position })?;

        // Voting power (committed equal weight; never reinterpreted).
        if claimed.voting_power != expected_entry.voting_power {
            return Err(RecordCorrespondenceError::ValidatorVotingPowerMismatch {
                position,
                expected: expected_entry.voting_power,
                claimed: claimed.voting_power,
            });
        }
        // Suite.
        if claimed.suite != expected_suite {
            return Err(RecordCorrespondenceError::ValidatorSuiteMismatch {
                position,
                expected: expected_suite,
                claimed: claimed.suite,
            });
        }
        // Complete public-key bytes.
        if claimed.public_key != expected_key {
            return Err(RecordCorrespondenceError::ValidatorKeyMismatch {
                position,
                expected_fingerprint: public_key_fingerprint(&expected_key),
                claimed_fingerprint: public_key_fingerprint(&claimed.public_key),
            });
        }
    }

    // 7. claimed epoch vs the expected founding epoch.
    let founding = expected.founding_epoch();
    if record.claimed_epoch != founding {
        return Err(RecordCorrespondenceError::ClaimedEpochNotFounding {
            claimed_epoch: record.claimed_epoch,
            founding_epoch: founding,
        });
    }

    // 8. C1 observation (error / absent handle / absent epoch stay explicit).
    let storage_epoch = match storage {
        Err(e) => return Err(RecordCorrespondenceError::StorageObservationError(e)),
        Ok(ConsensusStorageObservation::NoStorageHandle) => {
            return Err(RecordCorrespondenceError::StorageHandleAbsent)
        }
        Ok(ConsensusStorageObservation::PresentNoCommittedEpoch) => {
            return Err(RecordCorrespondenceError::StorageCommittedEpochAbsent)
        }
        Ok(ConsensusStorageObservation::CommittedEpoch(e)) => e,
    };

    // 9. claimed epoch vs the C1 observed committed epoch. (The claimed epoch is
    //    already pinned to the founding epoch above, so this also confirms the
    //    observed epoch is the founding one.)
    if record.claimed_epoch != storage_epoch {
        return Err(RecordCorrespondenceError::RecordStorageEpochMismatch {
            claimed_epoch: record.claimed_epoch,
            storage_epoch,
        });
    }

    Ok(GenesisRecordCorrespondence {
        chain_id: expected.chain_id().to_string(),
        genesis_fingerprint: public_key_fingerprint(expected.genesis_hash()),
        commitment_fingerprint: fp_hex(expected.authority_commitment()),
        validator_count: expected.validator_count(),
        corresponded_epoch: storage_epoch,
    })
}

/// Short hex fingerprint of a 32-byte value for diagnostics (mirrors the
/// genesis-authority module's `fp_hex`; kept local to avoid widening that
/// module's public surface).
fn fp_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// ============================================================================
// Logic-level unit tests. Real genesis-loader + real temporary RocksDB
// behavioral coverage lives in the integration target
// `crates/qbind-node/tests/run_422_d7c2_genesis_record_correspondence_tests.rs`.
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis_consensus_authority::GENESIS_STATIC_AUTHORITY_EPOCH;

    #[test]
    fn missing_record_diagnostic_is_bounded_and_self_describing() {
        // This narrow unit test checks only the `MissingRecord` diagnostic
        // itself: its `Display` is stable and self-describing. It does not
        // construct an `ExpectedGenesisIdentity` (which has no cheap
        // constructor). Missing-record behavior *through the real checker* —
        // that a `None` record short-circuits before the expected identity is
        // touched — is exercised against a real pinned expected identity in the
        // integration target (`d7c2_f_missing_record_is_explicit`).
        let e = RecordCorrespondenceError::MissingRecord;
        assert!(e.to_string().contains("no authority record supplied"));
    }

    #[test]
    fn correspondence_reports_non_authorizing_invariants() {
        let c = GenesisRecordCorrespondence {
            chain_id: "chain".to_string(),
            genesis_fingerprint: "aa".to_string(),
            commitment_fingerprint: "bb".to_string(),
            validator_count: 3,
            corresponded_epoch: GENESIS_STATIC_AUTHORITY_EPOCH,
        };
        assert!(!c.storage_record_coorigin_established());
        assert!(!c.activation_authorization_established());
        assert!(!c.current_authorization_available());
        assert_eq!(c.corresponded_epoch(), 0);
        assert_eq!(c.validator_count(), 3);
    }
}