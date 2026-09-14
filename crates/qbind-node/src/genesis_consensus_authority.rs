//! Run 422 — genesis-bound consensus authority for the standalone
//! `qbind-node` production path (Route A).
//!
//! # Why this module exists
//!
//! Runs 031–033 wired a `SuiteAwareValidatorKeyProvider` /
//! `ConsensusValidatorSet` into
//! [`crate::timeout_verification_bridge::try_build_timeout_verification_context`],
//! but they sourced every validator consensus public key from the
//! **operator-supplied, uncommitted** `network.static_peer_consensus_keys`
//! CLI surface (`--validator-consensus-key VID:SUITE:HEXPK`). An
//! uncommitted local override cannot define network authority: two
//! operators can each pass different `--validator-consensus-key` sets
//! and both "activate" against completely different key material with
//! no cryptographic tie to the network they claim to join.
//!
//! Run 422 closes that gap by **binding the consensus authority to the
//! already boot-verified canonical genesis** (Route A per the task
//! scope). The QBIND genesis (`qbind_ledger::GenesisConfig`) already
//! commits, per validator, an ML-DSA-44 `pqc_public_key`
//! (`GenesisValidator::pqc_public_key`, documented as "the validator's
//! signing key for consensus operations"), and the standalone binary
//! already computes and pins the canonical genesis hash at boot via
//! [`crate::pqc_boot_genesis::run_boot_time_genesis_verification`]. This
//! module reuses that canonical source instead of inventing a competing
//! registry: the validator set and the consensus key provider are
//! derived **directly from the genesis-committed validators**, and the
//! resulting immutable snapshot carries the accepted genesis hash so a
//! caller can reject a snapshot that does not match the storage/data-dir
//! network identity.
//!
//! # Trust model (stated explicitly)
//!
//! * The operator accepts a specific network/genesis identity through
//!   the existing trusted bootstrap procedure (external genesis file +
//!   `--expect-genesis-hash`, verified by
//!   `run_boot_time_genesis_verification`). This module does **not**
//!   independently decide that a supplied genesis is "the real network";
//!   it is handed the already-verified [`GenesisHash`] and binds to it.
//! * All validators are expected to accept the same genesis commitment.
//!   The consensus signing preimage binding (chain-aware) remains the
//!   Run 420 responsibility; this module only supplies membership + one
//!   authorized `(suite, public_key)` per validator.
//! * Private keys stay in operator custody and are handled exclusively
//!   by [`crate::signer_loader`] / [`crate::validator_signer`]. This
//!   module never sees, derives, generates, or logs any private key.
//!
//! # Authority separation
//!
//! This module reads **only** `GenesisConfig.validators[].pqc_public_key`.
//! It never reads `GenesisAuthorityConfig` transport roots or
//! bundle-signing roots: a transport certificate, KEMTLS root, or
//! bundle-signing key must never be reinterpreted as consensus signing
//! authority (see [`bundle_and_transport_roots_are_never_consensus_keys`]
//! in the tests).

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
use qbind_crypto::ConsensusSigSuiteId;
use qbind_ledger::{
    verify_boot_time_genesis, GenesisConfig, GenesisHash, NetworkEnvironmentPolicy,
};

use crate::peer_key_provider::decode_strict_hex_pk;
use crate::pqc_boot_genesis::load_external_genesis;
use crate::signer_loader::public_key_fingerprint;
use crate::timeout_verification_bridge::SUPPORTED_TIMEOUT_SUITE_ID;

/// Domain-separation tag for the Run 422 genesis-bound consensus
/// authority commitment. Versioned so a future schema change is a
/// distinct commitment and can never be confused with this one.
pub const GENESIS_CONSENSUS_AUTHORITY_COMMITMENT_TAG: &str =
    "qbind.run422.genesis-consensus-authority.v1";

/// Hard upper bound on the number of genesis validators this loader
/// will process before any per-entry hex decode / cryptographic work.
/// A genesis carrying more than this many validators is rejected
/// up-front so an oversized (or maliciously large) genesis cannot force
/// unbounded allocation / hashing during startup.
pub const MAX_GENESIS_CONSENSUS_VALIDATORS: usize = 4096;

/// Run 422 D7 — the single epoch a genesis-static consensus authority is
/// valid for.
///
/// The QBIND genesis validator set is the founding (epoch 0) membership
/// (`qbind_consensus::validator_set` documents "the genesis epoch (epoch
/// 0)"; the HotStuff engine and the binary path both start at
/// `current_epoch = 0`, and an absent persisted epoch key is treated as
/// epoch 0). A genesis-static authority derived from
/// `GenesisConfig.validators` therefore authorizes **only** epoch 0 with
/// exactly the committed membership and keys.
///
/// This run implements **no** key rotation, revocation, or membership
/// transition (task section 10). Because no safe transition is supported,
/// any observed epoch other than [`GENESIS_STATIC_AUTHORITY_EPOCH`] — i.e.
/// any epoch advance / reconfiguration — has **no authorized transition**
/// and is rejected fail-closed by [`GenesisConsensusAuthority::authorize_configuration`]
/// rather than allowing the stale genesis keys to keep signing. This is a
/// real stale-key guard, not an operational note.
pub const GENESIS_STATIC_AUTHORITY_EPOCH: u64 = 0;

/// Static, in-memory `SuiteAwareValidatorKeyProvider` whose entries are
/// derived exclusively from the genesis-committed validator set. There
/// is deliberately **no** public constructor other than
/// [`build_genesis_consensus_authority`]; the map cannot be mutated
/// after construction.
#[derive(Debug)]
struct GenesisConsensusKeyProvider {
    keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
}

impl SuiteAwareValidatorKeyProvider for GenesisConsensusKeyProvider {
    fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
        self.keys.get(&id).cloned()
    }
}

/// Immutable, validated genesis-bound consensus authority snapshot.
///
/// Produced only by [`build_genesis_consensus_authority`] after every
/// fail-closed cross-check passes. The [`Self::validators`] /
/// [`Self::key_provider`] pair is exactly what the caller feeds into
/// [`crate::timeout_verification_bridge::TimeoutVerificationBridgeInputs`],
/// so `main` constructs its live context from genesis-committed material
/// and nothing else.
pub struct GenesisConsensusAuthority {
    /// Membership derived from genesis validator order (index → id).
    pub validators: Arc<ConsensusValidatorSet>,
    /// Suite + public key per genesis-committed validator.
    pub key_provider: Arc<dyn SuiteAwareValidatorKeyProvider>,
    /// The accepted canonical genesis hash this authority is bound to.
    /// Callers MUST reject a snapshot whose `genesis_hash` disagrees
    /// with the initialized storage / data-dir network identity.
    pub genesis_hash: GenesisHash,
    /// Chain identity of the accepted genesis (`GenesisConfig.chain_id`).
    pub chain_id: String,
    /// Deterministic 32-byte commitment over every security-relevant
    /// field (chain id, genesis hash, and each validator's index /
    /// suite / public key). Two genesis inputs that differ in any of
    /// those fields produce different commitments.
    pub commitment: [u8; 32],
    /// Number of validators in the authority set.
    pub validator_count: usize,
    /// `(validator_id, suite, public-key fingerprint)` triples for safe
    /// startup logging. Never carries full key bytes.
    pub fingerprints: Vec<(ValidatorId, ConsensusSigSuiteId, String)>,
    /// Run 422 D7 — the single epoch this genesis-static authority is
    /// valid for. Always [`GENESIS_STATIC_AUTHORITY_EPOCH`] (the founding
    /// epoch 0); recorded explicitly so the lifetime guard
    /// ([`Self::authorize_configuration`]) can fail closed against any
    /// observed epoch other than the founding one. It is **not** derived
    /// from any live/synthetic epoch source and never participates in the
    /// authority commitment (the commitment already fixes chain / genesis
    /// / membership; the epoch fixes the lifetime).
    ///
    /// Private and immutable, enforced through construction (Run 422 D7
    /// corrective — section 2). The only constructor
    /// ([`build_genesis_consensus_authority`]) always sets it to
    /// [`GENESIS_STATIC_AUTHORITY_EPOCH`]; there is no public field and no
    /// setter, so the "always founding epoch 0" invariant cannot be broken by
    /// a caller mutating the field. Read it via [`Self::authorized_epoch`].
    authorized_epoch: u64,
    /// Run 422 D7-A2 (finding #2, corrective) — the expected wire `chain_id`
    /// of the **complete** selected v2 Proposal/Vote signing domain this
    /// authority is authorized for.
    ///
    /// Held independently of any verifier so
    /// [`crate::binary_consensus_loop::AuthorizedProposalVoteSnapshot::try_bind`]
    /// can require the bound verifier's domain to carry this exact
    /// `expected_wire_chain_id` — closing the gap where an owner authorized for
    /// domain A could otherwise admit a verifier B whose domain differed ONLY
    /// in `expected_wire_chain_id` (runtime chain, genesis and commitment
    /// unchanged).
    ///
    /// `None` in production: the release binary never resolves a runtime→wire
    /// chain-id mapping (no such validated mapping exists in this repository),
    /// so a production-built authority does not cover a wire chain id and can
    /// therefore never bind a verifier — production current-authorization
    /// activation stays unavailable. Only the explicitly `cfg(test)` fixture
    /// constructors set it to `Some`, and even then never by copying an inbound
    /// verifier's domain.
    authorized_wire_chain_id: Option<u32>,
}

impl std::fmt::Debug for GenesisConsensusAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenesisConsensusAuthority")
            .field("validator_count", &self.validator_count)
            .field("chain_id", &self.chain_id)
            .field("authorized_epoch", &self.authorized_epoch)
            .field("commitment_fp", &fp_hex(&self.commitment))
            .field("fingerprints", &self.fingerprints)
            .finish()
    }
}

/// Fail-closed reasons the genesis-bound consensus authority could not
/// be built. Every variant is a precise, bounded diagnostic and never
/// carries key bytes or private material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisConsensusAuthorityError {
    /// `GenesisConfig.validators` is empty. A genesis with no validators
    /// cannot define a consensus authority.
    EmptyValidatorSet,
    /// `GenesisConfig.validators` exceeds
    /// [`MAX_GENESIS_CONSENSUS_VALIDATORS`]; rejected before any
    /// per-entry cryptographic work.
    TooManyValidators { count: usize, max: usize },
    /// A validator's `pqc_public_key` is not strict, non-empty,
    /// even-length, unprefixed hex.
    MalformedValidatorKey {
        validator_index: usize,
        detail: &'static str,
    },
    /// A validator's decoded public key is not exactly
    /// [`ML_DSA_44_PUBLIC_KEY_SIZE`] bytes.
    InvalidKeyLength {
        validator_index: usize,
        got: usize,
        expected: usize,
    },
    /// Two validators commit the same public key. Ambiguous signing
    /// identity — a valid signature could not be uniquely attributed.
    AmbiguousSigningKey {
        first_index: usize,
        duplicate_index: usize,
        fingerprint: String,
    },
    /// Two validators share the same address string. A duplicate
    /// identity in the committed membership.
    DuplicateValidatorAddress {
        first_index: usize,
        duplicate_index: usize,
    },
    /// The requested local validator index is outside the committed
    /// membership range `[0, count)`.
    LocalValidatorOutOfRange { local_index: u64, count: usize },
    /// `ConsensusValidatorSet::new` rejected the assembled entries.
    /// Carries the consensus crate's error string verbatim (never key
    /// bytes).
    ValidatorSetBuildFailed { detail: String },
}

impl std::fmt::Display for GenesisConsensusAuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyValidatorSet => {
                write!(
                    f,
                    "genesis commits no validators; cannot build consensus authority"
                )
            }
            Self::TooManyValidators { count, max } => write!(
                f,
                "genesis commits {count} validators, exceeding the maximum of {max}"
            ),
            Self::MalformedValidatorKey {
                validator_index,
                detail,
            } => write!(
                f,
                "genesis validator index {validator_index} has malformed pqc_public_key: {detail}"
            ),
            Self::InvalidKeyLength {
                validator_index,
                got,
                expected,
            } => write!(
                f,
                "genesis validator index {validator_index} pqc_public_key decodes to {got} bytes; \
                 ML-DSA-44 requires exactly {expected}"
            ),
            Self::AmbiguousSigningKey {
                first_index,
                duplicate_index,
                fingerprint,
            } => write!(
                f,
                "genesis validators at index {first_index} and {duplicate_index} share the same \
                 consensus public key (fingerprint {fingerprint}); ambiguous signing identity"
            ),
            Self::DuplicateValidatorAddress {
                first_index,
                duplicate_index,
            } => write!(
                f,
                "genesis validators at index {first_index} and {duplicate_index} share the same \
                 address; duplicate validator identity"
            ),
            Self::LocalValidatorOutOfRange { local_index, count } => write!(
                f,
                "local validator index {local_index} is outside the genesis membership range \
                 [0, {count})"
            ),
            Self::ValidatorSetBuildFailed { detail } => {
                write!(f, "consensus validator set build failed: {detail}")
            }
        }
    }
}

impl std::error::Error for GenesisConsensusAuthorityError {}

/// Build the immutable, validated genesis-bound consensus authority.
///
/// `genesis` MUST be the same [`GenesisConfig`] whose canonical hash the
/// caller already verified at boot; `canonical_genesis_hash` MUST be the
/// value returned by
/// [`crate::pqc_boot_genesis::run_boot_time_genesis_verification`]. The
/// returned snapshot binds to that hash so a later restart/restore with
/// a mismatched network identity can be rejected before signing.
///
/// `local_validator_id` is validated for membership: it must land inside
/// `[0, genesis.validators.len())`. It does **not** participate in the
/// authority commitment (it is a per-node role, not network authority).
///
/// # Validations (all fail-closed, before any `Some` is published)
///
/// 1. Non-empty validator set, bounded count.
/// 2. Each `pqc_public_key` is strict hex of exactly
///    [`ML_DSA_44_PUBLIC_KEY_SIZE`] bytes.
/// 3. No duplicate public key (ambiguous signing identity) and no
///    duplicate address (duplicate membership).
/// 4. Deterministic ID/index mapping: genesis order index `i` →
///    [`ValidatorId::new`]`(i)`.
/// 5. Local validator index in range.
/// 6. `ConsensusValidatorSet::new` accepts the assembled entries.
pub fn build_genesis_consensus_authority(
    genesis: &GenesisConfig,
    canonical_genesis_hash: &GenesisHash,
    local_validator_id: ValidatorId,
) -> Result<GenesisConsensusAuthority, GenesisConsensusAuthorityError> {
    let count = genesis.validators.len();
    if count == 0 {
        return Err(GenesisConsensusAuthorityError::EmptyValidatorSet);
    }
    if count > MAX_GENESIS_CONSENSUS_VALIDATORS {
        return Err(GenesisConsensusAuthorityError::TooManyValidators {
            count,
            max: MAX_GENESIS_CONSENSUS_VALIDATORS,
        });
    }

    // Decode + validate every committed validator key, in genesis order
    // so index `i` deterministically maps to `ValidatorId(i)`.
    let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
    let mut ordered: Vec<(ValidatorId, Vec<u8>)> = Vec::with_capacity(count);
    // Duplicate detection tables (indexed for precise diagnostics).
    let mut seen_pk: HashMap<Vec<u8>, usize> = HashMap::new();
    let mut seen_addr: HashMap<&str, usize> = HashMap::new();

    for (i, v) in genesis.validators.iter().enumerate() {
        if let Some(&first) = seen_addr.get(v.address.as_str()) {
            return Err(GenesisConsensusAuthorityError::DuplicateValidatorAddress {
                first_index: first,
                duplicate_index: i,
            });
        }
        seen_addr.insert(v.address.as_str(), i);

        let pk = decode_strict_hex_pk(&v.pqc_public_key).map_err(|detail| {
            GenesisConsensusAuthorityError::MalformedValidatorKey {
                validator_index: i,
                detail,
            }
        })?;
        if pk.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(GenesisConsensusAuthorityError::InvalidKeyLength {
                validator_index: i,
                got: pk.len(),
                expected: ML_DSA_44_PUBLIC_KEY_SIZE,
            });
        }
        if let Some(&first) = seen_pk.get(&pk) {
            return Err(GenesisConsensusAuthorityError::AmbiguousSigningKey {
                first_index: first,
                duplicate_index: i,
                fingerprint: public_key_fingerprint(&pk),
            });
        }
        seen_pk.insert(pk.clone(), i);

        let vid = ValidatorId::new(i as u64);
        keys.insert(vid, (SUPPORTED_TIMEOUT_SUITE_ID, pk.clone()));
        ordered.push((vid, pk));
    }

    // Membership check for the local validator role.
    if local_validator_id.as_u64() >= count as u64 {
        return Err(GenesisConsensusAuthorityError::LocalValidatorOutOfRange {
            local_index: local_validator_id.as_u64(),
            count,
        });
    }

    // Assemble the consensus validator set (equal voting power, matching
    // the existing Run 033 provider — voting-weight binding is out of
    // scope for this genesis-static DevNet run).
    let entries: Vec<ValidatorSetEntry> = ordered
        .iter()
        .map(|(vid, _)| ValidatorSetEntry {
            id: *vid,
            voting_power: 1,
        })
        .collect();
    let validators = ConsensusValidatorSet::new(entries)
        .map_err(|detail| GenesisConsensusAuthorityError::ValidatorSetBuildFailed { detail })?;

    let commitment =
        compute_authority_commitment(&genesis.chain_id, canonical_genesis_hash, &ordered);

    let mut fingerprints: Vec<(ValidatorId, ConsensusSigSuiteId, String)> = ordered
        .iter()
        .map(|(vid, pk)| (*vid, SUPPORTED_TIMEOUT_SUITE_ID, public_key_fingerprint(pk)))
        .collect();
    fingerprints.sort_by_key(|(v, _, _)| v.as_u64());

    let provider: Arc<dyn SuiteAwareValidatorKeyProvider> =
        Arc::new(GenesisConsensusKeyProvider { keys });

    Ok(GenesisConsensusAuthority {
        validators: Arc::new(validators),
        key_provider: provider,
        genesis_hash: *canonical_genesis_hash,
        chain_id: genesis.chain_id.clone(),
        commitment,
        validator_count: count,
        fingerprints,
        authorized_epoch: GENESIS_STATIC_AUTHORITY_EPOCH,
        // Production resolves no runtime→wire chain-id mapping, so a
        // production authority covers no wire chain id and can never bind a
        // verifier (Run 422 D7-A2).
        authorized_wire_chain_id: None,
    })
}

/// Fail-closed reasons the shared production activation function
/// [`load_verify_and_build_genesis_authority`] refused to publish a
/// genesis-bound consensus authority. Never carries key bytes.
#[derive(Debug)]
pub enum GenesisAuthorityActivationError {
    /// The external genesis file could not be re-loaded/parsed for the
    /// single owned snapshot. Carries the boot-genesis loader's message.
    GenesisReloadFailed { detail: String },
    /// Full Run 101 re-validation (structural + authority + chain_id +
    /// expected-hash) of the exact reread contents failed. Carries the
    /// verifier's message verbatim.
    GenesisRevalidationFailed { detail: String },
    /// The canonical identity of the reread snapshot does not equal the
    /// identity accepted by boot-time verification. The genesis input was
    /// replaced between the boot stage and this activation stage; the
    /// replacement bytes must never silently become the signing authority.
    IdentityChangedSinceBoot {
        boot_fingerprint: String,
        reread_fingerprint: String,
    },
    /// The genesis-committed authority itself was rejected (empty/oversized
    /// set, malformed/duplicate key, out-of-range local id, ...).
    Authority(GenesisConsensusAuthorityError),
    /// The engine's peer-derived validator count disagrees with the
    /// canonical genesis-committed membership. Consensus membership and
    /// quorum must be defined by the committed authority, never by the
    /// connected-peer count; a mismatch is rejected rather than silently
    /// resized.
    MembershipCountMismatch {
        peer_derived_count: u64,
        genesis_authority_count: usize,
    },
}

impl std::fmt::Display for GenesisAuthorityActivationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::GenesisReloadFailed { detail } => {
                write!(f, "could not re-load the external genesis snapshot: {detail}")
            }
            Self::GenesisRevalidationFailed { detail } => write!(
                f,
                "re-validation of the reread genesis snapshot failed: {detail}"
            ),
            Self::IdentityChangedSinceBoot {
                boot_fingerprint,
                reread_fingerprint,
            } => write!(
                f,
                "reread genesis canonical identity (fp={reread_fingerprint}) does not equal the \
                 boot-accepted identity (fp={boot_fingerprint}); genesis input was replaced after \
                 boot verification"
            ),
            Self::Authority(e) => write!(f, "{e}"),
            Self::MembershipCountMismatch {
                peer_derived_count,
                genesis_authority_count,
            } => write!(
                f,
                "engine peer-derived validator count ({peer_derived_count}) disagrees with the \
                 genesis-committed consensus membership ({genesis_authority_count}); consensus \
                 membership must be defined by the committed authority, not the connected-peer count"
            ),
        }
    }
}

impl std::error::Error for GenesisAuthorityActivationError {}

/// Run 422 D7 — an observed live consensus configuration presented to the
/// genesis-static authority's fail-closed lifetime guard
/// ([`GenesisConsensusAuthority::authorize_configuration`]).
///
/// The caller assembles this from **already-validated** sources — the
/// network identity persisted / re-verified for the running node (chain
/// id, canonical genesis hash), the membership it is actually operating
/// (validator count + the authority commitment that fixes chain / genesis
/// / per-validator index / suite / key), and the epoch it is about to act
/// at. The epoch MUST come from a validated epoch source (e.g. the
/// engine's committed `current_epoch` / persisted epoch key); this type
/// never invents a synthetic epoch and is never used to activate a trust
/// bundle (the fail-closed `CurrentEpochUnavailable` boundary is
/// unchanged — task section 10).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedConsensusConfiguration {
    /// Chain identity the node is currently operating under.
    pub chain_id: String,
    /// Canonical genesis hash currently bound to the node's storage /
    /// data-dir identity.
    pub genesis_hash: GenesisHash,
    /// Deterministic authority commitment of the membership the node is
    /// actually operating (same encoding as
    /// [`GenesisConsensusAuthority::commitment`]).
    pub authority_commitment: [u8; 32],
    /// Number of validators in the operating membership.
    pub validator_count: usize,
    /// Epoch the node is about to sign / verify at. Supplied from a
    /// validated epoch source; never synthesized here.
    pub epoch: u64,
}

impl ObservedConsensusConfiguration {
    /// Assemble an observed configuration from its already-validated
    /// components. Kept explicit (no defaulting) so a caller cannot
    /// accidentally omit the epoch or membership commitment.
    pub fn new(
        chain_id: impl Into<String>,
        genesis_hash: GenesisHash,
        authority_commitment: [u8; 32],
        validator_count: usize,
        epoch: u64,
    ) -> Self {
        Self {
            chain_id: chain_id.into(),
            genesis_hash,
            authority_commitment,
            validator_count,
            epoch,
        }
    }
}

/// Run 422 D7 — fail-closed reasons a genesis-static consensus authority
/// refuses to authorize an observed configuration. Each variant carries
/// only bounded, non-secret diagnostics (fingerprints, counts, epochs);
/// never key bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorityLifetimeError {
    /// The observed chain identity differs from the one this authority was
    /// committed to. The genesis-static keys are bound to a single chain.
    ChainIdChanged {
        authorized: String,
        observed: String,
    },
    /// The observed canonical genesis hash differs from the one this
    /// authority was bound to at build time. A restart / restore / replay
    /// onto a different network identity must never reuse these keys.
    GenesisHashChanged {
        authorized_fingerprint: String,
        observed_fingerprint: String,
    },
    /// The observed authority commitment differs. Any change to the
    /// committed membership, per-validator index, suite, or public key
    /// changes the commitment; the genesis-static authority cannot
    /// authorize a changed validator set.
    AuthorityCommitmentChanged {
        authorized_fingerprint: String,
        observed_fingerprint: String,
    },
    /// The observed membership count differs from the committed one. A
    /// resized validator set is a different authority, not this one.
    MembershipCountChanged {
        authorized: usize,
        observed: usize,
    },
    /// The observed epoch differs from the single founding epoch this
    /// genesis-static authority is valid for. No key rotation / membership
    /// transition is implemented in this run, so there is **no authorized
    /// transition** to a later epoch: the stale genesis keys must not keep
    /// signing across an epoch/membership change. Fail closed.
    EpochTransitionUnauthorized {
        authorized_epoch: u64,
        observed_epoch: u64,
    },
}

impl std::fmt::Display for AuthorityLifetimeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ChainIdChanged {
                authorized,
                observed,
            } => write!(
                f,
                "observed chain id ({observed}) does not equal the genesis-static authority chain \
                 id ({authorized}); the genesis-committed keys are bound to a single chain"
            ),
            Self::GenesisHashChanged {
                authorized_fingerprint,
                observed_fingerprint,
            } => write!(
                f,
                "observed genesis identity (fp={observed_fingerprint}) does not equal the \
                 genesis-static authority identity (fp={authorized_fingerprint}); the genesis-bound \
                 keys must not authorize a different network identity"
            ),
            Self::AuthorityCommitmentChanged {
                authorized_fingerprint,
                observed_fingerprint,
            } => write!(
                f,
                "observed authority commitment (fp={observed_fingerprint}) does not equal the \
                 genesis-static commitment (fp={authorized_fingerprint}); the genesis-static \
                 authority cannot authorize a changed validator set / suite / key"
            ),
            Self::MembershipCountChanged {
                authorized,
                observed,
            } => write!(
                f,
                "observed membership count ({observed}) does not equal the genesis-committed \
                 membership ({authorized}); a resized validator set is a different authority"
            ),
            Self::EpochTransitionUnauthorized {
                authorized_epoch,
                observed_epoch,
            } => write!(
                f,
                "observed epoch ({observed_epoch}) differs from the genesis-static founding epoch \
                 ({authorized_epoch}); no key-rotation / membership transition is implemented, so \
                 the genesis-static authority has no authorized transition and refuses to sign with \
                 stale keys"
            ),
        }
    }
}

impl std::error::Error for AuthorityLifetimeError {}

/// Run 422 D7 (corrective — section 2) — the node's *independently held*
/// current local authorization state, kept explicitly separate from the
/// candidate [`GenesisConsensusAuthority`] snapshot and from any
/// operation-scoped capability.
///
/// Freshness cannot be proven by an authority comparing itself to its own
/// [`GenesisConsensusAuthority::config_identity`]; it must be decided against
/// this independently-sourced value. The three cases are distinguished so a
/// missing or not-yet-established current state can **never** be silently
/// read as "the founding epoch 0":
///
/// * [`Self::MissingStorage`] — no consensus/authority storage exists yet
///   (fresh data dir, wiped state); nothing establishes a current epoch.
/// * [`Self::StorageWithoutCommittedEpoch`] — storage exists but carries no
///   committed epoch key. An engine default of `0` is **not** an established
///   epoch and must not be treated as one.
/// * [`Self::Established`] — a concrete configuration (including epoch) read
///   from a validated source.
///
/// Only [`Self::Established`] can authorize; the other two are unavailable
/// and are rejected fail-closed by
/// [`GenesisConsensusAuthority::authorize_current_state`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalAuthorizationState {
    /// No consensus/authority storage present at all.
    MissingStorage,
    /// Storage present, but no epoch has been committed to it.
    StorageWithoutCommittedEpoch,
    /// An explicitly established current configuration from a validated
    /// source.
    Established(ObservedConsensusConfiguration),
}

/// Bounded, non-secret discriminator for an unavailable current state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CurrentStateUnavailableReason {
    /// No consensus/authority storage present.
    MissingStorage,
    /// Storage present but no committed epoch.
    StorageWithoutCommittedEpoch,
}

/// Run 422 D7 (corrective — section 2) — fail-closed reasons the
/// genesis-static authority refuses to prove freshness against the node's
/// independently held current state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FreshnessError {
    /// The current local authorization state is unavailable, so freshness
    /// cannot be established and authorization is refused. The stale genesis
    /// keys must not be used on the strength of an absent / uncommitted
    /// current epoch, which is never inferred as the founding epoch 0.
    CurrentStateUnavailable {
        /// Which unavailable case was observed (bounded, non-secret).
        reason: CurrentStateUnavailableReason,
    },
    /// The current local authorization state exists but does not match this
    /// authority's single founding configuration/epoch — a superseded
    /// snapshot after epoch advance / membership change / same-epoch
    /// replacement. Carries the underlying lifetime divergence.
    Superseded(AuthorityLifetimeError),
    /// Run 422 D7-A3 — the current-authorization owner has exhausted its
    /// generation space (a replacement could not be represented) and entered a
    /// terminal non-authorizing state. No new admission can succeed; the
    /// genesis-static keys are never used on an exhausted owner. Bounded and
    /// non-secret.
    AuthorizationExhausted,
}

impl std::fmt::Display for FreshnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentStateUnavailable { reason } => write!(
                f,
                "current local authorization state is unavailable ({reason:?}); freshness cannot \
                 be established and the genesis-static authority refuses to sign (an absent or \
                 uncommitted current epoch is never inferred as the founding epoch)"
            ),
            Self::Superseded(inner) => {
                write!(
                    f,
                    "current local authorization state is superseded: {inner}"
                )
            }
            Self::AuthorizationExhausted => write!(
                f,
                "current-authorization owner has exhausted its generation space and is in a \
                 terminal non-authorizing state; no new admission can succeed"
            ),
        }
    }
}

impl std::error::Error for FreshnessError {}

impl GenesisConsensusAuthority {
    /// The single epoch this genesis-static authority is valid for
    /// (always [`GENESIS_STATIC_AUTHORITY_EPOCH`]).
    pub fn authorized_epoch(&self) -> u64 {
        self.authorized_epoch
    }

    /// Run 422 D7-A2 — the expected wire `chain_id` of the complete selected
    /// v2 signing domain this authority is authorized for, if it covers one.
    ///
    /// `None` for a production-built authority (no runtime→wire chain-id
    /// mapping exists), which is why a production authority can never bind a
    /// verifier. Only the `cfg(test)` fixture constructors set `Some`.
    pub fn authorized_wire_chain_id(&self) -> Option<u32> {
        self.authorized_wire_chain_id
    }

    /// The authority's **own** immutable configuration identity, expressed as
    /// an [`ObservedConsensusConfiguration`] at its founding epoch.
    ///
    /// This is a self-description, **not** independent freshness evidence
    /// (Run 422 D7 corrective — section 2): feeding it back into
    /// [`Self::authorize_configuration`] is a tautology — an authority always
    /// equals itself — and proves nothing about whether the node's *current*
    /// state is still the founding one. Freshness must be decided against an
    /// independently-held current state via [`Self::authorize_current_state`],
    /// never against this value.
    pub fn config_identity(&self) -> ObservedConsensusConfiguration {
        ObservedConsensusConfiguration {
            chain_id: self.chain_id.clone(),
            genesis_hash: self.genesis_hash,
            authority_commitment: self.commitment,
            validator_count: self.validator_count,
            epoch: self.authorized_epoch,
        }
    }

    /// Run 422 D7 — fail-closed genesis-static authority lifetime /
    /// freshness guard.
    ///
    /// Returns `Ok(())` **only** when `observed` is byte-for-byte the exact
    /// founding configuration this authority was built from, at the single
    /// founding epoch. Any of the following is rejected without ever
    /// falling back to the stale genesis keys:
    ///
    /// * a different chain id, canonical genesis hash, authority
    ///   commitment, or membership count — this covers a restart / restore
    ///   / replay onto a mismatched network identity or a changed
    ///   validator set (the keys are bound to one immutable configuration);
    /// * any epoch other than the founding [`GENESIS_STATIC_AUTHORITY_EPOCH`]
    ///   — because this run implements no key-rotation / membership
    ///   transition, an epoch advance has **no authorized transition** and
    ///   the genesis-static keys must not keep signing across it.
    ///
    /// Checks are ordered coarse-to-fine (chain → genesis → membership
    /// count → commitment → epoch) so the returned diagnostic names the
    /// first, most fundamental divergence. Every path is total and
    /// non-panicking.
    pub fn authorize_configuration(
        &self,
        observed: &ObservedConsensusConfiguration,
    ) -> Result<(), AuthorityLifetimeError> {
        if observed.chain_id != self.chain_id {
            return Err(AuthorityLifetimeError::ChainIdChanged {
                authorized: self.chain_id.clone(),
                observed: observed.chain_id.clone(),
            });
        }
        if observed.genesis_hash != self.genesis_hash {
            return Err(AuthorityLifetimeError::GenesisHashChanged {
                authorized_fingerprint: public_key_fingerprint(&self.genesis_hash),
                observed_fingerprint: public_key_fingerprint(&observed.genesis_hash),
            });
        }
        if observed.validator_count != self.validator_count {
            return Err(AuthorityLifetimeError::MembershipCountChanged {
                authorized: self.validator_count,
                observed: observed.validator_count,
            });
        }
        if observed.authority_commitment != self.commitment {
            return Err(AuthorityLifetimeError::AuthorityCommitmentChanged {
                authorized_fingerprint: fp_hex(&self.commitment),
                observed_fingerprint: fp_hex(&observed.authority_commitment),
            });
        }
        if observed.epoch != self.authorized_epoch {
            return Err(AuthorityLifetimeError::EpochTransitionUnauthorized {
                authorized_epoch: self.authorized_epoch,
                observed_epoch: observed.epoch,
            });
        }
        Ok(())
    }

    /// Run 422 D7 (corrective — section 2) — fail-closed freshness gate
    /// against the node's **independently held** current authorization state.
    ///
    /// Unlike [`Self::authorize_configuration`] (a pure identity equality
    /// check a caller could trivially satisfy with the authority's own
    /// [`Self::config_identity`]), this method takes a
    /// [`LocalAuthorizationState`] sourced independently of this snapshot and:
    ///
    /// * rejects [`LocalAuthorizationState::MissingStorage`] and
    ///   [`LocalAuthorizationState::StorageWithoutCommittedEpoch`] as
    ///   unavailable — the genesis-static keys are never authorized on the
    ///   strength of an absent / uncommitted current epoch, and epoch 0 is
    ///   never inferred from missing state or an engine default;
    /// * for [`LocalAuthorizationState::Established`], delegates to the
    ///   coarse-to-fine lifetime guard, mapping any divergence to
    ///   [`FreshnessError::Superseded`].
    ///
    /// Returns `Ok(())` only when the independently established current state
    /// is byte-for-byte this authority's founding configuration at the
    /// founding epoch.
    pub fn authorize_current_state(
        &self,
        current: &LocalAuthorizationState,
    ) -> Result<(), FreshnessError> {
        let observed = match current {
            LocalAuthorizationState::MissingStorage => {
                return Err(FreshnessError::CurrentStateUnavailable {
                    reason: CurrentStateUnavailableReason::MissingStorage,
                });
            }
            LocalAuthorizationState::StorageWithoutCommittedEpoch => {
                return Err(FreshnessError::CurrentStateUnavailable {
                    reason: CurrentStateUnavailableReason::StorageWithoutCommittedEpoch,
                });
            }
            LocalAuthorizationState::Established(observed) => observed,
        };
        self.authorize_configuration(observed)
            .map_err(FreshnessError::Superseded)
    }
}

/// Run 422 D7-A3 — an opaque, allocation-backed **issuer identity** for a
/// single [`CurrentAuthorizationOwner`].
///
/// Each owner constructor allocates exactly one of these behind an `Arc`. The
/// identity is the *allocation itself*, not any value it carries (it is a
/// zero-sized marker), so:
///
/// * it is **unique** per owner — two owners built from byte-for-byte
///   identical configurations still hold distinct allocations;
/// * it is **stable across moves** — moving the owner value moves the `Arc`
///   handle, not the heap allocation it points at, so a ticket bound to the
///   allocation stays valid even though the owner's stack address changed;
/// * it is **not forgeable and not reusable** — it is never a raw pointer a
///   caller can fabricate, never a numeric id that could recur, and never a
///   wrapping global counter.
///
/// A ticket retains a clone of its issuer's `Arc<OwnerIdentity>`; confirmation
/// compares allocations with [`Arc::ptr_eq`]. Because the marker is
/// zero-sized and held **separately** from the owner's (large) state, a ticket
/// retaining it keeps only the identity marker alive, never the owner or its
/// snapshot.
#[derive(Debug)]
pub struct OwnerIdentity;

/// Run 422 D7-A — a short-lived, **in-process** admission ticket issued by
/// [`CurrentAuthorizationOwner::admit`] after a freshness check succeeds.
///
/// Run 422 D7-A3 — the ticket is **opaque** and bound to three things fixed at
/// admission:
///
/// * the **issuing owner**, via a clone of that owner's opaque allocation-backed
///   [`OwnerIdentity`] (`issuer`). A *different* owner rejects the ticket in
///   [`CurrentAuthorizationOwner::confirm`] even when both owners have
///   byte-for-byte identical configurations and equal generation numbers, and
///   an unavailable owner never accepts another owner's ticket;
/// * that owner's **immutable authorized snapshot**. The owner's `candidate`
///   authority is fixed for the life of the owner and its private `current`
///   state changes only through a replacement that advances `generation` (or
///   exhausts it). Therefore the pair *(issuer allocation, generation)*
///   uniquely pins the exact snapshot that was admitted: issuer binding plus
///   the generation below is *sufficient* to bind the snapshot, with no need to
///   copy or hash the snapshot into the ticket;
/// * the owner's **generation** at admission. Before an admitted operation
///   applies its effect (engine mutation / outbound), the caller re-confirms
///   the ticket; if the owner's current state was replaced in between
///   (generation advanced) the confirm fails and the operation is refused.
///
/// This is an **in-memory ordering** guarantee only. It is explicitly **not**
/// a durable anti-rollback mechanism and does not prevent an A→B→A signature
/// replay across process restarts: both the issuer allocation and the
/// generation live only for the life of the issuing owner value.
#[derive(Debug, Clone)]
pub struct AuthorizationTicket {
    /// A clone of the issuing owner's opaque allocation-backed identity. Bound
    /// by [`Arc::ptr_eq`] in `confirm`; never compared by value.
    issuer: Arc<OwnerIdentity>,
    generation: u64,
}

impl AuthorizationTicket {
    /// The owner generation this ticket was minted against.
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Whether this ticket was issued by `owner` (identity binding), regardless
    /// of generation. Compares the opaque issuer allocations by pointer.
    pub fn issued_by(&self, owner: &CurrentAuthorizationOwner) -> bool {
        Arc::ptr_eq(&self.issuer, &owner.identity)
    }
}

/// Run 422 D7-A — fail-closed error returned by
/// [`CurrentAuthorizationOwner::confirm`] when the owner's current
/// authorization state was replaced (its generation advanced) between the
/// admitting freshness check and the effect. Bounded, non-secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StaleAuthorizationError {
    /// The generation the admitting check was issued against.
    pub admitted_generation: u64,
    /// The owner's generation at confirm time (strictly greater).
    pub current_generation: u64,
}

impl std::fmt::Display for StaleAuthorizationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "current authorization was replaced between admission (generation {}) and effect \
             (generation {}); the earlier check must not be reused across the in-process \
             invalidation and the operation is refused",
            self.admitted_generation, self.current_generation
        )
    }
}

impl std::error::Error for StaleAuthorizationError {}

/// Run 422 D7-A3 — bounded, non-secret reasons
/// [`CurrentAuthorizationOwner::confirm`] refuses a ticket. Every variant is a
/// fail-closed rejection; none leaks configuration or key material.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmError {
    /// The ticket was not issued by this owner (its opaque issuer identity does
    /// not match). Rejected even if both owners carry identical configurations
    /// and equal generation numbers, and even if this owner is unavailable.
    ForeignIssuer,
    /// The ticket was issued by this owner, but the owner's current
    /// authorization state was replaced (generation advanced) between the
    /// admitting freshness check and the effect. Carries the generation detail.
    Stale(StaleAuthorizationError),
    /// The owner has permanently exhausted its generation space and entered a
    /// terminal non-authorizing state; no ticket — including one issued at the
    /// maximum generation — can be confirmed, and no replacement can restore
    /// authorization.
    Exhausted,
}

impl std::fmt::Display for ConfirmError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ForeignIssuer => f.write_str(
                "authorization ticket was issued by a different current-authorization owner; \
                 it is bound to its issuer and is refused here (the operation is refused)",
            ),
            Self::Stale(inner) => write!(f, "{inner}"),
            Self::Exhausted => f.write_str(
                "current-authorization owner has exhausted its generation space and is in a \
                 terminal non-authorizing state; every outstanding ticket is refused and the \
                 operation is refused",
            ),
        }
    }
}

impl std::error::Error for ConfirmError {}

/// Run 422 D7-A (corrective — section 3) — the **independently maintained
/// owner** of the node's current Proposal/Vote authorization state.
///
/// This type is deliberately distinct from any candidate authority snapshot.
/// The prior public construction
/// `LocalAuthorizationState::Established(auth.config_identity())` let an
/// authority present its **own** stale self-description as "current state",
/// which [`GenesisConsensusAuthority::authorize_current_state`] would then
/// compare against itself (a tautology). Here the current state is held
/// **privately** inside this owner and is obtained only through
/// [`Self::admit`]; a caller can never hand in a self-declared `Established`
/// wrapper as proof, and the authorization-relevant identity fields cannot be
/// swapped after a check without advancing the [`Self::generation`] (which
/// invalidates any outstanding [`AuthorizationTicket`]).
///
/// # Ownership / construction
///
/// * The owner bundles the `candidate` authority (the snapshot presenting
///   itself for admission) with the independently-sourced `current`
///   [`LocalAuthorizationState`]. Keeping both here — with `current` private —
///   is what enforces "obtain current authorization through the owner".
/// * The only **production-reachable** constructor is [`Self::unavailable`],
///   which yields an owner whose current state is explicitly unavailable and
///   therefore can never authorize. There is deliberately **no** production
///   constructor that accepts an arbitrary `Established` current
///   configuration: establishing a concrete current state is available only
///   through the explicitly test-identified [`Self::establish_for_fixture`]
///   (compiled only under `cfg(test)`), so a real trusted current-state
///   lifecycle remains unavailable in release builds.
///
/// # Clone semantics
///
/// This type deliberately does **not** implement [`Clone`]. Each constructor
/// allocates a fresh opaque [`OwnerIdentity`], so there is no way to obtain a
/// second *handle to the same logical owner* — every owner value is a
/// separately maintained owner with its own identity, and a ticket is only
/// ever confirmable by the exact owner that issued it. (No clone is introduced
/// merely to simplify tests; tests move the owner by value to prove
/// move-stability of the allocation-backed identity.)
pub struct CurrentAuthorizationOwner {
    /// Run 422 D7-A3 — this owner's opaque, allocation-backed issuer identity.
    /// A fresh `Arc<OwnerIdentity>` is allocated per constructor; tickets bind
    /// to it by [`Arc::ptr_eq`]. Stable across moves of the owner value.
    identity: Arc<OwnerIdentity>,
    /// The authority snapshot presenting itself for admission. A clone of
    /// this handle still fails admission when the independently-held current
    /// state has moved on — the candidate is not the source of truth for
    /// "current".
    candidate: Arc<GenesisConsensusAuthority>,
    /// The node's independently-sourced current authorization state. Private:
    /// callers cannot read it out and feed it back as a caller-declared proof,
    /// and cannot mutate its identity fields after a check.
    current: LocalAuthorizationState,
    /// Monotonic in-process generation, advanced on every replacement so an
    /// admitted check can detect an intervening invalidation before its
    /// effect. Not durable (see [`AuthorizationTicket`]).
    generation: u64,
    /// Run 422 D7-A3 — terminal exhaustion latch. Set once a generation
    /// advance cannot be represented ([`u64::MAX`] reached). While set, no
    /// admission succeeds, every outstanding ticket (including one issued at
    /// the maximum generation) fails confirmation, and no later replacement can
    /// clear it — there is no wraparound, reset, or silent reuse of the
    /// previous generation.
    exhausted: bool,
}

impl std::fmt::Debug for CurrentAuthorizationOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the full current configuration (avoid leaking the exact
        // committed identity into logs); the availability discriminator and
        // generation are enough for diagnostics.
        let availability = match &self.current {
            LocalAuthorizationState::MissingStorage => "unavailable(MissingStorage)",
            LocalAuthorizationState::StorageWithoutCommittedEpoch => {
                "unavailable(StorageWithoutCommittedEpoch)"
            }
            LocalAuthorizationState::Established(_) => "established",
        };
        f.debug_struct("CurrentAuthorizationOwner")
            .field("candidate_chain_id", &self.candidate.chain_id)
            .field("candidate_commitment_fp", &fp_hex(&self.candidate.commitment))
            .field("current", &availability)
            .field("generation", &self.generation)
            .field("exhausted", &self.exhausted)
            .finish()
    }
}

impl CurrentAuthorizationOwner {
    /// Production-reachable constructor: an owner whose current authorization
    /// state is explicitly **unavailable**. Such an owner can never admit an
    /// operation — [`Self::admit`] returns
    /// [`FreshnessError::CurrentStateUnavailable`]. This is the only owner a
    /// release build can construct, so a present `ProposalVoteAuthority` with
    /// an unavailable current authorization always rejects fail-closed.
    pub fn unavailable(
        candidate: Arc<GenesisConsensusAuthority>,
        reason: CurrentStateUnavailableReason,
    ) -> Self {
        let current = match reason {
            CurrentStateUnavailableReason::MissingStorage => {
                LocalAuthorizationState::MissingStorage
            }
            CurrentStateUnavailableReason::StorageWithoutCommittedEpoch => {
                LocalAuthorizationState::StorageWithoutCommittedEpoch
            }
        };
        Self {
            identity: Arc::new(OwnerIdentity),
            candidate,
            current,
            generation: 0,
            exhausted: false,
        }
    }

    /// The current owner generation (advances on every replacement).
    pub fn generation(&self) -> u64 {
        self.generation
    }

    /// Run 422 D7-A3 — whether this owner has entered the terminal exhausted
    /// (non-authorizing) state after a generation advance overflowed.
    pub fn is_exhausted(&self) -> bool {
        self.exhausted
    }

    /// The candidate authority snapshot presenting itself for admission.
    pub fn candidate(&self) -> &Arc<GenesisConsensusAuthority> {
        &self.candidate
    }

    /// Run 422 D7-A — admit an inbound operation against the independently
    /// held current authorization state.
    ///
    /// The current state is read privately here and checked with the candidate
    /// authority's [`GenesisConsensusAuthority::authorize_current_state`]:
    ///
    /// * a terminally **exhausted** owner (Run 422 D7-A3) is rejected as
    ///   [`FreshnessError::AuthorizationExhausted`] before any freshness check —
    ///   no admission can ever succeed again;
    /// * an unavailable current state (missing storage / no committed epoch)
    ///   is rejected as [`FreshnessError::CurrentStateUnavailable`] — the
    ///   founding epoch is never inferred from absent/uncommitted state;
    /// * an established-but-diverged current state (different chain, genesis,
    ///   membership count, commitment, or epoch — including a same-epoch
    ///   membership/key replacement) is rejected as
    ///   [`FreshnessError::Superseded`].
    ///
    /// On success a ticket bound to this owner's opaque identity and the
    /// current generation is returned; the caller MUST [`Self::confirm`] it
    /// immediately before applying any effect.
    pub fn admit(&self) -> Result<AuthorizationTicket, FreshnessError> {
        if self.exhausted {
            return Err(FreshnessError::AuthorizationExhausted);
        }
        self.candidate.authorize_current_state(&self.current)?;
        Ok(AuthorizationTicket {
            issuer: Arc::clone(&self.identity),
            generation: self.generation,
        })
    }

    /// Run 422 D7-A — re-confirm an admitted ticket immediately before the
    /// operation's effect. Fails closed, in order, if:
    ///
    /// * the ticket was issued by a *different* owner (Run 422 D7-A3 issuer
    ///   binding) — [`ConfirmError::ForeignIssuer`], rejected even for identical
    ///   configuration/generation and even on an unavailable owner;
    /// * this owner is terminally **exhausted** — [`ConfirmError::Exhausted`],
    ///   rejecting every outstanding ticket including one issued at the maximum
    ///   generation;
    /// * the owner's current state was replaced (generation advanced) since
    ///   admission — [`ConfirmError::Stale`], preventing a successful check from
    ///   being reused across an in-process invalidation.
    pub fn confirm(&self, ticket: &AuthorizationTicket) -> Result<(), ConfirmError> {
        if !ticket.issued_by(self) {
            return Err(ConfirmError::ForeignIssuer);
        }
        if self.exhausted {
            return Err(ConfirmError::Exhausted);
        }
        if ticket.generation == self.generation {
            Ok(())
        } else {
            Err(ConfirmError::Stale(StaleAuthorizationError {
                admitted_generation: ticket.generation,
                current_generation: self.generation,
            }))
        }
    }

    /// Explicitly test-identified interface (section 3): establish a concrete
    /// current authorization state from an independently-sourced observed
    /// configuration. Compiled **only** under `cfg(test)` so no release build
    /// can construct an `Established` current authority — production must wait
    /// for a real trusted current-state lifecycle.
    #[cfg(test)]
    pub fn establish_for_fixture(
        candidate: Arc<GenesisConsensusAuthority>,
        observed: ObservedConsensusConfiguration,
    ) -> Self {
        Self {
            identity: Arc::new(OwnerIdentity),
            candidate,
            current: LocalAuthorizationState::Established(observed),
            generation: 0,
            exhausted: false,
        }
    }

    /// Explicitly test-identified interface (section 4): replace the current
    /// authorization state, advancing the generation so any outstanding
    /// [`AuthorizationTicket`] is invalidated. Compiled only under `cfg(test)`;
    /// models the in-flight replacement ordering deterministically without
    /// sleeps.
    ///
    /// Run 422 D7-A3 — the advance is **checked**, not saturating: if the next
    /// generation cannot be represented the owner enters the terminal exhausted
    /// state (`exhausted = true`) with the generation left at [`u64::MAX`] — no
    /// wraparound, no reset to zero, no silent reuse of the previous
    /// generation, and no panic. Once exhausted, the state never changes: a
    /// later replacement leaves the owner exhausted and cannot restore
    /// authorization.
    #[cfg(test)]
    pub fn replace_for_fixture(&mut self, new_state: LocalAuthorizationState) {
        if self.exhausted {
            // Terminal: record the intended state but never restore
            // authorization or move the generation.
            self.current = new_state;
            return;
        }
        match self.generation.checked_add(1) {
            Some(next) => {
                self.current = new_state;
                self.generation = next;
            }
            None => {
                // Generation space exhausted: latch the terminal
                // non-authorizing state. Leave `generation` at u64::MAX (no
                // wraparound / reset) so any ticket — including one issued at
                // the maximum generation — is refused by `confirm` via the
                // `exhausted` gate, and `admit` refuses fail-closed.
                self.current = new_state;
                self.exhausted = true;
            }
        }
    }

    /// Explicitly test-identified interface (Run 422 D7-A3, section 4):
    /// position the owner one advance below the exhaustion boundary so a single
    /// [`Self::replace_for_fixture`] drives it into the terminal exhausted
    /// state deterministically. Compiled **only** under `cfg(test)`; there is
    /// no production path that positions the counter, so production retains
    /// unavailable-only current-authorization construction.
    #[cfg(test)]
    pub fn set_generation_for_exhaustion_fixture(&mut self, generation: u64) {
        self.generation = generation;
    }
}

#[cfg(test)]
impl GenesisConsensusAuthority {
    /// Explicitly test-identified interface (section 3): assemble a candidate
    /// authority directly from already-chosen identity fields, without going
    /// through genesis parsing. Compiled only under `cfg(test)`. The
    /// membership set is synthesized with equal voting power and an empty key
    /// provider — sufficient for the current-authorization freshness boundary,
    /// which consults only chain id, genesis hash, membership count,
    /// commitment, and epoch. This never constructs a production authority.
    pub fn for_current_authorization_fixture(
        chain_id: impl Into<String>,
        genesis_hash: GenesisHash,
        validator_count: usize,
        commitment: [u8; 32],
    ) -> Self {
        let entries: Vec<ValidatorSetEntry> = (0..validator_count as u64)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        let validators = ConsensusValidatorSet::new(entries).expect("valid fixture set");
        let key_provider: Arc<dyn SuiteAwareValidatorKeyProvider> =
            Arc::new(GenesisConsensusKeyProvider {
                keys: HashMap::new(),
            });
        Self {
            validators: Arc::new(validators),
            key_provider,
            genesis_hash,
            chain_id: chain_id.into(),
            commitment,
            validator_count,
            fingerprints: Vec::new(),
            authorized_epoch: GENESIS_STATIC_AUTHORITY_EPOCH,
            // Freshness-only fixture: never bound to a real verifier, so it
            // covers no wire chain id (Run 422 D7-A2).
            authorized_wire_chain_id: None,
        }
    }

    /// Run 422 D7-A2 (finding #2) — explicitly test-identified interface:
    /// assemble a candidate authority that describes the **actual verifier** by
    /// sharing the verifier's real validator membership and suite-aware key
    /// provider (not a synthesized empty-key placeholder). Compiled only under
    /// `cfg(test)`.
    ///
    /// Unlike [`Self::for_current_authorization_fixture`] (which synthesizes an
    /// empty key provider sufficient only for the freshness boundary), this
    /// takes the same `Arc<ConsensusValidatorSet>` and
    /// `Arc<dyn SuiteAwareValidatorKeyProvider>` the Proposal/Vote verifier
    /// uses. A [`crate::binary_consensus_loop::AuthorizedProposalVoteSnapshot`]
    /// built from this authority therefore coheres with the verifier by shared
    /// membership + shared key provider, so admission authorizes the exact
    /// snapshot the handler consumes. This never constructs a production
    /// authority (there is no production route to an `Established` current
    /// state, and `main` builds no `ProposalVoteAuthority`).
    ///
    /// `authorized_wire_chain_id` is the expected wire `chain_id` of the
    /// **complete** v2 signing domain this fixture authority is authorized for.
    /// It is supplied by the owner side independently of any inbound verifier
    /// (Run 422 D7-A2, finding #2): a coherent fixture passes the wire chain id
    /// of the domain it genuinely authorizes, while a regression can pass a
    /// DIFFERENT wire chain id than the paired verifier's domain to prove the
    /// binding rejects an owner-A + verifier-B pair that differs only there.
    pub fn for_verification_snapshot_fixture(
        chain_id: impl Into<String>,
        genesis_hash: GenesisHash,
        commitment: [u8; 32],
        authorized_wire_chain_id: u32,
        validators: Arc<ConsensusValidatorSet>,
        key_provider: Arc<dyn SuiteAwareValidatorKeyProvider>,
    ) -> Self {
        let validator_count = validators.len();
        Self {
            validators,
            key_provider,
            genesis_hash,
            chain_id: chain_id.into(),
            commitment,
            validator_count,
            fingerprints: Vec::new(),
            authorized_epoch: GENESIS_STATIC_AUTHORITY_EPOCH,
            authorized_wire_chain_id: Some(authorized_wire_chain_id),
        }
    }
}

///
/// This is the single function both the release binary (`main.rs`) and the
/// behavioral tests exercise, so the provenance, re-validation,
/// replaced-input, and engine/verifier membership checks are proven by the
/// same code path that publishes the live authority.
///
/// Provenance guarantee (Run 422 corrective, task section 4): the genesis
/// file is read exactly **once** into an owned [`GenesisConfig`]. The
/// canonical identity is derived from that same owned snapshot via
/// [`verify_boot_time_genesis`] (full structural + authority + chain_id +
/// expected-hash validation) and the authority key material is decoded from
/// the *same* parse. Keys from one file read are never paired with a hash
/// from a different read, and `compute_print_genesis_hash` (which reopens
/// the file without authority validation) is not used here.
///
/// Replaced-input guarantee (task section 4): when `boot_accepted_hash` is
/// supplied, the reread canonical identity must equal it or activation is
/// rejected. Replacement bytes can never silently become the signing
/// authority.
///
/// Membership guarantee (task section 5): the engine's `peer_derived_count`
/// (peers + self) must equal the canonical genesis-committed membership, or
/// activation is rejected. The connected-peer count never resizes or
/// redefines the consensus authority.
#[allow(clippy::too_many_arguments)]
pub fn load_verify_and_build_genesis_authority(
    genesis_path: &Path,
    env_policy: NetworkEnvironmentPolicy,
    expected_genesis_hash: Option<&GenesisHash>,
    boot_accepted_hash: Option<&GenesisHash>,
    local_validator_id: ValidatorId,
    peer_derived_count: u64,
) -> Result<GenesisConsensusAuthority, GenesisAuthorityActivationError> {
    // 1. Single owned read of the external genesis snapshot.
    let genesis = load_external_genesis(genesis_path).map_err(|e| {
        GenesisAuthorityActivationError::GenesisReloadFailed {
            detail: e.to_string(),
        }
    })?;

    // 2. Fully re-validate the EXACT reread contents and derive the
    //    canonical identity from this same owned snapshot.
    let canonical_hash = verify_boot_time_genesis(env_policy, &genesis, expected_genesis_hash)
        .map_err(
            |e| GenesisAuthorityActivationError::GenesisRevalidationFailed {
                detail: e.to_string(),
            },
        )?
        .canonical_hash;

    // 3. Require equality with the boot-accepted identity (reject a file
    //    swapped between boot verification and this activation stage).
    if let Some(boot_hash) = boot_accepted_hash {
        if boot_hash != &canonical_hash {
            return Err(GenesisAuthorityActivationError::IdentityChangedSinceBoot {
                boot_fingerprint: public_key_fingerprint(boot_hash),
                reread_fingerprint: public_key_fingerprint(&canonical_hash),
            });
        }
    }

    // 4. Build the immutable, validated authority from the SAME snapshot.
    let authority =
        build_genesis_consensus_authority(&genesis, &canonical_hash, local_validator_id)
            .map_err(GenesisAuthorityActivationError::Authority)?;

    // 5. Engine/verifier membership consistency: the peer-derived count the
    //    engine was configured with must equal the committed authority.
    if peer_derived_count != authority.validator_count as u64 {
        return Err(GenesisAuthorityActivationError::MembershipCountMismatch {
            peer_derived_count,
            genesis_authority_count: authority.validator_count,
        });
    }

    Ok(authority)
}

/// Deterministic, domain-separated commitment over the security-relevant
/// authority fields. `ordered` is in canonical genesis-index order, so
/// the encoding is fully determined by the genesis input (no ambiguous
/// ordering). Every field is length-prefixed to avoid concatenation
/// ambiguity.
fn compute_authority_commitment(
    chain_id: &str,
    genesis_hash: &GenesisHash,
    ordered: &[(ValidatorId, Vec<u8>)],
) -> [u8; 32] {
    let mut body: Vec<u8> = Vec::new();
    let chain_bytes = chain_id.as_bytes();
    body.extend_from_slice(&(chain_bytes.len() as u64).to_be_bytes());
    body.extend_from_slice(chain_bytes);
    body.extend_from_slice(genesis_hash);
    body.extend_from_slice(&(ordered.len() as u64).to_be_bytes());
    for (vid, pk) in ordered {
        body.extend_from_slice(&vid.as_u64().to_be_bytes());
        body.extend_from_slice(&SUPPORTED_TIMEOUT_SUITE_ID.as_u16().to_be_bytes());
        body.extend_from_slice(&(pk.len() as u64).to_be_bytes());
        body.extend_from_slice(pk);
    }
    qbind_hash::hash::sha3_256_tagged(GENESIS_CONSENSUS_AUTHORITY_COMMITMENT_TAG, &body)
}

/// Short hex fingerprint of a 32-byte value for logs.
fn fp_hex(bytes: &[u8; 32]) -> String {
    let mut s = String::with_capacity(16);
    for b in &bytes[..8] {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_ledger::{
        GenesisAllocation, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
        GenesisValidator,
    };

    /// Fresh, real ML-DSA-44 public key hex. Generated per call from the
    /// production backend CSPRNG — no embedded key bytes, and the secret
    /// key is dropped immediately (tests only need the public half).
    fn fresh_pk_hex() -> String {
        let (pk, _sk) = MlDsa44Backend::generate_keypair().expect("ml-dsa-44 keygen");
        assert_eq!(pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
        pk.iter().map(|b| format!("{:02x}", b)).collect()
    }

    fn validator(addr_seed: u8, pk_hex: String, stake: u128) -> GenesisValidator {
        GenesisValidator::new(format!("{:02x}", addr_seed).repeat(32), pk_hex, stake)
    }

    fn genesis_with(validators: Vec<GenesisValidator>) -> GenesisConfig {
        let mut g = GenesisConfig::new(
            "0000000051424e44",
            1_738_000_000_000,
            vec![GenesisAllocation::new(
                "0x1111111111111111111111111111111111111111",
                1_000_000u128,
            )],
            validators,
            GenesisCouncilConfig::new(
                vec![
                    "0xcccccccccccccccccccccccccccccccccccccccc".to_string(),
                    "0xdddddddddddddddddddddddddddddddddddddddd".to_string(),
                    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee".to_string(),
                ],
                2,
            ),
            GenesisMonetaryConfig::mainnet_default(),
        );
        g.chain_id = "0000000051424e44".to_string();
        g
    }

    fn hash_a() -> GenesisHash {
        [0xAAu8; 32]
    }

    #[test]
    fn builds_from_valid_genesis_and_maps_index_to_id() {
        let g = genesis_with(vec![
            validator(1, fresh_pk_hex(), 100),
            validator(2, fresh_pk_hex(), 100),
            validator(3, fresh_pk_hex(), 100),
        ]);
        let auth = build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0))
            .expect("valid genesis builds");
        assert_eq!(auth.validator_count, 3);
        assert!(auth.validators.contains(ValidatorId::new(0)));
        assert!(auth.validators.contains(ValidatorId::new(2)));
        assert!(!auth.validators.contains(ValidatorId::new(3)));
        // Every validator resolves to a 1312-byte ML-DSA-44 key.
        for i in 0..3u64 {
            let (suite, pk) = auth
                .key_provider
                .get_suite_and_key(ValidatorId::new(i))
                .expect("key present");
            assert_eq!(suite, SUPPORTED_TIMEOUT_SUITE_ID);
            assert_eq!(pk.len(), ML_DSA_44_PUBLIC_KEY_SIZE);
        }
    }

    #[test]
    fn commitment_is_deterministic() {
        let g = genesis_with(vec![
            validator(1, fresh_pk_hex(), 100),
            validator(2, fresh_pk_hex(), 100),
        ]);
        let a = build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)).unwrap();
        let b = build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(1)).unwrap();
        // Same genesis + same accepted hash ⇒ identical commitment,
        // regardless of which local validator role is selected.
        assert_eq!(a.commitment, b.commitment);
    }

    #[test]
    fn commitment_changes_with_genesis_hash() {
        let g = genesis_with(vec![validator(1, fresh_pk_hex(), 100)]);
        let a = build_genesis_consensus_authority(&g, &[0xAAu8; 32], ValidatorId::new(0)).unwrap();
        let b = build_genesis_consensus_authority(&g, &[0xBBu8; 32], ValidatorId::new(0)).unwrap();
        assert_ne!(a.commitment, b.commitment);
    }

    #[test]
    fn commitment_changes_with_chain_id() {
        let mut g1 = genesis_with(vec![validator(1, fresh_pk_hex(), 100)]);
        let mut g2 = g1.clone();
        g1.chain_id = "0000000051424e44".to_string();
        g2.chain_id = "0000000051424e45".to_string();
        let a = build_genesis_consensus_authority(&g1, &hash_a(), ValidatorId::new(0)).unwrap();
        let b = build_genesis_consensus_authority(&g2, &hash_a(), ValidatorId::new(0)).unwrap();
        assert_ne!(a.commitment, b.commitment);
    }

    #[test]
    fn commitment_changes_with_a_validator_key() {
        let g1 = genesis_with(vec![validator(1, fresh_pk_hex(), 100)]);
        let g2 = genesis_with(vec![validator(1, fresh_pk_hex(), 100)]);
        let a = build_genesis_consensus_authority(&g1, &hash_a(), ValidatorId::new(0)).unwrap();
        let b = build_genesis_consensus_authority(&g2, &hash_a(), ValidatorId::new(0)).unwrap();
        assert_ne!(a.commitment, b.commitment);
    }

    #[test]
    fn commitment_changes_with_membership_count() {
        // Share validator 0's key so only membership count differs.
        let pk0 = fresh_pk_hex();
        let g1 = genesis_with(vec![validator(1, pk0.clone(), 100)]);
        let g2 = genesis_with(vec![
            validator(1, pk0, 100),
            validator(2, fresh_pk_hex(), 100),
        ]);
        let a = build_genesis_consensus_authority(&g1, &hash_a(), ValidatorId::new(0)).unwrap();
        let b = build_genesis_consensus_authority(&g2, &hash_a(), ValidatorId::new(0)).unwrap();
        assert_ne!(a.commitment, b.commitment);
    }

    #[test]
    fn empty_validator_set_rejected() {
        let g = genesis_with(vec![]);
        assert!(matches!(
            build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)),
            Err(GenesisConsensusAuthorityError::EmptyValidatorSet)
        ));
    }

    #[test]
    fn malformed_key_rejected() {
        let g = genesis_with(vec![validator(1, "zzzz".to_string(), 100)]);
        assert!(matches!(
            build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)),
            Err(GenesisConsensusAuthorityError::MalformedValidatorKey { .. })
        ));
    }

    #[test]
    fn wrong_length_key_rejected() {
        let g = genesis_with(vec![validator(1, "abcd".to_string(), 100)]);
        match build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)) {
            Err(GenesisConsensusAuthorityError::InvalidKeyLength { got, expected, .. }) => {
                assert_eq!(got, 2);
                assert_eq!(expected, ML_DSA_44_PUBLIC_KEY_SIZE);
            }
            other => panic!("expected InvalidKeyLength, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_signing_key_rejected() {
        let pk = fresh_pk_hex();
        let g = genesis_with(vec![validator(1, pk.clone(), 100), validator(2, pk, 100)]);
        match build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)) {
            Err(GenesisConsensusAuthorityError::AmbiguousSigningKey {
                first_index,
                duplicate_index,
                ..
            }) => {
                assert_eq!(first_index, 0);
                assert_eq!(duplicate_index, 1);
            }
            other => panic!("expected AmbiguousSigningKey, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_address_rejected() {
        // Same address string, distinct keys.
        let g = genesis_with(vec![
            GenesisValidator::new("aa".repeat(32), fresh_pk_hex(), 100),
            GenesisValidator::new("aa".repeat(32), fresh_pk_hex(), 100),
        ]);
        match build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)) {
            Err(GenesisConsensusAuthorityError::DuplicateValidatorAddress {
                first_index,
                duplicate_index,
            }) => {
                assert_eq!(first_index, 0);
                assert_eq!(duplicate_index, 1);
            }
            other => panic!("expected DuplicateValidatorAddress, got {other:?}"),
        }
    }

    #[test]
    fn local_out_of_range_rejected() {
        let g = genesis_with(vec![validator(1, fresh_pk_hex(), 100)]);
        assert!(matches!(
            build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(5)),
            Err(GenesisConsensusAuthorityError::LocalValidatorOutOfRange {
                local_index: 5,
                count: 1
            })
        ));
    }

    #[test]
    fn too_many_validators_rejected() {
        let mut vs = Vec::new();
        for i in 0..(MAX_GENESIS_CONSENSUS_VALIDATORS + 1) {
            // Distinct short keys are fine — the count check fires
            // before any hex decode.
            vs.push(GenesisValidator::new(
                format!("{:064x}", i),
                "abcd".to_string(),
                100,
            ));
        }
        let g = genesis_with(vs);
        match build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)) {
            Err(GenesisConsensusAuthorityError::TooManyValidators { count, max }) => {
                assert_eq!(count, MAX_GENESIS_CONSENSUS_VALIDATORS + 1);
                assert_eq!(max, MAX_GENESIS_CONSENSUS_VALIDATORS);
            }
            other => panic!("expected TooManyValidators, got {other:?}"),
        }
    }

    /// A genesis whose authority config carries bundle-signing /
    /// transport roots must NOT pull those keys into the consensus
    /// authority — only `validators[].pqc_public_key` is consensus
    /// authority. Here we assert the provider resolves exactly the
    /// validator keys and nothing else.
    #[test]
    fn bundle_and_transport_roots_are_never_consensus_keys() {
        let vpk = fresh_pk_hex();
        let g = genesis_with(vec![validator(1, vpk.clone(), 100)]);
        let auth = build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)).unwrap();
        // Only validator 0 resolves; there is no phantom validator that
        // could correspond to an authority-root fingerprint.
        let (_, pk0) = auth
            .key_provider
            .get_suite_and_key(ValidatorId::new(0))
            .unwrap();
        assert_eq!(pk0, decode_strict_hex_pk(&vpk).unwrap());
        assert!(auth
            .key_provider
            .get_suite_and_key(ValidatorId::new(1))
            .is_none());
        assert_eq!(auth.validator_count, 1);
    }

    // =====================================================================
    // Run 422 D7-A3 — issuer-bound authorization tickets and fail-closed
    // generation exhaustion. Deterministic, no sleeps / no shared mutable
    // concurrency: replacement and exhaustion are modelled via the explicitly
    // `cfg(test)`-gated fixture interface.
    // =====================================================================
    mod d7a3_ticket_issuer_and_exhaustion {
        use super::*;

        const D7A3_CHAIN: &str = "qbind-d7a3-fixture";
        fn gh() -> GenesisHash {
            [0x33u8; 32]
        }
        const COMMIT: [u8; 32] = [0xA3u8; 32];

        /// A candidate authority with a fixed identity (chain / genesis /
        /// membership count / commitment / founding epoch).
        fn candidate() -> Arc<GenesisConsensusAuthority> {
            Arc::new(GenesisConsensusAuthority::for_current_authorization_fixture(
                D7A3_CHAIN, gh(), 4, COMMIT,
            ))
        }

        /// An owner whose independently-held current state matches its
        /// candidate's founding identity exactly, so `admit` succeeds.
        fn owner_matching() -> CurrentAuthorizationOwner {
            let c = candidate();
            let observed = c.config_identity();
            CurrentAuthorizationOwner::establish_for_fixture(c, observed)
        }

        // ---- Same owner, unchanged snapshot and generation: admit+confirm ok.
        #[test]
        fn same_owner_admit_and_confirm_succeed() {
            let owner = owner_matching();
            let ticket = owner.admit().expect("admit succeeds against matching state");
            assert_eq!(ticket.generation(), 0);
            assert!(ticket.issued_by(&owner));
            owner.confirm(&ticket).expect("confirm succeeds for own fresh ticket");
        }

        // ---- Foreign owner, identical configuration and generation: reject.
        #[test]
        fn foreign_owner_identical_config_and_generation_rejects() {
            let owner_a = owner_matching();
            let owner_b = owner_matching(); // byte-for-byte identical config
            assert_eq!(owner_a.generation(), owner_b.generation());

            let ticket_a = owner_a.admit().expect("A admits");
            // B has an identical configuration and the same generation number,
            // yet the ticket is bound to A's opaque issuer identity.
            assert!(!ticket_a.issued_by(&owner_b));
            assert_eq!(
                owner_b.confirm(&ticket_a),
                Err(ConfirmError::ForeignIssuer),
                "a foreign owner must reject another owner's ticket even with identical \
                 configuration and matching generation",
            );
            // A still confirms its own ticket.
            owner_a.confirm(&ticket_a).expect("A confirms its own ticket");
        }

        // ---- Foreign UNAVAILABLE owner at the same generation: reject.
        #[test]
        fn foreign_unavailable_owner_same_generation_rejects() {
            let owner_a = owner_matching();
            let owner_unavailable = CurrentAuthorizationOwner::unavailable(
                candidate(),
                CurrentStateUnavailableReason::MissingStorage,
            );
            assert_eq!(owner_a.generation(), owner_unavailable.generation());

            let ticket_a = owner_a.admit().expect("A admits");
            // An unavailable owner can never itself admit...
            assert!(matches!(
                owner_unavailable.admit(),
                Err(FreshnessError::CurrentStateUnavailable { .. })
            ));
            // ...and must never accept another owner's ticket.
            assert_eq!(
                owner_unavailable.confirm(&ticket_a),
                Err(ConfirmError::ForeignIssuer),
                "an unavailable owner must never accept another owner's ticket",
            );
        }

        // ---- Moving the owner does not invalidate its legitimate ticket.
        #[test]
        fn moving_owner_preserves_ticket() {
            let owner = owner_matching();
            let ticket = owner.admit().expect("admit");

            // Force the owner value to a new stack address by moving it into a
            // helper and back. The opaque allocation-backed identity is stable
            // across the move, so the ticket remains valid.
            fn move_through(o: CurrentAuthorizationOwner) -> CurrentAuthorizationOwner {
                let boxed = Box::new(o);
                *boxed
            }
            let moved = move_through(owner);
            assert!(ticket.issued_by(&moved));
            moved
                .confirm(&ticket)
                .expect("a moved owner still confirms its own legitimate ticket");
        }

        // ---- Ordinary replacement invalidates earlier tickets, including a
        // replacement with an identical configuration.
        #[test]
        fn replacement_invalidates_earlier_ticket_even_identical_config() {
            let mut owner = owner_matching();
            let observed = owner.candidate().config_identity();
            let ticket = owner.admit().expect("admit at gen 0");

            // Replace with the *identical* configuration: still a replacement,
            // still advances the generation, still invalidates the ticket.
            owner.replace_for_fixture(LocalAuthorizationState::Established(observed.clone()));
            assert_eq!(owner.generation(), 1);
            match owner.confirm(&ticket) {
                Err(ConfirmError::Stale(inner)) => {
                    assert_eq!(inner.admitted_generation, 0);
                    assert_eq!(inner.current_generation, 1);
                }
                other => panic!("expected Stale after identical-config replacement, got {other:?}"),
            }
            // A fresh admit against the (identical) established state binds the
            // new generation and confirms.
            let fresh = owner.admit().expect("re-admit after replacement");
            assert_eq!(fresh.generation(), 1);
            owner.confirm(&fresh).expect("fresh ticket confirms");
        }

        // ---- Near-maximum generation advancement behaves correctly.
        #[test]
        fn near_maximum_generation_advances_without_exhaustion() {
            let mut owner = owner_matching();
            let observed = owner.candidate().config_identity();
            // Position one advance below the boundary.
            owner.set_generation_for_exhaustion_fixture(u64::MAX - 1);
            let ticket_penultimate = owner.admit().expect("admit near max");
            assert_eq!(ticket_penultimate.generation(), u64::MAX - 1);

            // One advance reaches exactly u64::MAX and does NOT exhaust.
            owner.replace_for_fixture(LocalAuthorizationState::Established(observed));
            assert_eq!(owner.generation(), u64::MAX);
            assert!(!owner.is_exhausted());
            // The earlier ticket is stale; a new admit at MAX succeeds.
            assert!(matches!(
                owner.confirm(&ticket_penultimate),
                Err(ConfirmError::Stale(_))
            ));
            let ticket_max = owner.admit().expect("admit at max generation");
            assert_eq!(ticket_max.generation(), u64::MAX);
            owner.confirm(&ticket_max).expect("max-generation ticket confirms while not exhausted");
        }

        // ---- Exhaustion permanently rejects admission and confirmation,
        // including the last ticket issued at the maximum generation.
        #[test]
        fn exhaustion_permanently_rejects_admit_and_confirm() {
            let mut owner = owner_matching();
            let observed = owner.candidate().config_identity();
            owner.set_generation_for_exhaustion_fixture(u64::MAX);

            // A ticket legitimately issued at the maximum generation.
            let ticket_max = owner.admit().expect("admit at max before exhaustion");
            assert_eq!(ticket_max.generation(), u64::MAX);
            owner.confirm(&ticket_max).expect("confirms before exhaustion");

            // The next replacement cannot represent generation+1: the owner
            // enters the terminal exhausted state — no wraparound / reset.
            owner.replace_for_fixture(LocalAuthorizationState::Established(observed));
            assert!(owner.is_exhausted());
            assert_eq!(owner.generation(), u64::MAX, "no wraparound / reset to zero");

            // No new admission succeeds.
            assert_eq!(owner.admit().unwrap_err(), FreshnessError::AuthorizationExhausted);
            // Every outstanding ticket fails confirmation, including the one
            // issued at the maximum generation (its generation still equals the
            // owner's, but the exhausted gate rejects it).
            assert_eq!(ticket_max.generation(), owner.generation());
            assert_eq!(owner.confirm(&ticket_max), Err(ConfirmError::Exhausted));
        }

        // ---- Repeated attempts after exhaustion remain rejected; a later
        // replacement cannot restore authorization.
        #[test]
        fn repeated_attempts_after_exhaustion_remain_rejected() {
            let mut owner = owner_matching();
            let observed = owner.candidate().config_identity();
            owner.set_generation_for_exhaustion_fixture(u64::MAX);
            let ticket_max = owner.admit().expect("admit at max");
            owner.replace_for_fixture(LocalAuthorizationState::Established(observed.clone()));
            assert!(owner.is_exhausted());

            for _ in 0..3 {
                // Later replacement attempts cannot restore authorization.
                owner.replace_for_fixture(LocalAuthorizationState::Established(observed.clone()));
                assert!(owner.is_exhausted());
                assert_eq!(owner.generation(), u64::MAX);
                assert_eq!(owner.admit().unwrap_err(), FreshnessError::AuthorizationExhausted);
                assert_eq!(owner.confirm(&ticket_max), Err(ConfirmError::Exhausted));
            }
        }

        // ---- Clone semantics: the owner is intentionally not `Clone`, so a
        // second handle to the same logical owner cannot be forged; a
        // separately constructed owner always has a distinct issuer identity.
        #[test]
        fn separately_constructed_owners_have_distinct_identities() {
            let owner_a = owner_matching();
            let owner_b = owner_matching();
            let ticket_a = owner_a.admit().expect("A admits");
            let ticket_b = owner_b.admit().expect("B admits");
            assert!(ticket_a.issued_by(&owner_a));
            assert!(ticket_b.issued_by(&owner_b));
            assert!(!ticket_a.issued_by(&owner_b));
            assert!(!ticket_b.issued_by(&owner_a));
        }

        // ---- Shared candidate, distinct issuers: two independent owners built
        // from clones of *the same* candidate `Arc` still hold distinct opaque
        // issuer identities. This isolates issuer identity from candidate
        // identity: the owners share one candidate allocation
        // (`Arc::ptr_eq`) and carry identical observed configuration and equal
        // generations, yet each confirms only its own ticket and rejects the
        // other's with `ConfirmError::ForeignIssuer`.
        #[test]
        fn shared_candidate_owners_have_distinct_issuer_identities() {
            // Exactly one candidate allocation.
            let shared = candidate();
            let observed = shared.config_identity();

            // Two independent owners from clones of the *same* candidate Arc,
            // with byte-for-byte identical observed configuration.
            let owner_a =
                CurrentAuthorizationOwner::establish_for_fixture(Arc::clone(&shared), observed.clone());
            let owner_b =
                CurrentAuthorizationOwner::establish_for_fixture(Arc::clone(&shared), observed);

            // Equal generations...
            assert_eq!(owner_a.generation(), owner_b.generation());
            // ...and the *same* candidate allocation behind both owners.
            assert!(
                Arc::ptr_eq(owner_a.candidate(), owner_b.candidate()),
                "both owners must share the single candidate allocation",
            );
            assert!(Arc::ptr_eq(owner_a.candidate(), &shared));

            // A ticket from each owner.
            let ticket_a = owner_a.admit().expect("A admits against shared candidate");
            let ticket_b = owner_b.admit().expect("B admits against shared candidate");

            // Each owner confirms its own ticket.
            owner_a.confirm(&ticket_a).expect("A confirms its own ticket");
            owner_b.confirm(&ticket_b).expect("B confirms its own ticket");

            // Each owner rejects the other's ticket with ForeignIssuer, even
            // though they share a candidate allocation and equal generations.
            assert_eq!(
                owner_b.confirm(&ticket_a),
                Err(ConfirmError::ForeignIssuer),
                "B must reject A's ticket despite the shared candidate allocation",
            );
            assert_eq!(
                owner_a.confirm(&ticket_b),
                Err(ConfirmError::ForeignIssuer),
                "A must reject B's ticket despite the shared candidate allocation",
            );
        }
    }
}