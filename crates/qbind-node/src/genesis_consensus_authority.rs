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
use std::sync::Arc;

use qbind_consensus::ids::ValidatorId;
use qbind_consensus::key_registry::SuiteAwareValidatorKeyProvider;
use qbind_consensus::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
use qbind_crypto::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE;
use qbind_crypto::ConsensusSigSuiteId;
use qbind_ledger::{GenesisConfig, GenesisHash};

use crate::peer_key_provider::decode_strict_hex_pk;
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
}

impl std::fmt::Debug for GenesisConsensusAuthority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GenesisConsensusAuthority")
            .field("validator_count", &self.validator_count)
            .field("chain_id", &self.chain_id)
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
                write!(f, "genesis commits no validators; cannot build consensus authority")
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

    let commitment = compute_authority_commitment(
        &genesis.chain_id,
        canonical_genesis_hash,
        &ordered,
    );

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
    })
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
        let g = genesis_with(vec![
            validator(1, pk.clone(), 100),
            validator(2, pk, 100),
        ]);
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
        let auth =
            build_genesis_consensus_authority(&g, &hash_a(), ValidatorId::new(0)).unwrap();
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
}
