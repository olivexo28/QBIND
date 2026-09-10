//! Cryptographic verification of `BlockProposal` and `Vote` (F3 / F4 / F8, Run 420).
//!
//! This module provides the smallest honest binary-path-ready cryptographic
//! verification primitive for HotStuff proposal and vote traffic. It does
//! **not** introduce a parallel crypto path: it reuses the existing
//! `SuiteAwareValidatorKeyProvider` (governance-backed key + suite source)
//! and `ConsensusSigBackendRegistry` (suite → backend dispatch) abstractions
//! already used to verify timeouts (`timeout_verify.rs`) and by the
//! `MultiSuiteCryptoVerifier` (`crypto_verifier.rs`).
//!
//! # Scope (Run 420)
//!
//! - [`verify_proposal_msg`]: per-message verification of a received
//!   `BlockProposal`. Checks claimed-sender binding, membership,
//!   missing-signature, suite presence/policy/registration, governed key
//!   lookup, and the signature over the chain-ID-aware preimage emitted by
//!   [`qbind_wire::consensus::BlockProposal::signing_preimage_with_chain_id`].
//! - [`verify_vote_msg`]: the analogous per-message verification for a
//!   received `Vote`, over
//!   [`qbind_wire::consensus::Vote::signing_preimage_with_chain_id`].
//!
//! # Fail-closed contract
//!
//! Both primitives fail closed at the first failing step and return a typed
//! [`ProposalVoteVerifyError`]. A caller that gates mutation-capable engine
//! ingestion on `Ok(())` therefore cannot admit an unsigned, invalidly
//! signed, wrong-key, wrong-suite, unsupported-suite, unknown-validator, or
//! signer/claimed-validator-mismatched message. There is NO default,
//! fallback, first-supported-suite, cross-suite retry, or classical-suite
//! downgrade: dispatch happens only through the single governance-selected,
//! registry-backed suite backend.
//!
//! # Separation of authority
//!
//! `claimed` is the authenticated consensus sender established by the Run 418
//! F6 transport-to-consensus-sender binding. This module additionally
//! requires that the message's self-declared proposer/voter index equals that
//! authenticated sender AND that the signature verifies against the
//! authoritative consensus key for that validator. Transport identity (F6)
//! and message signature (F3/F4) are thus BOTH required; neither substitutes
//! for the other.

use std::sync::Arc;

use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ConsensusSigSuiteId;
use qbind_types::ChainId;
use qbind_wire::consensus::{BlockProposal, Vote};

use crate::crypto_verifier::ConsensusSigBackendRegistry;
use crate::ids::ValidatorId;
use crate::key_registry::SuiteAwareValidatorKeyProvider;
use crate::validator_set::ConsensusValidatorSet;

/// Errors produced by the proposal/vote cryptographic verification primitives.
///
/// The variants form a bounded, typed rejection taxonomy suitable for driving
/// per-reason metrics counters (see the caller in
/// `binary_consensus_loop.rs`). No variant carries attacker-controlled
/// free-form strings except [`ProposalVoteVerifyError::BackendError`], whose
/// message is produced by our own suite backends, never by wire input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProposalVoteVerifyError {
    /// The message's self-declared sender does not match the authenticated
    /// consensus sender (Run 418 F6 binding). This is a fail-closed defense
    /// even though the binary loop derives `claimed` from the same index:
    /// it guarantees the verify primitive itself cannot be misused to accept
    /// a message on behalf of a different validator.
    SignerMismatch {
        /// The authenticated consensus sender (F6-bound).
        claimed: ValidatorId,
        /// The validator index self-declared inside the message.
        message: ValidatorId,
    },
    /// The signer is not a member of the active validator set.
    UnknownValidator(ValidatorId),
    /// The signature field is empty (unsigned message).
    MissingSignature(ValidatorId),
    /// No public key is registered for the signer (governance gap).
    MissingKey(ValidatorId),
    /// No verifier backend is registered/allowed for the governance suite of
    /// the signer.
    UnsupportedSuite {
        /// The signer.
        validator_id: ValidatorId,
        /// The governance-configured suite for this signer.
        governance_suite: ConsensusSigSuiteId,
    },
    /// The wire `suite_id` carried in the message does not match the
    /// governance-configured suite for the signer.
    SuiteMismatch {
        /// The signer.
        validator_id: ValidatorId,
        /// The suite_id carried on the wire.
        wire_suite: ConsensusSigSuiteId,
        /// The suite_id from governance.
        governance_suite: ConsensusSigSuiteId,
    },
    /// The signature did not verify against the governed public key + the
    /// chain-aware signing preimage.
    InvalidSignature(ValidatorId),
    /// The signature bytes were structurally malformed (wrong length, etc.)
    /// before any cryptographic check could complete.
    MalformedSignature(ValidatorId),
    /// A signature/verifier-backend error other than "invalid signature".
    BackendError(ValidatorId, String),
}

impl std::fmt::Display for ProposalVoteVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProposalVoteVerifyError::SignerMismatch { claimed, message } => write!(
                f,
                "signer mismatch: authenticated sender {:?} != message index {:?}",
                claimed, message
            ),
            ProposalVoteVerifyError::UnknownValidator(id) => {
                write!(f, "unknown validator: {:?}", id)
            }
            ProposalVoteVerifyError::MissingSignature(id) => {
                write!(f, "missing signature from validator: {:?}", id)
            }
            ProposalVoteVerifyError::MissingKey(id) => {
                write!(f, "missing key for validator: {:?}", id)
            }
            ProposalVoteVerifyError::UnsupportedSuite {
                validator_id,
                governance_suite,
            } => write!(
                f,
                "unsupported suite for validator {:?}: governance_suite={}",
                validator_id, governance_suite
            ),
            ProposalVoteVerifyError::SuiteMismatch {
                validator_id,
                wire_suite,
                governance_suite,
            } => write!(
                f,
                "suite mismatch for validator {:?}: wire={}, governance={}",
                validator_id, wire_suite, governance_suite
            ),
            ProposalVoteVerifyError::InvalidSignature(id) => {
                write!(f, "invalid signature from validator: {:?}", id)
            }
            ProposalVoteVerifyError::MalformedSignature(id) => {
                write!(f, "malformed signature from validator: {:?}", id)
            }
            ProposalVoteVerifyError::BackendError(id, msg) => {
                write!(f, "backend error for validator {:?}: {}", id, msg)
            }
        }
    }
}

impl std::error::Error for ProposalVoteVerifyError {}

/// Per-call outcome bucket for metrics callers (Run 420 observability).
///
/// This is a bounded enum, never an attacker-controlled string, so it is safe
/// to use as a metric label.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProposalVoteVerifyOutcome {
    /// Signature, suite, membership and sender binding all verified.
    Accepted,
    /// Authenticated sender does not match the self-declared message index.
    SignerMismatch,
    /// Signer is not a member of the active validator set.
    UnknownValidator,
    /// Signature field was empty.
    MissingSignature,
    /// No governed public key for the signer.
    MissingKey,
    /// Governance suite has no registered/allowed backend.
    UnsupportedSuite,
    /// Wire suite does not match the governed suite.
    WrongSuite,
    /// Signature bytes did not verify (cryptographic failure).
    BadSignature,
    /// Signature bytes were malformed for the selected suite.
    MalformedSignature,
    /// Internal verifier/backend error.
    InternalError,
}

impl From<&ProposalVoteVerifyError> for ProposalVoteVerifyOutcome {
    fn from(e: &ProposalVoteVerifyError) -> Self {
        match e {
            ProposalVoteVerifyError::SignerMismatch { .. } => {
                ProposalVoteVerifyOutcome::SignerMismatch
            }
            ProposalVoteVerifyError::UnknownValidator(_) => {
                ProposalVoteVerifyOutcome::UnknownValidator
            }
            ProposalVoteVerifyError::MissingSignature(_) => {
                ProposalVoteVerifyOutcome::MissingSignature
            }
            ProposalVoteVerifyError::MissingKey(_) => ProposalVoteVerifyOutcome::MissingKey,
            ProposalVoteVerifyError::UnsupportedSuite { .. } => {
                ProposalVoteVerifyOutcome::UnsupportedSuite
            }
            ProposalVoteVerifyError::SuiteMismatch { .. } => ProposalVoteVerifyOutcome::WrongSuite,
            ProposalVoteVerifyError::InvalidSignature(_) => ProposalVoteVerifyOutcome::BadSignature,
            ProposalVoteVerifyError::MalformedSignature(_) => {
                ProposalVoteVerifyOutcome::MalformedSignature
            }
            ProposalVoteVerifyError::BackendError(_, _) => ProposalVoteVerifyOutcome::InternalError,
        }
    }
}

/// Shared verification core used by both proposal and vote paths.
///
/// Steps (in order, fail-closed at the first failure):
///
/// 1. Sender binding: `claimed` (F6-authenticated) == `message_signer`.
/// 2. Membership: `message_signer` ∈ `validators`.
/// 3. Missing signature: `signature` is non-empty.
/// 4. Governance lookup: `(governance_suite, pk)` for `message_signer`.
/// 5. Suite match: wire `suite_id` == `governance_suite`.
/// 6. Backend dispatch: a registered/allowed backend exists for the suite.
/// 7. Cryptographic verification of `signature` over `preimage`.
///
/// `verify` selects the suite-backend entrypoint (`verify_proposal` or
/// `verify_vote`); both share ML-DSA-44 semantics (a single per-validator
/// signature over the canonical preimage).
#[allow(clippy::too_many_arguments)]
fn verify_core<K, B, Vfn>(
    claimed: ValidatorId,
    message_signer: ValidatorId,
    wire_suite_id: u16,
    signature: &[u8],
    validators: &ConsensusValidatorSet,
    key_provider: &K,
    backend_registry: &B,
    preimage: &[u8],
    verify: Vfn,
) -> Result<(), ProposalVoteVerifyError>
where
    K: SuiteAwareValidatorKeyProvider + ?Sized,
    B: ConsensusSigBackendRegistry + ?Sized,
    Vfn: Fn(
        &Arc<dyn ConsensusSigVerifier>,
        u64,
        &[u8],
        &[u8],
        &[u8],
    ) -> Result<(), ConsensusSigError>,
{
    // Step 1: bind the authenticated transport sender (F6) to the message's
    // self-declared signer index. Both F6 identity and a valid signature are
    // required; this guarantees the primitive cannot accept a message under a
    // different validator's authority.
    if claimed != message_signer {
        return Err(ProposalVoteVerifyError::SignerMismatch {
            claimed,
            message: message_signer,
        });
    }

    // Step 2: membership in the active validator set.
    if !validators.contains(message_signer) {
        return Err(ProposalVoteVerifyError::UnknownValidator(message_signer));
    }

    // Step 3: reject unsigned messages before any key/suite work.
    if signature.is_empty() {
        return Err(ProposalVoteVerifyError::MissingSignature(message_signer));
    }

    // Step 4: governance lookup of (suite, pk_bytes).
    let (governance_suite, pk_bytes) = match key_provider.get_suite_and_key(message_signer) {
        Some(result) => result,
        None => return Err(ProposalVoteVerifyError::MissingKey(message_signer)),
    };

    // Step 5: suite ID match between wire and governance. No coercion,
    // truncation, or cross-suite retry: an altered/foreign suite fails closed.
    let wire_suite = ConsensusSigSuiteId::new(wire_suite_id);
    if wire_suite != governance_suite {
        return Err(ProposalVoteVerifyError::SuiteMismatch {
            validator_id: message_signer,
            wire_suite,
            governance_suite,
        });
    }

    // Step 6: backend dispatch via the suite registry (policy-allowed +
    // registered). Unsupported/disallowed suites fail BEFORE cryptographic
    // work.
    let backend: Arc<dyn ConsensusSigVerifier> =
        match backend_registry.get_backend(governance_suite) {
            Some(b) => b,
            None => {
                return Err(ProposalVoteVerifyError::UnsupportedSuite {
                    validator_id: message_signer,
                    governance_suite,
                });
            }
        };

    // Step 7: cryptographic verification over the canonical preimage.
    match verify(
        &backend,
        message_signer.as_u64(),
        &pk_bytes,
        preimage,
        signature,
    ) {
        Ok(()) => Ok(()),
        Err(ConsensusSigError::InvalidSignature) => {
            Err(ProposalVoteVerifyError::InvalidSignature(message_signer))
        }
        Err(ConsensusSigError::MalformedSignature) => {
            Err(ProposalVoteVerifyError::MalformedSignature(message_signer))
        }
        Err(ConsensusSigError::MissingKey(_)) => {
            Err(ProposalVoteVerifyError::MissingKey(message_signer))
        }
        Err(ConsensusSigError::Other(msg)) => {
            Err(ProposalVoteVerifyError::BackendError(message_signer, msg))
        }
    }
}

/// Verify a single received `BlockProposal` fail-closed.
///
/// `claimed` is the Run 418 F6-authenticated consensus sender. The message's
/// `header.proposer_index` must equal `claimed`, the signer must be a member
/// of `validators`, the signature must be present, the wire `suite_id` must
/// match the governed suite, the suite must have a registered/allowed backend,
/// and the signature must verify over
/// [`BlockProposal::signing_preimage_with_chain_id`].
pub fn verify_proposal_msg<K, B>(
    proposal: &BlockProposal,
    claimed: ValidatorId,
    validators: &ConsensusValidatorSet,
    key_provider: &K,
    backend_registry: &B,
    chain_id: ChainId,
) -> Result<(), ProposalVoteVerifyError>
where
    K: SuiteAwareValidatorKeyProvider + ?Sized,
    B: ConsensusSigBackendRegistry + ?Sized,
{
    let message_signer = ValidatorId::new(proposal.header.proposer_index as u64);
    let preimage = proposal.signing_preimage_with_chain_id(chain_id);
    verify_core(
        claimed,
        message_signer,
        proposal.header.suite_id,
        &proposal.signature,
        validators,
        key_provider,
        backend_registry,
        &preimage,
        |backend, id, pk, msg, sig| backend.verify_proposal(id, pk, msg, sig),
    )
}

/// Verify a single received `Vote` fail-closed.
///
/// `claimed` is the Run 418 F6-authenticated consensus sender. The message's
/// `validator_index` must equal `claimed`, the signer must be a member of
/// `validators`, the signature must be present, the wire `suite_id` must
/// match the governed suite, the suite must have a registered/allowed backend,
/// and the signature must verify over
/// [`Vote::signing_preimage_with_chain_id`].
pub fn verify_vote_msg<K, B>(
    vote: &Vote,
    claimed: ValidatorId,
    validators: &ConsensusValidatorSet,
    key_provider: &K,
    backend_registry: &B,
    chain_id: ChainId,
) -> Result<(), ProposalVoteVerifyError>
where
    K: SuiteAwareValidatorKeyProvider + ?Sized,
    B: ConsensusSigBackendRegistry + ?Sized,
{
    let message_signer = ValidatorId::new(vote.validator_index as u64);
    let preimage = vote.signing_preimage_with_chain_id(chain_id);
    verify_core(
        claimed,
        message_signer,
        vote.suite_id,
        &vote.signature,
        validators,
        key_provider,
        backend_registry,
        &preimage,
        |backend, id, pk, msg, sig| backend.verify_vote(id, pk, msg, sig),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::SUITE_PQ_RESERVED_1;
    use qbind_types::QBIND_DEVNET_CHAIN_ID;
    use qbind_wire::consensus::{BlockHeader, Vote};

    use crate::crypto_verifier::SimpleBackendRegistry;
    use crate::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};

    const TEST_SUITE: ConsensusSigSuiteId = SUITE_PQ_RESERVED_1; // 100 = ML-DSA-44
    const TEST_SUITE_U16: u16 = 100;

    #[derive(Debug, Clone)]
    struct TestKeyProvider {
        keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
    }
    impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
        fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
            self.keys.get(&id).cloned()
        }
    }

    struct Fixture {
        validators: ConsensusValidatorSet,
        kp: TestKeyProvider,
        br: SimpleBackendRegistry,
        sks: HashMap<ValidatorId, Vec<u8>>,
    }

    fn make_fixture(n: u64) -> Fixture {
        let mut keys = HashMap::new();
        let mut sks = HashMap::new();
        for i in 0..n {
            let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
            keys.insert(ValidatorId(i), (TEST_SUITE, pk));
            sks.insert(ValidatorId(i), sk);
        }
        let entries: Vec<ValidatorSetEntry> = (0..n)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        Fixture {
            validators: ConsensusValidatorSet::new(entries).expect("valid set"),
            kp: TestKeyProvider { keys },
            br: SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(MlDsa44Backend)),
            sks,
        }
    }

    fn base_header(proposer: u16) -> BlockHeader {
        BlockHeader {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 7,
            round: 7,
            parent_block_id: [1u8; 32],
            payload_hash: [2u8; 32],
            proposer_index: proposer,
            suite_id: TEST_SUITE_U16,
            tx_count: 0,
            timestamp: 0,
            payload_kind: 0,
            next_epoch: 0,
            batch_commitment: [0u8; 32],
        }
    }

    fn signed_proposal(f: &Fixture, proposer: u16) -> BlockProposal {
        let mut p = BlockProposal {
            header: base_header(proposer),
            qc: None,
            txs: vec![],
            signature: vec![],
        };
        let sk = f.sks.get(&ValidatorId(proposer as u64)).unwrap();
        let preimage = p.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
        p.signature = MlDsa44Backend::sign(sk, &preimage).expect("sign");
        p
    }

    fn signed_vote(f: &Fixture, voter: u16, block_id: [u8; 32]) -> Vote {
        let mut v = Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 7,
            round: 7,
            step: 0,
            block_id,
            validator_index: voter,
            suite_id: TEST_SUITE_U16,
            signature: vec![],
        };
        let sk = f.sks.get(&ValidatorId(voter as u64)).unwrap();
        let preimage = v.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
        v.signature = MlDsa44Backend::sign(sk, &preimage).expect("sign");
        v
    }

    fn vp(
        f: &Fixture,
        p: &BlockProposal,
        claimed: ValidatorId,
    ) -> Result<(), ProposalVoteVerifyError> {
        verify_proposal_msg(
            p,
            claimed,
            &f.validators,
            &f.kp,
            &f.br,
            QBIND_DEVNET_CHAIN_ID,
        )
    }
    fn vv(f: &Fixture, v: &Vote, claimed: ValidatorId) -> Result<(), ProposalVoteVerifyError> {
        verify_vote_msg(
            v,
            claimed,
            &f.validators,
            &f.kp,
            &f.br,
            QBIND_DEVNET_CHAIN_ID,
        )
    }

    // ---- positive controls ----
    #[test]
    fn proposal_valid_accepted() {
        let f = make_fixture(4);
        let p = signed_proposal(&f, 2);
        assert_eq!(vp(&f, &p, ValidatorId(2)), Ok(()));
    }

    #[test]
    fn vote_valid_accepted() {
        let f = make_fixture(4);
        let v = signed_vote(&f, 3, [9u8; 32]);
        assert_eq!(vv(&f, &v, ValidatorId(3)), Ok(()));
    }

    #[test]
    fn proposal_survives_encode_decode() {
        use qbind_wire::io::{WireDecode, WireEncode};
        let f = make_fixture(4);
        let p = signed_proposal(&f, 1);
        let mut buf = Vec::new();
        p.encode(&mut buf);
        let mut slice: &[u8] = &buf;
        let decoded = BlockProposal::decode(&mut slice).expect("decode");
        assert_eq!(vp(&f, &decoded, ValidatorId(1)), Ok(()));
    }

    // ---- signature failures ----
    #[test]
    fn proposal_missing_signature() {
        let f = make_fixture(4);
        let mut p = signed_proposal(&f, 1);
        p.signature.clear();
        assert_eq!(
            vp(&f, &p, ValidatorId(1)),
            Err(ProposalVoteVerifyError::MissingSignature(ValidatorId(1)))
        );
    }

    #[test]
    fn vote_missing_signature() {
        let f = make_fixture(4);
        let mut v = signed_vote(&f, 1, [3u8; 32]);
        v.signature.clear();
        assert_eq!(
            vv(&f, &v, ValidatorId(1)),
            Err(ProposalVoteVerifyError::MissingSignature(ValidatorId(1)))
        );
    }

    #[test]
    fn proposal_truncated_signature() {
        let f = make_fixture(4);
        let mut p = signed_proposal(&f, 1);
        p.signature.truncate(10);
        assert!(matches!(
            vp(&f, &p, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(_))
                | Err(ProposalVoteVerifyError::MalformedSignature(_))
        ));
    }

    #[test]
    fn proposal_bitflip_signature() {
        let f = make_fixture(4);
        let mut p = signed_proposal(&f, 1);
        p.signature[0] ^= 0xff;
        assert!(matches!(
            vp(&f, &p, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(_))
                | Err(ProposalVoteVerifyError::MalformedSignature(_))
        ));
    }

    #[test]
    fn proposal_changed_payload_after_signing() {
        let f = make_fixture(4);
        let mut p = signed_proposal(&f, 1);
        p.header.payload_hash = [7u8; 32];
        assert_eq!(
            vp(&f, &p, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(1)))
        );
    }

    #[test]
    fn vote_changed_block_after_signing() {
        let f = make_fixture(4);
        let mut v = signed_vote(&f, 1, [3u8; 32]);
        v.block_id = [4u8; 32];
        assert_eq!(
            vv(&f, &v, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(1)))
        );
    }

    #[test]
    fn vote_wrong_validator_signature() {
        // Vote claims to be from validator 1 but is signed by validator 2's key.
        let f = make_fixture(4);
        let mut v = signed_vote(&f, 1, [3u8; 32]);
        let sk2 = f.sks.get(&ValidatorId(2)).unwrap();
        let preimage = v.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
        v.signature = MlDsa44Backend::sign(sk2, &preimage).expect("sign");
        assert_eq!(
            vv(&f, &v, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(1)))
        );
    }

    #[test]
    fn proposal_signature_relabeled_as_vote_rejected() {
        // A signature over a Proposal preimage must not verify as a Vote.
        let f = make_fixture(4);
        let p = signed_proposal(&f, 1);
        let mut v = signed_vote(&f, 1, [3u8; 32]);
        v.signature = p.signature.clone();
        assert_eq!(
            vv(&f, &v, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(1)))
        );
    }

    #[test]
    fn vote_for_another_chain_rejected() {
        let f = make_fixture(4);
        let mut v = Vote {
            version: 1,
            chain_id: 1,
            epoch: 0,
            height: 7,
            round: 7,
            step: 0,
            block_id: [3u8; 32],
            validator_index: 1,
            suite_id: TEST_SUITE_U16,
            signature: vec![],
        };
        // Sign with a DIFFERENT chain scope than the verifier uses.
        let sk = f.sks.get(&ValidatorId(1)).unwrap();
        let other = v.signing_preimage_with_chain_id(qbind_types::QBIND_MAINNET_CHAIN_ID);
        v.signature = MlDsa44Backend::sign(sk, &other).expect("sign");
        // Verifier uses DevNet chain id → domain separation must reject.
        assert_eq!(
            vv(&f, &v, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(1)))
        );
    }

    // ---- suite failures ----
    #[test]
    fn proposal_suite_altered_after_signing() {
        let f = make_fixture(4);
        let mut p = signed_proposal(&f, 1);
        p.header.suite_id = 999; // not the governed suite
        assert!(matches!(
            vp(&f, &p, ValidatorId(1)),
            Err(ProposalVoteVerifyError::SuiteMismatch { .. })
        ));
    }

    #[test]
    fn vote_unsupported_suite_no_backend() {
        // Governance says validator uses suite 200, but no backend registered.
        let mut f = make_fixture(4);
        f.kp.keys.insert(
            ValidatorId(1),
            (ConsensusSigSuiteId::new(200), vec![0u8; 4]),
        );
        let mut v = signed_vote(&f, 1, [3u8; 32]);
        v.suite_id = 200;
        assert!(matches!(
            vv(&f, &v, ValidatorId(1)),
            Err(ProposalVoteVerifyError::UnsupportedSuite { .. })
        ));
    }

    #[test]
    fn no_classical_or_cross_suite_fallback() {
        // Signature length valid for another (unregistered) suite; selected
        // suite mismatch must fail closed with SuiteMismatch, never retry.
        let f = make_fixture(4);
        let mut p = signed_proposal(&f, 1);
        p.header.suite_id = 0; // SUITE_TOY_SHA3, not governed (governed=100)
        assert!(matches!(
            vp(&f, &p, ValidatorId(1)),
            Err(ProposalVoteVerifyError::SuiteMismatch { .. })
        ));
    }

    // ---- authority failures ----
    #[test]
    fn proposal_unknown_validator() {
        let f = make_fixture(4);
        let p = signed_proposal(&f, 1);
        // proposer index 9 not in a 4-validator set; claimed must match index.
        let mut p2 = p.clone();
        p2.header.proposer_index = 9;
        assert_eq!(
            vp(&f, &p2, ValidatorId(9)),
            Err(ProposalVoteVerifyError::UnknownValidator(ValidatorId(9)))
        );
    }

    #[test]
    fn vote_missing_key() {
        let mut f = make_fixture(4);
        f.kp.keys.remove(&ValidatorId(1));
        let v = signed_vote(&f, 1, [3u8; 32]);
        assert_eq!(
            vv(&f, &v, ValidatorId(1)),
            Err(ProposalVoteVerifyError::MissingKey(ValidatorId(1)))
        );
    }

    #[test]
    fn signer_mismatch_claimed_vs_message() {
        // Correct F6 sender binding but message index differs → fail closed.
        let f = make_fixture(4);
        let v = signed_vote(&f, 1, [3u8; 32]);
        assert_eq!(
            vv(&f, &v, ValidatorId(2)),
            Err(ProposalVoteVerifyError::SignerMismatch {
                claimed: ValidatorId(2),
                message: ValidatorId(1),
            })
        );
    }

    #[test]
    fn wrong_consensus_key_with_correct_binding_rejected() {
        // correct F6 sender binding (claimed==index==1) but signed by the
        // wrong consensus key (validator 3's key).
        let f = make_fixture(4);
        let mut p = signed_proposal(&f, 1);
        let sk3 = f.sks.get(&ValidatorId(3)).unwrap();
        let preimage = p.signing_preimage_with_chain_id(QBIND_DEVNET_CHAIN_ID);
        p.signature = MlDsa44Backend::sign(sk3, &preimage).expect("sign");
        assert_eq!(
            vp(&f, &p, ValidatorId(1)),
            Err(ProposalVoteVerifyError::InvalidSignature(ValidatorId(1)))
        );
    }

    #[test]
    fn empty_signature_never_panics_and_fails_closed() {
        let f = make_fixture(1);
        let p = BlockProposal {
            header: base_header(0),
            qc: None,
            txs: vec![],
            signature: vec![],
        };
        assert_eq!(
            vp(&f, &p, ValidatorId(0)),
            Err(ProposalVoteVerifyError::MissingSignature(ValidatorId(0)))
        );
    }
}
