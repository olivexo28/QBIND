//! Cryptographic verification of `TimeoutMsg` and `TimeoutCertificate` (C4 / Run 028).
//!
//! This module provides the smallest honest binary-path-ready cryptographic
//! verification primitive for HotStuff timeout traffic. It does **not**
//! introduce a parallel crypto path: it reuses the existing
//! `SuiteAwareValidatorKeyProvider` (governance-backed key + suite source)
//! and `ConsensusSigBackendRegistry` (suite → backend dispatch) abstractions
//! that are already used to verify proposals and votes (see
//! `crypto_verifier.rs` and `verify_pool.rs`).
//!
//! # Scope
//!
//! - [`verify_timeout_msg`]: per-message verification (membership + suite +
//!   signature) against the active validator set, governance-configured
//!   suite/key, and the chain-ID-aware signing preimage emitted by
//!   [`crate::timeout::timeout_signing_bytes_with_chain_id`].
//! - [`verify_timeout_certificate_with_evidence`]: verification of a
//!   `TimeoutCertificate` together with the per-signer signed `TimeoutMsg`
//!   evidence collected at the engine boundary, returning the deterministic
//!   maximum `high_qc` carried by the certificate. This validates:
//!     - all evidence timeouts share the same `view` as the certificate's
//!       `timeout_view`;
//!     - signers are unique;
//!     - every signer is in the active validator set;
//!     - every individual `TimeoutMsg` signature verifies against the
//!       governed suite/key for its signer;
//!     - accumulated voting power is ≥ `2f+1`;
//!     - the maximum `high_qc.view` derivation is deterministic and
//!       matches the certificate.
//!
//! # Out of scope (explicitly NOT closed in this pass)
//!
//! - Inbound binary-loop wiring of [`verify_timeout_msg`] /
//!   [`verify_timeout_certificate_with_evidence`] into
//!   `binary_consensus_loop.rs` `ConsensusNetMsg::Timeout` /
//!   `ConsensusNetMsg::NewView` handlers.
//! - Outbound-signing wiring of locally-generated `TimeoutMsg` through
//!   `ValidatorSigner` / remote signer.
//! - Carrying per-signer signed-timeout evidence on the wire inside
//!   `TimeoutCertificate`. The current `TimeoutCertificate` only carries
//!   `signers: Vec<ValidatorId>`; an evidence-carrying wire field is the
//!   next pass and is documented in the Run 028 evidence file.
//!
//! See `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_028.md` for the partial
//! evidence summary and the explicit gap list.

use std::sync::Arc;

use qbind_crypto::consensus_sig::{ConsensusSigError, ConsensusSigVerifier};
use qbind_crypto::ConsensusSigSuiteId;
use qbind_types::ChainId;

use crate::crypto_verifier::ConsensusSigBackendRegistry;
use crate::ids::ValidatorId;
use crate::key_registry::SuiteAwareValidatorKeyProvider;
use crate::qc::QuorumCertificate;
use crate::timeout::{timeout_signing_bytes_with_chain_id, TimeoutMsg};
use crate::validator_set::ConsensusValidatorSet;

/// Errors produced by the timeout cryptographic verification primitives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimeoutVerifyError {
    /// The signer is not a member of the active validator set.
    UnknownValidator(ValidatorId),
    /// No public key is registered for the signer (governance gap).
    MissingKey(ValidatorId),
    /// No verifier backend is registered for the governance suite of the
    /// signer.
    UnsupportedSuite {
        /// The signer.
        validator_id: ValidatorId,
        /// The governance-configured suite for this signer.
        governance_suite: ConsensusSigSuiteId,
    },
    /// The wire `suite_id` carried in the `TimeoutMsg` does not match the
    /// governance-configured suite for the signer.
    SuiteMismatch {
        /// The signer.
        validator_id: ValidatorId,
        /// The suite_id carried on the wire (in the `TimeoutMsg`).
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
    /// A duplicate signer was found inside `TimeoutCertificate` evidence.
    DuplicateSigner(ValidatorId),
    /// The certificate-level evidence does not cover every signer named in
    /// `tc.signers`, or carries entries for non-signers.
    EvidenceMismatch,
    /// One of the evidence timeouts had a `view` that does not match the
    /// certificate's `timeout_view`.
    MixedView {
        /// The certificate's `timeout_view`.
        expected: u64,
        /// The evidence's `view`.
        actual: u64,
    },
    /// Accumulated voting power of the verified signers did not reach
    /// `2f+1`.
    InsufficientQuorum {
        /// Voting power that successfully verified.
        accumulated_vp: u64,
        /// Required (`2f+1`-equivalent) voting power.
        required_vp: u64,
    },
    /// The certificate's `high_qc` is not the deterministic maximum
    /// (by `view`) of the `high_qc`s carried by the verified evidence
    /// timeouts.
    HighQcMismatch,
}

impl std::fmt::Display for TimeoutVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TimeoutVerifyError::UnknownValidator(id) => {
                write!(f, "unknown validator: {:?}", id)
            }
            TimeoutVerifyError::MissingKey(id) => {
                write!(f, "missing key for validator: {:?}", id)
            }
            TimeoutVerifyError::UnsupportedSuite {
                validator_id,
                governance_suite,
            } => write!(
                f,
                "unsupported suite for validator {:?}: governance_suite={}",
                validator_id, governance_suite
            ),
            TimeoutVerifyError::SuiteMismatch {
                validator_id,
                wire_suite,
                governance_suite,
            } => write!(
                f,
                "suite mismatch for validator {:?}: wire={}, governance={}",
                validator_id, wire_suite, governance_suite
            ),
            TimeoutVerifyError::InvalidSignature(id) => {
                write!(f, "invalid signature from validator: {:?}", id)
            }
            TimeoutVerifyError::MalformedSignature(id) => {
                write!(f, "malformed signature from validator: {:?}", id)
            }
            TimeoutVerifyError::BackendError(id, msg) => {
                write!(f, "backend error for validator {:?}: {}", id, msg)
            }
            TimeoutVerifyError::DuplicateSigner(id) => {
                write!(f, "duplicate signer in TC evidence: {:?}", id)
            }
            TimeoutVerifyError::EvidenceMismatch => {
                write!(f, "TC evidence does not cover signer set")
            }
            TimeoutVerifyError::MixedView { expected, actual } => write!(
                f,
                "TC evidence view mismatch: expected={}, actual={}",
                expected, actual
            ),
            TimeoutVerifyError::InsufficientQuorum {
                accumulated_vp,
                required_vp,
            } => write!(
                f,
                "insufficient quorum: have {} VP, need {} VP",
                accumulated_vp, required_vp
            ),
            TimeoutVerifyError::HighQcMismatch => write!(
                f,
                "TC high_qc is not the deterministic max of evidence high_qcs"
            ),
        }
    }
}

impl std::error::Error for TimeoutVerifyError {}

/// Per-call outcome bucket for metrics callers (`Run 028` observability).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeoutVerifyOutcome {
    /// Signature, suite, and membership all verified.
    Ok,
    /// Signer is not a member of the active validator set.
    UnknownValidator,
    /// Wire suite does not match the governed suite.
    WrongSuite,
    /// Signature bytes did not verify (cryptographic failure).
    BadSignature,
    /// Other (missing key, malformed signature bytes, unsupported suite,
    /// backend error).
    Other,
}

impl From<&TimeoutVerifyError> for TimeoutVerifyOutcome {
    fn from(e: &TimeoutVerifyError) -> Self {
        match e {
            TimeoutVerifyError::UnknownValidator(_) => TimeoutVerifyOutcome::UnknownValidator,
            TimeoutVerifyError::SuiteMismatch { .. } => TimeoutVerifyOutcome::WrongSuite,
            TimeoutVerifyError::InvalidSignature(_) => TimeoutVerifyOutcome::BadSignature,
            _ => TimeoutVerifyOutcome::Other,
        }
    }
}

/// Verify a single `TimeoutMsg` against the active validator set and the
/// governance-configured suite/key for its signer.
///
/// This is the smallest honest verification primitive callers can use to
/// gate `engine.on_timeout_msg` ingestion fail-closed. It is intentionally
/// a free function (not a trait method) so the binary path can call it
/// directly without taking ownership of the timeout message.
///
/// Verification steps (in order, fail-closed at the first failure):
///
/// 1. Membership: `timeout.validator_id` ∈ `validators`.
/// 2. Governance lookup: `(governance_suite, pk_bytes)` =
///    `key_provider.get_suite_and_key(timeout.validator_id)`.
/// 3. Suite check: `timeout.suite_id` (wire) == `governance_suite`
///    (returns [`TimeoutVerifyError::SuiteMismatch`] otherwise).
/// 4. Backend lookup: `backend_registry.get_backend(governance_suite)`
///    (returns [`TimeoutVerifyError::UnsupportedSuite`] otherwise).
/// 5. Cryptographic verification of `timeout.signature` over
///    `timeout_signing_bytes_with_chain_id(chain_id, timeout.view,
///    timeout.high_qc.as_ref(), timeout.validator_id)` using the suite
///    backend's `verify_vote` entry (timeouts share the ML-DSA-44
///    semantics of votes: a single per-validator signature over the
///    canonical preimage; see `verify_pool.rs:347-360` and
///    `crypto_verifier.rs:1048-1052`).
///
/// # Type parameters
/// - `BlockIdT`: as in [`TimeoutMsg`]; must be `Clone + AsRef<[u8]>`.
pub fn verify_timeout_msg<BlockIdT, K, B>(
    timeout: &TimeoutMsg<BlockIdT>,
    validators: &ConsensusValidatorSet,
    key_provider: &K,
    backend_registry: &B,
    chain_id: ChainId,
) -> Result<(), TimeoutVerifyError>
where
    BlockIdT: Clone + AsRef<[u8]>,
    K: SuiteAwareValidatorKeyProvider + ?Sized,
    B: ConsensusSigBackendRegistry + ?Sized,
{
    // Step 1: Membership in active validator set.
    if !validators.contains(timeout.validator_id) {
        return Err(TimeoutVerifyError::UnknownValidator(timeout.validator_id));
    }

    // Step 2: Governance lookup of (suite, pk_bytes).
    let (governance_suite, pk_bytes) = match key_provider.get_suite_and_key(timeout.validator_id) {
        Some(result) => result,
        None => return Err(TimeoutVerifyError::MissingKey(timeout.validator_id)),
    };

    // Step 3: Suite ID match between wire and governance.
    let wire_suite = ConsensusSigSuiteId::new(timeout.suite_id as u16);
    if wire_suite != governance_suite {
        return Err(TimeoutVerifyError::SuiteMismatch {
            validator_id: timeout.validator_id,
            wire_suite,
            governance_suite,
        });
    }

    // Step 4: Backend dispatch via the suite registry.
    let backend: Arc<dyn ConsensusSigVerifier> =
        match backend_registry.get_backend(governance_suite) {
            Some(b) => b,
            None => {
                return Err(TimeoutVerifyError::UnsupportedSuite {
                    validator_id: timeout.validator_id,
                    governance_suite,
                });
            }
        };

    // Step 5: Cryptographic verification over the canonical preimage.
    let preimage = timeout_signing_bytes_with_chain_id(
        chain_id,
        timeout.view,
        timeout.high_qc.as_ref(),
        timeout.validator_id,
    );

    match backend.verify_vote(
        timeout.validator_id.as_u64(),
        &pk_bytes,
        &preimage,
        &timeout.signature,
    ) {
        Ok(()) => Ok(()),
        Err(ConsensusSigError::InvalidSignature) => {
            Err(TimeoutVerifyError::InvalidSignature(timeout.validator_id))
        }
        Err(ConsensusSigError::MalformedSignature) => {
            Err(TimeoutVerifyError::MalformedSignature(timeout.validator_id))
        }
        Err(ConsensusSigError::MissingKey(_)) => {
            Err(TimeoutVerifyError::MissingKey(timeout.validator_id))
        }
        Err(ConsensusSigError::Other(msg)) => {
            Err(TimeoutVerifyError::BackendError(timeout.validator_id, msg))
        }
    }
}

/// Verify a `TimeoutCertificate` together with the per-signer signed
/// `TimeoutMsg` evidence collected at the engine boundary.
///
/// Returns `Ok((accumulated_vp, max_high_qc))` on success, where
/// `max_high_qc` is the deterministic `high_qc` (by maximum `view`) carried
/// by the verified evidence and is the value the engine should treat as
/// the certificate's effective high_qc for safety locking.
///
/// This function is the smallest honest TC-level cryptographic gate.
/// It does **not** mutate any consensus state; it only inspects the
/// supplied certificate, evidence, validator set, and crypto primitives.
///
/// Verification steps (fail-closed at the first failure):
///
/// 1. `evidence` is non-empty and every entry's `validator_id` is in
///    `tc.signers`. The evidence set must be a permutation of `tc.signers`
///    (no extras, no missing). Duplicate signers are rejected.
/// 2. Every evidence timeout has `timeout.view == tc.timeout_view`.
/// 3. Each evidence timeout passes [`verify_timeout_msg`] (which itself
///    enforces membership + suite + signature + chain-ID).
/// 4. The accumulated voting power of the verified signers is
///    ≥ `validators.two_thirds_vp()`.
/// 5. The deterministic max-`high_qc` over the verified evidence (by
///    `qc.view`) matches `tc.high_qc` (`None == None` and `Some(qc) ==
///    Some(qc')` iff their `view` and `block_id` match).
///
/// # Note on wire compatibility
///
/// The current `TimeoutCertificate` wire shape only carries
/// `signers: Vec<ValidatorId>` (no per-signer signatures). This function
/// therefore takes the per-signer evidence as a *separate* parameter; the
/// binary-loop caller is responsible for collecting the `TimeoutMsg`s out
/// of the local `TimeoutAccumulator` (for locally-formed TCs) or out of
/// an inbound `NewView` payload that explicitly carries them. Adding an
/// evidence-bearing wire field to `TimeoutCertificate` is the next pass —
/// see the Run 028 evidence document for the explicit gap and the
/// fail-closed posture for inbound TCs that arrive without evidence.
pub fn verify_timeout_certificate_with_evidence<BlockIdT, K, B>(
    tc: &crate::timeout::TimeoutCertificate<BlockIdT>,
    evidence: &[TimeoutMsg<BlockIdT>],
    validators: &ConsensusValidatorSet,
    key_provider: &K,
    backend_registry: &B,
    chain_id: ChainId,
) -> Result<(u64, Option<QuorumCertificate<BlockIdT>>), TimeoutVerifyError>
where
    BlockIdT: Clone + Eq + AsRef<[u8]>,
    K: SuiteAwareValidatorKeyProvider + ?Sized,
    B: ConsensusSigBackendRegistry + ?Sized,
{
    use std::collections::HashSet;

    // Step 1a: Reject empty evidence outright.
    if evidence.is_empty() || tc.signers.is_empty() {
        return Err(TimeoutVerifyError::EvidenceMismatch);
    }

    // Step 1b: tc.signers must be unique.
    let mut tc_signers: HashSet<ValidatorId> = HashSet::with_capacity(tc.signers.len());
    for id in &tc.signers {
        if !tc_signers.insert(*id) {
            return Err(TimeoutVerifyError::DuplicateSigner(*id));
        }
    }

    // Step 1c: evidence's validator_ids must form the same set as tc.signers,
    // with no duplicates and no extras.
    let mut evidence_seen: HashSet<ValidatorId> = HashSet::with_capacity(evidence.len());
    for ev in evidence {
        if !evidence_seen.insert(ev.validator_id) {
            return Err(TimeoutVerifyError::DuplicateSigner(ev.validator_id));
        }
        if !tc_signers.contains(&ev.validator_id) {
            return Err(TimeoutVerifyError::EvidenceMismatch);
        }
    }
    if evidence_seen.len() != tc_signers.len() {
        return Err(TimeoutVerifyError::EvidenceMismatch);
    }

    // Step 2 + 3 + 4: per-signer view/signature/membership + accumulate VP.
    let mut acc_vp: u64 = 0;
    for ev in evidence {
        if ev.view != tc.timeout_view {
            return Err(TimeoutVerifyError::MixedView {
                expected: tc.timeout_view,
                actual: ev.view,
            });
        }
        verify_timeout_msg(ev, validators, key_provider, backend_registry, chain_id)?;
        let idx = validators
            .index_of(ev.validator_id)
            .ok_or(TimeoutVerifyError::UnknownValidator(ev.validator_id))?;
        let entry = validators
            .get(idx)
            .ok_or(TimeoutVerifyError::UnknownValidator(ev.validator_id))?;
        acc_vp = acc_vp.saturating_add(entry.voting_power);
    }
    let required = validators.two_thirds_vp();
    if acc_vp < required {
        return Err(TimeoutVerifyError::InsufficientQuorum {
            accumulated_vp: acc_vp,
            required_vp: required,
        });
    }

    // Step 5: deterministic max-high_qc over the verified evidence.
    let derived_max = crate::timeout::select_max_high_qc::<BlockIdT, _>(evidence.iter());

    if !high_qc_eq(derived_max.as_ref(), tc.high_qc.as_ref()) {
        return Err(TimeoutVerifyError::HighQcMismatch);
    }

    Ok((acc_vp, derived_max))
}

/// Compare two `Option<&QuorumCertificate>` for the bytewise-equal block_id
/// and view that determine `select_max_high_qc` equivalence.
///
/// We do NOT compare the QC's signer-bitmap fields here: that is the
/// existing `verify_quorum_certificate` boundary and is intentionally
/// untouched by this module (Run 028 scope is timeout traffic only).
fn high_qc_eq<B: AsRef<[u8]>>(
    a: Option<&QuorumCertificate<B>>,
    b: Option<&QuorumCertificate<B>>,
) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.view == y.view && x.block_id.as_ref() == y.block_id.as_ref(),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_verifier::SimpleBackendRegistry;
    use crate::timeout::{TimeoutCertificate, TimeoutMsg, TIMEOUT_SUITE_ID};
    use crate::validator_set::{ConsensusValidatorSet, ValidatorSetEntry};
    use qbind_crypto::ml_dsa44::MlDsa44Backend;
    use qbind_crypto::{ConsensusSigSuiteId, SUITE_PQ_RESERVED_1};
    use qbind_types::QBIND_DEVNET_CHAIN_ID;
    use std::collections::HashMap;

    /// Suite ID used in these tests (governance suite for ML-DSA-44).
    const TEST_SUITE: ConsensusSigSuiteId = SUITE_PQ_RESERVED_1; // u16 100

    /// In-memory governance-style key + suite source for tests.
    #[derive(Debug, Clone)]
    struct TestKeyProvider {
        keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)>,
    }

    impl SuiteAwareValidatorKeyProvider for TestKeyProvider {
        fn get_suite_and_key(&self, id: ValidatorId) -> Option<(ConsensusSigSuiteId, Vec<u8>)> {
            self.keys.get(&id).cloned()
        }
    }

    fn make_validator_set(num: u64) -> ConsensusValidatorSet {
        let entries: Vec<ValidatorSetEntry> = (1..=num)
            .map(|i| ValidatorSetEntry {
                id: ValidatorId(i),
                voting_power: 1,
            })
            .collect();
        ConsensusValidatorSet::new(entries).expect("valid set")
    }

    /// Build a fresh `(key_provider, backend_registry, signing_keys)` test
    /// fixture for `n` validators, all on `TEST_SUITE` (ML-DSA-44).
    fn make_fixture(
        n: u64,
    ) -> (
        TestKeyProvider,
        SimpleBackendRegistry,
        HashMap<ValidatorId, Vec<u8>>,
    ) {
        let mut keys: HashMap<ValidatorId, (ConsensusSigSuiteId, Vec<u8>)> = HashMap::new();
        let mut signing_keys: HashMap<ValidatorId, Vec<u8>> = HashMap::new();
        for i in 1..=n {
            let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
            keys.insert(ValidatorId(i), (TEST_SUITE, pk));
            signing_keys.insert(ValidatorId(i), sk);
        }
        let provider = TestKeyProvider { keys };
        let backend = SimpleBackendRegistry::with_backend(TEST_SUITE, Arc::new(MlDsa44Backend));
        (provider, backend, signing_keys)
    }

    /// Build a signed `TimeoutMsg` for the given signer.
    fn signed_timeout(
        view: u64,
        validator_id: ValidatorId,
        signing_keys: &HashMap<ValidatorId, Vec<u8>>,
    ) -> TimeoutMsg<[u8; 32]> {
        let mut t = TimeoutMsg::<[u8; 32]>::new(view, None, validator_id);
        let preimage = t.signing_bytes_with_chain_id(QBIND_DEVNET_CHAIN_ID);
        let sk = signing_keys.get(&validator_id).expect("sk");
        let sig = MlDsa44Backend::sign(sk, &preimage).expect("sign");
        t.set_signature(sig);
        t
    }

    // -----------------------------------------------------------------------
    // verify_timeout_msg: positive
    // -----------------------------------------------------------------------

    #[test]
    fn verify_valid_signed_timeout_is_accepted() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let t = signed_timeout(7, ValidatorId(1), &sks);

        let res = verify_timeout_msg(&t, &validators, &kp, &br, QBIND_DEVNET_CHAIN_ID);
        assert!(res.is_ok(), "got {:?}", res);
    }

    // -----------------------------------------------------------------------
    // verify_timeout_msg: negative paths
    // -----------------------------------------------------------------------

    #[test]
    fn verify_unsigned_timeout_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, _sks) = make_fixture(4);
        // Construct without signing.
        let t = TimeoutMsg::<[u8; 32]>::new(7, None, ValidatorId(1));
        assert!(t.signature.is_empty());

        let res = verify_timeout_msg(&t, &validators, &kp, &br, QBIND_DEVNET_CHAIN_ID);
        match res {
            Err(TimeoutVerifyError::InvalidSignature(_))
            | Err(TimeoutVerifyError::MalformedSignature(_)) => {}
            other => panic!("expected sig rejection, got {:?}", other),
        }
    }

    #[test]
    fn verify_bad_signature_timeout_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let mut t = signed_timeout(7, ValidatorId(1), &sks);
        // Flip a byte deep inside the signature, away from any length tag.
        let mid = t.signature.len() / 2;
        t.signature[mid] ^= 0xFF;

        let res = verify_timeout_msg(&t, &validators, &kp, &br, QBIND_DEVNET_CHAIN_ID);
        assert!(
            matches!(
                res,
                Err(TimeoutVerifyError::InvalidSignature(v)) if v == ValidatorId(1)
            ),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_wrong_suite_timeout_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let mut t = signed_timeout(7, ValidatorId(1), &sks);
        // Tamper with the wire suite_id only — signature was made under
        // TEST_SUITE / TIMEOUT_SUITE_ID; we set a different value to force
        // the suite-mismatch branch ahead of any cryptographic check.
        t.suite_id = TIMEOUT_SUITE_ID.wrapping_add(1);

        let res = verify_timeout_msg(&t, &validators, &kp, &br, QBIND_DEVNET_CHAIN_ID);
        assert!(
            matches!(res, Err(TimeoutVerifyError::SuiteMismatch { .. })),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_unknown_validator_timeout_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        // Build a timeout naming a validator outside the set (id=42).
        // We need to sign for it though — extend signing_keys + provider
        // for the test to isolate the membership check from the key check.
        let outside = ValidatorId(42);
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        let mut kp2 = kp.clone();
        kp2.keys.insert(outside, (TEST_SUITE, pk));
        let mut sks2 = sks.clone();
        sks2.insert(outside, sk);

        let t = signed_timeout(7, outside, &sks2);
        let res = verify_timeout_msg(&t, &validators, &kp2, &br, QBIND_DEVNET_CHAIN_ID);
        assert!(
            matches!(
                res,
                Err(TimeoutVerifyError::UnknownValidator(v)) if v == outside
            ),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_missing_governance_key_is_rejected_with_missing_key() {
        let validators = make_validator_set(4);
        let (mut kp, br, sks) = make_fixture(4);
        // Drop validator 1's governance key; signing key still exists.
        kp.keys.remove(&ValidatorId(1));
        let t = signed_timeout(7, ValidatorId(1), &sks);
        let res = verify_timeout_msg(&t, &validators, &kp, &br, QBIND_DEVNET_CHAIN_ID);
        assert!(
            matches!(
                res,
                Err(TimeoutVerifyError::MissingKey(v)) if v == ValidatorId(1)
            ),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_unsupported_governance_suite_is_rejected() {
        let validators = make_validator_set(4);
        let (mut kp, br, _sks) = make_fixture(4);
        // Reassign validator 1 to a suite for which no backend is registered.
        // Use a u8-fitting value because TimeoutMsg.suite_id is u8 on the wire.
        let unsupported = ConsensusSigSuiteId::new(0xCD);
        let pk = kp
            .keys
            .get(&ValidatorId(1))
            .map(|(_, k)| k.clone())
            .unwrap();
        kp.keys.insert(ValidatorId(1), (unsupported, pk));
        // Build a timeout with the wire suite_id matching the unsupported one
        // so we exercise the unsupported-suite branch (not suite-mismatch).
        let mut t = TimeoutMsg::<[u8; 32]>::new(7, None, ValidatorId(1));
        t.suite_id = unsupported.as_u16() as u8;
        t.signature = vec![0u8; 64]; // structural placeholder; will not verify

        let res = verify_timeout_msg(&t, &validators, &kp, &br, QBIND_DEVNET_CHAIN_ID);
        assert!(
            matches!(res, Err(TimeoutVerifyError::UnsupportedSuite { .. })),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_timeout_outcome_classifier_matches_errors() {
        assert_eq!(
            TimeoutVerifyOutcome::from(&TimeoutVerifyError::UnknownValidator(ValidatorId(1))),
            TimeoutVerifyOutcome::UnknownValidator
        );
        assert_eq!(
            TimeoutVerifyOutcome::from(&TimeoutVerifyError::SuiteMismatch {
                validator_id: ValidatorId(1),
                wire_suite: ConsensusSigSuiteId::new(1),
                governance_suite: ConsensusSigSuiteId::new(2),
            }),
            TimeoutVerifyOutcome::WrongSuite
        );
        assert_eq!(
            TimeoutVerifyOutcome::from(&TimeoutVerifyError::InvalidSignature(ValidatorId(1))),
            TimeoutVerifyOutcome::BadSignature
        );
        assert_eq!(
            TimeoutVerifyOutcome::from(&TimeoutVerifyError::MissingKey(ValidatorId(1))),
            TimeoutVerifyOutcome::Other
        );
    }

    // -----------------------------------------------------------------------
    // verify_timeout_certificate_with_evidence: positive
    // -----------------------------------------------------------------------

    #[test]
    fn verify_valid_2f_plus_1_tc_is_accepted() {
        let validators = make_validator_set(4); // f=1, 2f+1=3
        let (kp, br, sks) = make_fixture(4);
        let view = 11u64;
        let evidence: Vec<_> = (1..=3)
            .map(|i| signed_timeout(view, ValidatorId(i), &sks))
            .collect();
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, signers);

        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(res.is_ok(), "got {:?}", res);
        let (acc_vp, max_high) = res.unwrap();
        assert!(acc_vp >= validators.two_thirds_vp());
        assert!(max_high.is_none());
    }

    #[test]
    fn verify_tc_high_qc_is_deterministic_max_view() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let view = 20u64;
        // Evidence 1 carries a high_qc at view 5; evidence 2 at view 8;
        // evidence 3 at view 6. The deterministic max is view=8.
        let qc_a = QuorumCertificate::<[u8; 32]>::new([1u8; 32], 5, vec![ValidatorId(1)]);
        let qc_b = QuorumCertificate::<[u8; 32]>::new([2u8; 32], 8, vec![ValidatorId(2)]);
        let qc_c = QuorumCertificate::<[u8; 32]>::new([3u8; 32], 6, vec![ValidatorId(3)]);

        let mk = |v: ValidatorId, qc: QuorumCertificate<[u8; 32]>| {
            let mut t = TimeoutMsg::<[u8; 32]>::new(view, Some(qc), v);
            let preimage = t.signing_bytes_with_chain_id(QBIND_DEVNET_CHAIN_ID);
            let sk = sks.get(&v).unwrap();
            t.set_signature(MlDsa44Backend::sign(sk, &preimage).unwrap());
            t
        };

        let evidence = vec![
            mk(ValidatorId(1), qc_a),
            mk(ValidatorId(2), qc_b.clone()),
            mk(ValidatorId(3), qc_c),
        ];
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, Some(qc_b.clone()), signers);

        let (_, max_high) = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        )
        .expect("ok");
        let max_high = max_high.expect("some");
        assert_eq!(max_high.view, 8);
        assert_eq!(max_high.block_id, [2u8; 32]);
    }

    // -----------------------------------------------------------------------
    // verify_timeout_certificate_with_evidence: negative paths
    // -----------------------------------------------------------------------

    #[test]
    fn verify_insufficient_quorum_tc_is_rejected() {
        let validators = make_validator_set(4); // 2f+1 = 3
        let (kp, br, sks) = make_fixture(4);
        let view = 5u64;
        let evidence: Vec<_> = (1..=2)
            .map(|i| signed_timeout(view, ValidatorId(i), &sks))
            .collect();
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, signers);

        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::InsufficientQuorum { .. })),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_duplicate_signer_tc_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let view = 5u64;
        let t1 = signed_timeout(view, ValidatorId(1), &sks);
        let t2 = signed_timeout(view, ValidatorId(2), &sks);
        let evidence = vec![t1.clone(), t2, t1.clone()];
        let tc = TimeoutCertificate::<[u8; 32]>::new(
            view,
            None,
            vec![ValidatorId(1), ValidatorId(2), ValidatorId(1)],
        );
        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::DuplicateSigner(_))),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_mixed_view_tc_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let view = 9u64;
        let mut evidence: Vec<_> = (1..=3)
            .map(|i| signed_timeout(view, ValidatorId(i), &sks))
            .collect();
        // Re-sign one of them at a different view to force MixedView.
        evidence[2] = signed_timeout(view + 1, ValidatorId(3), &sks);
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, signers);
        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::MixedView { .. })),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_tc_with_one_bad_signature_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let view = 9u64;
        let mut evidence: Vec<_> = (1..=3)
            .map(|i| signed_timeout(view, ValidatorId(i), &sks))
            .collect();
        // Flip a byte in evidence[1].signature.
        let mid = evidence[1].signature.len() / 2;
        evidence[1].signature[mid] ^= 0xAA;
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, signers);
        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::InvalidSignature(_))),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_tc_with_wrong_suite_signer_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let view = 9u64;
        let mut evidence: Vec<_> = (1..=3)
            .map(|i| signed_timeout(view, ValidatorId(i), &sks))
            .collect();
        evidence[0].suite_id = TIMEOUT_SUITE_ID.wrapping_add(1);
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, signers);
        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::SuiteMismatch { .. })),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_tc_with_unknown_signer_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);

        // Add an outsider with a key + signing key
        let outside = ValidatorId(42);
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        let mut kp2 = kp.clone();
        kp2.keys.insert(outside, (TEST_SUITE, pk));
        let mut sks2 = sks.clone();
        sks2.insert(outside, sk);

        let view = 9u64;
        // 2 honest + 1 outsider so quorum *would* be reached if the outsider were valid.
        let mut evidence: Vec<_> = (1..=2)
            .map(|i| signed_timeout(view, ValidatorId(i), &sks2))
            .collect();
        evidence.push(signed_timeout(view, outside, &sks2));
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, signers);

        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp2,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::UnknownValidator(v)) if v == outside),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_tc_with_evidence_mismatch_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let view = 9u64;
        let evidence: Vec<_> = (1..=3)
            .map(|i| signed_timeout(view, ValidatorId(i), &sks))
            .collect();
        // tc.signers names a different signer set than the evidence.
        let tc = TimeoutCertificate::<[u8; 32]>::new(
            view,
            None,
            vec![ValidatorId(1), ValidatorId(2), ValidatorId(4)],
        );
        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::EvidenceMismatch)),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_tc_with_empty_evidence_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, _sks) = make_fixture(4);
        let view = 9u64;
        let evidence: Vec<TimeoutMsg<[u8; 32]>> = Vec::new();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, vec![ValidatorId(1)]);
        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::EvidenceMismatch)),
            "got {:?}",
            res
        );
    }

    #[test]
    fn verify_tc_high_qc_mismatch_is_rejected() {
        let validators = make_validator_set(4);
        let (kp, br, sks) = make_fixture(4);
        let view = 12u64;
        let qc = QuorumCertificate::<[u8; 32]>::new([7u8; 32], 9, vec![ValidatorId(1)]);
        let mk = |v: ValidatorId, q: Option<QuorumCertificate<[u8; 32]>>| {
            let mut t = TimeoutMsg::<[u8; 32]>::new(view, q, v);
            let preimage = t.signing_bytes_with_chain_id(QBIND_DEVNET_CHAIN_ID);
            let sk = sks.get(&v).unwrap();
            t.set_signature(MlDsa44Backend::sign(sk, &preimage).unwrap());
            t
        };
        // All evidence has high_qc=Some(qc); but TC carries None, which is
        // not the deterministic max.
        let evidence = vec![
            mk(ValidatorId(1), Some(qc.clone())),
            mk(ValidatorId(2), Some(qc.clone())),
            mk(ValidatorId(3), Some(qc.clone())),
        ];
        let signers: Vec<ValidatorId> = evidence.iter().map(|e| e.validator_id).collect();
        let tc = TimeoutCertificate::<[u8; 32]>::new(view, None, signers);

        let res = verify_timeout_certificate_with_evidence(
            &tc,
            &evidence,
            &validators,
            &kp,
            &br,
            QBIND_DEVNET_CHAIN_ID,
        );
        assert!(
            matches!(res, Err(TimeoutVerifyError::HighQcMismatch)),
            "got {:?}",
            res
        );
    }
}
