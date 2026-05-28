//! Run 037: production-honest ML-DSA-44 `SignatureSuite` adapter.
//!
//! This module provides a thin adapter that exposes the existing
//! [`MlDsa44Backend`] (FIPS 204 / ML-DSA-44, also known as Dilithium2)
//! as a [`SignatureSuite`] for use by the network / KEMTLS layer.
//!
//! # Why this exists
//!
//! Pre-Run-037, the only `SignatureSuite` actually wired into the
//! `qbind-node` binary path was a test-grade `DummySig` whose `verify`
//! always returns `Ok(())`. That stub was acceptable for B12's
//! structural mutual-auth wiring on DevNet, but it cannot be used in
//! any production-honest mode because it accepts arbitrary bytes as a
//! valid signature.
//!
//! Run 037 introduces a real production-honest PQC root-key /
//! delegation-cert verification path. The signature primitive that
//! path uses is ML-DSA-44 — the exact same backend already used by
//! validator vote / proposal / timeout signing (see
//! `crates/qbind-crypto/src/ml_dsa44.rs`). This adapter intentionally
//! does NOT introduce a parallel crypto path; it forwards to
//! [`MlDsa44Backend::verify`].
//!
//! # Suite ID
//!
//! [`MlDsa44SignatureSuite`] carries a configurable `suite_id` so the
//! caller can use the same ML-DSA-44 verification primitive under
//! whatever transport-level signature suite ID it has registered. The
//! recommended canonical id is [`SUITE_PQ_RESERVED_1`] (`= 100`),
//! which is reserved for ML-DSA-44 in the consensus suite catalog.
//!
//! # Security
//!
//! - Verification is delegated to the `fips204` crate via
//!   [`MlDsa44Backend::verify`].
//! - No private key material flows through this adapter.
//! - No key bytes are logged.
//! - All errors are mapped to `CryptoError`; no sensitive information
//!   is leaked through the error type.

use crate::error::CryptoError;
use crate::ml_dsa44::MlDsa44Backend;
use crate::signature::SignatureSuite;
use qbind_types::Hash32;

/// Production-honest ML-DSA-44 `SignatureSuite` (Run 037).
///
/// Wraps the existing [`MlDsa44Backend`] and forwards `verify` calls
/// through to [`MlDsa44Backend::verify`]. The wrapped suite_id is
/// intentionally configurable so the same verification primitive can
/// be registered under different transport-level suite IDs without
/// duplicating the underlying crypto.
#[derive(Debug, Clone, Copy)]
pub struct MlDsa44SignatureSuite {
    suite_id: u8,
}

impl MlDsa44SignatureSuite {
    /// Construct a new ML-DSA-44 `SignatureSuite` adapter with the
    /// given `suite_id`.
    pub fn new(suite_id: u8) -> Self {
        Self { suite_id }
    }
}

impl SignatureSuite for MlDsa44SignatureSuite {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    fn public_key_len(&self) -> usize {
        crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE
    }

    fn signature_len(&self) -> usize {
        crate::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE
    }

    fn verify(&self, pk: &[u8], msg_digest: &Hash32, sig: &[u8]) -> Result<(), CryptoError> {
        // Delegate to the existing FIPS 204 verifier. `Hash32` is a
        // 32-byte canonical digest by construction, so we sign / verify
        // over the digest bytes directly. ML-DSA-44 internally hashes
        // the input again (HashML-DSA mode is not used here — we use
        // raw ML-DSA over the canonical digest, identical to the
        // existing consensus-vote signing path).
        MlDsa44Backend::verify(pk, msg_digest, sig).map_err(|_| CryptoError::InvalidSignature)
    }
}

/// Sign a 32-byte digest with an ML-DSA-44 secret key, producing a
/// signature byte vector compatible with [`MlDsa44SignatureSuite::verify`].
///
/// This helper exists so that the offline / dev cert-issuance helper
/// (`crates/qbind-node/examples/devnet_pqc_root_helper.rs`) can mint
/// real ML-DSA-signed `NetworkDelegationCert`s without re-implementing
/// any ML-DSA glue.
///
/// **Security**: The secret key MUST NEVER be logged. This function
/// does not log it.
pub fn ml_dsa_44_sign_digest(sk: &[u8], digest: &Hash32) -> Result<Vec<u8>, CryptoError> {
    MlDsa44Backend::sign(sk, digest).map_err(|_| CryptoError::InvalidSignature)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ml_dsa44::MlDsa44Backend;

    #[test]
    fn round_trip_via_signature_suite_trait() {
        // Generate a real ML-DSA-44 keypair.
        let (pk, sk) = MlDsa44Backend::generate_keypair().expect("keygen");
        // 32-byte canonical digest (e.g., what
        // network_delegation_cert_digest produces).
        let digest: Hash32 = [7u8; 32];

        // Sign with the helper, verify via the trait impl.
        let sig = ml_dsa_44_sign_digest(&sk, &digest).expect("sign");
        let suite = MlDsa44SignatureSuite::new(100);
        suite.verify(&pk, &digest, &sig).expect("verify ok");

        // Wrong digest → fail.
        let wrong: Hash32 = [8u8; 32];
        assert!(suite.verify(&pk, &wrong, &sig).is_err());

        // Tampered signature → fail.
        let mut bad_sig = sig.clone();
        bad_sig[0] ^= 0xFF;
        assert!(suite.verify(&pk, &digest, &bad_sig).is_err());

        // Wrong public key → fail.
        let (other_pk, _) = MlDsa44Backend::generate_keypair().expect("keygen2");
        assert!(suite.verify(&other_pk, &digest, &sig).is_err());

        // Malformed inputs → MalformedSignature path → CryptoError.
        assert!(suite.verify(&pk[..10], &digest, &sig).is_err());
        assert!(suite.verify(&pk, &digest, &sig[..10]).is_err());
    }

    #[test]
    fn suite_id_is_configurable() {
        assert_eq!(MlDsa44SignatureSuite::new(100).suite_id(), 100);
        assert_eq!(MlDsa44SignatureSuite::new(3).suite_id(), 3);
    }

    #[test]
    fn key_and_sig_lengths_match_backend() {
        let suite = MlDsa44SignatureSuite::new(100);
        assert_eq!(
            suite.public_key_len(),
            crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE
        );
        assert_eq!(
            suite.signature_len(),
            crate::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE
        );
    }
}
