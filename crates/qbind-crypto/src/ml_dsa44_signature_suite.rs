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
use crate::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};
use qbind_types::Hash32;

/// Canonical ASCII algorithm identifier (`FIPS204-ML-DSA`, 14 bytes).
///
/// This identifies the algorithm family and is independent of suite IDs.
pub const ML_DSA_44_ALGORITHM_ID: &[u8; 14] = b"FIPS204-ML-DSA";

/// Canonical ASCII parameter identifier (`44`, 2 bytes).
///
/// This identifies the FIPS 204 ML-DSA-44 parameter set and is independent of
/// suite IDs.
pub const ML_DSA_44_PARAMETER_ID: &[u8; 2] = b"44";

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
        MlDsa44Backend::verify(pk, msg_digest, sig)
            .map_err(|_| CryptoError::InvalidSignature)
    }

    fn canonical_key_descriptor<'a>(
        &self,
        encoded_public_key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        use fips204::ml_dsa_44;
        use fips204::traits::SerDes;

        // The serialized input must be exactly the adapter's fixed 1312-byte
        // format. Parsing copies it into one fixed array, the pinned decoder
        // materializes its fixed-array PublicKey value, and re-encoding
        // materializes one fixed-size byte array. The returned descriptor
        // borrows the caller's original slice and retains none of those
        // temporaries. These are source-level object shapes, not bounds on
        // physical stack use, dependency internals, process memory, or time.
        if encoded_public_key.len() != crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(KeyDescriptorError::Malformed);
        }

        // fips204 0.4.6 decodes rho and four range-checked packed t1
        // polynomials. For ML-DSA-44, each coefficient is 10 bits and the
        // permitted range is 0..=1023, so every full-length bit pattern is in
        // range. Retain the re-encode comparison as the canonicality check
        // rather than claiming a separate noncanonical encoding exists for
        // this parameter set.
        let encoded_array: [u8; crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE] = encoded_public_key
            .try_into()
            .map_err(|_| KeyDescriptorError::Malformed)?;
        let decoded = ml_dsa_44::PublicKey::try_from_bytes(encoded_array)
            .map_err(|_| KeyDescriptorError::Malformed)?;
        if decoded.into_bytes().as_slice() != encoded_public_key {
            return Err(KeyDescriptorError::NonCanonical);
        }

        Ok(CanonicalKeyDescriptor {
            algorithm_id: ML_DSA_44_ALGORITHM_ID,
            parameter_id: ML_DSA_44_PARAMETER_ID,
            public_key_encoding: encoded_public_key,
        })
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
    use crate::signature::{CanonicalKeyDescriptor, KeyDescriptorError, SignatureSuite};

    struct UnsupportedDescriptorSuite;

    impl SignatureSuite for UnsupportedDescriptorSuite {
        fn suite_id(&self) -> u8 {
            1
        }

        fn public_key_len(&self) -> usize {
            0
        }

        fn signature_len(&self) -> usize {
            0
        }

        fn verify(&self, _pk: &[u8], _msg_digest: &Hash32, _sig: &[u8]) -> Result<(), CryptoError> {
            Err(CryptoError::InvalidSignature)
        }
    }

    #[test]
    fn run422_canonical_key_descriptor_exact_field_equality() {
        let key_a = [7u8, 8, 9];
        let key_b = [7u8, 8, 10];
        let same_key_other_buffer = [7u8, 8, 9];
        let base = CanonicalKeyDescriptor {
            algorithm_id: b"algorithm-a",
            parameter_id: b"parameter-a",
            public_key_encoding: &key_a,
        };
        let equal_contents = CanonicalKeyDescriptor {
            algorithm_id: b"algorithm-a",
            parameter_id: b"parameter-a",
            public_key_encoding: &same_key_other_buffer,
        };
        let other_algorithm = CanonicalKeyDescriptor {
            algorithm_id: b"algorithm-b",
            ..base
        };
        let other_parameters = CanonicalKeyDescriptor {
            parameter_id: b"parameter-b",
            ..base
        };
        let other_key = CanonicalKeyDescriptor {
            public_key_encoding: &key_b,
            ..base
        };

        assert_eq!(base, equal_contents, "equal bytes must compare by content");
        assert_ne!(base, other_algorithm, "algorithm is part of identity");
        assert_ne!(base, other_parameters, "parameters are part of identity");
        assert_ne!(base, other_key, "key encoding is part of identity");
        assert_eq!(base.algorithm_id, b"algorithm-a");
        assert_eq!(base.parameter_id, b"parameter-a");
        assert_eq!(base.public_key_encoding, &key_a);
    }

    #[test]
    fn run422_canonical_key_descriptor_defaults_to_unsupported_object_safely() {
        let suite: &dyn SignatureSuite = &UnsupportedDescriptorSuite;
        assert_eq!(
            suite.canonical_key_descriptor(&[1, 2, 3]),
            Err(KeyDescriptorError::Unsupported),
            "legacy implementations must fail closed for identity"
        );
    }

    #[test]
    fn run422_canonical_key_descriptor_borrows_fixed_canonical_encoding() {
        let suite = MlDsa44SignatureSuite::new(100);
        let zero_key = vec![0u8; crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE];
        let descriptor = suite
            .canonical_key_descriptor(&zero_key)
            .expect("full-length all-zero encoding is accepted by the pinned decoder");

        assert_eq!(descriptor.algorithm_id, b"FIPS204-ML-DSA");
        assert_eq!(descriptor.algorithm_id.len(), 14);
        assert_eq!(descriptor.parameter_id, b"44");
        assert_eq!(descriptor.parameter_id.len(), 2);
        assert_eq!(descriptor.public_key_encoding.len(), zero_key.len());
        assert!(
            core::ptr::eq(descriptor.public_key_encoding.as_ptr(), zero_key.as_ptr()),
            "descriptor must borrow the original key bytes"
        );
    }

    #[test]
    fn run422_canonical_key_descriptor_rejects_bad_lengths() {
        let suite = MlDsa44SignatureSuite::new(100);
        for key in [
            Vec::new(),
            vec![0u8; crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE - 1],
            vec![0u8; crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE + 1],
        ] {
            assert_eq!(
                suite.canonical_key_descriptor(&key),
                Err(KeyDescriptorError::Malformed),
                "incorrect public-key length must be rejected"
            );
        }
    }

    #[test]
    fn run422_canonical_key_descriptor_genuine_keys_and_suite_aliases() {
        let (first_pk, first_sk) = MlDsa44Backend::generate_keypair().expect("first keygen");
        let (second_pk, second_sk) = MlDsa44Backend::generate_keypair().expect("second keygen");
        let digest: Hash32 = [0x42; 32];
        let first_signature =
            ml_dsa_44_sign_digest(&first_sk, &digest).expect("first genuine signature");
        let second_signature =
            ml_dsa_44_sign_digest(&second_sk, &digest).expect("second genuine signature");
        let suite_100 = MlDsa44SignatureSuite::new(100);
        let suite_3 = MlDsa44SignatureSuite::new(3);

        let first_descriptor = suite_100
            .canonical_key_descriptor(&first_pk)
            .expect("first generated key is canonical");
        let alias_descriptor = suite_3
            .canonical_key_descriptor(&first_pk)
            .expect("same key is canonical under alias");
        let second_descriptor = suite_100
            .canonical_key_descriptor(&second_pk)
            .expect("second generated key is canonical");

        assert_eq!(
            first_descriptor, alias_descriptor,
            "suite aliases must have equal key descriptors"
        );
        assert_ne!(
            first_descriptor, second_descriptor,
            "distinct generated keys must have unequal descriptors"
        );
        assert_eq!(
            first_descriptor.public_key_encoding.len(),
            crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE
        );

        let alias: &dyn SignatureSuite = &suite_3;
        alias
            .verify(&first_pk, &digest, &first_signature)
            .expect("genuine signature verifies through suite alias");
        suite_100
            .verify(&second_pk, &digest, &second_signature)
            .expect("second genuine signature verifies");
        assert!(
            suite_100
                .verify(&second_pk, &digest, &first_signature)
                .is_err(),
            "wrong-key signature must fail"
        );
        assert!(
            suite_100
                .verify(&first_pk, &digest, &second_signature)
                .is_err(),
            "opposite wrong-key signature must fail"
        );
    }

    #[test]
    fn run422_canonical_key_descriptor_does_not_verify_or_authorize() {
        let (public_key, secret_key) = MlDsa44Backend::generate_keypair().expect("keygen");
        let digest: Hash32 = [0x24; 32];
        let signature = ml_dsa_44_sign_digest(&secret_key, &digest).expect("signature");
        let suite = MlDsa44SignatureSuite::new(100);
        suite
            .canonical_key_descriptor(&public_key)
            .expect("descriptor identifies encoding");

        let unrelated_key = vec![0u8; crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE];
        suite
            .canonical_key_descriptor(&unrelated_key)
            .expect("descriptor construction is not signature verification");
        assert!(
            suite.verify(&unrelated_key, &digest, &signature).is_err(),
            "a descriptor alone must not make a signature valid"
        );
    }

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
        assert_eq!(suite.public_key_len(), crate::ml_dsa44::ML_DSA_44_PUBLIC_KEY_SIZE);
        assert_eq!(suite.signature_len(), crate::ml_dsa44::ML_DSA_44_SIGNATURE_SIZE);
    }
}