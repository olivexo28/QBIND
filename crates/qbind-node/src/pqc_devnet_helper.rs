//! Run 037: offline / DevNet helper to mint real ML-DSA-44-signed
//! `NetworkDelegationCert`s.
//!
//! This module is **dev / offline only**. It is not wired into runtime
//! cert auto-minting on production-required paths. Its purpose is to
//! produce real PQC-signed delegation certs so that:
//!
//! 1. the `pqc-static-root` mode of the binary path can be exercised
//!    with real ML-DSA-44 verification (no DummySig);
//! 2. negative tests can produce intentionally-corrupted certs and
//!    confirm the listener fails closed;
//! 3. operators can bootstrap a DevNet root + per-node leaf certs from
//!    a single command without ad-hoc scripts.
//!
//! The helper:
//! - never logs any secret key bytes;
//! - does not write cert keys with broader-than-owner permissions;
//! - never auto-rotates or auto-trusts; the operator must explicitly
//!   move the produced files into `--p2p-trusted-root` /
//!   `--p2p-leaf-cert*` config.
//!
//! Production CA / OCSP / CRL / rotation flow remains out of scope and
//! is tracked under C4 in `docs/whitepaper/contradiction.md`.

use qbind_crypto::{
    ml_dsa_44_sign_digest, MlDsa44Backend, KEM_SUITE_ML_KEM_768, ML_KEM_768_PUBLIC_KEY_SIZE,
};
use qbind_hash::net::network_delegation_cert_digest;
use qbind_wire::io::WireEncode;
use qbind_wire::net::NetworkDelegationCert;

use crate::pqc_root_config::PQC_TRANSPORT_SUITE_ML_DSA_44;

/// Minted DevNet root keypair. The private key is held in memory only.
/// **Caller is responsible for not logging `root_sk`.**
#[derive(Debug)]
pub struct DevNetRoot {
    /// Stable identifier, derived deterministically from the root pk
    /// so two callers with the same pk agree on the id.
    pub root_key_id: [u8; 32],
    pub root_pk: Vec<u8>,
    pub root_sk: Vec<u8>,
}

/// Mint a fresh DevNet root keypair using real ML-DSA-44.
///
/// `root_key_id` is the SHA3-256 of `root_pk`, which gives the operator
/// a stable, log-safe identifier without coupling to any specific KMS
/// shape.
///
/// **DevNet-ephemeral**: regenerated on every call. Operators who want
/// a stable DevNet root must persist the returned bytes themselves.
pub fn mint_devnet_root() -> Result<DevNetRoot, String> {
    let (pk, sk) = MlDsa44Backend::generate_keypair()
        .map_err(|e| format!("ML-DSA-44 keygen failed: {:?}", e))?;
    let root_key_id = derive_root_key_id(&pk);
    Ok(DevNetRoot {
        root_key_id,
        root_pk: pk,
        root_sk: sk,
    })
}

/// Stable id = SHA3-256(root_pk).
pub fn derive_root_key_id(root_pk: &[u8]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"QBIND:pqc-root-id:v1");
    h.update(root_pk);
    let digest = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Inputs for minting a leaf delegation cert.
#[derive(Debug, Clone)]
pub struct LeafCertSpec {
    /// 32-byte validator id field embedded in the cert.
    pub validator_id: [u8; 32],
    /// Stable id of the issuing root (must match a configured
    /// `--p2p-trusted-root` entry on every verifier).
    pub root_key_id: [u8; 32],
    /// KEM suite the leaf KEM keypair belongs to.
    pub leaf_kem_suite_id: u8,
    /// Raw leaf KEM public key bytes (the KEMTLS leaf identity).
    pub leaf_kem_pk: Vec<u8>,
    /// Validity window (Unix seconds). `not_before <= not_after`
    /// required.
    pub not_before: u64,
    pub not_after: u64,
    /// Free extension bytes (chain id binding, etc.). Empty in the
    /// minimal DevNet shape.
    pub ext_bytes: Vec<u8>,
}

impl LeafCertSpec {
    /// Run 045: build a `LeafCertSpec` that is currently valid under any
    /// realistic wall-clock — `not_before=0, not_after=u64::MAX`. This
    /// is the default helper / example shape used across DevNet and the
    /// vast majority of existing tests.
    pub fn currently_valid(
        validator_id: [u8; 32],
        root_key_id: [u8; 32],
        leaf_kem_pk: Vec<u8>,
    ) -> Self {
        Self {
            validator_id,
            root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk,
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: Vec::new(),
        }
    }

    /// Run 045: build a `LeafCertSpec` that is guaranteed-expired under
    /// any realistic wall-clock (`not_after = 1` second after the Unix
    /// epoch). Intended for negative tests / negative smoke evidence
    /// only — fail-closed verification is the property under test.
    pub fn expired_for_test(
        validator_id: [u8; 32],
        root_key_id: [u8; 32],
        leaf_kem_pk: Vec<u8>,
    ) -> Self {
        Self {
            validator_id,
            root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk,
            not_before: 0,
            not_after: 1,
            ext_bytes: Vec::new(),
        }
    }

    /// Run 045: build a `LeafCertSpec` that is guaranteed-not-yet-valid
    /// under any realistic wall-clock
    /// (`not_before = u64::MAX - 1`). Intended for negative tests /
    /// negative smoke evidence only.
    pub fn not_yet_valid_for_test(
        validator_id: [u8; 32],
        root_key_id: [u8; 32],
        leaf_kem_pk: Vec<u8>,
    ) -> Self {
        Self {
            validator_id,
            root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk,
            not_before: u64::MAX - 1,
            not_after: u64::MAX,
            ext_bytes: Vec::new(),
        }
    }
}

/// Errors returned by the cert-issuance helper.
#[derive(Debug)]
pub enum DevNetCertError {
    InvalidValidityWindow,
    UnsupportedSuite(u8),
    MalformedKemPublicKey { expected: usize, actual: usize },
    SigningFailed(String),
}

impl std::fmt::Display for DevNetCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidValidityWindow => f.write_str("not_before > not_after"),
            Self::UnsupportedSuite(s) => write!(f, "unsupported PQC suite: {}", s),
            Self::MalformedKemPublicKey { expected, actual } => write!(
                f,
                "malformed ML-KEM-768 public key: expected {} bytes, got {}",
                expected, actual
            ),
            Self::SigningFailed(s) => write!(f, "ML-DSA-44 signing failed: {}", s),
        }
    }
}

impl std::error::Error for DevNetCertError {}

/// Mint a real ML-DSA-44-signed `NetworkDelegationCert`.
///
/// The returned cert satisfies:
/// `verify_delegation_cert(crypto_with_ml_dsa_44_suite, cert, root_pk).is_ok()`.
pub fn issue_leaf_delegation_cert(
    spec: &LeafCertSpec,
    root_sk: &[u8],
) -> Result<NetworkDelegationCert, DevNetCertError> {
    if spec.not_before > spec.not_after {
        return Err(DevNetCertError::InvalidValidityWindow);
    }
    if spec.leaf_kem_suite_id != KEM_SUITE_ML_KEM_768 {
        return Err(DevNetCertError::UnsupportedSuite(spec.leaf_kem_suite_id));
    }
    if spec.leaf_kem_pk.len() != ML_KEM_768_PUBLIC_KEY_SIZE {
        return Err(DevNetCertError::MalformedKemPublicKey {
            expected: ML_KEM_768_PUBLIC_KEY_SIZE,
            actual: spec.leaf_kem_pk.len(),
        });
    }

    let mut cert = NetworkDelegationCert {
        version: 1,
        validator_id: spec.validator_id,
        root_key_id: spec.root_key_id,
        leaf_kem_suite_id: spec.leaf_kem_suite_id,
        leaf_kem_pk: spec.leaf_kem_pk.clone(),
        not_before: spec.not_before,
        not_after: spec.not_after,
        ext_bytes: spec.ext_bytes.clone(),
        sig_suite_id: PQC_TRANSPORT_SUITE_ML_DSA_44,
        // Filled in below.
        sig_bytes: Vec::new(),
    };

    let digest = network_delegation_cert_digest(&cert);
    let sig = ml_dsa_44_sign_digest(root_sk, &digest)
        .map_err(|e| DevNetCertError::SigningFailed(format!("{:?}", e)))?;
    cert.sig_bytes = sig;

    Ok(cert)
}

/// Encode a cert to the wire bytes a `--p2p-leaf-cert` file is expected
/// to contain.
pub fn encode_cert(cert: &NetworkDelegationCert) -> Vec<u8> {
    let mut out = Vec::new();
    cert.encode(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::{MlDsa44SignatureSuite, MlKem768Backend, StaticCryptoProvider};
    use std::sync::Arc;

    fn mock_leaf_kem_pk() -> Vec<u8> {
        MlKem768Backend::generate_keypair()
            .expect("ml-kem keygen")
            .0
    }

    #[test]
    fn round_trip_real_pqc_cert() {
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [7u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: vec![],
        };
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        assert_eq!(cert.sig_suite_id, PQC_TRANSPORT_SUITE_ML_DSA_44);
        assert!(!cert.sig_bytes.is_empty());

        // Verify via the existing qbind_net::handshake::verify_delegation_cert
        // path that production code will use.
        let suite = MlDsa44SignatureSuite::new(PQC_TRANSPORT_SUITE_ML_DSA_44);
        let crypto: Arc<StaticCryptoProvider> =
            Arc::new(StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)));
        qbind_net::verify_delegation_cert(crypto.as_ref(), &cert, &root.root_pk)
            .expect("real PQC cert verifies");

        // Negative: tampered signature byte fails.
        let mut bad = cert.clone();
        bad.sig_bytes[0] ^= 0xFF;
        assert!(qbind_net::verify_delegation_cert(crypto.as_ref(), &bad, &root.root_pk).is_err());

        // Negative: tampered validator_id (digest input changed) fails.
        let mut bad2 = cert.clone();
        bad2.validator_id[0] ^= 0x01;
        assert!(qbind_net::verify_delegation_cert(crypto.as_ref(), &bad2, &root.root_pk).is_err());

        // Negative: wrong root pk fails.
        let other_root = mint_devnet_root().expect("root2");
        assert!(
            qbind_net::verify_delegation_cert(crypto.as_ref(), &cert, &other_root.root_pk).is_err()
        );
    }

    #[test]
    fn round_trip_via_wire_encode_decode() {
        use qbind_wire::io::WireDecode;

        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [9u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 100,
            not_after: 200,
            ext_bytes: b"chain=devnet".to_vec(),
        };
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        let bytes = encode_cert(&cert);

        // Decode and re-verify to confirm the wire format round-trips
        // without breaking the digest preimage.
        let mut slice: &[u8] = &bytes;
        let decoded = NetworkDelegationCert::decode(&mut slice).expect("decode");
        assert_eq!(decoded, cert);

        let suite = MlDsa44SignatureSuite::new(PQC_TRANSPORT_SUITE_ML_DSA_44);
        let crypto: Arc<StaticCryptoProvider> =
            Arc::new(StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)));
        // Run 045: use the explicit validation-time entry point so the
        // assertion is independent of wall-clock (this cert is
        // intentionally pinned to a fixed historical window for digest
        // round-trip purposes).
        qbind_net::verify_delegation_cert_at(crypto.as_ref(), &decoded, &root.root_pk, 150)
            .expect("decoded PQC cert verifies");
    }

    #[test]
    fn rejects_invalid_validity_window() {
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [0u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 200,
            not_after: 100,
            ext_bytes: vec![],
        };
        let err = issue_leaf_delegation_cert(&spec, &root.root_sk).unwrap_err();
        assert!(matches!(err, DevNetCertError::InvalidValidityWindow));
    }

    #[test]
    fn unknown_root_pk_rejected_by_verifier() {
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [1u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: vec![],
        };
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        // Verify with a different root's pk.
        let other = mint_devnet_root().expect("root2");
        let suite = MlDsa44SignatureSuite::new(PQC_TRANSPORT_SUITE_ML_DSA_44);
        let crypto: Arc<StaticCryptoProvider> =
            Arc::new(StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)));
        assert!(qbind_net::verify_delegation_cert(crypto.as_ref(), &cert, &other.root_pk).is_err());
    }

    #[test]
    fn devnet_helper_keeps_root_secret_flow_explicit() {
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [3u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: vec![],
        };
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        assert_eq!(cert.root_key_id, root.root_key_id);
        assert_eq!(cert.leaf_kem_suite_id, KEM_SUITE_ML_KEM_768);
    }

    // ========================================================================
    // Run 045 — validity-window helper tests
    // ========================================================================

    fn pqc_crypto_provider() -> Arc<StaticCryptoProvider> {
        Arc::new(
            StaticCryptoProvider::new()
                .with_signature_suite(Arc::new(MlDsa44SignatureSuite::new(
                    PQC_TRANSPORT_SUITE_ML_DSA_44,
                ))),
        )
    }

    #[test]
    fn helper_default_cert_is_currently_valid() {
        let root = mint_devnet_root().expect("root");
        let spec =
            LeafCertSpec::currently_valid([7u8; 32], root.root_key_id, mock_leaf_kem_pk());
        assert_eq!(spec.not_before, 0);
        assert_eq!(spec.not_after, u64::MAX);
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        // Wall-clock wrapper must accept.
        qbind_net::verify_delegation_cert(pqc_crypto_provider().as_ref(), &cert, &root.root_pk)
            .expect("currently-valid cert must verify");
    }

    #[test]
    fn helper_can_create_expired_cert_that_fails_closed() {
        let root = mint_devnet_root().expect("root");
        let spec =
            LeafCertSpec::expired_for_test([7u8; 32], root.root_key_id, mock_leaf_kem_pk());
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        // Real signature MUST still verify against the digest preimage
        // (validity fields are signature-covered).
        let provider = pqc_crypto_provider();
        // At an explicit validation time inside the window, it
        // succeeds (proves signature verifies).
        qbind_net::verify_delegation_cert_at(provider.as_ref(), &cert, &root.root_pk, 1)
            .expect("expired cert verifies at validation_time within window");
        // Under wall-clock, it must fail closed as expired.
        let err = qbind_net::verify_delegation_cert(provider.as_ref(), &cert, &root.root_pk)
            .unwrap_err();
        assert!(
            matches!(err, qbind_net::NetError::ClientCertInvalid("cert expired")),
            "got {:?}",
            err
        );
    }

    #[test]
    fn helper_can_create_not_yet_valid_cert_that_fails_closed() {
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec::not_yet_valid_for_test(
            [7u8; 32],
            root.root_key_id,
            mock_leaf_kem_pk(),
        );
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        let provider = pqc_crypto_provider();
        // Inside future window: passes.
        qbind_net::verify_delegation_cert_at(
            provider.as_ref(),
            &cert,
            &root.root_pk,
            u64::MAX,
        )
        .expect("not-yet-valid cert verifies at validation_time inside future window");
        // Wall-clock: fails closed.
        let err = qbind_net::verify_delegation_cert(provider.as_ref(), &cert, &root.root_pk)
            .unwrap_err();
        assert!(
            matches!(err, qbind_net::NetError::ClientCertInvalid("cert not yet valid")),
            "got {:?}",
            err
        );
    }

    #[test]
    fn helper_rejects_inverted_window_at_issuance() {
        // Inverted windows are explicitly rejected at issuance — the
        // helper does NOT mint such certs. This is the most defensive
        // contract: we never mint a cert that we know is unverifiable.
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [0u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 200,
            not_after: 100,
            ext_bytes: vec![],
        };
        let err = issue_leaf_delegation_cert(&spec, &root.root_sk).unwrap_err();
        assert!(matches!(err, DevNetCertError::InvalidValidityWindow));
    }

    #[test]
    fn helper_validity_fields_are_encoded_and_signature_covered() {
        use qbind_hash::net::network_delegation_cert_digest;

        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [11u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 1_000,
            not_after: 2_000,
            ext_bytes: vec![],
        };
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        assert_eq!(cert.not_before, 1_000);
        assert_eq!(cert.not_after, 2_000);

        // Wire-encoding round-trip preserves both fields.
        use qbind_wire::io::WireDecode;
        let mut slice: &[u8] = &encode_cert(&cert);
        let decoded = NetworkDelegationCert::decode(&mut slice).expect("decode");
        assert_eq!(decoded.not_before, 1_000);
        assert_eq!(decoded.not_after, 2_000);

        // Tampering not_before must change the digest preimage (proves
        // signature coverage).
        let mut tampered = cert.clone();
        tampered.not_before = 1_001;
        assert_ne!(
            network_delegation_cert_digest(&cert),
            network_delegation_cert_digest(&tampered),
            "not_before MUST be in digest preimage"
        );
        let mut tampered2 = cert.clone();
        tampered2.not_after = 1_999;
        assert_ne!(
            network_delegation_cert_digest(&cert),
            network_delegation_cert_digest(&tampered2),
            "not_after MUST be in digest preimage"
        );

        // The original cert verifies at validation_time inside [1000, 2000].
        let provider = pqc_crypto_provider();
        qbind_net::verify_delegation_cert_at(provider.as_ref(), &cert, &root.root_pk, 1_500)
            .expect("currently-valid window must verify");
        // The tampered (not_before=1001) cert fails signature verify
        // (because the real signature only covers the original digest).
        let err = qbind_net::verify_delegation_cert_at(
            provider.as_ref(),
            &tampered,
            &root.root_pk,
            1_500,
        )
        .unwrap_err();
        assert!(
            matches!(err, qbind_net::NetError::KeySchedule("signature verify error")),
            "got {:?}",
            err
        );
    }
}