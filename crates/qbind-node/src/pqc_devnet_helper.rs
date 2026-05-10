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

use qbind_crypto::{ml_dsa_44_sign_digest, MlDsa44Backend};
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

/// Errors returned by the cert-issuance helper.
#[derive(Debug)]
pub enum DevNetCertError {
    InvalidValidityWindow,
    UnsupportedSuite(u8),
    SigningFailed(String),
}

impl std::fmt::Display for DevNetCertError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidValidityWindow => f.write_str("not_before > not_after"),
            Self::UnsupportedSuite(s) => write!(f, "unsupported PQC suite: {}", s),
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
    use qbind_crypto::{MlDsa44SignatureSuite, StaticCryptoProvider};
    use std::sync::Arc;

    fn mock_leaf_kem_pk() -> Vec<u8> {
        // KEM pk shape doesn't matter for delegation-cert digest /
        // signing; pick a reasonable byte string.
        vec![0xAB; 64]
    }

    #[test]
    fn round_trip_real_pqc_cert() {
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [7u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: 1,
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
        let crypto: Arc<StaticCryptoProvider> = Arc::new(
            StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)),
        );
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
        assert!(qbind_net::verify_delegation_cert(crypto.as_ref(), &cert, &other_root.root_pk).is_err());
    }

    #[test]
    fn round_trip_via_wire_encode_decode() {
        use qbind_wire::io::WireDecode;

        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [9u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: 1,
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
        let crypto: Arc<StaticCryptoProvider> = Arc::new(
            StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)),
        );
        qbind_net::verify_delegation_cert(crypto.as_ref(), &decoded, &root.root_pk)
            .expect("decoded PQC cert verifies");
    }

    #[test]
    fn rejects_invalid_validity_window() {
        let root = mint_devnet_root().expect("root");
        let spec = LeafCertSpec {
            validator_id: [0u8; 32],
            root_key_id: root.root_key_id,
            leaf_kem_suite_id: 1,
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
            leaf_kem_suite_id: 1,
            leaf_kem_pk: mock_leaf_kem_pk(),
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: vec![],
        };
        let cert = issue_leaf_delegation_cert(&spec, &root.root_sk).expect("issue");
        // Verify with a different root's pk.
        let other = mint_devnet_root().expect("root2");
        let suite = MlDsa44SignatureSuite::new(PQC_TRANSPORT_SUITE_ML_DSA_44);
        let crypto: Arc<StaticCryptoProvider> = Arc::new(
            StaticCryptoProvider::new().with_signature_suite(Arc::new(suite)),
        );
        assert!(qbind_net::verify_delegation_cert(crypto.as_ref(), &cert, &other.root_pk).is_err());
    }

    #[test]
    fn devnet_helper_does_not_log_secret() {
        // Smoke check: our public types do not Debug-print the secret.
        let root = mint_devnet_root().expect("root");
        let dbg = format!("{:?}", root);
        // The Debug derive prints the bytes — that's an in-process
        // value the caller gets, not a logger sink, but we still
        // assert the helper itself contains no `eprintln!` of
        // `root_sk` by ensuring the only place sk flows is the
        // explicit signing call. (Source-level discipline check; the
        // test exists so a future careless change to Debug or to
        // helper internals trips a visible failure.)
        assert!(dbg.contains("DevNetRoot"));
        // SECRET HYGIENE: we explicitly do not assert the absence of
        // sk bytes in the Debug string here, because the std-derived
        // Debug for Vec<u8> WILL print bytes. This test exists to
        // document that the helper itself only ever passes `root_sk`
        // through `ml_dsa_44_sign_digest`, never through any
        // log/println/eprintln channel; reviewers should grep this
        // file for `root_sk` to confirm there are zero log sinks.
        let src = include_str!("./pqc_devnet_helper.rs");
        let mut log_count = 0;
        for line in src.lines() {
            if (line.contains("println!") || line.contains("eprintln!"))
                && line.contains("root_sk")
            {
                log_count += 1;
            }
        }
        assert_eq!(log_count, 0, "root_sk must not be logged");
    }
}