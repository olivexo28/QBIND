//! Run 044 — focused unit tests for the live PQC cert-verification
//! metric-increment wiring.
//!
//! These tests exercise the listener-side `parse_and_verify_client_cert`
//! and the dialer-side `handle_server_accept` cert-verification region
//! through the existing public `ServerHandshake::handle_client_init` /
//! `ClientHandshake::handle_server_accept` APIs, and assert exactly one
//! per-reason counter (and the aggregate `inc_accepted` boundary) moves
//! per cert verification event. The tests also assert the absence of a
//! sink does not change verification behaviour.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    CertVerifyMetricsSink, ClientHandshake, ClientHandshakeConfig, KemPrivateKey, MutualAuthMode,
    NetError, ServerHandshake, ServerHandshakeConfig, TrustedClientRoots,
};
use qbind_wire::io::WireEncode;
use qbind_wire::net::{ClientInit, NetworkDelegationCert, ServerAccept, PROTOCOL_VERSION_2};

// ============================================================================
// Counting sink used by every test in this file
// ============================================================================

#[derive(Default)]
struct CountingSink {
    accepted: AtomicU64,
    unknown_root: AtomicU64,
    wrong_suite: AtomicU64,
    bad_signature: AtomicU64,
    validator_mismatch: AtomicU64,
    malformed: AtomicU64,
    expired: AtomicU64,
}

impl CountingSink {
    fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.unknown_root.load(Ordering::Relaxed),
            self.wrong_suite.load(Ordering::Relaxed),
            self.bad_signature.load(Ordering::Relaxed),
            self.validator_mismatch.load(Ordering::Relaxed),
            self.malformed.load(Ordering::Relaxed),
            self.expired.load(Ordering::Relaxed),
        )
    }
}

impl CertVerifyMetricsSink for CountingSink {
    fn inc_accepted(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_rejected_unknown_root(&self) {
        self.unknown_root.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_rejected_wrong_suite(&self) {
        self.wrong_suite.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_rejected_bad_signature(&self) {
        self.bad_signature.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_rejected_validator_mismatch(&self) {
        self.validator_mismatch.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_rejected_malformed(&self) {
        self.malformed.fetch_add(1, Ordering::Relaxed);
    }
    fn inc_rejected_expired(&self) {
        self.expired.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Dummy crypto primitives (deterministic, byte-stable, mirror m8_mutual_auth)
// ============================================================================

struct DummyKem {
    suite_id: u8,
}
impl KemSuite for DummyKem {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }
    fn public_key_len(&self) -> usize {
        32
    }
    fn secret_key_len(&self) -> usize {
        32
    }
    fn ciphertext_len(&self) -> usize {
        48
    }
    fn shared_secret_len(&self) -> usize {
        32
    }
    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = vec![0u8; 48];
        for (i, b) in ct.iter_mut().enumerate() {
            *b = pk[i % pk.len()].wrapping_add(0x11);
        }
        let mut ss = vec![0u8; 32];
        for (i, b) in ss.iter_mut().enumerate() {
            *b = pk[i % pk.len()].wrapping_mul(3);
        }
        Ok((ct, ss))
    }
    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let mut ss = vec![0u8; 32];
        for (i, b) in ss.iter_mut().enumerate() {
            *b = ct[i % ct.len()].wrapping_sub(0x11).wrapping_mul(3);
        }
        Ok(ss)
    }
}

/// Signature suite that ALWAYS accepts.
struct AlwaysOkSig {
    suite_id: u8,
}
impl SignatureSuite for AlwaysOkSig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }
    fn public_key_len(&self) -> usize {
        32
    }
    fn signature_len(&self) -> usize {
        64
    }
    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

/// Signature suite that ALWAYS rejects.
struct AlwaysFailSig {
    suite_id: u8,
}
impl SignatureSuite for AlwaysFailSig {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }
    fn public_key_len(&self) -> usize {
        32
    }
    fn signature_len(&self) -> usize {
        64
    }
    fn verify(&self, _pk: &[u8], _msg_digest: &[u8; 32], _sig: &[u8]) -> Result<(), CryptoError> {
        Err(CryptoError::InvalidSignature)
    }
}

struct DummyAead {
    suite_id: u8,
}
impl AeadSuite for DummyAead {
    fn suite_id(&self) -> u8 {
        self.suite_id
    }
    fn key_len(&self) -> usize {
        32
    }
    fn nonce_len(&self) -> usize {
        12
    }
    fn tag_len(&self) -> usize {
        16
    }
    fn seal(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut out = plaintext.to_vec();
        out.extend(vec![0u8; self.tag_len()]);
        Ok(out)
    }
    fn open(
        &self,
        _key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let tag_len = self.tag_len();
        if ciphertext.len() < tag_len {
            return Err(CryptoError::InvalidCiphertext);
        }
        Ok(ciphertext[..ciphertext.len() - tag_len].to_vec())
    }
}

// ============================================================================
// Helpers
// ============================================================================

const KEM_SUITE: u8 = 1;
const AEAD_SUITE: u8 = 2;
const SIG_SUITE: u8 = 3;
/// A signature suite id that is intentionally NOT registered with the
/// provider — used to drive the "wrong suite" rejection boundary.
const UNREGISTERED_SIG_SUITE: u8 = 99;

fn provider_ok_sig() -> Arc<StaticCryptoProvider> {
    Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem {
                suite_id: KEM_SUITE,
            }))
            .with_aead_suite(Arc::new(DummyAead {
                suite_id: AEAD_SUITE,
            }))
            .with_signature_suite(Arc::new(AlwaysOkSig {
                suite_id: SIG_SUITE,
            })),
    )
}

fn provider_fail_sig() -> Arc<StaticCryptoProvider> {
    Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem {
                suite_id: KEM_SUITE,
            }))
            .with_aead_suite(Arc::new(DummyAead {
                suite_id: AEAD_SUITE,
            }))
            .with_signature_suite(Arc::new(AlwaysFailSig {
                suite_id: SIG_SUITE,
            })),
    )
}

fn make_cert(
    validator_id: [u8; 32],
    root_key_id: [u8; 32],
    sig_suite_id: u8,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id: KEM_SUITE,
        leaf_kem_pk: (0..32u8).collect(),
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: Vec::new(),
        sig_suite_id,
        sig_bytes: vec![0u8; 64],
    }
}

fn encode_cert(cert: &NetworkDelegationCert) -> Vec<u8> {
    let mut out = Vec::new();
    cert.encode(&mut out);
    out
}

/// Build a server-side handshake configured for `Required` mutual-auth
/// with the provided trusted-roots resolver, optional sink.
fn server_cfg(
    provider: Arc<StaticCryptoProvider>,
    validator_id: [u8; 32],
    trusted: Option<TrustedClientRoots>,
    sink: Option<Arc<dyn CertVerifyMetricsSink>>,
) -> ServerHandshakeConfig {
    let server_cert = make_cert(validator_id, [9u8; 32], SIG_SUITE);
    ServerHandshakeConfig {
        kem_suite_id: KEM_SUITE,
        aead_suite_id: AEAD_SUITE,
        crypto: provider,
        local_root_network_pk: vec![0u8; 32],
        local_delegation_cert: encode_cert(&server_cert),
        local_kem_sk: Arc::new(KemPrivateKey::new(vec![0u8; 32])),
        kem_metrics: None,
        cookie_config: None,
        local_validator_id: validator_id,
        mutual_auth_mode: MutualAuthMode::Required,
        trusted_client_roots: trusted,
        cert_verify_metrics: sink,
        leaf_cert_revocations: None,
    }
}

fn client_init_with_cert(validator_id: [u8; 32], client_cert_bytes: Vec<u8>) -> ClientInit {
    ClientInit {
        version: PROTOCOL_VERSION_2,
        kem_suite_id: KEM_SUITE,
        aead_suite_id: AEAD_SUITE,
        client_random: [0u8; 32],
        validator_id,
        kem_ct: vec![0u8; 48],
        cookie: Vec::new(),
        client_cert: client_cert_bytes,
    }
}

// ============================================================================
// Listener-side: parse_and_verify_client_cert
// ============================================================================

/// Drive the listener through `handle_client_init` so we exercise the
/// real `parse_and_verify_client_cert` boundary used by the live binary.
fn run_listener(
    cfg: ServerHandshakeConfig,
    init: ClientInit,
    crypto: Arc<StaticCryptoProvider>,
) -> Result<(), NetError> {
    let mut server = ServerHandshake::new(cfg, [1u8; 32]);
    server
        .handle_client_init(crypto.as_ref(), &init)
        .map(|_| ())
}

#[test]
fn listener_accepted_increments_accepted_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];

    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
    );

    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], SIG_SUITE));
    let init = client_init_with_cert(validator_id, client_cert);

    // The downstream KEM decapsulation will succeed for DummyKem.
    let result = run_listener(cfg, init, provider);
    assert!(
        result.is_ok(),
        "listener handshake should succeed: {:?}",
        result
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(accepted, 1, "accepted must increment exactly once");
    assert_eq!((ur, ws, bs, vm, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn listener_unknown_root_increments_unknown_root_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];

    // Resolver returns None for any root key.
    let trusted = TrustedClientRoots::new(|_| None);
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
    );

    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], SIG_SUITE));
    let init = client_init_with_cert(validator_id, client_cert);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(
        matches!(err, NetError::ClientCertInvalid("untrusted root")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(accepted, 0);
    assert_eq!(ur, 1, "unknown_root must increment exactly once");
    assert_eq!((ws, bs, vm, m, e), (0, 0, 0, 0, 0));
}

#[test]
fn listener_wrong_suite_increments_wrong_suite_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];

    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
    );

    // Cert claims an UNREGISTERED signature suite id → `signature_suite`
    // returns None → `verify_delegation_cert` yields `UnsupportedSuite`.
    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], UNREGISTERED_SIG_SUITE));
    let init = client_init_with_cert(validator_id, client_cert);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(
        matches!(err, NetError::UnsupportedSuite(UNREGISTERED_SIG_SUITE)),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(accepted, 0);
    assert_eq!(ws, 1, "wrong_suite must increment exactly once");
    assert_eq!((ur, bs, vm, m, e), (0, 0, 0, 0, 0));
}

#[test]
fn listener_bad_signature_increments_bad_signature_once() {
    // Use a provider whose signature suite ALWAYS returns Err to drive
    // the `KeySchedule("signature verify error")` branch.
    let provider = provider_fail_sig();
    let validator_id = [b'v'; 32];

    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
    );

    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], SIG_SUITE));
    let init = client_init_with_cert(validator_id, client_cert);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(
        matches!(err, NetError::KeySchedule("signature verify error")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(accepted, 0);
    assert_eq!(bs, 1, "bad_signature must increment exactly once");
    assert_eq!((ur, ws, vm, m, e), (0, 0, 0, 0, 0));
}

#[test]
fn listener_malformed_cert_increments_malformed_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];

    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
    );

    // Send completely malformed cert bytes that cannot decode.
    let init = client_init_with_cert(validator_id, vec![0xFFu8; 3]);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(
        matches!(err, NetError::ClientCertInvalid("parse error")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(accepted, 0);
    assert_eq!(m, 1, "malformed must increment exactly once");
    assert_eq!((ur, ws, bs, vm, e), (0, 0, 0, 0, 0));
}

#[test]
fn listener_no_sink_does_not_change_verification_result() {
    // Without a sink, the unknown_root failure path must still return
    // the same `NetError::ClientCertInvalid("untrusted root")`.
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];

    let trusted = TrustedClientRoots::new(|_| None);
    let cfg = server_cfg(provider.clone(), validator_id, Some(trusted), None);
    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], SIG_SUITE));
    let init = client_init_with_cert(validator_id, client_cert);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(matches!(err, NetError::ClientCertInvalid("untrusted root")));
}

// ============================================================================
// Dialer-side: handle_server_accept (cert-verification region)
// ============================================================================

fn dialer_cfg(
    provider: Arc<StaticCryptoProvider>,
    sink: Option<Arc<dyn CertVerifyMetricsSink>>,
) -> ClientHandshakeConfig {
    ClientHandshakeConfig {
        kem_suite_id: KEM_SUITE,
        aead_suite_id: AEAD_SUITE,
        crypto: provider,
        peer_root_network_pk: vec![0u8; 32],
        kem_metrics: None,
        local_delegation_cert: None,
        cert_verify_metrics: sink,
        leaf_cert_revocations: None,
    }
}

/// Drive the dialer through `start_handshake` + `handle_server_accept`
/// directly on a synthetic `ServerAccept` so the test can target the
/// cert-verification region without standing up a full server.
fn run_dialer_cert_verify(
    provider: Arc<StaticCryptoProvider>,
    sink: Option<Arc<dyn CertVerifyMetricsSink>>,
    server_cert_bytes: Vec<u8>,
    dialer_expected_validator_id: [u8; 32],
) -> Result<(), NetError> {
    let cfg = dialer_cfg(provider.clone(), sink);
    let mut client = ClientHandshake::new(cfg, [2u8; 32]);
    // Drive the dialer through `start` so KEM encapsulation + shared
    // secret are populated exactly as in production.
    let server_kem_pk: Vec<u8> = (0..32u8).collect();
    let init = client.start(dialer_expected_validator_id, &server_kem_pk)?;
    let accept = ServerAccept {
        version: PROTOCOL_VERSION_2,
        kem_suite_id: KEM_SUITE,
        aead_suite_id: AEAD_SUITE,
        server_random: [3u8; 32],
        validator_id: dialer_expected_validator_id,
        client_random: [2u8; 32],
        delegation_cert: server_cert_bytes,
        flags: 0,
    };
    client
        .handle_server_accept(provider.as_ref(), &init, &accept)
        .map(|_| ())
}

#[test]
fn dialer_accepted_increments_accepted_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], SIG_SUITE));

    let result = run_dialer_cert_verify(provider, Some(dyn_sink), server_cert, validator_id);
    assert!(
        result.is_ok(),
        "dialer cert-verify should succeed: {:?}",
        result
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(accepted, 1, "accepted must increment exactly once");
    assert_eq!((ur, ws, bs, vm, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_malformed_cert_increments_malformed_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    // Garbage server cert bytes.
    let err = run_dialer_cert_verify(provider, Some(dyn_sink), vec![0xFF; 3], validator_id)
        .expect_err("must fail closed");
    assert!(
        matches!(
            err,
            NetError::KeySchedule("failed to parse delegation cert")
        ),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!((accepted, ur, ws, bs, vm, e), (0, 0, 0, 0, 0, 0));
    assert_eq!(m, 1, "malformed must increment exactly once");
}

#[test]
fn dialer_wrong_suite_increments_wrong_suite_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], UNREGISTERED_SIG_SUITE));

    let err = run_dialer_cert_verify(provider, Some(dyn_sink), server_cert, validator_id)
        .expect_err("must fail closed");
    assert!(
        matches!(err, NetError::UnsupportedSuite(UNREGISTERED_SIG_SUITE)),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(ws, 1);
    assert_eq!((accepted, ur, bs, vm, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_bad_signature_increments_bad_signature_once() {
    let provider = provider_fail_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], SIG_SUITE));

    let err = run_dialer_cert_verify(provider, Some(dyn_sink), server_cert, validator_id)
        .expect_err("must fail closed");
    assert!(
        matches!(err, NetError::KeySchedule("signature verify error")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(bs, 1);
    assert_eq!((accepted, ur, ws, vm, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_validator_mismatch_increments_validator_mismatch_once() {
    let provider = provider_ok_sig();
    let cert_validator_id = [b'p'; 32];
    let expected_validator_id = [b'X'; 32]; // intentionally different
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let server_cert = encode_cert(&make_cert(cert_validator_id, [9u8; 32], SIG_SUITE));

    let err = run_dialer_cert_verify(provider, Some(dyn_sink), server_cert, expected_validator_id)
        .expect_err("must fail closed");
    assert!(
        matches!(err, NetError::KeySchedule("validator_id mismatch in cert")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(vm, 1);
    // Cert-signature path PASSED before the mismatch check fired —
    // accepted must still be zero at this boundary because the boundary
    // contract is "all checks at this boundary pass" before bumping it.
    assert_eq!((accepted, ur, ws, bs, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_no_sink_preserves_verification_behaviour() {
    let provider = provider_fail_sig();
    let validator_id = [b'p'; 32];
    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], SIG_SUITE));
    let err = run_dialer_cert_verify(provider, None, server_cert, validator_id)
        .expect_err("must fail closed");
    assert!(matches!(
        err,
        NetError::KeySchedule("signature verify error")
    ));
}

#[test]
fn expired_counter_documented_unused_at_live_boundary() {
    // Run 044 reason-mapping table: validity-window enforcement is not
    // yet implemented in `qbind_net::handshake::verify_delegation_cert`.
    // The counter must stay visible at zero on the live path. We assert
    // here that NO existing live failure boundary calls
    // `inc_rejected_expired`; if a future change wires it, this test
    // will continue to pass (it only documents the current contract via
    // assertion of zero), and the dedicated negative test for that
    // change can flip the assertion.
    let sink = Arc::new(CountingSink::default());

    // Run every other negative boundary above and check expired remains 0.
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];

    // Listener malformed
    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
    );
    let _ = run_listener(
        cfg,
        client_init_with_cert(validator_id, vec![0xFFu8; 3]),
        provider.clone(),
    );

    // Dialer validator_mismatch
    let dyn_sink2: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let server_cert = encode_cert(&make_cert([b'p'; 32], [9u8; 32], SIG_SUITE));
    let _ = run_dialer_cert_verify(provider, Some(dyn_sink2), server_cert, [b'X'; 32]);

    assert_eq!(sink.expired.load(Ordering::Relaxed), 0);
}
