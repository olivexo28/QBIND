//! Run 045 — focused tests for delegation-cert validity-window
//! enforcement in `qbind_net::handshake::verify_delegation_cert` /
//! `verify_delegation_cert_at` and its mapping onto the Run 044
//! `inc_rejected_expired` cert-verify metrics sink boundary.
//!
//! Semantics under test:
//! - Validity-window enforcement runs **after** signature verification,
//!   so tampered validity fields surface as bad-signature (existing
//!   contract) rather than as validity-window errors.
//! - Inclusive on both ends:
//!   `not_before <= validation_time <= not_after`.
//! - Inverted (`not_before > not_after`) → fail-closed
//!   `ClientCertInvalid("cert invalid validity window")`.
//! - `validation_time < not_before` → fail-closed
//!   `ClientCertInvalid("cert not yet valid")`.
//! - `validation_time > not_after` → fail-closed
//!   `ClientCertInvalid("cert expired")`.
//! - Live handshake boundary (listener + dialer) maps all three to
//!   `inc_rejected_expired` exactly once; no other per-reason counter
//!   moves; `inc_accepted` stays at zero.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    verify_delegation_cert, verify_delegation_cert_at, CertVerifyMetricsSink, ClientHandshake,
    ClientHandshakeConfig, KemPrivateKey, MutualAuthMode, NetError, ServerHandshake,
    ServerHandshakeConfig, TrustedClientRoots,
};
use qbind_wire::io::WireEncode;
use qbind_wire::net::{ClientInit, NetworkDelegationCert, ServerAccept, PROTOCOL_VERSION_2};

// ============================================================================
// Counting sink (mirrors run_044 shape)
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
// Dummy crypto primitives (deterministic; identical to run_044 shapes)
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

const KEM_SUITE: u8 = 1;
const AEAD_SUITE: u8 = 2;
const SIG_SUITE: u8 = 3;

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
    not_before: u64,
    not_after: u64,
) -> NetworkDelegationCert {
    NetworkDelegationCert {
        version: 1,
        validator_id,
        root_key_id,
        leaf_kem_suite_id: KEM_SUITE,
        leaf_kem_pk: (0..32u8).collect(),
        not_before,
        not_after,
        ext_bytes: Vec::new(),
        sig_suite_id: SIG_SUITE,
        sig_bytes: vec![0u8; 64],
    }
}

fn encode_cert(cert: &NetworkDelegationCert) -> Vec<u8> {
    let mut out = Vec::new();
    cert.encode(&mut out);
    out
}

// ============================================================================
// Direct verify_delegation_cert_at semantics
// ============================================================================

#[test]
fn currently_valid_cert_verifies_at_validation_time() {
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 100, 200);
    verify_delegation_cert_at(provider.as_ref(), &cert, &[0u8; 32], 150)
        .expect("validation_time 150 within [100,200] must verify");
}

#[test]
fn cert_expired_rejected_with_distinguishable_error() {
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 100, 200);
    let err = verify_delegation_cert_at(provider.as_ref(), &cert, &[0u8; 32], 201).unwrap_err();
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert expired")),
        "wrong error: {:?}",
        err
    );
}

#[test]
fn cert_not_yet_valid_rejected_with_distinguishable_error() {
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 100, 200);
    let err = verify_delegation_cert_at(provider.as_ref(), &cert, &[0u8; 32], 99).unwrap_err();
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert not yet valid")),
        "wrong error: {:?}",
        err
    );
}

#[test]
fn inverted_window_rejected_with_distinguishable_error() {
    let provider = provider_ok_sig();
    // not_before > not_after: documented as fail-closed.
    let cert = make_cert([1u8; 32], [9u8; 32], 200, 100);
    let err = verify_delegation_cert_at(provider.as_ref(), &cert, &[0u8; 32], 150).unwrap_err();
    assert!(
        matches!(
            err,
            NetError::ClientCertInvalid("cert invalid validity window")
        ),
        "wrong error: {:?}",
        err
    );
}

#[test]
fn boundary_at_not_before_is_inclusive() {
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 100, 200);
    verify_delegation_cert_at(provider.as_ref(), &cert, &[0u8; 32], 100)
        .expect("validation_time == not_before must verify (inclusive)");
}

#[test]
fn boundary_at_not_after_is_inclusive() {
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 100, 200);
    verify_delegation_cert_at(provider.as_ref(), &cert, &[0u8; 32], 200)
        .expect("validation_time == not_after must verify (inclusive)");
}

#[test]
fn signature_verify_runs_before_validity_check() {
    // If signature is bad (or tampered field), we must surface
    // signature-verify error rather than validity-window error — this
    // preserves the existing fail-mode contract for tampered certs.
    let provider = provider_fail_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 100, 200);
    let err = verify_delegation_cert_at(provider.as_ref(), &cert, &[0u8; 32], 150).unwrap_err();
    assert!(
        matches!(err, NetError::KeySchedule("signature verify error")),
        "expected signature-verify error first; got {:?}",
        err
    );

    // Same with an expired cert: signature error MUST surface first.
    let cert_expired = make_cert([1u8; 32], [9u8; 32], 1, 2);
    let err =
        verify_delegation_cert_at(provider.as_ref(), &cert_expired, &[0u8; 32], 1_000).unwrap_err();
    assert!(
        matches!(err, NetError::KeySchedule("signature verify error")),
        "tampered/bad-sig expired cert must surface as signature error first; got {:?}",
        err
    );
}

#[test]
fn validity_fields_are_signature_covered() {
    // The digest used by verify_delegation_cert is
    // qbind_hash::net::network_delegation_cert_digest, which already
    // includes not_before and not_after (qbind-hash::net). With a
    // real signature suite, any tampering of these fields after signing
    // would fail signature verification. AlwaysOkSig accepts any
    // signature, so to prove signature-coverage we just use the
    // real-cert helper in qbind-node tests; here we assert the
    // digest behaviour indirectly: changing not_before/not_after must
    // change the digest preimage and therefore the signature contract.
    use qbind_hash::net::network_delegation_cert_digest;
    let a = make_cert([1u8; 32], [9u8; 32], 100, 200);
    let mut b = a.clone();
    b.not_before = 101;
    assert_ne!(
        network_delegation_cert_digest(&a),
        network_delegation_cert_digest(&b),
        "not_before MUST be in digest preimage"
    );
    let mut c = a.clone();
    c.not_after = 201;
    assert_ne!(
        network_delegation_cert_digest(&a),
        network_delegation_cert_digest(&c),
        "not_after MUST be in digest preimage"
    );
}

#[test]
fn wall_clock_wrapper_accepts_eternally_valid_cert() {
    // The existing default helper / test fixtures use
    // not_before=0, not_after=u64::MAX. Confirm wall-clock wrapper
    // accepts.
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 0, u64::MAX);
    verify_delegation_cert(provider.as_ref(), &cert, &[0u8; 32])
        .expect("eternally-valid cert must verify under wall-clock");
}

#[test]
fn wall_clock_wrapper_rejects_clearly_expired_cert() {
    // not_after = 1 (epoch + 1s) — guaranteed-expired under any
    // realistic wall-clock since 1970.
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], 0, 1);
    let err = verify_delegation_cert(provider.as_ref(), &cert, &[0u8; 32]).unwrap_err();
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert expired")),
        "wrong error: {:?}",
        err
    );
}

#[test]
fn wall_clock_wrapper_rejects_clearly_not_yet_valid_cert() {
    // not_before = u64::MAX - 1 — guaranteed-future under any realistic
    // wall-clock.
    let provider = provider_ok_sig();
    let cert = make_cert([1u8; 32], [9u8; 32], u64::MAX - 1, u64::MAX);
    let err = verify_delegation_cert(provider.as_ref(), &cert, &[0u8; 32]).unwrap_err();
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert not yet valid")),
        "wrong error: {:?}",
        err
    );
}

// ============================================================================
// Listener-side metric mapping
// ============================================================================

fn server_cfg_for_validity(
    provider: Arc<StaticCryptoProvider>,
    validator_id: [u8; 32],
    sink: Option<Arc<dyn CertVerifyMetricsSink>>,
) -> ServerHandshakeConfig {
    let server_cert = make_cert(validator_id, [9u8; 32], 0, u64::MAX);
    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
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
        trusted_client_roots: Some(trusted),
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
fn listener_expired_cert_increments_expired_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg_for_validity(provider.clone(), validator_id, Some(dyn_sink));

    // Clearly-expired client cert under wall-clock.
    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], 0, 1));
    let init = client_init_with_cert(validator_id, client_cert);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert expired")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(e, 1, "expired must increment exactly once");
    assert_eq!(
        (accepted, ur, ws, bs, vm, m),
        (0, 0, 0, 0, 0, 0),
        "no other per-reason counter must move for validity failure"
    );
}

#[test]
fn listener_not_yet_valid_cert_increments_expired_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg_for_validity(provider.clone(), validator_id, Some(dyn_sink));

    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], u64::MAX - 1, u64::MAX));
    let init = client_init_with_cert(validator_id, client_cert);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert not yet valid")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(e, 1, "expired counter must increment exactly once");
    assert_eq!((accepted, ur, ws, bs, vm, m), (0, 0, 0, 0, 0, 0));
}

#[test]
fn listener_inverted_window_cert_increments_expired_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let cfg = server_cfg_for_validity(provider.clone(), validator_id, Some(dyn_sink));

    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], 200, 100));
    let init = client_init_with_cert(validator_id, client_cert);

    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(
        matches!(
            err,
            NetError::ClientCertInvalid("cert invalid validity window")
        ),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(e, 1, "expired counter must increment exactly once");
    assert_eq!((accepted, ur, ws, bs, vm, m), (0, 0, 0, 0, 0, 0));
}

#[test]
fn listener_no_sink_validity_failure_preserves_error_shape() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let cfg = server_cfg_for_validity(provider.clone(), validator_id, None);
    let client_cert = encode_cert(&make_cert(validator_id, [9u8; 32], 0, 1));
    let init = client_init_with_cert(validator_id, client_cert);
    let err = run_listener(cfg, init, provider).expect_err("must fail closed");
    assert!(matches!(err, NetError::ClientCertInvalid("cert expired")));
}

// ============================================================================
// Dialer-side metric mapping
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

fn run_dialer(
    provider: Arc<StaticCryptoProvider>,
    sink: Option<Arc<dyn CertVerifyMetricsSink>>,
    server_cert_bytes: Vec<u8>,
    expected_validator_id: [u8; 32],
) -> Result<(), NetError> {
    let cfg = dialer_cfg(provider.clone(), sink);
    let mut client = ClientHandshake::new(cfg, [2u8; 32]);
    let server_kem_pk: Vec<u8> = (0..32u8).collect();
    let init = client.start(expected_validator_id, &server_kem_pk)?;
    let accept = ServerAccept {
        version: PROTOCOL_VERSION_2,
        kem_suite_id: KEM_SUITE,
        aead_suite_id: AEAD_SUITE,
        server_random: [3u8; 32],
        validator_id: expected_validator_id,
        client_random: [2u8; 32],
        delegation_cert: server_cert_bytes,
        flags: 0,
    };
    client
        .handle_server_accept(provider.as_ref(), &init, &accept)
        .map(|_| ())
}

#[test]
fn dialer_expired_cert_increments_expired_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], 0, 1));
    let err = run_dialer(provider, Some(dyn_sink), server_cert, validator_id)
        .expect_err("must fail closed");
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert expired")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(e, 1);
    assert_eq!((accepted, ur, ws, bs, vm, m), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_not_yet_valid_cert_increments_expired_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], u64::MAX - 1, u64::MAX));
    let err = run_dialer(provider, Some(dyn_sink), server_cert, validator_id)
        .expect_err("must fail closed");
    assert!(
        matches!(err, NetError::ClientCertInvalid("cert not yet valid")),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(e, 1);
    assert_eq!((accepted, ur, ws, bs, vm, m), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_inverted_window_cert_increments_expired_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], 200, 100));
    let err = run_dialer(provider, Some(dyn_sink), server_cert, validator_id)
        .expect_err("must fail closed");
    assert!(
        matches!(
            err,
            NetError::ClientCertInvalid("cert invalid validity window")
        ),
        "wrong error variant: {:?}",
        err
    );

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(e, 1);
    assert_eq!((accepted, ur, ws, bs, vm, m), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_no_sink_validity_failure_preserves_error_shape() {
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], 0, 1));
    let err = run_dialer(provider, None, server_cert, validator_id).expect_err("must fail closed");
    assert!(matches!(err, NetError::ClientCertInvalid("cert expired")));
}

#[test]
fn dialer_valid_cert_still_increments_only_accepted() {
    // Regression: a currently-valid cert must NOT trigger expired and
    // MUST still bump accepted exactly once.
    let provider = provider_ok_sig();
    let validator_id = [b'p'; 32];
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let server_cert = encode_cert(&make_cert(validator_id, [9u8; 32], 0, u64::MAX));
    let result = run_dialer(provider, Some(dyn_sink), server_cert, validator_id);
    assert!(result.is_ok(), "valid cert should verify: {:?}", result);

    let (accepted, ur, ws, bs, vm, m, e) = sink.snapshot();
    assert_eq!(accepted, 1);
    assert_eq!((ur, ws, bs, vm, m, e), (0, 0, 0, 0, 0, 0));
}
