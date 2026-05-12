//! Run 052 — focused integration tests for the live PQC leaf-cert
//! revocation enforcement at the qbind-net handshake boundary.
//!
//! These tests exercise the listener-side `parse_and_verify_client_cert`
//! and the dialer-side `handle_server_accept` cert-verification
//! regions through the existing public
//! `ServerHandshake::handle_client_init` /
//! `ClientHandshake::handle_server_accept` APIs, with a configured
//! `LeafCertRevocationList` on the handshake config. The tests
//! assert:
//!
//! - When the verified leaf cert's canonical fingerprint is on the
//!   active leaf-revocation list, the handshake fails closed with
//!   `NetError::ClientCertInvalid("cert revoked")`, the per-reason
//!   sink method `inc_rejected_revoked` is called exactly once, and
//!   `inc_accepted` is NOT called.
//! - When the verified leaf cert is NOT on the active list, the
//!   handshake proceeds and `inc_accepted` is called exactly once.
//! - When `leaf_cert_revocations = None` (default; the pre-Run-052
//!   verification surface), behaviour is bit-for-bit identical to
//!   Run 044 — proving the new field is a zero-cost no-op when not
//!   configured.
//! - The same enforcement applies on both sides (listener + dialer).
//!
//! These tests use the deterministic `DummyKem` / `AlwaysOkSig` /
//! `DummyAead` stack from Run 044 so they target the verification
//! seam itself; the real-PQC end-to-end path (ml-kem-768 + ml-dsa-44)
//! is exercised by `crates/qbind-node/tests/run_037_pqc_static_root_*`
//! and continues to pass unchanged.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    leaf_cert_fingerprint, CertVerifyMetricsSink, ClientHandshake, ClientHandshakeConfig,
    KemPrivateKey, LeafCertRevocationList, MutualAuthMode, NetError, ServerHandshake,
    ServerHandshakeConfig, TrustedClientRoots,
};
use qbind_wire::io::WireEncode;
use qbind_wire::net::{ClientInit, NetworkDelegationCert, ServerAccept, PROTOCOL_VERSION_2};

// ============================================================================
// Counting sink (mirrors Run 044, extended with `revoked`)
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
    revoked: AtomicU64,
}

impl CountingSink {
    fn snapshot(&self) -> (u64, u64, u64, u64, u64, u64, u64, u64) {
        (
            self.accepted.load(Ordering::Relaxed),
            self.unknown_root.load(Ordering::Relaxed),
            self.wrong_suite.load(Ordering::Relaxed),
            self.bad_signature.load(Ordering::Relaxed),
            self.validator_mismatch.load(Ordering::Relaxed),
            self.malformed.load(Ordering::Relaxed),
            self.expired.load(Ordering::Relaxed),
            self.revoked.load(Ordering::Relaxed),
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
    fn inc_rejected_revoked(&self) {
        self.revoked.fetch_add(1, Ordering::Relaxed);
    }
}

// ============================================================================
// Deterministic crypto primitives (same as Run 044 fixture)
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
    fn verify(
        &self,
        _pk: &[u8],
        _msg_digest: &[u8; 32],
        _sig: &[u8],
    ) -> Result<(), CryptoError> {
        Ok(())
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

fn provider_ok_sig() -> Arc<StaticCryptoProvider> {
    Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem { suite_id: KEM_SUITE }))
            .with_aead_suite(Arc::new(DummyAead {
                suite_id: AEAD_SUITE,
            }))
            .with_signature_suite(Arc::new(AlwaysOkSig { suite_id: SIG_SUITE })),
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

fn server_cfg(
    provider: Arc<StaticCryptoProvider>,
    validator_id: [u8; 32],
    trusted: Option<TrustedClientRoots>,
    sink: Option<Arc<dyn CertVerifyMetricsSink>>,
    revocations: Option<LeafCertRevocationList>,
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
        leaf_cert_revocations: revocations,
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
    server.handle_client_init(crypto.as_ref(), &init).map(|_| ())
}

// ============================================================================
// Listener-side enforcement
// ============================================================================

#[test]
fn listener_revoked_leaf_fails_closed_and_bumps_revoked_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let client_cert = make_cert(validator_id, [9u8; 32], SIG_SUITE);
    let client_cert_bytes = encode_cert(&client_cert);
    let revoked_fp = leaf_cert_fingerprint(&client_cert);

    // Configure a revocation list that contains exactly this cert's
    // canonical fingerprint.
    let revoked_fp_for_closure = revoked_fp;
    let rev_list = LeafCertRevocationList::new(1, move |fp: &[u8; 32]| *fp == revoked_fp_for_closure);
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
        Some(rev_list),
    );
    let init = client_init_with_cert(validator_id, client_cert_bytes);

    let result = run_listener(cfg, init, provider);
    match result {
        Err(NetError::ClientCertInvalid("cert revoked")) => {}
        other => panic!("expected ClientCertInvalid(\"cert revoked\"), got {:?}", other),
    }

    let (accepted, ur, ws, bs, vm, m, e, revoked) = sink.snapshot();
    assert_eq!(accepted, 0, "accepted MUST NOT increment on revoked");
    assert_eq!(revoked, 1, "revoked MUST increment exactly once");
    assert_eq!((ur, ws, bs, vm, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn listener_non_revoked_leaf_proceeds_and_bumps_accepted_once() {
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let client_cert = make_cert(validator_id, [9u8; 32], SIG_SUITE);
    let client_cert_bytes = encode_cert(&client_cert);

    // Configure a revocation list that contains an UNRELATED fingerprint.
    let unrelated_fp = [0u8; 32];
    let rev_list = LeafCertRevocationList::new(1, move |fp: &[u8; 32]| *fp == unrelated_fp);
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
        Some(rev_list),
    );
    let init = client_init_with_cert(validator_id, client_cert_bytes);

    let result = run_listener(cfg, init, provider);
    assert!(
        result.is_ok(),
        "non-revoked client cert must verify: {:?}",
        result
    );

    let (accepted, ur, ws, bs, vm, m, e, revoked) = sink.snapshot();
    assert_eq!(accepted, 1, "accepted MUST increment exactly once");
    assert_eq!(revoked, 0, "revoked MUST stay 0 for a non-revoked leaf");
    assert_eq!((ur, ws, bs, vm, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn listener_no_revocation_list_preserves_run_044_behavior() {
    // Regression guard: `leaf_cert_revocations: None` is the
    // zero-cost no-op path. The listener must accept exactly as it
    // did pre-Run-052 (no `revoked` increments, accepted=1).
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let client_cert = make_cert(validator_id, [9u8; 32], SIG_SUITE);
    let client_cert_bytes = encode_cert(&client_cert);

    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
        None, // <-- no revocation list configured
    );
    let init = client_init_with_cert(validator_id, client_cert_bytes);

    let result = run_listener(cfg, init, provider);
    assert!(result.is_ok(), "no-revocation-list path must accept");

    let (accepted, _, _, _, _, _, _, revoked) = sink.snapshot();
    assert_eq!(accepted, 1);
    assert_eq!(revoked, 0);
}

#[test]
fn listener_empty_revocation_list_accepts() {
    // An explicit but empty revocation list must NOT spuriously
    // reject any cert.
    let provider = provider_ok_sig();
    let validator_id = [b'v'; 32];
    let trusted = TrustedClientRoots::new(|_| Some(vec![0xAAu8; 32]));
    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let client_cert = make_cert(validator_id, [9u8; 32], SIG_SUITE);
    let client_cert_bytes = encode_cert(&client_cert);

    let rev_list = LeafCertRevocationList::empty();
    let cfg = server_cfg(
        provider.clone(),
        validator_id,
        Some(trusted),
        Some(dyn_sink),
        Some(rev_list),
    );
    let init = client_init_with_cert(validator_id, client_cert_bytes);

    let result = run_listener(cfg, init, provider);
    assert!(result.is_ok());

    let (accepted, _, _, _, _, _, _, revoked) = sink.snapshot();
    assert_eq!(accepted, 1);
    assert_eq!(revoked, 0);
}

// ============================================================================
// Dialer-side enforcement
// ============================================================================

fn build_server_accept_for_dialer(
    server_validator_id: [u8; 32],
    cert_bytes: Vec<u8>,
) -> ServerAccept {
    ServerAccept {
        version: PROTOCOL_VERSION_2,
        kem_suite_id: KEM_SUITE,
        aead_suite_id: AEAD_SUITE,
        server_random: [0u8; 32],
        validator_id: server_validator_id,
        client_random: [0u8; 32],
        delegation_cert: cert_bytes,
        flags: 0,
    }
}

fn dialer_cfg(
    provider: Arc<StaticCryptoProvider>,
    sink: Option<Arc<dyn CertVerifyMetricsSink>>,
    revocations: Option<LeafCertRevocationList>,
) -> ClientHandshakeConfig {
    ClientHandshakeConfig {
        kem_suite_id: KEM_SUITE,
        aead_suite_id: AEAD_SUITE,
        crypto: provider,
        peer_root_network_pk: vec![0u8; 32],
        kem_metrics: None,
        local_delegation_cert: None,
        cert_verify_metrics: sink,
        leaf_cert_revocations: revocations,
    }
}

#[test]
fn dialer_revoked_leaf_fails_closed_and_bumps_revoked_once() {
    let provider = provider_ok_sig();
    let server_validator_id = [b's'; 32];

    // Build the server cert that the dialer will receive.
    let server_cert = make_cert(server_validator_id, [9u8; 32], SIG_SUITE);
    let server_cert_bytes = encode_cert(&server_cert);
    let revoked_fp = leaf_cert_fingerprint(&server_cert);

    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let revoked_fp_for_closure = revoked_fp;
    let rev_list = LeafCertRevocationList::new(1, move |fp: &[u8; 32]| *fp == revoked_fp_for_closure);

    let cfg = dialer_cfg(provider.clone(), Some(dyn_sink), Some(rev_list));

    // Drive the dialer through start() + handle_server_accept()
    // to reach the cert-verification region.
    let mut client = ClientHandshake::new(cfg, [0u8; 32]);
    let client_init = client
        .start(server_validator_id, &[0u8; 32])
        .expect("client.start succeeds");
    let server_accept = build_server_accept_for_dialer(server_validator_id, server_cert_bytes);
    let result = client.handle_server_accept(provider.as_ref(), &client_init, &server_accept);
    match result {
        Err(NetError::ClientCertInvalid("cert revoked")) => {}
        other => panic!(
            "dialer expected ClientCertInvalid(\"cert revoked\"), got {:?}",
            other
        ),
    }

    let (accepted, ur, ws, bs, vm, m, e, revoked) = sink.snapshot();
    assert_eq!(accepted, 0);
    assert_eq!(revoked, 1);
    assert_eq!((ur, ws, bs, vm, m, e), (0, 0, 0, 0, 0, 0));
}

#[test]
fn dialer_non_revoked_leaf_proceeds_and_bumps_accepted_once() {
    let provider = provider_ok_sig();
    let server_validator_id = [b's'; 32];
    let server_cert = make_cert(server_validator_id, [9u8; 32], SIG_SUITE);
    let server_cert_bytes = encode_cert(&server_cert);

    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();
    let unrelated_fp = [0u8; 32];
    let rev_list = LeafCertRevocationList::new(1, move |fp: &[u8; 32]| *fp == unrelated_fp);

    let cfg = dialer_cfg(provider.clone(), Some(dyn_sink), Some(rev_list));
    let mut client = ClientHandshake::new(cfg, [0u8; 32]);
    let client_init = client
        .start(server_validator_id, &[0u8; 32])
        .expect("client.start succeeds");
    let server_accept = build_server_accept_for_dialer(server_validator_id, server_cert_bytes);
    let _ = client
        .handle_server_accept(provider.as_ref(), &client_init, &server_accept)
        .expect("non-revoked cert must verify");

    let (accepted, _, _, _, _, _, _, revoked) = sink.snapshot();
    assert_eq!(accepted, 1);
    assert_eq!(revoked, 0);
}

#[test]
fn dialer_no_revocation_list_preserves_run_044_behavior() {
    let provider = provider_ok_sig();
    let server_validator_id = [b's'; 32];
    let server_cert = make_cert(server_validator_id, [9u8; 32], SIG_SUITE);
    let server_cert_bytes = encode_cert(&server_cert);

    let sink = Arc::new(CountingSink::default());
    let dyn_sink: Arc<dyn CertVerifyMetricsSink> = sink.clone();

    let cfg = dialer_cfg(provider.clone(), Some(dyn_sink), None);
    let mut client = ClientHandshake::new(cfg, [0u8; 32]);
    let client_init = client
        .start(server_validator_id, &[0u8; 32])
        .expect("client.start succeeds");
    let server_accept = build_server_accept_for_dialer(server_validator_id, server_cert_bytes);
    let _ = client
        .handle_server_accept(provider.as_ref(), &client_init, &server_accept)
        .expect("no-revocation-list path must accept");

    let (accepted, _, _, _, _, _, _, revoked) = sink.snapshot();
    assert_eq!(accepted, 1);
    assert_eq!(revoked, 0);
}

// ============================================================================
// LeafCertRevocationList type-level checks
// ============================================================================

#[test]
fn leaf_revocation_list_is_clone_and_send_sync() {
    fn assert_send_sync<T: Send + Sync + Clone>() {}
    assert_send_sync::<LeafCertRevocationList>();
}

#[test]
fn leaf_revocation_list_active_count_is_observable() {
    let revoked_fp = [0xAAu8; 32];
    let revoked_fp_for_closure = revoked_fp;
    let rev = LeafCertRevocationList::new(7, move |fp: &[u8; 32]| {
        *fp == revoked_fp_for_closure
    });
    assert_eq!(rev.active_count(), 7);
    assert!(rev.is_revoked(&revoked_fp));
    assert!(!rev.is_revoked(&[0u8; 32]));
}