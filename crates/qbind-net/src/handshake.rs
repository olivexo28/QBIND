//! KEMTLS-PDK handshake engine for validator / inter-node connections.
//!
//! This module provides the client-side and server-side state machines for
//! establishing AEAD sessions using post-quantum KEM-based key exchange.
//!
//! # Security Properties (T141)
//!
//! - KEM shared secrets are wrapped in `SharedSecret` with `ZeroizeOnDrop`.
//! - All derived session keys use `AeadKeyMaterial` with `ZeroizeOnDrop`.
//! - Server-side shared secrets are explicitly zeroized after key derivation.
//!
//! # DoS Cookie Protection (M6)
//!
//! The server-side handshake implements a 2-step handshake for DoS protection:
//! - Step A: ClientInit without valid cookie → server replies with ServerCookie challenge
//!   (no expensive KEM decapsulation or session allocation occurs)
//! - Step B: ClientInit with valid cookie → proceed with normal KEMTLS accept path
//!
//! This prevents connection exhaustion attacks by requiring clients to prove they
//! received a server challenge before any expensive cryptographic operations.
//!
//! # Mutual Authentication (M8)
//!
//! Protocol version 2 (0x02) adds mutual authentication with client certificate:
//! - ClientInit v2 includes client's `NetworkDelegationCert`
//! - Server verifies client cert AFTER cookie validation (DoS protection preserved)
//! - Server derives NodeId from verified client cert (cryptographic binding)
//! - Transcript hash includes BOTH server and client identity fields
//!
//! Configuration:
//! - `MutualAuthMode::Required`: Client cert required (TestNet/MainNet default)
//! - `MutualAuthMode::Optional`: Client cert verified if present but not required
//! - `MutualAuthMode::Disabled`: Server-auth only, v1 protocol (DevNet compatibility)

use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use qbind_crypto::CryptoProvider;
use qbind_hash::net::{derive_node_id_from_cert, network_delegation_cert_digest};
use qbind_wire::io::WireDecode;
use qbind_wire::net::{
    ClientInit, NetworkDelegationCert, ServerAccept, ServerCookie,
    PROTOCOL_VERSION_1, PROTOCOL_VERSION_2,
};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

use crate::cert_verify_metrics::CertVerifyMetricsSink;
use crate::cookie::{CookieConfig, CookieValidation, MAX_COOKIE_SIZE};
use crate::error::NetError;
use crate::kem_metrics::KemOpMetrics;
use crate::keys::{KemPrivateKey, SessionKeys, SharedSecret};
use crate::session::AeadSession;

/// Simplified connection state: either in handshake or established.
#[derive(Debug)]
pub enum ConnectionState<'a> {
    /// Handshake in progress; no AEAD session yet.
    Handshaking,
    /// Established AEAD session ready for transport.
    Established(AeadSession<'a>),
}

/// Identifies which side of the KEMTLS handshake we are on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeSide {
    Client,
    Server,
}

/// Mutual authentication mode for KEMTLS handshake (M8).
///
/// Controls whether the server requires, accepts, or ignores client certificates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MutualAuthMode {
    /// Client certificate is required (TestNet/MainNet default).
    ///
    /// - Server rejects ClientInit v1 (no client cert).
    /// - Server rejects ClientInit v2 without client_cert.
    /// - Server rejects ClientInit v2 with invalid client_cert.
    #[default]
    Required,

    /// Client certificate is verified if present but not required.
    ///
    /// - Server accepts ClientInit v1 (server-auth only).
    /// - Server verifies client_cert if present in ClientInit v2.
    /// - If client_cert is present and invalid, handshake fails.
    Optional,

    /// Mutual auth disabled; server-auth only (DevNet compatibility).
    ///
    /// - Server accepts ClientInit v1 and v2.
    /// - Server ignores client_cert even if present.
    /// - No client NodeId derivation from cert.
    Disabled,
}

/// Result of a completed handshake: AEAD session + peer identity info.
#[derive(Debug)]
pub struct HandshakeResult<'a> {
    /// The derived AEAD session (ready for use).
    pub session: AeadSession<'a>,
    /// Validator ID of the peer (from delegation cert).
    pub peer_validator_id: [u8; 32],
    /// KEM suite ID used for this session.
    pub kem_suite_id: u8,
    /// AEAD suite ID used for this session.
    pub aead_suite_id: u8,
    /// Client's NodeId derived from verified client certificate (M8 mutual auth).
    ///
    /// - Server side: Set to the cryptographically-bound NodeId if client cert was
    ///   verified successfully. None if server-auth only mode or no client cert.
    /// - Client side: Always None (client doesn't have its own NodeId from server).
    pub client_node_id: Option<[u8; 32]>,
    /// Whether mutual authentication was performed.
    ///
    /// True if client certificate was verified successfully.
    /// False for server-auth only mode.
    pub mutual_auth_complete: bool,
}

/// Verify a NetworkDelegationCert against a trusted root public key.
///
/// `root_pk` is the long-term ValidatorNetwork root key for the validator,
/// which must match the `root_key_id` semantics used in the cert.
///
/// This uses qbind-hash::net::network_delegation_cert_digest(cert) as the message
/// to be signed, and verifies using the suite indicated by `cert.sig_suite_id`.
///
/// # Run 045 — validity-window enforcement (transport freshness)
///
/// This convenience entry point enforces the cert's `not_before` / `not_after`
/// fields against the current wall-clock (Unix seconds). Wall-clock here is
/// strictly a **transport-layer operational freshness check** and is NOT a
/// consensus time source — consensus safety remains independent of wall-clock.
/// For deterministic tests, pass an explicit validation time via
/// [`verify_delegation_cert_at`].
///
/// On a malformed validity window (`not_before > not_after`), an expired cert
/// (`now > not_after`), or a not-yet-valid cert (`now < not_before`), this
/// returns [`NetError::ClientCertInvalid`] with a distinguishable static
/// string (`"cert expired"`, `"cert not yet valid"`,
/// `"cert invalid validity window"`).
pub fn verify_delegation_cert(
    crypto: &dyn CryptoProvider,
    cert: &NetworkDelegationCert,
    root_pk: &[u8],
) -> Result<(), NetError> {
    verify_delegation_cert_at(crypto, cert, root_pk, current_unix_secs())
}

/// Verify a NetworkDelegationCert against a trusted root public key at an
/// explicit validation time (Unix seconds).
///
/// See [`verify_delegation_cert`] for the wall-clock convenience wrapper.
///
/// # Validity-window semantics (Run 045)
///
/// Inclusive on both ends: a cert is valid iff
/// `not_before <= validation_time <= not_after`.
///
/// Fail-closed cases:
/// - `not_before > not_after` → [`NetError::ClientCertInvalid("cert invalid validity window")`]
/// - `validation_time > not_after` → [`NetError::ClientCertInvalid("cert expired")`]
/// - `validation_time < not_before` → [`NetError::ClientCertInvalid("cert not yet valid")`]
///
/// Signature verification still runs first, so a tampered validity field
/// (which is signature-covered via
/// [`qbind_hash::net::network_delegation_cert_digest`]) fails as
/// `NetError::KeySchedule("signature verify error")` rather than as a
/// validity-window error.
pub fn verify_delegation_cert_at(
    crypto: &dyn CryptoProvider,
    cert: &NetworkDelegationCert,
    root_pk: &[u8],
    validation_time_secs: u64,
) -> Result<(), NetError> {
    // 1) Resolve signature suite.
    let suite = crypto
        .signature_suite(cert.sig_suite_id)
        .ok_or(NetError::UnsupportedSuite(cert.sig_suite_id))?;

    // 2) Compute digest for the cert according to qbind-hash.
    //    Validity fields are part of the digest preimage (qbind-hash::net),
    //    so any tampered window fails signature verify below.
    let digest = network_delegation_cert_digest(cert);

    // 3) Verify signature.
    suite
        .verify(root_pk, &digest, &cert.sig_bytes)
        .map_err(|_| NetError::KeySchedule("signature verify error"))?;

    // 4) Run 045: enforce validity window AFTER signature verify so that
    //    tampered validity fields surface as bad-signature (the existing
    //    failure-mode contract) rather than as validity-window errors.
    if cert.not_before > cert.not_after {
        return Err(NetError::ClientCertInvalid("cert invalid validity window"));
    }
    if validation_time_secs < cert.not_before {
        return Err(NetError::ClientCertInvalid("cert not yet valid"));
    }
    if validation_time_secs > cert.not_after {
        return Err(NetError::ClientCertInvalid("cert expired"));
    }

    Ok(())
}

/// Current Unix time in seconds.
///
/// Wall-clock here is strictly used for transport-layer cert freshness
/// (Run 045) and is **not** a consensus time source. If the system clock is
/// before the Unix epoch (extremely unlikely; system misconfiguration),
/// returns 0, which forces honest certs with `not_before > 0` to be
/// classified as "not yet valid" rather than silently treated as valid.
fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Configuration inputs for a client-side handshake.
#[derive(Clone)]
pub struct ClientHandshakeConfig {
    /// KEM suite ID we want to use.
    pub kem_suite_id: u8,
    /// AEAD suite ID we want to use.
    pub aead_suite_id: u8,
    /// Crypto provider used to obtain KEM, AEAD, and signature suites.
    pub crypto: Arc<dyn CryptoProvider>,
    /// Root ValidatorNetwork public key for the peer we expect to talk to.
    pub peer_root_network_pk: Vec<u8>,
    /// Optional KEM operation metrics (for observability).
    pub kem_metrics: Option<Arc<KemOpMetrics>>,
    /// Client's delegation certificate for mutual auth (M8).
    ///
    /// If set, enables protocol version 2 with mutual authentication.
    /// The server will verify this certificate and derive a NodeId from it.
    /// If None, uses protocol version 1 (server-auth only).
    pub local_delegation_cert: Option<Vec<u8>>,
    /// Run 044: optional cert-verify metrics sink (observability-only).
    ///
    /// When set, the dialer-side server-cert verification path inside
    /// `ClientHandshake::handle_server_accept` invokes the sink at each
    /// existing success/failure boundary. `None` is a zero-cost no-op
    /// path that preserves pre-Run-044 verification behaviour
    /// bit-for-bit. Crate layering: defined in `qbind-net` to avoid
    /// `qbind-net → qbind-node` dependency.
    pub cert_verify_metrics: Option<Arc<dyn CertVerifyMetricsSink>>,
}

impl std::fmt::Debug for ClientHandshakeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshakeConfig")
            .field("kem_suite_id", &self.kem_suite_id)
            .field("aead_suite_id", &self.aead_suite_id)
            .field("peer_root_network_pk", &self.peer_root_network_pk)
            .field("local_delegation_cert", &self.local_delegation_cert.as_ref().map(|c| c.len()))
            .finish_non_exhaustive()
    }
}

/// Client-side KEMTLS handshake state.
///
/// # Security Properties (T141)
///
/// - The `shared_secret` field uses `SharedSecret` wrapper with `ZeroizeOnDrop`.
/// - When `ClientHandshake` is dropped (after handshake completion), the shared
///   secret is automatically zeroized.
pub struct ClientHandshake {
    cfg: ClientHandshakeConfig,
    /// Client-side ephemeral random data (randomness not modeled; caller passes).
    client_random: [u8; 32],
    /// Stored KEM encapsulated ciphertext produced in start().
    kem_ct: Option<Vec<u8>>,
    /// Stored KEM shared secret from encapsulation (zeroized on drop).
    shared_secret: Option<SharedSecret>,
}

impl std::fmt::Debug for ClientHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshake")
            .field("cfg", &self.cfg)
            .field("client_random", &self.client_random)
            .field("kem_ct", &self.kem_ct.as_ref().map(|v| v.len()))
            .field(
                "shared_secret",
                &self
                    .shared_secret
                    .as_ref()
                    .map(|s| format!("<redacted:{}>", s.len())),
            )
            .finish()
    }
}

impl ClientHandshake {
    /// Create a new client handshake with config and caller-provided client_random.
    pub fn new(cfg: ClientHandshakeConfig, client_random: [u8; 32]) -> Self {
        ClientHandshake {
            cfg,
            client_random,
            kem_ct: None,
            shared_secret: None,
        }
    }

    /// Build a ClientInit message for the peer validator_id.
    ///
    /// This:
    ///  - uses the configured KEM suite to encapsulate to `peer_kem_pk`,
    ///  - stores (kem_ct, shared_secret) locally,
    ///  - fills out ClientInit with suite IDs, client_random, validator_id, etc.
    ///  - includes client delegation cert if configured (M8 mutual auth, v2 protocol)
    pub fn start(
        &mut self,
        validator_id: [u8; 32],
        peer_kem_pk: &[u8],
    ) -> Result<ClientInit, NetError> {
        let kem = self
            .cfg
            .crypto
            .kem_suite(self.cfg.kem_suite_id)
            .ok_or(NetError::UnsupportedSuite(self.cfg.kem_suite_id))?;

        // Measure KEM encapsulation latency
        let start = Instant::now();
        let (ct, ss) = kem
            .encaps(peer_kem_pk)
            .map_err(|_| NetError::KeySchedule("kem encaps failed"))?;
        let duration = start.elapsed();

        // Record metrics (best-effort, never affects handshake behavior)
        if let Some(metrics) = &self.cfg.kem_metrics {
            metrics.record_encaps(duration);
        }

        self.kem_ct = Some(ct.clone());
        // Wrap shared secret in zeroizing container (T141)
        self.shared_secret = Some(SharedSecret::new(ss));

        // M8: Determine protocol version based on client cert availability
        let (version, client_cert) = if let Some(ref cert) = self.cfg.local_delegation_cert {
            (PROTOCOL_VERSION_2, cert.clone())
        } else {
            (PROTOCOL_VERSION_1, Vec::new())
        };

        // Build ClientInit. Adjust to actual fields in qbind-wire::net::ClientInit.
        Ok(ClientInit {
            version,
            kem_suite_id: self.cfg.kem_suite_id,
            aead_suite_id: self.cfg.aead_suite_id,
            client_random: self.client_random,
            validator_id,
            cookie: Vec::new(), // no cookie for T25; DoS cookies can be added in later tasks.
            kem_ct: ct,
            client_cert,
        })
    }

    /// Complete the client-side handshake after receiving ServerAccept.
    ///
    /// This:
    ///  - verifies the NetworkDelegationCert against peer_root_network_pk,
    ///  - computes a transcript hash over ClientInit + ServerAccept fields,
    ///  - derives SessionKeys and constructs an AeadSession.
    pub fn handle_server_accept<'a>(
        &mut self,
        crypto: &'a dyn CryptoProvider,
        client_init: &ClientInit,
        accept: &ServerAccept,
    ) -> Result<HandshakeResult<'a>, NetError> {
        // Run 044: observability-only — see `cert_verify_metrics.rs` for
        // the per-reason mapping table. Each branch below bumps exactly
        // one per-reason counter before propagating the existing
        // `NetError` variant; the success path bumps `inc_accepted`
        // exactly once after ALL checks pass. Verification result is
        // unchanged whether or not a sink is configured.
        let sink = self.cfg.cert_verify_metrics.as_ref();

        // 1) Parse and verify delegation cert from raw bytes.
        let mut cert_slice: &[u8] = &accept.delegation_cert;
        let delegation_cert = match NetworkDelegationCert::decode(&mut cert_slice) {
            Ok(c) => c,
            Err(_) => {
                if let Some(s) = sink {
                    s.inc_rejected_malformed();
                }
                return Err(NetError::KeySchedule("failed to parse delegation cert"));
            }
        };

        if let Err(e) = verify_delegation_cert(
            self.cfg.crypto.as_ref(),
            &delegation_cert,
            &self.cfg.peer_root_network_pk,
        ) {
            if let Some(s) = sink {
                match &e {
                    NetError::UnsupportedSuite(_) => s.inc_rejected_wrong_suite(),
                    // Run 045: validity-window failures surface as
                    // `ClientCertInvalid` with these three specific
                    // strings. Map them to `inc_rejected_expired` (the
                    // already-wired Run 044 boundary). Any other
                    // `ClientCertInvalid` would currently never occur
                    // from `verify_delegation_cert`; if it ever does,
                    // fall back to bad_signature rather than
                    // mis-classify as expired.
                    NetError::ClientCertInvalid(
                        "cert expired"
                        | "cert not yet valid"
                        | "cert invalid validity window",
                    ) => s.inc_rejected_expired(),
                    NetError::KeySchedule(_) => s.inc_rejected_bad_signature(),
                    _ => s.inc_rejected_bad_signature(),
                }
            }
            return Err(e);
        }

        // 2) Check that validator_id matches what we expected.
        if delegation_cert.validator_id != client_init.validator_id {
            if let Some(s) = sink {
                s.inc_rejected_validator_mismatch();
            }
            return Err(NetError::KeySchedule("validator_id mismatch in cert"));
        }

        // Run 044: all cert-verification checks at this boundary
        // succeeded. Bump accepted exactly once before any downstream
        // (non-cert-verification) handshake work begins.
        if let Some(s) = sink {
            s.inc_accepted();
        }

        // 3) Compute transcript hash (M8: includes client cert if present for mutual auth).
        // Format: "QBIND:KEMTLS" || client_random || server_random || kem_ct || client_cert
        let mut h = Sha3_256::new();
        h.update(b"QBIND:KEMTLS");
        h.update(client_init.client_random);
        h.update(accept.server_random);
        h.update(&client_init.kem_ct);
        // M8: Include client cert in transcript for mutual auth binding
        if client_init.version >= PROTOCOL_VERSION_2 && !client_init.client_cert.is_empty() {
            h.update(&client_init.client_cert);
        }
        let transcript_hash = h.finalize();

        // 4) Use shared_secret from encapsulation.
        let shared = self
            .shared_secret
            .as_ref()
            .ok_or(NetError::KeySchedule("missing shared_secret"))?;

        // 5) Get key length from AEAD suite.
        let aead = crypto
            .aead_suite(client_init.aead_suite_id)
            .ok_or(NetError::UnsupportedSuite(client_init.aead_suite_id))?;
        let key_len = aead.key_len();

        // 6) Derive session keys (SharedSecret provides as_bytes() accessor).
        let keys = SessionKeys::derive(
            shared.as_bytes(),
            &transcript_hash,
            client_init.kem_suite_id,
            client_init.aead_suite_id,
            key_len,
        );

        // 7) Build AEAD session (takes ownership of keys for secure handling).
        let session = AeadSession::new(crypto, client_init.aead_suite_id, keys)?;

        // M8: Client side doesn't have client_node_id (that's server's view of client)
        // Mutual auth is considered complete if we sent a client cert (v2 protocol)
        let mutual_auth_complete = client_init.version >= PROTOCOL_VERSION_2 
            && !client_init.client_cert.is_empty();

        Ok(HandshakeResult {
            session,
            peer_validator_id: delegation_cert.validator_id,
            kem_suite_id: client_init.kem_suite_id,
            aead_suite_id: client_init.aead_suite_id,
            client_node_id: None, // Client side doesn't see its own NodeId
            mutual_auth_complete,
        })
    }
}

/// Configuration inputs for a server-side handshake.
///
/// # Security Properties (T142)
///
/// - The `local_kem_sk` field uses `Arc<KemPrivateKey>` which implements `ZeroizeOnDrop`.
/// - The `Arc` allows cloning the config without duplicating sensitive key material.
/// - When the last reference to the config is dropped, the KEM private key is zeroized.
///
/// # DoS Cookie Protection (M6)
///
/// If `cookie_config` is Some, the server enforces cookie-based DoS protection:
/// - ClientInit without valid cookie → returns ServerCookie challenge (no KEM decap)
/// - ClientInit with valid cookie → proceeds with full handshake
///
/// If `cookie_config` is None, cookies are not enforced (backward compatibility for tests).
///
/// # Mutual Authentication (M8)
///
/// The `mutual_auth_mode` field controls client certificate requirements:
/// - `Required`: Client must provide valid cert (TestNet/MainNet default)
/// - `Optional`: Cert verified if present but not required
/// - `Disabled`: Server-auth only, ignore client cert (DevNet compatibility)
///
/// When client cert is verified, server derives NodeId from cert using
/// `derive_node_id_from_cert()` for cryptographic identity binding.
#[derive(Clone)]
pub struct ServerHandshakeConfig {
    /// KEM suite ID this node supports for validator networking.
    pub kem_suite_id: u8,
    /// AEAD suite ID this node supports for validator networking.
    pub aead_suite_id: u8,
    /// Crypto provider.
    pub crypto: Arc<dyn CryptoProvider>,
    /// This validator's root network public key (for delegations).
    /// In a PDK model, the delegation cert is precomputed; for T25,
    /// we will assume we already have a valid NetworkDelegationCert.
    pub local_root_network_pk: Vec<u8>,
    /// Pre-built delegation cert we send to clients (encoded as raw bytes).
    pub local_delegation_cert: Vec<u8>,
    /// KEM private key for this node (corresponding to cert.leaf_kem_pk).
    ///
    /// Wrapped in `Arc<KemPrivateKey>` for two reasons:
    /// 1. `KemPrivateKey` implements `ZeroizeOnDrop` for secure memory handling.
    /// 2. `Arc` allows the config to be `Clone` without duplicating key material.
    pub local_kem_sk: Arc<KemPrivateKey>,
    /// Optional KEM operation metrics (for observability).
    pub kem_metrics: Option<Arc<KemOpMetrics>>,
    /// Optional cookie configuration for DoS protection (M6).
    ///
    /// If Some, cookie validation is enforced before KEM decapsulation.
    /// If None, cookies are not validated (for backward compatibility in tests).
    pub cookie_config: Option<CookieConfig>,
    /// Server's validator ID (needed for ServerCookie response).
    pub local_validator_id: [u8; 32],
    /// Mutual authentication mode (M8).
    ///
    /// Controls whether client certificate is required, optional, or disabled.
    /// Default is `Required` for TestNet/MainNet security.
    pub mutual_auth_mode: MutualAuthMode,
    /// Trusted root public keys for verifying client certificates (M8).
    ///
    /// Maps validator_id to the corresponding root network public key.
    /// Used to verify client certificates in mutual auth mode.
    /// If empty, client certs are verified against their embedded root_key_id
    /// (assumes self-signed or externally-validated certs).
    pub trusted_client_roots: Option<TrustedClientRoots>,
    /// Run 044: optional cert-verify metrics sink (observability-only).
    ///
    /// When set, the listener-side `parse_and_verify_client_cert` path
    /// invokes the sink at each existing success/failure boundary.
    /// `None` is a zero-cost no-op path that preserves pre-Run-044
    /// verification behaviour bit-for-bit. Crate layering: defined in
    /// `qbind-net` to avoid `qbind-net → qbind-node` dependency.
    pub cert_verify_metrics: Option<Arc<dyn CertVerifyMetricsSink>>,
}

/// Trusted root public keys for client certificate verification (M8).
///
/// This allows the server to verify client certificates against known root keys.
#[derive(Clone)]
pub struct TrustedClientRoots {
    /// Function to look up root public key by root_key_id.
    ///
    /// Returns Some(root_pk) if the root_key_id is trusted, None otherwise.
    /// This allows flexible trust models (static list, database lookup, etc.).
    lookup_fn: Arc<dyn Fn(&[u8; 32]) -> Option<Vec<u8>> + Send + Sync>,
}

impl std::fmt::Debug for TrustedClientRoots {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustedClientRoots")
            .field("lookup_fn", &"<fn>")
            .finish()
    }
}

impl TrustedClientRoots {
    /// Create a new TrustedClientRoots with a custom lookup function.
    pub fn new<F>(lookup_fn: F) -> Self
    where
        F: Fn(&[u8; 32]) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        TrustedClientRoots {
            lookup_fn: Arc::new(lookup_fn),
        }
    }

    /// Look up a root public key by its root_key_id.
    pub fn lookup(&self, root_key_id: &[u8; 32]) -> Option<Vec<u8>> {
        (self.lookup_fn)(root_key_id)
    }

    /// Create TrustedClientRoots that trusts any self-signed certificate.
    ///
    /// This extracts the public key from the certificate itself and uses it
    /// for verification. Only use this for testing or when external validation
    /// is performed elsewhere.
    pub fn trust_self_signed() -> Self {
        Self::new(|_| None)
    }
}

impl std::fmt::Debug for ServerHandshakeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandshakeConfig")
            .field("kem_suite_id", &self.kem_suite_id)
            .field("aead_suite_id", &self.aead_suite_id)
            .field("local_root_network_pk", &self.local_root_network_pk)
            .field("local_delegation_cert", &self.local_delegation_cert.len())
            .field("local_kem_sk", &"<redacted>")
            .field("cookie_config", &self.cookie_config.as_ref().map(|_| "<present>"))
            .field("local_validator_id", &self.local_validator_id)
            .field("mutual_auth_mode", &self.mutual_auth_mode)
            .field("trusted_client_roots", &self.trusted_client_roots.as_ref().map(|_| "<present>"))
            .finish()
    }
}

/// Server-side KEMTLS handshake state.
pub struct ServerHandshake {
    cfg: ServerHandshakeConfig,
    /// Server's random contribution.
    server_random: [u8; 32],
}

impl std::fmt::Debug for ServerHandshake {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerHandshake")
            .field("cfg", &self.cfg)
            .field("server_random", &self.server_random)
            .finish()
    }
}

/// Result of handling a ClientInit on the server with DoS cookie protection (M6).
///
/// This enum represents the two possible outcomes:
/// - `CookieChallenge`: No valid cookie was provided, send ServerCookie challenge.
/// - `HandshakeComplete`: Valid cookie was provided, handshake completed.
#[derive(Debug)]
pub enum ServerHandshakeResponse<'a> {
    /// Client must retry with the provided cookie.
    /// No expensive KEM decapsulation occurred.
    CookieChallenge(ServerCookie),

    /// Handshake completed successfully.
    /// KEM decapsulation occurred and session is ready.
    HandshakeComplete(ServerAccept, HandshakeResult<'a>),
}

impl ServerHandshake {
    pub fn new(cfg: ServerHandshakeConfig, server_random: [u8; 32]) -> Self {
        ServerHandshake { cfg, server_random }
    }

    /// Handle a ClientInit with DoS cookie protection (M6).
    ///
    /// This is the preferred method for production use. It implements a 2-step handshake:
    ///
    /// **Step A**: If `cookie_config` is set and the ClientInit cookie is empty or invalid,
    /// returns `ServerHandshakeResponse::CookieChallenge`. No KEM decapsulation occurs.
    ///
    /// **Step B**: If the cookie is valid (or cookie_config is None), performs KEM
    /// decapsulation and returns `ServerHandshakeResponse::HandshakeComplete`.
    ///
    /// # Arguments
    ///
    /// * `crypto` - Crypto provider for AEAD session creation.
    /// * `init` - The ClientInit message from the client.
    /// * `client_ip` - Client's IP address bytes (for cookie binding).
    /// * `current_time_secs` - Current Unix timestamp in seconds.
    ///
    /// # Fail-Closed Behavior
    ///
    /// - Invalid/expired cookie → only returns cookie challenge
    /// - Never decapsulates ML-KEM unless cookie is valid
    pub fn handle_client_init_with_cookie<'a>(
        &mut self,
        crypto: &'a dyn CryptoProvider,
        init: &ClientInit,
        client_ip: &[u8],
        current_time_secs: u64,
    ) -> Result<ServerHandshakeResponse<'a>, NetError> {
        // 1) Validate suites first (cheap check)
        if init.kem_suite_id != self.cfg.kem_suite_id {
            return Err(NetError::UnsupportedSuite(init.kem_suite_id));
        }
        if init.aead_suite_id != self.cfg.aead_suite_id {
            return Err(NetError::UnsupportedSuite(init.aead_suite_id));
        }

        // 2) Check cookie length (bounded parsing - security check)
        if init.cookie.len() > MAX_COOKIE_SIZE {
            // Cookie too large - treat as invalid
            return self.generate_cookie_challenge(init, client_ip, current_time_secs);
        }

        // 3) If cookie enforcement is enabled, validate the cookie BEFORE KEM decapsulation
        if let Some(ref cookie_cfg) = self.cfg.cookie_config {
            let validation = self.validate_cookie(
                cookie_cfg,
                init,
                client_ip,
                current_time_secs,
            );

            match validation {
                CookieValidation::Valid => {
                    // Cookie is valid, proceed with KEM decapsulation
                }
                CookieValidation::NoCookie | CookieValidation::Invalid => {
                    // No cookie or invalid cookie - return challenge
                    return self.generate_cookie_challenge(init, client_ip, current_time_secs);
                }
            }
        }

        // 4) Cookie is valid (or not enforced), proceed with KEM decapsulation
        let (accept, result) = self.handle_client_init_inner(crypto, init)?;
        Ok(ServerHandshakeResponse::HandshakeComplete(accept, result))
    }

    /// Validate the cookie in a ClientInit message.
    fn validate_cookie(
        &self,
        cookie_cfg: &CookieConfig,
        init: &ClientInit,
        client_ip: &[u8],
        current_time_secs: u64,
    ) -> CookieValidation {
        if init.cookie.is_empty() {
            return CookieValidation::NoCookie;
        }

        match cookie_cfg.verify(
            &init.cookie,
            client_ip,
            init.kem_suite_id,
            init.aead_suite_id,
            &init.client_random,
            &init.validator_id,
            current_time_secs,
        ) {
            Ok(()) => CookieValidation::Valid,
            Err(_) => CookieValidation::Invalid,
        }
    }

    /// Generate a ServerCookie challenge response.
    ///
    /// # Panics
    ///
    /// Panics if `cookie_config` is None. This method should only be called
    /// from `handle_client_init_with_cookie` after confirming cookie_config is Some.
    fn generate_cookie_challenge(
        &self,
        init: &ClientInit,
        client_ip: &[u8],
        current_time_secs: u64,
    ) -> Result<ServerHandshakeResponse<'static>, NetError> {
        let cookie_cfg = self.cfg.cookie_config.as_ref()
            .expect("generate_cookie_challenge called without cookie_config; this is a bug");

        let cookie = cookie_cfg.generate(
            client_ip,
            init.kem_suite_id,
            init.aead_suite_id,
            &init.client_random,
            &init.validator_id,
            current_time_secs,
        );

        let response = ServerCookie {
            version: 1,
            kem_suite_id: init.kem_suite_id,
            aead_suite_id: init.aead_suite_id,
            validator_id: self.cfg.local_validator_id,
            client_random: init.client_random,
            cookie: cookie.to_vec(),
        };

        Ok(ServerHandshakeResponse::CookieChallenge(response))
    }

    /// Internal implementation of ClientInit handling (performs KEM decapsulation).
    ///
    /// # M8 Mutual Auth
    ///
    /// After cookie validation but before KEM decapsulation, this method:
    /// 1. Checks mutual auth mode requirements
    /// 2. Parses and verifies client certificate (if required/present)
    /// 3. Derives client NodeId from verified certificate
    ///
    /// DoS protection is preserved: cookie validation MUST complete before this method
    /// is called, ensuring no expensive crypto operations without valid cookie.
    fn handle_client_init_inner<'a>(
        &mut self,
        crypto: &'a dyn CryptoProvider,
        init: &ClientInit,
    ) -> Result<(ServerAccept, HandshakeResult<'a>), NetError> {
        // M8: Verify client certificate based on mutual_auth_mode
        // This happens AFTER cookie validation (in handle_client_init_with_cookie)
        // but BEFORE KEM decapsulation to fail closed on invalid cert
        let (client_node_id, mutual_auth_complete, verified_client_cert) = 
            self.verify_client_cert_if_required(init)?;

        // KEM decapsulation using local secret key.
        let kem = self
            .cfg
            .crypto
            .kem_suite(self.cfg.kem_suite_id)
            .ok_or(NetError::UnsupportedSuite(self.cfg.kem_suite_id))?;

        // Measure KEM decapsulation latency
        let start = Instant::now();
        // Wrap the shared secret in a zeroizing container immediately (T141).
        let mut shared = SharedSecret::new(
            kem.decaps(self.cfg.local_kem_sk.as_bytes(), &init.kem_ct)
                .map_err(|_| NetError::KeySchedule("kem decaps failed"))?,
        );
        let duration = start.elapsed();

        // Record metrics
        if let Some(metrics) = &self.cfg.kem_metrics {
            metrics.record_decaps(duration);
        }

        // M8: Compute transcript hash including client cert for mutual auth binding
        // Format: "QBIND:KEMTLS" || client_random || server_random || kem_ct || client_cert
        let mut h = Sha3_256::new();
        h.update(b"QBIND:KEMTLS");
        h.update(init.client_random);
        h.update(self.server_random);
        h.update(&init.kem_ct);
        // Include client cert in transcript for mutual auth binding
        if init.version >= PROTOCOL_VERSION_2 && !init.client_cert.is_empty() {
            h.update(&init.client_cert);
        }
        let transcript_hash = h.finalize();

        // Get key length from AEAD suite.
        let aead = crypto
            .aead_suite(init.aead_suite_id)
            .ok_or(NetError::UnsupportedSuite(init.aead_suite_id))?;
        let key_len = aead.key_len();

        // Derive session keys.
        let keys = SessionKeys::derive(
            shared.as_bytes(),
            &transcript_hash,
            init.kem_suite_id,
            init.aead_suite_id,
            key_len,
        );

        // Explicitly zeroize the shared secret (T141).
        shared.zeroize();

        // Build AEAD session.
        let session = AeadSession::new(crypto, init.aead_suite_id, keys)?;

        // M8: Get peer validator ID from verified client cert if available,
        // otherwise use the validator_id from ClientInit (server-auth only mode)
        let peer_validator_id = verified_client_cert
            .as_ref()
            .map(|c| c.validator_id)
            .unwrap_or(init.validator_id);

        // Build ServerAccept.
        let accept = ServerAccept {
            version: init.version, // Echo client's version
            kem_suite_id: init.kem_suite_id,
            aead_suite_id: init.aead_suite_id,
            server_random: self.server_random,
            validator_id: init.validator_id,
            client_random: init.client_random,
            delegation_cert: self.cfg.local_delegation_cert.clone(),
            flags: 0,
        };

        let result = HandshakeResult {
            session,
            peer_validator_id,
            kem_suite_id: init.kem_suite_id,
            aead_suite_id: init.aead_suite_id,
            client_node_id,
            mutual_auth_complete,
        };

        Ok((accept, result))
    }

    /// Verify client certificate based on mutual auth mode (M8).
    ///
    /// Returns (client_node_id, mutual_auth_complete, verified_client_cert).
    ///
    /// # Security Invariants
    ///
    /// - `Required` mode: Fails if no valid client cert provided
    /// - `Optional` mode: Fails if cert present but invalid; succeeds without cert
    /// - `Disabled` mode: Always succeeds; ignores any client cert
    ///
    /// # Fail-Closed Behavior
    ///
    /// Any parsing or verification error results in handshake failure.
    fn verify_client_cert_if_required(
        &self,
        init: &ClientInit,
    ) -> Result<(Option<[u8; 32]>, bool, Option<NetworkDelegationCert>), NetError> {
        match self.cfg.mutual_auth_mode {
            MutualAuthMode::Disabled => {
                // Server-auth only mode: ignore client cert, no mutual auth
                Ok((None, false, None))
            }
            MutualAuthMode::Required => {
                // Client cert is required
                if init.version < PROTOCOL_VERSION_2 {
                    return Err(NetError::UnsupportedProtocolVersion(init.version));
                }
                if init.client_cert.is_empty() {
                    return Err(NetError::ClientCertRequired);
                }
                // Parse, verify, and derive NodeId
                let cert = self.parse_and_verify_client_cert(&init.client_cert)?;
                let node_id = derive_node_id_from_cert(&cert);
                Ok((Some(node_id), true, Some(cert)))
            }
            MutualAuthMode::Optional => {
                // Verify client cert if present, but don't require it
                if init.version >= PROTOCOL_VERSION_2 && !init.client_cert.is_empty() {
                    // Parse, verify, and derive NodeId
                    let cert = self.parse_and_verify_client_cert(&init.client_cert)?;
                    let node_id = derive_node_id_from_cert(&cert);
                    Ok((Some(node_id), true, Some(cert)))
                } else {
                    // No client cert, server-auth only
                    Ok((None, false, None))
                }
            }
        }
    }

    /// Parse and verify a client certificate (M8).
    ///
    /// # Verification Steps
    ///
    /// 1. Parse NetworkDelegationCert from raw bytes (fail-closed on parse error)
    /// 2. Look up root public key from trusted_client_roots (or use cert's root_key_id)
    /// 3. Verify signature using the root public key
    ///
    /// # Errors
    ///
    /// - `ClientCertInvalid("parse error")`: Failed to parse certificate
    /// - `ClientCertInvalid("untrusted root")`: Root key not in trusted list
    /// - `ClientCertInvalid("signature verify error")`: Signature verification failed
    ///
    /// # Run 044 (observability-only)
    ///
    /// At each existing success/failure boundary, the optional
    /// `cert_verify_metrics` sink configured on `ServerHandshakeConfig`
    /// is invoked exactly once with the matching reason method, before
    /// the unchanged `NetError` variant is returned. Verification
    /// result is unchanged whether or not a sink is configured.
    fn parse_and_verify_client_cert(
        &self,
        cert_bytes: &[u8],
    ) -> Result<NetworkDelegationCert, NetError> {
        let sink = self.cfg.cert_verify_metrics.as_ref();

        // 1) Parse the certificate
        let mut slice: &[u8] = cert_bytes;
        let cert = match NetworkDelegationCert::decode(&mut slice) {
            Ok(c) => c,
            Err(_) => {
                if let Some(s) = sink {
                    s.inc_rejected_malformed();
                }
                return Err(NetError::ClientCertInvalid("parse error"));
            }
        };

        // 2) Look up the root public key for verification
        let root_pk = if let Some(ref roots) = self.cfg.trusted_client_roots {
            // Use configured trusted roots
            match roots.lookup(&cert.root_key_id) {
                Some(pk) => pk,
                None => {
                    if let Some(s) = sink {
                        s.inc_rejected_unknown_root();
                    }
                    return Err(NetError::ClientCertInvalid("untrusted root"));
                }
            }
        } else {
            // No trusted roots configured - for testing, we accept any cert
            // but production should always configure trusted roots
            // Use an empty vec which will cause signature verification to fail
            // unless the test provides a valid self-signed cert
            Vec::new()
        };

        // 3) Verify the certificate signature
        if !root_pk.is_empty() {
            if let Err(e) =
                verify_delegation_cert(self.cfg.crypto.as_ref(), &cert, &root_pk)
            {
                if let Some(s) = sink {
                    match &e {
                        NetError::UnsupportedSuite(_) => s.inc_rejected_wrong_suite(),
                        // Run 045: validity-window failures map to the
                        // already-wired `inc_rejected_expired` boundary.
                        NetError::ClientCertInvalid(
                            "cert expired"
                            | "cert not yet valid"
                            | "cert invalid validity window",
                        ) => s.inc_rejected_expired(),
                        NetError::KeySchedule(_) => s.inc_rejected_bad_signature(),
                        _ => s.inc_rejected_bad_signature(),
                    }
                }
                return Err(e);
            }
        }

        // Run 044: all listener-side cert-verification checks at this
        // boundary succeeded. Bump accepted exactly once. NOTE: this
        // counts the cert-verification event, not the downstream
        // KEM/AEAD handshake outcome — by design (cert verification is
        // a distinct, earlier boundary that fails closed before any
        // KEM decapsulation).
        if let Some(s) = sink {
            s.inc_accepted();
        }

        Ok(cert)
    }

    /// Handle a ClientInit and produce ServerAccept plus a HandshakeResult.
    ///
    /// **Note**: This method does NOT enforce cookie protection. Use
    /// `handle_client_init_with_cookie` for production deployments with DoS protection.
    ///
    /// This method is preserved for backward compatibility with existing tests.
    pub fn handle_client_init<'a>(
        &mut self,
        crypto: &'a dyn CryptoProvider,
        init: &ClientInit,
    ) -> Result<(ServerAccept, HandshakeResult<'a>), NetError> {
        // 1) Ensure suites match what we support.
        if init.kem_suite_id != self.cfg.kem_suite_id {
            return Err(NetError::UnsupportedSuite(init.kem_suite_id));
        }
        if init.aead_suite_id != self.cfg.aead_suite_id {
            return Err(NetError::UnsupportedSuite(init.aead_suite_id));
        }

        // Delegate to inner implementation
        self.handle_client_init_inner(crypto, init)
    }
}