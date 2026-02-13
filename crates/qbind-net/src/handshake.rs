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

use std::sync::Arc;
use std::time::Instant;

use qbind_crypto::CryptoProvider;
use qbind_hash::net::network_delegation_cert_digest;
use qbind_wire::io::WireDecode;
use qbind_wire::net::{ClientInit, NetworkDelegationCert, ServerAccept, ServerCookie};
use sha3::{Digest, Sha3_256};
use zeroize::Zeroize;

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
}

/// Verify a NetworkDelegationCert against a trusted root public key.
///
/// `root_pk` is the long-term ValidatorNetwork root key for the validator,
/// which must match the `root_key_id` semantics used in the cert.
///
/// This uses qbind-hash::net::network_delegation_cert_digest(cert) as the message
/// to be signed, and verifies using the suite indicated by `cert.sig_suite_id`.
pub fn verify_delegation_cert(
    crypto: &dyn CryptoProvider,
    cert: &NetworkDelegationCert,
    root_pk: &[u8],
) -> Result<(), NetError> {
    // 1) Resolve signature suite.
    let suite = crypto
        .signature_suite(cert.sig_suite_id)
        .ok_or(NetError::UnsupportedSuite(cert.sig_suite_id))?;

    // 2) Compute digest for the cert according to qbind-hash.
    let digest = network_delegation_cert_digest(cert);

    // 3) Verify signature.
    suite
        .verify(root_pk, &digest, &cert.sig_bytes)
        .map_err(|_| NetError::KeySchedule("signature verify error"))?;

    Ok(())
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
}

impl std::fmt::Debug for ClientHandshakeConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHandshakeConfig")
            .field("kem_suite_id", &self.kem_suite_id)
            .field("aead_suite_id", &self.aead_suite_id)
            .field("peer_root_network_pk", &self.peer_root_network_pk)
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

        // Build ClientInit. Adjust to actual fields in qbind-wire::net::ClientInit.
        Ok(ClientInit {
            version: 1,
            kem_suite_id: self.cfg.kem_suite_id,
            aead_suite_id: self.cfg.aead_suite_id,
            client_random: self.client_random,
            validator_id,
            cookie: Vec::new(), // no cookie for T25; DoS cookies can be added in later tasks.
            kem_ct: ct,
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
        // 1) Parse and verify delegation cert from raw bytes.
        let mut cert_slice: &[u8] = &accept.delegation_cert;
        let delegation_cert = NetworkDelegationCert::decode(&mut cert_slice)
            .map_err(|_| NetError::KeySchedule("failed to parse delegation cert"))?;

        verify_delegation_cert(
            self.cfg.crypto.as_ref(),
            &delegation_cert,
            &self.cfg.peer_root_network_pk,
        )?;

        // 2) Check that validator_id matches what we expected.
        if delegation_cert.validator_id != client_init.validator_id {
            return Err(NetError::KeySchedule("validator_id mismatch in cert"));
        }

        // 3) Compute transcript hash (simplified for T25).
        // For now, use Sha3_256 over:
        //   "QBIND:KEMTLS" || client_random || server_random || kem_ct
        let mut h = Sha3_256::new();
        h.update(b"QBIND:KEMTLS");
        h.update(client_init.client_random);
        h.update(accept.server_random);
        h.update(&client_init.kem_ct);
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

        Ok(HandshakeResult {
            session,
            peer_validator_id: delegation_cert.validator_id,
            kem_suite_id: client_init.kem_suite_id,
            aead_suite_id: client_init.aead_suite_id,
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
    fn generate_cookie_challenge(
        &self,
        init: &ClientInit,
        client_ip: &[u8],
        current_time_secs: u64,
    ) -> Result<ServerHandshakeResponse<'static>, NetError> {
        let cookie_cfg = self.cfg.cookie_config.as_ref()
            .ok_or(NetError::Protocol("cookie_config required for challenge"))?;

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
    fn handle_client_init_inner<'a>(
        &mut self,
        crypto: &'a dyn CryptoProvider,
        init: &ClientInit,
    ) -> Result<(ServerAccept, HandshakeResult<'a>), NetError> {
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

        // Compute transcript hash (same formula as client).
        let mut h = Sha3_256::new();
        h.update(b"QBIND:KEMTLS");
        h.update(init.client_random);
        h.update(self.server_random);
        h.update(&init.kem_ct);
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

        // Build ServerAccept.
        let accept = ServerAccept {
            version: 1,
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
            peer_validator_id: init.validator_id,
            kem_suite_id: init.kem_suite_id,
            aead_suite_id: init.aead_suite_id,
        };

        Ok((accept, result))
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
