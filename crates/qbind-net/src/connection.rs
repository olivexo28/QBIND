//! High-level connection abstraction for KEMTLS-PDK handshake and transport.
//!
//! This module provides a unified `Connection` type that manages both the
//! handshake state machine and the established AEAD session.

use std::sync::Arc;

use qbind_crypto::CryptoProvider;
use qbind_wire::net::ClientInit;

use crate::error::NetError;
use crate::handshake::{
    ClientHandshake, ClientHandshakeConfig, ConnectionState, HandshakeSide, ServerHandshake,
    ServerHandshakeConfig,
};
use crate::handshake_packet::{
    pack_client_init, pack_server_accept, unpack_client_init, unpack_server_accept,
    HandshakePacket, HANDSHAKE_TYPE_CLIENT_INIT, HANDSHAKE_TYPE_SERVER_ACCEPT,
};
use crate::transport::{
    decrypt_app_frame, encrypt_app_frame, TransportFrame, TRANSPORT_TYPE_APP_MESSAGE,
};

/// Internal handshake enum to hold either client or server handshake state.
#[derive(Debug)]
enum HandshakeInner {
    Client(ClientHandshake),
    Server(ServerHandshake),
}

/// Client-specific configuration for starting a connection.
#[derive(Clone)]
pub struct ClientConnectionConfig {
    /// The base handshake configuration.
    pub handshake_config: ClientHandshakeConfig,
    /// Client's random contribution to the handshake.
    pub client_random: [u8; 32],
    /// The validator ID we are connecting to.
    pub validator_id: [u8; 32],
    /// The peer's KEM public key (from their delegation cert).
    pub peer_kem_pk: Vec<u8>,
}

impl std::fmt::Debug for ClientConnectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientConnectionConfig")
            .field("handshake_config", &self.handshake_config)
            .field("validator_id", &self.validator_id)
            .finish_non_exhaustive()
    }
}

/// Server-specific configuration for starting a connection.
#[derive(Clone)]
pub struct ServerConnectionConfig {
    /// The base handshake configuration.
    pub handshake_config: ServerHandshakeConfig,
    /// Server's random contribution to the handshake.
    pub server_random: [u8; 32],
}

impl std::fmt::Debug for ServerConnectionConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerConnectionConfig")
            .field("handshake_config", &self.handshake_config)
            .finish_non_exhaustive()
    }
}

/// High-level connection object managing handshake and transport.
///
/// # Invariants
///
/// - If `state` is `ConnectionState::Handshaking`, `handshake` must be `Some`.
/// - If `state` is `ConnectionState::Established(_)`, `handshake` must be `None`.
///
/// # Memory considerations
///
/// Due to the lifetime constraints of `AeadSession<'a>`, the `Connection` must leak
/// the `Arc<dyn CryptoProvider>` when transitioning to the Established state. Each
/// connection leaks one `Arc` (typically ~64 bytes plus the provider size) per handshake
/// completion. This is acceptable for long-lived connections but should be considered
/// if creating many short-lived connections. A future refactoring of `AeadSession` to
/// use `Arc<dyn CryptoProvider>` internally would eliminate this limitation.
pub struct Connection {
    side: HandshakeSide,
    /// Present only while we are in Handshaking state.
    handshake: Option<HandshakeInner>,
    /// Coarse connection state: handshaking vs established(session).
    state: ConnectionState<'static>,
    /// Crypto provider reference (needed for handshake completion).
    crypto: Arc<dyn CryptoProvider>,
    /// For client: stored ClientInit for later use in handle_server_accept.
    client_init: Option<ClientInit>,
    /// For client: the validator_id we're connecting to.
    validator_id: Option<[u8; 32]>,
    /// For client: the peer's KEM public key.
    peer_kem_pk: Option<Vec<u8>>,
    /// B12 — peer identity surfaced from the completed handshake's
    /// `HandshakeResult` (otherwise discarded). Populated on both sides
    /// at the `Established` transition.
    ///
    /// - On the **server side** under `MutualAuthMode::Required`,
    ///   `peer_validator_id` is the validator id field of the
    ///   *verified* client `NetworkDelegationCert` (cryptographically
    ///   bound to the client's leaf KEM pk that participated in the
    ///   transcript-bound key schedule), `peer_node_id` is
    ///   `derive_node_id_from_cert(client_cert)`, and
    ///   `mutual_auth_complete` is `true`.
    /// - On the **client side**, `peer_validator_id` is the server's
    ///   validator id from the verified server cert,
    ///   `peer_node_id` is `None` (the client doesn't bind a NodeId
    ///   for itself from the handshake), and `mutual_auth_complete`
    ///   reflects whether the client opted into the v2 mutual-auth
    ///   protocol.
    /// - Under `MutualAuthMode::Disabled`, `peer_node_id` is `None`
    ///   and `mutual_auth_complete` is `false`.
    peer_validator_id: Option<[u8; 32]>,
    peer_node_id: Option<[u8; 32]>,
    mutual_auth_complete: bool,
}

impl std::fmt::Debug for Connection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Connection")
            .field("side", &self.side)
            .field("handshake", &self.handshake.as_ref().map(|_| "<handshake>"))
            .field(
                "state",
                &match &self.state {
                    ConnectionState::Handshaking => "Handshaking",
                    ConnectionState::Established(_) => "Established",
                },
            )
            .finish_non_exhaustive()
    }
}

impl Connection {
    /// Create a client-side connection from a ClientConnectionConfig.
    pub fn new_client(cfg: ClientConnectionConfig) -> Self {
        let crypto = cfg.handshake_config.crypto.clone();
        let hs = ClientHandshake::new(cfg.handshake_config, cfg.client_random);
        Connection {
            side: HandshakeSide::Client,
            handshake: Some(HandshakeInner::Client(hs)),
            state: ConnectionState::Handshaking,
            crypto,
            client_init: None,
            validator_id: Some(cfg.validator_id),
            peer_kem_pk: Some(cfg.peer_kem_pk),
            peer_validator_id: None,
            peer_node_id: None,
            mutual_auth_complete: false,
        }
    }

    /// Create a server-side connection from a ServerConnectionConfig.
    pub fn new_server(cfg: ServerConnectionConfig) -> Self {
        let crypto = cfg.handshake_config.crypto.clone();
        let hs = ServerHandshake::new(cfg.handshake_config, cfg.server_random);
        Connection {
            side: HandshakeSide::Server,
            handshake: Some(HandshakeInner::Server(hs)),
            state: ConnectionState::Handshaking,
            crypto,
            client_init: None,
            validator_id: None,
            peer_kem_pk: None,
            peer_validator_id: None,
            peer_node_id: None,
            mutual_auth_complete: false,
        }
    }

    /// Check if the connection is established and ready for app data.
    pub fn is_established(&self) -> bool {
        matches!(self.state, ConnectionState::Established(_))
    }

    /// B12 — peer's validator id surfaced from the completed handshake
    /// (server side: from verified client cert under
    /// `MutualAuthMode::Required`; client side: from the verified
    /// server cert).
    ///
    /// Returns `None` while the handshake is still in progress, or in
    /// `MutualAuthMode::Disabled`/`Optional` (server side, no client
    /// cert presented) where no client-cert-bound peer id is available.
    pub fn peer_validator_id(&self) -> Option<[u8; 32]> {
        self.peer_validator_id
    }

    /// B12 — peer's NodeId derived from the verified client delegation
    /// cert (server side, `MutualAuthMode::Required` only).
    ///
    /// Returns `None` on the client side (the client doesn't bind a
    /// NodeId for itself from the handshake) and on the server side
    /// when mutual auth was not performed.
    ///
    /// When this returns `Some(node_id)`, the server has cryptographically
    /// bound the inbound session to the validator identity claimed by
    /// the client cert: a transport peer cannot have completed the
    /// handshake without holding the leaf KEM secret matching the
    /// cert's `leaf_kem_pk`, and the cert's `validator_id` was bundled
    /// into the transcript hash that derived the AEAD session keys.
    pub fn peer_node_id(&self) -> Option<[u8; 32]> {
        self.peer_node_id
    }

    /// B12 — whether mutual auth was performed and verified during the
    /// handshake.
    ///
    /// True iff a client `NetworkDelegationCert` was presented in v2
    /// `ClientInit` and the server's `MutualAuthMode` was not
    /// `Disabled` (so the cert went through `parse_and_verify_client_cert`).
    pub fn mutual_auth_complete(&self) -> bool {
        self.mutual_auth_complete
    }

    /// For clients: start the KEMTLS handshake and produce the first frame to send.
    ///
    /// Returns the encoded ClientInit packet ready to be sent over the wire.
    ///
    /// # Errors
    ///
    /// Returns `NetError::Protocol` if called on a server or in an invalid state.
    pub fn start_handshake(&mut self) -> Result<Vec<u8>, NetError> {
        match (&self.side, &mut self.handshake, &self.state) {
            (
                HandshakeSide::Client,
                Some(HandshakeInner::Client(hs)),
                ConnectionState::Handshaking,
            ) => {
                let validator_id = self
                    .validator_id
                    .ok_or(NetError::Protocol("missing validator_id"))?;
                let peer_kem_pk = self
                    .peer_kem_pk
                    .as_ref()
                    .ok_or(NetError::Protocol("missing peer_kem_pk"))?;

                let client_init = hs
                    .start(validator_id, peer_kem_pk)
                    .map_err(|_| NetError::Protocol("client handshake start failed"))?;

                // Store client_init for later use in handle_server_accept
                let pkt = pack_client_init(&client_init)?;
                self.client_init = Some(client_init);

                Ok(pkt.encode())
            }
            _ => Err(NetError::Protocol(
                "start_handshake called in invalid state",
            )),
        }
    }

    /// Handle an incoming handshake frame.
    ///
    /// Returns:
    /// - `Ok(Some(reply_bytes))` when a reply frame should be sent back (server side),
    /// - `Ok(None)` when no reply is needed (client after final ServerAccept),
    /// - `Err(NetError::Protocol(..))` on protocol misuse or decoding errors.
    pub fn handle_handshake_frame(&mut self, frame: &[u8]) -> Result<Option<Vec<u8>>, NetError> {
        let pkt = HandshakePacket::decode(frame)?;

        match (&self.side, &mut self.handshake, &mut self.state) {
            // Server side: expect ClientInit, produce ServerAccept and become Established
            (
                HandshakeSide::Server,
                Some(HandshakeInner::Server(hs)),
                ConnectionState::Handshaking,
            ) => {
                if pkt.msg_type != HANDSHAKE_TYPE_CLIENT_INIT {
                    return Err(NetError::Protocol("server expected ClientInit"));
                }
                let client_init = unpack_client_init(&pkt)?;

                // Create a 'static reference to the crypto provider. This leaks memory
                // (see struct-level docs) but is required because AeadSession requires 'static.
                let crypto_arc: &'static Arc<dyn CryptoProvider> =
                    Box::leak(Box::new(self.crypto.clone()));
                let crypto_ref: &'static dyn CryptoProvider = crypto_arc.as_ref();

                let (server_accept, result) = hs
                    .handle_client_init(crypto_ref, &client_init)
                    .map_err(|_| NetError::Protocol("server handle_client_init failed"))?;

                let reply_pkt = pack_server_accept(&server_accept)?;
                let reply_bytes = reply_pkt.encode();

                // B12 — capture verified peer identity from the
                // completed `HandshakeResult` before we drop it. On the
                // server side this is what makes the cryptographically
                // bound peer identity visible to the transport layer:
                // `result.peer_validator_id` is the validator id field
                // of the verified cert (client cert under mutual auth,
                // otherwise the server's own cert reflected back),
                // `result.client_node_id` is the cert-bound NodeId set
                // only when `MutualAuthMode::Required` and the client
                // cert verified, and `result.mutual_auth_complete`
                // mirrors the same condition.
                self.peer_validator_id = Some(result.peer_validator_id);
                self.peer_node_id = result.client_node_id;
                self.mutual_auth_complete = result.mutual_auth_complete;

                // Transition to Established state
                self.handshake = None;
                self.state = ConnectionState::Established(result.session);

                Ok(Some(reply_bytes))
            }

            // Client side: expect ServerAccept, become Established, no reply
            (
                HandshakeSide::Client,
                Some(HandshakeInner::Client(hs)),
                ConnectionState::Handshaking,
            ) => {
                if pkt.msg_type != HANDSHAKE_TYPE_SERVER_ACCEPT {
                    return Err(NetError::Protocol("client expected ServerAccept"));
                }
                let server_accept = unpack_server_accept(&pkt)?;

                let client_init = self.client_init.as_ref().ok_or(NetError::Protocol(
                    "client_init not set; call start_handshake first",
                ))?;

                // Create a 'static reference to the crypto provider. This leaks memory
                // (see struct-level docs) but is required because AeadSession requires 'static.
                let crypto_arc: &'static Arc<dyn CryptoProvider> =
                    Box::leak(Box::new(self.crypto.clone()));
                let crypto_ref: &'static dyn CryptoProvider = crypto_arc.as_ref();

                let result = hs
                    .handle_server_accept(crypto_ref, client_init, &server_accept)
                    .map_err(|_| NetError::Protocol("client handle_server_accept failed"))?;

                // B12 — capture verified peer identity from the
                // client-side `HandshakeResult` (the server's
                // validator id from the verified server cert, and the
                // mutual-auth flag).
                self.peer_validator_id = Some(result.peer_validator_id);
                self.peer_node_id = result.client_node_id;
                self.mutual_auth_complete = result.mutual_auth_complete;

                // Transition to Established state
                self.handshake = None;
                self.client_init = None;
                self.state = ConnectionState::Established(result.session);

                Ok(None)
            }

            _ => Err(NetError::Protocol(
                "handle_handshake_frame called in invalid state",
            )),
        }
    }

    /// Encrypt an application payload into a TransportFrame and encode it.
    ///
    /// # Direction mapping
    ///
    /// - Client: outgoing → session.c2s
    /// - Server: outgoing → session.s2c
    ///
    /// # Errors
    ///
    /// Returns `NetError::Protocol` if called before handshake is complete.
    pub fn encrypt_app(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, NetError> {
        let session = match &mut self.state {
            ConnectionState::Established(ref mut sess) => sess,
            ConnectionState::Handshaking => {
                return Err(NetError::Protocol(
                    "encrypt_app called before handshake complete",
                ));
            }
        };

        let frame: TransportFrame = match self.side {
            HandshakeSide::Client => encrypt_app_frame(&mut session.c2s, plaintext)?,
            HandshakeSide::Server => encrypt_app_frame(&mut session.s2c, plaintext)?,
        };

        frame.encode()
    }

    /// Decrypt an incoming transport frame and return the plaintext application data.
    ///
    /// # Direction mapping
    ///
    /// - Client: incoming → session.s2c
    /// - Server: incoming → session.c2s
    ///
    /// # Errors
    ///
    /// Returns `NetError::Protocol` if called before handshake is complete or
    /// if the frame has an unexpected msg_type.
    pub fn decrypt_app(&mut self, frame_bytes: &[u8]) -> Result<Vec<u8>, NetError> {
        let session = match &mut self.state {
            ConnectionState::Established(ref mut sess) => sess,
            ConnectionState::Handshaking => {
                return Err(NetError::Protocol(
                    "decrypt_app called before handshake complete",
                ));
            }
        };

        let frame = TransportFrame::decode(frame_bytes)?;

        if frame.msg_type != TRANSPORT_TYPE_APP_MESSAGE {
            return Err(NetError::Protocol("unexpected transport frame type"));
        }

        let plaintext = match self.side {
            HandshakeSide::Client => decrypt_app_frame(&mut session.s2c, &frame)?,
            HandshakeSide::Server => decrypt_app_frame(&mut session.c2s, &frame)?,
        };

        Ok(plaintext)
    }
}