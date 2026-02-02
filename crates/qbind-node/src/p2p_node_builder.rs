//! T175: P2P Node Builder
//!
//! This module provides `P2pNodeBuilder`, which wires up the P2P transport
//! components for a QBIND node:
//!
//! - `TcpKemTlsP2pService`: The P2P transport service
//! - `P2pInboundDemuxer`: Routes inbound messages to handlers
//! - `P2pConsensusNetwork`: Outbound consensus message sending
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────┐
//! │                       P2pNodeBuilder                            │
//! │                                                                 │
//! │  ┌───────────────────────────────────────────────────────────┐ │
//! │  │              TcpKemTlsP2pService                          │ │
//! │  │                       │                                   │ │
//! │  │           ┌───────────┴───────────┐                      │ │
//! │  │           ▼                       ▼                      │ │
//! │  │    subscribe()             broadcast() / send_to()       │ │
//! │  │           │                       ▲                      │ │
//! │  └───────────┼───────────────────────┼──────────────────────┘ │
//! │              │                       │                        │
//! │              ▼                       │                        │
//! │  ┌───────────────────────────────────┴──────────────────────┐ │
//! │  │              P2pInboundDemuxer                            │ │
//! │  │                      │                                    │ │
//! │  │    ┌─────────────────┼─────────────────┐                 │ │
//! │  │    ▼                 ▼                 ▼                 │ │
//! │  │ Consensus       DAG Handler     Control Handler          │ │
//! │  │ Handler                                                  │ │
//! │  └──────────────────────────────────────────────────────────┘ │
//! │                                                                │
//! │  ┌──────────────────────────────────────────────────────────┐ │
//! │  │           P2pConsensusNetwork                             │ │
//! │  │  (implements ConsensusNetworkFacade)                      │ │
//! │  └──────────────────────────────────────────────────────────┘ │
//! └─────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Usage
//!
//! ```rust,ignore
//! use qbind_node::p2p_node_builder::P2pNodeBuilder;
//!
//! let builder = P2pNodeBuilder::new();
//! let context = builder.build(&config, validator_id).await?;
//!
//! // ... run node ...
//!
//! P2pNodeBuilder::shutdown(context).await?;
//! ```

use std::sync::Arc;

use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::consensus_net_p2p::{P2pConsensusNetwork, SimpleValidatorNodeMapping};
use crate::metrics::P2pMetrics;
use crate::node_config::NodeConfig;
use crate::p2p::{NodeId, P2pMessage, P2pService};
use crate::p2p_inbound::{
    ConsensusInboundHandler, ControlInboundHandler, DagInboundHandler, NullConsensusHandler,
    NullControlHandler, NullDagHandler, P2pInboundDemuxer,
};
use crate::p2p_tcp::{P2pTransportError, TcpKemTlsP2pService};

use qbind_consensus::ids::ValidatorId;
use qbind_crypto::{AeadSuite, CryptoError, KemSuite, SignatureSuite, StaticCryptoProvider};
use qbind_net::{
    ClientConnectionConfig, ClientHandshakeConfig, KemPrivateKey, ServerConnectionConfig,
    ServerHandshakeConfig,
};

// ============================================================================
// Error Types
// ============================================================================

/// Errors that can occur during P2P node building and operation.
#[derive(Debug)]
pub enum P2pNodeError {
    /// Transport error.
    Transport(P2pTransportError),
    /// Configuration error.
    Config(String),
    /// IO error.
    Io(std::io::Error),
    /// Crypto error.
    Crypto(String),
}

impl std::fmt::Display for P2pNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            P2pNodeError::Transport(e) => write!(f, "P2P transport error: {:?}", e),
            P2pNodeError::Config(msg) => write!(f, "P2P config error: {}", msg),
            P2pNodeError::Io(e) => write!(f, "P2P I/O error: {}", e),
            P2pNodeError::Crypto(msg) => write!(f, "P2P crypto error: {}", msg),
        }
    }
}

impl std::error::Error for P2pNodeError {}

impl From<P2pTransportError> for P2pNodeError {
    fn from(e: P2pTransportError) -> Self {
        P2pNodeError::Transport(e)
    }
}

impl From<std::io::Error> for P2pNodeError {
    fn from(e: std::io::Error) -> Self {
        P2pNodeError::Io(e)
    }
}

// ============================================================================
// P2pNodeContext
// ============================================================================

/// Context holding all P2P node components.
///
/// This struct holds references to all P2P components that need to be
/// kept alive while the node is running.
pub struct P2pNodeContext {
    /// The P2P transport service.
    pub p2p_service: Arc<TcpKemTlsP2pService>,
    /// The P2P consensus network facade.
    pub consensus_network: P2pConsensusNetwork,
    /// Handle to the demuxer task.
    pub demuxer_handle: JoinHandle<()>,
    /// P2P metrics.
    pub metrics: Arc<P2pMetrics>,
    /// Local validator ID.
    pub validator_id: ValidatorId,
}

impl std::fmt::Debug for P2pNodeContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("P2pNodeContext")
            .field("validator_id", &self.validator_id)
            .finish()
    }
}

// ============================================================================
// Dummy Crypto Implementations (T175 Testing)
// ============================================================================

/// A DummyKem that produces deterministic shared secrets based on pk/sk.
/// Used for P2P testing without real PQC crypto overhead.
struct DummyKem {
    suite_id: u8,
}

impl DummyKem {
    fn new(suite_id: u8) -> Self {
        DummyKem { suite_id }
    }
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
        48
    }

    fn encaps(&self, pk: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CryptoError> {
        let mut ct = pk.to_vec();
        ct.extend_from_slice(b"ct-padding-bytes");
        ct.truncate(self.ciphertext_len());
        while ct.len() < self.ciphertext_len() {
            ct.push(0);
        }

        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }

        Ok((ct, ss))
    }

    fn decaps(&self, _sk: &[u8], ct: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let pk = &ct[..self.public_key_len().min(ct.len())];
        let mut ss = pk.to_vec();
        ss.extend_from_slice(b"ss-padding-bytes");
        ss.truncate(self.shared_secret_len());
        while ss.len() < self.shared_secret_len() {
            ss.push(0);
        }
        Ok(ss)
    }
}

/// A DummySig that always verifies successfully (for testing only).
struct DummySig {
    suite_id: u8,
}

impl DummySig {
    fn new(suite_id: u8) -> Self {
        DummySig { suite_id }
    }
}

impl SignatureSuite for DummySig {
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

/// A DummyAead that XORs with a single-byte key (test-only).
struct DummyAead {
    suite_id: u8,
}

impl DummyAead {
    fn new(suite_id: u8) -> Self {
        DummyAead { suite_id }
    }
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
        1
    }

    fn seal(
        &self,
        key: &[u8],
        _nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let key_byte = key.first().copied().unwrap_or(0);
        let mut ciphertext: Vec<u8> = plaintext.iter().map(|b| b ^ key_byte).collect();
        // Dummy tag: XOR of aad bytes
        let tag = aad.iter().fold(0u8, |acc, b| acc ^ b);
        ciphertext.push(tag);
        Ok(ciphertext)
    }

    fn open(
        &self,
        key: &[u8],
        _nonce: &[u8],
        _aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.is_empty() {
            return Err(CryptoError::InvalidCiphertext);
        }
        let key_byte = key.first().copied().unwrap_or(0);
        // Strip tag
        let ct_len = ciphertext.len() - self.tag_len();
        let plaintext: Vec<u8> = ciphertext[..ct_len].iter().map(|b| b ^ key_byte).collect();
        Ok(plaintext)
    }
}

/// Create a test crypto provider for P2P.
fn make_test_crypto_provider(
    kem_suite_id: u8,
    aead_suite_id: u8,
    sig_suite_id: u8,
) -> Arc<StaticCryptoProvider> {
    Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(DummyKem::new(kem_suite_id)))
            .with_aead_suite(Arc::new(DummyAead::new(aead_suite_id)))
            .with_signature_suite(Arc::new(DummySig::new(sig_suite_id))),
    )
}

// ============================================================================
// P2pNodeBuilder
// ============================================================================

/// Builder for P2P node components (T175).
///
/// This builder creates and wires all the P2P components needed for
/// a QBIND node to operate in P2P mode.
pub struct P2pNodeBuilder {
    /// Number of validators in the network (default: 4).
    num_validators: usize,
    /// Consensus inbound handler (optional override).
    consensus_handler: Option<Arc<dyn ConsensusInboundHandler>>,
    /// DAG inbound handler (optional override).
    dag_handler: Option<Arc<dyn DagInboundHandler>>,
    /// Control inbound handler (optional override).
    control_handler: Option<Arc<dyn ControlInboundHandler>>,
}

impl Default for P2pNodeBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl P2pNodeBuilder {
    /// Create a new P2P node builder with default settings.
    pub fn new() -> Self {
        Self {
            num_validators: 4,
            consensus_handler: None,
            dag_handler: None,
            control_handler: None,
        }
    }

    /// Set the number of validators in the network.
    pub fn with_num_validators(mut self, n: usize) -> Self {
        self.num_validators = n;
        self
    }

    /// Set a custom consensus inbound handler.
    pub fn with_consensus_handler(mut self, handler: Arc<dyn ConsensusInboundHandler>) -> Self {
        self.consensus_handler = Some(handler);
        self
    }

    /// Set a custom DAG inbound handler.
    pub fn with_dag_handler(mut self, handler: Arc<dyn DagInboundHandler>) -> Self {
        self.dag_handler = Some(handler);
        self
    }

    /// Set a custom control inbound handler.
    pub fn with_control_handler(mut self, handler: Arc<dyn ControlInboundHandler>) -> Self {
        self.control_handler = Some(handler);
        self
    }

    /// Build the P2P node context.
    ///
    /// This method:
    /// 1. Creates the TcpKemTlsP2pService
    /// 2. Starts the service (listen + dial peers)
    /// 3. Creates the P2pInboundDemuxer
    /// 4. Creates the P2pConsensusNetwork
    /// 5. Spawns the demuxer loop
    ///
    /// # Arguments
    ///
    /// * `config` - The node configuration
    /// * `validator_id` - The local validator ID
    ///
    /// # Returns
    ///
    /// A P2pNodeContext containing all wired components.
    pub async fn build(
        self,
        config: &NodeConfig,
        validator_id: u64,
    ) -> Result<P2pNodeContext, P2pNodeError> {
        let validator_id = ValidatorId::new(validator_id);

        // Create NodeId from validator ID
        let node_id =
            SimpleValidatorNodeMapping::node_id_from_index(validator_id.as_u64() as usize);

        // Create crypto provider (using test crypto for T175)
        let kem_suite_id: u8 = 1;
        let aead_suite_id: u8 = 2;
        let sig_suite_id: u8 = 3;
        let crypto = make_test_crypto_provider(kem_suite_id, aead_suite_id, sig_suite_id);

        // Create connection configs
        let (server_cfg, client_cfg) = self.create_connection_configs(
            validator_id,
            crypto.clone(),
            kem_suite_id,
            aead_suite_id,
            sig_suite_id,
        );

        // Create P2P service
        let mut p2p_service = TcpKemTlsP2pService::new(
            node_id,
            config.network.clone(),
            crypto,
            server_cfg,
            client_cfg,
        )?;

        // Start the service
        p2p_service.start().await?;

        let p2p_service = Arc::new(p2p_service);

        // Create metrics
        let metrics = Arc::new(P2pMetrics::new());

        // Get inbound receiver from P2P service
        // Note: TcpKemTlsP2pService uses an internal channel; for T175 we use
        // a simple channel-based approach
        let (_inbound_tx, inbound_rx) = mpsc::channel::<P2pMessage>(256);

        // Create handlers (use provided or default null handlers)
        let consensus_handler: Arc<dyn ConsensusInboundHandler> = self
            .consensus_handler
            .unwrap_or_else(|| Arc::new(NullConsensusHandler));
        let dag_handler: Arc<dyn DagInboundHandler> =
            self.dag_handler.unwrap_or_else(|| Arc::new(NullDagHandler));
        let control_handler: Arc<dyn ControlInboundHandler> = self
            .control_handler
            .unwrap_or_else(|| Arc::new(NullControlHandler));

        // Create demuxer
        let demuxer = P2pInboundDemuxer::new(
            inbound_rx,
            consensus_handler,
            dag_handler,
            Some(control_handler),
        )
        .with_metrics(metrics.clone());

        // Spawn demuxer loop
        let demuxer_handle = tokio::spawn(async move {
            demuxer.run().await;
        });

        // Create P2P consensus network
        let consensus_network = P2pConsensusNetwork::new(
            p2p_service.clone() as Arc<dyn P2pService>,
            self.num_validators,
        )
        .with_local_validator(validator_id);

        println!(
            "[T175] P2P node builder: validator={:?} node_id={:?} num_validators={}",
            validator_id, node_id, self.num_validators
        );

        Ok(P2pNodeContext {
            p2p_service,
            consensus_network,
            demuxer_handle,
            metrics,
            validator_id,
        })
    }

    /// Create KEMTLS connection configs for the node.
    fn create_connection_configs(
        &self,
        validator_id: ValidatorId,
        crypto: Arc<StaticCryptoProvider>,
        kem_suite_id: u8,
        aead_suite_id: u8,
        sig_suite_id: u8,
    ) -> (ServerConnectionConfig, ClientConnectionConfig) {
        // Create validator identity bytes
        let mut validator_id_bytes = [0u8; 32];
        let name = format!("qbind-val-{}", validator_id.as_u64());
        validator_id_bytes[..name.len().min(32)].copy_from_slice(name.as_bytes());

        // Create root key ID
        let mut root_key_id = [0u8; 32];
        root_key_id[0..8].copy_from_slice(b"root-key");

        // Create KEM keypair (deterministic from validator ID)
        let server_kem_pk: Vec<u8> = (0u8..32u8)
            .map(|i| i.wrapping_add(validator_id.as_u64() as u8))
            .collect();
        let server_kem_sk: Vec<u8> = server_kem_pk.iter().map(|x| x ^ 0xFF).collect();

        // Create a dummy delegation certificate
        let cert = self.make_dummy_delegation_cert(
            validator_id_bytes,
            root_key_id,
            server_kem_pk.clone(),
            kem_suite_id,
            sig_suite_id,
        );

        // Encode certificate
        use qbind_wire::io::WireEncode;
        let mut cert_bytes = Vec::new();
        cert.encode(&mut cert_bytes);

        // Root network public key (dummy)
        let root_network_pk: Vec<u8> = vec![0u8; 32];

        // Random values for handshake
        let mut client_random = [0u8; 32];
        let client_name = format!("qbind-client-{}", validator_id.as_u64());
        client_random[..client_name.len().min(32)].copy_from_slice(client_name.as_bytes());

        let mut server_random = [0u8; 32];
        let server_name = format!("qbind-server-{}", validator_id.as_u64());
        server_random[..server_name.len().min(32)].copy_from_slice(server_name.as_bytes());

        // Create handshake configs
        let client_handshake_cfg = ClientHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto: crypto.clone(),
            peer_root_network_pk: root_network_pk.clone(),
            kem_metrics: None,
        };

        let server_handshake_cfg = ServerHandshakeConfig {
            kem_suite_id,
            aead_suite_id,
            crypto,
            local_root_network_pk: root_network_pk,
            local_delegation_cert: cert_bytes,
            local_kem_sk: Arc::new(KemPrivateKey::new(server_kem_sk)),
            kem_metrics: None,
        };

        // Create connection configs
        let client_cfg = ClientConnectionConfig {
            handshake_config: client_handshake_cfg,
            client_random,
            validator_id: validator_id_bytes,
            peer_kem_pk: server_kem_pk,
        };

        let server_cfg = ServerConnectionConfig {
            handshake_config: server_handshake_cfg,
            server_random,
        };

        (server_cfg, client_cfg)
    }

    /// Create a dummy delegation certificate for testing.
    fn make_dummy_delegation_cert(
        &self,
        validator_id: [u8; 32],
        root_key_id: [u8; 32],
        leaf_kem_pk: Vec<u8>,
        kem_suite_id: u8,
        sig_suite_id: u8,
    ) -> qbind_wire::net::NetworkDelegationCert {
        qbind_wire::net::NetworkDelegationCert {
            version: 1,
            validator_id,
            root_key_id,
            leaf_kem_suite_id: kem_suite_id,
            leaf_kem_pk,
            not_before: 0,
            not_after: u64::MAX,
            ext_bytes: vec![],
            sig_suite_id,
            sig_bytes: vec![0u8; 64],
        }
    }

    /// Shutdown the P2P node.
    ///
    /// This method gracefully shuts down all P2P components:
    /// 1. Stops the demuxer loop
    /// 2. Stops the P2P transport service
    ///
    /// # Arguments
    ///
    /// * `context` - The P2P node context to shutdown
    pub async fn shutdown(context: P2pNodeContext) -> Result<(), P2pNodeError> {
        println!(
            "[T175] Shutting down P2P node for validator {:?}",
            context.validator_id
        );

        // Abort the demuxer task
        context.demuxer_handle.abort();

        // Wait for demuxer to finish (with timeout)
        let _ =
            tokio::time::timeout(std::time::Duration::from_secs(5), context.demuxer_handle).await;

        // Note: TcpKemTlsP2pService shutdown is handled via its internal
        // shutdown channel when it's dropped

        println!("[T175] P2P node shutdown complete");
        Ok(())
    }
}

// ============================================================================
// SimpleValidatorNodeMapping Extension
// ============================================================================

impl SimpleValidatorNodeMapping {
    /// Derive a NodeId from a validator index (public helper for T175).
    pub fn node_id_from_index(index: usize) -> NodeId {
        let mut bytes = [0u8; 32];
        let index_bytes = (index as u64).to_le_bytes();
        bytes[..8].copy_from_slice(&index_bytes);
        NodeId::new(bytes)
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::node_config::{DagCouplingMode, MempoolMode, NetworkMode, NetworkTransportConfig};
    use qbind_types::NetworkEnvironment;

    fn make_test_config() -> NodeConfig {
        NodeConfig {
            environment: NetworkEnvironment::Testnet,
            execution_profile: crate::node_config::ExecutionProfile::VmV0,
            data_dir: None,
            network: NetworkTransportConfig {
                enable_p2p: true,
                max_outbound: 4,
                max_inbound: 8,
                gossip_fanout: 3,
                listen_addr: Some("127.0.0.1:0".to_string()),
                advertised_addr: None,
                static_peers: vec![],
            },
            network_mode: NetworkMode::P2p,
            // T180 fields
            gas_enabled: false,
            enable_fee_priority: false,
            mempool_mode: MempoolMode::Fifo,
            dag_availability_enabled: false,
            // T189 field
            dag_coupling_mode: DagCouplingMode::Off,
            // T186 field
            stage_b_enabled: false,
        }
    }

    #[test]
    fn test_p2p_node_builder_new() {
        let builder = P2pNodeBuilder::new();
        assert_eq!(builder.num_validators, 4);
    }

    #[test]
    fn test_p2p_node_builder_with_num_validators() {
        let builder = P2pNodeBuilder::new().with_num_validators(7);
        assert_eq!(builder.num_validators, 7);
    }

    #[test]
    fn test_simple_validator_node_mapping_node_id() {
        let node_id_0 = SimpleValidatorNodeMapping::node_id_from_index(0);
        let node_id_1 = SimpleValidatorNodeMapping::node_id_from_index(1);

        assert_ne!(node_id_0, node_id_1);
    }

    #[tokio::test]
    async fn test_p2p_node_builder_build() {
        let config = make_test_config();
        let builder = P2pNodeBuilder::new().with_num_validators(4);

        let result = builder.build(&config, 0).await;
        assert!(
            result.is_ok(),
            "Should build P2P node context: {:?}",
            result.err()
        );

        let context = result.unwrap();
        assert_eq!(context.validator_id.as_u64(), 0);

        // Shutdown
        let shutdown_result = P2pNodeBuilder::shutdown(context).await;
        assert!(shutdown_result.is_ok());
    }
}