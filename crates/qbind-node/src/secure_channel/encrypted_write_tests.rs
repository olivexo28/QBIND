//! A11-F2 deterministic write faults through production send/worker logic.
//! Real ML-KEM-768 and ChaCha20-Poly1305; only certificate verification is dummy.

use super::*;
use std::future::Future;
use std::io::Write;
use std::net::TcpListener;
use std::sync::atomic::AtomicUsize;

use qbind_crypto::{
    AeadSuite, ChaCha20Poly1305Backend, CryptoError, MlKem768Backend, SignatureSuite,
    StaticCryptoProvider, AEAD_SUITE_CHACHA20_POLY1305, KEM_SUITE_ML_KEM_768,
};
use qbind_net::{ClientHandshakeConfig, KemPrivateKey, MutualAuthMode, ServerHandshakeConfig};
use qbind_wire::{io::WireEncode, net::NetworkDelegationCert};

#[derive(Debug, Default)]
pub(super) struct CryptoTrace {
    pub(super) nonces: Mutex<Vec<Vec<u8>>>,
    pub(super) opens: AtomicUsize,
    fail_seal: AtomicBool,
}

struct CountedRealAead(Arc<CryptoTrace>);

impl AeadSuite for CountedRealAead {
    fn suite_id(&self) -> u8 {
        AEAD_SUITE_CHACHA20_POLY1305
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
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.0.nonces.lock().unwrap().push(nonce.to_vec());
        let ciphertext = ChaCha20Poly1305Backend::new().seal(key, nonce, aad, plaintext)?;
        if self.0.fail_seal.load(Ordering::SeqCst) {
            return Err(CryptoError::InvalidCiphertext);
        }
        Ok(ciphertext)
    }
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        self.0.opens.fetch_add(1, Ordering::SeqCst);
        ChaCha20Poly1305Backend::new().open(key, nonce, aad, ciphertext)
    }
}

struct TestSignature;
impl SignatureSuite for TestSignature {
    fn suite_id(&self) -> u8 {
        3
    }
    fn public_key_len(&self) -> usize {
        32
    }
    fn signature_len(&self) -> usize {
        64
    }
    fn verify(&self, _: &[u8], _: &[u8; 32], _: &[u8]) -> Result<(), CryptoError> {
        Ok(())
    }
}

pub(super) fn pair(peer_init: bool) -> (SecureChannel, SecureChannel, Arc<CryptoTrace>) {
    let trace = Arc::new(CryptoTrace::default());
    let provider = Arc::new(
        StaticCryptoProvider::new()
            .with_kem_suite(Arc::new(MlKem768Backend::new()))
            .with_aead_suite(Arc::new(CountedRealAead(Arc::clone(&trace))))
            .with_signature_suite(Arc::new(TestSignature)),
    );
    let (pk, sk) = MlKem768Backend::generate_keypair().unwrap();
    let cert = NetworkDelegationCert {
        version: 1,
        validator_id: [7; 32],
        root_key_id: [8; 32],
        leaf_kem_suite_id: KEM_SUITE_ML_KEM_768,
        leaf_kem_pk: pk.clone(),
        not_before: 0,
        not_after: u64::MAX,
        ext_bytes: vec![],
        sig_suite_id: 3,
        sig_bytes: vec![0; 64],
    };
    let mut cert_bytes = Vec::new();
    cert.encode(&mut cert_bytes);
    let server_cfg = ServerConnectionConfig {
        handshake_config: ServerHandshakeConfig {
            kem_suite_id: KEM_SUITE_ML_KEM_768,
            aead_suite_id: AEAD_SUITE_CHACHA20_POLY1305,
            crypto: provider.clone(),
            local_root_network_pk: vec![0; 32],
            local_delegation_cert: cert_bytes,
            local_kem_sk: Arc::new(KemPrivateKey::new(sk)),
            kem_metrics: None,
            cookie_config: None,
            local_validator_id: [7; 32],
            mutual_auth_mode: MutualAuthMode::Disabled,
            trusted_client_roots: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        },
        server_random: [2; 32],
    };
    let client_cfg = ClientConnectionConfig {
        handshake_config: ClientHandshakeConfig {
            kem_suite_id: KEM_SUITE_ML_KEM_768,
            aead_suite_id: AEAD_SUITE_CHACHA20_POLY1305,
            crypto: provider,
            peer_root_network_pk: vec![0; 32],
            kem_metrics: None,
            local_delegation_cert: None,
            cert_verify_metrics: None,
            leaf_cert_revocations: None,
        },
        client_random: [1; 32],
        validator_id: [7; 32],
        peer_kem_pk: pk,
    };
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        if peer_init {
            SecureChannel::from_accepted_with_peer_init(stream, server_cfg)
                .unwrap()
                .0
        } else {
            SecureChannel::from_accepted(stream, server_cfg).unwrap()
        }
    });
    let client = SecureChannel::connect(&addr.to_string(), client_cfg).unwrap();
    (client, server.join().unwrap(), trace)
}

pub(crate) fn pair_channels(peer_init: bool) -> (SecureChannel, SecureChannel) {
    let (client, server, _) = pair(peer_init);
    (client, server)
}

#[test]
fn async_wrapper_refuses_when_shutdown_capability_creation_fails() {
    let (channel, mut peer, _) = pair(false);
    let result = SecureChannelAsync::try_new_with_shutdown_factory(channel, |_| {
        Err(io::Error::other(
            "injected shutdown capability creation failure",
        ))
    });
    assert!(matches!(
        result,
        Err(AsyncChannelError::Channel(ChannelError::Io(error)))
            if error.to_string().contains("injected shutdown capability creation failure")
    ));

    let error = peer.recv_app().unwrap_err();
    assert!(matches!(error, ChannelError::Io(_)));
}

#[derive(Debug, Default)]
struct IoTrace {
    bytes: Vec<u8>,
    writes: usize,
    flushes: usize,
    shutdowns: usize,
}

#[derive(Debug)]
pub(super) struct WriteFault {
    limit: usize,
    kind: io::ErrorKind,
    flush_failure: bool,
    shutdown_failure: bool,
    trace: Arc<Mutex<IoTrace>>,
}

impl WriteFault {
    fn new(limit: usize, kind: io::ErrorKind, flush_failure: bool, shutdown_failure: bool) -> Self {
        Self {
            limit,
            kind,
            flush_failure,
            shutdown_failure,
            trace: Arc::new(Mutex::new(IoTrace::default())),
        }
    }

    pub(super) fn writer<'a>(&'a mut self, stream: &'a mut TcpStream) -> FaultWriter<'a> {
        FaultWriter {
            fault: self,
            stream,
        }
    }

    pub(super) fn before_shutdown(&self) -> io::Result<()> {
        self.trace.lock().unwrap().shutdowns += 1;
        if self.shutdown_failure {
            return Err(io::Error::other("injected shutdown failure"));
        }
        Ok(())
    }
}

pub(super) struct FaultWriter<'a> {
    fault: &'a mut WriteFault,
    stream: &'a mut TcpStream,
}

impl Write for FaultWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut trace = self.fault.trace.lock().unwrap();
        trace.writes += 1;
        let remaining = self.fault.limit.saturating_sub(trace.bytes.len());
        if remaining == 0 {
            return if self.fault.kind == io::ErrorKind::WriteZero {
                Ok(0)
            } else {
                Err(io::Error::new(self.fault.kind, "injected write failure"))
            };
        }
        let n = self.stream.write(&buf[..buf.len().min(remaining)])?;
        trace.bytes.extend_from_slice(&buf[..n]);
        Ok(n)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.fault.trace.lock().unwrap().flushes += 1;
        if self.fault.flush_failure {
            return Err(io::Error::new(self.fault.kind, "injected flush failure"));
        }
        self.stream.flush()
    }
}

fn assert_invalidated(result: Result<(), ChannelError>) {
    assert!(matches!(
        result,
        Err(ChannelError::Net(NetError::Protocol(
            "secure channel session invalidated"
        )))
    ));
}

fn assert_once(trace: &CryptoTrace, server: bool) {
    let nonces = trace.nonces.lock().unwrap();
    assert_eq!(nonces.len(), 1, "failed command must never be re-encrypted");
    assert_eq!(nonces[0][0], if server { 2 } else { 1 });
    assert_eq!(&nonces[0][4..], &0u64.to_be_bytes());
}

#[test]
fn real_aead_full_send_receive_both_directions() {
    let (mut client, mut server, trace) = pair(true);
    for _ in 0..2 {
        client.send_app(b"client plaintext").unwrap();
        assert_eq!(server.recv_app().unwrap(), b"client plaintext");
        server.send_app(b"server plaintext").unwrap();
        assert_eq!(client.recv_app().unwrap(), b"server plaintext");
    }
    assert!(client.is_established() && server.is_established());
    assert_eq!(trace.opens.load(Ordering::SeqCst), 4);
    let nonces = trace.nonces.lock().unwrap();
    assert_eq!(nonces.len(), 4);
    for (index, nonce) in nonces.iter().enumerate() {
        assert_eq!(nonce[0], if index % 2 == 0 { 1 } else { 2 });
        assert_eq!(&nonce[4..], &(index as u64 / 2).to_be_bytes());
    }
}

#[test]
fn sync_zero_partial_flush_and_shutdown_failures_both_directions() {
    for server_side in [false, true] {
        for (limit, kind, flush, shutdown_failure) in [
            (0, io::ErrorKind::WouldBlock, false, false),
            (7, io::ErrorKind::WouldBlock, false, false),
            (7, io::ErrorKind::BrokenPipe, false, false),
            (0, io::ErrorKind::WriteZero, false, false),
            (usize::MAX, io::ErrorKind::TimedOut, true, false),
            (usize::MAX, io::ErrorKind::Other, true, false),
            (7, io::ErrorKind::WouldBlock, false, true),
        ] {
            let (client, server, crypto) = pair(false);
            let (mut sender, mut peer) = if server_side {
                (server, client)
            } else {
                (client, server)
            };
            let fault = WriteFault::new(limit, kind, flush, shutdown_failure);
            let io_trace = Arc::clone(&fault.trace);
            sender.write_fault = Some(fault);
            let error = sender.send_app(b"uncertain delivery").unwrap_err();
            assert!(matches!(error, ChannelError::Io(ref e) if e.kind() == kind));
            assert!(!sender.is_established());
            assert_invalidated(sender.send_app(b"must not send"));
            assert_invalidated(sender.recv_app().map(|_| ()));
            assert_once(&crypto, server_side);
            let trace = io_trace.lock().unwrap();
            assert_eq!(trace.shutdowns, 1);
            assert_eq!(trace.flushes, usize::from(flush));
            if flush {
                let frame = TransportFrame::decode(&trace.bytes).unwrap();
                assert_eq!(frame.ciphertext.len(), b"uncertain delivery".len() + 16);
                // All ciphertext reached the peer, yet the send still failed.
                assert_eq!(peer.recv_app().unwrap(), b"uncertain delivery");
            } else {
                assert_eq!(trace.bytes.len(), limit);
                assert_eq!(trace.writes, if limit == 0 { 1 } else { 2 });
                if shutdown_failure {
                    // Shutdown was refused by the seam: the socket still works,
                    // but the local application receive must not reach AEAD.
                    peer.send_app(b"live socket, invalid session").unwrap();
                    assert_invalidated(sender.recv_app().map(|_| ()));
                    assert_eq!(crypto.opens.load(Ordering::SeqCst), 0);
                } else {
                    let error = peer.recv_app().unwrap_err();
                    if limit == 0 {
                        assert!(
                            matches!(error, ChannelError::Io(ref e) if e.kind() == io::ErrorKind::UnexpectedEof)
                        );
                    } else {
                        assert!(matches!(error, ChannelError::Io(ref e)
                            if e.kind() == io::ErrorKind::InvalidData
                                && e.get_ref().unwrap().downcast_ref::<PartialFrameError>()
                                    .is_some_and(|detail| detail.consumed == limit
                                        && detail.cause.kind() == io::ErrorKind::UnexpectedEof)));
                        assert!(!peer.is_established());
                    }
                }
            }
            assert!(SecureChannelAsync::try_new(sender).is_err());
        }
    }
}

#[test]
fn encryption_error_also_latches_before_any_write() {
    let (mut client, _server, crypto) = pair(false);
    crypto.fail_seal.store(true, Ordering::SeqCst);
    let fault = WriteFault::new(0, io::ErrorKind::WouldBlock, false, true);
    let io_trace = Arc::clone(&fault.trace);
    client.write_fault = Some(fault);
    assert!(matches!(
        client.send_app(b"seal fails"),
        Err(ChannelError::Net(NetError::Aead(_)))
    ));
    assert_invalidated(client.send_app(b"no second seal"));
    assert_invalidated(client.recv_app().map(|_| ()));
    assert_once(&crypto, false);
    let trace = io_trace.lock().unwrap();
    assert_eq!(trace.writes, 0);
    assert_eq!(trace.shutdowns, 1);
}

#[test]
fn production_workers_propagate_error_drop_queued_send_and_terminate_reader() {
    for server_side in [false, true] {
        for (limit, kind, flush) in [
            (0, io::ErrorKind::WouldBlock, false),
            (7, io::ErrorKind::WouldBlock, false),
            (7, io::ErrorKind::BrokenPipe, false),
            (usize::MAX, io::ErrorKind::TimedOut, true),
        ] {
            let (client, server, crypto) = pair(false);
            let (mut sender, _peer) = if server_side {
                (server, client)
            } else {
                (client, server)
            };
            let fault = WriteFault::new(limit, kind, flush, true);
            let io_trace = Arc::clone(&fault.trace);
            sender.write_fault = Some(fault);
            let shared = Arc::new(Mutex::new(sender));
            let (tx, rx) = tokio::sync::mpsc::channel(2);
            let (first_tx, first_rx) = tokio::sync::oneshot::channel();
            let (second_tx, second_rx) = tokio::sync::oneshot::channel();
            tx.blocking_send(WriteCommand::Send {
                data: b"first".to_vec(),
                response: first_tx,
            })
            .unwrap();
            tx.blocking_send(WriteCommand::Send {
                data: b"queued".to_vec(),
                response: second_tx,
            })
            .unwrap();
            // Execute the actual worker, not a model of its retry policy.
            SecureChannelAsync::writer_worker(Arc::clone(&shared), rx);
            assert!(
                matches!(first_rx.blocking_recv().unwrap(), Err(ChannelError::Io(ref e)) if e.kind() == kind)
            );
            assert!(second_rx.blocking_recv().is_err());
            assert!(tx.is_closed());
            let (read_tx, mut read_rx) = tokio::sync::mpsc::channel(2);
            SecureChannelAsync::reader_worker(Arc::clone(&shared), read_tx);
            assert_invalidated(read_rx.blocking_recv().unwrap().map(|_| ()));
            assert!(read_rx.blocking_recv().is_none());
            assert_invalidated(shared.lock().unwrap().send_app(b"shared sync"));
            assert_once(&crypto, server_side);
            assert_eq!(io_trace.lock().unwrap().shutdowns, 1);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn async_clones_and_independent_shared_workers_refuse_failed_session() {
    for server_side in [false, true] {
        let (client, server, crypto) = pair(true);
        let (mut sender, _peer) = if server_side {
            (server, client)
        } else {
            (client, server)
        };
        sender.write_fault = Some(WriteFault::new(7, io::ErrorKind::WouldBlock, false, false));
        let shared = Arc::new(Mutex::new(sender));
        let first = SecureChannelAsync::from_shared(Arc::clone(&shared));
        let cloned = first.clone();
        let independent = SecureChannelAsync::from_shared(Arc::clone(&shared));
        let result = tokio::time::timeout(Duration::from_secs(5), first.send(b"uncertain"))
            .await
            .unwrap();
        assert!(
            matches!(result, Err(AsyncChannelError::Channel(ChannelError::Io(ref e))) if e.kind() == io::ErrorKind::WouldBlock)
        );
        let late = SecureChannelAsync::from_shared(Arc::clone(&shared));
        for handle in [&first, &cloned, &independent, &late] {
            assert!(!handle.is_established());
            assert!(matches!(
                handle.send(b"refused").await,
                Err(AsyncChannelError::Channel(ChannelError::Net(_)))
            ));
            assert!(matches!(
                handle.recv().await,
                Err(AsyncChannelError::Channel(ChannelError::Net(_)))
            ));
        }
        let mut sender = shared.lock().unwrap();
        assert_invalidated(sender.send_app(b"sync refused"));
        assert_invalidated(sender.recv_app().map(|_| ()));
        assert_once(&crypto, server_side);
        drop(sender);
        drop((first, cloned, independent, late));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn owned_async_worker_returns_original_error_and_clone_refuses() {
    let (mut client, _server, crypto) = pair(false);
    client.write_fault = Some(WriteFault::new(0, io::ErrorKind::WouldBlock, false, false));
    let channel = SecureChannelAsync::try_new(client).unwrap();
    let cloned = channel.clone();
    let result = tokio::time::timeout(Duration::from_secs(5), channel.send(b"once"))
        .await
        .unwrap();
    assert!(
        matches!(result, Err(AsyncChannelError::Channel(ChannelError::Io(ref e))) if e.kind() == io::ErrorKind::WouldBlock)
    );
    assert!(!cloned.is_established());
    assert!(cloned.send(b"no retry").await.is_err());
    assert!(cloned.recv().await.is_err());
    assert_once(&crypto, false);
}

#[tokio::test]
async fn queued_plaintext_is_not_released_after_invalidation() {
    let (mut client, mut server, _) = pair(false);
    server.send_app(b"already queued").unwrap();
    let plaintext = client.recv_app().unwrap();
    let (write_tx, _write_rx) = tokio::sync::mpsc::channel(1);
    let (read_tx, read_rx) = tokio::sync::mpsc::channel(1);
    read_tx.send(Ok(plaintext)).await.unwrap();
    let channel = SecureChannelAsync {
        invalidated: Arc::clone(&client.invalidated),
        shutdown_stream: None,
        shutdown_complete: Arc::new(AtomicBool::new(false)),
        fail_shutdown: Arc::new(AtomicBool::new(false)),
        worker_tasks: Arc::new(tokio::sync::Mutex::new(WorkerTasks {
            reader: None,
            writer: None,
            completion: None,
        })),
        write_tx,
        read_rx: Arc::new(tokio::sync::Mutex::new(read_rx)),
    };
    let read_guard = channel.read_rx.lock().await;
    let mut pending_recv = std::pin::pin!(channel.recv());
    let mut context = std::task::Context::from_waker(std::task::Waker::noop());
    assert!(pending_recv.as_mut().poll(&mut context).is_pending());
    client.write_fault = Some(WriteFault::new(0, io::ErrorKind::WouldBlock, false, true));
    assert!(client.send_app(b"fail").is_err());
    drop(read_guard);
    assert!(matches!(
        pending_recv.await,
        Err(AsyncChannelError::Channel(ChannelError::Net(_)))
    ));
    assert!(matches!(
        channel.recv().await,
        Err(AsyncChannelError::Channel(ChannelError::Net(_)))
    ));
}
