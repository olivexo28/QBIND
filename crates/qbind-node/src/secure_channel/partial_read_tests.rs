//! Controlled reads on real loopback KEMTLS/AEAD channels. Certificate
//! verification is dummy, as in the retained encrypted-write fixture.
use super::encrypted_write_tests::pair;
use super::*;
use std::io::Cursor;

#[derive(Debug, Default)]
struct ReadTrace {
    bytes: usize,
    reads: usize,
    shutdowns: usize,
}

#[derive(Debug)]
pub(super) struct ReadFault {
    remaining: Option<usize>,
    kind: io::ErrorKind,
    interrupted: bool,
    shutdown_failure: bool,
    trace: Arc<Mutex<ReadTrace>>,
}

impl ReadFault {
    fn new(limit: usize, kind: io::ErrorKind, shutdown_failure: bool) -> Self {
        Self {
            remaining: Some(limit),
            kind,
            interrupted: false,
            shutdown_failure,
            trace: Arc::new(Mutex::new(ReadTrace::default())),
        }
    }

    pub(super) fn reader<'a>(&'a mut self, stream: &'a mut TcpStream) -> FaultReader<'a> {
        FaultReader {
            fault: self,
            stream,
        }
    }

    pub(super) fn before_shutdown(&self) -> io::Result<()> {
        self.trace.lock().unwrap().shutdowns += 1;
        if self.shutdown_failure {
            return Err(io::Error::other("injected receive shutdown failure"));
        }
        Ok(())
    }
}

pub(super) struct FaultReader<'a> {
    fault: &'a mut ReadFault,
    stream: &'a mut TcpStream,
}

impl Read for FaultReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.fault.trace.lock().unwrap().reads += 1;
        if self.fault.interrupted {
            self.fault.interrupted = false;
            return Err(io::Error::from(io::ErrorKind::Interrupted));
        }
        if self.fault.remaining == Some(0) {
            self.fault.remaining = None;
            return if self.fault.kind == io::ErrorKind::UnexpectedEof {
                Ok(0)
            } else {
                Err(io::Error::new(self.fault.kind, "injected receive failure"))
            };
        }
        let len = buf.len().min(self.fault.remaining.unwrap_or(usize::MAX));
        let n = self.stream.read(&mut buf[..len])?;
        if let Some(remaining) = &mut self.fault.remaining {
            *remaining -= n;
        }
        self.fault.trace.lock().unwrap().bytes += n;
        Ok(n)
    }

    fn read_exact(&mut self, _: &mut [u8]) -> io::Result<()> {
        panic!("counting adapter must not delegate read_exact to the underlying reader")
    }
}

fn assert_refused(channel: &mut SecureChannel) {
    assert!(!channel.is_established());
    for result in [
        channel.send_app(b"must not encrypt"),
        channel.recv_app().map(|_| ()),
    ] {
        assert!(matches!(
            result,
            Err(ChannelError::Net(NetError::Protocol(
                "secure channel session invalidated"
            )))
        ));
    }
}

fn assert_partial(error: ChannelError, consumed: usize, kind: io::ErrorKind) {
    assert!(!AsyncChannelError::Channel(match error {
        ChannelError::Io(error) => {
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            let detail = error
                .get_ref()
                .unwrap()
                .downcast_ref::<PartialFrameError>()
                .unwrap();
            assert_eq!(detail.consumed, consumed);
            assert_eq!(detail.cause.kind(), kind);
            assert!(std::error::Error::source(detail).is_some());
            ChannelError::Io(error)
        }
        other => panic!("unexpected error: {other:?}"),
    })
    .is_timeout());
}

#[test]
fn idle_timeouts_retry_same_session_with_real_aead_and_interrupted() {
    for server_side in [false, true] {
        for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
            let (client, server, crypto) = pair(false);
            let (mut receiver, mut peer) = if server_side {
                (server, client)
            } else {
                (client, server)
            };
            receiver.read_fault = Some(ReadFault::new(0, kind, false));
            let error = receiver.recv_app().unwrap_err();
            assert!(matches!(error, ChannelError::Io(ref e) if e.kind() == kind));
            assert!(AsyncChannelError::Channel(error).is_timeout());
            assert!(receiver.is_established());
            assert_eq!(crypto.opens.load(Ordering::SeqCst), 0);
            assert_eq!(
                receiver
                    .read_fault
                    .as_ref()
                    .unwrap()
                    .trace
                    .lock()
                    .unwrap()
                    .shutdowns,
                0
            );
            receiver.read_fault.as_mut().unwrap().interrupted = true;
            for _ in 0..2 {
                peer.send_app(b"complete after idle").unwrap();
                assert_eq!(receiver.recv_app().unwrap(), b"complete after idle");
                receiver.send_app(b"reverse").unwrap();
                assert_eq!(peer.recv_app().unwrap(), b"reverse");
            }
            assert_eq!(crypto.opens.load(Ordering::SeqCst), 4);
        }
    }
}

#[test]
fn partial_header_header_only_and_body_failures_latch_both_directions() {
    for server_side in [false, true] {
        for kind in [
            io::ErrorKind::WouldBlock,
            io::ErrorKind::TimedOut,
            io::ErrorKind::UnexpectedEof,
            io::ErrorKind::ConnectionReset,
        ] {
            for consumed in [1, 4, 5, 7] {
                for shutdown_failure in [false, true] {
                    let (client, server, crypto) = pair(true);
                    let (mut receiver, mut peer) = if server_side {
                        (server, client)
                    } else {
                        (client, server)
                    };
                    peer.send_app(b"partial frame must never decrypt").unwrap();
                    let fault = ReadFault::new(consumed, kind, shutdown_failure);
                    let trace = Arc::clone(&fault.trace);
                    receiver.read_fault = Some(fault);
                    assert_partial(receiver.recv_app().unwrap_err(), consumed, kind);
                    assert_refused(&mut receiver);
                    assert_eq!(crypto.opens.load(Ordering::SeqCst), 0);
                    assert_eq!(crypto.nonces.lock().unwrap().len(), 1);
                    let before = {
                        let trace = trace.lock().unwrap();
                        assert_eq!(trace.bytes, consumed);
                        assert_eq!(trace.shutdowns, 1);
                        trace.reads
                    };
                    if shutdown_failure {
                        peer.send_app(b"socket still live").unwrap();
                        assert_refused(&mut receiver);
                        assert_eq!(trace.lock().unwrap().reads, before);
                        assert_eq!(crypto.opens.load(Ordering::SeqCst), 0);
                    } else {
                        assert!(
                            matches!(peer.recv_app(), Err(ChannelError::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof)
                        );
                    }
                    assert!(SecureChannelAsync::try_new(receiver).is_err());
                }
            }
        }
    }
}

#[test]
fn actual_reader_retries_idle_then_reports_partial_error_and_terminates() {
    for kind in [io::ErrorKind::WouldBlock, io::ErrorKind::TimedOut] {
        for consumed in [0, 2, 5, 7] {
            let (mut receiver, mut peer, crypto) = pair(false);
            peer.send_app(b"worker control").unwrap();
            if consumed == 0 {
                peer.stream.shutdown(Shutdown::Write).unwrap();
            }
            receiver.read_fault = Some(ReadFault::new(consumed, kind, true));
            let shared = Arc::new(Mutex::new(receiver));
            let (tx, mut rx) = tokio::sync::mpsc::channel(3);
            let (done_tx, done_rx) = std::sync::mpsc::channel();
            let worker_channel = Arc::clone(&shared);
            let worker = std::thread::spawn(move || {
                SecureChannelAsync::reader_worker(worker_channel, tx);
                done_tx.send(()).unwrap();
            });
            done_rx.recv_timeout(Duration::from_secs(5)).unwrap();
            worker.join().unwrap();
            if consumed == 0 {
                assert_eq!(rx.blocking_recv().unwrap().unwrap(), b"worker control");
                assert!(
                    matches!(rx.blocking_recv().unwrap(), Err(ChannelError::Io(ref e)) if e.kind() == io::ErrorKind::UnexpectedEof)
                );
                assert_eq!(crypto.opens.load(Ordering::SeqCst), 1);
            } else {
                assert_partial(rx.blocking_recv().unwrap().unwrap_err(), consumed, kind);
                assert_refused(&mut shared.lock().unwrap());
                assert_eq!(crypto.opens.load(Ordering::SeqCst), 0);
            }
            assert!(rx.blocking_recv().is_none());
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn spawned_owned_cloned_and_independent_shared_handles_refuse_partial_reads() {
    for shutdown_failure in [false, true] {
        for owned in [false, true] {
            let (mut receiver, mut peer, crypto) = pair(false);
            peer.send_app(b"partial").unwrap();
            receiver.read_fault =
                Some(ReadFault::new(5, io::ErrorKind::TimedOut, shutdown_failure));
            let (first, independent, shared) = if owned {
                (SecureChannelAsync::try_new(receiver).unwrap(), None, None)
            } else {
                let shared = Arc::new(Mutex::new(receiver));
                (
                    SecureChannelAsync::from_shared(shared.clone()),
                    Some(SecureChannelAsync::from_shared(shared.clone())),
                    Some(shared),
                )
            };
            let cloned = first.clone();
            let result = tokio::time::timeout(Duration::from_secs(5), first.recv())
                .await
                .unwrap();
            assert!(result.is_err());
            assert!(!result.unwrap_err().is_timeout());
            for handle in [&first, &cloned].into_iter().chain(independent.as_ref()) {
                assert!(!handle.is_established());
                assert!(handle.send(b"refused").await.is_err());
                assert!(handle.recv().await.is_err());
            }
            if !owned {
                let shared = shared.as_ref().unwrap();
                let late = SecureChannelAsync::from_shared(shared.clone());
                assert!(late.send(b"late refused").await.is_err());
                assert!(late.recv().await.is_err());
                assert_refused(&mut shared.lock().unwrap());
            }
            assert_eq!(crypto.opens.load(Ordering::SeqCst), 0);
        }
    }
}

#[test]
fn counted_framing_keeps_limit_and_does_not_read_past_frame() {
    use qbind_net::framed_io::MAX_TRANSPORT_CIPHERTEXT;
    let frame = TransportFrame {
        msg_type: 1,
        ciphertext: vec![0x42; MAX_TRANSPORT_CIPHERTEXT],
    };
    let mut bytes = frame.encode().unwrap();
    bytes.extend_from_slice(b"sentinel");
    let mut cursor = Cursor::new(bytes);
    let (result, consumed) = read_counted_frame(&mut cursor);
    assert_eq!(result.unwrap(), frame);
    assert_eq!(consumed, MAX_TRANSPORT_CIPHERTEXT + 5);
    assert_eq!(cursor.position(), consumed as u64);

    let mut header = vec![1];
    header.extend_from_slice(&((MAX_TRANSPORT_CIPHERTEXT + 1) as u32).to_be_bytes());
    header.extend_from_slice(b"unread");
    let mut cursor = Cursor::new(header);
    let (result, consumed) = read_counted_frame(&mut cursor);
    assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    assert_eq!(consumed, 5);
    assert_eq!(cursor.position(), 5);
}

#[test]
fn real_aead_full_ciphertext_at_limit() {
    use qbind_net::framed_io::MAX_TRANSPORT_CIPHERTEXT;
    for server_side in [false, true] {
        let (client, server, crypto) = pair(false);
        let (mut sender, mut receiver) = if server_side {
            (server, client)
        } else {
            (client, server)
        };
        let plaintext = vec![0x24; MAX_TRANSPORT_CIPHERTEXT - 16];
        let sent = plaintext.clone();
        let worker = std::thread::spawn(move || sender.send_app(&sent).unwrap());
        assert_eq!(receiver.recv_app().unwrap(), plaintext);
        worker.join().unwrap();
        assert_eq!(crypto.opens.load(Ordering::SeqCst), 1);
    }
}
