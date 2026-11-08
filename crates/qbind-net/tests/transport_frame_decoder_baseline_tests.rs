use qbind_net::{NetError, TransportFrame};

fn header(msg_type: u8, declared_len: u32) -> [u8; 5] {
    let len = declared_len.to_be_bytes();
    [msg_type, len[0], len[1], len[2], len[3]]
}

#[test]
fn short_headers_return_the_existing_error() {
    for len in 0..5 {
        assert!(matches!(
            TransportFrame::decode(&[0x41; 5][..len]),
            Err(NetError::Protocol("transport frame too short"))
        ));
    }
}

#[test]
fn truncated_payload_returns_the_existing_error() {
    let mut bytes = header(0x41, 3).to_vec();
    bytes.extend_from_slice(&[0xAA, 0xBB]);

    assert!(matches!(
        TransportFrame::decode(&bytes),
        Err(NetError::Protocol("transport frame payload truncated"))
    ));
}

#[test]
fn valid_frame_round_trips_through_the_public_decoder() {
    let expected = TransportFrame {
        msg_type: 0x41,
        ciphertext: vec![0xAA, 0xBB, 0xCC],
    };

    let encoded = expected.encode().expect("encoding should succeed");
    let decoded = TransportFrame::decode(&encoded).expect("decoding should succeed");

    assert_eq!(decoded, expected);
}

#[test]
fn trailing_bytes_after_declared_payload_are_ignored() {
    let mut bytes = header(0x41, 2).to_vec();
    bytes.extend_from_slice(&[0xAA, 0xBB, 0xCC, 0xDD]);

    let decoded = TransportFrame::decode(&bytes).expect("decoding should succeed");

    assert_eq!(decoded.msg_type, 0x41);
    assert_eq!(decoded.ciphertext, [0xAA, 0xBB]);
}

#[test]
fn header_only_boundary_lengths_return_truncation_when_endpoint_is_representable() {
    let mut lengths = vec![0, u32::MAX - 5];

    #[cfg(target_pointer_width = "64")]
    lengths.extend([u32::MAX - 4, u32::MAX]);

    for declared_len in lengths {
        let bytes = header(0x41, declared_len);
        let result = TransportFrame::decode(&bytes);

        if declared_len == 0 {
            let decoded = result.expect("zero-length payload should be valid");
            assert_eq!(decoded.msg_type, 0x41);
            assert!(decoded.ciphertext.is_empty());
        } else {
            assert!(matches!(
                result,
                Err(NetError::Protocol("transport frame payload truncated"))
            ));
        }
    }
}

#[cfg(target_pointer_width = "32")]
#[test]
fn unrepresentable_payload_endpoints_return_exact_errors_without_panicking() {
    let representable_endpoint = header(0x41, u32::MAX - 5);
    assert!(matches!(
        TransportFrame::decode(&representable_endpoint),
        Err(NetError::Protocol("transport frame payload truncated"))
    ));

    for declared_len in [u32::MAX - 4, u32::MAX] {
        let bytes = header(0x41, declared_len);
        assert!(matches!(
            TransportFrame::decode(&bytes),
            Err(NetError::Protocol(
                "transport frame payload length overflow"
            ))
        ));
    }
}
