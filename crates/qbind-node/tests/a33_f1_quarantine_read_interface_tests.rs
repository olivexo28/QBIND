use qbind_node::pqc_reset_quarantine::{
    classify_for_reset, DecodeError, DecodedRecord, ObservedState, QuarantineReader,
    QuarantinedState, ReadError, RecordDecoder, ResetRefusal, StoreIdentity,
};

struct FakeReader(Result<Option<Vec<u8>>, ReadError>);

impl QuarantineReader for FakeReader {
    fn read_record(&mut self, _max_bytes: usize) -> Result<Option<Vec<u8>>, ReadError> {
        self.0.clone()
    }
}

struct FakeDecoder(Result<DecodedRecord, DecodeError>);

impl RecordDecoder for FakeDecoder {
    fn decode(&self, _bytes: &[u8]) -> Result<DecodedRecord, DecodeError> {
        self.0.clone()
    }
}

fn expected_identity() -> StoreIdentity {
    StoreIdentity {
        store_id: "synthetic-store".to_owned(),
        chain_id: "synthetic-chain".to_owned(),
    }
}

fn decoded(state: ObservedState) -> DecodedRecord {
    DecodedRecord {
        identity: expected_identity(),
        state,
    }
}

fn classify(reader: FakeReader, decoder: FakeDecoder) -> Result<(), ResetRefusal> {
    let mut reader = reader;
    classify_for_reset(&expected_identity(), 16, &mut reader, &decoder)
}

#[test]
fn supported_quarantined_states_refuse_reset() {
    for (state, expected) in [
        (
            QuarantinedState::Applying,
            ResetRefusal::Quarantined(QuarantinedState::Applying),
        ),
        (
            QuarantinedState::RecordedOutcome,
            ResetRefusal::Quarantined(QuarantinedState::RecordedOutcome),
        ),
    ] {
        assert_eq!(
            classify(
                FakeReader(Ok(Some(vec![1]))),
                FakeDecoder(Ok(decoded(ObservedState::Quarantined(state)))),
            ),
            Err(expected)
        );
    }
}

#[test]
fn absence_and_clean_looking_observations_do_not_authorize_reset() {
    assert_eq!(
        classify(
            FakeReader(Ok(None)),
            FakeDecoder(Ok(decoded(ObservedState::CleanLooking))),
        ),
        Err(ResetRefusal::Absent)
    );
    assert_eq!(
        classify(
            FakeReader(Ok(Some(vec![1]))),
            FakeDecoder(Ok(decoded(ObservedState::CleanLooking))),
        ),
        Err(ResetRefusal::CleanLookingRequiresSeparateAuthority)
    );
}

#[test]
fn malformed_unsupported_and_decoder_uncertainty_refuse_reset() {
    for (error, expected) in [
        (
            DecodeError::MalformedOrCorrupt,
            ResetRefusal::MalformedOrCorrupt,
        ),
        (
            DecodeError::UnsupportedVersion { version: 99 },
            ResetRefusal::UnsupportedVersion { version: 99 },
        ),
        (DecodeError::Uncertain, ResetRefusal::Uncertain),
    ] {
        assert_eq!(
            classify(FakeReader(Ok(Some(vec![1]))), FakeDecoder(Err(error)),),
            Err(expected)
        );
    }
}

#[test]
fn foreign_store_or_chain_identity_refuses_reset() {
    for identity in [
        StoreIdentity {
            store_id: "other-store".to_owned(),
            chain_id: "synthetic-chain".to_owned(),
        },
        StoreIdentity {
            store_id: "synthetic-store".to_owned(),
            chain_id: "other-chain".to_owned(),
        },
    ] {
        assert_eq!(
            classify(
                FakeReader(Ok(Some(vec![1]))),
                FakeDecoder(Ok(DecodedRecord {
                    identity,
                    state: ObservedState::CleanLooking,
                })),
            ),
            Err(ResetRefusal::ForeignOrMismatchedIdentity)
        );
    }
}

#[test]
fn unavailable_oversized_partial_and_uncertain_reads_refuse_reset() {
    for (read, expected) in [
        (Err(ReadError::Unavailable), ResetRefusal::Unavailable),
        (
            Err(ReadError::Oversized { limit: 16 }),
            ResetRefusal::Oversized { limit: 16 },
        ),
        (
            Err(ReadError::ReadFailed {
                bytes_read: 3,
                kind: std::io::ErrorKind::UnexpectedEof,
            }),
            ResetRefusal::ReadFailure {
                bytes_read: 3,
                kind: std::io::ErrorKind::UnexpectedEof,
            },
        ),
        (Err(ReadError::Uncertain), ResetRefusal::Uncertain),
    ] {
        assert_eq!(
            classify(
                FakeReader(read),
                FakeDecoder(Ok(decoded(ObservedState::CleanLooking)))
            ),
            Err(expected)
        );
    }
    assert_eq!(
        classify(
            FakeReader(Ok(Some(vec![0; 17]))),
            FakeDecoder(Ok(decoded(ObservedState::CleanLooking))),
        ),
        Err(ResetRefusal::Oversized { limit: 16 })
    );
}

#[test]
fn invalid_identity_or_limit_refuses_before_reading() {
    let mut reader = FakeReader(Ok(None));
    let decoder = FakeDecoder(Ok(decoded(ObservedState::CleanLooking)));
    let mut invalid_identity = expected_identity();
    invalid_identity.store_id.clear();
    assert_eq!(
        classify_for_reset(&invalid_identity, 16, &mut reader, &decoder),
        Err(ResetRefusal::InvalidExpectedIdentity)
    );
    assert_eq!(
        classify_for_reset(&expected_identity(), 0, &mut reader, &decoder),
        Err(ResetRefusal::InvalidReadLimit)
    );
}
