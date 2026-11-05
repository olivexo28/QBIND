//! Non-wired read/classification boundary for a future reset-quarantine
//! backend. This module has no persistent format, filesystem adapter, allow
//! decision, startup gate, or reset/CLI caller.
//!
//! The reader must bind records to an opaque store identity and chain
//! identity. Their derivation and encoding remain unselected. A matching
//! local identity does not establish freshness, anti-rollback, reconciliation,
//! or exclusive signer ownership.
//!
//! Backends must not create, repair, truncate, replace, or delete records
//! while reading. They remain responsible for durability, publication
//! ordering, initialization/migration, path identity, concurrent writers,
//! and failure-after-publication semantics. The trait and bounded-read
//! helper do not solve those obligations.

use std::io::{self, Read};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoreIdentity {
    pub store_id: String,
    pub chain_id: String,
}

impl StoreIdentity {
    fn is_well_formed(&self) -> bool {
        !self.store_id.trim().is_empty() && !self.chain_id.trim().is_empty()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QuarantinedState {
    Applying,
    RecordedOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedRecord {
    pub identity: StoreIdentity,
    pub state: ObservedState,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ObservedState {
    Quarantined(QuarantinedState),
    CleanLooking,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DecodeError {
    MalformedOrCorrupt,
    UnsupportedVersion { version: u64 },
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadError {
    Unavailable,
    Oversized {
        limit: usize,
    },
    ReadFailed {
        bytes_read: usize,
        kind: io::ErrorKind,
    },
    Uncertain,
    InvalidLimit,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResetRefusal {
    Quarantined(QuarantinedState),
    Absent,
    MalformedOrCorrupt,
    UnsupportedVersion {
        version: u64,
    },
    ForeignOrMismatchedIdentity,
    Unavailable,
    Oversized {
        limit: usize,
    },
    ReadFailure {
        bytes_read: usize,
        kind: io::ErrorKind,
    },
    Uncertain,
    CleanLookingRequiresSeparateAuthority,
    InvalidExpectedIdentity,
    InvalidReadLimit,
}

/// Read-only backend contract. Implementations must enforce `max_bytes` while
/// reading (for example via [`read_bounded`]); returned bytes are checked
/// against the limit again by the classifier. `None` means observed absence,
/// not permission to initialize or allow reset.
pub trait QuarantineReader {
    fn read_record(&mut self, max_bytes: usize) -> Result<Option<Vec<u8>>, ReadError>;
}

/// Format-specific decoding is deliberately supplied by a future backend;
/// this interface selects no wire or persistent format. A decoder must reject
/// truncated or otherwise incomplete records as malformed or uncertain.
pub trait RecordDecoder {
    fn decode(&self, bytes: &[u8]) -> Result<DecodedRecord, DecodeError>;
}

fn probe_limit(max_bytes: usize) -> Option<u64> {
    max_bytes
        .checked_add(1)
        .and_then(|value| u64::try_from(value).ok())
}

/// Classify one read for reset refusal only. The direct return type makes an
/// allow result unrepresentable; there is intentionally no production allow,
/// clear, or resume variant.
pub fn classify_for_reset<R: QuarantineReader, D: RecordDecoder>(
    expected: &StoreIdentity,
    max_bytes: usize,
    reader: &mut R,
    decoder: &D,
) -> ResetRefusal {
    if !expected.is_well_formed() {
        return ResetRefusal::InvalidExpectedIdentity;
    }
    if max_bytes == 0 || probe_limit(max_bytes).is_none() {
        return ResetRefusal::InvalidReadLimit;
    }

    let bytes = match reader.read_record(max_bytes) {
        Ok(Some(bytes)) if bytes.len() > max_bytes => {
            return ResetRefusal::Oversized { limit: max_bytes };
        }
        Ok(Some(bytes)) => bytes,
        Ok(None) => return ResetRefusal::Absent,
        Err(ReadError::Unavailable) => return ResetRefusal::Unavailable,
        Err(ReadError::Oversized { limit }) => return ResetRefusal::Oversized { limit },
        Err(ReadError::ReadFailed { bytes_read, kind }) => {
            return ResetRefusal::ReadFailure { bytes_read, kind };
        }
        Err(ReadError::Uncertain) => return ResetRefusal::Uncertain,
        Err(ReadError::InvalidLimit) => return ResetRefusal::InvalidReadLimit,
    };

    let record = match decoder.decode(&bytes) {
        Ok(record) => record,
        Err(DecodeError::MalformedOrCorrupt) => return ResetRefusal::MalformedOrCorrupt,
        Err(DecodeError::UnsupportedVersion { version }) => {
            return ResetRefusal::UnsupportedVersion { version };
        }
        Err(DecodeError::Uncertain) => return ResetRefusal::Uncertain,
    };
    if record.identity != *expected {
        return ResetRefusal::ForeignOrMismatchedIdentity;
    }
    match record.state {
        ObservedState::Quarantined(state) => ResetRefusal::Quarantined(state),
        ObservedState::CleanLooking => ResetRefusal::CleanLookingRequiresSeparateAuthority,
    }
}

/// Read no more than `max_bytes`, probing one additional byte to detect an
/// oversized record. Any I/O error, including after a partial read, remains
/// an error and cannot be interpreted as absence.
pub fn read_bounded<R: Read>(reader: &mut R, max_bytes: usize) -> Result<Vec<u8>, ReadError> {
    let read_limit = probe_limit(max_bytes)
        .filter(|_| max_bytes != 0)
        .ok_or(ReadError::InvalidLimit)?;
    let mut bytes = Vec::new();
    if let Err(error) = reader.take(read_limit).read_to_end(&mut bytes) {
        return Err(ReadError::ReadFailed {
            bytes_read: bytes.len(),
            kind: error.kind(),
        });
    }
    if bytes.len() > max_bytes {
        return Err(ReadError::Oversized { limit: max_bytes });
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingAfterPrefix {
        first: bool,
    }

    impl Read for FailingAfterPrefix {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            if self.first {
                self.first = false;
                buffer[0] = b'x';
                return Ok(1);
            }
            Err(io::Error::other("synthetic read failure"))
        }
    }

    #[test]
    fn bounded_read_detects_oversize_and_preserves_partial_failure() {
        assert_eq!(read_bounded(&mut &b""[..], 0), Err(ReadError::InvalidLimit));
        assert_eq!(
            read_bounded(&mut &b"1234"[..], 3),
            Err(ReadError::Oversized { limit: 3 })
        );
        assert_eq!(
            read_bounded(&mut FailingAfterPrefix { first: true }, 8),
            Err(ReadError::ReadFailed {
                bytes_read: 1,
                kind: io::ErrorKind::Other
            })
        );
    }
}
