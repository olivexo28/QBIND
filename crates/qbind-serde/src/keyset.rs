use crate::error::StateError;
use crate::io::{get_bytes, get_u16, get_u8, put_bytes, put_u16, put_u8, StateDecode, StateEncode};
use qbind_types::{KeysetAccount, KeysetEntry};

impl StateEncode for KeysetEntry {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.suite_id);
        put_u16(out, self.weight);
        put_bytes(out, &self.reserved0);
        // Use the stored pubkey_len field for encoding to maintain consistency.
        // Callers are responsible for ensuring pubkey_len matches pubkey_bytes.len().
        put_u16(out, self.pubkey_len);
        put_bytes(out, &self.pubkey_bytes);
    }
}

impl StateDecode for KeysetEntry {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let suite_id = get_u8(input)?;
        let weight = get_u16(input)?;
        let reserved0_bytes = get_bytes(input, 1)?;
        let mut reserved0 = [0u8; 1];
        reserved0.copy_from_slice(reserved0_bytes);
        let pubkey_len = get_u16(input)? as usize;
        let pubkey_bytes = get_bytes(input, pubkey_len)?.to_vec();

        Ok(KeysetEntry {
            suite_id,
            weight,
            reserved0,
            pubkey_len: pubkey_len as u16,
            pubkey_bytes,
        })
    }
}

impl StateEncode for KeysetAccount {
    fn encode_state(&self, out: &mut Vec<u8>) {
        put_u8(out, self.version);
        put_bytes(out, &self.reserved0);
        put_u16(out, self.threshold);
        // Use the stored entry_count field for encoding to maintain consistency.
        // Callers are responsible for ensuring entry_count matches entries.len().
        put_u16(out, self.entry_count);
        put_bytes(out, &self.reserved1);
        for entry in &self.entries {
            entry.encode_state(out);
        }
    }
}

impl StateDecode for KeysetAccount {
    fn decode_state(input: &mut &[u8]) -> Result<Self, StateError> {
        let version = get_u8(input)?;
        let reserved0_bytes = get_bytes(input, 3)?;
        let mut reserved0 = [0u8; 3];
        reserved0.copy_from_slice(reserved0_bytes);
        let threshold = get_u16(input)?;
        let entry_count = get_u16(input)? as usize;
        let reserved1_bytes = get_bytes(input, 4)?;
        let mut reserved1 = [0u8; 4];
        reserved1.copy_from_slice(reserved1_bytes);

        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(KeysetEntry::decode_state(input)?);
        }

        Ok(KeysetAccount {
            version,
            reserved0,
            threshold,
            entry_count: entry_count as u16,
            reserved1,
            entries,
        })
    }
}

/// Caller-selected framing budgets, not deployment or authorization policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredKeysetLimits {
    pub max_encoded_bytes: usize,
    pub max_entries: usize,
    pub max_key_bytes: usize,
    pub max_total_key_bytes: usize,
}

/// Fixed-size failures distinguish malformed framing from each resource limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StoredKeysetParseError {
    Malformed(StateError),
    EncodedBytesLimit,
    EntryCountLimit,
    PerKeyBytesLimit,
    AggregateKeyBytesLimit,
}

/// Completely framed stored state. Construction is private; keys remain borrowed.
///
/// This establishes no version/suite support, canonical key encoding, meaningful
/// threshold, distinct identities, signatures, ownership, or authorization.
#[derive(Clone, Copy, Debug)]
pub struct StoredKeysetView<'a> {
    input: &'a [u8],
    version: u8,
    reserved0: [u8; 3],
    threshold: u16,
    entry_count: u16,
    reserved1: [u8; 4],
}

impl<'a> StoredKeysetView<'a> {
    pub fn encoded_bytes(&self) -> &'a [u8] {
        self.input
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn reserved0(&self) -> [u8; 3] {
        self.reserved0
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn entry_count(&self) -> u16 {
        self.entry_count
    }

    pub fn reserved1(&self) -> [u8; 4] {
        self.reserved1
    }

    /// Each independent traversal is O(entry_count), with O(1) storage.
    pub fn entries(&self) -> StoredKeysetEntries<'a> {
        StoredKeysetEntries {
            remaining: &self.input[12..],
            count: self.entry_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StoredKeysetEntryView<'a> {
    pub suite_id: u8,
    pub weight: u16,
    pub reserved0: [u8; 1],
    pub pubkey_len: u16,
    pub pubkey_bytes: &'a [u8],
}

/// Forward-only traversal of already validated, immutable bytes.
#[derive(Clone, Debug)]
pub struct StoredKeysetEntries<'a> {
    remaining: &'a [u8],
    count: u16,
}

impl<'a> Iterator for StoredKeysetEntries<'a> {
    type Item = StoredKeysetEntryView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        // Private construction and immutable input guarantee both splits.
        let (prefix, rest) = self.remaining.split_at(6);
        let pubkey_len = u16::from_le_bytes([prefix[4], prefix[5]]);
        let (pubkey_bytes, rest) = rest.split_at(usize::from(pubkey_len));
        self.remaining = rest;
        self.count -= 1;
        Some(StoredKeysetEntryView {
            suite_id: prefix[0],
            weight: u16::from_le_bytes([prefix[1], prefix[2]]),
            reserved0: [prefix[3]],
            pubkey_len,
            pubkey_bytes,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = usize::from(self.count);
        (count, Some(count))
    }
}

impl ExactSizeIterator for StoredKeysetEntries<'_> {}
impl std::iter::FusedIterator for StoredKeysetEntries<'_> {}

/// Validate the complete stored-state slice before returning any view.
///
/// Admission checks encoded bytes before reading, count and checked minimum
/// size before looping, then per-key and checked aggregate lengths before each
/// body. Bounded slice splits avoid offset addition. No heap allocation or
/// variable-length copy occurs in parsing or traversal. Work is O(entry_count)
/// and controls are O(1); key bodies are borrowed, not scanned.
///
/// Limits bound admitted encoded lengths and parsing work, not input acquisition,
/// allocator overhead, physical memory, or arbitrary repeated caller traversals.
pub fn parse_stored_keyset(
    input: &[u8],
    limits: StoredKeysetLimits,
) -> Result<StoredKeysetView<'_>, StoredKeysetParseError> {
    use StoredKeysetParseError::*;
    if input.len() > limits.max_encoded_bytes {
        return Err(EncodedBytesLimit);
    }
    let mut remaining = input;
    let header = get_bytes(&mut remaining, 12).map_err(Malformed)?;
    let entry_count = u16::from_le_bytes([header[6], header[7]]);
    if usize::from(entry_count) > limits.max_entries {
        return Err(EntryCountLimit);
    }
    let minimum = usize::from(entry_count)
        .checked_mul(6)
        .and_then(|size| size.checked_add(12))
        .ok_or(Malformed(StateError::LengthOverflow))?;
    if input.len() < minimum {
        return Err(Malformed(StateError::UnexpectedEof));
    }
    let mut total_key_bytes = 0usize;
    for _ in 0..entry_count {
        let prefix = get_bytes(&mut remaining, 6).map_err(Malformed)?;
        let key_len = usize::from(u16::from_le_bytes([prefix[4], prefix[5]]));
        if key_len > limits.max_key_bytes {
            return Err(PerKeyBytesLimit);
        }
        total_key_bytes = total_key_bytes
            .checked_add(key_len)
            .ok_or(Malformed(StateError::LengthOverflow))?;
        if total_key_bytes > limits.max_total_key_bytes {
            return Err(AggregateKeyBytesLimit);
        }
        get_bytes(&mut remaining, key_len).map_err(Malformed)?;
    }
    if !remaining.is_empty() {
        return Err(Malformed(StateError::InvalidValue(
            "trailing stored keyset bytes",
        )));
    }
    Ok(StoredKeysetView {
        input,
        version: header[0],
        reserved0: [header[1], header[2], header[3]],
        threshold: u16::from_le_bytes([header[4], header[5]]),
        entry_count,
        reserved1: [header[8], header[9], header[10], header[11]],
    })
}

#[cfg(test)]
mod run422_bounded_keyset_parse {
    use super::*;

    fn fixture() -> Vec<u8> {
        // Independent bytes: 12-byte header, 6-byte prefixes, LE u16 fields.
        vec![
            0x91, 0x11, 0x12, 0x13, 0x34, 0x12, 2, 0, 0x21, 0x22, 0x23, 0x24, 0xa1, 0x78, 0x56,
            0x31, 3, 0, 0x41, 0x42, 0x43, 0xa2, 0xbc, 0x9a, 0x32, 2, 0, 0x51, 0x52,
        ]
    }

    fn exact() -> StoredKeysetLimits {
        StoredKeysetLimits {
            max_encoded_bytes: 29,
            max_entries: 2,
            max_key_bytes: 3,
            max_total_key_bytes: 5,
        }
    }

    fn permissive() -> StoredKeysetLimits {
        StoredKeysetLimits {
            max_encoded_bytes: usize::MAX,
            max_entries: usize::MAX,
            max_key_bytes: usize::MAX,
            max_total_key_bytes: usize::MAX,
        }
    }

    fn parse(
        input: &[u8],
        limits: StoredKeysetLimits,
    ) -> Result<StoredKeysetView<'_>, StoredKeysetParseError> {
        let before = input.to_vec();
        let result = parse_stored_keyset(input, limits);
        assert_eq!(input, before, "success and refusal must leave input intact");
        result
    }

    #[test]
    fn layout_borrowing_and_repeatable_traversal() {
        let bytes = fixture();
        let view = parse(&bytes, exact()).unwrap();
        assert_eq!(view.encoded_bytes(), bytes);
        assert_eq!(view.version(), 0x91);
        assert_eq!(view.reserved0(), [0x11, 0x12, 0x13]);
        assert_eq!(view.threshold(), 0x1234);
        assert_eq!(view.entry_count(), 2);
        assert_eq!(view.reserved1(), [0x21, 0x22, 0x23, 0x24]);
        let expected = [
            StoredKeysetEntryView {
                suite_id: 0xa1,
                weight: 0x5678,
                reserved0: [0x31],
                pubkey_len: 3,
                pubkey_bytes: &bytes[18..21],
            },
            StoredKeysetEntryView {
                suite_id: 0xa2,
                weight: 0x9abc,
                reserved0: [0x32],
                pubkey_len: 2,
                pubkey_bytes: &bytes[27..29],
            },
        ];
        assert_eq!(expected[0].pubkey_bytes, [0x41, 0x42, 0x43]);
        assert_eq!(expected[1].pubkey_bytes, [0x51, 0x52]);
        let mut first = view.entries();
        let mut second = view.entries();
        assert_eq!(first.len(), 2);
        for (index, expected) in expected.into_iter().enumerate() {
            let entry = first.next().unwrap();
            assert_eq!(entry, expected);
            assert_eq!(entry.pubkey_bytes.as_ptr(), expected.pubkey_bytes.as_ptr());
            assert_eq!(second.next(), Some(entry));
            assert_eq!(first.len(), 1 - index);
        }
        assert_eq!(first.next(), None);
        assert_eq!(first.next(), None);
        assert_eq!(second.next(), None);
        assert!(view.entries().eq(view.entries()));
    }

    #[test]
    fn encoder_owned_correspondence() {
        let owned = KeysetAccount {
            version: 7,
            reserved0: [1, 2, 3],
            threshold: 0x1234,
            entry_count: 2,
            reserved1: [4, 5, 6, 7],
            entries: vec![
                KeysetEntry {
                    suite_id: 8,
                    weight: 0x5678,
                    reserved0: [9],
                    pubkey_len: 3,
                    pubkey_bytes: vec![10, 11, 12],
                },
                KeysetEntry {
                    suite_id: 13,
                    weight: 0x9abc,
                    reserved0: [14],
                    pubkey_len: 2,
                    pubkey_bytes: vec![15, 16],
                },
            ],
        };
        let mut bytes = Vec::new();
        owned.encode_state(&mut bytes);
        let mut remaining = bytes.as_slice();
        let decoded = KeysetAccount::decode_state(&mut remaining).unwrap();
        assert!(remaining.is_empty());
        let view = parse(&bytes, exact()).unwrap();
        assert_eq!(view.version(), decoded.version);
        assert_eq!(view.reserved0(), decoded.reserved0);
        assert_eq!(view.threshold(), decoded.threshold);
        assert_eq!(view.entry_count(), decoded.entry_count);
        assert_eq!(view.reserved1(), decoded.reserved1);
        assert_eq!(view.entries().len(), decoded.entries.len());
        for (entry, decoded) in view.entries().zip(&decoded.entries) {
            assert_eq!(entry.suite_id, decoded.suite_id);
            assert_eq!(entry.weight, decoded.weight);
            assert_eq!(entry.reserved0, decoded.reserved0);
            assert_eq!(entry.pubkey_len, decoded.pubkey_len);
            assert_eq!(entry.pubkey_bytes, decoded.pubkey_bytes);
        }
    }

    #[test]
    fn exact_limits_and_independent_one_over_refusals() {
        use StoredKeysetParseError::*;
        let bytes = fixture();
        assert!(parse(&bytes, exact()).is_ok());
        let cases = [
            (
                StoredKeysetLimits {
                    max_encoded_bytes: 28,
                    ..exact()
                },
                EncodedBytesLimit,
            ),
            (
                StoredKeysetLimits {
                    max_entries: 1,
                    ..exact()
                },
                EntryCountLimit,
            ),
            (
                StoredKeysetLimits {
                    max_key_bytes: 2,
                    ..exact()
                },
                PerKeyBytesLimit,
            ),
            (
                StoredKeysetLimits {
                    max_total_key_bytes: 4,
                    ..exact()
                },
                AggregateKeyBytesLimit,
            ),
        ];
        for (limits, error) in cases {
            assert_eq!(parse(&bytes, limits).unwrap_err(), error);
            // Only the selected limit differs from the accepting exact budgets.
            assert!(parse(&bytes, exact()).is_ok());
        }
        assert_eq!(
            parse(
                &bytes,
                StoredKeysetLimits {
                    max_encoded_bytes: 0,
                    ..exact()
                }
            )
            .unwrap_err(),
            EncodedBytesLimit
        );
        assert!(parse(&bytes, permissive()).is_ok());
    }

    #[test]
    fn zero_entries_and_zero_length_keys() {
        let mut bytes = fixture()[..12].to_vec();
        bytes[6..8].copy_from_slice(&[0, 0]);
        let limits = StoredKeysetLimits {
            max_encoded_bytes: 12,
            max_entries: 0,
            max_key_bytes: 0,
            max_total_key_bytes: 0,
        };
        let view = parse(&bytes, limits).unwrap();
        assert_eq!(view.entry_count(), 0);
        assert_eq!(view.entries().next(), None);
        bytes[6] = 1;
        bytes.extend_from_slice(&[0xff, 0, 0, 0xfe, 0, 0]);
        let view = parse(
            &bytes,
            StoredKeysetLimits {
                max_encoded_bytes: 18,
                max_entries: 1,
                ..limits
            },
        )
        .unwrap();
        let entry = view.entries().next().unwrap();
        assert_eq!(entry.pubkey_len, 0);
        assert!(entry.pubkey_bytes.is_empty());
        assert_eq!(entry.reserved0, [0xfe]);
    }

    #[test]
    fn every_truncated_prefix() {
        let bytes = fixture();
        for end in 0..bytes.len() {
            assert_eq!(
                parse(&bytes[..end], exact()).unwrap_err(),
                StoredKeysetParseError::Malformed(StateError::UnexpectedEof),
                "truncated at {end}"
            );
        }
        assert!(parse(&bytes, exact()).is_ok());
    }

    #[test]
    fn malformed_counts_trailing_and_final_entries() {
        use StoredKeysetParseError::Malformed;
        let mut excessive = fixture();
        excessive[6..8].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            parse(&excessive, exact()).unwrap_err(),
            StoredKeysetParseError::EntryCountLimit
        );
        assert_eq!(
            parse(&excessive, permissive()).unwrap_err(),
            Malformed(StateError::UnexpectedEof)
        );
        for count in [0u16, 1] {
            let mut bytes = fixture();
            bytes[6..8].copy_from_slice(&count.to_le_bytes());
            assert_eq!(
                parse(&bytes, permissive()).unwrap_err(),
                Malformed(StateError::InvalidValue("trailing stored keyset bytes"))
            );
        }
        let mut trailing = fixture();
        trailing.push(0);
        assert_eq!(
            parse(&trailing, permissive()).unwrap_err(),
            Malformed(StateError::InvalidValue("trailing stored keyset bytes"))
        );
        let mut final_body = fixture();
        final_body[25..27].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            parse(&final_body, permissive()).unwrap_err(),
            Malformed(StateError::UnexpectedEof)
        );
        let final_prefix = &fixture()[..25];
        assert_eq!(
            parse(final_prefix, permissive()).unwrap_err(),
            Malformed(StateError::UnexpectedEof)
        );
    }

    #[test]
    fn admission_order_before_body_access() {
        use StoredKeysetParseError::*;
        assert_eq!(
            parse(
                &[0],
                StoredKeysetLimits {
                    max_encoded_bytes: 0,
                    ..permissive()
                }
            )
            .unwrap_err(),
            EncodedBytesLimit
        );
        let bytes = fixture();
        assert_eq!(
            parse(&bytes[..12], exact()).unwrap_err(),
            Malformed(StateError::UnexpectedEof)
        );
        assert_eq!(
            parse(
                &bytes[..12],
                StoredKeysetLimits {
                    max_entries: 1,
                    ..exact()
                }
            )
            .unwrap_err(),
            EntryCountLimit
        );
        assert_eq!(
            parse(
                &bytes[..28],
                StoredKeysetLimits {
                    max_total_key_bytes: 4,
                    ..exact()
                }
            )
            .unwrap_err(),
            AggregateKeyBytesLimit
        );
        assert_eq!(
            parse(
                &bytes[..28],
                StoredKeysetLimits {
                    max_key_bytes: 1,
                    ..exact()
                }
            )
            .unwrap_err(),
            PerKeyBytesLimit
        );
    }

    #[test]
    fn structural_success_is_not_authorization() {
        let mut bytes = vec![0xff, 1, 2, 3, 0, 0, 2, 0, 4, 5, 6, 7];
        for _ in 0..2 {
            bytes.extend_from_slice(&[0xff, 0, 0, 8, 1, 0, 0xff]);
        }
        let view = parse(&bytes, permissive()).unwrap();
        assert_eq!(view.version(), 0xff);
        assert_eq!(view.threshold(), 0);
        assert_eq!(view.reserved0(), [1, 2, 3]);
        assert_eq!(view.reserved1(), [4, 5, 6, 7]);
        let mut entries = view.entries();
        let first = entries.next().unwrap();
        assert_eq!(first.suite_id, 0xff);
        assert_eq!(first.weight, 0);
        assert_eq!(first.reserved0, [8]);
        assert_eq!(first.pubkey_bytes, [0xff]);
        assert_eq!(entries.next(), Some(first));
        assert_eq!(entries.next(), None);
        // Unknown fields, duplicate opaque keys and zero weights/threshold survive.
        // No signature, owner, identity, or canonical-key validation was performed.
    }

    #[test]
    fn boundary_fields_without_limit_sized_storage() {
        let mut bytes = vec![0xff; 12];
        bytes[6..8].copy_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&[0xff; 6]);
        bytes.resize(18 + usize::from(u16::MAX), 0xa5);
        let view = parse(&bytes, permissive()).unwrap();
        assert_eq!(view.threshold(), u16::MAX);
        assert_eq!(view.version(), u8::MAX);
        assert_eq!(view.reserved0(), [u8::MAX; 3]);
        assert_eq!(view.reserved1(), [u8::MAX; 4]);
        let entry = view.entries().next().unwrap();
        assert_eq!(entry.suite_id, u8::MAX);
        assert_eq!(entry.weight, u16::MAX);
        assert_eq!(entry.reserved0, [u8::MAX]);
        assert_eq!(entry.pubkey_len, u16::MAX);
        assert_eq!(entry.pubkey_bytes.len(), usize::from(u16::MAX));
        assert_eq!(entry.pubkey_bytes.as_ptr(), bytes[18..].as_ptr());

        let mut many = vec![0xff; 12];
        for _ in 0..u16::MAX {
            many.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0, 0]);
        }
        let view = parse(&many, permissive()).unwrap();
        assert_eq!(view.entry_count(), u16::MAX);
        assert_eq!(view.entries().count(), usize::from(u16::MAX));
        assert!(view.entries().eq(view.entries()));
        // Fixture storage follows encoded bytes, never the usize::MAX budgets.
        assert!(parse(&fixture(), permissive()).is_ok());
    }
}
