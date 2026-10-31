use crate::error::WireError;
use crate::io::{
    get_bytes, get_u16, get_u8, len_to_u16, put_bytes, put_u16, put_u8, WireDecode, WireEncode,
};
use qbind_types::AccountId;

/// Opcode for creating a new keyset account.
pub const OP_KEYSET_CREATE: u8 = 0x30;

/// Wire-level representation of a single key entry in CreateKeysetCall.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WireKeyEntry {
    pub suite_id: u8,
    pub weight: u16,
    pub pubkey_bytes: Vec<u8>,
}

/// Call_data for keyset creation:
///
/// op_code:     u8   // 0x30
/// version:     u8   // 0x01
/// target_id:   [u8; 32]  // AccountId where the keyset account will live
/// threshold:   u16
/// entry_count: u16
/// reserved0:   [u8; 4]
/// entries:     repeated { suite_id: u8, weight: u16, pk_len: u16, pk_bytes: [u8; pk_len] }
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CreateKeysetCall {
    pub version: u8,
    pub target_id: AccountId,
    pub threshold: u16,
    pub entries: Vec<WireKeyEntry>,
}

impl WireEncode for WireKeyEntry {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, self.suite_id);
        put_u16(out, self.weight);
        let pk_len = len_to_u16(self.pubkey_bytes.len());
        put_u16(out, pk_len);
        put_bytes(out, &self.pubkey_bytes);
    }
}

impl WireDecode for WireKeyEntry {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let suite_id = get_u8(input)?;
        let weight = get_u16(input)?;
        let pk_len = get_u16(input)? as usize;
        let pk_bytes = get_bytes(input, pk_len)?.to_vec();
        Ok(WireKeyEntry {
            suite_id,
            weight,
            pubkey_bytes: pk_bytes,
        })
    }
}

impl WireEncode for CreateKeysetCall {
    fn encode(&self, out: &mut Vec<u8>) {
        put_u8(out, OP_KEYSET_CREATE);
        put_u8(out, self.version);
        put_bytes(out, &self.target_id);
        put_u16(out, self.threshold);
        let entry_count_u16 = len_to_u16(self.entries.len());
        put_u16(out, entry_count_u16);
        put_bytes(out, &[0u8; 4]); // reserved0
        for e in &self.entries {
            e.encode(out);
        }
    }
}

impl WireDecode for CreateKeysetCall {
    fn decode(input: &mut &[u8]) -> Result<Self, WireError> {
        let op = get_u8(input)?;
        if op != OP_KEYSET_CREATE {
            return Err(WireError::InvalidValue(
                "unexpected op_code for CreateKeysetCall",
            ));
        }
        let version = get_u8(input)?;
        let id_bytes = get_bytes(input, 32)?;
        let mut target_id = [0u8; 32];
        target_id.copy_from_slice(id_bytes);
        let threshold = get_u16(input)?;
        let entry_count = get_u16(input)? as usize;
        let _reserved0 = get_bytes(input, 4)?;
        let mut entries = Vec::with_capacity(entry_count);
        for _ in 0..entry_count {
            entries.push(WireKeyEntry::decode(input)?);
        }
        Ok(CreateKeysetCall {
            version,
            target_id,
            threshold,
            entries,
        })
    }
}

/// Caller-selected framing budgets, not deployment or authorization policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateKeysetLimits {
    pub max_encoded_bytes: usize,
    pub max_entries: usize,
    pub max_key_bytes: usize,
    pub max_total_key_bytes: usize,
}

/// Fixed-size failures distinguish malformed framing from each resource limit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreateKeysetParseError {
    Malformed(WireError),
    EncodedBytesLimit,
    EntryCountLimit,
    PerKeyBytesLimit,
    AggregateKeyBytesLimit,
}

/// Completely framed create call, retaining even the reserved header bytes.
///
/// This establishes no version/suite support, canonical key encoding, meaningful
/// threshold, distinct identities, signatures, ownership, or authorization.
#[derive(Clone, Copy, Debug)]
pub struct CreateKeysetView<'a> {
    input: &'a [u8],
    opcode: u8,
    version: u8,
    target_id: AccountId,
    threshold: u16,
    entry_count: u16,
    reserved0: [u8; 4],
}

impl<'a> CreateKeysetView<'a> {
    pub fn encoded_bytes(&self) -> &'a [u8] {
        self.input
    }

    pub fn opcode(&self) -> u8 {
        self.opcode
    }

    pub fn version(&self) -> u8 {
        self.version
    }

    pub fn target_id(&self) -> AccountId {
        self.target_id
    }

    pub fn threshold(&self) -> u16 {
        self.threshold
    }

    pub fn entry_count(&self) -> u16 {
        self.entry_count
    }

    pub fn reserved0(&self) -> [u8; 4] {
        self.reserved0
    }

    /// Each independent traversal is O(entry_count), with O(1) storage.
    pub fn entries(&self) -> CreateKeysetEntries<'a> {
        CreateKeysetEntries {
            remaining: &self.input[42..],
            count: self.entry_count,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreateKeysetEntryView<'a> {
    pub suite_id: u8,
    pub weight: u16,
    pub pubkey_len: u16,
    pub pubkey_bytes: &'a [u8],
}

/// Forward-only traversal of already validated, immutable bytes.
#[derive(Clone, Debug)]
pub struct CreateKeysetEntries<'a> {
    remaining: &'a [u8],
    count: u16,
}

impl<'a> Iterator for CreateKeysetEntries<'a> {
    type Item = CreateKeysetEntryView<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.count == 0 {
            return None;
        }
        // Private construction and immutable input guarantee both splits.
        let (prefix, rest) = self.remaining.split_at(5);
        let pubkey_len = u16::from_le_bytes([prefix[3], prefix[4]]);
        let (pubkey_bytes, rest) = rest.split_at(usize::from(pubkey_len));
        self.remaining = rest;
        self.count -= 1;
        Some(CreateKeysetEntryView {
            suite_id: prefix[0],
            weight: u16::from_le_bytes([prefix[1], prefix[2]]),
            pubkey_len,
            pubkey_bytes,
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let count = usize::from(self.count);
        (count, Some(count))
    }
}

impl ExactSizeIterator for CreateKeysetEntries<'_> {}
impl std::iter::FusedIterator for CreateKeysetEntries<'_> {}

/// Validate the complete create-call slice, including the create opcode.
///
/// Admission checks encoded bytes before reading, count and checked minimum
/// size before looping, then per-key and checked aggregate lengths before each
/// body. Bounded slice splits avoid offset addition. No heap allocation or
/// variable-length copy occurs in parsing or traversal. Work is O(entry_count)
/// and controls are O(1); key bodies are borrowed, not scanned.
///
/// Limits bound admitted encoded lengths and parsing work, not input acquisition,
/// allocator overhead, physical memory, or arbitrary repeated caller traversals.
pub fn parse_create_keyset(
    input: &[u8],
    limits: CreateKeysetLimits,
) -> Result<CreateKeysetView<'_>, CreateKeysetParseError> {
    use CreateKeysetParseError::*;
    if input.len() > limits.max_encoded_bytes {
        return Err(EncodedBytesLimit);
    }
    let mut remaining = input;
    let header = get_bytes(&mut remaining, 42).map_err(Malformed)?;
    if header[0] != OP_KEYSET_CREATE {
        return Err(Malformed(WireError::InvalidValue(
            "unexpected op_code for CreateKeysetCall",
        )));
    }
    let entry_count = u16::from_le_bytes([header[36], header[37]]);
    if usize::from(entry_count) > limits.max_entries {
        return Err(EntryCountLimit);
    }
    let minimum = usize::from(entry_count)
        .checked_mul(5)
        .and_then(|size| size.checked_add(42))
        .ok_or(Malformed(WireError::LengthOverflow))?;
    if input.len() < minimum {
        return Err(Malformed(WireError::UnexpectedEof));
    }
    let mut total_key_bytes = 0usize;
    for _ in 0..entry_count {
        let prefix = get_bytes(&mut remaining, 5).map_err(Malformed)?;
        let key_len = usize::from(u16::from_le_bytes([prefix[3], prefix[4]]));
        if key_len > limits.max_key_bytes {
            return Err(PerKeyBytesLimit);
        }
        total_key_bytes = total_key_bytes
            .checked_add(key_len)
            .ok_or(Malformed(WireError::LengthOverflow))?;
        if total_key_bytes > limits.max_total_key_bytes {
            return Err(AggregateKeyBytesLimit);
        }
        get_bytes(&mut remaining, key_len).map_err(Malformed)?;
    }
    if !remaining.is_empty() {
        return Err(Malformed(WireError::InvalidValue(
            "trailing create keyset bytes",
        )));
    }
    let mut target_id = [0u8; 32];
    target_id.copy_from_slice(&header[2..34]);
    Ok(CreateKeysetView {
        input,
        opcode: header[0],
        version: header[1],
        target_id,
        threshold: u16::from_le_bytes([header[34], header[35]]),
        entry_count,
        reserved0: [header[38], header[39], header[40], header[41]],
    })
}

#[cfg(test)]
mod run422_bounded_keyset_parse {
    use super::*;

    fn fixture() -> Vec<u8> {
        // Independent bytes: 42-byte header, 5-byte prefixes, LE u16 fields.
        vec![
            0x30, 0x91, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
            21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 0x34, 0x12, 2, 0, 0x21, 0x22, 0x23, 0x24,
            0xa1, 0x78, 0x56, 3, 0, 0x41, 0x42, 0x43, 0xa2, 0xbc, 0x9a, 2, 0, 0x51, 0x52,
        ]
    }

    fn exact() -> CreateKeysetLimits {
        CreateKeysetLimits {
            max_encoded_bytes: 57,
            max_entries: 2,
            max_key_bytes: 3,
            max_total_key_bytes: 5,
        }
    }

    fn permissive() -> CreateKeysetLimits {
        CreateKeysetLimits {
            max_encoded_bytes: usize::MAX,
            max_entries: usize::MAX,
            max_key_bytes: usize::MAX,
            max_total_key_bytes: usize::MAX,
        }
    }

    fn parse(
        input: &[u8],
        limits: CreateKeysetLimits,
    ) -> Result<CreateKeysetView<'_>, CreateKeysetParseError> {
        let before = input.to_vec();
        let result = parse_create_keyset(input, limits);
        assert_eq!(input, before, "success and refusal must leave input intact");
        result
    }

    #[test]
    fn layout_borrowing_and_repeatable_traversal() {
        let bytes = fixture();
        let view = parse(&bytes, exact()).unwrap();
        assert_eq!(view.encoded_bytes(), bytes);
        assert_eq!(view.opcode(), OP_KEYSET_CREATE);
        assert_eq!(view.version(), 0x91);
        assert_eq!(view.target_id(), std::array::from_fn(|i| i as u8));
        assert_eq!(view.threshold(), 0x1234);
        assert_eq!(view.entry_count(), 2);
        assert_eq!(view.reserved0(), [0x21, 0x22, 0x23, 0x24]);
        let expected = [
            CreateKeysetEntryView {
                suite_id: 0xa1,
                weight: 0x5678,
                pubkey_len: 3,
                pubkey_bytes: &bytes[47..50],
            },
            CreateKeysetEntryView {
                suite_id: 0xa2,
                weight: 0x9abc,
                pubkey_len: 2,
                pubkey_bytes: &bytes[55..57],
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
        let owned = CreateKeysetCall {
            version: 7,
            target_id: std::array::from_fn(|i| i as u8),
            threshold: 0x1234,
            entries: vec![
                WireKeyEntry {
                    suite_id: 8,
                    weight: 0x5678,
                    pubkey_bytes: vec![10, 11, 12],
                },
                WireKeyEntry {
                    suite_id: 13,
                    weight: 0x9abc,
                    pubkey_bytes: vec![15, 16],
                },
            ],
        };
        let mut bytes = Vec::new();
        owned.encode(&mut bytes);
        let mut remaining = bytes.as_slice();
        let decoded = CreateKeysetCall::decode(&mut remaining).unwrap();
        assert!(remaining.is_empty());
        let view = parse(&bytes, exact()).unwrap();
        assert_eq!(view.opcode(), OP_KEYSET_CREATE);
        assert_eq!(view.version(), decoded.version);
        assert_eq!(view.target_id(), decoded.target_id);
        assert_eq!(view.threshold(), decoded.threshold);
        assert_eq!(usize::from(view.entry_count()), decoded.entries.len());
        assert_eq!(view.reserved0(), [0; 4]);
        for (entry, decoded) in view.entries().zip(&decoded.entries) {
            assert_eq!(entry.suite_id, decoded.suite_id);
            assert_eq!(entry.weight, decoded.weight);
            assert_eq!(usize::from(entry.pubkey_len), decoded.pubkey_bytes.len());
            assert_eq!(entry.pubkey_bytes, decoded.pubkey_bytes);
        }
        // The existing owned decoder discards these bytes; the view retains them.
        bytes[38..42].copy_from_slice(&[1, 2, 3, 4]);
        assert_eq!(parse(&bytes, exact()).unwrap().reserved0(), [1, 2, 3, 4]);
        assert_eq!(
            CreateKeysetCall::decode(&mut bytes.as_slice()).unwrap(),
            decoded
        );
    }

    #[test]
    fn exact_limits_and_independent_one_over_refusals() {
        use CreateKeysetParseError::*;
        let bytes = fixture();
        assert!(parse(&bytes, exact()).is_ok());
        let cases = [
            (
                CreateKeysetLimits {
                    max_encoded_bytes: 56,
                    ..exact()
                },
                EncodedBytesLimit,
            ),
            (
                CreateKeysetLimits {
                    max_entries: 1,
                    ..exact()
                },
                EntryCountLimit,
            ),
            (
                CreateKeysetLimits {
                    max_key_bytes: 2,
                    ..exact()
                },
                PerKeyBytesLimit,
            ),
            (
                CreateKeysetLimits {
                    max_total_key_bytes: 4,
                    ..exact()
                },
                AggregateKeyBytesLimit,
            ),
        ];
        for (limits, error) in cases {
            assert_eq!(parse(&bytes, limits).unwrap_err(), error);
            assert!(parse(&bytes, exact()).is_ok());
        }
        assert_eq!(
            parse(
                &bytes,
                CreateKeysetLimits {
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
        let mut bytes = fixture()[..42].to_vec();
        bytes[36..38].copy_from_slice(&[0, 0]);
        let limits = CreateKeysetLimits {
            max_encoded_bytes: 42,
            max_entries: 0,
            max_key_bytes: 0,
            max_total_key_bytes: 0,
        };
        let view = parse(&bytes, limits).unwrap();
        assert_eq!(view.entry_count(), 0);
        assert_eq!(view.entries().next(), None);
        bytes[36] = 1;
        bytes.extend_from_slice(&[0xff, 0, 0, 0, 0]);
        let view = parse(
            &bytes,
            CreateKeysetLimits {
                max_encoded_bytes: 47,
                max_entries: 1,
                ..limits
            },
        )
        .unwrap();
        let entry = view.entries().next().unwrap();
        assert_eq!(entry.pubkey_len, 0);
        assert!(entry.pubkey_bytes.is_empty());
    }

    #[test]
    fn every_truncated_prefix() {
        let bytes = fixture();
        for end in 0..bytes.len() {
            assert_eq!(
                parse(&bytes[..end], exact()).unwrap_err(),
                CreateKeysetParseError::Malformed(WireError::UnexpectedEof),
                "truncated at {end}"
            );
        }
        assert!(parse(&bytes, exact()).is_ok());
    }

    #[test]
    fn malformed_counts_trailing_and_final_entries() {
        use CreateKeysetParseError::Malformed;
        let mut excessive = fixture();
        excessive[36..38].copy_from_slice(&u16::MAX.to_le_bytes());
        assert_eq!(
            parse(&excessive, exact()).unwrap_err(),
            CreateKeysetParseError::EntryCountLimit
        );
        assert_eq!(
            parse(&excessive, permissive()).unwrap_err(),
            Malformed(WireError::UnexpectedEof)
        );
        for count in [0, 1] {
            let mut bytes = fixture();
            bytes[36..38].copy_from_slice(&count.to_le_bytes());
            assert_eq!(
                parse(&bytes, permissive()).unwrap_err(),
                Malformed(WireError::InvalidValue("trailing create keyset bytes"))
            );
        }
        let mut trailing = fixture();
        trailing.push(0);
        assert_eq!(
            parse(&trailing, permissive()).unwrap_err(),
            Malformed(WireError::InvalidValue("trailing create keyset bytes"))
        );
        let mut final_body = fixture();
        final_body[53..55].copy_from_slice(&3u16.to_le_bytes());
        assert_eq!(
            parse(&final_body, permissive()).unwrap_err(),
            Malformed(WireError::UnexpectedEof)
        );
        let final_prefix = &fixture()[..53];
        assert_eq!(
            parse(final_prefix, permissive()).unwrap_err(),
            Malformed(WireError::UnexpectedEof)
        );
    }

    #[test]
    fn wrong_create_opcode() {
        let mut bytes = fixture();
        for opcode in [0, OP_KEYSET_CREATE - 1, OP_KEYSET_CREATE + 1, u8::MAX] {
            bytes[0] = opcode;
            assert_eq!(
                parse(&bytes, permissive()).unwrap_err(),
                CreateKeysetParseError::Malformed(WireError::InvalidValue(
                    "unexpected op_code for CreateKeysetCall"
                ))
            );
        }
    }

    #[test]
    fn admission_order_before_body_access() {
        use CreateKeysetParseError::*;
        assert_eq!(
            parse(
                &[0],
                CreateKeysetLimits {
                    max_encoded_bytes: 0,
                    ..permissive()
                }
            )
            .unwrap_err(),
            EncodedBytesLimit
        );
        let bytes = fixture();
        assert_eq!(
            parse(&bytes[..42], exact()).unwrap_err(),
            Malformed(WireError::UnexpectedEof)
        );
        assert_eq!(
            parse(
                &bytes[..42],
                CreateKeysetLimits {
                    max_entries: 1,
                    ..exact()
                }
            )
            .unwrap_err(),
            EntryCountLimit
        );
        assert_eq!(
            parse(
                &bytes[..56],
                CreateKeysetLimits {
                    max_total_key_bytes: 4,
                    ..exact()
                }
            )
            .unwrap_err(),
            AggregateKeyBytesLimit
        );
        assert_eq!(
            parse(
                &bytes[..56],
                CreateKeysetLimits {
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
        let mut bytes = fixture()[..42].to_vec();
        bytes[1] = 0xff;
        bytes[34..36].copy_from_slice(&[0, 0]);
        for _ in 0..2 {
            bytes.extend_from_slice(&[0xff, 0, 0, 1, 0, 0xff]);
        }
        let view = parse(&bytes, permissive()).unwrap();
        assert_eq!(view.version(), 0xff);
        assert_eq!(view.threshold(), 0);
        assert_eq!(view.reserved0(), [0x21, 0x22, 0x23, 0x24]);
        let mut entries = view.entries();
        let first = entries.next().unwrap();
        assert_eq!(first.suite_id, 0xff);
        assert_eq!(first.weight, 0);
        assert_eq!(first.pubkey_bytes, [0xff]);
        assert_eq!(entries.next(), Some(first));
        assert_eq!(entries.next(), None);
        // Unknown fields, duplicate opaque keys and zero weights/threshold survive.
        // No signature, owner, identity, or canonical-key validation was performed.
    }

    #[test]
    fn boundary_fields_without_limit_sized_storage() {
        let mut bytes = vec![0xff; 42];
        bytes[0] = OP_KEYSET_CREATE;
        bytes[36..38].copy_from_slice(&1u16.to_le_bytes());
        bytes.extend_from_slice(&[0xff; 5]);
        bytes.resize(47 + usize::from(u16::MAX), 0xa5);
        let view = parse(&bytes, permissive()).unwrap();
        assert_eq!(view.threshold(), u16::MAX);
        assert_eq!(view.version(), u8::MAX);
        assert_eq!(view.target_id(), [u8::MAX; 32]);
        assert_eq!(view.reserved0(), [u8::MAX; 4]);
        let entry = view.entries().next().unwrap();
        assert_eq!(entry.suite_id, u8::MAX);
        assert_eq!(entry.weight, u16::MAX);
        assert_eq!(entry.pubkey_len, u16::MAX);
        assert_eq!(entry.pubkey_bytes.len(), usize::from(u16::MAX));
        assert_eq!(entry.pubkey_bytes.as_ptr(), bytes[47..].as_ptr());

        let mut many = vec![0xff; 42];
        many[0] = OP_KEYSET_CREATE;
        for _ in 0..u16::MAX {
            many.extend_from_slice(&[0xff, 0xff, 0xff, 0, 0]);
        }
        let view = parse(&many, permissive()).unwrap();
        assert_eq!(view.entry_count(), u16::MAX);
        assert_eq!(view.entries().count(), usize::from(u16::MAX));
        assert!(view.entries().eq(view.entries()));
        assert!(parse(&fixture(), permissive()).is_ok());
    }
}
