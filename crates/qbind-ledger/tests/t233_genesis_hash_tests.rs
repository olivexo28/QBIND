//! T233: Genesis Hash Commitment & Verification Tests
//!
//! This test module verifies the genesis hash computation and ChainMeta types
//! as specified in T233.
//!
//! # Test Coverage
//!
//! - `test_compute_genesis_hash_deterministic`: Hash same bytes twice → same result
//! - `test_genesis_hash_different_inputs`: Different inputs → different hashes
//! - `test_format_genesis_hash`: Format hash as hex string with 0x prefix
//! - `test_parse_genesis_hash_with_prefix`: Parse hex string with 0x prefix
//! - `test_parse_genesis_hash_without_prefix`: Parse bare hex string
//! - `test_parse_genesis_hash_invalid_length`: Reject invalid length
//! - `test_parse_genesis_hash_invalid_hex`: Reject invalid hex characters
//! - `test_chain_meta_creation`: Create ChainMeta struct
//! - `test_chain_meta_serialization_roundtrip`: Serialize/deserialize ChainMeta

use qbind_ledger::{
    compute_genesis_hash_bytes, format_genesis_hash, parse_genesis_hash, ChainMeta, ChainMetaError,
    GenesisHash,
};

// ============================================================================
// Genesis Hash Computation Tests
// ============================================================================

#[test]
fn test_compute_genesis_hash_deterministic() {
    // Given a fixed byte array, compute hash twice
    let bytes = br#"{"chain_id": "qbind-mainnet-v0", "genesis_time_unix_ms": 1738000000000}"#;

    let hash1 = compute_genesis_hash_bytes(bytes);
    let hash2 = compute_genesis_hash_bytes(bytes);

    // Then the hashes must be equal
    assert_eq!(
        hash1, hash2,
        "genesis hash computation must be deterministic"
    );
    assert_eq!(hash1.len(), 32, "genesis hash must be 32 bytes");
}

#[test]
fn test_genesis_hash_different_inputs() {
    // Given two different byte arrays
    let bytes1 = b"genesis v1";
    let bytes2 = b"genesis v2";

    let hash1 = compute_genesis_hash_bytes(bytes1);
    let hash2 = compute_genesis_hash_bytes(bytes2);

    // Then the hashes must be different
    assert_ne!(
        hash1, hash2,
        "different inputs must produce different hashes"
    );
}

#[test]
fn test_genesis_hash_sensitive_to_whitespace() {
    // Genesis hash MUST NOT normalize whitespace - exact bytes matter
    let bytes1 = br#"{"chain_id":"test"}"#;
    let bytes2 = br#"{ "chain_id" : "test" }"#;

    let hash1 = compute_genesis_hash_bytes(bytes1);
    let hash2 = compute_genesis_hash_bytes(bytes2);

    // Then the hashes must be different (no whitespace normalization)
    assert_ne!(
        hash1, hash2,
        "genesis hash must be sensitive to whitespace (no normalization)"
    );
}

#[test]
fn test_genesis_hash_empty_input() {
    // Even empty input produces a valid 32-byte hash
    let hash = compute_genesis_hash_bytes(b"");

    assert_eq!(hash.len(), 32);
    // SHA3-256 of empty input is a known value
    // We just verify it's not all zeros
    assert_ne!(hash, [0u8; 32]);
}

// ============================================================================
// Genesis Hash Formatting Tests
// ============================================================================

#[test]
fn test_format_genesis_hash() {
    // Given a known hash
    let hash: GenesisHash = [
        0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67,
        0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
        0x67, 0x89,
    ];

    let hex = format_genesis_hash(&hash);

    // Then it should be formatted with 0x prefix and lowercase hex
    assert!(hex.starts_with("0x"), "formatted hash must start with 0x");
    assert_eq!(
        hex.len(),
        66,
        "formatted hash must be 66 chars (0x + 64 hex)"
    );
    assert_eq!(
        hex,
        "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    );
}

#[test]
fn test_format_and_parse_roundtrip() {
    // Given a hash computed from some bytes
    let original_hash = compute_genesis_hash_bytes(b"test genesis file content");

    // Format it as hex
    let hex = format_genesis_hash(&original_hash);

    // Parse it back
    let parsed_hash = parse_genesis_hash(&hex).expect("should parse valid hex");

    // Then they should be equal
    assert_eq!(
        original_hash, parsed_hash,
        "format and parse should round-trip"
    );
}

// ============================================================================
// Genesis Hash Parsing Tests
// ============================================================================

#[test]
fn test_parse_genesis_hash_with_prefix() {
    // Given a valid hex string with 0x prefix
    let hex = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let hash = parse_genesis_hash(hex).expect("should parse valid hex with prefix");

    assert_eq!(hash[0], 0xab);
    assert_eq!(hash[1], 0xcd);
    assert_eq!(hash[31], 0x89);
}

#[test]
fn test_parse_genesis_hash_without_prefix() {
    // Given a valid hex string without 0x prefix
    let hex = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let hash = parse_genesis_hash(hex).expect("should parse valid hex without prefix");

    assert_eq!(hash[0], 0xab);
    assert_eq!(hash[31], 0x89);
}

#[test]
fn test_parse_genesis_hash_uppercase() {
    // Given a valid uppercase hex string
    let hex = "0xABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789";

    let hash = parse_genesis_hash(hex).expect("should parse valid uppercase hex");

    assert_eq!(hash[0], 0xab);
    assert_eq!(hash[31], 0x89);
}

#[test]
fn test_parse_genesis_hash_invalid_length_short() {
    // Given a hex string that's too short
    let hex = "0x1234";

    let result = parse_genesis_hash(hex);

    assert!(result.is_err(), "should reject short hex string");
    let err = result.unwrap_err();
    assert!(
        err.contains("length"),
        "error should mention length: {}",
        err
    );
}

#[test]
fn test_parse_genesis_hash_invalid_length_long() {
    // Given a hex string that's too long
    let hex = "0xabcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789ff";

    let result = parse_genesis_hash(hex);

    assert!(result.is_err(), "should reject long hex string");
}

#[test]
fn test_parse_genesis_hash_invalid_hex_chars() {
    // Given a hex string with invalid characters
    let hex = "0xzzzzzz0123456789abcdef0123456789abcdef0123456789abcdef0123456789";

    let result = parse_genesis_hash(hex);

    assert!(result.is_err(), "should reject invalid hex characters");
    let err = result.unwrap_err();
    assert!(
        err.contains("hex character") || err.contains("invalid"),
        "error should mention invalid character: {}",
        err
    );
}

// ============================================================================
// ChainMeta Tests
// ============================================================================

#[test]
fn test_chain_meta_creation() {
    // Given a chain_id and genesis_hash
    let chain_id = "qbind-mainnet-v0";
    let genesis_hash: GenesisHash = [0x42u8; 32];

    // When we create a ChainMeta
    let meta = ChainMeta::new(chain_id, genesis_hash);

    // Then the fields should be set correctly
    assert_eq!(meta.chain_id, "qbind-mainnet-v0");
    assert_eq!(meta.genesis_hash, [0x42u8; 32]);
}

#[test]
fn test_chain_meta_genesis_hash_hex() {
    // Given a ChainMeta with a known hash
    let meta = ChainMeta::new(
        "test",
        [
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45,
            0x67, 0x89, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0x01,
            0x23, 0x45, 0x67, 0x89,
        ],
    );

    // When we get the hex representation
    let hex = meta.genesis_hash_hex();

    // Then it should be correctly formatted
    assert!(hex.starts_with("0x"));
    assert_eq!(hex.len(), 66);
}

#[test]
fn test_chain_meta_serialization_roundtrip() {
    // Given a ChainMeta
    let original = ChainMeta::new(
        "qbind-testnet-v0",
        compute_genesis_hash_bytes(b"test genesis"),
    );

    // When we serialize and deserialize
    let json = serde_json::to_string(&original).expect("should serialize");
    let deserialized: ChainMeta = serde_json::from_str(&json).expect("should deserialize");

    // Then they should be equal
    assert_eq!(original, deserialized);
}

#[test]
fn test_chain_meta_json_format() {
    // Given a ChainMeta
    let meta = ChainMeta::new("test-chain", [0x01u8; 32]);

    // When we serialize to JSON
    let json = serde_json::to_string_pretty(&meta).expect("should serialize");

    // Then it should contain expected fields
    assert!(json.contains("chain_id"));
    assert!(json.contains("test-chain"));
    assert!(json.contains("genesis_hash"));
}

// ============================================================================
// ChainMetaError Tests
// ============================================================================

#[test]
fn test_chain_meta_error_display() {
    // Test error display formatting
    let err = ChainMetaError::AlreadyExists;
    let msg = format!("{}", err);
    assert!(msg.contains("already exists"));

    let err = ChainMetaError::NotFound;
    let msg = format!("{}", err);
    assert!(msg.contains("not found"));

    let err = ChainMetaError::SerializationError("test error".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("serialization"));
    assert!(msg.contains("test error"));

    let err = ChainMetaError::StorageError("disk full".to_string());
    let msg = format!("{}", err);
    assert!(msg.contains("storage"));
    assert!(msg.contains("disk full"));
}

// ============================================================================
// Integration-like Tests
// ============================================================================

#[test]
fn test_genesis_hash_from_realistic_json() {
    // Given a realistic genesis JSON (similar to actual format)
    let genesis_json = br#"{
  "chain_id": "qbind-mainnet-v0",
  "genesis_time_unix_ms": 1738000000000,
  "allocations": [
    {
      "address": "0x1234567890abcdef1234567890abcdef12345678",
      "amount": 1000000000000000000000000
    }
  ],
  "validators": [
    {
      "address": "0xabc...",
      "pqc_public_key": "0x...",
      "stake": 100000
    }
  ],
  "council": {
    "members": ["0x111...", "0x222..."],
    "threshold": 2
  }
}"#;

    // When we compute the hash
    let hash = compute_genesis_hash_bytes(genesis_json);

    // Then it should be a valid 32-byte hash
    assert_eq!(hash.len(), 32);

    // And it should be deterministic
    let hash2 = compute_genesis_hash_bytes(genesis_json);
    assert_eq!(hash, hash2);

    // And we can format and parse it
    let hex = format_genesis_hash(&hash);
    let parsed = parse_genesis_hash(&hex).unwrap();
    assert_eq!(hash, parsed);
}

#[test]
fn test_chain_meta_from_genesis_bytes() {
    // This simulates the workflow of creating ChainMeta during genesis application
    let genesis_bytes = br#"{"chain_id": "qbind-testnet-v0", "genesis_time_unix_ms": 123}"#;

    // Compute the hash
    let genesis_hash = compute_genesis_hash_bytes(genesis_bytes);

    // In a real scenario, we'd parse the JSON to extract chain_id
    let chain_id = "qbind-testnet-v0";

    // Create ChainMeta
    let meta = ChainMeta::new(chain_id, genesis_hash);

    // Verify
    assert_eq!(meta.chain_id, "qbind-testnet-v0");
    assert_eq!(meta.genesis_hash.len(), 32);

    // The hex should be usable for verification
    let hex = meta.genesis_hash_hex();
    assert!(hex.starts_with("0x"));

    // Operator can verify by parsing the expected hash
    let expected = parse_genesis_hash(&hex).unwrap();
    assert_eq!(expected, meta.genesis_hash);
}
