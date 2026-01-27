//! Local validator keystore abstraction (T144).
//!
//! This module provides a keystore abstraction for loading validator signing keys
//! from local storage. The keystore is designed to be minimal and focused on the
//! needs of node startup.
//!
//! # Design
//!
//! The keystore abstraction consists of:
//! - `ValidatorKeystore` trait: defines the interface for loading signing keys
//! - `FsValidatorKeystore`: filesystem-backed implementation that reads keys from disk
//! - `KeystoreConfig`: configuration for the keystore (root directory, etc.)
//! - `LocalKeystoreEntryId`: identifier for a keystore entry
//!
//! # On-Disk Format
//!
//! The filesystem keystore uses a simple JSON format:
//!
//! ```json
//! {
//!   "suite_id": 100,
//!   "private_key_hex": "..."
//! }
//! ```
//!
//! Where:
//! - `suite_id`: Must be 100 (ML-DSA-44, SUITE_PQ_RESERVED_1) for T144
//! - `private_key_hex`: The secret key bytes encoded as lowercase hex
//!
//! The file is located at `{keystore_root}/{entry_id}.json`.
//!
//! # Security Notes
//!
//! - Key bytes are never logged.
//! - The keystore does not clone key material; it constructs `ValidatorSigningKey`
//!   directly from parsed bytes.
//! - T144 assumes OS-level disk protections; explicit encryption/HSM will be added
//!   in later tasks.
//! - File paths and entry IDs may be logged at debug/trace level, but never key bytes.
//!
//! # Future Work
//!
//! - Key generation, rotation, and write operations
//! - Remote/HSM keystore backends

use std::fs;
use std::io;
use std::path::PathBuf;

use qbind_crypto::ValidatorSigningKey;

/// Expected suite_id for ML-DSA-44 keys in T144.
///
/// This matches `qbind_crypto::SUITE_PQ_RESERVED_1.0` (100).
/// We use the raw value here to avoid depending on the ConsensusSigSuiteId type.
const EXPECTED_SUITE_ID: u8 = 100;

// ============================================================================
// Types
// ============================================================================

/// Keystore backend type selection (T153).
///
/// This enum allows selection between different keystore implementations:
/// - `PlainFs`: Plaintext JSON files (legacy/testing)
/// - `EncryptedFsV1`: Encrypted files with passphrase-based KDF
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum KeystoreBackend {
    /// Plaintext JSON keystore (default for DevNet, testing only).
    ///
    /// Files are stored at `{root}/{entry_id}.json` with plaintext key material.
    #[default]
    PlainFs,

    /// Encrypted keystore v1 with AEAD and KDF (T153).
    ///
    /// Files are stored at `{root}/{entry_id}.enc` with encrypted key material.
    /// Encryption key is derived from a passphrase via PBKDF2.
    EncryptedFsV1,
}

/// Identifier for a local keystore entry.
///
/// This is an opaque string identifier that maps to a file on disk
/// (for the filesystem keystore) or a key in a remote store (for future
/// implementations).
pub struct LocalKeystoreEntryId(pub String);

/// Configuration for the validator keystore.
///
/// This struct holds the configuration needed to initialize a keystore.
/// Currently only supports a filesystem root path, but future fields
/// (encryption, remote endpoints) will be added here.
pub struct KeystoreConfig {
    /// The root directory where keystore entries are stored.
    ///
    /// For `FsValidatorKeystore`, keys are stored at `{root}/{entry_id}.json`.
    pub root: PathBuf,
}

/// Configuration for encrypted keystore v1 (T153).
///
/// This struct holds the parameters needed to decrypt keys from an
/// encrypted keystore. The encryption key is derived from a passphrase
/// using PBKDF2.
#[derive(Debug, Clone)]
pub struct EncryptedKeystoreConfig {
    /// Name of the environment variable containing the passphrase.
    ///
    /// Example: `"QBIND_VALIDATOR_KEY_PASSPHRASE"`
    ///
    /// The passphrase is read from this environment variable at startup
    /// and used to derive the encryption key via PBKDF2.
    pub passphrase_env_var: String,

    /// Number of PBKDF2 iterations.
    ///
    /// Higher values provide more security but slower key derivation.
    /// DevNet default: 100,000 iterations (~100ms on modern hardware).
    pub kdf_iterations: u32,
}

// ============================================================================
// Error types
// ============================================================================

/// Error type for keystore operations.
///
/// This error type is designed to be informative without leaking sensitive
/// information (such as key bytes).
#[derive(Debug)]
pub enum KeystoreError {
    /// The requested keystore entry was not found.
    ///
    /// This typically means the file `{root}/{entry_id}.json` does not exist.
    NotFound(String),

    /// Failed to parse the keystore entry.
    ///
    /// This indicates malformed JSON, missing required fields, or invalid
    /// field values (e.g., non-hex characters in the key).
    Parse(String),

    /// The key material is invalid.
    ///
    /// This indicates that the key bytes were parsed successfully but are
    /// not valid for the expected algorithm (e.g., wrong size, invalid
    /// suite_id, or fails cryptographic validation).
    InvalidKey,

    /// Configuration error (T153).
    ///
    /// This indicates a problem with the keystore configuration, such as
    /// a missing environment variable or invalid parameters.
    Config(String),

    /// I/O error reading the keystore entry.
    Io(io::Error),
}

impl std::fmt::Display for KeystoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeystoreError::NotFound(entry) => write!(f, "keystore entry not found: {}", entry),
            KeystoreError::Parse(msg) => write!(f, "failed to parse keystore entry: {}", msg),
            KeystoreError::InvalidKey => write!(f, "invalid key material"),
            KeystoreError::Config(msg) => write!(f, "keystore configuration error: {}", msg),
            KeystoreError::Io(e) => write!(f, "io error: {}", e),
        }
    }
}

impl std::error::Error for KeystoreError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KeystoreError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for KeystoreError {
    fn from(e: io::Error) -> Self {
        KeystoreError::Io(e)
    }
}

// ============================================================================
// Trait
// ============================================================================

/// Trait for loading validator signing keys from a keystore.
///
/// Implementations of this trait provide access to validator signing keys
/// stored in various backends (filesystem, HSM, remote service, etc.).
///
/// # Thread Safety
///
/// Implementations must be `Send + Sync` to allow use from async contexts.
///
/// # Security
///
/// Implementations must not log key material. Entry IDs and file paths
/// may be logged at debug/trace level.
pub trait ValidatorKeystore: Send + Sync {
    /// Load a validator signing key by entry ID.
    ///
    /// This method reads the key material from the keystore and constructs
    /// a `ValidatorSigningKey`. The key material is owned by the returned
    /// value and will be zeroized when dropped.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The entry does not exist (`KeystoreError::NotFound`)
    /// - The entry cannot be parsed (`KeystoreError::Parse`)
    /// - The key material is invalid (`KeystoreError::InvalidKey`)
    /// - An I/O error occurs (`KeystoreError::Io`)
    fn load_signing_key(
        &self,
        entry: &LocalKeystoreEntryId,
    ) -> Result<ValidatorSigningKey, KeystoreError>;
}

// ============================================================================
// Plaintext Filesystem implementation (T144)
// ============================================================================

/// Plaintext filesystem-backed validator keystore (T144).
///
/// This implementation reads validator signing keys from plaintext JSON files on disk.
/// Each entry is stored at `{config.root}/{entry_id}.json`.
///
/// # File Format
///
/// ```json
/// {
///   "suite_id": 100,
///   "private_key_hex": "abcd1234..."
/// }
/// ```
///
/// # Security
///
/// - This implementation assumes OS-level disk protections.
/// - Key files should have restricted permissions (e.g., 0600).
/// - For encrypted keys, use `EncryptedFsValidatorKeystore` (T153).
pub struct FsValidatorKeystore {
    config: KeystoreConfig,
}

impl FsValidatorKeystore {
    /// Create a new filesystem keystore with the given configuration.
    pub fn new(config: KeystoreConfig) -> Self {
        Self { config }
    }

    /// Get the file path for a given entry ID.
    fn entry_path(&self, entry: &LocalKeystoreEntryId) -> PathBuf {
        self.config.root.join(format!("{}.json", entry.0))
    }
}

impl ValidatorKeystore for FsValidatorKeystore {
    fn load_signing_key(
        &self,
        entry: &LocalKeystoreEntryId,
    ) -> Result<ValidatorSigningKey, KeystoreError> {
        let path = self.entry_path(entry);

        // Read file contents
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(KeystoreError::NotFound(entry.0.clone()));
            }
            Err(e) => return Err(KeystoreError::Io(e)),
        };

        // Parse JSON manually (avoid external dependency)
        // Expected format: {"suite_id": 100, "private_key_hex": "..."}
        let parsed = parse_keystore_json(&contents)?;

        // Validate suite_id - must be 100 (ML-DSA-44, SUITE_PQ_RESERVED_1) for T144
        if parsed.suite_id != EXPECTED_SUITE_ID {
            return Err(KeystoreError::InvalidKey);
        }

        // Decode hex key bytes
        let key_bytes = decode_hex(&parsed.private_key_hex)
            .map_err(|e| KeystoreError::Parse(format!("invalid hex: {}", e)))?;

        // Construct ValidatorSigningKey - this takes ownership of the bytes
        Ok(ValidatorSigningKey::new(key_bytes))
    }
}

// ============================================================================
// Encrypted Filesystem implementation (T153)
// ============================================================================

/// Encrypted filesystem-backed validator keystore (T153).
///
/// This implementation reads validator signing keys from encrypted files on disk.
/// Each entry is stored at `{root}/{entry_id}.enc` with AEAD-encrypted content.
///
/// # File Format
///
/// ```json
/// {
///   "version": 1,
///   "suite_id": 100,
///   "aead": "ChaCha20-Poly1305",
///   "kdf": "PBKDF2-HMAC-SHA256",
///   "kdf_iterations": 100000,
///   "salt_hex": "...",
///   "nonce_hex": "...",
///   "ciphertext_hex": "..."
/// }
/// ```
///
/// The plaintext (before encryption) is a JSON object:
/// ```json
/// {
///   "private_key_hex": "..."
/// }
/// ```
///
/// # Security
///
/// - Encryption uses ChaCha20-Poly1305 AEAD
/// - Encryption key is derived from passphrase using PBKDF2-HMAC-SHA256
/// - Passphrase is read from environment variable (not stored on disk)
/// - Salt and nonce are stored in the encrypted file (safe to be public)
/// - Key derivation intentionally slow (~100ms) to resist brute-force
pub struct EncryptedFsValidatorKeystore {
    root: PathBuf,
    enc_config: EncryptedKeystoreConfig,
}

impl EncryptedFsValidatorKeystore {
    /// Create a new encrypted filesystem keystore.
    pub fn new(root: PathBuf, enc_config: EncryptedKeystoreConfig) -> Self {
        Self { root, enc_config }
    }

    /// Get the file path for a given entry ID.
    fn entry_path(&self, entry: &LocalKeystoreEntryId) -> PathBuf {
        self.root.join(format!("{}.enc", entry.0))
    }
}

impl ValidatorKeystore for EncryptedFsValidatorKeystore {
    fn load_signing_key(
        &self,
        entry: &LocalKeystoreEntryId,
    ) -> Result<ValidatorSigningKey, KeystoreError> {
        use qbind_crypto::{
            derive_key_pbkdf2, AeadSuite, ChaCha20Poly1305Backend, CHACHA20_POLY1305_NONCE_SIZE,
        };

        let path = self.entry_path(entry);

        // Read encrypted file contents
        let contents = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(KeystoreError::NotFound(entry.0.clone()));
            }
            Err(e) => return Err(KeystoreError::Io(e)),
        };

        // Parse encrypted file JSON
        let encrypted = parse_encrypted_keystore_json(&contents)?;

        // Validate version
        if encrypted.version != 1 {
            return Err(KeystoreError::Parse(format!(
                "unsupported encrypted keystore version: {}",
                encrypted.version
            )));
        }

        // Validate suite_id
        if encrypted.suite_id != EXPECTED_SUITE_ID {
            return Err(KeystoreError::InvalidKey);
        }

        // Get passphrase from environment variable
        let passphrase = std::env::var(&self.enc_config.passphrase_env_var).map_err(|_| {
            KeystoreError::Config(format!(
                "passphrase environment variable '{}' not set",
                self.enc_config.passphrase_env_var
            ))
        })?;

        // Decode salt and nonce from hex
        let salt = decode_hex(&encrypted.salt_hex)
            .map_err(|e| KeystoreError::Parse(format!("invalid salt hex: {}", e)))?;
        let nonce = decode_hex(&encrypted.nonce_hex)
            .map_err(|e| KeystoreError::Parse(format!("invalid nonce hex: {}", e)))?;
        let ciphertext = decode_hex(&encrypted.ciphertext_hex)
            .map_err(|e| KeystoreError::Parse(format!("invalid ciphertext hex: {}", e)))?;

        // Validate nonce size
        if nonce.len() != CHACHA20_POLY1305_NONCE_SIZE {
            return Err(KeystoreError::Parse(format!(
                "invalid nonce size: expected {}, got {}",
                CHACHA20_POLY1305_NONCE_SIZE,
                nonce.len()
            )));
        }

        // Derive encryption key from passphrase using PBKDF2
        let encryption_key =
            derive_key_pbkdf2(passphrase.as_bytes(), &salt, encrypted.kdf_iterations);

        // Decrypt using ChaCha20-Poly1305
        let aead = ChaCha20Poly1305Backend::new();
        let plaintext_json = aead
            .open(&encryption_key, &nonce, b"", &ciphertext)
            .map_err(|_| {
                // Decryption failure likely means wrong passphrase or corrupted file
                KeystoreError::InvalidKey
            })?;

        // Parse plaintext JSON to extract private_key_hex
        let plaintext_str = String::from_utf8(plaintext_json).map_err(|_| {
            KeystoreError::Parse("decrypted plaintext is not valid UTF-8".to_string())
        })?;

        let plaintext_parsed = parse_plaintext_json(&plaintext_str)?;

        // Decode hex key bytes
        let key_bytes = decode_hex(&plaintext_parsed.private_key_hex)
            .map_err(|e| KeystoreError::Parse(format!("invalid private key hex: {}", e)))?;

        // Construct ValidatorSigningKey
        Ok(ValidatorSigningKey::new(key_bytes))
    }
}

// ============================================================================
// JSON parsing (minimal, no external deps)
// ============================================================================

/// Parsed keystore entry (internal).
struct ParsedKeystoreEntry {
    suite_id: u8,
    private_key_hex: String,
}

/// Parse a keystore JSON string.
///
/// This is a minimal JSON parser that handles the specific format we need.
/// It avoids external dependencies for this security-sensitive code.
fn parse_keystore_json(json: &str) -> Result<ParsedKeystoreEntry, KeystoreError> {
    // Trim whitespace
    let json = json.trim();

    // Must be an object
    if !json.starts_with('{') || !json.ends_with('}') {
        return Err(KeystoreError::Parse("expected JSON object".to_string()));
    }

    // Remove braces
    let inner = &json[1..json.len() - 1];

    let mut suite_id: Option<u8> = None;
    let mut private_key_hex: Option<String> = None;

    // Simple state machine to parse key-value pairs
    // This handles: "key": value, "key": "string_value"
    let mut chars = inner.chars().peekable();

    loop {
        // Skip whitespace and commas
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }

        // Check if we're done
        if chars.peek().is_none() {
            break;
        }

        // Parse key (expect quoted string)
        if chars.next() != Some('"') {
            return Err(KeystoreError::Parse("expected quoted key".to_string()));
        }

        let mut key = String::new();
        loop {
            match chars.next() {
                Some('"') => break,
                Some(c) => key.push(c),
                None => return Err(KeystoreError::Parse("unterminated key string".to_string())),
            }
        }

        // Skip whitespace and colon
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.next() != Some(':') {
            return Err(KeystoreError::Parse("expected colon after key".to_string()));
        }
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }

        // Parse value
        match key.as_str() {
            "suite_id" => {
                // Parse number
                let mut num_str = String::new();
                while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                    num_str.push(chars.next().unwrap());
                }
                let id: u8 = num_str
                    .parse()
                    .map_err(|_| KeystoreError::Parse("invalid suite_id".to_string()))?;
                suite_id = Some(id);
            }
            "private_key_hex" => {
                // Parse string
                if chars.next() != Some('"') {
                    return Err(KeystoreError::Parse(
                        "expected quoted string for private_key_hex".to_string(),
                    ));
                }
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => {
                            // Handle escape sequences
                            match chars.next() {
                                Some('n') => value.push('\n'),
                                Some('r') => value.push('\r'),
                                Some('t') => value.push('\t'),
                                Some('\\') => value.push('\\'),
                                Some('"') => value.push('"'),
                                Some(c) => {
                                    value.push('\\');
                                    value.push(c);
                                }
                                None => {
                                    return Err(KeystoreError::Parse(
                                        "unterminated escape sequence".to_string(),
                                    ))
                                }
                            }
                        }
                        Some(c) => value.push(c),
                        None => {
                            return Err(KeystoreError::Parse(
                                "unterminated value string".to_string(),
                            ))
                        }
                    }
                }
                private_key_hex = Some(value);
            }
            _ => {
                // Skip unknown field - find end of value
                // This handles strings, numbers, and simple values
                if chars.peek() == Some(&'"') {
                    chars.next(); // consume opening quote
                    loop {
                        match chars.next() {
                            Some('"') => break,
                            Some('\\') => {
                                chars.next();
                            } // skip escaped char
                            Some(_) => {}
                            None => {
                                return Err(KeystoreError::Parse("unterminated string".to_string()))
                            }
                        }
                    }
                } else {
                    // Consume until comma or end
                    while chars.peek().is_some_and(|c| *c != ',' && *c != '}') {
                        chars.next();
                    }
                }
            }
        }
    }

    // Validate required fields
    let suite_id =
        suite_id.ok_or_else(|| KeystoreError::Parse("missing suite_id field".to_string()))?;
    let private_key_hex = private_key_hex
        .ok_or_else(|| KeystoreError::Parse("missing private_key_hex field".to_string()))?;

    Ok(ParsedKeystoreEntry {
        suite_id,
        private_key_hex,
    })
}

/// Parsed encrypted keystore entry (T153).
struct ParsedEncryptedKeystoreEntry {
    version: u32,
    suite_id: u8,
    kdf_iterations: u32,
    salt_hex: String,
    nonce_hex: String,
    ciphertext_hex: String,
}

/// Parse an encrypted keystore JSON string (T153).
///
/// Expected format:
/// ```json
/// {
///   "version": 1,
///   "suite_id": 100,
///   "aead": "ChaCha20-Poly1305",
///   "kdf": "PBKDF2-HMAC-SHA256",
///   "kdf_iterations": 100000,
///   "salt_hex": "...",
///   "nonce_hex": "...",
///   "ciphertext_hex": "..."
/// }
/// ```
fn parse_encrypted_keystore_json(
    json: &str,
) -> Result<ParsedEncryptedKeystoreEntry, KeystoreError> {
    let json = json.trim();

    if !json.starts_with('{') || !json.ends_with('}') {
        return Err(KeystoreError::Parse("expected JSON object".to_string()));
    }

    let inner = &json[1..json.len() - 1];

    let mut version: Option<u32> = None;
    let mut suite_id: Option<u8> = None;
    let mut kdf_iterations: Option<u32> = None;
    let mut salt_hex: Option<String> = None;
    let mut nonce_hex: Option<String> = None;
    let mut ciphertext_hex: Option<String> = None;

    let mut chars = inner.chars().peekable();

    loop {
        // Skip whitespace and commas
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        // Parse key
        if chars.next() != Some('"') {
            return Err(KeystoreError::Parse("expected quoted key".to_string()));
        }

        let mut key = String::new();
        loop {
            match chars.next() {
                Some('"') => break,
                Some(c) => key.push(c),
                None => return Err(KeystoreError::Parse("unterminated key string".to_string())),
            }
        }

        // Skip whitespace and colon
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.next() != Some(':') {
            return Err(KeystoreError::Parse("expected colon after key".to_string()));
        }
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }

        // Parse value based on key
        match key.as_str() {
            "version" | "suite_id" | "kdf_iterations" => {
                // Parse number
                let mut num_str = String::new();
                while chars.peek().is_some_and(|c| c.is_ascii_digit()) {
                    num_str.push(chars.next().unwrap());
                }

                match key.as_str() {
                    "version" => {
                        version =
                            Some(num_str.parse().map_err(|_| {
                                KeystoreError::Parse("invalid version".to_string())
                            })?);
                    }
                    "suite_id" => {
                        suite_id =
                            Some(num_str.parse().map_err(|_| {
                                KeystoreError::Parse("invalid suite_id".to_string())
                            })?);
                    }
                    "kdf_iterations" => {
                        kdf_iterations = Some(num_str.parse().map_err(|_| {
                            KeystoreError::Parse("invalid kdf_iterations".to_string())
                        })?);
                    }
                    _ => unreachable!(),
                }
            }
            "salt_hex" | "nonce_hex" | "ciphertext_hex" | "aead" | "kdf" => {
                // Parse string
                if chars.next() != Some('"') {
                    return Err(KeystoreError::Parse(format!(
                        "expected quoted string for {}",
                        key
                    )));
                }

                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => match chars.next() {
                            Some('n') => value.push('\n'),
                            Some('r') => value.push('\r'),
                            Some('t') => value.push('\t'),
                            Some('\\') => value.push('\\'),
                            Some('"') => value.push('"'),
                            Some(c) => {
                                value.push('\\');
                                value.push(c);
                            }
                            None => {
                                return Err(KeystoreError::Parse(
                                    "unterminated escape sequence".to_string(),
                                ))
                            }
                        },
                        Some(c) => value.push(c),
                        None => {
                            return Err(KeystoreError::Parse(
                                "unterminated value string".to_string(),
                            ))
                        }
                    }
                }

                match key.as_str() {
                    "salt_hex" => salt_hex = Some(value),
                    "nonce_hex" => nonce_hex = Some(value),
                    "ciphertext_hex" => ciphertext_hex = Some(value),
                    "aead" | "kdf" => {} // Informational fields, ignored
                    _ => unreachable!(),
                }
            }
            _ => {
                // Skip unknown field
                if chars.peek() == Some(&'"') {
                    chars.next();
                    loop {
                        match chars.next() {
                            Some('"') => break,
                            Some('\\') => {
                                chars.next();
                            }
                            Some(_) => {}
                            None => {
                                return Err(KeystoreError::Parse("unterminated string".to_string()))
                            }
                        }
                    }
                } else {
                    while chars.peek().is_some_and(|c| *c != ',' && *c != '}') {
                        chars.next();
                    }
                }
            }
        }
    }

    // Validate required fields
    let version =
        version.ok_or_else(|| KeystoreError::Parse("missing version field".to_string()))?;
    let suite_id =
        suite_id.ok_or_else(|| KeystoreError::Parse("missing suite_id field".to_string()))?;
    let kdf_iterations = kdf_iterations
        .ok_or_else(|| KeystoreError::Parse("missing kdf_iterations field".to_string()))?;
    let salt_hex =
        salt_hex.ok_or_else(|| KeystoreError::Parse("missing salt_hex field".to_string()))?;
    let nonce_hex =
        nonce_hex.ok_or_else(|| KeystoreError::Parse("missing nonce_hex field".to_string()))?;
    let ciphertext_hex = ciphertext_hex
        .ok_or_else(|| KeystoreError::Parse("missing ciphertext_hex field".to_string()))?;

    Ok(ParsedEncryptedKeystoreEntry {
        version,
        suite_id,
        kdf_iterations,
        salt_hex,
        nonce_hex,
        ciphertext_hex,
    })
}

/// Parsed plaintext entry (inside encrypted envelope).
struct ParsedPlaintextEntry {
    private_key_hex: String,
}

/// Parse plaintext JSON (decrypted content from encrypted keystore).
///
/// Expected format:
/// ```json
/// {
///   "private_key_hex": "..."
/// }
/// ```
fn parse_plaintext_json(json: &str) -> Result<ParsedPlaintextEntry, KeystoreError> {
    let json = json.trim();

    if !json.starts_with('{') || !json.ends_with('}') {
        return Err(KeystoreError::Parse("expected JSON object".to_string()));
    }

    let inner = &json[1..json.len() - 1];
    let mut private_key_hex: Option<String> = None;
    let mut chars = inner.chars().peekable();

    loop {
        // Skip whitespace and commas
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }

        if chars.peek().is_none() {
            break;
        }

        // Parse key
        if chars.next() != Some('"') {
            return Err(KeystoreError::Parse("expected quoted key".to_string()));
        }

        let mut key = String::new();
        loop {
            match chars.next() {
                Some('"') => break,
                Some(c) => key.push(c),
                None => return Err(KeystoreError::Parse("unterminated key string".to_string())),
            }
        }

        // Skip whitespace and colon
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        if chars.next() != Some(':') {
            return Err(KeystoreError::Parse("expected colon after key".to_string()));
        }
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }

        // Parse value
        if key == "private_key_hex" {
            // Parse string
            if chars.next() != Some('"') {
                return Err(KeystoreError::Parse(
                    "expected quoted string for private_key_hex".to_string(),
                ));
            }

            let mut value = String::new();
            loop {
                match chars.next() {
                    Some('"') => break,
                    Some('\\') => match chars.next() {
                        Some('n') => value.push('\n'),
                        Some('r') => value.push('\r'),
                        Some('t') => value.push('\t'),
                        Some('\\') => value.push('\\'),
                        Some('"') => value.push('"'),
                        Some(c) => {
                            value.push('\\');
                            value.push(c);
                        }
                        None => {
                            return Err(KeystoreError::Parse(
                                "unterminated escape sequence".to_string(),
                            ))
                        }
                    },
                    Some(c) => value.push(c),
                    None => {
                        return Err(KeystoreError::Parse(
                            "unterminated value string".to_string(),
                        ))
                    }
                }
            }
            private_key_hex = Some(value);
        } else {
            // Skip unknown field
            if chars.peek() == Some(&'"') {
                chars.next();
                loop {
                    match chars.next() {
                        Some('"') => break,
                        Some('\\') => {
                            chars.next();
                        }
                        Some(_) => {}
                        None => {
                            return Err(KeystoreError::Parse("unterminated string".to_string()))
                        }
                    }
                }
            } else {
                while chars.peek().is_some_and(|c| *c != ',' && *c != '}') {
                    chars.next();
                }
            }
        }
    }

    let private_key_hex = private_key_hex
        .ok_or_else(|| KeystoreError::Parse("missing private_key_hex field".to_string()))?;

    Ok(ParsedPlaintextEntry { private_key_hex })
}

// ============================================================================
// Hex encoding/decoding (minimal, no external deps)
// ============================================================================

/// Decode a hex string into bytes.
fn decode_hex(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex.trim();

    if !hex.len().is_multiple_of(2) {
        return Err("hex string has odd length".to_string());
    }

    let mut bytes = Vec::with_capacity(hex.len() / 2);

    for chunk in hex.as_bytes().chunks(2) {
        let high = hex_char_to_nibble(chunk[0])?;
        let low = hex_char_to_nibble(chunk[1])?;
        bytes.push((high << 4) | low);
    }

    Ok(bytes)
}

/// Encode bytes as a hex string.
#[cfg(test)]
fn encode_hex(bytes: &[u8]) -> String {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        hex.push(HEX_CHARS[(byte >> 4) as usize] as char);
        hex.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
    }
    hex
}

fn hex_char_to_nibble(c: u8) -> Result<u8, String> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(format!("invalid hex character: {}", c as char)),
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use qbind_crypto::consensus_sig::ConsensusSigVerifier;
    use qbind_crypto::ml_dsa44::{MlDsa44Backend, ML_DSA_44_SECRET_KEY_SIZE};
    use std::fs::File;
    use std::io::Write;
    use tempfile::TempDir;

    /// Helper to create a test keystore file.
    fn write_keystore_file(dir: &TempDir, entry_id: &str, suite_id: u8, key_hex: &str) {
        let path = dir.path().join(format!("{}.json", entry_id));
        let mut file = File::create(path).expect("create file");
        writeln!(
            file,
            r#"{{"suite_id": {}, "private_key_hex": "{}"}}"#,
            suite_id, key_hex
        )
        .expect("write file");
    }

    /// Helper to create an encrypted keystore file (T153).
    fn write_encrypted_keystore_file(
        dir: &TempDir,
        entry_id: &str,
        suite_id: u8,
        key_hex: &str,
        passphrase: &str,
        kdf_iterations: u32,
    ) {
        use qbind_crypto::{
            derive_key_pbkdf2, AeadSuite, ChaCha20Poly1305Backend, CHACHA20_POLY1305_NONCE_SIZE,
            PBKDF2_SALT_SIZE,
        };

        // Generate random salt and nonce
        let salt = {
            let mut s = [0u8; PBKDF2_SALT_SIZE];
            // For tests, use a deterministic "random" salt based on entry_id
            for (i, byte) in entry_id.as_bytes().iter().enumerate() {
                if i < PBKDF2_SALT_SIZE {
                    s[i] = *byte;
                }
            }
            s
        };

        let nonce = {
            let mut n = [0u8; CHACHA20_POLY1305_NONCE_SIZE];
            // For tests, use a deterministic "random" nonce
            for (i, byte) in entry_id.as_bytes().iter().rev().enumerate() {
                if i < CHACHA20_POLY1305_NONCE_SIZE {
                    n[i] = byte.wrapping_add(1);
                }
            }
            n
        };

        // Derive encryption key from passphrase
        let encryption_key = derive_key_pbkdf2(passphrase.as_bytes(), &salt, kdf_iterations);

        // Create plaintext JSON
        let plaintext_json = format!(r#"{{"private_key_hex": "{}"}}"#, key_hex);

        // Encrypt with ChaCha20-Poly1305
        let aead = ChaCha20Poly1305Backend::new();
        let ciphertext = aead
            .seal(&encryption_key, &nonce, b"", plaintext_json.as_bytes())
            .expect("encryption should succeed");

        // Write encrypted file
        let path = dir.path().join(format!("{}.enc", entry_id));
        let mut file = File::create(path).expect("create file");
        writeln!(
            file,
            r#"{{
  "version": 1,
  "suite_id": {},
  "aead": "ChaCha20-Poly1305",
  "kdf": "PBKDF2-HMAC-SHA256",
  "kdf_iterations": {},
  "salt_hex": "{}",
  "nonce_hex": "{}",
  "ciphertext_hex": "{}"
}}"#,
            suite_id,
            kdf_iterations,
            encode_hex(&salt),
            encode_hex(&nonce),
            encode_hex(&ciphertext)
        )
        .expect("write file");
    }

    // ------------------------------------------------------------------------
    // Happy path tests
    // ------------------------------------------------------------------------

    #[test]
    fn load_signing_key_happy_path() {
        // Generate a real ML-DSA-44 keypair
        let (pk, sk) = MlDsa44Backend::generate_keypair()
            .expect("ML-DSA-44 keypair generation should succeed");

        // Create temp directory and write keystore file
        let temp_dir = TempDir::new().expect("create temp dir");
        let key_hex = encode_hex(&sk);
        write_keystore_file(&temp_dir, "validator1", EXPECTED_SUITE_ID, &key_hex);

        // Load key from keystore
        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });
        let loaded_key = keystore
            .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
            .expect("load_signing_key should succeed");

        // Verify key works for signing
        let message = b"test message for keystore";
        let signature = loaded_key.sign(message).expect("signing should succeed");

        // Verify signature
        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(1, &pk, message, &signature);
        assert!(result.is_ok(), "signature should verify, got: {:?}", result);
    }

    #[test]
    fn load_signing_key_with_whitespace_in_json() {
        let (pk, sk) = MlDsa44Backend::generate_keypair()
            .expect("ML-DSA-44 keypair generation should succeed");

        let temp_dir = TempDir::new().expect("create temp dir");
        let key_hex = encode_hex(&sk);

        // Write JSON with extra whitespace and newlines
        let path = temp_dir.path().join("validator1.json");
        let mut file = File::create(path).expect("create file");
        writeln!(
            file,
            r#"{{
                "suite_id" : {},
                "private_key_hex" : "{}"
            }}"#,
            EXPECTED_SUITE_ID, key_hex
        )
        .expect("write file");

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });
        let loaded_key = keystore
            .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
            .expect("load_signing_key should succeed");

        // Verify key works
        let message = b"test";
        let signature = loaded_key.sign(message).expect("signing should succeed");
        let backend = MlDsa44Backend::new();
        assert!(backend.verify_vote(1, &pk, message, &signature).is_ok());
    }

    // ------------------------------------------------------------------------
    // Error case tests
    // ------------------------------------------------------------------------

    #[test]
    fn load_signing_key_missing_file() {
        let temp_dir = TempDir::new().expect("create temp dir");

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });

        let result = keystore.load_signing_key(&LocalKeystoreEntryId("nonexistent".to_string()));

        match result {
            Err(KeystoreError::NotFound(entry)) => {
                assert_eq!(entry, "nonexistent");
            }
            other => panic!("expected NotFound error, got: {:?}", other),
        }
    }

    #[test]
    fn load_signing_key_malformed_json() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Write malformed JSON
        let path = temp_dir.path().join("validator1.json");
        let mut file = File::create(path).expect("create file");
        writeln!(file, "not valid json").expect("write file");

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });

        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        match result {
            Err(KeystoreError::Parse(_)) => {}
            other => panic!("expected Parse error, got: {:?}", other),
        }
    }

    #[test]
    fn load_signing_key_missing_suite_id() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Write JSON missing suite_id
        let path = temp_dir.path().join("validator1.json");
        let mut file = File::create(path).expect("create file");
        writeln!(file, r#"{{"private_key_hex": "00"}}"#).expect("write file");

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });

        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        match result {
            Err(KeystoreError::Parse(msg)) => {
                assert!(msg.contains("suite_id"), "error should mention suite_id");
            }
            other => panic!("expected Parse error, got: {:?}", other),
        }
    }

    #[test]
    fn load_signing_key_missing_private_key_hex() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Write JSON missing private_key_hex
        let path = temp_dir.path().join("validator1.json");
        let mut file = File::create(path).expect("create file");
        writeln!(file, r#"{{"suite_id": 100}}"#).expect("write file");

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });

        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        match result {
            Err(KeystoreError::Parse(msg)) => {
                assert!(
                    msg.contains("private_key_hex"),
                    "error should mention private_key_hex"
                );
            }
            other => panic!("expected Parse error, got: {:?}", other),
        }
    }

    #[test]
    fn load_signing_key_wrong_suite_id() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Write JSON with wrong suite_id
        let key_hex = encode_hex(&vec![0u8; ML_DSA_44_SECRET_KEY_SIZE]);
        write_keystore_file(&temp_dir, "validator1", 99, &key_hex); // Wrong suite_id

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });

        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        match result {
            Err(KeystoreError::InvalidKey) => {}
            other => panic!("expected InvalidKey error, got: {:?}", other),
        }
    }

    #[test]
    fn load_signing_key_invalid_hex() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Write JSON with invalid hex
        let path = temp_dir.path().join("validator1.json");
        let mut file = File::create(path).expect("create file");
        writeln!(
            file,
            r#"{{"suite_id": {}, "private_key_hex": "not_valid_hex!"}}"#,
            EXPECTED_SUITE_ID
        )
        .expect("write file");

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });

        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        match result {
            Err(KeystoreError::Parse(msg)) => {
                assert!(msg.contains("hex"), "error should mention hex");
            }
            other => panic!("expected Parse error, got: {:?}", other),
        }
    }

    #[test]
    fn load_signing_key_odd_length_hex() {
        let temp_dir = TempDir::new().expect("create temp dir");

        // Write JSON with odd-length hex
        let path = temp_dir.path().join("validator1.json");
        let mut file = File::create(path).expect("create file");
        writeln!(
            file,
            r#"{{"suite_id": {}, "private_key_hex": "abc"}}"#, // Odd length
            EXPECTED_SUITE_ID
        )
        .expect("write file");

        let keystore = FsValidatorKeystore::new(KeystoreConfig {
            root: temp_dir.path().to_path_buf(),
        });

        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        match result {
            Err(KeystoreError::Parse(msg)) => {
                assert!(
                    msg.contains("hex") || msg.contains("odd"),
                    "error should mention hex issue"
                );
            }
            other => panic!("expected Parse error, got: {:?}", other),
        }
    }

    // ------------------------------------------------------------------------
    // Hex encoding/decoding tests
    // ------------------------------------------------------------------------

    #[test]
    fn hex_roundtrip() {
        let original = vec![0x00, 0x0f, 0xf0, 0xff, 0x12, 0xab];
        let hex = encode_hex(&original);
        let decoded = decode_hex(&hex).expect("decode should succeed");
        assert_eq!(original, decoded);
    }

    #[test]
    fn hex_decode_uppercase() {
        let decoded = decode_hex("ABCDEF").expect("decode should succeed");
        assert_eq!(decoded, vec![0xab, 0xcd, 0xef]);
    }

    #[test]
    fn hex_decode_mixed_case() {
        let decoded = decode_hex("AbCdEf").expect("decode should succeed");
        assert_eq!(decoded, vec![0xab, 0xcd, 0xef]);
    }

    // ------------------------------------------------------------------------
    // JSON parsing tests
    // ------------------------------------------------------------------------

    #[test]
    fn parse_json_with_extra_fields() {
        // Extra fields should be ignored
        let json = r#"{"suite_id": 100, "private_key_hex": "00ff", "extra": "ignored"}"#;
        let parsed = parse_keystore_json(json).expect("parse should succeed");
        assert_eq!(parsed.suite_id, 100);
        assert_eq!(parsed.private_key_hex, "00ff");
    }

    #[test]
    fn parse_json_fields_in_any_order() {
        // Fields can be in any order
        let json = r#"{"private_key_hex": "00ff", "suite_id": 100}"#;
        let parsed = parse_keystore_json(json).expect("parse should succeed");
        assert_eq!(parsed.suite_id, 100);
        assert_eq!(parsed.private_key_hex, "00ff");
    }

    // ------------------------------------------------------------------------
    // Encrypted keystore tests (T153)
    // ------------------------------------------------------------------------

    #[test]
    fn encrypted_keystore_happy_path() {
        use qbind_crypto::DEFAULT_PBKDF2_ITERATIONS;

        // Generate a real ML-DSA-44 keypair
        let (pk, sk) = MlDsa44Backend::generate_keypair()
            .expect("ML-DSA-44 keypair generation should succeed");

        // Create temp directory and write encrypted keystore file
        let temp_dir = TempDir::new().expect("create temp dir");
        let key_hex = encode_hex(&sk);
        let passphrase = "test-passphrase-12345";

        // Set passphrase in environment
        std::env::set_var("QBIND_TEST_PASSPHRASE", passphrase);

        write_encrypted_keystore_file(
            &temp_dir,
            "validator1",
            EXPECTED_SUITE_ID,
            &key_hex,
            passphrase,
            DEFAULT_PBKDF2_ITERATIONS,
        );

        // Load key from encrypted keystore
        let enc_config = EncryptedKeystoreConfig {
            passphrase_env_var: "QBIND_TEST_PASSPHRASE".to_string(),
            kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
        };
        let keystore = EncryptedFsValidatorKeystore::new(temp_dir.path().to_path_buf(), enc_config);
        let loaded_key = keystore
            .load_signing_key(&LocalKeystoreEntryId("validator1".to_string()))
            .expect("load_signing_key should succeed");

        // Verify key works for signing
        let message = b"test message for encrypted keystore";
        let signature = loaded_key.sign(message).expect("signing should succeed");

        // Verify signature
        let backend = MlDsa44Backend::new();
        let result = backend.verify_vote(1, &pk, message, &signature);
        assert!(result.is_ok(), "signature should verify, got: {:?}", result);

        // Clean up
        std::env::remove_var("QBIND_TEST_PASSPHRASE");
    }

    #[test]
    fn encrypted_keystore_wrong_passphrase() {
        use qbind_crypto::DEFAULT_PBKDF2_ITERATIONS;

        let (_, sk) = MlDsa44Backend::generate_keypair()
            .expect("ML-DSA-44 keypair generation should succeed");

        let temp_dir = TempDir::new().expect("create temp dir");
        let key_hex = encode_hex(&sk);
        let correct_passphrase = "correct-passphrase";
        let wrong_passphrase = "wrong-passphrase";

        // Create file with correct passphrase
        write_encrypted_keystore_file(
            &temp_dir,
            "validator1",
            EXPECTED_SUITE_ID,
            &key_hex,
            correct_passphrase,
            DEFAULT_PBKDF2_ITERATIONS,
        );

        // Try to load with wrong passphrase
        std::env::set_var("QBIND_TEST_PASSPHRASE_WRONG", wrong_passphrase);

        let enc_config = EncryptedKeystoreConfig {
            passphrase_env_var: "QBIND_TEST_PASSPHRASE_WRONG".to_string(),
            kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
        };
        let keystore = EncryptedFsValidatorKeystore::new(temp_dir.path().to_path_buf(), enc_config);
        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        // Should fail with InvalidKey (decryption failure)
        match result {
            Err(KeystoreError::InvalidKey) => {}
            other => panic!(
                "expected InvalidKey error for wrong passphrase, got: {:?}",
                other
            ),
        }

        std::env::remove_var("QBIND_TEST_PASSPHRASE_WRONG");
    }

    #[test]
    fn encrypted_keystore_missing_env_var() {
        use qbind_crypto::DEFAULT_PBKDF2_ITERATIONS;

        let (_, sk) = MlDsa44Backend::generate_keypair()
            .expect("ML-DSA-44 keypair generation should succeed");

        let temp_dir = TempDir::new().expect("create temp dir");
        let key_hex = encode_hex(&sk);

        write_encrypted_keystore_file(
            &temp_dir,
            "validator1",
            EXPECTED_SUITE_ID,
            &key_hex,
            "some-passphrase",
            DEFAULT_PBKDF2_ITERATIONS,
        );

        // Ensure env var is not set
        std::env::remove_var("QBIND_TEST_MISSING");

        let enc_config = EncryptedKeystoreConfig {
            passphrase_env_var: "QBIND_TEST_MISSING".to_string(),
            kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
        };
        let keystore = EncryptedFsValidatorKeystore::new(temp_dir.path().to_path_buf(), enc_config);
        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        // Should fail with Config error
        match result {
            Err(KeystoreError::Config(msg)) => {
                assert!(
                    msg.contains("QBIND_TEST_MISSING"),
                    "error should mention the env var name"
                );
            }
            other => panic!(
                "expected Config error for missing env var, got: {:?}",
                other
            ),
        }
    }

    #[test]
    fn encrypted_keystore_wrong_suite_id() {
        use qbind_crypto::DEFAULT_PBKDF2_ITERATIONS;

        let temp_dir = TempDir::new().expect("create temp dir");
        let key_hex = encode_hex(&vec![0u8; ML_DSA_44_SECRET_KEY_SIZE]);
        let passphrase = "test-passphrase";

        // Write encrypted file with wrong suite_id
        write_encrypted_keystore_file(
            &temp_dir,
            "validator1",
            99, // Wrong suite_id
            &key_hex,
            passphrase,
            DEFAULT_PBKDF2_ITERATIONS,
        );

        std::env::set_var("QBIND_TEST_PASSPHRASE_SUITE", passphrase);

        let enc_config = EncryptedKeystoreConfig {
            passphrase_env_var: "QBIND_TEST_PASSPHRASE_SUITE".to_string(),
            kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
        };
        let keystore = EncryptedFsValidatorKeystore::new(temp_dir.path().to_path_buf(), enc_config);
        let result = keystore.load_signing_key(&LocalKeystoreEntryId("validator1".to_string()));

        // Should fail with InvalidKey
        match result {
            Err(KeystoreError::InvalidKey) => {}
            other => panic!(
                "expected InvalidKey error for wrong suite_id, got: {:?}",
                other
            ),
        }

        std::env::remove_var("QBIND_TEST_PASSPHRASE_SUITE");
    }

    #[test]
    fn encrypted_keystore_missing_file() {
        use qbind_crypto::DEFAULT_PBKDF2_ITERATIONS;

        let temp_dir = TempDir::new().expect("create temp dir");

        std::env::set_var("QBIND_TEST_PASSPHRASE_MISSING", "passphrase");

        let enc_config = EncryptedKeystoreConfig {
            passphrase_env_var: "QBIND_TEST_PASSPHRASE_MISSING".to_string(),
            kdf_iterations: DEFAULT_PBKDF2_ITERATIONS,
        };
        let keystore = EncryptedFsValidatorKeystore::new(temp_dir.path().to_path_buf(), enc_config);
        let result = keystore.load_signing_key(&LocalKeystoreEntryId("nonexistent".to_string()));

        // Should fail with NotFound
        match result {
            Err(KeystoreError::NotFound(entry)) => {
                assert_eq!(entry, "nonexistent");
            }
            other => panic!("expected NotFound error, got: {:?}", other),
        }

        std::env::remove_var("QBIND_TEST_PASSPHRASE_MISSING");
    }
}
