use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::hkdf::{hkdf_expand_label, hkdf_extract};

// ============================================================================
// T141/T142: Zeroizing Key Wrappers
// ============================================================================

/// KEM private key wrapper with zeroization on drop (T142).
///
/// This wrapper holds the KEM private key used in KEMTLS server-side
/// decapsulation and ensures it is zeroized when dropped.
///
/// # Security Properties
///
/// - `ZeroizeOnDrop`: Private key is overwritten with zeros when dropped.
/// - No `Clone`: Prevents accidental key duplication.
/// - No `Copy`: Private keys should not be implicitly copied.
/// - Custom `Debug`: Never prints actual key bytes.
///
/// # Lifecycle
///
/// The KEM private key is typically long-lived:
/// 1. Loaded from secure storage at node startup
/// 2. Used in KEMTLS handshakes for decapsulation
/// 3. Zeroized when the server config is dropped or node shuts down
///
/// # Usage
///
/// ```ignore
/// let sk = KemPrivateKey::new(secret_key_bytes);
/// // Use sk.as_bytes() for KEM decapsulation
/// drop(sk); // Key is zeroized here
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct KemPrivateKey {
    bytes: Vec<u8>,
}

impl KemPrivateKey {
    /// Create a new KEM private key from a byte vector.
    ///
    /// Takes ownership of the vector to avoid copying key material.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Access the raw private key bytes.
    ///
    /// # Security Note
    ///
    /// The returned reference should be used immediately for KEM decapsulation
    /// and not stored. The underlying bytes are zeroized when this wrapper is dropped.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the private key.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the private key is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for KemPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KemPrivateKey")
            .field("bytes", &format!("<redacted:{}>", self.bytes.len()))
            .finish()
    }
}

/// Variable-length AEAD key material with zeroization on drop.
///
/// This wrapper ensures that key material is zeroized when dropped, preventing
/// key leakage through memory disclosure attacks. It supports variable-length
/// keys to accommodate different AEAD suites (e.g., ChaCha20-Poly1305 uses 32 bytes).
///
/// # Security Properties
///
/// - `ZeroizeOnDrop`: Key bytes are overwritten with zeros when dropped.
/// - No `Clone` or `Copy`: Prevents accidental key duplication.
/// - Custom `Debug`: Never prints actual key bytes.
///
/// # Usage
///
/// ```ignore
/// let key = AeadKeyMaterial::from_vec(vec![0u8; 32]);
/// // Use key.as_bytes() to access key material
/// drop(key); // Key is zeroized here
/// ```
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct AeadKeyMaterial {
    bytes: Vec<u8>,
}

impl AeadKeyMaterial {
    /// Create a new AEAD key from a byte vector.
    ///
    /// Takes ownership of the vector to avoid copying key material.
    pub fn from_vec(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Create a new AEAD key from a slice.
    ///
    /// Copies the slice into a new vector. Prefer `from_vec` when possible
    /// to avoid extra copies of key material.
    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            bytes: slice.to_vec(),
        }
    }

    /// Access the raw key bytes.
    ///
    /// # Security Note
    ///
    /// The returned reference should be used immediately and not stored.
    /// The underlying bytes are zeroized when this wrapper is dropped.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the key material.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the key is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for AeadKeyMaterial {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AeadKeyMaterial")
            .field("bytes", &format!("<redacted:{}>", self.bytes.len()))
            .finish()
    }
}

/// KEM shared secret wrapper with zeroization on drop.
///
/// This wrapper holds the shared secret produced by KEM encapsulation/decapsulation
/// and ensures it is zeroized after use.
///
/// # Security Properties
///
/// - `ZeroizeOnDrop`: Shared secret is overwritten with zeros when dropped.
/// - No `Clone`: Prevents accidental secret duplication.
/// - Custom `Debug`: Never prints actual secret bytes.
///
/// # Lifecycle
///
/// The shared secret should be consumed immediately after KEM operations:
/// 1. KEM encaps/decaps produces the shared secret
/// 2. HKDF extract uses the secret to derive PRK
/// 3. SharedSecret is dropped and zeroized
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SharedSecret {
    bytes: Vec<u8>,
}

impl SharedSecret {
    /// Create a new shared secret from a byte vector.
    ///
    /// Takes ownership of the vector to avoid copying secrets.
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Access the raw secret bytes.
    ///
    /// # Security Note
    ///
    /// The returned reference should be used immediately and not stored.
    /// The underlying bytes are zeroized when this wrapper is dropped.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Get the length of the shared secret.
    #[inline]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Check if the shared secret is empty.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl std::fmt::Debug for SharedSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedSecret")
            .field("bytes", &format!("<redacted:{}>", self.bytes.len()))
            .finish()
    }
}

// ============================================================================
// SessionKeys (updated to use AeadKeyMaterial)
// ============================================================================

/// Session keys derived from a KEM shared secret and transcript hash.
///
/// # Security Properties (T141)
///
/// - `k_c2s` and `k_s2c` are wrapped in `AeadKeyMaterial` with `ZeroizeOnDrop`.
/// - When `SessionKeys` is dropped, all key material is automatically zeroized.
/// - No `Clone` implementation to prevent accidental key duplication.
///
/// # Key Derivation
///
/// Keys are derived using HKDF-SHA3:
/// ```text
/// PRK = HKDF-Extract(salt = "CANO:KDF" || transcript_hash, ikm = shared_secret)
/// session_id = HKDF-Expand-Label(PRK, "CANO:session-id", info, 3)
/// k_c2s = HKDF-Expand-Label(PRK, "CANO:k_c2s", info, key_len)
/// k_s2c = HKDF-Expand-Label(PRK, "CANO:k_s2c", info, key_len)
/// ```
pub struct SessionKeys {
    /// 3-byte session identifier (non-secret, used in nonce construction).
    pub session_id: [u8; 3],
    /// Client-to-server AEAD key (zeroized on drop).
    pub k_c2s: AeadKeyMaterial,
    /// Server-to-client AEAD key (zeroized on drop).
    pub k_s2c: AeadKeyMaterial,
    /// AEAD key length in bytes.
    pub key_len: usize,
}

impl std::fmt::Debug for SessionKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionKeys")
            .field("session_id", &self.session_id)
            .field("k_c2s", &"<redacted>")
            .field("k_s2c", &"<redacted>")
            .field("key_len", &self.key_len)
            .finish()
    }
}

impl SessionKeys {
    /// Derive session keys from:
    ///  - shared_secret: KEM shared secret,
    ///  - transcript_hash: hash of the KEMTLS transcript (caller-provided),
    ///  - kem_suite_id, aead_suite_id: one-byte identifiers,
    ///  - key_len: desired AEAD key length in bytes.
    ///
    /// HKDF layout:
    ///  - prk = HKDF-Extract(salt = "CANO:KDF" || transcript_hash, ikm = shared_secret)
    ///  - session_id = first 3 bytes of HKDF-Expand-Label(prk, "CANO:session-id", info, 3)
    ///  - k_c2s = HKDF-Expand-Label(prk, "CANO:k_c2s", info, key_len)
    ///  - k_s2c = HKDF-Expand-Label(prk, "CANO:k_s2c", info, key_len)
    ///
    /// where info = [kem_suite_id, aead_suite_id].
    ///
    /// # Security Notes (T141)
    ///
    /// - The PRK (pseudo-random key) is explicitly zeroized after key derivation.
    /// - All derived keys are wrapped in `AeadKeyMaterial` for automatic zeroization on drop.
    /// - The shared_secret parameter is borrowed; caller is responsible for zeroizing it.
    pub fn derive(
        shared_secret: &[u8],
        transcript_hash: &[u8],
        kem_suite_id: u8,
        aead_suite_id: u8,
        key_len: usize,
    ) -> Self {
        let mut salt = b"CANO:KDF".to_vec();
        salt.extend_from_slice(transcript_hash);

        // PRK is sensitive intermediate key material - will be zeroized at end of scope
        let mut prk = hkdf_extract(&salt, shared_secret);

        let info = [kem_suite_id, aead_suite_id];

        let sid_bytes = hkdf_expand_label(&prk, b"CANO:session-id", &info, 3);
        let mut session_id = [0u8; 3];
        session_id.copy_from_slice(&sid_bytes[..3]);

        // Derive keys and immediately wrap in zeroizing containers.
        // Using from_vec takes ownership, avoiding an extra copy of key material.
        let k_c2s_raw = hkdf_expand_label(&prk, b"CANO:k_c2s", &info, key_len);
        let k_s2c_raw = hkdf_expand_label(&prk, b"CANO:k_s2c", &info, key_len);

        let k_c2s = AeadKeyMaterial::from_vec(k_c2s_raw);
        let k_s2c = AeadKeyMaterial::from_vec(k_s2c_raw);

        // Explicitly zeroize the PRK now that keys are derived.
        // The k_c2s_raw and k_s2c_raw are moved into AeadKeyMaterial, so no need to zeroize.
        prk.zeroize();

        SessionKeys {
            session_id,
            k_c2s,
            k_s2c,
            key_len,
        }
    }
}
