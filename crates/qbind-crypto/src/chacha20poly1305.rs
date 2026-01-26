//! ChaCha20-Poly1305 AEAD backend for KEMTLS data path.
//!
//! This module provides a production-grade AEAD implementation using ChaCha20-Poly1305,
//! which is suitable for encrypting application data over the KEMTLS secure channel.
//!
//! # Security Properties
//!
//! - **Key Size**: 256 bits (32 bytes)
//! - **Nonce Size**: 96 bits (12 bytes)
//! - **Tag Size**: 128 bits (16 bytes)
//! - **Security Level**: ~128 bits against generic attacks
//!
//! # Usage Notes
//!
//! - Each (key, nonce) pair must be unique across all messages
//! - The caller is responsible for nonce management (typically using counters)
//! - AAD (associated authenticated data) is authenticated but not encrypted

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};

use crate::aead::AeadSuite;
use crate::error::CryptoError;

/// Suite ID for ChaCha20-Poly1305 in the QBIND protocol.
///
/// This value is chosen to be distinct from DummyAead suite IDs used in tests.
/// Value 101 follows the ML-KEM-768 suite ID (100) in the PQC range.
pub const AEAD_SUITE_CHACHA20_POLY1305: u8 = 101;

/// Key size for ChaCha20-Poly1305 (256 bits).
pub const CHACHA20_POLY1305_KEY_SIZE: usize = 32;

/// Nonce size for ChaCha20-Poly1305 (96 bits).
pub const CHACHA20_POLY1305_NONCE_SIZE: usize = 12;

/// Tag size for ChaCha20-Poly1305 (128 bits).
pub const CHACHA20_POLY1305_TAG_SIZE: usize = 16;

/// ChaCha20-Poly1305 AEAD backend implementing the `AeadSuite` trait.
///
/// This is a stateless backend that performs AEAD operations using the
/// ChaCha20-Poly1305 cipher suite. Nonce management is handled by the caller
/// (typically `AeadSession` in qbind-net).
///
/// # Example
///
/// ```ignore
/// use qbind_crypto::{ChaCha20Poly1305Backend, AeadSuite};
///
/// let backend = ChaCha20Poly1305Backend::new();
/// let key = [0u8; 32];
/// let nonce = [0u8; 12];
/// let aad = b"header";
/// let plaintext = b"secret message";
///
/// let ciphertext = backend.seal(&key, &nonce, aad, plaintext).unwrap();
/// let decrypted = backend.open(&key, &nonce, aad, &ciphertext).unwrap();
/// assert_eq!(plaintext, &decrypted[..]);
/// ```
#[derive(Debug, Clone, Copy)]
pub struct ChaCha20Poly1305Backend {
    suite_id: u8,
}

impl Default for ChaCha20Poly1305Backend {
    fn default() -> Self {
        Self::new()
    }
}

impl ChaCha20Poly1305Backend {
    /// Create a new ChaCha20-Poly1305 backend instance.
    #[inline]
    pub fn new() -> Self {
        ChaCha20Poly1305Backend {
            suite_id: AEAD_SUITE_CHACHA20_POLY1305,
        }
    }
}

impl AeadSuite for ChaCha20Poly1305Backend {
    #[inline]
    fn suite_id(&self) -> u8 {
        self.suite_id
    }

    #[inline]
    fn key_len(&self) -> usize {
        CHACHA20_POLY1305_KEY_SIZE
    }

    #[inline]
    fn nonce_len(&self) -> usize {
        CHACHA20_POLY1305_NONCE_SIZE
    }

    #[inline]
    fn tag_len(&self) -> usize {
        CHACHA20_POLY1305_TAG_SIZE
    }

    /// Seal (encrypt + authenticate) a message using ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 12-byte unique nonce (must not be reused with the same key)
    /// * `aad` - Associated authenticated data (not encrypted, but authenticated)
    /// * `plaintext` - Data to encrypt
    ///
    /// # Returns
    ///
    /// On success, returns `ciphertext || tag` where tag is 16 bytes.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if key length is incorrect.
    fn seal(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Validate key length
        if key.len() != CHACHA20_POLY1305_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }

        // Validate nonce length
        if nonce.len() != CHACHA20_POLY1305_NONCE_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Create cipher instance from key
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

        // Create nonce from slice
        let nonce = Nonce::from_slice(nonce);

        // Create payload with AAD
        use chacha20poly1305::aead::Payload;
        let payload = Payload {
            msg: plaintext,
            aad,
        };

        // Encrypt and authenticate
        let ciphertext = cipher
            .encrypt(nonce, payload)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        Ok(ciphertext)
    }

    /// Open (decrypt + verify) a message using ChaCha20-Poly1305.
    ///
    /// # Arguments
    ///
    /// * `key` - 32-byte encryption key
    /// * `nonce` - 12-byte nonce (must match the nonce used for sealing)
    /// * `aad` - Associated authenticated data (must match what was used for sealing)
    /// * `ciphertext_and_tag` - Encrypted data with authentication tag appended
    ///
    /// # Returns
    ///
    /// On success, returns the decrypted plaintext.
    ///
    /// # Errors
    ///
    /// Returns `CryptoError::InvalidKey` if key length is incorrect.
    /// Returns `CryptoError::InvalidCiphertext` if authentication fails or ciphertext is malformed.
    fn open(
        &self,
        key: &[u8],
        nonce: &[u8],
        aad: &[u8],
        ciphertext_and_tag: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        // Validate key length
        if key.len() != CHACHA20_POLY1305_KEY_SIZE {
            return Err(CryptoError::InvalidKey);
        }

        // Validate nonce length
        if nonce.len() != CHACHA20_POLY1305_NONCE_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Ciphertext must be at least tag_len bytes
        if ciphertext_and_tag.len() < CHACHA20_POLY1305_TAG_SIZE {
            return Err(CryptoError::InvalidCiphertext);
        }

        // Create cipher instance from key
        let cipher = ChaCha20Poly1305::new_from_slice(key).map_err(|_| CryptoError::InvalidKey)?;

        // Create nonce from slice
        let nonce = Nonce::from_slice(nonce);

        // Create payload with AAD
        use chacha20poly1305::aead::Payload;
        let payload = Payload {
            msg: ciphertext_and_tag,
            aad,
        };

        // Decrypt and verify
        let plaintext = cipher
            .decrypt(nonce, payload)
            .map_err(|_| CryptoError::InvalidCiphertext)?;

        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_open_roundtrip() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"header data";
        let plaintext = b"secret message for encryption";

        let ciphertext = backend.seal(&key, &nonce, aad, plaintext).unwrap();
        let decrypted = backend.open(&key, &nonce, aad, &ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_ciphertext_length() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"aad";
        let plaintext = b"test";

        let ciphertext = backend.seal(&key, &nonce, aad, plaintext).unwrap();

        // Ciphertext should be plaintext + 16-byte tag
        assert_eq!(
            ciphertext.len(),
            plaintext.len() + CHACHA20_POLY1305_TAG_SIZE
        );
    }

    #[test]
    fn test_different_nonces_produce_different_ciphertext() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce1 = [0x01u8; 12];
        let nonce2 = [0x02u8; 12];
        let aad = b"aad";
        let plaintext = b"same plaintext";

        let ct1 = backend.seal(&key, &nonce1, aad, plaintext).unwrap();
        let ct2 = backend.seal(&key, &nonce2, aad, plaintext).unwrap();

        assert_ne!(
            ct1, ct2,
            "Different nonces should produce different ciphertext"
        );
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"header";
        let plaintext = b"secret message";

        let mut ciphertext = backend.seal(&key, &nonce, aad, plaintext).unwrap();

        // Tamper with ciphertext
        ciphertext[0] ^= 0xff;

        let result = backend.open(&key, &nonce, aad, &ciphertext);
        assert!(
            result.is_err(),
            "Tampered ciphertext should fail to decrypt"
        );
    }

    #[test]
    fn test_wrong_aad_fails() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad_seal = b"correct header";
        let aad_open = b"wrong header";
        let plaintext = b"secret";

        let ciphertext = backend.seal(&key, &nonce, aad_seal, plaintext).unwrap();

        let result = backend.open(&key, &nonce, aad_open, &ciphertext);
        assert!(result.is_err(), "Wrong AAD should fail to decrypt");
    }

    #[test]
    fn test_wrong_key_fails() {
        let backend = ChaCha20Poly1305Backend::new();

        let key_seal = [0x42u8; 32];
        let key_open = [0x43u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"aad";
        let plaintext = b"secret";

        let ciphertext = backend.seal(&key_seal, &nonce, aad, plaintext).unwrap();

        let result = backend.open(&key_open, &nonce, aad, &ciphertext);
        assert!(result.is_err(), "Wrong key should fail to decrypt");
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce_seal = [0x01u8; 12];
        let nonce_open = [0x02u8; 12];
        let aad = b"aad";
        let plaintext = b"secret";

        let ciphertext = backend.seal(&key, &nonce_seal, aad, plaintext).unwrap();

        let result = backend.open(&key, &nonce_open, aad, &ciphertext);
        assert!(result.is_err(), "Wrong nonce should fail to decrypt");
    }

    #[test]
    fn test_empty_plaintext() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"aad";
        let plaintext = b"";

        let ciphertext = backend.seal(&key, &nonce, aad, plaintext).unwrap();
        assert_eq!(ciphertext.len(), CHACHA20_POLY1305_TAG_SIZE);

        let decrypted = backend.open(&key, &nonce, aad, &ciphertext).unwrap();
        assert!(decrypted.is_empty());
    }

    #[test]
    fn test_empty_aad() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"";
        let plaintext = b"secret";

        let ciphertext = backend.seal(&key, &nonce, aad, plaintext).unwrap();
        let decrypted = backend.open(&key, &nonce, aad, &ciphertext).unwrap();

        assert_eq!(plaintext, &decrypted[..]);
    }

    #[test]
    fn test_large_message() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"large message test";
        let plaintext: Vec<u8> = (0..8192).map(|i| (i % 256) as u8).collect();

        let ciphertext = backend.seal(&key, &nonce, aad, &plaintext).unwrap();
        let decrypted = backend.open(&key, &nonce, aad, &ciphertext).unwrap();

        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_invalid_key_length() {
        let backend = ChaCha20Poly1305Backend::new();

        let key_short = [0x42u8; 16]; // Too short
        let nonce = [0x01u8; 12];
        let aad = b"aad";
        let plaintext = b"secret";

        let result = backend.seal(&key_short, &nonce, aad, plaintext);
        assert!(result.is_err(), "Short key should fail");
    }

    #[test]
    fn test_invalid_nonce_length() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce_short = [0x01u8; 8]; // Too short
        let aad = b"aad";
        let plaintext = b"secret";

        let result = backend.seal(&key, &nonce_short, aad, plaintext);
        assert!(result.is_err(), "Short nonce should fail");
    }

    #[test]
    fn test_suite_constants() {
        let backend = ChaCha20Poly1305Backend::new();

        assert_eq!(backend.suite_id(), AEAD_SUITE_CHACHA20_POLY1305);
        assert_eq!(backend.suite_id(), 101);
        assert_eq!(backend.key_len(), 32);
        assert_eq!(backend.nonce_len(), 12);
        assert_eq!(backend.tag_len(), 16);
    }

    #[test]
    fn test_truncated_ciphertext_fails() {
        let backend = ChaCha20Poly1305Backend::new();

        let key = [0x42u8; 32];
        let nonce = [0x01u8; 12];
        let aad = b"aad";

        // Ciphertext shorter than tag size
        let short_ct = [0u8; 8];
        let result = backend.open(&key, &nonce, aad, &short_ct);
        assert!(result.is_err(), "Truncated ciphertext should fail");
    }
}
