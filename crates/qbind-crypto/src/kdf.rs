//! Key Derivation Functions (KDF) for QBIND.
//!
//! This module provides KDF primitives used for deriving encryption keys
//! from passphrases (e.g., for encrypted keystores).
//!
//! # T153: Encrypted Keystore
//!
//! The encrypted keystore v1 uses PBKDF2-HMAC-SHA256 to derive an encryption
//! key from a user-provided passphrase.

use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// Default number of PBKDF2 iterations for encrypted keystore v1.
///
/// This value balances security and performance for DevNet:
/// - ~100ms on modern hardware
/// - Sufficient for development/testing use cases
/// - May be increased for TestNet/MainNet
pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt size for PBKDF2 (16 bytes = 128 bits).
///
/// This provides sufficient entropy for salt uniqueness.
pub const PBKDF2_SALT_SIZE: usize = 16;

/// Derived key size for PBKDF2 output (32 bytes = 256 bits).
///
/// This matches the key size for ChaCha20-Poly1305 AEAD.
pub const PBKDF2_OUTPUT_SIZE: usize = 32;

/// Derive an encryption key from a passphrase using PBKDF2-HMAC-SHA256.
///
/// # Parameters
///
/// - `passphrase`: The user-provided passphrase (UTF-8 bytes)
/// - `salt`: Random salt (should be unique per encrypted key)
/// - `iterations`: Number of PBKDF2 iterations (higher = more secure but slower)
///
/// # Returns
///
/// A 32-byte encryption key suitable for use with ChaCha20-Poly1305.
///
/// # Security Notes
///
/// - The salt MUST be unique for each encrypted key
/// - The salt does NOT need to be secret (can be stored alongside ciphertext)
/// - Higher iteration counts provide more resistance to brute-force attacks
/// - The output key should be zeroized after use
///
/// # Example
///
/// ```ignore
/// use qbind_crypto::kdf::derive_key_pbkdf2;
///
/// let passphrase = b"my-secure-passphrase";
/// let salt = [0u8; 16]; // In practice, use random salt
/// let iterations = 100_000;
///
/// let key = derive_key_pbkdf2(passphrase, &salt, iterations);
/// // Use key for AEAD encryption
/// ```
pub fn derive_key_pbkdf2(
    passphrase: &[u8],
    salt: &[u8],
    iterations: u32,
) -> [u8; PBKDF2_OUTPUT_SIZE] {
    let mut output = [0u8; PBKDF2_OUTPUT_SIZE];
    pbkdf2_hmac::<Sha256>(passphrase, salt, iterations, &mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_pbkdf2_produces_correct_length() {
        let passphrase = b"test-passphrase";
        let salt = [42u8; PBKDF2_SALT_SIZE];
        let iterations = 1000;

        let key = derive_key_pbkdf2(passphrase, &salt, iterations);
        assert_eq!(key.len(), PBKDF2_OUTPUT_SIZE);
    }

    #[test]
    fn derive_key_pbkdf2_is_deterministic() {
        let passphrase = b"test-passphrase";
        let salt = [42u8; PBKDF2_SALT_SIZE];
        let iterations = 1000;

        let key1 = derive_key_pbkdf2(passphrase, &salt, iterations);
        let key2 = derive_key_pbkdf2(passphrase, &salt, iterations);

        assert_eq!(key1, key2);
    }

    #[test]
    fn derive_key_pbkdf2_different_passphrase_produces_different_key() {
        let salt = [42u8; PBKDF2_SALT_SIZE];
        let iterations = 1000;

        let key1 = derive_key_pbkdf2(b"passphrase1", &salt, iterations);
        let key2 = derive_key_pbkdf2(b"passphrase2", &salt, iterations);

        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_pbkdf2_different_salt_produces_different_key() {
        let passphrase = b"test-passphrase";
        let iterations = 1000;

        let key1 = derive_key_pbkdf2(passphrase, &[1u8; PBKDF2_SALT_SIZE], iterations);
        let key2 = derive_key_pbkdf2(passphrase, &[2u8; PBKDF2_SALT_SIZE], iterations);

        assert_ne!(key1, key2);
    }

    #[test]
    fn derive_key_pbkdf2_different_iterations_produces_different_key() {
        let passphrase = b"test-passphrase";
        let salt = [42u8; PBKDF2_SALT_SIZE];

        let key1 = derive_key_pbkdf2(passphrase, &salt, 1000);
        let key2 = derive_key_pbkdf2(passphrase, &salt, 2000);

        assert_ne!(key1, key2);
    }
}
