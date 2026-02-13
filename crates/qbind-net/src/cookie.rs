//! DoS cookie protection for KEMTLS handshake (M6).
//!
//! This module implements a stateless cookie-based DoS mitigation mechanism
//! that requires clients to prove they received a server challenge before
//! expensive KEM decapsulation / session allocation occurs.
//!
//! # Cookie Design
//!
//! Cookie = HMAC-SHA3-256_k( client_ip || client_init_fields || timestamp_bucket || context_tag )
//!
//! Where:
//! - k = server-side secret key (rotated at startup)
//! - client_ip = client's IP address (4 or 16 bytes)
//! - client_init_fields = kem_suite_id || aead_suite_id || client_random || validator_id
//! - timestamp_bucket = current_time / BUCKET_DURATION_SECS
//! - context_tag = "QBIND:cookie:v1"
//!
//! # Security Properties
//!
//! - **Stateless**: Server does not need to store per-client state until cookie is verified
//! - **Replay-limited**: Timestamp bucket prevents long-term cookie reuse
//! - **Binding**: Cookie is bound to client IP and ClientInit fields
//! - **Fail-closed**: Invalid/expired cookie only returns cookie challenge, never decapsulates KEM

use hmac::{Hmac, Mac};
use sha3::Sha3_256;
use subtle::ConstantTimeEq;

use crate::error::NetError;

/// Domain separation tag for cookie generation.
pub const COOKIE_DOMAIN_TAG: &str = "QBIND:cookie:v1";

/// Cookie output size (HMAC-SHA3-256 produces 32 bytes).
pub const COOKIE_SIZE: usize = 32;

/// Maximum cookie size accepted in ClientInit (prevents DoS via large cookies).
pub const MAX_COOKIE_SIZE: usize = 64;

/// Default bucket duration in seconds (30 seconds).
pub const DEFAULT_BUCKET_DURATION_SECS: u64 = 30;

/// Default number of old buckets to accept for clock skew tolerance.
/// With 30-second buckets, allowing 1 old bucket gives ~30-60s effective window.
pub const DEFAULT_CLOCK_SKEW_BUCKETS: u64 = 1;

/// HMAC-SHA3-256 type alias.
type HmacSha3_256 = Hmac<Sha3_256>;

/// Cookie generator and verifier configuration.
///
/// This struct holds the server-side secret key and configuration for
/// generating and verifying stateless DoS cookies.
#[derive(Clone)]
pub struct CookieConfig {
    /// Server-side secret key for HMAC (should be at least 32 bytes).
    /// This key should be generated at startup and rotated periodically.
    secret_key: Vec<u8>,

    /// Bucket duration in seconds.
    bucket_duration_secs: u64,

    /// Number of old buckets to accept (clock skew tolerance).
    clock_skew_buckets: u64,
}

impl CookieConfig {
    /// Create a new cookie configuration with the given secret key.
    ///
    /// Uses default bucket duration (30s) and clock skew tolerance (1 bucket).
    ///
    /// # Security
    ///
    /// The secret key should be:
    /// - At least 32 bytes of cryptographically random data
    /// - Rotated at server startup (acceptable for current deployment model)
    /// - Never logged or exposed
    pub fn new(secret_key: Vec<u8>) -> Self {
        Self {
            secret_key,
            bucket_duration_secs: DEFAULT_BUCKET_DURATION_SECS,
            clock_skew_buckets: DEFAULT_CLOCK_SKEW_BUCKETS,
        }
    }

    /// Create a new cookie configuration with custom parameters.
    pub fn with_params(secret_key: Vec<u8>, bucket_duration_secs: u64, clock_skew_buckets: u64) -> Self {
        Self {
            secret_key,
            bucket_duration_secs,
            clock_skew_buckets,
        }
    }

    /// Generate a cookie for the given ClientInit fields and client IP.
    ///
    /// # Arguments
    ///
    /// * `client_ip` - Client's IP address bytes (4 for IPv4, 16 for IPv6)
    /// * `kem_suite_id` - KEM suite ID from ClientInit
    /// * `aead_suite_id` - AEAD suite ID from ClientInit
    /// * `client_random` - 32-byte client random from ClientInit
    /// * `validator_id` - 32-byte validator ID from ClientInit
    /// * `current_time_secs` - Current Unix timestamp in seconds
    ///
    /// # Returns
    ///
    /// A 32-byte cookie that can be sent to the client in a ServerCookie message.
    pub fn generate(
        &self,
        client_ip: &[u8],
        kem_suite_id: u8,
        aead_suite_id: u8,
        client_random: &[u8; 32],
        validator_id: &[u8; 32],
        current_time_secs: u64,
    ) -> [u8; COOKIE_SIZE] {
        let bucket = current_time_secs / self.bucket_duration_secs;
        self.generate_for_bucket(
            client_ip,
            kem_suite_id,
            aead_suite_id,
            client_random,
            validator_id,
            bucket,
        )
    }

    /// Generate a cookie for a specific timestamp bucket.
    fn generate_for_bucket(
        &self,
        client_ip: &[u8],
        kem_suite_id: u8,
        aead_suite_id: u8,
        client_random: &[u8; 32],
        validator_id: &[u8; 32],
        bucket: u64,
    ) -> [u8; COOKIE_SIZE] {
        // HMAC-SHA3-256_k( domain_tag || client_ip || client_init_fields || bucket )
        let mut mac = HmacSha3_256::new_from_slice(&self.secret_key)
            .expect("HMAC key length is valid");

        // Domain separation
        mac.update(COOKIE_DOMAIN_TAG.as_bytes());

        // Client IP binding
        mac.update(client_ip);

        // ClientInit fields binding
        mac.update(&[kem_suite_id]);
        mac.update(&[aead_suite_id]);
        mac.update(client_random);
        mac.update(validator_id);

        // Timestamp bucket
        mac.update(&bucket.to_be_bytes());

        let result = mac.finalize();
        let mut cookie = [0u8; COOKIE_SIZE];
        cookie.copy_from_slice(&result.into_bytes());
        cookie
    }

    /// Verify a cookie against the given ClientInit fields and client IP.
    ///
    /// # Arguments
    ///
    /// * `cookie` - The cookie bytes from ClientInit
    /// * `client_ip` - Client's IP address bytes
    /// * `kem_suite_id` - KEM suite ID from ClientInit
    /// * `aead_suite_id` - AEAD suite ID from ClientInit
    /// * `client_random` - 32-byte client random from ClientInit
    /// * `validator_id` - 32-byte validator ID from ClientInit
    /// * `current_time_secs` - Current Unix timestamp in seconds
    ///
    /// # Returns
    ///
    /// `Ok(())` if the cookie is valid and not expired.
    /// `Err(NetError::CookieExpired)` if the cookie was valid but is now expired.
    /// `Err(NetError::CookieInvalid)` if the cookie doesn't match.
    pub fn verify(
        &self,
        cookie: &[u8],
        client_ip: &[u8],
        kem_suite_id: u8,
        aead_suite_id: u8,
        client_random: &[u8; 32],
        validator_id: &[u8; 32],
        current_time_secs: u64,
    ) -> Result<(), NetError> {
        // Check cookie size
        if cookie.len() != COOKIE_SIZE {
            return Err(NetError::CookieInvalid);
        }

        let current_bucket = current_time_secs / self.bucket_duration_secs;

        // Check current bucket and older buckets (clock skew tolerance)
        for offset in 0..=self.clock_skew_buckets {
            // Prevent underflow when current_bucket < offset
            let bucket = current_bucket.saturating_sub(offset);

            let expected = self.generate_for_bucket(
                client_ip,
                kem_suite_id,
                aead_suite_id,
                client_random,
                validator_id,
                bucket,
            );

            // Constant-time comparison
            if constant_time_compare(cookie, &expected) {
                return Ok(());
            }
        }

        // Cookie doesn't match any valid bucket - could be expired or invalid.
        // We return CookieInvalid since we can't distinguish without more state.
        Err(NetError::CookieInvalid)
    }
}

impl std::fmt::Debug for CookieConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CookieConfig")
            .field("secret_key", &"<redacted>")
            .field("bucket_duration_secs", &self.bucket_duration_secs)
            .field("clock_skew_buckets", &self.clock_skew_buckets)
            .finish()
    }
}

/// Constant-time comparison to prevent timing attacks.
///
/// Uses the `subtle` crate's `ConstantTimeEq` trait for cryptographically
/// secure constant-time comparison that is not susceptible to compiler
/// optimizations.
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    // Length check in constant time by comparing to fixed-size value
    if a.len() != b.len() {
        // Return false in constant time relative to data content
        // Note: Length leaks are acceptable for cookies since the expected
        // length (COOKIE_SIZE = 32) is a public constant.
        return false;
    }
    // Use subtle crate for guaranteed constant-time byte comparison
    a.ct_eq(b).into()
}

/// Result of cookie validation in the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CookieValidation {
    /// No cookie was provided in ClientInit.
    NoCookie,
    /// Cookie was provided but is invalid or expired.
    Invalid,
    /// Cookie is valid - proceed with KEM decapsulation.
    Valid,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_cookie_config() -> CookieConfig {
        let secret = vec![0x42u8; 32];
        CookieConfig::new(secret)
    }

    #[test]
    fn cookie_generation_deterministic() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];
        let time_secs = 1000u64;

        let cookie1 = config.generate(&client_ip, 1, 2, &client_random, &validator_id, time_secs);
        let cookie2 = config.generate(&client_ip, 1, 2, &client_random, &validator_id, time_secs);

        assert_eq!(cookie1, cookie2);
    }

    #[test]
    fn cookie_verify_valid() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];
        let time_secs = 1000u64;

        let cookie = config.generate(&client_ip, 1, 2, &client_random, &validator_id, time_secs);

        let result = config.verify(
            &cookie,
            &client_ip,
            1,
            2,
            &client_random,
            &validator_id,
            time_secs,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cookie_verify_accepts_within_clock_skew() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];

        // Generate at bucket 33 (time 1000 / 30 = 33)
        let gen_time = 1000u64;
        let cookie = config.generate(&client_ip, 1, 2, &client_random, &validator_id, gen_time);

        // Verify at bucket 34 (time 1020 / 30 = 34) - one bucket later
        let verify_time = 1020u64;
        let result = config.verify(
            &cookie,
            &client_ip,
            1,
            2,
            &client_random,
            &validator_id,
            verify_time,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cookie_verify_rejects_expired() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];

        // Generate at bucket 33 (time 1000 / 30 = 33)
        let gen_time = 1000u64;
        let cookie = config.generate(&client_ip, 1, 2, &client_random, &validator_id, gen_time);

        // Verify at bucket 36 (time 1080 / 30 = 36) - three buckets later (expired)
        let verify_time = 1080u64;
        let result = config.verify(
            &cookie,
            &client_ip,
            1,
            2,
            &client_random,
            &validator_id,
            verify_time,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cookie_verify_rejects_wrong_ip() {
        let config = make_test_cookie_config();
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];
        let time_secs = 1000u64;

        let cookie = config.generate(&[127, 0, 0, 1], 1, 2, &client_random, &validator_id, time_secs);

        // Verify with different IP
        let result = config.verify(
            &cookie,
            &[192, 168, 1, 1],
            1,
            2,
            &client_random,
            &validator_id,
            time_secs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cookie_verify_rejects_wrong_client_random() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let validator_id = [2u8; 32];
        let time_secs = 1000u64;

        let cookie = config.generate(&client_ip, 1, 2, &[1u8; 32], &validator_id, time_secs);

        // Verify with different client_random
        let result = config.verify(
            &cookie,
            &client_ip,
            1,
            2,
            &[9u8; 32],
            &validator_id,
            time_secs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cookie_verify_rejects_wrong_suite_id() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];
        let time_secs = 1000u64;

        let cookie = config.generate(&client_ip, 1, 2, &client_random, &validator_id, time_secs);

        // Verify with different KEM suite ID
        let result = config.verify(
            &cookie,
            &client_ip,
            99, // wrong
            2,
            &client_random,
            &validator_id,
            time_secs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cookie_verify_rejects_wrong_length() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];
        let time_secs = 1000u64;

        // Too short
        let result = config.verify(
            &[0u8; 16],
            &client_ip,
            1,
            2,
            &client_random,
            &validator_id,
            time_secs,
        );
        assert!(result.is_err());

        // Too long
        let result = config.verify(
            &[0u8; 64],
            &client_ip,
            1,
            2,
            &client_random,
            &validator_id,
            time_secs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn cookie_verify_rejects_random_bytes() {
        let config = make_test_cookie_config();
        let client_ip = [127, 0, 0, 1];
        let client_random = [1u8; 32];
        let validator_id = [2u8; 32];
        let time_secs = 1000u64;

        // Random cookie bytes
        let random_cookie = [0xAB; COOKIE_SIZE];
        let result = config.verify(
            &random_cookie,
            &client_ip,
            1,
            2,
            &client_random,
            &validator_id,
            time_secs,
        );
        assert!(result.is_err());
    }

    #[test]
    fn constant_time_compare_works() {
        assert!(constant_time_compare(&[1, 2, 3], &[1, 2, 3]));
        assert!(!constant_time_compare(&[1, 2, 3], &[1, 2, 4]));
        assert!(!constant_time_compare(&[1, 2, 3], &[1, 2]));
        assert!(!constant_time_compare(&[1, 2], &[1, 2, 3]));
        assert!(constant_time_compare(&[], &[]));
    }
}
