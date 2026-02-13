#[derive(Debug)]
pub enum NetError {
    /// HKDF or key derivation failure.
    KeySchedule(&'static str),

    /// AEAD encrypt/decrypt failure.
    Aead(&'static str),

    /// Nonce counter overflow.
    NonceOverflow,

    /// Unsupported or unknown suite.
    UnsupportedSuite(u8),

    /// Protocol or framing error (e.g., packet parsing).
    Protocol(&'static str),

    /// Cookie is invalid or doesn't match (M6 DoS protection).
    CookieInvalid,

    /// Cookie has expired (M6 DoS protection).
    CookieExpired,

    /// Cookie is required but not provided (M6 DoS protection).
    CookieRequired,

    /// Client certificate required but not provided (M8 mutual auth).
    ClientCertRequired,

    /// Client certificate verification failed (M8 mutual auth).
    ClientCertInvalid(&'static str),

    /// Client NodeId mismatch with derived value (M8 mutual auth).
    ClientNodeIdMismatch,

    /// Protocol version not supported.
    UnsupportedProtocolVersion(u8),
}