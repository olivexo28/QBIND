use crate::CryptoError;
use qbind_types::Hash32;

/// Exact identity descriptor for a canonical public-key encoding.
///
/// Equality compares the algorithm identifier, parameter identifier, and
/// public-key bytes by content. This identifies an encoding only; it is not a
/// verified-signature result, authorized signer, freshness assertion, or
/// permission to execute.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct CanonicalKeyDescriptor<'a> {
    /// Stable canonical identifier for the cryptographic algorithm.
    pub algorithm_id: &'static [u8],
    /// Stable canonical identifier for the algorithm's parameter set.
    pub parameter_id: &'static [u8],
    /// Canonical public-key serialization, borrowed from the caller.
    pub public_key_encoding: &'a [u8],
}

impl core::fmt::Debug for CanonicalKeyDescriptor<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CanonicalKeyDescriptor")
            .field("algorithm_id", &self.algorithm_id)
            .field("parameter_id", &self.parameter_id)
            .field("public_key_encoding_len", &self.public_key_encoding.len())
            .finish()
    }
}

/// Fixed-size error returned while describing a canonical public key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyDescriptorError {
    /// This suite does not provide canonical key identity.
    Unsupported,
    /// The input is malformed, including an invalid length or failed decode.
    Malformed,
    /// The decoded key did not re-encode to the supplied bytes.
    NonCanonical,
}

/// A verification-only signature suite (e.g. ML-DSA-65/87 or SLH-DSA).
/// This is algorithm-agnostic: we don't expose key formats or parameters here.
pub trait SignatureSuite: Send + Sync {
    /// Numeric suite_id, must match on-chain SuiteRegistry.suite_id for this suite.
    fn suite_id(&self) -> u8;

    /// Expected public key length in bytes, if known; 0 may mean "variable or unknown".
    fn public_key_len(&self) -> usize;

    /// Expected signature length in bytes, if known; 0 may mean "variable or unknown".
    fn signature_len(&self) -> usize;

    /// Verify a signature over a 32-byte digest.
    ///
    /// `pk` is the raw public key bytes as stored on-chain.
    /// `msg_digest` is the canonical digest (e.g. tx_digest or vote_digest).
    fn verify(&self, pk: &[u8], msg_digest: &Hash32, sig: &[u8]) -> Result<(), CryptoError>;

    /// Describe the exact canonical identity of an encoded public key.
    ///
    /// Implementations must not use suite IDs as key identity. Returned key
    /// bytes borrow `encoded_public_key`; implementations must not retain or
    /// normalize the input. The default keeps existing suites source-compatible
    /// while making unsupported identity explicit.
    fn canonical_key_descriptor<'a>(
        &self,
        _encoded_public_key: &'a [u8],
    ) -> Result<CanonicalKeyDescriptor<'a>, KeyDescriptorError> {
        Err(KeyDescriptorError::Unsupported)
    }
}

/// Optional signing interface, for local key-holding components (e.g. validator nodes).
/// This is not used by consensus to *verify*; it's used by nodes to produce signatures.
pub trait Signer {
    /// suite_id must match the SignatureSuite used by verifiers.
    fn suite_id(&self) -> u8;

    /// Return the public key bytes associated with this signer.
    fn public_key(&self) -> &[u8];

    /// Sign a canonical digest and return the raw signature bytes.
    fn sign(&self, msg_digest: &Hash32) -> Result<Vec<u8>, CryptoError>;
}
