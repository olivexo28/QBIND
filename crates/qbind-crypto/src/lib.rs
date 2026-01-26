pub mod aead;
pub mod chacha20poly1305;
pub mod consensus_sig;
pub mod error;
pub mod kem;
pub mod ml_dsa44;
pub mod ml_kem768;
pub mod provider;
pub mod signature;
pub mod suite_catalog;

pub use aead::AeadSuite;
pub use chacha20poly1305::{
    ChaCha20Poly1305Backend, AEAD_SUITE_CHACHA20_POLY1305, CHACHA20_POLY1305_KEY_SIZE,
    CHACHA20_POLY1305_NONCE_SIZE, CHACHA20_POLY1305_TAG_SIZE,
};
pub use consensus_sig::{
    ConsensusSigError, ConsensusSigSuiteId, ConsensusSigVerifier, SUITE_TOY_SHA3,
};
pub use error::CryptoError;
pub use kem::KemSuite;
pub use ml_dsa44::{
    MlDsa44Backend, ValidatorSigningKey, ML_DSA_44_PUBLIC_KEY_SIZE, ML_DSA_44_SECRET_KEY_SIZE,
    ML_DSA_44_SIGNATURE_SIZE,
};
pub use ml_kem768::{
    MlKem768Backend, KEM_SUITE_ML_KEM_768, ML_KEM_768_CIPHERTEXT_SIZE, ML_KEM_768_PUBLIC_KEY_SIZE,
    ML_KEM_768_SECRET_KEY_SIZE, ML_KEM_768_SHARED_SECRET_SIZE,
};
pub use provider::{CryptoProvider, StaticCryptoProvider};
pub use signature::{SignatureSuite, Signer};
pub use suite_catalog::{
    all_suites, effective_security_bits, find_suite, is_known_suite, suite_name,
    validate_suite_catalog, ConsensusSigSuiteInfo, KNOWN_CONSENSUS_SIG_SUITES, SUITE_PQ_RESERVED_1,
    SUITE_PQ_RESERVED_2, SUITE_PQ_RESERVED_3,
};
