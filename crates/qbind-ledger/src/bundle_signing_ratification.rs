//! Run 103 — Minimal Bundle-Signing-Key Ratification Verifier.
//!
//! This module implements only the **minimal** authority-layer primitive
//! described in `task/RUN_103_TASK.txt`:
//!
//! > A bundle-signing key is not merely locally configured; it must be
//! > ratified by a genesis-bound bundle-signing authority root.
//!
//! ## Scope (Run 103)
//!
//! * Defines a versioned, canonically-serialisable
//!   [`BundleSigningRatification`] object that authorises a single PQC
//!   bundle-signing public key against a single genesis-bound bundle-signing
//!   authority root.
//! * Provides a deterministic, domain-separated canonical preimage helper
//!   ([`canonical_ratification_preimage`]) so that signing and verifying
//!   produce identical bytes without any JSON map-order ambiguity.
//! * Exposes a narrow verifier API
//!   ([`verify_bundle_signing_key_ratification`]) that returns typed
//!   accept/reject reasons.
//! * Verifies the ratification signature with the existing production
//!   ML-DSA-44 [`SignatureSuite`] adapter — no parallel crypto stack, no
//!   classical signatures, no dummy verifier.
//! * Restricts authority-root lookup to
//!   [`GenesisAuthorityConfig::bundle_signing_authority_roots`] — entries in
//!   [`GenesisAuthorityConfig::pqc_transport_roots`] **cannot** ratify
//!   bundle-signing keys (Run 100 spec §5 / §13, Run 101 separation
//!   invariant).
//!
//! ## Non-goals (Run 103)
//!
//! Run 103 explicitly does NOT implement:
//!
//!   * signing-key rotation lifecycle;
//!   * signing-key revocation lifecycle;
//!   * authority anti-rollback persistence;
//!   * ratified-authority state storage;
//!   * peer-driven live apply;
//!   * KMS/HSM custody;
//!   * governance, validator-set rotation;
//!   * any trust-bundle wire-format change;
//!   * any consumption of this verifier inside trust-bundle acceptance
//!     paths (deferred to Run 104).
//!
//! ## Authority-key material boundary
//!
//! The Run 101 [`GenesisAuthorityRoot::key_fingerprint`] field accepts
//! either:
//!
//!   * a SHA3-256 fingerprint of the authority public key (64 hex chars,
//!     32 bytes), or
//!   * the **full** ML-DSA-44 public key bytes hex-encoded (2624 hex chars
//!     = 1312 bytes).
//!
//! Signature verification needs the full key. When the genesis-bound root
//! carries only a 64-hex fingerprint, the verifier fails closed with
//! [`RatificationFailure::AuthorityKeyMaterialUnavailable`]; the verifier
//! never fakes verification when key material is absent. This is the
//! documented Run 103 partial boundary — Run 104+ will land the
//! authority-key-material registry that resolves fingerprints to full PKs.
//!
//! See:
//!   * `docs/protocol/QBIND_TRUST_ANCHOR_AUTHORITY_MODEL.md`
//!   * `docs/devnet/QBIND_DEVNET_EVIDENCE_RUN_103.md`
//!   * `docs/whitepaper/contradiction.md` (Run 103 update)

use serde::{Deserialize, Serialize};

use qbind_crypto::{
    MlDsa44SignatureSuite, SignatureSuite, ML_DSA_44_PUBLIC_KEY_SIZE,
    ML_DSA_44_SIGNATURE_SIZE,
};

use crate::genesis::{
    authority_public_key_fingerprint, GenesisAuthorityConfig, GenesisAuthorityRoot,
    GenesisAuthorityRootKind, GenesisAuthoritySuiteId, GenesisHash, NetworkEnvironmentPolicy,
    GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN, GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES,
    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
};

// ===========================================================================
// Domain separator
// ===========================================================================

/// Domain separator for the canonical bundle-signing-key ratification
/// preimage (Run 103, v1).
///
/// Mirrors the project convention `QBIND:<SUBJECT>:vN` used by other
/// domain-bound digests (e.g. `QBIND:GENESIS:v1` for the canonical genesis
/// hash). Bumping the trailing version invalidates every previously signed
/// ratification object.
pub const BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1: &[u8] =
    b"QBIND:BUNDLE-SIGNING-RATIFICATION:v1";

/// Current ratification-object schema version. Run 103 = `1`.
///
/// Any future schema change MUST bump this constant AND the trailing `v1`
/// of [`BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1`].
pub const BUNDLE_SIGNING_RATIFICATION_VERSION_V1: u32 = 1;

// ===========================================================================
// Ratification object
// ===========================================================================

/// Environment tag inside a ratification object.
///
/// Stored as a stable lowercase ASCII string in JSON / canonical bytes so
/// that the on-disk shape is forward/backward compatible with future
/// environments. Maps 1:1 to [`NetworkEnvironmentPolicy`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RatificationEnvironment {
    /// Development network.
    Devnet,
    /// Public test network.
    Testnet,
    /// Production main network.
    Mainnet,
}

impl RatificationEnvironment {
    /// Map to the per-environment [`NetworkEnvironmentPolicy`] used by
    /// Run 101/102 validators.
    pub const fn policy(self) -> NetworkEnvironmentPolicy {
        match self {
            RatificationEnvironment::Devnet => NetworkEnvironmentPolicy::Devnet,
            RatificationEnvironment::Testnet => NetworkEnvironmentPolicy::Testnet,
            RatificationEnvironment::Mainnet => NetworkEnvironmentPolicy::Mainnet,
        }
    }

    /// Lowercase ASCII tag (`"devnet"` / `"testnet"` / `"mainnet"`).
    pub const fn tag(self) -> &'static str {
        match self {
            RatificationEnvironment::Devnet => "devnet",
            RatificationEnvironment::Testnet => "testnet",
            RatificationEnvironment::Mainnet => "mainnet",
        }
    }

    /// Construct from a [`NetworkEnvironmentPolicy`].
    pub const fn from_policy(p: NetworkEnvironmentPolicy) -> Self {
        match p {
            NetworkEnvironmentPolicy::Devnet => RatificationEnvironment::Devnet,
            NetworkEnvironmentPolicy::Testnet => RatificationEnvironment::Testnet,
            NetworkEnvironmentPolicy::Mainnet => RatificationEnvironment::Mainnet,
        }
    }
}

/// Run 103 minimal bundle-signing-key ratification object.
///
/// Authorises **exactly one** bundle-signing public key against **exactly
/// one** genesis-bound bundle-signing authority root, on **exactly one**
/// chain/environment, under **exactly one** PQC signature suite.
///
/// Canonical encoding is deterministic, length-prefixed, and
/// domain-separated; see [`canonical_ratification_preimage`]. The
/// `signature` field is the ML-DSA-44 signature over
/// `sha3_256(canonical_preimage)`.
///
/// Run 103 does NOT include rotation, revocation, anti-rollback sequence
/// numbers, or validity windows — those are explicitly out of scope per
/// `task/RUN_103_TASK.txt` "Strict non-goals".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleSigningRatification {
    /// Ratification-object schema version. Run 103 = `1`.
    pub version: u32,

    /// Chain identifier this ratification is bound to (e.g.
    /// `"qbind-mainnet-v0"`). Must equal the runtime's expected chain id.
    pub chain_id: String,

    /// Environment tag this ratification is bound to.
    pub environment: RatificationEnvironment,

    /// Canonical genesis hash this ratification is bound to.
    ///
    /// Equals [`crate::genesis::compute_canonical_genesis_hash`] over the
    /// authoritative genesis config for `chain_id` / `environment`. Locks
    /// the ratification to a specific genesis authority surface.
    pub genesis_hash: GenesisHash,

    /// Authority-root fingerprint that signed this ratification.
    ///
    /// Lowercase hex, matching the on-disk
    /// [`GenesisAuthorityRoot::key_fingerprint`] format. The verifier looks
    /// this up inside
    /// [`GenesisAuthorityConfig::bundle_signing_authority_roots`].
    pub authority_root_fingerprint: String,

    /// PQC signature suite identifier used for both the authority key and
    /// the signature. Run 103 accepts only [`GENESIS_AUTHORITY_SUITE_ML_DSA_44`]
    /// (= 100).
    pub signature_suite_id: GenesisAuthoritySuiteId,

    /// Full bundle-signing public key bytes being authorised.
    ///
    /// For ML-DSA-44 this MUST be `ML_DSA_44_PUBLIC_KEY_SIZE` bytes
    /// (1312). Carried in full (not only as a fingerprint) so that
    /// downstream consumers can install the key directly after a successful
    /// ratification without an extra resolution step.
    #[serde(with = "hex_vec")]
    pub bundle_signing_public_key: Vec<u8>,

    /// SHA3-256 fingerprint of `bundle_signing_public_key`, lowercase hex.
    ///
    /// Redundant by construction — the verifier recomputes the fingerprint
    /// from the full key and rejects any mismatch. The redundant form is
    /// retained so that operator tooling can index ratifications by
    /// fingerprint without parsing the full PK.
    pub bundle_signing_public_key_fingerprint: String,

    /// ML-DSA-44 signature over `sha3_256(canonical_preimage(self))`,
    /// produced by the authority root's private key.
    #[serde(with = "hex_vec")]
    pub signature: Vec<u8>,
}

/// Hex serialisation helper for `Vec<u8>` fields (lowercase, no prefix).
mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        let mut out = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            use std::fmt::Write;
            let _ = write!(&mut out, "{:02x}", b);
        }
        s.serialize_str(&out)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s: String = String::deserialize(d)?;
        if s.len() % 2 != 0 {
            return Err(serde::de::Error::custom("hex length must be even"));
        }
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_nibble(bytes[i]).ok_or_else(|| {
                serde::de::Error::custom("non-hex byte in hex_vec field")
            })?;
            let lo = hex_nibble(bytes[i + 1]).ok_or_else(|| {
                serde::de::Error::custom("non-hex byte in hex_vec field")
            })?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }

    fn hex_nibble(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(10 + b - b'a'),
            _ => None,
        }
    }
}

// ===========================================================================
// Canonical preimage
// ===========================================================================

/// Compute the canonical, domain-separated signing preimage for a
/// [`BundleSigningRatification`] object.
///
/// Layout (all integers big-endian, all variable-length fields prefixed
/// with a `u32` byte length):
///
/// ```text
/// BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1
/// u32  version
/// u32  len(chain_id)             | chain_id bytes
/// u32  len(environment_tag)      | environment_tag bytes  (ascii)
/// 32   genesis_hash
/// u32  len(authority_root_fp)    | authority_root_fp bytes
/// u8   signature_suite_id
/// u32  len(bundle_signing_pk)    | bundle_signing_pk bytes (raw bytes, NOT hex)
/// u32  len(bundle_signing_pk_fp) | bundle_signing_pk_fp bytes
/// ```
///
/// The `signature` field is intentionally NOT included — it is the output
/// of signing this preimage, not part of the message being signed.
///
/// The preimage is deterministic given the object's field values; no JSON
/// map-order or whitespace ambiguity is possible. Changing **any**
/// consensus/security-relevant field produces different preimage bytes and
/// therefore a different SHA3-256 digest.
pub fn canonical_ratification_preimage(r: &BundleSigningRatification) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::with_capacity(
        BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1.len()
            + 4
            + 4 + r.chain_id.len()
            + 4 + r.environment.tag().len()
            + 32
            + 4 + r.authority_root_fingerprint.len()
            + 1
            + 4 + r.bundle_signing_public_key.len()
            + 4 + r.bundle_signing_public_key_fingerprint.len(),
    );
    buf.extend_from_slice(BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1);
    buf.extend_from_slice(&r.version.to_be_bytes());

    encode_length_prefixed_bytes(&mut buf, r.chain_id.as_bytes());
    encode_length_prefixed_bytes(&mut buf, r.environment.tag().as_bytes());
    buf.extend_from_slice(&r.genesis_hash);

    encode_length_prefixed_bytes(&mut buf, r.authority_root_fingerprint.as_bytes());
    buf.push(r.signature_suite_id);

    encode_length_prefixed_bytes(&mut buf, &r.bundle_signing_public_key);
    encode_length_prefixed_bytes(&mut buf, r.bundle_signing_public_key_fingerprint.as_bytes());

    buf
}

/// 32-byte SHA3-256 digest of [`canonical_ratification_preimage`].
///
/// This is exactly the digest signed and verified under the ML-DSA-44
/// [`SignatureSuite`] adapter.
pub fn canonical_ratification_digest(r: &BundleSigningRatification) -> [u8; 32] {
    qbind_hash::sha3_256(&canonical_ratification_preimage(r))
}

fn encode_length_prefixed_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    buf.extend_from_slice(bytes);
}

// ===========================================================================
// Verifier API
// ===========================================================================

/// Successful ratification result: the bundle-signing key identity that
/// has been ratified by a genesis-bound authority root.
///
/// This is intentionally a typed struct (not `bool`) so callers cannot
/// accidentally drop the bound metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RatifiedBundleSigningKey {
    /// Full ML-DSA-44 public key bytes of the ratified bundle-signing key.
    pub public_key: Vec<u8>,
    /// Lowercase hex SHA3-256 fingerprint of `public_key`.
    pub fingerprint: String,
    /// PQC signature suite id (Run 103 = ML-DSA-44 = 100).
    pub signature_suite_id: GenesisAuthoritySuiteId,
    /// Lowercase hex fingerprint of the authority root that ratified the key.
    pub authority_root_fingerprint: String,
}

/// Typed accept/reject reasons returned by
/// [`verify_bundle_signing_key_ratification`].
///
/// Every variant is precise enough to drive a fail-closed operator log
/// message without any "invalid object" catch-all.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatificationFailure {
    /// `version` is not [`BUNDLE_SIGNING_RATIFICATION_VERSION_V1`].
    UnsupportedVersion { got: u32, expected: u32 },

    /// `chain_id` does not match the runtime's expected chain id.
    ChainMismatch { expected: String, got: String },

    /// `environment` does not match the runtime's expected environment.
    EnvironmentMismatch {
        expected: RatificationEnvironment,
        got: RatificationEnvironment,
    },

    /// `genesis_hash` does not match the canonical genesis hash for the
    /// runtime's authoritative genesis config.
    GenesisHashMismatch {
        expected: GenesisHash,
        got: GenesisHash,
    },

    /// `signature_suite_id` is not accepted by Run 103
    /// (only ML-DSA-44 = 100 is accepted).
    UnsupportedSuite { suite_id: GenesisAuthoritySuiteId },

    /// The `bundle_signing_public_key_fingerprint` field does not equal
    /// `sha3_256_hex(bundle_signing_public_key)`.
    BundleSigningKeyFingerprintMismatch {
        expected: String,
        got: String,
    },

    /// `bundle_signing_public_key` has the wrong length for the declared
    /// suite (e.g. not 1312 bytes for ML-DSA-44).
    MalformedBundleSigningPublicKey {
        suite_id: GenesisAuthoritySuiteId,
        got_len: usize,
        expected_len: usize,
    },

    /// `signature` has the wrong length for the declared suite (e.g. not
    /// 2420 bytes for ML-DSA-44).
    MalformedSignature {
        suite_id: GenesisAuthoritySuiteId,
        got_len: usize,
        expected_len: usize,
    },

    /// No `bundle_signing_authority_roots` entry matches the ratification's
    /// `authority_root_fingerprint`.
    UnknownAuthorityRoot { fingerprint: String },

    /// The matching authority root exists, but it is a
    /// [`GenesisAuthorityRootKind::Transport`] entry — transport roots
    /// MUST NOT authorise bundle-signing keys (Run 100 spec §5 / §13).
    TransportRootNotAllowed { fingerprint: String },

    /// The authority root's declared suite differs from the ratification
    /// suite.
    AuthorityRootSuiteMismatch {
        root_suite_id: GenesisAuthoritySuiteId,
        ratification_suite_id: GenesisAuthoritySuiteId,
    },

    /// The matched authority root carries only a short fingerprint (e.g.
    /// 64-hex SHA3-256 of the PK) and not the full PQC public-key bytes,
    /// so signature verification cannot be performed without an additional
    /// authority-key-material registry.
    ///
    /// Run 104 narrowed this boundary: MainNet roots are required to
    /// carry full `public_key_hex`, so this failure only fires for
    /// legacy DevNet/TestNet fingerprint-only roots or for explicitly
    /// incomplete genesis. The verifier still fails closed — no fake
    /// verification, no fallback authority.
    AuthorityKeyMaterialUnavailable {
        fingerprint: String,
        suite_id: GenesisAuthoritySuiteId,
        got_hex_len: usize,
        required_hex_len: usize,
    },

    /// Run 104: the matched authority root declares a full
    /// `public_key_hex` but the bytes are malformed (non-hex, wrong
    /// length for the declared suite, or fingerprint mismatch). The
    /// verifier fails closed with a typed reason rather than silently
    /// falling back to any other key material.
    AuthorityKeyMaterialMalformed {
        fingerprint: String,
        suite_id: GenesisAuthoritySuiteId,
        reason: String,
    },

    /// The PQC signature verification under the authority root's public key
    /// failed.
    BadSignature,

    /// The genesis configuration supplied to the verifier does not contain
    /// an `authority` block at all (MainNet/TestNet require it).
    MissingAuthorityBlock,
}

impl std::fmt::Display for RatificationFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RatificationFailure::UnsupportedVersion { got, expected } => write!(
                f,
                "bundle-signing ratification version {} unsupported (expected {})",
                got, expected
            ),
            RatificationFailure::ChainMismatch { expected, got } => write!(
                f,
                "bundle-signing ratification chain_id mismatch: expected '{}' got '{}'",
                expected, got
            ),
            RatificationFailure::EnvironmentMismatch { expected, got } => write!(
                f,
                "bundle-signing ratification environment mismatch: expected {:?} got {:?}",
                expected, got
            ),
            RatificationFailure::GenesisHashMismatch { .. } => write!(
                f,
                "bundle-signing ratification genesis_hash does not match runtime canonical genesis hash"
            ),
            RatificationFailure::UnsupportedSuite { suite_id } => write!(
                f,
                "bundle-signing ratification signature_suite_id {} not accepted (Run 103 accepts only ML-DSA-44 = {})",
                suite_id, GENESIS_AUTHORITY_SUITE_ML_DSA_44
            ),
            RatificationFailure::BundleSigningKeyFingerprintMismatch { expected, got } => {
                write!(
                    f,
                    "bundle-signing public key fingerprint mismatch: expected sha3_256_hex={} got={}",
                    expected, got
                )
            }
            RatificationFailure::MalformedBundleSigningPublicKey {
                suite_id,
                got_len,
                expected_len,
            } => write!(
                f,
                "bundle-signing public key length {} invalid for suite_id {} (expected {})",
                got_len, suite_id, expected_len
            ),
            RatificationFailure::MalformedSignature {
                suite_id,
                got_len,
                expected_len,
            } => write!(
                f,
                "bundle-signing ratification signature length {} invalid for suite_id {} (expected {})",
                got_len, suite_id, expected_len
            ),
            RatificationFailure::UnknownAuthorityRoot { fingerprint } => write!(
                f,
                "bundle-signing ratification authority_root_fingerprint '{}' not present in genesis bundle_signing_authority_roots",
                fingerprint
            ),
            RatificationFailure::TransportRootNotAllowed { fingerprint } => write!(
                f,
                "bundle-signing ratification refused: fingerprint '{}' resolves to a pqc_transport_root, which cannot authorise bundle-signing keys",
                fingerprint
            ),
            RatificationFailure::AuthorityRootSuiteMismatch {
                root_suite_id,
                ratification_suite_id,
            } => write!(
                f,
                "bundle-signing ratification suite_id {} differs from authority root suite_id {}",
                ratification_suite_id, root_suite_id
            ),
            RatificationFailure::AuthorityKeyMaterialUnavailable {
                fingerprint,
                suite_id,
                got_hex_len,
                required_hex_len,
            } => write!(
                f,
                "bundle-signing ratification cannot be verified: authority root '{}' (suite_id {}) carries only a {}-hex fingerprint; full {}-hex PQC public key required (genesis-bound key material registry)",
                fingerprint, suite_id, got_hex_len, required_hex_len
            ),
            RatificationFailure::AuthorityKeyMaterialMalformed {
                fingerprint,
                suite_id,
                reason,
            } => write!(
                f,
                "bundle-signing ratification cannot be verified: authority root '{}' (suite_id {}) public_key_hex is malformed: {}",
                fingerprint, suite_id, reason
            ),
            RatificationFailure::BadSignature => write!(
                f,
                "bundle-signing ratification signature failed PQC verification"
            ),
            RatificationFailure::MissingAuthorityBlock => write!(
                f,
                "genesis authority block is absent; bundle-signing-key ratification cannot be verified"
            ),
        }
    }
}

impl std::error::Error for RatificationFailure {}

/// Inputs to [`verify_bundle_signing_key_ratification`].
///
/// All four fields are required so that the verifier never has to fall back
/// to ambient state and never accepts a ratification that was generated
/// for a different runtime.
pub struct RatificationVerifierInputs<'a> {
    /// Ratification object under test.
    pub ratification: &'a BundleSigningRatification,
    /// Genesis authority block from the runtime's authoritative
    /// [`crate::genesis::GenesisConfig::authority`] field.
    pub authority: &'a GenesisAuthorityConfig,
    /// Expected chain id (from runtime).
    pub expected_chain_id: &'a str,
    /// Expected environment policy (from runtime).
    pub expected_environment: NetworkEnvironmentPolicy,
    /// Canonical genesis hash that the runtime computed via
    /// [`crate::genesis::compute_canonical_genesis_hash`].
    pub expected_genesis_hash: &'a GenesisHash,
}

/// Minimal Run 103 verifier.
///
/// Performs, in order:
///
///   1. version / chain / environment / genesis-hash binding checks;
///   2. suite-id allow-list (only ML-DSA-44 = 100);
///   3. bundle-signing-key length and fingerprint self-consistency;
///   4. authority-root lookup inside
///      `authority.bundle_signing_authority_roots`, **never** inside
///      `pqc_transport_roots`;
///   5. authority-root → PQC signature verification using the existing
///      [`MlDsa44SignatureSuite`] adapter.
///
/// On success returns the [`RatifiedBundleSigningKey`] identity that has
/// been authorised by the genesis-bound root. On failure returns a
/// precise [`RatificationFailure`].
///
/// Fail-closed: every error path returns `Err(..)`; there is no boolean
/// "best-effort" branch.
pub fn verify_bundle_signing_key_ratification(
    inputs: RatificationVerifierInputs<'_>,
) -> Result<RatifiedBundleSigningKey, RatificationFailure> {
    let r = inputs.ratification;

    // 1a. Version.
    if r.version != BUNDLE_SIGNING_RATIFICATION_VERSION_V1 {
        return Err(RatificationFailure::UnsupportedVersion {
            got: r.version,
            expected: BUNDLE_SIGNING_RATIFICATION_VERSION_V1,
        });
    }

    // 1b. Chain.
    if r.chain_id != inputs.expected_chain_id {
        return Err(RatificationFailure::ChainMismatch {
            expected: inputs.expected_chain_id.to_string(),
            got: r.chain_id.clone(),
        });
    }

    // 1c. Environment.
    let expected_env_tag = RatificationEnvironment::from_policy(inputs.expected_environment);
    if r.environment != expected_env_tag {
        return Err(RatificationFailure::EnvironmentMismatch {
            expected: expected_env_tag,
            got: r.environment,
        });
    }

    // 1d. Genesis hash.
    if &r.genesis_hash != inputs.expected_genesis_hash {
        return Err(RatificationFailure::GenesisHashMismatch {
            expected: *inputs.expected_genesis_hash,
            got: r.genesis_hash,
        });
    }

    // 2. Suite-id allow-list.
    if r.signature_suite_id != GENESIS_AUTHORITY_SUITE_ML_DSA_44 {
        return Err(RatificationFailure::UnsupportedSuite {
            suite_id: r.signature_suite_id,
        });
    }

    // 3a. Bundle-signing key length must match the declared suite.
    if r.bundle_signing_public_key.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
        return Err(RatificationFailure::MalformedBundleSigningPublicKey {
            suite_id: r.signature_suite_id,
            got_len: r.bundle_signing_public_key.len(),
            expected_len: ML_DSA_44_PUBLIC_KEY_SIZE,
        });
    }

    // 3b. Bundle-signing key fingerprint self-consistency.
    let recomputed_fp = sha3_256_hex(&r.bundle_signing_public_key);
    if r.bundle_signing_public_key_fingerprint != recomputed_fp {
        return Err(RatificationFailure::BundleSigningKeyFingerprintMismatch {
            expected: recomputed_fp,
            got: r.bundle_signing_public_key_fingerprint.clone(),
        });
    }

    // 3c. Signature length must match the declared suite.
    if r.signature.len() != ML_DSA_44_SIGNATURE_SIZE {
        return Err(RatificationFailure::MalformedSignature {
            suite_id: r.signature_suite_id,
            got_len: r.signature.len(),
            expected_len: ML_DSA_44_SIGNATURE_SIZE,
        });
    }

    // 4. Authority-root lookup. The verifier ONLY consults
    // `bundle_signing_authority_roots`; transport roots are never accepted
    // here. We additionally check the transport set so we can return a
    // precise `TransportRootNotAllowed` error when an operator points the
    // ratification at a transport-only fingerprint.
    let bundle_root = find_root(
        &inputs.authority.bundle_signing_authority_roots,
        &r.authority_root_fingerprint,
        r.signature_suite_id,
    );
    if bundle_root.is_none() {
        // Distinguish "in transport set" from "unknown" for clearer error
        // messages — both still fail closed.
        let transport_hit = find_root(
            &inputs.authority.pqc_transport_roots,
            &r.authority_root_fingerprint,
            r.signature_suite_id,
        );
        if transport_hit.is_some() {
            return Err(RatificationFailure::TransportRootNotAllowed {
                fingerprint: r.authority_root_fingerprint.clone(),
            });
        }
        return Err(RatificationFailure::UnknownAuthorityRoot {
            fingerprint: r.authority_root_fingerprint.clone(),
        });
    }
    let bundle_root = bundle_root.expect("checked above");

    if bundle_root.suite_id != r.signature_suite_id {
        return Err(RatificationFailure::AuthorityRootSuiteMismatch {
            root_suite_id: bundle_root.suite_id,
            ratification_suite_id: r.signature_suite_id,
        });
    }

    // 5. Resolve authority-root public-key bytes.
    //
    // Run 104 resolution order:
    //   1. If the matched root carries `public_key_hex`, decode and use
    //      that. Any malformed bytes (non-hex, wrong length for the
    //      declared suite, fingerprint mismatch with the root's
    //      `key_fingerprint`) fail closed with
    //      `AuthorityKeyMaterialMalformed`.
    //   2. Otherwise, fall back to the Run 103 legacy overload where
    //      `key_fingerprint` itself carries the full PK hex (2624 chars
    //      for ML-DSA-44). This path is preserved for backward
    //      compatibility with DevNet/TestNet genesis written before Run
    //      104 introduced the explicit `public_key_hex` field.
    //   3. Otherwise (only a short SHA3-256 fingerprint exists), fail
    //      closed with `AuthorityKeyMaterialUnavailable` — never fake
    //      verification, never fall back to local/static keys.
    let required_hex_len = ML_DSA_44_PUBLIC_KEY_SIZE * 2;
    let authority_pk: Vec<u8> = if let Some(pk_hex) = bundle_root.public_key_hex.as_deref() {
        // Run 104 clean path.
        if pk_hex.len() != GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN {
            return Err(RatificationFailure::AuthorityKeyMaterialMalformed {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                reason: format!(
                    "public_key_hex length {} != expected {}",
                    pk_hex.len(),
                    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN
                ),
            });
        }
        let pk_bytes = match decode_hex(pk_hex) {
            Some(b) => b,
            None => {
                return Err(RatificationFailure::AuthorityKeyMaterialMalformed {
                    fingerprint: bundle_root.key_fingerprint.clone(),
                    suite_id: bundle_root.suite_id,
                    reason: "public_key_hex is not lowercase hex".into(),
                });
            }
        };
        if pk_bytes.len() != GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES {
            return Err(RatificationFailure::AuthorityKeyMaterialMalformed {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                reason: format!(
                    "decoded public_key_hex is {} bytes; ML-DSA-44 requires {}",
                    pk_bytes.len(),
                    GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_BYTES
                ),
            });
        }
        // Enforce the Run 104 key_fingerprint ↔ public_key_hex binding
        // *at verification time* too, so a malformed genesis that
        // somehow slipped past `validate_for_environment` still fails
        // closed rather than silently authenticating the wrong key.
        if bundle_root.key_fingerprint.len() == GENESIS_AUTHORITY_KEY_FINGERPRINT_HEX_LEN {
            let derived = authority_public_key_fingerprint(&pk_bytes);
            if derived != bundle_root.key_fingerprint {
                return Err(RatificationFailure::AuthorityKeyMaterialMalformed {
                    fingerprint: bundle_root.key_fingerprint.clone(),
                    suite_id: bundle_root.suite_id,
                    reason: format!(
                        "public_key_hex sha3_256={} does not match declared key_fingerprint={}",
                        derived, bundle_root.key_fingerprint
                    ),
                });
            }
        }
        pk_bytes
    } else {
        // Legacy fallback: `key_fingerprint` may carry the full PK hex.
        let fp_hex = &bundle_root.key_fingerprint;
        if fp_hex.len() != required_hex_len {
            return Err(RatificationFailure::AuthorityKeyMaterialUnavailable {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                got_hex_len: fp_hex.len(),
                required_hex_len,
            });
        }
        let authority_pk = match decode_hex(fp_hex) {
            Some(pk) => pk,
            None => {
                return Err(RatificationFailure::AuthorityKeyMaterialUnavailable {
                    fingerprint: bundle_root.key_fingerprint.clone(),
                    suite_id: bundle_root.suite_id,
                    got_hex_len: fp_hex.len(),
                    required_hex_len,
                });
            }
        };
        if authority_pk.len() != ML_DSA_44_PUBLIC_KEY_SIZE {
            return Err(RatificationFailure::AuthorityKeyMaterialUnavailable {
                fingerprint: bundle_root.key_fingerprint.clone(),
                suite_id: bundle_root.suite_id,
                got_hex_len: fp_hex.len(),
                required_hex_len,
            });
        }
        authority_pk
    };

    // 6. PQC signature verification via the existing production ML-DSA-44
    // adapter — no parallel crypto stack.
    let digest = canonical_ratification_digest(r);
    let suite = MlDsa44SignatureSuite::new(GENESIS_AUTHORITY_SUITE_ML_DSA_44);
    match suite.verify(&authority_pk, &digest, &r.signature) {
        Ok(()) => Ok(RatifiedBundleSigningKey {
            public_key: r.bundle_signing_public_key.clone(),
            fingerprint: r.bundle_signing_public_key_fingerprint.clone(),
            signature_suite_id: r.signature_suite_id,
            authority_root_fingerprint: r.authority_root_fingerprint.clone(),
        }),
        // CryptoError is intentionally collapsed into BadSignature — the
        // typed verifier API does not leak crypto-library internals.
        Err(_) => Err(RatificationFailure::BadSignature),
    }
}

fn find_root<'a>(
    roots: &'a [GenesisAuthorityRoot],
    fingerprint: &str,
    suite_id: GenesisAuthoritySuiteId,
) -> Option<&'a GenesisAuthorityRoot> {
    roots
        .iter()
        .find(|r| r.suite_id == suite_id && r.key_fingerprint == fingerprint)
        // If the operator only stores a short fingerprint in genesis and the
        // ratification carries the full key in `authority_root_fingerprint`
        // (or vice versa), they will not match. That is intentional: the
        // verifier requires exact agreement between the ratification and
        // the genesis-bound surface. Operators must use a consistent
        // representation.
        .or_else(|| {
            // Permit the inverse pairing where genesis stores the full PK
            // in `key_fingerprint` (Run 103 legacy overload) and the
            // ratification carries the SHA3-256 fingerprint. This keeps
            // operator tooling flexible without weakening any check.
            roots.iter().find(|r| {
                r.suite_id == suite_id
                    && r.key_fingerprint.len() == ML_DSA_44_PUBLIC_KEY_SIZE * 2
                    && fingerprint.len() == 64
                    && {
                        match decode_hex(&r.key_fingerprint) {
                            Some(pk_bytes) => sha3_256_hex(&pk_bytes) == fingerprint,
                            None => false,
                        }
                    }
            })
        })
        .or_else(|| {
            // Run 104: when genesis carries the clean Run 104 shape
            // (short `key_fingerprint` + separate `public_key_hex`),
            // also allow operators to point a ratification at the full
            // PK hex. The verifier checks consistency via the SHA3-256
            // fingerprint binding, so this never accepts an
            // inconsistent root.
            roots.iter().find(|r| {
                r.suite_id == suite_id
                    && fingerprint.len() == GENESIS_AUTHORITY_ML_DSA_44_PUBLIC_KEY_HEX_LEN
                    && r.public_key_hex.as_deref() == Some(fingerprint)
            })
        })
}

/// Best-effort transport/bundle-signing kind classification for a
/// fingerprint. Returns `None` if the fingerprint is unknown to the
/// authority block.
///
/// This is exposed primarily for diagnostic tooling; the verifier itself
/// performs the kind check inline.
pub fn classify_authority_root_kind(
    authority: &GenesisAuthorityConfig,
    fingerprint: &str,
    suite_id: GenesisAuthoritySuiteId,
) -> Option<GenesisAuthorityRootKind> {
    if find_root(&authority.bundle_signing_authority_roots, fingerprint, suite_id).is_some() {
        return Some(GenesisAuthorityRootKind::BundleSigning);
    }
    if find_root(&authority.pqc_transport_roots, fingerprint, suite_id).is_some() {
        return Some(GenesisAuthorityRootKind::Transport);
    }
    None
}

// ===========================================================================
// Hex helpers
// ===========================================================================

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if s.len() % 2 != 0 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Some(out)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(10 + b - b'a'),
        // Reject uppercase: every fingerprint in QBIND is lowercase hex.
        _ => None,
    }
}

fn sha3_256_hex(bytes: &[u8]) -> String {
    let d = qbind_hash::sha3_256(bytes);
    let mut out = String::with_capacity(64);
    for b in d.iter() {
        use std::fmt::Write;
        let _ = write!(&mut out, "{:02x}", b);
    }
    out
}

/// SHA3-256 fingerprint (lowercase hex) of a PQC public key.
///
/// Convenience helper for operator tooling that constructs ratification
/// objects.
pub fn pqc_public_key_fingerprint(pk: &[u8]) -> String {
    sha3_256_hex(pk)
}

// ===========================================================================
// Test-only signer helper
// ===========================================================================

/// Test-only helper to mint a fully-signed [`BundleSigningRatification`] from
/// raw inputs.
///
/// Only compiled under `cfg(any(test, feature = "test-helpers"))`. NOT a
/// production code path — production signing is done out-of-band by the
/// authority-key holder.
#[cfg(any(test, feature = "test-helpers"))]
pub mod test_helpers {
    use super::*;
    use qbind_crypto::ml_dsa_44_sign_digest;

    /// Build and sign a Run 103 ratification object.
    ///
    /// `authority_sk` is the ML-DSA-44 secret key of the authority root.
    /// `authority_pk_hex` is the lowercase hex of the matching public key,
    /// used as the ratification's `authority_root_fingerprint` AND as the
    /// genesis-bound root's `key_fingerprint`.
    pub fn build_signed_ratification(
        chain_id: &str,
        environment: RatificationEnvironment,
        genesis_hash: GenesisHash,
        authority_pk_hex: &str,
        authority_sk: &[u8],
        bundle_signing_pk: &[u8],
    ) -> BundleSigningRatification {
        let fp = pqc_public_key_fingerprint(bundle_signing_pk);
        let mut r = BundleSigningRatification {
            version: BUNDLE_SIGNING_RATIFICATION_VERSION_V1,
            chain_id: chain_id.to_string(),
            environment,
            genesis_hash,
            authority_root_fingerprint: authority_pk_hex.to_string(),
            signature_suite_id: GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            bundle_signing_public_key: bundle_signing_pk.to_vec(),
            bundle_signing_public_key_fingerprint: fp,
            signature: Vec::new(),
        };
        let digest = canonical_ratification_digest(&r);
        let sig = ml_dsa_44_sign_digest(authority_sk, &digest)
            .expect("ml_dsa_44_sign_digest in test helper must succeed");
        r.signature = sig;
        r
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::genesis::{
        compute_canonical_genesis_hash, GenesisAllocation, GenesisAuthorityConfig,
        GenesisAuthorityRoot, GenesisConfig, GenesisCouncilConfig, GenesisMonetaryConfig,
        GenesisValidator, GENESIS_AUTHORITY_SUITE_ML_DSA_44,
    };
    use qbind_crypto::MlDsa44Backend;

    // ---------------- helpers ----------------

    fn full_pk_hex(pk: &[u8]) -> String {
        let mut s = String::with_capacity(pk.len() * 2);
        for b in pk {
            use std::fmt::Write;
            let _ = write!(&mut s, "{:02x}", b);
        }
        s
    }

    fn mk_genesis(chain_id: &str, authority_pk_hex: &str) -> GenesisConfig {
        let mut cfg = GenesisConfig::new(
            chain_id,
            1_738_000_000_000,
            vec![GenesisAllocation::new(format!("0x{}", "11".repeat(32)), 100)],
            vec![GenesisValidator::new(
                format!("0x{}", "22".repeat(32)),
                "ab".repeat(32),
                100,
            )],
            GenesisCouncilConfig::new(
                vec![
                    format!("0x{}", "33".repeat(32)),
                    format!("0x{}", "44".repeat(32)),
                    format!("0x{}", "55".repeat(32)),
                ],
                2,
            ),
            GenesisMonetaryConfig::mainnet_default(),
        );
        let root = GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            authority_pk_hex,
            "foundation-bundle-signing-1",
        );
        cfg.authority = Some(GenesisAuthorityConfig::new(vec![root]));
        cfg
    }

    fn mk_inputs<'a>(
        r: &'a BundleSigningRatification,
        authority: &'a GenesisAuthorityConfig,
        chain_id: &'a str,
        env: NetworkEnvironmentPolicy,
        gh: &'a GenesisHash,
    ) -> RatificationVerifierInputs<'a> {
        RatificationVerifierInputs {
            ratification: r,
            authority,
            expected_chain_id: chain_id,
            expected_environment: env,
            expected_genesis_hash: gh,
        }
    }

    // ---------------- A. schema/preimage ----------------

    #[test]
    fn preimage_is_deterministic() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let p1 = canonical_ratification_preimage(&r);
        let p2 = canonical_ratification_preimage(&r);
        assert_eq!(p1, p2);
        assert!(p1.starts_with(BUNDLE_SIGNING_RATIFICATION_DOMAIN_V1));
    }

    #[test]
    fn preimage_changes_with_each_consensus_field() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let base = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let base_p = canonical_ratification_preimage(&base);

        // chain
        let mut m = base.clone();
        m.chain_id = "qbind-mainnet-vX".into();
        assert_ne!(canonical_ratification_preimage(&m), base_p);

        // environment
        let mut m = base.clone();
        m.environment = RatificationEnvironment::Testnet;
        assert_ne!(canonical_ratification_preimage(&m), base_p);

        // genesis hash
        let mut m = base.clone();
        m.genesis_hash[0] ^= 0xFF;
        assert_ne!(canonical_ratification_preimage(&m), base_p);

        // authority fingerprint
        let mut m = base.clone();
        m.authority_root_fingerprint.push('a');
        m.authority_root_fingerprint.push('a');
        assert_ne!(canonical_ratification_preimage(&m), base_p);

        // suite id
        let mut m = base.clone();
        m.signature_suite_id = 7;
        assert_ne!(canonical_ratification_preimage(&m), base_p);

        // bundle-signing key
        let mut m = base.clone();
        m.bundle_signing_public_key[0] ^= 0xFF;
        assert_ne!(canonical_ratification_preimage(&m), base_p);

        // bundle-signing key fingerprint
        let mut m = base.clone();
        m.bundle_signing_public_key_fingerprint = "00".repeat(32);
        assert_ne!(canonical_ratification_preimage(&m), base_p);
    }

    #[test]
    fn unsupported_version_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.version = 2;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::UnsupportedVersion { got: 2, .. }
        ));
    }

    // ---------------- B. authority lookup ----------------

    #[test]
    fn known_bundle_signing_root_accepted() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let ok = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("valid ratification must verify");
        assert_eq!(ok.public_key, bsk_pk);
        assert_eq!(ok.signature_suite_id, GENESIS_AUTHORITY_SUITE_ML_DSA_44);
    }

    #[test]
    fn unknown_authority_root_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        // Genesis carries `other_pk` as the only bundle-signing root —
        // not `auth_pk` that we will sign with.
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&other_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::UnknownAuthorityRoot { .. }
        ));
    }

    #[test]
    fn transport_root_rejected_as_bundle_signing_authority() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        // Bundle-signing set contains `other_pk` only; transport set
        // contains `auth_pk`. Ratification signed by `auth_pk` must be
        // rejected with the specific TransportRootNotAllowed reason.
        let mut cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&other_pk));
        cfg.authority.as_mut().unwrap().pqc_transport_roots = vec![GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            full_pk_hex(&auth_pk),
            "foundation-transport-1",
        )];
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::TransportRootNotAllowed { .. }
        ));
    }

    #[test]
    fn wrong_chain_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.chain_id = "qbind-testnet-beta".into();
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(err, RatificationFailure::ChainMismatch { .. }));
    }

    #[test]
    fn wrong_environment_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.environment = RatificationEnvironment::Testnet;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::EnvironmentMismatch { .. }
        ));
    }

    #[test]
    fn wrong_genesis_hash_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let mut wrong = gh;
        wrong[0] ^= 0xFF;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &wrong,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::GenesisHashMismatch { .. }
        ));
    }

    // ---------------- C. signature ----------------

    #[test]
    fn bad_signature_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.signature[0] ^= 0xFF;
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(err, RatificationFailure::BadSignature));
    }

    #[test]
    fn unsupported_suite_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.signature_suite_id = 99; // not ML-DSA-44
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::UnsupportedSuite { suite_id: 99 }
        ));
    }

    #[test]
    fn mutated_preimage_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk2_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        // Swap the bundle-signing key but keep the original signature →
        // mutated preimage → must fail closed via BadSignature (after the
        // fingerprint self-consistency check is also updated).
        r.bundle_signing_public_key = bsk2_pk.clone();
        r.bundle_signing_public_key_fingerprint = pqc_public_key_fingerprint(&bsk2_pk);
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(err, RatificationFailure::BadSignature));
    }

    #[test]
    fn wrong_authority_root_signature_rejected() {
        let (auth_pk, _auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (_other_pk, other_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        // Genesis trusts `auth_pk`; we sign with `other_sk` but claim
        // `auth_pk` is the authority. Signature verification must fail.
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &other_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(err, RatificationFailure::BadSignature));
    }

    // ---------------- D. bundle-signing key binding ----------------

    #[test]
    fn bundle_signing_key_fingerprint_mismatch_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.bundle_signing_public_key_fingerprint = "00".repeat(32);
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::BundleSigningKeyFingerprintMismatch { .. }
        ));
    }

    #[test]
    fn malformed_bundle_signing_public_key_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.bundle_signing_public_key.truncate(10);
        // Keep fingerprint to surface only the length error.
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::MalformedBundleSigningPublicKey { .. }
        ));
    }

    #[test]
    fn malformed_signature_rejected() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let mut r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        r.signature.truncate(50);
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::MalformedSignature { .. }
        ));
    }

    // ---------------- E. authority key material boundary ----------------

    #[test]
    fn authority_root_with_only_short_fingerprint_returns_unavailable() {
        // Genesis carries only a 64-hex SHA3 fingerprint of the authority
        // PK. The verifier must NOT fake verification — it must fail
        // closed with AuthorityKeyMaterialUnavailable.
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let auth_pk_fp = pqc_public_key_fingerprint(&auth_pk); // 64-hex
        let cfg = mk_genesis("qbind-mainnet-v0", &auth_pk_fp);
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        // Ratification carries the same short fingerprint as authority_root_fingerprint.
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &auth_pk_fp,
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(matches!(
            err,
            RatificationFailure::AuthorityKeyMaterialUnavailable { .. }
        ));
    }

    #[test]
    fn classify_authority_root_kind_distinguishes_sets() {
        let (auth_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (xport_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        cfg.authority.as_mut().unwrap().pqc_transport_roots = vec![GenesisAuthorityRoot::new(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            full_pk_hex(&xport_pk),
            "foundation-transport-1",
        )];
        let auth = cfg.authority.as_ref().unwrap();
        assert_eq!(
            classify_authority_root_kind(
                auth,
                &full_pk_hex(&auth_pk),
                GENESIS_AUTHORITY_SUITE_ML_DSA_44
            ),
            Some(GenesisAuthorityRootKind::BundleSigning)
        );
        assert_eq!(
            classify_authority_root_kind(
                auth,
                &full_pk_hex(&xport_pk),
                GENESIS_AUTHORITY_SUITE_ML_DSA_44
            ),
            Some(GenesisAuthorityRootKind::Transport)
        );
        assert_eq!(
            classify_authority_root_kind(auth, &"de".repeat(32), GENESIS_AUTHORITY_SUITE_ML_DSA_44),
            None
        );
    }

    // ---------------- F. round-trip / serde ----------------

    #[test]
    fn ratification_object_round_trips_through_json() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis("qbind-mainnet-v0", &full_pk_hex(&auth_pk));
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let s = serde_json::to_string(&r).expect("ser");
        let r2: BundleSigningRatification = serde_json::from_str(&s).expect("de");
        assert_eq!(r, r2);
        // And the round-tripped object still verifies.
        let auth = cfg.authority.as_ref().unwrap();
        verify_bundle_signing_key_ratification(mk_inputs(
            &r2,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("must still verify after json round-trip");
    }

    // ===================================================================
    // Run 104 — clean-shape genesis with separate `public_key_hex`
    // ===================================================================

    /// Build a Run 104 mainnet genesis whose bundle-signing root carries
    /// a separate `public_key_hex` (clean shape) and whose
    /// `key_fingerprint` is the SHA3-256 of that PK.
    fn mk_genesis_run_104_clean(chain_id: &str, auth_pk: &[u8]) -> GenesisConfig {
        let mut cfg = GenesisConfig::new(
            chain_id,
            1_738_000_000_000,
            vec![GenesisAllocation::new(format!("0x{}", "11".repeat(32)), 100)],
            vec![GenesisValidator::new(
                format!("0x{}", "22".repeat(32)),
                "ab".repeat(32),
                100,
            )],
            GenesisCouncilConfig::new(
                vec![
                    format!("0x{}", "33".repeat(32)),
                    format!("0x{}", "44".repeat(32)),
                    format!("0x{}", "55".repeat(32)),
                ],
                2,
            ),
            GenesisMonetaryConfig::mainnet_default(),
        );
        let root = GenesisAuthorityRoot::with_public_key_bytes(
            GENESIS_AUTHORITY_SUITE_ML_DSA_44,
            auth_pk,
            "foundation-bundle-signing-104",
        );
        cfg.authority = Some(GenesisAuthorityConfig::new(vec![root]));
        cfg
    }

    #[test]
    fn run_104_verifier_uses_public_key_hex_when_present() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis_run_104_clean("qbind-mainnet-v0", &auth_pk);
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        // Operator chooses to bind the ratification by the canonical
        // 64-hex SHA3 fingerprint of the authority key — Run 104's
        // clean shape supports this without overloading anything.
        let fp = qbind_hash::sha3_256(&auth_pk);
        let fp_hex: String = fp.iter().map(|b| format!("{:02x}", b)).collect();
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &fp_hex,
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect(
            "Run 104 clean-shape ratification (short-fingerprint binding) must verify against \
             the genesis-bound public_key_hex",
        );
    }

    #[test]
    fn run_104_verifier_accepts_full_pk_binding_against_clean_root() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let cfg = mk_genesis_run_104_clean("qbind-mainnet-v0", &auth_pk);
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        // Operator chooses to bind the ratification by the full PK hex.
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &full_pk_hex(&auth_pk),
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .expect("full-PK ratification binding must verify against a Run 104 clean-shape root");
    }

    #[test]
    fn run_104_verifier_rejects_malformed_public_key_hex() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = mk_genesis_run_104_clean("qbind-mainnet-v0", &auth_pk);
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let fp = qbind_hash::sha3_256(&auth_pk);
        let fp_hex: String = fp.iter().map(|b| format!("{:02x}", b)).collect();
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &fp_hex,
            &auth_sk,
            &bsk_pk,
        );
        // Corrupt the genesis-bound public_key_hex by truncation.
        let pk_mut = cfg.authority.as_mut().unwrap()
            .bundle_signing_authority_roots[0]
            .public_key_hex
            .as_mut()
            .unwrap();
        pk_mut.truncate(pk_mut.len() - 2);
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationFailure::AuthorityKeyMaterialMalformed { .. }),
            "got {:?}",
            err
        );
    }

    #[test]
    fn run_104_verifier_rejects_pk_hex_fingerprint_mismatch() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (other_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let mut cfg = mk_genesis_run_104_clean("qbind-mainnet-v0", &auth_pk);
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let fp = qbind_hash::sha3_256(&auth_pk);
        let fp_hex: String = fp.iter().map(|b| format!("{:02x}", b)).collect();
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &fp_hex,
            &auth_sk,
            &bsk_pk,
        );
        // Swap in a different PK while leaving the SHA3 fingerprint
        // declaring the original — this is the tampering case.
        cfg.authority.as_mut().unwrap()
            .bundle_signing_authority_roots[0]
            .public_key_hex = Some(full_pk_hex(&other_pk));
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(err, RatificationFailure::AuthorityKeyMaterialMalformed { .. }),
            "got {:?}",
            err
        );
    }

    #[test]
    fn run_104_verifier_still_fails_closed_when_only_short_fingerprint_present() {
        let (auth_pk, auth_sk) = MlDsa44Backend::generate_keypair().unwrap();
        let (bsk_pk, _) = MlDsa44Backend::generate_keypair().unwrap();
        let fp = qbind_hash::sha3_256(&auth_pk);
        let fp_hex: String = fp.iter().map(|b| format!("{:02x}", b)).collect();
        // Genesis carries only the 64-hex fingerprint — no public_key_hex,
        // no legacy full-PK overload. The verifier must fail closed.
        let mut cfg = mk_genesis("qbind-mainnet-v0", &fp_hex);
        // Clear any accidental public_key_hex helper effect.
        cfg.authority.as_mut().unwrap()
            .bundle_signing_authority_roots[0]
            .public_key_hex = None;
        let gh = compute_canonical_genesis_hash(&cfg, NetworkEnvironmentPolicy::Mainnet);
        let r = test_helpers::build_signed_ratification(
            "qbind-mainnet-v0",
            RatificationEnvironment::Mainnet,
            gh,
            &fp_hex,
            &auth_sk,
            &bsk_pk,
        );
        let auth = cfg.authority.as_ref().unwrap();
        let err = verify_bundle_signing_key_ratification(mk_inputs(
            &r,
            auth,
            "qbind-mainnet-v0",
            NetworkEnvironmentPolicy::Mainnet,
            &gh,
        ))
        .unwrap_err();
        assert!(
            matches!(
                err,
                RatificationFailure::AuthorityKeyMaterialUnavailable { .. }
            ),
            "got {:?}",
            err
        );
    }
}